// Package edgeapi serves the node-agent: long-polled config delivery and
// telemetry ingest. Authenticated with the shared agent token (Phase 1; Phase 3
// replaces this with per-node mTLS).
package edgeapi

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/aegis/control-plane/internal/appcfg"
	"github.com/aegis/control-plane/internal/clickhouse"
	"github.com/aegis/control-plane/internal/config"
	"github.com/aegis/control-plane/internal/domains"
	"github.com/aegis/control-plane/internal/geoip"
	"github.com/aegis/control-plane/internal/pki"
	"github.com/aegis/control-plane/internal/store"
	"github.com/aegis/control-plane/internal/web"
)

type API struct {
	Store   *store.Store
	Cfg     *appcfg.Config
	CH      *clickhouse.Client
	Geo     *geoip.DB
	Domains *domains.Service
	CA      *pki.CA
}

func New(st *store.Store, cfg *appcfg.Config, ch *clickhouse.Client, geo *geoip.DB, dom *domains.Service, ca *pki.CA) *API {
	return &API{Store: st, Cfg: cfg, CH: ch, Geo: geo, Domains: dom, CA: ca}
}

// clientCertTTL is the lifetime of an edge's per-node client certificate.
const clientCertTTL = 90 * 24 * time.Hour

// AuthnMTLS authenticates an edge by its verified client certificate (the TLS
// layer has already checked the chain against our CA). The cert CommonName is
// the edge UUID; the resolved edge is attached to the request context.
func (a *API) AuthnMTLS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
			web.Error(w, http.StatusUnauthorized, "unauthorized", "client certificate required")
			return
		}
		peer := r.TLS.PeerCertificates[0]
		id, err := uuid.Parse(peer.Subject.CommonName)
		if err != nil {
			web.Error(w, http.StatusForbidden, "forbidden", "client certificate has no edge identity")
			return
		}
		edge, err := a.Store.GetEdge(r.Context(), id)
		if err != nil {
			web.Error(w, http.StatusForbidden, "forbidden", "unknown edge")
			return
		}
		if edge.RevokedAt != nil {
			web.Error(w, http.StatusForbidden, "revoked", "edge certificate has been revoked")
			return
		}
		// Reject a superseded cert: only the edge's current (latest-issued) serial
		// is accepted, so a rotated-out cert is implicitly revoked.
		if edge.CertSerial != nil && *edge.CertSerial != peer.SerialNumber.String() {
			web.Error(w, http.StatusForbidden, "superseded", "client certificate has been superseded; renew required")
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), edgeCtxKey, edge)))
	})
}

type ctxKey int

const edgeCtxKey ctxKey = iota

// edgeFromCtx returns the per-node edge identity when the request authenticated
// with an enrolled edge's token (nil for the shared all-in-one token).
func edgeFromCtx(ctx context.Context) *store.Edge {
	e, _ := ctx.Value(edgeCtxKey).(*store.Edge)
	return e
}

func randToken(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func hashToken(tok string) string {
	sum := sha256.Sum256([]byte(tok))
	return hex.EncodeToString(sum[:])
}

var nonEdgeName = regexp.MustCompile(`[^a-z0-9-]+`)

const maxEventsBatch = 20000

// ingestEvent mirrors the edge event plus the GeoIP fields we enrich on ingest.
type ingestEvent struct {
	TS      int64  `json:"ts"`
	Host    string `json:"host"`
	IP      string `json:"ip"`
	Method  string `json:"method"`
	Path    string `json:"path"`
	Status  int    `json:"status"`
	Bytes   int64  `json:"bytes"`
	UA      string `json:"ua"`
	JA4H    string `json:"ja4h"`
	Action  string `json:"action"`
	Country string `json:"country"`
	ASN     uint32 `json:"asn"`
	ASNOrg  string `json:"asn_org"`
}

// Events ingests a batch of per-request analytics events from the agent,
// enriches them with GeoIP (country + ASN), and inserts them into ClickHouse.
// When ClickHouse is disabled the batch is accepted and dropped so the edge's
// Redis queue still drains.
func (a *API) Events(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Events []ingestEvent `json:"events"`
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 32<<20))
	if err := dec.Decode(&in); err != nil {
		web.Error(w, http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	if !a.CH.Enabled() || len(in.Events) == 0 {
		web.JSON(w, http.StatusOK, map[string]any{"ok": true, "stored": 0})
		return
	}
	if len(in.Events) > maxEventsBatch {
		in.Events = in.Events[:maxEventsBatch]
	}
	lines := make([]string, 0, len(in.Events))
	for _, e := range in.Events {
		if a.Geo != nil {
			e.Country, e.ASN, e.ASNOrg = a.Geo.Lookup(e.IP)
		}
		b, err := json.Marshal(e)
		if err != nil {
			continue
		}
		lines = append(lines, string(b))
	}
	if err := a.CH.Insert(r.Context(), "aegis_requests", strings.Join(lines, "\n")); err != nil {
		web.Error(w, http.StatusBadGateway, "analytics_error", "insert failed: "+err.Error())
		return
	}
	web.JSON(w, http.StatusOK, map[string]any{"ok": true, "stored": len(lines)})
}

// Authn authenticates an edge: it accepts either the shared all-in-one agent
// token (local edge) or a per-node token issued at enrollment. For per-node
// tokens the edge identity is attached to the request context.
func (a *API) Authn(next http.Handler) http.Handler {
	want := "Bearer " + a.Cfg.AgentToken
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got := r.Header.Get("Authorization")
		if a.Cfg.AgentToken != "" && subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 1 {
			next.ServeHTTP(w, r)
			return
		}
		if tok, ok := strings.CutPrefix(got, "Bearer "); ok && tok != "" {
			if edge, err := a.Store.GetEdgeByTokenHash(r.Context(), hashToken(tok)); err == nil {
				next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), edgeCtxKey, edge)))
				return
			}
		}
		web.Error(w, http.StatusUnauthorized, "unauthorized", "invalid agent token")
	})
}

// RenewCert issues a fresh client certificate to an already-authenticated edge
// (over its current mTLS connection) and records it as the edge's current cert,
// superseding the old one. Served on the mTLS listener.
func (a *API) RenewCert(w http.ResponseWriter, r *http.Request) {
	edge := edgeFromCtx(r.Context())
	if edge == nil || a.CA == nil {
		web.Error(w, http.StatusForbidden, "forbidden", "mTLS edge identity required")
		return
	}
	certPEM, keyPEM, serial, notAfter, err := a.CA.IssueClient(edge.ID.String(), clientCertTTL)
	if err != nil {
		web.Error(w, http.StatusInternalServerError, "internal", "could not issue certificate")
		return
	}
	if err := a.Store.SetEdgeCert(r.Context(), edge.ID, serial, notAfter); err != nil {
		web.Error(w, http.StatusInternalServerError, "internal", "could not record certificate")
		return
	}
	_ = a.Store.Audit(r.Context(), nil, nil, "edge.cert_renew", edge.Name, clientIP(r), map[string]any{"edge_id": edge.ID.String()})
	web.JSON(w, http.StatusOK, map[string]any{
		"cert_b64":   base64.StdEncoding.EncodeToString(certPEM),
		"key_b64":    base64.StdEncoding.EncodeToString(keyPEM),
		"ca_b64":     base64.StdEncoding.EncodeToString(a.CA.CertPEM),
		"expires_at": notAfter,
	})
}

// Enroll exchanges a single-use enrollment token for a durable per-node agent
// token and registers the edge. It is unauthenticated except by the enrollment
// token itself. On success the new edge joins the DNS rotation immediately.
func (a *API) Enroll(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Token    string `json:"token"`
		Name     string `json:"name"`
		PublicIP string `json:"public_ip"`
		Region   string `json:"region"`
	}
	if err := web.Decode(w, r, &in); err != nil {
		web.Error(w, http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	in.Token = strings.TrimSpace(in.Token)
	if in.Token == "" {
		web.Error(w, http.StatusBadRequest, "validation", "token is required")
		return
	}
	if _, err := netip.ParseAddr(strings.TrimSpace(in.PublicIP)); err != nil {
		web.Error(w, http.StatusBadRequest, "validation", "a valid public_ip is required")
		return
	}
	name := edgeName(in.Name)
	region := strings.TrimSpace(in.Region)
	if region == "" {
		region = "default"
	}

	agentToken := randToken(32)
	edge, err := a.Store.EnrollEdge(r.Context(), hashToken(in.Token), name, strings.TrimSpace(in.PublicIP), region, hashToken(agentToken))
	if errors.Is(err, store.ErrNotFound) {
		web.Error(w, http.StatusUnauthorized, "invalid_token", "invalid, expired or already-used enrollment token")
		return
	}
	if err != nil {
		web.Error(w, http.StatusInternalServerError, "internal", "could not enroll edge")
		return
	}

	// Issue a per-node mTLS client certificate (CN = edge id) signed by our CA.
	resp := map[string]any{
		"edge_id":           edge.ID,
		"name":              edge.Name,
		"region":            edge.Region,
		"public_ip":         edge.PublicIP,
		"agent_token":       agentToken,
		"control_plane_url": a.Cfg.ControlPlaneURL,
		"challenge_secret":  a.Cfg.ChallengeSecret,
	}
	if a.CA != nil {
		certPEM, keyPEM, serial, notAfter, cerr := a.CA.IssueClient(edge.ID.String(), clientCertTTL)
		if cerr != nil {
			web.Error(w, http.StatusInternalServerError, "internal", "could not issue client certificate")
			return
		}
		_ = a.Store.SetEdgeCert(r.Context(), edge.ID, serial, notAfter)
		resp["control_plane_mtls_url"] = a.Cfg.ControlPlaneMTLSURL
		resp["cert_b64"] = base64.StdEncoding.EncodeToString(certPEM)
		resp["key_b64"] = base64.StdEncoding.EncodeToString(keyPEM)
		resp["ca_b64"] = base64.StdEncoding.EncodeToString(a.CA.CertPEM)
	}

	// Bring the new edge into the DNS rotation + LB pools (re-sync proxied zones).
	if a.Domains != nil {
		rc, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		_ = a.Domains.ReconcileEdges(rc)
		cancel()
	}
	_ = a.Store.Audit(r.Context(), nil, nil, "edge.enroll", edge.Name, clientIP(r), map[string]any{"edge_id": edge.ID.String(), "public_ip": edge.PublicIP})

	web.JSON(w, http.StatusOK, resp)
}

func edgeName(n string) string {
	n = strings.ToLower(strings.TrimSpace(n))
	n = nonEdgeName.ReplaceAllString(n, "-")
	n = strings.Trim(n, "-")
	if n == "" {
		return "edge-" + randToken(4)
	}
	if len(n) > 60 {
		n = n[:60]
	}
	return n
}

func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		return strings.TrimSpace(strings.Split(xff, ",")[0])
	}
	host, _, _ := strings.Cut(r.RemoteAddr, ":")
	return host
}

func (a *API) latest(r *http.Request) (*store.ConfigBundle, error) {
	b, err := a.Store.GetLatestBundle(r.Context())
	if errors.Is(err, store.ErrNotFound) {
		return nil, nil
	}
	return b, err
}

// Config delivers the newest config bundle, long-polling (≤25s) when the agent
// is already up to date so changes propagate quickly without busy polling.
func (a *API) Config(w http.ResponseWriter, r *http.Request) {
	since, _ := strconv.ParseInt(r.URL.Query().Get("since"), 10, 64)

	b, err := a.latest(r)
	if err != nil {
		web.Error(w, http.StatusInternalServerError, "internal", "could not load config")
		return
	}
	if b != nil && b.Version > since {
		writeBundle(w, b)
		return
	}

	// Wait for a change poke or timeout, then re-check.
	sub := a.Store.Redis.Subscribe(r.Context(), config.RedisChannel)
	defer sub.Close()
	select {
	case <-sub.Channel():
	case <-time.After(25 * time.Second):
	case <-r.Context().Done():
		return
	}

	b, err = a.latest(r)
	if err != nil {
		web.Error(w, http.StatusInternalServerError, "internal", "could not load config")
		return
	}
	if b != nil && b.Version > since {
		writeBundle(w, b)
		return
	}
	w.WriteHeader(http.StatusNoContent) // unchanged
}

func writeBundle(w http.ResponseWriter, b *store.ConfigBundle) {
	web.JSON(w, http.StatusOK, map[string]any{
		"version":   b.Version,
		"checksum":  b.Checksum,
		"caddyfile": b.Caddyfile,
	})
}

type metricIn struct {
	Domain      string `json:"domain"`
	Requests    int64  `json:"requests"`
	BlockedWAF  int64  `json:"blocked_waf"`
	BlockedRate int64  `json:"blocked_rate"`
	Challenged  int64  `json:"challenged"`
	CacheHits   int64  `json:"cache_hits"`
	CacheMiss   int64  `json:"cache_miss"`
	Bytes       int64  `json:"bytes"`
}

type telemetryIn struct {
	EdgeName      string     `json:"edge_name"`
	PublicIP      string     `json:"public_ip"`
	AgentVersion  string     `json:"agent_version"`
	Status        string     `json:"status"`
	ConfigVersion int64      `json:"config_version"`
	Metrics       []metricIn `json:"metrics"`
}

// Telemetry records an edge heartbeat and its per-domain metrics.
func (a *API) Telemetry(w http.ResponseWriter, r *http.Request) {
	var in telemetryIn
	if err := web.Decode(w, r, &in); err != nil {
		web.Error(w, http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	// An enrolled edge is identified by its per-node token (trusted); the shared
	// all-in-one token falls back to the self-reported edge_name.
	edge := edgeFromCtx(r.Context())
	if edge == nil {
		if in.EdgeName == "" {
			web.Error(w, http.StatusBadRequest, "validation", "edge_name required")
			return
		}
		var err error
		edge, err = a.Store.GetEdgeByName(r.Context(), in.EdgeName)
		if errors.Is(err, store.ErrNotFound) {
			edge, err = a.Store.UpsertEdge(r.Context(), in.EdgeName, in.PublicIP, "default")
		}
		if err != nil {
			web.Error(w, http.StatusInternalServerError, "internal", "could not resolve edge")
			return
		}
	}
	status := in.Status
	if status == "" {
		status = "healthy"
	}
	_ = a.Store.EdgeHeartbeat(r.Context(), edge.ID, in.AgentVersion, status)

	for _, m := range in.Metrics {
		em := &store.EdgeMetric{
			EdgeID:      &edge.ID,
			Requests:    m.Requests,
			BlockedWAF:  m.BlockedWAF,
			BlockedRate: m.BlockedRate,
			Challenged:  m.Challenged,
			CacheHits:   m.CacheHits,
			CacheMiss:   m.CacheMiss,
			Bytes:       m.Bytes,
		}
		if m.Domain != "" {
			if d, err := a.Store.GetDomainByName(r.Context(), m.Domain); err == nil {
				em.DomainID = &d.ID
			}
		}
		_ = a.Store.InsertMetric(r.Context(), em)
	}
	web.JSON(w, http.StatusOK, map[string]any{"ok": true})
}
