// Package domains implements domain onboarding/verification and DNS record
// management, keeping PowerDNS in sync (substituting edge IPs for proxied records).
package domains

import (
	"context"
	"fmt"
	"net"
	"regexp"
	"sort"
	"strings"

	"github.com/aegis/control-plane/internal/appcfg"
	"github.com/aegis/control-plane/internal/config"
	"github.com/aegis/control-plane/internal/dns"
	"github.com/aegis/control-plane/internal/store"
)

type Service struct {
	Store  *store.Store
	DNS    *dns.Client
	Cfg    *appcfg.Config
	Render *config.Renderer
}

func New(st *store.Store, d *dns.Client, cfg *appcfg.Config, r *config.Renderer) *Service {
	return &Service{Store: st, DNS: d, Cfg: cfg, Render: r}
}

var domainNameRe = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$`)

func validDomainName(name string) bool {
	return len(name) <= 253 && domainNameRe.MatchString(name)
}

func isProxied(r store.DNSRecord) bool {
	return r.Proxied && (r.Type == "A" || r.Type == "AAAA" || r.Type == "CNAME")
}

// lbTTL is the TTL of proxied (load-balanced) records — short so weight changes
// and edge churn propagate quickly.
const lbTTL = 30

// luaWeighted renders the PowerDNS Lua `pickwhashed` expression that splits
// traffic across the edge pool by weight (consistent per client). It falls back
// to the configured edge IP when no edge is eligible.
func (s *Service) luaWeighted(edges []store.Edge) string {
	var parts []string
	for _, e := range edges {
		if e.Weight > 0 {
			parts = append(parts, fmt.Sprintf("{%d,'%s'}", e.Weight, e.PublicIP))
		}
	}
	if len(parts) == 0 {
		parts = append(parts, fmt.Sprintf("{100,'%s'}", s.Cfg.EdgePublicIP))
	}
	return fmt.Sprintf("A \"pickwhashed({%s})\"", strings.Join(parts, ","))
}

// formatContent renders a non-proxied record's content into PowerDNS wire form.
func formatContent(r store.DNSRecord) string {
	switch r.Type {
	case "TXT":
		if strings.HasPrefix(r.Content, "\"") {
			return r.Content
		}
		return "\"" + strings.ReplaceAll(r.Content, "\"", "\\\"") + "\""
	case "CNAME", "NS":
		return dns.Canonical(r.Content)
	case "MX":
		pri := int32(10)
		if r.Priority != nil {
			pri = *r.Priority
		}
		return fmt.Sprintf("%d %s", pri, dns.Canonical(r.Content))
	case "SRV":
		pri := int32(0)
		if r.Priority != nil {
			pri = *r.Priority
		}
		return fmt.Sprintf("%d %s", pri, r.Content)
	default:
		return r.Content
	}
}

type rrKey struct{ name, typ string }

// syncZone reconciles all of a domain's records into PowerDNS. Proxied records
// are published as A records pointing at the edge pool.
func (s *Service) syncZone(ctx context.Context, domain *store.Domain) error {
	// Self-heal: ensure the zone exists (e.g. if PowerDNS was down at creation).
	if err := s.DNS.EnsureZone(ctx, domain.Name, []string{s.Cfg.AssignedNS[0], s.Cfg.AssignedNS[1]}); err != nil {
		return err
	}
	recs, err := s.Store.ListRecords(ctx, domain.ID)
	if err != nil {
		return err
	}
	edges, err := s.Store.ListHealthyEdgesForLB(ctx)
	if err != nil {
		return err
	}
	lua := s.luaWeighted(edges)

	groups := map[rrKey]map[string]struct{}{}
	ttls := map[rrKey]int{}
	proxied := map[string]struct{}{}
	add := func(k rrKey, ttl int, contents ...string) {
		if groups[k] == nil {
			groups[k] = map[string]struct{}{}
		}
		for _, c := range contents {
			groups[k][c] = struct{}{}
		}
		if ttls[k] == 0 {
			ttls[k] = ttl
		}
	}

	for _, r := range recs {
		fqdn := dns.FQDN(domain.Name, r.Name)
		if isProxied(r) {
			proxied[fqdn] = struct{}{} // published as one weighted Lua record below
		} else {
			add(rrKey{fqdn, r.Type}, int(r.TTL), formatContent(r))
		}
	}

	// Proxied hosts resolve to the edge pool via a weighted Lua record. Drop any
	// stale plain A/AAAA (e.g. from before LUA publishing) so only the LUA answers.
	for host := range proxied {
		_ = s.DNS.DeleteRRset(ctx, domain.Name, host, "A")
		_ = s.DNS.DeleteRRset(ctx, domain.Name, host, "AAAA")
		if err := s.DNS.UpsertRRset(ctx, domain.Name, host, "LUA", lbTTL, []string{lua}); err != nil {
			return err
		}
	}
	for k, set := range groups {
		contents := make([]string, 0, len(set))
		for c := range set {
			contents = append(contents, c)
		}
		sort.Strings(contents)
		if err := s.DNS.UpsertRRset(ctx, domain.Name, k.name, k.typ, ttls[k], contents); err != nil {
			return err
		}
	}
	return nil
}

// ReconcileEdges re-publishes every active zone's proxied records against the
// current healthy edge IP set and re-renders edge config. Called when the edge
// fleet changes (e.g. a node enrolls) so new edges join the DNS rotation.
func (s *Service) ReconcileEdges(ctx context.Context) error {
	doms, err := s.Store.ListActiveDomainsForRender(ctx)
	if err != nil {
		return err
	}
	for i := range doms {
		_ = s.syncZone(ctx, &doms[i]) // best-effort per zone
	}
	_, _, _ = s.Render.Rebuild(ctx)
	return nil
}

// fqdnOf returns the fully-qualified host for a record within its zone.
func fqdnOf(zone string, r *store.DNSRecord) string {
	return dns.FQDN(zone, r.Name)
}

// publishedType reports the RR type a record is served as. Proxied records are
// published as a weighted Lua (LUA) record over the edge pool.
func publishedType(r store.DNSRecord) string {
	if isProxied(r) {
		return "LUA"
	}
	return r.Type
}

// verify checks whether the domain delegates to our nameservers. In internal
// (dev) TLS mode it auto-verifies so the local demo can proceed.
func (s *Service) verify(ctx context.Context, domain *store.Domain) (bool, string) {
	resolver := net.Resolver{}
	if nss, err := resolver.LookupNS(ctx, domain.Name); err == nil {
		for _, ns := range nss {
			h := dns.Host(ns.Host)
			if h == dns.Host(s.Cfg.AssignedNS[0]) || h == dns.Host(s.Cfg.AssignedNS[1]) {
				return true, "ns_delegated"
			}
		}
	}
	if s.Cfg.EdgeTLSMode == "internal" {
		return true, "dev_auto_verify"
	}
	return false, "ns_not_delegated"
}
