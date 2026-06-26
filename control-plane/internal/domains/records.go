package domains

import (
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/aegis/control-plane/internal/auth"
	"github.com/aegis/control-plane/internal/store"
	"github.com/aegis/control-plane/internal/web"
)

var allowedRecordTypes = map[string]bool{
	"A": true, "AAAA": true, "CNAME": true, "TXT": true,
	"MX": true, "NS": true, "CAA": true, "SRV": true,
}

type recordDTO struct {
	ID        string    `json:"id"`
	DomainID  string    `json:"domain_id"`
	Type      string    `json:"type"`
	Name      string    `json:"name"`
	Content   string    `json:"content"`
	TTL       int32     `json:"ttl"`
	Priority  *int32    `json:"priority"`
	Proxied   bool      `json:"proxied"`
	UpdatedAt time.Time `json:"updated_at"`
}

func toRecordDTO(r *store.DNSRecord) recordDTO {
	return recordDTO{
		ID: r.ID.String(), DomainID: r.DomainID.String(), Type: r.Type, Name: r.Name,
		Content: r.Content, TTL: r.TTL, Priority: r.Priority, Proxied: r.Proxied, UpdatedAt: r.UpdatedAt,
	}
}

type recordInput struct {
	Type     string `json:"type"`
	Name     string `json:"name"`
	Content  string `json:"content"`
	TTL      int32  `json:"ttl"`
	Priority *int32 `json:"priority"`
	Proxied  bool   `json:"proxied"`
}

func (in *recordInput) normaliseAndValidate() (string, bool) {
	in.Type = strings.ToUpper(strings.TrimSpace(in.Type))
	in.Name = strings.ToLower(strings.TrimSpace(in.Name))
	in.Content = strings.TrimSpace(in.Content)
	if in.Name == "" {
		in.Name = "@"
	}
	if !allowedRecordTypes[in.Type] {
		return "unsupported record type", false
	}
	if in.Content == "" {
		return "content is required", false
	}
	if in.TTL == 0 {
		in.TTL = 300
	}
	if in.TTL < 60 {
		in.TTL = 60
	}
	if in.TTL > 86400 {
		in.TTL = 86400
	}
	if in.Proxied && in.Type != "A" && in.Type != "AAAA" && in.Type != "CNAME" {
		return "only A, AAAA and CNAME records can be proxied", false
	}
	return "", true
}

func (s *Service) loadOwnedRecord(w http.ResponseWriter, r *http.Request) (*store.DNSRecord, *store.Domain, bool) {
	u := auth.MustUser(r.Context())
	id, err := uuid.Parse(chi.URLParam(r, "recordID"))
	if err != nil {
		web.Error(w, http.StatusBadRequest, "bad_id", "invalid record id")
		return nil, nil, false
	}
	rec, err := s.Store.GetRecord(r.Context(), id)
	if err != nil {
		web.Error(w, http.StatusNotFound, "not_found", "record not found")
		return nil, nil, false
	}
	domain, err := s.Store.GetDomainOwned(r.Context(), rec.DomainID, u.AccountID)
	if err != nil {
		web.Error(w, http.StatusNotFound, "not_found", "record not found")
		return nil, nil, false
	}
	return rec, domain, true
}

func (s *Service) ListRecords(w http.ResponseWriter, r *http.Request) {
	d, ok := s.loadOwnedDomain(w, r)
	if !ok {
		return
	}
	recs, err := s.Store.ListRecords(r.Context(), d.ID)
	if err != nil {
		web.Error(w, http.StatusInternalServerError, "internal", "could not list records")
		return
	}
	out := make([]recordDTO, len(recs))
	for i := range recs {
		out[i] = toRecordDTO(&recs[i])
	}
	web.JSON(w, http.StatusOK, map[string]any{"records": out})
}

func (s *Service) CreateRecord(w http.ResponseWriter, r *http.Request) {
	d, ok := s.loadOwnedDomain(w, r)
	if !ok {
		return
	}
	var in recordInput
	if err := web.Decode(w, r, &in); err != nil {
		web.Error(w, http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	if msg, ok := in.normaliseAndValidate(); !ok {
		web.Error(w, http.StatusBadRequest, "validation", msg)
		return
	}
	rec, err := s.Store.CreateRecord(r.Context(), &store.DNSRecord{
		DomainID: d.ID, Type: in.Type, Name: in.Name, Content: in.Content,
		TTL: in.TTL, Priority: in.Priority, Proxied: in.Proxied,
	})
	if err != nil {
		web.Error(w, http.StatusInternalServerError, "internal", "could not create record")
		return
	}
	if err := s.syncZone(r.Context(), d); err != nil {
		web.Error(w, http.StatusBadGateway, "dns_error", "record saved but DNS sync failed: "+err.Error())
		return
	}
	_, _, _ = s.Render.Rebuild(r.Context())
	web.JSON(w, http.StatusCreated, map[string]any{"record": toRecordDTO(rec)})
}

func (s *Service) UpdateRecord(w http.ResponseWriter, r *http.Request) {
	old, d, ok := s.loadOwnedRecord(w, r)
	if !ok {
		return
	}
	var in recordInput
	if err := web.Decode(w, r, &in); err != nil {
		web.Error(w, http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	if msg, ok := in.normaliseAndValidate(); !ok {
		web.Error(w, http.StatusBadRequest, "validation", msg)
		return
	}
	oldFQDN := fqdnOf(d.Name, old)
	oldType := publishedType(*old)

	updated := *old
	updated.Type, updated.Name, updated.Content = in.Type, in.Name, in.Content
	updated.TTL, updated.Priority, updated.Proxied = in.TTL, in.Priority, in.Proxied
	rec, err := s.Store.UpdateRecord(r.Context(), &updated)
	if err != nil {
		web.Error(w, http.StatusInternalServerError, "internal", "could not update record")
		return
	}

	newFQDN := fqdnOf(d.Name, rec)
	if oldFQDN != newFQDN || oldType != publishedType(*rec) {
		_ = s.DNS.DeleteRRset(r.Context(), d.Name, oldFQDN, oldType)
	}
	if err := s.syncZone(r.Context(), d); err != nil {
		web.Error(w, http.StatusBadGateway, "dns_error", "record saved but DNS sync failed: "+err.Error())
		return
	}
	_, _, _ = s.Render.Rebuild(r.Context())
	web.JSON(w, http.StatusOK, map[string]any{"record": toRecordDTO(rec)})
}

func (s *Service) DeleteRecord(w http.ResponseWriter, r *http.Request) {
	rec, d, ok := s.loadOwnedRecord(w, r)
	if !ok {
		return
	}
	if err := s.Store.DeleteRecord(r.Context(), rec.ID); err != nil {
		web.Error(w, http.StatusInternalServerError, "internal", "could not delete record")
		return
	}
	_ = s.DNS.DeleteRRset(r.Context(), d.Name, fqdnOf(d.Name, rec), publishedType(*rec))
	_ = s.syncZone(r.Context(), d) // re-add any siblings sharing the rrset
	_, _, _ = s.Render.Rebuild(r.Context())
	web.JSON(w, http.StatusOK, map[string]any{"ok": true})
}
