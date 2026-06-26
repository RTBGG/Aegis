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

type domainDTO struct {
	ID         string     `json:"id"`
	Name       string     `json:"name"`
	Status     string     `json:"status"`
	Paused     bool       `json:"paused"`
	VerifiedAt *time.Time `json:"verified_at"`
	CreatedAt  time.Time  `json:"created_at"`
}

func toDomainDTO(d *store.Domain) domainDTO {
	return domainDTO{ID: d.ID.String(), Name: d.Name, Status: d.Status, Paused: d.Paused, VerifiedAt: d.VerifiedAt, CreatedAt: d.CreatedAt}
}

func (s *Service) loadOwnedDomain(w http.ResponseWriter, r *http.Request) (*store.Domain, bool) {
	u := auth.MustUser(r.Context())
	id, err := uuid.Parse(chi.URLParam(r, "domainID"))
	if err != nil {
		web.Error(w, http.StatusBadRequest, "bad_id", "invalid domain id")
		return nil, false
	}
	d, err := s.Store.GetDomainOwned(r.Context(), id, u.AccountID)
	if err != nil {
		web.Error(w, http.StatusNotFound, "not_found", "domain not found")
		return nil, false
	}
	return d, true
}

func (s *Service) List(w http.ResponseWriter, r *http.Request) {
	u := auth.MustUser(r.Context())
	ds, err := s.Store.ListDomainsByAccount(r.Context(), u.AccountID)
	if err != nil {
		web.Error(w, http.StatusInternalServerError, "internal", "could not list domains")
		return
	}
	out := make([]domainDTO, len(ds))
	for i := range ds {
		out[i] = toDomainDTO(&ds[i])
	}
	web.JSON(w, http.StatusOK, map[string]any{"domains": out})
}

func (s *Service) Create(w http.ResponseWriter, r *http.Request) {
	u := auth.MustUser(r.Context())
	var in struct {
		Name string `json:"name"`
	}
	if err := web.Decode(w, r, &in); err != nil {
		web.Error(w, http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	name := strings.ToLower(strings.TrimSpace(strings.TrimSuffix(in.Name, ".")))
	if !validDomainName(name) {
		web.Error(w, http.StatusBadRequest, "validation", "invalid domain name")
		return
	}
	if _, err := s.Store.GetDomainByName(r.Context(), name); err == nil {
		web.Error(w, http.StatusConflict, "domain_taken", "domain already registered")
		return
	}
	token := "aegis-verify-" + uuid.NewString()
	d, err := s.Store.CreateDomain(r.Context(), u.AccountID, name, token)
	if err != nil {
		web.Error(w, http.StatusInternalServerError, "internal", "could not create domain")
		return
	}
	if err := s.DNS.EnsureZone(r.Context(), name, []string{s.Cfg.AssignedNS[0], s.Cfg.AssignedNS[1]}); err != nil {
		web.Error(w, http.StatusBadGateway, "dns_error", "could not create DNS zone: "+err.Error())
		return
	}
	_, _ = s.Store.GetOrCreatePolicy(r.Context(), d.ID)
	_ = s.Store.Audit(r.Context(), &u.AccountID, &u.ID, "domain.create", name, "", nil)

	web.JSON(w, http.StatusCreated, map[string]any{
		"domain":      toDomainDTO(d),
		"nameservers": []string{s.Cfg.AssignedNS[0], s.Cfg.AssignedNS[1]},
		"verification": map[string]string{
			"txt_name":  "_aegis-challenge." + name,
			"txt_value": token,
		},
	})
}

func (s *Service) Get(w http.ResponseWriter, r *http.Request) {
	d, ok := s.loadOwnedDomain(w, r)
	if !ok {
		return
	}
	web.JSON(w, http.StatusOK, map[string]any{
		"domain":      toDomainDTO(d),
		"nameservers": []string{s.Cfg.AssignedNS[0], s.Cfg.AssignedNS[1]},
	})
}

func (s *Service) Verify(w http.ResponseWriter, r *http.Request) {
	d, ok := s.loadOwnedDomain(w, r)
	if !ok {
		return
	}
	verified, reason := s.verify(r.Context(), d)
	if !verified {
		web.JSON(w, http.StatusOK, map[string]any{"verified": false, "reason": reason,
			"nameservers": []string{s.Cfg.AssignedNS[0], s.Cfg.AssignedNS[1]}})
		return
	}
	if err := s.Store.MarkDomainVerified(r.Context(), d.ID); err != nil {
		web.Error(w, http.StatusInternalServerError, "internal", "could not mark verified")
		return
	}
	_ = s.syncZone(r.Context(), d)
	_, _, _ = s.Render.Rebuild(r.Context())
	web.JSON(w, http.StatusOK, map[string]any{"verified": true, "reason": reason})
}

func (s *Service) SetPaused(w http.ResponseWriter, r *http.Request) {
	d, ok := s.loadOwnedDomain(w, r)
	if !ok {
		return
	}
	var in struct {
		Paused bool `json:"paused"`
	}
	if err := web.Decode(w, r, &in); err != nil {
		web.Error(w, http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	if err := s.Store.SetDomainPaused(r.Context(), d.ID, in.Paused); err != nil {
		web.Error(w, http.StatusInternalServerError, "internal", "could not update domain")
		return
	}
	_, _, _ = s.Render.Rebuild(r.Context())
	web.JSON(w, http.StatusOK, map[string]any{"paused": in.Paused})
}

func (s *Service) Delete(w http.ResponseWriter, r *http.Request) {
	d, ok := s.loadOwnedDomain(w, r)
	if !ok {
		return
	}
	_ = s.DNS.DeleteZone(r.Context(), d.Name)
	if err := s.Store.DeleteDomain(r.Context(), d.ID); err != nil {
		web.Error(w, http.StatusInternalServerError, "internal", "could not delete domain")
		return
	}
	_, _, _ = s.Render.Rebuild(r.Context())
	web.JSON(w, http.StatusOK, map[string]any{"ok": true})
}
