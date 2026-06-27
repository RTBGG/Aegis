package domains

import (
	"net/http"

	"github.com/aegis/control-plane/internal/auth"
	"github.com/aegis/control-plane/internal/web"
)

// GetDNSSEC returns the zone's signing state and DS/DNSKEY records.
func (s *Service) GetDNSSEC(w http.ResponseWriter, r *http.Request) {
	d, ok := s.loadOwnedDomain(w, r)
	if !ok {
		return
	}
	info, err := s.DNS.DNSSECStatus(r.Context(), d.Name)
	if err != nil {
		web.Error(w, http.StatusBadGateway, "dns_error", "could not read DNSSEC status: "+err.Error())
		return
	}
	web.JSON(w, http.StatusOK, map[string]any{"dnssec": info})
}

// EnableDNSSEC signs the zone (idempotent) and returns the DS records the
// operator must publish at their registrar to complete the chain of trust.
func (s *Service) EnableDNSSEC(w http.ResponseWriter, r *http.Request) {
	d, ok := s.loadOwnedDomain(w, r)
	if !ok {
		return
	}
	info, err := s.DNS.EnableDNSSEC(r.Context(), d.Name)
	if err != nil {
		web.Error(w, http.StatusBadGateway, "dns_error", "could not enable DNSSEC: "+err.Error())
		return
	}
	u := auth.MustUser(r.Context())
	_ = s.Store.Audit(r.Context(), &u.AccountID, &u.ID, "dnssec.enable", d.Name, r.RemoteAddr, nil)
	web.JSON(w, http.StatusOK, map[string]any{"dnssec": info})
}

// DisableDNSSEC removes all keys, returning the zone to unsigned.
func (s *Service) DisableDNSSEC(w http.ResponseWriter, r *http.Request) {
	d, ok := s.loadOwnedDomain(w, r)
	if !ok {
		return
	}
	if err := s.DNS.DisableDNSSEC(r.Context(), d.Name); err != nil {
		web.Error(w, http.StatusBadGateway, "dns_error", "could not disable DNSSEC: "+err.Error())
		return
	}
	u := auth.MustUser(r.Context())
	_ = s.Store.Audit(r.Context(), &u.AccountID, &u.ID, "dnssec.disable", d.Name, r.RemoteAddr, nil)
	web.JSON(w, http.StatusOK, map[string]any{"dnssec": map[string]any{"enabled": false}})
}
