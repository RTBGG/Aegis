package domains

import (
	"context"
	"net"
	"strings"
	"time"

	"github.com/aegis/control-plane/internal/dns"
	"github.com/aegis/control-plane/internal/store"
)

// Resolver abstracts the DNS lookups used for domain verification. In
// production it is *net.Resolver; tests inject a fake.
type Resolver interface {
	LookupTXT(ctx context.Context, name string) ([]string, error)
	LookupNS(ctx context.Context, name string) ([]*net.NS, error)
	LookupCNAME(ctx context.Context, host string) (string, error)
}

// verifyAttempts bounds how many DNS lookups verification performs, spaced by
// Service.VerifyRetry, to tolerate propagation delays and transient failures.
const verifyAttempts = 3

// verify reports whether the domain is connected/owned by the caller.
//   - ns mode: the domain's NS records must include one of our nameservers.
//   - cname mode: proof via the _aegis-challenge TXT token, or a CNAME from the
//     registered host to CNAME_TARGET (useful for subdomain-only onboarding).
//
// In internal (dev) TLS mode a failed check auto-verifies so local testing
// without public DNS still works.
func (s *Service) verify(ctx context.Context, domain *store.Domain) (bool, string) {
	switch domain.DNSMode {
	case "cname":
		if ok, reason := s.verifyCNAME(ctx, domain); ok {
			return true, reason
		}
		if s.Cfg.EdgeTLSMode == "internal" {
			return true, "dev_auto_verify"
		}
		return false, "cname_not_verified"
	default:
		if ok, reason := s.verifyNS(ctx, domain); ok {
			return true, reason
		}
		if s.Cfg.EdgeTLSMode == "internal" {
			return true, "dev_auto_verify"
		}
		return false, "ns_not_delegated"
	}
}

func (s *Service) verifyNS(ctx context.Context, domain *store.Domain) (bool, string) {
	for attempt := 0; attempt < verifyAttempts; attempt++ {
		nss, err := s.Resolver.LookupNS(ctx, domain.Name)
		if err == nil {
			for _, ns := range nss {
				h := dns.Host(ns.Host)
				if h == dns.Host(s.Cfg.AssignedNS[0]) || h == dns.Host(s.Cfg.AssignedNS[1]) {
					return true, "ns_delegated"
				}
			}
		}
		if !sleepCtx(ctx, s.VerifyRetry) {
			break
		}
	}
	return false, "ns_not_delegated"
}

func (s *Service) verifyCNAME(ctx context.Context, domain *store.Domain) (bool, string) {
	txtName := "_aegis-challenge." + domain.Name
	for attempt := 0; attempt < verifyAttempts; attempt++ {
		// 1) Preferred: prove ownership with the token in a TXT record.
		if txts, err := s.Resolver.LookupTXT(ctx, txtName); err == nil {
			for _, t := range txts {
				if strings.TrimSpace(t) == domain.VerificationToken {
					return true, "txt_verified"
				}
			}
		}
		// 2) Fallback: the registered host itself is a CNAME to our target (the
		//    natural proof when onboarding a single subdomain).
		if cn, err := s.Resolver.LookupCNAME(ctx, domain.Name); err == nil {
			if dns.Host(cn) == dns.Host(s.Cfg.CNAMETarget) {
				return true, "cname_verified"
			}
		}
		if !sleepCtx(ctx, s.VerifyRetry) {
			break
		}
	}
	return false, "cname_not_verified"
}

func sleepCtx(ctx context.Context, d time.Duration) bool {
	if d <= 0 {
		return true
	}
	select {
	case <-ctx.Done():
		return false
	case <-time.After(d):
		return true
	}
}
