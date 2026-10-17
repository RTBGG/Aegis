package domains

import (
	"context"
	"errors"
	"net"
	"testing"

	"github.com/aegis/control-plane/internal/appcfg"
	"github.com/aegis/control-plane/internal/store"
)

type fakeResolver struct {
	lookupTXT   func(context.Context, string) ([]string, error)
	lookupNS    func(context.Context, string) ([]*net.NS, error)
	lookupCNAME func(context.Context, string) (string, error)
}

func (f fakeResolver) LookupTXT(ctx context.Context, n string) ([]string, error) {
	if f.lookupTXT != nil {
		return f.lookupTXT(ctx, n)
	}
	return nil, errors.New("no such host")
}
func (f fakeResolver) LookupNS(ctx context.Context, n string) ([]*net.NS, error) {
	if f.lookupNS != nil {
		return f.lookupNS(ctx, n)
	}
	return nil, errors.New("no such host")
}
func (f fakeResolver) LookupCNAME(ctx context.Context, h string) (string, error) {
	if f.lookupCNAME != nil {
		return f.lookupCNAME(ctx, h)
	}
	return "", errors.New("no such host")
}

func testService(res Resolver, tlsMode string) *Service {
	return &Service{
		Cfg: &appcfg.Config{
			AssignedNS:  [2]string{"ns1.example.com", "ns2.example.com"},
			CNAMETarget: "edge.example.com",
			EdgeTLSMode: tlsMode,
		},
		Resolver:    res,
		VerifyRetry: 0,
	}
}

func TestVerifyNSDelegated(t *testing.T) {
	res := fakeResolver{lookupNS: func(context.Context, string) ([]*net.NS, error) {
		return []*net.NS{{Host: "ns1.example.com."}, {Host: "ns9.example.com."}}, nil
	}}
	ok, reason := testService(res, "acme").verify(context.Background(),
		&store.Domain{Name: "customer.com", DNSMode: "ns"})
	if !ok || reason != "ns_delegated" {
		t.Fatalf("got (%v,%q), want (true, ns_delegated)", ok, reason)
	}
}

func TestVerifyNSSiteNotDelegated(t *testing.T) {
	res := fakeResolver{lookupNS: func(context.Context, string) ([]*net.NS, error) {
		return []*net.NS{{Host: "ns.other.example."}}, nil
	}}
	ok, reason := testService(res, "acme").verify(context.Background(),
		&store.Domain{Name: "customer.com", DNSMode: "ns"})
	if ok || reason != "ns_not_delegated" {
		t.Fatalf("got (%v,%q), want (false, ns_not_delegated)", ok, reason)
	}
}

func TestVerifyNSDevAutoVerify(t *testing.T) {
	res := fakeResolver{} // every lookup fails
	ok, reason := testService(res, "internal").verify(context.Background(),
		&store.Domain{Name: "customer.com", DNSMode: "ns"})
	if !ok || reason != "dev_auto_verify" {
		t.Fatalf("got (%v,%q), want (true, dev_auto_verify)", ok, reason)
	}
}

func TestVerifyCNAMEViaTXT(t *testing.T) {
	res := fakeResolver{lookupTXT: func(_ context.Context, name string) ([]string, error) {
		if name != "_aegis-challenge.app.customer.com" {
			t.Errorf("looked up %q, want the challenge name", name)
		}
		return []string{"aegis-verify-token"}, nil
	}}
	ok, reason := testService(res, "acme").verify(context.Background(),
		&store.Domain{Name: "app.customer.com", DNSMode: "cname", VerificationToken: "aegis-verify-token"})
	if !ok || reason != "txt_verified" {
		t.Fatalf("got (%v,%q), want (true, txt_verified)", ok, reason)
	}
}

func TestVerifyCNAMEWrongTXTFallsBackToCNAME(t *testing.T) {
	res := fakeResolver{
		lookupTXT: func(context.Context, string) ([]string, error) { return []string{"wrong"}, nil },
		lookupCNAME: func(_ context.Context, h string) (string, error) {
			return "edge.example.com.", nil
		},
	}
	ok, reason := testService(res, "acme").verify(context.Background(),
		&store.Domain{Name: "app.customer.com", DNSMode: "cname", VerificationToken: "tok"})
	if !ok || reason != "cname_verified" {
		t.Fatalf("got (%v,%q), want (true, cname_verified)", ok, reason)
	}
}

func TestVerifyCNAMEDenied(t *testing.T) {
	res := fakeResolver{
		lookupTXT:   func(context.Context, string) ([]string, error) { return []string{"wrong"}, nil },
		lookupCNAME: func(context.Context, string) (string, error) { return "somewhere.else.", nil },
	}
	ok, reason := testService(res, "acme").verify(context.Background(),
		&store.Domain{Name: "app.customer.com", DNSMode: "cname", VerificationToken: "tok"})
	if ok || reason != "cname_not_verified" {
		t.Fatalf("got (%v,%q), want (false, cname_not_verified)", ok, reason)
	}
}

func TestVerifyCNAMEDevAutoVerify(t *testing.T) {
	res := fakeResolver{}
	ok, reason := testService(res, "internal").verify(context.Background(),
		&store.Domain{Name: "app.customer.com", DNSMode: "cname", VerificationToken: "tok"})
	if !ok || reason != "dev_auto_verify" {
		t.Fatalf("got (%v,%q), want (true, dev_auto_verify)", ok, reason)
	}
}

func TestVerifyCNAMERetriesTransientFailure(t *testing.T) {
	calls := 0
	res := fakeResolver{lookupTXT: func(context.Context, string) ([]string, error) {
		calls++
		if calls == 1 {
			return nil, &net.DNSError{Err: "temporary", IsTemporary: true}
		}
		return []string{"tok"}, nil
	}}
	ok, reason := testService(res, "acme").verify(context.Background(),
		&store.Domain{Name: "app.customer.com", DNSMode: "cname", VerificationToken: "tok"})
	if !ok || reason != "txt_verified" {
		t.Fatalf("got (%v,%q), want (true, txt_verified) after retry", ok, reason)
	}
	if calls < 2 {
		t.Fatalf("expected a retry, got %d call(s)", calls)
	}
}

func TestVerifyCNAMEIgnoresNonMatchingAndErrors(t *testing.T) {
	// DNS errors must not panic and must result in a negative verdict in acme mode.
	res := fakeResolver{
		lookupTXT:   func(context.Context, string) ([]string, error) { return nil, errors.New("timeout") },
		lookupCNAME: func(context.Context, string) (string, error) { return "", errors.New("servfail") },
	}
	ok, reason := testService(res, "acme").verify(context.Background(),
		&store.Domain{Name: "app.customer.com", DNSMode: "cname", VerificationToken: "tok"})
	if ok || reason != "cname_not_verified" {
		t.Fatalf("got (%v,%q), want (false, cname_not_verified)", ok, reason)
	}
}

func TestValidDNSMode(t *testing.T) {
	for _, m := range []string{"ns", "cname"} {
		if !validDNSMode(m) {
			t.Errorf("validDNSMode(%q) = false", m)
		}
	}
	for _, m := range []string{"", "NS", "A", "alias", "cname "} {
		if validDNSMode(m) {
			t.Errorf("validDNSMode(%q) = true", m)
		}
	}
}
