package pki

import (
	"crypto/x509"
	"encoding/pem"
	"net"
	"testing"
	"time"
)

func loadLeaf(t *testing.T, certPEM []byte) *x509.Certificate {
	t.Helper()
	b, _ := pem.Decode(certPEM)
	if b == nil {
		t.Fatal("invalid leaf PEM")
	}
	c, err := x509.ParseCertificate(b.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func newCA(t *testing.T) *CA {
	t.Helper()
	certPEM, keyPEM, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	ca, err := Load(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	return ca
}

func TestClientCert_VerifiesAndCarriesCN(t *testing.T) {
	ca := newCA(t)
	certPEM, keyPEM, serial, notAfter, err := ca.IssueClient("edge-123", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if len(keyPEM) == 0 {
		t.Fatal("empty key")
	}
	leaf := loadLeaf(t, certPEM)
	if leaf.Subject.CommonName != "edge-123" {
		t.Fatalf("CN = %q, want edge-123", leaf.Subject.CommonName)
	}
	if leaf.SerialNumber.String() != serial {
		t.Fatalf("returned serial %q != cert serial %q", serial, leaf.SerialNumber.String())
	}
	if notAfter.Before(time.Now()) {
		t.Fatal("notAfter should be in the future")
	}
	// A fresh issue has a different serial (no reuse).
	if _, _, s2, _, _ := ca.IssueClient("edge-123", time.Hour); s2 == serial {
		t.Fatal("two issues must have distinct serials")
	}
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:     ca.Pool(),
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		t.Fatalf("client cert should verify against CA: %v", err)
	}
}

func TestServerCert_HasSANs(t *testing.T) {
	ca := newCA(t)
	certPEM, _, err := ca.IssueServer([]string{"api", "cp.example.com"}, []net.IP{net.ParseIP("127.0.0.1")}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	leaf := loadLeaf(t, certPEM)
	if err := leaf.VerifyHostname("api"); err != nil {
		t.Errorf("server cert should be valid for 'api': %v", err)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:     ca.Pool(),
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}); err != nil {
		t.Fatalf("server cert should verify: %v", err)
	}
}

func TestForeignCertRejected(t *testing.T) {
	ca1, ca2 := newCA(t), newCA(t)
	certPEM, _, _, _, _ := ca1.IssueClient("edge-x", time.Hour)
	leaf := loadLeaf(t, certPEM)
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: ca2.Pool(), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err == nil {
		t.Fatal("a cert from a different CA must not verify")
	}
}
