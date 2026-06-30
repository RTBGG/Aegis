// Package pki is a minimal ECDSA certificate authority for per-node edge mTLS:
// a self-signed CA plus server- and client-leaf issuance, all PEM in/out.
package pki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"time"
)

// CA holds a parsed certificate authority used to sign edge/server leaves.
type CA struct {
	Cert    *x509.Certificate
	Key     *ecdsa.PrivateKey
	CertPEM []byte
}

// Generate creates a new self-signed ECDSA CA (10-year lifetime), returning its
// cert and key as PEM.
func Generate() (certPEM, keyPEM []byte, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	serial, err := randSerial()
	if err != nil {
		return nil, nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "Aegis Edge CA", Organization: []string{"Aegis"}},
		NotBefore:             time.Now().Add(-5 * time.Minute),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	return encodeCert(der), encodeKey(key), nil
}

// Load parses a CA from PEM cert+key.
func Load(certPEM, keyPEM []byte) (*CA, error) {
	cb, _ := pem.Decode(certPEM)
	if cb == nil {
		return nil, fmt.Errorf("pki: invalid CA cert PEM")
	}
	cert, err := x509.ParseCertificate(cb.Bytes)
	if err != nil {
		return nil, err
	}
	kb, _ := pem.Decode(keyPEM)
	if kb == nil {
		return nil, fmt.Errorf("pki: invalid CA key PEM")
	}
	key, err := x509.ParsePKCS8PrivateKey(kb.Bytes)
	if err != nil {
		return nil, err
	}
	ecKey, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("pki: CA key is not ECDSA")
	}
	return &CA{Cert: cert, Key: ecKey, CertPEM: certPEM}, nil
}

// Pool returns a cert pool containing the CA, for verifying peers signed by it.
func (ca *CA) Pool() *x509.CertPool {
	p := x509.NewCertPool()
	p.AddCert(ca.Cert)
	return p
}

// IssueServer signs a server leaf (ExtKeyUsageServerAuth) for the given DNS
// names / IPs.
func (ca *CA) IssueServer(dnsNames []string, ips []net.IP, ttl time.Duration) (certPEM, keyPEM []byte, err error) {
	certPEM, keyPEM, _, _, err = ca.issue(&x509.Certificate{
		Subject:     pkix.Name{CommonName: "aegis-control-plane"},
		DNSNames:    dnsNames,
		IPAddresses: ips,
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}, ttl)
	return certPEM, keyPEM, err
}

// IssueClient signs an edge client leaf (ExtKeyUsageClientAuth) whose CommonName
// carries the edge identity (its UUID). It also returns the cert's serial (as a
// decimal string, matching x509 SerialNumber.String()) and expiry, so the caller
// can record the current cert for rotation/revocation checks.
func (ca *CA) IssueClient(commonName string, ttl time.Duration) (certPEM, keyPEM []byte, serial string, notAfter time.Time, err error) {
	return ca.issue(&x509.Certificate{
		Subject:     pkix.Name{CommonName: commonName},
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}, ttl)
}

func (ca *CA) issue(tmpl *x509.Certificate, ttl time.Duration) (certPEM, keyPEM []byte, serial string, notAfter time.Time, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, "", time.Time{}, err
	}
	sn, err := randSerial()
	if err != nil {
		return nil, nil, "", time.Time{}, err
	}
	tmpl.SerialNumber = sn
	tmpl.NotBefore = time.Now().Add(-5 * time.Minute)
	tmpl.NotAfter = time.Now().Add(ttl)
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.Cert, &key.PublicKey, ca.Key)
	if err != nil {
		return nil, nil, "", time.Time{}, err
	}
	return encodeCert(der), encodeKey(key), sn.String(), tmpl.NotAfter, nil
}

func encodeCert(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func encodeKey(key *ecdsa.PrivateKey) []byte {
	der, _ := x509.MarshalPKCS8PrivateKey(key)
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

func randSerial() (*big.Int, error) {
	return rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
}
