package agent

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"
)

const rotateCheckInterval = 6 * time.Hour

// rotateLoop renews the per-node client certificate before it expires. It only
// runs when mTLS certs are configured.
func (c Config) rotateLoop(ctx context.Context, log *slog.Logger) {
	if c.CertFile == "" || c.transport == nil {
		return
	}
	t := time.NewTimer(time.Minute) // first check shortly after boot
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		if nb, na, err := certWindow(c.CertFile); err == nil && needsRenewal(nb, na, time.Now()) {
			if err := c.renewCert(ctx); err != nil {
				log.Warn("cert renewal failed", "err", errString(err))
			} else {
				log.Info("renewed client certificate")
			}
		}
		t.Reset(rotateCheckInterval)
	}
}

// needsRenewal reports whether a cert has entered the last third of its lifetime.
func needsRenewal(notBefore, notAfter, now time.Time) bool {
	life := notAfter.Sub(notBefore)
	if life <= 0 {
		return true
	}
	return now.After(notAfter.Add(-life / 3))
}

func certWindow(certFile string) (notBefore, notAfter time.Time, err error) {
	b, err := os.ReadFile(certFile)
	if err != nil {
		return
	}
	blk, _ := pem.Decode(b)
	if blk == nil {
		return notBefore, notAfter, fmt.Errorf("no PEM in %s", certFile)
	}
	crt, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		return
	}
	return crt.NotBefore, crt.NotAfter, nil
}

// renewCert requests a fresh client cert over the current mTLS connection, writes
// it, and drops idle connections so subsequent handshakes use the new cert.
func (c Config) renewCert(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(c.ControlPlaneURL, "/")+"/edge/v1/renew-cert", nil)
	if err != nil {
		return err
	}
	resp, err := c.authedClient(30 * time.Second).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("renew status %d", resp.StatusCode)
	}
	var out struct {
		CertB64 string `json:"cert_b64"`
		KeyB64  string `json:"key_b64"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return err
	}
	cert, err := base64.StdEncoding.DecodeString(out.CertB64)
	if err != nil {
		return err
	}
	key, err := base64.StdEncoding.DecodeString(out.KeyB64)
	if err != nil {
		return err
	}
	// Write key first then cert (both atomically) to minimise any mismatch window.
	if err := writeFileAtomic(c.KeyFile, key, 0o600); err != nil {
		return err
	}
	if err := writeFileAtomic(c.CertFile, cert, 0o644); err != nil {
		return err
	}
	c.transport.CloseIdleConnections()
	return nil
}

func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, perm); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
