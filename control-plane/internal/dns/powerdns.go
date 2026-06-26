// Package dns is a thin client for the PowerDNS Authoritative HTTP API plus
// helpers to publish a zone's records (substituting edge IPs for proxied ones).
package dns

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Client talks to a PowerDNS Authoritative server's REST API.
type Client struct {
	base   string
	key    string
	server string
	http   *http.Client
}

func NewClient(baseURL, apiKey string) *Client {
	return &Client{
		base:   strings.TrimRight(baseURL, "/"),
		key:    apiKey,
		server: "localhost",
		http:   &http.Client{Timeout: 10 * time.Second},
	}
}

// Canonical ensures a DNS name is lower-case and fully qualified (trailing dot).
func Canonical(name string) string {
	name = strings.ToLower(strings.TrimSpace(name))
	if name == "" {
		return "."
	}
	if !strings.HasSuffix(name, ".") {
		name += "."
	}
	return name
}

func (c *Client) do(ctx context.Context, method, path string, body any, out any) error {
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+"/api/v1/servers/"+c.server+path, rdr)
	if err != nil {
		return err
	}
	req.Header.Set("X-API-Key", c.key)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("powerdns %s %s: %d %s", method, path, resp.StatusCode, strings.TrimSpace(string(msg)))
	}
	if out != nil {
		return json.NewDecoder(resp.Body).Decode(out)
	}
	return nil
}

// Health verifies the API is reachable.
func (c *Client) Health(ctx context.Context) error {
	return c.do(ctx, http.MethodGet, "/zones?limit=1", nil, nil)
}

// EnsureZone creates a Native zone with the given nameservers if it does not
// already exist. Idempotent: a 409/Conflict is treated as success.
func (c *Client) EnsureZone(ctx context.Context, zone string, nameservers []string) error {
	ns := make([]string, len(nameservers))
	for i, n := range nameservers {
		ns[i] = Canonical(n)
	}
	body := map[string]any{
		"name":        Canonical(zone),
		"kind":        "Native",
		"nameservers": ns,
	}
	err := c.do(ctx, http.MethodPost, "/zones", body, nil)
	if err != nil && strings.Contains(err.Error(), "Conflict") {
		return nil // already exists
	}
	if err != nil && strings.Contains(err.Error(), "409") {
		return nil
	}
	return err
}

func (c *Client) DeleteZone(ctx context.Context, zone string) error {
	return c.do(ctx, http.MethodDelete, "/zones/"+Canonical(zone), nil, nil)
}

type rrRecord struct {
	Content  string `json:"content"`
	Disabled bool   `json:"disabled"`
}

type rrset struct {
	Name       string     `json:"name"`
	Type       string     `json:"type"`
	TTL        int        `json:"ttl"`
	ChangeType string     `json:"changetype"`
	Records    []rrRecord `json:"records"`
}

// UpsertRRset replaces all records of (name,type) in zone with contents.
// contents must already be in PowerDNS wire form (e.g. TXT quoted, targets FQDN).
func (c *Client) UpsertRRset(ctx context.Context, zone, name, rtype string, ttl int, contents []string) error {
	recs := make([]rrRecord, len(contents))
	for i, ct := range contents {
		recs[i] = rrRecord{Content: ct, Disabled: false}
	}
	patch := map[string]any{"rrsets": []rrset{{
		Name: Canonical(name), Type: rtype, TTL: ttl, ChangeType: "REPLACE", Records: recs,
	}}}
	return c.do(ctx, http.MethodPatch, "/zones/"+Canonical(zone), patch, nil)
}

// DeleteRRset removes all records of (name,type) from zone.
func (c *Client) DeleteRRset(ctx context.Context, zone, name, rtype string) error {
	patch := map[string]any{"rrsets": []rrset{{
		Name: Canonical(name), Type: rtype, ChangeType: "DELETE",
	}}}
	return c.do(ctx, http.MethodPatch, "/zones/"+Canonical(zone), patch, nil)
}
