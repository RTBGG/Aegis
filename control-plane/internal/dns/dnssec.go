package dns

import (
	"context"
	"fmt"
	"net/http"
)

// Cryptokey is the subset of a PowerDNS DNSSEC key we consume. The private key
// material PowerDNS returns on creation is intentionally NOT modelled here, so
// it can never be serialised back to a client.
type Cryptokey struct {
	ID        int      `json:"id"`
	KeyType   string   `json:"keytype"`
	Active    bool     `json:"active"`
	Flags     int      `json:"flags"`
	Algorithm string   `json:"algorithm"`
	DNSKEY    string   `json:"dnskey"`
	DS        []string `json:"ds"`
}

// DNSSECInfo summarises a zone's signing state for the dashboard: whether it is
// signed and the DS / DNSKEY records the operator must publish at their registrar.
type DNSSECInfo struct {
	Enabled bool     `json:"enabled"`
	DS      []string `json:"ds"`
	DNSKEY  []string `json:"dnskey"`
}

func (c *Client) listCryptokeys(ctx context.Context, zone string) ([]Cryptokey, error) {
	var out []Cryptokey
	err := c.do(ctx, http.MethodGet, "/zones/"+Canonical(zone)+"/cryptokeys", nil, &out)
	return out, err
}

// addCSK creates and activates a Combined Signing Key, securing the zone.
func (c *Client) addCSK(ctx context.Context, zone string) error {
	body := map[string]any{"keytype": "csk", "active": true}
	return c.do(ctx, http.MethodPost, "/zones/"+Canonical(zone)+"/cryptokeys", body, nil)
}

func (c *Client) deleteCryptokey(ctx context.Context, zone string, id int) error {
	return c.do(ctx, http.MethodDelete, fmt.Sprintf("/zones/%s/cryptokeys/%d", Canonical(zone), id), nil, nil)
}

// dnssecInfo aggregates the DS/DNSKEY of a zone's active keys. Inactive keys
// (e.g. mid-rollover) are ignored.
func dnssecInfo(keys []Cryptokey) *DNSSECInfo {
	info := &DNSSECInfo{}
	for _, k := range keys {
		if !k.Active {
			continue
		}
		info.Enabled = true
		info.DS = append(info.DS, k.DS...)
		if k.DNSKEY != "" {
			info.DNSKEY = append(info.DNSKEY, k.DNSKEY)
		}
	}
	return info
}

// DNSSECStatus reports a zone's signing state and the DS/DNSKEY records of its
// active keys.
func (c *Client) DNSSECStatus(ctx context.Context, zone string) (*DNSSECInfo, error) {
	keys, err := c.listCryptokeys(ctx, zone)
	if err != nil {
		return nil, err
	}
	return dnssecInfo(keys), nil
}

// EnableDNSSEC secures the zone with a CSK if it is not already signed. It is
// idempotent and returns the resulting DS/DNSKEY records.
func (c *Client) EnableDNSSEC(ctx context.Context, zone string) (*DNSSECInfo, error) {
	info, err := c.DNSSECStatus(ctx, zone)
	if err != nil {
		return nil, err
	}
	if info.Enabled {
		return info, nil
	}
	if err := c.addCSK(ctx, zone); err != nil {
		return nil, err
	}
	return c.DNSSECStatus(ctx, zone)
}

// DisableDNSSEC removes every key from the zone, returning it to unsigned. It is
// idempotent (a zone with no keys is a no-op).
func (c *Client) DisableDNSSEC(ctx context.Context, zone string) error {
	keys, err := c.listCryptokeys(ctx, zone)
	if err != nil {
		return err
	}
	for _, k := range keys {
		if err := c.deleteCryptokey(ctx, zone, k.ID); err != nil {
			return err
		}
	}
	return nil
}
