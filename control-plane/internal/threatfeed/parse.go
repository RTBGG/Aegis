// Package threatfeed fetches free IP-reputation feeds (Spamhaus DROP, FireHOL
// Level 1, …) on a schedule and stores their CIDRs as a global edge blocklist.
package threatfeed

import (
	"net/netip"
	"sort"
	"strings"
)

// maxEntriesPerFeed caps how many CIDRs we keep from a single feed. It bounds
// memory and the rendered Caddyfile size even if a feed is malformed or hostile.
const maxEntriesPerFeed = 300_000

// ParseCIDRs extracts validated, de-duplicated, sorted CIDR strings from a
// line-based IP-reputation feed. It tolerates FireHOL `.netset` files (one CIDR
// per line, `#` comments) and Spamhaus DROP files (`CIDR ; SBLxxxx`). Bare
// IPv4/IPv6 addresses are normalised to /32 and /128; invalid lines are skipped.
// The second return value is the count of non-blank, non-comment lines that
// were unparseable — useful for observability/alerting on feed-format drift.
func ParseCIDRs(body string) ([]string, int) {
	seen := make(map[string]struct{})
	var out []string
	skipped := 0
	for _, raw := range strings.Split(body, "\n") {
		line := raw
		// Strip inline comments: everything from the first ';' or '#'.
		if i := strings.IndexAny(line, ";#"); i >= 0 {
			line = line[:i]
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		// Keep only the first token (defensive against trailing junk).
		if i := strings.IndexAny(line, " \t"); i >= 0 {
			line = line[:i]
		}
		cidr, ok := normalizeCIDR(line)
		if !ok {
			skipped++
			continue
		}
		if _, dup := seen[cidr]; dup {
			continue
		}
		seen[cidr] = struct{}{}
		out = append(out, cidr)
		if len(out) >= maxEntriesPerFeed {
			break
		}
	}
	sort.Strings(out)
	return out, skipped
}

// normalizeCIDR validates a token as a CIDR (or bare IP) and returns it in
// canonical masked form, e.g. "1.2.3.4/24" -> "1.2.3.0/24", "8.8.8.8" -> "8.8.8.8/32".
func normalizeCIDR(tok string) (string, bool) {
	if strings.Contains(tok, "/") {
		p, err := netip.ParsePrefix(tok)
		if err != nil {
			return "", false
		}
		return p.Masked().String(), true
	}
	addr, err := netip.ParseAddr(tok)
	if err != nil {
		return "", false
	}
	bits := 32
	if addr.Is6() {
		bits = 128
	}
	return netip.PrefixFrom(addr, bits).String(), true
}
