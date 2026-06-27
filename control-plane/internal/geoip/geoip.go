// Package geoip enriches analytics events with country + ASN using the free,
// public-domain (PDDL) iptoasn.com IP-to-ASN database. The DB is loaded into a
// sorted in-memory range table and refreshed on a schedule.
package geoip

import (
	"bufio"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// maxEntries caps the loaded range count as a safety bound.
const maxEntries = 4_000_000

type entry struct {
	start, end netip.Addr
	cc         string
	asn        uint32
	org        string
}

// DB is a concurrency-safe IP→(country, ASN) lookup table.
type DB struct {
	mu      sync.RWMutex
	entries []entry // sorted by start; IPv4 sorts before IPv6
}

// Lookup returns the country code, ASN and AS org for an IP, or zero values when
// unknown (private/unrouted IPs, parse errors, or DB not loaded).
func (d *DB) Lookup(ipStr string) (cc string, asn uint32, org string) {
	if d == nil {
		return
	}
	addr, err := netip.ParseAddr(strings.TrimSpace(ipStr))
	if err != nil {
		return
	}
	addr = addr.Unmap()
	d.mu.RLock()
	es := d.entries
	d.mu.RUnlock()

	// Last range whose start <= addr, then confirm addr <= end.
	i := sort.Search(len(es), func(i int) bool { return es[i].start.Compare(addr) > 0 }) - 1
	if i >= 0 && addr.Compare(es[i].end) <= 0 {
		return es[i].cc, es[i].asn, es[i].org
	}
	return
}

// Loaded reports whether the DB has data.
func (d *DB) Loaded() bool {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return len(d.entries) > 0
}

func (d *DB) swap(es []entry) {
	d.mu.Lock()
	d.entries = es
	d.mu.Unlock()
}

// Syncer downloads and periodically refreshes the GeoIP DB.
type Syncer struct {
	db   *DB
	v4   string
	v6   string
	http *http.Client
	log  *slog.Logger
}

const refreshInterval = 24 * time.Hour

func New(v4url, v6url string) *Syncer {
	return &Syncer{
		db:   &DB{},
		v4:   v4url,
		v6:   v6url,
		http: &http.Client{Timeout: 90 * time.Second},
		log:  slog.Default(),
	}
}

// DB returns the lookup table (safe to use before the first load — Lookup just
// returns empty values until data arrives).
func (s *Syncer) DB() *DB { return s.db }

// Run loads the DB immediately, then refreshes on a schedule until ctx is done.
func (s *Syncer) Run(ctx context.Context) {
	s.refresh(ctx)
	t := time.NewTicker(refreshInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.refresh(ctx)
		}
	}
}

func (s *Syncer) refresh(ctx context.Context) {
	var all []entry
	for _, u := range []string{s.v4, s.v6} {
		if u == "" {
			continue
		}
		es, err := s.load(ctx, u)
		if err != nil {
			s.log.Warn("geoip: load failed", "url", u, "err", err)
			return // keep the previous good table
		}
		all = append(all, es...)
	}
	if len(all) == 0 {
		return
	}
	sort.Slice(all, func(i, j int) bool { return all[i].start.Compare(all[j].start) < 0 })
	s.db.swap(all)
	s.log.Info("geoip: loaded", "entries", len(all))
}

func (s *Syncer) load(ctx context.Context, url string) ([]entry, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := s.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status %d", resp.StatusCode)
	}
	var r io.Reader = resp.Body
	if strings.HasSuffix(url, ".gz") {
		gz, err := gzip.NewReader(resp.Body)
		if err != nil {
			return nil, err
		}
		defer gz.Close()
		r = gz
	}
	return parseTSV(r)
}

// parseTSV parses iptoasn TSV rows: start_ip <tab> end_ip <tab> asn <tab>
// country <tab> as_description. Unrouted rows (asn 0) are skipped.
func parseTSV(r io.Reader) ([]entry, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	var out []entry
	for sc.Scan() {
		f := strings.Split(sc.Text(), "\t")
		if len(f) < 3 {
			continue
		}
		start, err := netip.ParseAddr(f[0])
		if err != nil {
			continue
		}
		end, err := netip.ParseAddr(f[1])
		if err != nil {
			continue
		}
		asn, err := strconv.ParseUint(f[2], 10, 32)
		if err != nil || asn == 0 {
			continue
		}
		e := entry{start: start.Unmap(), end: end.Unmap(), asn: uint32(asn)}
		if len(f) >= 4 && f[3] != "None" {
			e.cc = f[3]
		}
		if len(f) >= 5 {
			e.org = f[4]
		}
		out = append(out, e)
		if len(out) >= maxEntries {
			break
		}
	}
	return out, sc.Err()
}
