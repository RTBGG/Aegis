package geoip

import (
	"sort"
	"strings"
	"testing"
)

func testDB(t *testing.T, tsv string) *DB {
	t.Helper()
	es, err := parseTSV(strings.NewReader(tsv))
	if err != nil {
		t.Fatalf("parseTSV: %v", err)
	}
	sort.Slice(es, func(i, j int) bool { return es[i].start.Compare(es[j].start) < 0 })
	d := &DB{}
	d.swap(es)
	return d
}

const sampleTSV = "1.0.0.0\t1.0.0.255\t13335\tUS\tCLOUDFLARENET\n" +
	"1.0.1.0\t1.0.3.255\t0\tNone\tNot routed\n" + // skipped (asn 0)
	"8.8.8.0\t8.8.8.255\t15169\tUS\tGOOGLE\n" +
	"2001:4860::\t2001:4860:ffff:ffff:ffff:ffff:ffff:ffff\t15169\tUS\tGOOGLE\n"

func TestParseTSV_SkipsUnrouted(t *testing.T) {
	es, _ := parseTSV(strings.NewReader(sampleTSV))
	if len(es) != 3 {
		t.Fatalf("expected 3 routed entries (asn 0 skipped), got %d", len(es))
	}
}

func TestLookup(t *testing.T) {
	d := testDB(t, sampleTSV)
	cases := []struct {
		ip, cc string
		asn    uint32
		org    string
	}{
		{"8.8.8.8", "US", 15169, "GOOGLE"},
		{"8.8.8.0", "US", 15169, "GOOGLE"},   // start boundary
		{"8.8.8.255", "US", 15169, "GOOGLE"}, // end boundary
		{"1.0.0.50", "US", 13335, "CLOUDFLARENET"},
		{"2001:4860:4860::8888", "US", 15169, "GOOGLE"}, // IPv6
		{"1.0.2.0", "", 0, ""},                          // unrouted (skipped row)
		{"9.9.9.9", "", 0, ""},                          // not in any range
		{"192.168.1.1", "", 0, ""},                      // private
		{"not-an-ip", "", 0, ""},                        // parse error
	}
	for _, c := range cases {
		cc, asn, org := d.Lookup(c.ip)
		if cc != c.cc || asn != c.asn || org != c.org {
			t.Errorf("Lookup(%s) = (%q,%d,%q), want (%q,%d,%q)", c.ip, cc, asn, org, c.cc, c.asn, c.org)
		}
	}
}

func TestLookup_NilSafe(t *testing.T) {
	var d *DB
	if cc, asn, org := d.Lookup("8.8.8.8"); cc != "" || asn != 0 || org != "" {
		t.Fatal("nil DB should return zero values")
	}
}
