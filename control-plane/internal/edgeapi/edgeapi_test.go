package edgeapi

import (
	"strings"
	"testing"
)

func TestEdgeName(t *testing.T) {
	cases := map[string]string{
		"Edge One":    "edge-one",
		"host_2.fra":  "host-2-fra",
		"--weird--":   "weird",
		"GOOD-name-1": "good-name-1",
	}
	for in, want := range cases {
		if got := edgeName(in); got != want {
			t.Errorf("edgeName(%q) = %q, want %q", in, got, want)
		}
	}
	// Empty/garbage names get a generated fallback.
	if got := edgeName("   "); !strings.HasPrefix(got, "edge-") {
		t.Errorf("edgeName(blank) = %q, want edge-* fallback", got)
	}
	if got := edgeName("!!!"); !strings.HasPrefix(got, "edge-") {
		t.Errorf("edgeName(symbols) = %q, want edge-* fallback", got)
	}
}

func TestHashTokenStable(t *testing.T) {
	if hashToken("abc") != hashToken("abc") {
		t.Fatal("hashToken must be deterministic")
	}
	if hashToken("abc") == hashToken("abd") {
		t.Fatal("different tokens must hash differently")
	}
}
