package config

import (
	"strings"
	"testing"

	"github.com/aegis/control-plane/internal/appcfg"
	"github.com/aegis/control-plane/internal/store"
)

func TestThreatFeedSnippet_Empty(t *testing.T) {
	if s, ok := threatFeedSnippet(nil); ok || s != "" {
		t.Fatalf("empty input: got (%q,%v), want (\"\",false)", s, ok)
	}
}

func TestThreatFeedSnippet_RendersMatcherAndRespond(t *testing.T) {
	s, ok := threatFeedSnippet([]string{"1.2.3.0/24", "8.8.8.8/32"})
	if !ok {
		t.Fatal("expected ok=true for non-empty input")
	}
	want := "(aegis_threatfeeds) {\n" +
		"\t@aegis_threatfeed remote_ip 1.2.3.0/24 8.8.8.8/32\n" +
		"\trespond @aegis_threatfeed \"Forbidden\" 403\n" +
		"}\n\n"
	if s != want {
		t.Fatalf("snippet mismatch:\n got: %q\nwant: %q", s, want)
	}
}

func TestZoneName(t *testing.T) {
	if got := zoneName("app.example.com"); got != "app_example_com" {
		t.Fatalf("zoneName = %q, want app_example_com", got)
	}
}

func renderSite(t *testing.T, p *store.SecurityPolicy) string {
	t.Helper()
	r := &Renderer{Cfg: &appcfg.Config{EdgeTLSMode: "acme"}}
	var b strings.Builder
	r.writeSite(&b, "app.example.com", p, []string{"http://origin"}, nil, false, nil)
	return b.String()
}

func TestWriteSite_KeyedByHost(t *testing.T) {
	// The site block must be keyed by the record's hostname so the edge selects
	// it by the request Host/SNI (unknown hosts get no site).
	out := renderSite(t, &store.SecurityPolicy{BotProtection: "off", ChallengeMode: "pow"})
	if !strings.HasPrefix(out, "app.example.com {") {
		t.Fatalf("site block must start with the hostname:\n%s", out)
	}
}

func TestWriteSite_UnderAttackChallengesEveryone(t *testing.T) {
	// Under Attack Mode must challenge every visitor even when bot scoring is
	// disabled and the "challenge suspicious traffic" toggle is off.
	out := renderSite(t, &store.SecurityPolicy{
		BotProtection: "off", ChallengeEnabled: false, UnderAttack: true, ChallengeMode: "pow",
	})
	if !strings.Contains(out, "challenge {") || !strings.Contains(out, "under_attack on") {
		t.Fatalf("want challenge block with under_attack on, got:\n%s", out)
	}
	if strings.Contains(out, "botscore {") {
		t.Fatalf("bot protection is off; unexpected botscore:\n%s", out)
	}
}

func TestWriteSite_NoChallengeWhenDisabled(t *testing.T) {
	out := renderSite(t, &store.SecurityPolicy{
		BotProtection: "off", ChallengeEnabled: false, UnderAttack: false, ChallengeMode: "pow",
	})
	if strings.Contains(out, "challenge {") {
		t.Fatalf("did not expect challenge block, got:\n%s", out)
	}
}

func TestWriteSite_SuspiciousOnlyChallengeHasNoUnderAttack(t *testing.T) {
	out := renderSite(t, &store.SecurityPolicy{
		BotProtection: "medium", ChallengeEnabled: true, UnderAttack: false, ChallengeMode: "pow",
	})
	if !strings.Contains(out, "challenge {") {
		t.Fatalf("want challenge block for suspicious traffic, got:\n%s", out)
	}
	if strings.Contains(out, "under_attack on") {
		t.Fatalf("normal mode must not set under_attack on:\n%s", out)
	}
}
