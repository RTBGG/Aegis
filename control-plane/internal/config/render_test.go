package config

import "testing"

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
