package botscore

import "testing"

func TestScoreSignals(t *testing.T) {
	cases := []struct {
		name string
		sig  signals
		want int
	}{
		{"clean", signals{}, 0},
		{"empty UA", signals{uaEmpty: true}, 40},
		{"suspect UA", signals{uaSuspect: true}, 35},
		{"empty beats suspect", signals{uaEmpty: true, uaSuspect: true}, 40},
		{"missing headers", signals{missingAccept: true, missingAcceptLang: true, missingAcceptEnc: true, missingCookies: true, missingSecFetch: true}, 65},
		{"suspect path", signals{suspectPath: true}, 30},
		{"rate low", signals{rate: 61}, 10},
		{"rate mid", signals{rate: 121}, 25},
		{"rate high", signals{rate: 301}, 50},
	}
	for _, c := range cases {
		if got := scoreSignals(c.sig); got != c.want {
			t.Errorf("%s: scoreSignals = %d, want %d", c.name, got, c.want)
		}
	}
}

func TestIsVerifiedBot(t *testing.T) {
	if !isVerifiedBot("mozilla/5.0 (compatible; googlebot/2.1; +http://www.google.com/bot.html)") {
		t.Error("googlebot should be verified")
	}
	if isVerifiedBot("mozilla/5.0 (windows nt 10.0) chrome/120") {
		t.Error("a normal chrome UA is not a verified bot")
	}
}

func TestMatchesSuspectPath(t *testing.T) {
	if !matchesSuspectPath("/wp-login.php") || !matchesSuspectPath("/.env") {
		t.Error("scanner paths should match")
	}
	if matchesSuspectPath("/index.html") {
		t.Error("normal path should not match")
	}
}

func TestThresholds(t *testing.T) {
	c, b := thresholds("high")
	if c != 35 || b != 75 {
		t.Fatalf("high thresholds = %d,%d", c, b)
	}
	c, b = thresholds("unknown") // defaults to medium
	if c != 55 || b != 100 {
		t.Fatalf("default thresholds = %d,%d", c, b)
	}
}
