package config

import (
	"strings"
	"testing"

	"github.com/aegis/control-plane/internal/store"
)

func ptr(i int32) *int32 { return &i }

func TestWAFOverrideRule(t *testing.T) {
	off, ok := wafOverrideRule(9010000, store.WAFRouteOverride{Path: "/admin", Mode: "off"})
	if !ok || off != `SecRule REQUEST_URI "@beginsWith /admin" "id:9010000,phase:1,pass,nolog,t:none,ctl:ruleEngine=Off"` {
		t.Fatalf("off rule wrong: %q", off)
	}

	excl, ok := wafOverrideRule(9010001, store.WAFRouteOverride{Path: "/api/", Mode: "inherit", ExcludedRules: "942100 942110"})
	if !ok || !strings.Contains(excl, "ctl:ruleRemoveById=942100,ctl:ruleRemoveById=942110") {
		t.Fatalf("exclusion rule wrong: %q", excl)
	}

	par, ok := wafOverrideRule(9010002, store.WAFRouteOverride{Path: "/relaxed", Mode: "detect", Paranoia: ptr(2)})
	if !ok ||
		!strings.Contains(par, "ctl:ruleEngine=DetectionOnly") ||
		!strings.Contains(par, "setvar:tx.blocking_paranoia_level=2") ||
		!strings.Contains(par, "setvar:tx.detection_paranoia_level=2") {
		t.Fatalf("paranoia rule wrong: %q", par)
	}

	if _, ok := wafOverrideRule(9010003, store.WAFRouteOverride{Path: "/x", Mode: "inherit"}); ok {
		t.Fatal("a no-op override should not render a rule")
	}
}

func TestCorazaDirectives(t *testing.T) {
	p := &store.SecurityPolicy{WAFEnabled: true, WAFParanoia: 1, WAFMode: "block",
		WAFCustomRules: "SecAction \"id:5000,phase:1,pass,nolog\""}
	overrides := []store.WAFRouteOverride{{Path: "/admin", Mode: "off"}}

	out := corazaDirectives(p, overrides)
	for _, want := range []string{
		"Include /etc/caddy/coraza/coraza.conf",
		"setvar:tx.blocking_paranoia_level=1",
		`SecRule REQUEST_URI "@beginsWith /admin"`, // override before CRS
		"Include /etc/caddy/coraza/rules/*.conf",
		`SecAction "id:5000,phase:1,pass,nolog"`, // custom rule after CRS
		"SecRuleEngine On",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("directives missing %q\n---\n%s", want, out)
		}
	}
	// Order: override rule must come before the CRS include; custom rule after it.
	if strings.Index(out, "@beginsWith /admin") > strings.Index(out, "rules/*.conf") {
		t.Error("override rule should precede the CRS include")
	}
	if strings.Index(out, "id:5000") < strings.Index(out, "rules/*.conf") {
		t.Error("custom rule should follow the CRS include")
	}
}

func TestParseRuleIDs(t *testing.T) {
	got := parseRuleIDs("942100, 942110 abc 942120")
	want := []string{"942100", "942110", "942120"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("got %v, want %v", got, want)
	}
}
