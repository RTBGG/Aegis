package security

import "testing"

func TestValidateCustomSecRules_Allowed(t *testing.T) {
	ok := []string{
		"",
		"# just a comment\n",
		`SecRule ARGS "@rx evil" "id:1000,phase:2,deny,status:403"`,
		"SecAction \"id:1001,phase:1,pass,nolog\"\nSecRuleRemoveById 942100",
		// line continuation
		"SecRule ARGS \"@rx x\" \\\n  \"id:1002,phase:2,deny\"",
	}
	for _, s := range ok {
		if err := validateCustomSecRules(s); err != nil {
			t.Errorf("expected valid, got error for %q: %v", s, err)
		}
	}
}

func TestValidateCustomSecRules_Rejected(t *testing.T) {
	bad := map[string]string{
		"include":         "Include /etc/passwd",
		"engine":          "SecRuleEngine Off",
		"remote":          `SecRemoteRules key https://evil.test/rules`,
		"audit":           "SecAuditLog /var/log/x",
		"backtick":        "SecAction \"id:1,`whoami`\"",
		"unbalanced":      `SecRule ARGS "@rx x "id:1,deny"`,
		"sneaky_via_cont": "SecAction \"id:1,pass\"\nInclude /etc/passwd",
	}
	for name, s := range bad {
		if err := validateCustomSecRules(s); err == nil {
			t.Errorf("%s: expected rejection, got nil for %q", name, s)
		}
	}
}

func TestValidateWAFPath(t *testing.T) {
	good := []string{"/", "/api", "/api/v1/users"}
	for _, p := range good {
		if err := validateWAFPath(p); err != nil {
			t.Errorf("path %q should be valid: %v", p, err)
		}
	}
	bad := []string{"", "api", "/has space", "/has\"quote", "/back`tick"}
	for _, p := range bad {
		if err := validateWAFPath(p); err == nil {
			t.Errorf("path %q should be rejected", p)
		}
	}
}

func TestNormalizeRuleIDs(t *testing.T) {
	got, err := normalizeRuleIDs("942100, 942110\t942120")
	if err != nil || got != "942100 942110 942120" {
		t.Fatalf("got %q, %v", got, err)
	}
	if _, err := normalizeRuleIDs("942100 notanid"); err == nil {
		t.Fatal("expected error for non-numeric rule id")
	}
	if got, _ := normalizeRuleIDs(""); got != "" {
		t.Fatalf("empty should yield empty, got %q", got)
	}
}
