package security

import (
	"fmt"
	"strings"
)

const maxCustomRulesLen = 20000

// allowedDirectives is the whitelist of SecLang directives a tenant may import.
// It deliberately excludes anything that does I/O, fetches remote content, or
// changes engine-wide behaviour (Include, SecRuleEngine, SecRemoteRules,
// SecAuditLog*, Sec*Dir, SecDebugLog*, …), which could break or subvert the
// shared edge WAF.
var allowedDirectives = map[string]bool{
	"secrule":                  true,
	"secaction":                true,
	"secmarker":                true,
	"secruleremovebyid":        true,
	"secruleremovebytag":       true,
	"secruleupdateactionbyid":  true,
	"secruleupdatetargetbyid":  true,
	"secruleupdatetargetbytag": true,
}

// validateCustomSecRules checks operator-supplied SecLang against the directive
// allowlist and for gross syntax errors. A bad rule must be rejected here: it is
// rendered into the shared Caddyfile and a parse failure at the edge would stall
// config application for every domain (Caddy keeps the last-good config).
func validateCustomSecRules(s string) error {
	if len(s) > maxCustomRulesLen {
		return fmt.Errorf("custom rules too long (max %d characters)", maxCustomRulesLen)
	}
	if strings.ContainsRune(s, '`') {
		return fmt.Errorf("custom rules must not contain backticks")
	}
	for _, d := range splitDirectives(s) {
		d = strings.TrimSpace(d)
		if d == "" || strings.HasPrefix(d, "#") {
			continue
		}
		directive := strings.ToLower(strings.Fields(d)[0])
		if !allowedDirectives[directive] {
			return fmt.Errorf("directive %q is not permitted; allowed: SecRule, SecAction, SecMarker, "+
				"SecRuleRemoveById, SecRuleRemoveByTag, SecRuleUpdateActionById, SecRuleUpdateTargetById, SecRuleUpdateTargetByTag",
				strings.Fields(d)[0])
		}
		if countUnescapedQuotes(d)%2 != 0 {
			return fmt.Errorf("unbalanced double-quotes in directive %q", strings.Fields(d)[0])
		}
	}
	return nil
}

// splitDirectives joins backslash-continued lines into logical SecLang directives.
func splitDirectives(s string) []string {
	var dirs []string
	var cur strings.Builder
	for _, raw := range strings.Split(s, "\n") {
		line := strings.TrimRight(raw, "\r")
		if trimmed := strings.TrimRight(line, " \t"); strings.HasSuffix(trimmed, "\\") {
			cur.WriteString(strings.TrimSuffix(trimmed, "\\"))
			cur.WriteByte(' ')
			continue
		}
		cur.WriteString(line)
		dirs = append(dirs, cur.String())
		cur.Reset()
	}
	if cur.Len() > 0 {
		dirs = append(dirs, cur.String())
	}
	return dirs
}

func countUnescapedQuotes(s string) int {
	n := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '"' && (i == 0 || s[i-1] != '\\') {
			n++
		}
	}
	return n
}

// normalizeRuleIDs validates a free-form list of CRS rule IDs and returns them
// space-joined. Every token must be numeric.
func normalizeRuleIDs(s string) (string, error) {
	var ids []string
	for _, tok := range strings.FieldsFunc(s, func(r rune) bool { return r == ' ' || r == ',' || r == '\t' || r == '\n' }) {
		for _, c := range tok {
			if c < '0' || c > '9' {
				return "", fmt.Errorf("excluded rule ID %q must be numeric", tok)
			}
		}
		ids = append(ids, tok)
	}
	return strings.Join(ids, " "), nil
}

// validateWAFPath ensures a route-override path is a safe URL path prefix.
func validateWAFPath(p string) error {
	if p == "" || !strings.HasPrefix(p, "/") {
		return fmt.Errorf("path must start with '/'")
	}
	if len(p) > 200 {
		return fmt.Errorf("path too long")
	}
	if strings.ContainsAny(p, "\"` \t\r\n") {
		return fmt.Errorf("path must not contain quotes, backticks or whitespace")
	}
	return nil
}
