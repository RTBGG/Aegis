package dns

import "strings"

// Host strips a trailing dot from a DNS name (for use as a Caddy site address).
func Host(name string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), ".")
}

// FQDN resolves a record name within a zone to a fully-qualified host with no
// trailing dot. "@"/"" -> zone apex; short names are suffixed with the zone.
func FQDN(zone, name string) string {
	zone = Host(zone)
	name = Host(name)
	switch {
	case name == "" || name == "@":
		return zone
	case name == zone || strings.HasSuffix(name, "."+zone):
		return name
	default:
		return name + "." + zone
	}
}
