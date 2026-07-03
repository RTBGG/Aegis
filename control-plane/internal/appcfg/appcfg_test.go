package appcfg

import "testing"

func TestNameserverDefaults(t *testing.T) {
	cases := []struct {
		host, ns1, ns2 string
	}{
		// Bare registrable domain used as the control-plane host.
		{"rtb.st", "ns1.rtb.st", "ns2.rtb.st"},
		// Any subdomain collapses to the registrable domain (eTLD+1).
		{"cp.rtb.st", "ns1.rtb.st", "ns2.rtb.st"},
		{"panel.rtb.st", "ns1.rtb.st", "ns2.rtb.st"},
		{"cp.localtest.me", "ns1.localtest.me", "ns2.localtest.me"},
		{"dashboard.example.com", "ns1.example.com", "ns2.example.com"},
		{"cpanel.example.com", "ns1.example.com", "ns2.example.com"},
		// Multi-label public suffixes are handled via the Public Suffix List.
		{"cp.foo.co.uk", "ns1.foo.co.uk", "ns2.foo.co.uk"},
		// A host with no registrable domain is used verbatim.
		{"localhost", "ns1.localhost", "ns2.localhost"},
	}
	for _, tc := range cases {
		ns1, ns2 := nameserverDefaults(tc.host)
		if ns1 != tc.ns1 || ns2 != tc.ns2 {
			t.Errorf("nameserverDefaults(%q) = %q,%q; want %q,%q", tc.host, ns1, ns2, tc.ns1, tc.ns2)
		}
	}
}
