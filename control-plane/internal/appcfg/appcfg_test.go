package appcfg

import "testing"

func TestNameserverDefaults(t *testing.T) {
	cases := []struct {
		host, ns1, ns2 string
	}{
		// Bare registrable domain used as the control-plane host.
		{"rtb.st", "ns1.rtb.st", "ns2.rtb.st"},
		// The conventional cp.<domain> host strips the "cp." label.
		{"cp.rtb.st", "ns1.rtb.st", "ns2.rtb.st"},
		{"cp.localtest.me", "ns1.localtest.me", "ns2.localtest.me"},
		// A non-"cp." subdomain is kept as-is.
		{"dashboard.example.com", "ns1.dashboard.example.com", "ns2.dashboard.example.com"},
		// "cp" only strips when it is a whole leading label.
		{"cpanel.example.com", "ns1.cpanel.example.com", "ns2.cpanel.example.com"},
	}
	for _, tc := range cases {
		ns1, ns2 := nameserverDefaults(tc.host)
		if ns1 != tc.ns1 || ns2 != tc.ns2 {
			t.Errorf("nameserverDefaults(%q) = %q,%q; want %q,%q", tc.host, ns1, ns2, tc.ns1, tc.ns2)
		}
	}
}
