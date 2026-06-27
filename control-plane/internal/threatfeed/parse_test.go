package threatfeed

import (
	"fmt"
	"reflect"
	"testing"
)

func TestParseCIDRs_Formats(t *testing.T) {
	// Mixed Spamhaus DROP (CIDR ; comment) and FireHOL netset (# comments) lines,
	// a bare IP, a duplicate (in unmasked form), and two invalid lines.
	body := `; Spamhaus DROP List 2026/06/27
# FireHOL header line
1.10.16.0/20 ; SBL256894
192.0.2.0/24
8.8.8.8
1.10.16.255/20 ; duplicate of the first range once masked
not-an-ip

203.0.113.7/33`

	got, skipped := ParseCIDRs(body)
	want := []string{"1.10.16.0/20", "192.0.2.0/24", "8.8.8.8/32"}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ParseCIDRs got %v, want %v", got, want)
	}
	if skipped != 2 { // "not-an-ip" and the out-of-range /33
		t.Fatalf("skipped = %d, want 2", skipped)
	}
}

func TestParseCIDRs_MasksAndSorts(t *testing.T) {
	got, _ := ParseCIDRs("10.0.0.5/8\n2.2.2.2/16\n")
	want := []string{"10.0.0.0/8", "2.2.0.0/16"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestParseCIDRs_IPv6(t *testing.T) {
	got, _ := ParseCIDRs("2001:db8:abcd::/48\n2001:db8::1\n")
	// Lexicographic sort: ':' (0x3a) sorts before 'a' (0x61).
	want := []string{"2001:db8::1/128", "2001:db8:abcd::/48"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestParseCIDRs_Empty(t *testing.T) {
	got, skipped := ParseCIDRs("# only comments\n;and more\n\n")
	if len(got) != 0 || skipped != 0 {
		t.Fatalf("got %v skipped %d, want empty/0", got, skipped)
	}
}

func TestParseCIDRs_DedupesAcrossForms(t *testing.T) {
	got, _ := ParseCIDRs("1.2.3.0/24\n1.2.3.4/24\n1.2.3.255/24\n")
	if len(got) != 1 {
		t.Fatalf("expected 1 deduped entry, got %v", got)
	}
}

func ExampleParseCIDRs() {
	cidrs, _ := ParseCIDRs("203.0.113.0/24 ; SBL1\n198.51.100.7\n")
	fmt.Println(cidrs)
	// Output: [198.51.100.7/32 203.0.113.0/24]
}
