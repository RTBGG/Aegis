package dns

import (
	"reflect"
	"testing"
)

func TestDNSSECInfo_Unsigned(t *testing.T) {
	info := dnssecInfo(nil)
	if info.Enabled || len(info.DS) != 0 || len(info.DNSKEY) != 0 {
		t.Fatalf("empty key set should be unsigned, got %+v", info)
	}
}

func TestDNSSECInfo_AggregatesActiveOnly(t *testing.T) {
	keys := []Cryptokey{
		{ID: 1, Active: true, KeyType: "csk", DNSKEY: "257 3 13 AAAA", DS: []string{"111 13 2 abc", "111 13 4 def"}},
		{ID: 2, Active: false, KeyType: "zsk", DNSKEY: "256 3 13 BBBB", DS: []string{"222 13 2 ignored"}},
	}
	info := dnssecInfo(keys)
	if !info.Enabled {
		t.Fatal("expected enabled")
	}
	if want := []string{"111 13 2 abc", "111 13 4 def"}; !reflect.DeepEqual(info.DS, want) {
		t.Fatalf("DS = %v, want %v (inactive key must be excluded)", info.DS, want)
	}
	if want := []string{"257 3 13 AAAA"}; !reflect.DeepEqual(info.DNSKEY, want) {
		t.Fatalf("DNSKEY = %v, want %v", info.DNSKEY, want)
	}
}

func TestDNSSECInfo_InactiveOnlyIsUnsigned(t *testing.T) {
	info := dnssecInfo([]Cryptokey{{ID: 1, Active: false, DS: []string{"1 13 2 x"}}})
	if info.Enabled {
		t.Fatal("a zone with only inactive keys must report unsigned")
	}
}
