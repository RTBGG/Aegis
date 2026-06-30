package domains

import (
	"testing"

	"github.com/aegis/control-plane/internal/appcfg"
	"github.com/aegis/control-plane/internal/store"
)

func TestLuaWeighted(t *testing.T) {
	s := &Service{Cfg: &appcfg.Config{EdgePublicIP: "127.0.0.1"}}

	got := s.luaWeighted([]store.Edge{
		{PublicIP: "203.0.113.1", Weight: 10},
		{PublicIP: "203.0.113.2", Weight: 90},
	})
	if want := `A "pickwhashed({{10,'203.0.113.1'},{90,'203.0.113.2'}})"`; got != want {
		t.Fatalf("got %s, want %s", got, want)
	}

	// Zero-weight edges are drained (excluded).
	if got := s.luaWeighted([]store.Edge{{PublicIP: "1.1.1.1", Weight: 0}, {PublicIP: "2.2.2.2", Weight: 5}}); got != `A "pickwhashed({{5,'2.2.2.2'}})"` {
		t.Fatalf("drain: got %s", got)
	}

	// No eligible edges => fall back to the configured edge IP.
	if got := s.luaWeighted(nil); got != `A "pickwhashed({{100,'127.0.0.1'}})"` {
		t.Fatalf("fallback: got %s", got)
	}
}
