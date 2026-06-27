package auth

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func TestSession_NoImpersonationFieldsWhenAbsent(t *testing.T) {
	b, err := json.Marshal(Session{UserID: uuid.New()})
	if err != nil {
		t.Fatal(err)
	}
	if s := string(b); strings.Contains(s, "imp") {
		t.Fatalf("normal session should not carry impersonation keys, got %s", s)
	}
}

func TestSession_ImpersonationRoundTrip(t *testing.T) {
	admin := uuid.New()
	in := Session{UserID: uuid.New(), ImpersonatorID: &admin, ImpersonatorEmail: "admin@example.com"}
	b, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	var out Session
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	if out.ImpersonatorID == nil || *out.ImpersonatorID != admin {
		t.Fatalf("impersonator id did not round-trip: %+v", out)
	}
	if out.ImpersonatorEmail != "admin@example.com" {
		t.Fatalf("impersonator email did not round-trip: %q", out.ImpersonatorEmail)
	}
}
