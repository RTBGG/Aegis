package challenge

import (
	"strconv"
	"testing"
)

func TestLeadingZeroBits(t *testing.T) {
	cases := []struct {
		in   []byte
		want int
	}{
		{[]byte{0xff}, 0},
		{[]byte{0x0f}, 4},
		{[]byte{0x00, 0xff}, 8},
		{[]byte{0x00, 0x0f}, 12},
	}
	for _, c := range cases {
		if got := leadingZeroBits(c.in); got != c.want {
			t.Errorf("leadingZeroBits(%v) = %d, want %d", c.in, got, c.want)
		}
	}
}

func TestTokenAndProofOfWork(t *testing.T) {
	h := &Handler{Secret: "test-secret", Difficulty: 8}
	tok := h.issueToken()
	if !h.validToken(tok) {
		t.Fatal("freshly issued token should validate")
	}
	if h.validToken(tok + "tamper") {
		t.Fatal("tampered token must not validate")
	}

	var nonce string
	for i := 0; i < 1_000_000; i++ {
		n := strconv.Itoa(i)
		if solved(tok, n, h.Difficulty) {
			nonce = n
			break
		}
	}
	if nonce == "" {
		t.Fatal("failed to find a PoW solution at difficulty 8")
	}
	if !solved(tok, nonce, h.Difficulty) {
		t.Fatal("found nonce does not re-verify")
	}
}
