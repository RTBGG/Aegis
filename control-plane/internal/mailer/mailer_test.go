package mailer

import (
	"strings"
	"testing"
)

func TestBuildMessage_HeadersAndCRLF(t *testing.T) {
	msg := string(buildMessage("no-reply@aegis.test", "user@example.com", "Hello", "line1\nline2"))

	for _, want := range []string{
		"From: no-reply@aegis.test\r\n",
		"To: user@example.com\r\n",
		"Subject: Hello\r\n",
		"MIME-Version: 1.0\r\n",
		"Content-Type: text/plain; charset=utf-8\r\n",
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("message missing header %q", want)
		}
	}
	// Header/body separated by a blank CRLF line; body uses CRLF endings.
	if !strings.Contains(msg, "\r\n\r\nline1\r\nline2") {
		t.Errorf("body not CRLF-normalised:\n%q", msg)
	}
	if strings.Contains(strings.ReplaceAll(msg, "\r\n", ""), "\n") {
		t.Errorf("message contains a bare LF: %q", msg)
	}
}

func TestBuildMessage_EncodesNonASCIISubject(t *testing.T) {
	msg := string(buildMessage("a@b.c", "d@e.f", "Café ☕", "body"))
	if strings.Contains(msg, "Subject: Café ☕") {
		t.Error("non-ASCII subject should be Q-encoded, not raw")
	}
	if !strings.Contains(msg, "Subject: =?utf-8?q?") {
		t.Errorf("expected RFC 2047 encoded-word subject, got:\n%s", msg)
	}
}

func TestLoginAuth_Challenges(t *testing.T) {
	a := loginAuth("bob", "s3cret")
	mech, _, err := a.Start(nil)
	if err != nil || mech != "LOGIN" {
		t.Fatalf("Start = %q, %v; want LOGIN, nil", mech, err)
	}
	u, err := a.Next([]byte("Username:"), true)
	if err != nil || string(u) != "bob" {
		t.Fatalf("username challenge = %q, %v", u, err)
	}
	p, err := a.Next([]byte("Password:"), true)
	if err != nil || string(p) != "s3cret" {
		t.Fatalf("password challenge = %q, %v", p, err)
	}
	if _, err := a.Next([]byte("Surprise:"), true); err == nil {
		t.Error("expected error on unexpected server challenge")
	}
}
