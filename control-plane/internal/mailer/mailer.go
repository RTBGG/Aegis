// Package mailer sends transactional email. In dev (MAILER=log) it logs to
// stdout; with MAILER=smtp it talks to a real SMTP server with optional AUTH
// (PLAIN/LOGIN) over STARTTLS or implicit TLS.
package mailer

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"mime"
	"net"
	"net/smtp"
	"strings"
	"time"

	"github.com/aegis/control-plane/internal/appcfg"
)

type Mailer interface {
	Send(ctx context.Context, to, subject, body string) error
}

// New returns a Mailer for the given kind ("log" or "smtp").
func New(kind string, cfg appcfg.SMTPConfig) Mailer {
	if kind == "smtp" {
		return &smtpMailer{cfg: cfg}
	}
	return &logMailer{}
}

type logMailer struct{}

func (l *logMailer) Send(_ context.Context, to, subject, body string) error {
	slog.Info("DEV MAILER", "to", to, "subject", subject)
	fmt.Printf("\n----- EMAIL to %s -----\nSubject: %s\n\n%s\n-----------------------\n\n", to, subject, body)
	return nil
}

type smtpMailer struct {
	cfg appcfg.SMTPConfig
}

const smtpTimeout = 20 * time.Second

func (s *smtpMailer) Send(_ context.Context, to, subject, body string) error {
	host, _, err := net.SplitHostPort(s.cfg.Addr)
	if err != nil {
		return fmt.Errorf("smtp addr %q: %w", s.cfg.Addr, err)
	}
	tlsConf := &tls.Config{ServerName: host, InsecureSkipVerify: s.cfg.Insecure} //nolint:gosec // Insecure is opt-in for self-signed internal relays

	client, err := s.dial(host, tlsConf)
	if err != nil {
		return err
	}
	defer client.Close()

	if err := s.authenticate(client, host); err != nil {
		return err
	}
	if err := client.Mail(s.cfg.From); err != nil {
		return fmt.Errorf("smtp MAIL FROM: %w", err)
	}
	if err := client.Rcpt(to); err != nil {
		return fmt.Errorf("smtp RCPT TO: %w", err)
	}
	wc, err := client.Data()
	if err != nil {
		return fmt.Errorf("smtp DATA: %w", err)
	}
	if _, err := wc.Write(buildMessage(s.cfg.From, to, subject, body)); err != nil {
		_ = wc.Close()
		return fmt.Errorf("smtp write: %w", err)
	}
	if err := wc.Close(); err != nil {
		return fmt.Errorf("smtp close data: %w", err)
	}
	return client.Quit()
}

// dial connects to the SMTP server, honouring the configured TLS mode.
func (s *smtpMailer) dial(host string, tlsConf *tls.Config) (*smtp.Client, error) {
	if s.cfg.TLS == "tls" { // implicit TLS (typically :465)
		conn, err := tls.DialWithDialer(&net.Dialer{Timeout: smtpTimeout}, "tcp", s.cfg.Addr, tlsConf)
		if err != nil {
			return nil, fmt.Errorf("smtp tls dial: %w", err)
		}
		c, err := smtp.NewClient(conn, host)
		if err != nil {
			_ = conn.Close()
			return nil, fmt.Errorf("smtp client: %w", err)
		}
		return c, nil
	}

	conn, err := net.DialTimeout("tcp", s.cfg.Addr, smtpTimeout)
	if err != nil {
		return nil, fmt.Errorf("smtp dial: %w", err)
	}
	c, err := smtp.NewClient(conn, host)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("smtp client: %w", err)
	}
	if s.cfg.TLS == "starttls" {
		if ok, _ := c.Extension("STARTTLS"); !ok {
			_ = c.Close()
			return nil, fmt.Errorf("smtp: server does not support STARTTLS")
		}
		if err := c.StartTLS(tlsConf); err != nil {
			_ = c.Close()
			return nil, fmt.Errorf("smtp starttls: %w", err)
		}
	}
	return c, nil
}

// authenticate runs SMTP AUTH when credentials are configured, choosing PLAIN or
// LOGIN based on what the server advertises.
func (s *smtpMailer) authenticate(client *smtp.Client, host string) error {
	if s.cfg.Username == "" {
		return nil
	}
	ok, mechs := client.Extension("AUTH")
	if !ok {
		return fmt.Errorf("smtp: credentials set but server advertises no AUTH")
	}
	var auth smtp.Auth
	switch {
	case strings.Contains(mechs, "PLAIN"):
		auth = smtp.PlainAuth("", s.cfg.Username, s.cfg.Password, host)
	case strings.Contains(mechs, "LOGIN"):
		auth = loginAuth(s.cfg.Username, s.cfg.Password)
	default:
		return fmt.Errorf("smtp: no supported AUTH mechanism (server offers %q)", mechs)
	}
	if err := client.Auth(auth); err != nil {
		return fmt.Errorf("smtp auth: %w", err)
	}
	return nil
}

// buildMessage assembles an RFC 5322 message with a Q-encoded subject.
func buildMessage(from, to, subject, body string) []byte {
	var b strings.Builder
	fmt.Fprintf(&b, "From: %s\r\n", from)
	fmt.Fprintf(&b, "To: %s\r\n", to)
	fmt.Fprintf(&b, "Subject: %s\r\n", mime.QEncoding.Encode("utf-8", subject))
	fmt.Fprintf(&b, "Date: %s\r\n", time.Now().Format(time.RFC1123Z))
	b.WriteString("MIME-Version: 1.0\r\n")
	b.WriteString("Content-Type: text/plain; charset=utf-8\r\n")
	b.WriteString("Content-Transfer-Encoding: 8bit\r\n")
	b.WriteString("\r\n")
	// Normalise body to CRLF line endings.
	b.WriteString(strings.ReplaceAll(strings.ReplaceAll(body, "\r\n", "\n"), "\n", "\r\n"))
	return []byte(b.String())
}

// loginAuth implements the non-standard but widely used AUTH LOGIN mechanism
// (e.g. Office 365), which the stdlib does not provide.
type loginAuthState struct{ username, password string }

func loginAuth(username, password string) smtp.Auth {
	return &loginAuthState{username, password}
}

func (a *loginAuthState) Start(_ *smtp.ServerInfo) (string, []byte, error) {
	return "LOGIN", nil, nil
}

func (a *loginAuthState) Next(fromServer []byte, more bool) ([]byte, error) {
	if !more {
		return nil, nil
	}
	switch strings.ToLower(strings.TrimSpace(string(fromServer))) {
	case "username:":
		return []byte(a.username), nil
	case "password:":
		return []byte(a.password), nil
	default:
		return nil, fmt.Errorf("smtp login: unexpected server challenge %q", fromServer)
	}
}
