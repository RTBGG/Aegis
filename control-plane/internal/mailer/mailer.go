// Package mailer sends transactional email. In dev it logs to stdout; with
// MAILER=smtp it talks to a local Mailpit/SMTP server.
package mailer

import (
	"context"
	"fmt"
	"log/slog"
	"net/smtp"
	"strings"
)

type Mailer interface {
	Send(ctx context.Context, to, subject, body string) error
}

// New returns a Mailer for the given kind ("log" or "smtp").
func New(kind, smtpAddr, from string) Mailer {
	if kind == "smtp" {
		return &smtpMailer{addr: smtpAddr, from: from}
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
	addr string
	from string
}

func (s *smtpMailer) Send(_ context.Context, to, subject, body string) error {
	msg := strings.Builder{}
	fmt.Fprintf(&msg, "From: %s\r\n", s.from)
	fmt.Fprintf(&msg, "To: %s\r\n", to)
	fmt.Fprintf(&msg, "Subject: %s\r\n", subject)
	msg.WriteString("MIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n")
	msg.WriteString(body)
	return smtp.SendMail(s.addr, nil, s.from, []string{to}, []byte(msg.String()))
}
