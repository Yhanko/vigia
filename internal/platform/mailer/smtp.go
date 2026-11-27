// Package mailer provides a minimal, stdlib-only transactional SMTP adapter
// for verification, password reset, security alerts, and invitations (README §7.7).
package mailer

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/smtp"
	"net/url"
	"strings"
	"time"
)

const defaultDialTimeout = 5 * time.Second

// Message represents a plain-text transactional email.
type Message struct {
	To       string
	Subject  string
	TextBody string
}

// SMTPMailer delivers plain-text emails over smtp:// or smtps://.
type SMTPMailer struct {
	host        string
	port        string
	useTLS      bool
	fromAddress string
	username    string
	password    string
	timeout     time.Duration
}

// NewSMTPMailer parses smtpURL (smtp:// or smtps://) and configures an SMTPMailer.
func NewSMTPMailer(smtpURL, fromAddress string) (*SMTPMailer, error) {
	u, err := url.Parse(strings.TrimSpace(smtpURL))
	if err != nil {
		return nil, fmt.Errorf("mailer: parse smtp url: %w", err)
	}
	if u.Scheme != "smtp" && u.Scheme != "smtps" {
		return nil, fmt.Errorf("mailer: unsupported smtp scheme %q", u.Scheme)
	}
	host := u.Hostname()
	if host == "" {
		return nil, errors.New("mailer: smtp host is required")
	}
	port := u.Port()
	if port == "" {
		if u.Scheme == "smtps" {
			port = "465"
		} else {
			port = "587"
		}
	}
	if err := validateHeaderValue(fromAddress); err != nil || strings.TrimSpace(fromAddress) == "" {
		return nil, errors.New("mailer: valid from address is required")
	}

	var user, pass string
	if u.User != nil {
		user = u.User.Username()
		pass, _ = u.User.Password()
	}

	return &SMTPMailer{
		host:        host,
		port:        port,
		useTLS:      u.Scheme == "smtps",
		fromAddress: strings.TrimSpace(fromAddress),
		username:    user,
		password:    pass,
		timeout:     defaultDialTimeout,
	}, nil
}

// Send delivers a plain-text email synchronously with context-bounded dial/IO timeouts.
// Callers MUST invoke Send outside database transactions (go-conventions.md §4).
func (m *SMTPMailer) Send(ctx context.Context, to, subject, textBody string) error {
	to = strings.TrimSpace(to)
	subject = strings.TrimSpace(subject)
	if to == "" || validateHeaderValue(to) != nil {
		return errors.New("mailer: invalid recipient address")
	}
	if subject == "" || validateHeaderValue(subject) != nil {
		return errors.New("mailer: invalid subject")
	}

	addr := net.JoinHostPort(m.host, m.port)
	dialer := &net.Dialer{Timeout: m.timeout}

	var (
		conn net.Conn
		err  error
	)
	if m.useTLS {
		tlsDialer := &tls.Dialer{
			NetDialer: dialer,
			Config:    &tls.Config{ServerName: m.host, MinVersion: tls.VersionTLS12},
		}
		conn, err = tlsDialer.DialContext(ctx, "tcp", addr)
	} else {
		conn, err = dialer.DialContext(ctx, "tcp", addr)
	}
	if err != nil {
		return fmt.Errorf("mailer: dial smtp: %w", err)
	}
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	} else {
		_ = conn.SetDeadline(time.Now().Add(m.timeout))
	}

	client, err := smtp.NewClient(conn, m.host)
	if err != nil {
		_ = conn.Close()
		return fmt.Errorf("mailer: smtp client: %w", err)
	}
	defer func() { _ = client.Close() }()

	if !m.useTLS {
		if ok, _ := client.Extension("STARTTLS"); ok {
			if err := client.StartTLS(&tls.Config{ServerName: m.host, MinVersion: tls.VersionTLS12}); err != nil {
				return fmt.Errorf("mailer: starttls: %w", err)
			}
		}
	}

	if m.username != "" {
		auth := smtp.PlainAuth("", m.username, m.password, m.host)
		if err := client.Auth(auth); err != nil {
			return fmt.Errorf("mailer: smtp auth: %w", err)
		}
	}

	if err := client.Mail(m.fromAddress); err != nil {
		return fmt.Errorf("mailer: mail from: %w", err)
	}
	if err := client.Rcpt(to); err != nil {
		return fmt.Errorf("mailer: rcpt to: %w", err)
	}

	wc, err := client.Data()
	if err != nil {
		return fmt.Errorf("mailer: data: %w", err)
	}

	raw := fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: %s\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\n%s\r\n",
		m.fromAddress, to, subject, textBody)
	if _, err := wc.Write([]byte(raw)); err != nil {
		_ = wc.Close()
		return fmt.Errorf("mailer: write body: %w", err)
	}
	if err := wc.Close(); err != nil {
		return fmt.Errorf("mailer: close data: %w", err)
	}
	return client.Quit()
}

func validateHeaderValue(v string) error {
	if strings.ContainsAny(v, "\r\n\x00") {
		return errors.New("mailer: header injection characters rejected")
	}
	return nil
}
