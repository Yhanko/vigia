package mailer

import (
	"context"
	"testing"
)

func TestNewSMTPMailerValidation(t *testing.T) {
	if _, err := NewSMTPMailer("http://localhost:1025", "no-reply@vigia.ao"); err == nil {
		t.Fatal("expected error for non-smtp scheme")
	}
	if _, err := NewSMTPMailer("smtp://", "no-reply@vigia.ao"); err == nil {
		t.Fatal("expected error for missing host")
	}
	if _, err := NewSMTPMailer("smtp://localhost:1025", "bad\r\nBcc: evil@example.com"); err == nil {
		t.Fatal("expected error for header injection in fromAddress")
	}

	m, err := NewSMTPMailer("smtp://localhost:1025", "no-reply@vigia.ao")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := m.Send(context.Background(), "victim@example.com\r\nBcc: evil@example.com", "Hi", "Body"); err == nil {
		t.Fatal("expected error for header injection in recipient")
	}
	if err := m.Send(context.Background(), "victim@example.com", "Hi\r\nBcc: evil@example.com", "Body"); err == nil {
		t.Fatal("expected error for header injection in subject")
	}
}
