//go:build integration

package mailer_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/Yhanko/vigia/internal/platform/mailer"
)

// Exact Mailpit image and digest pinned in compose.yaml.
const mailpitImage = "axllent/mailpit:v1.34.0@sha256:23a2ef85bc50853ab3093645d1d64679afd8887e89da5e48a88940c172591a4e"

func TestSMTPMailerMailpitIntegration(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	ctr, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			Image:        mailpitImage,
			ExposedPorts: []string{"1025/tcp", "8025/tcp"},
			WaitingFor:   wait.ForLog("accessible via http://").WithStartupTimeout(1 * time.Minute),
		},
		Started: true,
	})
	if err != nil {
		t.Fatalf("start mailpit container: %v", err)
	}
	t.Cleanup(func() {
		if err := testcontainers.TerminateContainer(ctr); err != nil {
			t.Logf("terminate mailpit: %v", err)
		}
	})

	host, err := ctr.Host(ctx)
	if err != nil {
		t.Fatal(err)
	}
	smtpPort, err := ctr.MappedPort(ctx, "1025/tcp")
	if err != nil {
		t.Fatal(err)
	}
	httpPort, err := ctr.MappedPort(ctx, "8025/tcp")
	if err != nil {
		t.Fatal(err)
	}

	m, err := mailer.NewSMTPMailer(fmt.Sprintf("smtp://%s:%s", host, smtpPort.Port()), "no-reply@vigia.ao")
	if err != nil {
		t.Fatalf("NewSMTPMailer: %v", err)
	}

	if err := m.Send(ctx, "alice@example.com", "Verify your Vigia email", "Hello Alice, verify your account."); err != nil {
		t.Fatalf("Send: %v", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("http://%s:%s/api/v1/messages", host, httpPort.Port()), nil)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("query mailpit API: %v", err)
	}
	defer resp.Body.Close()

	var payload struct {
		Total    int `json:"total"`
		Messages []struct {
			Subject string `json:"Subject"`
		} `json:"messages"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		t.Fatalf("decode mailpit messages: %v", err)
	}
	if payload.Total != 1 || len(payload.Messages) != 1 || payload.Messages[0].Subject != "Verify your Vigia email" {
		t.Fatalf("unexpected mailpit messages: %+v", payload)
	}
}
