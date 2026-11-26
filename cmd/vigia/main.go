// Comando vigia: um único binário com um subcomando por papel (README, secção 4.4).
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/CipherPath/vigia/internal/platform/config"
	"github.com/CipherPath/vigia/internal/platform/httpserver"
)

// Injectados no build com -ldflags "-X main.version=... -X main.commit=...".
var (
	version = "dev"
	commit  = "none"
)

const usage = `Uso: vigia <comando>

Comandos:
  api           Inicia a API HTTP
  healthcheck   Verifica se a API local responde (para HEALTHCHECK de containers)
  version       Mostra a versão do binário

Ainda não implementados: worker, scheduler, evaluator, dispatcher, migrate`

func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, nil)))

	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, usage)
		os.Exit(2)
	}

	var err error
	switch os.Args[1] {
	case "api":
		err = runAPI()
	case "healthcheck":
		err = runHealthcheck()
	case "version":
		fmt.Printf("vigia %s (commit %s)\n", version, commit)
		return
	case "-h", "--help", "help":
		fmt.Println(usage)
		return
	default:
		fmt.Fprintf(os.Stderr, "comando desconhecido: %q\n\n%s\n", os.Args[1], usage)
		os.Exit(2)
	}

	if err != nil {
		slog.Error("o processo terminou com erro", "error", err)
		os.Exit(1)
	}
}

func runAPI() error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	srv := httpserver.New(cfg.Port)

	errCh := make(chan error, 1)
	go func() {
		slog.Info("API a escutar", "addr", srv.Addr, "version", version, "commit", commit)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
		close(errCh)
	}()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
	}

	slog.Info("a encerrar a API")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return srv.Shutdown(shutdownCtx)
}

// runHealthcheck chama /health/live no próprio container. Não escreve logs em caso
// de sucesso, para não encher os logs a cada intervalo do HEALTHCHECK.
func runHealthcheck() error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}

	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get(fmt.Sprintf("http://127.0.0.1:%d/health/live", cfg.Port))
	if err != nil {
		return fmt.Errorf("healthcheck falhou: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("healthcheck falhou: status %d", resp.StatusCode)
	}
	return nil
}
