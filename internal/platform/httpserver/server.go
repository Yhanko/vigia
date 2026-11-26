// Package httpserver monta o servidor HTTP da API: router, middleware e SSE.
package httpserver

import (
	"fmt"
	"net/http"
	"time"
)

// NewHandler devolve o router com as rotas da API.
func NewHandler() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		fmt.Fprintln(w, "Olá, mundo!")
	})

	mux.HandleFunc("GET /health/live", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	return mux
}

// New cria o servidor HTTP com timeouts definidos (nunca usar os valores por defeito, que não têm limite).
func New(port int) *http.Server {
	return &http.Server{
		Addr:              fmt.Sprintf(":%d", port),
		Handler:           NewHandler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
}
