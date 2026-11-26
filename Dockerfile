# syntax=docker/dockerfile:1
#
# Imagem do backend Vigia (Go). Ver README, secção 16.4.
#
# Build:   docker build --build-arg VERSION=$(git describe --tags --always) \
#                       --build-arg COMMIT=$(git rev-parse --short HEAD) -t vigia .
# Testes:  docker build --target test .
# Run:     docker run --rm -p 8080:8080 --read-only --cap-drop ALL \
#                     --security-opt no-new-privileges vigia
#
# As imagens base estão fixadas por versão E digest: o digest garante que o build é
# reprodutível e que uma tag reescrita no registry não muda a imagem sem revisão.
# Para actualizar: docker buildx imagetools inspect <imagem:tag>

ARG GO_IMAGE=golang:1.27.4-alpine3.24@sha256:70bd7ddea8b6cbe5d6943cde279d6b67feb10cc924fb9100d1d8757c1575b280
ARG RUNTIME_IMAGE=gcr.io/distroless/static-debian13:nonroot@sha256:8ce6dd87e9823c5b48dcfb2c8604714ccb351ce59607327bcc4957448da279b5

# ─── base: toolchain Go ─────────────────────────────────────────────────────────
# Compila na arquitectura do host e faz cross-compile para a de destino (rápido em
# builds multi-arch, sem emulação).
FROM --platform=$BUILDPLATFORM ${GO_IMAGE} AS base
ENV CGO_ENABLED=0 \
    GOTOOLCHAIN=local \
    GOFLAGS=-mod=readonly
WORKDIR /src

# ─── deps: módulos Go (camada em cache enquanto go.mod/go.sum não mudarem) ──────
FROM base AS deps
COPY go.mod go.sum* ./
RUN --mount=type=cache,target=/go/pkg/mod \
    go mod download && go mod verify

# ─── test: vet + testes (docker build --target test .) ──────────────────────────
# O race detector precisa de CGO; corre no CI fora do container (go test -race).
FROM deps AS test
COPY cmd ./cmd
COPY internal ./internal
COPY migrations ./migrations
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    go vet ./... && go test ./...

# ─── build: binário estático ────────────────────────────────────────────────────
FROM deps AS build
ARG TARGETOS
ARG TARGETARCH
ARG VERSION=dev
ARG COMMIT=none
COPY cmd ./cmd
COPY internal ./internal
COPY migrations ./migrations
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -trimpath -buildvcs=false \
      -ldflags="-s -w -X main.version=${VERSION} -X main.commit=${COMMIT}" \
      -o /out/vigia ./cmd/vigia

# ─── runtime: distroless, sem shell nem gestor de pacotes, utilizador não-root ──
FROM ${RUNTIME_IMAGE} AS runtime
ARG VERSION=dev
ARG COMMIT=none

LABEL org.opencontainers.image.title="vigia" \
      org.opencontainers.image.description="Vigia: monitorização, alertas, auditoria e error tracking" \
      org.opencontainers.image.source="https://github.com/CipherPath/vigia" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${COMMIT}" \
      org.opencontainers.image.licenses="UNLICENSED"

# O binário pertence a root e não é gravável pelo utilizador da aplicação.
COPY --from=build /out/vigia /vigia

ENV PORT=8080
USER 65532:65532
EXPOSE 8080
STOPSIGNAL SIGTERM

HEALTHCHECK --interval=15s --timeout=3s --start-period=5s --retries=3 \
  CMD ["/vigia", "healthcheck"]

ENTRYPOINT ["/vigia"]
CMD ["api"]
