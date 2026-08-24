# Build stage
FROM golang:1.23-alpine AS builder

WORKDIR /app

RUN apk add --no-cache git

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o webridge ./cmd/server

# Runtime stage
FROM alpine:3.20

RUN apk add --no-cache ca-certificates tzdata && \
    adduser -D -u 10001 appuser

WORKDIR /app

# Optional extra root CAs for TLS-inspected networks (e.g. Sophos SSL CA).
# Drop *.crt files into deploy/docker/ca-trust/ and rebuild; empty = no-op.
COPY deploy/docker/ca-trust/ /usr/local/share/ca-certificates/
RUN update-ca-certificates

COPY --from=builder /app/webridge .
COPY --from=builder /app/configs/config.yaml.example ./config.yaml

USER appuser

EXPOSE 8080

ENV CONFIG_PATH=/app/config.yaml

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD wget -q --spider http://localhost:8080/healthz || exit 1

ENTRYPOINT ["./webridge"]