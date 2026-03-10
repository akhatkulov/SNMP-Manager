# Multi-stage build for minimal production image
FROM golang:1.22-alpine AS builder

WORKDIR /app

# Cache dependencies
COPY go.mod go.sum ./
RUN go mod download

# Build
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags="-s -w -X main.version=$(git describe --tags --always 2>/dev/null || echo dev) -X main.buildTime=$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    -o /snmp-manager \
    ./cmd/snmpmanager

# ──────────────────────────────────────────────────────────────────────
FROM alpine:3.19

RUN apk --no-cache add ca-certificates tzdata && \
    addgroup -S snmpmanager && \
    adduser -S snmpmanager -G snmpmanager

# Create directories
RUN mkdir -p /etc/snmp-manager /var/lib/snmp-manager/mibs /var/log/snmp-manager && \
    chown -R snmpmanager:snmpmanager /var/lib/snmp-manager /var/log/snmp-manager

# Copy binary and files
COPY --from=builder /snmp-manager /usr/local/bin/snmp-manager
COPY configs/config.yaml /etc/snmp-manager/config.yaml

# Ports
EXPOSE 162/udp 8080 9090

USER snmpmanager

ENTRYPOINT ["snmp-manager"]
CMD ["--config", "/etc/snmp-manager/config.yaml"]
