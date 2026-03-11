# Multi-stage build for minimal production image
FROM golang:1.25-alpine AS builder

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
RUN mkdir -p /etc/snmp-manager /usr/share/snmp/mibs /var/log/snmp-manager /app/web && \
    chown -R snmpmanager:snmpmanager /usr/share/snmp /var/log/snmp-manager /app

WORKDIR /app

# Copy binary
COPY --from=builder /snmp-manager /usr/local/bin/snmp-manager

# Copy config (docker-specific)
COPY configs/config.docker.yaml /etc/snmp-manager/config.yaml

# Copy MIB files
COPY mibs/ /usr/share/snmp/mibs/

# Copy web UI (to ./web relative to WORKDIR /app)
COPY web/ /app/web/

# Ports: SNMP Trap (162/udp), API (8080), Metrics (9090)
EXPOSE 162/udp 8080 9090

USER snmpmanager

ENTRYPOINT ["snmp-manager"]
CMD ["--config", "/etc/snmp-manager/config.yaml"]
