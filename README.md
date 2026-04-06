# 🔌 SNMP Manager for SIEM

A high-performance SNMP Manager written in Go, designed for Security Information and Event Management (SIEM) integration. Collects, normalizes, enriches, and forwards SNMP data from network devices to SIEM platforms.

## ✨ Features

- **SNMP Polling** — Scheduled polling with configurable intervals per device (GET/WALK/BULK)
- **Trap Receiver** — UDP trap listener with SNMPv1/v2c/v3 support and deduplication
- **Network Discovery** — Automated Subnet sweeping with SNMP probing & template auto-matching
- **Topology Mapper** — LLDP & CDP graph generation for L2/L3 visual network maps
- **Enterprise Security** — Built-in RBAC (Roles: Admin, Operator, Viewer) via JSON-based JWT auth
- **Event Pipeline** — Multi-stage processing: Normalize → Enrich → Filter → Format → Output
- **SIEM Formats** — CEF (ArcSight), JSON (ELK/Wazuh), Syslog RFC 5424, LEEF (QRadar)
- **REST API & Swagger docs** — Full OpenAPI 3.1 specs for device/discovery management
- **High Performance** — Go goroutines + channels for concurrent polling of 10,000+ devices
- **Single Binary** — No external dependencies, runs on Linux/Windows/ARM

## 🚀 Quick Start

```bash
# Build
make build

# Run in development mode
make dev

# Or run directly
go run ./cmd/snmpmanager --config configs/config.yaml
```

## 📁 Project Structure

```
snmp-manager/
├── cmd/snmpmanager/       # Application entry point
├── internal/
│   ├── config/            # YAML configuration loader
│   ├── device/            # Device model and registry
│   ├── poller/            # SNMP polling engine
│   ├── trap/              # SNMP trap receiver
│   ├── mib/               # MIB resolver (OID ↔ Name)
│   ├── pipeline/          # Event processing pipeline
│   ├── formatter/         # CEF, JSON, Syslog, LEEF formatters
│   ├── output/            # Syslog, File, Stdout outputs
│   ├── api/               # REST API server
│   └── telemetry/         # Logging setup
├── configs/               # Configuration files
├── Dockerfile             # Multi-stage Docker build
└── Makefile               # Build automation
```

## ⚙️ Configuration

Edit `configs/config.yaml` to configure devices, outputs, and pipeline settings. Environment variables are supported using `${VAR}` syntax.

```yaml
devices:
  - name: "core-router-01"
    ip: "192.168.1.1"
    snmp_version: "v3"
    credentials:
      username: "siem_monitor"
      auth_protocol: "SHA256"
      auth_passphrase: "${SNMP_AUTH_PASS}"
      priv_protocol: "AES256"
      priv_passphrase: "${SNMP_PRIV_PASS}"

outputs:
  - type: "syslog"
    address: "siem.company.local:514"
    protocol: "tcp"
    format: "cef"
```

## 🔗 API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/health` | Health check |
| GET | `/api/v1/stats` | System statistics |
| GET | `/api/v1/devices` | List all devices |
| GET | `/api/v1/devices/{name}` | Get device details |
| POST | `/api/v1/devices/{name}/poll` | Manual poll |
| GET | `/api/v1/mibs/groups` | List MIB groups |
| GET | `/api/v1/mibs/resolve/{oid}` | Resolve OID |

## 🧪 Testing

The repository uses Go's standard `testing` framework for robust unit tests and integration verifications spanning multiple components (auth, pipeline, discovery, metrics, outputs).

```bash
# Run all tests sequentially
go test ./... -v -count=1

# Run tests with race condition detection
go test -race ./...

# Generate and view test coverage
go test -coverprofile=coverage.out ./...
go tool cover -html=coverage.out
```

### Module Breakdown
- `internal/auth`: Validates RBAC permissions, JWT issuance, PBKDF2 hashing, and store manipulations.
- `internal/api`: Tests REST endpoint logic, middleware guards, and handler integration.
- `internal/discovery`: Validates CIDR subnet expansion, IP logic, auto-vendor detection engine, and discovery flows.
- `internal/poller`, `internal/pipeline`, `internal/trap`: Verifies raw byte translations, event deduplications, concurrency safeguards, and metrics output formatting (CEF/JSON/Syslog).

## 🐳 Docker

```bash
# Build & run
make docker-run

# Or manually
docker build -t snmp-manager .
docker run -p 162:162/udp -p 8080:8080 snmp-manager
```

## 📜 License

MIT
