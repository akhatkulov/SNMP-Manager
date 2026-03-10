# 🔌 SNMP Manager for SIEM

A high-performance SNMP Manager written in Go, designed for Security Information and Event Management (SIEM) integration. Collects, normalizes, enriches, and forwards SNMP data from network devices to SIEM platforms.

## ✨ Features

- **SNMP Polling** — Scheduled polling with configurable intervals per device (GET/WALK/BULK)
- **Trap Receiver** — UDP trap listener with SNMPv1/v2c/v3 support and deduplication
- **Event Pipeline** — Multi-stage processing: Normalize → Enrich → Filter → Format → Output
- **SIEM Formats** — CEF (ArcSight), JSON (ELK/Wazuh), Syslog RFC 5424, LEEF (QRadar)
- **SNMPv3 Security** — Full USM support with SHA-256/512 + AES-256 authentication & encryption
- **REST API** — Device management, manual polling, MIB resolution, and system stats
- **Built-in MIB** — 60+ pre-loaded OIDs for system, interfaces, CPU, memory, and traps
- **Auto-Detection** — Vendor and device type detection from sysDescr
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
