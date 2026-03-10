# 🏗️ SNMP Manager — Architecture & Developer Guide

## Project Structure

```
snmp-manager/
├── cmd/
│   ├── snmpmanager/          # Main application entry point
│   │   └── main.go           # Wires all components, signal handling
│   └── trapsender/           # Test utility for sending SNMP traps
│       └── main.go
│
├── internal/
│   ├── config/               # Configuration management
│   │   ├── config.go         # YAML loading, validation, env expansion
│   │   └── config_test.go
│   │
│   ├── device/               # Device model and registry
│   │   ├── device.go         # Device struct, status, vendor detection
│   │   ├── registry.go       # Thread-safe device management
│   │   ├── device_test.go
│   │   └── registry_test.go
│   │
│   ├── mib/                  # MIB/OID resolver
│   │   ├── resolver.go       # OID↔Name resolution, 63 built-in OIDs
│   │   ├── resolver_test.go
│   │   └── mibs/             # Custom MIB files directory
│   │
│   ├── poller/               # SNMP polling engine
│   │   ├── poller.go         # Worker pool, scheduled polling, v1/v2c/v3
│   │   └── poller_test.go
│   │
│   ├── trap/                 # SNMP trap receiver
│   │   ├── listener.go       # UDP listener, dedup, v1/v2c/v3
│   │   └── listener_test.go
│   │
│   ├── pipeline/             # Event processing pipeline
│   │   ├── event.go          # SNMPEvent data model
│   │   ├── pipeline.go       # Channel-based pipeline orchestrator
│   │   ├── normalizer.go     # OID resolution, severity/category
│   │   ├── enricher.go       # Asset lookup, tag generation
│   │   ├── event_test.go
│   │   └── pipeline_test.go
│   │
│   ├── formatter/            # SIEM output formatters
│   │   ├── formatter.go      # CEF, JSON, Syslog RFC5424, LEEF
│   │   └── formatter_test.go
│   │
│   ├── output/               # Event destinations
│   │   ├── syslog.go         # TCP/UDP syslog with reconnect
│   │   ├── file.go           # File with rotation + stdout
│   │   └── output_test.go
│   │
│   ├── api/                  # REST API server
│   │   ├── server.go         # HTTP handlers, auth, CORS
│   │   └── server_test.go
│   │
│   └── telemetry/            # Observability
│       ├── logging.go        # zerolog setup
│       └── logging_test.go
│
├── configs/
│   └── config.yaml           # Default configuration
│
├── docs/
│   ├── USER_GUIDE.md         # User documentation (Uzbek)
│   └── ARCHITECTURE.md       # This file
│
├── Dockerfile                # Multi-stage build
├── Makefile                  # Build automation
├── go.mod / go.sum           # Go modules
└── README.md                 # Project overview
```

## Data Flow

```
                    ┌─────────────┐
                    │ SNMP Device  │
                    └──────┬──────┘
                           │
              ┌────────────┴────────────┐
              │                         │
         Poll (GET)               Trap (UDP)
              │                         │
    ┌─────────▼─────────┐   ┌──────────▼──────────┐
    │  Poller            │   │  Trap Listener       │
    │  - Worker pool     │   │  - UDP :1620         │
    │  - Scheduled       │   │  - Deduplication     │
    │  - Batch OIDs      │   │  - v1/v2c/v3         │
    └─────────┬─────────┘   └──────────┬──────────┘
              │                         │
              └────────────┬────────────┘
                           │
                    SNMPEvent struct
                           │
              ┌────────────▼────────────┐
              │  Pipeline (channels)     │
              │                         │
              │  ┌───────────────────┐  │
              │  │ 1. Normalizer     │  │
              │  │  - OID → Name     │  │
              │  │  - Severity       │  │
              │  │  - Category       │  │
              │  └────────┬──────────┘  │
              │           │             │
              │  ┌────────▼──────────┐  │
              │  │ 2. Enricher       │  │
              │  │  - Asset lookup   │  │
              │  │  - Tags           │  │
              │  │  - Severity adj.  │  │
              │  └────────┬──────────┘  │
              └───────────┬─────────────┘
                          │
              ┌───────────▼─────────────┐
              │  Outputs (parallel)      │
              │  ┌─────┐ ┌─────┐ ┌────┐ │
              │  │Syslog│ │File │ │Std │ │
              │  │CEF/  │ │JSON │ │out │ │
              │  │JSON  │ │     │ │    │ │
              │  └─────┘ └─────┘ └────┘ │
              └──────────────────────────┘
```

## Key Design Decisions

1. **Channel-based pipeline** — Each stage connected via buffered channels for backpressure
2. **Worker pools** — Configurable goroutine count per stage for performance tuning
3. **Non-blocking submit** — Events are dropped (not blocked) when pipeline is full
4. **Thread-safe registry** — sync.RWMutex for concurrent device access
5. **Graceful shutdown** — context.Context propagation + WaitGroup coordination
6. **Zero-allocation logging** — zerolog for structured, zero-alloc JSON logs
7. **Built-in MIB** — No external MIB files needed for common monitoring OIDs

## Testing

```bash
make test           # All tests
make test-cover     # With coverage report
go test -race ./... # With race detector
```

Coverage: ~63% overall, 98-100% on core modules (config, device, mib).
