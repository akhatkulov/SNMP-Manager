# 📖 SNMP Manager — Foydalanuvchi Qo'llanmasi

## Mundarija

1. [Kirish](#kirish)
2. [O'rnatish](#ornatish)
3. [Tezkor Boshlash](#tezkor-boshlash)
4. [Konfiguratsiya](#konfiguratsiya)
5. [Qurilmalarni Qo'shish](#qurilmalarni-qoshish)
6. [SNMP Trap Qabul Qilish](#snmp-trap-qabul-qilish)
7. [SIEM Integratsiya](#siem-integratsiya)
8. [REST API](#rest-api)
9. [Test va Debug](#test-va-debug)
10. [Production Deploy](#production-deploy)
11. [Troubleshooting](#troubleshooting)

---

## Kirish

SNMP Manager — bu Go dasturlash tilida yozilgan yuqori samarali SNMP monitoring tizimi bo'lib, tarmoq qurilmalaridan (router, switch, firewall, server) SNMP ma'lumotlarini yig'ish, qayta ishlash va SIEM tizimlariga yuborish uchun mo'ljallangan.

### Asosiy Imkoniyatlar

| Imkoniyat | Tavsif |
|-----------|--------|
| **SNMP Polling** | Qurilmalardan muntazam ma'lumot yig'ish (GET/WALK) |
| **Trap Receiver** | UDP orqali SNMP trap qabul qilish |
| **SNMPv1/v2c/v3** | Barcha SNMP versiyalarini qo'llab-quvvatlash |
| **Event Pipeline** | Normalize → Enrich → Classify → Format → Output |
| **SIEM Formatlar** | CEF, JSON, Syslog RFC 5424, LEEF |
| **REST API** | Qurilmalarni boshqarish va monitoring |
| **Auto-Detection** | Vendor va qurilma turini avtomatik aniqlash |

### Arxitektura

```
Tarmoq qurilmalari          SNMP Manager                    SIEM
┌──────────┐         ┌─────────────────────┐         ┌──────────┐
│ Router   │──poll──→│  Poller (10 worker)  │         │ ArcSight │
│ Switch   │──poll──→│         ↓            │──CEF──→ │ Splunk   │
│ Firewall │──trap──→│  Pipeline            │──JSON─→ │ ELK      │
│ Server   │──trap──→│  Normalize→Enrich    │──Syslog→│ QRadar   │
│ AP       │         │         ↓            │         │ Wazuh    │
└──────────┘         │  Output (file/syslog)│         └──────────┘
                     │  REST API (:8080)    │
                     └─────────────────────┘
```

---

## O'rnatish

### Talablar

- Go 1.22+
- Linux/macOS/Windows

### Loyihani Klonlash va Build

```bash
git clone https://github.com/me262/SNMP-Manager.git
cd SNMP-Manager

# Dependencylarni yuklab olish
go mod tidy

# Build
make build

# Yoki to'g'ridan-to'g'ri ishga tushirish
make dev
```

### Docker bilan

```bash
# Docker image yaratish
make docker-build

# Ishga tushirish
make docker-run
```

---

## Tezkor Boshlash

### 1-qadam: Konfiguratsiya fayl tayyor

`configs/config.yaml` — standart sozlamalar bilan tayyor keladi.

### 2-qadam: Ishga tushirish

```bash
make dev
```

Natija:
```
🚀 SNMP Manager starting  name=snmp-manager-01
✅ SNMP Manager is running
   devices=1  outputs=2  poller_workers=10  trap_receiver=true
   Trap Listener:  0.0.0.0:1620/UDP
   REST API:       0.0.0.0:8080/TCP
```

### 3-qadam: Health Check

```bash
curl http://localhost:8080/api/v1/health
```

```json
{
  "status": "healthy",
  "uptime": "5m30s",
  "devices": {"total": 1, "up": 1, "down": 0}
}
```

### 4-qadam: Test trap yuborish

```bash
go run ./cmd/trapsender --type all
```

---

## Konfiguratsiya

Asosiy konfiguratsiya fayli: `configs/config.yaml`

### Umumiy Sozlamalar

```yaml
server:
  name: "snmp-manager-01"     # Server nomi (loglar uchun)
  log_level: "info"           # debug, info, warn, error
  log_format: "console"       # console (dev), json (production)
```

### Poller Sozlamalari

```yaml
poller:
  workers: 10                 # Parallel polling goroutine soni
  default_interval: 60s       # Standart polling oraligi
  timeout: 5s                 # Har bir SNMP so'rov uchun timeout
  retries: 2                  # Qayta urinishlar soni
  max_oids_per_request: 20    # Bitta requestda max OID
```

| Parametr | Default | Tavsif |
|----------|---------|--------|
| `workers` | 50 | Bir vaqtda nechta qurilmani poll qiladi |
| `default_interval` | 60s | Har necha sekundda poll qiladi |
| `timeout` | 5s | SNMP javob kutish vaqti |
| `retries` | 2 | Xatolikda qayta urinish |

### Trap Receiver Sozlamalari

```yaml
trap_receiver:
  enabled: true
  listen_address: "0.0.0.0:1620"   # UDP port
```

> **Eslatma:** Standart SNMP trap porti — `162/UDP`, lekin u root ruxsatini talab qiladi. Dev muhitda `1620` ishlatiladi. Productionlarni pastda ko'ring.

### Muhit O'zgaruvchilari (Environment Variables)

Maxfiy ma'lumotlarni konfiguratsiyada `${VAR_NAME}` formatida yozish mumkin:

```yaml
devices:
  - name: "router-01"
    credentials:
      auth_passphrase: "${SNMP_AUTH_PASS}"
      priv_passphrase: "${SNMP_PRIV_PASS}"
```

```bash
export SNMP_AUTH_PASS="my-secret-auth-pass"
export SNMP_PRIV_PASS="my-secret-priv-pass"
make dev
```

---

## Qurilmalarni Qo'shish

### SNMPv2c Qurilma (oddiy)

```yaml
devices:
  - name: "core-switch-01"        # Unikal nom
    ip: "192.168.1.10"            # Qurilma IP
    port: 161                     # SNMP port (default: 161)
    snmp_version: "v2c"
    community: "public"           # Community string
    poll_interval: 30s            # Qancha tez-tez poll qilish
    enabled: true
    oid_groups:                   # Qaysi OID guruhlarni yig'ish
      - "system"
      - "interfaces"
    tags:
      location: "DC-Tashkent-01"
      criticality: "high"
```

### SNMPv3 Qurilma (xavfsiz — production uchun tavsiya)

```yaml
devices:
  - name: "core-router-01"
    ip: "10.0.0.1"
    snmp_version: "v3"
    poll_interval: 30s
    credentials:
      username: "siem_monitor"
      auth_protocol: "SHA256"           # MD5, SHA, SHA224, SHA256, SHA384, SHA512
      auth_passphrase: "${SNMP_AUTH_PASS}"
      priv_protocol: "AES256"           # DES, AES, AES192, AES256
      priv_passphrase: "${SNMP_PRIV_PASS}"
      context_name: ""                  # Odatda bo'sh
    oid_groups:
      - "system"
      - "interfaces"
      - "cpu_memory"
    tags:
      location: "DC-Tashkent-01"
      criticality: "critical"
```

### Mavjud OID Guruhlari

| Guruh | OID soni | Nimani yig'adi |
|-------|----------|----------------|
| `system` | 7 | sysDescr, sysUpTime, sysName, sysContact, sysLocation |
| `interfaces` | 17 | ifOperStatus, ifInOctets, ifOutOctets, ifSpeed, ifErrors |
| `cpu_memory` | 14 | CPU load, RAM usage (host-resources + UCD) |
| `host` | 8 | hrSWRunName, hrStorageDescr, hrStorageUsed |
| `ip` | 3 | ipForwarding, ipInReceives, ipInDiscards |
| `tcp` | 2 | tcpActiveOpens, tcpCurrEstab |
| `udp` | 1 | udpInDatagrams |
| `trap` | 5 | coldStart, warmStart, linkDown, linkUp, authFail |
| `entity` | 4 | entPhysicalDescr, entPhysicalName |
| `snmp_engine` | 2 | snmpEngineID, snmpEngineBoots |

### Qurilma turlarini qo'llab-quvvatlash

SNMP Manager quyidagi vendorlarni avtomatik aniqlaydi:
- **Cisco** (IOS, IOS-XE, ASA, NX-OS)
- **Juniper** (JUNOS)
- **Huawei** (VRP)
- **MikroTik** (RouterOS)
- **HP/Aruba** (ProCurve)
- **Fortinet** (FortiGate)
- **Palo Alto** (PAN-OS)
- **Linux** (Ubuntu, CentOS, RHEL)
- **Windows** (Server 2016/2019/2022)
- **VMware** (ESXi)

---

## SNMP Trap Qabul Qilish

### Trap Listener Porti

```
Standart port (production):  162/UDP   (root kerak)
Development port:            1620/UDP  (root kerak emas)
```

### Qurilmalarni Trap Yuborishga Sozlash

#### Cisco IOS / IOS-XE
```
snmp-server host 172.16.16.19 version 2c public udp-port 1620
snmp-server enable traps snmp linkdown linkup coldstart warmstart
snmp-server enable traps config
snmp-server enable traps cpu threshold
```

#### Cisco IOS — SNMPv3 Trap
```
snmp-server group SIEM-GROUP v3 priv
snmp-server user siem_monitor SIEM-GROUP v3 auth sha256 AUTH_PASS priv aes 256 PRIV_PASS
snmp-server host 172.16.16.19 version 3 priv siem_monitor udp-port 1620
snmp-server enable traps
```

#### MikroTik RouterOS
```
/snmp
set enabled=yes trap-community=public trap-version=2
/snmp community
set public addresses=172.16.16.19/32
# MikroTik standart 162 portga yuboradi, iptables redirect kerak
```

#### Huawei VRP
```
snmp-agent target-host trap address udp-domain 172.16.16.19 udp-port 1620 params securityname public v2c
snmp-agent trap enable
```

#### Linux (snmptrapd test)
```bash
# snmptrap bilan test trap yuborish
snmptrap -v 2c -c public 172.16.16.19:1620 '' .1.3.6.1.6.3.1.1.5.3 \
  .1.3.6.1.2.1.2.2.1.8.1 i 2
```

### Trap Categorization

SNMP Manager qabul qilingan traplarni avtomatik kategoriyalaydi:

| Trap OID | Nom | Severity | Category |
|----------|-----|----------|----------|
| `.1.3.6.1.6.3.1.1.5.1` | coldStart | **medium** | availability |
| `.1.3.6.1.6.3.1.1.5.2` | warmStart | **low** | availability |
| `.1.3.6.1.6.3.1.1.5.3` | linkDown | **high** | network |
| `.1.3.6.1.6.3.1.1.5.4` | linkUp | **info** | network |
| `.1.3.6.1.6.3.1.1.5.5` | authFail | **high** | security |

### Trap Deduplication

Bir xil IP + OID kombinatsiyasi 30 soniya ichida takrorlanmaydi (dublikat sifatida tashlanadi).

---

## SIEM Integratsiya

### Output Konfiguratsiyasi

#### 1. Syslog → ArcSight (CEF format)
```yaml
outputs:
  - type: "syslog"
    enabled: true
    address: "siem.company.local:514"
    protocol: "tcp"
    format: "cef"
```

Chiqish namunasi:
```
CEF:0|SNMPManager|SNMP-Manager|1.0|SNMP-LINK-DOWN|linkDown|7|src=192.168.1.1 shost=core-router-01 cat=network rt=2026-03-10T12:00:00Z
```

#### 2. Syslog → Splunk/ELK (JSON format)
```yaml
outputs:
  - type: "syslog"
    enabled: true
    address: "splunk.company.local:514"
    protocol: "tcp"
    format: "json"
```

#### 3. Syslog → Universal (RFC 5424)
```yaml
outputs:
  - type: "syslog"
    enabled: true
    address: "syslog.company.local:514"
    protocol: "udp"
    format: "syslog"
```

#### 4. File (zaxira)
```yaml
outputs:
  - type: "file"
    enabled: true
    path: "/var/log/snmp-manager/events.log"
    max_size_mb: 100      # Rotatsiya hajmi
    max_backups: 10        # Nechta zaxira
    compress: true
```

#### 5. Stdout (debug uchun)
```yaml
outputs:
  - type: "stdout"
    enabled: true
```

### Bir nechta SIEM ga yuborish

```yaml
outputs:
  # ArcSight uchun CEF
  - type: "syslog"
    enabled: true
    address: "arcsight.company.local:514"
    protocol: "tcp"
    format: "cef"

  # ELK/Splunk uchun JSON
  - type: "syslog"
    enabled: true
    address: "elk.company.local:5514"
    protocol: "tcp"
    format: "json"

  # QRadar uchun LEEF
  - type: "syslog"
    enabled: true
    address: "qradar.company.local:514"
    protocol: "udp"
    format: "leef"

  # Zaxira log fayl
  - type: "file"
    enabled: true
    path: "./logs/snmp-events.log"
```

---

## REST API

**Base URL:** `http://<server-ip>:8080`
**Auth:** `X-API-Key` header yoki `?api_key=` query parameter

### Endpointlar

#### Health Check (auth kerak emas)
```bash
curl http://localhost:8080/api/v1/health
```

#### Statistika
```bash
curl -H "X-API-Key: dev-api-key-change-me" \
  http://localhost:8080/api/v1/stats
```

```json
{
  "uptime": "2h30m",
  "devices": {"total": 5, "up": 4, "down": 1},
  "poller": {"total_polls": 450, "total_errors": 3},
  "traps": {"total_traps": 128, "v2c_traps": 120, "v3_traps": 8},
  "pipeline": {"events_in": 578, "events_out": 578, "events_dropped": 0}
}
```

#### Qurilmalar Ro'yxati
```bash
curl -H "X-API-Key: dev-api-key-change-me" \
  http://localhost:8080/api/v1/devices
```

#### Bitta Qurilma
```bash
curl -H "X-API-Key: dev-api-key-change-me" \
  http://localhost:8080/api/v1/devices/core-router-01
```

#### Manual Poll (debug uchun)
```bash
curl -X POST -H "X-API-Key: dev-api-key-change-me" \
  http://localhost:8080/api/v1/devices/core-router-01/poll
```

#### MIB Guruhlari
```bash
curl -H "X-API-Key: dev-api-key-change-me" \
  http://localhost:8080/api/v1/mibs/groups
```

#### OID Resolve
```bash
curl -H "X-API-Key: dev-api-key-change-me" \
  http://localhost:8080/api/v1/mibs/resolve/1.3.6.1.2.1.1.1
```

```json
{
  "oid": "1.3.6.1.2.1.1.1",
  "name": "sysDescr",
  "module": "SNMPv2-MIB",
  "description": "System description",
  "category": "system"
}
```

### API Key Sozlash

```yaml
api:
  enabled: true
  listen_address: "0.0.0.0:8080"
  auth:
    type: "api_key"
    keys:
      - "${SNMP_API_KEY}"           # Env variable
      - "production-api-key-here"   # Yoki to'g'ridan-to'g'ri
```

---

## Test va Debug

### Test Trap Sender

Loyiha ichida test trap yuborish uchun maxsus vosita bor:

```bash
# Barcha trap turlarini yuborish
go run ./cmd/trapsender --type all

# Faqat linkDown
go run ./cmd/trapsender --type linkDown

# 10 ta trap, 200ms oraliq bilan
go run ./cmd/trapsender --type linkDown --count 10 --interval 200ms

# Boshqa serverga yuborish
go run ./cmd/trapsender --target 172.16.16.19 --port 1620 --type authFail

# Barcha parametrlar
go run ./cmd/trapsender \
  --target 172.16.16.19 \
  --port 1620 \
  --community public \
  --type all \
  --count 5 \
  --interval 1s
```

Mavjud trap turlari: `coldStart`, `linkDown`, `linkUp`, `authFail`, `custom`, `all`

### Debug Rejimi

```yaml
server:
  log_level: "debug"      # Batafsil loglar
  log_format: "console"   # Chiroyli formatda
```

### Log Fayllarni Ko'rish

```bash
# Oxirgi eventlarni ko'rish
tail -f logs/snmp-events.log | python3 -m json.tool

# Faqat high severity
cat logs/snmp-events.log | python3 -c "
import sys, json
for line in sys.stdin:
    e = json.loads(line)
    if e['severity'] >= 7:
        print(f'[{e[\"severity_label\"]:8s}] {e[\"source\"][\"ip\"]:15s} {e[\"snmp\"][\"oid_name\"]}')
"
```

---

## Production Deploy

### 1. Port 162 ga O'tish

162 porti uchun ikki variant:

**A. iptables redirect (tavsiya):**
```bash
sudo iptables -t nat -A PREROUTING -p udp --dport 162 -j REDIRECT --to-port 1620
```

**B. Root sifatida ishga tushirish:**
```yaml
trap_receiver:
  listen_address: "0.0.0.0:162"
```
```bash
sudo ./bin/snmp-manager --config configs/config.yaml
```

### 2. Systemd Service

```ini
# /etc/systemd/system/snmp-manager.service
[Unit]
Description=SNMP Manager for SIEM
After=network.target

[Service]
Type=simple
User=snmpmanager
Group=snmpmanager
WorkingDirectory=/opt/snmp-manager
ExecStart=/opt/snmp-manager/bin/snmp-manager --config /etc/snmp-manager/config.yaml
Restart=always
RestartSec=5
LimitNOFILE=65535

# Environment
EnvironmentFile=-/etc/snmp-manager/.env

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl enable snmp-manager
sudo systemctl start snmp-manager
sudo systemctl status snmp-manager
```

### 3. Docker Compose

```yaml
# docker-compose.yml
version: '3.8'
services:
  snmp-manager:
    build: .
    ports:
      - "162:162/udp"
      - "8080:8080"
    volumes:
      - ./configs:/etc/snmp-manager
      - ./logs:/var/log/snmp-manager
    environment:
      - SNMP_AUTH_PASS=${SNMP_AUTH_PASS}
      - SNMP_PRIV_PASS=${SNMP_PRIV_PASS}
      - SNMP_API_KEY=${SNMP_API_KEY}
    restart: unless-stopped
```

### 4. Production Konfiguratsiya Namunasi

```yaml
server:
  name: "snmp-manager-prod"
  log_level: "info"
  log_format: "json"          # JSON loglar

poller:
  workers: 50
  default_interval: 30s
  timeout: 5s
  retries: 3

trap_receiver:
  enabled: true
  listen_address: "0.0.0.0:1620"

devices:
  - name: "core-router-01"
    ip: "10.0.0.1"
    snmp_version: "v3"
    poll_interval: 30s
    credentials:
      username: "siem_monitor"
      auth_protocol: "SHA256"
      auth_passphrase: "${SNMP_AUTH_PASS}"
      priv_protocol: "AES256"
      priv_passphrase: "${SNMP_PRIV_PASS}"
    oid_groups: ["system", "interfaces", "cpu_memory"]
    tags:
      location: "DC-Tashkent-01"
      criticality: "critical"

  - name: "access-switch-01"
    ip: "10.0.1.1"
    snmp_version: "v2c"
    community: "${SNMP_COMMUNITY}"
    poll_interval: 60s
    oid_groups: ["system", "interfaces"]

pipeline:
  buffer_size: 50000
  workers: 8

outputs:
  - type: "syslog"
    enabled: true
    address: "siem.company.local:514"
    protocol: "tcp"
    format: "cef"

  - type: "file"
    enabled: true
    path: "/var/log/snmp-manager/events.log"
    max_size_mb: 500
    max_backups: 30

api:
  enabled: true
  listen_address: "0.0.0.0:8080"
  auth:
    keys:
      - "${SNMP_API_KEY}"
```

---

## Troubleshooting

### "address already in use" xatosi

Oldingi process hali ishlayapti:
```bash
# Qaysi process portni egallayotganini topish
ss -ulnp | grep 1620
ss -tlnp | grep 8080

# Processni o'ldirish
kill <PID>

# Yoki barcha snmpmanager processlarini to'xtatish
pkill -f snmpmanager
```

### SNMP GET failed — connection refused

Bu demak qurilmada SNMP agent ishlamayapti yoki IP/port noto'g'ri:
```bash
# Qurilmaga SNMP bilan ulanishni tekshirish
# (snmpget o'rnatilgan bo'lsa)
snmpget -v2c -c public 192.168.1.1 .1.3.6.1.2.1.1.1.0
```

### Trap kelmayapti

1. Listener ishlayaptimi tekshiring:
```bash
ss -ulnp | grep 1620
```

2. Firewall ruxsat berilganmi:
```bash
sudo ufw allow 1620/udp
# yoki
sudo iptables -A INPUT -p udp --dport 1620 -j ACCEPT
```

3. Test trap yuborib tekshiring:
```bash
go run ./cmd/trapsender --target 127.0.0.1 --port 1620 --type linkDown
```

### Loglar juda ko'p

Log darajangizni `warn` yoki `error` ga o'zgartiring:
```yaml
server:
  log_level: "warn"
```

### Performance Masalalar

Pipeline to'lib qolgan bo'lsa:
```bash
curl -s -H "X-API-Key: KEY" http://localhost:8080/api/v1/stats | python3 -m json.tool
```

`events_dropped > 0` bo'lsa — buffer hajmini va worker sonini oshiring:
```yaml
pipeline:
  buffer_size: 50000   # 10000 → 50000
  workers: 8           # 4 → 8
```

---

## Makefile Buyruqlari

```bash
make build          # Binary yaratish (bin/snmp-manager)
make dev            # Development rejimda ishga tushirish
make test           # Barcha testlarni ishga tushirish
make test-cover     # Test coverage hisoboti
make lint           # Lint tekshiruvi
make clean          # Build fayllarni tozalash
make docker-build   # Docker image yaratish
make docker-run     # Docker da ishga tushirish
make tidy           # go mod tidy
make help           # Yordam
```
