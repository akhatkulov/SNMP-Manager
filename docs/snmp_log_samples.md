# SNMP Event Log Namunalari

Quyida SNMP-Manager chiqaradigan barcha log formatlari bo'yicha real namunalar.
Har bir namuna alohida ssenariyga tegishli.

---

## 1. Switch Harorati (Temperature) — JSON

**Ssenariy:** Cisco Catalyst 3850 switch processori harorati 68°C ga yetdi (warning chegara: 65°C)

```json
{
  "id": "a3f2c1d4-8b7e-4e21-9f3a-2c8d1e0b4567",
  "@timestamp": "2026-04-04T11:05:33.412Z",
  "event_type": "poll",
  "snmp_version": "v2c",

  "device_ip": "10.10.11.53",
  "device_hostname": "SW-CORE-01",
  "device_sysname": "SW-CORE-01.dc.local",
  "device_type": "network-switch",
  "device_vendor": "Cisco",
  "device_model": "Catalyst 3850-48T",
  "device_location": "DC-Tashkent-Rack-A3",

  "oid": "1.3.6.1.4.1.9.9.13.1.3.1.3.1",
  "oid_name": "ciscoEnvMonTemperatureStatusValue.1",
  "oid_module": "CISCO-ENVMON-MIB",
  "oid_description": "CPU board temperature sensor",

  "value": 68,
  "value_type": "Integer",
  "value_str": "68",

  "metric_value": 68.0,
  "metric_unit": "°C",
  "metric_raw": 68.0,
  "threshold_warn": 65.0,
  "threshold_crit": 80.0,

  "severity": 5,
  "severity_label": "medium",
  "category": "environment",

  "asset_criticality": "critical",
  "tags": ["snmp-v2c", "type-poll", "vendor-cisco", "cat-environment", "temp-warn"],
  "custom_fields": {
    "department": "NOC",
    "location_floor": "3rd Floor DataCenter"
  },

  "filter_reason": "changed",
  "processed_at": "2026-04-04T11:05:33.415Z",
  "pipeline_ms": 3
}
```

---

## 2. Link Down Trap — JSON

**Ssenariy:** MikroTik routerda GigabitEthernet0/2 port o'chib qoldi

```json
{
  "id": "b9e1f2a3-4c5d-4f8e-b2a1-7d3e9f0c8b21",
  "@timestamp": "2026-04-04T11:17:02.881Z",
  "event_type": "trap",
  "snmp_version": "v2c",

  "device_ip": "192.168.10.1",
  "device_hostname": "GW-MIKROTIK-01",
  "device_sysname": "MikroTik",
  "device_type": "router",
  "device_vendor": "MikroTik",
  "device_location": "Office-Main",

  "oid": "1.3.6.1.6.3.1.1.5.3",
  "oid_name": "linkDown",
  "oid_module": "SNMPv2-MIB",

  "value": 2,
  "value_type": "Integer",
  "value_str": "2",

  "trap_oid": "1.3.6.1.6.3.1.1.5.3",
  "trap_oid_name": "linkDown",

  "variables": [
    {
      "oid": "1.3.6.1.2.1.2.2.1.1.2",
      "oid_name": "ifIndex.2",
      "value": 2,
      "type": "Integer",
      "value_str": "2"
    },
    {
      "oid": "1.3.6.1.2.1.2.2.1.2.2",
      "oid_name": "ifDescr.2",
      "value": "ether2",
      "type": "OctetString",
      "value_str": "ether2"
    },
    {
      "oid": "1.3.6.1.2.1.2.2.1.8.2",
      "oid_name": "ifOperStatus.2",
      "value": 2,
      "type": "Integer",
      "value_str": "down"
    }
  ],

  "severity": 7,
  "severity_label": "high",
  "category": "network",

  "asset_criticality": "high",
  "tags": ["snmp-v2c", "type-trap", "vendor-mikrotik", "cat-network", "link-down"],

  "filter_reason": "new",
  "processed_at": "2026-04-04T11:17:02.884Z",
  "pipeline_ms": 2
}
```

---

## 3. CPU Load High — JSON

**Ssenariy:** Linux server CPU yuklama 92% ga yetdi (UCD-SNMP-MIB)

```json
{
  "id": "c7d3a9f1-2e4b-4a8c-9d6e-5f1b3c8a2e74",
  "@timestamp": "2026-04-04T11:22:10.007Z",
  "event_type": "poll",
  "snmp_version": "v2c",

  "device_ip": "10.20.5.12",
  "device_hostname": "SRV-APP-03",
  "device_sysname": "srv-app-03.corp.local",
  "device_type": "server",
  "device_vendor": "Dell",
  "device_model": "PowerEdge R750",
  "device_location": "DC-Tashkent-Rack-B7",

  "oid": "1.3.6.1.4.1.2021.11.11.0",
  "oid_name": "ssCpuIdle.0",
  "oid_module": "UCD-SNMP-MIB",
  "oid_description": "CPU idle percentage (100 - this = used)",

  "value": 8,
  "value_type": "Integer",
  "value_str": "8",

  "metric_value": 92.0,
  "metric_unit": "%",
  "metric_raw": 8.0,
  "threshold_warn": 80.0,
  "threshold_crit": 95.0,

  "severity": 7,
  "severity_label": "high",
  "category": "performance",

  "asset_criticality": "critical",
  "tags": ["snmp-v2c", "type-poll", "vendor-dell", "cat-performance", "cpu-high"],
  "custom_fields": {
    "owner": "devops@corp.local",
    "environment": "production"
  },

  "filter_reason": "changed",
  "processed_at": "2026-04-04T11:22:10.011Z",
  "pipeline_ms": 4
}
```

---

## 4. BGP Peer Down — JSON

**Ssenariy:** Cisco ASR9001 routerda BGP qo'shni ulanishi uzildi

```json
{
  "id": "d4e2b8c5-1f3a-4b7d-8e9c-6a2f5d1b0c38",
  "@timestamp": "2026-04-04T11:30:55.112Z",
  "event_type": "trap",
  "snmp_version": "v3",

  "device_ip": "172.16.1.1",
  "device_hostname": "RTR-BORDER-01",
  "device_sysname": "RTR-BORDER-01.isp.net",
  "device_type": "router",
  "device_vendor": "Cisco",
  "device_model": "ASR9001",
  "device_location": "POP-Tashkent-1",

  "oid": "1.3.6.1.2.1.15.7",
  "oid_name": "bgpBackwardTransition",
  "oid_module": "BGP4-MIB",

  "value": "172.16.50.1",
  "value_type": "IPAddress",
  "value_str": "172.16.50.1",

  "trap_oid": "1.3.6.1.2.1.15.7",
  "trap_oid_name": "bgpBackwardTransition",

  "variables": [
    {
      "oid": "1.3.6.1.2.1.15.3.1.7.172.16.50.1",
      "oid_name": "bgpPeerState.172.16.50.1",
      "value": 1,
      "type": "Integer",
      "value_str": "idle"
    },
    {
      "oid": "1.3.6.1.2.1.15.3.1.2.172.16.50.1",
      "oid_name": "bgpPeerRemoteAddr.172.16.50.1",
      "value": "172.16.50.1",
      "type": "IPAddress",
      "value_str": "172.16.50.1"
    },
    {
      "oid": "1.3.6.1.2.1.15.3.1.9.172.16.50.1",
      "oid_name": "bgpPeerRemoteAs.172.16.50.1",
      "value": 65002,
      "type": "Integer",
      "value_str": "65002"
    }
  ],

  "severity": 10,
  "severity_label": "critical",
  "category": "bgp",

  "asset_criticality": "critical",
  "tags": ["snmp-v3", "type-trap", "vendor-cisco", "cat-bgp", "bgp-down"],

  "filter_reason": "new",
  "processed_at": "2026-04-04T11:30:55.115Z",
  "pipeline_ms": 3
}
```

---

## 5. Authentication Failure Trap — JSON

**Ssenariy:** Noma'lum manbadan SNMP so'rovi — autentifikatsiya muvaffaqiyatsiz

```json
{
  "id": "e1c3d7b9-5a2f-4e8d-a1b3-9c4f6d2e8a45",
  "@timestamp": "2026-04-04T11:35:41.334Z",
  "event_type": "trap",
  "snmp_version": "v2c",

  "device_ip": "10.10.11.53",
  "device_hostname": "SW-CORE-01",
  "device_type": "network-switch",
  "device_vendor": "Cisco",
  "device_location": "DC-Tashkent-Rack-A3",

  "oid": "1.3.6.1.6.3.1.1.5.5",
  "oid_name": "authenticationFailure",
  "oid_module": "SNMPv2-MIB",

  "value": "10.99.0.44",
  "value_type": "IPAddress",
  "value_str": "10.99.0.44",

  "trap_oid": "1.3.6.1.6.3.1.1.5.5",
  "trap_oid_name": "authenticationFailure",

  "variables": [],

  "severity": 7,
  "severity_label": "high",
  "category": "security",

  "asset_criticality": "critical",
  "tags": ["snmp-v2c", "type-trap", "vendor-cisco", "cat-security", "security-alert", "auth-fail"],

  "filter_reason": "new",
  "processed_at": "2026-04-04T11:35:41.337Z",
  "pipeline_ms": 2
}
```

---

## 6. Interface Bandwidth Counter — JSON

**Ssenariy:** Huawei switch interfeysi trafik counter (polling asosida)

```json
{
  "id": "f2d4e8a1-3b5c-4f2d-b7e9-1a8c3d5f7e02",
  "@timestamp": "2026-04-04T11:40:00.001Z",
  "event_type": "poll",
  "snmp_version": "v2c",

  "device_ip": "10.10.20.5",
  "device_hostname": "SW-ACCESS-B02",
  "device_sysname": "sw-access-b02",
  "device_type": "network-switch",
  "device_vendor": "Huawei",
  "device_model": "S5720-28P-SI",
  "device_location": "Office-Building-B-2F",

  "oid": "1.3.6.1.2.1.31.1.1.1.6.5",
  "oid_name": "ifHCInOctets[XGE0/0/5]",
  "oid_module": "IF-MIB",
  "oid_description": "High-capacity incoming bytes counter for port GE0/0/5",

  "value": 48392741029,
  "value_type": "Counter64",
  "value_str": "48392741029",

  "metric_value": 125431808.0,
  "metric_unit": "bps",
  "metric_raw": 48392741029.0,
  "metric_is_rate": true,

  "severity": 0,
  "severity_label": "info",
  "category": "network",

  "tags": ["snmp-v2c", "type-poll", "vendor-huawei", "cat-network"],

  "filter_reason": "changed",
  "processed_at": "2026-04-04T11:40:00.004Z",
  "pipeline_ms": 3
}
```

---

## 7. UPS Power Failure — JSON

**Ssenariy:** APC UPS asosiy quvvat ta'minotidan o'chdi, batareyaga o'tdi

```json
{
  "id": "a8c1e3f5-7b2d-4a9e-c3f8-2d6b4e8a1c37",
  "@timestamp": "2026-04-04T11:48:22.771Z",
  "event_type": "trap",
  "snmp_version": "v1",

  "device_ip": "10.10.99.5",
  "device_hostname": "UPS-APC-RACK-A",
  "device_sysname": "APC Smart-UPS",
  "device_type": "ups",
  "device_vendor": "APC",
  "device_model": "Smart-UPS 3000",
  "device_location": "DC-Tashkent-Rack-A-PDU",

  "oid": "1.3.6.1.4.1.318.1.1.1.11.1.1",
  "oid_name": "upsAdvBatteryStatus",
  "oid_module": "PowerNet-MIB",

  "value": 2,
  "value_type": "Integer",
  "value_str": "onBattery",

  "trap_oid": "1.3.6.1.4.1.318.0.5",
  "trap_oid_name": "onBattery",
  "enterprise": "1.3.6.1.4.1.318",
  "generic_trap": 6,
  "specific_trap": 5,

  "variables": [
    {
      "oid": "1.3.6.1.4.1.318.1.1.1.2.2.1.0",
      "oid_name": "upsAdvInputLineVoltage",
      "value": 0,
      "type": "Gauge32",
      "value_str": "0"
    },
    {
      "oid": "1.3.6.1.4.1.318.1.1.1.3.2.1.0",
      "oid_name": "upsAdvOutputVoltage",
      "value": 220,
      "type": "Gauge32",
      "value_str": "220"
    },
    {
      "oid": "1.3.6.1.4.1.318.1.1.1.2.2.4.0",
      "oid_name": "upsAdvInputLineFailCause",
      "value": 9,
      "type": "Integer",
      "value_str": "notYetDetermined"
    }
  ],

  "severity": 10,
  "severity_label": "critical",
  "category": "ups",

  "asset_criticality": "critical",
  "tags": ["snmp-v1", "type-trap", "vendor-apc", "cat-ups", "power-fail"],

  "filter_reason": "new",
  "processed_at": "2026-04-04T11:48:22.774Z",
  "pipeline_ms": 3
}
```

---

## 8. Xuddi shu loglar — Boshqa formatlarda

### CEF Format (ArcSight / SIEM)

**Link Down trapi:**
```
CEF:0|SNMPManager|SNMP-Manager|1.0|SNMP-LINK-DOWN|linkDown|7|src=192.168.10.1 rt=2026-04-04T11:17:02Z cat=network shost=GW-MIKROTIK-01 cs1Label=DeviceType cs1=router cs2Label=Vendor cs2=MikroTik cs3Label=OID cs3=1.3.6.1.6.3.1.1.5.3 cs4Label=SNMPVersion cs4=v2c msg=2 cs5Label=Location cs5=Office-Main
```

**Authentication Failure:**
```
CEF:0|SNMPManager|SNMP-Manager|1.0|SNMP-AUTH-FAIL|authenticationFailure|7|src=10.10.11.53 rt=2026-04-04T11:35:41Z cat=security shost=SW-CORE-01 cs1Label=DeviceType cs1=network-switch cs2Label=Vendor cs2=Cisco cs3Label=OID cs3=1.3.6.1.6.3.1.1.5.5 cs4Label=SNMPVersion cs4=v2c msg=10.99.0.44 cs5Label=Location cs5=DC-Tashkent-Rack-A3
```

**CPU High (poll):**
```
CEF:0|SNMPManager|SNMP-Manager|1.0|SNMP-EVENT|ssCpuIdle.0|7|src=10.20.5.12 rt=2026-04-04T11:22:10Z cat=performance shost=SRV-APP-03 cs1Label=DeviceType cs1=server cs2Label=Vendor cs2=Dell cs3Label=OID cs3=1.3.6.1.4.1.2021.11.11.0 cs4Label=SNMPVersion cs4=v2c msg=8 cs5Label=Location cs5=DC-Tashkent-Rack-B7
```

---

### Syslog RFC 5424 Format

**Link Down:**
```
<131>1 2026-04-04T11:17:02Z GW-MIKROTIK-01 snmpmanager b9e1f2a3 SNMP_TRAP [snmp oid="1.3.6.1.6.3.1.1.5.3" name="linkDown" value="2" version="v2c" type="trap"] linkDown=2 on GW-MIKROTIK-01
```

**Authentication Failure:**
```
<131>1 2026-04-04T11:35:41Z SW-CORE-01 snmpmanager e1c3d7b9 SNMP_TRAP [snmp oid="1.3.6.1.6.3.1.1.5.5" name="authenticationFailure" value="10.99.0.44" version="v2c" type="trap"] authenticationFailure=10.99.0.44 on SW-CORE-01
```

**CPU poll (info):**
```
<134>1 2026-04-04T11:22:10Z SRV-APP-03 snmpmanager c7d3a9f1 SNMP_POLL [snmp oid="1.3.6.1.4.1.2021.11.11.0" name="ssCpuIdle.0" value="8" version="v2c" type="poll"] ssCpuIdle.0=8 on SRV-APP-03
```

> Priority formula: `(facility*8) + severity` → facility=16(local0), syslog severity=3(error/high) → `16*8+3=131`

---

### LEEF Format (IBM QRadar)

**Link Down:**
```
LEEF:2.0|SNMPManager|SNMP-Manager|1.0|linkDown|src=192.168.10.1	sev=7	cat=network	devTime=2026-04-04T11:17:02Z	srcName=GW-MIKROTIK-01	oid=1.3.6.1.6.3.1.1.5.3	oidName=linkDown	value=2
```

**BGP Peer Down:**
```
LEEF:2.0|SNMPManager|SNMP-Manager|1.0|bgpBackwardTransition|src=172.16.1.1	sev=10	cat=bgp	devTime=2026-04-04T11:30:55Z	srcName=RTR-BORDER-01	oid=1.3.6.1.2.1.15.7	oidName=bgpBackwardTransition	value=172.16.50.1
```

**UPS onBattery:**
```
LEEF:2.0|SNMPManager|SNMP-Manager|1.0|upsAdvBatteryStatus|src=10.10.99.5	sev=10	cat=ups	devTime=2026-04-04T11:48:22Z	srcName=UPS-APC-RACK-A	oid=1.3.6.1.4.1.318.1.1.1.11.1.1	oidName=upsAdvBatteryStatus	value=onBattery
```

---

## Severity Darajalar Jadvali

| Label | Qiymat | Misollar |
|---|---|---|
| `info` | 0 | Odatiy polling, counter o'lchovlari |
| `low` | 3 | Minor o'zgarishlar, kichik ogohlantirishlar |
| `medium` | 5 | Harorat warning, disk ~80%, CPU ~70-80% |
| `high` | 7 | Link down, auth failure, CPU >90%, harorat >65°C |
| `critical` | 10 | BGP down, UPS on battery, power failure, service down |

## Kategoriyalar

| Kategoriya | Qo'llaniladi |
|---|---|
| `network` | Link up/down, interface errors |
| `environment` | Harorat, namlik, fan tezligi |
| `performance` | CPU, RAM, disk I/O, bandwidth |
| `security` | Auth failure, access violation |
| `bgp` / `ospf` | Routing protocol traplari |
| `ups` | Quvvat ta'minoti hodisalari |
| `availability` | Qurilma offline/online |
| `system` | sysDescr, sysUpTime, sysName |
