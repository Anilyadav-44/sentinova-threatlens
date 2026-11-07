# ThreatLens System Architecture & Technical Specifications
**Sentinova Security Systems** · *CTI Platform Baseline Architecture*

---

## 1. Architectural Overview

ThreatLens follows a decoupled, service-oriented architecture designed to handle high-throughput threat intelligence ingestion without degrading interactive dashboard query performance.

```
                           +-----------------------------------------------------------+
                           |                    External Feeds                         |
                           | AbuseIPDB · URLhaus · MalwareBazaar · ThreatFox · Feodo   |
                           +-----------------------------------------------------------+
                                                         |
                                                         v
                                      +------------------------------------+
                                      |     Ingestion & Normalizer         |
                                      | - Defangs (hxxp, 1[.]1[.]1[.]1)    |
                                      | - Auto-detects IOC Types           |
                                      +------------------------------------+
                                                         |
                                                         v
                                      +------------------------------------+
                                      |     Deduplicator & Provenance      |
                                      | - Canonical indicator merge (≥99%) |
                                      | - Multi-source provenance tracking |
                                      +------------------------------------+
                                                         |
                                                         v
                                      +------------------------------------+
                                      |     Internal Telemetry Engine      |
                                      | Correlates Firewall, Proxy, EDR    |
                                      +------------------------------------+
                                                         |
                                                         v
                                      +------------------------------------+
                                      |    Dynamic Severity Scoring (0-100)|
                                      | 40% Rep + 25% Corrob + 15% Recency |
                                      |        + 20% Telemetry Multiplier  |
                                      +------------------------------------+
                                                         |
                                 +-----------------------+-----------------------+
                                 |                                               |
                                 v                                               v
                   +---------------------------+                   +---------------------------+
                   |  Relational Storage (RDBMS)|                  |   Real-Time Event Gateway |
                   |  SQLite / PostgreSQL 16   |                   |  WebSocket (< 5s Latency) |
                   |  Canonical Indicators,    |                   |  Channel: `alerts.stream` |
                   |  Incidents, Audit Logs    |                   |  `indicators.high_severity`
                   +---------------------------+                   +---------------------------+
                                 |                                               |
                                 +-----------------------+-----------------------+
                                                         |
                                                         v
                                      +------------------------------------+
                                      |       ThreatLens REST API v1       |
                                      |  FastAPI + Pydantic v2 + JWT RBAC  |
                                      +------------------------------------+
                                                         |
                                 +-----------------------+-----------------------+
                                 |                                               |
                                 v                                               v
                   +---------------------------+                   +---------------------------+
                   | SOC Interactive Dashboard |                   | Next.js / External Tooling|
                   | Embedded Single-Page App  |                   | SIEM / STIX 2.1 Export /  |
                   | Chart.js, Leaflet, Lucide |                   | EDR Ingestion Connectors  |
                   +---------------------------+                   +---------------------------+
```

---

## 2. Ingestion & Processing Pipeline

### 2.1 Supported Threat Intelligence Sources
ThreatLens integrates automated ingestion workers across 6 public and commercial threat feeds:

| Source | Indicator Types | Update Cadence | Transport / Format |
| :--- | :--- | :--- | :--- |
| **AbuseIPDB** | Malicious IPv4 / IPv6 addresses | Hourly / Webhook | JSON REST API |
| **URLhaus (abuse.ch)** | Malicious payload URLs & hostnames | Every 15 min | CSV / JSON Feed |
| **MalwareBazaar** | SHA-256, MD5 sample hashes | Hourly | JSON REST API |
| **ThreatFox (abuse.ch)** | IOCs, C2 IPs, ports, botnet domains | Every 10 min | JSON Export API |
| **Feodo Tracker** | Botnet C2 servers (Dridex, Emotet, TrickBot) | Hourly | Blocklist Text / CSV |
| **AlienVault OTX** | Pulses, threat actors, CVEs, file hashes | Daily / Polled | OTX Direct v1 API |

### 2.2 Normalization & Defanging
All raw values undergo sanitization before deduplication:
- Replaces `hxxp://` and `hxxps://` with `http://` and `https://`
- Strips brackets around dots (e.g., `1[.]1[.]1[.]1` -> `1.1.1.1`)
- Regex-based classification identifies `IP`, `DOMAIN`, `URL`, `HASH_SHA256`, `HASH_MD5`, `EMAIL`, and `CVE`.

### 2.3 Deduplication & Provenance (FR-02, FR-03)
Overlapping feeds are merged into a single canonical `Indicator` record. Multi-source provenance is retained in `IndicatorSource`, tracking:
- First reported timestamp
- Last reported timestamp
- Source confidence score
- Feed-specific references and raw payloads

---

## 3. Dynamic Severity Scoring Formula (FR-13)

ThreatLens implements a deterministic, transparent 0–100 severity scoring model:

$$\text{Severity Score} = 0.40 \times S_{\text{rep}} + 0.25 \times C_{\text{src}} + 0.15 \times R_{\text{rec}} + 0.20 \times I_{\text{sight}}$$

### Component Weights & Rules:

1. **Base Reputation ($S_{\text{rep}}$, 40% weight)**:
   - Raw feed score clamped to $[0, 100]$.
2. **Source Corroboration ($C_{\text{src}}$, 25% weight)**:
   - 0 sources: $20$
   - 1 source: $45$
   - 2 sources: $75$
   - $\ge 3$ sources: $100$
3. **Recency Decay ($R_{\text{rec}}$, 15% weight)**:
   - $\le 1$ day old: $100$
   - $\le 7$ days old: $80$
   - $\le 30$ days old: $50$
   - $> 30$ days old: $20$
4. **Internal Sightings Multiplier ($I_{\text{sight}}$, 20% weight)**:
   - 0 sightings: $0$
   - 1 sighting: $60$
   - 2–5 sightings: $85$
   - $> 5$ sightings: $100$

Any indicator achieving a score $\ge 70$ is automatically escalated into the SOC triage alert queue. If $\ge 85$, it is labeled as **CRITICAL**.

---

## 4. Internal Telemetry Correlation (FR-16)

ThreatLens correlates incoming IOCs against internal security telemetry:
- **Palo Alto NGFW (Perimeter)**: Outbound and inbound connection logs (`destination_ip`, `domain`)
- **CrowdStrike Falcon (EDR)**: Process execution and download events (`file_hash`, `url`)
- **Squid Proxy (Corporate)**: Web traffic requests (`url`, `domain`)

Matches mark internal telemetry as `is_correlated = True` and link directly to the canonical indicator.

---

## 5. Role-Based Access Control (RBAC) Matrix (Section 11)

| Feature / Resource | Analyst (`analyst`) | CISO (`ciso`) | IR Lead (`ir_lead`) | Hunter (`hunter`) | Engineer (`engineer`) | Admin (`admin`) |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **SOC Alert Triage** | Read / Write | Read Only | Read Only | Read Only | Read Only | Full Control |
| **Incident Management** | Read Only | Read Only | Full Control | Read Only | Read Only | Full Control |
| **MITRE ATT&CK Matrix** | Read Only | Read Only | Read Only | Full Control | Read Only | Full Control |
| **Feed Polling & Health** | Read Only | Read Only | Read Only | Read Only | Full Control | Full Control |
| **Threat Exposure Index**| Read Only | Full Control | Read Only | Read Only | Read Only | Full Control |
| **STIX / CSV Export** | Read / Export | Read / Export | Read / Export | Read / Export | Read / Export | Full Control |
| **Audit Logs** | - | Read Only | - | - | - | Full Control |

---

## 6. Standards Compliance

- **STIX 2.1**: Compliant JSON Bundles at `/api/v1/export/stix` with `indicator`, `observed-data`, and `relationship` SDOs.
- **TAXII 2.1**: Ready collection transport endpoints.
- **Traffic Light Protocol (TLP 2.0)**: Supports `TLP:CLEAR`, `TLP:GREEN`, `TLP:AMBER`, `TLP:RED`.
- **MITRE ATT&CK**: Direct mapping to Enterprise Matrix techniques (e.g. `T1071.001`, `T1566`, `T1190`, `T1486`).
