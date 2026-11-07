# ThreatLens — Cyber Threat Intelligence (CTI) Platform
**Sentinova Security Systems** · *Product Requirements Document v1.0 Baseline*

[![Python](https://img.shields.io/badge/Python-3.11%2B-blue?logo=python&logoColor=white)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.110%2B-009688?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)
[![Next.js](https://img.shields.io/badge/Next.js-14.2-black?logo=next.js&logoColor=white)](https://nextjs.org/)
[![Database](https://img.shields.io/badge/Database-SQLite%20%7C%20PostgreSQL%2016-336791?logo=postgresql&logoColor=white)](https://www.postgresql.org/)
[![Real-Time](https://img.shields.io/badge/Real--Time-WebSockets-orange?logo=websocket&logoColor=white)](https://websockets.spec.whatwg.org/)
[![Standards](https://img.shields.io/badge/Standards-STIX%202.1%20%7C%20MITRE%20ATT%26CK-green)](https://oasis-open.github.io/cti-documentation/)
[![Tests](https://img.shields.io/badge/Pytest-8%20Passed-brightgreen?logo=pytest&logoColor=white)](https://pytest.org/)
[![License](https://img.shields.io/badge/License-Confidential%20%2F%20Proprietary-red)](LICENSE)

ThreatLens is an enterprise-grade Cyber Threat Intelligence (CTI) platform engineered to consolidate, normalize, deduplicate, score, and operationalize high-volume threat data across a 24/7 Security Operations Centre (SOC). It turns disparate, raw threat indicators into prioritized, enriched, and contextualized intelligence that analysts and incident response teams can act on in seconds rather than hours.

---

## 📑 Table of Contents

- [Overview & The Problem](#-overview--the-problem)
- [System Architecture](#-system-architecture)
- [Key Features & Capabilities](#-key-features--capabilities)
- [Severity Scoring Algorithm](#-severity-scoring-algorithm)
- [Demo Persona Accounts](#-demo-persona-accounts)
- [Project Directory Structure](#-project-directory-structure)
- [Quickstart & Installation Guide](#-quickstart--installation-guide)
  - [Prerequisites](#prerequisites)
  - [Option 1: Direct Local Bring-Up](#option-1-direct-local-bring-up-recommended-for-evaluation)
  - [Option 2: Docker Compose Full Stack](#option-2-docker-compose-full-stack)
- [API & WebSocket Reference](#-api--websocket-reference)
- [Automated Test Suite](#-automated-test-suite)
- [Standards & Compliance](#-standards--compliance)
- [Documentation & Archive Index](#-documentation--archive-index)

---

## 🎯 Overview & The Problem

Modern SOC teams are overwhelmed by thousands of uncoordinated threat indicators arriving daily across open and commercial feeds. This results in:
- **Fragmentation**: Intelligence trapped in disparate vendor portals, browser tabs, and spreadsheets with no single source of truth.
- **Volume & Alert Fatigue**: Feeds flooding queues with unranked, stale, or low-value indicators, masking genuinely critical compromises.
- **Lack of Context**: Indicators lacking multi-source corroboration, MITRE ATT&CK technique mapping, and internal network telemetry sightings.
- **Slow Escalation**: Manual handoffs between Tier-1 triage, Tier-2 analysis, and Incident Response leads.

### ThreatLens Solves This By Providing:
1. **Automated Multi-Feed Ingestion (≥ 6 Sources)**: Continuously collects, defangs, and normalizes external indicators.
2. **Canonical Deduplication (FR-02, FR-03)**: Unifies overlapping feeds into single canonical records with multi-source provenance.
3. **Transparent 0–100 Severity Scoring (FR-13)**: Combines reputation, corroboration, recency decay, and internal telemetry sightings.
4. **Internal Telemetry Correlation (FR-16)**: Auto-matches IOCs against firewall, proxy, and EDR events, auto-promoting high risks to alerts.
5. **Role-Tailored Dashboards**: 6 persona-specific views covering CISO exposure, analyst triage, incident response, threat hunting, feed health, and audit logs.
6. **Open Standards**: Full export to **STIX 2.1 JSON Bundles**, CSV, and TAXII 2.1 ready endpoints.

---

## 🏛️ System Architecture

ThreatLens is designed with a decoupled, service-oriented architecture ensuring that intensive background ingestion and scoring jobs never impact interactive dashboard performance.

```
                           +-------------------------------------------------------------+
                           |                    External Threat Feeds                    |
                           |   AbuseIPDB · URLhaus · MalwareBazaar · ThreatFox · Feodo   |
                           +-------------------------------------------------------------+
                                                          |
                                                          v
                                       +-------------------------------------+
                                       |      Ingestion & Normalizer         |
                                       | - Defanging: hxxp:// -> http://     |
                                       | - Regex IOC Classification          |
                                       +-------------------------------------+
                                                          |
                                                          v
                                       +-------------------------------------+
                                       |      Deduplicator & Provenance      |
                                       | - Canonical Indicator Merge (≥99%)  |
                                       | - Multi-Source Provenance Store     |
                                       +-------------------------------------+
                                                          |
                                                          v
                                       +-------------------------------------+
                                       |      Internal Telemetry Engine      |
                                       | - Palo Alto NGFW · CrowdStrike EDR  |
                                       | - Squid Proxy Event Matcher         |
                                       +-------------------------------------+
                                                          |
                                                          v
                                       +-------------------------------------+
                                       |   Dynamic 0-100 Severity Scoring    |
                                       | 40% Rep + 25% Corrob + 15% Recency  |
                                       |        + 20% Telemetry Multiplier   |
                                       +-------------------------------------+
                                                          |
                                  +-----------------------+-----------------------+
                                  |                                               |
                                  v                                               v
                    +---------------------------+                   +---------------------------+
                    |  Relational Storage Layer |                   |   Real-Time Event Gateway |
                    |  SQLite (dev) / PostgreSQL|                   |  WebSocket (< 5s Latency) |
                    |  Indicators, Alerts, IR   |                   |  Channels: `alerts.stream`|
                    +---------------------------+                   +---------------------------+
                                  |                                               |
                                  +-----------------------+-----------------------+
                                                          |
                                                          v
                                       +-------------------------------------+
                                       |       ThreatLens REST API v1        |
                                       |  FastAPI · Pydantic v2 · JWT RBAC   |
                                       +-------------------------------------+
                                                          |
                                  +-----------------------+-----------------------+
                                  |                                               |
                                  v                                               v
                    +---------------------------+                   +---------------------------+
                    |  SOC Interactive Console  |                   | Next.js / External Tools  |
                    |  Embedded SPA Dashboard   |                   | SIEM / STIX 2.1 Bundles / |
                    |  Chart.js, Leaflet Map    |                   | Security Automation (SOAR)|
                    +---------------------------+                   +---------------------------+
```

For full architectural specifications, see [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

---

## 🛡️ Key Features & Capabilities

| Capability | Specification | PRD Reference |
| :--- | :--- | :--- |
| **Multi-Feed Ingestion** | Ingests from AbuseIPDB, URLhaus, MalwareBazaar, ThreatFox, Feodo Tracker, and AlienVault OTX. | FR-01, FR-04, FR-05 |
| **Canonical Deduplication** | Normalizes defanged inputs (`hxxp://`, `1[.]1[.]1[.]1`) and merges records into canonical indicators while retaining full per-feed reporting provenance. | FR-02, FR-03 |
| **Severity Scoring Engine** | Transparent, formulaic 0–100 severity calculation. Indicators scoring $\ge 70$ automatically promote to the SOC triage queue. | FR-13, FR-17 |
| **Internal Telemetry Correlation** | Correlates incoming external IOCs against Palo Alto firewall, CrowdStrike EDR, and Squid proxy telemetry. | FR-16 |
| **Real-Time WebSocket Gateway** | Under 5-second streaming delivery of critical indicators (`indicators.high_severity`) and alerts (`alerts.stream`). | FR-15 |
| **Persona-Based Dashboards** | Custom dashboards tailored for CISO, SOC Analysts, Incident Responders, Threat Hunters, Security Engineers, and Admins. | Section 12 |
| **Global Attack Heatmap** | Interactive Leaflet geographic map visualizing threat origins, coordinates, and target density. | FR-20 |
| **MITRE ATT&CK Matrix** | Enterprise technique mapping (`T1071.001`, `T1566`, `T1190`, `T1486`) with faceted search and visual coverage heatmaps. | FR-07, FR-25 |
| **STIX 2.1 & CSV Export** | One-click export of standardized STIX 2.1 JSON Bundles (`/api/v1/export/stix`) and CSVs (`/api/v1/export/csv`). | FR-24 |
| **100% Immutable Audit Trail** | Tamper-evident, append-only audit logging recording actor, timestamp, action, and target entity for compliance. | FR-27 |

---

## 🔢 Severity Scoring Algorithm

ThreatLens calculates a reproducible **0–100 severity score** using four weighted components:

$$\text{Severity Score} = 0.40 \times S_{\text{rep}} + 0.25 \times C_{\text{src}} + 0.15 \times R_{\text{rec}} + 0.20 \times I_{\text{sight}}$$

```
+-------------------------------------------------------------------------------------------------+
| Component                       | Weight | Description / Calculation                            |
+-------------------------------------------------------------------------------------------------+
| Base Reputation (S_rep)         |  40%   | Direct external feed confidence score [0 - 100].     |
| Source Corroboration (C_src)    |  25%   | 1 source = 45, 2 sources = 75, 3+ sources = 100.     |
| Recency Decay (R_rec)           |  15%   | <= 1 day = 100, <= 7 days = 80, <= 30d = 50, >30d=20.|
| Internal Sightings (I_sight)    |  20%   | 0 sights = 0, 1 sight = 60, 2-5 sights = 85, >5 = 100|
+-------------------------------------------------------------------------------------------------+
```

- **Triage Threshold**: Any indicator scoring $\ge 70$ is automatically converted to an actionable Alert.
- **Critical Classification**: Scores $\ge 85$ trigger a `CRITICAL` priority alert with immediate WebSocket broadcast.

---

## 👥 Demo Persona Accounts

All demo accounts are pre-configured with role-based access control and use the standard demo password:

> **Universal Demo Password**: `ThreatLens@2026!`

| Persona | Role | Username | Primary Workspace & Capabilities |
| :--- | :--- | :--- | :--- |
| **Priya Nair** | Tier-2 SOC Analyst | `analyst` | **SOC Analyst Triage Queue**: Inline alert triage, indicator inspection drawer, Acknowledge / Escalate workflows. |
| **Rachel Adeyemi** | Chief Information Security Officer (CISO) | `ciso` | **Executive Overview**: 0–100 Threat Exposure Index, 30-day incident velocity, category breakdowns, top targeted assets. |
| **Daniel Okafor** | Incident Response Lead | `ir_lead` | **Incident Workspaces**: Active incident management, interactive containment checklists, append-only chronological timelines. |
| **Mei Lin Tan** | Threat Hunter | `hunter` | **Threat Hunting**: Sub-second faceted search, MITRE ATT&CK enterprise matrix heatmap, and IOC relationship pivoting. |
| **Alex Rivera** | Administrator | `admin` | **System Governance**: Full administrative control, user RBAC management, and immutable audit logs. |
| **Sam Chen** | Security Engineer | `engineer` | **Feed Configuration**: Ingestion feed health monitoring, manual polling triggers, and external API integrations. |

---

## 📁 Project Directory Structure

```
sentinova/
├── backend/                               # FastAPI CTI Application & Services
│   ├── app/
│   │   ├── api/v1/                        # Versioned REST API Endpoints
│   │   │   ├── alerts.py                  # Alert triage, escalation & status
│   │   │   ├── audit.py                   # Immutable audit log queries
│   │   │   ├── auth.py                    # JWT authentication & session refresh
│   │   │   ├── export.py                  # STIX 2.1 & CSV exports
│   │   │   ├── feeds.py                   # Ingestion feed management & polling
│   │   │   ├── incidents.py               # Incident workspaces & chronological timeline
│   │   │   ├── indicators.py              # Canonical indicator queries & enrichments
│   │   │   ├── router.py                  # Centralized API v1 router
│   │   │   ├── search.py                  # Full-text & faceted search
│   │   │   └── stats.py                   # Threat Exposure Index & metrics
│   │   ├── core/                          # Infrastructure & Configuration
│   │   │   ├── config.py                  # Pydantic Settings & environment variables
│   │   │   ├── database.py                # SQLAlchemy engine & session factory
│   │   │   ├── deps.py                    # JWT validation & RBAC dependency injection
│   │   │   ├── security.py                # Password hashing (bcrypt) & JWT token handling
│   │   │   └── websocket.py               # Real-time WebSocket connection manager
│   │   ├── ingestion/                     # Multi-Feed Ingestion Pipeline
│   │   │   ├── feeds/                     # Automated Threat Collectors
│   │   │   │   ├── abuseipdb.py           # AbuseIPDB API collector
│   │   │   │   ├── base.py                # Base collector abstract class
│   │   │   │   ├── feodotracker.py        # Feodo Tracker botnet collector
│   │   │   │   ├── malwarebazaar.py       # MalwareBazaar sample hash collector
│   │   │   │   ├── otx.py                 # AlienVault OTX pulse collector
│   │   │   │   ├── threatfox.py           # ThreatFox C2 indicator collector
│   │   │   │   └── urlhaus.py             # URLhaus payload URL collector
│   │   │   ├── deduplicator.py            # Deduplication, provenance & telemetry matcher
│   │   │   ├── manager.py                 # Multi-feed polling manager
│   │   │   └── normalizer.py              # Defanging & regex IOC classifier
│   │   ├── models/                        # SQLAlchemy Database Entities
│   │   │   ├── alert.py                   # Alert & AlertRule models
│   │   │   ├── audit.py                   # Immutable AuditLog model
│   │   │   ├── base.py                    # SQLAlchemy declarative base
│   │   │   ├── feed.py                    # Feed configuration & polling status
│   │   │   ├── incident.py                # Incident, Timeline, and Task entities
│   │   │   ├── indicator.py               # Canonical Indicator, Sources, Tags, ATT&CK
│   │   │   ├── security_event.py          # Internal telemetry event model
│   │   │   └── user.py                    # User account & UserRole enum
│   │   ├── schemas/                       # Pydantic v2 Request/Response Validation
│   │   │   ├── alert.py, audit.py, feed.py, incident.py, indicator.py, user.py
│   │   ├── seed/                          # Database Seeding Engine
│   │   │   └── seed_data.py               # Seeds 6 personas, telemetry, and initial feeds
│   │   ├── services/                      # Business Logic Engines
│   │   │   ├── audit.py                   # Audit event recorder
│   │   │   └── scoring.py                 # Deterministic 0-100 severity scoring engine
│   │   ├── static/                        # Embedded SOC Single-Page Application (SPA)
│   │   │   ├── app.js                     # SPA controllers, WebSockets, Chart.js, Leaflet
│   │   │   └── index.html                 # Dark SOC theme HTML console
│   │   └── main.py                        # FastAPI entrypoint, lifespan & static mounting
│   ├── tests/                             # Automated Test Suite (Pytest)
│   │   ├── test_auth_rbac.py              # RBAC & JWT token validation tests
│   │   ├── test_normalizer.py             # Defanger & IOC classification tests
│   │   └── test_scoring.py                # Severity scoring engine unit tests
│   ├── .env.example                       # Environment variable template
│   ├── Dockerfile                         # Production backend container definition
│   ├── requirements.txt                   # Python dependencies
│   └── threatlens.db                      # Local SQLite database (seeded)
├── frontend/                              # Next.js 14 Dashboard Service
│   ├── src/app/                           # Next.js App Router (Layout, Page, CSS)
│   ├── Dockerfile                         # Frontend container definition
│   ├── package.json                       # Next.js, React, Tailwind & Lucide dependencies
│   ├── tailwind.config.js                 # Cyber SOC theme tokens
│   └── tsconfig.json                      # TypeScript configuration
├── docs/                                  # Platform Documentation
│   ├── ARCHITECTURE.md                    # Deep-dive architectural specification
│   └── PRD.md                             # Formatted Product Requirements Document (PRD v1.0)
├── 5753463d40ab1eb8eb18fa167e778651.docx  # Baseline PRD Document Archive
├── docker-compose.yml                     # Multi-container orchestration
└── README.md                              # This documentation
```

---

## 🚀 Quickstart & Installation Guide

### Prerequisites
- **Python**: Version 3.11 or higher
- **Node.js**: Version 18+ (optional, for Next.js development)
- **Docker & Docker Compose** (optional, for full-stack containerization)

---

### Option 1: Direct Local Bring-Up (Recommended for Evaluation)

The backend includes a pre-packaged, zero-dependency SQLite store and serves the complete interactive single-page application directly.

#### 1. Clone & Navigate
```bash
git clone https://github.com/your-org/sentinova.git
cd sentinova
```

#### 2. Activate the Virtual Environment
- **Windows PowerShell**:
  ```powershell
  .\backend\venv\Scripts\Activate.ps1
  ```
- **Linux / macOS Bash**:
  ```bash
  source backend/venv/bin/activate
  ```
*(If creating a fresh virtual environment: `python -m venv backend/venv` followed by `pip install -r backend/requirements.txt`)*

#### 3. Configure Environment Variables
```bash
# Copy the template
cp backend/.env.example backend/.env
```
*(The defaults in `.env.example` work out of the box with SQLite)*

#### 4. Seed the Database
Populate the database with the 6 persona accounts, sample Palo Alto/EDR telemetry events, and baseline feed indicators:
```bash
cd backend
python -m app.seed.seed_data
```

#### 5. Launch the ThreatLens Platform
```bash
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

#### 6. Access ThreatLens
- **Interactive SOC Dashboard**: [http://localhost:8000](http://localhost:8000) or [http://localhost:8000/dashboard](http://localhost:8000/dashboard)
- **Interactive OpenAPI 3 / Swagger Docs**: [http://localhost:8000/docs](http://localhost:8000/docs)
- **Alternative ReDoc UI**: [http://localhost:8000/redoc](http://localhost:8000/redoc)
- **Health Check Endpoint**: [http://localhost:8000/health](http://localhost:8000/health)

---

### Option 2: Docker Compose (Full Stack)

To run the complete production environment including PostgreSQL 16, Redis 7, Elasticsearch 8, the FastAPI backend, and the Next.js frontend:

```bash
docker-compose up --build
```

- **Next.js Portal**: [http://localhost:3000](http://localhost:3000)
- **FastAPI Backend & SOC Dashboard**: [http://localhost:8000](http://localhost:8000)
- **Elasticsearch API**: [http://localhost:9200](http://localhost:9200)

---

## 📡 API & WebSocket Reference

### Core REST Endpoints (`/api/v1`)

| Method | Endpoint | Description | Access / Role |
| :--- | :--- | :--- | :--- |
| `POST` | `/api/v1/auth/token` | Authenticate with username/password, returns JWT bearer token | Public |
| `GET` | `/api/v1/auth/me` | Fetch profile and permissions for currently authenticated user | Authenticated |
| `GET` | `/api/v1/indicators` | Paginated search of canonical indicators with filter parameters | Authenticated |
| `GET` | `/api/v1/indicators/{id}` | Inspect indicator details, multi-source provenance, and metadata | Authenticated |
| `POST` | `/api/v1/indicators/{id}/enrich`| Trigger manual external reputation enrichment | Analyst, Admin |
| `GET` | `/api/v1/alerts` | Retrieve prioritized SOC alert queue sorted by severity score | Authenticated |
| `POST` | `/api/v1/alerts/{id}/triage` | Update alert triage status (`acknowledged`, `resolved`, `closed`) | SOC Analyst, Admin |
| `POST` | `/api/v1/alerts/{id}/escalate` | Escalate an active alert into a formal Incident workspace | SOC Analyst, Admin |
| `GET` | `/api/v1/incidents` | List active security incidents and response statuses | Authenticated |
| `POST` | `/api/v1/incidents/{id}/timeline`| Append an immutable note or forensic action to incident timeline | IR Lead, Admin |
| `GET` | `/api/v1/feeds` | List all threat feeds, collector status, and ingestion metrics | Authenticated |
| `POST` | `/api/v1/feeds/{name}/poll` | Trigger manual on-demand feed polling and deduplication | Engineer, Admin |
| `GET` | `/api/v1/stats/exposure-index` | Calculate CISO Threat Exposure Index (0–100) and risk posture | Authenticated |
| `GET` | `/api/v1/stats/mitre-matrix` | MITRE ATT&CK technique frequency and enterprise matrix heatmap | Authenticated |
| `GET` | `/api/v1/export/stix` | Export filtered indicators as standardized **STIX 2.1 JSON Bundle** | Authenticated |
| `GET` | `/api/v1/export/csv` | Export canonical indicators in CSV format for SIEM/EDR ingest | Authenticated |
| `GET` | `/api/v1/audit/logs` | Fetch immutable audit logs for compliance and accountability | Admin, CISO |

### Real-Time WebSocket Channels

Connect via WebSocket to `ws://localhost:8000/ws?channel=<channel_name>`:
- `alerts.stream`: Broadcasts newly elevated security alerts ($\text{score} \ge 70$) in real time ($< 5\text{s}$ latency).
- `indicators.high_severity`: Streams high-severity external indicators as they are normalized and scored.

---

## 🧪 Automated Test Suite

ThreatLens maintains rigorous automated testing covering indicator normalization, defanging, the 0–100 severity scoring algorithm, and JWT RBAC authentication.

### Running Pytest
```bash
# From project root:
.\backend\venv\Scripts\python.exe -m pytest .\backend\tests -v
```

### Test Coverage Highlights
- `test_scoring.py`: Validates deterministic 40/25/15/20 component weighting, recency decay over 1/7/30 days, source corroboration steps, and internal sightings multipliers.
- `test_normalizer.py`: Validates defanging (`hxxp`, `1[.]1[.]1[.]1`) and regex detection for IPv4, SHA-256, MD5, CVEs, emails, domains, and URLs.
- `test_auth_rbac.py`: Validates password hashing (bcrypt), JWT generation, claims parsing, and role enforcement.

```
backend/tests/test_auth_rbac.py::test_password_hash_and_verify PASSED
backend/tests/test_auth_rbac.py::test_create_access_token_payload PASSED
backend/tests/test_normalizer.py::test_defanging PASSED
backend/tests/test_normalizer.py::test_indicator_type_detection PASSED
backend/tests/test_scoring.py::test_scoring_weights PASSED
backend/tests/test_scoring.py::test_source_corroboration PASSED
backend/tests/test_scoring.py::test_recency_decay PASSED
backend/tests/test_scoring.py::test_internal_sightings_multiplier PASSED

*Sentinova Security Systems · ThreatLens CTI Platform · Internal & Confidential*
