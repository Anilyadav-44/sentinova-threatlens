# ThreatLens — Cyber Threat Intelligence (CTI) Platform
## Product Requirements Document (PRD) v1.0 Baseline

> **Document Owner**: Product & Security Engineering, Sentinova Security Systems
> **Classification**: Internal — Confidential
> **Source File**: 5753463d40ab1eb8eb18fa167e778651.docx (Official PRD Archive)
> **Delivery Model**: Single-engineer build, 4-week delivery cycle

---

SENTINOVA SECURITY SYSTEMS

Product Requirements Document

ThreatLens

Cyber Threat Intelligence Dashboard

An enterprise-grade platform for aggregating, correlating, scoring and operationalising cyber threat intelligence across a Security Operations Centre.

Document Control

Document Title

ThreatLens — Cyber Threat Intelligence Dashboard: Product Requirements Document

Document Owner

Product & Security Engineering, Sentinova Security Systems

Version

1.0 (Baseline)

Status

Approved for Build

Classification

Internal — Confidential

Delivery Model

Single-engineer build, 4-week (20 working-day) delivery cycle

Intended Use

Capstone / final-year project, professional portfolio, and internship demonstration

Date of Issue

01 July 2026

REVISION HISTORY

Version

Date

Author

Summary of Change

0.1

10 Jun 2026

Product & Security Engineering

Initial draft — scope, personas, functional baseline

0.5

20 Jun 2026

Product & Security Engineering

Architecture, data model and API design added

0.9

28 Jun 2026

Product & Security Engineering

Security, deployment, testing and roadmap finalised

1.0

01 Jul 2026

Product & Security Engineering

Baselined and approved for build

APPROVALS

Role

Responsibility

Sign-off

Product Owner

Scope, priorities and acceptance criteria

Approved

Security Architect

Threat model, control set and data protection

Approved

Engineering Lead

Technical feasibility within the 4-week window

Approved

Table of Contents

1.  Project Overview	4

2.  Problem Statement	4

3.  Objectives and Goals	5

4.  Target Users	6

5.  User Personas	6

6.  Functional Requirements	8

7.  Non-Functional Requirements	10

8.  System Architecture	11

9.  Database Design	13

10.  API Architecture	14

11.  User Roles and Permissions	15

12.  Dashboard Design Requirements	16

13.  Security Requirements	17

14.  Deployment Architecture	18

15.  Scalability Considerations	19

16.  Future Enhancements	20

17.  Success Metrics	20

18.  Development Roadmap	21

19.  Testing Strategy	22

20.  Technology Stack Recommendations	23

21.  Tools Required	24

1. Project Overview

ThreatLens is a Cyber Threat Intelligence (CTI) platform that consolidates threat data from public feeds, commercial subscriptions and internal telemetry into a single operational surface for a Security Operations Centre (SOC). It transforms fragmented, high-volume threat data into ranked, contextual, and actionable intelligence that analysts can act on in seconds rather than hours.

The platform ingests indicators of compromise (IOCs) — IP addresses, domains, URLs and file hashes — enriches them against reputation and detection services, correlates them against internal security events, assigns a confidence-weighted severity score, and surfaces the results through role-specific dashboards. It is designed around the standards a real SOC operates on: STIX 2.1 for representing intelligence, TAXII 2.1 for exchanging it, the MITRE ATT&CK framework for adversary technique mapping, the Traffic Light Protocol (TLP) for handling classification, and the Cyber Kill Chain and Diamond Model for structuring analysis.

Scope of this Document

This PRD defines the complete product: the problem it solves, the users it serves, its functional and non-functional requirements, the system and data architecture, the API and security design, and the deployment, scaling and testing strategy. It is scoped to be built end-to-end by a single engineer across a focused four-week delivery cycle, while remaining architecturally faithful to how a commercial CTI platform is constructed.

In Scope

Aggregation and normalisation of threat intelligence from multiple public and private sources into a unified schema.

IOC lifecycle management with enrichment, deduplication, confidence scoring and expiry.

Reputation, malicious-domain, and malware-hash analysis workflows.

Real-time monitoring, alerting, correlation and role-based dashboards (Executive, SOC Analyst, Incident Response, Threat Hunting).

Reporting, export (STIX/CSV/PDF), audit logging and third-party tool integration.

Out of Scope

Active response actions on production infrastructure (blocking, quarantine, firewall changes) — the platform recommends and exports, it does not enforce.

Full sandbox detonation of malware samples; the platform relies on external analysis verdicts rather than executing samples itself.

Replacing a SIEM — the platform correlates and enriches, and integrates with a SIEM rather than superseding it.

2. Problem Statement

Security teams do not suffer from a shortage of threat data — they suffer from an excess of it, spread across disconnected tools with no shared context. A typical mid-sized SOC subscribes to several open and commercial feeds, each with its own format, update cadence and reliability, and each surfacing thousands of indicators per day. Analysts spend a disproportionate share of their time collecting, de-duplicating and manually cross-referencing this data before any actual analysis begins.

Core Problems Addressed

Fragmentation. Threat data lives in browser tabs, spreadsheets and separate vendor portals with no single source of truth, so the same indicator is investigated repeatedly by different analysts.

Volume and noise. Feeds deliver far more indicators than a team can triage. Without confidence-weighted scoring, genuinely high-risk indicators are buried alongside stale or low-value ones.

Lack of context. A raw indicator ("185.220.101.4 is malicious") is not actionable on its own. Analysts need to know why it is malicious, how confident the sources are, which ATT&CK techniques it maps to, and whether it has been seen inside the organisation.

Slow correlation. Linking an external indicator to internal events is manual and error-prone, which lengthens the time between an indicator appearing in a feed and a defender acting on it.

Poor auditability. When intelligence drives a decision, teams frequently cannot reconstruct which source, at what confidence, at what time, led to that decision — a gap for both incident review and compliance.

The result is a measurable operational cost: elevated mean-time-to-detect (MTTD) and mean-time-to-respond (MTTR), analyst fatigue, and defensive decisions made on incomplete information. This platform exists to close that gap by turning scattered, unranked threat data into a single, scored, correlated and auditable intelligence picture.

3. Objectives and Goals

The platform's objectives are expressed as measurable outcomes so that success can be evaluated rather than asserted.

Primary Objectives

Unify. Provide a single normalised store of threat intelligence aggregated from at least six distinct sources, deduplicated to a canonical indicator record.

Prioritise. Assign every indicator a transparent, reproducible severity score (0–100) derived from source reputation, confidence, recency and internal sightings, so analysts always work the highest-risk items first.

Correlate. Automatically match incoming indicators against internal security events and existing incidents to reduce manual cross-referencing.

Operationalise. Deliver role-specific dashboards and exports that feed directly into detection tooling (SIEM, firewall, EDR) via standard formats.

Account. Maintain a complete, tamper-evident audit trail of every intelligence action for review and compliance.

Measurable Goals

Goal

Target

Feed sources integrated at launch

≥ 6 public/private sources

IOC enrichment latency (per indicator, cached vs. cold)

< 300 ms cached / < 3 s cold

Dashboard time-to-first-paint on the analyst view

< 2 seconds

Real-time alert delivery from ingestion to UI

< 5 seconds via WebSocket

Deduplication accuracy on overlapping feeds

≥ 99% canonical merge

Reduction in manual triage steps per indicator (vs. manual baseline)

≥ 60%

Audit coverage of state-changing actions

100%

Non-Goals

The platform does not aim to be a real-time packet inspection or IDS/IPS engine.

It does not attempt automated attribution to named threat actors beyond mapping to ATT&CK techniques and documented campaigns.

4. Target Users

The platform serves the full escalation chain of a security operation, from the analyst watching the feed at 2 a.m. to the executive who needs a one-glance risk posture the next morning. Each user group has a distinct information need, which drives the role-specific dashboard design in Section 12.

User Group

Primary Need

Interaction Pattern

SOC Analysts (Tier 1/2)

Rapid triage and enrichment of incoming indicators and alerts

High-frequency, continuous monitoring

Incident Responders

Timeline reconstruction and correlation during active incidents

Burst, investigation-driven

Threat Hunters

Proactive pivoting across indicators to find undetected activity

Exploratory, query-heavy

SOC Managers / Leads

Team workload, alert throughput and coverage oversight

Periodic, supervisory

CISO / Executives

Aggregated risk posture and trend reporting

Low-frequency, summary-level

Security Engineers

Feed configuration, integrations and platform health

Administrative, as-needed

5. User Personas

Four representative personas anchor the product decisions in this document. They are used throughout the requirements to justify feature priority and dashboard layout.

Priya Nair  — Tier-2 SOC Analyst

Profile

Experience

3 years in a 24×7 SOC; strong on triage, learning threat hunting

Context

Works rotating shifts; monitors alert queue and escalations continuously

Tools today

SIEM console, VirusTotal, AbuseIPDB, a shared spreadsheet of indicators

Goals

Clear the alert queue without missing a genuinely critical indicator.

Enrich an indicator in one place instead of pivoting across five browser tabs.

Hand off clean, contextual notes when escalating to incident response.

Pain Points

The same suspicious IP gets investigated three times per shift by different people.

No single score to tell her what to work first, so triage order is guesswork.

Copy-pasting between tools introduces errors under time pressure.

How they use ThreatLens

Lives in the SOC Analyst dashboard; works the queue sorted by severity score.

Uses one-click enrichment and the correlation panel to see internal sightings.

Tags and escalates indicators, which auto-populate the incident timeline.

Daniel Okafor  — Incident Response Lead

Profile

Experience

8 years; leads containment and post-incident review

Context

Pulled into active incidents; needs the full story fast, then defensible records

Tools today

EDR, ticketing, forensic tooling, ad-hoc timelines in documents

Goals

Reconstruct exactly what happened, in order, with sources attached.

See every indicator, event and analyst action tied to one incident.

Produce an evidence-backed report without rebuilding the timeline by hand.

Pain Points

Timelines are stitched together manually from several tools after the fact.

Hard to prove which intelligence, at what confidence, drove each decision.

Reporting eats hours that should go to containment.

How they use ThreatLens

Uses the Incident Response dashboard and incident timeline as the system of record.

Relies on event correlation to link external IOCs to internal activity.

Generates the incident report directly from the platform's audit trail.

Mei Lin Tan  — Threat Hunter

Profile

Experience

6 years; proactive hunting, detection engineering, ATT&CK-driven

Context

Hypothesis-led hunts; pivots across indicators looking for what alerts missed

Tools today

SIEM search, MISP, custom scripts, ATT&CK Navigator

Goals

Pivot quickly from one indicator to related infrastructure and techniques.

Map observed activity to ATT&CK to find coverage gaps.

Save and share hunts so successful ones become detections.

Pain Points

Pivoting means writing throwaway queries against several data stores.

Relationships between indicators are implicit and easily lost.

Good hunts rarely get captured for reuse.

How they use ThreatLens

Uses the Threat Hunting dashboard with full-text and faceted search over Elasticsearch.

Explores the indicator relationship graph and ATT&CK technique overlay.

Saves queries as reusable hunts and exports findings as new detections.

Rachel Adeyemi  — Chief Information Security Officer (CISO)

Profile

Experience

18 years; owns security strategy and board reporting

Context

Needs posture and trend at a glance, and confidence the SOC is keeping pace

Tools today

Manually assembled slide decks from analyst summaries

Goals

Understand current risk posture and how it is trending.

Report to the board with credible, current numbers.

Confirm the team is prioritising the threats that matter.

Pain Points

Executive reporting is manual, slow and out of date the moment it is produced.

No consistent, defensible measure of exposure over time.

How they use ThreatLens

Uses the Executive Overview dashboard for posture, trends and top threats.

Schedules automated reports instead of commissioning manual decks.

6. Functional Requirements

Requirements are grouped by capability and prioritised using MoSCoW. Must items are required for the 4-week baseline; Should items are built if capacity allows; Could items are candidates for the enhancement backlog.

6.1 Threat Intelligence Aggregation

ID

Requirement

Priority

FR-01

Ingest indicators from at least six configured public/private sources on independent schedules.

Must

FR-02

Normalise every ingested indicator into a canonical schema regardless of source format (JSON, CSV, STIX).

Must

FR-03

Deduplicate indicators to a single canonical record, retaining a per-source provenance list.

Must

FR-04

Support TAXII 2.1 collections as an ingestion transport.

Should

FR-05

Allow a security engineer to add, disable and re-poll a feed from the UI without code changes.

Should

6.2 IOC Management

ID

Requirement

Priority

FR-06

Store, view, edit and expire IOCs of type IP, domain, URL, file hash (MD5/SHA-1/SHA-256), email and CVE.

Must

FR-07

Attach tags, TLP marking, ATT&CK technique IDs and free-text analyst notes to any IOC.

Must

FR-08

Apply configurable time-to-live so stale indicators automatically age out of active status.

Should

FR-09

Maintain relationships between IOCs (e.g. domain resolves-to IP, hash communicates-with domain).

Should

6.3 Analysis & Enrichment

ID

Requirement

Priority

FR-10

Perform IP reputation analysis, aggregating verdicts and abuse confidence from reputation sources.

Must

FR-11

Detect and flag malicious domains, including newly-registered and known-phishing domains.

Must

FR-12

Look up malware hashes against detection services and display engine verdict ratios.

Must

FR-13

Compute a 0–100 severity score per indicator from a documented, reproducible scoring model.

Must

FR-14

Enrich indicators with geolocation and ASN/owner data for mapping and pivoting.

Should

6.4 Monitoring, Correlation & Alerting

ID

Requirement

Priority

FR-15

Stream new high-severity indicators and alerts to connected dashboards in real time.

Must

FR-16

Correlate incoming indicators against ingested internal security events and open incidents.

Must

FR-17

Provide a configurable alert rule engine (threshold, category, source, score) with per-user routing.

Must

FR-18

Manage alert lifecycle: new → acknowledged → in-progress → resolved → closed, with assignee.

Must

FR-19

Maintain an ordered, immutable incident timeline that auto-captures related indicators and actions.

Should

6.5 Visualisation & Reporting

ID

Requirement

Priority

FR-20

Render a global geographic heatmap of threat origin and target activity.

Must

FR-21

Provide trend charts (volume over time, category breakdown, top sources, severity distribution).

Must

FR-22

Allow users to build custom dashboards from a widget library and save layouts per user.

Should

FR-23

Generate scheduled and on-demand threat reports (PDF) with an executive summary and detail.

Should

FR-24

Export indicators and intelligence as STIX 2.1 bundles and CSV for downstream tooling.

Must

6.6 Search, Access & Governance

ID

Requirement

Priority

FR-25

Provide full-text and faceted search across all indicators and events with sub-second response.

Must

FR-26

Enforce role-based access control across all data and actions (see Section 11).

Must

FR-27

Write an immutable audit log entry for every authentication and state-changing action.

Must

FR-28

Expose authenticated REST and WebSocket APIs for integration with external security tools.

Must

FR-29

Provide inbound integration hooks (webhook/API) for SIEM, EDR and ticketing systems.

Could

7. Non-Functional Requirements

Non-functional requirements (NFRs) define how the system must behave under load, over time and under adverse conditions. Each is stated as a testable target.

ID

Category

Requirement & Target

NFR-01

Performance

Dashboard interactive load < 2 s; API p95 response < 400 ms under nominal load.

NFR-02

Real-time

End-to-end alert propagation (ingest → UI) < 5 s via WebSocket.

NFR-03

Scalability

Sustain ≥ 50,000 indicator ingests/hour and ≥ 200 concurrent users through horizontal scaling.

NFR-04

Availability

Target 99.5% monthly availability for the core API and dashboard.

NFR-05

Search latency

Full-text/faceted queries return < 800 ms at p95 over 10M+ indexed documents.

NFR-06

Security

All data in transit over TLS 1.2+; sensitive data encrypted at rest (AES-256).

NFR-07

Reliability

No data loss on service restart; ingestion is idempotent and replay-safe.

NFR-08

Maintainability

≥ 80% unit-test coverage on core scoring, correlation and ingestion modules.

NFR-09

Usability

Primary analyst workflow (triage → enrich → escalate) completable in ≤ 4 clicks.

NFR-10

Observability

Structured logs, health endpoints and metrics exposed for every service.

NFR-11

Portability

Entire stack runs from a single docker-compose up locally and on Kubernetes in cloud.

NFR-12

Compliance

Audit records retained ≥ 1 year; access controls support least-privilege review.

8. System Architecture

The platform follows a layered, service-oriented architecture. Ingestion, enrichment/scoring, and API/real-time delivery are decoupled so that heavy feed processing never blocks the interactive analyst experience. Redis provides both a caching layer and a lightweight message channel between ingestion workers and the real-time gateway.

8.1 Architectural Layers

Presentation Layer. A React/Next.js single-page application delivering the role-specific dashboards, consuming the REST API for data and a WebSocket channel for live updates.

API & Gateway Layer. A FastAPI application exposing versioned REST endpoints and a WebSocket gateway. It handles authentication, RBAC enforcement, request validation and audit logging.

Processing Layer. Background workers that poll feeds, normalise and deduplicate indicators, call enrichment services, compute severity scores and run correlation. Scheduled by a task queue so ingestion runs independently of user traffic.

Intelligence & Data Layer. PostgreSQL as the system of record, Elasticsearch as the search/analytics index, and Redis for caching enrichment results and brokering real-time events.

Integration Layer. Outbound connectors (STIX/TAXII, CSV, webhooks) and inbound hooks that let external tools push events in and pull intelligence out.

8.2 Logical Architecture Diagram

External Threat Sources

OTX · AbuseIPDB · URLhaus

MalwareBazaar · Feodo · TAXII

Enrichment Services

IP reputation · Geo/ASN

Malware verdicts

Integration Endpoints

SIEM · EDR · Ticketing

Webhooks (in/out)

PROCESSING LAYER — Task Queue & Workers

Feed Poller  →  Normaliser / Deduper  →  Enrichment  →  Scoring Engine  →  Correlation

PostgreSQL

System of record

Indicators · Incidents · Audit

Elasticsearch

Search & analytics

10M+ indexed docs

Redis

Cache & event bus

Enrichment · Pub/Sub

API & REAL-TIME GATEWAY (FastAPI)

REST (versioned) · WebSocket · Auth + RBAC · Audit

PRESENTATION — React / Next.js SPA

Executive · SOC Analyst · Incident Response · Threat Hunting dashboards

Figure 1. Logical architecture. External sources flow through ingestion workers into the data layer; the API and real-time gateway serve the dashboards while integration connectors move intelligence in and out.

8.3 Key Data Flows

Ingestion. A scheduled worker polls a feed, normalises each record to the canonical schema, and upserts it into PostgreSQL, deduplicating against existing indicators.

Enrichment & scoring. New or changed indicators are enriched (reputation, geo/ASN, detection verdicts, cached in Redis) and assigned a severity score by the scoring engine.

Indexing. The canonical record is projected into Elasticsearch so it is immediately searchable and available to analytics aggregations.

Correlation & alerting. The indicator is matched against internal events and alert rules; qualifying matches raise an alert published to Redis.

Real-time delivery. The WebSocket gateway consumes the Redis event channel and pushes the alert to subscribed dashboards in under five seconds.

9. Database Design

PostgreSQL is the authoritative store. The schema is normalised around a canonical indicator, with provenance, enrichment, relationships, incidents and audit kept in dedicated tables. Elasticsearch mirrors a denormalised, search-optimised projection of indicators and events; Redis holds only transient cache and pub/sub data.

9.1 Core Tables

Table

Purpose

users

Accounts, hashed credentials, assigned role and status.

roles / permissions

RBAC role definitions and the permissions granted to each.

indicators

Canonical IOC record — value, type, severity score, confidence, TLP, first/last seen, status.

indicator_sources

Provenance: which feed reported an indicator, with per-source confidence and timestamp.

enrichments

Cached enrichment results (reputation, geo/ASN, detection verdicts) linked to an indicator.

indicator_relationships

Typed edges between indicators (resolves-to, communicates-with, drops).

tags / indicator_tags

Free and controlled tags and their many-to-many mapping to indicators.

attack_techniques

MITRE ATT&CK technique reference and mapping to indicators.

feeds

Configured sources, transport, schedule, credentials reference and enabled state.

alerts

Raised alerts with severity, rule reference, lifecycle state and assignee.

alert_rules

User-defined conditions that raise alerts.

incidents

Investigation container linking indicators, alerts and analyst actions.

incident_timeline

Ordered, append-only events belonging to an incident.

security_events

Ingested internal events used for correlation.

reports

Generated report metadata and storage reference.

audit_log

Append-only record of authentication and state-changing actions.

9.2 Representative Table — indicators

Column

Type

Notes

id

UUID (PK)

Primary key, generated on insert.

value

TEXT

The indicator itself (IP, domain, hash, etc.). Indexed and unique per type.

type

ENUM

ip | domain | url | hash_md5 | hash_sha256 | email | cve.

severity_score

SMALLINT

0–100, from the scoring engine.

confidence

SMALLINT

0–100 aggregate source confidence.

tlp

ENUM

clear | green | amber | red.

status

ENUM

active | expired | whitelisted | under_review.

first_seen / last_seen

TIMESTAMPTZ

Lifecycle timestamps used for recency scoring and TTL.

created_at / updated_at

TIMESTAMPTZ

Audit timestamps maintained by the ORM.

9.3 Key Relationships & Indexing

indicator_sources, enrichments, indicator_tags, indicator_relationships and attack mappings all reference indicators.id (one-to-many / many-to-many).

incidents link to alerts and indicators through join tables; incident_timeline rows are append-only and ordered by timestamp.

B-tree indexes on indicators(value, type, status) and severity_score; a composite index supports the default "active, highest severity first" queue query.

The audit_log table is append-only with no UPDATE/DELETE grants to the application role, giving tamper-evidence at the database layer.

10. API Architecture

The platform exposes a versioned REST API for request/response operations and a WebSocket channel for live updates. All endpoints require a valid JWT and are subject to RBAC checks and audit logging. Responses are JSON; list endpoints support pagination, filtering and sorting.

10.1 Design Principles

Versioned base path (/api/v1) so breaking changes never affect existing integrations.

Consistent envelope: predictable success/error shapes, standard HTTP status codes, machine-readable error codes.

Stateless authentication via short-lived access tokens plus refresh tokens; no server-side session store required.

Rate limiting per API key/user and idempotent ingestion endpoints to make retries safe.

OpenAPI 3 specification generated automatically from the FastAPI schema for self-documenting integration.

10.2 Representative REST Endpoints

Method

Endpoint

Purpose

POST

/api/v1/auth/login

Authenticate and issue access + refresh tokens.

GET

/api/v1/indicators

List indicators with filter, sort and pagination.

GET

/api/v1/indicators/{id}

Retrieve one indicator with enrichment and relationships.

POST

/api/v1/indicators/{id}/enrich

Trigger or refresh enrichment for an indicator.

GET

/api/v1/reputation/ip/{ip}

Return aggregated IP reputation analysis.

GET

/api/v1/hash/{sha256}

Return malware hash lookup and verdict ratio.

GET

/api/v1/domains/{domain}/analysis

Return malicious-domain assessment.

GET

/api/v1/search

Full-text/faceted search across indicators and events.

GET

/api/v1/alerts

List and filter alerts.

PATCH

/api/v1/alerts/{id}

Update alert lifecycle state / assignee.

GET

/api/v1/incidents/{id}/timeline

Retrieve the ordered incident timeline.

POST

/api/v1/reports

Generate an on-demand report.

GET

/api/v1/export/stix

Export a STIX 2.1 bundle of selected intelligence.

GET

/api/v1/feeds

List and manage configured feeds (admin).

10.3 Real-time Channels (WebSocket)

Channel

Pushes

alerts.stream

New and updated alerts as they are raised or change state.

indicators.high_severity

Newly ingested indicators above the configured severity threshold.

incidents.{id}

Live timeline updates for a specific incident under investigation.

system.health

Feed and service health changes for the engineering view.

10.4 Error Handling & Security

Uniform error body: { error_code, message, correlation_id } for traceability across services.

401 for missing/expired tokens, 403 for RBAC denials, 409 for idempotency conflicts, 429 for rate-limit breaches.

All input validated at the schema boundary (Pydantic) to prevent injection and malformed data reaching the data layer.

11. User Roles and Permissions

Access is governed by role-based access control (RBAC). Every user is assigned exactly one primary role; each role carries a fixed permission set enforced at the API layer on every request. Roles follow least privilege — a user can only perform actions their role explicitly grants.

11.1 Roles

Role

Description

Administrator

Full control: user and role management, feed configuration, all data and settings.

Security Engineer

Configures feeds and integrations, monitors platform health; no user management.

Incident Responder

Manages incidents, timelines and alerts; can edit indicators tied to an incident.

Threat Hunter

Full read and search across intelligence; creates saved hunts and exports; limited edit.

SOC Analyst

Triages alerts, enriches and tags indicators, escalates to incidents.

Executive (Read-only)

Views executive dashboards and reports; no operational actions.

11.2 Permission Matrix

Capability

Admin

Sec Eng

IR

Hunter

Analyst

Exec

View dashboards

●

●

●

●

●

●

Search intelligence

●

●

●

●

●

—

Enrich / tag indicators

●

●

●

◐

●

—

Manage alerts

●

◐

●

◐

●

—

Manage incidents & timeline

●

—

●

◐

◐

—

Create saved hunts / export

●

●

●

●

◐

—

Generate reports

●

●

●

●

●

●

Configure feeds & integrations

●

●

—

—

—

—

Manage users & roles

●

—

—

—

—

—

View audit log

●

◐

◐

—

—

—

Legend:  ● full access   ◐ limited/contextual access   — no access

12. Dashboard Design Requirements

The interface is organised into four purpose-built dashboards, each mapped to a persona from Section 5, plus a shared widget and notification system. Every dashboard shares a common shell — top navigation, global search, notification tray and user menu — so context is never lost when switching views.

12.1 Executive Overview Dashboard

Audience: CISO / executives (Rachel). Purpose: risk posture at a glance.

Headline risk score and 30-day trend; count of active critical/high indicators.

Top threat categories and top targeted assets/geographies.

Alert throughput and open-vs-resolved trend to show the SOC is keeping pace.

One-click export of the current view to a scheduled executive report.

12.2 SOC Analyst Dashboard

Audience: Tier-1/2 analysts (Priya). Purpose: fast, prioritised triage.

Alert queue sorted by severity score with inline acknowledge / assign / escalate.

Indicator detail drawer with one-click enrichment and source provenance.

Correlation panel showing internal sightings of the selected indicator.

Live counters (new alerts, unassigned, my queue) updated over WebSocket.

12.3 Incident Response Dashboard

Audience: incident responders (Daniel). Purpose: investigation and record-keeping.

Incident workspace listing linked indicators, alerts and analyst actions.

Chronological, append-only incident timeline auto-populated from correlated events.

Containment checklist and one-click report generation from the audit trail.

12.4 Threat Hunting Dashboard

Audience: threat hunters (Mei Lin). Purpose: exploration and pivoting.

Advanced search with facets (type, source, score, tag, ATT&CK technique).

Indicator relationship graph for visual pivoting across linked infrastructure.

ATT&CK technique overlay highlighting coverage and gaps.

Save-as-hunt to persist a query and export findings as new detections.

12.5 Shared Visual Components

Component

Requirement

Global attack heatmap

World map shading threat origin/target density; drill-down by region.

Trend charts

Time-series volume, category breakdown, severity distribution, top sources.

Custom widgets

Users compose dashboards from a widget library; layouts saved per user.

Notifications & alerts

Real-time toast + persistent tray; unread counts; per-user routing.

Search & filter bar

Present on every dashboard; sub-second faceted results.

12.6 UX & Accessibility Requirements

Dark-first palette suited to prolonged SOC monitoring, with a high-contrast light mode.

Consistent severity colour language (critical/high/medium/low) across every view.

Keyboard-navigable core workflows and WCAG 2.1 AA contrast for text and controls.

Responsive layout from a wall-mounted SOC display down to a 13-inch laptop.

13. Security Requirements

As a security product handling sensitive intelligence, the platform must itself meet a high security bar. Requirements are grouped by domain and align with OWASP application security guidance and the principle of least privilege throughout.

13.1 Authentication & Session

JWT-based authentication with short-lived access tokens and rotating refresh tokens.

Passwords hashed with a modern adaptive algorithm (bcrypt/argon2); no plaintext ever stored.

Support for optional multi-factor authentication (TOTP) for privileged roles.

Account lockout and back-off after repeated failed authentication attempts.

13.2 Authorization

RBAC enforced server-side on every endpoint; the UI never enforces access alone.

Object-level checks so users only act on records their role and context permit.

13.3 Data Protection

TLS 1.2+ for all traffic; HSTS enabled at the gateway.

Sensitive fields (credentials, feed API keys, tokens) encrypted at rest with AES-256.

Feed and integration secrets stored in a secrets manager, never in source or config files.

TLP markings honoured on export so restricted intelligence is not shared beyond its handling class.

13.4 Application Hardening

All input validated and parameterised — protection against SQL injection, XSS and SSRF.

Security headers (CSP, X-Content-Type-Options, X-Frame-Options) set at the gateway.

Per-user/API-key rate limiting and request size limits to blunt abuse and DoS.

Dependency and container image scanning in CI to catch known vulnerabilities before release.

13.5 Auditing & Monitoring

Append-only audit log of authentication and every state-changing action, with actor, timestamp and correlation ID.

Structured, centralised application logs with sensitive values redacted.

Health and metrics endpoints for uptime and anomaly monitoring.

13.6 Threat Model Summary

Threat

Mitigation

Credential theft / brute force

Adaptive hashing, MFA for privileged roles, lockout and rate limiting.

Privilege escalation

Server-side RBAC with object-level checks and least privilege.

Injection (SQLi/XSS/SSRF)

Schema validation, parameterised queries, output encoding, egress controls.

Secret leakage

Secrets manager, encryption at rest, redacted logs, no secrets in VCS.

Tampering with intelligence/audit

Append-only audit table, restricted DB grants, integrity checks.

Supply-chain vulnerabilities

Dependency and image scanning gated in CI/CD.

14. Deployment Architecture

The platform is container-first. Every service ships as a Docker image; the full stack runs locally through a single docker-compose file and deploys to a Kubernetes cluster for staging and production. This keeps the development and production environments consistent and makes the project trivial to demonstrate.

14.1 Environments

Environment

Runtime

Purpose

Local / Dev

docker-compose

Single-command bring-up for development and demos.

Staging

Kubernetes (single node)

Integration testing and pre-release validation.

Production

Kubernetes (multi-node)

Scaled, resilient deployment with autoscaling.

14.2 Containerised Services

frontend — the React/Next.js SPA served behind the ingress.

api — the FastAPI REST + WebSocket application (horizontally scalable).

worker — background ingestion, enrichment, scoring and correlation.

scheduler — triggers feed polling and report generation on schedule.

postgres, elasticsearch, redis — stateful backing services (managed or StatefulSets).

14.3 CI/CD Pipeline

Commit triggers the pipeline: lint, type-check and unit tests run first.

Integration tests run against ephemeral service containers.

Docker images are built, scanned for vulnerabilities, and tagged.

Images are pushed to the registry; staging is deployed automatically.

Production deploys on approval via a rolling update with health-gated rollout.

14.4 Cloud Deployment Support

Cloud-agnostic: runs on any managed Kubernetes service (EKS/GKE/AKS).

Managed PostgreSQL, Elasticsearch/OpenSearch and Redis can replace in-cluster instances in production.

Ingress with TLS termination; secrets sourced from the cloud secrets manager.

Infrastructure expressed as code so environments are reproducible.

15. Scalability Considerations

The architecture is designed to grow along two axes independently: ingestion throughput (how much intelligence flows in) and interactive load (how many analysts query it). Decoupling these is the central scaling strategy.

Dimension

Strategy

Ingestion throughput

Stateless, idempotent workers scale horizontally behind the task queue; feeds are polled independently so one slow source never blocks others.

Interactive/API load

The API is stateless (JWT) and scales horizontally behind the ingress; Kubernetes HPA scales pods on CPU/latency.

Search & analytics

Elasticsearch scales via sharding and replicas; heavy aggregations hit the index, never the primary DB.

Caching

Redis caches enrichment results and hot queries, cutting external API calls and DB load.

Database

Read replicas for reporting; partitioning of high-volume tables (indicators, events, audit) by time.

Real-time delivery

The WebSocket gateway consumes a Redis pub/sub channel, so multiple gateway instances fan out the same events.

15.1 Bottleneck Management

External enrichment APIs are rate-limited: results are cached and requests queued/back-pressured to stay within provider limits.

Bulk operations (large exports, report generation) run as background jobs so they never block interactive requests.

Time-based data retention and TTL keep the active dataset bounded and query performance stable as history grows.

16. Future Enhancements

The baseline is deliberately focused. The following enhancements extend the platform toward a full commercial CTI product and form a natural backlog beyond the initial four-week build.

Enhancement

Value

Complexity

Automated actor/campaign clustering

Group related indicators into campaigns for higher-level analysis.

High

ML-based severity refinement

Learn from analyst dispositions to sharpen scoring over time.

High

Native sandbox integration

Detonate samples for first-party verdicts rather than relying on external ones.

High

Bi-directional SOAR playbooks

Trigger automated response workflows from within the platform.

Medium

Collaborative MISP-style sharing

Share curated intelligence with partner organisations via TAXII.

Medium

Mobile companion app

On-call alert acknowledgement and triage from a phone.

Medium

Natural-language threat query

Ask questions of the intelligence store in plain language.

Medium

Dark-web / paste-site monitoring

Extend sourcing to leaked-credential and chatter feeds.

High

17. Success Metrics

Success is measured against product outcomes, operational performance and delivery quality. These map back to the goals in Section 3 and provide concrete acceptance evidence for the finished project.

17.1 Operational Metrics

Metric

Target

How Measured

Mean time to triage an indicator

≤ 90 seconds

Instrumented UI timing

Feeds aggregated & normalised

≥ 6 sources

Feed config audit

Deduplication accuracy

≥ 99%

Overlap test dataset

Real-time alert latency

< 5 seconds

End-to-end trace

Search response (p95)

< 800 ms

Load test

Reduction in manual triage steps

≥ 60%

Workflow comparison

17.2 Product & Delivery Metrics

All Must-have functional requirements delivered and demonstrable end-to-end.

≥ 80% unit-test coverage on scoring, correlation and ingestion; green CI on main.

All four dashboards usable by their target persona without training beyond a short walkthrough.

Zero critical/high vulnerabilities outstanding from the dependency and image scans.

Complete audit coverage of state-changing actions verified by test.

18. Development Roadmap

The build is planned as four one-week sprints for a single engineer, sequenced so that a working vertical slice exists early and each week adds a demonstrable capability. Roughly 30–35 focused hours per week is assumed.

Sprint

Theme

Sprint Goal

Week 1

Foundation & Ingestion

Project scaffolding, auth/RBAC, database schema, and first feeds ingesting into a normalised store.

Week 2

Analysis & Intelligence

Enrichment services, severity scoring engine, IOC management and search over Elasticsearch.

Week 3

Real-time & Dashboards

WebSocket alerting, correlation, and the four role-specific dashboards with charts and heatmap.

Week 4

Reporting, Hardening & Deploy

Reports and exports, security hardening, tests, CI/CD, containerisation and deployment.

Week 1 — Foundation & Ingestion

Repository, docker-compose, PostgreSQL schema and migrations.

JWT authentication, roles/permissions and RBAC middleware.

Feed framework and the first three source integrations with normalisation and deduplication.

Audit logging wired into every state-changing action from day one.

Week 2 — Analysis & Intelligence

Enrichment connectors (IP reputation, geo/ASN, hash and domain lookups) with Redis caching.

Severity scoring engine (documented, unit-tested) and IOC management endpoints/UI.

Elasticsearch projection and full-text/faceted search API.

Three further feeds added to reach the ≥ 6 target.

Week 3 — Real-time & Dashboards

WebSocket gateway, alert rule engine and alert lifecycle.

Event correlation and incident timeline.

Executive, SOC Analyst, Incident Response and Threat Hunting dashboards.

Global heatmap, trend charts and custom widget layout.

Week 4 — Reporting, Hardening & Deployment

Report generation (PDF) and STIX/CSV export.

Security hardening pass, dependency/image scanning and rate limiting.

Test suite to coverage target; CI/CD pipeline green.

Kubernetes manifests, cloud deployment, documentation and demo walkthrough.

19. Testing Strategy

Testing follows the classic pyramid: a broad base of fast unit tests, a focused layer of integration tests across service boundaries, and a thin layer of end-to-end tests over the critical workflows. Security and performance testing run as dedicated tracks.

Layer

Scope

Tooling

Unit

Scoring engine, deduplication, normalisation, RBAC checks, API validation.

Pytest / Jest

Integration

Ingestion → DB → index; API against real Postgres/ES/Redis containers.

Pytest + testcontainers

End-to-end

Triage → enrich → escalate → incident → report, driven through the UI.

Playwright

Performance

Ingestion throughput, search p95, concurrent-user load.

k6 / Locust

Security

Dependency & image scans, auth/RBAC abuse cases, OWASP checks.

Trivy / OWASP ZAP

Contract

OpenAPI schema conformance for external integrators.

Schemathesis

19.1 Quality Gates

Pull requests blocked unless lint, type-check and unit tests pass.

Coverage must not fall below 80% on core intelligence modules.

No critical/high vulnerabilities may be merged; scans run on every build.

19.2 Test Data Approach

Ingestion and enrichment are validated against known-good reference indicators from the public feeds themselves (e.g. documented URLhaus/MalwareBazaar samples), so behaviour is checked against real, verifiable source records.

Correlation is exercised with a controlled set of internal event records that map to those known indicators.

Scoring is verified with table-driven cases that assert exact score outputs for defined inputs.

20. Technology Stack Recommendations

The stack is chosen for enterprise credibility, strong ecosystem support, and single-engineer productivity within the four-week window. Where the brief offered alternatives, the recommended primary choice is stated with a short rationale.

20.1 Frontend

Concern

Recommendation

Rationale

Framework

Next.js (React) + TypeScript

SSR/routing out of the box; type safety across a large UI.

Styling

Tailwind CSS

Fast, consistent, dark-first SOC theming.

Charts

Recharts + a mapping library (Leaflet/MapLibre)

Trend charts plus the geographic heatmap.

State/data

TanStack Query

Caching, background refresh, WebSocket-friendly.

20.2 Backend

Concern

Recommendation

Rationale

API framework

Python + FastAPI

Async, auto OpenAPI, Pydantic validation; ideal for the CTI domain and rapid single-dev delivery.

Real-time

FastAPI WebSockets

Native to the framework; no extra runtime.

Task queue

Celery (or RQ) + Redis

Reliable scheduled ingestion and background jobs.

ORM & validation

SQLAlchemy + Pydantic

Safe queries and strict schema boundaries.

20.3 Data & Infrastructure

Concern

Recommendation

Rationale

System of record

PostgreSQL

Relational integrity for indicators, incidents and audit.

Search & analytics

Elasticsearch (or OpenSearch)

Sub-second full-text and aggregation at scale.

Cache & event bus

Redis

Enrichment cache plus pub/sub for real-time.

Containers & orchestration

Docker + Kubernetes

Consistent local-to-cloud deployment.

CI/CD

GitHub Actions

Lint, test, scan, build and deploy pipeline.

Auth & security

JWT, RBAC, TLS, AES-256, secrets manager

Meets Section 13 requirements.

20.4 Standards & Frameworks Adopted

STIX 2.1 / TAXII 2.1 for representing and exchanging intelligence.

MITRE ATT&CK for technique mapping; Cyber Kill Chain and Diamond Model for analysis structure.

Traffic Light Protocol (TLP) for handling classification; CVSS for vulnerability severity.

OWASP ASVS as the application-security baseline.

21. Tools Required

This section lists everything needed to build, run and demonstrate the project. All primary tooling is free or open-source; the external intelligence services below offer free API tiers sufficient for a full working build.

21.1 Development Tools

Category

Tool

IDE / editor

Visual Studio Code (with Python, ESLint, Prettier, Docker extensions).

Runtimes

Python 3.11+, Node.js 20+ (LTS).

Version control

Git + GitHub (repository, Actions CI/CD, issue tracking).

API testing

Postman or Insomnia; Swagger UI from the generated OpenAPI spec.

Database tools

pgAdmin or DBeaver; Kibana/Dev Tools for Elasticsearch.

Diagramming

draw.io / Excalidraw for architecture and data-flow diagrams.

21.2 Frameworks & Libraries

Layer

Libraries

Frontend

Next.js, React, TypeScript, Tailwind CSS, Recharts, Leaflet/MapLibre, TanStack Query.

Backend

FastAPI, Uvicorn, SQLAlchemy, Pydantic, Celery/RQ, python-jose (JWT), passlib (hashing).

Data clients

psycopg (PostgreSQL), elasticsearch-py, redis-py.

Testing

Pytest, Jest, Playwright, k6/Locust, testcontainers, Schemathesis.

Security scanning

Trivy (images/deps), OWASP ZAP (dynamic), Bandit (Python SAST).

21.3 Infrastructure & Platform

Category

Tool

Containerisation

Docker, Docker Compose.

Orchestration

Kubernetes (local: Minikube/kind; cloud: EKS/GKE/AKS).

CI/CD

GitHub Actions.

Data stores

PostgreSQL, Elasticsearch/OpenSearch, Redis (as containers or managed services).

Secrets

Docker/Kubernetes secrets locally; cloud secrets manager in production.

21.4 Threat Intelligence Sources & Enrichment APIs

These provide the actual intelligence the platform aggregates and the enrichment it performs. Each offers a documented, free API tier suitable for the project.

Source / API

Provides

AlienVault OTX

Community threat intelligence pulses across all IOC types.

AbuseIPDB

IP abuse reports and confidence scoring for reputation analysis.

VirusTotal (Public API)

File hash, URL and domain verdicts across many detection engines.

URLhaus (abuse.ch)

Malicious URLs and payload-serving domains.

MalwareBazaar (abuse.ch)

Malware samples and hashes for lookup and reference testing.

ThreatFox (abuse.ch)

Fresh IOCs linked to malware families.

Feodo Tracker (abuse.ch)

Botnet C2 IP addresses.

Spamhaus / PhishTank

Blocklists and known phishing domains.

GreyNoise (Community)

Context on internet-wide scanning noise to reduce false positives.

Shodan

Host and exposure enrichment for IP indicators.

MITRE ATT&CK (STIX data)

Technique reference for mapping and overlays.

CISA KEV catalog

Known exploited vulnerabilities for CVE prioritisation.

Note. Register for individual API keys where required and store them in the secrets manager, never in source control. Respect each provider's rate limits and terms of use; the caching layer described in Section 15 is designed to keep usage within free-tier allowances.

End of Document — ThreatLens Cyber Threat Intelligence Dashboard PRD v1.0

Sentinova Security Systems · Internal — Confidential