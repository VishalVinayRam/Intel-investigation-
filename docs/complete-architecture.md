# Threat Intelligence Ingestion Pipeline — Complete Architecture & Documentation

## Table of Contents

1. [Project Overview](#1-project-overview)
2. [High-Level Architecture](#2-high-level-architecture)
3. [Namespace Layout](#3-namespace-layout)
4. [Data Flow — End to End](#4-data-flow--end-to-end)
5. [Application Components](#5-application-components)
   - 5.1 [Intel Worker (Legacy)](#51-intel-worker-legacy)
   - 5.2 [Intel Fetcher (Producer)](#52-intel-fetcher-producer)
   - 5.3 [Intel Processor (Consumer)](#53-intel-processor-consumer)
6. [Messaging Layer — NATS JetStream](#6-messaging-layer--nats-jetstream)
7. [Storage Layer — Redis](#7-storage-layer--redis)
8. [Kubernetes Infrastructure](#8-kubernetes-infrastructure)
   - 8.1 [Deployments & StatefulSets](#81-deployments--statefulsets)
   - 8.2 [Services & Networking](#82-services--networking)
   - 8.3 [Horizontal Pod Autoscaler](#83-horizontal-pod-autoscaler)
   - 8.4 [Pod Security Hardening](#84-pod-security-hardening)
9. [Secret Management & Key Rotation](#9-secret-management--key-rotation)
10. [Observability — LGTM Stack](#10-observability--lgtm-stack)
    - 10.1 [Loki — Log Aggregation](#101-loki--log-aggregation)
    - 10.2 [Promtail — Log Shipper](#102-promtail--log-shipper)
    - 10.3 [Tempo — Distributed Tracing](#103-tempo--distributed-tracing)
    - 10.4 [Mimir — Metrics Storage](#104-mimir--metrics-storage)
    - 10.5 [Prometheus — Metrics Scraping](#105-prometheus--metrics-scraping)
    - 10.6 [Grafana — Unified Dashboards](#106-grafana--unified-dashboards)
    - 10.7 [Alerting Rules](#107-alerting-rules)
11. [OpenTelemetry Tracing (In-App)](#11-opentelemetry-tracing-in-app)
12. [Security Policies — Kyverno](#12-security-policies--kyverno)
13. [CI/CD Pipeline — GitHub Actions](#13-cicd-pipeline--github-actions)
    - 13.1 [SAST Scan](#131-sast-scan)
    - 13.2 [SCA Dependency Scan](#132-sca-dependency-scan)
    - 13.3 [Build & Container Scan](#133-build--container-scan)
    - 13.4 [Image Signing](#134-image-signing)
    - 13.5 [Deploy to Staging](#135-deploy-to-staging)
    - 13.6 [Trivy Ignore Policy](#136-trivy-ignore-policy)
14. [Container Images & Dockerfiles](#14-container-images--dockerfiles)
15. [Python Dependencies](#15-python-dependencies)
16. [Known Limitations (POC Scope)](#16-known-limitations-poc-scope)

---

## 1. Project Overview

This project is a **Kubernetes-native threat intelligence ingestion pipeline**. It continuously pulls live indicators of compromise (IOCs) from public threat feeds, routes them through a durable message queue (NATS JetStream), processes and stores them in Redis, and exposes full observability through the LGTM stack (Loki, Grafana, Tempo, Mimir).

**Threat feeds consumed:**
- **URLhaus** (Abuse.ch) — malicious URLs
- **ThreatFox** (Abuse.ch) — malicious hosts and IPs

**Core design goals:**
- Decoupled producer/consumer via NATS JetStream (no data loss on processor restart)
- Horizontally scalable consumers (HPA, 3–50 replicas)
- Automatic Redis secret rotation with zero pod restarts
- Security-hardened containers enforced at admission time via Kyverno
- Full observability: logs → Loki, metrics → Mimir, traces → Tempo

---

## 2. High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                        EXTERNAL INTERNET                            │
│         URLhaus (Abuse.ch)          ThreatFox (Abuse.ch)            │
└───────────────────────┬─────────────────────┬───────────────────────┘
                        │ HTTPS every 5 min   │
                        ▼                     ▼
┌──────────────────────────────────────────────────────┐
│                   intel-ingestion ns                 │
│                                                      │
│  ┌─────────────────┐       ┌──────────────────────┐  │
│  │  Intel Fetcher  │       │    Intel Worker      │  │
│  │  (Producer)     │       │  (Legacy direct path)│  │
│  │  fetcher.py     │       │    worker.py         │  │
│  │  port :8001     │       │    port :8000        │  │
│  └────────┬────────┘       └──────────┬───────────┘  │
│           │ NATS publish              │ Redis SETEX   │
│           │                           │               │
└───────────┼───────────────────────────┼───────────────┘
            ▼                           │
┌───────────────────────┐               │
│     nats-system ns    │               │
│                       │               │
│  ┌─────────────────┐  │               │
│  │  NATS JetStream │  │               │
│  │  StatefulSet    │  │               │
│  │  10Gi PVC       │  │               │
│  │  Stream:        │  │               │
│  │  THREAT_        │  │               │
│  │  INDICATORS     │  │               │
│  └────────┬────────┘  │               │
│           │           │               │
└───────────┼───────────┘               │
            │ NATS pull consumer        │
            ▼                           ▼
┌────────────────────────────────────────────────────┐
│                   intel-ingestion ns               │
│                                                    │
│  ┌──────────────────────────────────────────────┐  │
│  │     Intel Processor (Consumer) x3–50        │  │
│  │     processor.py  port :8002                │  │
│  │     HPA: CPU 70% / Mem 80%                  │  │
│  └──────────────────────┬───────────────────────┘  │
│                         │ Redis SETEX 24h TTL       │
│  ┌──────────────────────▼───────────────────────┐  │
│  │                    Redis                     │  │
│  │     threat:url:*  /  threat:host:*           │  │
│  └──────────────────────────────────────────────┘  │
│                                                    │
│  ┌──────────────────────────────────────────────┐  │
│  │  Key Rotator CronJob (every hour)            │  │
│  │  kubectl exec → redis-cli CONFIG SET        │  │
│  │  kubectl patch secret threat-feed-secrets   │  │
│  └──────────────────────────────────────────────┘  │
└────────────────────────────────────────────────────┘

┌────────────────────────────────────────────────────────────┐
│                      monitoring ns                         │
│  Promtail → Loki     Prometheus → Mimir     App → Tempo    │
│                    Grafana (NodePort :3000)                 │
└────────────────────────────────────────────────────────────┘
```

---

## 3. Namespace Layout

| Namespace | Contents |
|---|---|
| `intel-ingestion` | intel-fetcher, intel-processor, intel-worker, Redis, key-rotator CronJob, RBAC, Kyverno enforcement |
| `nats-system` | NATS StatefulSet, nats-stream-setup Job, headless + client Services |
| `monitoring` | Loki, Promtail DaemonSet, Tempo, Mimir, Prometheus, Grafana |

---

## 4. Data Flow — End to End

```
Step 1 — Fetch
  intel-fetcher polls URLhaus + ThreatFox via HTTPS every 5 minutes.
  Parses each feed into structured JSON indicator objects.

Step 2 — Publish
  intel-fetcher publishes each indicator to NATS JetStream.
  Subject pattern: threat.indicators.<source>.<type>
    e.g.  threat.indicators.urlhaus.malicious_url
          threat.indicators.threatfox.malicious_host
  Each message carries a Nats-Msg-Id header for deduplication (2-min window).
  JetStream persists the message to disk (10Gi PVC) — survives pod restarts.

Step 3 — Consume
  intel-processor (pull consumer, durable: processor-group) fetches messages
  in batches of 10 from the THREAT_INDICATORS stream.
  Multiple processor replicas compete for messages — each message is
  delivered to exactly one replica.

Step 4 — Process
  For each message the processor:
    • Parses JSON
    • Routes by indicator type to a Redis key:
        malicious_url  → threat:url:<url>
        malicious_host → threat:host:<domain>
        other          → threat:generic:<source>:<id>
    • Stores in Redis with 24-hour TTL (SETEX)
    • ACKs the message on success
    • NAKs the message on failure (JetStream will redeliver)
    • TERMs the message if JSON is malformed (no retry)

Step 5 — Observe
  All pods emit:
    • Structured JSON logs → stdout → Promtail → Loki
    • Prometheus metrics on /metrics → Prometheus → Mimir → Grafana
    • OpenTelemetry spans → OTLP gRPC → Tempo → Grafana

Step 6 — Rotate (async, every hour)
  CronJob updates Redis password live (redis-cli CONFIG SET).
  Patches Kubernetes Secret.
  Kubelet syncs volume-mounted secret to running processor pods (~60s).
  Processor detects change every 10 batches and reconnects to Redis.
```

---

## 5. Application Components

### 5.1 Intel Worker (Legacy)

**File:** `app/worker.py` | **Image:** `Dockerfile` | **Port:** `8000`

The original, single-process worker. Fetches the same URLhaus and ThreatFox feeds and writes directly to Redis — no NATS involvement. Retained alongside the new producer/consumer architecture for reference and comparison.

| Attribute | Value |
|---|---|
| Feed poll interval | 300 seconds (env: `FETCH_INTERVAL`) |
| URLhaus limit | 100 indicators per cycle |
| ThreatFox limit | 100 indicators per cycle |
| Redis key format | `indicator:<source>:<id>` |
| Redis TTL | 86400 seconds (24 hours) |
| Metrics port | `8000` |
| Tracing | OpenTelemetry → Tempo (spans on feed fetch + Redis write) |

**Prometheus metrics exposed:**
- `threat_indicators_processed_total` — counter, labels: `source`, `type`
- `external_api_errors_count` — counter, labels: `source`, `error_type`
- `threat_feed_last_success_timestamp` — gauge, labels: `source`

---

### 5.2 Intel Fetcher (Producer)

**File:** `app/fetcher.py` | **Image:** `Dockerfile.fetcher` | **Port:** `8001`

The NATS producer. Decoupled from storage — it only fetches feeds and publishes to JetStream. Designed to run as a single replica (idempotent, deduplication handled by JetStream).

| Attribute | Value |
|---|---|
| Feed poll interval | 300 seconds (env: `FETCH_INTERVAL`) |
| NATS URL | `nats://nats-client.nats-system:4222` (env: `NATS_URL`) |
| Publish subject | `threat.indicators.<source>.<type>` |
| Deduplication header | `Nats-Msg-Id: <source>-<id>` |
| NATS reconnect attempts | 60, retry interval 2s |
| Metrics port | `8001` |

**Feed parsing:**
- **URLhaus CSV** — parses comma-separated lines, extracts `id`, `url`, `threat`, `tags`
- **ThreatFox hostfile** — parses space-separated lines, extracts `ip`, `domain`

**Prometheus metrics exposed:**
- `threat_feeds_fetched_total` — counter, labels: `source`, `status`
- `threat_indicators_published_total` — counter, labels: `source`, `type`
- `nats_publish_errors_total` — counter, labels: `source`, `error_type`
- `threat_feed_last_fetch_timestamp` — gauge, labels: `source`

**Error handling:**
- NATS connect: 5 retries with 5s backoff
- Publish timeout: increments `nats_publish_errors_total{error_type="timeout"}`
- Feed HTTP error: increments `threat_feeds_fetched_total{status="failed"}`

---

### 5.3 Intel Processor (Consumer)

**File:** `app/processor.py` | **Image:** `Dockerfile.processor` | **Port:** `8002`

The NATS consumer. Reads from the `THREAT_INDICATORS` stream using a durable pull consumer, processes each indicator, and stores it in Redis. Designed to run as multiple replicas — JetStream distributes messages across all replicas automatically.

| Attribute | Value |
|---|---|
| NATS URL | `nats://nats-client.nats-system:4222` (env: `NATS_URL`) |
| Stream | `THREAT_INDICATORS` |
| Consumer | `processor-group` (durable, pull) |
| Batch size | 10 messages per fetch (env: `BATCH_SIZE`) |
| Fetch timeout | 5 seconds |
| Redis password file | `/etc/secrets/REDIS_PASSWORD` (env: `REDIS_PASSWORD_FILE`) |
| Key rotation check | Every 10 batches |
| Queue monitor interval | Every 30 seconds |
| Metrics port | `8002` |

**Message handling logic:**

```
for each message in batch:
    parse JSON
    ├─ success → process_indicator() → Redis SETEX → ACK
    ├─ Redis error → NAK (JetStream redelivers)
    ├─ processing error → NAK (JetStream redelivers)
    └─ JSON decode error → TERM (no retry, malformed)
```

**Prometheus metrics exposed:**
- `threat_indicators_consumed_total` — counter, labels: `source`, `type`
- `threat_indicators_processed_total` — counter, labels: `source`, `type`
- `threat_indicators_failed_total` — counter, labels: `source`, `error_type`
- `indicator_processing_duration_seconds` — histogram, labels: `source`, `type`
- `nats_message_errors_total` — counter, labels: `error_type`
- `redis_storage_operations_total` — counter, labels: `operation`, `status`
- `nats_queue_backlog` — gauge (messages pending in stream)

---

## 6. Messaging Layer — NATS JetStream

**File:** `k8s/nats-jetstream.yaml` | **Namespace:** `nats-system`

### Server

| Resource | Detail |
|---|---|
| Kind | StatefulSet |
| Image | `nats:2.10-alpine` |
| Replicas | 1 (single-node POC) |
| Storage | 10Gi PVC at `/data/jetstream` |
| Client port | `4222` |
| Monitor port | `8222` |
| Config | `POD_NAME` injected via downward API for `server_name` |

**JetStream config (in `nats.conf`):**
```
jetstream {
  store_dir: /data/jetstream
  max_memory_store: 1Gi
  max_file_store: 10Gi
}
```

### Services

| Service | Type | Purpose |
|---|---|---|
| `nats` | Headless | StatefulSet DNS (`nats-0.nats.nats-system`) |
| `nats-client` | ClusterIP | Application access point — used in NATS URLs |

### Prometheus Exporter Sidecar

`natsio/prometheus-nats-exporter:0.14.0` runs alongside the NATS container, scraping the monitoring HTTP endpoint and exposing metrics on port `7777`. Flags: `-connz -routez -subz -varz -jsz=all` (includes JetStream metrics).

### Stream Configuration

Created once by the `nats-stream-setup` Job using `nats-box`:

| Setting | Value |
|---|---|
| Stream name | `THREAT_INDICATORS` |
| Subjects | `threat.indicators.>` |
| Storage | File (persistent) |
| Retention | Limits |
| Max age | 24 hours |
| Max size | 10 GB |
| Max message size | 1 MB |
| Deduplication window | 2 minutes |
| Discard policy | Old |
| Replicas | 1 |

### Consumer Configuration

| Setting | Value |
|---|---|
| Consumer name | `processor-group` |
| Type | Pull (durable) |
| Deliver policy | All (from start of stream) |
| Ack policy | Explicit |
| Replay policy | Instant |

---

## 7. Storage Layer — Redis

**Namespace:** `intel-ingestion` | **Deployment:** `deploy/redis`

All threat indicators are stored in Redis with a 24-hour TTL. Redis is accessed exclusively by the processor (and legacy worker). Authentication is optional — password stored in `threat-feed-secrets` and auto-rotated hourly.

### Key Schema

| Indicator type | Key pattern | Value |
|---|---|---|
| `malicious_url` | `threat:url:<url>` | JSON: `{id, url, threat, tags, source, timestamp, type}` |
| `malicious_host` | `threat:host:<domain>` | JSON: `{ip, domain, source, timestamp, type}` |
| Generic | `threat:generic:<source>:<id>` | JSON: full indicator object |

**Legacy worker key pattern:** `indicator:<source>:<id>` (different prefix, same TTL)

---

## 8. Kubernetes Infrastructure

### 8.1 Deployments & StatefulSets

| Resource | Kind | Namespace | Replicas | Port |
|---|---|---|---|---|
| `intel-worker` | Deployment | `intel-ingestion` | 1 | 8000 |
| `intel-fetcher` | Deployment | `intel-ingestion` | 1 | 8001 |
| `intel-processor` | Deployment | `intel-ingestion` | 3–50 (HPA) | 8002 |
| `nats` | StatefulSet | `nats-system` | 1 | 4222, 8222 |
| `loki` | Deployment | `monitoring` | 1 | 3100 |
| `promtail` | DaemonSet | `monitoring` | 1/node | 9080 |
| `tempo` | Deployment | `monitoring` | 1 | 3200, 4317, 4318 |
| `mimir` | Deployment | `monitoring` | 1 | 9009 |
| `prometheus` | Deployment | `monitoring` | 1 | 9090 |
| `grafana` | Deployment | `monitoring` | 1 | 3000 |

### 8.2 Services & Networking

| Service | Namespace | Type | Port(s) |
|---|---|---|---|
| `intel-worker` | `intel-ingestion` | ClusterIP | 8000 |
| `intel-fetcher` | `intel-ingestion` | ClusterIP | 8001 |
| `intel-processor` | `intel-ingestion` | ClusterIP | 8002 |
| `nats` | `nats-system` | Headless | 4222, 8222, 7777 |
| `nats-client` | `nats-system` | ClusterIP | 4222 |
| `loki` | `monitoring` | ClusterIP | 3100 |
| `tempo` | `monitoring` | ClusterIP | 3200, 4317, 4318 |
| `mimir` | `monitoring` | ClusterIP | 9009, 9095 |
| `prometheus` | `monitoring` | ClusterIP | 9090 |
| `grafana` | `monitoring` | NodePort | 3000 |

**ServiceMonitor** (`k8s/servicemonitor.yaml`): Enables Prometheus Operator auto-discovery of `intel-worker` metrics at 30s intervals (label: `release: prometheus`).

### 8.3 Horizontal Pod Autoscaler

**Target:** `intel-processor` Deployment

| Setting | Value |
|---|---|
| Min replicas | 3 |
| Max replicas | 50 |
| CPU target | 70% utilization |
| Memory target | 80% utilization |
| Scale-up stabilization | 60 seconds |
| Scale-up max rate | 100% of current pods, or +10 pods, per 30s |
| Scale-down stabilization | 300 seconds (5 minutes) |
| Scale-down max rate | 50% of current pods, or -5 pods, per 60s |

Note: Queue-depth-based scaling (`nats_queue_backlog` custom metric) is defined in the manifest but commented out — it requires the Kubernetes custom metrics API to be set up.

### 8.4 Pod Security Hardening

All pods in `intel-ingestion` are configured with — and enforced at admission by Kyverno:

| Control | Setting |
|---|---|
| Run as non-root | `runAsNonRoot: true`, `runAsUser: 1000` |
| Filesystem group | `fsGroup: 1000` |
| Seccomp profile | `RuntimeDefault` |
| Privilege escalation | `allowPrivilegeEscalation: false` |
| Root filesystem | `readOnlyRootFilesystem: true` |
| Linux capabilities | `capabilities.drop: [ALL]` |
| Service account token | `automountServiceAccountToken: false` |
| Writable paths | `emptyDir` volumes mounted at `/tmp` (and `/app/.cache` for worker) |

---

## 9. Secret Management & Key Rotation

**File:** `k8s/key-rotation-automation.yaml`

### Secret Storage

The `threat-feed-secrets` Kubernetes Secret holds:
- `REDIS_PASSWORD` — Redis authentication password
- `THREAT_FEED_API_KEY` — API key for premium threat feeds (optional)

In the processor, the secret is mounted as a **volume** (not an env var):
```
/etc/secrets/REDIS_PASSWORD   ← file updated automatically by kubelet
```
This is the key design choice — env vars are fixed at container start; volume mounts update in-place when the secret changes.

### Rotation Sequence

```
T+0:00  CronJob runs (schedule: "0 * * * *")
         • Generates NEW_PASS (32-char alphanumeric, from /dev/urandom)
         • Reads OLD_PASS from threat-feed-secrets
         • kubectl exec deploy/redis -- redis-cli CONFIG SET requirepass $NEW_PASS
           → Redis password updated live, zero downtime

T+0:01  kubectl patch secret threat-feed-secrets
         → Kubernetes Secret updated with base64(NEW_PASS)

T+0:01  to T+1:01  Kubelet secret sync
         → Kubernetes propagates updated Secret to all volume-mounted
           pod filesystems (up to ~60 seconds, kubelet sync period)

T+1:01  (approx) Processor detects change
         • check_key_rotation() reads /etc/secrets/REDIS_PASSWORD
         • Compares with in-memory self.redis_password
         • On mismatch: reconnects Redis with new password
         → No pod restart required

~60s window: processor uses old password on a Redis that now requires the new one.
             Redis operations fail → messages NAK'd → JetStream redelivers.
             No data loss — messages are safely held in the stream.
```

### RBAC

`key-rotator-sa` ServiceAccount with a namespaced Role granting:
- `secrets`: `get`, `patch`, `update`, `create`, `list`
- `pods`, `pods/exec`: `get`, `list`
- `deployments`: `get`, `list`

Scoped to `intel-ingestion` namespace only.

---

## 10. Observability — LGTM Stack

**File:** `k8s/lgtm-stack.yaml` | **Namespace:** `monitoring`

### 10.1 Loki — Log Aggregation

Receives structured logs from Promtail. Stores logs indexed by labels (not full-text) for cost-efficient querying.

| Setting | Value |
|---|---|
| Image | `grafana/loki:2.9.0` |
| Port | `3100` |
| Storage | `emptyDir` (POC — data lost on restart) |
| Retention | 168 hours (`reject_old_samples_max_age`) |
| Schema | `v11`, `boltdb-shipper` |
| Ingestion rate limit | 10 MB/s burst, 20 MB/s burst |
| Auth | Disabled (`auth_enabled: false`) |

### 10.2 Promtail — Log Shipper

DaemonSet that runs on every node, scrapes all pod logs, parses JSON, and forwards to Loki.

**Log pipeline stages:**
1. `regex` — extracts `namespace` and `app` from the pod log path
2. `json` — extracts fields: `timestamp`, `level`, `message`, `source`, `count`, `duration_ms`
3. `labels` — promotes `level` and `source` to Loki stream labels
4. `timestamp` — parses RFC3339 timestamp from log field
5. `output` — sets the log line body to the `message` field

This means in Grafana/Loki you can filter by `{app="intel-processor", level="ERROR"}`.

### 10.3 Tempo — Distributed Tracing

Receives OpenTelemetry spans from all application pods.

| Setting | Value |
|---|---|
| Image | `grafana/tempo:latest` |
| Ports | `3200` (HTTP), `4317` (OTLP gRPC), `4318` (OTLP HTTP) |
| Storage | `emptyDir` at `/tmp/tempo` (POC) |
| Receivers | OTLP (gRPC + HTTP), Jaeger, Zipkin, OpenCensus |
| Max traces/user | 10,000 |

Application pods export to: `tempo.monitoring.svc.cluster.local:4317`

### 10.4 Mimir — Metrics Storage

Long-term, Prometheus-compatible metrics backend. Prometheus remote-writes all scraped metrics here.

| Setting | Value |
|---|---|
| Image | `grafana/mimir:latest` |
| Port | `9009` (HTTP), `9095` (gRPC) |
| Mode | Single-process (`target: all`) |
| Storage | `emptyDir` at `/data` (POC) |
| Ingestion rate | 10,000 samples/s, burst 20,000 |
| Alert rules | Loaded from `mimir-alerts` ConfigMap |

### 10.5 Prometheus — Metrics Scraping

Scrapes all annotated pods and services, then remote-writes to Mimir.

**Discovery annotations used on pods/services:**
```yaml
prometheus.io/scrape: "true"
prometheus.io/port: "8001"   # or 8002
prometheus.io/path: "/metrics"
```

**Remote write:** `http://mimir:9009/api/v1/push`

Scrape interval: `15s`

RBAC: `prometheus` ServiceAccount with ClusterRole to `list/watch` nodes, pods, services, endpoints.

### 10.6 Grafana — Unified Dashboards

Single pane of glass for logs (Loki), metrics (Mimir), and traces (Tempo).

| Setting | Value |
|---|---|
| Image | `grafana/grafana:latest` |
| Port | `3000` (NodePort — accessible from host) |
| Storage | `emptyDir` (dashboards lost on restart in POC) |
| Auth | Anonymous access enabled, role: Admin |
| Default datasource | Mimir (Prometheus-compatible) |

**Pre-configured datasources (via ConfigMap):**

| Datasource | Type | URL |
|---|---|---|
| Mimir | Prometheus | `http://mimir:9009/prometheus` |
| Loki | Loki | `http://loki:3100` |
| Tempo | Tempo | `http://tempo:3200` |

### 10.7 Alerting Rules

**Loki alert** (`loki-alerts` ConfigMap):

| Alert | Expression | Threshold | Severity |
|---|---|---|---|
| `HighErrorRate` | `sum(rate({app="intel-worker", level="ERROR"}[5m]))` | > 1/s for 1m | Warning |

**Mimir alerts** (`mimir-alerts` ConfigMap):

| Alert | Expression | Threshold | Severity |
|---|---|---|---|
| `ThreatFeedFailures` | `rate(external_api_errors_count_total[5m])` | > 0 for 1m | Critical |
| `HighErrorRatio` | errors / (processed + errors) | > 10% for 2m | Warning |

---

## 11. OpenTelemetry Tracing (In-App)

All three application components (`worker.py`, `fetcher.py`, `processor.py`) set up distributed tracing using the OpenTelemetry Python SDK.

**Setup (per app):**
```python
TracerProvider(
    resource=Resource.create({
        "service.name": "intel-processor",   # or intel-worker / intel-fetcher
        "service.version": "1.0.0",
        "environment": "poc"
    })
)
OTLPSpanExporter(endpoint="tempo.monitoring.svc.cluster.local:4317", insecure=True)
BatchSpanProcessor(exporter)
```

**Auto-instrumentation:**
- `RedisInstrumentor().instrument()` — creates spans for every Redis command
- `RequestsInstrumentor().instrument()` — creates spans for every outbound HTTP call (worker only)

**Manual spans in processor:**

| Span name | Description |
|---|---|
| `process_indicator` | Full indicator processing, includes source/type attributes |
| `redis_store` | Child span wrapping the Redis SETEX call |
| `fetch_batch` | NATS JetStream batch fetch, includes batch size attribute |
| `process_message` | Per-message span, includes subject and indicator attributes |

---

## 12. Security Policies — Kyverno

**File:** `k8s/kyverno-policies.yaml`

`ClusterPolicy: require-non-root-and-secure-context`
- **Scope:** All Pods in namespace `intel-ingestion`
- **Action:** `Enforce` — pods that violate any rule are **rejected at admission**
- **Background mode:** `true` — also audits existing resources

**Three rules enforced:**

| Rule | Check |
|---|---|
| `require-run-as-non-root` | `spec.securityContext.runAsNonRoot: true` AND container-level `runAsNonRoot: true` |
| `disallow-privilege-escalation` | Container `securityContext.allowPrivilegeEscalation: false` |
| `drop-all-capabilities` | Container `securityContext.capabilities.drop: ["ALL"]` |

Any deployment that does not set these fields will have its pods rejected by the Kubernetes API server before they are scheduled.

---

## 13. CI/CD Pipeline — GitHub Actions

**File:** `.github/workflows/security-pipeline.yaml`

Triggers: push to `main`/`develop`, pull requests to `main`, manual dispatch.

```
┌──────────┐    ┌──────────┐    ┌──────────────────┐
│ Job 1    │    │ Job 2    │    │ Job 3            │
│ SAST     ├───▶│ SCA      ├───▶│ Build & Scan     │
│ Scan     │    │ Dep Scan │    │ Container Image  │
└──────────┘    └──────────┘    └────────┬─────────┘
                                         │
                                         ▼
                                ┌──────────────────┐
                                │ Job 4            │
                                │ Sign Image       │
                                └────────┬─────────┘
                                         │ (main branch only)
                                         ▼
                                ┌──────────────────┐
                                │ Job 5            │
                                │ Deploy Staging   │
                                └──────────────────┘
                     ┌──────────────────────────────┐
                     │ Job 6: Security Summary       │
                     │ (runs always, after 1+2+3)    │
                     └──────────────────────────────┘
```

### 13.1 SAST Scan

**Tool:** Bandit + pip-audit

- **Bandit** (`bandit[toml]`): Static analysis of `app/` for security issues (SQL injection, hardcoded secrets, unsafe deserialization, etc.). Config from `pyproject.toml`.
- **Secret scan**: Grep for patterns like `password\s*=\s*"..."` in source code.
- **pip-audit**: Checks `app/requirements.txt` against the OSV vulnerability database.
- Results uploaded as artifact (`sast-results`).

### 13.2 SCA Dependency Scan

**Tool:** Trivy (filesystem mode)

- Scans `app/` directory for vulnerable packages.
- Output formats: SARIF (uploaded to GitHub Security tab) + table (visible in logs).
- Severity filter: `CRITICAL,HIGH,MEDIUM`.
- Ignores listed in `.trivyignore`.

### 13.3 Build & Container Scan

**Tool:** docker/build-push-action + Trivy (image mode)

Steps:
1. Build `intel-worker:<sha>` image with GHA layer cache (`type=gha`).
2. Trivy scans the built image for OS + application CVEs.
3. SARIF output uploaded to GitHub Security tab (only if file exists — guarded with `hashFiles()`).
4. Table scan with `exit-code: 1` — pipeline fails if CRITICAL or HIGH CVEs are found (excluding those in `.trivyignore`).
5. Image saved as `.tar` artifact for subsequent jobs.

### 13.4 Image Signing

**Tool:** Sigstore Cosign (conceptual in POC)

- Downloads the image `.tar` artifact.
- Documents the signing strategy (keyless OIDC signing via GitHub Actions OIDC token).
- Actual `cosign sign` command is shown but commented — requires a registry push first.

### 13.5 Deploy to Staging

- Runs only on `main` branch pushes.
- Documents the `kubectl set image` + `kubectl rollout status` deployment strategy.
- References minikube local deployment commands.

### 13.6 Trivy Ignore Policy

**File:** `.trivyignore`

Contains CVEs that are unfixable at the OS package level (Debian marks them `will_not_fix` or `affected`). The pipeline would otherwise fail on these since they are CRITICAL/HIGH severity.

| CVE | Package | Status | Reason |
|---|---|---|---|
| `CVE-2026-4046` | `glibc` | `fix_deferred` | iconv() DoS — deferred in Debian Bookworm |
| `CVE-2025-69720` | `ncurses` | `affected` | Buffer overflow — no interactive terminal in container |
| `CVE-2026-29111` | `systemd` / `libudev1` | `affected` | Transitive dep of curl — no systemd daemon in container |
| `CVE-2023-45853` | `zlib1g` | `will_not_fix` | Integer overflow in zip creation — not used by this app |

---

## 14. Container Images & Dockerfiles

### `Dockerfile` → `intel-worker:latest`

Multi-stage build for the legacy worker.

| Stage | Base | Actions |
|---|---|---|
| `builder` | `python:3.11-slim-bookworm` | Creates `/opt/venv`, installs all Python deps |
| `runtime` | `python:3.11-slim-bookworm` | `apt-get upgrade`, installs `curl`, copies venv, runs as UID 1000 |

- Health check: `GET http://localhost:8000/health`
- Entrypoint: `python worker.py`

### `Dockerfile.fetcher` → `intel-fetcher:latest`

Multi-stage build for the NATS producer.

| Stage | Base | Actions |
|---|---|---|
| `builder` | `python:3.11-slim-bookworm` | Creates `/opt/venv`, installs all Python deps |
| `runtime` | `python:3.11-slim-bookworm` | `apt-get upgrade`, copies venv, runs as UID 1000 |

- Health check: `GET http://localhost:8001/health`
- Entrypoint: `python fetcher.py`

### `Dockerfile.processor` → `intel-processor:latest`

Minimal single-stage build for the NATS consumer (used in POC).

| Step | Action |
|---|---|
| Base | `python:3.11-slim` |
| Copy | `app/requirements.txt` |
| Install | `pip install -r requirements.txt` |
| Copy | `app/processor.py` |
| User | `1000` |

- Entrypoint: `python processor.py`

---

## 15. Python Dependencies

**File:** `app/requirements.txt`

| Package | Version | Purpose |
|---|---|---|
| `redis` | `5.0.3` | Redis client for indicator storage |
| `requests` | `2.32.3` | HTTP client for feed fetching |
| `prometheus-client` | `0.20.0` | Expose Prometheus metrics |
| `flask` | `3.1.3` | HTTP server for `/metrics` and `/health` |
| `urllib3` | `>=2.0.0` | HTTP transport used by requests |
| `certifi` | `2024.8.30` | TLS certificate bundle |
| `nats-py` | `2.9.0` | NATS JetStream async client |
| `setuptools` | `>=80.1.0` | Build tooling (security patched) |
| `opentelemetry-api` | `1.28.2` | OTel API layer |
| `opentelemetry-sdk` | `1.28.2` | OTel SDK (TracerProvider, spans) |
| `opentelemetry-exporter-otlp-proto-grpc` | `1.28.2` | OTLP gRPC export to Tempo |
| `opentelemetry-instrumentation-requests` | `0.49b2` | Auto-instrument HTTP calls |
| `opentelemetry-instrumentation-redis` | `0.49b2` | Auto-instrument Redis commands |
| `opentelemetry-instrumentation-flask` | `0.49b2` | Auto-instrument Flask routes |
| `protobuf` | `>=5.29.6` | gRPC serialization (security patched) |
| `wheel` | `>=0.46.2` | Package build (security patched) |
| `jaraco.context` | `>=6.1.0` | Context utilities (security patched) |

---

## 16. Known Limitations (POC Scope)

| Area | Limitation | Production Fix |
|---|---|---|
| NATS auth | Server is unauthenticated — any pod in the cluster can publish | Enable NATS NKey or TLS client certs |
| NATS HA | Single replica StatefulSet | 3-node cluster with JetStream replication factor 3 |
| Grafana auth | Admin/admin, anonymous access enabled | OIDC/LDAP integration, disable anonymous |
| Grafana storage | `emptyDir` — dashboards lost on restart | PVC or Grafana dashboard provisioning via ConfigMap |
| Loki/Mimir/Tempo storage | `emptyDir` — all data lost on restart | Object storage (S3/GCS) for each component |
| Key rotation timing | ~60s window where processor uses stale Redis password | Use Kubernetes CSI secrets driver for instant sync |
| NATS queue-depth HPA | Commented out — requires custom metrics API | Deploy `kube-prometheus-stack` with custom metrics adapter |
| Intel Worker | Bypasses NATS entirely — direct Redis path | Remove or migrate fully to fetcher+processor pattern |
| CI image signing | Cosign signing is documented but not executed | Push to registry first, then sign with OIDC keyless flow |
| Single Dockerfile in CI | Pipeline only builds `intel-worker` image | Add separate jobs for `intel-fetcher` and `intel-processor` |
