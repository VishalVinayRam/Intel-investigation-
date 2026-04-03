# Threat Intelligence Ingestion Pipeline — Implementation Overview

## 1. System Summary

This is a Kubernetes-native, cloud-ready threat intelligence ingestion pipeline. It continuously fetches indicators of compromise (IOCs) from public threat feeds, queues them through NATS JetStream, processes and stores them in Redis, and exposes full observability via the LGTM stack (Loki + Grafana + Tempo + Mimir).

---

## 2. Components Implemented

### 2.1 Application Layer

| Component | File | Role |
|---|---|---|
| Intel Worker | `app/worker.py` | Legacy direct-to-Redis worker (v1, pre-NATS) |
| Intel Fetcher | `app/fetcher.py` | Producer — fetches feeds, publishes to NATS JetStream |
| Intel Processor | `app/processor.py` | Consumer — reads from NATS JetStream, stores to Redis |

#### Intel Fetcher (`fetcher.py`)
- Connects to NATS JetStream at `nats://nats-client.nats-system:4222`
- Polls two public threat feeds every 5 minutes (`FETCH_INTERVAL=300`):
  - **URLhaus** (Abuse.ch): Malicious URLs in CSV format
  - **ThreatFox** (Abuse.ch): Malicious hosts/IPs in hostfile format
- Parses each feed into structured indicator objects (`malicious_url`, `malicious_host`)
- Publishes each indicator to JetStream on subject `threat.indicators.<source>.<type>`
- Uses `Nats-Msg-Id` header per message for JetStream deduplication (2-minute window)
- Exposes Prometheus metrics on port `8001` and `/health` endpoint
- Retry logic: 5 attempts with 5s backoff for NATS connection

#### Intel Processor (`processor.py`)
- Connects to NATS JetStream using a **pull consumer** (`processor-group`, durable)
- Fetches messages in configurable batches (`BATCH_SIZE=10`)
- For each message:
  - Parses JSON indicator
  - Routes by type: `malicious_url` → `threat:url:<url>`, `malicious_host` → `threat:host:<domain>`, generic → `threat:generic:<source>:<id>`
  - Stores in Redis with 24-hour TTL (`setex`)
  - **ACK** on success, **NAK** (retry) on failure, **TERM** on malformed JSON
- Runs a background queue monitor every 30 seconds (updates `nats_queue_backlog` gauge)
- Checks for Redis password rotation every 10 batches (`check_key_rotation`)
- Exposes Prometheus metrics on port `8002` and `/health` endpoint
- Structured JSON logging for Loki ingestion

#### Intel Worker (`worker.py`)
- Older direct-to-Redis path (no NATS), retained for reference
- Fetches same URLhaus and ThreatFox feeds
- Stores directly to Redis with a `indicator:<source>:<id>` key pattern
- Used by the `intel-worker` Deployment (port `8000`)

---

### 2.2 Messaging Layer — NATS JetStream

**File:** `k8s/nats-jetstream.yaml`

| Resource | Detail |
|---|---|
| StatefulSet `nats` | Single-node NATS 2.10, JetStream enabled, `nats-system` namespace |
| Persistent Volume | 10Gi PVC for JetStream file storage (`/data/jetstream`) |
| Prometheus Exporter sidecar | `natsio/prometheus-nats-exporter:0.14.0` on port `7777` |
| Headless Service `nats` | For StatefulSet DNS |
| ClusterIP Service `nats-client` | Application access point at port `4222` |
| Setup Job `nats-stream-setup` | One-time Job using `nats-box` to create stream and consumer |

**Stream configuration (`THREAT_INDICATORS`):**
- Subjects: `threat.indicators.>` (wildcard, catches all sources/types)
- Storage: File-based (persistent)
- Retention: Limits-based, max age 24h, max size 10GB
- Deduplication window: 2 minutes
- Discard policy: Old (drop old on overflow)
- Replicas: 1 (POC single-node)

**Consumer configuration (`processor-group`):**
- Pull-based (processor fetches, not push)
- Delivery: All (from beginning of stream)
- Ack: Explicit (processor must ack/nak each message)
- Replay: Instant

---

### 2.3 Storage Layer — Redis

- Deployed as `deploy/redis` in `intel-ingestion` namespace
- Accessed by processor via `REDIS_HOST` / `REDIS_PORT` from ConfigMap `worker-config`
- Password-protected (optional); password stored in Secret `threat-feed-secrets`
- All indicators stored with 24-hour TTL

**Key patterns:**
```
threat:url:<url>           → malicious URL indicators
threat:host:<domain>       → malicious host/IP indicators
threat:generic:<src>:<id>  → all other types
```

---

### 2.4 Kubernetes Deployments

**File:** `k8s/fetcher-deployment.yaml`
- `intel-fetcher` Deployment, 1 replica (stateless, idempotent)
- Namespace: `intel-ingestion`
- Security: non-root (UID 1000), read-only root filesystem, all capabilities dropped, no privilege escalation
- SeccompProfile: RuntimeDefault
- ServiceAccount: `intel-worker-sa` (no automount token)
- Volumes: `tmp` emptyDir only

**File:** `k8s/processor-deployment.yaml`
- `intel-processor` Deployment, starts at 3 replicas
- All the same security hardening as fetcher
- Additional volume: `secrets` — mounts `threat-feed-secrets` at `/etc/secrets` (read-only, mode 0444)
- `REDIS_PASSWORD_FILE=/etc/secrets/REDIS_PASSWORD` env var set explicitly
- HPA: scales 3–50 replicas based on CPU (70%) and memory (80%)
  - Scale-up: fast (100% in 30s, max +10 pods per 30s)
  - Scale-down: conservative (max 50% in 60s, 5-minute stabilization window)
- Anti-affinity: spread processors across nodes

**File:** `k8s/deployment.yaml`
- `intel-worker` Deployment (legacy path), 1 replica
- `intel-worker-sa` ServiceAccount defined here

---

### 2.5 Automatic Secret Retrieval & Key Rotation

**File:** `k8s/key-rotation-automation.yaml`

The full rotation cycle works as follows:

**Step 1 — CronJob generates new password (every hour):**
```
schedule: "0 * * * *"
```
- Generates a 32-char alphanumeric password from `/dev/urandom`
- Reads current password from `threat-feed-secrets` secret
- Calls `redis-cli CONFIG SET requirepass <new>` via `kubectl exec` — **live update, no Redis restart**
- On success: patches `threat-feed-secrets` with base64-encoded new password

**Step 2 — Kubernetes propagates the secret to running pods:**
- The secret is mounted as a volume (not an env var), so Kubernetes will sync the updated value to the running pod's filesystem within ~60 seconds (kubelet sync cycle)

**Step 3 — Processor detects the rotation:**
- `check_key_rotation()` is called every 10 message batches
- Reads `/etc/secrets/REDIS_PASSWORD` and compares with the in-memory password
- On mismatch: reconnects to Redis with the new password (no pod restart needed)

**RBAC for rotation (`key-rotator-sa`):**
- `secrets`: get, patch, update, create, list
- `pods`, `pods/exec`: get, list
- `deployments`: get, list
- Scoped to `intel-ingestion` namespace only

---

### 2.6 Observability — LGTM Stack

**File:** `k8s/lgtm-stack.yaml`

| Component | Role | Port |
|---|---|---|
| **Loki** | Log aggregation (receives from Promtail) | 3100 |
| **Promtail** | DaemonSet log shipper — scrapes pod logs from `/var/log/pods` | 9080 |
| **Tempo** | Distributed tracing backend (OTLP gRPC + HTTP) | 3200 / 4317 / 4318 |
| **Mimir** | Long-term metrics storage (Prometheus-compatible) | 9009 |
| **Prometheus** | Scrapes pod/service metrics, remote-writes to Mimir | 9090 |
| **Grafana** | Unified dashboard, pre-configured datasources (Loki, Tempo, Mimir) | 3000 (NodePort) |

**Log pipeline:** Pod stdout → Promtail DaemonSet → Loki
- Promtail parses JSON log lines and extracts `level` and `source` as labels

**Metrics pipeline:** Pod `/metrics` endpoint → Prometheus scrape → remote_write → Mimir → Grafana

**Tracing pipeline:** App (OpenTelemetry SDK) → OTLP gRPC → Tempo → Grafana

**Alerting:**
- Loki alert (`loki-alerts` ConfigMap): `HighErrorRate` — fires if ERROR logs > 1/sec over 5 minutes
- Mimir alerts (`mimir-alerts` ConfigMap):
  - `ThreatFeedFailures` — any external API errors (critical)
  - `HighErrorRatio` — >10% of fetches failing (warning)

---

### 2.7 OpenTelemetry Tracing (in-app)

Both `worker.py` and `processor.py` set up `TracerProvider` with:
- `OTLPSpanExporter` pointing to `tempo.monitoring.svc.cluster.local:4317`
- `BatchSpanProcessor` for efficient export
- Service name: `intel-worker` / `intel-processor`
- Redis instrumentation via `RedisInstrumentor`
- HTTP instrumentation via `RequestsInstrumentor` (worker only)

Spans created:
- `process_indicator` — full indicator processing span
- `redis_store` — child span for Redis write
- `fetch_batch` — NATS fetch span
- `process_message` — per-message span

---

### 2.8 Security Policies — Kyverno

**File:** `k8s/kyverno-policies.yaml`

`ClusterPolicy: require-non-root-and-secure-context` enforces on all Pods in `intel-ingestion`:
- `runAsNonRoot: true` at pod and container level
- `allowPrivilegeEscalation: false`
- `capabilities.drop: [ALL]`

Validation failure action: `Enforce` (pod rejected at admission if non-compliant).

---

## 3. End-to-End Data Flow

```
External Internet
  │
  │  HTTPS (every 5 min)
  ▼
┌─────────────────────┐
│   Intel Fetcher     │  (1 replica)
│   fetcher.py        │
│   port :8001        │
└────────┬────────────┘
         │ NATS JetStream publish
         │ subject: threat.indicators.<source>.<type>
         │ with Nats-Msg-Id dedup header
         ▼
┌─────────────────────┐
│   NATS JetStream    │  StatefulSet, 10Gi PVC
│   Stream:           │  max age: 24h
│   THREAT_INDICATORS │  dedup window: 2min
└────────┬────────────┘
         │ Pull consumer (processor-group)
         │ batch size: 10 messages
         ▼
┌─────────────────────┐
│  Intel Processor    │  (3–50 replicas via HPA)
│  processor.py       │
│  port :8002         │
└────────┬────────────┘
         │ Redis SETEX (24h TTL)
         ▼
┌─────────────────────┐
│      Redis          │
│  threat:url:*       │
│  threat:host:*      │
└─────────────────────┘

Observability plane (parallel to all above):
  All pods → Promtail DaemonSet → Loki
  All pods :metrics → Prometheus → Mimir
  All pods (OTLP) → Tempo
  Grafana queries Loki + Mimir + Tempo
```

---

## 4. Namespace Layout

| Namespace | Contents |
|---|---|
| `intel-ingestion` | fetcher, processor, worker, redis, key-rotator CronJob, RBAC |
| `nats-system` | NATS StatefulSet, stream setup Job, services |
| `monitoring` | Loki, Promtail, Tempo, Mimir, Prometheus, Grafana |

---

## 5. Known Limitations (POC Scope)

| Area | Limitation |
|---|---|
| NATS auth | No authentication configured (open server) |
| NATS replicas | Single node — no HA |
| Grafana auth | Anonymous access enabled, admin/admin credentials |
| Grafana storage | emptyDir — dashboards lost on pod restart |
| Loki/Mimir/Tempo storage | emptyDir — data lost on pod restart |
| Key rotation window | ~60s gap between Redis password change and pod file update where Redis ops will fail (messages are NAK'd and retried, no data loss) |
| NATS stream HPA | Queue-depth-based HPA scaling is commented out (requires custom metrics API) |
| Worker v1 | `worker.py` bypasses NATS entirely — direct Redis path, left for reference |
