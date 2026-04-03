# Study References — Threat Intelligence Ingestion Pipeline

This document lists official documentation, guides, and learning resources for every technology used in this project. Organized by layer.

---

## 1. NATS JetStream (Message Broker)

**What it is:** A cloud-native, high-performance messaging system. JetStream is NATS's persistence layer — it adds durable streams, consumers, and at-least-once delivery guarantees.

| Resource | URL | Focus |
|---|---|---|
| NATS Docs — JetStream Overview | https://docs.nats.io/nats-concepts/jetstream | Core concepts: streams, consumers, subjects |
| JetStream — Streams | https://docs.nats.io/nats-concepts/jetstream/streams | Retention, storage, limits, dedup |
| JetStream — Consumers | https://docs.nats.io/nats-concepts/jetstream/consumers | Pull vs push, ack, durable names |
| JetStream — Message Deduplication | https://docs.nats.io/nats-concepts/jetstream/deduplication | `Nats-Msg-Id` header usage |
| nats.py (Python client) | https://github.com/nats-io/nats.py | Python async client used in fetcher/processor |
| nats.py examples | https://nats-io.github.io/nats.py/ | `js.publish`, `pull_subscribe`, ack/nak/term |
| NATS CLI (`nats-box`) | https://docs.nats.io/using-nats/nats-tools/nats_cli | Commands used in stream setup Job |
| NATS Prometheus Exporter | https://github.com/nats-io/prometheus-nats-exporter | Sidecar used for metrics (`-jsz=all` flag) |

**Key concepts to understand:**
- Subject hierarchy and wildcards (`threat.indicators.>`)
- Durable consumers vs ephemeral consumers
- Explicit ack vs auto-ack
- Pull vs push delivery models
- Stream limits: `max-age`, `max-bytes`, `discard old`

---

## 2. Kubernetes (Orchestration)

**What it is:** Container orchestration platform. Manages deployments, scaling, networking, storage, and secrets across a cluster.

| Resource | URL | Focus |
|---|---|---|
| Kubernetes Docs (home) | https://kubernetes.io/docs/home/ | Full reference |
| StatefulSets | https://kubernetes.io/docs/concepts/workloads/controllers/statefulset/ | Used for NATS (stable identity + PVC) |
| Deployments | https://kubernetes.io/docs/concepts/workloads/controllers/deployment/ | Used for fetcher, processor, worker |
| HorizontalPodAutoscaler | https://kubernetes.io/docs/tasks/run-application/horizontal-pod-autoscale/ | Scales processor 3–50 replicas |
| ConfigMaps & Secrets | https://kubernetes.io/docs/concepts/configuration/ | `worker-config`, `threat-feed-secrets` |
| Secrets as Volumes | https://kubernetes.io/docs/concepts/configuration/secret/#using-secrets-as-files-from-a-pod | How secret rotation reaches running pods |
| Secret volume update timing | https://kubernetes.io/docs/concepts/configuration/secret/#mounted-secrets-are-updated-automatically | Why there's a ~60s sync delay |
| CronJobs | https://kubernetes.io/docs/concepts/workloads/controllers/cron-jobs/ | Used for hourly key rotation |
| Jobs | https://kubernetes.io/docs/concepts/workloads/controllers/job/ | Used for NATS stream setup |
| RBAC | https://kubernetes.io/docs/reference/access-authn-authz/rbac/ | `key-rotator-sa` Role and RoleBinding |
| Pod Security Context | https://kubernetes.io/docs/tasks/configure-pod-container/security-context/ | `runAsNonRoot`, `fsGroup`, `seccompProfile` |
| ServiceAccount token automounting | https://kubernetes.io/docs/tasks/configure-pod-container/configure-service-account/#opt-out-of-api-credential-automounting | `automountServiceAccountToken: false` |
| VolumeClaimTemplates | https://kubernetes.io/docs/concepts/workloads/controllers/statefulset/#volume-claim-templates | PVC per NATS pod |
| Pod Anti-Affinity | https://kubernetes.io/docs/concepts/scheduling-eviction/assign-pod-node/#affinity-and-anti-affinity | Spread pods across nodes |

---

## 3. Python Async (asyncio)

**What it is:** Python's built-in library for writing concurrent code using coroutines. Used by both fetcher and processor since the NATS Python client is async-only.

| Resource | URL | Focus |
|---|---|---|
| asyncio docs | https://docs.python.org/3/library/asyncio.html | Full reference |
| asyncio — coroutines and tasks | https://docs.python.org/3/library/asyncio-task.html | `asyncio.create_task`, `await`, `asyncio.run` |
| asyncio — mixing sync/async | https://docs.python.org/3/library/asyncio-eventloop.html | Threading + asyncio pattern (metrics server in thread) |
| Real Python — asyncio guide | https://realpython.com/async-io-python/ | Accessible end-to-end guide |

**Key pattern used:** `threading.Thread` runs Flask (sync) as a daemon thread while `asyncio.run()` drives the main async loop.

---

## 4. Redis

**What it is:** In-memory key-value store used as the final indicator storage with TTL-based expiry.

| Resource | URL | Focus |
|---|---|---|
| Redis Docs | https://redis.io/docs/ | Full reference |
| SETEX command | https://redis.io/commands/setex/ | Set key with TTL (used for all indicators) |
| CONFIG SET | https://redis.io/commands/config-set/ | Live password rotation without restart |
| redis-py (Python client) | https://redis-py.readthedocs.io/ | Client used in worker/processor |
| Redis AUTH | https://redis.io/docs/management/security/ | Password authentication |

---

## 5. OpenTelemetry & Distributed Tracing

**What it is:** Vendor-neutral observability framework for collecting traces, metrics, and logs. Used here to instrument Redis and HTTP calls, exporting spans to Tempo via OTLP.

| Resource | URL | Focus |
|---|---|---|
| OpenTelemetry Docs | https://opentelemetry.io/docs/ | Concepts and SDK reference |
| OpenTelemetry Python | https://opentelemetry-python.readthedocs.io/ | TracerProvider, Span, BatchSpanProcessor |
| OTLP Exporter (Python) | https://opentelemetry-python-contrib.readthedocs.io/en/latest/exporter/otlp/otlp.html | `OTLPSpanExporter` gRPC config |
| RedisInstrumentor | https://opentelemetry-python-contrib.readthedocs.io/en/latest/instrumentation/redis/redis.html | Auto-instrument redis-py |
| RequestsInstrumentor | https://opentelemetry-python-contrib.readthedocs.io/en/latest/instrumentation/requests/requests.html | Auto-instrument HTTP calls |
| Resource attributes | https://opentelemetry.io/docs/concepts/resources/ | `service.name`, `service.version` |
| W3C Trace Context | https://www.w3.org/TR/trace-context/ | Standard behind trace propagation |

---

## 6. Grafana Tempo (Distributed Tracing Backend)

**What it is:** Grafana's scalable tracing backend. Receives spans over OTLP and integrates with Grafana for trace visualization.

| Resource | URL | Focus |
|---|---|---|
| Tempo Docs | https://grafana.com/docs/tempo/latest/ | Configuration, ingestion, querying |
| Tempo config reference | https://grafana.com/docs/tempo/latest/configuration/ | The `tempo.yaml` structure |
| OTLP receiver config | https://grafana.com/docs/tempo/latest/configuration/receivers/ | `otlp.protocols.grpc` / `http` |
| Tempo + Grafana | https://grafana.com/docs/grafana/latest/datasources/tempo/ | Grafana datasource setup |

---

## 7. Prometheus (Metrics Collection)

**What it is:** Pull-based metrics system. Scrapes `/metrics` endpoints and evaluates alerting rules.

| Resource | URL | Focus |
|---|---|---|
| Prometheus Docs | https://prometheus.io/docs/introduction/overview/ | Overview and architecture |
| Kubernetes SD config | https://prometheus.io/docs/prometheus/latest/configuration/configuration/#kubernetes_sd_config | How Prometheus discovers pods/services |
| `remote_write` | https://prometheus.io/docs/prometheus/latest/configuration/configuration/#remote_write | Sending metrics to Mimir |
| prometheus-client (Python) | https://github.com/prometheus/client_python | Counter, Gauge, Histogram used in apps |
| Annotation-based scraping | https://prometheus.io/docs/prometheus/latest/configuration/configuration/#relabel_config | `prometheus.io/scrape` annotations |

---

## 8. Grafana Mimir (Long-term Metrics Storage)

**What it is:** Horizontally scalable, Prometheus-compatible metrics backend. Receives data via `remote_write` from Prometheus.

| Resource | URL | Focus |
|---|---|---|
| Mimir Docs | https://grafana.com/docs/mimir/latest/ | Overview and architecture |
| Mimir config reference | https://grafana.com/docs/mimir/latest/configure/configuration-parameters/ | The `mimir.yaml` structure |
| Mimir single-process mode | https://grafana.com/docs/mimir/latest/get-started/ | `target: all` used in this project |
| Alerting with Mimir | https://grafana.com/docs/mimir/latest/manage/mimir-runbooks/ | Ruler config for alert rules |

---

## 9. Grafana Loki (Log Aggregation)

**What it is:** Log aggregation system. Indexes labels (not full-text) making it cost-efficient. Works with Promtail for log shipping.

| Resource | URL | Focus |
|---|---|---|
| Loki Docs | https://grafana.com/docs/loki/latest/ | Overview and config |
| Loki config reference | https://grafana.com/docs/loki/latest/configure/ | The `loki.yaml` structure |
| LogQL | https://grafana.com/docs/loki/latest/query/ | Query language for Grafana dashboards and alerts |
| Loki alerting rules | https://grafana.com/docs/loki/latest/alert/ | The `HighErrorRate` rule format |

---

## 10. Promtail (Log Shipper)

**What it is:** Agent that runs as a DaemonSet, reads container logs, and ships them to Loki with labels.

| Resource | URL | Focus |
|---|---|---|
| Promtail Docs | https://grafana.com/docs/loki/latest/send-data/promtail/ | Configuration reference |
| Pipeline stages | https://grafana.com/docs/loki/latest/send-data/promtail/stages/ | `json`, `regex`, `labels`, `output` stages used in config |
| Kubernetes logs discovery | https://grafana.com/docs/loki/latest/send-data/promtail/configuration/#kubernetes_sd_configs | How Promtail discovers pods |

---

## 11. Grafana (Dashboards)

**What it is:** Unified visualization platform. Queries Loki, Mimir, and Tempo from a single UI.

| Resource | URL | Focus |
|---|---|---|
| Grafana Docs | https://grafana.com/docs/grafana/latest/ | Overview |
| Datasource provisioning | https://grafana.com/docs/grafana/latest/administration/provisioning/#datasources | The `datasources.yaml` ConfigMap format |
| Explore view | https://grafana.com/docs/grafana/latest/explore/ | Ad-hoc log/trace/metric querying |
| Grafana + Tempo trace linking | https://grafana.com/docs/grafana/latest/datasources/tempo/configure-tempo-data-source/ | Trace-to-log correlation |

---

## 12. Kyverno (Policy Engine)

**What it is:** Kubernetes-native policy engine that validates, mutates, and generates resources at admission time.

| Resource | URL | Focus |
|---|---|---|
| Kyverno Docs | https://kyverno.io/docs/ | Overview and installation |
| ClusterPolicy reference | https://kyverno.io/docs/kyverno-policies/ | Policy structure |
| Validate rules | https://kyverno.io/docs/writing-policies/validate/ | `pattern` matching used in this project |
| `validationFailureAction: Enforce` | https://kyverno.io/docs/writing-policies/validate/#validation-failure-action | Reject non-compliant pods |
| Pod security policies with Kyverno | https://kyverno.io/policies/pod-security/ | Pre-built policies similar to what's implemented |

---

## 13. Container Security (General)

| Resource | URL | Focus |
|---|---|---|
| Seccomp profiles in K8s | https://kubernetes.io/docs/tutorials/security/seccomp/ | `RuntimeDefault` seccomp |
| Linux capabilities | https://man7.org/linux/man-pages/man7/capabilities.7.html | Why `drop: [ALL]` matters |
| Read-only root filesystem | https://kubernetes.io/docs/concepts/security/pod-security-standards/ | Container hardening baseline |
| OWASP Container Security | https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html | Security checklist |

---

## 14. Threat Intelligence Feeds (Data Sources)

| Resource | URL | Focus |
|---|---|---|
| URLhaus (Abuse.ch) | https://urlhaus.abuse.ch/ | Malicious URL feed used by fetcher |
| URLhaus CSV feed docs | https://urlhaus.abuse.ch/api/ | Feed format documentation |
| ThreatFox (Abuse.ch) | https://threatfox.abuse.ch/ | Malicious host/IP feed |
| ThreatFox hostfile docs | https://threatfox.abuse.ch/api/ | Hostfile format documentation |
| MISP (context) | https://www.misp-project.org/ | Common IOC standard (for future reference) |
| STIX/TAXII (context) | https://oasis-open.github.io/cti-documentation/ | Industry standard threat intel format |

---

## 15. Suggested Learning Path

If you are new to this stack, work through the topics in this order:

1. **Kubernetes basics** — Pods, Deployments, Services, ConfigMaps, Secrets
2. **Python asyncio** — coroutines, tasks, event loop
3. **Redis** — data types, TTL, AUTH
4. **NATS JetStream** — streams, pull consumers, ack semantics
5. **Prometheus + metrics** — Counter, Gauge, Histogram; scraping
6. **OpenTelemetry** — spans, traces, OTLP export
7. **Loki + Promtail** — log labels, LogQL queries
8. **Grafana** — datasources, Explore, dashboards
9. **Kyverno** — ClusterPolicy, validate rules
10. **Kubernetes RBAC + Secrets** — Roles, bindings, volume-mounted secrets, rotation
