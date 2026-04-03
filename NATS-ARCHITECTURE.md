# NATS-Based Queue Architecture

## Overview

This document describes the NATS JetStream-based queue system implementation for the Threat Intelligence Ingestion Platform. This architecture replaces the monolithic worker with a scalable producer-consumer pattern.

## Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────────┐
│                     Threat Intelligence Platform                     │
│                       (NATS-Based Architecture)                      │
└─────────────────────────────────────────────────────────────────────┘

┌──────────────┐         ┌──────────────────────────┐         ┌────────────────┐
│   External   │         │    NATS JetStream        │         │   Consumers    │
│ Threat Feeds │         │   (3-node cluster)       │         │  (Processors)  │
│              │         │                          │         │                │
│ - URLhaus    │         │  Stream:                 │         │  ┌──────────┐  │
│ - ThreatFox  │────────▶│  THREAT_INDICATORS       │────────▶│  │ Proc 1-N │  │
│ - Others     │         │                          │         │  └──────────┘  │
│              │         │  Subjects:               │         │                │
└──────────────┘         │  threat.indicators.>     │         │  HPA: 3-50     │
       │                 │                          │         │  replicas      │
       │                 │  Consumer Group:         │         │                │
       │                 │  processor-group         │         └────────────────┘
       │                 │                          │                │
       ▼                 │  Persistence: 10GB       │                ▼
┌──────────────┐         │  Retention: 24h          │         ┌────────────────┐
│   Producer   │         │  Replication: 3          │         │     Redis      │
│  (Fetcher)   │         │                          │         │                │
│              │         │  Deduplication: 2m       │         │  - Indicators  │
│  1 replica   │         └──────────────────────────┘         │  - TTL: 24h    │
│              │                                               │                │
└──────────────┘                                               └────────────────┘
       │
       │
       ▼
┌──────────────────────────────────────────────────────────────────┐
│                    LGTM Observability Stack                       │
│                                                                   │
│  ┌─────────┐  ┌─────────┐  ┌─────────┐  ┌─────────┐           │
│  │  Loki   │  │ Grafana │  │  Tempo  │  │  Mimir  │           │
│  │  Logs   │  │Dashboard│  │ Traces  │  │ Metrics │           │
│  └─────────┘  └─────────┘  └─────────┘  └─────────┘           │
└──────────────────────────────────────────────────────────────────┘
```

## Components

### 1. Producer (Fetcher)

**File**: `app/fetcher.py`

**Purpose**: Fetch threat intelligence feeds from external sources and publish to NATS JetStream

**Key Features**:
- Fetches from URLhaus and ThreatFox APIs
- Publishes to NATS subjects: `threat.indicators.<source>.<type>`
- Message deduplication using `Nats-Msg-Id` headers
- Configurable fetch interval (default: 5 minutes)
- Prometheus metrics for feed fetches and publishes
- Structured JSON logging for Loki
- OpenTelemetry tracing

**Deployment**:
- 1 replica (stateless, idempotent)
- Metrics port: 8001
- Resource requests: 100m CPU, 128Mi memory
- Resource limits: 500m CPU, 512Mi memory

**Metrics Exposed**:
- `threat_feeds_fetched_total{source, status}` - Feed fetch attempts
- `threat_indicators_published_total{source, type}` - Indicators published
- `nats_publish_errors_total{source, error_type}` - Publish failures
- `threat_feed_last_fetch_timestamp{source}` - Last successful fetch time

### 2. NATS JetStream

**File**: `k8s/nats-jetstream.yaml`

**Purpose**: Durable, persistent message queue with exactly-once delivery guarantees

**Configuration**:
- **Cluster**: 3-node StatefulSet for high availability
- **Storage**: File-based with 10GB max per replica
- **Retention**: 24 hours max age, size-based eviction
- **Replication**: 3 replicas per message
- **Deduplication**: 2-minute window using message IDs
- **Stream**: `THREAT_INDICATORS`
- **Subjects**: `threat.indicators.>` (wildcard)
- **Consumer**: `processor-group` (pull-based)

**Features**:
- Persistent storage (PVC: 10Gi per pod)
- Clustering for fault tolerance
- Message deduplication (prevents duplicate processing)
- Prometheus metrics exporter sidecar
- Health checks and graceful shutdown

**Ports**:
- 4222: Client connections
- 6222: Cluster communication
- 8222: HTTP monitoring
- 7777: Prometheus metrics

### 3. Consumer (Processor)

**File**: `app/processor.py`

**Purpose**: Pull messages from NATS, process threat indicators, store in Redis

**Key Features**:
- Pull-based consumer (batch size: 10 messages)
- Explicit acknowledgment (ack/nak/term)
- Processes indicators and stores in Redis with 24h TTL
- Auto-scaling via HPA (3-50 replicas)
- Error handling with retry (nak for transient errors)
- Processing duration histograms
- Queue backlog monitoring

**Deployment**:
- 3 replicas minimum (HPA scales 3-50)
- Metrics port: 8002
- Resource requests: 200m CPU, 256Mi memory
- Resource limits: 1000m CPU, 1Gi memory
- Anti-affinity for spreading across nodes

**Metrics Exposed**:
- `threat_indicators_consumed_total{source, type}` - Messages consumed
- `threat_indicators_processed_total{source, type}` - Successfully processed
- `threat_indicators_failed_total{source, error_type}` - Processing failures
- `indicator_processing_duration_seconds{source, type}` - Histogram
- `nats_message_errors_total{error_type}` - Message errors
- `redis_storage_operations_total{operation, status}` - Redis ops
- `nats_queue_backlog` - Pending messages in queue

### 4. Horizontal Pod Autoscaler (HPA)

**File**: `k8s/processor-deployment.yaml`

**Configuration**:
- Min replicas: 3
- Max replicas: 50
- Target CPU: 70%
- Target Memory: 80%

**Scaling Behavior**:
- **Scale Up**: Fast (100% or 10 pods per 30s)
- **Scale Down**: Conservative (50% or 5 pods per 60s, 5min stabilization)

**Custom Metrics** (optional):
- Can scale based on `nats_queue_backlog` metric
- Requires custom metrics API setup

## Data Flow

### 1. Ingestion Flow

```
External Feed → Fetcher → NATS JetStream → Processor → Redis
```

1. **Fetcher** polls external feeds every 5 minutes
2. Parses CSV/text data into structured JSON
3. Publishes each indicator to NATS with subject:
   - `threat.indicators.urlhaus.malicious_url`
   - `threat.indicators.threatfox.malicious_host`
4. NATS stores message persistently in stream
5. **Processor** pulls batch of 10 messages
6. Processes each indicator:
   - Validates and enriches data
   - Stores in Redis with key pattern: `threat:url:<url>` or `threat:host:<domain>`
   - Sets 24h TTL
7. Acknowledges (ACK) successful processing
8. Negative acknowledges (NAK) failures for retry

### 2. Message Format

**NATS Message**:
```json
{
  "id": "12345",
  "url": "http://malicious.example.com",
  "threat": "malware_download",
  "tags": "elf,mirai",
  "source": "urlhaus",
  "timestamp": "2026-04-03T10:30:00Z",
  "type": "malicious_url"
}
```

**NATS Headers**:
```
Nats-Msg-Id: urlhaus-12345
Source: urlhaus
Type: malicious_url
```

**Redis Storage**:
```
Key: threat:url:http://malicious.example.com
Value: <JSON indicator>
TTL: 86400 seconds (24h)
```

## Scalability and Performance

### Handling Spike Traffic

**Problem**: Sudden surge of 100,000 indicators in 1 minute

**Solution**:
1. **NATS Buffer**: Stream stores all messages persistently
2. **HPA Scaling**: Detects high CPU/memory usage
3. **Auto-scale**: Spins up processors (up to 50 replicas)
4. **Parallel Processing**: 50 processors × 10 msg/batch = 500 concurrent
5. **Backpressure**: Queue depth metric triggers scaling
6. **Graceful Degradation**: Messages wait in queue, no data loss

**Metrics During Spike**:
- `nats_queue_backlog` increases
- HPA scales up processors
- `threat_indicators_consumed_total` rate increases
- Queue drains within minutes

### Capacity Planning

**Current Configuration**:
- **Fetcher**: 1 replica handles ~1000 indicators/minute
- **Processor**: 3 replicas process ~300 indicators/minute
- **NATS**: 10GB storage ≈ 1M small messages
- **Redis**: Memory-based, scales with pod resources

**To Scale**:
- Increase HPA max replicas (50 → 100)
- Add more NATS nodes (3 → 5)
- Increase NATS storage (10GB → 50GB)
- Use Redis Cluster for horizontal scaling

## Deployment

### Quick Start

```bash
# Build all NATS services
make build-nats-minikube

# Deploy NATS cluster
make nats-deploy

# Deploy fetcher and processor
make nats-services-deploy

# Full deployment with LGTM stack
make full-deploy-nats
```

### Step-by-Step

1. **Start Minikube**:
   ```bash
   make minikube-start
   ```

2. **Build Docker Images**:
   ```bash
   make build-nats-minikube
   ```

3. **Deploy Infrastructure** (Terraform):
   ```bash
   make tf-apply
   ```

4. **Deploy NATS JetStream**:
   ```bash
   make nats-deploy
   ```

5. **Deploy Services**:
   ```bash
   make nats-services-deploy
   ```

6. **Deploy LGTM Stack**:
   ```bash
   make lgtm-deploy
   ```

7. **Verify Deployment**:
   ```bash
   make status
   make nats-status
   ```

## Monitoring

### Grafana Dashboard

Import `k8s/grafana-dashboard-nats.json` into Grafana for comprehensive monitoring:

**Panels**:
- NATS queue backlog (critical for scaling)
- Indicators published (fetcher throughput)
- Indicators consumed (processor throughput)
- Processing failures (error tracking)
- NATS publish errors
- Processing duration p95 (latency)
- Processor pod count (HPA status)
- Feed fetch success/failure
- Redis operations
- NATS server metrics
- Application logs (Loki)
- Distributed traces (Tempo)

### Access Grafana

```bash
make grafana
# Open http://localhost:3000
# Username: admin / Password: admin
```

### View Metrics Directly

```bash
# Fetcher metrics
make metrics-fetcher
curl http://localhost:8001/metrics

# Processor metrics
make metrics-processor
curl http://localhost:8002/metrics

# NATS metrics
make nats-metrics
curl http://localhost:7777/metrics
```

### View Logs

```bash
# Fetcher logs
make logs-fetcher

# Processor logs
make logs-processor

# All NATS services
make logs-all-nats
```

### NATS CLI

```bash
# Connect to NATS CLI
make nats-cli

# Inside nats-box:
nats -s nats://nats-client.nats-system:4222 stream info THREAT_INDICATORS
nats -s nats://nats-client.nats-system:4222 consumer info THREAT_INDICATORS processor-group
nats -s nats://nats-client.nats-system:4222 stream view THREAT_INDICATORS
```

## Advantages Over Monolithic Worker

### Previous Architecture (Monolithic)

```
External Feeds → Worker → Redis
```

**Limitations**:
- Single point of failure
- No buffering during spikes
- Vertical scaling only
- Fetch and process tightly coupled
- No replay capability

### NATS-Based Architecture

```
External Feeds → Fetcher → NATS → Processors → Redis
```

**Benefits**:

1. **Decoupling**: Fetcher and processor are independent
2. **Buffering**: NATS queues messages during spikes
3. **Horizontal Scaling**: HPA scales processors dynamically
4. **Fault Tolerance**: NATS 3-node cluster, message replication
5. **Exactly-Once**: Deduplication prevents duplicate processing
6. **Replay**: Can reprocess messages from stream
7. **Backpressure**: Queue depth visible, triggers scaling
8. **Observability**: Per-service metrics and traces
9. **Resource Efficiency**: Scale only processing layer
10. **Graceful Degradation**: Messages persist during downtime

## Security

### Network Policies

- Fetcher: Egress to external HTTPS (threat feeds) and NATS
- Processor: Egress to NATS and Redis only
- NATS: Ingress from fetcher/processor, egress for clustering

### Container Security

- Non-root user (UID 1000)
- Read-only root filesystem
- Dropped all capabilities
- No privilege escalation
- Kyverno admission control enforcement

### Secrets Management

- ConfigMaps for non-sensitive config
- Kubernetes Secrets for credentials (Redis, external APIs)
- Secret rotation via CronJob or External Secrets Operator

## Troubleshooting

### Issue: Queue Backlog Growing

**Symptoms**: `nats_queue_backlog` metric increasing

**Diagnosis**:
```bash
kubectl get hpa -n intel-ingestion
kubectl top pods -n intel-ingestion
```

**Solutions**:
- Increase HPA max replicas
- Check processor logs for errors
- Verify Redis is healthy

### Issue: Messages Not Being Consumed

**Symptoms**: Fetcher publishes but processors idle

**Diagnosis**:
```bash
make nats-cli
# Inside nats-box:
nats stream info THREAT_INDICATORS
nats consumer info THREAT_INDICATORS processor-group
```

**Solutions**:
- Verify consumer group exists
- Check processor pod logs
- Ensure NATS connectivity

### Issue: Duplicate Processing

**Symptoms**: Same indicator processed multiple times

**Diagnosis**:
- Check `Nats-Msg-Id` headers in fetcher
- Verify deduplication window (2m)

**Solutions**:
- Ensure unique message IDs
- Increase deduplication window if needed

## Cost Optimization

### Resource Tuning

1. **Fetcher**: Single replica sufficient for low-volume feeds
2. **Processor**: Start with 3 replicas, let HPA scale
3. **NATS**: 3 nodes minimum for HA, can reduce to 1 for dev

### Storage Optimization

- Reduce NATS retention from 24h to 6h if acceptable
- Reduce max storage from 10GB to 5GB
- Use node affinity to colocate NATS pods

### Dev/Test Environment

```bash
# Single-node NATS (no HA)
kubectl scale statefulset nats --replicas=1 -n nats-system

# Minimal processors
kubectl scale deployment intel-processor --replicas=1 -n intel-ingestion
```

## Future Enhancements

1. **Multi-Region**: NATS super-cluster across regions
2. **Rate Limiting**: Prevent overwhelming downstream systems
3. **Priority Queues**: High-priority threats processed first
4. **Dead Letter Queue**: Failed messages after N retries
5. **Custom Metrics HPA**: Scale based on queue depth
6. **NATS Leaf Nodes**: Edge deployments feeding central NATS
7. **Stream Partitioning**: Split by source or type for parallelism
8. **Geo-Replication**: Mirror streams across clusters

## References

- [NATS JetStream Documentation](https://docs.nats.io/nats-concepts/jetstream)
- [Kubernetes HPA](https://kubernetes.io/docs/tasks/run-application/horizontal-pod-autoscale/)
- [LGTM Stack](https://grafana.com/docs/)
- [Threat Feeds](https://abuse.ch/)
