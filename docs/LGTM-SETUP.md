# LGTM Stack Setup Guide

Complete observability with **Loki + Grafana + Tempo + Mimir** for the Threat Intelligence Platform.

## Overview

The LGTM stack provides:

- **Loki** - Log aggregation and querying
- **Grafana** - Unified visualization dashboard
- **Tempo** - Distributed tracing
- **Mimir** - Long-term metrics storage (Prometheus-compatible)
- **Prometheus** - Metrics scraping and forwarding to Mimir
- **Promtail** - Log collection and forwarding to Loki

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         Grafana (Port 3000)                      │
│                    Unified Observability Dashboard               │
└───────────┬─────────────┬─────────────┬─────────────────────────┘
            │             │             │
   ┌────────▼────┐  ┌────▼─────┐  ┌───▼──────┐
   │    Loki     │  │  Tempo   │  │  Mimir   │
   │   (Logs)    │  │ (Traces) │  │(Metrics) │
   │  Port 3100  │  │Port 4317 │  │Port 9009 │
   └────────▲────┘  └────▲─────┘  └───▲──────┘
            │             │            │
   ┌────────┴────┐  ┌────┴─────┐  ┌──┴────────┐
   │  Promtail   │  │  Worker  │  │Prometheus │
   │ (DaemonSet) │  │  (OTLP)  │  │ (Scraper) │
   └─────────────┘  └──────────┘  └───────────┘
```

## Quick Deployment

### Step 1: Deploy LGTM Stack

```bash
# Deploy the full LGTM stack
minikube kubectl -- apply -f k8s/lgtm-stack.yaml

# Wait for all components to be ready
minikube kubectl -- wait --for=condition=ready pod -l app=grafana -n monitoring --timeout=300s
minikube kubectl -- wait --for=condition=ready pod -l app=loki -n monitoring --timeout=300s
minikube kubectl -- wait --for=condition=ready pod -l app=tempo -n monitoring --timeout=300s
minikube kubectl -- wait --for=condition=ready pod -l app=mimir -n monitoring --timeout=300s
```

### Step 2: Rebuild Worker with LGTM Support

```bash
# Build new image with OpenTelemetry libraries
docker build -t intel-worker:latest .

# Load into minikube
minikube image load intel-worker:latest

# Update ConfigMap with Tempo endpoint (already in terraform)
cd terraform
terraform apply -auto-approve
cd ..

# Restart worker deployment to pick up new image and config
minikube kubectl -- rollout restart deployment/intel-worker -n intel-ingestion
```

### Step 3: Access Grafana Dashboard

```bash
# Port-forward to Grafana
minikube kubectl -- port-forward -n monitoring svc/grafana 3000:3000

# Open in browser: http://localhost:3000
# Username: admin
# Password: admin
```

## Verification

### Check All Components

```bash
# View all monitoring components
minikube kubectl -- get all -n monitoring

# Expected output:
# - grafana (1/1 Running)
# - loki (1/1 Running)
# - tempo (1/1 Running)
# - mimir (1/1 Running)
# - prometheus (1/1 Running)
# - promtail (DaemonSet - should match number of nodes)
```

### Test Each Component

#### 1. Loki (Logs)

```bash
# Port-forward to Loki
minikube kubectl -- port-forward -n monitoring svc/loki 3100:3100 &

# Query logs via LogQL
curl -G -s "http://localhost:3100/loki/api/v1/query" \
  --data-urlencode 'query={namespace="intel-ingestion"}' | jq

# Example query for errors only
curl -G -s "http://localhost:3100/loki/api/v1/query" \
  --data-urlencode 'query={namespace="intel-ingestion", level="ERROR"}' | jq
```

#### 2. Tempo (Traces)

```bash
# Port-forward to Tempo
minikube kubectl -- port-forward -n monitoring svc/tempo 3200:3200 &

# Search for traces
curl -s "http://localhost:3200/api/search?tags=service.name=intel-worker" | jq

# View trace details
# Get trace ID from search, then:
curl -s "http://localhost:3200/api/traces/<trace-id>" | jq
```

#### 3. Mimir (Metrics)

```bash
# Port-forward to Mimir
minikube kubectl -- port-forward -n monitoring svc/mimir 9009:9009 &

# Query metrics via PromQL
curl -s "http://localhost:9009/prometheus/api/v1/query?query=threat_indicators_processed_total" | jq

# Query feed freshness
curl -s "http://localhost:9009/prometheus/api/v1/query?query=threat_feed_last_success_timestamp" | jq
```

#### 4. Prometheus (Scraper)

```bash
# Port-forward to Prometheus
minikube kubectl -- port-forward -n monitoring svc/prometheus 9090:9090 &

# Open Prometheus UI: http://localhost:9090
# Check targets: http://localhost:9090/targets
```

## Grafana Configuration

### Pre-configured Datasources

The deployment automatically configures:

1. **Loki** (http://loki:3100)
   - Type: Loki
   - For log queries

2. **Tempo** (http://tempo:3200)
   - Type: Tempo
   - For distributed tracing

3. **Mimir** (http://mimir:9009/prometheus)
   - Type: Prometheus
   - Default datasource
   - For metrics queries

### Import Threat Intelligence Dashboard

```bash
# Option 1: Via Grafana UI
# 1. Open Grafana (http://localhost:3000)
# 2. Go to Dashboards → Import
# 3. Upload k8s/grafana-dashboard.json

# Option 2: Via ConfigMap (automated)
minikube kubectl -- create configmap grafana-dashboards \
  --from-file=k8s/grafana-dashboard.json \
  -n monitoring

# Add dashboard provisioning to Grafana deployment
# (See full automation in k8s/lgtm-stack.yaml)
```

### Dashboard Features

The Threat Intelligence dashboard includes:

1. **Real-time Metrics**
   - Total indicators processed (rate)
   - Indicators by source and type
   - API error rates
   - Feed freshness

2. **Logs Panel**
   - Structured JSON logs from worker
   - Filter by log level
   - Search by source or error type
   - Top error messages

3. **Tracing Panel**
   - Feed fetch duration
   - Request spans
   - Error traces
   - Service dependencies

4. **Alerts**
   - Feed down detection
   - High error rate warnings
   - Stale data alerts

## Example Queries

### LogQL (Loki)

```logql
# All logs from intel-worker
{namespace="intel-ingestion", app="intel-worker"}

# Only ERROR logs
{namespace="intel-ingestion", level="ERROR"}

# Logs with specific source
{namespace="intel-ingestion"} | json | source="urlhaus"

# Count errors in last hour
count_over_time({namespace="intel-ingestion", level="ERROR"}[1h])

# Logs with duration > 1000ms
{namespace="intel-ingestion"} | json | duration_ms > 1000
```

### PromQL (Mimir/Prometheus)

```promql
# Indicators processed per second
rate(threat_indicators_processed_total[5m])

# Total indicators by source
sum by (source) (threat_indicators_processed_total)

# Error rate percentage
sum(rate(external_api_errors_count_total[5m])) /
  (sum(rate(threat_indicators_processed_total[5m])) +
   sum(rate(external_api_errors_count_total[5m])))

# Feed staleness (seconds since last success)
time() - threat_feed_last_success_timestamp

# Alert on stale feed (> 10 minutes)
(time() - threat_feed_last_success_timestamp) > 600
```

### TraceQL (Tempo)

```traceql
# All traces from intel-worker
{service.name="intel-worker"}

# Traces with errors
{service.name="intel-worker" && status=error}

# Slow feed fetches (> 2 seconds)
{service.name="intel-worker" && duration > 2s}

# Traces for specific operation
{service.name="intel-worker" && name="fetch_urlhaus_feed"}
```

## Structured Logging

The worker now outputs JSON logs for Loki:

```json
{
  "timestamp": "2024-01-15T10:30:45.123456",
  "level": "INFO",
  "logger": "__main__",
  "message": "Feed fetch successful",
  "module": "worker",
  "function": "fetch_urlhaus_feed",
  "line": 216,
  "source": "urlhaus",
  "count": 100,
  "duration_ms": 1234.56
}
```

### Log Levels

- **DEBUG**: Verbose information (skipped lines, debug traces)
- **INFO**: Normal operations (feed fetches, processing)
- **WARNING**: Recoverable errors (retry attempts)
- **ERROR**: Failures (API errors, connection issues)

## Distributed Tracing

### Trace Attributes

Each trace includes:

- `service.name`: "intel-worker"
- `service.version`: "1.0.0"
- `deployment.environment`: "poc"
- `feed.source`: "urlhaus" | "threatfox"
- `feed.indicators_count`: number of indicators
- `feed.duration_ms`: fetch duration

### Viewing Traces in Grafana

1. Open Grafana → Explore
2. Select "Tempo" datasource
3. Query: `{service.name="intel-worker"}`
4. View trace waterfall
5. Click spans to see details
6. Correlate with logs (trace ID in logs)

## Performance Tuning

### Resource Limits

Current limits (adjust as needed):

```yaml
Component     CPU Request  CPU Limit  Memory Request  Memory Limit
-----------   -----------  ---------  --------------  ------------
Loki          100m         500m       128Mi           512Mi
Tempo         100m         500m       128Mi           512Mi
Mimir         100m         1000m      256Mi           1Gi
Prometheus    100m         500m       256Mi           1Gi
Grafana       100m         500m       128Mi           512Mi
Promtail      50m          200m       64Mi            256Mi
```

### Storage Configuration

For POC, using `emptyDir` (ephemeral). For production:

```yaml
# Use PersistentVolumeClaims
volumes:
- name: storage
  persistentVolumeClaim:
    claimName: loki-pvc
```

### Retention Policies

**Loki:**
- Default: 168h (7 days)
- Configure in `loki.yaml`: `limits_config.reject_old_samples_max_age`

**Tempo:**
- Default: 24h
- Configure in `tempo.yaml`: `compactor.compaction.block_retention`

**Mimir:**
- Configurable via compactor settings
- Blocks stored in `/data/blocks`

## Alerting Integration

### Prometheus Alert Rules

Add to `prometheus.yml`:

```yaml
rule_files:
- /etc/prometheus/alerts.yml

alerting:
  alertmanagers:
  - static_configs:
    - targets: ['alertmanager:9093']
```

### Example Alert Rules

```yaml
groups:
- name: threat_intel_alerts
  rules:
  - alert: FeedDown
    expr: rate(external_api_errors_count_total[5m]) > 0.1
    for: 5m
    labels:
      severity: critical
    annotations:
      summary: "Threat feed {{ $labels.source }} is down"

  - alert: StaleFeed
    expr: (time() - threat_feed_last_success_timestamp) > 900
    for: 5m
    labels:
      severity: warning
    annotations:
      summary: "Feed {{ $labels.source }} is stale"
```

## Troubleshooting

### Loki Not Receiving Logs

```bash
# Check Promtail is running
minikube kubectl -- get pods -n monitoring -l app=promtail

# Check Promtail logs
minikube kubectl -- logs -n monitoring -l app=promtail --tail=50

# Verify Loki connectivity
minikube kubectl -- exec -n monitoring -it deploy/promtail -- \
  curl -s http://loki:3100/ready

# Check log format (should be JSON)
minikube kubectl -- logs -n intel-ingestion -l app=intel-worker --tail=1
```

### Tempo Not Receiving Traces

```bash
# Check worker logs for OpenTelemetry initialization
minikube kubectl -- logs -n intel-ingestion -l app=intel-worker | grep -i "telemetry\|tempo"

# Verify Tempo OTLP endpoint is accessible
minikube kubectl -- exec -n intel-ingestion -it deploy/intel-worker -- \
  nc -zv tempo.monitoring.svc.cluster.local 4317

# Check Tempo logs
minikube kubectl -- logs -n monitoring -l app=tempo --tail=50
```

### Mimir Not Storing Metrics

```bash
# Check Prometheus is scraping
minikube kubectl -- logs -n monitoring -l app=prometheus | grep -i "scrape\|mimir"

# Verify Mimir endpoint
curl -s http://localhost:9009/prometheus/api/v1/query?query=up

# Check Prometheus remote write config
minikube kubectl -- get cm -n monitoring prometheus-config -o yaml
```

### Grafana Data source Issues

```bash
# Check datasource connectivity from Grafana pod
minikube kubectl -- exec -n monitoring -it deploy/grafana -- \
  curl -s http://loki:3100/ready

minikube kubectl -- exec -n monitoring -it deploy/grafana -- \
  curl -s http://tempo:3200/ready

minikube kubectl -- exec -n monitoring -it deploy/grafana -- \
  curl -s http://mimir:9009/ready
```

## Cleanup

```bash
# Remove LGTM stack
minikube kubectl -- delete -f k8s/lgtm-stack.yaml

# Or delete namespace
minikube kubectl -- delete namespace monitoring
```

## Production Recommendations

1. **Use Helm Charts**
   ```bash
   helm repo add grafana https://grafana.github.io/helm-charts
   helm install loki grafana/loki-stack -n monitoring
   helm install tempo grafana/tempo -n monitoring
   helm install mimir grafana/mimir-distributed -n monitoring
   ```

2. **Persistent Storage**
   - Use PersistentVolumes instead of emptyDir
   - Consider object storage (S3, GCS) for Loki/Tempo/Mimir

3. **High Availability**
   - Run multiple replicas
   - Use distributed mode for Loki, Tempo, Mimir
   - Deploy across multiple availability zones

4. **Security**
   - Enable TLS for all endpoints
   - Use authentication (OAuth, LDAP)
   - Encrypt data at rest
   - Network policies for isolation

5. **Backup & Restore**
   - Regular backups of Grafana dashboards
   - Export alert rules
   - Snapshot important queries

## References

- [Loki Documentation](https://grafana.com/docs/loki/latest/)
- [Tempo Documentation](https://grafana.com/docs/tempo/latest/)
- [Mimir Documentation](https://grafana.com/docs/mimir/latest/)
- [Grafana Documentation](https://grafana.com/docs/grafana/latest/)
- [OpenTelemetry Python](https://opentelemetry.io/docs/instrumentation/python/)

---

**Built for comprehensive observability** 📊🔍📈
