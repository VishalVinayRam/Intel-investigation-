# Upgrading to LGTM Stack

This guide explains how to upgrade your existing deployment from basic Prometheus metrics to the full **LGTM observability stack**.

## What Changed?

### Summary of Changes

| Component | Before | After |
|-----------|--------|-------|
| **Logs** | Plain text to stdout | Structured JSON → Loki |
| **Metrics** | Prometheus endpoint only | Prometheus → Mimir (long-term storage) |
| **Tracing** | None | OpenTelemetry → Tempo |
| **Visualization** | Manual port-forward | Grafana unified dashboard |

### Files Modified

1. **app/worker.py**
   - Added JSON structured logging (Loki-compatible)
   - Added OpenTelemetry instrumentation
   - Trace spans for feed fetches
   - Enhanced error logging with context

2. **app/requirements.txt**
   - Added OpenTelemetry libraries
   - Added OTLP gRPC exporter

3. **terraform/main.tf**
   - Added `TEMPO_ENDPOINT` to ConfigMap
   - Added `ENVIRONMENT` variable

4. **k8s/lgtm-stack.yaml** (NEW)
   - Complete LGTM stack deployment
   - Loki, Grafana, Tempo, Mimir, Prometheus, Promtail

5. **Makefile**
   - Added LGTM deployment commands
   - Added `full-deploy` target

6. **docs/LGTM-SETUP.md** (NEW)
   - Complete setup and usage guide

## Upgrade Steps

### Step 1: Deploy LGTM Stack

```bash
# Deploy the observability stack
make lgtm-deploy

# Or manually:
minikube kubectl -- apply -f k8s/lgtm-stack.yaml

# Verify deployment
make lgtm-status
```

Expected output:
```
NAME                          READY   STATUS    RESTARTS   AGE
pod/grafana-xxx               1/1     Running   0          2m
pod/loki-xxx                  1/1     Running   0          2m
pod/mimir-xxx                 1/1     Running   0          2m
pod/prometheus-xxx            1/1     Running   0          2m
pod/promtail-xxx              1/1     Running   0          2m
pod/tempo-xxx                 1/1     Running   0          2m
```

### Step 2: Rebuild Worker Image

```bash
# Build new image with LGTM support
docker build -t intel-worker:latest .

# Load into minikube
minikube image load intel-worker:latest
```

### Step 3: Update Infrastructure

```bash
# Apply Terraform changes (adds TEMPO_ENDPOINT)
cd terraform
terraform apply -auto-approve
cd ..
```

### Step 4: Restart Worker

```bash
# Restart to pick up new image and config
minikube kubectl -- rollout restart deployment/intel-worker -n intel-ingestion

# Watch rollout
minikube kubectl -- rollout status deployment/intel-worker -n intel-ingestion

# Verify new logs (should be JSON)
minikube kubectl -- logs -n intel-ingestion -l app=intel-worker --tail=5
```

Expected log format (JSON):
```json
{
  "timestamp": "2024-01-15T10:30:45.123456",
  "level": "INFO",
  "message": "Feed fetch successful",
  "source": "urlhaus",
  "count": 100,
  "duration_ms": 1234.56
}
```

### Step 5: Access Grafana

```bash
# Port-forward to Grafana
make grafana

# Or manually:
minikube kubectl -- port-forward -n monitoring svc/grafana 3000:3000

# Open browser: http://localhost:3000
# Login: admin / admin
```

### Step 6: Verify Data Sources

In Grafana:

1. **Check Loki** (Logs)
   - Go to Explore → Select "Loki"
   - Query: `{namespace="intel-ingestion"}`
   - You should see JSON structured logs

2. **Check Tempo** (Traces)
   - Go to Explore → Select "Tempo"
   - Query: `{service.name="intel-worker"}`
   - You should see trace spans

3. **Check Mimir** (Metrics)
   - Go to Explore → Select "Mimir"
   - Query: `threat_indicators_processed_total`
   - You should see metrics

### Step 7: Import Dashboard

```bash
# Option 1: Manual import
# In Grafana: Dashboards → Import → Upload k8s/grafana-dashboard.json

# Option 2: Automated (future enhancement)
# Add dashboard provisioning to lgtm-stack.yaml
```

## Verification Checklist

- [ ] LGTM stack deployed (6 pods running in `monitoring` namespace)
- [ ] Worker restarted with new image
- [ ] Logs are in JSON format
- [ ] Grafana accessible at http://localhost:3000
- [ ] Loki receiving logs (query works in Grafana)
- [ ] Tempo receiving traces (traces visible in Grafana)
- [ ] Mimir receiving metrics (metrics queryable)
- [ ] Dashboard imported and showing data

## Troubleshooting

### Issue: Traces Not Appearing in Tempo

**Check 1: Tempo endpoint configuration**
```bash
# Verify ConfigMap has TEMPO_ENDPOINT
minikube kubectl -- get cm -n intel-ingestion worker-config -o yaml | grep TEMPO

# Should show:
# TEMPO_ENDPOINT: tempo.monitoring.svc.cluster.local:4317
```

**Check 2: Worker logs**
```bash
# Look for OpenTelemetry initialization
minikube kubectl -- logs -n intel-ingestion -l app=intel-worker | grep -i "telemetry\|tempo"

# Should see:
# {"message": "OpenTelemetry tracing configured", "tempo_endpoint": "tempo.monitoring.svc.cluster.local:4317"}
```

**Check 3: Tempo connectivity**
```bash
# Test from worker pod
minikube kubectl -- exec -n intel-ingestion -it deploy/intel-worker -- \
  nc -zv tempo.monitoring.svc.cluster.local 4317

# Should return: Connection to tempo.monitoring.svc.cluster.local 4317 port [tcp/*] succeeded!
```

### Issue: Logs Not in Loki

**Check 1: Promtail is running**
```bash
minikube kubectl -- get pods -n monitoring -l app=promtail

# Should show DaemonSet pod(s) running
```

**Check 2: Promtail logs**
```bash
minikube kubectl -- logs -n monitoring -l app=promtail --tail=50

# Look for errors or warnings
```

**Check 3: Log format**
```bash
# Verify logs are JSON
minikube kubectl -- logs -n intel-ingestion -l app=intel-worker --tail=1

# Should be valid JSON, not plain text
```

### Issue: Metrics Not in Mimir

**Check 1: Prometheus scraping**
```bash
# Check Prometheus targets
minikube kubectl -- port-forward -n monitoring svc/prometheus 9090:9090 &

# Open http://localhost:9090/targets
# intel-worker should be listed and UP
```

**Check 2: Remote write to Mimir**
```bash
# Check Prometheus logs for remote write errors
minikube kubectl -- logs -n monitoring -l app=prometheus | grep -i "remote\|mimir"
```

### Issue: Grafana Shows "No data"

**Quick fix:**
```bash
# Restart Grafana to refresh datasources
minikube kubectl -- rollout restart deployment/grafana -n monitoring

# Wait for restart
minikube kubectl -- wait --for=condition=ready pod -l app=grafana -n monitoring --timeout=60s
```

## Rollback (If Needed)

If you encounter issues and need to rollback:

```bash
# 1. Delete LGTM stack
make lgtm-delete

# 2. Revert worker to previous version (without LGTM)
# Checkout previous version of worker.py and requirements.txt
git checkout HEAD~1 -- app/worker.py app/requirements.txt

# 3. Rebuild image
docker build -t intel-worker:latest .
minikube image load intel-worker:latest

# 4. Restart worker
minikube kubectl -- rollout restart deployment/intel-worker -n intel-ingestion
```

## Performance Impact

### Resource Usage (LGTM Stack)

| Component | CPU Request | Memory Request | Storage |
|-----------|-------------|----------------|---------|
| Loki | 100m | 128Mi | emptyDir |
| Tempo | 100m | 128Mi | emptyDir |
| Mimir | 100m | 256Mi | emptyDir |
| Prometheus | 100m | 256Mi | emptyDir |
| Grafana | 100m | 128Mi | emptyDir |
| Promtail | 50m per node | 64Mi per node | - |
| **Total** | ~650m | ~960Mi | Ephemeral |

### Worker Overhead

- **Logging**: Negligible (JSON formatting is fast)
- **Tracing**: ~5-10ms per trace span
- **Metrics**: No change (same Prometheus endpoint)

## Benefits of LGTM Stack

### Before (Prometheus Only)

```bash
# To view metrics:
kubectl port-forward svc/intel-worker 8000:8000
curl http://localhost:8000/metrics

# To view logs:
kubectl logs -f -l app=intel-worker

# Tracing: Not available
# Correlation: Manual
# Dashboards: None
```

### After (LGTM Stack)

```bash
# Single unified interface (Grafana):
make grafana

# In Grafana:
# - Metrics: PromQL queries with long-term storage
# - Logs: LogQL queries with filtering
# - Traces: TraceQL with span details
# - Correlation: Click trace ID → see logs
# - Dashboards: Pre-built visualizations
# - Alerts: Built-in alert rules
```

## Next Steps

1. **Customize Dashboard**
   - Add panels for your specific use cases
   - Create alert rules
   - Set up notification channels

2. **Production Hardening**
   - Use persistent volumes
   - Enable authentication/authorization
   - Configure retention policies
   - Set up backup/restore

3. **Advanced Queries**
   - Learn LogQL for complex log queries
   - Create PromQL recording rules
   - Use TraceQL for trace analysis

4. **Integration**
   - Export to SIEM
   - Connect to incident management
   - Integrate with ChatOps

## References

- [LGTM Setup Guide](./LGTM-SETUP.md) - Complete setup documentation
- [Grafana Dashboard](../k8s/grafana-dashboard.json) - Pre-built dashboard
- [LGTM Stack Manifests](../k8s/lgtm-stack.yaml) - K8s deployment

---

**Upgrade complete!** 🎉 You now have full observability with the LGTM stack.
