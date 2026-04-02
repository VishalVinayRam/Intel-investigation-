# Complete Setup Guide

This guide walks you through setting up the Threat Intelligence Ingestion platform from scratch.

## Prerequisites Check

Run these commands to verify you have the required tools:

```bash
# Check Docker
docker --version
# Required: Docker version 20.10.0 or later

# Check Minikube
minikube version
# Required: minikube version v1.30.0 or later

# Check Terraform
terraform --version
# Required: Terraform v1.0.0 or later

# Check kubectl
kubectl version --client
# Required: v1.27.0 or later

# Check Make (optional)
make --version
```

If any tool is missing, refer to the installation instructions in README.md.

---

## Step-by-Step Setup

### 1. Clone/Navigate to Project

```bash
cd /path/to/intel-ingestion
```

### 2. Start Minikube Cluster

```bash
# Start with recommended resources
minikube start --cpus=2 --memory=4096

# Verify cluster is running
minikube status

# Expected output:
# minikube
# type: Control Plane
# host: Running
# kubelet: Running
# apiserver: Running
# kubeconfig: Configured
```

### 3. Configure Docker Environment

**Important:** This makes Docker commands use minikube's internal Docker daemon.

```bash
# Configure shell to use minikube's Docker
eval $(minikube docker-env)

# Verify you're using minikube's Docker
docker ps
# Should show minikube's containers
```

**Note:** You need to run `eval $(minikube docker-env)` in each new terminal session.

### 4. Build Container Image

```bash
# Build the Docker image
docker build -t intel-worker:latest .

# Verify image was created
docker images | grep intel-worker

# Test image locally (optional)
docker run --rm intel-worker:latest id
# Should show: uid=1000(appuser) gid=1000(appuser)
```

### 5. Deploy Infrastructure with Terraform

```bash
cd terraform

# Initialize Terraform (first time only)
terraform init

# Review the planned changes
terraform plan

# Apply the infrastructure
terraform apply

# Type 'yes' when prompted

# View created resources
terraform output
```

**What was created:**
- ✅ Namespace: `intel-ingestion`
- ✅ Redis deployment and service
- ✅ Kubernetes Secret for API keys
- ✅ ConfigMap for configuration
- ✅ NetworkPolicy for network isolation

```bash
# Verify with kubectl
kubectl get namespace intel-ingestion
kubectl get all -n intel-ingestion
```

### 6. Deploy Application

```bash
# Return to project root
cd ..

# Apply Kubernetes manifests
kubectl apply -f k8s/deployment.yaml
kubectl apply -f k8s/service.yaml

# Optional: Apply ServiceMonitor (if Prometheus Operator is installed)
# kubectl apply -f k8s/servicemonitor.yaml
```

### 7. Verify Deployment

```bash
# Check pods are running
kubectl get pods -n intel-ingestion

# Expected output:
# NAME                            READY   STATUS    RESTARTS   AGE
# intel-worker-xxxxxxxxxx-xxxxx   1/1     Running   0          1m
# redis-xxxxxxxxxx-xxxxx          1/1     Running   0          3m

# If STATUS is not Running, debug with:
kubectl describe pod -n intel-ingestion -l app=intel-worker
```

### 8. View Application Logs

```bash
# Follow worker logs
kubectl logs -n intel-ingestion -l app=intel-worker -f

# You should see:
# INFO - Starting Threat Intelligence Worker
# INFO - Connected to Redis at redis:6379
# INFO - Worker will fetch feeds every 300 seconds
# INFO - Fetching threat feed from urlhaus
# INFO - Fetched 100 indicators from urlhaus
# INFO - Processed 200 total indicators
```

### 9. Access Metrics

```bash
# Open a new terminal and port-forward
kubectl port-forward -n intel-ingestion svc/intel-worker 8000:8000

# In another terminal, query metrics
curl http://localhost:8000/metrics

# Or open in browser:
# http://localhost:8000/metrics
# http://localhost:8000/health
```

**Expected Metrics:**

```
threat_indicators_processed_total{source="urlhaus",type="malicious_url"} 100.0
threat_indicators_processed_total{source="threatfox",type="malicious_host"} 100.0
external_api_errors_count{error_type="request_failed",source="urlhaus"} 0.0
```

---

## Verification Checklist

- [ ] Minikube cluster is running
- [ ] Docker is using minikube's daemon (`eval $(minikube docker-env)`)
- [ ] Docker image `intel-worker:latest` exists
- [ ] Namespace `intel-ingestion` exists
- [ ] Redis pod is running (1/1 Ready)
- [ ] Intel-worker pod is running (1/1 Ready)
- [ ] Worker logs show successful feed fetching
- [ ] Metrics endpoint is accessible
- [ ] Health endpoint returns 200 OK

---

## Common Issues and Solutions

### Issue: Pod stuck in "ImagePullBackOff"

**Cause:** Docker image not found in minikube's registry.

**Solution:**
```bash
# Make sure you're using minikube's Docker
eval $(minikube docker-env)

# Rebuild the image
docker build -t intel-worker:latest .

# Verify image exists
docker images | grep intel-worker

# Delete and recreate pod
kubectl delete pod -n intel-ingestion -l app=intel-worker
```

### Issue: Pod stuck in "CrashLoopBackOff"

**Cause:** Application error or missing dependencies.

**Solution:**
```bash
# Check logs for errors
kubectl logs -n intel-ingestion -l app=intel-worker --previous

# Common fixes:
# 1. Redis not ready - wait a few seconds
# 2. Network policy blocking - check NetworkPolicy
# 3. Missing environment variables - check ConfigMap/Secret
```

### Issue: "connection refused" when accessing metrics

**Cause:** Port-forward not established or pod not ready.

**Solution:**
```bash
# Verify pod is running
kubectl get pods -n intel-ingestion

# Check pod has 1/1 READY
# Then retry port-forward
kubectl port-forward -n intel-ingestion svc/intel-worker 8000:8000
```

### Issue: Terraform apply fails

**Cause:** Kubernetes context not configured for minikube.

**Solution:**
```bash
# Verify kubectl context
kubectl config current-context
# Should show: minikube

# If not, set context
kubectl config use-context minikube

# Verify connection
kubectl get nodes

# Retry Terraform
cd terraform
terraform apply
```

### Issue: NetworkPolicy blocks external feeds

**Cause:** Minikube CNI may not support NetworkPolicies by default.

**Solution:**
```bash
# Start minikube with Calico
minikube start --cni=calico --cpus=2 --memory=4096

# Or disable NetworkPolicy temporarily
kubectl delete networkpolicy -n intel-ingestion worker-network-policy
```

---

## Testing the Setup

### Test 1: Redis Connectivity

```bash
# Connect to Redis from worker pod
kubectl exec -it -n intel-ingestion deploy/intel-worker -- \
  python -c "import redis; r=redis.Redis(host='redis'); print('Redis ping:', r.ping())"

# Expected: Redis ping: True
```

### Test 2: External Feed Access

```bash
# Test external connectivity from worker
kubectl exec -it -n intel-ingestion deploy/intel-worker -- \
  python -c "import requests; r=requests.get('https://urlhaus.abuse.ch'); print('Status:', r.status_code)"

# Expected: Status: 200
```

### Test 3: Metrics Collection

```bash
# Query metrics
kubectl port-forward -n intel-ingestion svc/intel-worker 8000:8000 &
sleep 2
curl -s http://localhost:8000/metrics | grep threat_indicators_processed_total

# Should show counter values > 0
```

### Test 4: Health Check

```bash
# Check health endpoint
curl -s http://localhost:8000/health | python -m json.tool

# Expected:
# {
#   "status": "healthy",
#   "timestamp": "2024-01-15T10:30:45.123456"
# }
```

---

## Cleanup

### Partial Cleanup (Keep Minikube)

```bash
# Delete application
kubectl delete -f k8s/

# Destroy infrastructure
cd terraform
terraform destroy -auto-approve
```

### Complete Cleanup

```bash
# Using Makefile
make clean-all

# Or manually:
kubectl delete namespace intel-ingestion --force --grace-period=0
cd terraform && terraform destroy -auto-approve && cd ..
minikube delete
```

---

## Next Steps

After successful setup:

1. **Explore Metrics:** Set up Prometheus and Grafana
   ```bash
   # See docs/prometheus-alerts.yaml for setup
   ```

2. **Run Security Scans:**
   ```bash
   make scan-all
   ```

3. **Customize Configuration:**
   - Edit `terraform/variables.tf` for different settings
   - Modify `app/worker.py` to add more threat feeds
   - Adjust fetch interval in ConfigMap

4. **Set Up CI/CD:**
   - Push to GitHub to trigger security pipeline
   - Review `.github/workflows/security-pipeline.yaml`

5. **Production Hardening:**
   - Implement image signing with Cosign
   - Add admission controller for policy enforcement
   - Configure external secret management
   - Set up log aggregation

---

## Getting Help

If you encounter issues:

1. Check this guide's Common Issues section
2. Review main README.md troubleshooting section
3. Examine pod logs: `kubectl logs -n intel-ingestion -l app=intel-worker`
4. Check events: `kubectl get events -n intel-ingestion --sort-by='.lastTimestamp'`
5. Verify resources: `kubectl get all -n intel-ingestion`

---

**Happy SecDevOps! 🔒🚀**
