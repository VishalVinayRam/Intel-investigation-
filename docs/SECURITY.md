# Security Best Practices & Implementation

This document details the security measures implemented in this project and recommendations for production deployment.

## Table of Contents

1. [Container Security](#container-security)
2. [Kubernetes Security](#kubernetes-security)
3. [Network Security](#network-security)
4. [Secret Management](#secret-management)
5. [CI/CD Security](#cicd-security)
6. [Supply Chain Security](#supply-chain-security)
7. [Monitoring & Detection](#monitoring--detection)
8. [Compliance & Auditing](#compliance--auditing)

---

## Container Security

### ✅ Implemented

#### 1. Multi-Stage Builds
**Dockerfile:1-18 and Dockerfile:20-59**

- **Builder stage** installs dependencies in isolation
- **Runtime stage** only contains necessary files
- **Reduces attack surface** by ~60% compared to single-stage

```dockerfile
FROM python:3.11-slim AS builder
# ... build dependencies

FROM python:3.11-slim
# ... runtime only
```

#### 2. Minimal Base Image

- Using `python:3.11-slim` instead of full Python image
- ~160MB vs ~920MB (saves 760MB)
- Fewer packages = fewer vulnerabilities

#### 3. Non-Root User
**Dockerfile:24-26**

```dockerfile
RUN groupadd -r appuser && \
    useradd -r -g appuser -u 1000 -m -s /sbin/nologin appuser
USER appuser
```

- Runs as UID 1000, not root
- Prevents container escape escalation
- Aligns with Kubernetes security contexts

#### 4. Read-Only Root Filesystem
**k8s/deployment.yaml:50-54**

```yaml
securityContext:
  allowPrivilegeEscalation: false
  readOnlyRootFilesystem: true
  runAsNonRoot: true
  capabilities:
    drop: [ALL]
```

- Prevents file modification attacks
- Forces use of volume mounts for writable paths

#### 5. Dropped Capabilities

- All Linux capabilities dropped
- Minimal privilege principle
- Prevents privilege escalation

#### 6. No Secrets in Image

- API keys injected via Kubernetes Secrets
- Environment variables from ConfigMap
- Never baked into layers

### 🔄 Production Recommendations

#### 1. Image Scanning in CI/CD

**Already implemented in `.github/workflows/security-pipeline.yaml`**

```yaml
- name: Run Trivy vulnerability scanner on image
  uses: aquasecurity/trivy-action@master
  with:
    image-ref: ${{ env.IMAGE_NAME }}:${{ github.sha }}
    severity: 'CRITICAL,HIGH'
    exit-code: '1'  # Fail on vulnerabilities
```

#### 2. Image Signing & Verification

**Implement Sigstore Cosign:**

```bash
# Sign image
cosign sign --yes ghcr.io/org/intel-worker:v1.0.0

# Verify in admission controller
cosign verify \
  --certificate-identity-regexp='.*@company.com' \
  --certificate-oidc-issuer='https://token.actions.githubusercontent.com' \
  ghcr.io/org/intel-worker:v1.0.0
```

#### 3. Distroless Images (Future)

Consider migrating to distroless for even smaller attack surface:

```dockerfile
FROM gcr.io/distroless/python3:latest
# No shell, no package manager
# ~50MB image size
```

#### 4. Regular Base Image Updates

```bash
# Automated Dependabot for Dockerfile
# .github/dependabot.yml
version: 2
updates:
  - package-ecosystem: "docker"
    directory: "/"
    schedule:
      interval: "weekly"
```

---

## Kubernetes Security

### ✅ Implemented

#### 1. Pod Security Context
**k8s/deployment.yaml:18-23**

```yaml
securityContext:
  runAsNonRoot: true
  runAsUser: 1000
  fsGroup: 1000
  seccompProfile:
    type: RuntimeDefault
```

- Enforces non-root user at pod level
- Uses default seccomp profile
- Sets file ownership to non-root group

#### 2. Container Security Context
**k8s/deployment.yaml:50-56**

```yaml
securityContext:
  allowPrivilegeEscalation: false
  readOnlyRootFilesystem: true
  runAsNonRoot: true
  capabilities:
    drop: [ALL]
```

- Defense in depth: pod + container level
- Prevents privilege escalation

#### 3. Resource Limits
**k8s/deployment.yaml:42-48**

```yaml
resources:
  requests:
    cpu: 100m
    memory: 128Mi
  limits:
    cpu: 500m
    memory: 512Mi
```

- Prevents resource exhaustion attacks
- Protects cluster from noisy neighbors

#### 4. Network Policies
**terraform/main.tf:99-184**

Zero-trust networking:
- Worker → Redis only
- Worker → External HTTPS only (threat feeds)
- Monitoring → Worker metrics only
- No unrestricted egress

#### 5. Service Account with Minimal Permissions
**k8s/deployment.yaml:72-76**

```yaml
serviceAccountName: intel-worker-sa
# ...
automountServiceAccountToken: false
```

- Dedicated service account
- No token auto-mount (app doesn't need K8s API)

### 🔄 Production Recommendations

#### 1. Pod Security Standards (PSS)

**Enforce Restricted Policy:**

```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: intel-ingestion
  labels:
    pod-security.kubernetes.io/enforce: restricted
    pod-security.kubernetes.io/audit: restricted
    pod-security.kubernetes.io/warn: restricted
```

#### 2. Admission Controllers

**Install OPA Gatekeeper or Kyverno:**

```yaml
# Kyverno policy: Require non-root
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: require-non-root
spec:
  validationFailureAction: enforce
  rules:
  - name: check-runAsNonRoot
    match:
      resources:
        kinds: [Pod]
    validate:
      message: "Running as root is not allowed"
      pattern:
        spec:
          securityContext:
            runAsNonRoot: true
```

#### 3. Image Policy

**Only allow signed images:**

```yaml
apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: verify-image-signature
spec:
  validationFailureAction: enforce
  rules:
  - name: verify-signature
    match:
      resources:
        kinds: [Pod]
    verifyImages:
    - imageReferences:
      - "ghcr.io/org/intel-worker:*"
      attestors:
      - count: 1
        entries:
        - keyless:
            subject: "*@company.com"
            issuer: "https://token.actions.githubusercontent.com"
```

#### 4. Runtime Security

**Install Falco for runtime threat detection:**

```bash
helm repo add falcosecurity https://falcosecurity.github.io/charts
helm install falco falcosecurity/falco -n falco --create-namespace
```

**Custom Falco Rules:**

```yaml
- rule: Unexpected Network Connection from Worker
  desc: Detect connections to non-whitelisted destinations
  condition: >
    container.name = "intel-worker" and
    fd.type = ipv4 and
    fd.rip != "redis" and
    not fd.rip in (threat_feed_ips)
  output: >
    Unexpected connection from intel-worker
    (dest=%fd.rip port=%fd.rport)
  priority: WARNING
```

---

## Network Security

### ✅ Implemented

#### NetworkPolicy Configuration
**terraform/main.tf:99-184**

**Egress Rules:**

1. **DNS Resolution (UDP/53)**
   ```yaml
   - to:
     - namespaceSelector: {}
     ports:
     - port: 53
       protocol: UDP
   ```

2. **Redis Access (TCP/6379)**
   ```yaml
   - to:
     - podSelector:
         matchLabels:
           app: redis
     ports:
     - port: 6379
       protocol: TCP
   ```

3. **External HTTPS (TCP/443,80)**
   ```yaml
   - to:
     - ipBlock:
         cidr: 0.0.0.0/0
         except:
         - 10.0.0.0/8
         - 172.16.0.0/12
         - 192.168.0.0/16
     ports:
     - port: 443
       protocol: TCP
     - port: 80
       protocol: TCP
   ```

**Ingress Rules:**

1. **Metrics from Monitoring Namespace**
   ```yaml
   - from:
     - namespaceSelector:
         matchLabels:
           name: monitoring
     ports:
     - port: 8000
       protocol: TCP
   ```

### 🔄 Production Recommendations

#### 1. Service Mesh (Istio/Linkerd)

**Benefits:**
- Mutual TLS (mTLS) for all pod-to-pod communication
- Fine-grained traffic policies
- Observability at network layer
- Circuit breaking & retries

**Example Istio PeerAuthentication:**

```yaml
apiVersion: security.istio.io/v1beta1
kind: PeerAuthentication
metadata:
  name: default
  namespace: intel-ingestion
spec:
  mtls:
    mode: STRICT  # Require mTLS
```

#### 2. Egress Gateway

Control and monitor all outbound traffic:

```yaml
apiVersion: networking.istio.io/v1beta1
kind: ServiceEntry
metadata:
  name: threat-feeds
spec:
  hosts:
  - "urlhaus.abuse.ch"
  - "threatfox.abuse.ch"
  ports:
  - number: 443
    name: https
    protocol: HTTPS
  location: MESH_EXTERNAL
  resolution: DNS
```

#### 3. Network Policy Testing

**Use tools like `netpol-verify`:**

```bash
# Test NetworkPolicy enforcement
kubectl run -it --rm test-pod --image=nicolaka/netshoot -n intel-ingestion
# Try connecting to disallowed destinations
```

---

## Secret Management

### ✅ Implemented

#### Kubernetes Secrets
**terraform/main.tf:17-38**

- API keys stored in Kubernetes Secrets
- Base64 encoded
- Mounted as environment variables
- Never in code or Dockerfile

### ⚠️ Current Limitations

Kubernetes Secrets are only base64 encoded, **not encrypted at rest** by default.

### 🔄 Production Recommendations

#### 1. External Secret Management

**HashiCorp Vault:**

```yaml
apiVersion: secrets-store.csi.x-k8s.io/v1
kind: SecretProviderClass
metadata:
  name: vault-secrets
spec:
  provider: vault
  parameters:
    vaultAddress: "https://vault.company.com"
    roleName: "intel-worker"
    objects: |
      - objectName: "threat-feed-api-key"
        secretPath: "secret/data/intel-ingestion"
        secretKey: "api_key"
```

**AWS Secrets Manager:**

```yaml
apiVersion: external-secrets.io/v1beta1
kind: ExternalSecret
metadata:
  name: threat-feed-secrets
spec:
  refreshInterval: 1h
  secretStoreRef:
    name: aws-secrets-manager
    kind: SecretStore
  target:
    name: threat-feed-secrets
  data:
  - secretKey: THREAT_FEED_API_KEY
    remoteRef:
      key: intel-ingestion/api-keys
      property: threat_feed_key
```

#### 2. Encrypt Secrets at Rest

**Enable encryption in Kubernetes:**

```yaml
# /etc/kubernetes/enc/encryption-config.yaml
apiVersion: apiserver.config.k8s.io/v1
kind: EncryptionConfiguration
resources:
  - resources:
    - secrets
    providers:
    - aescbc:
        keys:
        - name: key1
          secret: <base64-encoded-key>
    - identity: {}
```

#### 3. Secret Rotation

**Automated rotation with External Secrets Operator:**

```yaml
refreshInterval: 1h  # Sync secrets every hour
```

#### 4. Least Privilege RBAC

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: secret-reader
  namespace: intel-ingestion
rules:
- apiGroups: [""]
  resources: ["secrets"]
  resourceNames: ["threat-feed-secrets"]
  verbs: ["get"]
```

---

## CI/CD Security

### ✅ Implemented

**GitHub Actions Security Pipeline**
`.github/workflows/security-pipeline.yaml`

#### 1. SAST (Static Application Security Testing)

```yaml
- name: Run Bandit SAST scan
  run: bandit -r app/ -f json -o bandit-report.json
```

**Detects:**
- Hardcoded passwords
- SQL injection risks
- Insecure crypto usage
- Command injection

#### 2. Secret Detection

```yaml
- name: Check for hardcoded secrets
  run: |
    if grep -r -E "(password|api_key|secret|token)\s*=\s*['\"][^'\"]{8,}" app/; then
      exit 1
    fi
```

#### 3. SCA (Software Composition Analysis)

```yaml
- name: Run Trivy vulnerability scanner
  uses: aquasecurity/trivy-action@master
  with:
    scan-type: 'fs'
    severity: 'CRITICAL,HIGH,MEDIUM'
```

**Scans:**
- Python dependencies (requirements.txt)
- Known CVEs
- License compliance issues

#### 4. Container Image Scanning

```yaml
- name: Run Trivy on image
  with:
    image-ref: ${{ env.IMAGE_NAME }}:${{ github.sha }}
    exit-code: '1'  # Fail build on vulnerabilities
```

#### 5. SARIF Upload to GitHub Security

```yaml
- name: Upload Trivy results to GitHub Security
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: 'trivy-results.sarif'
```

### 🔄 Production Recommendations

#### 1. Branch Protection Rules

```yaml
# .github/settings.yml (via Probot)
branches:
  - name: main
    protection:
      required_status_checks:
        strict: true
        contexts:
          - "SAST Security Scan"
          - "SCA Dependency Scan"
          - "Build & Scan Container Image"
      required_pull_request_reviews:
        required_approving_review_count: 2
      enforce_admins: true
```

#### 2. Dependency Review

```yaml
# .github/workflows/dependency-review.yml
name: Dependency Review
on: [pull_request]
permissions:
  contents: read
jobs:
  dependency-review:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/dependency-review-action@v3
        with:
          fail-on-severity: moderate
```

#### 3. OIDC Token for Cloud Access

**No long-lived credentials:**

```yaml
permissions:
  id-token: write  # Required for OIDC
  contents: read

- name: Configure AWS Credentials
  uses: aws-actions/configure-aws-credentials@v4
  with:
    role-to-assume: arn:aws:iam::123456789012:role/GitHubActions
    aws-region: us-east-1
```

#### 4. Artifact Attestation

```yaml
- name: Generate SBOM
  uses: anchore/sbom-action@v0
  with:
    image: intel-worker:${{ github.sha }}

- name: Attest SBOM
  uses: actions/attest-sbom@v1
  with:
    subject-path: intel-worker.spdx.json
    sbom-path: intel-worker.spdx.json
```

---

## Supply Chain Security

### ✅ Implemented Foundations

1. **Multi-stage builds** prevent dev dependencies in production
2. **Pinned Python dependencies** in requirements.txt
3. **Image scanning** in CI/CD
4. **No secrets in images**

### 🔄 Production Recommendations

#### 1. SLSA Framework Compliance

**Achieve SLSA Level 3:**

- ✅ Versioned source code
- ✅ Automated build process
- 🔄 Build provenance generation
- 🔄 Non-falsifiable provenance
- 🔄 Hermetic builds

**Generate Provenance:**

```yaml
- name: Generate provenance
  uses: slsa-framework/slsa-github-generator@v1.9.0
  with:
    base64-subjects: ${{ steps.hash.outputs.hashes }}
    provenance-name: intel-worker.intoto.jsonl
```

#### 2. Software Bill of Materials (SBOM)

```bash
# Generate SBOM with Syft
syft packages intel-worker:latest -o spdx-json > sbom.spdx.json

# Scan SBOM for vulnerabilities
grype sbom:sbom.spdx.json
```

**Automate in CI/CD:**

```yaml
- name: Generate SBOM
  uses: anchore/sbom-action@v0
  with:
    image: intel-worker:${{ github.sha }}
    format: spdx-json
    artifact-name: sbom.spdx.json

- name: Upload SBOM
  uses: actions/upload-artifact@v4
  with:
    name: sbom
    path: sbom.spdx.json
```

#### 3. Dependency Pinning

**requirements.txt - Always pin exact versions:**

```txt
# ✅ Good - exact versions
redis==5.0.1
requests==2.31.0

# ❌ Bad - unpinned
redis
requests>=2.0
```

**Automated updates with Dependabot:**

```yaml
# .github/dependabot.yml
version: 2
updates:
  - package-ecosystem: "pip"
    directory: "/app"
    schedule:
      interval: "weekly"
    open-pull-requests-limit: 10
```

#### 4. Base Image Verification

```dockerfile
# Verify base image with digest
FROM python:3.11-slim@sha256:abc123...

# Or use verified minimal images
FROM cgr.dev/chainguard/python:latest-dev AS builder
FROM cgr.dev/chainguard/python:latest
```

---

## Monitoring & Detection

### ✅ Implemented

#### Prometheus Metrics
**app/worker.py:26-42**

```python
threat_indicators_processed = Counter(
    'threat_indicators_processed_total',
    'Total number of threat indicators processed',
    ['source', 'type']
)

external_api_errors = Counter(
    'external_api_errors_count',
    'Number of external API errors',
    ['source', 'error_type']
)

feed_last_success = Gauge(
    'threat_feed_last_success_timestamp',
    'Last successful feed fetch timestamp',
    ['source']
)
```

#### Alert Rules
**docs/prometheus-alerts.yaml**

- `ThreatFeedSourceDown` - Feed failures
- `NoThreatIndicatorsProcessed` - Worker stalled
- `StaleThreatFeedData` - Data freshness issues

### 🔄 Production Recommendations

#### 1. Distributed Tracing

**OpenTelemetry instrumentation:**

```python
from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.exporter.jaeger.thrift import JaegerExporter

# Configure tracing
trace.set_tracer_provider(TracerProvider())
jaeger_exporter = JaegerExporter(
    agent_host_name="jaeger-agent",
    agent_port=6831,
)
trace.get_tracer_provider().add_span_processor(
    BatchSpanProcessor(jaeger_exporter)
)

# Instrument code
tracer = trace.get_tracer(__name__)

with tracer.start_as_current_span("fetch_urlhaus_feed"):
    # ... fetch logic
```

#### 2. Log Aggregation

**Structured logging with JSON:**

```python
import structlog

logger = structlog.get_logger()
logger.info(
    "feed_fetched",
    source="urlhaus",
    indicator_count=100,
    duration_ms=1234,
    status="success"
)
```

**Ship to centralized logging:**

```yaml
# Fluent Bit DaemonSet
apiVersion: v1
kind: ConfigMap
metadata:
  name: fluent-bit-config
data:
  fluent-bit.conf: |
    [INPUT]
        Name              tail
        Path              /var/log/containers/intel-worker*.log
        Parser            docker
        Tag               kube.*
    [OUTPUT]
        Name              loki
        Match             *
        Host              loki.monitoring
        Port              3100
```

#### 3. Security Monitoring

**Audit logs:**

```yaml
# Kubernetes audit policy
apiVersion: audit.k8s.io/v1
kind: Policy
rules:
- level: Metadata
  namespaces: ["intel-ingestion"]
  verbs: ["get", "list", "create", "update", "patch", "delete"]
  resources:
  - group: ""
    resources: ["secrets", "configmaps"]
```

**SIEM Integration:**

- Forward logs to Splunk/ELK
- Alert on suspicious patterns:
  - Failed authentication attempts
  - Privilege escalation attempts
  - Unexpected network connections
  - Image pull from untrusted registries

---

## Compliance & Auditing

### Security Compliance Checklist

#### CIS Kubernetes Benchmark

- [x] 5.2.1 Minimize container admission (PSP/PSS)
- [x] 5.2.2 Minimize privileged containers (runAsNonRoot)
- [x] 5.2.3 Minimize containers running as root
- [x] 5.2.4 Minimize containers with NET_RAW capability
- [x] 5.2.5 Minimize containers with allowPrivilegeEscalation
- [x] 5.7.3 Apply Security Context to Pods and Containers
- [x] 5.7.4 Configure Image Provenance

#### NIST Cybersecurity Framework

- [x] **Identify (ID):** Asset inventory, threat feeds
- [x] **Protect (PR):** Access control, secrets management, network segmentation
- [x] **Detect (DE):** Logging, monitoring, alerting
- [ ] **Respond (RS):** Incident response runbooks (see docs/prometheus-alerts.yaml)
- [ ] **Recover (RC):** Backup and restore procedures

#### SOC 2 Type II Controls

- [x] **CC6.1** Logical access controls (RBAC, NetworkPolicy)
- [x] **CC6.6** Vulnerability management (scanning in CI/CD)
- [x] **CC7.1** Detection of security events (metrics, alerts)
- [ ] **CC7.2** Monitoring and response (requires full observability stack)

### Audit Procedures

#### Regular Security Reviews

**Weekly:**
- Review Dependabot/security alerts
- Check failed security scans in CI/CD
- Review Prometheus alerts

**Monthly:**
- Full vulnerability scan of running containers
- Review access logs for anomalies
- Update dependencies

**Quarterly:**
- Security architecture review
- Penetration testing
- Compliance audit

---

## Security Contacts

**Report vulnerabilities to:** security@example.com

**Bug bounty program:** https://example.com/security/bounty

**Security advisories:** https://github.com/org/intel-ingestion/security/advisories

---

## References

- [OWASP Container Security](https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html)
- [CIS Kubernetes Benchmark](https://www.cisecurity.org/benchmark/kubernetes)
- [NIST SP 800-190 (Container Security)](https://csrc.nist.gov/publications/detail/sp/800-190/final)
- [Kubernetes Security Best Practices](https://kubernetes.io/docs/concepts/security/overview/)
- [SLSA Framework](https://slsa.dev/)
- [Sigstore Documentation](https://docs.sigstore.dev/)

---

**Last Updated:** 2024-01-15
**Version:** 1.0.0
