# 🛡️ Intel Ingestion: Hardened Threat Intelligence Pipeline

This is an enterprise-grade, high-throughput pipeline for ingesting, processing, and observing threat intelligence indicators at scale. Built with **NATS JetStream**, **Redis**, and the **LGTM Observability Stack**, it’s designed to be security-hardened and horizontally scalable from day one.

---

## 🚀 One-Command Management
We've unified the lifecycle of this pipeline into a single script. Use **`manage.sh`** for everything:

```bash
# 1. Start the entire application (Minikube + All Services)
./manage.sh up

# 2. Check the health status of all pods and NATS streams
./manage.sh status

# 3. Open the Grafana Dashboard
./manage.sh dashboard

# 4. Stop everything (tears down services, keeps the cluster ready)
./manage.sh down
```

---

## 🏗️ Architecture at a Glance
The system is built on a "Three-Stage Relay" pattern:
- **Stage 1 (Fetch):** Proactive fetchers troll global threat feeds every 5 minutes.
- **Stage 2 (Buffer):** NATS JetStream provides disk-persistent, "at-least-once" delivery.
- **Stage 3 (Process):** A fleet of auto-scaling processors (HPA 3-50) commits indicators to Redis with a 24h TTL.

---

## 🔍 The Documentation Set
- [**Implementation Overview**](./docs/implementation-overview.md): Your "Day 1" guide to the code and logic.
- [**System Architecture**](./docs/complete-architecture.md): The "Architect's Notebook" on design choices and data flow.
- [**NATS Strategy**](./NATS-ARCHITECTURE.md): A deep dive into how we handle massive traffic spikes.
- [**Knowledge Base**](./docs/references.md): A curated reading list to master the stack.

---

## 🔒 Security & Hardening
Security isn't an "afterthought" here; it's physically enforced:
- **Admission Control:** Kyverno blocks any pod that isn't hardened (non-root, read-only FS).
- **Supply Chain:** GitHub Actions run SAST (Bandit) and SCA (Trivy) scans on every PR.
- **Zero-Restart Secrets:** Redis passwords rotate hourly and hot-reload in the app without downtime.

---
*Maintained with ❤️ for resilient security engineering.*
