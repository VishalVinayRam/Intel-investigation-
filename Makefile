.PHONY: help build push deploy destroy test clean scan

# Variables
IMAGE_NAME := intel-worker
IMAGE_TAG := latest
NAMESPACE := intel-ingestion
DOCKER_REGISTRY := localhost:5000

help: ## Show this help message
	@echo 'Usage: make [target]'
	@echo ''
	@echo 'Available targets:'
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'

# Development
install: ## Install Python dependencies locally
	pip install -r app/requirements.txt

run-local: ## Run worker locally (requires Redis)
	cd app && python worker.py

# Docker
build: ## Build Docker image
	docker build -t $(IMAGE_NAME):$(IMAGE_TAG) .
	docker tag $(IMAGE_NAME):$(IMAGE_TAG) $(IMAGE_NAME):$(shell git rev-parse --short HEAD 2>/dev/null || echo "local")

build-minikube: ## Build for minikube
	eval $$(minikube docker-env) && docker build -t $(IMAGE_NAME):$(IMAGE_TAG) .

push: build ## Push image to registry
	docker tag $(IMAGE_NAME):$(IMAGE_TAG) $(DOCKER_REGISTRY)/$(IMAGE_NAME):$(IMAGE_TAG)
	docker push $(DOCKER_REGISTRY)/$(IMAGE_NAME):$(IMAGE_TAG)

# Minikube
minikube-start: ## Start minikube cluster
	minikube start --cpus=2 --memory=4096
	@echo "Minikube started. Run 'eval \$$(minikube docker-env)' to use minikube's Docker daemon"

minikube-stop: ## Stop minikube cluster
	minikube stop

minikube-delete: ## Delete minikube cluster
	minikube delete

# Terraform
tf-init: ## Initialize Terraform
	cd terraform && terraform init

tf-plan: ## Plan Terraform changes
	cd terraform && terraform plan

tf-apply: ## Apply Terraform configuration
	cd terraform && terraform apply -auto-approve

tf-destroy: ## Destroy Terraform resources
	cd terraform && terraform destroy -auto-approve

# Kubernetes
k8s-apply: ## Apply Kubernetes manifests
	minikube kubectl -- apply -f k8s/

k8s-delete: ## Delete Kubernetes resources
	minikube kubectl -- delete -f k8s/ --ignore-not-found=true

deploy: build-minikube tf-apply kyverno-deploy k8s-apply ## Full deployment to minikube
	@echo "Deployment complete!"
	@echo "Check status: kubectl get pods -n $(NAMESPACE)"
	@echo "View logs: kubectl logs -f -n $(NAMESPACE) -l app=intel-worker"
	@echo "Access metrics: kubectl port-forward -n $(NAMESPACE) svc/intel-worker 8000:8000"

# Kyverno (Admission Controller)
kyverno-deploy: ## Deploy Kyverno Admission Controller and policies
	@echo "Deploying Kyverno..."
	minikube kubectl -- create -f https://github.com/kyverno/kyverno/releases/download/v1.11.4/install.yaml || true
	@echo "Waiting for Kyverno to become ready..."
	minikube kubectl -- wait --for=condition=ready pod -l app.kubernetes.io/name=kyverno -n kyverno --timeout=300s || true
	@echo "Applying Kyverno ClusterPolicies..."
	minikube kubectl -- apply -f k8s/kyverno-policies.yaml
	@echo "Patching Kyverno cleanup jobs Image..."
	minikube kubectl -- patch cronjob kyverno-cleanup-admission-reports -n kyverno --type='json' -p='[{"op": "replace", "path": "/spec/jobTemplate/spec/template/spec/containers/0/image", "value":"bitnami/kubectl:latest"}]'
	minikube kubectl -- patch cronjob kyverno-cleanup-cluster-admission-reports -n kyverno --type='json' -p='[{"op": "replace", "path": "/spec/jobTemplate/spec/template/spec/containers/0/image", "value":"bitnami/kubectl:latest"}]'
	@echo "Kyverno successfully deployed!"

# LGTM Stack (Loki, Grafana, Tempo, Mimir)
lgtm-deploy: ## Deploy LGTM observability stack
	@echo "Deploying LGTM stack (Loki, Grafana, Tempo, Mimir)..."
	kubectl apply -f k8s/lgtm-stack.yaml
	@echo "Waiting for LGTM components to be ready..."
	kubectl wait --for=condition=ready pod -l app=grafana -n monitoring --timeout=300s || true
	kubectl wait --for=condition=ready pod -l app=loki -n monitoring --timeout=300s || true
	kubectl wait --for=condition=ready pod -l app=tempo -n monitoring --timeout=300s || true
	kubectl wait --for=condition=ready pod -l app=mimir -n monitoring --timeout=300s || true
	@echo ""
	@echo "LGTM Stack deployed!"
	@echo "Access Grafana: kubectl port-forward -n monitoring svc/grafana 3000:3000"
	@echo "Open http://localhost:3000 (admin/admin)"

lgtm-status: ## Check LGTM stack status
	@echo "=== LGTM Stack Status ==="
	kubectl get all -n monitoring

lgtm-delete: ## Delete LGTM stack
	kubectl delete -f k8s/lgtm-stack.yaml

grafana: ## Port-forward to Grafana
	@echo "Accessing Grafana at http://localhost:3000"
	@echo "Username: admin / Password: admin"
	minikube kubectl -- port-forward -n monitoring svc/grafana 3000:3000

loki: ## Port-forward to Loki
	@echo "Accessing Loki at http://localhost:3100"
	minikube kubectl -- port-forward -n monitoring svc/loki 3100:3100

tempo: ## Port-forward to Tempo
	@echo "Accessing Tempo at http://localhost:3200"
	minikube kubectl -- port-forward -n monitoring svc/tempo 3200:3200

full-deploy: minikube-start build-minikube tf-apply k8s-apply lgtm-deploy ## Complete deployment with LGTM stack
	@echo ""
	@echo "========================================="
	@echo "Full deployment complete!"
	@echo "========================================="
	@echo ""
	@echo "Threat Intelligence Worker:"
	@echo "  - Status: kubectl get pods -n $(NAMESPACE)"
	@echo "  - Logs: kubectl logs -f -n $(NAMESPACE) -l app=intel-worker"
	@echo "  - Metrics: kubectl port-forward -n $(NAMESPACE) svc/intel-worker 8000:8000"
	@echo ""
	@echo "LGTM Observability Stack:"
	@echo "  - Grafana: make grafana (then open http://localhost:3000)"
	@echo "  - Logs: Loki + Promtail"
	@echo "  - Traces: Tempo"
	@echo "  - Metrics: Mimir + Prometheus"
	@echo ""

destroy: k8s-delete tf-destroy ## Destroy all resources
	@echo "All resources destroyed"

# Testing & Security
test: ## Run tests
	@echo "Running unit tests..."
	# pytest tests/

scan-code: ## Run SAST scan with Bandit
	@echo "Running Bandit SAST scan..."
	pip install bandit
	bandit -r app/ -f txt

scan-deps: ## Scan dependencies for vulnerabilities
	@echo "Running Safety scan..."
	pip install safety
	safety check --file=app/requirements.txt

scan-image: build ## Scan Docker image with Trivy
	@echo "Running Trivy scan..."
	docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
		aquasec/trivy:latest image $(IMAGE_NAME):$(IMAGE_TAG)

scan-all: scan-code scan-deps scan-image ## Run all security scans

# Monitoring
logs: ## Show worker logs
	kubectl logs -f -n $(NAMESPACE) -l app=intel-worker

metrics: ## Port-forward to metrics endpoint
	@echo "Accessing metrics at http://localhost:8000/metrics"
	kubectl port-forward -n $(NAMESPACE) svc/intel-worker 8000:8000

redis-cli: ## Connect to Redis CLI
	kubectl exec -it -n $(NAMESPACE) deploy/redis -- redis-cli

status: ## Check deployment status
	@echo "=== Namespace ==="
	kubectl get namespace $(NAMESPACE) 2>/dev/null || echo "Namespace not found"
	@echo ""
	@echo "=== Deployments ==="
	kubectl get deployments -n $(NAMESPACE)
	@echo ""
	@echo "=== Pods ==="
	kubectl get pods -n $(NAMESPACE)
	@echo ""
	@echo "=== Services ==="
	kubectl get services -n $(NAMESPACE)
	@echo ""
	@echo "=== NetworkPolicies ==="
	kubectl get networkpolicies -n $(NAMESPACE)

# Cleanup
clean: ## Clean local build artifacts
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name '*.pyc' -delete
	find . -type f -name '*.pyo' -delete
	find . -type d -name '*.egg-info' -exec rm -rf {} + 2>/dev/null || true
	rm -f *.tar

clean-all: clean destroy minikube-delete ## Clean everything
	@echo "Complete cleanup done"
