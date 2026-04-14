#!/bin/bash

# Intel Ingestion Pipeline: Management Script

set -e

BOLD='\033[1m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
CYAN='\033[0;36m'
NC='\033[0m'

function info()    { echo -e "${BLUE}${BOLD}[INFO]${NC} $1"; }
function success() { echo -e "${GREEN}${BOLD}[OK]${NC}   $1"; }
function warn()    { echo -e "${YELLOW}${BOLD}[WARN]${NC} $1"; }
function error()   { echo -e "${RED}${BOLD}[FAIL]${NC} $1"; }
function header()  { echo -e "\n${CYAN}${BOLD}=== $1 ===${NC}"; }

# -------------------------------------------------------
# health: check every pod across all namespaces
# -------------------------------------------------------
function health_check() {
    local all_ok=true

    header "Minikube"
    if minikube status | grep -q "Running"; then
        success "Minikube is running"
    else
        error "Minikube is NOT running"
        all_ok=false
    fi

    header "intel-ingestion pods"
    check_namespace_pods "intel-ingestion" all_ok

    header "nats-system pods"
    check_namespace_pods "nats-system" all_ok

    header "monitoring pods"
    check_namespace_pods "monitoring" all_ok

    header "kyverno pods"
    check_namespace_pods "kyverno" all_ok

    header "Port-forwards"
    check_port 3000 "Grafana"
    check_port 3100 "Loki"
    check_port 3200 "Tempo"
    check_port 4222 "NATS"

    header "Result"
    if $all_ok; then
        success "All systems healthy"
    else
        warn "Some components need attention (see above)"
    fi
}

function check_namespace_pods() {
    local ns=$1
    local -n _ok=$2

    if ! minikube kubectl -- get namespace "$ns" &>/dev/null; then
        warn "Namespace '$ns' does not exist yet"
        _ok=false
        return
    fi

    local pods
    pods=$(minikube kubectl -- get pods -n "$ns" --no-headers 2>/dev/null)

    if [[ -z "$pods" ]]; then
        warn "No pods found in $ns"
        _ok=false
        return
    fi

    while IFS= read -r line; do
        local name ready status
        name=$(echo "$line" | awk '{print $1}')
        ready=$(echo "$line" | awk '{print $2}')
        status=$(echo "$line" | awk '{print $3}')

        if [[ "$status" == "Running" || "$status" == "Completed" ]]; then
            success "$ns / $name  ($ready  $status)"
        else
            error  "$ns / $name  ($ready  $status)"
            _ok=false
        fi
    done <<< "$pods"
}

function check_port() {
    local port=$1
    local name=$2
    if ss -tlnp 2>/dev/null | grep -q ":${port} "; then
        success "$name is reachable on localhost:$port"
    else
        warn "$name port-forward not active (localhost:$port)"
    fi
}

# -------------------------------------------------------
# ports: start all port-forwards in the background
# -------------------------------------------------------
function start_ports() {
    header "Starting port-forwards"

    forward_bg "monitoring"  "svc/grafana"      3000 "Grafana"
    forward_bg "monitoring"  "svc/loki"         3100 "Loki"
    forward_bg "monitoring"  "svc/tempo"        3200 "Tempo"
    forward_bg "nats-system" "svc/nats-client"  4222 "NATS"

    echo ""
    info "Port-forwards running in background. PIDs saved to /tmp/intel-pf.pids"
    info "Run './manage.sh ports-stop' to kill them all."
    echo ""
    echo "  Grafana  -> http://localhost:3000  (admin / admin)"
    echo "  Loki     -> http://localhost:3100"
    echo "  Tempo    -> http://localhost:3200"
    echo "  NATS     -> localhost:4222"
}

function forward_bg() {
    local ns=$1 resource=$2 port=$3 name=$4

    # kill any existing forward on this port
    if ss -tlnp 2>/dev/null | grep -q ":${port} "; then
        warn "$name already forwarded on :$port — skipping"
        return
    fi

    minikube kubectl -- port-forward -n "$ns" "$resource" "${port}:${port}" &>/tmp/pf-${port}.log &
    local pid=$!
    echo "$pid" >> /tmp/intel-pf.pids
    sleep 1
    if kill -0 "$pid" 2>/dev/null; then
        success "$name  localhost:$port (pid $pid)"
    else
        error "$name port-forward failed — check /tmp/pf-${port}.log"
    fi
}

function stop_ports() {
    if [[ ! -f /tmp/intel-pf.pids ]]; then
        info "No port-forward PIDs found."
        return
    fi
    while read -r pid; do
        kill "$pid" 2>/dev/null && info "Killed PID $pid" || true
    done < /tmp/intel-pf.pids
    rm -f /tmp/intel-pf.pids
    success "All port-forwards stopped."
}

# -------------------------------------------------------
# show_help
# -------------------------------------------------------
function show_help() {
    echo -e "${BOLD}Threat Intel Pipeline — Control Centre${NC}"
    echo "Usage: ./manage.sh [command]"
    echo ""
    echo "Deployment:"
    echo "  up          Start Minikube, build images, deploy full NATS + LGTM stack"
    echo "  down        Delete all services (keeps Minikube cluster)"
    echo "  reset       DESTROY everything and redeploy from scratch"
    echo ""
    echo "Observability:"
    echo "  health      Health check — pods, namespaces, and port-forwards"
    echo "  ports       Start all port-forwards in the background"
    echo "  ports-stop  Kill all background port-forwards"
    echo "  status      kubectl summary of pods, HPA, and NATS"
    echo "  logs        Tail Fetcher and Processor logs"
    echo ""
    echo "Testing:"
    echo "  stress      Run 5000-message load test"
}

# -------------------------------------------------------
# Main
# -------------------------------------------------------
case "$1" in
    up)
        info "Initializing the threat intelligence pipeline..."
        info "Building images and deploying NATS + LGTM stack..."
        make full-deploy-nats

        info "Waiting 15s for pods to settle..."
        sleep 15

        health_check

        echo ""
        info "Run './manage.sh ports' to start all port-forwards."
        ;;

    down)
        warn "Stopping services..."
        make nats-services-delete
        make nats-delete
        make lgtm-delete
        stop_ports
        success "Cleanup complete. Cluster is still running."
        ;;

    health)
        health_check
        ;;

    ports)
        start_ports
        ;;

    ports-stop)
        stop_ports
        ;;

    status)
        info "Fetching system status..."
        make status
        echo ""
        make nats-status
        ;;

    logs)
        info "Tailing Fetcher and Processor logs..."
        make logs-all-nats
        ;;

    stress)
        info "Launching load test: 5000 messages..."
        cd scripts && python load-test.py
        ;;

    reset)
        error "WARNING: This will delete your entire Minikube cluster and all data."
        read -p "Are you sure? (y/N) " confirm
        if [[ $confirm == [yY] || $confirm == [yY][eE][sS] ]]; then
            info "Destroying cluster..."
            make clean-all
            info "Starting fresh deployment..."
            $0 up
        else
            info "Reset cancelled."
        fi
        ;;

    *)
        show_help
        ;;
esac
