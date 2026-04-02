# Kubernetes Namespace for Intel Ingestion
resource "kubernetes_namespace" "intel_ingestion" {
  metadata {
    name = "intel-ingestion"

    labels = {
      name        = "intel-ingestion"
      environment = "poc"
      managed-by  = "terraform"
    }
  }
}

# Secret Store for API Keys (Mock Cloud Secret Manager)
resource "kubernetes_secret" "threat_feed_api_keys" {
  metadata {
    name      = "threat-feed-secrets"
    namespace = kubernetes_namespace.intel_ingestion.metadata[0].name

    labels = {
      app         = "intel-worker"
      environment = "poc"
    }
  }

  # Note: In production, these would be injected via CI/CD or external secret manager
  # For POC, we're using placeholder values
  data = {
    THREAT_FEED_API_KEY = base64encode("your-api-key-here-not-hardcoded")
    REDIS_PASSWORD      = base64encode("")  # Empty for POC, should be set in production
  }

  type = "Opaque"
}

# Redis Deployment (Task Queue)
resource "kubernetes_deployment" "redis" {
  metadata {
    name      = "redis"
    namespace = kubernetes_namespace.intel_ingestion.metadata[0].name

    labels = {
      app  = "redis"
      role = "cache"
    }
  }

  spec {
    replicas = 1

    selector {
      match_labels = {
        app = "redis"
      }
    }

    template {
      metadata {
        labels = {
          app  = "redis"
          role = "cache"
        }
      }

      spec {
        container {
          name  = "redis"
          image = "redis:7-alpine"

          port {
            container_port = 6379
            name           = "redis"
          }

          resources {
            requests = {
              cpu    = "100m"
              memory = "128Mi"
            }
            limits = {
              cpu    = "500m"
              memory = "512Mi"
            }
          }

          liveness_probe {
            tcp_socket {
              port = 6379
            }
            initial_delay_seconds = 30
            period_seconds        = 10
          }

          readiness_probe {
            exec {
              command = ["redis-cli", "ping"]
            }
            initial_delay_seconds = 5
            period_seconds        = 10
          }

          # Security: Run as non-root
          security_context {
            run_as_non_root             = true
            run_as_user                 = 999
            allow_privilege_escalation  = false
            read_only_root_filesystem   = true

            capabilities {
              drop = ["ALL"]
            }
          }
        }

        # Security: Pod-level security context
        security_context {
          fs_group            = 999
          run_as_non_root     = true
          supplemental_groups = [999]
        }
      }
    }
  }
}

# Redis Service
resource "kubernetes_service" "redis" {
  metadata {
    name      = "redis"
    namespace = kubernetes_namespace.intel_ingestion.metadata[0].name

    labels = {
      app = "redis"
    }
  }

  spec {
    selector = {
      app = "redis"
    }

    port {
      port        = 6379
      target_port = 6379
      protocol    = "TCP"
    }

    type = "ClusterIP"
  }
}

# NetworkPolicy: Restrict worker traffic
# Only allow:
# 1. Worker -> Redis
# 2. Worker -> External internet (for threat feeds)
# 3. Ingress to worker metrics port (from Prometheus namespace - if exists)
resource "kubernetes_network_policy" "worker_isolation" {
  metadata {
    name      = "worker-network-policy"
    namespace = kubernetes_namespace.intel_ingestion.metadata[0].name

    labels = {
      app = "intel-worker"
    }
  }

  spec {
    pod_selector {
      match_labels = {
        app = "intel-worker"
      }
    }

    # Allow egress to Redis and external internet
    egress {
      # Allow DNS
      to {
        namespace_selector {}
      }
      ports {
        port     = "53"
        protocol = "UDP"
      }
    }

    egress {
      # Allow Redis
      to {
        pod_selector {
          match_labels = {
            app = "redis"
          }
        }
      }
      ports {
        port     = "6379"
        protocol = "TCP"
      }
    }

    egress {
      # Allow HTTPS to external threat feeds
      to {
        # Allow all external IPs (not in cluster)
        ip_block {
          cidr = "0.0.0.0/0"
          except = [
            "10.0.0.0/8",    # Private network
            "172.16.0.0/12", # Private network
            "192.168.0.0/16" # Private network
          ]
        }
      }
      ports {
        port     = "443"
        protocol = "TCP"
      }
      ports {
        port     = "80"
        protocol = "TCP"
      }
    }

    # Allow ingress to metrics endpoint
    ingress {
      from {
        namespace_selector {
          match_labels = {
            name = "monitoring"
          }
        }
      }
      ports {
        port     = "8000"
        protocol = "TCP"
      }
    }

    # Allow ingress from within same namespace for debugging
    ingress {
      from {
        pod_selector {}
      }
      ports {
        port     = "8000"
        protocol = "TCP"
      }
    }

    policy_types = ["Ingress", "Egress"]
  }
}

# ConfigMap for worker configuration
resource "kubernetes_config_map" "worker_config" {
  metadata {
    name      = "worker-config"
    namespace = kubernetes_namespace.intel_ingestion.metadata[0].name

    labels = {
      app = "intel-worker"
    }
  }

  data = {
    REDIS_HOST     = "redis"
    REDIS_PORT     = "6379"
    FETCH_INTERVAL = "300"  # 5 minutes
    METRICS_PORT   = "8000"
    LOG_LEVEL      = "INFO"
  }
}
