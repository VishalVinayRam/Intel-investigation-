output "namespace_name" {
  description = "The name of the created namespace"
  value       = kubernetes_namespace.intel_ingestion.metadata[0].name
}

output "redis_service_name" {
  description = "The name of the Redis service"
  value       = kubernetes_service.redis.metadata[0].name
}

output "redis_service_endpoint" {
  description = "The Redis service endpoint"
  value       = "${kubernetes_service.redis.metadata[0].name}.${kubernetes_namespace.intel_ingestion.metadata[0].name}.svc.cluster.local:6379"
}

output "secret_name" {
  description = "The name of the secret containing API keys"
  value       = kubernetes_secret.threat_feed_api_keys.metadata[0].name
}

output "network_policy_name" {
  description = "The name of the network policy"
  value       = kubernetes_network_policy.worker_isolation.metadata[0].name
}
