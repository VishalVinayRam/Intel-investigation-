variable "namespace" {
  description = "Kubernetes namespace for intel ingestion"
  type        = string
  default     = "intel-ingestion"
}

variable "redis_image" {
  description = "Redis Docker image"
  type        = string
  default     = "redis:7-alpine"
}

variable "redis_replicas" {
  description = "Number of Redis replicas"
  type        = number
  default     = 1
}

variable "environment" {
  description = "Environment name (poc, staging, production)"
  type        = string
  default     = "poc"
}
