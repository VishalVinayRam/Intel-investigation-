terraform {
  required_version = ">= 1.0"

  required_providers {
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "~> 2.24"
    }
  }
}

# Configure Kubernetes provider for minikube
provider "kubernetes" {
  config_path    = "~/.kube/config"
  config_context = "minikube"
}
