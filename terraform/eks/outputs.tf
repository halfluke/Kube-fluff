output "aws_region" {
  description = "AWS region."
  value       = var.aws_region
}

output "cluster_name" {
  description = "EKS cluster name."
  value       = module.eks.cluster_name
}

output "configure_kubectl" {
  description = "Shell command to configure kubectl."
  value       = "aws eks update-kubeconfig --region ${var.aws_region} --name ${module.eks.cluster_name}"
}

output "capability_test_namespace" {
  description = "Namespace for EKS-ContainerCapabilities.sh fixtures (empty if deploy_capability_test_workloads is false)."
  value       = var.deploy_capability_test_workloads ? var.capability_test_namespace : ""
}

output "rbac_test_namespace" {
  description = "Namespace for RBAC fixtures (empty if deploy_rbac_test_fixtures is false)."
  value       = var.deploy_rbac_test_fixtures ? var.rbac_test_namespace : ""
}

output "run_rbac_audit" {
  description = "Example command for EKS-rbac.sh after kubectl is configured."
  value       = <<-EOT
    aws eks update-kubeconfig --region ${var.aws_region} --name ${module.eks.cluster_name}
    ../../EKS-rbac.sh --quiet
  EOT
}

output "run_container_capabilities_audit" {
  description = "Example command for EKS-ContainerCapabilities.sh after kubectl is configured."
  value       = <<-EOT
    aws eks update-kubeconfig --region ${var.aws_region} --name ${module.eks.cluster_name}
    ../../EKS-ContainerCapabilities.sh
  EOT
}

output "cluster_endpoint" {
  description = "Kubernetes API endpoint (sensitive)."
  value       = module.eks.cluster_endpoint
  sensitive   = true
}
