output "kube_context_used" {
  description = "Context passed to the provider; empty means kubeconfig current-context."
  value       = var.kube_context
}

output "capability_test_namespace" {
  description = "Namespace for Vanilla-ContainerCapabilities.sh fixtures."
  value       = var.deploy_capability_test_workloads ? var.capability_test_namespace : ""
}

output "rbac_test_namespace" {
  description = "Namespace for Vanilla-RBAC.sh fixtures."
  value       = var.deploy_rbac_test_fixtures ? var.rbac_test_namespace : ""
}

output "run_scripts_from_repo_root" {
  description = "Run with kubectl pointed at the same cluster/context Terraform used."
  value       = <<-EOT
    cd ../..
    ./Vanilla-ContainerCapabilities.sh
    ./Vanilla-RBAC.sh
  EOT
}
