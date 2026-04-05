output "resource_group_name" {
  description = "Azure resource group containing the cluster."
  value       = azurerm_resource_group.this.name
}

output "location" {
  description = "Azure region."
  value       = azurerm_resource_group.this.location
}

output "cluster_name" {
  description = "AKS cluster name."
  value       = azurerm_kubernetes_cluster.this.name
}

output "configure_kubectl" {
  description = "Shell command to configure kubectl (requires Azure CLI)."
  value       = "az aks get-credentials --resource-group ${azurerm_resource_group.this.name} --name ${azurerm_kubernetes_cluster.this.name} --overwrite-existing"
}

output "capability_test_namespace" {
  description = "Namespace for AKS-ContainerCapabilities.sh fixtures (empty if deploy_capability_test_workloads is false)."
  value       = var.deploy_capability_test_workloads ? var.capability_test_namespace : ""
}

output "rbac_test_namespace" {
  description = "Namespace for RBAC fixtures (empty if deploy_rbac_test_fixtures is false)."
  value       = var.deploy_rbac_test_fixtures ? var.rbac_test_namespace : ""
}

output "run_rbac_audit" {
  description = "Example env + command for AKS-rbac.sh after kubectl is configured (Check 2 needs az + AKS_RESOURCE_GROUP / AKS_CLUSTER_NAME)."
  value       = <<-EOT
    az aks get-credentials --resource-group ${azurerm_resource_group.this.name} --name ${azurerm_kubernetes_cluster.this.name} --overwrite-existing
    export AKS_RESOURCE_GROUP="${azurerm_resource_group.this.name}"
    export AKS_CLUSTER_NAME="${azurerm_kubernetes_cluster.this.name}"
    ../../AKS-rbac.sh --quiet
  EOT
}

output "run_container_capabilities_audit" {
  description = "Example command for AKS-ContainerCapabilities.sh after kubectl is configured."
  value       = <<-EOT
    az aks get-credentials --resource-group ${azurerm_resource_group.this.name} --name ${azurerm_kubernetes_cluster.this.name} --overwrite-existing
    ../../AKS-ContainerCapabilities.sh
  EOT
}

output "cluster_fqdn" {
  description = "Kubernetes API server FQDN (sensitive)."
  value       = azurerm_kubernetes_cluster.this.fqdn
  sensitive   = true
}
