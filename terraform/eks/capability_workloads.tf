# Fixtures for ../../EKS-ContainerCapabilities.sh: caps add/drop, init vs app,
# automountServiceAccountToken, runAsNonRoot / allowPrivilegeEscalation.
# Namespace uses PSA enforce=privileged so pods are not blocked by baseline/restricted admission.

resource "kubernetes_namespace" "cap_test" {
  count = var.deploy_capability_test_workloads ? 1 : 0

  metadata {
    name = var.capability_test_namespace
    labels = {
      "pod-security.kubernetes.io/enforce" = "privileged"
      "pod-security.kubernetes.io/audit"   = "restricted"
      "pod-security.kubernetes.io/warn"    = "restricted"
    }
  }

  depends_on = [module.eks]
}

resource "kubernetes_deployment" "cap_net_admin" {
  count = var.deploy_capability_test_workloads ? 1 : 0

  metadata {
    name      = "cap-test-net-admin"
    namespace = var.capability_test_namespace
    labels    = { "app.kubernetes.io/name" = "cap-test-net-admin" }
  }

  spec {
    replicas = 1
    selector {
      match_labels = { "app.kubernetes.io/name" = "cap-test-net-admin" }
    }
    template {
      metadata {
        labels = { "app.kubernetes.io/name" = "cap-test-net-admin" }
      }
      spec {
        container {
          name  = "main"
          image = var.capability_test_pause_image
          security_context {
            capabilities {
              add = ["NET_ADMIN"]
            }
          }
        }
      }
    }
  }

  depends_on = [kubernetes_namespace.cap_test]
}

resource "kubernetes_deployment" "cap_baseline_privileged" {
  count = var.deploy_capability_test_workloads ? 1 : 0

  metadata {
    name      = "cap-test-chown-dac"
    namespace = var.capability_test_namespace
    labels    = { "app.kubernetes.io/name" = "cap-test-chown-dac" }
  }

  spec {
    replicas = 1
    selector {
      match_labels = { "app.kubernetes.io/name" = "cap-test-chown-dac" }
    }
    template {
      metadata {
        labels = { "app.kubernetes.io/name" = "cap-test-chown-dac" }
      }
      spec {
        container {
          name  = "main"
          image = var.capability_test_pause_image
          security_context {
            capabilities {
              add = ["CHOWN", "DAC_OVERRIDE"]
            }
          }
        }
      }
    }
  }

  depends_on = [kubernetes_namespace.cap_test]
}

resource "kubernetes_deployment" "cap_drop_all_net_bind" {
  count = var.deploy_capability_test_workloads ? 1 : 0

  metadata {
    name      = "cap-test-drop-all-net-bind"
    namespace = var.capability_test_namespace
    labels    = { "app.kubernetes.io/name" = "cap-test-drop-all-net-bind" }
  }

  spec {
    replicas = 1
    selector {
      match_labels = { "app.kubernetes.io/name" = "cap-test-drop-all-net-bind" }
    }
    template {
      metadata {
        labels = { "app.kubernetes.io/name" = "cap-test-drop-all-net-bind" }
      }
      spec {
        container {
          name  = "main"
          image = var.capability_test_pause_image
          security_context {
            capabilities {
              drop = ["ALL"]
              add  = ["NET_BIND_SERVICE"]
            }
          }
        }
      }
    }
  }

  depends_on = [kubernetes_namespace.cap_test]
}

resource "kubernetes_deployment" "cap_init_vs_main" {
  count = var.deploy_capability_test_workloads ? 1 : 0

  metadata {
    name      = "cap-test-init-mknod"
    namespace = var.capability_test_namespace
    labels    = { "app.kubernetes.io/name" = "cap-test-init-mknod" }
  }

  spec {
    replicas = 1
    selector {
      match_labels = { "app.kubernetes.io/name" = "cap-test-init-mknod" }
    }
    template {
      metadata {
        labels = { "app.kubernetes.io/name" = "cap-test-init-mknod" }
      }
      spec {
        init_container {
          name    = "init-caps"
          image   = var.capability_test_init_container_image
          command = ["/bin/sh", "-c", "exit 0"]
          security_context {
            capabilities {
              add = ["MKNOD"]
            }
          }
        }
        container {
          name  = "main"
          image = var.capability_test_pause_image
        }
      }
    }
  }

  depends_on = [kubernetes_namespace.cap_test]
}

resource "kubernetes_deployment" "cap_automount_nonroot" {
  count = var.deploy_capability_test_workloads ? 1 : 0

  metadata {
    name      = "cap-test-automount-nonroot"
    namespace = var.capability_test_namespace
    labels    = { "app.kubernetes.io/name" = "cap-test-automount-nonroot" }
  }

  spec {
    replicas = 1
    selector {
      match_labels = { "app.kubernetes.io/name" = "cap-test-automount-nonroot" }
    }
    template {
      metadata {
        labels = { "app.kubernetes.io/name" = "cap-test-automount-nonroot" }
      }
      spec {
        automount_service_account_token = false
        security_context {
          run_as_non_root = true
          run_as_user     = 65534
        }
        container {
          name  = "main"
          image = var.capability_test_pause_image
          security_context {
            allow_privilege_escalation = false
            run_as_non_root            = true
            run_as_user                = 65534
          }
        }
      }
    }
  }

  depends_on = [kubernetes_namespace.cap_test]
}
