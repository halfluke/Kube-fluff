# IRSA demo: IAM role trusted by the cluster OIDC provider + annotated ServiceAccount + pause pod
# so ../../EKS-ContainerCapabilities.sh surfaces irsa_iam_role_arn.

locals {
  irsa_enabled = var.deploy_irsa_demo && var.deploy_capability_test_workloads
  oidc_host    = trimsuffix(replace(module.eks.cluster_oidc_issuer_url, "https://", ""), "/")
}

data "aws_iam_policy_document" "irsa_demo_assume" {
  count = local.irsa_enabled ? 1 : 0

  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRoleWithWebIdentity"]

    principals {
      type        = "Federated"
      identifiers = [module.eks.oidc_provider_arn]
    }

    condition {
      test     = "StringEquals"
      variable = "${local.oidc_host}:aud"
      values   = ["sts.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "${local.oidc_host}:sub"
      values   = ["system:serviceaccount:${var.capability_test_namespace}:${var.irsa_demo_service_account_name}"]
    }
  }
}

resource "aws_iam_role" "irsa_demo" {
  count = local.irsa_enabled ? 1 : 0

  name                  = "${var.cluster_name}-irsa-demo"
  assume_role_policy    = data.aws_iam_policy_document.irsa_demo_assume[0].json
  force_detach_policies = true

  depends_on = [module.eks]
}

resource "aws_iam_role_policy" "irsa_demo_minimal" {
  count = local.irsa_enabled ? 1 : 0

  name = "sts-get-caller-identity"
  role = aws_iam_role.irsa_demo[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["sts:GetCallerIdentity"]
      Resource = "*"
    }]
  })
}

resource "kubernetes_service_account" "irsa_demo" {
  count = local.irsa_enabled ? 1 : 0

  metadata {
    name      = var.irsa_demo_service_account_name
    namespace = var.capability_test_namespace
    annotations = {
      "eks.amazonaws.com/role-arn" = aws_iam_role.irsa_demo[0].arn
    }
  }

  depends_on = [
    kubernetes_namespace.cap_test,
    aws_iam_role.irsa_demo,
  ]
}

resource "kubernetes_deployment" "irsa_demo" {
  count = local.irsa_enabled ? 1 : 0

  metadata {
    name      = "cap-test-irsa-demo"
    namespace = var.capability_test_namespace
    labels    = { "app.kubernetes.io/name" = "cap-test-irsa-demo" }
  }

  spec {
    replicas = 1
    selector {
      match_labels = { "app.kubernetes.io/name" = "cap-test-irsa-demo" }
    }
    template {
      metadata {
        labels = { "app.kubernetes.io/name" = "cap-test-irsa-demo" }
      }
      spec {
        service_account_name = var.irsa_demo_service_account_name
        container {
          name  = "main"
          image = var.capability_test_pause_image
        }
      }
    }
  }

  depends_on = [
    kubernetes_namespace.cap_test,
    kubernetes_service_account.irsa_demo,
  ]
}
