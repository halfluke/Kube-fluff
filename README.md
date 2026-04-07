# Kube-fluff

**Testing disclaimer:** These scripts have been exercised **only in local Kubernetes environments** and, **partially**, on **OpenShift** (an **earlier** version of the repo). They have **not** yet been fully validated on **AKS, EKS, or GKE**; **planned** testing on those platforms is expected **within a reasonable timeframe**. Treat cloud-specific paths and Terraform stacks accordingly.

Shell-based **Kubernetes security audits** focused on **RBAC** and **workload security posture** (PSA labels, pod security context, Linux capabilities, and cloud-specific identity hints). Optional **Terraform** stacks provision short-lived clusters and apply test fixtures.

These tools are intended for **analysis, education, and lab environments**. They do not replace cloud IAM reviews, admission controllers, or organizational policy.

---

## What the scripts do

### RBAC audit scripts

| Script | Target | Scope |
|--------|--------|--------|
| `Vanilla-RBAC.sh` | Local / lab Kubernetes (kubectl) | Checks **1–19**: core RBAC plus token minting, enhanced wildcards, sensitive subresources, CRD heuristics, default-SA bindings, workload cross-reference; **no** provider IAM |
| `EKS-rbac.sh` | EKS-oriented cluster | Full check catalogue including EKS **`aws-auth`** scan (Check 2) and IRSA demo support in Terraform |
| `GKE-rbac.sh` | GKE-oriented cluster | Full catalogue + optional **GCP cluster IAM** (Check 2) + GKE Workload Identity (Check 22) |
| `AKS-rbac.sh` | AKS-oriented cluster | Full catalogue + optional **Azure RBAC on the cluster resource** (Check 2) + Azure WI (Check 22) |
| `OpenShift-RBAC.sh` | OpenShift | Same CLI style as Vanilla-RBAC; uses **`oc`**; OpenShift-focused namespace defaults |

RBAC scripts answer: **who can perform high-risk API actions** (cluster-admin, secrets, exec, token minting, wildcards, CRD exposure heuristics, etc.). Each script documents semantics in its file header (bindings, `via =/≠`, excluded namespaces).

**Vanilla-RBAC.sh and the API:** When you run checks **3–19** or a full audit (no `--checks`), the script **prefetches once** per run: ClusterRoleBindings, all RoleBindings, and combined ClusterRoles/Roles. Most checks reuse that JSON (including `check_permission` and subject resolution), which avoids repeated full list calls. **`--checks=1` and/or `2` only** skips that prefetch. Check **19** still calls workload APIs to read ServiceAccount names on pods and controllers; its cluster/namespace summary **counts** use `kubectl get … --no-headers` style listing instead of pulling full resource JSON for totals.

**Cloud “Check 2” notes (read the script headers):**

- **EKS:** Reads **`kube-system/aws-auth`** for `mapRoles` / `mapUsers` entries mapping to **`system:masters`**. Not a full AWS/EKS access audit (e.g. Access Entry APIs, IRSA, node IAM).
- **GKE:** Uses **`gcloud container clusters get-iam-policy`** on the **cluster resource** for `roles/container.clusterAdmin` and `roles/container.admin`. Parent project/folder/org bindings may not appear.
- **AKS:** Uses **`az role assignment list`** at the **managed cluster ARM scope** (and CLI-specific `--all` behavior). Not a complete map of Azure paths to cluster admin.

When Check 2 runs, the scripts print a short **scope line** (unless `--quiet`) so operators know what is included.

### Container capabilities / PSA scripts

| Script | Target | Notes |
|--------|--------|--------|
| `Vanilla-ContainerCapabilities.sh` | Generic Kubernetes | PSA labels + pod spec; **no** cloud identity column |
| `EKS-ContainerCapabilities.sh` | EKS | + **IRSA** role ARN hint (pod or ServiceAccount) |
| `GKE-ContainerCapabilities.sh` | GKE | + **GKE Workload Identity** annotation; optional Autopilot `[INFO]` |
| `AKS-ContainerCapabilities.sh` | AKS | + **Azure Workload Identity** client-id; optional AKS node `[INFO]` |
| `OpenShift-ContainerCapabilities.sh` | OpenShift | **SCC**-aware flow; uses **`oc`** and a bundled **`./jq-linux-amd64`**; different flags (`--scc-matching`) |

These scripts inspect **declared** pod/namespace state. They are **not** full admission-controller or runtime-enforcement audits; each run prints an `[INFO]` line stating that (and that cloud identity columns are in-cluster hints, not cloud IAM).

---

## Node port exposure script

`ControlPlane_WorkerNodes_fromAllPods.sh` probes node ports from all running pods and reports whether access is blocked, auth-gated, or exposed.

- CLI behavior: uses `oc` when available, otherwise falls back to `kubectl`.
- Requirements: `jq`, `curl`, and `timeout`. Source pods that do not have `curl` and `timeout` are skipped.
- Runtime modes:
  - `full`: control-plane nodes are visible; runs control-plane + worker checks.
  - `worker_only`: control-plane nodes are hidden/unavailable (common in AKS/EKS/GKE); runs worker checks and prints a CP-skipped notice.
- Default ports:
  - secure/API endpoints: `2379`, `10250`, `10257`, `10259`
  - insecure kubelet read-only endpoint: `10255`
- Port behavior by mode:
  - `full`: tests `2379`, `10250`, `10257`, `10259` on control-plane nodes, `10250` on worker nodes, and `10255` on all discovered nodes.
  - `worker_only`: skips control-plane-only checks (`2379`, `10257`, `10259`), tests `10250` and `10255` on discovered worker nodes.
- etcd probe detail:
  - `2379` is tested using unauthenticated etcd v3 API request to `/v3/maintenance/status` (not `/`) for more reliable exposure detection.
- Output format:
  - `SRC_NS | SRC_POD | HOSTNETWORK | SERVICEACCOUNT | NETPOL_NS_COUNT | NETPOL_MATCH | DEST_ROLE | DEST_IP | PORT | STATUS | DETAILS`
- Per-pod context:
  - `HOSTNETWORK`: whether the pod uses `hostNetwork: true`.
  - `SERVICEACCOUNT`: pod service account name.
  - `NETPOL_NS_COUNT`: total NetworkPolicies in the pod namespace.
  - `NETPOL_MATCH`: policies whose `podSelector` structurally matches pod labels.
  - NetworkPolicy context uses Kubernetes native `networking.k8s.io/v1` `NetworkPolicy` only and is selector-based metadata, not a full enforcement proof across all CNI-specific controls.
- Status meanings:
  - `EXPOSED`: unauthenticated access succeeded (highest risk).
  - `AUTH_REQUIRED`: endpoint reachable but requires authentication/authorization.
  - `DENIED_WITHOUT_CREDS`: endpoint reachable but denied by TLS/auth/path constraints.
  - `BLOCKED_OR_UNREACHABLE`: network blocked, timed out, or no route.
  - `TEST_ERROR`: probe could not complete reliably (missing tools, exec failure, ambiguous transport failure).
  - `SKIPPED`: source pod missing required probe tools (`curl` and/or `timeout`), so no probes were attempted from that pod.
- Exit/status mapping (how statuses are determined):
  - `BLOCKED_OR_UNREACHABLE`: curl/timeout exit code in `{6,7,28,124}`.
  - `DENIED_WITHOUT_CREDS`: curl exit code in `{35,51,52,56,58,60}` or HTTP `400/404` during auth probe stage.
  - `TEST_ERROR`: other probe/exec failures or ambiguous transport failures.
- Risk highlighting:
  - `EXPOSED` findings are wrapped by:
    - `=========ALERT=========`
    - `<result line>`
    - `=========ALERT=========`

---

## Subject access verifier script

`check_subject_access.sh` evaluates effective RBAC exposure for a specific subject (`User`, `Group`, or `ServiceAccount`) and flags high-risk privilege patterns.

- CLI behavior: uses `oc` when available, otherwise falls back to `kubectl`.
- Inputs:
  - `--kind <user|group|serviceaccount>`
  - `--name <subject-name>` (for service accounts, supports `ns/name`)
  - optional `--namespace`, `--groups`, `--output <human|json|both>`, `--no-prompt`
- What it does:
  - builds effective subject set (direct subject + optional groups)
  - resolves matching `ClusterRoleBinding` and `RoleBinding` grants
  - resolves referenced `ClusterRole`/`Role` rules
  - emits findings for high-risk patterns (for example: `cluster-admin`, wildcard all, `bind`, `escalate`, impersonation, secret read, RBAC writes, node access)
- Output/exit behavior:
  - prints human-readable and/or JSON result set with findings summary
  - exits `1` when high-risk findings are present, `0` otherwise

---

## Endpoint connectivity sweep script

`network_segreg_via_endpoints.sh` performs namespace-to-endpoint connectivity checks by selecting one running curl-capable source pod per namespace, then probing discovered service endpoints.

- CLI behavior: uses `oc` when available, otherwise falls back to `kubectl`.
- Discovery model:
  - source pods: one exec-capable pod with `curl` per namespace
  - targets: EndpointSlice API first, then Endpoints API fallback
- Probe model:
  - HTTP connectivity checks to each `endpointIP:port` using timeout-based `curl`
  - per-source-pod result table plus cluster-wide summary counters
- Notable outputs:
  - `SUCCESS`, `TIMED OUT`, `CONNECTION REFUSED/BAD RESPONSE`, `RECV FAILURE`, `UNKNOWN FAILURE`
  - skipped namespaces list when no curl-capable source pod is available

---

## Requirements

### On your workstation

- **Bash** (scripts use `#!/usr/bin/env bash` or `#!/bin/bash`).
- **`kubectl`** on `PATH` for all scripts **except** OpenShift variants (those use **`oc`**).
- **`jq`** on `PATH` for JSON parsing (RBAC + most capabilities scripts).

### Optional (by script / check)

| Need | Used for |
|------|-----------|
| **AWS CLI** | `aws eks update-kubeconfig` (EKS); EKS Terraform kubernetes provider exec |
| **Google Cloud SDK (`gcloud`)** | Cluster credentials; **GKE-rbac.sh Check 2** (`GKE_*` env vars) |
| **Azure CLI (`az`)** | Cluster credentials; **AKS-rbac.sh Check 2** (`AKS_*` env vars) |
| **`terraform`** | Provisioning lab clusters and fixtures under `terraform/` |

### Kubernetes access

- A **kubeconfig** with a context that can **list namespaces** and **read** RBAC and workload objects (exact verbs depend on your role). The capabilities scripts fail early if `kubectl get ns` fails.

### OpenShift-only

- **`oc`** authenticated to the cluster (`OC` env var overrides the binary path; default `oc`).
- **`OpenShift-ContainerCapabilities.sh`:** expects **`./jq-linux-amd64`** in the repo directory (as noted in the script).

---

## How to run (from repository root)

```bash
cd /path/to/Kube-fluff
chmod +x *.sh   # once, if needed
```

### RBAC scripts

```bash
./Vanilla-RBAC.sh --help
./Vanilla-RBAC.sh --quiet
./Vanilla-RBAC.sh --list-checks
./Vanilla-RBAC.sh --checks=1,3-5
```

The same flag style applies to **`EKS-rbac.sh`**, **`GKE-rbac.sh`**, **`AKS-rbac.sh`**, and **`OpenShift-RBAC.sh`**: `--checks`, `--list` / `--list-checks`, `--quiet`, `--critical`, `--debug-check20`, `--debug-check21`, `-h` / `--help`. **`Vanilla-RBAC.sh`** uses **`--debug-check18`** / **`--debug-check19`** for its workload-binding diagnostics (see `--help`).

**Override kubectl binary (RBAC scripts that use `K=`):**

```bash
K=/path/to/kubectl ./EKS-rbac.sh --quiet
```

**OpenShift RBAC** uses **`oc`**:

```bash
OC=/path/to/oc ./OpenShift-RBAC.sh --quiet
```

**Optional Check 2 environment variables**

- **GKE:** `GKE_PROJECT`, `GKE_CLUSTER_NAME`, `GKE_LOCATION` (region or zone matching your cluster type).
- **AKS:** `AKS_RESOURCE_GROUP`, `AKS_CLUSTER_NAME`, optional `AKS_SUBSCRIPTION_ID` (else active `az account`).

### Container capabilities scripts

```bash
./Vanilla-ContainerCapabilities.sh
./Vanilla-ContainerCapabilities.sh --only-user-ns --output text
./EKS-ContainerCapabilities.sh --output json
```

Flags: `--only-user-ns`, `--output text|csv|json`, `--debug` (where supported). **`OpenShift-ContainerCapabilities.sh`** also supports `--scc-matching v1|v2` (see script header).

---

## Terraform lab stacks

Under **`terraform/`**, each directory is a **standalone** root module (run commands from that directory).

| Directory | Creates cluster? | Purpose |
|-----------|------------------|---------|
| `terraform/eks/` | Yes (EKS + VPC) | Fixtures for `EKS-rbac.sh`, `EKS-ContainerCapabilities.sh`; optional IRSA demo |
| `terraform/gke/` | Yes (GKE) | Fixtures for `GKE-rbac.sh`, `Vanilla-ContainerCapabilities.sh` |
| `terraform/aks/` | Yes (AKS) | Fixtures for `AKS-rbac.sh`, `AKS-ContainerCapabilities.sh` |
| `terraform/local-vanilla/` | No | Applies fixtures to **existing** cluster via kubeconfig |

Typical workflow:

```bash
cd terraform/<stack>
cp terraform.tfvars.example terraform.tfvars   # if present; edit values
terraform init
terraform apply
terraform output -raw configure_kubectl        # or get_credentials / equivalent
cd ../..
./<Matching-rbac-script>.sh --quiet
```

- **`terraform.tfvars`** is gitignored; use `*.example` files as templates.
- See each stack’s **`outputs.tf`** for copy-paste **`run_rbac_audit`** / **`run_container_capabilities_audit`** examples (including exports for GKE/AKS Check 2).

---

## Limitations (summary)

- RBAC audits reflect **Kubernetes RBAC** (plus the **documented** cloud slices for Check 2 on GKE/AKS, and **aws-auth** on EKS). They are not complete cloud IAM inventories.
- Capabilities scripts use **pod spec + namespace labels**, not live admission results.
- Terraform configs are for **labs** (e.g. single-node pools, permissive test namespaces). Harden before production use.

For full behavior, semantics, and check IDs, use **`--help`** and **`--list-checks`** on each RBAC script and read the **header comments** at the top of each file.
