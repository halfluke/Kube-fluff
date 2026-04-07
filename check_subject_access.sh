#!/usr/bin/env bash
set -euo pipefail

# Example usage:
#   ./check_subject_access.sh --kind user --name alice --groups "team-dev,team-ops" --output both
#   ./check_subject_access.sh --kind serviceaccount --name default --namespace app-ns --output json
#   SUBJECT_GROUPS="team-dev team-ops" ./check_subject_access.sh --kind user --name alice

OUTPUT_MODE="human"
SUBJECT_KIND=""
SUBJECT_NAME=""
SUBJECT_NAMESPACE=""
GROUPS_INPUT="${SUBJECT_GROUPS:-}"
NO_PROMPT=0
KCTL=""

usage() {
  cat <<'EOF'
Usage:
  check_subject_access.sh [options]

Options:
  --kind <user|group|serviceaccount>
  --name <subject-name>
  --namespace <namespace>          Required only for serviceaccount when --name is not ns/name
  --groups "<g1,g2>"               Optional effective groups for user/serviceaccount
  --output <human|json|both>       Default: human
  --no-prompt                      Fail instead of prompting for missing input
  -h, --help
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --kind) SUBJECT_KIND="${2:-}"; shift 2 ;;
    --name) SUBJECT_NAME="${2:-}"; shift 2 ;;
    --namespace) SUBJECT_NAMESPACE="${2:-}"; shift 2 ;;
    --groups) GROUPS_INPUT="${2:-}"; shift 2 ;;
    --output) OUTPUT_MODE="${2:-}"; shift 2 ;;
    --no-prompt) NO_PROMPT=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Error: Unknown option '$1'"; usage; exit 2 ;;
  esac
done

normalize_kind() {
  local raw="${1,,}"
  case "$raw" in
    user|users) echo "User" ;;
    group|groups) echo "Group" ;;
    serviceaccount|serviceaccounts|sa) echo "ServiceAccount" ;;
    *) echo "" ;;
  esac
}

pick_client() {
  if command -v oc >/dev/null 2>&1; then
    echo "oc"
    return
  fi
  if command -v kubectl >/dev/null 2>&1; then
    echo "kubectl"
    return
  fi
  echo ""
}

if [[ -z "$SUBJECT_KIND" && $NO_PROMPT -eq 0 ]]; then
  read -r -p "Enter subject kind (User, Group, ServiceAccount): " SUBJECT_KIND
fi
if [[ -z "$SUBJECT_NAME" && $NO_PROMPT -eq 0 ]]; then
  read -r -p "Enter subject name (for ServiceAccount can be ns/name): " SUBJECT_NAME
fi
if [[ -z "$GROUPS_INPUT" && $NO_PROMPT -eq 0 ]]; then
  read -r -p "Optional groups for effective access (comma/space separated, leave blank for none): " GROUPS_INPUT
fi

CANON_KIND="$(normalize_kind "$SUBJECT_KIND")"
if [[ -z "$CANON_KIND" ]]; then
  echo "Error: Invalid subject kind '$SUBJECT_KIND'. Use User, Group, or ServiceAccount." >&2
  exit 2
fi
if [[ -z "$SUBJECT_NAME" ]]; then
  echo "Error: Subject name cannot be empty." >&2
  exit 2
fi
if [[ ! "$OUTPUT_MODE" =~ ^(human|json|both)$ ]]; then
  echo "Error: --output must be one of human, json, or both." >&2
  exit 2
fi

if [[ "$CANON_KIND" == "ServiceAccount" ]]; then
  if [[ "$SUBJECT_NAME" == */* ]]; then
    SUBJECT_NAMESPACE="${SUBJECT_NAME%%/*}"
    SUBJECT_NAME="${SUBJECT_NAME#*/}"
  fi
  if [[ -z "$SUBJECT_NAMESPACE" ]]; then
    if [[ $NO_PROMPT -eq 0 ]]; then
      read -r -p "Enter ServiceAccount namespace: " SUBJECT_NAMESPACE
    fi
  fi
  if [[ -z "$SUBJECT_NAMESPACE" ]]; then
    echo "Error: ServiceAccount requires namespace (via --namespace or ns/name)." >&2
    exit 2
  fi
else
  SUBJECT_NAMESPACE="-"
fi

GROUPS_JSON="$(printf "%s" "$GROUPS_INPUT" \
  | tr ',;' '  ' \
  | tr -s '[:space:]' '\n' \
  | sed '/^$/d' \
  | sort -u \
  | jq -R . \
  | jq -s .)"

KCTL="$(pick_client)"
if [[ -z "$KCTL" ]]; then
  echo "Error: Neither oc nor kubectl is available in PATH." >&2
  exit 2
fi
if ! "$KCTL" cluster-info >/dev/null 2>&1; then
  echo "Error: $KCTL is not authenticated or cluster is unreachable." >&2
  exit 2
fi

echo "--- OpenShift Effective Subject Access Verifier ---"
echo "Client: $KCTL"
echo "Subject: $CANON_KIND/$SUBJECT_NAME (namespace: $SUBJECT_NAMESPACE)"

TMP_DIR="$(mktemp -d)"
cleanup() {
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

"$KCTL" get clusterrolebinding -o json > "$TMP_DIR/crb.json"
"$KCTL" get rolebinding -A -o json > "$TMP_DIR/rb.json"
"$KCTL" get clusterrole -o json > "$TMP_DIR/cr.json"
"$KCTL" get role -A -o json > "$TMP_DIR/r.json"

EFFECTIVE_SUBJECTS_FILE="$TMP_DIR/effective_subjects.json"
jq -n \
  --arg kind "$CANON_KIND" \
  --arg name "$SUBJECT_NAME" \
  --arg ns "$SUBJECT_NAMESPACE" \
  --argjson groups "$GROUPS_JSON" '
  def uniq_subjects: unique_by(.kind + "|" + .name + "|" + .namespace);
  (
    [{kind:$kind, name:$name, namespace:$ns}] +
    ($groups | map({kind:"Group", name:., namespace:"-"}))
  ) | uniq_subjects
' > "$EFFECTIVE_SUBJECTS_FILE"

GRANTS_FILE="$TMP_DIR/grants.json"
jq -n \
  --slurpfile crb "$TMP_DIR/crb.json" \
  --slurpfile rb "$TMP_DIR/rb.json" \
  --slurpfile subjects "$EFFECTIVE_SUBJECTS_FILE" '
  def subj_ns($s): ($s.namespace // "-");
  def subject_match($sub):
    any($subjects[0][]; .kind == $sub.kind and .name == $sub.name and .namespace == subj_ns($sub));

  (
    [
      $crb[0].items[]? as $b
      | $b.subjects[]? as $s
      | select(subject_match($s))
      | {
          bindingKind: "ClusterRoleBinding",
          bindingName: $b.metadata.name,
          bindingNamespace: "cluster",
          roleRefKind: $b.roleRef.kind,
          roleRefName: $b.roleRef.name,
          matchedSubject: {kind:$s.kind, name:$s.name, namespace:subj_ns($s)}
        }
    ] +
    [
      $rb[0].items[]? as $b
      | $b.subjects[]? as $s
      | select(subject_match($s))
      | {
          bindingKind: "RoleBinding",
          bindingName: $b.metadata.name,
          bindingNamespace: ($b.metadata.namespace // "-"),
          roleRefKind: $b.roleRef.kind,
          roleRefName: $b.roleRef.name,
          matchedSubject: {kind:$s.kind, name:$s.name, namespace:subj_ns($s)}
        }
    ]
  ) | unique_by(
    .bindingKind + "|" + .bindingName + "|" + .bindingNamespace + "|" +
    .roleRefKind + "|" + .roleRefName + "|" +
    .matchedSubject.kind + "|" + .matchedSubject.name + "|" + .matchedSubject.namespace
  )
' > "$GRANTS_FILE"

ENRICHED_GRANTS_FILE="$TMP_DIR/enriched_grants.json"
jq -n \
  --slurpfile grants "$GRANTS_FILE" \
  --slurpfile cr "$TMP_DIR/cr.json" \
  --slurpfile r "$TMP_DIR/r.json" '
  [
    $grants[0][] as $g
    | $g + (
        if $g.roleRefKind == "ClusterRole" then
          {
            resolvedRoleKind: "ClusterRole",
            resolvedRoleName: $g.roleRefName,
            resolvedRoleNamespace: "cluster",
            rules: (
              [ $cr[0].items[]? | select(.metadata.name == $g.roleRefName) | .rules ] | first // []
            ),
            roleMissing: (
              ([ $cr[0].items[]? | select(.metadata.name == $g.roleRefName) ] | length) == 0
            )
          }
        else
          {
            resolvedRoleKind: "Role",
            resolvedRoleName: $g.roleRefName,
            resolvedRoleNamespace: $g.bindingNamespace,
            rules: (
              [
                $r[0].items[]?
                | select(.metadata.namespace == $g.bindingNamespace and .metadata.name == $g.roleRefName)
                | .rules
              ] | first // []
            ),
            roleMissing: (
              ([
                $r[0].items[]?
                | select(.metadata.namespace == $g.bindingNamespace and .metadata.name == $g.roleRefName)
              ] | length) == 0
            )
          }
        end
      )
  ]
' > "$ENRICHED_GRANTS_FILE"

RESULT_FILE="$TMP_DIR/result.json"
jq -n \
  --arg kind "$CANON_KIND" \
  --arg name "$SUBJECT_NAME" \
  --arg namespace "$SUBJECT_NAMESPACE" \
  --arg output "$OUTPUT_MODE" \
  --slurpfile effectiveSubjects "$EFFECTIVE_SUBJECTS_FILE" \
  --slurpfile grants "$ENRICHED_GRANTS_FILE" '
  def has_verb($rule; $verbs):
    any($rule.verbs[]?; . == "*" or (. as $v | any($verbs[]; . == $v)));
  def has_resource($rule; $resources):
    any($rule.resources[]?; . == "*" or (. as $r | any($resources[]; . == $r)));

  def findings_for_grant($g):
    [
      (if $g.roleRefKind == "ClusterRole" and $g.roleRefName == "cluster-admin" then
        {
          severity:"critical",
          reasonCode:"cluster_admin_binding",
          message:"Direct or effective binding to cluster-admin.",
          grant:$g
        }
      else empty end),
      (
        $g.rules[]? as $rule
        | (if has_verb($rule; ["*"]) and has_resource($rule; ["*"]) then
            {
              severity:"critical",
              reasonCode:"wildcard_all",
              message:"Role grants wildcard verbs and wildcard resources.",
              grant:$g
            }
          else empty end),
        (if has_verb($rule; ["bind"]) and has_resource($rule; ["clusterroles","roles","clusterrolebindings","rolebindings"]) then
            {
              severity:"critical",
              reasonCode:"rbac_bind",
              message:"Role can bind RBAC roles/bindings.",
              grant:$g
            }
          else empty end),
        (if has_verb($rule; ["escalate"]) and has_resource($rule; ["clusterroles","roles"]) then
            {
              severity:"critical",
              reasonCode:"rbac_escalate",
              message:"Role can escalate RBAC privileges.",
              grant:$g
            }
          else empty end),
        (if has_verb($rule; ["impersonate"]) and has_resource($rule; ["users","groups","serviceaccounts","userextras"]) then
            {
              severity:"critical",
              reasonCode:"impersonate_broad",
              message:"Role can impersonate identities.",
              grant:$g
            }
          else empty end),
        (if has_verb($rule; ["get","list","watch"]) and has_resource($rule; ["secrets"]) then
            {
              severity:"high",
              reasonCode:"secrets_read",
              message:"Role can read secrets.",
              grant:$g
            }
          else empty end),
        (if has_verb($rule; ["create","update","patch","delete"]) and has_resource($rule; ["validatingwebhookconfigurations","mutatingwebhookconfigurations"]) then
            {
              severity:"high",
              reasonCode:"webhook_mutation",
              message:"Role can mutate admission webhook configuration.",
              grant:$g
            }
          else empty end),
        (if has_verb($rule; ["create","update","patch","delete"]) and has_resource($rule; ["roles","clusterroles","rolebindings","clusterrolebindings"]) then
            {
              severity:"high",
              reasonCode:"rbac_write",
              message:"Role can modify RBAC objects.",
              grant:$g
            }
          else empty end),
        (if has_verb($rule; ["get","list","watch","patch","update"]) and has_resource($rule; ["nodes"]) then
            {
              severity:"high",
              reasonCode:"node_access",
              message:"Role can access or modify nodes.",
              grant:$g
            }
          else empty end)
      )
    ];

  (
    [ $grants[0][] as $g | findings_for_grant($g)[] ]
    | unique_by(.reasonCode + "|" + .grant.bindingKind + "|" + .grant.bindingName + "|" + .grant.resolvedRoleKind + "|" + .grant.resolvedRoleName + "|" + .grant.matchedSubject.kind + "|" + .grant.matchedSubject.name + "|" + .grant.matchedSubject.namespace)
  ) as $findings
  |
  {
    input: {
      kind: $kind,
      name: $name,
      namespace: $namespace,
      outputMode: $output
    },
    effectiveSubjects: $effectiveSubjects[0],
    grants: $grants[0],
    findings: $findings,
    summary: {
      effectiveSubjectCount: ($effectiveSubjects[0] | length),
      grantCount: ($grants[0] | length),
      findingCount: ($findings | length),
      hasHighRisk: (($findings | length) > 0)
    }
  }
' > "$RESULT_FILE"

RESULT_JSON="$(<"$RESULT_FILE")"

print_human() {
  local json="$1"
  echo "--------------------------------------------------"
  echo "Effective subjects:"
  echo "$json" | jq -r '.effectiveSubjects[] | "  - \(.kind)/\(.name) (ns: \(.namespace))"'
  echo

  local grant_count
  grant_count="$(echo "$json" | jq -r '.summary.grantCount')"
  echo "Matched grants: $grant_count"
  if [[ "$grant_count" -gt 0 ]]; then
    echo "$json" | jq -r '.grants[] | "  - \(.bindingKind)/\(.bindingName) -> \(.resolvedRoleKind)/\(.resolvedRoleName) (binding-ns: \(.bindingNamespace), matched: \(.matchedSubject.kind)/\(.matchedSubject.name))"'
  fi
  echo

  local finding_count
  finding_count="$(echo "$json" | jq -r '.summary.findingCount')"
  if [[ "$finding_count" -eq 0 ]]; then
    echo "SUMMARY: No high-privileged access patterns detected for this effective subject set."
  else
    echo "Findings:"
    echo "$json" | jq -r '.findings[] | "  - [\(.severity | ascii_upcase)] \(.reasonCode): \(.message)\n      via \(.grant.bindingKind)/\(.grant.bindingName) -> \(.grant.resolvedRoleKind)/\(.grant.resolvedRoleName) (matched: \(.grant.matchedSubject.kind)/\(.grant.matchedSubject.name))"'
    echo
    echo "SUMMARY: High-privileged access detected."
  fi
}

case "$OUTPUT_MODE" in
  human)
    print_human "$RESULT_JSON"
    ;;
  json)
    echo "$RESULT_JSON" | jq .
    ;;
  both)
    print_human "$RESULT_JSON"
    echo
    echo "--- JSON ---"
    echo "$RESULT_JSON" | jq .
    ;;
esac

if [[ "$(echo "$RESULT_JSON" | jq -r '.summary.hasHighRisk')" == "true" ]]; then
  exit 1
fi
exit 0
