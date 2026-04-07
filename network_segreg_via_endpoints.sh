#!/bin/bash
set -euo pipefail

# --- Configuration ---
TIMEOUT=3
CONNECT_TIMEOUT=3
OUTPUT_MODE="human"
NAMESPACE_FILTER_RAW=""
# --- End Configuration ---

usage() {
    cat <<'EOF'
Usage:
  network_segreg_via_endpoints.sh [options]

Options:
  --namespaces ns1,ns2      Restrict source namespaces
  --output human|jsonl      Output mode (default: human)
  --timeout N               Probe timeout seconds (default: 3)
  --connect-timeout N       curl connect timeout seconds (default: 3)
  -h, --help                Show help
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --namespaces) NAMESPACE_FILTER_RAW="${2:-}"; shift 2 ;;
        --output) OUTPUT_MODE="${2:-}"; shift 2 ;;
        --timeout) TIMEOUT="${2:-}"; shift 2 ;;
        --connect-timeout) CONNECT_TIMEOUT="${2:-}"; shift 2 ;;
        -h|--help) usage; exit 0 ;;
        *) echo "Error: Unknown option '$1'"; usage; exit 2 ;;
    esac
done

if [[ ! "$OUTPUT_MODE" =~ ^(human|jsonl)$ ]]; then
    echo "Error: --output must be human or jsonl"
    exit 2
fi

declare -A STATUS_COUNTS
declare -A PORT_STATUS_COUNTS
TOTAL_NAMESPACES_CONSIDERED=0
TOTAL_NAMESPACES_TESTED=0
TOTAL_NAMESPACES_SKIPPED=0
UNKNOWN_POLICY_CRD_GROUPS="-"

if command -v oc >/dev/null 2>&1; then
    KUBE_CLI="oc"
elif command -v kubectl >/dev/null 2>&1; then
    KUBE_CLI="kubectl"
else
    echo "ERROR: Neither 'oc' nor 'kubectl' was found in PATH."
    exit 1
fi

if ! command -v jq >/dev/null 2>&1; then
    echo "ERROR: 'jq' is required but not found in PATH."
    exit 1
fi

echo "Using CLI: $KUBE_CLI"
echo "How this script works: for each namespace, it tries to find one running pod that allows exec and has curl, then uses each selected source pod to test all endpoint IP:port targets in the cluster."
echo "Timeout option: each check uses timeout=$TIMEOUT seconds (timeout + curl -m). Increase it for slower clusters; decrease it for faster sweeps."
echo "Discovering one exec-capable curl pod per namespace..."

set +e
NATIVE_NETPOL_JSON=$("$KUBE_CLI" get networkpolicy -A -o json 2>/dev/null)
NATIVE_NETPOL_RC=$?
CALICO_NS_JSON=$("$KUBE_CLI" get networkpolicies.crd.projectcalico.org -A -o json 2>/dev/null)
CALICO_NS_RC=$?
CALICO_GLOBAL_JSON=$("$KUBE_CLI" get globalnetworkpolicies.crd.projectcalico.org -o json 2>/dev/null)
CALICO_GLOBAL_RC=$?
CILIUM_NS_JSON=$("$KUBE_CLI" get ciliumnetworkpolicies.cilium.io -A -o json 2>/dev/null)
CILIUM_NS_RC=$?
CILIUM_CLUSTER_JSON=$("$KUBE_CLI" get ciliumclusterwidenetworkpolicies.cilium.io -o json 2>/dev/null)
CILIUM_CLUSTER_RC=$?
CRD_JSON=$("$KUBE_CLI" get crd -o json 2>/dev/null)
CRD_RC=$?
set -e

if [[ $NATIVE_NETPOL_RC -ne 0 ]]; then NATIVE_NETPOL_JSON='{"items":[]}'; fi
if [[ $CALICO_NS_RC -ne 0 ]]; then CALICO_NS_JSON='{"items":[]}'; fi
if [[ $CALICO_GLOBAL_RC -ne 0 ]]; then CALICO_GLOBAL_JSON='{"items":[]}'; fi
if [[ $CILIUM_NS_RC -ne 0 ]]; then CILIUM_NS_JSON='{"items":[]}'; fi
if [[ $CILIUM_CLUSTER_RC -ne 0 ]]; then CILIUM_CLUSTER_JSON='{"items":[]}'; fi
if [[ $CRD_RC -ne 0 ]]; then CRD_JSON='{"items":[]}'; fi

if [[ $CRD_RC -eq 0 ]]; then
    UNKNOWN_POLICY_CRD_GROUPS=$(printf "%s" "$CRD_JSON" | jq -r '
      [
        .items[]
        | {n:(.metadata.name // ""), g:(.spec.group // "")}
        | select((.n|test("networkpolic|policy|egress|ingress";"i")) or (.g|test("policy|network";"i")))
        | .g
        | select(. != "networking.k8s.io" and . != "policy.networking.k8s.io" and . != "projectcalico.org" and . != "cilium.io")
        | select(endswith(".projectcalico.org") | not)
        | select(endswith(".cilium.io") | not)
      ] | unique | if length==0 then "-" else join(",") end
    ')
fi

emit_row() {
    local source_namespace="$1" source_pod="$2" source_host_network="$3" source_service_account="$4" native_netpol_count="$5" native_netpol_match="$6" source_policy_engine="$7" plugin_count="$8" source_plugin_refs="$9" dest_namespace="${10}" service_name="${11}" dest_ip="${12}" dest_port="${13}" exit_code="${14}" status="${15}" details="${16}"
    STATUS_COUNTS["$status"]=$(( ${STATUS_COUNTS["$status"]:-0} + 1 ))
    if [[ "$dest_port" != "-" ]]; then
        PORT_STATUS_COUNTS["$dest_port|$status"]=$(( ${PORT_STATUS_COUNTS["$dest_port|$status"]:-0} + 1 ))
    fi
    if [[ "$OUTPUT_MODE" == "jsonl" ]]; then
        jq -cn --arg source_namespace "$source_namespace" --arg source_pod "$source_pod" --arg hostNetwork "$source_host_network" --arg serviceAccount "$source_service_account" --arg netpol_ns_count "$native_netpol_count" --arg netpol_match "$native_netpol_match" --arg policy_engine "$source_policy_engine" --arg plugin_policy_count "$plugin_count" --arg plugin_policy_refs "$source_plugin_refs" --arg dest_namespace "$dest_namespace" --arg service_name "$service_name" --arg dest_ip "$dest_ip" --arg dest_port "$dest_port" --arg exit_code "$exit_code" --arg status "$status" --arg details "$details" --arg risk "$([[ "$status" == "EXPOSED" ]] && echo true || echo false)" '{source_namespace:$source_namespace,source_pod:$source_pod,hostNetwork:$hostNetwork,serviceAccount:$serviceAccount,netpol_ns_count:$netpol_ns_count,netpol_match:$netpol_match,policy_engine:$policy_engine,plugin_policy_count:$plugin_policy_count,plugin_policy_refs:$plugin_policy_refs,dest_namespace:$dest_namespace,service_name:$service_name,dest_ip:$dest_ip,dest_port:$dest_port,exit_code:$exit_code,status:$status,details:$details,risk:($risk=="true")}'
    else
        if [[ "$status" == "EXPOSED" ]]; then
            echo "=========ALERT========="
        fi
        printf "%-20s | %-28s | %-15s | %-7s | %-9s | %-22s | %s\n" "$dest_namespace" "$service_name" "$dest_ip" "$dest_port" "$exit_code" "$status" "$details"
        if [[ "$status" == "EXPOSED" ]]; then
            echo "=========ALERT========="
        fi
    fi
}

SOURCE_MAP_FILE="$(mktemp)"
SKIPPED_FILE="$(mktemp)"
ENDPOINTS_FILE="$(mktemp)"

cleanup() {
    rm -f "$SOURCE_MAP_FILE" "$SKIPPED_FILE" "$ENDPOINTS_FILE"
}
trap cleanup EXIT

NAMESPACE_FILTER_REGEX=""
if [[ -n "$NAMESPACE_FILTER_RAW" ]]; then
    NAMESPACE_FILTER_REGEX="$(printf "%s" "$NAMESPACE_FILTER_RAW" | tr ',' '|' )"
fi

PRE_NODE_COUNT=$("$KUBE_CLI" get nodes --no-headers 2>/dev/null | wc -l | tr -d ' ')
if "$KUBE_CLI" cluster-info >/dev/null 2>&1; then PRE_API_HEALTH="ok"; else PRE_API_HEALTH="unreachable"; fi

while read -r namespace; do
    [ -z "$namespace" ] && continue
    TOTAL_NAMESPACES_CONSIDERED=$((TOTAL_NAMESPACES_CONSIDERED + 1))
    if [[ -n "$NAMESPACE_FILTER_REGEX" ]] && [[ ! "$namespace" =~ ^($NAMESPACE_FILTER_REGEX)$ ]]; then
        continue
    fi
    found="false"
    if [[ "$OUTPUT_MODE" == "human" ]]; then
        echo "Looking for source pod in namespace: $namespace"
    fi

    while read -r pod; do
        [ -z "$pod" ] && continue
        if "$KUBE_CLI" exec -n "$namespace" "$pod" -- sh -c 'command -v curl >/dev/null 2>&1 && command -v timeout >/dev/null 2>&1' >/dev/null 2>&1; then
            printf "%s|%s\n" "$namespace" "$pod" >>"$SOURCE_MAP_FILE"
            found="true"
            if [[ "$OUTPUT_MODE" == "human" ]]; then
                echo "  Selected source pod: $pod"
            fi
            break
        fi
    done < <("$KUBE_CLI" get pods -n "$namespace" --field-selector=status.phase=Running -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}')

    if [ "$found" = "false" ]; then
        TOTAL_NAMESPACES_SKIPPED=$((TOTAL_NAMESPACES_SKIPPED + 1))
        if [[ "$OUTPUT_MODE" == "human" ]]; then
            echo "  No exec-capable curl pod found."
        fi
        printf "%s\n" "$namespace" >>"$SKIPPED_FILE"
    else
        TOTAL_NAMESPACES_TESTED=$((TOTAL_NAMESPACES_TESTED + 1))
    fi
done < <("$KUBE_CLI" get ns -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}')

if [ ! -s "$SOURCE_MAP_FILE" ]; then
    echo "ERROR: No namespace has a running pod where exec works and curl is installed."
    exit 1
fi

if [[ "$OUTPUT_MODE" == "human" ]]; then
    echo "Source pods selected:"
    while IFS='|' read -r src_namespace src_pod; do
        printf "  - %s: %s\n" "$src_namespace" "$src_pod"
    done <"$SOURCE_MAP_FILE"
fi

echo "Collecting endpoint targets..."
set +e
"$KUBE_CLI" get endpointslices.discovery.k8s.io -A -o json 2>/dev/null | jq -r '.items[] | .metadata.namespace as $ns | (.metadata.labels."kubernetes.io/service-name" // .metadata.name) as $svc_name | .endpoints[]? as $ep | $ep.addresses[]? as $ip | .ports[]? as $port_data | "\($ns)|\($svc_name)|\($ip)|\($port_data.port)"' >"$ENDPOINTS_FILE"
endpoint_slice_status=$?
set -e

if [ "$endpoint_slice_status" -eq 0 ] && [ -s "$ENDPOINTS_FILE" ]; then
    echo "Collected targets using EndpointSlice API."
else
    echo "Falling back to Endpoints API."
    "$KUBE_CLI" get endpoints -A -o json | jq -r '.items[] | .metadata.namespace as $ns | .metadata.name as $svc_name | .subsets[]? | .addresses[]? as $ip_data | .ports[]? as $port_data | "\($ns)|\($svc_name)|\($ip_data.ip)|\($port_data.port)"' >"$ENDPOINTS_FILE"
fi

if [ ! -s "$ENDPOINTS_FILE" ]; then
    echo "No endpoint IP:port targets were found."
    exit 0
fi

total_tested=0
success_count=0
timeout_count=0
recv_fail_count=0
other_count=0

if [[ "$OUTPUT_MODE" == "human" ]]; then
    echo
    echo "Legend:"
    echo "  EXPOSED: Connection established without auth barrier"
    echo "  BLOCKED_OR_UNREACHABLE: timeout / connect issues"
    echo "  DENIED_WITHOUT_CREDS: TLS/auth-denial style failure"
    echo "  TEST_ERROR: ambiguous or other failure"
    echo "  Pre-check: API=$PRE_API_HEALTH | NODE_COUNT=$PRE_NODE_COUNT"
    echo
else
    jq -cn --arg type "meta" --arg stage "precheck" --arg api "$PRE_API_HEALTH" --arg node_count "$PRE_NODE_COUNT" --arg unknown_policy_crd_groups "$UNKNOWN_POLICY_CRD_GROUPS" '{type:$type,stage:$stage,api:$api,node_count:($node_count|tonumber),unknown_policy_crd_groups:$unknown_policy_crd_groups}'
fi

while IFS='|' read -r source_namespace source_pod; do
    source_pod_json=$("$KUBE_CLI" get pod -n "$source_namespace" "$source_pod" -o json)
    source_host_network=$(printf "%s" "$source_pod_json" | jq -r '.spec.hostNetwork // false')
    source_service_account=$(printf "%s" "$source_pod_json" | jq -r '.spec.serviceAccountName // "default"')
    source_labels=$(printf "%s" "$source_pod_json" | jq -c '.metadata.labels // {}')

    native_netpol_count=$(printf "%s" "$NATIVE_NETPOL_JSON" | jq --arg ns "$source_namespace" '[.items[] | select(.metadata.namespace == $ns)] | length')
    native_netpol_match=$(printf "%s" "$NATIVE_NETPOL_JSON" | jq -r --arg ns "$source_namespace" --argjson labels "$source_labels" '
      def label_match($sel; $labels):
        (($sel.matchLabels // {}) | to_entries | all($labels[.key] == .value)) and
        (($sel.matchExpressions // []) | all(
          if .operator == "In" then (($labels[.key] // null) as $v | ($v != null and ((.values // []) | index($v) != null)))
          elif .operator == "NotIn" then (($labels[.key] // null) as $v | ($v == null or ((.values // []) | index($v) == null)))
          elif .operator == "Exists" then ($labels[.key] != null)
          elif .operator == "DoesNotExist" then ($labels[.key] == null)
          else false
          end
        ));
      [ .items[]
        | select(.metadata.namespace == $ns)
        | select(label_match((.spec.podSelector // {}); $labels))
        | "\(.metadata.namespace)/\(.metadata.name)"
      ] | if length == 0 then "-" else join(",") end
    ')

    plugin_engine_parts=("k8s-native")
    plugin_refs=()
    plugin_count=0

    if [[ $CALICO_NS_RC -eq 0 ]] || [[ $CALICO_GLOBAL_RC -eq 0 ]]; then
        plugin_engine_parts+=("calico")
        calico_ns_count=$(printf "%s" "$CALICO_NS_JSON" | jq --arg ns "$source_namespace" '[.items[] | select(.metadata.namespace == $ns)] | length')
        calico_global_count=$(printf "%s" "$CALICO_GLOBAL_JSON" | jq '[.items[]] | length')
        plugin_count=$((plugin_count + calico_ns_count + calico_global_count))
        if [[ "$calico_ns_count" -gt 0 ]]; then
            calico_ns_refs=$(printf "%s" "$CALICO_NS_JSON" | jq -r --arg ns "$source_namespace" '[.items[] | select(.metadata.namespace == $ns) | "calico-np/\(.metadata.namespace)/\(.metadata.name)"] | join(",")')
            [[ -n "$calico_ns_refs" ]] && plugin_refs+=("$calico_ns_refs")
        fi
        if [[ "$calico_global_count" -gt 0 ]]; then
            calico_global_refs=$(printf "%s" "$CALICO_GLOBAL_JSON" | jq -r '[.items[] | "calico-gnp/\(.metadata.name)"] | join(",")')
            [[ -n "$calico_global_refs" ]] && plugin_refs+=("$calico_global_refs")
        fi
    fi
    if [[ $CILIUM_NS_RC -eq 0 ]] || [[ $CILIUM_CLUSTER_RC -eq 0 ]]; then
        plugin_engine_parts+=("cilium")
        cilium_ns_count=$(printf "%s" "$CILIUM_NS_JSON" | jq --arg ns "$source_namespace" '[.items[] | select(.metadata.namespace == $ns)] | length')
        cilium_cluster_count=$(printf "%s" "$CILIUM_CLUSTER_JSON" | jq '[.items[]] | length')
        plugin_count=$((plugin_count + cilium_ns_count + cilium_cluster_count))
        if [[ "$cilium_ns_count" -gt 0 ]]; then
            cilium_ns_refs=$(printf "%s" "$CILIUM_NS_JSON" | jq -r --arg ns "$source_namespace" '[.items[] | select(.metadata.namespace == $ns) | "cilium-np/\(.metadata.namespace)/\(.metadata.name)"] | join(",")')
            [[ -n "$cilium_ns_refs" ]] && plugin_refs+=("$cilium_ns_refs")
        fi
        if [[ "$cilium_cluster_count" -gt 0 ]]; then
            cilium_cluster_refs=$(printf "%s" "$CILIUM_CLUSTER_JSON" | jq -r '[.items[] | "cilium-ccnp/\(.metadata.name)"] | join(",")')
            [[ -n "$cilium_cluster_refs" ]] && plugin_refs+=("$cilium_cluster_refs")
        fi
    fi

    if [[ $CRD_RC -eq 0 ]]; then
        heuristic_engine_parts=()
        while IFS= read -r grp; do
            [[ -z "$grp" ]] && continue
            if [[ "$grp" == "networking.k8s.io" ]] || [[ "$grp" == "policy.networking.k8s.io" ]] || [[ "$grp" == "projectcalico.org" ]] || [[ "$grp" == "cilium.io" ]] || [[ "$grp" == *.projectcalico.org ]] || [[ "$grp" == *.cilium.io ]]; then
                continue
            fi
            heuristic_engine_parts+=("heuristic:$grp")
        done < <(printf "%s" "$CRD_JSON" | jq -r '
          [
            .items[]
            | {
                n: (.metadata.name // ""),
                g: (.spec.group // "")
              }
            | select(
                (.n | test("networkpolic|policy|egress|ingress"; "i")) or
                (.g | test("policy|network"; "i"))
              )
            | .g
          ] | unique[]?
        ')
        if [[ ${#heuristic_engine_parts[@]} -gt 0 ]]; then
            plugin_engine_parts+=("${heuristic_engine_parts[@]}")
        fi
    fi
    source_policy_engine=$(printf "%s\n" "${plugin_engine_parts[@]}" | jq -R . | jq -s -r 'unique | join(",")')
    if [[ ${#plugin_refs[@]} -eq 0 ]]; then
        source_plugin_refs="-"
    else
        source_plugin_refs=$(printf "%s," "${plugin_refs[@]}" | sed 's/,$//')
    fi

    if [[ "$OUTPUT_MODE" == "human" ]]; then
        echo "======================================================================================="
        echo "Source namespace: $source_namespace"
        echo "Source pod chosen for this test block: $source_pod"
        echo "Source pod context: HOSTNETWORK=$source_host_network | SERVICEACCOUNT=$source_service_account"
        echo "Native NetworkPolicy context: NETPOL_NS_COUNT=$native_netpol_count | NETPOL_MATCH=$native_netpol_match"
        echo "Plugin policy context (additive): POLICY_ENGINE=$source_policy_engine | PLUGIN_POLICY_COUNT=$plugin_count | PLUGIN_POLICY_REFS=$source_plugin_refs"
        printf "%-20s | %-28s | %-15s | %-7s | %-9s | %-22s | %s\n" "DEST_NS" "SERVICE" "DEST_IP" "PORT" "EXIT_CODE" "STATUS" "DETAILS"
        echo "---------------------------------------------------------------------------------------"
    fi

    while IFS='|' read -r dest_namespace service_name dest_ip dest_port; do
        if [ -z "$dest_ip" ] || [ -z "$dest_port" ]; then
            continue
        fi

        set +e
        "$KUBE_CLI" exec -n "$source_namespace" "$source_pod" -- sh -c "timeout $TIMEOUT curl -s -o /dev/null --connect-timeout $CONNECT_TIMEOUT -m $TIMEOUT http://$dest_ip:$dest_port; exit \$?" >/dev/null 2>&1
        remote_exit_code=$?
        set -e

        if [[ "$remote_exit_code" -eq 0 ]]; then
            status="EXPOSED"
            result="Unauthenticated connection succeeded."
            success_count=$((success_count + 1))
        elif [[ "$remote_exit_code" -eq 6 ]] || [[ "$remote_exit_code" -eq 7 ]] || [[ "$remote_exit_code" -eq 28 ]] || [[ "$remote_exit_code" -eq 124 ]]; then
            status="BLOCKED_OR_UNREACHABLE"
            result="Connection blocked/unreachable (curl/timeout rc=$remote_exit_code)."
            timeout_count=$((timeout_count + 1))
        elif [[ "$remote_exit_code" -eq 51 ]] || [[ "$remote_exit_code" -eq 58 ]] || [[ "$remote_exit_code" -eq 60 ]]; then
            status="DENIED_WITHOUT_CREDS"
            result="TLS/client-credential denial (curl rc=$remote_exit_code)."
            recv_fail_count=$((recv_fail_count + 1))
        else
            status="TEST_ERROR"
            result="Ambiguous probe failure (curl rc=$remote_exit_code)."
            other_count=$((other_count + 1))
        fi

        total_tested=$((total_tested + 1))
        emit_row "$source_namespace" "$source_pod" "$source_host_network" "$source_service_account" "$native_netpol_count" "$native_netpol_match" "$source_policy_engine" "$plugin_count" "$source_plugin_refs" "$dest_namespace" "$service_name" "$dest_ip" "$dest_port" "$remote_exit_code" "$status" "$result"
    done <"$ENDPOINTS_FILE"
    [[ "$OUTPUT_MODE" == "human" ]] && echo
done <"$SOURCE_MAP_FILE"

POST_NODE_COUNT=$("$KUBE_CLI" get nodes --no-headers 2>/dev/null | wc -l | tr -d ' ')
if "$KUBE_CLI" cluster-info >/dev/null 2>&1; then POST_API_HEALTH="ok"; else POST_API_HEALTH="unreachable"; fi

if [[ "$OUTPUT_MODE" == "human" ]]; then
    echo "======================================================================================="
    echo "Summary:"
    echo "  Total tests:            $total_tested"
    echo "  Namespaces considered:  $TOTAL_NAMESPACES_CONSIDERED"
    echo "  Namespaces tested:      $TOTAL_NAMESPACES_TESTED"
    echo "  Namespaces skipped:     $TOTAL_NAMESPACES_SKIPPED"
    echo "  Unknown policy groups:  $UNKNOWN_POLICY_CRD_GROUPS"
    echo "  Status counts:"
    for key in "${!STATUS_COUNTS[@]}"; do
      echo "    - $key: ${STATUS_COUNTS[$key]}"
    done
    echo "  Per-port status counts:"
    for key in "${!PORT_STATUS_COUNTS[@]}"; do
      echo "    - $key: ${PORT_STATUS_COUNTS[$key]}"
    done
    echo "  Post-check: API=$POST_API_HEALTH | NODE_COUNT=$POST_NODE_COUNT"
    if [ -s "$SKIPPED_FILE" ]; then
        echo "  Namespaces without curl+timeout source pod:"
        while read -r skipped_ns; do
            [ -z "$skipped_ns" ] && continue
            echo "    - $skipped_ns"
        done <"$SKIPPED_FILE"
    fi
    echo "Endpoint connectivity sweep complete."
else
    jq -cn --arg type "summary" --argjson total_tests "$total_tested" --argjson namespaces_considered "$TOTAL_NAMESPACES_CONSIDERED" --argjson namespaces_tested "$TOTAL_NAMESPACES_TESTED" --argjson namespaces_skipped "$TOTAL_NAMESPACES_SKIPPED" --arg unknown_policy_crd_groups "$UNKNOWN_POLICY_CRD_GROUPS" --arg pre_api "$PRE_API_HEALTH" --arg post_api "$POST_API_HEALTH" --argjson pre_nodes "${PRE_NODE_COUNT:-0}" --argjson post_nodes "${POST_NODE_COUNT:-0}" '{type:$type,total_tests:$total_tests,namespaces_considered:$namespaces_considered,namespaces_tested:$namespaces_tested,namespaces_skipped:$namespaces_skipped,unknown_policy_crd_groups:$unknown_policy_crd_groups,pre_api:$pre_api,post_api:$post_api,pre_node_count:$pre_nodes,post_node_count:$post_nodes}'
fi
