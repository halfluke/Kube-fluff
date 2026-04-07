#!/bin/bash
set -eu

# --- Configuration ---
HTTPS_CHECK_PORTS=("2379" "10250" "10257" "10259")
KUBELET_HTTP_RO_PORT="10255"
TIMEOUT=3
# --- End Configuration ---

if command -v oc >/dev/null 2>&1; then
    KCLI="oc"
elif command -v kubectl >/dev/null 2>&1; then
    KCLI="kubectl"
else
    echo "Error: Neither 'oc' nor 'kubectl' is available on PATH."
    exit 1
fi

if ! command -v timeout >/dev/null 2>&1; then
    echo "Error: 'timeout' is required on the host running this script."
    exit 1
fi
if ! command -v jq >/dev/null 2>&1; then
    echo "Error: 'jq' is required on the host running this script."
    exit 1
fi

contains_exact_ip() {
    local needle="${1:-}"
    shift
    local item=""
    for item in "$@"; do
        if [[ "$item" == "$needle" ]]; then
            return 0
        fi
    done
    return 1
}

classify_connectivity_code() {
    local rc="${1:-}"
    case "$rc" in
        6|7|28|124)
            echo "BLOCKED_OR_UNREACHABLE"
            ;;
        51|58|60)
            echo "DENIED_WITHOUT_CREDS"
            ;;
        0)
            echo "REACHABLE"
            ;;
        *)
            echo "TEST_ERROR"
            ;;
    esac
}

run_exec_probe() {
    local src_namespace="${1:-}" src_name="${2:-}" cmd="${3:-}"
    set +e
    "$KCLI" exec -n "$src_namespace" "$src_name" -- sh -c "$cmd" >/dev/null 2>&1
    local rc=$?
    set -e
    echo "$rc"
}

resolve_node_role() {
    local ip="${1:-}"
    if contains_exact_ip "$ip" "${CP_IPS_ARR[@]}"; then
        echo "CP"
    else
        echo "Worker"
    fi
}

print_result() {
    local src_namespace="${1:-}" src_name="${2:-}" host_network="${3:-}" service_account="${4:-}" netpol_count="${5:-}" netpol_match="${6:-}" dest_role="${7:-}" ip="${8:-}" port="${9:-}" status="${10:-}" details="${11:-}"
    if [[ "$status" == "EXPOSED" ]]; then
        echo "=========ALERT========="
    fi
    printf "%s | %s | %s | %s | %s | %s | %s | %s | %s | %s | %s\n" "$src_namespace" "$src_name" "$host_network" "$service_account" "$netpol_count" "$netpol_match" "$dest_role" "$ip" "$port" "$status" "$details"
    if [[ "$status" == "EXPOSED" ]]; then
        echo "=========ALERT========="
    fi
}

test_connection_simple() {
    local src_namespace="${1:-}" src_name="${2:-}" host_network="${3:-}" service_account="${4:-}" netpol_count="${5:-}" netpol_match="${6:-}" dest_role="${7:-}" ip="${8:-}" port="${9:-}"
    local probe_cmd="command -v curl >/dev/null 2>&1 || exit 127; timeout $TIMEOUT curl -s -o /dev/null -m $TIMEOUT http://$ip:$port"
    local rc
    rc=$(run_exec_probe "$src_namespace" "$src_name" "$probe_cmd")

    case "$(classify_connectivity_code "$rc")" in
        REACHABLE)
            print_result "$src_namespace" "$src_name" "$host_network" "$service_account" "$netpol_count" "$netpol_match" "$dest_role" "$ip" "$port" "EXPOSED" "Port responded without auth (curl rc=$rc)."
            ;;
        BLOCKED_OR_UNREACHABLE)
            print_result "$src_namespace" "$src_name" "$host_network" "$service_account" "$netpol_count" "$netpol_match" "$dest_role" "$ip" "$port" "BLOCKED_OR_UNREACHABLE" "Connection blocked/unreachable (curl/timeout rc=$rc)."
            ;;
        *)
            print_result "$src_namespace" "$src_name" "$host_network" "$service_account" "$netpol_count" "$netpol_match" "$dest_role" "$ip" "$port" "TEST_ERROR" "Probe failed (curl/exec rc=$rc)."
            ;;
    esac
}

test_auth_status_https() {
    local src_namespace="${1:-}" src_name="${2:-}" host_network="${3:-}" service_account="${4:-}" netpol_count="${5:-}" netpol_match="${6:-}" dest_role="${7:-}" ip="${8:-}" port="${9:-}"
    local endpoint="/metrics"
    local probe_cmd=""
    if [[ "$port" == "2379" ]]; then
        # etcd API auth behavior is better tested against v3 API than "/".
        probe_cmd="command -v curl >/dev/null 2>&1 || exit 127; timeout $TIMEOUT curl -sk -m $TIMEOUT -o /dev/null -H 'Content-Type: application/json' -d '{}' https://$ip:$port/v3/maintenance/status"
    else
        probe_cmd="command -v curl >/dev/null 2>&1 || exit 127; timeout $TIMEOUT curl -sk -m $TIMEOUT -o /dev/null https://$ip:$port$endpoint"
    fi
    local reach_rc
    reach_rc=$(run_exec_probe "$src_namespace" "$src_name" "$probe_cmd")

    local reach_class
    reach_class=$(classify_connectivity_code "$reach_rc")
    if [[ "$reach_class" == "BLOCKED_OR_UNREACHABLE" ]]; then
        print_result "$src_namespace" "$src_name" "$host_network" "$service_account" "$netpol_count" "$netpol_match" "$dest_role" "$ip" "$port" "BLOCKED_OR_UNREACHABLE" "Initial HTTPS probe blocked/unreachable (rc=$reach_rc)."
        return
    fi
    if [[ "$reach_class" == "DENIED_WITHOUT_CREDS" ]]; then
        print_result "$src_namespace" "$src_name" "$host_network" "$service_account" "$netpol_count" "$netpol_match" "$dest_role" "$ip" "$port" "DENIED_WITHOUT_CREDS" "TLS/client-credential denial (rc=$reach_rc)."
        return
    fi
    if [[ "$reach_class" == "TEST_ERROR" ]]; then
        print_result "$src_namespace" "$src_name" "$host_network" "$service_account" "$netpol_count" "$netpol_match" "$dest_role" "$ip" "$port" "TEST_ERROR" "Initial HTTPS probe failed (rc=$reach_rc)."
        return
    fi

    local code_cmd
    if [[ "$port" == "2379" ]]; then
        code_cmd="command -v curl >/dev/null 2>&1 || exit 127; timeout $TIMEOUT curl -sk -m $TIMEOUT -o /dev/null -w '%{http_code}:%{exitcode}' -H 'Content-Type: application/json' -d '{}' https://$ip:$port/v3/maintenance/status"
    else
        code_cmd="command -v curl >/dev/null 2>&1 || exit 127; timeout $TIMEOUT curl -sk -m $TIMEOUT -o /dev/null -w '%{http_code}:%{exitcode}' https://$ip:$port$endpoint"
    fi
    set +e
    local http_out
    http_out=$("$KCLI" exec -n "$src_namespace" "$src_name" -- sh -c "$code_cmd" 2>/dev/null)
    local http_cmd_rc=$?
    set -e

    if [[ "$http_cmd_rc" -ne 0 ]] || [[ "$http_out" != *:* ]]; then
        print_result "$src_namespace" "$src_name" "$host_network" "$service_account" "$netpol_count" "$netpol_match" "$dest_role" "$ip" "$port" "TEST_ERROR" "HTTP status probe failed (exec rc=$http_cmd_rc, out='${http_out:-none}')."
        return
    fi

    local http_code="${http_out%%:*}"
    local curl_rc="${http_out##*:}"

    if [[ "$http_code" == "200" ]]; then
        if [[ "$port" == "2379" ]]; then
            print_result "$src_namespace" "$src_name" "$host_network" "$service_account" "$netpol_count" "$netpol_match" "$dest_role" "$ip" "$port" "EXPOSED" "Unauthenticated HTTP 200 from etcd v3 endpoint '/v3/maintenance/status'."
        else
            print_result "$src_namespace" "$src_name" "$host_network" "$service_account" "$netpol_count" "$netpol_match" "$dest_role" "$ip" "$port" "EXPOSED" "Unauthenticated HTTP 200 from endpoint '$endpoint'."
        fi
    elif [[ "$http_code" == "401" ]] || [[ "$http_code" == "403" ]]; then
        print_result "$src_namespace" "$src_name" "$host_network" "$service_account" "$netpol_count" "$netpol_match" "$dest_role" "$ip" "$port" "AUTH_REQUIRED" "Endpoint requires authentication/authorization (HTTP $http_code)."
    elif [[ "$http_code" == "400" ]] || [[ "$http_code" == "404" ]]; then
        print_result "$src_namespace" "$src_name" "$host_network" "$service_account" "$netpol_count" "$netpol_match" "$dest_role" "$ip" "$port" "DENIED_WITHOUT_CREDS" "Endpoint denied request without credentials/path (HTTP $http_code)."
    elif [[ "$http_code" == "000" ]]; then
        case "$(classify_connectivity_code "$curl_rc")" in
            BLOCKED_OR_UNREACHABLE)
                print_result "$src_namespace" "$src_name" "$host_network" "$service_account" "$netpol_count" "$netpol_match" "$dest_role" "$ip" "$port" "BLOCKED_OR_UNREACHABLE" "No HTTP response and transport failure (curl rc=$curl_rc)."
                ;;
            DENIED_WITHOUT_CREDS)
                print_result "$src_namespace" "$src_name" "$host_network" "$service_account" "$netpol_count" "$netpol_match" "$dest_role" "$ip" "$port" "DENIED_WITHOUT_CREDS" "No HTTP response due to TLS/client auth denial (curl rc=$curl_rc)."
                ;;
            *)
                print_result "$src_namespace" "$src_name" "$host_network" "$service_account" "$netpol_count" "$netpol_match" "$dest_role" "$ip" "$port" "TEST_ERROR" "No HTTP response and ambiguous probe failure (curl rc=$curl_rc)."
                ;;
        esac
    else
        print_result "$src_namespace" "$src_name" "$host_network" "$service_account" "$netpol_count" "$netpol_match" "$dest_role" "$ip" "$port" "TEST_ERROR" "Unhandled HTTP response (http=$http_code, curl rc=$curl_rc)."
    fi
}

echo "Using Kubernetes CLI: $KCLI"
echo "Identifying Node IPs by Role..."
CP_IPS_RAW=$("$KCLI" get nodes -l node-role.kubernetes.io/control-plane= -o jsonpath='{.items[*].status.addresses[?(@.type=="InternalIP")].address}')
ALL_NODE_IPS_RAW=$("$KCLI" get nodes -o jsonpath='{.items[*].status.addresses[?(@.type=="InternalIP")].address}')
if [ -z "$ALL_NODE_IPS_RAW" ]; then
    echo "Error: Could not find any node InternalIPs."
    exit 1
fi

MODE="full"
if [ -n "$CP_IPS_RAW" ]; then
    read -r -a CP_IPS_ARR <<< "$CP_IPS_RAW"
else
    MODE="worker_only"
    CP_IPS_ARR=()
fi

read -r -a ALL_NODE_IPS_ARR <<< "$ALL_NODE_IPS_RAW"
WORKER_IPS_RAW=$("$KCLI" get nodes -l node-role.kubernetes.io/worker= -o jsonpath='{.items[*].status.addresses[?(@.type=="InternalIP")].address}')
WORKER_IPS_ARR=()

if [ -n "$WORKER_IPS_RAW" ]; then
    read -r -a WORKER_IPS_ARR <<< "$WORKER_IPS_RAW"
elif [ "$MODE" == "full" ]; then
    for ip in "${ALL_NODE_IPS_ARR[@]}"; do
        if ! contains_exact_ip "$ip" "${CP_IPS_ARR[@]}"; then
            WORKER_IPS_ARR+=("$ip")
        fi
    done
else
    WORKER_IPS_ARR=("${ALL_NODE_IPS_ARR[@]}")
fi

WORKER_IPS_RAW="${WORKER_IPS_ARR[*]}"
if [ "$MODE" == "full" ]; then
    ALL_NODES_IPS=("${CP_IPS_ARR[@]}" "${WORKER_IPS_ARR[@]}")
else
    ALL_NODES_IPS=("${WORKER_IPS_ARR[@]}")
fi

if [ -n "$CP_IPS_RAW" ]; then
    echo "Control Plane IPs found: $CP_IPS_RAW"
else
    echo "Control Plane IPs found: none"
fi
if [ -n "$WORKER_IPS_RAW" ]; then
    echo "Worker IPs found: $WORKER_IPS_RAW"
else
    echo "Worker IPs found: none"
fi

if [ "$MODE" == "worker_only" ]; then
    echo "Mode: worker_only"
    echo "Info: Control-plane nodes are not visible. Skipping CP-only checks (2379, 10257, 10259)."
else
    echo "Mode: full"
    if [ -z "$WORKER_IPS_RAW" ]; then
        echo "Info: No worker-labeled nodes were detected. Running control-plane-only checks."
    fi
fi
echo "---------------------------------------------------------------------"
echo "Testing connectivity from all running pods..."
echo "Status legend:"
echo "- EXPOSED: unauthenticated access succeeded."
echo "- AUTH_REQUIRED: endpoint reachable but requires auth."
echo "- DENIED_WITHOUT_CREDS: reachable but denied by TLS/auth/path constraints."
echo "- BLOCKED_OR_UNREACHABLE: network path blocked, timed out, or no route."
echo "- TEST_ERROR: probe could not be completed reliably."
echo "- SKIPPED: source pod missing required probe tools (curl/timeout)."
echo "- NETPOL_* fields are based on Kubernetes native NetworkPolicy objects only (networking.k8s.io/v1)."
echo "  They do not include CNI-specific policy engines (for example Calico GlobalNetworkPolicy)."
echo "Connectivity/transport code mapping:"
echo "- BLOCKED_OR_UNREACHABLE: curl/timeout rc in {6,7,28,124}"
echo "- DENIED_WITHOUT_CREDS: curl rc in {51,58,60} or HTTP 400/404 in auth probe stage"
echo "- TEST_ERROR: any other probe/exec failure or ambiguous rc"
echo "- EXPOSED findings are wrapped with =========ALERT========= lines."
echo "Format: SRC_NS | SRC_POD | HOSTNETWORK | SERVICEACCOUNT | NETPOL_NS_COUNT | NETPOL_MATCH | DEST_ROLE | DEST_IP | PORT | STATUS | DETAILS"
echo "---------------------------------------------------------------------"
PODS_JSON=$("$KCLI" get pods -A -o json)
set +e
NETPOL_JSON=$("$KCLI" get networkpolicy -A -o json 2>/dev/null)
NETPOL_RC=$?
set -e
if [[ $NETPOL_RC -ne 0 ]]; then
    NETPOL_JSON='{"items":[]}'
    echo "Warning: Could not read NetworkPolicies with $KCLI. NETPOL context will be n/a."
fi

echo "$PODS_JSON" | jq -rc '.items[] | select(.status.phase=="Running") | [.metadata.namespace, .metadata.name, (.spec.hostNetwork // false), (.spec.serviceAccountName // "default"), (.metadata.labels // {})] | @base64' | while read -r pod_rec; do
    pod_data=$(printf "%s" "$pod_rec" | base64 -d)
    src_namespace=$(printf "%s" "$pod_data" | jq -r '.[0]')
    src_name=$(printf "%s" "$pod_data" | jq -r '.[1]')
    host_network=$(printf "%s" "$pod_data" | jq -r '.[2]')
    service_account=$(printf "%s" "$pod_data" | jq -r '.[3]')
    pod_labels=$(printf "%s" "$pod_data" | jq -c '.[4]')
    if [[ "$service_account" == "null" ]] || [[ -z "$service_account" ]]; then
        service_account="default"
    fi

    if [[ $NETPOL_RC -eq 0 ]]; then
        netpol_count=$(printf "%s" "$NETPOL_JSON" | jq --arg ns "$src_namespace" '[.items[] | select(.metadata.namespace == $ns)] | length')
        netpol_match=$(printf "%s" "$NETPOL_JSON" | jq -r --arg ns "$src_namespace" --argjson labels "$pod_labels" '
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
    else
        netpol_count="n/a"
        netpol_match="n/a"
    fi

    preflight_rc=$(run_exec_probe "$src_namespace" "$src_name" "command -v curl >/dev/null 2>&1 && command -v timeout >/dev/null 2>&1")
    if [[ "$preflight_rc" -ne 0 ]]; then
        print_result "$src_namespace" "$src_name" "$host_network" "$service_account" "$netpol_count" "$netpol_match" "-" "-" "-" "SKIPPED" "Missing required tools in source pod (need curl + timeout; rc=$preflight_rc)."
        continue
    fi

    for ip in "${ALL_NODES_IPS[@]}"; do
        NODE_ROLE=$(resolve_node_role "$ip")

        for port in "${HTTPS_CHECK_PORTS[@]}"; do
            if [[ "$NODE_ROLE" == "CP" ]]; then
                test_auth_status_https "$src_namespace" "$src_name" "$host_network" "$service_account" "$netpol_count" "$netpol_match" "$NODE_ROLE" "$ip" "$port"
            elif [[ "$NODE_ROLE" == "Worker" ]] && [[ "$port" == "10250" ]]; then
                test_auth_status_https "$src_namespace" "$src_name" "$host_network" "$service_account" "$netpol_count" "$netpol_match" "$NODE_ROLE" "$ip" "$port"
            fi
        done
    done

    for ip in "${ALL_NODES_IPS[@]}"; do
        NODE_ROLE=$(resolve_node_role "$ip")
        test_connection_simple "$src_namespace" "$src_name" "$host_network" "$service_account" "$netpol_count" "$netpol_match" "$NODE_ROLE" "$ip" "$KUBELET_HTTP_RO_PORT"
    done
done

echo "---------------------------------------------------------------------"
echo "Cluster port connectivity test complete."
