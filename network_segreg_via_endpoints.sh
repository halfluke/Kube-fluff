#!/bin/bash
set -euo pipefail

# --- Configuration ---
TIMEOUT=3
# --- End Configuration ---

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

SOURCE_MAP_FILE="$(mktemp)"
SKIPPED_FILE="$(mktemp)"
ENDPOINTS_FILE="$(mktemp)"

cleanup() {
    rm -f "$SOURCE_MAP_FILE" "$SKIPPED_FILE" "$ENDPOINTS_FILE"
}
trap cleanup EXIT

while read -r namespace; do
    [ -z "$namespace" ] && continue
    found="false"
    echo "Looking for source pod in namespace: $namespace"

    while read -r pod; do
        [ -z "$pod" ] && continue
        if "$KUBE_CLI" exec -n "$namespace" "$pod" -- sh -c 'command -v curl >/dev/null 2>&1' >/dev/null 2>&1; then
            printf "%s|%s\n" "$namespace" "$pod" >>"$SOURCE_MAP_FILE"
            found="true"
            echo "  Selected source pod: $pod"
            break
        fi
    done < <("$KUBE_CLI" get pods -n "$namespace" --field-selector=status.phase=Running -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}')

    if [ "$found" = "false" ]; then
        echo "  No exec-capable curl pod found."
        printf "%s\n" "$namespace" >>"$SKIPPED_FILE"
    fi
done < <("$KUBE_CLI" get ns -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{end}')

if [ ! -s "$SOURCE_MAP_FILE" ]; then
    echo "ERROR: No namespace has a running pod where exec works and curl is installed."
    exit 1
fi

echo "Source pods selected:"
while IFS='|' read -r src_namespace src_pod; do
    printf "  - %s: %s\n" "$src_namespace" "$src_pod"
done <"$SOURCE_MAP_FILE"

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
refused_count=0
recv_fail_count=0
other_count=0

echo
echo "Legend:"
echo "  SUCCESS: Connection established"
echo "  TIMED OUT: Network Policy/Firewall Blocked"
echo "  CONNECTION REFUSED/BAD RESPONSE: App not listening"
echo "  RECV FAILURE: Connection reset by peer"
echo "  UNKNOWN FAILURE: Exit Code <n>"
echo

while IFS='|' read -r source_namespace source_pod; do
    echo "======================================================================================="
    echo "Source namespace: $source_namespace"
    echo "Source pod chosen for this test block: $source_pod"
    printf "%-20s | %-28s | %-15s | %-7s | %-9s | %s\n" "DEST_NS" "SERVICE" "DEST_IP" "PORT" "EXIT_CODE" "RESULT"
    echo "---------------------------------------------------------------------------------------"

    while IFS='|' read -r dest_namespace service_name dest_ip dest_port; do
        if [ -z "$dest_ip" ] || [ -z "$dest_port" ]; then
            continue
        fi

        set +e
        "$KUBE_CLI" exec -n "$source_namespace" "$source_pod" -- sh -c "timeout $TIMEOUT curl -s -o /dev/null -m $TIMEOUT http://$dest_ip:$dest_port; exit \$?" >/dev/null 2>&1
        remote_exit_code=$?
        set -e

        if [[ "$remote_exit_code" -eq 0 ]] || [[ "$remote_exit_code" -eq 1 ]] || [[ "$remote_exit_code" -eq 52 ]]; then
            result="SUCCESS: Connection established"
            success_count=$((success_count + 1))
        elif [[ "$remote_exit_code" -eq 124 ]]; then
            result="TIMED OUT: Network Policy/Firewall Blocked"
            timeout_count=$((timeout_count + 1))
        elif [[ "$remote_exit_code" -eq 7 ]]; then
            result="CONNECTION REFUSED/BAD RESPONSE: App not listening"
            refused_count=$((refused_count + 1))
        elif [[ "$remote_exit_code" -eq 56 ]]; then
            result="RECV FAILURE: Connection reset by peer"
            recv_fail_count=$((recv_fail_count + 1))
        else
            result="UNKNOWN FAILURE: Exit Code $remote_exit_code"
            other_count=$((other_count + 1))
        fi

        total_tested=$((total_tested + 1))
        printf "%-20s | %-28s | %-15s | %-7s | %-9d | %s\n" "$dest_namespace" "$service_name" "$dest_ip" "$dest_port" "$remote_exit_code" "$result"
    done <"$ENDPOINTS_FILE"
    echo
done <"$SOURCE_MAP_FILE"

skipped_namespaces=0
if [ -s "$SKIPPED_FILE" ]; then
    skipped_namespaces=$(wc -l <"$SKIPPED_FILE")
fi

echo "======================================================================================="
echo "Summary:"
echo "  Total tests:            $total_tested"
echo "  Success:                $success_count"
echo "  Timed out:              $timeout_count"
echo "  Connection refused:     $refused_count"
echo "  Recv failure:           $recv_fail_count"
echo "  Unknown failure:        $other_count"
echo "  Skipped namespaces:     $skipped_namespaces"

if [ -s "$SKIPPED_FILE" ]; then
    echo "  Namespaces without curl-capable source pod:"
    while read -r skipped_ns; do
        [ -z "$skipped_ns" ] && continue
        echo "    - $skipped_ns"
    done <"$SKIPPED_FILE"
fi

echo "Endpoint connectivity sweep complete."
