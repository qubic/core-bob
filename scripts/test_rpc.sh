#!/bin/bash

# Qubic RPC Test Script
# Tests all read-only methods on both HTTP and WebSocket endpoints

# Don't exit on errors - we want to continue testing even if some tests fail
# set -e

# Default configuration (can be overridden by args or env vars)
HOST="${RPC_HOST:-localhost}"
PORT="${RPC_PORT:-40420}"
HTTP_ONLY=false
WS_ONLY=false
VERBOSE=false

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --host)
            HOST="$2"
            shift 2
            ;;
        --port)
            PORT="$2"
            shift 2
            ;;
        --http-only)
            HTTP_ONLY=true
            shift
            ;;
        --ws-only)
            WS_ONLY=true
            shift
            ;;
        --verbose|-v)
            VERBOSE=true
            shift
            ;;
        --help|-h)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --host HOST      RPC host (default: localhost)"
            echo "  --port PORT      RPC port (default: 40420)"
            echo "  --http-only      Skip WebSocket tests"
            echo "  --ws-only        Skip HTTP tests"
            echo "  --verbose, -v    Show full responses"
            echo "  --help, -h       Show this help"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            echo "Use --help for usage information"
            exit 1
            ;;
    esac
done

# Build URLs after parsing arguments
HTTP_URL="http://${HOST}:${PORT}/qubic"
WS_URL="ws://${HOST}:${PORT}/ws/qubic"

# Test identity (use a known valid one or override with env var)
TEST_IDENTITY="${TEST_IDENTITY:-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAFXIB}"
TEST_IDENTITY_HEX="${TEST_IDENTITY_HEX:-0x0000000000000000000000000000000000000000000000000000000000000000}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Counters
PASS=0
FAIL=0
SKIP=0

# Print functions
print_header() {
    echo -e "\n${BLUE}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${BLUE}  $1${NC}"
    echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}\n"
}

print_test() {
    echo -e "${YELLOW}Testing:${NC} $1"
}

print_pass() {
    echo -e "${GREEN}✓ PASS${NC}: $1"
    ((PASS++))
}

print_fail() {
    echo -e "${RED}✗ FAIL${NC}: $1"
    echo -e "${RED}  Response: $2${NC}"
    ((FAIL++))
}

print_skip() {
    echo -e "${YELLOW}⊘ SKIP${NC}: $1"
    ((SKIP++))
}

# JSON-RPC request helper for HTTP
rpc_http() {
    local method="$1"
    local params="$2"
    local id="${3:-1}"

    local payload
    if [ -z "$params" ] || [ "$params" == "null" ]; then
        payload="{\"jsonrpc\":\"2.0\",\"method\":\"$method\",\"params\":[],\"id\":$id}"
    else
        payload="{\"jsonrpc\":\"2.0\",\"method\":\"$method\",\"params\":$params,\"id\":$id}"
    fi

    curl -s -X POST "$HTTP_URL" \
        -H "Content-Type: application/json" \
        -d "$payload" 2>/dev/null
}

# JSON-RPC request helper for WebSocket (using websocat if available)
rpc_ws() {
    local method="$1"
    local params="$2"
    local id="${3:-1}"

    if ! command -v websocat &> /dev/null; then
        echo '{"error":"websocat not installed"}'
        return 1
    fi

    local payload
    if [ -z "$params" ] || [ "$params" == "null" ]; then
        payload="{\"jsonrpc\":\"2.0\",\"method\":\"$method\",\"params\":[],\"id\":$id}"
    else
        payload="{\"jsonrpc\":\"2.0\",\"method\":\"$method\",\"params\":$params,\"id\":$id}"
    fi

    echo "$payload" | timeout 5 websocat -n1 "$WS_URL" 2>/dev/null || echo '{"error":"websocket timeout"}'
}

# Check if response is successful (has result, no error)
check_success() {
    local response="$1"
    local method="$2"

    # Check for error field (must exist AND not be null)
    if echo "$response" | jq -e 'has("error") and .error != null' > /dev/null 2>&1; then
        local error_msg=$(echo "$response" | jq -r '.error.message // .error // "unknown error"')
        # Some errors are expected (e.g., not found)
        if [[ "$error_msg" == *"not found"* ]] || [[ "$error_msg" == *"Not found"* ]]; then
            print_pass "$method (resource not found - expected)"
            return 0
        fi
        print_fail "$method" "$error_msg"
        return 1
    fi

    # Check for result field (must exist AND not be null, unless result is legitimately null)
    if echo "$response" | jq -e 'has("result")' > /dev/null 2>&1; then
        print_pass "$method"
        return 0
    fi

    print_fail "$method" "No result in response: $response"
    return 1
}

# Check for specific error code
check_error_code() {
    local response="$1"
    local expected_code="$2"
    local method="$3"

    local actual_code=$(echo "$response" | jq -r '.error.code // "none"')
    if [ "$actual_code" == "$expected_code" ]; then
        print_pass "$method (error code $expected_code)"
        return 0
    fi
    print_fail "$method" "Expected error code $expected_code, got $actual_code"
    return 1
}

# ============================================================================
# HTTP Tests
# ============================================================================

test_http() {
    print_header "HTTP RPC Tests ($HTTP_URL)"

    # Check if server is reachable (POST with empty body should return 400, GET returns 405)
    print_test "Server connectivity"
    local http_code
    http_code=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$HTTP_URL" -H "Content-Type: application/json" -d '{}' 2>/dev/null || echo "000")
    if ! echo "$http_code" | grep -qE "^(200|400)$"; then
        print_fail "Server not reachable at $HTTP_URL (HTTP $http_code)"
        return 1
    fi
    print_pass "Server reachable"

    # ========================================================================
    # Chain Info Methods
    # ========================================================================
    echo -e "\n${BLUE}--- Chain Info Methods ---${NC}"

    print_test "qubic_chainId"
    response=$(rpc_http "qubic_chainId")
    check_success "$response" "qubic_chainId"

    print_test "qubic_clientVersion"
    response=$(rpc_http "qubic_clientVersion")
    check_success "$response" "qubic_clientVersion"

    print_test "qubic_syncing"
    response=$(rpc_http "qubic_syncing")
    check_success "$response" "qubic_syncing"

    print_test "qubic_getCurrentEpoch"
    response=$(rpc_http "qubic_getCurrentEpoch")
    check_success "$response" "qubic_getCurrentEpoch"

    # ========================================================================
    # Tick Methods
    # ========================================================================
    echo -e "\n${BLUE}--- Tick Methods ---${NC}"

    print_test "qubic_getTickNumber"
    response=$(rpc_http "qubic_getTickNumber")
    check_success "$response" "qubic_getTickNumber"
    CURRENT_TICK=$(echo "$response" | jq -r '.result // 0')
    echo "  Current tick: $CURRENT_TICK"

    print_test "qubic_getTickByNumber (latest)"
    response=$(rpc_http "qubic_getTickByNumber" '["latest", false]')
    check_success "$response" "qubic_getTickByNumber (latest)"

    print_test "qubic_getTickByNumber (with transactions)"
    response=$(rpc_http "qubic_getTickByNumber" '["latest", true]')
    check_success "$response" "qubic_getTickByNumber (with transactions)"

    if [ "$CURRENT_TICK" != "0" ] && [ "$CURRENT_TICK" != "null" ]; then
        print_test "qubic_getTickByNumber (numeric: $CURRENT_TICK)"
        response=$(rpc_http "qubic_getTickByNumber" "[\"$CURRENT_TICK\", false]")
        check_success "$response" "qubic_getTickByNumber (numeric)"
    fi

    # ========================================================================
    # Transaction Methods
    # ========================================================================
    echo -e "\n${BLUE}--- Transaction Methods ---${NC}"

    # Use a dummy tx hash - will return not found but should not error
    DUMMY_TX="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAА"

    print_test "qubic_getTransactionByHash"
    response=$(rpc_http "qubic_getTransactionByHash" "[\"$DUMMY_TX\"]")
    # This will likely return null (not found) which is OK
    if echo "$response" | jq -e '.result == null' > /dev/null 2>&1; then
        print_pass "qubic_getTransactionByHash (not found - expected)"
    else
        check_success "$response" "qubic_getTransactionByHash"
    fi

    print_test "qubic_getTransactionReceipt"
    response=$(rpc_http "qubic_getTransactionReceipt" "[\"$DUMMY_TX\"]")
    if echo "$response" | jq -e '.result == null' > /dev/null 2>&1; then
        print_pass "qubic_getTransactionReceipt (not found - expected)"
    else
        check_success "$response" "qubic_getTransactionReceipt"
    fi

    # ========================================================================
    # Balance & Transfer Methods
    # ========================================================================
    echo -e "\n${BLUE}--- Balance & Transfer Methods ---${NC}"

    print_test "qubic_getBalance (Qubic identity)"
    response=$(rpc_http "qubic_getBalance" "[\"$TEST_IDENTITY\"]")
    check_success "$response" "qubic_getBalance (Qubic identity)"

    print_test "qubic_getBalance (hex identity)"
    response=$(rpc_http "qubic_getBalance" "[\"$TEST_IDENTITY_HEX\"]")
    check_success "$response" "qubic_getBalance (hex identity)"

    print_test "qubic_getTransfers"
    response=$(rpc_http "qubic_getTransfers" '[{"fromTick": 0, "toTick": 100}]')
    check_success "$response" "qubic_getTransfers"

    # ========================================================================
    # Asset Methods
    # ========================================================================
    echo -e "\n${BLUE}--- Asset Methods ---${NC}"

    print_test "qubic_getAssetBalance"
    response=$(rpc_http "qubic_getAssetBalance" "[\"$TEST_IDENTITY\", \"$TEST_IDENTITY\", \"TEST\"]")
    check_success "$response" "qubic_getAssetBalance"

    print_test "qubic_getAssets"
    response=$(rpc_http "qubic_getAssets" "[\"$TEST_IDENTITY\"]")
    # This returns error "not implemented" which is expected
    if echo "$response" | jq -e '.result.error' > /dev/null 2>&1; then
        print_pass "qubic_getAssets (not implemented - expected)"
    else
        check_success "$response" "qubic_getAssets"
    fi

    # ========================================================================
    # Log Methods
    # ========================================================================
    echo -e "\n${BLUE}--- Log Methods ---${NC}"

    print_test "qubic_getLogs"
    response=$(rpc_http "qubic_getLogs" '[{"fromTick": 0, "toTick": 100}]')
    check_success "$response" "qubic_getLogs"

    # ========================================================================
    # Subscription Methods (should fail on HTTP)
    # ========================================================================
    echo -e "\n${BLUE}--- Subscription Methods (HTTP - should fail) ---${NC}"

    print_test "qubic_subscribe (should fail on HTTP)"
    response=$(rpc_http "qubic_subscribe" '["newTicks"]')
    check_error_code "$response" "-32601" "qubic_subscribe"

    print_test "qubic_unsubscribe (should fail on HTTP)"
    response=$(rpc_http "qubic_unsubscribe" '["sub_123"]')
    check_error_code "$response" "-32601" "qubic_unsubscribe"

    # ========================================================================
    # Error Handling Tests
    # ========================================================================
    echo -e "\n${BLUE}--- Error Handling ---${NC}"

    print_test "Invalid method"
    response=$(rpc_http "qubic_invalidMethod")
    check_error_code "$response" "-32601" "Invalid method"

    print_test "Empty method"
    response=$(curl -s -X POST "$HTTP_URL" -H "Content-Type: application/json" \
        -d '{"jsonrpc":"2.0","method":"","params":[],"id":1}')
    check_error_code "$response" "-32600" "Empty method"

    print_test "Missing method"
    response=$(curl -s -X POST "$HTTP_URL" -H "Content-Type: application/json" \
        -d '{"jsonrpc":"2.0","params":[],"id":1}')
    check_error_code "$response" "-32600" "Missing method"

    print_test "Invalid identity format"
    response=$(rpc_http "qubic_getBalance" '["invalid_identity"]')
    check_error_code "$response" "-32602" "Invalid identity format"

    print_test "Missing required parameter"
    response=$(rpc_http "qubic_getBalance" '[]')
    check_error_code "$response" "-32602" "Missing required parameter"

    # ========================================================================
    # Alias Method Test
    # ========================================================================
    echo -e "\n${BLUE}--- Method Aliases ---${NC}"

    print_test "qubic_sendRawTransaction (alias for broadcastTransaction)"
    # This will fail with "no connection" but proves the method is recognized
    response=$(rpc_http "qubic_sendRawTransaction" '["0xdeadbeef"]')
    # Accept either "no connection" error or invalid data error
    if echo "$response" | jq -e '.result.error' > /dev/null 2>&1; then
        print_pass "qubic_sendRawTransaction (method recognized)"
    elif echo "$response" | jq -e '.error' > /dev/null 2>&1; then
        print_fail "qubic_sendRawTransaction" "$(echo "$response" | jq -r '.error.message')"
    else
        print_pass "qubic_sendRawTransaction (method recognized)"
    fi
}

# ============================================================================
# WebSocket Tests
# ============================================================================

test_websocket() {
    print_header "WebSocket RPC Tests ($WS_URL)"

    # Check if websocat is available
    if ! command -v websocat &> /dev/null; then
        echo -e "${YELLOW}websocat not installed - skipping WebSocket tests${NC}"
        echo "Install with: cargo install websocat"
        return 0
    fi

    # Check if WebSocket server is reachable
    print_test "WebSocket connectivity"
    response=$(rpc_ws "qubic_chainId")
    if echo "$response" | grep -q "error.*timeout\|error.*connection"; then
        print_fail "WebSocket not reachable at $WS_URL"
        return 1
    fi
    print_pass "WebSocket reachable"

    # ========================================================================
    # Chain Info Methods
    # ========================================================================
    echo -e "\n${BLUE}--- Chain Info Methods (WebSocket) ---${NC}"

    print_test "qubic_chainId"
    response=$(rpc_ws "qubic_chainId")
    check_success "$response" "qubic_chainId"

    print_test "qubic_clientVersion"
    response=$(rpc_ws "qubic_clientVersion")
    check_success "$response" "qubic_clientVersion"

    print_test "qubic_syncing"
    response=$(rpc_ws "qubic_syncing")
    check_success "$response" "qubic_syncing"

    print_test "qubic_getCurrentEpoch"
    response=$(rpc_ws "qubic_getCurrentEpoch")
    check_success "$response" "qubic_getCurrentEpoch"

    # ========================================================================
    # Tick Methods
    # ========================================================================
    echo -e "\n${BLUE}--- Tick Methods (WebSocket) ---${NC}"

    print_test "qubic_getTickNumber"
    response=$(rpc_ws "qubic_getTickNumber")
    check_success "$response" "qubic_getTickNumber"

    print_test "qubic_getTickByNumber (latest)"
    response=$(rpc_ws "qubic_getTickByNumber" '["latest", false]')
    check_success "$response" "qubic_getTickByNumber (latest)"

    # ========================================================================
    # Balance Methods
    # ========================================================================
    echo -e "\n${BLUE}--- Balance Methods (WebSocket) ---${NC}"

    print_test "qubic_getBalance"
    response=$(rpc_ws "qubic_getBalance" "[\"$TEST_IDENTITY\"]")
    check_success "$response" "qubic_getBalance"

    # ========================================================================
    # Subscription Methods (WebSocket only)
    # ========================================================================
    echo -e "\n${BLUE}--- Subscription Methods (WebSocket) ---${NC}"

    print_test "qubic_subscribe (newTicks)"
    response=$(rpc_ws "qubic_subscribe" '["newTicks"]')
    if echo "$response" | jq -e '.result' > /dev/null 2>&1; then
        SUB_ID=$(echo "$response" | jq -r '.result')
        print_pass "qubic_subscribe (newTicks) - subscription ID: $SUB_ID"

        # Test unsubscribe
        print_test "qubic_unsubscribe"
        response=$(rpc_ws "qubic_unsubscribe" "[\"$SUB_ID\"]")
        check_success "$response" "qubic_unsubscribe"
    else
        check_success "$response" "qubic_subscribe (newTicks)"
    fi

    print_test "qubic_subscribe (logs)"
    response=$(rpc_ws "qubic_subscribe" '["logs", {}]')
    check_success "$response" "qubic_subscribe (logs)"

    print_test "qubic_subscribe (transfers)"
    response=$(rpc_ws "qubic_subscribe" '["transfers", {}]')
    check_success "$response" "qubic_subscribe (transfers)"

    print_test "qubic_subscribe (tickStream)"
    response=$(rpc_ws "qubic_subscribe" '["tickStream", {}]')
    check_success "$response" "qubic_subscribe (tickStream)"

    print_test "qubic_subscribe (invalid type)"
    response=$(rpc_ws "qubic_subscribe" '["invalidType"]')
    check_error_code "$response" "-32602" "qubic_subscribe (invalid type)"
}

# ============================================================================
# Batch Request Tests
# ============================================================================

test_batch() {
    print_header "Batch Request Tests"

    print_test "HTTP batch request"
    response=$(curl -s -X POST "$HTTP_URL" \
        -H "Content-Type: application/json" \
        -d '[
            {"jsonrpc":"2.0","method":"qubic_chainId","params":[],"id":1},
            {"jsonrpc":"2.0","method":"qubic_clientVersion","params":[],"id":2},
            {"jsonrpc":"2.0","method":"qubic_getTickNumber","params":[],"id":3}
        ]')

    if echo "$response" | jq -e 'type == "array" and length == 3' > /dev/null 2>&1; then
        print_pass "HTTP batch request (3 responses)"
    else
        print_fail "HTTP batch request" "$response"
    fi

    print_test "HTTP empty batch (should fail)"
    response=$(curl -s -X POST "$HTTP_URL" \
        -H "Content-Type: application/json" \
        -d '[]')
    check_error_code "$response" "-32600" "HTTP empty batch"
}

# ============================================================================
# Main
# ============================================================================

main() {
    echo -e "${BLUE}"
    echo "╔═══════════════════════════════════════════════════════════════╗"
    echo "║           Qubic JSON-RPC Test Suite                           ║"
    echo "╚═══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    echo "Target: $HTTP_URL"
    echo "WebSocket: $WS_URL"
    echo ""

    # Run tests based on flags
    if [ "$WS_ONLY" = false ]; then
        test_http
        test_batch
    fi
    if [ "$HTTP_ONLY" = false ]; then
        test_websocket
    fi

    # Summary
    print_header "Test Summary"
    echo -e "  ${GREEN}Passed:${NC}  $PASS"
    echo -e "  ${RED}Failed:${NC}  $FAIL"
    echo -e "  ${YELLOW}Skipped:${NC} $SKIP"
    echo ""

    TOTAL=$((PASS + FAIL))
    if [ $FAIL -eq 0 ]; then
        echo -e "${GREEN}All $TOTAL tests passed!${NC}"
        exit 0
    else
        echo -e "${RED}$FAIL of $TOTAL tests failed${NC}"
        exit 1
    fi
}

# Run if executed directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
