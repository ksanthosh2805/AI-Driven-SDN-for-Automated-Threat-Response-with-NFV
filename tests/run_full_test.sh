#!/bin/bash
# Complete end-to-end testing automation

echo "=========================================="
echo "AI-SDN PROJECT - FULL SYSTEM TEST"
echo "=========================================="

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Test counters
TESTS_PASSED=0
TESTS_FAILED=0

# Function to check if service is running
check_service() {
    local service_name=$1
    local port=$2

    if netstat -tuln | grep -q ":$port "; then
        echo -e "${GREEN}✓${NC} $service_name is running (port $port)"
        return 0
    else
        echo -e "${RED}✗${NC} $service_name is NOT running (port $port)"
        return 1
    fi
}

# Function to test API endpoint
test_api_endpoint() {
    local endpoint=$1
    local expected_status=$2

    response=$(curl -s -o /dev/null -w "%{http_code}" "$endpoint")

    if [ "$response" -eq "$expected_status" ]; then
        echo -e "${GREEN}✓${NC} API endpoint $endpoint returned $response"
        ((TESTS_PASSED++))
        return 0
    else
        echo -e "${RED}✗${NC} API endpoint $endpoint returned $response (expected $expected_status)"
        ((TESTS_FAILED++))
        return 1
    fi
}

echo ""
echo "STEP 1: Checking Prerequisites"
echo "=========================================="

# Check if AI API is running
check_service "AI API" 5000
AI_RUNNING=$?

# Check if Ryu controller is running
check_service "Ryu Controller" 6633
RYU_RUNNING=$?

if [ $AI_RUNNING -ne 0 ] || [ $RYU_RUNNING -ne 0 ]; then
    echo -e "${RED}ERROR: Required services not running!${NC}"
    echo "Start services:"
    echo "  1. Terminal 1: cd ai && python3 ai_api.py"
    echo "  2. Terminal 2: ryu-manager controller/microsegmentation_controller.py"
    echo "  3. Terminal 3: sudo mn --custom topologies/vnf_topology.py --topo vnf \\"
    echo "                   --controller=remote,ip=127.0.0.1,port=6633 --switch ovs"
    exit 1
fi

echo ""
echo "STEP 2: Testing AI API Endpoints"
echo "=========================================="

# Test health endpoint
test_api_endpoint "http://localhost:5000/health" 200

# Test info endpoint
test_api_endpoint "http://localhost:5000/info" 200

# Test prediction endpoint with sample data (h1 -> h3)
echo "Testing /predict endpoint..."
prediction_response=$(
  curl -s -X POST http://localhost:5000/predict \
    -H "Content-Type: application/json" \
    -d '{
      "src_ip": "192.168.1.10",
      "dst_ip": "192.168.1.20",
      "src_port": 12345,
      "dst_port": 80,
      "duration_sec": 2.5,
      "packets_total": 100,
      "bytes_total": 50000,
      "packets_per_sec": 40,
      "bytes_per_sec": 20000,
      "avg_packet_size": 500
    }'
)

if echo "$prediction_response" | grep -q "prediction"; then
    echo -e "${GREEN}✓${NC} Prediction API working"
    prediction=$(echo "$prediction_response" | grep -o '"prediction":"[^"]*"' | cut -d':' -f2 | tr -d '"')
    echo "  Result: $prediction"
    ((TESTS_PASSED++))
else
    echo -e "${RED}✗${NC} Prediction API failed"
    ((TESTS_FAILED++))
fi

echo ""
echo "STEP 3: Testing Network Connectivity"
echo "=========================================="
echo "NOTE: This requires Mininet (vnf_topology.py) to be running."
echo "Manual verification needed:"
echo "  mininet> pingall"
echo "  Expected: 0% packet loss"

echo ""
echo "STEP 4: Testing Attack Detection"
echo "=========================================="
echo "Simulating malicious traffic pattern (high-intensity flow h1 -> h3)..."

# Send multiple suspicious requests that should look like an attack
for i in {1..5}; do
  curl -s -X POST http://localhost:5000/predict \
    -H "Content-Type: application/json" \
    -d '{
      "src_ip": "192.168.1.10",
      "dst_ip": "192.168.1.20",
      "src_port": 54321,
      "dst_port": 23,
      "duration_sec": 0.1,
      "packets_total": 10000,
      "bytes_total": 500000,
      "packets_per_sec": 100000,
      "bytes_per_sec": 5000000,
      "avg_packet_size": 50
    }' >/dev/null
done

echo -e "${YELLOW}Check controller logs for threat detection and quarantine events.${NC}"

echo ""
echo "=========================================="
echo "TEST SUMMARY"
echo "=========================================="
echo -e "${GREEN}Passed: $TESTS_PASSED${NC}"
echo -e "${RED}Failed: $TESTS_FAILED${NC}"

if [ $TESTS_FAILED -eq 0 ]; then
    echo -e "${GREEN}All tests passed! ✓${NC}"
    exit 0
else
    echo -e "${RED}Some tests failed!${NC}"
    exit 1
fi
