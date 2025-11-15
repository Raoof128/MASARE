#!/bin/bash
#
# Network Isolation Testing Script for MASARE
# Purpose: Verify that malware analysis lab is properly isolated
# Author: Security Research Team
# Last Updated: 2025-11-15
#
# Run this script on REMnux VM to verify isolation

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}╔══════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║        MASARE Network Isolation Test Suite              ║${NC}"
echo -e "${BLUE}╚══════════════════════════════════════════════════════════╝${NC}"
echo ""

TESTS_PASSED=0
TESTS_FAILED=0

# Test counter
test_count=0

# Function to run a test
run_test() {
    local test_name="$1"
    local test_command="$2"
    local expected_result="$3"  # "pass" or "fail"

    ((test_count++))
    echo -e "${YELLOW}[Test $test_count] $test_name${NC}"

    if eval "$test_command" &> /dev/null; then
        actual_result="pass"
    else
        actual_result="fail"
    fi

    if [ "$actual_result" == "$expected_result" ]; then
        echo -e "${GREEN}  ✓ PASSED${NC}"
        ((TESTS_PASSED++))
        return 0
    else
        echo -e "${RED}  ✗ FAILED${NC}"
        echo -e "${RED}  Expected: $expected_result, Got: $actual_result${NC}"
        ((TESTS_FAILED++))
        return 1
    fi
}

echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BLUE}1. Internet Connectivity Tests (Should FAIL)${NC}"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

# Test 1: Ping Google DNS (should FAIL)
run_test "Ping 8.8.8.8 (Google DNS) - SHOULD FAIL" \
    "ping -c 1 -W 2 8.8.8.8" \
    "fail"

# Test 2: Ping Cloudflare DNS (should FAIL)
run_test "Ping 1.1.1.1 (Cloudflare DNS) - SHOULD FAIL" \
    "ping -c 1 -W 2 1.1.1.1" \
    "fail"

# Test 3: HTTP request to Google (should FAIL)
run_test "HTTP request to google.com - SHOULD FAIL" \
    "curl -s --connect-timeout 2 http://www.google.com" \
    "fail"

# Test 4: HTTPS request (should FAIL)
run_test "HTTPS request to github.com - SHOULD FAIL" \
    "curl -s --connect-timeout 2 https://github.com" \
    "fail"

# Test 5: DNS resolution of external domain (should FAIL or sinkhole)
run_test "DNS query for external domain - SHOULD FAIL" \
    "host -W 2 google.com 8.8.8.8" \
    "fail"

echo ""
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BLUE}2. Internal Network Connectivity (Should SUCCEED)${NC}"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

# Test 6: Ping gateway (pfSense)
run_test "Ping gateway (192.168.1.1) - SHOULD SUCCEED" \
    "ping -c 1 -W 2 192.168.1.1" \
    "pass"

# Test 7: Ping FLARE VM (if exists)
if ip route | grep -q "192.168.1.20"; then
    run_test "Ping FLARE VM (192.168.1.20) - SHOULD SUCCEED" \
        "ping -c 1 -W 2 192.168.1.20" \
        "pass"
fi

echo ""
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BLUE}3. Network Configuration Verification${NC}"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

# Test 8: Verify no default route to internet
echo -e "${YELLOW}[Test $((test_count+1))] Verify default gateway is NOT internet-routable${NC}"
DEFAULT_GW=$(ip route | grep default | awk '{print $3}')
((test_count++))

if [[ "$DEFAULT_GW" == "192.168.1.1" ]]; then
    echo -e "${GREEN}  ✓ PASSED - Default gateway: $DEFAULT_GW (isolated)${NC}"
    ((TESTS_PASSED++))
else
    echo -e "${RED}  ✗ FAILED - Default gateway: $DEFAULT_GW (potentially exposed!)${NC}"
    ((TESTS_FAILED++))
fi

# Test 9: Verify IP address is in 192.168.1.0/24 range
echo -e "${YELLOW}[Test $((test_count+1))] Verify IP address in isolated range${NC}"
IP_ADDR=$(hostname -I | awk '{print $1}')
((test_count++))

if [[ "$IP_ADDR" == 192.168.1.* ]]; then
    echo -e "${GREEN}  ✓ PASSED - IP address: $IP_ADDR (isolated network)${NC}"
    ((TESTS_PASSED++))
else
    echo -e "${RED}  ✗ FAILED - IP address: $IP_ADDR (wrong network!)${NC}"
    ((TESTS_FAILED++))
fi

# Test 10: Verify DNS server is NOT public DNS
echo -e "${YELLOW}[Test $((test_count+1))] Verify DNS server is NOT public DNS${NC}"
DNS_SERVER=$(cat /etc/resolv.conf | grep nameserver | awk '{print $2}' | head -1)
((test_count++))

if [[ "$DNS_SERVER" != "8.8.8.8" ]] && [[ "$DNS_SERVER" != "1.1.1.1" ]]; then
    echo -e "${GREEN}  ✓ PASSED - DNS server: $DNS_SERVER (not public DNS)${NC}"
    ((TESTS_PASSED++))
else
    echo -e "${RED}  ✗ FAILED - DNS server: $DNS_SERVER (public DNS detected!)${NC}"
    ((TESTS_FAILED++))
fi

echo ""
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BLUE}4. Firewall & Security Checks${NC}"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

# Test 11: Verify no iptables ACCEPT rules for outbound traffic
echo -e "${YELLOW}[Test $((test_count+1))] Check for unexpected iptables rules${NC}"
((test_count++))

if sudo iptables -L OUTPUT -n | grep -q "ACCEPT.*0.0.0.0/0"; then
    echo -e "${YELLOW}  ⚠ WARNING - Permissive iptables rules detected${NC}"
    sudo iptables -L OUTPUT -n | grep "ACCEPT.*0.0.0.0/0"
else
    echo -e "${GREEN}  ✓ PASSED - No unexpected outbound rules${NC}"
    ((TESTS_PASSED++))
fi

# Test 12: Verify no active VPN connections
echo -e "${YELLOW}[Test $((test_count+1))] Verify no VPN connections${NC}"
((test_count++))

if ip link show | grep -q "tun\|tap"; then
    echo -e "${RED}  ✗ FAILED - VPN interface detected (isolation bypass!)${NC}"
    ((TESTS_FAILED++))
else
    echo -e "${GREEN}  ✓ PASSED - No VPN interfaces${NC}"
    ((TESTS_PASSED++))
fi

echo ""
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${BLUE}5. Service Availability Tests${NC}"
echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""

# Test 13: Check if Cuckoo service is running (optional)
if command -v cuckoo &> /dev/null; then
    echo -e "${YELLOW}[Test $((test_count+1))] Verify Cuckoo Sandbox availability${NC}"
    ((test_count++))

    if pgrep -f cuckoo > /dev/null; then
        echo -e "${GREEN}  ✓ PASSED - Cuckoo Sandbox is running${NC}"
        ((TESTS_PASSED++))
    else
        echo -e "${YELLOW}  ⚠ WARNING - Cuckoo Sandbox not running (start manually)${NC}"
    fi
fi

# Test 14: Check shared folders (if mounted)
if mount | grep -q "vboxsf"; then
    echo -e "${YELLOW}[Test $((test_count+1))] Verify shared folders mounted${NC}"
    ((test_count++))
    echo -e "${GREEN}  ✓ PASSED - Shared folders mounted:${NC}"
    mount | grep vboxsf | while read line; do
        echo -e "${GREEN}    - $line${NC}"
    done
    ((TESTS_PASSED++))
fi

echo ""
echo -e "${BLUE}╔══════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║                    TEST SUMMARY                          ║${NC}"
echo -e "${BLUE}╚══════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "Total Tests:   $test_count"
echo -e "${GREEN}Passed:        $TESTS_PASSED${NC}"
echo -e "${RED}Failed:        $TESTS_FAILED${NC}"
echo ""

if [ $TESTS_FAILED -eq 0 ]; then
    echo -e "${GREEN}╔══════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║   ✓✓✓ ALL ISOLATION TESTS PASSED ✓✓✓                    ║${NC}"
    echo -e "${GREEN}║   Lab is properly isolated from internet                ║${NC}"
    echo -e "${GREEN}║   Safe to analyze malware samples                       ║${NC}"
    echo -e "${GREEN}╚══════════════════════════════════════════════════════════╝${NC}"
    exit 0
else
    echo -e "${RED}╔══════════════════════════════════════════════════════════╗${NC}"
    echo -e "${RED}║   ✗✗✗ ISOLATION TEST FAILURES DETECTED ✗✗✗              ║${NC}"
    echo -e "${RED}║   DO NOT ANALYZE MALWARE UNTIL ISSUES RESOLVED          ║${NC}"
    echo -e "${RED}║   Review failed tests above                             ║${NC}"
    echo -e "${RED}╚══════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${YELLOW}Recommended Actions:${NC}"
    echo -e "1. Verify VirtualBox/UTM network configuration (Host-Only mode)"
    echo -e "2. Check pfSense firewall rules (block all egress)"
    echo -e "3. Verify no VPN or proxy connections"
    echo -e "4. Restart VMs and re-run this test"
    echo ""
    exit 1
fi
