#!/bin/bash
#
# MASARE System Status Check
# Verifies all components are properly configured
#
# Usage: ./check_system.sh

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}╔══════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║         MASARE System Status Check                      ║${NC}"
echo -e "${BLUE}╚══════════════════════════════════════════════════════════╝${NC}"
echo ""

CHECKS_PASSED=0
CHECKS_FAILED=0

check_item() {
    local name="$1"
    local command="$2"

    printf "%-50s" "$name"

    if eval "$command" &> /dev/null; then
        echo -e "${GREEN}✓ OK${NC}"
        ((CHECKS_PASSED++))
        return 0
    else
        echo -e "${RED}✗ FAIL${NC}"
        ((CHECKS_FAILED++))
        return 1
    fi
}

echo -e "${YELLOW}Python Environment:${NC}"
check_item "Python 3.11+ installed" "python3 --version | grep -E 'Python 3\.(11|12|13)'"
check_item "pip installed" "pip3 --version"
check_item "requests module" "python3 -c 'import requests'"
check_item "jinja2 module" "python3 -c 'import jinja2'"
check_item "yara-python module" "python3 -c 'import yara'"

echo ""
echo -e "${YELLOW}VirtualBox/VM Environment:${NC}"
check_item "VirtualBox installed" "VBoxManage --version"
check_item "REMnux VM exists" "VBoxManage list vms | grep -q REMnux_MASARE"
check_item "FLARE VM exists" "VBoxManage list vms | grep -q FLARE_MASARE"
check_item "Host-Only network exists" "VBoxManage list hostonlyifs | grep -q vboxnet0"

echo ""
echo -e "${YELLOW}Network Configuration:${NC}"
if VBoxManage list runningvms | grep -q REMnux_MASARE; then
    check_item "REMnux VM running" "true"
    check_item "REMnux reachable" "ping -c 1 -W 2 192.168.1.10"
else
    echo -e "${YELLOW}REMnux VM not running - skipping network checks${NC}"
fi

echo ""
echo -e "${YELLOW}Directory Structure:${NC}"
check_item "Analysis directory exists" "test -d analysis"
check_item "Automation directory exists" "test -d automation"
check_item "Detection directory exists" "test -d detection"
check_item "Infrastructure directory exists" "test -d infrastructure"
check_item "Tests directory exists" "test -d tests"
check_item "Docs directory exists" "test -d docs"

echo ""
echo -e "${YELLOW}Configuration Files:${NC}"
check_item "README.md exists" "test -f README.md"
check_item "ARCHITECTURE.md exists" "test -f ARCHITECTURE.md"
check_item "LEGAL_FRAMEWORK.md exists" "test -f LEGAL_FRAMEWORK.md"
check_item "requirements.txt exists" "test -f requirements.txt"
check_item "Setup guide exists" "test -f docs/SETUP_GUIDE.md"

echo ""
echo -e "${YELLOW}Analysis Scripts:${NC}"
check_item "Cuckoo orchestrator" "test -x analysis/cuckoo/orchestrator.py"
check_item "Ghidra analyzer" "test -f analysis/ghidra/analyze_binary.py"
check_item "YARA generator" "test -x detection/yara/signature_generator.py"
check_item "Report generator" "test -x automation/report_generator.py"
check_item "MITRE mapper" "test -x automation/mitre_attack_mapper.py"
check_item "Batch analyzer" "test -x automation/batch_analyzer.py"

echo ""
echo -e "${YELLOW}Infrastructure Scripts:${NC}"
check_item "REMnux setup script" "test -x infrastructure/virtualbox/remnux_setup.sh"
check_item "FLARE VM setup script" "test -f infrastructure/virtualbox/flare_vm_setup.ps1"
check_item "Isolation test script" "test -x tests/test_isolation.sh"

echo ""
echo -e "${YELLOW}Templates & Configs:${NC}"
check_item "Cuckoo config template" "test -f analysis/cuckoo/config/cuckoo.conf.template"
check_item "VirtualBox config template" "test -f analysis/cuckoo/config/virtualbox.conf.template"
check_item "pfSense config" "test -f infrastructure/firewall/pfsense_config.xml"
check_item "Docker Compose config" "test -f infrastructure/docker/docker-compose.yml"
check_item "Sigma rules" "test -f detection/sigma/malware_detection_rules.yml"

echo ""
echo -e "${BLUE}╔══════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║                   SUMMARY                                ║${NC}"
echo -e "${BLUE}╚══════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "Total Checks: $((CHECKS_PASSED + CHECKS_FAILED))"
echo -e "${GREEN}Passed: $CHECKS_PASSED${NC}"
echo -e "${RED}Failed: $CHECKS_FAILED${NC}"
echo ""

if [ $CHECKS_FAILED -eq 0 ]; then
    echo -e "${GREEN}✓ System check PASSED - MASARE is ready for use${NC}"
    exit 0
else
    echo -e "${YELLOW}⚠ Some checks failed - review issues above${NC}"
    echo -e "${YELLOW}To install missing dependencies:${NC}"
    echo -e "  pip3 install -r requirements.txt"
    echo -e "  bash infrastructure/virtualbox/remnux_setup.sh"
    exit 1
fi
