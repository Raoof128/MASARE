#!/bin/bash
#
# REMnux VM Setup Script for MASARE
# Purpose: Automated deployment of REMnux analysis VM with malware analysis tools
# Author: Security Research Team
# Last Updated: 2025-11-15
#

set -e  # Exit on error
set -u  # Exit on undefined variable

# Color output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration variables
VM_NAME="REMnux_MASARE"
VM_MEMORY=4096  # 4GB RAM
VM_CPUS=2
VM_VRAM=128
VM_DISK_SIZE=102400  # 100GB
NETWORK_NAME="vboxnet0"
NETWORK_CIDR="192.168.1.0/24"
VM_IP="192.168.1.10"
GATEWAY_IP="192.168.1.1"

# REMnux ISO (download from: https://remnux.org)
REMNUX_ISO="$HOME/Downloads/remnux-v7-focal.ova"

echo -e "${GREEN}╔══════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║          MASARE - REMnux VM Setup Script                ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════════════╝${NC}"
echo ""

# Check if VirtualBox is installed
check_virtualbox() {
    echo -e "${YELLOW}[*] Checking VirtualBox installation...${NC}"
    if ! command -v VBoxManage &> /dev/null; then
        echo -e "${RED}[✗] VirtualBox is not installed!${NC}"
        echo -e "${YELLOW}[i] Install from: https://www.virtualbox.org/wiki/Downloads${NC}"
        exit 1
    fi
    VBOX_VERSION=$(VBoxManage --version | cut -d 'r' -f 1)
    echo -e "${GREEN}[✓] VirtualBox $VBOX_VERSION installed${NC}"
}

# Create Host-Only network adapter
create_hostonly_network() {
    echo -e "${YELLOW}[*] Creating Host-Only network adapter...${NC}"

    # Check if network exists
    if VBoxManage list hostonlyifs | grep -q "$NETWORK_NAME"; then
        echo -e "${YELLOW}[i] Network $NETWORK_NAME already exists, removing...${NC}"
        VBoxManage hostonlyif remove "$NETWORK_NAME" || true
    fi

    # Create new Host-Only network
    VBoxManage hostonlyif create

    # Get the created interface name (usually vboxnet0)
    HOSTONLY_IF=$(VBoxManage list hostonlyifs | grep -E "^Name:" | head -1 | awk '{print $2}')

    # Configure IP address
    VBoxManage hostonlyif ipconfig "$HOSTONLY_IF" \
        --ip 192.168.1.254 \
        --netmask 255.255.255.0

    echo -e "${GREEN}[✓] Host-Only network created: $HOSTONLY_IF${NC}"
    echo -e "${YELLOW}[i] Network: $NETWORK_CIDR${NC}"
    echo -e "${YELLOW}[i] Host IP: 192.168.1.254${NC}"
}

# Create REMnux VM
create_vm() {
    echo -e "${YELLOW}[*] Creating REMnux VM...${NC}"

    # Check if VM already exists
    if VBoxManage list vms | grep -q "\"$VM_NAME\""; then
        echo -e "${YELLOW}[!] VM $VM_NAME already exists. Delete it? (y/n)${NC}"
        read -r response
        if [[ "$response" =~ ^[Yy]$ ]]; then
            echo -e "${YELLOW}[*] Removing existing VM...${NC}"
            VBoxManage unregistervm "$VM_NAME" --delete || true
        else
            echo -e "${RED}[✗] Aborting setup${NC}"
            exit 1
        fi
    fi

    # Import REMnux OVA
    if [ ! -f "$REMNUX_ISO" ]; then
        echo -e "${RED}[✗] REMnux OVA not found: $REMNUX_ISO${NC}"
        echo -e "${YELLOW}[i] Download from: https://remnux.org${NC}"
        echo -e "${YELLOW}[i] Or update REMNUX_ISO path in script${NC}"
        exit 1
    fi

    echo -e "${YELLOW}[*] Importing REMnux OVA (this may take several minutes)...${NC}"
    VBoxManage import "$REMNUX_ISO" \
        --vsys 0 \
        --vmname "$VM_NAME" \
        --memory $VM_MEMORY \
        --cpus $VM_CPUS

    echo -e "${GREEN}[✓] VM created successfully${NC}"
}

# Configure VM settings
configure_vm() {
    echo -e "${YELLOW}[*] Configuring VM settings...${NC}"

    # Network configuration (Host-Only, no internet access)
    VBoxManage modifyvm "$VM_NAME" \
        --nic1 hostonly \
        --hostonlyadapter1 "$NETWORK_NAME" \
        --nictype1 virtio \
        --macaddress1 080027000010

    # Performance optimizations
    VBoxManage modifyvm "$VM_NAME" \
        --memory $VM_MEMORY \
        --cpus $VM_CPUS \
        --vram $VM_VRAM \
        --accelerate3d off \
        --accelerate2dvideo off

    # Disable unnecessary features (security hardening)
    VBoxManage modifyvm "$VM_NAME" \
        --clipboard disabled \
        --draganddrop disabled \
        --usb off \
        --audio none

    # Boot order
    VBoxManage modifyvm "$VM_NAME" \
        --boot1 disk \
        --boot2 none \
        --boot3 none \
        --boot4 none

    echo -e "${GREEN}[✓] VM configured${NC}"
}

# Create shared folder for malware samples (read-only)
create_shared_folders() {
    echo -e "${YELLOW}[*] Creating shared folders...${NC}"

    # Create host directories if they don't exist
    mkdir -p "$HOME/MASARE/shared/malware/samples"
    mkdir -p "$HOME/MASARE/shared/analysis/results"
    mkdir -p "$HOME/MASARE/shared/logs"

    # Add shared folders (read-only for samples)
    VBoxManage sharedfolder add "$VM_NAME" \
        --name "malware_samples" \
        --hostpath "$HOME/MASARE/shared/malware/samples" \
        --readonly \
        --automount

    VBoxManage sharedfolder add "$VM_NAME" \
        --name "analysis_results" \
        --hostpath "$HOME/MASARE/shared/analysis/results" \
        --automount

    VBoxManage sharedfolder add "$VM_NAME" \
        --name "logs" \
        --hostpath "$HOME/MASARE/shared/logs" \
        --automount

    echo -e "${GREEN}[✓] Shared folders created${NC}"
}

# Create baseline snapshot
create_snapshot() {
    echo -e "${YELLOW}[*] Creating baseline snapshot...${NC}"

    VBoxManage snapshot "$VM_NAME" take "baseline_clean" \
        --description "Clean REMnux installation ($(date +%Y-%m-%d))"

    echo -e "${GREEN}[✓] Baseline snapshot created${NC}"
}

# Start VM
start_vm() {
    echo -e "${YELLOW}[*] Starting VM...${NC}"

    VBoxManage startvm "$VM_NAME" --type headless

    echo -e "${GREEN}[✓] VM started in headless mode${NC}"
    echo -e "${YELLOW}[i] Connect via SSH: ssh remnux@$VM_IP${NC}"
    echo -e "${YELLOW}[i] Default password: malware${NC}"
}

# Post-installation instructions
post_install_instructions() {
    echo ""
    echo -e "${GREEN}╔══════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║              REMnux VM Setup Complete!                   ║${NC}"
    echo -e "${GREEN}╚══════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${YELLOW}Next Steps:${NC}"
    echo ""
    echo -e "1. Wait for VM to boot (30-60 seconds)"
    echo -e "2. Connect via SSH:"
    echo -e "   ${GREEN}ssh remnux@$VM_IP${NC}"
    echo -e "   Password: ${GREEN}malware${NC}"
    echo ""
    echo -e "3. Configure static IP address (inside VM):"
    echo -e "   ${GREEN}sudo nmtui${NC}"
    echo -e "   - Edit connection"
    echo -e "   - IPv4: Manual"
    echo -e "   - Address: $VM_IP/24"
    echo -e "   - Gateway: $GATEWAY_IP"
    echo -e "   - DNS: $GATEWAY_IP"
    echo ""
    echo -e "4. Install additional tools (inside VM):"
    echo -e "   ${GREEN}sudo apt update && sudo apt upgrade -y${NC}"
    echo -e "   ${GREEN}pip install cuckoo yara-python volatility3${NC}"
    echo ""
    echo -e "5. Mount shared folders (inside VM):"
    echo -e "   ${GREEN}sudo mount -t vboxsf malware_samples /mnt/malware_samples${NC}"
    echo -e "   ${GREEN}sudo mount -t vboxsf analysis_results /mnt/analysis_results${NC}"
    echo ""
    echo -e "6. Run isolation test:"
    echo -e "   ${GREEN}bash /mnt/analysis_results/tests/test_isolation.sh${NC}"
    echo ""
    echo -e "${YELLOW}Security Checklist:${NC}"
    echo -e "  ☐ Verify no internet access (ping 8.8.8.8 should FAIL)"
    echo -e "  ☐ Verify inter-VM communication (ping 192.168.1.20)"
    echo -e "  ☐ Install Cuckoo Sandbox"
    echo -e "  ☐ Configure Ghidra headless mode"
    echo -e "  ☐ Create analysis scripts"
    echo ""
    echo -e "${GREEN}VM Management Commands:${NC}"
    echo -e "  Stop VM:     ${YELLOW}VBoxManage controlvm $VM_NAME poweroff${NC}"
    echo -e "  Start VM:    ${YELLOW}VBoxManage startvm $VM_NAME --type headless${NC}"
    echo -e "  Snapshot:    ${YELLOW}VBoxManage snapshot $VM_NAME take \"snapshot_name\"${NC}"
    echo -e "  Restore:     ${YELLOW}VBoxManage snapshot $VM_NAME restore baseline_clean${NC}"
    echo ""
}

# Main execution
main() {
    check_virtualbox
    create_hostonly_network
    create_vm
    configure_vm
    create_shared_folders
    create_snapshot
    start_vm
    post_install_instructions
}

# Run main function
main
