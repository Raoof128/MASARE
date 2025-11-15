# MASARE Setup Guide

## Complete Step-by-Step Deployment Instructions

**Estimated Setup Time:** 2-3 hours (excluding VM downloads)

---

## Prerequisites

### Hardware Requirements

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| CPU | 4 cores | 8+ cores (Intel VT-x / AMD-V required) |
| RAM | 12GB | 16GB+ |
| Storage | 200GB free | 300GB+ SSD |
| Platform | macOS, Linux, Windows | macOS M-series or Linux |

### Software Requirements

- **Hypervisor**: VirtualBox 7.0+ OR UTM (for M-series Mac)
- **Python**: 3.11 or later
- **Git**: For cloning repository
- **Network**: Ability to create Host-Only network adapter

---

## Phase 1: Repository Setup (10 minutes)

### 1.1 Clone Repository

```bash
git clone https://github.com/Raoof128/MASARE.git
cd MASARE
```

### 1.2 Install Python Dependencies

```bash
# Create virtual environment (recommended)
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

Create `requirements.txt`:
```txt
requests>=2.31.0
jinja2>=3.1.2
yara-python>=4.3.1
pandas>=2.1.0
```

---

## Phase 2: VM Infrastructure Setup (60-90 minutes)

### 2.1 Download VM Images

**REMnux (Linux Analysis VM):**
1. Visit: https://remnux.org
2. Download REMnux OVA (7.0+)
3. Save to `~/Downloads/remnux-v7-focal.ova`

**FLARE VM (Windows Sandbox):**
1. Download Windows 10 Enterprise ISO from Microsoft
2. Save to `~/Downloads/Win10_Enterprise_x64.iso`
3. Note: FLARE VM tools installed post-Windows installation

### 2.2 Deploy REMnux VM

**On macOS/Linux:**
```bash
cd infrastructure/virtualbox
chmod +x remnux_setup.sh
./remnux_setup.sh
```

**Manual Steps:**
1. Wait for VM to boot (~2 minutes)
2. SSH into VM:
   ```bash
   ssh remnux@192.168.1.10
   # Password: malware
   ```

3. Configure static IP:
   ```bash
   sudo nmtui
   # Select: Edit a connection
   # Choose: Wired connection 1
   # IPv4 Configuration: Manual
   #   Address: 192.168.1.10/24
   #   Gateway: 192.168.1.1
   #   DNS: 192.168.1.1
   # Save and quit
   sudo systemctl restart NetworkManager
   ```

4. Update system and install tools:
   ```bash
   sudo apt update && sudo apt upgrade -y
   sudo apt install -y python3-pip git wget curl

   # Install Cuckoo dependencies
   sudo apt install -y python3-dev libffi-dev libssl-dev
   sudo apt install -y postgresql postgresql-contrib
   sudo apt install -y mongodb-server

   # Install Python packages
   pip3 install cuckoo yara-python volatility3
   ```

5. Mount shared folders:
   ```bash
   sudo mkdir -p /mnt/malware_samples /mnt/analysis_results /mnt/logs
   sudo mount -t vboxsf malware_samples /mnt/malware_samples
   sudo mount -t vboxsf analysis_results /mnt/analysis_results
   sudo mount -t vboxsf logs /mnt/logs

   # Add to /etc/fstab for auto-mount
   echo "malware_samples /mnt/malware_samples vboxsf defaults 0 0" | sudo tee -a /etc/fstab
   echo "analysis_results /mnt/analysis_results vboxsf defaults 0 0" | sudo tee -a /etc/fstab
   echo "logs /mnt/logs vboxsf defaults 0 0" | sudo tee -a /etc/fstab
   ```

6. Install Ghidra:
   ```bash
   cd /opt
   sudo wget https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_11.0_build/ghidra_11.0_PUBLIC_20231222.zip
   sudo unzip ghidra_11.0_PUBLIC_20231222.zip
   sudo mv ghidra_11.0_PUBLIC /opt/ghidra
   ```

### 2.3 Deploy FLARE VM

**On Windows Host (PowerShell as Administrator):**
```powershell
cd infrastructure\virtualbox
.\flare_vm_setup.ps1
```

**Manual Steps:**
1. Start VM and install Windows 10
2. After installation, run post-install script:
   ```powershell
   .\flare_post_install.ps1
   ```

3. Install FLARE VM tools:
   ```powershell
   # Download FLARE VM installer
   git clone https://github.com/mandiant/flare-vm.git C:\flare-vm
   cd C:\flare-vm

   # Install (takes 2-3 hours)
   .\install.ps1
   ```

4. Install Cuckoo Agent:
   ```powershell
   # On FLARE VM, download agent.py from REMnux
   # (After Cuckoo is configured on REMnux)
   Invoke-WebRequest -Uri http://192.168.1.10:8000/agent.py -OutFile C:\cuckoo_agent\agent.py

   # Create auto-start task
   $action = New-ScheduledTaskAction -Execute "python.exe" -Argument "C:\cuckoo_agent\agent.py"
   $trigger = New-ScheduledTaskTrigger -AtStartup
   Register-ScheduledTask -TaskName "CuckooAgent" -Action $action -Trigger $trigger -User "SYSTEM"
   ```

---

## Phase 3: Cuckoo Sandbox Configuration (30 minutes)

**On REMnux VM:**

### 3.1 Initialize Cuckoo

```bash
cuckoo init

# Edit configuration
nano ~/.cuckoo/conf/cuckoo.conf
# Change:
#   machinery = virtualbox
#   [resultserver]
#   ip = 192.168.1.10
#   port = 2042

nano ~/.cuckoo/conf/virtualbox.conf
# Add FLARE VM:
#   [FLARE_MASARE]
#   label = FLARE_MASARE
#   platform = windows
#   ip = 192.168.1.20
#   snapshot = baseline_clean

nano ~/.cuckoo/conf/routing.conf
# Disable internet routing:
#   [routing]
#   route = none
#   internet = none
```

### 3.2 Start Cuckoo

```bash
# In separate terminals:

# Terminal 1: Cuckoo main process
cuckoo -d

# Terminal 2: Web interface
cuckoo web runserver 192.168.1.10:8000

# Terminal 3: Process monitoring
cuckoo process auto
```

### 3.3 Verify Cuckoo

```bash
# Submit test sample
cuckoo submit /bin/ls
cuckoo submit --url http://www.example.com
```

Access web UI: `http://192.168.1.10:8000`

---

## Phase 4: Network Isolation Verification (10 minutes)

### 4.1 Run Isolation Tests

**On REMnux VM:**
```bash
cd /mnt/analysis_results
chmod +x tests/test_isolation.sh
./tests/test_isolation.sh
```

**Expected Output:**
```
✓ ALL ISOLATION TESTS PASSED
  Lab is properly isolated from internet
  Safe to analyze malware samples
```

### 4.2 Manual Verification

```bash
# Should FAIL (no internet)
ping -c 1 8.8.8.8
curl http://www.google.com

# Should SUCCEED (internal network)
ping -c 1 192.168.1.1  # Gateway
ping -c 1 192.168.1.20 # FLARE VM
```

---

## Phase 5: Analysis Pipeline Deployment (20 minutes)

### 5.1 Copy Analysis Scripts to REMnux

**On Host Machine:**
```bash
# Copy scripts to REMnux via shared folder
cp -r analysis /path/to/MASARE/shared/
cp -r automation /path/to/MASARE/shared/
cp -r detection /path/to/MASARE/shared/
```

**On REMnux VM:**
```bash
# Link scripts to local directory
ln -s /mnt/analysis_results/analysis ~/masare_analysis
ln -s /mnt/analysis_results/automation ~/masare_automation
ln -s /mnt/analysis_results/detection ~/masare_detection

# Make executable
chmod +x ~/masare_analysis/cuckoo/orchestrator.py
chmod +x ~/masare_analysis/ghidra/analyze_binary.py
chmod +x ~/masare_automation/*.py
chmod +x ~/masare_detection/yara/signature_generator.py
```

### 5.2 Test Analysis Pipeline

```bash
# Create test malware sample directory
mkdir -p /shared/malware/samples/test

# Download test samples (from VirusShare - requires account)
# Or use EICAR test file
echo 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > /tmp/eicar.com

# Encrypt sample
gpg --symmetric --cipher-algo AES256 /tmp/eicar.com
mv /tmp/eicar.com.gpg /shared/malware/samples/test/

# Decrypt and analyze
gpg --decrypt /shared/malware/samples/test/eicar.com.gpg > /tmp/eicar.com
python3 ~/masare_analysis/cuckoo/orchestrator.py --sample /tmp/eicar.com
```

---

## Phase 6: Sample Acquisition & Storage (15 minutes)

### 6.1 Create Encrypted Storage

```bash
# On host machine
mkdir -p ~/MASARE/shared/malware/samples

# Download samples from approved sources
# Example: VirusShare (requires registration)
# https://virusshare.com

# Encrypt each sample
for sample in ~/Downloads/malware/*.exe; do
    gpg --symmetric --cipher-algo AES256 "$sample"
    mv "${sample}.gpg" ~/MASARE/shared/malware/samples/
    shred -u -z -n 3 "$sample"  # Secure delete original
done
```

### 6.2 Sample Manifest

Create `~/MASARE/shared/malware/samples/manifest.json`:
```json
{
  "samples": [
    {
      "filename": "emotet_variant_2024.exe.gpg",
      "sha256": "abc123...",
      "source": "VirusShare",
      "source_url": "https://virusshare.com/file/abc123",
      "family": "Emotet",
      "acquired_date": "2025-11-15",
      "encryption": "GPG AES-256"
    }
  ]
}
```

---

## Phase 7: Snapshot Management (10 minutes)

### 7.1 Create Baseline Snapshots

**REMnux VM:**
```bash
VBoxManage snapshot REMnux_MASARE take "baseline_configured" \
    --description "Clean state with Cuckoo and tools installed ($(date +%Y-%m-%d))"
```

**FLARE VM:**
```bash
VBoxManage snapshot FLARE_MASARE take "baseline_clean" \
    --description "Clean Windows 10 with FLARE tools ($(date +%Y-%m-%d))"
```

### 7.2 Test Snapshot Restore

```bash
# Restore to baseline
VBoxManage snapshot REMnux_MASARE restore baseline_configured
VBoxManage startvm REMnux_MASARE --type headless
```

---

## Troubleshooting

### Issue: VM Cannot Reach Other VMs

**Solution:**
```bash
# Verify Host-Only network
VBoxManage list hostonlyifs

# Check VM network settings
VBoxManage showvminfo REMnux_MASARE | grep NIC

# Restart network on VM
sudo systemctl restart NetworkManager
```

### Issue: Cuckoo Cannot Connect to FLARE VM

**Solution:**
1. Verify FLARE VM IP: `192.168.1.20`
2. Check Windows Firewall (should be disabled)
3. Verify Cuckoo Agent running on FLARE VM:
   ```powershell
   Get-Process python
   ```
4. Check Cuckoo logs:
   ```bash
   tail -f ~/.cuckoo/log/cuckoo.log
   ```

### Issue: Internet Access Detected During Isolation Test

**Solution:**
```bash
# Remove default route
sudo ip route del default

# Verify pfSense firewall rules
# Check VirtualBox network adapter settings (must be Host-Only)
```

---

## Next Steps

1. **Analyze First Sample**: [ANALYSIS_WORKFLOW.md](ANALYSIS_WORKFLOW.md)
2. **Generate YARA Rules**: See detection/yara/signature_generator.py
3. **Create Reports**: See automation/report_generator.py
4. **MITRE Mapping**: See automation/mitre_attack_mapper.py

---

## Security Checklist

Before analyzing malware, verify:

- [ ] Network isolation tests passed
- [ ] No internet access from VMs
- [ ] Baseline snapshots created
- [ ] Malware samples encrypted (AES-256)
- [ ] Shared folders mounted (read-only for samples)
- [ ] Cuckoo Sandbox running
- [ ] FLARE VM Cuckoo Agent running
- [ ] pfSense firewall blocking egress
- [ ] Analysis scripts accessible on REMnux

---

**Setup Complete! You're ready to analyze malware safely.**

For questions or issues, see [TROUBLESHOOTING.md](TROUBLESHOOTING.md)
