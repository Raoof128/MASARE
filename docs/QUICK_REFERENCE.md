# MASARE Quick Reference Guide

## Essential Commands Cheat Sheet

---

## VM Management

```bash
# Start VMs
VBoxManage startvm REMnux_MASARE --type headless
VBoxManage startvm FLARE_MASARE --type headless

# Stop VMs
VBoxManage controlvm REMnux_MASARE poweroff
VBoxManage controlvm FLARE_MASARE poweroff

# List running VMs
VBoxManage list runningvms

# Create snapshot
VBoxManage snapshot FLARE_MASARE take "snapshot_name"

# Restore snapshot
VBoxManage snapshot FLARE_MASARE restore baseline_clean

# SSH into REMnux
ssh remnux@192.168.1.10  # password: malware
```

---

## System Verification

```bash
# Check system status
./scripts/check_system.sh

# Verify network isolation
./tests/test_isolation.sh

# Check Cuckoo service
curl http://192.168.1.10:8090
```

---

## Sample Management

```bash
# Encrypt malware sample
gpg --symmetric --cipher-algo AES256 malware.exe

# Decrypt sample (to /tmp only!)
gpg --decrypt malware.exe.gpg > /tmp/sample.exe

# Calculate hashes
md5sum /tmp/sample.exe
sha256sum /tmp/sample.exe

# Secure delete
shred -u -z -n 3 /tmp/sample.exe
```

---

## Analysis Commands

```bash
# Single sample analysis
python3 analysis/cuckoo/orchestrator.py --sample /tmp/malware.exe

# Batch analysis (3 parallel workers)
python3 automation/batch_analyzer.py \
    --samples-dir /tmp/samples \
    --parallel 3

# Generate YARA rules
python3 detection/yara/signature_generator.py \
    --sample /tmp/malware.exe \
    --output rules.yar

# MITRE ATT&CK mapping
python3 automation/mitre_attack_mapper.py \
    --analysis-report results/task_123/report.json \
    --navigator mitre_layer.json

# Generate HTML report
python3 automation/report_generator.py \
    --analysis-dir results/task_123
```

---

## Cuckoo Operations

```bash
# Start Cuckoo (on REMnux)
cuckoo -d

# Start web interface
cuckoo web runserver 192.168.1.10:8090

# Submit sample
cuckoo submit /tmp/malware.exe

# View task status
cuckoo submit --url http://example.com

# Process analysis results
cuckoo process auto
```

---

## Network Verification

```bash
# Test isolation (REMnux VM)
ping -c 1 8.8.8.8           # Should FAIL
ping -c 1 192.168.1.20      # Should SUCCEED
ping -c 1 192.168.1.1       # Should SUCCEED

# Check default route
ip route
# Should only show: default via 192.168.1.1

# Check network interfaces
ip addr show

# DNS test
nslookup google.com 192.168.1.1
# Should sinkhole to 192.168.1.1
```

---

## File Locations

```
📁 Project Structure:
├── analysis/
│   ├── cuckoo/orchestrator.py          ← Main analysis script
│   └── ghidra/analyze_binary.py        ← Static analysis
├── automation/
│   ├── batch_analyzer.py               ← Batch processing
│   ├── report_generator.py             ← Report creation
│   └── mitre_attack_mapper.py          ← MITRE mapping
├── detection/
│   └── yara/signature_generator.py     ← YARA rules
├── infrastructure/
│   ├── virtualbox/
│   │   ├── remnux_setup.sh             ← REMnux deployment
│   │   └── flare_vm_setup.ps1          ← FLARE deployment
│   ├── firewall/pfsense_config.xml     ← Firewall config
│   └── docker/docker-compose.yml       ← Docker alternative
├── tests/
│   └── test_isolation.sh               ← Isolation tests
├── docs/
│   ├── SETUP_GUIDE.md                  ← Setup instructions
│   ├── ANALYSIS_WORKFLOW.md            ← Analysis process
│   └── TROUBLESHOOTING.md              ← Problem solving
└── scripts/
    └── check_system.sh                 ← System status

📁 Shared Directories (VMs):
/shared/malware/samples/                 ← Encrypted samples (AES-256)
/shared/analysis/results/                ← Analysis reports
/shared/logs/                            ← System logs
```

---

## Common Workflows

### Workflow 1: Analyze Single Sample

```bash
# 1. Verify isolation
./tests/test_isolation.sh

# 2. Decrypt sample
gpg --decrypt ~/MASARE/shared/malware/samples/sample.exe.gpg > /tmp/sample.exe

# 3. Run analysis
python3 analysis/cuckoo/orchestrator.py --sample /tmp/sample.exe

# 4. View results
firefox ~/MASARE/shared/analysis/results/task_*/report.html

# 5. Cleanup
shred -u -z -n 3 /tmp/sample.exe
```

### Workflow 2: Batch Analysis

```bash
# 1. Prepare samples
mkdir /tmp/batch
for f in ~/MASARE/shared/malware/samples/*.gpg; do
    gpg --decrypt "$f" > "/tmp/batch/$(basename $f .gpg)"
done

# 2. Run batch analysis
python3 automation/batch_analyzer.py --samples-dir /tmp/batch --parallel 3

# 3. Generate consolidated IOC feed
python3 automation/report_generator.py \
    --ioc-feed ~/MASARE/shared/analysis/results \
    --output iocs.json

# 4. Cleanup
shred -u -z -n 3 /tmp/batch/*
```

### Workflow 3: Generate & Test YARA Rules

```bash
# 1. Generate rules
python3 detection/yara/signature_generator.py \
    --sample /tmp/malware.exe \
    --analysis-report results/task_123/report.json \
    --output detection.yar

# 2. Test rules
yara detection.yar /tmp/malware.exe
# Should match: emotet_variant_hash, emotet_variant_behavior

# 3. Test against benign files (should NOT match)
yara detection.yar /bin/ls
# (no output = good!)

# 4. Deploy to production
cp detection.yar /etc/yara/rules/
```

---

## Troubleshooting Quick Fixes

### Issue: VM won't start
```bash
# Check VirtualBox status
sudo systemctl status vboxdrv
sudo /sbin/vboxconfig
VBoxManage list vms
```

### Issue: Can't reach FLARE VM
```bash
# Verify network
VBoxManage showvminfo FLARE_MASARE | grep NIC
ping 192.168.1.20

# On FLARE VM, check IP:
ipconfig
```

### Issue: Cuckoo connection failed
```bash
# Check Cuckoo running
curl http://192.168.1.10:8090

# Check FLARE VM agent
# On FLARE VM:
Get-Process python
netstat -an | Select-String 2042
```

### Issue: Internet access detected (CRITICAL!)
```bash
# Remove default gateway
sudo ip route del default

# Verify isolation
ping -c 1 8.8.8.8  # Must FAIL

# Check VM network type
VBoxManage showvminfo REMnux_MASARE | grep "NIC 1"
# Must be: Host-only
```

---

## Performance Optimization

```bash
# Increase VM RAM (from 4GB to 8GB)
VBoxManage modifyvm FLARE_MASARE --memory 8192

# Add more CPUs
VBoxManage modifyvm FLARE_MASARE --cpus 4

# Enable nested virtualization
VBoxManage modifyvm FLARE_MASARE --nested-hw-virt on

# Use RAM disk for /tmp (faster analysis)
sudo mount -t tmpfs -o size=2G tmpfs /tmp
```

---

## Keyboard Shortcuts & Tips

- **Tab completion**: Use tab to auto-complete file paths
- **History search**: `Ctrl+R` to search command history
- **Screen sessions**: Use `screen` or `tmux` for long-running tasks
- **Log monitoring**: `tail -f /shared/logs/*.log`
- **Quick hash**: `sha256sum <file> | awk '{print $1}'`

---

## Emergency Procedures

### Suspected Malware Escape

```bash
# 1. IMMEDIATE SHUTDOWN
VBoxManage controlvm REMnux_MASARE poweroff
VBoxManage controlvm FLARE_MASARE poweroff

# 2. DISCONNECT HOST FROM NETWORK
sudo ifconfig eth0 down

# 3. VERIFY CONTAINMENT
ps aux | grep malware
netstat -tulpn

# 4. RESTORE FROM CLEAN STATE
VBoxManage snapshot REMnux_MASARE restore baseline_clean
VBoxManage snapshot FLARE_MASARE restore baseline_clean

# 5. DOCUMENT INCIDENT
# See LEGAL_FRAMEWORK.md Section 7
```

---

## Help & Documentation

- **Full Setup**: `docs/SETUP_GUIDE.md`
- **Analysis Process**: `docs/ANALYSIS_WORKFLOW.md`
- **Troubleshooting**: `docs/TROUBLESHOOTING.md`
- **Architecture**: `ARCHITECTURE.md`
- **Legal/Ethics**: `LEGAL_FRAMEWORK.md`

---

**Quick Reference Version:** 1.0
**Last Updated:** 2025-11-15
