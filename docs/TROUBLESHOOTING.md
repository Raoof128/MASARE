# MASARE Troubleshooting Guide

## Common Issues and Solutions

---

## 1. VM Network Issues

### Issue: REMnux VM cannot reach FLARE VM (or vice versa)

**Symptoms:**
```bash
ping 192.168.1.20
# Destination Host Unreachable
```

**Solutions:**

**A. Verify Host-Only Network Configuration**
```bash
# Check VirtualBox networks
VBoxManage list hostonlyifs

# Verify network exists and has correct IP
# Should show:
#   Name:     vboxnet0
#   IP:       192.168.1.254
#   Netmask:  255.255.255.0
```

**B. Check VM Network Adapter**
```bash
# Verify VM is using correct adapter
VBoxManage showvminfo REMnux_MASARE | grep NIC

# Should show: NIC 1: ... Host-only Interface 'vboxnet0'
```

**C. Restart VirtualBox Network Service**
```bash
# On Linux/macOS
sudo systemctl restart vboxdrv
# Or reinstall VirtualBox kernel modules
sudo /sbin/vboxconfig

# On Windows (PowerShell as Admin)
Restart-Service -Name "VBoxNetAdp"
```

**D. Verify VM IP Configuration**

On REMnux:
```bash
ip addr show
# Should see: inet 192.168.1.10/24

# If DHCP assigned wrong IP:
sudo nmtui
# Set manual IP: 192.168.1.10/24, Gateway: 192.168.1.1
```

On FLARE VM:
```powershell
ipconfig
# Should see: IPv4 Address: 192.168.1.20

# If wrong IP:
$adapter = Get-NetAdapter
New-NetIPAddress -InterfaceIndex $adapter.ifIndex -IPAddress "192.168.1.20" -PrefixLength 24 -DefaultGateway "192.168.1.1"
```

---

## 2. Cuckoo Sandbox Issues

### Issue: Cuckoo cannot connect to FLARE VM

**Symptoms:**
```
ERROR: Unable to connect to guest (192.168.1.20)
ERROR: Analysis failed
```

**Solutions:**

**A. Verify Cuckoo Agent is Running on FLARE VM**

On FLARE VM:
```powershell
# Check if agent.py is running
Get-Process python

# If not running, start manually:
python C:\cuckoo_agent\agent.py

# Verify listening on port 2042
netstat -an | Select-String "2042"
# Should show: TCP    0.0.0.0:2042    LISTENING
```

**B. Check Windows Firewall**

On FLARE VM:
```powershell
# Disable firewall (analysis VM only!)
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False

# Verify disabled
Get-NetFirewallProfile | Select Name, Enabled
```

**C. Verify Cuckoo Configuration**

On REMnux:
```bash
# Check VirtualBox config
cat ~/.cuckoo/conf/virtualbox.conf

# Verify:
#   [FLARE_MASARE]
#   ip = 192.168.1.20
#   resultserver_ip = 192.168.1.10
#   resultserver_port = 2042

# Test network connectivity
ping 192.168.1.20
telnet 192.168.1.20 2042  # Should connect
```

**D. Check VM Snapshot**

```bash
# List snapshots
VBoxManage snapshot FLARE_MASARE list

# Verify 'baseline_clean' exists
# If not, create it:
VBoxManage snapshot FLARE_MASARE take "baseline_clean"
```

---

## 3. Network Isolation Issues

### Issue: Isolation test shows internet access (CRITICAL!)

**Symptoms:**
```bash
./tests/test_isolation.sh
# ✗ FAILED - Ping 8.8.8.8 succeeded (should FAIL)
```

**Solutions:**

**A. Verify Network Adapter Type**
```bash
# Check VM network mode
VBoxManage showvminfo REMnux_MASARE | grep "NIC 1"

# Should show: Host-only
# If shows NAT or Bridged: FIX IMMEDIATELY!

# Fix:
VBoxManage modifyvm REMnux_MASARE --nic1 hostonly --hostonlyadapter1 vboxnet0
```

**B. Remove Default Gateway**

On REMnux:
```bash
# Check default route
ip route

# If default gateway points to internet, remove:
sudo ip route del default

# Add only lab gateway:
sudo ip route add default via 192.168.1.1
```

**C. Check for VPN/Tunnel Interfaces**

On REMnux:
```bash
# List all interfaces
ip link show

# If tun0, tap0, or wg0 exists, malware could escape!
# Remove VPN:
sudo ip link set tun0 down
sudo ip link delete tun0
```

**D. Verify pfSense Firewall Rules**

Access pfSense web interface: http://192.168.1.1

Check firewall rules:
1. **WAN interface**: ALL traffic BLOCKED
2. **LAN interface**: Only inter-VM traffic ALLOWED
3. **No NAT rules** (prevents internet masquerading)

---

## 4. Analysis Script Errors

### Issue: `orchestrator.py` fails with "Connection refused"

**Symptoms:**
```bash
python3 orchestrator.py --sample malware.exe
# ERROR: Connection refused (192.168.1.10:8090)
```

**Solutions:**

**A. Start Cuckoo Web Interface**
```bash
# In separate terminal:
cuckoo web runserver 192.168.1.10:8090

# Verify running:
curl http://192.168.1.10:8090
# Should return HTML
```

**B. Check Cuckoo API Port**
```bash
# Check if port is listening
netstat -tulpn | grep 8090

# If different port (e.g., 8000), update orchestrator:
# Edit orchestrator.py:
#   cuckoo_url = "http://192.168.1.10:8000"
```

---

### Issue: Ghidra analysis fails with "analyzeHeadless not found"

**Symptoms:**
```bash
python3 batch_analyzer.py --samples-dir /samples
# ERROR: /opt/ghidra/support/analyzeHeadless: No such file or directory
```

**Solutions:**

**A. Verify Ghidra Installation**
```bash
# Check Ghidra path
ls -la /opt/ghidra/support/analyzeHeadless

# If not found, install Ghidra:
cd /opt
sudo wget https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_11.0_build/ghidra_11.0_PUBLIC_20231222.zip
sudo unzip ghidra_11.0_PUBLIC_20231222.zip
sudo mv ghidra_11.0_PUBLIC /opt/ghidra
```

**B. Add Ghidra to PATH**
```bash
echo 'export PATH=$PATH:/opt/ghidra' >> ~/.bashrc
source ~/.bashrc
```

---

## 5. YARA Rule Compilation Errors

### Issue: `yara-python` import error

**Symptoms:**
```bash
python3 signature_generator.py --sample malware.exe
# ModuleNotFoundError: No module named 'yara'
```

**Solutions:**

**A. Install yara-python**
```bash
# Ubuntu/Debian
sudo apt install libyara-dev
pip3 install yara-python

# Verify installation
python3 -c "import yara; print(yara.__version__)"
```

---

### Issue: YARA syntax error in generated rules

**Symptoms:**
```
ERROR: syntax error, unexpected STRING_IDENTIFIER
```

**Solutions:**

**A. Escape Special Characters**

The issue is usually unescaped special characters in strings.

Fix in `signature_generator.py`:
```python
# Ensure proper escaping
escaped = string_value.replace('\\', '\\\\').replace('"', '\\"')
```

**B. Test Rules Manually**
```bash
# Save rule to file
cat > test.yar << 'EOF'
rule test {
  strings:
    $str = "suspicious string"
  condition:
    $str
}
EOF

# Compile
yara test.yar malware.exe
```

---

## 6. Permission Issues

### Issue: "Permission denied" when accessing shared folders

**Symptoms:**
```bash
ls /mnt/malware_samples
# Permission denied
```

**Solutions:**

**A. Add User to vboxsf Group**

On REMnux:
```bash
sudo usermod -aG vboxsf $USER
# Logout and login again

# Verify group membership
groups
# Should include: vboxsf
```

**B. Mount with Proper Permissions**
```bash
sudo mount -t vboxsf -o uid=1000,gid=1000 malware_samples /mnt/malware_samples
```

---

## 7. VM Performance Issues

### Issue: Analysis is very slow (>10 minutes per sample)

**Solutions:**

**A. Increase VM Resources**
```bash
# Increase RAM (from 4GB to 8GB)
VBoxManage modifyvm FLARE_MASARE --memory 8192

# Add more CPUs
VBoxManage modifyvm FLARE_MASARE --cpus 4

# Enable hardware virtualization
VBoxManage modifyvm FLARE_MASARE --nested-hw-virt on
```

**B. Use SSD for VM Storage**

Move VM to SSD:
```bash
# Export VM
VBoxManage export FLARE_MASARE -o /ssd/path/FLARE.ova

# Import to SSD location
VBoxManage import /ssd/path/FLARE.ova
```

**C. Disable Unnecessary Services on FLARE VM**

On FLARE VM:
```powershell
# Disable Windows Search
Stop-Service wsearch
Set-Service wsearch -StartupType Disabled

# Disable Windows Update
Stop-Service wuauserv
Set-Service wuauserv -StartupType Disabled
```

---

## 8. Sample Decryption Issues

### Issue: Cannot decrypt GPG-encrypted samples

**Symptoms:**
```bash
gpg --decrypt malware.exe.gpg
# gpg: decryption failed: No secret key
```

**Solutions:**

**A. Verify Passphrase**

GPG symmetric encryption uses a passphrase (no key needed):
```bash
# Decrypt with passphrase
gpg --decrypt malware.exe.gpg > malware.exe
# Enter passphrase when prompted
```

**B. Check Encryption Method**

Re-encrypt if needed:
```bash
# Symmetric encryption (recommended)
gpg --symmetric --cipher-algo AES256 malware.exe
# Creates malware.exe.gpg
```

---

## 9. Report Generation Issues

### Issue: HTML report shows no data

**Symptoms:**
- Report generates but shows "N/A" for all fields
- Missing IOCs

**Solutions:**

**A. Verify Analysis Completed Successfully**
```bash
# Check Cuckoo report exists
ls -la ~/.cuckoo/storage/analyses/*/reports/report.json

# Verify report has data
jq '.network.domains' ~/.cuckoo/storage/analyses/1/reports/report.json
```

**B. Check Report Generator Input**
```bash
# Test with existing analysis
python3 report_generator.py --analysis-dir /path/to/task_123
```

---

## 10. Emergency: Malware Escape Suspected

### IMMEDIATE ACTIONS

**If you suspect malware has escaped the lab environment:**

**Step 1: ISOLATE IMMEDIATELY**
```bash
# Shutdown ALL VMs
VBoxManage controlvm REMnux_MASARE poweroff
VBoxManage controlvm FLARE_MASARE poweroff

# Disconnect host from network
sudo ifconfig eth0 down  # Linux
# Or disable WiFi/Ethernet in Network Settings
```

**Step 2: VERIFY CONTAINMENT**
```bash
# Check host for suspicious processes
ps aux | grep -E "(malware|suspicious)"

# Check network connections
netstat -tulpn | grep ESTABLISHED

# Check for new files
find /tmp /var/tmp ~ -mtime -1 -ls
```

**Step 3: RESTORE FROM CLEAN STATE**
```bash
# Delete potentially compromised VMs
VBoxManage unregistervm REMnux_MASARE --delete
VBoxManage unregistervm FLARE_MASARE --delete

# Restore from baseline snapshots
# Re-run setup scripts from trusted source
```

**Step 4: INCIDENT REPORTING**
- Document timeline of events
- Preserve logs: `tar -czf incident_logs.tar.gz /shared/logs`
- Contact security team/management
- Report to appropriate CERT if required

---

## Getting Help

If issues persist:

1. **Check Logs:**
   ```bash
   # Cuckoo logs
   tail -f ~/.cuckoo/log/cuckoo.log

   # Analysis logs
   tail -f /shared/logs/orchestrator.log

   # System logs
   journalctl -xe
   ```

2. **GitHub Issues:**
   - https://github.com/Raoof128/MASARE/issues

3. **Cuckoo Community:**
   - https://github.com/cuckoosandbox/cuckoo/issues

4. **MASARE Documentation:**
   - README.md
   - SETUP_GUIDE.md
   - ARCHITECTURE.md

---

**Last Updated:** 2025-11-15
**Version:** 1.0
