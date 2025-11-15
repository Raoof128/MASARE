# MASARE Analysis Workflow

## Complete Malware Analysis Process

**Time Required:** 10-15 minutes per sample
**Analyst Skill Level:** Intermediate to Advanced

---

## Pre-Analysis Checklist

Before analyzing any malware sample, verify:

```bash
# 1. Network isolation verified
./tests/test_isolation.sh
# ✓ ALL ISOLATION TESTS PASSED

# 2. VMs running
VBoxManage list runningvms
# Should show: REMnux_MASARE, FLARE_MASARE

# 3. Cuckoo services active
curl http://192.168.1.10:8090
# Should return Cuckoo web interface

# 4. Baseline snapshots exist
VBoxManage snapshot FLARE_MASARE list | grep baseline_clean
# ✓ Name: baseline_clean
```

**⚠️ CRITICAL:** Never skip the isolation test!

---

## Workflow Overview

```
Sample Acquisition → Encryption → Decryption → Analysis → IOC Extraction
     → MITRE Mapping → YARA Generation → Report → Cleanup
```

---

## Step 1: Sample Acquisition (5 minutes)

### 1.1 Obtain from Approved Sources

**Approved Repositories:**
- VirusShare: https://virusshare.com (requires registration)
- MalwareBazaar: https://bazaar.abuse.ch
- Any.run: https://any.run
- Hybrid-Analysis: https://hybrid-analysis.com

**Example: MalwareBazaar**
```bash
# Download via API
curl -X POST "https://mb-api.abuse.ch/api/v1/" \
     -d "query=get_file" \
     -d "sha256_hash=abc123..." \
     -o malware_sample.zip

# Extract (password: infected)
unzip -P infected malware_sample.zip
```

### 1.2 Document Chain of Custody

Create manifest entry:
```json
{
  "filename": "emotet_variant_2024.exe",
  "sha256": "abc123def456...",
  "source": "MalwareBazaar",
  "source_url": "https://bazaar.abuse.ch/sample/abc123",
  "family": "Emotet",
  "acquired_date": "2025-11-15T10:30:00Z",
  "analyst": "your_name"
}
```

### 1.3 Encrypt Sample

```bash
# Encrypt with AES-256
gpg --symmetric --cipher-algo AES256 emotet_variant_2024.exe
# Enter strong passphrase (store in password manager!)

# Move to secure storage
mv emotet_variant_2024.exe.gpg ~/MASARE/shared/malware/samples/

# Securely delete original
shred -u -z -n 3 emotet_variant_2024.exe
```

---

## Step 2: Pre-Analysis Triage (2 minutes)

### 2.1 Basic File Analysis

```bash
# Decrypt to temporary location (tmpfs)
gpg --decrypt ~/MASARE/shared/malware/samples/emotet_variant_2024.exe.gpg > /tmp/sample.exe

# File type identification
file /tmp/sample.exe
# Output: PE32 executable (GUI) Intel 80386, for MS Windows

# Calculate hashes
md5sum /tmp/sample.exe
sha256sum /tmp/sample.exe
ssdeep /tmp/sample.exe  # Fuzzy hash

# Quick strings check
strings /tmp/sample.exe | grep -E "(http|\.dll|KERNEL32)" | head -20
```

### 2.2 VirusTotal Check (Optional)

```bash
# Check if sample is already known
curl "https://www.virustotal.com/api/v3/files/$(sha256sum /tmp/sample.exe | awk '{print $1}')" \
     -H "x-apikey: YOUR_VT_API_KEY"
```

**⚠️ Note:** Only check hash, never upload unknown samples to public services!

---

## Step 3: Automated Analysis (6-8 minutes)

### 3.1 Single Sample Analysis

```bash
cd ~/masare_analysis

# Submit for complete analysis
python3 cuckoo/orchestrator.py --sample /tmp/sample.exe --timeout 120

# Monitor progress
tail -f /shared/logs/orchestrator.log
```

**Expected Output:**
```
[*] Starting analysis of: sample.exe
[+] Submitted: sample.exe → Task 12345
[*] Waiting for task 12345 to complete (timeout: 300s)...
[✓] Task 12345 completed successfully
[+] Extracted 42 domains, 15 IPs, 8 file hashes
[+] Results saved to: /shared/analysis/results/task_12345_sample.exe
```

### 3.2 Batch Processing (Multiple Samples)

```bash
# Place all samples in directory
mkdir /tmp/batch_samples
# Decrypt multiple samples to /tmp/batch_samples/

# Run batch analysis with 3 parallel workers
python3 ~/masare_automation/batch_analyzer.py \
    --samples-dir /tmp/batch_samples \
    --parallel 3 \
    --output-dir /shared/analysis/results
```

---

## Step 4: Analysis Results Review (2-3 minutes)

### 4.1 Access Results

```bash
# Navigate to results directory
cd /shared/analysis/results/task_12345_sample.exe

# Files generated:
ls -lah
# report.json       - Complete analysis data
# report.html       - Human-readable report
# iocs.json         - Machine-readable IOCs
# summary.json      - Executive summary
# detection_rules.yar - YARA signatures
# mitre_navigator.json - ATT&CK layer
```

### 4.2 Review HTML Report

```bash
# Open in browser (from host machine)
firefox /path/to/MASARE/shared/analysis/results/task_12345_sample.exe/report.html

# Or copy to host and view
```

**Key Report Sections:**
1. **Executive Summary** - Threat level, file info
2. **IOCs** - Network indicators, file hashes, registry keys
3. **MITRE ATT&CK** - Behavioral tactics/techniques
4. **Process Activity** - Process tree, API calls
5. **Detection Signatures** - YARA rules
6. **Remediation Steps** - How to clean infected systems

### 4.3 Review IOCs

```bash
# Extract specific IOCs
cat iocs.json | jq '.domains[]'
# "malicious-c2.com"
# "evil-server.net"

cat iocs.json | jq '.ips[]'
# "192.0.2.100"
# "198.51.100.50"

cat iocs.json | jq '.file_hashes[]'
# "abc123..." (MD5)
# "def456..." (SHA256)
```

---

## Step 5: Manual Static Analysis (Optional, 15-30 minutes)

For deeper analysis, use Ghidra interactively:

### 5.1 Launch Ghidra

```bash
/opt/ghidra/ghidraRun &

# Import sample:
# File → Import File → /tmp/sample.exe

# Analyze:
# Analysis → Auto Analyze
```

### 5.2 Key Areas to Investigate

**A. Strings Analysis**
```
Window → Defined Strings
Search for:
- URLs (http://, https://)
- IP addresses
- File paths (C:\, AppData)
- Registry keys (SOFTWARE\)
- API function names
```

**B. Imports Table**
```
Window → Symbol Tree → Imports
Look for suspicious APIs:
- VirtualAllocEx (process injection)
- WriteProcessMemory (process injection)
- CreateRemoteThread (process injection)
- RegSetValue (persistence)
- URLDownloadToFile (downloader)
```

**C. Entry Point Analysis**
```
Navigate to: _entry
Review initial code flow
Identify anti-analysis checks:
- IsDebuggerPresent
- CheckRemoteDebuggerPresent
- CPUID checks (VM detection)
```

---

## Step 6: YARA Rule Validation (5 minutes)

### 6.1 Generate YARA Rules

```bash
python3 ~/masare_detection/yara/signature_generator.py \
    --sample /tmp/sample.exe \
    --analysis-report /shared/analysis/results/task_12345_sample.exe/report.json \
    --output /shared/detection/yara/emotet_detection.yar
```

### 6.2 Test YARA Rules

```bash
# Compile rules
yara-python -c /shared/detection/yara/emotet_detection.yar

# Test against original sample (should match)
yara /shared/detection/yara/emotet_detection.yar /tmp/sample.exe
# emotet_variant_2024_hash /tmp/sample.exe
# emotet_variant_2024_behavior /tmp/sample.exe

# Test against clean files (should NOT match)
yara /shared/detection/yara/emotet_detection.yar /bin/ls
# (no output = no match, good!)
```

### 6.3 Calculate Detection Rate

```bash
# Test against multiple samples
for sample in /tmp/test_samples/*.exe; do
    yara /shared/detection/yara/emotet_detection.yar "$sample"
done
```

---

## Step 7: MITRE ATT&CK Mapping (3 minutes)

### 7.1 Generate ATT&CK Navigator Layer

```bash
python3 ~/masare_automation/mitre_attack_mapper.py \
    --analysis-report /shared/analysis/results/task_12345_sample.exe/report.json \
    --navigator /shared/analysis/results/task_12345_sample.exe/mitre_layer.json
```

### 7.2 Visualize in ATT&CK Navigator

1. Open: https://mitre-attack.github.io/attack-navigator/
2. Click: "Open Existing Layer"
3. Upload: `mitre_layer.json`
4. Review highlighted techniques (red = observed)

**Common Emotet TTPs:**
- T1055 - Process Injection
- T1547.001 - Registry Run Keys (Persistence)
- T1071.001 - Web Protocols (C2)
- T1003 - Credential Dumping

---

## Step 8: Report Finalization (5 minutes)

### 8.1 Generate Professional Report

```bash
# HTML report (already generated by orchestrator)
# Located at: /shared/analysis/results/task_12345_sample.exe/report.html

# Generate IOC feed for SIEM
python3 ~/masare_automation/report_generator.py \
    --ioc-feed /shared/analysis/results \
    --output /shared/analysis/consolidated_iocs.json
```

### 8.2 Export for Distribution

```bash
# Create analysis package
cd /shared/analysis/results/task_12345_sample.exe
tar -czf emotet_analysis_$(date +%Y%m%d).tar.gz \
    report.html \
    iocs.json \
    detection_rules.yar \
    mitre_layer.json

# Move to reports directory
mv emotet_analysis_*.tar.gz /shared/reports/
```

---

## Step 9: Cleanup & VM Reset (2 minutes)

### 9.1 Secure Deletion of Decrypted Sample

```bash
# Overwrite and delete
shred -u -z -n 3 /tmp/sample.exe

# Verify deleted
ls /tmp/sample.exe
# ls: cannot access '/tmp/sample.exe': No such file or directory
```

### 9.2 Restore FLARE VM to Baseline

```bash
# Stop FLARE VM
VBoxManage controlvm FLARE_MASARE poweroff

# Restore snapshot
VBoxManage snapshot FLARE_MASARE restore baseline_clean

# Restart VM
VBoxManage startvm FLARE_MASARE --type headless

# Wait for boot (30 seconds)
sleep 30

# Verify Cuckoo can connect
curl http://192.168.1.10:8090/tasks/create/file
```

---

## Step 10: Intelligence Sharing (Optional)

### 10.1 Share IOCs with Community

**Via MISP (Malware Information Sharing Platform):**
```bash
# Export to MISP format
python3 ~/masare_automation/export_to_misp.py \
    --iocs /shared/analysis/results/task_12345_sample.exe/iocs.json \
    --output misp_event.json

# Upload to MISP instance
curl -X POST "https://misp.example.com/events" \
     -H "Authorization: YOUR_MISP_KEY" \
     -H "Content-Type: application/json" \
     -d @misp_event.json
```

### 10.2 Submit YARA Rules to GitHub

```bash
# Fork: https://github.com/Yara-Rules/rules
# Add rules to: malware/MALW_Emotet.yar
# Submit pull request
```

---

## Quality Assurance Checklist

Before considering analysis complete:

- [ ] Network isolation verified before and after analysis
- [ ] Complete HTML report generated
- [ ] IOCs extracted (domains, IPs, file hashes, registry keys)
- [ ] YARA rules compiled and tested (no false positives on benign files)
- [ ] MITRE ATT&CK mapping completed
- [ ] Decrypted sample securely deleted from /tmp
- [ ] FLARE VM restored to baseline snapshot
- [ ] Analysis results archived to /shared/reports
- [ ] Chain of custody documentation updated

---

## Performance Benchmarks

**Target Metrics:**
- **Total Analysis Time:** 10-15 minutes per sample
- **Automated vs Manual:** 80% automated, 20% manual review
- **IOC Extraction Rate:** 30-50 IOCs per sample
- **YARA Rule Quality:** <2% false positive rate

**Actual Performance:**
```bash
# Check analysis statistics
python3 ~/masare_automation/generate_stats.py \
    --results-dir /shared/analysis/results

# Example output:
# Total Samples Analyzed: 15
# Average Analysis Time: 8.3 minutes
# Total IOCs Extracted: 485
# YARA Rules Generated: 45
# False Positive Rate: 1.2%
```

---

## Advanced Techniques

### Memory Forensics with Volatility

```bash
# Enable memory dump in Cuckoo (cuckoo.conf)
# memory_dump = on

# After analysis, dump is in:
ls ~/.cuckoo/storage/analyses/12345/memory.dmp

# Analyze with Volatility 3
vol3 -f memory.dmp windows.pslist
vol3 -f memory.dmp windows.netscan
vol3 -f memory.dmp windows.malfind
```

### Unpacking Encrypted Samples

For packed/encrypted malware:

```bash
# Use automated unpacker
/opt/de4dot/de4dot.exe /tmp/packed_sample.exe
# Or use x64dbg to manually step through packer
```

---

**Last Updated:** 2025-11-15
**Version:** 1.0
