# MASARE Architecture Documentation

## Enterprise Malware Analysis Sandbox - Technical Design

**Version:** 1.0
**Last Updated:** November 2025
**Architecture Owner:** Security Research Team

---

## Table of Contents

1. [System Overview](#1-system-overview)
2. [Network Architecture](#2-network-architecture)
3. [Virtual Machine Infrastructure](#3-virtual-machine-infrastructure)
4. [Analysis Pipeline](#4-analysis-pipeline)
5. [Data Flow](#5-data-flow)
6. [Security Controls](#6-security-controls)
7. [Scalability & Performance](#7-scalability--performance)
8. [Disaster Recovery](#8-disaster-recovery)

---

## 1. System Overview

### 1.1 Architecture Goals

The MASARE platform is designed to achieve the following objectives:

✅ **Isolation**: Complete air-gapping of malware analysis from production networks
✅ **Automation**: Minimize manual intervention through orchestration scripts
✅ **Scalability**: Process multiple samples concurrently with parallel analysis
✅ **Observability**: Comprehensive logging and monitoring of all malware behavior
✅ **Reproducibility**: Snapshot-based VM management for consistent analysis
✅ **Extensibility**: Modular design allowing integration of new analysis tools

### 1.2 High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                         HOST MACHINE                                │
│                    macOS / Linux / Windows                          │
│                    Min: 16GB RAM, 256GB SSD                         │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  ┌───────────────────────────────────────────────────────────────┐ │
│  │              HYPERVISOR LAYER                                 │ │
│  │         VirtualBox 7.0 / UTM (M-series Mac)                   │ │
│  └───────────────────────────────────────────────────────────────┘ │
│                                                                     │
│  ┌───────────────────────────────────────────────────────────────┐ │
│  │            ISOLATED NETWORK (192.168.1.0/24)                  │ │
│  │                  Host-Only Adapter                            │ │
│  │                                                               │ │
│  │  ┌─────────────┐  ┌─────────────┐  ┌────────────────────┐   │ │
│  │  │  REMnux VM  │  │  FLARE VM   │  │  pfSense Router    │   │ │
│  │  │             │  │             │  │                    │   │ │
│  │  │ 192.168.1.10│  │192.168.1.20 │  │  192.168.1.1       │   │ │
│  │  │             │  │             │  │                    │   │ │
│  │  │ Ubuntu 22.04│  │ Windows 10  │  │  Firewall/Router   │   │ │
│  │  │ 4GB RAM     │  │ 4GB RAM     │  │  512MB RAM         │   │ │
│  │  │ 100GB Disk  │  │ 80GB Disk   │  │  8GB Disk          │   │ │
│  │  │             │  │             │  │                    │   │ │
│  │  │ Components: │  │ Components: │  │  Components:       │   │ │
│  │  │ • Cuckoo    │  │ • x64dbg    │  │  • Packet Filter   │   │ │
│  │  │ • Ghidra    │  │ • IDA Free  │  │  • IDS/IPS         │   │ │
│  │  │ • Radare2   │  │ • Wireshark │  │  • DNS Sinkhole    │   │ │
│  │  │ • YARA      │  │ • ProcessMon│  │  • Traffic Logger  │   │ │
│  │  │ • tcpdump   │  │ • RegShot   │  │                    │   │ │
│  │  │ • Volatility│  │ • Autoruns  │  │                    │   │ │
│  │  │ • Strings   │  │ • FakeNet-NG│  │                    │   │ │
│  │  └─────────────┘  └─────────────┘  └────────────────────┘   │ │
│  │                                                               │ │
│  │  Network Rules:                                               │ │
│  │  • NO internet access (egress blocked)                        │ │
│  │  • Inter-VM communication allowed                            │ │
│  │  • Host → VM (management only)                               │ │
│  │  • VM → Host (BLOCKED)                                       │ │
│  └───────────────────────────────────────────────────────────────┘ │
│                                                                     │
│  ┌───────────────────────────────────────────────────────────────┐ │
│  │              SHARED STORAGE LAYER                             │ │
│  │                                                               │ │
│  │  /shared/malware/samples/    (Encrypted AES-256)             │ │
│  │  /shared/analysis/results/   (Analysis reports)              │ │
│  │  /shared/logs/               (System & network logs)         │ │
│  │  /shared/iocs/               (IOC feeds, YARA rules)         │ │
│  └───────────────────────────────────────────────────────────────┘ │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

### 1.3 Technology Stack

| Layer | Component | Purpose |
|-------|-----------|---------|
| **Hypervisor** | VirtualBox 7.0 / UTM | Virtual machine management |
| **Analysis OS** | REMnux (Ubuntu 22.04) | Linux-based malware analysis |
| **Sandbox OS** | FLARE VM (Windows 10) | Windows malware execution |
| **Network** | pfSense 2.7+ | Firewall, routing, IDS |
| **Dynamic Analysis** | Cuckoo Sandbox 2.0+ | Automated behavior monitoring |
| **Static Analysis** | Ghidra 11.0+, Radare2 | Reverse engineering |
| **Packet Capture** | Wireshark, tcpdump | Network traffic analysis |
| **Detection** | YARA 4.3+, Sigma | Signature-based detection |
| **Orchestration** | Python 3.11+ | Automation & reporting |
| **Monitoring** | Prometheus, Grafana | Performance metrics |

---

## 2. Network Architecture

### 2.1 Network Topology

```
┌─────────────────────────────────────────────────────────────────┐
│                      INTERNET                                   │
│                         ⛔ BLOCKED                              │
└─────────────────────────────────────────────────────────────────┘
                           ▲
                           │ NO ACCESS
                           │
┌─────────────────────────────────────────────────────────────────┐
│                   HOST MACHINE                                  │
│              Physical NIC: eth0 / en0                           │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  Host-Only Network Adapter: vboxnet0 / vmnet1                  │
│  CIDR: 192.168.1.0/24                                          │
│  Gateway: 192.168.1.1 (pfSense)                                │
│  DHCP: DISABLED (static IPs only)                              │
│                                                                 │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │                pfSense Router/Firewall                   │  │
│  │                IP: 192.168.1.1/24                        │  │
│  │                                                          │  │
│  │  Interfaces:                                             │  │
│  │  • LAN:  em0 (192.168.1.1) → Lab Network                │  │
│  │  • WAN:  em1 (DISABLED)    → No uplink                  │  │
│  │                                                          │  │
│  │  Firewall Rules:                                         │  │
│  │  1. BLOCK all egress traffic (default deny)             │  │
│  │  2. ALLOW inter-VM communication (LAN → LAN)            │  │
│  │  3. ALLOW host → VM management (SSH, RDP)               │  │
│  │  4. BLOCK VM → host (prevent VM escape)                 │  │
│  │  5. ALLOW DNS queries (sinkhole to 192.168.1.1)         │  │
│  │  6. LOG all traffic attempts                            │  │
│  │                                                          │  │
│  │  IDS/IPS:                                                │  │
│  │  • Snort 3.x / Suricata for threat detection            │  │
│  │  • Alert on suspicious outbound connections             │  │
│  │  • Log all C2 beaconing attempts                        │  │
│  └──────────────────────────────────────────────────────────┘  │
│               │                          │                     │
│               ▼                          ▼                     │
│  ┌─────────────────────┐    ┌──────────────────────────┐      │
│  │   REMnux VM         │    │   FLARE VM               │      │
│  │   192.168.1.10/24   │    │   192.168.1.20/24        │      │
│  │   GW: 192.168.1.1   │    │   GW: 192.168.1.1        │      │
│  │                     │    │                          │      │
│  │   Ports:            │    │   Ports:                 │      │
│  │   • 22/tcp (SSH)    │    │   • 3389/tcp (RDP)       │      │
│  │   • 8000/tcp (Cuckoo│    │   • 445/tcp (SMB share)  │      │
│  │     Web UI)         │    │   • 2042/tcp (Cuckoo Agt)│      │
│  └─────────────────────┘    └──────────────────────────┘      │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### 2.2 IP Address Allocation

| Device | IP Address | MAC Address | Purpose |
|--------|-----------|-------------|---------|
| pfSense Router | 192.168.1.1/24 | 08:00:27:00:00:01 | Gateway & firewall |
| REMnux VM | 192.168.1.10/24 | 08:00:27:00:00:10 | Analysis workstation |
| FLARE VM | 192.168.1.20/24 | 08:00:27:00:00:20 | Malware sandbox |
| Host (management) | 192.168.1.254/24 | N/A | VM management interface |

### 2.3 Network Isolation Testing

```bash
#!/bin/bash
# Isolation verification script (run on REMnux VM)

echo "[*] Testing network isolation..."

# Test 1: Verify NO internet access
echo "[1] Testing internet connectivity (should FAIL):"
ping -c 1 8.8.8.8 &> /dev/null
if [ $? -eq 0 ]; then
    echo "❌ FAILED: Internet is accessible (SECURITY RISK)"
    exit 1
else
    echo "✅ PASSED: No internet access"
fi

# Test 2: Verify inter-VM communication
echo "[2] Testing inter-VM communication (should SUCCEED):"
ping -c 1 192.168.1.20 &> /dev/null
if [ $? -eq 0 ]; then
    echo "✅ PASSED: Can reach FLARE VM"
else
    echo "❌ FAILED: Cannot reach FLARE VM"
    exit 1
fi

# Test 3: Verify DNS sinkhole
echo "[3] Testing DNS resolution (should sinkhole):"
host malicious-domain.com 192.168.1.1 | grep "192.168.1.1"
if [ $? -eq 0 ]; then
    echo "✅ PASSED: DNS sinkholed to 192.168.1.1"
else
    echo "⚠️  WARNING: DNS not sinkholed"
fi

# Test 4: Verify no default route to internet
echo "[4] Testing default route (should only be 192.168.1.1):"
ip route | grep "default via" | grep -v "192.168.1.1"
if [ $? -ne 0 ]; then
    echo "✅ PASSED: No internet gateway configured"
else
    echo "❌ FAILED: Unexpected default route detected"
    exit 1
fi

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "✅ ALL ISOLATION TESTS PASSED"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
```

---

## 3. Virtual Machine Infrastructure

### 3.1 REMnux Analysis VM

**Purpose**: Primary malware analysis workstation with Linux-based tools

**Specifications:**
- **OS**: REMnux 7.0 (Ubuntu 22.04 LTS)
- **CPU**: 2 vCPUs
- **RAM**: 4GB
- **Disk**: 100GB (dynamically allocated)
- **Network**: Host-Only (192.168.1.10/24)

**Installed Tools:**
```
┌─────────────────────────────────────────────────────────┐
│              REMnux Tool Suite                          │
├─────────────────────────────────────────────────────────┤
│ Dynamic Analysis:                                       │
│  • Cuckoo Sandbox 2.0+  (automated execution)          │
│  • Volatility 3.x       (memory forensics)             │
│  • tcpdump / Wireshark  (packet capture)               │
│  • Burp Suite           (web proxy analysis)           │
│                                                         │
│ Static Analysis:                                        │
│  • Ghidra 11.0+         (NSA reverse engineering)      │
│  • Radare2 / Rizin      (binary analysis)              │
│  • IDA Free             (disassembler)                 │
│  • objdump / readelf    (binary inspection)            │
│                                                         │
│ Detection Engineering:                                  │
│  • YARA 4.3+            (signature matching)           │
│  • ClamAV               (antivirus engine)             │
│  • Sigma                (SIEM detection rules)         │
│                                                         │
│ Scripting & Automation:                                 │
│  • Python 3.11+         (orchestration)                │
│  • pefile               (PE file analysis)             │
│  • oletools             (Office doc analysis)          │
│  • peepdf               (PDF malware analysis)         │
│                                                         │
│ Utilities:                                              │
│  • strings              (extract text)                 │
│  • binwalk              (firmware extraction)          │
│  • exiftool             (metadata extraction)          │
│  • ssdeep               (fuzzy hashing)                │
└─────────────────────────────────────────────────────────┘
```

**VM Configuration:**
```bash
# VirtualBox configuration
VBoxManage createvm --name REMnux --ostype Linux_64 --register
VBoxManage modifyvm REMnux \
    --memory 4096 \
    --cpus 2 \
    --vram 128 \
    --nic1 hostonly \
    --hostonlyadapter1 vboxnet0 \
    --boot1 disk \
    --boot2 none \
    --boot3 none \
    --boot4 none

VBoxManage createhd --filename ~/VirtualBox\ VMs/REMnux/REMnux.vdi --size 102400
VBoxManage storagectl REMnux --name "SATA" --add sata --controller IntelAhci
VBoxManage storageattach REMnux --storagectl "SATA" --port 0 --device 0 --type hdd --medium ~/VirtualBox\ VMs/REMnux/REMnux.vdi
```

### 3.2 FLARE VM Windows Sandbox

**Purpose**: Windows malware execution environment with monitoring agents

**Specifications:**
- **OS**: Windows 10 Professional (64-bit)
- **CPU**: 2 vCPUs
- **RAM**: 4GB
- **Disk**: 80GB (dynamically allocated)
- **Network**: Host-Only (192.168.1.20/24)

**Installed Tools:**
```
┌─────────────────────────────────────────────────────────┐
│              FLARE VM Tool Suite                        │
├─────────────────────────────────────────────────────────┤
│ Debuggers:                                              │
│  • x64dbg / x32dbg      (user-mode debugger)           │
│  • WinDbg               (kernel debugger)              │
│  • OllyDbg              (assembly debugger)            │
│                                                         │
│ Process Monitoring:                                     │
│  • Process Monitor      (Sysinternals)                 │
│  • Process Explorer     (Sysinternals)                 │
│  • Autoruns             (persistence detection)        │
│  • RegShot              (registry diff tool)           │
│                                                         │
│ Network Analysis:                                       │
│  • Wireshark            (packet sniffer)               │
│  • FakeNet-NG           (network simulation)           │
│  • TCPView              (connection monitor)           │
│  • INetSim              (service emulation)            │
│                                                         │
│ Disassemblers:                                          │
│  • IDA Free             (static analysis)              │
│  • Ghidra               (NSA tool)                     │
│  • PE-bear              (PE file viewer)               │
│  • CFF Explorer         (PE editor)                    │
│                                                         │
│ Cuckoo Integration:                                     │
│  • Cuckoo Agent         (behavior monitor)             │
│  • Python 3.11          (scripting)                    │
└─────────────────────────────────────────────────────────┘
```

**Hardening Configuration:**
```powershell
# Disable Windows Defender (malware analysis only!)
Set-MpPreference -DisableRealtimeMonitoring $true

# Disable Windows Update (prevent changes during analysis)
Stop-Service wuauserv
Set-Service wuauserv -StartupType Disabled

# Disable UAC (for automated execution)
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -Value 0

# Enable showing hidden files & extensions
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Hidden" -Value 1
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideFileExt" -Value 0

# Install Cuckoo Agent (auto-start)
New-Item -Path "C:\cuckoo_agent" -ItemType Directory
Copy-Item \\192.168.1.10\cuckoo\agent.py C:\cuckoo_agent\
```

### 3.3 pfSense Router/Firewall

**Purpose**: Network isolation, traffic filtering, IDS/IPS

**Specifications:**
- **OS**: pfSense 2.7+
- **CPU**: 1 vCPU
- **RAM**: 512MB
- **Disk**: 8GB
- **Interfaces**:
  - LAN: em0 (192.168.1.1/24)
  - WAN: em1 (DISABLED)

**Firewall Rules:**
```
Priority | Action | Interface | Source         | Destination    | Port | Description
---------|--------|-----------|----------------|----------------|------|------------------
1        | BLOCK  | WAN       | *              | *              | *    | Block all egress
2        | ALLOW  | LAN       | 192.168.1.0/24 | 192.168.1.0/24 | *    | Inter-VM traffic
3        | ALLOW  | LAN       | 192.168.1.10   | *              | 53   | DNS (sinkhole)
4        | BLOCK  | LAN       | 192.168.1.0/24 | 192.168.1.254  | *    | Block VM → host
5        | LOG    | LAN       | *              | *              | *    | Log all traffic
```

**DNS Sinkhole Configuration:**
```
# /etc/dnsmasq.conf
address=/#/192.168.1.1  # Sinkhole all DNS queries
log-queries             # Log all DNS requests for C2 detection
```

---

## 4. Analysis Pipeline

### 4.1 Workflow Architecture

```
┌────────────────────────────────────────────────────────────────┐
│                   MALWARE ANALYSIS PIPELINE                    │
└────────────────────────────────────────────────────────────────┘

┌─────────────┐
│   Sample    │  Encrypted malware binary (AES-256)
│ Acquisition │  Source: VirusShare, MalwareBazaar, etc.
└──────┬──────┘
       │
       ▼
┌─────────────┐
│ Decryption  │  GPG decrypt to /tmp (in-memory filesystem)
│  & Staging  │  SHA-256 hash verification
└──────┬──────┘
       │
       ├──────────────────────────────────┐
       │                                  │
       ▼                                  ▼
┌──────────────┐                  ┌──────────────┐
│   STATIC     │                  │   DYNAMIC    │
│   ANALYSIS   │                  │   ANALYSIS   │
│              │                  │              │
│ • Ghidra     │                  │ • Cuckoo     │
│ • strings    │                  │   Sandbox    │
│ • pefile     │                  │ • Process    │
│ • YARA scan  │                  │   Monitor    │
│              │                  │ • Wireshark  │
└──────┬───────┘                  └──────┬───────┘
       │                                  │
       │                                  │
       ▼                                  ▼
┌─────────────────────────────────────────────┐
│           IOC EXTRACTION ENGINE             │
│                                             │
│ • File Hashes (MD5, SHA256)                │
│ • Network Indicators (IPs, domains, URLs)   │
│ • Registry Keys & File Paths               │
│ • Process Trees & API Calls                │
│ • Behavioral Patterns                      │
└──────┬──────────────────────────────────────┘
       │
       ▼
┌─────────────────────────────────────────────┐
│         MITRE ATT&CK MAPPER                 │
│                                             │
│ Map behaviors → TTPs:                       │
│ • Process Injection    → T1055             │
│ • Registry Persistence → T1547             │
│ • C2 Communication     → T1071             │
└──────┬──────────────────────────────────────┘
       │
       ├──────────────────────┬─────────────────┐
       │                      │                 │
       ▼                      ▼                 ▼
┌──────────────┐      ┌──────────────┐  ┌──────────────┐
│ YARA Rule    │      │ HTML Report  │  │  IOC Feed    │
│  Generation  │      │  Generation  │  │  (JSON)      │
│              │      │              │  │              │
│ • Hash rules │      │ • Executive  │  │ • STIX 2.1   │
│ • Behavioral │      │   summary    │  │ • OpenIOC    │
│   signatures │      │ • Technical  │  │ • MISP       │
│              │      │   details    │  │              │
└──────┬───────┘      └──────┬───────┘  └──────┬───────┘
       │                      │                 │
       └──────────────────────┴─────────────────┘
                              │
                              ▼
                     ┌─────────────────┐
                     │  Report Archive │
                     │  & Distribution │
                     │                 │
                     │ • Local storage │
                     │ • GitHub Pages  │
                     │ • SIEM export   │
                     └─────────────────┘
```

### 4.2 Component Integration

```python
# Orchestrator pseudocode
class MalwareAnalysisPipeline:
    def __init__(self, sample_path):
        self.sample = self.decrypt_sample(sample_path)
        self.results = {
            'static_analysis': {},
            'dynamic_analysis': {},
            'iocs': {},
            'mitre_mapping': [],
            'yara_rules': [],
        }

    def execute(self):
        # Run analyses in parallel
        with ThreadPoolExecutor() as executor:
            static_future = executor.submit(self.static_analysis)
            dynamic_future = executor.submit(self.dynamic_analysis)

        # Collect results
        self.results['static_analysis'] = static_future.result()
        self.results['dynamic_analysis'] = dynamic_future.result()

        # Extract IOCs
        self.results['iocs'] = self.extract_iocs()

        # MITRE mapping
        self.results['mitre_mapping'] = self.map_to_mitre()

        # Generate YARA rules
        self.results['yara_rules'] = self.generate_yara_rules()

        # Create reports
        self.generate_reports()

        # Cleanup
        self.secure_delete(self.sample)
```

---

## 5. Data Flow

### 5.1 Analysis Data Flow Diagram

```
┌─────────────────────────────────────────────────────────────────┐
│                       HOST MACHINE                              │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  /shared/malware/samples/                                       │
│  ├── sample_001.bin.enc  (AES-256 encrypted)                   │
│  ├── sample_002.bin.enc                                        │
│  └── manifest.json       (sample metadata)                     │
│           │                                                     │
│           │ (1) Mount shared folder                            │
│           ▼                                                     │
│  ┌───────────────────────────────────────────────────────┐     │
│  │         REMnux VM (192.168.1.10)                      │     │
│  │                                                       │     │
│  │  /mnt/shared/malware/samples/  (read-only)           │     │
│  │                                                       │     │
│  │  (2) Orchestrator decrypts sample                    │     │
│  │      ↓                                                │     │
│  │  /tmp/analysis/sample_001.bin  (tmpfs, in-memory)    │     │
│  │      ↓                                                │     │
│  │  (3) Static Analysis (Ghidra, strings, pefile)       │     │
│  │      ↓                                                │     │
│  │  (4) Submit to Cuckoo Sandbox ────┐                  │     │
│  │      │                             │                  │     │
│  │      │  (5) Cuckoo sends sample via network          │     │
│  │      │      to FLARE VM            │                  │     │
│  └──────┼─────────────────────────────┼──────────────────┘     │
│         │                             │                        │
│         │                             ▼                        │
│  ┌──────┼─────────────────────────────────────────────┐       │
│  │      │      FLARE VM (192.168.1.20)                │       │
│  │      │                                              │       │
│  │      │  (6) Cuckoo Agent receives sample           │       │
│  │      │      ↓                                       │       │
│  │      │  C:\cuckoo_temp\sample_001.exe              │       │
│  │      │      ↓                                       │       │
│  │      │  (7) Execute malware (monitored)            │       │
│  │      │      • Process Monitor logs                 │       │
│  │      │      • Registry changes (RegShot)           │       │
│  │      │      • Network traffic (Wireshark)          │       │
│  │      │      • File system changes                  │       │
│  │      │      ↓                                       │       │
│  │      │  (8) Cuckoo Agent sends results back ───────┼───┐   │
│  │      │                                              │   │   │
│  └──────┼──────────────────────────────────────────────┘   │   │
│         │                                                  │   │
│         │  (9) Static analysis complete                   │   │
│         │      ↓                                           │   │
│         │  /tmp/static_results.json                       │   │
│         │                                                  │   │
│         │  (10) Dynamic analysis complete ◀───────────────┘   │
│         │      ↓                                              │
│         │  /tmp/dynamic_results.json                         │
│         │      ↓                                              │
│         │  (11) IOC Extraction                               │
│         │      • Network IOCs (IPs, domains, URLs)           │
│         │      • File IOCs (hashes, paths)                   │
│         │      • Registry IOCs                               │
│         │      ↓                                              │
│         │  (12) MITRE ATT&CK Mapping                         │
│         │      ↓                                              │
│         │  (13) YARA Rule Generation                         │
│         │      ↓                                              │
│         │  (14) Report Generation (HTML, JSON)               │
│         │      ↓                                              │
│         ▼                                                     │
│  /shared/analysis/results/                                    │
│  ├── sample_001/                                              │
│  │   ├── report.html                                          │
│  │   ├── report.json                                          │
│  │   ├── iocs.json                                            │
│  │   ├── yara_rules.yar                                       │
│  │   ├── screenshots/                                         │
│  │   └── pcap/network_traffic.pcap                           │
│  └── manifest.json                                            │
│                                                               │
└─────────────────────────────────────────────────────────────────┘
```

### 5.2 Logging & Monitoring

**Log Storage:**
```
/shared/logs/
├── cuckoo/
│   ├── cuckoo.log                 (Cuckoo orchestrator logs)
│   └── task_12345.log             (Per-task execution logs)
├── network/
│   ├── pfsense.log                (Firewall traffic logs)
│   ├── dns_queries.log            (Sinkhole DNS logs)
│   └── ids_alerts.log             (Snort/Suricata alerts)
├── vm/
│   ├── remnux_system.log          (REMnux syslog)
│   └── flare_events.log           (Windows Event Log export)
└── analysis/
    └── orchestrator.log           (Python orchestration logs)
```

---

## 6. Security Controls

### 6.1 Defense-in-Depth Layers

```
┌─────────────────────────────────────────────────────────────┐
│ Layer 1: Physical Isolation                                │
│ • Dedicated analysis host (not shared with production)     │
│ • Air-gapped network (no physical WAN connection)          │
└─────────────────────────────────────────────────────────────┘
                          ▼
┌─────────────────────────────────────────────────────────────┐
│ Layer 2: Network Segmentation                              │
│ • Host-Only networking (no internet route)                 │
│ • pfSense firewall with default-deny egress                │
│ • IDS/IPS monitoring (Snort/Suricata)                      │
└─────────────────────────────────────────────────────────────┘
                          ▼
┌─────────────────────────────────────────────────────────────┐
│ Layer 3: VM Isolation                                      │
│ • Snapshot-based rollback after each analysis              │
│ • Restricted shared folders (read-only for samples)        │
│ • No clipboard sharing or drag-and-drop                    │
└─────────────────────────────────────────────────────────────┘
                          ▼
┌─────────────────────────────────────────────────────────────┐
│ Layer 4: Data Encryption                                   │
│ • AES-256 for malware sample storage                       │
│ • Passphrase-protected GPG encryption                      │
│ • Full disk encryption for analysis VMs                    │
└─────────────────────────────────────────────────────────────┘
                          ▼
┌─────────────────────────────────────────────────────────────┐
│ Layer 5: Access Control                                    │
│ • SSH key-based authentication (no passwords)              │
│ • Principle of least privilege for VM access               │
│ • Audit logs for all sample access                         │
└─────────────────────────────────────────────────────────────┘
                          ▼
┌─────────────────────────────────────────────────────────────┐
│ Layer 6: Monitoring & Detection                            │
│ • Real-time IDS alerts (Snort rules)                       │
│ • Automated isolation verification tests                   │
│ • Anomaly detection for VM escape attempts                 │
└─────────────────────────────────────────────────────────────┘
```

### 6.2 Threat Model

| Threat | Mitigation | Residual Risk |
|--------|-----------|---------------|
| **VM Escape** | Hypervisor patching, snapshot rollback | LOW |
| **Network Breach** | Air-gapped network, firewall rules | VERY LOW |
| **Data Exfiltration** | No internet access, encrypted storage | VERY LOW |
| **Accidental Execution** | Encrypted samples, read-only mounts | LOW |
| **Insider Threat** | Access logs, least privilege | MEDIUM |
| **Supply Chain Attack** | Verified tool sources, checksums | LOW |

---

## 7. Scalability & Performance

### 7.1 Performance Benchmarks

| Metric | Target | Measured |
|--------|--------|----------|
| Sample analysis time | <10 min | 6-8 min |
| Concurrent samples | 3 | 3 (limited by RAM) |
| IOC extraction rate | 30-50/sample | 35-45 |
| Report generation | <2 min | 1.5 min |
| YARA compilation | <5 sec | 3 sec |

### 7.2 Scaling Options

**Horizontal Scaling (Multi-VM):**
```
┌─────────────────────────────────────────────────────────┐
│              Load Balancer (REMnux Master)              │
│                 192.168.1.10                            │
└─────────────────────────────────────────────────────────┘
          │              │              │
          ▼              ▼              ▼
┌─────────────┐  ┌─────────────┐  ┌─────────────┐
│ FLARE VM 1  │  │ FLARE VM 2  │  │ FLARE VM 3  │
│192.168.1.20 │  │192.168.1.21 │  │192.168.1.22 │
│             │  │             │  │             │
│ Cuckoo      │  │ Cuckoo      │  │ Cuckoo      │
│ Worker 1    │  │ Worker 2    │  │ Worker 3    │
└─────────────┘  └─────────────┘  └─────────────┘
```

**Vertical Scaling (Resource Increase):**
- Increase RAM from 4GB → 8GB per VM
- Add more vCPUs for parallel Ghidra analysis
- Faster SSD storage (NVMe) for I/O-intensive tasks

---

## 8. Disaster Recovery

### 8.1 Backup Strategy

| Component | Backup Frequency | Retention | Storage Location |
|-----------|-----------------|-----------|------------------|
| VM Snapshots (baseline) | After major changes | 3 snapshots | Local host |
| Analysis Reports | Daily (automated) | 1 year | Encrypted USB + Cloud |
| YARA Rules | On commit (Git) | Indefinite | GitHub repository |
| Malware Samples | **NOT backed up** | N/A | Single encrypted copy |
| Configuration Files | Weekly | 6 months | GitHub repository |

### 8.2 Recovery Procedures

**Scenario 1: VM Corruption**
```bash
# Restore from snapshot
VBoxManage snapshot REMnux restore baseline_clean
VBoxManage startvm REMnux --type headless
```

**Scenario 2: Accidental Malware Infection**
```bash
# Emergency shutdown
VBoxManage controlvm REMnux poweroff
VBoxManage snapshot REMnux restore baseline_clean

# Verify isolation before restart
bash tests/test_isolation.sh
```

**Scenario 3: Data Loss (Reports)**
```bash
# Restore from encrypted backup
gpg --decrypt reports_backup_20251115.tar.gpg | tar -xzf -
```

---

## 9. Future Enhancements

**Planned Improvements:**
1. **Container-based Architecture**: Migrate to Docker for faster provisioning
2. **GPU Acceleration**: CUDA support for ML-based malware classification
3. **Threat Intelligence Integration**: Automated IOC submission to MISP/OpenCTI
4. **Real-time Collaboration**: Multi-analyst support with shared workspaces
5. **Advanced Evasion Detection**: Machine learning for anti-analysis detection

---

**Document Version:** 1.0
**Next Review Date:** 2026-02-15
