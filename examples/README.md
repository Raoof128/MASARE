# MASARE Usage Examples

This directory contains practical examples demonstrating how to use MASARE for malware analysis workflows.

## Table of Contents

- [Basic Analysis](#basic-analysis) - Analyze a single malware sample
- [Batch Processing](#batch-processing) - Analyze multiple samples in parallel
- [YARA Rule Generation](#yara-rule-generation) - Create custom detection signatures
- [Custom Reporting](#custom-reporting) - Generate tailored analysis reports
- [Integration Examples](#integration-examples) - Integrate MASARE into your workflow

## Prerequisites

Before running these examples:

1. **Complete MASARE setup** following `docs/SETUP_GUIDE.md`
2. **Verify VMs are running**:
   ```bash
   ./scripts/check_system.sh
   ```
3. **Activate Python environment**:
   ```bash
   python3 -m venv venv
   source venv/bin/activate  # Linux/macOS
   # venv\Scripts\activate  # Windows
   pip install -r requirements.txt
   ```
4. **Start Cuckoo Sandbox** on REMnux VM:
   ```bash
   cuckoo -d
   ```

## Quick Start

### 1. Basic Analysis

Analyze a single malware sample:

```bash
cd examples/
python3 basic_analysis.py /path/to/malware.exe
```

**Output**: Analysis report in `reports/` directory with IOCs, behavior analysis, and YARA signatures.

### 2. Batch Processing

Analyze multiple samples in a directory:

```bash
python3 batch_processing.py /path/to/malware/samples/ --parallel 4
```

**Output**: Consolidated report with comparative analysis across all samples.

### 3. YARA Rule Generation

Generate YARA signatures from analyzed samples:

```bash
python3 yara_generation.py --report-id 12345 --output custom_rules.yar
```

**Output**: Production-ready YARA rules with metadata and testing results.

### 4. Custom Reporting

Create custom reports tailored to your needs:

```bash
python3 reporting.py --format pdf --include-screenshots --executive-summary
```

## Example Files

| File | Description | Use Case |
|------|-------------|----------|
| `basic_analysis.py` | Single sample analysis | Quick malware triage |
| `batch_processing.py` | Parallel multi-sample analysis | Malware campaign analysis |
| `yara_generation.py` | Automated signature creation | Building detection rules |
| `reporting.py` | Custom report generation | Client deliverables |
| `advanced_integration.py` | SOAR/SIEM integration | Enterprise workflows |
| `sample_malware/eicar.com` | EICAR test file | Safe testing |

## Sample Data

The `sample_malware/` directory contains:

- **EICAR test file** - Safe "malware" for testing
- **Encrypted sample storage** - GPG-protected real malware samples (for authorized users)
- **Configuration examples** - Pre-configured analysis profiles

## Testing Your Setup

Use the EICAR test file to verify everything works:

```bash
python3 basic_analysis.py sample_malware/eicar.com
```

**Expected behavior**:
- ✅ Cuckoo analyzes the file
- ✅ YARA detects "EICAR_Test_File" signature
- ✅ Report generated successfully
- ✅ Network isolation confirmed (no internet access)

## Advanced Workflows

### Automated Threat Hunting

```python
# Search for samples matching specific YARA rules
from automation.batch_analyzer import BatchMalwareAnalyzer

analyzer = BatchMalwareAnalyzer()
results = analyzer.hunt_with_yara('rules/apt_signatures.yar', '/samples/')
```

### MITRE ATT&CK Mapping

```python
# Map observed behaviors to ATT&CK framework
from automation.mitre_attack_mapper import MITREMapper

mapper = MITREMapper()
techniques = mapper.map_behaviors(cuckoo_report)
print(f"Detected techniques: {techniques}")
```

### Integration with SIEM

```python
# Export IOCs to SIEM format
from automation.report_generator import ReportGenerator

generator = ReportGenerator()
iocs = generator.export_iocs(task_id, format='stix')
# Send to your SIEM platform
```

## Troubleshooting

**Issue**: "Connection refused" to Cuckoo API
- **Solution**: Ensure Cuckoo is running on REMnux VM (`cuckoo -d`)
- **Verify**: `curl http://192.168.1.10:8090/cuckoo/status`

**Issue**: "Module not found" errors
- **Solution**: Install dependencies: `pip install -r requirements.txt`
- **Verify**: `python3 -c "import requests, yara"`

**Issue**: Analysis hangs indefinitely
- **Solution**: Check VM network isolation: `./tests/test_isolation.sh`
- **Check logs**: `tail -f /shared/logs/orchestrator.log`

## Best Practices

1. **Always test with EICAR first** before analyzing real malware
2. **Verify network isolation** before each analysis session
3. **Encrypt malware samples** when storing: `gpg -c malware.exe`
4. **Review reports** manually - automation aids but doesn't replace expertise
5. **Update signatures regularly** - run YARA rule generation weekly

## Contributing Examples

Have a useful workflow? Contribute it!

1. Create a new `.py` file in `examples/`
2. Add clear comments and docstrings
3. Include expected output samples
4. Update this README with your example
5. Submit a pull request

See `CONTRIBUTING.md` for detailed guidelines.

## Legal Notice

⚠️ **WARNING**: Malware analysis must be conducted in authorized environments only.

- Review `LEGAL_FRAMEWORK.md` before analyzing real malware
- Only use samples from approved sources (VirusTotal, MalwareBazaar, etc.)
- Maintain chain-of-custody documentation
- Never execute malware outside isolated VMs

## Resources

- **MASARE Documentation**: `../docs/`
- **Cuckoo API Docs**: https://cuckoo.readthedocs.io/en/latest/
- **YARA Documentation**: https://yara.readthedocs.io/
- **MITRE ATT&CK**: https://attack.mitre.org/

## Support

- **GitHub Issues**: Report bugs or request features
- **Discussions**: Ask questions and share workflows
- **Documentation**: Comprehensive guides in `../docs/`

---

**Happy hunting!** 🔍🔒
