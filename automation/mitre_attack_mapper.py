#!/usr/bin/env python3
"""
MITRE ATT&CK Behavior Mapper for MASARE
Purpose: Map malware behaviors to MITRE ATT&CK framework
Author: Security Research Team
Last Updated: 2025-11-15

Usage:
    python3 mitre_attack_mapper.py --analysis-report /path/to/report.json
    python3 mitre_attack_mapper.py --behaviors "process_creation,registry_modification"
"""

import argparse
import json
import logging
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Set

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger('MASARE.MITREMapper')


class MITREATTACKMapper:
    """Map observed malware behaviors to MITRE ATT&CK techniques"""

    def __init__(self):
        self.behavior_mappings = self._load_behavior_mappings()
        self.technique_database = self._load_technique_database()

    def _load_behavior_mappings(self) -> Dict[str, List[str]]:
        """Load behavior-to-technique mappings"""
        return {
            # Execution
            'winexec': ['T1106'],  # Native API
            'shellexecute': ['T1059.003'],  # Command and Scripting Interpreter: Windows Command Shell
            'createprocess': ['T1106', 'T1059'],  # Native API, Command and Scripting Interpreter
            'powershell_execution': ['T1059.001'],  # PowerShell
            'wscript_execution': ['T1059.005'],  # Visual Basic

            # Persistence
            'registry_run_key': ['T1547.001'],  # Boot or Logon Autostart Execution: Registry Run Keys
            'scheduled_task': ['T1053.005'],  # Scheduled Task/Job: Scheduled Task
            'service_creation': ['T1543.003'],  # Create or Modify System Process: Windows Service
            'startup_folder': ['T1547.001'],  # Boot or Logon Autostart Execution

            # Privilege Escalation
            'token_manipulation': ['T1134'],  # Access Token Manipulation
            'process_injection': ['T1055'],  # Process Injection
            'dll_injection': ['T1055.001'],  # Process Injection: Dynamic-link Library Injection

            # Defense Evasion
            'virtualallocex': ['T1055'],  # Process Injection
            'writeprocessmemory': ['T1055'],  # Process Injection
            'anti_debugging': ['T1622'],  # Debugger Evasion
            'anti_vm': ['T1497'],  # Virtualization/Sandbox Evasion
            'obfuscation': ['T1027'],  # Obfuscated Files or Information
            'dll_sideloading': ['T1574.002'],  # Hijack Execution Flow: DLL Side-Loading

            # Credential Access
            'credential_dumping': ['T1003'],  # OS Credential Dumping
            'lsass_access': ['T1003.001'],  # OS Credential Dumping: LSASS Memory
            'keylogging': ['T1056.001'],  # Input Capture: Keylogging
            'credential_from_registry': ['T1552.002'],  # Unsecured Credentials: Credentials in Registry

            # Discovery
            'process_discovery': ['T1057'],  # Process Discovery
            'file_discovery': ['T1083'],  # File and Directory Discovery
            'system_info': ['T1082'],  # System Information Discovery
            'network_discovery': ['T1016'],  # System Network Configuration Discovery

            # Lateral Movement
            'remote_services': ['T1021'],  # Remote Services
            'smb_lateral': ['T1021.002'],  # Remote Services: SMB/Windows Admin Shares
            'wmi_execution': ['T1047'],  # Windows Management Instrumentation

            # Collection
            'clipboard_data': ['T1115'],  # Clipboard Data
            'screen_capture': ['T1113'],  # Screen Capture
            'file_collection': ['T1005'],  # Data from Local System

            # Command and Control
            'http_c2': ['T1071.001'],  # Application Layer Protocol: Web Protocols
            'dns_tunneling': ['T1071.004'],  # Application Layer Protocol: DNS
            'encrypted_channel': ['T1573'],  # Encrypted Channel

            # Exfiltration
            'exfiltration_c2': ['T1041'],  # Exfiltration Over C2 Channel
            'exfiltration_web': ['T1048.003'],  # Exfiltration Over Alternative Protocol: Exfiltration Over Unencrypted Non-C2 Protocol

            # Impact
            'file_encryption': ['T1486'],  # Data Encrypted for Impact
            'data_destruction': ['T1485'],  # Data Destruction
            'service_stop': ['T1489'],  # Service Stop
        }

    def _load_technique_database(self) -> Dict[str, Dict]:
        """Load MITRE ATT&CK technique details"""
        return {
            'T1106': {
                'name': 'Native API',
                'tactic': 'Execution',
                'description': 'Adversaries may interact with the native OS API to execute behaviors.'
            },
            'T1059': {
                'name': 'Command and Scripting Interpreter',
                'tactic': 'Execution',
                'description': 'Adversaries may abuse command and script interpreters to execute commands.'
            },
            'T1059.001': {
                'name': 'PowerShell',
                'tactic': 'Execution',
                'description': 'Adversaries may abuse PowerShell commands and scripts for execution.'
            },
            'T1059.003': {
                'name': 'Windows Command Shell',
                'tactic': 'Execution',
                'description': 'Adversaries may abuse the Windows command shell for execution.'
            },
            'T1059.005': {
                'name': 'Visual Basic',
                'tactic': 'Execution',
                'description': 'Adversaries may abuse Visual Basic (VB) for execution.'
            },
            'T1547.001': {
                'name': 'Registry Run Keys / Startup Folder',
                'tactic': 'Persistence',
                'description': 'Adversaries may achieve persistence by adding a program to a startup folder or registry run key.'
            },
            'T1053.005': {
                'name': 'Scheduled Task',
                'tactic': 'Persistence',
                'description': 'Adversaries may abuse the Windows Task Scheduler to perform task scheduling for initial or recurring execution of malicious code.'
            },
            'T1543.003': {
                'name': 'Windows Service',
                'tactic': 'Persistence',
                'description': 'Adversaries may create or modify Windows services to repeatedly execute malicious payloads as part of persistence.'
            },
            'T1134': {
                'name': 'Access Token Manipulation',
                'tactic': 'Privilege Escalation',
                'description': 'Adversaries may modify access tokens to operate under a different user or system security context.'
            },
            'T1055': {
                'name': 'Process Injection',
                'tactic': 'Defense Evasion',
                'description': 'Adversaries may inject code into processes in order to evade process-based defenses as well as possibly elevate privileges.'
            },
            'T1055.001': {
                'name': 'DLL Injection',
                'tactic': 'Defense Evasion',
                'description': 'Adversaries may inject dynamic-link libraries (DLLs) into processes in order to evade process-based defenses.'
            },
            'T1622': {
                'name': 'Debugger Evasion',
                'tactic': 'Defense Evasion',
                'description': 'Adversaries may employ various means to detect and avoid debuggers.'
            },
            'T1497': {
                'name': 'Virtualization/Sandbox Evasion',
                'tactic': 'Defense Evasion',
                'description': 'Adversaries may employ various means to detect and avoid virtualization and sandbox environments.'
            },
            'T1027': {
                'name': 'Obfuscated Files or Information',
                'tactic': 'Defense Evasion',
                'description': 'Adversaries may attempt to make an executable or file difficult to discover or analyze.'
            },
            'T1574.002': {
                'name': 'DLL Side-Loading',
                'tactic': 'Defense Evasion',
                'description': 'Adversaries may execute their own malicious payloads by side-loading DLLs.'
            },
            'T1003': {
                'name': 'OS Credential Dumping',
                'tactic': 'Credential Access',
                'description': 'Adversaries may attempt to dump credentials to obtain account login and credential material.'
            },
            'T1003.001': {
                'name': 'LSASS Memory',
                'tactic': 'Credential Access',
                'description': 'Adversaries may attempt to access credential material stored in the process memory of the Local Security Authority Subsystem Service (LSASS).'
            },
            'T1056.001': {
                'name': 'Keylogging',
                'tactic': 'Credential Access',
                'description': 'Adversaries may log user keystrokes to intercept credentials as the user types them.'
            },
            'T1552.002': {
                'name': 'Credentials in Registry',
                'tactic': 'Credential Access',
                'description': 'Adversaries may search the Registry on compromised systems for insecurely stored credentials.'
            },
            'T1057': {
                'name': 'Process Discovery',
                'tactic': 'Discovery',
                'description': 'Adversaries may attempt to get information about running processes on a system.'
            },
            'T1083': {
                'name': 'File and Directory Discovery',
                'tactic': 'Discovery',
                'description': 'Adversaries may enumerate files and directories or may search in specific locations of a host or network share for certain information.'
            },
            'T1082': {
                'name': 'System Information Discovery',
                'tactic': 'Discovery',
                'description': 'An adversary may attempt to get detailed information about the operating system and hardware.'
            },
            'T1016': {
                'name': 'System Network Configuration Discovery',
                'tactic': 'Discovery',
                'description': 'Adversaries may look for details about the network configuration and settings of systems.'
            },
            'T1021': {
                'name': 'Remote Services',
                'tactic': 'Lateral Movement',
                'description': 'Adversaries may use Valid Accounts to log into a service specifically designed to accept remote connections.'
            },
            'T1021.002': {
                'name': 'SMB/Windows Admin Shares',
                'tactic': 'Lateral Movement',
                'description': 'Adversaries may use SMB/Windows Admin Shares to move laterally through a network.'
            },
            'T1047': {
                'name': 'Windows Management Instrumentation',
                'tactic': 'Lateral Movement',
                'description': 'Adversaries may abuse WMI to execute malicious commands and payloads.'
            },
            'T1115': {
                'name': 'Clipboard Data',
                'tactic': 'Collection',
                'description': 'Adversaries may collect data stored in the clipboard from users copying information within or between applications.'
            },
            'T1113': {
                'name': 'Screen Capture',
                'tactic': 'Collection',
                'description': 'Adversaries may attempt to take screen captures of the desktop to gather information over the course of an operation.'
            },
            'T1005': {
                'name': 'Data from Local System',
                'tactic': 'Collection',
                'description': 'Adversaries may search local system sources, such as file systems or local databases, to find files of interest.'
            },
            'T1071.001': {
                'name': 'Web Protocols',
                'tactic': 'Command and Control',
                'description': 'Adversaries may communicate using application layer protocols associated with web traffic to avoid detection/network filtering.'
            },
            'T1071.004': {
                'name': 'DNS',
                'tactic': 'Command and Control',
                'description': 'Adversaries may communicate using the Domain Name System (DNS) application layer protocol to avoid detection/network filtering.'
            },
            'T1573': {
                'name': 'Encrypted Channel',
                'tactic': 'Command and Control',
                'description': 'Adversaries may employ a known encryption algorithm to conceal command and control traffic.'
            },
            'T1041': {
                'name': 'Exfiltration Over C2 Channel',
                'tactic': 'Exfiltration',
                'description': 'Adversaries may steal data by exfiltrating it over an existing command and control channel.'
            },
            'T1048.003': {
                'name': 'Exfiltration Over Unencrypted Non-C2 Protocol',
                'tactic': 'Exfiltration',
                'description': 'Adversaries may steal data by exfiltrating it over an un-encrypted network protocol other than that of the existing command and control channel.'
            },
            'T1486': {
                'name': 'Data Encrypted for Impact',
                'tactic': 'Impact',
                'description': 'Adversaries may encrypt data on target systems or on large numbers of systems in a network to interrupt availability to system and network resources.'
            },
            'T1485': {
                'name': 'Data Destruction',
                'tactic': 'Impact',
                'description': 'Adversaries may destroy data and files on specific systems or in large numbers on a network to interrupt availability to systems, services, and network resources.'
            },
            'T1489': {
                'name': 'Service Stop',
                'tactic': 'Impact',
                'description': 'Adversaries may stop or disable services on a system to render those services unavailable to legitimate users.'
            },
        }

    def map_behaviors_to_mitre(self, observed_behaviors: List[str]) -> List[Dict]:
        """Map observed behaviors to MITRE ATT&CK techniques"""
        mappings = []
        seen_techniques = set()

        for behavior in observed_behaviors:
            behavior_lower = behavior.lower()

            # Find matching techniques
            matching_techniques = []
            for behavior_pattern, technique_ids in self.behavior_mappings.items():
                if behavior_pattern in behavior_lower:
                    matching_techniques.extend(technique_ids)

            # Get technique details
            for technique_id in set(matching_techniques):
                if technique_id in seen_techniques:
                    continue

                seen_techniques.add(technique_id)
                technique = self.technique_database.get(technique_id, {})

                mappings.append({
                    'observed_behavior': behavior,
                    'technique_id': technique_id,
                    'technique_name': technique.get('name', 'Unknown'),
                    'tactic': technique.get('tactic', 'Unknown'),
                    'description': technique.get('description', ''),
                    'confidence': 'HIGH' if technique else 'MEDIUM',
                })

        logger.info(f"[+] Mapped {len(mappings)} behaviors to MITRE ATT&CK techniques")
        return mappings

    def map_from_analysis_report(self, analysis_report: Dict) -> List[Dict]:
        """Extract behaviors from analysis report and map to MITRE"""
        observed_behaviors = []

        # Extract from IOCs
        iocs = analysis_report.get('iocs', {})

        # API calls
        for api in iocs.get('api_calls', []):
            observed_behaviors.append(f"API: {api}")

        # Registry keys
        for reg_key in iocs.get('registry_keys', []):
            if 'run' in reg_key.lower() or 'currentversion' in reg_key.lower():
                observed_behaviors.append('registry_run_key')

        # Process creation
        if len(iocs.get('processes', [])) > 1:
            observed_behaviors.append('createprocess')

        # Network activity
        if iocs.get('domains') or iocs.get('urls'):
            observed_behaviors.append('http_c2')

        # Check for specific suspicious patterns
        suspicious_patterns = analysis_report.get('suspicious_patterns', [])
        for pattern in suspicious_patterns:
            pattern_type = pattern.get('type', '').lower()
            if 'injection' in pattern_type:
                observed_behaviors.append('process_injection')
            elif 'keylog' in pattern_type:
                observed_behaviors.append('keylogging')
            elif 'anti-debugging' in pattern_type:
                observed_behaviors.append('anti_debugging')
            elif 'vm' in pattern_type:
                observed_behaviors.append('anti_vm')

        return self.map_behaviors_to_mitre(observed_behaviors)

    def generate_navigator_layer(self, mappings: List[Dict], output_path: str = None) -> Dict:
        """Generate MITRE ATT&CK Navigator layer JSON"""
        navigator_data = {
            "name": "MASARE Malware Analysis",
            "versions": {
                "attack": "13",
                "navigator": "4.8.1",
                "layer": "4.4"
            },
            "domain": "enterprise-attack",
            "description": f"MITRE ATT&CK mapping generated by MASARE on {datetime.now().isoformat()}",
            "filters": {
                "platforms": ["windows"]
            },
            "sorting": 0,
            "layout": {
                "layout": "side",
                "showID": True,
                "showName": True
            },
            "hideDisabled": False,
            "techniques": [],
            "gradient": {
                "colors": [
                    "#ff6666",
                    "#ffe766",
                    "#8ec843"
                ],
                "minValue": 0,
                "maxValue": 100
            },
            "legendItems": [],
            "metadata": [],
            "showTacticRowBackground": False,
            "tacticRowBackground": "#dddddd",
            "selectTechniquesAcrossTactics": True,
            "selectSubtechniquesWithParent": False
        }

        # Add techniques to layer
        for mapping in mappings:
            navigator_data['techniques'].append({
                "techniqueID": mapping['technique_id'],
                "tactic": mapping['tactic'].lower().replace(' ', '-'),
                "color": "#ff6666" if mapping['confidence'] == 'HIGH' else "#ffe766",
                "comment": mapping['observed_behavior'],
                "enabled": True,
                "metadata": [],
                "links": [],
                "showSubtechniques": False
            })

        # Save to file if path provided
        if output_path:
            output_file = Path(output_path)
            output_file.parent.mkdir(parents=True, exist_ok=True)
            with open(output_file, 'w') as f:
                json.dump(navigator_data, f, indent=2)
            logger.info(f"[+] Navigator layer saved to {output_path}")

        return navigator_data


def main():
    parser = argparse.ArgumentParser(description='MASARE MITRE ATT&CK Mapper')

    parser.add_argument('--analysis-report', type=str, help='Path to analysis report JSON')
    parser.add_argument('--behaviors', type=str, help='Comma-separated list of behaviors')
    parser.add_argument('--output', type=str, help='Output JSON file path')
    parser.add_argument('--navigator', type=str, help='Generate ATT&CK Navigator layer JSON')

    args = parser.parse_args()

    mapper = MITREATTACKMapper()

    try:
        if args.analysis_report:
            # Load analysis report
            with open(args.analysis_report, 'r') as f:
                report = json.load(f)

            # Map behaviors
            mappings = mapper.map_from_analysis_report(report)

            # Print mappings
            print("\n" + "="*60)
            print("MITRE ATT&CK Behavior Mapping")
            print("="*60)
            for mapping in mappings:
                print(f"\n[{mapping['technique_id']}] {mapping['technique_name']}")
                print(f"  Tactic: {mapping['tactic']}")
                print(f"  Confidence: {mapping['confidence']}")
                print(f"  Observed: {mapping['observed_behavior']}")

            # Save to file
            if args.output:
                with open(args.output, 'w') as f:
                    json.dump(mappings, f, indent=2)
                print(f"\n[✓] Mappings saved to {args.output}")

            # Generate Navigator layer
            if args.navigator:
                mapper.generate_navigator_layer(mappings, args.navigator)
                print(f"[✓] Navigator layer saved to {args.navigator}")

        elif args.behaviors:
            # Map provided behaviors
            behaviors = args.behaviors.split(',')
            mappings = mapper.map_behaviors_to_mitre(behaviors)

            for mapping in mappings:
                print(f"[{mapping['technique_id']}] {mapping['technique_name']} - {mapping['tactic']}")

        else:
            parser.print_help()
            sys.exit(1)

    except Exception as e:
        logger.error(f"[✗] Error: {e}", exc_info=True)
        sys.exit(1)


if __name__ == '__main__':
    main()
