#!/usr/bin/env python3
"""
YARA Signature Generator for MASARE
Purpose: Automated YARA rule generation from malware analysis
Author: Security Research Team
Last Updated: 2025-11-15

Usage:
    python3 signature_generator.py --sample /path/to/malware.exe --output rules.yar
    python3 signature_generator.py --analysis-report /path/to/report.json --output rules.yar
"""

import argparse
import hashlib
import json
import logging
import os
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Set

try:
    import yara
except ImportError:
    print("[!] YARA Python module not installed")
    print("[i] Install: pip install yara-python")
    sys.exit(1)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('YARA.Generator')


class YARASignatureGenerator:
    """Generate YARA detection rules from malware analysis"""

    def __init__(self, output_file: str = None):
        self.output_file = output_file or '/shared/detection/yara/generated_rules.yar'
        self.rules = []

    def generate_from_sample(self, sample_path: str, analysis_data: Dict = None) -> str:
        """Generate YARA rule from malware sample"""

        sample_path = Path(sample_path)
        if not sample_path.exists():
            raise FileNotFoundError(f"Sample not found: {sample_path}")

        # Read sample
        with open(sample_path, 'rb') as f:
            sample_data = f.read()

        # Calculate hashes
        md5 = hashlib.md5(sample_data).hexdigest()
        sha256 = hashlib.sha256(sample_data).hexdigest()

        # Generate safe rule name
        rule_name = self._sanitize_rule_name(sample_path.stem)

        # Generate hash-based rule (high precision)
        hash_rule = self._generate_hash_rule(
            rule_name=f"{rule_name}_hash",
            md5=md5,
            sha256=sha256,
            sample_name=sample_path.name
        )

        self.rules.append(hash_rule)

        # Generate behavioral rule if analysis data provided
        if analysis_data:
            behavioral_rule = self._generate_behavioral_rule(
                rule_name=f"{rule_name}_behavior",
                analysis_data=analysis_data,
                sample_name=sample_path.name
            )
            self.rules.append(behavioral_rule)

        # Generate string-based rule
        strings_rule = self._generate_string_rule(
            rule_name=f"{rule_name}_strings",
            sample_data=sample_data,
            sample_name=sample_path.name
        )
        self.rules.append(strings_rule)

        logger.info(f"[+] Generated {len(self.rules)} rules for {sample_path.name}")

        return '\n\n'.join(self.rules)

    def _sanitize_rule_name(self, name: str) -> str:
        """Sanitize name for YARA rule compatibility"""
        # YARA rules: alphanumeric and underscores only
        sanitized = ''.join(c if c.isalnum() or c == '_' else '_' for c in name)
        # Ensure starts with letter
        if not sanitized[0].isalpha():
            sanitized = 'rule_' + sanitized
        return sanitized

    def _generate_hash_rule(self, rule_name: str, md5: str, sha256: str, sample_name: str) -> str:
        """Generate hash-based YARA rule (100% precision, 0% false positives)"""

        rule = f'''rule {rule_name} {{
    meta:
        description = "Hash-based detection for {sample_name}"
        author = "MASARE Automated Analysis"
        date = "{datetime.now().strftime('%Y-%m-%d')}"
        hash_md5 = "{md5}"
        hash_sha256 = "{sha256}"
        severity = "CRITICAL"
        confidence = "HIGH"

    condition:
        // PE file header
        uint16(0) == 0x5A4D and
        // Hash match
        (
            hash.md5(0, filesize) == "{md5}" or
            hash.sha256(0, filesize) == "{sha256}"
        )
}}'''

        return rule

    def _generate_behavioral_rule(self, rule_name: str, analysis_data: Dict, sample_name: str) -> str:
        """Generate behavior-based YARA rule (generic detection, may catch variants)"""

        # Extract IOCs from analysis
        iocs = analysis_data.get('iocs', {})

        strings_section = []
        condition_parts = []

        # Add suspicious strings
        suspicious_strings = iocs.get('suspicious_strings', [])[:10]  # Limit to 10 strings
        for i, string_obj in enumerate(suspicious_strings):
            if isinstance(string_obj, dict):
                string_value = string_obj.get('value', '')
            else:
                string_value = str(string_obj)

            # Escape special characters
            escaped = string_value.replace('\\', '\\\\').replace('"', '\\"')

            if len(escaped) > 4:  # Only meaningful strings
                strings_section.append(f'        $str{i} = "{escaped}" wide ascii nocase')

        # Add suspicious API calls
        suspicious_apis = iocs.get('suspicious_apis', [])[:5]
        for i, api_obj in enumerate(suspicious_apis):
            if isinstance(api_obj, dict):
                api_name = api_obj.get('api', '')
            else:
                api_name = str(api_obj)

            if api_name:
                strings_section.append(f'        $api{i} = "{api_name}" wide ascii')

        # Add network indicators
        domains = iocs.get('domains', [])[:3]
        for i, domain in enumerate(domains):
            if domain and not domain.startswith('127.'):
                strings_section.append(f'        $domain{i} = "{domain}" ascii')

        # Build condition
        num_strings = len(strings_section)
        if num_strings >= 3:
            condition_parts.append(f"{min(3, num_strings)} of them")
        elif num_strings > 0:
            condition_parts.append(f"any of them")

        # Metadata
        threat_level = analysis_data.get('summary', {}).get('threat_level', 'UNKNOWN')
        family = analysis_data.get('family', 'Unknown')

        rule = f'''rule {rule_name} {{
    meta:
        description = "Behavioral detection for {sample_name}"
        author = "MASARE Automated Analysis"
        date = "{datetime.now().strftime('%Y-%m-%d')}"
        family = "{family}"
        severity = "{threat_level}"
        confidence = "MEDIUM"

    strings:
{chr(10).join(strings_section) if strings_section else '        // No strings extracted'}

    condition:
        uint16(0) == 0x5A4D and  // PE header
        {' and '.join(condition_parts) if condition_parts else 'false'}
}}'''

        return rule

    def _generate_string_rule(self, rule_name: str, sample_data: bytes, sample_name: str) -> str:
        """Generate string-based YARA rule from binary content"""

        # Extract interesting strings (ASCII printable)
        strings = self._extract_strings(sample_data, min_length=8)

        # Filter for suspicious patterns
        suspicious_strings = []
        suspicious_patterns = [
            'http://', 'https://', '.exe', '.dll', '.bat', '.ps1',
            'cmd.exe', 'powershell', 'regsvr32', 'rundll32',
            'SOFTWARE\\', 'CurrentVersion\\Run', 'AppData',
            'kernel32', 'ntdll', 'advapi32', 'user32',
        ]

        for string in strings[:50]:  # Limit to 50 strings
            for pattern in suspicious_patterns:
                if pattern.lower() in string.lower():
                    suspicious_strings.append(string)
                    break

        # Build strings section
        strings_section = []
        for i, string in enumerate(suspicious_strings[:15]):  # Max 15 strings
            escaped = string.replace('\\', '\\\\').replace('"', '\\"')
            strings_section.append(f'        $str{i} = "{escaped}" wide ascii nocase')

        # Calculate file size range (±10%)
        filesize = len(sample_data)
        size_min = int(filesize * 0.9)
        size_max = int(filesize * 1.1)

        rule = f'''rule {rule_name} {{
    meta:
        description = "String-based detection for {sample_name}"
        author = "MASARE Automated Analysis"
        date = "{datetime.now().strftime('%Y-%m-%d')}"
        reference = "{sample_name}"
        confidence = "LOW"

    strings:
{chr(10).join(strings_section) if strings_section else '        // No suspicious strings found'}

    condition:
        uint16(0) == 0x5A4D and  // PE header
        filesize > {size_min} and filesize < {size_max} and
        {f"{min(3, len(strings_section))} of them" if strings_section else "false"}
}}'''

        return rule

    def _extract_strings(self, data: bytes, min_length: int = 4) -> List[str]:
        """Extract ASCII strings from binary data"""
        strings = []
        current_string = []

        for byte in data:
            # Printable ASCII characters
            if 32 <= byte <= 126:
                current_string.append(chr(byte))
            else:
                if len(current_string) >= min_length:
                    strings.append(''.join(current_string))
                current_string = []

        # Don't forget last string
        if len(current_string) >= min_length:
            strings.append(''.join(current_string))

        return strings

    def compile_and_test(self, test_samples: List[str] = None) -> Dict:
        """Compile YARA rules and validate"""

        logger.info("[*] Compiling YARA rules...")

        # Write rules to temporary file
        temp_rules_file = '/tmp/test_rules.yar'
        with open(temp_rules_file, 'w') as f:
            f.write('\n\n'.join(self.rules))

        try:
            # Compile rules
            compiled_rules = yara.compile(filepath=temp_rules_file)
            logger.info("[✓] Rules compiled successfully")

            results = {
                'compiled_successfully': True,
                'num_rules': len(self.rules),
                'detection_stats': {},
            }

            # Test against samples if provided
            if test_samples:
                logger.info(f"[*] Testing rules against {len(test_samples)} samples...")
                for sample_path in test_samples:
                    try:
                        matches = compiled_rules.match(sample_path)
                        results['detection_stats'][sample_path] = {
                            'matched': len(matches) > 0,
                            'num_matches': len(matches),
                            'rules_triggered': [m.rule for m in matches],
                        }
                        logger.info(f"[+] {sample_path}: {len(matches)} matches")
                    except Exception as e:
                        logger.error(f"[-] Error testing {sample_path}: {e}")

            return results

        except yara.SyntaxError as e:
            logger.error(f"[✗] YARA syntax error: {e}")
            return {
                'compiled_successfully': False,
                'error': str(e),
            }
        except Exception as e:
            logger.error(f"[✗] Compilation failed: {e}")
            return {
                'compiled_successfully': False,
                'error': str(e),
            }
        finally:
            # Cleanup
            if os.path.exists(temp_rules_file):
                os.remove(temp_rules_file)

    def save_rules(self, output_file: str = None):
        """Save generated rules to file"""

        output_file = output_file or self.output_file
        output_path = Path(output_file)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        with open(output_path, 'w') as f:
            f.write('\n\n'.join(self.rules))

        logger.info(f"[✓] Saved {len(self.rules)} rules to {output_path}")


def main():
    parser = argparse.ArgumentParser(
        description='MASARE YARA Signature Generator',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    parser.add_argument('--sample', type=str, help='Path to malware sample')
    parser.add_argument('--analysis-report', type=str, help='Path to analysis report JSON')
    parser.add_argument('--output', type=str, default='/shared/detection/yara/generated_rules.yar',
                       help='Output YARA rules file')
    parser.add_argument('--test-samples', nargs='+', help='Test samples for validation')
    parser.add_argument('--compile-only', action='store_true', help='Only compile existing rules')

    args = parser.parse_args()

    generator = YARASignatureGenerator(output_file=args.output)

    try:
        if args.compile_only:
            # Load existing rules and compile
            with open(args.output, 'r') as f:
                generator.rules = [f.read()]
            results = generator.compile_and_test(args.test_samples)
            print(json.dumps(results, indent=2))

        elif args.sample:
            # Load analysis report if provided
            analysis_data = None
            if args.analysis_report:
                with open(args.analysis_report, 'r') as f:
                    analysis_data = json.load(f)

            # Generate rules
            rules_text = generator.generate_from_sample(args.sample, analysis_data)
            print("\n" + "="*60)
            print("Generated YARA Rules:")
            print("="*60)
            print(rules_text)

            # Compile and test
            results = generator.compile_and_test(args.test_samples or [args.sample])

            if results['compiled_successfully']:
                # Save rules
                generator.save_rules()
                print("\n[✓] Rules generated, compiled, and saved successfully")
            else:
                print(f"\n[✗] Compilation failed: {results.get('error')}")
                sys.exit(1)

        else:
            parser.print_help()
            sys.exit(1)

    except Exception as e:
        logger.error(f"[✗] Fatal error: {e}", exc_info=True)
        sys.exit(1)


if __name__ == '__main__':
    main()
