#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MASARE YARA Rule Generation Example

This script demonstrates how to generate custom YARA signatures from
analyzed malware samples, including hash-based, string-based, and
behavioral detection rules.

Copyright (c) 2025 MASARE Project
Licensed under the MIT License - see LICENSE file for details

Usage:
    python3 yara_generation.py /path/to/malware.exe
    python3 yara_generation.py /path/to/malware.exe --output custom_rules.yar
    python3 yara_generation.py --from-report 12345 --output apt_signatures.yar
"""

import sys
import argparse
import logging
from pathlib import Path
from datetime import datetime

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def setup_argument_parser():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description='Generate YARA signatures from malware samples',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Generate rules from malware sample
  python3 yara_generation.py ransomware.exe

  # Generate from existing Cuckoo report
  python3 yara_generation.py --from-report 12345

  # Custom output file
  python3 yara_generation.py malware.exe --output my_rules.yar

  # Generate behavioral rules only
  python3 yara_generation.py malware.exe --behavioral-only
        """
    )

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        'sample',
        type=str,
        nargs='?',
        help='Path to malware sample'
    )
    group.add_argument(
        '--from-report',
        type=int,
        metavar='TASK_ID',
        help='Generate rules from existing Cuckoo task ID'
    )

    parser.add_argument(
        '--output',
        type=str,
        default='generated_rules.yar',
        help='Output YARA rules file (default: generated_rules.yar)'
    )

    parser.add_argument(
        '--behavioral-only',
        action='store_true',
        help='Generate only behavioral rules (from Cuckoo analysis)'
    )

    parser.add_argument(
        '--hash-only',
        action='store_true',
        help='Generate only hash-based rules (fast detection)'
    )

    parser.add_argument(
        '--test',
        action='store_true',
        help='Test generated rules against the sample'
    )

    parser.add_argument(
        '--verbose',
        action='store_true',
        help='Enable verbose output'
    )

    return parser


def generate_from_sample(sample_path: Path, args):
    """
    Generate YARA rules from a malware sample.

    Args:
        sample_path: Path to the sample
        args: Command line arguments

    Returns:
        Generated YARA rules as string
    """
    logger.info(f"Analyzing sample: {sample_path.name}")

    try:
        from detection.yara.signature_generator import YARASignatureGenerator
        import hashlib

        generator = YARASignatureGenerator()

        # Calculate hashes
        logger.info("Calculating file hashes...")
        with open(sample_path, 'rb') as f:
            data = f.read()
            md5 = hashlib.md5(data).hexdigest()
            sha256 = hashlib.sha256(data).hexdigest()

        logger.info(f"  MD5: {md5}")
        logger.info(f"  SHA256: {sha256}")

        # Generate rules based on options
        rules = []

        if args.hash_only:
            logger.info("\nGenerating hash-based rule...")
            rule = generator.generate_hash_rule(
                md5=md5,
                sha256=sha256,
                sample_name=sample_path.stem
            )
            rules.append(rule)

        elif args.behavioral_only:
            logger.info("\nBehavioral rules require Cuckoo analysis.")
            logger.info("Please use --from-report with a task ID, or run without --behavioral-only")
            return None

        else:
            logger.info("\nGenerating comprehensive ruleset...")

            # Hash rule
            logger.info("  [1/3] Hash-based detection...")
            rules.append(generator.generate_hash_rule(md5, sha256, sample_path.stem))

            # String-based rule
            logger.info("  [2/3] String-based detection...")
            string_rule = generator.generate_string_rule(
                sample_path=str(sample_path),
                sample_name=sample_path.stem
            )
            if string_rule:
                rules.append(string_rule)

            # PE structure rule (if applicable)
            logger.info("  [3/3] Structural analysis...")
            if sample_path.suffix.lower() in ['.exe', '.dll', '.sys']:
                pe_rule = generator.generate_pe_rule(
                    sample_path=str(sample_path),
                    sample_name=sample_path.stem
                )
                if pe_rule:
                    rules.append(pe_rule)

        if not rules:
            logger.error("No rules generated!")
            return None

        # Combine rules
        yara_rules = '\n\n'.join(rules)

        # Add header
        header = f"""/*
 * YARA Rules Generated by MASARE
 * Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
 * Source: {sample_path.name}
 * MD5: {md5}
 * SHA256: {sha256}
 *
 * WARNING: These rules are auto-generated and should be validated
 * before deployment in production environments.
 */

import "hash"
import "pe"

"""
        yara_rules = header + yara_rules

        logger.info(f"\n✓ Generated {len(rules)} YARA rule(s)")
        return yara_rules

    except ImportError as e:
        logger.error(f"Failed to import YARA generator: {e}")
        return None

    except Exception as e:
        logger.error(f"Rule generation failed: {e}", exc_info=args.verbose)
        return None


def generate_from_report(task_id: int, args):
    """
    Generate YARA rules from existing Cuckoo report.

    Args:
        task_id: Cuckoo task ID
        args: Command line arguments

    Returns:
        Generated YARA rules as string
    """
    logger.info(f"Fetching Cuckoo report for task {task_id}...")

    try:
        from detection.yara.signature_generator import YARASignatureGenerator
        from analysis.cuckoo.orchestrator import CuckooClient

        # Fetch report
        cuckoo = CuckooClient()
        report = cuckoo.get_report(task_id)

        if not report:
            logger.error(f"Report not found for task {task_id}")
            return None

        # Extract IOCs
        logger.info("Extracting behavioral indicators...")
        iocs = cuckoo.extract_iocs(report)

        logger.info(f"  - Domains: {len(iocs.get('domains', []))}")
        logger.info(f"  - IPs: {len(iocs.get('ips', []))}")
        logger.info(f"  - Files: {len(iocs.get('files', []))}")
        logger.info(f"  - Registry: {len(iocs.get('registry', []))}")

        # Generate behavioral rule
        logger.info("\nGenerating behavioral YARA rule...")
        generator = YARASignatureGenerator()

        rule = generator.generate_behavioral_rule(
            iocs=iocs,
            sample_name=f"task_{task_id}"
        )

        if not rule:
            logger.error("Failed to generate behavioral rule")
            return None

        # Add header
        header = f"""/*
 * Behavioral YARA Rules Generated by MASARE
 * Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
 * Source: Cuckoo Task {task_id}
 *
 * These rules detect behavioral patterns observed during dynamic analysis.
 */

"""
        yara_rules = header + rule

        logger.info("✓ Generated behavioral YARA rule")
        return yara_rules

    except ImportError as e:
        logger.error(f"Failed to import required modules: {e}")
        return None

    except Exception as e:
        logger.error(f"Rule generation failed: {e}", exc_info=args.verbose)
        return None


def test_yara_rules(rules: str, sample_path: Path):
    """
    Test generated YARA rules against the sample.

    Args:
        rules: YARA rules as string
        sample_path: Path to test sample

    Returns:
        True if rules match, False otherwise
    """
    logger.info("\nTesting generated rules...")

    try:
        import yara
        import tempfile

        # Write rules to temp file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yar', delete=False) as f:
            f.write(rules)
            rules_file = f.name

        # Compile and test
        compiled_rules = yara.compile(filepath=rules_file)
        matches = compiled_rules.match(str(sample_path))

        # Clean up
        Path(rules_file).unlink()

        if matches:
            logger.info(f"✓ Rules matched! Detected as: {', '.join(m.rule for m in matches)}")
            return True
        else:
            logger.warning("✗ Rules did not match the sample (this may indicate an issue)")
            return False

    except Exception as e:
        logger.error(f"Rule testing failed: {e}")
        return False


def main():
    """Main entry point."""
    parser = setup_argument_parser()
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    logger.info("="*70)
    logger.info(f"MASARE YARA Rule Generator - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    logger.info("="*70)

    # Generate rules
    if args.from_report:
        rules = generate_from_report(args.from_report, args)
        sample_path = None
    else:
        sample_path = Path(args.sample).resolve()
        if not sample_path.exists():
            logger.error(f"Sample not found: {sample_path}")
            sys.exit(1)
        rules = generate_from_sample(sample_path, args)

    if not rules:
        logger.error("\n✗ Rule generation failed!")
        sys.exit(1)

    # Save rules
    output_file = Path(args.output).resolve()
    output_file.parent.mkdir(parents=True, exist_ok=True)

    with open(output_file, 'w') as f:
        f.write(rules)

    logger.info(f"\nYARA rules saved to: {output_file}")
    logger.info(f"Size: {len(rules)} bytes")

    # Test if requested
    if args.test and sample_path:
        test_yara_rules(rules, sample_path)

    logger.info("\n" + "="*70)
    logger.info("Next Steps:")
    logger.info(f"  1. Review rules: cat {output_file}")
    logger.info(f"  2. Test rules: yara {output_file} /path/to/samples/")
    logger.info(f"  3. Deploy to your detection systems")
    logger.info("="*70)

    logger.info("\n✓ YARA rule generation completed!")
    sys.exit(0)


if __name__ == '__main__':
    main()
