#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MASARE Basic Analysis Example

This script demonstrates how to analyze a single malware sample using MASARE.
It performs dynamic analysis with Cuckoo, static analysis with Ghidra,
generates YARA signatures, and produces a comprehensive report.

Copyright (c) 2025 MASARE Project
Licensed under the MIT License - see LICENSE file for details

Usage:
    python3 basic_analysis.py /path/to/malware.exe
    python3 basic_analysis.py /path/to/malware.exe --timeout 180 --output ./my_reports/
"""

import sys
import argparse
import logging
from pathlib import Path
from datetime import datetime

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler('basic_analysis.log')
    ]
)
logger = logging.getLogger(__name__)


def setup_argument_parser():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description='Analyze a single malware sample with MASARE',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic analysis
  python3 basic_analysis.py suspicious.exe

  # Extended analysis with 5-minute timeout
  python3 basic_analysis.py ransomware.exe --timeout 300

  # Custom output directory
  python3 basic_analysis.py trojan.dll --output /reports/2025-01/

  # Skip static analysis (faster)
  python3 basic_analysis.py sample.exe --no-ghidra
        """
    )

    parser.add_argument(
        'sample',
        type=str,
        help='Path to malware sample to analyze'
    )

    parser.add_argument(
        '--timeout',
        type=int,
        default=120,
        help='Analysis timeout in seconds (default: 120)'
    )

    parser.add_argument(
        '--output',
        type=str,
        default='./reports',
        help='Output directory for reports (default: ./reports)'
    )

    parser.add_argument(
        '--no-ghidra',
        action='store_true',
        help='Skip Ghidra static analysis (faster but less comprehensive)'
    )

    parser.add_argument(
        '--cuckoo-url',
        type=str,
        default='http://192.168.1.10:8090',
        help='Cuckoo API URL (default: http://192.168.1.10:8090)'
    )

    parser.add_argument(
        '--verbose',
        action='store_true',
        help='Enable verbose output'
    )

    return parser


def validate_sample(sample_path: Path) -> bool:
    """
    Validate the malware sample exists and is accessible.

    Args:
        sample_path: Path to the malware sample

    Returns:
        True if valid, False otherwise
    """
    if not sample_path.exists():
        logger.error(f"Sample not found: {sample_path}")
        return False

    if not sample_path.is_file():
        logger.error(f"Path is not a file: {sample_path}")
        return False

    if sample_path.stat().st_size == 0:
        logger.error(f"Sample is empty: {sample_path}")
        return False

    logger.info(f"✓ Sample validated: {sample_path.name} ({sample_path.stat().st_size} bytes)")
    return True


def analyze_sample(args):
    """
    Main analysis function.

    Args:
        args: Parsed command line arguments

    Returns:
        Dictionary containing analysis results
    """
    sample_path = Path(args.sample).resolve()
    output_dir = Path(args.output).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    # Validate sample
    if not validate_sample(sample_path):
        return None

    logger.info("="*70)
    logger.info(f"MASARE Malware Analysis - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    logger.info("="*70)
    logger.info(f"Sample: {sample_path.name}")
    logger.info(f"Size: {sample_path.stat().st_size:,} bytes")
    logger.info(f"Output: {output_dir}")
    logger.info(f"Timeout: {args.timeout}s")
    logger.info("="*70)

    try:
        # Import analysis modules
        logger.info("\n[1/5] Importing MASARE modules...")
        from analysis.cuckoo.orchestrator import MalwareAnalysisOrchestrator
        from detection.yara.signature_generator import YARASignatureGenerator
        from automation.report_generator import ReportGenerator

        # Initialize orchestrator
        logger.info("\n[2/5] Initializing analysis orchestrator...")
        orchestrator = MalwareAnalysisOrchestrator(
            cuckoo_url=args.cuckoo_url,
            output_dir=str(output_dir)
        )

        # Submit to Cuckoo for dynamic analysis
        logger.info("\n[3/5] Submitting to Cuckoo Sandbox for dynamic analysis...")
        logger.info(f"    This may take up to {args.timeout} seconds...")

        analysis_result = orchestrator.analyze_sample(
            sample_path=str(sample_path),
            timeout=args.timeout,
            enable_ghidra=not args.no_ghidra
        )

        if analysis_result.get('status') != 'success':
            logger.error(f"Analysis failed: {analysis_result.get('error', 'Unknown error')}")
            return None

        task_id = analysis_result.get('task_id')
        logger.info(f"    ✓ Analysis complete (Task ID: {task_id})")

        # Extract IOCs
        logger.info("\n[4/5] Extracting Indicators of Compromise (IOCs)...")
        iocs = analysis_result.get('iocs', {})

        logger.info(f"    - Domains contacted: {len(iocs.get('domains', []))}")
        logger.info(f"    - IP addresses: {len(iocs.get('ips', []))}")
        logger.info(f"    - Files created: {len(iocs.get('files', []))}")
        logger.info(f"    - Registry keys: {len(iocs.get('registry', []))}")
        logger.info(f"    - Processes spawned: {len(iocs.get('processes', []))}")

        # Generate YARA signatures
        logger.info("\n[5/5] Generating YARA detection signatures...")
        yara_gen = YARASignatureGenerator()

        yara_rules = yara_gen.generate_comprehensive_ruleset(
            sample_path=str(sample_path),
            iocs=iocs,
            task_id=task_id
        )

        yara_file = output_dir / f"{sample_path.stem}_signatures.yar"
        with open(yara_file, 'w') as f:
            f.write(yara_rules)

        logger.info(f"    ✓ YARA rules saved: {yara_file}")

        # Generate report
        logger.info("\n[6/6] Generating comprehensive report...")
        report_gen = ReportGenerator()

        report_path = report_gen.generate_html_report(
            task_id=task_id,
            output_dir=str(output_dir)
        )

        logger.info(f"    ✓ HTML report: {report_path}")

        # Print summary
        logger.info("\n" + "="*70)
        logger.info("ANALYSIS SUMMARY")
        logger.info("="*70)
        logger.info(f"Sample: {sample_path.name}")
        logger.info(f"Task ID: {task_id}")
        logger.info(f"Status: {analysis_result.get('status', 'unknown').upper()}")

        if iocs.get('domains'):
            logger.info(f"\nNetwork Activity:")
            for domain in iocs['domains'][:5]:  # Show first 5
                logger.info(f"  - {domain}")
            if len(iocs['domains']) > 5:
                logger.info(f"  ... and {len(iocs['domains']) - 5} more")

        if args.verbose and iocs.get('processes'):
            logger.info(f"\nProcess Activity:")
            for proc in iocs['processes'][:5]:
                logger.info(f"  - {proc}")

        logger.info(f"\nReports:")
        logger.info(f"  - HTML: {report_path}")
        logger.info(f"  - YARA: {yara_file}")
        logger.info("="*70)

        return analysis_result

    except ImportError as e:
        logger.error(f"Failed to import MASARE modules: {e}")
        logger.error("Ensure you're running from the MASARE root directory")
        logger.error("and have installed all dependencies: pip install -r requirements.txt")
        return None

    except Exception as e:
        logger.error(f"Analysis failed with error: {e}", exc_info=args.verbose)
        return None


def main():
    """Main entry point."""
    parser = setup_argument_parser()
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    # Run analysis
    result = analyze_sample(args)

    # Exit with appropriate code
    if result and result.get('status') == 'success':
        logger.info("\n✓ Analysis completed successfully!")
        sys.exit(0)
    else:
        logger.error("\n✗ Analysis failed!")
        sys.exit(1)


if __name__ == '__main__':
    main()
