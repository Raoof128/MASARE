#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MASARE Batch Processing Example

This script demonstrates how to analyze multiple malware samples in parallel
using MASARE's batch processing capabilities.

Copyright (c) 2025 MASARE Project
Licensed under the MIT License - see LICENSE file for details

Usage:
    python3 batch_processing.py /path/to/samples/directory/
    python3 batch_processing.py /path/to/samples/ --parallel 4 --timeout 180
    python3 batch_processing.py /path/to/samples/ --filter "*.exe" --output ./batch_reports/
"""

import sys
import argparse
import logging
from pathlib import Path
from datetime import datetime
import json

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def setup_argument_parser():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description='Batch analyze multiple malware samples with MASARE',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Analyze all files in directory
  python3 batch_processing.py /samples/malware/

  # Parallel processing with 4 workers
  python3 batch_processing.py /samples/ --parallel 4

  # Only analyze .exe files
  python3 batch_processing.py /samples/ --filter "*.exe"

  # Custom timeout and output
  python3 batch_processing.py /samples/ --timeout 300 --output /reports/batch1/
        """
    )

    parser.add_argument(
        'directory',
        type=str,
        help='Directory containing malware samples'
    )

    parser.add_argument(
        '--parallel',
        type=int,
        default=2,
        help='Number of parallel analysis workers (default: 2)'
    )

    parser.add_argument(
        '--timeout',
        type=int,
        default=120,
        help='Analysis timeout per sample in seconds (default: 120)'
    )

    parser.add_argument(
        '--filter',
        type=str,
        default='*',
        help='File pattern filter (e.g., "*.exe", "*.dll") (default: *)'
    )

    parser.add_argument(
        '--output',
        type=str,
        default='./batch_reports',
        help='Output directory for reports (default: ./batch_reports)'
    )

    parser.add_argument(
        '--skip-duplicates',
        action='store_true',
        help='Skip samples with duplicate hashes'
    )

    parser.add_argument(
        '--verbose',
        action='store_true',
        help='Enable verbose output'
    )

    return parser


def find_samples(directory: Path, pattern: str = '*') -> list:
    """
    Find all malware samples in directory matching pattern.

    Args:
        directory: Directory to search
        pattern: File pattern (e.g., "*.exe")

    Returns:
        List of Path objects for found samples
    """
    samples = []

    if not directory.exists():
        logger.error(f"Directory not found: {directory}")
        return samples

    logger.info(f"Scanning directory: {directory}")
    logger.info(f"Pattern: {pattern}")

    for sample in directory.rglob(pattern):
        if sample.is_file() and sample.stat().st_size > 0:
            samples.append(sample)

    logger.info(f"Found {len(samples)} sample(s)")
    return samples


def deduplicate_samples(samples: list) -> list:
    """
    Remove duplicate samples based on file hash.

    Args:
        samples: List of sample paths

    Returns:
        Deduplicated list of samples
    """
    import hashlib

    unique_samples = {}
    duplicates = []

    logger.info("Checking for duplicate samples...")

    for sample in samples:
        # Calculate SHA256
        sha256 = hashlib.sha256()
        with open(sample, 'rb') as f:
            sha256.update(f.read())
        file_hash = sha256.hexdigest()

        if file_hash in unique_samples:
            duplicates.append(sample.name)
            logger.debug(f"Duplicate: {sample.name} (same as {unique_samples[file_hash].name})")
        else:
            unique_samples[file_hash] = sample

    if duplicates:
        logger.info(f"Removed {len(duplicates)} duplicate(s)")

    return list(unique_samples.values())


def batch_analyze(args):
    """
    Main batch analysis function.

    Args:
        args: Parsed command line arguments

    Returns:
        Dictionary containing batch analysis results
    """
    directory = Path(args.directory).resolve()
    output_dir = Path(args.output).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    logger.info("="*70)
    logger.info(f"MASARE Batch Analysis - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    logger.info("="*70)
    logger.info(f"Input Directory: {directory}")
    logger.info(f"Output Directory: {output_dir}")
    logger.info(f"Parallel Workers: {args.parallel}")
    logger.info(f"Timeout per Sample: {args.timeout}s")
    logger.info("="*70)

    # Find samples
    samples = find_samples(directory, args.filter)

    if not samples:
        logger.error("No samples found!")
        return None

    # Deduplicate if requested
    if args.skip_duplicates:
        samples = deduplicate_samples(samples)

    try:
        # Import batch analyzer
        logger.info("\nImporting MASARE batch analyzer...")
        from automation.batch_analyzer import BatchMalwareAnalyzer

        # Initialize analyzer
        analyzer = BatchMalwareAnalyzer(
            max_workers=args.parallel,
            output_dir=str(output_dir)
        )

        # Run batch analysis
        logger.info(f"\nAnalyzing {len(samples)} sample(s)...")
        logger.info("This may take a while...\n")

        results = analyzer.process_directory(
            directory=str(directory),
            file_pattern=args.filter,
            timeout=args.timeout
        )

        # Generate summary
        logger.info("\n" + "="*70)
        logger.info("BATCH ANALYSIS SUMMARY")
        logger.info("="*70)

        total = len(results)
        successful = sum(1 for r in results if r.get('status') == 'success')
        failed = total - successful

        logger.info(f"Total Samples: {total}")
        logger.info(f"Successful: {successful} ({100*successful/total:.1f}%)")
        logger.info(f"Failed: {failed} ({100*failed/total:.1f}%)")

        # Statistics
        if successful > 0:
            total_iocs = sum(len(r.get('iocs', {}).get('domains', [])) for r in results)
            avg_iocs = total_iocs / successful if successful > 0 else 0

            logger.info(f"\nNetwork IOCs:")
            logger.info(f"  - Total domains contacted: {total_iocs}")
            logger.info(f"  - Average per sample: {avg_iocs:.1f}")

            # Top malicious domains
            all_domains = []
            for r in results:
                all_domains.extend(r.get('iocs', {}).get('domains', []))

            from collections import Counter
            if all_domains:
                logger.info(f"\nTop 5 Contacted Domains:")
                for domain, count in Counter(all_domains).most_common(5):
                    logger.info(f"  - {domain} ({count} sample{'s' if count > 1 else ''})")

        # Save consolidated report
        summary_file = output_dir / 'batch_summary.json'
        with open(summary_file, 'w') as f:
            json.dump({
                'timestamp': datetime.now().isoformat(),
                'total_samples': total,
                'successful': successful,
                'failed': failed,
                'results': results
            }, f, indent=2)

        logger.info(f"\nConsolidated Report: {summary_file}")
        logger.info("="*70)

        return results

    except ImportError as e:
        logger.error(f"Failed to import MASARE modules: {e}")
        logger.error("Ensure you're in the MASARE root directory")
        return None

    except Exception as e:
        logger.error(f"Batch analysis failed: {e}", exc_info=args.verbose)
        return None


def main():
    """Main entry point."""
    parser = setup_argument_parser()
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    # Run batch analysis
    results = batch_analyze(args)

    # Exit with appropriate code
    if results:
        logger.info("\n✓ Batch analysis completed!")
        sys.exit(0)
    else:
        logger.error("\n✗ Batch analysis failed!")
        sys.exit(1)


if __name__ == '__main__':
    main()
