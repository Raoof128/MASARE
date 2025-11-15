#!/usr/bin/env python3
"""
Batch Malware Analysis Automation for MASARE
Purpose: Process multiple malware samples through complete analysis pipeline
Author: Security Research Team
Last Updated: 2025-11-15

Usage:
    python3 batch_analyzer.py --samples-dir /path/to/samples --output-dir /path/to/results
    python3 batch_analyzer.py --samples-dir /path/to/samples --parallel 3
"""

import argparse
import json
import logging
import os
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from typing import List, Dict

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

# Try to import modules, fall back to running as standalone scripts if import fails
try:
    from analysis.cuckoo.orchestrator import MalwareAnalysisOrchestrator
    from detection.yara.signature_generator import YARASignatureGenerator
    from automation.report_generator import MalwareAnalysisReportGenerator
    from automation.mitre_attack_mapper import MITREATTACKMapper
    IMPORTS_AVAILABLE = True
except ImportError as e:
    logging.warning(f"Could not import modules directly: {e}")
    logging.info("Will run analysis scripts as subprocesses instead")
    IMPORTS_AVAILABLE = False

# Create logs directory if it doesn't exist
log_dir = Path('/shared/logs')
if not log_dir.exists():
    log_dir = Path.home() / 'masare_logs'
    log_dir.mkdir(parents=True, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(log_dir / 'batch_analyzer.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger('MASARE.BatchAnalyzer')


class BatchMalwareAnalyzer:
    """Complete automated malware analysis pipeline for batch processing"""

    def __init__(self, output_dir: str = '/shared/analysis/results'):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

        # Initialize components (only if imports available)
        if IMPORTS_AVAILABLE:
            self.cuckoo_orchestrator = MalwareAnalysisOrchestrator(output_dir=str(self.output_dir))
            self.yara_generator = YARASignatureGenerator()
            self.report_generator = MalwareAnalysisReportGenerator()
            self.mitre_mapper = MITREATTACKMapper()
        else:
            self.cuckoo_orchestrator = None
            self.yara_generator = None
            self.report_generator = None
            self.mitre_mapper = None

        self.results = []

    def analyze_sample_complete(self, sample_path: str) -> Dict:
        """Run complete analysis pipeline on a single sample"""
        sample_name = Path(sample_path).name
        logger.info(f"[*] Starting complete analysis pipeline for: {sample_name}")

        try:
            # Step 1: Dynamic analysis (Cuckoo)
            logger.info(f"[1/5] Running dynamic analysis...")
            cuckoo_results = self.cuckoo_orchestrator.analyze_sample(sample_path)

            # Step 2: Static analysis (Ghidra) - if binary is PE/ELF
            logger.info(f"[2/5] Running static analysis...")
            ghidra_results = self._run_ghidra_analysis(sample_path)

            # Merge static analysis into results
            if ghidra_results:
                cuckoo_results['ghidra_analysis'] = ghidra_results

            # Step 3: MITRE ATT&CK mapping
            logger.info(f"[3/5] Mapping to MITRE ATT&CK...")
            mitre_mappings = self.mitre_mapper.map_from_analysis_report(cuckoo_results)
            cuckoo_results['mitre_mapping'] = mitre_mappings

            # Step 4: YARA rule generation
            logger.info(f"[4/5] Generating YARA detection rules...")
            yara_rules = self.yara_generator.generate_from_sample(
                sample_path,
                analysis_data=cuckoo_results
            )
            cuckoo_results['yara_rule'] = yara_rules

            # Step 5: Report generation
            logger.info(f"[5/5] Generating reports...")
            task_id = cuckoo_results['task_id']
            report_dir = self.output_dir / f"task_{task_id}_{sample_name}"

            # HTML report
            html_report_path = report_dir / 'report.html'
            self.report_generator.generate_html_report(
                cuckoo_results,
                output_path=str(html_report_path)
            )

            # Save YARA rules
            yara_rules_path = report_dir / 'detection_rules.yar'
            with open(yara_rules_path, 'w') as f:
                f.write(yara_rules)

            # Save MITRE Navigator layer
            navigator_path = report_dir / 'mitre_navigator.json'
            self.mitre_mapper.generate_navigator_layer(
                mitre_mappings,
                output_path=str(navigator_path)
            )

            logger.info(f"[✓] Complete analysis finished for {sample_name}")
            logger.info(f"[+] Results saved to: {report_dir}")

            return {
                'sample': sample_name,
                'status': 'success',
                'task_id': task_id,
                'report_dir': str(report_dir),
                'threat_level': cuckoo_results['summary']['threat_level'],
                'iocs_extracted': {
                    'domains': len(cuckoo_results['iocs']['domains']),
                    'ips': len(cuckoo_results['iocs']['ips']),
                    'file_hashes': len(cuckoo_results['iocs']['file_hashes']),
                },
            }

        except Exception as e:
            logger.error(f"[✗] Analysis failed for {sample_name}: {e}", exc_info=True)
            return {
                'sample': sample_name,
                'status': 'failed',
                'error': str(e),
            }

    def _run_ghidra_analysis(self, sample_path: str) -> Dict:
        """Run Ghidra headless analysis"""
        try:
            ghidra_script = Path(__file__).parent.parent / 'analysis' / 'ghidra' / 'analyze_binary.py'
            output_file = f'/tmp/ghidra_analysis_{Path(sample_path).stem}.json'

            # Run Ghidra headless analysis
            cmd = [
                '/opt/ghidra/support/analyzeHeadless',
                '/tmp/ghidra_projects',
                'MalwareProject',
                '-import', sample_path,
                '-scriptPath', str(ghidra_script.parent),
                '-postScript', 'analyze_binary.py', output_file,
                '-deleteProject'  # Clean up after analysis
            ]

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=600  # 10-minute timeout
            )

            if result.returncode == 0 and Path(output_file).exists():
                with open(output_file, 'r') as f:
                    ghidra_data = json.load(f)
                os.remove(output_file)  # Clean up
                return ghidra_data
            else:
                logger.warning(f"[!] Ghidra analysis failed: {result.stderr}")
                return {}

        except Exception as e:
            logger.warning(f"[!] Could not run Ghidra analysis: {e}")
            return {}

    def analyze_batch(self, samples_dir: str, parallel: int = 1) -> List[Dict]:
        """Analyze multiple samples in batch mode"""
        samples_path = Path(samples_dir)

        if not samples_path.is_dir():
            raise ValueError(f"Directory not found: {samples_dir}")

        # Find all malware samples
        patterns = ['*.exe', '*.dll', '*.bin', '*.scr', '*.com', '*.bat', '*.ps1', '*.vbs']
        samples = []
        for pattern in patterns:
            samples.extend(samples_path.glob(pattern))

        logger.info(f"[*] Found {len(samples)} samples for batch analysis")
        logger.info(f"[*] Parallel workers: {parallel}")

        # Process samples (parallel or sequential)
        if parallel > 1:
            with ThreadPoolExecutor(max_workers=parallel) as executor:
                futures = {
                    executor.submit(self.analyze_sample_complete, str(sample)): sample
                    for sample in samples
                }

                for future in as_completed(futures):
                    sample = futures[future]
                    try:
                        result = future.result()
                        self.results.append(result)
                    except Exception as e:
                        logger.error(f"[✗] Error processing {sample}: {e}")
                        self.results.append({
                            'sample': sample.name,
                            'status': 'failed',
                            'error': str(e)
                        })
        else:
            # Sequential processing
            for sample in samples:
                result = self.analyze_sample_complete(str(sample))
                self.results.append(result)

        # Generate summary report
        self._generate_summary_report()

        return self.results

    def _generate_summary_report(self):
        """Generate batch analysis summary report"""
        summary_path = self.output_dir / 'batch_summary.json'

        summary = {
            'analysis_date': datetime.now().isoformat(),
            'total_samples': len(self.results),
            'successful': sum(1 for r in self.results if r['status'] == 'success'),
            'failed': sum(1 for r in self.results if r['status'] == 'failed'),
            'threat_levels': {
                'CRITICAL': sum(1 for r in self.results if r.get('threat_level') == 'CRITICAL'),
                'HIGH': sum(1 for r in self.results if r.get('threat_level') == 'HIGH'),
                'MEDIUM': sum(1 for r in self.results if r.get('threat_level') == 'MEDIUM'),
                'LOW': sum(1 for r in self.results if r.get('threat_level') == 'LOW'),
            },
            'total_iocs': {
                'domains': sum(r.get('iocs_extracted', {}).get('domains', 0) for r in self.results),
                'ips': sum(r.get('iocs_extracted', {}).get('ips', 0) for r in self.results),
                'file_hashes': sum(r.get('iocs_extracted', {}).get('file_hashes', 0) for r in self.results),
            },
            'results': self.results,
        }

        with open(summary_path, 'w') as f:
            json.dump(summary, f, indent=2)

        logger.info(f"[✓] Batch summary saved to: {summary_path}")

        # Generate consolidated IOC feed
        ioc_feed_path = self.output_dir / 'consolidated_iocs.json'
        all_reports = []
        for result in self.results:
            if result['status'] == 'success':
                report_file = Path(result['report_dir']) / 'report.json'
                if report_file.exists():
                    with open(report_file, 'r') as f:
                        all_reports.append(json.load(f))

        if all_reports:
            self.report_generator.generate_json_ioc_feed(
                all_reports,
                output_path=str(ioc_feed_path)
            )
            logger.info(f"[✓] Consolidated IOC feed saved to: {ioc_feed_path}")


def main():
    parser = argparse.ArgumentParser(
        description='MASARE Batch Malware Analyzer',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Analyze all samples in directory (sequential)
  python3 batch_analyzer.py --samples-dir /path/to/samples

  # Analyze with 3 parallel workers
  python3 batch_analyzer.py --samples-dir /path/to/samples --parallel 3

  # Specify custom output directory
  python3 batch_analyzer.py --samples-dir /path/to/samples --output-dir /custom/output
        """
    )

    parser.add_argument('--samples-dir', type=str, required=True,
                       help='Directory containing malware samples')
    parser.add_argument('--output-dir', type=str, default='/shared/analysis/results',
                       help='Output directory for results')
    parser.add_argument('--parallel', type=int, default=1,
                       help='Number of parallel analysis workers (default: 1)')

    args = parser.parse_args()

    # Initialize batch analyzer
    analyzer = BatchMalwareAnalyzer(output_dir=args.output_dir)

    try:
        logger.info("="*60)
        logger.info("MASARE Batch Malware Analyzer")
        logger.info("="*60)

        # Run batch analysis
        results = analyzer.analyze_batch(
            samples_dir=args.samples_dir,
            parallel=args.parallel
        )

        # Print summary
        successful = sum(1 for r in results if r['status'] == 'success')
        failed = sum(1 for r in results if r['status'] == 'failed')

        print("\n" + "="*60)
        print("BATCH ANALYSIS COMPLETE")
        print("="*60)
        print(f"Total Samples:  {len(results)}")
        print(f"Successful:     {successful}")
        print(f"Failed:         {failed}")
        print(f"Output Directory: {args.output_dir}")
        print("="*60)

    except KeyboardInterrupt:
        logger.warning("\n[!] Batch analysis interrupted by user")
        sys.exit(130)
    except Exception as e:
        logger.error(f"[✗] Fatal error: {e}", exc_info=True)
        sys.exit(1)


if __name__ == '__main__':
    main()
