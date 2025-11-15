#!/usr/bin/env python3
"""
Cuckoo Sandbox Orchestrator for MASARE
Purpose: Automated malware analysis workflow with IOC extraction
Author: Security Research Team
Last Updated: 2025-11-15

Usage:
    python3 orchestrator.py --sample /path/to/malware.exe
    python3 orchestrator.py --batch /path/to/samples/
    python3 orchestrator.py --task-id 12345
"""

import argparse
import json
import logging
import os
import requests
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional, Set
from datetime import datetime

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('/shared/logs/orchestrator.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger('MASARE.Orchestrator')


class CuckooClient:
    """Interface to Cuckoo Sandbox REST API"""

    def __init__(self, cuckoo_url: str = "http://192.168.1.10:8090", api_token: str = None):
        self.cuckoo_url = cuckoo_url.rstrip('/')
        self.api_token = api_token or os.environ.get('CUCKOO_API_TOKEN', '')
        self.session = requests.Session()
        self.session.headers.update({
            'Authorization': f'Bearer {self.api_token}' if self.api_token else ''
        })
        self.timeout = 300  # 5-minute timeout per sample

    def submit_sample(self, malware_path: str, **options) -> int:
        """Submit malware sample for analysis"""
        try:
            with open(malware_path, 'rb') as f:
                files = {'file': (os.path.basename(malware_path), f)}
                data = {
                    'timeout': options.get('timeout', 120),
                    'priority': options.get('priority', 1),
                    'enforce_timeout': options.get('enforce_timeout', True),
                    'memory': options.get('memory', False),
                    'options': options.get('options', ''),
                }

                response = self.session.post(
                    f"{self.cuckoo_url}/tasks/create/file",
                    files=files,
                    data=data,
                    timeout=30
                )
                response.raise_for_status()

                task_id = response.json()['task_id']
                logger.info(f"[+] Submitted: {Path(malware_path).name} → Task {task_id}")
                return task_id

        except Exception as e:
            logger.error(f"[-] Failed to submit {malware_path}: {e}")
            raise

    def get_task_status(self, task_id: int) -> Dict:
        """Get task status and details"""
        try:
            response = self.session.get(
                f"{self.cuckoo_url}/tasks/view/{task_id}",
                timeout=10
            )
            response.raise_for_status()
            return response.json()
        except Exception as e:
            logger.error(f"[-] Failed to get task {task_id} status: {e}")
            raise

    def wait_for_completion(self, task_id: int, timeout: int = None) -> Dict:
        """Poll Cuckoo until analysis completes"""
        timeout = timeout or self.timeout
        start_time = time.time()

        logger.info(f"[*] Waiting for task {task_id} to complete (timeout: {timeout}s)...")

        while time.time() - start_time < timeout:
            try:
                task_info = self.get_task_status(task_id)
                status = task_info['task']['status']

                if status == 'reported':
                    logger.info(f"[✓] Task {task_id} completed successfully")
                    return self.get_report(task_id)
                elif status == 'failed':
                    logger.error(f"[✗] Task {task_id} failed")
                    raise RuntimeError(f"Task {task_id} failed")

                # Log progress
                logger.debug(f"[*] Task {task_id} status: {status}")
                time.sleep(5)

            except Exception as e:
                logger.warning(f"[!] Error polling task {task_id}: {e}")
                time.sleep(5)

        raise TimeoutError(f"Task {task_id} exceeded {timeout}s timeout")

    def get_report(self, task_id: int, report_format: str = 'json') -> Dict:
        """Retrieve analysis report"""
        try:
            response = self.session.get(
                f"{self.cuckoo_url}/tasks/report/{task_id}/{report_format}",
                timeout=30
            )
            response.raise_for_status()
            return response.json()
        except Exception as e:
            logger.error(f"[-] Failed to retrieve report for task {task_id}: {e}")
            raise

    def list_tasks(self, limit: int = 100, offset: int = 0) -> List[Dict]:
        """List recent analysis tasks"""
        try:
            response = self.session.get(
                f"{self.cuckoo_url}/tasks/list/{limit}/{offset}",
                timeout=10
            )
            response.raise_for_status()
            return response.json()['tasks']
        except Exception as e:
            logger.error(f"[-] Failed to list tasks: {e}")
            raise


class IOCExtractor:
    """Extract Indicators of Compromise from Cuckoo reports"""

    @staticmethod
    def extract_iocs(cuckoo_report: Dict) -> Dict[str, Set]:
        """Extract all IOCs from Cuckoo analysis report"""
        iocs = {
            'file_hashes': set(),
            'domains': set(),
            'ips': set(),
            'urls': set(),
            'registry_keys': set(),
            'file_paths': set(),
            'mutexes': set(),
            'processes': [],
            'api_calls': set(),
        }

        # Extract file hashes
        target = cuckoo_report.get('target', {}).get('file', {})
        if target:
            iocs['file_hashes'].add(target.get('md5'))
            iocs['file_hashes'].add(target.get('sha1'))
            iocs['file_hashes'].add(target.get('sha256'))

        # Extract dropped files
        for dropped in cuckoo_report.get('dropped', []):
            iocs['file_hashes'].add(dropped.get('md5'))
            iocs['file_hashes'].add(dropped.get('sha256'))
            if 'path' in dropped:
                iocs['file_paths'].add(dropped['path'])

        # Extract network IOCs
        network = cuckoo_report.get('network', {})

        # DNS requests
        for dns in network.get('dns', []):
            domain = dns.get('request')
            if domain and domain not in ['localhost', '127.0.0.1']:
                iocs['domains'].add(domain)

        # HTTP requests
        for http in network.get('http', []):
            if 'uri' in http:
                iocs['urls'].add(http['uri'])
            if 'host' in http:
                host = http['host']
                # Check if IP or domain
                if IOCExtractor._is_ip(host):
                    iocs['ips'].add(host)
                else:
                    iocs['domains'].add(host)

        # TCP/UDP connections
        for protocol in ['tcp', 'udp']:
            for conn in network.get(protocol, []):
                dst = conn.get('dst')
                if dst and not IOCExtractor._is_private_ip(dst):
                    iocs['ips'].add(dst)

        # Extract behavioral IOCs
        behavior = cuckoo_report.get('behavior', {})

        # Process tree
        for process in behavior.get('processes', []):
            iocs['processes'].append({
                'pid': process.get('process_id'),
                'name': process.get('process_name'),
                'command_line': process.get('command_line'),
                'first_seen': process.get('first_seen'),
            })

            # Extract API calls
            for call in process.get('calls', []):
                api_name = call.get('api')
                if api_name:
                    iocs['api_calls'].add(api_name)

        # Registry keys
        for summary in behavior.get('summary', {}).get('keys', []):
            iocs['registry_keys'].add(summary)

        # Mutexes
        for mutex in behavior.get('summary', {}).get('mutexes', []):
            iocs['mutexes'].add(mutex)

        # Remove None values
        for key in iocs:
            if isinstance(iocs[key], set):
                iocs[key].discard(None)
                iocs[key] = list(iocs[key])

        return iocs

    @staticmethod
    def _is_ip(value: str) -> bool:
        """Check if string is an IP address"""
        parts = value.split('.')
        if len(parts) != 4:
            return False
        try:
            return all(0 <= int(part) <= 255 for part in parts)
        except ValueError:
            return False

    @staticmethod
    def _is_private_ip(ip: str) -> bool:
        """Check if IP is in private range"""
        if not IOCExtractor._is_ip(ip):
            return False
        parts = [int(p) for p in ip.split('.')]
        return (
            parts[0] == 10 or
            (parts[0] == 172 and 16 <= parts[1] <= 31) or
            (parts[0] == 192 and parts[1] == 168) or
            ip.startswith('127.') or
            ip == '0.0.0.0'
        )


class MalwareAnalysisOrchestrator:
    """Main orchestrator for MASARE malware analysis pipeline"""

    def __init__(self, output_dir: str = '/shared/analysis/results'):
        self.cuckoo = CuckooClient()
        self.ioc_extractor = IOCExtractor()
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def analyze_sample(self, sample_path: str, **options) -> Dict:
        """Analyze a single malware sample"""
        sample_path = Path(sample_path)

        logger.info(f"[*] Starting analysis of: {sample_path.name}")

        try:
            # Submit to Cuckoo
            task_id = self.cuckoo.submit_sample(str(sample_path), **options)

            # Wait for completion
            report = self.cuckoo.wait_for_completion(task_id)

            # Extract IOCs
            iocs = self.ioc_extractor.extract_iocs(report)

            # Compile results
            results = {
                'sample': {
                    'name': sample_path.name,
                    'path': str(sample_path),
                    'size': sample_path.stat().st_size if sample_path.exists() else 0,
                },
                'task_id': task_id,
                'analysis_date': datetime.now().isoformat(),
                'cuckoo_report': report,
                'iocs': iocs,
                'summary': self._generate_summary(report, iocs),
            }

            # Save results
            self._save_results(results)

            logger.info(f"[✓] Analysis complete for {sample_path.name}")
            logger.info(f"[+] Extracted {len(iocs['domains'])} domains, "
                       f"{len(iocs['ips'])} IPs, "
                       f"{len(iocs['file_hashes'])} file hashes")

            return results

        except Exception as e:
            logger.error(f"[-] Analysis failed for {sample_path.name}: {e}")
            raise

    def analyze_batch(self, sample_directory: str, **options) -> List[Dict]:
        """Analyze all samples in a directory"""
        sample_dir = Path(sample_directory)

        if not sample_dir.is_dir():
            raise ValueError(f"Directory not found: {sample_directory}")

        # Find all binary files (common malware extensions)
        patterns = ['*.exe', '*.dll', '*.bin', '*.scr', '*.com', '*.bat', '*.ps1', '*.vbs']
        samples = []
        for pattern in patterns:
            samples.extend(sample_dir.glob(pattern))

        logger.info(f"[*] Found {len(samples)} samples in {sample_directory}")

        results = []
        for i, sample_path in enumerate(samples, 1):
            logger.info(f"[*] Processing sample {i}/{len(samples)}: {sample_path.name}")
            try:
                result = self.analyze_sample(str(sample_path), **options)
                results.append(result)
            except Exception as e:
                logger.error(f"[-] Skipping {sample_path.name}: {e}")
                continue

        logger.info(f"[✓] Batch analysis complete: {len(results)}/{len(samples)} successful")
        return results

    def _generate_summary(self, report: Dict, iocs: Dict) -> Dict:
        """Generate executive summary from analysis"""
        target = report.get('target', {}).get('file', {})
        info = report.get('info', {})

        # Determine threat level based on behaviors
        signatures = report.get('signatures', [])
        threat_level = 'LOW'
        if len(signatures) > 10:
            threat_level = 'CRITICAL'
        elif len(signatures) > 5:
            threat_level = 'HIGH'
        elif len(signatures) > 2:
            threat_level = 'MEDIUM'

        return {
            'threat_level': threat_level,
            'file_type': target.get('type', 'Unknown'),
            'md5': target.get('md5'),
            'sha256': target.get('sha256'),
            'analysis_duration': info.get('duration', 0),
            'signatures_triggered': len(signatures),
            'network_activity': {
                'domains_contacted': len(iocs['domains']),
                'ips_contacted': len(iocs['ips']),
                'http_requests': len(iocs['urls']),
            },
            'behavior': {
                'processes_created': len(iocs['processes']),
                'files_dropped': len([h for h in iocs['file_hashes'] if h != target.get('md5')]),
                'registry_modified': len(iocs['registry_keys']),
                'mutexes_created': len(iocs['mutexes']),
            },
        }

    def _save_results(self, results: Dict):
        """Save analysis results to disk"""
        sample_name = results['sample']['name']
        task_id = results['task_id']

        # Create output directory for this sample
        output_dir = self.output_dir / f"task_{task_id}_{sample_name}"
        output_dir.mkdir(parents=True, exist_ok=True)

        # Save full report
        report_path = output_dir / 'report.json'
        with open(report_path, 'w') as f:
            json.dump(results, f, indent=2, default=str)

        # Save IOCs separately (for SIEM ingestion)
        ioc_path = output_dir / 'iocs.json'
        with open(ioc_path, 'w') as f:
            json.dump(results['iocs'], f, indent=2)

        # Save summary
        summary_path = output_dir / 'summary.json'
        with open(summary_path, 'w') as f:
            json.dump(results['summary'], f, indent=2)

        logger.info(f"[+] Results saved to: {output_dir}")


def main():
    parser = argparse.ArgumentParser(
        description='MASARE Malware Analysis Orchestrator',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Analyze single sample
  python3 orchestrator.py --sample /path/to/malware.exe

  # Analyze batch of samples
  python3 orchestrator.py --batch /path/to/samples/

  # Retrieve existing task report
  python3 orchestrator.py --task-id 12345
        """
    )

    parser.add_argument('--sample', type=str, help='Path to malware sample')
    parser.add_argument('--batch', type=str, help='Directory containing samples')
    parser.add_argument('--task-id', type=int, help='Retrieve report for existing task')
    parser.add_argument('--timeout', type=int, default=120, help='Analysis timeout (seconds)')
    parser.add_argument('--output-dir', type=str, default='/shared/analysis/results',
                       help='Output directory for results')
    parser.add_argument('--cuckoo-url', type=str, default='http://192.168.1.10:8090',
                       help='Cuckoo API URL')

    args = parser.parse_args()

    # Initialize orchestrator
    orchestrator = MalwareAnalysisOrchestrator(output_dir=args.output_dir)
    orchestrator.cuckoo.cuckoo_url = args.cuckoo_url

    try:
        if args.task_id:
            # Retrieve existing report
            logger.info(f"[*] Retrieving report for task {args.task_id}")
            report = orchestrator.cuckoo.get_report(args.task_id)
            print(json.dumps(report, indent=2, default=str))

        elif args.sample:
            # Analyze single sample
            results = orchestrator.analyze_sample(
                args.sample,
                timeout=args.timeout
            )
            print(f"\n[✓] Analysis complete: {results['summary']['threat_level']} threat level")

        elif args.batch:
            # Analyze batch
            results = orchestrator.analyze_batch(
                args.batch,
                timeout=args.timeout
            )
            print(f"\n[✓] Batch analysis complete: {len(results)} samples analyzed")

        else:
            parser.print_help()
            sys.exit(1)

    except KeyboardInterrupt:
        logger.warning("\n[!] Analysis interrupted by user")
        sys.exit(130)
    except Exception as e:
        logger.error(f"[✗] Fatal error: {e}", exc_info=True)
        sys.exit(1)


if __name__ == '__main__':
    main()
