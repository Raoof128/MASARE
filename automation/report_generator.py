#!/usr/bin/env python3
"""
Multi-Format Report Generator for MASARE
Purpose: Generate professional malware analysis reports (HTML, PDF, JSON)
Author: Security Research Team
Last Updated: 2025-11-15

Usage:
    python3 report_generator.py --analysis-dir /path/to/analysis/results/task_123
    python3 report_generator.py --json /path/to/report.json --output report.html
"""

import argparse
import json
import logging
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, List

try:
    from jinja2 import Template
except ImportError:
    print("[!] Jinja2 not installed")
    print("[i] Install: pip install jinja2")
    sys.exit(1)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('MASARE.ReportGenerator')


class MalwareAnalysisReportGenerator:
    """Generate professional malware analysis reports"""

    def __init__(self):
        self.html_template = self._load_html_template()

    def _load_html_template(self) -> Template:
        """Load HTML report template"""
        template_str = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Malware Analysis Report - {{ sample_name }}</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: 'Courier New', monospace;
            background-color: #0a0a0a;
            color: #00ff00;
            padding: 20px;
            line-height: 1.6;
        }

        .container {
            max-width: 1200px;
            margin: 0 auto;
            background-color: #111;
            border: 2px solid #00ff00;
            padding: 30px;
        }

        h1 {
            color: #00ff00;
            border-bottom: 3px solid #00ff00;
            padding-bottom: 10px;
            margin-bottom: 20px;
            text-align: center;
        }

        h2 {
            color: #00ff00;
            margin-top: 30px;
            margin-bottom: 15px;
            border-left: 5px solid #00ff00;
            padding-left: 15px;
        }

        h3 {
            color: #00cc00;
            margin-top: 20px;
            margin-bottom: 10px;
        }

        .metadata {
            background-color: #1a1a1a;
            border: 1px solid #00ff00;
            padding: 15px;
            margin-bottom: 20px;
        }

        .metadata p {
            margin: 5px 0;
        }

        .threat-level {
            display: inline-block;
            padding: 10px 20px;
            font-weight: bold;
            font-size: 1.2em;
            margin: 15px 0;
        }

        .critical {
            background-color: #ff0000;
            color: white;
            border: 2px solid #cc0000;
        }

        .high {
            background-color: #ff6600;
            color: white;
            border: 2px solid #cc5200;
        }

        .medium {
            background-color: #ffcc00;
            color: black;
            border: 2px solid #cca300;
        }

        .low {
            background-color: #00ff00;
            color: black;
            border: 2px solid #00cc00;
        }

        table {
            width: 100%;
            border-collapse: collapse;
            margin: 15px 0;
            background-color: #1a1a1a;
        }

        th, td {
            border: 1px solid #00ff00;
            padding: 10px;
            text-align: left;
        }

        th {
            background-color: #003300;
            font-weight: bold;
        }

        tr:nth-child(even) {
            background-color: #0d0d0d;
        }

        code {
            background-color: #1a1a1a;
            border: 1px solid #003300;
            padding: 2px 6px;
            font-family: 'Courier New', monospace;
            color: #00ff00;
        }

        pre {
            background-color: #1a1a1a;
            border: 1px solid #00ff00;
            padding: 15px;
            overflow-x: auto;
            margin: 10px 0;
        }

        .ioc-list {
            background-color: #1a1a1a;
            border: 1px solid #00ff00;
            padding: 15px;
            margin: 10px 0;
        }

        .ioc-item {
            padding: 5px 0;
            border-bottom: 1px dotted #003300;
        }

        .process-tree {
            font-family: 'Courier New', monospace;
            margin-left: 20px;
        }

        .warning {
            background-color: #331100;
            border: 2px solid #ff6600;
            padding: 15px;
            margin: 20px 0;
            color: #ffaa00;
        }

        .footer {
            margin-top: 40px;
            padding-top: 20px;
            border-top: 2px solid #00ff00;
            text-align: center;
            color: #008800;
        }

        ol, ul {
            margin-left: 30px;
            margin-top: 10px;
        }

        li {
            margin: 5px 0;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔍 MALWARE ANALYSIS REPORT</h1>

        <div class="metadata">
            <p><strong>Sample Name:</strong> {{ sample_name }}</p>
            <p><strong>MD5:</strong> <code>{{ md5 }}</code></p>
            <p><strong>SHA256:</strong> <code>{{ sha256 }}</code></p>
            <p><strong>File Size:</strong> {{ file_size }} bytes</p>
            <p><strong>Analysis Date:</strong> {{ analysis_date }}</p>
            <p><strong>Analysis System:</strong> MASARE v1.0</p>
        </div>

        <h2>Executive Summary</h2>
        <div class="threat-level {{ threat_level|lower }}">
            <strong>Threat Level:</strong> {{ threat_level }}
        </div>
        <p>{{ summary }}</p>

        <h2>File Information</h2>
        <table>
            <tr><th>Property</th><th>Value</th></tr>
            <tr><td>File Type</td><td>{{ file_type }}</td></tr>
            <tr><td>MD5</td><td><code>{{ md5 }}</code></td></tr>
            <tr><td>SHA1</td><td><code>{{ sha1 }}</code></td></tr>
            <tr><td>SHA256</td><td><code>{{ sha256 }}</code></td></tr>
            <tr><td>File Size</td><td>{{ file_size }} bytes</td></tr>
            <tr><td>Analysis Duration</td><td>{{ analysis_duration }} seconds</td></tr>
        </table>

        <h2>Indicators of Compromise (IOCs)</h2>

        {% if network_iocs %}
        <h3>Network Indicators</h3>
        <table>
            <tr><th>Type</th><th>Indicator</th><th>Context</th></tr>
            {% for ioc in network_iocs %}
            <tr>
                <td>{{ ioc.type }}</td>
                <td><code>{{ ioc.value }}</code></td>
                <td>{{ ioc.context }}</td>
            </tr>
            {% endfor %}
        </table>
        {% endif %}

        {% if file_iocs %}
        <h3>File Indicators</h3>
        <div class="ioc-list">
            {% for ioc in file_iocs %}
            <div class="ioc-item"><code>{{ ioc }}</code></div>
            {% endfor %}
        </div>
        {% endif %}

        {% if registry_iocs %}
        <h3>Registry Indicators</h3>
        <div class="ioc-list">
            {% for ioc in registry_iocs %}
            <div class="ioc-item"><code>{{ ioc }}</code></div>
            {% endfor %}
        </div>
        {% endif %}

        {% if mitre_mapping %}
        <h2>MITRE ATT&CK Mapping</h2>
        <table>
            <tr><th>Tactic</th><th>Technique ID</th><th>Technique Name</th><th>Description</th></tr>
            {% for mapping in mitre_mapping %}
            <tr>
                <td>{{ mapping.tactic }}</td>
                <td><code>{{ mapping.technique_id }}</code></td>
                <td>{{ mapping.technique_name }}</td>
                <td>{{ mapping.description }}</td>
            </tr>
            {% endfor %}
        </table>
        {% endif %}

        {% if processes %}
        <h2>Process Activity</h2>
        <div class="process-tree">
            {% for process in processes %}
            <p><strong>PID {{ process.pid }}:</strong> {{ process.name }}</p>
            <p style="margin-left: 20px;"><em>Command:</em> <code>{{ process.command_line }}</code></p>
            {% endfor %}
        </div>
        {% endif %}

        {% if yara_rule %}
        <h2>Detection Signatures</h2>
        <h3>YARA Rule</h3>
        <pre><code>{{ yara_rule }}</code></pre>
        {% endif %}

        <h2>Behavioral Analysis</h2>
        <table>
            <tr><th>Behavior</th><th>Count</th></tr>
            <tr><td>Processes Created</td><td>{{ behavior.processes_created }}</td></tr>
            <tr><td>Files Dropped</td><td>{{ behavior.files_dropped }}</td></tr>
            <tr><td>Registry Keys Modified</td><td>{{ behavior.registry_modified }}</td></tr>
            <tr><td>Network Connections</td><td>{{ behavior.network_connections }}</td></tr>
            <tr><td>Mutexes Created</td><td>{{ behavior.mutexes_created }}</td></tr>
        </table>

        {% if remediation %}
        <h2>Remediation Steps</h2>
        <div class="warning">
            <strong>⚠️ IMMEDIATE ACTIONS REQUIRED</strong>
        </div>
        <ol>
            {% for step in remediation %}
            <li>{{ step }}</li>
            {% endfor %}
        </ol>
        {% endif %}

        <div class="footer">
            <p>Generated by MASARE (Malware Analysis Sandbox with Automated Reverse Engineering)</p>
            <p>Report generated: {{ generation_time }}</p>
            <p>🔒 Confidential - For Authorized Personnel Only</p>
        </div>
    </div>
</body>
</html>
        """
        return Template(template_str)

    def generate_html_report(self, analysis_data: Dict, output_path: str = None) -> str:
        """Generate HTML report from analysis data"""

        # Extract data
        sample = analysis_data.get('sample', {})
        iocs = analysis_data.get('iocs', {})
        summary_data = analysis_data.get('summary', {})
        cuckoo_report = analysis_data.get('cuckoo_report', {})

        # Prepare network IOCs for table
        network_iocs = []
        for domain in iocs.get('domains', []):
            network_iocs.append({
                'type': 'Domain',
                'value': domain,
                'context': 'DNS query or HTTP connection'
            })
        for ip in iocs.get('ips', []):
            network_iocs.append({
                'type': 'IP Address',
                'value': ip,
                'context': 'Network connection'
            })
        for url in iocs.get('urls', []):
            network_iocs.append({
                'type': 'URL',
                'value': url,
                'context': 'HTTP request'
            })

        # Get target file info from Cuckoo report
        target = cuckoo_report.get('target', {}).get('file', {})

        # Render template
        html_content = self.html_template.render(
            sample_name=sample.get('name', 'Unknown'),
            md5=target.get('md5', 'N/A'),
            sha1=target.get('sha1', 'N/A'),
            sha256=target.get('sha256', 'N/A'),
            file_size=target.get('size', sample.get('size', 0)),
            file_type=target.get('type', 'Unknown'),
            analysis_date=analysis_data.get('analysis_date', datetime.now().isoformat()),
            analysis_duration=cuckoo_report.get('info', {}).get('duration', 0),
            threat_level=summary_data.get('threat_level', 'UNKNOWN'),
            summary=self._generate_summary_text(summary_data),
            network_iocs=network_iocs,
            file_iocs=iocs.get('file_hashes', []),
            registry_iocs=iocs.get('registry_keys', []),
            mitre_mapping=analysis_data.get('mitre_mapping', []),
            processes=iocs.get('processes', []),
            yara_rule=analysis_data.get('yara_rule', ''),
            behavior={
                'processes_created': len(iocs.get('processes', [])),
                'files_dropped': summary_data.get('behavior', {}).get('files_dropped', 0),
                'registry_modified': len(iocs.get('registry_keys', [])),
                'network_connections': len(iocs.get('domains', [])) + len(iocs.get('ips', [])),
                'mutexes_created': len(iocs.get('mutexes', [])),
            },
            remediation=self._generate_remediation_steps(summary_data),
            generation_time=datetime.now().isoformat(),
        )

        # Save to file if path provided
        if output_path:
            output_file = Path(output_path)
            output_file.parent.mkdir(parents=True, exist_ok=True)
            with open(output_file, 'w') as f:
                f.write(html_content)
            logger.info(f"[+] HTML report saved to {output_path}")

        return html_content

    def generate_json_ioc_feed(self, analysis_results: List[Dict], output_path: str = None) -> Dict:
        """Generate machine-readable IOC feed for SIEM integration"""

        ioc_feed = {
            'version': '1.0',
            'format': 'MASARE IOC Feed',
            'generated': datetime.now().isoformat(),
            'num_samples': len(analysis_results),
            'indicators': {
                'files': [],
                'urls': [],
                'domains': [],
                'ips': [],
                'registry': [],
            }
        }

        for report in analysis_results:
            iocs = report.get('iocs', {})
            sample_name = report.get('sample', {}).get('name', 'Unknown')

            # File hashes
            for hash_value in iocs.get('file_hashes', []):
                if hash_value:
                    ioc_feed['indicators']['files'].append({
                        'hash': hash_value,
                        'source': sample_name,
                        'timestamp': report.get('analysis_date'),
                    })

            # Network indicators
            for domain in iocs.get('domains', []):
                if domain:
                    ioc_feed['indicators']['domains'].append({
                        'domain': domain,
                        'source': sample_name,
                        'timestamp': report.get('analysis_date'),
                    })

            for ip in iocs.get('ips', []):
                if ip:
                    ioc_feed['indicators']['ips'].append({
                        'ip': ip,
                        'source': sample_name,
                        'timestamp': report.get('analysis_date'),
                    })

            for url in iocs.get('urls', []):
                if url:
                    ioc_feed['indicators']['urls'].append({
                        'url': url,
                        'source': sample_name,
                        'timestamp': report.get('analysis_date'),
                    })

            # Registry keys
            for reg_key in iocs.get('registry_keys', []):
                if reg_key:
                    ioc_feed['indicators']['registry'].append({
                        'key': reg_key,
                        'source': sample_name,
                        'timestamp': report.get('analysis_date'),
                    })

        # Save to file if path provided
        if output_path:
            output_file = Path(output_path)
            output_file.parent.mkdir(parents=True, exist_ok=True)
            with open(output_file, 'w') as f:
                json.dump(ioc_feed, f, indent=2)
            logger.info(f"[+] IOC feed saved to {output_path}")

        return ioc_feed

    def _generate_summary_text(self, summary_data: Dict) -> str:
        """Generate executive summary text"""
        threat_level = summary_data.get('threat_level', 'UNKNOWN')
        signatures = summary_data.get('signatures_triggered', 0)
        network = summary_data.get('network_activity', {})
        behavior = summary_data.get('behavior', {})

        summary = f"This malware sample has been classified as {threat_level} threat. "
        summary += f"Analysis detected {signatures} behavioral signatures. "

        if network.get('domains_contacted', 0) > 0:
            summary += f"The sample attempted to contact {network['domains_contacted']} external domains "
            summary += f"and {network['ips_contacted']} IP addresses. "

        if behavior.get('files_dropped', 0) > 0:
            summary += f"It dropped {behavior['files_dropped']} additional files to disk. "

        if behavior.get('registry_modified', 0) > 0:
            summary += f"Registry modifications were detected ({behavior['registry_modified']} keys). "

        summary += "Immediate remediation is recommended."

        return summary

    def _generate_remediation_steps(self, summary_data: Dict) -> List[str]:
        """Generate remediation steps based on analysis"""
        steps = [
            "Isolate affected systems from network immediately",
            "Terminate all suspicious processes identified in this report",
            "Block all network indicators (IPs, domains, URLs) at firewall/proxy",
            "Remove malicious files from affected systems using provided file hashes",
            "Remove registry keys created for persistence",
            "Scan entire network for additional infections using provided YARA rules",
            "Reset passwords for any credentials potentially compromised",
            "Monitor network for C2 callback attempts to identified domains/IPs",
            "Implement EDR/SIEM detections using provided IOCs",
            "Conduct forensic investigation to determine initial infection vector"
        ]
        return steps


def main():
    parser = argparse.ArgumentParser(description='MASARE Report Generator')

    parser.add_argument('--analysis-dir', type=str, help='Analysis results directory')
    parser.add_argument('--json', type=str, help='Analysis report JSON file')
    parser.add_argument('--output', type=str, help='Output HTML file path')
    parser.add_argument('--ioc-feed', type=str, help='Generate IOC feed from multiple reports')

    args = parser.parse_args()

    generator = MalwareAnalysisReportGenerator()

    try:
        if args.analysis_dir:
            # Load report from directory
            report_file = Path(args.analysis_dir) / 'report.json'
            if not report_file.exists():
                logger.error(f"[-] Report not found: {report_file}")
                sys.exit(1)

            with open(report_file, 'r') as f:
                analysis_data = json.load(f)

            # Generate HTML report
            output_file = args.output or str(Path(args.analysis_dir) / 'report.html')
            generator.generate_html_report(analysis_data, output_file)
            print(f"[✓] HTML report generated: {output_file}")

        elif args.json:
            # Load JSON report
            with open(args.json, 'r') as f:
                analysis_data = json.load(f)

            # Generate HTML report
            output_file = args.output or args.json.replace('.json', '.html')
            generator.generate_html_report(analysis_data, output_file)
            print(f"[✓] HTML report generated: {output_file}")

        elif args.ioc_feed:
            # Generate IOC feed from multiple reports
            reports = []
            for json_file in Path(args.ioc_feed).glob('**/report.json'):
                with open(json_file, 'r') as f:
                    reports.append(json.load(f))

            ioc_feed = generator.generate_json_ioc_feed(reports, args.output)
            print(f"[✓] IOC feed generated with {ioc_feed['num_samples']} samples")

        else:
            parser.print_help()
            sys.exit(1)

    except Exception as e:
        logger.error(f"[✗] Error generating report: {e}", exc_info=True)
        sys.exit(1)


if __name__ == '__main__':
    main()
