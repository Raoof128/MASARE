#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Pytest Configuration and Shared Fixtures

Copyright (c) 2025 MASARE Project
Licensed under the MIT License - see LICENSE file for details
"""

import pytest
import tempfile
import sys
from pathlib import Path

# Add project root to Python path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))


def pytest_configure(config):
    """Configure pytest with custom markers."""
    config.addinivalue_line(
        "markers",
        "integration: marks tests as integration tests (require live services)"
    )
    config.addinivalue_line(
        "markers",
        "slow: marks tests as slow (deselect with '-m \"not slow\"')"
    )
    config.addinivalue_line(
        "markers",
        "requires_cuckoo: marks tests that require a running Cuckoo instance"
    )
    config.addinivalue_line(
        "markers",
        "requires_vm: marks tests that require VMs to be running"
    )


@pytest.fixture(scope="session")
def eicar_file():
    """Provide EICAR test file for testing."""
    eicar_content = b'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'

    with tempfile.NamedTemporaryFile(delete=False, suffix='.com', mode='wb') as tmp:
        tmp.write(eicar_content)
        tmp_path = tmp.name

    yield tmp_path

    # Cleanup
    Path(tmp_path).unlink(missing_ok=True)


@pytest.fixture(scope="session")
def temp_output_dir():
    """Provide temporary output directory for tests."""
    import tempfile
    import shutil

    temp_dir = tempfile.mkdtemp(prefix='masare_test_')

    yield temp_dir

    # Cleanup
    shutil.rmtree(temp_dir, ignore_errors=True)


@pytest.fixture
def mock_cuckoo_report():
    """Provide a mock Cuckoo analysis report."""
    return {
        'info': {
            'id': 12345,
            'category': 'file',
            'duration': 120,
            'started': '2025-01-15 10:00:00',
            'ended': '2025-01-15 10:02:00'
        },
        'target': {
            'file': {
                'name': 'malware.exe',
                'size': 102400,
                'md5': 'd41d8cd98f00b204e9800998ecf8427e',
                'sha256': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
            }
        },
        'network': {
            'domains': [
                {'domain': 'malware-c2.com', 'ip': '1.2.3.4'},
                {'domain': 'evil-domain.net', 'ip': '5.6.7.8'}
            ],
            'hosts': ['1.2.3.4', '5.6.7.8', '10.0.0.1'],
            'dns': [
                {'request': 'malware-c2.com', 'answers': ['1.2.3.4']}
            ],
            'http': [
                {'uri': 'http://malware-c2.com/config', 'method': 'GET'}
            ]
        },
        'signatures': [
            {
                'name': 'network_cnc_http',
                'severity': 5,
                'description': 'Connects to C&C server'
            },
            {
                'name': 'creates_exe',
                'severity': 3,
                'description': 'Creates executable files'
            }
        ],
        'dropped': [
            {'name': 'payload.exe', 'md5': 'abc123def456'},
            {'name': 'config.dat', 'md5': '789ghi012jkl'}
        ],
        'behavior': {
            'processes': [
                {
                    'process_name': 'malware.exe',
                    'pid': 1234,
                    'parent_id': 5678
                },
                {
                    'process_name': 'cmd.exe',
                    'pid': 9012,
                    'parent_id': 1234
                }
            ],
            'summary': {
                'files': ['C:\\Temp\\payload.exe', 'C:\\Windows\\config.dat'],
                'keys': [
                    'HKLM\\Software\\Malware\\Config',
                    'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Evil'
                ]
            }
        }
    }


@pytest.fixture
def sample_iocs():
    """Provide sample IOCs for testing."""
    return {
        'domains': ['malware.com', 'evil-c2.net', 'phishing.org'],
        'ips': ['192.0.2.1', '198.51.100.1', '203.0.113.1'],
        'files': [
            'C:\\Temp\\malware.exe',
            'C:\\Windows\\System32\\payload.dll',
            '/tmp/dropped_file.bin'
        ],
        'registry': [
            'HKLM\\Software\\Malware\\Config',
            'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Persistence'
        ],
        'processes': ['cmd.exe', 'powershell.exe', 'malware.exe'],
        'urls': [
            'http://malware.com/payload',
            'https://evil-c2.net/beacon'
        ]
    }


@pytest.fixture
def minimal_pe_file():
    """Create a minimal valid PE file for testing."""
    # Minimal PE structure
    dos_header = b'MZ' + b'\x90\x00' + b'\x00' * 58 + b'\x80\x00\x00\x00'
    dos_stub = b'\x00' * (0x80 - len(dos_header))
    pe_signature = b'PE\x00\x00'
    coff_header = (
        b'\x4c\x01'  # Machine (i386)
        + b'\x03\x00'  # NumberOfSections
        + b'\x00' * 12  # TimeDateStamp, etc.
        + b'\xE0\x00'  # SizeOfOptionalHeader
        + b'\x02\x01'  # Characteristics
    )
    optional_header = b'\x00' * 224  # Minimal optional header

    pe_content = dos_header + dos_stub + pe_signature + coff_header + optional_header

    with tempfile.NamedTemporaryFile(delete=False, suffix='.exe', mode='wb') as tmp:
        tmp.write(pe_content)
        tmp_path = tmp.name

    yield tmp_path

    Path(tmp_path).unlink(missing_ok=True)


# Skip markers for CI/CD environments
def pytest_collection_modifyitems(config, items):
    """Automatically skip integration tests in CI unless explicitly requested."""
    import os

    if os.environ.get('CI') == 'true' and not os.environ.get('RUN_INTEGRATION_TESTS'):
        skip_integration = pytest.mark.skip(reason="Skipping integration tests in CI")
        for item in items:
            if "integration" in item.keywords:
                item.add_marker(skip_integration)

            if "requires_cuckoo" in item.keywords:
                item.add_marker(skip_integration)

            if "requires_vm" in item.keywords:
                item.add_marker(skip_integration)
