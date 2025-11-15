#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Unit Tests for Cuckoo Orchestrator

Copyright (c) 2025 MASARE Project
Licensed under the MIT License - see LICENSE file for details
"""

import pytest
import tempfile
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock

# Import the module to test
try:
    from analysis.cuckoo.orchestrator import CuckooClient, MalwareAnalysisOrchestrator
    IMPORTS_AVAILABLE = True
except ImportError:
    IMPORTS_AVAILABLE = False
    pytest.skip("Cuckoo orchestrator module not available", allow_module_level=True)


class TestCuckooClient:
    """Test suite for CuckooClient class."""

    def test_initialization_default(self):
        """Test CuckooClient initialization with defaults."""
        client = CuckooClient()
        assert client.cuckoo_url == "http://192.168.1.10:8090"
        assert isinstance(client.session, object)

    def test_initialization_custom_url(self):
        """Test CuckooClient initialization with custom URL."""
        custom_url = "http://10.0.0.5:9000"
        client = CuckooClient(cuckoo_url=custom_url)
        assert client.cuckoo_url == custom_url

    def test_url_normalization(self):
        """Test that trailing slashes are removed from URL."""
        client = CuckooClient(cuckoo_url="http://192.168.1.10:8090/")
        assert client.cuckoo_url == "http://192.168.1.10:8090"

    @patch('requests.Session.post')
    def test_submit_sample_success(self, mock_post):
        """Test successful sample submission."""
        # Create a temporary test file
        with tempfile.NamedTemporaryFile(delete=False, suffix='.exe') as tmp:
            tmp.write(b'MZ\x90\x00')  # Minimal PE header
            tmp_path = tmp.name

        try:
            # Mock successful API response
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.json.return_value = {'task_id': 12345}
            mock_post.return_value = mock_response

            client = CuckooClient()
            task_id = client.submit_sample(tmp_path)

            assert task_id == 12345
            assert mock_post.called

        finally:
            Path(tmp_path).unlink()

    def test_submit_sample_file_not_found(self):
        """Test error handling for non-existent file."""
        client = CuckooClient()
        with pytest.raises(FileNotFoundError):
            client.submit_sample('/nonexistent/file.exe')

    @patch('requests.Session.get')
    def test_get_task_status(self, mock_get):
        """Test retrieving task status."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            'task': {'status': 'reported', 'id': 123}
        }
        mock_get.return_value = mock_response

        client = CuckooClient()
        status = client.get_task_status(123)

        assert status == 'reported'

    @patch('requests.Session.get')
    def test_get_report_success(self, mock_get):
        """Test retrieving analysis report."""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            'info': {'id': 123},
            'network': {'domains': ['evil.com']},
            'signatures': []
        }
        mock_get.return_value = mock_response

        client = CuckooClient()
        report = client.get_report(123)

        assert report is not None
        assert report['info']['id'] == 123
        assert 'evil.com' in report['network']['domains']

    def test_extract_iocs_from_report(self):
        """Test IOC extraction from Cuckoo report."""
        mock_report = {
            'network': {
                'domains': [{'domain': 'malware.com'}, {'domain': 'evil.net'}],
                'hosts': ['1.2.3.4', '5.6.7.8']
            },
            'dropped': [
                {'name': 'malware.exe'},
                {'name': 'payload.dll'}
            ],
            'behavior': {
                'processes': [
                    {'process_name': 'cmd.exe'},
                    {'process_name': 'powershell.exe'}
                ]
            }
        }

        client = CuckooClient()
        iocs = client.extract_iocs(mock_report)

        assert 'malware.com' in iocs['domains']
        assert 'evil.net' in iocs['domains']
        assert '1.2.3.4' in iocs['ips']
        assert len(iocs['files']) == 2
        assert len(iocs['processes']) == 2

    @patch('requests.Session.get')
    def test_wait_for_completion_timeout(self, mock_get):
        """Test timeout when waiting for analysis completion."""
        # Mock response that always returns 'running' status
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            'task': {'status': 'running'}
        }
        mock_get.return_value = mock_response

        client = CuckooClient()

        # Should timeout after specified duration
        with pytest.raises(TimeoutError):
            client.wait_for_completion(task_id=123, timeout=1, poll_interval=0.1)


class TestMalwareAnalysisOrchestrator:
    """Test suite for MalwareAnalysisOrchestrator class."""

    def test_initialization(self):
        """Test orchestrator initialization."""
        orchestrator = MalwareAnalysisOrchestrator()
        assert orchestrator.cuckoo_client is not None
        assert orchestrator.output_dir is not None

    @patch('analysis.cuckoo.orchestrator.CuckooClient')
    def test_analyze_sample_workflow(self, mock_cuckoo_class):
        """Test complete analysis workflow."""
        # Create temporary test file
        with tempfile.NamedTemporaryFile(delete=False, suffix='.exe') as tmp:
            tmp.write(b'MZ\x90\x00')
            tmp_path = tmp.name

        try:
            # Mock Cuckoo client
            mock_cuckoo = Mock()
            mock_cuckoo.submit_sample.return_value = 12345
            mock_cuckoo.wait_for_completion.return_value = True
            mock_cuckoo.get_report.return_value = {
                'info': {'id': 12345},
                'network': {'domains': [], 'hosts': []},
                'signatures': []
            }
            mock_cuckoo.extract_iocs.return_value = {
                'domains': [],
                'ips': [],
                'files': [],
                'processes': []
            }
            mock_cuckoo_class.return_value = mock_cuckoo

            orchestrator = MalwareAnalysisOrchestrator()
            result = orchestrator.analyze_sample(tmp_path)

            assert result['status'] == 'success'
            assert result['task_id'] == 12345
            assert 'iocs' in result

        finally:
            Path(tmp_path).unlink()


class TestIntegration:
    """Integration tests (require actual Cuckoo instance)."""

    @pytest.mark.integration
    @pytest.mark.skipif(True, reason="Requires live Cuckoo instance")
    def test_eicar_analysis(self):
        """Test analysis of EICAR test file (requires live system)."""
        # Create EICAR test file
        eicar_content = b'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'

        with tempfile.NamedTemporaryFile(delete=False, suffix='.com') as tmp:
            tmp.write(eicar_content)
            tmp_path = tmp.name

        try:
            orchestrator = MalwareAnalysisOrchestrator()
            result = orchestrator.analyze_sample(tmp_path, timeout=60)

            assert result['status'] == 'success'
            assert result['task_id'] > 0

        finally:
            Path(tmp_path).unlink()


# Fixtures
@pytest.fixture
def sample_cuckoo_report():
    """Fixture providing a sample Cuckoo report."""
    return {
        'info': {
            'id': 123,
            'category': 'file',
            'duration': 120
        },
        'network': {
            'domains': [
                {'domain': 'malware.com'},
                {'domain': 'c2server.net'}
            ],
            'hosts': ['1.2.3.4', '5.6.7.8']
        },
        'signatures': [
            {'name': 'creates_exe', 'severity': 3},
            {'name': 'network_cnc_http', 'severity': 5}
        ],
        'dropped': [
            {'name': 'payload.exe', 'md5': 'abc123'},
            {'name': 'config.dat', 'md5': 'def456'}
        ],
        'behavior': {
            'processes': [
                {'process_name': 'malware.exe', 'pid': 1234},
                {'process_name': 'cmd.exe', 'pid': 5678}
            ]
        }
    }


@pytest.fixture
def temp_malware_sample():
    """Fixture providing a temporary test file."""
    with tempfile.NamedTemporaryFile(delete=False, suffix='.exe') as tmp:
        tmp.write(b'MZ\x90\x00' + b'\x00' * 100)  # Minimal PE
        tmp_path = tmp.name

    yield tmp_path

    # Cleanup
    Path(tmp_path).unlink(missing_ok=True)
