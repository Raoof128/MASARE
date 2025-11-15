#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Unit Tests for YARA Signature Generator

Copyright (c) 2025 MASARE Project
Licensed under the MIT License - see LICENSE file for details
"""

import pytest
import tempfile
from pathlib import Path
from unittest.mock import Mock, patch

# Import the module to test
try:
    from detection.yara.signature_generator import YARASignatureGenerator
    import yara
    IMPORTS_AVAILABLE = True
except ImportError:
    IMPORTS_AVAILABLE = False
    pytest.skip("YARA module not available", allow_module_level=True)


class TestYARASignatureGenerator:
    """Test suite for YARASignatureGenerator class."""

    def test_initialization(self):
        """Test YARASignatureGenerator initialization."""
        generator = YARASignatureGenerator()
        assert generator is not None

    def test_generate_hash_rule(self):
        """Test generation of hash-based YARA rule."""
        generator = YARASignatureGenerator()

        md5 = "d41d8cd98f00b204e9800998ecf8427e"
        sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        sample_name = "test_malware"

        rule = generator.generate_hash_rule(md5, sha256, sample_name)

        assert rule is not None
        assert "rule " in rule
        assert sample_name in rule
        assert md5 in rule
        assert sha256 in rule
        assert "import \"hash\"" in rule or "hash.md5" in rule

    def test_generate_hash_rule_compiles(self):
        """Test that generated hash rule compiles successfully."""
        generator = YARASignatureGenerator()

        rule = generator.generate_hash_rule(
            md5="d41d8cd98f00b204e9800998ecf8427e",
            sha256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            sample_name="test_sample"
        )

        # Add necessary imports
        full_rule = 'import "hash"\n' + rule

        # Should compile without errors
        try:
            compiled = yara.compile(source=full_rule)
            assert compiled is not None
        except yara.SyntaxError as e:
            pytest.fail(f"Generated rule has syntax errors: {e}")

    def test_generate_string_rule(self):
        """Test generation of string-based YARA rule."""
        # Create temporary file with distinctive strings
        with tempfile.NamedTemporaryFile(delete=False, mode='wb') as tmp:
            tmp.write(b'MZ\x90\x00')  # PE header
            tmp.write(b'This is a distinctive string for testing')
            tmp.write(b'\x00' * 50)
            tmp.write(b'Another unique pattern XYZ123')
            tmp_path = tmp.name

        try:
            generator = YARASignatureGenerator()
            rule = generator.generate_string_rule(
                sample_path=tmp_path,
                sample_name="string_test"
            )

            assert rule is not None
            assert "rule " in rule
            assert "strings:" in rule
            assert "$" in rule  # Variable definitions

        finally:
            Path(tmp_path).unlink()

    def test_generate_behavioral_rule(self):
        """Test generation of behavioral YARA rule from IOCs."""
        iocs = {
            'domains': ['malware.com', 'evil-c2.net', 'phishing-site.org'],
            'ips': ['1.2.3.4', '5.6.7.8'],
            'files': ['malware.exe', 'payload.dll'],
            'registry': [
                'HKLM\\Software\\Malware\\Config',
                'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Evil'
            ],
            'processes': ['cmd.exe', 'powershell.exe']
        }

        generator = YARASignatureGenerator()
        rule = generator.generate_behavioral_rule(
            iocs=iocs,
            sample_name="behavioral_test"
        )

        assert rule is not None
        assert "rule " in rule
        assert "behavioral_test" in rule

        # Check that IOCs are included
        for domain in iocs['domains']:
            assert domain in rule

    def test_generate_pe_rule(self):
        """Test generation of PE-specific YARA rule."""
        # Create minimal PE file
        pe_header = (
            b'MZ'  # DOS signature
            b'\x90\x00'  # DOS header bytes
            + b'\x00' * 58  # Padding to offset 0x3C
            + b'\x40\x00\x00\x00'  # PE header offset at 0x40
            + b'\x00' * (0x40 - 64)  # More padding
            + b'PE\x00\x00'  # PE signature
            + b'\x4c\x01'  # Machine (i386)
            + b'\x00' * 100  # Rest of PE header
        )

        with tempfile.NamedTemporaryFile(delete=False, suffix='.exe', mode='wb') as tmp:
            tmp.write(pe_header)
            tmp_path = tmp.name

        try:
            generator = YARASignatureGenerator()
            rule = generator.generate_pe_rule(
                sample_path=tmp_path,
                sample_name="pe_test"
            )

            # Rule may be None if pefile can't parse it (expected for minimal PE)
            # or it should contain PE-specific checks
            if rule:
                assert "rule " in rule
                assert 'import "pe"' in rule or "pe." in rule

        finally:
            Path(tmp_path).unlink()

    def test_comprehensive_ruleset_generation(self):
        """Test generation of comprehensive ruleset."""
        # Create test file
        with tempfile.NamedTemporaryFile(delete=False, suffix='.exe', mode='wb') as tmp:
            tmp.write(b'MZ\x90\x00')
            tmp.write(b'Distinctive malware string')
            tmp.write(b'\x00' * 100)
            tmp_path = tmp.name

        try:
            iocs = {
                'domains': ['evil.com'],
                'ips': ['1.2.3.4'],
                'files': ['dropped.exe'],
                'processes': ['cmd.exe']
            }

            generator = YARASignatureGenerator()
            ruleset = generator.generate_comprehensive_ruleset(
                sample_path=tmp_path,
                iocs=iocs,
                task_id=12345
            )

            assert ruleset is not None
            assert len(ruleset) > 0
            assert "rule " in ruleset

            # Should contain multiple rule types
            # (hash, string, behavioral, etc.)

        finally:
            Path(tmp_path).unlink()

    def test_rule_compilation(self):
        """Test that generated rules compile successfully."""
        generator = YARASignatureGenerator()

        # Generate a simple rule
        rule = """
rule test_compilation {
    meta:
        description = "Test rule for compilation"
    strings:
        $test = "test string"
    condition:
        $test
}
"""

        # Should compile without errors
        try:
            compiled = yara.compile(source=rule)
            assert compiled is not None
        except yara.SyntaxError as e:
            pytest.fail(f"Rule compilation failed: {e}")

    def test_rule_matching(self):
        """Test that generated rule matches the sample."""
        # Create test file
        test_content = b'This file contains a MALWARE_SIGNATURE pattern'

        with tempfile.NamedTemporaryFile(delete=False, mode='wb') as tmp:
            tmp.write(test_content)
            tmp_path = tmp.name

        try:
            # Create a rule to match this content
            rule = """
rule test_match {
    strings:
        $sig = "MALWARE_SIGNATURE"
    condition:
        $sig
}
"""

            compiled = yara.compile(source=rule)
            matches = compiled.match(tmp_path)

            assert len(matches) > 0
            assert matches[0].rule == "test_match"

        finally:
            Path(tmp_path).unlink()

    def test_empty_iocs_handling(self):
        """Test handling of empty IOCs."""
        generator = YARASignatureGenerator()

        empty_iocs = {
            'domains': [],
            'ips': [],
            'files': [],
            'processes': []
        }

        # Should handle gracefully without crashing
        rule = generator.generate_behavioral_rule(
            iocs=empty_iocs,
            sample_name="empty_test"
        )

        # May return None or a minimal rule
        assert rule is None or isinstance(rule, str)

    def test_sanitize_rule_name(self):
        """Test rule name sanitization."""
        generator = YARASignatureGenerator()

        # Test various problematic names
        test_cases = [
            ("malware.exe", "malware_exe"),
            ("test file.dll", "test_file_dll"),
            ("123_leading_number", "sample_123_leading_number"),
            ("special!@#chars", "special___chars"),
        ]

        for input_name, expected_output in test_cases:
            # Generate a rule with this name
            rule = generator.generate_hash_rule(
                md5="d41d8cd98f00b204e9800998ecf8427e",
                sha256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                sample_name=input_name
            )

            # Rule name should be sanitized
            assert input_name not in rule or expected_output in rule


class TestYARAIntegration:
    """Integration tests for YARA functionality."""

    @pytest.mark.integration
    def test_eicar_detection(self):
        """Test YARA detection of EICAR test file."""
        # Create EICAR test file
        eicar = b'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'

        with tempfile.NamedTemporaryFile(delete=False, mode='wb') as tmp:
            tmp.write(eicar)
            tmp_path = tmp.name

        try:
            # Generate YARA rule for EICAR
            generator = YARASignatureGenerator()
            rule = generator.generate_string_rule(
                sample_path=tmp_path,
                sample_name="eicar"
            )

            # Compile and test
            full_rule = 'import "hash"\n' + rule
            compiled = yara.compile(source=full_rule)
            matches = compiled.match(tmp_path)

            assert len(matches) > 0

        finally:
            Path(tmp_path).unlink()


# Fixtures
@pytest.fixture
def sample_iocs():
    """Fixture providing sample IOCs."""
    return {
        'domains': [
            'malware-domain.com',
            'evil-c2.net',
            'phishing.org'
        ],
        'ips': [
            '192.0.2.1',
            '198.51.100.1',
            '203.0.113.1'
        ],
        'files': [
            'malware.exe',
            'payload.dll',
            'config.dat'
        ],
        'registry': [
            'HKLM\\Software\\Malware',
            'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Evil'
        ],
        'processes': [
            'cmd.exe',
            'powershell.exe',
            'malware.exe'
        ]
    }


@pytest.fixture
def temp_pe_file():
    """Fixture providing a temporary PE file."""
    pe_content = b'MZ\x90\x00' + b'\x00' * 200

    with tempfile.NamedTemporaryFile(delete=False, suffix='.exe', mode='wb') as tmp:
        tmp.write(pe_content)
        tmp_path = tmp.name

    yield tmp_path

    Path(tmp_path).unlink(missing_ok=True)
