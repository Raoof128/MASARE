# Contributing to MASARE

Thank you for your interest in contributing to MASARE (Malware Analysis Sandbox with Automated Reverse Engineering)! This document provides guidelines for contributing to the project.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [How to Contribute](#how-to-contribute)
- [Development Workflow](#development-workflow)
- [Coding Standards](#coding-standards)
- [Testing Guidelines](#testing-guidelines)
- [Documentation](#documentation)
- [Security](#security)

## Code of Conduct

By participating in this project, you agree to abide by our [Code of Conduct](CODE_OF_CONDUCT.md). Please read it before contributing.

## Getting Started

1. **Fork the repository** on GitHub
2. **Clone your fork** locally:
   ```bash
   git clone https://github.com/YOUR_USERNAME/MASARE.git
   cd MASARE
   ```
3. **Add upstream remote**:
   ```bash
   git remote add upstream https://github.com/Raoof128/MASARE.git
   ```
4. **Create a feature branch**:
   ```bash
   git checkout -b feature/your-feature-name
   ```

## How to Contribute

### Reporting Bugs

Before creating bug reports, please check existing issues. When you create a bug report, include:

- **Clear title and description**
- **Steps to reproduce** the issue
- **Expected vs actual behavior**
- **Environment details** (OS, Python version, VM software)
- **Error messages** and logs
- **Screenshots** if applicable

**Template:**
```markdown
## Bug Description
Brief description of the issue

## Steps to Reproduce
1. Step one
2. Step two
3. ...

## Expected Behavior
What should happen

## Actual Behavior
What actually happens

## Environment
- OS: Ubuntu 22.04
- Python: 3.11.4
- VirtualBox: 7.0.10
```

### Suggesting Enhancements

Enhancement suggestions are welcome! Please provide:

- **Clear use case** - Why is this enhancement needed?
- **Detailed description** - How should it work?
- **Alternative approaches** - Have you considered other solutions?
- **Impact assessment** - Who benefits from this?

### Submitting Pull Requests

1. **Ensure your code follows** our coding standards
2. **Add tests** for new functionality
3. **Update documentation** as needed
4. **Ensure all tests pass**
5. **Create a pull request** with a clear description

## Development Workflow

### Setting Up Development Environment

```bash
# Install development dependencies
pip install -r requirements.txt
pip install -r requirements-dev.txt  # If available

# Set up pre-commit hooks
pip install pre-commit
pre-commit install

# Run system check
./scripts/check_system.sh
```

### Making Changes

1. **Keep changes focused** - One feature/fix per PR
2. **Write clear commit messages**:
   ```
   type(scope): Short description

   Longer description of what changed and why.

   Fixes #123
   ```

   Types: `feat`, `fix`, `docs`, `style`, `refactor`, `test`, `chore`

3. **Update tests** for your changes
4. **Update documentation** if needed

### Testing Your Changes

```bash
# Run syntax checks
python3 -m py_compile analysis/cuckoo/orchestrator.py

# Run network isolation tests
./tests/test_isolation.sh

# Run Python tests (when available)
pytest tests/

# Run linting
pylint analysis/ automation/ detection/
```

## Coding Standards

### Python Code

Follow [PEP 8](https://pep8.org/) style guide:

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Module docstring describing purpose.

Copyright (c) 2025 MASARE Project
Licensed under the MIT License
"""

import standard_lib
import third_party
from local_module import something


class ExampleClass:
    """Class docstring."""

    def __init__(self, param: str):
        """
        Initialize the class.

        Args:
            param: Description of parameter
        """
        self.param = param

    def method(self, arg: int) -> bool:
        """
        Method docstring.

        Args:
            arg: Description

        Returns:
            Description of return value
        """
        return True
```

**Requirements:**
- ✅ Docstrings for all modules, classes, and functions
- ✅ Type hints where appropriate
- ✅ Maximum line length: 100 characters
- ✅ 4 spaces for indentation (no tabs)
- ✅ Meaningful variable names
- ✅ Comments for complex logic

### Shell Scripts

```bash
#!/bin/bash
#
# Script description
# Author: Name
# Last Updated: YYYY-MM-DD
#

set -e  # Exit on error
set -u  # Exit on undefined variable

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

main() {
    # Clear function naming
    echo "Doing something..."
}

main "$@"
```

### Configuration Files

- **YAML/JSON**: Properly formatted and validated
- **Comments**: Explain non-obvious settings
- **Secrets**: NEVER commit secrets (use environment variables)

## Testing Guidelines

### Test Coverage

Aim for >80% test coverage for critical components:

```python
#!/usr/bin/env python3
"""Tests for orchestrator module."""

import pytest
from analysis.cuckoo.orchestrator import CuckooClient


class TestCuckooClient:
    """Test suite for CuckooClient."""

    def test_initialization(self):
        """Test CuckooClient initialization."""
        client = CuckooClient("http://localhost:8090")
        assert client.cuckoo_url == "http://localhost:8090"

    def test_submit_sample_invalid_path(self):
        """Test error handling for invalid sample path."""
        client = CuckooClient()
        with pytest.raises(FileNotFoundError):
            client.submit_sample("/nonexistent/file.exe")
```

### Integration Tests

Test actual malware analysis workflow (in isolated environment):

```python
def test_end_to_end_analysis(tmp_path):
    """Test complete analysis pipeline."""
    # Use EICAR test file
    eicar = tmp_path / "eicar.com"
    eicar.write_text('X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*')

    orchestrator = MalwareAnalysisOrchestrator()
    result = orchestrator.analyze_sample(str(eicar))

    assert result['status'] == 'success'
    assert len(result['iocs']) > 0
```

## Documentation

### Code Documentation

- **Docstrings**: All public functions/classes
- **Inline comments**: For complex logic
- **README updates**: For new features
- **Architecture docs**: For structural changes

### User Documentation

Update relevant docs:
- `README.md` - For feature additions
- `docs/SETUP_GUIDE.md` - For installation changes
- `docs/ANALYSIS_WORKFLOW.md` - For workflow changes
- `docs/TROUBLESHOOTING.md` - For known issues

### API Documentation

Use clear docstrings that auto-generate docs:

```python
def analyze_sample(self, sample_path: str, timeout: int = 120) -> Dict[str, Any]:
    """
    Analyze a malware sample using Cuckoo Sandbox.

    This method submits the sample to Cuckoo, waits for analysis completion,
    and extracts IOCs from the resulting report.

    Args:
        sample_path: Absolute path to the malware sample
        timeout: Maximum analysis time in seconds (default: 120)

    Returns:
        Dictionary containing:
        - status: 'success' or 'failed'
        - task_id: Cuckoo task ID
        - iocs: Extracted indicators of compromise
        - report_path: Path to HTML report

    Raises:
        FileNotFoundError: If sample_path does not exist
        TimeoutError: If analysis exceeds timeout
        ConnectionError: If cannot connect to Cuckoo API

    Example:
        >>> orchestrator = MalwareAnalysisOrchestrator()
        >>> result = orchestrator.analyze_sample('/tmp/malware.exe')
        >>> print(result['iocs']['domains'])
        ['evil-domain.com', 'malware-c2.net']
    """
```

## Security

### Responsible Disclosure

If you discover a security vulnerability:

1. **DO NOT** open a public issue
2. **Email** security@example.com with details
3. **Wait** for response before public disclosure
4. **Follow** coordinated disclosure timeline (90 days)

### Security Best Practices

When contributing:

- ✅ Never commit malware samples (encrypted or not)
- ✅ Validate all user inputs
- ✅ Use parameterized queries (prevent injection)
- ✅ Sanitize file paths
- ✅ Follow principle of least privilege
- ✅ Document security implications

### Code Review Checklist

Before submitting PR, verify:

- [ ] No hardcoded credentials or API keys
- [ ] No malware samples in commits
- [ ] Input validation for user-supplied data
- [ ] Proper error handling
- [ ] Security implications documented
- [ ] Tests for edge cases
- [ ] Documentation updated

## Pull Request Process

1. **Update CHANGELOG.md** with your changes
2. **Ensure all tests pass**:
   ```bash
   ./scripts/check_system.sh
   pytest tests/
   ```
3. **Get code review** from at least one maintainer
4. **Address feedback** promptly
5. **Squash commits** if requested
6. **Maintainer will merge** once approved

### PR Description Template

```markdown
## Description
Brief description of changes

## Motivation and Context
Why is this change needed? What problem does it solve?

## Type of Change
- [ ] Bug fix (non-breaking change which fixes an issue)
- [ ] New feature (non-breaking change which adds functionality)
- [ ] Breaking change (fix or feature that would cause existing functionality to not work as expected)
- [ ] Documentation update

## How Has This Been Tested?
Describe the tests you ran

## Checklist
- [ ] My code follows the code style of this project
- [ ] I have added tests to cover my changes
- [ ] All new and existing tests passed
- [ ] I have updated the documentation
- [ ] My changes generate no new warnings
- [ ] I have added necessary comments
```

## Recognition

Contributors will be:
- Listed in `AUTHORS.md`
- Acknowledged in release notes
- Credited in relevant documentation

## Questions?

- **GitHub Discussions**: For general questions
- **Issues**: For bug reports and feature requests
- **Email**: For security or private matters

---

Thank you for contributing to MASARE! 🔒🔍
