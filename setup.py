#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MASARE Setup Script

This setup.py is provided for backward compatibility.
Modern installations should use pyproject.toml with:
    pip install -e .

Copyright (c) 2025 MASARE Project
Licensed under the MIT License - see LICENSE file for details
"""

from setuptools import setup, find_packages
from pathlib import Path

# Read README for long description
readme_file = Path(__file__).parent / "README.md"
long_description = readme_file.read_text(encoding="utf-8") if readme_file.exists() else ""

# Read requirements
requirements_file = Path(__file__).parent / "requirements.txt"
if requirements_file.exists():
    with open(requirements_file, 'r', encoding='utf-8') as f:
        requirements = [
            line.strip()
            for line in f
            if line.strip() and not line.startswith('#')
        ]
else:
    requirements = [
        "requests>=2.31.0",
        "yara-python>=4.3.1",
        "jinja2>=3.1.2",
        "pandas>=2.1.0",
        "pefile>=2023.2.7",
        "python-magic>=0.4.27",
        "colorama>=0.4.6",
    ]

# Development dependencies
dev_requirements = [
    "pytest>=7.4.0",
    "pytest-cov>=4.1.0",
    "pytest-mock>=3.11.1",
    "black>=23.7.0",
    "flake8>=6.1.0",
    "pylint>=2.17.5",
    "isort>=5.12.0",
    "mypy>=1.5.0",
    "bandit>=1.7.5",
]

setup(
    name="masare",
    version="1.0.0",
    description="Enterprise-grade Malware Analysis Sandbox with Automated Reverse Engineering",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="MASARE Project",
    author_email="masare@example.com",
    url="https://github.com/Raoof128/MASARE",
    project_urls={
        "Documentation": "https://github.com/Raoof128/MASARE/blob/main/README.md",
        "Source": "https://github.com/Raoof128/MASARE",
        "Issues": "https://github.com/Raoof128/MASARE/issues",
        "Changelog": "https://github.com/Raoof128/MASARE/blob/main/CHANGELOG.md",
    },
    license="MIT",
    packages=find_packages(
        exclude=["tests", "tests.*", "examples", "examples.*", "docs", "docs.*"]
    ),
    include_package_data=True,
    package_data={
        "": ["*.conf", "*.yml", "*.yaml", "*.json"],
    },
    install_requires=requirements,
    extras_require={
        "dev": dev_requirements,
        "all": dev_requirements,
    },
    python_requires=">=3.10",
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "Intended Audience :: Science/Research",
        "Topic :: Security",
        "Topic :: System :: Monitoring",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Operating System :: POSIX :: Linux",
        "Operating System :: MacOS",
        "Environment :: Console",
    ],
    keywords=[
        "malware",
        "analysis",
        "sandbox",
        "reverse-engineering",
        "cuckoo",
        "yara",
        "threat-intelligence",
        "security",
        "dfir",
        "incident-response",
    ],
    entry_points={
        "console_scripts": [
            "masare-analyze=automation.batch_analyzer:main",
            "masare-report=automation.report_generator:main",
            "masare-yara=detection.yara.signature_generator:main",
        ],
    },
    zip_safe=False,
)
