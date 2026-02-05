#!/usr/bin/env python3
"""
BAT - Autonomous Vulnerability Investigation for C Memory Bugs

Setup script for installation.
"""

from setuptools import setup, find_packages
from pathlib import Path

# Read README
readme_path = Path(__file__).parent / "README.md"
long_description = ""
if readme_path.exists():
    long_description = readme_path.read_text(encoding='utf-8')

setup(
    name="bat-vuln-scanner",
    version="1.0.0",
    author="BAT Team",
    author_email="bat@example.com",
    description="Autonomous Vulnerability Investigation for C Memory Bugs",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/your-repo/BAT",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Intended Audience :: Information Technology",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Topic :: Security",
        "Topic :: Software Development :: Quality Assurance",
        "Topic :: Software Development :: Testing",
    ],
    python_requires=">=3.8",
    install_requires=[
        # Core dependencies are from standard library
    ],
    extras_require={
        "clang": ["clang>=14.0"],
        "dev": [
            "pytest>=7.0.0",
            "pytest-cov>=4.0.0",
            "black>=23.0.0",
            "mypy>=1.0.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "bat=BAT.cli:main",
        ],
    },
    include_package_data=True,
    package_data={
        "BAT": [
            "rag/knowledge_base/*.json",
            "report/templates/*.md",
        ],
    },
)
