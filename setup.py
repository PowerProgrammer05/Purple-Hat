#!/usr/bin/env python3
"""
PURPLE HAT - Modern Security Testing Framework
Setup script for package distribution
"""

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = [line.strip() for line in fh if line.strip() and not line.startswith("#")]

setup(
    name="purple-hat",
    version="2.0.0",
    author="Security Testing Team",
    author_email="security@purplehat.io",
    description="Comprehensive security testing framework for penetration testing and vulnerability assessment",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/PowerProgrammer05/Purple-Hat",
    packages=find_packages(),
    include_package_data=True,
    classifiers=[
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "Topic :: System :: Networking",
        "Topic :: Security",
    ],
    python_requires=">=3.8",
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "purplehat=main:main",
        ],
    },
    package_data={
        "ui": ["templates/*.html", "static/**/*"],
    },
)
