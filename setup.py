"""
Setup configuration for Zodiac Android Security Analyzer
"""

from setuptools import setup, find_packages
from pathlib import Path

# Read the README file
this_directory = Path(__file__).parent
long_description = (this_directory / "README.md").read_text(encoding="utf-8")

# Read requirements
requirements = (this_directory / "requirements.txt").read_text().strip().split('\n')

setup(
    name="zodiac-security",
    version="2.0.0",
    author="Zodiac Security Team",
    author_email="security@zodiac.dev",
    description="Enterprise Android Security Analyzer powered by LangChain",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/zodiac/zodiac-security",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "Topic :: Software Development :: Testing",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
    ],
    python_requires=">=3.8",
    install_requires=requirements,
    extras_require={
        "dev": [
            "pytest>=7.0.0",
            "pytest-asyncio>=0.21.0",
            "pytest-cov>=4.0.0",
            "black>=23.0.0",
            "flake8>=6.0.0",
            "mypy>=1.0.0",
            "pre-commit>=3.0.0",
        ],
        "docs": [
            "sphinx>=5.0.0",
            "sphinx-rtd-theme>=1.2.0",
            "sphinx-autodoc-typehints>=1.22.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "zodiac=zodiac.main:run",
            "zodiac-analyze=zodiac.main:run",
        ],
    },
    include_package_data=True,
    package_data={
        "zodiac": [
            "config/*.yaml",
            "config/*.json",
            "templates/*.html",
            "templates/*.md",
        ],
    },
    zip_safe=False,
)