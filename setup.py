"""Setup configuration for ofac-crypto-screener."""

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as f:
    long_description = f.read()

setup(
    name="ofac-crypto-screener",
    version="0.1.0",
    author="Osman Sonmez",
    author_email="osman@example.com",
    description="Screen cryptocurrency addresses against OFAC SDN List",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/ofac-crypto-screener",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Financial and Insurance Industry",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Office/Business :: Financial",
        "Topic :: Security",
    ],
    python_requires=">=3.10",
    install_requires=[
        "lxml>=5.0.0",
        "requests>=2.31.0",
        "flask>=3.0.0",
        "click>=8.1.0",
        "pandas>=2.0.0",
        "python-Levenshtein>=0.25.0",
        "python-dotenv>=1.0.0",
        "pydantic>=2.0.0",
        "structlog>=24.0.0",
    ],
    extras_require={
        "dev": [
            "pytest>=8.0.0",
            "pytest-cov>=4.0.0",
            "black>=24.0.0",
            "ruff>=0.3.0",
            "mypy>=1.9.0",
        ],
        "blockchain": [
            "web3>=7.0.0",
            "base58>=2.1.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "ofac-screener=ofac_screener.cli:main",
        ],
    },
)
