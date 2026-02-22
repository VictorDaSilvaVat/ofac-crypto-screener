# OFAC Crypto Screener

## 👤 Author

**Osman Sonmez**

Blockchain Security Researcher | Smart Contract Auditor | Attorney at Law

Specializing in cryptocurrency compliance, blockchain law, smart contract security, and regulatory technology. Founder of Sonmez Partners Law Firm (Turkey) and Sonmez Consulting (USA).

- 🌐 Website: [osmansonmez.com](https://osmansonmez.com)
- 💼 LinkedIn: [linkedin.com/in/sonmezosman](https://www.linkedin.com/in/sonmezosman)
- 🐙 GitHub: [github.com/sonmez-lab](https://github.com/sonmez-lab)

**Focus Areas:** Blockchain Security | AML/CFT Compliance | Smart Contract Auditing | Cryptocurrency Law | OFAC Sanctions | DeFi Regulations | Token Classifications | Travel Rule | FATF Compliance

---



[![Python](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![OFAC Compliant](https://img.shields.io/badge/OFAC-Compliant-green.svg)](https://ofac.treasury.gov/)

**A Python-based tool for screening cryptocurrency wallet addresses against OFAC's Specially Designated Nationals (SDN) List, supporting sanctions compliance for Virtual Asset Service Providers (VASPs).**

## 🎯 Purpose

This tool addresses a critical gap in open-source sanctions compliance infrastructure by providing:

- **Real-time OFAC SDN screening** for cryptocurrency addresses (BTC, ETH, USDT, XMR, Tron)
- **Fuzzy matching** to catch potential evasion attempts (Levenshtein distance ≤2)
- **Risk scoring** based on address patterns and jurisdiction context
- **Both CLI and REST API** interfaces for flexible integration

## 🏛️ National Security Context

Per the [2024 National Strategy for Combating Terrorist and Other Illicit Financing](https://home.treasury.gov/), cryptocurrency-based sanctions evasion represents a priority threat. OFAC enforcement against crypto-enabled sanctions circumvention has accelerated, with recent designations including:

- **Zedcex Exchange** (January 2026) - First-ever OFAC designation of digital asset exchanges for Iran operations
- **Garantex/Grinex** - Russian crypto exchange facilitating billions in illicit transactions
- **Cryptex** - Processed $5.88B in transactions for sanctioned entities

This tool helps VASPs, compliance teams, and researchers meet their obligations under the Bank Secrecy Act (31 U.S.C. §5311) and OFAC requirements.

## 📋 Features

### Core Functionality
- Download and parse OFAC SDN_ADVANCED.XML from Treasury's Sanctions List Service
- Extract all Digital Currency Address records (BTC, ETH, USDT, XMR, Tron)
- Screen user-provided wallet addresses against sanctioned addresses
- Exact match and fuzzy matching with configurable thresholds
- JSON/CSV output with match confidence scores

### API Endpoints
- `POST /screen` - Screen a single wallet address
- `POST /batch-screen` - Screen multiple addresses
- `GET /sdn/addresses` - List all sanctioned crypto addresses
- `GET /sdn/stats` - SDN list statistics
- `GET /health` - Health check

### Integrations
- OpenSanctions data support (EU, UN, UK lists)
- Chainalysis free sanctions oracle contract verification
- Delta file support for incremental updates

## 🚀 Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/ofac-crypto-screener.git
cd ofac-crypto-screener

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### CLI Usage

```bash
# Download/update SDN data
python -m ofac_screener update

# Screen a single address
python -m ofac_screener screen 0x1234567890abcdef...

# Screen multiple addresses from file
python -m ofac_screener batch addresses.txt --output results.json

# Get SDN statistics
python -m ofac_screener stats
```

### API Usage

```bash
# Start the API server
python -m ofac_screener api --port 8000

# Screen an address
curl -X POST http://localhost:8000/screen \
  -H "Content-Type: application/json" \
  -d '{"address": "0x1234567890abcdef...", "chain": "ETH"}'
```

## 📁 Project Structure

```
ofac-crypto-screener/
├── ofac_screener/
│   ├── __init__.py
│   ├── __main__.py          # CLI entry point
│   ├── cli.py                # CLI commands
│   ├── api.py                # Flask REST API
│   ├── parser.py             # SDN XML parser
│   ├── screener.py           # Core screening logic
│   ├── matcher.py            # Fuzzy matching algorithms
│   ├── models.py             # Data models
│   └── config.py             # Configuration
├── tests/
│   ├── test_parser.py
│   ├── test_screener.py
│   └── test_api.py
├── data/                     # SDN data cache
├── requirements.txt
├── Dockerfile
├── docker-compose.yml
└── README.md
```

## 🔧 Configuration

Environment variables:
```bash
OFAC_SLS_URL=https://sanctionslist.ofac.treas.gov
SDN_CACHE_DIR=./data
FUZZY_THRESHOLD=2              # Levenshtein distance threshold
API_RATE_LIMIT=100             # Requests per minute
LOG_LEVEL=INFO
```

## ⚠️ Important Notes

### OFAC SLS Requirements
The Treasury Sanctions List Service (SLS) **requires a User-Agent HTTP header**. Requests without it receive 403 errors. This tool automatically includes the proper headers.

### Legal Considerations
- OFAC data is U.S. government-published with no copyright restrictions
- Building compliance tools is explicitly encouraged by regulators
- This tool aids compliance but does not constitute legal advice
- Consult with legal counsel for your specific compliance obligations


## 🤝 Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## 📄 License

MIT License - see [LICENSE](LICENSE) for details.

## 🔗 Related Projects

- [OpenSanctions](https://github.com/opensanctions/opensanctions) - Aggregated sanctions data
- [moov-io/watchman](https://github.com/moov-io/watchman) - SDN screening HTTP server
- [0xB10C/ofac-sanctioned-digital-currency-addresses](https://github.com/0xB10C/ofac-sanctioned-digital-currency-addresses) - SDN address extraction

## 📚 References

- [OFAC Sanctions List Service (SLS)](https://sanctionslist.ofac.treas.gov)
- [OFAC Virtual Currency Guidance (2021)](https://home.treasury.gov/policy-issues/financial-sanctions/recent-actions/20211015)
- [2024 National Strategy for Combating Terrorist and Other Illicit Financing](https://home.treasury.gov/system/files/136/2024-National-Strategy-for-Combating-Terrorist-and-Other-Illicit-Financing.pdf)
- [Bank Secrecy Act (31 U.S.C. §5311)](https://www.fincen.gov/resources/statutes-regulations/bank-secrecy-act)
