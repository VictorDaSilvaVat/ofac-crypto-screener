"""Configuration settings for OFAC Crypto Screener."""

import os
from pathlib import Path
from dataclasses import dataclass


@dataclass
class Config:
    """Application configuration."""
    
    # OFAC Sanctions List Service URLs
    SLS_BASE_URL: str = "https://sanctionslist.ofac.treas.gov"
    SDN_ADVANCED_XML: str = f"{SLS_BASE_URL}/api/PublicationPreview/exports/SDN_ADVANCED.XML"
    SDN_CSV: str = f"{SLS_BASE_URL}/api/PublicationPreview/exports/SDN.CSV"
    
    # Legacy URLs (still work via redirect)
    LEGACY_SDN_XML: str = "https://www.treasury.gov/ofac/downloads/sdn.xml"
    LEGACY_SDN_ADVANCED_XML: str = "https://www.treasury.gov/ofac/downloads/sdn_advanced.xml"
    
    # Data storage
    DATA_DIR: Path = Path(os.getenv("SDN_CACHE_DIR", "./data"))
    SDN_CACHE_FILE: str = "sdn_advanced.xml"
    ADDRESSES_CACHE_FILE: str = "sanctioned_addresses.json"
    
    # Screening settings
    FUZZY_THRESHOLD: int = int(os.getenv("FUZZY_THRESHOLD", "2"))
    
    # API settings
    API_HOST: str = os.getenv("API_HOST", "0.0.0.0")
    API_PORT: int = int(os.getenv("API_PORT", "8000"))
    API_RATE_LIMIT: int = int(os.getenv("API_RATE_LIMIT", "100"))
    
    # HTTP settings - IMPORTANT: SLS requires User-Agent header
    USER_AGENT: str = "OFAC-Crypto-Screener/0.1.0 (Compliance Tool)"
    REQUEST_TIMEOUT: int = 30
    
    # Logging
    LOG_LEVEL: str = os.getenv("LOG_LEVEL", "INFO")
    
    # Supported cryptocurrency chains
    SUPPORTED_CHAINS: list = None
    
    def __post_init__(self):
        self.SUPPORTED_CHAINS = [
            "BTC",   # Bitcoin
            "ETH",   # Ethereum
            "USDT",  # Tether (various chains)
            "XMR",   # Monero
            "TRX",   # Tron
            "LTC",   # Litecoin
            "XBT",   # Bitcoin (ISO code)
            "DASH",  # Dash
            "ZEC",   # Zcash
            "BSV",   # Bitcoin SV
            "BCH",   # Bitcoin Cash
        ]
        
        # Ensure data directory exists
        self.DATA_DIR.mkdir(parents=True, exist_ok=True)


# Global config instance
config = Config()
