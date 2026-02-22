"""
SDN XML Parser - Extract cryptocurrency addresses from OFAC SDN_ADVANCED.XML

The OFAC Sanctions List Service (SLS) provides SDN data in multiple formats.
This parser handles the SDN_ADVANCED.XML format which contains Digital Currency
Address records with cryptocurrency wallet addresses.

IMPORTANT: Treasury SLS requires a User-Agent HTTP header. Requests without it
receive 403 Forbidden errors.
"""

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import List, Optional, Generator
from xml.etree import ElementTree as ET

import requests
from lxml import etree

from .config import config
from .models import SanctionedAddress, Chain, SDNStats

logger = logging.getLogger(__name__)

# XML namespaces used in SDN_ADVANCED.XML
NAMESPACES = {
    "sdn": "http://www.un.org/sanctions/1.0",
}


class SDNParser:
    """
    Parser for OFAC SDN_ADVANCED.XML files.
    
    Extracts Digital Currency Address records containing cryptocurrency
    wallet addresses of sanctioned entities.
    """
    
    def __init__(self, cache_dir: Optional[Path] = None):
        """
        Initialize the SDN parser.
        
        Args:
            cache_dir: Directory for caching SDN data files
        """
        self.cache_dir = cache_dir or config.DATA_DIR
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self._addresses: List[SanctionedAddress] = []
        self._stats: Optional[SDNStats] = None
    
    @property
    def sdn_file_path(self) -> Path:
        """Path to cached SDN XML file."""
        return self.cache_dir / config.SDN_CACHE_FILE
    
    @property
    def addresses_cache_path(self) -> Path:
        """Path to cached addresses JSON file."""
        return self.cache_dir / config.ADDRESSES_CACHE_FILE
    
    def download_sdn(self, force: bool = False) -> bool:
        """
        Download SDN_ADVANCED.XML from Treasury SLS.
        
        Args:
            force: Force download even if cache exists
            
        Returns:
            True if download successful, False otherwise
        """
        if self.sdn_file_path.exists() and not force:
            logger.info(f"Using cached SDN file: {self.sdn_file_path}")
            return True
        
        logger.info(f"Downloading SDN data from {config.SDN_ADVANCED_XML}")
        
        headers = {
            "User-Agent": config.USER_AGENT,  # REQUIRED by SLS
            "Accept": "application/xml",
        }
        
        try:
            response = requests.get(
                config.SDN_ADVANCED_XML,
                headers=headers,
                timeout=config.REQUEST_TIMEOUT,
            )
            response.raise_for_status()
            
            # Save to cache
            self.sdn_file_path.write_bytes(response.content)
            logger.info(f"SDN data saved to {self.sdn_file_path} ({len(response.content)} bytes)")
            
            return True
            
        except requests.RequestException as e:
            logger.error(f"Failed to download SDN data: {e}")
            
            # Try legacy URL as fallback
            try:
                logger.info("Trying legacy URL...")
                response = requests.get(
                    config.LEGACY_SDN_ADVANCED_XML,
                    headers=headers,
                    timeout=config.REQUEST_TIMEOUT,
                )
                response.raise_for_status()
                self.sdn_file_path.write_bytes(response.content)
                logger.info(f"SDN data saved from legacy URL")
                return True
            except Exception as e2:
                logger.error(f"Legacy URL also failed: {e2}")
                return False
    
    def parse(self) -> List[SanctionedAddress]:
        """
        Parse the SDN XML file and extract cryptocurrency addresses.
        
        Returns:
            List of SanctionedAddress objects
        """
        if not self.sdn_file_path.exists():
            raise FileNotFoundError(
                f"SDN file not found: {self.sdn_file_path}. "
                "Run download_sdn() first."
            )
        
        logger.info(f"Parsing SDN file: {self.sdn_file_path}")
        
        self._addresses = []
        self._stats = SDNStats(
            file_size_bytes=self.sdn_file_path.stat().st_size,
            last_updated=datetime.fromtimestamp(
                self.sdn_file_path.stat().st_mtime
            ),
        )
        
        # Use lxml for efficient parsing of large XML files
        context = etree.iterparse(
            str(self.sdn_file_path),
            events=("end",),
            tag="{http://www.un.org/sanctions/1.0}sdnEntry",
        )
        
        for event, elem in context:
            self._stats.total_entries += 1
            self._process_sdn_entry(elem)
            elem.clear()  # Free memory
        
        # Update stats
        self._stats.crypto_addresses = len(self._addresses)
        
        # Cache extracted addresses
        self._save_addresses_cache()
        
        logger.info(
            f"Parsed {self._stats.total_entries} entries, "
            f"found {self._stats.crypto_addresses} crypto addresses"
        )
        
        return self._addresses
    
    def _process_sdn_entry(self, entry: etree._Element) -> None:
        """Process a single SDN entry and extract crypto addresses."""
        ns = {"sdn": "http://www.un.org/sanctions/1.0"}
        
        # Get entry metadata
        uid_elem = entry.find(".//sdn:uid", ns)
        uid = uid_elem.text if uid_elem is not None else "UNKNOWN"
        
        # Get primary name
        name_elem = entry.find(".//sdn:firstName", ns)
        lastname_elem = entry.find(".//sdn:lastName", ns)
        
        if lastname_elem is not None:
            name = lastname_elem.text or ""
            if name_elem is not None and name_elem.text:
                name = f"{name_elem.text} {name}"
        else:
            name = "UNKNOWN"
        
        # Get programs
        programs = []
        for prog in entry.findall(".//sdn:program", ns):
            if prog.text:
                programs.append(prog.text)
        program = ", ".join(programs) if programs else "UNKNOWN"
        
        # Find Digital Currency Addresses
        # They are typically in <id> elements with idType containing "Digital Currency Address"
        for id_elem in entry.findall(".//sdn:id", ns):
            id_type_elem = id_elem.find("sdn:idType", ns)
            id_number_elem = id_elem.find("sdn:idNumber", ns)
            
            if id_type_elem is None or id_number_elem is None:
                continue
            
            id_type = id_type_elem.text or ""
            
            # Check if this is a crypto address
            if "Digital Currency Address" in id_type:
                # Extract chain from idType (e.g., "Digital Currency Address - XBT")
                chain = self._extract_chain(id_type)
                address = id_number_elem.text
                
                if address:
                    sanctioned = SanctionedAddress(
                        address=address.strip(),
                        chain=chain,
                        uid=uid,
                        name=name.strip(),
                        program=program,
                    )
                    self._addresses.append(sanctioned)
                    
                    # Update stats
                    chain_key = chain.value
                    self._stats.by_chain[chain_key] = (
                        self._stats.by_chain.get(chain_key, 0) + 1
                    )
                    
                    for prog in programs:
                        self._stats.by_program[prog] = (
                            self._stats.by_program.get(prog, 0) + 1
                        )
    
    def _extract_chain(self, id_type: str) -> Chain:
        """Extract blockchain chain from ID type string."""
        id_type_upper = id_type.upper()
        
        for chain in Chain:
            if chain.value in id_type_upper:
                return chain
        
        # Check for common variations
        if "BITCOIN" in id_type_upper:
            return Chain.BTC
        if "ETHEREUM" in id_type_upper:
            return Chain.ETH
        if "TETHER" in id_type_upper:
            return Chain.USDT
        if "TRON" in id_type_upper:
            return Chain.TRX
        if "MONERO" in id_type_upper:
            return Chain.XMR
        
        return Chain.UNKNOWN
    
    def _save_addresses_cache(self) -> None:
        """Save extracted addresses to JSON cache."""
        cache_data = {
            "extracted_at": datetime.utcnow().isoformat(),
            "count": len(self._addresses),
            "addresses": [
                {
                    "address": addr.address,
                    "chain": addr.chain.value,
                    "uid": addr.uid,
                    "name": addr.name,
                    "program": addr.program,
                }
                for addr in self._addresses
            ],
        }
        
        self.addresses_cache_path.write_text(
            json.dumps(cache_data, indent=2)
        )
    
    def load_from_cache(self) -> List[SanctionedAddress]:
        """Load addresses from JSON cache if available."""
        if not self.addresses_cache_path.exists():
            return self.parse()
        
        logger.info(f"Loading addresses from cache: {self.addresses_cache_path}")
        
        data = json.loads(self.addresses_cache_path.read_text())
        
        self._addresses = [
            SanctionedAddress(
                address=a["address"],
                chain=Chain(a["chain"]),
                uid=a["uid"],
                name=a["name"],
                program=a["program"],
            )
            for a in data["addresses"]
        ]
        
        return self._addresses
    
    @property
    def addresses(self) -> List[SanctionedAddress]:
        """Get parsed addresses, loading from cache if needed."""
        if not self._addresses:
            self._addresses = self.load_from_cache()
        return self._addresses
    
    @property
    def stats(self) -> SDNStats:
        """Get SDN statistics."""
        if not self._stats:
            self.parse()
        return self._stats
