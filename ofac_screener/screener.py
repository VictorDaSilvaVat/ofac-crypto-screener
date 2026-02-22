"""
OFAC Crypto Screener - Main screening engine.

Combines SDN parsing, address matching, and risk assessment to provide
comprehensive sanctions screening for cryptocurrency wallet addresses.
"""

import logging
import time
from datetime import datetime
from pathlib import Path
from typing import List, Optional, Union

from .config import config
from .models import (
    SanctionedAddress,
    ScreeningResult,
    SDNStats,
    Chain,
    MatchType,
    RiskLevel,
)
from .parser import SDNParser
from .matcher import AddressMatcher

logger = logging.getLogger(__name__)


class OFACScreener:
    """
    Main OFAC cryptocurrency screening engine.
    
    Provides methods for:
    - Downloading and parsing OFAC SDN data
    - Screening individual or batch wallet addresses
    - Risk scoring based on match results
    
    Example:
        >>> screener = OFACScreener()
        >>> screener.update()  # Download latest SDN data
        >>> result = screener.screen("0x1234...")
        >>> print(result.risk_level)
    """
    
    def __init__(self, data_dir: Optional[Path] = None):
        """
        Initialize the OFAC screener.
        
        Args:
            data_dir: Directory for SDN data cache (default: ./data)
        """
        self.data_dir = data_dir or config.DATA_DIR
        self.parser = SDNParser(cache_dir=self.data_dir)
        self._matcher: Optional[AddressMatcher] = None
        self._initialized = False
    
    def update(self, force: bool = False) -> bool:
        """
        Download and parse the latest OFAC SDN data.
        
        Args:
            force: Force re-download even if cache exists
            
        Returns:
            True if successful, False otherwise
        """
        logger.info("Updating OFAC SDN data...")
        
        if not self.parser.download_sdn(force=force):
            logger.error("Failed to download SDN data")
            return False
        
        addresses = self.parser.parse()
        logger.info(f"Extracted {len(addresses)} crypto addresses from SDN")
        
        self._matcher = AddressMatcher(addresses)
        self._initialized = True
        
        return True
    
    def _ensure_initialized(self) -> None:
        """Ensure the screener is initialized with SDN data."""
        if not self._initialized:
            logger.info("Screener not initialized, loading SDN data...")
            addresses = self.parser.load_from_cache()
            
            if not addresses:
                raise RuntimeError(
                    "No SDN data available. Run update() first."
                )
            
            self._matcher = AddressMatcher(addresses)
            self._initialized = True
    
    def screen(
        self,
        address: str,
        chain: Optional[Union[Chain, str]] = None,
        include_fuzzy: bool = True,
    ) -> ScreeningResult:
        """
        Screen a cryptocurrency wallet address against OFAC SDN list.
        
        Args:
            address: Wallet address to screen
            chain: Blockchain network (optional, auto-detected if not provided)
            include_fuzzy: Include fuzzy matching results
            
        Returns:
            ScreeningResult with match details and risk assessment
        """
        self._ensure_initialized()
        
        start_time = time.time()
        
        # Normalize chain parameter
        if isinstance(chain, str):
            try:
                chain = Chain(chain.upper())
            except ValueError:
                chain = None
        
        # Auto-detect chain if not provided
        if chain is None:
            chain = self._matcher.detect_chain(address)
        
        # Perform matching
        exact_result, fuzzy_results = self._matcher.match(
            address,
            chain=chain,
            include_fuzzy=include_fuzzy,
        )
        
        # Build screening result
        screening_time = (time.time() - start_time) * 1000  # ms
        
        if exact_result.matched:
            return ScreeningResult(
                address=address,
                chain=chain,
                match_type=MatchType.EXACT,
                risk_level=RiskLevel.CRITICAL,
                confidence_score=1.0,
                matched_addresses=[exact_result.sanctioned_address],
                screening_time_ms=screening_time,
            )
        
        if fuzzy_results:
            # Take the closest fuzzy match
            best_fuzzy = fuzzy_results[0]
            return ScreeningResult(
                address=address,
                chain=chain,
                match_type=MatchType.FUZZY,
                risk_level=RiskLevel.HIGH,
                confidence_score=best_fuzzy.confidence,
                matched_addresses=[r.sanctioned_address for r in fuzzy_results[:5]],
                fuzzy_distance=best_fuzzy.distance,
                screening_time_ms=screening_time,
            )
        
        return ScreeningResult(
            address=address,
            chain=chain,
            match_type=MatchType.NO_MATCH,
            risk_level=RiskLevel.CLEAR,
            confidence_score=0.0,
            matched_addresses=[],
            screening_time_ms=screening_time,
        )
    
    def batch_screen(
        self,
        addresses: List[str],
        chain: Optional[Union[Chain, str]] = None,
        include_fuzzy: bool = True,
    ) -> List[ScreeningResult]:
        """
        Screen multiple addresses in batch.
        
        Args:
            addresses: List of wallet addresses
            chain: Blockchain network (optional)
            include_fuzzy: Include fuzzy matching
            
        Returns:
            List of ScreeningResults
        """
        return [
            self.screen(addr, chain=chain, include_fuzzy=include_fuzzy)
            for addr in addresses
        ]
    
    def get_sanctioned_addresses(
        self,
        chain: Optional[Chain] = None,
    ) -> List[SanctionedAddress]:
        """
        Get all sanctioned cryptocurrency addresses.
        
        Args:
            chain: Filter by blockchain network (optional)
            
        Returns:
            List of SanctionedAddress objects
        """
        self._ensure_initialized()
        
        addresses = self.parser.addresses
        
        if chain:
            addresses = [a for a in addresses if a.chain == chain]
        
        return addresses
    
    def get_stats(self) -> SDNStats:
        """
        Get statistics about the SDN data.
        
        Returns:
            SDNStats object with counts and metadata
        """
        self._ensure_initialized()
        return self.parser.stats
    
    def search_by_name(self, name: str) -> List[SanctionedAddress]:
        """
        Search sanctioned addresses by entity name.
        
        Args:
            name: Name or partial name to search
            
        Returns:
            List of matching SanctionedAddress objects
        """
        self._ensure_initialized()
        
        name_lower = name.lower()
        return [
            addr for addr in self.parser.addresses
            if name_lower in addr.name.lower()
        ]
    
    def search_by_program(self, program: str) -> List[SanctionedAddress]:
        """
        Search sanctioned addresses by sanctions program.
        
        Args:
            program: Program name (e.g., "IRAN", "CYBER2", "RUSSIA")
            
        Returns:
            List of matching SanctionedAddress objects
        """
        self._ensure_initialized()
        
        program_upper = program.upper()
        return [
            addr for addr in self.parser.addresses
            if program_upper in addr.program.upper()
        ]
