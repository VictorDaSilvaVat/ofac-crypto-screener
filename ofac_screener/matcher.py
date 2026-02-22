"""
Fuzzy matching algorithms for cryptocurrency address screening.

Provides exact matching, Levenshtein distance-based fuzzy matching, and
pattern-based matching for detecting potential sanctions evasion attempts.
"""

import logging
from typing import List, Tuple, Optional
from dataclasses import dataclass

try:
    from Levenshtein import distance as levenshtein_distance
except ImportError:
    # Fallback implementation if python-Levenshtein not available
    def levenshtein_distance(s1: str, s2: str) -> int:
        if len(s1) < len(s2):
            return levenshtein_distance(s2, s1)
        if len(s2) == 0:
            return len(s1)
        
        previous_row = range(len(s2) + 1)
        for i, c1 in enumerate(s1):
            current_row = [i + 1]
            for j, c2 in enumerate(s2):
                insertions = previous_row[j + 1] + 1
                deletions = current_row[j] + 1
                substitutions = previous_row[j] + (c1 != c2)
                current_row.append(min(insertions, deletions, substitutions))
            previous_row = current_row
        
        return previous_row[-1]

from .config import config
from .models import SanctionedAddress, Chain

logger = logging.getLogger(__name__)


@dataclass
class MatchResult:
    """Result of a matching operation."""
    matched: bool
    sanctioned_address: Optional[SanctionedAddress]
    match_type: str  # "exact", "fuzzy", "none"
    distance: int = 0
    confidence: float = 1.0


class AddressMatcher:
    """
    Cryptocurrency address matching engine.
    
    Supports exact matching, fuzzy matching (Levenshtein distance),
    and various normalization strategies for different blockchain networks.
    """
    
    def __init__(
        self,
        sanctioned_addresses: List[SanctionedAddress],
        fuzzy_threshold: int = None,
    ):
        """
        Initialize the matcher with sanctioned addresses.
        
        Args:
            sanctioned_addresses: List of OFAC-sanctioned addresses
            fuzzy_threshold: Maximum Levenshtein distance for fuzzy matches
        """
        self.fuzzy_threshold = fuzzy_threshold or config.FUZZY_THRESHOLD
        
        # Index addresses by chain for faster lookup
        self._addresses_by_chain: dict = {}
        self._all_addresses: set = set()
        
        for addr in sanctioned_addresses:
            normalized = self._normalize_address(addr.address, addr.chain)
            self._all_addresses.add(normalized)
            
            if addr.chain not in self._addresses_by_chain:
                self._addresses_by_chain[addr.chain] = {}
            
            self._addresses_by_chain[addr.chain][normalized] = addr
        
        logger.info(
            f"Initialized matcher with {len(sanctioned_addresses)} addresses "
            f"across {len(self._addresses_by_chain)} chains"
        )
    
    def _normalize_address(self, address: str, chain: Chain) -> str:
        """
        Normalize address for consistent matching.
        
        Different blockchains have different address formats:
        - ETH/USDT(ERC20): Case-insensitive hex, checksum encoding
        - BTC: Case-sensitive base58check
        - XMR: Base58, variable length
        - TRX: Base58check, starts with 'T'
        """
        address = address.strip()
        
        if chain in (Chain.ETH, Chain.USDT):
            # Ethereum addresses are case-insensitive (except checksum)
            return address.lower()
        elif chain == Chain.TRX:
            # Tron addresses are base58, case-sensitive but normalize anyway
            return address
        elif chain in (Chain.BTC, Chain.XBT):
            # Bitcoin addresses are case-sensitive
            return address
        else:
            # Default: lowercase
            return address.lower()
    
    def exact_match(
        self,
        address: str,
        chain: Optional[Chain] = None,
    ) -> MatchResult:
        """
        Check for exact match against sanctioned addresses.
        
        Args:
            address: Wallet address to check
            chain: Blockchain network (optional, checks all if None)
            
        Returns:
            MatchResult with match details
        """
        chains_to_check = [chain] if chain else list(self._addresses_by_chain.keys())
        
        for c in chains_to_check:
            if c not in self._addresses_by_chain:
                continue
                
            normalized = self._normalize_address(address, c)
            
            if normalized in self._addresses_by_chain[c]:
                return MatchResult(
                    matched=True,
                    sanctioned_address=self._addresses_by_chain[c][normalized],
                    match_type="exact",
                    distance=0,
                    confidence=1.0,
                )
        
        return MatchResult(
            matched=False,
            sanctioned_address=None,
            match_type="none",
        )
    
    def fuzzy_match(
        self,
        address: str,
        chain: Optional[Chain] = None,
        threshold: Optional[int] = None,
    ) -> List[MatchResult]:
        """
        Find fuzzy matches using Levenshtein distance.
        
        Args:
            address: Wallet address to check
            chain: Blockchain network (optional)
            threshold: Maximum edit distance (default: config value)
            
        Returns:
            List of MatchResults sorted by distance
        """
        threshold = threshold if threshold is not None else self.fuzzy_threshold
        chains_to_check = [chain] if chain else list(self._addresses_by_chain.keys())
        
        matches = []
        
        for c in chains_to_check:
            if c not in self._addresses_by_chain:
                continue
            
            normalized = self._normalize_address(address, c)
            
            for sanctioned_addr, sanctioned_obj in self._addresses_by_chain[c].items():
                dist = levenshtein_distance(normalized, sanctioned_addr)
                
                if dist <= threshold and dist > 0:  # Exclude exact matches
                    # Calculate confidence based on distance and address length
                    max_len = max(len(normalized), len(sanctioned_addr))
                    confidence = 1.0 - (dist / max_len)
                    
                    matches.append(MatchResult(
                        matched=True,
                        sanctioned_address=sanctioned_obj,
                        match_type="fuzzy",
                        distance=dist,
                        confidence=confidence,
                    ))
        
        # Sort by distance (closest first)
        matches.sort(key=lambda m: (m.distance, -m.confidence))
        
        return matches
    
    def match(
        self,
        address: str,
        chain: Optional[Chain] = None,
        include_fuzzy: bool = True,
    ) -> Tuple[MatchResult, List[MatchResult]]:
        """
        Perform comprehensive matching (exact + fuzzy).
        
        Args:
            address: Wallet address to check
            chain: Blockchain network (optional)
            include_fuzzy: Whether to include fuzzy matches
            
        Returns:
            Tuple of (exact_result, list of fuzzy_results)
        """
        # Check exact match first
        exact = self.exact_match(address, chain)
        
        if exact.matched:
            return exact, []
        
        # Check fuzzy matches if enabled
        fuzzy_matches = []
        if include_fuzzy:
            fuzzy_matches = self.fuzzy_match(address, chain)
        
        return exact, fuzzy_matches
    
    def detect_chain(self, address: str) -> Chain:
        """
        Attempt to detect blockchain network from address format.
        
        Args:
            address: Wallet address
            
        Returns:
            Detected Chain or UNKNOWN
        """
        address = address.strip()
        
        # Ethereum (0x prefix, 40 hex chars)
        if address.startswith("0x") and len(address) == 42:
            try:
                int(address[2:], 16)
                return Chain.ETH
            except ValueError:
                pass
        
        # Tron (T prefix, 34 chars)
        if address.startswith("T") and len(address) == 34:
            return Chain.TRX
        
        # Bitcoin (1, 3, or bc1 prefix)
        if len(address) >= 26 and len(address) <= 62:
            if address.startswith("1") or address.startswith("3"):
                return Chain.BTC
            if address.startswith("bc1"):
                return Chain.BTC
        
        # Monero (4 prefix, 95 or 106 chars)
        if address.startswith("4") and len(address) in (95, 106):
            return Chain.XMR
        
        return Chain.UNKNOWN
