"""Data models for OFAC Crypto Screener."""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional, List


class Chain(Enum):
    """Supported blockchain networks."""
    BTC = "BTC"
    ETH = "ETH"
    USDT = "USDT"
    XMR = "XMR"
    TRX = "TRX"
    LTC = "LTC"
    XBT = "XBT"
    DASH = "DASH"
    ZEC = "ZEC"
    BSV = "BSV"
    BCH = "BCH"
    UNKNOWN = "UNKNOWN"


class MatchType(Enum):
    """Type of match found during screening."""
    EXACT = "exact"
    FUZZY = "fuzzy"
    NO_MATCH = "no_match"


class RiskLevel(Enum):
    """Risk level classification."""
    CRITICAL = "critical"    # Exact OFAC match
    HIGH = "high"            # Fuzzy match or related address
    MEDIUM = "medium"        # Indirect connection
    LOW = "low"              # Minor flags
    CLEAR = "clear"          # No matches


@dataclass
class SanctionedAddress:
    """A cryptocurrency address from the OFAC SDN list."""
    
    address: str
    chain: Chain
    uid: str                          # OFAC UID (e.g., "OFAC-12345")
    name: str                         # Sanctioned entity name
    program: str                      # Sanctions program (e.g., "IRAN", "CYBER2")
    added_date: Optional[datetime] = None
    remarks: Optional[str] = None
    
    def __hash__(self):
        return hash((self.address.lower(), self.chain))
    
    def __eq__(self, other):
        if not isinstance(other, SanctionedAddress):
            return False
        return (self.address.lower() == other.address.lower() and 
                self.chain == other.chain)


@dataclass
class ScreeningResult:
    """Result of screening a wallet address."""
    
    address: str
    chain: Chain
    timestamp: datetime = field(default_factory=datetime.utcnow)
    match_type: MatchType = MatchType.NO_MATCH
    risk_level: RiskLevel = RiskLevel.CLEAR
    confidence_score: float = 0.0
    matched_addresses: List[SanctionedAddress] = field(default_factory=list)
    fuzzy_distance: Optional[int] = None
    screening_time_ms: float = 0.0
    
    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        return {
            "address": self.address,
            "chain": self.chain.value,
            "timestamp": self.timestamp.isoformat(),
            "match_type": self.match_type.value,
            "risk_level": self.risk_level.value,
            "confidence_score": self.confidence_score,
            "matched_addresses": [
                {
                    "address": m.address,
                    "chain": m.chain.value,
                    "uid": m.uid,
                    "name": m.name,
                    "program": m.program,
                }
                for m in self.matched_addresses
            ],
            "fuzzy_distance": self.fuzzy_distance,
            "screening_time_ms": self.screening_time_ms,
        }


@dataclass
class SDNStats:
    """Statistics about the SDN list."""
    
    total_entries: int = 0
    crypto_addresses: int = 0
    by_chain: dict = field(default_factory=dict)
    by_program: dict = field(default_factory=dict)
    last_updated: Optional[datetime] = None
    file_size_bytes: int = 0
    
    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        return {
            "total_entries": self.total_entries,
            "crypto_addresses": self.crypto_addresses,
            "by_chain": self.by_chain,
            "by_program": self.by_program,
            "last_updated": self.last_updated.isoformat() if self.last_updated else None,
            "file_size_bytes": self.file_size_bytes,
        }
