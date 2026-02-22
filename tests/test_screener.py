"""Tests for OFAC Crypto Screener."""

import pytest
from ofac_screener.models import Chain, MatchType, RiskLevel, SanctionedAddress
from ofac_screener.matcher import AddressMatcher, MatchResult


class TestAddressMatcher:
    """Test suite for AddressMatcher."""
    
    @pytest.fixture
    def sample_addresses(self):
        """Sample sanctioned addresses for testing."""
        return [
            SanctionedAddress(
                address="0x1234567890abcdef1234567890abcdef12345678",
                chain=Chain.ETH,
                uid="OFAC-12345",
                name="Test Entity 1",
                program="CYBER2",
            ),
            SanctionedAddress(
                address="bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh",
                chain=Chain.BTC,
                uid="OFAC-12346",
                name="Test Entity 2",
                program="IRAN",
            ),
            SanctionedAddress(
                address="TNVTkMf5JJGpzKmCW8bxv7eVdH4EBbPGAp",
                chain=Chain.TRX,
                uid="OFAC-12347",
                name="Test Entity 3",
                program="RUSSIA",
            ),
        ]
    
    @pytest.fixture
    def matcher(self, sample_addresses):
        """Create matcher with sample addresses."""
        return AddressMatcher(sample_addresses)
    
    def test_exact_match_found(self, matcher):
        """Test exact match detection."""
        result = matcher.exact_match(
            "0x1234567890abcdef1234567890abcdef12345678",
            chain=Chain.ETH
        )
        
        assert result.matched is True
        assert result.match_type == "exact"
        assert result.sanctioned_address is not None
        assert result.sanctioned_address.uid == "OFAC-12345"
    
    def test_exact_match_case_insensitive_eth(self, matcher):
        """Test ETH addresses are matched case-insensitively."""
        result = matcher.exact_match(
            "0x1234567890ABCDEF1234567890ABCDEF12345678",
            chain=Chain.ETH
        )
        
        assert result.matched is True
    
    def test_exact_match_not_found(self, matcher):
        """Test no match for unknown address."""
        result = matcher.exact_match(
            "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
            chain=Chain.ETH
        )
        
        assert result.matched is False
        assert result.match_type == "none"
    
    def test_fuzzy_match(self, matcher):
        """Test fuzzy matching."""
        # Address with 1 character difference
        results = matcher.fuzzy_match(
            "0x1234567890abcdef1234567890abcdef12345679",  # Last char different
            chain=Chain.ETH,
            threshold=2
        )
        
        assert len(results) > 0
        assert results[0].match_type == "fuzzy"
        assert results[0].distance == 1
    
    def test_chain_detection_eth(self, matcher):
        """Test Ethereum address detection."""
        chain = matcher.detect_chain("0x1234567890abcdef1234567890abcdef12345678")
        assert chain == Chain.ETH
    
    def test_chain_detection_btc(self, matcher):
        """Test Bitcoin address detection."""
        chain = matcher.detect_chain("bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh")
        assert chain == Chain.BTC
    
    def test_chain_detection_tron(self, matcher):
        """Test Tron address detection."""
        chain = matcher.detect_chain("TNVTkMf5JJGpzKmCW8bxv7eVdH4EBbPGAp")
        assert chain == Chain.TRX


class TestScreeningResult:
    """Test ScreeningResult model."""
    
    def test_to_dict(self):
        """Test serialization to dictionary."""
        from ofac_screener.models import ScreeningResult
        from datetime import datetime
        
        result = ScreeningResult(
            address="0x1234",
            chain=Chain.ETH,
            match_type=MatchType.NO_MATCH,
            risk_level=RiskLevel.CLEAR,
        )
        
        data = result.to_dict()
        
        assert data["address"] == "0x1234"
        assert data["chain"] == "ETH"
        assert data["match_type"] == "no_match"
        assert data["risk_level"] == "clear"


class TestSanctionedAddress:
    """Test SanctionedAddress model."""
    
    def test_equality(self):
        """Test address equality comparison."""
        addr1 = SanctionedAddress(
            address="0x1234",
            chain=Chain.ETH,
            uid="1",
            name="Test",
            program="TEST"
        )
        addr2 = SanctionedAddress(
            address="0x1234",
            chain=Chain.ETH,
            uid="2",
            name="Test 2",
            program="TEST2"
        )
        
        assert addr1 == addr2  # Same address and chain
    
    def test_hash(self):
        """Test address hashing for set usage."""
        addr1 = SanctionedAddress(
            address="0x1234",
            chain=Chain.ETH,
            uid="1",
            name="Test",
            program="TEST"
        )
        addr2 = SanctionedAddress(
            address="0x1234",
            chain=Chain.ETH,
            uid="2",
            name="Test 2",
            program="TEST2"
        )
        
        addresses = {addr1, addr2}
        assert len(addresses) == 1  # Same address, should dedupe
