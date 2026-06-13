"""Tests for OOB canary registry."""
import time

import pytest

from pwnproxy.shared.canary import CanaryRegistry, CanaryToken


class TestCanaryToken:
    def test_create_token(self):
        """Test creating a canary token."""
        token = CanaryToken(token="abc123", scan_id="scan-1")
        assert token.token == "abc123"
        assert token.scan_id == "scan-1"
        assert not token.callback_received
        assert token.callback_ip is None
    
    def test_token_not_expired_initially(self):
        """Test that new tokens are not expired."""
        token = CanaryToken(token="abc123", scan_id="scan-1")
        assert not token.is_expired
    
    def test_token_expired_after_timeout(self):
        """Test that tokens expire after 60 seconds."""
        token = CanaryToken(
            token="abc123",
            scan_id="scan-1",
            created_at=time.time() - 61,  # 61 seconds ago
        )
        assert token.is_expired


class TestCanaryRegistry:
    def test_create_canary(self):
        """Test creating a canary in the registry."""
        registry = CanaryRegistry()
        canary = registry.create("scan-1")
        
        assert canary.scan_id == "scan-1"
        assert len(canary.token) == 16  # 8 hex bytes = 16 chars
        assert len(registry) == 1
    
    def test_get_canary(self):
        """Test retrieving a canary by token."""
        registry = CanaryRegistry()
        canary = registry.create("scan-1")
        
        retrieved = registry.get(canary.token)
        assert retrieved is canary
    
    def test_get_unknown_canary(self):
        """Test retrieving unknown canary returns None."""
        registry = CanaryRegistry()
        assert registry.get("unknown") is None
    
    def test_mark_callback(self):
        """Test marking a canary as confirmed."""
        registry = CanaryRegistry()
        canary = registry.create("scan-1")
        
        result = registry.mark_callback(
            canary.token,
            ip="192.168.1.100",
            headers={"User-Agent": "test"},
        )
        
        assert result is True
        assert canary.callback_received
        assert canary.callback_ip == "192.168.1.100"
        assert canary.callback_headers == {"User-Agent": "test"}
    
    def test_mark_callback_unknown_token(self):
        """Test marking unknown canary returns False."""
        registry = CanaryRegistry()
        result = registry.mark_callback("unknown", ip="192.168.1.100")
        assert result is False
    
    def test_mark_callback_expired_token(self):
        """Test marking expired canary returns False."""
        registry = CanaryRegistry()
        canary = registry.create("scan-1")
        canary.created_at = time.time() - 61  # Expire it
        
        result = registry.mark_callback(canary.token, ip="192.168.1.100")
        assert result is False
        assert not canary.callback_received
    
    def test_cleanup_expired(self):
        """Test cleaning up expired canaries."""
        registry = CanaryRegistry()
        
        # Create active canary
        active = registry.create("scan-1")
        
        # Create expired canary
        expired = registry.create("scan-2")
        expired.created_at = time.time() - 61
        
        assert len(registry) == 2
        
        removed = registry.cleanup_expired()
        
        assert removed == 1
        assert len(registry) == 1
        assert registry.get(active.token) is active
        assert registry.get(expired.token) is None
    
    def test_list_active(self):
        """Test listing active canaries."""
        registry = CanaryRegistry()
        
        active1 = registry.create("scan-1")
        active2 = registry.create("scan-2")
        
        expired = registry.create("scan-3")
        expired.created_at = time.time() - 61
        
        active_list = registry.list_active()
        
        assert len(active_list) == 2
        assert active1 in active_list
        assert active2 in active_list
        assert expired not in active_list
