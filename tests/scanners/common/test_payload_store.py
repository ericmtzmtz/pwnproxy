"""Tests for payload store (second-order detection)."""
from pwnproxy.services.scan.payload_store import PayloadStore, get_store


class TestPayloadStore:
    def test_store_payload(self):
        """Test storing a payload."""
        store = PayloadStore()
        store.store(
            url="http://example.com/profile",
            param_name="name",
            param_location="body",
            payload="<script>alert(1)</script>",
        )
        assert len(store) == 1
        payloads = store.get_payloads("http://example.com/profile")
        assert len(payloads) == 1
        assert payloads[0].payload == "<script>alert(1)</script>"
    
    def test_store_multiple_payloads(self):
        """Test storing multiple payloads for same URL."""
        store = PayloadStore()
        store.store("http://example.com/search", "q", "query", "test1")
        store.store("http://example.com/search", "q", "query", "test2")
        assert len(store) == 2
        payloads = store.get_payloads("http://example.com/search")
        assert len(payloads) == 2
    
    def test_get_untriggered(self):
        """Test getting untriggered payloads."""
        store = PayloadStore()
        store.store("http://example.com/page", "id", "query", "payload1")
        store.store("http://example.com/page", "id", "query", "payload2")
        
        untriggered = store.get_all_untriggered()
        assert len(untriggered) == 2
    
    def test_mark_triggered(self):
        """Test marking a payload as triggered."""
        store = PayloadStore()
        store.store("http://example.com/page", "id", "query", "payload1")
        
        store.mark_triggered("http://example.com/page", "payload1", "found")
        
        payloads = store.get_payloads("http://example.com/page")
        assert payloads[0].triggered
        assert payloads[0].trigger_result == "found"
        
        untriggered = store.get_all_untriggered()
        assert len(untriggered) == 0
    
    def test_url_normalization(self):
        """Test URL normalization removes hashes and trailing slashes."""
        store = PayloadStore()
        store.store("http://example.com/page/", "id", "query", "test")
        store.store("http://example.com/page", "id", "query", "test2")
        
        # Both should be under same key
        payloads = store.get_payloads("http://example.com/page")
        assert len(payloads) == 2
    
    def test_clear(self):
        """Test clearing all payloads."""
        store = PayloadStore()
        store.store("http://example.com/a", "x", "query", "test1")
        store.store("http://example.com/b", "y", "query", "test2")
        assert len(store) == 2
        
        store.clear()
        assert len(store) == 0
    
    def test_stats(self):
        """Test statistics."""
        store = PayloadStore()
        store.store("http://example.com/a", "x", "query", "payload1")
        store.store("http://example.com/a", "x", "query", "payload2")
        store.mark_triggered("http://example.com/a", "payload1")
        
        stats = store.stats()
        assert stats["total_stored"] == 2
        assert stats["triggered"] == 1
        assert stats["pending"] == 1
        assert stats["urls_tracked"] == 1


class TestGlobalStore:
    def test_singleton(self):
        """Test get_store returns same instance."""
        s1 = get_store()
        s2 = get_store()
        assert s1 is s2
