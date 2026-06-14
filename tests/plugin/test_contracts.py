import pytest
from unittest.mock import AsyncMock

from pwnproxy.plugins.core.contracts import (
    FlowConsumer,
    FindingConsumer,
    SurfaceConsumer,
    EvidenceConsumer,
)


class MockFlowConsumer(FlowConsumer):
    async def on_flow(self, flow):
        return f"processed_{flow}"


class MockFindingConsumer(FindingConsumer):
    async def on_finding(self, finding):
        return f"analyzed_{finding}"


class MockSurfaceConsumer(SurfaceConsumer):
    async def on_surface(self, surface):
        return f"mapped_{surface}"


class MockEvidenceConsumer(EvidenceConsumer):
    async def on_evidence(self, evidence):
        return f"verified_{evidence}"


class TestFlowConsumer:
    @pytest.mark.asyncio
    async def test_consumes_attribute(self):
        consumer = MockFlowConsumer()
        assert consumer.consumes == ["flow"]

    @pytest.mark.asyncio
    async def test_on_flow_method(self):
        consumer = MockFlowConsumer()
        result = await consumer.on_flow("test_flow")
        assert result == "processed_test_flow"


class TestFindingConsumer:
    @pytest.mark.asyncio
    async def test_consumes_attribute(self):
        consumer = MockFindingConsumer()
        assert consumer.consumes == ["finding"]

    @pytest.mark.asyncio
    async def test_on_finding_method(self):
        consumer = MockFindingConsumer()
        result = await consumer.on_finding("test_finding")
        assert result == "analyzed_test_finding"


class TestSurfaceConsumer:
    @pytest.mark.asyncio
    async def test_consumes_attribute(self):
        consumer = MockSurfaceConsumer()
        assert consumer.consumes == ["surface"]

    @pytest.mark.asyncio
    async def test_on_surface_method(self):
        consumer = MockSurfaceConsumer()
        result = await consumer.on_surface("test_surface")
        assert result == "mapped_test_surface"


class TestEvidenceConsumer:
    @pytest.mark.asyncio
    async def test_consumes_attribute(self):
        consumer = MockEvidenceConsumer()
        assert consumer.consumes == ["evidence"]

    @pytest.mark.asyncio
    async def test_on_evidence_method(self):
        consumer = MockEvidenceConsumer()
        result = await consumer.on_evidence("test_evidence")
        assert result == "verified_test_evidence"


class TestContractDuckTyping:
    """Test that contract mixins are optional - duck typing still works without inheritance"""
    
    @pytest.mark.asyncio
    async def test_duck_typing_flow_consumer(self):
        class DuckFlowConsumer:
            consumes = ["flow"]
            
            async def on_flow(self, flow):
                return f"duck_processed_{flow}"
        
        consumer = DuckFlowConsumer()
        assert consumer.consumes == ["flow"]
        result = await consumer.on_flow("test_flow")
        assert result == "duck_processed_test_flow"
    
    @pytest.mark.asyncio
    async def test_duck_typing_finding_consumer(self):
        class DuckFindingConsumer:
            consumes = ["finding"]
            
            async def on_finding(self, finding):
                return f"duck_analyzed_{finding}"
        
        consumer = DuckFindingConsumer()
        assert consumer.consumes == ["finding"]
        result = await consumer.on_finding("test_finding")
        assert result == "duck_analyzed_test_finding"