import asyncio
import pytest
from unittest.mock import MagicMock

from pwnproxy.plugins.core.chain import (
    DetectionDepth, DetectionStage, StageResult,
    DetectionChain, BudgetChain, chain_from_depth,
)
from pwnproxy.shared.models import Flow
from pwnproxy.shared.scan.params import InjectionPoint

@pytest.fixture
def flow():
    return Flow(id="test", method="GET", url="http://test.com", request_headers={})

@pytest.fixture
def points():
    p = MagicMock(spec=InjectionPoint)
    p.key = ("GET", "test.com/", "q", "query")
    return [p]

@pytest.mark.asyncio
async def test_budget_chain_escalates_when_fast_finds_nothing(flow, points):
    fast_stage = MagicMock(spec=DetectionStage)
    fast_stage.order = 0
    fast_stage.min_depth = DetectionDepth.FAST
    fast_stage.should_run.return_value = True
    fast_stage.execute.return_value = StageResult(findings=[], confirmed_points=set())

    standard_stage = MagicMock(spec=DetectionStage)
    standard_stage.order = 1
    standard_stage.min_depth = DetectionDepth.STANDARD
    standard_stage.should_run.return_value = True
    from pwnproxy.plugins.core.base import Finding
    f = Finding(scanner="test", url="http://test.com", method="GET", param_name="q", param_location="query", technique="test", severity="low", confidence="tentative", payload="", evidence="")
    standard_stage.execute.return_value = StageResult(findings=[f], confirmed_points={points[0].key})

    chain = BudgetChain([fast_stage, standard_stage], depth=DetectionDepth.FAST, max_depth=DetectionDepth.STANDARD, budget_ms=30000)
    results = []
    async for finding in chain.run(flow, points):
        results.append(finding)

    assert len(results) == 1
    fast_stage.execute.assert_called_once()
    standard_stage.execute.assert_called_once()

@pytest.mark.asyncio
async def test_budget_chain_stops_when_all_confirmed(flow, points):
    from pwnproxy.plugins.core.base import Finding
    f = Finding(scanner="test", url="http://test.com", method="GET", param_name="q", param_location="query", technique="test", severity="low", confidence="tentative", payload="", evidence="")
    fast_stage = MagicMock(spec=DetectionStage)
    fast_stage.order = 0
    fast_stage.min_depth = DetectionDepth.FAST
    fast_stage.should_run.return_value = True
    fast_stage.execute.return_value = StageResult(findings=[f], confirmed_points={points[0].key})

    standard_stage = MagicMock(spec=DetectionStage)
    standard_stage.order = 1
    standard_stage.min_depth = DetectionDepth.STANDARD
    standard_stage.should_run.return_value = True

    chain = BudgetChain([fast_stage, standard_stage], depth=DetectionDepth.FAST, max_depth=DetectionDepth.STANDARD, budget_ms=30000)
    results = []
    async for finding in chain.run(flow, points):
        results.append(finding)

    assert len(results) == 1
    fast_stage.execute.assert_called_once()
    standard_stage.execute.assert_not_called()

@pytest.mark.asyncio
async def test_chain_from_depth_maps_depth(flow, points):
    stage = MagicMock(spec=DetectionStage)
    stage.min_depth = DetectionDepth.FAST
    stage.should_run.return_value = True
    stage.execute.return_value = StageResult(findings=[], confirmed_points=set())

    chain = chain_from_depth([stage], depth="fast", budget_ms=5000)
    assert isinstance(chain, BudgetChain)
    assert chain._budget_ms == 5000

@pytest.mark.asyncio
async def test_budget_chain_depth_limits_waves():
    fast_stage = MagicMock(spec=DetectionStage)
    fast_stage.order = 0
    fast_stage.min_depth = DetectionDepth.FAST
    fast_stage.should_run.return_value = True
    fast_stage.execute.return_value = StageResult(findings=[], confirmed_points=set())
    standard_stage = MagicMock(spec=DetectionStage)
    standard_stage.order = 1
    standard_stage.min_depth = DetectionDepth.STANDARD
    standard_stage.should_run.return_value = True

    chain = BudgetChain([fast_stage, standard_stage], depth=DetectionDepth.FAST, max_depth=DetectionDepth.FAST, budget_ms=30000)
    # dummy injection point
    point = MagicMock(spec=InjectionPoint)
    point.key = ("GET", "t.com/", "q", "query")
    results = []
    async for finding in chain.run(
        Flow(id="t", method="GET", url="http://t.com", request_headers={}),
        [point]
    ):
        results.append(finding)

    fast_stage.execute.assert_called_once()
    standard_stage.execute.assert_not_called()
