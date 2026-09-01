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
async def test_budget_chain_passes_deadline_to_stage(flow, points):
    stage = MagicMock(spec=DetectionStage)
    stage.min_depth = DetectionDepth.FAST
    stage.should_run.return_value = True
    stage.execute.return_value = StageResult(findings=[], confirmed_points=set())

    chain = BudgetChain([stage], depth=DetectionDepth.FAST, max_depth=DetectionDepth.FAST, budget_ms=3000)
    async for _ in chain.run(flow, points):
        pass

    stage.set_deadline.assert_called_once()
    deadline = stage.set_deadline.call_args[0][0]
    assert isinstance(deadline, float)
    assert deadline > 0.0


@pytest.mark.asyncio
async def test_budget_chain_passes_deadline_before_each_stage(flow, points):
    fast_stage = MagicMock(spec=DetectionStage)
    fast_stage.order = 0
    fast_stage.min_depth = DetectionDepth.FAST
    fast_stage.should_run.return_value = True
    fast_stage.execute.return_value = StageResult(findings=[], confirmed_points=set())
    standard_stage = MagicMock(spec=DetectionStage)
    standard_stage.order = 1
    standard_stage.min_depth = DetectionDepth.STANDARD
    standard_stage.should_run.return_value = True
    standard_stage.execute.return_value = StageResult(findings=[], confirmed_points=set())

    chain = BudgetChain([fast_stage, standard_stage], depth=DetectionDepth.FAST, max_depth=DetectionDepth.STANDARD, budget_ms=3000)
    async for _ in chain.run(flow, points):
        pass

    fast_stage.set_deadline.assert_called_once()
    standard_stage.set_deadline.assert_called_once()
    # Both stages receive the same absolute deadline (start + budget).
    assert fast_stage.set_deadline.call_args[0][0] == standard_stage.set_deadline.call_args[0][0]


@pytest.mark.asyncio
async def test_chain_from_depth_maps_fast_to_fast_budget():
    stage = MagicMock(spec=DetectionStage)
    stage.min_depth = DetectionDepth.FAST
    stage.should_run.return_value = True
    stage.execute.return_value = StageResult(findings=[], confirmed_points=set())

    chain = chain_from_depth([stage], depth="fast")
    assert chain._budget_ms == BudgetChain.WAVE_BUDGET_MS[DetectionDepth.FAST]


@pytest.mark.asyncio
async def test_chain_from_depth_maps_standard_to_standard_budget():
    stage = MagicMock(spec=DetectionStage)
    stage.min_depth = DetectionDepth.STANDARD
    stage.should_run.return_value = True
    stage.execute.return_value = StageResult(findings=[], confirmed_points=set())

    chain = chain_from_depth([stage], depth="standard")
    assert chain._budget_ms == BudgetChain.WAVE_BUDGET_MS[DetectionDepth.STANDARD]


@pytest.mark.asyncio
async def test_chain_from_depth_maps_deep_to_deep_budget():
    stage = MagicMock(spec=DetectionStage)
    stage.min_depth = DetectionDepth.DEEP
    stage.should_run.return_value = True
    stage.execute.return_value = StageResult(findings=[], confirmed_points=set())

    chain = chain_from_depth([stage], depth="deep")
    assert chain._budget_ms == BudgetChain.WAVE_BUDGET_MS[DetectionDepth.DEEP]


@pytest.mark.asyncio
async def test_chain_from_depth_defaults_to_deep_budget_on_unknown():
    stage = MagicMock(spec=DetectionStage)
    stage.min_depth = DetectionDepth.FAST
    stage.should_run.return_value = True
    stage.execute.return_value = StageResult(findings=[], confirmed_points=set())

    chain = chain_from_depth([stage], depth="fast")
    # fast must NOT receive deep budget (regression for the DEEP-hardcoded bug)
    assert chain._budget_ms != BudgetChain.WAVE_BUDGET_MS[DetectionDepth.DEEP]

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
