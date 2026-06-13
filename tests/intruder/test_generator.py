import pytest

from pwnproxy.services.intruder.generator import ClusterBombGenerator, SniperGenerator


async def _collect(agen):
    results = []
    async for item in agen:
        results.append(item)
    return results


class TestSniperGenerator:
    @pytest.mark.asyncio
    async def test_single_marker_single_payload(self):
        gen = SniperGenerator("user={0}", [(0, "admin")], ["foo"])
        results = await _collect(gen)
        assert len(results) == 1
        assert results[0] == ("foo", "user=foo")

    @pytest.mark.asyncio
    async def test_single_marker_multiple_payloads(self):
        gen = SniperGenerator("user={0}", [(0, "admin")], ["a", "b", "c"])
        results = await _collect(gen)
        assert len(results) == 3
        assert results[0] == ("a", "user=a")
        assert results[1] == ("b", "user=b")
        assert results[2] == ("c", "user=c")

    @pytest.mark.asyncio
    async def test_two_markers_sniper(self):
        gen = SniperGenerator(
            "a={0}&b={1}",
            [(0, "x"), (1, "y")],
            ["p1", "p2"],
        )
        results = await _collect(gen)
        assert len(results) == 4  # 2 markers * 2 payloads
        assert ("p1", "a=p1&b=y") in results
        assert ("p2", "a=p2&b=y") in results
        assert ("p1", "a=x&b=p1") in results
        assert ("p2", "a=x&b=p2") in results

    def test_total_requests(self):
        gen = SniperGenerator("x={0}", [(0, "a"), (1, "b")], ["p1", "p2", "p3"])
        assert gen.total_requests == 6


class TestClusterBombGenerator:
    @pytest.mark.asyncio
    async def test_two_markers(self):
        gen = ClusterBombGenerator(
            "a={0}&b={1}",
            [(0, "x"), (1, "y")],
            [["a1", "a2"], ["b1", "b2", "b3"]],
        )
        results = await _collect(gen)
        assert len(results) == 6  # 2 * 3
        assert ("a1, b1", "a=a1&b=b1") in results
        assert ("a2, b3", "a=a2&b=b3") in results

    @pytest.mark.asyncio
    async def test_single_marker_cluster_bomb(self):
        gen = ClusterBombGenerator(
            "x={0}",
            [(0, "z")],
            [["a", "b", "c"]],
        )
        results = await _collect(gen)
        assert len(results) == 3

    @pytest.mark.asyncio
    async def test_mismatched_wordlists_raises(self):
        with pytest.raises(ValueError):
            gen = ClusterBombGenerator("x={0}", [(0, "a"), (1, "b")], [["a"]])
            _ = await _collect(gen)

    def test_total_requests(self):
        gen = ClusterBombGenerator(
            "x={0}", [(0, "a"), (1, "b")],
            [["p1", "p2"], ["q1", "q2", "q3"]],
        )
        assert gen.total_requests == 6
