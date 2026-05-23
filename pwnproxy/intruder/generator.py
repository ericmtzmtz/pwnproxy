import asyncio
from typing import AsyncIterator, List, Tuple


async def read_wordlist(path: str) -> AsyncIterator[str]:
    """Yield lines from a wordlist file asynchronously."""
    loop = asyncio.get_running_loop()

    def _read() -> List[str]:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return [line.rstrip("\r\n") for line in f if line.strip()]

    lines = await loop.run_in_executor(None, _read)
    for line in lines:
        yield line


class SniperGenerator:
    """Sniper mode: one wordlist applied to markers sequentially."""

    def __init__(self, template: str, markers: list[Tuple[int, str]], wordlist: List[str]):
        self._template = template
        self._markers = markers
        self._wordlist = wordlist

    def __aiter__(self) -> AsyncIterator[tuple[str, str]]:
        return self._generate()

    async def _generate(self) -> AsyncIterator[tuple[str, str]]:
        for idx, base_value in self._markers:
            for payload in self._wordlist:
                request = self._template.format(
                    *[payload if i == idx else self._markers[i][1] for i in range(len(self._markers))]
                )
                yield (payload, request)

    @property
    def total_requests(self) -> int:
        return len(self._markers) * len(self._wordlist)


class ClusterBombGenerator:
    """Cluster Bomb mode: N wordlists permuted across N markers."""

    def __init__(self, template: str, markers: list[Tuple[int, str]], wordlists: List[List[str]]):
        self._template = template
        self._markers = markers
        self._wordlists = wordlists

    def __aiter__(self) -> AsyncIterator[tuple[str, str]]:
        return self._generate()

    async def _generate(self) -> AsyncIterator[tuple[str, str]]:
        if len(self._wordlists) != len(self._markers):
            raise ValueError("Wordlists count must match markers count")

        def _product(*lists: list[str]) -> list[tuple[str, ...]]:
            from itertools import product
            return list(product(*lists))

        combinations = _product(*self._wordlists)

        for combo in combinations:
            payload_label = ", ".join(combo)
            request = self._template.format(*combo)
            yield (payload_label, request)

    @property
    def total_requests(self) -> int:
        from functools import reduce
        from operator import mul
        if not self._wordlists:
            return 0
        return reduce(mul, (len(w) for w in self._wordlists), 1)
