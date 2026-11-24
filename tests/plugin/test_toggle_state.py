"""Toggle a plugin that keeps state built in ``on_load``.

A plugin that opens its state in ``on_load()`` and discards it in ``on_unload()``
must keep working after ``POST /api/v1/plugins/{name}/toggle`` turns it off and on
again: the loader stops and restarts its consumer tasks and does **not** unload the
instance, so nothing has to rebuild the state. These tests are the guard for that
promise, with one finding per published flow so a duplicated consumer shows up as a
duplicated finding.

Both delivery paths are covered: ``HookBus`` (what the tests use) and the
``InProcessBus`` that ``pwnproxy start`` hands to the loader — the branch a real
off/on actually runs on.

The plugin is installed for real (no ``pip``) through the ``install_fake_plugin``
fixture; the built-in scanners are left out by pointing the discovery at an empty
directory, so "one finding" can only come from the fake.
"""

from __future__ import annotations

import asyncio
import importlib

import pytest

from pwnproxy.plugins.core.loader import PluginLoader
from pwnproxy.shared.bus.transports.inprocess import InProcessBus
from pwnproxy.shared.hooks import HookBus
from pwnproxy.shared.models import Flow

#: Name of the installed fake plugin (generic: nothing of this test is product
#: specific).
PLUGIN = "example-stateful"

#: A scanner whose state lives in ``on_load`` and is dropped in ``on_unload``. It
#: publishes one finding per flow **only** while the state is there, which is
#: exactly the shape a toggle can break: a consumer restarted without its state
#: stays silent, and a duplicated consumer publishes twice.
STATEFUL_SOURCE = f'''
from pwnproxy.plugins.core.base import Finding, PluginMetadata, ScannerPlugin

LOADS = []
UNLOADS = []
STATE = {{}}


class StatefulScanner(ScannerPlugin):
    metadata = PluginMetadata(
        name={PLUGIN!r},
        version="1.0.0",
        author="fixture",
        consumes=["flow"],
        produces=["finding"],
    )

    async def on_load(self) -> None:
        LOADS.append(self.metadata.name)
        STATE[self.metadata.name] = True

    async def on_unload(self) -> None:
        UNLOADS.append(self.metadata.name)
        STATE.pop(self.metadata.name, None)

    async def on_flow(self, flow):
        if not STATE.get(self.metadata.name):
            return
        yield Finding(
            scanner=self.metadata.name,
            url=flow.url,
            method=flow.method,
            param_name="id",
            param_location="query",
            technique="stateful",
            severity="low",
            confidence="confirmed",
            payload="1",
            evidence="the state built in on_load is still there",
        )
'''

#: ``[plugin.activation]`` of a test where the plugin starts loaded.
LOADED = f"[plugin.activation]\n{PLUGIN} = true\n"

#: ``[plugin.activation]`` of a test where the plugin starts switched off.
DISABLED = f"[plugin.activation]\n{PLUGIN} = false\n"


@pytest.fixture
def stateful(install_fake_plugin, activation_config, tmp_path):
    """Install the stateful fake and return ``(module, empty_scanners_dir)``.

    ``empty_scanners_dir`` holds no built-in scanner on purpose: the discovery of
    this test only sees the fake, so a published finding has one single possible
    author.
    """
    activation_config("")
    empty = tmp_path / "no_builtins"
    empty.mkdir()
    fake = install_fake_plugin(
        dist="pwnproxy-example",
        plugin_name=PLUGIN,
        class_name="StatefulScanner",
        source=STATEFUL_SOURCE,
    )
    return importlib.import_module(fake.module), empty


class Scene:
    """A loader over the fake only, on the transport the test asked for.

    ``bus`` is ``None`` for the ``HookBus`` path (the loader registers a queue per
    consumer) and an :class:`InProcessBus` for the path ``pwnproxy start`` uses.
    """

    def __init__(self, stateful, activation_config, activation: str, *, bus: bool) -> None:
        self.module, empty = stateful
        activation_config(activation)
        self.hook_bus = HookBus()
        self.inprocess = InProcessBus() if bus else None
        self.loader = PluginLoader(hook_bus=self.hook_bus, bus=self.inprocess)
        self._empty = empty

    async def start(self) -> Scene:
        before = self._subscribed()
        await self.loader.refresh_catalog(str(self._empty))
        if PLUGIN in self.loader.list_plugins():
            # ``refresh_catalog`` loads (``on_load``) but does not start the
            # consumers; ``pwnproxy start`` calls ``activate`` for each loaded
            # plugin right after, so the scene does the same.
            assert await self.loader.activate(PLUGIN) is True
            await self._wait_for_a_new_consumer(before)
        return self

    async def _wait_for_a_new_consumer(self, before: int) -> None:
        """Wait for the consumer task of the last activation to subscribe.

        A cancelled consumer leaves its subscription behind in both transports
        (the bus has no unsubscribe), so "there is a subscriber" is not enough:
        the wait is for the count to grow past ``before``.
        """
        await _wait_for(lambda: self._subscribed() > before)

    def _subscribed(self) -> int:
        if self.inprocess is None:
            return len(self.hook_bus._subscribers.get("flow", []))
        return self.inprocess.subscriber_count("flow")

    def live_consumers(self) -> list[str]:
        prefix = f"{PLUGIN}_"
        return [key for key in self.loader._plugin_tasks if key.startswith(prefix)]

    async def toggle(self) -> str:
        before = self._subscribed()
        status = await self.loader.toggle(PLUGIN)
        if status == "enabled":
            await self._wait_for_a_new_consumer(before)
        return status

    async def findings_for(self, identifier: str) -> list[tuple[str, str]]:
        """Publish one flow and return ``(scanner, url)`` of every finding it made."""
        queue = self.hook_bus.register("finding")
        flow = Flow(
            id=identifier,
            method="GET",
            url=f"http://lab.test/orders/{identifier}",
            request_headers={},
        )
        if self.inprocess is not None:
            await self.inprocess.publish("flow", flow)
        else:
            self.hook_bus.publish("flow", flow)
        await asyncio.sleep(0.3)
        produced = []
        while queue.has_data:
            finding = queue.get_nowait()
            produced.append((finding.scanner, finding.url))
        return produced

    async def stop(self) -> None:
        await self.loader.shutdown()


def _scene(stateful, activation_config, activation: str, *, bus: bool) -> Scene:
    return Scene(stateful, activation_config, activation, bus=bus)


async def _wait_for(predicate, timeout: float = 2.0) -> None:
    """Wait until ``predicate()`` is true, failing instead of hanging."""
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    while not predicate():
        assert loop.time() < deadline, "the consumer never subscribed"
        await asyncio.sleep(0.01)


@pytest.fixture(params=["hookbus", "inprocess-bus"])
def transport(request) -> bool:
    """``True`` for the ``InProcessBus`` the real process uses, ``False`` for ``HookBus``."""
    return request.param == "inprocess-bus"


class TestToggleWithState:
    """Off/on must leave the state and exactly one consumer in place."""

    @pytest.mark.asyncio
    async def test_off_and_on_keeps_the_state_and_still_produces_findings(
        self, stateful, activation_config, transport
    ):
        scene = await _scene(stateful, activation_config, LOADED, bus=transport).start()
        try:
            assert (scene.loader.list_plugins(), scene.module.LOADS) == ([PLUGIN], [PLUGIN])

            assert (await scene.toggle(), await scene.toggle()) == ("disabled", "enabled")
            produced = await scene.findings_for("1")

            assert (scene.module.LOADS, produced) == (
                [PLUGIN],
                [(PLUGIN, "http://lab.test/orders/1")],
            )
        finally:
            await scene.stop()

    @pytest.mark.asyncio
    async def test_two_off_on_rounds_leave_a_single_consumer(
        self, stateful, activation_config, transport
    ):
        scene = await _scene(stateful, activation_config, LOADED, bus=transport).start()
        try:
            for _round in range(2):
                assert (await scene.toggle(), await scene.toggle()) == (
                    "disabled",
                    "enabled",
                )
            produced = await scene.findings_for("2")

            # One flow, one finding: a leaked consumer would publish twice.
            assert (scene.module.LOADS, scene.live_consumers(), produced) == (
                [PLUGIN],
                [f"{PLUGIN}_flow"],
                [(PLUGIN, "http://lab.test/orders/2")],
            )
        finally:
            await scene.stop()

    @pytest.mark.asyncio
    async def test_enabling_a_plugin_that_started_disabled_runs_on_load_once(
        self, stateful, activation_config, transport
    ):
        scene = await _scene(stateful, activation_config, DISABLED, bus=transport).start()
        try:
            assert (scene.loader.list_plugins(), scene.module.LOADS) == ([], [])

            assert await scene.toggle() == "enabled"
            produced = await scene.findings_for("3")

            assert (
                scene.loader.list_plugins(),
                scene.module.LOADS,
                scene.module.UNLOADS,
                produced,
            ) == ([PLUGIN], [PLUGIN], [], [(PLUGIN, "http://lab.test/orders/3")])
        finally:
            await scene.stop()
