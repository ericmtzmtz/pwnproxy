"""The SSRF TUI config modal must work against the public ``SSRFScanner`` API.

It used to read ``self._scanner._payload_gen`` (an attribute the scanner never
had) and call a ``configure(listen_port=...)`` method that did not exist, so the
modal raised ``AttributeError`` as soon as it composed.
"""

import asyncio

import pytest
from textual.app import App
from textual.widgets import Input, Static

from pwnproxy.plugins.scanners.ssrf.scanner import SSRFScanner
from pwnproxy.plugins.scanners.ssrf.tui.screen import ConfigScreen, SsrfScannerScreen
from pwnproxy.shared.ports import DEFAULT_CALLBACK_PORT
from pwnproxy.shared.scan.replayer import RequestReplayer


class _Harness(App):
    """Minimal host app: pushes one screen and nothing else."""

    def __init__(self, screen):
        super().__init__()
        self._initial_screen = screen

    def on_mount(self) -> None:
        self.push_screen(self._initial_screen)


@pytest.fixture
def scanner():
    replayer = RequestReplayer()
    scanner = SSRFScanner(replayer, callback_host="10.1.2.3", callback_port=18001)
    yield scanner
    asyncio.run(replayer.close())


@pytest.mark.asyncio
async def test_config_modal_prefills_the_scanner_callback_config(scanner):
    app = _Harness(ConfigScreen(scanner))
    async with app.run_test() as pilot:
        await pilot.pause()
        shown = (
            app.screen.query_one("#config-host", Input).value,
            app.screen.query_one("#config-port", Input).value,
        )
    assert shown == ("10.1.2.3", "18001")


@pytest.mark.asyncio
async def test_save_applies_the_new_callback_config_to_the_scanner(scanner):
    app = _Harness(ConfigScreen(scanner))
    async with app.run_test() as pilot:
        await pilot.pause()
        app.screen.query_one("#config-host", Input).value = "203.0.113.7"
        app.screen.query_one("#config-port", Input).value = "19992"
        await pilot.click("#btn-save")
        await pilot.pause()
        modal_closed = not isinstance(app.screen, ConfigScreen)
    assert ((scanner.callback_host, scanner.callback_port), modal_closed) == (
        ("203.0.113.7", 19992),
        True,
    )


@pytest.mark.asyncio
async def test_cancel_leaves_the_scanner_config_untouched(scanner):
    app = _Harness(ConfigScreen(scanner))
    async with app.run_test() as pilot:
        await pilot.pause()
        app.screen.query_one("#config-host", Input).value = "203.0.113.7"
        app.screen.query_one("#config-port", Input).value = "19992"
        await pilot.click("#btn-cancel")
        await pilot.pause()
    assert (scanner.callback_host, scanner.callback_port) == ("10.1.2.3", 18001)


@pytest.mark.asyncio
async def test_unparsable_port_falls_back_to_the_shared_default(scanner):
    app = _Harness(ConfigScreen(scanner))
    async with app.run_test() as pilot:
        await pilot.pause()
        app.screen.query_one("#config-port", Input).value = "not-a-port"
        await pilot.click("#btn-save")
        await pilot.pause()
    assert (scanner.callback_host, scanner.callback_port) == ("10.1.2.3", DEFAULT_CALLBACK_PORT)


@pytest.mark.asyncio
async def test_screen_binding_opens_the_modal_and_shows_the_applied_config(scanner):
    app = _Harness(SsrfScannerScreen(scanner))
    async with app.run_test() as pilot:
        await pilot.pause()
        await pilot.press("c")
        await pilot.pause()
        assert isinstance(app.screen, ConfigScreen)
        app.screen.query_one("#config-host", Input).value = "198.51.100.9"
        app.screen.query_one("#config-port", Input).value = "19993"
        await pilot.click("#btn-save")
        await pilot.pause()
        status = str(app.screen.query_one("#ssrf-status-text", Static).content)
        applied = not isinstance(app.screen, ConfigScreen)
    assert (
        (scanner.callback_host, scanner.callback_port),
        "198.51.100.9:19993" in status,
        applied,
    ) == (("198.51.100.9", 19993), True, True)
