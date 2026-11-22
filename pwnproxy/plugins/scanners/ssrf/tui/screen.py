"""Textual surface for the SSRF scanner.

``SSRFScanner`` is a per-flow detection chain driven by ``SSRFScannerPlugin``:
it owns no findings store, no start/stop lifecycle and no listener. The only
runtime state it exposes is the OOB callback host/port its payloads point at,
so that is the only thing this screen configures.
"""

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal
from textual.screen import ModalScreen, Screen
from textual.widgets import Button, Header, Input, Label, Static

from pwnproxy.plugins.scanners.ssrf.scanner import SSRFScanner
from pwnproxy.shared.ports import DEFAULT_CALLBACK_PORT

DEFAULT_CALLBACK_HOST = "127.0.0.1"


class ConfigScreen(ModalScreen[None]):
    """Edit the host/port the SSRF payloads point at."""

    def __init__(self, scanner: SSRFScanner):
        super().__init__()
        self._scanner = scanner

    def compose(self) -> ComposeResult:
        yield Container(
            Label("SSRF Callback Configuration", classes="title"),
            Label("Callback Host:"),
            Input(
                value=self._scanner.callback_host,
                id="config-host",
            ),
            Label("Listen Port:"),
            Input(
                value=str(self._scanner.callback_port),
                id="config-port",
            ),
            Button("Save", id="btn-save", variant="primary"),
            Button("Cancel", id="btn-cancel"),
            id="config-dialog",
        )

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id != "btn-save":
            self.app.pop_screen()
            return
        host = self.query_one("#config-host", Input).value.strip() or DEFAULT_CALLBACK_HOST
        port_str = self.query_one("#config-port", Input).value.strip()
        try:
            port = int(port_str)
        except ValueError:
            port = DEFAULT_CALLBACK_PORT
        self._scanner.configure(callback_host=host, callback_port=port)
        self.app.pop_screen()


class SsrfScannerScreen(Screen[None]):
    BINDINGS = [
        Binding("c", "show_config", "Config"),
    ]

    def __init__(self, scanner: SSRFScanner, name: str | None = None):
        super().__init__(name=name)
        self._scanner = scanner

    def compose(self) -> ComposeResult:
        yield Header(show_clock=False)
        with Container(id="ssrf-main"):
            with Horizontal(id="ssrf-status-bar"):
                yield Static("", id="ssrf-status-text")
                yield Button("Config", id="btn-config", variant="default")
            yield Static("", id="ssrf-detail", classes="detail-panel")

    def on_mount(self) -> None:
        self._update_status()

    def on_screen_resume(self) -> None:
        # The config modal may have changed host/port.
        self._update_status()

    def _update_status(self) -> None:
        self.query_one("#ssrf-status-text", Static).update(
            f"[bold]SSRF SCANNER[/] Callback: "
            f"{self._scanner.callback_host}:{self._scanner.callback_port}"
        )
        self.query_one("#ssrf-detail", Static).update(
            "SSRF findings are produced per flow by the ssrf plugin "
            "(DetectionChain: simple redirect, redirect, OOB). "
            "Press [bold]c[/] to change the callback host/port."
        )

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-config":
            self.action_show_config()

    def action_show_config(self) -> None:
        self.app.push_screen(ConfigScreen(self._scanner))
