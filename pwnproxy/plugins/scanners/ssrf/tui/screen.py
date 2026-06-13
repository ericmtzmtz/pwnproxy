import asyncio
from typing import Optional

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal
from textual.screen import Screen, ModalScreen
from textual.widgets import Button, DataTable, Header, Input, Label, Static

from pwnproxy.plugins.scanners.ssrf.models import SsrfFinding
from pwnproxy.plugins.scanners.ssrf.scanner import SSRFScanner


class ConfigScreen(ModalScreen[None]):
    def __init__(self, scanner: SSRFScanner):
        super().__init__()
        self._scanner = scanner

    def compose(self) -> ComposeResult:
        yield Container(
            Label("SSRF Callback Configuration", classes="title"),
            Label("Callback Host:"),
            Input(
                value=self._scanner._payload_gen.callback_host,
                id="config-host",
            ),
            Label("Listen Port:"),
            Input(
                value=str(self._scanner._payload_gen.callback_port),
                id="config-port",
            ),
            Button("Save", id="btn-save", variant="primary"),
            Button("Cancel", id="btn-cancel"),
            id="config-dialog",
        )

    def on_button_pressed(self, event: Button.Pressed) -> None:
        host = self.query_one("#config-host", Input).value
        port_str = self.query_one("#config-port", Input).value
        try:
            port = int(port_str)
        except ValueError:
            port =18080
        self._scanner.configure(callback_host=host, listen_port=port)
        self.app.pop_screen()


class SsrfScannerScreen(Screen[None]):
    BINDINGS = [
        Binding("c", "show_config", "Config"),
        Binding("space", "toggle_scanner", "Start/Stop"),
    ]

    def __init__(self, scanner: SSRFScanner, name: Optional[str] = None):
        super().__init__(name=name)
        self._scanner = scanner
        self._findings: list[SsrfFinding] = []

    def compose(self) -> ComposeResult:
        yield Header(show_clock=False)
        with Container(id="ssrf-main"):
            with Horizontal(id="ssrf-status-bar"):
                yield Static("", id="ssrf-status-text")
                yield Static("", id="ssrf-counters")
                yield Button("Config", id="btn-config", variant="default")
            yield DataTable(id="ssrf-table")
            yield Static("", id="ssrf-detail", classes="detail-panel")

    def on_mount(self) -> None:
        table = self.query_one("#ssrf-table", DataTable)
        table.add_columns("SEV", "URL", "PARAM", "CALLBACK IP", "TIME")
        self._update_status()
        self._refresh_table()

    def _update_status(self) -> None:
        status = self._scanner.status()
        running_text = "[green]RUNNING[/]" if status["running"] else "[red]STOPPED[/]"
        listener_text = "[green]LISTENING[/]" if status["listener_running"] else "[red]OFF[/]"
        self.query_one("#ssrf-status-text", Static).update(
            f"[bold]SSRF SCANNER[/] [{running_text}] Listener: [{listener_text}] "
            f"({status['listener_host']}:{status['listener_port']})"
        )
        self.query_one("#ssrf-counters", Static).update(
            f"Findings: {status['findings']}  "
            f"Flows: {status['flows_processed']}  "
            f"Scanned: {status['params_scanned']}"
        )

    def _refresh_table(self) -> None:
        async def reload():
            findings = await self._scanner._storage.get_findings()
            self._findings = findings
            table = self.query_one("#ssrf-table", DataTable)
            table.clear()
            if not findings:
                self.query_one("#ssrf-detail", Static).update(
                    f"No SSRF findings yet. Scanner is {'running' if self._scanner.is_running else 'stopped'}."
                )
                return
            for f in findings:
                sev_icon = "🔴" if f.severity == "critical" else "🟠"
                table.add_row(
                    sev_icon,
                    f.url[:80],
                    f.param_name,
                    f.callback_ip or "pending",
                    f.timestamp.strftime("%H:%M:%S"),
                )
        asyncio.create_task(reload())

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        idx = event.cursor_key
        if idx is not None and idx < len(self._findings):
            f = self._findings[idx]
            detail = (
                f"[bold]URL:[/] {f.url}\n"
                f"[bold]Param:[/] {f.param_name} ({f.param_location})\n"
                f"[bold]Severity:[/] {f.severity}\n"
                f"[bold]Callback IP:[/] {f.callback_ip or 'pending'}\n"
                f"[bold]Payload:[/] {f.payload}\n"
                f"[bold]Canary:[/] {f.canary}\n"
                f"[bold]Time:[/] {f.timestamp}"
            )
            self.query_one("#ssrf-detail", Static).update(detail)

    def action_toggle_scanner(self) -> None:
        if self._scanner.is_running:
            asyncio.create_task(self._scanner.stop())
        else:
            asyncio.create_task(self._scanner.start())
        self._update_status()

    def action_show_config(self) -> None:
        self.app.push_screen(ConfigScreen(self._scanner))

    def on_finding(self, finding: SsrfFinding) -> None:
        self._findings.insert(0, finding)
        self._update_status()
        self._refresh_table()
