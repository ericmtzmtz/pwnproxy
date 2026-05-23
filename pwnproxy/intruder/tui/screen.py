import asyncio
from pathlib import Path
from typing import Optional

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.screen import Screen
from textual.widgets import Header, Static

from pwnproxy.intruder.engine import IntruderEngine
from pwnproxy.intruder.generator import ClusterBombGenerator, SniperGenerator, read_wordlist
from pwnproxy.intruder.parser import parse_markers
from pwnproxy.intruder.tui.config import IntruderConfig
from pwnproxy.intruder.tui.editor import IntruderEditor
from pwnproxy.intruder.tui.results import IntruderResults
from pwnproxy.core.models import Flow


class IntruderScreen(Screen[None]):
    """Main Intruder screen combining editor, config, and results."""

    BINDINGS = [
        Binding("escape", "close_screen", "Close"),
        Binding("ctrl+s", "start_attack", "Start"),
    ]

    def __init__(self, engine: Optional[IntruderEngine] = None):
        super().__init__()
        self._engine = engine or IntruderEngine()
        self._running = False
        self._cancel_event = asyncio.Event()

    def compose(self) -> ComposeResult:
        yield Header(show_clock=False)
        with Horizontal(id="intruder-main"):
            with Vertical(id="intruder-editor-panel"):
                yield Static("[bold]Request with §markers§[/]", classes="panel-title")
                yield IntruderEditor(id="intruder-editor")
            yield IntruderConfig(id="intruder-config")
        yield Static("", id="intruder-status")
        yield IntruderResults(id="intruder-results")

    def populate_from_flow(self, flow: Flow) -> None:
        from pwnproxy.repeater.integration import format_flow_as_raw_request
        raw = format_flow_as_raw_request(flow)
        editor = self.query_one("#intruder-editor", IntruderEditor)
        editor.text = raw

    async def action_start_attack(self) -> None:
        if self._running:
            return

        editor = self.query_one("#intruder-editor", IntruderEditor)
        raw = editor.text
        if not raw.strip():
            self._set_status("[red]Empty request[/]")
            return

        template, markers = parse_markers(raw)
        if not markers:
            self._set_status("[red]No §markers§ found in request[/]")
            return

        config = self.query_one("#intruder-config", IntruderConfig)
        mode = config.query_one("#attack-mode", Select).value
        concurrency_str = config.query_one("#concurrency", Input).value
        try:
            concurrency = int(concurrency_str) if concurrency_str else 10
        except ValueError:
            concurrency = 10

        wordlist_path = config.query_one("#wordlist-path", Input).value.strip()
        if not wordlist_path:
            self._set_status("[red]No wordlist selected[/]")
            return

        path = Path(wordlist_path)
        if not path.exists():
            self._set_status(f"[red]Wordlist not found: {wordlist_path}[/]")
            return

        self._set_status(f"[yellow]Loading wordlist...[/]")
        wordlist = [w async for w in read_wordlist(str(path))]
        config.set_wordlist_info(len(wordlist))

        if mode == "cluster_bomb":
            wordlists = [wordlist] * len(markers)
            gen = ClusterBombGenerator(template, markers, wordlists)
        else:
            gen = SniperGenerator(template, markers, wordlist)

        total = gen.total_requests
        self._set_status(f"[yellow]Starting {mode} attack: {total} requests...[/]")
        self._running = True
        self._cancel_event.clear()
        self._toggle_controls(False)

        results_table = self.query_one("#intruder-results", IntruderResults)
        results_table.clear()

        self._engine = IntruderEngine(concurrency=concurrency)

        async for result in self._engine.execute(gen, total):
            results_table.add_result(
                result.request_id,
                result.payload,
                result.status_code,
                result.response_length,
                result.timing_ms,
                result.error,
            )

        self._running = False
        self._toggle_controls(True)
        self._set_status(f"[green]Attack complete: {total} requests sent[/]")

    def action_stop_attack(self) -> None:
        self._cancel_event.set()

    def action_close_screen(self) -> None:
        self.app.pop_screen()

    def _set_status(self, msg: str) -> None:
        self.query_one("#intruder-status", Static).update(msg)

    def _toggle_controls(self, enabled: bool) -> None:
        config = self.query_one("#intruder-config", IntruderConfig)
        config.query_one("#btn-start", Button).disabled = not enabled
        config.query_one("#btn-stop", Button).disabled = enabled
