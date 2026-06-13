import asyncio
from pathlib import Path
from typing import Optional

import httpx

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.screen import Screen
from textual.widgets import Button, Header, Input, Select, Static

from pwnproxy.services.intruder.engine import IntruderEngine
from pwnproxy.services.intruder.tui.config import IntruderConfig
from pwnproxy.services.intruder.tui.editor import IntruderEditor
from pwnproxy.services.intruder.tui.results import IntruderResults


class IntruderScreen(Screen[None]):
    """Main Intruder screen combining editor, config, and results."""

    BINDINGS = [
        Binding("escape", "close_screen", "Close"),
        Binding("ctrl+s", "start_attack", "Start"),
    ]

    DEFAULT_CSS = """
    #intruder-body {
        height: 1fr;
    }
    #intruder-top {
        height: 1fr;
    }
    #intruder-editor-panel {
        height: 1fr;
    }
    #intruder-config {
        width: 30;
        height: 1fr;
    }
    #intruder-bottom {
        height: 1fr;
    }
    #intruder-status {
        height: 1;
    }
    #intruder-results {
        height: 1fr;
        min-height: 10;
    }
    """

    def __init__(self, engine: Optional[IntruderEngine] = None, initial_request: str = "", api_host: str = "127.0.0.1", api_port: int = 8000):
        super().__init__()
        self._engine = engine or IntruderEngine()
        self._initial_request = initial_request
        self._api_host = api_host
        self._api_port = api_port
        self._running = False
        self._cancel_event = asyncio.Event()

    def compose(self) -> ComposeResult:
        yield Header(show_clock=False)
        with Vertical(id="intruder-body"):
            with Horizontal(id="intruder-top"):
                with Vertical(id="intruder-editor-panel"):
                    yield Static("[bold]Request with §markers§[/]", classes="panel-title")
                    yield IntruderEditor(id="intruder-editor")
                yield IntruderConfig(id="intruder-config")
            with Vertical(id="intruder-bottom"):
                yield Static("", id="intruder-status")
                yield IntruderResults(id="intruder-results")

    def on_mount(self) -> None:
        if self._initial_request:
            self.query_one("#intruder-editor", IntruderEditor).text = self._initial_request

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-start":
            self.notify("Start Attack clicked")
            asyncio.create_task(self.action_start_attack())
        elif event.button.id == "btn-stop":
            self.action_stop_attack()

    async def action_start_attack(self) -> None:
        if self._running:
            return

        editor = self.query_one("#intruder-editor", IntruderEditor)
        raw = editor.text
        if not raw.strip():
            self._set_status("[red]Empty request[/]")
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

        self._set_status("[yellow]Starting attack via API...[/]")
        self._running = True
        self._toggle_controls(False)

        url = f"http://{self._api_host}:{self._api_port}/api/v1/intruder/run"
        try:
            async with httpx.AsyncClient() as client:
                resp = await client.post(url, json={
                    "raw_request": raw,
                    "mode": mode,
                    "wordlist_path": wordlist_path,
                    "concurrency": concurrency,
                }, timeout=300)
            resp.raise_for_status()
            data = resp.json()
            total = data.get("total", 0)
            results = data.get("results", [])
            self.query_one("#intruder-results", IntruderResults).post_message(
                IntruderResults.AddResults(results)
            )
            self._set_status(f"[green]Complete: {len(results)}/{total} results[/]")
        except Exception as e:
            self._set_status(f"[red]Error: {e}[/]")
        finally:
            self._running = False
            self._toggle_controls(True)

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
