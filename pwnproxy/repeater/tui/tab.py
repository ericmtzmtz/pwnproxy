import asyncio
from typing import Optional

from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical
from textual.widgets import Button, Static, TextArea

from pwnproxy.intruder.tui.screen import IntruderScreen
from pwnproxy.repeater.engine import RepeaterEngine
from pwnproxy.repeater.parser import parse_raw_request
from pwnproxy.repeater.tui.editor import RequestEditor
from pwnproxy.repeater.tui.viewer import ResponseViewer


class RepeaterTab(Vertical):
    """A single repeater tab with editor (left) and viewer (right)."""

    def __init__(
        self,
        title: str = "Untitled",
        initial_text: str = "",
        engine: Optional[RepeaterEngine] = None,
        **kwargs,
    ):
        super().__init__(**kwargs)
        self._title = title
        self._initial_text = initial_text
        self._engine = engine or RepeaterEngine()

    def compose(self) -> ComposeResult:
        yield Static(self._title, classes="tab-title")
        with Horizontal(id="repeater-content"):
            with Vertical(id="editor-panel", classes="repeater-panel"):
                yield Static("[bold]Request[/]", classes="panel-title")
                yield RequestEditor(text=self._initial_text, id="req-editor")
                yield Button("Send (F5)", id="btn-send", variant="primary")
                yield Button("Send to Intruder", id="btn-intruder", variant="default")

            with Vertical(id="viewer-panel", classes="repeater-panel"):
                yield Static("[bold]Response[/]", classes="panel-title")
                yield ResponseViewer(id="resp-viewer")

    def on_mount(self) -> None:
        editor = self.query_one("#req-editor", RequestEditor)
        editor.focus()

    async def action_send(self) -> None:
        editor = self.query_one("#req-editor", RequestEditor)
        viewer = self.query_one("#resp-viewer", ResponseViewer)

        raw_text = editor.text
        if not raw_text.strip():
            viewer.update("[red]Empty request[/]")
            return

        viewer.update("[yellow]Sending...[/]")

        try:
            parsed = parse_raw_request(raw_text)
            response = await self._engine.send(parsed)
            viewer.show_response(
                status_code=response.status_code,
                headers=dict(response.headers),
                body=response.content,
            )
        except Exception as exc:
            viewer.update(f"[red]Error: {exc}[/]")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-send":
            asyncio.create_task(self.action_send())
        elif event.button.id == "btn-intruder":
            editor = self.query_one("#req-editor", RequestEditor)
            from pwnproxy.core.models import Flow
            flow = Flow(
                id="intruder",
                method="GET",
                url="http://localhost",
                request_headers={},
                request_body=None,
            )
            intruder = IntruderScreen()
            intruder.populate_from_flow(flow)
            intruder.query_one("#intruder-editor", TextArea).text = editor.text
            self.app.push_screen(intruder)

    def on_text_area_key(self, event) -> None:
        if event.key == "f5":
            asyncio.create_task(self.action_send())
