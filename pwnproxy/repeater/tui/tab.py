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

    DEFAULT_CSS = """
    RepeaterTab {
        height: 1fr;
    }
    #repeater-toolbar {
        height: auto;
    }
    #repeater-content {
        height: 1fr;
    }
    .repeater-panel {
        height: 1fr;
        width: 1fr;
    }
    #req-editor {
        height: 1fr;
    }
    #resp-viewer {
        height: 1fr;
    }
    """

    def __init__(
        self,
        initial_text: str = "",
        engine: Optional[RepeaterEngine] = None,
        on_response=None,
        **kwargs,
    ):
        super().__init__(**kwargs)
        self._initial_text = initial_text
        self._engine = engine or RepeaterEngine()
        self.on_response = on_response

    def compose(self) -> ComposeResult:
        with Horizontal(id="repeater-toolbar"):
            yield Button("Send (F5)", id="btn-send", variant="primary")
            yield Button("Send to Intruder", id="btn-intruder", variant="default")
        with Horizontal(id="repeater-content"):
            with Vertical(id="editor-panel", classes="repeater-panel"):
                yield Static("[bold]Request[/]", classes="panel-title")
                yield RequestEditor(text=self._initial_text, id="req-editor")

            with Vertical(id="viewer-panel", classes="repeater-panel"):
                yield Static("[bold]Response[/]", classes="panel-title")
                yield ResponseViewer(id="resp-viewer")

    def on_mount(self) -> None:
        pass

    async def action_send(self) -> None:
        editor = self.query_one("#req-editor", RequestEditor)
        viewer = self.query_one("#resp-viewer", ResponseViewer)

        raw_text = editor.text
        if not raw_text.strip():
            viewer.update("--- Empty request ---")
            return

        viewer.update("--- Sending... ---")

        try:
            parsed = parse_raw_request(raw_text)
            t0 = asyncio.get_event_loop().time()
            response = await self._engine.send(parsed)
            elapsed = (asyncio.get_event_loop().time() - t0) * 1000
            viewer.show_response(
                status_code=response.status_code,
                headers=dict(response.headers),
                body=response.content,
            )
            if self.on_response:
                self.on_response({
                    "text": viewer.text,
                    "method": parsed["method"],
                    "path": parsed["path"],
                    "status_code": response.status_code,
                    "size": len(response.content or b""),
                    "duration_ms": elapsed,
                })
        except Exception as exc:
            viewer.update(f"--- Error: {exc} ---")
            if self.on_response:
                self.on_response({
                    "text": viewer.text,
                    "method": "",
                    "path": "",
                    "status_code": 0,
                    "size": 0,
                    "duration_ms": 0,
                })

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-send":
            asyncio.create_task(self.action_send())
        elif event.button.id == "btn-intruder":
            editor = self.query_one("#req-editor", RequestEditor)
            intruder = IntruderScreen(initial_request=editor.text)
            self.app.push_screen(intruder)

    def on_text_area_key(self, event) -> None:
        if event.key == "f5":
            asyncio.create_task(self.action_send())
