from typing import Optional

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal, Vertical
from textual.screen import ModalScreen, Screen
from textual.widgets import Button, Header, Input, Label, Static, TextArea

from pwnproxy.core.models import Flow
from pwnproxy.modules.interceptor.diff import compute_full_diff
from pwnproxy.modules.interceptor.controller import (
    InterceptorController,
    FlowSnapshot,
)

MAX_TUI_BODY = 102_400  # 100 KB display cap


class HeaderInput(Static):
    """A labeled single-line input."""
    def compose(self, fields: tuple[str, str]) -> ComposeResult:
        label, value = fields
        yield Label(label)
        yield Input(value=value, id=f"hdr-{label.lower()}")


class DiffOverlay(ModalScreen[None]):
    """Full-screen diff overlay showing original vs edited."""
    def __init__(
        self,
        original: FlowSnapshot,
        edited: FlowSnapshot,
        name: Optional[str] = None,
        ident: Optional[str] = None,
        classes: Optional[str] = None,
    ):
        super().__init__(name=name, id=ident, classes=classes)
        self._diffs = compute_full_diff(original, edited)

    def compose(self) -> ComposeResult:
        yield Header(show clock=False)
        with Container(id="diff-content"):
            for section, lines in self._diffs.items():
                yield Static(f"[bold]── {section} ──[/]", classes="diff-section")
                if not lines or lines == ["No changes"]:
                    yield Static("  No changes", classes="diff-nochange")
                elif lines == ["Body too large for diff"]:
                    yield Static("  Body too large for diff", classes="diff-truncated")
                else:
                    for line in lines:
                        css_class = "diff-add" if line.startswith("+") else (
                            "diff-remove" if line.startswith("-") else "diff-ctx"
                        )
                        yield Static(f"  {line}", classes=css_class)
        yield Static("[bold]Press any key to close[/]", id="diff-close-hint")

    def on_key(self) -> None:
        self.dismiss()


class InterceptorScreen(Screen[None]):
    """Main interceptor screen showing intercepted flow for editing."""

    BINDINGS = [
        Binding("ctrl+i", "toggle_interceptor", "Toggle"),
        Binding("escape", "close_screen", "Close"),
    ]

    def __init__(
        self,
        controller: InterceptorController,
        flow: Flow,
        original: FlowSnapshot,
    ):
        super().__init__()
        self._controller = controller
        self._flow = flow
        self._original = original

    def compose(self) -> ComposeResult:
        yield Header(show clock=False)
        with Container(id="interceptor-main"):
            with Container(id="interceptor-panels"):
                with Vertical(id="request-panel", classes="panel"):
                    yield Static("[bold]REQUEST[/]", classes="panel-title")
                    yield Input(
                        value=self._flow.method,
                        id="req-method",
                        placeholder="Method",
                        classes="field-compact",
                    )
                    yield Input(
                        value=self._flow.url,
                        id="req-url",
                        placeholder="URL",
                    )
                    yield Static("Headers:", classes="section-label")
                    yield TextArea(
                        text=self._format_headers(self._flow.request_headers),
                        id="req-headers",
                        classes="headers-editor",
                    )
                    yield Static("Body:", classes="section-label")
                    yield TextArea(
                        text=self._format_body(self._flow.request_body),
                        id="req-body",
                        classes="body-editor",
                    )

                with Vertical(id="response-panel", classes="panel"):
                    yield Static("[bold]RESPONSE[/]", classes="panel-title")
                    yield Input(
                        value=str(self._flow.status_code or ""),
                        id="res-status",
                        placeholder="Status",
                        classes="field-compact",
                    )
                    yield Static("Headers:", classes="section-label")
                    yield TextArea(
                        text=self._format_headers(self._flow.response_headers),
                        id="res-headers",
                        classes="headers-editor",
                    )
                    yield Static("Body:", classes="section-label")
                    yield TextArea(
                        text=self._format_body(self._flow.response_body),
                        id="res-body",
                        classes="body-editor",
                    )

            with Horizontal(id="action-bar"):
                yield Button("Forward", id="btn-forward", variant="primary")
                yield Button("Forward with edits", id="btn-fwdedit", variant="default")
                yield Button("Drop", id="btn-drop", variant="error")
                yield Button("Diff", id="btn-diff", variant="default")

    def _format_headers(self, headers: Optional[dict[str, str]]) -> str:
        if not headers:
            return ""
        return "\n".join(f"{k}: {v}" for k, v in headers.items())

    def _format_body(self, body: Optional[bytes]) -> str:
        if not body:
            return ""
        text = body.decode("utf-8", "replace")
        if len(text) > MAX_TUI_BODY:
            text = text[:MAX_TUI_BODY]
        return text

    def _read_headers(self, text: str) -> dict[str, str]:
        result: dict[str, str] = {}
        for line in text.splitlines():
            if ":" in line:
                k, _, v = line.partition(":")
                result[k.strip()] = v.strip()
        return result

    def _read_body_bytes(self, text_area: TextArea) -> Optional[bytes]:
        text = text_area.text
        if not text.strip():
            return None
        return text.encode("utf-8")

    def _apply_json_highlight(self, body_area: TextArea, content_type: str) -> None:
        if "json" in content_type.lower():
            body_area.language = "json"

    def on_mount(self) -> None:
        self._update_header()
        req_body = self.query_one("#req-body", TextArea)
        ct = self._flow.request_headers.get("content-type", "")
        self._apply_json_highlight(req_body, ct)
        res_body = self.query_one("#res-body", TextArea)
        if self._flow.response_headers:
            rct = self._flow.response_headers.get("content-type", "")
            self._apply_json_highlight(res_body, rct)

    def _update_header(self) -> None:
        status = "ON" if self._controller.enabled else "OFF"
        count = self._controller.pending_count
        self.sub_title = f"Interceptor [{status}]  Pending: {count}"

    def _build_edited_flow(self) -> Flow:
        req_method = self.query_one("#req-method", Input).value
        req_url = self.query_one("#req-url", Input).value
        req_headers = self._read_headers(
            self.query_one("#req-headers", TextArea).text
        )
        req_body = self._read_body_bytes(self.query_one("#req-body", TextArea))
        res_status_str = self.query_one("#res-status", Input).value
        res_status = int(res_status_str) if res_status_str and res_status_str.isdigit() else None
        res_headers = self._read_headers(
            self.query_one("#res-headers", TextArea).text
        ) or None
        res_body = self._read_body_bytes(self.query_one("#res-body", TextArea))

        edited = Flow(
            id=self._flow.id,
            method=req_method,
            url=req_url,
            request_headers=req_headers,
            request_body=req_body,
            status_code=res_status,
            response_headers=res_headers,
            response_body=res_body,
        )
        return edited

    def action_toggle_interceptor(self) -> None:
        self._controller.toggle()
        self._update_header()

    def action_close_screen(self) -> None:
        self.app.pop_screen()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-forward":
            self._controller.forward(self._flow.id)
            self.app.pop_screen()
        elif event.button.id == "btn-fwdedit":
            edited = self._build_edited_flow()
            self._controller.forward_with_edits(self._flow.id, edited)
            self.app.pop_screen()
        elif event.button.id == "btn-drop":
            self._controller.drop(self._flow.id)
            self.app.pop_screen()
        elif event.button.id == "btn-diff":
            edited = self._build_edited_flow()
            edited_snap = FlowSnapshot.from_flow(edited)
            self.app.push_screen(
                DiffOverlay(self._original, edited_snap)
            )
