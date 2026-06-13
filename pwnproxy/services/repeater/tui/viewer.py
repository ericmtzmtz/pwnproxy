from typing import Optional

from textual.widgets import TextArea


class ResponseViewer(TextArea):
    """Displays HTTP response as plain text (no markup parsing)."""

    def __init__(self, **kwargs):
        super().__init__(text="", read_only=True, **kwargs)

    def show_response(self, status_code: int, headers: dict, body: Optional[bytes]) -> None:
        parts = [f"HTTP/1.1 {status_code}"]
        for key, value in headers.items():
            parts.append(f"{key}: {value}")
        parts.append("")
        if body:
            text = body.decode("utf-8", "replace")
            if len(text) > 100_000:
                text = text[:100_000] + "\n... [truncated]"
            parts.append(text)
        self.text = "\n".join(parts)
        self.move_cursor((0, 0))

    def update(self, content: str) -> None:
        self.text = content