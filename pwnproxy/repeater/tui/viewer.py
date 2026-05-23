from typing import Optional

from textual.widgets import Static


class ResponseViewer(Static):
    """Displays HTTP response contents (status, headers, body)."""

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    def show_response(self, status_code: int, headers: dict, body: Optional[bytes]) -> None:
        """Populate the viewer with response data."""
        parts = [f"[bold]HTTP/1.1 {status_code}[/]"]
        for key, value in headers.items():
            parts.append(f"{key}: {value}")
        parts.append("")
        if body:
            text = body.decode("utf-8", "replace")
            if len(text) > 100_000:
                text = text[:100_000] + "\n... [truncated]"
            parts.append(text)
        self.update("\n".join(parts))
