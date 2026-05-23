from typing import Optional

from textual.widgets import DataTable


class IntruderResults(DataTable):
    """Real-time table for fuzzing results."""

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.add_columns("#", "Payload", "Status", "Length", "Time (ms)", "Error")

    def add_result(self, request_id: int, payload: str, status: int, length: int, timing: float, error: Optional[str] = None) -> None:
        status_str = f"[green]{status}[/]" if status and status < 500 else f"[red]{status}[/]" if status else "[grey]ERR[/]"
        err_display = f"[red]{error[:20]}[/]" if error else ""
        self.add_row(
            str(request_id),
            payload[:30],
            status_str,
            str(length),
            str(timing),
            err_display,
        )
