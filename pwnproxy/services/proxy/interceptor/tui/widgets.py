from textual.widgets import Static, TextArea
from textual.widgets._toggle import Button


class HeaderInput(Static):
    """Label + Input pair for HTTP header rows."""


class HeadersEditor(TextArea):
    """Multi-line text area for editing headers as key: value lines."""


class BodyEditor(TextArea):
    """Text area for editing request/response bodies with optional language mode."""
