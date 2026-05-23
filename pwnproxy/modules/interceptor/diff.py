import difflib
from typing import Optional

from pwnproxy.modules.interceptor.controller import FlowSnapshot

MAX_DIFF_SIZE = 102_400  # 100 KB


def compute_body_diff(original: str, edited: str) -> list[str]:
    if len(original) > MAX_DIFF_SIZE or len(edited) > MAX_DIFF_SIZE:
        return ["Body too large for diff"]
    if original == edited:
        return ["No changes"]
    orig_lines = original.splitlines(keepends=True)
    edit_lines = edited.splitlines(keepends=True)
    result = list(
        difflib.unified_diff(orig_lines, edit_lines, lineterm="")
    )
    return result if result else ["No changes"]


def _format_header_line(key: str, value: str) -> str:
    return f"{key}: {value}"


def compute_headers_diff(
    original: Optional[dict[str, str]],
    edited: Optional[dict[str, str]],
) -> list[str]:
    orig = original or {}
    ed = edited or {}
    if orig == ed:
        return ["No changes"]
    orig_lines = sorted(f"{k}: {v}" for k, v in orig.items())
    edit_lines = sorted(f"{k}: {v}" for k, v in ed.items())
    result = list(
        difflib.unified_diff(orig_lines, edit_lines, lineterm="")
    )
    return result if result else ["No changes"]


def compute_full_diff(
    original: FlowSnapshot, edited: FlowSnapshot
) -> dict[str, list[str]]:
    req_body_orig = (original.request_body or b"").decode("utf-8", "replace")
    req_body_edit = (edited.request_body or b"").decode("utf-8", "replace")
    res_body_orig = (original.response_body or b"").decode("utf-8", "replace")
    res_body_edit = (edited.response_body or b"").decode("utf-8", "replace")

    return {
        "request_body": compute_body_diff(req_body_orig, req_body_edit),
        "request_headers": compute_headers_diff(
            original.request_headers, edited.request_headers
        ),
        "response_body": compute_body_diff(res_body_orig, res_body_edit),
        "response_headers": compute_headers_diff(
            original.response_headers, edited.response_headers
        ),
    }
