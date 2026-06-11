import re
from typing import Optional

LFI_SIGNATURES: dict[str, list[re.Pattern]] = {
    "unix": [
        re.compile(r"root:x:0:0:"),
        re.compile(r"daemon:x:1:1:"),
        re.compile(r"bin:x:1:1:"),
        re.compile(r"/bin/bash"),
        re.compile(r"/bin/sh"),
        re.compile(r"nobody:x:\d+:\d+:"),
        re.compile(r"127\.0\.0\.1\s+localhost"),
        re.compile(r"::1\s+localhost"),
    ],
    "windows": [
        re.compile(r"\[extensions\]"),
        re.compile(r"\[fonts\]"),
        re.compile(r"\[mail\]"),
        re.compile(r"\[compatibility\]"),
        re.compile(r"for 16-bit app support"),
        re.compile(r"\[files\]"),
        re.compile(r"^;?\s*\[?(fonts|extensions|mail|compatibility)\]?"),
    ],
    "php": [
        re.compile(r"^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$", re.M),
    ],
}


def detect_os(body: str) -> tuple[Optional[str], Optional[str]]:
    for os_type, patterns in LFI_SIGNATURES.items():
        for pat in patterns:
            m = pat.search(body)
            if m:
                return os_type, m.group()
    return None, None
