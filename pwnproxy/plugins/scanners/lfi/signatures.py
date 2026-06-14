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
    "php": [
        re.compile(r"<\?php"),
        re.compile(r"<\?="),
        re.compile(r"PD9waHA"),  # base64 of <?php
        re.compile(r"eval\s*\("),
        re.compile(r"base64_decode\s*\("),
        re.compile(r"system\s*\("),
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
}


class OsSignatureMatcher:
    """Matches OS type from LFI payload evidence in response body."""

    def match(self, body: str, min_matches: int = 2) -> tuple[Optional[str], Optional[str]]:
        best_os = None
        best_evidence = None
        best_count = 0

        for os_type, patterns in LFI_SIGNATURES.items():
            matches = []
            for pat in patterns:
                m = pat.search(body)
                if m:
                    matches.append(m.group())
            if len(matches) >= min_matches and len(matches) > best_count:
                best_os = os_type
                best_evidence = matches[0]
                best_count = len(matches)

        if best_os and best_count >= min_matches:
            return best_os, best_evidence
        return None, None


def detect_os(body: str, min_matches: int = 1) -> tuple[Optional[str], Optional[str]]:
    """Legacy wrapper — prefer OsSignatureMatcher.match()."""
    return OsSignatureMatcher().match(body, min_matches)
