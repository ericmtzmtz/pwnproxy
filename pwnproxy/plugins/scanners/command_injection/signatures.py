"""Signatures of OS command output for the command-injection scanner.

Every pattern must be specific enough that ordinary page text — HTML, JS,
JSON, or a binary document decoded as text — cannot trip it. The false
positive that motivated these patterns was a PDF whose decoded text matched
the old ``whoami`` rule (``^[a-z_][a-z0-9_]{1,31}$`` with ``MULTILINE``, so
the isolated keyword ``endobj`` counted as a username).

``has_command_output`` also receives the *baseline* body (the same request
without any payload). A pattern that already matches the baseline is page
text, not the result of an injection, so it is not evidence.
"""

import re

# Patterns that indicate command output in the response. Each technique groups
# the forms a single command prints; a body must add output the baseline did not
# already have.
CMD_OUTPUT_SIGNATURES: dict[str, list[re.Pattern]] = {
    # `id` prints its fields in one line: uid=… gid=… (both are required;
    # account names may contain dots and dashes, e.g. `www-data`).
    "uid": [
        re.compile(r"\buid=\d+\([\w.-]+\)\s+gid=\d+\([\w.-]+\)"),
    ],
    # `uname -a`: kernel name, host, release, then at least the machine field.
    "uname": [
        re.compile(r"^Linux\s+\S+\s+\d+\.\d+[\w.\- ]*\s+\S+", re.MULTILINE),
        re.compile(r"^Darwin\s+\S+\s+\d+\.\d+", re.MULTILINE),
    ],
    # `ls -l` / `ls -la`: mode, links, owner, group, size, then the name.
    "directory": [
        re.compile(
            r"^[-dlbcps][-rwxsStT]{9}[.@+]?\s+\d+\s+\S+\s+\S+\s+\d+\s+\S",
            re.MULTILINE,
        ),
        re.compile(r"^total\s+\d+$", re.MULTILINE),
    ],
    # `/etc/passwd` first line: root:x:0:0:root:/root:/bin/bash
    "passwd": [
        re.compile(r"^root:[^:\s]*:0:0:", re.MULTILINE),
    ],
    # Windows `dir`: a dated entry table or the "Directory of X:\" heading.
    "dir": [
        re.compile(r"^\s+\d{2}/\d{2}/\d{4}\s+\d{2}:\d{2}\s+(?:AM|PM)?\s*<?(?:DIR|FILE)>?", re.MULTILINE | re.IGNORECASE),
        re.compile(r"^Directory of\s+[A-Za-z]:\\", re.MULTILINE | re.IGNORECASE),
    ],
    # Shell diagnostics: the shell name must prefix the message, so prose that
    # merely says "command not found" is not a hit.
    "error": [
        re.compile(r"(?:^|\s)(?:/bin/|/usr/bin/)?(?:sh|bash|dash|zsh|ash|ksh): .{0,120}command not found", re.IGNORECASE),
        re.compile(r"'[^'\n]{1,40}' is not recognized as an internal or external command", re.IGNORECASE),
        re.compile(
            r"^(?:/bin/|/usr/bin/)?(?:sh|bash|dash|zsh|ash|ksh): \d+: [^:\n]{1,80}: not found\s*$",
            re.MULTILINE,
        ),
    ],
}

# `whoami` prints one bare account name and nothing else, so the whole response
# has to be that line: a short lowercase token, no other content.
WHOAMI_LINE_RE = re.compile(r"^[a-z_][a-z0-9_-]{0,31}$")

# Isolated lowercase tokens produced by document/archive formats decoded as
# text (PDF keywords, archive entries, format names). They have the shape of an
# account name but are never the output of `whoami`.
FORMAT_TOKENS = frozenset({
    "endobj", "endstream", "obj", "stream", "xref", "startxref", "trailer",
    "flate", "lzw", "ascii", "binary", "true", "false", "null", "none",
    "undefined", "body", "head", "html", "xml", "json", "total", "index",
    "default", "error", "success", "loading", "ver", "log",
})


def _isolated_line(body: str, line: str) -> bool:
    """True when ``line`` appears in ``body`` as a line of its own (stripped)."""
    return any(candidate.strip() == line for candidate in body.splitlines())


def _whoami_output(body: str, baseline: str) -> bool:
    """True when the whole body is a bare, short account name absent from the baseline.

    Args:
        body: Injected response body.
        baseline: Response body without the payload.

    Returns:
        ``True`` only for a single-line body that looks like a username and is
        not already printed (as its own line) by the baseline.
    """
    text = (body or "").strip()
    if not text or "\n" in text or "\r" in text:
        return False
    if not WHOAMI_LINE_RE.match(text):
        return False
    if text in FORMAT_TOKENS:
        return False
    return not _isolated_line(baseline or "", text)


def has_command_output(response_body: str, baseline: str = "") -> tuple[bool, str]:
    """Check whether the response contains evidence of command execution.

    Args:
        response_body: Body returned when the payload was injected.
        baseline: Body returned without the payload (captured response or one
            clean request). Defaults to ``""`` for callers without a baseline.

    Returns:
        ``(is_positive, detected_technique)``. A pattern that also matches the
        baseline does not count: the output was already there.
    """
    body = response_body or ""
    base = baseline or ""

    for technique, patterns in CMD_OUTPUT_SIGNATURES.items():
        for pattern in patterns:
            if pattern.search(body) and not pattern.search(base):
                return True, technique

    if _whoami_output(body, base):
        return True, "whoami"

    return False, ""


def get_evidence(response_body: str, technique: str) -> str:
    """Extract a short evidence snippet for the matched technique.

    Args:
        response_body: Injected response body.
        technique: Technique name returned by :func:`has_command_output`.

    Returns:
        A one-line description with at most 200 characters of context.
    """
    if technique == "whoami":
        return f"Command output detected (whoami): {response_body.strip()[:200]}"
    patterns = CMD_OUTPUT_SIGNATURES.get(technique, [])
    for pattern in patterns:
        match = pattern.search(response_body)
        if match:
            start = max(0, match.start() - 20)
            end = min(len(response_body), match.end() + 80)
            evidence = response_body[start:end].strip()
            return f"Command output detected ({technique}): {evidence[:200]}"
    return f"Suspicious response matched {technique}"
