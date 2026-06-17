import re

# Patterns that indicate command output in the response
CMD_OUTPUT_SIGNATURES: dict[str, list[re.Pattern]] = {
    "uid": [
        re.compile(r"uid=\d+\(\w+\)", re.IGNORECASE),
        re.compile(r"gid=\d+\(\w+\)", re.IGNORECASE),
        re.compile(r"groups=\d+\(\w+\)", re.IGNORECASE),
    ],
    "whoami": [
        re.compile(r"^[a-z_][a-z0-9_]{1,31}$", re.MULTILINE),  # matches "root", "www-data", etc.
    ],
    "uname": [
        re.compile(r"Linux\s+\w+\s+[\d.]+-[\w-]+", re.IGNORECASE),
        re.compile(r"Darwin\s+\w+\s+[\d.]+", re.IGNORECASE),
    ],
    "directory": [
        re.compile(r"^total\s+\d+", re.MULTILINE),  # output of ls -la starts with "total N"
        re.compile(r"^d[rwx-]{9}", re.MULTILINE),   # directory entries
        re.compile(r"^-[rwx-]{9}", re.MULTILINE),   # file entries
    ],
    "passwd": [
        re.compile(r"^root:[^:]+:\d+:\d+:", re.MULTILINE),  # /etc/passwd entry
    ],
    "dir": [
        re.compile(r"\s+<DIR>\s+", re.IGNORECASE),  # Windows dir output
        re.compile(r"\s+Directory of\s+", re.IGNORECASE),
    ],
    "error": [
        re.compile(r"command not found", re.IGNORECASE),
        re.compile(r"not recognized", re.IGNORECASE),
        re.compile(r"is not recognized", re.IGNORECASE),
    ],
}

def has_command_output(response_body: str) -> tuple[bool, str]:
    """Check if the response contains evidence of command execution.
    
    Returns (is_positive, detected_technique)
    """
    for technique, patterns in CMD_OUTPUT_SIGNATURES.items():
        for pattern in patterns:
            if pattern.search(response_body):
                return True, technique
    return False, ""

def get_evidence(response_body: str, technique: str) -> str:
    """Extract relevant evidence from response body."""
    patterns = CMD_OUTPUT_SIGNATURES.get(technique, [])
    for pattern in patterns:
        match = pattern.search(response_body)
        if match:
            start = max(0, match.start() - 20)
            end = min(len(response_body), match.end() + 80)
            evidence = response_body[start:end].strip()
            return f"Command output detected ({technique}): {evidence[:200]}"
    return f"Suspicious response matched {technique}"
