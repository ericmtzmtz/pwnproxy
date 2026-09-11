"""Guard: stages must not define inline payload lists — payloads.py is the single source."""
import pathlib
import re

def test_no_inline_payload_lists_in_stages():
    stages_dir = pathlib.Path("pwnproxy/shared/scan/stages")
    # Payload-looking patterns: list literals with typical payload fragments
    payload_markers = [
        "<script", "file://", "etc/passwd", "onerror", "SELECT", "UNION",
    ]
    violations = []
    for f in stages_dir.glob("*.py"):
        text = f.read_text(encoding="utf-8")
        # Look for list literals that contain payload markers
        # Simple heuristic: find "[  ... ]" blocks with payload substrings
        for marker in payload_markers:
            if marker in text:
                # check if marker is inside a list literal defined in stages (not imported)
                # Search for "PAYLOADS = [" or "payloads = [" in stages
                if re.search(r"^\s*[A-Z_]*(?:PAYLOADS|PAYLOAD)\s*=\s*\[", text, re.MULTILINE):
                    # Allow if the list is STORED_PAYLOADS imported (now removed) — check file content
                    # For xss_stages, the import line replaces the definition, so should not trigger
                    # Only flag if the file defines a list with payload content that is not imported
                    # We check for direct list definitions containing the marker
                    lines = text.splitlines()
                    for i, line in enumerate(lines):
                        if re.match(r"^\s*[A-Z_]*PAYLOADS\s*=\s*\[", line):
                            snippet = "\n".join(lines[i:i+20])
                            if marker in snippet:
                                violations.append(f"{f.name}:{i+1} contains inline payload list with '{marker}'")
                                break
                    break
    assert not violations, "Inline payload lists found in stages (move to payloads.py):\n" + "\n".join(violations)
