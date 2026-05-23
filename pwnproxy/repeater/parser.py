from typing import Optional


def parse_raw_request(raw: str) -> dict:
    """Parse a raw HTTP request string into its components.

    Returns dict with keys: method, path, http_version, headers, body.
    """
    if not raw or not raw.strip():
        raise ValueError("Empty raw request")

    lines = raw.splitlines()
    if not lines:
        raise ValueError("Empty raw request")

    request_line = lines[0].strip()
    parts = request_line.split(" ", 2)
    if len(parts) < 2:
        raise ValueError(f"Invalid request line: {request_line}")

    method = parts[0]
    path = parts[1]
    http_version = parts[2] if len(parts) > 2 else "HTTP/1.1"

    headers: dict[str, str] = {}
    body_lines: list[str] = []
    in_body = False

    for line in lines[1:]:
        if not in_body:
            if line == "" or line == "\r":
                in_body = True
                continue
            if ":" in line:
                key, _, value = line.partition(":")
                headers[key.strip()] = value.strip()
        else:
            body_lines.append(line)

    body = "\n".join(body_lines) if body_lines else ""

    return {
        "method": method,
        "path": path,
        "http_version": http_version,
        "headers": headers,
        "body": body,
    }
