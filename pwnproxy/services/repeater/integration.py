from pwnproxy.shared.models import Flow


def format_flow_as_raw_request(flow: Flow) -> str:
    """Format a Flow into a raw HTTP request string for the Repeater editor."""
    path = flow.url
    if "://" in path:
        idx = path.find("/", path.find("://") + 3)
        if idx != -1:
            path = path[idx:]
        else:
            path = "/"

    lines: list[str] = []
    lines.append(f"{flow.method} {path} HTTP/1.1")

    has_host = False
    for key, value in flow.request_headers.items():
        lines.append(f"{key}: {value}")
        if key.lower() == "host":
            has_host = True

    if not has_host and flow.url:
        from urllib.parse import urlparse
        parsed = urlparse(flow.url)
        if parsed.hostname:
            host_str = parsed.hostname
            if parsed.port:
                host_str = f"{parsed.hostname}:{parsed.port}"
            lines.append(f"Host: {host_str}")

    lines.append("")

    if flow.request_body:
        body = flow.request_body.decode("utf-8", "replace")
        lines.append(body)
    else:
        lines.append("")

    return "\r\n".join(lines)
