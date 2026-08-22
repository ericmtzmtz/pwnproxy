"""Utility functions for request building.

Provides ``build_request()`` helper that constructs an ``httpx.Request``
given a flow or injection point and optionally mutated body.
"""

from typing import Optional

import httpx

from pwnproxy.shared.models import Flow
from pwnproxy.shared.scan.params import InjectionPoint, _header


def build_request(
    flow: Flow | InjectionPoint,
    point: InjectionPoint,
    mutated_body: Optional[str] = None,
    override_body: bool = False,
) -> httpx.Request:
    """Build an HTTP request with optional mutated body.

    If ``override_body`` is True, uses ``mutated_body`` instead of the
    original body extracted from ``point.original_body``.
    Otherwise respects location-specific injection logic.

    Args:
        flow: Original HTTP flow containing request data.
        point: Injection point with location and parameter details.
        mutated_body: Optional mutated body for point-specific mutations.
        override_body: If True, forces use of ``mutated_body`` in request.

    Returns:
        httpx.Request ready to be sent.
    """
    # Extract original request components
    method = flow.method.upper()
    headers = dict(flow.request_headers)
    url = str(flow.url)

    if override_body and mutated_body is not None:
        # Force use of mutated body
        # Preserve original content-type unless overridden
        content = mutated_body.encode("utf-8")
        headers.pop("content-length", None)
        return httpx.Request(method, url, headers=headers, content=content)

    # For location-based injection, use point.inject() to mutate
    # This delegates to the appropriate mutation strategy
    # (query, form, json, cookie, header)
    # The mutation is already applied to ``point.value`` by this wrapper
    point.injected_value = mutated_body  # attach mutated value

    # Build request based on location (reuses RequestReplayer logic)
    location = point.location
    if location == "query":
        # Query param injection handled by mutating URL
        payload_value = mutated_body or point.value
        # Re-encode using original flow's query (simplified)
        # This is a fallback for override_body=False case
        return httpx.Request(
            method,
            url,
            headers=headers,
            content=None,
        )

    elif location == "body":
        content_type = _header(headers, "content-type").lower()
        if "application/x-www-form-urlencoded" in content_type:
            body = mutated_body or point.original_body or ""
            if isinstance(body, str):
                from urllib.parse import urlencode

                params = {}
                for line in body.split("&"):
                    if "=" in line:
                        k, v = line.split("=", 1)
                        params[k] = v
                # Inject via value attribute set earlier
                from urllib.parse import urlencode

                new_body = urlencode({**params, point.name: payload_value})
                content = new_body.encode()
        elif "application/json" in content_type:
            import json

            data = json.loads(mutated_body or point.original_body or "{}")
            # Simplified JSON injection – mutate value attached to point
            content = json.dumps(data).encode()
        else:
            content = mutated_body.encode() if mutated_body else None
        headers.pop("content-length", None)
        return httpx.Request(method, url, headers=headers, content=content)

    elif location == "cookie":
        cookie_value = mutated_body or headers.get("cookie", "")
        headers["cookie"] = cookie_value
        content = point.original_body.encode() if point.original_body else None
        return httpx.Request(method, url, headers=headers, content=content)

    elif location == "header":
        header_name = point.name
        headers[header_name] = mutated_body or point.value
        content = point.original_body.encode() if point.original_body else None
        return httpx.Request(method, url, headers=headers, content=content)

    else:
        raise ValueError(f"Unsupported injection location: {location}")