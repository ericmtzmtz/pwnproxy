"""Out-of-band (OOB) callback server for blind vulnerability detection.

Provides HTTP and DNS callback servers that log incoming requests,
enabling confirmation of blind SSRF, SQLi, and XXE vulnerabilities.
"""
from pwnproxy.oob.canary import CanaryRegistry, CanaryToken

__all__ = [
    "CanaryRegistry",
    "CanaryToken",
]

# Lazy imports for servers (require optional dependencies)
def get_http_server():
    """Get HTTP callback server (requires aiohttp)."""
    from pwnproxy.oob.http_server import HTTPCallbackServer
    return HTTPCallbackServer

def get_dns_server():
    """Get DNS callback server."""
    from pwnproxy.oob.dns_server import DNSCallbackServer
    return DNSCallbackServer
