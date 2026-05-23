from pwnproxy.scanners.ssrf.scanner import SSRFScanner

__all__ = ["SSRFScanner"]


def create_scanner(hook_bus, on_finding=None):
    return SSRFScanner(hook_bus, on_finding)
