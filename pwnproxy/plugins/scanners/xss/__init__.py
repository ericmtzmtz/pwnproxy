from pwnproxy.plugins.scanners.xss.scanner import XSSScanner

__all__ = ["XSSScanner"]


def create_scanner(hook_bus, on_finding=None):
    return XSSScanner(hook_bus, on_finding)
