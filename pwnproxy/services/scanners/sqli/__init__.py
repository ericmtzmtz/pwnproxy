from pwnproxy.services.scanners.sqli.scanner import SQLiScanner

__all__ = ["SQLiScanner"]


def create_scanner(hook_bus, on_finding=None):
    return SQLiScanner(hook_bus, on_finding)
