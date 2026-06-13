from pwnproxy.services.scanners.xxe.scanner import XXEScanner

__all__ = ["XXEScanner"]


def create_scanner(hook_bus, on_finding=None):
    return XXEScanner(hook_bus, on_finding)
