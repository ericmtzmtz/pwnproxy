from pwnproxy.scanners.lfi.scanner import LFIScanner

__all__ = ["LFIScanner"]


def create_scanner(hook_bus, on_finding=None):
    return LFIScanner(hook_bus, on_finding)
