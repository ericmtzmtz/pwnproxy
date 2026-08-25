"""Passive crawler: URL discovery from proxied responses."""

from pwnproxy.services.crawler.storage import DiscoveredURLORM, DiscoveredURLStorage

__all__ = ["DiscoveredURLORM", "DiscoveredURLStorage"]
