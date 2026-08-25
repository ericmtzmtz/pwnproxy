"""Passive crawler: URL discovery from proxied responses."""

from pwnproxy.services.crawler.storage import DiscoveredURLORM, DiscoveredURLStorage, JobORM, JobStorage

__all__ = ["DiscoveredURLORM", "DiscoveredURLStorage", "JobORM", "JobStorage"]
