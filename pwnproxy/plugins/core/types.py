from dataclasses import dataclass, field
from typing import Any


@dataclass
class Surface:
    """Represents an attack surface discovered by a crawler plugin.
    
    Attributes:
        url: The discovered URL or endpoint.
        method: HTTP method (GET, POST, etc.).
        params: List of parameter names found.
        content_type: Response content type.
        status_code: HTTP response status code.
        source: How the surface was discovered (e.g., "crawl", "sitemap", "link").
        extra: Optional metadata.
    """
    url: str
    method: str = "GET"
    params: list[str] = field(default_factory=list)
    content_type: str = ""
    status_code: int = 0
    source: str = ""
    extra: dict[str, Any] = field(default_factory=dict)


@dataclass
class Evidence:
    """Represents evidence that a vulnerability exists.
    
    Attributes:
        finding_id: Reference to the Finding that produced this evidence.
        exploit_result: Description of what the exploit achieved.
        impact: Severity of confirmed impact.
        details: Technical details for the report.
        poc: Proof-of-concept data (request/response pairs).
        extra: Optional metadata.
    """
    finding_id: str = ""
    exploit_result: str = ""
    impact: str = ""
    details: str = ""
    poc: str = ""
    extra: dict[str, Any] = field(default_factory=dict)
