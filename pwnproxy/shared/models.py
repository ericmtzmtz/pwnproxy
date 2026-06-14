import json
from dataclasses import dataclass
from typing import Any, Dict, Optional


@dataclass
class Flow:
    """Simplified representation of an HTTP flow for internal pwnproxy use."""
    id: str
    method: str
    url: str
    request_headers: Dict[str, str]
    request_body: Optional[bytes] = None
    
    status_code: Optional[int] = None
    response_headers: Optional[Dict[str, str]] = None
    response_body: Optional[bytes] = None
    
    duration_ms: Optional[float] = None
    error: Optional[str] = None
    tls: bool = False
    request_body_truncated: bool = False
    response_body_truncated: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "method": self.method,
            "url": self.url,
            "request_headers": self.request_headers,
            "request_body": self.request_body.decode("utf-8", errors="replace") if self.request_body else None,
            "request_body_truncated": self.request_body_truncated,
            "status_code": self.status_code,
            "response_headers": self.response_headers,
            "response_body": self.response_body.decode("utf-8", errors="replace") if self.response_body else None,
            "response_body_truncated": self.response_body_truncated,
            "duration_ms": self.duration_ms,
            "error": self.error,
            "tls": self.tls,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "Flow":
        return cls(
            id=d.get("id", ""),
            method=d.get("method", "GET"),
            url=d.get("url", ""),
            request_headers=d.get("request_headers", {}),
            request_body=d["request_body"].encode("utf-8") if d.get("request_body") else None,
            request_body_truncated=d.get("request_body_truncated", False),
            status_code=d.get("status_code"),
            response_headers=d.get("response_headers"),
            response_body=d["response_body"].encode("utf-8") if d.get("response_body") else None,
            response_body_truncated=d.get("response_body_truncated", False),
            duration_ms=d.get("duration_ms"),
            error=d.get("error"),
            tls=d.get("tls", False),
        )

    @classmethod
    def from_mitmproxy(cls, mflow) -> "Flow":
        """Convert a mitmproxy flow into a pwnproxy Flow."""
        req = mflow.request
        res = mflow.response
        err = mflow.error
        
        # mitmproxy headers are multi-dict, we simplify to dict for json serialization
        req_headers = {k: v for k, v in req.headers.items(multi=True)} if req else {}
        res_headers = {k: v for k, v in res.headers.items(multi=True)} if res else None
        
        duration = None
        if req and req.timestamp_start:
            end_time = mflow.response.timestamp_end if (mflow.response and mflow.response.timestamp_end) else (err.timestamp if err else None)
            if end_time:
                duration = (end_time - req.timestamp_start) * 1000

        raw_req_body = req.content if req else None
        raw_res_body = res.content if res else None
        MAX_BODY = 1_048_576
        req_body = raw_req_body[:MAX_BODY] if raw_req_body and len(raw_req_body) > MAX_BODY else raw_req_body
        res_body = raw_res_body[:MAX_BODY] if raw_res_body and len(raw_res_body) > MAX_BODY else raw_res_body
        req_trunc = bool(raw_req_body and len(raw_req_body) > MAX_BODY)
        res_trunc = bool(raw_res_body and len(raw_res_body) > MAX_BODY)

        return cls(
            id=mflow.id,
            method=req.method if req else "",
            url=req.url if req else "",
            request_headers=req_headers,
            request_body=req_body,
            request_body_truncated=req_trunc,
            status_code=res.status_code if res else None,
            response_headers=res_headers,
            response_body=res_body,
            response_body_truncated=res_trunc,
            duration_ms=duration,
            error=err.msg if err else None,
            tls=req.scheme == "https" if req else False,
        )
