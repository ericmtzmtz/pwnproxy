from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel


class FlowResponse(BaseModel):
    id: int
    method: str
    url: str
    request_headers: Dict[str, Any]
    request_body: Optional[bytes] = None
    status_code: Optional[int] = None
    response_headers: Optional[Dict[str, Any]] = None
    response_body: Optional[bytes] = None
    timestamp: datetime
    duration_ms: Optional[float] = None
    error: Optional[str] = None
    tls: bool = False


class ScannerTriggerRequest(BaseModel):
    flow_id: int
    scanners: List[str]


class FindingItem(BaseModel):
    id: int
    url: str
    param_name: str
    param_value: str
    severity: str
    timestamp: datetime
    extra: Dict[str, Any] = {}
