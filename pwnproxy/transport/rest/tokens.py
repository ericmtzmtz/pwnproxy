from typing import Any, Optional

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, ConfigDict

router = APIRouter(prefix="/api/v1", tags=["tokens"])


class TokenSummary(BaseModel):
    model_config = ConfigDict(extra="allow")

    id: Optional[int] = None
    token_type: Optional[str] = None
    token_value: Optional[str] = None
    label: Optional[str] = None
    status: Optional[str] = None
    source_url: Optional[str] = None
    ref_count: Optional[int] = None
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    expires_at: Optional[str] = None


class TokenDetail(BaseModel):
    model_config = ConfigDict(extra="allow")

    id: Optional[int] = None
    token_type: Optional[str] = None
    token_value: Optional[str] = None
    label: Optional[str] = None
    status: Optional[str] = None
    decoded_header: Any = None
    decoded_payload: Any = None
    source_url: Optional[str] = None
    source_flow_id: Optional[int] = None
    ref_count: Optional[int] = None
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None
    expires_at: Optional[str] = None


@router.get("/tokens", response_model=list[TokenSummary])
async def list_tokens(request: Request, token_type: Optional[str] = None, search: Optional[str] = None):
    storage = request.app.state.token_storage
    tokens = await storage.query(token_type=token_type, search=search)
    return [
        {
            "id": t.id,
            "token_type": t.token_type,
            "token_value": t.token_value[:80] + ("..." if len(t.token_value) > 80 else ""),
            "label": t.label,
            "status": t.status,
            "source_url": t.source_url,
            "ref_count": t.ref_count,
            "first_seen": t.first_seen.isoformat() if t.first_seen else None,
            "last_seen": t.last_seen.isoformat() if t.last_seen else None,
            "expires_at": t.expires_at.isoformat() if t.expires_at else None,
        }
        for t in tokens
    ]


@router.get("/tokens/{token_id}", response_model=TokenDetail)
async def get_token(request: Request, token_id: int):
    storage = request.app.state.token_storage
    token = await storage.get_by_id(token_id)
    if not token:
        raise HTTPException(status_code=404, detail="Token not found")
    return {
        "id": token.id,
        "token_type": token.token_type,
        "token_value": token.token_value,
        "label": token.label,
        "status": token.status,
        "decoded_header": token.decoded_header,
        "decoded_payload": token.decoded_payload,
        "source_url": token.source_url,
        "source_flow_id": token.source_flow_id,
        "ref_count": token.ref_count,
        "first_seen": token.first_seen.isoformat() if token.first_seen else None,
        "last_seen": token.last_seen.isoformat() if token.last_seen else None,
        "expires_at": token.expires_at.isoformat() if token.expires_at else None,
    }


@router.delete("/tokens/{token_id}", status_code=204)
async def delete_token(request: Request, token_id: int):
    storage = request.app.state.token_storage
    deleted = await storage.delete_by_id(token_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Token not found")