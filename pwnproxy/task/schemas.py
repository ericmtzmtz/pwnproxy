from datetime import datetime, timezone
from typing import Any, Optional
from pydantic import BaseModel, field_validator


class TaskCreateRequest(BaseModel):
    type: str
    config: dict[str, Any]

    @field_validator("type")
    @classmethod
    def type_must_be_valid(cls, v: str) -> str:
        allowed = {"scan", "intruder", "repeater"}
        if v not in allowed:
            raise ValueError(f"type must be one of {allowed}")
        return v


class TaskCreateResponse(BaseModel):
    task_id: str
    status: str = "running"


class TaskStatusResponse(BaseModel):
    id: str
    type: str
    status: str
    progress: int
    total: int
    config: dict[str, Any]
    result: Optional[dict[str, Any]] = None
    error: Optional[str] = None
    created_at: str
    completed_at: Optional[str] = None


class TaskSummary(BaseModel):
    id: str
    type: str
    status: str
    progress: int
    total: int
    created_at: str
    completed_at: Optional[str] = None


class TaskListResponse(BaseModel):
    tasks: list[TaskSummary]
    total: int
