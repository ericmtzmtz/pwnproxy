from typing import Any

from pydantic import BaseModel, SerializeAsAny, field_validator


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
    result: dict[str, Any] | None = None
    error: str | None = None
    created_at: str
    completed_at: str | None = None


class TaskSummary(BaseModel):
    id: str
    type: str
    status: str
    progress: int
    total: int
    created_at: str
    completed_at: str | None = None


class TaskDetailSummary(TaskSummary):
    """`TaskSummary` plus the task's `config` and `result`.

    Returned by ``GET /tasks?detail=true`` so list views that render a task's
    request and response (e.g. the Repeater history) need a single request
    instead of one ``GET /tasks/{id}`` per row.
    """

    config: dict[str, Any]
    result: dict[str, Any] | None = None


class TaskListResponse(BaseModel):
    # SerializeAsAny keeps the extra fields of `TaskDetailSummary` items; plain
    # `TaskSummary` items keep serializing without `config`/`result`.
    tasks: list[SerializeAsAny[TaskSummary]]
    total: int
