"""HTTP routes for a plugin's configuration (schema, settings, collections, actions).

Eight routes under ``/api/v1/plugins/{name}``, all of them behind the local API
token, that publish nothing of their own: the schema comes from the plugin, the
values are validated by ``plugins/core/config_schema.py`` and the write is done
by the plugin through ``plugins/core/config_service.py``. This module is only the
transport: request bodies, response shapes, error codes and the **scope matrix**.

Two rules shape it:

* **The scope is enforced here, not in the service** (design D8). A token with
  scope ``agent`` (the MCP) reads anything but may not write a declared ``secret``
  field nor run an action that requires ``full``. The decision depends on the
  body and on the schema, so a ``Depends(require_scope("full"))`` does not fit:
  the same route accepts ``agent`` without secrets and refuses it with secrets.
* **The ``403`` comes before any validation.** The secret keys are looked up in
  the body *before* the service validates the values, so an ``agent`` write that
  carries a secret is refused without a ``422`` that could describe it.

The scope comes from ``request.state.scope`` (set by the auth middleware) and an
absent scope is treated as insufficient: this module fails closed.
"""

from __future__ import annotations

import logging
from collections.abc import Awaitable, Mapping, Sequence
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel, Field

from pwnproxy.plugins.core.config_schema import (
    SECRET_WRITE_REQUIRES_FULL_DETAIL,
    ActionSpec,
    FieldSpec,
    PluginValidationError,
    SchemaViolation,
    action_scope,
    secret_keys,
)
from pwnproxy.plugins.core.config_service import (
    PluginConfigError,
    PluginConfigService,
    error_response,
)
from pwnproxy.shared.api_token import SCOPE_FULL
from pwnproxy.transport.rest.auth import FORBIDDEN_SCOPE_DETAIL, WWW_AUTHENTICATE

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/plugins", tags=["plugin-config"])

# --------------------------------------------------------------------- models


class PluginSchemaResponse(BaseModel):
    """What the plugin declares: settings, collections and actions."""

    plugin: str
    schema_version: int
    settings: list[dict[str, Any]] = Field(default_factory=list)
    collections: list[dict[str, Any]] = Field(default_factory=list)
    actions: list[dict[str, Any]] = Field(default_factory=list)


class PluginSettingsResponse(BaseModel):
    """Settings rendered as ``{"value": …}`` / ``{"set": bool}`` (never a secret)."""

    plugin: str
    schema_version: int
    values: dict[str, dict[str, Any]] = Field(default_factory=dict)


class PluginItemResponse(BaseModel):
    """One collection item: its id plus the same ``value``/``set`` shape."""

    id: str
    values: dict[str, dict[str, Any]] = Field(default_factory=dict)


class PluginCollectionResponse(BaseModel):
    """A whole collection, with ``max_items`` so a client can show ``n/max``."""

    plugin: str
    collection: str
    schema_version: int
    max_items: int
    items: list[PluginItemResponse] = Field(default_factory=list)


class PluginActionResponse(BaseModel):
    """Outcome of an action: inline (``200``) or via the task store (``202``)."""

    plugin: str
    action: str
    status: str
    task_id: str | None = None
    result: Any = None


class ValuesPayload(BaseModel):
    """Body of a settings or collection write.

    ``values`` is deliberately an untyped mapping: the schema of the plugin —not
    pydantic— decides whether a key is valid, and the transport has to be able to
    look at the keys *before* any validation runs (scope rule). Extra top-level
    keys are ignored rather than echoed back in a ``422``.
    """

    values: dict[str, Any] = Field(default_factory=dict)


class ParametersPayload(BaseModel):
    """Body of an action call; same reasoning as :class:`ValuesPayload`."""

    parameters: dict[str, Any] = Field(default_factory=dict)


#: ``responses`` blocks, one per group of routes, so ``/docs`` says what fails.
_NOT_FOUND = {404: {"description": "The plugin, the collection or the action is not declared"}}
_CANNOT_SERVE = {
    409: {
        "description": (
            "The plugin cannot serve this now: broken package, invalid schema, "
            "full collection, or an action on a plugin that is not loaded"
        )
    }
}
_READ_ERRORS = {**_NOT_FOUND, **_CANNOT_SERVE}
_FORBIDDEN = {
    403: {"description": "The token's scope cannot write secrets or run this action"}
}
_VALIDATION = {
    422: {
        "description": (
            "The values break the declared schema; `detail` is "
            "`{\"field\": …, \"message\": …}`"
        )
    }
}
_WRITE_ERRORS = {**_READ_ERRORS, **_FORBIDDEN, **_VALIDATION}
_ACTION_ERRORS = {
    **_WRITE_ERRORS,
    503: {"description": "No task store in this process for a long-running action"},
}


# ----------------------------------------------------------------- dependency


def get_config_service(request: Request) -> PluginConfigService:
    """Build the configuration service for ``request`` from ``app.state``.

    Args:
        request: The incoming request.

    Returns:
        A service over the process' plugin loader, task store and event bus. The
        loader is required (``503`` otherwise, the same criterion ``POST
        /plugins/{name}/toggle`` uses); the store and the bus are optional —
        only a long action needs the first one and only the audit trail the
        second one.

    Raises:
        HTTPException: ``503`` when the process has no plugin loader.
    """
    loader = getattr(request.app.state, "plugin_loader", None)
    if loader is None:
        raise HTTPException(status_code=503, detail="plugin_loader not available")
    manager = getattr(request.app.state, "session_manager", None)
    store = getattr(manager, "task_store", None) if manager is not None else None
    if store is None:
        store = getattr(request.app.state, "task_store", None)
    return PluginConfigService(
        loader, task_store=store, hook_bus=getattr(request.app.state, "hook_bus", None)
    )


# -------------------------------------------------------------- scope matrix


def _scope(request: Request) -> str:
    """Return the scope of the token that authenticated ``request``.

    ``""`` when the middleware did not set one: an unknown scope is treated as
    insufficient by both checks below (fail closed).
    """
    return str(getattr(request.state, "scope", "") or "")


def _forbidden(detail: str) -> HTTPException:
    """Build the ``403`` of the scope matrix (same challenge header as auth)."""
    return HTTPException(
        status_code=403, detail=detail, headers={"WWW-Authenticate": WWW_AUTHENTICATE}
    )


def _check_secret_scope(
    request: Request, fields: Sequence[FieldSpec], values: Mapping[str, Any]
) -> None:
    """Refuse an ``agent`` write that carries a declared secret field.

    Runs **before** the service validates the body: with an ``agent`` token the
    request is rejected without looking at the values, so no ``422`` can describe
    a secret. The message is the specific one from ``config_schema`` — not the
    generic scope body — because the schema is public (the field *is* secret) and
    "use the Web UI or the CLI" is the fix the client needs.

    Args:
        request: Incoming request (its ``state.scope`` is the caller's scope).
        fields: Declared fields of the object being written.
        values: Whatever the body carried.

    Raises:
        HTTPException: ``403`` with ``SECRET_WRITE_REQUIRES_FULL_DETAIL``.
    """
    if secret_keys(fields, values) and _scope(request) != SCOPE_FULL:
        raise _forbidden(SECRET_WRITE_REQUIRES_FULL_DETAIL)


def _check_action_scope(request: Request, spec: ActionSpec) -> None:
    """Refuse an action that requires ``full`` when the token is ``agent``.

    Args:
        request: Incoming request (its ``state.scope`` is the caller's scope).
        spec: The declared action.

    Raises:
        HTTPException: ``403`` with the generic ``FORBIDDEN_SCOPE_DETAIL`` — the
            specific secret message would be misleading here, no field is being
            written.
    """
    if action_scope(spec) == SCOPE_FULL and _scope(request) != SCOPE_FULL:
        raise _forbidden(FORBIDDEN_SCOPE_DETAIL)


# ---------------------------------------------------------------- translation


async def _call(name: str, operation: Awaitable[Any]) -> Any:
    """Await a service call, translating its errors to the contract's codes.

    The mapping itself lives in ``config_service.error_response`` (one site); this
    wrapper only turns it into an ``HTTPException``. Anything the plugin raised
    that the contract does not know becomes the fixed ``500`` body, with the
    traceback **only** in the log.

    Args:
        name: Plugin name (the ``500`` body quotes it).
        operation: Coroutine of the service.

    Returns:
        Whatever the service returned.
    """
    try:
        return await operation
    except (PluginConfigError, SchemaViolation, PluginValidationError) as exc:
        status_code, detail = error_response(exc, plugin=name)
        raise HTTPException(status_code=status_code, detail=detail) from None
    except Exception:  # boundary: plugin code, never a 500 with a trace in the body
        logger.exception("plugin '%s' failed while handling a configuration request", name)
        raise HTTPException(status_code=500, detail=f"plugin '{name}' failed") from None


# -------------------------------------------------------------------- schema


@router.get(
    "/{name}/schema",
    response_model=PluginSchemaResponse,
    summary="Configuration schema the plugin declares",
    description=(
        "Empty lists when the plugin declares no configuration (a `200`, never a "
        "`404`: clients have one code path). The schema is public and never "
        "contains a secret value."
    ),
    responses=_READ_ERRORS,
)
async def get_plugin_schema(
    name: str, service: PluginConfigService = Depends(get_config_service)
) -> dict[str, Any]:
    """Return the schema of plugin ``name``."""
    return await _call(name, service.schema(name))


# ------------------------------------------------------------------ settings


@router.get(
    "/{name}/settings",
    response_model=PluginSettingsResponse,
    summary="Read the plugin's settings (secrets as `set`/`unset`)",
    responses=_READ_ERRORS,
)
async def get_plugin_settings(
    name: str, service: PluginConfigService = Depends(get_config_service)
) -> dict[str, Any]:
    """Return the settings rendered as ``{"value"}/{"set"}``."""
    return await _call(name, service.read_settings(name))


@router.patch(
    "/{name}/settings",
    response_model=PluginSettingsResponse,
    summary="Write some settings (partial)",
    description=(
        "Only the keys sent are written; a key that is not sent is not touched. "
        "Writing a `secret` field needs a token of scope `full`: with an `agent` "
        "token the answer is `403` **before** the body is validated."
    ),
    responses=_WRITE_ERRORS,
)
async def patch_plugin_settings(
    name: str,
    payload: ValuesPayload,
    request: Request,
    service: PluginConfigService = Depends(get_config_service),
) -> dict[str, Any]:
    """Write the settings present in the body and return the settings again."""
    declared = await _call(name, service.declared_schema(name))
    _check_secret_scope(request, declared.settings, payload.values)
    return await _call(
        name, service.write_settings(name, payload.values, scope=_scope(request))
    )


# --------------------------------------------------------------- collections


@router.get(
    "/{name}/collections/{collection}",
    response_model=PluginCollectionResponse,
    summary="Read one collection of the plugin",
    responses=_READ_ERRORS,
)
async def get_plugin_collection(
    name: str,
    collection: str,
    service: PluginConfigService = Depends(get_config_service),
) -> dict[str, Any]:
    """Return the items of ``collection`` with their ``max_items``."""
    return await _call(name, service.list_items(name, collection))


@router.post(
    "/{name}/collections/{collection}",
    response_model=PluginItemResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create one item in a collection",
    description=(
        "`409` when the collection already holds `max_items` items (the server "
        "checks it without asking the plugin); the plugin's own rules still "
        "answer `422` with its message. A `secret` field needs scope `full`."
    ),
    responses=_WRITE_ERRORS,
)
async def post_plugin_collection_item(
    name: str,
    collection: str,
    payload: ValuesPayload,
    request: Request,
    service: PluginConfigService = Depends(get_config_service),
) -> dict[str, Any]:
    """Create one item and return it rendered."""
    declared = await _call(name, service.declared_schema(name))
    spec = declared.collection(collection)
    if spec is not None:  # undeclared: the service answers the documented 404
        _check_secret_scope(request, spec.item, payload.values)
    return await _call(
        name,
        service.create_item(name, collection, payload.values, scope=_scope(request)),
    )


@router.patch(
    "/{name}/collections/{collection}/{item_id}",
    response_model=PluginItemResponse,
    summary="Change some fields of one item (partial)",
    responses=_WRITE_ERRORS,
)
async def patch_plugin_collection_item(
    name: str,
    collection: str,
    item_id: str,
    payload: ValuesPayload,
    request: Request,
    service: PluginConfigService = Depends(get_config_service),
) -> dict[str, Any]:
    """Write the fields present in the body and return the item rendered."""
    declared = await _call(name, service.declared_schema(name))
    spec = declared.collection(collection)
    if spec is not None:
        _check_secret_scope(request, spec.item, payload.values)
    return await _call(
        name,
        service.update_item(name, collection, item_id, payload.values, scope=_scope(request)),
    )


@router.delete(
    "/{name}/collections/{collection}/{item_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    response_model=None,
    summary="Delete one item",
    responses=_READ_ERRORS,
)
async def delete_plugin_collection_item(
    name: str,
    collection: str,
    item_id: str,
    request: Request,
    service: PluginConfigService = Depends(get_config_service),
) -> None:
    """Delete ``item_id`` from ``collection`` (``404`` when it is already gone)."""
    await _call(name, service.delete_item(name, collection, item_id, scope=_scope(request)))


# ------------------------------------------------------------------- actions


@router.post(
    "/{name}/actions/{action}",
    response_model=PluginActionResponse,
    response_model_exclude_none=True,
    summary="Run one action the plugin declares",
    description=(
        "`200` with the result when the action is short; `202` with a `task_id` "
        "when it declares `long_running` (the result then lands in "
        "`GET /api/v1/tasks/{task_id}`). An action that requires the `full` scope "
        "answers `403` to an `agent` token, and no action runs on a plugin that "
        "is not loaded (`409`)."
    ),
    responses=_ACTION_ERRORS,
)
async def post_plugin_action(
    name: str,
    action: str,
    payload: ParametersPayload,
    request: Request,
    response: Response,
    service: PluginConfigService = Depends(get_config_service),
) -> dict[str, Any]:
    """Run ``action`` and report whether it completed or is running."""
    declared = await _call(name, service.declared_schema(name))
    spec = declared.action(action)
    if spec is not None:  # undeclared: the service answers the documented 404
        _check_action_scope(request, spec)
    result = await _call(
        name,
        service.run_action(name, action, payload.parameters, scope=_scope(request)),
    )
    if result.get("status") == "running":
        response.status_code = status.HTTP_202_ACCEPTED
    return result


__all__ = [
    "ParametersPayload",
    "PluginActionResponse",
    "PluginCollectionResponse",
    "PluginItemResponse",
    "PluginSchemaResponse",
    "PluginSettingsResponse",
    "ValuesPayload",
    "get_config_service",
    "router",
]
