"""elengenix.api.routes.flows — Flow lifecycle + related-resource listing.

Ports PentAGI's ``/flows/*`` REST endpoints (originally GraphQL
mutations ``createFlow`` / ``putUserInput`` / ``stopFlow`` /
``deleteFlow`` / ``renameFlow``, plus GraphQL queries for tasks,
subtasks, containers, toolcalls, msglogs, termlogs, searchlogs,
screenshots, usage — see Task 1-c recommendation §2).

Routes
------
* ``POST   /flows``                 — create a new flow (kicks off the
                                      orchestrator asynchronously).
* ``GET    /flows``                 — list flows (paginated).
* ``GET    /flows/{id}``            — get a single flow.
* ``PUT    /flows/{id}``            — update a flow (rename, etc.).
* ``DELETE /flows/{id}``            — delete a flow (cascades to
                                      related rows + stops containers).
* ``GET    /flows/{id}/graph``      — knowledge-graph data for the flow.
* ``GET    /flows/{id}/tasks``      — list tasks in the flow.
* ``GET    /flows/{id}/subtasks``   — list subtasks.
* ``GET    /flows/{id}/containers`` — list containers.
* ``GET    /flows/{id}/toolcalls``  — list tool calls.
* ``GET    /flows/{id}/msglogs``    — list message logs.
* ``GET    /flows/{id}/termlogs``   — list terminal logs.
* ``GET    /flows/{id}/searchlogs`` — list search logs.
* ``GET    /flows/{id}/screenshots``— list screenshots.
* ``GET    /flows/{id}/usage``      — token usage for the flow.
* ``POST   /flows/{id}/input``      — submit user input to a running
                                      flow.
* ``POST   /flows/{id}/stop``       — stop a running flow.
* ``GET    /flows/{id}/report``     — fetch the flow's report
                                      (markdown/PDF/HTML).

All routes are ``auth_token_required`` — both API tokens and sessions
are accepted. The flow store + orchestrator are provided by
``app.state.flows`` and ``app.state.orchestrator`` respectively (added
by future tasks).
"""

from __future__ import annotations

import logging
import time
from typing import Any, Optional

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import JSONResponse, PlainTextResponse

from .._auth import Identity, auth_token_required
from .._models import (
    CreateFlowRequest,
    FlowInputRequest,
    FlowPublic,
    FlowReportFormat,
    Page,
    UpdateFlowRequest,
    error_response,
    success_response,
)

logger = logging.getLogger("elengenix.api.routes.flows")

router = APIRouter(prefix="/flows", tags=["flows"])


# ---------------------------------------------------------------------------
# POST /flows — create
# ---------------------------------------------------------------------------


@router.post("", summary="Create and start a new flow")
async def create_flow(
    body: CreateFlowRequest,
    request: Request,
    identity: Identity = Depends(auth_token_required),
) -> JSONResponse:
    """Create a new flow. The orchestrator starts processing
    asynchronously — the response returns immediately with
    ``status="created"`` or ``status="running"``."""
    develop = bool(getattr(request.app.state, "develop", False))
    flows = getattr(request.app.state, "flows", None)
    if flows is None:
        return JSONResponse(
            status_code=503,
            content=error_response(
                "service_unavailable",
                "Flow store not configured",
                develop=develop,
            ),
        )

    try:
        row = await flows.create_flow(
            user_id=identity.user_id,
            title=body.title,
            input=body.input,
            model=body.model,
            language=body.language,
            image=body.image,
        )
    except Exception as exc:
        logger.exception("flows.create_flow failed")
        return JSONResponse(
            status_code=500,
            content=error_response(
                "internal",
                "Failed to create flow",
                error=str(exc),
                develop=develop,
            ),
        )

    # Kick off the orchestrator asynchronously. The orchestrator is
    # optional — if not wired, the flow remains in ``created`` status
    # until a separate worker picks it up.
    orchestrator = getattr(request.app.state, "orchestrator", None)
    if orchestrator is not None:
        try:
            await orchestrator.start_flow(flow_id=int(row["id"]))
        except Exception:
            logger.exception("orchestrator.start_flow failed")

    return JSONResponse(
        status_code=201,
        content=success_response(_row_to_public(row).model_dump()),
    )


# ---------------------------------------------------------------------------
# GET /flows — list (paginated)
# ---------------------------------------------------------------------------


@router.get("", summary="List flows (paginated)")
async def list_flows(
    request: Request,
    page: int = Query(default=1, ge=1),
    per_page: int = Query(default=20, ge=1, le=100),
    status: Optional[str] = Query(default=None),
    identity: Identity = Depends(auth_token_required),
) -> dict[str, Any]:
    """Return a paginated list of the user's flows."""
    p = Page(page=page, per_page=per_page)
    flows = getattr(request.app.state, "flows", None)
    if flows is None:
        return success_response(
            {"items": [], "page": p.page, "per_page": p.per_page, "total": 0}
        )

    try:
        rows = await flows.list_flows(
            user_id=identity.user_id,
            offset=p.offset,
            limit=p.per_page,
            status=status,
        )
        total = await flows.count_flows(identity.user_id, status=status)
    except Exception as exc:
        logger.exception("flows.list_flows failed")
        return success_response(
            {"items": [], "page": p.page, "per_page": p.per_page, "total": 0}
        )

    items = [_row_to_public(r).model_dump() for r in rows]
    return success_response(
        {
            "items": items,
            "page": p.page,
            "per_page": p.per_page,
            "total": total,
        }
    )


# ---------------------------------------------------------------------------
# GET /flows/{id} — get
# ---------------------------------------------------------------------------


@router.get("/{flow_id}", summary="Get a single flow")
async def get_flow(
    flow_id: int,
    request: Request,
    identity: Identity = Depends(auth_token_required),
) -> JSONResponse:
    """Return the full flow record. 404 if not found or not owned."""
    develop = bool(getattr(request.app.state, "develop", False))
    flows = getattr(request.app.state, "flows", None)
    if flows is None:
        return JSONResponse(
            status_code=503,
            content=error_response(
                "service_unavailable",
                "Flow store not configured",
                develop=develop,
            ),
        )
    try:
        row = await flows.get_flow(flow_id=flow_id, user_id=identity.user_id)
    except Exception as exc:
        logger.exception("flows.get_flow failed")
        return JSONResponse(
            status_code=500,
            content=error_response(
                "internal",
                "Failed to fetch flow",
                error=str(exc),
                develop=develop,
            ),
        )
    if not row:
        return JSONResponse(
            status_code=404,
            content=error_response(
                "flow_not_found",
                f"Flow not found: {flow_id}",
                develop=develop,
            ),
        )
    return JSONResponse(
        status_code=200,
        content=success_response(_row_to_public(row).model_dump()),
    )


# ---------------------------------------------------------------------------
# PUT /flows/{id} — update (rename, etc.)
# ---------------------------------------------------------------------------


@router.put("/{flow_id}", summary="Update a flow (rename, etc.)")
async def update_flow(
    flow_id: int,
    body: UpdateFlowRequest,
    request: Request,
    identity: Identity = Depends(auth_token_required),
) -> JSONResponse:
    """Update flow metadata (currently only ``title``).

    Returns the updated flow. 404 if not found.
    """
    develop = bool(getattr(request.app.state, "develop", False))
    flows = getattr(request.app.state, "flows", None)
    if flows is None:
        return JSONResponse(
            status_code=503,
            content=error_response(
                "service_unavailable",
                "Flow store not configured",
                develop=develop,
            ),
        )
    try:
        row = await flows.update_flow(
            flow_id=flow_id,
            user_id=identity.user_id,
            title=body.title,
        )
    except Exception as exc:
        logger.exception("flows.update_flow failed")
        return JSONResponse(
            status_code=500,
            content=error_response(
                "internal",
                "Failed to update flow",
                error=str(exc),
                develop=develop,
            ),
        )
    if not row:
        return JSONResponse(
            status_code=404,
            content=error_response(
                "flow_not_found",
                f"Flow not found: {flow_id}",
                develop=develop,
            ),
        )
    return JSONResponse(
        status_code=200,
        content=success_response(_row_to_public(row).model_dump()),
    )


# ---------------------------------------------------------------------------
# DELETE /flows/{id} — delete
# ---------------------------------------------------------------------------


@router.delete("/{flow_id}", summary="Delete a flow")
async def delete_flow(
    flow_id: int,
    request: Request,
    identity: Identity = Depends(auth_token_required),
) -> JSONResponse:
    """Delete a flow. Cascades to tasks, subtasks, containers, logs,
    screenshots, usage. Also stops any running containers via the
    orchestrator's ``cleanup_flow`` hook."""
    develop = bool(getattr(request.app.state, "develop", False))
    flows = getattr(request.app.state, "flows", None)
    if flows is None:
        return JSONResponse(
            status_code=503,
            content=error_response(
                "service_unavailable",
                "Flow store not configured",
                develop=develop,
            ),
        )

    # Stop running containers first (best-effort).
    orchestrator = getattr(request.app.state, "orchestrator", None)
    if orchestrator is not None:
        try:
            await orchestrator.cleanup_flow(flow_id=flow_id)
        except Exception:
            logger.exception("orchestrator.cleanup_flow failed")

    try:
        deleted: bool = await flows.delete_flow(
            flow_id=flow_id, user_id=identity.user_id
        )
    except Exception as exc:
        logger.exception("flows.delete_flow failed")
        return JSONResponse(
            status_code=500,
            content=error_response(
                "internal",
                "Failed to delete flow",
                error=str(exc),
                develop=develop,
            ),
        )

    if not deleted:
        return JSONResponse(
            status_code=404,
            content=error_response(
                "flow_not_found",
                f"Flow not found: {flow_id}",
                develop=develop,
            ),
        )
    return JSONResponse(
        status_code=200,
        content=success_response({"deleted": True, "id": flow_id}),
    )


# ---------------------------------------------------------------------------
# GET /flows/{id}/graph — knowledge graph data
# ---------------------------------------------------------------------------


@router.get("/{flow_id}/graph", summary="Get flow knowledge-graph data")
async def get_flow_graph(
    flow_id: int,
    request: Request,
    identity: Identity = Depends(auth_token_required),
) -> JSONResponse:
    """Return the flow's knowledge graph (nodes + edges) for the UI
    visualiser. Returns an empty graph if the flow has no graph yet."""
    develop = bool(getattr(request.app.state, "develop", False))
    flows = getattr(request.app.state, "flows", None)
    if flows is None or not hasattr(flows, "get_graph"):
        return JSONResponse(
            status_code=200,
            content=success_response({"nodes": [], "edges": []}),
        )
    try:
        graph = await flows.get_graph(flow_id=flow_id, user_id=identity.user_id)
    except Exception as exc:
        logger.exception("flows.get_graph failed")
        return JSONResponse(
            status_code=200,
            content=success_response({"nodes": [], "edges": []}),
        )
    if not graph:
        return JSONResponse(
            status_code=404,
            content=error_response(
                "flow_not_found",
                f"Flow not found: {flow_id}",
                develop=develop,
            ),
        )
    return JSONResponse(status_code=200, content=success_response(graph))


# ---------------------------------------------------------------------------
# Generic related-resource lister — backs all the /flows/{id}/<related>
# endpoints (tasks, subtasks, containers, toolcalls, msglogs, termlogs,
# searchlogs, screenshots).
# ---------------------------------------------------------------------------


async def _list_related(
    *,
    request: Request,
    flow_id: int,
    identity: Identity,
    relation: str,
    page: int,
    per_page: int,
) -> dict[str, Any]:
    """Shared lister for all the ``/flows/{id}/<relation>`` endpoints.

    Calls ``flows.list_<relation>(flow_id, user_id, offset, limit)``.
    Returns an empty page on any error (so the UI doesn't crash).
    """
    p = Page(page=page, per_page=per_page)
    flows = getattr(request.app.state, "flows", None)
    if flows is None:
        return _empty_page(p)
    method_name = f"list_{relation}"
    method = getattr(flows, method_name, None)
    if method is None:
        return _empty_page(p)
    try:
        items = await method(
            flow_id=flow_id,
            user_id=identity.user_id,
            offset=p.offset,
            limit=p.per_page,
        )
    except Exception:
        logger.exception("flows.%s failed", method_name)
        return _empty_page(p)
    return {
        "items": list(items or []),
        "page": p.page,
        "per_page": p.per_page,
        "total": len(items or []),
    }


def _empty_page(p: Page) -> dict[str, Any]:
    return {"items": [], "page": p.page, "per_page": p.per_page, "total": 0}


@router.get("/{flow_id}/tasks", summary="List tasks in a flow")
async def list_flow_tasks(
    flow_id: int,
    request: Request,
    page: int = Query(default=1, ge=1),
    per_page: int = Query(default=50, ge=1, le=200),
    identity: Identity = Depends(auth_token_required),
) -> dict[str, Any]:
    return success_response(
        await _list_related(
            request=request,
            flow_id=flow_id,
            identity=identity,
            relation="tasks",
            page=page,
            per_page=per_page,
        )
    )


@router.get("/{flow_id}/subtasks", summary="List subtasks in a flow")
async def list_flow_subtasks(
    flow_id: int,
    request: Request,
    page: int = Query(default=1, ge=1),
    per_page: int = Query(default=50, ge=1, le=200),
    identity: Identity = Depends(auth_token_required),
) -> dict[str, Any]:
    return success_response(
        await _list_related(
            request=request,
            flow_id=flow_id,
            identity=identity,
            relation="subtasks",
            page=page,
            per_page=per_page,
        )
    )


@router.get("/{flow_id}/containers", summary="List containers for a flow")
async def list_flow_containers(
    flow_id: int,
    request: Request,
    page: int = Query(default=1, ge=1),
    per_page: int = Query(default=50, ge=1, le=200),
    identity: Identity = Depends(auth_token_required),
) -> dict[str, Any]:
    return success_response(
        await _list_related(
            request=request,
            flow_id=flow_id,
            identity=identity,
            relation="containers",
            page=page,
            per_page=per_page,
        )
    )


@router.get("/{flow_id}/toolcalls", summary="List tool calls in a flow")
async def list_flow_toolcalls(
    flow_id: int,
    request: Request,
    page: int = Query(default=1, ge=1),
    per_page: int = Query(default=50, ge=1, le=200),
    identity: Identity = Depends(auth_token_required),
) -> dict[str, Any]:
    return success_response(
        await _list_related(
            request=request,
            flow_id=flow_id,
            identity=identity,
            relation="toolcalls",
            page=page,
            per_page=per_page,
        )
    )


@router.get("/{flow_id}/msglogs", summary="List message logs in a flow")
async def list_flow_msglogs(
    flow_id: int,
    request: Request,
    page: int = Query(default=1, ge=1),
    per_page: int = Query(default=50, ge=1, le=200),
    identity: Identity = Depends(auth_token_required),
) -> dict[str, Any]:
    return success_response(
        await _list_related(
            request=request,
            flow_id=flow_id,
            identity=identity,
            relation="msglogs",
            page=page,
            per_page=per_page,
        )
    )


@router.get("/{flow_id}/termlogs", summary="List terminal logs in a flow")
async def list_flow_termlogs(
    flow_id: int,
    request: Request,
    page: int = Query(default=1, ge=1),
    per_page: int = Query(default=50, ge=1, le=200),
    identity: Identity = Depends(auth_token_required),
) -> dict[str, Any]:
    return success_response(
        await _list_related(
            request=request,
            flow_id=flow_id,
            identity=identity,
            relation="termlogs",
            page=page,
            per_page=per_page,
        )
    )


@router.get("/{flow_id}/searchlogs", summary="List search logs in a flow")
async def list_flow_searchlogs(
    flow_id: int,
    request: Request,
    page: int = Query(default=1, ge=1),
    per_page: int = Query(default=50, ge=1, le=200),
    identity: Identity = Depends(auth_token_required),
) -> dict[str, Any]:
    return success_response(
        await _list_related(
            request=request,
            flow_id=flow_id,
            identity=identity,
            relation="searchlogs",
            page=page,
            per_page=per_page,
        )
    )


@router.get("/{flow_id}/screenshots", summary="List screenshots in a flow")
async def list_flow_screenshots(
    flow_id: int,
    request: Request,
    page: int = Query(default=1, ge=1),
    per_page: int = Query(default=50, ge=1, le=200),
    identity: Identity = Depends(auth_token_required),
) -> dict[str, Any]:
    return success_response(
        await _list_related(
            request=request,
            flow_id=flow_id,
            identity=identity,
            relation="screenshots",
            page=page,
            per_page=per_page,
        )
    )


# ---------------------------------------------------------------------------
# GET /flows/{id}/usage — token usage
# ---------------------------------------------------------------------------


@router.get("/{flow_id}/usage", summary="Get token usage for a flow")
async def get_flow_usage(
    flow_id: int,
    request: Request,
    identity: Identity = Depends(auth_token_required),
) -> JSONResponse:
    """Return aggregated token usage for the flow.

    Shape mirrors PentAGI's GraphQL ``usageStatsByFlow`` query:

    ```
    {
      "total_tokens": 12345,
      "input_tokens": 10000,
      "output_tokens": 2345,
      "by_model": [{"model": "gpt-4o", "tokens": 12345, ...}],
      "by_agent": [{"agent": "primary", "tokens": 12345, ...}]
    }
    ```
    """
    develop = bool(getattr(request.app.state, "develop", False))
    flows = getattr(request.app.state, "flows", None)
    if flows is None or not hasattr(flows, "get_usage"):
        return JSONResponse(
            status_code=200,
            content=success_response(
                {
                    "total_tokens": 0,
                    "input_tokens": 0,
                    "output_tokens": 0,
                    "by_model": [],
                    "by_agent": [],
                }
            ),
        )
    try:
        usage = await flows.get_usage(
            flow_id=flow_id, user_id=identity.user_id
        )
    except Exception as exc:
        logger.exception("flows.get_usage failed")
        return JSONResponse(
            status_code=200,
            content=success_response(
                {
                    "total_tokens": 0,
                    "input_tokens": 0,
                    "output_tokens": 0,
                    "by_model": [],
                    "by_agent": [],
                }
            ),
        )
    if usage is None:
        return JSONResponse(
            status_code=404,
            content=error_response(
                "flow_not_found",
                f"Flow not found: {flow_id}",
                develop=develop,
            ),
        )
    return JSONResponse(status_code=200, content=success_response(usage))


# ---------------------------------------------------------------------------
# POST /flows/{id}/input — submit user input
# ---------------------------------------------------------------------------


@router.post("/{flow_id}/input", summary="Submit user input to a running flow")
async def submit_flow_input(
    flow_id: int,
    body: FlowInputRequest,
    request: Request,
    identity: Identity = Depends(auth_token_required),
) -> JSONResponse:
    """Submit additional user input to a flow that's waiting for it.

    PentAGI's GraphQL ``putUserInput`` mutation. 404 if the flow doesn't
    exist; 409 if the flow isn't in ``waiting`` status.
    """
    develop = bool(getattr(request.app.state, "develop", False))
    flows = getattr(request.app.state, "flows", None)
    if flows is None:
        return JSONResponse(
            status_code=503,
            content=error_response(
                "service_unavailable",
                "Flow store not configured",
                develop=develop,
            ),
        )
    try:
        result = await flows.put_user_input(
            flow_id=flow_id,
            user_id=identity.user_id,
            input=body.input,
            related_to=body.related_to,
        )
    except Exception as exc:
        logger.exception("flows.put_user_input failed")
        return JSONResponse(
            status_code=500,
            content=error_response(
                "internal",
                "Failed to submit input",
                error=str(exc),
                develop=develop,
            ),
        )
    if result is None:
        return JSONResponse(
            status_code=404,
            content=error_response(
                "flow_not_found",
                f"Flow not found: {flow_id}",
                develop=develop,
            ),
        )
    if isinstance(result, dict) and result.get("status") == "conflict":
        return JSONResponse(
            status_code=409,
            content=error_response(
                "conflict",
                result.get(
                    "message", "Flow is not in 'waiting' status"
                ),
                develop=develop,
            ),
        )
    return JSONResponse(
        status_code=200,
        content=success_response(result if isinstance(result, dict) else {}),
    )


# ---------------------------------------------------------------------------
# POST /flows/{id}/stop — stop flow
# ---------------------------------------------------------------------------


@router.post("/{flow_id}/stop", summary="Stop a running flow")
async def stop_flow(
    flow_id: int,
    request: Request,
    identity: Identity = Depends(auth_token_required),
) -> JSONResponse:
    """Stop a running flow. Idempotent — stopping an already-finished
    flow returns 200 with ``stopped=False``."""
    develop = bool(getattr(request.app.state, "develop", False))
    flows = getattr(request.app.state, "flows", None)
    orchestrator = getattr(request.app.state, "orchestrator", None)
    if flows is None:
        return JSONResponse(
            status_code=503,
            content=error_response(
                "service_unavailable",
                "Flow store not configured",
                develop=develop,
            ),
        )

    # First, signal the orchestrator to cancel the running task.
    stopped = False
    if orchestrator is not None and hasattr(orchestrator, "stop_flow"):
        try:
            stopped = bool(await orchestrator.stop_flow(flow_id=flow_id))
        except Exception:
            logger.exception("orchestrator.stop_flow failed")

    # Then mark the flow as ``Finished`` in the DB.
    try:
        result = await flows.stop_flow(
            flow_id=flow_id, user_id=identity.user_id
        )
    except Exception as exc:
        logger.exception("flows.stop_flow failed")
        return JSONResponse(
            status_code=500,
            content=error_response(
                "internal",
                "Failed to stop flow",
                error=str(exc),
                develop=develop,
            ),
        )

    if result is None:
        return JSONResponse(
            status_code=404,
            content=error_response(
                "flow_not_found",
                f"Flow not found: {flow_id}",
                develop=develop,
            ),
        )

    return JSONResponse(
        status_code=200,
        content=success_response(
            {"stopped": True, "id": flow_id, "orchestrator": stopped}
        ),
    )


# ---------------------------------------------------------------------------
# GET /flows/{id}/report — flow report (markdown/PDF)
# ---------------------------------------------------------------------------


@router.get("/{flow_id}/report", summary="Get the flow report")
async def get_flow_report(
    flow_id: int,
    request: Request,
    format: FlowReportFormat = Query(default=FlowReportFormat.MARKDOWN),
    identity: Identity = Depends(auth_token_required),
) -> Any:
    """Fetch the flow's report. ``format`` controls the response:

    * ``markdown`` — ``text/markdown`` plain-text body.
    * ``pdf``      — ``application/pdf`` binary body.
    * ``html``     — ``text/html`` body.

    404 if the flow doesn't exist or has no report yet.
    """
    develop = bool(getattr(request.app.state, "develop", False))
    flows = getattr(request.app.state, "flows", None)
    if flows is None or not hasattr(flows, "get_report"):
        if format == FlowReportFormat.MARKDOWN:
            return PlainTextResponse(
                content=f"# Flow {flow_id}\n\nNo report available.\n",
                media_type="text/markdown",
            )
        return JSONResponse(
            status_code=503,
            content=error_response(
                "service_unavailable",
                "Report generation not configured",
                develop=develop,
            ),
        )

    try:
        report = await flows.get_report(
            flow_id=flow_id,
            user_id=identity.user_id,
            format=format.value,
        )
    except Exception as exc:
        logger.exception("flows.get_report failed")
        return JSONResponse(
            status_code=500,
            content=error_response(
                "internal",
                "Failed to generate report",
                error=str(exc),
                develop=develop,
            ),
        )

    if report is None:
        return JSONResponse(
            status_code=404,
            content=error_response(
                "flow_not_found",
                f"Flow or report not found: {flow_id}",
                develop=develop,
            ),
        )

    if format == FlowReportFormat.MARKDOWN:
        return PlainTextResponse(
            content=str(report),
            media_type="text/markdown",
        )
    if format == FlowReportFormat.HTML:
        return PlainTextResponse(
            content=str(report),
            media_type="text/html",
        )
    # PDF — return as a binary response. ``report`` may be bytes or a
    # base64-encoded string; we delegate that normalisation to the
    # store. If it returns a dict (e.g. {"url": "..."}), pass it
    # through the success envelope.
    if isinstance(report, (bytes, bytearray)):
        from fastapi import Response

        return Response(content=bytes(report), media_type="application/pdf")
    return JSONResponse(
        status_code=200,
        content=success_response(report if isinstance(report, dict) else {
            "report": report,
        }),
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _row_to_public(row: dict[str, Any]) -> FlowPublic:
    """Coerce a raw flow-store row into a ``FlowPublic`` model."""
    return FlowPublic(
        id=int(row.get("id", 0)),
        title=str(row.get("title")) if row.get("title") else None,
        status=str(row.get("status", "created")),
        model=str(row.get("model")) if row.get("model") else None,
        language=str(row.get("language")) if row.get("language") else None,
        image=str(row.get("image")) if row.get("image") else None,
        created_at=int(row.get("created_at", 0)) or int(time.time()),
        updated_at=int(row.get("updated_at", 0)) or int(time.time()),
        finished_at=(
            int(row["finished_at"]) if row.get("finished_at") else None
        ),
    )


__all__ = ["router"]
