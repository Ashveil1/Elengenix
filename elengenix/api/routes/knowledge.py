"""elengenix.api.routes.knowledge — Knowledge-base documents + semantic search.

Ports PentAGI's ``/knowledge/*`` REST endpoints (originally GraphQL
mutations ``createKnowledgeDocument`` / ``deleteKnowledgeDocument`` /
``searchKnowledge`` — see Task 1-c recommendation §2).

Routes
------
* ``GET    /knowledge/documents``         — list documents (paginated).
* ``POST   /knowledge/documents``         — upload a document. Accepts
                                            multipart/form-data (file
                                            upload) or JSON (text/URL).
* ``DELETE /knowledge/documents/{id}``    — delete a document (also
                                            removes its chunks from the
                                            vector store).
* ``POST   /knowledge/search``            — semantic search across all
                                            documents. Returns top-K
                                            hits with snippets + scores.

All routes are ``auth_token_required`` — both API tokens and sessions
are accepted.

The actual storage layer (vector DB + metadata DB) is provided by
``app.state.knowledge`` (a ``KnowledgeStore`` protocol implementation
added by a future task). The route layer is responsible for request
validation, response envelope formatting, and calling the store.
"""

from __future__ import annotations

import logging
import time
from typing import Any, Optional

from fastapi import (
    APIRouter,
    Depends,
    File,
    Form,
    Request,
    UploadFile,
)
from fastapi.responses import JSONResponse

from .._auth import Identity, auth_token_required
from .._models import (
    KnowledgeDocumentPublic,
    KnowledgeSearchHit,
    KnowledgeSearchRequest,
    KnowledgeSearchResponse,
    Page,
    error_response,
    success_response,
)

logger = logging.getLogger("elengenix.api.routes.knowledge")

router = APIRouter(prefix="/knowledge", tags=["knowledge"])

# Upload size cap — PentAGI uses 32 MB for multipart memory buffer.
MAX_UPLOAD_BYTES = 32 * 1024 * 1024


# ---------------------------------------------------------------------------
# GET /knowledge/documents
# ---------------------------------------------------------------------------


@router.get("/documents", summary="List knowledge documents (paginated)")
async def list_documents(
    request: Request,
    page: int = 1,
    per_page: int = 20,
    identity: Identity = Depends(auth_token_required),
) -> dict[str, Any]:
    """Return a paginated list of the user's knowledge documents."""
    p = Page(page=page, per_page=per_page)
    store = getattr(request.app.state, "knowledge", None)
    if store is None:
        return success_response(
            {"items": [], "page": p.page, "per_page": p.per_page, "total": 0}
        )
    try:
        rows: list[dict[str, Any]] = await store.list_documents(
            user_id=identity.user_id,
            offset=p.offset,
            limit=p.per_page,
        )
        total: int = await store.count_documents(identity.user_id)
    except Exception as exc:
        logger.exception("knowledge.list_documents failed")
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
# POST /knowledge/documents
# ---------------------------------------------------------------------------


@router.post("/documents", summary="Upload a knowledge document")
async def upload_document(
    request: Request,
    identity: Identity = Depends(auth_token_required),
    title: Optional[str] = Form(default=None),
    url: Optional[str] = Form(default=None),
    text: Optional[str] = Form(default=None),
    file: Optional[UploadFile] = File(default=None),
) -> JSONResponse:
    """Upload a document to the knowledge base.

    Accepts one of three payload shapes (mutually exclusive):

    * ``file``  — multipart/form-data file upload (binary content).
    * ``url``   — fetch the document from a URL (server-side).
    * ``text``  — raw text body.

    The document is queued for asynchronous processing (extraction,
    chunking, embedding). The response returns the document row with
    ``status="queued"``.
    """
    develop = bool(getattr(request.app.state, "develop", False))
    store = getattr(request.app.state, "knowledge", None)
    if store is None:
        return JSONResponse(
            status_code=503,
            content=error_response(
                "service_unavailable",
                "Knowledge store not configured",
                develop=develop,
            ),
        )

    # Pick the payload source — exactly one is required.
    if file is not None:
        content = await file.read()
        if len(content) > MAX_UPLOAD_BYTES:
            return JSONResponse(
                status_code=413,
                content=error_response(
                    "bad_request",
                    f"Upload too large: {len(content)} bytes "
                    f"(max {MAX_UPLOAD_BYTES})",
                    develop=develop,
                ),
            )
        doc_title = title or (file.filename or "uploaded-file")
        mime = file.content_type or "application/octet-stream"
        try:
            row = await store.create_document_from_bytes(
                user_id=identity.user_id,
                title=doc_title,
                content=content,
                mime_type=mime,
                filename=file.filename,
            )
        except Exception as exc:
            logger.exception("create_document_from_bytes failed")
            return JSONResponse(
                status_code=500,
                content=error_response(
                    "internal",
                    "Failed to store document",
                    error=str(exc),
                    develop=develop,
                ),
            )
    elif url:
        try:
            row = await store.create_document_from_url(
                user_id=identity.user_id,
                title=title or url,
                url=url,
            )
        except Exception as exc:
            logger.exception("create_document_from_url failed")
            return JSONResponse(
                status_code=500,
                content=error_response(
                    "internal",
                    "Failed to fetch URL",
                    error=str(exc),
                    develop=develop,
                ),
            )
    elif text is not None and text:
        try:
            row = await store.create_document_from_text(
                user_id=identity.user_id,
                title=title or "inline-text",
                text=text,
            )
        except Exception as exc:
            logger.exception("create_document_from_text failed")
            return JSONResponse(
                status_code=500,
                content=error_response(
                    "internal",
                    "Failed to store text",
                    error=str(exc),
                    develop=develop,
                ),
            )
    else:
        return JSONResponse(
            status_code=400,
            content=error_response(
                "bad_request",
                "Must provide one of: file, url, or text",
                develop=develop,
            ),
        )

    return JSONResponse(
        status_code=201,
        content=success_response(_row_to_public(row).model_dump()),
    )


# ---------------------------------------------------------------------------
# DELETE /knowledge/documents/{id}
# ---------------------------------------------------------------------------


@router.delete("/documents/{doc_id}", summary="Delete a knowledge document")
async def delete_document(
    doc_id: int,
    request: Request,
    identity: Identity = Depends(auth_token_required),
) -> JSONResponse:
    """Delete a document AND all its vector chunks.

    Idempotent — deleting a non-existent ID returns 404. Deleting an
    already-deleted document returns 200 (mirrors PentAGI).
    """
    develop = bool(getattr(request.app.state, "develop", False))
    store = getattr(request.app.state, "knowledge", None)
    if store is None:
        return JSONResponse(
            status_code=503,
            content=error_response(
                "service_unavailable",
                "Knowledge store not configured",
                develop=develop,
            ),
        )

    try:
        deleted: bool = await store.delete_document(
            doc_id=doc_id, user_id=identity.user_id
        )
    except Exception as exc:
        logger.exception("delete_document failed")
        return JSONResponse(
            status_code=500,
            content=error_response(
                "internal",
                "Failed to delete document",
                error=str(exc),
                develop=develop,
            ),
        )

    if not deleted:
        return JSONResponse(
            status_code=404,
            content=error_response(
                "not_found",
                f"Document not found: {doc_id}",
                develop=develop,
            ),
        )

    return JSONResponse(
        status_code=200,
        content=success_response({"deleted": True, "id": doc_id}),
    )


# ---------------------------------------------------------------------------
# POST /knowledge/search
# ---------------------------------------------------------------------------


@router.post("/search", summary="Semantic search across the knowledge base")
async def search_knowledge(
    body: KnowledgeSearchRequest,
    request: Request,
    identity: Identity = Depends(auth_token_required),
) -> JSONResponse:
    """Run a semantic search across all of the user's documents.

    Returns top-K hits with snippets + scores in the
    ``KnowledgeSearchResponse`` shape.
    """
    develop = bool(getattr(request.app.state, "develop", False))
    store = getattr(request.app.state, "knowledge", None)
    if store is None:
        return JSONResponse(
            status_code=503,
            content=error_response(
                "service_unavailable",
                "Knowledge store not configured",
                develop=develop,
            ),
        )

    t0 = time.time()
    try:
        hits_raw: list[dict[str, Any]] = await store.search(
            user_id=identity.user_id,
            query=body.query,
            top_k=body.top_k,
            min_score=body.min_score,
        )
    except Exception as exc:
        logger.exception("knowledge.search failed")
        return JSONResponse(
            status_code=500,
            content=error_response(
                "internal",
                "Search failed",
                error=str(exc),
                develop=develop,
            ),
        )

    hits = [
        KnowledgeSearchHit(
            document_id=int(h.get("document_id", 0)),
            title=str(h.get("title", "")),
            snippet=str(h.get("snippet", "")),
            score=float(h.get("score", 0.0)),
            metadata=dict(h.get("metadata", {}) or {}),
        )
        for h in hits_raw
    ]
    response = KnowledgeSearchResponse(
        query=body.query,
        hits=hits,
        took_ms=int((time.time() - t0) * 1000),
    )
    return JSONResponse(
        status_code=200,
        content=success_response(response.model_dump()),
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _row_to_public(row: dict[str, Any]) -> KnowledgeDocumentPublic:
    """Coerce a raw store row into a ``KnowledgeDocumentPublic`` model."""
    return KnowledgeDocumentPublic(
        id=int(row.get("id", 0)),
        title=str(row.get("title", "")),
        type=str(row.get("type", "file")),
        mime_type=str(row.get("mime_type")) if row.get("mime_type") else None,
        size_bytes=int(row.get("size_bytes", 0)),
        status=str(row.get("status", "queued")),
        created_at=int(row.get("created_at", 0)),
        updated_at=(
            int(row["updated_at"]) if row.get("updated_at") else None
        ),
        checksum=str(row.get("checksum")) if row.get("checksum") else None,
    )


__all__ = ["router"]
