"""FastAPI backend."""
from __future__ import annotations

import logging
import time
from contextlib import asynccontextmanager
from typing import Any

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel

from threatiq import __version__
from threatiq.agents.graph import get_graph
from threatiq.agents.orchestrator import AGENTS
from threatiq.config import get_settings
from threatiq.copilot import ask
from threatiq.db.repo import Repository, get_repository, reset_repository
from threatiq.engine import threat_graph as graph_engine
from threatiq.engine.indicators import classify_input, extract_indicators
from threatiq.llm import get_llm
from threatiq.schemas import (
    CopilotRequest, CopilotResponse, InvestigationReport, InvestigationRequest,
    Severity,
)
from threatiq.service import investigate
from threatiq.telemetry import setup_langsmith, setup_logging, setup_opentelemetry
from threatiq.api.throttle import get_inbound_limiter, throttle
from threatiq.tools import registry
from threatiq.tools.ratelimit import RateLimiter

log = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = get_settings()
    setup_logging(settings)
    setup_langsmith(settings)
    setup_opentelemetry(settings, app)
    await get_repository()
    _, backend = get_graph()
    log.info("ThreatIQ %s starting (graph=%s, llm=%s)",
             __version__, backend,
             get_llm().model_name if get_llm().enabled else "disabled")
    yield
    await reset_repository()


app = FastAPI(
    title="ThreatIQ API",
    description="Agentic AI security operations platform.",
    version=__version__,
    lifespan=lifespan,
)

settings = get_settings()
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origin_list,
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)


@app.middleware("http")
async def add_timing(request: Request, call_next):
    start = time.perf_counter()
    response = await call_next(request)
    response.headers["X-Process-Time-Ms"] = str(
        int((time.perf_counter() - start) * 1000)
    )
    # Defence in depth: the API serves JSON and one debug HTML page.
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    return response


async def require_api_key(x_api_key: str | None = Header(default=None)) -> str:
    """Shared-secret auth. An empty configured key disables auth for local dev,
    and that state is reported by /health so it cannot go unnoticed."""
    expected = get_settings().api_key
    if not expected:
        return "anonymous"
    if not x_api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing X-API-Key header",
        )
    # Constant-time compare so the key cannot be recovered by timing.
    import hmac
    if not hmac.compare_digest(x_api_key, expected):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid API key"
        )
    return "api_key_user"


async def repo_dep() -> Repository:
    return await get_repository()


# --------------------------------------------------------------------------
# health / meta
# --------------------------------------------------------------------------

@app.get("/health", tags=["meta"])
async def health() -> dict[str, Any]:
    s = get_settings()
    repo = await get_repository()
    _, backend = get_graph()
    configured = {
        name: registry.configured(name, s) for name in
        [m["name"] for m in registry.describe()]
    }
    return {
        "status": "ok",
        "version": __version__,
        "environment": s.environment,
        "graph_backend": backend,
        "repository": type(repo).__name__,
        "llm": {"enabled": s.llm_enabled, "provider": s.llm_provider,
                "model": get_llm().model_name if s.llm_enabled else None},
        "auth_enabled": bool(s.api_key),
        "tools_configured": configured,
        "tools_unconfigured": [k for k, v in configured.items() if not v],
        "active_scanning": {
            "zap_configured": bool(s.zap_base_url),
            "authorized_targets": sorted(s.authorized_targets),
        },
        # Which sources are being paced, and against what published quota.
        # Worth surfacing: on the free tiers the limiter is the difference
        # between partial coverage and a wall of 429s.
        "rate_limits": {
            "max_wait_s": s.rate_limit_max_wait_s,
            "max_response_bytes": s.max_response_bytes,
            "sources": RateLimiter(s).describe(),
        },
        "inbound_limits": get_inbound_limiter().describe(),
    }


@app.get("/tools", tags=["meta"])
async def list_tools() -> dict[str, Any]:
    s = get_settings()
    return {"tools": [
        {**m, "configured": registry.configured(m["name"], s)}
        for m in registry.describe()
    ]}


@app.get("/agents", tags=["meta"])
async def list_agents() -> dict[str, Any]:
    return {"agents": [{"name": k, "description": v} for k, v in AGENTS.items()],
            "pipeline": ["orchestrator", "specialists (parallel)", "correlation",
                         "risk", "compliance", "remediation", "report"]}


# --------------------------------------------------------------------------
# investigations
# --------------------------------------------------------------------------

class ClassifyRequest(BaseModel):
    input: str


@app.post("/classify", tags=["investigations"])
async def classify(body: ClassifyRequest) -> dict[str, Any]:
    """Cheap preview of what an investigation would do, no external calls."""
    kind = classify_input(body.input)
    indicators = extract_indicators(body.input)
    return {
        "kind": kind.value,
        "indicators": [
            {"type": i.type.value, "value": i.value} for i in indicators
        ],
    }


@app.post("/investigate", response_model=InvestigationReport, tags=["investigations"])
async def run_investigation(
    body: InvestigationRequest,
    actor: str = Depends(require_api_key),
    repo: Repository = Depends(repo_dep),
    _throttle: None = Depends(throttle),
) -> InvestigationReport:
    # Concurrency ceiling as well as rate: a handful of simultaneous
    # investigations is what actually exhausts sockets and memory, and the
    # per-caller bucket alone does not bound that across callers.
    async with get_inbound_limiter().slot():
        report = await investigate(body)
    try:
        await repo.save(report)
    except Exception as exc:
        # Losing persistence must not lose the analyst's result.
        log.error("failed to persist investigation %s: %s", report.id, exc)
        report.error = (report.error or "") + f" [persistence failed: {exc}]"
    await repo.audit(actor, "investigate", report.id, {
        "kind": report.kind.value, "risk": report.risk.score,
        "findings": len(report.findings),
    })
    return report


@app.get("/investigations", tags=["investigations"])
async def list_investigations(
    limit: int = Query(default=50, ge=1, le=200),
    min_severity: str | None = Query(default=None),
    repo: Repository = Depends(repo_dep),
) -> dict[str, Any]:
    return {"investigations": await repo.list_recent(limit, min_severity)}


@app.get("/investigations/{investigation_id}", response_model=InvestigationReport,
         tags=["investigations"])
async def get_investigation(
    investigation_id: str, repo: Repository = Depends(repo_dep),
) -> InvestigationReport:
    report = await repo.get(investigation_id)
    if report is None:
        raise HTTPException(status_code=404, detail="Investigation not found")
    return report


@app.get("/investigations/{investigation_id}/graph", tags=["investigations"])
async def get_graph_data(
    investigation_id: str, repo: Repository = Depends(repo_dep),
) -> dict[str, Any]:
    report = await repo.get(investigation_id)
    if report is None:
        raise HTTPException(status_code=404, detail="Investigation not found")
    return {
        "graph": report.graph.model_dump(mode="json"),
        "analysis": graph_engine.analyze(report.graph),
    }


@app.get("/investigations/{investigation_id}/graph.html",
         response_class=HTMLResponse, tags=["investigations"])
async def get_graph_html(
    investigation_id: str,
    theme: str = Query(default="dark", pattern="^(dark|light)$"),
    repo: Repository = Depends(repo_dep),
) -> HTMLResponse:
    report = await repo.get(investigation_id)
    if report is None:
        raise HTTPException(status_code=404, detail="Investigation not found")
    return HTMLResponse(graph_engine.render_html(report.graph, theme=theme))


@app.get("/findings", tags=["investigations"])
async def list_findings(
    limit: int = Query(default=100, ge=1, le=500),
    severity: str | None = Query(default=None),
    repo: Repository = Depends(repo_dep),
) -> dict[str, Any]:
    rows = await repo.list_recent(limit=limit)
    findings: list[dict[str, Any]] = []
    for row in rows:
        report = await repo.get(row["id"])
        if report is None:
            continue
        for f in report.findings:
            if severity and f.severity.value != severity:
                continue
            findings.append({
                "investigation_id": report.id,
                "title": f.title, "category": f.category,
                "severity": f.severity.value, "confidence": f.confidence,
                "agent": f.agent, "owasp": f.owasp, "cwe": f.cwe,
                "mitre_attack": f.mitre_attack, "nist_csf": f.nist_csf,
                "indicators": f.indicators,
            })
    # Sort by severity RANK, not the label. Sorting the string alphabetically
    # puts "medium" above "critical", which buried the findings that matter most
    # at the bottom of the list.
    findings.sort(
        key=lambda f: (Severity(f["severity"]).rank, f["confidence"]), reverse=True
    )
    return {"findings": findings[:limit]}


@app.get("/search", tags=["investigations"])
async def search(
    indicator: str = Query(min_length=2, max_length=512),
    repo: Repository = Depends(repo_dep),
) -> dict[str, Any]:
    return {"results": await repo.search_indicator(indicator)}


@app.get("/stats", tags=["investigations"])
async def stats(repo: Repository = Depends(repo_dep)) -> dict[str, Any]:
    return await repo.stats()


# --------------------------------------------------------------------------
# copilot
# --------------------------------------------------------------------------

@app.post("/copilot/chat", response_model=CopilotResponse, tags=["copilot"])
async def copilot_chat(
    body: CopilotRequest,
    actor: str = Depends(require_api_key),
    repo: Repository = Depends(repo_dep),
    _throttle: None = Depends(throttle),
) -> CopilotResponse:
    response = await ask(body, repo)
    await repo.audit(actor, "copilot", body.investigation_id or "",
                     {"question": body.question[:200]})
    return response


@app.exception_handler(Exception)
async def unhandled(request: Request, exc: Exception) -> JSONResponse:
    log.exception("unhandled error on %s %s", request.method, request.url.path)
    # Never leak internals to the caller; the detail is in the server log.
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error",
                 "path": request.url.path},
    )
