"""Investigation service, the seam between the API and the agent graph."""
from __future__ import annotations

import asyncio
import logging
import time
from datetime import UTC, datetime

from threatiq.agents.graph import get_graph
from threatiq.agents.state import new_state
from threatiq.config import get_settings
from threatiq.engine.indicators import classify_input
from threatiq.llm import llm_for
from threatiq.schemas import (
    InvestigationReport,
    InvestigationRequest,
    RiskAssessment,
    ThreatGraph,
)
from threatiq.tools.base import ToolContext

log = logging.getLogger(__name__)


async def investigate(request: InvestigationRequest) -> InvestigationReport:
    """Run one investigation to completion and return a serializable report."""
    # Credentials the caller supplied for this request only. `with_overrides`
    # returns a copy, so these keys live as long as this call and are never
    # visible to a concurrent investigation or written anywhere.
    settings = get_settings().with_overrides(request.resolved_overrides())
    started = time.monotonic()
    kind = request.kind or classify_input(request.input)

    report = InvestigationReport(
        input=request.input[:2000], kind=kind, status="running",
    )

    async with ToolContext(settings=settings) as ctx:
        state = new_state(
            investigation_id=report.id,
            raw_input=request.input,
            kind=kind,
            asset_criticality=request.asset_criticality,
            internet_exposed=request.internet_exposed,
            allow_active_scan=request.allow_active_scan,
            tool_ctx=ctx,
            llm=llm_for(settings),
        )

        runnable, backend = get_graph()
        try:
            # A hung upstream API must not hold a request open indefinitely;
            # whatever completed before the deadline is still reported.
            final = await asyncio.wait_for(
                runnable.ainvoke(
                    state,
                    config={
                        "recursion_limit": 25,
                        "metadata": {
                            "investigation_id": report.id,
                            "kind": kind.value,
                            "threatiq_backend": backend,
                        },
                        "run_name": f"threatiq-investigation-{report.id}",
                    },
                ),
                timeout=settings.max_investigation_seconds,
            )
            state = final if isinstance(final, dict) else state
            report.status = "completed"
        except TimeoutError:
            log.warning("investigation %s timed out", report.id)
            report.status = "completed"
            report.error = (
                f"Investigation exceeded {settings.max_investigation_seconds}s; "
                f"reporting partial results collected before the deadline."
            )
        except Exception as exc:
            log.exception("investigation %s failed", report.id)
            report.status = "failed"
            report.error = f"{type(exc).__name__}: {exc}"

        report.indicators = list(state.get("indicators", []))
        report.evidence = list(state.get("evidence", []))
        report.findings = list(state.get("findings", []))
        report.risk = state.get("risk") or RiskAssessment()
        report.graph = state.get("graph") or ThreatGraph()
        report.remediation = list(state.get("remediation", []))
        report.actions = list(state.get("actions", []))
        report.summary = state.get("summary", "") or report.summary
        if state.get("error") and not report.error:
            report.error = str(state["error"])

    report.completed_at = datetime.now(UTC)
    log.info(
        "investigation %s finished in %.1fs: risk=%s findings=%d evidence=%d",
        report.id, time.monotonic() - started, report.risk.score,
        len(report.findings), len(report.evidence),
    )
    return report
