"""Shared investigation state passed between LangGraph nodes."""
from __future__ import annotations

import time
from typing import Annotated, Any, TypedDict

from threatiq.schemas import (
    AgentAction, Evidence, Finding, Indicator, InputKind, RemediationAction,
    RiskAssessment, ThreatGraph,
)
from threatiq.tools.base import ToolContext


def merge_lists(left: list, right: list) -> list:
    """Reducer for parallel branches: concatenate without losing either side."""
    return (left or []) + (right or [])


def merge_findings(left: list, right: list) -> list:
    """Reducer for findings that also de-duplicates.

    Two agents can legitimately reach the same conclusion about the same
    indicator (the threat-intel and websec agents both notice missing security
    headers). Collapsing here, rather than in a later node, keeps every
    branch free to report what it found without inflating the risk score.
    """
    merged: dict[tuple, object] = {}
    for finding in (left or []) + (right or []):
        key = (finding.title, tuple(sorted(finding.indicators)))
        existing = merged.get(key)
        if existing is None:
            merged[key] = finding
            continue
        # Keep the stronger claim, but union the evidence behind both.
        if (finding.severity.rank, finding.confidence) > \
           (existing.severity.rank, existing.confidence):  # type: ignore[attr-defined]
            finding.evidence_ids = sorted(
                set(finding.evidence_ids) | set(existing.evidence_ids)  # type: ignore[attr-defined]
            )
            merged[key] = finding
        else:
            existing.evidence_ids = sorted(  # type: ignore[attr-defined]
                set(existing.evidence_ids) | set(finding.evidence_ids)  # type: ignore[attr-defined]
            )
    return list(merged.values())


class InvestigationState(TypedDict, total=False):
    # --- input ---
    investigation_id: str
    raw_input: str
    kind: InputKind
    asset_criticality: str
    internet_exposed: bool
    allow_active_scan: bool

    # --- orchestrator plan ---
    plan: list[str]           # agent names to run
    plan_reason: str
    loop_count: int

    # --- accumulated (parallel-safe via reducers) ---
    indicators: Annotated[list[Indicator], merge_lists]
    evidence: Annotated[list[Evidence], merge_lists]
    findings: Annotated[list[Finding], merge_findings]
    actions: Annotated[list[AgentAction], merge_lists]

    # --- derived ---
    correlation: dict[str, Any]
    graph: ThreatGraph
    risk: RiskAssessment
    remediation: list[RemediationAction]
    summary: str
    error: str | None

    # --- runtime handles (not serialized to the DB) ---
    tool_ctx: ToolContext
    started_at: float


def new_state(**kwargs: Any) -> InvestigationState:
    state: InvestigationState = {
        "indicators": [], "evidence": [], "findings": [], "actions": [],
        "plan": [], "plan_reason": "", "loop_count": 0,
        "correlation": {}, "remediation": [], "summary": "", "error": None,
        "started_at": time.monotonic(),
    }
    state.update(kwargs)  # type: ignore[typeddict-item]
    return state


class timed_action:
    """Context manager that records an AgentAction for the audit trail."""

    def __init__(self, agent: str, action: str, detail: str = "") -> None:
        self.record = AgentAction(agent=agent, action=action, detail=detail)
        self._start = 0.0

    def __enter__(self) -> AgentAction:
        self._start = time.perf_counter()
        return self.record

    def __exit__(self, exc_type: type | None, exc: BaseException | None,
                 tb: object) -> bool:
        self.record.duration_ms = int((time.perf_counter() - self._start) * 1000)
        if exc_type is not None:
            self.record.status = "error"
            self.record.detail = f"{self.record.detail} | {exc_type.__name__}: {exc}"
        return False  # never swallow: the graph decides what a failure means
