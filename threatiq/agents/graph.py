"""LangGraph workflow assembly.

    START
      |
   orchestrator            (classify input, extract IOCs, choose specialists)
      |
      +-- conditional fan-out (parallel) --+
      |         |          |        |      |
 threat_intel phishing vulnerability websec
      |         |          |        |      |
      +---------+----------+--------+------+
      |
  correlation   (threat graph, campaign linkage)
      |
     risk       (deterministic score, LLM explains)
      |
  compliance    (RAG-grounded OWASP/CWE/MITRE/NIST mapping)
      |
  remediation   (prioritised actions)
      |
    report
      |
     END

A pure-Python executor mirrors the same topology so ThreatIQ runs even when
LangGraph is not installed. Both paths call identical node functions, so the
behaviour does not fork.
"""
from __future__ import annotations

import asyncio
import logging
from collections.abc import Callable
from typing import Any

from threatiq.agents import (
    compliance,
    correlation,
    orchestrator,
    phishing,
    remediation,
    report,
    risk,
    threat_intel,
    vuln,
    websec,
)
from threatiq.agents.state import InvestigationState, merge_findings, merge_lists

log = logging.getLogger(__name__)

SPECIALISTS: dict[str, Callable] = {
    "threat_intel": threat_intel.run,
    "phishing": phishing.run,
    "vulnerability": vuln.run,
    "websec": websec.run,
}

PIPELINE: list[tuple[str, Callable]] = [
    ("correlation", correlation.run),
    ("risk", risk.run),
    ("compliance", compliance.run),
    ("remediation", remediation.run),
    ("report", report.run),
]

# Keys whose updates accumulate rather than replace.
_REDUCERS: dict[str, Callable[[list, list], list]] = {
    "indicators": merge_lists,
    "evidence": merge_lists,
    "actions": merge_lists,
    "findings": merge_findings,
}


def apply_update(state: InvestigationState, update: dict[str, Any]) -> None:
    """Merge a node's return value into the state, honouring the reducers."""
    for key, value in (update or {}).items():
        reducer = _REDUCERS.get(key)
        if reducer is not None:
            state[key] = reducer(state.get(key) or [], value or [])  # type: ignore[literal-required]
        else:
            state[key] = value  # type: ignore[literal-required]


def build_langgraph():
    """Compile the real LangGraph StateGraph, or return None if unavailable."""
    try:
        from langgraph.graph import END, START, StateGraph
    except ImportError:
        return None

    try:
        graph = StateGraph(InvestigationState)
        graph.add_node("orchestrator", orchestrator.orchestrate)
        for name, fn in SPECIALISTS.items():
            graph.add_node(name, fn)
        for name, fn in PIPELINE:
            graph.add_node(name, fn)

        graph.add_edge(START, "orchestrator")
        # Fan out to every scheduled specialist in parallel.
        graph.add_conditional_edges(
            "orchestrator", orchestrator.route, list(SPECIALISTS.keys())
        )
        # Every specialist converges on correlation; LangGraph waits for all
        # scheduled branches before the join runs.
        for name in SPECIALISTS:
            graph.add_edge(name, "correlation")
        for (current, _), (nxt, _) in zip(PIPELINE, PIPELINE[1:], strict=False):
            graph.add_edge(current, nxt)
        graph.add_edge(PIPELINE[-1][0], END)
        return graph.compile()
    except Exception as exc:
        log.warning("LangGraph compilation failed (%s); using fallback executor", exc)
        return None


class FallbackExecutor:
    """Same topology, hand-rolled. Used when LangGraph is not importable."""

    async def ainvoke(self, state: InvestigationState,
                      config: dict | None = None) -> InvestigationState:
        apply_update(state, await orchestrator.orchestrate(state))

        scheduled = [
            name for name in orchestrator.route(state) if name in SPECIALISTS
        ]
        if scheduled:
            results = await asyncio.gather(
                *(SPECIALISTS[name](state) for name in scheduled),
                return_exceptions=True,
            )
            for name, result in zip(scheduled, results, strict=False):
                if isinstance(result, BaseException):
                    log.exception("specialist %s failed", name, exc_info=result)
                    state["error"] = f"{name} agent failed: {result}"
                    continue
                apply_update(state, result)

        for name, fn in PIPELINE:
            try:
                apply_update(state, await fn(state))
            except Exception as exc:
                log.exception("pipeline stage %s failed", name)
                state["error"] = f"{name} stage failed: {exc}"
        return state


_compiled: Any = None
_backend: str = "unknown"


def get_graph() -> tuple[Any, str]:
    """Return (runnable, backend_name). Compiled once per process."""
    global _compiled, _backend
    if _compiled is None:
        _compiled = build_langgraph()
        if _compiled is not None:
            _backend = "langgraph"
        else:
            _compiled = FallbackExecutor()
            _backend = "fallback"
        log.info("investigation graph backend: %s", _backend)
    return _compiled, _backend
