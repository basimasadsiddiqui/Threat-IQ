"""Risk agent.

The score comes from the deterministic engine. The LLM is given the already-
computed factors and asked only to write prose about them, it cannot change
the number, and if it is unavailable the engine's own explanation is used.
"""
from __future__ import annotations

import logging

from threatiq.agents.state import InvestigationState, timed_action
from threatiq.engine.risk_engine import RiskInput, assess
from threatiq.llm import get_llm
from threatiq.prompt_safety import neutralise

log = logging.getLogger(__name__)

_EXPLAIN_PROMPT = """A deterministic risk engine has scored an investigation.
You are writing the analyst-facing justification for that score.

COMPUTED RESULT (authoritative, do not change these numbers):
  Risk score: {score}/100
  Severity:   {severity}
  Confidence: {confidence}

SCORING FACTORS:
{factors}

EVIDENCE COLLECTED:
{evidence}

Write 3-5 sentences explaining why this score is what it is, in the voice of a
senior SOC analyst. Reference the specific evidence. State plainly if the
confidence is low and why. Do not restate the score in a bulleted list, do not
add recommendations, and do not introduce any fact not shown above."""


async def run(state: InvestigationState) -> InvestigationState:
    with timed_action("risk", "score") as record:
        evidence = state.get("evidence", [])
        findings = state.get("findings", [])

        assessment = assess(RiskInput(
            evidence=evidence,
            findings=findings,
            asset_criticality=str(state.get("asset_criticality", "medium")),
            internet_exposed=bool(state.get("internet_exposed", True)),
        ))

        llm = get_llm()
        if llm.enabled and evidence:
            factor_lines = "\n".join(
                f"  - {f.name}: contributed {f.contribution * 100:.1f} of "
                f"{f.weight * 100:.0f} points, {f.rationale}"
                for f in assessment.factors
            )
            # Evidence summaries quote indicator values, page titles and email
            # subjects, all attacker-controlled. Defanged before they reach the
            # prompt: the model must not be talked out of the score the
            # deterministic engine already computed.
            evidence_lines = "\n".join(
                f"  - [{e.source}] {neutralise(e.summary)}"
                for e in evidence
                if e.status.value in ("ok", "not_found") and e.summary
            )[:4000]

            prose = await llm.complete(
                _EXPLAIN_PROMPT.format(
                    score=assessment.score,
                    severity=assessment.severity.value,
                    confidence=f"{assessment.confidence:.0%}",
                    factors=factor_lines,
                    evidence=evidence_lines or "  (no successful lookups)",
                ),
                system="You explain risk scores. You never compute them.",
                max_tokens=500,
            )
            if prose:
                # The engine's breakdown stays attached underneath the prose so
                # the arithmetic is always auditable.
                assessment.explanation = (
                    prose.strip() + "\n\n--- Score breakdown ---\n"
                    + assessment.explanation
                )

        record.detail = (f"score={assessment.score} severity="
                         f"{assessment.severity.value} "
                         f"confidence={assessment.confidence:.2f} "
                         f"sources={assessment.corroborating_sources}")

    return {"risk": assessment, "actions": [record]}
