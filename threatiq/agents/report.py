"""Report agent, the analyst-facing summary.

Builds a complete deterministic summary first, then optionally replaces the
narrative paragraph with an LLM version. The structured sections (verdict,
evidence table, framework mapping, next steps) are never model-generated.
"""
from __future__ import annotations

import logging

from threatiq.agents.state import InvestigationState, timed_action
from threatiq.llm import get_llm
from threatiq.prompt_safety import neutralise, quoted
from threatiq.schemas import Severity, ToolStatus

log = logging.getLogger(__name__)

_SUMMARY_PROMPT = """Write the executive summary of this security investigation.

{submitted}

RISK: {score}/100 ({severity}), confidence {confidence}

FINDINGS:
{findings}

EVIDENCE:
{evidence}

TOP RECOMMENDED ACTIONS:
{actions}

Write 4-6 sentences for a security manager: what was submitted, what was found,
how confident we are, and what happens next. Be direct. Do not use bullet
points, headers, or markdown. Do not invent any fact not listed above."""


def _deterministic_summary(state: InvestigationState) -> str:
    risk = state.get("risk")
    findings = state.get("findings", [])
    evidence = state.get("evidence", [])
    remediation = state.get("remediation", [])
    kind = state.get("kind")

    ok = [e for e in evidence if e.status == ToolStatus.OK]
    skipped = [e for e in evidence if e.status == ToolStatus.SKIPPED]
    sources = sorted({e.source for e in ok})

    lines: list[str] = []
    if risk:
        lines.append(
            f"Investigation of the submitted "
            f"{kind.value.replace('_', ' ') if kind else 'input'} scored "
            f"{risk.score}/100 ({risk.severity.value.upper()}) with "
            f"{risk.confidence:.0%} confidence."
        )

    if findings:
        by_severity: dict[str, int] = {}
        for f in findings:
            by_severity[f.severity.value] = by_severity.get(f.severity.value, 0) + 1
        breakdown = ", ".join(
            f"{n} {sev}" for sev, n in sorted(
                by_severity.items(), key=lambda kv: -Severity(kv[0]).rank
            )
        )
        worst = max(findings, key=lambda f: (f.severity.rank, f.confidence))
        lines.append(f"{len(findings)} finding(s) were raised ({breakdown}). "
                     f"The most severe is: {worst.title}.")
    else:
        lines.append("No findings were raised.")

    lines.append(
        f"{len(ok)} lookup(s) succeeded across {len(sources)} source(s)"
        + (f" ({', '.join(sources)})" if sources else "") + "."
    )
    if skipped:
        missing = sorted({e.source for e in skipped})
        lines.append(
            f"Note: {len(skipped)} lookup(s) were skipped because no API key is "
            f"configured for {', '.join(missing)}; absence of a detection from "
            f"these sources is not evidence of safety."
        )

    if remediation:
        top = [a for a in remediation if a.priority <= 2][:3] or remediation[:3]
        lines.append(
            "Immediate next steps: " + "; ".join(a.action for a in top) + "."
        )
    return " ".join(lines)


async def run(state: InvestigationState) -> InvestigationState:
    with timed_action("report", "compose") as record:
        summary = _deterministic_summary(state)
        risk = state.get("risk")
        findings = state.get("findings", [])
        evidence = state.get("evidence", [])
        remediation = state.get("remediation", [])

        llm = get_llm()
        if llm.enabled and risk:
            prose = await llm.complete(
                _SUMMARY_PROMPT.format(
                    # The submitted material is attacker-controlled. Fenced
                    # behind an unguessable marker so instructions planted in a
                    # phishing body cannot reach the instruction context and
                    # talk the summary into calling a 88/100 finding routine.
                    submitted=quoted("submitted-input",
                                     str(state.get("raw_input", "")), limit=1200),
                    score=risk.score, severity=risk.severity.value,
                    confidence=f"{risk.confidence:.0%}",
                    # Findings and evidence summaries embed indicator values and
                    # email subject lines, so they are defanged too.
                    findings="\n".join(
                        f"- [{f.severity.value}] {neutralise(f.title)}: "
                        f"{neutralise(f.description[:220])}"
                        for f in findings[:10]
                    ) or "  (none)",
                    evidence="\n".join(
                        f"- [{e.source}] {neutralise(e.summary)}"
                        for e in evidence if e.status == ToolStatus.OK
                    )[:3500] or "  (none)",
                    actions="\n".join(
                        f"- {a.action}" for a in remediation[:6]
                    ) or "  (none)",
                ),
                system="You write executive summaries for security investigations.",
                max_tokens=600,
            )
            if prose and len(prose.strip()) > 80:
                # Keep the deterministic coverage caveat appended, it is the
                # part a manager most needs and the model tends to drop it.
                caveat = next(
                    (line for line in summary.split(". ")
                     if line.startswith("Note:")), "",
                )
                summary = prose.strip() + (f" {caveat}." if caveat else "")

        record.detail = f"summary composed ({len(summary)} chars)"

    return {"summary": summary, "actions": [record]}
