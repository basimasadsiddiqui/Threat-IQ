"""Security Copilot, conversational Q&A grounded in stored investigations.

Grounding order matters: investigation data first (what we actually observed),
knowledge base second (what the frameworks say). The model is told explicitly
that anything outside those two blocks is out of scope, and answers without
either fall back to a stock response rather than free-associating.
"""
from __future__ import annotations

import logging
import re

from threatiq.config import get_settings
from threatiq.db.repo import Repository
from threatiq.engine.indicators import extract_indicators
from threatiq.llm import llm_for
from threatiq.prompt_safety import neutralise, quoted
from threatiq.rag.retriever import get_retriever
from threatiq.schemas import CopilotRequest, CopilotResponse, InvestigationReport

log = logging.getLogger(__name__)

_SYSTEM = """You are the ThreatIQ Security Copilot, answering questions about
investigations this platform has already run.

You may use ONLY the INVESTIGATION DATA and KNOWLEDGE BASE sections given to
you. If they do not contain the answer, say what is missing and suggest which
investigation or lookup would provide it. Never invent indicators, scores,
detections or CVE details. Cite framework codes (e.g. A03:2021, T1566.002) when
you reference them."""

_PROMPT = """{investigation}

{knowledge}

CONVERSATION SO FAR:
{history}

ANALYST QUESTION: {question}

Answer directly and specifically, in at most 250 words."""


def _render_investigation(report: InvestigationReport) -> str:
    lines = [
        f"=== INVESTIGATION {report.id} ===",
        # The submitted material is hostile by definition; quote it as data.
        quoted("submitted-input", report.input, limit=800),
        f"Type: {report.kind.value}",
        f"Risk: {report.risk.score}/100 ({report.risk.severity.value}), "
        f"confidence {report.risk.confidence:.0%}, "
        f"scored on {report.risk.coverage:.0%} of the model's weight",
        "",
        "RISK FACTORS:",
    ]
    for f in report.risk.factors:
        state = "" if f.applicable else " [not applicable]"
        lines.append(f"  - {f.name}{state}: value {f.value:.2f} of weight "
                     f"{f.weight:.2f}, {f.rationale}")

    # Titles, descriptions and summaries all quote attacker-chosen strings.
    lines.append("\nFINDINGS:")
    for f in report.findings:
        codes = ", ".join(f.owasp + f.cwe + f.mitre_attack + f.nist_csf) or "unmapped"
        lines.append(
            f"  - [{f.severity.value}] {neutralise(f.title)} "
            f"(confidence {f.confidence:.0%}, agent {f.agent}, "
            f"frameworks: {codes})\n    {neutralise(f.description[:320])}"
        )
    if not report.findings:
        lines.append("  (none)")

    lines.append("\nEVIDENCE:")
    for e in report.evidence:
        lines.append(f"  - [{e.source}/{e.tool}] status={e.status.value} "
                     f"verdict={e.verdict.value} :: {neutralise(e.summary[:200])}")

    lines.append("\nRECOMMENDED ACTIONS:")
    for a in report.remediation:
        lines.append(f"  - P{a.priority} ({a.owner}): {a.action}, {a.rationale[:160]}")

    return "\n".join(lines)[:14000]


def _deterministic_answer(question: str, report: InvestigationReport | None,
                          related: list[dict]) -> str:
    """Used when no LLM is configured, still genuinely useful, just terser."""
    q = question.lower()
    if report is None:
        if related:
            lines = [f"Found {len(related)} investigation(s) matching that indicator:"]
            for r in related[:8]:
                lines.append(
                    f"  - {r['id']}: {r['input'][:70]}, risk {r['risk_score']}/100 "
                    f"({r['severity']}), {r['finding_count']} finding(s)"
                )
            return "\n".join(lines)
        return ("No investigation is selected and no stored indicator matches "
                "that question. Run an investigation first, or reference an "
                "investigation ID.")

    if re.search(r"\bwhy\b.*\b(critical|high|risk|score|severe)\b", q):
        return report.risk.explanation
    if re.search(r"\b(fix|remediat|do|action|next step|priorit)\w*\b", q):
        lines = ["Recommended actions in priority order:"]
        for a in sorted(report.remediation, key=lambda a: a.priority):
            lines.append(f"  P{a.priority} [{a.owner}] {a.action}\n       {a.rationale}")
        return "\n".join(lines) or "No actions were generated."
    if re.search(r"\b(owasp|cwe|mitre|nist|framework|complian\w*)\b", q):
        lines = ["Framework mapping for this investigation:"]
        for f in report.findings:
            codes = ", ".join(f.owasp + f.cwe + f.mitre_attack + f.nist_csf)
            lines.append(f"  - {f.title}: {codes or 'unmapped'}")
        return "\n".join(lines)
    if re.search(r"\b(evidence|source|proof|who said|detect)\w*\b", q):
        lines = ["Evidence collected:"]
        for e in report.evidence:
            lines.append(f"  - [{e.source}] {e.status.value}: {e.summary}")
        return "\n".join(lines)
    return report.summary or report.risk.explanation


async def ask(request: CopilotRequest, repo: Repository) -> CopilotResponse:
    report: InvestigationReport | None = None
    used_context: list[str] = []

    if request.investigation_id:
        report = await repo.get(request.investigation_id)
        if report:
            used_context.append(f"investigation:{report.id}")

    # An IOC in the question pulls in every prior investigation that saw it -
    # this is what makes "show me everything related to this IP" work.
    related: list[dict] = []
    for indicator in extract_indicators(request.question)[:3]:
        hits = await repo.search_indicator(indicator.value)
        for hit in hits:
            if hit["id"] not in [r["id"] for r in related]:
                related.append(hit)
                used_context.append(f"related:{hit['id']}")
    if report is None and related:
        report = await repo.get(related[0]["id"])

    # Retrieve against the question *plus* what the investigation actually
    # found. The bare question ("why is this risky?") carries no security
    # terminology, so on its own it retrieves arbitrary corpus entries and the
    # answer ends up citing references that have nothing to do with the case.
    retrieval_query = request.question
    if report and report.findings:
        retrieval_query += " " + " ".join(
            f"{f.title} {f.category}" for f in report.findings[:4]
        )
    retriever = get_retriever()
    knowledge, citations = await retriever.context_block(retrieval_query, top_k=4)

    # Honours a key the caller supplied for this question only, the same way an
    # investigation does; otherwise this is the shared process-wide client.
    llm = llm_for(get_settings().with_overrides(request.resolved_overrides()))
    if not llm.enabled:
        # The deterministic answer is assembled from stored investigation data
        # and never consults the knowledge base, so citing it would misrepresent
        # where the answer came from.
        answer = _deterministic_answer(request.question, report, related)
        mapped_codes = sorted({
            code for f in (report.findings if report else [])
            for code in f.owasp + f.cwe + f.mitre_attack + f.nist_csf
        })
        return CopilotResponse(
            answer=answer, citations=mapped_codes, used_context=used_context,
        )

    used_context.extend(f"kb:{c}" for c in citations)

    investigation_block = (
        _render_investigation(report) if report
        else "=== INVESTIGATION DATA ===\n(no investigation selected)"
    )
    if related:
        investigation_block += "\n\n=== RELATED INVESTIGATIONS ===\n" + "\n".join(
            f"  - {r['id']}: {r['input'][:80]}, risk {r['risk_score']}/100 "
            f"({r['severity']})" for r in related[:6]
        )

    # `history` and `question` arrive in the request body. A caller can put
    # anything in either, including a forged "assistant:" turn claiming the
    # tooling already cleared an indicator. Both are defanged, and the role
    # label is constrained to the two values the protocol allows rather than
    # echoed back verbatim.
    history = "\n".join(
        f"{'assistant' if m.get('role') == 'assistant' else 'analyst'}: "
        f"{neutralise(str(m.get('content', ''))[:400])}"
        for m in request.history[-6:]
    ) or "(start of conversation)"

    answer = await llm.complete(
        _PROMPT.format(
            investigation=investigation_block,
            knowledge=(f"=== KNOWLEDGE BASE ===\n{knowledge}" if knowledge
                       else "=== KNOWLEDGE BASE ===\n(no relevant entries)"),
            history=history,
            question=neutralise(request.question),
        ),
        system=_SYSTEM, max_tokens=900,
    )
    if not answer:
        answer = _deterministic_answer(request.question, report, related)

    return CopilotResponse(answer=answer, citations=citations,
                           used_context=used_context)
