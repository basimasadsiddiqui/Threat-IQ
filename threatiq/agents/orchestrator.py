"""Orchestrator agent, decides what the investigation needs.

Routing is deterministic first (input kind -> required specialists), with the
LLM only allowed to *add* an optional agent it can justify. That ordering
matters: a model that is down, rate-limited or hallucinating must never be able
to stop a phishing email from reaching the phishing agent.
"""
from __future__ import annotations

import logging

from threatiq.agents.state import InvestigationState, llm_of, timed_action
from threatiq.engine.indicators import (
    classify_input,
    extract_indicators,
    primary_indicator,
    strip_infrastructure_headers,
)
from threatiq.prompt_safety import neutralise, quoted
from threatiq.schemas import IndicatorType, InputKind

log = logging.getLogger(__name__)

AGENTS = {
    "threat_intel": "Reputation and infrastructure analysis of URLs, domains, IPs and hashes.",
    "phishing": "Email header/body analysis, brand impersonation and BEC detection.",
    "vulnerability": "CVE severity, exploitability and CISA KEV prioritisation.",
    "websec": "Active web/API security scanning (authorised targets only).",
}

# The non-negotiable baseline per input kind.
REQUIRED: dict[InputKind, list[str]] = {
    InputKind.URL: ["threat_intel", "phishing"],
    InputKind.DOMAIN: ["threat_intel", "phishing"],
    InputKind.IP: ["threat_intel"],
    InputKind.EMAIL_MESSAGE: ["phishing", "threat_intel"],
    InputKind.FILE_HASH: ["threat_intel"],
    InputKind.CVE: ["vulnerability"],
    InputKind.WEB_TARGET: ["websec", "threat_intel"],
    InputKind.FREE_TEXT: ["threat_intel"],
}

_PLAN_PROMPT = """An analyst submitted the following for investigation.

Input kind: {kind}
Indicators extracted: {indicators}

{preview}

Agents already scheduled (mandatory, cannot be removed): {required}
Optional agents available:
{optional}

Decide whether any OPTIONAL agent should also run. Only add one if the
indicators genuinely justify it.

Return JSON: {{"add": ["agent_name", ...], "reason": "one sentence"}}"""


async def orchestrate(state: InvestigationState) -> InvestigationState:
    with timed_action("orchestrator", "triage") as record:
        raw = state["raw_input"]

        kind = state.get("kind") or classify_input(raw)
        # For a message, only the sender and body are in scope, the Received
        # and Authentication-Results chain is our own infrastructure.
        source_text = (strip_infrastructure_headers(raw)
                       if kind == InputKind.EMAIL_MESSAGE else raw)
        indicators = extract_indicators(source_text)

        # An email is itself an indicator even though no regex produces it.
        if kind == InputKind.EMAIL_MESSAGE:
            from threatiq.schemas import Indicator
            # Key must be `email_message:submitted` so the evidence emitted by
            # the email tool attaches to this node in the threat graph.
            indicators.insert(0, Indicator(
                type=IndicatorType.EMAIL_MESSAGE, value="submitted",
                source="user_input",
            ))

        plan = list(REQUIRED.get(kind, ["threat_intel"]))

        # A CVE mentioned inside any other input still needs the vuln agent.
        if any(i.type == IndicatorType.CVE for i in indicators):
            if "vulnerability" not in plan:
                plan.append("vulnerability")

        # Active scanning is opt-in and additionally gated in the agent itself.
        if state.get("allow_active_scan") and "websec" not in plan:
            plan.append("websec")

        reason = f"Input classified as {kind.value}; scheduled {', '.join(plan)}."

        llm = llm_of(state)
        if llm.enabled:
            optional = {k: v for k, v in AGENTS.items() if k not in plan}
            if optional:
                proposal = await llm.structured(
                    _PLAN_PROMPT.format(
                        kind=kind.value,
                        indicators=neutralise(", ".join(
                            f"{i.type.value}={i.value}" for i in indicators[:12]
                        )) or "none",
                        # The raw submission is the most attacker-controlled
                        # string in the system and it reaches a prompt here.
                        # Fenced like every other piece of quoted evidence.
                        preview=quoted("submitted-input", raw, limit=600),
                        required=", ".join(plan),
                        optional="\n".join(f"- {k}: {v}" for k, v in optional.items()),
                    ),
                    system="You are the investigation orchestrator for a SOC.",
                    max_tokens=300,
                )
                if proposal:
                    # Additive only, and never grants the active-scan privilege.
                    for name in proposal.get("add", []) or []:
                        if name in optional and name != "websec":
                            plan.append(name)
                    if proposal.get("reason"):
                        reason += f" Orchestrator note: {proposal['reason']}"

        primary = primary_indicator(indicators, kind)
        record.detail = (f"kind={kind.value} indicators={len(indicators)} "
                         f"plan={plan} primary={primary.key if primary else 'none'}")

    return {
        "kind": kind,
        "indicators": indicators,
        "plan": plan,
        "plan_reason": reason,
        "actions": [record],
    }


def route(state: InvestigationState) -> list[str]:
    """Conditional edge: fan out to every scheduled specialist in parallel."""
    plan = state.get("plan") or ["threat_intel"]
    return [name for name in plan if name in AGENTS]
