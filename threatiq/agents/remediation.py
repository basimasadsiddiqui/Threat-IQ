"""Remediation agent, what to actually do, in what order.

Actions are generated from a deterministic playbook keyed on finding category
and severity, so a report is never empty just because the LLM was unavailable.
When an LLM is present it may add context-specific actions on top.
"""
from __future__ import annotations

import logging

from threatiq.agents.state import InvestigationState, timed_action
from threatiq.llm import get_llm
from threatiq.schemas import Finding, RemediationAction, Severity

log = logging.getLogger(__name__)

_ADD_PROMPT = """You are advising on incident response for this investigation.

RISK: {score}/100 ({severity})

FINDINGS:
{findings}

ACTIONS ALREADY PLANNED:
{planned}

Suggest up to 3 ADDITIONAL concrete actions that are not already planned and
that follow specifically from these findings. Skip generic advice.

Return JSON: {{"actions": [{{"action": "", "rationale": "", "priority": 1-5,
"effort": "low|medium|high", "owner": ""}}]}}"""


# The submitted message is a container, not something you can block at a proxy.
_NON_BLOCKABLE = {"email_message:submitted"}


def _playbook(finding: Finding, indicators: list[str]) -> list[RemediationAction]:
    """Category-specific containment, eradication and recovery steps."""
    blockable = [i for i in indicators if i not in _NON_BLOCKABLE]
    ioc = ", ".join(i.split(":", 1)[-1] for i in blockable[:4])
    critical = finding.severity.rank >= Severity.HIGH.rank
    actions: list[RemediationAction] = []

    if finding.category in ("phishing", "bec"):
        actions.append(RemediationAction(
            priority=1,
            action="Quarantine the message and search the mail estate for other "
                   "copies from the same sender"
                   + (f" or containing {ioc}" if ioc else ""),
            rationale="Other recipients likely received the same campaign; "
                      "containment is incomplete until they are pulled.",
            owner="email_security", effort="low", automatable=True,
        ))
        if finding.category == "bec":
            actions.append(RemediationAction(
                priority=1,
                action="Freeze and independently verify any pending payment or "
                       "bank-detail change referenced in the message, using a "
                       "phone number from your own records",
                rationale="BEC losses are recoverable only before the transfer "
                          "settles. Verification must not use contact details "
                          "supplied in the email itself.",
                owner="finance", effort="low",
            ))

        # A text-only BEC has no blockable indicator; the actions above still
        # apply, the network-level ones below do not.
        if not ioc:
            return actions
        actions += [
            RemediationAction(
                priority=1,
                action=f"Block {ioc} at the web proxy, DNS resolver and mail gateway",
                rationale="Prevents further access to the credential-harvesting "
                          "infrastructure from inside the network.",
                owner="network_security", effort="low", automatable=True,
            ),
            RemediationAction(
                priority=2,
                action="Query proxy and DNS logs for users who resolved or "
                       f"visited {ioc}, then reset credentials and revoke active "
                       "sessions for anyone who did",
                rationale="A stolen password is only useful until it is rotated; "
                          "session revocation closes the window on tokens already "
                          "issued.",
                owner="identity_team", effort="medium",
            ),
        ]

    elif finding.category in ("malicious_infrastructure", "suspicious_infrastructure",
                              "campaign"):
        if not ioc:
            return actions
        actions += [
            RemediationAction(
                priority=1,
                action=f"Add {ioc} to blocklists on the firewall, proxy and EDR",
                rationale="Denies the infrastructure reachability from the estate.",
                owner="network_security", effort="low", automatable=True,
            ),
            RemediationAction(
                priority=2,
                action=f"Hunt across SIEM and EDR telemetry for historical contact "
                       f"with {ioc} over the last 90 days",
                rationale="Blocking stops future contact; only retrospective "
                          "hunting establishes whether compromise already occurred.",
                owner="threat_hunting", effort="medium",
            ),
        ]

    elif finding.category == "vulnerability":
        cve = next((i.split(":", 1)[1] for i in finding.indicators
                    if i.startswith("cve:")), "the vulnerability")
        actions += [
            RemediationAction(
                priority=1 if critical else 3,
                action=f"Apply the vendor patch for {cve} to all affected assets",
                rationale=("This vulnerability is confirmed exploited in the wild, "
                           "so exposure time is measured in hours."
                           if "actively exploited" in finding.title.lower()
                           else "Patching removes the vulnerability outright."),
                owner="infrastructure", effort="medium",
            ),
            RemediationAction(
                priority=2,
                action=f"If patching cannot be completed immediately, restrict "
                       f"network exposure of the affected service and add "
                       f"detection for exploitation of {cve}",
                rationale="Compensating controls reduce the window while the "
                          "change goes through normal release process.",
                owner="infrastructure", effort="medium",
            ),
        ]

    elif finding.category in ("misconfiguration", "web_vulnerability"):
        actions.append(RemediationAction(
            priority=2 if critical else 4,
            action=f"Remediate '{finding.title}' on the affected endpoint",
            rationale=finding.description.split("\n")[0][:220],
            owner="application_team",
            effort="low" if finding.category == "misconfiguration" else "medium",
        ))

    for action in actions:
        action.references = finding.references[:3]
    return actions


def _dedupe(actions: list[RemediationAction]) -> list[RemediationAction]:
    seen: dict[str, RemediationAction] = {}
    for action in actions:
        key = action.action.lower()[:90]
        existing = seen.get(key)
        if existing is None or action.priority < existing.priority:
            seen[key] = action
    return sorted(seen.values(), key=lambda a: (a.priority, a.owner))


async def run(state: InvestigationState) -> InvestigationState:
    with timed_action("remediation", "plan") as record:
        findings = state.get("findings", [])
        risk = state.get("risk")
        actions: list[RemediationAction] = []

        for finding in sorted(findings, key=lambda f: -f.severity.rank):
            actions.extend(_playbook(finding, finding.indicators))

        if risk and risk.severity.rank >= Severity.HIGH.rank:
            actions.append(RemediationAction(
                priority=3,
                action="Open an incident ticket and notify the on-call security "
                       "lead",
                rationale=f"Risk scored {risk.score}/100 ({risk.severity.value}), "
                          f"which meets the threshold for formal incident handling.",
                owner="soc", effort="low",
            ))
        if not actions:
            actions.append(RemediationAction(
                priority=5,
                action="No action required; record the investigation outcome",
                rationale="No adverse findings were produced by the sources queried.",
                owner="soc", effort="low",
            ))

        actions = _dedupe(actions)

        llm = get_llm()
        if llm.enabled and findings:
            proposal = await llm.structured(
                _ADD_PROMPT.format(
                    score=risk.score if risk else 0,
                    severity=risk.severity.value if risk else "unknown",
                    findings="\n".join(
                        f"- [{f.severity.value}] {f.title}: "
                        f"{f.description[:200]}" for f in findings[:8]
                    ),
                    planned="\n".join(f"- {a.action}" for a in actions[:10]),
                ),
                system="You are an incident response advisor.",
                max_tokens=700,
            )
            for item in (proposal or {}).get("actions", [])[:3]:
                text = str(item.get("action", "")).strip()
                if not text:
                    continue
                effort = str(item.get("effort", "medium")).lower()
                actions.append(RemediationAction(
                    priority=max(1, min(5, int(item.get("priority", 3) or 3))),
                    action=text[:300],
                    rationale=str(item.get("rationale", ""))[:400],
                    owner=str(item.get("owner", "security_team"))[:40],
                    effort=effort if effort in ("low", "medium", "high") else "medium",
                ))
            actions = _dedupe(actions)

        record.detail = f"{len(actions)} action(s) across {len(findings)} finding(s)"

    return {"remediation": actions, "actions": [record]}
