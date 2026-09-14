"""Compliance mapper, findings to OWASP / CWE / MITRE ATT&CK / NIST CSF.

RAG is what makes this trustworthy: the mapping is grounded in the retrieved
corpus entries, and any framework code the model returns that is not in the
retrieved set is discarded. A hallucinated "A11:2021" never reaches the report.
"""
from __future__ import annotations

import logging

from threatiq.agents.state import InvestigationState, timed_action
from threatiq.knowledge.corpus import BY_CODE
from threatiq.llm import get_llm
from threatiq.rag.retriever import get_retriever
from threatiq.schemas import Finding

log = logging.getLogger(__name__)

# Deterministic backstop so mapping works with no LLM at all.
CATEGORY_DEFAULTS: dict[str, dict[str, list[str]]] = {
    "phishing": {
        "owasp": ["A07:2021"], "cwe": ["CWE-290"],
        "mitre_attack": ["T1566", "T1566.002"], "nist_csf": ["DE.CM", "RS.MI"],
    },
    "bec": {
        "owasp": ["A07:2021"], "cwe": ["CWE-290"],
        "mitre_attack": ["T1598", "T1656"], "nist_csf": ["DE.CM", "RS.MI"],
    },
    "malicious_infrastructure": {
        "owasp": [], "cwe": [], "mitre_attack": ["T1583.001", "T1071"],
        "nist_csf": ["DE.CM", "RS.MI"],
    },
    "suspicious_infrastructure": {
        "owasp": [], "cwe": [], "mitre_attack": ["T1583.001"],
        "nist_csf": ["DE.CM"],
    },
    "vulnerability": {
        "owasp": ["A06:2021"], "cwe": ["CWE-1395"],
        "mitre_attack": ["T1190"], "nist_csf": ["ID.RA", "PR.PS"],
    },
    "misconfiguration": {
        "owasp": ["A05:2021"], "cwe": ["CWE-693"],
        "mitre_attack": [], "nist_csf": ["PR.PS"],
    },
    "web_vulnerability": {
        "owasp": ["A03:2021"], "cwe": [], "mitre_attack": ["T1190"],
        "nist_csf": ["ID.RA", "PR.PS"],
    },
    "campaign": {
        "owasp": [], "cwe": [], "mitre_attack": ["T1583.001"],
        "nist_csf": ["DE.CM", "RS.MI"],
    },
}

_MAP_PROMPT = """Map this security finding to the security frameworks below.

FINDING
  Title:    {title}
  Category: {category}
  Severity: {severity}
  Details:  {description}

RETRIEVED FRAMEWORK REFERENCES (you may ONLY choose codes from this list):
{context}

Choose only the codes that genuinely apply. It is correct to return an empty
list for a framework that does not apply to this finding.

Return JSON:
{{"owasp": [], "cwe": [], "mitre_attack": [], "nist_csf": [], "rationale": ""}}"""

_FRAMEWORK_FIELD = {
    "OWASP": "owasp", "OWASP-API": "owasp", "CWE": "cwe",
    "MITRE": "mitre_attack", "NIST-CSF": "nist_csf",
}

MAX_MAPPED = 12


async def _map_one(finding: Finding, retriever, llm) -> Finding:
    query = f"{finding.title}. {finding.description[:600]} category: {finding.category}"
    hits = await retriever.search(query, top_k=8)
    allowed_codes = {h.doc.code for h in hits}

    defaults = CATEGORY_DEFAULTS.get(finding.category, {})
    mapping: dict[str, list[str]] = {
        "owasp": list(defaults.get("owasp", [])),
        "cwe": list(finding.cwe) + list(defaults.get("cwe", [])),
        "mitre_attack": list(defaults.get("mitre_attack", [])),
        "nist_csf": list(defaults.get("nist_csf", [])),
    }

    if llm.enabled and hits:
        context = "\n\n".join(
            f"- {h.doc.framework} {h.doc.code}: {h.doc.title}\n  {h.doc.text[:280]}"
            for h in hits
        )
        proposal = await llm.structured(
            _MAP_PROMPT.format(
                title=finding.title, category=finding.category,
                severity=finding.severity.value,
                description=finding.description[:900], context=context,
            ),
            system="You map security findings to frameworks using only "
                   "the references provided.",
            max_tokens=500,
        )
        if proposal:
            for field in ("owasp", "cwe", "mitre_attack", "nist_csf"):
                for code in proposal.get(field, []) or []:
                    code = str(code).strip()
                    # The grounding check: retrieved set only, correct framework.
                    if code not in allowed_codes:
                        continue
                    doc = BY_CODE.get(code)
                    if doc and _FRAMEWORK_FIELD.get(doc.framework) == field:
                        mapping[field].append(code)

    for field, codes in mapping.items():
        seen: list[str] = []
        for code in codes:
            if code and code not in seen:
                seen.append(code)
        mapping[field] = seen[:4]

    finding.owasp = mapping["owasp"]
    finding.cwe = mapping["cwe"]
    finding.mitre_attack = mapping["mitre_attack"]
    finding.nist_csf = mapping["nist_csf"]

    references = list(finding.references)
    for code in mapping["owasp"] + mapping["cwe"] + mapping["mitre_attack"]:
        doc = BY_CODE.get(code)
        if doc and doc.url and doc.url not in references:
            references.append(doc.url)
    finding.references = references[:8]
    return finding


async def run(state: InvestigationState) -> InvestigationState:
    with timed_action("compliance", "map") as record:
        findings = state.get("findings", [])
        if not findings:
            record.detail = "no findings to map"
            return {"actions": [record]}

        retriever = get_retriever()
        llm = get_llm()

        # Map the most severe findings first and cap the count, mapping is the
        # most LLM-expensive stage and low findings rarely change a decision.
        ordered = sorted(findings, key=lambda f: (-f.severity.rank, -f.confidence))
        mapped = 0
        for finding in ordered[:MAX_MAPPED]:
            try:
                await _map_one(finding, retriever, llm)
                mapped += 1
            except Exception as exc:
                log.warning("compliance mapping failed for %s: %s", finding.title, exc)

        # Anything past the cap still gets the deterministic default mapping.
        for finding in ordered[MAX_MAPPED:]:
            defaults = CATEGORY_DEFAULTS.get(finding.category, {})
            finding.owasp = finding.owasp or list(defaults.get("owasp", []))
            finding.cwe = finding.cwe or list(defaults.get("cwe", []))
            finding.mitre_attack = finding.mitre_attack or list(
                defaults.get("mitre_attack", []))
            finding.nist_csf = finding.nist_csf or list(defaults.get("nist_csf", []))

        codes = {c for f in findings
                 for c in f.owasp + f.cwe + f.mitre_attack + f.nist_csf}
        record.detail = (f"{mapped} finding(s) mapped via RAG"
                         f"{' + LLM' if llm.enabled else ' (deterministic)'}; "
                         f"{len(codes)} distinct framework code(s)")

    return {"actions": [record]}
