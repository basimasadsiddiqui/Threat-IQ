"""Data contracts shared by tools, agents, API and UI.

The whole pipeline is typed end to end: tools emit Evidence, agents emit
Findings, the risk engine consumes both. Nothing downstream parses free text.
"""
from __future__ import annotations

import uuid
from datetime import UTC, datetime
from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, Field, SecretStr


def _now() -> datetime:
    return datetime.now(UTC)


def _uid() -> str:
    return uuid.uuid4().hex[:12]


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}[self.value]

    @classmethod
    def from_score(cls, score: float) -> Severity:
        if score >= 85:
            return cls.CRITICAL
        if score >= 65:
            return cls.HIGH
        if score >= 40:
            return cls.MEDIUM
        if score >= 15:
            return cls.LOW
        return cls.INFO


class IndicatorType(str, Enum):
    URL = "url"
    DOMAIN = "domain"
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    EMAIL = "email"
    EMAIL_MESSAGE = "email_message"
    FILE_HASH = "file_hash"
    CVE = "cve"
    ASN = "asn"
    UNKNOWN = "unknown"


class InputKind(str, Enum):
    """What the user actually submitted, which drives orchestrator routing."""
    URL = "url"
    DOMAIN = "domain"
    IP = "ip"
    EMAIL_MESSAGE = "email_message"
    FILE_HASH = "file_hash"
    CVE = "cve"
    WEB_TARGET = "web_target"
    FREE_TEXT = "free_text"


class Verdict(str, Enum):
    MALICIOUS = "malicious"
    SUSPICIOUS = "suspicious"
    BENIGN = "benign"
    UNKNOWN = "unknown"


class Indicator(BaseModel):
    id: str = Field(default_factory=_uid)
    type: IndicatorType
    value: str
    # Where this indicator came from, user input, or pivoted from another IOC.
    source: str = "user_input"
    parent_id: str | None = None
    first_seen: datetime = Field(default_factory=_now)

    @property
    def key(self) -> str:
        return f"{self.type.value}:{self.value.lower()}"


class ToolStatus(str, Enum):
    OK = "ok"
    ERROR = "error"
    SKIPPED = "skipped"          # not configured
    RATE_LIMITED = "rate_limited"
    NOT_FOUND = "not_found"
    REFUSED = "refused"          # e.g. unauthorized active scan target


class Evidence(BaseModel):
    """One atomic fact returned by one tool about one indicator.

    `raw` keeps the upstream payload for audit; `summary` and the normalized
    fields are what the risk engine reads. The LLM never writes these.
    """
    id: str = Field(default_factory=_uid)
    source: str                       # "virustotal", "abuseipdb", "dns", ...
    tool: str                         # specific endpoint/method
    indicator: str                    # Indicator.key
    status: ToolStatus = ToolStatus.OK
    verdict: Verdict = Verdict.UNKNOWN
    confidence: float = 0.5           # 0..1, how much we trust this source here
    severity_hint: Severity = Severity.INFO
    summary: str = ""
    signals: dict[str, Any] = Field(default_factory=dict)
    raw: dict[str, Any] = Field(default_factory=dict)
    error: str | None = None
    latency_ms: int = 0
    collected_at: datetime = Field(default_factory=_now)


class Finding(BaseModel):
    """An analyst-level conclusion drawn from one or more pieces of evidence."""
    id: str = Field(default_factory=_uid)
    title: str
    description: str
    category: str                     # "phishing", "malicious_infra", "vuln", ...
    severity: Severity = Severity.MEDIUM
    confidence: float = 0.5
    indicators: list[str] = Field(default_factory=list)
    evidence_ids: list[str] = Field(default_factory=list)
    agent: str = "unknown"
    # Populated by the compliance mapper.
    owasp: list[str] = Field(default_factory=list)
    cwe: list[str] = Field(default_factory=list)
    mitre_attack: list[str] = Field(default_factory=list)
    nist_csf: list[str] = Field(default_factory=list)
    references: list[str] = Field(default_factory=list)


class RiskFactor(BaseModel):
    """One additive component of the risk score, kept visible for auditability."""
    name: str
    weight: float
    value: float            # 0..1 normalized
    contribution: float     # weight * value
    rationale: str
    # False when this dimension could not be evaluated at all, no CVE in a
    # phishing case, no reputation key configured. Inapplicable factors are
    # excluded from the denominator instead of silently scoring zero.
    applicable: bool = True


class RiskAssessment(BaseModel):
    score: float = 0.0                 # 0..100
    severity: Severity = Severity.INFO
    confidence: float = 0.0            # 0..1
    factors: list[RiskFactor] = Field(default_factory=list)
    explanation: str = ""
    evidence_count: int = 0
    corroborating_sources: int = 0
    # Share of the total weight that could actually be evaluated (0..1).
    coverage: float = 0.0


class GraphNode(BaseModel):
    id: str
    label: str
    type: str
    verdict: Verdict = Verdict.UNKNOWN
    meta: dict[str, Any] = Field(default_factory=dict)


class GraphEdge(BaseModel):
    source: str
    target: str
    relation: str
    meta: dict[str, Any] = Field(default_factory=dict)


class ThreatGraph(BaseModel):
    nodes: list[GraphNode] = Field(default_factory=list)
    edges: list[GraphEdge] = Field(default_factory=list)


class RemediationAction(BaseModel):
    priority: int = 3                  # 1 = do first
    action: str
    rationale: str
    owner: str = "security_team"
    effort: Literal["low", "medium", "high"] = "medium"
    automatable: bool = False
    references: list[str] = Field(default_factory=list)


class AgentAction(BaseModel):
    """Audit trail entry, what each agent did, so runs are reproducible."""
    id: str = Field(default_factory=_uid)
    agent: str
    action: str
    detail: str = ""
    started_at: datetime = Field(default_factory=_now)
    duration_ms: int = 0
    status: str = "ok"


class WithKeyOverrides(BaseModel):
    """Mixin for requests that may carry the caller's own API keys.

    Lets an analyst bring their own credentials instead of the deployment
    holding a shared set, which is what makes a public console safe to offer:
    nothing is written to disk and one caller's keys are never visible to
    another.

    Two protections, both structural rather than remembered:

    `SecretStr` means an accidental log line, a traceback or a `model_dump()`
    prints `**********` instead of the key. Requests get logged eventually,
    somewhere, by someone, and that is exactly when a plain `str` would burn a
    credential.

    `exclude=True` keeps the field out of every serialization of the request,
    so it cannot ride along into a stored report or an audit record.

    Which field names are actually honoured is decided in one place, by
    `Settings.with_overrides`, and nowhere else.
    """
    key_overrides: dict[str, SecretStr] = Field(
        default_factory=dict, exclude=True, max_length=16,
    )

    def resolved_overrides(self) -> dict[str, str]:
        """Plain values, for `Settings.with_overrides`. Keep the result local."""
        return {
            name: secret.get_secret_value()
            for name, secret in self.key_overrides.items()
        }


class InvestigationRequest(WithKeyOverrides):
    input: str = Field(min_length=1, max_length=200_000)
    kind: InputKind | None = None      # None -> auto-detect
    context: dict[str, Any] = Field(default_factory=dict)
    # Asset metadata feeds the risk engine; unknown values fall back to defaults.
    asset_criticality: Literal["low", "medium", "high", "critical"] = "medium"
    internet_exposed: bool = True
    allow_active_scan: bool = False


class InvestigationReport(BaseModel):
    id: str = Field(default_factory=_uid)
    created_at: datetime = Field(default_factory=_now)
    completed_at: datetime | None = None
    status: Literal["pending", "running", "completed", "failed"] = "pending"
    input: str = ""
    kind: InputKind = InputKind.FREE_TEXT
    indicators: list[Indicator] = Field(default_factory=list)
    evidence: list[Evidence] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    risk: RiskAssessment = Field(default_factory=RiskAssessment)
    graph: ThreatGraph = Field(default_factory=ThreatGraph)
    remediation: list[RemediationAction] = Field(default_factory=list)
    actions: list[AgentAction] = Field(default_factory=list)
    summary: str = ""
    error: str | None = None

    @property
    def duration_s(self) -> float:
        if not self.completed_at:
            return 0.0
        return (self.completed_at - self.created_at).total_seconds()


class CopilotRequest(WithKeyOverrides):
    question: str = Field(min_length=1, max_length=4000)
    investigation_id: str | None = None
    history: list[dict[str, str]] = Field(default_factory=list)


class CopilotResponse(BaseModel):
    answer: str
    citations: list[str] = Field(default_factory=list)
    used_context: list[str] = Field(default_factory=list)
