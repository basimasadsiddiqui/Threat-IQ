"""SQLAlchemy models.

The schema keeps evidence, findings and risk factors as separate rows rather
than one JSON blob, because the Copilot needs to query across investigations
("show me everything related to this IP") and that has to be an index lookup.
"""
from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import (
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


def utcnow() -> datetime:
    return datetime.now(UTC)


class Base(DeclarativeBase):
    pass


class Investigation(Base):
    __tablename__ = "investigations"

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True),
                                                 default=utcnow, index=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    status: Mapped[str] = mapped_column(String(20), default="pending", index=True)
    input: Mapped[str] = mapped_column(Text)
    kind: Mapped[str] = mapped_column(String(32), index=True)

    risk_score: Mapped[float] = mapped_column(Float, default=0.0, index=True)
    severity: Mapped[str] = mapped_column(String(16), default="info", index=True)
    confidence: Mapped[float] = mapped_column(Float, default=0.0)
    coverage: Mapped[float] = mapped_column(Float, default=0.0)

    summary: Mapped[str] = mapped_column(Text, default="")
    risk_explanation: Mapped[str] = mapped_column(Text, default="")
    risk_factors: Mapped[list] = mapped_column(JSONB, default=list)
    graph: Mapped[dict] = mapped_column(JSONB, default=dict)
    remediation: Mapped[list] = mapped_column(JSONB, default=list)
    agent_actions: Mapped[list] = mapped_column(JSONB, default=list)
    error: Mapped[str | None] = mapped_column(Text)

    indicators: Mapped[list[IndicatorRow]] = relationship(
        back_populates="investigation", cascade="all, delete-orphan")
    evidence: Mapped[list[EvidenceRow]] = relationship(
        back_populates="investigation", cascade="all, delete-orphan")
    findings: Mapped[list[FindingRow]] = relationship(
        back_populates="investigation", cascade="all, delete-orphan")


class IndicatorRow(Base):
    __tablename__ = "indicators"

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    investigation_id: Mapped[str] = mapped_column(
        ForeignKey("investigations.id", ondelete="CASCADE"), index=True)
    type: Mapped[str] = mapped_column(String(24), index=True)
    value: Mapped[str] = mapped_column(String(2048), index=True)
    ioc_key: Mapped[str] = mapped_column(String(2100), index=True)
    source: Mapped[str] = mapped_column(String(64), default="user_input")
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True),
                                                 default=utcnow)
    investigation: Mapped[Investigation] = relationship(back_populates="indicators")


class EvidenceRow(Base):
    __tablename__ = "evidence"

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    investigation_id: Mapped[str] = mapped_column(
        ForeignKey("investigations.id", ondelete="CASCADE"), index=True)
    source: Mapped[str] = mapped_column(String(48), index=True)
    tool: Mapped[str] = mapped_column(String(48))
    indicator: Mapped[str] = mapped_column(String(2100), index=True)
    status: Mapped[str] = mapped_column(String(20), index=True)
    verdict: Mapped[str] = mapped_column(String(20), index=True)
    confidence: Mapped[float] = mapped_column(Float, default=0.0)
    severity_hint: Mapped[str] = mapped_column(String(16), default="info")
    summary: Mapped[str] = mapped_column(Text, default="")
    signals: Mapped[dict] = mapped_column(JSONB, default=dict)
    raw: Mapped[dict] = mapped_column(JSONB, default=dict)
    error: Mapped[str | None] = mapped_column(Text)
    latency_ms: Mapped[int] = mapped_column(Integer, default=0)
    collected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True),
                                                   default=utcnow)
    investigation: Mapped[Investigation] = relationship(back_populates="evidence")


class FindingRow(Base):
    __tablename__ = "findings"

    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    investigation_id: Mapped[str] = mapped_column(
        ForeignKey("investigations.id", ondelete="CASCADE"), index=True)
    title: Mapped[str] = mapped_column(String(512))
    description: Mapped[str] = mapped_column(Text, default="")
    category: Mapped[str] = mapped_column(String(48), index=True)
    severity: Mapped[str] = mapped_column(String(16), index=True)
    confidence: Mapped[float] = mapped_column(Float, default=0.0)
    agent: Mapped[str] = mapped_column(String(32), index=True)
    indicators: Mapped[list] = mapped_column(JSONB, default=list)
    evidence_ids: Mapped[list] = mapped_column(JSONB, default=list)
    owasp: Mapped[list] = mapped_column(JSONB, default=list)
    cwe: Mapped[list] = mapped_column(JSONB, default=list)
    mitre_attack: Mapped[list] = mapped_column(JSONB, default=list)
    nist_csf: Mapped[list] = mapped_column(JSONB, default=list)
    references: Mapped[list] = mapped_column(JSONB, default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True),
                                                 default=utcnow, index=True)
    investigation: Mapped[Investigation] = relationship(back_populates="findings")


class AuditLog(Base):
    """Append-only record of every state-changing request."""
    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    at: Mapped[datetime] = mapped_column(DateTime(timezone=True),
                                         default=utcnow, index=True)
    actor: Mapped[str] = mapped_column(String(128), default="anonymous")
    action: Mapped[str] = mapped_column(String(64), index=True)
    target: Mapped[str] = mapped_column(String(256), default="")
    detail: Mapped[dict] = mapped_column(JSONB, default=dict)
    success: Mapped[bool] = mapped_column(Boolean, default=True)


# Cross-investigation IOC lookup is the Copilot's hottest query path.
Index("ix_indicators_value_type", IndicatorRow.value, IndicatorRow.type)
Index("ix_evidence_indicator_verdict", EvidenceRow.indicator, EvidenceRow.verdict)
Index("ix_findings_severity_created", FindingRow.severity, FindingRow.created_at)
