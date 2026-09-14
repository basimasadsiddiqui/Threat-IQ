"""Repository layer.

Two interchangeable implementations behind one interface: PostgreSQL when
DATABASE_URL is set, and an in-memory store otherwise. The in-memory path is
not a stub, it implements the same queries, so ThreatIQ is fully usable, and
fully testable, with no database running.
"""
from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Any

from threatiq.config import Settings, get_settings
from threatiq.schemas import InvestigationReport, Severity

log = logging.getLogger(__name__)


class Repository(ABC):
    @abstractmethod
    async def save(self, report: InvestigationReport) -> None: ...

    @abstractmethod
    async def get(self, investigation_id: str) -> InvestigationReport | None: ...

    @abstractmethod
    async def list_recent(self, limit: int = 50,
                          min_severity: str | None = None) -> list[dict[str, Any]]: ...

    @abstractmethod
    async def search_indicator(self, value: str) -> list[dict[str, Any]]: ...

    @abstractmethod
    async def stats(self) -> dict[str, Any]: ...

    @abstractmethod
    async def audit(self, actor: str, action: str, target: str = "",
                    detail: dict | None = None, success: bool = True) -> None: ...

    async def close(self) -> None:
        return None


class InMemoryRepository(Repository):
    """Process-local store. Data is lost on restart, acceptable for dev and
    tests, and the API reports which backend is in use so it is never a
    surprise in a demo."""

    def __init__(self, max_reports: int = 500) -> None:
        self._reports: dict[str, InvestigationReport] = {}
        self._order: list[str] = []
        self._audit: list[dict[str, Any]] = []
        self._max = max_reports

    async def save(self, report: InvestigationReport) -> None:
        if report.id not in self._reports:
            self._order.append(report.id)
        self._reports[report.id] = report
        while len(self._order) > self._max:
            self._reports.pop(self._order.pop(0), None)

    async def get(self, investigation_id: str) -> InvestigationReport | None:
        return self._reports.get(investigation_id)

    async def list_recent(self, limit: int = 50,
                          min_severity: str | None = None) -> list[dict[str, Any]]:
        threshold = Severity(min_severity).rank if min_severity else -1
        rows = []
        for rid in reversed(self._order):
            report = self._reports.get(rid)
            if report is None or report.risk.severity.rank < threshold:
                continue
            rows.append(_summary_row(report))
            if len(rows) >= limit:
                break
        return rows

    async def search_indicator(self, value: str) -> list[dict[str, Any]]:
        needle = value.strip().lower()
        hits = []
        for rid in reversed(self._order):
            report = self._reports.get(rid)
            if report is None:
                continue
            matched = [i for i in report.indicators if needle in i.value.lower()]
            if not matched:
                continue
            hits.append({
                **_summary_row(report),
                "matched_indicators": [i.value for i in matched],
                "related_findings": [
                    {"title": f.title, "severity": f.severity.value}
                    for f in report.findings
                    if any(m.key in f.indicators for m in matched)
                ],
            })
        return hits

    async def stats(self) -> dict[str, Any]:
        reports = list(self._reports.values())
        by_severity: dict[str, int] = {}
        for r in reports:
            key = r.risk.severity.value
            by_severity[key] = by_severity.get(key, 0) + 1
        findings = [f for r in reports for f in r.findings]
        by_category: dict[str, int] = {}
        for f in findings:
            by_category[f.category] = by_category.get(f.category, 0) + 1
        return {
            "backend": "memory",
            "investigations": len(reports),
            "findings": len(findings),
            "by_severity": by_severity,
            "by_category": by_category,
            "mean_risk": round(
                sum(r.risk.score for r in reports) / len(reports), 1
            ) if reports else 0.0,
        }

    async def audit(self, actor: str, action: str, target: str = "",
                    detail: dict | None = None, success: bool = True) -> None:
        self._audit.append({
            "at": datetime.now(timezone.utc).isoformat(), "actor": actor,
            "action": action, "target": target, "detail": detail or {},
            "success": success,
        })
        del self._audit[:-2000]


def _summary_row(report: InvestigationReport) -> dict[str, Any]:
    return {
        "id": report.id,
        "created_at": report.created_at.isoformat(),
        "status": report.status,
        "input": report.input[:180],
        "kind": report.kind.value,
        "risk_score": report.risk.score,
        "severity": report.risk.severity.value,
        "confidence": report.risk.confidence,
        "finding_count": len(report.findings),
        "evidence_count": len(report.evidence),
    }


class PostgresRepository(Repository):
    """Async SQLAlchemy over PostgreSQL."""

    def __init__(self, settings: Settings) -> None:
        from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

        url = settings.database_url
        # Accept the sync-style URL people paste from psql and upgrade it.
        if url.startswith("postgresql://"):
            url = url.replace("postgresql://", "postgresql+psycopg://", 1)
        self.engine = create_async_engine(
            url, echo=settings.db_echo, pool_pre_ping=True, pool_size=5,
            max_overflow=10,
        )
        self.session_factory = async_sessionmaker(self.engine, expire_on_commit=False)

    # Indexes that need an extension or an expression SQLAlchemy cannot model.
    # Applied after create_all because they depend on those tables existing.
    _POST_CREATE_DDL = (
        # Makes the Copilot's cross-investigation ILIKE indicator search an
        # index scan instead of a sequential one.
        "CREATE INDEX IF NOT EXISTS ix_indicators_value_trgm "
        "ON indicators USING gin (value gin_trgm_ops)",
    )

    async def create_all(self) -> None:
        from sqlalchemy import text

        from threatiq.db.models import Base

        async with self.engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

        for statement in self._POST_CREATE_DDL:
            try:
                async with self.engine.begin() as conn:
                    await conn.execute(text(statement))
            except Exception as exc:
                # pg_trgm may not be installed on a managed instance; the query
                # still works without the index, just slower.
                log.warning("optional index skipped (%s): %s",
                            statement.split()[5], exc)

    async def save(self, report: InvestigationReport) -> None:
        from threatiq.db.models import (
            EvidenceRow, FindingRow, IndicatorRow, Investigation,
        )

        async with self.session_factory() as session:
            async with session.begin():
                row = Investigation(
                    id=report.id, created_at=report.created_at,
                    completed_at=report.completed_at, status=report.status,
                    input=report.input, kind=report.kind.value,
                    risk_score=report.risk.score,
                    severity=report.risk.severity.value,
                    confidence=report.risk.confidence,
                    coverage=report.risk.coverage,
                    summary=report.summary,
                    risk_explanation=report.risk.explanation,
                    risk_factors=[f.model_dump() for f in report.risk.factors],
                    graph=report.graph.model_dump(mode="json"),
                    remediation=[a.model_dump() for a in report.remediation],
                    agent_actions=[a.model_dump(mode="json") for a in report.actions],
                    error=report.error,
                )
                await session.merge(row)

                for ind in report.indicators:
                    await session.merge(IndicatorRow(
                        id=ind.id, investigation_id=report.id, type=ind.type.value,
                        value=ind.value[:2048], ioc_key=ind.key[:2100],
                        source=ind.source, first_seen=ind.first_seen,
                    ))
                for ev in report.evidence:
                    await session.merge(EvidenceRow(
                        id=ev.id, investigation_id=report.id, source=ev.source,
                        tool=ev.tool, indicator=ev.indicator[:2100],
                        status=ev.status.value, verdict=ev.verdict.value,
                        confidence=ev.confidence,
                        severity_hint=ev.severity_hint.value,
                        summary=ev.summary, signals=_jsonable(ev.signals),
                        raw=_jsonable(ev.raw), error=ev.error,
                        latency_ms=ev.latency_ms, collected_at=ev.collected_at,
                    ))
                for f in report.findings:
                    await session.merge(FindingRow(
                        id=f.id, investigation_id=report.id, title=f.title[:512],
                        description=f.description, category=f.category,
                        severity=f.severity.value, confidence=f.confidence,
                        agent=f.agent, indicators=f.indicators,
                        evidence_ids=f.evidence_ids, owasp=f.owasp, cwe=f.cwe,
                        mitre_attack=f.mitre_attack, nist_csf=f.nist_csf,
                        references=f.references,
                    ))

    async def get(self, investigation_id: str) -> InvestigationReport | None:
        from sqlalchemy import select
        from sqlalchemy.orm import selectinload

        from threatiq.db.models import Investigation

        async with self.session_factory() as session:
            result = await session.execute(
                select(Investigation)
                .options(
                    selectinload(Investigation.indicators),
                    selectinload(Investigation.evidence),
                    selectinload(Investigation.findings),
                )
                .where(Investigation.id == investigation_id)
            )
            row = result.scalar_one_or_none()
            return _row_to_report(row) if row else None

    async def list_recent(self, limit: int = 50,
                          min_severity: str | None = None) -> list[dict[str, Any]]:
        from sqlalchemy import func, select

        from threatiq.db.models import FindingRow, Investigation

        async with self.session_factory() as session:
            stmt = select(Investigation).order_by(Investigation.created_at.desc())
            if min_severity:
                threshold = Severity(min_severity).rank
                allowed = [s.value for s in Severity if s.rank >= threshold]
                stmt = stmt.where(Investigation.severity.in_(allowed))
            rows = (await session.execute(stmt.limit(limit))).scalars().all()

            counts = dict((await session.execute(
                select(FindingRow.investigation_id, func.count(FindingRow.id))
                .where(FindingRow.investigation_id.in_([r.id for r in rows] or [""]))
                .group_by(FindingRow.investigation_id)
            )).all())

            return [{
                "id": r.id, "created_at": r.created_at.isoformat(),
                "status": r.status, "input": r.input[:180], "kind": r.kind,
                "risk_score": r.risk_score, "severity": r.severity,
                "confidence": r.confidence,
                "finding_count": counts.get(r.id, 0), "evidence_count": 0,
            } for r in rows]

    async def search_indicator(self, value: str) -> list[dict[str, Any]]:
        from sqlalchemy import select
        from sqlalchemy.orm import selectinload

        from threatiq.db.models import IndicatorRow, Investigation

        needle = f"%{value.strip().lower()}%"
        async with self.session_factory() as session:
            ids = (await session.execute(
                select(IndicatorRow.investigation_id)
                .where(IndicatorRow.value.ilike(needle))
                .distinct().limit(50)
            )).scalars().all()
            if not ids:
                return []
            rows = (await session.execute(
                select(Investigation)
                .options(selectinload(Investigation.findings),
                         selectinload(Investigation.indicators))
                .where(Investigation.id.in_(ids))
                .order_by(Investigation.created_at.desc())
            )).scalars().all()

            out = []
            for r in rows:
                matched = [i.value for i in r.indicators
                           if value.strip().lower() in i.value.lower()]
                out.append({
                    "id": r.id, "created_at": r.created_at.isoformat(),
                    "status": r.status, "input": r.input[:180], "kind": r.kind,
                    "risk_score": r.risk_score, "severity": r.severity,
                    "confidence": r.confidence,
                    "finding_count": len(r.findings),
                    "evidence_count": 0,
                    "matched_indicators": matched,
                    "related_findings": [
                        {"title": f.title, "severity": f.severity}
                        for f in r.findings
                    ],
                })
            return out

    async def stats(self) -> dict[str, Any]:
        from sqlalchemy import func, select

        from threatiq.db.models import FindingRow, Investigation

        async with self.session_factory() as session:
            total = (await session.execute(
                select(func.count(Investigation.id)))).scalar() or 0
            mean = (await session.execute(
                select(func.avg(Investigation.risk_score)))).scalar() or 0.0
            by_severity = dict((await session.execute(
                select(Investigation.severity, func.count(Investigation.id))
                .group_by(Investigation.severity))).all())
            findings_total = (await session.execute(
                select(func.count(FindingRow.id)))).scalar() or 0
            by_category = dict((await session.execute(
                select(FindingRow.category, func.count(FindingRow.id))
                .group_by(FindingRow.category))).all())
            return {
                "backend": "postgres", "investigations": total,
                "findings": findings_total, "by_severity": by_severity,
                "by_category": by_category, "mean_risk": round(float(mean), 1),
            }

    async def audit(self, actor: str, action: str, target: str = "",
                    detail: dict | None = None, success: bool = True) -> None:
        from threatiq.db.models import AuditLog

        async with self.session_factory() as session:
            async with session.begin():
                session.add(AuditLog(
                    actor=actor[:128], action=action[:64], target=target[:256],
                    detail=_jsonable(detail or {}), success=success,
                ))

    async def close(self) -> None:
        await self.engine.dispose()


def _jsonable(value: Any) -> Any:
    """JSONB columns reject datetimes and sets; normalise before writing."""
    if isinstance(value, dict):
        return {str(k): _jsonable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_jsonable(v) for v in value]
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return str(value)


def _row_to_report(row: Any) -> InvestigationReport:
    from threatiq.schemas import (
        AgentAction, Evidence, Finding, Indicator, InputKind, RemediationAction,
        RiskAssessment, RiskFactor, ThreatGraph,
    )

    return InvestigationReport(
        id=row.id, created_at=row.created_at, completed_at=row.completed_at,
        status=row.status, input=row.input, kind=InputKind(row.kind),
        summary=row.summary, error=row.error,
        indicators=[Indicator(id=i.id, type=i.type, value=i.value,
                              source=i.source, first_seen=i.first_seen)
                    for i in row.indicators],
        evidence=[Evidence(id=e.id, source=e.source, tool=e.tool,
                           indicator=e.indicator, status=e.status,
                           verdict=e.verdict, confidence=e.confidence,
                           severity_hint=e.severity_hint, summary=e.summary,
                           signals=e.signals or {}, raw=e.raw or {},
                           error=e.error, latency_ms=e.latency_ms,
                           collected_at=e.collected_at)
                  for e in row.evidence],
        findings=[Finding(id=f.id, title=f.title, description=f.description,
                          category=f.category, severity=f.severity,
                          confidence=f.confidence, agent=f.agent,
                          indicators=f.indicators or [],
                          evidence_ids=f.evidence_ids or [],
                          owasp=f.owasp or [], cwe=f.cwe or [],
                          mitre_attack=f.mitre_attack or [],
                          nist_csf=f.nist_csf or [],
                          references=f.references or [])
                  for f in row.findings],
        risk=RiskAssessment(
            score=row.risk_score, severity=row.severity,
            confidence=row.confidence, coverage=row.coverage,
            explanation=row.risk_explanation,
            factors=[RiskFactor(**f) for f in (row.risk_factors or [])],
        ),
        graph=ThreatGraph(**(row.graph or {})),
        remediation=[RemediationAction(**a) for a in (row.remediation or [])],
        actions=[AgentAction(**a) for a in (row.agent_actions or [])],
    )


_repo: Repository | None = None


async def get_repository() -> Repository:
    global _repo
    if _repo is not None:
        return _repo
    settings = get_settings()
    if settings.database_url:
        try:
            pg = PostgresRepository(settings)
            await pg.create_all()
            _repo = pg
            log.info("repository backend: postgres")
            return _repo
        except Exception as exc:
            # A database that is configured but unreachable should degrade to
            # in-memory rather than take the whole service down.
            log.error("postgres unavailable (%s); falling back to in-memory", exc)
    _repo = InMemoryRepository()
    log.info("repository backend: in-memory")
    return _repo


async def reset_repository() -> None:
    global _repo
    if _repo is not None:
        await _repo.close()
    _repo = None
