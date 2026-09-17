"""Risk engine tests.

These encode the calibration decisions, especially the two that were wrong in
the first implementation: unreachable weight deflating real threats, and
missing data reading as a clean verdict.
"""
from threatiq.engine.risk_engine import RiskInput, assess
from threatiq.schemas import (
    Evidence,
    Finding,
    Severity,
    ToolStatus,
    Verdict,
)


def ev(source, verdict=Verdict.UNKNOWN, confidence=0.8, indicator="domain:x.com",
       status=ToolStatus.OK, **signals):
    return Evidence(source=source, tool="t", indicator=indicator, status=status,
                    verdict=verdict, confidence=confidence, signals=signals,
                    summary=f"{source} said {verdict.value}")


def finding(severity=Severity.CRITICAL, confidence=0.9, indicator="domain:x.com",
            category="phishing"):
    return Finding(title="t", description="d", category=category,
                   severity=severity, confidence=confidence,
                   indicators=[indicator])


def test_weights_sum_to_one():
    from threatiq.engine.risk_engine import WEIGHTS
    assert abs(sum(WEIGHTS.values()) - 1.0) < 1e-9


def test_no_evidence_scores_zero():
    result = assess(RiskInput(evidence=[], findings=[]))
    assert result.score == 0.0
    assert result.severity is Severity.INFO
    assert result.confidence == 0.0


def test_clean_critical_asset_is_not_medium_risk():
    """Exposure alone must never imply a threat."""
    result = assess(RiskInput(
        evidence=[ev("virustotal", Verdict.BENIGN),
                  ev("dns", Verdict.UNKNOWN, resolves=True)],
        findings=[], asset_criticality="critical", internet_exposed=True,
    ))
    assert result.score <= 10
    assert result.severity is Severity.INFO


def test_inapplicable_weight_does_not_deflate_a_real_threat():
    """A phishing case has no CVE and no reputation key. Those dimensions must
    be excluded from the denominator, not scored as zero."""
    result = assess(RiskInput(
        evidence=[
            ev("email", Verdict.MALICIOUS, 0.9, "email_message:submitted",
               phishing_score=0.9, reply_to_mismatch=True),
            ev("lookalike", Verdict.MALICIOUS, 0.85, score=0.95,
               matched_brand="microsoft", technique="character_substitution"),
        ],
        findings=[finding()],
        asset_criticality="high",
    ))
    assert result.score >= 65, f"phishing under-scored at {result.score}"
    assert result.severity.rank >= Severity.HIGH.rank
    # Exploitation could not be evaluated and must say so.
    exploitation = next(f for f in result.factors
                        if f.name == "Exploitation evidence")
    assert exploitation.applicable is False
    assert result.coverage < 1.0


def test_unknown_to_reputation_is_not_a_clean_verdict():
    """A source that has never seen the indicator has not cleared it."""
    result = assess(RiskInput(
        evidence=[
            ev("virustotal", Verdict.UNKNOWN, status=ToolStatus.NOT_FOUND),
            ev("urlscan", Verdict.UNKNOWN, status=ToolStatus.NOT_FOUND),
            ev("lookalike", Verdict.MALICIOUS, 0.9, score=0.95),
        ],
        findings=[finding()],
    ))
    reputation = next(f for f in result.factors
                      if f.name == "Threat intelligence reputation")
    assert reputation.applicable is False
    assert result.score >= 60


def test_reputation_scoped_to_suspected_indicator():
    """A clean verdict on an unrelated host must not dilute the score."""
    scoped = assess(RiskInput(
        evidence=[
            # Clean reputation, but for a host nothing has flagged.
            ev("virustotal", Verdict.BENIGN, 0.9, indicator="domain:relay.corp.com"),
            ev("lookalike", Verdict.MALICIOUS, 0.9, indicator="domain:evil.tk",
               score=0.95),
        ],
        findings=[finding(indicator="domain:evil.tk")],
    ))
    reputation = next(f for f in scoped.factors
                      if f.name == "Threat intelligence reputation")
    assert reputation.applicable is False, \
        "reputation of an unrelated host must not be scored"
    assert scoped.score >= 55


def test_kev_membership_drives_critical():
    result = assess(RiskInput(
        evidence=[
            ev("cisa_kev", Verdict.MALICIOUS, 0.98, "cve:CVE-2024-3400",
               in_kev=True, known_ransomware_use=True),
            ev("nvd", Verdict.MALICIOUS, 0.95, "cve:CVE-2024-3400",
               cvss_score=10.0, network_exploitable=True,
               no_privileges_required=True),
        ],
        findings=[finding(category="vulnerability", indicator="cve:CVE-2024-3400")],
        asset_criticality="critical",
    ))
    assert result.score >= 85
    assert result.severity is Severity.CRITICAL


def test_corroboration_increases_confidence():
    single = assess(RiskInput(
        evidence=[ev("virustotal", Verdict.MALICIOUS, 0.9)], findings=[finding()]))
    multi = assess(RiskInput(
        evidence=[ev("virustotal", Verdict.MALICIOUS, 0.9),
                  ev("abuseipdb", Verdict.MALICIOUS, 0.9),
                  ev("urlscan", Verdict.MALICIOUS, 0.9)],
        findings=[finding()]))
    assert multi.confidence > single.confidence
    assert multi.corroborating_sources == 3


def test_skipped_tools_lower_confidence_not_score():
    """Missing API keys must reduce confidence, never imply safety."""
    result = assess(RiskInput(
        evidence=[
            ev("virustotal", status=ToolStatus.SKIPPED, confidence=0.0),
            ev("abuseipdb", status=ToolStatus.SKIPPED, confidence=0.0),
            ev("lookalike", Verdict.MALICIOUS, 0.9, score=0.95),
        ],
        findings=[finding()],
    ))
    assert result.confidence < 0.8
    assert result.score >= 55


def test_not_internet_exposed_reduces_exposure_factor():
    exposed = assess(RiskInput(evidence=[ev("lookalike", Verdict.MALICIOUS, 0.9,
                                            score=0.9)],
                               findings=[finding()], internet_exposed=True))
    internal = assess(RiskInput(evidence=[ev("lookalike", Verdict.MALICIOUS, 0.9,
                                             score=0.9)],
                                findings=[finding()], internet_exposed=False))
    assert internal.score < exposed.score


def test_factors_are_auditable():
    result = assess(RiskInput(
        evidence=[ev("lookalike", Verdict.MALICIOUS, 0.9, score=0.9)],
        findings=[finding()]))
    assert result.factors
    for f in result.factors:
        assert f.rationale, f"{f.name} has no rationale"
        assert 0.0 <= f.value <= 1.0
        assert abs(f.contribution - f.weight * f.value) < 1e-6


def test_severity_thresholds():
    assert Severity.from_score(90) is Severity.CRITICAL
    assert Severity.from_score(70) is Severity.HIGH
    assert Severity.from_score(50) is Severity.MEDIUM
    assert Severity.from_score(20) is Severity.LOW
    assert Severity.from_score(5) is Severity.INFO
