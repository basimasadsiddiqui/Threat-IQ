"""Correlation agent, turns a pile of findings into one story.

Two jobs:
  1. Build the threat graph and read its structure (which indicator is the hub).
  2. Merge findings that describe the same thing, so the report says
     "this domain, its IP and the email that carried it are one campaign"
     rather than listing three unrelated items.
"""
from __future__ import annotations

import logging

from threatiq.agents.state import InvestigationState, timed_action
from threatiq.engine import threat_graph
from threatiq.schemas import Finding, Severity, Verdict

log = logging.getLogger(__name__)


async def run(state: InvestigationState) -> InvestigationState:
    with timed_action("correlation", "correlate") as record:
        indicators = state.get("indicators", [])
        evidence = state.get("evidence", [])
        # Already de-duplicated by the findings reducer in state.py.
        findings = state.get("findings", [])

        graph = threat_graph.build(indicators, evidence, findings)
        analysis = threat_graph.analyze(graph)

        # --- campaign linkage ---
        # Indicators that share an IP, a redirect target, or an impersonated
        # brand are almost always one operation rather than coincidence.
        clusters: dict[str, set[str]] = {}
        for edge in graph.edges:
            if edge.relation in ("resolves_to", "redirects_to", "links_to",
                                 "impersonates", "pivoted_to"):
                clusters.setdefault(edge.target, set()).add(edge.source)

        linked = {
            target: sorted(sources)
            for target, sources in clusters.items() if len(sources) > 1
        }

        new_findings: list[Finding] = []
        malicious_nodes = analysis.get("malicious_nodes", [])
        # Require an actual observed relationship between them, otherwise two
        # unrelated bad indicators in one submission read as a "campaign".
        connected_malicious = [
            n for n in malicious_nodes
            if any(e.source == n or e.target == n for e in graph.edges
                   if e.relation in ("resolves_to", "redirects_to", "links_to",
                                     "pivoted_to", "impersonates"))
        ]
        if len(connected_malicious) >= 2:
            new_findings.append(Finding(
                title="Correlated malicious infrastructure cluster",
                description=(
                    f"{len(connected_malicious)} indicators in this investigation are "
                    f"independently classified as malicious and are connected "
                    f"through observed relationships (DNS resolution, redirects "
                    f"or embedded links): "
                    f"{', '.join(n.split(':', 1)[-1] for n in connected_malicious[:8])}. "
                    f"They should be treated as a single cluster and blocked "
                    f"together rather than individually."
                ),
                category="campaign",
                severity=Severity.HIGH,
                confidence=0.75,
                indicators=connected_malicious[:10],
                agent="correlation",
            ))

        for target, sources in list(linked.items())[:3]:
            if not target.startswith(("ipv4:", "domain:")):
                continue
            new_findings.append(Finding(
                title=f"Shared infrastructure: {target.split(':', 1)[1]}",
                description=(
                    f"{len(sources)} indicator(s) in this investigation converge "
                    f"on {target.split(':', 1)[1]}: "
                    f"{', '.join(s.split(':', 1)[-1] for s in sources[:6])}. "
                    f"Blocking the shared node disrupts all of them at once."
                ),
                category="campaign", severity=Severity.MEDIUM, confidence=0.7,
                indicators=[target] + sources[:5], agent="correlation",
            ))

        correlation = {
            **analysis,
            "linked_indicators": linked,
            "verdict_counts": {
                v.value: sum(1 for e in evidence if e.verdict == v)
                for v in Verdict
            },
        }
        record.detail = (
            f"graph: {analysis['node_count']} nodes / {analysis['edge_count']} edges, "
            f"{analysis['components']} component(s); "
            f"{len(findings)} existing finding(s), "
            f"{len(new_findings)} correlation finding(s)"
        )

    return {
        "graph": graph,
        "correlation": correlation,
        "findings": new_findings,
        "actions": [record],
    }
