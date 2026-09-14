"""Evidence correlation as a graph.

Nodes are indicators and sources; edges are the relationships the tools
actually observed (resolves_to, redirects_to, reported_by). NetworkX gives us
the analytics (centrality, components) and PyVis renders it for the dashboard.
"""
from __future__ import annotations

import logging
from typing import Any

from threatiq.schemas import (
    Evidence, Finding, GraphEdge, GraphNode, Indicator, ThreatGraph, Verdict,
)

log = logging.getLogger(__name__)


def build(indicators: list[Indicator], evidence: list[Evidence],
          findings: list[Finding]) -> ThreatGraph:
    nodes: dict[str, GraphNode] = {}
    edges: list[GraphEdge] = []
    seen_edges: set[tuple[str, str, str]] = set()

    def add_node(node_id: str, label: str, ntype: str,
                 verdict: Verdict = Verdict.UNKNOWN, **meta: Any) -> None:
        existing = nodes.get(node_id)
        if existing is None:
            nodes[node_id] = GraphNode(
                id=node_id, label=label, type=ntype, verdict=verdict, meta=meta
            )
        else:
            # Keep the worst verdict any source assigned to this node.
            order = [Verdict.UNKNOWN, Verdict.BENIGN, Verdict.SUSPICIOUS, Verdict.MALICIOUS]
            if order.index(verdict) > order.index(existing.verdict):
                existing.verdict = verdict
            existing.meta.update({k: v for k, v in meta.items() if v not in (None, "", [])})

    def add_edge(src: str, dst: str, relation: str, **meta: Any) -> None:
        key = (src, dst, relation)
        if key in seen_edges or src == dst:
            return
        if src not in nodes or dst not in nodes:
            return
        seen_edges.add(key)
        edges.append(GraphEdge(source=src, target=dst, relation=relation, meta=meta))

    # --- indicator nodes ---
    for ind in indicators:
        add_node(ind.key, ind.value, ind.type.value, source=ind.source)
        if ind.parent_id:
            parent = next((i for i in indicators if i.id == ind.parent_id), None)
            if parent:
                add_edge(parent.key, ind.key, "pivoted_to")

    # --- verdicts and source nodes from evidence ---
    for ev in evidence:
        if ev.indicator in nodes and ev.verdict != Verdict.UNKNOWN:
            add_node(ev.indicator, nodes[ev.indicator].label,
                     nodes[ev.indicator].type, ev.verdict)

        if ev.status.value != "ok":
            continue

        source_id = f"source:{ev.source}"
        add_node(source_id, ev.source, "source", ev.verdict)
        if ev.indicator in nodes:
            add_edge(source_id, ev.indicator, "reported_on",
                     verdict=ev.verdict.value, summary=ev.summary[:160],
                     confidence=ev.confidence)

        # --- relationships the tools observed directly ---
        for ip in ev.signals.get("ips", []) or ev.signals.get("observed_ips", []):
            ip_id = f"ipv4:{str(ip).lower()}"
            add_node(ip_id, str(ip), "ipv4")
            add_edge(ev.indicator, ip_id, "resolves_to")

        chain = ev.signals.get("redirect_chain") or []
        for i in range(len(chain) - 1):
            src_url = str(chain[i].get("url", "")).lower()
            dst_url = str(chain[i + 1].get("url", "")).lower()
            if not src_url or not dst_url:
                continue
            add_node(f"url:{src_url}", chain[i]["url"], "url")
            add_node(f"url:{dst_url}", chain[i + 1]["url"], "url")
            add_edge(f"url:{src_url}", f"url:{dst_url}", "redirects_to",
                     status=chain[i].get("status"))

        for domain in ev.signals.get("link_domains", []) or []:
            dom_id = f"domain:{str(domain).lower()}"
            add_node(dom_id, str(domain), "domain")
            add_edge("email_message:submitted", dom_id, "links_to")

        brand = ev.signals.get("matched_brand")
        if brand:
            brand_id = f"brand:{brand}"
            add_node(brand_id, f"{brand} (impersonated)", "brand", Verdict.UNKNOWN)
            add_edge(ev.indicator, brand_id, "impersonates",
                     technique=ev.signals.get("technique"))

    # --- findings tie evidence back to conclusions ---
    for finding in findings:
        finding_id = f"finding:{finding.id}"
        verdict = (Verdict.MALICIOUS if finding.severity.rank >= 3
                   else Verdict.SUSPICIOUS)
        add_node(finding_id, finding.title, "finding", verdict,
                 severity=finding.severity.value, category=finding.category)
        for ind_key in finding.indicators:
            if ind_key in nodes:
                add_edge(finding_id, ind_key, "concerns")

    return ThreatGraph(nodes=list(nodes.values()), edges=edges)


def to_networkx(graph: ThreatGraph):
    import networkx as nx

    g = nx.DiGraph()
    for node in graph.nodes:
        g.add_node(node.id, label=node.label, type=node.type,
                   verdict=node.verdict.value, **node.meta)
    for edge in graph.edges:
        g.add_edge(edge.source, edge.target, relation=edge.relation, **edge.meta)
    return g


def analyze(graph: ThreatGraph) -> dict[str, Any]:
    """Structural analytics, which indicator is the hub of this cluster?"""
    import networkx as nx

    g = to_networkx(graph)
    if g.number_of_nodes() == 0:
        return {"node_count": 0, "edge_count": 0, "central_indicators": [],
                "components": 0, "malicious_nodes": []}

    undirected = g.to_undirected()
    try:
        centrality = nx.degree_centrality(g)
    except Exception:
        centrality = {}

    indicator_nodes = [
        n for n, d in g.nodes(data=True)
        if d.get("type") not in ("source", "finding", "brand")
    ]
    ranked = sorted(
        ((n, centrality.get(n, 0.0)) for n in indicator_nodes),
        key=lambda kv: -kv[1],
    )[:5]

    return {
        "node_count": g.number_of_nodes(),
        "edge_count": g.number_of_edges(),
        "components": nx.number_connected_components(undirected),
        "central_indicators": [
            {"indicator": n, "centrality": round(c, 3)} for n, c in ranked
        ],
        # Only real indicators count. A source node inherits the verdict of
        # what it reported on, so counting them would make a single malicious
        # CVE look like a multi-node infrastructure cluster.
        "malicious_nodes": [
            n for n, d in g.nodes(data=True)
            if d.get("verdict") == "malicious"
            and d.get("type") not in ("source", "finding", "brand")
        ],
    }


def render_html(graph: ThreatGraph, height: str = "560px",
                theme: str = "dark") -> str:
    """Standalone, self-contained threat-graph page for the report iframe.

    Delegates to graph_render, which inlines vis-network from disk so the page
    makes no outbound request. See that module for the encoding and motion
    decisions.
    """
    from threatiq.engine import graph_render

    try:
        return graph_render.render(graph, theme=theme, height=height)
    except Exception as exc:  # a broken graph must not break the report
        log.exception("threat graph rendering failed")
        return (f'<p style="font:14px sans-serif;padding:16px">'
                f"Could not render the threat graph: "
                f"{type(exc).__name__}.</p>")
