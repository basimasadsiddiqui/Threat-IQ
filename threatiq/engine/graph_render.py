"""Threat graph renderer.

Written against vis-network directly rather than through PyVis's page template,
for three reasons that matter in a security product:

  * PyVis emits `<script src="../node_modules/vis/dist/vis.js">`, a dead
    relative path inside the iframe.
  * It pulls Bootstrap from a public CDN. An air-gapped SOC cannot reach it, and
    a security tool should not make unnecessary third-party requests.
  * The stock template gives no control over encoding or motion.

The vis-network asset ships inside the pyvis package, so it is inlined from
disk and the page makes no outbound request at all.

Visual encoding (nothing relies on colour alone):
  colour  verdict, from the active severity ramp
  size    degree centrality, so the hub of a cluster is visibly the hub
  shape   indicator type
  border  thicker on malicious nodes

Motion is used where it carries information and nowhere else:
  * the physics settle shows cluster structure resolving, which is the point
    of a force-directed layout
  * hovering dims everything but a node's neighbours, answering "what does this
    actually touch"
  * clicking eases the camera onto a node
All of it collapses to a static layout under prefers-reduced-motion.
"""
from __future__ import annotations

import html
import json
import logging
from functools import lru_cache
from pathlib import Path

from threatiq.schemas import ThreatGraph, Verdict

log = logging.getLogger(__name__)

# Kept in step with .streamlit/config.toml and ui/app.py.
THEMES = {
    "dark": {
        "bg": "#0b0f14", "panel": "#141b23", "ink": "#e6edf3",
        "muted": "#8b93a1", "edge": "#3a4757", "edge_dim": "#1e2733",
        "border": "#243040", "accent": "#2f6fd8",
        "malicious": "#ea5459", "suspicious": "#f76808",
        "benign": "#46a758", "unknown": "#8b93a1",
    },
    "light": {
        "bg": "#ffffff", "panel": "#f4f6f9", "ink": "#0f172a",
        "muted": "#55606e", "edge": "#94a3b8", "edge_dim": "#e2e8f0",
        "border": "#d8dee7", "accent": "#2f6fd8",
        "malicious": "#c62a2f", "suspicious": "#b4530a",
        "benign": "#22713a", "unknown": "#4b5563",
    },
}

SHAPES = {
    "url": "square", "domain": "dot", "ipv4": "diamond", "ipv6": "diamond",
    "email": "triangle", "email_message": "triangle", "file_hash": "hexagon",
    "cve": "star", "source": "dot", "finding": "hexagon", "brand": "triangleDown",
}

# Relations the tools observed directly get a solid line. Provenance edges
# ("this source reported on that indicator") are dashed, so the eye separates
# the actual infrastructure from the reporting about it.
DASHED_RELATIONS = {"reported_on", "concerns"}

_TYPE_LABELS = {
    "url": "URL", "domain": "Domain", "ipv4": "IP address",
    "ipv6": "IP address", "email": "Email address",
    "email_message": "Email message", "file_hash": "File hash", "cve": "CVE",
    "source": "Intelligence source", "finding": "Finding",
    "brand": "Impersonated brand",
}


@lru_cache(maxsize=2)
def _vis_assets() -> tuple[str, str]:
    """Inline vis-network from the installed pyvis package. Cached: it is
    roughly 670KB and re-reading it per request is wasteful."""
    try:
        import pyvis

        lib = Path(pyvis.__file__).parent / "lib"
        candidates = sorted(
            (d for d in lib.iterdir() if d.is_dir() and d.name.startswith("vis-")),
            reverse=True,
        )
        for folder in candidates:
            js = folder / "vis-network.min.js"
            css = folder / "vis-network.css"
            if js.exists() and css.exists():
                return js.read_text(encoding="utf-8"), css.read_text(encoding="utf-8")
    except Exception as exc:
        log.error("could not inline vis-network: %s", exc)
    return "", ""


def _degree(graph: ThreatGraph) -> dict[str, int]:
    counts: dict[str, int] = {n.id: 0 for n in graph.nodes}
    for edge in graph.edges:
        if edge.source in counts:
            counts[edge.source] += 1
        if edge.target in counts:
            counts[edge.target] += 1
    return counts


def _build_nodes(graph: ThreatGraph, palette: dict[str, str]) -> list[dict]:
    degree = _degree(graph)
    busiest = max(degree.values(), default=1) or 1
    nodes = []

    for node in graph.nodes:
        verdict = node.verdict.value if isinstance(node.verdict, Verdict) else str(node.verdict)
        colour = palette.get(verdict, palette["unknown"])
        is_bad = verdict in ("malicious", "suspicious")
        is_source = node.type == "source"

        # Size carries centrality. Sources sit visually behind the indicators
        # they describe, so they stay small regardless of how much they touch.
        share = degree.get(node.id, 0) / busiest
        size = 10 + round(6 * share) if is_source else 16 + round(20 * share)

        label = node.label if len(node.label) <= 30 else node.label[:29] + "…"

        tooltip = [f"<b>{html.escape(node.label)}</b>",
                   _TYPE_LABELS.get(node.type, node.type)]
        if verdict != "unknown":
            tooltip.append(f"Verdict: {verdict}")
        tooltip.append(f"Connections: {degree.get(node.id, 0)}")
        for key, value in list(node.meta.items())[:6]:
            if value not in (None, "", [], {}):
                tooltip.append(f"{html.escape(str(key))}: "
                               f"{html.escape(str(value))[:90]}")

        nodes.append({
            "id": node.id,
            "label": label,
            "title": "<br>".join(tooltip),
            "shape": SHAPES.get(node.type, "dot"),
            "size": size,
            "verdict": verdict,
            "ntype": node.type,
            "color": {
                "background": colour if not is_source else palette["panel"],
                "border": colour,
                "highlight": {"background": colour, "border": palette["ink"]},
                "hover": {"background": colour, "border": palette["ink"]},
            },
            "borderWidth": 3 if is_bad else 1,
            "borderWidthSelected": 4,
            "font": {
                "color": palette["muted"] if is_source else palette["ink"],
                "size": 11 if is_source else 13,
                "face": "-apple-system, Segoe UI, Roboto, sans-serif",
                "strokeWidth": 3,
                "strokeColor": palette["bg"],
            },
            "shadow": {"enabled": is_bad, "size": 14, "color": colour,
                       "x": 0, "y": 0},
        })
    return nodes


def _build_edges(graph: ThreatGraph, palette: dict[str, str]) -> list[dict]:
    edges = []
    for i, edge in enumerate(graph.edges):
        provenance = edge.relation in DASHED_RELATIONS
        edges.append({
            "id": f"e{i}",
            "from": edge.source,
            "to": edge.target,
            "label": edge.relation.replace("_", " "),
            "dashes": provenance,
            "color": {
                "color": palette["edge_dim"] if provenance else palette["edge"],
                "highlight": palette["accent"],
                "hover": palette["accent"],
                "opacity": 0.55 if provenance else 0.9,
            },
            "width": 1 if provenance else 2,
            "font": {
                "color": palette["muted"], "size": 9, "strokeWidth": 3,
                "strokeColor": palette["bg"], "align": "middle",
            },
            "arrows": {"to": {"enabled": True, "scaleFactor": 0.5}},
            "smooth": {"enabled": True, "type": "dynamic", "roundness": 0.4},
        })
    return edges


def render(graph: ThreatGraph, theme: str = "dark",
           height: str = "560px") -> str:
    palette = THEMES.get(theme, THEMES["dark"])
    vis_js, vis_css = _vis_assets()
    if not vis_js:
        return (f'<p style="font:14px sans-serif;color:{palette["ink"]}">'
                f"Graph library unavailable.</p>")

    nodes = _build_nodes(graph, palette)
    edges = _build_edges(graph, palette)

    if not nodes:
        return (f'<div style="height:{height};display:flex;align-items:center;'
                f'justify-content:center;background:{palette["bg"]};'
                f'color:{palette["muted"]};font:14px sans-serif">'
                f"No relationships were observed between indicators.</div>")

    counts: dict[str, int] = {}
    for node in nodes:
        counts[node["verdict"]] = counts.get(node["verdict"], 0) + 1

    legend = "".join(
        f'<span class="lg"><i style="background:{palette[v]}"></i>'
        f'{v.capitalize()} <b>{counts[v]}</b></span>'
        for v in ("malicious", "suspicious", "benign", "unknown")
        if counts.get(v)
    )

    options = {
        "nodes": {"scaling": {"min": 10, "max": 40}, "shapeProperties": {
            "interpolation": False}},
        "edges": {"selectionWidth": 2, "hoverWidth": 1},
        "physics": {
            "enabled": True,
            "solver": "barnesHut",
            "barnesHut": {
                # Tuned for a wide, short viewport holding several
                # disconnected components. Weaker repulsion and stronger
                # central gravity keep the clusters in one readable frame
                # instead of sprawling twice the canvas height.
                "gravitationalConstant": -4500,
                "centralGravity": 0.75,
                "springLength": 95,
                "springConstant": 0.055,
                "damping": 0.4,
                "avoidOverlap": 0.35,
            },
            # Visible stabilisation: watching the clusters resolve is the
            # information a force-directed layout exists to convey.
            "stabilization": {"enabled": True, "iterations": 320,
                              "updateInterval": 12, "fit": True},
        },
        "interaction": {
            "hover": True, "hoverConnectedEdges": True,
            "tooltipDelay": 120, "navigationButtons": False,
            "keyboard": {"enabled": True, "bindToWindow": False},
            "multiselect": False, "dragView": True, "zoomView": True,
        },
        "layout": {"improvedLayout": True, "randomSeed": 7},
    }

    return _TEMPLATE.format(
        vis_css=vis_css,
        vis_js=vis_js,
        nodes=json.dumps(nodes),
        edges=json.dumps(edges),
        options=json.dumps(options),
        height=height,
        legend=legend,
        node_count=len(nodes),
        edge_count=len(edges),
        **{f"c_{k}": v for k, v in palette.items()},
    )


_TEMPLATE = """<!DOCTYPE html>
<html><head><meta charset="utf-8">
<style>{vis_css}</style>
<style>
  html,body {{ margin:0; padding:0; background:{c_bg}; }}
  #wrap {{ position:relative; height:{height}; background:{c_bg};
           font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif; }}
  #net {{ width:100%; height:100%; }}
  .bar {{ position:absolute; top:10px; left:12px; right:12px; z-index:5;
          display:flex; gap:10px; align-items:center; flex-wrap:wrap;
          pointer-events:none; }}
  .lg {{ display:inline-flex; align-items:center; gap:6px; font-size:11px;
         color:{c_muted}; background:{c_panel}; border:1px solid {c_border};
         border-radius:3px; padding:3px 8px; }}
  .lg i {{ width:9px; height:9px; border-radius:2px; display:inline-block; }}
  .lg b {{ color:{c_ink}; font-weight:600; }}
  .spacer {{ flex:1 1 auto; }}
  button.act {{ pointer-events:auto; font:inherit; font-size:11px;
      color:{c_ink}; background:{c_panel}; border:1px solid {c_border};
      border-radius:3px; padding:4px 10px; cursor:pointer; }}
  button.act:hover {{ border-color:{c_accent}; color:{c_accent}; }}
  button.act:active {{ transform:translateY(1px); }}
  button.act:focus-visible {{ outline:2px solid {c_accent}; outline-offset:2px; }}
  #load {{ position:absolute; inset:0; display:flex; align-items:center;
           justify-content:center; z-index:4; background:{c_bg};
           color:{c_muted}; font-size:12px; transition:opacity .45s ease; }}
  /* visibility, not just opacity: an element left at opacity 0 still sits in
     the layer and can render faintly mid-transition or under a screenshot
     tool that fast-forwards the clock. */
  #load.gone {{ opacity:0; visibility:hidden; pointer-events:none; }}
  #hint {{ position:absolute; bottom:10px; left:12px; z-index:5;
           font-size:10.5px; color:{c_muted}; }}
  @media (prefers-reduced-motion: reduce) {{
    #load {{ transition:none; }}
    button.act:active {{ transform:none; }}
  }}
</style></head>
<body>
<div id="wrap">
  <div class="bar">
    {legend}
    <span class="spacer"></span>
    <button class="act" id="replay" type="button">Replay layout</button>
    <button class="act" id="fit" type="button">Fit</button>
  </div>
  <div id="net"></div>
  <div id="load">Resolving {node_count} indicators across {edge_count} relationships</div>
  <div id="hint">Hover a node to isolate what it touches. Click to focus.</div>
</div>
<script>{vis_js}</script>
<script>
(function () {{
  var reduce = window.matchMedia
    && window.matchMedia("(prefers-reduced-motion: reduce)").matches;

  var baseNodes = {nodes};
  var baseEdges = {edges};
  var options   = {options};

  // Reduced motion: no settle, no camera easing, no transitions. The layout
  // still runs, it just arrives already solved.
  if (reduce) {{
    options.physics.stabilization.iterations = 600;
    options.physics.stabilization.updateInterval = 600;
  }}

  var nodes = new vis.DataSet(baseNodes);
  var edges = new vis.DataSet(baseEdges);
  var container = document.getElementById("net");
  var network = new vis.Network(container, {{nodes: nodes, edges: edges}}, options);
  // Exposed so the layout can be inspected and refitted from the host page.
  window.threatiqNetwork = network;

  var loader = document.getElementById("load");
  function settle(animate) {{
    // setSize + redraw before fitting. The canvas backing store is scaled by
    // devicePixelRatio, and fitting before that is reconciled leaves the view
    // centred on the wrong box, which renders the whole graph offset into a
    // corner.
    network.setSize("100%", "100%");
    network.redraw();
    requestAnimationFrame(function () {{
      network.fit({{
        animation: (animate && !reduce)
          ? {{duration: 500, easingFunction: "easeOutQuad"}} : false
      }});
    }});
  }}

  network.once("stabilizationIterationsDone", function () {{
    // Physics off once settled: it keeps the layout readable and stops the
    // graph drifting under the cursor.
    network.setOptions({{physics: {{enabled: false}}}});
    loader.classList.add("gone");
    // Take it out of the box once the fade has run, so it can never linger.
    setTimeout(function () {{ loader.style.display = "none"; }}, 600);
    settle(true);
  }});

  // The iframe is resized by the host page; refit rather than leave the
  // viewport clipped.
  var refit;
  window.addEventListener("resize", function () {{
    clearTimeout(refit);
    refit = setTimeout(function () {{ settle(false); }}, 180);
  }});

  // --- hover: dim everything that is not a neighbour -----------------------
  var DIM = "{c_edge_dim}";
  var original = {{}};
  baseNodes.forEach(function (n) {{ original[n.id] = n; }});

  function setFocus(rootId) {{
    var keep = null;
    if (rootId) {{
      keep = {{}};
      keep[rootId] = true;
      network.getConnectedNodes(rootId).forEach(function (id) {{ keep[id] = true; }});
    }}
    nodes.update(baseNodes.map(function (n) {{
      var on = !keep || keep[n.id];
      return {{
        id: n.id,
        opacity: on ? 1 : 0.18,
        font: Object.assign({{}}, n.font, {{
          color: on ? n.font.color : DIM
        }})
      }};
    }}));
    edges.update(baseEdges.map(function (e) {{
      var on = !keep || (keep[e.from] && keep[e.to]);
      return {{
        id: e.id,
        color: Object.assign({{}}, e.color, {{opacity: on ? e.color.opacity : 0.06}})
      }};
    }}));
  }}

  network.on("hoverNode", function (p) {{ setFocus(p.node); }});
  network.on("blurNode",  function ()  {{ setFocus(null); }});

  network.on("click", function (p) {{
    if (p.nodes.length) {{
      network.focus(p.nodes[0], {{
        scale: 1.25,
        animation: reduce ? false
          : {{duration: 520, easingFunction: "easeInOutQuad"}}
      }});
    }} else {{
      setFocus(null);
    }}
  }});

  document.getElementById("fit").addEventListener("click", function () {{
    settle(true);
  }});

  document.getElementById("replay").addEventListener("click", function () {{
    setFocus(null);
    loader.style.display = "";
    loader.classList.remove("gone");
    network.setOptions({{physics: {{enabled: true}}}});
    network.stabilize();
  }});
}})();
</script>
</body></html>"""
