"""ThreatIQ analyst console.

Talks to the FastAPI backend over HTTP and never imports the agent graph, so
analysis logic cannot leak into the presentation layer.

Design rules this file follows:
  * Colour carries meaning. Red/orange/amber belong to the severity scale and
    nothing else; blue means "interactive". The palette is locked in
    .streamlit/config.toml and mirrored in SEVERITY below.
  * Severity is ordered by rank, never by label. Sorting the string puts
    "medium" above "critical".
  * Missing data is shown as missing. A skipped lookup is never rendered the
    same way as a clean result.
"""
from __future__ import annotations

import html
import os
import re
from typing import Any
from urllib.parse import quote

import httpx
import pandas as pd
import plotly.graph_objects as go
import streamlit as st

API_BASE = os.getenv("THREATIQ_API_URL", "http://localhost:8000")
API_KEY = os.getenv("THREATIQ_API_KEY", "")
TIMEOUT = float(os.getenv("THREATIQ_TIMEOUT", "300"))

# Single source of truth for severity presentation. `rank` drives every sort in
# this file; `color` matches the ramp in .streamlit/config.toml.
# Interactive accent. `ACCENT` matches theme.primaryColor in both modes and is
# what white button text sits on (WCAG AA 4.79:1).
ACCENT = "#2f6fd8"
ACCENT_MARK_DARK = "#5b93ee"
ACCENT_MARK_LIGHT = "#2f6fd8"

# Two severity ramps, not one stretched across both modes. The dark ramp fails
# contrast on white (#e5484d on white is 3.6:1), so each mode has colours tuned
# for its own canvas. `rank` is shared and drives every sort in this file.
_RANKS = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
_ICONS = {
    "critical": ":material/gpp_maybe:", "high": ":material/priority_high:",
    "medium": ":material/warning:", "low": ":material/info:",
    "info": ":material/help:",
}
_BADGES = {"critical": "red", "high": "orange", "medium": "orange",
           "low": "green", "info": "gray"}

_RAMP = {
    "dark":  {"critical": "#ea5459", "high": "#f76808", "medium": "#ffb224",
              "low": "#46a758", "info": "#8b93a1"},
    "light": {"critical": "#c62a2f", "high": "#b4530a", "medium": "#8a6116",
              "low": "#22713a", "info": "#4b5563"},
}

# Chart chrome. Plotly draws onto a transparent canvas, so it needs the host
# theme's ink and grid explicitly; inheriting is not possible.
_CHROME = {
    "dark":  {"ink": "#e6edf3", "muted": "#9aa6b2", "grid": "#1e2733",
              "axis": "#243040", "tick": "#3a4757", "track": "#243040"},
    "light": {"ink": "#0f172a", "muted": "#55606e", "grid": "#e2e8f0",
              "axis": "#d8dee7", "tick": "#94a3b8", "track": "#e2e8f0"},
}


def _tint(hex_color: str, alpha: float = 0.18) -> str:
    """Translucent band fill derived from a ramp colour."""
    raw = hex_color.lstrip("#")
    r, g, b = (int(raw[i:i + 2], 16) for i in (0, 2, 4))
    return f"rgba({r},{g},{b},{alpha})"


def active_theme() -> str:
    """Which mode the viewer is actually seeing.

    The theme is not forced in config.toml, so it follows the viewer's own
    light/dark preference. Anything that paints its own pixels (Plotly, the
    PyVis iframe) has to ask, because those surfaces do not inherit the page
    theme the way ordinary widgets do.
    """
    try:
        kind = getattr(st.context.theme, "type", None)
    except Exception:
        kind = None
    return "light" if kind == "light" else "dark"


def palette() -> dict[str, str]:
    return _CHROME[active_theme()]


def sev_palette() -> dict[str, str]:
    return _RAMP[active_theme()]


def accent_mark() -> str:
    """Fill colour for data marks, which carry no text and only need to stay
    legible against the canvas."""
    return ACCENT_MARK_DARK if active_theme() == "dark" else ACCENT_MARK_LIGHT


SEVERITY: dict[str, dict[str, Any]] = {
    name: {"rank": _RANKS[name], "badge": _BADGES[name], "icon": _ICONS[name],
           "color": _RAMP["dark"][name], "color_light": _RAMP["light"][name]}
    for name in _RANKS
}

# Labels only. These deliberately carry no colour: verdict is rendered inside a
# dataframe cell, and a hardcoded hex here would be dark-only and would get
# reused into a render path later.
VERDICT = {
    "malicious": "Malicious", "suspicious": "Suspicious",
    "benign": "Benign", "unknown": "Unknown",
}

# Tool outcome glyphs. A skipped lookup must not look like a clean one, so the
# wording is explicit rather than a tick or a cross.
TOOL_STATUS = {
    "ok":           "OK",
    "not_found":    "Not known",
    "skipped":      "No API key",
    "rate_limited": "Rate limited",
    "refused":      "Refused",
    "error":        "Failed",
}

st.set_page_config(
    page_title="ThreatIQ Analyst Console",
    page_icon=":material/security:",
    layout="wide",
    initial_sidebar_state="expanded",
)


def sev_rank(name: str) -> int:
    return SEVERITY.get(name, SEVERITY["info"])["rank"]


def sev_color(name: str) -> str:
    return sev_palette().get(name, sev_palette()["info"])


# --------------------------------------------------------------- API client

def _headers() -> dict[str, str]:
    return {"X-API-Key": API_KEY} if API_KEY else {}


def api_get(path: str, **params: Any) -> dict[str, Any] | None:
    try:
        r = httpx.get(f"{API_BASE}{path}", params=params,
                      headers=_headers(), timeout=30.0)
        r.raise_for_status()
        return r.json()
    except httpx.HTTPStatusError as exc:
        if exc.response.status_code == 404:
            return None
        st.error(f"API returned {exc.response.status_code}: "
                 f"{exc.response.text[:280]}")
    except httpx.HTTPError as exc:
        st.error(f"Cannot reach the ThreatIQ API at {API_BASE}. {exc}")
    return None


def api_post(path: str, payload: dict, timeout: float = TIMEOUT) -> dict | None:
    try:
        r = httpx.post(f"{API_BASE}{path}", json=payload,
                       headers=_headers(), timeout=timeout)
        r.raise_for_status()
        return r.json()
    except httpx.HTTPStatusError as exc:
        st.error(f"API returned {exc.response.status_code}: "
                 f"{exc.response.text[:280]}")
    except httpx.TimeoutException:
        st.error(f"The investigation exceeded {timeout:.0f}s. Partial results "
                 f"may still be stored under Investigations.")
    except httpx.HTTPError as exc:
        st.error(f"Request failed: {exc}")
    return None


# --------------------------------------------------------------- components

def risk_gauge(score: float, severity: str) -> go.Figure:
    """Transparent background so the gauge inherits the page theme rather than
    carrying its own, which is what made the old chart a light box on dark."""
    ink = palette()
    ramp = sev_palette()
    fig = go.Figure(go.Indicator(
        # Arc only. Plotly centres an indicator's number inside the arc's
        # sweep, so in a narrow column the two always collide no matter how the
        # font or domain is tuned. The score is typeset separately in
        # risk_headline(), which also lets it carry the severity colour and the
        # theme's metric weight. The arc keeps the job it is actually good at:
        # showing where this score falls between the severity thresholds.
        mode="gauge",
        value=score,
        gauge={
            "axis": {"range": [0, 100], "tickwidth": 1,
                     "tickcolor": ink["tick"], "tickfont": {"size": 10}},
            "bar": {"color": sev_color(severity), "thickness": 0.7},
            "bgcolor": "rgba(0,0,0,0)",
            "borderwidth": 0,
            # Bands mirror Severity.from_score() in the risk engine, tinted
            # from whichever ramp is active.
            "steps": [
                {"range": lo_hi, "color": _tint(ramp[name])}
                for name, lo_hi in (("info", [0, 15]), ("low", [15, 40]),
                                    ("medium", [40, 65]), ("high", [65, 85]),
                                    ("critical", [85, 100]))
            ],
        },
    ))
    fig.update_layout(
        # Side margins keep the 0 and 100 axis labels from clipping.
        height=150, margin=dict(l=30, r=30, t=10, b=4),
        paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
        font={"color": ink["ink"]},
    )
    return fig


def risk_headline(score: float, severity: str) -> None:
    """The score, typeset rather than drawn into the chart."""
    colour = sev_color(severity)
    ink = palette()
    st.markdown(
        f'<div style="line-height:1;margin:2px 0 6px">'
        f'<span style="font-size:46px;font-weight:700;color:{colour};'
        f'letter-spacing:-1px">{score:g}</span>'
        f'<span style="font-size:17px;color:{ink["muted"]};'
        f'font-weight:500"> / 100</span></div>',
        unsafe_allow_html=True,
    )


def factor_chart(factors: list[dict]) -> go.Figure:
    """Contribution against available weight.

    Only applicable factors are plotted. An inapplicable dimension is not a
    zero score, so drawing it as an empty bar would misrepresent the model.
    """
    ink = palette()
    applicable = [f for f in factors if f.get("applicable", True)]
    applicable.sort(key=lambda f: f["contribution"])
    names = [f["name"] for f in applicable]

    fig = go.Figure()
    fig.add_bar(
        y=names, x=[f["contribution"] * 100 for f in applicable],
        orientation="h", name="Scored", marker_color=accent_mark(),
        hovertemplate="%{y}<br>%{x:.1f} points scored<extra></extra>",
    )
    fig.add_bar(
        y=names, x=[(f["weight"] - f["contribution"]) * 100 for f in applicable],
        orientation="h", name="Unused weight", marker_color=ink["track"],
        hovertemplate="%{y}<br>%{x:.1f} points unused<extra></extra>",
    )
    fig.update_layout(
        barmode="stack", height=68 + 40 * max(1, len(names)),
        margin=dict(l=8, r=8, t=34, b=8),
        xaxis_title="Points of the model's 100",
        paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
        font={"color": ink["muted"], "size": 12},
        xaxis={"gridcolor": ink["grid"], "zerolinecolor": ink["axis"]},
        yaxis={"gridcolor": "rgba(0,0,0,0)"},
        legend={"orientation": "h", "y": 1.22, "x": 0,
                "bgcolor": "rgba(0,0,0,0)"},
    )
    return fig


def severity_chip(severity: str) -> None:
    st.badge(severity.upper(), color=SEVERITY.get(severity, SEVERITY["info"])["badge"])


_URL_RE = re.compile(r"\bhttps?://[^\s<>\"']+", re.I)


def defang(text: str) -> str:
    """Neutralise live URLs before they are rendered.

    Streamlit's markdown auto-links bare URLs, so a phishing link pulled out of
    a hostile email was arriving in the console as a working anchor. An analyst
    could click the payload straight out of the tool that is analysing it.
    Rewriting http to hxxp and dotting the separators keeps the indicator
    readable and copyable while making it inert.
    """
    def _mask(match: re.Match[str]) -> str:
        url = match.group(0)
        return url.replace("http", "hxxp", 1).replace(".", "[.]")

    return _URL_RE.sub(_mask, text or "")


def report_skeleton() -> None:
    """Placeholder shaped like the report that is about to arrive.

    A bare spinner tells the analyst only that something is happening. This
    shows the shape of the answer (gauge, summary, four counters), so the eye
    is already where the content will land. No fake progress bar: the API call
    is a single blocking request and the client genuinely cannot know how far
    along the agents are, so inventing a percentage would be a lie.
    """
    left, right = st.columns([1, 2.4], gap="large")
    with left:
        st.skeleton(height=210)
        st.skeleton(height=90)
    with right:
        st.skeleton(height=24)
        st.skeleton(height=150)
        for col in st.columns(4):
            with col:
                st.skeleton(height=88)


def kv_row(items: list[tuple[str, str]]) -> None:
    """Compact label/value strip. Used instead of st.metric where the value is
    text rather than a number worth a large display treatment."""
    cols = st.columns(len(items))
    for col, (label, value) in zip(cols, items):
        col.caption(label)
        col.markdown(f"**{value}**")



# ------------------------------------------------------------------ findings

def enrich(finding: dict, evidence: list[dict]) -> dict:
    """Join a finding to the evidence behind it.

    Findings carry only `evidence_ids`. Everything an analyst actually needs to
    triage a vulnerability (CVSS, the attack vector, KEV status, the vendor's
    remediation deadline) sits in the evidence signals, so it has to be pulled
    forward or the report shows a severity label and nothing to justify it.
    """
    by_id = {e["id"]: e for e in evidence}
    linked = [by_id[i] for i in finding.get("evidence_ids", []) if i in by_id]

    # Fall back to matching on the indicator: correlation findings are derived
    # rather than sourced, so they carry no evidence ids of their own.
    if not linked:
        wanted = set(finding.get("indicators", []))
        linked = [e for e in evidence if e["indicator"] in wanted]

    facts: dict[str, Any] = {"sources": sorted({e["source"] for e in linked})}
    for e in linked:
        sig = e.get("signals") or {}
        if e["source"] == "nvd":
            facts.update({
                "cvss": sig.get("cvss_score"),
                "cvss_vector": sig.get("cvss_vector", ""),
                "published": (sig.get("published") or "")[:10],
                "products": sig.get("affected_products", [])[:6],
                "network": sig.get("network_exploitable"),
                "no_privs": sig.get("no_privileges_required"),
                "no_interaction": sig.get("no_user_interaction"),
                "detail": sig.get("description", ""),
            })
        elif e["source"] == "cisa_kev" and sig.get("in_kev"):
            facts.update({
                "kev": True,
                "kev_due": sig.get("due_date", ""),
                "ransomware": bool(sig.get("known_ransomware_use")),
                "vendor": sig.get("vendor_project", ""),
                "product": sig.get("product", ""),
                "required_action": sig.get("required_action", ""),
            })
        elif e["source"] == "lookalike" and sig.get("matched_brand"):
            facts["brand"] = sig["matched_brand"]
            facts["technique"] = str(sig.get("technique", "")).replace("_", " ")
        elif e["source"] == "rdap" and isinstance(sig.get("age_days"), int):
            facts["domain_age_days"] = sig["age_days"]
        elif e["source"] == "abuseipdb" and sig.get("total_reports"):
            facts["abuse_reports"] = sig["total_reports"]
            facts["abuse_score"] = sig.get("abuse_confidence_score")
        elif e["source"] == "virustotal" and sig.get("total_engines"):
            facts["vt"] = sig.get("detection_ratio", "")
    return facts


# Categories that describe a weakness in something we own, as opposed to
# intelligence about someone else's infrastructure. This split is what lets the
# report answer "what is wrong with us" separately from "who is attacking us".
FLAW_CATEGORIES = {"vulnerability", "web_vulnerability", "misconfiguration"}

CATEGORY_LABELS = {
    "vulnerability": "Vulnerability",
    "web_vulnerability": "Web or API weakness",
    "misconfiguration": "Misconfiguration",
    "phishing": "Phishing",
    "bec": "Business email compromise",
    "malicious_infrastructure": "Malicious infrastructure",
    "suspicious_infrastructure": "Suspicious infrastructure",
    "campaign": "Correlated campaign",
}


def severity_bar(findings: list[dict]) -> None:
    """Colour-coded posture strip: one segment per severity, width by count.

    A stacked bar rather than five separate counters, because the question an
    analyst asks first is proportion ("is this mostly noise or mostly bad"),
    and proportion is what a stacked bar answers at a glance.
    """
    if not findings:
        return
    ramp = sev_palette()
    order = ["critical", "high", "medium", "low", "info"]
    counts = {s: sum(1 for f in findings if f["severity"] == s) for s in order}
    total = sum(counts.values()) or 1

    # Values here are integers and palette constants only, no external input.
    segments = "".join(
        f'<div title="{counts[s]} {s}" style="flex:{counts[s]};'
        f'background:{ramp[s]};height:10px"></div>'
        for s in order if counts[s]
    )
    labels = "  ".join(
        f'<span style="color:{ramp[s]};font-weight:600">{counts[s]}</span>'
        f'<span style="opacity:.75"> {s}</span>'
        for s in order if counts[s]
    )
    st.markdown(
        f'<div style="display:flex;gap:2px;border-radius:3px;overflow:hidden;'
        f'margin:2px 0 6px">{segments}</div>'
        f'<div style="font-size:12.5px;letter-spacing:.2px">{labels}</div>',
        unsafe_allow_html=True,
    )


def finding_card(f: dict, facts: dict, actions: list[dict]) -> None:
    """One flaw, presented so severity is readable before any text is."""
    ramp = sev_palette()
    colour = ramp.get(f["severity"], ramp["info"])
    ink = palette()

    chips: list[str] = []

    def chip(text: str, strong: bool = False) -> str:
        border = colour if strong else ink["axis"]
        weight = "600" if strong else "500"
        # Escaped: chip text carries indicator values and vendor strings, both
        # of which originate outside this system.
        return (f'<span style="border:1px solid {border};color:'
                f'{colour if strong else ink["muted"]};border-radius:3px;'
                f'padding:1px 7px;font-size:11px;font-weight:{weight};'
                f'white-space:nowrap">{html.escape(str(text))}</span>')

    if facts.get("cvss") is not None:
        chips.append(chip(f"CVSS {facts['cvss']}", strong=True))
    if facts.get("kev"):
        chips.append(chip("CISA KEV: exploited in the wild", strong=True))
    if facts.get("ransomware"):
        chips.append(chip("Ransomware campaign use", strong=True))
    if facts.get("network"):
        chips.append(chip("Remotely exploitable"))
    if facts.get("no_privs"):
        chips.append(chip("No privileges needed"))
    if facts.get("no_interaction"):
        chips.append(chip("No user interaction"))
    if facts.get("vt"):
        chips.append(chip(f"VirusTotal {facts['vt']}"))
    if facts.get("abuse_reports"):
        chips.append(chip(f"{facts['abuse_reports']} abuse reports"))
    if isinstance(facts.get("domain_age_days"), int):
        chips.append(chip(f"Domain {facts['domain_age_days']}d old"))
    if facts.get("brand"):
        chips.append(chip(f"Impersonates {facts['brand']}"))

    # A finding title embeds indicator values and email subject lines, which
    # are attacker-controlled by definition. Anything crossing into
    # unsafe_allow_html is escaped first; a phishing lure must never be able to
    # inject markup into the console analysing it.
    category = html.escape(CATEGORY_LABELS.get(f["category"], f["category"]))
    safe_title = html.escape(str(f["title"]))
    safe_severity = html.escape(str(f["severity"]).upper())
    st.markdown(
        f'<div style="border-left:4px solid {colour};padding:2px 0 2px 14px;'
        f'margin:4px 0 2px">'
        f'<div style="font-size:11px;letter-spacing:.6px;'
        f'color:{colour};font-weight:700">{safe_severity}'
        f'<span style="color:{ink["muted"]};font-weight:500;'
        f'letter-spacing:0"> &nbsp;{category}</span></div>'
        f'<div style="font-size:17px;font-weight:600;margin-top:2px;'
        f'color:{ink["ink"]}">{safe_title}</div></div>',
        unsafe_allow_html=True,
    )
    if chips:
        st.markdown(
            '<div style="display:flex;gap:6px;flex-wrap:wrap;margin:6px 0 2px">'
            + "".join(chips) + "</div>",
            unsafe_allow_html=True,
        )

    st.write(defang(f["description"]))

    if facts.get("required_action"):
        st.markdown("**Vendor-required action.** "
                    + defang(facts["required_action"])
                    + (f" Due {facts['kev_due']}." if facts.get("kev_due") else ""))
    # The vulnerability agent already appends the product list to the finding
    # description, so only surface it here when it is not already there.
    if facts.get("products") and "Affected products" not in f["description"]:
        st.caption("Affected products: " + ", ".join(facts["products"]))
    if facts.get("cvss_vector"):
        st.caption(f"Vector `{facts['cvss_vector']}`")

    mapped = [(label, f.get(key) or [])
              for label, key in (("OWASP", "owasp"), ("CWE", "cwe"),
                                 ("MITRE ATT&CK", "mitre_attack"),
                                 ("NIST CSF", "nist_csf"))]
    mapped = [(label, codes) for label, codes in mapped if codes]
    if mapped:
        for label, codes in mapped:
            name_col, code_col = st.columns([1, 3])
            name_col.caption(label)
            code_col.markdown(f"`{'`  `'.join(codes)}`")

    if actions:
        st.caption("Fix")
        for a in actions[:3]:
            st.markdown(f"- **P{a['priority']}** " + defang(a["action"]))

    st.caption(
        f"Raised by the `{f['agent']}` agent at "
        f"{f['confidence'] * 100:.0f}% confidence. Affects: "
        + (", ".join(f"`{defang(i)}`" for i in f.get("indicators", []))
           or "none")
    )


def actions_for(finding: dict, remediation: list[dict]) -> list[dict]:
    """Remediation entries whose text names one of this finding's indicators."""
    names = {i.split(":", 1)[-1].lower() for i in finding.get("indicators", [])}
    names.discard("submitted")
    matched = [a for a in remediation
               if any(n and n in a["action"].lower() for n in names)]
    if matched:
        return sorted(matched, key=lambda a: a["priority"])
    # Vulnerability findings name the CVE in the action text instead.
    cve = next((i.split(":", 1)[1] for i in finding.get("indicators", [])
                if i.startswith("cve:")), "")
    if cve:
        return [a for a in remediation if cve.lower() in a["action"].lower()]
    return []


# --------------------------------------------------------------- report view

def render_report(report: dict) -> None:
    risk = report.get("risk", {})
    findings = sorted(report.get("findings", []),
                      key=lambda f: (-sev_rank(f["severity"]), -f["confidence"]))
    evidence = report.get("evidence", [])
    remediation = sorted(report.get("remediation", []),
                         key=lambda a: a["priority"])
    severity = risk.get("severity", "info")

    if report.get("error"):
        st.warning(report["error"], icon=":material/error:")

    head_l, head_r = st.columns([1, 2.4], gap="large")
    with head_l:
        risk_headline(risk.get("score", 0), severity)
        severity_chip(severity)
        st.plotly_chart(risk_gauge(risk.get("score", 0), severity),
                        width="stretch", config={"displayModeBar": False})
        # Three separate facts. Strung together with separators they read as
        # one run-on line and none of them is scannable.
        st.caption(f"Confidence {risk.get('confidence', 0) * 100:.0f}%")
        st.caption(f"Scored on {risk.get('coverage', 0) * 100:.0f}% "
                   f"of the model's weight")
        st.caption(f"{risk.get('corroborating_sources', 0)} corroborating "
                   f"source(s)")
    with head_r:
        st.markdown("##### Summary")
        st.write(defang(report.get("summary") or "No summary was produced."))
        severity_bar(findings)
        counts = st.columns(4)
        counts[0].metric("Findings", len(findings), border=True)
        counts[1].metric("Evidence", len(evidence), border=True)
        counts[2].metric("Indicators", len(report.get("indicators", [])),
                         border=True)
        counts[3].metric("Actions", len(remediation), border=True)

    st.divider()

    flaws = [f for f in findings if f["category"] in FLAW_CATEGORIES]
    intel = [f for f in findings if f["category"] not in FLAW_CATEGORIES]
    remediation_list = remediation

    tabs = st.tabs([
        f"Flaws and vulnerabilities ({len(flaws)})",
        f"Threat intelligence ({len(intel)})",
        "Risk breakdown", "Evidence", "Threat graph", "Remediation",
        "Agent trace",
    ])

    # --- flaws and vulnerabilities ------------------------------------
    with tabs[0]:
        if not flaws:
            st.success(
                "No vulnerability, misconfiguration or web weakness was found "
                "in the submitted target.", icon=":material/check_circle:")
        for i, f in enumerate(flaws):
            finding_card(f, enrich(f, evidence), actions_for(f, remediation_list))
            if i < len(flaws) - 1:
                st.divider()

    # --- threat intelligence -------------------------------------------
    with tabs[1]:
        st.caption("What the intelligence sources say about the indicators "
                   "themselves, as opposed to weaknesses in the target.")
        if not intel:
            st.info("No intelligence findings were raised.",
                    icon=":material/travel_explore:")
        for i, f in enumerate(intel):
            finding_card(f, enrich(f, evidence), actions_for(f, remediation_list))
            if i < len(intel) - 1:
                st.divider()

    # --- risk breakdown ----------------------------------------------
    with tabs[2]:
        factors = risk.get("factors", [])
        if factors:
            st.plotly_chart(factor_chart(factors), width="stretch",
                            config={"displayModeBar": False})
        skipped = [f for f in factors if not f.get("applicable", True)]
        if skipped:
            st.info(
                "**Not evaluated.** These dimensions are excluded from the "
                "score rather than counted as zero, because absence of data is "
                "not evidence of safety:\n\n"
                + "\n".join(f"- **{f['name']}**: {f['rationale']}" for f in skipped),
                icon=":material/help:",
            )
        st.markdown("##### How the score was reached")
        st.code(defang(risk.get("explanation", "No explanation available.")),
                language=None, wrap_lines=True)

    # --- evidence -----------------------------------------------------
    with tabs[3]:
        if not evidence:
            st.info("No evidence was collected.", icon=":material/inbox:")
        else:
            frame = pd.DataFrame([{
                "Source": e["source"],
                "Tool": e["tool"],
                "Indicator": defang(e["indicator"]),
                "Result": TOOL_STATUS.get(e["status"], e["status"]),
                "Verdict": VERDICT.get(e["verdict"], "Unknown"),
                "Confidence": e["confidence"],
                "Latency": e["latency_ms"],
                "Detail": defang(e["summary"]),
            } for e in evidence])
            st.dataframe(
                frame, width="stretch", hide_index=True,
                column_config={
                    "Confidence": st.column_config.ProgressColumn(
                        "Confidence", min_value=0.0, max_value=1.0,
                        format="percent"),
                    "Latency": st.column_config.NumberColumn(
                        "Latency", format="%d ms"),
                    "Detail": st.column_config.TextColumn("Detail", width="large"),
                },
            )

            unconfigured = sorted({e["source"] for e in evidence
                                   if e["status"] == "skipped"})
            if unconfigured:
                st.warning(
                    f"**{', '.join(unconfigured)}** were skipped because no API "
                    f"key is configured. A clean result from the remaining "
                    f"sources is weaker evidence than it appears.",
                    icon=":material/key_off:",
                )
            with st.expander("Raw signals", icon=":material/data_object:"):
                for e in evidence:
                    if e.get("signals"):
                        st.caption(f"{e['source']}/{e['tool']} on "
                                   + defang(e["indicator"]))
                        st.json(e["signals"], expanded=False)

    # --- threat graph --------------------------------------------------
    with tabs[4]:
        graph = report.get("graph", {})
        nodes, edges = graph.get("nodes", []), graph.get("edges", [])
        if not nodes:
            st.info("No relationships were observed between indicators.",
                    icon=":material/hub:")
        else:
            # The graph is served into an iframe, which does not inherit the
            # host page's theme, so the active mode is passed explicitly.
            st.iframe(
                f"{API_BASE}/investigations/{report.get('id', '')}"
                f"/graph.html?theme={active_theme()}",
                height=600,
            )
            st.caption(
                f"{len(nodes)} indicators, {len(edges)} observed relationships. "
                f"Node size reflects how many things it connects to. Solid "
                f"edges are relationships the tools observed; dashed edges are "
                f"a source reporting on an indicator."
            )
            if edges:
                st.dataframe(
                    pd.DataFrame([{"From": e["source"], "Relation": e["relation"],
                                   "To": e["target"]} for e in edges]),
                    width="stretch", hide_index=True,
                )

    # --- remediation ---------------------------------------------------
    with tabs[5]:
        if not remediation:
            st.info("No remediation actions were generated.",
                    icon=":material/task_alt:")
        for a in remediation:
            head, meta = st.columns([4, 1])
            head.markdown(f"**P{a['priority']}**  " + defang(a["action"]))
            meta.caption(
                f"{a['owner']}\n\n{a['effort']} effort"
                + ("\n\nautomatable" if a.get("automatable") else "")
            )
            head.caption(defang(a["rationale"]))
            st.divider()

    # --- agent trace ----------------------------------------------------
    with tabs[6]:
        actions = report.get("actions", [])
        if not actions:
            st.info("No agent actions were recorded.", icon=":material/route:")
        else:
            st.dataframe(
                pd.DataFrame([{
                    "Agent": a["agent"], "Step": a["action"],
                    "Status": a["status"], "Duration": a["duration_ms"],
                    "Detail": a["detail"],
                } for a in actions]),
                width="stretch", hide_index=True,
                column_config={
                    "Duration": st.column_config.NumberColumn(
                        "Duration", format="%d ms"),
                    "Detail": st.column_config.TextColumn("Detail", width="large"),
                },
            )
            fig = go.Figure(go.Bar(
                x=[a["duration_ms"] for a in actions],
                y=[a["agent"] for a in actions],
                orientation="h", marker_color=accent_mark(),
                hovertemplate="%{y}: %{x} ms<extra></extra>",
            ))
            fig.update_layout(
                height=60 + 32 * len(actions), xaxis_title="Duration (ms)",
                margin=dict(l=8, r=8, t=8, b=8),
                paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
                font={"color": palette()["muted"], "size": 12},
                xaxis={"gridcolor": palette()["grid"]},
                yaxis={"autorange": "reversed"},
            )
            st.plotly_chart(fig, width="stretch",
                            config={"displayModeBar": False})


# --------------------------------------------------------------------- pages

def page_investigate() -> None:
    st.title("Investigate")
    st.caption("Evidence is collected by tools, then interpreted. "
               "Scores are computed, not generated.")

    with st.form("investigate"):
        text = st.text_area(
            "URL, domain, IP address, file hash, CVE, or a full email message",
            height=160,
            placeholder="https://suspicious-domain.com\n"
                        "185.220.101.5\n"
                        "CVE-2024-3400\n"
                        "or paste a complete email including its headers",
        )
        c1, c2, c3 = st.columns([2, 1, 1])
        criticality = c1.selectbox(
            "Asset criticality", ["low", "medium", "high", "critical"], index=1,
            help="Feeds the exposure factor of the risk model.",
        )
        exposed = c2.checkbox("Internet exposed", value=True)
        active = c3.checkbox(
            "Active scanning", value=False,
            help="Permitted only for hosts listed in AUTHORIZED_SCAN_TARGETS "
                 "on the server. Every other target is refused.",
        )
        submitted = st.form_submit_button(
            "Investigate", type="primary", width="stretch",
            icon=":material/search:",
        )

    if submitted and text.strip():
        preview = api_post("/classify", {"input": text}, timeout=30)
        if preview:
            found = ", ".join(f"`{i['value']}`" for i in preview["indicators"][:8])
            st.caption(f"Classified as **{preview['kind']}**. "
                       f"{len(preview['indicators'])} indicator(s): {found or 'none'}")
        placeholder = st.empty()
        with placeholder.container():
            st.caption("Agents are collecting and correlating evidence")
            report_skeleton()
        report = api_post("/investigate", {
            "input": text, "asset_criticality": criticality,
            "internet_exposed": exposed, "allow_active_scan": active,
        })
        placeholder.empty()
        if report:
            st.session_state["last_report"] = report
            st.session_state["last_id"] = report["id"]
            st.query_params["investigation"] = report["id"]
    elif submitted:
        st.warning("Enter an indicator to investigate.", icon=":material/edit:")

    # Deep link: /?investigation=<id> opens a stored report directly, so an
    # analyst can hand a colleague a link to the exact investigation.
    deep_link = st.query_params.get("investigation")
    report = st.session_state.get("last_report")
    if deep_link and (not report or report.get("id") != deep_link):
        fetched = api_get(f"/investigations/{deep_link}")
        if fetched:
            report = fetched
            st.session_state["last_report"] = fetched
            st.session_state["last_id"] = deep_link
        else:
            st.error(f"No stored investigation with id `{deep_link}`.",
                     icon=":material/search_off:")

    if report:
        st.divider()
        st.caption(f"Investigation `{report['id']}`")
        render_report(report)
    elif not submitted:
        st.info(
            "Submit an indicator above. Sources without an API key are "
            "reported as skipped, never silently ignored.",
            icon=":material/lightbulb:",
        )


def page_history() -> None:
    st.title("Investigations")
    data = api_get("/investigations", limit=100)
    rows = (data or {}).get("investigations", [])
    if not rows:
        st.info("Nothing stored yet. Run an investigation first.",
                icon=":material/inbox:")
        return

    rows.sort(key=lambda r: (-sev_rank(r["severity"]), -r["risk_score"]))
    st.dataframe(
        pd.DataFrame([{
            "Severity": r["severity"].upper(),
            "Risk": r["risk_score"],
            "Input": defang(r["input"][:70]),
            "Type": r["kind"],
            "Findings": r["finding_count"],
            "When": r["created_at"][:19].replace("T", " "),
            "ID": r["id"],
        } for r in rows]),
        width="stretch", hide_index=True,
        column_config={
            "Risk": st.column_config.ProgressColumn(
                "Risk", min_value=0, max_value=100, format="%.1f"),
            "Input": st.column_config.TextColumn("Input", width="large"),
        },
    )

    chosen = st.selectbox(
        "Open an investigation", [r["id"] for r in rows],
        format_func=lambda i: next(
            f"{r['severity'].upper()} {r['risk_score']}  {r['input'][:52]}"
            for r in rows if r["id"] == i),
    )
    if chosen:
        report = api_get(f"/investigations/{chosen}")
        if report:
            st.session_state["last_id"] = chosen
            st.divider()
            render_report(report)


def page_copilot() -> None:
    st.title("Security Copilot")
    st.caption("Answers are grounded in stored investigations and the "
               "security knowledge base.")

    data = api_get("/investigations", limit=50)
    ids = [r["id"] for r in (data or {}).get("investigations", [])]
    options = ["None"] + ids
    index = options.index(st.session_state["last_id"]) \
        if st.session_state.get("last_id") in options else 0
    picked = st.selectbox("Investigation context", options, index=index)
    context_id = None if picked == "None" else picked

    st.session_state.setdefault("chat", [])
    for message in st.session_state["chat"]:
        with st.chat_message(message["role"]):
            st.markdown(message["content"])
            if message.get("citations"):
                st.caption("Frameworks referenced: "
                           + ", ".join(message["citations"]))

    question = st.chat_input("Why is this critical? What should I fix first?")
    if question:
        st.session_state["chat"].append({"role": "user", "content": question})
        with st.chat_message("user"):
            st.markdown(question)
        with st.chat_message("assistant"), st.spinner("Consulting the evidence"):
            response = api_post("/copilot/chat", {
                "question": question,
                "investigation_id": context_id,
                "history": [{"role": m["role"], "content": m["content"]}
                            for m in st.session_state["chat"][-6:]],
            }, timeout=120)
            if response:
                st.markdown(response["answer"])
                if response.get("citations"):
                    st.caption("Frameworks referenced: "
                               + ", ".join(response["citations"]))
                st.session_state["chat"].append({
                    "role": "assistant", "content": response["answer"],
                    "citations": response.get("citations", []),
                })

    if st.session_state["chat"] and st.button("Clear conversation",
                                              icon=":material/delete:"):
        st.session_state["chat"] = []
        st.rerun()


def page_search() -> None:
    st.title("Indicator pivot")
    st.caption("Every investigation that has touched an indicator.")
    value = st.text_input("Indicator", placeholder="185.220.101.5 or evil.example")
    if not value:
        return
    if len(value) < 2:
        st.warning("Enter at least two characters.", icon=":material/edit:")
        return

    results = (api_get("/search", indicator=value) or {}).get("results", [])
    if not results:
        st.info(f"No stored investigation references `{value}`.",
                icon=":material/search_off:")
        return

    st.caption(f"{len(results)} investigation(s) reference this indicator.")
    for r in sorted(results, key=lambda r: -sev_rank(r["severity"])):
        with st.expander(
            f"{r['severity'].upper()} at risk {r['risk_score']}  ·  "
            + defang(r["input"][:60]),
            icon=SEVERITY.get(r["severity"], SEVERITY["info"])["icon"],
        ):
            st.markdown("**Matched:** " + ", ".join(
                f"`{defang(m)}`" for m in r.get("matched_indicators", [])))
            for f in sorted(r.get("related_findings", []),
                            key=lambda f: -sev_rank(f["severity"])):
                st.markdown(f"- {f['title']}")
                severity_chip(f["severity"])


def page_status() -> None:
    st.title("System status")
    health = api_get("/health")
    if not health:
        st.error("The API is unreachable.", icon=":material/cloud_off:")
        return

    cols = st.columns(3)
    cols[0].metric("Version", health["version"], border=True)
    cols[1].metric("Graph backend", health["graph_backend"], border=True)
    cols[2].metric("Repository", health["repository"].replace("Repository", ""),
                   border=True)

    llm = health["llm"]
    if llm["enabled"]:
        st.success(f"Language model: {llm['provider']} `{llm['model']}`",
                   icon=":material/smart_toy:")
    else:
        st.warning(
            "No language model is configured. Evidence collection, risk "
            "scoring, framework mapping and remediation all still run. Only "
            "the narrative explanations are reduced.",
            icon=":material/smart_toy:",
        )

    if not health["auth_enabled"]:
        st.error(
            "API authentication is disabled because no API_KEY is set. Do not "
            "expose this deployment beyond localhost.",
            icon=":material/lock_open:",
        )

    st.subheader("Intelligence sources")
    tools = api_get("/tools")
    if tools:
        st.dataframe(
            pd.DataFrame([{
                "Source": t["name"],
                "Status": "Configured" if t["configured"] else "No API key",
                "Accepts": ", ".join(t["accepts"]),
                "Purpose": t["description"],
            } for t in sorted(tools["tools"],
                              key=lambda t: (not t["configured"], t["name"]))]),
            width="stretch", hide_index=True,
            column_config={"Purpose": st.column_config.TextColumn(
                "Purpose", width="large")},
        )

    st.subheader("Active scanning")
    scanning = health["active_scanning"]
    targets = scanning["authorized_targets"]
    kv_row([
        ("ZAP instance", "Configured" if scanning["zap_configured"] else "Absent"),
        ("Authorised targets", ", ".join(targets) if targets
         else "None. Every active scan is refused."),
    ])

    st.subheader("Stored data")
    stats = api_get("/stats")
    if stats:
        cols = st.columns(3)
        cols[0].metric("Investigations", stats["investigations"], border=True)
        cols[1].metric("Findings", stats["findings"], border=True)
        cols[2].metric("Mean risk", stats["mean_risk"], border=True)
        if stats.get("by_severity"):
            ordered = sorted(stats["by_severity"].items(),
                             key=lambda kv: -sev_rank(kv[0]))
            fig = go.Figure(go.Bar(
                x=[k.upper() for k, _ in ordered],
                y=[v for _, v in ordered],
                marker_color=[sev_color(k) for k, _ in ordered],
                hovertemplate="%{x}: %{y}<extra></extra>",
            ))
            fig.update_layout(
                height=260, margin=dict(l=8, r=8, t=8, b=8),
                paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
                font={"color": palette()["muted"]},
                yaxis={"gridcolor": palette()["grid"]},
            )
            st.plotly_chart(fig, width="stretch",
                            config={"displayModeBar": False})


# --------------------------------------------------------------------- shell

_FONT = ("-apple-system,BlinkMacSystemFont,Segoe UI,Roboto,"
         "Helvetica Neue,Arial,sans-serif")


def wordmark(theme: str) -> str:
    """Data-URI wordmark for the sidebar's logo slot.

    st.navigation renders its links at the very top of the sidebar, above
    anything written with st.sidebar, so the only supported place for branding
    is st.logo. Hand-drawn SVG illustration is a tell; a wordmark set in the
    interface's own type is not, and it is the one case where drawing the mark
    is the right call. The mark is a rotated square, which is also the shape the
    graph uses for an IP node.

    Rendered per theme because an <img> cannot inherit the page's text colour.
    """
    ink = _CHROME[theme]["ink"]
    muted = _CHROME[theme]["muted"]
    accent = ACCENT_MARK_DARK if theme == "dark" else ACCENT
    svg = (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="176" height="44" '
        f'viewBox="0 0 176 44" role="img" '
        f'aria-label="ThreatIQ analyst console">'
        f'<rect x="3" y="13" width="13" height="13" rx="1.8" '
        f'transform="rotate(45 9.5 19.5)" fill="{accent}"/>'
        f'<text x="29" y="22" fill="{ink}" font-size="19" '
        f'font-weight="700" letter-spacing="-.4" '
        f'font-family="{_FONT}">ThreatIQ</text>'
        f'<text x="29" y="35" fill="{muted}" font-size="11" '
        f'letter-spacing=".4" font-family="{_FONT}">Analyst console</text>'
        f'</svg>'
    )
    return "data:image/svg+xml;utf8," + quote(svg)


def status_dot(state: str, label: str) -> None:
    """One line of system state, colour-encoded by how much it matters.

    The old sidebar printed "Authentication disabled" in exactly the same grey
    as "API 1.0.0". One of those is a security warning and the other is a
    version string, and a console that renders them identically is training the
    analyst to skim past the warning.

    A square rather than a circle: the nav above no longer uses radio circles,
    and reintroducing them here would read as another control.
    """
    ramp = sev_palette()
    ink = palette()
    colour = {"bad": ramp["critical"], "warn": ramp["high"],
              "ok": ramp["low"]}.get(state, ink["muted"])
    weight = "600" if state in ("bad", "warn") else "400"
    text = ink["ink"] if state in ("bad", "warn") else ink["muted"]
    st.markdown(
        f'<div style="display:flex;align-items:center;gap:8px;'
        f'margin:0 0 6px">'
        f'<span style="width:7px;height:7px;border-radius:1px;flex:none;'
        f'background:{colour}"></span>'
        f'<span style="font-size:12.5px;color:{text};font-weight:{weight}">'
        f'{html.escape(label)}</span></div>',
        unsafe_allow_html=True,
    )


def sidebar_status() -> None:
    """System state, quiet when healthy and loud when not.

    Only conditions that need an analyst's attention get a line and a colour.
    A healthy deployment shows one muted footer and nothing else, so anything
    that does appear here is worth reading.
    """
    health = api_get("/health")
    ink = palette()

    if not health:
        status_dot("bad", "API unreachable")
        st.caption(API_BASE)
        return

    if not health.get("auth_enabled"):
        status_dot("warn", "Authentication disabled")

    missing = health.get("tools_unconfigured", [])
    if missing:
        status_dot("warn", f"{len(missing)} sources without an API key")

    # Configuration facts, not warnings. Colouring these amber alongside
    # "Authentication disabled" would flatten the distinction between a
    # security problem and a deployment choice, which is the same mistake as
    # printing them all in identical grey.
    llm = health.get("llm", {})
    if not llm.get("enabled"):
        status_dot("info", "No language model configured")

    if health.get("repository", "").startswith("InMemory"):
        status_dot("info", "In-memory store, cleared on restart")

    # Neutral facts sit below the warnings, muted and on one line.
    st.markdown(
        f'<div style="font-size:11.5px;color:{ink["muted"]};margin-top:10px;'
        f'letter-spacing:.2px">v{html.escape(str(health["version"]))} '
        f'&nbsp;&middot;&nbsp; graph {html.escape(str(health["graph_backend"]))}'
        f'</div>',
        unsafe_allow_html=True,
    )


PAGES = [
    (page_investigate, "Investigate", ":material/search:", "investigate"),
    (page_history, "Investigations", ":material/history:", "investigations"),
    (page_copilot, "Security Copilot", ":material/forum:", "copilot"),
    (page_search, "Indicator pivot", ":material/hub:", "pivot"),
    (page_status, "System status", ":material/monitor_heart:", "status"),
]


def main() -> None:
    # st.navigation renders real navigation links rather than a radio group.
    # Radio circles are a form affordance: they say "choose a value", not "go
    # to a page". It also gives every page its own URL, so an analyst can send
    # a colleague a link to the Copilot or to a specific investigation.
    nav = st.navigation(
        [
            st.Page(fn, title=title, icon=icon, url_path=path,
                    default=(i == 0))
            for i, (fn, title, icon, path) in enumerate(PAGES)
        ],
        position="sidebar",
    )

    st.logo(wordmark(active_theme()), size="large", link=None)

    # No divider here: st.navigation already draws stSidebarNavSeparator under
    # its link list. Stacking a second rule on top of it left a dead gap
    # between the navigation and the status block.
    with st.sidebar:
        sidebar_status()

    nav.run()


if __name__ == "__main__":
    main()
