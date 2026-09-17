"""Brand impersonation detection, offline, deterministic, no API required.

Catches the three techniques that cover most credential-phishing domains:
  1. character substitution   (paypa1.com, micros0ft.com)
  2. affix/hyphen padding     (microsoft-login-verify.com)
  3. unicode homoglyphs       (аpple.com with a Cyrillic 'а')
"""
from __future__ import annotations

import unicodedata

from threatiq.schemas import Evidence, Severity, ToolStatus, Verdict
from threatiq.tools.base import ToolContext, registry, timed

# Brands whose credentials are worth the most to an attacker.
PROTECTED_BRANDS = {
    "microsoft", "office365", "outlook", "onedrive", "sharepoint", "azure",
    "google", "gmail", "apple", "icloud", "amazon", "aws", "paypal", "stripe",
    "facebook", "instagram", "whatsapp", "linkedin", "netflix", "dropbox",
    "docusign", "adobe", "github", "gitlab", "slack", "zoom", "okta", "duo",
    "chase", "wellsfargo", "hsbc", "barclays", "citibank", "binance", "coinbase",
    "dhl", "fedex", "ups", "usps", "irs", "hmrc", "steam", "roblox", "meta",
}

# Visually confusable ASCII pairs used in substitution attacks.
_CONFUSABLES = str.maketrans({
    "0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b",
    "$": "s", "@": "a", "|": "l", "!": "i",
})

# TLDs where a domain matching a brand name exactly is most likely the brand
# itself (or a legitimate regional presence) rather than abuse.
_BRAND_SAFE_TLDS = {
    "com", "net", "org", "io", "co", "edu", "gov", "mil", "int", "info",
    "uk", "de", "fr", "jp", "cn", "in", "au", "ca", "nl", "se", "no", "dk",
    "fi", "es", "it", "br", "mx", "pk", "ch", "at", "be", "ie", "nz", "sg",
    "ai", "dev", "app", "cloud",
}

# Words appended to a brand to make a phishing domain look procedural.
_LURE_TOKENS = {
    "login", "signin", "sign-in", "verify", "verification", "secure", "security",
    "account", "accounts", "update", "confirm", "support", "help", "service",
    "billing", "payment", "invoice", "alert", "recovery", "reset", "auth",
    "portal", "webmail", "mail", "id", "identity", "session", "unlock", "suspend",
}


def _levenshtein(a: str, b: str) -> int:
    """Iterative two-row edit distance; no third-party dependency needed."""
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    previous = list(range(len(b) + 1))
    for i, ca in enumerate(a, start=1):
        current = [i]
        for j, cb in enumerate(b, start=1):
            current.append(min(
                previous[j] + 1,        # deletion
                current[j - 1] + 1,     # insertion
                previous[j - 1] + (ca != cb),  # substitution
            ))
        previous = current
    return previous[-1]


def _registrable_label(domain: str) -> tuple[str, str]:
    """Split a hostname into (registrable label, public suffix).

    A hand-rolled rule cannot tell `bbc.co.uk` from `foo.bar.com`, so the
    Public Suffix List is used when available. The heuristic fallback keeps the
    tool working offline, where tldextract cannot refresh its snapshot.
    """
    try:
        import tldextract

        # suffix_list_urls=() forces the bundled snapshot: no network call on
        # first use, and no surprise latency inside an investigation.
        extracted = tldextract.TLDExtract(suffix_list_urls=())(domain)
        if extracted.domain and extracted.suffix:
            return extracted.domain.lower(), extracted.suffix.lower()
    except Exception:  # noqa: S110
        # tldextract is an accelerator, not a dependency: the manual
        # suffix split below is the fallback and is always correct enough
        # for the comparison that follows.
        pass

    parts = domain.split(".")
    if len(parts) >= 3 and len(parts[-2]) <= 3 and len(parts[-1]) <= 3:
        return parts[-3], ".".join(parts[-2:])
    if len(parts) >= 2:
        return parts[-2], parts[-1]
    return domain, ""


def _skeleton(label: str) -> str:
    """Collapse a label to its visual skeleton so `paypa1` == `paypal`."""
    normalized = unicodedata.normalize("NFKD", label)
    ascii_only = normalized.encode("ascii", "ignore").decode("ascii")
    return ascii_only.lower().translate(_CONFUSABLES).replace("-", "").replace("_", "")


def has_non_ascii(domain: str) -> bool:
    return any(ord(ch) > 127 for ch in domain)


def detect_homoglyph(domain: str) -> dict[str, object] | None:
    """Flag mixed-script labels, legitimate domains rarely mix alphabets."""
    scripts: set[str] = set()
    for ch in domain:
        if not ch.isalpha():
            continue
        try:
            name = unicodedata.name(ch)
        except ValueError:
            continue
        scripts.add(name.split()[0])
    if len(scripts) > 1:
        return {"mixed_scripts": sorted(scripts)}
    if domain.startswith("xn--") or ".xn--" in domain:
        return {"punycode": True}
    return None


def analyze_domain(domain: str, extra_brands: set[str] | None = None) -> dict:
    """Return the full impersonation analysis for one domain."""
    domain = domain.lower().strip().rstrip(".")
    parts = domain.split(".")
    label, suffix = _registrable_label(domain)
    # Everything left of the public suffix, so subdomain lures like
    # "login.microsoft.evil.com" are still visible to the embedding check.
    full_prefix = domain[: -(len(suffix) + 1)] if suffix and domain.endswith(
        "." + suffix) else ".".join(parts[:-1]) or domain

    brands = PROTECTED_BRANDS | (extra_brands or set())
    skeleton = _skeleton(label)
    haystack = _skeleton(full_prefix)
    # The registrable suffix, so "co.uk" is treated as one unit, not "uk".
    tld = suffix or (parts[-1].lower() if len(parts) > 1 else "")

    result: dict = {
        "domain": domain,
        "label": label,
        "matched_brand": None,
        "technique": None,
        "edit_distance": None,
        "lure_tokens": sorted(t for t in _LURE_TOKENS if t in full_prefix),
        "homoglyph": detect_homoglyph(domain),
        "non_ascii": has_non_ascii(domain),
        "score": 0.0,
    }

    # A label that literally *is* a known brand cannot be a lookalike of a
    # different one. Without this, edit-distance flags real brands as typosquats
    # of their neighbours, github.com reads as a typosquat of gitlab.
    if label in brands:
        # Compare against the last label of the suffix so multi-part ccTLDs
        # resolve correctly: paypal.co.uk is PayPal UK, not brand abuse.
        if tld.rsplit(".", 1)[-1] in _BRAND_SAFE_TLDS:
            return result
        # The real brand name on a throwaway TLD is not a typo, but it is not
        # the brand either; that is brand abuse and still worth surfacing.
        result.update({
            "matched_brand": label, "technique": "brand_tld_abuse",
            "edit_distance": 0, "score": 0.6,
        })
        if result["lure_tokens"]:
            result["score"] = min(1.0, result["score"] + 0.1 * len(result["lure_tokens"]))
        return result

    best: tuple[float, str, str, int] | None = None
    for brand in brands:
        if skeleton == brand:
            # Exact skeleton match but not the real domain -> substitution attack.
            if label != brand:
                candidate = (0.95, brand, "character_substitution", 0)
            else:
                candidate = (0.0, brand, "exact_label", 0)
        elif brand in haystack and skeleton != brand:
            # Brand embedded in a longer name: microsoft-login-verify.com
            candidate = (0.8, brand, "brand_embedding", len(haystack) - len(brand))
        else:
            distance = _levenshtein(skeleton, brand)
            # Only near-misses on brands long enough for the distance to mean
            # something; short brands produce false positives at distance 1.
            if len(brand) >= 5 and 1 <= distance <= 2:
                candidate = (0.9 - 0.15 * (distance - 1), brand, "typosquat", distance)
            else:
                continue
        if best is None or candidate[0] > best[0]:
            best = candidate

    if best and best[0] > 0:
        score, brand, technique, distance = best
        result.update({
            "matched_brand": brand, "technique": technique,
            "edit_distance": distance, "score": score,
        })

    # Lure tokens and homoglyphs stack on top of the brand match.
    if result["lure_tokens"]:
        result["score"] = min(1.0, result["score"] + 0.1 * len(result["lure_tokens"]))
    if result["homoglyph"]:
        result["score"] = min(1.0, result["score"] + 0.25)
    if result["non_ascii"]:
        result["score"] = min(1.0, result["score"] + 0.15)

    return result


@registry.register(
    "lookalike_domain",
    description="Detect brand impersonation, typosquatting and homoglyph domains.",
    accepts=["domain"],
)
@timed("lookalike", "analyze")
async def lookalike_domain(ctx: ToolContext, domain: str) -> Evidence:
    analysis = analyze_domain(domain)
    score = float(analysis["score"])
    indicator = f"domain:{domain.lower()}"

    if score >= 0.8:
        verdict, severity, confidence = Verdict.MALICIOUS, Severity.CRITICAL, 0.85
    elif score >= 0.5:
        verdict, severity, confidence = Verdict.SUSPICIOUS, Severity.HIGH, 0.7
    elif score >= 0.25:
        verdict, severity, confidence = Verdict.SUSPICIOUS, Severity.MEDIUM, 0.55
    else:
        verdict, severity, confidence = Verdict.UNKNOWN, Severity.INFO, 0.5

    notes: list[str] = []
    if analysis["matched_brand"]:
        notes.append(
            f"resembles the '{analysis['matched_brand']}' brand via "
            f"{str(analysis['technique']).replace('_', ' ')}"
        )
    if analysis["lure_tokens"]:
        notes.append(
            "contains credential-harvesting keywords: "
            + ", ".join(analysis["lure_tokens"])
        )
    if analysis["homoglyph"]:
        notes.append(f"homoglyph indicators: {analysis['homoglyph']}")
    if not notes:
        notes.append("no brand-impersonation patterns detected")

    return Evidence(
        source="lookalike", tool="analyze", indicator=indicator,
        status=ToolStatus.OK, verdict=verdict, severity_hint=severity,
        confidence=confidence, summary=f"{domain}: " + "; ".join(notes),
        signals=analysis,
    )
