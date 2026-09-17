"""Live verification of an API key against the service that issued it.

One definition of "what a working key looks like", shared by the `make keys`
CLI and by the settings page in the console. They used to be separate, which is
how a probe drifts: the CLI would say a key was fine while the UI had never
heard of that provider.

A probe is deliberately boring. One GET, to a fixed URL, for a well-known
public indicator, with no writes and no user-supplied destination. The URLs
below are constants precisely so that exposing this over HTTP cannot turn into
a request-forgery primitive: a caller chooses which provider to test, never
where the request goes.

What the result deliberately does NOT contain is the key. A check returns the
verdict and nothing else, so a key cannot come back out through the same
endpoint that accepted it.
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass

import httpx

# How long a single probe may take. Short: this runs while someone waits on a
# settings page, and a provider that cannot answer in 15s is not going to serve
# an investigation either.
PROBE_TIMEOUT_S = 15.0


@dataclass(frozen=True)
class Probe:
    """How to ask one provider whether it recognises a key."""
    name: str                 # display name
    setting: str              # the Settings field this key populates
    signup: str               # where to get one
    unlocks: str              # what it buys, in plain words
    url: str                  # fixed; never built from caller input
    auth_header: str
    auth_template: str = "{key}"
    extra_headers: tuple[tuple[str, str], ...] = ()
    # Optional means ThreatIQ already works without it, the key only widens
    # coverage or raises a quota.
    optional: bool = False
    # For providers whose URL lists models: the response is searched for the
    # model this deployment is configured to call. A key can be perfectly valid
    # against a model that has been retired, and then every request 404s while
    # the key itself tests clean.
    model_setting: str | None = None

    def headers(self, key: str) -> dict[str, str]:
        return {self.auth_header: self.auth_template.format(key=key),
                **dict(self.extra_headers)}


# google.com and 8.8.8.8 are safe to look up from anywhere and are already in
# every one of these providers' caches, so a probe costs the cheapest possible
# unit of the free-tier quota it is testing.
PROBES: tuple[Probe, ...] = (
    Probe(
        name="VirusTotal",
        setting="virustotal_api_key",
        signup="https://www.virustotal.com/gui/my-apikey",
        unlocks="URL, domain, IP and file-hash reputation, plus 24% of the risk model",
        url="https://www.virustotal.com/api/v3/domains/google.com",
        auth_header="x-apikey",
    ),
    Probe(
        name="AbuseIPDB",
        setting="abuseipdb_api_key",
        signup="https://www.abuseipdb.com/account/api",
        unlocks="IP abuse reports, the only IP reputation source",
        url="https://api.abuseipdb.com/api/v2/check?ipAddress=8.8.8.8&maxAgeInDays=90",
        auth_header="Key",
        extra_headers=(("Accept", "application/json"),),
    ),
    Probe(
        name="NVD",
        setting="nvd_api_key",
        signup="https://nvd.nist.gov/developers/request-an-api-key",
        unlocks="a higher CVE lookup rate; CVE lookups already work without it",
        url="https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2021-44228",
        auth_header="apiKey",
        optional=True,
    ),
    Probe(
        name="urlscan.io",
        setting="urlscan_api_key",
        signup="https://urlscan.io/user/apikey",
        unlocks="a higher search quota; search already works without it",
        url="https://urlscan.io/api/v1/search/?q=domain%3Agoogle.com&size=1",
        auth_header="API-Key",
        optional=True,
    ),
    Probe(
        name="Groq",
        setting="groq_api_key",
        signup="https://console.groq.com/keys",
        unlocks="narrative explanations; every score is computed without it",
        url="https://api.groq.com/openai/v1/models",
        auth_header="Authorization",
        auth_template="Bearer {key}",
        optional=True,
        model_setting="groq_model",
    ),
    Probe(
        # Header auth rather than the ?key= form Google also accepts: a key in a
        # query string lands in proxy logs and browser history.
        name="Gemini",
        setting="google_api_key",
        signup="https://aistudio.google.com/apikey",
        unlocks="narrative explanations; every score is computed without it",
        url="https://generativelanguage.googleapis.com/v1beta/models",
        auth_header="x-goog-api-key",
        optional=True,
    ),
)

PROBES_BY_SETTING: dict[str, Probe] = {p.setting: p for p in PROBES}


@dataclass(frozen=True)
class KeyCheck:
    """The verdict on one key. Carries no key material by construction."""
    name: str
    setting: str
    state: str          # ok | rejected | unreachable | unclear | absent
    detail: str
    optional: bool
    signup: str
    unlocks: str

    @property
    def usable(self) -> bool:
        return self.state == "ok"


def _absent(probe: Probe) -> KeyCheck:
    return KeyCheck(
        name=probe.name, setting=probe.setting, state="absent",
        detail="not set", optional=probe.optional,
        signup=probe.signup, unlocks=probe.unlocks,
    )


def _classify(probe: Probe, status_code: int) -> KeyCheck:
    if status_code in (200, 201):
        state, detail = "ok", "accepted"
    elif status_code in (401, 403):
        # The single most useful thing this whole module does. A key that is
        # present but wrong makes its tool report `error` rather than `skipped`,
        # which is easy to skim past in a long evidence table.
        state, detail = "rejected", f"rejected the key (HTTP {status_code})"
    elif status_code == 429:
        # Valid key, spent quota. Reporting this as a failure would send someone
        # hunting for a typo in a key that is perfectly fine.
        state, detail = "ok", "accepted, but currently rate limited (HTTP 429)"
    else:
        state, detail = "unclear", f"unexpected HTTP {status_code}"
    return KeyCheck(
        name=probe.name, setting=probe.setting, state=state, detail=detail,
        optional=probe.optional, signup=probe.signup, unlocks=probe.unlocks,
    )


def _model_is_offered(probe: Probe, response: httpx.Response,
                      model: str) -> KeyCheck | None:
    """Reject a good key pointed at a model the provider no longer serves.

    Checking only that the key is accepted answers the wrong question. Providers
    retire models, and when they do, `/models` keeps returning 200 for the key
    while every completion returns 404. The console then reports the language
    model as configured and working, the pipeline silently takes its
    deterministic branch on every call, and the only trace is a log line nobody
    is reading. That is the same failure this module exists to catch, one level
    further in: present, accepted, and not actually usable.
    """
    if not model:
        return None
    try:
        offered = {m.get("id") for m in response.json().get("data", [])}
    except ValueError:
        return None          # not the JSON we expected; let the status stand
    if not offered or model in offered:
        return None
    return KeyCheck(
        name=probe.name, setting=probe.setting, state="rejected",
        detail=(f"key accepted, but the configured model {model!r} is not one "
                f"this provider offers, so every call would fail"),
        optional=probe.optional, signup=probe.signup, unlocks=probe.unlocks,
    )


async def check_one(client: httpx.AsyncClient, probe: Probe, key: str,
                    model: str = "") -> KeyCheck:
    """Probe one provider. Never raises, and never returns the key."""
    if not key or not key.strip():
        return _absent(probe)
    try:
        response = await client.get(
            probe.url, headers=probe.headers(key.strip()),
            timeout=PROBE_TIMEOUT_S,
        )
    except httpx.HTTPError as exc:
        # Reaching the provider is a different failure from the provider
        # refusing the key, and conflating them sends people to fix the wrong
        # thing. The exception type only, never its text: a connection error can
        # echo the request back, and the request carries the key in a header.
        return KeyCheck(
            name=probe.name, setting=probe.setting, state="unreachable",
            detail=f"could not reach the service ({type(exc).__name__})",
            optional=probe.optional, signup=probe.signup, unlocks=probe.unlocks,
        )
    verdict = _classify(probe, response.status_code)
    if verdict.state == "ok" and probe.model_setting:
        return _model_is_offered(probe, response, model) or verdict
    return verdict


async def check_keys(keys: dict[str, str],
                     probes: tuple[Probe, ...] = PROBES,
                     models: dict[str, str] | None = None) -> list[KeyCheck]:
    """Check every probe against the supplied keys, concurrently.

    Providers are unrelated to each other, so one slow or unreachable service
    must not decide how long the whole settings page takes.

    `models` maps a Settings field name to the model configured for it, so a
    provider that lists its models can be asked whether the one this deployment
    would actually call still exists.
    """
    models = models or {}
    async with httpx.AsyncClient(follow_redirects=True) as client:
        return list(await asyncio.gather(*(
            check_one(client, probe, keys.get(probe.setting, ""),
                      models.get(probe.model_setting or "", ""))
            for probe in probes
        )))
