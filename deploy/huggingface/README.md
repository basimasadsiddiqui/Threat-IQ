---
title: ThreatIQ
emoji: 🛡️
colorFrom: blue
colorTo: indigo
sdk: docker
app_port: 7860
pinned: false
license: mit
short_description: Agentic AI security operations platform. Bring your own API keys.
---

# ThreatIQ

Submit a URL, domain, IP, file hash, CVE or a whole phishing email. ThreatIQ
plans an investigation, calls real security APIs, correlates the results into a
threat graph, scores the risk deterministically, maps findings to OWASP / CWE /
MITRE ATT&CK / NIST CSF, and says what to fix first.

The governing rule: **tools collect facts, the model interprets them.** The risk
score, the framework mapping and the remediation plan are produced by
deterministic code. The language model explains those results and is
structurally prevented from inventing them.

## This demo holds no API keys

Open **API keys** in the sidebar and paste your own. They are held in your
browser session, sent with each request, and used for that request only:
nothing is written to disk, and your keys are never visible to anyone else
using this Space. The page verifies each one against the service that issued it
before you rely on it.

Free keys, if you want fuller coverage:

- [VirusTotal](https://www.virustotal.com/gui/my-apikey) unlocks URL, domain, IP
  and file-hash reputation, and 24% of the risk model
- [AbuseIPDB](https://www.abuseipdb.com/account/api) is the only IP reputation
  source
- [Groq](https://console.groq.com/keys) or
  [Gemini](https://aistudio.google.com/apikey) adds the written narrative

**It works with no keys at all.** Nine of the fifteen tools need none: CISA KEV,
NVD, DNS, RDAP, urlscan search, plus lookalike detection, email header analysis
and HTTP probing, which are computed locally. A source without a key is reported
as `skipped` rather than counted as a clean result, so a thin investigation is
never mistaken for a reassuring one.

## Notes on this deployment

- Investigations are **not persisted**. A Space runs one container with no
  database, so the in-memory store is cleared whenever it restarts.
- Active scanning is **disabled**. It requires a server-side allowlist of hosts
  you own, and no such list exists here, so every scan is refused.
- The API is bound to loopback inside the container and is not reachable from
  the internet. Only the console is published.

Source, and how to run the full stack with Postgres and pgvector:
<https://github.com/basimasadsiddiqui/Threat-IQ>
