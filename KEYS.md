# Getting the API keys

Every key here is free to obtain. You have to create the accounts yourself:
they are issued against your identity and your acceptance of each provider's
terms, so they cannot be requested on your behalf.

ThreatIQ runs without any of them. Nine of its fifteen tools need no key at
all, which is why it already produces real findings. Each key you add widens
coverage and raises the confidence of the result rather than switching
anything on.

There are two places to put a key, and they suit different deployments.

**The console's API keys page.** Paste a key, press Test keys, and it is checked
against the service that issued it. The key is held for that browser session
only: never written to disk, never shared with another visitor, sent with each
request and used for that request alone. This is the right choice when more than
one person uses the deployment, or when you would rather not put credentials on
a server at all.

**`.env` on the server.** One shared set of keys for everyone who uses the
deployment, read once at start-up. Simplest for a machine only you use. After
pasting a key into `.env`, restart the API and run:

```bash
make keys
```

That makes one cheap request per key and tells you whether the service
accepted it. Worth doing: a key that is present but wrong makes its tool report
`error` rather than `skipped`, which is easy to skim past in a long evidence
table.

---

## 1. VirusTotal — the biggest single gain

**Sign up:** <https://www.virustotal.com/gui/join-us>
**Copy your key:** <https://www.virustotal.com/gui/my-apikey> (under your
profile menu)
**Paste into:** `VIRUSTOTAL_API_KEY=`

Unlocks four tools at once: URL, domain, IP and file-hash reputation. File
hashes have no other source at all, so without this key ThreatIQ cannot assess
a hash.

It also unlocks the `threat_intel_reputation` factor, which carries **24% of
the risk model**. Until then every investigation reports "scored on 76% of the
model's weight", because the engine excludes what it could not evaluate rather
than scoring it as zero.

**Free tier:** 4 requests/minute, 500/day.
**Licence:** the free Public API
[must not be used in commercial products or services](https://docs.virustotal.com/reference/public-vs-premium-api).
Research, teaching and personal use are fine. A commercial deployment needs
their paid Premium API.

The 4/minute limit is why ThreatIQ paces this source. Calls beyond the quota
are reported as `Rate limited`, never as a clean result.

---

## 2. AbuseIPDB — the only IP reputation source

**Sign up:** <https://www.abuseipdb.com/register>
**Copy your key:** <https://www.abuseipdb.com/account/api>
**Paste into:** `ABUSEIPDB_API_KEY=`

Without it, an IP pivot resolves ownership through RDAP but carries no verdict.
With it, you get abuse report counts, reporter numbers, a confidence score and
the attack categories.

**Free tier:** 1,000 IP checks/day. No credit card.

---

## 3. NVD — optional, raises a rate limit

**Request:** <https://nvd.nist.gov/developers/request-an-api-key>
**Paste into:** `NVD_API_KEY=`

CVE lookups **already work without this**. The key only raises the request
rate, which matters if you submit many CVEs at once.

Free, US government, no commercial restriction.

---

## 4. urlscan.io — optional, raises a quota

**Sign up:** <https://urlscan.io/user/signup>
**Copy your key:** <https://urlscan.io/user/apikey>
**Paste into:** `URLSCAN_API_KEY=`

Search already works unauthenticated, and search is what ThreatIQ uses by
default. A key raises the quota.

Note that *submitting* a URL for a live scan publishes it. ThreatIQ only
submits behind an explicit opt-in, and uses `visibility: unlisted` when it
does.

**Free tier:** 1,000 searches/day, plus scan quotas.

---

## 5. An LLM — optional

Pick one:

- **Groq:** <https://console.groq.com/keys> → `GROQ_API_KEY=`
- **Gemini:** <https://aistudio.google.com/apikey> → `GOOGLE_API_KEY=`

Set `LLM_PROVIDER` to `groq` or `gemini` to match.

This changes less than you would expect, by design. Risk scores, framework
mappings and remediation steps are all computed deterministically. The model
writes the narrative around them and is structurally prevented from inventing
facts. Without a key you lose the prose, not the analysis.

---

## 6. LangSmith — optional, for tracing

**Sign up:** <https://smith.langchain.com>
**Paste into:** `LANGCHAIN_API_KEY=` and set `LANGCHAIN_TRACING_V2=true`

Traces the LangGraph run and any LLM calls that go through LangChain. Useful
for seeing which agent made which decision and how long each step took.

One caveat: the LLM layer falls back to raw HTTP when a LangChain provider
package is missing, and LangSmith cannot see those calls. `make verify` reports
which path your LLM calls take.

---

## Nothing to obtain

These already work and need no account:

- **CISA KEV** — the exploited-vulnerability catalogue, the strongest
  prioritisation signal in the tool
- **NVD** — CVSS scores and vectors, unauthenticated
- **DNS and RDAP** — resolution, domain age, registrar, network ownership
- **urlscan.io search** — unauthenticated
- **Lookalike detection, email analysis, HTTP probing** — computed locally

---

## Suggested order

1. **VirusTotal** — four tools and a quarter of the risk model
2. **AbuseIPDB** — free, and the only IP verdict you can get
3. Stop there unless something is actually limiting you

Then set `API_KEY` to any long random string. The API currently accepts
unauthenticated requests, which `/health` and the sidebar both report.
