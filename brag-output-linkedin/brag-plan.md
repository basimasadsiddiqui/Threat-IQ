# Brag Plan: ThreatIQ — LinkedIn walkthrough

## What is this app?
An agentic AI security operations platform. Paste a URL, domain, IP, file hash,
CVE or a whole phishing email and it plans an investigation, calls real security
APIs, correlates the results, scores the risk deterministically, and says what to
fix first.

## The angle
The first brag video argued a thesis. This one **shows the product working**, end
to end, because that is what a LinkedIn viewer scrolling past actually wants:
what do I type, what comes back, and what do I do with it.

The spine is the real happy path from the deployed console — submit, classify,
score, name, evidence, copilot — with the numbers taken from an actual run of
`paypa1-secure-login.tk` on the live site. Nothing here is invented for the
video.

The one opinionated beat kept from the product's philosophy: the coverage line.
`Scored on 56% of the model's weight` is on screen and called out, because a tool
that admits what it could not check is the differentiator, and on LinkedIn that
reads as engineering maturity rather than as weakness.

## Hook (first 2-3 seconds)
An empty console input, a cursor, and one instruction: **"Paste anything
suspicious."** Then a look-alike domain types itself in. The hook is the promise
of a single box that accepts six different kinds of thing.

## Key moments (the middle)
- The input classifies itself: `Classified as domain · 1 indicator`.
- The verdict lands: **66.9 / 100, HIGH**.
- The investigation **names itself**: `paypa1-secure-login.tk - phishing` — not a
  hex id, a sentence a human can recognise in a list a week later.
- Two real findings arrive as cards, severity-railed, the critical one first.
- `Scored on 56% of the model's weight` — the honesty beat.
- One tap on **Ask the Copilot how to fix this**, and a grounded remediation
  answer types out with its MITRE citation.

## Outro / punchline
`Tools collect facts. The model interprets them.` then the wordmark and the live
URL, so the viewer can go and try it.

## User flow worth showing
This video *is* the user flow, in the order the console performs it:
1. Paste an indicator into the Investigate box.
2. It classifies, extracts indicators, and runs the agent graph.
3. A named report comes back with a score, findings and a route to the Copilot.

## Tone
- Preset: `app-store`
- Creative direction: a calm product walkthrough that respects the viewer's time
- Interpretation: clean sequential reveals, one idea per beat, no hype adjectives.
  Motion slides and settles. The pace comes from cuts, not from rushing text.

## Format: vertical — 1080x1920
## Duration: 25.0 seconds

## Visual identity (from the project)
- Background `#0b0f14`, panel `#141b23`, border `#243040`
- Ink `#e6edf3`, muted `#9aa6b2`, accent `#2f6fd8`
- Severity: critical `#ea5459`, high `#f76808`, low `#46a758`
- Display: system sans. Mono: `JetBrains Mono, SF Mono, Menlo`
- Strongest visual: the risk headline in its severity colour, directly above the
  investigation's own name

## Share copy (draft)
Paste a suspicious domain. ThreatIQ plans the investigation, calls the real
threat-intel APIs, scores it deterministically, and tells you what to block
first. It also tells you what it could not check — 56% coverage on this one,
reported rather than scored as zero. Live link in comments.

## Audio direction
- Role: clean product bed with motion-matched interface accents
- Music: `happy-beats-business-moves-vol-9-by-ende-dot-app.mp3` (114.84 BPM)
- Music treatment: from 0 at ~0.24, fade out under the outro
- Music cue guidance: strong cues at **4.23s** (submit), **7.92s** (score lands),
  **12.65s** (first finding card), **23.17s** (outro settle). Sequential finding
  cards on the beat grid at 12.65 / 13.70 / 14.76 — every other beat, because
  0.52s spacing outruns reading a card.
- Audio-reactive treatment: none. This is a walkthrough; steady is the point.
- SFX posture: moderate but clean — key ticks while typing, one click on submit,
  one soft impact on the score, a tick per finding card, one click on the Copilot
  button. Nothing under the outro.
- Restraint rule: no risers, no whooshes. If a cue would make it feel like an
  advert rather than a tool, drop it.

## Storyboard

### Scene 1 — The box — 4.2s
Vertical frame. Small `ThreatIQ` wordmark top-left. Centred: the Investigate
card with its real label `URL, domain, IP address, file hash, CVE, or a full
email message`, an empty input and a blinking cursor. Above it, large:
**Paste anything suspicious.**
At 1.6s `paypa1-secure-login.tk` types into the field.
Sequential/interaction: yes — typed input, character reveal.
Audio intent: quiet, ready. Key ticks under the typing.
Transition mood: clean → Scene 2

### Scene 2 — It runs — 3.2s
The primary `Investigate` button depresses at **4.23s** with a click. A chip
appears beneath: `Classified as domain · 1 indicator: paypa1-secure-login.tk`.
Then four agent pills light one after another: `orchestrator`, `threat intel`,
`phishing`, `correlation` — showing that this is a graph, not one call.
Sequential/interaction: yes — simulated button press, then four pills.
Audio intent: one click, then soft ticks as each pill lights.
Transition mood: clean → Scene 3

### Scene 3 — The verdict, and its name — 5.2s
**66.9 / 100** lands at **7.92s** in high-orange with a `HIGH` badge. At
**8.44s**, directly beneath, the investigation's own name types in:
`paypa1-secure-login.tk - phishing`, with the hex id small and muted below it
(`Investigation 8c3f262643f3`) to show the name is the label, not a replacement
for the key.
Sequential/interaction: yes — score, then name, two beats.
Audio intent: one soft impact on the number. Nothing on the name; let it read.
Transition mood: clean → Scene 4

### Scene 4 — What it found — 4.8s
Two finding cards slide in at **12.65s** and **13.70s**, each with a severity
rail: `CRITICAL — Brand impersonation domain` and `HIGH — Malicious indicator`.
At **14.76s** the coverage line appears beneath, muted:
`Scored on 56% of the model's weight` with the small caption
`missing coverage is reported, never scored as zero`.
Sequential/interaction: yes — two cards one by one, then the coverage line.
Audio intent: one tick per card. The coverage line is silent.
Transition mood: clean → Scene 5

### Scene 5 — And what to do — 4.1s
The `Ask the Copilot how to fix this` button appears and is tapped at **17.91s**.
The frame becomes a chat: the question `How do I fix this?` on the right, then a
grounded answer types in on the left:
`Block paypa1-secure-login.tk at the web proxy, DNS resolver and mail gateway.`
with the citation row `T1566 · T1583.001` beneath it.
Sequential/interaction: yes — simulated tap, then a typed answer.
Audio intent: one click on the button, light ticks under the answer.
Transition mood: soft → Scene 6

### Scene 6 — The rule — 3.5s
Clears to off-black. **Tools collect facts. The model interprets them.** Then
the wordmark, and beneath it `threat-iq-project.streamlit.app`.
Sequential/interaction: line, then mark, then URL.
Audio intent: music fades to silence. No stinger.

**Music mood for this video:** clean, steady, product-walkthrough.
**Audio summary:** typing and one click to start, a soft impact when the score
lands, methodical ticks through the findings, one click into the Copilot, then
silence under the closing line.
