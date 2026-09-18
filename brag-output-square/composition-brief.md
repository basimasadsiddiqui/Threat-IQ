# Hyperframes Composition Brief: ThreatIQ — LinkedIn walkthrough

## Objective
A vertical product walkthrough for LinkedIn showing ThreatIQ's real happy path
end to end: paste an indicator, watch it classify and run, see the named report
with its score and findings, and follow it into the Copilot for a fix.

## Output
- Composition directory: `brag-output-square/composition/`
- Rendered video: `brag-output-square/brag.mp4`
- Format: square — 1080x1080
- Duration: 25.0 seconds

## Source Material
- Project root: `/home/home/Downloads/threatiq`
- Primary files: `ui/app.py`, `threatiq/schemas.py` (the `label` property),
  `threatiq/engine/risk_engine.py`, `.streamlit/config.toml`
- Numbers taken from a real run of `paypa1-secure-login.tk` on the deployed site
- Copy that must appear verbatim:
  - `URL, domain, IP address, file hash, CVE, or a full email message`
  - `paypa1-secure-login.tk`
  - `Investigate`
  - `Classified as domain · 1 indicator`
  - `66.9`, `/ 100`, `HIGH`
  - `paypa1-secure-login.tk - phishing`
  - `Investigation 8c3f262643f3`
  - `Brand impersonation domain`
  - `Malicious indicator`
  - `Scored on 56% of the model's weight`
  - `Ask the Copilot how to fix this`
  - `How do I fix this?`
  - `Block paypa1-secure-login.tk at the web proxy, DNS resolver and mail gateway.`
  - `Tools collect facts. The model interprets them.`
  - `threat-iq-project.streamlit.app`

## Creative Direction
- Tone preset: `app-store`
- Creative direction: a calm product walkthrough that respects the viewer's time
- Interpretation: clean sequential reveals, one idea per beat, slides that settle.
  Pace from cuts, never from rushing text.
- Hook: an empty console box and "Paste anything suspicious."
- Outro: the governing line, the wordmark, the live URL.
- Avoid: generic SaaS language, abstract filler, emoji (the project bans them in
  its own UI and a test enforces it), anything that reads as an advert.

## Visual Identity
- Background `#0b0f14`, panel `#141b23`, border `#243040`
- Ink `#e6edf3`, muted `#9aa6b2`, accent `#2f6fd8`
- Severity: critical `#ea5459`, high `#f76808`, low `#46a758`
- Display font: system sans stack. Mono: `"JetBrains Mono", "SF Mono", Menlo`
- Vertical layout: stacked cards in a single column, designed for 1080x1080; each beat owns the frame rather than stacking —
  do NOT letterbox a landscape console screenshot.

## Storyboard
Use `brag-output-square/brag-plan.md` as the creative contract.

1. The box — 4.2s — the Investigate card; the domain types in
2. It runs — 3.2s — submit at 4.23s; classification chip; four agent pills light
3. The verdict, and its name — 5.2s — `66.9 / 100 HIGH` at 7.92s, name at 8.44s
4. What it found — 4.8s — two finding cards at 12.65 / 13.70, coverage at 14.76
5. And what to do — 4.1s — Copilot tapped at 17.91s, grounded answer types in
6. The rule — 3.5s — closing line, wordmark, live URL

## Audio
- Audio role: clean product bed with motion-matched interface accents
- Music: `happy-beats-business-moves-vol-9-by-ende-dot-app.mp3`, level ~0.24,
  fading to silence under the outro
- Music cue guidance: strong cues **4.23s** (submit), **7.92s** (score),
  **12.65s** (first finding), **23.17s** (outro settle). Finding cards on the
  beat grid at 12.65 / 13.70 / 14.76 — every other beat; 0.52s spacing outruns
  reading a card.
- Audio-reactive treatment: none. Steady is the point for a walkthrough.
- Audio-coupled moments: typed input, the submit click, the four agent pills,
  the score impact, one tick per finding card, the Copilot tap, the typed answer.
- SFX: key ticks for typing, one click for each button press, one soft impact for
  the score, soft ticks for cards. Nothing under the outro.
- Set the bed level on the timeline with `tl.set`, not via `data-volume`, because
  a GSAP volume tween replaces the element gain rather than scaling it.
- Every `<audio>` element must carry an `id` or the renderer cannot discover it
  and the track renders silent.

## Hyperframes Instructions
The `hyperframes-*` domain skills are not installed here; use the CLI docs
(`npx hyperframes docs compositions|data-attributes|gsap|rendering`).

Requirements:
- Show real UI and real copy from the project.
- Keep text readable: short labels ~0.8s settled, sentences ~0.3s/word.
- 15-25 seconds.
- Include the music/SFX layer.
- Run `npx hyperframes check` before render — the single gate.

## Environment constraints (measured)
- `/tmp` is a 3.9 GB tmpfs with under 1 GB free and the renderer's disk guard
  reads it. Export `TMPDIR` and `HYPERFRAMES_EXTRACT_CACHE_DIR` to paths under
  `/home` before rendering, and pass `--frames-cache-dir`.
- Low RAM: render with `--workers 2` and stop the local ThreatIQ stack first.
