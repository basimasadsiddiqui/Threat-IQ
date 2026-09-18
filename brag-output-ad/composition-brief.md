# Hyperframes Composition Brief: ThreatIQ — the ad

## Objective
A 21-second square advert. State a problem an analyst recognises in three
seconds, collapse it into the product, prove it with real numbers, land the one
claim competitors will not make, and give an address.

## Output
- Composition directory: `brag-output-ad/composition/`
- Rendered video: `brag-output-ad/brag.mp4`
- Format: square — 1080x1080 · Duration: 21.0s

## Source Material
- Project root: `/home/home/Downloads/threatiq`
- Figures measured from the codebase, not rounded for effect:
  15 registered tools (9 need no key), 4 specialist agents, 7 weighted risk
  factors, 46 knowledge-base entries, 303 tests
- Copy that must appear verbatim:
  - `One indicator.` / `Eleven tabs.` / `One box.`
  - `URL, domain, IP address, file hash, CVE, or a full email message`
  - `15 tools`, `nine need no API key`
  - `4 agents`, `run in parallel, deterministically routed`
  - `7 factors`, `weighted, inspectable, reproducible`
  - `Scored on 56% of the model's weight.`
  - `A failed lookup is not evidence of safety.`
  - `Tools collect facts. The model interprets them.`
  - `threat-iq-project.streamlit.app`
  - `Free. No key required to start.`

## Creative Direction
- Tone preset: `app-store`
- Creative direction: a confident B2B security ad that never oversells, because
  the product's credibility IS the pitch
- Interpretation: one claim per frame, decisive cuts, numbers instead of
  adjectives. Motion arrives fast and stops dead.
- Hook: eleven real tool names stacking up, then "One indicator. Eleven tabs."
- Outro: the rule, the wordmark, the URL.
- Avoid: speed multipliers, "powered by AI", any suggestion the model decides
  the verdict (the product's thesis is the opposite), emoji, generic SaaS
  language, risers and whooshes.

## Visual Identity
Background `#0b0f14`, panel `#141b23`, border `#243040`, ink `#e6edf3`,
muted `#9aa6b2`, accent `#2f6fd8`, severity critical `#ea5459` / high `#f76808`.
Display: system sans stack. Mono: `"JetBrains Mono", "SF Mono", Menlo`.

## Storyboard
See `brag-output-ad/brag-plan.md`.
1. Eleven tabs — 3.7s · 2. One box — 3.6s · 3. What it does — 4.6s ·
4. The part nobody advertises — 4.4s · 5. The rule — 2.6s · 6. Where to go — 2.1s

## Audio
- Music `happy-beats-business-moves-vol-9-by-ende-dot-app.mp3`, bed 0.24 set via
  `tl.set` (a volume tween replaces the element gain rather than scaling it),
  fading out under the URL.
- Cue locks: **3.70s** collapse, **7.92s** first proof card, **12.65s** the
  differentiator, **19.48s** the URL. Proof cards on the beat grid at
  7.92 / 8.96 / 10.01 — every other beat.
- SFX: a tick per tab chip, one soft impact on the collapse, one tick per proof
  card. Nothing from the differentiator card onward — the last eight seconds are
  deliberately unscored.
- Every `<audio>` needs an `id` or the renderer cannot discover it and the track
  renders silent.

## Hyperframes Instructions
`hyperframes-*` domain skills are not installed; use `npx hyperframes docs
compositions|data-attributes|gsap`. Keep text readable (short label ~0.8s
settled, sentence ~0.3s/word). Run `npx hyperframes check` before render.

## Environment constraints
`/tmp` is nearly full and the renderer's disk guard reads it: export `TMPDIR`
and `HYPERFRAMES_EXTRACT_CACHE_DIR` under `/home`, pass `--frames-cache-dir`,
render with `--workers 2`, and stop the local ThreatIQ stack first.
