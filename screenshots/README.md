# Screenshots

Captured with headless Chromium against a live local stack.

| File | What it shows |
|---|---|
| `01-report-flaws.png` | Full report page: sidebar, risk headline and gauge, severity posture strip, counters, and the Flaws and vulnerabilities tab with a CISA KEV vulnerability card |
| `02-threat-graph.png` | Threat graph after the physics settle, with the verdict legend and layout controls |

Regenerate:

```bash
ID=$(curl -s -X POST localhost:8000/investigate -H 'Content-Type: application/json' \
  -d '{"input":"CVE-2024-3400","asset_criticality":"critical"}' | jq -r .id)
chromium --headless=new --disable-gpu --hide-scrollbars \
  --window-size=1180,2450 --virtual-time-budget=50000 --force-dark-mode \
  --screenshot=screenshots/01-report-flaws.png \
  "http://127.0.0.1:8501/?investigation=$ID"
```
