#!/usr/bin/env bash
# Start both halves of ThreatIQ inside the single container a Space gets.
#
# The API is NOT published. A Space exposes exactly one port, so uvicorn binds
# loopback and only the console is reachable: the investigation pipeline cannot
# be driven from the internet at all, which matters because /investigate makes
# ThreatIQ fetch URLs the caller chose.
set -euo pipefail

APP_PORT="${APP_PORT:-7860}"
API_PORT="${API_PORT:-8000}"

# Streamlit refuses a WebSocket from an origin that is not on its allowlist, and
# the checked-in allowlist is localhost, so a Space would sit at "Please wait"
# for ever. SPACE_HOST is injected by the platform and is the only place the
# real hostname is known, so it has to be written in at start rather than baked
# into the image.
ORIGIN="https://${SPACE_HOST:-localhost:${APP_PORT}}"
python - "$ORIGIN" <<'PY'
import pathlib, re, sys

origin = sys.argv[1]
path = pathlib.Path("/app/.streamlit/config.toml")
text = path.read_text(encoding="utf-8")
text, count = re.subn(
    r"^corsAllowedOrigins\s*=.*$",
    f'corsAllowedOrigins = ["{origin}"]',
    text,
    flags=re.M,
)
# Loud rather than silent: if the key is ever renamed upstream, a quiet no-op
# here produces a console that loads and then hangs, which is a miserable thing
# to debug from a build log.
if count != 1:
    sys.exit(f"[entrypoint] expected one corsAllowedOrigins line, found {count}")
path.write_text(text, encoding="utf-8")
print(f"[entrypoint] corsAllowedOrigins = {origin}", file=sys.stderr)
PY

# The API and the console name the shared secret differently. Deriving one from
# the other here means a Space owner sets a single secret, rather than setting
# two and having the console 401 against its own backend when they drift.
export THREATIQ_API_URL="http://127.0.0.1:${API_PORT}"
export THREATIQ_API_KEY="${API_KEY:-}"

if [ -z "${API_KEY:-}" ]; then
  echo "[entrypoint] warning: API_KEY is unset, so the API accepts unauthenticated" >&2
  echo "[entrypoint] requests. It is bound to loopback and unreachable from" >&2
  echo "[entrypoint] outside, but set the secret anyway." >&2
fi

uvicorn threatiq.api.main:app --host 127.0.0.1 --port "${API_PORT}" &
API_PID=$!

# A console whose backend has died is a page of error toasts, not a degraded
# service. Take the container down instead so the platform restarts it.
trap 'kill "${API_PID}" 2>/dev/null || true' EXIT INT TERM

for _ in $(seq 1 60); do
  if curl -fsS "http://127.0.0.1:${API_PORT}/health" >/dev/null 2>&1; then
    echo "[entrypoint] API is up" >&2
    break
  fi
  if ! kill -0 "${API_PID}" 2>/dev/null; then
    echo "[entrypoint] API exited during startup" >&2
    exit 1
  fi
  sleep 1
done

exec streamlit run ui/app.py \
  --server.port "${APP_PORT}" \
  --server.address 0.0.0.0 \
  --server.headless true \
  --browser.gatherUsageStats false
