#!/usr/bin/env bash
# Publish ThreatIQ to a Hugging Face Space.
#
#   deploy/huggingface/deploy.sh <username>/<space-name>
#
# Needs a write token from https://huggingface.co/settings/tokens, given as
# $HF_TOKEN or typed when prompted. The token is never written to disk and is
# kept out of the pushed remote URL, so it cannot end up in the Space's git
# config or in your shell history via the remote.
#
# The Space repo is assembled from scratch in a temporary directory each time,
# copying only the files the image needs. That is deliberate: a Space is a
# public git repo, and syncing the working tree wholesale is how a .env, a
# database dump or a stray note ends up published. Nothing is copied unless it
# is named below.
set -euo pipefail

SPACE_ID="${1:-}"
if [ -z "${SPACE_ID}" ] || [[ "${SPACE_ID}" != */* ]]; then
  echo "usage: $0 <username>/<space-name>" >&2
  exit 2
fi

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
HERE="${ROOT}/deploy/huggingface"

# Everything that goes into the Space. An allowlist, so a file added to the
# project later is not published by accident.
PAYLOAD=(
  "threatiq"
  "ui"
  "scripts"
  ".streamlit"
  "requirements.txt"
  "LICENSE"
)

if [ -z "${HF_TOKEN:-}" ]; then
  read -rsp "Hugging Face write token (input hidden): " HF_TOKEN
  echo
fi
if [ -z "${HF_TOKEN}" ]; then
  echo "error: no token supplied" >&2
  exit 2
fi

WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT

echo "==> assembling the Space in ${WORK}"
for item in "${PAYLOAD[@]}"; do
  if [ ! -e "${ROOT}/${item}" ]; then
    echo "error: ${item} is missing from the project" >&2
    exit 1
  fi
  cp -r "${ROOT}/${item}" "${WORK}/"
done
cp "${HERE}/Dockerfile" "${WORK}/Dockerfile"
cp "${HERE}/entrypoint.sh" "${WORK}/entrypoint.sh"
# The Space's own README carries the platform's YAML front matter, which is
# what tells it to build a Docker Space and which port to publish. The
# project's README stays as it is on GitHub.
cp "${HERE}/README.md" "${WORK}/README.md"

# Caches and compiled bytecode bloat the build context and can carry local
# paths; a .env would carry credentials. None of them are in PAYLOAD, but the
# directory copies can drag them along.
find "${WORK}" -name "__pycache__" -type d -prune -exec rm -rf {} + 2>/dev/null || true
find "${WORK}" \( -name "*.pyc" -o -name ".env" -o -name "*.log" \) -delete 2>/dev/null || true

echo "==> verifying nothing secret is about to be published"
if [ -f "${ROOT}/.env" ]; then
  leaked=0
  while IFS='=' read -r name value; do
    case "${name}" in \#*|"") continue ;; esac
    [ -z "${value}" ] && continue
    case "${name}" in *KEY*|*PASSWORD*|*TOKEN*|*SECRET*) ;; *) continue ;; esac
    if grep -rqF -- "${value}" "${WORK}" 2>/dev/null; then
      echo "  REFUSING: the value of ${name} appears in the payload" >&2
      leaked=1
    fi
  done < "${ROOT}/.env"
  if [ "${leaked}" -ne 0 ]; then
    echo "error: refusing to publish, a secret from .env is in the payload" >&2
    exit 1
  fi
  echo "  no value from .env appears in the payload"
fi

cd "${WORK}"
git init -q
git checkout -qb main
git add -A
git -c user.email="deploy@threatiq.local" -c user.name="ThreatIQ deploy" \
    commit -qm "Deploy ThreatIQ"

echo "==> pushing to https://huggingface.co/spaces/${SPACE_ID}"
# The token goes in a header rather than the URL so it is not stored in
# .git/config and does not appear in process listings as part of the remote.
git remote add origin "https://huggingface.co/spaces/${SPACE_ID}"
AUTH="$(printf 'user:%s' "${HF_TOKEN}" | base64 -w0)"
git -c "http.extraHeader=Authorization: Basic ${AUTH}" push -q --force origin main

cat <<EOF

Done. The Space is building at:
  https://huggingface.co/spaces/${SPACE_ID}

Next, in Settings -> Variables and secrets, add ONE secret:

  API_KEY     any long random string

Do NOT add VIRUSTOTAL_API_KEY, ABUSEIPDB_API_KEY or GROQ_API_KEY there. A
public Space would spend your free-tier quota on behalf of every visitor, and
VirusTotal's free API is not licensed for that. Visitors bring their own keys
through the console's API keys page instead, which is what it is for.
EOF
