# syntax=docker/dockerfile:1
# Single image serving both the API and the UI; the compose file picks the
# command. Python 3.12 because the pinned dependency set has wheels for it.
FROM python:3.12-slim AS base

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

# curl is used by the container healthchecks below.
RUN apt-get update \
 && apt-get install -y --no-install-recommends curl \
 && rm -rf /var/lib/apt/lists/*

# Dependencies in their own layer so code changes don't re-resolve them.
COPY requirements.txt .
RUN pip install -r requirements.txt

COPY threatiq/ ./threatiq/
COPY ui/ ./ui/
COPY scripts/ ./scripts/
# The theme lives here. Without it the container renders with Streamlit's stock
# palette, whose primary red is the same red this app uses for CRITICAL.
COPY .streamlit/ ./.streamlit/

# Never run as root.
RUN useradd --create-home --uid 10001 threatiq \
 && chown -R threatiq:threatiq /app
USER threatiq

EXPOSE 8000 8501

# ---------------------------------------------------------------- API
FROM base AS api
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD curl -fsS http://localhost:8000/health || exit 1
CMD ["uvicorn", "threatiq.api.main:app", "--host", "0.0.0.0", "--port", "8000"]

# ---------------------------------------------------------------- UI
FROM base AS ui
HEALTHCHECK --interval=30s --timeout=5s --start-period=25s --retries=3 \
  CMD curl -fsS http://localhost:8501/_stcore/health || exit 1
CMD ["streamlit", "run", "ui/app.py", \
     "--server.port=8501", "--server.address=0.0.0.0", \
     "--server.headless=true", "--browser.gatherUsageStats=false"]
