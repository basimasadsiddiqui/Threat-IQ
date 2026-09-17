# ThreatIQ as a single-container Hugging Face Space.
#
# The project's own Dockerfile builds two images and Compose runs them beside
# Postgres. A Space gets one container and one published port, so this image
# runs both processes and lets the pipeline take the degraded paths it already
# supports: the in-memory repository instead of Postgres, and the in-process
# retrieval index instead of pgvector. Neither is a compromise in analysis
# quality; investigations are simply not persisted across a restart.
FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# curl serves the entrypoint's readiness probe.
RUN apt-get update \
 && apt-get install -y --no-install-recommends curl \
 && rm -rf /var/lib/apt/lists/*

# Spaces run the container as uid 1000 and expect that user to own a writable
# HOME; Streamlit will not start without somewhere to put its state.
RUN useradd --create-home --uid 1000 user
ENV HOME=/home/user

WORKDIR /app

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY threatiq/ ./threatiq/
COPY ui/ ./ui/
COPY scripts/ ./scripts/
# The theme. Without it the console renders on Streamlit's stock palette, whose
# primary red is the same red this app uses for a CRITICAL verdict.
COPY .streamlit/ ./.streamlit/
COPY entrypoint.sh /usr/local/bin/entrypoint.sh

# /app must be writable by `user`: the entrypoint rewrites the CORS origin into
# .streamlit/config.toml once the platform hostname is known.
RUN chmod +x /usr/local/bin/entrypoint.sh \
 && chown -R user:user /app

USER user

ENV APP_PORT=7860 \
    API_PORT=8000 \
    ENVIRONMENT=prod \
    LOG_LEVEL=INFO
EXPOSE 7860

CMD ["/usr/local/bin/entrypoint.sh"]
