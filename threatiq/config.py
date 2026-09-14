"""Central configuration. Every external dependency is optional so the system
degrades gracefully instead of crashing when a key or service is absent."""
from __future__ import annotations

from functools import lru_cache
from typing import Literal

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env", env_file_encoding="utf-8", extra="ignore"
    )

    app_name: str = "ThreatIQ"
    environment: Literal["dev", "staging", "prod"] = "dev"
    log_level: str = "INFO"

    # --- API ---
    api_host: str = "0.0.0.0"
    api_port: int = 8000
    api_base_url: str = "http://localhost:8000"
    # Shared secret between UI and API. Empty string disables auth (dev only).
    api_key: str = ""
    cors_origins: str = "http://localhost:8501"

    # --- LLM ---
    llm_provider: Literal["groq", "gemini", "none"] = "groq"
    groq_api_key: str = ""
    groq_model: str = "llama-3.3-70b-versatile"
    google_api_key: str = ""
    gemini_model: str = "gemini-2.0-flash"
    llm_temperature: float = 0.1
    llm_timeout_s: int = 60

    # --- database ---
    database_url: str = ""  # empty -> in-memory repository
    db_echo: bool = False

    # --- external security APIs ---
    virustotal_api_key: str = ""
    abuseipdb_api_key: str = ""
    urlscan_api_key: str = ""
    nvd_api_key: str = ""  # optional, raises NVD rate limit
    otx_api_key: str = ""

    # --- scanning ---
    zap_base_url: str = ""  # e.g. http://zap:8090
    zap_api_key: str = ""
    # Active scanning is refused unless the target is listed here.
    authorized_scan_targets: str = ""

    # --- retrieval ---
    embedding_dim: int = 384
    rag_top_k: int = 5

    # --- budgets ---
    tool_timeout_s: int = 20
    max_investigation_seconds: int = 180
    max_agent_loops: int = 3

    # How long a single call may wait for its source's rate-limit quota before
    # being shed and reported as rate-limited. VirusTotal's free tier allows 4
    # requests a minute, so a wide fan-out would otherwise queue for minutes
    # and consume the whole investigation deadline. Partial coverage that is
    # reported honestly beats a request that blocks.
    rate_limit_max_wait_s: int = 25

    # Hard ceiling on any single upstream response body. http_probe fetches
    # attacker-chosen URLs, so without a cap a hostile host can answer with a
    # multi-gigabyte body and exhaust the container. 2 MB is far more than
    # headers, a redirect chain or a reputation payload ever need.
    max_response_bytes: int = 2_000_000
    # The CISA KEV catalogue is a single large JSON document and is exempt.
    kev_max_response_bytes: int = 30_000_000

    # --- inbound abuse controls ---
    # Outbound calls are paced; inbound ones were not. Anyone able to reach
    # /investigate could submit thousands of URLs and use ThreatIQ as a
    # scanning proxy, burning third-party quota and putting this host's address
    # in someone else's logs as the scanner.
    inbound_rate_per_minute: int = 20
    inbound_burst: int = 10
    max_concurrent_investigations: int = 4

    # Raise the ceilings when you hold a paid tier, as "source=requests/seconds"
    # entries, e.g. "virustotal=1000/60,abuseipdb=50000/86400".
    rate_limit_overrides: str = ""

    # --- observability ---
    langchain_tracing_v2: bool = Field(default=False, alias="LANGCHAIN_TRACING_V2")
    langchain_api_key: str = Field(default="", alias="LANGCHAIN_API_KEY")
    langchain_project: str = Field(default="threatiq", alias="LANGCHAIN_PROJECT")
    otel_exporter_otlp_endpoint: str = ""
    otel_enabled: bool = False

    @property
    def cors_origin_list(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]

    @property
    def authorized_targets(self) -> set[str]:
        return {
            t.strip().lower()
            for t in self.authorized_scan_targets.split(",")
            if t.strip()
        }

    @property
    def llm_enabled(self) -> bool:
        if self.llm_provider == "groq":
            return bool(self.groq_api_key)
        if self.llm_provider == "gemini":
            return bool(self.google_api_key)
        return False

    @property
    def rate_limit_override_map(self) -> dict[str, tuple[int, float]]:
        """Parse RATE_LIMIT_OVERRIDES into {source: (requests, seconds)}.

        A malformed entry is skipped rather than raising: a typo in an optional
        tuning variable must not stop the service from starting, and the
        published free-tier default is the safe thing to fall back to.
        """
        out: dict[str, tuple[int, float]] = {}
        for entry in self.rate_limit_overrides.split(","):
            entry = entry.strip()
            if not entry or "=" not in entry or "/" not in entry:
                continue
            source, _, quota = entry.partition("=")
            requests, _, seconds = quota.partition("/")
            try:
                count, window = int(requests), float(seconds)
            except ValueError:
                continue
            name = source.strip().lower()
            # An empty name would create an override keyed on "", which
            # silently matches nothing and hides the typo that produced it.
            if name and count > 0 and window > 0:
                out[name] = (count, window)
        return out


@lru_cache
def get_settings() -> Settings:
    return Settings()
