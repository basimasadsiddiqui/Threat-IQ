"""Observability wiring.

LangSmith covers the agent/LLM layer; OpenTelemetry covers everything else
(HTTP in, HTTP out, SQL). Both are opt-in and failing to configure either must
never prevent the service from starting.
"""
from __future__ import annotations

import logging
import os
import sys

from threatiq.config import Settings

log = logging.getLogger(__name__)


def setup_logging(settings: Settings) -> None:
    level = getattr(logging, settings.log_level.upper(), logging.INFO)
    root = logging.getLogger()
    root.setLevel(level)
    if not root.handlers:
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(logging.Formatter(
            "%(asctime)s %(levelname)-7s %(name)-28s %(message)s",
            datefmt="%H:%M:%S",
        ))
        root.addHandler(handler)
    # These libraries log every request at INFO; that drowns our own output.
    for noisy in ("httpx", "httpcore", "urllib3", "asyncio"):
        logging.getLogger(noisy).setLevel(logging.WARNING)


def setup_langsmith(settings: Settings) -> bool:
    """LangSmith reads its config from the environment, so export it there."""
    if not (settings.langchain_tracing_v2 and settings.langchain_api_key):
        return False
    os.environ["LANGCHAIN_TRACING_V2"] = "true"
    os.environ["LANGCHAIN_API_KEY"] = settings.langchain_api_key
    os.environ["LANGCHAIN_PROJECT"] = settings.langchain_project
    log.info("LangSmith tracing enabled for project %r", settings.langchain_project)
    return True


def setup_opentelemetry(settings: Settings, app: object | None = None) -> bool:
    if not settings.otel_enabled or not settings.otel_exporter_otlp_endpoint:
        return False
    try:
        from opentelemetry import trace
        from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import (
            OTLPSpanExporter,
        )
        from opentelemetry.sdk.resources import Resource
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor

        provider = TracerProvider(resource=Resource.create({
            "service.name": settings.app_name.lower(),
            "deployment.environment": settings.environment,
        }))
        provider.add_span_processor(BatchSpanProcessor(
            OTLPSpanExporter(endpoint=settings.otel_exporter_otlp_endpoint)
        ))
        trace.set_tracer_provider(provider)

        from opentelemetry.instrumentation.httpx import HTTPXClientInstrumentor
        HTTPXClientInstrumentor().instrument()

        if app is not None:
            from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
            FastAPIInstrumentor.instrument_app(app)

        log.info("OpenTelemetry exporting to %s",
                 settings.otel_exporter_otlp_endpoint)
        return True
    except ImportError as exc:
        log.warning("OpenTelemetry packages missing (%s); tracing disabled", exc)
    except Exception as exc:
        log.warning("OpenTelemetry setup failed: %s", exc)
    return False
