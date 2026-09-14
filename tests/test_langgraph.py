"""LangGraph backend tests.

The orchestration graph has two interchangeable executors: the real LangGraph
StateGraph, and a hand-rolled fallback used when LangGraph is not installed.
Two executors mean two chances to drift, and the fallback is chosen silently,
so a broken StateGraph would never announce itself: the app would just quietly
run the other path. These tests exist to make that impossible.
"""
from __future__ import annotations

import pytest

pytest.importorskip("langgraph", reason="LangGraph is an optional dependency")

from threatiq.schemas import InvestigationRequest  # noqa: E402

PHISHING_EMAIL = """From: "Microsoft" <security@micros0ft-alerts.tk>
Reply-To: recovery@mailbox-secure.top
Authentication-Results: mx.corp.com; spf=fail dmarc=fail
Subject: Urgent: verify your account

Verify now: https://micros0ft-login.tk/verify
Also patch CVE-2024-3400 on the gateway.
"""


def test_stategraph_compiles_with_every_agent():
    from threatiq.agents.graph import PIPELINE, SPECIALISTS, build_langgraph

    compiled = build_langgraph()
    assert compiled is not None, "the LangGraph StateGraph failed to compile"

    names = set(compiled.get_graph().nodes)
    expected = {"orchestrator"} | set(SPECIALISTS) | {n for n, _ in PIPELINE}
    missing = expected - names
    assert not missing, f"nodes missing from the compiled graph: {missing}"


def test_langgraph_is_preferred_when_available():
    """If LangGraph is installed it must actually be used. Falling back while
    the dependency is present would mean a compile error nobody ever sees."""
    import threatiq.agents.graph as graph_module

    graph_module._compiled = None
    graph_module._backend = "unknown"
    try:
        _, backend = graph_module.get_graph()
        assert backend == "langgraph"
    finally:
        graph_module._compiled = None
        graph_module._backend = "unknown"


@pytest.mark.asyncio
@pytest.mark.parametrize("submitted,criticality", [
    (PHISHING_EMAIL, "critical"),
    ("CVE-2024-3400", "critical"),
    ("wikipedia.org", "medium"),
])
async def test_both_executors_agree(stub_network, submitted, criticality):
    """Differential test: the two executors must produce the same verdict.

    This is what proves the LangGraph wiring is real rather than decorative.
    The parallel fan-out, the state reducers and the conditional routing all
    have to behave the same way under LangGraph's state management as they do
    under the straight-line fallback.
    """
    import threatiq.agents.graph as graph_module
    from threatiq.service import investigate

    async def run_with(force_fallback: bool):
        graph_module._compiled = None
        graph_module._backend = "unknown"
        real_builder = graph_module.build_langgraph
        if force_fallback:
            graph_module.build_langgraph = lambda: None
        try:
            report = await investigate(InvestigationRequest(
                input=submitted, asset_criticality=criticality))
            return report, graph_module._backend
        finally:
            graph_module.build_langgraph = real_builder
            graph_module._compiled = None
            graph_module._backend = "unknown"

    via_graph, backend_a = await run_with(force_fallback=False)
    via_fallback, backend_b = await run_with(force_fallback=True)

    assert backend_a == "langgraph" and backend_b == "fallback", (
        "the test did not exercise both executors")

    assert via_graph.risk.score == via_fallback.risk.score
    assert via_graph.risk.severity == via_fallback.risk.severity
    assert len(via_graph.findings) == len(via_fallback.findings)
    assert ({a.agent for a in via_graph.actions}
            == {a.agent for a in via_fallback.actions})


@pytest.mark.asyncio
async def test_parallel_specialists_all_contribute(stub_network):
    """The fan-out is conditional and parallel. If LangGraph dropped a branch,
    the evidence from that specialist would simply be absent."""
    import threatiq.agents.graph as graph_module
    from threatiq.service import investigate

    graph_module._compiled = None
    graph_module._backend = "unknown"
    try:
        report = await investigate(InvestigationRequest(
            input=PHISHING_EMAIL, asset_criticality="critical"))
        assert graph_module._backend == "langgraph"
    finally:
        graph_module._compiled = None
        graph_module._backend = "unknown"

    agents = {a.agent for a in report.actions}
    # Both specialists the orchestrator schedules for an email, plus the whole
    # downstream pipeline, must have recorded an action.
    assert {"phishing", "threat_intel", "vulnerability"} <= agents
    assert {"correlation", "risk", "compliance", "remediation", "report"} <= agents


# ------------------------------------------------------- LangChain / LangSmith

def test_llm_uses_a_langchain_runnable_when_the_provider_is_installed():
    """LangSmith traces LangChain runnables. The LLM layer falls back to raw
    httpx when a provider package is missing, and those calls are invisible to
    LangSmith, so which path is taken decides whether LLM tracing works at all.
    """
    pytest.importorskip("langchain_groq")

    from threatiq.config import Settings
    from threatiq.llm import LLMClient

    client = LLMClient(Settings(llm_provider="groq",
                                groq_api_key="gsk_construction_test",
                                groq_model="llama-3.3-70b-versatile"))
    assert client.enabled
    model = client._try_langchain()
    assert model is not None, "provider installed but the LangChain path declined"
    assert hasattr(model, "ainvoke"), "not a LangChain runnable, so untraceable"


@pytest.mark.asyncio
async def test_llm_returns_none_without_a_key_rather_than_raising():
    """Every deterministic stage has to keep working with no model at all."""
    from threatiq.config import Settings
    from threatiq.llm import LLMClient

    client = LLMClient(Settings(llm_provider="groq", groq_api_key=""))
    assert client.enabled is False
    assert await client.complete("anything") is None


def test_langsmith_exports_env_only_when_configured(monkeypatch):
    """LangGraph and LangChain read tracing config from the environment, so
    setup_langsmith has to actually export it, and must not export anything
    when tracing is off."""
    from threatiq.config import Settings
    from threatiq.telemetry import setup_langsmith

    for key in ("LANGCHAIN_TRACING_V2", "LANGCHAIN_API_KEY", "LANGCHAIN_PROJECT"):
        monkeypatch.delenv(key, raising=False)

    assert setup_langsmith(
        Settings(langchain_tracing_v2=False, langchain_api_key="")) is False
    import os
    assert os.environ.get("LANGCHAIN_TRACING_V2") is None

    assert setup_langsmith(Settings(
        langchain_tracing_v2=True, langchain_api_key="ls_test",
        langchain_project="threatiq-test")) is True
    assert os.environ["LANGCHAIN_TRACING_V2"] == "true"
    assert os.environ["LANGCHAIN_API_KEY"] == "ls_test"
    assert os.environ["LANGCHAIN_PROJECT"] == "threatiq-test"


def test_pinned_versions_match_what_is_installed():
    """The pins were a 0.x series that had never been executed here, while the
    differential test ran against 1.x. Shipping pins nobody has run is how a
    green test suite ends up proving nothing about the artefact."""
    import importlib.metadata as md
    import re
    from pathlib import Path

    text = (Path(__file__).resolve().parents[1] / "requirements.txt").read_text()
    pins = dict(re.findall(r"^([A-Za-z0-9_.\-]+)==([^\s#]+)", text, re.M))

    for package in ("langgraph", "langchain-core", "langsmith"):
        try:
            installed = md.version(package)
        except md.PackageNotFoundError:
            pytest.skip(f"{package} not installed in this environment")
        assert pins.get(package) == installed, (
            f"{package} pinned at {pins.get(package)} but verified against "
            f"{installed}")
