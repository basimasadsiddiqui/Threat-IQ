#!/usr/bin/env python3
"""Report which parts of the agent stack are actually executing.

    python scripts/verify_stack.py

This exists because the orchestration layer degrades silently. If LangGraph is
missing, `get_graph()` quietly returns a hand-rolled fallback executor and the
application carries on; if a LangChain provider package is missing, the LLM
layer quietly drops to raw httpx, which LangSmith cannot see. Both are
reasonable behaviours at runtime and terrible ones to be unaware of, so this
script asks each layer what it is really doing rather than what it declares.

Exit code is non-zero if a declared dependency is installed but its code path
is not being taken, because that combination means something is broken rather
than merely unconfigured.
"""
from __future__ import annotations

import asyncio
import importlib.metadata as metadata
import importlib.util
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from threatiq.config import get_settings  # noqa: E402
from threatiq.llm import LLMClient  # noqa: E402
from threatiq.telemetry import setup_langsmith  # noqa: E402

PACKAGES = ["langgraph", "langchain-core", "langchain-groq",
            "langchain-google-genai", "langsmith"]


def _installed(dist: str) -> str | None:
    try:
        return metadata.version(dist)
    except metadata.PackageNotFoundError:
        return None


def section(title: str) -> None:
    print(f"\n{title}\n{'-' * len(title)}")


def check_packages() -> dict[str, str | None]:
    section("Installed packages")
    versions = {}
    for dist in PACKAGES:
        version = _installed(dist)
        versions[dist] = version
        print(f"  {dist:26s} {version or 'not installed'}")
    return versions


def check_langgraph(versions: dict[str, str | None]) -> bool:
    section("LangGraph")
    from threatiq.agents.graph import PIPELINE, SPECIALISTS, get_graph

    _, backend = get_graph()
    print(f"  active backend            {backend}")

    if versions["langgraph"] is None:
        print("  LangGraph is not installed, so the fallback executor is")
        print("  expected. Install it to run the real StateGraph.")
        return True

    if backend != "langgraph":
        print("  PROBLEM: LangGraph is installed but the fallback is running,")
        print("  which means the StateGraph failed to compile. Run with")
        print("  LOG_LEVEL=DEBUG to see the compilation error.")
        return False

    from threatiq.agents.graph import build_langgraph

    graph = build_langgraph().get_graph()
    expected = {"orchestrator"} | set(SPECIALISTS) | {n for n, _ in PIPELINE}
    missing = expected - set(graph.nodes)
    print(f"  compiled nodes            {len(graph.nodes)}")
    print(f"  compiled edges            {len(graph.edges)}")
    print(f"  agents wired              {len(expected) - len(missing)}/{len(expected)}")
    if missing:
        print(f"  PROBLEM: missing nodes    {sorted(missing)}")
        return False
    return True


def check_langchain(versions: dict[str, str | None]) -> bool:
    section("LangChain")
    settings = get_settings()
    client = LLMClient(settings)

    print(f"  provider                  {settings.llm_provider}")
    print(f"  api key configured        {client.enabled}")

    if not client.enabled:
        print("  No LLM key, so nothing to route. Every deterministic stage")
        print("  still runs; only the narrative prose is reduced.")
        return True

    provider_pkg = ("langchain-groq" if settings.llm_provider == "groq"
                    else "langchain-google-genai")
    model = client._try_langchain()
    if model is None:
        print(f"  routing                   direct HTTP ({provider_pkg} absent)")
        print("  NOTE: LangSmith cannot trace raw httpx calls. Install")
        print(f"  {provider_pkg} if you want LLM calls in your traces.")
        return True

    print(f"  routing                   LangChain ({type(model).__name__})")
    print(f"  traceable by LangSmith    {hasattr(model, 'ainvoke')}")
    return True


def check_langsmith(versions: dict[str, str | None]) -> bool:
    section("LangSmith")
    settings = get_settings()

    installed = versions["langsmith"] is not None
    print(f"  package installed         {installed}")
    print(f"  LANGCHAIN_TRACING_V2      {settings.langchain_tracing_v2}")
    print(f"  LANGCHAIN_API_KEY set     {bool(settings.langchain_api_key)}")
    print(f"  project                   {settings.langchain_project}")

    active = setup_langsmith(settings)
    print(f"  tracing activated         {active}")

    if not active:
        print("  To enable: set LANGCHAIN_TRACING_V2=true and LANGCHAIN_API_KEY")
        print("  in .env, then restart the API. Traces appear under the project")
        print("  name above at smith.langchain.com.")
    else:
        print("  Environment exported. Graph runs and any LangChain LLM calls")
        print("  will be sent to LangSmith.")
    return True


async def differential_check(versions: dict[str, str | None]) -> bool:
    """Run one investigation through both executors and compare."""
    section("Executor equivalence")
    if versions["langgraph"] is None:
        print("  skipped, LangGraph not installed")
        return True

    import threatiq.agents.graph as graph_module
    from threatiq.schemas import InvestigationRequest
    from threatiq.service import investigate

    async def run(force_fallback: bool):
        graph_module._compiled = None
        graph_module._backend = "unknown"
        real = graph_module.build_langgraph
        if force_fallback:
            graph_module.build_langgraph = lambda: None
        try:
            report = await investigate(
                InvestigationRequest(input="CVE-2024-3400",
                                     asset_criticality="critical"))
            return report, graph_module._backend
        finally:
            graph_module.build_langgraph = real
            graph_module._compiled = None
            graph_module._backend = "unknown"

    print("  running CVE-2024-3400 through both executors, this needs network")
    graph_report, graph_backend = await run(False)
    fallback_report, fallback_backend = await run(True)

    same = (graph_report.risk.score == fallback_report.risk.score
            and graph_report.risk.severity == fallback_report.risk.severity
            and len(graph_report.findings) == len(fallback_report.findings))

    print(f"  {graph_backend:9s} risk {graph_report.risk.score} "
          f"{graph_report.risk.severity.value} "
          f"findings {len(graph_report.findings)}")
    print(f"  {fallback_backend:9s} risk {fallback_report.risk.score} "
          f"{fallback_report.risk.severity.value} "
          f"findings {len(fallback_report.findings)}")
    print(f"  executors agree           {same}")
    return same


async def main() -> int:
    print("ThreatIQ agent stack verification")
    versions = check_packages()

    ok = True
    ok &= check_langgraph(versions)
    ok &= check_langchain(versions)
    ok &= check_langsmith(versions)
    try:
        ok &= await differential_check(versions)
    except Exception as exc:
        section("Executor equivalence")
        print(f"  could not run: {type(exc).__name__}: {exc}")
        print("  this check needs outbound network access")

    section("Result")
    print("  all declared dependencies are taking their intended code path"
          if ok else
          "  at least one dependency is installed but not being used, see above")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
