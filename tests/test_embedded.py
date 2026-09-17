"""The single-process arrangement, for hosts that give you one process.

Streamlit Community Cloud runs `streamlit run ui/app.py` and nothing else, so
the API has to come up inside the console's own process. What is asserted here
is mostly that the console cannot tell the difference: it keeps speaking HTTP,
against a real socket, with the same auth header, so there is one code path to
keep working rather than two.
"""
from __future__ import annotations

import socket

import pytest

from ui import embedded

# --------------------------------------------------------------------- ports

def test_the_preferred_port_is_used_when_free():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        free = int(probe.getsockname()[1])
    # The probe socket is closed, so the port is genuinely available again.
    assert embedded._pick_port(free) == free


def test_a_taken_port_falls_back_to_a_free_one():
    """A host with something already on 8000 would otherwise fail in a way that
    reads as the API crashing rather than as a collision."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as taken:
        taken.bind(("127.0.0.1", 0))
        taken.listen(1)
        busy = int(taken.getsockname()[1])

        chosen = embedded._pick_port(busy)
        assert chosen != busy
        assert embedded._port_is_free(chosen)


def test_port_is_free_reports_a_listening_socket_as_taken():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as taken:
        taken.bind(("127.0.0.1", 0))
        taken.listen(1)
        assert not embedded._port_is_free(int(taken.getsockname()[1]))


# ------------------------------------------------------------- shared secret

def test_a_secret_is_generated_when_the_host_supplied_none(monkeypatch):
    """Not because the key defends anything here, the API is on loopback in
    this process, but because without one the console renders a prominent,
    permanent "Authentication disabled, do not expose this deployment" warning
    that is untrue, and a status block that cries wolf gets skimmed."""
    monkeypatch.delenv("API_KEY", raising=False)
    monkeypatch.delenv("THREATIQ_API_KEY", raising=False)

    embedded._ensure_shared_secret()

    import os
    assert len(os.environ["API_KEY"]) >= 32
    assert os.environ["THREATIQ_API_KEY"] == os.environ["API_KEY"]


def test_both_halves_end_up_with_the_same_secret(monkeypatch):
    """The API reads API_KEY and the console reads THREATIQ_API_KEY. A
    deployment that sets only one gets a console that 401s against its own
    backend."""
    monkeypatch.setenv("API_KEY", "supplied-by-the-host")
    monkeypatch.delenv("THREATIQ_API_KEY", raising=False)

    embedded._ensure_shared_secret()

    import os
    assert os.environ["API_KEY"] == "supplied-by-the-host"
    assert os.environ["THREATIQ_API_KEY"] == "supplied-by-the-host"


def test_a_supplied_secret_is_never_replaced(monkeypatch):
    monkeypatch.delenv("API_KEY", raising=False)
    monkeypatch.setenv("THREATIQ_API_KEY", "set-by-the-operator")

    embedded._ensure_shared_secret()

    import os
    assert os.environ["API_KEY"] == "set-by-the-operator"
    assert os.environ["THREATIQ_API_KEY"] == "set-by-the-operator"


def test_generated_secrets_differ_between_deployments(monkeypatch):
    import os

    seen = set()
    for _ in range(3):
        monkeypatch.delenv("API_KEY", raising=False)
        monkeypatch.delenv("THREATIQ_API_KEY", raising=False)
        embedded._ensure_shared_secret()
        seen.add(os.environ["API_KEY"])
    assert len(seen) == 3, "the generated secret is not random"


# ------------------------------------------------------------------- startup

def test_startup_failure_is_raised_not_swallowed(monkeypatch):
    """A console that loads and then reports every source as unreachable is a
    miserable thing to debug. Fail loudly instead."""
    def never_serves(port: int) -> None:
        return None          # the thread exits immediately

    monkeypatch.setattr(embedded, "_serve", never_serves)
    with pytest.raises(RuntimeError, match="exited during startup"):
        embedded.start_backend(timeout=5.0)


def test_the_api_really_answers_over_http():
    """The whole point: a real socket, so the console's HTTP client, auth
    header and error handling are the same ones the Compose deployment uses."""
    import httpx

    base = embedded.start_backend(timeout=90.0)
    response = httpx.get(f"{base}/health", timeout=15.0)
    assert response.status_code == 200
    assert response.json()["status"] == "ok"
    assert base.startswith("http://127.0.0.1:"), "must not bind a public address"


def test_embedded_is_importable_the_way_streamlit_launches_the_app():
    """`streamlit run ui/app.py` puts ui/ on sys.path, NOT the repo root.

    So the sibling module is plain `embedded`, and `ui.embedded` does not
    resolve. Running through `python -m streamlit` also puts the working
    directory on sys.path, which makes the package path work and hides the
    difference. That is the gap this shipped through: every local check used
    `-m`, and the deployed host does not.

    A subprocess with a hand-built sys.path is the only honest way to assert
    it, since this test session already has the repo root importable.
    """
    import subprocess
    import sys
    from pathlib import Path

    ui_dir = Path(__file__).resolve().parents[1] / "ui"
    # Exactly what streamlit arranges: the script's directory, and no repo root.
    code = (
        f"import sys; sys.path.insert(0, {str(ui_dir)!r})\n"
        "from embedded import start_backend\n"
        "print('ok')\n"
    )
    result = subprocess.run(
        [sys.executable, "-c", code],
        capture_output=True, text=True, cwd="/", timeout=120,
    )
    assert result.returncode == 0, (
        f"embedded.py is not importable as streamlit imports it:\n"
        f"{result.stderr[-1500:]}"
    )
    assert "ok" in result.stdout


def test_the_app_resolves_its_backend_import_either_way():
    """The console must start its backend under both launch styles."""
    import subprocess
    import sys
    from pathlib import Path

    root = Path(__file__).resolve().parents[1]
    for path_entry, label in ((root / "ui", "streamlit run"), (root, "python -m")):
        code = (
            f"import sys; sys.path.insert(0, {str(path_entry)!r})\n"
            "try:\n"
            "    from ui.embedded import start_backend\n"
            "except ModuleNotFoundError:\n"
            "    from embedded import start_backend\n"
            "print('ok')\n"
        )
        result = subprocess.run(
            [sys.executable, "-c", code],
            capture_output=True, text=True, cwd="/", timeout=120,
        )
        assert result.returncode == 0, (
            f"the {label} launch style cannot import the backend:\n"
            f"{result.stderr[-1500:]}"
        )
