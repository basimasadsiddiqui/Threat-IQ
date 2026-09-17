"""Run the API inside the console's own process.

Some hosts give you one process and one port. Streamlit Community Cloud is the
case in hand: it runs `streamlit run ui/app.py` and nothing else, so there is
nowhere to put a second container the way Compose does.

The tempting shortcut is to have the console import the pipeline and call it
directly. That is refused here. `ui/app.py` talks to the API over HTTP and
never imports the agent graph, which is what keeps analysis logic out of the
presentation layer; a second in-process code path would fork that behaviour and
the HTTP one would rot, because the deployment everyone actually looks at would
be the other one.

So the API is started on a background thread, bound to loopback, and the
console goes on speaking HTTP to it exactly as it does against Compose. The
same requests, the same auth header, the same error handling. Nothing about the
console changes, and there is only ever one code path to keep working.
"""
from __future__ import annotations

import os
import pathlib
import secrets
import socket
import sys
import threading
import time

import httpx

# streamlit runs ui/app.py as a script, so sys.path[0] is ui/ and the project
# is not importable. The console never needed it; this module does.
ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

DEFAULT_PORT = 8000
STARTUP_TIMEOUT_S = 120.0


def _port_is_free(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            probe.bind(("127.0.0.1", port))
        except OSError:
            return False
    return True


def _pick_port(preferred: int) -> int:
    """The preferred port, or any free one.

    A fixed port is friendlier to read in a log, but a host that already has
    something on 8000 would otherwise fail in a way that looks like the API
    crashed rather than like a collision.
    """
    if _port_is_free(preferred):
        return preferred
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


def _ensure_shared_secret() -> None:
    """Give the embedded API a key, generating one if the host supplied none.

    The API is on loopback, on an unpredictable port, inside this process, so
    it is not reachable from outside and the key defends against nothing an
    attacker can do. It is set anyway because of what the alternative reports:
    with no key the API answers `auth_enabled: false`, and the console renders
    "Authentication disabled. Do not expose this deployment beyond localhost."
    That warning would be prominent, permanent and untrue here, and a console
    that cries wolf in its status block teaches people to skim the block where
    the real warnings also appear.

    Generating rather than suppressing keeps the display honest without
    weakening anything: auth genuinely is on.

    Both names are set because the two halves spell it differently, and a
    deployment that sets only one gets a console that 401s against its own
    backend.
    """
    key = os.environ.get("API_KEY") or os.environ.get("THREATIQ_API_KEY")
    if not key:
        key = secrets.token_urlsafe(32)
    os.environ["API_KEY"] = key
    os.environ["THREATIQ_API_KEY"] = key


def _serve(port: int) -> None:
    import uvicorn

    # Imported here, inside the thread, so that any environment the caller set
    # up is already in place: threatiq.api.main reads Settings at import time,
    # and a key exported afterwards would arrive too late to be seen.
    from threatiq.api.main import app

    config = uvicorn.Config(
        app, host="127.0.0.1", port=port,
        log_level="warning", access_log=False,
    )
    server = uvicorn.Server(config)
    # uvicorn installs signal handlers on startup, which only the main thread
    # may do. Without this the server raises before it ever binds.
    server.install_signal_handlers = lambda: None  # type: ignore[method-assign]
    server.run()


def start_backend(port: int = DEFAULT_PORT,
                  timeout: float = STARTUP_TIMEOUT_S) -> str:
    """Start the API on a daemon thread and return its base URL.

    Blocks until /health answers, because the console's first render queries it
    immediately and a page of connection errors is a poor first impression.
    Raises if it never comes up: failing loudly beats a console that loads and
    then reports every source as unreachable.
    """
    _ensure_shared_secret()
    chosen = _pick_port(port)
    thread = threading.Thread(
        target=_serve, args=(chosen,), name="threatiq-api", daemon=True,
    )
    thread.start()

    base = f"http://127.0.0.1:{chosen}"
    deadline = time.monotonic() + timeout
    last: Exception | None = None
    while time.monotonic() < deadline:
        if not thread.is_alive():
            raise RuntimeError(
                "the embedded ThreatIQ API thread exited during startup")
        try:
            response = httpx.get(f"{base}/health", timeout=5.0)
            if response.status_code == 200:
                return base
        except httpx.HTTPError as exc:
            last = exc
        time.sleep(0.5)

    raise RuntimeError(
        f"the embedded ThreatIQ API did not answer on {base} within "
        f"{timeout:.0f}s ({last})"
    )
