"""Tool package.

Importing this package registers every tool. The registry is populated by
import side effect, so a module that is never imported is silently absent from
`run_many`, importing them all here is what prevents that class of bug.
"""
# Registration side effects, order is irrelevant, presence is not.
from threatiq.tools import (
    abuseipdb,  # noqa: F401,E402
    dns_tools,  # noqa: F401,E402
    email_analysis,  # noqa: F401,E402
    http_probe,  # noqa: F401,E402
    lookalike,  # noqa: F401,E402
    urlscan,  # noqa: F401,E402
    virustotal,  # noqa: F401,E402
    vuln_feeds,  # noqa: F401,E402
)
from threatiq.tools.base import ToolContext, registry  # noqa: F401

__all__ = ["ToolContext", "registry"]
