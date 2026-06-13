"""messagefoundry — a lightweight, open-source HL7 v2 integration engine.

The engine is an importable library. The PySide6 console (and any other client)
drives it over a localhost HTTP + WebSocket API, so the same code path serves
in-process, local-daemon, and remote deployments.

Config modules author the message graph code-first against this surface::

    from messagefoundry import inbound, outbound, router, handler, Send, MLLP, File, Message
"""

from messagefoundry.config.models import (
    AckMode,
    BuildupThreshold,
    ContentType,
    InternalErrorPolicy,
    OrderingMode,
    RetryPolicy,
)
from messagefoundry.config.wiring import (
    Database,
    File,
    MLLP,
    Rest,
    Soap,
    Send,
    env,
    handler,
    inbound,
    outbound,
    router,
)
from messagefoundry.parsing.message import Message, RawMessage

__version__ = "0.0.1"

__all__ = [
    "Message",
    "RawMessage",
    "Send",
    "MLLP",
    "File",
    "Rest",
    "Database",
    "Soap",
    "env",
    "AckMode",
    "RetryPolicy",
    "OrderingMode",
    "InternalErrorPolicy",
    "BuildupThreshold",
    "ContentType",
    "inbound",
    "outbound",
    "router",
    "handler",
    "__version__",
]
