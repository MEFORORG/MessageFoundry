"""messagefoundry — an open-source integration engine for healthcare.

The engine is an importable library. The PySide6 console (and any other client)
drives it over a localhost HTTP + WebSocket API, so the same code path serves
in-process, local-daemon, and remote deployments.

Config modules define the message graph against this surface::

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
from messagefoundry.config.active_environment import current_environment
from messagefoundry.config.reference import reference
from messagefoundry.config.state import state_get
from messagefoundry.config.wiring import (
    CodeSet,
    Database,
    DatabasePoll,
    DatabaseRef,
    File,
    FileRef,
    MLLP,
    Reference,
    Rest,
    Soap,
    Tcp,
    Send,
    SetState,
    code_set,
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
    "SetState",
    "state_get",
    "MLLP",
    "Tcp",
    "File",
    "Rest",
    "Database",
    "DatabasePoll",
    "Soap",
    "env",
    "code_set",
    "CodeSet",
    "reference",
    "Reference",
    "FileRef",
    "DatabaseRef",
    "current_environment",
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
