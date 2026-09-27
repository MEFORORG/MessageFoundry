# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The PHI, credential and control-character chain for ``tray.log`` (BACKLOG #2092).

``tray.__main__._setup_logging`` opens a rotating ``tray.log``. Until this module it had a plain
formatter and no filter, and the poller logs with ``exc_info``, so a traceback carrying engine reply
text or a credential would have reached the file verbatim on a first deployment.

The engine's own chain is four ``logging.Filter`` classes in ``messagefoundry.logging_setup``. The
tray cannot import that module: it imports ``messagefoundry.config.tls_policy``, and ADR 0113 section
1 forbids the tray ``config``. So this module composes the same three stdlib-only leaves those
filters call, in the same order:

1. :func:`~messagefoundry.redaction.redact_untrusted` (the engine's ``RedactionFilter``), after the
   traceback is rendered into ``exc_text`` and ``exc_info`` is cleared.
2. :func:`~messagefoundry.secretscrub.scrub_credentials` (``CredentialScrubFilter``).
3. :func:`~messagefoundry.controlchars.scrub_control_chars` (``ControlCharScrubFilter``), last,
   because escaping removes the whitespace the credential patterns end on. A traceback keeps its
   line breaks and every line is indented, as the engine does.

``CredentialQueryScrubFilter`` is left out on purpose. It scrubs OIDC ``code`` and ``state`` from a
request URL's query string, and no tray log line carries a request URL. Its vocabulary is private to
``logging_setup``, and copying it here would make two lists that can drift.

``tests/test_tray_logscrub.py`` pins this composition against the engine chain, so a filter added
there and not here fails a test instead of passing silently.
"""

from __future__ import annotations

import logging

from messagefoundry.controlchars import scrub_control_chars
from messagefoundry.redaction import redact_untrusted
from messagefoundry.secretscrub import scrub_credentials

__all__ = ["TrayLogScrubFilter"]

#: The engine's traceback continuation prefix (``logging_setup._CONTINUATION_PREFIX``). Every line
#: of a traceback is indented with it, so no line can pass for a new record's prefix.
_CONTINUATION_PREFIX = "    | "

# Renders a record's exception to text. ``formatException`` ignores the format string, so one
# shared instance is safe.
_EXC_RENDERER = logging.Formatter()


def _scrub_text(text: str) -> str:
    """Redact PHI, then mask credentials. Control characters are left for the caller."""
    return scrub_credentials(redact_untrusted(text))


def _scrub_block(text: str) -> str:
    """Scrub a multi-line block, keeping its line breaks and indenting every line."""
    return "\n".join(
        _CONTINUATION_PREFIX + scrub_control_chars(line.removeprefix(_CONTINUATION_PREFIX))
        for line in _scrub_text(text).split("\n")
    )


class TrayLogScrubFilter(logging.Filter):
    """Scrub the rendered message, the traceback and ``stack_info`` of every ``tray.log`` record."""

    def filter(self, record: logging.LogRecord) -> bool:
        # Render the traceback first and clear exc_info unconditionally, so no formatter can
        # re-render the raw exception past the scrub (the engine's RedactionFilter does the same).
        if not record.exc_text and record.exc_info:
            record.exc_text = _EXC_RENDERER.formatException(record.exc_info)
        record.exc_info = None
        message = record.getMessage()
        scrubbed = scrub_control_chars(_scrub_text(message))
        if scrubbed != message:
            record.msg = scrubbed
            record.args = ()
        if record.exc_text:
            record.exc_text = _scrub_block(record.exc_text)
        if record.stack_info:
            record.stack_info = _scrub_block(record.stack_info)
        return True
