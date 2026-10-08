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
request URL's query string. The tray holds no OIDC credential, and the one library that would log
its request URLs, httpx at INFO, is held at WARNING by ``_setup_logging``. The URL the tray does log
is its own configured ``engine_url``, where ``scrub_credentials`` still masks token-shaped
parameters. The filter's vocabulary is private to ``logging_setup``, and copying it here would make
two lists that can drift.

``tests/test_tray_logscrub.py`` pins this composition against the engine chain, so a filter added
there and not here fails a test instead of passing silently.
"""

from __future__ import annotations

import logging

from messagefoundry.controlchars import scrub_control_chars
from messagefoundry.redaction import prepare_log_record, redact_untrusted
from messagefoundry.secretscrub import scrub_credentials

__all__ = ["TrayLogScrubFilter"]

#: The engine's traceback continuation prefix (``logging_setup._CONTINUATION_PREFIX``). Every line
#: of a traceback is indented with it, so no line can pass for a new record's prefix.
_CONTINUATION_PREFIX = "    | "


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
        try:
            self._scrub(record)
        except Exception as exc:  # a log call must never raise, or kill the poller thread
            # logging does not guard Handler.filter, so a bad %-format or a raising __repr__ would
            # otherwise reach the call site. Fail closed: write a fixed line, never the raw record.
            record.msg = f"[tray log record dropped: {type(exc).__name__} while scrubbing it]"
            record.args = ()
            record.exc_info = None
            record.exc_text = None
            record.stack_info = None
        return True

    @staticmethod
    def _scrub(record: logging.LogRecord) -> None:
        # Render the traceback first and clear exc_info unconditionally, so no formatter can
        # re-render the raw exception past the scrub (the engine's RedactionFilter does the same).
        # A UnicodeError prints from its attributes, never its str() (vault BACKLOG #3185).
        prepare_log_record(record)
        # Always replace msg and args, so the formatter writes the text that was scrubbed rather
        # than rendering the arguments a second time.
        record.msg = scrub_control_chars(_scrub_text(record.getMessage()))
        record.args = ()
        if record.exc_text:
            record.exc_text = _scrub_block(record.exc_text)
        if record.stack_info:
            record.stack_info = _scrub_block(record.stack_info)
