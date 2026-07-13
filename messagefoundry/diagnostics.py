# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Diagnostic helpers — the one output-independent side effect the transform vocabulary allows.

``log_note`` / ``checkpoint`` (Corepoint ``EnvLogText`` / ``MsgLog``) write a troubleshooting line to
the module logger — the analyst's equivalent of a print-debug. They live **separately** from
:mod:`messagefoundry.actions` precisely because that module promises purity/no-I/O and logging is a side
effect. It is nonetheless a *safe* one: a re-run yields an identical message (the log line does not
affect the transform's output), so the at-least-once reliability invariant is untouched — unlike a
``db_lookup`` this changes nothing the pipeline reads.

PHI (CLAUDE.md §9): both emit only at ``DEBUG`` and **redact by default** — ``log_note`` replaces every
interpolated value with :data:`TRACE_REDACTED`, and ``checkpoint`` reports only structural segment ids,
never field values. Raw values appear only when the process-wide dev reveal flag :data:`_reveal` is set
(the diagnostic analogue of ``dryrun --show-phi``); it defaults off and must never be enabled outside a
dev environment (ADR 0106 §6; env-clamping is a wiring concern for the caller).
"""

from __future__ import annotations

import logging

from messagefoundry.parsing.message import Message

__all__ = ["log_note", "checkpoint"]

_logger = logging.getLogger("messagefoundry.diagnostics")

#: Substituted for every ``log_note`` operand while redaction is on (the default).
TRACE_REDACTED = "‹redacted›"  # ‹redacted›

#: Dev-only reveal switch. OFF by default; only a dev tool should ever flip it — never staging/prod.
_reveal = False


def log_note(template: str, /, *values: object) -> None:
    """Emit a diagnostic line to the ``messagefoundry.diagnostics`` DEBUG log (Corepoint ``EnvLogText``).

    ``template`` is a :meth:`str.format` template whose ``{}`` slots are filled from ``values`` (typically
    ``msg.field(...)`` reads). **Every value is redacted by default** — replaced with
    :data:`TRACE_REDACTED` — so no PHI reaches the log unless :data:`_reveal` is explicitly set. Never
    raises: a diagnostic must not fail a transform (a malformed template is swallowed, not propagated)."""
    shown: tuple[object, ...] = values if _reveal else tuple(TRACE_REDACTED for _ in values)
    try:
        _logger.debug(template.format(*shown))
    except (IndexError, KeyError, ValueError):
        _logger.debug("log_note: could not format %r with %d value(s)", template, len(values))


def checkpoint(msg: Message, label: str = "") -> None:
    """Log a redacted structural snapshot of ``msg`` at DEBUG (Corepoint ``MsgLog``).

    Records the ordered **segment ids** present (structure, not content) plus an optional ``label`` — for
    troubleshooting parse/mapping issues without duplicating PHI into the general log (the full raw
    message already lives, secured, in the store). Emits no field values; a segment id is the first three
    characters of a line (HL7 §2.5), never PHI."""
    seg_ids = [line[:3] for line in msg.encode().split("\r") if line]
    _logger.debug("checkpoint %s: %d segments %s", label, len(seg_ids), seg_ids)
