# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Exceptions for the X12 codec.

Kept in their own module (mirroring how :mod:`messagefoundry.parsing.peek` owns ``HL7PeekError``) so
the delimiter / peek / interchange / message modules can raise them without importing each other. All
derive from :class:`ValueError`, so a Router/Handler that already routes ``ValueError`` to the
error/dead-letter path catches them without special-casing X12.
"""

from __future__ import annotations

__all__ = ["X12Error", "X12PeekError", "X12FrameError", "X12ValidationError"]


class X12Error(ValueError):
    """Base class for every X12 codec error."""


class X12PeekError(X12Error):
    """The bytes are not a parseable X12 interchange (no ISA, a truncated/malformed ISA header,
    non-mutually-distinct delimiters) or an X12 field path is malformed. The X12 analog of
    :class:`~messagefoundry.parsing.peek.HL7PeekError` — a Router routes the message to the
    error/dead-letter path rather than guessing."""


class X12FrameError(X12Error):
    """A streaming interchange exceeded its byte cap before the closing ``IEA`` segment — signals the
    transport to drop the connection rather than buffer without bound (the X12 analog of
    :class:`~messagefoundry.transports.framing.FrameError`)."""


class X12ValidationError(X12Error):
    """The opt-in strict validator (``pyx12``, ADR 0012) could not finish a structural validation
    pass over this interchange: at least when the bytes are not a parseable X12 data file, when
    pyx12 has no map that selects it, which a conformant interchange under a guide pyx12 does not
    bundle also meets, and when pyx12 raises partway through a walk, as a non-numeric GE01 makes it
    do. So this does not always mean the interchange is bad.

    A walk failure of a type a sender's bytes cannot raise
    (:func:`~messagefoundry.parsing.x12._deps.is_x12_install_fault`) is a :class:`RuntimeError`
    instead. A Handler's ``except ValueError`` does not catch that, but left uncaught it takes the
    ``internal_error`` policy, whose default, ``CONTINUE``, also dead-letters the row.

    **A damaged install can land here too.** A map or table that still parses but is wrong raises
    an ordinary error, and an index that lost a map's entry reads as having no map, so each is this
    error, which a Handler's ``except ValueError`` would dead-letter. Each refusal logs its exception
    class at WARNING, rate-limited, so a run of one class shows an operator the damage.

    The X12 analog of
    :class:`~messagefoundry.parsing.fhir.errors.FhirValidationError`. A *failed validation* (a pass
    that finishes with violations of the implementation guide) is **not** this — it is reported as
    data on :class:`~messagefoundry.parsing.x12.validate.X12ValidationResult` (``valid=False`` +
    structural :class:`~messagefoundry.parsing.x12.validate.X12SegmentError` items + a 997/999 ack), so
    a Handler can route the *message* to the error path while still emitting the negative ack (the ack
    is ``None`` if pyx12 did not complete it). Its message is **PHI-safe**: it names only the failure
    mode and, where pyx12 raised, that exception's class, never the input bytes, and it chains no
    pyx12 exception."""
