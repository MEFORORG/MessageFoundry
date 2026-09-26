# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The inbound payload-format enum, in a module that imports nothing from the engine (BACKLOG #1596).

``parsing/sniff.py`` needs :class:`ContentType`, and ``parsing/`` is the one engine package a client
may import (CLAUDE.md section 4). It used to take the enum from ``config.models``, which loaded the
``config`` package, ``tls_policy`` and pydantic behind it, so a client importing ``parsing`` got the
configuration layer too. The enum lives here now, stdlib only, and ``config.models`` re-exports it,
so ``from messagefoundry.config.models import ContentType`` still names this same class.
"""

from __future__ import annotations

from enum import Enum

__all__ = ["ContentType"]


class ContentType(str, Enum):  # noqa: UP042
    """The payload format of an inbound connection (ADR 0004 — payload-agnostic ingress).

    ``HL7V2`` (the default, so every existing config is unchanged) gets the full HL7 peek / optional
    strict-validate / HL7-ACK ingress path and is routed to Routers/Handlers as a mutable
    :class:`~messagefoundry.parsing.message.Message`. Any other value **skips** HL7 parsing/validation/
    ACK: the decoded body is committed verbatim and routed as a
    :class:`~messagefoundry.parsing.message.RawMessage` (``.raw`` / ``.text`` / ``.json()``)."""

    HL7V2 = "hl7v2"
    JSON = "json"
    XML = "xml"
    TEXT = "text"
    X12 = "x12"  # ASC X12 EDI, relayed opaquely (no structured parse) — routes as RawMessage
    FHIR = (
        "fhir"  # HL7 FHIR JSON — routed as RawMessage; parsed on demand via parsing/fhir (ADR 0022)
    )
    BINARY = "binary"  # opaque byte payload — base64-carried over the str/TEXT substrate (ADR 0028)
    DICOM = "dicom"  # DICOM Part-10 object (binary) — base64-carried; parsed on demand via parsing/dicom (ADR 0025)

    @property
    def is_binary(self) -> bool:
        """Whether an inbound of this type carries **raw bytes** that must be base64-carried at the
        source boundary (ADR 0028) rather than decoded as text — a ``NUL``/non-UTF-8 body would be
        rejected (Postgres) or silently truncated (SQLite/SQL Server) by the ``str``/TEXT store.
        Byte-oriented codecs (DICOM, …) join this set; everything else routes as decoded text."""
        return self in _BINARY_CONTENT_TYPES


#: Content types whose inbound bodies are raw bytes, carried as base64 per ADR 0028. Kept as a set so
#: a byte-oriented codec (e.g. DICOM) opts in by adding its member — see :attr:`ContentType.is_binary`.
_BINARY_CONTENT_TYPES: frozenset[ContentType] = frozenset({ContentType.BINARY, ContentType.DICOM})
