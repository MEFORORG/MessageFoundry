# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Lazy loader for the optional ``[dicom]`` extra (``pydicom``).

``pydicom`` lives behind the ``messagefoundry[dicom]`` optional extra (ADR 0025 §7), so it is imported
**inside** these functions — never at module top. That keeps ``import messagefoundry.parsing.dicom``
(e.g. a console import for a client-side tag-tree viewer, or the bare structural
:class:`~messagefoundry.parsing.dicom.peek.DicomPeek` dataclass) free of the extra: only the ``parse``
paths require it. A missing extra raises a clear, actionable :class:`RuntimeError` (mirroring
:mod:`messagefoundry.parsing.fhir._deps` and the SQL-Server/Postgres store backends), **distinct** from
the :class:`ValueError`-rooted data errors in :mod:`messagefoundry.parsing.dicom.errors` — so a
Handler's ``except ValueError`` does **not** swallow a deploy/config error.

This module imports ``pydicom`` (third-party, not an engine package) and nothing from
``messagefoundry.config``/``pipeline``/``store``/``transports`` — the codec's purity is preserved.
"""

from __future__ import annotations

import struct
from collections.abc import Callable
from types import ModuleType
from typing import Any

#: The ``pydicom.filereader`` functions ``read_partial`` runs, in this order, before it inflates a
#: Deflated Explicit VR LE Data Set. Two are private; see :func:`load_header_readers`.
_HEADER_READERS = ("read_preamble", "_read_file_meta_info", "_read_command_set_elements")


def _missing_extra(feature: str) -> RuntimeError:
    return RuntimeError(
        f"{feature} requires the optional 'dicom' extra: pip install 'messagefoundry[dicom]'"
    )


def load_dcmread() -> Callable[..., Any]:
    """The ``pydicom.dcmread`` reader, or a clear :class:`RuntimeError` if the ``[dicom]`` extra is
    absent. Callers pass ``stop_before_pixels=True`` so pixel data is never materialised (headers/SR
    only — no ``numpy``, ADR 0025 §1/§9)."""
    try:
        from pydicom import dcmread
    except ImportError as exc:  # pragma: no cover - exercised only without the [dicom] extra
        raise _missing_extra("DICOM parsing") from exc
    return dcmread


def load_header_readers() -> ModuleType:
    """``pydicom.filereader``, checked to still carry the :data:`_HEADER_READERS` the deflate guard
    replays (BACKLOG #1926). A missing extra raises the usual :class:`RuntimeError`. A ``pydicom`` that
    renamed a reader also raises one: the guard must refuse, because ``dcmread`` would still run and
    inflate unbounded."""
    try:
        from pydicom import filereader
    except ImportError as exc:
        # Every parse runs the guard before dcmread, so this is the error a missing extra usually meets.
        raise _missing_extra("DICOM parsing") from exc
    missing = [name for name in _HEADER_READERS if not hasattr(filereader, name)]
    if missing:
        raise RuntimeError(
            f"the installed pydicom has no {', '.join(missing)}, which the DICOM deflate guard "
            "replays to bound dcmread's inflate; refusing to parse DICOM with it"
        )
    return filereader


def header_error_types() -> tuple[type[BaseException], ...]:
    """The exceptions pydicom's header readers raise for a MALFORMED object, and nothing else. The
    deflate guard stands aside only on these, because ``dcmread`` then fails at the same step before
    its inflate (BACKLOG #1926).

    Deliberately narrower than :func:`parse_error_types`. ``AttributeError``, ``KeyError``,
    ``IndexError``, ``TypeError`` and ``ValueError`` are what a pydicom API change raises in the
    replay itself, and standing aside on one of those would let ``dcmread`` inflate unbounded. So
    they propagate, and the guard fails closed. The set was measured, not guessed: 60,000 random
    header mutations on 2026-09-24 raised only ``InvalidDicomError``, ``BytesLengthException``,
    ``NotImplementedError`` (an unknown VR) and ``struct.error``. ``EOFError`` is pydicom's own
    truncation signal."""
    from pydicom.errors import BytesLengthException, InvalidDicomError

    return (InvalidDicomError, BytesLengthException, NotImplementedError, struct.error, EOFError)


def parse_error_types() -> tuple[type[BaseException], ...]:
    """The exception tuple a ``dcmread`` of **untrusted** bytes may raise — wrapped by the codec into a
    PHI-safe :class:`~messagefoundry.parsing.dicom.errors.DicomError` so a malformed object
    dead-letters (``ERROR``) instead of crashing the connection. ``InvalidDicomError`` is *not* a
    ``ValueError`` (it descends straight from ``Exception``), so it must be named explicitly; the
    stdlib members cover the truncation/garbage decode paths. Imported lazily to preserve no-extra
    purity."""
    from pydicom.errors import InvalidDicomError

    return (
        InvalidDicomError,
        ValueError,
        EOFError,
        OSError,
        struct.error,
        AttributeError,
        KeyError,
        IndexError,
    )
