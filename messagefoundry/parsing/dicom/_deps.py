# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
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
from typing import Any, Callable


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
