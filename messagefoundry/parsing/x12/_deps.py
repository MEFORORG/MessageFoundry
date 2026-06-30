# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Lazy loader for the optional ``[x12]`` extra (``pyx12``) — the strict X12 validator's only need.

``pyx12`` lives behind the ``messagefoundry[x12]`` optional extra (ADR 0012), so it is imported
**inside** these functions — never at module top. That keeps ``import messagefoundry.parsing.x12``
(the tolerant :class:`~messagefoundry.parsing.x12.peek.X12Peek` / :class:`X12Message` hot path the
console and every Router use) free of the extra: **only** the opt-in strict
:func:`~messagefoundry.parsing.x12.validate.validate` slow path requires ``pyx12``. A missing extra
raises a clear, actionable :class:`RuntimeError` (mirroring :mod:`messagefoundry.parsing.fhir._deps`
and the SQL-Server/Postgres store backends), **distinct** from the :class:`ValueError`-rooted data
errors in :mod:`messagefoundry.parsing.x12.errors` — so a Handler's ``except ValueError`` does **not**
swallow a deploy/config error.

This module imports ``pyx12`` (third-party, not an engine package) and nothing from
``messagefoundry.config``/``pipeline``/``store``/``transports`` — the codec's purity is preserved.
"""

from __future__ import annotations

from typing import Any


def _missing_extra(feature: str) -> RuntimeError:
    return RuntimeError(
        f"{feature} requires the optional 'x12' extra: pip install 'messagefoundry[x12]'"
    )


def load_x12_validator() -> tuple[Any, Any]:
    """Return ``(x12n_document, params_factory)`` from ``pyx12``, or a clear :class:`RuntimeError`
    if the ``[x12]`` extra is absent.

    ``x12n_document(param, src, fd_997, fd_html, fd_xmldoc, fd_json)`` is pyx12's primary validator: it
    walks the interchange against the bundled implementation-guide maps, writes a 997/999
    acknowledgment to ``fd_997`` and structured errors to ``fd_json``, and returns a bool. The maps
    ship inside the ``pyx12`` wheel, so no map path/config is needed."""
    try:
        import pyx12.params
        import pyx12.x12n_document
    except ImportError as exc:  # pragma: no cover - exercised only without the [x12] extra
        raise _missing_extra("strict X12 validation") from exc
    return pyx12.x12n_document.x12n_document, pyx12.params.params
