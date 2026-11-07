# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
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

from collections.abc import Callable
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


def load_x12_code_resolver() -> Callable[..., str | None]:
    """Return a resolver over ``pyx12.error_codes``, or a clear :class:`RuntimeError` if the ``[x12]``
    extra is absent or older than pyx12 4.0.1, which added that module.

    ``resolve(err_cde, prefer_5010=...)`` is pyx12's ``x12_code_for``: the X12 code the 999
    (``True``, IK first) or 997 (``False``, AK first) carries for a pyx12 error name, ``None`` where
    pyx12 maps the name to neither, and a raw X12 number passed through unchanged. With
    ``prefer_5010=False`` it also returns ``None`` where pyx12's table has no AK code for the name,
    rather than ``x12_code_for``'s fallback to a 999 code no 997 carries; pyx12's own 997 writer
    omits those errors by the same table."""
    try:
        import pyx12.error_codes
    except ImportError as exc:  # pragma: no cover - exercised only without the [x12] extra
        raise RuntimeError(
            "strict X12 validation requires pyx12>=4.0.1 from the optional 'x12' extra: "
            "pip install 'messagefoundry[x12]'"
        ) from exc
    table = pyx12.error_codes.ERROR_CODES
    x12_code_for = pyx12.error_codes.x12_code_for

    def resolve(err_cde: str, prefer_5010: bool = True) -> str | None:
        if not prefer_5010:
            spec = table.get(err_cde)
            if spec is not None and spec.ak_code is None:
                return None
        code: str | None = x12_code_for(err_cde, prefer_5010=prefer_5010)
        return code

    return resolve
