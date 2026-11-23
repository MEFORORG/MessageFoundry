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

import logging
import threading
import time
from collections.abc import Callable
from importlib.resources import files
from typing import TYPE_CHECKING, Any

from messagefoundry._vendor.defusedxml.ElementTree import ParseError, parse

if TYPE_CHECKING:
    from importlib.resources.abc import Traversable

_log = logging.getLogger(__name__)
_MAP_IDS_LOCK = threading.Lock()
_MAP_IDS_RETRY_SECONDS = 60.0
_map_ids: frozenset[str] = frozenset()
_map_ids_retry_at = 0.0


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


def _read_map_segment_ids(map_dir: Traversable) -> frozenset[str]:
    """The ``xid`` of every ``<segment>`` in the maps that ``maps.xml`` under ``map_dir`` lists.

    pyx12 selects its maps from that index, so a bundled file it omits (``comp_test.xml``, the only
    source of ``TST`` and ``UNU``) adds no id. All or nothing: an index or listed map that cannot be
    read or parsed, or a set with no id, gives the empty set, so a caller keeps no id rather than
    trusting the shape alone."""
    ids: set[str] = set()
    try:
        with map_dir.joinpath("maps.xml").open("rb") as fd:
            map_files = {name for m in parse(fd).iter("map") if (name := (m.text or "").strip())}
        for map_file in map_files:
            with map_dir.joinpath(map_file).open("rb") as fd:
                ids.update(xid for seg in parse(fd).iter("segment") if (xid := seg.get("xid")))
    # ValueError covers defusedxml's refusals and a multi-byte encoding declaration; LookupError an
    # unknown one.
    except (OSError, ParseError, ValueError, LookupError) as exc:
        _log.warning(
            "pyx12's maps could not be read (%s); X12 errors will carry no segment id",
            type(exc).__name__,
        )
        return frozenset()
    if not ids:
        _log.warning("pyx12's maps define no segment; X12 errors will carry no segment id")
    return frozenset(ids)


def load_x12_map_segment_ids() -> frozenset[str]:
    """Every segment id the maps in pyx12's bundled index define, read on first use.

    ``validate()`` passes pyx12 no map path, so pyx12 selects from this same index. The read takes
    a noticeable fraction of a second, so it runs only when a violation has an id-shaped value to
    check, and the lock keeps threads that miss together to one read. A good read is kept for the
    process. An empty one is not, so a passing fault cannot remove every id until a restart; it is
    retried at most once per :data:`_MAP_IDS_RETRY_SECONDS`, and until then no id is kept."""
    global _map_ids, _map_ids_retry_at
    if _map_ids:
        return _map_ids
    with _MAP_IDS_LOCK:
        if not _map_ids and time.monotonic() >= _map_ids_retry_at:
            _map_ids = _read_map_segment_ids(files("pyx12").joinpath("map"))
            if not _map_ids:
                _map_ids_retry_at = time.monotonic() + _MAP_IDS_RETRY_SECONDS
        return _map_ids


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
            "strict X12 validation requires pyx12>=4.1.0 from the optional 'x12' extra: "
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
