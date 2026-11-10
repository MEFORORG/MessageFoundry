# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Message-content matching (ADR 0046, BACKLOG #51) — the pure, decrypt-in-memory predicate.

``messages.raw`` / ``summary`` are AES-GCM-encrypted at rest (``store/crypto.py``), so a plain SQL
``LIKE`` is impossible while the cipher is on: the on-disk bytes are per-row random-nonced ciphertext.
The shippable first slice (ADR 0046 D1) is **scan-and-decrypt-per-row** — pre-filter on the indexed
metadata, then decrypt each candidate body and match the needle **in memory** here.

This module is the matcher only — **no cipher, no I/O, no DB** (it takes already-decrypted plaintext),
so it carries no PHI-at-rest material and stays trivially testable and backend-agnostic. Each store
backend feeds it the decrypted ``raw``/``summary`` for one candidate row; it returns whether the row
matches and (because matching may parse HL7) is run **off the event loop** by the backend.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from enum import Enum
from typing import Any

from messagefoundry.parsing.peek import HL7PeekError, Peek, parse_path

# Hard caps (ADR 0046 D1 §3 — the non-negotiable cost ceiling). ``DEFAULT_SCAN_LIMIT`` bounds how many
# candidate rows are decrypted before the scan stops and reports ``truncated``; ``MAX_SCAN_LIMIT`` is
# the upper bound an operator may request (mirrors ``/messages`` ``le=500`` for the result cap, but the
# scan ceiling is larger because most candidates won't match). A search that hits the scan cap degrades
# to "narrow your filters", never a full-store decrypt.
DEFAULT_SCAN_LIMIT = 2_000
MAX_SCAN_LIMIT = 10_000


class SearchTarget(str, Enum):  # noqa: UP042
    """Which decrypted column(s) a raw-substring needle is tested against."""

    RAW = "raw"  # the inbound body only
    SUMMARY = "summary"  # the ingest-derived MRN/name summary only
    BOTH = "both"  # match if either matches (the default)


@dataclass(frozen=True)
class SearchSpec:
    """A parsed, validated content-search request — the metadata pre-filter lives separately (it is the
    SQL ``WHERE``); this is only the in-memory content predicate + caps.

    Exactly one of ``substring`` / ``field_path`` is set (validated by :func:`make_spec`):

    * ``substring`` — a literal case-insensitive substring tested against the decrypted target column(s).
    * ``field_path`` + ``field_value`` — an HL7 field path (``PID-3``) resolved via ``Peek.field`` against
      the decrypted ``raw``; matches when the field's value contains ``field_value`` (case-insensitive),
      or — when ``field_value`` is ``None`` — when the field is merely **present/non-empty**.
    """

    substring: str | None
    field_path: str | None
    field_value: str | None
    target: SearchTarget
    scan_limit: int

    def __post_init__(self) -> None:
        # make_spec clamps; a spec built any other way must already be in range, or SQLite would take
        # `LIMIT 0` / `LIMIT -1` (no limit at all) from fetch_limit and the cap would vanish (#2068).
        # A bool passes the range check (True == 1), so it is refused by type first (#6700).
        if isinstance(self.scan_limit, bool) or not isinstance(self.scan_limit, int):
            raise ValueError(f"scan_limit must be an int, not {type(self.scan_limit).__name__}")
        if not 1 <= self.scan_limit <= MAX_SCAN_LIMIT:
            raise ValueError(f"scan_limit must be in [1, {MAX_SCAN_LIMIT}], got {self.scan_limit}")

    @property
    def fetch_limit(self) -> int:
        """How many candidate rows a backend's ``SELECT`` may read (BACKLOG #2068): the scan cap plus
        one. The extra row is never decrypted; its presence is how ``_scan_rows`` tells "stopped at
        the cap" (``truncated``) from "saw every candidate"."""
        return self.scan_limit + 1


def newest_first(rows: Iterable[Any]) -> list[Any]:
    """Order fetched candidates newest-first, as the scan walks them. Done here rather than by an
    outer SQL ``ORDER BY``, which would make the database sort the rows with their bodies (and may
    spill them to temp files) when the rows are already in memory (BACKLOG #2068).

    Equal timestamps tie-break on ``id`` in code-point order. That agrees with each backend's
    ``ORDER BY received_at DESC, id DESC`` under a binary, a case-insensitive or a default
    linguistic collation, because every message id is 32 lowercase hex characters (``uuid4().hex``
    or a truncated SHA-256 hex digest), which sort alike under each of those. A collation with
    numeric ordering would not agree (BACKLOG #6699)."""
    return sorted(rows, key=lambda r: (r["received_at"], r["id"]), reverse=True)


class ContentSearchError(ValueError):
    """A malformed content-search request: at least an empty needle, both or neither needle kinds, a
    ``field_value`` beside a content substring, a bad field path, or a ``scan_limit`` not an ``int``."""


def _sent(value: str | None) -> str | None:
    """``value`` unchanged, or ``None`` when it is empty or only whitespace (counts as not sent)."""
    return value if value and not value.isspace() else None


def make_spec(
    *,
    content: str | None,
    field_path: str | None,
    field_value: str | None,
    target: SearchTarget = SearchTarget.BOTH,
    scan_limit: int = DEFAULT_SCAN_LIMIT,
) -> SearchSpec:
    """Validate a content-search request into a :class:`SearchSpec`.

    Raises :class:`ContentSearchError` on an empty needle, supplying both a substring and a field path,
    a ``field_value`` beside a substring (it would otherwise be dropped unread), a malformed HL7 field
    path, or a ``scan_limit`` that is not an ``int`` (a ``bool`` is refused too). A value of only
    whitespace counts as not sent; any other needle is kept exactly as given, because leading or
    trailing spaces narrow a contains-match. ``scan_limit`` is clamped into ``[1, MAX_SCAN_LIMIT]``."""
    if isinstance(scan_limit, bool) or not isinstance(scan_limit, int):
        raise ContentSearchError(f"scan_limit must be an integer, not {type(scan_limit).__name__}")
    limit = max(1, min(scan_limit, MAX_SCAN_LIMIT))
    needle = _sent(content)
    path = field_path.strip() if field_path else ""  # a locator, not a needle: padding is noise
    fv = _sent(field_value)
    if (needle is None) == (not path):
        raise ContentSearchError("provide exactly one of a content substring or an HL7 field path")
    if needle is not None:
        if fv is not None:
            raise ContentSearchError(
                "field_value applies only to an HL7 field path, not to content"
            )
        return SearchSpec(
            substring=needle,
            field_path=None,
            field_value=None,
            target=target,
            scan_limit=limit,
        )
    # Field-path needle — validate the path eagerly so a bad path is a 4xx, not a per-row failure.
    try:
        parse_path(path)
    except HL7PeekError as exc:
        raise ContentSearchError(str(exc)) from exc
    return SearchSpec(
        substring=None,
        field_path=path,
        field_value=fv,
        target=target,
        scan_limit=limit,
    )


def row_matches(spec: SearchSpec, *, raw: str | None, summary: str | None) -> bool:
    """Whether one candidate row matches ``spec``, given its **already-decrypted** ``raw``/``summary``.

    Pure (no I/O, no cipher). Parsing a non-HL7 / unparseable ``raw`` for a field-path query is treated
    as **no match** (tolerant — a malformed body simply doesn't satisfy ``PID-3``), never an error that
    aborts the scan."""
    if spec.substring is not None:
        needle = spec.substring.casefold()
        if spec.target in (SearchTarget.RAW, SearchTarget.BOTH) and raw is not None:  # noqa: SIM102
            if needle in raw.casefold():
                return True
        if spec.target in (SearchTarget.SUMMARY, SearchTarget.BOTH) and summary is not None:  # noqa: SIM102
            if needle in summary.casefold():
                return True
        return False
    # Field-path needle: resolve the path against the decrypted raw body.
    if raw is None:
        return False
    try:
        value = Peek.parse(raw).field(spec.field_path)  # type: ignore[arg-type]
    except HL7PeekError:
        return False  # unparseable body can't satisfy a field-path predicate
    if value is None:
        return False
    if spec.field_value is None:
        return True  # presence test — the field exists and is non-empty
    return spec.field_value.casefold() in value.casefold()
