# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
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

from dataclasses import dataclass
from enum import Enum

from messagefoundry.parsing.peek import HL7PeekError, Peek, parse_path

# Hard caps (ADR 0046 D1 §3 — the non-negotiable cost ceiling). ``DEFAULT_SCAN_LIMIT`` bounds how many
# candidate rows are decrypted before the scan stops and reports ``truncated``; ``MAX_SCAN_LIMIT`` is
# the upper bound an operator may request (mirrors ``/messages`` ``le=500`` for the result cap, but the
# scan ceiling is larger because most candidates won't match). A search that hits the scan cap degrades
# to "narrow your filters", never a full-store decrypt.
DEFAULT_SCAN_LIMIT = 2_000
MAX_SCAN_LIMIT = 10_000


class SearchTarget(str, Enum):
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


class ContentSearchError(ValueError):
    """A malformed content-search request (empty needle, both/neither needle kinds, bad field path)."""


def make_spec(
    *,
    content: str | None,
    field_path: str | None,
    field_value: str | None,
    target: SearchTarget = SearchTarget.BOTH,
    scan_limit: int = DEFAULT_SCAN_LIMIT,
) -> SearchSpec:
    """Validate + normalize a content-search request into a :class:`SearchSpec`.

    Raises :class:`ContentSearchError` on an empty needle, supplying both a substring and a field path,
    or a malformed HL7 field path. ``scan_limit`` is clamped into ``[1, MAX_SCAN_LIMIT]``."""
    has_content = bool(content and content.strip())
    has_field = bool(field_path and field_path.strip())
    if has_content == has_field:
        raise ContentSearchError("provide exactly one of a content substring or an HL7 field path")
    limit = max(1, min(int(scan_limit), MAX_SCAN_LIMIT))
    if has_content:
        return SearchSpec(
            substring=content.strip(),  # type: ignore[union-attr]
            field_path=None,
            field_value=None,
            target=target,
            scan_limit=limit,
        )
    # Field-path needle — validate the path eagerly so a bad path is a 4xx, not a per-row failure.
    path = field_path.strip()  # type: ignore[union-attr]
    try:
        parse_path(path)
    except HL7PeekError as exc:
        raise ContentSearchError(str(exc)) from exc
    fv = field_value.strip() if field_value and field_value.strip() else None
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
        if spec.target in (SearchTarget.RAW, SearchTarget.BOTH) and raw is not None:
            if needle in raw.casefold():
                return True
        if spec.target in (SearchTarget.SUMMARY, SearchTarget.BOTH) and summary is not None:
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
