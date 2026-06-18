# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Tolerant X12 *peek* — cheap routing-field extraction (the HL7 :class:`~messagefoundry.parsing.peek.Peek`
analog for X12 EDI).

Routing should never force a full parse, so :class:`X12Peek` does a **fixed-offset ISA read** for the
interchange identity (sender/receiver, version, control number, usage) plus a shallow ``GS``/``ST``
header walk for the functional groups and their transaction-set ids — the keys a Router branches on.

One ISA can carry **multiple ``GS`` groups**, and one ``GS`` **multiple ``ST`` sets**, so the group /
transaction ids are not single-valued: :meth:`X12Peek.groups` returns the **full list** of
:class:`X12Group` so a Router can fan out or filter precisely (returning only the first would silently
mis-route multi-group interchanges). The implementation-guide version a Router most often branches on
(e.g. ``005010X222A1`` for 837P) lives in **GS08**, distinct from the ISA12 envelope version exposed by
:attr:`X12Peek.version`.

Pure: works on ``str`` (or ``bytes``, decoded UTF-8/replace), no I/O, no engine imports.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass

from messagefoundry.parsing.x12.delimiters import (
    DEFAULT_MAX_INTERCHANGE_BYTES,
    Delimiters,
    discover_delimiters,
    find_isa_start,
)
from messagefoundry.parsing.x12.errors import X12PeekError

__all__ = ["X12Peek", "X12Group"]

# ISA fixed-offset field slices (relative to the ISA start): name -> (start, end). The ISA is fixed
# width, so these are read directly rather than tokenized.
_ISA_FIELDS: dict[str, tuple[int, int]] = {
    "sender_qual": (32, 34),  # ISA05
    "sender_id": (35, 50),  # ISA06
    "receiver_qual": (51, 53),  # ISA07
    "receiver_id": (54, 69),  # ISA08
    "date": (70, 76),  # ISA09 (YYMMDD)
    "time": (77, 81),  # ISA10 (HHMM)
    "version": (84, 89),  # ISA12 (envelope version, e.g. "00501")
    "control_number": (90, 99),  # ISA13
    "usage": (102, 103),  # ISA15 ("P" production / "T" test)
}


def _element(fields: list[str], index: int) -> str | None:
    """The 1-based-by-X12-convention element at ``index`` (0 = segment tag), trimmed, or None."""
    if index < len(fields):
        return fields[index].strip() or None
    return None


@dataclass(frozen=True)
class X12Group:
    """A functional group (``GS``/``GE``) and the transaction-set ids it carries.

    ``version`` is GS08 (Version/Release/Industry Identifier Code, the implementation-guide version,
    e.g. ``005010X222A1``) — distinct from :attr:`X12Peek.version` (the ISA12 envelope version)."""

    functional_id: str | None  # GS01, e.g. "HC" (health care claim)
    app_sender: str | None  # GS02
    app_receiver: str | None  # GS03
    control_number: str | None  # GS06
    version: str | None  # GS08
    transactions: tuple[str, ...]  # ST01 ids in order, e.g. ("837",)


@dataclass(frozen=True)
class X12Peek:
    """A tolerant view over one X12 interchange exposing routing fields. Construct via :meth:`parse`.

    ``raw`` is the interchange text; ``delimiters`` are discovered from its ISA; ``isa_start`` is where
    the ISA begins (≥0; nonzero when leading whitespace/BOM preceded it)."""

    raw: str
    delimiters: Delimiters
    isa_start: int

    @classmethod
    def parse(
        cls,
        raw: str | bytes,
        *,
        max_bytes: int | None = DEFAULT_MAX_INTERCHANGE_BYTES,
    ) -> X12Peek:
        """Peek the interchange that starts ``raw`` (after any leading whitespace/BOM).

        Raises :class:`X12PeekError` if the bytes are not a parseable X12 interchange (no ISA,
        truncated/malformed ISA, non-distinct delimiters) or exceed ``max_bytes``."""
        if isinstance(raw, (bytes, bytearray)):
            raw = bytes(raw).decode("utf-8", "replace")
        if max_bytes is not None and len(raw) > max_bytes:
            raise X12PeekError(f"X12 interchange exceeds max size ({len(raw)} > {max_bytes} chars)")
        isa_start = find_isa_start(raw)
        delimiters = discover_delimiters(raw, isa_start)
        return cls(raw=raw, delimiters=delimiters, isa_start=isa_start)

    # --- interchange-level identity (ISA, by fixed offset) -------------------

    def _isa(self, name: str) -> str:
        start, end = _ISA_FIELDS[name]
        return self.raw[self.isa_start + start : self.isa_start + end]

    @property
    def sender_qual(self) -> str | None:
        """ISA05 — interchange sender ID qualifier (e.g. ``ZZ``, ``01``)."""
        return self._isa("sender_qual").strip() or None

    @property
    def sender_id(self) -> str | None:
        """ISA06 — interchange sender ID (trailing space-padding trimmed)."""
        return self._isa("sender_id").strip() or None

    @property
    def receiver_qual(self) -> str | None:
        """ISA07 — interchange receiver ID qualifier."""
        return self._isa("receiver_qual").strip() or None

    @property
    def receiver_id(self) -> str | None:
        """ISA08 — interchange receiver ID (trailing space-padding trimmed)."""
        return self._isa("receiver_id").strip() or None

    @property
    def date(self) -> str | None:
        """ISA09 — interchange date, ``YYMMDD``."""
        return self._isa("date").strip() or None

    @property
    def time(self) -> str | None:
        """ISA10 — interchange time, ``HHMM``."""
        return self._isa("time").strip() or None

    @property
    def version(self) -> str | None:
        """ISA12 — interchange control version number (the **envelope** version, e.g. ``00501``).
        The implementation-guide version is per-group GS08 (see :attr:`X12Group.version`)."""
        return self._isa("version").strip() or None

    @property
    def control_number(self) -> str | None:
        """ISA13 — interchange control number (used for de-dup/correlation; ties to IEA02)."""
        return self._isa("control_number").strip() or None

    @property
    def usage(self) -> str | None:
        """ISA15 — usage indicator: ``P`` (production) or ``T`` (test)."""
        return self._isa("usage").strip() or None

    @property
    def is_test(self) -> bool:
        """True when the usage indicator (ISA15) is ``T`` (test)."""
        return self.usage == "T"

    # --- functional groups (GS/ST walk) -------------------------------------

    def _iter_segments(self) -> Iterator[list[str]]:
        """Yield each segment of the first interchange as a list of elements (``[tag, e1, e2, …]``),
        stopping after ``IEA``. Tolerates cosmetic whitespace between segments."""
        element = self.delimiters.element
        terminator = self.delimiters.segment
        for chunk in self.raw[self.isa_start :].split(terminator):
            stripped = chunk.lstrip(" \t\r\n")
            if not stripped:
                continue
            fields = stripped.split(element)
            yield fields
            if fields[0] == "IEA":
                return

    def groups(self) -> list[X12Group]:
        """Every functional group in the interchange, with its transaction-set ids. Empty if none."""
        # (gs-fields | None, [st01 …]); a new group opens at each GS, transactions attach to the last.
        accumulated: list[tuple[list[str] | None, list[str]]] = []
        for fields in self._iter_segments():
            tag = fields[0]
            if tag == "GS":
                accumulated.append((fields, []))
            elif tag == "ST":
                if not accumulated:
                    accumulated.append((None, []))  # orphan ST (malformed) — don't lose it
                st01 = _element(fields, 1)
                if st01 is not None:
                    accumulated[-1][1].append(st01)
        return [
            X12Group(
                functional_id=_element(gs, 1) if gs else None,
                app_sender=_element(gs, 2) if gs else None,
                app_receiver=_element(gs, 3) if gs else None,
                control_number=_element(gs, 6) if gs else None,
                version=_element(gs, 8) if gs else None,
                transactions=tuple(tx),
            )
            for gs, tx in accumulated
        ]

    def transaction_ids(self) -> list[str]:
        """Flat list of every ST01 transaction-set id across all groups, in order (e.g. ``["837"]``)."""
        return [st for group in self.groups() for st in group.transactions]

    def segment_ids(self) -> list[str]:
        """Ordered segment ids of the first interchange (e.g. ``["ISA", "GS", "ST", …, "IEA"]``)."""
        return [fields[0] for fields in self._iter_segments()]
