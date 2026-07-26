# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Doc-drift guard for the per-backend store capability matrix in ``docs/CONFIGURATION.md``.

**Why this exists.** The engine's per-backend capabilities are `supports_*` flags on the
:class:`~messagefoundry.store.base.QueueStore` protocol. Prose that *describes* those flags rots
silently: SQL Server shipped ``capture_response`` + ``reingress_to`` re-ingress in #249 (2026-06-15),
but several docstrings, an ADR test-plan, and a raised error kept saying it did not — and a downstream
team read that prose, believed SQL Server "refuses capture", and scoped work to build a feature that had
existed for a month.

``tests/test_cloud_phi_hipaa_doc_drift.py`` already names this failure mode and explains why it cannot
catch it: *"A name-existence guard structurally cannot catch a false-negative prose claim (an assertion
that 'X does not exist' when X was later built)."* A **value** guard can. So the doc table is the
fixture: every cell is parsed out of ``docs/CONFIGURATION.md`` and asserted against the value the store
class actually declares. Prose and code cannot drift apart without a red test.

No database, no ODBC driver, and no server extras are needed: the flags are plain class attributes and
the drivers are imported method-locally, so all three store classes import on a bare venv. That is
load-bearing — these tests are deliberately **not** ``importorskip``-gated, because a capability guard
that silently skips on a minimal CI leg is precisely the fossil it was built to prevent.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from messagefoundry.store.base import QueueStore
from messagefoundry.store.postgres import PostgresStore
from messagefoundry.store.sqlserver import SqlServerStore
from messagefoundry.store.store import MessageStore

_ROOT = Path(__file__).resolve().parent.parent
_DOC = _ROOT / "docs" / "CONFIGURATION.md"
_HEADING = "#### Per-backend capability matrix"

#: Doc column header -> the store class it describes. The doc table's column order must match.
_BACKENDS: dict[str, type[Any]] = {
    "SQLite": MessageStore,
    "Postgres": PostgresStore,
    "SQL Server": SqlServerStore,
}

_FLAG_CELL = re.compile(r"`(supports_\w+)`")
#: Cells carry markdown emphasis on the rows that vary (e.g. ``**yes**``) — read the word, not the bold.
_YES_NO = {"yes": True, "no": False}


def _doc_matrix() -> dict[str, dict[str, bool]]:
    """Parse the capability table out of the doc: ``{flag: {backend column: bool}}``."""
    lines = _DOC.read_text(encoding="utf-8").splitlines()
    try:
        start = next(i for i, ln in enumerate(lines) if ln.strip() == _HEADING)
    except StopIteration:  # pragma: no cover - the failure message IS the point
        raise AssertionError(
            f"{_DOC} has no {_HEADING!r} section. The capability matrix is the single source of "
            "operator-facing truth for per-backend support; it must not be deleted."
        ) from None

    matrix: dict[str, dict[str, bool]] = {}
    for line in lines[start:]:
        if line.startswith("#") and line.strip() != _HEADING:
            break  # next section — the table is behind us
        flag = _FLAG_CELL.match(line.strip().lstrip("|").strip())
        if flag is None:
            continue
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        values = [_YES_NO.get(c.strip("* ").lower()) for c in cells[1:]]
        assert len(values) == len(_BACKENDS), (
            f"row {flag.group(1)!r} has {len(values)} backend cells, expected {len(_BACKENDS)} "
            f"({', '.join(_BACKENDS)})"
        )
        assert None not in values, (
            f"row {flag.group(1)!r} has a cell that is neither 'yes' nor 'no': {cells[1:]}"
        )
        matrix[flag.group(1)] = {name: bool(v) for name, v in zip(_BACKENDS, values, strict=True)}
    return matrix


def _declared_flags() -> set[str]:
    """Every ``supports_*`` capability flag that exists today.

    Unions the protocol's ``__annotations__`` with the concrete classes' attributes. The annotations are
    load-bearing: ``supports_ingest_stage`` and ``supports_response_capture`` are declared on
    :class:`QueueStore` **without a default**, so they do not appear in ``dir()`` — enumerating via
    ``dir()`` alone would silently miss the two flags at the very heart of the incident this guards.
    """
    flags = {f for f in getattr(QueueStore, "__annotations__", {}) if f.startswith("supports_")}
    for cls in _BACKENDS.values():
        flags |= {f for f in dir(cls) if f.startswith("supports_")}
    return flags


def test_doc_matrix_matches_store_class_attributes() -> None:
    # Every cell of the published table must equal the flag the store class actually declares. This is
    # the assertion whose ABSENCE let "SQL Server doesn't support capture" survive a month past #249.
    matrix = _doc_matrix()
    assert matrix, f"the {_HEADING!r} table in {_DOC} parsed to zero rows"
    wrong: list[str] = []
    for flag, row in matrix.items():
        for backend, documented in row.items():
            actual = getattr(_BACKENDS[backend], flag)
            if actual is not documented:
                wrong.append(
                    f"  {backend}.{flag}: doc says {'yes' if documented else 'no'}, "
                    f"code says {'yes' if actual else 'no'}"
                )
    assert not wrong, (
        "docs/CONFIGURATION.md capability matrix disagrees with the store classes:\n"
        + "\n".join(wrong)
        + "\n\nUpdate the table in the SAME commit as the flag change."
    )


def test_every_supports_flag_has_a_documented_row() -> None:
    # The anti-fossil clause: a NEW capability flag added to a store class with no doc row fails HERE,
    # loudly, instead of quietly becoming the next stale "backend X doesn't do Y" claim.
    documented = set(_doc_matrix())
    declared = _declared_flags()
    missing = declared - documented
    assert not missing, (
        f"capability flag(s) {sorted(missing)} exist in code but have no row in the {_HEADING!r} "
        f"table in {_DOC}. Add a row (in this same commit) or the matrix rots."
    )
    stale = documented - declared
    assert not stale, (
        f"the {_HEADING!r} table documents flag(s) {sorted(stale)} that no longer exist in code."
    )


def test_response_capture_and_pt_reingress_supported_on_all_backends() -> None:
    # The direct, named inverse of the ADR-0013 fossil — the assertion that must exist INSTEAD of that
    # ADR's prescribed "a reingress_to outbound on SQL Server is rejected at start" test, which was never
    # written and would fail. Capture + PT/Loopback re-ingress work on ALL THREE backends.
    for name, cls in _BACKENDS.items():
        assert cls.supports_response_capture is True, f"{name} lost response capture (ADR 0013)"
        assert cls.supports_pt_reingress is True, f"{name} lost PT re-ingress"


def test_matrix_records_the_capability_that_actually_varies() -> None:
    # The matrix earns its keep only because it is NOT uniformly True — a table of all-yes would be
    # worthless and would invite "simplification" back into a falsehood. Pin the real asymmetry, in BOTH
    # directions, so it cannot be flattened by a careless sweep.
    #   fused sync handoff: SQL Server ONLY (ADR 0071 B5 — aioodbc's per-statement thread crossing is the
    #   wall; asyncpg is loop-native and SQLite's handoff lock is loop-affine, so neither has anything to
    #   fuse). SQL Server is the MOST capable backend here — the exact inverse of the fossil prose.
    assert SqlServerStore.supports_fused_sync_handoff is True
    assert MessageStore.supports_fused_sync_handoff is False
    assert PostgresStore.supports_fused_sync_handoff is False


def test_reference_sets_supported_on_all_backends() -> None:
    # Reference sets (ADR 0006) STOPPED being a capability that varies when BACKLOG #235 ported the
    # snapshot store to SQL Server (2026-07-16; T-SQL proven on the sqlserver-store 2022+2025 CI matrix
    # before the flag flipped). Pin all-three-True the same way capture/PT re-ingress are pinned above,
    # so "not on SQL Server" cannot regrow — as prose OR as a table cell.
    for name, cls in _BACKENDS.items():
        assert cls.supports_reference_sets is True, f"{name} lost reference sets (ADR 0006 / #235)"
