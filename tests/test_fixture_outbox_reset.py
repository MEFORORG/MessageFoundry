# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""No test fixture may issue an UNGUARDED ``DELETE FROM outbox`` once the legacy table is retired.

ASVS 14.2.7 migrates the legacy SQL Server ``outbox`` table into ``queue`` and DROPs it. After that, a
fixture doing::

    for table in ("message_events", "state", "queue", "response", "outbox", "messages"):
        await cur.execute(f"DELETE FROM {table}")

fails with *Invalid object name 'outbox'* and takes its whole module with it.

**Why a source scanner rather than "run the tests and see":** of the eighteen files carrying such a
reset list, **nine appear in no SQL Server CI step at all** — `test_adr0071_dispatch_wiring_sqlserver`,
`test_adr0071_fused_callables_sqlserver`, `test_adr0075_batch_sqlserver`, `test_adr0114_claim_proc_live`,
`test_batch_completion`, `test_metadata_bag`, `test_outbound_batch`, `test_shard_recovery_sqlserver`,
`test_sqlserver_sync_handoff`. A mutation planted in any of those **passes vacuously**, so "the SS leg
is green" is not evidence that the reset lists were all updated. This test needs no database and runs
on the plain leg, which is the only leg guaranteed to exist.

The **guarded** form is fine and stays::

    await cur.execute(f"IF OBJECT_ID(N'{table}', N'U') IS NOT NULL DELETE FROM {table}")

— it is a no-op once the table is gone. That distinction is structural, not stylistic, which is why this
scanner reads the loop body rather than grepping for the word ``outbox``.
"""

from __future__ import annotations

import ast
import pathlib

import pytest

_TESTS = pathlib.Path(__file__).resolve().parent

#: Existence-guard markers. A reset whose statement contains one of these degrades to a no-op when the
#: table is absent, so it survives the retirement untouched.
_GUARD_MARKERS = ("OBJECT_ID", "IF EXISTS", "information_schema", "in existing", "to_regclass")

#: `"outbox"` appears in these for reasons that are not a reset list. Exempted by FILE, with the reason,
#: because a blanket substring skip would also hide a real one landing in the same file later.
_NOT_RESET_LISTS = {
    # A Pydantic field-name allow-list and a forbidden-substring tuple — neither is a table name.
    "test_security_doc_drift.py": "_MAPPED_MODEL_NON_PHI_FIELDS — model field names, not tables",
    "test_tray_boundary.py": "_FORBIDDEN_FIELD_SUBSTRINGS — substring matching, not tables",
    # Response-payload dict keys asserted in API tests.
    "test_api.py": "response-body keys, not tables",
    "test_api_auth.py": "response-body keys, not tables",
    # This scanner and the AST guard both name the table in prose/fixtures on purpose.
    "test_fixture_outbox_reset.py": "this file",
    "test_sqlserver_encrypt_pass_tables.py": "synthetic fixtures naming the table deliberately",
}


def _unguarded_outbox_resets(path: pathlib.Path) -> list[tuple[int, str]]:
    """Loops over a literal table tuple containing ``"outbox"`` whose body issues a BARE delete.

    Anchored on the `for` node and its body's source span, so the guarded and unguarded spellings are
    told apart by what the statement actually does — not by whether the word ``outbox`` is nearby.
    """
    source = path.read_text(encoding="utf-8")
    try:
        tree = ast.parse(source)
    except SyntaxError:  # pragma: no cover - a test file that does not parse fails elsewhere
        return []
    lines = source.splitlines()
    hits: list[tuple[int, str]] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.For | ast.AsyncFor):
            continue
        if not isinstance(node.iter, ast.Tuple | ast.List | ast.Set):
            continue
        names = {
            e.value
            for e in node.iter.elts
            if isinstance(e, ast.Constant) and isinstance(e.value, str)
        }
        if "outbox" not in names:
            continue
        body_lines: list[str] = []
        for stmt in node.body:
            body_lines.extend(lines[stmt.lineno - 1 : (stmt.end_lineno or stmt.lineno)])
        body_src = "\n".join(body_lines)
        if "DELETE FROM" not in body_src.upper():
            continue
        if any(marker.upper() in body_src.upper() for marker in _GUARD_MARKERS):
            continue  # existence-guarded — a no-op once the table is gone
        hits.append((node.lineno, body_src.strip().splitlines()[0][:100]))
    return hits


def _scanned_files() -> list[pathlib.Path]:
    return sorted(p for p in _TESTS.glob("test_*.py") if p.name not in _NOT_RESET_LISTS)


@pytest.mark.xfail(
    strict=True,
    reason=(
        "EXPECTED RED until the legacy SQL Server `outbox` table is retired. 21 unguarded reset sites "
        "across 18 files still name it, and they are CORRECT today — the table exists. This guard "
        "lands FIRST, before the retirement, so the retirement cannot ship half-done; its failure list "
        "is the work list. strict=True makes this self-clearing: the moment the last reset list is "
        "fixed the test XPASSes, which strict turns into a FAILURE, forcing this marker to be removed "
        "in the same commit. A non-strict xfail would let the guard rot silently green forever."
    ),
)
def test_no_fixture_issues_an_unguarded_outbox_delete() -> None:
    """After the legacy table is retired, an unguarded reset is a module-wide failure.

    Mutation: add `"outbox"` to the reset tuple in `tests/test_metadata_bag.py` — reds here on the plain
    leg naming the file and line, which is the only place it can be caught for the nine files that run
    on no SQL Server CI step.

    NOTE this test is expected to FAIL until Commit 6 updates the reset lists. That is deliberate and is
    the point of landing the guard first: the failure list below IS the work list.
    """
    scanned = _scanned_files()
    # Liveness receipt: report what was EXAMINED, not just what was found. A glob that silently matched
    # nothing would make this pass while checking zero files.
    assert len(scanned) > 100, f"only scanned {len(scanned)} test files — the glob looks broken"

    offenders: list[str] = []
    for path in scanned:
        for lineno, snippet in _unguarded_outbox_resets(path):
            offenders.append(f"  {path.name}:{lineno}  {snippet}")

    assert not offenders, (
        f"scanned {len(scanned)} test files; {len(offenders)} carry an UNGUARDED "
        f"`DELETE FROM outbox` reset. Once the legacy table is dropped each of these fails with "
        f"'Invalid object name' and takes its whole module with it — and nine of them run on no SQL "
        f"Server CI step, so no live leg would tell you:\n" + "\n".join(offenders) + "\n\n"
        "Fix by removing 'outbox' from the tuple, or by using the guarded form:\n"
        "  await cur.execute(f\"IF OBJECT_ID(N'{table}', N'U') IS NOT NULL DELETE FROM {table}\")"
    )


def test_the_scanner_distinguishes_guarded_from_unguarded() -> None:
    """Prove the detector's discrimination, rather than trusting it.

    A scanner that flagged everything would make the test above permanently red and get deleted; one
    that flagged nothing would pass forever. Drive both spellings through it.
    """
    unguarded = _TESTS / "_scan_fixture_unguarded.py"
    guarded = _TESTS / "_scan_fixture_guarded.py"
    unguarded.write_text(
        "async def f(cur):\n"
        '    for table in ("queue", "outbox", "messages"):\n'
        '        await cur.execute(f"DELETE FROM {table}")\n',
        encoding="utf-8",
    )
    guarded.write_text(
        "async def f(cur):\n"
        '    for table in ("queue", "outbox", "messages"):\n'
        "        await cur.execute(\n"
        "            f\"IF OBJECT_ID(N'{table}', N'U') IS NOT NULL DELETE FROM {table}\"\n"
        "        )\n",
        encoding="utf-8",
    )
    try:
        assert _unguarded_outbox_resets(unguarded), "the bare DELETE was NOT flagged"
        assert not _unguarded_outbox_resets(guarded), (
            "the OBJECT_ID-guarded DELETE was wrongly flagged"
        )
    finally:
        unguarded.unlink(missing_ok=True)
        guarded.unlink(missing_ok=True)


@pytest.mark.parametrize("exempt", sorted(_NOT_RESET_LISTS))
def test_every_exemption_still_exists_and_still_needs_exempting(exempt: str) -> None:
    """An exemption for a file that no longer exists, or no longer mentions the table, is dead weight
    that quietly widens the next person's blind spot. Fail when one goes stale."""
    path = _TESTS / exempt
    assert path.exists(), f"exempted file {exempt} is gone — drop it from _NOT_RESET_LISTS"
    assert "outbox" in path.read_text(encoding="utf-8"), (
        f"{exempt} no longer mentions 'outbox' — the exemption is stale and should be removed, "
        f"otherwise a genuine reset list landing in this file later would be silently skipped"
    )
