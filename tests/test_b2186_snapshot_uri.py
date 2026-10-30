# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #2186: the DR backup, its verify and the restore open their snapshot read-only through
the store's own URI builder, so a ``#``, ``?`` or ``%XX`` in a staging path cannot change the
file it names.

SQLite reads ``#`` and ``?`` in a ``file:`` URI as URI syntax. A bare ``f"file:{path}?mode=ro"``
over a path whose directory holds ``#`` ends the path at the ``#``, drops ``mode=ro`` with it, and
opens -- creating it -- an empty stand-in database named for the prefix. The backup then recorded
``row_counts == {}`` in its manifest, the verify counted the same empty stand-in, an empty manifest
has no keys to mismatch, and ``integrity_check`` on an empty file is ``ok``: a PASS that read nothing.

The first test is the control that keeps the others meaningful: it shows the bare form really does
open a stand-in on this platform under such a directory, so a green run below is the fix working,
not a path that never reached the hazard."""

from __future__ import annotations

import ast
import sqlite3
import sys
import tempfile
from collections import Counter
from pathlib import Path

import pytest

from messagefoundry.config.settings import BackupSettings, StoreSettings
from messagefoundry.pipeline.dr_backup import (
    BackupRunner,
    _count_tables,
    _integrity_check,
    run_restore,
    run_restore_verify,
)
from messagefoundry.store import MessageStore
from messagefoundry.store.crypto import generate_key, make_cipher

_REPO = Path(__file__).resolve().parents[1]


def _real_db(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path)
    try:
        conn.execute("CREATE TABLE t (x INTEGER)")
        conn.executemany("INSERT INTO t VALUES (?)", [(1,), (2,), (3,)])
        conn.commit()
    finally:
        conn.close()


#: Characters a bare ``file:`` URI misreads: ``#`` and ``?`` cut the path, and ``%41`` decodes to
#: ``A``, naming another file. Windows refuses ``?`` in a file name.
_URI_HAZARDS = ["#", "%41"] + ([] if sys.platform == "win32" else ["?"])


def _refuse_a_hazardous_tmp_path(tmp_path: Path) -> None:
    """The bare open below would cut a path ABOVE ``tmp_path`` if ``tmp_path`` itself held one of
    the hazards, and leave its stand-in outside pytest's temp tree."""
    if any(c in str(tmp_path) for c in "#?%"):
        pytest.skip(f"tmp_path itself holds a URI hazard: {tmp_path}")


def test_a_bare_file_uri_opens_a_stand_in_under_a_hash_directory(tmp_path: Path) -> None:
    """The control: what the old open did on this platform, and what the helpers now do instead."""
    _refuse_a_hazardous_tmp_path(tmp_path)
    real = tmp_path / "a#b" / "real.db"
    _real_db(real)
    stand_in = tmp_path / "a"

    bare = sqlite3.connect(f"file:{real}?mode=ro", uri=True)
    try:
        tables = bare.execute("SELECT name FROM sqlite_master").fetchall()
    finally:
        bare.close()
    assert tables == [], "the bare URI read the real file, so this platform cannot show the defect"
    assert stand_in.is_file(), "the bare URI did not create the stand-in this test expects"
    stand_in.unlink()

    assert _count_tables(real) == {"t": 3}
    assert _integrity_check(real) == (True, "ok")
    assert not stand_in.exists()


@pytest.mark.parametrize("hazard", _URI_HAZARDS)
async def test_backup_verify_and_restore_count_the_real_snapshot_under_hazard_paths(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, hazard: str
) -> None:
    """Every place a snapshot is staged sits under a directory holding ``hazard``: the backup's
    (the store's data directory), the standalone verify's (the OS temp dir) and the restore's (the
    destination's directory). Each count must be the real snapshot's, and nothing may appear in
    ``tmp_path`` but the directories this test made."""
    _refuse_a_hazardous_tmp_path(tmp_path)
    os_temp = tmp_path / f"os{hazard}temp"
    os_temp.mkdir()
    monkeypatch.setattr(tempfile, "tempdir", str(os_temp))
    data_dir = tmp_path / f"data{hazard}store"
    data_dir.mkdir()
    out_dir = tmp_path / f"b{hazard}out"
    restore_dir = tmp_path / f"r{hazard}dest"

    key_b64 = generate_key()
    store = await MessageStore.open(data_dir / "msg.db", cipher=make_cipher(key_b64))
    try:
        await store.enqueue_message(
            channel_id="c1",
            raw="MSH|^~\\&|x",
            deliveries=[("d1", "OUT|y")],
            control_id="CID-1",
            now=1.0,
        )
        ss = StoreSettings(path=str(data_dir / "msg.db"), encryption_key=key_b64)
        runner = BackupRunner(
            store,
            BackupSettings(enabled=True, destination=str(out_dir)),
            store_settings=ss,
            config_dir=None,
        )
        backup = await runner.run_once(now=1.0)
    finally:
        await store.close()
    assert backup is not None
    # The manifest's counts: an empty stand-in recorded {} here.
    assert backup.row_counts.get("messages") == 1
    assert backup.verify is not None and backup.verify.status == "PASS"
    assert backup.verify.row_counts.get("messages") == 1

    verified = await run_restore_verify(backup.archive_path, store_settings=ss)
    assert verified.status == "PASS"
    assert verified.manifest_counts.get("messages") == 1
    assert verified.row_counts == verified.manifest_counts

    restored = await run_restore(
        backup.archive_path,
        dest_store_path=restore_dir / "restored.db",
        store_settings=ss,
    )
    assert restored.row_counts.get("messages") == 1

    # A stand-in lands beside these, at the cut path, so anything else here is one.
    made = {os_temp.name, data_dir.name, out_dir.name, restore_dir.name}
    assert {p.name for p in tmp_path.iterdir()} == made


# --- the guard: no bare `file:` URI built from a path anywhere in the engine's own packages ---

#: Each package, with a floor on the files walked in it, so a moved or renamed package fails the
#: scan rather than turning it into a vacuous pass.
_SCANNED = {"messagefoundry": 200, "messagefoundry_webconsole": 20, "messagefoundry_toolkit": 3}

#: The functions allowed to assemble a ``file:`` URI from parts, each of which encodes the path,
#: and how many such sites each holds. The store's read-only builder rewrites the UNC prefix of
#: ``Path.as_uri()``'s already-encoded output; the offline probe percent-encodes the path with
#: ``urllib.parse.quote``. The count is pinned so a second, unencoded site in one of them fails.
_SANCTIONED = Counter(
    {
        ("messagefoundry/store/store.py", "_sqlite_readonly_uri"): 1,
        ("messagefoundry/__main__.py", "_sqlite_store_held_elsewhere"): 1,
    }
)


def _starts_file_uri(node: ast.expr) -> bool:
    """A string literal opening a ``file:`` URI. ``file:`` then whitespace is not one: the file
    transport opens its error messages that way (``"file: refusing ..."``)."""
    return (
        isinstance(node, ast.Constant)
        and isinstance(node.value, str)
        and node.value.startswith("file:")
        and not node.value[5:6].isspace()
    )


def _is_bare_file_uri(node: ast.expr) -> bool:
    if isinstance(node, ast.JoinedStr):
        return bool(node.values) and _starts_file_uri(node.values[0])
    if isinstance(node, ast.BinOp):
        return isinstance(node.op, ast.Add | ast.Mod) and _starts_file_uri(node.left)
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "format"
        and _starts_file_uri(node.func.value)
    )


def bare_file_uris(source: str) -> list[tuple[int, str]]:
    """``(line, enclosing function)`` for every ``file:`` URI assembled from parts; the function is
    ``""`` at module level. Comments and docstrings are not code, so the AST never shows them.

    Caught: an f-string opening with ``file:``, ``"file:" + x``, ``"file:%s" % x`` and
    ``"file:{}".format(x)``. Whether ``x`` is encoded is not judged here: a site that encodes it is
    named in :data:`_SANCTIONED` instead. Not caught, at least: a prefix held in a variable, a
    ``join``, and a URI built by ``Path.as_uri()`` (which encodes, but loses a UNC server)."""
    hits: list[tuple[int, str]] = []

    def visit(node: ast.AST, func: str) -> None:
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            func = node.name
        if isinstance(node, ast.expr) and _is_bare_file_uri(node):
            hits.append((node.lineno, func))
        for child in ast.iter_child_nodes(node):
            visit(child, func)

    # A one-shot parse, not the shared cached one: these trees are not probed twice.
    visit(ast.parse(source.removeprefix("\ufeff")), "")
    return sorted(hits)


def test_the_guard_catches_each_bare_form_and_passes_the_others() -> None:
    bad = (
        'c(f"file:{p}?mode=ro", uri=True)\n'
        'c("file:" + p, uri=True)\n'
        'c("file:%s?mode=ro" % p, uri=True)\n'
        'c("file:{}?mode=ro".format(p), uri=True)\n'
        'c("file:" + shlex.quote(p), uri=True)\n'
    )
    assert bare_file_uris(bad) == [(1, ""), (2, ""), (3, ""), (4, ""), (5, "")]
    assert bare_file_uris("def f(p):\n    return f'file:{p}'\n") == [(2, "f")]
    good = (
        '"""A docstring may say f"file:{path}"."""\n'
        '# so may a comment: f"file:{path}"\n'
        "c(_sqlite_readonly_uri(p), uri=True)\n"
        'raise DeliveryError(f"file: refusing {name}")\n'
        'x = "file:"\n'
    )
    assert bare_file_uris(good) == []


def test_no_engine_module_builds_a_bare_file_uri() -> None:
    offenders: list[str] = []
    sanctioned_seen: Counter[tuple[str, str]] = Counter()
    for package, floor in _SCANNED.items():
        files = sorted((_REPO / package).rglob("*.py"))
        assert len(files) >= floor, f"walked only {len(files)} files under {package}; did it move?"
        for py in files:
            text = py.read_text(encoding="utf-8")
            # Only a file holding the text can hold the form, so the rest skip the parse.
            if "file:" not in text:
                continue
            rel = py.relative_to(_REPO).as_posix()
            for line, func in bare_file_uris(text):
                if (rel, func) in _SANCTIONED:
                    sanctioned_seen[(rel, func)] += 1
                else:
                    offenders.append(f"{rel}:{line} in {func or '<module>'}")
    # The exemptions are checked as well as used: one that matches nothing any more is stale, a
    # scan that no longer sees a sanctioned site's own concatenation has stopped seeing that form,
    # and an extra site inside a sanctioned function is not covered by its exemption.
    assert sanctioned_seen == _SANCTIONED
    assert offenders == [], (
        "a bare `file:` URI cuts its path at `#` or `?` and drops `mode=ro` (BACKLOG #2186); "
        f"open through store.cipher_cells.connect_readonly or store.store._sqlite_readonly_uri: {offenders}"
    )
