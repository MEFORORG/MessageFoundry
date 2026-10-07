# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The shared config-editor write path (vault BACKLOG #2782, review finding F-9).

Four editors rewrite a file an operator also edits by hand: ``alerts_edit`` and ``security_edit``
(the service-settings TOML), ``codeset_edit`` (``codesets/<name>.csv``) and ``connections_edit``
(``connections.toml``). Three of them wrote a fixed ``<name>.tmp`` at the process umask, all four
put unvalidated text at the live path while validating it and rolled it back afterwards without the
owner-only restriction, and none took a lock another process could see. These tests pin the shared
replacement in :mod:`messagefoundry.config.atomic_edit` through each editor's public surface."""

from __future__ import annotations

import os
import stat
import sys
import textwrap
import threading
from collections.abc import Callable
from pathlib import Path

import pytest

from messagefoundry.config import (
    alerts_edit,
    atomic_edit,
    codeset_edit,
    connections_edit,
    security_edit,
)
from messagefoundry.config.code_sets import load_code_set
from messagefoundry.config.wiring import WiringError, load_config

posix_only = pytest.mark.skipif(sys.platform == "win32", reason="POSIX permission bits")

#: A join bound for threads that should finish promptly, so a deadlock fails instead of hanging.
_JOIN_S = 20.0

LOGIC_PY = textwrap.dedent(
    """
    from messagefoundry import Send, handler, router

    @router("r")
    def route(msg):
        return ["h"]

    @handler("h")
    def handle(msg):
        return Send("OB_TOML", msg)
    """
)

CONNECTIONS_TOML = textwrap.dedent(
    """
    # A hand-authored comment.
    [[inbound]]
    name = "IB_TOML"
    transport = "mllp"
    router = "r"
    [inbound.settings]
    port = 2600

    [[outbound]]
    name = "OB_TOML"
    transport = "mllp"
    [outbound.settings]
    host = "127.0.0.1"
    port = 2700
    """
)

SETTINGS_TOML = "# keep me\n[security]\nrequire_mfa = true\n"


def _refuse(_path: Path) -> None:
    raise ValueError("simulated load failure")


def _noop(_path: Path) -> None:
    return None


# --- one row per editor: (live file, an edit that calls validate) ---------------------------------

Edit = Callable[[Callable[[Path], None]], object]


def _security(tmp_path: Path) -> tuple[Path, Edit]:
    path = tmp_path / "messagefoundry.toml"
    path.write_text(SETTINGS_TOML, encoding="utf-8")
    return path, lambda v: security_edit.set_security(path, {"require_mfa": False}, validate=v)


def _alerts(tmp_path: Path) -> tuple[Path, Edit]:
    path = tmp_path / "messagefoundry.toml"
    path.write_text(SETTINGS_TOML, encoding="utf-8")
    return path, lambda v: alerts_edit.add_rule(
        path, {"event_type": "connection_stopped"}, validate=v
    )


def _codeset(tmp_path: Path) -> tuple[Path, Edit]:
    codeset_edit.upsert_code_set(
        tmp_path, "diets", ["code", "value"], [["A", "Apple"]], validate=_noop
    )
    path = tmp_path / "codesets" / "diets.csv"
    return path, lambda v: codeset_edit.upsert_code_set(
        tmp_path, "diets", ["code", "value"], [["A", "Avocado"]], validate=v
    )


def _connections(tmp_path: Path) -> tuple[Path, Edit]:
    path = tmp_path / "connections.toml"
    path.write_text(CONNECTIONS_TOML, encoding="utf-8")
    entry: dict[str, object] = {"direction": "outbound", "name": "OB_NEW", "transport": "mllp"}
    entry["settings"] = {"host": "127.0.0.1", "port": 2702}
    return path, lambda v: connections_edit.upsert_connection(tmp_path, entry, validate=v)


EDITORS = pytest.mark.parametrize(
    "make",
    [_security, _alerts, _codeset, _connections],
    ids=["security", "alert", "codeset", "conn"],
)


def _leftovers(directory: Path) -> list[str]:
    """Edit candidates or temp files an editor left behind (the lock sidecar is meant to stay)."""
    return sorted(p.name for p in directory.iterdir() if p.name.endswith((".edit", ".tmp")))


# --- the closing tests named by the row -----------------------------------------------------------


@posix_only
@EDITORS
def test_a_refused_edit_keeps_the_owner_only_mode_and_the_bytes(
    tmp_path: Path, make: Callable[[Path], tuple[Path, Edit]]
) -> None:
    """Closing step 5: the permission after a FAILED edit, on POSIX. The rollback used to rewrite the
    live file at the process umask and return without re-restricting it; now nothing is written."""
    path, edit = make(tmp_path)
    os.chmod(path, 0o600)
    before = path.read_bytes()
    with pytest.raises(ValueError):  # each editor's refusal type is a ValueError subclass
        edit(_refuse)
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert path.read_bytes() == before
    assert _leftovers(path.parent) == []


@posix_only
@EDITORS
def test_a_successful_edit_leaves_the_file_owner_only(
    tmp_path: Path, make: Callable[[Path], tuple[Path, Edit]]
) -> None:
    path, edit = make(tmp_path)
    os.chmod(path, 0o644)
    edit(_noop)
    assert stat.S_IMODE(path.stat().st_mode) == 0o600


@EDITORS
def test_validation_reads_a_candidate_while_the_live_file_is_unchanged(
    tmp_path: Path, make: Callable[[Path], tuple[Path, Edit]]
) -> None:
    """Closing step 1: the candidate is validated BEFORE it replaces the live file, so no reader ever
    sees unvalidated text at the live path. The candidate keeps the live name, which the loaders read."""
    path, edit = make(tmp_path)
    before = path.read_bytes()
    seen: list[Path] = []

    def check(arg: Path) -> None:
        seen.append(arg)
        assert path.read_bytes() == before  # still the old bytes while validating

    edit(check)
    assert len(seen) == 1
    if path.name == "connections.toml":
        assert seen[0] == path.parent  # connections_edit hands its callback the config dir
    else:
        assert seen[0] != path and seen[0].name == path.name
        assert seen[0].parent.parent == path.parent
    assert path.read_bytes() != before


def test_a_refused_new_file_is_never_created(tmp_path: Path) -> None:
    path = tmp_path / "messagefoundry.toml"
    with pytest.raises(security_edit.SecurityEditError):
        security_edit.set_security(path, {"require_mfa": True}, validate=_refuse)
    assert not path.exists()
    assert _leftovers(tmp_path) == []


def test_candidates_are_unique_and_cleaned_up(tmp_path: Path) -> None:
    """Closing step 2: no fixed ``<name>.tmp``. Each write gets its own private directory, which is
    gone afterwards whether the edit landed or was refused."""
    path = tmp_path / "messagefoundry.toml"
    path.write_text(SETTINGS_TOML, encoding="utf-8")
    seen: list[Path] = []
    for _ in range(3):
        atomic_edit.replace_validated(path, b"[security]\n", seen.append)
    with pytest.raises(ValueError):
        atomic_edit.replace_validated(path, b"[security]\n", _refuse)
    assert len({p.parent for p in seen}) == 3
    assert not any(p.parent.exists() for p in seen)
    assert _leftovers(tmp_path) == []
    assert not (tmp_path / "messagefoundry.toml.tmp").exists()


@posix_only
def test_the_candidate_is_owner_only_from_creation(tmp_path: Path) -> None:
    path = tmp_path / "messagefoundry.toml"
    modes: list[tuple[int, int]] = []

    def check(candidate: Path) -> None:
        modes.append(
            (stat.S_IMODE(candidate.stat().st_mode), stat.S_IMODE(candidate.parent.stat().st_mode))
        )

    atomic_edit.replace_validated(path, b"x = 1\n", check)
    assert modes == [(0o600, 0o700)]


def test_bytes_are_written_verbatim(tmp_path: Path) -> None:
    path = tmp_path / "f.toml"
    atomic_edit.replace_validated(path, b"a = 1\r\nb = 2\n", _noop)
    assert path.read_bytes() == b"a = 1\r\nb = 2\n"


def test_codeset_candidate_carries_its_policy_sidecar(tmp_path: Path) -> None:
    path, edit = _codeset(tmp_path)
    (path.parent / "diets.policy.toml").write_text('kind = "passthrough"\n', encoding="utf-8")
    sidecars: list[bool] = []

    def check(candidate: Path) -> None:
        sidecars.append((candidate.parent / "diets.policy.toml").is_file())
        load_code_set(candidate)

    edit(check)
    assert sidecars == [True]


def test_connections_candidate_is_what_load_config_reads(tmp_path: Path) -> None:
    """The real loader, not a stub: the candidate the edit validates is what ``load_config`` of the
    config dir loads, and a candidate that does not load leaves the live file as it was."""
    (tmp_path / "logic.py").write_text(LOGIC_PY, encoding="utf-8")
    path = tmp_path / "connections.toml"
    path.write_text(CONNECTIONS_TOML, encoding="utf-8")
    loaded: list[set[str]] = []

    def check(config_dir: Path) -> None:
        loaded.append(set(load_config(config_dir, allow_empty=True).outbound))

    ob: dict[str, object] = {"direction": "outbound", "name": "OB_NEW", "transport": "mllp"}
    ob["settings"] = {"host": "127.0.0.1", "port": 2702}
    connections_edit.upsert_connection(tmp_path, ob, validate=check)
    assert loaded == [{"OB_TOML", "OB_NEW"}]
    # The override is scoped to the validation: a later load reads the live file again.
    assert set(load_config(tmp_path).outbound) == {"OB_TOML", "OB_NEW"}

    before = path.read_bytes()
    bad: dict[str, object] = {"direction": "inbound", "name": "IB_BAD", "transport": "mllp"}
    bad.update(router="missing", settings={"port": 2601})

    def real(config_dir: Path) -> None:
        load_config(config_dir, allow_empty=True)

    with pytest.raises(WiringError):
        connections_edit.upsert_connection(tmp_path, bad, validate=real)
    assert path.read_bytes() == before
    assert _leftovers(tmp_path) == []


# --- closing step 4: the cross-process lock ---------------------------------------------------------


def _hold_lock(
    path: Path,
    held: threading.Event,
    release: threading.Event,
    action: Callable[[], None] = lambda: None,
) -> threading.Thread:
    """Start a thread that takes the lock, signals ``held``, waits for ``release``, then runs
    ``action`` before letting go."""

    def run() -> None:
        with atomic_edit.edit_lock(path):
            held.set()
            release.wait(_JOIN_S)
            action()

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    assert held.wait(_JOIN_S)
    return thread


def test_a_second_writer_waits_for_the_lock_and_loses_nothing(tmp_path: Path) -> None:
    """Another holder of the lock (a thread here, standing in for the CLI in another process: ``flock``
    and ``msvcrt.locking`` lock per handle, so threads exclude each other the same way) makes a writer
    wait, and the writer's read happens after the holder's write, so neither edit is lost."""
    path = tmp_path / "messagefoundry.toml"
    path.write_text(SETTINGS_TOML, encoding="utf-8")
    held, release, done = threading.Event(), threading.Event(), threading.Event()

    def holders_edit() -> None:
        # The holder's own read-modify-write of the same file, made while it still holds the lock.
        text = path.read_text(encoding="utf-8")
        path.write_text(text + "\n[alerts]\nrealert_seconds = 120\n", encoding="utf-8")

    holder = _hold_lock(path, held, release, holders_edit)

    def writer() -> None:
        alerts_edit.add_rule(path, {"event_type": "queue_buildup"}, validate=_noop)
        done.set()

    second = threading.Thread(target=writer, daemon=True)
    second.start()
    assert not done.wait(0.5)  # blocked on the lock, not finished
    release.set()
    holder.join(_JOIN_S)
    second.join(_JOIN_S)
    assert done.is_set()
    text = path.read_text(encoding="utf-8")
    assert "realert_seconds = 120" in text  # the holder's edit survived
    assert "queue_buildup" in text  # and so did the waiter's


def test_a_held_lock_times_out_in_the_editors_own_error_type(tmp_path: Path) -> None:
    path = tmp_path / "connections.toml"
    path.write_text(CONNECTIONS_TOML, encoding="utf-8")
    held, release = threading.Event(), threading.Event()
    holder = _hold_lock(path, held, release)
    try:
        with (
            pytest.raises(WiringError, match="another edit"),
            atomic_edit.edit_lock(path, busy_error=WiringError, timeout=0.2),
        ):
            pass
    finally:
        release.set()
        holder.join(_JOIN_S)


def test_the_lock_is_reentrant_within_a_thread(tmp_path: Path) -> None:
    """The engine's flag toggle holds the lock across its list and its upsert, and the upsert takes it
    again. A second ``flock`` on a new handle in one process would wait on the first forever."""
    path = tmp_path / "connections.toml"
    path.write_text(CONNECTIONS_TOML, encoding="utf-8")
    finished = threading.Event()

    def run() -> None:
        with connections_edit.locked(tmp_path):
            entry = next(
                e for e in connections_edit.list_connections(tmp_path) if e["name"] == "OB_TOML"
            )
            entry["flagged"] = True
            connections_edit.upsert_connection(tmp_path, entry, validate=_noop)
        finished.set()

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    thread.join(_JOIN_S)
    assert finished.is_set()
    assert "flagged = true" in path.read_text(encoding="utf-8")


def test_one_hidden_lock_file_per_directory(tmp_path: Path) -> None:
    """One lock per directory, and code sets take the CONFIG directory's: a renamed or removed code
    set leaves no lock file of its own behind, and nothing at all in ``codesets/``."""
    codesets = tmp_path / "codesets"
    assert atomic_edit.lock_path_for(codesets / "diets.csv") == codesets / ".mefor-edit.lock"
    assert atomic_edit.lock_path_for(tmp_path / "connections.toml") == tmp_path / ".mefor-edit.lock"
    codeset_edit.upsert_code_set(tmp_path, "diets", ["code", "value"], [["A", "B"]], validate=_noop)
    codeset_edit.rename_code_set(tmp_path, "diets", "meals", validate=_noop)
    assert sorted(p.name for p in codesets.iterdir()) == ["meals.csv"]
    assert (tmp_path / ".mefor-edit.lock").is_file()


def test_codeset_remove_waits_for_the_directory_lock(tmp_path: Path) -> None:
    """A remove cannot run in the middle of an upsert of the same stem, which would otherwise
    re-create the table it just reported removed."""
    codeset_edit.upsert_code_set(tmp_path, "diets", ["code", "value"], [["A", "B"]], validate=_noop)
    path = tmp_path / "codesets" / "diets.csv"
    held, release, done = threading.Event(), threading.Event(), threading.Event()
    # The config directory's lock, the one a connection edit (and the engine toggle) holds.
    holder = _hold_lock(tmp_path / "connections.toml", held, release)

    def remover() -> None:
        codeset_edit.remove_code_set(tmp_path, "diets", validate=_noop)
        done.set()

    thread = threading.Thread(target=remover, daemon=True)
    thread.start()
    assert not done.wait(0.5)
    assert path.exists()
    release.set()
    holder.join(_JOIN_S)
    thread.join(_JOIN_S)
    assert done.is_set() and not path.exists()


def test_a_mixed_ending_file_is_written_back_lf(tmp_path: Path) -> None:
    """One stray CRLF line does not reflow the whole file to CRLF."""
    path = tmp_path / "messagefoundry.toml"
    path.write_bytes(b"# keep me\r\n[security]\nrequire_mfa = true\n")
    security_edit.set_security(path, {"require_mfa": False}, validate=_noop)
    assert b"\r\n" not in path.read_bytes()


@pytest.mark.parametrize("ending", [b"\n", b"\r\n"], ids=["lf", "crlf"])
def test_an_edit_keeps_the_files_line_endings(tmp_path: Path, ending: bytes) -> None:
    path = tmp_path / "messagefoundry.toml"
    path.write_bytes(SETTINGS_TOML.encode("utf-8").replace(b"\n", ending))
    security_edit.set_security(path, {"require_mfa": False}, validate=_noop)
    data = path.read_bytes()
    assert b"require_mfa = false" in data
    assert data.count(ending) == data.count(b"\n")  # every line ends the same way


def test_a_candidate_error_names_the_live_file(tmp_path: Path) -> None:
    """A connection loaded from the candidate records the live ``connections.toml`` as its source, so
    an error or an editor link points at a file the operator has, not at a deleted candidate."""
    (tmp_path / "logic.py").write_text(LOGIC_PY, encoding="utf-8")
    (tmp_path / "connections.toml").write_text(CONNECTIONS_TOML, encoding="utf-8")
    sources: list[str] = []

    def check(config_dir: Path) -> None:
        registry = load_config(config_dir, allow_empty=True)
        sources.extend(str(c.source_file) for c in registry.outbound.values())

    ob: dict[str, object] = {"direction": "outbound", "name": "OB_NEW", "transport": "mllp"}
    ob["settings"] = {"host": "127.0.0.1", "port": 2702}
    connections_edit.upsert_connection(tmp_path, ob, validate=check)
    assert sources == [str(tmp_path / "connections.toml")] * 2


def test_a_stale_candidate_is_removed_and_a_fresh_one_kept(tmp_path: Path) -> None:
    """A killed editor's leftover candidate goes at the next edit of that file; one young enough to
    be a live edit (on a file system that could not lock) is left alone."""
    path = tmp_path / "messagefoundry.toml"
    path.write_text(SETTINGS_TOML, encoding="utf-8")
    stale = tmp_path / f".messagefoundry.toml.old12345{atomic_edit.CANDIDATE_DIR_SUFFIX}"
    fresh = tmp_path / f".messagefoundry.toml.new12345{atomic_edit.CANDIDATE_DIR_SUFFIX}"
    other = tmp_path / f".connections.toml.old12345{atomic_edit.CANDIDATE_DIR_SUFFIX}"
    # A sibling file whose name extends this one's: the prefix alone would match its candidates.
    sibling = tmp_path / f".messagefoundry.toml.bak.old12345{atomic_edit.CANDIDATE_DIR_SUFFIX}"
    for leftover in (stale, fresh, other, sibling):
        leftover.mkdir()
        (leftover / "x").write_text("x", encoding="utf-8")
    long_ago = os.stat(path).st_mtime - 3600
    os.utime(stale, (long_ago, long_ago))
    os.utime(other, (long_ago, long_ago))
    os.utime(sibling, (long_ago, long_ago))
    security_edit.set_security(path, {"require_mfa": False}, validate=_noop)
    assert not stale.exists()
    assert fresh.is_dir(), "a young candidate may be a live edit"
    assert other.is_dir(), "another file's candidate is that file's editor's to clear"
    assert sibling.is_dir(), "a sibling whose name extends this one's is another file"


def test_the_candidate_name_rule_matches_the_real_mkdtemp(tmp_path: Path) -> None:
    """The backup skip and the stale sweep both read candidates by name, so the rule is pinned to
    the directory the edit really creates, not to a hand-written example."""
    path = tmp_path / "messagefoundry.toml"
    path.write_text(SETTINGS_TOML, encoding="utf-8")
    seen: list[str] = []

    def check(candidate: Path) -> None:
        seen.append(candidate.parent.name)

    security_edit.set_security(path, {"require_mfa": False}, validate=check)
    assert len(seen) == 1
    assert atomic_edit.is_candidate_dir_name(seen[0], of=path.name)
    assert not atomic_edit.is_candidate_dir_name(seen[0], of="connections.toml")
    # An operator's own hidden directories that only share the suffix are not candidates.
    for name in (".edit", ".golden.edit", ".fixtures.v2.edit"):
        assert not atomic_edit.is_candidate_dir_name(name), name


@posix_only
def test_a_lock_file_planted_as_a_link_is_refused(tmp_path: Path) -> None:
    path = tmp_path / "messagefoundry.toml"
    path.write_text(SETTINGS_TOML, encoding="utf-8")
    target = tmp_path / "elsewhere"
    target.write_text("", encoding="utf-8")
    atomic_edit.lock_path_for(path).symlink_to(target)
    with pytest.raises(TimeoutError, match="is a link"), atomic_edit.edit_lock(path):
        pass
