# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""An edit the file system refuses is the editor's own refusal, not an ``OSError`` (vault BACKLOG
#3106 item 2, #3765).

The recommended container layout makes ``/config`` root-owned, or mounts it read-only, so a
``connection`` CLI edit run under an account that cannot write there meets an ``OSError`` (``EACCES``
from the lock file, the read, the candidate or the replace, ``EROFS`` on a read-only mount). The
editor raises ``WiringError`` instead, for every step that leaves the live file as it was and for
none after the replace. The other three editors refuse the same way, each in its own type. The
running engine writes no config file, so no route meets this (BACKLOG #2623).

The refusals are simulated with monkeypatched raises, so the tests run on Windows too, and as root,
where a real root-owned directory would not refuse anything. The Windows hold on a file has real
tests as well, because how Windows reports one is the point."""

from __future__ import annotations

import errno
import os
import shutil
import subprocess
import sys
import tempfile
import textwrap
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from messagefoundry import restricted_file
from messagefoundry.config import (
    alerts_edit,
    atomic_edit,
    codeset_edit,
    connections_edit,
    security_edit,
)
from messagefoundry.config.wiring import WiringError

CONNECTIONS_TOML = textwrap.dedent(
    """
    # A hand-authored comment.
    [[outbound]]
    name = "OB_TOML"
    transport = "mllp"
    [outbound.settings]
    host = "127.0.0.1"
    port = 2700
    """
)

ENTRY: dict[str, Any] = {
    "direction": "outbound",
    "name": "OB_TOML",
    "transport": "mllp",
    "deployed": False,
    "settings": {"host": "127.0.0.1", "port": 2700},
}

# Factories, not instances: a shared instance would carry each run's traceback into the next.
REFUSALS = pytest.mark.parametrize(
    "make_refusal",
    [
        lambda: PermissionError(errno.EACCES, "Permission denied"),
        lambda: OSError(errno.EROFS, "Read-only file system"),
        lambda: PermissionError(errno.EPERM, "Operation not permitted"),
    ],
    ids=["root-owned", "read-only", "not-permitted"],
)

_real_open = os.open


def _noop(_path: Path) -> None:
    return None


def _live(tmp_path: Path) -> Path:
    path = tmp_path / "connections.toml"
    path.write_bytes(CONNECTIONS_TOML.encode("utf-8"))
    return path


def _refuse_open(
    monkeypatch: pytest.MonkeyPatch, refusal: OSError, when: Callable[[Path], bool]
) -> None:
    def fake_open(path: Any, flags: int, *args: Any, **kwargs: Any) -> int:
        if when(Path(path)):
            raise refusal
        return _real_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(os, "open", fake_open)


def _raising(exc: OSError) -> Callable[..., Any]:
    def fake(*_args: Any, **_kwargs: Any) -> Any:
        raise exc

    return fake


def _assert_refused(
    exc: WiringError,
    tmp_path: Path,
    refusal: OSError,
    lead: str = "connections.toml was not changed",
) -> None:
    message = str(exc)
    assert lead in message
    assert refusal.errno is not None
    assert errno.errorcode[refusal.errno] in message
    # The host's directory stays in the log.
    assert str(tmp_path) not in message
    assert exc.__cause__ is refusal


def _leftovers(directory: Path) -> list[str]:
    return sorted(p.name for p in directory.iterdir() if p.name.endswith(".edit"))


@REFUSALS
def test_a_lock_file_it_cannot_create_is_a_wiring_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, make_refusal: Callable[[], OSError]
) -> None:
    refusal = make_refusal()
    path = _live(tmp_path)
    before = path.read_bytes()
    _refuse_open(monkeypatch, refusal, lambda p: p.name == atomic_edit.LOCK_FILE_NAME)

    with pytest.raises(WiringError) as caught:
        connections_edit.upsert_connection(tmp_path, ENTRY, validate=_noop)

    _assert_refused(caught.value, tmp_path, refusal)
    assert path.read_bytes() == before


@REFUSALS
def test_the_lock_itself_refuses_the_same_way(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, make_refusal: Callable[[], OSError]
) -> None:
    refusal = make_refusal()
    # A caller may take `locked` around a read-modify-write before the upsert takes it again.
    _live(tmp_path)
    _refuse_open(monkeypatch, refusal, lambda p: p.name == atomic_edit.LOCK_FILE_NAME)

    with pytest.raises(WiringError) as caught, connections_edit.locked(tmp_path):
        pass

    _assert_refused(caught.value, tmp_path, refusal)


@REFUSALS
def test_a_candidate_directory_it_cannot_create_is_a_wiring_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, make_refusal: Callable[[], OSError]
) -> None:
    refusal = make_refusal()
    path = _live(tmp_path)
    before = path.read_bytes()
    validated: list[Path] = []

    monkeypatch.setattr(tempfile, "mkdtemp", _raising(refusal))

    with pytest.raises(WiringError) as caught:
        connections_edit.upsert_connection(tmp_path, ENTRY, validate=validated.append)

    _assert_refused(caught.value, tmp_path, refusal)
    assert path.read_bytes() == before
    assert validated == []


@REFUSALS
def test_a_candidate_it_cannot_write_is_a_wiring_error_and_cleaned_up(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, make_refusal: Callable[[], OSError]
) -> None:
    refusal = make_refusal()
    path = _live(tmp_path)
    before = path.read_bytes()
    _refuse_open(
        monkeypatch,
        refusal,
        lambda p: p.parent.name.endswith(atomic_edit.CANDIDATE_DIR_SUFFIX),
    )

    with pytest.raises(WiringError) as caught:
        connections_edit.remove_connection(tmp_path, "OB_TOML", validate=_noop)

    _assert_refused(caught.value, tmp_path, refusal)
    assert path.read_bytes() == before
    assert _leftovers(tmp_path) == []


@REFUSALS
def test_a_replace_it_is_refused_is_a_wiring_error_and_the_live_file_stays(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, make_refusal: Callable[[], OSError]
) -> None:
    # A rename that fails has not happened, so this is a refused edit like the steps before it.
    refusal = make_refusal()
    path = _live(tmp_path)
    before = path.read_bytes()

    monkeypatch.setattr(os, "replace", _raising(refusal))

    with pytest.raises(WiringError, match="replace it with the validated edit") as caught:
        connections_edit.upsert_connection(tmp_path, ENTRY, validate=_noop)

    _assert_refused(caught.value, tmp_path, refusal)
    assert path.read_bytes() == before
    assert _leftovers(tmp_path) == []


def test_an_error_after_the_replace_is_never_converted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The edit has landed by then, so "was not changed" would be false.
    path = _live(tmp_path)
    before = path.read_bytes()
    refusal = PermissionError(errno.EACCES, "Permission denied")

    monkeypatch.setattr(atomic_edit, "_secure_file", _raising(refusal))

    with pytest.raises(PermissionError) as caught:
        connections_edit.upsert_connection(tmp_path, ENTRY, validate=_noop)

    assert caught.value is refusal
    assert path.read_bytes() != before


def test_an_error_from_the_validate_callback_is_never_converted(
    tmp_path: Path,
) -> None:
    # The callback owns its wording, and an OSError from it is not this file's refusal.
    path = _live(tmp_path)
    before = path.read_bytes()
    refusal = PermissionError(errno.EACCES, "Permission denied")

    with pytest.raises(PermissionError) as caught:
        connections_edit.upsert_connection(tmp_path, ENTRY, validate=_raising(refusal))

    assert caught.value is refusal
    assert path.read_bytes() == before


def _refuse_reads(monkeypatch: pytest.MonkeyPatch, refusal: OSError, name: str) -> None:
    real_bytes = Path.read_bytes

    def fake_bytes(self: Path) -> bytes:
        if self.name == name:
            raise refusal
        return real_bytes(self)

    monkeypatch.setattr(Path, "read_bytes", fake_bytes)


def _refuse_stat(monkeypatch: pytest.MonkeyPatch, refusal: OSError, name: str) -> None:
    """What a real stat failure does: ``Path.stat`` raises and ``Path``'s predicates catch it and
    answer ``False``. They go round ``Path.stat`` to ``os.path``, so patching that alone would leave
    them answering for the real file on disk, and a gate that used them would look like it refused."""
    real_stat = Path.stat

    def fake_stat(self: Path, *, follow_symlinks: bool = True) -> os.stat_result:
        if self.name == name:
            raise refusal
        return real_stat(self, follow_symlinks=follow_symlinks)

    monkeypatch.setattr(Path, "stat", fake_stat)
    for predicate in ("is_file", "is_dir", "exists"):
        real = getattr(Path, predicate)

        def fake(self: Path, *args: Any, real: Any = real, **kwargs: Any) -> bool:
            return False if self.name == name else bool(real(self, *args, **kwargs))

        monkeypatch.setattr(Path, predicate, fake)


@REFUSALS
@pytest.mark.parametrize(
    "edit",
    [
        lambda d: connections_edit.upsert_connection(d, ENTRY, validate=_noop),
        lambda d: connections_edit.remove_connection(d, "OB_TOML", validate=_noop),
        # A read-modify-write lists before it writes, so this read comes first on that path.
        connections_edit.list_connections,
    ],
    ids=["upsert", "remove", "list"],
)
def test_a_file_it_cannot_read_is_a_wiring_error(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    make_refusal: Callable[[], OSError],
    edit: Callable[[Path], Any],
) -> None:
    refusal = make_refusal()
    _live(tmp_path)
    _refuse_reads(monkeypatch, refusal, "connections.toml")

    with pytest.raises(WiringError) as caught:
        edit(tmp_path)

    _assert_refused(caught.value, tmp_path, refusal, lead="connections.toml could not be read")


RULE: dict[str, Any] = {"event_type": "connection_failed", "severity": "warning"}
RULES_TOML = '[alerts]\n[[alerts.rules]]\nevent_type = "connection_failed"\nseverity = "warning"\n'


def _alerts_add(path: Path) -> Any:
    return alerts_edit.add_rule(path, RULE, validate=_noop)


def _alerts_remove(path: Path) -> Any:
    return alerts_edit.remove_rule(path, 0, validate=_noop)


def _security_set(path: Path) -> Any:
    return security_edit.set_security(path, {"require_mfa": False}, validate=_noop)


def _codeset_upsert(
    path: Path, *, validate: Callable[[Path], None] = _noop, create: bool = False
) -> Any:
    return codeset_edit.upsert_code_set(
        path.parent.parent,
        "diets",
        ["key", "value"],
        [["a", "b"]],
        validate=validate,
        create=create,
    )


# What each of the other three editors edits, how, and the refusal type it names.
EDITORS = pytest.mark.parametrize(
    ("relative", "content", "edit", "refused"),
    [
        ("messagefoundry.toml", RULES_TOML, _alerts_add, alerts_edit.AlertRuleError),
        ("messagefoundry.toml", RULES_TOML, _alerts_remove, alerts_edit.AlertRuleError),
        (
            "messagefoundry.toml",
            "[security]\nrequire_mfa = true\n",
            _security_set,
            security_edit.SecurityEditError,
        ),
        ("codesets/diets.csv", "key,value\nx,y\n", _codeset_upsert, WiringError),
    ],
    ids=["alerts-add", "alerts-remove", "security", "codeset"],
)


def _refuse_lock(monkeypatch: pytest.MonkeyPatch, refusal: OSError) -> None:
    _refuse_open(monkeypatch, refusal, lambda p: p.name == atomic_edit.LOCK_FILE_NAME)


def _refuse_candidate_dir(monkeypatch: pytest.MonkeyPatch, refusal: OSError) -> None:
    monkeypatch.setattr(tempfile, "mkdtemp", _raising(refusal))


def _refuse_candidate(monkeypatch: pytest.MonkeyPatch, refusal: OSError) -> None:
    _refuse_open(
        monkeypatch,
        refusal,
        lambda p: p.parent.name.endswith(atomic_edit.CANDIDATE_DIR_SUFFIX),
    )


def _refuse_replace(monkeypatch: pytest.MonkeyPatch, refusal: OSError) -> None:
    monkeypatch.setattr(os, "replace", _raising(refusal))


@EDITORS
@pytest.mark.parametrize(
    ("step", "refuse"),
    [
        ("create or open its edit lock", _refuse_lock),
        ("create its edit candidate", _refuse_candidate_dir),
        ("write its edit candidate", _refuse_candidate),
        ("replace it with the validated edit", _refuse_replace),
    ],
    ids=["lock", "candidate-dir", "candidate", "replace"],
)
def test_the_other_editors_refuse_each_step_in_their_own_type(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    relative: str,
    content: str,
    edit: Callable[[Path], Any],
    refused: type[Exception],
    step: str,
    refuse: Callable[[pytest.MonkeyPatch, OSError], None],
) -> None:
    path = tmp_path / relative
    path.parent.mkdir(exist_ok=True)
    path.write_bytes(content.encode("utf-8"))
    refusal = OSError(errno.EROFS, "Read-only file system")
    refuse(monkeypatch, refusal)

    with pytest.raises(refused, match=step) as caught:
        edit(path)

    assert "was not changed" in str(caught.value)
    assert caught.value.__cause__ is refusal
    assert path.read_bytes() == content.encode("utf-8")


@pytest.mark.parametrize(
    ("edit", "refused"),
    [
        (_alerts_add, alerts_edit.AlertRuleError),
        (_alerts_remove, alerts_edit.AlertRuleError),
        (alerts_edit.list_rules, alerts_edit.AlertRuleError),
        (_security_set, security_edit.SecurityEditError),
        # The security CLI reads through here before it sets, so this read comes first there.
        (security_edit.read_security, security_edit.SecurityEditError),
    ],
    ids=["alerts-add", "alerts-remove", "alerts-list", "security-set", "security-read"],
)
def test_the_settings_editors_refuse_a_read_in_their_own_type(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    edit: Callable[[Path], Any],
    refused: type[Exception],
) -> None:
    path = tmp_path / "messagefoundry.toml"
    path.write_text(RULES_TOML, encoding="utf-8")
    refusal = PermissionError(errno.EACCES, "Permission denied")
    _refuse_reads(monkeypatch, refusal, path.name)

    with pytest.raises(refused, match="could not be read") as caught:
        edit(path)

    assert caught.value.__cause__ is refusal


def test_a_read_refusal_gives_read_advice_not_write_advice(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A read-only directory refuses no read, so naming one would send an operator the wrong way.
    _live(tmp_path)
    _refuse_reads(
        monkeypatch, PermissionError(errno.EACCES, "Permission denied"), "connections.toml"
    )

    with pytest.raises(WiringError) as caught:
        connections_edit.list_connections(tmp_path)

    assert "read-only" not in str(caught.value)
    assert "was not changed" not in str(caught.value)
    assert "give this account access" in str(caught.value)


def _connection_upsert(path: Path) -> Any:
    return connections_edit.upsert_connection(path.parent, ENTRY, validate=_noop)


def _connection_remove(path: Path) -> Any:
    return connections_edit.remove_connection(path.parent, "OB_TOML", validate=_noop)


def _connection_list(path: Path) -> Any:
    return connections_edit.list_connections(path.parent)


@pytest.mark.parametrize(
    ("name", "content", "edit", "refused"),
    [
        ("messagefoundry.toml", RULES_TOML, _alerts_add, alerts_edit.AlertRuleError),
        ("messagefoundry.toml", RULES_TOML, _alerts_remove, alerts_edit.AlertRuleError),
        ("messagefoundry.toml", RULES_TOML, alerts_edit.list_rules, alerts_edit.AlertRuleError),
        ("messagefoundry.toml", RULES_TOML, _security_set, security_edit.SecurityEditError),
        (
            "messagefoundry.toml",
            RULES_TOML,
            security_edit.read_security,
            security_edit.SecurityEditError,
        ),
        ("connections.toml", CONNECTIONS_TOML, _connection_upsert, WiringError),
        ("connections.toml", CONNECTIONS_TOML, _connection_remove, WiringError),
        ("connections.toml", CONNECTIONS_TOML, _connection_list, WiringError),
    ],
    ids=[
        "alerts-add",
        "alerts-remove",
        "alerts-list",
        "security-set",
        "security-read",
        "connection-upsert",
        "connection-remove",
        "connection-list",
    ],
)
def test_a_path_it_cannot_stat_is_refused_rather_than_read_as_absent(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    name: str,
    content: str,
    edit: Callable[[Path], Any],
    refused: type[Exception],
) -> None:
    # Path.is_file answers False for a path it could not stat, as for a link into a directory this
    # account cannot search. Reading that as "no file" would make an edit start from an empty
    # document and replace the link, and a listing answer empty.
    path = tmp_path / name
    path.write_bytes(content.encode("utf-8"))
    replaced: list[Path] = []
    _refuse_stat(monkeypatch, PermissionError(errno.EACCES, "Permission denied"), name)
    monkeypatch.setattr(os, "replace", lambda src, _dst: replaced.append(Path(src)))

    with pytest.raises(refused, match="could not be read"):
        edit(path)

    assert replaced == []
    assert path.read_bytes() == content.encode("utf-8")


def test_a_path_that_is_no_regular_file_is_never_opened_to_read(tmp_path: Path) -> None:
    # The gate is a stat, not a read: a FIFO planted here would block the read, under the lock.
    path = tmp_path / "messagefoundry.toml"
    path.mkdir()

    assert atomic_edit.read_text_if_present(path, refused_error=WiringError) == (None, False)


def test_an_edit_of_a_file_that_is_not_there_creates_it(tmp_path: Path) -> None:
    path = tmp_path / "messagefoundry.toml"

    _security_set(path)

    assert "require_mfa" in path.read_text(encoding="utf-8")


def _code_set(tmp_path: Path) -> Path:
    path = tmp_path / "codesets" / "diets.csv"
    path.parent.mkdir()
    path.write_text("key,value\nx,y\n", encoding="utf-8")
    return path


def _code_set_create(path: Path) -> Any:
    return _codeset_upsert(path, create=True)


def _code_set_list(path: Path) -> Any:
    return codeset_edit.list_code_sets(path.parent.parent)


def _code_set_show(path: Path) -> Any:
    return codeset_edit.show_code_set(path.parent.parent, "diets")


def _code_set_remove(path: Path) -> Any:
    return codeset_edit.remove_code_set(path.parent.parent, "diets", validate=_noop)


def _code_set_rename_onto(path: Path) -> Any:
    # ``meals`` is the source, so the path under test is the rename's destination.
    (path.parent / "meals.csv").write_text("key,value\nx,y\n", encoding="utf-8")
    return codeset_edit.rename_code_set(path.parent.parent, "meals", "diets", validate=_noop)


def _link(link: Path, target: Path) -> None:
    link.parent.mkdir(exist_ok=True)
    try:
        link.symlink_to(target)
    except OSError as exc:
        # An account without the Windows symlink privilege; a Linux runner always reaches the test.
        pytest.skip(f"this account cannot create a link: {exc}")


# Every gate that answers whether a config path is there, and its refusal type.
GATES = pytest.mark.parametrize(
    ("relative", "edit", "refused"),
    [
        ("messagefoundry.toml", _alerts_add, alerts_edit.AlertRuleError),
        ("messagefoundry.toml", _alerts_remove, alerts_edit.AlertRuleError),
        ("messagefoundry.toml", alerts_edit.list_rules, alerts_edit.AlertRuleError),
        ("messagefoundry.toml", _security_set, security_edit.SecurityEditError),
        ("messagefoundry.toml", security_edit.read_security, security_edit.SecurityEditError),
        ("connections.toml", _connection_upsert, WiringError),
        ("connections.toml", _connection_remove, WiringError),
        ("connections.toml", _connection_list, WiringError),
    ],
    ids=[
        "alerts-add",
        "alerts-remove",
        "alerts-list",
        "security-set",
        "security-read",
        "connection-upsert",
        "connection-remove",
        "connection-list",
    ],
)

# The code-set gates, each with a table of the path's name the editor would otherwise miss.
CODE_SET_GATES = pytest.mark.parametrize(
    ("name", "edit"),
    [
        ("diets.csv", _code_set_create),
        ("diets.toml", _code_set_create),
        ("diets.csv", _codeset_upsert),
        ("diets.toml", _codeset_upsert),
        ("diets.csv", _code_set_list),
        ("diets.csv", _code_set_show),
        ("diets.csv", _code_set_remove),
        ("diets.toml", _code_set_rename_onto),
    ],
    ids=[
        "create-csv",
        "create-toml",
        "edit-csv",
        "edit-toml",
        "list",
        "show",
        "remove",
        "rename-onto",
    ],
)


class _WinError(OSError):
    """A Windows error by its code, on every platform: off Windows ``OSError`` drops a winerror."""

    def __init__(self, winerror: int) -> None:
        super().__init__(errno.EINVAL, "A Windows error")
        self.winerror = winerror


class _Unreachable(FileNotFoundError):
    """A share Windows could not reach, which CPython raises as ``FileNotFoundError``."""

    def __init__(self, winerror: int) -> None:
        super().__init__(errno.ENOENT, "The network path was not found")
        self.winerror = winerror


# A name no file can have, or nothing under a parent that is no directory. Each reads as absent,
# as Path.is_file answered, because no file is there to lose. The classifier is
# snapshot.is_missing_directory; real paths for what each platform answers are in a test below.
NO_SUCH_FILE = pytest.mark.parametrize(
    "make_failure",
    [
        lambda: NotADirectoryError(errno.ENOTDIR, "Not a directory"),
        lambda: OSError(errno.ENAMETOOLONG, "File name too long"),
        lambda: _WinError(123),
        lambda: _WinError(161),
        lambda: _WinError(206),
    ],
    ids=["enotdir", "enametoolong", "winerror-123", "winerror-161", "winerror-206"],
)

# Nothing in these says the file is not there: a link cycle, the Windows cycle, a disk fault, the
# two shares Windows says it could not reach, and ENOENT for a file that is there all the same,
# as from a share reconnecting or a writer between an unlink and a create.
UNKNOWN = pytest.mark.parametrize(
    "make_failure",
    [
        lambda: OSError(errno.ELOOP, "Too many levels of symbolic links"),
        lambda: _WinError(1921),
        lambda: OSError(errno.EIO, "Input/output error"),
        lambda: _Unreachable(53),
        lambda: _Unreachable(67),
        lambda: FileNotFoundError(errno.ENOENT, "No such file or directory"),
    ],
    ids=["eloop", "winerror-1921", "eio", "winerror-53", "winerror-67", "enoent-yet-there"],
)


@NO_SUCH_FILE
def test_a_name_no_file_can_have_reads_as_absent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, make_failure: Callable[[], OSError]
) -> None:
    path = tmp_path / "connections.toml"
    _refuse_stat(monkeypatch, make_failure(), path.name)

    assert not atomic_edit.is_file(path, refused_error=WiringError)
    assert not atomic_edit.is_dir(path, refused_error=WiringError)


@GATES
def test_every_gate_lets_a_name_no_file_can_have_through(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    relative: str,
    edit: Callable[[Path], Any],
    refused: type[Exception],
) -> None:
    # Only the stat answers here, so an edit goes on to create the file, where a raw OSError
    # escaped the gate. A remove finds nothing to remove, which is its own refusal.
    path = tmp_path / relative
    _refuse_stat(monkeypatch, NotADirectoryError(errno.ENOTDIR, "Not a directory"), path.name)

    try:
        edit(path)
    except refused as exc:
        assert "could not be read" not in str(exc)
    if edit in (_alerts_add, _security_set, _connection_upsert):
        assert path.read_bytes()


@pytest.mark.parametrize(
    "parts",
    [
        # Each path is real on both platforms: WinError 123 on Windows and a plain absence on POSIX
        # for the first, ENOENT or ENOTDIR for the second, WinError 123 or ENAMETOOLONG for the third.
        ("sub?", "messagefoundry.toml"),
        ("a-file", "messagefoundry.toml"),
        ("n" * 300,),
        # A NUL raises ValueError from the stat on both, not OSError.
        ("a\0b",),
    ],
    ids=["invalid-name", "file-as-parent", "too-long", "nul"],
)
@pytest.mark.parametrize(
    ("listing", "empty"),
    [(alerts_edit.list_rules, []), (security_edit.read_security, {})],
    ids=["alerts", "security"],
)
def test_a_real_path_no_file_can_have_lists_as_absent(
    tmp_path: Path, parts: tuple[str, ...], listing: Callable[[Path], Any], empty: Any
) -> None:
    (tmp_path / "a-file").write_bytes(b"")

    assert listing(tmp_path.joinpath(*parts)) == empty


def test_a_real_code_set_name_no_file_can_have_is_no_such_code_set(tmp_path: Path) -> None:
    (tmp_path / "codesets").mkdir()

    with pytest.raises(WiringError, match="no such code set"):
        codeset_edit.show_code_set(tmp_path, "sub?")


@NO_SUCH_FILE
def test_a_code_set_path_no_file_can_have_reads_as_absent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, make_failure: Callable[[], OSError]
) -> None:
    path = tmp_path / "codesets" / "diets.csv"
    path.parent.mkdir()
    _refuse_stat(monkeypatch, make_failure(), path.name)

    with pytest.raises(WiringError, match="no such code set"):
        _code_set_show(path)


@NO_SUCH_FILE
def test_a_codesets_folder_no_directory_can_have_lists_empty(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, make_failure: Callable[[], OSError]
) -> None:
    _refuse_stat(monkeypatch, make_failure(), "codesets")

    assert codeset_edit.list_code_sets(tmp_path) == []


@UNKNOWN
def test_a_stat_that_cannot_say_the_file_is_gone_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, make_failure: Callable[[], OSError]
) -> None:
    path = _live(tmp_path)
    failure = make_failure()
    _refuse_stat(monkeypatch, failure, path.name)

    for gate in (atomic_edit.is_file, atomic_edit.is_dir):
        with pytest.raises(WiringError, match="could not be read") as caught:
            gate(path, refused_error=WiringError)

        assert caught.value.__cause__ is failure


@GATES
def test_every_gate_refuses_a_stat_fault_and_leaves_the_file(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    relative: str,
    edit: Callable[[Path], Any],
    refused: type[Exception],
) -> None:
    path = tmp_path / relative
    before = b"x = 1\n"
    path.write_bytes(before)
    _refuse_stat(monkeypatch, OSError(errno.EIO, "Input/output error"), path.name)

    with pytest.raises(refused, match="could not be read"):
        edit(path)

    assert path.read_bytes() == before


def test_a_stat_fault_does_not_blame_another_account(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A permission is not the cause of a disk fault or a broken link, so the advice must not say so.
    path = _live(tmp_path)
    _refuse_stat(monkeypatch, OSError(errno.EIO, "Input/output error"), path.name)

    with pytest.raises(WiringError) as caught:
        connections_edit.list_connections(tmp_path)

    assert "Another account" not in str(caught.value)
    assert "EIO" in str(caught.value)
    assert str(tmp_path) not in str(caught.value)


@pytest.mark.parametrize("cycle", [False, True], ids=["dangling", "cycle"])
@GATES
def test_a_link_it_cannot_follow_is_refused_rather_than_replaced(
    tmp_path: Path,
    relative: str,
    edit: Callable[[Path], Any],
    refused: type[Exception],
    cycle: bool,
) -> None:
    # As for a file linked to an unmounted share: the rest of its content is there, not here.
    path = tmp_path / relative
    _link(path, path if cycle else tmp_path / "unmounted" / relative)

    with pytest.raises(refused, match="could not be read") as caught:
        edit(path)

    assert "link" in str(caught.value)
    assert path.is_symlink()
    assert not (tmp_path / "unmounted").exists()


@GATES
def test_a_config_folder_that_is_a_broken_link_is_refused_at_every_gate(
    tmp_path: Path,
    relative: str,
    edit: Callable[[Path], Any],
    refused: type[Exception],
) -> None:
    # A listing would answer empty, and an edit would fail its lock open as a raw FileNotFoundError.
    config = tmp_path / "config"
    _link(config, tmp_path / "unmounted")

    with pytest.raises(refused, match="could not be read"):
        edit(config / relative)


def test_a_file_that_is_not_there_under_a_healthy_link_is_absent(tmp_path: Path) -> None:
    # The positive control for the walk up the path: this link can be followed.
    (tmp_path / "real").mkdir()
    _link(tmp_path / "config", tmp_path / "real")

    assert connections_edit.list_connections(tmp_path / "config") == []


@pytest.mark.parametrize(
    "edit",
    [
        _codeset_upsert,
        _code_set_create,
        _code_set_show,
        _code_set_remove,
        lambda p: codeset_edit.rename_code_set(p.parent.parent, "diets", "meals", validate=_noop),
    ],
    ids=["edit", "create", "show", "remove", "rename"],
)
def test_a_codesets_folder_that_is_a_broken_link_refuses_every_code_set_edit(
    tmp_path: Path, edit: Callable[[Path], Any]
) -> None:
    # Its tables are on the far side of the link, so "no such code set" would be false.
    folder = tmp_path / "codesets"
    _link(folder, tmp_path / "unmounted")

    with pytest.raises(WiringError, match="could not be read"):
        edit(folder / "diets.csv")


@pytest.mark.skipif(sys.platform != "win32", reason="a Windows junction")
def test_a_dangling_junction_is_refused_rather_than_listed_empty(tmp_path: Path) -> None:
    # Path.is_symlink answers False for a junction, so this is the row a link test cannot stand for.
    target = tmp_path / "unmounted"
    target.mkdir()
    subprocess.run(
        ["cmd", "/c", "mklink", "/J", str(tmp_path / "codesets"), str(target)],
        check=True,
        capture_output=True,
        timeout=30,
    )
    target.rmdir()

    with pytest.raises(WiringError, match="could not be read"):
        codeset_edit.list_code_sets(tmp_path)


def test_a_link_to_a_real_file_reads_through_it(tmp_path: Path) -> None:
    # The positive control: the refusals above are for a link that cannot be followed.
    target = tmp_path / "elsewhere.toml"
    target.write_bytes(CONNECTIONS_TOML.encode("utf-8"))
    _link(tmp_path / "connections.toml", target)

    assert [entry["name"] for entry in connections_edit.list_connections(tmp_path)] == ["OB_TOML"]


def test_a_stat_failure_with_no_refusal_type_is_the_os_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The same contract as refused_as, for a caller of replace_validated that names no type.
    path = _live(tmp_path)
    failure = PermissionError(errno.EACCES, "Permission denied")
    _refuse_stat(monkeypatch, failure, path.name)

    with pytest.raises(PermissionError) as caught:
        atomic_edit.is_file(path, refused_error=None)

    assert caught.value is failure


def test_is_dir_answers_for_a_directory_and_nothing_else(tmp_path: Path) -> None:
    (tmp_path / "a-file").write_bytes(b"")

    assert atomic_edit.is_dir(tmp_path, refused_error=WiringError)
    assert not atomic_edit.is_dir(tmp_path / "a-file", refused_error=WiringError)
    assert not atomic_edit.is_dir(tmp_path / "missing", refused_error=WiringError)
    assert not atomic_edit.is_dir(tmp_path / "a-file" / "under", refused_error=WiringError)


@CODE_SET_GATES
def test_a_code_set_it_cannot_stat_is_refused_rather_than_read_as_absent(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    name: str,
    edit: Callable[[Path], Any],
) -> None:
    # The create row is the one that matters most: read as absent, the unstattable table would
    # pass the create-collision refusal and be overwritten.
    path = tmp_path / "codesets" / name
    path.parent.mkdir()
    path.write_bytes(b"key,value\nx,y\n" if name.endswith(".csv") else b"x = 'y'\n")
    before = path.read_bytes()
    failure = PermissionError(errno.EACCES, "Permission denied")
    _refuse_stat(monkeypatch, failure, path.name)

    with pytest.raises(WiringError, match="could not be read") as caught:
        edit(path)

    assert caught.value.__cause__ is failure
    assert path.read_bytes() == before


@CODE_SET_GATES
def test_a_dangling_code_set_link_is_refused_rather_than_read_as_absent(
    tmp_path: Path, name: str, edit: Callable[[Path], Any]
) -> None:
    # In the codesets folder, because a .csv link out of it fails _validate_name first.
    path = tmp_path / "codesets" / name
    _link(path, path.with_name("gone" + path.suffix))

    with pytest.raises(WiringError, match="could not be read"):
        edit(path)

    assert path.is_symlink()


def test_a_codesets_folder_it_cannot_stat_is_refused_rather_than_listed_empty(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _code_set(tmp_path)
    failure = PermissionError(errno.EACCES, "Permission denied")
    _refuse_stat(monkeypatch, failure, "codesets")

    with pytest.raises(WiringError, match="could not be read") as caught:
        codeset_edit.list_code_sets(tmp_path)

    assert caught.value.__cause__ is failure


def test_a_dangling_codesets_folder_is_refused_rather_than_listed_empty(tmp_path: Path) -> None:
    _link(tmp_path / "codesets", tmp_path / "unmounted")

    with pytest.raises(WiringError, match="could not be read"):
        codeset_edit.list_code_sets(tmp_path)


def test_a_codesets_folder_that_is_not_there_still_lists_empty(tmp_path: Path) -> None:
    assert codeset_edit.list_code_sets(tmp_path) == []


def test_a_listing_is_not_refused_over_a_file_it_never_reads(tmp_path: Path) -> None:
    # The positive control for the listing's gate: it must look at code sets only.
    path = _code_set(tmp_path)
    _link(path.with_name("notes.txt"), path.with_name("gone.txt"))

    assert [entry["name"] for entry in codeset_edit.list_code_sets(tmp_path)] == ["diets"]


def test_a_listing_is_not_refused_over_an_editors_lock_link(tmp_path: Path) -> None:
    # The name Emacs gives one: it has a table's suffix, and it dangles for as long as it exists.
    path = _code_set(tmp_path)
    _link(path.with_name(".#diets.csv"), path.with_name("user@host.1234"))

    assert [entry["name"] for entry in codeset_edit.list_code_sets(tmp_path)] == ["diets"]


def test_a_table_named_like_a_lock_link_is_still_listed(tmp_path: Path) -> None:
    # The loader reads it, so the skip above must stop at a link that dangles.
    path = _code_set(tmp_path)
    path.with_name(".#hidden.csv").write_bytes(path.read_bytes())

    assert ".#hidden" in [entry["name"] for entry in codeset_edit.list_code_sets(tmp_path)]


def test_a_codesets_folder_it_cannot_list_is_a_wiring_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The stat passes, as at mode 0311, so the gate alone does not catch this.
    _code_set(tmp_path)
    refusal = PermissionError(errno.EACCES, "Permission denied")
    monkeypatch.setattr(Path, "iterdir", _raising(refusal))

    with pytest.raises(WiringError, match="codesets could not be read") as caught:
        codeset_edit.list_code_sets(tmp_path)

    assert caught.value.__cause__ is refusal


def test_a_refusal_logs_a_listed_name_without_its_control_characters(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    name = "forged\r\nCRITICAL line.csv"
    _refuse_stat(monkeypatch, OSError(errno.EIO, "Input/output error"), name)

    with pytest.raises(WiringError):
        atomic_edit.is_file(tmp_path / name, refused_error=WiringError)

    assert [record for record in caplog.records if "\n" in record.getMessage()] == []


def test_a_folder_with_a_tables_name_still_collides(tmp_path: Path) -> None:
    path = _code_set(tmp_path)
    path.with_suffix(".toml").mkdir()

    with pytest.raises(WiringError, match="duplicate code set name"):
        _codeset_upsert(path)


def test_a_policy_sidecar_it_cannot_stat_is_never_left_out_of_the_candidate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Left out, the candidate would validate with no policy and the edit would land on that proof.
    path = _code_set(tmp_path)
    before = path.read_bytes()
    (path.parent / "diets.policy.toml").write_text("", encoding="utf-8")
    failure = PermissionError(errno.EACCES, "Permission denied")
    _refuse_stat(monkeypatch, failure, "diets.policy.toml")
    ran: list[Path] = []

    with pytest.raises(WiringError, match=r"diets\.policy\.toml could not be read") as caught:
        _codeset_upsert(path, validate=ran.append)

    assert caught.value.__cause__ is failure
    assert ran == []
    assert path.read_bytes() == before
    assert _leftovers(path.parent) == []


def test_a_dangling_policy_sidecar_is_never_left_out_of_the_candidate(tmp_path: Path) -> None:
    path = _code_set(tmp_path)
    before = path.read_bytes()
    _link(path.with_name("diets.policy.toml"), tmp_path / "unmounted.toml")
    ran: list[Path] = []

    with pytest.raises(WiringError, match=r"diets\.policy\.toml could not be read"):
        _codeset_upsert(path, validate=ran.append)

    assert ran == []
    assert path.read_bytes() == before


def test_a_code_set_rename_it_is_refused_is_a_wiring_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = _code_set(tmp_path)
    refusal = PermissionError(errno.EACCES, "Permission denied")
    monkeypatch.setattr(os, "replace", _raising(refusal))

    with pytest.raises(WiringError, match=r"rename it to meals\.csv") as caught:
        codeset_edit.rename_code_set(tmp_path, "diets", "meals", validate=_noop)

    assert caught.value.__cause__ is refusal
    assert path.is_file()


def test_a_code_set_remove_it_is_refused_is_a_wiring_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = _code_set(tmp_path)
    refusal = PermissionError(errno.EACCES, "Permission denied")
    monkeypatch.setattr(Path, "unlink", _raising(refusal))

    with pytest.raises(WiringError, match="remove it") as caught:
        codeset_edit.remove_code_set(tmp_path, "diets", validate=_noop)

    assert caught.value.__cause__ is refusal
    assert path.is_file()


def test_a_codesets_directory_it_cannot_create_is_a_wiring_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    refusal = OSError(errno.EROFS, "Read-only file system")
    monkeypatch.setattr(Path, "mkdir", _raising(refusal))

    with pytest.raises(WiringError, match="create its directory") as caught:
        _codeset_upsert(tmp_path / "codesets" / "diets.csv")

    assert caught.value.__cause__ is refusal


def test_a_policy_sidecar_it_cannot_copy_is_a_wiring_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = _code_set(tmp_path)
    before = path.read_bytes()
    (path.parent / "diets.policy.toml").write_text("", encoding="utf-8")
    refusal = PermissionError(errno.EACCES, "Permission denied")
    monkeypatch.setattr(shutil, "copyfile", _raising(refusal))

    with pytest.raises(WiringError, match=r"copy diets\.policy\.toml") as caught:
        _codeset_upsert(path)

    assert caught.value.__cause__ is refusal
    assert path.read_bytes() == before
    assert _leftovers(path.parent) == []


def test_a_caller_that_names_no_refusal_type_gets_the_os_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The engine's undo of a failed audit row replaces with no refused_error and catches OSError.
    path = _live(tmp_path)
    refusal = OSError(errno.EROFS, "Read-only file system")
    monkeypatch.setattr(os, "replace", _raising(refusal))

    with pytest.raises(OSError) as caught:
        atomic_edit.replace_validated(path, b"x = 1\n", _noop)

    assert caught.value is refusal


class _Held(PermissionError):
    """A Windows hold on a file, as a replace reports it, on every platform."""

    def __init__(self, winerror: int) -> None:
        super().__init__(errno.EACCES, "held")
        self.winerror = winerror


@pytest.mark.parametrize(
    "winerror",
    [restricted_file.WINERROR_SHARING_VIOLATION, restricted_file.WINERROR_ACCESS_DENIED],
    ids=["candidate-held", "live-file-held"],
)
def test_a_momentary_hold_on_the_replace_is_ridden_out(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, winerror: int
) -> None:
    # A virus scanner reading the new candidate is the common case, and it passes in moments.
    path = _live(tmp_path)
    real_replace = os.replace
    refusals = [_Held(winerror), _Held(winerror)]

    def held_then_free(src: Any, dst: Any) -> None:
        if refusals:
            raise refusals.pop()
        real_replace(src, dst)

    monkeypatch.setattr(os, "replace", held_then_free)

    connections_edit.upsert_connection(tmp_path, ENTRY, validate=_noop)

    assert refusals == []
    assert "deployed = false" in path.read_text(encoding="utf-8")


def test_a_code_set_rename_and_remove_ride_out_a_momentary_hold(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = _code_set(tmp_path)
    real_replace = os.replace
    real_unlink = Path.unlink
    refusals = [_Held(restricted_file.WINERROR_SHARING_VIOLATION) for _ in range(2)]

    def held_replace(src: Any, dst: Any) -> None:
        if len(refusals) == 2:
            raise refusals.pop()
        real_replace(src, dst)

    def held_unlink(self: Path, missing_ok: bool = False) -> None:
        if refusals:
            raise refusals.pop()
        real_unlink(self, missing_ok=missing_ok)

    monkeypatch.setattr(os, "replace", held_replace)
    monkeypatch.setattr(Path, "unlink", held_unlink)

    codeset_edit.rename_code_set(tmp_path, "diets", "meals", validate=_noop)
    moved = path.with_name("meals.csv")
    assert moved.is_file() and not path.exists()

    codeset_edit.remove_code_set(tmp_path, "meals", validate=_noop)
    assert not moved.exists()
    assert refusals == []


def test_a_hold_that_does_not_pass_is_refused_and_says_try_again(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = _live(tmp_path)
    before = path.read_bytes()
    refusal = _Held(restricted_file.WINERROR_SHARING_VIOLATION)
    monkeypatch.setattr(restricted_file, "_HELD_RETRY_S", 0.0)
    monkeypatch.setattr(os, "replace", _raising(refusal))
    monkeypatch.setattr(atomic_edit, "_WINDOWS", True)

    with pytest.raises(WiringError, match="Another program may have the file open") as caught:
        connections_edit.upsert_connection(tmp_path, ENTRY, validate=_noop)

    assert caught.value.__cause__ is refusal
    assert path.read_bytes() == before


@pytest.mark.parametrize(
    ("windows", "code", "names_a_holder"),
    [
        (True, errno.EACCES, True),
        (True, errno.EROFS, False),
        (False, errno.EACCES, False),
    ],
    ids=["windows-denied", "windows-read-only", "posix-denied"],
)
def test_only_a_windows_access_denied_names_a_holder(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    windows: bool,
    code: int,
    names_a_holder: bool,
) -> None:
    # EACCES on POSIX is a permission and nothing else, so saying "try again" there would mislead.
    _live(tmp_path)
    monkeypatch.setattr(atomic_edit, "_WINDOWS", windows)
    _refuse_lock(monkeypatch, OSError(code, os.strerror(code)))

    with pytest.raises(WiringError) as caught:
        connections_edit.upsert_connection(tmp_path, ENTRY, validate=_noop)

    assert ("Another program may have the file open" in str(caught.value)) is names_a_holder
    # The permission causes stay named on every path: Windows cannot rule them out either.
    assert "another account owns" in str(caught.value)


windows_only = pytest.mark.skipif(sys.platform != "win32", reason="a real Windows hold on a file")


@windows_only
def test_a_real_hold_on_the_live_file_is_refused_with_the_file_intact(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = _live(tmp_path)
    before = path.read_bytes()
    monkeypatch.setattr(restricted_file, "_HELD_RETRY_S", 0.1)

    with path.open("rb"), pytest.raises(WiringError, match="Another program may have") as caught:
        connections_edit.upsert_connection(tmp_path, ENTRY, validate=_noop)

    assert caught.value.__cause__ is not None
    assert path.read_bytes() == before
    assert _leftovers(tmp_path) == []


@windows_only
def test_a_real_hold_that_lets_go_inside_the_retry_lets_the_edit_land(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = _live(tmp_path)
    holder = path.open("rb")
    real_replace = os.replace
    refused: list[OSError] = []

    def lets_go_once_refused(src: Any, dst: Any) -> None:
        try:
            real_replace(src, dst)
        except PermissionError as exc:
            # Inside the first refusal, so the test proves the replace met the hold.
            refused.append(exc)
            holder.close()
            raise

    monkeypatch.setattr(os, "replace", lets_go_once_refused)
    try:
        connections_edit.upsert_connection(tmp_path, ENTRY, validate=_noop)
    finally:
        holder.close()

    assert len(refused) == 1
    assert "deployed = false" in path.read_text(encoding="utf-8")


@pytest.mark.parametrize("code", [errno.ENOSPC, errno.ENOENT], ids=["disk-full", "missing"])
@pytest.mark.parametrize("refuse", [_refuse_lock, _refuse_replace], ids=["lock", "replace"])
def test_an_error_that_is_not_a_refusal_keeps_its_own_type(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    code: int,
    refuse: Callable[[pytest.MonkeyPatch, OSError], None],
) -> None:
    # A full disk or a missing directory is not a permission problem, so it is not reported as one.
    _live(tmp_path)
    refusal = OSError(code, os.strerror(code))
    refuse(monkeypatch, refusal)

    with pytest.raises(OSError) as caught:
        connections_edit.upsert_connection(tmp_path, ENTRY, validate=_noop)

    assert caught.value is refusal


def test_the_message_names_the_step_the_file_system_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _live(tmp_path)
    refusal = PermissionError(errno.EACCES, "Permission denied")
    _refuse_open(monkeypatch, refusal, lambda p: p.name == atomic_edit.LOCK_FILE_NAME)

    with pytest.raises(WiringError, match=r"create or open its edit lock \.mefor-edit\.lock"):
        connections_edit.upsert_connection(tmp_path, ENTRY, validate=_noop)
