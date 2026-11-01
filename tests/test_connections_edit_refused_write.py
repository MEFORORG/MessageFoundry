# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""An edit the file system refuses is the editor's own refusal, not an ``OSError`` (vault BACKLOG
#3106 item 2, #3765).

The recommended container layout makes ``/config`` root-owned, or mounts it read-only, so the engine's
own account cannot write there. The console's connection-flag toggle then reached
``connections_edit`` and its ``OSError`` (``EACCES`` from the lock file, the read, the candidate or
the replace, ``EROFS`` on a read-only mount) would leave the API as a 500. The API maps ``WiringError``
to 409, so the editor raises that instead, for every step that leaves the live file as it was and for
none after the replace. The other three editors refuse the same way, each in its own type.

The refusals are simulated with monkeypatched raises, so the tests run on Windows too, and as root,
where a real root-owned directory would not refuse anything. The Windows hold on a file has real
tests as well, because how Windows reports one is the point."""

from __future__ import annotations

import errno
import os
import shutil
import sys
import tempfile
import textwrap
import threading
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
    "flagged": True,
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


def _assert_refused(exc: WiringError, tmp_path: Path, refusal: OSError) -> None:
    message = str(exc)
    assert "connections.toml was not changed" in message
    assert refusal.errno is not None
    assert errno.errorcode[refusal.errno] in message
    # The message reaches the operator over the API; the host's directory stays in the log.
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
def test_the_engines_own_lock_refuses_the_same_way(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, make_refusal: Callable[[], OSError]
) -> None:
    refusal = make_refusal()
    # The flag toggle takes `locked` around its read-modify-write before the upsert takes it again.
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


def test_a_replace_error_that_is_not_a_refusal_keeps_its_own_type(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _live(tmp_path)
    fault = OSError(errno.ENOSPC, os.strerror(errno.ENOSPC))

    monkeypatch.setattr(os, "replace", _raising(fault))

    with pytest.raises(OSError) as caught:
        connections_edit.upsert_connection(tmp_path, ENTRY, validate=_noop)

    assert caught.value is fault


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
    real_text = Path.read_text

    def fake_bytes(self: Path) -> bytes:
        if self.name == name:
            raise refusal
        return real_bytes(self)

    def fake_text(self: Path, *args: Any, **kwargs: Any) -> str:
        if self.name == name:
            raise refusal
        return real_text(self, *args, **kwargs)

    monkeypatch.setattr(Path, "read_bytes", fake_bytes)
    monkeypatch.setattr(Path, "read_text", fake_text)


@REFUSALS
@pytest.mark.parametrize(
    "edit",
    [
        lambda d: connections_edit.upsert_connection(d, ENTRY, validate=_noop),
        lambda d: connections_edit.remove_connection(d, "OB_TOML", validate=_noop),
        # The flag toggle lists before it writes, so this read comes first on that path.
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

    with pytest.raises(WiringError, match="read it") as caught:
        edit(tmp_path)

    _assert_refused(caught.value, tmp_path, refusal)


RULE: dict[str, Any] = {"event_type": "connection_failed", "severity": "warning"}
RULES_TOML = '[alerts]\n[[alerts.rules]]\nevent_type = "connection_failed"\nseverity = "warning"\n'


def _alerts_add(path: Path) -> Any:
    return alerts_edit.add_rule(path, RULE, validate=_noop)


def _alerts_remove(path: Path) -> Any:
    return alerts_edit.remove_rule(path, 0, validate=_noop)


def _security_set(path: Path) -> Any:
    return security_edit.set_security(path, {"require_mfa": False}, validate=_noop)


def _codeset_upsert(path: Path) -> Any:
    return codeset_edit.upsert_code_set(
        path.parent.parent, "diets", ["key", "value"], [["a", "b"]], validate=_noop
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
    "edit",
    [_alerts_add, _alerts_remove, _security_set],
    ids=["alerts-add", "alerts-remove", "security"],
)
def test_the_settings_editors_refuse_a_read_in_their_own_type(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, edit: Callable[[Path], Any]
) -> None:
    path = tmp_path / "messagefoundry.toml"
    path.write_text(RULES_TOML, encoding="utf-8")
    refusal = PermissionError(errno.EACCES, "Permission denied")
    _refuse_reads(monkeypatch, refusal, path.name)

    with pytest.raises(
        (alerts_edit.AlertRuleError, security_edit.SecurityEditError), match="read it"
    ) as caught:
        edit(path)

    assert caught.value.__cause__ is refusal


def _code_set(tmp_path: Path) -> Path:
    path = tmp_path / "codesets" / "diets.csv"
    path.parent.mkdir()
    path.write_text("key,value\nx,y\n", encoding="utf-8")
    return path


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
    assert "flagged" in path.read_text(encoding="utf-8")


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
def test_a_real_hold_that_lets_go_inside_the_retry_lets_the_edit_land(tmp_path: Path) -> None:
    path = _live(tmp_path)
    holder = path.open("rb")
    timer = threading.Timer(0.2, holder.close)
    timer.start()
    try:
        connections_edit.upsert_connection(tmp_path, ENTRY, validate=_noop)
    finally:
        timer.join()

    assert "flagged" in path.read_text(encoding="utf-8")


@pytest.mark.parametrize("code", [errno.ENOSPC, errno.ENOENT], ids=["disk-full", "missing"])
def test_an_error_that_is_not_a_refusal_keeps_its_own_type(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, code: int
) -> None:
    # A full disk or a missing directory is not a permission problem, so it is not reported as one.
    _live(tmp_path)
    refusal = OSError(code, os.strerror(code))
    _refuse_open(monkeypatch, refusal, lambda p: p.name == atomic_edit.LOCK_FILE_NAME)

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
