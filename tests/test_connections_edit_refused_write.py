# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A ``connections.toml`` edit the file system refuses is a ``WiringError``, not an ``OSError``
(vault BACKLOG #3106 item 2).

The recommended container layout makes ``/config`` root-owned, or mounts it read-only, so the engine's
own account cannot write there. The console's connection-flag toggle then reached
``connections_edit`` and its ``OSError`` (``EACCES`` from the lock file or the candidate directory,
``EROFS`` on a read-only mount) left the API as a 500. The API maps ``WiringError`` to 409, so the
editor raises that instead, for every step before the replace and for none after it.

The refusals are simulated with monkeypatched raises, so the tests run on Windows too, and as root,
where a real root-owned directory would not refuse anything."""

from __future__ import annotations

import errno
import os
import tempfile
import textwrap
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from messagefoundry.config import atomic_edit, connections_edit, security_edit
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
    ],
    ids=["root-owned", "read-only"],
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
    def fake_open(path: Any, flags: int, mode: int = 0o777, **kwargs: Any) -> int:
        if when(Path(path)):
            raise refusal
        return _real_open(path, flags, mode, **kwargs)

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


def test_an_error_from_the_replace_is_never_converted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Only the steps before the replace are known not to have written anything; from the replace
    # onward the editor cannot say the file was not changed, so the error propagates as it is.
    _live(tmp_path)
    refusal = PermissionError(errno.EACCES, "Permission denied")

    monkeypatch.setattr(os, "replace", _raising(refusal))

    with pytest.raises(PermissionError) as caught:
        connections_edit.upsert_connection(tmp_path, ENTRY, validate=_noop)

    assert caught.value is refusal
    assert _leftovers(tmp_path) == []


def test_an_editor_that_does_not_opt_in_still_raises_the_os_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The other editors' callers catch OSError already, so their contract is unchanged.
    path = tmp_path / "messagefoundry.toml"
    path.write_text("[security]\nrequire_mfa = true\n", encoding="utf-8")
    refusal = OSError(errno.EROFS, "Read-only file system")

    monkeypatch.setattr(tempfile, "mkdtemp", _raising(refusal))

    with pytest.raises(OSError) as caught:
        security_edit.set_security(path, {"require_mfa": False}, validate=_noop)

    assert caught.value is refusal


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

    with pytest.raises(WiringError, match=r"create its edit lock \.mefor-edit\.lock"):
        connections_edit.upsert_connection(tmp_path, ENTRY, validate=_noop)
