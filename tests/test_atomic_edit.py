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

import errno
import os
import re
import stat
import sys
import textwrap
import threading
from collections.abc import Callable
from pathlib import Path
from typing import Any

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
from tests._win_acl import assert_owner_only, folder_granting, protected_entries

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


def _connections_remove(tmp_path: Path) -> tuple[Path, Edit]:
    path = tmp_path / "connections.toml"
    path.write_text(CONNECTIONS_TOML, encoding="utf-8")
    return path, lambda v: connections_edit.remove_connection(tmp_path, "OB_TOML", validate=v)


@pytest.mark.parametrize(
    "make",
    [_security, _alerts, _codeset, _connections, _connections_remove],
    ids=["security", "alert", "codeset", "conn", "conn-remove"],
)
@pytest.mark.parametrize("ending", [b"\n", b"\r\n"], ids=["lf", "crlf"])
def test_a_refused_edit_leaves_the_file_byte_for_byte(
    tmp_path: Path, make: Callable[[Path], tuple[Path, Edit]], ending: bytes
) -> None:
    """Vault BACKLOG #2944 item 3: after a REFUSED toggle, the old rollback rewrote a CRLF
    connections.toml as LF. The toggle no longer writes the file (the flag lives in the store), so
    this pins the same guarantee on at least these file-writing entry points (not alerts
    ``remove_rule``). Both endings, because a text-mode rewrite flips one ending on each OS (CRLF
    to LF on POSIX, LF to CRLF on Windows). No platform skip, so it runs on the Windows test legs."""
    path, edit = make(tmp_path)
    # Give every line `ending`: write_text and the CSV writer each pick their own.
    path.write_bytes(path.read_bytes().replace(b"\r\n", b"\n").replace(b"\n", ending))
    before = path.read_bytes()
    lines = before.count(b"\n")
    assert lines > 0 and before.count(b"\r\n") == (lines if ending == b"\r\n" else 0)
    # The match pins the refusal to validate time, not an earlier read or parse of the file.
    with pytest.raises(ValueError, match="simulated load failure"):
        edit(_refuse)
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


# --- vault BACKLOG #5619: an edit keeps the file's owner, and never replaces a link ---------------

windows_only = pytest.mark.skipif(sys.platform != "win32", reason="a Windows access list")


def _make_link(link: Path, target: Path) -> None:
    try:
        link.symlink_to(target)
    except OSError as exc:
        # An account without the Windows symlink privilege; a Linux runner always reaches the test.
        pytest.skip(f"this account cannot create a link: {exc}")


@EDITORS
def test_an_edit_of_a_link_is_refused_and_leaves_the_link_and_its_target(
    tmp_path: Path, make: Callable[[Path], tuple[Path, Edit]]
) -> None:
    """The replace renames over the LINK, so the edit would have left a detached regular file where
    the link was and its target unedited. It is refused before anything is written."""
    path, edit = make(tmp_path)
    target = tmp_path / "elsewhere" / path.name
    target.parent.mkdir()
    target.write_bytes(path.read_bytes())
    before = target.read_bytes()
    path.unlink()
    _make_link(path, target)

    # Each refusal type is a ValueError. The code-set editor already refused a table that resolves
    # outside its folder before it reached the write path; the others reach the new refusal.
    with pytest.raises(ValueError, match="it is a link|escapes the codesets directory"):
        edit(_noop)

    assert path.is_symlink() and path.resolve() == target.resolve()
    assert target.read_bytes() == before
    assert _leftovers(path.parent) == []


def test_a_link_with_no_refusal_type_is_an_os_error(tmp_path: Path) -> None:
    target = tmp_path / "real.toml"
    target.write_text("x = 1\n", encoding="utf-8")
    link = tmp_path / "linked.toml"
    _make_link(link, target)

    with pytest.raises(OSError, match="it is a link") as caught:
        atomic_edit.replace_validated(link, b"x = 2\n", _noop)

    assert caught.value.errno == errno.ELOOP
    assert target.read_text(encoding="utf-8") == "x = 1\n"


def test_a_code_set_table_linked_inside_its_folder_is_refused(tmp_path: Path) -> None:
    # The code-set editor refuses a table that resolves outside codesets/ on its own, so the
    # parametrized test above cannot tell whether a link inside the folder reaches the new refusal.
    _, edit = _codeset(tmp_path)
    folder = tmp_path / "codesets"
    target = folder / "meals.csv"
    target.write_bytes((folder / "diets.csv").read_bytes())
    before = target.read_bytes()
    (folder / "diets.csv").unlink()
    _make_link(folder / "diets.csv", target)

    with pytest.raises(WiringError, match="it is a link"):
        edit(_noop)

    assert (folder / "diets.csv").is_symlink()
    assert target.read_bytes() == before


def _a_file_root_does_not_own(tmp_path: Path) -> tuple[Path, os.stat_result]:
    """A live connections.toml owned by an account other than root, even on a runner that is root."""
    path = tmp_path / "connections.toml"
    path.write_text(CONNECTIONS_TOML, encoding="utf-8")
    if os.geteuid() == 0:
        os.chown(path, 12345, 12345)
    return path, path.stat()


def _as_root(monkeypatch: pytest.MonkeyPatch, chown: Callable[..., None]) -> None:
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    monkeypatch.setattr(os, "getegid", lambda: 0)
    monkeypatch.setattr(os, "fchown", chown)


@posix_only
def test_root_gives_the_replaced_file_back_to_its_owner(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Root used to leave the edited file owned by root at 0600, so the service account that owns
    it could no longer read it. The chown is simulated, so this runs as any account."""
    path, st = _a_file_root_does_not_own(tmp_path)
    chowned: list[tuple[int, int]] = []

    def _record(_fd: int, uid: int, gid: int) -> None:
        chowned.append((uid, gid))

    _as_root(monkeypatch, _record)

    atomic_edit.replace_validated(path, b"x = 1\n", _noop)

    assert chowned == [(st.st_uid, st.st_gid)]
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert path.read_bytes() == b"x = 1\n"


@posix_only
def test_an_account_editing_its_own_file_changes_no_owner(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "connections.toml"
    path.write_text(CONNECTIONS_TOML, encoding="utf-8")
    st = path.stat()

    def _forbidden(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("an edit by the file's own account changed its owner")

    monkeypatch.setattr(os, "geteuid", lambda: st.st_uid)
    monkeypatch.setattr(os, "getegid", lambda: st.st_gid)
    monkeypatch.setattr(os, "fchown", _forbidden)

    atomic_edit.replace_validated(path, b"x = 1\n", _noop)

    assert path.read_bytes() == b"x = 1\n"


@posix_only
@pytest.mark.parametrize(
    ("refusal", "cause"),
    [
        (PermissionError(errno.EPERM, "Operation not permitted"), "may not change a file's owner"),
        # An owner id this mount or user namespace cannot map: the chown fails all the same, and
        # must reach the operator as a refused edit rather than a raw OSError.
        (OSError(errno.EINVAL, "Invalid argument"), "id may not exist"),
        (OSError(errno.EOVERFLOW, "Value too large for defined data type"), "id may not exist"),
        # A file system that keeps no owners: any failure here is before the rename.
        (OSError(errno.ENOSYS, "Function not implemented"), "may not change a file's owner"),
    ],
    ids=["EPERM", "EINVAL", "EOVERFLOW", "ENOSYS"],
)
def test_a_refused_chown_leaves_the_live_file_as_it_was(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, refusal: OSError, cause: str
) -> None:
    path, _ = _a_file_root_does_not_own(tmp_path)
    before = path.read_bytes()

    def _refused(*_args: object, **_kwargs: object) -> None:
        raise refusal

    _as_root(monkeypatch, _refused)

    with pytest.raises(WiringError, match="could not give the edited file back") as refused:
        atomic_edit.replace_validated(path, b"x = 1\n", _noop, refused_error=WiringError)

    assert cause in str(refused.value)

    assert path.read_bytes() == before
    assert _leftovers(tmp_path) == []


@posix_only
def test_a_lock_file_root_makes_is_given_to_the_folders_owner(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Root gives the edited file back to its owner, so a root-owned 0600 lock file would refuse
    # that owner's next edit. Simulated: the lock reads as root's and the folder as another's.
    path, _ = _a_file_root_does_not_own(tmp_path)
    given: list[tuple[int, int]] = []
    real_fstat, real_stat = os.fstat, os.stat
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    monkeypatch.setattr(os, "fstat", lambda fd: _with_uid(real_fstat(fd), 0))
    monkeypatch.setattr(
        os,
        "stat",
        lambda p, **kw: (
            _with_uid(real_stat(p, **kw), 777) if Path(p) == tmp_path else real_stat(p, **kw)
        ),
    )
    monkeypatch.setattr(os, "fchown", lambda _fd, uid, gid: given.append((uid, gid)))

    with atomic_edit.edit_lock(path):
        pass

    assert given == [(777, real_stat(tmp_path).st_gid)]


def _with_uid(st: os.stat_result, uid: int) -> os.stat_result:
    fields = list(st)
    fields[stat.ST_UID] = uid
    return os.stat_result(fields)


@posix_only
def test_a_lock_name_planted_as_a_hard_link_is_never_handed_over(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The folder's owner could hard-link the lock name to a file root owns; the hand-over must not
    # chown it. Simulated as root, like the test above.
    path, _ = _a_file_root_does_not_own(tmp_path)
    victim = tmp_path / "victim"
    victim.write_bytes(b"root's")
    os.link(victim, atomic_edit.lock_path_for(path))
    given: list[tuple[int, int]] = []
    real_fstat = os.fstat
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    monkeypatch.setattr(os, "fstat", lambda fd: _with_uid(real_fstat(fd), 0))
    monkeypatch.setattr(os, "fchown", lambda _fd, uid, gid: given.append((uid, gid)))

    with atomic_edit.edit_lock(path):
        pass

    assert given == []


#: An editing account no real account here is, reported through the token seam.
_EDITOR_SID = "S-1-5-21-1000000001-1000000002-1000000003-4242"


def _owner_and_grants(path: Path) -> tuple[str | None, list[str]]:
    """The owner and the granted SIDs of ``path``, each in ``S-1-...`` form."""
    _, owner, entries = protected_entries(path)
    return owner, [sid for *_, sid in entries]


def _real_owner(path: Path) -> str:
    from messagefoundry.store.store import _SDDL_OWNER, _read_dacl_sddl

    match = _SDDL_OWNER.search(_read_dacl_sddl(path, owner=True) or "")
    assert match is not None
    sid = atomic_edit._canonical_sid(match.group(1))
    assert sid is not None
    return sid


@windows_only
def test_a_file_another_account_owns_stays_that_accounts_on_windows(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An elevated administrator editing a file the service account owns used to restrict it to the
    administrator alone, so the service could no longer read it. Here the file's real owner plays
    the service account, and the token seam reports another account as the editor."""
    import messagefoundry.restricted_file as restricted_mod
    import messagefoundry.store.store as store_mod

    path = tmp_path / "connections.toml"
    path.write_text(CONNECTIONS_TOML, encoding="utf-8")
    owner = _real_owner(path)
    monkeypatch.setattr(store_mod, "_current_user_sid", lambda: _EDITOR_SID)
    # On Windows Server the owner is Administrators; it must still count as another account here.
    monkeypatch.setattr(restricted_mod, "administrators_enabled", lambda: False)

    atomic_edit.replace_validated(path, b"x = 1\n", _noop)

    assert _owner_and_grants(path) == (owner, [owner, _EDITOR_SID])
    assert path.read_bytes() == b"x = 1\n"


@windows_only
def test_a_foreign_owners_edited_file_passes_the_config_source_check_on_windows(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The owner keeps its grant so that it can load the file again (vault BACKLOG #5619), and the
    # loader refuses a config file a non-owner, non-admin account can write. So the editing account
    # may read the replaced file, never write it. Here this process is the owner, the account the
    # engine runs as, and the token seam reports another account as the editor.
    import messagefoundry.restricted_file as restricted_mod
    import messagefoundry.store.store as store_mod

    path = tmp_path / "connections.toml"
    path.write_text(CONNECTIONS_TOML, encoding="utf-8")
    owner = _real_owner(path)
    monkeypatch.setattr(store_mod, "_current_user_sid", lambda: _EDITOR_SID)
    monkeypatch.setattr(restricted_mod, "administrators_enabled", lambda: False)

    atomic_edit.replace_validated(path, b"x = 1\n", _noop)

    assert _config_verdict(path, owner) is None
    assert path.read_bytes() == b"x = 1\n"
    assert protected_entries(path)[2] == [("A", "", "FA", owner), ("A", "", "FR", _EDITOR_SID)]
    # The control: the same reader and check refuse this file once the editor may write it, the
    # list this path wrote before, so the verdict above is not passing on a reading it cannot make.
    written = store_mod._set_security_from_sddl(
        path, f"D:P(A;;FA;;;{owner})(A;;FA;;;{_EDITOR_SID})", protected=True
    )
    assert written.failure is None and written.dacl_status == 0, written
    assert (
        _config_verdict(path, owner)
        == f"a non-owner, non-admin principal ({_EDITOR_SID}) has write access"
    )


#: A service account no real account here is: the live file's foreign owner where this process
#: plays the editing administrator, so naming it as the owner is refused (no restore privilege).
_SERVICE_SID = "S-1-5-21-1000000001-1000000002-1000000003-7777"


def _config_verdict(path: Path, engine_sid: str) -> str | None:
    """What the config loader, running as ``engine_sid``, says of ``path``: ``None`` to accept."""
    from messagefoundry.config.wiring import _evaluate_config_dacl, _win32_config_source_probes

    probes = _win32_config_source_probes()
    security = probes.read_path(path)
    assert security.status == 0 and security.owner_sid is not None
    assert security.aces is not None
    return _evaluate_config_dacl(
        security.owner_sid, security.aces, engine_sid, probes.owner_in_admins
    )


@windows_only
@pytest.mark.parametrize("hand_back", ["succeeds", "refused"])
def test_a_foreign_owners_file_can_be_edited_again_on_windows(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, hand_back: str
) -> None:
    """A second edit after a foreign-owner edit, with the config loader's check after each.

    ``succeeds``: this process plays the file's owner, the service account, and the token seam
    reports another account as the editor, so the ownership hand-back is to this process itself.
    ``refused``: this process plays the editing administrator, and the owner is a service account
    no real account is, so Windows refuses to name it as the owner and this process keeps the file.
    Its folder grants this process Modify, which holds no right to delete another file in it, so
    the second edit can replace the file only through the file's own entry."""
    import messagefoundry.restricted_file as restricted_mod
    import messagefoundry.store.store as store_mod

    me = store_mod._current_user_sid()
    assert me is not None
    folder = tmp_path / "config"
    folder.mkdir()
    written = store_mod._set_security_from_sddl(
        folder, f"D:P(A;OICI;0x1301bf;;;{me})", protected=True
    )
    assert written.failure is None and written.dacl_status == 0, written
    path = folder / "connections.toml"
    path.write_text(CONNECTIONS_TOML, encoding="utf-8")
    monkeypatch.setattr(restricted_mod, "administrators_enabled", lambda: False)
    if hand_back == "succeeds":
        engine = _real_owner(path)
        monkeypatch.setattr(store_mod, "_current_user_sid", lambda: _EDITOR_SID)
    else:
        engine = _SERVICE_SID
        monkeypatch.setattr(atomic_edit, "_foreign_windows_owner", lambda _path: _SERVICE_SID)

    for text in (b"x = 1\n", b"x = 2\n"):
        atomic_edit.replace_validated(path, text, _noop)
        assert path.read_bytes() == text
        assert _config_verdict(path, engine) is None


@windows_only
def test_both_failed_list_writes_leave_a_foreign_owned_file_its_candidate_list_on_windows(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Both writes after the rename fail, but the candidate's list took: the file must keep it. The
    # store's _secure_file grants the editing account alone, so running it here would take the
    # owning account's entry (vault BACKLOG #5619). RED before the fix: it ran.
    import messagefoundry.restricted_file as restricted_mod
    import messagefoundry.store.store as store_mod

    path = tmp_path / "connections.toml"
    path.write_text(CONNECTIONS_TOML, encoding="utf-8")
    owner = _real_owner(path)
    monkeypatch.setattr(store_mod, "_current_user_sid", lambda: _EDITOR_SID)
    monkeypatch.setattr(restricted_mod, "administrators_enabled", lambda: False)
    monkeypatch.setattr(atomic_edit, "_restrict_to_owner_and_editor", lambda _path, _owner: False)
    real_restrict = atomic_edit._restrict_to_editor

    def _refused_after_the_rename(
        target: Path, *, owner: str | None = None, editor_writes: bool = False
    ) -> bool:
        if target == path:
            return False
        return real_restrict(target, owner=owner, editor_writes=editor_writes)

    monkeypatch.setattr(atomic_edit, "_restrict_to_editor", _refused_after_the_rename)
    secured: list[Path] = []
    monkeypatch.setattr(atomic_edit, "_secure_file", secured.append)

    atomic_edit.replace_validated(path, b"x = 1\n", _noop)

    assert secured == []
    assert protected_entries(path)[2] == [("A", "", "FA", owner), ("A", "", "FA", _EDITOR_SID)]
    assert path.read_bytes() == b"x = 1\n"


@windows_only
def test_a_failed_owner_and_editor_list_write_keeps_the_foreign_owners_grant_on_windows(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # When the owner-and-editor list write after the rename fails, the fallback list must still
    # name the account that owns the file, or that account could no longer read it (vault BACKLOG
    # #5619). The candidate's own list write fails too, so the file reaches the fallback with its
    # staging directory's inherited list, and only the fallback's own write can pass this test.
    import messagefoundry.restricted_file as restricted_mod
    import messagefoundry.store.store as store_mod

    path = tmp_path / "connections.toml"
    path.write_text(CONNECTIONS_TOML, encoding="utf-8")
    owner = _real_owner(path)
    monkeypatch.setattr(store_mod, "_current_user_sid", lambda: _EDITOR_SID)
    monkeypatch.setattr(restricted_mod, "administrators_enabled", lambda: False)
    monkeypatch.setattr(atomic_edit, "_restrict_to_owner_and_editor", lambda _path, _owner: False)
    real_write = store_mod._set_security_from_sddl

    def _candidate_refused(target: Path, sddl: str, *, protected: bool) -> Any:
        if target != path:
            return store_mod._SddlWrite(failure="refused for the test")
        return real_write(target, sddl, protected=protected)

    monkeypatch.setattr(store_mod, "_set_security_from_sddl", _candidate_refused)
    secured: list[Path] = []
    monkeypatch.setattr(atomic_edit, "_secure_file", secured.append)

    atomic_edit.replace_validated(path, b"x = 1\n", _noop)

    assert secured == []
    assert protected_entries(path)[2] == [("A", "", "FA", owner), ("A", "", "FR", _EDITOR_SID)]
    assert path.read_bytes() == b"x = 1\n"


@windows_only
def test_a_file_this_account_owns_is_still_made_owner_only_on_windows(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The edit's own-account path leaves the file its owner's alone. The folder grants only this
    # account and SYSTEM, so an entry for Administrators or OWNER RIGHTS can come only from the edit's
    # own staging: Python 3.13+ writes both, and SYSTEM, on the mkdtemp directory, and the rename
    # used to carry them onto the file. The token seam reports the file's real owner, so the test
    # means the same on every runner.
    path, owner = _an_own_file_in_a_folder_without_staging_entries(tmp_path, monkeypatch)
    handed_back: list[str] = []

    def _hand_back(_path: Path, foreign: str) -> bool:
        handed_back.append(foreign)
        return True

    monkeypatch.setattr(atomic_edit, "_restrict_to_owner_and_editor", _hand_back)

    atomic_edit.replace_validated(path, b"x = 1\n", _noop)

    assert handed_back == [], "an edit by the file's own account took the foreign-owner path"
    assert_owner_only(path, owner)
    assert path.read_bytes() == b"x = 1\n"


@pytest.mark.parametrize(
    ("owner", "editor", "editor_writes", "expected"),
    [
        ("S-1-5-80-1", "S-1-5-21-9", False, "D:P(A;;FA;;;S-1-5-80-1)(A;;FR;;;S-1-5-21-9)"),
        ("S-1-5-80-1", "S-1-5-21-9", True, "D:P(A;;FA;;;S-1-5-80-1)(A;;FA;;;S-1-5-21-9)"),
        (None, "S-1-5-21-9", False, "D:P(A;;FA;;;S-1-5-21-9)"),
        ("S-1-5-21-9", "S-1-5-21-9", False, "D:P(A;;FA;;;S-1-5-21-9)"),
        ("S-1-5-80-1", None, False, "D:P(A;;FA;;;S-1-5-80-1)"),
    ],
    ids=["foreign-owner", "candidate", "own-account", "editor-is-owner", "no-editor"],
)
def test_the_owner_and_editor_list(
    owner: str | None, editor: str | None, editor_writes: bool, expected: str
) -> None:
    # Pure string building, so every case runs on every platform.
    assert (
        atomic_edit._owner_and_editor_list(owner, editor, editor_writes=editor_writes) == expected
    )


@windows_only
@pytest.mark.parametrize(
    "dacl",
    [
        "D:(A;;FA;;;{me})",  # inheritance not blocked
        "D:P(A;;FA;;;{me})(A;;FR;;;S-1-5-32-545)",  # a second entry
        "D:P(A;;FR;;;{me})",  # the right account, at read only
        "D:P(A;;FA;;;S-1-5-18)",  # full control, for another account
    ],
    ids=["unprotected", "extra-entry", "read-only", "other-account"],
)
def test_the_owner_only_check_fails_on_anything_else(tmp_path: Path, dacl: str) -> None:
    """The positive control for :func:`assert_owner_only`: each list here differs from the owner-only
    one in one way, and the check must refuse it. The last write is the owner-only list itself,
    which it must accept, so the check is not refusing everything."""
    import messagefoundry.store.store as store_mod

    me = store_mod._current_user_sid()
    assert me is not None
    path = folder_granting(tmp_path / "folder", me) / "probe"
    path.write_bytes(b"x")
    result = store_mod._set_security_from_sddl(
        path, dacl.format(me=me), protected=dacl.startswith("D:P")
    )
    assert result.failure is None and result.dacl_status == 0, result
    # The refusal must be about the list it read, not a failed read: both of the check's own
    # asserts on a list it read carry that list as their message.
    sddl = store_mod._read_dacl_sddl(path, owner=True)
    assert sddl is not None
    with pytest.raises(AssertionError, match=re.escape(sddl)):
        assert_owner_only(path, me)
    result = store_mod._set_security_from_sddl(path, f"D:P(A;;FA;;;{me})", protected=True)
    assert result.failure is None and result.dacl_status == 0, result
    assert_owner_only(path, me)


def _an_own_file_in_a_folder_without_staging_entries(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> tuple[Path, str]:
    """A config file in a folder granting only this account and SYSTEM, and its real owner, which
    the token seam then reports as the editing account."""
    import messagefoundry.store.store as store_mod
    from messagefoundry.auth.anchor_path import SYSTEM_SID

    token = store_mod._current_user_sid()
    assert token is not None
    path = folder_granting(tmp_path / "config", token, SYSTEM_SID) / "connections.toml"
    path.write_text(CONNECTIONS_TOML, encoding="utf-8")
    owner = _real_owner(path)
    monkeypatch.setattr(store_mod, "_current_user_sid", lambda: owner)
    return path, owner


@windows_only
def test_the_candidate_is_restricted_before_its_first_byte_on_windows(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import messagefoundry.store.store as store_mod

    path, owner = _an_own_file_in_a_folder_without_staging_entries(tmp_path, monkeypatch)
    real_write = store_mod._set_security_from_sddl
    writes: list[tuple[Path, int]] = []

    def _recording(target: Path, sddl: str, *, protected: bool) -> Any:
        writes.append((target, target.stat().st_size))
        result = real_write(target, sddl, protected=protected)
        if target != path:
            # The candidate's own list, read back before any byte reaches it.
            assert_owner_only(target, owner)
        return result

    monkeypatch.setattr(store_mod, "_set_security_from_sddl", _recording)
    # Larger than the write buffer, so a restriction moved after the write sees the bytes on disk.
    data = b"x = 1\n" + b"#" * (1 << 17) + b"\n"

    atomic_edit.replace_validated(path, data, _noop)

    (candidate, size), (final, _) = writes
    assert atomic_edit.is_candidate_dir_name(candidate.parent.name, of=path.name)
    assert size == 0, "the candidate held bytes before its access list was written"
    assert final == path
    assert path.read_bytes() == data


@windows_only
@pytest.mark.parametrize("failing", ["candidate", "both"])
def test_a_failed_list_write_still_restricts_the_file_on_windows(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failing: str
) -> None:
    # A candidate whose list could not be written still ends owner-only, because the replaced file
    # gets the whole list again. Only when that write fails too does the store's _secure_file run.
    import messagefoundry.store.store as store_mod

    path, owner = _an_own_file_in_a_folder_without_staging_entries(tmp_path, monkeypatch)
    real_write = store_mod._set_security_from_sddl

    def _failing(target: Path, sddl: str, *, protected: bool) -> Any:
        if failing == "both" or target != path:
            return store_mod._SddlWrite(failure="refused for the test")
        return real_write(target, sddl, protected=protected)

    secured: list[Path] = []
    monkeypatch.setattr(store_mod, "_set_security_from_sddl", _failing)
    monkeypatch.setattr(atomic_edit, "_secure_file", secured.append)

    atomic_edit.replace_validated(path, b"x = 1\n", _noop)

    assert path.read_bytes() == b"x = 1\n"
    if failing == "both":
        assert secured == [path]
    else:
        assert secured == []
        assert_owner_only(path, owner)


@windows_only
@pytest.mark.parametrize(
    ("owner", "editor", "admins", "foreign"),
    [
        ("LS", "S-1-5-19", False, None),
        ("BA", _EDITOR_SID, True, None),
        ("BA", _EDITOR_SID, False, "S-1-5-32-544"),
        ("SY", _EDITOR_SID, True, "S-1-5-18"),
        ("BU", _EDITOR_SID, False, None),
        ("WD", _EDITOR_SID, False, None),
        ("SY", None, False, None),
    ],
    ids=[
        "alias-is-self",
        "administrators-elevated",
        "administrators-not-held",
        "system",
        "users-is-never-granted",
        "everyone-is-never-granted",
        "no-token",
    ],
)
def test_who_counts_as_another_owner(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    owner: str,
    editor: str | None,
    admins: bool,
    foreign: str | None,
) -> None:
    # SDDL spells well-known owners by alias, so an editor running as LOCAL SERVICE must still
    # recognise its own file, and an elevated administrator its Administrators-owned one.
    import messagefoundry.restricted_file as restricted_mod
    import messagefoundry.store.store as store_mod

    sddl = f"O:{owner}D:P"
    monkeypatch.setattr(store_mod, "_read_dacl_sddl", lambda _path, owner=False: sddl)
    monkeypatch.setattr(store_mod, "_current_user_sid", lambda: editor)
    monkeypatch.setattr(restricted_mod, "administrators_enabled", lambda: admins)

    assert atomic_edit._foreign_windows_owner(tmp_path / "x.toml") == foreign


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
    """A caller may hold the lock across a list and an upsert, and the upsert takes it again. A
    second ``flock`` on a new handle in one process would wait on the first forever."""
    path = tmp_path / "connections.toml"
    path.write_text(CONNECTIONS_TOML, encoding="utf-8")
    finished = threading.Event()

    def run() -> None:
        with connections_edit.locked(tmp_path):
            entry = next(
                e for e in connections_edit.list_connections(tmp_path) if e["name"] == "OB_TOML"
            )
            entry["deployed"] = False
            connections_edit.upsert_connection(tmp_path, entry, validate=_noop)
        finished.set()

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    thread.join(_JOIN_S)
    assert finished.is_set()
    assert "deployed = false" in path.read_text(encoding="utf-8")


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
    # The config directory's lock, the one a connection edit holds.
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


@posix_only
def test_the_lock_file_is_owner_only(tmp_path: Path) -> None:
    """Owner-only like the files it guards, which every edit leaves 0600."""
    path = tmp_path / "messagefoundry.toml"
    with atomic_edit.edit_lock(path):
        pass
    assert stat.S_IMODE(atomic_edit.lock_path_for(path).stat().st_mode) == 0o600


def test_an_edit_locks_on_nfs_where_an_exclusive_lock_needs_a_writable_handle(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """flock(2): an NFS client emulates flock with a byte-range lock, so an exclusive lock on a
    read-only handle fails EBADF. No NFS mount here, so the rule is modelled, on every platform."""
    path = tmp_path / "messagefoundry.toml"
    path.write_text(SETTINGS_TOML, encoding="utf-8")
    real_open = os.open
    opened: dict[int, int] = {}
    locked: list[int] = []

    def spying_open(target: Any, flags: int, *args: Any, **kwargs: Any) -> int:
        fd = real_open(target, flags, *args, **kwargs)
        opened[fd] = flags
        return fd

    def nfs_lock(fd: int) -> bool:
        if not opened[fd] & (os.O_WRONLY | os.O_RDWR):
            raise OSError(errno.EBADF, "Bad file descriptor")
        locked.append(fd)
        return True

    monkeypatch.setattr(os, "open", spying_open)
    monkeypatch.setattr(atomic_edit, "_try_lock", nfs_lock)
    monkeypatch.setattr(atomic_edit, "_WINDOWS", False)

    with atomic_edit.edit_lock(path):
        pass

    assert locked


def test_the_lock_handle_stays_read_only_on_windows(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A holder with read sharing only, such as a backup agent, would refuse a request for write."""
    real_open = os.open
    seen: list[int] = []

    def spying_open(target: Any, flags: int, *args: Any, **kwargs: Any) -> int:
        seen.append(flags)
        return real_open(target, flags, *args, **kwargs)

    monkeypatch.setattr(os, "open", spying_open)
    monkeypatch.setattr(atomic_edit, "_try_lock", lambda _fd: True)
    monkeypatch.setattr(atomic_edit, "_WINDOWS", True)

    with atomic_edit.edit_lock(tmp_path / "messagefoundry.toml"):
        pass

    assert seen
    assert not seen[0] & (os.O_WRONLY | os.O_RDWR)


def test_the_candidate_pattern_ends_in_the_candidate_suffix() -> None:
    """The pattern is a literal so the static regex scanner can read it; this holds its trailing
    ``\\.edit`` to ``CANDIDATE_DIR_SUFFIX`` so the two cannot drift."""
    import re

    pattern = atomic_edit._CANDIDATE_DIR_RE.pattern
    assert pattern.endswith(re.escape(atomic_edit.CANDIDATE_DIR_SUFFIX))
