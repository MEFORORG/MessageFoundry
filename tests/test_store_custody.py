# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Key custody primitives (vault BACKLOG #3411, slice S3; the vault key custody ADR draft).

Round trips, the refusals, and that no key material reaches a repr or an exception message. The
DPAPI cases run on Windows and the file-mode and credential cases on POSIX; the decisions behind the
file checks are pure and run everywhere."""

from __future__ import annotations

import errno
import os
import stat
import struct
import sys
from pathlib import Path

import pytest

from messagefoundry import restricted_file
from messagefoundry.restricted_file import RestrictedFileError
from messagefoundry.secrets_dpapi import DpapiUnavailable
from messagefoundry.store import custody
from messagefoundry.store.custody import (
    CredentialUnavailable,
    CustodyError,
    HostBlob,
    MasterKey,
    RecoveryKey,
    StoreId,
    unwrap_master_key,
    wrap_master_key,
)

windows_only = pytest.mark.skipif(sys.platform != "win32", reason="DPAPI is Windows-only")
linux_only = pytest.mark.skipif(
    sys.platform != "linux", reason="custody files on POSIX are read on Linux only"
)

# Fixed, recognisable key material, so a test can look for it in text.
_MASTER = bytes(range(32))
_RECOVERY = bytes(range(100, 132))


def _blob(earlier: int = 2) -> HostBlob:
    return HostBlob(
        MasterKey(_MASTER),
        StoreId(b"\x11" * 16),
        tuple(StoreId(bytes([0x20 + i]) * 16) for i in range(earlier)),
    )


def _leaks(text: str, *secrets: bytes) -> list[str]:
    """Each rendering of a secret that appears in ``text``: hex, either case, and the raw repr."""
    found = []
    for secret in secrets:
        for form in (secret.hex(), secret.hex().upper(), repr(secret)[2:-1]):
            if form in text:
                found.append(form)
    return found


# --- mint ---------------------------------------------------------------------------------------


def test_mint_gives_the_sizes_the_draft_names_and_a_fresh_value_each_time() -> None:
    assert len(MasterKey.mint().material()) == 32
    assert len(StoreId.mint().value) == 16
    assert len(RecoveryKey.mint().material()) == 32
    assert MasterKey.mint() != MasterKey.mint()
    assert StoreId.mint() != StoreId.mint()
    assert RecoveryKey.mint() != RecoveryKey.mint()


@pytest.mark.parametrize("cls", [MasterKey, RecoveryKey, StoreId])
def test_a_value_of_the_wrong_size_is_refused(cls: type) -> None:
    with pytest.raises(CustodyError, match="bytes, not 31"):
        cls(b"\x00" * 31)


# --- the recovery key text ------------------------------------------------------------------------


def test_recovery_key_text_round_trips_and_is_grouped() -> None:
    key = RecoveryKey(_RECOVERY)
    text = key.text()
    groups = text.split("-")
    assert len(groups) == 14 and all(len(g) == 4 for g in groups)
    assert RecoveryKey.parse(text) == key
    # Case, dashes and spaces do not matter, and the look-alike letters read as their digits.
    loose = " ".join(groups).lower()
    assert RecoveryKey.parse(loose) == key
    assert RecoveryKey.parse(text.replace("0", "O").replace("1", "I")) == key
    # A word processor's en dash between groups is a separator too.
    assert RecoveryKey.parse(text.replace("-", "–")) == key


def test_a_non_ascii_letter_is_not_read_as_a_digit() -> None:
    text = RecoveryKey(_RECOVERY).text()
    # U+0131, dotless i, upper-cases to an ASCII I; it is refused rather than read as a 1.
    with pytest.raises(CustodyError, match="character 1 of the entry"):
        RecoveryKey.parse("ı" + text[1:])


def test_every_single_character_mistype_is_refused_by_the_checksum() -> None:
    text = RecoveryKey(_RECOVERY).text().replace("-", "")
    alphabet = custody._ALPHABET
    refused = 0
    for position, ch in enumerate(text):
        swap = alphabet[(alphabet.index(ch) + 7) % len(alphabet)]
        entry = text[:position] + swap + text[position + 1 :]
        with pytest.raises(CustodyError, match="checksum does not match") as excinfo:
            RecoveryKey.parse(entry)
        message = str(excinfo.value)
        assert entry not in message and text not in message
        assert not any(entry[i : i + 4] in message for i in range(0, 56, 4))
        refused += 1
    assert refused == 56  # the control: every position was tried


def test_a_recovery_key_of_the_wrong_length_or_alphabet_is_refused_without_echo() -> None:
    text = RecoveryKey(_RECOVERY).text()
    compact = text.replace("-", "")
    with pytest.raises(CustodyError, match="this entry has 55") as short:
        RecoveryKey.parse(compact[:-1])
    # The position counts the dashes the person sees: the third character of the second group.
    bad_entry = text[:7] + "U" + text[8:]
    with pytest.raises(CustodyError, match="character 8 of the entry") as bad:
        RecoveryKey.parse(bad_entry)
    for excinfo in (short, bad):
        message = str(excinfo.value)
        # No run of the entry survives into the message: not the whole key, not one group of it.
        assert compact[:-1] not in message and bad_entry not in message
        assert not any(group in message for group in bad_entry.split("-"))


def test_a_refusal_leaves_no_key_material_in_the_raising_frame() -> None:
    # A renderer that prints frame locals (BACKLOG #3471's concern) walks the traceback's frames.
    text = RecoveryKey(_RECOVERY).text()
    mistyped = ("1" if text[0] != "1" else "2") + text[1:]
    bad_blob = _blob().serialize()[:-1]
    for call in (lambda: RecoveryKey.parse(mistyped), lambda: HostBlob.parse(bad_blob)):
        with pytest.raises(CustodyError) as excinfo:
            call()
        seen = 0
        tb = excinfo.value.__traceback__
        while tb is not None:
            frame = tb.tb_frame
            if frame.f_code.co_filename == custody.__file__:
                seen += 1
                rendered = repr(dict(frame.f_locals))
                assert mistyped not in rendered and text[5:9] not in rendered
                assert not _leaks(rendered, _MASTER)
            tb = tb.tb_next
        assert seen == 1  # the control: the raising frame in custody.py was examined


def test_a_long_paste_is_refused_at_the_first_extra_character() -> None:
    text = RecoveryKey(_RECOVERY).text()
    with pytest.raises(CustodyError, match="this entry has more"):
        RecoveryKey.parse(text + "0" * 2_000_000)


def test_earlier_store_ids_are_held_as_a_tuple() -> None:
    ids = [StoreId(b"\x21" * 16)]
    blob = HostBlob(MasterKey(_MASTER), StoreId(b"\x11" * 16), ids)  # type: ignore[arg-type]
    ids.append(StoreId(b"\x11" * 16))  # a later change to the list does not reach the blob
    assert blob.earlier_store_ids == (StoreId(b"\x21" * 16),)
    generated = HostBlob(MasterKey(_MASTER), StoreId(b"\x11" * 16), (s for s in ids[:1]))  # type: ignore[arg-type]
    assert generated.earlier_store_ids == (StoreId(b"\x21" * 16),)


def test_a_host_blob_given_as_a_bytearray_parses() -> None:
    assert HostBlob.parse(bytearray(_blob().serialize())) == _blob()


# --- the host blob --------------------------------------------------------------------------------


def test_host_blob_round_trips() -> None:
    for earlier in (0, 1, 3):
        blob = _blob(earlier)
        assert HostBlob.parse(blob.serialize()) == blob


def test_an_unknown_host_blob_version_is_refused() -> None:
    data = bytearray(_blob().serialize())
    data[4] = 2
    with pytest.raises(CustodyError, match="version 2, and this engine reads version 1 only"):
        HostBlob.parse(bytes(data))


@pytest.mark.parametrize(
    "mangle",
    [
        lambda d: b"XXXX" + d[4:],  # not the magic
        lambda d: d[:-1],  # short by one
        lambda d: d + b"\x00",  # long by one
        lambda d: d[:10],  # shorter than the head
    ],
)
def test_a_host_blob_of_the_wrong_shape_is_refused(mangle: object) -> None:
    data = _blob().serialize()
    with pytest.raises(CustodyError) as excinfo:
        HostBlob.parse(mangle(data))  # type: ignore[operator]
    assert not _leaks(str(excinfo.value), _MASTER)


def test_a_host_blob_naming_a_store_id_twice_is_refused() -> None:
    current = StoreId(b"\x11" * 16)
    with pytest.raises(CustodyError, match="each store id once"):
        HostBlob(MasterKey(_MASTER), current, (current,))


# --- the recovery wrap ----------------------------------------------------------------------------


def test_recovery_wrap_round_trips() -> None:
    master, recovery, store_id = MasterKey(_MASTER), RecoveryKey(_RECOVERY), StoreId.mint()
    wrapped = wrap_master_key(master, recovery, store_id)
    assert _MASTER not in wrapped  # the wrap holds ciphertext, not the key
    assert unwrap_master_key(wrapped, recovery, store_id) == master
    # A fresh nonce each time: two wraps of one key differ and both open.
    again = wrap_master_key(master, recovery, store_id)
    assert again != wrapped
    assert unwrap_master_key(again, recovery, store_id) == master


def test_a_wrong_recovery_key_is_refused() -> None:
    store_id = StoreId.mint()
    wrapped = wrap_master_key(MasterKey(_MASTER), RecoveryKey(_RECOVERY), store_id)
    with pytest.raises(CustodyError, match="does not open this recovery wrap") as excinfo:
        unwrap_master_key(wrapped, RecoveryKey.mint(), store_id)
    # Raised outside the handler: no chained exception at all, not one merely hidden.
    assert excinfo.value.__cause__ is None and excinfo.value.__context__ is None
    assert not _leaks(str(excinfo.value), _MASTER, _RECOVERY)


def test_a_wrong_store_id_in_the_associated_data_is_refused() -> None:
    recovery = RecoveryKey(_RECOVERY)
    wrapped = wrap_master_key(MasterKey(_MASTER), recovery, StoreId(b"\x01" * 16))
    assert unwrap_master_key(wrapped, recovery, StoreId(b"\x01" * 16)).material() == _MASTER
    with pytest.raises(CustodyError, match="does not open this recovery wrap"):
        unwrap_master_key(wrapped, recovery, StoreId(b"\x02" * 16))


def test_a_recovery_wrap_of_another_version_or_shape_is_refused() -> None:
    recovery, store_id = RecoveryKey(_RECOVERY), StoreId.mint()
    wrapped = wrap_master_key(MasterKey(_MASTER), recovery, store_id)
    with pytest.raises(CustodyError, match="version 9, and this engine reads version 1 only"):
        unwrap_master_key(wrapped[:4] + b"\x09" + wrapped[5:], recovery, store_id)
    with pytest.raises(CustodyError, match="not a recovery wrap"):
        unwrap_master_key(b"MFRW", recovery, store_id)
    with pytest.raises(CustodyError, match="not a recovery wrap"):
        unwrap_master_key(b"", recovery, store_id)
    with pytest.raises(CustodyError, match="bytes, not"):
        unwrap_master_key(wrapped[:-1], recovery, store_id)


# --- nothing renders key material -----------------------------------------------------------------


def test_no_type_renders_its_key_material() -> None:
    blob = _blob()
    recovery = RecoveryKey(_RECOVERY)
    for value in (blob.master_key, recovery, blob):
        for text in (repr(value), str(value), f"{value!r}", f"{[value]}"):
            assert not _leaks(text, _MASTER, _RECOVERY), text
            assert recovery.text() not in text
    # The control: a store id is not a secret, and its repr names it.
    assert blob.store_id.hex() in repr(blob)
    assert repr(blob.store_id) == f"StoreId({'11' * 16})"


def test_the_key_types_are_not_hashable() -> None:
    # A hash of a key would be a stable value derived from it, sitting in any dict or set it joins.
    with pytest.raises(TypeError):
        hash(MasterKey(_MASTER))
    with pytest.raises(TypeError):
        hash(RecoveryKey(_RECOVERY))


# --- the POSIX file decisions, run everywhere -----------------------------------------------------


_HOST = custody._HOST_FILE_POLICY
_CREDENTIAL = custody._PosixPolicy(owners=frozenset({0}), access_list=True)
_REG = stat.S_IFREG
_UNDEFINED_ID = 0xFFFFFFFF
_R, _RW = 0o4, 0o6
_USER_OBJ, _USER, _GROUP_OBJ = custody._ACL_USER_OBJ, custody._ACL_USER, custody._ACL_GROUP_OBJ
_GROUP, _MASK, _OTHER = custody._ACL_GROUP, custody._ACL_MASK, custody._ACL_OTHER
_ACL_XATTR = restricted_file.POSIX_ACL_XATTR


def _entry(tag: int, perms: int, ident: int = _UNDEFINED_ID) -> bytes:
    return custody._ACL_ENTRY.pack(tag, perms, ident)


def _acl(*entries: bytes) -> bytes:
    """A ``system.posix_acl_access`` value as Linux stores it: the version, then each entry."""
    return custody._ACL_HEADER.pack(custody._ACL_VERSION) + b"".join(entries)


def _systemd_acl(*named: bytes, group_perms: int = 0, uid: int = 1000) -> bytes:
    """The list systemd leaves on a credential for a non-root service user (``uid``): the owner and
    the named user read only, the group nothing, the mask read, and nothing for others."""
    return _acl(
        _entry(_USER_OBJ, _R),
        *(named or (_entry(_USER, _R, uid),)),
        _entry(_GROUP_OBJ, group_perms),
        _entry(_MASK, _R),
        _entry(_OTHER, 0),
    )


def _problem(
    mode: int,
    owner: int,
    policy: custody._PosixPolicy,
    *,
    group: int = 1000,
    acl: bytes | None = None,
    kind: int = _REG,
) -> str | None:
    return custody._posix_file_problem(
        kind | mode, policy, acl, owner=owner, group=group, euid=1000
    )


def test_the_posix_host_file_check_refuses_any_group_or_other_bit_and_a_foreign_owner() -> None:
    assert _problem(0o600, 1000, _HOST) is None  # the control
    assert "0644" in str(_problem(0o644, 1000, _HOST))
    assert "0610" in str(_problem(0o610, 1000, _HOST))
    # Owner only (draft rule 3b, mode 0600): group read is refused even for the engine's own group.
    assert "gid 1000 read" in str(_problem(0o640, 1000, _HOST))
    assert "uid 0" in str(_problem(0o600, 0, _HOST))
    assert "not a regular file" in str(_problem(0o700, 1000, _HOST, kind=stat.S_IFDIR))
    assert "not a regular file" in str(_problem(0o600, 1000, _HOST, kind=stat.S_IFIFO))


def test_a_systemd_credential_with_no_list_is_read_by_its_owner_alone() -> None:
    assert _problem(0o400, 0, _CREDENTIAL, group=0) is None  # the control
    assert _problem(0o400, 1000, _CREDENTIAL, group=1000) is None
    assert _problem(0o400, 1000, _CREDENTIAL, group=5) is None
    # No group reads a credential, not even root's or the engine's own: neither systemd form needs it.
    assert "gid 0 read" in str(_problem(0o440, 0, _CREDENTIAL, group=0))
    assert "gid 1000 read" in str(_problem(0o440, 1000, _CREDENTIAL, group=1000))
    assert "gid 5 read" in str(_problem(0o440, 0, _CREDENTIAL, group=5))
    assert "0444" in str(_problem(0o444, 0, _CREDENTIAL, group=0))
    assert "0460" in str(_problem(0o460, 0, _CREDENTIAL, group=0))
    assert "0450" in str(_problem(0o450, 0, _CREDENTIAL, group=0))
    assert "uid 2000" in str(_problem(0o400, 2000, _CREDENTIAL))


def test_the_access_control_list_systemd_writes_for_a_service_user_is_accepted() -> None:
    # Owned by root at 0400, with read for the service user in a named entry, which shows the mode
    # as 0440. The group bits are the mask, so the file's group (gid 5 here) reads nothing.
    assert _problem(0o440, 0, _CREDENTIAL, group=0, acl=_systemd_acl()) is None
    assert _problem(0o440, 0, _CREDENTIAL, group=5, acl=_systemd_acl()) is None


@pytest.mark.parametrize(
    ("acl", "group", "expected"),
    [
        (_systemd_acl(_entry(_USER, _R, 2000)), 0, "names uid 2000"),
        (_systemd_acl(_entry(_USER, 0, 2000)), 0, "names uid 2000"),
        (_systemd_acl(_entry(_USER, _RW, 1000)), 0, "own uid more than read"),
        (_systemd_acl(_entry(_USER, _R, 1000), _entry(_GROUP, _R, 0)), 0, "names gid 0"),
        (_systemd_acl(group_perms=_R), 0, "group gid 0 access"),
        (_systemd_acl(group_perms=_R), 5, "group gid 5 access"),
        (_systemd_acl(group_perms=_RW), 0, "group gid 0 access"),
        (
            _acl(_entry(_USER_OBJ, _R), _entry(_GROUP_OBJ, 0), _entry(_OTHER, _R)),
            0,
            "every other account",
        ),
        (
            _acl(_entry(_USER_OBJ, _R), _entry(_GROUP_OBJ, 0), _entry(_OTHER, 0), _entry(0x40, _R)),
            0,
            "of a kind this engine does not read",
        ),
        # Not a list Linux writes: no group or other entry, a second owner entry, named entries
        # with no mask, two masks, or the header alone. Each is refused, not read as granting nothing.
        (_acl(_entry(_USER_OBJ, _RW), _entry(_OTHER, 0)), 0, "not in a form"),
        (_acl(_entry(_USER_OBJ, _RW), _entry(_GROUP_OBJ, 0)), 0, "not in a form"),
        (_systemd_acl() + _entry(_USER_OBJ, _R), 0, "not in a form"),
        (
            _acl(
                _entry(_USER_OBJ, _R),
                _entry(_USER, _R, 1000),
                _entry(_GROUP_OBJ, 0),
                _entry(_OTHER, 0),
            ),
            0,
            "not in a form",
        ),
        (_systemd_acl() + _entry(_MASK, _R), 0, "not in a form"),
        (_acl(), 0, "not in a form"),
        (_systemd_acl()[:-1], 0, "not in a form"),
        (struct.pack("<I", 1) + _systemd_acl()[4:], 0, "not in a form"),
        (b"", 0, "not in a form"),
    ],
)
def test_an_access_control_list_entry_beyond_the_policy_is_refused(
    acl: bytes, group: int, expected: str
) -> None:
    assert expected in str(_problem(0o440, 0, _CREDENTIAL, group=group, acl=acl))


_CARRIES_A_LIST = "carries a POSIX access control list"


def test_the_host_file_carries_no_access_control_list_whatever_it_grants() -> None:
    assert _problem(0o600, 1000, _HOST) is None  # the control: no list
    owner_only = _acl(_entry(_USER_OBJ, _RW), _entry(_GROUP_OBJ, 0), _entry(_OTHER, 0))
    assert _CARRIES_A_LIST in str(_problem(0o600, 1000, _HOST, acl=owner_only))
    # Even the engine's own uid in a named entry is refused.
    assert _CARRIES_A_LIST in str(_problem(0o600, 1000, _HOST, acl=_systemd_acl()))
    named = _systemd_acl(_entry(_USER, 0, 2000))
    assert _CARRIES_A_LIST in str(_problem(0o600, 1000, _HOST, acl=named))


def test_a_host_file_at_0640_with_a_read_mask_and_an_empty_group_entry_is_refused() -> None:
    # The mask makes the mode read 0640, and with a list the group bits are the mask, so the mode's
    # group read is not judged; the list's group entry grants nothing. That file is still refused.
    masked = _acl(
        _entry(_USER_OBJ, _RW), _entry(_GROUP_OBJ, 0), _entry(_MASK, _R), _entry(_OTHER, 0)
    )
    assert _CARRIES_A_LIST in str(_problem(0o640, 1000, _HOST, acl=masked))
    # The same list is one a credential may carry, so the refusal is the host policy's.
    assert _problem(0o440, 0, _CREDENTIAL, acl=masked) is None


@pytest.mark.parametrize(
    ("code", "no_list"),
    [(errno.ENODATA, True), (errno.ENOTSUP, True), (errno.EOPNOTSUPP, True), (errno.EIO, False)],
)
def test_only_no_attribute_or_no_extended_attributes_reads_as_no_access_control_list(
    code: int, no_list: bool, monkeypatch: pytest.MonkeyPatch
) -> None:
    def _getxattr(fd: int, name: str) -> bytes:
        assert name == _ACL_XATTR
        raise OSError(code, os.strerror(code))

    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.setattr(os, "getxattr", _getxattr, raising=False)
    if no_list:
        assert restricted_file.posix_access_acl(3) is None
    else:  # a list that could not be read is not a list shown absent
        with pytest.raises(OSError) as excinfo:
            restricted_file.posix_access_acl(3)
        assert excinfo.value.errno == code


def test_custody_files_are_refused_on_a_posix_host_other_than_linux(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "store-a").write_bytes(_blob().serialize())
    environ = {"CREDENTIALS_DIRECTORY": str(tmp_path)}
    monkeypatch.setattr(sys, "platform", "darwin")
    with pytest.raises(CustodyError, match="Linux and Windows only"):
        custody.read_host_file(tmp_path / "store-a")
    with pytest.raises(CustodyError, match="Linux and Windows only"):
        custody.write_host_file(tmp_path / "host.blob", _blob())
    assert not (tmp_path / "host.blob").exists()
    with pytest.raises(CredentialUnavailable, match="Linux only"):
        custody.read_systemd_credential("store-a", environ=environ)


# --- the POSIX host file, for real ----------------------------------------------------------------


@linux_only
def test_posix_host_file_round_trips_at_mode_0600(tmp_path: Path) -> None:
    path = tmp_path / "host.blob"
    custody.write_host_file(path, _blob())
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert custody.read_host_file(path) == _blob()
    with pytest.raises(FileExistsError):
        custody.write_host_file(path, _blob(0))


@linux_only
def test_posix_host_file_at_0644_is_refused(tmp_path: Path) -> None:
    path = tmp_path / "host.blob"
    custody.write_host_file(path, _blob())
    os.chmod(path, 0o644)
    with pytest.raises(CustodyError, match="mode is 0644") as excinfo:
        custody.read_host_file(path)
    assert not _leaks(str(excinfo.value), _MASTER)


@linux_only
def test_posix_host_file_that_is_a_link_is_refused(tmp_path: Path) -> None:
    real = tmp_path / "host.blob"
    custody.write_host_file(real, _blob())
    link = tmp_path / "link.blob"
    link.symlink_to(real)
    with pytest.raises(CustodyError, match="could not be read"):
        custody.read_host_file(link)


@linux_only
def test_posix_host_file_that_is_a_fifo_is_refused_without_blocking(tmp_path: Path) -> None:
    fifo = tmp_path / "host.blob"
    os.mkfifo(fifo, 0o600)
    with pytest.raises(CustodyError, match="not a regular file"):
        custody.read_host_file(fifo)


@linux_only
def test_systemd_credential_is_read_from_the_named_file(tmp_path: Path) -> None:
    (tmp_path / "store-a").write_bytes(_blob().serialize())
    os.chmod(tmp_path / "store-a", 0o400)
    environ = {"CREDENTIALS_DIRECTORY": str(tmp_path)}
    assert custody.read_systemd_credential("store-a", environ=environ) == _blob()
    with pytest.raises(CredentialUnavailable, match="no credential named 'store-b'"):
        custody.read_systemd_credential("store-b", environ=environ)
    os.chmod(tmp_path / "store-a", 0o404)
    with pytest.raises(CustodyError, match="mode is 0404"):
        custody.read_systemd_credential("store-a", environ=environ)
    with pytest.raises(CustodyError, match="absolute path"):
        custody.read_systemd_credential("store-a", environ={"CREDENTIALS_DIRECTORY": "relative"})


@linux_only
def test_a_credentials_directory_that_does_not_exist_is_refused_not_unavailable(
    tmp_path: Path,
) -> None:
    environ = {"CREDENTIALS_DIRECTORY": str(tmp_path / "missing")}
    with pytest.raises(CustodyError, match="names no directory") as excinfo:
        custody.read_systemd_credential("store-a", environ=environ)
    assert not isinstance(excinfo.value, CredentialUnavailable)


def _set_acl_or_skip(path: Path, name: str, acl: bytes) -> None:
    try:
        os.setxattr(path, name, acl)
    except OSError as exc:
        if exc.errno in {errno.ENOTSUP, errno.EOPNOTSUPP}:
            pytest.skip("this file system keeps no POSIX access control list")
        raise


@linux_only
def test_a_host_file_whose_access_control_list_names_another_account_is_refused(
    tmp_path: Path,
) -> None:
    path = tmp_path / "host.blob"
    custody.write_host_file(path, _blob())
    other = os.geteuid() + 1
    acl = _acl(
        _entry(_USER_OBJ, _RW),
        _entry(_USER, _R, other),
        _entry(_GROUP_OBJ, 0),
        _entry(_MASK, 0),
        _entry(_OTHER, 0),
    )
    _set_acl_or_skip(path, _ACL_XATTR, acl)
    assert stat.S_IMODE(path.stat().st_mode) == 0o600  # the mode alone would pass
    with pytest.raises(CustodyError, match=_CARRIES_A_LIST) as excinfo:
        custody.read_host_file(path)
    assert not _leaks(str(excinfo.value), _MASTER)


@linux_only
def test_a_host_file_at_0640_with_a_read_mask_and_an_empty_group_entry_is_refused_for_real(
    tmp_path: Path,
) -> None:
    path = tmp_path / "host.blob"
    custody.write_host_file(path, _blob())
    assert custody.read_host_file(path) == _blob()  # the control
    masked = _acl(
        _entry(_USER_OBJ, _RW), _entry(_GROUP_OBJ, 0), _entry(_MASK, _R), _entry(_OTHER, 0)
    )
    _set_acl_or_skip(path, _ACL_XATTR, masked)
    assert stat.S_IMODE(path.stat().st_mode) == 0o640  # the group bits are now the mask
    with pytest.raises(CustodyError, match=_CARRIES_A_LIST) as excinfo:
        custody.read_host_file(path)
    assert not _leaks(str(excinfo.value), _MASTER)


@linux_only
def test_a_credential_with_the_access_control_list_systemd_writes_is_read(tmp_path: Path) -> None:
    path = tmp_path / "store-a"
    path.write_bytes(_blob().serialize())
    os.chmod(path, 0o400)
    euid = os.geteuid()
    _set_acl_or_skip(path, _ACL_XATTR, _systemd_acl(uid=euid))
    assert stat.S_IMODE(path.stat().st_mode) == 0o440  # the group bits are now the mask
    environ = {"CREDENTIALS_DIRECTORY": str(tmp_path)}
    assert custody.read_systemd_credential("store-a", environ=environ) == _blob()
    os.setxattr(path, _ACL_XATTR, _systemd_acl(_entry(_USER, _R, euid + 1)))
    with pytest.raises(CustodyError, match=f"names uid {euid + 1}"):
        custody.read_systemd_credential("store-a", environ=environ)


@linux_only
def test_a_host_file_written_under_a_default_access_control_list_reads_back(
    tmp_path: Path,
) -> None:
    directory = tmp_path / "keys"
    directory.mkdir()
    default = _acl(
        _entry(_USER_OBJ, 0o7),
        _entry(_USER, _RW, os.geteuid() + 1),
        _entry(_GROUP_OBJ, 0o5),
        _entry(_MASK, 0o7),
        _entry(_OTHER, 0o5),
    )
    _set_acl_or_skip(directory, "system.posix_acl_default", default)
    path = directory / "host.blob"
    custody.write_host_file(path, _blob())
    with pytest.raises(OSError) as excinfo:  # no access control list is left on the file
        os.getxattr(path, _ACL_XATTR)
    assert excinfo.value.errno == errno.ENODATA
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert custody.read_host_file(path) == _blob()


@linux_only
def test_an_inherited_access_control_list_that_cannot_be_removed_leaves_no_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def _removexattr(fd: int, name: str) -> None:
        raise PermissionError(errno.EPERM, "Operation not permitted")

    monkeypatch.setattr(restricted_file, "posix_access_acl", lambda fd: b"inherited")
    monkeypatch.setattr(os, "removexattr", _removexattr)
    path = tmp_path / "host.blob"
    with pytest.raises(RestrictedFileError, match="inherited POSIX access control list"):
        custody.write_host_file(path, _blob())
    assert not path.exists()


@linux_only
def test_an_inherited_access_control_list_still_there_after_removal_leaves_no_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(restricted_file, "posix_access_acl", lambda fd: b"inherited")
    monkeypatch.setattr(os, "removexattr", lambda fd, name: None)
    path = tmp_path / "host.blob"
    with pytest.raises(RestrictedFileError, match="still carries one after it was removed"):
        custody.write_host_file(path, _blob())
    assert not path.exists()


@linux_only
def test_a_host_file_is_written_at_0600_whatever_the_umask(tmp_path: Path) -> None:
    previous = os.umask(0o677)
    try:
        custody.write_host_file(tmp_path / "host.blob", _blob())
    finally:
        os.umask(previous)
    assert stat.S_IMODE((tmp_path / "host.blob").stat().st_mode) == 0o600
    assert custody.read_host_file(tmp_path / "host.blob") == _blob()


@linux_only
def test_an_access_control_list_that_cannot_be_read_refuses_the_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "host.blob"
    custody.write_host_file(path, _blob())

    def _getxattr(fd: int, name: str) -> bytes:
        raise OSError(errno.EIO, "I/O error")

    monkeypatch.setattr(os, "getxattr", _getxattr)
    with pytest.raises(CustodyError, match="access control list could not be read"):
        custody.read_host_file(path)


def test_systemd_credential_refusals_that_need_no_file() -> None:
    with pytest.raises(CredentialUnavailable, match="is not set"):
        custody.read_systemd_credential("store-a", environ={})
    for name in ("", ".", "..", "a/b", "a\\b", "a\x00b"):
        with pytest.raises(CustodyError, match="plain file name"):
            custody.read_systemd_credential(name, environ={"CREDENTIALS_DIRECTORY": "/run/x"})


# --- the Windows host provider and the handoff ----------------------------------------------------


@pytest.fixture
def dpapi_scopes(monkeypatch: pytest.MonkeyPatch) -> list[bool]:
    """The ``machine_scope`` of each real ``dpapi_protect`` call made during the test."""
    from messagefoundry import secrets_dpapi

    scopes: list[bool] = []
    real = secrets_dpapi.dpapi_protect

    def _spy(secret: bytes, *, machine_scope: bool) -> bytes:
        scopes.append(machine_scope)
        return real(secret, machine_scope=machine_scope)

    monkeypatch.setattr(secrets_dpapi, "dpapi_protect", _spy)
    return scopes


@windows_only
def test_windows_host_blob_round_trips_under_user_scope_dpapi(dpapi_scopes: list[bool]) -> None:
    protected = custody.protect_host_blob(_blob())
    assert dpapi_scopes == [False]  # user scope: only this account can open it
    assert _MASTER not in protected
    assert custody.unprotect_host_blob(protected) == _blob()


@windows_only
def test_windows_host_file_round_trips(tmp_path: Path) -> None:
    path = tmp_path / "master.key"
    custody.write_host_file(path, _blob())
    assert _MASTER not in path.read_bytes()
    assert custody.read_host_file(path) == _blob()


def _aces(path: Path) -> set[tuple[int, int, str]]:
    from messagefoundry.config.wiring import _win32_config_source_probes

    security = _win32_config_source_probes().read_path(path)
    assert security.aces is not None
    return set(security.aces)


@windows_only
def test_windows_handoff_grants_the_service_and_no_package_sid(
    tmp_path: Path, dpapi_scopes: list[bool]
) -> None:
    path = tmp_path / "handoff.key"
    custody.write_handoff_file(path, _blob(), service_account="NT AUTHORITY\\LOCAL SERVICE")
    assert dpapi_scopes == [True]  # machine scope, so the service account can open it
    sids = {sid for _type, _mask, sid in _aces(path)}
    assert "S-1-5-19" in sids  # the control: the grant reached the list
    assert not [sid for sid in sids if sid.upper().startswith("S-1-15-")]
    assert custody.read_handoff_file(path) == _blob()


@windows_only
@pytest.mark.parametrize(
    "package",
    [
        "*S-1-15-2-1",
        "*S-1-15-2-3624051433-2125758914-1423191267-1740899205-1073925389-3782572162-737981194",
    ],
)
def test_windows_handoff_refuses_a_package_sid(tmp_path: Path, package: str) -> None:
    path = tmp_path / "handoff.key"
    with pytest.raises(RestrictedFileError, match="application package"):
        custody.write_handoff_file(path, _blob(), service_account=package)
    assert not path.exists()


_PACKAGE = "S-1-15-2-3624051433-2125758914-1423191267-1740899205-1073925389-3782572162-737981194"


@windows_only
def test_windows_a_key_file_widened_to_a_package_after_creation_is_refused(
    tmp_path: Path,
) -> None:
    from messagefoundry.store import store as store_mod

    path = tmp_path / "master.key"
    custody.write_host_file(path, _blob())
    assert custody.read_host_file(path) == _blob()  # the control
    store_mod._grant_read(path, f"*{_PACKAGE}")
    assert _PACKAGE in {sid for _t, _m, sid in _aces(path)}  # the grant landed
    with pytest.raises(CustodyError, match="application package"):
        custody.read_host_file(path)


@windows_only
def test_windows_a_blob_of_the_other_scope_is_refused(tmp_path: Path) -> None:
    handoff = tmp_path / "handoff.key"
    custody.write_handoff_file(handoff, _blob(), service_account="NT AUTHORITY\\LOCAL SERVICE")
    # A handoff renamed to the host file's path is machine scope, so it is not a host blob.
    with pytest.raises(CustodyError, match="not a user-scope DPAPI blob"):
        custody.read_host_file(handoff)
    host = tmp_path / "master.key"
    custody.write_host_file(host, _blob())
    with pytest.raises(CustodyError, match="not a machine-scope DPAPI blob"):
        custody.read_handoff_file(host)
    with pytest.raises(CustodyError, match="not a user-scope DPAPI blob"):
        custody.unprotect_host_blob(b"too short")


@windows_only
def test_windows_the_held_file_cannot_be_replaced_or_deleted(tmp_path: Path) -> None:
    path = tmp_path / "master.key"
    custody.write_host_file(path, _blob())
    other = tmp_path / "other.key"
    other.write_bytes(b"planted")
    fd = custody._open_windows_held(path)
    try:
        with pytest.raises(PermissionError):
            os.replace(other, path)
        with pytest.raises(PermissionError):
            os.unlink(path)
    finally:
        os.close(fd)
    os.replace(other, path)  # the control: once released, the name can be replaced


@windows_only
def test_windows_a_device_is_refused() -> None:
    # A device that exists and is not a disk file: the null device.
    with pytest.raises(CustodyError, match="not a file on disk"):
        custody._open_windows_held(Path("NUL"))


@windows_only
def test_windows_a_missing_custody_file_is_file_not_found(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        custody.read_host_file(tmp_path / "absent.key")
    with pytest.raises(FileNotFoundError):
        custody.read_handoff_file(tmp_path / "absent.key")


def test_the_handoff_is_windows_only(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "platform", "linux")
    with pytest.raises(DpapiUnavailable):
        custody.write_handoff_file(tmp_path / "h", _blob(), service_account="svc")
    with pytest.raises(DpapiUnavailable):
        custody.read_handoff_file(tmp_path / "h")
