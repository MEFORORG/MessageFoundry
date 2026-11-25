# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #6687: a DR copy loop refuses a ``None`` read rather than reading it as end of stream.

A non-blocking source answers ``None`` when it has nothing ready. A copy loop that stops on
``if not buf: break`` ends the copy short there, and so does ``shutil.copyfileobj``. The copies in
``pipeline/dr_backup.py`` that read through :class:`dr_backup._NoneRefusingReader`, which reads
through the codec's ``_read_once`` and so refuses a ``None`` read as the keyed branch does,
include at least these. By way of :func:`dr_backup._read_chunks`: the no-key build, the plaintext
verify, the config-member restore, ``_extract_member`` and the plaintext branch of
``_restore_blocking``. Handed to ``shutil.copyfileobj``: the copy fallback of
``_place_restored_store``. The refusal is raised as an ``OSError``, so each site reports it the way
it reports any ``OSError`` in that copy. These tests drive each of those sites, the last four
against an ``OSError`` read as the control; for the placement copy they check the ``OSError``
``_place_restored_store`` raises, not the restore's report of it. Reads in that module this branch does not change include at least
``_sha256_file``, where a ``None`` read raises a ``TypeError`` from the hash rather than ending the
read short, ``_looks_encrypted`` and ``_read_manifest_from_tar``. The sources are synthetic: a
store with one made-up row, and a tar of made-up config bytes."""

from __future__ import annotations

import builtins
import errno
import hashlib
import io
import json
import os
import sqlite3
import tarfile
import tempfile
from pathlib import Path
from typing import Any

import pytest

from messagefoundry.config.settings import BackupSettings, StoreSettings
from messagefoundry.pipeline import dr_backup as dr
from messagefoundry.pipeline.dr_backup import BackupError, BackupRunner
from messagefoundry.store import MessageStore
from messagefoundry.store.backup_codec import BackupCodecError

# The 1 MiB literal is the pre-fix loops' read size, so the module still imports on that code.
_CHUNK: int = getattr(dr, "_COPY_CHUNK_BYTES", 1024 * 1024)


class _Scripted:
    """A source that answers each ``read`` from a fixed script: ``None``, bytes, then ``b""``."""

    def __init__(self, script: list[bytes | None]) -> None:
        self._script = list(script)
        self.reads = 0

    def read(self, size: int = -1, /) -> bytes | None:
        self.reads += 1
        if not self._script:
            raise AssertionError("read again past an end of stream already returned")
        return self._script.pop(0)


class _Stalling:
    """Wraps a real binary reader: each copy-sized read is answered ``None`` once before the real
    read, the way a non-blocking source with no data ready yet answers it."""

    def __init__(self, inner: Any) -> None:
        self._inner = inner
        self._owed = True
        self.stalls = 0

    def read(self, size: int = -1, /) -> bytes | None:
        if size == _CHUNK and self._owed:
            self._owed = False
            self.stalls += 1
            return None
        self._owed = True
        data: bytes | None = self._inner.read(size)
        return data

    def __getattr__(self, name: str) -> Any:
        return getattr(self._inner, name)

    def __enter__(self) -> _Stalling:
        return self

    def __exit__(self, *exc: object) -> None:
        self._inner.close()


# --- the shared loop itself -------------------------------------------------------------------


def test_a_none_read_is_refused_not_read_as_end_of_stream() -> None:
    src = _Scripted([b"ab", None, b"cd", b""])
    chunks = dr._read_chunks(src, "test copy")
    assert next(chunks) == b"ab"
    with pytest.raises(OSError, match="no data ready reading the test copy") as caught:
        next(chunks)
    assert caught.value.errno == errno.EIO
    assert isinstance(caught.value.__cause__, BackupCodecError)
    assert src.reads == 2


def test_an_empty_read_ends_the_stream_and_nothing_reads_past_it() -> None:
    # _Scripted raises on a read past its script, so a loop that kept reading would fail here.
    src = _Scripted([b"ab", b"cd", b""])
    assert list(dr._read_chunks(src, "test copy")) == [b"ab", b"cd"]


def test_the_scripted_source_refuses_a_read_past_its_end() -> None:
    # Positive control for the test above: without it, that test could pass on a source that never
    # refuses.
    src = _Scripted([b""])
    assert src.read(1) == b""
    with pytest.raises(AssertionError, match="past an end of stream"):
        src.read(1)


def test_the_stalling_wrapper_answers_none_before_each_copy_sized_read() -> None:
    # Positive control: the site tests below rest on this wrapper really answering None.
    src = _Stalling(io.BytesIO(b"xy"))
    assert src.read(_CHUNK) is None
    assert src.read(_CHUNK) == b"xy"
    assert src.read(_CHUNK) is None
    assert src.read(_CHUNK) == b""
    assert src.stalls == 2


# --- the copy sites ---------------------------------------------------------------------------


async def _store_with_a_row(path: Path) -> MessageStore:
    store = await MessageStore.open(path)
    await store.enqueue_message(
        channel_id="c1",
        raw="MSH|^~\\&|synthetic-body",
        deliveries=[("d1", "OUT|synthetic-delivered")],
        control_id="CID-1",
        message_type="ADT^A01",
        summary="SYNTH001 TEST^PATIENT",
        now=1.0,
    )
    return store


@pytest.mark.parametrize(
    ("site", "what", "kind"),
    [("build", "plaintext tar", "write"), ("verify", "plaintext archive", "verify")],
)
async def test_a_plaintext_backup_refuses_a_none_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, site: str, what: str, kind: str
) -> None:
    """The no-key build copies the staged tar to the archive, and verify copies the archive back to
    a tar. A ``None`` at either used to end the copy short: here, on the first read, it ended it at
    zero bytes and the run failed later on an empty tar. It now fails at the read, naming the
    copy, with the failure kind any ``OSError`` in that copy gets: ``write`` at the build, and at
    verify a ``FAIL`` not worded as a decrypt, since a no-key copy decrypts nothing."""
    dest = (tmp_path / "backups").resolve()
    wrapped: list[_Stalling] = []
    real_open = builtins.open

    def _open(file: Any, mode: str = "r", *args: Any, **kwargs: Any) -> Any:
        fh = real_open(file, mode, *args, **kwargs)
        if mode != "rb":
            return fh
        path = Path(file).resolve()
        hit = path.name == "archive.tar" if site == "build" else path.is_relative_to(dest)
        if not hit:
            return fh
        stalling = _Stalling(fh)
        wrapped.append(stalling)
        return stalling

    monkeypatch.setattr(dr, "open", _open, raising=False)
    db = tmp_path / "msg.db"
    store = await _store_with_a_row(db)
    try:
        runner = BackupRunner(
            store,
            BackupSettings.model_validate(
                {"enabled": True, "destination": str(dest), "allow_unencrypted": True}
            ),
            store_settings=StoreSettings(path=str(db), encryption_key=None),
            config_dir=None,
        )
        with pytest.raises(BackupError, match=f"no data ready reading the {what}") as caught:
            await runner.run_once(now=1.0)
    finally:
        await store.close()
    assert sum(w.stalls for w in wrapped) > 0, "no copy-sized read went through the wrapper"
    assert caught.value.kind == kind
    assert "OSError" in str(caught.value)
    assert "decrypt" not in str(caught.value)


def test_a_config_restore_refuses_a_none_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    payload = b"synthetic = true\n" * 1000
    tar_path = tmp_path / "archive.tar"
    with tarfile.open(tar_path, "w:") as tar:
        info = tarfile.TarInfo("config/settings.toml")
        info.size = len(payload)
        tar.addfile(info, io.BytesIO(payload))

    wrapped: list[_Stalling] = []
    real_extractfile = tarfile.TarFile.extractfile

    def _extractfile(self: tarfile.TarFile, member: Any) -> Any:
        fh = real_extractfile(self, member)
        if fh is None:
            return None
        stalling = _Stalling(fh)
        wrapped.append(stalling)
        return stalling

    monkeypatch.setattr(tarfile.TarFile, "extractfile", _extractfile)
    dest = tmp_path / "restored-config"
    written: list[Path] = []
    # The restore's own wrapper names the OSError as a restore refusal.
    with pytest.raises(BackupError, match="no data ready reading the config member") as caught:
        dr._restore_config_members(tar_path, dest, written=written)
    assert sum(w.stalls for w in wrapped) > 0
    assert caught.value.kind == "restore"
    # The file the refused copy opened is on the caller's rollback ledger.
    assert (dest / "settings.toml").resolve() in [p.resolve() for p in written]


def test_a_config_member_still_restores_whole_from_a_blocking_reader(tmp_path: Path) -> None:
    payload = b"synthetic = true\n" * 200_000  # over 3 MiB, so the copy takes several reads
    tar_path = tmp_path / "archive.tar"
    with tarfile.open(tar_path, "w:") as tar:
        info = tarfile.TarInfo("config/settings.toml")
        info.size = len(payload)
        tar.addfile(info, io.BytesIO(payload))
    dest = tmp_path / "restored-config"
    assert dr._extract_config_members(tar_path, dest) == 1
    assert (dest / "settings.toml").read_bytes() == payload


# --- _HashingReader (added item 10, met by engine PR 3033; pinned here) -------------------------


def test_the_hashing_reader_passes_a_none_read_through_and_hashes_the_bytes_after_it() -> None:
    raw = _Stalling(io.BytesIO(b"synthetic archive bytes"))
    reader = dr._HashingReader(raw)  # type: ignore[arg-type]
    assert reader.read(_CHUNK) is None
    assert reader.read(_CHUNK) == b"synthetic archive bytes"
    assert reader.digest.hexdigest() == hashlib.sha256(b"synthetic archive bytes").hexdigest()


# --- the store member, the restore's plaintext copy and the placement copy ---------------------
#
# Each site is driven twice: once with a read that answers ``None``, once with a read that raises an
# ``OSError``, which is how a failed read of a real file reaches that copy. The two must be reported
# alike, so the ``None`` refusal takes the failure kind an ``OSError`` already had at the site.


class _Failing(_Stalling):
    """The control: each copy-sized read raises an ``OSError``, as a failed read of a file does."""

    def read(self, size: int = -1, /) -> bytes | None:
        if size == _CHUNK:
            self.stalls += 1
            raise OSError(errno.EIO, "synthetic read fault")
        data: bytes | None = self._inner.read(size)
        return data


class _StallingLate(_Stalling):
    """A ``None`` read after the first copy-sized read has returned data, so the copy has already
    written part of the stream when the stall comes, which a refusal on the first read only would
    miss."""

    def __init__(self, inner: Any) -> None:
        super().__init__(inner)
        self._reads = 0

    def read(self, size: int = -1, /) -> bytes | None:
        if size == _CHUNK:
            self._reads += 1
            if self._reads == 2:
                self.stalls += 1
                return None
        data: bytes | None = self._inner.read(size)
        return data


_FAULTS: dict[str, tuple[type[_Stalling], str]] = {
    "none-read": (_Stalling, "no data ready reading the {what}"),
    "none-read-midway": (_StallingLate, "no data ready reading the {what}"),
    "oserror": (_Failing, "synthetic read fault"),
}


def _assert_no_staging_left(caught: BaseException, dest: Path) -> None:
    """The restore tore its staging down: it names no leftover, and nothing is left beside the
    destination or in the OS temp dir the ``own_os_temp`` fixture gives the test."""
    assert "Separately" not in str(caught)
    assert not dest.parent.exists() or list(dest.parent.iterdir()) == []
    assert list((dest.parent.parent / "ostemp").iterdir()) == []


@pytest.fixture
def own_os_temp(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A restore stages beside its destination, and may sweep the OS temp dir: make it the test's."""
    (tmp_path / "ostemp").mkdir()
    monkeypatch.setattr(tempfile, "tempdir", str(tmp_path / "ostemp"))


def _plaintext_archive(path: Path) -> str:
    """A plaintext archive: a manifest and a synthetic one-table ``store.db`` over 1 MiB, so the
    member copy takes more than one read."""
    db = path.with_suffix(".db")
    conn = sqlite3.connect(db)
    try:
        conn.execute("CREATE TABLE messages (id INTEGER, body BLOB)")
        conn.execute("INSERT INTO messages VALUES (1, zeroblob(1500000))")
        conn.commit()
    finally:
        conn.close()
    manifest = json.dumps({"row_counts": {"messages": 1}, "config_only": False}).encode("utf-8")
    with tarfile.open(path, "w:") as tar:
        for name, data in ((dr._MANIFEST_MEMBER, manifest), (dr._STORE_MEMBER, db.read_bytes())):
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    return str(path)


def _wrap_store_member(monkeypatch: pytest.MonkeyPatch, cls: type[_Stalling]) -> list[_Stalling]:
    """Wrap the reader ``tarfile`` hands out for the ``store.db`` member, and no other member."""
    wrapped: list[_Stalling] = []
    real_extractfile = tarfile.TarFile.extractfile

    def _extractfile(self: tarfile.TarFile, member: Any) -> Any:
        fh = real_extractfile(self, member)
        name = member if isinstance(member, str) else member.name
        if fh is None or name != dr._STORE_MEMBER:
            return fh
        reader = cls(fh)
        wrapped.append(reader)
        return reader

    monkeypatch.setattr(tarfile.TarFile, "extractfile", _extractfile)
    return wrapped


def _wrap_open(
    monkeypatch: pytest.MonkeyPatch, cls: type[_Stalling], target: Path
) -> list[_Stalling]:
    """Wrap each binary read-open of ``target`` made in ``dr_backup``."""
    wrapped: list[_Stalling] = []
    real_open = builtins.open

    def _open(file: Any, mode: str = "r", *args: Any, **kwargs: Any) -> Any:
        fh = real_open(file, mode, *args, **kwargs)
        if mode != "rb" or Path(file).resolve() != target.resolve():
            return fh
        reader = cls(fh)
        wrapped.append(reader)
        return reader

    monkeypatch.setattr(dr, "open", _open, raising=False)
    return wrapped


def _restore(archive: str, dest: Path) -> None:
    dr._restore_blocking(
        archive_path=archive,
        dest_store_path=dest,
        config_dest=None,
        keys=[],
        max_age_seconds=None,
    )


@pytest.mark.parametrize("fault", sorted(_FAULTS))
def test_verify_reports_a_none_read_of_the_store_member_as_it_reports_an_oserror(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fault: str
) -> None:
    """``_extract_member`` on the verify path: a ``None`` read used to end the member short, so the
    verify went on to check a truncated store. It is now a ``FAIL`` at the read, as an ``OSError``
    there is, and not worded as a decrypt."""
    archive = _plaintext_archive(tmp_path / "plain.mfbak")
    cls, text = _FAULTS[fault]
    wrapped = _wrap_store_member(monkeypatch, cls)
    result = dr._verify_archive_blocking(
        archive_path=archive, keys=[], full=False, staging_root=tmp_path / "staging", secure=True
    )
    assert sum(w.stalls for w in wrapped) > 0, "no copy-sized read went through the wrapper"
    assert result.status == "FAIL"
    assert result.reason is not None
    assert text.format(what="store.db member") in result.reason
    assert result.reason.startswith("OSError: ")


@pytest.mark.usefixtures("own_os_temp")
@pytest.mark.parametrize("fault", sorted(_FAULTS))
def test_restore_reports_a_none_read_of_the_store_member_as_it_reports_an_oserror(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fault: str
) -> None:
    """``_extract_member`` on the restore path: the same ``None`` read is refused, and is the
    ``restore`` refusal an ``OSError`` at that read is. Nothing is placed."""
    archive = _plaintext_archive(tmp_path / "plain.mfbak")
    cls, text = _FAULTS[fault]
    wrapped = _wrap_store_member(monkeypatch, cls)
    dest = tmp_path / "restored" / "store.db"
    with pytest.raises(BackupError, match=text.format(what="store.db member")) as caught:
        _restore(archive, dest)
    assert sum(w.stalls for w in wrapped) > 0
    assert caught.value.kind == "restore"
    assert str(caught.value).startswith("the restore failed: OSError: [Errno 5] ")
    assert not dest.exists()
    _assert_no_staging_left(caught.value, dest)


@pytest.mark.usefixtures("own_os_temp")
@pytest.mark.parametrize("fault", sorted(_FAULTS))
def test_restore_reports_a_none_read_of_a_plaintext_archive_as_it_reports_an_oserror(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fault: str
) -> None:
    """The plaintext branch of ``_restore_blocking`` copies the archive into the staged tar. A
    ``None`` read there used to end the copy short: at zero bytes for ``none-read``, after the first
    1 MiB for ``none-read-midway``, and the restore failed later on a short tar. It is now the
    ``restore`` refusal an ``OSError`` at that read is."""
    archive = _plaintext_archive(tmp_path / "plain.mfbak")
    cls, text = _FAULTS[fault]
    wrapped = _wrap_open(monkeypatch, cls, Path(archive))
    dest = tmp_path / "restored" / "store.db"
    with pytest.raises(BackupError, match=text.format(what="plaintext archive")) as caught:
        _restore(archive, dest)
    assert sum(w.stalls for w in wrapped) > 0
    assert caught.value.kind == "restore"
    assert str(caught.value).startswith("the restore failed: OSError: [Errno 5] ")
    assert not dest.exists()
    _assert_no_staging_left(caught.value, dest)


def _refuse_links(monkeypatch: pytest.MonkeyPatch) -> None:
    def _no_link(*_a: object, **_k: object) -> None:
        raise OSError(errno.EPERM, "synthetic: links refused")

    monkeypatch.setattr(os, "link", _no_link)


@pytest.mark.parametrize("fault", sorted(_FAULTS))
def test_the_placement_copy_reports_a_none_read_as_it_reports_an_oserror(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fault: str
) -> None:
    """``_place_restored_store``'s copy fallback, taken where a hard link is refused. A ``None``
    read used to end ``copyfileobj`` short, and a truncated store was placed and reported placed.
    It now raises at the read, as an ``OSError`` there does, and the partial file is removed."""
    src = tmp_path / "staged.db"
    src.write_bytes(b"synthetic store bytes " * 100_000)  # over 2 MiB: several reads
    dest = tmp_path / "placed.db"
    _refuse_links(monkeypatch)
    cls, text = _FAULTS[fault]
    wrapped = _wrap_open(monkeypatch, cls, src)
    with pytest.raises(OSError, match=text.format(what="staged store")) as caught:
        dr._place_restored_store(src, dest)
    assert sum(w.stalls for w in wrapped) > 0
    assert caught.value.errno == errno.EIO
    assert not dest.exists()


def test_the_placement_copy_still_copies_whole_from_a_blocking_reader(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    src = tmp_path / "staged.db"
    payload = b"synthetic store bytes " * 100_000
    src.write_bytes(payload)
    dest = tmp_path / "placed.db"
    _refuse_links(monkeypatch)
    assert dr._place_restored_store(src, dest) == (len(payload), False)
    assert dest.read_bytes() == payload


@pytest.mark.parametrize("script", [["not bytes"], [b"x" * 9]], ids=["str-read", "oversize-read"])
def test_the_refusing_reader_refuses_a_read_that_is_not_bytes_or_over_the_size(
    script: list[Any],
) -> None:
    """The reader's other per-read checks, which the placement copy also leans on."""
    reader = dr._NoneRefusingReader(_Scripted(script), "staged store")
    with pytest.raises(OSError) as caught:
        reader.read(8)
    assert caught.value.errno == errno.EIO
    assert isinstance(caught.value.__cause__, BackupCodecError)


@pytest.mark.parametrize("call", ["no-argument", "negative"])
def test_the_refusing_reader_refuses_a_read_all_before_reading(call: str) -> None:
    """A ``read()`` or ``read(-1)`` is refused with no read, rather than answered with one chunk or
    with the whole source pulled into memory."""
    src = _Scripted([b"synthetic"])
    reader = dr._NoneRefusingReader(src, "staged store")
    with pytest.raises(ValueError, match="positive"):
        if call == "no-argument":
            reader.read()
        else:
            reader.read(-1)
    assert src.reads == 0
