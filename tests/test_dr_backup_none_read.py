# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #6687: a DR copy loop refuses a ``None`` read rather than reading it as end of stream.

A non-blocking source answers ``None`` when it has nothing ready. A copy loop that stops on
``if not buf: break`` ends the copy short there. Three copy loops in ``pipeline/dr_backup.py`` now
share :func:`dr_backup._read_chunks`, which reads through the codec's ``_read_once`` and so refuses
a ``None`` read, as the keyed branch does. It raises the refusal as an ``OSError``, so each site
reports it the way it reports any ``OSError`` in that copy; these tests drive each of the three and
check that report. Reads in that module this branch does not change include at least
``_extract_member``, the plaintext branch of ``_restore_blocking``, the ``shutil.copyfileobj`` in
``_place_restored_store`` and ``_sha256_file``. The sources are synthetic: a store with one made-up
row, and a tar of made-up config bytes."""

from __future__ import annotations

import builtins
import errno
import hashlib
import io
import tarfile
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
