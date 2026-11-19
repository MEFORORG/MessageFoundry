# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Follow-ups to the upload sidecar hardening (BACKLOG #5387 added item 1, #5388 added item 2,
#5397 added item 2).

A part the filesystem refuses the engine is answered as an access refusal, never as damage, by the
store and by the API, whose 423 carries the kind as a typed signal. A plaintext sidecar too long to
seal within the sidecar cap is refused as damaged by every reader, and ``rotate-key`` skips it,
since it may hold a value under a prior key. The body check and the reseal open through ``_open_plain``. The session
token a sign-in replaces is bounded where it enters ``AuthService``. Synthetic data only."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import httpx
import pytest

import messagefoundry.uploads as uploads
from messagefoundry.api.auth_models import _TOKEN_MAX
from messagefoundry.auth import Role
from messagefoundry.auth.service import SUPERSEDES_MAX, _superseded_hash
from messagefoundry.auth.tokens import hash_token
from messagefoundry.pipeline import Engine
from messagefoundry.store.crypto import cell_aad, generate_key, make_cipher
from messagefoundry.uploads import (
    UploadDamagedError,
    UploadedFileMeta,
    UploadStore,
)
from tests._bound_proof import reproving_transport
from tests.test_b532r_uploads_sidecar_reads import _OsWith
from tests.test_upload_api import (
    ADT,
    PW,
    _add_user,
    _login,
    _make_user,
    _uploads_settings,
    engine,  # noqa: F401 - the fixture, used by name
)

_BODY = b"synthetic diagnostic line\n"


def _store(root: Path, key: str | None = None) -> UploadStore:
    cipher = make_cipher(key, write_v2=True) if key is not None else make_cipher(None)
    return UploadStore(root, cipher, max_bytes=4096)


async def _saved(store: UploadStore) -> UploadedFileMeta:
    return await store.save(data=_BODY, filename="a.txt", uploader="op", uploader_id="u-op")


def _too_long(sidecar: Path) -> str:
    """The sidecar's own JSON with an extra key that takes it past the plaintext bound, still
    under the on-disk cap."""
    d = json.loads(sidecar.read_text(encoding="utf-8"))
    d["filler"] = "x" * (uploads._PLAIN_SIDECAR_LIMIT + 1)
    text = json.dumps(d)
    assert uploads._PLAIN_SIDECAR_LIMIT < len(text) <= uploads._SIDECAR_LIMIT
    return text


# --- the plaintext bound -------------------------------------------------------------------------


def test_a_plaintext_sidecar_at_the_bound_seals_within_the_cap() -> None:
    # The bound is derived, so pin that it holds: the longest plaintext a reader takes seals into
    # a sidecar the reader still takes.
    cipher = make_cipher(generate_key(), write_v2=True)
    plain = "x" * uploads._PLAIN_SIDECAR_LIMIT
    sealed = cipher.encrypt(plain, aad=cell_aad("uploaded_file", "meta", "0" * 32))
    assert len(sealed.encode("utf-8")) <= uploads._SIDECAR_LIMIT


async def test_a_plaintext_sidecar_too_long_to_seal_is_damaged_on_every_read(
    tmp_path: Path,
) -> None:
    # Follow-up: on origin/main's branch head such a sidecar was read (keyless) or refused under
    # the key for good, and rotate-key failed on it on every run.
    store = _store(tmp_path / "uploads")
    meta = await _saved(store)
    sidecar = store._root / f"{meta.file_id}.meta"  # noqa: SLF001
    sidecar.write_text(_too_long(sidecar), encoding="utf-8")
    with pytest.raises(UploadDamagedError):
        await store.get_meta(meta.file_id)
    assert await store.list_files() == []


async def test_rotate_key_skips_a_too_long_plaintext_sidecar(tmp_path: Path) -> None:
    # BACKLOG #5387, fail-safe: rotate-key does not read inside a sidecar it refuses, so it is a
    # skip and the rotation stays open.
    root = tmp_path / "uploads"
    meta = await _saved(_store(root))
    sidecar = root / f"{meta.file_id}.meta"
    planted = _too_long(sidecar)
    sidecar.write_text(planted, encoding="utf-8")
    result = await _store(root, generate_key()).reseal_to_active()
    assert (result.skipped, result.refused_sidecars, result.damaged) == (1, 1, 0)
    assert result.incomplete
    assert sidecar.read_text(encoding="utf-8") == planted


async def test_a_sealed_sidecar_is_not_held_to_the_plaintext_bound(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Control: the bound is a plaintext one. A sealed sidecar longer than it still reads.
    key = generate_key()
    store = _store(tmp_path / "uploads", key)
    meta = await _saved(store)
    sealed = (store._root / f"{meta.file_id}.meta").read_text(encoding="utf-8")  # noqa: SLF001
    monkeypatch.setattr(uploads, "_PLAIN_SIDECAR_LIMIT", len(sealed) - 1)
    assert await store.get_meta(meta.file_id) == meta


# --- the body check and the reseal open through _open_plain ---------------------------------------


async def test_the_body_check_and_the_reseal_open_through_open_plain(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Review finding 6: _lost_body_size and _reseal_half opened by name after their own lstat or
    # stat, so a link or FIFO swapped in between was followed or waited on.
    root = tmp_path / "uploads"
    meta = await _saved(_store(root))
    opened: list[str] = []
    real = uploads._open_plain

    def _spy(path: Path) -> Any:
        opened.append(path.name)
        return real(path)

    monkeypatch.setattr(uploads, "_open_plain", _spy)
    keyed = _store(root, generate_key())
    blob = root / f"{meta.file_id}.blob"
    assert keyed._lost_body_size(blob) is None  # noqa: SLF001 - readable text
    assert opened == [blob.name]
    opened.clear()
    result = await keyed.reseal_to_active()
    assert result.resealed == 2
    assert {f"{meta.file_id}.blob", f"{meta.file_id}.meta"} <= set(opened)


async def test_the_body_check_does_not_follow_a_link(tmp_path: Path) -> None:
    # On the branch head blob.stat() followed the link, so a link to a file that is not text made
    # the upload read as one whose body is lost, which the prune and the delete then remove.
    root = tmp_path / "uploads"
    store = _store(root)
    meta = await _saved(store)
    blob = root / f"{meta.file_id}.blob"
    target = tmp_path / "elsewhere"
    target.write_bytes(b"\xff\xfe not text")
    blob.unlink()
    try:
        blob.symlink_to(target)
    except OSError:
        pytest.skip("this account cannot create a symbolic link")
    assert store._lost_body_size(blob) is None  # noqa: SLF001


async def test_the_body_check_opens_nothing_on_a_cached_match(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Review round 1: the body was opened on every scan, even when its check was cached.
    root = tmp_path / "uploads"
    store = _store(root)
    meta = await _saved(store)
    blob = root / f"{meta.file_id}.blob"
    assert store._lost_body_size(blob) is None  # noqa: SLF001 - fills the cache
    opened: list[str] = []
    real = uploads._open_plain

    def _spy(path: Path) -> Any:
        opened.append(path.name)
        return real(path)

    monkeypatch.setattr(uploads, "_open_plain", _spy)
    assert store._lost_body_size(blob) is None  # noqa: SLF001
    assert opened == []
    # Control: a changed body is opened and checked again.
    blob.write_bytes(b"\xff\xfe not text")
    assert store._lost_body_size(blob) == len(b"\xff\xfe not text")  # noqa: SLF001
    assert opened == [blob.name]


async def test_the_body_check_logs_a_refused_open(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    root = tmp_path / "uploads"
    store = _store(root)
    meta = await _saved(store)
    blob = root / f"{meta.file_id}.blob"

    def _deny(path: Path) -> Any:
        raise PermissionError(13, "Permission denied", str(path))

    monkeypatch.setattr(uploads, "_open_plain", _deny)
    with caplog.at_level("WARNING", logger=uploads._log.name):  # noqa: SLF001
        assert store._lost_body_size(blob) is None  # noqa: SLF001
    assert "could not check the body" in caplog.text


def test_open_plain_closes_the_descriptor_when_fdopen_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "plain.txt"
    path.write_bytes(b"synthetic")
    opened: list[int] = []
    closed: list[int] = []
    real_open, real_close = os.open, os.close

    def _open(p: Any, flags: int, *args: Any) -> int:
        fd = real_open(p, flags, *args)
        opened.append(fd)
        return fd

    def _close(fd: int) -> None:
        closed.append(fd)
        real_close(fd)

    def _fdopen(*_a: Any, **_k: Any) -> Any:
        raise MemoryError("synthetic")

    monkeypatch.setattr(os, "open", _open)
    monkeypatch.setattr(os, "close", _close)
    monkeypatch.setattr(os, "fdopen", _fdopen)
    with pytest.raises(MemoryError):
        uploads._open_plain(path)
    assert opened and closed == opened


async def test_a_sidecar_that_grew_after_its_fstat_is_read_bounded(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Review round 1: past the size gate the reseal read the rest of the file without a bound, so
    # one that grew after the fstat was read whole.
    root = tmp_path / "uploads"
    meta = await _saved(_store(root))
    sidecar = root / f"{meta.file_id}.meta"
    sidecar.write_text("x" * (uploads._SIDECAR_LIMIT + 4096), encoding="utf-8")
    real = uploads._open_plain
    read: list[int] = []

    class _Counted:
        def __init__(self, handle: Any) -> None:
            self._h = handle

        def read(self, n: int = -1) -> bytes:
            data: bytes = self._h.read(n)
            read.append(len(data))
            return data

        def __enter__(self) -> _Counted:
            return self

        def __exit__(self, *exc: object) -> None:
            self._h.close()

    class _Small:
        def __init__(self, st: os.stat_result) -> None:
            self._st = st
            self.st_size = 10

        def __getattr__(self, name: str) -> Any:
            return getattr(self._st, name)

    def _stale(path: Path) -> Any:
        handle, st = real(path)
        if path == sidecar:
            return _Counted(handle), _Small(st)
        return handle, st

    monkeypatch.setattr(uploads, "_open_plain", _stale)
    result = await _store(root, generate_key()).reseal_to_active()
    assert (result.skipped, result.refused_sidecars, result.damaged) == (1, 1, 0)
    assert sum(read) <= uploads._SIDECAR_LIMIT + 1


@pytest.mark.parametrize("lost_body", [True, False])
@pytest.mark.parametrize("planted", [b" \r\n", b"", b"\xef\xbb\xbf \t"])
async def test_a_blank_sidecar_is_left_as_damaged(
    tmp_path: Path, planted: bytes, lost_body: bool
) -> None:
    # Review rounds 1 and 2: a padding-only sidecar was sealed as an empty value, or sealed as
    # plaintext, with a fresh mtime that restarted the prune's window. Read in full within the
    # cap, it provably holds nothing, so it is neither written nor skipped (BACKLOG #5387).
    root = tmp_path / "uploads"
    meta = await _saved(_store(root))
    sidecar = root / f"{meta.file_id}.meta"
    sidecar.write_bytes(planted)
    if lost_body:
        (root / f"{meta.file_id}.blob").unlink()
    result = await _store(root, generate_key()).reseal_to_active()
    assert result.damaged == 1 and result.unsealable == 0 and not result.incomplete
    assert result.resealed == (0 if lost_body else 1)  # the body alone, when there is one
    assert sidecar.read_bytes() == planted


async def test_a_current_sidecar_padded_past_the_cap_is_a_skip_not_current(
    tmp_path: Path,
) -> None:
    # Review round 2: the active-marker test ran before the cap, so this read as CURRENT. Every
    # reader refuses it before decrypting, so it is a skip (BACKLOG #5387).
    key = generate_key()
    root = tmp_path / "uploads"
    meta = await _saved(_store(root, key))
    sidecar = root / f"{meta.file_id}.meta"
    padded = sidecar.read_bytes() + b" " * (uploads._SIDECAR_LIMIT + 1)
    sidecar.write_bytes(padded)
    result = await _store(root, key).reseal_to_active()
    assert (result.skipped, result.refused_sidecars, result.damaged) == (1, 1, 0)
    assert sidecar.read_bytes() == padded


async def test_the_reseal_read_is_sized_by_the_file_not_the_limit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Review round 2: read(limit + 1) allocates the whole limit, about twice max_upload_bytes,
    # for every body however small.
    root = tmp_path / "uploads"
    await _saved(_store(root))
    real = uploads._open_plain
    asked: list[int] = []

    class _Asked:
        def __init__(self, handle: Any) -> None:
            self._h = handle

        def read(self, n: int = -1) -> bytes:
            asked.append(n)
            data: bytes = self._h.read(n)
            return data

        def __enter__(self) -> _Asked:
            return self

        def __exit__(self, *exc: object) -> None:
            self._h.close()

    def _spy(path: Path) -> Any:
        handle, st = real(path)
        return _Asked(handle), st

    monkeypatch.setattr(uploads, "_open_plain", _spy)
    result = await _store(root, generate_key()).reseal_to_active()
    assert result.resealed == 2
    assert asked and max(asked) <= 4096


def test_a_permission_error_on_a_folder_is_damage(tmp_path: Path) -> None:
    # Review round 2: Windows answers an open of a folder with a PermissionError.
    folder = tmp_path / "x.meta"
    folder.mkdir()
    assert uploads._refused_read(PermissionError(13, "denied", str(folder))) == "damaged"
    plain = tmp_path / "y.meta"
    plain.write_bytes(b"synthetic")
    assert uploads._refused_read(PermissionError(13, "denied", str(plain))) == "denied"
    assert uploads._refused_read(PermissionError(13, "denied")) == "denied"


def test_the_plain_open_sets_o_noctty_where_there_is_one() -> None:
    noctty = getattr(os, "O_NOCTTY", 0)
    assert uploads._PLAIN_OPEN_FLAGS & noctty == noctty


async def test_a_keyless_save_refuses_a_sidecar_past_the_plaintext_bound(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Review round 1: a keyless store could write a plaintext sidecar every reader then refuses.
    store = _store(tmp_path / "uploads")
    monkeypatch.setattr(uploads, "_PLAIN_SIDECAR_LIMIT", 64)
    with pytest.raises(uploads.UploadFieldError):
        await _saved(store)
    assert not any(p.suffix in {".meta", ".blob"} for p in tmp_path.rglob("*"))
    # Control: a keyed store seals the same sidecar, so the plaintext bound does not apply.
    assert (await _saved(_store(tmp_path / "keyed", generate_key()))).file_id


# --- the API answers an access refusal with its own text and kind ---------------------------------

_ACCESS_TEXT_START = "this uploaded file could not be opened, because the filesystem refused"


async def test_the_api_answers_an_access_refusal_apart_from_damage(
    engine: Engine,  # noqa: F811 - the imported fixture
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pytest.importorskip("psutil")
    from messagefoundry.api import create_app

    service = await _make_user(engine, Role.OPERATOR, name="op")
    await _add_user(service, Role.ADMINISTRATOR, name="root")
    root = tmp_path / "uploads"
    app = create_app(engine, auth=service, store_settings=_uploads_settings(tmp_path))
    transport = reproving_transport(PW, app=app)
    denied: set[Path] = set()

    def _deny(path: Any, flags: int, *args: Any) -> int:
        if Path(path) in denied:
            raise PermissionError(13, "Permission denied", str(path))
        return os.open(path, flags, *args)

    monkeypatch.setattr(uploads, "os", _OsWith(_deny))
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
        h = await _login(c, "op")
        ha = await _login(c, "root")
        body_fid = (
            await c.post("/uploads", files={"file": ("x.hl7", ADT, "text/plain")}, headers=h)
        ).json()["file_id"]
        meta_fid = (
            await c.post("/uploads", files={"file": ("y.hl7", ADT, "text/plain")}, headers=h)
        ).json()["file_id"]
        denied.update({root / f"{body_fid}.blob", root / f"{meta_fid}.meta"})
        # A body the engine may not open reaches its owner as the access 423.
        r = await c.get(f"/uploads/{body_fid}/messages", headers=h)
        assert r.status_code == 423, r.text
        assert r.json()["detail"].startswith(_ACCESS_TEXT_START)
        assert "damaged" not in r.json()["detail"].split(".")[0]
        # A sidecar the engine may not open hides its owner, so only the override holder gets it,
        # on browse and on delete, and the delete removes nothing.
        assert (await c.get(f"/uploads/{meta_fid}/messages", headers=h)).status_code == 404
        for r in (
            await c.get(f"/uploads/{meta_fid}/messages", headers=ha),
            await c.delete(f"/uploads/{meta_fid}", headers=ha),
        ):
            assert r.status_code == 423, r.text
            assert r.json()["detail"].startswith(_ACCESS_TEXT_START)
    assert (root / f"{meta_fid}.meta").exists() and (root / f"{meta_fid}.blob").exists()


# --- the superseded session token is bounded where it enters AuthService -------------------------


def test_the_engine_bound_matches_the_json_route() -> None:
    assert SUPERSEDES_MAX == _TOKEN_MAX


def test_an_oversized_superseded_token_is_not_hashed() -> None:
    assert _superseded_hash("a" * (SUPERSEDES_MAX + 1)) is None
    assert _superseded_hash("") is None
    assert _superseded_hash(None) is None
    # Control: at the bound it is the token's own hash.
    assert _superseded_hash("a" * SUPERSEDES_MAX) == hash_token("a" * SUPERSEDES_MAX)


async def test_a_sign_in_ends_no_session_for_an_oversized_superseded_token(
    engine: Engine,  # noqa: F811 - the imported fixture
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Review finding 5: only /ui/login bounded the cookie, so the SSO and federated legs, and any
    # other caller, passed one of any length on to be hashed.
    service = await _make_user(engine, Role.OPERATOR, name="op")
    ended: list[str] = []

    async def _spy(prior_hash: str, *, client: str | None) -> None:
        ended.append(prior_hash)

    monkeypatch.setattr(service, "_supersede_session_hash", _spy)
    long = "a" * (SUPERSEDES_MAX + 1)
    assert (await service.login("op", PW, supersedes=long)).ok
    assert ended == []
    within = "a" * SUPERSEDES_MAX
    assert (await service.login("op", PW, supersedes=within)).ok
    assert ended == [hash_token(within)]
