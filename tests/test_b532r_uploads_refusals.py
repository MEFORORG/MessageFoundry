# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Follow-ups to the upload sidecar hardening (BACKLOG #5387 added item 1, #5388 added item 2,
#5397 added item 2).

A part the filesystem refuses the engine is answered as an access refusal, never as damage, by the
store and by the API, whose 423 carries the kind as a typed signal. A plaintext sidecar too long to
seal within the sidecar cap is refused as damaged by every reader and left by ``rotate-key`` as a
terminal count, not a skip. The body check and the reseal open through ``_open_plain``. The session
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


async def test_rotate_key_counts_a_too_long_plaintext_sidecar_apart_and_completes(
    tmp_path: Path,
) -> None:
    root = tmp_path / "uploads"
    meta = await _saved(_store(root))
    sidecar = root / f"{meta.file_id}.meta"
    planted = _too_long(sidecar)
    sidecar.write_text(planted, encoding="utf-8")
    result = await _store(root, generate_key()).reseal_to_active()
    assert (result.skipped, result.too_long) == (0, 1)
    assert not result.incomplete
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
