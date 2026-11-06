# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A Transit outage on the data key is :class:`CipherUnavailableError`, and the upload routes answer
it 503 with ``Retry-After`` where a refused value still answers 423 (BACKLOG #3734).

The cipher half runs against a fake Transit client whose ``encrypt_data`` / ``decrypt_data`` raise
what hvac and requests raise for each failure. The route half swaps a Transit-backed upload store
into the app, as ``tests/test_upload_api.py`` swaps a keyed one in. Synthetic HL7 only."""

from __future__ import annotations

import base64
import os
from collections.abc import Callable
from pathlib import Path
from typing import Any

import httpx
import pytest
import requests
from hvac.exceptions import (  # type: ignore[import-untyped]
    BadGateway,
    Forbidden,
    InternalServerError,
    InvalidPath,
    InvalidRequest,
    RateLimitExceeded,
    VaultDown,
)

from messagefoundry.auth import Role
from messagefoundry.pipeline import Engine
from messagefoundry.store.crypto import CipherError, CipherUnavailableError, cell_aad
from messagefoundry.store.crypto_transit import TransitCipher
from messagefoundry.store.keyprovider_vault import is_vault_unavailable
from messagefoundry.transports.bounded_read import MalformedReplyHeadError
from messagefoundry.transports.strict_requests import VaultHopRefused
from messagefoundry.uploads import (
    UploadStore,
    UploadUnavailableError,
    UploadUnreadableError,
)
from messagefoundry_webconsole.routes import uploaded_logs
from tests._bound_proof import reproving_transport
from tests.test_crypto_transit import _FakeClient
from tests.test_crypto_transit import _FakeTransit as _RealAeadTransit
from tests.test_upload_api import (
    BATCH,
    PW,
    _add_user,
    _login,
    _make_user,
    _running_registry,
    _uploads_settings,
    engine,
)

__all__ = ["engine"]  # the fixture, imported so this file runs on the same engine

_KEY = "mefor-store"


def _malformed_head() -> requests.exceptions.ConnectionError:
    """The shape the strict reply adapter's ``build_response`` raises for a reply head it refused."""
    refusal = MalformedReplyHeadError("vault framed its reply head ambiguously", reason="bare-cr")
    try:
        raise requests.exceptions.ConnectionError(refusal) from refusal
    except requests.exceptions.ConnectionError as exc:
        return exc


_OUTAGES: list[Exception] = [
    requests.exceptions.ConnectionError("connection refused"),
    requests.exceptions.ConnectTimeout("connect timed out"),
    requests.exceptions.ReadTimeout("read timed out"),
    VaultDown("Vault is sealed"),
    InternalServerError("internal error"),
    BadGateway("bad gateway"),
    RateLimitExceeded("rate limited"),
]
_REFUSALS: list[Exception] = [
    InvalidRequest("cipher: message authentication failed"),
    Forbidden("permission denied"),
    InvalidPath("no such key"),
    requests.exceptions.SSLError("certificate verify failed"),
    VaultHopRefused("store: the Vault hop is refused"),
    RuntimeError("anything else"),
    _malformed_head(),
    # urllib3 and requests keep a wrapped error in ``args``, with no cause set.
    requests.exceptions.ConnectionError(
        MalformedReplyHeadError("vault framed its reply head ambiguously", reason="bare-cr")
    ),
]


@pytest.mark.parametrize("exc", _OUTAGES, ids=lambda e: type(e).__name__)
def test_an_outage_reads_as_unavailable(exc: Exception) -> None:
    assert is_vault_unavailable(exc)


@pytest.mark.parametrize("exc", _REFUSALS, ids=lambda e: type(e).__name__)
def test_a_refusal_does_not_read_as_unavailable(exc: Exception) -> None:
    assert not is_vault_unavailable(exc)


class _FakeTransit(_RealAeadTransit):
    """The suite's AES-GCM Transit stand-in, with failure hooks.

    ``fail`` is raised by every data-key call whose associated data ``when`` accepts, and
    ``hmac_fail`` by every audit HMAC."""

    def __init__(self) -> None:
        super().__init__()
        self.fail: Exception | None = None
        self.when: Callable[[str | None], bool] = lambda _assoc: True
        self.hmac_fail: Exception | None = None

    def _check(self, assoc: str | None) -> None:
        if self.fail is not None and self.when(assoc):
            raise self.fail

    def encrypt_data(self, *, associated_data: str | None = None, **kw: Any) -> dict[str, Any]:
        self._check(associated_data)
        return super().encrypt_data(associated_data=associated_data, **kw)

    def decrypt_data(self, *, associated_data: str | None = None, **kw: Any) -> dict[str, Any]:
        self._check(associated_data)
        return super().decrypt_data(associated_data=associated_data, **kw)

    def generate_hmac(self, **kw: Any) -> dict[str, Any]:
        if self.hmac_fail is not None:
            raise self.hmac_fail
        return super().generate_hmac(**kw)


def _cipher() -> tuple[TransitCipher, _FakeTransit]:
    transit = _FakeTransit()
    return TransitCipher(_FakeClient(transit), _KEY), transit


def _assoc(column: str, file_id: str) -> str:
    return base64.b64encode(cell_aad("uploaded_file", column, file_id)).decode("ascii")


# --- the cipher -------------------------------------------------------------------------------


@pytest.mark.parametrize("exc", _OUTAGES, ids=lambda e: type(e).__name__)
def test_an_outage_on_encrypt_and_decrypt_is_cipher_unavailable(exc: Exception) -> None:
    cipher, transit = _cipher()
    stored = cipher.encrypt("PID|1||MRN123", aad=b"cell")
    transit.fail = exc
    for call in (
        lambda: cipher.encrypt("PID|1||MRN123", aad=b"cell"),
        lambda: cipher.decrypt(stored, aad=b"cell"),
    ):
        with pytest.raises(CipherUnavailableError) as info:
            call()
        # Type-only, as before: no plaintext and no Vault text.
        assert "MRN123" not in str(info.value) and type(exc).__name__ in str(info.value)


@pytest.mark.parametrize("exc", _REFUSALS, ids=lambda e: type(e).__name__)
def test_a_refusal_on_encrypt_and_decrypt_stays_plain_cipher_error(exc: Exception) -> None:
    cipher, transit = _cipher()
    stored = cipher.encrypt("PID|1", aad=b"cell")
    transit.fail = exc
    for call in (
        lambda: cipher.encrypt("PID|1", aad=b"cell"),
        lambda: cipher.decrypt(stored, aad=b"cell"),
    ):
        with pytest.raises(CipherError) as info:
            call()
        assert not isinstance(info.value, CipherUnavailableError)


def test_a_refused_tag_is_not_an_outage() -> None:
    """Control on the fake: a value moved to another cell fails its AES-GCM tag, a refusal."""
    cipher, _ = _cipher()
    stored = cipher.encrypt("PID|1", aad=b"cell-a")
    with pytest.raises(CipherError) as info:
        cipher.decrypt(stored, aad=b"cell-b")
    assert not isinstance(info.value, CipherUnavailableError)
    assert cipher.decrypt(stored, aad=b"cell-a") == "PID|1"


def test_the_audit_hmac_keeps_plain_cipher_error_on_an_outage() -> None:
    """The split is for the data key's encrypt and decrypt alone."""
    cipher, transit = _cipher()
    transit.hmac_fail = requests.exceptions.ConnectionError("connection refused")
    with pytest.raises(CipherError) as info:
        cipher.audit_hmac(b"row")
    assert not isinstance(info.value, CipherUnavailableError)


# --- the upload store -------------------------------------------------------------------------


async def test_the_upload_store_raises_unavailable_for_an_outage(tmp_path: Path) -> None:
    cipher, transit = _cipher()
    store = UploadStore(tmp_path, cipher, max_bytes=1 << 20)
    meta = await store.save(data=BATCH.encode(), filename="a.hl7", uploader="op", uploader_id="u-1")
    transit.fail = requests.exceptions.ConnectionError("connection refused")
    for call in (store.get_meta, store.read_bytes, store.delete):
        with pytest.raises(UploadUnavailableError):
            await call(meta.file_id)
    with pytest.raises(UploadUnavailableError):
        await store.save(data=BATCH.encode(), filename="b.hl7", uploader="op", uploader_id="u-1")
    # Nothing was removed, and the refused save left nothing behind.
    assert sorted(p.name for p in tmp_path.iterdir()) == sorted(
        [f"{meta.file_id}.blob", f"{meta.file_id}.meta"]
    )
    transit.fail = None
    assert (await store.read_bytes(meta.file_id)).decode() == BATCH


async def test_the_upload_store_still_raises_unreadable_for_a_refusal(tmp_path: Path) -> None:
    cipher, transit = _cipher()
    store = UploadStore(tmp_path, cipher, max_bytes=1 << 20)
    meta = await store.save(data=BATCH.encode(), filename="a.hl7", uploader="op", uploader_id="u-1")
    transit.fail = InvalidRequest("cipher: message authentication failed")
    for call in (store.get_meta, store.read_bytes, store.delete):
        with pytest.raises(UploadUnreadableError):
            await call(meta.file_id)
    assert (tmp_path / f"{meta.file_id}.meta").exists()


# --- the routes -------------------------------------------------------------------------------


async def test_the_upload_routes_answer_an_outage_503_and_a_refusal_423(
    engine: Engine, tmp_path: Path
) -> None:
    """* An override holder whose sidecar read meets an outage gets 503 with ``Retry-After`` on
      browse, resend and delete, where a refused sidecar gets 423.
    * The owner, who cannot be told apart from anyone else while the sidecar is unread, keeps 404.
    * A readable sidecar over a body read that meets an outage gets the owner 503.
    * An upload during an outage answers 503 and stores nothing."""
    pytest.importorskip("psutil")
    from messagefoundry.api import create_app

    engine.add_registry(_running_registry(tmp_path))
    await engine.start()
    service = await _make_user(engine, Role.OPERATOR, name="op")
    await _add_user(service, Role.ADMINISTRATOR, name="root")
    root = tmp_path / "uploads"
    app = create_app(engine, auth=service, store_settings=_uploads_settings(tmp_path))
    cipher, transit = _cipher()
    root.mkdir(parents=True, exist_ok=True)
    app.state.upload_store = UploadStore(root, cipher, max_bytes=10**6, max_files_per_user=100)
    async with httpx.AsyncClient(
        transport=reproving_transport(PW, app=app), base_url="http://t"
    ) as c:
        h = await _login(c, "op")
        ha = await _login(c, "root")
        r = await c.post("/uploads", files={"file": ("a.hl7", BATCH, "text/plain")}, headers=h)
        assert r.status_code == 200, r.text
        fid = r.json()["file_id"]

        async def _by_id(headers: dict[str, str], *, delete: bool = True) -> list[httpx.Response]:
            out = [
                await c.get(f"/uploads/{fid}/messages", headers=headers),
                await c.post(
                    f"/uploads/{fid}/resend", json={"index": 0, "to": "in1"}, headers=headers
                ),
            ]
            if delete:
                out.append(await c.delete(f"/uploads/{fid}", headers=headers))
            return out

        transit.fail = requests.exceptions.ConnectionError("connection refused")
        for r in await _by_id(ha):
            assert r.status_code == 503, r.text
            assert r.headers.get("retry-after") == "5"
            assert "key service" in r.text and "a.hl7" not in r.text and "MRN" not in r.text
        for r in await _by_id(h):
            assert r.status_code == 404, r.text  # the owner is unreadable: no existence oracle

        transit.fail = InvalidRequest("cipher: message authentication failed")
        for r in await _by_id(ha):
            assert r.status_code == 423, r.text
            assert "retry-after" not in r.headers

        # The sidecar reads; only the body read meets the outage.
        transit.fail = requests.exceptions.ReadTimeout("read timed out")
        transit.when = lambda assoc: assoc == _assoc("body", fid)
        for r in await _by_id(h, delete=False):
            assert r.status_code == 503, r.text
            assert r.headers.get("retry-after") == "5"

        transit.when = lambda _assoc: True
        transit.fail = VaultDown("Vault is sealed")
        r = await c.post("/uploads", files={"file": ("b.hl7", BATCH, "text/plain")}, headers=h)
        assert r.status_code == 503, r.text
        assert r.headers.get("retry-after") == "5"

        transit.fail = None
        assert sorted(os.listdir(root)) == sorted([f"{fid}.blob", f"{fid}.meta"])
        assert [f["file_id"] for f in (await c.get("/uploads", headers=h)).json()["files"]] == [fid]


# --- the web console --------------------------------------------------------------------------


def test_the_console_tells_an_outage_503_from_a_missing_store_503() -> None:
    from fastapi import HTTPException

    outage = HTTPException(503, "key service", headers={"Retry-After": "5"})
    no_store = HTTPException(503, "uploaded logs are not configured")
    for codes in (
        uploaded_logs._BROWSE_CODES,  # noqa: SLF001
        uploaded_logs._RESEND_CODES,  # noqa: SLF001
        uploaded_logs._DELETE_CODES,  # noqa: SLF001
    ):
        assert uploaded_logs._refusal_code(outage, codes) == uploaded_logs.KEY_SERVICE_BUSY_CODE  # noqa: SLF001
        assert (
            uploaded_logs._refusal_code(no_store, codes) == uploaded_logs.UPLOADS_UNAVAILABLE_CODE
        )  # noqa: SLF001
    assert (
        uploaded_logs._LIST_NOTICES[uploaded_logs.KEY_SERVICE_BUSY_CODE]  # noqa: SLF001
        == uploaded_logs.KEY_SERVICE_BUSY_NOTICE
    )
