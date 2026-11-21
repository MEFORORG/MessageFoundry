# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #5391 added item 2: a start refused by ``[api].tls_client_ca_file`` leaves its audit row.

``serve`` builds the API TLS context before uvicorn runs the lifespan, so a refused client CA used
to stop the start before the store opened, and the lifespan's audited preflight never wrote the
anchor's ``auth.trust_anchor`` row. The forwarder's CA kept its row (BACKLOG #3470). Each test
here drives ``serve`` itself, with the real context build, and reads the store afterwards.
"""

from __future__ import annotations

import asyncio
import json
import logging
from pathlib import Path
from typing import Any

import pytest

from messagefoundry import __main__ as cli
from messagefoundry.__main__ import main
from messagefoundry.auth import trust_anchors as ta
from messagefoundry.auth.anchor_path import PathVerdict
from messagefoundry.pki import make_self_signed
from messagefoundry.store.crypto import generate_key
from messagefoundry.store.store import MessageStore

SAMPLES_CONFIG = Path(__file__).resolve().parents[1] / "samples" / "config"
_WRONG_PIN = "00" * 32


def _serve_with_client_ca(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    pin: str | None,
    extra_api: str = "",
) -> tuple[int, Path]:
    """Run ``serve`` in ``tmp_path`` with a client CA pinned to ``pin``, or to its own bytes when
    ``pin`` is None. uvicorn is stubbed, so nothing binds; the managed app and the API context are
    real."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("MEFOR_STORE_ENCRYPTION_KEY", generate_key())
    ca = tmp_path / "client-ca.pem"
    ca.write_bytes(make_self_signed("client-ca.example", [], 30)[0])
    if pin is None:
        pin = ta.anchor_fingerprint(ca)
    cert_pem, key_pem = make_self_signed("localhost", ["127.0.0.1"], 30)
    cert, key = tmp_path / "api-cert.pem", tmp_path / "api-key.pem"
    cert.write_bytes(cert_pem)
    key.write_bytes(key_pem)
    (tmp_path / "messagefoundry.toml").write_text(
        'security.enforcement = "warn"\n'
        "[api]\n"
        f"tls_cert_file = {json.dumps(str(cert))}\n"
        f"tls_key_file = {json.dumps(str(key))}\n"
        f"tls_client_ca_file = {json.dumps(str(ca))}\n"
        f'tls_client_ca_pin = "{pin}"\n'
        f"{extra_api}",
        encoding="utf-8",
    )
    # The host's temp directory decides the path and ACL verdicts, not the test (BACKLOG #1142).
    monkeypatch.setattr(ta, "anchor_path_verdict", lambda _p: PathVerdict(True))
    monkeypatch.setattr(ta, "dacl_is_owner_only", lambda _p: True)
    monkeypatch.setattr("uvicorn.run", lambda *a, **k: None)
    rc = main(["serve", "--config", str(SAMPLES_CONFIG), "--env", "dev"])
    return rc, tmp_path / "messagefoundry.db"


def _anchor_rows(db: Path) -> list[dict[str, Any]]:
    async def read() -> list[dict[str, Any]]:
        store = await MessageStore.open(db)
        try:
            rows = await store.list_audit(action=ta.AUDIT_ACTION, limit=200)
        finally:
            await store.close()
        return [json.loads(r["detail"]) for r in rows]

    return asyncio.run(read())


def test_a_refused_client_ca_writes_its_trust_anchor_row(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Red on main: the refusal returned 2 before any store opened, so no store, and no row."""
    rc, db = _serve_with_client_ca(tmp_path, monkeypatch, pin=_WRONG_PIN)
    assert rc == 2
    err = capsys.readouterr().err
    assert "error: the API TLS context was not built:" in err
    assert db.is_file(), "the refusal opened no store, so it wrote no audit row"
    events = [r.get("event") for r in _anchor_rows(db) if r.get("label") == "api_client"]
    assert "pin_mismatch" in events, events


def test_a_store_that_does_not_open_leaves_the_clean_refusal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The audit is best-effort on a start already refused: a store that fails to open is logged,
    and the exit stays the clean 2 rather than the uncaught floor's 1."""

    async def refuse_open(*_a: object, **_k: object) -> object:
        raise OSError("planted store open failure")

    monkeypatch.setattr("messagefoundry.api.app.open_store", refuse_open)
    seen: list[str] = []

    class _Grab(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            seen.append(record.getMessage())

    grab = _Grab(logging.WARNING)
    logger = logging.getLogger(cli.__name__)
    logger.addHandler(grab)
    try:
        logger.warning("probe")
        assert seen == ["probe"]
        rc, _db = _serve_with_client_ca(tmp_path, monkeypatch, pin=_WRONG_PIN)
    finally:
        logger.removeHandler(grab)
    assert rc == 2
    assert "error: the API TLS context was not built:" in capsys.readouterr().err
    assert [m for m in seen if "no audit row records the refused [api].tls_client_ca_file" in m], (
        seen
    )


def test_a_context_that_builds_opens_no_store_for_the_audit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The control: with the CA's own pin the context builds, the start goes on to uvicorn
    (stubbed), and this path runs no lifespan, so it opens no store."""
    calls: list[bool] = []
    real = cli._audit_refused_api_client_ca

    def spy(*a: Any, **k: Any) -> None:
        calls.append(True)
        real(*a, **k)

    monkeypatch.setattr(cli, "_audit_refused_api_client_ca", spy)
    rc, db = _serve_with_client_ca(tmp_path, monkeypatch, pin=None)
    assert rc == 0
    assert calls == []
    assert not db.exists()


def test_a_refused_crl_beside_a_sound_ca_opens_no_store(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The context also refuses ``[api].tls_client_crl_file``, which the audited preflight leaves
    out, so no row could come of it. With that CRL refused and the CA sound, no startup runs."""
    from messagefoundry.api import tls as api_tls

    crl = tmp_path / "client.crl"
    crl.write_bytes(b"planted")

    def refuse(*_a: object, **_k: object) -> object:
        raise ta.TrustAnchorError("planted CRL refusal")

    real_refusal = ta.anchor_refusal

    def crl_refused(spec: ta.AnchorSpec, **kw: Any) -> ta.TrustAnchorError | None:
        if spec.label == "api_client_crl":
            return ta.TrustAnchorError("planted CRL refusal")
        return real_refusal(spec, **kw)

    monkeypatch.setattr(api_tls, "build_api_ssl_context", refuse)
    monkeypatch.setattr(ta, "anchor_refusal", crl_refused)
    crl_line = f"tls_client_crl_file = {json.dumps(str(crl))}\n"
    rc, db = _serve_with_client_ca(tmp_path, monkeypatch, pin=None, extra_api=crl_line)
    assert rc == 2
    assert "error: the API TLS context was not built:" in capsys.readouterr().err
    assert not db.exists()


def test_a_ca_refused_for_its_content_writes_its_row(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """A CA refused for what its bytes hold passes the pin, ACL and path checks, and is still the
    CA's refusal: the audited preflight writes its row. Round 2 review finding 1."""
    from messagefoundry.api import tls as api_tls

    def refuse(*_a: object, **_k: object) -> object:
        raise ta.TrustAnchorError("planted content refusal")

    monkeypatch.setattr(api_tls, "build_api_ssl_context", refuse)
    rc, db = _serve_with_client_ca(tmp_path, monkeypatch, pin=None)
    assert rc == 2
    assert "error: the API TLS context was not built:" in capsys.readouterr().err
    assert db.is_file(), "the CA's refusal ran no audited startup"
