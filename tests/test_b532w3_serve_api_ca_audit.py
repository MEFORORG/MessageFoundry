# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #5391 added item 2: a start refused by ``[api].tls_client_ca_file`` leaves its audit row.

``serve`` builds the API TLS context before uvicorn runs the lifespan, so a refused client CA used
to stop the start before the store opened, and the lifespan's audited preflight never wrote the
anchor's ``auth.trust_anchor`` row. ``serve`` now runs that audited preflight against the store
directly, with no lifespan. Each test drives ``serve`` itself, with the real context build unless
it says otherwise, and reads the store afterwards. Every PEM here is synthetic.
"""

from __future__ import annotations

import asyncio
import json
import logging
from collections.abc import Callable, Iterator
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
# A synthetic private-key block: the anchors' content check refuses a file holding one.
# Built from parts, so the secret scanner does not read a fake label as a key.
_KEY_LABEL = b"PRIVATE " + b"KEY"
_KEY_BLOCK = b"-----BEGIN " + _KEY_LABEL + b"-----\nQUFBQQ==\n-----END " + _KEY_LABEL + b"-----\n"


def _serve_with_client_ca(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    pin: str | None,
    ca_bytes: bytes | None = None,
    extra_toml: str = "",
    extra_api: str = "",
    enforcement: str = "warn",
    uvicorn_run: Callable[..., None] | None = None,
) -> tuple[int, Path]:
    """Run ``serve`` in ``tmp_path`` with a client CA pinned to ``pin``, or to its own bytes when
    ``pin`` is None. The CA holds ``ca_bytes``, or a real self-signed certificate. uvicorn is
    stubbed by ``uvicorn_run``, or by a no-op, so nothing binds."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("MEFOR_STORE_ENCRYPTION_KEY", generate_key())
    ca = tmp_path / "client-ca.pem"
    ca.write_bytes(
        ca_bytes if ca_bytes is not None else make_self_signed("client-ca.example", [], 30)[0]
    )
    if pin is None:
        pin = ta.anchor_fingerprint(ca)
    cert_pem, key_pem = make_self_signed("localhost", ["127.0.0.1"], 30)
    cert, key = tmp_path / "api-cert.pem", tmp_path / "api-key.pem"
    cert.write_bytes(cert_pem)
    key.write_bytes(key_pem)
    (tmp_path / "messagefoundry.toml").write_text(
        f'security.enforcement = "{enforcement}"\n'
        f"{extra_toml}"
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
    monkeypatch.setattr("uvicorn.run", uvicorn_run or (lambda *a, **k: None))
    rc = main(["serve", "--config", str(SAMPLES_CONFIG), "--env", "dev"])
    return rc, tmp_path / "messagefoundry.db"


def _anchor_events(db: Path, label: str) -> list[str]:
    async def read() -> list[dict[str, Any]]:
        store = await MessageStore.open(db)
        try:
            rows = await store.list_audit(action=ta.AUDIT_ACTION, limit=200)
        finally:
            await store.close()
        return [json.loads(r["detail"]) for r in rows]

    return [str(r.get("event")) for r in asyncio.run(read()) if r.get("label") == label]


class _Grab(logging.Handler):
    def __init__(self) -> None:
        super().__init__(logging.WARNING)
        self.seen: list[str] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.seen.append(record.getMessage())


@pytest.fixture
def grab() -> Iterator[_Grab]:
    """What this module's logger handles at WARNING and above, with a positive control."""
    handler = _Grab()
    logger = logging.getLogger(cli.__name__)
    logger.addHandler(handler)
    try:
        logger.warning("probe")
        assert handler.seen == ["probe"]
        handler.seen.clear()
        yield handler
    finally:
        logger.removeHandler(handler)


def _no_lifespan(monkeypatch: pytest.MonkeyPatch) -> None:
    """Fail the test if the managed app's lifespan opens its store: the audit must not run it."""
    from messagefoundry.api import app as api_app

    def refuse(*_a: object, **_k: object) -> object:
        raise AssertionError("the audit ran the managed lifespan's store open")

    monkeypatch.setattr(api_app, "open_store", refuse)


def test_a_refused_client_ca_writes_its_trust_anchor_row(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    grab: _Grab,
) -> None:
    """Red on main: the refusal returned 2 before any store opened, so no store, and no row. The
    row is written with no lifespan run, and the refusal's reason is logged."""
    _no_lifespan(monkeypatch)
    rc, db = _serve_with_client_ca(tmp_path, monkeypatch, pin=_WRONG_PIN)
    assert rc == 2
    assert "error: the API TLS context was not built:" in capsys.readouterr().err
    assert db.is_file(), "the refusal opened no store, so it wrote no audit row"
    assert "pin_mismatch" in _anchor_events(db, "api_client")
    # The reason is safe_exc's length-bounded rendering, and it quotes the CA's path, so its tail is
    # cut where the temp path is long (an xdist worker's is). Its head names the anchor either way.
    refused = [m for m in grab.seen if m.startswith("the audited check refused")]
    head = "the audited check refused [api].tls_client_ca_file: TrustAnchorError: "
    assert refused and refused[0].startswith(head), grab.seen


def test_a_ca_refused_for_its_content_writes_its_row(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """A CA refused for what its bytes hold, here a private-key block pinned to its own bytes, is
    the CA's refusal, and the audited preflight writes its ``pem_refused`` row."""
    rc, db = _serve_with_client_ca(tmp_path, monkeypatch, pin=None, ca_bytes=_KEY_BLOCK)
    assert rc == 2
    assert "error: the API TLS context was not built:" in capsys.readouterr().err
    assert "pem_refused" in _anchor_events(db, "api_client")


def _crl_refused(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> str:
    """Plant a context build that refuses ``[api].tls_client_crl_file`` with its tag, and return
    the ``[api]`` line that configures that CRL."""
    from messagefoundry.api import tls as api_tls

    crl = tmp_path / "client.crl"
    crl.write_bytes(b"planted")

    def refuse(*_a: object, **_k: object) -> object:
        raise ta.TrustAnchorError("planted CRL refusal", setting="[api].tls_client_crl_file")

    monkeypatch.setattr(api_tls, "build_api_ssl_context", refuse)
    return f"tls_client_crl_file = {json.dumps(str(crl))}\n"


def _collector_ca_refused(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> str:
    """A TLS log forwarder whose collector CA ``_start_logging`` refused, so it left the CA's row
    to the audited preflight (BACKLOG #3470). The CA holds a private-key block, which that preflight
    refuses with a ``pem_refused`` row. The early check runs no content check on a CA its hop reads
    by path, and under ``warn`` it refuses no ACL, so its refusal is planted here, as an
    ``enforce`` start's ACL refusal would come."""
    real = ta.anchor_refusal

    def early(spec: ta.AnchorSpec, **kw: Any) -> ta.TrustAnchorError | None:
        if spec.label == "logging_forward_ca":
            return ta.TrustAnchorError("planted early refusal", setting=spec.setting)
        return real(spec, **kw)

    monkeypatch.setattr(ta, "anchor_refusal", early)
    collector_ca = tmp_path / "collector-ca.pem"
    collector_ca.write_bytes(_KEY_BLOCK)
    return (
        "[logging]\n"
        "forward_enabled = true\n"
        'forward_host = "collector.example.org"\n'
        'forward_protocol = "tls"\n'
        f"forward_tls_ca_file = {json.dumps(str(collector_ca))}\n"
        "[egress]\n"
        'allowed_syslog = ["collector.example.org"]\n'
    )


def test_a_refused_collector_ca_is_audited_beside_the_client_ca(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The start never runs the lifespan that would write the collector CA's row, so the audit
    writes it too, beside the client CA's. Red with the collector CA left out of the audit."""
    _no_lifespan(monkeypatch)
    extra = _collector_ca_refused(tmp_path, monkeypatch)
    rc, db = _serve_with_client_ca(tmp_path, monkeypatch, pin=_WRONG_PIN, extra_toml=extra)
    assert rc == 2
    assert "error: the API TLS context was not built:" in capsys.readouterr().err
    assert "pin_mismatch" in _anchor_events(db, "api_client")
    assert "pem_refused" in _anchor_events(db, "logging_forward_ca")


def test_a_refused_collector_ca_is_audited_when_the_crl_refused_the_build(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """A build refused by the CRL alone audits no client CA, but the collector CA this start
    refused still gets its row."""
    crl_line = _crl_refused(tmp_path, monkeypatch)
    _no_lifespan(monkeypatch)
    rc, db = _serve_with_client_ca(
        tmp_path,
        monkeypatch,
        pin=None,
        extra_toml=_collector_ca_refused(tmp_path, monkeypatch),
        extra_api=crl_line,
    )
    assert rc == 2
    assert "error: the API TLS context was not built:" in capsys.readouterr().err
    assert "pem_refused" in _anchor_events(db, "logging_forward_ca")
    assert _anchor_events(db, "api_client") == []


def test_a_store_refusing_one_row_does_not_hide_the_next_anchor(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, grab: _Grab
) -> None:
    """``AnchorStoreUnavailable`` is not a ``TrustAnchorError``: the check passed and the store
    refused its row. The client CA's is planted, and the collector CA is still checked and gets
    its row. Red with only ``TrustAnchorError`` caught per anchor."""
    real = ta.run_anchor_preflight

    async def preflight(specs: list[ta.AnchorSpec], store: Any, **kw: Any) -> object:
        if specs[0].label == "api_client":
            raise ta.AnchorStoreUnavailable("planted store refusal")
        return await real(specs, store, **kw)

    monkeypatch.setattr(ta, "run_anchor_preflight", preflight)
    extra = _collector_ca_refused(tmp_path, monkeypatch)
    rc, db = _serve_with_client_ca(tmp_path, monkeypatch, pin=_WRONG_PIN, extra_toml=extra)
    assert rc == 2
    assert "pem_refused" in _anchor_events(db, "logging_forward_ca")
    head = "no audit row records the refused [api].tls_client_ca_file: the audited check passed"
    assert [m for m in grab.seen if m.startswith(head)], grab.seen


def test_a_store_that_does_not_open_leaves_the_clean_refusal(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    grab: _Grab,
) -> None:
    """The audit is best-effort on a start already refused: a store that fails to open is logged,
    and the exit stays the clean 2 rather than the uncaught floor's 1."""

    async def refuse_open(*_a: object, **_k: object) -> object:
        raise OSError("planted store open failure")

    monkeypatch.setattr("messagefoundry.store.open_store", refuse_open)
    rc, _db = _serve_with_client_ca(tmp_path, monkeypatch, pin=_WRONG_PIN)
    assert rc == 2
    assert "error: the API TLS context was not built:" in capsys.readouterr().err
    assert [m for m in grab.seen if "no audit row records the refused trust anchor" in m], grab.seen


def test_a_context_that_builds_opens_no_store_for_the_audit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The control: with the CA's own pin the context builds, the start goes on to uvicorn
    (stubbed), and the audit does not run, so no store is opened."""
    calls: list[bool] = []
    monkeypatch.setattr(
        cli, "_audit_anchors_refused_before_the_store", lambda *a, **k: calls.append(True)
    )
    rc, db = _serve_with_client_ca(tmp_path, monkeypatch, pin=None)
    assert rc == 0
    assert calls == []
    assert not db.exists()


def test_a_refused_crl_opens_no_store(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The context also refuses ``[api].tls_client_crl_file``, which the audited preflight leaves
    out, so no row could come of it. The build tags that refusal with the CRL's setting, and the
    audit reads the tag rather than checking the files again."""
    crl_line = _crl_refused(tmp_path, monkeypatch)
    rc, db = _serve_with_client_ca(tmp_path, monkeypatch, pin=None, extra_api=crl_line)
    assert rc == 2
    assert "error: the API TLS context was not built:" in capsys.readouterr().err
    assert not db.exists()


def test_the_build_tags_a_crl_refusal_with_its_setting(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The tag the audit reads: ``build_api_ssl_context`` names the CRL on its refusal. Red before
    the tag, when the refusal carried no setting."""
    from messagefoundry.api.tls import build_api_ssl_context
    from messagefoundry.config.settings import ApiSettings

    ca_pem = make_self_signed("client-ca.example", [], 30)[0]
    cert_pem, key_pem = make_self_signed("localhost", ["127.0.0.1"], 30)
    ca, cert, key = tmp_path / "ca.pem", tmp_path / "cert.pem", tmp_path / "key.pem"
    ca.write_bytes(ca_pem)
    cert.write_bytes(cert_pem)
    key.write_bytes(key_pem)
    crl = tmp_path / "client.crl"
    crl.write_bytes(b"planted")
    # The CA passes its checks; the CRL's ACL check refuses it under enforce.
    monkeypatch.setattr(ta, "anchor_path_verdict", lambda _p: PathVerdict(True))
    monkeypatch.setattr(ta, "dacl_is_owner_only", lambda p: str(p) != str(crl))
    api = ApiSettings(
        tls_cert_file=str(cert),
        tls_key_file=str(key),
        tls_client_ca_file=str(ca),
        tls_client_crl_file=str(crl),
    )
    with pytest.raises(ta.TrustAnchorError) as err:
        build_api_ssl_context(api, enforcing=True)
    assert err.value.setting == "[api].tls_client_crl_file"


def test_the_no_lifespan_guard_fires_when_the_lifespan_runs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The positive control for ``_no_lifespan``: a start that reaches uvicorn, stubbed here to
    run the managed app's lifespan, trips the guard. So a test that passes with the guard in
    place shows the audit ran no lifespan, not that the guard could never fire."""
    _no_lifespan(monkeypatch)
    tripped: list[BaseException] = []

    def run_lifespan(app: Any, **_k: object) -> None:
        async def go() -> None:
            async with app.router.lifespan_context(app):
                pass

        try:
            asyncio.run(go())
        except BaseException as exc:
            tripped.append(exc)
            raise

    rc, _db = _serve_with_client_ca(tmp_path, monkeypatch, pin=None, uvicorn_run=run_lifespan)
    assert rc != 0
    assert any("the audit ran the managed lifespan's store open" in str(e) for e in tripped), (
        tripped
    )


def _store_posture_spy(monkeypatch: pytest.MonkeyPatch) -> list[object]:
    """Record the ``posture`` each ``messagefoundry.store.open_store`` call passes."""
    import messagefoundry.store as store_pkg

    real = store_pkg.open_store
    seen: list[object] = []

    async def spy(*a: Any, **k: Any) -> Any:
        seen.append(k.get("posture"))
        return await real(*a, **k)

    monkeypatch.setattr(store_pkg, "open_store", spy)
    return seen


@pytest.mark.parametrize("enforcement", ["warn", "enforce"])
def test_the_audit_opens_the_store_at_the_lifespans_posture(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, enforcement: str
) -> None:
    """Manager decision Q1: the audit's store open passes the posture the lifespan's own open
    passes, ``hop_posture_from_ai`` at the instance's enforcement, so it is never stricter than
    serve (at warn) and never looser (at enforce, where the open refuses what serve's refuses).
    The refused CA gets its row under either. Called directly, since an ``enforce`` serve start
    over the sample config is refused by earlier gates. Red at warn before, when the audit passed
    ``_command_hop_posture``'s None there."""
    from messagefoundry.config.settings import (
        ApiSettings,
        SecurityEnforcement,
        SecuritySettings,
        ServiceSettings,
        StoreSettings,
        hop_posture_from_ai,
    )

    monkeypatch.setattr(ta, "anchor_path_verdict", lambda _p: PathVerdict(True))
    monkeypatch.setattr(ta, "dacl_is_owner_only", lambda _p: True)
    ca = tmp_path / "client-ca.pem"
    ca.write_bytes(make_self_signed("client-ca.example", [], 30)[0])
    db = tmp_path / "messagefoundry.db"
    settings = ServiceSettings(
        store=StoreSettings(path=str(db), encryption_key=generate_key()),
        api=ApiSettings(
            tls_cert_file=str(tmp_path / "api-cert.pem"),
            tls_client_ca_file=str(ca),
            tls_client_ca_pin=_WRONG_PIN,
        ),
        security=SecuritySettings(enforcement=SecurityEnforcement(enforcement)),
    )
    seen = _store_posture_spy(monkeypatch)
    cli._audit_anchors_refused_before_the_store(
        settings,
        enforcing=enforcement == "enforce",
        forward_ca_refused=False,
        api_ca_refusal=ta.TrustAnchorError("planted build refusal"),
    )
    expected = hop_posture_from_ai(settings.ai, enforcement=SecurityEnforcement(enforcement))
    assert seen == [expected], seen
    assert expected.enforcing is (enforcement == "enforce")
    assert "pin_mismatch" in _anchor_events(db, "api_client")


def test_serve_at_warn_passes_the_lifespans_posture(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The same through ``serve`` itself, at warn, where the two postures differ."""
    seen = _store_posture_spy(monkeypatch)
    rc, db = _serve_with_client_ca(tmp_path, monkeypatch, pin=_WRONG_PIN)
    assert rc == 2
    assert len(seen) == 1 and seen[0] is not None, seen
    assert seen[0].enforcing is False  # type: ignore[attr-defined]
    assert "pin_mismatch" in _anchor_events(db, "api_client")


def _plant_exit(monkeypatch: pytest.MonkeyPatch, exit_kind: str, tmp_path: Path) -> str:
    """Plant one way out of ``serve`` between ``_start_logging`` and uvicorn, and return any
    extra ``[logging]`` lines it needs."""
    from messagefoundry.api import tls as api_tls
    from messagefoundry.keywrap import KeyWrapRefused

    def build(exc: BaseException) -> None:
        def refuse(*_a: object, **_k: object) -> object:
            raise exc

        monkeypatch.setattr(api_tls, "build_api_ssl_context", refuse)

    if exit_kind == "logging-file":
        return f"file = {json.dumps(str(tmp_path))}\n"  # a directory: configure_logging refuses it
    if exit_kind == "key-wrap":
        build(KeyWrapRefused("planted key-wrap refusal"))
    elif exit_kind == "tls-oserror":
        build(OSError("planted TLS material failure"))
    elif exit_kind == "diagnostics":
        monkeypatch.setattr(cli, "_emit_anchor_diagnostics", lambda **_k: (2, None))
    elif exit_kind == "raise":

        def boom(**_k: object) -> object:
            raise RuntimeError("planted defect")

        monkeypatch.setattr(cli, "_emit_anchor_diagnostics", boom)
    else:
        raise AssertionError(exit_kind)
    return ""


@pytest.mark.parametrize(
    "exit_kind", ["logging-file", "key-wrap", "tls-oserror", "diagnostics", "raise"]
)
def test_every_way_out_before_the_lifespan_audits_the_collector_ca(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, exit_kind: str
) -> None:
    """Manager decision Q2: one exit hook over the span from ``_start_logging`` to uvicorn, so a
    refused collector CA gets its row whichever way the start leaves before the lifespan runs:
    ``_start_logging``'s own refusal, a key-wrap refusal and an ``OSError`` from the API TLS
    build, a gate's ``return 2``, and a raise. The client CA, which nothing refused, is not
    audited. Red before on every case: none of these exits opened a store."""
    _no_lifespan(monkeypatch)
    extra = _collector_ca_refused(tmp_path, monkeypatch)
    extra = extra.replace(
        "[egress]\n", _plant_exit(monkeypatch, exit_kind, tmp_path) + "[egress]\n"
    )
    rc, db = _serve_with_client_ca(tmp_path, monkeypatch, pin=None, extra_toml=extra)
    # The CLI's floor turns the raise into its own exit code; every refusal here is a clean 2.
    assert rc == (1 if exit_kind == "raise" else 2), rc
    assert db.is_file(), "the exit opened no store, so it wrote no audit row"
    assert "pem_refused" in _anchor_events(db, "logging_forward_ca")
    assert _anchor_events(db, "api_client") == []


def test_an_interrupt_runs_no_audit(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """An interrupt is not a refusal: it propagates at once, and no store opens for the audit."""
    extra = _collector_ca_refused(tmp_path, monkeypatch)

    def interrupt(**_k: object) -> object:
        raise KeyboardInterrupt

    monkeypatch.setattr(cli, "_emit_anchor_diagnostics", interrupt)
    with pytest.raises(KeyboardInterrupt):
        _serve_with_client_ca(tmp_path, monkeypatch, pin=None, extra_toml=extra)
    assert not (tmp_path / "messagefoundry.db").exists()


def test_a_memory_fault_on_one_anchor_does_not_stop_the_next(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, grab: _Grab
) -> None:
    """Finding 5: the collector CA's check runs out of memory (planted), and the client CA is
    still checked and gets its row. The ``MemoryError`` is raised once both are checked. Red
    before, when the first anchor's ``MemoryError`` ended the loop."""
    real = ta.run_anchor_preflight

    async def preflight(specs: list[ta.AnchorSpec], store: Any, **kw: Any) -> object:
        if specs[0].label == "logging_forward_ca":
            raise MemoryError("planted")
        return await real(specs, store, **kw)

    monkeypatch.setattr(ta, "run_anchor_preflight", preflight)
    extra = _collector_ca_refused(tmp_path, monkeypatch)
    rc, db = _serve_with_client_ca(tmp_path, monkeypatch, pin=_WRONG_PIN, extra_toml=extra)
    assert rc not in (0, 2), "the MemoryError was swallowed into the clean refusal"
    assert "pin_mismatch" in _anchor_events(db, "api_client")
    head = "no audit row records the refused [logging].forward_tls_ca_file: out of memory"
    assert head in grab.seen, grab.seen


def test_an_unreadable_ca_is_not_logged_as_having_a_row(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, grab: _Grab
) -> None:
    """Finding 3: a CA file that cannot be read is refused before any row is written, so the
    WARNING must not say a row records it. The file is removed after the build refused it, so
    the audit's read fails."""
    from messagefoundry.api import tls as api_tls

    real_build = api_tls.build_api_ssl_context

    def build_then_remove(api: Any, **k: Any) -> Any:
        try:
            return real_build(api, **k)
        finally:
            Path(api.tls_client_ca_file).unlink()

    monkeypatch.setattr(api_tls, "build_api_ssl_context", build_then_remove)
    rc, db = _serve_with_client_ca(tmp_path, monkeypatch, pin=_WRONG_PIN)
    assert rc == 2
    assert _anchor_events(db, "api_client") == []
    refused = [m for m in grab.seen if m.startswith("the audited check refused [api]")]
    assert len(refused) == 1, grab.seen
    assert "row is written unless" in refused[0], refused


def test_a_low_disk_refusal_writes_nothing_to_the_store(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, grab: _Grab
) -> None:
    """The low-disk floor refuses a start so that nothing writes to a volume about to fill, so its
    exit opens no store for the audit, and says the refused collector CA has no row. Red before
    the floor marked its exit, when the audit created the store there."""
    from messagefoundry.pipeline import retention

    def low(_path: str, floor_mb: int) -> retention.DiskFloorReading:
        return retention.DiskFloorReading(probed=str(tmp_path), free_bytes=1, floor_bytes=floor_mb)

    monkeypatch.setattr(retention, "read_disk_floor", low)
    extra = _collector_ca_refused(tmp_path, monkeypatch) + "[retention]\nmin_free_disk_mb = 100\n"
    rc, db = _serve_with_client_ca(tmp_path, monkeypatch, pin=None, extra_toml=extra)
    assert rc == 2
    assert not db.exists()
    head = "no audit row records the refused trust anchors: the start was refused because the store"
    assert [m for m in grab.seen if m.startswith(head)], grab.seen


def test_the_audit_writes_a_replaced_pairs_row(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A generated pair this start replaced gets its ``api.tls_generated_pair_replaced`` row once
    the audit opens the store, as the lifespan would have written it (ADR 0172 decision 6). Red
    before, when the audit wrote only anchor rows."""
    from messagefoundry.api.tls import GENERATED_PAIR_REPLACED, GeneratedPairReplaced
    from messagefoundry.config.settings import LoggingSettings, ServiceSettings, StoreSettings

    monkeypatch.setattr(ta, "anchor_path_verdict", lambda _p: PathVerdict(True))
    monkeypatch.setattr(ta, "dacl_is_owner_only", lambda _p: True)
    collector_ca = tmp_path / "collector-ca.pem"
    collector_ca.write_bytes(_KEY_BLOCK)
    db = tmp_path / "messagefoundry.db"
    settings = ServiceSettings(
        store=StoreSettings(path=str(db), encryption_key=generate_key()),
        logging=LoggingSettings(
            forward_enabled=True,
            forward_host="collector.example.org",
            forward_protocol="tls",
            forward_tls_ca_file=str(collector_ca),
        ),
    )
    event = GeneratedPairReplaced(
        reason="renewal",
        cert_file=str(tmp_path / "api-cert.pem"),
        old_sha256="00" * 32,
        old_not_after="2026-01-01",
        new_sha256="11" * 32,
        new_not_after="2027-01-01",
    )
    cli._audit_anchors_refused_before_the_store(
        settings, enforcing=False, forward_ca_refused=True, api_ca_refusal=None, replaced=[event]
    )
    assert "pem_refused" in _anchor_events(db, "logging_forward_ca")

    async def read() -> list[dict[str, Any]]:
        store = await MessageStore.open(db)
        try:
            return await store.list_audit(action=GENERATED_PAIR_REPLACED, limit=10)
        finally:
            await store.close()

    assert len(asyncio.run(read())) == 1


def test_serve_without_its_hook_fails_loudly() -> None:
    """The body asks for the hook's record and raises when there is none, so dropping the
    decorator cannot silently turn the audit off."""
    with pytest.raises(RuntimeError, match="pre-lifespan anchor audit hook"):
        cli._pre_lifespan_anchor_audit()


def test_a_start_that_reaches_uvicorn_leaves_the_rows_to_the_lifespan(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The negative control for ``disarm``: a refused collector CA on a start that reaches uvicorn
    (stubbed, so no lifespan runs) is the lifespan's to audit, so the exit hook opens no store.
    Red with the ``disarm`` call removed, when the hook audited after uvicorn returned."""
    extra = _collector_ca_refused(tmp_path, monkeypatch)
    rc, db = _serve_with_client_ca(tmp_path, monkeypatch, pin=None, extra_toml=extra)
    assert rc == 0
    assert not db.exists()
