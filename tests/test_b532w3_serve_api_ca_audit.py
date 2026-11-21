# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #5391 added item 2: a trust anchor ``serve`` refuses before its lifespan is reported.

``serve`` builds the API TLS context, and ``_start_logging`` checks the collector's CA, before
uvicorn runs the lifespan whose audited preflight writes an anchor's ``auth.trust_anchor`` row. A
start refused before that writes no row: every writable store open writes more than the row, and
a refused start must write nothing (Manager decision on round-32e2013d's finding 1). ``serve``'s
one exit hook, over every way out from ``_start_logging`` to uvicorn, logs a WARNING for each such
anchor instead, and opens no store. Each test drives ``serve`` itself, with the real context build
unless it says otherwise. Every PEM here is synthetic.
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
from messagefoundry.store import open_store as _real_open_store
from messagefoundry.store.crypto import generate_key

SAMPLES_CONFIG = Path(__file__).resolve().parents[1] / "samples" / "config"
_WRONG_PIN = "00" * 32
# A synthetic private-key block: the anchors' content check refuses a file holding one.
# Built from parts, so the secret scanner does not read a fake label as a key.
_KEY_LABEL = b"PRIVATE " + b"KEY"
_KEY_BLOCK = b"-----BEGIN " + _KEY_LABEL + b"-----\nQUFBQQ==\n-----END " + _KEY_LABEL + b"-----\n"
_CLIENT_CA_LINE = "no audit row records the refused [api].tls_client_ca_file (BACKLOG"
_COLLECTOR_CA_LINE = "no audit row records the refused [logging].forward_tls_ca_file (BACKLOG"


def _provision(db: Path, key: str | None) -> None:
    """Create the store at ``db`` with this build's schema, as a prior start would have: keyed with
    ``key``, or keyless where it is None. The real ``open_store``, so a planted one cannot stop
    it."""
    from messagefoundry.config.settings import StoreSettings

    async def make() -> None:
        store = await _real_open_store(
            StoreSettings(path=str(db), encryption_key=key),
            create=True,
            keyless_chain_refusal=None,
        )
        await store.close()

    asyncio.run(make())


def _store_files(db: Path) -> dict[str, bytes]:
    """The store's file and its WAL siblings, byte for byte, so a later write shows."""
    return {p.name: p.read_bytes() for p in db.parent.glob(db.name + "*")}


def _serve_with_client_ca(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    pin: str | None,
    extra_toml: str = "",
    extra_api: str = "",
    uvicorn_run: Callable[..., None] | None = None,
    provision: bool = True,
    store_key: str | None = None,
) -> tuple[int, Path]:
    """Run ``serve`` in ``tmp_path`` with a real client CA pinned to ``pin``, or to its own bytes
    when ``pin`` is None. uvicorn is stubbed by ``uvicorn_run``, or by a no-op, so nothing binds.
    With ``provision`` a current, keyed store exists first, so a test can show it is left alone."""
    monkeypatch.chdir(tmp_path)
    store_key = store_key or generate_key()
    monkeypatch.setenv("MEFOR_STORE_ENCRYPTION_KEY", store_key)
    if provision:
        _provision(tmp_path / "messagefoundry.db", store_key)
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


class _Grab(logging.Handler):
    def __init__(self) -> None:
        super().__init__(logging.WARNING)
        self.seen: list[str] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.seen.append(record.getMessage())

    def starting(self, head: str) -> list[str]:
        return [m for m in self.seen if m.startswith(head)]


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


@pytest.fixture
def no_store_open(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Record every store open the start makes after the test's own provisioning: the store
    package's, the managed lifespan's and SQLite's own. The report must make none."""
    import messagefoundry.store as store_pkg
    from messagefoundry.api import app as api_app
    from messagefoundry.store.store import MessageStore

    opened: list[str] = []

    def spy(name: str) -> Callable[..., Any]:
        def refuse(*_a: object, **_k: object) -> object:
            opened.append(name)
            raise AssertionError(f"the refused start opened the store through {name}")

        return refuse

    monkeypatch.setattr(store_pkg, "open_store", spy("messagefoundry.store.open_store"))
    monkeypatch.setattr(api_app, "open_store", spy("the managed lifespan's open_store"))
    monkeypatch.setattr(MessageStore, "open", spy("MessageStore.open"))
    return opened


def test_the_store_guard_fires_on_a_store_open(no_store_open: list[str]) -> None:
    """The positive control for ``no_store_open``: a store open is caught and recorded."""
    import messagefoundry.store as store_pkg

    opener: Callable[..., Any] = store_pkg.open_store  # the spy, which raises before any await
    with pytest.raises(AssertionError, match="opened the store"):
        opener(object())
    assert no_store_open == ["messagefoundry.store.open_store"]


def test_a_refused_client_ca_is_reported_and_the_store_is_untouched(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    grab: _Grab,
) -> None:
    """The client CA's refusal is printed, the WARNING says no row records it, and the existing
    store is byte for byte what it was. Red before, when the audit opened the store writable
    and wrote the row (and, at least, the cipher's invocation reserve)."""
    db = tmp_path / "messagefoundry.db"
    monkeypatch.chdir(tmp_path)
    key = generate_key()
    _provision(db, key)
    before = _store_files(db)
    rc, _db = _serve_with_client_ca(
        tmp_path, monkeypatch, pin=_WRONG_PIN, provision=False, store_key=key
    )
    assert rc == 2
    assert "error: the API TLS context was not built:" in capsys.readouterr().err
    assert _store_files(db) == before
    assert len(grab.starting(_CLIENT_CA_LINE)) == 1, grab.seen


def test_a_keyless_store_is_not_sealed_by_a_refused_keyed_start(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, grab: _Grab
) -> None:
    """The legacy-plaintext case: a store written keyless, met by a start that now has a key. A
    keyed writable open would bind its salt and seal what it holds. The refused start leaves it
    byte for byte. Red before, when the audit's open did those writes."""
    db = tmp_path / "messagefoundry.db"
    monkeypatch.chdir(tmp_path)
    _provision(db, None)
    before = _store_files(db)
    rc, _db = _serve_with_client_ca(tmp_path, monkeypatch, pin=_WRONG_PIN, provision=False)
    assert rc == 2
    assert _store_files(db) == before
    assert grab.starting(_CLIENT_CA_LINE), grab.seen


def test_an_absent_store_stays_absent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, grab: _Grab
) -> None:
    """A refused start never creates a store. Red at the first r3 head, when the audit opened with
    ``create=True``."""
    rc, db = _serve_with_client_ca(tmp_path, monkeypatch, pin=_WRONG_PIN, provision=False)
    assert rc == 2
    assert not db.exists()
    assert grab.starting(_CLIENT_CA_LINE), grab.seen


def test_the_report_opens_no_store(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, grab: _Grab, no_store_open: list[str]
) -> None:
    """Whatever the store holds (a ``key_provider = "host"`` custody handoff, legacy plaintext,
    an old schema), the report cannot change it: it opens no store at all. This covers the
    custody-handoff case, whose DPAPI handoff a test cannot stage portably. Red before, when the
    audit opened the store."""
    rc, _db = _serve_with_client_ca(tmp_path, monkeypatch, pin=_WRONG_PIN, provision=False)
    assert rc == 2
    assert no_store_open == []
    assert grab.starting(_CLIENT_CA_LINE), grab.seen


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


def test_a_refused_crl_is_reported_by_its_own_setting(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, grab: _Grab
) -> None:
    """The build tags a CRL refusal with the CRL's setting, and the report names that setting,
    not the client CA's."""
    crl_line = _crl_refused(tmp_path, monkeypatch)
    rc, _db = _serve_with_client_ca(tmp_path, monkeypatch, pin=None, extra_api=crl_line)
    assert rc == 2
    crl = grab.starting("no audit row records the refused [api].tls_client_crl_file (BACKLOG")
    assert len(crl) == 1, grab.seen
    assert grab.starting(_CLIENT_CA_LINE) == []


def test_the_build_tags_a_crl_refusal_with_its_setting(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The tag the report reads: ``build_api_ssl_context`` names the CRL on its refusal. Red before
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


def _collector_ca_refused(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> str:
    """A TLS log forwarder whose collector CA ``_start_logging`` refused and deferred to the
    lifespan (BACKLOG #3470). The early check runs no content check on a CA its hop reads by path,
    and under ``warn`` it refuses no ACL, so its refusal is planted here, as an ``enforce`` start's
    ACL refusal would come."""
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
def test_every_way_out_before_the_lifespan_reports_the_collector_ca(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, grab: _Grab, exit_kind: str
) -> None:
    """Manager decision Q2: one exit hook over the span from ``_start_logging`` to uvicorn, so a
    refused collector CA is reported whichever way the start leaves before the lifespan runs:
    ``_start_logging``'s own refusal, a key-wrap refusal and an ``OSError`` from the API TLS
    build, a gate's ``return 2``, and a raise. The client CA, which nothing refused, is not named,
    and the store is untouched. Red on main, where none of these exits said anything."""
    extra = _collector_ca_refused(tmp_path, monkeypatch)
    extra = extra.replace(
        "[egress]\n", _plant_exit(monkeypatch, exit_kind, tmp_path) + "[egress]\n"
    )
    db = tmp_path / "messagefoundry.db"
    monkeypatch.chdir(tmp_path)
    key = generate_key()
    _provision(db, key)
    before = _store_files(db)
    rc, _db = _serve_with_client_ca(
        tmp_path, monkeypatch, pin=None, extra_toml=extra, provision=False, store_key=key
    )
    # The CLI's floor turns the raise into its own exit code; every refusal here is a clean 2.
    assert rc == (1 if exit_kind == "raise" else 2), rc
    assert len(grab.starting(_COLLECTOR_CA_LINE)) == 1, grab.seen
    assert grab.starting(_CLIENT_CA_LINE) == []
    assert _store_files(db) == before


def test_an_interrupt_reports_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, grab: _Grab
) -> None:
    """An interrupt is not a refusal: it propagates at once, and nothing is reported."""
    extra = _collector_ca_refused(tmp_path, monkeypatch)

    def interrupt(**_k: object) -> object:
        raise KeyboardInterrupt

    monkeypatch.setattr(cli, "_emit_anchor_diagnostics", interrupt)
    with pytest.raises(KeyboardInterrupt):
        _serve_with_client_ca(tmp_path, monkeypatch, pin=None, extra_toml=extra)
    assert grab.starting(_COLLECTOR_CA_LINE) == []


def test_a_context_that_builds_does_not_call_the_report(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The control: a refused collector CA, and the context builds, so the start goes on to uvicorn
    (stubbed) and the CA is the lifespan's to audit. The report is not called. Red with the
    ``disarm`` call removed."""
    calls: list[bool] = []
    monkeypatch.setattr(
        cli, "_report_anchors_refused_before_the_lifespan", lambda **_k: calls.append(True)
    )
    extra = _collector_ca_refused(tmp_path, monkeypatch)
    rc, _db = _serve_with_client_ca(tmp_path, monkeypatch, pin=None, extra_toml=extra)
    assert rc == 0
    assert calls == []


def test_the_lifespan_guard_fires_when_the_lifespan_runs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, no_store_open: list[str]
) -> None:
    """The positive control that a start reaching uvicorn, stubbed to run the managed app's
    lifespan, opens the store there: so ``no_store_open`` staying empty elsewhere means the
    report ran no lifespan."""

    def run_lifespan(app: Any, **_k: object) -> None:
        async def go() -> None:
            async with app.router.lifespan_context(app):
                pass

        asyncio.run(go())

    rc, _db = _serve_with_client_ca(
        tmp_path, monkeypatch, pin=None, uvicorn_run=run_lifespan, provision=False
    )
    assert rc != 0
    assert "the managed lifespan's open_store" in no_store_open, no_store_open


def test_serve_without_its_hook_fails_loudly() -> None:
    """The body asks for the hook's record and raises when there is none, so dropping the
    decorator cannot silently turn the report off."""
    with pytest.raises(RuntimeError, match="pre-lifespan anchor audit hook"):
        cli._pre_lifespan_anchor_audit()


def test_the_report_survives_an_error_log_level(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, grab: _Grab
) -> None:
    """``[logging].level = "ERROR"`` must not drop the report: it goes through
    ``_write_start_audit``, which skips the level, as the start's other AUDIT lines do. Red
    before, when the report was a plain ``log.warning``."""
    extra = _collector_ca_refused(tmp_path, monkeypatch).replace(
        "[logging]\n", '[logging]\nlevel = "ERROR"\n'
    )
    monkeypatch.setattr(cli, "_emit_anchor_diagnostics", lambda **_k: (2, None))
    rc, _db = _serve_with_client_ca(tmp_path, monkeypatch, pin=None, extra_toml=extra)
    assert rc == 2
    assert len(grab.starting(_COLLECTOR_CA_LINE)) == 1, grab.seen


def test_the_report_carries_the_collector_cas_reason(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, grab: _Grab
) -> None:
    """When ``configure_logging`` refuses after the collector CA was deferred, nothing else
    prints the CA's reason, so the report carries it. Red before, when the report named the
    setting only."""
    extra = _collector_ca_refused(tmp_path, monkeypatch).replace(
        "[egress]\n", f"file = {json.dumps(str(tmp_path))}\n[egress]\n"
    )
    rc, _db = _serve_with_client_ca(tmp_path, monkeypatch, pin=None, extra_toml=extra)
    assert rc == 2
    lines = grab.starting(_COLLECTOR_CA_LINE)
    assert len(lines) == 1 and "planted early refusal" in lines[0], grab.seen


def test_a_client_ca_the_build_cannot_read_is_reported(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, grab: _Grab
) -> None:
    """``verified_anchor_cadata`` passes the client CA file's own read failure through as a bare
    ``OSError``, which the build's catch also turns into exit 2. It is the client CA's refusal, so
    it is reported too. Planted at the read, naming the CA's file. Red before, when only a
    ``TrustAnchorError`` was reported."""
    real = ta.evaluate_anchor

    def unreadable(spec: ta.AnchorSpec) -> ta.AnchorVerdict:
        if spec.label == "api_client":
            raise PermissionError(13, "planted unreadable CA", spec.path)
        return real(spec)

    monkeypatch.setattr(ta, "evaluate_anchor", unreadable)
    rc, _db = _serve_with_client_ca(tmp_path, monkeypatch, pin=None)
    assert rc == 2
    lines = grab.starting(_CLIENT_CA_LINE)
    assert len(lines) == 1 and "PermissionError" in lines[0], grab.seen


def test_an_unrelated_oserror_is_not_reported_as_the_client_ca(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, grab: _Grab
) -> None:
    """The control: an ``OSError`` from the build that names another file, here the API key, is
    not the client CA's refusal, and is not reported as one."""
    from messagefoundry.api import tls as api_tls

    def refuse(*_a: object, **_k: object) -> object:
        raise FileNotFoundError(2, "planted", str(tmp_path / "api-key.pem"))

    monkeypatch.setattr(api_tls, "build_api_ssl_context", refuse)
    rc, _db = _serve_with_client_ca(tmp_path, monkeypatch, pin=None)
    assert rc == 2
    assert grab.starting(_CLIENT_CA_LINE) == [], grab.seen
