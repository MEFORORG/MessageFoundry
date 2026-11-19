# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Follow-ups to the verify detail scrub (BACKLOG #5395) and the shared port probe (#5389).

Every secret here is synthetic, and carries a hyphen and an underscore so the unrelated long-base64
sweep cannot be what hides it."""

from __future__ import annotations

import urllib.request
from pathlib import Path
from typing import Any

import pytest

from harness.acceptance import probes, runner
from harness.acceptance.matrix import Status as HarnessStatus
from messagefoundry.config.models import ConnectorType
from messagefoundry.config.settings import ServiceSettings
from messagefoundry.config.wiring import ConnectionSpec, InboundConnection, Registry
from messagefoundry.verify import cipher_policy, federation, smoke
from messagefoundry.verify.cipher_policy import ProbeFailed, ProbeUnavailable
from messagefoundry.verify.model import CheckResult, Status

_PLANTED = "pw-V3rify_Fol-52"
_LEAKY = f"connection to postgresql://svc:{_PLANTED}@db.invalid:5432/mefor failed"


# ---- smoke: inbound selection names stay readable ---------------------------------------------


def _registry(*names: str) -> Registry:
    reg = Registry()
    for name in names:
        reg.add_inbound(
            InboundConnection(
                name,
                ConnectionSpec(ConnectorType.MLLP, {"host": "127.0.0.1", "port": 0}),
                router="r",
            )
        )
    reg.add_router("r", lambda m: [])
    return reg


def test_an_ambiguous_choice_prints_every_name(tmp_path: Path) -> None:
    # On 4c7081a56c the names went through the PHI pass, which read "ADT, LAB" as a name.
    reg = _registry("ADT", "LAB", "ORU")
    r = smoke.smoke_self(str(tmp_path), graph=lambda: reg)
    assert r.status is Status.SKIP, r.detail
    assert "choose one: ADT, LAB, ORU; pass --inbound NAME to pick one" in r.detail, r.detail
    assert "[redacted]" not in r.detail


def test_an_unknown_name_prints_every_configured_name_and_scrubs_the_typed_one(
    tmp_path: Path,
) -> None:
    reg = _registry("ADT", "LAB", "ORU")
    r = smoke.smoke_self(str(tmp_path), inbound="IB_TYPO", graph=lambda: reg)
    assert r.status is Status.FAIL, r.detail
    assert "'IB_TYPO'" in r.detail
    assert "the config has: ADT, LAB, ORU" in r.detail, r.detail
    # The typed value is free text, so it is still scrubbed.
    leaky = smoke.smoke_self(str(tmp_path), inbound=f"x password={_PLANTED}", graph=lambda: reg)
    assert _PLANTED not in leaky.detail, leaky.detail
    assert "the config has: ADT, LAB, ORU" in leaky.detail, leaky.detail


# ---- cipher_policy: exception text is scrubbed ------------------------------------------------


@pytest.mark.parametrize(
    ("raised", "status"),
    [(ProbeUnavailable(_LEAKY), Status.MANUAL), (ProbeFailed(_LEAKY), Status.ERROR)],
)
def test_a_probe_exception_is_scrubbed(raised: Exception, status: Status) -> None:
    def probe() -> None:
        raise raised

    taken = cipher_policy._taken("what", probe, "; hint")
    assert isinstance(taken, cipher_policy._Reading)
    assert taken.status is status
    assert taken.text.startswith("what not read"), taken.text
    assert _PLANTED not in taken.text, taken.text


def test_an_unstatable_system_file_is_scrubbed(monkeypatch: pytest.MonkeyPatch) -> None:
    class _Unstatable:
        def lstat(self) -> None:
            raise PermissionError(13, f"denied, password={_PLANTED}")

        def __str__(self) -> str:
            return "/etc/ssl/openssl.cnf"

    monkeypatch.delenv("OPENSSL_CONF", raising=False)
    monkeypatch.setattr(cipher_policy, "_SYSTEM_CNF", _Unstatable())
    monkeypatch.setattr(cipher_policy, "_openssl_default_file", lambda: _raise_unavailable())
    readings = cipher_policy._linux_policy_readings()
    texts = " ".join(r.text for r in readings)
    assert "OpenSSL file not read: /etc/ssl/openssl.cnf could not be read" in texts, texts
    assert _PLANTED not in texts, texts


def _raise_unavailable() -> Path:
    raise ProbeUnavailable("openssl not found")


@pytest.mark.parametrize("missing", [Status.FAIL, Status.MANUAL])
def test_a_missing_file_path_is_scrubbed(tmp_path: Path, missing: Status) -> None:
    # OPENSSL_CONF names the path, so the FileNotFoundError quotes it.
    path = tmp_path / f"password={_PLANTED}" / "openssl.cnf"
    reading = cipher_policy._policy_reading(path, missing=missing)
    assert reading.status is missing
    assert "no file at " in reading.text, reading.text
    assert _PLANTED not in reading.text, reading.text


# ---- federation: the _tls_row catch-all names the type ----------------------------------------


def _settings(**over: Any) -> ServiceSettings:
    auth: dict[str, Any] = {
        "ad_enabled": True,
        "ad_server": "ldaps://x",
        "ad_user_search_base": "DC=x",
        "ad_bind_dn": "CN=svc,DC=x",
        "ad_bind_password": "x",
        "ad_domain": "corp.example",
        "oidc_enabled": True,
        "oidc_issuer": "https://idp.example",
        "oidc_client_id": "mefor-console",
        "oidc_client_secret": "shhh",
        "oidc_authorization_endpoint": "https://idp.example/authorize",
        "oidc_token_endpoint": "https://idp.example/token",
        "oidc_jwks_uri": "https://idp.example/jwks",
        "oidc_allowed_endpoints": ["idp.example"],
    }
    auth.update(over)
    return ServiceSettings.model_validate(
        {"auth": auth, "api": {"public_origin": "https://ops.example"}}
    )


def test_the_anchor_reread_catch_all_names_the_type(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    from messagefoundry.auth import trust_anchors

    def boom(*args: object) -> object:
        raise RuntimeError(_LEAKY)

    opener = urllib.request.OpenerDirector()
    monkeypatch.setattr(federation, "_idp_opener", lambda settings: opener)
    monkeypatch.setattr(trust_anchors, "oidc_anchor_spec", boom)
    row, got = federation._tls_row(_settings(oidc_tls_ca_cert_file=str(tmp_path / "ca.pem")))
    assert got is opener
    assert row.status is Status.ERROR
    assert "re-reading the anchor for this report failed: RuntimeError: " in row.detail, row.detail
    assert _PLANTED not in row.detail, row.detail


# ---- harness: the raw arms are scrubbed -------------------------------------------------------


def test_a3_driver_list_failure_is_scrubbed(monkeypatch: pytest.MonkeyPatch) -> None:
    import importlib
    import types

    fake = types.SimpleNamespace(drivers=lambda: (_ for _ in ()).throw(RuntimeError(_LEAKY)))
    monkeypatch.setattr(probes, "_can_import", lambda module: True)
    real = importlib.import_module
    monkeypatch.setattr(
        importlib, "import_module", lambda name: fake if name == "pyodbc" else real(name)
    )
    r = probes.probe_sqlserver_odbc_driver()
    assert r.status is HarnessStatus.ERROR
    assert r.detail.startswith("pyodbc.drivers() failed: "), r.detail
    assert _PLANTED not in r.detail, r.detail


def test_a6_write_failure_is_scrubbed(monkeypatch: pytest.MonkeyPatch) -> None:
    def refuse(**kwargs: object) -> object:
        raise PermissionError(13, f"denied, password={_PLANTED}")

    import tempfile

    monkeypatch.setattr(tempfile, "NamedTemporaryFile", refuse)
    r = probes.probe_writable_dirs()
    assert r.status is HarnessStatus.FAIL
    assert r.detail.startswith("cannot write working dir "), r.detail
    assert _PLANTED not in r.detail, r.detail


def test_run_probe_scrubs_what_a_probe_raised(monkeypatch: pytest.MonkeyPatch) -> None:
    def raises() -> probes.ProbeResult:
        raise RuntimeError(_LEAKY)

    monkeypatch.setitem(probes.PROBES, "leaky", raises)
    r = probes.run_probe("leaky")
    assert r.status is HarnessStatus.ERROR
    assert r.detail.startswith("probe 'leaky' raised RuntimeError: "), r.detail
    assert _PLANTED not in r.detail, r.detail


def test_an_unreadable_junit_file_is_scrubbed(monkeypatch: pytest.MonkeyPatch) -> None:
    def unreadable(path: object) -> object:
        raise OSError(f"cannot open, password={_PLANTED}")

    monkeypatch.setattr(runner, "_parse_junit_by_file", unreadable)
    import subprocess

    monkeypatch.setattr(subprocess, "run", lambda *a, **k: None)
    r = runner.default_pytest_runner(["tests/test_nothing.py"])
    assert r.run_error.startswith("unreadable JUnit XML ("), r.run_error
    assert _PLANTED not in r.run_error, r.run_error


# ---- round-1 review: further raw arms, and the harness scrub's fail-closed path ---------------


def test_the_replay_catch_all_is_scrubbed(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    from messagefoundry.auth import oidc

    def boom(*args: object) -> object:
        raise RuntimeError(_LEAKY)

    token, jwks = tmp_path / "t.jwt", tmp_path / "jwks.json"
    token.write_text("a.b.c", encoding="ascii")
    jwks.write_text("{}", encoding="ascii")
    ok = CheckResult("fed.jwks", "JWKS", Status.PASS, "parsed")
    monkeypatch.setattr(federation, "_jwks_row", lambda raw: (object(), ok))
    monkeypatch.setattr(oidc, "validate_id_token", boom)
    rows = federation._replay_rows(_settings(), str(token), str(jwks), None)
    last = rows[-1]
    assert last.id == "fed.replay" and last.status is Status.ERROR, rows
    assert last.detail.startswith("RuntimeError: "), last.detail
    assert _PLANTED not in last.detail, last.detail


def test_a_settings_load_failure_is_scrubbed(monkeypatch: pytest.MonkeyPatch) -> None:
    from messagefoundry.config import settings as settings_module
    from messagefoundry.verify import runner as verify_runner

    def refuse(**kwargs: object) -> object:
        raise ValueError(f"[auth].oidc_token_endpoint https://svc:{_PLANTED}@idp.invalid/ refused")

    monkeypatch.setattr(settings_module, "load_settings", refuse)
    settings, error = verify_runner._load_settings("svc.toml")
    assert settings is None and error is not None
    assert "oidc_token_endpoint" in error, error
    assert _PLANTED not in error, error


def test_the_harness_scrub_withholds_the_text_when_it_cannot_run(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from messagefoundry import verify_leaf

    def broken(*args: object, **kwargs: object) -> str:
        raise SyntaxError("an interpreter too old for the engine")

    monkeypatch.setattr(verify_leaf, "safe_exc_text", broken)
    monkeypatch.setattr(verify_leaf, "safe_exc_detail", broken)
    monkeypatch.setattr(verify_leaf, "safe_detail_text", broken)
    for typed in (False, True):
        text = probes.scrubbed_exc(RuntimeError(_LEAKY), before="x: ", typed=typed)
        assert text.startswith("RuntimeError (detail withheld"), text
        assert "x: " not in text, text
        assert _PLANTED not in text, text


def test_the_typed_harness_scrub_scans_before_and_keeps_the_probe_key() -> None:
    # The typed path once added ``before`` unscrubbed, so a credential the caller built into it
    # printed. The probe key the operator needs must survive the scan.
    text = probes.scrubbed_exc(
        RuntimeError(_LEAKY), before=f"probe 'db_driver' raised at password={_PLANTED} ", typed=True
    )
    assert _PLANTED not in text, text
    assert text.startswith("probe 'db_driver' raised"), text
    assert "RuntimeError" in text, text


def test_the_typed_harness_scrub_reads_before_against_the_raw_text() -> None:
    # A second pass over already-scrubbed text no longer sees the value it hid, so ``before``
    # quoting that value printed it. One pass over the whole line hides both copies.
    text = probes.scrubbed_exc(
        RuntimeError(f"Login Password: {_PLANTED}"),
        before=f"probe for {_PLANTED} raised ",
        typed=True,
    )
    assert _PLANTED not in text, text


def test_the_typed_harness_scrub_keeps_the_unscanned_note() -> None:
    # A second length bound once dropped the first pass's unscanned-input note.
    text = probes.scrubbed_exc(
        RuntimeError("word " * 20000), before="probe 'k' raised ", typed=True
    )
    assert "unscanned" in text, text[-200:]


def test_run_probe_names_the_key_and_scrubs_the_text(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom() -> probes.ProbeResult:
        raise RuntimeError(_LEAKY)

    monkeypatch.setitem(probes.PROBES, "console_gui", boom)
    result = probes.run_probe("console_gui")
    assert result.detail.startswith("probe 'console_gui' raised RuntimeError"), result.detail
    assert _PLANTED not in result.detail, result.detail


def test_the_typed_harness_scrub_withholds_before_when_the_line_scrub_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from messagefoundry import verify_leaf

    def broken(*args: object, **kwargs: object) -> str:
        raise SyntaxError("an interpreter too old for the engine")

    monkeypatch.setattr(verify_leaf, "safe_detail_text", broken)
    text = probes.scrubbed_exc(RuntimeError("x"), before=f"password={_PLANTED} ", typed=True)
    assert text.startswith("RuntimeError (detail withheld"), text
    assert _PLANTED not in text, text
