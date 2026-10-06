# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""ADR 0118 AC-7 — the gate-parity safety net.

The [security] section only RE-SOURCES the posture switches (a desugar into the internal fields the
gate ladder already reads); it must never loosen a shipped refusal. This module reproduces the KNOWN
pre-refactor refuse/allow decisions *through the new [security] keys* and asserts they are unchanged,
and confirms the ``checks.py`` commit/CI mirror fails-closed on an unresolved posture the same way
``serve`` does — both keyed off ``[security]``.
"""

from __future__ import annotations

import os
import tomllib
from pathlib import Path

import pytest

from messagefoundry.__main__ import main
from messagefoundry.checks import CheckResult, run_checks
from tests._phi_gate_provisions import (
    PHI_GATE_PROVISIONS_NO_ALERTS_TOML,
    PHI_GATE_PROVISIONS_TOML,
)
from tests.test_api_tls import _ACK_MODES, _posture_b_toml, _run_posture_b, _self_signed

SAMPLES_CONFIG = Path(__file__).resolve().parents[1] / "samples" / "config"

# Non-security plumbing that pre-clears the OTHER exposure gates so exactly one refusal is under test at
# a time (a real TLS-terminating proxy + bounded retention + an SMTP alert channel).
_PROXY = (
    '[api]\ntls_terminated_upstream = true\nplaintext_upstream_hop_acknowledged = true\ntrusted_proxies = ["10.0.0.1"]\n'
    'proxy_intra_service_auth = "network"\nproxy_tls_min_version = "1.2"\n'
)
_RETENTION_DL = "[retention]\ndead_letter_days = 30\n"
_ALERTS = (
    '[alerts]\nemail_smtp_host = "smtp.example.org"\nemail_from = "sec@example.org"\n'
    'email_to = ["ops@example.org"]\n'
)
#: ADR 0152 rung 2: an EXPOSED PHI instance without an in-use data-protection declaration WARNS at
#: every start. Declared in the exposed rows exactly like the retention/alerts plumbing above, so a
#: row testing a DIFFERENT gate never has this rung's output mixed into its stderr. Must precede
#: _PROXY: it is a [security] key, and TOML would file it under [api] if it followed a table header.
#: The rung's own warn/refuse matrix lives in tests/test_memory_encryption_readout.py.
_MEMORY_ENCRYPTION = "security.memory_encryption_operator_declared = true\n"
#: BACKLOG #1026: a PHI instance behind a declared terminator under `enforce` REFUSES without a
#: public address -- the ASVS 12.1.1 probe dials it, and an unset value silently disabled that check.
#: Declared in the exposed rows exactly like _MEMORY_ENCRYPTION above, and subject to the SAME
#: placement rule for the same reason: it is a [security] key, so it must precede _PROXY or TOML
#: files it under [api]. The AUTHORED key is `web_console_public_address`; `[api].public_origin` is
#: the INTERNAL settings name and ADR 0118 retired the authored form, which is refused outright.
_PUBLIC_ADDRESS = 'security.web_console_public_address = "https://mefor.example.org"\n'


class _PassingProbe:
    """Stand-in for TlsFloorProbe: the startup ladder reads only ``.ok`` and ``.describe()``."""

    ok = True

    def describe(self) -> str:
        return "stubbed probe (test)"


def _serve(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    toml: str,
    *,
    env: str,
    key: bool = True,
    insecure: bool = False,
) -> int:
    monkeypatch.chdir(tmp_path)
    if key:
        monkeypatch.setenv("MEFOR_STORE_ENCRYPTION_KEY", "x" * 44)
    else:
        monkeypatch.delenv("MEFOR_STORE_ENCRYPTION_KEY", raising=False)
    (tmp_path / "messagefoundry.toml").write_text(toml, encoding="utf-8")
    monkeypatch.setattr("messagefoundry.api.create_managed_app", lambda **kw: object())
    monkeypatch.setattr("uvicorn.run", lambda *a, **k: None)
    # The 12.1.1 probe makes real TLS handshakes against the declared address, which #1026 now
    # requires in this posture. Stubbed to PASS for the same reason uvicorn.run is: these rows test
    # CONFIG-GATE PARITY, and the probe's own network behaviour is tests/test_tls_floor_probe.py.
    monkeypatch.setattr(
        "messagefoundry.config.tls_probe.probe_tls_floor", lambda origin: _PassingProbe()
    )
    argv = ["serve", "--config", str(SAMPLES_CONFIG), "--env", env]
    if insecure:
        argv.append("--allow-insecure-bind")
    return main(argv)


#: (label, [security]-expressed config, env, key-present, expected serve exit code). Each REFUSE (2) is a
#: pre-refactor gate that must still fire through [security]; each ALLOW (0) must still start. No entry
#: uses a legacy key — the whole point is that the new keys reproduce the old decisions.
_MATRIX: list[tuple[str, str, str, bool, int]] = [
    # keyless refusals. These were data_class-gated; since BACKLOG #1279 every instance is in scope,
    # so the only thing that varies is whether the per-gate ack is present.
    ("keyless-prod-phi-refuses", "", "prod", False, 2),
    ("keyless-staging-phi-refuses", "", "staging", False, 2),
    # A dev box declares no data class; it takes the per-gate acks like any other (BACKLOG #1279).
    (
        "keyless-dev-with-acks-allows",
        PHI_GATE_PROVISIONS_TOML,
        "dev",
        False,
        0,
    ),
    (
        "keyless-declared-phi-on-dev-refuses",
        "",
        "dev",
        False,
        2,
    ),
    (
        "keyless-phi-override-allows",
        'security.enforcement = "warn"\nsecurity.allow_unencrypted_phi = true\n',
        "staging",
        False,
        0,
    ),
    # No-loosen carve-out (ADR 0140): production-PHI keyless now requires BOTH acks; the single flag alone
    # refuses on prod (a deliberate tightening), and the single-factor-admin ack lifts the exposed-prod MFA
    # refusal to warn-and-start. Non-prod (staging above) is unchanged.
    (
        # Pre-clear egress/retention/alerts so the ONLY remaining refusal is the ADR-0140 keyless-prod
        # branch — exit 2 here discriminates that branch (deleting it would flip this row to ALLOW),
        # unlike a bare single-flag config whose exit 2 the later open-egress gate would also produce.
        #
        # THIS ROW MUST NEVER TAKE A SHARED PROVISIONS BUNDLE, and no subtraction of one works either.
        # Its whole scenario is a MISSING second ack, and both bundles carry
        # `allow_unencrypted_phi_under_strict_enforcement` — the very flag whose absence is under test.
        # Taking one provisions the refusal away, so the row would pass on whatever gate fired next, or
        # on none. It once took `PHI_GATE_PROVISIONS_TOML` and duplicated the dotted
        # `security.allow_unencrypted_phi` key, which made the TOML unparseable; `TOMLDecodeError`
        # subclasses `ValueError`, the config load returns 2, and the row expected 2 — so it passed
        # without ever reaching this gate. Spell the four lines out here.
        "keyless-prod-phi-single-flag-refuses",
        "security.allow_unencrypted_phi = true\n"
        "security.block_unlisted_outbound = true\n"
        "security.delete_message_bodies_after_days = 30\n" + _RETENTION_DL + _ALERTS,
        "prod",
        False,
        2,
    ),
    (
        "keyless-prod-phi-both-acks-allows",
        PHI_GATE_PROVISIONS_NO_ALERTS_TOML
        + "security.delete_message_bodies_after_days = 30\n"
        + _RETENTION_DL
        + _ALERTS,
        "prod",
        False,
        0,
    ),
    (
        "mfa-off-exposed-prod-phi-single-factor-ack-allows",
        'security.local_access_only = false\nsecurity.listen_address = "0.0.0.0"\n'
        "security.require_mfa = false\nsecurity.allow_single_factor_admin_when_exposed = true\n"
        + PHI_GATE_PROVISIONS_NO_ALERTS_TOML
        + "security.delete_message_bodies_after_days = 30\n"
        + _MEMORY_ENCRYPTION
        + _PUBLIC_ADDRESS
        + _PROXY
        + _RETENTION_DL
        + _ALERTS,
        "prod",
        True,
        0,
    ),
    (
        "encrypt-off-allows-keyless-phi",
        'security.enforcement = "warn"\nsecurity.encrypt_stored_data = false\n',
        "staging",
        False,
        0,
    ),
    # The auth-off row that sat here went with [security].require_sign_in (vault BACKLOG #2719). No
    # [security] key turns sign-in off now, so a row setting it would exit 2 at the LOAD, not at the
    # gate it claims to measure. tests/test_cli.py drives the arm itself.
    # cleartext off-loopback bind: refuse by default; the config-twin of --allow-insecure-bind
    # (require_encryption_for_remote=false) allows it on non-prod-PHI but the prod-PHI CLAMP still refuses.
    (
        "cleartext-offloopback-refuses",
        'security.local_access_only = false\nsecurity.listen_address = "0.0.0.0"\n',
        "dev",
        True,
        2,
    ),
    (
        # The escape is CLAMPED INERT while enforcing. That clamp used to need enforcing AND PHI, and
        # this row escaped it by declaring the box synthetic; BACKLOG #1279 left the dial as the only
        # key, so the dial is what opens this path. The prod-clamp row below still covers the refusal.
        "cleartext-offloopback-warn-escape-allows",
        'security.enforcement = "warn"\n'
        + PHI_GATE_PROVISIONS_TOML
        + 'security.local_access_only = false\nsecurity.listen_address = "0.0.0.0"\n'
        "security.require_encryption_for_remote = false\n",
        "dev",
        True,
        0,
    ),
    (
        "cleartext-offloopback-prod-phi-clamp-refuses",
        'security.local_access_only = false\nsecurity.listen_address = "0.0.0.0"\n'
        "security.require_encryption_for_remote = false\n"
        "security.block_unlisted_outbound = true\nsecurity.delete_message_bodies_after_days = 30\n"
        + _RETENTION_DL
        + _ALERTS,
        "prod",
        True,
        2,
    ),
    # open egress: prod PHI refuses, synthetic is quiet.
    (
        "open-egress-prod-phi-refuses",
        "security.block_unlisted_outbound = false\n",
        "prod",
        True,
        2,
    ),
    # MFA-at-exposure: production PHI behind a declared proxy with require_mfa off refuses.
    (
        "mfa-off-exposed-prod-phi-refuses",
        'security.local_access_only = false\nsecurity.listen_address = "0.0.0.0"\n'
        "security.require_mfa = false\nsecurity.block_unlisted_outbound = true\n"
        "security.delete_message_bodies_after_days = 30\n" + _PROXY + _RETENTION_DL + _ALERTS,
        "prod",
        True,
        2,
    ),
    (
        "mfa-off-exposed-staging-phi-warns-and-starts",
        'security.enforcement = "warn"\n'
        'security.local_access_only = false\nsecurity.listen_address = "0.0.0.0"\n'
        "security.require_mfa = false\nsecurity.block_unlisted_outbound = true\n"
        "security.delete_message_bodies_after_days = 30\n" + _PROXY + _RETENTION_DL + _ALERTS,
        "staging",
        True,
        0,
    ),
    # BACKLOG #326: the SAME refusal on the runbook's RECOMMENDED topology — a LOOPBACK bind
    # (local_access_only left true) behind a DECLARED TLS-terminating proxy. This row is the one the
    # old `admin_exposed = not is_loopback or ui_exposed` keying could not produce: the ADR 0143
    # auto-degrade clears serve_ui first, so ui_exposed was False and a production PHI instance with
    # single-factor admin on the network started clean. Driven through the REAL gate (`main(["serve",
    # ...])`) because checks.py is not a second gate site for it — that mirror reads neither
    # require_mfa nor is_loopback.
    (
        "mfa-off-loopback-behind-proxy-prod-phi-refuses",
        "security.require_mfa = false\nsecurity.block_unlisted_outbound = true\n"
        "security.delete_message_bodies_after_days = 30\n"
        + _MEMORY_ENCRYPTION
        + _PROXY
        + _RETENTION_DL
        + _ALERTS,
        "prod",
        True,
        2,
    ),
    # unbounded retention on a production PHI instance refuses.
    (
        "unbounded-retention-prod-phi-refuses",
        "security.block_unlisted_outbound = true\nsecurity.delete_message_bodies_after_days = 0\n"
        + _RETENTION_DL
        + _ALERTS,
        "prod",
        True,
        2,
    ),
    # a fully-configured prod loopback instance (key + egress locked + retention bounded + alerts) starts.
    (
        "prod-loopback-fully-configured-allows",
        "security.block_unlisted_outbound = true\nsecurity.delete_message_bodies_after_days = 30\n"
        + _RETENTION_DL
        + _ALERTS,
        "prod",
        True,
        0,
    ),
    # a synthetic dev loopback instance is byte-identical: it starts with a key. GIVEN 1 (ADR 0148):
    # dev derives PHI now, so the synthetic posture is declared explicitly.
    (
        "synthetic-loopback-default-allows",
        PHI_GATE_PROVISIONS_TOML,
        "dev",
        True,
        0,
    ),
]


@pytest.mark.parametrize("label,toml,env,key,expected", _MATRIX, ids=[m[0] for m in _MATRIX])
def test_every_matrix_row_is_valid_toml(
    label: str, toml: str, env: str, key: bool, expected: int
) -> None:
    """A row that does not PARSE still exits 2, so a REFUSE row passes without reaching its gate.

    `__main__` catches `ValueError` from the config load and returns 2, and `TOMLDecodeError`
    subclasses `ValueError`. That makes a malformed row indistinguishable from the refusal it claims
    to measure. One row concatenated a bundle that already carried the same dotted key and sat green
    for the life of the matrix; 19 of 20 rows parsed and the 20th passed anyway.

    This control is cheap because it does not start anything -- it only asserts the fixture is the
    document the row's author thought they wrote.
    """
    tomllib.loads(toml)


@pytest.mark.parametrize("label,toml,env,key,expected", _MATRIX, ids=[m[0] for m in _MATRIX])
def test_gate_parity_through_security_keys(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    label: str,
    toml: str,
    env: str,
    key: bool,
    expected: int,
) -> None:
    rc = _serve(tmp_path, monkeypatch, toml, env=env, key=key)
    assert rc == expected, f"{label}: serve exit {rc}, expected {expected}"


# --- checks.py mirror parity: the posture gate fails-closed through [security] exactly as serve does --


def _config_repo(tmp_path: Path, toml_body: str) -> Path:
    repo = tmp_path / "repo"
    cfg = repo / "config"
    cfg.mkdir(parents=True)
    (cfg / "c.py").write_text(
        "from messagefoundry import inbound, router, File\n"
        "inbound('IB_X', File(directory='in'), router='r')\n"
        "@router('r')\n"
        "def r(m): return []\n",
        encoding="utf-8",
    )
    (repo / "messagefoundry.toml").write_text(toml_body, encoding="utf-8")
    return cfg


def _posture(cfg: Path) -> object:
    return next(r for r in run_checks(cfg, run_lint=False).results if r.name == "posture")


def test_checks_mirror_posture_parity_through_security_keys(tmp_path: Path) -> None:
    # A custom env with NO [security] posture: the checks mirror FAILS closed, naming the [security] key —
    # exactly the fail-closed require_posture() that serve refuses on.
    fail = _posture(_config_repo(tmp_path / "a", '[ai]\nenvironment = "poc"\n'))
    assert fail.required and not fail.ok and not fail.skipped  # type: ignore[attr-defined]
    # It named BOTH posture keys until BACKLOG #1279 removed the data class. Asserting the ABSENCE of
    # the retired one matters as much as the presence of the survivor: a remediation naming a key the
    # loader refuses costs an operator a restart cycle to discover, and reads as authoritative.
    assert "production_instance" in fail.detail  # type: ignore[attr-defined]
    assert "handles_real_patient_data" not in fail.detail  # type: ignore[attr-defined]

    # The SAME custom env with the posture set via [security] resolves — the mirror passes.
    ok = _posture(
        _config_repo(
            tmp_path / "b",
            "security.block_unlisted_outbound = true\nsecurity.production_instance = false\n"
            '[ai]\nenvironment = "poc"\n',
        )
    )
    assert ok.required and ok.ok and not ok.skipped  # type: ignore[attr-defined]


# --- BACKLOG #1179: the plaintext-hop acknowledgement refuses in serve AND fails the check ---------
# serve refuses a declared terminator with no [api].tls_cert_file and no acknowledgement, in every
# mode. The check must fail on exactly the configs serve refuses, or the commit/CI gate passes a
# config the engine will not start. Each arm runs BOTH on ONE messagefoundry.toml, reusing the
# Posture-B fixture from tests/test_api_tls.py, which pre-satisfies every other exposure gate, so
# serve's exit code is this gate's decision and not some neighbour's.

#: (arm, ack, cert, expected serve exit). The refuse arm is the only one that exits 2.
_HOP_ACK_ARMS = [
    ("refuses-without-ack", False, False, 2),
    ("acknowledged-starts", True, False, 0),
    ("operator-cert-needs-no-ack", False, True, 0),
]


def _hop_ack_check(toml: Path) -> CheckResult:
    report = run_checks(SAMPLES_CONFIG, run_lint=False, service_config=toml)
    return next(r for r in report.results if r.name == "upstream-hop-ack")


@_ACK_MODES
@pytest.mark.parametrize("arm,ack,cert,expected", _HOP_ACK_ARMS, ids=[a[0] for a in _HOP_ACK_ARMS])
def test_checks_mirror_hop_ack_parity_with_serve(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    loopback: bool,
    enforcement: str,
    arm: str,
    ack: bool,
    cert: bool,
    expected: int,
) -> None:
    # intra="mtls" with the certificate, as the serve-side tests do: it is the attestation that
    # goes with an engine serving the hop over TLS.
    _posture_b_toml(
        tmp_path,
        intra="mtls" if cert else "network",
        floor="1.2",
        enforcement=enforcement,
        loopback=loopback,
        ack=ack,
        cert=_self_signed(tmp_path) if cert else None,
    )
    rc = _run_posture_b(tmp_path, monkeypatch, env="prod")
    err = capsys.readouterr().err
    assert rc == expected, f"{arm}: serve exit {rc}, expected {expected}"
    if expected == 2:
        # Other gates also exit 2; the message pins that THIS one refused.
        assert "without [api].plaintext_upstream_hop_acknowledged" in err

    result = _hop_ack_check(tmp_path / "messagefoundry.toml")
    assert result.required and not result.skipped
    # The parity itself: the check fails exactly when serve refuses.
    assert result.ok == (rc == 0), f"{arm}: serve exit {rc} but check ok={result.ok}"
    if not result.ok:
        assert "plaintext_upstream_hop_acknowledged" in result.detail


def test_hop_ack_check_passes_without_a_terminator(tmp_path: Path) -> None:
    # No terminator means the engine serves its own TLS: there is no plaintext hop to acknowledge.
    toml = tmp_path / "messagefoundry.toml"
    toml.write_text("[api]\n", encoding="utf-8")
    result = _hop_ack_check(toml)
    assert result.required and result.ok and not result.skipped
    assert "generated" in result.detail


def test_hop_ack_check_fails_a_stray_acknowledgement(tmp_path: Path) -> None:
    # serve refuses this at load (the acknowledgement needs a terminator); the check must too, as a
    # FAIL and not a SKIP (BACKLOG #1318).
    toml = tmp_path / "messagefoundry.toml"
    toml.write_text("[api]\nplaintext_upstream_hop_acknowledged = true\n", encoding="utf-8")
    result = _hop_ack_check(toml)
    assert result.required and not result.ok and not result.skipped
    assert "plaintext_upstream_hop_acknowledged requires" in result.detail


def test_hop_ack_check_allows_an_acknowledgement_beside_an_operator_cert(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # serve allows this (test_api_tls.py); the check must not fail it.
    _posture_b_toml(tmp_path, intra="mtls", floor="1.2", ack=True, cert=_self_signed(tmp_path))
    assert _run_posture_b(tmp_path, monkeypatch, env="prod") == 0
    result = _hop_ack_check(tmp_path / "messagefoundry.toml")
    assert result.required and result.ok and not result.skipped
    assert "operator" in result.detail


def test_hop_ack_check_fails_through_the_default_toml_search(tmp_path: Path) -> None:
    # The documented `check --config config` form passes no service_config: the check walks up to
    # the repo's messagefoundry.toml. A leg that only worked with an explicit path would pass here.
    cfg = _config_repo(
        tmp_path, '[api]\ntls_terminated_upstream = true\ntrusted_proxies = ["10.0.0.1"]\n'
    )
    result = next(
        r for r in run_checks(cfg, run_lint=False).results if r.name == "upstream-hop-ack"
    )
    assert result.required and not result.ok and not result.skipped


def test_hop_ack_check_skips_without_a_service_toml(tmp_path: Path) -> None:
    cfg = tmp_path / "config"
    cfg.mkdir()
    result = next(
        r
        for r in run_checks(cfg, run_lint=False, suppress_service_toml_search=True).results
        if r.name == "upstream-hop-ack"
    )
    assert result.required and result.ok and result.skipped


def test_hop_ack_check_load_failure_echoes_no_secret(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A ValidationError's str() carries the section's input values, env-sourced secrets included.
    monkeypatch.setenv("MEFOR_API_TLS_KEY_PASSWORD", "SUPERSECRET123")
    toml = tmp_path / "messagefoundry.toml"
    toml.write_text("[api]\nplaintext_upstream_hop_acknowledged = true\n", encoding="utf-8")
    result = _hop_ack_check(toml)
    assert not result.ok
    assert "SUPERSECRET123" not in result.detail


# --- vault BACKLOG #2622 item 1: the inbound exposure gates run at check, as at start -------------
# serve refuses a cleartext off-loopback listener when it starts it. The build-check leg now runs
# the same four gates, keyed on the same posture and the same escape, so the gate fails the config
# rather than passing it to a serve that refuses. The runner-level parity, the same message from
# both arms, is pinned in tests/test_wiring_engine.py.

_ESCAPE = "security.require_encryption_for_remote = false\n"

#: (arm, [security] lines, bind off loopback?, expected build-check ok). The loopback control shows
#: the refusal is about exposure and not about MLLP.
_EXPOSURE_ARMS = [
    ("off-loopback-cleartext-refused", "", True, False),
    ("loopback-control-passes", "", False, True),
    # serve folds [security].require_encryption_for_remote=false into its cleartext escape, and
    # under enforcement=warn the escape crosses with a warning. check must agree.
    ("escape-under-warn-passes", 'security.enforcement = "warn"\n' + _ESCAPE, True, True),
    # Under enforce the escape is clamped, at start and at check alike.
    ("escape-under-enforce-refused", _ESCAPE, True, False),
]


def _scrub_mefor_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Remove every MEFOR_* variable for this test. A CI job or this file's own fixtures can export
    settings variables, and these tests must read only what they set."""
    for name in list(os.environ):
        if name.upper().startswith("MEFOR_"):
            monkeypatch.delenv(name)


@pytest.mark.parametrize(
    "arm,security,exposed,ok", _EXPOSURE_ARMS, ids=[a[0] for a in _EXPOSURE_ARMS]
)
def test_build_check_runs_the_inbound_exposure_gates(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    arm: str,
    security: str,
    exposed: bool,
    ok: bool,
) -> None:
    # An exported MEFOR_INBOUND_BIND_HOST or MEFOR_SECURITY_* would beat the file below.
    _scrub_mefor_env(monkeypatch)
    repo = tmp_path / "repo"
    cfg = repo / "config"
    cfg.mkdir(parents=True)
    (cfg / "c.py").write_text(
        "from messagefoundry import inbound, router, MLLP\n"
        "inbound('IB_EXPOSED', MLLP(port=2600), router='r')\n"
        "@router('r')\n"
        "def r(m): return []\n",
        encoding="utf-8",
    )
    # The dotted [security] keys come first, or TOML files them under the last table header.
    bind = '[inbound]\nbind_host = "0.0.0.0"\n' if exposed else ""
    toml = repo / "messagefoundry.toml"
    toml.write_text(security + '[ai]\nenvironment = "dev"\n' + bind, encoding="utf-8")
    # Named explicitly, so no messagefoundry.toml above tmp_path can stand in for it.
    report = run_checks(cfg, run_lint=False, service_config=toml)
    result = next(r for r in report.results if r.name == "build-check")
    assert result.required and not result.skipped, f"{arm}: {result.detail}"
    assert result.ok is ok, f"{arm}: {result.detail}"
    if not ok:
        assert "IB_EXPOSED" in result.detail and "without TLS" in result.detail
        # The gate's text names serve's flag; the leg must say check cannot read it.
        assert "reads only [security].require_encryption_for_remote = false" in result.detail


# --- vault BACKLOG #2355: an instance declared in MEFOR_* variables alone is checked, not skipped --
# Before this every settings leg returned SKIP "no messagefoundry.toml" before reading a variable, so
# a site configured by environment alone got a green gate that read nothing. The trigger is
# MEFOR_AI_ENVIRONMENT, because serve refuses to start without an active environment; any other
# MEFOR_<SECTION>_* variable alone, a store key in a dev shell, keeps the bare-dir SKIP.

_ENV_ONLY_NOTE = "settings from environment only"
_MLLP_CONFIG = (
    "from messagefoundry import inbound, router, MLLP\n"
    "inbound('IB_ENV', MLLP(port=2601), router='r')\n"
    "@router('r')\n"
    "def r(m): return []\n"
)


def _bare_config(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, body: str = _MLLP_CONFIG) -> Path:
    """A config dir with no messagefoundry.toml, and an environment holding no MEFOR_* variable
    but the ones the test sets."""
    _scrub_mefor_env(monkeypatch)
    cfg = tmp_path / "config"
    cfg.mkdir()
    (cfg / "c.py").write_text(body, encoding="utf-8")
    # A --project-root check names a messagefoundry.toml in the working directory, so run from an
    # empty one: a developer's own file at the repository root must not change these results.
    empty = tmp_path / "cwd"
    empty.mkdir()
    monkeypatch.chdir(empty)
    return cfg


def _leg(cfg: Path, name: str) -> CheckResult:
    # suppress_service_toml_search confines the look to cfg, so no file anywhere above tmp_path can
    # stand in for the environment. _bare_config runs from an empty working directory.
    report = run_checks(cfg, run_lint=False, suppress_service_toml_search=True)
    return next(r for r in report.results if r.name == name)


_SETTINGS_LEGS = (
    "posture",
    "build-check",
    "reference-backend",
    "upstream-hop-ack",
    "oidc-auth-params",
    "static-credentials",
    "alert-smtp-tls",
)


@pytest.mark.parametrize("name", _SETTINGS_LEGS)
def test_every_settings_leg_reads_an_environment_only_instance(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, name: str
) -> None:
    cfg = _bare_config(tmp_path, monkeypatch)
    monkeypatch.setenv("MEFOR_AI_ENVIRONMENT", "dev")
    result = _leg(cfg, name)
    assert _ENV_ONLY_NOTE in result.detail, f"{name}: {result.detail}"
    assert "graph only" not in result.detail  # static-credentials read the settings half too
    if name != "static-credentials":  # that leg reads the graph either way, so never skipped
        assert not result.skipped, f"{name}: {result.detail}"


@pytest.mark.parametrize("name", _SETTINGS_LEGS)
def test_a_store_key_alone_keeps_the_bare_dir_skip(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, name: str
) -> None:
    # Trap 2 of the item: a dev shell exporting settings variables but naming no environment is
    # not an instance serve would run, so nothing changes for it.
    cfg = _bare_config(tmp_path, monkeypatch)
    monkeypatch.setenv("MEFOR_STORE_ENCRYPTION_KEY", "x" * 44)
    monkeypatch.setenv("MEFOR_INBOUND_BIND_HOST", "0.0.0.0")
    result = _leg(cfg, name)
    assert _ENV_ONLY_NOTE not in result.detail
    if name == "static-credentials":
        assert "graph only" in result.detail
    else:
        assert result.skipped and result.detail == "no messagefoundry.toml", result.detail


@pytest.mark.parametrize("name", _SETTINGS_LEGS)
def test_a_missing_named_service_config_never_falls_through_to_the_environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, name: str
) -> None:
    # serve refuses a --service-config that does not exist. Reading defaults plus the environment
    # in its place would pass a config serve will not start, so the leg keeps its old answer.
    cfg = _bare_config(tmp_path, monkeypatch)
    monkeypatch.setenv("MEFOR_AI_ENVIRONMENT", "dev")
    report = run_checks(cfg, run_lint=False, service_config=tmp_path / "typo.toml")
    result = next(r for r in report.results if r.name == name)
    assert _ENV_ONLY_NOTE not in result.detail, f"{name}: {result.detail}"
    if name == "static-credentials":
        assert "graph only" in result.detail
    else:
        assert result.skipped, f"{name}: {result.detail}"


def test_a_graph_skip_is_not_tagged_as_an_environment_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A config that will not load skips for a graph reason. The environment-only tag would name the
    # wrong cause, so it goes only on a line that ran.
    cfg = _bare_config(tmp_path, monkeypatch, "this is not python\n")
    monkeypatch.setenv("MEFOR_AI_ENVIRONMENT", "dev")
    report = run_checks(cfg, run_lint=False, suppress_service_toml_search=True)
    for name in ("build-check", "reference-backend", "static-credentials"):
        result = next(r for r in report.results if r.name == name)
        assert result.skipped and "config did not load" in result.detail, result.detail
        assert _ENV_ONLY_NOTE not in result.detail
    # The settings-only legs still ran, and say where they read from.
    assert _ENV_ONLY_NOTE in next(r for r in report.results if r.name == "posture").detail


def test_a_malformed_environment_values_file_fails_the_leg_not_the_gate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # An environment-only instance reaches the env() value load from a bare dir. A broken
    # environments/<env>.toml used to escape as a traceback that ended the whole run.
    cfg = _bare_config(tmp_path, monkeypatch)
    values = tmp_path / "values"
    (values / "environments").mkdir(parents=True)
    (values / "environments" / "dev.toml").write_text("this = = broken\n", encoding="utf-8")
    monkeypatch.chdir(values)
    monkeypatch.setenv("MEFOR_AI_ENVIRONMENT", "dev")
    report = run_checks(cfg, run_lint=False, suppress_service_toml_search=True)
    result = next(r for r in report.results if r.name == "build-check")
    assert result.required and not result.ok and not result.skipped
    assert "environment values or [tls] trust anchors did not load" in result.detail
    # The other legs were still reported.
    assert any(r.name == "upstream-hop-ack" and r.ok for r in report.results)


def test_posture_refuses_an_environment_only_custom_name(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    cfg = _bare_config(tmp_path, monkeypatch)
    monkeypatch.setenv("MEFOR_AI_ENVIRONMENT", "poc")
    fail = _leg(cfg, "posture")
    assert fail.required and not fail.ok and not fail.skipped
    assert "production_instance" in fail.detail
    monkeypatch.setenv("MEFOR_SECURITY_PRODUCTION_INSTANCE", "false")
    ok = _leg(cfg, "posture")
    assert ok.ok and not ok.skipped, ok.detail


def test_build_check_refuses_an_environment_only_exposed_listener(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The two items meet here: the bind host comes from the environment, and the exposure gate it
    # trips now runs at check.
    cfg = _bare_config(tmp_path, monkeypatch)
    monkeypatch.setenv("MEFOR_AI_ENVIRONMENT", "dev")
    monkeypatch.setenv("MEFOR_INBOUND_BIND_HOST", "0.0.0.0")
    result = _leg(cfg, "build-check")
    assert result.required and not result.ok and not result.skipped
    assert "IB_ENV" in result.detail and "without TLS" in result.detail
    assert _ENV_ONLY_NOTE in result.detail


def test_hop_ack_refuses_an_environment_only_terminator(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # BACKLOG #1179's recorded gap: a terminator set only through MEFOR_API_* reached serve and not
    # the check.
    cfg = _bare_config(tmp_path, monkeypatch)
    monkeypatch.setenv("MEFOR_AI_ENVIRONMENT", "dev")
    monkeypatch.setenv("MEFOR_API_TLS_TERMINATED_UPSTREAM", "true")
    monkeypatch.setenv("MEFOR_API_TRUSTED_PROXIES", "10.0.0.1")
    result = _leg(cfg, "upstream-hop-ack")
    assert result.required and not result.ok and not result.skipped
    assert "plaintext_upstream_hop_acknowledged" in result.detail


def test_reference_backend_reads_an_environment_only_backend(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The SQL Server flag stands in for a future backend with no snapshot store, as in
    # tests/test_checks.py. The backend is declared only in MEFOR_STORE_*.
    from messagefoundry.store.sqlserver import SqlServerStore

    monkeypatch.setattr(SqlServerStore, "supports_reference_sets", False)
    csv = tmp_path / "npi.csv"
    csv.write_text("key,value\nMED1,9991\n", encoding="utf-8")
    cfg = _bare_config(
        tmp_path,
        monkeypatch,
        "from messagefoundry import inbound, router, File, Reference, FileRef\n"
        "inbound('IB_X', File(directory='in'), router='r')\n"
        f"Reference('provider_npi', source=FileRef(path={str(csv)!r}))\n"
        "@router('r')\n"
        "def r(m): return []\n",
    )
    monkeypatch.setenv("MEFOR_AI_ENVIRONMENT", "dev")
    for key, value in (
        ("BACKEND", "sqlserver"),
        ("SERVER", "db.example.invalid"),
        ("DATABASE", "mefor"),
        ("USERNAME", "mefor_svc"),
    ):
        monkeypatch.setenv(f"MEFOR_STORE_{key}", value)
    result = _leg(cfg, "reference-backend")
    assert result.required and not result.ok and not result.skipped
    assert "provider_npi" in result.detail and "sqlserver" in result.detail


@pytest.mark.parametrize("declared", [True, False], ids=["env-declared", "no-env-name"])
def test_project_root_names_an_unread_working_directory_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, declared: bool
) -> None:
    # Review round 3. `serve --project-root` with no --service-config reads ./messagefoundry.toml
    # in its own working directory. check under --project-root does not read the one in its working
    # directory (ADR 0050 AC-6: it may be another instance's), so with MEFOR_AI_ENVIRONMENT set it
    # read the environment alone and printed an OK line saying there was no file. It now SKIPs and
    # names the file. This one declares a terminator with no acknowledgement, which the leg would
    # refuse if it read it, so a SKIP also shows the file was not read.
    cfg = _bare_config(tmp_path, monkeypatch)
    here = tmp_path / "here"
    here.mkdir()
    stray = here / "messagefoundry.toml"
    stray.write_text(
        '[api]\ntls_terminated_upstream = true\ntrusted_proxies = ["10.0.0.1"]\n', encoding="utf-8"
    )
    monkeypatch.chdir(here)
    if declared:
        monkeypatch.setenv("MEFOR_AI_ENVIRONMENT", "dev")
    for name in _SETTINGS_LEGS:
        result = _leg(cfg, name)
        assert _ENV_ONLY_NOTE not in result.detail, f"{name}: {result.detail}"
        assert str(stray) in result.detail and "--service-config" in result.detail, result.detail
        if name != "static-credentials":  # reads the graph half either way
            assert result.skipped and result.ok, f"{name}: {result.detail}"


def test_a_directory_named_messagefoundry_toml_is_not_read_past(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # serve's load_settings tests exists() and then opens the path, so a directory of that name in
    # its working directory stops it. check must not read the environment past it and report OK.
    cfg = _bare_config(tmp_path, monkeypatch)
    here = tmp_path / "here"
    (here / "messagefoundry.toml").mkdir(parents=True)
    monkeypatch.chdir(here)
    monkeypatch.setenv("MEFOR_AI_ENVIRONMENT", "dev")
    result = _leg(cfg, "posture")
    assert result.skipped and _ENV_ONLY_NOTE not in result.detail, result.detail
    assert "--service-config" in result.detail


# BACKLOG #1967: this file's serve fixtures test other gates, so they bound the two warn-only
# retention tiers that ship with no window (tests/conftest.py, bounded_warn_only_retention).
pytestmark = pytest.mark.usefixtures("bounded_warn_only_retention", "verified_log_forwarding")
