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
_ALERTS = '[alerts]\nemail_smtp_host = "smtp.example.org"\nemail_from = "sec@example.org"\n'
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
    # auth-off + non-loopback is a HARD refuse regardless of the insecure escape.
    (
        "authoff-nonloopback-refuses",
        'security.require_sign_in = false\nsecurity.local_access_only = false\nsecurity.listen_address = "0.0.0.0"\n',
        "dev",
        True,
        2,
    ),
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
