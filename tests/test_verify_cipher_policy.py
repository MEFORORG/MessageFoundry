# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""``host.ciphers``: DEPLOY-SERVER-DB.md section 5.4's host cipher checks, run by ``verify``.

The platform probes are stubbed, so both platform branches run on any OS. Each branch has a passing
and a failing policy reading, and the control-is-zero case, which must never read as a PASS."""

from __future__ import annotations

import sys
from collections.abc import Mapping
from pathlib import Path

import pytest

from messagefoundry.verify import checks, cipher_policy
from messagefoundry.verify.cipher_policy import ProbeFailed, ProbeUnavailable
from messagefoundry.verify.model import CheckResult, Status

# Names as Get-TlsCipherSuite prints them.
_WIN_AEAD = ["TLS_AES_256_GCM_SHA384", "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"]
_WIN_CBC = "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384"

# Lines as `openssl ciphers -s -v` prints them.
_SSL_AEAD = [
    "TLS_AES_256_GCM_SHA384 TLSv1.3 Kx=any Au=any Enc=AESGCM(256) Mac=AEAD",
    "ECDHE-RSA-AES256-GCM-SHA384 TLSv1.2 Kx=ECDH Au=RSA Enc=AESGCM(256) Mac=AEAD",
]
_SSL_CBC = "ECDHE-RSA-AES256-SHA384 TLSv1.2 Kx=ECDH Au=RSA Enc=AES(256) Mac=SHA384"

_HEALTHY_CNF = [("CipherString", "ECDHE+AESGCM+AES256:@SECLEVEL=2"), ("MinProtocol", "TLSv1.2")]


def _windows(
    monkeypatch: pytest.MonkeyPatch,
    suites: list[str] | Exception,
    enabled: Mapping[str, int | None] | Exception,
) -> CheckResult:
    def read_suites() -> list[str]:
        if isinstance(suites, Exception):
            raise suites
        return suites

    def read_enabled(version: str) -> int | None:
        if isinstance(enabled, Exception):
            raise enabled
        return enabled[version]

    monkeypatch.setattr(cipher_policy, "_windows_enabled_suites", read_suites)
    monkeypatch.setattr(cipher_policy, "_schannel_client_enabled", read_enabled)
    return cipher_policy.read_host_cipher_policy("win32")


def _linux(
    monkeypatch: pytest.MonkeyPatch,
    lines: list[str] | Exception,
    settings: list[tuple[str, str]] | Exception,
) -> CheckResult:
    def read_lines() -> list[str]:
        if isinstance(lines, Exception):
            raise lines
        return lines

    def read_settings() -> tuple[Path, list[tuple[str, str]]]:
        if isinstance(settings, Exception):
            raise settings
        return Path("/etc/ssl/openssl.cnf"), settings

    monkeypatch.setattr(cipher_policy, "_openssl_suites", read_lines)
    monkeypatch.setattr(cipher_policy, "_openssl_policy_lines", read_settings)
    return cipher_policy.read_host_cipher_policy("linux")


_OFF = {"TLS 1.0": 0, "TLS 1.1": 0}


# ---- Windows ----------------------------------------------------------------------------------


def test_windows_healthy_policy_passes(monkeypatch: pytest.MonkeyPatch) -> None:
    r = _windows(monkeypatch, _WIN_AEAD, _OFF)
    assert r.id == "host.ciphers"
    assert r.status is Status.PASS, r.detail
    assert "all 2 enabled suites are AEAD" in r.detail


def test_windows_cbc_suite_fails_and_is_named(monkeypatch: pytest.MonkeyPatch) -> None:
    r = _windows(monkeypatch, [*_WIN_AEAD, _WIN_CBC], _OFF)
    assert r.status is Status.FAIL
    assert "1 of 3 enabled suites are not AEAD" in r.detail
    assert _WIN_CBC in r.evidence
    assert "section 5.4" in r.detail


@pytest.mark.parametrize(
    ("enabled", "expect"),
    [
        ({"TLS 1.0": None, "TLS 1.1": 0}, "TLS 1.0 client Enabled is not set"),
        ({"TLS 1.0": 0, "TLS 1.1": 1}, "TLS 1.1 client Enabled=1"),
    ],
)
def test_windows_legacy_protocol_left_on_fails(
    monkeypatch: pytest.MonkeyPatch, enabled: dict[str, int | None], expect: str
) -> None:
    """An unset value is the stock host section 5.4 measured: it is not the asked-for 0."""
    r = _windows(monkeypatch, _WIN_AEAD, enabled)
    assert r.status is Status.FAIL
    assert expect in r.detail


def test_windows_empty_suite_list_is_not_a_pass(monkeypatch: pytest.MonkeyPatch) -> None:
    """The control is 0, so "no non-AEAD suite" says nothing, even with both protocols off."""
    r = _windows(monkeypatch, [], _OFF)
    assert r.status is Status.ERROR
    assert "control is 0" in r.detail


def test_windows_missing_powershell_is_manual(monkeypatch: pytest.MonkeyPatch) -> None:
    r = _windows(monkeypatch, ProbeUnavailable("powershell.exe not found"), _OFF)
    assert r.status is Status.MANUAL
    assert "powershell.exe not found" in r.detail


def test_windows_failed_probes_are_errors(monkeypatch: pytest.MonkeyPatch) -> None:
    r = _windows(monkeypatch, ProbeFailed("powershell.exe exited 1"), _OFF)
    assert r.status is Status.ERROR
    r = _windows(monkeypatch, _WIN_AEAD, ProbeFailed("TLS 1.0 client key could not be read"))
    assert r.status is Status.ERROR


def test_a_finding_outranks_a_broken_reading(monkeypatch: pytest.MonkeyPatch) -> None:
    r = _windows(monkeypatch, [_WIN_CBC], ProbeFailed("registry"))
    assert r.status is Status.FAIL
    assert "protocol switches not read" in r.detail


# ---- Linux ------------------------------------------------------------------------------------


def test_linux_healthy_policy_passes(monkeypatch: pytest.MonkeyPatch) -> None:
    r = _linux(monkeypatch, _SSL_AEAD, _HEALTHY_CNF)
    assert r.status is Status.PASS, r.detail
    assert "MinProtocol = TLSv1.2" in r.detail


def test_linux_non_aead_suite_fails_and_is_named(monkeypatch: pytest.MonkeyPatch) -> None:
    r = _linux(monkeypatch, [*_SSL_AEAD, _SSL_CBC], _HEALTHY_CNF)
    assert r.status is Status.FAIL
    assert "1 of 3 enabled suites are not AEAD" in r.detail
    assert r.evidence.startswith("not AEAD: ECDHE-RSA-AES256-SHA384")


def test_linux_empty_suite_list_is_not_a_pass(monkeypatch: pytest.MonkeyPatch) -> None:
    """Section 5.4: with no ``openssl`` the rig printed 0 for both counts. Zero needs its control."""
    r = _linux(monkeypatch, [], _HEALTHY_CNF)
    assert r.status is Status.ERROR
    assert "control is 0" in r.detail


@pytest.mark.parametrize(
    ("settings", "expect"),
    [
        ([("CipherString", "DEFAULT:@SECLEVEL=2")], "no MinProtocol line"),
        ([*_HEALTHY_CNF, ("MinProtocol", "TLSv1")], "MinProtocol = TLSv1, not TLSv1.2"),
        ([*_HEALTHY_CNF, ("CipherString", "DEFAULT")], "2 CipherString lines, not 1"),
        ([("MinProtocol", "TLSv1.3")], "0 CipherString lines, not 1"),
    ],
)
def test_linux_policy_file_findings_fail(
    monkeypatch: pytest.MonkeyPatch, settings: list[tuple[str, str]], expect: str
) -> None:
    r = _linux(monkeypatch, _SSL_AEAD, settings)
    assert r.status is Status.FAIL
    assert expect in r.detail


def test_linux_missing_openssl_is_manual(monkeypatch: pytest.MonkeyPatch) -> None:
    r = _linux(monkeypatch, ProbeUnavailable("openssl not found"), _HEALTHY_CNF)
    assert r.status is Status.MANUAL


def test_linux_missing_policy_file_is_manual(monkeypatch: pytest.MonkeyPatch) -> None:
    missing = FileNotFoundError(2, "No such file", "/etc/ssl/openssl.cnf")
    r = _linux(monkeypatch, _SSL_AEAD, missing)
    assert r.status is Status.MANUAL
    assert "confirm MinProtocol by hand" in r.detail


def test_policy_lines_read_the_openssl_conf_file(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """``OPENSSL_CONF`` names the file the ``openssl`` probe loads, so it is the one read."""
    cnf = tmp_path / "openssl.cnf"
    cnf.write_text(
        "[system_default_sect]\n"
        "# CipherString = commented out\n"
        "CipherString = ECDHE+AESGCM  # trailing comment\n"
        "  MinProtocol = TLSv1.2\n"
        "Options = ServerPreference\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("OPENSSL_CONF", str(cnf))
    path, settings = cipher_policy._openssl_policy_lines()
    assert path == cnf
    assert settings == [("CipherString", "ECDHE+AESGCM"), ("MinProtocol", "TLSv1.2")]


# ---- the probe runner and the platform gates --------------------------------------------------


def test_run_lines_reads_stdout_lines() -> None:
    out = cipher_policy._run_lines([sys.executable, "-c", "print('A'); print(); print(' B ')"])
    assert out == ["A", "B"]


def test_run_lines_missing_command_is_unavailable() -> None:
    with pytest.raises(ProbeUnavailable):
        cipher_policy._run_lines(["mefor-no-such-command-3277"])


def test_run_lines_nonzero_exit_fails_with_stderr() -> None:
    script = "import sys; sys.stderr.write('boom\\n'); sys.exit(3)"
    with pytest.raises(ProbeFailed, match="exited 3: boom"):
        cipher_policy._run_lines([sys.executable, "-c", script])


@pytest.mark.skipif(sys.platform != "win32", reason="reads the real SChannel registry keys")
def test_schannel_registry_read_returns_a_value_or_none() -> None:
    for version in ("TLS 1.0", "TLS 1.1"):
        value = cipher_policy._schannel_client_enabled(version)
        assert value is None or isinstance(value, int)


@pytest.mark.skipif(sys.platform == "win32", reason="the off-Windows branch")
def test_schannel_registry_read_is_unavailable_off_windows() -> None:
    with pytest.raises(ProbeUnavailable):
        cipher_policy._schannel_client_enabled("TLS 1.0")


def test_other_platforms_skip() -> None:
    assert cipher_policy.read_host_cipher_policy("darwin").status is Status.SKIP


def _hide_pyodbc(monkeypatch: pytest.MonkeyPatch) -> None:
    real = checks._can_import
    monkeypatch.setattr(checks, "_can_import", lambda module: module != "pyodbc" and real(module))


def test_no_odbc_driver_means_skip(monkeypatch: pytest.MonkeyPatch) -> None:
    """Without pyodbc no ODBC hop can run here, so the policy is not this host's concern."""

    def must_not_run(platform: str = sys.platform) -> CheckResult:
        raise AssertionError("the policy was read with no ODBC hop possible")

    _hide_pyodbc(monkeypatch)
    monkeypatch.setattr(cipher_policy, "read_host_cipher_policy", must_not_run)
    r = checks.check_host_cipher_policy()
    assert (r.id, r.status) == ("host.ciphers", Status.SKIP)


def test_odbc_driver_present_reads_the_policy(monkeypatch: pytest.MonkeyPatch) -> None:
    stub = CheckResult("host.ciphers", "t", Status.FAIL, "stub reading")
    monkeypatch.setattr(checks, "_can_import", lambda module: True)
    monkeypatch.setattr(cipher_policy, "read_host_cipher_policy", lambda: stub)
    assert checks.check_host_cipher_policy() is stub


def test_host_section_carries_the_row(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _hide_pyodbc(monkeypatch)
    results = checks.run_host_checks(ports={"MLLP": 2575}, writable_dir=tmp_path)
    assert "host.ciphers" in {r.id for r in results}


def test_only_verify_reads_the_policy() -> None:
    """Report only: owner ruling R3 declined a startup check, so no engine path may import this."""
    root = Path(cipher_policy.__file__).resolve().parents[1]
    importers = {
        p.relative_to(root).as_posix()
        for p in root.rglob("*.py")
        if "cipher_policy" in p.read_text(encoding="utf-8", errors="replace")
    }
    assert importers == {"verify/checks.py", "verify/cipher_policy.py"}
