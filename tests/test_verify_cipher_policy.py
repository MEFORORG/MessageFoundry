# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""``host.ciphers``: DEPLOY-SERVER-DB.md section 5.4's host cipher checks, run by ``verify``.

The platform probes are stubbed, so both platform branches run on any OS. Each branch has a passing
and a failing policy reading, and the control-is-zero case, which must never read as a PASS."""

from __future__ import annotations

import ast
import subprocess
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


def _give[T](value: T | Exception) -> T:
    if isinstance(value, Exception):
        raise value
    return value


def _windows(
    monkeypatch: pytest.MonkeyPatch,
    suites: list[str] | Exception,
    enabled: Mapping[str, int | None | Exception] | Exception,
    order: list[str] | None | Exception = None,
) -> CheckResult:
    monkeypatch.setattr(cipher_policy, "_windows_enabled_suites", lambda: _give(suites))
    monkeypatch.setattr(
        cipher_policy, "_schannel_client_enabled", lambda v: _give(_give(enabled)[v])
    )
    monkeypatch.setattr(cipher_policy, "_schannel_policy_order", lambda: _give(order))
    return cipher_policy.read_host_cipher_policy("win32")


def _linux(
    monkeypatch: pytest.MonkeyPatch,
    lines: list[str] | Exception,
    settings: list[tuple[str, str]] | Exception,
) -> CheckResult:
    monkeypatch.setattr(cipher_policy, "_openssl_suites", lambda: _give(lines))
    monkeypatch.setattr(
        cipher_policy,
        "_openssl_policy_lines",
        lambda: (cipher_policy._OPENSSL_CNF, _give(settings)),
    )
    return cipher_policy.read_host_cipher_policy("linux")


_OFF = dict.fromkeys(cipher_policy._LEGACY_VERSIONS, 0)


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
    assert "TLS 1.0 client Enabled not read" in r.detail


def test_a_broken_read_keeps_the_other_versions_finding(monkeypatch: pytest.MonkeyPatch) -> None:
    """TLS 1.0 left on, then the TLS 1.1 key unreadable: the TLS 1.0 finding must survive."""
    enabled: dict[str, int | None | Exception] = {"TLS 1.0": 1, "TLS 1.1": ProbeFailed("denied")}
    r = _windows(monkeypatch, _WIN_AEAD, enabled)
    assert r.status is Status.FAIL
    assert "TLS 1.0 client Enabled=1" in r.detail
    assert "TLS 1.1 client Enabled not read: denied" in r.detail


@pytest.mark.parametrize(
    ("order", "status"),
    [(_WIN_AEAD, Status.PASS), ([*_WIN_AEAD, _WIN_CBC], Status.FAIL), ([], Status.ERROR)],
)
def test_a_group_policy_suite_order_is_checked_too(
    monkeypatch: pytest.MonkeyPatch, order: list[str], status: Status
) -> None:
    """A trimmed local table must not read as a PASS beneath a policy that still lists CBC."""
    r = _windows(monkeypatch, _WIN_AEAD, _OFF, order=order)
    assert r.status is status, r.detail
    assert "Group Policy suite-order suites" in r.detail


@pytest.mark.parametrize(
    ("found", "expect"),
    [
        (None, None),
        (("A, B,,C", 1), ["A", "B", "C"]),
        ((["A", " B "], 7), ["A", "B"]),
    ],
)
def test_policy_order_parses_both_string_forms(
    monkeypatch: pytest.MonkeyPatch, found: tuple[object, int] | None, expect: list[str] | None
) -> None:
    monkeypatch.setattr(cipher_policy, "_hklm_value", lambda subkey, name: found)
    assert cipher_policy._schannel_policy_order() == expect


def test_policy_order_of_another_type_is_a_failed_read(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(cipher_policy, "_hklm_value", lambda subkey, name: (5, 4))
    with pytest.raises(ProbeFailed, match="registry type 4"):
        cipher_policy._schannel_policy_order()


# ---- Linux ------------------------------------------------------------------------------------


def test_linux_healthy_policy_passes(monkeypatch: pytest.MonkeyPatch) -> None:
    r = _linux(monkeypatch, _SSL_AEAD, _HEALTHY_CNF)
    assert r.status is Status.PASS, r.detail
    assert "MinProtocol = TLSv1.2" in r.detail


def test_linux_non_aead_suite_fails_and_is_named(monkeypatch: pytest.MonkeyPatch) -> None:
    r = _linux(monkeypatch, [*_SSL_AEAD, _SSL_CBC], _HEALTHY_CNF)
    assert r.status is Status.FAIL
    assert "1 of 3 enabled suites are not AEAD" in r.detail
    assert r.evidence.startswith("not AEAD in the enabled suites: ECDHE-RSA-AES256-SHA384")


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
        "Options = ServerPreference\n"
        "minprotocol = TLSv1\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("OPENSSL_CONF", str(cnf))
    path, settings = cipher_policy._openssl_policy_lines()
    assert path == cnf
    # OpenSSL matches a command name without case, so the last line is the floor in effect.
    assert settings == [
        ("CipherString", "ECDHE+AESGCM"),
        ("MinProtocol", "TLSv1.2"),
        ("MinProtocol", "TLSv1"),
    ]


# ---- the probe runner and the platform gates --------------------------------------------------


def test_stdout_lines_drops_blank_lines() -> None:
    done = subprocess.CompletedProcess([], 0, stdout="A\n\n B \n", stderr="")
    assert cipher_policy._stdout_lines("tool", done) == ["A", "B"]


def test_stdout_lines_nonzero_exit_fails_with_stderr() -> None:
    done = subprocess.CompletedProcess([], 3, stdout="A\n", stderr="\nboom\n")
    with pytest.raises(ProbeFailed, match="tool exited 3: boom"):
        cipher_policy._stdout_lines("tool", done)


@pytest.mark.parametrize(
    ("raised", "expect"),
    [
        (FileNotFoundError(2, "missing"), ProbeUnavailable),
        (subprocess.TimeoutExpired(["tool"], 30), ProbeFailed),
        (PermissionError(13, "denied"), ProbeFailed),
    ],
)
def test_probe_errors_map_a_failed_start(raised: Exception, expect: type[Exception]) -> None:
    with pytest.raises(expect, match="tool"), cipher_policy._probe_errors("tool"):
        raise raised


@pytest.mark.skipif(sys.platform != "win32", reason="reads the real SChannel registry keys")
def test_schannel_registry_read_returns_a_value_or_none() -> None:
    for version in cipher_policy._LEGACY_VERSIONS:
        value = cipher_policy._schannel_client_enabled(version)
        assert value is None or isinstance(value, int)


@pytest.mark.skipif(sys.platform == "win32", reason="the off-Windows branch")
def test_schannel_registry_read_is_unavailable_off_windows() -> None:
    with pytest.raises(ProbeUnavailable):
        cipher_policy._schannel_client_enabled("TLS 1.0")


def test_other_platforms_skip() -> None:
    assert cipher_policy.read_host_cipher_policy("darwin").status is Status.SKIP


def test_the_default_platform_is_read_at_call_time(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(sys, "platform", "darwin")
    assert cipher_policy.read_host_cipher_policy().detail.endswith("not darwin")


def _hide_pyodbc(monkeypatch: pytest.MonkeyPatch) -> None:
    real = checks._can_import
    monkeypatch.setattr(checks, "_can_import", lambda module: module != "pyodbc" and real(module))


def test_no_odbc_driver_means_skip(monkeypatch: pytest.MonkeyPatch) -> None:
    """Without pyodbc no ODBC hop can run here, so the policy is not this host's concern."""

    def must_not_run(platform: str | None = None) -> CheckResult:
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


#: Modules that can reach the probe: the verify package itself and the ones it calls through.
_PROBE_MODULES = frozenset(
    {
        "messagefoundry.verify",
        "messagefoundry.verify.runner",
        "messagefoundry.verify.checks",
        "messagefoundry.verify.cipher_policy",
    }
)


def _reaches_the_probe(node: ast.AST) -> bool:
    if isinstance(node, ast.ImportFrom):
        names = {f"{node.module}.{alias.name}" for alias in node.names}
        return node.module in _PROBE_MODULES or bool(names & _PROBE_MODULES)
    return isinstance(node, ast.Import) and any(a.name in _PROBE_MODULES for a in node.names)


def test_only_the_verify_command_reaches_the_policy() -> None:
    """Report only: owner ruling R3 declined a startup check. Outside ``verify/``, the only import
    of a module that runs the probe is in the ``verify`` subcommand's own handler."""
    root = Path(cipher_policy.__file__).resolve().parents[2]
    reachers: set[tuple[str, str]] = set()
    for package in ("messagefoundry", "messagefoundry_webconsole", "messagefoundry_toolkit"):
        for path in (root / package).rglob("*.py"):
            rel = path.relative_to(root).as_posix()
            if rel.startswith("messagefoundry/verify/"):
                continue
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for top in tree.body:
                name = getattr(top, "name", "<module>")
                if any(_reaches_the_probe(node) for node in ast.walk(top)):
                    reachers.add((rel, name))
    assert reachers == {("messagefoundry/__main__.py", "_verify")}


def test_the_reach_detector_fires() -> None:
    assert _reaches_the_probe(
        ast.parse("from messagefoundry.verify.runner import run_verify").body[0]
    )
    assert _reaches_the_probe(ast.parse("from messagefoundry.verify import checks").body[0])
    assert _reaches_the_probe(ast.parse("import messagefoundry.verify.cipher_policy").body[0])
    assert not _reaches_the_probe(
        ast.parse("from messagefoundry.verify.model import Status").body[0]
    )
