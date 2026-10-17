# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""``host.ciphers``: DEPLOY-SERVER-DB.md section 5.4's host cipher checks, run by ``verify``.

The platform probes are stubbed, so both platform branches run on any OS. Each branch has a passing
and a failing policy reading, and the control-is-zero case, which must never read as a PASS. One
Windows-only test runs the real PowerShell command."""

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
from tests._ast_sites import callee_name, parse_source
from tests.test_dependency_boundaries import _modules_imported_by

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
    section: str | None = "system_default_sect",
) -> CheckResult:
    monkeypatch.setattr(cipher_policy, "_openssl_suites", lambda: _give(lines))
    monkeypatch.setattr(
        cipher_policy,
        "_openssl_policy_lines",
        lambda: (cipher_policy._OPENSSL_CNF, section, _give(settings)),
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
    ("raised", "status", "expect"),
    [
        (ProbeUnavailable("no registry"), Status.MANUAL, "Group Policy suite order not read (no"),
        (ProbeFailed("denied"), Status.ERROR, "Group Policy suite order not read: denied"),
    ],
)
def test_an_unread_group_policy_order_is_never_a_pass(
    monkeypatch: pytest.MonkeyPatch, raised: Exception, status: Status, expect: str
) -> None:
    """A healthy local table and both protocols off still leave the policy order unread."""
    r = _windows(monkeypatch, _WIN_AEAD, _OFF, order=raised)
    assert r.status is status, r.detail
    assert expect in r.detail


def _powershell_returns(
    monkeypatch: pytest.MonkeyPatch, returncode: int, stdout: str
) -> list[list[str]]:
    """Stub the PowerShell start; returns the argument lists it was called with."""
    calls: list[list[str]] = []

    def run(argv: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        calls.append(argv)
        return subprocess.CompletedProcess(argv, returncode, stdout=stdout, stderr="")

    monkeypatch.setattr(cipher_policy, "_system_exe", lambda *parts: "powershell.exe")
    monkeypatch.setattr(subprocess, "run", run)
    return calls


def test_suite_names_are_read_one_per_line(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = _powershell_returns(monkeypatch, 0, "TLS_AES_256_GCM_SHA384\n\n SSL_CK_RC4_X \n")
    assert cipher_policy._windows_enabled_suites() == ["TLS_AES_256_GCM_SHA384", "SSL_CK_RC4_X"]
    assert calls[0][-1] == cipher_policy._SUITES_COMMAND


def test_the_command_runs_the_system_tls_modules_own_cmdlet() -> None:
    """A ``Get-TlsCipherSuite`` on ``PATH`` or in the account's Documents modules must not answer:
    the module is imported by its ``$PSHOME`` path and its exported command object is run, so the
    name is never looked up through command discovery."""
    command = cipher_policy._SUITES_COMMAND
    assert "Import-Module -Name (Join-Path $PSHOME 'Modules\\TLS') -PassThru" in command
    assert "(& $m.ExportedCommands['Get-TlsCipherSuite']).Name" in command
    # Every mention of the name is inside a lookup on the imported module, never a bare call.
    assert command.count("Get-TlsCipherSuite") == command.count("ExportedCommands")


@pytest.mark.parametrize("odd", ["WARNING: module loaded late", "AVERTISSEMENT : x", "TLS AES"])
def test_a_line_that_is_not_a_suite_name_is_an_error(
    monkeypatch: pytest.MonkeyPatch, odd: str
) -> None:
    """Windows PowerShell 5.1 writes stream lines to a redirected stdout. One the command did not
    silence is neither counted as a suite nor dropped, since a dropped line could be a suite."""
    _powershell_returns(monkeypatch, 0, f"TLS_AES_256_GCM_SHA384\n{odd}\n")
    with pytest.raises(ProbeFailed, match="not a suite name"):
        cipher_policy._windows_enabled_suites()


def test_a_host_without_the_tls_cmdlet_is_manual(monkeypatch: pytest.MonkeyPatch) -> None:
    """No ``Get-TlsCipherSuite`` is an instrument missing from the host, not a failed reading."""
    _powershell_returns(monkeypatch, cipher_policy._NO_CMDLET_EXIT, "")
    with pytest.raises(ProbeUnavailable, match="Get-TlsCipherSuite not found"):
        cipher_policy._windows_enabled_suites()


def test_a_cmdlet_that_ran_and_failed_is_an_error(monkeypatch: pytest.MonkeyPatch) -> None:
    _powershell_returns(monkeypatch, 1, "")
    with pytest.raises(ProbeFailed, match="exited 1"):
        cipher_policy._windows_enabled_suites()


@pytest.mark.skipif(sys.platform != "win32", reason="runs the real Windows PowerShell")
def test_the_powershell_command_runs_on_this_host() -> None:
    """The guarded command parses and prints suite names on a host with stock suites, with the
    probe's own environment, so the stubs above match a real start: the module imported by its
    path, the cmdlet guard did not fire, and every line kept the suite-name shape."""
    assert cipher_policy._windows_enabled_suites()


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


def test_no_system_default_section_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    r = _linux(monkeypatch, _SSL_AEAD, [], section=None)
    assert r.status is Status.FAIL
    assert "no system-default section" in r.detail


#: The chain of the stock Ubuntu file, from the default section to the policy section.
_CHAIN = (
    "openssl_conf = openssl_init\n"
    "[openssl_init]\nssl_conf = ssl_sect\n"
    "[ssl_sect]\nsystem_default = system_default_sect\n"
)


def _point_openssl_conf_at(monkeypatch: pytest.MonkeyPatch, cnf: Path, text: str) -> None:
    cnf.write_text(text, encoding="utf-8")
    monkeypatch.setenv("OPENSSL_CONF", str(cnf))


def _read_cnf(
    monkeypatch: pytest.MonkeyPatch, cnf: Path, text: str
) -> tuple[Path, str | None, list[tuple[str, str]]]:
    _point_openssl_conf_at(monkeypatch, cnf, text)
    return cipher_policy._openssl_policy_lines()


def _linux_from_file(monkeypatch: pytest.MonkeyPatch, cnf: Path, text: str) -> CheckResult:
    """The whole Linux row over a real file, with the suite probe stubbed healthy."""
    _point_openssl_conf_at(monkeypatch, cnf, text)
    monkeypatch.setattr(cipher_policy, "_openssl_suites", lambda: _SSL_AEAD)
    return cipher_policy.read_host_cipher_policy("linux")


def test_policy_lines_read_the_openssl_conf_file(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """``OPENSSL_CONF`` names the file the ``openssl`` probe loads, so it is the one read."""
    cnf = tmp_path / "openssl.cnf"
    path, section, settings = _read_cnf(
        monkeypatch,
        cnf,
        _CHAIN + "[system_default_sect]\n"
        "# CipherString = commented out\n"
        "CipherString = ECDHE+AESGCM  # trailing comment\n"
        "  MinProtocol = TLSv1.2\n"
        "Options = ServerPreference\n"
        "minprotocol = TLSv1\n",
    )
    assert (path, section) == (cnf, "system_default_sect")
    # OpenSSL matches a command name without case, so the last line is the floor in effect.
    assert settings == [
        ("CipherString", "ECDHE+AESGCM"),
        ("MinProtocol", "TLSv1.2"),
        ("MinProtocol", "TLSv1"),
    ]


def test_policy_lines_come_from_the_section_openssl_applies(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Policy lines in another section are not applied, so they are not read. The chain may name
    any section, not only ``[system_default_sect]``."""
    _, section, settings = _read_cnf(
        monkeypatch,
        tmp_path / "openssl.cnf",
        "openssl_conf = init\n"
        "[ init ]\nssl_conf = ssl\n"
        "[ssl]\nsystem_default = tls_policy\n"
        "[system_default_sect]\nMinProtocol = TLSv1.3\nCipherString = HIGH\n"
        "[tls_policy]\nMinProtocol = TLSv1\n"
        "[client_sect]\nCipherString = DEFAULT\n",
    )
    assert section == "tls_policy"
    assert settings == [("MinProtocol", "TLSv1")]


def test_a_file_with_no_chain_has_no_policy_section(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Without ``openssl_conf``, OpenSSL applies none of the file's TLS lines."""
    text = "[system_default_sect]\nCipherString = ECDHE+AESGCM\nMinProtocol = TLSv1.2\n"
    assert _read_cnf(monkeypatch, tmp_path / "a.cnf", text)[1:] == (None, [])
    # The chain broken at its second link: ssl_conf names nothing.
    broken = "openssl_conf = init\n[init]\nproviders = p\n" + text
    assert _read_cnf(monkeypatch, tmp_path / "b.cnf", broken)[1:] == (None, [])


@pytest.mark.parametrize(
    ("raw", "value"),
    [
        ('"TLSv1.2"', "TLSv1.2"),
        ("'TLSv1.2'  # quoted", "TLSv1.2"),
        ('"DEFAULT:#x" # comment', "DEFAULT:#x"),
        (r"a\#b", "a#b"),
        ('" spaced "  ', " spaced "),
        ("TLSv1.2   ", "TLSv1.2"),
        ("", ""),
    ],
)
def test_config_values_are_read_as_openssl_reads_them(raw: str, value: str) -> None:
    assert cipher_policy._config_value(raw) == value


_HEALTHY_SECTION = "[system_default_sect]\nCipherString = ECDHE+AESGCM\nMinProtocol = TLSv1.2\n"


@pytest.mark.parametrize(
    ("text", "construct"),
    [
        (_CHAIN + _HEALTHY_SECTION + ".include /etc/ssl/more.cnf\n", ".include"),
        (".include = /etc/ssl/more.cnf\n" + _CHAIN + _HEALTHY_SECTION, ".include"),
        (".pragma dollarid:on\n" + _CHAIN + _HEALTHY_SECTION, ".pragma"),
        (_CHAIN + _HEALTHY_SECTION + "Options = A,\\\n  B\n", "a line continued"),
        (_CHAIN + _HEALTHY_SECTION + "MinProtocol = $floor\n", "$ variable expansion"),
        (_CHAIN.replace("ssl_sect\n[", "$name\n[") + _HEALTHY_SECTION, "$ variable expansion"),
        (
            _CHAIN + _HEALTHY_SECTION + "[other]\nsystem_default_sect::MinProtocol = TLSv1\n",
            "section::name",
        ),
        ("﻿.include /etc/ssl/more.cnf\n" + _CHAIN + _HEALTHY_SECTION, ".include"),
    ],
)
def test_a_file_using_what_the_check_does_not_follow_is_manual(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, text: str, construct: str
) -> None:
    """Each can change the lines OpenSSL applies, so the row must never PASS on what it read."""
    cnf = tmp_path / "openssl.cnf"
    r = _linux_from_file(monkeypatch, cnf, text)
    assert r.status is Status.MANUAL, r.detail
    assert construct in r.detail
    assert str(cnf) in r.detail


def test_a_dollar_outside_the_read_lines_is_not_refused(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """The stock Ubuntu file uses ``$dir`` in its CA sections, which the TLS policy never reads."""
    text = "HOME = .\n" + _CHAIN + _HEALTHY_SECTION + "[CA_default]\ncerts = $dir/certs\n"
    assert _read_cnf(monkeypatch, tmp_path / "openssl.cnf", text)[1] == "system_default_sect"
    # Ciphersuites is evidence only, so a $ there does not stop the verdict.
    r = _linux_from_file(monkeypatch, tmp_path / "b.cnf", text + "Ciphersuites = $tls13\n")
    assert r.status is Status.PASS, r.detail


def test_a_byte_order_mark_is_dropped_as_openssl_drops_it(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A BOM before ``openssl_conf`` must not break the chain into a false FAIL."""
    text = "﻿" + _CHAIN + _HEALTHY_SECTION
    assert _read_cnf(monkeypatch, tmp_path / "openssl.cnf", text)[1] == "system_default_sect"


def test_an_empty_openssl_conf_is_manual(monkeypatch: pytest.MonkeyPatch) -> None:
    """``openssl`` gets the empty name, so the file it read is not known; the system file is not
    read in its place."""
    monkeypatch.setenv("OPENSSL_CONF", "")
    monkeypatch.setattr(cipher_policy, "_openssl_suites", lambda: _SSL_AEAD)
    r = cipher_policy.read_host_cipher_policy("linux")
    assert r.status is Status.MANUAL, r.detail
    assert "OPENSSL_CONF is set but empty" in r.detail


def test_a_quoted_min_protocol_passes(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    r = _linux_from_file(
        monkeypatch,
        tmp_path / "openssl.cnf",
        _CHAIN + '[system_default_sect]\nCipherString = "ECDHE+AESGCM"\nMinProtocol = "TLSv1.2"\n',
    )
    assert r.status is Status.PASS, r.detail


def test_without_openssl_conf_the_system_file_is_read(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    cnf = tmp_path / "system.cnf"
    cnf.write_text(_CHAIN + "[system_default_sect]\nMinProtocol = TLSv1.2\n", encoding="utf-8")
    monkeypatch.delenv("OPENSSL_CONF", raising=False)
    monkeypatch.setattr(cipher_policy, "_OPENSSL_CNF", cnf)
    assert cipher_policy._openssl_policy_lines() == (
        cnf,
        "system_default_sect",
        [("MinProtocol", "TLSv1.2")],
    )


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


def _reaches_the_probe(tree: ast.AST, package: str) -> bool:
    """Whether code under ``tree``, in a file of the dotted ``package``, imports a probe module:
    by an absolute or relative import, or by ``import_module`` or ``__import__`` given its name as
    a literal."""
    if _modules_imported_by(tree, package, with_names=True) & _PROBE_MODULES:
        return True
    return any(
        isinstance(node, ast.Call)
        and callee_name(node) in {"import_module", "__import__"}
        and bool(node.args)
        and isinstance(node.args[0], ast.Constant)
        and node.args[0].value in _PROBE_MODULES
        for node in ast.walk(tree)
    )


def test_only_the_verify_command_reaches_the_policy() -> None:
    """Report only: owner ruling R3 declined a startup check. Outside ``verify/``, the only import
    of a module whose functions run the probe is in the ``verify`` subcommand's own handler.

    That is not "the probe module is never loaded elsewhere". ``messagefoundry/verify/__init__.py``
    imports the runner, so importing any ``messagefoundry.verify`` submodule, as the ``check``
    gate's federation import does, loads ``cipher_policy`` too. Loading it runs no probe, and a
    call through the loaded package by attribute is outside what this test sees.

    Nor does it see a module name built at run time, a module reached through an attribute of one
    already imported, or a plugin entry point. A file whose text never says ``verify`` is skipped,
    since every import the detector sees names it."""
    root = Path(cipher_policy.__file__).resolve().parents[2]
    reachers: set[tuple[str, str]] = set()
    for package in ("messagefoundry", "messagefoundry_webconsole", "messagefoundry_toolkit"):
        for path in (root / package).rglob("*.py"):
            rel = path.relative_to(root)
            if rel.as_posix().startswith("messagefoundry/verify/"):
                continue
            text = path.read_text(encoding="utf-8")
            if "verify" not in text:
                continue
            dotted = ".".join(rel.parent.parts)  # an __init__.py sits in its own package
            for top in parse_source(text).body:
                if _reaches_the_probe(top, dotted):
                    reachers.add((rel.as_posix(), getattr(top, "name", "<module>")))
    assert reachers == {("messagefoundry/__main__.py", "_verify")}


@pytest.mark.parametrize(
    ("source", "package"),
    [
        ("from messagefoundry.verify.runner import run_verify", ""),
        ("from messagefoundry.verify import checks", ""),
        ("import messagefoundry.verify.cipher_policy", ""),
        ("from .verify import runner", "messagefoundry"),
        ("from ..verify.checks import run_host_checks", "messagefoundry.api"),
        ("from .. import verify", "messagefoundry.api"),
        ("importlib.import_module('messagefoundry.verify.checks')", ""),
        ("__import__('messagefoundry.verify')", ""),
    ],
)
def test_the_reach_detector_fires(source: str, package: str) -> None:
    assert _reaches_the_probe(ast.parse(source), package)


@pytest.mark.parametrize(
    ("source", "package"),
    [
        ("from messagefoundry.verify.model import Status", ""),
        ("from .verify.model import Status", "messagefoundry"),
        ("from . import checks", "messagefoundry"),
        ("importlib.import_module('messagefoundry.verify.model')", ""),
    ],
)
def test_the_reach_detector_spares_other_modules(source: str, package: str) -> None:
    assert not _reaches_the_probe(ast.parse(source), package)
