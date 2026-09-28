# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The R4 (a) forwarding start-gate predicate (BACKLOG #1966, ADR 0200, ASVS 16.4.3).

The predicate passes only verified TLS to a non-loopback collector, and reads configuration alone.
"""

from __future__ import annotations

import socket
from pathlib import Path
from typing import Any

import pytest

from messagefoundry.config.settings import LoggingSettings, forwarding_gate_refusal


def _log(**kwargs: Any) -> LoggingSettings:
    return LoggingSettings(**kwargs)


def _verified(tmp_path: Path, host: str = "siem.example.org") -> LoggingSettings:
    ca = tmp_path / "ca.pem"
    ca.write_text("placeholder; the predicate never opens it\n")
    return _log(forward_host=host, forward_protocol="tls", forward_tls_ca_file=str(ca))


def test_verified_tls_to_a_remote_collector_passes(tmp_path: Path) -> None:
    assert forwarding_gate_refusal(_verified(tmp_path)) is None


@pytest.mark.parametrize(
    ("settings", "needle"),
    [
        ({}, "no off-box collector"),
        ({"forward_host": "siem.example.org", "forward_enabled": False}, "no off-box collector"),
        ({"forward_host": "siem.example.org"}, "'udp', not 'tls'"),
        ({"forward_host": "siem.example.org", "forward_protocol": "tcp"}, "'tcp', not 'tls'"),
        (
            {
                "forward_host": "siem.example.org",
                "forward_protocol": "tls",
                "forward_tls_verify": False,
            },
            "not authenticated",
        ),
    ],
)
def test_anything_short_of_verified_tls_is_refused(settings: dict[str, Any], needle: str) -> None:
    reason = forwarding_gate_refusal(_log(**settings))
    assert reason is not None and needle in reason


@pytest.mark.parametrize(
    "host",
    [
        "127.0.0.1",
        "127.8.9.10",
        "localhost",
        "::1",
        "0.0.0.0",
        "::",
        "localhost.",
        "LOCALHOST",
        "127.1",
    ],
)
def test_a_loopback_collector_is_refused_even_over_verified_tls(tmp_path: Path, host: str) -> None:
    reason = forwarding_gate_refusal(_verified(tmp_path, host=host))
    assert reason is not None and "loopback" in reason


def test_an_attested_plaintext_hop_does_not_pass_the_gate() -> None:
    """``forward_hop_attested`` answers a different question and must not answer this one."""
    reason = forwarding_gate_refusal(
        _log(
            forward_host="siem.example.org",
            forward_protocol="tcp",
            forward_hop_attested=True,
            forward_hop_attested_reason="an IPsec tunnel covers the hop",
        )
    )
    assert reason is not None and "not 'tls'" in reason


def test_the_gate_opens_no_connection_and_resolves_no_name(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Keyed on configuration, so a down collector cannot block a start through it. Any socket or
    name lookup during the check fails the test."""
    settings = _verified(tmp_path)

    def _no_network(*args: Any, **kwargs: Any) -> Any:
        raise AssertionError("the forwarding gate touched the network")

    monkeypatch.setattr(socket, "socket", _no_network)
    monkeypatch.setattr(socket, "create_connection", _no_network)
    monkeypatch.setattr(socket, "getaddrinfo", _no_network)
    monkeypatch.setattr(socket, "gethostbyname", _no_network)
    assert forwarding_gate_refusal(settings) is None
    assert forwarding_gate_refusal(_log()) is not None


# --- the gate wired into serve ------------------------------------------------------------------

_SAMPLES_CONFIG = Path(__file__).resolve().parents[1] / "samples" / "config"


def _serve(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, extra: str = "", *, forwarding: bool
) -> int:
    """A prod-PHI serve with every OTHER gate pre-cleared, so only forwarding decides it."""
    from messagefoundry.__main__ import main
    from tests._phi_gate_provisions import (
        PHI_GATE_PROVISIONS_TOML,
        make_syslog_ca_and_crl,
        setenv_retention_windows,
        setenv_verified_log_forwarding,
    )

    monkeypatch.chdir(tmp_path)
    setenv_retention_windows(monkeypatch)
    if forwarding:
        setenv_verified_log_forwarding(monkeypatch, make_syslog_ca_and_crl(tmp_path))
    (tmp_path / "messagefoundry.toml").write_text(
        PHI_GATE_PROVISIONS_TOML + extra, encoding="utf-8"
    )
    monkeypatch.setattr("messagefoundry.api.create_managed_app", lambda **kw: object())
    monkeypatch.setattr("uvicorn.run", lambda *a, **k: None)
    return main(["serve", "--config", str(_SAMPLES_CONFIG), "--env", "prod"])


def test_serve_refuses_a_phi_start_with_no_verified_forwarding(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    assert _serve(tmp_path, monkeypatch, forwarding=False) == 2
    err = capsys.readouterr().err
    assert "refusing to start" in err and "ASVS 16.4.3" in err and "no off-box collector" in err
    # The fix text names everything the NEXT gate would ask for, so following it does not just
    # move the operator to the #1498 revocation refusal; and it offers no loopback agent.
    assert "forward_tls_crl_file" in err and "6514" in err
    assert "let a local agent" not in err


def test_a_refused_start_opens_no_spool_and_contacts_no_collector(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The gate runs before configure_logging, so a start it refuses never builds the forwarder."""
    from messagefoundry import __main__ as main_module

    def _must_not_run(*args: Any, **kwargs: Any) -> bool:
        raise AssertionError("configure_logging ran for a start the #1966 gate refuses")

    monkeypatch.setattr(main_module, "configure_logging", _must_not_run)
    # A loopback UDP collector: the #200 hop gate allows it, so only #1966 decides the start.
    extra = '[logging]\nforward_host = "127.0.0.1"\nforward_protocol = "udp"\n'
    assert _serve(tmp_path, monkeypatch, extra, forwarding=False) == 2
    assert "ASVS 16.4.3" in capsys.readouterr().err
    assert not (tmp_path / "log-spool").exists()


def test_serve_starts_with_verified_forwarding_to_a_collector_that_is_down(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The pass, and the ruling's key property in one: the collector does not exist (a reserved
    name that never resolves), and the start still succeeds, because the gate reads configuration
    only. The forwarder reports the collector itself at ERROR and runs without it."""
    assert _serve(tmp_path, monkeypatch, forwarding=True) == 0
    captured = capsys.readouterr()
    assert "ASVS 16.4.3" not in captured.err
    assert "failed permanently" in captured.out  # the collector really was unreachable


def test_serve_under_warn_warns_instead_of_refusing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    extra = 'security.enforcement = "warn"\n'
    assert _serve(tmp_path, monkeypatch, extra, forwarding=False) == 0
    assert "does not forward its logs off-box over verified TLS" in capsys.readouterr().err
