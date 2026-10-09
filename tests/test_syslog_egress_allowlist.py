# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""``[egress].allowed_syslog`` governs the off-box log forwarder's collector (BACKLOG #2356).

``[logging].forward_host`` was an outbound destination no ``[egress]`` list covered. The list has
the raw-TCP list's grammar and its empty-list rule, and ``serve`` and ``supervise`` check it at
start, before the forwarder opens a socket.

No test here opens a socket or resolves a name; the harness is the supervisor forwarding suite's.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from messagefoundry.config.models import ConnectorType, Destination
from messagefoundry.config.settings import EgressSettings, ServiceSettings
from messagefoundry.config.wiring import WiringError
from messagefoundry.transports.egress import check_egress_allowed, syslog_forward_refusal
from tests._phi_gate_provisions import PHI_GATE_PROVISIONS_TOML, VERIFIED_LOG_FORWARDING_HOST
from tests.test_supervisor_log_forwarding import _errors, _run

_HOST = "siem.example.org"
_ENV = "MEFOR_EGRESS_ALLOWED_SYSLOG"


# --- the predicate ------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "allowed",
    [
        pytest.param([_HOST], id="host-any-port"),
        pytest.param([f"{_HOST}:6514"], id="host-and-port"),
        pytest.param(["other.example.org", "SIEM.Example.ORG:6514"], id="second-entry-any-case"),
    ],
)
def test_a_listed_collector_passes(allowed: list[str]) -> None:
    assert syslog_forward_refusal(_HOST, 6514, EgressSettings(allowed_syslog=allowed)) is None


@pytest.mark.parametrize(
    "allowed",
    [
        pytest.param(["other.example.org"], id="another-host"),
        pytest.param([f"{_HOST}:514"], id="another-port"),
        pytest.param([f"sub.{_HOST}"], id="a-subdomain-is-not-the-host"),
    ],
)
@pytest.mark.parametrize("deny_by_default", [True, False])
def test_a_collector_off_a_set_list_is_refused(allowed: list[str], deny_by_default: bool) -> None:
    """A set list refuses whichever way the deny switch is written."""
    egress = EgressSettings(allowed_syslog=allowed, deny_by_default=deny_by_default)
    reason = syslog_forward_refusal(_HOST, 6514, egress)
    assert reason == (
        f"the syslog collector [logging].forward_host {_HOST!r} port 6514 is not in the "
        "[egress].allowed_syslog allowlist"
    )


def test_an_empty_list_refuses_under_the_deny_default() -> None:
    """Unset is the empty list, and the model default is deny."""
    assert EgressSettings().allowed_syslog == [] and EgressSettings().deny_by_default is True
    reason = syslog_forward_refusal(_HOST, 6514, EgressSettings())
    assert reason is not None
    assert "[security].block_unlisted_outbound is in force" in reason
    assert "[egress].allowed_syslog is empty" in reason and repr(_HOST) in reason


def test_an_empty_list_is_unrestricted_under_the_opt_out() -> None:
    assert syslog_forward_refusal(_HOST, 6514, EgressSettings(deny_by_default=False)) is None


def test_the_list_loads_from_one_comma_separated_environment_value(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(_ENV, f"{_HOST}:6514, backup.example.org")
    from messagefoundry.config.settings import load_settings

    egress = load_settings(config_path=None).egress
    assert egress.allowed_syslog == [f"{_HOST}:6514", "backup.example.org"]


# --- the sibling lists are unaffected -----------------------------------------------------------


def test_no_other_list_permits_the_collector() -> None:
    """A host on every destination list is still refused as a collector."""
    everywhere = EgressSettings(
        allowed_mllp=[_HOST],
        allowed_tcp=[_HOST],
        allowed_http=[_HOST],
        allowed_db=[_HOST],
        allowed_remote=[_HOST],
        allowed_smtp=[_HOST],
        allowed_direct=[_HOST],
        allowed_proxy=[_HOST],
    )
    assert syslog_forward_refusal(_HOST, 6514, everywhere) is not None


def test_the_syslog_list_permits_no_connection() -> None:
    """Listing a collector opens no message destination: a raw-TCP outbound to the same host and
    port is still refused, and passes once it is on its own list."""
    dest = Destination(name="OB_T", type=ConnectorType.TCP, settings={"host": _HOST, "port": 6514})
    with pytest.raises(WiringError, match="no allowlist permits a tcp destination"):
        check_egress_allowed(dest, EgressSettings(allowed_syslog=[_HOST]))
    check_egress_allowed(dest, EgressSettings(allowed_syslog=[_HOST], allowed_tcp=[_HOST]))


# --- the check wired into serve and supervise ---------------------------------------------------


@pytest.mark.parametrize("command", ["serve", "supervise"])
def test_a_collector_outside_the_list_is_refused_at_start(
    command: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    rc, recorder = _run(
        command, tmp_path, monkeypatch, verified_forwarding=True, allowed_syslog="other.example.org"
    )
    assert rc == 2
    assert _errors(capsys.readouterr().err) == [
        f"error: the syslog collector [logging].forward_host {VERIFIED_LOG_FORWARDING_HOST!r} "
        "port 514 is not in the [egress].allowed_syslog allowlist; refusing to start. List the "
        "collector in [egress].allowed_syslog as 'host' (any port) or 'host:port'."
    ]
    assert recorder.forwards == [], "a forwarder was installed for a refused collector"
    assert recorder.spawned == 0


@pytest.mark.parametrize("command", ["serve", "supervise"])
def test_an_unset_list_is_refused_at_start_under_the_deny_default(
    command: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    rc, recorder = _run(
        command, tmp_path, monkeypatch, verified_forwarding=True, allowed_syslog=None
    )
    assert rc == 2
    errors = _errors(capsys.readouterr().err)
    assert len(errors) == 1 and "[egress].allowed_syslog is empty" in errors[0], errors
    assert errors[0].endswith(
        "refusing to start. List the collector in [egress].allowed_syslog as 'host' (any port) "
        "or 'host:port'."
    )
    assert recorder.forwards == [] and recorder.spawned == 0


@pytest.mark.parametrize("command", ["serve", "supervise"])
def test_a_listed_collector_starts(
    command: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The control for the two refusals above: the same fixture with the collector listed."""
    rc, recorder = _run(command, tmp_path, monkeypatch, verified_forwarding=True)
    assert rc == 0
    assert [forward.host for forward in recorder.forwards] == [VERIFIED_LOG_FORWARDING_HOST]


#: The fixture's provisions with the deny switch written off. One destination list is set, because
#: `serve` refuses the opt-out with none (the open-egress gate, not this one).
_OPTED_OUT_TOML = PHI_GATE_PROVISIONS_TOML.replace(
    "security.block_unlisted_outbound = true\n",
    'security.block_unlisted_outbound = false\negress.allowed_mllp = ["receiver.invalid:6661"]\n',
)


@pytest.mark.parametrize("command", ["serve", "supervise"])
def test_an_unset_list_starts_under_the_opt_out(
    command: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    assert _OPTED_OUT_TOML != PHI_GATE_PROVISIONS_TOML
    assert (
        ServiceSettings().egress.deny_by_default is True
    )  # so the opt-out below is doing the work
    rc, recorder = _run(
        command,
        tmp_path,
        monkeypatch,
        verified_forwarding=True,
        allowed_syslog=None,
        provisions=_OPTED_OUT_TOML,
    )
    assert rc == 0
    assert len(recorder.forwards) == 1


def test_the_syslog_list_does_not_satisfy_the_open_egress_start_gate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """It names no message destination, so `serve` still refuses an instance that lists nothing
    else and has not written the deny switch."""
    provisions = PHI_GATE_PROVISIONS_TOML.replace("security.block_unlisted_outbound = true\n", "")
    assert provisions != PHI_GATE_PROVISIONS_TOML
    rc, _ = _run("serve", tmp_path, monkeypatch, verified_forwarding=True, provisions=provisions)
    assert rc == 2
    assert "no outbound destination is declared" in capsys.readouterr().err
