# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The R4 (a) forwarding start-gate predicate (BACKLOG #1966, ADR 0200, ASVS 16.4.3).

The predicate passes only verified TLS to a non-loopback collector that is not this host's own name
or address. It reads configuration and local host state, sends no packet and resolves no name.
"""

from __future__ import annotations

import ipaddress
import socket
from pathlib import Path
from typing import Any

import pytest

from messagefoundry.config import settings as settings_module
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
    name lookup during the check fails the test.

    This holds for a collector given BY NAME, which is what this test uses. An IP-literal collector
    does open one unsent UDP socket for the own-address check; the test after the next section
    holds that path to no resolver call and no connection."""
    settings = _verified(tmp_path)

    def _no_network(*args: Any, **kwargs: Any) -> Any:
        raise AssertionError("the forwarding gate touched the network")

    monkeypatch.setattr(socket, "socket", _no_network)
    monkeypatch.setattr(socket, "create_connection", _no_network)
    monkeypatch.setattr(socket, "getaddrinfo", _no_network)
    monkeypatch.setattr(socket, "gethostbyname", _no_network)
    assert forwarding_gate_refusal(settings) is None
    assert forwarding_gate_refusal(_log()) is not None


# --- this host's own name and addresses (vault BACKLOG #2375) -----------------------------------
#
# Most tests below inject the host's identity, so they read no runner state. At least three run the
# REAL OS name and probe, and each is written so its answer is the same on any host: the
# address-collector test (a documentation address no host holds), the loopback probe test, and the
# odd-host-text test (text that is no host's name). They need a working socket layer.

_OWN_V4 = "10.20.30.40"
_OWN_V6 = "2001:db8::40"


def _as_this_host(
    monkeypatch: pytest.MonkeyPatch, *, names: tuple[str, ...] = (), addresses: tuple[str, ...] = ()
) -> None:
    """Make the gate see a host with these names, holding these addresses. Any other address is
    reached FROM the first one, as a real routing table answers for a remote destination."""
    own = [ipaddress.ip_address(a) for a in addresses]

    def source(addr: Any) -> Any:
        if addr in own:
            return addr
        return next((a for a in own if a.version == addr.version), None)

    monkeypatch.setattr(settings_module, "_own_host_names", lambda: frozenset(names))
    monkeypatch.setattr(settings_module, "_local_source_address", source)


@pytest.mark.parametrize(
    "host",
    [_OWN_V4, _OWN_V6, f"[{_OWN_V6}]", f"::ffff:{_OWN_V4}", "eng1", "ENG1.", "eng1.corp.test"],
)
def test_a_collector_at_this_hosts_own_name_or_address_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, host: str
) -> None:
    """The defect: the gate refused loopback only, so the engine's own LAN address passed."""
    _as_this_host(monkeypatch, names=("eng1.corp.test", "eng1"), addresses=(_OWN_V4, _OWN_V6))
    reason = forwarding_gate_refusal(_verified(tmp_path, host=host))
    assert reason is not None and "own name or one of its own addresses" in reason


@pytest.mark.parametrize("host", ["10.20.30.41", "2001:db8::41", "siem.corp.test", "eng10"])
def test_another_hosts_name_or_address_still_passes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, host: str
) -> None:
    """The control: the same injected host does not refuse a neighbour one address or name away."""
    _as_this_host(monkeypatch, names=("eng1.corp.test", "eng1"), addresses=(_OWN_V4, _OWN_V6))
    assert forwarding_gate_refusal(_verified(tmp_path, host=host)) is None


def test_a_probe_that_fails_passes_the_gate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Fail-open, by decision: with no host name and no source address the gate decides as it did
    before the probe existed. The second half shows the same address refuses once the probe answers."""
    monkeypatch.setattr(settings_module, "_own_host_names", lambda: frozenset())
    monkeypatch.setattr(settings_module, "_local_source_address", lambda addr: None)
    assert forwarding_gate_refusal(_verified(tmp_path, host=_OWN_V4)) is None
    assert forwarding_gate_refusal(_verified(tmp_path, host="eng1")) is None
    _as_this_host(monkeypatch, names=("eng1",), addresses=(_OWN_V4,))
    assert forwarding_gate_refusal(_verified(tmp_path, host=_OWN_V4)) is not None


def test_a_short_os_name_does_not_claim_a_qualified_one(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The stated residue: the OS name is ``eng1``, so ``eng1.corp.test`` is not known to be this
    host without a lookup, and the gate makes none."""
    _as_this_host(monkeypatch, names=("eng1",), addresses=(_OWN_V4,))
    assert forwarding_gate_refusal(_verified(tmp_path, host="eng1.corp.test")) is None


@pytest.mark.parametrize(
    ("os_name", "expected"),
    [
        ("Eng1.Corp.Test.", {"eng1.corp.test", "eng1"}),
        ("ENG1", {"eng1"}),
        ("", set()),
    ],
)
def test_the_own_names_come_from_the_os_name_alone(
    monkeypatch: pytest.MonkeyPatch, os_name: str, expected: set[str]
) -> None:
    monkeypatch.setattr(socket, "gethostname", lambda: os_name)
    assert settings_module._own_host_names() == expected


def test_no_os_name_means_no_own_names(monkeypatch: pytest.MonkeyPatch) -> None:
    def _fails() -> str:
        raise OSError("no host name")

    monkeypatch.setattr(socket, "gethostname", _fails)
    assert settings_module._own_host_names() == frozenset()


class _FakeUdp:
    """A UDP socket that answers ``getsockname`` from a table and records what it was asked."""

    sources: dict[str, str] = {}
    calls: list[tuple[str, Any]] = []

    def __init__(self, family: int, kind: int) -> None:
        self.calls.append(("socket", (family, kind)))

    def __enter__(self) -> _FakeUdp:
        return self

    def __exit__(self, *exc: object) -> None:
        self.calls.append(("close", None))

    def connect(self, address: tuple[str, int]) -> None:
        self.calls.append(("connect", address))
        if address[0] not in self.sources:
            raise OSError("network is unreachable")
        self._to = address[0]

    def getsockname(self) -> tuple[str, int]:
        return (self.sources[self._to], 50000)


def test_the_source_address_probe_is_one_unsent_udp_connect(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The probe is a UDP socket, connected and closed, with nothing sent. It reads a zoned answer,
    and an OS error is None rather than a crash."""
    monkeypatch.setattr(_FakeUdp, "calls", [])
    monkeypatch.setattr(
        _FakeUdp, "sources", {_OWN_V4: _OWN_V4, "192.0.2.9": _OWN_V4, "fe80::1": "fe80::1%eth0"}
    )
    monkeypatch.setattr(socket, "socket", _FakeUdp)
    probe = settings_module._local_source_address
    assert probe(ipaddress.ip_address(_OWN_V4)) == ipaddress.ip_address(_OWN_V4)
    assert probe(ipaddress.ip_address("192.0.2.9")) == ipaddress.ip_address(_OWN_V4)
    assert probe(ipaddress.ip_address("fe80::1")) == ipaddress.ip_address("fe80::1%eth0")
    assert probe(ipaddress.ip_address("198.51.100.1")) is None  # connect raised OSError
    assert _FakeUdp.calls[:3] == [
        ("socket", (socket.AF_INET, socket.SOCK_DGRAM)),
        ("connect", (_OWN_V4, 9)),
        ("close", None),
    ]
    assert ("socket", (socket.AF_INET6, socket.SOCK_DGRAM)) in _FakeUdp.calls
    assert {name for name, _ in _FakeUdp.calls} == {"socket", "connect", "close"}
    # Only an IP LITERAL may reach connect(). CPython resolves a NAME inside connect() in C, where
    # no Python-level patch of getaddrinfo can see it, so this is the check that holds "no lookup".
    connected = [args[0] for name, args in _FakeUdp.calls if name == "connect"]
    assert len(connected) == 4
    for target in connected:
        ipaddress.ip_address(target)


def test_a_failed_probe_is_logged(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """Fail-open is not silent. The same config can pass before an interface is up and refuse at
    the next start, and the WARNING is the only record of which. It does not echo the address."""
    monkeypatch.setattr(_FakeUdp, "calls", [])
    monkeypatch.setattr(_FakeUdp, "sources", {})
    monkeypatch.setattr(socket, "socket", _FakeUdp)
    with caplog.at_level("WARNING", logger=settings_module.__name__):
        assert settings_module._local_source_address(ipaddress.ip_address(_OWN_V4)) is None
    assert "no source address" in caplog.text and "OSError" in caplog.text
    assert _OWN_V4 not in caplog.text

    def _fails() -> str:
        raise OSError("no host name")

    caplog.clear()
    monkeypatch.setattr(socket, "gethostname", _fails)
    with caplog.at_level("WARNING", logger=settings_module.__name__):
        assert settings_module._own_host_names() == frozenset()
    assert "no host name" in caplog.text


def test_a_zoned_link_local_address_of_this_host_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The OS may answer with or without a zone; either way it is the same address."""
    monkeypatch.setattr(settings_module, "_own_host_names", lambda: frozenset())
    monkeypatch.setattr(
        settings_module, "_local_source_address", lambda addr: ipaddress.ip_address("fe80::1%eth0")
    )
    assert forwarding_gate_refusal(_verified(tmp_path, host="fe80::1")) is not None
    assert forwarding_gate_refusal(_verified(tmp_path, host="fe80::2")) is None


def test_a_name_collector_never_opens_the_probe_socket(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A collector given by name is compared with the OS name only, so no socket is made for it."""

    def _no_socket(*args: Any, **kwargs: Any) -> Any:
        raise AssertionError("a name collector opened a socket")

    monkeypatch.setattr(socket, "socket", _no_socket)
    monkeypatch.setattr(socket, "gethostname", lambda: "eng1")
    assert forwarding_gate_refusal(_verified(tmp_path, host="siem.corp.test")) is None
    assert forwarding_gate_refusal(_verified(tmp_path, host="eng1")) is not None


def test_an_address_collector_resolves_no_name_and_opens_no_connection(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The IP-literal path with the REAL probe: it may make its one UDP socket, and nothing else.
    192.0.2.10 is a documentation address no host holds, so the gate passes whether this machine
    has a route to it or not. A resolver call or a stream connection fails the test."""

    def _no_lookup(*args: Any, **kwargs: Any) -> Any:
        raise AssertionError("the forwarding gate resolved a name or opened a connection")

    made: list[int] = []
    real_socket = socket.socket

    def _udp_only(family: int, kind: int, *args: Any, **kwargs: Any) -> socket.socket:
        made.append(kind)
        return real_socket(family, kind, *args, **kwargs)

    monkeypatch.setattr(socket, "socket", _udp_only)
    monkeypatch.setattr(socket, "create_connection", _no_lookup)
    monkeypatch.setattr(socket, "getaddrinfo", _no_lookup)
    monkeypatch.setattr(socket, "gethostbyname", _no_lookup)
    monkeypatch.setattr(socket, "getfqdn", _no_lookup)
    assert forwarding_gate_refusal(_verified(tmp_path, host="192.0.2.10")) is None
    assert made == [socket.SOCK_DGRAM]


def test_the_real_probe_reads_a_loopback_address_as_local() -> None:
    """What the OS does, not what a fake says: the source address for 127.0.0.1 is 127.0.0.1 on
    any host with a loopback interface, so this reads no runner-specific state."""
    loopback = ipaddress.ip_address("127.0.0.1")
    assert settings_module._local_source_address(loopback) == loopback


_UNUSABLE_HOSTS = ["a\x00b", "fe80::1%\x00", "\udcff", "siem\n.corp.test", "siem\x7f"]


@pytest.mark.parametrize("host", _UNUSABLE_HOSTS)
def test_host_text_that_can_name_no_collector_is_refused_at_load(tmp_path: Path, host: str) -> None:
    """A NUL or an undecodable byte raised out of the gate (review round 1, measured), and once the
    gate tolerated it, out of the forwarder's own socket call (round 2). The load refuses it, and
    the message does not quote the value."""
    with pytest.raises(ValueError, match="control character or an undecodable byte") as refused:
        _verified(tmp_path, host=host)
    assert host not in str(refused.value)


@pytest.mark.parametrize("host", _UNUSABLE_HOSTS)
def test_the_host_helpers_answer_for_text_the_load_refuses(host: str) -> None:
    """Defence in depth: a caller that builds the helpers' input some other way gets an answer,
    never an exception."""
    assert settings_module._names_this_host(host) is False
    assert settings_module._is_own_name_or_address(host) is False


@pytest.mark.parametrize("host", ["1234", "999.1.1.1", "[zz::", "siem corp"])
def test_odd_but_loadable_host_text_passes_the_gate(tmp_path: Path, host: str) -> None:
    """Text that is neither this host's name nor one of its addresses passes; the forwarder then
    reports the collector itself. ``1234`` reads as the IPv4 shorthand for 0.0.4.210, so this runs
    the real probe toward an address no host holds."""
    assert forwarding_gate_refusal(_verified(tmp_path, host=host)) is None


def test_an_all_digit_os_name_is_compared_as_a_name(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``1234`` also parses as the IPv4 shorthand for 0.0.4.210. The name is compared first, so a
    host really named ``1234`` is still recognised."""
    _as_this_host(monkeypatch, names=("1234",), addresses=(_OWN_V4,))
    assert forwarding_gate_refusal(_verified(tmp_path, host="1234")) is not None


def test_an_ipv6_zone_keeps_its_case(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A zone is an interface name, which is case-sensitive on Linux, so the probe must be asked
    about ``%enP4p65s0`` and not a lowercased copy."""
    asked: list[str] = []

    def source(addr: Any) -> Any:
        asked.append(str(addr))
        return addr

    monkeypatch.setattr(settings_module, "_own_host_names", lambda: frozenset())
    monkeypatch.setattr(settings_module, "_local_source_address", source)
    assert forwarding_gate_refusal(_verified(tmp_path, host="FE80::1%enP4p65s0")) is not None
    assert asked == ["fe80::1%enP4p65s0"]


def test_the_own_address_refusal_points_at_the_adr_for_a_virtual_address(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The routing table calls a virtual address local when it is bound here, even if another
    system answers on it. The refusal points at the ADR for that case. It does not print the step
    itself, because the same step would let a collector that IS this host through (round 2)."""
    _as_this_host(monkeypatch, names=("eng1",), addresses=(_OWN_V4,))
    reason = forwarding_gate_refusal(_verified(tmp_path, host=_OWN_V4))
    assert reason is not None and "ADR 0200 Amendment A" in reason
    assert "DNS name" not in reason


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
    name that never resolves), and the start still succeeds, because the gate never contacts or
    resolves the collector. The forwarder reports the collector itself at ERROR and runs without it."""
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
