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
from tests._content_free import assert_chain_severed


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
        # A non-ASCII OS name is held in the form the socket layer dials, so it meets a collector
        # written either way.
        ("B" + chr(0xDC) + "cher.Corp.Test", {"xn--bcher-kva.corp.test", "xn--bcher-kva"}),
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
    with pytest.raises(ValueError, match="control character or an undecodable byte"):
        _verified(tmp_path, host=host)
    _assert_the_validator_does_not_echo(host, "control character or an undecodable byte")


def _echoes(message: str, host: str) -> bool:
    """Whether ``message`` carries ``host`` in any of the forms an error would quote it in."""
    return host in message or ascii(host) in message or repr(host) in message


def _assert_the_validator_does_not_echo(host: str, needle: str) -> None:
    """The validator's OWN message, read off a direct call. The loaded model strips every input
    from its errors, so an assertion on that error could never fail; this one can. The last two
    lines are the control: the same search finds the value in a message that does quote it."""
    with pytest.raises(ValueError) as raw:
        settings_module.LoggingSettings._check_forward_host(host)
    message = str(raw.value)
    assert needle in message
    assert not _echoes(message, host)
    # No chain either. The codec's error holds the whole host on `.object`, and `from None` would
    # leave it on `__context__`, so the refusal is raised after the handler has ended.
    assert_chain_severed(raw.value)
    assert _echoes(f"{message}: {host!r}", host)
    assert _echoes(f"{message}: {host}", host)


@pytest.mark.parametrize("setting", ["forward_host", "ntp_peer"])
def test_the_error_a_real_load_keeps_carries_no_host(setting: str) -> None:
    """The same chain check on the path a real load takes, for both settings. The model strips
    the input from each error but KEEPS the validator's own exception under ``ctx``, so that
    object is what a serializer or crash reporter would walk. With ``from None`` it held the
    whole host on ``__context__.object`` (measured against the earlier shape)."""
    from pydantic import ValidationError

    host = "siem" + chr(0xFFFD) + ".corp"
    with pytest.raises(ValidationError) as refused:
        _log(**{setting: host})
    kept = [err["ctx"]["error"] for err in refused.value.errors() if "ctx" in err]
    assert len(kept) == 1 and isinstance(kept[0], ValueError)
    assert_chain_severed(kept[0])
    assert not _echoes(str(kept[0]), host)


#: Host text the socket layer's "idna" encoding refuses. Each loaded before and then raised
#: UnicodeEncodeError out of the start (on main too). At least: an empty label, a leading dot, a
#: label over 63 characters, a C1 control (U+0085), and a character IDNA prohibits (U+FFFD).
#: Built with chr(), so no invisible character sits in this file.
_IDNA_INVALID_HOSTS = [
    "siem..corp.test",
    ".siem",
    "x" * 64 + ".corp.test",
    "siem" + chr(0x85) + ".corp",
    "siem" + chr(0xFFFD) + ".corp",
]


@pytest.mark.parametrize("host", _IDNA_INVALID_HOSTS)
def test_a_host_the_network_layer_cannot_encode_is_refused_at_load(
    tmp_path: Path, host: str
) -> None:
    with pytest.raises(UnicodeError):
        host.encode("idna")  # the premise: this is what the forwarder's socket call would raise
    with pytest.raises(ValueError, match="not a host name the network layer can encode"):
        _verified(tmp_path, host=host)
    _assert_the_validator_does_not_echo(host, "network layer can encode")


def test_the_prohibited_character_case_is_not_an_empty_label_in_disguise() -> None:
    """The prohibited character is refused as itself. An invisible one would be dropped by the
    encoding and refused as the empty label it leaves, which an earlier version of this list
    used by mistake."""

    def reason(host: str) -> str:
        with pytest.raises(UnicodeError) as refused:
            host.encode("idna")
        return str(refused.value)

    empty_label = reason("siem..corp.test")
    prohibited = reason("siem" + chr(0xFFFD) + ".corp")
    invisible = reason(chr(0x200B) + ".corp")  # maps to nothing, so it fails as an empty label
    # Compared with each other, never with CPython's wording, which has changed between versions.
    assert prohibited != empty_label
    assert invisible.split(":", 1)[-1] == reason(".corp").split(":", 1)[-1]


@pytest.mark.parametrize(
    "host",
    [
        "siem.corp.test",
        "siem.corp.test.",
        "x" * 63 + ".corp.test",
        "b" + chr(0xFC) + "cher.example",
        "a_b.example",
        "10.0.0.5",
        "::1",
        "fe80::1%eth0",
        "[2001:db8::1]",
        "::ffff:10.0.0.5",
    ],
)
def test_an_encodable_host_still_loads(tmp_path: Path, host: str) -> None:
    """The control: an ordinary name, an internationalised one and at least these IP-literal
    forms load."""
    assert _verified(tmp_path, host=host).forward_host == host


@pytest.mark.parametrize("peer", ["ntp\x00", "ntp" + chr(0x85) + ".corp", "ntp" + chr(0xFFFD)])
def test_the_time_sync_peer_refuses_text_that_raised_a_traceback(peer: str) -> None:
    """``[logging].ntp_peer`` reaches the socket layer through a caller that catches OSError only.
    A NUL, or non-ASCII text the encoding refuses, raised TypeError there (measured)."""
    with pytest.raises(ValueError, match=r"\[logging\]\.ntp_peer"):
        LoggingSettings(ntp_peer=peer)


@pytest.mark.parametrize("peer", ["time.corp.test", "ntp..corp.test", ".ntp", "x" * 64 + ".corp"])
def test_the_time_sync_peer_leaves_an_ascii_typo_to_the_probe(peer: str) -> None:
    """The control, and a promise kept: an ASCII name with a bad label is a ``gaierror`` at the
    probe, which ``serve`` warns on, or refuses cleanly under ``time_sync_fail_closed``. Refusing
    it at load would turn that warning into a refused start, so it still loads."""
    assert LoggingSettings(ntp_peer=peer).ntp_peer == peer


def _fullwidth(text: str) -> str:
    """``text`` with its digits and dots as full-width forms, which the "idna" encoding folds back."""
    return "".join(
        chr(0xFF0E) if c == "." else chr(0xFF10 + int(c)) if c.isdigit() else c for c in text
    )


def test_the_gate_compares_the_form_the_socket_layer_will_dial(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The gate compared raw text while the socket layer encodes with "idna" first. So loopback
    typed in full-width digits, ``localhost`` with a soft hyphen inside, and this host's own name
    with a zero-width space inside each read as another host, and the forwarder then dialled this
    one (review, measured). Each loads, and each is now refused by the gate."""
    _as_this_host(monkeypatch, names=("eng1",), addresses=(_OWN_V4,))
    wide_loopback = _fullwidth("127.0.0.1")
    soft_localhost = "local" + chr(0xAD) + "host"
    spaced_own_name = "en" + chr(0x200B) + "g1"
    wide_own_address = _fullwidth(_OWN_V4)
    assert wide_loopback.encode("idna") == b"127.0.0.1"  # the premise
    for host, needle in (
        (wide_loopback, "loopback"),
        (soft_localhost, "loopback"),
        (spaced_own_name, "own name"),
        (wide_own_address, "own name or one of its own addresses"),
        # A space the encoding uncovers, once the invisible character beside it is dropped.
        ("localhost " + chr(0x200B), "loopback"),
        (chr(0x200B) + " 127.0.0.1", "loopback"),
    ):
        reason = forwarding_gate_refusal(_verified(tmp_path, host=host))
        assert reason is not None and needle in reason, ascii(host)
    # The control: a full-width address that is NOT this host still passes.
    assert forwarding_gate_refusal(_verified(tmp_path, host=_fullwidth("10.20.30.41"))) is None


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
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    extra: str = "",
    *,
    forwarding: bool,
    host: str | None = None,
) -> int:
    """A prod-PHI serve with every OTHER gate pre-cleared, so only forwarding decides it. ``host``
    replaces the verified collector's name, for a test that needs an IP-literal one."""
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
    if host is not None:
        monkeypatch.setenv("MEFOR_LOGGING_FORWARD_HOST", host)
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


_NO_ROUTE_HOST = "192.0.2.10"  # a documentation address no host holds
_FAIL_OPEN_LINE = "no source address for [logging].forward_host"


def _serve_with_a_failing_probe(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> tuple[int, str, str]:
    """An enforcing serve whose collector is an IP literal the OS will not route to, so the REAL
    own-address probe fails open. Every connect to that address is refused, the forwarder's
    included, so the test waits on no timeout. Returns the exit code, stdout and stderr."""

    class _Unroutable(socket.socket):
        def connect(self, address: Any) -> None:
            if address[0] == _NO_ROUTE_HOST:
                raise OSError("network is unreachable")
            super().connect(address)

    monkeypatch.setattr(socket, "socket", _Unroutable)
    code = _serve(tmp_path, monkeypatch, forwarding=True, host=_NO_ROUTE_HOST)
    captured = capsys.readouterr()
    return code, captured.out, captured.err


def test_a_fail_open_pass_is_recorded_by_the_configured_log_handlers(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """ADR 0200 Amendment A calls the WARNING the record of a fail-open pass. The gate runs before
    ``configure_logging``, so logged there it reached bare stderr only. ``serve`` now writes it
    twice, as it does the #1989 static-credential lines: to stderr where the gate runs, and again
    through the handlers ``configure_logging`` installs. Standard output is such a handler here,
    and the app log file and the off-box forwarder hang off the same root logger."""
    code, out, err = _serve_with_a_failing_probe(tmp_path, monkeypatch, capsys)
    assert code == 0  # fail-open: the start still succeeds
    assert f"warning: the OS gave {_FAIL_OPEN_LINE}" in err  # where the gate ran
    assert _FAIL_OPEN_LINE in out  # after configure_logging, through its handler
    assert out.count(_FAIL_OPEN_LINE) == 1  # recorded once there, not once per handler pass
    assert _NO_ROUTE_HOST not in "".join(
        line for line in (out + err).splitlines() if _FAIL_OPEN_LINE in line
    )


def test_a_named_collector_records_no_fail_open_line(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """A control: a collector given by name runs no probe and logs no line."""
    assert _serve(tmp_path, monkeypatch, forwarding=True) == 0
    captured = capsys.readouterr()
    assert _FAIL_OPEN_LINE not in captured.out + captured.err


def test_an_address_collector_whose_probe_answers_records_no_fail_open_line(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The control that matters: the same IP-literal start, with a probe that ANSWERS. The line
    is for a fail-open pass only, so a start that logged it for every address collector reds here.
    The probe's answer is faked, so no route is needed; the forwarder's own connect is refused."""

    class _Routable(socket.socket):
        _probed = False

        def connect(self, address: Any) -> None:
            if address[0] != _NO_ROUTE_HOST:
                super().connect(address)
            elif self.type == socket.SOCK_DGRAM:
                self._probed = True  # the gate's probe: "connected", nothing sent
            else:
                raise OSError("connection refused")  # the forwarder: the collector is down

        def getsockname(self) -> Any:
            return ("10.9.9.9", 50000) if self._probed else super().getsockname()

    monkeypatch.setattr(socket, "socket", _Routable)
    assert _serve(tmp_path, monkeypatch, forwarding=True, host=_NO_ROUTE_HOST) == 0
    captured = capsys.readouterr()
    assert "ASVS 16.4.3" not in captured.err
    assert _FAIL_OPEN_LINE not in captured.out + captured.err


def test_the_fail_open_line_honours_the_configured_log_level(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The re-emitted line is an ordinary WARNING. With ``[logging].level = "ERROR"`` the handlers
    do not get it, as they would not get any other WARNING; stderr, where the gate ran, still does."""
    monkeypatch.setenv("MEFOR_LOGGING_LEVEL", "ERROR")
    code, out, err = _serve_with_a_failing_probe(tmp_path, monkeypatch, capsys)
    assert code == 0
    assert _FAIL_OPEN_LINE not in out
    assert f"warning: the OS gave {_FAIL_OPEN_LINE}" in err


def test_a_gate_that_raises_still_logs_its_notes(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture, tmp_path: Path
) -> None:
    """``forwarding_gate_check`` holds the notes for its caller. If the gate raises after making
    one, the caller never gets the list, so the note is logged before the error leaves."""

    def _note_then_raise(host: str) -> bool:
        settings_module._fail_open_note("a note made before the fault")
        raise RuntimeError("a fault in the gate")

    monkeypatch.setattr(settings_module, "_is_own_name_or_address", _note_then_raise)
    with (
        caplog.at_level("WARNING", logger=settings_module.__name__),
        pytest.raises(RuntimeError),
    ):
        settings_module.forwarding_gate_check(_verified(tmp_path))
    assert "a note made before the fault" in caplog.text
    # And the hold is released: a later note is logged at once again, not appended to a dead list.
    caplog.clear()
    with caplog.at_level("WARNING", logger=settings_module.__name__):
        settings_module._fail_open_note("a later note")
    assert "a later note" in caplog.text


def test_the_check_returns_its_notes_and_logs_none(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture, tmp_path: Path
) -> None:
    """The other half: on a normal return the notes come back as text and are NOT also logged, so
    a caller that writes them does not double them."""
    monkeypatch.setattr(_FakeUdp, "calls", [])
    monkeypatch.setattr(_FakeUdp, "sources", {})
    monkeypatch.setattr(socket, "socket", _FakeUdp)
    monkeypatch.setattr(settings_module, "_own_host_names", lambda: frozenset())
    with caplog.at_level("WARNING", logger=settings_module.__name__):
        refusal, notes = settings_module.forwarding_gate_check(_verified(tmp_path, host=_OWN_V4))
    assert refusal is None
    assert len(notes) == 1 and "no source address" in notes[0] and _OWN_V4 not in notes[0]
    assert caplog.text == ""


def test_serve_under_warn_warns_instead_of_refusing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    extra = 'security.enforcement = "warn"\n'
    assert _serve(tmp_path, monkeypatch, extra, forwarding=False) == 0
    assert "does not forward its logs off-box over verified TLS" in capsys.readouterr().err
