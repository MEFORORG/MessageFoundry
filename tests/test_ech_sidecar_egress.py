# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The ``[egress].allowed_ech_sidecar`` gate on a REST connection's ECH sidecar (BACKLOG #5528).

An ``ech_egress`` REST connection sends every request, body and credential headers included, to its
loopback ``ech_sidecar``, and on a SMART or OAuth2 connection the token-endpoint POST takes the same
hop (ADR 0139). Before this gate the egress check read only the upstream ``url``, so a connection
could name any loopback port as its sidecar, and a deploying site's connection would have sent PHI
and credentials to whatever listened there.

The list is deny-by-default on its own terms, as ``allowed_proxy`` is (ADR 0126): an empty list
refuses an ECH connection even under ``[security].block_unlisted_outbound = false``. Each entry is
``host:port``, and an entry with no port is refused at load rather than read as any port.
"""

from __future__ import annotations

import logging
from typing import Any

import pytest
from pydantic import ValidationError

from messagefoundry.config.models import ConnectorType, Destination
from messagefoundry.config.settings import EgressSettings
from messagefoundry.config.wiring import WiringError
from messagefoundry.transports.egress import check_egress_allowed
from messagefoundry.transports.rest import RestDestination
from tests._egress_policy import permitting

_PARTNER = "https://partner.example.org/api"


def _ech(sidecar: str, **extra: Any) -> Destination:
    return Destination(
        name="OB_ECH",
        type=ConnectorType.REST,
        settings={"url": _PARTNER, "ech_egress": True, "ech_sidecar": sidecar, **extra},
    )


def _egress(*sidecars: str, deny_by_default: bool = True) -> EgressSettings:
    return EgressSettings(
        allowed_http=["partner.example.org"],
        allowed_ech_sidecar=list(sidecars),
        deny_by_default=deny_by_default,
    )


def test_an_unlisted_sidecar_port_is_refused() -> None:
    """The finding itself: before the gate this returned with no error, so a sidecar at any loopback
    port, here a cache's, would have received the request body and its credential headers."""
    with pytest.raises(WiringError, match=r"allowed_ech_sidecar"):
        check_egress_allowed(_ech("http://127.0.0.1:6379"), _egress("127.0.0.1:8123"))


def test_an_empty_list_refuses_even_under_the_allow_any_opt_out() -> None:
    """Deny-by-default on its own terms, like allowed_proxy: the opt-out that makes an empty
    destination list allow any host does not open the sidecar hop."""
    wide_open = EgressSettings(deny_by_default=False)
    with pytest.raises(WiringError, match=r"allowed_ech_sidecar is empty"):
        check_egress_allowed(_ech("http://127.0.0.1:8123"), wide_open)


def test_a_listed_sidecar_is_permitted() -> None:
    check_egress_allowed(_ech("http://127.0.0.1:8123"), _egress("127.0.0.1:8123"))
    check_egress_allowed(_ech("https://localhost:8443/"), _egress("LOCALHOST:8443"))
    check_egress_allowed(
        _ech("http://127.0.0.1:8123"), _egress("127.0.0.1:8123", deny_by_default=False)
    )


def test_the_port_must_match_and_the_host_must_match() -> None:
    with pytest.raises(WiringError, match=r"allowed_ech_sidecar"):
        check_egress_allowed(_ech("http://127.0.0.1:8124"), _egress("127.0.0.1:8123"))
    with pytest.raises(WiringError, match=r"allowed_ech_sidecar"):
        check_egress_allowed(_ech("http://localhost:8123"), _egress("127.0.0.1:8123"))


def test_a_url_with_no_port_is_judged_at_the_port_urllib_dials() -> None:
    """urllib dials 80 for http and 443 for https when the URL names no port, so that is the port
    the gate compares; a URL with no port is not a wildcard either."""
    check_egress_allowed(_ech("http://127.0.0.1"), _egress("127.0.0.1:80"))
    check_egress_allowed(_ech("https://127.0.0.1/"), _egress("127.0.0.1:443"))
    with pytest.raises(WiringError, match=r"allowed_ech_sidecar"):
        check_egress_allowed(_ech("http://127.0.0.1"), _egress("127.0.0.1:443"))


def test_a_sidecar_port_urllib_cannot_read_is_refused_in_fixed_words() -> None:
    with pytest.raises(WiringError, match=r"not a number from 0 to 65535") as caught:
        check_egress_allowed(_ech("http://127.0.0.1:99999"), _egress("127.0.0.1:8123"))
    assert "99999" not in str(caught.value)
    # Leading zeros pass the credential screen's port check, then break int() past 4300 digits.
    long_port = "0" * 5000 + "8123"
    with pytest.raises(WiringError, match=r"cannot be read as a number") as caught:
        check_egress_allowed(_ech(f"http://127.0.0.1:{long_port}"), _egress("127.0.0.1:8123"))
    assert long_port not in str(caught.value)


def test_the_shared_test_policy_lists_no_sidecar_it_cannot_list() -> None:
    port_zero = {"ech_egress": True, "ech_sidecar": "http://127.0.0.1:0"}
    assert permitting(port_zero).allowed_ech_sidecar == []
    ipv6 = {"ech_egress": True, "ech_sidecar": "http://[::1]"}
    assert permitting(ipv6).allowed_ech_sidecar == ["[::1]:80"]


def test_a_bracketed_ipv6_loopback_entry_matches() -> None:
    check_egress_allowed(_ech("http://[::1]:8123"), _egress("[::1]:8123"))
    # One address, two spellings: compared as an address on both sides.
    check_egress_allowed(_ech("http://[0:0:0:0:0:0:0:1]:8123"), _egress("[::1]:8123"))
    check_egress_allowed(_ech("http://[::1]:8123"), _egress("[0:0:0:0:0:0:0:1]:8123"))
    with pytest.raises(WiringError, match=r"allowed_ech_sidecar"):
        check_egress_allowed(_ech("http://[::1]:8124"), _egress("[::1]:8123"))


@pytest.mark.parametrize(
    "entry",
    [
        "127.0.0.1",  # no port: every other [egress] list reads this as any port; this one refuses
        "127.0.0.1:",
        "127.0.0.1:0",
        "127.0.0.1:65536",
        "127.0.0.1:http",
        ":8123",
        "::1:8123",  # an unbracketed IPv6 literal cannot be split unambiguously
        "http://127.0.0.1:8123",
        "127.0.0.1:" + "1" * 5000,  # past int()'s digit limit: refused, not a stray ValueError
        # Entries no sidecar could ever match, so an operator is not told the sidecar is listed:
        "10.0.0.5:8123",  # the resolver refuses a sidecar off this machine
        "user@127.0.0.1:8123",
        "[127.0.0.1]:8123",  # urlsplit refuses a bracketed IPv4 literal in a URL
    ],
)
def test_an_entry_that_is_not_host_and_port_is_refused_at_load(entry: str) -> None:
    with pytest.raises(ValidationError, match=r"allowed_ech_sidecar") as caught:
        EgressSettings(allowed_ech_sidecar=[entry])
    # The refusal names the entry by its position, never by its text: an operator who pasted a
    # sidecar URL with a credential in it would otherwise find it in the error.
    assert "entry 1 " in str(caught.value)


def test_the_entry_position_skips_blank_entries() -> None:
    with pytest.raises(ValidationError, match=r"entry 2 \(counting non-blank entries\)"):
        EgressSettings(allowed_ech_sidecar=["127.0.0.1:8123", "", "bad"])


def test_a_portless_entry_built_unvalidated_still_does_not_wildcard() -> None:
    """The gate reads only entries that pin a port, so a list that skipped validation (a
    ``model_construct``) still cannot admit a sidecar at any port."""
    unvalidated = EgressSettings.model_construct(
        allowed_http=["partner.example.org"], allowed_ech_sidecar=["127.0.0.1"]
    )
    with pytest.raises(WiringError, match=r"allowed_ech_sidecar"):
        check_egress_allowed(_ech("http://127.0.0.1:6379"), unvalidated)


def test_the_list_reads_a_comma_separated_env_value() -> None:
    parsed = EgressSettings(allowed_ech_sidecar="127.0.0.1:8123, localhost:9000")  # type: ignore[arg-type]
    assert parsed.allowed_ech_sidecar == ["127.0.0.1:8123", "localhost:9000"]


def test_a_connection_without_ech_egress_is_not_gated() -> None:
    plain = Destination(name="OB_PLAIN", type=ConnectorType.REST, settings={"url": _PARTNER})
    check_egress_allowed(plain, EgressSettings(allowed_http=["partner.example.org"]))
    # ech_sidecar alone, with ech_egress off, is never dialled, so it is not judged either.
    idle = Destination(
        name="OB_IDLE",
        type=ConnectorType.REST,
        settings={"url": _PARTNER, "ech_sidecar": "http://127.0.0.1:6379"},
    )
    check_egress_allowed(idle, EgressSettings(allowed_http=["partner.example.org"]))


def test_a_sidecar_the_resolver_refuses_is_refused_by_the_gate() -> None:
    """The gate reads the sidecar through the resolver the connector dials from, so a value the
    build would refuse is refused here too, before any list is read."""
    with pytest.raises(WiringError, match=r"loopback"):
        check_egress_allowed(_ech("http://sidecar.example.org:8123"), _egress("127.0.0.1:8123"))
    with pytest.raises(WiringError, match=r"ech_sidecar is empty"):
        check_egress_allowed(_ech(""), _egress("127.0.0.1:8123"))


def test_a_sidecar_url_with_a_credential_is_refused_and_not_echoed(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """urllib would hand ``user:pw@host`` to http.client as the host, so the hop the gate would
    judge is not the hop dialled. Refused, and no part of the value reaches the error or the log."""
    sidecar = "http://svc:s3cr3t-token@127.0.0.1:8123"
    with caplog.at_level(logging.WARNING), pytest.raises(WiringError) as caught:
        check_egress_allowed(_ech(sidecar), _egress("127.0.0.1:8123"))
    assert "s3cr3t" not in str(caught.value)
    assert "s3cr3t" not in caplog.text
    assert caught.value.__context__ is None or "s3cr3t" not in str(caught.value.__context__)
    # The remedy is the sidecar's own configuration: a credential on the connection would ride
    # every request through the sidecar to the partner.
    assert "sidecar's own configuration" in str(caught.value)
    assert "egress denied" in caplog.text


def test_an_unlisted_refusal_names_the_host_and_never_the_url(
    caplog: pytest.LogCaptureFixture,
) -> None:
    with caplog.at_level(logging.WARNING), pytest.raises(WiringError) as caught:
        check_egress_allowed(_ech("http://127.0.0.1:6379/private-path"), _egress("127.0.0.1:8123"))
    assert "'127.0.0.1'" in str(caught.value)
    assert "private-path" not in str(caught.value)
    assert "private-path" not in caplog.text
    assert "egress denied" in caplog.text


def test_a_listed_sidecar_does_not_satisfy_the_destination_gate() -> None:
    """The sidecar list gates the hop, never the destination: an ECH connection whose upstream is
    not in allowed_http is still refused."""
    egress = EgressSettings(
        allowed_http=["other.example.org"], allowed_ech_sidecar=["127.0.0.1:8123"]
    )
    with pytest.raises(WiringError, match=r"allowed_http"):
        check_egress_allowed(_ech("http://127.0.0.1:8123"), egress)


@pytest.mark.parametrize(
    ("sidecar", "match"), [("http://sidecar.example.org:8123", "loopback"), ("", "is empty")]
)
def test_the_connector_still_refuses_a_bad_sidecar_on_its_own(sidecar: str, match: str) -> None:
    """A control. build_destination now runs the gate before the builder, so the tests that build
    through it are refused by the gate first. This pins the connector's own refusal, built
    directly, so it cannot go away unseen behind the gate."""
    with pytest.raises(ValueError, match=match):
        RestDestination(_ech(sidecar))
