# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Fail-closed outbound/egress allowlist (WP-11c, ASVS 13.2.4/13.2.5/14.2.3): a destination not on the
[egress] allowlist is refused at config build_check; an empty list = unrestricted."""

from __future__ import annotations

from pathlib import Path

import pytest

from messagefoundry.config.models import ConnectorType, Destination, Source
from messagefoundry.config.settings import EgressSettings
from messagefoundry.config.wiring import (
    ConnectionSpec,
    InboundConnection,
    OutboundConnection,
    Registry,
    WiringError,
)
from messagefoundry.pipeline.wiring_runner import (
    RegistryRunner,
    check_egress_allowed,
    check_lookup_allowed,
    check_source_allowed,
)
from messagefoundry.store.store import MessageStore


def _mllp(host: str, port: int) -> Destination:
    return Destination(name="OB", type=ConnectorType.MLLP, settings={"host": host, "port": port})


def _file(directory: str) -> Destination:
    return Destination(name="OB", type=ConnectorType.FILE, settings={"directory": directory})


def test_empty_allowlist_is_unrestricted() -> None:
    e = EgressSettings()  # nothing configured → today's behavior (any destination)
    check_egress_allowed(_mllp("anywhere.example", 1234), e)
    check_egress_allowed(_file("/tmp/whatever"), e)


def test_mllp_allowlist_host_and_port() -> None:
    e = EgressSettings(allowed_mllp=["hl7.partner.org:2575", "10.0.0.5"])
    check_egress_allowed(_mllp("hl7.partner.org", 2575), e)  # exact host:port
    check_egress_allowed(_mllp("HL7.Partner.org", 2575), e)  # case-insensitive host
    check_egress_allowed(_mllp("10.0.0.5", 9999), e)  # host-only entry → any port
    with pytest.raises(WiringError, match="allowed_mllp"):
        check_egress_allowed(_mllp("evil.example", 2575), e)  # wrong host
    with pytest.raises(WiringError, match="allowed_mllp"):
        check_egress_allowed(_mllp("hl7.partner.org", 6661), e)  # wrong port


def test_file_allowlist_directory_prefix(tmp_path: Path) -> None:
    base = tmp_path / "out"
    (base / "sub").mkdir(parents=True)
    e = EgressSettings(allowed_file_dirs=[str(base)])
    check_egress_allowed(_file(str(base)), e)  # exact
    check_egress_allowed(_file(str(base / "sub")), e)  # nested under an allowed dir
    with pytest.raises(WiringError, match="allowed_file_dirs"):
        check_egress_allowed(_file(str(tmp_path / "elsewhere")), e)  # outside


def _registry(tmp_path: Path, host: str) -> Registry:
    reg = Registry()
    reg.add_inbound(
        InboundConnection(
            "IB", ConnectionSpec(ConnectorType.FILE, {"directory": str(tmp_path)}), router="r"
        )
    )
    reg.add_router("r", lambda m: [])
    reg.add_outbound(
        OutboundConnection("OB", ConnectionSpec(ConnectorType.MLLP, {"host": host, "port": 2575}))
    )
    return reg


async def test_build_check_refuses_disallowed_outbound(tmp_path: Path) -> None:
    store = await MessageStore.open(tmp_path / "x.db")
    try:
        egress = EgressSettings(allowed_mllp=["good.partner.org:2575"])
        # A non-allowed destination is refused at config validation (→ WiringError → 422 / refused reload).
        bad = RegistryRunner(_registry(tmp_path, "evil.example"), store, egress=egress)
        with pytest.raises(WiringError, match="allowed_mllp"):
            bad.build_check(bad.registry)
        # An allowed destination build-checks cleanly.
        good = RegistryRunner(_registry(tmp_path, "good.partner.org"), store, egress=egress)
        good.build_check(good.registry)  # no raise
    finally:
        await store.close()


# --- deny_by_default (Q5b): an empty allowlist refuses instead of allowing --------------------------


def _db_dest(server: str) -> Destination:
    return Destination(
        name="OB", type=ConnectorType.DATABASE, settings={"server": server, "port": 1433}
    )


def test_deny_by_default_refuses_empty_allowlist() -> None:
    e = EgressSettings(deny_by_default=True)  # nothing listed → every destination refused
    for dest in (_mllp("hl7.partner.org", 2575), _file("/tmp/out"), _db_dest("sql.internal")):
        with pytest.raises(WiringError, match="block_unlisted_outbound"):
            check_egress_allowed(dest, e)


def test_deny_by_default_honours_a_set_allowlist() -> None:
    # With the relevant list set, behavior matches today: the list is enforced (no extra refusal).
    e = EgressSettings(deny_by_default=True, allowed_mllp=["hl7.partner.org:2575"])
    check_egress_allowed(_mllp("hl7.partner.org", 2575), e)  # listed → allowed
    with pytest.raises(WiringError, match="allowed_mllp"):
        check_egress_allowed(_mllp("evil.example", 2575), e)  # not listed → refused
    # The flag is global, so a different transport with no list of its own is still refused.
    with pytest.raises(WiringError, match="block_unlisted_outbound"):
        check_egress_allowed(_file("/tmp/out"), e)


def test_deny_by_default_off_is_unrestricted() -> None:
    e = EgressSettings()  # default false + empty lists → today's behavior (any destination)
    check_egress_allowed(_mllp("anywhere.example", 1234), e)
    check_egress_allowed(_db_dest("any.sql"), e)


def test_deny_by_default_gates_dial_out_sources_and_lookups() -> None:
    e = EgressSettings(deny_by_default=True)
    db_source = Source(
        type=ConnectorType.DATABASE, settings={"server": "sql.internal", "port": 1433}
    )
    with pytest.raises(WiringError, match="block_unlisted_outbound"):
        check_source_allowed(db_source, "IB_DB", e)
    with pytest.raises(WiringError, match="block_unlisted_outbound"):
        check_lookup_allowed("LK", {"server": "sql.internal", "port": 1433}, e)
    # A listener source (MLLP binds + waits; never dials out) is unaffected even under deny_by_default.
    mllp_source = Source(type=ConnectorType.MLLP, settings={"host": "0.0.0.0", "port": 2575})
    check_source_allowed(mllp_source, "IB_MLLP", e)  # no raise


async def test_build_check_deny_by_default_refuses_unlisted(tmp_path: Path) -> None:
    store = await MessageStore.open(tmp_path / "x.db")
    try:
        # deny_by_default with nothing listed → the MLLP outbound is refused at build_check.
        refused = RegistryRunner(
            _registry(tmp_path, "good.partner.org"),
            store,
            egress=EgressSettings(deny_by_default=True),
        )
        with pytest.raises(WiringError, match="block_unlisted_outbound"):
            refused.build_check(refused.registry)
        # Listing the destination permits it even under deny_by_default.
        allowed = RegistryRunner(
            _registry(tmp_path, "good.partner.org"),
            store,
            egress=EgressSettings(deny_by_default=True, allowed_mllp=["good.partner.org:2575"]),
        )
        allowed.build_check(allowed.registry)  # no raise
    finally:
        await store.close()


# --- Credential-bearing token endpoints (ASVS 14.2.3) --------------------------------------------
# A token URL is a SECOND egress host that receives CREDENTIALS, distinct from the data `url` the
# host gate checks. `smart_token_url` was gated from the start; `oauth2_token_url` was NOT, until
# 2026-07-31 — its only validation was the http(s) scheme check in transports/http_auth.py, so a
# crafted value exfiltrated client_id + client_secret to any host while [egress].allowed_http gated
# only the data URL.


def _rest(url: str, **extra: str) -> Destination:
    return Destination(name="OB", type=ConnectorType.REST, settings={"url": url, **extra})


def test_outbound_denies_unlisted_oauth2_token_url() -> None:
    """The data host is allowlisted and the token host is not — the credential POST must be refused."""
    egress = EgressSettings(allowed_http=["api.partner.org"])
    dest = _rest("https://api.partner.org/v1", oauth2_token_url="https://evil.example/token")
    with pytest.raises(WiringError, match="OAuth2 token endpoint"):
        check_egress_allowed(dest, egress)


def test_outbound_permits_allowlisted_oauth2_token_url() -> None:
    egress = EgressSettings(allowed_http=["api.partner.org", "auth.partner.org"])
    dest = _rest("https://api.partner.org/v1", oauth2_token_url="https://auth.partner.org/token")
    check_egress_allowed(dest, egress)  # no raise


def test_outbound_unset_oauth2_token_url_is_a_no_op() -> None:
    egress = EgressSettings(allowed_http=["api.partner.org"])
    check_egress_allowed(_rest("https://api.partner.org/v1"), egress)  # no raise


def test_every_credential_token_url_key_is_gated_on_the_outbound_arm() -> None:
    """Structural guard, not a point check: EVERY key in the credential-URL table must be refused
    when it points off-allowlist. This is what stops the next credential-bearing endpoint setting
    from shipping ungated the way `oauth2_token_url` did — add a key to the table and this test
    fails until the gate actually covers it."""
    from messagefoundry.pipeline.wiring_runner import _CREDENTIAL_EGRESS_URL_KEYS

    assert _CREDENTIAL_EGRESS_URL_KEYS, "the credential-URL table must not be empty"
    egress = EgressSettings(allowed_http=["api.partner.org"])
    for key, what in _CREDENTIAL_EGRESS_URL_KEYS:
        dest = _rest("https://api.partner.org/v1", **{key: "https://evil.example/token"})
        with pytest.raises(WiringError, match=what):
            check_egress_allowed(dest, egress)


def test_every_credential_token_url_key_is_gated_on_the_lookup_arm() -> None:
    """The read arm must stay in lockstep with the outbound arm — DELTA-04 was exactly that drift
    (the read arm gated only `url`). Same table, both arms, asserted together."""
    from messagefoundry.pipeline.wiring_runner import (
        _CREDENTIAL_EGRESS_URL_KEYS,
        check_fhir_lookup_allowed,
    )

    egress = EgressSettings(allowed_http=["fhir.example.org"])
    for key, what in _CREDENTIAL_EGRESS_URL_KEYS:
        settings = {"url": "https://fhir.example.org/fhir", key: "https://evil.example/token"}
        with pytest.raises(WiringError, match=what):
            check_fhir_lookup_allowed("epic", settings, egress)


# --- The forward/egress web proxy host (ADR 0126, BACKLOG #1659) ---------------------------------
# The proxy is a THIRD egress host on an http-family connection, distinct from the data `url` and from
# the token endpoints above, and it is credential-bearing: `proxy_auth_type = basic` (the default)
# mints a pre-emptive `Proxy-Authorization` that urllib delivers to the proxy on an http destination
# as a request header and on an https one inside the CONNECT tunnel. It is gated by its OWN
# `[egress].allowed_proxy` list and NOT by `allowed_http` — ADR 0126 puts the proxy host out of that
# gate's scope ("one corporate proxy fronts many hosts, and it would have to be co-listed with every
# destination"), so folding it in would re-create exactly the co-listing the ADR rejected.


def test_proxy_url_is_not_in_the_credential_token_url_table() -> None:
    """The mechanism ADR 0126 forbids, pinned so the next pass does not re-file it.

    The #1659 ledger row's own closing step said to add `proxy_url` to `_CREDENTIAL_EGRESS_URL_KEYS`.
    That table gates against `[egress].allowed_http`, which the ADR rules the proxy host out of, so
    the key must stay out and the dedicated list below must do the gating instead.

    NOT A RED-FIRST TEST, deliberately: `proxy_url` was never in the table, so this passed before the
    gate was built and passes after. It is a regression pin against a FUTURE edit, and it earns its
    place only because that edit is what the ledger row asks for in writing.
    """
    from messagefoundry.pipeline.wiring_runner import _CREDENTIAL_EGRESS_URL_KEYS

    assert "proxy_url" not in {key for key, _what in _CREDENTIAL_EGRESS_URL_KEYS}


def test_outbound_denies_unlisted_proxy_host() -> None:
    egress = EgressSettings(allowed_http=["api.partner.org"], allowed_proxy=["proxy.corp.example"])
    dest = _rest("https://api.partner.org/v1", proxy_url="http://evil.example:3128")
    with pytest.raises(WiringError, match="allowed_proxy"):
        check_egress_allowed(dest, egress)


def test_outbound_permits_listed_proxy_host() -> None:
    egress = EgressSettings(
        allowed_http=["api.partner.org"], allowed_proxy=["proxy.corp.example:3128"]
    )
    dest = _rest("https://api.partner.org/v1", proxy_url="http://proxy.corp.example:3128")
    check_egress_allowed(dest, egress)  # no raise
    # A host-only entry permits any port, matching every other [egress] list's host[:port] shape.
    host_only = EgressSettings(
        allowed_http=["api.partner.org"], allowed_proxy=["proxy.corp.example"]
    )
    check_egress_allowed(
        _rest("https://api.partner.org/v1", proxy_url="http://proxy.corp.example:8080"), host_only
    )
    with pytest.raises(WiringError, match="allowed_proxy"):  # pinned port must match
        check_egress_allowed(
            _rest("https://api.partner.org/v1", proxy_url="http://proxy.corp.example:8080"), egress
        )


def test_proxy_gate_is_deny_by_default_with_an_empty_list() -> None:
    """The asymmetry with the destination lists, asserted rather than left to the comment.

    `allowed_http` is permissive when empty; `allowed_proxy` is not, matching `[ai].allowed_endpoints`
    (ADR 0135). It costs an operator who configures no proxy nothing — the gate only bites once a
    proxy is set — and permissive-when-empty would leave this credential-bearing host ungated on the
    default posture, which is the hole the key exists to close.
    """
    wide_open = EgressSettings()  # no allowed_http, no allowed_proxy, no deny_by_default
    with pytest.raises(WiringError, match="allowed_proxy is empty"):
        check_egress_allowed(
            _rest("https://api.partner.org/v1", proxy_url="http://p.example"), wide_open
        )
    # ...and with no proxy configured the same empty list refuses nothing.
    check_egress_allowed(_rest("https://api.partner.org/v1"), wide_open)


def test_proxy_gate_skips_the_default_sentinel() -> None:
    """`proxy_url = "default"` names no address at config time (urllib resolves the OS proxy at
    request time) and `proxy_config_from_settings` refuses to pair it with proxy credentials, so that
    path mints no Proxy-Authorization and there is nothing here to match against a host list.

    NOT A RED-FIRST TEST: it asserts a NON-raise, so it would pass with no gate at all. Its job is to
    pin the carve-out against a later tightening that would refuse every `"default"` proxy at load.
    The deny-by-default arm it must not trip IS red-first — see the test above."""
    from messagefoundry.transports.rest import PROXY_DEFAULT

    egress = EgressSettings()  # empty allowed_proxy — the deny-by-default arm must NOT fire
    check_egress_allowed(_rest("https://api.partner.org/v1", proxy_url=PROXY_DEFAULT), egress)
    check_egress_allowed(_rest("https://api.partner.org/v1", proxy_url="DEFAULT"), egress)


def test_proxy_gate_covers_the_fhir_lookup_read_arm() -> None:
    """The read arm dials through the same proxy as the outbound, so it must stay in lockstep —
    DELTA-04 was exactly that drift. Gated OUTSIDE the `allowed_http` guard: that list being empty
    says nothing about whether the proxy is permitted."""
    from messagefoundry.pipeline.wiring_runner import check_fhir_lookup_allowed

    egress = EgressSettings(allowed_http=["fhir.example.org"], allowed_proxy=["proxy.corp.example"])
    settings = {"url": "https://fhir.example.org/fhir", "proxy_url": "http://evil.example:3128"}
    with pytest.raises(WiringError, match="allowed_proxy"):
        check_fhir_lookup_allowed("epic", settings, egress)
    ok = {"url": "https://fhir.example.org/fhir", "proxy_url": "http://proxy.corp.example:3128"}
    check_fhir_lookup_allowed("epic", ok, egress)  # no raise
    # The deny-by-default arm reaches the read arm too, and fires with allowed_http empty.
    with pytest.raises(WiringError, match="allowed_proxy is empty"):
        check_fhir_lookup_allowed("epic", settings, EgressSettings())


def test_a_listed_proxy_does_not_satisfy_the_destination_gate() -> None:
    """`allowed_proxy` is not a destination list: listing a proxy must not permit an unlisted PHI
    destination. The two lists are independent gates, and this is the confusion the dedicated key
    invites.

    NOT A RED-FIRST TEST: the refusal it asserts is `allowed_http`'s, which predates this change. It
    pins that the new list did not weaken the old one."""
    egress = EgressSettings(allowed_http=["api.partner.org"], allowed_proxy=["proxy.corp.example"])
    dest = _rest("https://evil.example/v1", proxy_url="http://proxy.corp.example:3128")
    with pytest.raises(WiringError, match="allowed_http"):
        check_egress_allowed(dest, egress)
