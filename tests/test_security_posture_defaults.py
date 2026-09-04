# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""The shipped-default posture lane: ONE posture, and operators may only LOOSEN from it.

Two defaults moved to the hardened value (ADR 0148 GIVEN 1 — the hardened path is the shipped path, so it
is the path every test, CI leg and dogfood instance exercises, not one first met in production):

* ``[store].aad_bind`` ``false`` → **``true``** (ADR 0019, 2026-07-28 amendment) — at-rest values are
  cell-bound (``mfenc:v2``) by default;
* ``[auth].ad_session_recheck_seconds`` ``0`` → **``300``** (ADR 0079, 2026-07-28 amendment) — directory
  revocation propagates by default.

The governing rule is that every deviation from that one posture is VISIBLE: ``security_loosenings()`` +
``GET /security/posture`` + ``docs/SECURITY-LOOSENING.md``. A deviation the registry cannot see is a
second posture by the back door, so these tests are as much about the REGISTRY as about the defaults —
including a completeness floor, because a registry with no floor is exactly the shape that lets a later
switch be added at an insecure value with nothing reporting it.
"""

from __future__ import annotations

from pathlib import Path

import httpx
import pytest

from messagefoundry.api import create_app
from messagefoundry.config.settings import (
    AlertsSettings,
    AuthSettings,
    SecuritySettings,
    ServiceSettings,
    StoreSettings,
    load_settings,
    security_loosenings,
)
from messagefoundry.pipeline import Engine


def _ad(**over: object) -> AuthSettings:
    """AD-enabled auth settings with the connection essentials the model requires."""
    base: dict[str, object] = {
        "ad_enabled": True,
        "ad_server": "ldaps://dc.test.invalid",
        "ad_user_search_base": "OU=Staff,DC=test,DC=invalid",
        "ad_bind_dn": "CN=svc-mefor,OU=Service,DC=test,DC=invalid",
        "ad_bind_password": "synthetic",
    }
    base.update(over)
    return AuthSettings(**base)  # type: ignore[arg-type]


def _names(
    sec: SecuritySettings | None = None,
    store: StoreSettings | None = None,
    auth: AuthSettings | None = None,
    alerts: AlertsSettings | None = None,
    cleartext_hops: tuple[str, ...] = (),
    expiry_hops: tuple[str, ...] = (),
    db_hops: tuple[str, ...] = (),
) -> list[str]:
    """The loosening SWITCH NAMES for a settings combination (defaults where not overridden)."""
    return [
        name
        for name, _ in security_loosenings(
            sec or SecuritySettings(),
            store or StoreSettings(),
            auth or AuthSettings(),
            alerts or AlertsSettings(),
            cleartext_hops,
            expiry_hops,
            db_hops,
            None,
        )
    ]


# --- the shipped defaults themselves ---------------------------------------------------------


def test_shipped_defaults_are_the_hardened_values() -> None:
    """Both flips, pinned at the model. A default that moves back reds here first."""
    settings = ServiceSettings()
    assert settings.store.aad_bind is True
    assert settings.auth.ad_session_recheck_seconds == 300


def test_the_shipped_defaults_are_not_themselves_loosenings() -> None:
    """The whole point: at the shipped defaults the registry reports NOTHING. If a hardened default
    were reported as a deviation, the list would be noise and operators would stop reading it."""
    assert _names() == []


# --- [store].aad_bind ------------------------------------------------------------------------


def test_aad_bind_off_is_a_named_loosening() -> None:
    named = dict(
        security_loosenings(
            SecuritySettings(),
            StoreSettings(aad_bind=False),
            AuthSettings(),
            AlertsSettings(),
            (),
            (),
            (),
            None,
        )
    )
    assert "aad_bind" in named
    # The risk text must say what is actually lost — cell binding, i.e. at-rest INTEGRITY binding — not
    # merely that a switch is off. An operator reading the serve warning gets this sentence and nothing
    # else; "aad_bind is false" would tell them nothing they did not already know.
    assert "cell" in named["aad_bind"]


def test_aad_bind_loosening_names_its_no_op_caveat() -> None:
    """It is a genuine no-op without a store key (the identity cipher has no tag to bind), and the risk
    text says so. Reporting it as a live weakness on a keyless dev box would train operators to ignore
    the list — the failure mode a loosening registry can least afford."""
    named = dict(
        security_loosenings(
            SecuritySettings(),
            StoreSettings(aad_bind=False),
            AuthSettings(),
            AlertsSettings(),
            (),
            (),
            (),
            None,
        )
    )
    assert "no effect without a store key" in named["aad_bind"]


# --- [auth].ad_session_recheck_seconds -------------------------------------------------------


def test_recheck_zero_with_ad_enabled_is_a_named_loosening() -> None:
    auth = _ad(ad_session_recheck_seconds=0)
    named = dict(
        security_loosenings(
            SecuritySettings(), StoreSettings(), auth, AlertsSettings(), (), (), (), None
        )
    )
    assert "ad_session_recheck_seconds" in named
    assert "revocation" in named["ad_session_recheck_seconds"]


def test_recheck_zero_without_ad_is_NOT_a_loosening() -> None:
    """CONDITIONAL, like allowed_client_networks. With no directory to reconcile against, 0 is not a
    weaker choice — it is the only meaningful one.

    This is the detector-can-fire half of the guard: a rule that fired on every non-AD deployment would
    be a permanent false positive, and a permanently-true warning is read as noise, not as signal."""
    assert "ad_session_recheck_seconds" not in _names(
        auth=AuthSettings(ad_session_recheck_seconds=0)
    )


def test_recheck_at_the_default_with_ad_enabled_is_not_a_loosening() -> None:
    assert "ad_session_recheck_seconds" not in _names(auth=_ad())


# --- the cross-field refusal, keyed on model_fields_set ---------------------------------------
#
# These go through load_settings, NOT the constructor. Constructing AuthSettings(...) in Python marks
# every passed field as "set", so a constructor-only test cannot distinguish the shipped default from an
# explicitly-typed 300 — which is the entire distinction the guard turns on. It would pass while proving
# nothing.


def _load(tmp_path: Path, toml: str) -> ServiceSettings:
    path = tmp_path / "messagefoundry.toml"
    path.write_text(toml, encoding="utf-8")
    return load_settings(config_path=path)


def test_shipped_default_does_not_break_a_non_ad_deployment(tmp_path: Path) -> None:
    """The reason the refusal had to be re-keyed: with a non-zero SHIPPED default, an unconditional
    'requires ad_enabled' rule would fail startup on every deployment that does not use AD."""
    # `local_users` was not an AuthSettings field, so this fixture used to say nothing at all — the very
    # silence the unknown-key refusal now removes. `ad_enabled = false` states "no AD" in a real field.
    settings = _load(tmp_path, "[auth]\nad_enabled = false\n")
    assert settings.auth.ad_session_recheck_seconds == 300
    assert settings.auth.ad_enabled is False


def test_explicit_value_without_ad_still_refuses(tmp_path: Path) -> None:
    """THE test that proves the guard still bites. An operator who typed a value believes directory
    revocation now propagates; a silently-dead security control is worse than one never enabled.

    Note the value is the SAME as the shipped default — so this can only pass if the check keys on
    `model_fields_set` rather than on the value."""
    with pytest.raises(ValueError, match="ad_session_recheck_seconds requires ad_enabled"):
        _load(tmp_path, "[auth]\nad_session_recheck_seconds = 300\n")


def test_explicit_zero_without_ad_loads(tmp_path: Path) -> None:
    """Explicitly disabling the loop on a non-AD box is coherent, not an error — there is nothing to
    reconcile, and the operator has asserted no belief the refusal needs to falsify."""
    settings = _load(tmp_path, "[auth]\nad_session_recheck_seconds = 0\n")
    assert settings.auth.ad_session_recheck_seconds == 0


# --- registry completeness --------------------------------------------------------------------


def test_every_security_bool_at_its_insecure_value_is_reported() -> None:
    """A COMPLETENESS FLOOR for the registry, which otherwise has none.

    Nothing else asserts that `security_loosenings()` can SEE every switch. Under "one posture, loosen
    only", a registry with no floor is the leak-gate-blindness shape: a switch added later at an insecure
    value would simply never be reported, and the green list would keep saying "no deviations".

    Scope, stated honestly: this covers the BOOLEAN `[security]` switches whose insecure value is the
    negation of their default — the mechanical majority. Non-boolean knobs (timeouts, day counts) and the
    deliberately-conditional entries have their own targeted tests above and below; they are listed here
    as exemptions so the exemption itself is visible rather than an accident of the loop."""
    #: Bools this floor deliberately does NOT require, each with the reason it is exempt.
    exempt = {
        # `audit_all_authorization_decisions` USED TO SIT HERE, and its removal is the point of BACKLOG
        # #1277 rather than a tidy-up. The reason it carried was "turning it ON is the hardening move,
        # not the loosening" — true only while the default was `false`. The default is `true` now, so
        # `false` is the insecure value and the loop below requires the registry to name it.
        # ADR 0152: these ASSERT / REQUIRE a host property rather than giving one up. Neither is a
        # loosening at either value; both are documented as such.
        "memory_encryption_operator_declared",
        "require_memory_encryption_declaration",
        # ADR 0143: disabling the console SHRINKS attack surface — the opposite of a loosening.
        "serve_web_console",
        # The data-class lever has its own entry keyed on the derived posture, not a plain negation.
        "handles_real_patient_data",
        "production_instance",
    }
    for field, info in SecuritySettings.model_fields.items():
        if field in exempt or not isinstance(info.default, bool):
            continue
        flipped = SecuritySettings(**{field: not info.default})
        assert field in _names(sec=flipped), (
            f"[security].{field} at its insecure value ({not info.default}) is NOT named by "
            "security_loosenings(). Add it to the registry, or add it to this test's `exempt` set "
            "with the reason it is not a loosening — silence is not an option."
        )


#: Every per-connection parameter name the connection-factory census below classifies, mapped to the
#: reader that reports it. #333 step 7: the `[security]`/`[store]`/`[auth]` floors iterate
#: `model_fields`, so a CONNECTION-scoped deviation is outside their reach BY CONSTRUCTION — which is
#: exactly why `cleartext_accepted` needed a hand-written entry, why `tls_allow_expired` and the
#: generic-ODBC hop had none for as long as they did, and why nothing would have caught the next one.
_CONNECTION_DEVIATIONS_REPORTED = {
    "cleartext_accepted": "accepted_cleartext_hops",
    "tls_allow_expired": "expiry_relaxed_hops",
}

#: Per-connection parameters the readers do NOT report, each with the reason. Same discipline as the
#: `[store]`/`[auth]` exemption sets: the gap is a written decision a new parameter cannot silently
#: join, not an accident of a regex.
_CONNECTION_DEVIATIONS_EXEMPT = {
    # Not switches — the reason string beside a declaration, and TLS key/cert material or paths.
    "cleartext_reason": "the reason text for cleartext_accepted, not a second switch",
    "tls_cert_file": "material/path, not a posture switch",
    "tls_key_file": "material/path, not a posture switch",
    "tls_key_password": "material/path, not a posture switch",
    "tls_ca_file": "material/path, not a posture switch",
    # BACKLOG #1005 added this one. It is exempt for BOTH of the reasons already used above, and
    # stating only the first would be the weaker half: it is a material PATH like tls_ca_file
    # beside it, AND its ABSENCE is GATED rather than reported -- check_inbound_revocation refuses
    # an mTLS listener with no CRL on an enforcing PHI instance, the same way the ADR 0092 hop cell
    # gates tls/tls_verify below. A reader that merely reported "no CRL configured" would be strictly
    # weaker than the refusal that already exists.
    "tls_crl_file": "material/path; its absence is gated by #1005's posture-keyed revocation refusal",
    # Not TLS at all — the regex matches the word 'verify' in an HL7 ACK correlation check.
    "verify_ack_control_id": "HL7 ACK control-id correlation, unrelated to transport TLS",
    # Verify-off and TLS-off are GATED rather than reported: the ADR 0092 posture-keyed cell refuses
    # them on a production-PHI hop unless attested, and ADR 0153's cleartext_accepted is the declared
    # escape that IS reported. A connection-scoped verify-off READER is owed work (it would report the
    # connectors' tls_verify=false the way this pass reports tls_allow_expired), recorded here rather
    # than done silently — #333 scoped itself to the expiry flag and the generic-ODBC hop.
    "tls": "TLS-off is gated by the ADR 0092 hop cell; the declared escape (cleartext_accepted) is reported",
    "use_tls": "same as tls",
    "tls_verify": "verify-off is gated by the ADR 0092 hop cell; a connection-scoped reader is owed",
    "verify_tls": "same as tls_verify",
    "tls_check_hostname": "gated by the same ADR 0092 hop cell",
    "encrypt": "SQL Server preset only — _build_dsn's posture-keyed weakened-TLS refusal gates it",
}


def test_every_per_connection_tls_parameter_is_reported_or_exempt() -> None:
    """The CONNECTION-scoped completeness floor (#333 step 7).

    The floors above iterate `SecuritySettings` / `StoreSettings` / `AuthSettings` `model_fields`, and a
    per-connection deviation lives in none of those — it is a keyword argument on a connection factory
    that lands in `spec.settings`. So this floor censuses the FACTORIES instead: every parameter whose
    name is TLS-shaped must be either reported by one of the connection-scoped readers or exempt with a
    written reason. A new one is a test failure rather than a re-audit three months later."""
    import inspect
    import re

    from messagefoundry.config import wiring

    shaped = re.compile(r"tls|ssl|cleartext|verify|insecure|encrypt", re.IGNORECASE)
    census: dict[str, list[str]] = {}
    for name in wiring.__all__:
        obj = getattr(wiring, name, None)
        if not callable(obj):
            continue
        try:
            sig = inspect.signature(obj)
        except (
            TypeError,
            ValueError,
        ):  # builtins / C-level callables have no introspectable signature
            continue
        params = [p for p in sig.parameters if shaped.search(p)]
        if params:
            census[name] = params

    # LIVE POSITIVE CONTROL. A census that silently stopped seeing anything — a renamed `__all__`, an
    # import that started failing, a regex typo — would make every assertion below vacuously true. This
    # is the blindness guard: name factories that certainly carry these parameters and require them.
    assert {"MLLP", "Rest", "FHIR", "Soap", "Ftp", "DICOM"} <= set(census), sorted(census)
    for factory in ("MLLP", "Rest", "FHIR", "Soap", "Ftp", "DICOM"):
        assert "tls_allow_expired" in census[factory], (factory, census[factory])

    classified = set(_CONNECTION_DEVIATIONS_REPORTED) | set(_CONNECTION_DEVIATIONS_EXEMPT)
    unclassified = {p for params in census.values() for p in params} - classified
    assert not unclassified, (
        f"per-connection parameter(s) {sorted(unclassified)} are TLS-shaped and are neither reported "
        "by a connection-scoped reader nor exempt with a reason. Report them (extend "
        "config.wiring's readers and security_loosenings), or add them to "
        "_CONNECTION_DEVIATIONS_EXEMPT with the reason — silence is not an option. "
        f"Scanned {len(census)} factories: "
        + "; ".join(f"{k}({', '.join(v)})" for k, v in sorted(census.items()))
    )


def test_the_reported_connection_deviations_are_actually_wired() -> None:
    """The other half of the floor: the map above claims two parameters are REPORTED, and a claim that
    nothing executes is exactly what this lane exists to prevent. Drive each through its reader AND
    through `security_loosenings`, so "reported" means reported."""
    from messagefoundry.config.models import ConnectorType
    from messagefoundry.config.wiring import (
        ConnectionSpec,
        Registry,
        accepted_cleartext_hops,
        build_outbound_connection,
        expiry_relaxed_hops,
    )

    reg = Registry()
    reg.add_outbound(
        build_outbound_connection(
            "OB_EXPIRED",
            ConnectionSpec(
                type=ConnectorType.MLLP,
                settings={"host": "h", "port": 1, "tls_allow_expired": True},
            ),
        )
    )
    reg.add_outbound(
        build_outbound_connection(
            "OB_CLEAR",
            ConnectionSpec(type=ConnectorType.TCP, settings={"host": "h", "port": 2}),
            cleartext_accepted=True,
            cleartext_reason="vendor firmware predates TLS",
        )
    )
    assert _CONNECTION_DEVIATIONS_REPORTED["tls_allow_expired"] == "expiry_relaxed_hops"
    assert _CONNECTION_DEVIATIONS_REPORTED["cleartext_accepted"] == "accepted_cleartext_hops"
    names = _names(
        expiry_hops=tuple(n for n, _ in expiry_relaxed_hops(reg)),
        cleartext_hops=tuple(n for n, _ in accepted_cleartext_hops(reg)),
    )
    assert "tls_allow_expired" in names and "cleartext_accepted" in names


# --- the API surface: GET /security/posture reports store + auth deviations --------------------


async def _posture_body(engine: Engine, **state: object) -> dict[str, object]:
    app = create_app(engine, allow_no_auth=True)
    for key, value in state.items():
        setattr(app.state, key, value)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://t") as client:
        resp = await client.get("/security/posture")
    assert resp.status_code == 200
    body: dict[str, object] = resp.json()
    return body


@pytest.fixture
async def engine(tmp_path: Path):  # type: ignore[no-untyped-def]
    eng = await Engine.create(tmp_path / "posture.db", poll_interval=0.02)
    yield eng
    await eng.stop()


async def test_posture_route_reports_the_store_deviation(engine: Engine) -> None:
    body = await _posture_body(engine, store_settings=StoreSettings(aad_bind=False))
    switches = [entry["switch"] for entry in body["loosenings"]]  # type: ignore[index,union-attr]
    assert "aad_bind" in switches


async def test_posture_route_reports_the_auth_deviation(engine: Engine) -> None:
    body = await _posture_body(engine, auth_settings=_ad(ad_session_recheck_seconds=0))
    switches = [entry["switch"] for entry in body["loosenings"]]  # type: ignore[index,union-attr]
    assert "ad_session_recheck_seconds" in switches


async def test_posture_route_reports_nothing_at_the_shipped_defaults(engine: Engine) -> None:
    """The route must be quiet on a default instance, or its signal is worthless."""
    body = await _posture_body(engine)
    assert body["loosenings"] == []


# --- the ONE connection-scoped deviation (ADR 0153) --------------------------------------------


def test_cleartext_accepted_is_a_named_loosening() -> None:
    """ADR 0153's per-connection declaration MUST surface in the same registry as the settings
    switches. It is a deviation from the one shipped posture, and a deviation the registry cannot see is
    a second posture by the back door."""
    named = dict(
        security_loosenings(
            SecuritySettings(),
            StoreSettings(),
            AuthSettings(),
            AlertsSettings(),
            ("OB_LEGACY", "OB_LAB"),
            (),
            (),
            None,
        )
    )
    assert "cleartext_accepted" in named
    risk = named["cleartext_accepted"]
    # It must NAME the connections. "some connections cross a cleartext hop" is not actionable — an
    # operator has to know WHICH, because the remedy is per-connection.
    assert "OB_LEGACY" in risk and "OB_LAB" in risk
    assert "2 connection(s)" in risk


def test_no_declared_hops_is_not_a_loosening() -> None:
    assert "cleartext_accepted" not in _names(cleartext_hops=())
    assert "tls_allow_expired" not in _names(expiry_hops=())
    assert "generic_odbc_tls_unenforced" not in _names(db_hops=())


# --- the two OTHER connection-scoped deviations (#333) -----------------------------------------


def test_expiry_relaxation_is_a_named_loosening() -> None:
    """#333(a). ``tls_allow_expired`` reached NO reporting surface: it was absent from
    ``config/settings.py``, ``api/app.py``, ``checks.py`` and ``__main__.py``, so an auditor querying
    ``GET /security/posture`` got a list that said nothing about it. The one thing that fired was a
    construction log line, and a log line emitted once at startup is not what anyone reads later."""
    named = dict(
        security_loosenings(
            SecuritySettings(),
            StoreSettings(),
            AuthSettings(),
            AlertsSettings(),
            (),
            ("OB_PARTNER_ADT", "OB_LAB_ORU"),
            (),
            None,
        )
    )
    assert "tls_allow_expired" in named
    risk = named["tls_allow_expired"]
    assert "OB_PARTNER_ADT" in risk and "OB_LAB_ORU" in risk
    # BOTH halves. Omitting the mitigation would overstate it into verify-off (ADR 0094 ORs exactly one
    # flag); omitting the risk would leave an operator thinking a lapsed bridge closes itself.
    assert "EXPIRED" in risk
    assert "nothing that expires the relaxation" in risk
    assert "hostname" in risk and "chain" in risk


def test_generic_odbc_unenforced_tls_is_a_named_loosening() -> None:
    """#333(b). ADR 0092 accepted the generic-ODBC delegation on the strength of ONE mitigation —
    "construction logs it". That mitigation was defeatable (the detector was value-blind), anonymous,
    and lived in a log stream rather than any surface a reviewer reads. This is the surface."""
    named = dict(
        security_loosenings(
            SecuritySettings(),
            StoreSettings(),
            AuthSettings(),
            AlertsSettings(),
            (),
            (),
            ("OB_PG_RESULTS", "inbound:IB_PG_ORDERS"),
            None,
        )
    )
    assert "generic_odbc_tls_unenforced" in named
    risk = named["generic_odbc_tls_unenforced"]
    assert "OB_PG_RESULTS" in risk and "inbound:IB_PG_ORDERS" in risk
    # The DSN credential rides the same hop as the rows; an operator weighing the risk needs both.
    assert "credential" in risk and "plaintext" in risk


def test_expiry_relaxed_hops_reads_the_graph() -> None:
    """The shared reader. The flag lands in ``spec.settings`` (six outbound factories take it), NOT in a
    typed ``OutboundConnection`` field like ``cleartext_accepted`` — so a reader copied from its sibling
    without noticing that would report every graph as clean."""
    from messagefoundry.config.models import ConnectorType
    from messagefoundry.config.wiring import (
        ConnectionSpec,
        Registry,
        build_outbound_connection,
        expiry_relaxed_hops,
    )

    reg = Registry()
    reg.add_outbound(
        build_outbound_connection(
            "OB_STRICT",
            ConnectionSpec(
                type=ConnectorType.MLLP,
                settings={"host": "a.example", "port": 1, "tls_allow_expired": False},
            ),
        )
    )
    reg.add_outbound(
        build_outbound_connection(
            "OB_BRIDGE",
            ConnectionSpec(
                type=ConnectorType.MLLP,
                settings={"host": "b.example", "port": 2, "tls_allow_expired": True},
            ),
        )
    )
    assert expiry_relaxed_hops(reg) == [("OB_BRIDGE", "b.example:2")]


def test_expiry_relaxed_hops_never_leaks_a_url_credential() -> None:
    """These labels land in ``GET /security/posture``. A REST/SOAP/FHIR outbound's peer is a ``url``,
    which can carry ``user:password@`` userinfo — the exact hole #1207 closed on the metadata
    serializers. An unresolved ``env()`` shows its KEY, never a resolved value, for the same reason."""
    from messagefoundry.config.models import ConnectorType
    from messagefoundry.config.wiring import (
        ConnectionSpec,
        Registry,
        build_outbound_connection,
        env,
        expiry_relaxed_hops,
    )

    reg = Registry()
    reg.add_outbound(
        build_outbound_connection(
            "OB_REST",
            ConnectionSpec(
                type=ConnectorType.REST,
                settings={
                    "url": "https://svc:hunter2@api.example/ingest",
                    "tls_allow_expired": True,
                },
            ),
        )
    )
    reg.add_outbound(
        build_outbound_connection(
            "OB_ENV",
            ConnectionSpec(
                type=ConnectorType.MLLP,
                settings={"host": env("partner_host"), "port": 7, "tls_allow_expired": True},
            ),
        )
    )
    peers = dict(expiry_relaxed_hops(reg))
    assert "hunter2" not in peers["OB_REST"]
    assert peers["OB_REST"] == "https://svc:***@api.example/ingest"
    assert peers["OB_ENV"] == "env(partner_host):7"


def test_unverified_generic_db_hops_walks_inbound_as_well_as_outbound() -> None:
    """``accepted_cleartext_hops`` reads outbound + FHIR lookups; a ``DatabasePoll`` INBOUND crosses the
    same generic hop, in the same dialect, with the same credential in the same DSN. Reading only
    outbound would report a live unenforced hop as absent — the failure this whole registry exists to
    prevent."""
    from messagefoundry.config.wiring import (
        Database,
        DatabasePoll,
        Registry,
        build_inbound_connection,
        build_outbound_connection,
        unverified_generic_db_hops,
    )

    reg = Registry()
    reg.add_outbound(
        build_outbound_connection(
            "OB_PG_OK",
            Database(
                server="ok.example",
                dialect="generic",
                odbc_driver="PostgreSQL Unicode",
                statement="INSERT INTO t (a) VALUES (:a)",
                odbc_params={"SSLmode": "verify-full"},
            ),
        )
    )
    reg.add_outbound(
        build_outbound_connection(
            "OB_PG_BARE",
            Database(
                server="bare.example",
                dialect="generic",
                odbc_driver="PostgreSQL Unicode",
                statement="INSERT INTO t (a) VALUES (:a)",
            ),
        )
    )
    reg.add_outbound(
        build_outbound_connection(
            "OB_SQLSERVER",
            Database(
                server="ss.example",
                database="MFDB",
                statement="INSERT INTO t (a) VALUES (:a)",
            ),
        )
    )
    reg.add_inbound(
        build_inbound_connection(
            "IB_PG_ORDERS",
            DatabasePoll(
                server="poll.example",
                dialect="generic",
                odbc_driver="PostgreSQL Unicode",
                poll_statement="SELECT 1",
                odbc_params={"SSLmode": "disable"},
            ),
            router="R",
        )
    )
    hops = dict(unverified_generic_db_hops(reg))
    # The sqlserver dialect is NOT here: it keeps the byte-identical posture-keyed refusal, so it is
    # gated rather than merely reported, and listing it would be noise.
    assert set(hops) == {"OB_PG_BARE", "inbound:IB_PG_ORDERS"}
    assert "no TLS keyword" in hops["OB_PG_BARE"]
    # The value-blind detector fixed in step 1 is what makes this arm real: `SSLmode=disable` used to
    # read as "the operator has taken TLS ownership".
    assert "SSLmode=disable" in hops["inbound:IB_PG_ORDERS"]


def test_accepted_cleartext_hops_reads_the_graph() -> None:
    """The single shared reader — `messagefoundry check` and the API posture route both use it, so the
    two can never report different accepted sets."""
    from messagefoundry.config.models import ConnectorType
    from messagefoundry.config.wiring import (
        ConnectionSpec,
        Registry,
        accepted_cleartext_hops,
        build_outbound_connection,
    )

    reg = Registry()
    reg.add_outbound(
        build_outbound_connection(
            "OB_PLAIN", ConnectionSpec(type=ConnectorType.TCP, settings={"host": "x", "port": 1})
        )
    )
    reg.add_outbound(
        build_outbound_connection(
            "OB_LEGACY",
            ConnectionSpec(type=ConnectorType.TCP, settings={"host": "y", "port": 2}),
            cleartext_accepted=True,
            cleartext_reason="vendor firmware predates TLS",
        )
    )
    assert accepted_cleartext_hops(reg) == [("OB_LEGACY", "vendor firmware predates TLS")]


async def test_posture_route_reports_declared_cleartext_hops(engine: Engine) -> None:
    """The surface the owner named explicitly. The route reads the LIVE graph off the engine's registry
    runner, so a reload is reflected rather than a startup snapshot going stale."""
    from messagefoundry.config.models import ConnectorType
    from messagefoundry.config.wiring import ConnectionSpec, Registry, build_outbound_connection

    reg = Registry()
    reg.add_outbound(
        build_outbound_connection(
            "OB_LEGACY",
            ConnectionSpec(type=ConnectorType.TCP, settings={"host": "127.0.0.1", "port": 5099}),
            cleartext_accepted=True,
            cleartext_reason="vendor firmware predates TLS",
        )
    )
    engine.add_registry(reg)
    body = await _posture_body(engine)
    entry = next(
        e
        for e in body["loosenings"]  # type: ignore[union-attr]
        if e["switch"] == "cleartext_accepted"  # type: ignore[index]
    )
    assert "OB_LEGACY" in entry["risk"]  # type: ignore[index]


def test_declared_fhir_lookup_read_hops_are_named_too() -> None:
    """A ``FhirLookup`` is a connection that crosses a PHI-bearing read hop, and the read executor
    honours the declaration — so if this reader skipped ``registry.fhir_lookups`` a live cleartext hop
    would cross while `check`, `security_loosenings()` and `GET /security/posture` all reported the
    accepted set as EMPTY. That is precisely "a deviation the registry cannot see"."""
    from messagefoundry.config import wiring
    from messagefoundry.config.wiring import FhirLookup, Registry, accepted_cleartext_hops

    reg = Registry()
    prev = wiring._active
    wiring._active = reg
    try:
        FhirLookup("quiet", url="https://fhir.example.org/fhir")
        FhirLookup(
            "legacy",
            url="http://fhir.example.org/fhir",
            cleartext_accepted=True,
            cleartext_reason="on-prem facade has no TLS listener",
        )
    finally:
        wiring._active = prev
    assert accepted_cleartext_hops(reg) == [
        ("fhir_lookup:legacy", "on-prem facade has no TLS listener")
    ]


def test_fhir_lookup_declaration_is_load_validated() -> None:
    """The factory is the ONE authoring surface, so the flag/reason coherence rule must fire there.

    Before this, the only way to declare it on a lookup was mutating ``spec.settings`` by hand — an
    escape with no validation and nothing for the registry to name."""
    from messagefoundry.config import wiring
    from messagefoundry.config.wiring import FhirLookup, Registry, WiringError

    reg = Registry()
    prev = wiring._active
    wiring._active = reg
    try:
        with pytest.raises(WiringError, match="requires cleartext_reason"):
            FhirLookup("x", url="http://f.example.org/fhir", cleartext_accepted=True)
        with pytest.raises(WiringError, match="without cleartext_accepted"):
            FhirLookup("y", url="http://f.example.org/fhir", cleartext_reason="why")
        with pytest.raises(WiringError, match="must be non-empty"):
            FhirLookup(
                "z",
                url="http://f.example.org/fhir",
                cleartext_accepted=True,
                cleartext_reason="   ",
            )
    finally:
        wiring._active = prev


def test_every_store_and_auth_bool_is_reported_or_exempt() -> None:
    """The completeness floor, extended over the two OTHER sections this registry reaches into.

    The floor above covers ``[security]`` only. Without this one, the registry's reach into
    ``[store]``/``[auth]`` would be exactly the leak-gate-blindness shape one section over: a green
    "no deviations" that has never looked. The exemption set below is the honest part — it enumerates
    the switches that are NOT reported today, so the gap is a written decision rather than an
    accident, and a NEW switch in either section cannot silently join it."""
    #: Not reported by security_loosenings() today. Each is gated elsewhere; extending the registry
    #: over them is real work with its own SECURITY-LOOSENING.md entries, and is recorded as owed
    #: rather than done silently here. A new field in either section reds this test until it is
    #: either reported or added here with a reason.
    exempt_store = {
        # Not security switches at all — FIFO-claim performance levers and pool knobs.
        "fifo_claim_fold_reset",
        "fifo_claim_proc",
        "fifo_claim_prepared",
        "multi_subnet_failover",
        "warm_pool",
        # HARDENINGS at their non-default value (turning them ON tightens), so a flip is not a loosening.
        "require_encryption",
        "require_managed_identity",
        # #1008: turning it ON adds a REFUSAL on an over-granted / unobservable store principal. The
        # deviation it acts on IS reported — as the OBSERVATION passed in `store_privilege`, not as
        # this switch — so it stays visible either way, and reporting the switch would make a
        # hardening read as a weakening.
        "require_least_privilege",
        # Security-relevant and gated ELSEWHERE, not by this registry. Extending it over them is real
        # work with its own SECURITY-LOOSENING.md entries — recorded as owed, not done silently.
        "encrypt",  # the keyless-PHI serve gate refuses it in its own right
        "trust_server_certificate",  # gated by weakened_tls_escape_permitted (the ADR 0092 clamp)
        "allow_unencrypted_phi",  # reported via [security].allow_unencrypted_phi (ADR 0118 move)
    }
    exempt_auth = {
        # HARDENINGS / topology choices — a flip is not a weakening of the shipped posture.
        "require_action_step_up",
        "admin_new_ip_step_up",
        "ad_enabled",
        "ad_use_nested_groups",
        "kerberos_enabled",
        "oidc_enabled",
        "oidc_username_strip_domain",
        "notify_security_events",
        # Password-policy composition rules: individually neither secure nor insecure (the policy is
        # scored as a whole), and none is a posture switch.
        "password_require_uppercase",
        "password_require_lowercase",
        "password_require_digit",
        "password_require_symbol",
        "password_check_context",
        "password_check_username",
        "password_check_breached",
        # Security-relevant and gated ELSEWHERE, not by this registry — same owed note as [store].
        "enabled",  # the serve-time exposed-gates refuse an exposed auth-off instance outright
        "require_mfa",  # refused at exposure by the __main__ posture gates
        "ad_tls_verify",  # gated by weakened_tls_escape_permitted
        "ad_allow_insecure_ldap",  # gated by the same clamp
        "oidc_require_mfa_claim",  # gated by the OIDC serve gate
        "login_rate_limit_enabled",  # DoS hardening with its own serve-time defaults
        "phi_read_rate_limit_enabled",
        "admin_write_rate_limit_enabled",
    }
    for model, exempt, section in (
        (StoreSettings, exempt_store, "store"),
        (AuthSettings, exempt_auth, "auth"),
    ):
        for field, info in model.model_fields.items():
            if field in exempt or not isinstance(info.default, bool):
                continue
            flipped = model(**{field: not info.default})  # type: ignore[arg-type]
            kwargs = {"store": flipped} if section == "store" else {"auth": flipped}
            assert field in _names(**kwargs), (  # type: ignore[arg-type]
                f"[{section}].{field} at its insecure value ({not info.default}) is NOT named by "
                "security_loosenings(). Add it to the registry, or add it to this test's exemption "
                "set with the reason — silence is not an option."
            )


async def test_posture_route_declares_its_scope_when_no_graph_is_loaded(engine: Engine) -> None:
    """An engine with no registry runner cannot see the connection-scoped declarations, so it SAYS so.

    Reporting a settings-only list with no marker is the failure this whole lane exists to prevent:
    a subset that reads as the whole posture. `security show` carries the same marker for the same
    reason, and this pins that the route does not quietly differ from it."""
    body = await _posture_body(engine)
    assert body["loosenings_scope"] is not None
    assert "cleartext_accepted" in str(body["loosenings_scope"])


async def test_posture_route_scope_is_none_once_a_graph_is_loaded(engine: Engine) -> None:
    """The complementary arm — the marker must CLEAR, or it degrades into permanent noise."""
    from messagefoundry.config.wiring import Registry

    engine.add_registry(Registry())
    body = await _posture_body(engine)
    assert body["loosenings_scope"] is None


async def test_managed_app_stashes_auth_settings_for_the_registry(tmp_path: Path) -> None:
    """Drive the REAL wiring: `create_managed_app` must stash `auth_settings` on app.state, or the
    route silently falls back to `AuthSettings()` defaults and the auth deviation is never reported.

    The targeted route test above sets `app.state.auth_settings` by hand, so it cannot fail if the
    stash regresses. This one goes through the lifespan, which is the only thing that proves the
    production path is wired."""
    from messagefoundry.api import create_managed_app

    app = create_managed_app(
        db_path=tmp_path / "managed_posture.db",
        poll_interval=0.05,
        # enabled=False so the route stays reachable without a session; the stash is deliberately
        # OUTSIDE the `enabled` guard, and that is exactly what this pins — a settings object that
        # exists but is disabled is still the resolved settings the registry must read.
        auth_settings=_ad(ad_session_recheck_seconds=0, enabled=False),
    )
    transport = httpx.ASGITransport(app=app)
    async with (
        httpx.AsyncClient(transport=transport, base_url="http://t") as client,
        app.router.lifespan_context(app),
    ):
        resp = await client.get("/security/posture")
    assert resp.status_code == 200
    switches = [entry["switch"] for entry in resp.json()["loosenings"]]
    assert "ad_session_recheck_seconds" in switches
