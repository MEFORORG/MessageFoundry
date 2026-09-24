# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The engine-wide static-credential hop inventory (BACKLOG #1182, ASVS 13.2.1).

``static_credential_hops`` widens the database-only reader to every backend hop the engine dials,
against the owner's 2026-08-22 classification: ``Rest()``, ``FHIR()`` and ``FhirLookup()`` have a
compliant kind through the SMART and OAuth2 composition; ``DICOMweb()`` does not; ``Tcp()``, ``X12()``,
``File()``'s alternate-share credential and the forward-proxy hop are in the hard class.

Each fixture hop runs through the REAL factory, so a settings key renamed in ``wiring.py`` breaks a
test here rather than silently blinding the reader. Every firing case has a quiet twin: a hop that
presents a compliant credential must never be listed, and a reader that listed everything would pass
the firing half alone.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from messagefoundry.config.settings import ServiceSettings
from messagefoundry.config.static_credentials import (
    StaticCredentialHop,
    evaluate_static_credential_gate,
    static_credential_hops,
)
from messagefoundry.config.wiring import Registry, load_config, static_credential_db_hops

_MODULE = """
from messagefoundry import (
    DICOM, DICOMweb, Database, Email, FHIR, FhirLookup, File, Ftp, MLLP, Rest, Send, Sftp, Soap, Tcp,
    X12, env, handler, inbound, outbound, router,
)
from messagefoundry.transports.http_auth import with_oauth2_client_credentials
from messagefoundry.transports.smart import with_smart_backend

inbound("IB", MLLP(port=15101), router="r")

# --- FIRES --------------------------------------------------------------------------------------
outbound("OB_REST_BASIC", Rest(url="https://a.example.invalid/x", basic_user="u",
                               basic_password=env("pw")))
outbound("OB_REST_NOAUTH", Rest(url="https://b.example.invalid/x"))
outbound("OB_FHIR_BEARER", FHIR(url="https://c.example.invalid/fhir", bearer_token=env("tok")))
outbound("OB_SOAP_WS", Soap(url="https://d.example.invalid/ws", ws_username="u",
                            ws_password=env("pw"), ws_security=True, soap_version="1.2"))
outbound("OB_SOAP_BODY", Soap(url="https://q.example.invalid/ws", body_secrets={"PLACEHOLDER_a1b2c3d4e5f6": env("bs")}))
outbound("OB_DICOMWEB", DICOMweb(url="https://e.example.invalid/dw", bearer_token=env("tok")))
outbound("OB_TCP", Tcp(host="f.example.invalid", port=15102))
outbound("OB_X12", X12(host="g.example.invalid", port=15103))
outbound("OB_MLLP_PLAIN", MLLP(host="h.example.invalid", port=15104))
outbound("OB_DICOM_PLAIN", DICOM(ae_title="ME", host="i.example.invalid", port=15105))
outbound("OB_EMAIL", Email(host="smtp.example.invalid", sender="a@x.invalid",
                           recipients=["b@x.invalid"], username="u", password=env("pw")))
outbound("OB_FTP", Ftp(host="ftp.example.invalid", remote_dir="/in", username="u",
                       password=env("pw")))
outbound("OB_SFTP_PW", Sftp(host="sftp.example.invalid", remote_dir="/in", username="u",
                            password=env("pw")))
outbound("OB_FILE_SHARE", File(directory=r"\\\\share.example.invalid\\drop",
                               credential_username="svc", credential_password=env("pw")))
outbound("OB_REST_PROXY", with_oauth2_client_credentials(
    Rest(url="https://j.example.invalid/x", proxy="http://proxy.example.invalid:3128",
         proxy_user="pu", proxy_password=env("ppw")),
    token_url="https://j.example.invalid/token", client_id="c", client_secret=env("cs")))
outbound("OB_DB", Database(server="db.example.invalid", database="d",
                           statement="INSERT INTO t VALUES (:b)"))
inbound("IB_FTP_POLL", Ftp(host="ftp2.example.invalid", remote_dir="/out"), router="r")
FhirLookup("lk_basic", url="https://k.example.invalid/fhir", basic_user="u",
           basic_password=env("pw"))

# --- QUIET: a compliant credential and no static one ----------------------------------------------
outbound("OB_REST_SMART", with_smart_backend(Rest(url="https://l.example.invalid/x"),
         token_url="https://l.example.invalid/token", client_id="c", private_key=env("key")))
outbound("OB_FHIR_OAUTH", with_oauth2_client_credentials(FHIR(url="https://m.example.invalid/f"),
         token_url="https://m.example.invalid/token", client_id="c", client_secret=env("cs")))
outbound("OB_SOAP_CERT", Soap(url="https://n.example.invalid/ws", client_cert_file="c.pem",
                              client_key_file="k.pem"))
outbound("OB_MLLP_MTLS", MLLP(host="o.example.invalid", port=15106, tls=True,
                              tls_cert_file="c.pem", tls_key_file="k.pem"))
outbound("OB_SFTP_KEY", Sftp(host="sftp2.example.invalid", remote_dir="/in", username="u",
                             private_key=env("key")))
outbound("OB_FILE_LOCAL", File(directory="C:/drop"))
outbound("OB_DB_GMSA", Database(server="db2.example.invalid", database="d", auth="integrated",
                                statement="INSERT INTO t VALUES (:b)"))
# Review-round cases: each is a configuration where the key is set but the connector sends nothing.
outbound("OB_MLLP_CERT_NO_TLS", MLLP(host="r.example.invalid", port=15107, tls_cert_file="c.pem",
                                     tls_key_file="k.pem"))  # FIRES: tls off, so no cert is sent
outbound("OB_REST_HALF_BASIC", Rest(url="https://s.example.invalid/x", basic_user="u"))  # FIRES none
outbound("OB_REST_BASIC_AND_OAUTH", with_oauth2_client_credentials(
    Rest(url="https://t.example.invalid/x", basic_user="u", basic_password=env("pw")),
    token_url="https://t.example.invalid/token", client_id="c", client_secret=env("cs")))  # QUIET
outbound("OB_SOAP_WS_OFF", Soap(url="https://u.example.invalid/ws", ws_username="u",
                                client_cert_file="c.pem", client_key_file="k.pem"))  # QUIET
outbound("OB_UNDEPLOYED", Rest(url="https://v.example.invalid/x", bearer_token=env("tok")),
         deployed=False)  # QUIET: never built
outbound("OB_PROXY_CRED_NO_PROXY", with_oauth2_client_credentials(
    Rest(url="https://w.example.invalid/x", proxy_user="pu", proxy_password=env("ppw")),
    token_url="https://w.example.invalid/token", client_id="c", client_secret=env("cs")))
FhirLookup("lk_noauth", url="https://p.example.invalid/fhir")  # no auth at all


@router("r")
def route(msg):
    return ["h"]


@handler("h")
def handle(msg):
    return Send("OB_TCP", msg)
"""

_FIRES = {
    "OB_REST_BASIC",
    "OB_REST_NOAUTH",
    "OB_FHIR_BEARER",
    "OB_SOAP_WS",
    "OB_SOAP_BODY",
    "OB_DICOMWEB",
    "OB_TCP",
    "OB_X12",
    "OB_MLLP_PLAIN",
    "OB_DICOM_PLAIN",
    "OB_EMAIL",
    "OB_FTP",
    "OB_SFTP_PW",
    "OB_FILE_SHARE",
    "proxy:OB_REST_PROXY",
    "OB_DB",
    "inbound:IB_FTP_POLL",
    "fhir_lookup:lk_basic",
    "OB_MLLP_CERT_NO_TLS",
    "OB_REST_HALF_BASIC",
    # With no settings the reader cannot see [egress].proxy_url, so a proxy credential is reported.
    "proxy:OB_PROXY_CRED_NO_PROXY",
    "fhir_lookup:lk_noauth",  # a lookup with no auth presents nothing: reported as "none"
}

_QUIET = {
    "OB_REST_SMART",
    "OB_FHIR_OAUTH",
    "OB_SOAP_CERT",
    "OB_MLLP_MTLS",
    "OB_SFTP_KEY",
    "OB_FILE_LOCAL",
    "OB_DB_GMSA",
    "OB_REST_PROXY",  # its OWN hop is OAuth2; only its proxy hop is reported
    "IB",  # a listener: out of scope by design
    "OB_REST_BASIC_AND_OAUTH",  # the minted bearer replaces the Basic header on the wire
    "OB_SOAP_WS_OFF",  # ws_security off: no UsernameToken is stamped; mTLS is all that is presented
    "OB_UNDEPLOYED",
    "OB_PROXY_CRED_NO_PROXY",
}


@pytest.fixture(scope="module")
def registry(tmp_path_factory: pytest.TempPathFactory) -> Registry:
    cfg = tmp_path_factory.mktemp("static_hops") / "config"
    cfg.mkdir()
    (cfg / "feed.py").write_text(_MODULE, encoding="utf-8")
    return load_config(cfg)


@pytest.fixture(scope="module")
def graph_hops(registry: Registry) -> dict[str, StaticCredentialHop]:
    return {hop.name: hop for hop in static_credential_hops(registry=registry, settings=None)}


def test_every_firing_hop_is_reported(graph_hops: dict[str, StaticCredentialHop]) -> None:
    missing = _FIRES - set(graph_hops)
    assert not missing, sorted(missing)


def test_no_compliant_hop_is_ever_listed(graph_hops: dict[str, StaticCredentialHop]) -> None:
    listed = _QUIET & set(graph_hops)
    assert not listed, sorted(listed)


def test_the_census_is_exact(graph_hops: dict[str, StaticCredentialHop]) -> None:
    """Exact equality, so a reader that over-reports an unexpected hop goes red too."""
    assert set(graph_hops) == _FIRES


@pytest.mark.parametrize(
    ("name", "credential", "compliant_kind"),
    [
        # The owner's 2026-08-22 classification, one row per class.
        ("OB_REST_BASIC", "static", True),
        ("OB_REST_NOAUTH", "none", True),
        ("OB_FHIR_BEARER", "static", True),
        ("fhir_lookup:lk_basic", "static", True),
        ("OB_SOAP_WS", "static", True),
        ("OB_SOAP_BODY", "static", True),
        ("OB_DICOMWEB", "static", False),
        ("OB_TCP", "none", False),
        ("OB_X12", "none", False),
        ("OB_FILE_SHARE", "static", False),
        ("proxy:OB_REST_PROXY", "static", False),
        ("OB_MLLP_PLAIN", "none", True),
        ("OB_MLLP_CERT_NO_TLS", "none", True),
        ("OB_REST_HALF_BASIC", "none", True),
        ("OB_DICOM_PLAIN", "none", True),
        ("OB_EMAIL", "static", False),
        ("OB_FTP", "static", False),
        ("inbound:IB_FTP_POLL", "none", False),
        ("OB_SFTP_PW", "static", True),
        ("OB_DB", "static", True),
    ],
)
def test_each_hop_carries_its_classification(
    graph_hops: dict[str, StaticCredentialHop],
    name: str,
    credential: str,
    compliant_kind: bool,
) -> None:
    hop = graph_hops[name]
    assert (hop.credential, hop.compliant_kind) == (credential, compliant_kind)


def test_no_detail_ever_carries_a_secret(graph_hops: dict[str, StaticCredentialHop]) -> None:
    """Every credential in the fixture is an ``env()`` reference whose key names it. A detail may name
    a peer (rendered ``env(<key>)`` when unresolved) but never a credential field, so none of the
    credential keys may appear in any detail, in either rendering."""
    keys = ("pw", "tok", "ppw", "cs", "key", "bs")
    for hop in graph_hops.values():
        for key in keys:
            assert f"env({key})" not in hop.detail and f"'{key}'" not in hop.detail, hop


# --- the settings half ----------------------------------------------------------------------------


def _settings(**sections: dict[str, object]) -> ServiceSettings:
    return ServiceSettings.model_validate(sections)


def test_the_default_settings_report_nothing() -> None:
    """The negative control for the settings half: a SQLite store and nothing else configured."""
    assert static_credential_hops(registry=None, settings=ServiceSettings()) == []


def test_the_settings_hops_are_reported_with_their_classification() -> None:
    settings = _settings(
        store={
            "backend": "sqlserver",
            "server": "db.example.invalid",
            "database": "mf",
            "username": "u",
            "password": "p",
            "key_provider": "vault",
        },
        secrets={"provider": "vault"},
        alerts={
            "webhook_url": "https://hook.example.invalid/x",
            "email_smtp_host": "smtp.x",
            "email_from": "mf@x.invalid",
            # A *_secret reference is what makes the connector secret provider dial Vault at all.
            "email_password_secret": "kv/mf#smtp",
        },
    )
    hops = {h.name: h for h in static_credential_hops(registry=None, settings=settings)}
    assert (hops["settings:store"].credential, hops["settings:store"].compliant_kind) == (
        "static",
        True,
    )
    assert hops["settings:vault.store_key"].compliant_kind is False
    assert hops["settings:vault.secrets"].compliant_kind is False
    # The webhook sink declares no credential field of any kind: a "none" hop with no compliant kind.
    assert (
        hops["settings:alerts.webhook"].credential,
        hops["settings:alerts.webhook"].compliant_kind,
    ) == (
        "none",
        False,
    )
    assert hops["settings:alerts.smtp"].credential == "static"


def test_a_delegated_store_identity_is_not_listed() -> None:
    settings = _settings(
        store={"backend": "sqlserver", "server": "db", "database": "mf", "auth": "integrated"}
    )
    assert static_credential_hops(registry=None, settings=settings) == []


# --- the gate evaluation --------------------------------------------------------------------------


def _hop(name: str) -> StaticCredentialHop:
    return StaticCredentialHop(name, "static", "d", True)


def test_a_hop_with_no_opt_out_is_refused_and_one_with_an_opt_out_is_accepted() -> None:
    verdict = evaluate_static_credential_gate(
        [_hop("A"), _hop("B")], {"B": "partner offers Basic only"}
    )
    assert [h.name for h in verdict.refused] == ["A"]
    assert [(h.name, r) for h, r in verdict.accepted] == [("B", "partner offers Basic only")]
    assert verdict.unmatched == ()


def test_an_opt_out_naming_no_hop_is_reported_as_unmatched_within_its_half() -> None:
    accepted = {"OB_GONE": "r", "settings:store": "r"}
    graph = evaluate_static_credential_gate([], accepted, settings_half=False)
    assert graph.unmatched == ("OB_GONE",)
    settings = evaluate_static_credential_gate([], accepted, settings_half=True)
    assert settings.unmatched == ("settings:store",)
    assert evaluate_static_credential_gate([], accepted).unmatched == ("OB_GONE", "settings:store")


def test_the_database_arm_is_reused_not_restated(registry: Registry) -> None:
    """The database hops come from ``static_credential_db_hops`` verbatim, so the two readers cannot
    disagree about a database hop."""
    db = dict(static_credential_db_hops(registry))
    wide = {h.name: h.detail for h in static_credential_hops(registry=registry, settings=None)}
    assert db and all(wide[name] == reason for name, reason in db.items())


def test_a_proxy_credential_with_no_proxy_anywhere_is_not_a_hop(registry: Registry) -> None:
    """With the settings visible, a proxy credential and no proxy (per connection or site-wide) is
    never sent, so it is not a hop. With a site-wide proxy it is."""
    none = {h.name for h in static_credential_hops(registry=registry, settings=ServiceSettings())}
    assert "proxy:OB_PROXY_CRED_NO_PROXY" not in none
    assert "proxy:OB_REST_PROXY" in none  # its own proxy_url is set
    site = _settings(
        egress={
            "proxy_url": "http://site.example.invalid:3128",
            "allowed_proxy": ["site.example.invalid"],
        }
    )
    names = {h.name for h in static_credential_hops(registry=registry, settings=site)}
    assert "proxy:OB_PROXY_CRED_NO_PROXY" in names


def test_smtp_host_alone_is_not_a_hop() -> None:
    """Both SMTP consumers need a sender as well as a host; with no sender nothing dials."""
    settings = _settings(alerts={"email_smtp_host": "smtp.x"})
    assert static_credential_hops(registry=None, settings=settings) == []


def test_the_http_family_matches_the_runner() -> None:
    """``config`` cannot import ``pipeline``, so the tuple is restated; pin the two equal."""
    from messagefoundry.config import static_credentials
    from messagefoundry.pipeline.wiring_runner import _HTTP_FAMILY_DEST_TYPES

    assert frozenset(_HTTP_FAMILY_DEST_TYPES) == static_credentials._HTTP_FAMILY


def test_the_syslog_forwarder_is_a_hop_until_it_presents_a_client_cert() -> None:
    plain = _settings(logging={"forward_host": "siem.example.invalid"})
    names = {h.name: h for h in static_credential_hops(registry=None, settings=plain)}
    assert names["settings:logging.forward"].credential == "none"
    assert names["settings:logging.forward"].compliant_kind is True
    mtls = _settings(
        logging={
            "forward_host": "siem.example.invalid",
            "forward_protocol": "tls",
            "forward_tls_ca_file": __file__,
            "forward_tls_client_cert": __file__,
        }
    )
    assert static_credential_hops(registry=None, settings=mtls) == []


def test_a_query_string_never_reaches_a_detail(tmp_path: Path) -> None:
    """A URL query can carry a credential; the detail reaches a startup refusal and the reload log."""
    cfg = tmp_path / "config"
    cfg.mkdir()
    (cfg / "feed.py").write_text(
        "from messagefoundry import Rest, outbound\n"
        "outbound('OB_Q', Rest(url='https://a.example.invalid/x?api_key=SEKRIT#frag'))\n",
        encoding="utf-8",
    )
    (hop,) = static_credential_hops(registry=load_config(cfg, allow_empty=True), settings=None)
    assert "SEKRIT" not in hop.detail and "a.example.invalid/x" in hop.detail
