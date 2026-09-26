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
from messagefoundry.config.wiring import (
    Registry,
    _peer_label,
    load_config,
    static_credential_db_hops,
)

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
    assert "SEKRIT" not in hop.detail and "frag" not in hop.detail
    # The path goes too: a webhook path can itself be the secret. Scheme and host name the peer.
    assert "(https://a.example.invalid)" in hop.detail


# --- a detail cannot carry a secret, by construction ---------------------------------------------
#
# The reviewer's four probes against the earlier label, which masked only the password half of a
# URL's userinfo. The label now carries scheme, host and port and nothing else, and it says so with a
# fixed placeholder when the address does not parse, rather than echoing the raw string.

#: A graph whose every address carries a secret the old label let through. Each goes through a real
#: factory, so a probe the factories refuse outright would fail here rather than test nothing.
PROBE_MODULE = """
from messagefoundry import MLLP, Rest, env, outbound

# 1. A proxy URL with no scheme: the old label kept the whole password.
outbound("OB_PROBE_PROXY", Rest(url="https://p1.example.invalid/x",
    proxy="user:S3CRET@proxy.corp.invalid:3128", proxy_user="u", proxy_password=env("ppw")))
# 2. A key-only userinfo (the key is the user half): the old label kept the key.
outbound("OB_PROBE_KEY", Rest(url="https://p2.example.invalid/x",
    proxy="http://sk_live_ABC123:@proxy2.example.invalid:3128", proxy_user="u",
    proxy_password=env("ppw")))
outbound("OB_PROBE_KEY_HOST", MLLP(host="sk_live_KEY9:@mllp.example.invalid", port=2575))
# 3. A secret in the path, as a webhook URL carries one.
outbound("OB_PROBE_PATH", Rest(url="https://hooks.example.invalid/services/T/B/CAPSECRET"))
# 4. An @ in the query: the old label named b.c as the host.
outbound("OB_PROBE_QUERY_AT", Rest(url="https://api.example.invalid:8443/x?e=a@b.c"))
"""

#: Every secret-bearing fragment of the probes. None may appear in any detail.
PROBE_SECRETS = ("S3CRET", "sk_live_ABC123", "sk_live_KEY9", "CAPSECRET", "services", "b.c", "e=a")

#: What each probe's detail must still name, so a label that emitted nothing would not pass.
PROBE_PEERS = {
    "proxy:OB_PROBE_PROXY": "(proxy.corp.invalid:3128)",
    "proxy:OB_PROBE_KEY": "(http://proxy2.example.invalid:3128)",
    "OB_PROBE_KEY_HOST": "(mllp.example.invalid:2575)",
    "OB_PROBE_PATH": "(https://hooks.example.invalid)",
}


def write_probe_graph(cfg: Path) -> None:
    cfg.mkdir()
    (cfg / "feed.py").write_text(PROBE_MODULE, encoding="utf-8")


@pytest.fixture(scope="module")
def probe_hops(tmp_path_factory: pytest.TempPathFactory) -> dict[str, StaticCredentialHop]:
    cfg = tmp_path_factory.mktemp("probe_hops") / "config"
    write_probe_graph(cfg)
    hops = static_credential_hops(registry=load_config(cfg, allow_empty=True), settings=None)
    return {h.name: h for h in hops}


def test_no_probe_secret_reaches_a_detail(probe_hops: dict[str, StaticCredentialHop]) -> None:
    assert set(PROBE_PEERS) | {"OB_PROBE_QUERY_AT"} <= set(probe_hops)
    for hop in probe_hops.values():
        for secret in PROBE_SECRETS:
            assert secret not in hop.detail, hop
        assert "@" not in hop.detail and "?" not in hop.detail, hop


def test_each_probe_still_names_its_host(probe_hops: dict[str, StaticCredentialHop]) -> None:
    for name, peer in PROBE_PEERS.items():
        assert peer in probe_hops[name].detail, probe_hops[name]


def test_an_at_outside_the_authority_names_no_host(
    probe_hops: dict[str, StaticCredentialHop],
) -> None:
    """``?e=a@b.c`` and a password holding an unencoded ``/`` look the same to a parser, so the label
    names no host rather than guess. The old label named ``b.c``."""
    detail = probe_hops["OB_PROBE_QUERY_AT"].detail
    assert "api.example.invalid" not in detail and "withheld" in detail


@pytest.mark.parametrize(
    ("settings", "label"),
    [
        ({"host": "h.example.invalid", "port": 2575}, "h.example.invalid:2575"),
        ({"url": "https://a.example.invalid:8443/p?q=1#f"}, "https://a.example.invalid:8443"),
        ({"url": "https://[2001:db8::1]:443/p"}, "https://[2001:db8::1]:443"),
        ({"url": "user:S3CRET@proxy.corp.invalid:3128"}, "proxy.corp.invalid:3128"),
        ({"url": "https://sk_live_ABC123:@api.example.invalid/"}, "https://api.example.invalid"),
        ({"server": "db.example.invalid"}, "db.example.invalid"),
        ({"server": "tcp:db.example.invalid,1433"}, "db.example.invalid,1433"),
        ({"server": r"db.example.invalid\INST"}, r"db.example.invalid\INST"),
        # A database server joins its port as the DSN does, however the server was spelled.
        ({"server": "tcp:db.example.invalid", "port": 1433}, "db.example.invalid,1433"),
        ({"server": "db.example.invalid", "port": 1433}, "db.example.invalid,1433"),
        # A bare IPv6 host is what a socket takes; the label brackets it so the port stays readable.
        ({"host": "2001:db8::1", "port": 2575}, "[2001:db8::1]:2575"),
        ({"host": "::1"}, "[::1]"),
        ({}, "(unknown peer)"),
    ],
)
def test_the_label_keeps_scheme_host_and_port(settings: dict[str, object], label: str) -> None:
    assert _peer_label(settings) == label


@pytest.mark.parametrize(
    "value",
    [
        "https://user:12/34@host.example.invalid/",  # a password holding an unencoded "/"
        "https://sk_live_A?B@host.example.invalid/",  # a key holding an unencoded "?"
        "https://user%3AS3CRET%40host.example.invalid/",  # an encoded userinfo in the host
        "https://host.example.invalid:S3CRET/",  # a non-numeric port
        "not a url at all S3CRET",
        # urlsplit deletes tab, CR and LF, which would fold the text after them into the host.
        "https://host.example.invalid\tS3CRET/",
        "https://host.example.invalid\nS3CRET/",
        # No scheme means a bare authority; a path on one is a mistyped URL, not a host to name.
        "http:/S3CRET.example.invalid/x",
    ],
)
def test_an_unparseable_address_is_withheld_not_echoed(value: str) -> None:
    label = _peer_label({"url": value})
    assert "s3cret" not in label.lower() and "sk_live" not in label and "12" not in label
    assert "withheld" in label


@pytest.mark.parametrize(
    "host", ["fe80::1%user:S3CRET@x", "fe80::1%sk_live_12345", "fe80::1%\tS3CRET", "fe80::1%\x00S"]
)
def test_an_ipv6_zone_id_is_withheld(host: str) -> None:
    """``ip_address`` accepts nearly any text after ``%`` and echoes it back."""
    label = _peer_label({"host": host, "port": 2575})
    # The first case parses as a userinfo before host "x", which is dropped; the rest are withheld.
    assert "S3CRET" not in label and "sk_live" not in label and "%" not in label
    assert "\t" not in label and "\x00" not in label


def test_http_digest_is_read_from_the_mode_the_connector_reads() -> None:
    """The connector answers a Digest challenge only with ``http_auth='digest'``; the credential
    keys alone send nothing."""
    from messagefoundry.config.models import ConnectorType
    from messagefoundry.config.static_credentials import _http_static

    keys = {"http_auth_user": "u", "http_auth_password": "p"}
    assert "HTTP Digest" not in _http_static(ConnectorType.REST, keys, False)
    digest = {**keys, "http_auth": "digest"}
    assert "HTTP Digest" in _http_static(ConnectorType.REST, digest, False)


# --- review round 2: a proxy URL's userinfo, and the remote-file protocol ---------------------------

#: A proxy password that must never reach a detail.
_PROXY_PW = "PROXY-userinfo-SECRET"


def test_a_proxy_url_carrying_userinfo_is_a_static_credential_hop(tmp_path: Path) -> None:
    """urllib's ``ProxyHandler`` turns ``user:password@`` in the proxy URL into a pre-emptive
    ``Proxy-authorization: Basic`` header, so the hop presents a static credential with no
    ``proxy_user`` set. The label still carries scheme, host and port only."""
    cfg = tmp_path / "config"
    cfg.mkdir()
    (cfg / "feed.py").write_text(
        "from messagefoundry import Rest, outbound\n"
        "outbound('OB_P', Rest(url='https://a.example.invalid/x',\n"
        f"    proxy='https://puser:{_PROXY_PW}@proxy.example.invalid:3128'))\n",
        encoding="utf-8",
    )
    hops = {
        h.name: h
        for h in static_credential_hops(
            registry=load_config(cfg, allow_empty=True), settings=ServiceSettings()
        )
    }
    hop = hops["proxy:OB_P"]
    assert hop.credential == "static" and hop.compliant_kind is False
    assert "(https://proxy.example.invalid:3128)" in hop.detail
    assert _PROXY_PW not in hop.detail and "puser" not in hop.detail


def test_a_site_proxy_carrying_userinfo_is_a_hop_for_every_http_connection(tmp_path: Path) -> None:
    """The inherited ``[egress].proxy_url`` is sent by every HTTP-family connection with no proxy of
    its own, so its userinfo is presented on each of those hops."""
    cfg = tmp_path / "config"
    cfg.mkdir()
    (cfg / "feed.py").write_text(
        "from messagefoundry import Rest, outbound\n"
        "outbound('OB_S', Rest(url='https://a.example.invalid/x'))\n",
        encoding="utf-8",
    )
    registry = load_config(cfg, allow_empty=True)
    site = _settings(
        egress={
            "proxy_url": f"http://suser:{_PROXY_PW}@site.example.invalid:3128",
            "allowed_proxy": ["site.example.invalid"],
        }
    )
    hops = {h.name: h for h in static_credential_hops(registry=registry, settings=site)}
    hop = hops["proxy:OB_S"]
    assert hop.credential == "static"
    assert "(http://site.example.invalid:3128)" in hop.detail
    assert _PROXY_PW not in hop.detail and "suser" not in hop.detail
    # The control: the same site proxy without userinfo presents nothing to the proxy.
    bare = _settings(
        egress={
            "proxy_url": "http://site.example.invalid:3128",
            "allowed_proxy": ["site.example.invalid"],
        }
    )
    assert "proxy:OB_S" not in {
        h.name for h in static_credential_hops(registry=registry, settings=bare)
    }


@pytest.mark.parametrize("protocol", ["SFTP", "Sftp", None])
def test_sftp_is_classified_with_the_transports_normalisation_and_default(
    protocol: str | None,
) -> None:
    """The transport lowercases ``protocol`` and defaults it to ``sftp``. A key on an upper-case or
    missing protocol is an SSH key, not an FTP password."""
    from messagefoundry.config.models import ConnectorType
    from messagefoundry.config.static_credentials import _connection_hop

    base: dict[str, object] = {"host": "sftp.example.invalid", "remote_dir": "/in"}
    if protocol is not None:
        base["protocol"] = protocol
    key = {**base, "username": "u", "private_key": "k.pem"}
    assert _connection_hop("OB_K", ConnectorType.REMOTEFILE, key) is None
    pw = _connection_hop(
        "OB_P", ConnectorType.REMOTEFILE, {**base, "username": "u", "password": "x"}
    )
    assert pw is not None and pw.detail.startswith("SFTP password") and pw.compliant_kind is True


def test_an_upper_case_ftp_protocol_is_still_ftp() -> None:
    """The control for the case above: normalising must not turn FTP into SFTP."""
    from messagefoundry.config.models import ConnectorType
    from messagefoundry.config.static_credentials import _connection_hop

    s = {"host": "ftp.example.invalid", "protocol": "FTPS", "username": "u", "password": "x"}
    hop = _connection_hop("OB_F", ConnectorType.REMOTEFILE, s)
    assert hop is not None and hop.detail.startswith("FTP password") and hop.compliant_kind is False


#: Proxy URL shapes on both sides of urllib's parser, each with whether the engine sends a
#: credential from it.
_PROXY_SHAPES = [
    ("http://u:p@proxy.example.invalid:3128", True),
    ("https://u:p@proxy.example.invalid:3128/", True),
    ("  http://u:p@proxy.example.invalid:3128  ", True),  # the transport strips the value
    ("http://u:pa/ss@proxy.example.invalid:3128", True),  # urlsplit ends the authority at '/'
    ("http://u:pa?ss@proxy.example.invalid:3128", True),
    ("http://u:pa#ss@proxy.example.invalid:3128", True),
    ("http://u:p@x@proxy.example.invalid:3128", True),
    ("http://u@proxy.example.invalid:3128", False),  # a user with no password sends nothing
    ("http://u:@proxy.example.invalid:3128", False),
    ("http://:p@proxy.example.invalid:3128", False),
    ("http://us%40er@proxy.example.invalid:3128", False),  # an encoded '@' is not a separator
    ("http://proxy%40x.example.invalid:3128", False),
    # urllib reads everything before the '@' as userinfo, so it sends "proxy...:3128/path" as a
    # password. Surprising, but it is what goes on the wire, so it is listed.
    ("http://proxy.example.invalid:3128/path@x", True),
    ("http://proxy.example.invalid:3128", False),
    ("http://u:p@[::1:3128", False),  # malformed: the transport refuses it at build
    ("u:p@proxy.example.invalid:3128", False),  # scheme 'u': refused, not http(s)
    ("socks5://u:p@proxy.example.invalid:1080", False),
    ("default", False),
    ("", False),
]


@pytest.mark.parametrize(("url", "sent"), _PROXY_SHAPES)
def test_the_userinfo_reader_answers_what_the_engine_sends(url: str, sent: bool) -> None:
    """``ProxyHandler`` sends a header exactly when ``_parse_proxy`` yields a user and a password,
    and the transport reaches the handler only for an http(s) URL it can parse. The reader calls a
    private stdlib function, so the shapes where it matters are pinned here."""
    from messagefoundry.config.static_credentials import _proxy_url_sends_userinfo

    assert _proxy_url_sends_userinfo(url) is sent


def test_the_reader_pairs_with_urllibs_own_parser() -> None:
    """The control for the pin above: on every shape the transport would build, the reader agrees
    with ``_parse_proxy`` run on the stripped value, which is what the handler receives."""
    import urllib.parse
    import urllib.request

    from messagefoundry.config.static_credentials import _proxy_url_sends_userinfo

    for url, _ in _PROXY_SHAPES:
        proxy = url.strip()
        try:
            if urllib.parse.urlsplit(proxy).scheme not in ("http", "https"):
                continue
        except ValueError:
            continue
        _, user, password, _ = urllib.request._parse_proxy(proxy)  # type: ignore[attr-defined]
        assert _proxy_url_sends_userinfo(url) is bool(user and password), url


def test_a_malformed_proxy_url_never_crashes_the_reader() -> None:
    """``urlsplit`` raises on an unclosed IPv6 bracket. The single reader must not, or ``check``,
    the posture view and the reload guard all fail. With a keyed credential the hop is still listed,
    so the label path runs on the malformed URL too, and withholds it."""
    from messagefoundry.config.static_credentials import _proxy_hop

    assert _proxy_hop("OB", {"proxy_url": "http://[::1:3128"}, "") is None
    keyed = {
        "proxy_url": f"http://u:{_PROXY_PW}@[::1:3128",
        "proxy_user": "pu",
        "proxy_password": "pp",
    }
    hop = _proxy_hop("OB", keyed, "")
    assert hop is not None and _PROXY_PW not in hop.detail


def test_a_site_proxy_carrying_userinfo_reaches_a_fhir_lookup(tmp_path: Path) -> None:
    """A lookup takes no proxy of its own, so the inherited ``[egress].proxy_url`` is its only one.
    The hop is named ``proxy:fhir_lookup:<name>``, which is the name an opt-out must use."""
    cfg = tmp_path / "config"
    cfg.mkdir()
    (cfg / "feed.py").write_text(
        "from messagefoundry import FhirLookup\n"
        "FhirLookup('lk', url='https://k.example.invalid/fhir')\n",
        encoding="utf-8",
    )
    site = _settings(
        egress={
            "proxy_url": f"http://suser:{_PROXY_PW}@site.example.invalid:3128",
            "allowed_proxy": ["site.example.invalid"],
        }
    )
    hops = {
        h.name: h
        for h in static_credential_hops(registry=load_config(cfg, allow_empty=True), settings=site)
    }
    assert hops["proxy:fhir_lookup:lk"].credential == "static"
    assert _PROXY_PW not in hops["proxy:fhir_lookup:lk"].detail


def test_url_userinfo_is_basic_whatever_proxy_auth_type_says() -> None:
    """The handler sends URL userinfo as pre-emptive Basic and it replaces the engine's own header,
    so the detail names Basic even beside a Digest pair. Without userinfo the type is read the way
    the transport reads it, trimmed and lowercased."""
    from messagefoundry.config.static_credentials import _proxy_hop

    both = {
        "proxy_url": f"http://u:{_PROXY_PW}@proxy.example.invalid:3128",
        "proxy_user": "pu",
        "proxy_password": "pp",
        "proxy_auth_type": "digest",
    }
    hop = _proxy_hop("OB", both, "")
    assert hop is not None and "forward-proxy basic credential" in hop.detail
    assert _PROXY_PW not in hop.detail
    keyed = {
        "proxy_url": "http://proxy.example.invalid:3128",
        "proxy_user": "pu",
        "proxy_password": "pp",
        "proxy_auth_type": " Digest ",
    }
    hop = _proxy_hop("OB", keyed, "")
    assert hop is not None and "forward-proxy digest credential" in hop.detail
