# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The harness email family: the loopback SMTP sink, the Email scenarios on the real graph, and a
Direct (S/MIME over STARTTLS) round trip on ``harness/config/direct``.

Three layers, each with a control that must fail:

* the sink alone, driven by ``smtplib`` and by a raw socket (dot-unstuffing, a refused RCPT,
  command sequencing, STARTTLS);
* the registered Email scenarios against the served ``harness/config`` graph, plus the retry count
  the 550 path takes, and two scenarios built to fail;
* the Direct graph, served on its own with trust material minted here: the sink receives an
  S/MIME enveloped-data message over STARTTLS, it decrypts with the partner's key and not with any
  other, and the signature inside verifies against the sender's key.

Every certificate and key is minted per test under ``tmp_path``; none is committed.
"""

from __future__ import annotations

import dataclasses
import smtplib
import socket
import ssl
import time
from collections.abc import Iterator
from email.message import EmailMessage
from pathlib import Path
from typing import Any

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import pkcs7

from harness import sinks
from harness.drivers.mllp import MLLPDriver
from harness.endpoints import Endpoints
from harness.scenarios import (
    SCENARIOS,
    Scenario,
    _verify_disposition,
    control_id_of,
    run_scenario,
)
from harness.scenarios.email import (
    RECIPIENT,
    REFUSED_RECIPIENT,
    SENDER,
    EmailScenario,
    body_control_id,
)
from harness.sinks import LOOPBACK, Record
from harness.sinks.email import MAX_LINE_BYTES, EmailSink, parse
from messagefoundry import pki
from messagefoundry.apiclient import EngineClient
from messagefoundry.config.wiring import EnvRef, load_config
from tests._harness_engine import (
    HARNESS_CONFIG,
    ephemeral_overrides,
    harness_egress,
    serve_harness_config,
)
from tests.test_direct_transport import _mint_ca, _mint_leaf, _write_key, _write_pem

_EMAIL_SCENARIOS = ("email_delivered", "email_rejected_recipient")


# --- the sink alone ----------------------------------------------------------------------------------


@pytest.fixture
def sink() -> Iterator[EmailSink]:
    with EmailSink(reject=["refused@harness.invalid"]) as s:
        yield s


def _converse(port: int, lines: list[bytes]) -> list[bytes]:
    """Send each line (CRLF appended) and return every reply line, greeting first."""
    replies: list[bytes] = []
    in_data = False
    with socket.create_connection((LOOPBACK, port), 5) as sock:
        reader = sock.makefile("rb")
        replies.append(reader.readline().rstrip(b"\r\n"))
        for line in lines:
            sock.sendall(line + b"\r\n")
            if in_data and line != b".":
                continue  # a body line: the server answers only the terminating dot
            while True:  # read one reply, multi-line ("250-...") included
                reply = reader.readline().rstrip(b"\r\n")
                replies.append(reply)
                if reply[3:4] != b"-":
                    break
            in_data = reply.startswith(b"354")
    return replies


def test_sink_records_the_envelope_and_the_message_as_submitted(sink: EmailSink) -> None:
    msg = EmailMessage()
    msg["From"] = "a@harness.invalid"
    msg["To"] = "b@harness.invalid"
    msg["Subject"] = "synthetic"
    msg.set_content("first line\n.a line smtplib must dot-stuff\n..two dots\n")
    with smtplib.SMTP(LOOPBACK, sink.port, timeout=5) as client:
        client.send_message(msg)
    [record] = sink.wait_for(lambda rs: len(rs) == 1, 5)
    assert record.meta["mail_from"] == "a@harness.invalid"
    assert record.meta["rcpt_to"] == "b@harness.invalid"
    assert record.meta["tls"] == "no"
    # smtplib doubled each leading dot on the wire; the sink removed exactly one, and kept the
    # CRLF line ends the wire carried.
    assert record.payload.endswith(
        b"\r\n\r\nfirst line\r\n.a line smtplib must dot-stuff\r\n..two dots\r\n"
    )
    assert str(parse(record)["Subject"]) == "synthetic"


def test_sink_unstuffs_a_raw_data_body_and_keeps_crlf_line_ends(sink: EmailSink) -> None:
    replies = _converse(
        sink.port,
        [
            b"EHLO driver.invalid",
            b"MAIL FROM:<a@harness.invalid>",
            b"RCPT TO:<b@harness.invalid>",
            b"DATA",
            b"payload-1",
            b"..leading dot",
            b"...",
            b".",
            b"QUIT",
        ],
    )
    assert replies[0].startswith(b"220 ")
    assert b"250 2.0.0 OK: queued" in replies
    assert replies[-1].startswith(b"221 ")
    [record] = sink.records()
    assert record.payload == b"payload-1\r\n.leading dot\r\n..\r\n"


def test_sink_refuses_a_configured_recipient_with_550_and_records_nothing(
    sink: EmailSink,
) -> None:
    with (
        smtplib.SMTP(LOOPBACK, sink.port, timeout=5) as client,
        pytest.raises(smtplib.SMTPRecipientsRefused) as caught,
    ):
        client.sendmail("a@harness.invalid", ["refused@harness.invalid"], b"Subject: x\r\n\r\nx")
    assert caught.value.recipients["refused@harness.invalid"][0] == 550
    assert sink.records() == []
    assert [(r.mail_from, r.recipient) for r in sink.rejections()] == [
        ("a@harness.invalid", "refused@harness.invalid")
    ]


def test_sink_delivers_to_the_accepted_recipients_only(sink: EmailSink) -> None:
    """Control for the refusal: with one good recipient beside the refused one, the message is
    accepted, and the envelope names only the recipient the sink took."""
    with smtplib.SMTP(LOOPBACK, sink.port, timeout=5) as client:
        refused = client.sendmail(
            "a@harness.invalid",
            ["REFUSED@harness.invalid", "ok@harness.invalid"],
            b"Subject: x\r\n\r\nbody\r\n",
        )
    assert list(refused) == ["REFUSED@harness.invalid"]  # matched case-insensitively
    [record] = sink.wait_for(lambda rs: len(rs) == 1, 5)
    assert record.meta["rcpt_to"] == "ok@harness.invalid"


def test_sink_enforces_command_order_and_names_unknown_commands(sink: EmailSink) -> None:
    replies = _converse(
        sink.port,
        [
            b"MAIL FROM:<a@harness.invalid>",  # before EHLO
            b"HELO driver.invalid",
            b"RCPT TO:<b@harness.invalid>",  # before MAIL
            b"MAIL FROM:<a@harness.invalid>",
            b"DATA",  # no recipient yet
            b"MAIL FROM:<a@harness.invalid>",  # nested
            b"RSET",
            b"NOOP",
            b"VRFY b",
            b"STARTTLS",  # this sink was given no TLS context
            b"QUIT",
        ],
    )
    codes = [r[:3] for r in replies]
    assert codes == [
        b"220",
        b"503",
        b"250",
        b"503",
        b"250",
        b"554",
        b"503",
        b"250",
        b"250",
        b"502",
        b"502",
        b"221",
    ]


def test_sink_cuts_off_a_command_line_past_the_cap(sink: EmailSink) -> None:
    with socket.create_connection((LOOPBACK, sink.port), 5) as sock:
        reader = sock.makefile("rb")
        reader.readline()
        sock.sendall(b"X" * (MAX_LINE_BYTES + 10))
        assert reader.readline().startswith(b"500 ")
        assert reader.readline() == b""  # and the sink closed the connection
    # A TERMINATED line past the cap is refused the same way, not parsed and answered.
    with socket.create_connection((LOOPBACK, sink.port), 5) as sock:
        reader = sock.makefile("rb")
        reader.readline()
        sock.sendall(b"NOOP " + b"X" * MAX_LINE_BYTES + b"\r\n")
        assert reader.readline().startswith(b"500 ")
        assert reader.readline() == b""
    # Control: a line at the cap is still a command.
    with socket.create_connection((LOOPBACK, sink.port), 5) as sock:
        reader = sock.makefile("rb")
        reader.readline()
        sock.sendall(b"NOOP " + b"X" * (MAX_LINE_BYTES - 5) + b"\r\n")
        assert reader.readline().startswith(b"250 ")


def test_sink_refuses_a_bare_string_as_its_refusal_list() -> None:
    with pytest.raises(TypeError, match="not one string"):
        EmailSink(reject="refused@harness.invalid")


def test_every_email_sink_binds_loopback_whatever_the_host_endpoint_says() -> None:
    eps = Endpoints({"host": "0.0.0.0"}, environ={})  # noqa: S104  (the point of the test)
    sink = sinks.build("email", eps, "email_smtp")
    assert isinstance(sink, EmailSink)
    assert sink._server.host == LOOPBACK


def _tls_pair(tmp_path: Path) -> tuple[Path, Path]:
    cert_pem, key_pem = pki.make_self_signed("127.0.0.1", ["127.0.0.1"], 1)
    cert, key = tmp_path / "relay.crt", tmp_path / "relay.key"
    cert.write_bytes(cert_pem)
    key.write_bytes(key_pem)
    return cert, key


def _server_tls(cert: Path, key: Path) -> ssl.SSLContext:
    ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ctx.load_cert_chain(cert, key)
    return ctx


def test_sink_upgrades_with_starttls_only_when_given_a_context(tmp_path: Path) -> None:
    cert, key = _tls_pair(tmp_path)
    client_ctx = ssl.create_default_context(cafile=str(cert))
    with EmailSink(tls=_server_tls(cert, key)) as tls_sink:
        with smtplib.SMTP(LOOPBACK, tls_sink.port, timeout=5) as client:
            client.ehlo()
            assert client.has_extn("starttls")
            client.starttls(context=client_ctx)
            client.ehlo()
            assert not client.has_extn("starttls")  # offered once, not again inside TLS
            client.sendmail("a@harness.invalid", ["b@harness.invalid"], b"Subject: x\r\n\r\nx\r\n")
        [record] = tls_sink.wait_for(lambda rs: len(rs) == 1, 5)
        assert record.meta["tls"] == "yes"
    # Control: a sink with no context does not offer STARTTLS at all.
    with EmailSink() as plain, smtplib.SMTP(LOOPBACK, plain.port, timeout=5) as client:
        client.ehlo()
        assert not client.has_extn("starttls")


def test_a_peer_stalled_mid_handshake_does_not_hold_up_stop(tmp_path: Path) -> None:
    """The handshake polls for a stop, so a client that says STARTTLS and then sends nothing is
    let go at once, not after the handshake deadline."""
    cert, key = _tls_pair(tmp_path)
    tls_sink = EmailSink(tls=_server_tls(cert, key))
    tls_sink.start()
    with socket.create_connection((LOOPBACK, tls_sink.port), 5) as sock:
        reader = sock.makefile("rb")
        reader.readline()
        sock.sendall(b"EHLO stall.invalid\r\n")
        while reader.readline()[3:4] == b"-":
            pass
        sock.sendall(b"STARTTLS\r\n")
        assert reader.readline().startswith(b"220 ")
        time.sleep(0.5)  # the handler is now inside the handshake, waiting for a ClientHello
        began = time.monotonic()
        tls_sink.stop()
        elapsed = time.monotonic() - began
    assert elapsed < 2.0, elapsed
    assert not [t for t in tls_sink._server._threads if t.is_alive()]


# --- the Email scenarios on the real graph --------------------------------------------------------------


@pytest.fixture
def server(tmp_path: Path) -> Iterator[tuple[str, Endpoints]]:
    with serve_harness_config(tmp_path, ephemeral_overrides(tmp_path)) as served:
        yield served


def test_the_email_scenarios_are_registered_and_claim_only_the_email_outbound() -> None:
    from harness import endpoints

    declared = set(endpoints.registry())
    for name in _EMAIL_SCENARIOS:
        scenario = SCENARIOS[name]
        assert scenario.covers == {("email", "outbound")}
        # The shared registry test checks only plain Scenario instances, so these are checked here.
        assert isinstance(scenario, EmailScenario)
        assert {scenario.inbound, scenario.sink_endpoint} <= declared, name
    with pytest.raises(ValueError, match="at least one"):
        EmailScenario("x", "", "A08", "delivered", RECIPIENT, 0)


def test_the_graph_spells_the_scenario_addresses() -> None:
    """The graph imports nothing from the harness, so its sender and recipients are literals; they
    must equal the scenario module's constants or a scenario asserts against the wrong mailbox."""
    registry = load_config(str(HARNESS_CONFIG))
    delivered = registry.outbound["OB_Harness_Email"].spec.settings
    refused = registry.outbound["OB_Harness_Email_Rejected"].spec.settings
    assert (delivered["sender"], delivered["recipients"]) == (SENDER, [RECIPIENT])
    assert (refused["sender"], refused["recipients"]) == (SENDER, [REFUSED_RECIPIENT])
    # Cleartext on loopback is declared with the engine's own setting, not the process-wide escape.
    for name in ("OB_Harness_Email", "OB_Harness_Email_Rejected"):
        oc = registry.outbound[name]
        assert oc.spec.settings["use_tls"] is False
        assert oc.cleartext_accepted and oc.cleartext_reason


def _submission(control_id: str, rcpt: str = RECIPIENT) -> Record:
    msg = EmailMessage()
    msg["To"] = rcpt
    msg.set_content(f"MSH|^~\\&|A|B|C|D|20260101||ADT^A08|{control_id}|P|2.5.1\r")
    return Record(msg.as_bytes(), {"mail_from": SENDER, "rcpt_to": rcpt})


def test_the_delivered_check_fails_on_a_second_copy_of_one_message() -> None:
    """``email_delivered`` itself runs in test_harness_scenarios against the real graph; this pins
    the "exactly one" half of it, which a clean run never exercises. Control: one copy passes."""
    scenario = SCENARIOS["email_delivered"]
    assert isinstance(scenario, EmailScenario)
    once = EmailSink()
    once._add(_submission("C1"))
    assert scenario._check_delivered(once, ["C1"], 0.1, "prior").ok
    twice = EmailSink()
    twice._add(_submission("C1"))
    twice._add(_submission("C1"))
    result = scenario._check_delivered(twice, ["C1"], 0.1, "prior")
    assert not result.ok
    assert "2 submissions for 1 messages" in result.detail


def test_a_refused_recipient_is_dead_lettered_within_the_retry_ceiling(
    server: tuple[str, Endpoints],
) -> None:
    """The 550 path: each message is dead-lettered after at most the outbound's ``max_attempts``
    (2). Measured 2026-10-02, the engine retries a 550 to that ceiling (it maps every
    ``SMTPException`` to a transient ``DeliveryError``); a change that dead-letters a permanent 5xx
    on the first attempt also passes here, so this does not pin the retry as correct."""
    api_url, eps = server
    scenario = SCENARIOS["email_rejected_recipient"]
    assert isinstance(scenario, EmailScenario)
    with EngineClient(api_url) as client:
        result = run_scenario(scenario, client, timeout=30.0, endpoints=eps)
        assert result.ok, result.detail
        dead = client.list_dead_letters(destination_name="OB_Harness_Email_Rejected", limit=50)
    assert len(dead.dead_letters) == scenario.count
    assert all(1 <= d.attempts <= 2 for d in dead.dead_letters), [
        d.attempts for d in dead.dead_letters
    ]


def test_a_delivered_scenario_expecting_another_recipient_fails(
    server: tuple[str, Endpoints],
) -> None:
    """Negative control: the recipient check bites. The graph mails clinic@, so a scenario that
    expects anyone else must fail even though every message was delivered."""
    api_url, eps = server
    wrong = EmailScenario(
        "email_wrong_recipient", "", "A08", "delivered", "other@harness.invalid", 1
    )
    with EngineClient(api_url) as client:
        result = run_scenario(wrong, client, timeout=15.0, endpoints=eps)
    assert not result.ok
    assert "envelope" in result.detail


def test_a_rejected_scenario_fails_when_the_sink_accepts_the_recipient(
    server: tuple[str, Endpoints],
) -> None:
    """Negative control: with the sink refusing a DIFFERENT address, the graph's refused@ mail is
    accepted, so nothing dead-letters and the scenario must fail."""
    api_url, eps = server
    accepted = EmailScenario(
        "email_not_refused",
        "",
        "A31",
        "rejected",
        "nobody@harness.invalid",
        1,
        dead_letter_destination="OB_Harness_Email_Rejected",
    )
    with EngineClient(api_url) as client:
        result = run_scenario(accepted, client, timeout=5.0, endpoints=eps)
    assert not result.ok
    assert "0/1" in result.detail


@pytest.mark.parametrize(
    "toml",
    [
        # Each carries the same opt-out as HARNESS_EGRESS_TOML, so the relay host passes and only
        # the recipient-domain gate can refuse (the model default denies, vault BACKLOG #2605).
        pytest.param(
            '[security]\nblock_unlisted_outbound = false\n[egress]\nallowed_http = ["127.0.0.1"]\n',
            id="no-recipient-domains",
        ),
        pytest.param(
            "[security]\nblock_unlisted_outbound = false\n"
            '[egress]\nallowed_http = ["127.0.0.1"]\nallowed_recipient_domains = ["other.invalid"]\n',
            id="another-domain",
        ),
    ],
)
def test_an_unlisted_recipient_domain_fails_the_delivered_scenario(
    tmp_path: Path, toml: str
) -> None:
    """Control for the passing Email runs: they pass because ``allowed_recipient_domains`` names
    the harness mail domain (vault BACKLOG #2616). With the list empty or naming another domain, the
    engine refuses both Email outbounds and the delivered scenario fails."""
    scenario = SCENARIOS["email_delivered"]
    assert isinstance(scenario, EmailScenario)
    egress = harness_egress(tmp_path, toml)
    with serve_harness_config(tmp_path, ephemeral_overrides(tmp_path), egress=egress) as served:
        api_url, eps = served
        with EngineClient(api_url) as client:
            listing = client.connections()
            result = run_scenario(
                dataclasses.replace(scenario, count=1), client, timeout=3.0, endpoints=eps
            )
    outbound: dict[str, set[str]] = {}
    for row in listing:
        if row.role == "destination" and row.destination:
            outbound.setdefault(row.destination, set()).add(row.status)
    inbound = {row.channel_id: row.status for row in listing if row.role == "source"}
    for name in ("OB_Harness_Email", "OB_Harness_Email_Rejected"):
        assert outbound[name] == {"failed"}, (name, outbound.get(name))
    assert inbound["IB_Harness_Email"] == "running"
    # It must fail BECAUSE delivery was refused: the message reached the engine and got no further.
    assert not result.ok
    assert "could not send" not in result.detail, result.detail
    assert "0/1 reached 'processed'" in result.detail, result.detail


def test_body_control_id_reads_the_plain_text_body_only() -> None:
    hl7 = "MSH|^~\\&|A|B|C|D|20260101||ADT^A08|CTRL123|P|2.5.1\rEVN|A08|20260101\r"
    msg = EmailMessage()
    msg["To"] = RECIPIENT
    msg.set_content(hl7)
    assert body_control_id(Record(msg.as_bytes())) == "CTRL123"
    # Control: the same HL7 in a header and not in the body is not found.
    other = EmailMessage()
    other["Subject"] = "CTRL123"
    other.set_content("no hl7 here")
    assert body_control_id(Record(other.as_bytes())) is None


# --- Direct: S/MIME over STARTTLS, on its own graph --------------------------------------------------


_DIRECT_CONFIG = HARNESS_CONFIG / "direct"
_PARTNER = "partner@direct.harness.invalid"
_DIRECT_SENDER = "engine@direct.harness.invalid"


@pytest.fixture
def direct_pki(tmp_path: Path) -> dict[str, Any]:
    """A synthetic Direct trust domain for one test: a CA, the sender's signing pair, the partner's
    encryption pair, and a self-signed loopback certificate for the SMTP relay's STARTTLS."""
    pki_dir = tmp_path / "pki"
    pki_dir.mkdir()
    # The minting helpers of the Direct transport's own tests, so there is one Direct PKI recipe.
    ca_key, ca = _mint_ca()
    signer_key, signer = _mint_leaf(_DIRECT_SENDER, ca_key, ca)
    partner_key, partner = _mint_leaf(_PARTNER, ca_key, ca)
    env = {
        "direct_signing_cert": str(pki_dir / "signer.crt"),
        "direct_signing_key": str(pki_dir / "signer.key"),
        "direct_recipient_cert": str(pki_dir / "partner.crt"),
        "direct_trust_anchor": str(pki_dir / "ca.crt"),
    }
    _write_pem(Path(env["direct_signing_cert"]), signer)
    _write_key(Path(env["direct_signing_key"]), signer_key)
    _write_pem(Path(env["direct_recipient_cert"]), partner)
    _write_pem(Path(env["direct_trust_anchor"]), ca)
    relay_cert, relay_key = _tls_pair(pki_dir)
    env["direct_relay_ca"] = str(relay_cert)
    return {
        "env": env,
        "signer_key": signer_key,
        "partner_key": partner_key,
        "partner": partner,
        "relay_tls": _server_tls(relay_cert, relay_key),
    }


def _enveloped_der(record: Record) -> bytes:
    message = parse(record)
    assert message.get_content_type() == "application/pkcs7-mime"
    assert message.get_param("smime-type") == "enveloped-data"
    content = message.get_content()
    assert isinstance(content, bytes)
    return content


def _candidate_bodies(signed_der: bytes) -> list[bytes]:
    """Every reading of the HL7 content inside the decrypted SignedData. The connector signs with
    ``Binary``, so the body sits verbatim in one DER OCTET STRING right before ``MSH|``. Its length
    header is 2, 3 or 4 bytes, and a shorter form can also match the TAIL of a longer header, so
    every form that parses is returned; the caller keeps the one the sender's signature covers."""
    start = signed_der.index(b"MSH|")
    bodies: list[bytes] = []
    for header_len in (2, 3, 4):  # short form, then the 0x81 and 0x82 long forms
        header = signed_der[start - header_len : start]
        if len(header) != header_len or header[0] != 0x04:
            continue
        if header_len == 2 and header[1] < 0x80:
            bodies.append(signed_der[start : start + header[1]])
        elif header_len > 2 and header[1] == 0x80 + header_len - 2:
            bodies.append(signed_der[start : start + int.from_bytes(header[2:], "big")])
    return bodies


def test_the_direct_graph_reads_the_email_endpoints_with_equal_defaults() -> None:
    """The subdirectory graph is outside the top-level contract walk, so its harness_* reads are
    held to the same rule here: declared, with the same default."""
    from harness import endpoints

    registry = load_config(str(_DIRECT_CONFIG))
    spec_settings = [c.spec.settings for c in registry.inbound.values()]
    spec_settings += [c.spec.settings for c in registry.outbound.values()]
    refs = {
        v.key.removeprefix("harness_"): v.default
        for settings in spec_settings
        for v in settings.values()
        if isinstance(v, EnvRef) and v.key.startswith("harness_")
    }
    assert set(refs) == {"host", "email_in", "email_smtp"}
    declared = endpoints.registry()
    for key, default in refs.items():
        assert str(default) == declared[key].default, key


def test_direct_sends_signed_then_encrypted_smime_to_the_partner_over_starttls(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, direct_pki: dict[str, Any]
) -> None:
    for key, value in direct_pki["env"].items():
        monkeypatch.setenv(f"MEFOR_VALUE_{key.upper()}", value)
    shape = Scenario("direct_once", "", "ADT", "A08", 2, "processed", inbound="email_in")
    payloads, control_ids = shape.payloads()
    overrides = ephemeral_overrides(tmp_path)
    with (
        serve_harness_config(tmp_path, overrides, config_dir=_DIRECT_CONFIG) as (api_url, eps),
        EmailSink(LOOPBACK, eps.port("email_smtp"), tls=direct_pki["relay_tls"]) as sink,
        EngineClient(api_url) as client,
    ):
        injections = MLLPDriver(eps.host, eps.port("email_in")).inject(payloads)
        assert not [i.error for i in injections if i.error]
        verdict = _verify_disposition(shape, client, control_ids, 30.0, [])
        assert verdict.ok, verdict.detail
        records = sink.wait_for(lambda rs: len(rs) >= len(control_ids), 15)

    assert len(records) == len(control_ids)
    seen: set[str] = set()
    for record in records:
        # The hop: STARTTLS was taken, and the envelope names the partner and nobody else.
        assert record.meta["tls"] == "yes"
        assert (record.meta["mail_from"], record.meta["rcpt_to"]) == (_DIRECT_SENDER, _PARTNER)
        assert str(parse(record)["To"]) == _PARTNER
        enveloped = _enveloped_der(record)
        # ENCRYPTED to the partner: its key opens the envelope...
        signed = pkcs7.pkcs7_decrypt_der(
            enveloped, direct_pki["partner"], direct_pki["partner_key"], []
        )
        # ...and a key that is not the partner's does not (the negative control for this leg).
        stranger_key, stranger = _mint_ca()
        with pytest.raises(ValueError):
            pkcs7.pkcs7_decrypt_der(enveloped, stranger, stranger_key, [])
        # SIGNED by the sender: NoAttributes + PKCS#1 v1.5 is deterministic, so the signature over
        # the exact body is recomputable and must sit inside the SignedData.
        signer_key = direct_pki["signer_key"]
        covered = [
            b
            for b in _candidate_bodies(signed)
            if signer_key.sign(b, padding.PKCS1v15(), hashes.SHA256()) in signed
        ]
        assert len(covered) == 1, "the sender's signature over the carried body is not present"
        body = covered[0]
        # Control for the signature leg: a signature over a changed body is not in there.
        tampered = signer_key.sign(body + b"X", padding.PKCS1v15(), hashes.SHA256())
        assert tampered not in signed
        cid = control_id_of(body)
        assert cid is not None
        seen.add(cid)
    assert seen == set(control_ids)
