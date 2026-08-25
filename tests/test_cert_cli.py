# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""CLI cert tooling (BACKLOG #71/#72): `.pfx` import, read-only inventory, self-signed dev certs.

Driven end-to-end through `messagefoundry.__main__.main([...])` (int return codes + capsys/tmp_path),
matching tests/test_cli.py. `.pfx` bundles are built in-memory with pkcs12.serialize_key_and_certificates
(there is no shipped helper). Security-relevant coverage: the 0o600 + O_EXCL key write, the env-only
passphrase, and that a bad/missing password never leaks into the error output.
"""

from __future__ import annotations

import datetime
import json
import time
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.hazmat.primitives.serialization.pkcs12 import PKCS12PrivateKeyTypes
from cryptography.x509.oid import NameOID

from messagefoundry.__main__ import main

SAMPLES_CONFIG = Path(__file__).resolve().parents[1] / "samples" / "config"
_UTC = datetime.UTC


def _make_cert(
    cn: str = "mefor-test",
    *,
    sans: list[str] | None = None,
    issuer_cn: str | None = None,
    not_after: datetime.datetime | None = None,
) -> tuple[ec.EllipticCurvePrivateKey, x509.Certificate]:
    """Build an EC P-256 cert (fast keygen). Self-issued unless `issuer_cn` differs."""
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer_cn or cn)])
    end = not_after or (datetime.datetime.now(_UTC) + datetime.timedelta(days=90))
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        # Always before `end`, so an "expired" cert (end in the past) still has a valid ordering.
        .not_valid_before(end - datetime.timedelta(days=365))
        .not_valid_after(end)
    )
    if sans:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(s) for s in sans]), critical=False
        )
    return key, builder.sign(key, hashes.SHA256())


def _make_pfx(
    key: PKCS12PrivateKeyTypes,
    cert: x509.Certificate,
    *,
    cas: list[x509.Certificate] | None = None,
    password: bytes | None = None,
) -> bytes:
    enc: serialization.KeySerializationEncryption = (
        serialization.BestAvailableEncryption(password)
        if password
        else serialization.NoEncryption()
    )
    return pkcs12.serialize_key_and_certificates(b"mefor", key, cert, cas, enc)


def _pem(cert: x509.Certificate) -> bytes:
    return cert.public_bytes(serialization.Encoding.PEM)


# --- cert import ------------------------------------------------------------


def test_import_roundtrip_writes_reloadable_pems(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("MEFOR_PFX_PASSWORD", raising=False)
    _ca_key, ca_cert = _make_cert("mefor-ca")
    key, cert = _make_cert("leaf.example.org", sans=["leaf.example.org"])
    pfx_path = tmp_path / "bundle.pfx"
    pfx_path.write_bytes(_make_pfx(key, cert, cas=[ca_cert]))
    out = tmp_path / "out"

    rc = main(["cert", "import", "--pfx", str(pfx_path), "--out-dir", str(out), "--json"])
    assert rc == 0
    result = json.loads(capsys.readouterr().out)
    assert result["ca_count"] == 1

    # Every written PEM re-loads with the library the TLS loaders use.
    reloaded_cert = x509.load_pem_x509_certificate((out / "cert.pem").read_bytes())
    assert reloaded_cert.subject.rfc4514_string() == cert.subject.rfc4514_string()
    reloaded_key = serialization.load_pem_private_key((out / "key.pem").read_bytes(), password=None)
    assert reloaded_key is not None
    reloaded_ca = x509.load_pem_x509_certificate((out / "ca-chain.pem").read_bytes())
    assert reloaded_ca.subject.rfc4514_string() == ca_cert.subject.rfc4514_string()


def test_import_without_cas_omits_ca_chain(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("MEFOR_PFX_PASSWORD", raising=False)
    key, cert = _make_cert("solo.example.org")
    pfx_path = tmp_path / "b.pfx"
    pfx_path.write_bytes(_make_pfx(key, cert))
    out = tmp_path / "o"

    rc = main(["cert", "import", "--pfx", str(pfx_path), "--out-dir", str(out), "--json"])
    assert rc == 0
    result = json.loads(capsys.readouterr().out)
    assert result["ca_count"] == 0
    assert result["ca_chain"] is None
    assert not (out / "ca-chain.pem").exists()


def test_import_encrypted_pfx_via_env(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    password = "corr3ct-h0rse-battery"
    key, cert = _make_cert("enc.example.org")
    pfx_path = tmp_path / "enc.pfx"
    pfx_path.write_bytes(_make_pfx(key, cert, password=password.encode()))
    monkeypatch.setenv("MEFOR_PFX_PASSWORD", password)
    out = tmp_path / "o"

    rc = main(["cert", "import", "--pfx", str(pfx_path), "--out-dir", str(out)])
    assert rc == 0
    assert (out / "cert.pem").exists()
    assert serialization.load_pem_private_key((out / "key.pem").read_bytes(), password=None)


def test_import_wrong_password_does_not_leak(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    correct = "s3cr3t-PANCAKE"
    wrong = "NOPE-wrongpass-XYZ"
    key, cert = _make_cert("enc.example.org")
    pfx_path = tmp_path / "enc.pfx"
    pfx_path.write_bytes(_make_pfx(key, cert, password=correct.encode()))
    monkeypatch.setenv("MEFOR_PFX_PASSWORD", wrong)
    out = tmp_path / "o"

    rc = main(["cert", "import", "--pfx", str(pfx_path), "--out-dir", str(out)])
    assert rc == 2
    captured = capsys.readouterr()
    combined = captured.out + captured.err
    # Neither the (wrong) supplied passphrase nor the correct one may appear anywhere in the output.
    assert wrong not in combined
    assert correct not in combined
    assert not (out / "key.pem").exists()  # nothing written on a load failure


def test_import_missing_password_fails_cleanly(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    correct = "needed-pw-42"
    key, cert = _make_cert()
    pfx_path = tmp_path / "enc.pfx"
    pfx_path.write_bytes(_make_pfx(key, cert, password=correct.encode()))
    monkeypatch.delenv("MEFOR_PFX_PASSWORD", raising=False)
    out = tmp_path / "o"

    rc = main(["cert", "import", "--pfx", str(pfx_path), "--out-dir", str(out)])
    assert rc == 2
    combined = capsys.readouterr().err
    assert correct not in combined
    assert not (out / "key.pem").exists()


def test_import_refuses_to_overwrite_existing_key(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("MEFOR_PFX_PASSWORD", raising=False)
    key, cert = _make_cert("dupe.example.org")
    pfx_path = tmp_path / "b.pfx"
    pfx_path.write_bytes(_make_pfx(key, cert))
    out = tmp_path / "o"

    assert main(["cert", "import", "--pfx", str(pfx_path), "--out-dir", str(out)]) == 0
    capsys.readouterr()
    original = (out / "key.pem").read_bytes()
    # A second import into the same dir must NOT clobber the existing key (O_EXCL).
    rc = main(["cert", "import", "--pfx", str(pfx_path), "--out-dir", str(out)])
    assert rc == 2
    assert "overwrite" in capsys.readouterr().err.lower()
    assert (out / "key.pem").read_bytes() == original


# --- cert inventory ---------------------------------------------------------


def test_inventory_lists_facts_and_flags_expired(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _k, good = _make_cert(
        "good.example.org",
        sans=["good.example.org", "www.good.example.org"],
        not_after=datetime.datetime.now(_UTC) + datetime.timedelta(days=45),
    )
    good_path = tmp_path / "good.pem"
    good_path.write_bytes(_pem(good))
    _k2, expired = _make_cert(
        "old.example.org", not_after=datetime.datetime.now(_UTC) - datetime.timedelta(days=5)
    )
    exp_path = tmp_path / "old.pem"
    exp_path.write_bytes(_pem(expired))

    rc = main(["cert", "inventory", "--cert", str(good_path), "--cert", str(exp_path), "--json"])
    # An expired cert is a normal reportable state (not a read error) → exit 0.
    assert rc == 0
    certs = {c["path"]: c for c in json.loads(capsys.readouterr().out)["certs"]}

    g = certs[str(good_path)]
    # Exact DN, not a substring: a substring match also passes for a lookalike CN (the SAN
    # `www.good.example.org` contains `good.example.org`), so it would not catch the wrong name
    # being reported. `_make_cert` is self-issued, so issuer == subject.
    assert g["subject"] == "CN=good.example.org"
    assert g["issuer"] == "CN=good.example.org"
    assert g["sans"] == ["good.example.org", "www.good.example.org"]
    assert g["expired"] is False
    assert g["days_remaining"] >= 40

    e = certs[str(exp_path)]
    assert e["expired"] is True
    assert e["days_remaining"] < 0


def test_inventory_human_output_renders_facts(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _k, cert = _make_cert("human.example.org", sans=["human.example.org"])
    cert_path = tmp_path / "c.pem"
    cert_path.write_bytes(_pem(cert))

    assert main(["cert", "inventory", "--cert", str(cert_path)]) == 0
    printed = capsys.readouterr().out
    # Assert the CN on the SUBJECT line specifically: a bare `"human.example.org" in printed` is
    # satisfied by the SAN line alone, so it would still pass if the subject stopped being rendered.
    subject_line = next(ln for ln in printed.splitlines() if ln.strip().startswith("subject:"))
    assert subject_line.split(":", 1)[1].strip() == "CN=human.example.org"
    assert "SAN(DNS)" in printed
    assert "notAfter" in printed


def test_inventory_requires_a_source(capsys: pytest.CaptureFixture[str]) -> None:
    rc = main(["cert", "inventory", "--json"])
    assert rc == 2
    assert "error" in json.loads(capsys.readouterr().out)


def test_inventory_missing_cert_is_soft_error(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    rc = main(["cert", "inventory", "--cert", str(tmp_path / "nope.pem"), "--json"])
    assert rc == 1
    data = json.loads(capsys.readouterr().out)
    assert data["certs"][0]["error"] == "file not found"


def test_inventory_unparseable_cert_does_not_leak(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # Point --cert at a private KEY file: parsing fails, and the error must be generic (no key bytes).
    key = ec.generate_private_key(ec.SECP256R1())
    key_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    key_path = tmp_path / "priv.pem"
    key_path.write_bytes(key_pem)

    rc = main(["cert", "inventory", "--cert", str(key_path), "--json"])
    assert rc == 1
    entry = json.loads(capsys.readouterr().out)["certs"][0]
    assert entry["error"] == "could not read or parse certificate"
    # No PEM key body echoed.
    assert "PRIVATE KEY" not in json.dumps(entry)


def test_inventory_config_source_loads(capsys: pytest.CaptureFixture[str]) -> None:
    # The --config branch loads the Registry (like validate/graph) and enumerates wired TLS certs; the
    # sample config wires none, so the list is empty but the command still succeeds.
    rc = main(["cert", "inventory", "--config", str(SAMPLES_CONFIG), "--json"])
    assert rc == 0
    assert "certs" in json.loads(capsys.readouterr().out)


def test_inventory_service_config_adds_api_cert(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _k, cert = _make_cert("api.local", sans=["api.local"])
    cert_path = tmp_path / "api.pem"
    cert_path.write_bytes(_pem(cert))
    svc = tmp_path / "messagefoundry.toml"
    svc.write_text(f"[api]\ntls_cert_file = {json.dumps(str(cert_path))}\n", encoding="utf-8")

    rc = main(
        [
            "cert",
            "inventory",
            "--config",
            str(SAMPLES_CONFIG),
            "--service-config",
            str(svc),
            "--json",
        ]
    )
    assert rc == 0
    certs = json.loads(capsys.readouterr().out)["certs"]
    api = next(c for c in certs if c["label"] == "api")
    assert "api.local" in api["subject"]
    assert api["sans"] == ["api.local"]


# --- cert self-signed -------------------------------------------------------


def test_self_signed_is_self_issued_with_san(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    out = tmp_path / "o"
    rc = main(
        [
            "cert",
            "self-signed",
            "--cn",
            "dev.local",
            "--san",
            "alt.local",
            "--days",
            "30",
            "--out-dir",
            str(out),
            "--json",
        ]
    )
    assert rc == 0
    result = json.loads(capsys.readouterr().out)
    assert result["sans"] == ["dev.local", "alt.local"]

    cert = x509.load_pem_x509_certificate((out / "cert.pem").read_bytes())
    assert cert.subject == cert.issuer  # self-issued
    san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert san.get_values_for_type(x509.DNSName) == ["dev.local", "alt.local"]
    assert serialization.load_pem_private_key((out / "key.pem").read_bytes(), password=None)


def test_self_signed_ip_literal_lands_as_ip_address_san(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """An IP-literal name must be an ``iPAddress`` SAN entry, never a ``DNSName`` spelling the digits.

    Hostname verification for an IP-literal URL is satisfied ONLY by an ``iPAddress`` entry -- a DNS
    entry carrying the same characters does not match it. Every shipped first-party client defaults
    to ``http://127.0.0.1:8765`` (``ide/src/cli.ts``, ``tray/config.py``, ``apiclient/client.py``) and
    ``[api].host`` binds ``127.0.0.1``, so minting for the engine's own default produced a
    certificate that could not verify against any of them. BACKLOG #1179.
    """
    out = tmp_path / "o"
    rc = main(
        [
            "cert",
            "self-signed",
            "--cn",
            "127.0.0.1",
            "--san",
            "localhost",
            "--san",
            "::1",
            "--days",
            "30",
            "--out-dir",
            str(out),
            "--json",
        ]
    )
    assert rc == 0
    cert = x509.load_pem_x509_certificate((out / "cert.pem").read_bytes())
    san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value

    # The two IP literals are iPAddress entries; only the real hostname is a DNSName.
    assert {str(ip) for ip in san.get_values_for_type(x509.IPAddress)} == {"127.0.0.1", "::1"}
    assert san.get_values_for_type(x509.DNSName) == ["localhost"]

    # The CLI's own JSON echoes the INPUT names, so it cannot witness this -- asserting on it would
    # pass whatever the certificate contained. Read the minted file back instead.
    assert json.loads(capsys.readouterr().out)["sans"] == ["127.0.0.1", "localhost", "::1"]

    # The READER is a second, coupled site: it collected DNSName values only, so fixing the writer
    # alone would make `cert inventory` under-report a certificate whose names are IP addresses.
    from messagefoundry import pki

    facts = pki.read_cert_facts((out / "cert.pem").read_bytes(), now=time.time())
    assert facts.sans == ["127.0.0.1", "localhost", "::1"]


def test_self_signed_human_output_warns_dev_only(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    out = tmp_path / "o"
    assert main(["cert", "self-signed", "--cn", "dev.local", "--out-dir", str(out)]) == 0
    printed = capsys.readouterr().out.lower()
    assert "non-prod" in printed


def test_self_signed_refuses_to_overwrite_existing_key(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    out = tmp_path / "o"
    assert main(["cert", "self-signed", "--cn", "a.local", "--out-dir", str(out)]) == 0
    capsys.readouterr()
    first_key = (out / "key.pem").read_bytes()

    rc = main(["cert", "self-signed", "--cn", "b.local", "--out-dir", str(out)])
    assert rc == 2
    assert "overwrite" in capsys.readouterr().err.lower()
    assert (out / "key.pem").read_bytes() == first_key  # O_EXCL kept the original key


def test_self_signed_rejects_non_positive_days(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    out = tmp_path / "o"
    rc = main(["cert", "self-signed", "--cn", "dev.local", "--days", "0", "--out-dir", str(out)])
    assert rc == 2
    assert not (out / "key.pem").exists()


def test_read_cert_facts_is_best_effort_on_unparseable_extensions(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A cert whose extension set fails to parse — a duplicate SAN raises `DuplicateExtension`, which is
    an `Exception` but NOT a `ValueError` — must not sink the cert. `read_cert_facts` still returns the
    `notAfter` the expiry monitor needs, with SANs degraded to empty, rather than propagating an
    uncatchable error that would crash `cert inventory` and silently drop the cert from monitoring.
    (Regression: a duplicate-SAN cert can only be forged via DER surgery, so we stub the loader to raise
    the real `cryptography` exception type from `cert.extensions`.)"""
    from messagefoundry import pki

    end = datetime.datetime(2031, 1, 1, tzinfo=_UTC)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "leaf")])

    class _BadExtCert:
        not_valid_after_utc = end
        subject = name
        issuer = name

        @property
        def extensions(self) -> x509.Extensions:
            raise x509.DuplicateExtension("duplicate SAN", x509.SubjectAlternativeName.oid)

    monkeypatch.setattr(pki.x509, "load_pem_x509_certificate", lambda _pem: _BadExtCert())
    facts = pki.read_cert_facts(
        b"-----BEGIN CERTIFICATE-----\nx\n-----END CERTIFICATE-----\n", now=0.0
    )
    assert facts.sans == []  # degraded, not a crash
    assert facts.subject == "CN=leaf"
    assert facts.issuer == "CN=leaf"
    assert facts.not_after_iso == end.isoformat()  # monitor-critical fact preserved
    assert facts.days_remaining > 0
    assert facts.expired is False


def test_inventory_does_not_crash_or_leak_on_non_valueerror_parse_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Defense in depth: if reading a cert raises a non-`ValueError` type (cryptography does — e.g.
    `DuplicateExtension` / `UnsupportedAlgorithm`), `cert inventory` still reports a generic per-row
    error and exits 1 — never an uncaught traceback, and never echoing the exception text."""
    from messagefoundry import pki

    _key, cert = _make_cert(cn="leaf")
    pem_path = tmp_path / "c.pem"
    pem_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))

    def _boom(_pem: bytes, *, now: float) -> pki.CertFacts:
        raise x509.DuplicateExtension("SECRET-LOOKING-TEXT", x509.SubjectAlternativeName.oid)

    monkeypatch.setattr(pki, "read_cert_facts", _boom)
    rc = main(["cert", "inventory", "--cert", str(pem_path)])
    captured = capsys.readouterr()
    combined = captured.out + captured.err
    assert rc == 1
    assert "could not read or parse certificate" in combined
    assert "SECRET-LOOKING-TEXT" not in combined  # exception text never echoed
