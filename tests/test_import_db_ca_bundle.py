# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""``import-db-ca.ps1`` reads every certificate in the file, and trusts only CAs (BACKLOG #5561).

The script used to build one ``X509Certificate2`` from the path and then hand the path to
``Import-Certificate``. An unsigned ``.p7b`` chain, the shape the help advertises, made the
constructor throw ``Cannot find the original signer``; a PEM bundle showed the operator only its
first certificate. Now the bytes are read once into a collection, every certificate in it is shown
and checked, and the whole file is refused when any one is not a CA or carries a private key, or
when .NET's chain engine (``X509Chain``, given the file as its extra store) does not build each
one's chain to a self-signed root in the same file, or a root in it is outside its validity
period. A root goes into the machine Root store and any other CA into the intermediate store.

NOTHING HERE WRITES A CERTIFICATE STORE. The fixtures are generated in a pytest temporary
directory. The function-level tests lift ``Read-CaBundle``, ``Get-CaRefusal`` and
``Get-CaChainCheck`` (and the console helpers they call) out of the script's AST and call them, as
``tests/test_import_db_ca_console_text.py`` does. The whole-script tests but one run it with
``-WhatIf``, where ``ShouldProcess`` declines every import, so the store is never opened. The one
run without it is the elevation refusal test, which gives it a file the script refuses anyway.
All of them are skipped in an elevated session, so even a regression that ignored ``-WhatIf``
would meet the script's own elevation refusal rather than the machine Root store. Both halves need
``pwsh`` and skip where there is none.
"""

from __future__ import annotations

import base64
import datetime
import itertools
import json
import os
import shutil
import subprocess
import sys
import uuid
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.serialization import pkcs7, pkcs12
from cryptography.x509.oid import NameOID

_SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "service" / "import-db-ca.ps1"


def _pwsh() -> str:
    exe = shutil.which("pwsh")
    if exe is None:
        pytest.skip("SKIP (nothing run): pwsh not on PATH")
    return exe


def _elevated() -> bool:
    if sys.platform != "win32":
        return os.geteuid() == 0
    import ctypes

    return bool(ctypes.windll.shell32.IsUserAnAdmin())


_Key = ec.EllipticCurvePrivateKey


def _cert(
    cn: str,
    ca: bool | None,
    issuer: tuple[x509.Certificate, _Key] | None = None,
    *,
    cert_sign: bool | None = None,
    valid_days: tuple[int, int] = (-1, 30),
    key: _Key | None = None,
) -> tuple[x509.Certificate, _Key]:
    """A synthetic certificate. ``ca`` None leaves the basic constraints extension out, and
    ``cert_sign`` None leaves the key usage extension out. ``valid_days`` is its validity period,
    in days from now, and ``key`` its own key, a fresh one when None."""
    key = key or ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = datetime.datetime.now(datetime.UTC)
    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(issuer[0].subject if issuer else name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now + datetime.timedelta(days=valid_days[0]))
        .not_valid_after(now + datetime.timedelta(days=valid_days[1]))
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), False)
    )
    if ca is not None:
        builder = builder.add_extension(x509.BasicConstraints(ca=ca, path_length=None), True)
    if cert_sign is not None:
        usage = dict.fromkeys(
            (
                "content_commitment",
                "key_encipherment",
                "data_encipherment",
                "key_agreement",
                "crl_sign",
                "encipher_only",
                "decipher_only",
            ),
            False,
        )
        builder = builder.add_extension(
            x509.KeyUsage(digital_signature=True, key_cert_sign=cert_sign, **usage), True
        )
    return builder.sign(issuer[1] if issuer else key, hashes.SHA256()), key


def _thumb(cert: x509.Certificate) -> str:
    return cert.fingerprint(hashes.SHA1()).hex().upper()


def _pem(*certs: x509.Certificate) -> bytes:
    return b"".join(c.public_bytes(serialization.Encoding.PEM) for c in certs)


@pytest.fixture(scope="module")
def chain() -> dict[str, tuple[x509.Certificate, _Key]]:
    root = _cert("Synthetic Test Root CA", True)
    certs = {
        "root": root,
        "intermediate": _cert("Synthetic Test Issuing CA", True, root),
        "leaf": _cert("db.test.invalid", False, root),
        "unconstrained": _cert("Synthetic No Constraints", None),
        "no_cert_sign": _cert("Synthetic CA Without CertSign", True, cert_sign=False),
        "cert_sign": _cert("Synthetic CA With CertSign", True, cert_sign=True),
        # A DER CA whose bytes spell PEM armour inside its subject.
        "armour_in_subject": _cert("-----BEGIN NOTE-----", True),
    }
    other_root = _cert("Synthetic Other Root CA", True)
    second_root = _cert("Synthetic Second Root CA", True)
    expired_root = _cert("Synthetic Expired Root CA", True, valid_days=(-60, -1))
    certs.update(
        {
            "other_root": other_root,
            # An issuing CA whose root is not in the files it is put in.
            "foreign": _cert("Synthetic Foreign Issuing CA", True, other_root),
            # Names the root as its issuer, but another key signed it.
            "forged": _cert("Synthetic Forged CA", True, (root[0], other_root[1])),
            "second_root": second_root,
            # The second root's name and key, signed by the first root: a cross-certificate.
            "cross": _cert("Synthetic Second Root CA", True, root, key=second_root[1]),
            "expired_root": expired_root,
            "future_root": _cert("Synthetic Future Root CA", True, valid_days=(1, 30)),
            "expired_root_inter": _cert("Synthetic Issuing CA Of Expired", True, expired_root),
        }
    )
    return certs


@pytest.fixture(scope="module")
def extra(chain: dict[str, tuple[x509.Certificate, _Key]]) -> dict[str, x509.Certificate]:
    """An RSA self-signed root, the same key's root signed with RSA-PSS, and a re-key
    certificate: self-issued (its subject and issuer are the root's name) but signed by the root's
    old key, so it is not self-signed."""
    root, root_key = chain["root"]
    now = datetime.datetime.now(datetime.UTC)

    def build(name: x509.Name, public: object) -> x509.CertificateBuilder:
        return (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(public)  # type: ignore[arg-type]
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=30))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), True)
            # OpenSSL reads a certificate with matching names and no subject key identifier as
            # self-signed, so the re-key certificate needs one to be linked to its signer there.
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(public), False)  # type: ignore[arg-type]
        )

    rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    rsa_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Synthetic RSA Root CA")])
    new_key = ec.generate_private_key(ec.SECP384R1())
    pss_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Synthetic RSA-PSS Root CA")])
    # The authority key identifier names the root's key, as a CA's re-key certificate does: it is
    # what tells a chain engine that a self-issued certificate is not self-signed. Without it, the
    # Windows engine reads the re-key certificate as self-signed with a signature that fails.
    root_ski = root.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value
    rekey = build(root.subject, new_key.public_key()).add_extension(
        x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(root_ski), False
    )
    pss = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32)
    return {
        "rsa_root": build(rsa_name, rsa_key.public_key()).sign(rsa_key, hashes.SHA256()),
        "rekey": rekey.sign(root_key, hashes.SHA256()),
        "pss_root": build(pss_name, rsa_key.public_key()).sign(
            rsa_key, hashes.SHA256(), rsa_padding=pss
        ),
    }


@pytest.fixture(scope="module")
def files(
    tmp_path_factory: pytest.TempPathFactory,
    chain: dict[str, tuple[x509.Certificate, _Key]],
    extra: dict[str, x509.Certificate],
) -> dict[str, Path]:
    """Every fixture file, written once for the module."""
    tmp_path = tmp_path_factory.mktemp("dbca")
    root, root_key = chain["root"]
    inter = chain["intermediate"][0]
    leaf = chain["leaf"][0]
    der = serialization.Encoding.DER
    contents = {
        "der": root.public_bytes(der),
        "pem_one": _pem(root),
        "p7b_der": pkcs7.serialize_certificates([root, inter], der),
        "p7b_pem": pkcs7.serialize_certificates([root, inter], serialization.Encoding.PEM),
        "pem_bundle": b"subject=ignored text\n" + _pem(root, inter),
        "p7b_with_leaf": pkcs7.serialize_certificates([root, leaf], der),
        "pem_with_unconstrained": _pem(root, chain["unconstrained"][0]),
        # PEM keeps its order, where a .p7b's certificate SET may be re-sorted.
        "pem_two_refused": _pem(root, leaf, chain["no_cert_sign"][0]),
        "pfx": pkcs12.serialize_key_and_certificates(
            b"x", root_key, root, None, serialization.NoEncryption()
        ),
        "pem_with_key": _pem(root)
        + root_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ),
        "pem_unterminated": _pem(root) + b"-----BEGIN CERTIFICATE-----\nMIIB\n",
        # A text file whose first byte is '0' (0x30, an ASN.1 SEQUENCE) is still PEM.
        "pem_zero_first": b"0 s:/CN=x\n" + _pem(root, inter),
        "pem_zero_first_with_key": b"0\n"
        + _pem(root)
        + root_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        ),
        "pem_utf16": b"\xff\xfe" + _pem(root, inter).decode("ascii").encode("utf-16-le"),
        "pem_x509_label": _pem(root).replace(b" CERTIFICATE-----", b" X509 CERTIFICATE-----"),
        "pem_duplicate": _pem(root, root),
        "pem_key_usage": _pem(chain["no_cert_sign"][0], chain["cert_sign"][0]),
        # Bare base64 with no armour, and the AD CS shape: a base64 .p7b under a CERTIFICATE header.
        "b64_der": base64.encodebytes(root.public_bytes(der)),
        # The same behind a byte-order mark, as a Windows editor saves it.
        "b64_der_utf8_bom": b"\xef\xbb\xbf" + base64.encodebytes(root.public_bytes(der)),
        "b64_der_utf16_bom": b"\xff\xfe"
        + base64.encodebytes(root.public_bytes(der)).decode("ascii").encode("utf-16-le"),
        "pem_utf8_bom": b"\xef\xbb\xbf" + _pem(root, inter),
        # A .pfx under a CERTIFICATE header, which only the content check can tell apart.
        "pfx_in_pem": b"-----BEGIN CERTIFICATE-----\n"
        + base64.encodebytes(
            pkcs12.serialize_key_and_certificates(
                b"x", root_key, root, None, serialization.NoEncryption()
            )
        )
        + b"-----END CERTIFICATE-----\n",
        "adcs_p7b": b"-----BEGIN CERTIFICATE-----\n"
        + base64.encodebytes(pkcs7.serialize_certificates([root, inter], der))
        + b"-----END CERTIFICATE-----\n",
        "der_armour_in_subject": chain["armour_in_subject"][0].public_bytes(der),
        "inter_only": _pem(inter),
        "rsa_root": _pem(extra["rsa_root"]),
        "rekey_only": _pem(extra["rekey"]),
        "root_and_rekey": _pem(root, extra["rekey"]),
        "pss_root": _pem(extra["pss_root"]),
        # A root, beside an issuing CA that chains to another root, or names the root as its
        # issuer but was signed by another key: the CA does not chain to a root in the file.
        "root_and_foreign": _pem(root, chain["foreign"][0]),
        "root_and_forged": _pem(root, chain["forged"][0]),
        # Two roots and a cross-certificate between them: each chains to a root in the file.
        "cross": _pem(root, chain["second_root"][0], chain["cross"][0]),
        "expired_root": _pem(chain["expired_root"][0]),
        "future_root": _pem(chain["future_root"][0]),
        "expired_root_chain": _pem(chain["expired_root"][0], chain["expired_root_inter"][0]),
        # DER that does not end where its bytes end, and DER in front of PEM: refused.
        "der_trailing": root.public_bytes(der) + b"\x00trailing",
        "der_concat": root.public_bytes(der) + inter.public_bytes(der),
        "der_then_pem": root.public_bytes(der) + _pem(inter),
        "b64_trailing": base64.encodebytes(root.public_bytes(der) + b"\x00\x01"),
        "empty": b"",
        "base64_junk": b"not a certificate at all\n",
        "garbage": b"not a certificate!\n",
    }
    paths = {}
    for name, data in contents.items():
        p = tmp_path / f"{name}.bin"
        p.write_bytes(data)
        paths[name] = p
    return paths


def _psq(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def _read_all(tmp_path: Path, paths: dict[str, Path]) -> dict[str, dict[str, object]]:
    """Each file through ``Read-CaBundle``, then ``Get-CaRefusal`` and ``Get-CaChainCheck``, as the
    script does."""
    script = f"""
$ErrorActionPreference = 'Stop'
$ast = [System.Management.Automation.Language.Parser]::ParseFile(
    {_psq(str(_SCRIPT))}, [ref]$null, [ref]$null)
foreach ($name in @('Test-EscapedForConsole', 'ConvertTo-PrintableText', 'Read-DerHeader',
                    'Read-CaBundle', 'Get-CaRefusal', 'Invoke-CaChainBuild', 'Get-CaChainCheck')) {{
  $def = $ast.Find({{ $args[0] -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
      $args[0].Name -eq $name }}, $true)
  if (-not $def) {{ throw "missing function $name" }}
  . ([scriptblock]::Create($def.Extent.Text))
}}
$paths = {_psq(json.dumps({k: str(v) for k, v in paths.items()}))} | ConvertFrom-Json -AsHashtable
$out = @{{}}
foreach ($k in $paths.Keys) {{
  try {{
    $bundle = Read-CaBundle -Bytes ([System.IO.File]::ReadAllBytes($paths[$k]))
    $checks = Get-CaChainCheck -Bundle $bundle -Now ([datetime]::UtcNow)
    $out[$k] = @{{ certs = @(foreach ($c in $bundle) {{
      $check = $checks[$c.Thumbprint]
      $why = Get-CaRefusal -Certificate $c
      if (-not $why) {{ $why = $check.Refusal }}
      @{{ thumb = $c.Thumbprint; refusal = $why; store = $check.Store }} }}) }}
  }} catch {{
    $out[$k] = @{{ error = $_.Exception.Message }}
  }}
}}
$out | ConvertTo-Json -Depth 5 -Compress -EscapeHandling EscapeNonAscii
"""
    f = tmp_path / f"dbca-{uuid.uuid4().hex}.ps1"
    f.write_text(script, encoding="utf-8")
    proc = subprocess.run(
        [_pwsh(), "-NoProfile", "-NonInteractive", "-File", str(f)],
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=120,
    )
    assert proc.returncode == 0, f"harness failed: {proc.stdout}\n{proc.stderr}"
    result: dict[str, dict[str, object]] = json.loads(proc.stdout.strip().splitlines()[-1])
    return result


def test_every_shape_reads_every_certificate_and_only_cas_pass(
    tmp_path: Path,
    chain: dict[str, tuple[x509.Certificate, _Key]],
    extra: dict[str, x509.Certificate],
    files: dict[str, Path],
) -> None:
    got = _read_all(tmp_path, files)
    root = _thumb(chain["root"][0])
    inter = _thumb(chain["intermediate"][0])

    def full(name: str) -> list[tuple[str, str | None, str]]:
        entry = got[name]
        assert "error" not in entry, f"{name}: {entry}"
        listed = entry["certs"]
        assert isinstance(listed, list)
        return [(c["thumb"], c["refusal"], c["store"]) for c in listed]

    def certs(name: str) -> list[tuple[str, str | None]]:
        return [(thumb, refusal) for thumb, refusal, _store in full(name)]

    # Accepted: the unsigned .p7b chain the help advertises, in both encodings, and a PEM bundle,
    # each read in full -- not its first certificate only. The root is bound for Root, and the
    # issuing CA for the intermediate store, never for Root.
    assert certs("der") == [(root, None)]
    assert certs("pem_one") == [(root, None)]
    assert certs("b64_der") == [(root, None)]
    # A byte-order mark in front of bare base64 or PEM is not read as part of it.
    assert certs("b64_der_utf8_bom") == [(root, None)]
    assert certs("b64_der_utf16_bom") == [(root, None)]
    assert sorted(full("pem_utf8_bom")) == sorted(
        [(root, None, "Root"), (inter, None, "CertificateAuthority")]
    )
    assert certs("der_armour_in_subject") == [(_thumb(chain["armour_in_subject"][0]), None)]
    for name in ("p7b_der", "p7b_pem", "pem_bundle", "pem_zero_first", "pem_utf16", "adcs_p7b"):
        assert sorted(full(name)) == sorted(
            [(root, None, "Root"), (inter, None, "CertificateAuthority")]
        ), name
    assert certs("pem_x509_label") == [(root, None)]
    assert certs("pem_duplicate") == [(root, None)]

    # Root means self-signed, as the chain engine reads it: an RSA root's signature verifies under
    # its own key, in PKCS#1 v1.5 or PSS, and a self-issued re-key certificate another key signed
    # goes to the intermediate store.
    assert full("rsa_root") == [(_thumb(extra["rsa_root"]), None, "Root")]
    assert full("pss_root") == [(_thumb(extra["pss_root"]), None, "Root")]
    rekey = _thumb(extra["rekey"])
    assert sorted(full("root_and_rekey")) == sorted(
        [(root, None, "Root"), (rekey, None, "CertificateAuthority")]
    )
    second = _thumb(chain["second_root"][0])
    assert sorted(full("cross")) == sorted(
        [
            (root, None, "Root"),
            (second, None, "Root"),
            (_thumb(chain["cross"][0]), None, "CertificateAuthority"),
        ]
    )

    # Every CA must chain to a self-signed root in the same file, whatever else the file holds.
    unchained = "it does not chain to a self-signed root in this file"
    assert full("inter_only") == [(inter, unchained, "CertificateAuthority")]
    assert full("rekey_only") == [(rekey, unchained, "CertificateAuthority")]
    assert sorted(full("root_and_foreign")) == sorted(
        [(root, None, "Root"), (_thumb(chain["foreign"][0]), unchained, "CertificateAuthority")]
    )
    # The Windows engine links the forged CA to the root by name and then finds the signature
    # false; another platform's engine may not link it at all. Either refuses it.
    forged = {t: (why, store) for t, why, store in full("root_and_forged")}
    assert forged[root] == (None, "Root")
    assert forged[_thumb(chain["forged"][0])] in {
        (unchained, "CertificateAuthority"),
        ("the chain engine reports NotSignatureValid on its chain", "CertificateAuthority"),
    }

    # A root outside its validity period is refused, and so the whole file with it.
    outside = "it is a self-signed root outside its validity period"
    expired = _thumb(chain["expired_root"][0])
    assert full("expired_root") == [(expired, outside, "Root")]
    assert full("future_root") == [(_thumb(chain["future_root"][0]), outside, "Root")]
    assert dict(certs("expired_root_chain"))[expired] == outside

    # Read in full, so the non-CA among them is seen and refused.
    leaf = _thumb(chain["leaf"][0])
    with_leaf = dict(certs("p7b_with_leaf"))
    assert set(with_leaf) == {root, leaf}
    assert with_leaf[root] is None
    assert with_leaf[leaf] == "its basic constraints say it is not a CA"
    unconstrained = dict(certs("pem_with_unconstrained"))
    assert unconstrained[_thumb(chain["unconstrained"][0])] == (
        "it has no basic constraints extension, so it is not marked as a CA"
    )
    usage = dict(certs("pem_key_usage"))
    assert usage[_thumb(chain["no_cert_sign"][0])] == (
        "its key usage does not allow it to sign certificates"
    )
    assert usage[_thumb(chain["cert_sign"][0])] is None

    # Refused before anything is parsed: a private key, in either container, and what is not a
    # certificate file at all.
    def error(name: str) -> str:
        entry = got[name]
        assert "error" in entry, f"{name} was accepted: {entry}"
        return str(entry["error"])

    assert "'Pfx' content" in error("pfx")
    assert "'Pfx' content" in error("pfx_in_pem")
    assert "labelled 'PRIVATE KEY'" in error("pem_with_key")
    assert "labelled 'EC PRIVATE KEY'" in error("pem_zero_first_with_key")
    assert "not well formed" in error("pem_unterminated")
    assert "empty" in error("empty")
    assert "no certificate" in error("garbage")
    assert "'Unknown' content" in error("base64_junk")
    # DER that does not end where its bytes end, and a control character outside PEM blocks,
    # refuse the file.
    for name in ("der_trailing", "der_concat", "b64_trailing"):
        assert "does not end where its bytes end" in error(name), name
    assert "control character outside its PEM blocks" in error("der_then_pem")


def test_a_chain_ending_outside_the_file_or_unbuilt_is_refused(
    tmp_path: Path, chain: dict[str, tuple[x509.Certificate, _Key]], files: dict[str, Path]
) -> None:
    # A chain the engine ends at a root the machine already trusts, or cannot build at all, needs a
    # machine store this test must not write. So Get-CaChainCheck is run over a stand-in for
    # Invoke-CaChainBuild that reports those chains, and the verdict is read.
    outside = "F" * 40
    root = _thumb(chain["root"][0])
    inter = _thumb(chain["intermediate"][0])
    script = f"""
$ErrorActionPreference = 'Stop'
$ast = [System.Management.Automation.Language.Parser]::ParseFile(
    {_psq(str(_SCRIPT))}, [ref]$null, [ref]$null)
foreach ($name in @('Test-EscapedForConsole', 'ConvertTo-PrintableText', 'Read-DerHeader',
                    'Read-CaBundle', 'Get-CaChainCheck')) {{
  $def = $ast.Find({{ $args[0] -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
      $args[0].Name -eq $name }}, $true)
  if (-not $def) {{ throw "missing function $name" }}
  . ([scriptblock]::Create($def.Extent.Text))
}}
$script:mode = $null
function Invoke-CaChainBuild {{
  param($Certificate, $Bundle, $Anchors)
  if ($Certificate.Thumbprint -eq {_psq(root)}) {{ return @{{ Flags = 32; Path = @({_psq(root)}) }} }}
  if ($script:mode -eq 'error') {{ return @{{ Error = 'stand-in failure' }} }}
  return @{{ Flags = 0; Path = @({_psq(inter)}, {_psq(outside)}) }}
}}
$bundle = Read-CaBundle -Bytes ([System.IO.File]::ReadAllBytes({_psq(str(files["pem_bundle"]))}))
$out = @{{}}
foreach ($m in 'outside', 'error') {{
  $script:mode = $m
  $checks = Get-CaChainCheck -Bundle $bundle -Now ([datetime]::UtcNow)
  $out[$m] = @{{ root = $checks[{_psq(root)}].Refusal; inter = $checks[{_psq(inter)}].Refusal }}
}}
$out | ConvertTo-Json -Compress
"""
    f = tmp_path / f"dbca-{uuid.uuid4().hex}.ps1"
    f.write_text(script, encoding="utf-8")
    proc = subprocess.run(
        [_pwsh(), "-NoProfile", "-NonInteractive", "-File", str(f)],
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=120,
    )
    assert proc.returncode == 0, f"harness failed: {proc.stdout}\n{proc.stderr}"
    got = json.loads(proc.stdout.strip().splitlines()[-1])
    assert got["outside"] == {
        "root": None,
        "inter": f"its chain ends at {outside}, which is not a self-signed root in this file",
    }
    assert got["error"] == {
        "root": None,
        "inter": "the chain engine could not build its chain: stand-in failure",
    }


#: What the wrapper in :func:`_run_script` writes in front of the terminating error's message.
_MESSAGE = "TERMINATING-ERROR-MESSAGE: "


def _run_script(
    ca_path: Path, env: dict[str, str] | None = None, *, whatif: bool = True
) -> subprocess.CompletedProcess[str]:
    """The script run on ``ca_path``, inside a wrapper that writes a terminating error's own
    message to stderr behind :data:`_MESSAGE` and exits 1, so a test reads that message rather than
    pwsh's rendered error view, whose source-line excerpt quotes the script's code.

    ``whatif`` False drops ``-WhatIf``; only the elevation refusal test does that."""
    if _elevated():
        pytest.skip("SKIP (nothing run): elevated session; the script is run only unelevated")
    whatif_flag = " -WhatIf" if whatif else ""
    command = (
        f"try {{ & {_psq(str(_SCRIPT))} -CaPath {_psq(str(ca_path))}{whatif_flag} }} "
        f"catch {{ [Console]::Error.WriteLine({_psq(_MESSAGE)} + $_.Exception.Message); exit 1 }}"
    )
    return subprocess.run(
        [_pwsh(), "-NoProfile", "-NonInteractive", "-Command", command],
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=120,
        env=env,
    )


def _message(proc: subprocess.CompletedProcess[str]) -> str:
    """The terminating error's own message, or "" when the script raised none."""
    lines = [ln for ln in proc.stderr.splitlines() if ln.startswith(_MESSAGE)]
    assert len(lines) <= 1, proc.stderr
    return lines[0].removeprefix(_MESSAGE) if lines else ""


def test_whatif_shows_and_offers_every_certificate_of_an_unsigned_p7b(
    chain: dict[str, tuple[x509.Certificate, _Key]], files: dict[str, Path]
) -> None:
    proc = _run_script(files["p7b_der"])
    out = proc.stdout + proc.stderr
    assert proc.returncode == 0, out
    assert "The file holds 2 certificate(s)" in out
    # No elevation was needed, and each certificate is offered for its own store.
    assert "requires an elevated" not in out
    for key, store in (
        ("root", "Cert:\\LocalMachine\\Root"),
        ("intermediate", "Cert:\\LocalMachine\\CA"),
    ):
        thumb = _thumb(chain[key][0])
        assert f"Thumbprint : {thumb}" in out
        offered = [ln for ln in out.splitlines() if "What if" in ln and thumb in ln]
        assert len(offered) == 1 and f'"{store}"' in offered[0], (thumb, offered)
    assert "Imported" not in out


@pytest.mark.parametrize(
    ("name", "key", "why"),
    [
        # An issuing CA alone, or a self-issued certificate another key signed: no root.
        ("inter_only", "intermediate", "it does not chain to a self-signed root in this file"),
        ("rekey_only", "rekey", "it does not chain to a self-signed root in this file"),
        # A root, but not the one the issuing CA chains to.
        ("root_and_foreign", "foreign", "it does not chain to a self-signed root in this file"),
        # A root whose validity period is over, or has not begun.
        ("expired_root", "expired_root", "it is a self-signed root outside its validity period"),
        ("future_root", "future_root", "it is a self-signed root outside its validity period"),
    ],
)
def test_a_ca_without_a_valid_root_in_the_file_imports_nothing(
    name: str,
    key: str,
    why: str,
    chain: dict[str, tuple[x509.Certificate, _Key]],
    extra: dict[str, x509.Certificate],
    files: dict[str, Path],
) -> None:
    cert = extra[key] if key in extra else chain[key][0]
    proc = _run_script(files[name])
    out = proc.stdout + proc.stderr
    assert proc.returncode != 0, out
    message = _message(proc)
    assert message.startswith("Nothing was imported."), out
    assert f"Refused: {_thumb(cert)}: {why}." in message, message
    assert f"  {_thumb(cert)}: {why}" in proc.stdout.splitlines(), out
    assert "  Store      : none (refused)" in proc.stdout.splitlines(), out
    assert "What if" not in out


def test_not_after_is_printed_in_utc(
    chain: dict[str, tuple[x509.Certificate, _Key]], files: dict[str, Path]
) -> None:
    # The 'u' format writes a 'Z' suffix whatever the time's kind, so a local time printed with it
    # reads as a UTC time that is wrong by the zone's offset. TZ sets the zone for .NET on Linux and
    # macOS. Windows ignores it and uses the host's own zone, so on a Windows host running in UTC,
    # as hosted runners do, this test cannot fail for the bug it guards; the Linux leg guards it.
    proc = _run_script(files["der"], dict(os.environ, TZ="Pacific/Chatham"))
    assert proc.returncode == 0, proc.stdout + proc.stderr
    want = chain["root"][0].not_valid_after_utc.strftime("%Y-%m-%d %H:%M:%SZ")
    assert f"  Not after  : {want}" in proc.stdout.splitlines(), proc.stdout


_NOT_A_CA = "its basic constraints say it is not a CA"
_NO_CERT_SIGN = "its key usage does not allow it to sign certificates"


@pytest.mark.parametrize(
    ("name", "refused"),
    [
        ("p7b_with_leaf", [("leaf", _NOT_A_CA)]),
        ("pem_two_refused", [("leaf", _NOT_A_CA), ("no_cert_sign", _NO_CERT_SIGN)]),
    ],
)
def test_a_bundle_holding_a_certificate_that_cannot_sign_certificates_imports_nothing(
    name: str,
    refused: list[tuple[str, str]],
    chain: dict[str, tuple[x509.Certificate, _Key]],
    files: dict[str, Path],
) -> None:
    """A non-CA, or a CA whose key usage leaves out certificate signing, refuses the file."""
    proc = _run_script(files[name])
    out = proc.stdout + proc.stderr
    assert proc.returncode != 0, out
    message = _message(proc)
    assert message.startswith("Nothing was imported."), out
    thumbs = [_thumb(chain[key][0]) for key, _why in refused]
    # The error's own message names each refused certificate with its reason, in file order, in
    # the form the printed list uses, and nothing else.
    assert message.endswith(
        "Refused: "
        + "; ".join(f"{t}: {why}" for t, (_key, why) in zip(thumbs, refused, strict=True))
        + "."
    ), message
    # The listing names no store for a refused certificate, and the root's for the root.
    stores = [ln for ln in proc.stdout.splitlines() if ln.startswith("  Store      : ")]
    assert stores.count("  Store      : none (refused)") == len(refused), out
    assert "  Store      : Cert:\\LocalMachine\\Root" in stores, out
    # The printed list holds each reason as a whole line, in file order, and nothing else: pwsh's
    # error view rewraps at the console width, and at a Linux runner's 80 columns that split a
    # thumbprint from its reason.
    lines = proc.stdout.splitlines()
    assert "Refused:" in lines, out
    listed = itertools.takewhile(
        lambda ln: ln.startswith("  "), lines[lines.index("Refused:") + 1 :]
    )
    # Each refused certificate is named by its Subject too, not by thumbprint alone (BACKLOG #5561
    # item 27), on its own line under its reason.
    # The attribute type admits bytes; a CN here is text, so narrow it and format the CN value by hand.
    subjects: list[str] = []
    for key, _why in refused:
        cn = chain[key][0].subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        assert isinstance(cn, str), cn
        subjects.append(cn)
    assert list(listed) == [
        line
        for t, (_key, why), cn in zip(thumbs, refused, subjects, strict=True)
        for line in (f"  {t}: {why}", f"    Subject: CN={cn}")
    ], out
    # The error does not name the root CA beside them.
    assert _thumb(chain["root"][0]) not in message, message
    # Refused before a single import is offered, even the CA beside it.
    assert "What if" not in out


def test_the_script_adds_through_the_store_and_never_by_path() -> None:
    code = "\n".join(
        ln
        for ln in _SCRIPT.read_text(encoding="utf-8").splitlines()
        if not ln.lstrip().startswith("#")
    )
    body = code.split("[CmdletBinding(", 1)[1]
    # The bytes are read once; nothing re-reads the path behind the operator's back.
    assert body.count("ReadAllBytes(") == 1
    assert "Import-Certificate" not in body
    assert "X509Certificate2]::new($CaPath)" not in body
    # Elevation is checked before the file is read, and every certificate is checked before a
    # single import is offered.
    assert body.index("IsInRole(") < body.index("ReadAllBytes(")
    assert body.index("Get-CaRefusal -Certificate") < body.index("ShouldProcess(")
    assert body.index("ShouldProcess(") < body.index(".Store.Add(")


_NEEDS_PWSH_71 = "This script needs PowerShell 7.1 or later."


def test_the_runtime_guard_runs_before_any_store_or_chain() -> None:
    code = "\n".join(
        ln
        for ln in _SCRIPT.read_text(encoding="utf-8").splitlines()
        if not ln.lstrip().startswith("#")
    )
    body = code.split("[CmdletBinding(", 1)[1]
    guard = body.index("PSObject.Properties['TrustMode']")
    assert "PSObject.Properties['DisableCertificateDownloads']" in body[guard : guard + 200]
    assert _NEEDS_PWSH_71 in body[guard : guard + 400]
    # Before the stores are built, elevation is checked, a chain is built or the file is read.
    for later in ("X509Store]::new(", "IsInRole(", "X509Chain]::new(", "ReadAllBytes("):
        assert guard < body.index(later), later
    # Nothing past the guard asks the runtime again, so no fallback path is left behind it.
    assert body.count("PSObject.Properties[") == 2


def test_windows_powershell_is_refused_before_anything_is_read(files: dict[str, Path]) -> None:
    exe = shutil.which("powershell")
    if exe is None or sys.platform != "win32":
        pytest.skip("SKIP (nothing run): no Windows PowerShell 5.1 here")
    proc = subprocess.run(
        [exe, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", str(_SCRIPT)]
        + ["-CaPath", str(files["p7b_der"]), "-WhatIf"],
        capture_output=True,
        text=True,
        timeout=120,
    )
    out = proc.stdout + proc.stderr
    assert proc.returncode != 0, out
    assert _NEEDS_PWSH_71 in " ".join(out.split()), out
    assert "The file holds" not in out and "What if" not in out


def test_an_unelevated_run_without_whatif_is_refused_before_the_file_is_read(
    files: dict[str, Path],
) -> None:
    """Without ``-WhatIf`` the script writes the machine stores, so an unelevated run stops before
    it reads the file. Run only unelevated (``_run_script`` skips an elevated session), and on a
    file the script refuses anyway (a root beside a leaf), so even a regression that skipped the
    elevation check would import nothing. The elevation check is Windows-only. A hosted Windows
    runner is elevated, so this runs only on an unelevated Windows host, never in CI."""
    if sys.platform != "win32":
        pytest.skip("SKIP (nothing run): the elevation check reads a Windows identity")
    proc = _run_script(files["p7b_with_leaf"], whatif=False)
    out = proc.stdout + proc.stderr
    assert proc.returncode != 0, out
    assert "requires an elevated (Administrator) PowerShell" in _message(proc), out
    assert "The file holds" not in out and "What if" not in out
