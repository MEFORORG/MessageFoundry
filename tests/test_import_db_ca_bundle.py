# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""``import-db-ca.ps1`` reads every certificate in the file, and trusts only CAs (BACKLOG #5561).

The script used to build one ``X509Certificate2`` from the path and then hand the path to
``Import-Certificate``. An unsigned ``.p7b`` chain, the shape the help advertises, made the
constructor throw ``Cannot find the original signer``; a PEM bundle showed the operator only its
first certificate. Now the bytes are read once into a collection, every certificate in it is shown
and checked, and the whole file is refused when any one is not a CA or carries a private key. A
root goes into the machine Root store and any other CA into the intermediate store.

NOTHING HERE WRITES A CERTIFICATE STORE. The fixtures are generated in a pytest temporary
directory. The function-level tests lift ``Read-CaBundle``, ``Get-CaRefusal`` and
``Get-CaStoreName`` (and the console helpers they call) out of the script's AST and call them, as
``tests/test_import_db_ca_console_text.py`` does. The whole-script tests run it with ``-WhatIf``
only, where ``ShouldProcess`` declines every import, so the store is never opened; they are also
skipped in an elevated session, so even a regression that ignored ``-WhatIf`` would meet the
script's own elevation refusal rather than the machine Root store. Both halves need ``pwsh`` and
skip where there is none.
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
from cryptography.hazmat.primitives.asymmetric import ec, rsa
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
    valid_from_days: int = -1,
    valid_to_days: int = 30,
) -> tuple[x509.Certificate, _Key]:
    """A synthetic certificate. ``ca`` None leaves the basic constraints extension out, and
    ``cert_sign`` None leaves the key usage extension out. The validity period is given in days
    from now."""
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = datetime.datetime.now(datetime.UTC)
    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(issuer[0].subject if issuer else name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now + datetime.timedelta(days=valid_from_days))
        .not_valid_after(now + datetime.timedelta(days=valid_to_days))
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
    other_root = _cert("Synthetic Other Root CA", True)
    return {
        "root": root,
        "intermediate": _cert("Synthetic Test Issuing CA", True, root),
        "leaf": _cert("db.test.invalid", False, root),
        # Issued by a root the file does not hold, and signed under the same issuer NAME as the
        # file's root by another key: neither chains to the file's root.
        "foreign_intermediate": _cert("Synthetic Foreign Issuing CA", True, other_root),
        "name_only_intermediate": _cert(
            "Synthetic Name-Only Issuing CA", True, (root[0], other_root[1])
        ),
        "expired_root": _cert(
            "Synthetic Expired Root CA", True, valid_from_days=-30, valid_to_days=-1
        ),
        "future_root": _cert("Synthetic Future Root CA", True, valid_from_days=2),
        "unconstrained": _cert("Synthetic No Constraints", None),
        "no_cert_sign": _cert("Synthetic CA Without CertSign", True, cert_sign=False),
        "cert_sign": _cert("Synthetic CA With CertSign", True, cert_sign=True),
        # A DER CA whose bytes spell PEM armour inside its subject.
        "armour_in_subject": _cert("-----BEGIN NOTE-----", True),
    }


@pytest.fixture(scope="module")
def extra(chain: dict[str, tuple[x509.Certificate, _Key]]) -> dict[str, x509.Certificate]:
    """An RSA self-signed root, and a re-key certificate: self-issued (its subject and issuer are
    the root's name) but signed by the root's old key, so it is not self-signed."""
    root, root_key = chain["root"]
    now = datetime.datetime.now(datetime.UTC)

    def build(name: x509.Name, public: object, signer: object) -> x509.Certificate:
        return (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(public)  # type: ignore[arg-type]
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=30))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), True)
            .sign(signer, hashes.SHA256())  # type: ignore[arg-type]
        )

    rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    rsa_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Synthetic RSA Root CA")])
    new_key = ec.generate_private_key(ec.SECP384R1())
    return {
        "rsa_root": build(rsa_name, rsa_key.public_key(), rsa_key),
        "rekey": build(root.subject, new_key.public_key(), root_key),
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
        "adcs_p7b": b"-----BEGIN CERTIFICATE-----\n"
        + base64.encodebytes(pkcs7.serialize_certificates([root, inter], der))
        + b"-----END CERTIFICATE-----\n",
        "der_armour_in_subject": chain["armour_in_subject"][0].public_bytes(der),
        "inter_only": _pem(inter),
        "rsa_root": _pem(extra["rsa_root"]),
        "rekey_only": _pem(extra["rekey"]),
        "root_and_rekey": _pem(root, extra["rekey"]),
        # DER that does not end where its bytes end, and DER in front of PEM: refused.
        "der_trailing": root.public_bytes(der) + b"\x00trailing",
        "der_concat": root.public_bytes(der) + inter.public_bytes(der),
        "der_then_pem": root.public_bytes(der) + _pem(inter),
        "b64_trailing": base64.encodebytes(root.public_bytes(der) + b"\x00\x01"),
        # A root beside a CA that does not chain to it: a foreign issuer, or the root's name alone.
        "pem_foreign_intermediate": _pem(root, chain["foreign_intermediate"][0]),
        "pem_name_only_intermediate": _pem(root, chain["name_only_intermediate"][0]),
        # Outside the validity period: an expired root beside a valid one, and a root not valid yet.
        "pem_expired_root": _pem(root, chain["expired_root"][0]),
        "pem_future_root": _pem(chain["future_root"][0]),
        # Bare base64 behind a byte-order mark, UTF-8 and UTF-16.
        "b64_utf8_bom": b"\xef\xbb\xbf" + base64.encodebytes(root.public_bytes(der)),
        "b64_utf16_bom": b"\xff\xfe"
        + base64.encodebytes(root.public_bytes(der)).decode("ascii").encode("utf-16-le"),
        # A .pfx carried under a CERTIFICATE header: refused by its content, not its label.
        "pfx_in_certificate_block": b"-----BEGIN CERTIFICATE-----\n"
        + base64.encodebytes(
            pkcs12.serialize_key_and_certificates(
                b"x", root_key, root, None, serialization.NoEncryption()
            )
        )
        + b"-----END CERTIFICATE-----\n",
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
    """Each file through ``Read-CaBundle``, then ``Get-CaRefusal``, ``Get-CaStoreName`` and
    ``Get-ChainRefusal``, as the script does."""
    script = f"""
$ErrorActionPreference = 'Stop'
$ast = [System.Management.Automation.Language.Parser]::ParseFile(
    {_psq(str(_SCRIPT))}, [ref]$null, [ref]$null)
foreach ($name in @('Test-EscapedForConsole', 'ConvertTo-PrintableText', 'Read-DerHeader',
                    'Read-CaBundle', 'Get-CaRefusal', 'Test-SignedBy', 'Test-SelfSigned',
                    'Get-ChainRefusal', 'Get-CaStoreName')) {{
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
    $out[$k] = @{{ certs = @(foreach ($c in $bundle) {{
      @{{ thumb = $c.Thumbprint; refusal = (Get-CaRefusal -Certificate $c);
          store = (Get-CaStoreName -Certificate $c);
          chain = (Get-ChainRefusal -Certificate $c -Bundle $bundle) }} }}) }}
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
    assert certs("der_armour_in_subject") == [(_thumb(chain["armour_in_subject"][0]), None)]
    assert full("inter_only") == [(inter, None, "CertificateAuthority")]
    for name in ("p7b_der", "p7b_pem", "pem_bundle", "pem_zero_first", "pem_utf16", "adcs_p7b"):
        assert sorted(full(name)) == sorted(
            [(root, None, "Root"), (inter, None, "CertificateAuthority")]
        ), name
    assert certs("pem_x509_label") == [(root, None)]
    assert certs("pem_duplicate") == [(root, None)]

    # Root means self-signed: an RSA root's signature verifies under its own key, and a
    # self-issued re-key certificate another key signed goes to the intermediate store.
    assert full("rsa_root") == [(_thumb(extra["rsa_root"]), None, "Root")]
    rekey = _thumb(extra["rekey"])
    assert full("rekey_only") == [(rekey, None, "CertificateAuthority")]
    assert sorted(full("root_and_rekey")) == sorted(
        [(root, None, "Root"), (rekey, None, "CertificateAuthority")]
    )

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

    # Bare base64 behind a byte-order mark reads as the root it holds.
    assert certs("b64_utf8_bom") == [(root, None)]
    assert certs("b64_utf16_bom") == [(root, None)]

    # Outside its validity period, a root is refused on its own, whatever else the file holds.
    expired = dict(certs("pem_expired_root"))
    assert expired[_thumb(chain["expired_root"][0])] == "it has expired"
    assert expired[root] is None
    assert certs("pem_future_root") == [(_thumb(chain["future_root"][0]), "it is not valid yet")]

    # Each CA must chain to a self-signed root through the file's own certificates: an issuing CA
    # and a re-key certificate that do pass, and one whose issuer is not in the file, or only
    # carries the root's name under another key, does not.
    def chained(name: str) -> dict[str, object]:
        entry = got[name]
        assert "error" not in entry, f"{name}: {entry}"
        listed = entry["certs"]
        assert isinstance(listed, list)
        return {c["thumb"]: c["chain"] for c in listed}

    assert chained("p7b_der") == {root: None, inter: None}
    assert chained("root_and_rekey") == {root: None, rekey: None}
    unchained = "it does not chain to a self-signed root in the file"
    for name, key in (
        ("pem_foreign_intermediate", "foreign_intermediate"),
        ("pem_name_only_intermediate", "name_only_intermediate"),
    ):
        assert chained(name) == {root: None, _thumb(chain[key][0]): unchained}, name
        # Each is a CA in its own right, so only the chain check catches it.
        assert dict(certs(name))[_thumb(chain[key][0])] is None, name

    # Refused before anything is parsed: a private key, in either container, and what is not a
    # certificate file at all.
    def error(name: str) -> str:
        entry = got[name]
        assert "error" in entry, f"{name} was accepted: {entry}"
        return str(entry["error"])

    assert "'Pfx' content" in error("pfx")
    assert "'Pfx' content" in error("pfx_in_certificate_block")
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


_ERROR_MARK = "TERMINATING-ERROR-MESSAGE: "


def _run_script(ca_path: Path, *, whatif: bool = True) -> subprocess.CompletedProcess[str]:
    """Run the script unelevated. Its terminating error's own message, not pwsh's rendered error
    view, is printed to stdout on one line after ``_ERROR_MARK``: the view rewraps at the console
    width and quotes the throwing source line, so text read there can come from the code."""
    if _elevated():
        pytest.skip("SKIP (nothing run): elevated session; the script is run only unelevated")
    wrapper = Path(ca_path).parent / f"run-{uuid.uuid4().hex}.ps1"
    wrapper.write_text(
        f"""
$ErrorActionPreference = 'Stop'
try {{
    & {_psq(str(_SCRIPT))} -CaPath {_psq(str(ca_path))}{" -WhatIf" if whatif else ""}
}} catch {{
    [Console]::Out.WriteLine({_psq(_ERROR_MARK)} + ($_.Exception.Message -replace '\\s+', ' '))
    exit 1
}}
""",
        encoding="utf-8",
    )
    return subprocess.run(
        [_pwsh(), "-NoProfile", "-NonInteractive", "-File", str(wrapper)],
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=120,
    )


def _error_message(proc: subprocess.CompletedProcess[str]) -> str:
    found = [
        ln[len(_ERROR_MARK) :] for ln in proc.stdout.splitlines() if ln.startswith(_ERROR_MARK)
    ]
    assert len(found) == 1, proc.stdout + proc.stderr
    return found[0]


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


@pytest.mark.parametrize("name", ["inter_only", "rekey_only"])
def test_a_file_without_a_self_signed_root_imports_nothing(
    name: str, files: dict[str, Path]
) -> None:
    # An issuing CA alone, or a self-issued certificate another key signed: no root, so refused.
    proc = _run_script(files[name])
    out = proc.stdout + proc.stderr
    assert proc.returncode != 0, out
    assert _error_message(proc).startswith(
        "Nothing was imported. The file holds no self-signed root."
    ), out
    assert "What if" not in out


_NOT_A_CA = "its basic constraints say it is not a CA"
_NO_CERT_SIGN = "its key usage does not allow it to sign certificates"
_UNCHAINED = "it does not chain to a self-signed root in the file"


def _pair(cert: x509.Certificate, why: str) -> str:
    return f"{_thumb(cert)} ({cert.subject.rfc4514_string()}): {why}"


@pytest.mark.parametrize(
    ("name", "refused"),
    [
        ("p7b_with_leaf", [("leaf", _NOT_A_CA)]),
        ("pem_two_refused", [("leaf", _NOT_A_CA), ("no_cert_sign", _NO_CERT_SIGN)]),
        ("pem_expired_root", [("expired_root", "it has expired")]),
        ("pem_foreign_intermediate", [("foreign_intermediate", _UNCHAINED)]),
        ("pem_name_only_intermediate", [("name_only_intermediate", _UNCHAINED)]),
    ],
)
def test_a_bundle_holding_a_refused_certificate_imports_nothing(
    name: str,
    refused: list[tuple[str, str]],
    chain: dict[str, tuple[x509.Certificate, _Key]],
    files: dict[str, Path],
) -> None:
    proc = _run_script(files[name])
    out = proc.stdout + proc.stderr
    assert proc.returncode != 0, out
    pairs = [_pair(chain[key][0], why) for key, why in refused]
    # The printed list holds each refusal as a whole line, in file order, and nothing else: pwsh's
    # error view rewraps at the console width, and at a Linux runner's 80 columns that split a
    # thumbprint from its reason.
    lines = proc.stdout.splitlines()
    assert "Refused:" in lines, out
    listed = itertools.takewhile(
        lambda ln: ln.startswith("  "), lines[lines.index("Refused:") + 1 :]
    )
    assert list(listed) == [f"  {p}" for p in pairs], out
    # The error's own message carries every pair, worded as the list words it, in order, and not
    # the root CA beside them.
    message = _error_message(proc)
    assert message.startswith("Nothing was imported."), message
    at = [message.find(p) for p in pairs]
    assert -1 not in at and at == sorted(at), message
    assert _thumb(chain["root"][0]) not in message, message
    # Refused before a single import is offered, even the CA beside it.
    assert "What if" not in out


def test_the_error_names_the_first_five_refusals_and_counts_the_rest(
    tmp_path: Path, chain: dict[str, tuple[x509.Certificate, _Key]]
) -> None:
    leaves = [_cert(f"db{i}.test.invalid", False, chain["root"])[0] for i in range(7)]
    path = tmp_path / "seven_leaves.pem"
    path.write_bytes(_pem(chain["root"][0], *leaves))
    proc = _run_script(path)
    assert proc.returncode != 0, proc.stdout + proc.stderr
    message = _error_message(proc)
    for leaf in leaves[:5]:
        assert _pair(leaf, _NOT_A_CA) in message, message
    for leaf in leaves[5:]:
        assert _thumb(leaf) not in message, message
        # Still listed for the operator.
        assert f"  {_pair(leaf, _NOT_A_CA)}" in proc.stdout.splitlines(), proc.stdout
    assert message.endswith("; and 2 more, listed above."), message


def test_a_listed_refused_certificate_names_no_store(
    chain: dict[str, tuple[x509.Certificate, _Key]], files: dict[str, Path]
) -> None:
    proc = _run_script(files["p7b_with_leaf"])
    lines = proc.stdout.splitlines()
    at = lines.index(f"  Thumbprint : {_thumb(chain['leaf'][0])}")
    block = list(itertools.takewhile(lambda ln: ln.startswith("  "), lines[at:]))
    assert f"  Refused    : {_NOT_A_CA}" in block, block
    assert not any(ln.startswith("  Store") for ln in block), block
    # The validity period is printed in UTC, so its 'Z' suffix is true.
    not_after = chain["leaf"][0].not_valid_after_utc.strftime("%Y-%m-%d %H:%M:%SZ")
    assert f"  Not after  : {not_after}" in block, block


def test_an_unelevated_import_is_refused_before_the_file_is_read(files: dict[str, Path]) -> None:
    if sys.platform != "win32":
        pytest.skip("SKIP (nothing run): the elevation check reads a Windows token")
    proc = _run_script(files["der"], whatif=False)
    assert proc.returncode != 0, proc.stdout + proc.stderr
    assert "requires an elevated (Administrator) PowerShell" in _error_message(proc)
    assert "The file holds" not in proc.stdout


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
    assert body.index("Get-ChainRefusal -Certificate") < body.index("ShouldProcess(")
    assert body.index("ShouldProcess(") < body.index("$store.Add(")
