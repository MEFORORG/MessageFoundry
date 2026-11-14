# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""``import-db-ca.ps1`` reads every certificate in the file, and trusts only CAs (BACKLOG #5561).

The script used to build one ``X509Certificate2`` from the path and then hand the path to
``Import-Certificate``. An unsigned ``.p7b`` chain, the shape the help advertises, made the
constructor throw ``Cannot find the original signer``; a PEM bundle showed the operator only its
first certificate. Now the bytes are read once into a collection, every certificate in it is shown
and checked, and the whole file is refused when any one is not a CA or carries a private key.

NOTHING HERE WRITES A CERTIFICATE STORE. The fixtures are generated in a pytest temporary
directory. The function-level tests lift ``Read-CaBundle`` and ``Get-CaRefusal`` (and the console
helpers they call) out of the script's AST and call them, as
``tests/test_import_db_ca_console_text.py`` does. The whole-script tests run it with ``-WhatIf``
only, where ``ShouldProcess`` declines every import, so the store is never opened; they are also
skipped in an elevated session, so even a regression that ignored ``-WhatIf`` would meet the
script's own elevation refusal rather than the machine Root store. Both halves need ``pwsh`` and
skip where there is none.
"""

from __future__ import annotations

import datetime
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
from cryptography.hazmat.primitives.asymmetric import ec
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
    cn: str, ca: bool | None, issuer: tuple[x509.Certificate, _Key] | None = None
) -> tuple[x509.Certificate, _Key]:
    """A synthetic certificate. ``ca`` None leaves the basic constraints extension out."""
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = datetime.datetime.now(datetime.UTC)
    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(issuer[0].subject if issuer else name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=30))
    )
    if ca is not None:
        builder = builder.add_extension(x509.BasicConstraints(ca=ca, path_length=None), True)
    return builder.sign(issuer[1] if issuer else key, hashes.SHA256()), key


def _thumb(cert: x509.Certificate) -> str:
    return cert.fingerprint(hashes.SHA1()).hex().upper()


def _pem(*certs: x509.Certificate) -> bytes:
    return b"".join(c.public_bytes(serialization.Encoding.PEM) for c in certs)


@pytest.fixture(scope="module")
def chain() -> dict[str, tuple[x509.Certificate, _Key]]:
    root = _cert("Synthetic Test Root CA", True)
    return {
        "root": root,
        "intermediate": _cert("Synthetic Test Issuing CA", True, root),
        "leaf": _cert("db.test.invalid", False, root),
        "unconstrained": _cert("Synthetic No Constraints", None),
    }


@pytest.fixture(scope="module")
def files(
    tmp_path_factory: pytest.TempPathFactory, chain: dict[str, tuple[x509.Certificate, _Key]]
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
        "empty": b"",
        "garbage": b"not a certificate at all\n",
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
    """Each file through ``Read-CaBundle`` then ``Get-CaRefusal``, as the script does."""
    script = f"""
$ErrorActionPreference = 'Stop'
$ast = [System.Management.Automation.Language.Parser]::ParseFile(
    {_psq(str(_SCRIPT))}, [ref]$null, [ref]$null)
foreach ($name in @('Test-EscapedForConsole', 'ConvertTo-PrintableText', 'Read-CaBundle',
                    'Get-CaRefusal')) {{
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
      @{{ thumb = $c.Thumbprint; refusal = (Get-CaRefusal -Certificate $c) }} }}) }}
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
    tmp_path: Path, chain: dict[str, tuple[x509.Certificate, _Key]], files: dict[str, Path]
) -> None:
    got = _read_all(tmp_path, files)
    root = _thumb(chain["root"][0])
    inter = _thumb(chain["intermediate"][0])

    def certs(name: str) -> list[tuple[str, str | None]]:
        entry = got[name]
        assert "error" not in entry, f"{name}: {entry}"
        listed = entry["certs"]
        assert isinstance(listed, list)
        return [(c["thumb"], c["refusal"]) for c in listed]

    # Accepted: the unsigned .p7b chain the help advertises, in both encodings, and a PEM bundle,
    # each read in full -- not its first certificate only.
    assert certs("der") == [(root, None)]
    assert certs("pem_one") == [(root, None)]
    for name in ("p7b_der", "p7b_pem", "pem_bundle"):
        assert sorted(certs(name)) == sorted([(root, None), (inter, None)]), name

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

    # Refused before anything is parsed: a private key, in either container, and what is not a
    # certificate file at all.
    def error(name: str) -> str:
        entry = got[name]
        assert "error" in entry, f"{name} was accepted: {entry}"
        return str(entry["error"])

    assert "'Pfx' content" in error("pfx")
    assert "labelled 'PRIVATE KEY'" in error("pem_with_key")
    assert "not well formed" in error("pem_unterminated")
    assert "empty" in error("empty")
    assert "no certificate" in error("garbage")


def _run_whatif(ca_path: Path) -> subprocess.CompletedProcess[str]:
    if _elevated():
        pytest.skip("SKIP (nothing run): elevated session; the script is run only unelevated")
    return subprocess.run(
        [
            _pwsh(),
            "-NoProfile",
            "-NonInteractive",
            "-File",
            str(_SCRIPT),
            "-CaPath",
            str(ca_path),
            "-WhatIf",
        ],
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=120,
    )


def test_whatif_shows_and_offers_every_certificate_of_an_unsigned_p7b(
    chain: dict[str, tuple[x509.Certificate, _Key]], files: dict[str, Path]
) -> None:
    proc = _run_whatif(files["p7b_der"])
    out = proc.stdout + proc.stderr
    assert proc.returncode == 0, out
    assert "About to trust 2 CA certificate(s)" in out
    for key in ("root", "intermediate"):
        thumb = _thumb(chain[key][0])
        assert f"Thumbprint : {thumb}" in out
        assert any("What if" in ln and thumb in ln for ln in out.splitlines()), thumb
    assert "Imported" not in out


def test_a_bundle_holding_a_non_ca_imports_nothing(
    chain: dict[str, tuple[x509.Certificate, _Key]], files: dict[str, Path]
) -> None:
    proc = _run_whatif(files["p7b_with_leaf"])
    out = proc.stdout + proc.stderr
    assert proc.returncode != 0, out
    assert "Nothing was imported" in out
    assert f"{_thumb(chain['leaf'][0])}: its basic constraints say it is not a CA" in out
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
    # Every certificate is checked before a single import is offered.
    assert body.index("Get-CaRefusal -Certificate") < body.index("ShouldProcess(")
    assert body.index("ShouldProcess(") < body.index("$store.Add(")
