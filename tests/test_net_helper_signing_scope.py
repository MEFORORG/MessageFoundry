# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Pin where ``.github/workflows/net-helper.yml`` reads its code-signing secrets (BACKLOG #1537).

A secret read in a job that names no environment can only be a repository or organization secret, and
any branch can run its own copy of a workflow that reads one. The key is safe only in a job that names
the ``net-helper-signing`` environment, once a repository administrator restricts that environment's
deployment branches to ``main``. No test here can see that setting. These tests see the file, where one
honest edit could move a secret back into the build job, give the signing job a token scope, or let it
run for pull requests. Each test fails on one such edit.

They do not stop a hostile branch, which can edit this file too. The environment's branch rule does.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest

from tests._workflow_contexts import jobs_of, step_script

_WORKFLOW = "net-helper.yml"
_ENVIRONMENT = "net-helper-signing"
_ON_MAIN = "github.ref == 'refs/heads/main'"


def _reads_a_secret(node: Any) -> bool:
    # Parsed YAML carries no comments, so prose that mentions the secrets context cannot match.
    return "secrets." in repr(node)


def test_only_the_sign_job_reads_a_secret() -> None:
    readers = {key for key, job in jobs_of(_WORKFLOW).items() if _reads_a_secret(job)}
    assert readers == {"sign"}, (
        f"jobs reading a secret: {sorted(readers)}. A job with no environment can only read a "
        f"repository or organization secret, which any branch can read too."
    )


def test_the_sign_job_names_the_environment_and_runs_only_on_main() -> None:
    sign = jobs_of(_WORKFLOW)["sign"]
    assert sign.get("environment") == _ENVIRONMENT
    # Skipped rather than failed elsewhere: a job naming a branch-restricted environment on another ref
    # fails, which would turn every pull request touching the helper red.
    assert str(sign.get("if", "")).strip() == _ON_MAIN
    assert sign.get("needs") == "build"


def test_the_sign_job_holds_no_token_scope_and_checks_out_nothing() -> None:
    sign = jobs_of(_WORKFLOW)["sign"]
    assert sign.get("permissions") == {}
    uses = [str(step.get("uses", "")) for step in sign.get("steps", [])]
    assert uses, "the sign job has no steps, so the checkout assertion below would pass vacuously"
    assert not any(u.startswith("actions/checkout@") for u in uses), uses


def test_the_sign_step_keeps_its_own_ref_guard() -> None:
    steps = [s for s in jobs_of(_WORKFLOW)["sign"].get("steps", []) if s.get("id") == "sign"]
    assert len(steps) == 1, "expected exactly one step with id: sign"
    assert _ON_MAIN in str(steps[0].get("if", ""))


def test_the_build_job_names_no_environment() -> None:
    # Once the environment admits only main, naming it here would fail every pull request run.
    assert "environment" not in jobs_of(_WORKFLOW)["build"]


# --- the signing step itself (BACKLOG #5478) --------------------------------------------------------


def _sign_script() -> str:
    # Comment lines stripped, so no needle below can be met by prose.
    return step_script(_WORKFLOW, "sign", "Sign (signtool")[1]


def test_the_key_import_sits_inside_the_try_whose_finally_deletes_it() -> None:
    """RED when: the PersistKeySet import runs before the try, or the finally stops deleting the key.

    PersistKeySet writes the private key to the user's key store. Imported outside the try, a failure
    between the import and the try left it there; removing the certificate from the store never
    deleted the key file at all.
    """
    script = _sign_script()
    import_at = script.index("X509Certificate2]::new(")
    try_at = script.find("try {")
    assert 0 <= try_at < import_at, "the certificate import must sit inside the try block"
    finally_block = script[script.index("} finally {", import_at) :]
    assert "$store.Remove($cert)" in finally_block
    delete_at = finally_block.index(".Key.Delete()")
    assert "PersistKeyInCsp = $false" in finally_block, "the finally block must delete a CSP key"
    # The key goes first: a store call that throws must not stop the key from being deleted.
    assert delete_at < finally_block.index("$store.Remove($cert)")


_VERIFY_START = "$signature = Get-AuthenticodeSignature"
_VERIFY_END = 'Write-Host "signed by'

#: Builds a self-signed certificate in memory (nothing reaches a store or the disk), stubs
#: Get-AuthenticodeSignature -- a function shadows the cmdlet -- and runs the shipped check verbatim.
_HARNESS = r"""
$ErrorActionPreference = 'Stop'
function New-ProbeCertificate([string]$eku) {
  $rsa = [System.Security.Cryptography.RSA]::Create(2048)
  $req = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new(
    'CN=net-helper probe', $rsa, 'SHA256', [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
  $oids = [System.Security.Cryptography.OidCollection]::new()
  $null = $oids.Add([System.Security.Cryptography.Oid]::new($eku))
  $req.CertificateExtensions.Add(
    [System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]::new($oids, $false))
  $req.CreateSelfSigned([datetimeoffset]::Now.AddDays(-1), [datetimeoffset]::Now.AddDays(1))
}
$signer = New-ProbeCertificate $env:PROBE_EKU
$thumbprint = if ($env:PROBE_SAME_SIGNER -eq '1') { $signer.Thumbprint } else { 'DEADBEEF' }
function Get-AuthenticodeSignature {
  param($FilePath)
  [pscustomobject]@{
    SignerCertificate = $signer
    TimeStamperCertificate = $signer
    Status = $env:PROBE_STATUS
    StatusMessage = 'probe'
  }
}
$exe = 'mefor-net-helper.exe'
"""

_CODE_SIGNING = "1.3.6.1.5.5.7.3.3"
_SERVER_AUTH = "1.3.6.1.5.5.7.3.1"


@pytest.mark.skipif(shutil.which("pwsh") is None, reason="pwsh not on PATH")
@pytest.mark.parametrize(
    ("status", "same_signer", "eku", "accepted"),
    [
        ("Valid", True, _CODE_SIGNING, True),
        # An internal CA's root is untrusted on the runner, which Get-AuthenticodeSignature reports
        # as UnknownError. Accepted only when the chain fails for the unknown CA alone.
        ("UnknownError", True, _CODE_SIGNING, True),
        ("UnknownError", True, _SERVER_AUTH, False),
        ("HashMismatch", True, _CODE_SIGNING, False),
        ("NotSigned", True, _CODE_SIGNING, False),
        ("NotTrusted", True, _CODE_SIGNING, False),
        # Signed and timestamped, but by some certificate other than the one imported.
        ("Valid", False, _CODE_SIGNING, False),
    ],
)
def test_the_signature_check_refuses_more_than_absence(
    tmp_path: Path, status: str, same_signer: bool, eku: str, accepted: bool
) -> None:
    """RED when: the check accepts a signature on presence alone (BACKLOG #5478).

    The shipped check is run verbatim against a stubbed signature. A broken, foreign or distrusted
    signature must fail the step; a valid one, or one whose only fault is an unknown CA, must pass.
    """
    script = _sign_script()
    start = script.index(_VERIFY_START)
    end = script.index(_VERIFY_END, start)
    probe = tmp_path / "verify.ps1"
    probe.write_text(_HARNESS + script[start:end] + "\n'VERIFIED'\n", encoding="utf-8")
    env = {
        **os.environ,
        "PROBE_STATUS": status,
        "PROBE_SAME_SIGNER": "1" if same_signer else "0",
        "PROBE_EKU": eku,
    }
    proc = subprocess.run(
        ["pwsh", "-NoProfile", "-NonInteractive", "-File", str(probe)],
        capture_output=True,
        text=True,
        timeout=120,
        env=env,
    )
    verified = proc.returncode == 0 and "VERIFIED" in proc.stdout
    assert verified is accepted, (
        f"status={status} same_signer={same_signer} eku={eku}: rc={proc.returncode}\n"
        f"--- stdout ---\n{proc.stdout}\n--- stderr ---\n{proc.stderr}"
    )
