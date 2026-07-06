<#
.SYNOPSIS
    Import a private / internal-CA certificate into the Windows LocalMachine\Root trust store so
    the MessageFoundry engine can validate a PostgreSQL or SQL Server TLS server certificate
    without disabling certificate validation.

.DESCRIPTION
    ODBC Driver 18 (the SQL Server backend) has no connection-string CA-file keyword: it validates
    the DB server certificate against the *machine* trust store only. When the database is fronted
    by a private or internal CA, that CA must be present in LocalMachine\Root or the chain won't
    build -- and operators are then tempted to set TrustServerCertificate=true, which disables
    validation and re-opens a man-in-the-middle path to PHI (NIST SP 800-52r2; CWE-295).

    This script imports the CA into the *machine* store (Cert:\LocalMachine\Root) -- not the
    per-user store (Cert:\CurrentUser\Root) -- so the service principal (LocalSystem / a gMSA /
    a dedicated service account) sees it. It is the supported full-chain-trust path:
    trust_server_certificate stays false and the engine validates the full chain.

    PostgreSQL can alternatively pin a CA by file via [store].ssl_root_cert (no machine import
    needed). This machine-store import is the path SQL Server REQUIRES; Postgres can use either.

    Run from an elevated (Administrator) PowerShell prompt. Idempotent: re-importing the same CA
    is a no-op (Import-Certificate keys on thumbprint).

.PARAMETER CaPath
    Path to the CA certificate to trust (PEM/.crt/.cer with the public cert, or .p7b chain).

.PARAMETER WhatIf
    Show what would be imported without changing the store.

.EXAMPLE
    .\import-db-ca.ps1 -CaPath C:\certs\internal-root-ca.crt

.EXAMPLE
    # Equivalent one-liner without this script:
    Import-Certificate -FilePath C:\certs\internal-root-ca.crt -CertStoreLocation Cert:\LocalMachine\Root
    # certutil equivalent (also writes LocalMachine\Root):
    certutil -addstore -f Root C:\certs\internal-root-ca.crt

.NOTES
    Standards: NIST SP 800-52r2 (validate the full chain to a trusted CA); HIPAA 164.312(e)(1)
    (transmission security); CWE-295 (improper certificate validation). See the CA-import and
    rotation runbooks in docs/DEPLOY-SERVER-DB.md.
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory = $true)]
    [string]$CaPath
)

$ErrorActionPreference = "Stop"

# The machine root store -- NOT the per-user store. The engine runs as a service principal
# (LocalSystem / gMSA / dedicated account), which only reads the machine store, so a CurrentUser
# import would be invisible to it.
$StoreLocation = "Cert:\LocalMachine\Root"

# --- preflight ---------------------------------------------------------------

$principal = [Security.Principal.WindowsPrincipal]::new(
    [Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw ("Importing into the machine trust store ($StoreLocation) requires an elevated " +
        "(Administrator) PowerShell.")
}

if (-not (Test-Path -LiteralPath $CaPath)) {
    throw "CA certificate not found at: $CaPath"
}
$CaPath = (Resolve-Path -LiteralPath $CaPath).Path

# --- import ------------------------------------------------------------------

# Read the cert first so we can show the operator exactly what they're trusting (and so a malformed
# file fails loudly before touching the store).
try {
    $cert = [Security.Cryptography.X509Certificates.X509Certificate2]::new($CaPath)
} catch {
    throw "Could not read '$CaPath' as an X.509 certificate: $($_.Exception.Message)"
}

Write-Host "About to trust CA in $StoreLocation :"
Write-Host "  Subject    : $($cert.Subject)"
Write-Host "  Issuer     : $($cert.Issuer)"
Write-Host "  Thumbprint : $($cert.Thumbprint)"
Write-Host "  Not after  : $($cert.NotAfter.ToString('u'))"

if ($PSCmdlet.ShouldProcess($StoreLocation, "Import CA '$($cert.Subject)'")) {
    # Import-Certificate keys on thumbprint, so re-importing the same CA is a no-op (idempotent).
    Import-Certificate -FilePath $CaPath -CertStoreLocation $StoreLocation | Out-Null
    Write-Host ""
    Write-Host "Imported. The DB server cert chaining to this CA now validates with" -ForegroundColor Green
    Write-Host "trust_server_certificate = false (no TrustServerCertificate=true needed)." -ForegroundColor Green
    Write-Host ""
    Write-Host "Rotation: when the CA is replaced, import the NEW CA first (this leaves both trusted),"
    Write-Host "roll the server cert, then remove the OLD CA -- see docs/DEPLOY-SERVER-DB.md."
}
