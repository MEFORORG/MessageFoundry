# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
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

    The file is read once. Every certificate it holds is shown, checked, and only then added, so
    nothing reaches the store that the operator was not shown. The whole file is refused, and
    nothing is imported, when any certificate in it is not marked as a CA by its basic
    constraints, or carries a private key. A .pfx and a PEM private-key block are refused outright.

    Run from an elevated (Administrator) PowerShell prompt; -WhatIf needs no elevation. Idempotent:
    re-importing the same CA is a no-op (the store keys on thumbprint).

.PARAMETER CaPath
    Path to the CA certificate(s) to trust: a DER or PEM certificate (.cer/.crt/.pem, one
    certificate or a PEM bundle of several), or a .p7b chain (PKCS#7, signed or not).

.PARAMETER WhatIf
    Show what would be imported without changing the store. Needs no elevation.

.EXAMPLE
    .\import-db-ca.ps1 -CaPath C:\certs\internal-root-ca.crt

.EXAMPLE
    # Equivalent one-liner without this script, only for a file holding ONE certificate you have
    # checked yourself: neither command checks that what it imports is a CA.
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
# import would be invisible to it. Built unopened here, and the label every prompt names is read
# from it, so the store the operator approves and the one written cannot drift apart.
$store = [System.Security.Cryptography.X509Certificates.X509Store]::new(
    [System.Security.Cryptography.X509Certificates.StoreName]::Root,
    [System.Security.Cryptography.X509Certificates.StoreLocation]::LocalMachine)
$StoreLocation = "Cert:\$($store.Location)\$($store.Name)"

# A certificate's Subject and Issuer are whatever its author wrote, and the file is one an operator
# was handed. An ESC sequence there could rewrite what this prompt shows, and a bidirectional
# override could reorder the name the operator is asked to trust, so every control character
# (Cc) and every format character (Cf: the bidi overrides and isolates, zero-width marks) prints
# as a visible \uXXXX before it reaches the console (ASVS 1.1.2). Line and paragraph separators,
# private-use and unassigned code points go the same way -- the same categories as
# CONTROL_CATEGORIES in messagefoundry/controlchars.py, since this .NET runtime's tables cannot
# vouch for an unassigned one. So does every surrogate: PowerShell walks UTF-16 code units, so a
# character past the BMP prints as its escaped pair rather than being judged half at a time.
# A run of backslashes is doubled whole where it stands before 'u' and four hex digits or before a
# character about to be escaped, so a Subject spelling \u202e cannot pass for an escaped one.
# Unlike that module this helper writes only \uXXXX escapes (an ESC shows as \u001b, not \x1b),
# so 'u' is the only lookalike it guards.
function Test-EscapedForConsole {
    param([char]$C)
    $cat = [System.Globalization.CharUnicodeInfo]::GetUnicodeCategory($C)
    return ([char]::IsControl($C) -or
        $cat -eq [System.Globalization.UnicodeCategory]::Format -or
        $cat -eq [System.Globalization.UnicodeCategory]::LineSeparator -or
        $cat -eq [System.Globalization.UnicodeCategory]::ParagraphSeparator -or
        $cat -eq [System.Globalization.UnicodeCategory]::Surrogate -or
        $cat -eq [System.Globalization.UnicodeCategory]::PrivateUse -or
        $cat -eq [System.Globalization.UnicodeCategory]::OtherNotAssigned)
}

function ConvertTo-PrintableText {
    param([AllowNull()][AllowEmptyString()][string]$Text)
    if ($null -eq $Text) { return '' }
    # 'u' and four hex digits, anchored (\G) at the index Match is handed.
    $lookalike = [regex]::new('\Gu[0-9A-Fa-f]{4}')
    $out = [System.Text.StringBuilder]::new($Text.Length)
    $i = 0
    while ($i -lt $Text.Length) {
        $c = $Text[$i]
        if ($c -eq [char]'\') {
            $end = $i
            while ($end -lt $Text.Length -and $Text[$end] -eq [char]'\') { $end++ }
            $run = $Text.Substring($i, $end - $i)
            # Only the characters at $end are read, never a copy of the rest, so a Subject of
            # many short runs stays one linear pass.
            if ($lookalike.Match($Text, $end).Success -or
                ($end -lt $Text.Length -and (Test-EscapedForConsole $Text[$end]))) {
                $run = $run + $run
            }
            [void]$out.Append($run)
            $i = $end
            continue
        }
        if (Test-EscapedForConsole $c) {
            [void]$out.Append('\u').Append(([int]$c).ToString('x4'))
        } else {
            [void]$out.Append($c)
        }
        $i++
    }
    return $out.ToString()
}

# Every certificate the file holds, parsed from bytes the caller read once, so the collection
# returned is the one shown, checked and added. Only two shapes are accepted. One is DER, a single
# certificate or a PKCS#7 bundle (.p7b), signed or not. The other is PEM text whose blocks are all
# CERTIFICATE or PKCS7. The PEM is parsed here because Windows PowerShell 5.1's .NET Framework has
# no ImportFromPem, which would in any case skip a private-key block silently. A PKCS#12 (.pfx) and a PEM private-key block are refused before any of it is parsed, so no
# private key is ever loaded: a key has no place in a trust-store import, and such a file is
# usually a server certificate handed over by mistake.
function Read-CaBundle {
    param([Parameter(Mandatory = $true)][AllowEmptyCollection()][byte[]]$Bytes)
    $bundle = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2Collection
    if ($Bytes.Length -eq 0) { throw "The file is empty." }
    if ($Bytes[0] -eq 0x30) {
        # 0x30 opens an ASN.1 SEQUENCE: DER, which may be a certificate, a PKCS#7 or a PKCS#12.
        $type = [System.Security.Cryptography.X509Certificates.X509Certificate2]::GetCertContentType($Bytes)
        if ($type -ne 'Cert' -and $type -ne 'Pkcs7') {
            throw ("The file holds '$type' content. Only a certificate or a .p7b chain is " +
                "accepted; a .pfx carries a private key, which never belongs in the trust store.")
        }
        $bundle.Import($Bytes)
    } else {
        $text = [System.Text.Encoding]::ASCII.GetString($Bytes)
        $labels = [regex]::Matches($text, '-----BEGIN ([^\r\n]*?)-----')
        foreach ($label in $labels) {
            if ($label.Groups[1].Value -cnotin @('CERTIFICATE', 'PKCS7')) {
                throw ("The file holds a PEM block labelled '$(ConvertTo-PrintableText $label.Groups[1].Value)'. " +
                    "Only CERTIFICATE and PKCS7 blocks are accepted; a private key never belongs in the trust store.")
            }
        }
        $blocks = [regex]::Matches($text,
            '-----BEGIN (CERTIFICATE|PKCS7)-----([A-Za-z0-9+/=\s]*)-----END \1-----')
        if ($blocks.Count -ne $labels.Count) {
            throw "The file has a PEM block that is not well formed."
        }
        foreach ($block in $blocks) {
            $der = [Convert]::FromBase64String(($block.Groups[2].Value -replace '\s', ''))
            # The block's content must be what its label says, so a PKCS#7 under a CERTIFICATE
            # label, or a .pfx under either, is refused rather than read as whatever it holds.
            $want = if ($block.Groups[1].Value -ceq 'CERTIFICATE') { 'Cert' } else { 'Pkcs7' }
            if ([System.Security.Cryptography.X509Certificates.X509Certificate2]::GetCertContentType($der) -ne $want) {
                throw "A PEM $($block.Groups[1].Value) block does not hold what its label says."
            }
            $bundle.Import($der)
        }
    }
    if ($bundle.Count -eq 0) { throw "The file holds no certificate." }
    return , $bundle
}

# Why the certificate must not be trusted as a CA, or $null when it may be. A certificate whose basic
# constraints do not mark it as a CA cannot sign another, so it has no business in Root; a missing
# extension counts as not a CA (RFC 5280, the Basic Constraints section).
function Get-CaRefusal {
    param([Parameter(Mandatory = $true)][System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate)
    # Read-CaBundle already refuses every container that can carry a key; this holds if it ever stops.
    if ($Certificate.HasPrivateKey) { return 'it carries a private key' }
    $constraints = @($Certificate.Extensions |
        Where-Object { $_ -is [System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension] })
    if ($constraints.Count -eq 0) { return 'it has no basic constraints extension, so it is not marked as a CA' }
    if (@($constraints | Where-Object { -not $_.CertificateAuthority }).Count -gt 0) {
        return 'its basic constraints say it is not a CA'
    }
    return $null
}

# --- read and check --------------------------------------------------------------

if (-not (Test-Path -LiteralPath $CaPath -PathType Leaf)) {
    throw "CA certificate not found at: $CaPath"
}
$CaPath = (Resolve-Path -LiteralPath $CaPath).Path

# Read once, and parse before touching the store, so a malformed file fails loudly and the operator
# sees exactly what they are trusting.
try {
    $bundle = Read-CaBundle -Bytes ([System.IO.File]::ReadAllBytes($CaPath))
} catch {
    throw "Could not read '$CaPath' as X.509 CA certificates: $($_.Exception.Message)"
}

Write-Host "About to trust $($bundle.Count) CA certificate(s) in $StoreLocation :"
$refusals = @()
foreach ($cert in $bundle) {
    Write-Host ""
    Write-Host "  Subject    : $(ConvertTo-PrintableText $cert.Subject)"
    Write-Host "  Issuer     : $(ConvertTo-PrintableText $cert.Issuer)"
    Write-Host "  Thumbprint : $($cert.Thumbprint)"
    Write-Host "  Not after  : $($cert.NotAfter.ToString('u'))"
    $why = Get-CaRefusal -Certificate $cert
    if ($why) { $refusals += "  $($cert.Thumbprint): $why" }
}
if ($refusals.Count -gt 0) {
    throw ("Nothing was imported. Every certificate in the file must be a CA without a private " +
        "key, and these are not:`n" + ($refusals -join "`n"))
}

# --- import ------------------------------------------------------------------

$approved = @(foreach ($cert in $bundle) {
    if ($PSCmdlet.ShouldProcess($StoreLocation, "Import CA '$(ConvertTo-PrintableText $cert.Subject)' ($($cert.Thumbprint))")) {
        $cert
    }
})

if ($approved.Count -gt 0) {
    # Checked here, beside the write, so -WhatIf previews the file without elevation.
    $principal = [Security.Principal.WindowsPrincipal]::new(
        [Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw ("Importing into the machine trust store ($StoreLocation) requires an elevated " +
            "(Administrator) PowerShell.")
    }
    # The store keys on thumbprint, so re-importing the same CA is a no-op (idempotent).
    $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
    try {
        foreach ($cert in $approved) { $store.Add($cert) }
    } finally {
        $store.Close()
    }
    Write-Host ""
    Write-Host "Imported $($approved.Count) CA certificate(s). The DB server cert chaining to them now validates with" -ForegroundColor Green
    Write-Host "trust_server_certificate = false (no TrustServerCertificate=true needed)." -ForegroundColor Green
    Write-Host ""
    Write-Host "Rotation: when the CA is replaced, import the NEW CA first (this leaves both trusted),"
    Write-Host "roll the server cert, then remove the OLD CA -- see docs/DEPLOY-SERVER-DB.md."
}
