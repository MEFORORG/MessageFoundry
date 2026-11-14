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
    nothing reaches a store that the operator was not shown. The whole file is refused, and
    nothing is imported, when any certificate in it is not marked as a CA by its basic
    constraints, has a key usage that cannot sign certificates, or carries a private key. A .pfx
    and a PEM private-key block are refused outright. A self-issued root goes into
    LocalMachine\Root; any other CA in the file, such as an issuing CA in a .p7b chain, goes into
    the intermediate store LocalMachine\CA, so it helps build the chain without becoming a trust
    anchor itself.

    Run from an elevated (Administrator) PowerShell prompt; -WhatIf needs no elevation and changes
    nothing. Idempotent: re-importing the same CA is a no-op (each store keys on thumbprint).

.PARAMETER CaPath
    Path to the CA certificate(s) to trust: a DER or PEM certificate (.cer/.crt/.pem, one
    certificate or a PEM bundle of several), or a .p7b chain (PKCS#7, signed or not).

.PARAMETER WhatIf
    Show what would be imported without changing the store. Needs no elevation.

.EXAMPLE
    .\import-db-ca.ps1 -CaPath C:\certs\internal-root-ca.crt

.EXAMPLE
    # Equivalent one-liner without this script, only for a file holding ONE self-issued root CA
    # you have checked yourself: neither command checks that what it imports is a CA.
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

# The machine stores -- NOT the per-user ones. The engine runs as a service principal
# (LocalSystem / gMSA / dedicated account), which only reads the machine stores, so a CurrentUser
# import would be invisible to it. A self-issued CA (a root) goes into Root, the trust anchors. Any
# other CA, such as the issuing CA a .p7b chain carries, goes into the machine's intermediate store
# (CA), where chain building finds it without trusting it: in Root it would end the chain itself,
# so its root's revocation and constraints would never be checked. Each store is built unopened
# here, and the label every prompt names is read from it, so the store the operator approves and
# the one written cannot drift apart.
$stores = @{}
foreach ($name in 'Root', 'CertificateAuthority') {
    $s = [System.Security.Cryptography.X509Certificates.X509Store]::new(
        [System.Security.Cryptography.X509Certificates.StoreName]::$name,
        [System.Security.Cryptography.X509Certificates.StoreLocation]::LocalMachine)
    $stores[$name] = @{ Store = $s; Label = "Cert:\$($s.Location)\$($s.Name)" }
}
$StoreLocation = $stores['Root'].Label

# Checked before anything else, so a run that could change a store stops at once without
# administrator rights. A -WhatIf run changes nothing, so it may preview a file unelevated.
if (-not $WhatIfPreference) {
    $principal = [Security.Principal.WindowsPrincipal]::new(
        [Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw ("Importing into the machine trust store ($StoreLocation) requires an elevated " +
            "(Administrator) PowerShell.")
    }
}

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
# CERTIFICATE (or its legacy spelling X509 CERTIFICATE) or PKCS7, in ASCII, UTF-8 or UTF-16 with a
# byte-order mark. The PEM is parsed here because Windows PowerShell 5.1's .NET Framework has no
# ImportFromPem, which would in any case skip a private-key block silently. A PKCS#12 (.pfx) and a
# PEM private-key block are refused before any of it is parsed, so no private key is ever loaded:
# a key has no place in a trust-store import, and such a file is usually a server certificate
# handed over by mistake. A certificate the file holds twice is kept once.
function Read-CaBundle {
    param([Parameter(Mandatory = $true)][AllowEmptyCollection()][byte[]]$Bytes)
    $bundle = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2Collection
    if ($Bytes.Length -eq 0) { throw "The file is empty." }
    $encoding = [System.Text.Encoding]::ASCII
    if ($Bytes.Length -ge 2 -and $Bytes[0] -eq 0xFF -and $Bytes[1] -eq 0xFE) {
        $encoding = [System.Text.Encoding]::Unicode
    } elseif ($Bytes.Length -ge 2 -and $Bytes[0] -eq 0xFE -and $Bytes[1] -eq 0xFF) {
        $encoding = [System.Text.Encoding]::BigEndianUnicode
    }
    $text = $encoding.GetString($Bytes)
    if ($text.Contains('-----BEGIN ')) {
        # Any armour at all makes the file PEM, whatever its first byte, so a text file that
        # happens to start with '0' (0x30) is never handed to the DER reader, which would take its
        # first certificate only and never see a private-key block after it.
        $labels = [regex]::Matches($text, '-----BEGIN ([^\r\n]*?)-----')
        foreach ($label in $labels) {
            if ($label.Groups[1].Value -cnotin @('CERTIFICATE', 'X509 CERTIFICATE', 'PKCS7')) {
                throw ("The file holds a PEM block labelled '$(ConvertTo-PrintableText $label.Groups[1].Value)'. " +
                    "Only CERTIFICATE, X509 CERTIFICATE and PKCS7 blocks are accepted. Remove the " +
                    "others; a private key, for one, never belongs in the trust store.")
            }
        }
        $blocks = [regex]::Matches($text,
            '-----BEGIN (CERTIFICATE|X509 CERTIFICATE|PKCS7)-----([A-Za-z0-9+/=\s]*)-----END \1-----')
        if ($blocks.Count -ne $labels.Count) {
            throw "The file has a PEM block that is not well formed."
        }
        foreach ($block in $blocks) {
            $der = [Convert]::FromBase64String(($block.Groups[2].Value -replace '\s', ''))
            # The block's content must be what its label says, so a PKCS#7 under a CERTIFICATE
            # label, or a .pfx under either, is refused rather than read as whatever it holds.
            $want = if ($block.Groups[1].Value -ceq 'PKCS7') { 'Pkcs7' } else { 'Cert' }
            if ([System.Security.Cryptography.X509Certificates.X509Certificate2]::GetCertContentType($der) -ne $want) {
                throw "A PEM $($block.Groups[1].Value) block does not hold what its label says."
            }
            $bundle.Import($der)
        }
    } elseif ($Bytes[0] -eq 0x30) {
        # 0x30 opens an ASN.1 SEQUENCE: DER, which may be a certificate, a PKCS#7 or a PKCS#12.
        $type = [System.Security.Cryptography.X509Certificates.X509Certificate2]::GetCertContentType($Bytes)
        if ($type -ne 'Cert' -and $type -ne 'Pkcs7') {
            throw ("The file holds '$type' content. Only a certificate or a .p7b chain is " +
                "accepted; a .pfx carries a private key, which never belongs in the trust store.")
        }
        $bundle.Import($Bytes)
    }
    if ($bundle.Count -eq 0) {
        throw ("The file holds no certificate. Expected DER, PEM armour such as " +
            "'-----BEGIN CERTIFICATE-----', or a .p7b chain.")
    }
    $unique = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2Collection
    $seen = @{}
    foreach ($certificate in $bundle) {
        if (-not $seen.ContainsKey($certificate.Thumbprint)) {
            $seen[$certificate.Thumbprint] = $true
            [void]$unique.Add($certificate)
        }
    }
    return , $unique
}

# The store a checked CA belongs in: Root for a self-issued one, whose subject and issuer are the
# same name, and CertificateAuthority (the intermediate store) for any other. See $stores above.
function Get-CaStoreName {
    param([Parameter(Mandatory = $true)][System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate)
    $subject = [Convert]::ToBase64String($Certificate.SubjectName.RawData)
    $issuer = [Convert]::ToBase64String($Certificate.IssuerName.RawData)
    if ($subject -ceq $issuer) { return 'Root' }
    return 'CertificateAuthority'
}

# Why the certificate must not be trusted as a CA, or $null when it may be. A certificate whose basic
# constraints do not mark it as a CA cannot sign another, so it has no business in Root; a missing
# extension counts as not a CA (RFC 5280, the Basic Constraints section), and so does a key usage
# extension that leaves out certificate signing (RFC 5280, the Key Usage section).
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
    $keyCertSign = [System.Security.Cryptography.X509Certificates.X509KeyUsageFlags]::KeyCertSign
    foreach ($usage in @($Certificate.Extensions |
            Where-Object { $_ -is [System.Security.Cryptography.X509Certificates.X509KeyUsageExtension] })) {
        if (-not ($usage.KeyUsages -band $keyCertSign)) {
            return 'its key usage does not allow it to sign certificates'
        }
    }
    return $null
}

# --- read and check --------------------------------------------------------------

if (-not (Test-Path -LiteralPath $CaPath -PathType Leaf)) {
    throw "CA certificate not found at: $CaPath"
}
# The provider path, which .NET can open: .Path keeps a PSDrive name, or the provider prefix of a UNC
# path, and ReadAllBytes would then report the file as malformed.
$CaPath = (Resolve-Path -LiteralPath $CaPath).ProviderPath

# Read once, and parse before touching the store, so a malformed file fails loudly and the operator
# sees exactly what they are trusting.
try {
    $bundle = Read-CaBundle -Bytes ([System.IO.File]::ReadAllBytes($CaPath))
} catch {
    throw "Could not read '$CaPath' as X.509 CA certificates: $($_.Exception.Message)"
}

Write-Host "About to trust $($bundle.Count) CA certificate(s):"
$now = [datetime]::Now
$refusals = @()
foreach ($cert in $bundle) {
    Write-Host ""
    Write-Host "  Subject    : $(ConvertTo-PrintableText $cert.Subject)"
    Write-Host "  Issuer     : $(ConvertTo-PrintableText $cert.Issuer)"
    Write-Host "  Thumbprint : $($cert.Thumbprint)"
    Write-Host "  Not after  : $($cert.NotAfter.ToString('u'))"
    Write-Host "  Store      : $($stores[(Get-CaStoreName -Certificate $cert)].Label)"
    if ($cert.NotAfter -lt $now -or $cert.NotBefore -gt $now) {
        Write-Warning "$($cert.Thumbprint) is outside its validity period; a chain through it will not validate."
    }
    $why = Get-CaRefusal -Certificate $cert
    if ($why) { $refusals += "  $($cert.Thumbprint): $why" }
}
if ($refusals.Count -gt 0) {
    throw ("Nothing was imported. Every certificate in the file must be a CA without a private " +
        "key, and these are not:`n" + ($refusals -join "`n"))
}

# --- import ------------------------------------------------------------------

$approved = @(foreach ($cert in $bundle) {
    $target = $stores[(Get-CaStoreName -Certificate $cert)]
    if ($PSCmdlet.ShouldProcess($target.Label, "Import CA '$(ConvertTo-PrintableText $cert.Subject)' ($($cert.Thumbprint))")) {
        @{ Certificate = $cert; Target = $target }
    }
})

if ($approved.Count -gt 0) {
    # Each store keys on thumbprint, so re-importing the same CA is a no-op (idempotent).
    $added = 0
    try {
        foreach ($entry in $approved) {
            $entry.Target.Store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
            try {
                $entry.Target.Store.Add($entry.Certificate)
            } finally {
                $entry.Target.Store.Close()
            }
            $added++
        }
    } catch {
        throw ("Added $added of $($approved.Count) certificate(s), in the order shown, before this " +
            "failed: $($_.Exception.Message)")
    }
    Write-Host ""
    Write-Host "Imported $added CA certificate(s). The DB server cert chaining to them now validates with" -ForegroundColor Green
    Write-Host "trust_server_certificate = false (no TrustServerCertificate=true needed)." -ForegroundColor Green
    Write-Host ""
    Write-Host "Rotation: when the CA is replaced, import the NEW CA first (this leaves both trusted),"
    Write-Host "roll the server cert, then remove the OLD CA -- see docs/DEPLOY-SERVER-DB.md."
}
