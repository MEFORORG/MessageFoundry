# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
<#
.SYNOPSIS
    Import a private / internal CA into the Windows machine certificate stores (a root into the
    LocalMachine\Root trust store, an issuing CA into LocalMachine\CA) so the MessageFoundry engine
    can validate a PostgreSQL or SQL Server TLS server certificate without disabling certificate
    validation.

.DESCRIPTION
    ODBC Driver 18 (the SQL Server backend) has no connection-string CA-file keyword: it validates
    the DB server certificate against the *machine* trust store only. When the database is fronted
    by a private or internal CA, that CA must be present in LocalMachine\Root or the chain won't
    build -- and operators are then tempted to set TrustServerCertificate=true, which disables
    validation and re-opens a man-in-the-middle path to PHI (NIST SP 800-52r2; CWE-295).

    This script imports the CA into the *machine* stores (Cert:\LocalMachine\Root, and
    Cert:\LocalMachine\CA for an issuing CA) -- not the per-user stores (Cert:\CurrentUser\...)
    -- so the service principal (LocalSystem / a gMSA / a dedicated service account) sees it.
    The file must hold the root: an issuing CA alone goes into LocalMachine\CA, which is not a
    trust anchor, and the script warns that the chain will not validate unless the root is
    already in LocalMachine\Root. It is the supported full-chain-trust path:
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
    Path to the CA certificate(s) to trust: a DER, base64 or PEM certificate (.cer/.crt/.pem, one
    certificate or a PEM bundle of several), or a .p7b chain (PKCS#7, signed or not, DER or base64).

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
# returned is the one shown, checked and added. A certificate or a PKCS#7 bundle (.p7b), signed or
# not, is accepted as DER, as bare base64 of DER, or as PEM text whose blocks are all CERTIFICATE
# (or its legacy spelling X509 CERTIFICATE) or PKCS7, in ASCII, UTF-8 or UTF-16 with a byte-order
# mark. The PEM is parsed here because Windows PowerShell 5.1's .NET Framework has no
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
    # Every piece of DER, the whole file or one PEM block, must be a certificate or a PKCS#7 chain,
    # so a .pfx is refused wherever it sits, before it is parsed.
    $importDer = {
        param([byte[]]$Der)
        try {
            $type = [System.Security.Cryptography.X509Certificates.X509Certificate2]::GetCertContentType($Der)
        } catch [System.Management.Automation.MethodInvocationException] {
            # .NET on Windows throws for content it cannot classify rather than answering Unknown.
            $type = 'Unknown'
        }
        if ($type -ne 'Cert' -and $type -ne 'Pkcs7') {
            throw ("The file holds '$type' content. Only a certificate or a .p7b chain is " +
                "accepted (a .pfx is refused: it carries a private key, which never belongs in " +
                "the trust store).")
        }
        $bundle.Import($Der)
    }
    # One DER value that spans the whole file (0x30 opens an ASN.1 SEQUENCE, then its length), so a
    # DER file whose bytes happen to spell '-----BEGIN ' is still read as DER, and a text file that
    # happens to start with '0' (also 0x30) is not.
    $wholeDer = $false
    if ($Bytes.Length -ge 2 -and $Bytes[0] -eq 0x30) {
        $first = [int]$Bytes[1]
        if ($first -lt 0x80) {
            $wholeDer = (2 + $first) -eq $Bytes.Length
        } elseif ($first -ge 0x81 -and $first -le 0x84 -and $Bytes.Length -ge 2 + ($first - 0x80)) {
            $n = $first - 0x80
            $length = [long]0
            for ($k = 0; $k -lt $n; $k++) { $length = $length * 256 + $Bytes[2 + $k] }
            $wholeDer = (2 + $n + $length) -eq $Bytes.Length
        }
    }
    if ($wholeDer) {
        & $importDer $Bytes
    } elseif ($text.Contains('-----BEGIN ')) {
        # Any armour makes a file that is not one DER value PEM, so the DER reader, which would
        # take its first certificate only, never sees a private-key block after it.
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
            # Either label may hold a PKCS#7 chain: AD CS web enrollment and certutil -encode
            # write a base64 .p7b under a CERTIFICATE header.
            & $importDer ([Convert]::FromBase64String(($block.Groups[2].Value -replace '\s', '')))
        }
    } elseif ($Bytes[0] -eq 0x30) {
        # DER that does not span the file, such as BER with an indefinite length.
        & $importDer $Bytes
    } elseif ($text -match '^[A-Za-z0-9+/=\s]+$') {
        # Base64 of a DER value with no armour, which the X509Certificate2 constructor this script
        # used before also read.
        $der = $null
        try {
            $der = [Convert]::FromBase64String(($text -replace '\s', ''))
        } catch [System.FormatException] {
            throw "The file looks like base64 but does not decode."
        }
        & $importDer $der
    }
    if ($bundle.Count -eq 0) {
        throw ("The file holds no certificate. Expected DER, base64, PEM armour such as " +
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
# constraints do not mark it as a CA cannot sign another, so it has no business in Root. A missing
# extension counts as not a CA here. RFC 5280 (the Basic Constraints section) requires the extension
# of a version 3 CA certificate; a version 1 root, which cannot carry it, is refused too, by this
# script's choice rather than the RFC's. A key usage extension that leaves out certificate signing
# also counts as not a CA (RFC 5280, the Key Usage section).
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

Write-Host "The file holds $($bundle.Count) certificate(s):"
$now = [datetime]::Now
$refusals = @()
# The store each certificate is shown with is the one it is offered for and written to.
$entries = @(foreach ($cert in $bundle) {
    $target = $stores[(Get-CaStoreName -Certificate $cert)]
    Write-Host ""
    Write-Host "  Subject    : $(ConvertTo-PrintableText $cert.Subject)"
    Write-Host "  Issuer     : $(ConvertTo-PrintableText $cert.Issuer)"
    Write-Host "  Thumbprint : $($cert.Thumbprint)"
    Write-Host "  Not after  : $($cert.NotAfter.ToString('u'))"
    Write-Host "  Store      : $($target.Label)"
    if ($cert.NotAfter -lt $now -or $cert.NotBefore -gt $now) {
        Write-Warning "$($cert.Thumbprint) is outside its validity period; a chain through it will not validate."
    }
    $why = Get-CaRefusal -Certificate $cert
    if ($why) { $refusals += "  $($cert.Thumbprint): $why" }
    @{ Certificate = $cert; Target = $target }
})
if ($refusals.Count -gt 0) {
    throw ("Nothing was imported. Every certificate in the file must be a CA without a private " +
        "key, and these are not:`n" + ($refusals -join "`n"))
}
if (-not ($entries | Where-Object { $_.Target -eq $stores['Root'] })) {
    Write-Warning ("The file holds no self-issued root, so nothing here becomes a trust anchor. A chain " +
        "through these CAs validates only if its root is already in $StoreLocation; import the root too.")
}

# --- import ------------------------------------------------------------------

$approved = @(foreach ($entry in $entries) {
    $cert = $entry.Certificate
    if ($PSCmdlet.ShouldProcess($entry.Target.Label, "Import CA '$(ConvertTo-PrintableText $cert.Subject)' ($($cert.Thumbprint))")) {
        $entry
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
    Write-Host "Imported $added CA certificate(s)."
    if ($approved | Where-Object { $_.Target -eq $stores['Root'] }) {
        Write-Host "A DB server cert chaining to the imported root now validates with" -ForegroundColor Green
        Write-Host "trust_server_certificate = false (no TrustServerCertificate=true needed)." -ForegroundColor Green
    } else {
        Write-Warning ("No root was imported, so a DB server cert validates only if its root is already " +
            "in $StoreLocation.")
    }
    Write-Host ""
    Write-Host "Rotation: when the CA is replaced, import the NEW CA first (this leaves both trusted),"
    Write-Host "roll the server cert, then remove the OLD CA -- see docs/DEPLOY-SERVER-DB.md."
}
