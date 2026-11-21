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
    the DB server certificate against the *machine* stores only. When the database is fronted by a
    private or internal CA, that CA's root must be present in LocalMachine\Root or the chain won't
    build -- and operators are then tempted to set TrustServerCertificate=true, which disables
    validation and re-opens a man-in-the-middle path to PHI (NIST SP 800-52r2; CWE-295).

    This script imports the CA into the *machine* stores -- not the per-user stores
    (Cert:\CurrentUser\...) -- so the service principal (LocalSystem / a gMSA / a dedicated service
    account) sees it. It is the supported full-chain-trust path: trust_server_certificate stays
    false and the engine validates the full chain.

    Which store each CA goes into, and what each store is a trust anchor for, is stated once, in
    docs/DEPLOY-SERVER-DB.md section 5.2 ("Where each CA goes"), and so is the PowerShell version
    this needs.

    What this script checks. This paragraph states the chain and root checks, and the paragraph
    that starts "The file is read once" states at least the other refusals. The file is also
    refused when, at least, it is empty, holds a PEM block that is not well formed, holds base64
    that does not decode, or holds no certificate.
    docs/DEPLOY-SERVER-DB.md points here; at least docs/INPUT-SURFACES.md and
    docs/DANGEROUS-FUNCTIONALITY.md still name some of its refusals, with "at least", and this text
    governs where they differ. A
    certificate is a self-signed root when the chain .NET's chain engine (X509Chain) builds for it
    is that certificate alone and its signature verifies under its own key. The Windows chain
    engine needs an authority key identifier to link a self-issued certificate to its signer;
    without one it reads the certificate as self-signed with a signature that fails, so the file
    is refused. A file is refused unless the chain engine, given every certificate in the file as
    extra certificates, builds a chain from each certificate in it to a self-signed root in the
    same file, with no chain status other than an untrusted root or a time status. Only the
    file's own self-signed roots anchor that chain (CustomRootTrust), so a root this machine
    already trusts cannot stand in for them, and the engine fetches no missing issuer from a URL a
    certificate names (DisableCertificateDownloads). Every self-signed root in the file must also
    be within its validity period. The validity of any other CA, expired or not yet valid, is
    only warned of, and revocation is not checked. With -Confirm the operator may still decline
    the root and accept another CA.

    PostgreSQL can alternatively pin a CA by file via [store].ssl_root_cert (no machine import
    needed). This machine-store import is the path SQL Server REQUIRES; Postgres can use either.

    The file is read once. Every certificate it holds is shown, checked, and only then added, so
    nothing reaches a store that the operator was not shown. The whole file is refused, and
    nothing is imported, when any certificate in it is not marked as a CA by its basic
    constraints, has a key usage that cannot sign certificates, carries a private key, or fails
    the chain and root checks in "What this script checks", when a DER value in it (the whole file, a
    PEM block, or decoded base64) does not end where its bytes end, or when a control character
    other than tab, CR or LF sits outside its PEM blocks. Other text outside PEM blocks, bare
    base64 among them, is ignored, not refused. At least a .pfx, and a well-formed PEM block
    with any label but CERTIFICATE, X509 CERTIFICATE or PKCS7 (such as a PRIVATE KEY block),
    are refused before anything is parsed. Key material outside well-formed PEM armour is not
    looked for; no private key is ever loaded either way.

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
    # Equivalent one-liner without this script, only for a file holding ONE self-signed root CA
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

# Checked first, before any store or chain is touched. The chain check needs CustomRootTrust and
# DisableCertificateDownloads, which .NET 5 and later have and Windows PowerShell 5.1's .NET
# Framework does not, so this file keeps to syntax 5.1 parses and stops here.
$chainPolicy = [System.Security.Cryptography.X509Certificates.X509ChainPolicy]::new()
if (-not ($chainPolicy.PSObject.Properties['TrustMode'] -and
        $chainPolicy.PSObject.Properties['DisableCertificateDownloads'])) {
    throw ("This script needs PowerShell 7.1 or later. Run it from pwsh, not Windows PowerShell " +
        "(powershell.exe); nothing was imported.")
}

# The machine stores -- NOT the per-user ones. The engine runs as a service principal
# (LocalSystem / gMSA / dedicated account), which only reads the machine stores, so a CurrentUser
# import would be invisible to it. Which CA goes into which store, and what each store is a trust
# anchor for, is stated once, in docs/DEPLOY-SERVER-DB.md section 5.2. Each store is built unopened
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
        throw ("Importing into the machine certificate stores ($StoreLocation and " +
            "$($stores['CertificateAuthority'].Label)) requires an elevated (Administrator) PowerShell.")
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

# The header of the DER element at $Offset: its tag, where its content starts, its content length,
# and where the element ends. $null when it is not a definite-length element that fits in $Bytes.
# Only a single-byte tag is handled; this script reads it for where a SEQUENCE ends.
function Read-DerHeader {
    param([Parameter(Mandatory = $true)][AllowEmptyCollection()][byte[]]$Bytes, [int]$Offset = 0)
    if ($Offset -lt 0 -or $Offset + 2 -gt $Bytes.Length) { return $null }
    $first = [int]$Bytes[$Offset + 1]
    $start = $Offset + 2
    $length = [long]$first
    if ($first -ge 0x80) {
        $n = $first - 0x80
        # 0x80 is BER's indefinite length, whose end cannot be found without parsing the content.
        if ($n -lt 1 -or $n -gt 4 -or $start + $n -gt $Bytes.Length) { return $null }
        $length = [long]0
        for ($k = 0; $k -lt $n; $k++) { $length = $length * 256 + $Bytes[$start + $k] }
        $start += $n
    }
    $end = $start + $length
    if ($end -gt $Bytes.Length) { return $null }
    return @{ Tag = [int]$Bytes[$Offset]; Start = $start; Length = [int]$length; End = [int]$end }
}

# Every certificate the file holds, parsed from bytes the caller read once, so the collection
# returned is the one shown, checked and added. A certificate or a PKCS#7 bundle (.p7b), signed or
# not, is accepted as DER, as bare base64 of DER, or as PEM text whose blocks are all CERTIFICATE
# (or its legacy spelling X509 CERTIFICATE) or PKCS7, in ASCII, UTF-8 or UTF-16 with a byte-order
# mark. A DER value that does not end where its bytes end, or a control character other than tab,
# CR or LF outside PEM blocks, refuses the file; other text outside the blocks is ignored. The PEM
# is parsed here because ImportFromPem would skip a private-key block silently. At least a PKCS#12 (.pfx) and a well-formed PEM block with another
# label, such as PRIVATE KEY, are refused before any of it is parsed, so no private key is loaded:
# a key has no place in a trust-store import, and such a file is usually a server certificate
# handed over by mistake. A certificate the file holds twice is kept once.
function Read-CaBundle {
    param([Parameter(Mandatory = $true)][AllowEmptyCollection()][byte[]]$Bytes)
    $bundle = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2Collection
    if ($Bytes.Length -eq 0) { throw "The file is empty." }
    # The byte-order mark is left out of the text, so bare base64 behind one is still read.
    $encoding = [System.Text.Encoding]::ASCII
    $skip = 0
    if ($Bytes.Length -ge 2 -and $Bytes[0] -eq 0xFF -and $Bytes[1] -eq 0xFE) {
        $encoding = [System.Text.Encoding]::Unicode
        $skip = 2
    } elseif ($Bytes.Length -ge 2 -and $Bytes[0] -eq 0xFE -and $Bytes[1] -eq 0xFF) {
        $encoding = [System.Text.Encoding]::BigEndianUnicode
        $skip = 2
    } elseif ($Bytes.Length -ge 3 -and $Bytes[0] -eq 0xEF -and $Bytes[1] -eq 0xBB -and $Bytes[2] -eq 0xBF) {
        $skip = 3
    }
    $text = $encoding.GetString($Bytes, $skip, $Bytes.Length - $skip)
    # Every piece of DER, the whole file or one PEM block, must be a certificate or a PKCS#7 chain,
    # so a .pfx is refused wherever it sits, before it is parsed.
    $importDer = {
        param([byte[]]$Der)
        # A certificate, a PKCS#7 and a PKCS#12 are each one ASN.1 SEQUENCE, which opens with 0x30.
        $type = 'Unknown'
        if ($Der.Length -gt 0 -and $Der[0] -eq 0x30) {
            $header = Read-DerHeader -Bytes $Der
            if (-not $header -or $header.End -ne $Der.Length) {
                throw ("The file holds DER that does not end where its bytes end: trailing bytes, " +
                    "several values run together, or an indefinite length. That DER is not read " +
                    "in part; split it into PEM blocks or one .p7b.")
            }
            try {
                $type = [System.Security.Cryptography.X509Certificates.X509Certificate2]::GetCertContentType($Der)
            } catch [System.Management.Automation.MethodInvocationException] {
                # .NET on Windows throws for content it cannot classify rather than answering Unknown.
            }
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
    $top = if ($Bytes[0] -eq 0x30) { Read-DerHeader -Bytes $Bytes } else { $null }
    if ($top -and $top.End -eq $Bytes.Length) {
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
        $blockPattern = '-----BEGIN (CERTIFICATE|X509 CERTIFICATE|PKCS7)-----([A-Za-z0-9+/=\s]*)-----END \1-----'
        $blocks = [regex]::Matches($text, $blockPattern)
        if ($blocks.Count -ne $labels.Count) {
            throw "The file has a PEM block that is not well formed."
        }
        # Text outside the blocks, such as OpenSSL's 'subject=' lines, is ignored, and so is bare
        # base64 there. A control character other than tab, CR or LF outside the blocks, such as
        # DER in front of the PEM carries, refuses the file. Bytes above 0x7F are not checked.
        if ([regex]::Replace($text, $blockPattern, '') -match '[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]') {
            throw ("The file holds a control character outside its PEM blocks, as DER run " +
                "together with PEM does. Give each certificate its own PEM block.")
        }
        foreach ($block in $blocks) {
            # Either label may hold a PKCS#7 chain: AD CS web enrollment and certutil -encode
            # write a base64 .p7b under a CERTIFICATE header.
            & $importDer ([Convert]::FromBase64String(($block.Groups[2].Value -replace '\s', '')))
        }
    } elseif ($Bytes[0] -eq 0x30) {
        # DER that does not span the file: $importDer refuses it with the reason.
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

# One chain, built by .NET's X509Chain (the Windows chain engine on Windows) with every certificate
# in the file in ChainPolicy.ExtraStore, so the engine, not this script, matches each issuer to its
# signer and verifies each signature, in every signature algorithm it supports. Revocation is not
# checked: the file is being imported to become trusted. With -Anchors, only those certificates
# anchor the chain (CustomRootTrust); without, the machine's own trust stores do. Returns the
# statuses the engine set, OR-ed together, and the chain's thumbprints from the certificate up, or
# the engine's error when it could not build one.
function Invoke-CaChainBuild {
    param(
        [Parameter(Mandatory = $true)][System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,
        [Parameter(Mandatory = $true)][System.Security.Cryptography.X509Certificates.X509Certificate2Collection]$Bundle,
        [System.Security.Cryptography.X509Certificates.X509Certificate2Collection]$Anchors
    )
    $chain = [System.Security.Cryptography.X509Certificates.X509Chain]::new($true)
    try {
        $policy = $chain.ChainPolicy
        $policy.RevocationMode = [System.Security.Cryptography.X509Certificates.X509RevocationMode]::NoCheck
        [void]$policy.ExtraStore.AddRange($Bundle)
        $policy.DisableCertificateDownloads = $true
        if ($Anchors) {
            $policy.TrustMode = [System.Security.Cryptography.X509Certificates.X509ChainTrustMode]::CustomRootTrust
            [void]$policy.CustomTrustStore.AddRange($Anchors)
        }
        # Build's own verdict is not used: without -Anchors the file's roots are not trusted yet,
        # which it reports as UntrustedRoot. Each status the engine set is read instead.
        try {
            [void]$chain.Build($Certificate)
        } catch [System.Management.Automation.MethodInvocationException] {
            return @{ Error = $_.Exception.InnerException.Message }
        }
        $flags = 0
        foreach ($status in $chain.ChainStatus) { $flags = $flags -bor [int]$status.Status }
        $path = @(foreach ($element in $chain.ChainElements) { $element.Certificate.Thumbprint })
        if ($path.Count -eq 0) { return @{ Error = 'the chain engine built no chain' } }
        return @{ Flags = $flags; Path = $path }
    } finally {
        $chain.Dispose()
    }
}

# What the chain engine makes of each certificate in the file, keyed by thumbprint: the store it
# belongs in, why it must not be trusted ($null when it may be), and whether it is outside its
# validity period at $Now, a UTC time. A certificate is a root when the chain built for it is that
# certificate alone and its signature verifies under its own key; it goes into Root, and any other
# CA into CertificateAuthority (the intermediate store). docs/DEPLOY-SERVER-DB.md section 5.2 says
# what each store means. Every other certificate must chain to one of the file's roots, and only the
# file's roots anchor that chain, so a root the machine already trusts cannot take the place of the
# file's own, as an older root of the same name would. A file with no root gets no anchored build:
# an empty CustomTrustStore is never passed, and each certificate's chain, which then ends at no
# root of the file, is refused.
function Get-CaChainCheck {
    param(
        [Parameter(Mandatory = $true)][System.Security.Cryptography.X509Certificates.X509Certificate2Collection]$Bundle,
        [Parameter(Mandatory = $true)][datetime]$Now
    )
    $flagsType = [System.Security.Cryptography.X509Certificates.X509ChainStatusFlags]
    $unlinked = [int]$flagsType::PartialChain -bor [int]$flagsType::NotSignatureValid
    # UntrustedRoot is expected before the import. Validity is judged here for a root, and only
    # warned of for any other CA, so the engine's time statuses are set aside.
    $ignored = [int]$flagsType::UntrustedRoot -bor [int]$flagsType::NotTimeValid -bor
        [int]$flagsType::NotTimeNested
    # Membership is by thumbprint: a collection's Contains matches on issuer and serial number
    # alone, which two different certificates can share.
    $first = @{}
    $roots = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2Collection
    $rootThumbprints = @{}
    foreach ($cert in $Bundle) {
        $built = Invoke-CaChainBuild -Certificate $cert -Bundle $Bundle
        $first[$cert.Thumbprint] = $built
        if (-not $built.Error -and $built.Path.Count -eq 1 -and -not ($built.Flags -band $unlinked)) {
            [void]$roots.Add($cert)
            $rootThumbprints[$cert.Thumbprint] = $true
        }
    }
    $checks = @{}
    foreach ($cert in $Bundle) {
        $isRoot = $rootThumbprints.ContainsKey($cert.Thumbprint)
        $built = $first[$cert.Thumbprint]
        if ($roots.Count -gt 0 -and -not $isRoot) {
            $built = Invoke-CaChainBuild -Certificate $cert -Bundle $Bundle -Anchors $roots
        }
        $outside = $cert.NotAfter.ToUniversalTime() -lt $Now -or $cert.NotBefore.ToUniversalTime() -gt $Now
        $refusal = $null
        if ($built.Error) {
            $refusal = "the chain engine could not build its chain: $($built.Error)"
        } elseif ($built.Flags -band [int]$flagsType::PartialChain) {
            $refusal = 'it does not chain to a self-signed root in this file'
        } elseif (-not $rootThumbprints.ContainsKey($built.Path[-1])) {
            $refusal = "its chain ends at $($built.Path[-1]), which is not a self-signed root in this file"
        } elseif ($built.Flags -band -bnot $ignored) {
            $refusal = "the chain engine reports $([System.Enum]::ToObject($flagsType, $built.Flags -band -bnot $ignored)) on its chain"
        } elseif ($isRoot -and $outside) {
            $refusal = 'it is a self-signed root outside its validity period'
        }
        $checks[$cert.Thumbprint] = @{
            Store = $(if ($isRoot) { 'Root' } else { 'CertificateAuthority' })
            Refusal = $refusal
            Outside = $outside
        }
    }
    return $checks
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
$checks = Get-CaChainCheck -Bundle $bundle -Now ([datetime]::UtcNow)
$refusals = [System.Collections.Generic.List[object]]::new()
# The store each certificate is shown with is the one it is offered for and written to when the
# file passes; a file with any refusal offers nothing, and its refused certificates show none.
$entries = @(foreach ($cert in $bundle) {
    $check = $checks[$cert.Thumbprint]
    $target = $stores[$check.Store]
    $why = Get-CaRefusal -Certificate $cert
    if (-not $why) { $why = $check.Refusal }
    Write-Host ""
    Write-Host "  Subject    : $(ConvertTo-PrintableText $cert.Subject)"
    Write-Host "  Issuer     : $(ConvertTo-PrintableText $cert.Issuer)"
    Write-Host "  Thumbprint : $($cert.Thumbprint)"
    # 'u' writes a 'Z' suffix whatever the DateTime's kind, so the time must be UTC.
    Write-Host "  Not after  : $($cert.NotAfter.ToUniversalTime().ToString('u'))"
    # A refused certificate is offered for no store, so none is named for it.
    Write-Host "  Store      : $(if ($why) { 'none (refused)' } else { $target.Label })"
    if ($check.Outside) {
        Write-Warning "$($cert.Thumbprint) is outside its validity period; a chain through it will not validate."
    }
    if ($why) { $refusals.Add([pscustomobject]@{ Thumbprint = $cert.Thumbprint; Why = $why }) }
    @{ Certificate = $cert; Target = $target }
})
if ($refusals.Count -gt 0) {
    # Printed one per line for the operator. pwsh 7's default error view rewraps a message at the
    # console width, which can split a thumbprint from its reason. The error repeats each pair in
    # the same "thumbprint: reason" form, joined by '; ', for a caller that catches it or keeps
    # only the error stream; the error view may still rewrap it.
    Write-Host ""
    Write-Host "Refused:"
    foreach ($refusal in $refusals) { Write-Host "  $($refusal.Thumbprint): $($refusal.Why)" }
    throw ("Nothing was imported. Every certificate in the file must be a CA that may sign " +
        "certificates, carries no private key, and chains to a self-signed root in the file " +
        "that is within its validity period. Refused: " +
        (($refusals | ForEach-Object { "$($_.Thumbprint): $($_.Why)" }) -join '; ') + ".")
}
if (-not ($entries | Where-Object { $_.Target -eq $stores['Root'] })) {
    # Defensive: not expected to fire.
    throw ("Nothing was imported. The file holds no self-signed root. Give this script the root " +
        "the CA chains to, alone or in the same .p7b chain.")
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
        Write-Warning ("No root was imported. Over SChannel and ODBC a DB server cert validates only if " +
            "its root is already in $StoreLocation; the engine's Python TLS treats LocalMachine\CA " +
            "differently (see docs/DEPLOY-SERVER-DB.md section 5.2, 'Where each CA goes').")
    }
    Write-Host ""
    Write-Host "Rotation: when the CA is replaced, import the NEW CA first (this leaves both trusted),"
    Write-Host "roll the server cert, then remove the OLD CA -- see docs/DEPLOY-SERVER-DB.md."
}
