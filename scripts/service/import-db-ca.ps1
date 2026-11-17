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

    Where each CA goes. This is the one statement of it; docs/DEPLOY-SERVER-DB.md section 5.2
    repeats it for operators, and every other document points there. A self-signed root, whose
    signature verifies under its own key, goes into LocalMachine\Root. Any other CA in the file,
    such as an issuing CA in a .p7b chain, or a self-issued certificate another key signed, goes
    into the intermediate store LocalMachine\CA. That store is not a trust anchor for SChannel or
    ODBC Driver 18 chain building, so the SQL Server hop still checks the chain up to the root. It
    IS usable as a trust anchor by the engine's Python TLS on Windows: CPython's
    ssl.create_default_context(), which the PostgreSQL system-trust path calls, loads the CA and
    ROOT system stores, and Python 3.13 and later set partial-chain verification, so a chain that
    reaches a certificate in LocalMachine\CA validates there without its root. A file is refused
    unless it holds a self-signed root and every other CA in it chains to a self-signed root
    through the file's own certificates, each link's signature verified. No revocation, name
    constraint or path length is checked, and with -Confirm the operator may still decline the
    root and accept another CA.

    PostgreSQL can alternatively pin a CA by file via [store].ssl_root_cert (no machine import
    needed). This machine-store import is the path SQL Server REQUIRES; Postgres can use either.

    The file is read once. Every certificate it holds is shown, checked, and only then added, so
    nothing reaches a store that the operator was not shown. Roots are added first. The whole
    file is refused, and nothing is imported, when any certificate in it is not marked as a CA by
    its basic constraints, has a key usage that cannot sign certificates, carries a private key,
    or is outside its validity period, when it holds no self-signed root, when a CA in it does not
    chain to a self-signed root in the file, when a DER value in it (the whole file, a PEM block,
    or decoded base64) does not end where its bytes end, or when a control character other than
    tab, CR or LF sits outside its PEM blocks. A BER value with an indefinite length, which some
    tools write for a .p7b, is refused by that DER rule; re-encode it as DER first. Only RSA
    PKCS#1 v1.5 and ECDSA signatures with SHA-1 or SHA-2 are verified, so a root or a chain link
    signed any other way (RSA-PSS, for one) is refused. Other text outside PEM blocks, bare base64
    among them, is ignored, not refused. At least a .pfx, and
    a well-formed PEM block with any label but CERTIFICATE, X509 CERTIFICATE or PKCS7 (such as a
    PRIVATE KEY block), are refused before anything is parsed. Key material outside well-formed
    PEM armour is not looked for; no private key is ever loaded either way.

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

# The machine stores -- NOT the per-user ones. The engine runs as a service principal
# (LocalSystem / gMSA / dedicated account), which only reads the machine stores, so a CurrentUser
# import would be invisible to it. Which CA goes into which store, and what each store is a trust
# anchor for, is stated once, in the help's "Where each CA goes". Each store is built unopened
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
# Only the single-byte tags this script reads (SEQUENCE, INTEGER, BIT STRING) are handled.
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
# is parsed here because
# Windows PowerShell 5.1's .NET Framework has no ImportFromPem, which would in any case skip a
# private-key block silently. At least a PKCS#12 (.pfx) and a well-formed PEM block with another
# label, such as PRIVATE KEY, are refused before any of it is parsed, so no private key is loaded:
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
    } elseif ($Bytes.Length -ge 3 -and $Bytes[0] -eq 0xEF -and $Bytes[1] -eq 0xBB -and $Bytes[2] -eq 0xBF) {
        $encoding = [System.Text.Encoding]::UTF8
    }
    # GetString keeps a byte-order mark as U+FEFF, which bare base64 would otherwise fail to match.
    $text = $encoding.GetString($Bytes).TrimStart([char]0xFEFF)
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

# Whether $Signer issued the certificate: the certificate's issuer is $Signer's subject, byte for
# byte, AND its signature verifies under $Signer's public key. RSA PKCS#1 v1.5 and ECDSA with SHA-1
# or SHA-2 are checked; any other signature algorithm (RSA-PSS, SHA-224, Ed25519 and DSA among them)
# reads as not signed, which fails closed: such a certificate is never a root, and never a link.
function Test-SignedBy {
    param(
        [Parameter(Mandatory = $true)][System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,
        [Parameter(Mandatory = $true)][System.Security.Cryptography.X509Certificates.X509Certificate2]$Signer)
    if ([Convert]::ToBase64String($Signer.SubjectName.RawData) -cne
        [Convert]::ToBase64String($Certificate.IssuerName.RawData)) { return $false }
    $hashes = @{
        '1.2.840.113549.1.1.5' = 'SHA1'; '1.2.840.113549.1.1.11' = 'SHA256'
        '1.2.840.113549.1.1.12' = 'SHA384'; '1.2.840.113549.1.1.13' = 'SHA512'
        '1.2.840.10045.4.1' = 'SHA1'; '1.2.840.10045.4.3.2' = 'SHA256'
        '1.2.840.10045.4.3.3' = 'SHA384'; '1.2.840.10045.4.3.4' = 'SHA512'
    }
    $oid = $Certificate.SignatureAlgorithm.Value
    if (-not $hashes.ContainsKey($oid)) { return $false }
    $hash = [System.Security.Cryptography.HashAlgorithmName]::new($hashes[$oid])
    # Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue BIT STRING }.
    $raw = $Certificate.RawData
    $outer = Read-DerHeader -Bytes $raw
    if (-not $outer) { return $false }
    $tbs = Read-DerHeader -Bytes $raw -Offset $outer.Start
    if (-not $tbs) { return $false }
    $algorithm = Read-DerHeader -Bytes $raw -Offset $tbs.End
    if (-not $algorithm) { return $false }
    $bits = Read-DerHeader -Bytes $raw -Offset $algorithm.End
    if (-not $bits -or $bits.Tag -ne 0x03 -or $bits.Length -lt 2 -or $raw[$bits.Start] -ne 0) { return $false }
    $signed = New-Object byte[] ($tbs.End - $outer.Start)
    [Array]::Copy($raw, $outer.Start, $signed, 0, $signed.Length)
    $signature = New-Object byte[] ($bits.Length - 1)
    [Array]::Copy($raw, $bits.Start + 1, $signature, 0, $signature.Length)
    try {
        if ($oid.StartsWith('1.2.840.113549.')) {
            $rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPublicKey($Signer)
            if (-not $rsa) { return $false }
            return [bool]$rsa.VerifyData($signed, $signature, $hash,
                [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
        }
        $ecdsa = [System.Security.Cryptography.X509Certificates.ECDsaCertificateExtensions]::GetECDsaPublicKey($Signer)
        if (-not $ecdsa) { return $false }
        # X.509 carries an ECDSA signature as a DER SEQUENCE of r and s; .NET Framework's VerifyData
        # reads only r and s side by side, each padded to the key's width.
        $sequence = Read-DerHeader -Bytes $signature
        if (-not $sequence -or $sequence.End -ne $signature.Length) { return $false }
        $r = Read-DerHeader -Bytes $signature -Offset $sequence.Start
        if (-not $r) { return $false }
        $s = Read-DerHeader -Bytes $signature -Offset $r.End
        if (-not $s -or $s.End -ne $signature.Length) { return $false }
        $width = [int][Math]::Ceiling($ecdsa.KeySize / 8)
        $fixed = New-Object byte[] (2 * $width)
        foreach ($part in @(@($r, 0), @($s, $width))) {
            $from = $part[0].Start
            $count = $part[0].Length
            while ($count -gt 0 -and $signature[$from] -eq 0) { $from++; $count-- }
            if ($count -gt $width) { return $false }
            [Array]::Copy($signature, $from, $fixed, $part[1] + $width - $count, $count)
        }
        return [bool]$ecdsa.VerifyData($signed, $fixed, $hash)
    } catch [System.Management.Automation.MethodInvocationException] {
        return $false
    }
}

# Whether the certificate is self-signed: it is its own signer by Test-SignedBy, so its subject and
# issuer are the same name AND its signature verifies under its own public key. A self-issued
# certificate another key signed, such as a CA re-key link certificate, is not.
function Test-SelfSigned {
    param([Parameter(Mandatory = $true)][System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate)
    return (Test-SignedBy -Certificate $Certificate -Signer $Certificate)
}

# Why the certificate does not chain to a self-signed root in the file, or $null when it does. The
# walk follows issuer links through the file only, never a machine store: each step needs a
# certificate in $Bundle whose subject is the issuer's name and whose key verifies the signature
# (Test-SignedBy). Every such issuer is followed, not only the first, so a cross-certificate that
# shares a root's name and key cannot hide the root behind it; each certificate is visited once, so
# a loop of links ends. Nothing else about the chain is checked here; Get-CaRefusal checks each
# certificate on its own, and no revocation or name constraint is read.
function Get-ChainRefusal {
    param(
        [Parameter(Mandatory = $true)][System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][System.Security.Cryptography.X509Certificates.X509Certificate2Collection]$Bundle)
    $visited = @{ $Certificate.Thumbprint = $true }
    $pending = [System.Collections.Generic.Queue[object]]::new()
    $pending.Enqueue($Certificate)
    while ($pending.Count -gt 0) {
        $current = $pending.Dequeue()
        if (Test-SelfSigned -Certificate $current) { return $null }
        foreach ($candidate in $Bundle) {
            if (-not $visited.ContainsKey($candidate.Thumbprint) -and
                (Test-SignedBy -Certificate $current -Signer $candidate)) {
                $visited[$candidate.Thumbprint] = $true
                $pending.Enqueue($candidate)
            }
        }
    }
    return 'it does not chain to a self-signed root in the file'
}

# The store a checked CA belongs in: Root for a self-signed one, CertificateAuthority (the
# intermediate store) for any other. The help's "Where each CA goes" says what each store means.
function Get-CaStoreName {
    param([Parameter(Mandatory = $true)][System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate)
    if (Test-SelfSigned -Certificate $Certificate) { return 'Root' }
    return 'CertificateAuthority'
}

# Why the certificate must not be trusted as a CA, or $null when it may be. A certificate whose basic
# constraints do not mark it as a CA cannot sign another, so it has no business in Root. A missing
# extension counts as not a CA here. RFC 5280 (the Basic Constraints section) requires the extension
# of a version 3 CA certificate; a version 1 root, which cannot carry it, is refused too, by this
# script's choice rather than the RFC's. A key usage extension that leaves out certificate signing
# also counts as not a CA (RFC 5280, the Key Usage section). A certificate outside its validity
# period at $NowUtc is refused as well: nothing that chains through it validates, so importing it
# is only ever a mistake, and an expired root must not stand in for the one a CA chains to.
function Get-CaRefusal {
    param(
        [Parameter(Mandatory = $true)][System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,
        [datetime]$NowUtc = [datetime]::UtcNow)
    # Read-CaBundle already refuses every container that can carry a key; this holds if it ever stops.
    if ($Certificate.HasPrivateKey) { return 'it carries a private key' }
    if ($Certificate.NotAfter.ToUniversalTime() -lt $NowUtc) { return 'it has expired' }
    if ($Certificate.NotBefore.ToUniversalTime() -gt $NowUtc) { return 'it is not valid yet' }
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

$nowUtc = [datetime]::UtcNow
# Each refused certificate as one line: its thumbprint, its Subject escaped for the console, and why.
# The host listing and the terminating error both print these same lines.
$refusals = [System.Collections.Generic.List[string]]::new()
# Each certificate is checked before it is shown, so a refused one is listed with its reason and
# never with a store it would not go to. The store shown is the one it is offered for and written to.
# A certificate that passes on its own must also reach a root through this file's own certificates,
# so a root that signed none of them cannot carry an unrelated issuing CA in beside it.
Write-Host "The file holds $($bundle.Count) certificate(s):"
$entries = @(foreach ($cert in $bundle) {
    $target = $stores[(Get-CaStoreName -Certificate $cert)]
    $why = Get-CaRefusal -Certificate $cert -NowUtc $nowUtc
    if (-not $why) { $why = Get-ChainRefusal -Certificate $cert -Bundle $bundle }
    Write-Host ""
    Write-Host "  Subject    : $(ConvertTo-PrintableText $cert.Subject)"
    Write-Host "  Issuer     : $(ConvertTo-PrintableText $cert.Issuer)"
    Write-Host "  Thumbprint : $($cert.Thumbprint)"
    Write-Host "  Not before : $($cert.NotBefore.ToUniversalTime().ToString('u'))"
    Write-Host "  Not after  : $($cert.NotAfter.ToUniversalTime().ToString('u'))"
    if ($why) {
        Write-Host "  Refused    : $why"
        $refusals.Add("$($cert.Thumbprint) ($(ConvertTo-PrintableText $cert.Subject)): $why")
    } else {
        Write-Host "  Store      : $($target.Label)"
    }
    @{ Certificate = $cert; Target = $target }
})
if (-not ($entries | Where-Object { $_.Target -eq $stores['Root'] })) {
    # Without its root an issuing CA validates nothing over SChannel, and over the engine's Python TLS
    # it would be trusted with no root's revocation or constraints over it (the help's "Where each
    # CA goes"), so a rootless file is refused rather than imported. Checked first, since every CA
    # in such a file is also refused for reaching no root, and this message says why in one line.
    throw ("Nothing was imported. The file holds no self-signed root. Give this script the root " +
        "the CA chains to, alone or in the same .p7b chain.")
}
if ($refusals.Count -gt 0) {
    # Printed one per line for the operator: pwsh 7's default error view rewraps a message at the
    # console width, which can split a line. The error carries the same lines, joined into its one
    # message, for a caller that catches it or keeps only the error stream; past the first few it
    # gives the count instead.
    Write-Host ""
    Write-Host "Refused:"
    foreach ($line in $refusals) { Write-Host "  $line" }
    $shown = 5
    $named = ($refusals | Select-Object -First $shown) -join '; '
    if ($refusals.Count -gt $shown) { $named += "; and $($refusals.Count - $shown) more, listed above" }
    throw ("Nothing was imported. Every certificate in the file must be a CA, within its validity " +
        "period, that may sign certificates, carries no private key, and chains to a self-signed " +
        "root in the file. Refused: $named.")
}

# --- import ------------------------------------------------------------------

$approved = @(foreach ($entry in $entries) {
    $cert = $entry.Certificate
    if ($PSCmdlet.ShouldProcess($entry.Target.Label, "Import CA '$(ConvertTo-PrintableText $cert.Subject)' ($($cert.Thumbprint))")) {
        $entry
    }
})

if ($approved.Count -gt 0) {
    # Each store keys on thumbprint, so re-importing the same CA is a no-op (idempotent). Roots go
    # first, so a failure part way never leaves an approved issuing CA added and an approved root not.
    # Nothing is rolled back; the error says how many were added.
    $added = 0
    try {
        foreach ($name in 'Root', 'CertificateAuthority') {
            $batch = @($approved | Where-Object { $_.Target -eq $stores[$name] })
            if ($batch.Count -eq 0) { continue }
            $store = $stores[$name].Store
            $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
            try {
                foreach ($entry in $batch) {
                    $store.Add($entry.Certificate)
                    $added++
                }
            } finally {
                $store.Close()
            }
        }
    } catch {
        throw ("Added $added of $($approved.Count) certificate(s), roots first, before this " +
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
            "differently (see this script's help, 'Where each CA goes').")
    }
    Write-Host ""
    Write-Host "Rotation: when the CA is replaced, import the NEW CA first (this leaves both trusted),"
    Write-Host "roll the server cert, then remove every certificate the OLD file added, by the"
    Write-Host "thumbprints this script listed for it -- see docs/DEPLOY-SERVER-DB.md."
}
