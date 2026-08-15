# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
<#
.SYNOPSIS
    The worktree -> mailbox key function AND the message-id shape. ONE definition of each,
    dot-sourced by everything that needs them.

.DESCRIPTION
    Dot-source this; it defines functions and does nothing on its own.

        . "$PSScriptRoot\mail-key.ps1"
        $key = ConvertTo-BoxKey -Path $cwd

    ONE COPY ON PURPOSE, for the same reason session-registry.ps1 states for the liveness fence. The
    sender (scripts/coord/mail.ps1) and the drain (scripts/hooks/mail-drain.ps1) must compute the SAME
    key from the same path or mail is written to a box nobody reads -- and that failure is silent on
    both ends: the sender sees a queued message, the recipient sees an empty inbox, and nothing
    anywhere reports a mismatch. Two copies of this function would drift, and the copy that drifts is
    the one nobody is testing.

    NORMALISATION IS NOT COSMETIC. Three measured facts make it load-bearing:
      - VS Code records a LOWERCASE drive letter for the workspace path; the Desktop app records an
        uppercase one. The same physical worktree therefore arrives spelled two ways, and a
        case-sensitive key splits it into two boxes that never see each other's mail.
      - A path may or may not carry a trailing separator depending on who produced it.
      - Forward and back slashes both occur, because some producers are git and some are Windows.

    INJECTIVITY IS THE POINT OF THE HASH. A readable slug alone is not enough: two different worktree
    paths can sanitise to the same slug, and the failure mode is one worktree silently reading
    another's mail. The hash is computed over the NORMALISED path and is what carries injectivity. The
    slug exists only so a human can tell boxes apart in a directory listing.

    THE MESSAGE ID IS ALSO A SHARED CONTRACT, AND IT FAILS THE SAME WAY THE BOX KEY DOES. The drain
    treats the ON-DISK NAME as the message's identity -- the JSON 'id' field inside a message is body
    content and is never read -- so if the minter and the validator ever disagree about the shape, the
    drain delivers NOTHING while the sender keeps reporting messages queued. Silent on both ends,
    exactly the failure this file already exists to prevent. New-MessageId and Test-MailStem therefore
    sit next to each other here, not one in the sender and one in the reader.

    WHAT THIS FILE DOES NOT OWN. An on-disk mail filename is <stem>--<claim token>.json, and the
    CLAIM TOKEN half belongs to mail-claim.ps1. The two halves are joined in exactly one place,
    Split-MailFileName, which lives there with the token regex. Do not add a whole-filename validator
    here: that would be a second definition of the join, and the copy that drifts is the one nobody is
    testing.
#>

function ConvertTo-BoxKey {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    $norm = $Path.Trim().TrimEnd('\', '/').ToLowerInvariant() -replace '/', '\'

    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { $bytes = $sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($norm)) }
    finally { $sha.Dispose() }
    $short = -join ($bytes[0..3] | ForEach-Object { $_.ToString('x2') })

    $slug = (Split-Path $norm -Leaf) -replace '[^a-zA-Z0-9._-]', '-'
    if ($slug.Length -gt 40) { $slug = $slug.Substring(0, 40) }
    if (-not $slug) { $slug = 'root' }

    return "$slug-$short"
}

function New-MessageId {
    # Sortable-by-time, unique, and filename-safe. The time prefix is what makes an `ls` of the inbox
    # readable in arrival order without opening anything, and it is why the drain's Sort-Object Name
    # still yields arrival order after the claim token is appended to the filename.
    #
    # Test-MailStem below is the ONLY validator of what this mints. Change one and you must change the
    # other in the same commit.
    #
    # Get-Random is adequate HERE and is not adequate for a claim token: this value only has to not
    # collide with another message from the same millisecond, whereas a claim token has to be
    # unmintable by a concurrent claimer. See mail-claim.ps1 for why that one uses
    # RandomNumberGenerator instead.
    $t = [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfff')
    $r = -join ((1..6) | ForEach-Object { '0123456789abcdefghijklmnopqrstuvwxyz'[(Get-Random -Maximum 36)] })
    return "$t-$r"
}

function Test-MailStem {
    # THE FILENAME IS THE ONLY TRUSTWORTHY IDENTITY A READER HAS. It is what the OS holds, it cannot
    # contain a path separator, and -- unlike the JSON 'id' field -- nothing inside the message can
    # influence it. The drain derives its id, and the path it writes a receipt to, from the name only.
    #
    # \A and \z, NOT ^ and $: in .NET '$' also matches immediately before a trailing newline. A Windows
    # filename cannot carry one, so this is belt and braces here -- but the shape is meant to be
    # liftable into a test fixture or onto another platform, where it would not be.
    #
    # -cmatch, NOT -match: PowerShell's -match is case-INSENSITIVE by default and New-MessageId emits
    # lowercase only. One minted shape, one accepted shape.
    #
    # This validates the STEM, not the whole filename -- the extension and the claim-token half are
    # checked by Split-MailFileName in mail-claim.ps1, which is the one place the two shapes meet.
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Stem)
    return ($Stem -cmatch '\A[0-9]{8}T[0-9]{9}-[0-9a-z]{6}\z')
}
