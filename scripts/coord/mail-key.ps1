# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
<#
.SYNOPSIS
    The worktree -> mailbox key function AND the message-id shape. ONE definition of each,
    dot-sourced by everything that needs them.

.DESCRIPTION
    Dot-source this; it defines functions and does nothing on its own.

        . "$PSScriptRoot\mail-key.ps1"
        $key = ConvertTo-BoxKey -Path (Resolve-BoxPath -Path $cwd)
        $old = Get-BoxReadKeys -Path $cwd   # READERS ONLY; see that function

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
    another's mail. The hash is computed over the host and the NORMALISED path and is what carries
    injectivity. The slug exists only so a human can tell boxes apart in a directory listing.

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
    # THE KEY HASHES THE HOST AS WELL AS THE PATH (docs/COORD-SHARED-ROOT.md, migration step 4). On a
    # shared root two PCs can each hold a worktree at the same path, and a path-only key gave them one
    # seat id, one mailbox and one lane file. The hash input is '<HOST>|<normalised path>', with the
    # host upper-cased because Windows machine names are case-insensitive. The slug is unchanged, so
    # a directory listing still reads the same.
    #
    # -HostName exists for a reader that must name ANOTHER PC's box, and for tests. A writer passes
    # nothing and gets this machine.
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path, [string]$HostName)
    if (-not $HostName -or -not $HostName.Trim()) { $HostName = Get-BoxKeyHost }
    $norm = ConvertTo-BoxKeyPath -Path $Path
    return (Format-BoxKey -Norm $norm -HashInput ($HostName.Trim().ToUpperInvariant() + '|' + $norm))
}

function ConvertTo-LegacyBoxKey {
    # THE PATH-ONLY KEY, FOR READING ONLY. Every seat record, mailbox, lane file, handoff directory and
    # writer-alive heartbeat written before the host joined the key sits under this name. A reader
    # looks here too so nothing already written goes unread; NO WRITER MAY CALL THIS. A new record
    # under the legacy key is the collision step 4 removed. This is the one definition of the old key.
    #
    # THE LEGACY BOX IS SHARED BY EVERY PC AT THIS PATH, so a record read from it is judged by its
    # `host` field (Test-CoordRecordIsHere) before it is taken as this machine's.
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)
    $norm = ConvertTo-BoxKeyPath -Path $Path
    return (Format-BoxKey -Norm $norm -HashInput $norm)
}

function Resolve-BoxPath {
    # THE DIRECTORY A BOX IS KEYED ON, FOR ANY PATH INSIDE A WORKTREE (BACKLOG #7581). The sender,
    # the drain, the watcher and seat.ps1 each pass a path through this before ConvertTo-BoxKey, so a
    # session whose cwd is a SUBDIRECTORY of its worktree reads the box its seat record publishes,
    # the worktree root, and mail sent to a subdirectory path lands there too. Before this, the drain
    # keyed on the session's cwd and seat.ps1 on `git rev-parse --show-toplevel`, so one worktree
    # could name two boxes, each one the other end never read.
    #
    # Returns the worktree root when $Path is a folder inside a live worktree that git does not
    # ignore. Returns $Path UNCHANGED, so its key is exactly what it was before this function, when:
    #   - $Path is the worktree root itself (the common case, answered with no git call);
    #   - $Path is not rooted, or sits in no checkout: no root is guessed;
    #   - the nearest `.git` above $Path names no git directory, as a pruned worktree's stale `.git`
    #     file does: the walk never passes it to reach a checkout further up;
    #   - git IGNORES $Path in the checkout found above it. A removed worktree's leftover directory
    #     under the primary's .claude/worktrees/ is such a folder, and raising it would send its mail
    #     to the PRIMARY checkout's box. An ignored folder of a live worktree keeps its own box for
    #     the same reason, as it did before this function;
    #   - git cannot answer the ignore question. A failed probe is not "not ignored".
    #
    # Calls git only for a path strictly below a worktree root. Never throws.
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)
    try {
        $raw = $Path.Trim()
        if (-not $raw -or -not [System.IO.Path]::IsPathRooted($raw)) { return $Path }
        # GetFullPath collapses `..` and slash direction, so the walk below climbs real parents.
        $full = [System.IO.Path]::GetFullPath($raw).TrimEnd('\', '/')
        if (-not $full) { return $Path }
        $at = $full
        $root = $null
        while ($at) {
            $dotGit = Join-Path $at '.git'
            if (Test-Path -LiteralPath $dotGit) {
                if (-not (Test-BoxGitDir -DotGit $dotGit -Root $at)) { return $Path }
                $root = $at
                break
            }
            $parent = Split-Path -Parent $at
            if (-not $parent -or $parent -eq $at) { break }
            $at = $parent.TrimEnd('\', '/')
        }
        if (-not $root -or $full.Length -eq $root.Length) { return $Path }
        # Relative to the root, in forward slashes, with a trailing slash so a directory-only pattern
        # such as `/.claude/worktrees/` matches it.
        $rel = ($full.Substring($root.Length).TrimStart('\', '/') -replace '\\', '/') + '/'
        $null = & git -C $root check-ignore -q -- $rel 2>$null
        # 1 is "not ignored". 0 is ignored, and anything else is git failing to answer.
        if ($LASTEXITCODE -eq 1) { return $root }
        return $Path
    }
    catch { return $Path }
}

function Test-BoxGitDir {
    # Whether the `.git` at $DotGit names a git directory, read the way git reads it and calling no
    # git: a directory, or a file whose `gitdir:` line names one, that holds HEAD.
    param([Parameter(Mandatory)][string]$DotGit, [Parameter(Mandatory)][string]$Root)
    try {
        if (Test-Path -LiteralPath $DotGit -PathType Container) { $gitDir = $DotGit }
        else {
            $line = [string](Get-Content -LiteralPath $DotGit -TotalCount 1 -ErrorAction Stop)
            if ($line -notmatch '^gitdir:\s*(.+?)\s*$') { return $false }
            $gitDir = $Matches[1]
            if (-not [System.IO.Path]::IsPathRooted($gitDir)) { $gitDir = Join-Path $Root $gitDir }
        }
        return (Test-Path -LiteralPath (Join-Path $gitDir 'HEAD') -PathType Leaf)
    }
    catch { return $false }
}

function Get-BoxReadKeys {
    # EVERY OLDER KEY A READER OF $Path'S BOX STILL DRAINS, so no message already queued goes unread
    # when Resolve-BoxPath moves a box. Returns the keys to move mail FROM, never the current one. A
    # reader (the drain, the watcher) passes each to Move-LegacyInbox; NO WRITER MAY ADDRESS ONE.
    #   - the legacy path-only key of the resolved directory (the host joining the key, step 4);
    #   - when $Path is a subdirectory raised to its root: the key it was addressed by before
    #     Resolve-BoxPath, ConvertTo-BoxKey of $Path itself, and that path's legacy key.
    # -Resolved takes the caller's own Resolve-BoxPath answer for $Path, to spare a second git call.
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path, [string]$Resolved)
    $resolved = if ($Resolved) { $Resolved } else { Resolve-BoxPath -Path $Path }
    $keys = @(ConvertTo-LegacyBoxKey -Path $resolved)
    if ((ConvertTo-BoxKeyPath -Path $resolved) -cne (ConvertTo-BoxKeyPath -Path $Path)) {
        $keys += ConvertTo-BoxKey -Path $Path
        $keys += ConvertTo-LegacyBoxKey -Path $Path
    }
    return , $keys
}

# Set at load so a StrictMode caller can read it before the first load below.
$script:BoxKeyHostLoaded = $null

function Get-BoxKeyHost {
    # coord-root.ps1's Get-CoordHost, the one host rule. A caller that dot-sourced this file alone
    # gets it loaded from beside this file, and THROWS when it is missing rather than hashing a host
    # from a second copy of the rule that could drift from the one the other end uses.
    if (Get-Command Get-CoordHost -ErrorAction SilentlyContinue) { return [string](Get-CoordHost) }
    # Loaded here, the definitions leave scope on return, so the answer is kept for the next call.
    if ($script:BoxKeyHostLoaded) { return $script:BoxKeyHostLoaded }
    $lib = Join-Path $PSScriptRoot 'coord-root.ps1'
    if (-not (Test-Path -LiteralPath $lib -PathType Leaf)) {
        throw "mail-key.ps1: $lib is missing, so this machine's host cannot be named for a box key"
    }
    . $lib
    $script:BoxKeyHostLoaded = [string](Get-CoordHost)
    return $script:BoxKeyHostLoaded
}

function ConvertTo-BoxKeyPath {
    param([Parameter(Mandatory)][string]$Path)
    return ($Path.Trim().TrimEnd('\', '/').ToLowerInvariant() -replace '/', '\')
}

function Format-BoxKey {
    param([Parameter(Mandatory)][string]$Norm, [Parameter(Mandatory)][string]$HashInput)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { $bytes = $sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($HashInput)) }
    finally { $sha.Dispose() }
    $short = -join ($bytes[0..3] | ForEach-Object { $_.ToString('x2') })

    $slug = (Split-Path $Norm -Leaf) -replace '[^a-zA-Z0-9._-]', '-'
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
    #
    # COMPOSED FROM Get-MailStemPattern BELOW RATHER THAN CARRYING ITS OWN COPY OF THE SHAPE. The
    # anchors are this function's whole contribution: the shape itself has one definition, so the
    # validator and the search pattern cannot drift apart at all rather than being held together by a
    # test. That is this file's own rule, applied to the shape it owns.
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Stem)
    return ($Stem -cmatch ('\A' + (Get-MailStemPattern) + '\z'))
}

function Get-MailStemPattern {
    # THE STEM SHAPE, ONCE. Unanchored, because it has two jobs: Test-MailStem above anchors it to
    # decide whether a whole string is a stem, and the drain's receipt sweep matches it unanchored to
    # FIND a stem quoted inside a document.
    #
    # IT SITS HERE RATHER THAN IN THE DRAIN for the reason this whole file exists: a second copy of a
    # shared shape drifts, and the copy that drifts is the one nobody is testing.
    #
    # -cmatch above is case-SENSITIVE and .NET's Regex default is too, so a caller that builds its own
    # [regex] from this pattern gets the same verdict as the validator. Do not pass IgnoreCase.
    return '[0-9]{8}T[0-9]{9}-[0-9a-z]{6}'
}

function Split-ReceiptFileName {
    # THE RECEIPT NAME SHAPE, <stem>.json. Returns $null for anything this channel did not mint, and a
    # $null return is the caller's signal to LEAVE THE FILE ALONE -- the same contract as
    # Split-MailFileName and Split-ShownMarkerName in mail-claim.ps1.
    #
    # IT IS HERE AND NOT THERE BECAUSE A RECEIPT NAME HAS NO CLAIM TOKEN IN IT. Those two exist in
    # mail-claim.ps1 because they JOIN the stem shape to the token shape, and this file's header
    # forbids a second definition of that join. A receipt is a bare stem, so there is no join to
    # define and the shape belongs beside the stem validator that decides it.
    #
    # A CALLER MUST NOT REACH FOR Split-MailFileName HERE. That one requires the --<token> half a
    # receipt name does not carry, so it rejects every receipt in the directory -- and a sweep guarded
    # by it deletes nothing while reporting, truthfully, that it ran. Silent in both directions.
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Name)
    if (-not $Name.EndsWith('.json', [StringComparison]::Ordinal)) { return $null }
    $stem = $Name.Substring(0, $Name.Length - 5)
    if (-not (Test-MailStem -Stem $stem)) { return $null }
    return [pscustomobject]@{ Stem = $stem }
}
