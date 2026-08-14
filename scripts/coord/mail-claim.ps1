# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
<#
.SYNOPSIS
    The mail claim primitive. ONE definition of "move a message and know whether you got it",
    dot-sourced by both the sender and the drain.

.DESCRIPTION
    Dot-source this; it defines functions and does nothing on its own.

        . "$PSScriptRoot\mail-claim.ps1"
        $r = Move-Claimed -Source $src -DestinationDir $dir -Stem $stem -Token (New-ClaimToken)
        if ($r.Won) { ... }

    WHY THIS EXISTS AT ALL, AND WHY TWO OBVIOUS VERSIONS ARE BOTH WRONG.
    [System.IO.File]::Move RETURNS SUCCESS WITHOUT MOVING for losers under concurrent contention, so a
    non-throwing move is not a claim. THE NUMBERS, BOTH ARMS, BOTH CONTROLS, AND WHY
    scripts/coord/claim.ps1 IS NOT AFFECTED ARE IN
    docs/adr/0161-async-session-mail-for-unreachable-peers.md. Cite that; do not restate them here --
    this measurement was restated in six places once already and correcting it meant editing all six.

    THE PRIMITIVE, THEREFORE. Every move destination in this system is a name NO OTHER CLAIMER COULD
    MINT: <stem>--<token>.json. Uniqueness is what carries the exclusion.

    TWO CHECKS ARE INSUFFICIENT AND BOTH LOOK RIGOROUS. Neither is in the code below, and putting
    either back would make a reviewer believe the claim is stronger than it is:

      1. `Exists(dst) -and -not Exists(src)` -- true for the winner AND every loser, because the
         WINNER'S move makes it true for everybody. It cannot tell them apart at all.
      2. `Exists(my own destination)` ALONE -- this one is subtler and it survived a full review.
         File.Exists returns a TRANSIENT FALSE POSITIVE for a destination that was never created, and
         it does so ONLY ACROSS PROCESSES. Sixteen threads inside ONE process, 500 rounds, reported
         exactly one winner every round and looked conclusive; sixteen separate pwsh PROCESSES over
         800 rounds -- the configuration the drain actually runs in -- reported a win to MORE THAN ONE
         racer in 46 of 800 rounds. A re-probe a few milliseconds later cleared only some of them, so
         waiting is not the fix either.

    THE VERDICT IS AN EXCLUSIVE OPEN, which stale metadata cannot answer: Exists, and then a real
    open of that path with FileShare::None. See Test-FilePresent for the retry and Move-Claimed for why
    ceding is the safe failure direction.

    THAT VERDICT IS ALSO THE ONLY ACCEPTABLE "DOES THIS FILE REALLY EXIST" PROBE IN THIS CHANNEL.
    Test-FilePresent is the verdict with the move removed, and the drain asks it about shown-markers
    too. File.Exists is not an acceptable answer there for the same measured reason it is
    not one here: a false "yes, this was already shown" would suppress a display while the turn-boundary
    drain consumed the message, which is a silent loss. Test-FilePresent's failure direction is "could
    not prove it exists" -> show it again -> a duplicate, never a loss.

    A THROW IS A REPORT, NOT A VERDICT. The move can throw and still have happened, and it can return
    silently and not have happened, so `Won` is never inferred from whether an exception was raised.

    THE SESSION-ID SHAPES ARE HERE, AND mail-key.ps1 IS WHERE THEY BELONG. Test-SessionId,
    ConvertTo-SessionKey and Split-ShownMarkerName validate a hook-payload session id BEFORE the drain
    builds a shown-marker path out of it -- exactly the duty mail-key.ps1 states for the message stem,
    and exactly the lowercasing rationale it already records for the box key. They sit here rather than
    there for a scoping reason that has nothing to do with the design. Relocating them next to
    Test-MailStem is a mechanical change, and it must be a MOVE, never a copy: two definitions of a
    shape a path is built from is the drift this whole file exists to prevent.

    ASCII-only, pwsh 7. Nothing here throws to its caller: a hook consumer must be able to fail open.
#>

# Test-MailStem lives with the New-MessageId that mints it. Split-MailFileName below is the only place
# the stem shape and the token shape are joined, so it needs both -- and dot-sourcing here means a
# caller that took the claim primitive cannot accidentally have taken only half the contract.
. "$PSScriptRoot\mail-key.ps1"

function Get-ClaimHostToken {
    # Four hex of SHA-256 over the lowercased machine name. It SCOPES LIVENESS -- a PID from another
    # machine must never be read against this machine's process table -- while putting nothing readable
    # about the machine into a filename.
    #
    # Four hex can collide across machines. The worst outcome of a collision is a LIVE claim swept to
    # stranded/, which is visible in -Status and is never a double delivery, because the sweep only
    # ever moves claiming/ -> stranded/ and NEVER back to inbox/. Do not "improve" the sweep into a
    # re-queue; that is what would turn this collision into a delivered-twice bug.
    $n = ([string]$env:COMPUTERNAME).ToLowerInvariant()
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { $b = $sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($n)) }
    finally { $sha.Dispose() }
    return (-join ($b[0..1] | ForEach-Object { $_.ToString('x2') }))
}

function New-ClaimToken {
    # <host4>-<pidHex>-<startTicksHex>-<tidHex>-<rand8>
    #
    # THE TOKEN CARRIES TWO SEPARABLE DUTIES AND NEEDS BOTH HALVES. Each component below buys a
    # specific property; a future edit that drops one as redundant loses that property silently.
    #
    #   host4 + pidHex + startTicksHex  -- the OS process identity. This is the ONLY liveness-checkable
    #       part, and it is why a purely random token is insufficient: randomness cannot answer "is the
    #       owner of this claim still alive". The start time is not decoration either -- PIDs recycle,
    #       and a recycled PID would make a dead owner look live.
    #   tidHex  -- separates runspaces inside one pwsh process, which share both PID and start time.
    #   rand8   -- minted per ATTEMPT, which is what makes a RETRY a distinct claimer. Identity alone
    #       is insufficient for exactly that reason: two attempts by one process would otherwise
    #       contend on the same destination name.
    #
    # RandomNumberGenerator, NEVER Get-Random. Get-Random is seeded per runspace and two runspaces
    # created in the same tick have been observed to produce identical sequences; mail-key.ps1's
    # New-MessageId uses it because a message id only has to not collide with the same millisecond,
    # which is a much weaker requirement than "no concurrent claimer can mint my name".
    #
    # Never cached in a script-scope variable: a cached token would silently make every attempt by this
    # process the same claimer.
    $host4 = Get-ClaimHostToken
    $pidHex = $PID.ToString('x')
    $startHex = '0'
    try {
        $t = [System.Diagnostics.Process]::GetCurrentProcess().StartTime.ToUniversalTime().Ticks
        if ($t -gt 0) { $startHex = $t.ToString('x') }
    }
    catch {
        # An unreadable start time is not fatal: the token is still unique. It only costs liveness,
        # and Get-ClaimTokenOwnerState reports 'unknown' for a '0' rather than guessing.
        $startHex = '0'
    }
    $tidHex = [System.Threading.Thread]::CurrentThread.ManagedThreadId.ToString('x')
    $rand8 = -join ([System.Security.Cryptography.RandomNumberGenerator]::GetBytes(4) | ForEach-Object { $_.ToString('x2') })
    return "$host4-$pidHex-$startHex-$tidHex-$rand8"
}

function Test-ClaimToken {
    # The token half of a mail filename. Fixed lowercase hex groups joined by SINGLE hyphens, which is
    # what makes '--' an unambiguous separator between the stem and the token: neither half can
    # contain one.
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Token)
    return ($Token -cmatch '\A[0-9a-f]{4}-[0-9a-f]{1,8}-[0-9a-f]{1,16}-[0-9a-f]{1,8}-[0-9a-f]{8}\z')
}

function Get-ClaimTokenOwnerState {
    # 'live' | 'dead' | 'unknown', on the same "report only what you can PROVE" contract that
    # claim.ps1's Get-HolderLiveness states. Only 'dead' licenses a sweep; 'unknown' must never be
    # treated as permission to move someone else's claim.
    #
    # THERE IS DELIBERATELY NO AGE-BASED EXPIRY. Age measures how long the work has run, not whether
    # anyone is still doing it -- the exact error claim.ps1 records having fixed, where a 21h claim was
    # labelled STALE while its holder had committed two minutes earlier.
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Token)
    try {
        if (-not (Test-ClaimToken -Token $Token)) { return 'unknown' }
        $p = $Token.Split('-')
        # A foreign machine's PID space. Reading it against this machine's process table would answer
        # a different question than the one asked.
        if ($p[0] -ne (Get-ClaimHostToken)) { return 'unknown' }
        if ($p[2] -eq '0') { return 'unknown' }   # the minter could not read its own start time
        $ownerPid = [Convert]::ToInt64($p[1], 16)
        $proc = Get-Process -Id $ownerPid -ErrorAction SilentlyContinue
        if (-not $proc) { return 'dead' }
        $ticks = $null
        try { $ticks = $proc.StartTime.ToUniversalTime().Ticks } catch { return 'unknown' }
        if ($null -eq $ticks) { return 'unknown' }
        if ($ticks -eq [Convert]::ToInt64($p[2], 16)) { return 'live' }
        # Same PID, different start time: the PID was recycled and the original owner is gone.
        return 'dead'
    }
    catch {
        # Say 'unknown' rather than 'dead'. A failed probe that reported death would turn an
        # unreadable process record into a licence to sweep a live session's claim.
        return 'unknown'
    }
}

function Test-FilePresent {
    # PROVEN PRESENCE, NOT REPORTED PRESENCE. This is the claim verdict with the move removed, extracted
    # so the drain's shown-marker probe asks the same question the claim asks rather than a weaker one
    # that looks identical in a code review.
    #
    # WHY EXISTS IS NOT THE ANSWER -- and this is the correction that cost the most to find.
    # File.Exists returns a TRANSIENT FALSE POSITIVE for a path that was never created, and it does so
    # only ACROSS PROCESSES: a 16-thread, 500-round measurement inside ONE process saw exactly one
    # winner every round and concluded the verdict was sound. Re-measured 2026-08-05 with 16 separate
    # pwsh processes over 800 rounds -- the configuration the drain actually runs in -- the same verdict
    # reported a win to MORE THAN ONE racer in 46 of 800 rounds (5.75%), on 49 destinations that did not
    # exist in the final listing. A re-probe 3ms later cleared only 38 of those 49, so waiting is not a
    # fix. An EXCLUSIVE OPEN is the question stale metadata cannot answer -- the file is either really
    # there to be opened or it is not. In the same run it refused all 49 phantoms and gave exactly one
    # opener in 800 of 800 rounds.
    #
    # WHY THE RETRY, AND WHICH DIRECTION THE FAILURE POINTS. The open is very slightly over-strict: in 3
    # of 800 rounds a true winner's own open failed transiently. A few short retries recover most of
    # that; when they do not, this returns FALSE, and false is the safe answer at every call site. For a
    # claim it means cede rather than deliver on an unproven claim. For the drain's marker probe it
    # means "could not prove it exists" -> show the message again -> a duplicate display,
    # which is accepted, rather than a suppressed display over a message that is then consumed, which
    # would be a silent loss.
    #
    # THE EXISTS GATE KEEPS THE CHEAP PATH CHEAP. The retry loop is entered only when Exists is already
    # true, so a path that is not there costs one metadata call and no sleeps. The drain runs on every
    # turn boundary in every worktree; a change that put those sleeps on the negative path would put
    # them on the hot path.
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)
    if (-not [System.IO.File]::Exists($Path)) { return $false }
    foreach ($attempt in 1..4) {
        try {
            $fs = [System.IO.File]::Open($Path, [System.IO.FileMode]::Open,
                [System.IO.FileAccess]::Read, [System.IO.FileShare]::None)
            $fs.Dispose()
            return $true
        }
        catch { Start-Sleep -Milliseconds (2 * $attempt) }
    }
    return $false
}

function Test-SessionId {
    # The session id shape, validated BEFORE any path is built from it. A hook payload is input from
    # outside this script, and a shown-marker filename is built out of it, so this is the same duty
    # Test-MailStem carries for the message stem -- and skipping it would be the same traversal defect
    # the drain already fixed once.
    #
    # \A and \z, NOT ^ and $: in .NET '$' also matches immediately before a trailing newline, so '^...$'
    # would accept an id with one appended. Same reason mail-key.ps1 states.
    #
    # -cmatch with BOTH cases spelled into the class, so the regex states its own case policy rather
    # than inheriting -match's case- and culture-sensitive default. TOLERANT IN, CANONICAL OUT: an
    # uppercase id from some future client is accepted here and lowercased by ConvertTo-SessionKey,
    # because rejecting it would degrade that surface to "unmarkable" for no benefit.
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyString()][string]$SessionId)
    return ($SessionId -cmatch '\A[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\z')
}

function ConvertTo-SessionKey {
    # The canonical spelling of a session id, or $null if it is not one. $null is the caller's signal
    # that the session is UNMARKABLE -- never a licence to build a path from the raw value.
    #
    # LOWERCASED FOR THE REASON ConvertTo-BoxKey RECORDS: VS Code records a lowercase drive letter where
    # the Desktop app records an uppercase one, and the same normalisation argument applies to any id
    # that reaches this channel spelled two ways. ONE MINTED SPELLING, so a marker's name is predictable
    # from an id however the client happened to case it.
    #
    # The rationale this replaced -- "two spellings would mint two markers" -- cannot hold on the
    # platform this runs on: NTFS resolves both spellings to ONE file, so a second spelling collides
    # with the first rather than duplicating it. That mattered, because Split-ShownMarkerName was
    # written to the false version and rejected a case variant as foreign while the filesystem handed
    # the drain the same file. See its header.
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyString()][string]$SessionId)
    if (-not (Test-SessionId -SessionId $SessionId)) { return $null }
    return $SessionId.ToLowerInvariant()
}

function Split-ShownMarkerName {
    # The shown-marker name, <stem>--<sessionKey>.marker. Returns $null for anything this channel did
    # not mint, and a $null return is the caller's signal to LEAVE THE FILE ALONE -- never to build a
    # path out of it. Same contract as Split-MailFileName, and the same reason.
    #
    # Splitting on the FIRST '--' is unambiguous because neither half can contain one: a stem is
    # <yyyyMMddTHHmmssfff>-<6 base36> with single hyphens only, and a UUID has single hyphens only.
    #
    # The extension is checked here rather than by the caller because Get-ChildItem -Filter '*.marker'
    # is a Windows wildcard, not a suffix test.
    #
    # THE SESSION HALF IS MATCHED CASE-INSENSITIVELY, AND IT USED TO BE MATCHED WITH -cne. That was a
    # SPLIT BRAIN, not a strictness choice: this function decided ownership case-SENSITIVELY while every
    # consumer of the answer -- CreateNew, Test-FilePresent, Remove-Item -- reaches the file through a
    # filesystem that resolves the two spellings to ONE file. Measured: writing <stem>--<UPPER>.marker
    # then opening <stem>--<lower>.marker CreateNew fails with IOException and File.Exists on the
    # lowercase spelling returns true. So the drain reported the file as "a name this channel did not
    # mint, left alone", exempted it from both sweeps, and then used it as this session's marker --
    # suppressing a display on the strength of a file it had just told the reader it was ignoring.
    #
    # Accepting the variant is the side that makes the report true: it IS the file this channel would
    # mint for that id, by path identity on this platform. It is returned CANONICALISED so no caller can
    # build a second spelling back out of the answer.
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Name)
    if (-not $Name.EndsWith('.marker', [StringComparison]::Ordinal)) { return $null }
    $base = $Name.Substring(0, $Name.Length - 7)
    $i = $base.IndexOf('--', [StringComparison]::Ordinal)
    if ($i -lt 1) { return $null }
    $stem = $base.Substring(0, $i)
    $sk = $base.Substring($i + 2)
    if (-not (Test-MailStem -Stem $stem)) { return $null }
    $canon = ConvertTo-SessionKey -SessionId $sk
    if ($null -eq $canon) { return $null }
    return [pscustomobject]@{ Stem = $stem; SessionKey = $canon }
}

function Move-Claimed {
    # THE call site for every move in the mail system. Do not open-code [System.IO.File]::Move
    # anywhere else under scripts/coord or scripts/hooks; the reason is the whole header of this file.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Source,
        [Parameter(Mandatory)][string]$DestinationDir,
        [Parameter(Mandatory)][string]$Stem,
        [Parameter(Mandatory)][string]$Token
    )
    $dst = Join-Path $DestinationDir "$Stem--$Token.json"
    $threw = $false
    $err = ''
    # THE CATCH IS UNTYPED ON PURPOSE. claim.ps1:265 records that PowerShell wraps an exception thrown
    # by a .NET METHOD in a MethodInvocationException, so `catch [System.IO.IOException]` around this
    # call never matches and the failure escapes to $ErrorActionPreference.
    try { [System.IO.File]::Move($Source, $dst) }
    catch { $threw = $true; $err = $_.ToString() }

    # THE VERDICT. Evaluated even when the move threw, because a throw is not proof of loss any more
    # than a silent return is proof of a win.
    #
    # It must NOT consult Exists($Source): that post-condition was measured true for winners and
    # losers alike and cannot discriminate. See this file's header.
    #
    # AND EXISTS($dst) ALONE IS NOT ENOUGH EITHER. The verdict -- Exists, then an EXCLUSIVE OPEN, with a
    # short retry -- is Test-FilePresent above, where the measurement that forced it is recorded. It is
    # a function rather than an inline block because the drain now asks the identical question about
    # shown-markers and receipts, and one definition is what stops the second call site drifting back to
    # a bare Exists. In the drain a false win here is a DOUBLE DELIVERY: two claimers render the same
    # body and write the same receipt path. Ceding is the safe failure direction; a false win is not.
    $won = Test-FilePresent -Path $dst

    return [pscustomobject]@{ Won = $won; Path = $dst; Token = $Token; Threw = $threw; Error = $err }
}

function Split-MailFileName {
    # THE ONE PLACE the stem shape (mail-key.ps1) and the token shape (above) are joined. Returns
    # $null for anything that is not a name this channel minted, and a $null return is the caller's
    # signal to leave the file alone -- never to build a path out of it.
    #
    # Splitting on the FIRST '--' is unambiguous because neither half can contain one: a stem is
    # <yyyyMMddTHHmmssfff>-<6 base36> with single hyphens only, and a token is hex groups joined by
    # single hyphens.
    #
    # The extension is checked here rather than by the caller because Get-ChildItem -Filter '*.json'
    # is a Windows wildcard, not a suffix test, and can surface names the caller did not expect.
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyString()][string]$Name)
    if (-not $Name.EndsWith('.json', [StringComparison]::Ordinal)) { return $null }
    $base = $Name.Substring(0, $Name.Length - 5)
    $i = $base.IndexOf('--', [StringComparison]::Ordinal)
    if ($i -lt 1) { return $null }
    $stem = $base.Substring(0, $i)
    $tok = $base.Substring($i + 2)
    if (-not (Test-MailStem -Stem $stem)) { return $null }
    if (-not (Test-ClaimToken -Token $tok)) { return $null }
    return [pscustomobject]@{ Stem = $stem; Token = $tok }
}

function New-ClaimAttempt {
    # Move-Claimed with a FRESH token per attempt.
    #
    # RETRYING WITH THE SAME TOKEN IS FORBIDDEN and that is not a style point: an attempt can succeed
    # SILENTLY, so a same-token retry could collide with a name its own earlier attempt already
    # created, and the second Exists() would then report a win that belongs to the first attempt --
    # or, worse, to nobody.
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Source,
        [Parameter(Mandatory)][string]$DestinationDir,
        [Parameter(Mandatory)][string]$Stem,
        [int]$MaxAttempts = 3
    )
    $last = $null
    foreach ($i in 1..$MaxAttempts) {
        $last = Move-Claimed -Source $Source -DestinationDir $DestinationDir -Stem $Stem -Token (New-ClaimToken)
        if ($last.Won) { return $last }
        # STOP CONDITION, NOT A CLAIM CHECK. The source being gone means there is nothing left to
        # retry against -- somebody else has it. It is never used to decide `Won`; that decision is
        # made in Move-Claimed by an exclusive OPEN of this attempt's own destination, and nowhere else.
        $srcThere = $true
        try { $srcThere = [System.IO.File]::Exists($Source) } catch { $srcThere = $false }
        if (-not $srcThere) { return $last }
        Start-Sleep -Milliseconds (10 * $i)
    }
    return $last
}
