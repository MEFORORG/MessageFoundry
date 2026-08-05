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
    open of that path with FileShare::None. See Move-Claimed for the retry and for why ceding is the
    safe failure direction.

    A THROW IS A REPORT, NOT A VERDICT. The move can throw and still have happened, and it can return
    silently and not have happened, so `Won` is never inferred from whether an exception was raised.

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
    # AND EXISTS($dst) ALONE IS NOT ENOUGH EITHER -- this is the correction that cost the most to find.
    # File.Exists returns a TRANSIENT FALSE POSITIVE for a destination that was never created, and it
    # does so only ACROSS PROCESSES: a 16-thread, 500-round measurement inside ONE process saw exactly
    # one winner every round and concluded the verdict was sound. Re-measured 2026-08-05 with 16
    # separate pwsh processes over 800 rounds, the same verdict reported a win to MORE THAN ONE racer
    # in 46 of 800 rounds (5.75%), on 49 destinations that did not exist in the final listing. A
    # re-probe 3ms later cleared only 38 of those 49, so waiting is not a fix. In the drain a false win
    # is a DOUBLE DELIVERY: two claimers render the same body and write the same receipt path.
    #
    # An EXCLUSIVE OPEN is the question that cannot be answered by stale metadata -- the file is either
    # really there to be opened or it is not. In the same run it refused all 49 phantoms and gave
    # exactly one opener in 800 of 800 rounds.
    #
    # WHY THE RETRY, AND WHY CEDING IS THE SAFE FAILURE. The open is very slightly over-strict: in 3 of
    # 800 rounds the TRUE winner's own open failed transiently and nobody claimed the message. That
    # direction is the acceptable one -- an unclaimed message stays in claiming/ under this token, is
    # never delivered twice, and is reported by mail.ps1 -Status and by the dead-owner sweep once this
    # process exits. A few short retries recover most of it; if they do not, we cede rather than
    # deliver on an unproven claim.
    $won = $false
    if ([System.IO.File]::Exists($dst)) {
        foreach ($attempt in 1..4) {
            try {
                $fs = [System.IO.File]::Open($dst, [System.IO.FileMode]::Open,
                    [System.IO.FileAccess]::Read, [System.IO.FileShare]::None)
                $fs.Dispose()
                $won = $true
                break
            }
            catch { Start-Sleep -Milliseconds (2 * $attempt) }
        }
    }

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
