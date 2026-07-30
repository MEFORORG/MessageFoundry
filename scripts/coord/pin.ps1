<#
.SYNOPSIS
    Declared occupancy -- a worktree somebody has said, in so many words, they are working in.

.DESCRIPTION
    Dot-source this; it defines functions and does nothing on its own.

        . "$PSScriptRoot\pin.ps1"
        $pins = Get-WorktreePins -Worktrees $worktrees -Repo $RepoRoot
        if (-not $pins.Available) { <refuse to do anything destructive> }

    WHAT IT COVERS THAT NOTHING ELSE DOES. The cwd matcher sees registered sessions; the write
    footprint sees Claude tool calls. Neither sees a HUMAN: an editor session, an autosave, a plain
    terminal, a long-running process that keeps writing after the tool call that started it returned.
    Those leave no registry record and no transcript, ever, so the only way they can be fenced is for
    somebody to say so. That is what a pin is, and it is the whole reason this exists -- it is
    deliberately NOT an automatic lease with a renewal loop, because a lease needs a hook to renew it
    and a hook is exactly the surface this design has none of.

    IT IS ALSO THE ONLY COVER A BRAND-NEW WORKTREE HAS. A worktree created a second ago has zero
    commits, so it is "an ancestor of origin/main" and perfectly clean -- which is the state that got
    a worktree destroyed in the first place -- and it has no transcript history yet either. new.ps1
    takes a short pin at birth for that window.

    EVERY PIN EXPIRES. A pin with no expiry vetoes for ever, which turns the first forgotten one into
    a permanent refusal and the tool into something people work around. `expiresAt` is mandatory and
    an expired pin is reported, not honoured.

    FAIL-CLOSED, with one deliberate exception. A pin file that will not parse is a FAULT and makes
    the source unavailable, which makes the whole fence unavailable: a half-written pin is what
    somebody taking one right now looks like, and its path is unknowable so it clears no candidate.
    An UNEXPIRED pin naming a path that is no longer any worktree of this repo is a fault too -- it
    could be this repo's worktree under a spelling the matcher does not recognise. The exception is
    that an EXPIRED unplaceable pin is simply ignored, so a stale pin for a worktree that was properly
    removed heals itself instead of bricking the fence.

    CONCURRENCY. One file per pin, named for the worktree, the taker's pid and a random suffix, and
    written temp-then-rename. Never a read-modify-write over a shared list: measured on this repo, six
    concurrent writers keyed on a session id alone left ONE surviving write, 5678 nulls and six stray
    temp files -- and subagents share a process, so a pid alone is not a unique key either.
#>

. "$PSScriptRoot\session-registry.ps1"

# Where pins live: the SHARED git directory, so every worktree of the family sees the same set and a
# pin survives the worktree it names being removed (which is how a stale one can still be reported).
function Get-WorktreePinDir {
    [CmdletBinding()]
    param([string]$Repo)
    $gitArgs = @()
    if ($Repo) { $gitArgs = @('-C', $Repo) }
    $common = & git @gitArgs rev-parse --path-format=absolute --git-common-dir 2>$null
    if ($LASTEXITCODE -ne 0 -or -not $common) { return '' }
    return (Join-Path ([string]$common).Trim() 'worktree-pins')
}

<#
Read every pin and place it on a worktree, with a receipt.

Returns a pscustomobject:
    Available        [bool]   the store could be read and every unexpired pin could be placed
    Detail           [string] why it is unavailable, '' when it is available
    Note             [string] why it contributed nothing, when it did
    Dir              [string] the store that was read
    PinsExamined     [int]    files that PARSED
    PinsUnreadable   [int]    files that did not -- any at all => Available false
    PinsExpired      [int]    parsed, and past their expiry
    PinsUnplaceable  [int]    unexpired and naming no worktree of this repo => Available false
    Faults           [array]  {File, Why}
    Pins             [array]  one veto-worthy row per live pin
#>
function Get-WorktreePins {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowEmptyCollection()][object[]]$Worktrees,
        [string]$Repo,
        [string]$PinDir
    )
    $now = Get-Date
    $r = [ordered]@{
        Available = $true; Detail = ''; Note = ''
        Dir = ''; PinsExamined = 0; PinsUnreadable = 0; PinsExpired = 0; PinsUnplaceable = 0
        Faults = @(); Pins = @()
    }
    $faults = @()

    $dir = if ($PinDir) { $PinDir } else { Get-WorktreePinDir -Repo $Repo }
    if (-not $dir) {
        $r.Available = $false
        $r.Detail = 'the pin store could not be located (not inside a git repository?)'
        return [pscustomobject]$r
    }
    $r.Dir = $dir
    if (-not (Test-Path -LiteralPath $dir -PathType Container)) {
        # Nobody has ever taken one. That is a real answer, not a broken store.
        $r.Note = 'no pin has ever been taken in this repo, so this signal contributed nothing to this run'
        return [pscustomobject]$r
    }

    $wtIndex = @{}
    foreach ($w in $Worktrees) { if ($w.Path) { $wtIndex[(ConvertTo-Norm $w.Path)] = $w } }
    $primaryNorm = if ($Worktrees.Count -gt 0) { ConvertTo-Norm $Worktrees[0].Path } else { '' }

    $files = @()
    try { $files = @(Get-ChildItem -LiteralPath $dir -Filter *.json -File -EA Stop) }
    catch {
        # A store that exists and cannot be ENUMERATED is "could not look", never "nobody is here".
        $r.Available = $false
        $r.Detail = "the pin store could not be enumerated ($($_.Exception.GetType().Name))"
        return [pscustomobject]$r
    }

    $rows = @()
    foreach ($f in $files) {
        $rec = $null
        try { $rec = Get-Content -LiteralPath $f.FullName -Raw -EA Stop | ConvertFrom-Json -EA Stop }
        catch { $rec = $null }
        if (-not $rec) {
            $r.PinsUnreadable++
            $faults += [pscustomobject]@{ File = $f.FullName; Why = 'the pin will not parse (half-written, or corrupt); its path is unknowable so it clears no worktree' }
            continue
        }
        $r.PinsExamined++

        $expires = $null
        $rawExp = $rec.expiresAt
        if ($rawExp -is [datetime]) { $expires = ([datetime]$rawExp).ToLocalTime() }
        elseif ($rawExp) {
            try {
                $expires = [DateTimeOffset]::Parse([string]$rawExp, [Globalization.CultureInfo]::InvariantCulture,
                    [Globalization.DateTimeStyles]::RoundtripKind).LocalDateTime
            }
            catch { $expires = $null }
        }
        if ($null -eq $expires) {
            # A pin that cannot be dated cannot be aged out, so it would veto for ever. Refuse rather
            # than either honouring it indefinitely or silently discarding a declared occupancy.
            $faults += [pscustomobject]@{ File = $f.FullName; Why = 'the pin has no readable expiry, so it could never age out' }
            continue
        }
        $expired = ($expires -lt $now)
        if ($expired) { $r.PinsExpired++ }

        $norm = ConvertTo-Norm ([string]$rec.path)
        $match = $null; $bestLen = -1
        foreach ($k in $wtIndex.Keys) {
            if ($norm -eq $k -or $norm.StartsWith("$k/")) {
                if ($k.Length -gt $bestLen) { $match = $wtIndex[$k]; $bestLen = $k.Length }
            }
        }
        if (-not $match) {
            # Expired AND unplaceable is a stale pin for a worktree that is properly gone: ignore it,
            # or the store never heals. Unexpired and unplaceable could be this repo's worktree spelled
            # a way the matcher does not recognise, and that is a missed veto.
            if (-not $expired) {
                $r.PinsUnplaceable++
                $faults += [pscustomobject]@{ File = $f.FullName; Why = "a live pin names '$([string]$rec.path)', which is not a worktree of this repo -- it cannot be placed, so it clears none of them" }
            }
            continue
        }
        if ($expired) { continue }

        $mn = ConvertTo-Norm $match.Path
        $rows += [pscustomobject]@{
            Source       = 'pin'
            # PINNED is its own state on purpose: it is a declaration, not a liveness verdict, and
            # collapsing it into LIVE would let a reader think a process was fenced when a human was.
            State        = 'PINNED'
            Detail       = "pinned until $($expires.ToString('o')): $([string]$rec.reason)"
            SessionId    = [string]$rec.sessionId
            Short        = if ($rec.by) { [string]$rec.by } else { 'pin' }
            Pid          = $(try { [int]$rec.pid } catch { 0 })
            Cwd          = ''
            Entrypoint   = 'pin'
            Kind         = 'declared'
            Root         = $f.FullName
            StartedAt    = [string]$rec.at
            WorktreePath = $match.Path
            Worktree     = if ($mn -eq $primaryNorm) { 'primary' } else { Split-Path $match.Path -Leaf }
            IsPrimary    = ($mn -eq $primaryNorm)
            Branch       = $match.Branch
            Writes       = 0
            LastWriteAt  = ''
            CrossTree    = $false
            PlacedBy     = 'pin'
            Reason       = [string]$rec.reason
            ExpiresAt    = $expires.ToString('o')
        }
    }

    $r.Faults = @($faults | ForEach-Object { "$($_.File) -- $($_.Why)" })
    $r.Pins = @($rows)
    if ($faults.Count -gt 0) {
        $r.Available = $false
        $r.Detail = "$($faults.Count) pin(s) could not be used, so the declared-occupancy set is incomplete: $(($faults | ForEach-Object { "$($_.File) ($($_.Why))" }) -join '; ')"
    }
    elseif ($rows.Count -eq 0) {
        $r.Note = "$($r.PinsExamined) pin(s) examined and none is live on a worktree of this repo, so this signal contributed nothing to this run"
    }
    return [pscustomobject]$r
}

# Take a pin. One file per pin, temp-then-rename, unique per (worktree, pid, random) -- never a
# read-modify-write over a shared list, and never keyed on a session id alone: subagents share a
# process, so neither a session id nor a pid is unique on its own.
function New-WorktreePin {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [Parameter(Mandatory)][string]$Reason,
        [double]$Hours = 12,
        [string]$Repo,
        [string]$PinDir,
        [string]$By
    )
    if ($Hours -le 0) { throw "New-WorktreePin: -Hours must be positive; a pin that never applies is not a pin." }
    $dir = if ($PinDir) { $PinDir } else { Get-WorktreePinDir -Repo $Repo }
    if (-not $dir) { throw "New-WorktreePin: could not locate the pin store (not inside a git repository?)." }
    New-Item -ItemType Directory -Path $dir -Force | Out-Null

    $full = $Path
    if (Test-Path -LiteralPath $Path) { $full = (Resolve-Path -LiteralPath $Path).Path }
    $leaf = ($(Split-Path $full -Leaf) -replace '[^A-Za-z0-9._-]', '_')
    $rand = -join ((1..8) | ForEach-Object { '{0:x}' -f (Get-Random -Minimum 0 -Maximum 16) })
    $name = "$leaf.$PID.$rand.json"
    $rec = [pscustomobject]@{
        path      = $full
        reason    = $Reason
        by        = if ($By) { $By } else { $env:USERNAME }
        pid       = $PID
        sessionId = [string]$env:CLAUDE_SESSION_ID
        at        = (Get-Date).ToString('o')
        expiresAt = (Get-Date).AddHours($Hours).ToString('o')
    }
    $final = Join-Path $dir $name
    $tmp = "$final.tmp"
    try {
        Set-Content -LiteralPath $tmp -Value ($rec | ConvertTo-Json -Depth 4) -Encoding utf8
        # Rename, not write-in-place: a reader must never see a partial pin, and a partial pin is a
        # FAULT that refuses the whole run.
        [System.IO.File]::Move($tmp, $final)
    }
    finally {
        # A stray .tmp is invisible to the reader (it filters *.json) but it is still litter, and the
        # measured failure mode of the naive version was six of them.
        if (Test-Path -LiteralPath $tmp) { Remove-Item -LiteralPath $tmp -Force -EA SilentlyContinue }
    }
    return $final
}

# The rows that must VETO an action against $Path. Same nesting rule as the other sources: removing a
# parent takes a nested checkout with it, so a pin on the nested tree vetoes the ancestor too.
function Get-WorktreePinOccupants {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$PinSet,
        [Parameter(Mandatory)][string]$Path,
        [switch]$IncludeNested
    )
    $norm = ConvertTo-Norm $Path
    return @($PinSet.Pins | Where-Object {
            $wt = ConvertTo-Norm $_.WorktreePath
            $wt -eq $norm -or ($IncludeNested -and $wt.StartsWith("$norm/"))
        })
}
