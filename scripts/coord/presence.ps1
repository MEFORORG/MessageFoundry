<#
.SYNOPSIS
    Who is ACTUALLY live in this repo right now -- across every Claude Code surface, including VS Code.

.DESCRIPTION
    `claim.ps1` answers "what is being built"; this answers "who is here". They are different failures:
    a claim tells you work is taken, presence tells you whether the session that took it still exists.

    WHY THIS EXISTS RATHER THAN THE OBVIOUS ALTERNATIVES
    ----------------------------------------------------
    The Claude Desktop app's session tooling (its `list_sessions` MCP tool) enumerates an in-memory map
    of sessions THE DESKTOP APP ITSELF SPAWNED. A session launched by the VS Code extension is never
    entered into it -- not filtered out, never registered -- so it is invisible to that tool and cannot
    be addressed by it. Verified 2026-07-29: a live VS Code session sharing the DEFAULT config root was
    absent from `list_sessions` while its sibling desktop sessions were listed. It is not a login split.

    `<config-root>/sessions/<pid>.json` is the only registry that contains every surface. This script
    reads that, so a VS Code session in the primary checkout shows up next to desktop sessions in
    worktrees. Config roots are discovered dynamically (~\.claude plus any ~\.claude-account-N), because
    several logins can be in play on one machine and a session is only visible to the login that owns it.

    LIVENESS IS A FENCE, NOT A PID CHECK
    ------------------------------------
    A bare `is pid alive` check is wrong: PIDs are reused, and these files outlive their process (a
    session that dies uncleanly leaves its file behind -- measured, 2 of 3 IDE lock files on this host
    named dead processes, the oldest by 6.5 days). Claude Code's own registry carries a `procStart` field
    for exactly this fence, but on this host it serialises as absent, so the shipped guard passes
    unconditionally. We therefore compute process start time OURSELVES and require it to be consistent
    with the recorded session start. A reused PID hosts a process that started AFTER the session
    registered, and that is what STALE means below.

    A session is reported LIVE only when its pid resolves AND that process's start time is consistent.
    Anything else is STALE (pid reused or file orphaned) or DEAD (no such pid).

    READ-ONLY. This script never writes, never deletes a registry file, and never contacts another
    session. It is a roster, not a channel.

.EXAMPLE
    pwsh -NoProfile -File scripts\coord\presence.ps1
    pwsh -NoProfile -File scripts\coord\presence.ps1 -All        # include stale/dead entries
    pwsh -NoProfile -File scripts\coord\presence.ps1 -Json       # machine-readable
#>
[CmdletBinding()]
param(
    # Config roots to scan. Defaults to every ~\.claude* directory (Desktop + each CLI/VS Code login).
    # Tests point this at a fixture directory, so the real discovery logic is what gets exercised.
    [string[]]$ConfigRoot,
    # Show STALE and DEAD entries too. Default lists only sessions that are actually live.
    [switch]$All,
    # Emit JSON instead of a table.
    [switch]$Json,
    # Repo to scope to. Defaults to the current worktree's repo family (all worktrees sharing one .git).
    [string]$Repo,
    # Treat this pid as "me" so the roster can mark the calling session. Defaults to auto-detection by
    # ancestry (see Get-SelfPids) -- 0 means "work it out", which is what every real invocation wants.
    [int]$SelfPid = 0,
    # How far a process may have started BEFORE its session registered and still be the same run.
    # Generous: registration follows process start, but a cold start on a loaded box can lag.
    [int]$StartSkewMinutes = 15
)

$ErrorActionPreference = "Stop"

# --- Which worktrees count as "this repo" -------------------------------------------------------
# A session is in-scope when its cwd is inside ANY worktree sharing this .git. Keyed on the worktree
# set rather than a single path, because the whole point is seeing siblings, not just yourself.
function Get-RepoWorktrees([string]$RepoHint) {
    $gitArgs = @()
    if ($RepoHint) { $gitArgs = @("-C", $RepoHint) }
    $porcelain = & git @gitArgs worktree list --porcelain 2>$null
    if ($LASTEXITCODE -ne 0 -or -not $porcelain) { return @() }
    $out = @()
    $cur = $null
    foreach ($line in $porcelain) {
        if ($line -like "worktree *") {
            $cur = [pscustomobject]@{ Path = $line.Substring(9).Trim(); Branch = "" }
            $out += $cur
        }
        elseif ($line -like "branch *" -and $cur) {
            $cur.Branch = ($line.Substring(7).Trim() -replace '^refs/heads/', '')
        }
        elseif ($line -like "detached*" -and $cur) {
            $cur.Branch = "(detached)"
        }
    }
    return $out
}

function ConvertTo-Norm([string]$p) {
    if (-not $p) { return "" }
    return ($p -replace '\\', '/').TrimEnd('/').ToLowerInvariant()
}

# --- Config roots -------------------------------------------------------------------------------
# Discovered, not hardcoded: several logins can coexist (~\.claude for Desktop, ~\.claude-account-N for
# CLI/VS Code subscriptions) and a session is only ever visible to the login that owns it.
function Get-ConfigRoots {
    if ($ConfigRoot) { return @($ConfigRoot | Where-Object { Test-Path $_ }) }
    return @(
        Get-ChildItem -Path $env:USERPROFILE -Directory -Filter ".claude*" -Force -EA SilentlyContinue |
            Where-Object { Test-Path (Join-Path $_.FullName "sessions") } |
            ForEach-Object { $_.FullName }
    )
}

function Get-LoginLabel([string]$RootPath) {
    $leaf = Split-Path $RootPath -Leaf
    if ($leaf -ieq ".claude") { return "default" }
    return ($leaf -replace '^\.claude-account-', 'acct-') -replace '^\.claude-?', ''
}

# The surface a session was launched from. This is the field that makes VS Code sessions visible at all,
# so it is reported verbatim when it is something we do not recognise rather than folded into "other".
function Get-SurfaceLabel([string]$Entrypoint) {
    switch -Regex ($Entrypoint) {
        '^claude-desktop$' { return "desktop" }
        '^claude-vscode$' { return "vscode" }
        '^$' { return "?" }
        default { return $Entrypoint -replace '^claude-', '' }
    }
}

# --- The fence ----------------------------------------------------------------------------------
# LIVE requires the pid to resolve AND the process start time to be consistent with the recorded
# session start. Without the second half this is just a pid check, and a reused pid reads as alive.
function Get-Liveness([int]$ProcId, [object]$StartedAtMs, [int]$SkewMinutes) {
    if (-not $ProcId) { return @{ State = "DEAD"; Detail = "no pid in record" } }
    $proc = Get-Process -Id $ProcId -EA SilentlyContinue
    if (-not $proc) { return @{ State = "DEAD"; Detail = "pid $ProcId not running" } }

    $procStart = $null
    try { $procStart = $proc.StartTime } catch { }
    if (-not $procStart) {
        # Access can be denied for a process owned by another context. Report the uncertainty rather
        # than upgrading it to LIVE -- an unverifiable fence is not a passed fence.
        return @{ State = "UNVERIFIED"; Detail = "pid $ProcId alive; start time unreadable" }
    }
    if ($null -eq $StartedAtMs) {
        return @{ State = "UNVERIFIED"; Detail = "pid $ProcId alive; record has no startedAt" }
    }

    $registered = [DateTimeOffset]::FromUnixTimeMilliseconds([int64]$StartedAtMs).LocalDateTime
    # A process cannot have started after the session it hosts registered (allow a small forward slop
    # for clock jitter). Started much later => this pid was recycled onto a different process.
    $delta = ($procStart - $registered).TotalMinutes
    if ($delta -gt 1) {
        return @{ State = "STALE"; Detail = "pid $ProcId reused (process started $([int]$delta)m after the session)" }
    }
    if ($delta -lt (-1 * $SkewMinutes)) {
        return @{ State = "STALE"; Detail = "pid $ProcId start precedes the session by $([int](-$delta))m" }
    }
    return @{ State = "LIVE"; Detail = "" }
}

# --- Which of these sessions is the caller ------------------------------------------------------
# NOT $PID: this script runs as a pwsh child (often a grandchild, via a hook), so its own pid never
# appears in the registry. The session that invoked us is an ANCESTOR, so walk the parent chain and
# treat every pid on it as "self". Getting this wrong is not cosmetic -- a roster that cannot tell you
# from a sibling is one you will act on as though someone else were in your own worktree.
function Get-SelfPids([int]$Override) {
    if ($Override -gt 0) { return @($Override) }
    # ONE CIM query for the whole process table, not one per ancestor: this runs on every SessionStart,
    # and a dozen round-trips is the difference between a hook you notice and one you don't.
    $ppid = @{}
    try {
        Get-CimInstance Win32_Process -Property ProcessId, ParentProcessId -EA Stop |
            ForEach-Object { $ppid[[int]$_.ProcessId] = [int]$_.ParentProcessId }
    } catch { return @($PID) }

    $chain = @()
    $cur = $PID
    # Bounded: a runaway or cyclic parent chain must not hang a SessionStart hook.
    for ($i = 0; $i -lt 12 -and $cur -gt 0; $i++) {
        $chain += $cur
        $parent = $ppid[$cur]
        if (-not $parent -or $parent -le 0 -or $chain -contains $parent) { break }
        $cur = $parent
    }
    return $chain
}

# --- Collect ------------------------------------------------------------------------------------
$worktrees = Get-RepoWorktrees $Repo
if (-not $worktrees -or $worktrees.Count -eq 0) {
    if ($Json) { "[]" | Write-Output } else { Write-Host "Not inside a git repository -- nothing to scope presence to." }
    exit 0
}
$wtIndex = @{}
foreach ($w in $worktrees) { $wtIndex[(ConvertTo-Norm $w.Path)] = $w }
# The primary (trunk) checkout is the first entry git reports; naming it matters because a session
# sitting there is the one most likely to collide with everyone else.
$primaryNorm = ConvertTo-Norm $worktrees[0].Path

$selfPids = Get-SelfPids $SelfPid

$rows = @()
foreach ($root in (Get-ConfigRoots)) {
    $sessDir = Join-Path $root "sessions"
    foreach ($f in @(Get-ChildItem $sessDir -Filter *.json -EA SilentlyContinue)) {
        try { $rec = Get-Content $f.FullName -Raw -EA Stop | ConvertFrom-Json -EA Stop } catch { continue }
        if (-not $rec.cwd) { continue }

        # Scope: cwd inside one of this repo's worktrees. Exact match on the worktree root, or a
        # descendant of it -- a session cd'd into a subdirectory is still that worktree's session.
        $cwdNorm = ConvertTo-Norm $rec.cwd
        $match = $null
        foreach ($k in $wtIndex.Keys) {
            if ($cwdNorm -eq $k -or $cwdNorm.StartsWith("$k/")) {
                if (-not $match -or $k.Length -gt (ConvertTo-Norm $match.Path).Length) { $match = $wtIndex[$k] }
            }
        }
        if (-not $match) { continue }

        $live = Get-Liveness ([int]$rec.pid) $rec.startedAt $StartSkewMinutes
        $matchNorm = ConvertTo-Norm $match.Path
        $rows += [pscustomobject]@{
            State     = $live.State
            Detail    = $live.Detail
            Surface   = Get-SurfaceLabel $rec.entrypoint
            Login     = Get-LoginLabel $root
            SessionId = [string]$rec.sessionId
            Short     = if ($rec.sessionId) { ([string]$rec.sessionId).Substring(0, [Math]::Min(8, ([string]$rec.sessionId).Length)) } else { "?" }
            Pid       = [int]$rec.pid
            Cwd       = [string]$rec.cwd
            Worktree  = if ($matchNorm -eq $primaryNorm) { "primary" } else { Split-Path $match.Path -Leaf }
            IsPrimary = ($matchNorm -eq $primaryNorm)
            Branch    = $match.Branch
            Kind      = [string]$rec.kind
            IsSelf    = ($selfPids -contains [int]$rec.pid)
            StartedAt = if ($null -ne $rec.startedAt) { [DateTimeOffset]::FromUnixTimeMilliseconds([int64]$rec.startedAt).LocalDateTime.ToString("o") } else { "" }
        }
    }
}

$order = @{ "LIVE" = 0; "UNVERIFIED" = 1; "STALE" = 2; "DEAD" = 3 }
$rows = @($rows | Sort-Object @{ E = { $order[$_.State] } }, @{ E = { $_.Worktree } })
if (-not $All) { $rows = @($rows | Where-Object { $_.State -eq "LIVE" -or $_.State -eq "UNVERIFIED" }) }

if ($Json) {
    # -Depth so nested pscustomobjects survive; -AsArray so a single row is still a JSON list and a
    # caller can index it without special-casing.
    ($rows | ConvertTo-Json -Depth 4 -AsArray) | Write-Output
    exit 0
}

if ($rows.Count -eq 0) {
    Write-Host "No live sessions found for this repo." -ForegroundColor DarkGray
    Write-Host "(Add -All to include stale/dead registry entries.)" -ForegroundColor DarkGray
    exit 0
}

Write-Host ""
Write-Host "Live Claude sessions in this repo ($($rows.Count)):"
foreach ($r in $rows) {
    $me = if ($r.IsSelf) { "  <-- THIS session" } else { "" }
    $warn = if ($r.IsPrimary -and -not $r.IsSelf) { "  [in the SHARED PRIMARY]" } else { "" }
    $state = if ($r.State -eq "LIVE") { "" } else { "  [$($r.State): $($r.Detail)]" }
    Write-Host ("  {0,-8} {1,-7} {2,-34} {3}" -f $r.Short, $r.Surface, $r.Worktree, $r.Branch)
    if ($me -or $warn -or $state) { Write-Host ("           {0}{1}{2}" -f $me.TrimStart(), $warn, $state) }
}
Write-Host ""
Write-Host "  See what they are building:  pwsh -NoProfile -File scripts\coord\claim.ps1 -List"
Write-Host ""
exit 0
