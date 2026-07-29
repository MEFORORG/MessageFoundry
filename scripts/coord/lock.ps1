<#
.SYNOPSIS
    A short-lived, cross-session mutex for operations that are NOT safe to run concurrently.

.DESCRIPTION
    Dot-source this and wrap the critical section:

        . "$PSScriptRoot\..\coord\lock.ps1"
        $lock = Enter-CoordLock -Name "worktree-add"
        try { ...the operation... } finally { Exit-CoordLock $lock }

    Same atomic test-and-set as claim.ps1 and alloc.ps1: it claims by EXCLUSIVELY CREATING a file in
    <git-common-dir>/mefor-coord/locks/, and the failed create IS the mutual exclusion. A
    read-modify-write on a shared list is not an option here -- PowerShell was measured silently
    losing 4 of 8 concurrent writes.

    DIFFERENT FROM claim.ps1, deliberately. A claim is a long-lived note about WORK ("I am building
    #105"), held for a session, advisory, and released by hand. This is a short-lived mutex around a
    single OPERATION measured in seconds. That difference is why this one retries and claims do not.

    WE RETRY; WE NEVER STEAL. Breaking a lock we cannot prove is abandoned re-opens the exact race
    the lock exists to close, and on this host there is no reliable liveness signal to prove it with:
    the session registry has no heartbeat, and its shipped pid+procStart guard fails OPEN toward
    "still alive". So on timeout this FAILS LOUDLY with the holder's identity and the manual override,
    rather than quietly deciding the holder is dead. A wedged lock you can see beats a silent
    double-write you cannot.

    Do not use this for anything held longer than seconds. git's own posture works because a
    .lock is held for microseconds around one write, so a crash rarely lands inside it; the longer
    the hold, the more likely a crash leaves a lock nobody can safely break.
#>

# Returns the lock's path, to be passed back to Exit-CoordLock.
function Enter-CoordLock {
    [CmdletBinding()]
    param(
        # Lock identity. One name = one mutex; unrelated operations should use different names.
        [Parameter(Mandatory)][string]$Name,
        # How long to wait for a sibling to finish before giving up. Sized for the operation.
        [int]$TimeoutSeconds = 90,
        # Repo to anchor the lock directory to. Defaults to the current repo's shared git dir, so
        # every worktree AND the primary checkout resolve to the same lock.
        [string]$Repo
    )
    $gitArgs = @()
    if ($Repo) { $gitArgs = @("-C", $Repo) }
    $common = (& git @gitArgs rev-parse --path-format=absolute --git-common-dir 2>$null)
    if ($LASTEXITCODE -ne 0 -or -not $common) { throw "Enter-CoordLock: not inside a git repository." }

    $dir = Join-Path $common.Trim() "mefor-coord/locks"
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
    $safe = ($Name.Trim().ToLowerInvariant() -replace '[^a-z0-9._-]+', '-').Trim('-')
    if (-not $safe) { throw "Enter-CoordLock: name '$Name' reduces to nothing usable." }
    $lock = Join-Path $dir "$safe.lock"

    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while ($true) {
        try {
            $fs = [System.IO.File]::Open(
                $lock,
                [System.IO.FileMode]::CreateNew,
                [System.IO.FileAccess]::Write,
                [System.IO.FileShare]::None)
            try {
                # Recorded so a wedged lock names its holder instead of being an anonymous mystery.
                $who = [System.Text.Encoding]::UTF8.GetBytes(
                    "pid=$PID host=$env:COMPUTERNAME at=$((Get-Date).ToString('o'))")
                $fs.Write($who, 0, $who.Length)
            } finally { $fs.Dispose() }
            return $lock
        } catch [System.IO.IOException] {
            if ((Get-Date) -gt $deadline) {
                $held = "(unreadable)"
                try { $held = (Get-Content -LiteralPath $lock -Raw -EA Stop).Trim() } catch { }
                throw (
                    "Timed out after ${TimeoutSeconds}s waiting for the '$safe' lock.`n" +
                    "  held by: $held`n" +
                    "  NOT stealing it -- there is no reliable way to prove that session is gone, and`n" +
                    "  breaking the lock re-opens the race it exists to prevent.`n" +
                    "  If you are certain that session is dead, delete it by hand:`n" +
                    "      Remove-Item -LiteralPath '$lock'")
            }
            Start-Sleep -Milliseconds 200
        }
    }
}

function Exit-CoordLock {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$LockPath)
    # Best-effort: a failure to release must never mask the real error from the critical section,
    # which is usually why we are unwinding in the first place.
    Remove-Item -LiteralPath $LockPath -Force -ErrorAction SilentlyContinue
}
