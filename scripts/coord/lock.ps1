# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
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

# The exclusive create, on its own so a test can substitute a stream whose write or close fails.
function Open-CoordLockFile([string]$Path) {
    return [System.IO.File]::Open(
        $Path,
        [System.IO.FileMode]::CreateNew,
        [System.IO.FileAccess]::Write,
        [System.IO.FileShare]::None)
}

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
    # A caller's SilentlyContinue would otherwise suppress the throws below and run on into the block
    # that owns and deletes the lock file.
    $ErrorActionPreference = 'Stop'
    $gitArgs = @()
    if ($Repo) { $gitArgs = @("-C", $Repo) }
    $common = (& git @gitArgs rev-parse --path-format=absolute --git-common-dir 2>$null)
    if ($LASTEXITCODE -ne 0 -or -not $common) { throw "Enter-CoordLock: not inside a git repository." }

    $dir = Join-Path $common.Trim() "mefor-coord/locks"
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
    $safe = ($Name.Trim().ToLowerInvariant() -replace '[^a-z0-9._-]+', '-').Trim('-')
    if (-not $safe) { throw "Enter-CoordLock: name '$Name' reduces to nothing usable." }
    $lock = Join-Path $dir "$safe.lock"

    # Monotonic, so a clock or daylight-saving step cannot stretch or collapse either bound.
    $clock = [System.Diagnostics.Stopwatch]::StartNew()
    $deniedAt = $null
    while ($true) {
        try {
            $fs = Open-CoordLockFile $lock
        } catch [System.UnauthorizedAccessException] {
            # NTFS raises this, not IOException, for a name in delete-pending (measured on Windows
            # 10.0.26300, NTFS, with the legacy disposition; a plain File.Delete there frees the name at
            # once). A real denial raises it too. Pending shows as a file that is still there, and it
            # clears when the last handle closes, so it earns a short bounded wait. A directory at the
            # path can never clear and fails at once. Either way this reports the denial: the text in
            # a file being deleted names no holder.
            $now = $clock.Elapsed.TotalSeconds
            if ($null -eq $deniedAt) { $deniedAt = $now }
            $canClear = -not (Test-Path -LiteralPath $lock -PathType Container)
            if ($canClear -and $now -le $TimeoutSeconds -and ($now - $deniedAt) -lt 5) {
                Start-Sleep -Milliseconds 50
                continue
            }
            throw (
                "Enter-CoordLock: access denied creating the '$safe' lock at '$lock'.`n" +
                "  The file may still be pending deletion, so retry; if this repeats, check that path`n" +
                "  and its permissions.`n" +
                "  $($_.Exception.Message)")
        } catch [System.IO.IOException] {
            # Only a name that is taken is contention. Disk full, a missing directory or an over-long
            # path would otherwise spin to the timeout and be reported as a wedged holder.
            $io = if ($_.Exception.InnerException) { $_.Exception.InnerException } else { $_.Exception }
            if (($io.HResult -band 0xFFFF) -notin 0x50, 0x20) { throw }  # FILE_EXISTS, SHARING_VIOLATION
            $deniedAt = $null
            if ($clock.Elapsed.TotalSeconds -gt $TimeoutSeconds) {
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
            continue
        } catch {
            # Any other create failure. Without this clause a .NET method failure is only
            # statement-terminating, so execution would fall through to the block below, which owns
            # and deletes the lock file: it would delete a file this call never created.
            throw
        }

        # The create succeeded, so this call owns the file. Outside the catches above on purpose: a
        # failed write caught there would retry against the file this call just made, spin to the
        # timeout, and leave a lock that wedges every later caller.
        $recorded = $false
        try {
            # Recorded so a wedged lock names its holder instead of being an anonymous mystery.
            $who = [System.Text.Encoding]::UTF8.GetBytes(
                "pid=$PID host=$env:COMPUTERNAME at=$((Get-Date).ToString('o'))")
            $fs.Write($who, 0, $who.Length)
            # Inside the guard because FileStream buffers: a full disk can surface only here.
            $fs.Dispose()
            $recorded = $true
        } catch {
            # Not decoration. A .NET method failure is statement-terminating, so under a bare
            # try/finally execution continues past the finally and this would return a lock it had
            # just deleted. Measured: the caller printed ACQUIRED.
            throw
        } finally {
            if (-not $recorded) {
                try { $fs.Dispose() } catch { Write-Verbose "lock stream close failed: $_" }
                try { [System.IO.File]::Delete($lock) }
                catch { Write-Warning "Could not remove the '$safe' lock this call created. Remove it by hand: $lock" }
            }
        }
        return $lock
    }
}

function Exit-CoordLock {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$LockPath)
    # Best-effort: a failure to release must never mask the real error from the critical section,
    # which is usually why we are unwinding in the first place.
    Remove-Item -LiteralPath $LockPath -Force -ErrorAction SilentlyContinue
}
