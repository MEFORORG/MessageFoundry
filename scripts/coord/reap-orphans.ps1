# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
<#
.SYNOPSIS
    Find MSYS tool processes whose parent is dead. REPORT-ONLY unless you pass -Kill.

.DESCRIPTION
    THE FAILURE THIS EXISTS FOR. Killing a bash.exe wrapper does NOT kill its grandchildren.
    Measured 2026-09-20 on a claude -> bash -> bash -> bash -> python -> python chain: killing only
    the innermost bash left both pythons alive, reparented to a dead pid. IsProcessInJob answers
    True for every one of them and the job carries no kill-on-close. So any interrupt strands
    whatever MSYS tool was mid-run, and the orphan's parent is dead -- no pipe ever closes, no
    SIGPIPE ever arrives, and it runs until something stops it.

    WHAT IT COSTS WHEN THE STRANDED TOOL IS WALKING /proc. /proc/registry, /proc/registry32 and
    /proc/registry64 are the Windows registry mounted as filesystem trees by the MSYS2 runtime, so
    a walk opens a kernel handle per registry key and HKEY_CLASSES_ROOT alone is effectively
    unbounded. Measured the same day: 'find /proc/registry' passed 30,000 machine-wide handles in
    15 seconds and was still climbing; machine-wide before cleanup, 4,183,509 handles and 4,620 MB
    of paged pool out of 32.5 GB of RAM, with a 10-second test run taking 26 minutes.
    scripts/hooks/block-unbounded-fs-scan.ps1 is the before-the-fact half; this is the after.

    THE PARENT CHECK IS THE WHOLE TEST. A dead parent means no session is left to consume the
    output, so killing destroys no work product. A LIVE parent means something may still be
    waiting on it, and this script never touches those at any age -- not with -Kill, not with
    -Force.

    A PID IS NOT AN IDENTITY ACROSS TIME. Windows reuses pids, and the scan happens seconds before
    the kill, so -Kill re-reads each pid and compares the image name and the creation time against
    what it scanned. A mismatch skips and says so. Without that fence, an orphan that exited on its
    own between the two moments hands its number to whatever started next.

    KILLING IS OPT-IN AND STAYS OPT-IN. Report-only is the default on purpose, and no hook calls
    this. A guard that kills processes on its own is one bad predicate away from taking out a
    peer's work, and this repo has already paid that once: 'taskkill /IM python.exe' killed three
    interpreters and only one of them belonged to the session that ran it. Everything below kills
    BY PID and never by image name.

    THE CONTROL LINE IS NOT DECORATION. A scan that finds nothing and a scan that looked at
    nothing print the same empty list, so every run prints the total process count, the number of
    MSYS-tool processes alive, and the number of dead-parent processes at ANY age. If the middle
    number is zero on a box with a Git Bash session open, the instrument is broken, not the box.

    AND THE ZERO THIS SHIPPED WITH IS A MEASURED ZERO, not an untested path. First run,
    2026-09-20: no candidates at the default 10-minute floor, over 541 processes, 42 MSYS-tool
    processes alive and 23 dead-parent processes at any age. The same box at -MinAgeMinutes 0
    listed seven real orphans -- one grep.exe, one head.exe, four tail.exe and one sh.exe, all with
    dead parents, aged 0 to 8.1 minutes. So the detector fires, and the default floor is what was
    holding those back rather than an empty predicate.

.EXAMPLE
    pwsh -NoProfile -File scripts\coord\reap-orphans.ps1
    pwsh -NoProfile -File scripts\coord\reap-orphans.ps1 -MinAgeMinutes 30
    pwsh -NoProfile -File scripts\coord\reap-orphans.ps1 -Kill
    pwsh -NoProfile -File scripts\coord\reap-orphans.ps1 -Json
#>
[CmdletBinding()]
param(
    # Image names treated as MSYS tools. Read as "at least these": a name missing here costs a
    # missed orphan, which is visible in the control line, never a wrong kill.
    [string[]]$Image = @(
        'find.exe', 'grep.exe', 'rg.exe', 'tail.exe', 'sh.exe', 'bash.exe', 'head.exe',
        'sed.exe', 'awk.exe', 'gawk.exe', 'xargs.exe', 'sort.exe', 'git.exe'
    ),
    # How long a dead-parent process must have been running before it counts as stranded. A
    # process whose parent exited seconds ago may simply be finishing normally.
    [int]$MinAgeMinutes = 10,
    # Actually terminate the candidates. Without this the script only reports.
    [switch]$Kill,
    # Also kill a candidate that holds a LISTENING TCP port. Without this they are reported and
    # skipped: a listener is usually a fixture something else is still talking to.
    [switch]$Force,
    # Emit JSON instead of a table.
    [switch]$Json
)

$ErrorActionPreference = 'Stop'

# --- Read the process table once ----------------------------------------------------------------
# ONE CIM query for the whole table, not one per candidate. This runs while the box is already
# under memory pressure, which is the worst time to pay for a dozen round-trips.
try {
    # HandleCount comes back on the same query, and it is the quantity the whole header is about.
    # Asking for it here is what lets the control line report a walker this script's image list
    # cannot name -- a python.exe or rg.exe walking / leaks handles identically and would otherwise
    # sit inside a confident zero.
    $all = @(Get-CimInstance Win32_Process -Property ProcessId, ParentProcessId, Name, CreationDate, HandleCount -EA Stop)
} catch {
    Write-Error "reap-orphans: could not read the process table ($($_.Exception.Message)). Nothing was examined, so nothing can be concluded."
    exit 1
}

# A PowerShell hashtable is already case-insensitive, so the image names go in as written.
$imageSet = @{}
foreach ($n in $Image) { $imageSet[$n] = $true }

$alivePids = @{}
foreach ($p in $all) { $alivePids[[int]$p.ProcessId] = $true }

$now = Get-Date

# Handle count above which a process is worth naming whatever its image is. Not a kill threshold:
# nothing below ever widens what -Kill targets, it only widens what gets REPORTED.
$HANDLE_FLOOR = 10000

# --- One pass over the table, producing the control numbers and the candidate set ---------------
# ONE traversal, not three. The dead-parent predicate used to be written twice -- once for the
# control and once for the candidates -- and the control exists precisely to validate the candidate
# set, so two spellings of it could disagree silently. That is the failure the control was built to
# make visible, reproduced in the control's own wiring.
#
# A RECYCLED PARENT PID READS AS ALIVE, and therefore SUPPRESSES a candidate. That is the safe
# direction (an unkilled orphan is a reported nuisance; a killed live process is lost work) but it
# is unnamed elsewhere, so it is named here. The sibling session-registry.ps1 separates DEAD from
# STALE for the same reason; this script deliberately collapses them toward "leave it alone".
$totalProcesses = $all.Count
$msysAliveCount = 0
$deadParentAnyAge = 0
$highHandleDeadParent = 0
$candidates = [System.Collections.Generic.List[object]]::new()
foreach ($p in $all) {
    $isMsys = $imageSet.ContainsKey([string]$p.Name)
    if ($isMsys) { $msysAliveCount++ }
    if ($alivePids.ContainsKey([int]$p.ParentProcessId)) { continue }
    $deadParentAnyAge++
    if ([int]$p.HandleCount -ge $HANDLE_FLOOR) { $highHandleDeadParent++ }
    if (-not $isMsys) { continue }
    # A process with no readable creation time is treated as AGE ZERO, which excludes it from the
    # candidate set. The unknown direction has to be the safe one, for the reason above.
    $age = if ($null -eq $p.CreationDate) { 0.0 } else { ($now - [datetime]$p.CreationDate).TotalMinutes }
    if ($age -lt $MinAgeMinutes) { continue }
    $candidates.Add([pscustomobject]@{ Proc = $p; Age = $age })
}

# --- Which pids hold a listening socket ---------------------------------------------------------
# UNKNOWN IS NOT EMPTY. If the listener table cannot be read, every candidate is treated as though
# it might hold a port, so -Kill alone refuses and says why. Reading "could not look" as "nothing
# listening" is how a default sweep takes out a fixture.
#
# NOT CONSULTED IS A THIRD STATE, and it is not "unreadable" either. With no candidates there is
# nothing to ask about, and this is a CIM call over root/StandardCimv2 -- the second most expensive
# thing here -- so the common case should not pay for it.
$listeners = @{}
$listenerTable = 'not-consulted'
if ($candidates.Count -gt 0) {
    try {
        foreach ($c in @(Get-NetTCPConnection -State Listen -EA Stop)) {
            $listeners[[int]$c.OwningProcess] = $true
        }
        $listenerTable = 'read'
    } catch {
        $listenerTable = 'unreadable'
    }
}

$rows = @(
    $candidates | ForEach-Object {
        $p = $_.Proc
        [pscustomobject]@{
            Pid          = [int]$p.ProcessId
            Name         = $p.Name
            ParentPid    = [int]$p.ParentProcessId
            Handles      = [int]$p.HandleCount
            # The identity fence's other half. A pid alone does not name a process across time.
            StartedTicks = if ($null -ne $p.CreationDate) { ([datetime]$p.CreationDate).Ticks } else { 0 }
            AgeMinutes   = [math]::Round($_.Age, 1)
            # ONE field for one fact. A boolean beside it was the same information twice, and two
            # fields carrying one fact are two fields to keep in step.
            PortState    = if ($listenerTable -ceq 'read') {
                if ($listeners.ContainsKey([int]$p.ProcessId)) { 'listening' } else { 'none' }
            } else { 'unknown' }
            Action       = 'reported'
        }
    } | Sort-Object -Property AgeMinutes -Descending
)

# --- Kill, only when asked ----------------------------------------------------------------------
$killed = 0
$skippedPort = 0
$skippedIdentity = 0
if ($Kill) {
    foreach ($r in $rows) {
        if ($r.PortState -cne 'none' -and -not $Force) {
            $r.Action = if ($r.PortState -ceq 'unknown') { 'skipped (listener table unreadable; -Force to override)' }
                        else { 'skipped (holds a listening TCP port; -Force to override)' }
            $skippedPort++
            continue
        }
        # RE-READ THE PID IMMEDIATELY BEFORE KILLING IT. Windows reuses pids, and the scan above
        # happened seconds earlier -- long enough for the orphan to exit and something else to
        # inherit its number. A pid is not an identity across time, so the image name and the
        # creation time are checked again and a mismatch SKIPS. The sibling presence.ps1 keeps the
        # same fence for the same reason: 2 of 3 IDE lock files on this host named dead processes.
        try {
            $now = @(Get-CimInstance Win32_Process -Filter "ProcessId = $($r.Pid)" -Property ProcessId, Name, CreationDate -EA Stop)
        } catch {
            $now = @()
        }
        $sameProcess = (
            $now.Count -eq 1 -and
            ([string]$now[0].Name) -ieq ([string]$r.Name) -and
            ($null -ne $now[0].CreationDate) -and
            (([datetime]$now[0].CreationDate).Ticks -eq $r.StartedTicks)
        )
        if (-not $sameProcess) {
            $r.Action = 'skipped (pid no longer names the process that was scanned)'
            $skippedIdentity++
            continue
        }
        try {
            # BY PID. Never by image name: 'taskkill /IM python.exe' is machine-wide and has
            # already killed three peers' interpreters on this box.
            Stop-Process -Id $r.Pid -Force -EA Stop
            $r.Action = 'killed'
            $killed++
        } catch {
            $r.Action = "kill failed: $($_.Exception.Message)"
        }
    }
}

# --- Report -------------------------------------------------------------------------------------
$control = [pscustomobject]@{
    TotalProcesses          = $totalProcesses
    MsysToolsAlive          = $msysAliveCount
    DeadParentAnyAge        = $deadParentAnyAge
    DeadParentOverHandleFloor = $highHandleDeadParent
    HandleFloor             = $HANDLE_FLOOR
    MinAgeMinutes           = $MinAgeMinutes
    ListenerTable           = $listenerTable
    Candidates              = $rows.Count
    Killed                  = $killed
    SkippedHoldingAPort     = $skippedPort
    SkippedPidRecycled      = $skippedIdentity
    KillRequested           = [bool]$Kill
}

if ($Json) {
    ([pscustomobject]@{ control = $control; candidates = $rows } | ConvertTo-Json -Depth 5) | Write-Output
    exit 0
}

Write-Host ""
if ($rows.Count -eq 0) {
    Write-Host "No stranded MSYS tool processes found."
}
else {
    $verb = if ($Kill) { "Stranded MSYS tool processes" } else { "Stranded MSYS tool processes (REPORT ONLY -- pass -Kill to terminate)" }
    Write-Host "${verb}:"
    Write-Host ("  {0,-8} {1,-12} {2,-8} {3,-8} {4,-9} {5,-10} {6}" -f "pid", "image", "parent", "age-min", "handles", "port", "action")
    foreach ($r in $rows) {
        Write-Host ("  {0,-8} {1,-12} {2,-8} {3,-8} {4,-9} {5,-10} {6}" -f $r.Pid, $r.Name, $r.ParentPid, $r.AgeMinutes, $r.Handles, $r.PortState, $r.Action)
    }
}

# THE CONTROL LINE PRINTS ON EVERY RUN, INCLUDING THE ZERO. Without it a clean box and a broken
# scan are the same output.
Write-Host ("control: {0} processes total, {1} MSYS-tool processes alive, {2} dead-parent processes at any age, min-age {3}m." -f `
    $control.TotalProcesses, $control.MsysToolsAlive, $control.DeadParentAnyAge, $control.MinAgeMinutes)
# THE HANDLE NUMBER IS THE ONE THIS SCRIPT'S IMAGE LIST CANNOT REACH. A walker whose image is not
# on the list -- a python.exe, an rg.exe -- leaks handles identically and is otherwise invisible
# here, so a zero above must not read as "nothing is leaking".
Write-Host ("control: {0} of those dead-parent processes hold {1} or more handles, whatever their image." -f `
    $control.DeadParentOverHandleFloor, $control.HandleFloor)
if ($listenerTable -ceq 'unreadable') {
    Write-Host "control: the listening-port table could not be read, so every candidate is treated as holding a port. -Kill alone will skip them all."
}
if ($Kill) {
    Write-Host ("control: killed {0}, skipped {1} holding a listening port, skipped {2} whose pid no longer names the scanned process." -f `
        $killed, $skippedPort, $skippedIdentity)
}
Write-Host ""
exit 0
