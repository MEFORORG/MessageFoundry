<#
.SYNOPSIS
    Stop hook: record this session's episode so a replacement seat under another account can pick the
    work up. Thin by design -- it forwards stdin to scripts/coord/seat.ps1 and gets out of the way.

.DESCRIPTION
    WIRED TO Stop ONLY, and that is a measured choice rather than a default. Stop already pays a pwsh
    spawn for the mail drain, and install-coordination.ps1 measured roughly 366 ms per spawn against
    about 19 tool calls per turn. A second UserPromptSubmit hook would be a standing tax on every
    prompt for a path exercised at account-switch frequency -- days apart, not seconds. Stop fires at
    every turn end, so the record's asOf is still bounded by the seat's last COMPLETED turn.

    THE TURN IT IS WRITTEN IN IS THE TURN IT CANNOT SEE. A Stop hook runs at the end of a turn, so a
    turn killed mid-flight leaves no record of itself, and the blind spot is always the NEWEST turn --
    which is exactly what a replacement most needs. This is why fleet.ps1 re-reads the predecessor
    worktree's ACTUAL git status at render time rather than trusting the recorded one, and renders any
    disagreement as stranded work. The hook cannot close this gap; the reader has to.

    THIS HOOK MUST NEVER FAIL THE TURN. It exits 0 unconditionally, so a broken writer never takes the
    session's Stop handler down with it.

    BUT IT MUST NOT SWALLOW THE WRITER EITHER, AND IT USED TO. This hook ran seat.ps1 as
    `... 2>&1 | Out-Null` and exited 0, which is why the rule above needs the paragraph below rather
    than a one-liner. A non-zero exit from a child is not an exception, so the catch never fired, and
    the justification -- "seat.ps1 already records its own failures to seats/.writer-errors.txt" -- is
    FALSE for exactly the failures that discard hid. seat.ps1 leaves $script:SeatsDir null until it has
    resolved a worktree AND a git common dir, and Write-WriterError returns early while it is null, so
    every failure BEFORE that point can only reach stderr: its dot-source of mail-key.ps1 (outside its
    main try, under $ErrorActionPreference='Stop') and both of its Rule 1 no-write paths, which use
    `Write-Error ... -EA Continue` as their ONLY signal. The heartbeat is written after that point too,
    so those paths leave no .writer-alive touch either.

    MEASURED, one lab repo, one invocation shape. A writer that could not even start reported rc=1 and
    a real error on stderr when run directly; THROUGH THE HOOK it was rc=0, empty stdout, empty stderr,
    zero files touched -- byte-identical to a healthy quiet turn. The Rule 1 no-write path was the same
    picture at rc=0. Positive control, same rig: with the dependency restored the identical hook call
    produced both expected artifacts, so the hook was reachable and working throughout. That is the
    "confidently empty roster" this layer exists to make impossible, arriving through its own writer.

    SO: CAPTURE THE CHILD, AND RECORD ANY FAILURE HERE RATHER THAN DELEGATING IT. This hook can resolve
    <git-common-dir>/mefor-coord/seats itself, which is the entire point -- it is the surface that still
    works when the writer's own error path does not. A failure is appended to .writer-errors.txt, the
    file fleet.ps1's receipt already counts as writerErrorLines, so it lands where a cold-start reader
    is already looking.

    NO OUTPUT ON THE SUCCESS PATH. Stop-hook output is shown to the model, and a line printed at every
    single turn end is noise that trains the reader to skip the whole channel -- including the turn it
    finally says something that matters. Measured across three consecutive healthy turns, seat.ps1
    -Record emits zero bytes on both streams and exits 0 (its only two chatty lines are guarded by
    -BumpEpoch and by `-not $Record`), so "any output at all, or a non-zero exit" is a sound failure
    trigger that cannot fire on a healthy turn.
#>
[CmdletBinding()]
param([string]$CommonDir)

# Deliberately NOT 'Stop'. A throw here would surface as a failed Stop hook every turn.
$ErrorActionPreference = 'Continue'

# Where the seats layer lives, resolved WITHOUT seat.ps1's help. $CommonDir first: the shim does not
# pass it today, but honouring it costs nothing and it is the cheapest path when it is there.
function Resolve-SeatsDir {
    param([string]$Hint)
    $common = $null
    if ($CommonDir) {
        $common = $CommonDir
    } else {
        foreach ($from in @($Hint, $PSScriptRoot)) {
            if (-not $from) { continue }
            if (-not (Test-Path -LiteralPath $from -PathType Container)) { continue }
            # --path-format=absolute is not optional: the bare form resolves against the caller's cwd.
            $c = & git -C $from rev-parse --path-format=absolute --git-common-dir 2>$null
            if ($LASTEXITCODE -eq 0 -and $c) { $common = ([string]($c -join '')).Trim(); break }
        }
    }
    if (-not $common) { return $null }
    return (Join-Path (Join-Path $common 'mefor-coord') 'seats')
}

# Best-effort by construction, exactly like seat.ps1's own Write-WriterError: if we cannot record the
# failure we still exit 0. A real tab, from a double-quoted format string -- seat.ps1's single-quoted
# equivalent emits a literal backtick-t, so a reader splitting on tab gets one field per row there.
function Write-WriterError {
    param([string]$Stage, [string]$Message, [string]$Hint)
    try {
        $dir = Resolve-SeatsDir -Hint $Hint
        if (-not $dir) { return $false }
        if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
        $flat = ([string]$Message -replace '\s+', ' ').Trim()
        if ($flat.Length -gt 500) { $flat = $flat.Substring(0, 500) + ' ...[truncated]' }
        $line = "{0}`t{1}`t{2}`t{3}" -f ([DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')), $env:COMPUTERNAME, $Stage, $flat
        Add-Content -LiteralPath (Join-Path $dir '.writer-errors.txt') -Value $line -Encoding utf8 -EA Stop
        return $true
    } catch { return $false }
}

$hint = $null
try {
    # Read stdin ONCE and pass it on. The payload carries session_id, and without it seat.ps1 keys the
    # record on the literal string 'nosid' -- correct, but it collapses every unidentified session in
    # a worktree into one record, so the payload is worth forwarding carefully.
    $payload = ''
    if ([Console]::IsInputRedirected) { $payload = [Console]::In.ReadToEnd() }

    # The payload's cwd is the seat being recorded, so it names the clone whose seats layer a reader
    # will read. Parsing is advisory only -- a malformed payload must not cost us the run.
    if ($payload) {
        try {
            $j = $payload | ConvertFrom-Json
            if ($j -and ($j.PSObject.Properties.Name -contains 'cwd')) { $hint = [string]$j.cwd }
        } catch { $hint = $null }
    }

    $seat = Join-Path (Split-Path $PSScriptRoot -Parent) 'coord\seat.ps1'
    if (-not (Test-Path -LiteralPath $seat)) {
        # Resolving to nothing is the failure mode this whole layer exists to make visible, so say so
        # rather than exiting quietly. A wired hook that resolves nothing is byte-identical to a
        # healthy one with nothing to do.
        $m = "scripts/coord/seat.ps1 is missing from this checkout at '$seat'"
        Write-WriterError -Stage 'hook-missing-writer' -Message $m -Hint $hint | Out-Null
        Write-Output "[seat] scripts/coord/seat.ps1 is missing from this checkout -- the seat recorder is wired but resolving nothing."
        exit 0
    }

    if ($payload) {
        $out = $payload | & pwsh -NoProfile -File $seat -Record 2>&1
    } else {
        $out = & pwsh -NoProfile -File $seat -Record 2>&1
    }
    $rc = $LASTEXITCODE

    # A NON-ZERO EXIT IS NOT AN EXCEPTION, and seat.ps1's no-write paths exit 0 with a message on
    # stderr, so neither condition alone is sufficient. Both are checked.
    $said = ''
    if ($out) { $said = (($out | ForEach-Object { [string]$_ }) -join ' ').Trim() }
    if ($rc -ne 0 -or $said) {
        $detail = "seat.ps1 exited $rc" + $(if ($said) { ": $said" } else { " with no message" })
        $logged = Write-WriterError -Stage 'hook-writer-failed' -Message $detail -Hint $hint
        $where = if ($logged) { 'logged to seats/.writer-errors.txt' } else { 'COULD NOT be logged -- the seats layer was unreachable too' }
        Write-Output "[seat] this turn was NOT recorded ($where). A cold start would not see this seat. $detail"
    }
} catch {
    # Last resort: the hook itself broke. Try the durable surface first, then stderr, and end the turn
    # cleanly either way.
    $m = "seat-record.ps1 failed: $($_.Exception.Message)"
    Write-WriterError -Stage 'hook-crashed' -Message $m -Hint $hint | Out-Null
    Write-Error "[seat] $m" -EA Continue
}

exit 0
