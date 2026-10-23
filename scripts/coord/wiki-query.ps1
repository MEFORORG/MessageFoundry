# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
<#
.SYNOPSIS
    Query the fleet wiki with the SHARED coordination root as korus query.ps1's -StateRoot.

.DESCRIPTION
    The wiki inbox is a shared kind (docs/COORD-SHARED-ROOT.md). Building -StateRoot from
    `<git-common-dir>/mefor-coord` by hand reads this PC's local inbox, which the other PC never
    writes once root.toml names a share. This script resolves the root the way every other
    coordination script does, and calls korus query.ps1 with it.

    IT STOPS RATHER THAN PASS A BAD ROOT. korus query.ps1 reads an EMPTY -StateRoot as an
    unreachable inbox, prints `no note` and exits 0, so a broken root looks like a miss. So on any
    resolver error, or an empty path, this script throws a STOP line naming the cause and never
    calls query.ps1. The resolver is Resolve-CoordSharedRoot, which probes a configured root, so a
    share that is missing or unreachable stops here too.

    coord-root.ps1 is dot-sourced from this script's own directory, after a Test-Path. A function of
    the same name already loaded in the calling shell is never used: a missing library stops here.

    It refuses in a Claude Code cloud session with exit 3, as the other coordination readers do.

    It names the root of the clone it lives in, so run it from your engine worktree. It writes
    nothing itself. korus query.ps1 appends its own query log under the root it is given.

.EXAMPLE
    pwsh -NoProfile -File scripts/coord/wiki-query.ps1 -KorusCheckout "<korus checkout>" -Text "<subject>" -RecordRepo "<vault checkout>"
#>
[CmdletBinding()]
param(
    [string] $KorusCheckout,
    [string] $Text,
    [string] $RecordRepo,
    [string] $Seat
)

# A cloud VM's inbox is its own and empty, so a query there answers `no note` and reads as a clean
# miss. The one `exit` in this script: the census in tests/test_coord_cloud_refusal.py holds every
# guarded script to this exact line and exit code.
if ($env:CLAUDE_CODE_REMOTE -eq 'true') {
    [Console]::Error.WriteLine('wiki-query.ps1: refused in a Claude Code cloud session (CLAUDE_CODE_REMOTE=true). This VM''s .git/mefor-coord reaches no other session, so nothing was read or recorded.')
    exit 3
}

$ErrorActionPreference = 'Stop'

function Stop-WikiQuery {
    param([string] $Why)
    throw "STOP     wiki-query: $Why; no query ran"
}

$lib = Join-Path $PSScriptRoot 'coord-root.ps1'
if (-not (Test-Path -LiteralPath $lib -PathType Leaf)) { Stop-WikiQuery "$lib is missing, so the shared root cannot be resolved" }
. $lib

$root = Resolve-CoordSharedRoot -From $PSScriptRoot
if (-not $root) { Stop-WikiQuery 'the resolver returned nothing' }
if ($root.Error) { Stop-WikiQuery "no shared root: $($root.Error)" }
if (-not $root.Path) { Stop-WikiQuery 'no shared root: the resolver returned an empty path' }

if (-not $KorusCheckout) { Stop-WikiQuery 'pass -KorusCheckout <korus checkout>' }
$query = Join-Path $KorusCheckout 'scripts/wiki/query.ps1'
if (-not (Test-Path -LiteralPath $query -PathType Leaf)) { Stop-WikiQuery "$query is missing" }

$forward = @('-StateRoot', [string]$root.Path)
if ($Text) { $forward += @('-Text', $Text) }
if ($RecordRepo) { $forward += @('-RecordRepo', $RecordRepo) }
if ($Seat) { $forward += @('-Seat', $Seat) }

# A child process, so query.ps1's own libraries never meet coord-root.ps1's functions.
& pwsh -NoProfile -NonInteractive -File $query @forward
if ($LASTEXITCODE -ne 0) { throw "wiki-query: korus query.ps1 exited $LASTEXITCODE" }
