<#
.SYNOPSIS
    Declare that you are working in a worktree, so the pruner will not remove it.

.DESCRIPTION
    The occupancy fence in prune-merged.ps1 sees registered Claude sessions (by their recorded cwd)
    and Claude tool calls (by what they wrote). It cannot see a HUMAN: an editor, an autosave, a plain
    terminal, a build still writing after the command that started it returned. None of those leave a
    registry record or a transcript, so the only way they can be fenced is for somebody to say so.

    A pin is that statement. It is checked by the same fence, it cannot be overridden by -Name, and it
    ALWAYS expires -- a pin with no expiry turns the first forgotten one into a permanent refusal, and
    a tool that refuses for no visible reason is a tool people work around.

    It is deliberately manual. An automatic lease would need a hook to renew it, and a hook in front
    of every tool call is exactly the surface this design does not have.

.EXAMPLE
    scripts\worktree\worktree-pin.ps1 -Take -Reason "hand-editing in VS Code"       # here, 12h
    scripts\worktree\worktree-pin.ps1 -Take -Path ..\repo-pins -Hours 4 -Reason "..."
    scripts\worktree\worktree-pin.ps1 -List
    scripts\worktree\worktree-pin.ps1 -Release <file>
    scripts\worktree\worktree-pin.ps1 -Release -All
#>
[CmdletBinding(DefaultParameterSetName = 'List')]
param(
    [Parameter(ParameterSetName = 'Take', Mandatory)][switch]$Take,
    [Parameter(ParameterSetName = 'List')][switch]$List,
    [Parameter(ParameterSetName = 'Release', Mandatory)][switch]$Release,
    # The worktree to pin. Defaults to the checkout you are standing in.
    [Parameter(ParameterSetName = 'Take')][string]$Path,
    [Parameter(ParameterSetName = 'Take', Mandatory)][string]$Reason,
    [Parameter(ParameterSetName = 'Take')][double]$Hours = 12,
    # Which pin to release: the file the -Take reported, or its bare name.
    [Parameter(ParameterSetName = 'Release', Position = 0)][string]$Pin,
    [Parameter(ParameterSetName = 'Release')][switch]$All,
    [string]$Repo,
    [switch]$Json
)

$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false

. "$PSScriptRoot\..\coord\occupancy.ps1"

if (-not $Repo) { $Repo = (Get-Location).Path }
$dir = Get-WorktreePinDir -Repo $Repo
if (-not $dir) { throw "Not inside a git repository: $Repo" }

if ($Take) {
    if (-not $Path) { $Path = (Get-Location).Path }
    $wts = @(Get-RepoWorktrees $Repo)
    $norm = ConvertTo-Norm ((Resolve-Path -LiteralPath $Path).Path)
    $hit = @($wts | Where-Object { (ConvertTo-Norm $_.Path) -eq $norm })
    if ($hit.Count -eq 0) {
        # A pin naming a path that is not a worktree is a FAULT to the reader, which would refuse every
        # run until it expired. Refuse to create one rather than handing the operator a live landmine.
        throw "'$Path' is not a registered worktree of this repository, so a pin on it would refuse every prune until it expired. Pin the worktree root."
    }
    $file = New-WorktreePin -Path $hit[0].Path -Reason $Reason -Hours $Hours -PinDir $dir
    if ($Json) { @{ pin = $file; path = $hit[0].Path; hours = $Hours } | ConvertTo-Json -Depth 4 | Write-Output }
    else {
        Write-Host "Pinned $(Split-Path $hit[0].Path -Leaf) for $Hours h: $Reason" -ForegroundColor Green
        Write-Host "  $file" -ForegroundColor DarkGray
        Write-Host "  It expires on its own. Release it early with: $($MyInvocation.MyCommand.Path) -Release '$file'" -ForegroundColor DarkGray
    }
    exit 0
}

if ($Release) {
    if (-not $All -and -not $Pin) { throw "-Release needs a pin file, or -All." }
    $targets = @()
    if ($All) { $targets = @(Get-ChildItem -LiteralPath $dir -Filter *.json -File -EA SilentlyContinue) }
    else {
        $p = if (Test-Path -LiteralPath $Pin) { $Pin } else { Join-Path $dir $Pin }
        if (-not (Test-Path -LiteralPath $p)) { throw "No such pin: $Pin" }
        $targets = @(Get-Item -LiteralPath $p)
    }
    foreach ($t in $targets) { Remove-Item -LiteralPath $t.FullName -Force }
    if ($Json) { @{ released = $targets.Count } | ConvertTo-Json | Write-Output }
    else { Write-Host "Released $($targets.Count) pin(s)." -ForegroundColor Green }
    exit 0
}

$set = Get-WorktreePins -Worktrees @(Get-RepoWorktrees $Repo) -PinDir $dir
if ($Json) {
    [pscustomobject]@{
        available = [bool]$set.Available; detail = $set.Detail; note = $set.Note; dir = $set.Dir
        examined = $set.PinsExamined; unreadable = $set.PinsUnreadable
        expired = $set.PinsExpired; unplaceable = $set.PinsUnplaceable
        faults = @($set.Faults)
        pins = @($set.Pins | ForEach-Object {
                [pscustomobject]@{ worktree = $_.Worktree; by = $_.Short; reason = $_.Reason; expiresAt = $_.ExpiresAt; file = $_.Root }
            })
    } | ConvertTo-Json -Depth 5 | Write-Output
    exit 0
}

Write-Host ""
Write-Host "Pin store: $($set.Dir)" -ForegroundColor DarkCyan
Write-Host ("  $($set.PinsExamined) examined, $($set.PinsExpired) expired, $($set.PinsUnreadable) unreadable, $($set.PinsUnplaceable) unplaceable.") -ForegroundColor DarkGray
if (-not $set.Available) { Write-Host "  UNAVAILABLE -- $($set.Detail)" -ForegroundColor Red }
if ($set.Note) { Write-Host "  $($set.Note)" -ForegroundColor Yellow }
foreach ($p in $set.Pins) {
    Write-Host ("  {0,-36} by {1,-14} until {2}  {3}" -f $p.Worktree, $p.Short, $p.ExpiresAt, $p.Reason)
}
exit 0
