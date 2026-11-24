# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
<#
.SYNOPSIS
    Find (and rescue) Claude Code sessions for this repo across every login -- including the ones that
    relocating into a worktree made invisible.

.DESCRIPTION
    Claude Code files a session's transcript at

        <config-dir>\projects\<slug-of-cwd>\<session-id>.jsonl

    where the slug is derived from the session's CURRENT working directory. Relocate a live session into a
    worktree and the whole transcript is re-filed under the WORKTREE's slug -- so the conversation drops out
    of the session list of the window it was born in. Nothing is deleted; it is simply somewhere the window
    no longer looks. Measured here: a 5,159-line transcript moved out and left a 103-byte title stub behind.

    The gate (scripts\hooks\worktree_gate.ps1) now DENIES the EnterWorktree tool outright (rule 4), so a
    live session can no longer be relocated into a worktree in the first place. This script is the recovery
    path for the sessions that already went missing before that, and the way to see them at all:

        -Rehome moves a transcript back to the slug of the PRIMARY checkout, which puts it back in that
        window's session list, where you can resume it normally.

    Three logins are in play on this machine (~\.claude for the Desktop app, ~\.claude-account-{1,2,3} for
    the CLI/VS Code subscriptions), and a session is only ever visible to the login that owns it. This
    scans all of them, so "which login was that in?" stops being a question you have to answer by hand.

    Read-only unless you pass -Rehome. A bare invocation only ever LISTS -- it never moves anything. -Rehome
    is the one destructive action, and it honours -WhatIf (preview the move without touching disk) and
    refuses on a session that still looks live (see -MinIdleMinutes).

.EXAMPLE
    .\sessions.ps1                          # every session for this repo, newest first
    .\sessions.ps1 -Relocated               # only the ones that moved (i.e. are missing from a window)
    .\sessions.ps1 -Id 3858de6d             # detail for one session (id prefix is enough)
    .\sessions.ps1 -Rehome 3858de6d -WhatIf # preview the rehome without moving anything
    .\sessions.ps1 -Rehome 3858de6d         # put it back in the session list of the window it started in
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    # Only sessions whose transcript is filed somewhere other than where the session was born -- the ones
    # that vanished from a window's list.
    [switch]$Relocated,
    # Show one session in full. A unique id prefix is enough.
    [string]$Id,
    # Move a session's transcript under the PRIMARY's slug, so it reappears in the main window's session
    # list. Refuses on a session that still looks live (see -MinIdleMinutes). Honours -WhatIf.
    [string]$Rehome,
    # Rehome somewhere other than the primary (must be a directory you can actually open a window on).
    [string]$To,
    # A transcript touched more recently than this is assumed to belong to a RUNNING session; moving the
    # file out from under its writer would corrupt it. Override with -Force at your own risk.
    [int]$MinIdleMinutes = 10,
    [switch]$Force,
    [int]$Limit = 40
)

$ErrorActionPreference = "Stop"

$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path

# git prints forward slashes on Windows; transcripts record backslashes. Normalise before comparing.
function Get-NormPath([string]$Path) {
    if (-not $Path) { return "" }
    return ($Path -replace '/', '\').TrimEnd('\')
}

$WorktreePaths = @(
    & git -C $RepoRoot worktree list --porcelain 2>$null |
        Select-String -Pattern '^worktree (.+)$' |
        ForEach-Object { Get-NormPath $_.Matches[0].Groups[1].Value }
)

# Always reason about the PRIMARY, even when run from a worktree: it is the first entry of `worktree list`.
$Primary = if ($WorktreePaths.Count -gt 0) { $WorktreePaths[0] } else { Get-NormPath $RepoRoot }

# The one .git that every worktree of this repo shares. It is how we tell a worktree of OURS from a
# separate repo that merely sits next to it -- `MessageFoundry-public` (the mirror) and
# `messagefoundry-website` both slug to `...-MessageFoundry-*` and are otherwise indistinguishable from a
# worktree named `public` / `website`.
$OurGitDir = ""
try {
    $g = & git -C $RepoRoot rev-parse --path-format=absolute --git-common-dir 2>$null
    if ($LASTEXITCODE -eq 0 -and $g) { $OurGitDir = Get-NormPath $g }
} catch { $OurGitDir = "" }

$live = @{}
foreach ($w in $WorktreePaths) { $live[$w.ToLowerInvariant()] = $true }

# Does this recorded cwd belong to THIS repo? Three cases, and the third is the one that matters.
function Test-OurCheckout([string]$Cwd) {
    $n = Get-NormPath $Cwd
    if (-not $n) { return $true }                       # no cwd recorded -> trust the slug pre-filter
    if ($live.ContainsKey($n.ToLowerInvariant())) { return $true }   # a live worktree of ours

    if (Test-Path -LiteralPath $n -PathType Container) {
        # Still on disk but not a worktree of ours -> a different repo wearing a similar name. Drop it.
        if (-not $OurGitDir) { return $false }
        try {
            $g = & git -C $n rev-parse --path-format=absolute --git-common-dir 2>$null
            if ($LASTEXITCODE -ne 0 -or -not $g) { return $false }
            return ((Get-NormPath $g) -ieq $OurGitDir)
        } catch { return $false }
    }

    # The directory is GONE. This is a pruned worktree -- and a session stranded in a pruned worktree's slug
    # is exactly what this script exists to find, so keep it. (A deleted sibling repo would also land here;
    # that is a rare, harmless false positive, and the listing shows you the path.)
    return $true
}

# Claude Code's slug: every character that is not a letter or a digit becomes '-'. So
# C:\Code\MessageFoundry -> C--Code-MessageFoundry. Compared case-insensitively
# throughout: the drive letter's case varies between sessions ('c:\...' vs 'C:\...') and NTFS folds it
# anyway, so the two spellings are one directory.
function Get-Slug([string]$Path) {
    if (-not $Path) { return "" }
    return ($Path -replace '[^A-Za-z0-9]', '-')
}

$PrimarySlug = Get-Slug $Primary

# All logins on this box. The Desktop app uses the default ~\.claude; each CLI subscription launcher sets
# CLAUDE_CONFIG_DIR to its own ~\.claude-account-N. A session is only visible to the login that owns it.
# -LiteralPath: a profile folder whose name holds [ or ] is not a pattern (vault BACKLOG #2985, added
# item 2).
$ConfigDirs = @(
    Get-ChildItem -LiteralPath $env:USERPROFILE -Directory -Filter ".claude*" -Force -ErrorAction SilentlyContinue |
        Where-Object { Test-Path -LiteralPath (Join-Path $_.FullName "projects") } |
        ForEach-Object { $_.FullName }
)

# Pull the few facts we need out of the head of a transcript. Transcripts run to tens of MB, so never read
# one whole: the birth cwd, branch and first prompt are all in the first handful of records, and reading
# 400 lines of a 14 MB file costs nothing. The first line is often a queue-operation/last-prompt/mode
# record with no cwd, so scan for the first record that actually carries cwd/gitBranch rather than trusting
# line 1 (verified against the real transcript layout on this box).
function Read-TranscriptHead([string]$File) {
    $info = [ordered]@{ Cwd = ""; Branch = ""; Title = ""; Prompt = "" }
    $reader = $null
    try {
        $reader = [System.IO.StreamReader]::new($File)
        for ($n = 0; $n -lt 400 -and -not $reader.EndOfStream; $n++) {
            $line = $reader.ReadLine()
            if (-not $line) { continue }
            try { $o = $line | ConvertFrom-Json } catch { continue }

            if (-not $info.Cwd    -and $o.cwd)       { $info.Cwd = [string]$o.cwd }
            if (-not $info.Branch -and $o.gitBranch) { $info.Branch = [string]$o.gitBranch }
            # A title the user set by hand beats the model's generated one.
            if ($o.customTitle)                      { $info.Title = [string]$o.customTitle }
            if (-not $info.Title -and $o.aiTitle)    { $info.Title = [string]$o.aiTitle }

            # First real user turn -- skip sidechains (subagent traffic), which are not what you'd
            # recognise the session by.
            if (-not $info.Prompt -and $o.type -eq "user" -and -not $o.isSidechain) {
                $c = $o.message.content
                $text = if ($c -is [string]) { $c } else { ($c | Where-Object { $_.type -eq "text" } | Select-Object -First 1).text }
                if ($text) { $info.Prompt = ([string]$text -replace '\s+', ' ').Trim() }
            }
        }
    } catch {
        # A half-written transcript from a live session is normal, not an error. Report what we got.
    } finally {
        if ($reader) { $reader.Dispose() }
    }
    return [pscustomobject]$info
}

# --------------------------------------------------------------------------------------------- collect
$records = @()
foreach ($cfg in $ConfigDirs) {
    $projects = Join-Path $cfg "projects"

    # Pre-filter by slug so we don't crack open every unrelated repo's transcripts, then CONFIRM against
    # the cwd recorded inside the file. The prefix alone is not enough to decide: the sibling repo
    # `messagefoundry-website` slugs to `...-MessageFoundry-website`, which is indistinguishable from a
    # worktree named `website`. The recorded cwd settles it.
    $slugDirs = @(
        Get-ChildItem -LiteralPath $projects -Directory -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -eq $PrimarySlug -or $_.Name -like "$PrimarySlug-*" }
    )

    foreach ($dir in $slugDirs) {
        foreach ($file in (Get-ChildItem -LiteralPath $dir.FullName -Filter "*.jsonl" -File -ErrorAction SilentlyContinue)) {
            $head = Read-TranscriptHead $file.FullName

            # The confirming check: the slug prefix said "maybe", the recorded cwd says yes or no.
            $cwd = Get-NormPath $head.Cwd
            if (-not (Test-OurCheckout $cwd)) { continue }

            $bornSlug = if ($cwd) { Get-Slug $cwd } else { $dir.Name }
            $gone = [bool]($cwd -and -not (Test-Path -LiteralPath $cwd -PathType Container))
            $records += [pscustomobject]@{
                Id        = $file.BaseName
                Login     = Split-Path $cfg -Leaf
                ConfigDir = $cfg
                FiledIn   = $dir.FullName
                FiledSlug = $dir.Name
                BornCwd   = $cwd
                BornSlug  = $bornSlug
                Branch    = $head.Branch
                Title     = $head.Title
                Prompt    = $head.Prompt
                Bytes     = $file.Length
                Last      = $file.LastWriteTime
                File      = $file.FullName
                Gone      = $gone
                # THE symptom: the transcript is not filed where the session was born, so the window it
                # started in cannot see it. (Case-insensitive: the drive letter's case varies.)
                Relocated = ($bornSlug -and ($dir.Name -ine $bornSlug))
            }
        }
    }
}

# A relocated session leaves a title-only stub (one `custom-title` line, ~100 bytes) behind under its birth
# slug. Same id, so fold it into the real record rather than listing a phantom 103-byte session.
$byKey = $records | Group-Object { "$($_.ConfigDir)|$($_.Id)" }
$sessions = foreach ($g in $byKey) {
    $real = $g.Group | Sort-Object Bytes -Descending | Select-Object -First 1
    $stub = $g.Group | Where-Object { $_.File -ne $real.File }
    if (-not $real.Title) { $real.Title = ($stub | Where-Object Title | Select-Object -First 1).Title }
    $real | Add-Member -NotePropertyName Stubs -NotePropertyValue @($stub.File) -PassThru
}
$sessions = @($sessions | Sort-Object Last -Descending)

# ---------------------------------------------------------------------------------------------- rehome
if ($Rehome) {
    $hit = @($sessions | Where-Object { $_.Id -like "$Rehome*" })
    if ($hit.Count -eq 0) { throw "No session matching '$Rehome'. Run without -Rehome to list them." }
    if ($hit.Count -gt 1) { throw "'$Rehome' matches $($hit.Count) sessions. Use a longer id prefix." }
    $s = $hit[0]

    # Moving a transcript out from under a RUNNING session's writer corrupts it -- and relocating a live
    # session is precisely the injury this script exists to REPAIR, so a false "it's idle" here is the
    # worst failure it can have. Two INDEPENDENT signals, and EITHER may veto. Under -WhatIf we only
    # PREVIEW, so both are relaxed there -- nothing is moved, and you still see what the move would do.
    #
    # (1) The session registry, fenced on pid + process start time (scripts/coord/session-registry.ps1).
    #     This is the authoritative POSITIVE signal, and adding it is the point of this guard: transcript
    #     mtime is NOT liveness. Subagent and workflow output is written under <sessionId>/subagents/, so
    #     a session running a long workflow barely touches its own transcript. Measured on this host: a
    #     verifiably-live session sat 32 minutes idle by mtime while its process was alive and fenced --
    #     three times -MinIdleMinutes, i.e. the old guard would have waved the move straight through.
    #
    # (2) Transcript mtime, the original signal, KEPT rather than replaced. A session that exits cleanly
    #     unlinks its registry file, so "no record" is indistinguishable from "never registered" and
    #     cannot stand on its own either.
    #
    # Refusing when EITHER says live is deliberate: nothing on this host can PROVE a session is gone
    # (no heartbeat, and registry writes are event-driven), so only the positive answer is trustworthy.
    # A negative from one signal must never by itself authorise a destructive move.
    . "$PSScriptRoot\..\coord\session-registry.ps1"
    # Listed BEFORE the fence reads the registry, as box-activity.ps1 does: a record half-written at
    # this read and complete by the fence's is then seen by one check or the other (BACKLOG #7622).
    $unparsed = @(Get-SessionRecords -IncludeUnreadable | Where-Object { $_.Unreadable -and -not $_.Directory })
    $reg = Get-SessionLiveness -SessionId $s.Id -Worktree $s.BornCwd
    # UNREADABLE vetoes too: the fence could not be evaluated, or a record naming no session may be
    # this one (session-registry.ps1's header). Such a record used to throw here, which stopped the
    # move; reading UNREADABLE must stop it the same way (BACKLOG #5491).
    $anonymous = @($reg.Anonymous | Where-Object { $_ })
    if ($anonymous.Count -gt 0 -and -not $Force -and -not $WhatIfPreference) {
        # The refusal names its real reason: not this session's own record, but one that names no
        # session in its birth tree. Saying "still RUNNING" over a blank pid would push toward -Force.
        $named = @($anonymous | ForEach-Object { if ($_.Cwd) { "$($_.File) (cwd $($_.Cwd))" } else { "$($_.File) (no readable cwd)" } })
        throw ("Session $($s.Id) cannot be told apart from a registry record that names no session and may be " +
               "this session mid-write: $($named -join '; '). Its own record: " +
               "$(if ($reg.Found) { $reg.Detail } else { 'none' }). Wait for that record to gain its session id " +
               "or go away, then retry (or -Force once you have checked it).")
    }
    if ($reg.State -in @("LIVE", "UNVERIFIED", "UNREADABLE") -and -not $Force -and -not $WhatIfPreference) {
        throw ("Session $($s.Id) is $($reg.State) in the session registry (pid $(if ($reg.Record) { $reg.Record.pid } else { 'none recorded' })" +
               "$(if ($reg.Detail) { "; $($reg.Detail)" })) -- it is still RUNNING and moving its " +
               "transcript would corrupt it. Its transcript may look idle: subagent output is filed " +
               "elsewhere, so mtime is not liveness. Close that window, then retry (or -Force).")
    }
    # A registry file that does not parse names no session anyone can read, so Get-SessionLiveness never
    # sees it, and it may be this session's own record caught mid-write (BACKLOG #7622). It vetoes while
    # its file was written in the last 24 hours (the anonymous records' default bound), or when that
    # file has vanished or carries a future write time; it has no cwd anyone can read, so it cannot be
    # scoped to a tree and vetoes wherever it is. An older one does not veto, or a file that never
    # becomes readable would block every rehome until someone deleted it. A directory named *.json is
    # not a record being written, so it is left out above.
    $wall = [DateTime]::UtcNow
    $unreadable = @($unparsed | Where-Object {
        $item = Get-Item -LiteralPath $_.File -Force -EA SilentlyContinue
        -not $item -or ($wall - $item.LastWriteTimeUtc).TotalHours -lt 24
    })
    if ($unreadable.Count -gt 0 -and -not $Force -and -not $WhatIfPreference) {
        $named = @($unreadable | ForEach-Object { "$($_.File) ($($_.Error))" })
        throw ("Session $($s.Id) cannot be shown not to be running: $($unreadable.Count) session registry " +
               "file(s) written in the last 24h cannot be read, and may be this session's own record " +
               "mid-write: $($named -join '; '). Wait for it to become readable or go away, then retry " +
               "(or -Force once you have checked it).")
    }

    $idle = (Get-Date) - $s.Last
    if ($idle.TotalMinutes -lt $MinIdleMinutes -and -not $Force -and -not $WhatIfPreference) {
        throw ("Session $($s.Id) was written $([int]$idle.TotalMinutes) min ago and may still be RUNNING; " +
               "moving its transcript would corrupt it. Close that window, then retry (or -Force).")
    }

    # Rehome to the PRIMARY, not to wherever the session happened to be born.
    #
    # "Put it back where it started" is the obvious rule and it is wrong. A session can be born in a
    # worktree that no longer exists -- notably the empty ghost stubs the Desktop app's auto-worktree
    # leaves behind -- and its transcript can already be sitting in the primary, VISIBLE. Sending that one
    # "home" would file it under a directory nobody will ever open a window on, i.e. hide the very session
    # we were asked to rescue. (Real case here: a 16 MB session born in a ghost stub, filed in the primary.)
    #
    # The primary is the one checkout that is always open, so it is the one safe destination. -To overrides
    # when you specifically want the session to land in some worktree's window instead.
    $destCwd  = if ($To) { Get-NormPath $To } else { $Primary }
    $destSlug = Get-Slug $destCwd
    if ($To -and -not (Test-Path -LiteralPath $destCwd -PathType Container)) {
        throw "-To '$destCwd' does not exist; a session filed under a directory you cannot open a window on is still lost."
    }

    $destDir = Join-Path (Join-Path $s.ConfigDir "projects") $destSlug
    $dest = Join-Path $destDir "$($s.Id).jsonl"
    if ((Get-NormPath $dest) -ieq (Get-NormPath $s.File)) {
        Write-Host "Session $($s.Id) is already filed at $destSlug. Nothing to do." -ForegroundColor Green
        return
    }

    # A live session now also has a sidecar directory next to its transcript --
    # <config>\projects\<slug>\<session-id>\ (subagents\, workflows\). Move it alongside the .jsonl so the
    # rehome does not strand it under the old slug. (The session-env dir is keyed by session id, not slug,
    # so it is unaffected by a rehome and left alone.)
    $srcSidecar  = Join-Path $s.FiledIn $s.Id
    $destSidecar = Join-Path $destDir $s.Id
    $haveSidecar = Test-Path -LiteralPath $srcSidecar -PathType Container

    # A file already at the destination is merged in below only when it is a title stub: what a
    # relocation leaves behind, a few title records and nothing else (see the fold above). Anything else
    # may be a real transcript, which the move would overwrite, so refuse before touching disk. An
    # existing backup is never overwritten either: it may be the only copy of an earlier stub
    # (BACKLOG #7623).
    $stubLines = @()
    if (Test-Path -LiteralPath $dest) {
        $why = $null
        $item = Get-Item -LiteralPath $dest -Force -EA SilentlyContinue
        if (-not $item -or $item -isnot [System.IO.FileInfo]) { $why = "it is not a readable file" }
        elseif ($item.Length -gt 65536) { $why = "it is $($item.Length) bytes, far more than a title stub" }
        else {
            try { $stubLines = @(Get-Content -LiteralPath $dest -EA Stop | Where-Object { $_.Trim() }) }
            catch { $why = "it cannot be read: $($_.Exception.Message)" }
            if (-not $why) {
                if ($stubLines.Count -eq 0) { $why = "it holds no title record" }
                foreach ($line in $stubLines) {
                    $o = $null
                    # -NoEnumerate keeps a one-element array an array; the name and value compare
                    # case-sensitively, as the transcript reader does.
                    try { $o = ConvertFrom-Json -InputObject $line -NoEnumerate -EA Stop } catch { }
                    $p = if ($o -is [pscustomobject]) { $o.PSObject.Properties | Where-Object { $_.Name -ceq 'type' } | Select-Object -First 1 }
                    $type = if ($p) { [string]$p.Value } else { '' }
                    if ($type -cnotin @('custom-title', 'ai-title')) {
                        $why = "it holds a record that is not a title (type '$type')"
                        break
                    }
                }
            }
        }
        if ($why) {
            throw ("A file already exists at $dest and is not a title stub: $why. It may be a real " +
                   "transcript, so nothing was moved. Check it by hand.")
        }
        if (Test-Path -LiteralPath "$dest.stub.bak") {
            throw ("$dest.stub.bak already exists and may be the only copy of an earlier stub, so nothing " +
                   "was moved. Check it, move it aside, then retry.")
        }
    }

    # -WhatIf preview / confirmation. Nothing below this gate touches disk.
    $action = "rehome $($s.FiledSlug) -> $destSlug$(if ($haveSidecar) { ' (+ sidecar dir)' })"
    if (-not $PSCmdlet.ShouldProcess("session $($s.Id) [$($s.Login)]", $action)) { return }

    New-Item -ItemType Directory -Force -Path $destDir | Out-Null

    # The title stub already sitting at the destination (checked above) IS the session's custom title.
    # Keep it: back it up, then re-append its records to the end of the moved transcript (JSONL is a log
    # -- later records win).
    if (Test-Path -LiteralPath $dest) {
        # A file that appeared after the check above was never checked: refuse rather than merge it.
        if ($stubLines.Count -eq 0) { throw "A file appeared at $dest after it was checked, so nothing was moved. Retry." }
        # $false: never overwrite a backup that appeared since the check.
        [System.IO.File]::Copy($dest, "$dest.stub.bak", $false)
        Remove-Item -LiteralPath $dest -Force
    }

    Move-Item -LiteralPath $s.File -Destination $dest -Force
    if ($stubLines.Count -gt 0) { Add-Content -LiteralPath $dest -Value $stubLines -Encoding utf8 }

    # Move the sidecar directory too, if one exists and is not already at the destination.
    $movedSidecar = $false
    if ($haveSidecar -and ((Get-NormPath $srcSidecar) -ine (Get-NormPath $destSidecar))) {
        if (-not (Test-Path -LiteralPath $destSidecar)) {
            Move-Item -LiteralPath $srcSidecar -Destination $destSidecar -Force
            $movedSidecar = $true
        }
    }

    Write-Host ""
    Write-Host "Rehomed session $($s.Id)" -ForegroundColor Green
    Write-Host "  from : $($s.FiledSlug)"
    Write-Host "  to   : $destSlug   ($destCwd)"
    Write-Host "  login: $($s.Login)"
    if ($stubLines.Count -gt 0) { Write-Host "  kept : the title stub's $($stubLines.Count) record(s) (backup: $dest.stub.bak)" }
    if ($movedSidecar) { Write-Host "  moved: the session's sidecar dir ($($s.Id)\)" }
    Write-Host ""
    Write-Host "It is back in that folder's session list. Open a Claude Code window on $destCwd and it will"
    Write-Host "be there; or resume it directly:"
    Write-Host "  `$env:CLAUDE_CONFIG_DIR='$($s.ConfigDir)'; cd '$destCwd'; claude --resume $($s.Id)"
    return
}

# ---------------------------------------------------------------------------------------------- detail
if ($Id) {
    $hit = @($sessions | Where-Object { $_.Id -like "$Id*" })
    if ($hit.Count -eq 0) { throw "No session matching '$Id'." }
    foreach ($s in $hit) {
        Write-Host ""
        Write-Host "$($s.Id)" -ForegroundColor Cyan
        Write-Host "  title    : $($s.Title)"
        Write-Host "  login    : $($s.Login)"
        Write-Host "  born in  : $($s.BornCwd)$(if ($s.Gone) { '   [DIRECTORY GONE - worktree was pruned]' })   (branch $($s.Branch))"
        Write-Host "  filed in : $($s.FiledIn)"
        if ($s.Relocated -and $s.FiledSlug -ine $PrimarySlug) {
            Write-Host "  STATUS   : RELOCATED -- the window it started in cannot see it." -ForegroundColor Yellow
            Write-Host "             Bring it back to the main window:  .\sessions.ps1 -Rehome $($s.Id)"
        }
        Write-Host "  size     : $([math]::Round($s.Bytes / 1MB, 2)) MB, last written $($s.Last)"
        Write-Host "  opened   : $($s.Prompt)"
        Write-Host "  resume   : `$env:CLAUDE_CONFIG_DIR='$($s.ConfigDir)'; cd '$($s.BornCwd)'; claude --resume $($s.Id)"
    }
    return
}

# ------------------------------------------------------------------------------------------------ list
$show = if ($Relocated) { @($sessions | Where-Object Relocated) } else { $sessions }
if ($show.Count -eq 0) {
    Write-Host "No sessions found for $Primary across $($ConfigDirs.Count) login(s)." -ForegroundColor Yellow
    return
}

# Short, human label for where a transcript sits: the primary, or the worktree's own name.
function Get-Where([string]$Slug) {
    if ($Slug -ieq $PrimarySlug) { return "primary" }
    if ($Slug -like "$PrimarySlug--claude-worktrees-*") { return $Slug.Substring("$PrimarySlug--claude-worktrees-".Length) }
    if ($Slug -like "$PrimarySlug-*") { return $Slug.Substring($PrimarySlug.Length + 1) }
    return $Slug
}

$show | Select-Object -First $Limit | ForEach-Object {
    [pscustomobject]@{
        Last     = $_.Last.ToString("MM-dd HH:mm")
        Id       = $_.Id.Substring(0, 8)
        Login    = $_.Login -replace '^\.claude-account-', 'acct-' -replace '^\.claude$', 'desktop'
        FiledIn  = Get-Where $_.FiledSlug
        BornIn   = Get-Where $_.BornSlug
        MB       = [math]::Round($_.Bytes / 1MB, 1)
        Title    = if ($_.Title) { $_.Title } else { $_.Prompt }
    }
} | Format-Table -AutoSize

$moved = @($sessions | Where-Object { $_.Relocated -and $_.FiledSlug -ine $PrimarySlug }).Count
if ($moved -gt 0 -and -not $Relocated) {
    Write-Host ""
    Write-Host "$moved session(s) were relocated out of the window they started in, and that window's" -ForegroundColor Yellow
    Write-Host "session list can no longer see them. Nothing is lost -- they are just filed elsewhere." -ForegroundColor Yellow
    Write-Host "  list them             :  .\sessions.ps1 -Relocated" -ForegroundColor Yellow
    Write-Host "  bring one back to main:  .\sessions.ps1 -Rehome <id>" -ForegroundColor Yellow
}
