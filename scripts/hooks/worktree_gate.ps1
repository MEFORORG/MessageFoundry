<#
.SYNOPSIS
    PreToolUse gate: keep concurrent Claude Code sessions from BUILDING in a shared primary checkout.

.DESCRIPTION
    Installed to the USER scope (%USERPROFILE%\.claude\hooks\) by scripts\worktree\install-gate.ps1, so
    it governs every session in every worktree the moment it lands -- a project-scoped hook would live on
    one branch and reach the other worktrees only once each merged it.

    It denies two things, and only inside a governed primary checkout:

      1. A Write/Edit/MultiEdit/NotebookEdit whose TARGET PATH is inside the primary's working tree.
      2. A Task/Agent/Workflow dispatch made FROM the primary -- because a subagent inherits the parent's
         cwd, cannot create a worktree of its own, and its denied edits do not reliably surface to the
         parent (measured: the parent's result came back with an EMPTY permission_denials list). Blocking
         the fan-out costs one second; letting it run costs the whole workflow.

    KEYED ON THE TARGET PATH, NEVER ON THE SESSION'S cwd. Over 30 days, 29% of this repo's Edit/Write
    calls came from a session sitting in the primary but wrote into a sibling worktree by absolute path --
    i.e. already correct. A cwd-keyed gate would have denied all of them. Only the DESTINATION matters.

    FAILS OPEN on every error path (bad JSON, missing fields, unreadable allowlist). A guardrail that
    wedges all work gets uninstalled, and then it protects nothing.

    This is a guardrail against the ACCIDENTAL primary edit -- the "I forgot to spin up a worktree" case.
    It is NOT a security boundary: it inspects tool arguments, so a file written from a shell command is
    not seen. The shared .git/hooks/pre-commit is the backstop for that.

.NOTES
    Kill switch (from a plain terminal, takes effect immediately, no restart):
        pwsh -File scripts\worktree\install-gate.ps1 -Uninstall
    Deliberately NOT named in the deny message: a model running in bypassPermissions would use it.
#>
[CmdletBinding()]
param(
    # Newline-delimited list of primary checkouts to govern. Absent or empty => the gate is OFF.
    [string]$ReposFile = (Join-Path $env:USERPROFILE ".claude\hooks\worktree-gate.repos.txt")
)

# Fail OPEN: any unhandled error must let the tool call through, never block it.
$ErrorActionPreference = "SilentlyContinue"

function Write-Deny([string]$Reason) {
    # The hookSpecificOutput WRAPPER IS MANDATORY. A bare {"permissionDecision":"deny"} is silently
    # ignored and the tool call proceeds (measured, and reported upstream as #4669 / #37210).
    $payload = @{
        hookSpecificOutput = @{
            hookEventName            = "PreToolUse"
            permissionDecision       = "deny"
            permissionDecisionReason = $Reason
        }
    }
    [Console]::Out.Write(($payload | ConvertTo-Json -Compress -Depth 6))
    exit 0
}

# Canonicalize before comparing. Without GetFullPath, `...\MessageFoundry-tpA\..\MessageFoundry\x.md`
# does not string-match the primary's prefix and walks straight through the gate.
function Get-ComparablePath([string]$Path) {
    if (-not $Path) { return "" }
    try { $full = [System.IO.Path]::GetFullPath($Path) } catch { return "" }
    ($full -replace '\\', '/').TrimEnd('/').ToLowerInvariant()
}

try { $hook = [Console]::In.ReadToEnd() | ConvertFrom-Json } catch { exit 0 }
if (-not $hook) { exit 0 }

# The allowlist doubles as the kill switch: no file, no entries => nothing is governed.
# Each root keeps BOTH forms: a casefolded/slash-normalized one to compare against (Windows paths are
# case-insensitive), and the operator's original spelling to quote back in the deny message -- a message
# that shouts `c:\users\scott\...` at you looks broken even though the match is correct.
$roots = @(
    Get-Content -LiteralPath $ReposFile -ErrorAction SilentlyContinue |
        Where-Object { $_ -and -not $_.TrimStart().StartsWith("#") } |
        ForEach-Object {
            $raw = $_.Trim()
            $cmp = Get-ComparablePath $raw
            if ($cmp) { [pscustomobject]@{ Compare = $cmp; Display = $raw.TrimEnd('\', '/') } }
        }
)
if ($roots.Count -eq 0) { exit 0 }

$tool = [string]$hook.tool_name
$cwd  = Get-ComparablePath ([string]$hook.cwd)

# A worktree that git nests INSIDE the primary's path (.claude/worktrees/<name>, the first-party
# mechanism) is a legitimate worktree even though its path starts with the primary's. Never gate it.
function Test-Governed([string]$Candidate) {
    if (-not $Candidate) { return $null }
    foreach ($root in $roots) {
        $c = $root.Compare
        if ($Candidate -eq $c -or $Candidate.StartsWith("$c/")) {
            if ($Candidate.StartsWith("$c/.claude/worktrees/")) { return $null }
            return $root
        }
    }
    return $null
}

# ---------------------------------------------------------------------------------------------------
# Rule 2 -- dispatching a fan-out FROM the primary. Checked first: it is the cheapest place to stop a
# workflow that would otherwise burn 40 minutes and then report success while having written nothing.
# ---------------------------------------------------------------------------------------------------
if ($tool -in @("Task", "Agent", "Workflow")) {
    $root = Test-Governed $cwd
    if ($root) {
        $display = $root.Display
        Write-Deny @"
BLOCKED: this session is running in the SHARED PRIMARY checkout ($display), so it may not dispatch
subagents. A subagent inherits this cwd, cannot create a worktree for itself, and its blocked edits do
not reliably surface back to you -- the fan-out would appear to succeed while writing nothing.

Create a worktree first, then dispatch from it:

    pwsh -NoProfile -File $display\scripts\worktree\new.ps1 -Name <short-kebab-task-name>

That prints a worktree path. Ask the user to start the session there (or continue there yourself), then
re-dispatch. If you were only going to READ, do it directly -- reads are never blocked.
"@
    }
    exit 0
}

# ---------------------------------------------------------------------------------------------------
# Rule 3 -- a git command that SWAPS THE PRIMARY'S WORKING TREE out from under the sessions standing
# in it. This is not a hypothetical: a sibling session ran `git checkout <its-branch>` in the shared
# primary and then detached HEAD, and every other session's files silently became a different commit's
# files. Rules 1 and 2 cannot see it -- a git command is a SHELL call, not an Edit, so no amount of
# tool-argument inspection catches it.
#
# Scoped tightly: only verbs that change WHICH COMMIT the primary's tree reflects, or that DISCARD work.
# Reads (status/log/diff/show/fetch/branch/worktree/rev-parse/...) are untouched, and so are commit/push/
# add and `pull` (a fast-forward of a clean tree is ordinary maintenance). A worktree may switch its own
# branch freely -- only the SHARED primary is protected.
#
# NB this hook only exists INSIDE Claude Code. The operator's own terminal is never gated: this
# constrains agents, not the human, who remains the owner of the primary's HEAD.
# ---------------------------------------------------------------------------------------------------
if ($tool -in @("Bash", "PowerShell")) {
    $cmd = [string]$hook.tool_input.command
    if (-not $cmd) { exit 0 }

    # Match a git invocation however it is spelled: git, git.exe, or an absolute path to either.
    if ($cmd -cnotmatch '(^|[\s;&|(''"\\/])git(\.exe)?["'']?(\s|$)') { exit 0 }

    # The verb must be a whole SUBCOMMAND. `\bmerge\b` is not enough: a hyphen counts as a word boundary,
    # so it also matches the `merge` inside `merge-base` and `merge-tree` -- both of which are READ-ONLY
    # and are exactly what a session should be using instead of a checkout. Require the verb to end at
    # whitespace or end-of-string, and list `cherry-pick` before `merge` so the alternation prefers it.
    # `[^|;&]*?` keeps the scan inside one command, so `git log | grep reset` is not a false positive.
    $verbs = 'cherry-pick|checkout|switch|reset|restore|stash|clean|rebase|merge|revert|am|apply'
    if ($cmd -cnotmatch "\bgit(\.exe)?\b[^|;&]*?\s(?<verb>$verbs)(?=\s|$)") { exit 0 }
    $verb = $Matches['verb']

    # Which repo does it act on? An explicit `-C <path>` wins over the session's cwd -- otherwise a
    # session sitting in a worktree could reach INTO the primary with `git -C <primary> checkout x` and
    # sail straight past a cwd-only check.
    $target = $cwd
    if ($cmd -match '(?:^|\s)-C\s+"?([^"\s]+)"?') { $target = Get-ComparablePath $Matches[1] }

    $root = Test-Governed $target
    # `cd <primary>; git checkout ...` and `pushd` defeat both of the above, so also treat any command
    # that NAMES a governed primary as targeting it.
    if (-not $root) {
        $normalized = ($cmd -replace '\\', '/').ToLowerInvariant()
        foreach ($r in $roots) {
            if ($normalized.Contains($r.Compare)) { $root = $r; break }
        }
    }
    if (-not $root) { exit 0 }   # acting on a worktree or another repo entirely -- not our business

    $display = $root.Display
    Write-Deny @"
BLOCKED: 'git $verb' would change the working tree of the SHARED PRIMARY checkout ($display).

Other sessions are standing in that directory right now. Switching its branch (or resetting, stashing or
cleaning it) swaps every file under them mid-task -- silently. This has already happened here: a session
checked out its own branch in the primary and left HEAD detached, and the tree other sessions were reading
became a different commit's tree.

You almost never need this:
  * To BUILD, work in your own worktree -- and you can create one from here:
        pwsh -NoProfile -File $display\scripts\worktree\new.ps1 -Name <short-kebab-task-name>
  * To READ another branch WITHOUT touching any working tree, use the plumbing:
        git -C "$display" show <ref>:<path>        git -C "$display" ls-tree <ref>
        git -C "$display" diff <ref>..<ref>        git -C "$display" log <ref>
  * If the primary is genuinely broken (detached HEAD, wrong branch), REPAIR it rather than checking out
    by hand -- this is allowed, and it refuses if the tree is dirty:
        pwsh -NoProfile -File $display\scripts\worktree\restore-primary.ps1

If none of those fit, STOP and tell the user: "I need to change the primary checkout's branch and the
worktree gate blocked it." The primary's HEAD belongs to the user, not to a session.
"@
}

# ---------------------------------------------------------------------------------------------------
# Rule 1 -- writing INTO the primary's working tree, from anywhere.
# ---------------------------------------------------------------------------------------------------
if ($tool -notin @("Write", "Edit", "MultiEdit", "NotebookEdit")) { exit 0 }

$target = [string]$hook.tool_input.file_path
if (-not $target) { $target = [string]$hook.tool_input.notebook_path }
if (-not $target) { exit 0 }   # unrecognized tool shape -> fail open

# cwd is used ONLY to root a relative path -- never as the thing being judged.
if (-not [System.IO.Path]::IsPathRooted($target)) {
    if (-not $hook.cwd) { exit 0 }
    $target = Join-Path ([string]$hook.cwd) $target
}

$root = Test-Governed (Get-ComparablePath $target)
if (-not $root) { exit 0 }

$display = $root.Display

# Point the session at worktrees that ALREADY exist before it makes another one. Without this, every retry
# mints a fresh worktree and the machine fills up with them.
$worktrees = @()
try {
    $worktrees = @(
        & git -C $display worktree list --porcelain 2>$null |
            Select-String -Pattern '^worktree (.+)$' |
            ForEach-Object { $_.Matches[0].Groups[1].Value } |
            Where-Object { (Get-ComparablePath $_) -ne $root }
    )
} catch { $worktrees = @() }

$worktreeHint = if ($worktrees.Count -gt 0) {
    "`n`nWorktrees that already exist -- REUSE one if it is yours before creating another:`n" +
    (($worktrees | Select-Object -First 8 | ForEach-Object { "    $_" }) -join "`n")
} else { "" }

Write-Deny @"
BLOCKED: this write targets the SHARED PRIMARY checkout ($display), where concurrent sessions collide.
This is a hard gate. Re-issuing the same edit will fail again -- do not retry it, and do not route around
it with a shell command; that only hides the collision.

You are NOT blocked from working. Writes to any linked worktree, to the scratchpad, or to any other repo
are allowed FROM THIS SESSION -- you do not need to relocate, cd, or restart. Only the primary's own
working tree is off limits. Do one of these:

  A) BUILD IN A WORKTREE (the normal path). Create one, then re-issue your edit against an ABSOLUTE path
     inside it:
         pwsh -NoProfile -File $display\scripts\worktree\new.ps1 -Name <short-kebab-task-name>
     It prints the worktree path. It gets its own branch off a freshly fetched origin/main, and its own
     .venv, so tests there run against that code.

  B) RESCUE WORK ALREADY IN THE PRIMARY. If the primary's tree is already dirty, move it wholesale
     rather than re-doing it:
         pwsh -NoProfile -File $display\scripts\worktree\rescue.ps1 -Name <short-kebab-task-name>

  C) If neither fits -- e.g. the change genuinely belongs in the primary -- STOP and tell the user
     exactly that, in these words: "The worktree gate blocked a write to the primary checkout and I
     need you to decide." Do not attempt to disable the gate.$worktreeHint
"@
