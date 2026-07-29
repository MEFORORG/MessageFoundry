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

$tool   = [string]$hook.tool_name
$cwd    = Get-ComparablePath ([string]$hook.cwd)   # canonicalised: allowlist comparison only
$cwdRaw = [string]$hook.cwd                        # original case: for `git -C` in rule 3b

# ---------------------------------------------------------------------------------------------------
# Rule 4 -- deny the EnterWorktree tool. Relocating a LIVE session into a worktree re-files its
# transcript under the worktree's slug, so the conversation drops out of the window it was born in
# (measured: a 5,159-line transcript moved out, leaving a 103-byte stub). Open a FRESH session in the
# worktree instead; scripts\worktree\sessions.ps1 -Rehome recovers any session already relocated.
#
# Keys on the TOOL, not the cwd: relocation loses the chat wherever you start it, so once the gate is
# on (roots non-empty, guarded above) EnterWorktree is denied unconditionally. ExitWorktree is a safe
# keep and must NOT be caught. Fail-open is preserved: any earlier parse error already exited 0, and
# only an exact tool match reaches Write-Deny.
#
# Expressed as `$tool -in @("EnterWorktree")` so tests/test_install_gate_wiring.py SEES this tool as
# handled and ENFORCES that install-gate.ps1 registers a matcher for it -- rule 3 shipped dead once by
# implementing a rule with no matcher, and that tripwire exists to prevent exactly this. The matcher is
# wired in install-gate.ps1 alongside this change; delete it there and the wiring test goes red.
# ---------------------------------------------------------------------------------------------------
if ($tool -in @("EnterWorktree")) {
    Write-Deny @"
BLOCKED: EnterWorktree relocates this live session into a worktree, which re-files its chat transcript
under the worktree's slug and drops it from THIS window's session list (nothing is deleted -- it just
stops appearing where you started). Do not relocate a running session.

Instead:
  * Open a NEW Claude Code window/session directly on the worktree and continue there.
  * If a session has already been relocated and vanished, recover it:
        pwsh -NoProfile -File $($roots[0].Display)\scripts\worktree\sessions.ps1 -Rehome <id-prefix>
"@
}

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
# Rule 3b -- hijacking a LINKED WORKTREE by switching it onto an ALREADY-EXISTING branch. Rule 3 below
# protects only the shared PRIMARY; this protects every OTHER governed worktree from the one move that
# actually happened here: a session with no worktree of its own ran `git checkout <a-branch>` inside
# somebody else's worktree, yanking that session's files onto a different branch mid-task. git permits
# it because its native guard only blocks a branch ALREADY checked out somewhere -- a "free" branch can
# be grabbed by any worktree.
#
# Deliberately narrow: only a switch onto an EXISTING LOCAL BRANCH is denied. Creating a new branch
# (-b/-c), restoring files (`--`/pathspec), and reset/rebase/merge of the worktree's OWN branch stay
# allowed -- a worktree owns its own history; it just may not be pulled onto another in-flight branch.
# The gate cannot tell a worktree's rightful session from a squatter (both share the cwd), so it blocks
# the move for both; the rightful owner's escape hatch is a PLAIN terminal (never gated) or a fresh
# worktree for the other branch. Returns normally to ALLOW; calls Write-Deny (which exits) to block.
function Test-WorktreeHijack([string]$Verb, [string]$Cmd, [string]$CwdRaw) {
    if ($Verb -notin @("checkout", "switch")) { return }

    # Which working tree does the command act on? Keep the RAW (original-case) path -- every `git -C`
    # below MUST use it, never a Get-ComparablePath value: that form is lowercased, and on a
    # case-sensitive filesystem (Linux CI) `git -C /tmp/.../primary-wt` misses the real `.../Primary-wt`
    # dir, so the whole rule silently fails open. Get-ComparablePath is for allowlist comparison ONLY.
    # Read git's global `-C <path>` case-SENSITIVELY so a lowercase `-c <cfg>` is not taken as a path.
    # An explicit -C wins; else a leading `cd`/`pushd`; else the session's cwd (the case that happened).
    $wtRaw = $CwdRaw
    if ($Cmd -cmatch '(?:^|\s)-C\s+"?([^"\s]+)"?') { $wtRaw = $Matches[1] }
    elseif ($Cmd -match '(?:^|\s)(?:cd|pushd)\s+"?([^"&|;]+?)"?\s*(?:&&|;|\||$)') {
        $wtRaw = $Matches[1].Trim()
    }
    if (-not $wtRaw) { return }

    # Everything AFTER the first verb, up to the next command separator (so `git checkout x && ...`
    # does not drag the next command's tokens in). Parsing args here -- not the whole command -- keeps
    # git's pre-verb `-C`/`-c` globals from being read as checkout's `-b` / switch's `-c`.
    $after = ($Cmd -replace ('(?s)^.*?\b' + [regex]::Escape($Verb) + '\b'), '')
    $after = ($after -split '(?:&&|\|\||;|\|)', 2)[0]

    # Not a branch switch onto an existing branch? Leave it alone.
    #   `--`                       -> pathspec / file restore (`git checkout -- f`, `git checkout r -- f`)
    #   -b/-B (checkout) / -c/-C (switch) AFTER the verb -> creating a branch, not moving onto one
    if ($after -cmatch '(^|\s)--(\s|$)') { return }
    if ($after -cmatch '(^|\s)-[bBcC](?=\s|$)') { return }

    # The destination ref = first positional (non-flag) token after the verb.
    $dest = $null
    foreach ($tok in @($after -split '\s+' | Where-Object { $_ })) {
        if ($tok.StartsWith('-')) { continue }
        $dest = $tok.Trim('"', "'")
        break
    }
    if (-not $dest) { return }

    # Classify $wtRaw against git itself (robust for BOTH nested .claude/worktrees and sibling
    # worktrees): find the MAIN worktree of whatever repo it belongs to; act only if that main worktree
    # is a governed primary AND $wtRaw is a DIFFERENT (linked) worktree of it. All git calls take the RAW
    # path; only the results are canonicalised for comparison. Any git failure -> fail open.
    $list = @(& git -C $wtRaw worktree list --porcelain 2>$null)
    if ($LASTEXITCODE -ne 0 -or $list.Count -eq 0) { return }
    $mainLine = $list | Where-Object { $_ -match '^worktree ' } | Select-Object -First 1
    if (-not $mainLine) { return }
    $mainWt = Get-ComparablePath ($mainLine -replace '^worktree\s+', '')
    $gov = Test-Governed $mainWt
    if (-not $gov) { return }                                     # repo's main tree isn't governed

    $selfTopRaw = "$(& git -C $wtRaw rev-parse --show-toplevel 2>$null)".Trim()
    $selfTop = Get-ComparablePath $selfTopRaw
    if (-not $selfTop -or $selfTop -eq $mainWt) { return }        # $wtRaw IS the primary -- Rule 3 owns it

    # Only an EXISTING local branch, and only if it is not the branch we are already on (a no-op).
    & git -C $wtRaw rev-parse --verify --quiet ("refs/heads/" + $dest) *> $null
    if ($LASTEXITCODE -ne 0) { return }
    $head = "$(& git -C $wtRaw rev-parse --abbrev-ref HEAD 2>$null)".Trim()
    if ($dest -eq $head) { return }

    $newHint = "$($gov.Display)\scripts\worktree\new.ps1"
    Write-Deny @"
BLOCKED: 'git $Verb $dest' would switch a LINKED WORKTREE ($selfTopRaw) onto the existing branch '$dest'.

That worktree belongs to another session, which is building on '$head' right now. Switching it swaps every
file under that session mid-task -- silently -- and drags two sessions' work onto one branch. This is not
hypothetical: it is exactly the hijack that happened here. A session with no worktree of its own ran a
`git checkout` inside somebody else's worktree; git allowed it because '$dest' was not checked out anywhere.

What to do instead:
  * To BUILD on '$dest', give it its OWN worktree -- git then refuses to check that branch out twice,
    which is the protection you actually want. The branch already exists, so reuse it by name:
        pwsh -NoProfile -File $newHint -Name $dest
  * To READ '$dest' without touching any working tree, use the plumbing:
        git -C "$selfTopRaw" show $dest`:<path>        git -C "$selfTopRaw" diff HEAD..$dest
  * If you genuinely OWN this worktree and must switch it, do it from a PLAIN terminal -- the gate governs
    agents, not you. Do not route around this with a shell script; that only hides the collision.
"@
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
            # Match the primary path only at a DIRECTORY BOUNDARY, never as a raw prefix substring. A
            # sibling worktree is named `<primary>-<task>`, so its path CONTAINS the primary's as a prefix
            # ('.../messagefoundry-ss-capture' starts with '.../messagefoundry'); a plain .Contains() then
            # falsely re-flagged a legitimate `git -C "<sibling>" merge` whose -C already resolved to a
            # NON-governed target above. The first lookahead rejects the characters that CONTINUE a
            # directory name ([a-z0-9_-] -> messagefoundry-ss, messagefoundry2, messagefoundry_x are all
            # different dirs): the primary substring is not a boundary there, so those siblings are allowed.
            #
            # `.` is the awkward case and needs the SECOND lookahead. Windows silently STRIPS a trailing
            # dot from a path component, so `cd <primary>.` actually resolves to the primary itself and a
            # `git checkout` there swaps the shared tree -- that MUST block. But `<primary>.old` is a
            # genuinely different directory that must NOT. So a dot can't simply live in the first reject
            # class (that re-introduced a FALSE NEGATIVE on the tree-swapping `<primary>.`) nor be omitted
            # from all of it (that re-introduced the `<primary>.old` FALSE POSITIVE). `(?!\.[a-z0-9_-])`
            # splits them: it fails the match only when the dot BEGINS a longer name component (`.old`),
            # while a dot followed by a real terminator (quote, space, `;`, EOL) passes both lookaheads and
            # matches -- so `<primary>.` is blocked and `<primary>.old` is allowed.
            #
            # Every character that genuinely TERMINATES the path in a real `cd <primary>; git checkout` --
            # a path separator, whitespace, a quote, `;` `&` `|` `)`, a bare trailing dot, or end-of-string
            # -- clears both lookaheads and still matches, so no real primary tree-swap slips through.
            #
            # THIRD lookahead (BACKLOG #308): honour the SAME `.claude/worktrees/` exemption that
            # Test-Governed already applies. A linked worktree living UNDER the primary is not the
            # primary -- a git verb there swaps only its own tree -- but a path separator clears both
            # lookaheads above, so `<primary>/.claude/worktrees/<name>` matched and DENIED. That is
            # exactly where new.ps1 puts every worktree, so `cd <own worktree> && git rebase ...` -- the
            # most ordinary thing a session does -- was refused as if it were swapping the shared tree,
            # while the identical command with the path omitted was allowed: the block depended on how the
            # command was SPELLED, not on what it touched. Only this one subpath is exempt; the primary
            # itself and any OTHER path inside it (`<primary>/.claude/hooks`) still match and still deny.
            $boundary = [regex]::Escape($r.Compare) +
                '(?![a-z0-9_-])(?!\.[a-z0-9_-])(?!/\.claude/worktrees/)'
            if ($normalized -match $boundary) { $root = $r; break }
        }
    }
    if (-not $root) {
        # Not the shared primary. It may still be a governed LINKED WORKTREE being hijacked onto an
        # existing branch (rule 3b) -- Write-Deny + exit if so; otherwise this returns and we allow.
        # Pass the RAW cwd: rule 3b shells `git -C` and must not use a lowercased path (Linux CI).
        Test-WorktreeHijack $verb $cmd $cwdRaw
        exit 0
    }

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
