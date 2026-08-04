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
    #
    # Resolved null-safely: $env:USERPROFILE is Windows-only and is NULL elsewhere, where Join-Path throws
    # a parameter-binding error instead of returning a path. In a PARAMETER DEFAULT that is evaluated
    # during binding, so it would kill the hook before its first line -- and a hook that exits
    # non-zero-but-not-2 lets the tool call through SILENTLY. The gate would be off with nothing to say so.
    # NB `$( ... )`, not `( ... )`. A bare paren opens a COMMAND-INVOCATION group, so PowerShell parses the
    # `if` as a command NAME and fails with "The term 'if' is not recognized". A statement needs a
    # subexpression. This shipped broken and was invisible to 192 tests, because every one of them passes
    # -ReposFile explicitly and a parameter default is not evaluated when a value is supplied -- so nothing
    # ever exercised the production path. The gate was OFF on every real tool call for the length of one
    # install. tests/test_worktree_gate_default_reposfile.py now runs it with NO arguments.
    [string]$ReposFile = (Join-Path $(
        if ($env:USERPROFILE) { $env:USERPROFILE } else { [Environment]::GetFolderPath('UserProfile') }
    ) ".claude/hooks/worktree-gate.repos.txt")
)

# A HUMAN LABEL, not the parity check. `install-gate.ps1 -Status` compares SHA-256 and that comparison is
# authoritative; this string exists so the output is readable, and it is bumped by hand.
#
# Which means it can lie, and immediately did: rules 1a, 3c and 3d were added without bumping it, so
# -Status printed the SAME version on both sides directly above a *** STALE *** verdict. The SHA caught
# the drift, but a stamp that disagrees with the verdict beside it is the exact ambiguity this machinery
# exists to remove. -Status now prints the SHA prefix on both lines, so agreement is visible rather than
# asserted, and this label can never again be the only thing a reader compares.
$GateVersion = "2026.07.29.2"

# Fail OPEN: any unhandled error must let the tool call through, never block it.
$ErrorActionPreference = "SilentlyContinue"

function Write-Deny([string]$Reason, [string]$Rule = "?", [string]$Detail = "") {
    # Leave a RECEIPT before denying. Until this existed the gate was unfalsifiable: it wrote its decision
    # to stdout and exited 0, so nothing on the box could answer "how many drift events did we prevent",
    # "is the false-positive rate 1/day or 1/1000", or "did that fix change anything" -- and every severity
    # ranking about this machinery was therefore an opinion. Best-effort and never load-bearing: the log
    # lives beside the allowlist, and if the append fails the deny still goes out.
    #
    # Deliberately NOT logged: the raw command or file contents. Each rule passes a $Detail it composed
    # itself (a verb, a target path), so an argument carrying a secret cannot end up in a plaintext log.
    try {
        $logDir = Split-Path -Parent $ReposFile
        if ($logDir -and (Test-Path -LiteralPath $logDir)) {
            # ONE RECORD IS ONE LINE, always. $Detail is composed from tool input, so an embedded newline
            # or tab would let a crafted path forge extra records in a log whose whole purpose is counting.
            # Strip both and cap the length before composing.
            $clean = {
                param($s)
                $t = ("$s" -replace '[\r\n\t]', ' ')
                if ($t.Length -gt 400) { $t.Substring(0, 400) + '...' } else { $t }
            }
            $stamp = (Get-Date).ToString("s")
            $line = "$stamp`tv$GateVersion`tpid=$PID`trule=$(& $clean $Rule)`ttool=$(& $clean $tool)" +
                    "`tcwd=$(& $clean $cwdRaw)`t$(& $clean $Detail)"
            # Every session on the box shares this file, so concurrent denies race. Add-Content silently
            # dropped records under contention -- and a lossy counter is worse than none, because it reads
            # as a measurement. Retry a bounded number of times, then give up quietly: the deny matters,
            # the receipt does not.
            $path = Join-Path $logDir "worktree-gate.log"
            for ($i = 0; $i -lt 5; $i++) {
                try {
                    [System.IO.File]::AppendAllText($path, $line + [Environment]::NewLine)
                    break
                } catch {
                    Start-Sleep -Milliseconds (10 * ($i + 1))
                }
            }
        }
    } catch { }

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
function Get-ComparablePath([string]$Path, [string]$Base) {
    if (-not $Path) { return "" }
    try {
        # A RELATIVE path must resolve against the SESSION's cwd, not this hook process's. `../../..` is
        # exactly how a session sitting in <primary>/.claude/worktrees/<x> names the repo root, and
        # GetFullPath($Path) alone resolved it against wherever pwsh happened to be started -- so
        # `cd ../../.. && git reset --hard` did not look like it touched the primary and was ALLOWED
        # (measured, along with six other spellings). Callers that already have an absolute path may omit
        # $Base; GetFullPath throws on a non-rooted base, which the catch turns into "not governed".
        $full = if ($Base -and -not [System.IO.Path]::IsPathRooted($Path)) {
            [System.IO.Path]::GetFullPath($Path, $Base)
        } else {
            [System.IO.Path]::GetFullPath($Path)
        }
    } catch { return "" }
    ($full -replace '\\', '/').TrimEnd('/').ToLowerInvariant()
}

# Which working tree does a git command act on? ONE resolver, shared by rules 3 and 3b, because they used
# to have two and a real tree swap fell between them: rule 3 read only `-C` and cwd, so `cd <primary> &&
# git reset --hard` spelled relatively resolved to the session's own (ungoverned) worktree and it handed
# off to 3b -- which resolved the `cd` correctly, saw the primary, and returned with the comment "Rule 3
# owns it". Rule 3 had already declined. Both bowed out. Worse, 3b only handles checkout/switch, so for the
# other nine verbs there was no hand-off at all.
#
# Returns the RAW (original-case) path: rule 3b shells `git -C` with it, and on a case-sensitive
# filesystem a lowercased path misses the real directory and the whole rule silently fails open.
# Every path a git command could be acting on, in priority order, as RAW (original-case) strings.
#
# It returns a SET, not a winner, and the caller denies if ANY member is governed. That is the whole
# correction: `--work-tree` / `GIT_WORK_TREE` say where FILES land, they do NOT say which repository is
# mutated -- GIT_DIR still resolves from the cwd, so `git --work-tree=/tmp/x reset --hard` run in the
# primary still moves the SHARED repo's HEAD and index. Treating them as a replacement target turned a
# one-token flag into a bypass of the whole rule (measured DENY -> ALLOW). Only `-C` genuinely relocates
# both, so only `-C` replaces the cwd.
#
# $Prefix is the text BEFORE the git invocation on the same line, and a `cd` is honoured only from there.
# Reading `cd` from the whole command made the resolver order-blind: `git checkout main && cd ../elsewhere`
# resolved to `../elsewhere` and allowed a swap of the tree the git call had already acted on. A prefix
# that is ambiguous -- `popd`, `cd -`, a subshell, or more than one `cd` -- falls back to the session cwd,
# which is the DENY-side default.
function Get-GitTargetCandidatesRaw([string]$Line, [string]$Prefix, [string]$CwdRaw) {
    $out = @()

    # git's global `-C <path>`, read CASE-SENSITIVELY. `-match` is case-INsensitive in PowerShell, so
    # git's lowercase `-c name=value` config override was captured as if it were a path -- and being the
    # first match it also shadowed a real `-C` later in the same command.
    if ($Line -cmatch '(?:^|\s)-C\s+"?([^"\s]+)"?') {
        $out += $Matches[1]
    } else {
        $cd = $null
        if ($Prefix -notmatch '(?:^|\s)(?:popd|cd\s+-(?:\s|$))' -and $Prefix -notmatch '[({]') {
            $cds = [regex]::Matches($Prefix, '(?:^|\s)(?:cd|pushd)\s+"?([^"&|;]+?)"?\s*(?:&&|;|\||$)')
            if ($cds.Count -eq 1) { $cd = $cds[0].Groups[1].Value.Trim() }
        }
        $out += $(if ($cd) { $cd } else { $CwdRaw })
    }

    # ADDITIONAL, never instead of: see the note above.
    if ($Line -cmatch '(?:^|\s)--work-tree[=\s]+"?([^"\s]+)"?') { $out += $Matches[1]; $out += $CwdRaw }
    if ($Line -cmatch '(?:^|\s)GIT_WORK_TREE="?([^"\s]+)"?')    { $out += $Matches[1]; $out += $CwdRaw }
    # --git-dir names the repo; the tree is its parent. Add both rather than reason about which.
    if ($Line -cmatch '(?:^|\s)--git-dir[=\s]+"?([^"\s]+)"?') {
        $out += $Matches[1]
        $out += (Join-Path $Matches[1] "..")
    }
    $out | Where-Object { $_ }
}

# Decide from the COMMAND, never from prose inside it -- but "prose" and "code" are not the same as
# "quoted" and "unquoted", and conflating them was a measured regression.
#
# Three false positives came from scanning the raw string: a two-line command whose second line read
# `echo about to merge stuff` denied with verb=merge; `echo "git checkout main"` denied; and
# `git commit -m "chore: clean up dead code"` denied on `clean`. Blanking every quoted span fixed those --
# and broke something worse. The argument of an interpreter flag (`pwsh -Command "..."`, `bash -c "..."`,
# `cmd /c "..."`) is quoted, but it is CODE THAT RUNS: blanking it made `pwsh -Command "git reset --hard"`
# in the primary ALLOW where it had always denied, across rules 3 AND 3b. That is precisely the
# route-around the rule-3 deny text warns against, spelled in this repo's own house idiom.
#
# So an interpreter argument is not blanked, it is RECURSED INTO: its contents come back as an extra
# scan line, judged on its own terms. Everything else quoted stays inert.
#
# Each entry carries BOTH forms. Scan is for deciding whether a git verb is present; Raw is for parsing
# PATHS out of the same line, since the blanking that stops a commit message supplying a verb would also
# erase the path.
function Get-ScannableSegments([string]$Cmd) {
    # Fold line continuations FIRST, or the per-line split below separates `git \` from its verb and the
    # rule stops seeing the command at all. Prose does not end a line with a continuation character, so
    # this does not resurrect the `echo about to merge stuff` false positive.
    $folded = $Cmd -replace '\\\r?\n[ \t]*', ' '
    $folded = $folded -replace '`\r?\n[ \t]*', ' '

    $lines = @($folded -split '\r?\n')

    # One level of interpreter recursion. `-c`/`-lc`/`-Command`/`/c`/`/k` and their quoted argument.
    $inner = @()
    foreach ($ln in $lines) {
        foreach ($pat in @(
            '(?:^|\s)(?:-c|-lc|-ec|-Command|-EncodedCommand)\s+"([^"]*)"',
            "(?:^|\s)(?:-c|-lc|-ec|-Command|-EncodedCommand)\s+'([^']*)'",
            '(?:^|\s)/[ckCK]\s+"([^"]*)"'
        )) {
            foreach ($m in [regex]::Matches($ln, $pat)) { $inner += $m.Groups[1].Value }
        }
    }

    foreach ($line in @($lines + $inner)) {
        # A quoted PROGRAM path must keep its git token -- `"C:\Program Files\Git\bin\git.exe" checkout
        # main` is a real spelling and blanking it wholesale would be a false NEGATIVE. Collapse that form
        # to a bare token first, then blank every remaining quoted span.
        $s = $line -replace '"[^"]*[\\/](git(?:\.exe)?)"', '$1'
        $s = $s -replace "'[^']*[\\/](git(?:\.exe)?)'", '$1'
        $s = $s -replace '"[^"]*"', '""'
        $s = $s -replace "'[^']*'", "''"
        [pscustomobject]@{ Raw = $line; Scan = $s }
    }
}

try { $hook = [Console]::In.ReadToEnd() | ConvertFrom-Json } catch { exit 0 }
if (-not $hook) { exit 0 }

# The allowlist doubles as the kill switch: no file, no entries => nothing is governed.
# Each root keeps BOTH forms: a casefolded/slash-normalized one to compare against (Windows paths are
# case-insensitive), and the operator's original spelling to quote back in the deny message -- a message
# that shouts `c:\users\<you>\...` at you looks broken even though the match is correct.
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
# handled -- rule 3 shipped dead once by implementing a rule with no matcher, and that tripwire exists to
# prevent exactly this.
#
# NB the matcher is OPT-IN (`install-gate.ps1 -EnterWorktreeGate`), so this rule does not fire on a bare
# install. That is deliberate and pinned by test_the_default_install_wires_rules_1_2_and_3_and_nothing_else
# plus OPT_IN_TOOLS in tests/test_gate_installed_parity.py -- turning it on is a decision, not a side
# effect of re-installing. Rationale: docs/SESSION-DRIFT-CONTROLS.md section 4.
# ---------------------------------------------------------------------------------------------------
if ($tool -in @("EnterWorktree")) {
    Write-Deny -Rule "4" -Detail "relocate-session" -Reason @"
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
function Test-WorktreeHijack([string]$Verb, [string]$Cmd, [string]$WtRaw) {
    if ($Verb -notin @("checkout", "switch")) { return }

    # $WtRaw is resolved ONCE by rule 3 (Get-GitTargetCandidatesRaw) and handed down, so the two rules
    # cannot disagree about which tree a command acts on -- they used to have separate parsers, and a real
    # tree swap fell into the gap between them. It is the RAW (original-case) path, which every `git -C`
    # below MUST use: a Get-ComparablePath value is lowercased, and on a case-sensitive filesystem
    # (Linux CI) `git -C /tmp/.../primary-wt` misses the real `.../Primary-wt` and the rule fails open.
    if (-not $WtRaw) { return }
    $wtRaw = $WtRaw

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
    Write-Deny -Rule "3b" -Detail "git $Verb -> $selfTopRaw" -Reason @"
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
        Write-Deny -Rule "2" -Detail "dispatch $tool" -Reason @"
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

    # -----------------------------------------------------------------------------------------------
    # Rule 3c -- a git CONFIG write that disarms the SHARED repository. `config` changes no tree, so the
    # verb list never saw it, and its blast radius is worse than a tree swap: all eight worktrees share
    # one `.git`, so `git config core.hooksPath /dev/null` run in ANY of them disables the ledger, claim
    # and leak commit gates for EVERY one at once. `-c core.hooksPath=` does it for a single command,
    # which is enough to slip one commit past them. `core.worktree`, `alias.*` and `include.path` are the
    # same class: they redirect what a later git command actually does.
    #
    # Deliberately narrow. Reads (`--get`, `--list`, ...) and every other key stay untouched -- this must
    # not become a general ban on configuring a repo, and `git config user.email` is ordinary setup.
    #
    # Unlike rules 1-3 this does NOT use Test-Governed, because its `.claude/worktrees/` exemption is
    # exactly wrong here: a linked worktree is not the primary, but its config write lands in the SHARED
    # config and harms every sibling. Ask git for the common dir instead, which catches nested worktrees,
    # sibling worktrees and the primary alike. Any git failure falls through to ALLOW.
    # -----------------------------------------------------------------------------------------------
    $dangerKeys = 'core\.hookspath|core\.worktree|alias\.[\w.-]+|include\.path|includeif\.'
    foreach ($seg in (Get-ScannableSegments $cmd)) {
        if ($seg.Scan -cnotmatch '(^|[\s;&|(''"\\/])git(\.exe)?["'']?(\s|$)') { continue }
        if ($seg.Scan -notmatch "(?:\bconfig\b[^|;&]*?\s|-c\s+)(?<key>$dangerKeys)") { continue }
        $badKey = $Matches['key']
        # A read is not a write.
        if ($seg.Scan -match '(?:^|\s)--(get|get-all|get-regexp|list|show-origin)(\s|$)') { continue }

        $at = [regex]::Match($seg.Raw, '(^|[\s;&|(''"\\/])git(\.exe)?["'']?(\s|$)')
        $pfx = $(if ($at.Success) { $seg.Raw.Substring(0, $at.Index) } else { "" })
        $where = @(Get-GitTargetCandidatesRaw $seg.Raw $pfx $cwdRaw)
        if ($where.Count -eq 0) { continue }

        $common = "$(& git -C $where[0] rev-parse --git-common-dir 2>$null)".Trim()
        if ($LASTEXITCODE -ne 0 -or -not $common) { continue }
        $commonCmp = Get-ComparablePath $common $where[0]
        $govCfg = $null
        foreach ($r in $roots) {
            if ($commonCmp -eq $r.Compare -or $commonCmp.StartsWith("$($r.Compare)/")) { $govCfg = $r; break }
        }
        if (-not $govCfg) { continue }

        Write-Deny -Rule "3c" -Detail "git config $badKey" -Reason @"
BLOCKED: setting '$badKey' would change the SHARED git configuration of $($govCfg.Display).

Every worktree of this repository shares one .git directory, so this is not a local change: it takes
effect for all of them at once. Repointing core.hooksPath (or aliasing a command, or redirecting
core.worktree) disables the commit-time ledger, claim and secret-leak gates for every session on this
machine, and nothing would report that they had stopped running.

What to do instead:
  * If a commit hook is failing, FIX THE CAUSE -- the hook output names it. Never route around a gate;
    that converts a caught problem into an uncaught one.
  * If you need a different hook set for a genuine reason, that is a repository decision. STOP and tell
    the user: "I need to change core.hooksPath on the shared repo and the worktree gate blocked it."
  * Ordinary per-user config (user.email, user.name, and anything that is not on the disarm list) is
    untouched and needs no workaround.
"@
    }

    # -----------------------------------------------------------------------------------------------
    # Rule 3d -- `git worktree remove` / `move`, which DESTROYS OR RELOCATES ANOTHER SESSION'S CHECKOUT.
    # Every rule above protects a tree from being swapped; this one protects it from being deleted, which
    # is strictly worse and was entirely unguarded. The verb list could never have caught it: `worktree`
    # is two tokens (`worktree remove`) where every other entry is one, and git refuses to remove the
    # worktree you are STANDING in -- so a `worktree remove` that reaches git is, by construction, aimed
    # at somebody else's.
    #
    # The target is the PATH ARGUMENT, not the cwd, and it cannot be judged with Test-Governed: a linked
    # worktree is exempt there (correctly, for tree swaps) and a sibling worktree falls outside the roots
    # entirely. Ask git whether the path is a registered worktree of a governed repo instead. Any git
    # failure -- a path that is not a worktree, or does not exist -- falls through to ALLOW.
    # -----------------------------------------------------------------------------------------------
    foreach ($seg in (Get-ScannableSegments $cmd)) {
        if ($seg.Scan -cnotmatch '(^|[\s;&|(''"\\/])git(\.exe)?["'']?(\s|$)') { continue }
        if ($seg.Scan -cnotmatch '\bworktree\s+(?<wtverb>remove|move)(?=\s|$)') { continue }
        $wtVerb = $Matches['wtverb']

        # First positional (non-flag) token after the subcommand is the worktree being acted on.
        $after = ($seg.Raw -replace ('(?s)^.*?\bworktree\s+' + $wtVerb + '\b'), '')
        $after = ($after -split '(?:&&|\|\||;|\|)', 2)[0]
        $victimRaw = $null
        foreach ($tok in @($after -split '\s+' | Where-Object { $_ })) {
            if ($tok.StartsWith('-')) { continue }
            $victimRaw = $tok.Trim('"', "'")
            break
        }
        if (-not $victimRaw) { continue }

        $victimCommon = "$(& git -C $victimRaw rev-parse --git-common-dir 2>$null)".Trim()
        if ($LASTEXITCODE -ne 0 -or -not $victimCommon) { continue }
        $victimCmp = Get-ComparablePath $victimCommon $victimRaw
        $govWt = $null
        foreach ($r in $roots) {
            if ($victimCmp -eq $r.Compare -or $victimCmp.StartsWith("$($r.Compare)/")) { $govWt = $r; break }
        }
        if (-not $govWt) { continue }

        Write-Deny -Rule "3d" -Detail "git worktree $wtVerb" -Reason @"
BLOCKED: 'git worktree $wtVerb $victimRaw' acts on a worktree of $($govWt.Display) that belongs to
ANOTHER SESSION -- git refuses to remove the worktree you are standing in, so this one is not yours.

Removing it deletes that session's working tree and its branch, along with any uncommitted work in them.
There is no undo, and the session using it finds out when its next file read fails.

What to do instead:
  * Cleaning up merged worktrees is a maintenance job with its own dry-run-by-default tool. Run it and
    READ what it proposes before applying anything:
        pwsh -NoProfile -File $($govWt.Display)\scripts\worktree\prune-merged.ps1
  * To find out whether a worktree is still in use, look rather than delete:
        git -C "$($govWt.Display)" worktree list
  * If you are certain it is abandoned and must go now, that is the user's call, not yours. Say so:
    "I want to remove the worktree $victimRaw and I need you to confirm it is not in use."
"@
    }

    # The verb must be a whole SUBCOMMAND. `\bmerge\b` is not enough: a hyphen counts as a word boundary,
    # so it also matches the `merge` inside `merge-base` and `merge-tree` -- both of which are READ-ONLY
    # and are exactly what a session should be using instead of a checkout. Require the verb to end at
    # whitespace or end-of-string, and list `cherry-pick` before `merge` so the alternation prefers it.
    # `[^|;&]*?` keeps the scan inside one command, so `git log | grep reset` is not a false positive.
    $verbs = 'cherry-pick|checkout|switch|reset|restore|stash|clean|rebase|merge|revert|am|apply'

    # Scan SEGMENT BY SEGMENT (Get-ScannableSegments): per line, with quoted spans blanked, plus the
    # contents of any interpreter argument recursed into. A verb must come from a git invocation on the
    # same segment and outside inert quotes, or prose supplies it.
    # Evaluate EVERY verb-bearing segment, not just the first. `git -C ../x checkout main ; git checkout
    # main` has two invocations and only the second touches this tree; stopping at the first match judged
    # the wrong one. Deny on the first segment whose target set contains a governed tree.
    $verb = $null ; $verbLine = $null ; $targetRaw = $cwdRaw ; $root = $null
    # True once some segment's target had to be INFERRED (from cwd or a cd) rather than stated with `-C`.
    # An explicit `-C` is authoritative about which repository git acts on, so the in-text fallback below
    # must not second-guess it -- `cd <primary> && git -C <sibling> rebase` acts on the sibling, and
    # denying it because the primary's path appears in the `cd` is a false positive.
    $anyInferredTarget = $false
    $gitToken = '(^|[\s;&|(''"\\/])git(\.exe)?["'']?(\s|$)'
    foreach ($seg in (Get-ScannableSegments $cmd)) {
        # Match a git invocation however it is spelled: git, git.exe, or an absolute path to either.
        if ($seg.Scan -cnotmatch $gitToken) { continue }
        if ($seg.Scan -cnotmatch "\bgit(\.exe)?\b[^|;&]*?\s(?<verb>$verbs)(?=\s|$)") { continue }
        $segVerb = $Matches['verb']

        # Everything BEFORE the git invocation on this line. A `cd` is honoured only from here -- reading
        # it from the whole command made the resolver order-blind (see Get-GitTargetCandidatesRaw).
        $at = [regex]::Match($seg.Raw, $gitToken)
        $segPrefix = $(if ($at.Success) { $seg.Raw.Substring(0, $at.Index) } else { "" })

        if ($seg.Raw -cnotmatch '(?:^|\s)-C\s+"?([^"\s]+)"?') { $anyInferredTarget = $true }

        # Path parsing runs on the RAW line, never on the blanked scan string: the blanking that stops a
        # commit message supplying a verb would also erase the path. Deny if ANY candidate is governed --
        # a `--work-tree` elsewhere does not stop the cwd's repo being mutated.
        $cands = @(Get-GitTargetCandidatesRaw $seg.Raw $segPrefix $cwdRaw)
        if (-not $verb) {
            $verb = $segVerb ; $verbLine = $seg.Raw
            if ($cands.Count -gt 0) { $targetRaw = $cands[0] }
        }
        foreach ($c in $cands) {
            $hit = Test-Governed (Get-ComparablePath $c $cwdRaw)
            if ($hit) { $root = $hit ; $verb = $segVerb ; $verbLine = $seg.Raw ; $targetRaw = $c ; break }
        }
        if ($root) { break }
    }
    if (-not $verb) { exit 0 }

    # `cd <primary>; git checkout ...` and `pushd` defeat both of the above, so also treat any command
    # that NAMES a governed primary as targeting it -- but only where the target was inferred.
    if (-not $root -and $anyInferredTarget) {
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
            # The mention must be a DIRECTORY-CHANGE ARGUMENT, not merely present in the command.
            #
            # Matching the path ANYWHERE made the verdict depend on what else the command happened to
            # say. Measured 2026-08-04, three times in one session, all from a worktree and all safe:
            # `git restore <two files>` denied as "would change the working tree of the SHARED PRIMARY"
            # because a later `cat <primary>/.git/mefor-coord/...` in the same compound command named the
            # primary. Isolating the identical git call was allowed instantly. Worse than the noise: the
            # refusal TEXT was wrong about what the command did, so the operator reading it was told the
            # primary was at risk when it never was -- and a gate that misdescribes the thing it blocked
            # trains people to route around it. This is the same defect #308 fixed for the nested-worktree
            # subpath, arriving through a different spelling.
            #
            # Narrowing is safe because the fallback has exactly one job. Every OTHER way of aiming a git
            # verb at the primary is resolved STRUCTURALLY before this point and sets $root without it:
            # the cwd, an explicit `-C`, and `--work-tree` / `--git-dir` (added to the candidate set
            # above, which is why a RELATIVE `--work-tree=../../..` still denies -- it never reaches this
            # text scan). The fallback exists solely for `cd <primary>; git checkout`, where the verb runs
            # somewhere the hook cannot observe because the directory changes mid-command. So require the
            # directory change, and the true positive is untouched while the false one disappears.
            #
            # Still deliberately conservative: `cd <primary>; cd <elsewhere>; git checkout` denies. Once a
            # command has stepped into the primary this hook stops reasoning about where it stepped next.
            $dirChange = '(?:^|[;&|(]|\s)(?:cd|chdir|pushd|set-location|sl)' +
                '(?:\s+(?:/d|-path|-literalpath))?\s+["'']?' + $boundary
            if ($normalized -match $dirChange) { $root = $r; break }
        }
    }
    if (-not $root) {
        # Not the shared primary. It may still be a governed LINKED WORKTREE being hijacked onto an
        # existing branch (rule 3b) -- Write-Deny + exit if so; otherwise this returns and we allow.
        # Hand down the LINE the verb was found on and the tree already resolved from it, so 3b judges
        # the same command rule 3 did (including one recursed out of an interpreter argument).
        Test-WorktreeHijack $verb $verbLine $targetRaw
        exit 0
    }

    $display = $root.Display
    Write-Deny -Rule "3" -Detail "git $verb" -Reason @"
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

# ---------------------------------------------------------------------------------------------------
# Rule 1a -- the gate's OWN enforcement surface. The installed script and its allowlist live OUTSIDE
# every governed root, so Test-Governed returned $null for them and rule 1 allowed an Edit to either: one
# line written to the allowlist disarms the gate for every session on this machine, permanently and
# silently. The docstring's answer was that the kill switch is "deliberately NOT named in the deny
# message" -- obscurity over a file one `ls` away, and not a control.
#
# Scoped to ~/.claude/hooks/ ONLY, deliberately. settings.json is NOT covered: editing it is sanctioned
# work (the update-config skill exists to do exactly that), and blocking it would break a supported
# workflow to close a hole that requires a far more deliberate act than deleting a stray-looking text
# file. This closes the accident and the cheap route-around, which is all a guardrail is for.
#
# The installer is unaffected: it writes from a plain terminal via Set-Content/Copy-Item, which is a
# SHELL call and not an Edit, so no tool-argument rule sees it. That asymmetry is the point -- the human
# installs and removes the gate; a session may not.
# ---------------------------------------------------------------------------------------------------
# Match the two exact FILES, never their parent directory. Keying on the parent looked tidier and was
# wrong twice over: $ReposFile is a parameter that can point anywhere (under test it sits in a temp dir,
# where it swallowed every unrelated path), and ~/.claude/hooks/ also holds things this rule has no
# business governing. The surface worth protecting is precisely the kill switch and the script it arms.
$gateFiles = @(
    (Get-ComparablePath $ReposFile)
    (Get-ComparablePath (Join-Path (Split-Path -Parent $ReposFile) "worktree_gate.ps1"))
) | Where-Object { $_ }
if ((Get-ComparablePath $target) -in $gateFiles) {
    Write-Deny -Rule "1a" -Detail $target -Reason @"
BLOCKED: this writes to the worktree gate's own enforcement surface ($target).

That directory holds the installed hook and its allowlist. The allowlist is the gate's kill switch -- a
single edit there turns it off for every session on this machine, so a session may not write here at all.
This is not a file to fix in passing.

If the gate is genuinely wrong -- a false positive, a rule that needs changing -- fix it at the SOURCE and
re-install, which is a human act from a plain terminal:

    scripts\hooks\worktree_gate.ps1        the rule you want to change
    scripts\worktree\install-gate.ps1      installs it (refuses to run inside Claude Code)

If you need it OFF right now, say so and let the user decide, in these words: "I want the worktree gate
turned off and I need you to do it." Do not disable it yourself.
"@
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
            # `$root` is the PSCustomObject from Test-Governed, NOT a string -- comparing a path to it was
            # always -ne, so the filter never removed anything and the PRIMARY ITSELF was listed first under
            # "REUSE one if it is yours", displacing a real worktree off the 8-item cap below. The one part
            # of this hook whose entire job is steering the next action was steering it back at the tree we
            # had just refused. Compare against the canonicalised form.
            Where-Object { (Get-ComparablePath $_) -ne $root.Compare }
    )
} catch { $worktrees = @() }

$worktreeHint = if ($worktrees.Count -gt 0) {
    "`n`nWorktrees that already exist -- REUSE one if it is yours before creating another:`n" +
    (($worktrees | Select-Object -First 8 | ForEach-Object { "    $_" }) -join "`n")
} else { "" }

Write-Deny -Rule "1" -Detail $target -Reason @"
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
