<#
.SYNOPSIS
    PreToolUse gate: keep concurrent Claude Code sessions from BUILDING in a shared primary checkout.

.DESCRIPTION
    Installed to the USER scope (%USERPROFILE%\.claude\hooks\) by scripts\worktree\install-gate.ps1, so
    it governs every session in every worktree the moment it lands -- a project-scoped hook would live on
    one branch and reach the other worktrees only once each merged it.

    It denies two things, and only inside a governed primary checkout:

      1. A Write/Edit/MultiEdit/NotebookEdit whose TARGET PATH is inside the primary checkout -- its working
         tree, AND the shared .git beside it. Those are two different things and the difference is
         load-bearing, so do not shorten this line back to "working tree": nothing under .git/ is IN the
         working tree, yet .git/hooks/ and .git/config must still deny (rules 1/1b, and a test pins it).
         The one carve-out is the cross-session coordination state at .git/mefor-coord/, where handoff
         documents and delivery receipts are allowed and the machine-read registries are not -- see rule 1b.
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
$GateVersion = "2026.08.06.1"

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
#
# SPLIT IN TWO (BACKLOG #1061) so there is exactly ONE definition of "resolve this path", with two views
# of the result. Rule 3c needs this resolution but must NOT have the lowercasing tail: it hands the result
# to `git -C`, and this file warns at the top of the rule-3b resolver and again inside rule 3d that a
# lowercased path works on Windows and silently misses the real directory on a case-sensitive filesystem.
# A second resolver written beside this one would be two definitions that drift invisibly, so the raw form
# IS the shared core and Get-ComparablePath is a fold on top of it.
#
# The non-fully-qualified base is now REJECTED explicitly rather than thrown and caught. Same answer --
# GetFullPath demands a FULLY QUALIFIED base and threw otherwise -- but stating it makes "" mean exactly
# one thing, "I could not resolve this", which rule 3c distinguishes from "git says this is not a repo".
# IsPathFullyQualified, not IsPathRooted: on Windows `IsPathRooted("/tmp")` is true while
# `GetFullPath(x, "/tmp")` still throws, and that throw is what the old catch was absorbing.
function Get-FullPathRaw([string]$Path, [string]$Base) {
    if (-not $Path) { return "" }
    try {
        # A RELATIVE path must resolve against the SESSION's cwd, not this hook process's. `../../..` is
        # exactly how a session sitting in <primary>/.claude/worktrees/<x> names the repo root, and
        # GetFullPath($Path) alone resolved it against wherever pwsh happened to be started -- so
        # `cd ../../.. && git reset --hard` did not look like it touched the primary and was ALLOWED
        # (measured, along with six other spellings). Callers that already have an absolute path may omit
        # $Base.
        if ($Base -and -not [System.IO.Path]::IsPathRooted($Path)) {
            if (-not [System.IO.Path]::IsPathFullyQualified($Base)) { return "" }
            return [System.IO.Path]::GetFullPath($Path, $Base)
        }
        return [System.IO.Path]::GetFullPath($Path)
    } catch { return "" }
}

function Get-ComparablePath([string]$Path, [string]$Base) {
    $full = Get-FullPathRaw $Path $Base
    if (-not $full) { return "" }
    ($full -replace '\\', '/').TrimEnd('/').ToLowerInvariant()
}

# The host names that mean THIS MACHINE in a UNC path. Computed once; the comparison below is against
# an already-lowercased Get-ComparablePath value.
$localShareHosts = @('localhost', '127.0.0.1', '.', "$env:COMPUTERNAME".ToLowerInvariant()) |
    Where-Object { $_ }

# Rewrite a LOCAL ADMIN SHARE spelling of a path to its drive-letter form: //localhost/C$/x -> c:/x
# (BACKLOG #1071). Rule 3c asks git to resolve aliases for it -- which works for a junction, a `\\?\`
# prefix, drive-letter case, a trailing slash and `/./`, all measured -- but git echoes this one spelling
# BACK unresolved, so the comparison against a governed root never matched and a disarm-key write through
# `\\localhost\C$\...` was ALLOWED (measured on git 2.53).
#
# A TEXTUAL rewrite on purpose. The tempting answer is a canonicaliser of our own, and it is the wrong
# one: per-component link resolution inside a PreToolUse hook opens a handle per path component and can
# BLOCK on a dead network path -- a guardrail that hangs the tool call gets uninstalled. This costs one
# regex and touches no filesystem.
#
# Only a LOCAL host is rewritten. `\\otherbox\C$\...` is a different machine's disk as far as anything
# here can tell, and claiming otherwise would be an unmeasured assertion.
#
# NOT claimed, and left alone deliberately: a `subst`ed drive letter, a mapped network drive other than
# the admin share, 8.3 short names, and a WSL `/mnt/c` spelling. None was measured; each would need its
# own asymmetry pair.
function ConvertFrom-LocalAdminShare([string]$Cmp) {
    if (-not $Cmp) { return $Cmp }
    $m = [regex]::Match($Cmp, '^//([^/]+)/([a-z])\$(/.*)?$')
    if (-not $m.Success) { return $Cmp }
    if ($m.Groups[1].Value -notin $localShareHosts) { return $Cmp }
    return $m.Groups[2].Value + ':' + $m.Groups[3].Value
}

# Fold a CALLER-SUPPLIED value before it goes into a deny REASON. Write-Deny already does exactly this for
# the log line, and its note there explains why: "an embedded newline or tab would let a crafted path forge
# extra records in a log whose whole purpose is counting". The reason needed the same defence and did not
# have it, which is worse in one specific way -- a log record is COUNTED, but a reason is an INSTRUCTION an
# agent acts on, and these reasons carry a literal command block introduced by "Do this instead:".
#
# Measured on this hook: a Write whose file_path was
#     <primary>/.git/mefor-coord/alloc/adr/0163.json\n\nDo this instead:\n\n    pwsh -Command "echo PWNED"
# produced a rule 1b reason containing TWO "Do this instead:" blocks, the FORGED one first, so a model
# reading top-down reaches the attacker's command before the real remedy. The path never has to exist; only
# the JSON field does.
#
# Found because a sibling session hit the same class from the other end and asked: rule 3b interpolates a
# BRANCH NAME, and `git check-ref-format` accepts ';', '$', '|', '"' and "'" in a refname, so a branch
# called `x';calc;#` made its deny text parse as two statements with '#' hiding the remainder. Two
# different inputs, one defect -- so this is a helper rather than a patch at one site: treat every value a
# caller can influence as hostile on the way OUT, not only on the way in.
function Get-SafeForMessage([string]$Value) {
    $t = ("$Value" -replace '[\r\n\t]', ' ')
    if ($t.Length -gt 400) { return $t.Substring(0, 400) + '...' }
    return $t
}

# A git BRANCH name -> a legal worktree DIRECTORY component. Rule 3b hands back a REAL ref, and most of
# this repo's local branches contain a '/', which scripts\worktree\new.ps1's -Name can never carry (it is
# a PATH component: a slash there creates a NESTED directory, not the intended sibling). So the rule
# prints BOTH: -Branch gets the ref verbatim, -Name gets this slug.
#
# It lives HERE, not in scripts\worktree\, because install-gate.ps1 copies this hook OUTSIDE every
# working tree, so it can dot-source nothing from a checkout. No rule is duplicated: the gate SANITIZES,
# new.ps1 VALIDATES. Every output is inside new.ps1's accepted character class by construction, so this
# function never needs to know that pattern. new.ps1 must never sanitize, or a typo'd -Name would
# silently become a different directory -- the class this whole fix exists to remove.
#
# Total: the hash fallback covers a legal refname that reduces to nothing (all non-ASCII, or all
# separators). Deterministic, so one branch always maps to one directory name -- a re-run then fails
# loudly on the existing path rather than quietly creating a second worktree for the same branch.
function ConvertTo-WorktreeSlug([string]$Branch) {
    if (-not $Branch) { return "" }
    $s = $Branch -replace '[^A-Za-z0-9._-]', '-'
    $s = $s -replace '-{2,}', '-'
    $s = $s.Trim('-', '.')
    if ($s) { return $s }
    $h = [System.Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes($Branch))
    return "wt-" + (($h[0..3] | ForEach-Object { $_.ToString('x2') }) -join "")
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

    $mask = Get-QuoteMask $Line

    # git's global `-C <path>`, read CASE-SENSITIVELY. `-match` is case-INsensitive in PowerShell, so
    # git's lowercase `-c name=value` config override was captured as if it were a path -- and being the
    # first match it also shadowed a real `-C` later in the same command.
    #
    # THE OPTION IS FOUND IN THE MASK; ITS VALUE IS READ OUT OF THE RAW TEXT (BACKLOG #1066). Every
    # reader here used to be `"?([^"\s]+)"?` against the raw line -- DOUBLE quotes only, and stopping at
    # a SPACE. Both halves of that were live fail-opens, measured on the committed gate:
    #     git -C '../Primary' <disarm>      ALLOW  the token keeps its leading quote, so GetFullPath
    #     git -C '<absolute>' <disarm>      ALLOW  turns even an ABSOLUTE path into a relative one
    #     git -C "<root with a space>" ...  ALLOW  truncated at the space, so a governed root whose path
    #                                              contains one stopped being seen at all
    # This is the ordinary spelling, not an evasion: this rule's own test file writes a single-quoted
    # argument two lines from the case it is testing.
    #
    # Finding the option in the MASK preserves a distinction that matters rather than collapsing it. A
    # `-C` inside a quoted VALUE is INERT -- git never sees it as a flag -- and the mask blanks it, which
    # is what stops a quoted config value containing `-C <x>` from nominating <x> as the repository. A
    # `-C` inside an INTERPRETER argument is EXECUTED and still counts, because Get-ScannableSegments
    # recurses into that argument and hands its contents back as their own line, unquoted.
    $cvals = @(Get-OptionValuesRaw $Line $mask '(?:^|\s)-C(?=\s)')
    if ($cvals.Count -gt 0) {
        $out += $cvals[0]
    } else {
        $cd = $null
        if ($Prefix -notmatch '(?:^|\s)(?:popd|cd\s+-(?:\s|$))' -and $Prefix -notmatch '[({]') {
            $cds = [regex]::Matches((Get-QuoteMask $Prefix), '(?:^|\s)(?:cd|pushd)(?=\s)')
            if ($cds.Count -eq 1) { $cd = Read-ArgAt $Prefix ($cds[0].Index + $cds[0].Length) }
        }
        $out += $(if ($cd) { $cd } else { $CwdRaw })
    }

    # ADDITIONAL, never instead of: see the note above. Same reader, because the same truncation applied
    # to all four and fixing one of four identical spellings is how this file's -- detach/-d denylist got
    # it wrong twice.
    $wt = @(Get-OptionValuesRaw $Line $mask '(?:^|\s)--work-tree(?:=|(?=\s))')
    if ($wt.Count -gt 0) { $out += $wt[0]; $out += $CwdRaw }
    $gwt = @(Get-OptionValuesRaw $Line $mask '(?:^|\s)GIT_WORK_TREE=')
    if ($gwt.Count -gt 0) { $out += $gwt[0]; $out += $CwdRaw }
    # --git-dir names the repo; the tree is its parent. Add both rather than reason about which.
    $gd = @(Get-OptionValuesRaw $Line $mask '(?:^|\s)--git-dir(?:=|(?=\s))')
    if ($gd.Count -gt 0) {
        $out += $gd[0]
        $out += (Join-Path $gd[0] "..")
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
# The blanking half of Get-ScannableSegments, factored out so rule 3c can produce the SAME scan text for
# a sub-slice of a line without owning a second copy of these four substitutions. Two copies of "which
# characters are inert" is precisely the drift that put five separately-disagreeing regexes in this file
# once already; there is one definition and both callers use it.
function ConvertTo-ScanText([string]$Line) {
    # A quoted PROGRAM path must keep its git token -- `"C:\Program Files\Git\bin\git.exe" checkout main`
    # is a real spelling and blanking it wholesale would be a false NEGATIVE. Collapse that form to a bare
    # token first, then blank every remaining quoted span.
    $s = $Line -replace '"[^"]*[\\/](git(?:\.exe)?)"', '$1'
    $s = $s -replace "'[^']*[\\/](git(?:\.exe)?)'", '$1'
    $s = $s -replace '"[^"]*"', '""'
    $s = $s -replace "'[^']*'", "''"
    return $s
}

# A LENGTH-PRESERVING mask over quoted spans: nothing moves, so an offset found in the mask indexes the
# SAME character in the raw text and a caller can locate a token and then read its value back out of the
# original. ConvertTo-ScanText cannot do this job -- it rewrites a double-quoted span to an empty one,
# which shortens the string and makes every offset past it meaningless.
#
# $Filler replaces the CONTENT of a masked span; the quote characters themselves always become spaces,
# so the span stays a token boundary. $KeepBareWords leaves the content of a span that holds a SINGLE
# BARE WORD visible -- no whitespace, quotes, separators, parentheses or `$` (BACKLOG #1069). Prose has
# spaces and stays masked; a quoted config KEY does not, and is seen.
function Get-MaskedText([string]$Text, [char]$Filler, [switch]$KeepBareWords) {
    $sb = [System.Text.StringBuilder]::new($Text.Length)
    $i = 0
    while ($i -lt $Text.Length) {
        $ch = $Text[$i]
        if ($ch -eq '"' -or $ch -eq "'") {
            $end = $Text.IndexOf($ch, $i + 1)
            if ($end -lt 0) {
                # Unterminated quote: mask the remainder rather than guess where it would have closed.
                [void]$sb.Append(([string]$Filler) * ($Text.Length - $i))
                break
            }
            $content = $Text.Substring($i + 1, $end - $i - 1)
            [void]$sb.Append(' ')
            if ($KeepBareWords -and $content.Length -gt 0 -and $content -notmatch '[\s''"`$()&|;]') {
                [void]$sb.Append($content)
            } else {
                [void]$sb.Append(([string]$Filler) * $content.Length)
            }
            [void]$sb.Append(' ')
            $i = $end + 1
        } else {
            [void]$sb.Append($ch)
            $i++
        }
    }
    return $sb.ToString()
}

# The mask for LOCATING a token: every quoted span becomes spaces.
function Get-QuoteMask([string]$Text) { return Get-MaskedText $Text ' ' }

# The mask for deciding whether a DISARM KEY is present (BACKLOG #1069). Rule 3c matched the key against
# the scan string, which blanks every quoted span, so QUOTING THE KEY ERASED IT before the danger list
# ran. Six spellings were measured ALLOW on the committed gate, including a `-c <key>=<value>` override
# in both quoting styles and a quoted key argument to the `config` subcommand.
#
# Matching the RAW text instead is not the fix: it refuses a commit message that quotes the rule's own
# name, which is a shape this workstream writes constantly. A bare-word span is unmasked and prose is
# not, which separates the two.
#
# THE FILLER IS DELIBERATELY NOT WHITESPACE. An erased span made of spaces lets `-c\s+` step straight
# over it and bind to whatever token follows, which would invent matches that are not there. \x01 cannot
# appear in a key and cannot be crossed by `\s+`.
function Get-KeyScanText([string]$Text) { return Get-MaskedText $Text ([char]1) -KeepBareWords }

# Read the ARGUMENT that begins at or after $Index in the RAW text, the way a shell would: leading
# whitespace is skipped, a QUOTED argument yields its contents with the quotes stripped and any spaces
# kept, and a BARE one runs to the next whitespace or command separator. `x&&y` is `x` followed by a
# separator in every shell, so stopping there is not a shortcut.
#
# $Index is meant to come from a match against Get-QuoteMask's output. That only works because the mask
# is length-preserving: the offset means the same character in both strings.
function Read-ArgAt([string]$Text, [int]$Index) {
    $i = $Index
    while ($i -lt $Text.Length -and [char]::IsWhiteSpace($Text[$i])) { $i++ }
    if ($i -ge $Text.Length) { return "" }
    $ch = $Text[$i]
    if ($ch -eq '"' -or $ch -eq "'") {
        $end = $Text.IndexOf($ch, $i + 1)
        if ($end -lt 0) { return "" }          # unterminated quote: read nothing rather than guess
        return $Text.Substring($i + 1, $end - $i - 1)
    }
    $end = $i
    while ($end -lt $Text.Length -and -not ([char]::IsWhiteSpace($Text[$end]) -or $Text[$end] -in @('&', '|', ';'))) {
        $end++
    }
    return $Text.Substring($i, $end - $i)
}

# Every value of an OPTION on this line: the option token is located in the length-preserving $Mask, so a
# spelling of it inside a quoted argument is inert, and the value is then read out of the RAW $Line at
# the same offset. $Pattern must END where the value begins -- use a lookahead for the space-separated
# form and consume the `=` for the attached one.
function Get-OptionValuesRaw([string]$Line, [string]$Mask, [string]$Pattern) {
    $out = @()
    foreach ($m in [regex]::Matches($Mask, $Pattern)) {
        $v = Read-ArgAt $Line ($m.Index + $m.Length)
        if ($v) { $out += $v }
    }
    return $out
}

# Split a scan line into the individual COMMAND INVOCATIONS it chains together, at UNQUOTED `&&`, `||`,
# `;` and `|` (BACKLOG #1065). Rule 3c judged a whole line at once, and two fail-opens came straight out
# of that: a `-C` belonging to a DIFFERENT command on the line became "the repository being configured"
# (`git commit -C HEAD && git config core.hooksPath /nope` -- ALLOWED), and a neighbouring READ armed the
# rule's own read exclusion for the write beside it (`git config --list && git config core.hooksPath
# /nope` -- ALLOWED). Both are ordinary spellings; neither needs intent.
#
# Each piece carries the text BEFORE it as its Prefix, so a `cd` in an earlier invocation still counts as
# the prefix of a later one -- `cd <x> && git config ...` must keep resolving against <x>.
#
# The separators are found in the QUOTE MASK, so a `;` or `&&` inside a quoted argument does not split a
# command in two. Alternation order matters: `&&` and `||` are listed before the single `|` so a `||` is
# never read as two empty pipes.
function Split-Invocations([string]$Line) {
    $mask = Get-QuoteMask $Line
    $out = @()
    $start = 0
    foreach ($m in [regex]::Matches($mask, '&&|\|\||;|\|')) {
        $out += [pscustomobject]@{
            Text   = $Line.Substring($start, $m.Index - $start)
            Prefix = $Line.Substring(0, $start)
        }
        $start = $m.Index + $m.Length
    }
    $out += [pscustomobject]@{ Text = $Line.Substring($start); Prefix = $Line.Substring(0, $start) }
    return $out
}

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
        [pscustomobject]@{ Raw = $line; Scan = (ConvertTo-ScanText $line) }
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

# Rule 3c's target resolution, in ONE place (BACKLOG #1061). Every caller that has to answer "which
# repository would this configure?" goes through here, so the two steps can never drift apart again:
#
#   1. ROOT THE TOKEN AGAINST THE SESSION cwd. A relative target must resolve against where the SESSION
#      stands, not where this hook process happens to have been started. Get-FullPathRaw and NOT
#      Get-ComparablePath: the rooted path is handed to `git -C`, and a lowercased path passes on Windows
#      while silently missing the real directory on a case-sensitive filesystem.
#   2. ASK GIT WHERE THE REPOSITORY IS, and ask for the answer ALREADY ABSOLUTE.
#      `--path-format=absolute --git-common-dir` (git 2.31+) does BOTH jobs in one call, and the second
#      one is not cosmetic: git resolves path ALIASES itself. A junction to the primary was measured
#      ALLOW because `--git-common-dir` answers the bare string ".git" from a main working tree, and
#      [IO.Path]::GetFullPath does not traverse a reparse point -- so the composed path kept the junction
#      spelling and matched no governed root. Asked this way git answers with the real directory and the
#      junction denies. Measured on git 2.53: leaf junction, drive-letter case, trailing slash and `/./`
#      all normalise to one canonical path. `\\localhost\C$` does NOT (BACKLOG #1071, still open here).
#
# THE THREE OUTCOMES ARE DISTINCT AND ARE ANSWERED DIFFERENTLY -- collapsing any two is how this rule
# shipped open:
#   Unresolvable = $true   the token could not be made absolute at all. Nothing has been asked of git, so
#                          nothing has said this is or is not governed. The caller DENIES.
#   CommonCmp = ""         git ANSWERED and the answer was "not a repository". The caller ALLOWS.
#   Root                   the governing allowlist entry, or $null for an ungoverned repository.
function Resolve-ConfigTarget([string]$TargetRaw, [string]$CwdRaw) {
    $rooted = Get-FullPathRaw $TargetRaw $CwdRaw
    if (-not $rooted) {
        return [pscustomobject]@{ Raw = $TargetRaw; Rooted = ""; CommonCmp = ""; Root = $null; Unresolvable = $true }
    }

    $common = "$(& git -C $rooted rev-parse --path-format=absolute --git-common-dir 2>$null)".Trim()
    if ($LASTEXITCODE -ne 0 -or -not $common) {
        # git before 2.31 has no --path-format, and an unknown option is exit 129 -- indistinguishable
        # here from "not a repository", which is why the plain form is retried rather than assumed. It
        # answers RELATIVE TO THE TARGET (".git" from a main working tree), so it is rooted against the
        # target and NOT against the session cwd: ".git" resolved against the session would name a real
        # path that is not this repository's common dir, and the rule would read as fixed and stay open.
        $common = "$(& git -C $rooted rev-parse --git-common-dir 2>$null)".Trim()
        if ($LASTEXITCODE -ne 0 -or -not $common) {
            return [pscustomobject]@{ Raw = $TargetRaw; Rooted = $rooted; CommonCmp = ""; Root = $null; Unresolvable = $false }
        }
        $common = Get-FullPathRaw $common $rooted
        if (-not $common) {
            return [pscustomobject]@{ Raw = $TargetRaw; Rooted = $rooted; CommonCmp = ""; Root = $null; Unresolvable = $false }
        }
    }

    # BOTH SIDES go through the admin-share rewrite (BACKLOG #1071). Doing only the candidate side would
    # close the spelling that was measured and leave its mirror -- an allowlist entry written in the UNC
    # form -- silently governing nothing.
    $cmp = ConvertFrom-LocalAdminShare (Get-ComparablePath $common)
    $root = $null
    foreach ($r in $roots) {
        $rc = ConvertFrom-LocalAdminShare $r.Compare
        if ($cmp -eq $rc -or $cmp.StartsWith("$rc/")) { $root = $r; break }
    }
    [pscustomobject]@{ Raw = $TargetRaw; Rooted = $rooted; CommonCmp = $cmp; Root = $root; Unresolvable = $false }
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

    # And only a branch that is checked out NOWHERE. The deny text below asserts exactly that ("git
    # allowed it because '$dest' was not checked out anywhere") -- an assertion this rule never actually
    # made, which is a compensating control resting on an unverified premise. Two things follow from
    # checking it. If the branch IS checked out somewhere, git's own guard refuses the switch without
    # us, so there is nothing to protect; and the remediation would print `new.ps1 -Branch $dest`, which
    # dies with "fatal: '$dest' is already checked out at ...". That is the same defect class this
    # remediation was just fixed for -- a printed command the receiving side rejects. `git checkout main`
    # from any linked worktree is the common shape. $list is the porcelain already read above.
    #
    # BUT ONLY WITH NO FLAGS AT ALL, and that is an ALLOWLIST on purpose. "git already refuses this" is
    # a claim about a CONFIGURATION, not about git: a guard you do not own can be switched off by its
    # own caller. Measured against a branch live in another worktree --
    #     checkout/switch <b>                        -> fatal, git refuses      (deferring is sound)
    #     checkout/switch --force / --discard-changes -> fatal                  (deferring is sound)
    #     checkout/switch --ignore-other-worktrees <b> -> SWITCHES              (guard disabled)
    #     checkout/switch --detach <b>, and -d <b>    -> SWITCHES               (never takes the lock,
    #                                                    but still swaps the other session's files)
    # -- and the dest scanner above skips '-'-prefixed tokens, so every one of those still resolves
    # $dest normally. A denylist was written twice here and was wrong twice: --detach was missed while
    # fixing --ignore-other-worktrees, and `-d` would have been missed while fixing --detach. Git may
    # add a third tomorrow and the gate would silently reopen. So: any flag present means DENY. The cost
    # is a needless deny on `git checkout --quiet main`, whose remediation line is then the imperfect
    # one; that is strictly better than a missed hijack, and unlike a flag list it does not decay.
    $hasFlag = @($after -split '\s+' | Where-Object { $_ -and $_.StartsWith('-') }).Count -gt 0
    if (-not $hasFlag -and ($list -contains ("branch refs/heads/" + $dest))) { return }

    $newHint = "$($gov.Display)\scripts\worktree\new.ps1"
    $destSlug = ConvertTo-WorktreeSlug $dest
    # Doubled for the SINGLE-quoted emission below. A refname is not a safe shell token: `git
    # check-ref-format` accepts ';', '$', '|', '"' and "'" (all measured exit 0), and line ~349 trims
    # quotes only at the ENDS, so an interior one survives. Without the doubling, a legal branch named
    # `x';calc;#` emits a line that PARSES AS TWO STATEMENTS -- the second being whatever follows the
    # quote, with '#' commenting out the remainder. That is command injection into text this very
    # message tells an agent to run. $destSlug needs no such care: it is [A-Za-z0-9._-]+ by construction.
    $destQ = $dest -replace "'", "''"
    Write-Deny -Rule "3b" -Detail "git $Verb -> $selfTopRaw" -Reason @"
BLOCKED: 'git $Verb $dest' would switch a LINKED WORKTREE ($selfTopRaw) onto the existing branch '$dest'.

That worktree belongs to another session, which is building on '$head' right now. Switching it swaps every
file under that session mid-task -- silently -- and drags two sessions' work onto one branch. This is not
hypothetical: it is exactly the hijack that happened here. A session with no worktree of its own ran a
`git checkout` inside somebody else's worktree; git allowed it because '$dest' was not checked out anywhere.

What to do instead:
  * To BUILD on '$dest', give it its OWN worktree -- git then refuses to check that branch out twice,
    which is the protection you actually want. The branch already EXISTS, so this REUSES it rather than
    forking. -Branch is the git ref; -Name is only the DIRECTORY, which cannot contain '/':
        pwsh -NoProfile -File "$newHint" -Branch '$destQ' -Name $destSlug
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
    $gitToken = '(^|[\s;&|(''"\\/])git(\.exe)?["'']?(\s|$)'
    $keyMatch = "(?:\bconfig\b[^|;&]*?\s|-c\s+)(?<key>$dangerKeys)"
    $readOnly = '(?:^|\s)--(get|get-all|get-regexp|list|show-origin)(\s|$)'
    foreach ($seg in (Get-ScannableSegments $cmd)) {
        # Cheap pre-filter on the whole line, kept because everything below it costs more: a line with no
        # git token or no disarm key anywhere in it cannot produce a hit from any of its invocations.
        # The git-token half runs on the scan string (cheapest); the key half must use the KEY SCAN, or a
        # quoted key would be erased here and never reach the per-invocation check below.
        if ($seg.Scan -cnotmatch $gitToken) { continue }
        if ((Get-KeyScanText $seg.Raw) -notmatch $keyMatch) { continue }

        # THEN JUDGE EACH INVOCATION ON ITS OWN (BACKLOG #1065). Reading the whole line as one command was
        # two fail-opens, both reachable with an ordinary flag and no intent:
        #   git commit -C HEAD && git config core.hooksPath /nope   -> ALLOWED. `-C HEAD` is the ordinary
        #     reuse-that-commit's-message flag and belongs to a DIFFERENT command, but it was read as the
        #     repository being configured; it resolves to a non-repo, git exits 128, and the git-failure
        #     fail-open swallowed the write.
        #   git config --list && git config core.hooksPath /nope    -> ALLOWED. The read exclusion is a
        #     property of ONE invocation and was applied to the line, so a neighbouring read disarmed the
        #     rule for the write beside it.
        # Both now resolve against the invocation that actually carries the write.
        foreach ($inv in (Split-Invocations $seg.Raw)) {
            $invScan = ConvertTo-ScanText $inv.Text
            if ($invScan -cnotmatch $gitToken) { continue }
            if ((Get-KeyScanText $inv.Text) -notmatch $keyMatch) { continue }
            $badKey = $Matches['key']
            # A read is not a write -- and this one stays on the FULLY masked view on purpose. Reading it
            # off the key scan would let a quoted VALUE of `--get` disarm the exclusion for the write
            # beside it, which is the same shape as the defect above with the sign reversed.
            if ($invScan -match $readOnly) { continue }

            $at = [regex]::Match($inv.Text, $gitToken)
            $pfx = $inv.Prefix + $(if ($at.Success) { $inv.Text.Substring(0, $at.Index) } else { "" })
            $where = @(Get-GitTargetCandidatesRaw $inv.Text $pfx $cwdRaw)
            if ($where.Count -eq 0) { continue }

            # ROOT THE TARGET AGAINST THE SESSION CWD BEFORE ASKING GIT ANYTHING (BACKLOG #1061). This
            # block used to read `& git -C $where[0]` and `Get-ComparablePath $common $where[0]`, and with
            # a RELATIVE target it failed OPEN. Measured on the installed hook by two sessions
            # independently:
            #     git -C <primary-absolute> config core.hooksPath /dev/null   -> DENIED
            #     git -C ../../..           config core.hooksPath /dev/null   -> ALLOWED
            #     cd ../../.. && git        config core.hooksPath /dev/null   -> ALLOWED
            # `../../..` is simply how a session in <primary>/.claude/worktrees/<x> names the repo root.
            # It needs no variable and no intent, and it disarms the ledger, claim and secret-leak commit
            # gates for every worktree at once -- verbatim what the deny text below says this rule stops.
            #
            # THE MECHANISM WAS A BASE THAT IS NOT A BASE. `rev-parse --git-common-dir` answers RELATIVE
            # TO THE TARGET: from the PRIMARY it returns the bare string ".git"; from a linked worktree it
            # returns an absolute path. Get-ComparablePath then resolved ".git" against $where[0] -- the
            # target token AS WRITTEN -- and GetFullPath demands a fully qualified base, so it threw, the
            # catch returned "", no root matched "", and the rule allowed. The hole was scoped to the
            # primary precisely BECAUSE only the primary answers relatively, which is also why the crux
            # test (disarming FROM a linked worktree) stayed green straight over it.
            #
            # AND THE ROOTED PATH GOES TO `git -C` TOO, not only into the comparison. `& git -C
            # <relative>` resolved against THIS HOOK PROCESS's cwd, which is not the session's -- so a
            # relative target naming a LINKED worktree made git exit 128 and fall through to ALLOW as
            # well. Both steps now live in Resolve-ConfigTarget, which also states why an UNRESOLVABLE
            # target denies while git ANSWERING "not a repository" allows.
            #
            # EVERY CANDIDATE IS CHECKED, NOT JUST THE FIRST (BACKLOG #1065). Get-GitTargetCandidatesRaw's
            # own contract says so -- "It returns a SET, not a winner, and the caller denies if ANY member
            # is governed" -- and rule 3c was the one consumer that took [0] and stopped, while rule 3 at
            # the bottom of this file had always iterated. A `--git-dir` or `--work-tree` naming a
            # governed repository from an ungoverned cwd sat in the tail of that set and was never looked
            # at: `git --git-dir "<primary>/.git" config core.hooksPath /x` was ALLOWED, measured.
            #
            # A GOVERNED ANSWER OUTRANKS AN UNRESOLVABLE ONE. Both are deny-side, so the order only
            # decides which message is printed -- and naming the repository is strictly more useful than
            # reporting that a sibling token could not be resolved.
            $hits = @($where | ForEach-Object { Resolve-ConfigTarget $_ $cwdRaw })
            $t = @($hits | Where-Object { $_.Root })[0]
            if (-not $t) {
                $bad = @($hits | Where-Object { $_.Unresolvable })[0]
                if (-not $bad) { continue }
                Write-Deny -Rule "3c" -Detail "git config $badKey (unresolvable target)" -Reason @"
BLOCKED: this sets '$badKey', and the gate cannot tell WHICH repository it would set it in.

The target path '$(Get-SafeForMessage $bad.Raw)' could not be resolved to an absolute path from this
session's working directory ('$(Get-SafeForMessage $cwdRaw)'), so the check that would normally answer
"is this the shared configuration of a governed checkout?" cannot run at all.

'$badKey' is on the disarm list: setting it in a governed repository turns off the ledger, claim and
secret-leak commit gates for every worktree of it at once. An unanswerable question about that key is
refused rather than assumed safe.

What to do instead:
  * Re-run it with an ABSOLUTE path for the target (`git -C "<full path>" config ...`). Then the gate can
    see which repository is being configured, and an ordinary non-governed repo is allowed as usual.
  * Ordinary per-user config (user.email, user.name, and anything not on the disarm list) is untouched by
    this rule in any spelling.
"@
            }

            $govCfg = $t.Root
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
    }

    # -----------------------------------------------------------------------------------------------
    # Rule 3d -- `git worktree remove` / `move`, which DESTROYS OR RELOCATES ANOTHER SESSION'S CHECKOUT.
    # Every rule above protects a tree from being swapped; this one protects it from being deleted, which
    # is strictly worse and was entirely unguarded. The verb list could never have caught it: `worktree`
    # is two tokens (`worktree remove`) where every other entry is one.
    #
    # THIS RULE ONCE JUSTIFIED HAVING NO CWD CHECK WITH "git refuses to remove the worktree you are
    # STANDING in, so a remove that reaches git is aimed at somebody else's". THAT INFERENCE IS
    # UNREACHABLE FROM HERE (BACKLOG #1041). A PreToolUse hook decides whether anything reaches git at
    # all, so git's refusal never happens and the premise is never tested -- a rule cannot defer to a
    # guard that runs only after it has already decided. Reproduced: a session standing in a linked
    # worktree ran `git worktree remove <that same path>` and was told the tree belonged to ANOTHER
    # SESSION, then sent to confirm with a colleague who does not exist.
    #
    # So the cwd check is now made rather than argued for, just below. It is narrow on purpose: it
    # establishes "this IS the tree you are standing in", which is the one ownership fact available
    # here. It does NOT establish the converse -- a worktree that is not yours to stand in may still be
    # nobody's, and this rule has no occupancy or authorship signal to tell those apart. The deny text
    # below says only what is checked.
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

        # Is the victim the tree THIS session is standing in? $victimCmp above is the shared COMMON git
        # dir -- every worktree of one repo reports the same value, so it cannot answer this. Resolve
        # both TOPLEVELS instead. A git failure leaves $isSelf false, which keeps the pre-existing text.
        #
        # $cwdRaw, NEVER $cwd. $cwd is the Get-ComparablePath form, which is LOWERCASED, and this file
        # already warns at the top of the rule-3b resolver that every `git -C` must take the raw path:
        # on a case-sensitive filesystem `git -C /tmp/.../primary-wt` misses the real `.../Primary-wt`.
        # Written with $cwd first, it passed on Windows (case-insensitive) and failed on the Linux CI
        # leg, where the lookup returned nothing, $isSelf went false, and BOTH branches emitted the
        # generic deny -- byte-identical, which is exactly what the non-vacuity test below asserts
        # against. Platform-masked, and caught only because that test compares the two denies.
        $victimTopRaw = "$(& git -C $victimRaw rev-parse --show-toplevel 2>$null)".Trim()
        if (-not $victimTopRaw) { $victimTopRaw = $victimRaw }
        $victimTop = Get-ComparablePath $victimTopRaw
        $selfTop = Get-ComparablePath "$(& git -C $cwdRaw rev-parse --show-toplevel 2>$null)".Trim()
        $isSelf = $victimTop -and $selfTop -and ($victimTop -eq $selfTop)

        # WHICH FAMILY IS THE VICTIM IN? The remedy has to be one that can actually reach it, and until
        # now neither of the two this rule named could (BACKLOG #1057):
        #
        #   * `remove.ps1 -Name <dir>` resolves to <repo-parent>/<repo-leaf>-<dir>. new.ps1 ASSERTS that
        #     shape after deriving it, so the <primary>-<name> sibling family is the only one it can
        #     produce and the only one remove.ps1 can resolve; handed anything else it fails Test-Path
        #     and throws "No such worktree".
        #   * `prune-merged.ps1` excludes anything with a `.claude/worktrees/` path segment OUTRIGHT --
        #     its own header says so, and -Name cannot reach them either. That exclusion is deliberate:
        #     those are the trees a live session gets relocated into.
        #
        # Census on this clone 2026-08-06: 45 sibling worktrees, 8 Claude-managed, 4 other -- and every
        # live session sat in the 8. So the refused caller was reliably handed a command that throws and
        # a tool that reports nothing about their tree. Same defect as #1032, one rule over: there, rule
        # 3b printed a new.ps1 command new.ps1 refuses to run. A refusal the reader cannot act on is the
        # standing invitation to route around the guard, which costs more than the refusal buys.
        #
        # THIS BRANCHES THE REMEDY STRING ONLY. Which worktrees rule 3d refuses is untouched, and no
        # security decision reads $isSibling -- which is what makes a misclassification cheap here and
        # not in rule 3c. FAILURE DIRECTION, pinned by test rather than asserted: a junction or UNC
        # spelling breaks the prefix match, classifies NOT-sibling, and the not-sibling remedy is a
        # literal `git worktree remove <abs path>` that is valid for EVERY family, siblings included.
        # The dangerous direction needs a non-sibling to SPURIOUSLY match `<primary>-<name>`, which an
        # unresolved alias makes less likely rather than more.
        $govLeaf = Split-Path $govWt.Display -Leaf
        $sibPrefix = "$($govWt.Compare)-"
        $isSibling = $victimTop -and $victimTop.StartsWith($sibPrefix) -and
                     -not $victimTop.Substring($sibPrefix.Length).Contains('/')
        # NAME the directory rather than printing `<directory-name>`. The gate has just resolved the
        # path; leaving the caller to substitute a placeholder into a command is a second chance to get
        # it wrong, and it is the reason the own-tree branch was unrunnable for the sibling family too.
        $sibName = if ($isSibling) { (Split-Path $victimTopRaw -Leaf).Substring($govLeaf.Length + 1) } else { $null }
        $removeCmd = if ($isSibling) {
            "pwsh -NoProfile -File $($govWt.Display)\scripts\worktree\remove.ps1 -Name $sibName"
        }
        else {
            "git -C `"$($govWt.Display)`" worktree remove `"$victimTopRaw`""
        }
        # The sibling family KEEPS prune-merged.ps1 and that is not politeness: it is dry-run by default,
        # it consults occupancy, and it re-reads its fence immediately before each removal. For the family
        # it covers it is strictly better than a bare `git worktree remove`, so the fix must not become
        # "stop naming the scripts" -- a test pins that it is still offered here.
        $cleanupBullet = if ($isSibling) {
            @"
  * Cleaning up merged worktrees is a maintenance job with its own dry-run-by-default tool. Run it and
    READ what it proposes before applying anything:
        pwsh -NoProfile -File $($govWt.Display)\scripts\worktree\prune-merged.ps1
"@
        }
        else {
            @"
  * prune-merged.ps1 CANNOT help with this one, so do not reach for it: it skips anything under
    .claude/worktrees and anything that is not a <repo>-<name> sibling, by design, and its -Name cannot
    reach them either. If this tree really must go, that is the user's call and this is the command --
    it is not yours to run:
        $removeCmd
"@
        }

        if ($isSelf) {
            Write-Deny -Rule "3d" -Detail "git worktree $wtVerb (own worktree)" -Reason @"
BLOCKED: 'git worktree $wtVerb $victimRaw' acts on THE WORKTREE THIS SESSION IS RUNNING IN.

This is not somebody else's tree and nothing here says it is. git would refuse it too -- you cannot remove
the worktree you are standing in -- but this gate runs BEFORE git, so you would have got a confusing
failure from the hook rather than a clear one from git.

There is no version of this you can run from here. Removing your own checkout mid-session deletes the
files you are working on, and the removal has to happen from OUTSIDE this tree, after the session ends.

What to do instead:
  * Finish and COMMIT anything you still want. A commit survives the tree being deleted; a dirty tree
    does not.
  * Then ask the user, in these words: "I am finished in $victimRaw and it can be removed once this
    session ends." Removal is theirs to run from OUTSIDE this tree:
        $removeCmd
  * If you only wanted to leave it, just stop using it -- an unused worktree costs disk, not correctness.
"@
        }
        else {
            Write-Deny -Rule "3d" -Detail "git worktree $wtVerb" -Reason @"
BLOCKED: 'git worktree $wtVerb $victimRaw' acts on a worktree of $($govWt.Display) that is NOT the tree
this session is running in. This gate cannot tell whether another session is using it -- it has no
occupancy or authorship signal -- so it refuses rather than guess.

If it IS in use, removing it deletes that session's working tree and its branch, along with any
uncommitted work in them. There is no undo, and the session using it finds out when its next file read
fails. That asymmetry is why the default is refusal even though the tree may well be abandoned.

What to do instead:
$cleanupBullet
  * To find out whether a worktree is still in use, look rather than delete:
        git -C "$($govWt.Display)" worktree list
  * If you are certain it is abandoned and must go now, that is the user's call, not yours. Say so:
    "I want to remove the worktree $victimRaw and I need you to confirm it is not in use."
"@
        }
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
            # exactly where the Claude Code harness puts a worktree (new.ps1 makes SIBLINGS at
            # <repo-parent>\<repo-name>-<Name>; BOTH layouts are live here), so `cd <own worktree> &&
            # git rebase ...` -- the
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
#
# ANOTHER GATE DEPENDS ON THIS ONE, and not for the reason the rest of this file talks about. Elsewhere the
# relationship is that this hook PROTECTS the ledger gate's inputs -- rule 3c refuses a core.hooksPath
# repoint, rule 1b refuses a write to alloc/. This is different and it runs the other way: the ledger gate's
# ownership check keys on the WORKTREE that allocated a number (scripts/hooks/ledger_check.py owns()), and
# that key is only meaningful because rule 1 makes each session build somewhere of its own. Before this gate
# existed the key was MEASURED broken -- co-tenant sessions in the shared primary all mapped to one worktree,
# so the check was a no-op between exactly the sessions it was meant to separate. See
# docs/LEDGER-GATE.md, "Ownership keying -- and why it works now": the two gates are a pair.
#
# WHY IT IS WRITTEN HERE rather than only there. That document states the dependency from the DEPENDENT's
# side, which is invisible from the side that can break it -- and breaking it does not look like breaking a
# gate. Widening what rule 1 governs disarms no hook and fails no test; it quietly turns owns() back into a
# no-op for the newly-ungoverned paths, and the ledger then merges clean and corrupts silently, which is the
# defect that registry exists to prevent (measured 3x: d1d0a5a, 5b7d046, 9f3483d). This is not hypothetical:
# the first cut of rule 1b's exemption widened rule 1 to the whole of .git/mefor-coord/ and exposed
# alloc/<kind>/<n>.json, so a Write could forge an allocation owns() would then authorise. It was caught by
# an adversarial review, not by any gate. So if you are about to widen this rule, that is the cost to price.
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
BLOCKED: this writes to the worktree gate's own enforcement surface ($(Get-SafeForMessage $target)).

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

# ---------------------------------------------------------------------------------------------------
# Rule 1's ONE EXEMPTION -- <primary>/.git/mefor-coord/, the cross-session coordination state.
#
# Rule 1 says its subject is the primary's WORKING TREE, but it decides that by prefix-matching the
# primary's path STRING, and for one whole subtree those are different questions with different answers:
# nothing under <primary>/.git/ is in the working tree at all, because git forbids a tracked path
# component named `.git`. So the sessions writing exactly where they are DESIGNED to write -- announce
# delivery receipts at .git/mefor-coord/announce/sent/<session-id>.tsv, and the coordination handoff
# documents beside them, in the git COMMON dir all 46 worktrees share -- were refused by the rule that
# protects the tree those files are not in.
#
# Measured from this gate's own deny log (~/.claude/hooks/worktree-gate.log) on 2026-08-05: rule 1 had
# fired 18 times since it started keeping receipts, and HALF of those firings were this one false positive
# -- 9 Write denies on .git/mefor-coord/ paths, from 7 DISTINCT worktrees, 2026-08-02..2026-08-05. A
# count, not an intuition, the same way the 29% in the docstring above is what keyed this gate to the
# target path instead of the cwd. Read the RATIO and not the count: both numbers are live and still
# climbing (a 9th record arrived while this fix was under review). And it was never only the receipts --
# only 3 of the 9 were announce receipts; the rest were handoff documents, some at the state root and some
# under handoff/, under names nobody could have enumerated in advance. The whole state ROOT was
# unreachable, so an allowlist of filenames would have re-broken the next one.
#
# NARROWED TO mefor-coord/ ALONE -- never the common dir, never all of .git/. core.hooksPath is UNSET in
# this repo, which makes <primary>/.git/hooks/ the LIVE hook directory for every worktree at once: a
# Write to .git/hooks/pre-commit disarms the commit-time ledger, claim and secret-leak gates for every
# session on this machine, which is the exact blast radius rule 3c refuses for the `git config
# core.hooksPath` spelling of the same move. Rule 1's over-broad prefix is what blocks the ORDINARY
# drive-letter spelling of that write, and no other rule blocks it at all -- so exempting .git/ wholesale
# would trade a false positive for a hole. .git/config and every other path under .git/ therefore stay
# denied, and the trailing separator is required so a sibling named .git/mefor-coordX cannot match its
# way in.
#
# THAT LAST SENTENCE IS NOT A GUARANTEE, and it was measured, so state the limit here rather than let the
# next reader infer a stronger one. The prefix match is LEXICAL -- [System.IO.Path]::GetFullPath never
# touches the filesystem -- and it covers the drive-letter spelling only. Two other spellings of the SAME
# target are allowed today: an extended-length \\?\C:\... or a UNC admin-share \\localhost\C$\... path
# normalises to //?/c:/... or //localhost/c$/... , which matches no root at all (verified against this
# hook, both spellings live on this box); and a reparse point created INSIDE this exempt subtree keeps the
# exempt prefix while the write lands wherever the junction points. Both are PRE-EXISTING, both apply to
# every governed path and not just .git/, and both need a SHELL command to set up -- which is the route the
# docstring already says this gate cannot see, so neither is an escalation and neither argues for widening
# or narrowing the exemption. Closing them means folding both prefixes in Get-ComparablePath, which moves
# rules 3/3b/3c/3d too and belongs in its own change with its own tests.
#
# IT LIVES IN RULE 1 AND NOT IN Test-Governed, even though its shape is identical to the
# .claude/worktrees/ exemption already sitting there. Rule 3 feeds the SESSION'S cwd through
# Test-Governed, and `cd <primary>/.git/mefor-coord && git reset --hard` resolves GIT_DIR to the primary
# and swaps the shared working tree -- exempting this path inside Test-Governed would open that bypass to
# buy back a write. Rule 1 judges a WRITE TARGET, so only rule 1 gets the carve-out. The public fork of
# this gate reached the same split from the other direction: it carries a separate Test-GovernedSharedDir
# for rules 3c/3d precisely because the .claude/worktrees/ exemption gives the wrong answer once the blast
# radius is the shared .git.
#
# Matched on the ALREADY-CANONICALISED target, so a traversal back out of the exempt subtree --
# <primary>/.git/mefor-coord/../../messagefoundry/api/app.py -- resolves into the working tree and still
# denies (verified, along with the ./.. and x/../.. spellings). Get-ComparablePath returns "" on a path it
# cannot resolve, which matches nothing here and falls through to Test-Governed, i.e. to the behaviour this
# block did not exist to change.
# ---------------------------------------------------------------------------------------------------
# Rule 1b -- the MACHINE-READ state inside that exemption, which stays denied.
#
# mefor-coord/ is not inert data, and describing it as "the cross-session coordination state" invites
# exactly that reading. At least three of this repo's own gates read files in here as AUTHORITY, and each of
# them decides from ONE field or ONE file's existence, so a hand-written copy is indistinguishable from a
# real one:
#
#   alloc/<kind>/<n>.json         ledger_check.py owns() authorises an ADR/BACKLOG number by comparing the
#                                 `worktree` field ALONE, so a written file IS an allocation -- which
#                                 re-opens the clean-merging ledger corruption measured 3x (d1d0a5a,
#                                 5b7d046, 9f3483d) that this registry exists to prevent. Nothing
#                                 downstream catches the forgery either: --ci skips the rule outright
#                                 (`elif not self.ci and not self.owns(...)`).
#   alloc/*/.floor-highwater      two ONE-WAY ratchets. alloc.ps1's Get-Floor takes Max(computed,
#   alloc/*/.boundary-highwater   previous) forever -- its own comment records this happening by accident,
#                                 ratcheting a clone from 316 to a fabricated 990 no later run could undo
#                                 -- and a boundary above the constant makes alloc.ps1 REFUSE TO ALLOCATE
#                                 for every session in the clone, with a printed remedy that sends the
#                                 operator to edit PUBLIC_BACKLOG_FLOOR in source.
#   claims/<item>.json            claim_check.py compares `worktree` alone. A Write can name ANY worktree,
#                                 which claim.ps1 cannot -- it only ever writes its own repo and refuses to
#                                 overwrite a sibling's claim. So a Write does not merely forge a claim, it
#                                 TRANSFERS a live one, and the rightful holder's next -Take reports
#                                 "already claimed by another session": the exact duplicate build the
#                                 registry exists to stop.
#   overlap-cache.json            overlap.ps1 trusts it as data for 60s, bounded only against a future
#                                 stamp and a root mismatch. A `rows: []` payload makes collision_gate.ps1
#                                 read "RESOLVED, and nobody else is touching it" and ALLOW with no
#                                 additionalContext -- indistinguishable from a real all-clear, which is
#                                 the silent-green failure that gate was built to remove.
#   gate-unresolved/*.stamp       suppresses that gate's "could NOT check this edit" notice for 30 minutes.
#                                 Freshness is LastWriteTime, which a Write sets to now, so the existing
#                                 future-stamp bound does not see it.
#   locks/*.lock                  the cross-session mutex (Enter-CoordLock, scripts/coord/lock.ps1).
#   test-slots/*.lock             the pytest port-slot mutex (tests/conftest.py); a live PID written into
#                                 slots 0..N-1 saturates it for every concurrent test run on the box.
#   announce/OFF                  a documented REPO-WIDE kill switch -- announce-session.ps1 gates the
#                                 whole hook on its existence, so ONE Write stops every session announcing
#                                 itself, silently and with no receipt naming who did it. Same shape as
#                                 rule 1a's "one line written to the allowlist disarms the gate for every
#                                 session on this machine", and the reason that rule exists.
#
# This costs ZERO measured true positives: none of the 9 logged coord denies touches any of these (3 were
# announce receipts, the rest handoff documents), and every one of them is written by its own script
# through a shell call, which rule 1's tool set never observes. announce/ therefore stays exempt apart from
# the OFF switch -- announce/sent/ is where the hook itself tells the model to append its receipt.
#
# TWO MECHANISMS, AND THE ORDER MATTERS. The named list above exists for its REMEDY: it can tell a blocked
# session the one command that legitimately writes that registry, which a generic refusal cannot. But a list
# cannot carry a completeness claim -- see the backstop below, which is what actually makes this rule closed
# under addition, and which is there because this directory defeated enumeration twice in one review. Names
# for the error message, SHAPE for the guarantee. If you add a registry here, add it to the list so the
# refusal stays useful; the shape rule already denied it before you got there.
#
# ITS OWN DENY TEXT, not rule 1's. Rule 1 says "make a worktree and re-issue the edit there", and that
# remedy is WRONG here: these paths live in the git COMMON dir, so they are the SAME file seen from every
# worktree, and a session sent to try again in a fresh one would loop. A gate that misdescribes what it
# blocked trains people to route around it (rule 3's note above records that happening).
# ---------------------------------------------------------------------------------------------------
$targetCmp = Get-ComparablePath $target
foreach ($r in $roots) {
    $coordRoot = "$($r.Compare)/.git/mefor-coord/"
    # ORDINAL, EXPLICITLY, on both this match and the denylist's below. The one-argument
    # String.StartsWith overload compares under the CURRENT CULTURE, which SKIPS collation-ignorable
    # characters -- measured on this host, "<root>/.git/mefor-coord`u{200D}/evil".StartsWith("<root>/.git/
    # mefor-coord/") is True by default and False ordinally. Both operands are already casefolded and
    # slash-normalised by Get-ComparablePath, so ordinal is strictly what these comparisons already mean,
    # and the comment above earns the word "required" only under it. It matters most on rule 1b: a
    # culture-sensitive denylist decides membership of a SECURITY list by collation, which is not a
    # property anyone auditing this file would think to check.
    if (-not $targetCmp.StartsWith($coordRoot, [System.StringComparison]::Ordinal)) { continue }
    $rest = $targetCmp.Substring($coordRoot.Length)

    # CLASSIFY THE FILE THE WRITE LANDS ON, NOT THE SPELLING. `foo.json:bar.md` names an NTFS ALTERNATE
    # DATA STREAM of foo.json, and every classifier below would otherwise read the STREAM's name instead of
    # the file's: the single-file entries compare the whole remainder (`overlap-cache.json:x.md` is not
    # equal to `overlap-cache.json`, so the named list misses it) and GetExtension returns `.md`, so the
    # shape backstop then reads a registry as a document. The DIRECTORY entries (alloc/, claims/) survived
    # only because they match a path PREFIX, which a suffix does not disturb -- so the two spellings anyone
    # would test first were the two that looked fine.
    #
    # Measured, and not inert: `announce/OFF:x.md` and `overlap-cache.json:x.md` were both ALLOWED, and an
    # ADS write to a MISSING base CREATES the base with an empty default stream. announce-session.ps1 arms
    # its repo-wide kill switch on `Test-Path .../OFF` alone, so that one spelling silenced every session
    # in the repo through the rule added to prevent exactly that. What it could NOT do is forge alloc/ or
    # claims/ CONTENT, because an ADS write leaves the default stream untouched -- the reachable harm is
    # arming an existence-checked switch and squatting a name against an exclusive-create allocator.
    #
    # $rest is a REMAINDER, never a rooted path, so it carries no drive letter and the first colon can only
    # be a stream separator. Strip from there and judge the base: a registry keeps its real extension and
    # denies, while a stream on a genuine document stays a document.
    #
    # THE COLON IS ONE MEMBER OF A SET, AND THREE LAYERS COVER THE SET -- record which does what, because
    # they fail independently and this line is only one of them. Win32 maps MANY spellings onto ONE file:
    # measured on this box, `OFF.`, `OFF` with a trailing space, `OFF::$DATA` and `OFF:x.md` each create the
    # single file `OFF`, and announce-session.ps1 arms its kill switch on that file's existence alone.
    #
    #   trailing dot / trailing space  Get-ComparablePath ran GetFullPath first and canonicalisation ALREADY
    #                                  collapsed them -- `announce/OFF.` and `announce/OFF ` both arrive here
    #                                  as `announce/off`. They never reach this line and need not. This is
    #                                  PLATFORM behaviour, not ours, and .NET has changed trailing dot/space
    #                                  handling across versions: measured on pwsh 7.6.3 / .NET 10.0.9, twice,
    #                                  by two sessions independently. That is why the eight spelling tests
    #                                  exist rather than this comment alone -- if the runtime ever stops
    #                                  collapsing, they fail loudly and the failure reads as "the platform
    #                                  moved", which is diagnosable, instead of "the gate broke".
    #   a stream NOT named like a doc  the shape backstop below already denies it: GetExtension yields
    #                                  `.json::$data`, or nothing at all, and neither is in the allowlist.
    #                                  That covers `::$DATA`, the canonical default-stream alias.
    #   a stream named like a doc      THIS LINE, and only this line. `OFF:x.md` is the one spelling that
    #                                  flips to ALLOW when the strip is removed, because GetExtension then
    #                                  reports `.md` and the backstop waves it through.
    #
    # The split was MEASURED by reverting each layer, not reasoned about, and the first draft of this comment
    # got it wrong in the safe-looking direction: it credited the strip with the `::$DATA` cases, which it
    # does not cover. A control whose comment overstates which mechanism protects what is the compensating
    # control resting on a false premise that section 11 forbids -- doubly so when it flatters the code.
    #
    # So do NOT also trim trailing dots and spaces here. It would be dead code today and, worse, a SECOND
    # definition of canonicalisation sitting beside the platform's -- the two would drift and the divergence
    # would be invisible. Rely on GetFullPath for what it does, and handle only what it demonstrably leaves.
    # Raised by a sibling session that predicted the colon-free spellings would slip past the named list;
    # they do not, but nothing had recorded WHY, and an unstated premise under a security control is the
    # thing section 11 forbids. tests/test_worktree_gate.py pins all four spellings against both layers.
    #
    # This is "what turns off the thing I am deferring to" applied to GetExtension. The question came from a
    # sibling session that had just found `--ignore-other-worktrees` disabling the git guard its own rule
    # deferred to; the same question against this rule's classifier produced the spelling above.
    $colon = $rest.IndexOf(':')
    if ($colon -ge 0) { $rest = $rest.Substring(0, $colon) }

    # Name is matched as the WHOLE remainder or as a prefix ending in a separator, so `alloc` catches
    # alloc/adr/0162.json without catching a document called alloc-notes.md. Both sides are already
    # casefolded by Get-ComparablePath, which is why `announce/off` matches the real `announce/OFF`; the
    # prefix form matters there too, because announce-session.ps1 only Test-Paths the name, so a DIRECTORY
    # created by writing a file beneath it arms the kill switch just as well as a file does.
    $armed = $null
    foreach ($entry in @(
        @{ Name = "alloc"
           What = "the ledger gate's ADR/BACKLOG allocation registry (and its one-way floor ratchets)"
           Fix  = 'pwsh -NoProfile -File scripts\coord\alloc.ps1 -Kind <adr|backlog> -Title "<title>"' }
        @{ Name = "claims"
           What = "the claim gate's registry of who is building which BACKLOG item"
           Fix  = 'pwsh -NoProfile -File scripts\coord\claim.ps1 -Take <item> -Note "<what>"' }
        @{ Name = "locks"
           What = "the cross-session lock directory"
           Fix  = 'dot-source scripts\coord\lock.ps1 and call Enter-CoordLock -- it holds the file open' }
        @{ Name = "test-slots"
           What = "the pytest port-slot mutex"
           Fix  = 'run pytest; tests/conftest.py takes and releases a slot for you' }
        @{ Name = "gate-unresolved"
           What = "the collision gate's unresolved-notice throttle"
           Fix  = 'let scripts\hooks\collision_gate.ps1 stamp it; writing one HIDES its warning' }
        @{ Name = "overlap-cache.json"
           What = "the collision gate's peer-overlap input"
           Fix  = 'pwsh -NoProfile -File scripts\coord\overlap.ps1 -Refresh' }
        @{ Name = "announce/off"
           What = "the REPO-WIDE announce kill switch"
           Fix  = 'ask the user -- silencing announcements for every session is their decision, not yours' }
    )) {
        if ($rest -eq $entry.Name -or
            $rest.StartsWith("$($entry.Name)/", [System.StringComparison]::Ordinal)) { $armed = $entry; break }
    }

    # THE BACKSTOP, and the reason the list above is not sufficient on its own. The list is an ENUMERATION,
    # and this directory has now been measured to defeat enumeration twice over: an adversarial pass by three
    # independent readers found seven machine-read surfaces the first cut of this exemption had missed, and
    # then simply LISTING the directory's real contents turned up an eighth that all three had also missed --
    # announce/<session-id>.json, whose `state` field announce-session.ps1 reads to decide whether a session
    # has finished announcing (state `settled` or `exhausted` exits the hook outright). Writing one into a
    # PEER's marker silences that peer permanently, which is announce/OFF's harm aimed at one session and
    # harder to notice; announce/cwd-<hash>.stamp does the same for thirty minutes. An eighth found that way
    # is evidence there is a ninth, so the completeness claim has to come from a rule and not a list --
    # section 11's "prefer 'at least' to an enumeration", applied to code.
    #
    # So invert the default for everything the list does not name. The two populations are cleanly separated
    # by SHAPE, verified against the real directory: every legitimate session write is a document or a
    # receipt (`.md` handoffs at two depths, `.txt` for handoffs/backfill-baseline.txt, `.tsv` for
    # announce/sent/ and announce/receipts/), and every machine-read surface is `.json`, `.stamp`, `.lock`,
    # or extensionless (`announce/OFF`, `alloc/*/.floor-highwater`). This costs ZERO measured true positives
    # -- all 9 logged coord denies are `.md` or `.tsv` -- and it means the NEXT registry added here is denied
    # the day it appears rather than the day somebody remembers to update a list. Add it to the list anyway,
    # for the precise remedy; the shape rule is what holds until then.
    if (-not $armed -and
        [System.IO.Path]::GetExtension($rest) -notin @(".md", ".txt", ".tsv")) {
        $armed = @{
            What = "a file under .git\mefor-coord\ that is not a handoff document or a delivery receipt," +
                   " so this gate treats it as machine-read coordination state"
            Fix  = "if you meant to leave a NOTE, name it .md (or .txt); if you meant to append a delivery" +
                   " receipt, that is announce\sent\<session-id>.tsv"
        }
    }

    if (-not $armed) { exit 0 }

    Write-Deny -Rule "1b" -Detail $target -Reason @"
BLOCKED: this writes $($armed.What), which another gate on this machine reads as AUTHORITY ($(Get-SafeForMessage $target)).

Handoff documents and delivery receipts under .git\mefor-coord\ ARE exempt from rule 1 -- that is what the
exemption is for -- but they are exempt by SHAPE: a .md or .txt document, or a .tsv receipt. This path is
neither. It lives in the git COMMON dir -- ONE file, shared by every
worktree at once -- and the gate that reads it decides from a single field, or from the file merely
existing, so a hand-written copy is indistinguishable from a real one. That is how a write here forges an
allocation the allocator never issued, transfers a claim whose holder still believes it is theirs, or turns
a gate green with nothing behind it. Creating a worktree does NOT help: the same path resolves to the same
shared file from there.

Do this instead:

    $($armed.Fix)

If the state itself is WRONG -- a stale claim, a ratchet left high by an earlier accident -- say so and let
the user decide, naming the file and the change you want. Do not hand-edit it, and do not route around this
with a shell command; that only removes the record of which session did it.
"@
}

$root = Test-Governed $targetCmp
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
it with a shell command; that only hides the collision. That this gate inspects only Write/Edit/MultiEdit/
NotebookEdit is its SCOPE and not its rule -- the rule is the CONJUNCTION of one of those tools and a
target path in the primary's WORKING TREE -- so a write that lands in that tree by any other route breaks
the same rule; it is not permitted by this rule either, merely unobserved.

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
