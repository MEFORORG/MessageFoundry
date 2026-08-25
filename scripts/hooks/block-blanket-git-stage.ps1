# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
# PreToolUse guard: block blanket git staging so parallel Claude Code sessions sharing a working
# tree can't sweep each other's files into one commit. Reads the tool-call JSON on stdin; if the
# command does a broad stage (git add -A/--all/-u/. or git commit -a/-am/--all) it returns a
# PreToolUse "deny" decision asking for explicit paths. Anything else passes silently (exit 0).
# Fail-OPEN on any error: a guardrail must never wedge all git work.
#
# WIRING IS NOT ASSERTED HERE ON PURPOSE. Whether this script is referenced by a PreToolUse matcher
# is a property of settings.json, not of this file, and a comment claiming otherwise cannot be
# checked. tests/test_claude_settings_contract.py holds that assertion where it can fail.
# See docs/WORKTREES.md.
# ASCII-only on purpose (PS 5.1 ANSI-read lesson); run under pwsh 7 by the hook.

$ErrorActionPreference = 'SilentlyContinue'

# ---------------------------------------------------------------------------------------------
# WHY THIS FILE HAS FUNCTIONS NOW, AND WHY THEY ARE LOCAL (BACKLOG #1341)
#
# The old scan split on '(\|\||&&|[;|&\n])' and then matched the subcommand and flag tokens
# ANYWHERE in a segment. Both halves were wrong in the SAME direction -- toward denying:
#   * a separator inside a quoted span split the command, so quoted prose landed at a segment
#     front and was read there as a program name;
#   * 'add' appearing as an ARGUMENT ('git grep -n add -- .') was read as the subcommand.
#
# The sibling worktree_gate.ps1 has a quote-blanking pass (Remove-QuotedSpans) that solves the
# first half. It is NOT dot-sourced here, deliberately: BACKLOG #1332 is rewriting that tokeniser
# right now, and sharing a seam under two concurrent lanes costs more than a local copy. This is
# written against its SHAPE, not copied from it. When #1332 settles, this should be replaced by
# the shared helper and deleted -- it is one function with one caller for exactly that reason.
#
# THE POLARITY RULE, AND IT IS LOAD-BEARING (BACKLOG #1229's reverted experiment).
# A program-position predicate was built for worktree_gate.ps1 and withdrawn six hours later. It
# put an ALLOWLIST of transparent wrapper words on the path to a deny: a name it did not know
# ended the chain, and an ended chain meant no verb, and no verb meant ALLOW. At least 11 of 21
# measured dispatch prefixes flipped DENY to ALLOW that way -- 'cmd /c', 'pwsh -File', a
# PowerShell dot-source, 'source', an unlisted wrapper. Its own docstring priced the risk
# backwards, reasoning about a name wrongly ADDED when the failure mode is a name MISSING.
#
# So: RECOGNITION MAY ONLY EVER SUPPRESS A DENY, NEVER BE REQUIRED TO PRODUCE ONE. The only
# construct below that can turn a deny into an allow is $READ_ONLY_SUBCOMMANDS, and a name
# missing from it costs a FALSE DENY -- noisy, visible, self-reporting -- never a silent hole.
# Every unrecognised shape falls through to the old substring predicates, which deny.
# ---------------------------------------------------------------------------------------------

# Blank the BODY of every heredoc, preserving line structure. A heredoc body is data being
# written to a file, not a command, but its lines sit at the front of a newline-split segment and
# are read there as program position. Handles <<WORD, <<-WORD, <<'WORD' and <<"WORD".
function Hide-HeredocBodies([string]$Text) {
    $lines = $Text -split "`n", 0
    $out = New-Object 'System.Collections.Generic.List[string]'
    $terminator = $null
    foreach ($line in $lines) {
        if ($null -ne $terminator) {
            # Inside a body: blank it. The terminator line itself is kept so the shape stays legible.
            if ($line.Trim() -ceq $terminator) { $terminator = $null; $out.Add($line) }
            else { $out.Add(' ' * $line.Length) }
            continue
        }
        $out.Add($line)
        $m = [regex]::Match($line, '<<-?\s*(?:''([^'']+)''|"([^"]+)"|([A-Za-z_][A-Za-z0-9_]*))')
        if ($m.Success) {
            $terminator = @($m.Groups[1].Value, $m.Groups[2].Value, $m.Groups[3].Value) |
                Where-Object { $_ } | Select-Object -First 1
        }
    }
    return ($out -join "`n")
}

# Replace the CONTENTS of quoted spans with spaces, keeping the quote characters and the overall
# length. A separator inside a quoted span is then invisible to the splitter, and a git-looking
# token inside one cannot reach program position. Length preservation is what keeps the result
# usable for positional reasoning.
function Hide-QuotedSpans([string]$Text) {
    $sb = New-Object System.Text.StringBuilder
    $quote = $null
    foreach ($ch in $Text.ToCharArray()) {
        if ($null -ne $quote) {
            if ($ch -ceq $quote) { $quote = $null; [void]$sb.Append($ch) }
            elseif ($ch -ceq "`n") { [void]$sb.Append($ch) }  # keep line structure for the splitter
            else { [void]$sb.Append(' ') }
            continue
        }
        if ($ch -ceq '"' -or $ch -ceq "'") { $quote = $ch; [void]$sb.Append($ch); continue }
        [void]$sb.Append($ch)
    }
    return $sb.ToString()
}

# git subcommands that CANNOT stage anything. Recognising one here is the only way a command
# reaches ALLOW through this file's new logic, so a name MISSING from this list costs a false
# deny and never a bypass. Read as "at least these" -- add freely, the direction is safe.
$READ_ONLY_SUBCOMMANDS = @(
    'annotate', 'bisect', 'blame', 'branch', 'cat-file', 'check-ignore', 'config', 'describe',
    'diff', 'difftool', 'fetch', 'grep', 'help', 'log', 'ls-files', 'ls-remote', 'ls-tree',
    'merge-base', 'merge-tree', 'name-rev', 'reflog', 'remote', 'rev-list', 'rev-parse',
    'shortlog', 'show', 'show-ref', 'status', 'tag', 'var', 'verify-commit', 'version',
    'whatchanged', 'worktree'
)

# Resolve the token in SUBCOMMAND position, skipping git's leading global options. Returns $null
# when it cannot tell -- and $null means "fall through to the substring predicates", i.e. deny as
# before. It never means allow.
function Resolve-GitSubcommand([string[]]$Tokens) {
    for ($i = 1; $i -lt $Tokens.Count; $i++) {
        $t = $Tokens[$i]
        if ($t -notlike '-*') { return $t }
        # Global options that take a SEPARATE value. Skipping the value is what stops
        # 'git -C <path> add -A' resolving its subcommand to <path>. An option missing from this
        # list only ever mis-resolves toward a non-subcommand, which falls through to a deny.
        if ($t -cmatch '^(-C|-c|--git-dir|--work-tree|--namespace|--exec-path|--super-prefix)$') { $i++ }
    }
    return $null
}

$cmd = $null
try {
    $raw = [Console]::In.ReadToEnd()
    if (-not [string]::IsNullOrWhiteSpace($raw)) {
        $j = $raw | ConvertFrom-Json
        $cmd = [string]$j.tool_input.command
    }
} catch {
    exit 0
}
if ([string]::IsNullOrWhiteSpace($cmd)) { exit 0 }

# Scan the BLANKED form. Quoted spans and heredoc bodies are data; everything outside them keeps
# its exact offsets, so a real command is unchanged by this pass.
$scan = Hide-QuotedSpans (Hide-HeredocBodies $cmd)

$reason = $null
# Examine each shell-separated simple command on its own, so '... && git add -A' is still caught.
#
# TWO VIEWS OF THE SAME SEGMENT, AND THE SPLIT BETWEEN THEM IS DELIBERATE. Both Hide- passes above
# preserve LENGTH exactly, so an offset into $scan is the same offset into $cmd. The blanked view
# answers "where does a command start, and is this git" -- questions where quoted text must not
# count. The raw view answers "what are this command's arguments" -- where a quoted token is an
# ordinary argument and blanking it would hide a real pathspec. `git add ':(top)'` needs the raw
# view; `git commit -m "wip; git add -a"` needs the blanked one. The resolved SUBCOMMAND is what
# selects between them, below.
$bounds = New-Object 'System.Collections.Generic.List[int[]]'
$cursor = 0
foreach ($m in [regex]::Matches($scan, '(\|\||&&|[;|&\n])')) {
    $bounds.Add(@($cursor, ($m.Index - $cursor)))
    $cursor = $m.Index + $m.Length
}
$bounds.Add(@($cursor, ($scan.Length - $cursor)))

foreach ($b in $bounds) {
    if ($b[1] -le 0) { continue }
    $s = $scan.Substring($b[0], $b[1]).Trim()
    $rawSeg = $cmd.Substring($b[0], $b[1]).Trim()
    # The PROGRAM NAME is matched case-INSENSITIVELY, and only it. Windows resolves git, Git and
    # GIT to the same git.exe, so 'Git add -A' staged the tree while 'git add -A' was denied. The
    # subcommand and flag tests below stay -cmatch on purpose: git rejects 'git ADD', and '-A' and
    # '-a' are different flags.
    #
    # '^' pins this to the front of a SEGMENT. That now IS program position for the cases this
    # guard covers, because the splitter above no longer breaks inside quoted spans or heredoc
    # bodies. A command reached through a dispatching wrapper ('cmd /c "git add -A"') is still
    # not covered -- that is BACKLOG #1305's axis, on a different file, and deliberately not
    # widened here: doing so needs a wrapper allowlist, which is the construct #1229 proved
    # fails open.
    # `git.exe` is the SAME executable spelled with its extension, and it was one of the seven
    # measured bypasses. Only the BARE spelling is covered: a path-qualified or wrapper-dispatched
    # git ('C:/.../git.exe add -A', 'env git add -A') is BACKLOG #1305's axis and is left alone,
    # because closing it needs a wrapper allowlist -- the construct BACKLOG #1229 measured as
    # fail-open on the sibling gate.
    if ($s -inotmatch '^git(\.exe)?(\s|$)') { continue }

    $tokens = @($s -split '\s+' | Where-Object { $_ })

    # THE ONE SUPPRESSION. A recognised read-only subcommand cannot stage, so 'git grep -n add'
    # and 'git log --all --grep commit' allow. Anything unrecognised -- including $null -- falls
    # through to the predicates below unchanged.
    $sub = Resolve-GitSubcommand $tokens
    if ($null -ne $sub -and $READ_ONLY_SUBCOMMANDS -ccontains $sub) { continue }

    # LIMB 1 -- the SUBCOMMAND, including the synonym. `stage` is documented and dispatches to the
    # same builtin (`git stage -h` prints `usage: git add`), so testing only `add` let every flag
    # and pathspec row below be defeated by one word.
    #
    # WHICH VIEW THE ARGUMENTS ARE READ FROM IS DECIDED HERE, and it is decided by the RESOLVED
    # subcommand rather than by searching for the word. When the subcommand IS add/stage, every
    # non-flag argument is a pathspec, so the raw view is correct and safe -- `git add` has no
    # message flag whose quoted value could be mistaken for one. When it is anything else, the
    # blanked view is correct: `git commit -m "wip; git add -a"` must not be read as a stage.
    # A subcommand that does not resolve falls back to the ORIGINAL token search on the blanked
    # view, which preserves every deny this guard made before.
    $argView = if ($sub -ceq 'add' -or $sub -ceq 'stage') { $rawSeg } else { $s }
    $staging = ($sub -ceq 'add' -or $sub -ceq 'stage') -or
               ($null -eq $sub -and $s -cmatch '(^|\s)(?:add|stage)(\s|$)') -or
               ($null -ne $sub -and $sub -cne 'commit' -and $s -cmatch '(^|\s)(?:add|stage)(\s|$)')

    # LIMB 2 -- the blanket-stage FLAG family, GENERATED from the option words rather than typed,
    # per the method BACKLOG #1097 settled for worktree_gate.ps1's interpreter flag. A longer list
    # has the same shape as the defect and decays the same way.
    #
    # WHY A LADDER AND NOT TWO SPELLINGS: git's parse-options binds a long option by any
    # UNAMBIGUOUS ABBREVIATION, so `--a`, `--al`, `--up`, `--upd` and `--updat` all stage the tree.
    # Generating an ambiguous rung costs nothing -- git refuses it, and a command git refuses is
    # not a command to protect.
    $blanketWords = @('all', 'update', 'no-ignore-removal')
    $longNames = @(
        $blanketWords | ForEach-Object { $w = $_; 1..$w.Length | ForEach-Object { $w.Substring(0, $_) } }
    ) | Sort-Object -Property Length -Descending   # longest first: `--all` binds as `all`, not `a`+`ll`
    $longFlag = "--(?:$($longNames -join '|'))"
    # A short-option CLUSTER, the same construction the commit branch below already used. The
    # trigger set is EXACTLY {A, u} and CASE-SENSITIVE, and the case is the whole bound:
    #   -A  --all      stages everything          MUST trigger
    #   -u  --update   stages every tracked change MUST trigger
    #   -a             NOT a git add flag; `git add -a` exits 129 `unknown switch`. Folding case
    #                  here would deny commands git itself refuses: pure false-deny, zero gain.
    #   -U  --unified  IS a real flag and stages nothing. Matching it denies legitimate work.
    # `-a` and `-U` are pinned as ALLOW tests so the next reader cannot "simplify" this to (?i)[au].
    $shortFlag = '-[A-Za-z]*[Au][A-Za-z]*'
    $blanketFlag = "(?:$longFlag|$shortFlag)"

    # LIMB 3 -- a whole-tree PATHSPEC, kept a SEPARATE limb from the flags on purpose. A flag can be
    # anchored on a leading `-`; a pathspec cannot, and the only thing separating the blanket
    # `git add ./` from the scoped `git add ./src/x.py` is the trailing boundary. One fused rule
    # would need one boundary to satisfy both tests and would be wrong for one of them. The two
    # also earn different deny messages: telling an operator who typed `:/` that the problem was a
    # flag is the wrong sentence.
    # AT LEAST these four -- this is not an enumeration of git's pathspec grammar.
    # QUOTES ARE TOLERATED AROUND THE WHOLE TOKEN because `:(top)` cannot be typed unquoted in
    # either shell -- the parentheses are syntax. The token must still be EXACTLY the pathspec:
    # `git add './src/x.py'` stays allowed, because the trailing boundary is outside the quote.
    $treeRoot = '["'']?(?:\.|\./|:/|:\(top\))["'']?'

    # WHAT THESE THREE LIMBS DELIBERATELY DO NOT REACH, stated beside the rule per CLAUDE.md
    # section 11 rather than left for a reader to discover:
    #   --renormalize             implies -u; `git add --renormalize .` stages tracked changes
    #   --pathspec-from-file=-    the pathspec is on stdin, so no pathspec appears in the command
    #   :^x / :!x / :(glob) / *   the rest of magic pathspec; an exclude-only spec is a blanket
    #                             stage spelled as an exclusion
    #   any dispatching wrapper   `cmd /c "git add -A"`, `env git add -A`, a path-qualified git.
    #                             That is BACKLOG #1305's axis and needs a wrapper allowlist, the
    #                             construct BACKLOG #1229 measured as fail-open.
    if ($staging -and $argView -cmatch "(^|\s)$blanketFlag(\s|$)") {
        $reason = "git add/stage -A/--all/-u/--update (or a cluster containing A or u) stages everything, including files another session may be editing."
        break
    }
    if ($staging -and $argView -cmatch "(^|\s)$treeRoot(\s|$)") {
        $reason = "git add/stage with a whole-tree pathspec (. ./ :/ :(top)) stages everything, including files another session may be editing."
        break
    }
    # git commit with -a / -am / --all (auto-stages every tracked change). A single-dash flag
    # cluster containing 'a' catches -a, -am, -na, etc.; '--amend' (double dash) is left alone.
    if ($s -cmatch '\bcommit\b' -and ($s -cmatch '(^|\s)--all(\s|$)' -or $s -cmatch '(^|\s)-[A-Za-z]*a[A-Za-z]*(\s|$)')) {
        $reason = "git commit -a/-am/--all auto-stages every tracked change before committing."
        break
    }
}

if (-not $reason) { exit 0 }

$msg = "Blocked blanket git staging: $reason Stage explicit paths instead: 'git add <path> ...' then 'git commit -m ...'. (MessageFoundry guard; disable via /hooks.)"
$payload = [pscustomobject]@{
    hookSpecificOutput = [pscustomobject]@{
        hookEventName            = 'PreToolUse'
        permissionDecision       = 'deny'
        permissionDecisionReason = $msg
    }
}
[Console]::Out.Write(($payload | ConvertTo-Json -Compress -Depth 6))
exit 0
