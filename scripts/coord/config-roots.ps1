# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
<#
.SYNOPSIS
    Definitions only: what a Claude config root is, which one THIS session boots against, and where
    the usage collector publishes for it. Dot-source it; it does nothing on its own.

.DESCRIPTION
    WHY THIS FILE EXISTS. A box can run several Claude config roots at once -- ~/.claude for a bare
    `claude`, and one ~/.claude-account-<N> per launcher, each pinned through CLAUDE_CONFIG_DIR. Claude
    Code reads settings from the PINNED root. Three scripts in this directory need the same three
    answers about that (which roots exist, which one am I in, where does its usage state live), and
    when they answered separately they agreed only by luck: install-usage-statusline.ps1 wrote
    ~/.claude/settings.json while every session on this box read a pinned root, and reported
    "INSTALLED (user level -- every session on this machine)". The install succeeded, the collector
    never fired, and usage.ps1 said the collector was not installed. Two instruments disagreeing, the
    wrong one louder and earlier.

    The same blind spot has now been fixed three times in this codebase (scripts/worktree/
    install-gate.ps1 for the worktree gate, install-coordination.ps1 for the coordination hooks, and
    the out-of-repo _lift_from.py for a CLI grant). This file is where the rule stops being re-derived.

    FOUR CONSTRAINTS ON THIS FILE, because usage-collect.ps1 dot-sources it from a statusLine bound by
    NEVER THROWS, NEVER BLOCKS -- and dot-sourcing runs in the CALLER's scope, so anything at top level
    here happens to them:
      1. NO top-level param() block. It would consume the caller's own arguments.
      2. NO assignment to $ErrorActionPreference or any other preference variable. It would override
         the caller's, turning "worst case is a bare line of text" into a throw on the render path.
      3. NO I/O and NO pipeline output at load time. The statusLine fires on every assistant message
         behind a 300ms debounce.
      4. NO reading of $env:USERPROFILE inside a function -- take the home directory as an argument.
         Measured: with USERPROFILE overridden to C:/fake/home a child pwsh still reported
         [Environment]::GetFolderPath('UserProfile') = C:\Users\<user>. A callee that resolves home
         itself CANNOT be redirected by a test, and one dropped environment variable stands between a
         -AllRoots test and enumerating the owner's live account roots for real.
    tests/test_coord_usage.py asserts all four, because a comment cannot enforce them.

.EXAMPLE
    . (Join-Path $PSScriptRoot 'config-roots.ps1')
    $root = (Resolve-CurrentConfigRoot -HomeDir $HomeDir).Path
    $state = Get-UsageStateDir $root
#>

# The statusLine we own, named ONCE. install-usage-statusline.ps1 writes it as the command's first
# line, -Status and usage.ps1 recognise it, and -Uninstall removes only what matches. A second literal
# in any of them is a second definition of "ours", and the copy that drifts is the one that decides
# whether somebody else's status bar gets silently replaced.
$script:UsageStatusLineMarker = "mefor-usage"

# The NAME SHAPE of a config root, and the entire predicate. Carried from install-gate.ps1:95-113 and
# its Python twin at tests/test_gate_installed_parity.py:151 rather than re-derived, with the two
# measured incidents that produced the anchors:
#
#   * ~/.claude-account-2.lock IS A DIRECTORY carrying a settings.json of its own, and no .claude.json.
#     An unanchored `.claude-account-*` glob adopts it, and install-gate.ps1 wired it on every run for
#     weeks (BACKLOG #1024). So does any "looks like a config root because it has settings" test.
#   * ~/.claude-desktop-1..4 carry a .claude.json and NOTHING launches from them (measured 2026-08-27
#     against ~/claude-launchers/*.ps1: all ten launchers assign a literal .claude-account-<N>; the
#     .claude-desktop-<N> dirs are the Desktop app's --user-data-dir). So "has a .claude.json" is also
#     the wrong predicate on this box -- it admits four directories no session can boot from.
#
# `\z`, NOT `\Z`. .NET's \Z also matches BEFORE a trailing newline; .NET's \z is what Python's \Z
# means. Spelling it \Z would look like the Python twin and mean something slightly wider.
#
# CASE-SENSITIVE, matching that twin. -Filter is case-insensitive on Windows, so a `.Claude-Account-2`
# reaches this predicate and is rejected. That is deliberate but NOT FREE: every caller must pair it
# with Get-ClaudeConfigCandidates below, which reports such a directory BY NAME. Without that pairing
# the anchors create a silent under-reach, which is the failure mode this whole file exists to end.
$script:ClaudeAccountRootName = [regex]'\A\.claude-account-\d+\z'
$script:ClaudeDefaultRootName = [regex]'\A\.claude\z'

function Get-ClaudeConfigRoots {
    <#
    .SYNOPSIS
        Config roots a session can LAUNCH from, under $HomeDir. A READING function: it returns what it
        found, including nothing.
    .DESCRIPTION
        NO EMPTY-SET FALLBACK, deliberately. Seeding ~/.claude when the glob finds nothing would make
        every caller's "no config root found" guard dead code, and would manufacture a target that by
        definition does not exist. A caller that WANTS that seed keeps it at its own call site, where
        the choice is visible (install-coordination.ps1 does exactly that, and says why).

        -AccountsOnly drops ~/.claude. The statusLine installer's -AllRoots uses it: writing into
        ~/.claude means writing into a directory this repo's coordination tooling treats as shared
        state, for a launch mode no launcher on this box uses.
    #>
    param(
        [Parameter(Mandatory)][string]$HomeDir,
        [switch]$AccountsOnly
    )
    # -Force IS LOAD-BEARING AND ITS ABSENCE IS INVISIBLE ON WINDOWS. Get-ChildItem omits hidden
    # entries without it. On Windows a dot-prefixed directory carries no hidden ATTRIBUTE, so every
    # ~/.claude-account-N enumerates either way and the omission cannot be reproduced locally. On
    # Linux the dot prefix IS the hidden convention, so this glob returns NOTHING. install-gate.ps1
    # shipped that bug and only the CI ubuntu leg caught it.
    $found = @(
        Get-ChildItem -LiteralPath $HomeDir -Directory -Filter ".claude*" -Force -ErrorAction SilentlyContinue |
            Where-Object {
                $script:ClaudeAccountRootName.IsMatch($_.Name) -or
                (-not $AccountsOnly -and $script:ClaudeDefaultRootName.IsMatch($_.Name))
            } |
            ForEach-Object { $_.FullName }
    )
    # RETURNED WITHOUT A COMMA, AND CALLERS MUST WRAP IN @(). install-gate.ps1:192-200 makes the
    # opposite choice, correctly, for a HashSet -- unrolling destroys that type. For an ARRAY the comma
    # is the bug. Measured all four combinations:
    #     return ,@(...)  caller @(f)  ->  count 1, element is Object[]     <- SILENT NESTING
    #     return ,@(...)  caller f|%   ->  $_ is the whole array            <- SILENT NESTING
    #     return  @(...)  caller @(f)  ->  count 0 / 1 / N, elements String <- correct at every arity
    #     return  @(...)  caller f     ->  ONE result arrives as [String]   <- the caller's @() fixes it
    # The nesting arms are silent and produce a single bogus element whose string form is every path
    # joined by a space; that reached this repo as one -AllRoots target named
    # "<root-1> C:\...\<root-2>\settings.json". Wrap at the call site, always.
    return @($found | Sort-Object)
}

function Get-ClaudeConfigCandidates {
    <#
    .SYNOPSIS
        Every ~/.claude* directory carrying a settings.json, WITHOUT judging what it is.
    .DESCRIPTION
        Deliberately WIDER than Get-ClaudeConfigRoots and deliberately selected by a DIFFERENT rule.
        This is the independent audit population: it exists to catch a directory the name predicate
        rejects, so it must not be chosen by the predicate whose correctness it checks. A validator
        satisfied by construction reports only its own opinion back to itself.
    #>
    param([Parameter(Mandatory)][string]$HomeDir)
    # No comma, and callers wrap in @() -- same measured reason as Get-ClaudeConfigRoots above.
    return @(
        Get-ChildItem -LiteralPath $HomeDir -Directory -Filter ".claude*" -Force -ErrorAction SilentlyContinue |
            Where-Object { Test-Path -LiteralPath (Join-Path $_.FullName "settings.json") -PathType Leaf }
    )
}

function ConvertTo-NormalRootPath {
    <#
    .SYNOPSIS
        One spelling of a root path, so two spellings of the same root compare equal.
    .DESCRIPTION
        RESOLVE-PATH IS NOT A CANONICALISER and it is the obvious wrong choice here. Measured on one
        existing directory, spelled three ways:
            Resolve-Path 'C:/Temp/Demo'  -> C:\Temp\Demo
            Resolve-Path 'c:\temp\demo'  -> C:\temp\demo    (only the SEPARATORS were changed)
            Resolve-Path 'C:/Temp/Demo/' -> C:\Temp\Demo\   (trailing separator KEPT)
        so two spellings of one directory compare unequal under -ceq. GetFullPath does not fix the
        case either (measured: 'c:\temp\demo' stays lowercase), which is exactly why every comparison
        built on this uses -ieq and never -ceq. A key that is not stable is not a key.

        It also requires no filesystem access, so it works on a path that does not exist -- which is
        the case the installer has to report on rather than create.
    #>
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return $null }
    try { return ([System.IO.Path]::GetFullPath($Path)).TrimEnd('\', '/') } catch { return $Path.TrimEnd('\', '/') }
}

function Test-SameRoot {
    <#
    .SYNOPSIS
        Do two paths name the same config root? Case-INSENSITIVE, for the reason above.
    #>
    param([string]$A, [string]$B)
    $na = ConvertTo-NormalRootPath $A
    $nb = ConvertTo-NormalRootPath $B
    if ($null -eq $na -or $null -eq $nb) { return $false }
    return $na -ieq $nb
}

function Get-UsageStateDir {
    <#
    .SYNOPSIS
        Where the usage collector publishes for a given config root.
    .DESCRIPTION
        THE FILESYSTEM IS THE PARTITION KEY, so two roots cannot collide by construction. The
        alternative -- one shared tree keyed by a derived name -- needs a key derived from a path, and
        a leaf-name key collides the moment CLAUDE_CONFIG_DIR points at a `.claude` outside the home
        directory. That would reintroduce the exact defect this partitioning removes.

        WHY IT IS PARTITIONED AT ALL: see usage-collect.ps1's header. Briefly, a config root holds one
        credential set and therefore one Anthropic account, and separate accounts have separate 5-hour
        and 7-day pools. One shared file across roots is last-writer-wins across unrelated quotas.
    #>
    param([Parameter(Mandatory)][string]$ConfigRoot)
    return (Join-Path (ConvertTo-NormalRootPath $ConfigRoot) 'mefor-usage')
}

function Resolve-CurrentConfigRoot {
    <#
    .SYNOPSIS
        The config root THIS process is running against, and where that answer came from.
    .DESCRIPTION
        Returns @{ Path = <normalised root>; Source = 'CLAUDE_CONFIG_DIR' | 'default (CLAUDE_CONFIG_DIR unset)' }.

        THE SOURCE IS RETURNED, NOT RE-DERIVED BY THE CALLER. Every caller prints it, and a reader who
        cannot see WHY a path was chosen cannot tell a correct answer from a coincidence -- which is
        the whole complaint that produced this change.

        An EMPTY-STRING pin counts as unset: [bool]$env:CLAUDE_CONFIG_DIR is False for "" (measured),
        and falling through to the default is the right reading of a blank variable.
    #>
    param([Parameter(Mandatory)][string]$HomeDir)
    if ($env:CLAUDE_CONFIG_DIR) {
        return @{ Path = (ConvertTo-NormalRootPath $env:CLAUDE_CONFIG_DIR); Source = 'CLAUDE_CONFIG_DIR' }
    }
    return @{ Path = (ConvertTo-NormalRootPath (Join-Path $HomeDir '.claude')); Source = 'default (CLAUDE_CONFIG_DIR unset)' }
}

function Test-IsOurStatusLine {
    <#
    .SYNOPSIS
        Is this statusLine command ours? ANCHORED on the first line, never a substring.
    .DESCRIPTION
        THE SUBSTRING TEST STOPPED BEING SAFE WHEN THE PUBLISH PATH WENT INTO THE COMMAND. The wired
        command now contains `\mefor-usage` inside its -StateDir argument, so the old
        `command -like "*mefor-usage*"` would judge ANY foreign statusLine that merely mentions the
        publish path to be ours -- and silently replace it, in up to five roots at once. The refusal
        guard exists precisely to stop that.

        THREE-WAY, NOT TWO-WAY. A statusLine object present with a null, empty or whitespace command is
        NONE, not FOREIGN: classifying it FOREIGN would make the installer refuse that root forever
        while printing "already configured: " with nothing after the colon, and offer a remedy ("merge
        the two commands by hand") naming a command that does not exist. Callers ask
        Test-IsOurStatusLine only after establishing the command is non-empty.
    #>
    param([string]$Command)
    if ([string]::IsNullOrWhiteSpace($Command)) { return $false }
    return ((($Command -split "`r?`n", 2)[0]).Trim()) -ceq "# $script:UsageStatusLineMarker"
}

function Get-WiredStateDir {
    <#
    .SYNOPSIS
        The publish path a root's wired command NAMES. $null means a LEGACY command, which is an answer.
    .DESCRIPTION
        READ BACK, NEVER RECOMPUTED, and that is the point. install-usage-statusline.ps1:73 used to
        report "script exists: <bool>" against a path THAT INVOCATION had just resolved from git --
        so a root wired months ago from a checkout since deleted still reported True. Across five
        roots wired at different times from different checkouts, one recomputed line cannot describe
        any of them.

        A NO-MATCH IS NOT AN ERROR. It means the command carries no -StateDir: a command written before
        publish paths were per-root, or one the out-of-repo propagate stopgap copied. That is a real,
        reportable state (the collector then chooses at run time), and folding it into "wired" is how
        it would go silent.
    #>
    param([string]$Command)
    if ([string]::IsNullOrWhiteSpace($Command)) { return $null }
    $m = [regex]::Match($Command, "\`$d = '((?:[^']|'')*)'")
    if (-not $m.Success) { return $null }
    return ($m.Groups[1].Value -replace "''", "'")
}

function Get-WiredCollectorPath {
    <#
    .SYNOPSIS
        The collector script a root's wired command NAMES. $null when the shape is unrecognised.
    #>
    param([string]$Command)
    if ([string]::IsNullOrWhiteSpace($Command)) { return $null }
    $m = [regex]::Match($Command, "\`$s = '((?:[^']|'')*)'")
    if (-not $m.Success) { return $null }
    return ($m.Groups[1].Value -replace "''", "'")
}
