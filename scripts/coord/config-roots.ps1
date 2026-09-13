# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
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

# The AVAILABILITY MARKER, named ONCE for the same reason the statusLine marker above is. It sits in
# the root's publish directory rather than beside settings.json, because the publish directory is
# already the per-account partition key (Get-UsageStateDir) -- so a marker cannot end up describing a
# different account than the numbers it sits next to, and a reader pointed at an explicit -StateDir
# finds the marker that belongs to the numbers it is about to read.
#
# THE FACT LIVES ON THE BOX, NOT IN THIS REPOSITORY. Nothing here may enumerate which roots exist or
# which subscription was cancelled: the repository is public, an account root is one person's
# credential set, and the whole file above is built on DISCOVERING roots rather than listing them.
# So the repository carries the mechanism and the operator's own filesystem carries the fact.
$script:UsageUnavailableMarker = 'unavailable.json'

function Get-LaunchableConfigRoots {
    <#
    .SYNOPSIS
        Config roots a session can LAUNCH from, under $HomeDir. A READING function: it returns what it
        found, including nothing.
    .DESCRIPTION
        NOT Get-ClaudeConfigRoots, AND THE NAME IS DELIBERATE. session-registry.ps1 already defines a
        function by that name in this same directory, dot-sourced by eleven scripts, and it answers a
        DIFFERENT question: which roots have RUN a session (it filters on a `sessions/` subdirectory).
        This one answers which roots a session could BOOT from, by name shape. Both are correct for
        their own caller and neither substitutes for the other -- install-coordination.ps1 records why
        the `sessions/` filter is wrong for wiring: a root that exists but has not run a session yet
        has no `sessions/` and still needs wiring, because the first session it runs is exactly the one
        that would come up unconfigured.

        Sharing the name would make the winner depend on dot-source ORDER. It would also be worse than
        a plain error in one direction: that function resolves the home directory from
        $env:USERPROFILE itself, so a caller expecting this one's -HomeDir seam would silently
        enumerate the real home -- the exact test-safety hole constraint 4 above exists to close.

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
        Deliberately WIDER than Get-LaunchableConfigRoots and deliberately selected by a DIFFERENT rule.
        This is the independent audit population: it exists to catch a directory the name predicate
        rejects, so it must not be chosen by the predicate whose correctness it checks. A validator
        satisfied by construction reports only its own opinion back to itself.
    #>
    param([Parameter(Mandatory)][string]$HomeDir)
    # No comma, and callers wrap in @() -- same measured reason as Get-LaunchableConfigRoots above.
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

function ConvertTo-UtcDateTime {
    <#
    .SYNOPSIS
        One reading of a timestamp that came out of JSON. $null when it is not a date.
    .DESCRIPTION
        DO NOT STRINGIFY A VALUE ConvertFrom-Json HAS ALREADY TOUCHED. It coerces an ISO-8601 field into
        a [datetime] before any of our code sees it, and rendering that back to a string drops the 'Z';
        re-parsing a Z-less string assumes LOCAL, which on this box added five hours and dated a reading
        taken 90 seconds ago as 299 minutes in the FUTURE. usage.ps1's Get-AgeMinutes records the full
        measurement and now subtracts from this function rather than restating its own copy of the rule.

        A Kind of Unspecified is read as UTC because every timestamp this codebase writes is UTC. That
        assumption is the reason this lives in one function: it is wrong for any other input, and one
        place to change it is the difference between a fix and a hunt.
    #>
    param([object]$Value)
    if ($null -eq $Value) { return $null }
    if ($Value -is [datetime]) {
        switch ($Value.Kind) {
            ([System.DateTimeKind]::Utc) { return $Value }
            ([System.DateTimeKind]::Local) { return $Value.ToUniversalTime() }
            default { return [datetime]::SpecifyKind($Value, [System.DateTimeKind]::Utc) }
        }
    }
    if ($Value -is [datetimeoffset]) { return $Value.UtcDateTime }
    try { return ([System.DateTimeOffset]::Parse([string]$Value)).UtcDateTime } catch { return $null }
}

function Get-RootUnavailability {
    <#
    .SYNOPSIS
        Is this account still spendable? Reads the marker in a publish directory and reports one of
        AVAILABLE / UNAVAILABLE / PENDING / MALFORMED.
    .DESCRIPTION
        WHY THE TRACKING NEEDS THIS AT ALL. A cancelled account is the one failure this reader could not
        see, and it fails in the worst possible direction: a dead account never burns quota, so its last
        reading freezes low and its publish directory goes quiet -- which is byte-identical to an IDLE
        account with a full pool. A seat looking for "the account with the most headroom" is therefore
        steered at the one account that has none, and the reader's own remedy for a quiet root ("start a
        NEW session pinned to this root") points it at a subscription that no longer exists.

        FAIL CLOSED ON A MARKER IT CANNOT READ. A malformed marker is UNAVAILABLE, not AVAILABLE. The
        file exists because somebody put it there, so the reachable states are "cancelled" and
        "cancelled, and the note about it is damaged" -- and reading a damaged note as an all-clear is
        how a guard goes silent while still looking present. MALFORMED is returned separately from
        UNAVAILABLE so the operator is told to fix the file rather than left wondering why an account
        they never marked is refusing.

        PENDING IS A REAL STATE AND NOT A CONVENIENCE. A cancellation normally takes effect at the end
        of a billing period, so between the decision and that date the pool is still live and still
        worth spending. A marker carrying a future `effective_from` therefore does NOT suppress the
        numbers; it rides along beside them so a reader knows the account has an end date. Absent or
        past `effective_from` means the marker is live now.

        AN ABSENT MARKER IS AVAILABLE, and that is the only silent arm here -- correctly, because it is
        the overwhelmingly normal case and the alternative (requiring every root to carry a marker) puts
        a maintenance burden on five directories to describe a condition that applies to none of them.
    #>
    param([Parameter(Mandatory)][string]$StateDir)
    $path = Join-Path $StateDir $script:UsageUnavailableMarker
    $o = [ordered]@{
        state          = 'AVAILABLE'
        reason         = ''
        marked_at      = $null
        marked_by      = $null
        effective_from = $null
        marker_path    = $path
    }
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { return $o }

    $doc = $null
    try { $doc = Get-Content -LiteralPath $path -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop }
    catch {
        $o.state = 'MALFORMED'
        $o.reason = "the availability marker at $path is not readable JSON, so this account is treated as UNAVAILABLE rather than assumed spendable"
        return $o
    }
    # A MARKER SAYING `unavailable: false` IS AN ANSWER, not a broken file. It is what -Clear could
    # leave behind, and honouring it is what lets an operator record "checked, still live" explicitly.
    if ($doc.PSObject.Properties.Name -contains 'unavailable' -and -not [bool]$doc.unavailable) { return $o }

    $o.reason = [string]$doc.reason
    if (-not $o.reason) { $o.reason = 'no reason recorded in the marker' }
    # THROUGH THE CONVERTER, NOT [string]. ConvertFrom-Json has already turned this ISO field into a
    # [datetime], and stringifying that yields the machine's LOCAL short format -- measured here as
    # "09/08/2026 23:29:04": the 'Z' gone, and a day/month order that reads as 9 August to half the
    # world. It is printed as the sole audit trail for why an account is being skipped, so an
    # ambiguous date is the wrong kind of wrong. A value that is not a date is passed through as
    # written rather than blanked, because a hand-edited marker saying "last Tuesday" should show what
    # it says instead of vanishing.
    $mk = ConvertTo-UtcDateTime $doc.marked_at
    $o.marked_at = if ($mk) { $mk.ToString('yyyy-MM-ddTHH:mm:ssZ') } else { [string]$doc.marked_at }
    $o.marked_by = [string]$doc.marked_by
    $eff = ConvertTo-UtcDateTime $doc.effective_from
    if ($eff) {
        $o.effective_from = $eff.ToString('yyyy-MM-ddTHH:mm:ssZ')
        if ($eff -gt (Get-Date).ToUniversalTime()) {
            $o.state = 'PENDING'
            return $o
        }
    }
    $o.state = 'UNAVAILABLE'
    return $o
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
        READ BACK, NEVER RECOMPUTED, and that is the point. The installer's -Status used to
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
