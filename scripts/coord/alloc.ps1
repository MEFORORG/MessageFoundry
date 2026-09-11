# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
<#
.SYNOPSIS
    Allocate the next free ADR or BACKLOG number, atomically, so two concurrent sessions can never take
    the same one.

.DESCRIPTION
    NEVER grep for `max + 1`. Two sessions that both grep pick the SAME number, create DIFFERENTLY-named
    files, merge CLEAN, and silently corrupt the ledger. That has happened three times here (d1d0a5a #574,
    5b7d046 #598, 9f3483d) and it is invisible to git, to a file lock, and to `git merge-tree`.

    This is a test-and-set, not a read-modify-write. It claims the number by EXCLUSIVELY CREATING
    <git-common-dir>/mefor-coord/alloc/<kind>/<number>.json -- an atomic NTFS operation. If a sibling
    session already holds it, the create throws and we move to the next number. (A read-modify-write on a
    shared list is not an option: PowerShell was MEASURED silently losing 4 of 8 concurrent writes to one
    shared file.)

    The registry lives beside the SHARED object store, so every worktree of this repo sees the same
    allocations, and a different clone automatically gets its own registry.

    The floor is the max over: the numbers on origin/main, the numbers on EVERY local and remote ref, and
    every existing allocation. The all-refs term closes the "registry wiped -> re-issue a number that only
    exists on an unpushed branch" hole. NEITHER KIND SPAWNS A PROCESS PER REF, which is the property
    that matters: a per-ref sweep is fine at a few hundred refs and unusable at several thousand, and
    it does not announce the crossing (BACKLOG #1534). What each costs instead, COUNTED with GIT_TRACE
    on this clone on 2026-09-11 rather than reasoned about, and dated because both are live properties
    that drift:
      adr      440 git processes for the whole -ShowFloor run -- ref enumeration, one
               `cat-file --batch-check`, then one `ls-tree` per DISTINCT docs/adr tree, 434 here.
               It scales with distinct TREES, not with refs.
      backlog  18 -- ref enumeration, one `cat-file --batch-check`, then one `git grep` per 128
               DISTINCT ledger blobs, 13 here at 1,538 blobs (BACKLOG #1535). Scales with blobs.
    An earlier version of these lines said "TWO git processes" for each and was wrong twice over: it
    omitted the ref enumeration both branches run, and it described an adr stage 2 that has since been
    reverted. The cost is per allocation, not per edit.

    Numbers are never reclaimed. An abandoned branch holds its number forever and the sequence develops
    holes. That is deliberate: holes are free, collisions are not.

    -For NAMES THE OWNER AT BIRTH. IT IS NOT A TRANSFER VERB, AND THE DIFFERENCE IS THE WHOLE ARGUMENT.
    A claim records the tree that will COMMIT the number, and by default that is the tree the allocator
    runs in. When one seat allocates on another seat's behalf -- a Console reading the backlog and
    cutting a brief for a Builder in a different worktree -- the default records the wrong tree, both of
    ledger_check.py's ownership keys miss, and the gate correctly refuses the Builder's commit. Nothing
    can then move the number, so the work is re-filed at a fresh one and the first is burned. Measured
    on this clone: BACKLOG #1297/#1298, #1422/#1423 and #1425/#1426 are three such pairs.

    A TRANSFER verb was considered and DECLINED (docs/LEDGER-GATE.md): it "puts a hole in the
    non-transferable rule the gate rests on", because it would let a seat take a number another session
    is actively holding. -For does not, and cannot: it sets the owner inside the same atomic CreateNew
    that ISSUES the number, at an instant when no session holds it and none can. No existing claim's
    owner is ever changed, by this switch or any other. The exclusivity the gate rests on is untouched.

    It REFUSES a path that is not a live worktree of THIS clone, because the failure it exists to
    prevent is a claim born pointing somewhere the gate will never accept -- and a silent typo would
    reproduce that exactly.

.EXAMPLE
    pwsh -NoProfile -File scripts\coord\alloc.ps1 -Kind adr -Title "Worktree gate"
    pwsh -NoProfile -File scripts\coord\alloc.ps1 -Kind backlog -Title "Ledger allocator"
    pwsh -NoProfile -File scripts\coord\alloc.ps1 -Kind backlog -Title "Builder's item" -For C:\path\to\builder\worktree
    pwsh -NoProfile -File scripts\coord\alloc.ps1 -List
#>
[CmdletBinding()]
param(
    [ValidateSet("adr", "backlog")]
    [string]$Kind = "adr",
    [string]$Title,
    # Show what this worktree currently holds, and exit.
    [switch]$List,
    # Print the computed floor and the paths it swept, then exit WITHOUT allocating.
    #
    # Allocation is a one-way door -- claims are never released ("holes are free, collisions are not")
    # -- so before this switch the only way to find out what the floor could see was to spend a number
    # on the question. That makes the floor's own correctness the one property nobody re-tests, which
    # is how it went a whole release reading two refs while its header promised all of them. A gate
    # that cannot be inspected without altering the thing it guards will not be inspected.
    [switch]$ShowFloor,
    # Record the claim against ANOTHER live worktree of this clone -- the one that will commit the
    # number -- instead of the tree this allocator runs in. See the -For discussion in .DESCRIPTION:
    # it names the owner at BIRTH and never moves an existing claim, so it is not the transfer verb
    # docs/LEDGER-GATE.md declined.
    [string]$For
)

$ErrorActionPreference = "Stop"

# ANCHOR ON THE SCRIPT, NOT ON THE CURRENT DIRECTORY (BACKLOG #1060). Unanchored, every `git` call below
# resolved against wherever the shell happened to be standing, so an absolute `-File` invocation from
# worktree A while intending to commit from worktree B recorded the claim to A. The ledger gate then
# refused B's commit -- correctly, fails closed, nothing invalid lands -- but far from the cause and with
# a message about the wrong thing. It also cost a number: holes are free, collisions are not.
#
# `git -C $PSScriptRoot` rather than `Split-Path`, which is what the sibling scripts in scripts/dev use.
# The recorded `worktree` value is COMPARED, by ledger_check.py:227 and by -List below, so its string form
# is part of a contract: `--path-format=absolute` returns the forward-slash absolute form every claim
# already on disk carries, and `Split-Path` would start writing backslashes into the same field. Both
# comparisons normalise separators today, so this is not a live break -- it is a field whose format
# nothing pins, and changing it for no reason is how the next reader's grep stops matching.
#
# Every `git` call in this file is anchored the same way for the same reason. The floor's working-tree
# term (below) is the one where an unanchored read is more than misattribution: it looks for numbers
# written but committed NOWHERE, so reading the caller's tree makes a number drafted in the TARGET tree
# invisible and free to re-issue -- the collision this whole script exists to prevent.
$repo = (& git -C $PSScriptRoot rev-parse --path-format=absolute --show-toplevel 2>$null)
if (-not $repo) { throw "scripts/coord/ is not inside a git repository: $PSScriptRoot" }
$repo = $repo.Trim()
$common = (& git -C $repo rev-parse --path-format=absolute --git-common-dir).Trim()
$allocRoot = Join-Path $common "mefor-coord/alloc"
$alloc = Join-Path $allocRoot $Kind
New-Item -ItemType Directory -Force -Path $alloc | Out-Null

if ($List) {
    foreach ($k in @("adr", "backlog")) {
        $dir = Join-Path $allocRoot $k
        $mine = @(Get-ChildItem $dir -Filter *.json -EA SilentlyContinue | ForEach-Object {
                $c = Get-Content $_.FullName -Raw | ConvertFrom-Json
                if (($c.worktree -replace '\\', '/').TrimEnd('/') -ieq ($repo -replace '\\', '/').TrimEnd('/')) { $c }
            })
        Write-Host "$k allocated to this worktree: $(if ($mine) { ($mine.number -join ', ') } else { '(none)' })"
    }
    return
}

# -ShowFloor allocates nothing, so there is no claim for a title to be recorded against.
if (-not $Title -and -not $ShowFloor) { throw "-Title is required (it is recorded with the claim, so a sibling session can see what the number is for)." }

# `git branch --show-current` prints NOTHING on a detached HEAD, so `& git ...` yields $null (not "")
# -- calling .Trim() on it here threw *before* the detached-HEAD fallback below could run. Null-check first.
$branch = & git -C $repo branch --show-current
if ([string]::IsNullOrWhiteSpace($branch)) { $branch = "detached@" + (& git -C $repo rev-parse --short HEAD) }
$branch = $branch.Trim()

# THE RECORDED OWNER, WHICH IS NOT NECESSARILY THE TREE WE ARE RUNNING IN.
#
# $repo stays the tree the FLOOR is computed against -- every sweep below reads this checkout, and
# repointing it at -For would make a number drafted here invisible and free to re-issue, which is the
# collision the whole script exists to prevent. Only the two recorded fields move.
$ownerRepo = $repo
$ownerBranch = $branch
if ($For) {
    # Resolve through git rather than through the filesystem, so the recorded string is BYTE-IDENTICAL
    # to what ledger_check.py will compute when it runs there. Both comparisons casefold and swap
    # separators today, so this is belt and braces -- but the recorded value is a field nothing pins,
    # and deriving it two different ways is how the two definitions start drifting.
    $target = (& git -C $For rev-parse --path-format=absolute --show-toplevel 2>$null)
    if (-not $target) { throw "-For '$For' is not inside a git worktree, so a claim recorded to it could never be committed." }
    $target = $target.Trim()
    # SAME CLONE, CHECKED. The registry lives under this clone's common dir, so a claim recorded to a
    # worktree of a DIFFERENT clone is stranded the instant it is written: that clone has its own
    # registry and will never look here. Refusing beats writing an unusable claim.
    $targetCommon = (& git -C $target rev-parse --path-format=absolute --git-common-dir 2>$null)
    if (-not $targetCommon) { throw "-For '$For' has no resolvable git common dir." }
    if (($targetCommon.Trim() -replace '\\', '/').TrimEnd('/') -ine ($common -replace '\\', '/').TrimEnd('/')) {
        throw "-For '$target' belongs to a DIFFERENT clone. Its allocations live in that clone's own registry, so a claim written here would never be found."
    }
    $ownerRepo = $target
    $ownerBranch = & git -C $target branch --show-current
    if ([string]::IsNullOrWhiteSpace($ownerBranch)) { $ownerBranch = "detached@" + (& git -C $target rev-parse --short HEAD) }
    $ownerBranch = $ownerBranch.Trim()
}

# FLOOR = max over (origin/main) U (every local + remote ref) U (existing allocations).
function Get-Floor {
    # -Peek computes the floor WITHOUT advancing the high-water ratchet. The ratchet is a one-way
    # door, so an inspection that moves it is not an inspection -- and the first run of -ShowFloor
    # against a deliberately planted number proved it, ratcheting this clone from 316 to a fabricated
    # 990 that no later run could undo. Reading a value must not be able to corrupt it.
    param([switch]$Peek)

    $seen = [System.Collections.Generic.List[int]]::new()
    $seen.Add(0)

    if ($Kind -eq "adr") {
        # Batched for the reason the backlog branch below was batched, and it is the same measurement
        # taken again on a bigger clone: one `git ls-tree` PER REF is one PROCESS per ref, and this
        # clone now carries 7,196 of them. Measured 2026-09-11 -- 359.7s for a single -ShowFloor, and
        # over 17 minutes for the session that reported it, which lost two tool timeouts before its
        # allocation returned. The refs collapse hard: 7,199 specs resolve to 434 DISTINCT docs/adr
        # trees. So resolve every ref in ONE `cat-file --batch-check`, dedupe the tree ids, and read
        # each distinct tree ONCE. Measured on this clone: 359.7s -> 6.7s, same 181 numbers, same max.
        #
        # A TREE, NOT A BLOB, is the difference from the backlog branch. A directory has no fixed path
        # to hand `--batch-check`, so the dedupe collapses to distinct TREE ids and each distinct tree
        # is listed once. The refs are what exploded; the trees never were.
        #
        # THE SAVING IS THE DEDUPE, NOT A CLEVERER READER. 7,199 specs collapse to 434 trees, which is
        # a 16x cut in processes and the whole of the fix. Two spellings of stage 2 that tried to go
        # further were BUILT, MEASURED AND REVERTED, and both failed the same way -- silently, by
        # losing a name, which is a number that then reads as FREE:
        #
        #   `git rev-list --objects` dedupes by OBJECT, so two ADR files with byte-identical content
        #   print ONE of their two names. Measured: `0150-alpha.md` and `0151-beta.md` sharing a blob
        #   printed one name, which would re-issue 0151 over a live ADR.
        #
        #   Scanning the RAW TREE BYTES through the pipeline, anchored on `(?:100644|100755) `, broke
        #   TWICE. (a) A tree entry carries 20 RAW bytes of object id, and PowerShell decodes native
        #   output with [Console]::OutputEncoding -- the OEM console code page on Windows. Under a
        #   DBCS page a lead byte at the end of one entry's id CONSUMES the `1` that starts the next
        #   entry's `100644`, and that entry vanishes. Measured on this clone: cp932 lost 7 of 181
        #   numbers, cp936/949/950 lost 17, while utf-8 and cp1252 lost none. End to end on a fixture
        #   with `chcp` set before pwsh started, the floor fell from 999 to 100 and the next
        #   allocation would have landed on a live ADR. The comment that shipped it argued no
        #   multi-byte decode could swallow an ASCII byte; that is true of UTF-8 and false of DBCS.
        #   (b) The mode literal admitted regular files only, where `ls-tree` reports EVERY mode, so
        #   an ADR kept as a directory (`docs/adr/0199-with-assets/`, mode 040000) or as a symlink to
        #   its replacement (120000) became invisible.
        #
        # SO STAGE 2 IS `ls-tree` PER DISTINCT TREE, and it is the boring spelling on purpose. It
        # emits TEXT that git already decoded, so no console code page can touch it, and it reports
        # every mode, so no entry shape can hide from it. It costs 434 processes here instead of one
        # -- about 40s against the 5s the byte scan managed and the 359.7s this branch started at.
        # That trade is deliberate: the failures it buys out are both SILENT, and this script exists
        # to prevent exactly the collision they cause.
        #
        # `alloc_strand_sweep.py::numbers_on_refs` is the same sweep in Python and now the same shape.
        # Two implementations of one question drift; change one and read the other.
        $refs = @("origin/main") + @(& git -C $repo for-each-ref --format='%(refname)' refs/heads refs/remotes)
        $specs = foreach ($r in ($refs | Select-Object -Unique)) { "${r}:docs/adr" }

        $trees = [System.Collections.Generic.HashSet[string]]::new()
        foreach ($line in ($specs -join "`n" | & git -C $repo cat-file --batch-check='%(objectname) %(objecttype)' 2>$null)) {
            $p = "$line".Split(' ')
            if ($p.Count -ge 2 -and $p[1] -eq 'tree') { [void]$trees.Add($p[0]) }
        }

        # Anchored at `^` because these are bare entry names, not the `docs/adr/NNNN-` paths the
        # pre-dedupe spelling produced. `--name-only` yields one name per line and nothing else.
        $rx = [regex]::new('^(\d{4})-')
        foreach ($t in $trees) {
            foreach ($n in (& git -C $repo ls-tree --name-only $t 2>$null)) {
                $m = $rx.Match("$n")
                if ($m.Success) { $seen.Add([int]$m.Groups[1].Value) }
            }
        }
    } else {
        # BACKLOG.md is ONE BIG FILE, so the floor needs its CONTENT, not a filename listing -- but it
        # still needs EVERY ref, exactly like the adr branch above and exactly as this function's own
        # header comment promises. Reading only origin/main + HEAD is what re-issued #240-#247 on
        # 2026-07-30 over numbers ADR 0115 and seven amended ADRs already cite: the items holding
        # those numbers live on refs the published branch does not carry, so they were invisible here
        # and the allocator handed the numbers out as free. A number that exists on ANY ref is taken.
        #
        # Batched deliberately: ~550 refs share ~190 distinct BACKLOG.md blobs, and a `git show` per
        # ref costs ~34s on Windows (one process each). Two `git cat-file` processes do it in ~3s.
        # THE NUMBER SPACE SPANS TWO PATHS. Retiring an item MOVES it verbatim out of docs/BACKLOG.md
        # and into docs/archive/backlog/BACKLOG-CLOSED.md. Sweeping only the published file would make
        # every archived number invisible here and free to re-issue -- the #240-#247 shape again, just
        # sourced from a different blind spot. A number that exists in EITHER file, on ANY ref, is taken.
        #
        # The archive is ONE file with a FIXED name on purpose: `cat-file --batch-check` takes a spec
        # list and cannot glob a directory, so a per-ref `git ls-tree -r` would be needed to discover
        # archive filenames -- one process per ref, the ~34s cost the batching below exists to avoid.
        # A fixed second spec keeps the sweep at two processes. Splitting the archive into several
        # files means adding each one here; an archive file not listed here is not policed.
        $backlogPaths = @("docs/BACKLOG.md", "docs/archive/backlog/BACKLOG-CLOSED.md")

        $refs = @("origin/main", "HEAD") + @(& git -C $repo for-each-ref --format='%(refname)' refs/heads refs/remotes)
        $specs = foreach ($r in ($refs | Select-Object -Unique)) {
            foreach ($p in $backlogPaths) { "${r}:${p}" }
        }

        $oids = [System.Collections.Generic.HashSet[string]]::new()
        foreach ($line in ($specs -join "`n" | & git -C $repo cat-file --batch-check='%(objectname) %(objecttype)' 2>$null)) {
            $p = "$line".Split(' ')
            if ($p.Count -ge 2 -and $p[1] -eq 'blob') { [void]$oids.Add($p[0]) }
        }

        # GIT FILTERS; POWERSHELL DOES NOT (BACKLOG #1535). Stage 1 above is already batched, so this
        # branch never had the adr branch's one-process-per-ref defect. Its cost was BYTE VOLUME: the
        # 1,518 distinct blobs average ~2.8 MB, so feeding them through `cat-file --batch` shipped
        # ~4.2 GB and 24.5 MILLION pipeline objects into PowerShell to keep ~500 thousand lines. Only
        # ~13s of a ~111s stage was git. `git grep` applies the pattern in C and emits the headings
        # only: 526,162 lines, 4.3 MB, a 46x drop in objects and a 984x drop in bytes.
        #
        # PROVEN BY SET EQUALITY, NOT BY A STOPWATCH. Both spellings were run over the same 1,518 oids
        # on this clone: 855 distinct numbers, max 1535, SubFloorMax 354, `Compare-Object` empty in
        # BOTH directions. Re-verify that way, never by comparing floors -- the printed floor is the
        # union max and the REGISTRY term carries it, so this whole stage can return nothing and the
        # floor will not move. Measured: registry max 1537 against all-refs max 1536, and 61 numbers
        # live on refs and nowhere else.
        #
        # EVERY FLAG BELOW IS A SILENT-ZERO GUARD, and each was reproduced rather than assumed:
        #   -h      without it git prefixes `<oid>:` and the anchored extraction matches 0 of 314 lines
        #   -o      emits the heading alone: same line count, 4.3 MB instead of 55.1 MB
        #   -a      git otherwise prints `Binary file <oid> matches` and drops the lines. 0 of 1,518
        #           blobs trip it today, and `cat-file` had no such gate, so this is a failure mode the
        #           port INTRODUCES -- one NUL from a bad merge would zero a blob's contribution
        #   --no-color --no-line-number --no-column
        #           `color.ui=always`, `grep.lineNumber` and `grep.column` each prefix every line and
        #           each takes the extraction to 0. This stage reads git config that `cat-file` never
        #           did; these three neutralise it
        #   -E -e   `grep.patternType=fixed` turns the pattern into a literal without an explicit -E
        #
        # `[0-9]`, NEVER `\d`. Git's POSIX ERE HAS NO `\d`: the pattern matches ZERO lines corpus-wide
        # and exits 1, which reads as "no numbers on any ref" and frees every one of them. That is the
        # #240-#247 shape this term exists to prevent, and transcribing the .NET regex below is all it
        # takes to get there.
        $chunk = 128
        if ($oids.Count -gt 0) {
            $rxGrep = [regex]::new('^#{2,3} ([0-9]+)\.$')
            $oidList = @($oids)
            for ($i = 0; $i -lt $oidList.Count; $i += $chunk) {
                $slice = @($oidList[$i..([Math]::Min($i + $chunk - 1, $oidList.Count - 1))])

                # BOTH RESETS ARE LOAD-BEARING. An over-long argument list is not a non-zero exit: git
                # never starts, `$LASTEXITCODE` keeps its PREVIOUS value and `$out` keeps the PREVIOUS
                # slice's output, so an unguarded loop re-adds the last slice and skips this one with
                # no error.
                #
                # Ceiling bisected on this clone 2026-09-11, with a 72-char repo path: 794 oids run
                # and 795 does not, at roughly 32,710 chars against Windows' 32,767-char CreateProcess
                # limit. The message it fails with names StandardOutputEncoding, not the length, so
                # the argv cause is not discoverable from the error. A chunk of 128 leaves 666 spare
                # oids, about 27,300 characters of slack for a longer repo path, and the extra
                # processes are free against a stage that used to stream 4.2 GB. Both figures move
                # with the repo path, so re-bisect rather than trusting them elsewhere.
                $out = $null
                $global:LASTEXITCODE = -1
                $out = & git -C $repo grep -h -o -a --no-color --no-line-number --no-column -E -e '^#{2,3} [0-9]+\.' @slice 2>$null
                # THE EXIT CODE IS THE WITNESS, AND `$?` IS NOT. For a native command PowerShell sets
                # `$?` from the exit code, so `if (-not $?)` is true for git grep's exit 1 as well as
                # for a fatal -- and exit 1 means "no match", which is LEGITIMATE. Measured: a blob
                # with no numbered heading exits 1 with `$?` False. An earlier spelling threw there,
                # which made a repository whose ledger blobs carry no heading yet -- a fresh clone of
                # this tooling -- unable to allocate a backlog number AT ALL, and left the accurate
                # exit-code message below as dead code that could never print.
                #
                # -1 is the sentinel from the reset above and means git NEVER RAN: an over-long
                # argument list does not set an exit code, and without the sentinel the stale value
                # from the previous slice reads as success while `$out` still holds that slice's
                # output. 0 = matched, 1 = no match, 128 = fatal -- and a fatal aborts the WHOLE slice
                # for zero lines, so up to 128 blobs' numbers vanish at once.
                if ($LASTEXITCODE -lt 0) { throw "git grep never ran over backlog blobs $i..$($i + $slice.Count - 1). An over-long argument list reports a StandardOutputEncoding error rather than the real cause; lower `$chunk` before believing anything else." }
                if ($LASTEXITCODE -gt 1) { throw "git grep exited $LASTEXITCODE over backlog blobs $i..$($i + $slice.Count - 1); the whole slice returned nothing." }

                foreach ($line in $out) {
                    $m = $rxGrep.Match("$line")
                    # THROW, DO NOT SKIP. `$` anchors the whole emitted line, so a non-match means git
                    # emitted something we did not ask for -- a prefix from config, an ANSI escape, a
                    # binary notice. Skipping turns each of those into a number-free blob reported as
                    # clean; throwing turns a silent zero into a loud failure.
                    if (-not $m.Success) { throw "git grep emitted a line that is not a bare heading: [$line]" }
                    $seen.Add([int]$m.Groups[1].Value)
                }
            }
        }
        # MULTILINE IS LOAD-BEARING HERE, and its absence was a silent hole. `[regex]'^...'` anchors at
        # the start of the STRING, not of each line. The all-refs term above feeds one line at a time,
        # so `^` matched there and looked correct -- but this term feeds `Get-Content -Raw`, one string
        # starting "# Backlog", where `^` could never match. Measured on this tree: 0 of 277 headings
        # found without Multiline, 277 with. So the term that exists to catch a number written but
        # committed NOWHERE was finding nothing, and the all-refs term hid it by covering every number
        # committed somewhere -- i.e. every case except the one this term is for.
        #
        # ITS OWN VARIABLE, deliberately. The two regexes used to be one `$rx`, and that sharing is a
        # trap now that the grep path visibly does not need Multiline: tidying the flag away because
        # the loop above works fine without it returns THIS term to 0 of 749.
        #
        # THE TWO SPELLINGS DIVERGE ON PURPOSE AND THE ASYMMETRY IS SAFE. Git has no `\d` so the grep
        # pattern must say `[0-9]`; .NET `\d` also matches non-ASCII Unicode digits. Census over all
        # 1,518 blobs with PCRE, whose `\d` IS Unicode-aware: exactly 0 headings differ. Kept as `\d`
        # so this file still agrees character-for-character with ledger_check.py and
        # alloc_strand_sweep.py, which police the same headings in Python. Note that a heading with
        # non-ASCII digits would throw in `[int]::Parse` below, so `\d` is a latent crash rather than a
        # capability -- if that ever fires, narrow all four to `[0-9]` together, not this one alone.
        $rx = [regex]::new('^#{2,3} (\d+)\.', [System.Text.RegularExpressions.RegexOptions]::Multiline)
        # Working-tree term: catches a number written to a file but committed nowhere. Both paths, for
        # the same reason -- an item drafted straight into the archive is still a claim on its number.
        foreach ($p in $backlogPaths) {
            $wip = Join-Path $repo $p
            if (Test-Path $wip) {
                foreach ($m in $rx.Matches((Get-Content $wip -Raw))) { $seen.Add([int]$m.Groups[1].Value) }
            }
        }
    }

    foreach ($f in (Get-ChildItem $alloc -Filter *.json -EA SilentlyContinue)) {
        $n = 0
        if ([int]::TryParse($f.BaseName, [ref]$n)) { $seen.Add($n) }
    }

    # HIGH-WATER RATCHET -- the floor may rise but must never fall.
    #
    # Every other term above is derived from refs that a routine cleanup can remove. Measured on this
    # clone: the backlog floor is 314 counting all refs, but only 252 counting `refs/remotes/origin`
    # and local heads -- the missing 62 live on remote-tracking refs for a remote that `git remote -v`
    # no longer lists. Drop those and the floor silently reverts to the pre-fix value and the allocator
    # resumes issuing numbers that are already used, with no error and no signal. That is the exact bug
    # this function was fixed for, so leaving its correctness dependent on nobody tidying refs is not
    # good enough: persist the high-water mark and never go below it.
    #
    # SAFE:      `git fetch origin --prune` -- prunes only refs/remotes/origin/*, which is not where the
    #            high numbers live. It is also what you SHOULD run before allocating.
    # DANGEROUS: `git remote prune <name>` / `git remote remove <name>` for a non-origin remote,
    #            deleting refs/<vault-ish>/*, or an aggressive `gc` / `reflog expire` that drops
    #            unreachable objects. Those are what this ratchet defends against.
    # MEASURED 2026-08-05, and it narrows the alarm without retiring the rule: those 489 vault-ish refs
    #            WERE deleted (refs/remotes/vaultall/** 466, refs/remotes/vault/** 20, refs/vault/** 3;
    #            manifest kept outside the repo, every tip still addressable here and present in the
    #            separate vault clone). Floor 1032 and sub-floor max 353 were unchanged before and after:
    #            the #1000 partition clamps every new number above the internal band, and internal 314
    #            was already masked by public 353 (reason (d) below). So the hazard is still real in
    #            general -- a clone whose high numbers live ONLY on non-origin refs still loses them --
    #            and it no longer binds HERE. The ratchet stays: it is the one term that survives a clone
    #            that never had those refs at all. Provenance and full measurement:
    #            docs/LEDGER-GATE.md "The ref store, and the cleanup of 2026-08-05".
    $watermark = Join-Path $alloc ".floor-highwater"
    $computed = [int](($seen | Measure-Object -Maximum).Maximum)
    $previous = 0
    if (Test-Path $watermark) { [void][int]::TryParse((Get-Content $watermark -Raw).Trim(), [ref]$previous) }

    if ($previous -gt $computed) {
        Write-Host "NOTE: computed $Kind floor $computed is BELOW the recorded high-water $previous." -ForegroundColor Yellow
        Write-Host "      Using $previous. Refs that carried the higher numbers are missing from this clone;" -ForegroundColor Yellow
        Write-Host "      re-fetch them before trusting any number-space reasoning here." -ForegroundColor Yellow
    }
    $floor = [Math]::Max($computed, $previous)
    if ($floor -gt $previous -and -not $Peek) { Set-Content -Path $watermark -Value $floor -Encoding ASCII }

    # TWO NUMBERS, NOT ONE -- and conflating them is what bricked this script on 2026-08-03.
    #
    # `Floor` is the whole observed set's maximum. It answers "what must I not re-issue", so it MUST
    # include public numbers.
    #
    # `SubFloorMax` is the maximum BELOW the partition. It answers a different question -- "how much
    # runway does the maintainer-internal sequence have left" -- and it must EXCLUDE public numbers,
    # because a public item at or above the boundary is the design working, not a breach.
    #
    # Returning one number for both is not a style problem. The residual detector below read `Floor`,
    # so the first legitimate public item filed at #1000 made the guard throw on every subsequent
    # backlog allocation, repo-wide, until it was patched. The guard fired on correct input.
    #
    # `[int]` on both: Measure-Object hands back a [double], and the 'D4' format specifier is
    # integer-only and throws on one.
    [pscustomobject]@{
        Floor       = [int]$floor
        SubFloorMax = [int](($seen | Where-Object { $_ -lt $PublicBacklogFloor } | Measure-Object -Maximum).Maximum)
    }
}

# THE FLOOR IS DEFINED ONCE, IN THE GATE, AND READ HERE.
#
# Two integers that must agree is the next place this rots: the allocator would go on emitting numbers
# the gate refuses, and the tool would be sending people straight into a blocked commit while insisting
# it had given them a valid number. So parse it out of ledger_check.py rather than restating it, and
# REFUSE to allocate a backlog number if it cannot be read -- guessing a floor the gate will not honour
# is the failure this whole partition exists to prevent, reintroduced by its own tooling.
$gateFile = Join-Path $repo "scripts/hooks/ledger_check.py"
$PublicBacklogFloor = $null
if (Test-Path $gateFile) {
    # The optional `(?::[^=]+)?` tolerates a type annotation. `PUBLIC_BACKLOG_FLOOR: Final[int] = 1000`
    # is idiomatic in a mypy-strict codebase and would otherwise fail to match -- silently disarming
    # every backlog allocation as the result of an ordinary tidy-up. tests/test_ledger_check.py pins
    # this contract so the break lands in CI on whoever edits the constant, not on a session days later.
    $m = [regex]::Match((Get-Content $gateFile -Raw), '(?m)^PUBLIC_BACKLOG_FLOOR\s*(?::[^=]+)?=\s*(\d+)')
    if ($m.Success) { $PublicBacklogFloor = [int]$m.Groups[1].Value }
}

$measured = Get-Floor -Peek:$ShowFloor
$observed = $measured.Floor
$subFloorMax = $measured.SubFloorMax

# Both checks are evaluated ONCE, here, so -ShowFloor and a real allocation cannot disagree. They did:
# -ShowFloor returned 19 lines before the guard, so it printed a next number while every real
# allocation threw. An inspector that does not run the checks it previews reports a number the tool
# will refuse to issue -- it answers the adjacent question, which is the failure CLAUDE.md §11 names.
$warnAt = if ($null -ne $PublicBacklogFloor) { [int]($PublicBacklogFloor * 0.9) } else { 0 }
$residualWarning = ($Kind -eq "backlog") -and ($null -ne $PublicBacklogFloor) -and ($subFloorMax -ge $warnAt)

# THE BOUNDARY RATCHET -- the one refusal this data can actually justify.
#
# PUBLIC_BACKLOG_FLOOR is a constant in a source file, so it can be LOWERED: a bad revert, a merge
# resolved the wrong way, a tidy-up. Lower it to 900 and ledger_check.py cheerfully accepts a new
# public #900 sitting on top of an internal #900 -- with a GREEN pre-commit and a GREEN CI, because a
# runner has no memory of yesterday's value and the constant is the only thing either consults.
#
# A ratchet OUTSIDE the constant is the only instrument that can see this, and unlike the boundary
# check it replaces, it is genuinely reachable: it triggers on an observable local fact (the value
# moved down) rather than on an integer whose provenance cannot be recovered.
#
# THREE QUANTITIES, THREE PURPOSES -- keep them strictly separate:
#   $observed     (union max)      -> $start / the next number, ONLY
#   $subFloorMax  (below boundary) -> the WARNING, ONLY
#   $boundarySeen (highest floor)  -> the REFUSAL, ONLY
$boundaryMark = Join-Path $alloc ".boundary-highwater"
$boundarySeen = 0
if (Test-Path $boundaryMark) { [void][int]::TryParse((Get-Content $boundaryMark -Raw).Trim(), [ref]$boundarySeen) }
$boundaryLowered = ($Kind -eq "backlog") -and ($null -ne $PublicBacklogFloor) -and ($PublicBacklogFloor -lt $boundarySeen)

if ($ShowFloor) {
    # Name the SOURCES, not just the number. "Which files did this sweep actually read" is the
    # question every silent-narrowing bug turns on, and a bare integer cannot answer it -- a floor of
    # 353 looks identical whether it swept one path or two.
    Write-Host "kind     : $Kind"
    Write-Host "floor    : $observed"
    if ($Kind -eq "backlog") {
        Write-Host "paths    : docs/BACKLOG.md, docs/archive/backlog/BACKLOG-CLOSED.md"
        Write-Host "sub-floor: $subFloorMax  (highest number BELOW the #$PublicBacklogFloor boundary; over-states the internal high-water)"
        Write-Host "boundary : $PublicBacklogFloor  (highest ever seen on this clone: $boundarySeen)"
        Write-Host "next     : $([Math]::Max($observed, $PublicBacklogFloor - 1) + 1)  (clamped to >= $PublicBacklogFloor)"
    } else {
        Write-Host "paths    : docs/adr/NNNN-*.md (filenames, all refs)"
        Write-Host "next     : $($observed + 1)"
    }
    Write-Host "watermark: $(Join-Path $alloc '.floor-highwater')"
    if ($boundaryLowered) {
        Write-Host ""
        Write-Host "WOULD REFUSE: PUBLIC_BACKLOG_FLOOR is $PublicBacklogFloor but this clone has allocated against $boundarySeen." -ForegroundColor Red
    }
    if ($residualWarning) {
        Write-Host ""
        Write-Host "WOULD WARN: highest sub-boundary number $subFloorMax has reached 90% of #$PublicBacklogFloor." -ForegroundColor Yellow
    }
    Write-Host ""
    Write-Host "Read-only: nothing was allocated." -ForegroundColor DarkGray
    return
}

if ($Kind -eq "backlog") {
    if ($null -eq $PublicBacklogFloor) {
        throw "Could not read PUBLIC_BACKLOG_FLOOR from $gateFile. Refusing to allocate a backlog number rather than guess a floor the gate will not honour."
    }

    # WHY THE OLD "INTERNAL REACHED THE BOUNDARY" REFUSAL IS GONE.
    #
    # It compared the WHOLE-SET maximum against the floor, so the first legitimate public item filed at
    # #1000 (BACKLOG #1000, 2026-08-03) made every subsequent backlog allocation throw, repo-wide. It
    # was not detecting a breach; it was detecting the partition being used exactly as designed.
    #
    # It is NOT that this clone cannot see internal numbers -- that was suspected and is false.
    # Measured 2026-08-03, while the vault-ish refs were still here: 490 present, 489 carrying
    # docs/BACKLOG.md, and 67 item numbers living ONLY there, including the #242-#246 band ADR 0115
    # cites. The sweep did reach them, and that is exactly why the floor was trustworthy. (Those 489
    # refs were DELETED on 2026-08-05 -- docs/LEDGER-GATE.md has the provenance and the manifest's
    # whereabouts -- so this clone is now case (c) below. Floor 1032 and sub-floor max 353 were measured
    # unchanged across the deletion, for reason (d).)
    #
    # The premise fails for four other reasons, any ONE of them fatal:
    #   (a) NO PROVENANCE. An integer does not say which sequence issued it. "Internal reached the
    #       boundary" and "public was legitimately allocated at the boundary" are the SAME observation
    #       -- which is why #1000, on origin/main and holding a registry claim, read as a breach.
    #   (b) FOSSIL. The newest vault-ish ref was 2026-07-26 and the only configured refspec is
    #       +refs/heads/*:refs/remotes/origin/*, so nothing could advance them. The partition landed
    #       eight days later. (Measured: those refs said 314 while the real vault was at 315 -- the
    #       fossil was already stale by one item.)
    #   (c) CLONE-LOCAL. A fresh public clone has zero vault refs, so the term is absent entirely --
    #       and since the 2026-08-05 deletion, so does this one.
    #   (d) MASKED. Internal 314 < public 353, so the internal term never determined the sub-boundary
    #       maximum -- which is why deleting those refs moved neither number.
    #
    # So the refusal moved to a trigger that IS observable and IS reachable -- the boundary ratchet
    # above, which fires when PUBLIC_BACKLOG_FLOOR is lowered beneath a value this clone has already
    # allocated against. What remains here is a warning only.
    #
    # $subFloorMax is "the highest number below the boundary", NOT "the internal maximum". It includes
    # public pre-partition numbers, so it deliberately OVER-states the internal high-water: it warns
    # early rather than late, which is the safe direction for a runway indicator.
    if ($boundaryLowered) {
        throw @"
REFUSING TO ALLOCATE. PUBLIC_BACKLOG_FLOOR is $PublicBacklogFloor, but this clone has already
allocated against a boundary of $boundarySeen. The constant was LOWERED beneath numbers that were
issued under the higher value, so the next number handed out could collide with the maintainer-internal
sequence -- and neither the pre-commit gate nor CI can see it, because both read only the current value
of the constant and have no memory of the previous one.

Restore PUBLIC_BACKLOG_FLOOR in scripts/hooks/ledger_check.py to at least $boundarySeen. If the
reduction is deliberate, delete $boundaryMark and say why in the PR.
"@
    }
    if ($residualWarning) {
        Write-Host ""
        Write-Host "WARNING: the highest sub-partition number ($subFloorMax) has reached 90% of the #$PublicBacklogFloor boundary." -ForegroundColor Yellow
        Write-Host "         The maintainer-internal sequence is running out of room below the partition." -ForegroundColor Yellow
        Write-Host "         Raise PUBLIC_BACKLOG_FLOOR in scripts/hooks/ledger_check.py (this script reads" -ForegroundColor Yellow
        Write-Host "         it from there) BEFORE the two sequences meet, and say so in the PR. Once they" -ForegroundColor Yellow
        Write-Host "         meet, nothing in this repository can tell the two apart." -ForegroundColor Yellow
        Write-Host ""
    }
    # Record the boundary we are about to allocate under. Only rises; only on a real allocation.
    if ($PublicBacklogFloor -gt $boundarySeen) {
        Set-Content -Path $boundaryMark -Value $PublicBacklogFloor -Encoding ASCII
    }

    # $observed IS THE UNION MAXIMUM HERE, DELIBERATELY, AND MUST STAY THAT WAY.
    #
    # The tempting "fix" for the #1000 brick is to repoint $observed at the sub-boundary maximum, since
    # that is what the guard should have read. Do not: $start would become max(353, 999) + 1 = 1000 --
    # a number already merged on origin/main -- and in a FRESH clone, whose registry is empty, the
    # atomic CreateNew has no claim file to collide with and would NOT catch the re-issue. The union
    # maximum is what makes "never hand out a number that exists anywhere" true; the sub-boundary
    # maximum answers a different question and belongs only to the warning above.
    $start = [Math]::Max($observed, $PublicBacklogFloor - 1) + 1
}
else {
    $start = $observed + 1
}
for ($i = $start; $i -lt $start + 500; $i++) {
    $name = if ($Kind -eq "adr") { "{0:D4}" -f $i } else { "$i" }
    $file = Join-Path $alloc "$name.json"
    try {
        # ATOMIC test-and-set. 'CreateNew' + FileShare::None throws IOException if a sibling got here
        # first -- that throw IS the mutual exclusion.
        $fs = [System.IO.File]::Open($file, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
    } catch [System.IO.IOException] {
        continue    # taken by a sibling session; try the next number
    }
    try {
        $claim = [ordered]@{
            number   = $name
            kind     = $Kind
            title    = $Title
            branch   = $ownerBranch
            worktree = $ownerRepo
            claimed  = (Get-Date).ToString("o")
        } | ConvertTo-Json -Compress
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($claim)
        $fs.Write($bytes, 0, $bytes.Length)
    } finally {
        $fs.Dispose()
    }

    Write-Host ""
    if ($Kind -eq "adr") {
        $slug = ($Title.ToLowerInvariant() -replace '[^a-z0-9]+', '-').Trim('-')
        Write-Host "ALLOCATED ADR $name" -ForegroundColor Green
        Write-Host "  file  : docs/adr/$name-$slug.md"
        Write-Host "  index : add its row to docs/adr/README.md in the SAME commit (the gate checks)."
    } else {
        Write-Host "ALLOCATED BACKLOG #$name" -ForegroundColor Green
        Write-Host "  heading : ## $name. $Title"
        Write-Host "  file    : docs/BACKLOG.md"
    }
    Write-Host "  claimed by: $ownerRepo [$ownerBranch]"

    # -For is a deliberate redirection, so the surprise note below (which fires on the ACCIDENTAL kind)
    # would be noise. Say the useful thing instead: which tree has to do the committing.
    if ($For) {
        Write-Host "  -For: recorded to the named worktree, NOT the one this ran in. Commit from" -ForegroundColor Yellow
        Write-Host "        $ownerRepo -- the gate will refuse it anywhere else." -ForegroundColor Yellow
    }

    # SAY IT AT THE POINT OF USE when the shell is standing somewhere else (BACKLOG #1060). Anchoring is
    # now correct, but it is also SURPRISING: a caller who runs this by absolute path from worktree A gets
    # a claim recorded to worktree B, and the only other place that fact surfaces is the ledger gate
    # refusing a commit later, elsewhere, with a message about the wrong thing. One line here turns a
    # deferred, misdirected refusal into an immediate, accurate note. Silent on the ordinary same-tree
    # invocation, so it stays worth reading.
    $cwdTop = (& git rev-parse --path-format=absolute --show-toplevel 2>$null)
    if ($cwdTop -and -not $For) {
        $a = ($cwdTop.Trim() -replace '\\', '/').TrimEnd('/')
        $b = ($repo -replace '\\', '/').TrimEnd('/')
        if ($a -ine $b) {
            Write-Host "  NOTE: your shell is in $a, but this allocator lives in $b, so the claim is recorded" -ForegroundColor Yellow
            Write-Host "        to $b. COMMIT FROM THERE -- the ledger gate keys entitlement on the worktree" -ForegroundColor Yellow
            Write-Host "        named above and will refuse the commit anywhere else." -ForegroundColor Yellow
        }
    }
    exit 0
}

throw "No free $Kind number found in 500 tries starting at $start -- the registry looks wrong."
