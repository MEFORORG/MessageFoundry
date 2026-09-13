# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
<#
.SYNOPSIS
    Allocate the next free ADR number, atomically, so two concurrent sessions can never take the same one.

    THE BACKLOG KIND IS RETIRED (BACKLOG #1250, #1754). The numbered-item ledger left this
    repository, so there is no backlog namespace here to allocate into. `-Kind` no longer accepts
    `backlog`; PowerShell refuses it at parameter binding, before any of this runs.

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
    every existing allocation -- over refs REFRESHED FIRST by a pre-flight `git fetch origin`, because
    every one of those terms reads refs THIS CLONE ALREADY HAS. The all-refs term closes the "registry
    wiped -> re-issue a number that only exists on an unpushed branch" hole WITHIN one clone. It does NOT
    close the same hole ACROSS clones, and reading it as though it did is how BACKLOG #1616 survived: a
    number a sibling clone pushed is invisible here until something fetches it. That is what the
    pre-flight block at the single Get-Floor call site does, what -NoFetch turns off, and what REFUSES
    rather than allocating when the fetch fails -- holes are free, collisions are not.
    NEITHER KIND SPAWNS A PROCESS PER REF, which is the property
    that matters: a per-ref sweep is fine at a few hundred refs and unusable at several thousand, and
    it does not announce the crossing (BACKLOG #1534). What each costs instead, COUNTED with GIT_TRACE
    on this clone on 2026-09-11 rather than reasoned about, and dated because both are live properties
    that drift:
      adr      440 git processes for the whole -ShowFloor run -- ref enumeration, one
               `cat-file --batch-check`, then one `ls-tree` per DISTINCT docs/adr tree, 434 here.
               It scales with distinct TREES, not with refs.
    An earlier version of this line said "TWO git processes" and was wrong twice over: it omitted the
    ref enumeration, and it described a stage 2 that has since been reverted. The cost is per
    allocation, not per edit. The retired backlog branch cost 18 and scaled with ledger blobs.

    Both counts PREDATE the pre-flight fetch (2026-09-12), which adds one `config --get` probe on every
    run and, when origin is reachable, a `fetch` plus git's own children -- 12 invocations for a whole
    small run over a local remote, measured. The counts for the test fixtures are re-measured and
    ASSERTED in tests/test_coord_alloc_floor.py, which is the copy to trust: these two are prose.

    Numbers are never reclaimed. An abandoned branch holds its number forever and the sequence develops
    holes. That is deliberate: holes are free, collisions are not.

    -For NAMES THE OWNER AT BIRTH. IT IS NOT A TRANSFER VERB, AND THE DIFFERENCE IS THE WHOLE ARGUMENT.
    A claim records the tree that will COMMIT the number, and by default that is the tree the allocator
    runs in. When one seat allocates on another seat's behalf -- a Manager reading the backlog and
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
    pwsh -NoProfile -File scripts\coord\alloc.ps1 -Kind adr -Title "Peer's ADR" -For C:\path\to\builder\worktree
    pwsh -NoProfile -File scripts\coord\alloc.ps1 -List
    pwsh -NoProfile -File scripts\coord\alloc.ps1 -Kind adr -Title "Offline ADR" -NoFetch
#>
[CmdletBinding()]
param(
    # ONE VALUE, AND THAT IS THE HARD STOP (BACKLOG #1754). `-Kind backlog` is refused by parameter
    # binding, before the script body runs, so there is no path through this file that can issue a
    # backlog number. Widening this set is how that guarantee would be lost.
    [ValidateSet("adr")]
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
    [string]$For,
    # Skip the pre-flight `git fetch origin` that runs at the Get-Floor call site below.
    #
    # THE DEFAULT IS TO FETCH. This switch disables the ONLY instrument that can see a number already
    # allocated in ANOTHER CLONE: with it set, the floor is computed from whatever refs this clone
    # happens to hold, so a number taken on a branch nobody here has fetched reads FREE.
    #
    # It exists for a genuinely OFFLINE box, not for a slow one. ONE SAMPLE, this clone, 2026-09-12:
    # the fetch took about 1.4s against a 38-42s backlog sweep, which is inside that sweep's own
    # run-to-run spread. One remote on one link does not generalise -- a high-latency or authenticating
    # remote is not 1.4s -- so the claim is that the fetch was free HERE, not that it is free anywhere.
    [switch]$NoFetch
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
    #
    # -FetchState is the CALLER'S ANSWER TO "was origin consulted", and it is a parameter because this
    # function cannot know. It prints a note when the ratchet fires, and that note used to end "the
    # caller already fetched it" unconditionally -- false on both skip paths, which is the same defect
    # class the note was rewritten to remove: prose asserting a control ran when it did not.
    param(
        [switch]$Peek,
        [ValidateSet("fetched", "skipped-nofetch", "skipped-no-origin")]
        [string]$FetchState = "fetched"
    )

    $seen = [System.Collections.Generic.List[int]]::new()
    $seen.Add(0)

    # ADR NUMBERS ONLY. The backlog branch that used to sit beside this one swept docs/BACKLOG.md
    # and docs/archive/backlog/BACKLOG-CLOSED.md across every ref; both files left this repository
    # with the ledger (BACKLOG #1250), so the sweep had no subject and went with them.
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
    #            high numbers live.
    # NOT ADVICE: this table says which CLEANUP operations break the ratchet, and nothing more. It used
    #            to end by telling you to run that same line before allocating, which is advice for the
    #            ALLOCATOR bolted onto a table about cleanup. The caller fetches for you by default --
    #            see the pre-flight block at the single Get-Floor call site -- and it passes --no-prune
    #            EXPLICITLY, because a fetch there exists to ADD refs, which can only RAISE the floor,
    #            while a prune only DELETES refs, which can only lower one and removes witnesses.
    #            Explicitly, not by omission: `fetch.prune` turns pruning on from CONFIG.
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

    # NAME THE CAUSE, AND DO NOT SEND THE OPERATOR AFTER A REMEDY THAT CANNOT WORK. This used to end
    # "re-fetch them before trusting any number-space reasoning here", which is wrong twice over now:
    # the caller usually HAS fetched origin by the time this prints, and the refs carrying those higher
    # numbers are NON-ORIGIN remote-tracking refs, which no fetch of origin can restore. What the caller
    # actually did is -FetchState's business, not this block's guesswork -- there are three answers and
    # the last line says which one applies.
    if ($previous -gt $computed) {
        Write-Host "NOTE: computed $Kind floor $computed is BELOW the recorded high-water $previous." -ForegroundColor Yellow
        Write-Host "      Using $previous, so the gap is already covered -- this is the ratchet working," -ForegroundColor Yellow
        Write-Host "      not something to act on. The refs that carried the higher numbers are gone from" -ForegroundColor Yellow
        Write-Host "      this clone: a non-origin remote was deleted, an aggressive gc or reflog expire" -ForegroundColor Yellow
        Write-Host "      dropped unreachable objects, or this clone never had them. Fetching origin does" -ForegroundColor Yellow
        Write-Host "      not restore any of those." -ForegroundColor Yellow
        switch ($FetchState) {
            "fetched" {
                Write-Host "      Origin WAS fetched before this was computed, so a stale origin is not a cause." -ForegroundColor Yellow
            }
            "skipped-nofetch" {
                Write-Host "      Origin was NOT fetched: -NoFetch was passed, so a number a sibling clone" -ForegroundColor Yellow
                Write-Host "      pushed is missing too -- and that one a fetch WOULD find. Re-run without it." -ForegroundColor Yellow
            }
            "skipped-no-origin" {
                Write-Host "      Origin was NOT fetched: this clone has no usable 'origin' url, so nothing" -ForegroundColor Yellow
                Write-Host "      here has consulted any remote at all." -ForegroundColor Yellow
            }
        }
    }
    $floor = [Math]::Max($computed, $previous)
    if ($floor -gt $previous -and -not $Peek) { Set-Content -Path $watermark -Value $floor -Encoding ASCII }

    # ONE NUMBER NOW. `Floor` is the whole observed set's maximum -- "what must I not re-issue" --
    # so it includes every number seen anywhere.
    #
    # `SubFloorMax` used to ride alongside it: the maximum BELOW the #1000 partition, answering how
    # much runway the maintainer-internal sequence had left. The partition, its warning and its
    # ratchet all belonged to the backlog kind and went with it (BACKLOG #1250, #1754). Returning
    # one number for two questions is what bricked this script on 2026-08-03; there is now one
    # question, so do not add a second field back without a reader for it.
    #
    # `[int]`: Measure-Object hands back a [double], and the 'D4' format specifier is integer-only
    # and throws on one.
    [pscustomobject]@{
        Floor = [int]$floor
    }
}

# THE #1000 PARTITION IS GONE, AND SO IS THE CONSTANT THIS BLOCK USED TO READ.
#
# This script used to regex `PUBLIC_BACKLOG_FLOOR` out of scripts/hooks/ledger_check.py so the floor
# was defined exactly once, and refuse to allocate a backlog number if it could not be read. The
# ledger left this repository (BACKLOG #1250) and the constant went with the gate half that used it
# (BACKLOG #1754), so there is nothing to read and no backlog number to guard.
#
# DO NOT RESTORE A DEFAULT HERE IF SOMETHING LATER WANTS A FLOOR. A missing constant read as a
# number would be the exact failure the old block refused: a floor the gate will not honour,
# guessed by the tool that hands out the numbers.

# PRE-FLIGHT FETCH -- THE ONLY INSTRUMENT THAT CAN SEE A NUMBER ALLOCATED IN ANOTHER CLONE.
#
# Every term in Get-Floor reads refs THIS CLONE ALREADY HAS, and until this block landed the script
# executed zero fetches. So when clone B has not fetched since clone A pushed a branch, A's ref is
# simply absent here: the number reads FREE, B allocates it, and B's ledger gate then passes
# CORRECTLY -- the number genuinely IS allocated in B's own registry. Two machines, one number, every
# gate green on both sides, and nothing anywhere reporting it. That happened on 2026-09-11: PR 1061
# wrote "## 1546." while #1546 was allocated and claimed to PR 1060.
#
# WHAT IT DOES NOT CLOSE, stated here because the fix reads as total and is not. A fetch can only
# see what has been PUSHED, so two clones that BOTH fetch cleanly still take one number when the
# first has not pushed yet. Measured 2026-09-12: A allocated 1000 and pushed nothing, B fetched
# successfully and allocated 1000. This block narrows the exposure from "since this clone last
# fetched" to "since the sibling pushed". Closing the remainder needs a registry the clones share,
# which is not this block and is recorded as open in BACKLOG #1616.
#
# WHERE THIS SITS IS PART OF THE FIX. Four reasons, each load-bearing on its own:
#   * OUTSIDE Get-Floor. That function's -Peek comment says "Reading a value must not be able to
#     corrupt it", and network I/O belongs to the caller.
#   * AT THE ONE CALL SITE. Get-Floor has exactly one, so fetching here provably precedes BOTH of its
#     ref enumerations without touching either arm.
#   * BEFORE the -ShowFloor block below, whose own comment states the invariant that both checks are
#     evaluated ONCE so -ShowFloor and a real allocation cannot disagree. A fetch that ran only on a
#     real allocation would break exactly that, and -ShowFloor would preview a floor the allocator
#     would not use. (Spelled "the -ShowFloor block" and not with its `if` keyword on purpose:
#     tests/test_ledger_check.py locates that block with `src.index`, a FIRST-match instrument for a
#     question about the block itself, so writing the opening line verbatim in a comment ABOVE it
#     moves the index and reds a guard that has nothing to do with this change. Measured here.)
#   * AFTER the -List early return. -List reads the local registry only; it stays offline and fast.
#
# EVERY FLAG AND -c BELOW IS THERE BECAUSE CONFIG CAN CHANGE THE VERB UNDERNEATH IT. `git fetch
# origin` is not one operation; it is whatever this clone's config says it is. Each of these was
# measured on a fixture, one variable at a time, against a control arm, 2026-09-12:
#
#   --no-prune      EXPLICITLY, not by leaving --prune off. `fetch.prune` and `remote.<name>.prune`
#                   turn pruning on from CONFIG, in any scope, and the earlier version of this block
#                   claimed "no --prune" while honouring both. A fetch here exists to ADD refs, and
#                   an added ref can only RAISE the floor; a prune only DELETES refs, so it can only
#                   LOWER one and it removes witnesses. MEASURED with fetch.prune=true: a doomed
#                   remote-tracking ref carrying #9999 was deleted by the pre-flight fetch itself and
#                   the floor fell to 77 -- the allocator destroying its own evidence mid-run. The
#                   control arm, same fixture without the config, kept the ref and the number. That
#                   is the harm this flag now prevents outright, and the earlier measurement of the
#                   same shape by hand: one `git fetch origin --prune` on this clone deleted six
#                   refs, among them origin/gh-readonly-queue/main/pr-1060-..., a queue branch for
#                   one of the two PRs in the #1546 collision -- and a queue branch carries a row.
#   the refspec     +refs/heads/*:refs/remotes/origin/* WRITTEN OUT. It is the DEFAULT VALUE of
#                   remote.origin.fetch, not a property of the verb, and `clone --single-branch`
#                   (which --depth implies) and actions/checkout both narrow it to main alone.
#                   MEASURED with the narrow value: the fetch RAN, exited 0, printed nothing, and the
#                   floor stayed stale at 77 while the remote carried 4321 -- exactly the `fetch
#                   origin main` behaviour this block rejects, reached by config instead of by
#                   argument, and indistinguishable from a healthy run. Both #1546 items lived on
#                   UNMERGED refs/remotes/origin/claude/* refs, so main alone sees neither.
#   gc/maintenance  a fetch spawns `git maintenance run --auto`, and Get-Floor's DANGEROUS table
#                   names an aggressive gc as one of the things the ratchet defends against. No floor
#                   term reads an unreachable object, so this is belt and not brace -- but the
#                   allocator should not be the thing that starts the operation the file warns about.
#   credentials     with GIT_TERMINAL_PROMPT=0 below. A credential prompt has no timeout, and a HANG
#                   is the one outcome neither branch here handles: a Builder gets ONE turn, and a
#                   hung fetch spends it with nothing pushed. These two cover git's own terminal
#                   prompt and Git Credential Manager's interactive mode. A GUI askpass helper is a
#                   path neither covers, so this NARROWS the hazard; it does not close it.
#
# --all IS STILL REFUSED. It fails closed on ANY dead remote, including remotes that have nothing to
# do with the ledger, which manufactures deadlocks rather than safety.
#
# NO ORIGIN IS NOT A FAILURE AND MUST NOT FAIL CLOSED. Measured 2026-09-12: with origin absent,
# `git config --get remote.origin.url` exits 1 with no output, where an unguarded `git fetch origin`
# exits 128 with a fatal. None of the 10 fixtures that predate this block adds a remote, so an
# unguarded fail-closed fetch would refuse every one of them.
#
# BUT "NO ORIGIN" IS NOT "NO SHARED UPSTREAM", so the skip WARNS instead of going quiet. A clone made
# with `clone -o gh` has an upstream under another name and is fully exposed to the #1546 shape.
# MEASURED 2026-09-12 with the upstream named `upstream`: a stale floor, exit 0, and not one word of
# output -- the deliberate version of the same risk, -NoFetch, prints five lines. A skip that is
# silent because its premise says there is nothing to be stale against is that premise being wrong.
#
# A NETWORK FAILURE FAILS CLOSED AND ALLOCATES NOTHING, and this is the decisive part. What this
# replaces is a PRINTED WARNING that was already in this script when #1546 collided -- and in the
# never-fetched shape it cannot even fire: the missing number is absent from the computed floor AND
# from the watermark, so the ratchet's `$previous -gt $computed` is false and nothing prints. A
# control that cannot reach the case is not a weak control, it is none, and allocate-and-shout would
# reinstall exactly that -- the compensating-control-resting-on-a-false-premise defect CLAUDE.md
# section 11 and SDS-3.7 forbid. The header above already settles the trade: holes are free,
# collisions are not. The throw lands before the allocation loop, so there is no partial state.
#
# IT RETRIES BEFORE IT REFUSES, because a failed fetch is not evidence of a broken remote. `git
# fetch` takes a per-ref lock, so two allocations racing in ONE clone -- the ordinary case on this
# fleet, where the registry shows one allocation about every 36s against a ~38s sweep -- make the
# loser exit 1 with "cannot lock ref" while the winner brings the refs in. MEASURED 2026-09-12: four
# concurrent -ShowFloor runs, two refused; and a held ref lock released after 2.5s refused outright
# before this loop existed and succeeds with it. The retry is deliberately NOT conditioned on which
# error came back: an error list is always missing one (SDS-3.6), and seconds are cheap against a
# sweep measured in tens of them. A refusal that survives three attempts is worth believing.
$fetchAttempts = 3
$fetchRetryPause = 2
$fetchState = "fetched"
if ($NoFetch) {
    $fetchState = "skipped-nofetch"
    Write-Host "WARNING: -NoFetch. The floor below came from refs this clone ALREADY HAD." -ForegroundColor Yellow
    Write-Host "         A number allocated in another clone, on a branch nobody here has fetched," -ForegroundColor Yellow
    Write-Host "         reads FREE -- and the ledger gate will then pass on BOTH sides, because each" -ForegroundColor Yellow
    Write-Host "         registry genuinely holds its own claim. Nothing downstream reports it." -ForegroundColor Yellow
    Write-Host "         Say in the PR why you skipped the fetch." -ForegroundColor Yellow
}
else {
    # THE EXIT CODE IS THE WITNESS, NOT `$?`. Same rule the git grep loop records above: `$?` is False
    # after ANY non-zero native exit and cannot tell a fatal from a legitimate 1. -1 is a NEVER-RAN
    # sentinel, because a command that never starts sets no exit code at all and a stale value from an
    # earlier call would read as success.
    #
    # $ErrorActionPreference is pinned to Continue across this scope, and restored before anything
    # throws. `2>&1` on a native command yields ErrorRecord objects, so on a host with
    # $PSNativeCommandUseErrorActionPreference true the script-level "Stop" turns git's first stderr
    # line into a generic NativeCommandExitException and the actionable message below never prints.
    $fetchFailure = $null
    $previousEap = $ErrorActionPreference
    $hadPrompt = Test-Path Env:\GIT_TERMINAL_PROMPT
    $previousPrompt = $env:GIT_TERMINAL_PROMPT
    $ErrorActionPreference = "Continue"
    $env:GIT_TERMINAL_PROMPT = "0"
    try {
        $global:LASTEXITCODE = -1
        $originUrl = & git -C $repo config --get remote.origin.url 2>&1
        $originCode = $LASTEXITCODE
        if ($originCode -eq 0 -and -not [string]::IsNullOrWhiteSpace("$originUrl")) {
            $fetchArgs = @(
                "-C", $repo,
                "-c", "gc.auto=0",
                "-c", "maintenance.auto=false",
                "-c", "credential.interactive=false",
                "fetch", "--no-prune", "origin", "+refs/heads/*:refs/remotes/origin/*"
            )
            for ($attempt = 1; $attempt -le $fetchAttempts; $attempt++) {
                $global:LASTEXITCODE = -1
                $fetchOut = & git @fetchArgs 2>&1
                $fetchCode = $LASTEXITCODE
                if ($fetchCode -eq 0) {
                    $fetchFailure = $null
                    break
                }
                $fetchFailure = [pscustomobject]@{
                    Attempts = $attempt
                    Code     = $fetchCode
                    Detail   = ((@($fetchOut) | ForEach-Object { "$_" }) -join "`n  ").Trim()
                }
                if ($attempt -lt $fetchAttempts) { Start-Sleep -Seconds $fetchRetryPause }
            }
        }
        else {
            $fetchState = "skipped-no-origin"
            $global:LASTEXITCODE = -1
            $remotes = @((& git -C $repo remote 2>&1) | ForEach-Object { "$_".Trim() } | Where-Object { $_ })
            if ($LASTEXITCODE -eq 0 -and $remotes.Count -gt 0) {
                Write-Host "WARNING: no usable 'origin' url, so NOTHING WAS FETCHED -- but this clone does have" -ForegroundColor Yellow
                Write-Host "         remotes: $($remotes -join ', '). The pre-flight fetch names 'origin' and only" -ForegroundColor Yellow
                Write-Host "         'origin', so the floor below came from refs this clone already had. A number" -ForegroundColor Yellow
                Write-Host "         allocated in another clone and pushed to that upstream reads FREE here, and" -ForegroundColor Yellow
                Write-Host "         the ledger gate then passes on BOTH sides. Fetch it yourself, or set it as" -ForegroundColor Yellow
                Write-Host "         'origin', before trusting this number." -ForegroundColor Yellow
            }
        }
    } finally {
        $ErrorActionPreference = $previousEap
        if ($hadPrompt) { $env:GIT_TERMINAL_PROMPT = $previousPrompt }
        else { Remove-Item Env:\GIT_TERMINAL_PROMPT -ErrorAction SilentlyContinue }
    }
    if ($null -ne $fetchFailure) {
        # Named for what the run was actually going to do. -ShowFloor allocates nothing, and telling
        # its operator we refused an allocation misdescribes the refusal in its first four words.
        # Spelled with a ternary rather than an `if`, for the `src.index` reason recorded above.
        $refusing = $ShowFloor ? "REFUSING TO REPORT A FLOOR" : "REFUSING TO ALLOCATE"
        throw @"
$($refusing): the pre-flight 'git fetch origin' failed $($fetchFailure.Attempts) times, so the floor
could not be computed against the refs this clone is missing. NOTHING WAS ALLOCATED.

DO THIS: run it again -- a concurrent git process in any worktree of this clone fails a fetch on a
ref lock, and that clears on its own. If it keeps failing, check that the remote is reachable. On a
genuinely offline box pass -NoFetch, and say in the PR why the number was allocated without checking
the remote.

Last attempt: exit $($fetchFailure.Code) (-1 means git never ran). Git said:
  $($fetchFailure.Detail)

WHY THIS REFUSES RATHER THAN WARNING: allocate-and-shout was already the control here on 2026-09-11,
when PR 1061 wrote "## 1546." over a number claimed to PR 1060. Both registries were right, both
gates passed, and nothing reported the collision. Holes are free, collisions are not.
"@
    }
}

$measured = Get-Floor -Peek:$ShowFloor -FetchState $fetchState
$observed = $measured.Floor

# THE WARNING AND THE RATCHET BOTH BELONGED TO THE BACKLOG KIND, AND BOTH ARE GONE.
#
# What stood here: a residual warning when the highest number below #1000 reached 90% of the
# partition, and a `.boundary-highwater` ratchet that refused to allocate when PUBLIC_BACKLOG_FLOOR
# was LOWERED beneath a value this clone had already allocated against. Neither has a subject now
# that the ledger and the constant have left the repository (BACKLOG #1250, #1754).
#
# THE ORIGINAL LESSON STILL BINDS AND IS KEPT ON PURPOSE: a check must be evaluated ONCE so
# -ShowFloor and a real allocation cannot disagree. They did once -- -ShowFloor printed a next
# number while every real allocation threw, because the inspector did not run the checks it
# previewed. Any guard added here later must sit above this line, not inside one branch.
#
# An abandoned `.boundary-highwater` file may still sit beside the registry in an existing clone.
# Nothing reads it any more; it is inert, not load-bearing.

if ($ShowFloor) {
    # Name the SOURCES, not just the number. "Which files did this sweep actually read" is the
    # question every silent-narrowing bug turns on, and a bare integer cannot answer it -- a floor of
    # 353 looks identical whether it swept one path or two.
    Write-Host "kind     : $Kind"
    Write-Host "floor    : $observed"
    Write-Host "paths    : docs/adr/NNNN-*.md (filenames, all refs)"
    Write-Host "next     : $($observed + 1)"
    Write-Host "watermark: $(Join-Path $alloc '.floor-highwater')"
    Write-Host ""
    Write-Host "Read-only: nothing was allocated." -ForegroundColor DarkGray
    return
}

# NO CLAMP. The backlog kind clamped its start to the #1000 partition; ADR numbers have never had
# a floor beyond the union maximum, and that maximum is what makes "never hand out a number that
# exists anywhere" true.
$start = $observed + 1

for ($i = $start; $i -lt $start + 500; $i++) {
    # Zero-padded to four digits: ADR filenames sort lexically in docs/adr/.
    $name = "{0:D4}" -f $i
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
