<#
.SYNOPSIS
    Asynchronous session-to-session mail for the sessions the realtime channel cannot reach.

.DESCRIPTION
    WHAT THIS IS FOR, AND WHAT IT IS NOT FOR. Claude Desktop sessions under one login already have a
    REALTIME channel: the ccd_session_mgmt send_message MCP tool, driven by the announce hook. That
    stays the path for desktop-to-desktop, and this script does not replace it. This is the ASYNC lane
    for the peers that channel structurally cannot address:

      - a session launched by the VS Code extension. The Desktop app's session tooling enumerates an
        in-memory map of sessions THE DESKTOP APP ITSELF SPAWNED, so a VS Code session is never entered
        into it -- not filtered, never registered -- and cannot be listed or messaged by it.
      - a session under a DIFFERENT login. Config roots (~/.claude plus each ~/.claude-account-N) are
        independent; a session is only visible to the login that owns it. Measured 2026-08-05: the
        Desktop sessions were on ~/.claude while the VS Code sessions were on a ~/.claude-account-N, in
        the same repo, at the same time.

    WHY A FILE AND NOT SOMETHING CLEVERER. A file write is the only transport that is blind to BOTH of
    those axes: it does not care which app spawned the recipient or which account it authenticated
    against. The peer-to-peer protocol compiled into claude.exe is inert (the registry field carrying a
    peer's socket address is written by no code path, and it fails silently green -- an empty peer list,
    not an error), so there is nothing to build on there.

    WHERE IT LIVES, AND WHY THAT SATISFIES THE PUBLIC-REPO RULE BY LOCATION.
    <git-common-dir>/mefor-coord/mail/ -- inside .git, shared by every worktree of this repo. Nothing
    under .git can be placed in a commit by any git command, and mefor-coord is not a ref namespace, so
    `push --mirror` cannot carry it either. Worktree paths and branch names are therefore written in
    PLAIN TEXT here, deliberately: the leak constraint is already satisfied by location, and hashing
    them would buy nothing while destroying the ability to read the queue with `ls` when it misbehaves.
    The only hashing here is for filename injectivity.

    ADDRESSING. A box is keyed by the recipient's WORKTREE, not by session id and never by worktree
    NAME. Three separate reasons, each measured:
      - a worktree NAME is a creation-time label and nothing keeps it current; one worktree was observed
        switched onto four different branches by four different sessions in a single day.
      - a session id churns. It is stable while a session lives, but /clear mints a new one, so mail
        addressed to an id can be stranded by a keystroke. Session id is kept as an optional FILTER on a
        message, not as the box key.
      - the worktree is what the work is attached to, and it is what a sender actually knows.
    A cwd is matched case-insensitively and EXACTLY, never by prefix: every worktree cwd in this repo is
    an extension of the primary checkout's path, so a prefix match resolves any peer to some arbitrary
    worktree. VS Code also records a lowercase drive letter where the Desktop app records an uppercase
    one, so a case-sensitive compare splits one worktree into two boxes.

    THREE OBSERVABILITY RULES, each paid for by a real failure in this repo's history.
      1. What the recipient sees is a function of STATE. "No mail" must not render byte-identically to
         "the drain is not running". The defect this prevents is on record in announce-session.ps1: a
         hook that was wired, fired, resolved nothing and exited 0, for weeks, silently, and was
         indistinguishable from a healthy hook with no peers.
      2. A receipt records what was OBSERVED, not what was attempted. The existing announce receipts are
         written by the MODEL by hand, so they can assert a delivery that never happened. These are
         written by the drain at the moment it emits.
      3. Every observation carries its AS-OF time, and an undated observation is unusable rather than
         current. Measured 2026-08-05: a five-root hook table was accurate when taken and stale seven
         minutes later, and nothing in it recorded when it was read, so a stale reading was
         indistinguishable from a current one and two sessions disagreed about a file neither had
         misread.

    ATOMICITY, AND WHY THE MOVE'S THROW IS NOT THE SAFETY NET IT LOOKS LIKE. Every message is written
    to a unique name under tmp/ and then moved into place, so a reader never sees a half-written
    message: it appears whole or not at all. That half stands -- the rename is atomic on NTFS.

    What does NOT stand is the claim this paragraph used to make, that the move "throws if the target
    exists" and that a unique id therefore removes the question. The move RETURNS SUCCESS WITHOUT
    MOVING for losers under contention, so a silent loser would have been reported here as "Queued"
    while its message was gone, with no error anywhere.

    So the safety property does not rest on the throw. It rests on construction: every destination in
    this system embeds a per-attempt CLAIM TOKEN that no other writer can mint, and the mover then
    proves it holds that destination by OPENING it exclusively -- Exists alone is not enough either,
    for a reason that only shows up across processes. A throw is treated as a report, never as proof
    of either outcome. One definition of all that, in scripts/coord/mail-claim.ps1, shared with the
    drain; the measurement behind it -- every arm, every control, and why scripts/coord/claim.ps1 is
    not affected -- is in docs/adr/0161-async-session-mail-for-unreachable-peers.md and nowhere else.

    WHO CAN WRITE TO A BOX. Anyone running under this Windows account, and nothing checks. Every
    from.* field is a string the writer chose, so the drain renders them labelled [UNVERIFIED] and
    never as provenance. No authentication is planned -- see docs/SESSION-MAIL.md, "The write side is
    unauthenticated", for why a MAC here would be theatre.

    WHAT MAY NEVER GO IN A BODY. No message content, no PHI, no secrets -- synthetic or real. Mail the
    PATH to a file instead. Delivery copies the body into the recipient's transcript, which nothing in
    this repo can delete. The rule and its reasoning are in docs/SESSION-MAIL.md, "What may never go
    in a message body"; this is the pointer.

    FAIL OPEN, ALWAYS. Nothing here may block a prompt, a tool call or a turn. Every entry point
    catches, and the hook that consumes this exits 0 on any error.

.EXAMPLE
    pwsh -NoProfile -File scripts\coord\mail.ps1 -Send -To C:\path\to\worktree -Body "the ADR number is 0161"
    pwsh -NoProfile -File scripts\coord\mail.ps1 -List
    pwsh -NoProfile -File scripts\coord\mail.ps1 -Status
#>
[CmdletBinding(DefaultParameterSetName = 'Status')]
param(
    [Parameter(ParameterSetName = 'Send', Mandatory)][switch]$Send,
    # Recipient worktree. A path (matched case-insensitively and exactly), or "all" to broadcast to
    # every live peer in this repo. Defaults to nothing: refusing to guess is the point.
    [Parameter(ParameterSetName = 'Send')][string]$To,
    [Parameter(ParameterSetName = 'Send')][string]$Body,
    # Optional: only deliver if the reading session has this id. Use when the message is only meaningful
    # to one specific session and would be misleading to whoever occupies that worktree next.
    [Parameter(ParameterSetName = 'Send')][string]$ToSessionId,
    # How long the message stays deliverable. Past this it is swept to expired/ rather than shown, so a
    # session that starts next week is not told to act on something from last Tuesday.
    #
    # RAISED 720 -> 4320 (12h -> 72h) on 2026-08-11, because 12h was measured to be SHORTER THAN THE GAP
    # IT HAD TO SURVIVE. The delivery points are SessionStart and Stop, so a recipient that is closed --
    # or idle -- overnight receives nothing until someone opens it. At 720 an ordinary overnight gap
    # expired the mail, and EXPIRY IS SILENT IN BOTH DIRECTIONS: the recipient is never told a message
    # existed, and the sender is never told it went unread. That is the only place in this transport
    # where a message is genuinely LOST rather than merely late, and it was reachable by doing nothing.
    #
    # 72h is chosen to span a weekend, which is the longest gap a working session is expected to sit
    # through. It does NOT abandon the staleness argument above -- a three-day-old instruction is still
    # refused rather than acted on. If you need longer, pass -TtlMinutes explicitly and say why; do not
    # raise this default again without re-stating what gap it now has to cover.
    [Parameter(ParameterSetName = 'Send')][int]$TtlMinutes = 4320,
    [Parameter(ParameterSetName = 'Send')][ValidateSet('note', 'handoff', 'alert', 'broadcast')][string]$Kind = 'note',

    [Parameter(ParameterSetName = 'List', Mandatory)][switch]$List,
    [Parameter(ParameterSetName = 'Status', Mandatory = $false)][switch]$Status,
    [switch]$Json,
    # Overridable so tests exercise the real logic against a fixture instead of the live queue.
    [string]$MailRoot
)

$ErrorActionPreference = 'Stop'

# --- Location ------------------------------------------------------------------------------------

function Get-MailRoot {
    param([string]$Override)
    if ($Override) { return $Override }
    $c = & git rev-parse --path-format=absolute --git-common-dir 2>$null
    if ($LASTEXITCODE -ne 0 -or -not $c) {
        throw "Not inside a git worktree: refusing to guess where the mail queue lives."
    }
    return (Join-Path $c.Trim() "mefor-coord/mail")
}

# The worktree -> box key function. ONE definition, shared with the drain hook: if the two ends
# computed different keys, mail would be written to a box nobody reads and BOTH sides would look
# healthy. See mail-key.ps1 for why the normalisation is load-bearing.
. "$PSScriptRoot\mail-key.ps1"

# The claim primitive is shared with the drain for exactly the reason the box key is: three call sites
# hand-rolling "did my move win" is three chances for one of them to drift back to a check that was
# measured unable to tell a winner from a loser. See mail-claim.ps1.
. "$PSScriptRoot\mail-claim.ps1"

# New-MessageId now lives in mail-key.ps1, next to Test-MailStem. See that file's header for why.

# Receiver-side caps, ADVISORY COPIES. The ENFORCING copy is the constants at the top of
# scripts/hooks/mail-drain.ps1; these exist so the sender can warn at send time and so -Status can
# predict what the next drain will show. They are duplicated and must be changed together -- anyone
# who can write a file straight into an inbox never runs this code, which is why the drain has to be
# the copy that binds.
$MAIL_CAP_MESSAGES = 5
$MAIL_CAP_BODY_BYTES = 2000
$MAIL_CAP_TOTAL_BYTES = 8000

function Initialize-Box {
    param([Parameter(Mandatory)][string]$Root, [Parameter(Mandatory)][string]$Key)
    # claiming/, stranded/ and shown/ are the drain's, but they are created HERE because Initialize-Box
    # is the one place a box comes into existence -- a drain must be able to claim from, or mark in, a
    # box an older sender created without first having to invent the directory layout for itself.
    foreach ($sub in @('inbox', 'seen', 'done', 'expired', 'claiming', 'stranded', 'shown')) {
        $p = Join-Path $Root "box/$Key/$sub"
        if (-not (Test-Path -LiteralPath $p)) { New-Item -ItemType Directory -Path $p -Force | Out-Null }
    }
    foreach ($sub in @('tmp', 'receipts')) {
        $p = Join-Path $Root $sub
        if (-not (Test-Path -LiteralPath $p)) { New-Item -ItemType Directory -Path $p -Force | Out-Null }
    }
}

# --- Write ---------------------------------------------------------------------------------------

# Write-then-move, then VERIFY. The destination carries a claim token no other writer can mint, and
# publishing is decided by whether this process can OPEN its own destination -- not by whether the move
# threw, which was measured to say nothing either way, and not by Exists alone, which was measured to
# return a transient false positive across processes. See the ATOMICITY paragraph in the header.
#
# The tmp name carries the token too, so no two senders can ever share a source path. That removes the
# shared-source arm at this site by construction rather than detecting it afterwards.
function Write-Message {
    param(
        [Parameter(Mandatory)][string]$Root,
        [Parameter(Mandatory)][string]$Key,
        [Parameter(Mandatory)][hashtable]$Message
    )
    Initialize-Box -Root $Root -Key $Key
    $tok = New-ClaimToken
    $tmp = Join-Path $Root "tmp/$($Message.id)--$tok.json"
    # ASCII on purpose: this is read back by a hook that must not depend on console encoding.
    Set-Content -LiteralPath $tmp -Value ($Message | ConvertTo-Json -Depth 8) -Encoding ascii
    $r = Move-Claimed -Source $tmp -DestinationDir (Join-Path $Root "box/$Key/inbox") -Stem $Message.id -Token $tok
    if (-not $r.Won) {
        # Never orphan the tmp -- claim.ps1:279 states the same rule for the claim registry, and for
        # the same reason: a file nothing ever removes accumulates for the life of the repo.
        Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue
        throw "Publish FAILED for box $Key -- the message was NOT queued. $($r.Error)"
    }
    return $r.Path
}

function New-Message {
    param(
        [Parameter(Mandatory)][string]$Body,
        [Parameter(Mandatory)][string]$ToCwd,
        [string]$ToSessionId,
        [string]$Kind = 'note',
        # Kept in step with the parameter default above deliberately: every caller passes -TtlMinutes
        # explicitly, so this is the value a FUTURE caller that forgets to would silently get. Two
        # defaults that disagree is the shape where the tested path and the shipped path diverge.
        [int]$TtlMinutes = 4320
    )
    $now = [DateTime]::UtcNow
    return @{
        v            = 1
        id           = New-MessageId
        kind         = $Kind
        createdUtc   = $now.ToString('o')
        expiresUtc   = $now.AddMinutes($TtlMinutes).ToString('o')
        # Who sent it, so the recipient can weigh it. Filled from the environment the sender runs in;
        # every field is best-effort and absent rather than guessed.
        from         = @{
            sessionId = $env:CLAUDE_SESSION_ID
            cwd       = (Get-Location).Path
            branch    = (& git rev-parse --abbrev-ref HEAD 2>$null)
            host      = $env:COMPUTERNAME
        }
        to           = @{
            cwd       = $ToCwd
            sessionId = $ToSessionId
        }
        body         = $Body
    }
}

# --- Read ----------------------------------------------------------------------------------------

function Get-BoxMessages {
    param([Parameter(Mandatory)][string]$Root, [Parameter(Mandatory)][string]$Key, [string]$Sub = 'inbox')
    $dir = Join-Path $Root "box/$Key/$Sub"
    if (-not (Test-Path -LiteralPath $dir)) { return @() }
    $out = @()
    foreach ($f in @(Get-ChildItem -LiteralPath $dir -Filter *.json -EA SilentlyContinue | Sort-Object Name)) {
        try {
            $m = Get-Content -LiteralPath $f.FullName -Raw -EA Stop | ConvertFrom-Json -EA Stop
            $out += [pscustomobject]@{ Message = $m; File = $f.FullName }
        }
        catch {
            # A message we cannot parse is a message we must not silently drop. Surface it as a row with
            # a null body so the count still reflects what is physically in the box.
            $out += [pscustomobject]@{ Message = $null; File = $f.FullName }
        }
    }
    return $out
}

function Get-BoxShownCount {
    # SHOWN-AND-HELD MARKERS, counted as PLAIN FILES. Deliberately not Get-BoxMessages: that parses JSON
    # messages, and a marker is not a message -- it is a name, and the name is the whole fact.
    #
    # IT IS A MARKER COUNT, NOT A MESSAGE COUNT, and the two differ by design. Under the accepted
    # duplicate, one message shown to two sessions carries two markers, so this can exceed the inbox
    # count. Reporting it as a message count would be an instrument answering a question one step to the
    # side of the one asked.
    #
    # ONLY NAMES THIS CHANNEL MINTED ARE COUNTED. -Filter '*.marker' is a Windows wildcard, not a suffix
    # test, and a file in shown/ that this channel did not write is not evidence about this channel --
    # counting it would let anything able to write into the box inflate a number an operator reads as
    # "mail already shown". The drain reports such files separately and leaves them alone; so does this.
    #
    # AND ONLY MARKERS WHOSE MESSAGE IS STILL HERE. A marker outlives its message by design: the session
    # that consumes a message removes only ITS OWN marker, so under the accepted duplicate the other
    # session's marker survives until the next drain's orphan sweep. Counting those produced a reading
    # that contradicted itself in the same sentence -- "In the inbox: 0, of which 1 have already been
    # shown ... and are held" -- and the parenthetical offered on the next line explained it with a
    # cause that was not the one operating.
    #
    # inbox/ ONLY, and NOT the drain's live set, which also spans claiming/. The number this feeds is
    # read inside the sentence "in the inbox, of which N have been shown", and a claimed message has
    # LEFT the inbox. Counting it there would put the same contradiction back one case narrower. The
    # cost is that a message mid-consume is under-reported for the length of one claim, which is a
    # transient understatement rather than a false statement.
    param([Parameter(Mandatory)][string]$Root, [Parameter(Mandatory)][string]$Key)
    $dir = Join-Path $Root "box/$Key/shown"
    if (-not (Test-Path -LiteralPath $dir)) { return 0 }
    $live = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $inboxD = Join-Path $Root "box/$Key/inbox"
    if (Test-Path -LiteralPath $inboxD) {
        foreach ($f in @(Get-ChildItem -LiteralPath $inboxD -Filter *.json -File -EA SilentlyContinue)) {
            $p = Split-MailFileName -Name $f.Name
            if ($p) { [void]$live.Add($p.Stem) }
        }
    }
    $n = 0
    foreach ($f in @(Get-ChildItem -LiteralPath $dir -Filter *.marker -File -EA SilentlyContinue)) {
        $mp = Split-ShownMarkerName -Name $f.Name
        if ($mp -and $live.Contains($mp.Stem)) { $n++ }
    }
    return $n
}

# --- Entry points --------------------------------------------------------------------------------

$root = Get-MailRoot -Override $MailRoot

if ($Send) {
    if (-not $Body) { throw "-Body is required." }
    if ($Body.Length -gt $MAIL_CAP_BODY_BYTES) {
        throw ("-Body is $($Body.Length) characters; the receiver renders at most $MAIL_CAP_BODY_BYTES per message and " +
            "truncates the rest. Write the long form to a file in your worktree and mail the PATH. " +
            "(This check is a courtesy, NOT a control: the cap that binds is in mail-drain.ps1, because " +
            "anyone who can write a file into the inbox never runs this code.)")
    }
    if (-not $To) { throw "-To is required (a worktree path). Refusing to guess a recipient." }

    $targets = @()
    if ($To -ieq 'all') {
        # Broadcast: every live peer in this repo EXCEPT this one. Uses the shared roster so there is
        # exactly one notion of "who is here" -- see scripts/coord/presence.ps1.
        # CAPTURE STDERR, DO NOT DISCARD IT. presence.ps1 deliberately writes an "UNAVAILABLE" receipt
        # to stderr precisely so that "the fence could not look" stops rendering as an
        # indistinguishable empty list on stdout -- its own comment says so. This call used to end in
        # `2>$null`, which threw that receipt away and then printed a line claiming the empty result
        # meant "the roster returned nobody, not the roster could not look". It could not know that:
        # the only channel carrying the difference had just been suppressed. A message asserting a
        # distinction the code destroyed is a compensating control resting on a false premise.
        $rosterErr = @()
        $rosterJson = & pwsh -NoProfile -File (Join-Path $PSScriptRoot 'presence.ps1') -Json 2>&1 |
            ForEach-Object {
                if ($_ -is [System.Management.Automation.ErrorRecord]) { $rosterErr += [string]$_; }
                else { $_ }
            }
        $rosterUnavailable = @($rosterErr | Where-Object { $_ -match 'UNAVAILABLE' }).Count -gt 0
        $roster = @()
        try { $roster = @($rosterJson | ConvertFrom-Json) } catch { $roster = @(); $rosterUnavailable = $true }
        $me = (Get-Location).Path.TrimEnd('\', '/').ToLowerInvariant()
        foreach ($r in $roster) {
            if (-not $r.Worktree) { continue }
            if ($r.IsSelf) { continue }
            if ($r.Worktree.TrimEnd('\', '/').ToLowerInvariant() -eq $me) { continue }
            $targets += $r.Worktree
        }
        if ($targets.Count -eq 0) {
            # THE TWO CASES ARE NOW SEPARATED BY EVIDENCE RATHER THAN BY ASSERTION, and they exit
            # differently: an empty roster is a real answer, an unavailable one is a non-answer and must
            # not read as "nobody is here".
            if ($rosterUnavailable) {
                Write-Host ""
                Write-Host "ROSTER UNAVAILABLE -- nothing was broadcast, and this is NOT 'nobody is live'." -ForegroundColor Yellow
                Write-Host "  presence.ps1 could not measure who is here, so an empty peer list proves nothing."
                foreach ($e in $rosterErr) { Write-Host "  $e" -ForegroundColor Yellow }
                Write-Host "  Run scripts\coord\presence.ps1 to see why, then re-send."
                Write-Host ""
                exit 1
            }
            Write-Host "No live peers to broadcast to. Nothing written."
            Write-Host "  (The roster WAS readable and returned nobody -- presence.ps1 emitted no UNAVAILABLE receipt.)"
            exit 0
        }
    }
    else {
        if (-not (Test-Path -LiteralPath $To -PathType Container)) {
            throw "Recipient worktree does not exist: $To"
        }
        $targets = @((Resolve-Path -LiteralPath $To).Path)
    }

    # PER-TARGET, NOT ALL-OR-NOTHING. Now that a publish can genuinely fail -- the verify is real, so a
    # move that did not happen is reported instead of assumed -- a broadcast that aborted on target 1
    # would hide targets 2..N, and one that swallowed the failure would put the defect back at the
    # reporting layer. Every target gets its own row and its own status.
    $written = @()
    foreach ($t in $targets) {
        $key = ConvertTo-BoxKey -Path $t
        $msg = New-Message -Body $Body -ToCwd $t -ToSessionId $ToSessionId -Kind $Kind -TtlMinutes $TtlMinutes
        try {
            $p = Write-Message -Root $root -Key $key -Message $msg
            $written += [pscustomobject]@{ To = $t; Key = $key; Id = $msg.id; File = $p; Status = 'queued'; Error = '' }
        }
        catch {
            $written += [pscustomobject]@{ To = $t; Key = $key; Id = $msg.id; File = ''; Status = 'failed'; Error = $_.ToString() }
        }
    }

    if ($Json) { ($written | ConvertTo-Json -Depth 5 -AsArray) | Write-Output }
    else {
        $ok = @($written | Where-Object { $_.Status -eq 'queued' })
        $bad = @($written | Where-Object { $_.Status -ne 'queued' })

        Write-Host ""
        Write-Host "Queued $($ok.Count) message(s) as of $([DateTime]::UtcNow.ToString('o')):"
        foreach ($w in $ok) { Write-Host ("  {0}  ->  {1}" -f $w.Id, $w.To) }
        if ($bad.Count -gt 0) {
            Write-Host ""
            Write-Host "FAILED to queue $($bad.Count) message(s) -- these were NOT written:" -ForegroundColor Red
            foreach ($w in $bad) {
                Write-Host ("  {0}  ->  {1}" -f $w.Id, $w.To)
                Write-Host ("      {0}" -f $w.Error)
            }
        }
        Write-Host ""
        # The sender is told what queuing does and does NOT mean. A queued message is not a delivered one,
        # and the difference is the entire failure mode this channel is designed to make visible.
        Write-Host "  Queued is not delivered. It is delivered when that session's drain hook next runs and"
        Write-Host "  writes a receipt under mefor-coord/mail/receipts/. Check with -Status."
        Write-Host ""
    }
    if (@($written | Where-Object { $_.Status -ne 'queued' }).Count -gt 0) { exit 1 }
    exit 0
}

if ($List) {
    $boxes = @()
    $boxRoot = Join-Path $root 'box'
    if (Test-Path -LiteralPath $boxRoot) {
        foreach ($d in @(Get-ChildItem -LiteralPath $boxRoot -Directory -EA SilentlyContinue)) {
            $boxes += [pscustomobject]@{
                Key      = $d.Name
                Inbox    = @(Get-BoxMessages -Root $root -Key $d.Name -Sub 'inbox').Count
                Seen     = @(Get-BoxMessages -Root $root -Key $d.Name -Sub 'seen').Count
                Done     = @(Get-BoxMessages -Root $root -Key $d.Name -Sub 'done').Count
                # A claim mid-flight and a claim whose owner died are different facts, and neither is
                # visible from inbox/seen alone -- a claimed message is in NEITHER.
                Claiming = @(Get-BoxMessages -Root $root -Key $d.Name -Sub 'claiming').Count
                Stranded = @(Get-BoxMessages -Root $root -Key $d.Name -Sub 'stranded').Count
                # Shown-and-held: in the inbox, already displayed to some session, awaiting that
                # session's next turn boundary. Invisible from inbox/seen alone, exactly as claiming/
                # and stranded/ are.
                Shown    = (Get-BoxShownCount -Root $root -Key $d.Name)
                AsOfUtc  = [DateTime]::UtcNow.ToString('o')
            }
        }
    }
    if ($Json) { ($boxes | ConvertTo-Json -Depth 4 -AsArray) | Write-Output; exit 0 }
    Write-Host ""
    Write-Host "Mail boxes under $root  (as of $([DateTime]::UtcNow.ToString('o')))"
    if ($boxes.Count -eq 0) { Write-Host "  (none)" }
    foreach ($b in $boxes) {
        Write-Host ("  {0,-52} inbox={1} shown={2} seen={3} done={4} claiming={5} stranded={6}" -f `
                $b.Key, $b.Inbox, $b.Shown, $b.Seen, $b.Done, $b.Claiming, $b.Stranded)
    }
    Write-Host ""
    exit 0
}

# -Status (default): this worktree's own box.
$here = (Get-Location).Path
$key = ConvertTo-BoxKey -Path $here
$inbox = @(Get-BoxMessages -Root $root -Key $key -Sub 'inbox')
$seen = @(Get-BoxMessages -Root $root -Key $key -Sub 'seen')
$claiming = @(Get-BoxMessages -Root $root -Key $key -Sub 'claiming')
$stranded = @(Get-BoxMessages -Root $root -Key $key -Sub 'stranded')
# SHOWING IS NOT CONSUMING, so "Undelivered: <inbox count>" would be a lie. The drain renders mail at
# SessionStart and LEAVES IT IN THE INBOX, consuming it only at that session's next turn boundary --
# see docs/SESSION-MAIL.md, "Showing is not consuming". Counting held mail as undelivered would put the
# defect this whole channel exists to make visible ("queued is not delivered") back at the reporting
# layer, one rung up.
$shownHeld = Get-BoxShownCount -Root $root -Key $key

# What the NEXT drain will actually show. A sender who queues twenty messages otherwise sees twenty
# queued and has no way to learn that four drains will pass before the last one is read -- which would
# give "queued is not delivered" a second, undocumented failure mode.
#
# This is an ESTIMATE and deliberately errs low. The drain measures body bytes AFTER sanitising to
# ASCII and collapsing whitespace runs, which can only shrink a body, so counting raw characters here
# over-states the cost and therefore under-states how many will fit. "At least N" is the honest form.
$fits = 0
$runningBytes = 0
foreach ($row in $inbox) {
    if ($fits -ge $MAIL_CAP_MESSAGES) { break }
    $b = if ($row.Message -and $row.Message.body) { [string]$row.Message.body } else { '' }
    $cost = [Math]::Min($b.Length, $MAIL_CAP_BODY_BYTES)
    if (($runningBytes + $cost) -gt $MAIL_CAP_TOTAL_BYTES) { break }
    $runningBytes += $cost
    $fits++
}

if ($Json) {
    ([pscustomobject]@{
            Worktree = $here; Key = $key; Inbox = $inbox.Count; Seen = $seen.Count
            ShownHeld = $shownHeld
            Claiming = $claiming.Count; Stranded = $stranded.Count
            NextDrainShowsAtLeast = $fits
            MailRoot = $root; AsOfUtc = [DateTime]::UtcNow.ToString('o')
        } | ConvertTo-Json -Depth 4) | Write-Output
    exit 0
}
Write-Host ""
Write-Host "This worktree: $here"
Write-Host "Box key:       $key"
Write-Host "In the inbox:  $($inbox.Count), of which $shownHeld have already been shown to a session and are"
Write-Host "               held until its next turn boundary.  Consumed into seen/: $($seen.Count)"
Write-Host "               (Held is a MARKER count: one message shown to two sessions carries two markers,"
Write-Host "               so it can exceed the inbox count. Duplicate display is accepted; loss is not.)"
Write-Host "               Held mail is consumed at that session's next turn boundary. While the OFF switch"
Write-Host "               is present nothing is shown OR consumed, so held mail is consumed at the first"
Write-Host "               turn boundary after OFF is removed."
# NextDrainShowsAtLeast keeps its meaning deliberately: this runs in a worktree and cannot know which
# session will read next, and a session that has not been shown the mail is shown all of it.
Write-Host ("Next drain shows: at least {0} of {1} (caps: {2} messages / {3} bytes); {4} deferred to later drains." -f `
        $fits, $inbox.Count, $MAIL_CAP_MESSAGES, $MAIL_CAP_TOTAL_BYTES, [Math]::Max(0, $inbox.Count - $fits))
Write-Host "In flight:     $($claiming.Count) claimed by a drain that has not finished"
Write-Host "As of:         $([DateTime]::UtcNow.ToString('o'))"

if ($stranded.Count -gt 0) {
    # STRANDED IS THE ON-DISK RESIDUE OF A CLAIMER THAT DIED MID-DELIVERY, and it is reported here
    # rather than only in one drain's transient output: a fact that exists solely inside a turn that
    # has ended is a fact nobody can act on, which is the observability failure this file's rule 1
    # exists to prevent. These are NEVER re-queued -- a crash after the injection but before the
    # receipt is indistinguishable from a crash before the injection, so re-queueing would risk
    # showing a message twice while asserting it was never shown. Recovery is a human decision.
    $receiptDir = Join-Path $root 'receipts'
    Write-Host ""
    Write-Host "STRANDED: $($stranded.Count) message(s) claimed by a session that died before finishing." -ForegroundColor Yellow
    foreach ($row in $stranded) {
        $name = Split-Path $row.File -Leaf
        $parts = Split-MailFileName -Name $name
        if (-not $parts) {
            Write-Host ("  {0}  [name not minted by this channel -- left alone]" -f $name)
            continue
        }
        # The token in a stranded name belongs to the SWEEPER, not to the claimer that died -- the
        # sweep has to mint a fresh one or two sweepers would contend on the same destination. So the
        # owner's liveness is deliberately not reported here: it would describe the wrong process.
        # What matters is answerable without it -- whether a receipt exists for that stem.
        $hasReceipt = Test-Path -LiteralPath (Join-Path $receiptDir "$($parts.Stem).json")
        $shown = if ($hasReceipt) { "SHOWN (receipt exists; only the bookkeeping did not finish)" }
        else { "delivery UNPROVEN (no receipt -- it may or may not have been shown)" }
        Write-Host ("  {0}  {1}" -f $parts.Stem, $shown)
    }
    Write-Host "  Not re-queued, on purpose. Move one back to inbox/ by hand only if you accept it may be shown twice."
}
Write-Host ""
exit 0
