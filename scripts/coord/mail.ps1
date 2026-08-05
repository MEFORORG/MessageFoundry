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
        Desktop sessions were on ~/.claude while the VS Code sessions were on ~/.claude-account-4, in
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

    ATOMICITY. Every message is written to a UNIQUE name under tmp/ and then moved into place.
    [System.IO.File]::Move onto a name that does not exist is atomic on NTFS and throws if the target
    exists, so minting a unique id removes the replace-semantics question entirely rather than answering
    it. A reader therefore never sees a half-written message: it appears whole or not at all.

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
    [Parameter(ParameterSetName = 'Send')][int]$TtlMinutes = 720,
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

function New-MessageId {
    # Sortable-by-time, unique, and filename-safe. The time prefix is what makes an `ls` of the inbox
    # readable in arrival order without opening anything.
    $t = [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssfff')
    $r = -join ((1..6) | ForEach-Object { '0123456789abcdefghijklmnopqrstuvwxyz'[(Get-Random -Maximum 36)] })
    return "$t-$r"
}

function Initialize-Box {
    param([Parameter(Mandatory)][string]$Root, [Parameter(Mandatory)][string]$Key)
    foreach ($sub in @('inbox', 'seen', 'done', 'expired')) {
        $p = Join-Path $Root "box/$Key/$sub"
        if (-not (Test-Path -LiteralPath $p)) { New-Item -ItemType Directory -Path $p -Force | Out-Null }
    }
    foreach ($sub in @('tmp', 'receipts')) {
        $p = Join-Path $Root $sub
        if (-not (Test-Path -LiteralPath $p)) { New-Item -ItemType Directory -Path $p -Force | Out-Null }
    }
}

# --- Write ---------------------------------------------------------------------------------------

# Write-then-move. The move target is a name nothing else can mint, so the move is atomic and a reader
# never observes a partial file. This is the whole concurrency story; there is deliberately no lock.
function Write-Message {
    param(
        [Parameter(Mandatory)][string]$Root,
        [Parameter(Mandatory)][string]$Key,
        [Parameter(Mandatory)][hashtable]$Message
    )
    Initialize-Box -Root $Root -Key $Key
    $tmp = Join-Path $Root "tmp/$($Message.id).json"
    $dst = Join-Path $Root "box/$Key/inbox/$($Message.id).json"
    # ASCII on purpose: this is read back by a hook that must not depend on console encoding.
    Set-Content -LiteralPath $tmp -Value ($Message | ConvertTo-Json -Depth 8) -Encoding ascii
    [System.IO.File]::Move($tmp, $dst)
    return $dst
}

function New-Message {
    param(
        [Parameter(Mandatory)][string]$Body,
        [Parameter(Mandatory)][string]$ToCwd,
        [string]$ToSessionId,
        [string]$Kind = 'note',
        [int]$TtlMinutes = 720
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

# --- Entry points --------------------------------------------------------------------------------

$root = Get-MailRoot -Override $MailRoot

if ($Send) {
    if (-not $Body) { throw "-Body is required." }
    if (-not $To) { throw "-To is required (a worktree path). Refusing to guess a recipient." }

    $targets = @()
    if ($To -ieq 'all') {
        # Broadcast: every live peer in this repo EXCEPT this one. Uses the shared roster so there is
        # exactly one notion of "who is here" -- see scripts/coord/presence.ps1.
        $rosterJson = & pwsh -NoProfile -File (Join-Path $PSScriptRoot 'presence.ps1') -Json 2>$null
        $roster = @()
        try { $roster = @($rosterJson | ConvertFrom-Json) } catch { $roster = @() }
        $me = (Get-Location).Path.TrimEnd('\', '/').ToLowerInvariant()
        foreach ($r in $roster) {
            if (-not $r.Worktree) { continue }
            if ($r.IsSelf) { continue }
            if ($r.Worktree.TrimEnd('\', '/').ToLowerInvariant() -eq $me) { continue }
            $targets += $r.Worktree
        }
        if ($targets.Count -eq 0) {
            Write-Host "No live peers to broadcast to. Nothing written."
            Write-Host "  (This is 'the roster returned nobody', not 'the roster could not look' -- see presence.ps1 -Json.)"
            exit 0
        }
    }
    else {
        if (-not (Test-Path -LiteralPath $To -PathType Container)) {
            throw "Recipient worktree does not exist: $To"
        }
        $targets = @((Resolve-Path -LiteralPath $To).Path)
    }

    $written = @()
    foreach ($t in $targets) {
        $key = ConvertTo-BoxKey -Path $t
        $msg = New-Message -Body $Body -ToCwd $t -ToSessionId $ToSessionId -Kind $Kind -TtlMinutes $TtlMinutes
        $p = Write-Message -Root $root -Key $key -Message $msg
        $written += [pscustomobject]@{ To = $t; Key = $key; Id = $msg.id; File = $p }
    }

    if ($Json) { ($written | ConvertTo-Json -Depth 5 -AsArray) | Write-Output; exit 0 }

    Write-Host ""
    Write-Host "Queued $($written.Count) message(s) as of $([DateTime]::UtcNow.ToString('o')):"
    foreach ($w in $written) { Write-Host ("  {0}  ->  {1}" -f $w.Id, $w.To) }
    Write-Host ""
    # The sender is told what queuing does and does NOT mean. A queued message is not a delivered one,
    # and the difference is the entire failure mode this channel is designed to make visible.
    Write-Host "  Queued is not delivered. It is delivered when that session's drain hook next runs and"
    Write-Host "  writes a receipt under mefor-coord/mail/receipts/. Check with -Status."
    Write-Host ""
    exit 0
}

if ($List) {
    $boxes = @()
    $boxRoot = Join-Path $root 'box'
    if (Test-Path -LiteralPath $boxRoot) {
        foreach ($d in @(Get-ChildItem -LiteralPath $boxRoot -Directory -EA SilentlyContinue)) {
            $boxes += [pscustomobject]@{
                Key     = $d.Name
                Inbox   = @(Get-BoxMessages -Root $root -Key $d.Name -Sub 'inbox').Count
                Seen    = @(Get-BoxMessages -Root $root -Key $d.Name -Sub 'seen').Count
                Done    = @(Get-BoxMessages -Root $root -Key $d.Name -Sub 'done').Count
                AsOfUtc = [DateTime]::UtcNow.ToString('o')
            }
        }
    }
    if ($Json) { ($boxes | ConvertTo-Json -Depth 4 -AsArray) | Write-Output; exit 0 }
    Write-Host ""
    Write-Host "Mail boxes under $root  (as of $([DateTime]::UtcNow.ToString('o')))"
    if ($boxes.Count -eq 0) { Write-Host "  (none)" }
    foreach ($b in $boxes) { Write-Host ("  {0,-52} inbox={1} seen={2} done={3}" -f $b.Key, $b.Inbox, $b.Seen, $b.Done) }
    Write-Host ""
    exit 0
}

# -Status (default): this worktree's own box.
$here = (Get-Location).Path
$key = ConvertTo-BoxKey -Path $here
$inbox = @(Get-BoxMessages -Root $root -Key $key -Sub 'inbox')
$seen = @(Get-BoxMessages -Root $root -Key $key -Sub 'seen')
if ($Json) {
    ([pscustomobject]@{
        Worktree = $here; Key = $key; Inbox = $inbox.Count; Seen = $seen.Count
        MailRoot = $root; AsOfUtc = [DateTime]::UtcNow.ToString('o')
    } | ConvertTo-Json -Depth 4) | Write-Output
    exit 0
}
Write-Host ""
Write-Host "This worktree: $here"
Write-Host "Box key:       $key"
Write-Host "Undelivered:   $($inbox.Count)   already shown: $($seen.Count)"
Write-Host "As of:         $([DateTime]::UtcNow.ToString('o'))"
Write-Host ""
exit 0
