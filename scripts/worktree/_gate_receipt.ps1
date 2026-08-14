# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
#
# Install receipts for the machine-global worktree gate (BACKLOG #1247).
#
# WHY THIS IS A SEPARATE FILE AND NOT INLINE IN install-gate.ps1. Everything here has to be testable,
# and install-gate.ps1 cannot be dot-sourced to reach its functions -- it runs its install body on
# load, and that body writes to ~/.claude, a MACHINE-GLOBAL location shared by every session on the
# box. A test that had to run the installer to exercise the receipt would be a test that installs the
# gate, which is the owner's action by design and not a thing a suite may do. This file defines
# functions and nothing else, so a test dot-sources it against a temp directory and never touches the
# real gate.
#
# WHAT WENT WRONG, and it is the reason the design is shaped this way. The installed gate's CONTENT
# changed on this box while three sessions ran against it, and afterwards NOBODY COULD SAY WHO WROTE
# IT. The change happened to be benign -- it moved the gate forward -- but an unattributable write to
# a shared safety control is the same class of event whichever direction it goes.
#
# THE MTIME IS THE TRAP, NOT THE GAP. `Copy-Item` carries the SOURCE file's LastWriteTime, so the
# installed copy inherits a timestamp from whichever checkout installed it. That is worse than having
# no timestamp: a correct stale-gate report was RETRACTED on the strength of one ("nothing wrote it
# today") and the retraction reached three sessions and the owner before a baseline hash reproved the
# original finding. An absent record makes a reader say "unknown"; a WRONG record makes them say
# something false with confidence. So nothing here repairs or writes mtime -- a corrected timestamp is
# still one mutable field asserting a fact nothing corroborates.
#
# The receipt is a record of the past, written at the moment of the write. That is the property that
# matters: a re-measurement can only ever see the present, so it can never distinguish "my instrument
# was wrong" from "the artifact changed". Only a record taken beforehand can.

# DELIBERATELY NO `Set-StrictMode` HERE. Dot-sourcing runs a file in the CALLER'S scope, so a strict
# mode set in this file would silently impose itself on the rest of install-gate.ps1 -- a script
# written without it, where an unset variable is ordinary. The failure would appear as the installer
# throwing on a line this change never touched, and the cause would not be visibly connected to it.
# A helper that is dot-sourced must not configure its host.

#: Beside the gate, not inside it -- the gate must stay byte-identical to its source or
#: tests/test_gate_installed_parity.py reds, and an embedded receipt would change its content.
function Get-GateReceiptPath([string]$GatePath) {
    Join-Path (Split-Path -Parent $GatePath) "worktree_gate.install-receipt.json"
}

#: Reads a receipt, or $null when there is none or it is unreadable. A corrupt receipt is treated as
#: ABSENT rather than as a failure: the caller's safe response to both is the same (refuse to claim
#: provenance), and throwing here would make an unreadable receipt harder to recover from than none.
function Read-GateReceipt([string]$GatePath) {
    $p = Get-GateReceiptPath $GatePath
    if (-not (Test-Path -LiteralPath $p)) { return $null }
    try { Get-Content -LiteralPath $p -Raw | ConvertFrom-Json } catch { $null }
}

#: The provenance verdict for an installed gate, as one of three words. The three-way split is the
#: whole point and collapsing it to a boolean loses the distinction the item exists for:
#:
#:   ABSENT    no gate installed. Nothing to protect; install freely.
#:   UNRECORDED a gate is installed but carries no receipt. This is every gate installed before this
#:              change, so it is the NORMAL first-run state and must NOT be fatal -- refusing here
#:              would block the very re-install that adopts the mechanism.
#:   VERIFIED  installed content matches its receipt. Provenance is known.
#:   MODIFIED  installed content does NOT match its receipt. SOMETHING WROTE THIS FILE OUTSIDE THIS
#:             INSTALLER. That is the defect this whole item is about, and it is the only verdict
#:             that should stop an install and ask a human.
function Get-GateProvenance([string]$GatePath, [scriptblock]$HashFn) {
    if (-not (Test-Path -LiteralPath $GatePath)) { return "ABSENT" }
    $receipt = Read-GateReceipt $GatePath
    if ($null -eq $receipt) { return "UNRECORDED" }
    $installed = & $HashFn $GatePath
    if ($receipt.installed_content_sha256 -eq $installed) { return "VERIFIED" } else { return "MODIFIED" }
}

#: Preserve the bytes about to be overwritten, so a bad install is reversible. Byte-exact on purpose:
#: this is a recovery artifact, and folding line endings here would make it impossible to restore the
#: file that was actually there.
function Backup-GateBeforeWrite([string]$GatePath) {
    if (-not (Test-Path -LiteralPath $GatePath)) { return $null }
    $bak = "$GatePath.bak"
    Copy-Item -LiteralPath $GatePath -Destination $bak -Force
    $bak
}

#: Records who wrote the gate, from where, what was written, and WHAT WAS REPLACED -- the last field
#: being the one that makes an unexpected change detectable rather than merely visible.
#:
#: The timestamp is taken HERE, at write time, in UTC, and is never derived from a file. See the
#: header: an inherited mtime is the failure this replaces.
function Write-GateReceipt {
    param(
        [Parameter(Mandatory)][string]$GatePath,
        [Parameter(Mandatory)][string]$SourcePath,
        [Parameter(Mandatory)][string]$RepoRoot,
        [Parameter(Mandatory)][scriptblock]$HashFn,
        [string]$ReplacedSha,
        [string]$ReplacedProvenance,
        [string]$BackupPath
    )
    # EVERY GIT LOOKUP IS A STATEMENT, NEVER AN EXPRESSION. `try` is not an expression in PowerShell:
    # written as `key = (try { ... } catch { ... })` the parser reads `try` as a COMMAND NAME, the file
    # PARSES CLEAN, and at run time it fails with "The term 'try' is not recognized" -- which discards
    # the WHOLE hashtable, writes a receipt containing the literal `null`, and still returns a path and
    # exits 0. Measured here before this comment existed. That is the exact failure this file is meant
    # to prevent, reproduced inside it: a record that exists, looks like a record, and says nothing.
    #
    # The git values are optional by design -- a receipt that throws when git is unavailable is a
    # receipt nobody gets -- but optional must mean "recorded as null on purpose", not "silently lost".
    $srcBlob = $null
    try { $srcBlob = & git -C $RepoRoot hash-object $SourcePath 2>$null | Select-Object -First 1 } catch { $srcBlob = $null }
    $wt = $null
    try { $wt = & git -C $RepoRoot rev-parse --show-toplevel 2>$null } catch { $wt = $null }
    $branch = $null
    try { $branch = & git -C $RepoRoot rev-parse --abbrev-ref HEAD 2>$null } catch { $branch = $null }

    $receipt = [ordered]@{
        schema                    = "mefor.worktree-gate.install-receipt/1"
        written_at_utc            = [DateTime]::UtcNow.ToString("yyyy-MM-ddTHH:mm:ss.fffZ")
        installed_by_repo         = $RepoRoot
        installed_by_worktree     = $wt
        installed_by_branch       = $branch
        source_path               = $SourcePath
        source_blob_sha           = $srcBlob
        installed_content_sha256  = (& $HashFn $GatePath)
        replaced_content_sha256   = $ReplacedSha
        replaced_provenance       = $ReplacedProvenance
        backup_path               = $BackupPath
    }
    $path = Get-GateReceiptPath $GatePath
    $json = $receipt | ConvertTo-Json -Depth 10
    # Round-trip AND confirm the result carries the one field that cannot be absent. A bare
    # ConvertFrom-Json is not a control here: `null` is valid JSON, so the broken version above passed
    # this guard every time. A check that its own failure mode satisfies is not a check.
    $probe = $json | ConvertFrom-Json
    if ($null -eq $probe -or -not $probe.written_at_utc) {
        throw "refusing to write a receipt that carries no timestamp -- receipt construction failed"
    }
    $tmp = "$path.tmp-$PID"
    Set-Content -LiteralPath $tmp -Value $json -Encoding utf8
    Move-Item -LiteralPath $tmp -Destination $path -Force
    $path
}
