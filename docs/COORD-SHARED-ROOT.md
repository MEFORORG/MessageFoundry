# Sharing fleet coordination state across two PCs

**Status: APPROVED by the owner, 2026-10-21. Migration step 3 (resolver, host field, host-aware
liveness, gate) and step 4 (the host-qualified box key) are BUILT. No root is configured anywhere,
so the shared-root behaviour is unchanged until step 7.**

Known gaps after step 4, at least:

- **The batch skill's `read_batch.py` lives outside this repository** and still builds
  `<git-common-dir>/mefor-coord/seats`. It should import `scripts/coord/coord_root.py`. That edit is
  outside the worktree, so it is the owner's.
- **CLAUDE.md section 5's wiki command** passes `-StateRoot` as the local root. Once a root is
  configured, it must name the shared root instead. That edit lands with step 7.

Owner answers, 2026-10-21:

- Design approved as written.
- Host: Nucbox01 is always on. **Use the existing `Shared` share**, so the root is
  `\\Nucbox01\Shared\mefor-coord`, not a dedicated share. MEFORDEV01 and the MEFORHV01 server are
  also always on, and stay the fallback hosts if Nucbox01 proves unreliable. The access-list caveat
  under *PHI and secrets* still applies to a subfolder of `Shared`.
- MEFORDEV01 signs in to all the accounts and has its own clones. Its details come from a probe
  session there, which drops results under `Z:\mefor-coord-probe\`.
- Services: left to the Builder. Only the AFK zero-model cron reads shared state. It runs as the
  owner's user, on one PC, and reads the UNC path. No NSSM service needs it.

## The recommendation: one shared root on a dedicated SMB share, named by UNC path, split by class

Put the SHARED part of `mefor-coord/` on an SMB share on Nucbox01, named by its UNC path in one
setting every script reads. Keep the LOCAL part where it is. Exclusive operations fail closed when
the share is down; advisory reads fail open fast. Confidence: about 80 percent that this is the
right shape, and lower on the details that need the owner's answers below.

The owner asked for "the Z drive". Z: is the right **server**, but the drive letter is the wrong
**name** for it, and moving the whole directory is the wrong **scope**. The sections below say why.

## The failure this fixes is already happening

On 2026-10-21 a Manager seat on the other PC posted on engine PR 2471 (comment of
2026-10-21T22:51:29Z) that its worktree is `D:\Code\MessageFoundry\.claude\worktrees\autonomy-plan`,
seat record `autonomy-plan-62022e2c`, reachable with `mail.ps1 -To` at that path. Checked from
ALIENWARE the same day:

- `D:\` exists here, but that worktree path does not.
- `seats\` in this PC's `mefor-coord` holds no `autonomy-plan-*` record.

So its seat cannot be found and its mail address cannot be reached from this PC. The only channel
that worked was a PR comment. Two lessons for the design:

1. **A mail address that is a worktree path is per-PC.** On a shared root, `mail.ps1 -To` must
   accept a seat id, or a path qualified by host, and the seat record must name its host.
2. **The other PC's clone lives at `D:\Code\MessageFoundry`, not under the user profile as on ALIENWARE.**
   Nothing may assume the two PCs share clone paths. The shared root is the one path they share.

## What Z: actually is (measured 2026-10-21 on ALIENWARE)

| Fact | Reading | Instrument |
|---|---|---|
| Backing | An SMB share on the LAN, NTFS on a Windows host, mapped by IP address | `Get-PSDrive Z`, `Win32_LogicalDisk` |
| Host | The address reverse-resolves to `Nucbox01`, a third box, not MEFORDEV01 | `Dns.GetHostEntry` |
| Kind | A real share, not a sync folder (no OneDrive or Offline Files layer found) | `net use`, `Win32_OfflineFilesCache` empty |
| Round trip | ping under 1 ms; 20 x (exists + listing) took 76 ms, the same as 20 local listings of `seats/` | `Measure-Command` |
| Client caches | directory cache 10 s, file-info cache 10 s, not-found cache 5 s, session timeout 60 s | `Get-SmbClientConfiguration` |
| Mapping | `net use` shows Z: in this logon; `HKCU:\Network\Z` returned nothing | `Get-ItemProperty` |
| Neighbours | The share already holds unrelated files, and its access list is unknown | `Get-ChildItem Z:\` |

Not measured from ALIENWARE, on purpose: whether an elevated shell or a service sees Z:, and atomic
create and rename on the share. No probe file was written to Z: from this PC, because writing
outside the worktree needs the owner. MEFORDEV01 measured both, below.

## What MEFORDEV01 measured (2026-10-21)

A session on MEFORDEV01 ran the probe the owner asked for. Its report is
`Z:\mefor-coord-probe\MEFORDEV01-2026-10-21.md`.

| Fact | Reading |
|---|---|
| User and paths | A separate LOCAL account that has the same name as ALIENWARE's, not one shared identity. The profile's `Code` folder is a junction to `D:\Code`, so every common dir is on D:. Worktrees there report `D:\Code\...` paths. |
| Mapping | Z: is the same share, mapped by IP, persistent. `EnableLinkedConnections` is not set, so an elevated shell does not see Z:. That confirms the UNC-path rule. |
| Host | `Nucbox01` resolves by mDNS (`Nucbox01.local`), not by DNS, and TCP 445 answers. Forward resolution from ALIENWARE was not measured. |
| Tools | git 2.55.0, gh 2.102.0, pwsh 7.6.7, Python 3.14.7, uv 0.13.1. The same Claude accounts are signed in as on ALIENWARE. |
| Power | Sleep on AC is never. |
| Latency | 1 to 3 ms per round on Z:. The share was faster than a local temp folder. |
| **CreateNew race** | Two processes, 100 slots: 51 and 49 wins, **no double winners and no empty rounds.** Exclusive create holds on this share, from one client. |
| **Rename over a file being read** | **Not safe.** 2 of 50 `File.Move(..., $true)` calls failed with "Access to the path is denied.", and 56 of about 2,500 reads failed with a sharing violation. No reader saw partial content. |
| Local state | MEFORDEV01's own `mefor-coord` holds about 25,000 files: 4,634 under `seats/`, 2,834 under `mail/`, 880 under `alloc/`, 153 under `claims/`, plus large retired and backup trees. |

What this changes:

1. **BUILT. Writers that replace a file by rename need a retry, and readers must treat a sharing
   violation as "retry", never as "missing" or "torn".** `coord-root.ps1` holds the one helper:
   `Move-CoordFileReplace` renames in one step and retries a sharing violation or access denied, and
   `Read-CoordText` retries the same errors, and opens sharing read, write and delete so that it
   never blocks a rename itself. The retry is short and bounded; its numbers live once, in that
   file. A missing file is never retried, and when the tries run out the original error surfaces.
   At least these writers on shared kinds use it: `seat.ps1`, `lane.ps1`, `handoff.ps1` and
   `claim.ps1`'s refresh. `seat.ps1` and `lane.ps1` had used `Move-Item -Force`, which deletes
   before it renames, so a reader could find the record missing. At least the main readers of seat,
   claim, allocation, lane, handoff and mail records use `Read-CoordText`. The Python twin,
   `read_text` in `coord_root.py`, serves the claim and ledger gates, which only read.
   `tests/test_coord_smb_retry.py` holds each against a second process holding the file with no
   sharing, with a plain-call control that must fail. **Not covered:** `alloc.ps1` still rewrites
   `alloc/.floor-highwater` in place rather than by rename, `tombstone-retired-backlog-allocator.ps1`
   reads and writes without the helper, and `mail-claim.ps1` keeps its own claim-by-rename protocol.
2. **The cross-PC race is still unmeasured.** The race above ran two processes on one client. Run
   it again with one process on each PC before step 7, because the two clients' caches are the
   part no single-client test sees.
3. **Merging MEFORDEV01 is a large step, not a footnote.** It copies live folders only, never the
   retired or backup trees. Each of its ADR allocation records (`alloc/adr/`) gets checked against
   the share. The retired backlog allocator's records and tombstones are not live numbers, so they
   get their own disposition rather than a collision check.
4. **Reserve Nucbox01's address in DHCP**, because an IP mapping breaks silently if it changes.
   Name the share by IP in `root.toml` until forward resolution of `Nucbox01` is measured from both
   PCs: every probe resolves the name first, and the name resolves only by mDNS.

## Why not the drive letter

- **A drive letter belongs to one logon session.** An elevated shell does not see a non-elevated
  mapping unless `EnableLinkedConnections` is set. A service under NSSM or LocalSystem sees none. A
  scheduled task sees one only if it runs as the user with the mapping live.
- **The second PC may map a different letter**, or none.
- The UNC path names the same thing in every one of those contexts. Scripts read the UNC path; Z:
  stays the owner's convenience.

## Why not move the whole directory

At least five things under `mefor-coord/` are local by nature. Moving them adds network latency,
cross-PC false sharing, or both.

| Path | Class | Why |
|---|---|---|
| `seats/` | SHARED | The only way to find a peer across accounts (CLAUDE.md section 5). The point of the change. |
| `mail/` | SHARED | Cross-account, and now cross-PC, messages. |
| `claims/` (+ `.history`) | SHARED, exclusive | One item, one holder, fleet-wide. Two PCs claiming one item is the failure to prevent. |
| `alloc/` | SHARED, exclusive | ADR numbers. The allocator has collided before; a per-PC copy would collide by design. |
| `locks/` | FOLLOWS ITS RESOURCE | A lock lives on the same root as the thing it guards. `lock.ps1` callers must be sorted one by one. |
| `handoffs/` | SHARED | A seat can be resumed from either PC. |
| `wiki/` (inbox) | SHARED | Korus `scripts/wiki/*.ps1` take `-StateRoot`; point it at the shared root. |
| `announce/` | LOCAL | Per-session delivery receipts for the `list_sessions` lane, which is itself per-PC. |
| `wiki-prompt/` | LOCAL | Per-session Stop-hook state. |
| `overlap-cache/`, `overlap-terms.json` | LOCAL | A cache, about 190 MB measured. Rebuildable; never worth a network hop. |
| `pwsh-burst/` | LOCAL | Measures this machine's CPU. |
| `test-slots/` | LOCAL | Leases on this machine's test capacity. |

## The bug a plain path change would ship

**Liveness checks judge a record by looking at this machine's disk.** `claim.ps1` marks a claim
`HOLDER GONE` when `Test-Path` cannot find the holder's worktree (around its `HeldPath` check), and
`seat.ps1` probes a seat's worktree the same way. A claim taken on MEFORDEV01 names a path that does
not exist on ALIENWARE. After a plain move, every live claim from the other PC would read as
`HOLDER GONE` and invite a `-Force` release. That is the duplicate-work failure the claim registry
exists to stop.

The fix is part of the change, not a follow-up:

1. Every shared record carries `host` (`$env:COMPUTERNAME`). `seat.ps1` already writes it into its
   stage log, not into the record.
2. A liveness check judges only records whose `host` is this machine. A record from another host
   reads `ON <HOST>, NOT CHECKABLE HERE`, never `GONE`.
3. A record with no `host` is treated as this machine's, which is true of every record written
   before the change.

## The worktree gate must follow the root, by tightening

**CORRECTED 2026-10-21.** This section first said the gate's exemption must widen to the shared
root. Reading the gate showed the opposite. Rule 1 refuses a write tool's target under the primary
checkout only, so a target on the share is not governed at all, and nothing needs exempting. What
does not follow the root is **rule 1b**: it refuses a hand-written file under `alloc/`, `claims/`
and the other machine-read registries, because a hand-written claim TRANSFERS a live one. On the
share, rule 1b would not fire, so a Write tool could forge a claim or an allocation there.

The fix is a tightening: rule 1b also matches the configured shared root. The gate reads that root
lexically (env var, then each root's `root.toml`) and makes no network call, so it adds no latency
to a tool call. The installed copy of the gate changes only when `install-gate.ps1` runs again.

## Offline behaviour: fail closed for exclusive ops, fail open fast for reads

A dead SMB server does not answer "no". It hangs a file call for up to the 60 s session timeout. A
PreToolUse hook that waits on it would stall every tool call in every session on both PCs.

| Operation | If the shared root does not answer |
|---|---|
| `claim.ps1`, `alloc.ps1`, ledger and claim git hooks | **Refuse, and say the root is down.** Never fall back to a local copy: a fallback splits the fleet into two registries that each think they are the only one. |
| Seat declare, mail send, handoff write | Refuse with a clear message. The caller retries later. |
| Hooks that read (announce, mail drain, roster, collision gate) | Skip with a one-line note. Never block the tool call. |

One shared resolver does the probe: a TCP connect to port 445 with a 1.5 s timeout, then the file
call. It caches a "down" verdict per process for 60 s, so a dead share costs one timeout, not one
per hook.

## Atomicity over SMB

The scripts rely on three primitives. On a Windows NTFS server all three are decided by the
server, so they hold across clients:

- **Create-new fails if the file exists** (`FileMode.CreateNew`). Claims, allocations and locks use
  this, and the server makes it exclusive.
- **Rename over an existing file** is atomic on the server.
- **An open with no sharing** is enforced by the server.

What the client caches do break is **reads**: a new file can stay invisible for up to 10 s, and a
deleted one can still look present. So:

- Never decide "free" from a listing or `Test-Path`. Decide by attempting the exclusive create.
  The scripts already do this for claims and allocations; the migration audit confirms each caller.
- Accept that a roster or inbox read may be up to 10 s stale. Nothing in the fleet acts faster.
- A disconnected client can leave a durable handle open for up to about 60 s. A lock taken just
  before a network drop may block that long. Locks keep their staleness timeouts.

## PHI and secrets

Coordination records are seat goals, item numbers, paths and message text. None may carry PHI or a
secret, and the engine's rules (CLAUDE.md section 9) already forbid both. Two extra safeguards,
because the share is reachable from more than one machine:

- **Restrict the folder.** The owner chose the general `Shared` share, which already holds
  unrelated and possibly sensitive files and whose access list is unknown. So set an NTFS access
  list on `\\Nucbox01\Shared\mefor-coord` that grants only the accounts the two PCs present to
  Nucbox01, with inheritance off. Those are two separate local accounts that share a name, so name
  each one. A dedicated share remains the stronger option.
- Mail bodies are free text. `mail.ps1` should refuse a body that matches the leak gate's secret
  patterns, the same patterns the pre-commit gate uses. That is a follow-up, not a precondition.

## The contract every script reads

One resolver, `scripts/coord/coord-root.ps1` (dot-sourced) plus a Python twin for the git hooks and
`read_batch.py`. Two functions:

| Function | Returns |
|---|---|
| `Get-CoordSharedRoot` | `$env:MEFOR_COORD_ROOT` if set, else the `shared_root` value in `<git-common-dir>/mefor-coord/root.toml`, else `<git-common-dir>/mefor-coord` (today's behaviour). Probes reachability as above. |
| `Get-CoordLocalRoot` | Always `<git-common-dir>/mefor-coord`. |

Rules:

1. Each state path calls exactly one of the two, per the class table. No script builds
   `git-common-dir/mefor-coord` by hand any more; about 36 files do today.
2. The env var wins so that a test, a single session or a rollback can override without touching a
   file.
3. `root.toml` is per-clone and untracked, so each PC sets its own UNC path.
4. A cloud session (`CLAUDE_CODE_REMOTE=true`) still refuses, unchanged.
5. A test pins both roots to temp directories through the env var.
6. Korus wiki scripts get `-StateRoot (Get-CoordSharedRoot)`. The batch skill's `seats_dir()` calls
   the Python twin.

## Alternatives weighed

| Option | Verdict |
|---|---|
| Z: as a drive letter, whole directory | Rejected. Invisible to elevated shells and services; ships the liveness bug; drags local caches over the network. |
| Private GitHub repo or ref as the store | Rejected for seats and mail: a push per heartbeat is seconds of latency and spends the fleet's shared GitHub budget. Strongest compare-and-swap of any option, and works from cloud sessions too, so **a good later home for `alloc/` alone** if the SMB allocator ever collides. |
| A small coordination service on one PC | Rejected for now: a new process to run, secure and keep alive, for a beta. Revisit if a third PC or cloud sessions need to join. |
| Per-PC state plus a sync (robocopy, Syncthing) | Rejected for claims and allocations: sync cannot give exclusion, so both PCs win the same item. Fine only for read-mostly data, which does not need it. |
| Shared root by setting, local fallback | **Chosen**, with one change: no fallback for exclusive operations. |

Single point of failure: Nucbox01. If it is down, nobody can claim or allocate on either PC, by
design. Reads and builds keep working.

## Migration

1. Create `\\Nucbox01\Shared\mefor-coord` and restrict its access list as above.
2. On each PC, in a desktop shell, an elevated shell and a scheduled task, a probe script measures:
   UNC reachability, exclusive create (two processes race 100 times, exactly one wins each time),
   rename-over, and per-call latency. Results go into this note. Any failure stops the migration.
3. Land the resolver, the `host` field, the host-aware liveness checks and the gate tightening, with
   tests. Behaviour is unchanged, because no root is configured yet.
4. **BUILT.** Land the host-qualified box key: hash `<HOST>|<path>`, not the path alone, for seat
   ids, mailboxes and lane files. `ConvertTo-BoxKey` in `scripts/coord/mail-key.ps1` does this, and
   `ConvertTo-LegacyBoxKey` is the one definition of the old key, for readers only. The drain and
   the watcher move the old box's inbox into the new box before they read. `seat.ps1` takes its
   prior from whichever of its two records says it is newer. `fleet.ps1` treats the old and new
   boxes of one tree as one seat. The lane hook reads whichever lane file holds the fresher level. A send to a seat id published before the change goes to the
   new box. Writers write only the new key. `lane.ps1` no longer refuses another host's record,
   since the key now keeps the two apart. A record read from an old box is judged by its `host`,
   because every PC at that path shares the old name.
   **Roll out by updating the primary checkout soon after the merge.** The hooks run from it, while
   `mail.ps1`, `seat.ps1 -Declare` and `lane.ps1` run from each worktree's branch. Until the primary
   carries this change, its drain reads only the old box. Mail a new sender queued then waits. Its
   lane hook also reads only the old lane file.
   **Copy mail and lanes to the share under host-qualified keys only** (steps 6 and 10). An old box
   copied there would be read by every PC with a worktree at that path. Move each old inbox into
   its new box first; the drain does exactly that for its own tree.
   Also before step 7: the CreateNew race rerun with one process on each PC (see *What MEFORDEV01
   measured*). The rename-retry change for writers and readers of shared kinds is BUILT (same
   section, item 1).
5. Pick a quiet window. Announce it on the old mail lane.
6. Copy `seats/`, `mail/`, `claims/`, `alloc/`, `handoffs/` and the wiki inbox to the share, with
   `robocopy /E /COPY:DT`. Leave the originals in place. **Then stamp `host = ALIENWARE` on every
   copied JSON record that has no `host`.** "No host means this machine" is true only on the PC that
   wrote the record. Unstamped on the share, MEFORDEV01 would judge an ALIENWARE claim by its own disk,
   read it as HOLDER GONE, and could reap it. The stamp needs a small script with a dry-run, written
   with this step; nothing in step 3 does it.
7. Write `root.toml` on ALIENWARE. Every new hook call now uses the share.
8. Verify: declare a seat, send a mail to yourself, take and release a test claim, and read each
   back from a second account.
9. Rename the old local copies to `*.pre-share` so nothing reads them by accident.
10. Set up MEFORDEV01 the same way, then verify from it against a seat on ALIENWARE. **First merge
    its own local state**, because it already runs sessions with its own clones: stamp `host =
    MEFORDEV01` on its records, then copy its open claims, unread mail and seats to the share. Check
    every `alloc/<kind>/<n>.json` it holds against the share before copying. A number both PCs
    allocated is a collision the owner rules on, not one the copy may overwrite.

## Rollback

1. Delete `root.toml`, or set `MEFOR_COORD_ROOT` to the local path. The next hook call is local.
2. Copy back anything written to the share since step 7 that the fleet still needs, at least open
   claims and unread mail.
3. Rename the `*.pre-share` copies back.

The resolver keeps today's behaviour when nothing is configured, so rollback never needs a code
revert.

## Not in scope

- `session-registry.ps1`, `presence.ps1` and the `list_sessions` lane read the desktop app's own
  per-PC session store. They stay per-PC. The seat registry is the cross-PC view.
- Two PCs signed in to one Claude account share one usage pool. The Steward reads usage per
  account, so it still works, but its pacing must count both PCs. Unmeasured.
- The zero-model cron that reads the seat registry (owner AFK plan, section 8) should read
  `Get-CoordSharedRoot` and run on one PC only.
