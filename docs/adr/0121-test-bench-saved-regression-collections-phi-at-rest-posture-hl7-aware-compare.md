# ADR 0121 — Test Bench saved regression collections: PHI-at-rest posture + HL7-aware compare

- **Status:** Accepted (2026-07-17) — the DEMAND-GATE-BACKLOG session builds it. IDE-only, no engine
  change; phased (one coherent commit per layer), pushes/PR owner-approved.
- **Date:** 2026-07-17
- **Related:** BACKLOG [#168](../BACKLOG.md) (Test Bench saved regression collections); [ADR
  0030](0030-anonymization-test-harness-tee.md) (de-identification — the framework authors use to
  build PHI-free cases); [ADR 0072](0072-traced-dryrun-mode.md) / the Test Bench before/after diff
  (`hl7diff.ts`, reused here for the compare); CLAUDE.md §9 (PHI rules — this ADR adds a **new
  PHI-at-rest surface**), §10 (the Test Bench is an IDE authoring surface, not an operator console);
  §8 (read encoding chars from MSH; be explicit about HL7 volatility).

---

## Context

Today the Test Bench loads a message set through a one-shot file picker, dry-runs it, and shows a
before/after diff — but it **saves no case and asserts no result**. A migrating analyst who wants to
prove a config change didn't regress a feed must re-select the same files each session and eyeball
the diffs. BACKLOG #168 asks for **persisted, named, groupable collections of cases with recorded
expected outputs and one-click rerun flagging pass/fail**.

Two decisions must be made **up front**, because they are hard to reverse once cases exist:

**1. Where the case bodies live (PHI-at-rest).** A regression collection is self-contained only if it
records each case's **input message body and its expected output body(ies)** — not just file paths,
which move and mutate. Those bodies are **PHI**. CLAUDE.md §9 governs:

> Full payloads go only to the secured store … no PHI leaves the local environment without explicit,
> reviewed configuration.

This is a genuinely **new PHI-at-rest surface** for the IDE — the first that persists message bodies.
The storage location must therefore be **machine-local and never syncable off-box**:

- **NOT** a repo-tracked / committable file — that would let PHI into git and off the machine.
- **NOT** `context.globalState` — VS Code's *Settings Sync* is eligible to sync `globalState` to the
  user's cloud profile, which could carry PHI off-machine.
- **`context.workspaceState`** (machine-local, per-workspace, **not** Settings-Sync-eligible) is the
  correct home, and authors are steered to **synthetic, de-identified cases** (ADR 0030) with an
  explicit in-UI PHI notice.

**2. What "pass" means (compare semantics).** A byte-equality compare of expected vs actual would
**always fail** on a conformant HL7 message: every ACK/message carries volatile fields that legitimately
differ run-to-run — MSH-7 (message date/time) and MSH-10 (message control ID) foremost. A naive diff
would flag these as regressions and make the feature useless. The compare must be **HL7-aware with a
volatile-field ignore policy decided up front**, reusing the existing segment/field-aware alignment
(`hl7diff.diffMessages`) so an inserted/deleted segment doesn't cascade false changes (§8: read the
separators from MSH, never hardcode `|^~\&`).

## Decision

**Persist named regression collections of `{input body, expected output bodies}` cases in
`context.workspaceState`, and judge a rerun with an HL7-aware compare that ignores a fixed default set
of volatile fields (MSH-7, MSH-10).**

- **Model — `ide/src/testCollections.ts` (NEW, pure, `vscode`-free).** Types (`TestCase`,
  `TestCollection`, `ExpectedDelivery`), the `DEFAULT_VOLATILE_FIELDS` policy, and
  `compareMessages(expected, actual, ignore?)` → `{ pass, differences[], diff }`. The compare runs
  `hl7diff.diffMessages` (reused, not reimplemented) and walks the aligned cells: a `same` cell is
  clean; an `added`/`removed` **segment** is always a real difference; a `changed` cell is a real
  difference **only** for changed fields whose `(segment id, split-index)` coordinate is **not** in
  the ignore set. `pass` iff no real difference remains. Pure ⇒ unit-testable like `hl7diff.ts`.
- **Volatile-field policy (fixed default, up front).** `DEFAULT_VOLATILE_FIELDS = MSH-7`
  (message date/time — this is "ACK dates" for an ACK message, whose MSH-7 is its generation time)
  and **MSH-10** (message control ID). Expressed as `{ seg, index }` where `index` is the
  `hl7diff` split index (`fields[6]` = MSH-7, `fields[9]` = MSH-10, because MSH-1 is the separator
  char itself, not a split element). The set is a module constant so tests pin it and a future
  amendment can extend it (e.g. a per-collection override) without changing the compare shape.
- **Persistence.** A collection is `{ name, cases: TestCase[] }`; the whole named map lives under one
  `workspaceState` key. `TestBench` (holding `this.context`) does the CRUD; `testCollections.ts`
  stays storage-agnostic. Saved from the currently-loaded rows: each row's `raw` → `case.input`, its
  `deliveries` → `case.expected`. **Never** written to a repo file or `globalState`.
- **Rerun.** Because the `dryrun` CLI takes only file paths (`--messages`, no stdin), a rerun
  **materializes each case's stored input to a fresh per-run temp directory** (`os.tmpdir()`),
  dry-runs it (`--show-phi`, so expected/actual bodies are full), compares each case's new deliveries
  against its stored `expected` via `compareMessages`, and **deletes the temp directory in a
  `finally`**. A hard crash can still leave the directory behind; *Consequences* says what removes
  it (amended 2026-11-14, BACKLOG #5415). Pass/fail is shown per case;
  a click on a case shows its expected-vs-actual differences (see *Reveal on click*).
  *Amended 2026-11-15 (engine PR 2968, BACKLOG #5415):* this supersedes "deletes the temp directory
  in a `finally`" and "*Consequences* says what removes it" above. The `finally` tries to delete the
  directory and the sweep in *Consequences* can try later, but neither always removes it, and
  case files can stay with it. The first half of that sentence, "A hard crash can still leave the
  directory behind", still holds, and a crash is not the only way a directory is left. What is
  removed and what stays is recorded in the `deleteCaseDir` and `sweepStaleCaseDirs` docblocks in
  `ide/src/collectionCaseFiles.ts`.
- **A case must also end where it did (amended 2026-11-14, BACKLOG #5416).** An errored Router or
  Handler delivers nothing, so the delivery compare alone passed a case that expects no delivery. A
  case now records the disposition its row had when saved, and a rerun passes only with that same
  disposition and, unless the recorded one is `error`, no error text. A case saved before the field
  existed fails on any rerun with error text or an `error` disposition.
- **Reveal on click (amended 2026-09-29, BACKLOG #2437, ASVS 14.2.6, owner ruling R13).** The run
  view shows each case's name, PASS or FAIL, and disposition. It shows no field value and no error
  text. The host keeps each case's differences and error. The webview asks for one case when the
  developer clicks that case's Details button, and the host posts only that case. The webview shows
  at most one case's values at a time. It clears them on Back, and when another case or view opens.
  The host drops the held values when the panel re-renders or closes, or when any collection is
  saved or deleted. A run still in flight at any of those points is dropped too. So is an older
  run that finishes after a newer one starts. One case at a time is the view's rule, not the host's:
  the host answers a well-formed request for any held case. The webview runs only this extension's
  own script, under a nonce CSP.
- **PHI notice.** The collections UI carries a one-line notice steering authors to synthetic,
  de-identified cases (ADR 0030) and stating that bodies are stored machine-locally in workspace
  state.

**Must not break:** no new engine/CLI surface; no PHI to a repo file, `globalState`, or a log; the
temp materialization is always cleaned up; the compare never hardcodes `|^~\&` (reads MSH); the
existing Load / before-after / Coverage-Profiling panes and the `--show-phi` posture are untouched.

**Amended 2026-11-15 (engine PR 2968, BACKLOG #5415):** this supersedes "the temp materialization
is always cleaned up" in the sentence above: it is not always cleaned up, and case files can stay on
disk. What must not break in its place: a run tries to delete its directory, in its `finally`, or
before the error is rethrown when a case file fails to write; a sweep tries to delete old run
directories when a Test Bench panel is created and before a collection run writes its own
directory; and the delete never recurses, never follows a link that is an entry in the run
directory, and unlinks only regular files named as case files in that directory. The only
exception allowed is a race in which another process swaps the run directory, an entry in it, or
a directory above it, after the run made it or the sweep listed it. The races known to remain,
what the delete removes, and what stays are recorded in the `deleteCaseDir` and
`sweepStaleCaseDirs` docblocks in `ide/src/collectionCaseFiles.ts`.

## Acceptance Criteria

- **AC-1** — WHEN expected and actual differ **only** in MSH-7 and/or MSH-10, THE SYSTEM SHALL report
  `pass=true` (volatile fields ignored).
  → `ide/src/test/suite/test-collections.test.ts`
- **AC-2** — WHEN a non-volatile field differs (e.g. PID-5 patient name) or a segment is added/removed,
  THE SYSTEM SHALL report `pass=false` and list the differing coordinate in `differences`.
  → `ide/src/test/suite/test-collections.test.ts`
- **AC-3** — WHERE the messages use a non-`|` field separator, THE SYSTEM SHALL read it from MSH and
  still locate MSH-7/MSH-10 correctly (never hardcode `|^~\&`).
  → `ide/src/test/suite/test-collections.test.ts`
- **AC-4** — THE SYSTEM SHALL persist case bodies only in machine-local `workspaceState` — never in a
  repo-tracked file and never in `globalState` (Settings-Sync-eligible). *(Design/review-enforced; the
  storage key is `workspaceState`-scoped in `testBench.ts`.)*
- **AC-5** — WHEN a collection run completes, THE SYSTEM SHALL show each case's name, PASS or FAIL, and
  disposition, and no difference value or error text. WHEN the developer clicks one case, THE SYSTEM
  SHALL show that case's differences and error, and no other case's.
  → `ide/src/test/suite/test-bench-webview.test.ts`, `ide/src/test/suite/test-collections.test.ts`

## Options considered

1. **`workspaceState` bodies + HL7-aware compare ignoring MSH-7/MSH-10, temp-file rerun** — self-
   contained, machine-local, no off-box sync, honest pass/fail. **CHOSEN.**
2. **Store file paths only, rerun the original files** — no new PHI-at-rest, but not self-contained
   (files move/mutate); a "regression suite" that silently changes when a file is edited is a trap.
   Rejected.
3. **`globalState` for cross-workspace collections** — Rejected: Settings-Sync-eligible, could carry
   PHI to the user's cloud profile (§9 breach).
4. **Byte-equality compare** — Rejected: always fails on volatile MSH-7/MSH-10; useless.
5. **A committed `.regression.json` in the repo** — Rejected: PHI into git / off the machine (§9).

## Consequences

**Positive** — Analysts save named suites once and re-run with one click; pass/fail is HL7-honest
(volatile fields ignored, segment inserts don't cascade). The pure `testCollections.ts` reuses
`hl7diff` and is unit-testable. Storage is machine-local and non-syncable by construction.

**Negative / risks** — A **new PHI-at-rest surface**: message bodies persist in `workspaceState`
(machine-local, but plaintext in VS Code's per-workspace storage). Mitigated by the synthetic-case
steer (ADR 0030) and the in-UI notice; workspaceState is not encrypted, so authors must not save real
PHI. Rerun writes transient PHI to a temp dir — always cleaned in `finally`, but a hard crash mid-run
could leave a temp file. *Amended 2026-11-14 (BACKLOG #5415):* the run's directory is owner-only
(`0700`) and each case file is created exclusively and owner-only (`0600`) on POSIX; on Windows
those modes do nothing and the temp directory's own ACL governs, which is owner-only for the default
per-user TEMP but not for a shared directory TEMP is pointed at. A directory a crash left behind is
deleted when the Test Bench next opens or next runs a collection, once it is over an hour old, and
not before, so a run in another window survives; on POSIX only a directory this user owns is
deleted. Until then it stays on disk, with no bound if the Test Bench is not used again. The dry-run is handed the directory, not one path per case, so a large
collection no longer grows the command line (`ide/src/collectionCaseFiles.ts`). The volatile policy is a fixed default;
a feed with other volatile fields (e.g. a bespoke timestamp segment) may show a false regression until
a future per-collection override lands.

*Amended 2026-11-15 (engine PR 2968, BACKLOG #5415):* this supersedes, in the paragraph above,
"always cleaned in `finally`", the sentence beginning "A directory a crash left behind is deleted",
and the sentence "Until then it stays on disk, with no bound if the Test Bench is not used again".
The `finally` tries to delete a run directory and a later sweep can try to, but neither always
removes it: case files, and the directory holding them, can stay with no bound, and a sweep can
unlink the case files of a run still going more than an hour after its directory was last
modified, in another window included. The sweep runs when a Test Bench panel is created and before
a collection run writes its directory; which directories it tries, and the races that can get past its checks, are in
the docblocks named below. The rest of the sentence beginning "Rerun writes transient PHI", "but a
hard crash mid-run could leave a temp file", still holds. The detail is recorded in the
`deleteCaseDir` and `sweepStaleCaseDirs` docblocks in `ide/src/collectionCaseFiles.ts`.

**Out of scope** — Per-collection custom ignore policies (future amendment); encrypting
`workspaceState`; cross-workspace/shared collections; any engine/CLI change (e.g. a `dryrun` stdin
mode that would avoid temp files); an operator-console regression runner (§10).

## Amendment 2026-09-29 -- case bodies move to SecretStorage (BACKLOG #1174)

**What changed.** Saved collections now live in VS Code SecretStorage (`context.secrets`), the store
`ide/src/auth.ts` already uses for the engine bearer token. VS Code encrypts it with a key the OS
keychain holds. `workspaceState` stored the case bodies in plaintext in VS Code's per-workspace
storage, which the Negative / risks paragraph above names. The new home is
`ide/src/collectionStore.ts`, a `vscode`-free module that `testBench.ts` hands both stores to.

**What it replaces.** AC-4's "only in machine-local `workspaceState`" now reads "only in SecretStorage,
scoped to the workspace". The other limbs of AC-4 still hold: never a repo-tracked file, never
`globalState`. The "encrypting `workspaceState`" line under Out of scope is answered by moving off it
rather than encrypting it.

**Two details carry the old behaviour over.**

1. SecretStorage is shared by every workspace the extension runs in, while `workspaceState` was
   per-workspace. So the key carries a SHA-256 of the workspace's storage URI, and names no local path.
2. Existing collections migrate on the first load. The store writes them to SecretStorage and only
   then deletes the `workspaceState` copy, so a crash between the two leaves both and the next load
   finishes. On a name held in both, the SecretStorage copy wins.

**Where SecretStorage is weaker than it looks.** Three limits come from VS Code, not from this code.
Read in VS Code's `src/vs/platform/secrets/common/secrets.ts` by the review of this change, not
measured on a machine.

1. With no OS keyring (a Linux desktop without one), VS Code keeps secrets in memory only and
   `store()` still succeeds. There the migration moves the old map into memory and deletes the
   `workspaceState` copy, so the collections are gone after a restart, and every later save is lost
   the same way.
2. When VS Code cannot decrypt a stored secret (for example after the OS keychain key is reset), it
   deletes the secret and reports it absent. The collections then read as empty, with no error.
3. The key follows the workspace's storage URI. Turning a folder into a multi-root workspace, or
   renaming or deleting the folder, strands the old secret: the collections seem to vanish, and the
   case bodies stay in SecretStorage, which VS Code does not clean up per workspace.

So collections are a convenience store, not a record. A saved suite should be re-creatable from its
message files. A command to delete every saved collection, including stranded ones, is not built.

**What it does not change.** Case bodies are still PHI when an author saves real messages, so the
synthetic-case steer and the in-UI notice stay. The rerun still materializes inputs to a temp
directory and deletes it in `finally`. *Amended 2026-11-15 (engine PR 2968, BACKLOG #5415):* this
supersedes "deletes it in `finally`": the `finally` tries to delete it and does not always succeed,
as the dated note beneath *Must not break* says.

## Amendment 2026-10-20 -- the SecretStorage key carries a scheme version (BACKLOG #3426)

**What changed.** The key is now `messagefoundry.testBench.collections.v1.<digest>`. Before, it had
no version, so a change to the digest would have left every saved collection under a key nothing
reads. The release picks the scheme from a table compiled into it. No stored value names a scheme;
the lookup refuses an unknown one, which guards the code path and not any stored data.

**The move.** The first load moves a value from the unversioned key to the versioned one, write then
delete, as stored and unparsed. A value already under the versioned key wins whole, with no merge. So
a build from before this change that saves again after the move loses that save.

**Reset.** The Delete prompt removes at least the versioned key and the unversioned one, after any
running migration settles. It keeps a `workspaceState` map a failed migration left, which the next
load merges. It does not reach a key stranded under an earlier storage URI (limit 3 of the
2026-09-29 amendment), and that limit also covers an unversioned key of a workspace never reopened.
