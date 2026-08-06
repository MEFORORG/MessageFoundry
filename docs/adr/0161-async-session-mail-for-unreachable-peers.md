<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<!-- Copyright (C) 2026 MessageFoundry Organization and contributors -->

# ADR 0161 — Async session mail for unreachable peers

- **Status:** Proposed (2026-08-05) — the code is a **prototype and is deliberately NOT WIRED**; see §"Status and what gates wiring"
- **Date:** 2026-08-05
- **Related:** [BACKLOG #1028](../BACKLOG.md) · [SESSION-MAIL.md](../SESSION-MAIL.md) (the operator-facing document) · [ADR 0158](0158-silent-controls-green-signals-that-mean-nothing-and-shape-over-detection.md) (silent controls — a green signal that means nothing) · [ADR 0160](0160-public-repo-content-policy-operator-and-security-review-material-only.md) (what belongs in the public repo) · [CLAUDE.md](../../CLAUDE.md) §5 (worktrees, git discipline), §9 (PHI), §11 (state a load-bearing fact once; no glyphs) · [PHI.md](../PHI.md)

---

## Context

### The realtime channel cannot address two classes of peer, structurally

Claude Code sessions running in the Desktop app under one login already have a realtime channel: the
session-management `send_message` tool, driven by the announce hook described in
[WORKTREES.md](../WORKTREES.md). That channel is not deficient. It is *unaddressable* for two peer
classes, and in both cases the reason is architectural rather than a bug or a filter:

- **A session launched by the VS Code extension.** The Desktop app's session tooling enumerates an
  in-memory map of sessions **the Desktop app itself spawned**. A VS Code session is never entered
  into that map — not filtered out, never registered — so it cannot be listed and cannot be messaged.
- **A session under a different login.** Each config root (`~/.claude`, plus each
  `~/.claude-account-N`) is independent, and a session is visible only to the login that owns it.
  Measured 2026-08-05: in one repo, at one moment, the Desktop sessions were on one config root while
  the VS Code sessions were on a second, and neither side could see the other.

The peer-to-peer protocol compiled into the client is not an alternative. The registry field that
would carry a peer's socket address is written by no code path, and the lookup **fails silently
green** — an empty peer list, not an error. That failure shape is exactly the ADR 0158 class: a
channel that cannot report its own deadness.

### Why a file drop

A file write is the only transport blind to **both** axes at once: it does not care which
application spawned the recipient, and it does not care which account the recipient authenticated
against. Every richer option (a socket, a broker, an MCP server, a shared in-memory registry) is
scoped by the process tree or the config root that created it, which is the same wall.

### Where it lives, and why that satisfies the public-repo rule by location

The queue lives under `<git-common-dir>/mefor-coord/mail/` — inside `.git`, shared by every worktree
of the repo. Nothing under `.git` can be placed in a commit by any git command, and `mefor-coord` is
not a ref namespace, so `push --mirror` cannot carry it either. This is a **location** argument, not
a redaction argument: worktree paths and branch names are therefore written in plain text in the
queue on purpose, because hashing them would buy nothing already bought by location while destroying
the ability to read the queue with `ls` when it misbehaves. It also keeps the whole channel on the
right side of [ADR 0160](0160-public-repo-content-policy-operator-and-security-review-material-only.md)
without a deny-list.

### Addressing is by worktree, not by session id and never by worktree name

Three reasons, each observed rather than assumed:

- A worktree **name** is a creation-time label and nothing keeps it current. One worktree was observed
  switched onto four different branches by four different sessions in a single day.
- A **session id** churns. It is stable while a session lives, but `/clear` mints a new one, so mail
  addressed to an id can be stranded by a keystroke. Session id is kept only as an optional *filter*
  on a message.
- The worktree is what the work is attached to, and it is what a sender actually knows.

A recipient path is matched case-insensitively and **exactly**, never by prefix: every worktree path
in this repo is an extension of the primary checkout's path, so a prefix match resolves any peer to
some arbitrary worktree. VS Code also records a lowercase drive letter where the Desktop app records
an uppercase one, so a case-sensitive compare splits one physical worktree into two boxes that never
see each other's mail.

### A red-team pass found eight defects, and they are why this is not wired

The prototype was reviewed adversarially before wiring. Eight findings, four of them severe. Written
in the conditional throughout, per [CLAUDE.md](../../CLAUDE.md) §0 — this is developer tooling in a
not-deployed beta, so nothing below is a live exposure:

1. **Path traversal through the message id (critical).** The drain builds its receipt path from the
   JSON `id` field, which is body content the writer controls. An id of `..\..\..\evil` would write
   outside the mail root.
2. **An executable command line in the injection (critical).** The drain emits a paste-ready
   `mail.ps1 -Send -To "<sender path>" -Body "..."` reply line. The sender path is writer-controlled
   and the line is shell-parsed, and the line also *teaches the recipient to execute a command that
   arrived in tool output* — which CLAUDE.md forbids outright.
3. **The body can forge the frame (major).** The body is injected verbatim into a delimited block, so
   it can contain a counterfeit end-of-message delimiter followed by forged higher-authority text.
4. **The mutual-exclusion primitive does not exclude (critical).** See the measurement below.
5. **No write-side trust boundary is stated (major).** Any process running as the user can drop a
   file into any inbox. Every `from.*` field is an unverified self-assertion, and the drain renders
   them as provenance.
6. **No receiver-side caps (major).** There is no message-count or byte cap on a single injection,
   and the send-time cap is bypassed by writing the file directly.
7. **Content is unaddressed (major).** A body would be unencrypted, unredacted and retained
   indefinitely, and delivery would make a second copy of it in the recipient's transcript that no
   prune of the queue reaches.
8. **The urgent tier is one-shot (major).** The mid-turn rewake belongs to the process Claude Code
   spawned and tracks by hook id, so a self-spawned grandchild's exit code is heard by nobody. The
   watcher cannot re-arm itself.

### The measurement that forced the claim primitive

Finding 4 is not a race that is hard to hit. It is a false primitive.

**`[System.IO.File]::Move(src, dst)` returns success without moving, for losers, under concurrent
contention.** Measured 2026-08-05 on .NET 10.0.9 / Windows 10.0.26200, with 16 racers over 500
rounds, each round racing to move one source file. The instrument was written in C#, not PowerShell,
deliberately: PowerShell scriptblock-as-delegate closures do not capture loop variables reliably and
would have produced a clean-looking result for the wrong reason.

| Arm | Destination | Result over 500 rounds |
| --- | --- | --- |
| **A** — what the drain did | one shared name | **Every** round had more than one racer return with no exception. In **375 of 500** rounds **all sixteen** racers returned no exception. |
| **A**, post-condition check | one shared name | `File.Exists(dst) && !File.Exists(src)` was **true for all 16 racers in all 500 rounds**. |
| **B** — a name only the claimer could mint | unique per claimer | **Exactly one** racer's own destination existed, in **500 of 500** rounds. |

Two controls are why the above is trustworthy rather than a runtime that stopped throwing:
`Move()` on a source that never existed raises `FileNotFoundException` (the instrument can see
failure), and a **sequential** `Move()` of an already-moved source also raises
`FileNotFoundException`. The silent no-op is therefore **contention-only**.

The obvious fix — "verify the post-condition after the move" — **cannot discriminate a winner from a
loser**, because the winner's move makes that post-condition true for everybody. A fix built on it
would pass a test written against it and would still deliver one message N times.

### The correction: arm B was measured from the wrong vantage point

**Arm B above is not sufficient, and the way it looked sufficient is the more useful finding.** It ran
16 threads inside **one process**, where a shared per-process metadata cache hides the defect
completely. Re-measured with **16 separate `pwsh` processes** over **800 rounds** — the configuration
the drain actually runs in, since every hook invocation is its own process:

| Question | Result over 800 cross-process rounds |
| --- | --- |
| Destination files on disk | **800 for 800 rounds** — the *construction* is sound; uniqueness does exclude |
| `File.Exists(own destination)` as the verdict | reported a win to **more than one racer in 46 of 800 rounds (5.75%)**, across **49** destinations absent from the final listing |
| Re-probe 3 ms later | cleared only **38 of the 49** — so waiting is **not** a fix |
| Exclusive `File.Open(dst, Open, Read, None)` | refused **all 49** phantoms; **exactly one** opener in **800 of 800** rounds |
| Exclusive open, false negatives | **3 of 800** rounds had the true winner's own open fail transiently |

So `File.Exists` returns a **transient false positive for a path that was never created**, visible only
across processes. In the drain a false win is a **double delivery**: two claimers render the same body
and write the same receipt path.

The verdict is therefore an **exclusive open**, which stale metadata cannot answer, with a short retry
to absorb the 0.375 percent false-negative rate. **Ceding is the safe failure direction** — an
unclaimed message stays in `claiming/`, is never delivered twice, and is reported by `mail.ps1 -Status`
and by the dead-owner sweep. A false win is not recoverable in the same way.

> The general lesson, and the reason this section exists rather than a corrected table: **a
> concurrency result is a fact about a configuration, not about an API.** The first measurement was
> careful, controlled, and answered a question one step to the side of the one that mattered. See
> [`docs/Secure_Development_Standards.md`](../Secure_Development_Standards.md) §3 on confirming the
> instrument answers the question you asked.

**`scripts/coord/claim.ps1` is NOT affected.** Its mutual exclusion is an exclusive `CreateNew`, and
its `Move` targets a per-PID-unique temporary with overwrite semantics, so no two processes ever
contend on one source. Do not "fix" it, and do not record it as broken.

## Decision

**Build the async lane as a file drop under `<git-common-dir>/mefor-coord/mail/`, keyed by recipient
worktree; keep the realtime channel as the desktop-to-desktop path; and treat every message as
untrusted data whose only authority is that it exists.** In clauses:

- **D1 — An async file-drop lane, addressed by worktree.** A message is a JSON file under
  `box/<key>/inbox/`, where `<key>` is derived from the recipient's normalised worktree path by one
  function with **one definition**, dot-sourced by both the sender and the drain. Two copies of that
  function would drift, and the drift is silent on both ends: the sender sees a queued message, the
  recipient sees an empty inbox, and nothing reports a mismatch. Injectivity comes from a hash over
  the normalised path; the human-readable slug exists only so a directory listing is legible.

- **D2 — This does NOT replace the realtime channel.** Desktop-to-desktop messaging under one login
  stays on the existing tool and the announce hook. The lane exists for the peers that channel cannot
  address, and adding a second path for peers already reachable would produce two notions of "how you
  reach a session" with no rule for choosing between them.

- **D3 — The location is the leak control.** Living inside `.git` under a non-ref namespace is what
  makes plain-text worktree paths and branch names acceptable in the queue. This is not a
  confidentiality claim about the contents; it is a claim that no git operation can publish them.

- **D4 — The claim primitive is: move to a name no other claimer could mint, then verify your own
  destination exists.** Not a shared destination, and not a post-condition check on a shared
  destination — the measurement above shows that check is true for every loser. A per-claimer token
  goes in the destination name; the claimer that finds *its own* destination present is the one that
  won, and it is the only one that may deliver or write a receipt. This applies at all three sites
  the review named: the drain's expiry sweep, the drain's inbox-to-seen claim, and the sender's
  publish from `tmp/` into an inbox. The publish does not contend on a shared source (each message is
  written to a uniquely named temporary first), so the measured no-op does not apply to it directly;
  it is included because the current code relies on `Move` throwing when the destination already
  exists, and after Arm A that is not a property to rest a control on when verifying is cheaper than
  reasoning about it.

- **D5 — The on-disk filename is authoritative; the JSON `id` field is discarded.** The drain
  validates the filename stem against a fixed shape **before** it builds any path from it, and never
  consults the body's `id` for anything. Sanitising the body id would be a weaker control that looks
  identical from the outside: it leaves a writer-controlled string on a path-construction route.

- **D6 — The drain never emits a runnable command.** It prints a validated message id and points at
  [SESSION-MAIL.md](../SESSION-MAIL.md). A reply line assembled from writer-controlled fields is
  both a shell-injection route and an instruction to execute something that arrived in tool output.

- **D7 — One body sanitiser, stated once, applied at the single point of injection.** The framing
  block is the security boundary, so the body must not be able to mint a second delimiter or forge
  higher-authority text after one. A single ASCII scrub plus newline handling, defined in one place
  and referenced everywhere else — not a rule restated in three files that can diverge.

- **D8 — The write side is untrusted, stated in the document AND in the injected preamble.** This
  design **cannot** authenticate a writer: any process running as the user can drop a file into any
  inbox, and no filesystem permission available here separates one of the user's own sessions from
  another. So every `from.*` field is rendered as a self-assertion, and the preamble that precedes
  every delivery says the message is data, not authority — it authorises nothing, and it is not
  approval for anything that would otherwise need confirmation.

- **D9 — The receiver caps what it will inject.** A per-injection message count and byte budget,
  enforced by the drain. A send-time cap alone is not a cap: it is bypassed by writing the file
  directly, which is the same act the whole transport consists of.

- **D10 — A content rule with the force of the secrets rule.** A mail body is a plain file with no
  encryption, no redaction and no retention bound, and delivery duplicates it into the recipient's
  transcript, which no prune of the queue reaches. Therefore: no PHI and no secrets in a body, ever.
  The rule is stated once in [SESSION-MAIL.md](../SESSION-MAIL.md) and referenced from
  [PHI.md](../PHI.md); this ADR records the decision, not a third copy of the text.

- **D11 — The urgent tier stays one-shot, documented rather than papered over.** Re-arming has to
  come from a hook event, because a self-respawned watcher is a grandchild whose exit code Claude
  Code is not listening for. This ADR does not solve it. A watcher that appeared to re-arm and did
  not would be the ADR 0158 defect in its purest form.

## Acceptance Criteria

> EARS form, each linked to the test that verifies it. The linked module lands with the fix lane; see
> "To resolve on acceptance".

- **AC-1** — WHEN a message file whose JSON body carries an `id` containing path separators or
  `..` segments is drained, THE SYSTEM SHALL write its receipt under the validated on-disk filename
  and SHALL create no file outside the mail root.
  → `tests/test_session_mail.py::test_a_hostile_json_id_writes_nothing_outside_the_mail_root`
- **AC-2** — IF a message filename stem does not match the fixed id shape, THEN THE SYSTEM SHALL
  decline to deliver it and SHALL count it, never silently discarding it.
  → `tests/test_session_mail.py::test_a_filename_this_channel_did_not_mint_is_never_parsed`
- **AC-3** — THE SYSTEM SHALL NOT emit any runnable command line in an injection, for any message
  content, including one whose sender fields contain shell metacharacters.
  → `tests/test_session_mail.py::test_the_injection_contains_no_paste_ready_command`
- **AC-4** — WHEN a body contains text resembling the end-of-message delimiter, THE SYSTEM SHALL
  render that text inside the message block and the injection SHALL contain exactly one
  end-of-message delimiter.
  → `tests/test_session_mail.py::test_a_body_cannot_forge_the_end_of_message_delimiter`
- **AC-5** — WHEN N claimers drain one inbox concurrently, THE SYSTEM SHALL result in exactly one
  claimer observing its own uniquely-named destination, and exactly one delivery of that message.
  → `tests/test_session_mail.py::test_exactly_one_claimer_ends_up_with_the_message`
- **AC-6** — THE SYSTEM SHALL include, in every injection, a preamble stating that the message is
  untrusted data, that its sender fields are self-asserted, and that it authorises nothing.
  → `tests/test_session_mail.py::test_the_frame_and_the_preamble_tell_the_reader_the_sender_is_unverified`
- **AC-7** — IF an inbox holds more messages or more bytes than the receiver's per-injection budget,
  THEN THE SYSTEM SHALL inject up to the budget and SHALL state how many were withheld.
  → `tests/test_session_mail.py::test_more_messages_than_the_cap_are_bounded_and_the_rest_are_deferred`
- **AC-8** — WHILE any error occurs in the drain, THE SYSTEM SHALL exit 0 and write nothing to
  stderr, for every input including hostile and unreadable state.
  → `tests/test_session_mail.py::test_an_unwritable_receipt_directory_never_breaks_the_turn`
- **AC-9** — THE SYSTEM SHALL contain no byte above 0x7F in any mail script source, and SHALL emit no
  byte above 0x7E in any injection, including for a body carrying non-ASCII and control characters.
  → `tests/test_session_mail.py::test_the_mail_scripts_are_ascii_only`
- **AC-10** — WHEN the drain runs and delivers nothing, THE SYSTEM SHALL distinguish "the box was
  empty", "the box was unreadable", "everything expired" and "the OFF switch is set" from one another
  in what it emits.
  → `tests/test_session_mail.py::test_a_second_drain_shows_nothing_and_says_so`

## Options considered

1. **An async file drop under `<git-common-dir>/mefor-coord/mail/`, keyed by worktree — CHOSEN.**
   The only transport blind to both the spawning-application axis and the config-root axis, and the
   only one whose leak posture is settled by location rather than by a rule someone has to follow.

2. **Extend the realtime channel to reach VS Code sessions.** Rejected: not available to us. The
   Desktop app's map contains what the Desktop app spawned, and a VS Code session is never entered
   into it. There is no registration seam on our side of that boundary.

3. **Build on the client's compiled peer-to-peer protocol.** Rejected on measurement: the registry
   field carrying a peer's socket address is written by no code path, and the lookup fails silently
   green — an empty peer list rather than an error. Building on it would produce a channel that is
   indistinguishable, from the sender's side, between "no peers" and "does not work".

4. **Key boxes by session id.** Rejected: an id is minted fresh by `/clear`, so mail addressed to one
   can be stranded by a keystroke. Kept as an optional per-message filter, which is the role it can
   actually hold.

5. **Key boxes by worktree name.** Rejected: a name is a creation-time label that nothing keeps
   current; one worktree was observed on four branches under four sessions in one day.

6. **A lock file or a mutex around the claim.** Rejected as unnecessary and as a larger failure
   surface: a per-claimer destination name gives exclusion with no lock to leak, no stale-lock
   recovery path, and no lock lifetime to get wrong. The measurement shows the shared-destination
   move is the thing that does not work; a unique destination is what does.

7. **Hash worktree paths and branch names in the queue.** Rejected: location already settles the
   leak question (D3), and hashing destroys the ability to read the queue with `ls` when it
   misbehaves — which is precisely when a queue needs to be readable.

8. **Wire it now and fix the findings after.** Rejected: findings 1, 2 and 4 are each sufficient on
   their own to make delivery unsound, and wiring places the drain on `SessionStart` and `Stop` in
   every session in the repo at once.

## Consequences

**Positive** — Two peer classes become reachable that previously were not reachable at all, without
a broker, a daemon or a network listener. The transport is inspectable with `ls` and `cat` when it
misbehaves, which is when transports most need to be inspectable. Delivery is recorded by the process
that actually emitted the text, at the moment it emitted it, rather than asserted afterwards by the
model — the existing announce receipts are hand-written and can claim a delivery that never happened.
The queue cannot enter a commit or a `push --mirror` by construction rather than by discipline.

**Negative / risks** — Three of these are real and are not closed by this ADR:

- **The write-side trust boundary cannot be enforced by this design.** Any process running as the
  user can write into any inbox, so every provenance field is a self-assertion. D8 makes that visible
  to the reader; it does not make it false. Anything that would require an authenticated sender must
  not be carried here.
- **Delivery duplicates the body into a transcript no prune reaches.** Deleting a message from the
  queue does not unsay it. That is the whole reason for D10's content rule, and it is a permanent
  property of injecting into a conversation rather than a defect to be fixed later.
- **The urgent tier is one-shot.** After a single mid-turn delivery the watcher is finished, and the
  session falls back to the turn-boundary drain until the next arming event. Re-arming has to come
  from a hook.
- Two more, smaller: mail is delivered at `SessionStart` and `Stop`, so the default tier's latency is
  a turn boundary, not an instant; and a per-turn hook costs one process spawn per turn, which is why
  the drain is deliberately not on `PreToolUse` (measured on this repo's recent transcripts at 19.0
  tool calls per turn at the mean, a `PreToolUse` matcher would pay that spawn about 19 times per
  turn for the same practical latency).

**Out of scope** — Any use as a PHI or secrets carrier (D10 forbids it). Cross-machine mail: the
queue is one repo's `.git` directory on one filesystem. Authenticated senders. Ordering guarantees
beyond the arrival-order readability of a time-prefixed filename. Solving D11's re-arming. Replacing
the realtime channel (D2).

## Status and what gates wiring

This ADR is `Proposed`, and the code it describes is a **prototype that is deliberately not wired**.
The rows for the drain hook exist in `scripts/coord/install-coordination.ps1` and stay exactly as
they are; no config root has been installed from them, so nothing is live in any session. Wiring is a
separate, owner-approved step, and it is gated on the work tracked as
[BACKLOG #1028](../BACKLOG.md).

**Measured against the target surface, 2026-08-05.** The channel was tested from a real VS Code
extension session, against a throwaway repo carrying only project-level `.claude/settings.json` hooks.
Two results, and the second is the one that matters:

- **`Stop` fires in the extension.** A message queued *during* a turn was delivered *at the turn
  boundary*, with the drain writing a receipt carrying `byHookEvent: Stop`; `Stop` fired on two
  consecutive turns, and `SessionStart` and `UserPromptSubmit` fire too. So the pull path works on the
  surface this channel exists for. `claude-code#59718` is right and `#40029`, closed as not planned, is
  wrong or stale.
- **The extension fires `SessionStart` for sessions it then discards, and that broke the delivery
  model.** Two events 43 seconds apart under different ids; the queued message was consumed by the
  first, which the operator never interacted with, while the prompt came from the second. Delivered,
  receipted, moved to `seen/` -- and invisible to the human. Every instrument reported success, which is
  precisely why it was dangerous: the receipt is honest about what was emitted and says nothing about
  who read it.

  **Re-measured 2026-08-06: six `SessionStart` events under six ids in one launch, only one of which
  ever submitted a prompt**, two of them firing mid-session. Also from that run, and both material to
  any future design: **session ids are reused across launches**, and **`Stop` fires more than once per
  session**.

  **SOLVED by the show/consume split (D12) and verified end to end on the real surface.** Under those
  six events the message was displayed, held, not re-displayed to the session that had already seen it,
  and consumed exactly once at the surviving session's `Stop`. The residual risk is stated in
  [SESSION-MAIL.md](../SESSION-MAIL.md): because ids are reused, a phantom carrying the *surviving*
  session's id would be indistinguishable by construction. **That collision has now been REPRODUCED**
  (2026-08-06): a phantom displays and marks a message, a later session reusing that id has the
  display suppressed, and its `Stop` consumes a message it never saw. Strictly narrower than the
  defect the split closed -- which lost mail unconditionally, to the first of six phantoms, every
  launch -- but the same kind of failure: silent, receipt-clean, undetectable by any artefact here,
  since all of them are keyed by the session id the two sessions share. The principled fix is to
  consume only what the SAME drain invocation rendered, trading a guaranteed duplicate display for
  the removal of cross-invocation trust. Recorded, not made.

## To resolve on acceptance

- [x] The eight findings are closed in the scripts, with the tests the Acceptance Criteria name.
      `tests/test_session_mail.py` exists and every `→` link above resolves to a function in it.
- [x] AC-5's test carries a negative control that demonstrably goes red — a concurrency assertion
      with no proof it can fail is the ADR 0158 defect, and this one in particular has a plausible
      wrong version that passes.
      **Two controls, both in `tests/test_session_mail.py`:**
      `test_the_naive_shared_destination_pattern_does_not_exclude` runs the WRONG pattern inline and
      requires it to fail to exclude — so a green exclusion result is only evidence because the same
      harness is shown to detect the defect; and
      `test_the_claim_primitive_reports_a_failure_it_cannot_have_won` re-runs the measurement's own
      controls, so a `Move-Claimed` that returned `Won` unconditionally is caught rather than read as
      a subtle bug.
- [x] The per-injection caps in D9 get concrete numbers, chosen against a measurement rather than
      asserted. Numbers in `mail-drain.ps1`; anchors in [SESSION-MAIL.md](../SESSION-MAIL.md)
      (`CLAUDE.md` at 40,102 bytes as the deliberate per-session cost, `docs/STEERING.md` at 3,504
      bytes as a whole document, and announce's existing peer-field caps). `FRAME_OVERHEAD_BYTES`
      exists **because** of a measurement: charging the raw body while the renderer added six bytes a
      line let a 34,539-byte injection pass an 8,000-byte cap reporting `0 truncated`.
- [x] The content rule (D10) is stated in [SESSION-MAIL.md](../SESSION-MAIL.md) and referenced from
      [PHI.md](../PHI.md), in one place each. Stated once as a section heading; PHI.md carries one
      row pointing at it. The only other occurrence in SESSION-MAIL.md is an internal link back to
      that section, which is the shape this box asks for rather than a second statement.
- [x] Owner decision on whether the urgent `asyncRewake` tier is wired at all, given D11.
      **DECIDED 2026-08-06: NOT WIRED, and not rebuilt yet.** The default tier has never delivered
      mail in real use -- everything to date is rig-verified and the code is unmerged -- so building a
      second tier to cut a latency nobody has measured is a demand-gate item, not a gap. The rebuild
      path is recorded in [SESSION-MAIL.md](../SESSION-MAIL.md) so it is not rediscovered: arm on
      `UserPromptSubmit` rather than `SessionStart`. Revisit only if someone hits the latency in
      practice.
- [x] Owner approval to wire the drain rows, which places a hook on `SessionStart` and `Stop` for
      every session in this repo. **Given 2026-08-05/06, in two steps:** `Stop` first, then
      `SessionStart` once the show/consume split made a discarded session unable to consume what it
      displayed. Default config root only. ⚠️ The rows are live and the hook still resolves nothing
      outside a worktree holding this branch — see §"Status and what gates wiring".
