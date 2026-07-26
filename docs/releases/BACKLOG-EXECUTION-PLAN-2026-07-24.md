# Backlog execution plan — the non-deferred, non-ASVS items (2026-07-24)

> **Scope.** The 19 open backlog items that are **not** in the ASVS drive-to-green cluster and **not**
> in the `## Deferred` section. Explicitly **out of scope**: the ASVS cluster (#185, #277, #280–#307 — owned by
> parallel sessions; do not touch), and the 38 deferred items.
>
> **Baseline.** Every status below was reconciled against `origin/main` @ `8b89bb4b` by a 12-agent pass in which
> each "already built" claim faced an independent adversarial verifier. **0 of 12 status claims were refuted.**
> Banners were *not* trusted — each item was resolved by grepping its distinctive **code** symbol on `main` and
> scanning ~684 refs for unmerged work.

## The headline: a third of the list is not work

| Bucket | Count | Items |
|---|---|---|
| **Already done on `main`** (banner lags — bookkeeping only) | 5 | #102, #223, #237, #270, #273 |
| **Built on a dormant branch** (reconcile, don't rebuild) | 2 | #97, #117 |
| **Partial** (real, specific remainder) | 6 | #98, #99, #105, #157, #214, #274 |
| **Genuinely open** | 6 | #87, #119, #122, #275, #278, #306 |

Two structural findings drive the whole sequence:

1. **Four items are one lab window, not four tasks.** #275 → #98, #99(e), #274 all require the *same* throwaway
   AD forest, and `docs/security/AD-FEDERATION-LAB-RUNBOOK.md` says to plan them **"as one window, or not at
   all."** #275 is a **hard blocker** for #98 and #99(e). Scheduling these separately is pure waste.
2. **Most of the remaining "build" work is gated on a decision, not on engineering.** #278 is literally verdict
   *decide*; #122 needs sign-off on an architecture reversal; #306 needs an option picked before DDL lands;
   #214's remainder is an owner-deferred rewrite. Unblocking these costs minutes of your time, not days of mine.

---

## Wave 0 — Banner truth (no code, do first)

Five items are **already shipped on `main`** and are only mis-labelled. This is the same stale-signal hazard that
cost this project real rework (52 "open" items already closed; the 39 stale on-trigger lines). It is one PR.

| # | Title | Evidence it is done | Action |
|---|---|---|---|
| **#102** | Server-DB DR seed verification has no teeth | `has_prior_backup_history` on **all 3 backends** + `_verify_live_server_seed` fail-closed gate + 3 backend test modules; PR #890 | 🚧 → ✅ (residual is #223) |
| **#223** | DR restore vintage/completeness attestation | **ADR 0102** *is* the decision record (chose (c) + opt-in (b)); option (a) explicitly **declined** 2026-07-20 | 🚧 → ✅ (declined-scope noted) |
| **#237** | Worktree gate rule-3 substring-prefix false positive | Fix on `main` | 🚧 → ✅ |
| **#270** | Secure-by-default `[security]` schema (ADR 0118) | ADR 0118 Accepted, since amended by **0143** + **0148** | 🚧 → ✅ |
| **#273** | MFA TOTP step-boundary flake | Landed `691ae1c4` / PR #1187 | 🔢 → ✅ |

**Gate:** one banner per item, CLOSED glyph must not coexist with OPEN; re-run
`scripts/docs/backlog_status_check.py` after the edit. **Size S · no ADR · no dependencies.**

---

## Wave 1 — dg-s5 reconcile: #97 + #117 (ready now)

Fully authored on the dormant `dg-s5` branch (4 commits, 198 behind `main`) — **code, tests, docs and the
ADR 0067 §9 amendment are all written.** This is a *reconcile*, not a build, and it is the same playbook that
landed dg-s4 (#160/#172) this session.

- **#97** persistent `Tcp()`/`X12()` outbound — resolves ADR 0067 §8's own "Tcp/X12 parity" open item.
- **#117** MLLP no-wait-for-ACK (fire-and-forward) — **ADR 0124 already allocated. Do NOT mint a new number.**
- **Inseparable:** same branch, both touch `config/wiring.py`. Reconcile as **one unit**, in commit order
  (`60faddf3` docs → `0a922617` #117 → `e471fbd4` #97).

**Conflict surface (verified):** exactly 4 files — `transports/mllp.py` (2 hunks), `config/wiring.py` (1),
`docs/adr/README.md` (1 index row), `docs/BACKLOG.md` (discard the dg-s5 side; `main` rewrote it). Notably
`tcp.py` and `x12.py` do **not** conflict.

**Two known hazards:**
- **ADR 0124 claim transfer** — the claim names the dormant `MessageFoundry-dg-s5` worktree, so the pre-commit
  ledger gate will block. Transferring the claim is **classifier-gated ⇒ needs owner approval** (same as ADR 0123
  on dg-s4).
- **Long-path venv failure** — `new.ps1` bootstrap dies on Windows `MAX_PATH` under a long worktree path. Use a
  **short path**: `git worktree add C:/mfdg5 -b dg-s5-reconcile origin/main`, or install without the
  `harness`/PySide6 extra (these tests are transport-only).

**Semantic check to verify during the merge:** `no_ack` (reads no ACK) is mutually exclusive with the recently
landed `verify_ack_control_id` — confirm wiring rejects/no-ops that combo. The new #82 send-pacing is upstream in
`wiring_runner`, orthogonal to the `mllp.py` no-ack path. **Size S+M · no new ADR · owner approval for the claim.**

---

## Wave 2 — Buildable now, no owner gate

| # | Item | Why it's ready | Shape | Size |
|---|---|---|---|---|
| **#119** | Nightly application-log compression | **No hard blocker** — the host seam is already on `main`: #120's `_sweep_app_logs` + `[logging].log_dir` threaded `Engine`→`RetentionRunner`, and #121's `max_pass_seconds` between-phase deadline | An `app_log_compress_days` knob + a `_compress_app_logs` phase in `RetentionRunner.run_once`, beside `_sweep_app_logs`. Needs: configurable window, **free-space precheck**, and **integrity validation of the archive before deleting the original** | M |

**No new ADR** — clear precedent: #120 shipped the same shape as an ordinary addition without its own ADR;
ADR 0137 already governs the RetentionRunner phase structure.

---

## Wave 3 — The AD lab window (book once, run four items)

**This is the single biggest scheduling decision on the list.** Four items share one throwaway `mefor.lab` AD DS
forest (DC on a **VM, never a container**, + AD CS + a gMSA + a domain-joined client + optionally AD FS).

**Run order is dictated by the blocker chain:**

```
#275 (cell L1 — SPN defect)  ──blocks──▶  #98 (cell L6 — EPA spike)
                             ──blocks──▶  #99(e) (cells L2/L3/L5 — gMSA/SQL/SSO smoke)
#274 (cells L6a → L9 → L18 — OIDC lab validation; L6a gates the rest)
```

| # | What actually remains | Size | ADR |
|---|---|---|---|
| **#275** | **Step 1 = run cell L1** (no code) to confirm the defect. Step 2 (if confirmed, small): split `kerberos_spn` at the first `/` into `service=`/`hostname=` at **both** call sites | S | No — ADR 0068 §9 amendment at most |
| **#98** | (a) run the EPA spike; **(b) is conditional** on its answer — build the opt-in `tls-server-end-point` binding **only if** the acceptor enforces a client CBT | L | **Conditional** — see register |
| **#99(e)** | **Only sub-item (e)** — the real lab smoke (L2 gMSA logon, L3 integrated SQL auth, L5 Kerberos SSO; L7/L13 if the IIS+ARR posture is exercised). (a)(b)(d)(f) are on `main`; (c) is a documented stdlib scope-out; (g) shipped inside #274 | L | No |
| **#274** | **No code left.** The rig + cells L6a/L9/L18, then flip ADR 0142 Proposed → Accepted | L | No (0142 exists) |

**Why this matters beyond the items:** every serve-path TLS/proxy assertion today monkeypatches `uvicorn.run`
and checks kwargs, and `kerberos_principal` is `# pragma: no cover`. **The entire AD acceptor path is mock-seam
only** — this window is its first real validation, and #275 is already a suspected defect it will surface.

**Safety invariants (from the runbook, non-negotiable):** disposable LAB domain only, never production AD; DC on
a VM; **RFC 2606/5737 placeholders only** in anything committed — `forbidden-content` is a blocking CI context and
the L17 run record must be scrubbed before it is committed.

---

## Wave 4 — Decision-gated (cheap for you to unblock)

Each is blocked on **your** call, not on engineering. Listed cheapest-decision-first.

| # | The decision you make | Then the build | Size | ADR |
|---|---|---|---|---|
| **#306** | Confirm **option (a)** (add `last_used_at`) over (b) — it moves `_schema_hash` on both server backends, so it must be decided *before* DDL lands | `last_used_at` column on all 3 backends, refreshed from `get_search_preset`, re-key `purge_search_presets` on `MAX(updated_at, last_used_at)`; update the `tests/test_retention.py` pin | M | No — amend ADR 0136/0027 |
| **#278** | **Pick the replacement term or decline** (declining is explicitly allowed — "dead-letter queue/DLQ" *is* the industry term), and fix the rename **boundary** | Rename across the chosen boundary (operator-facing UI/docs vs API/store identifiers) | L | **YES — new** |
| **#122** | Sign off on an **architecture reversal**: introducing a Python-side file handler, reversing the deliberate stdout-only + NSSM-rotation posture. Also decide whether an unwritable log may **stop a connection** (a data-plane consequence) | (0) file handler → (a) rename, (b) roll, (c) record event, (d) stop connection if the new file is also unwritable | M | **YES — new** |
| **#214** | Go/no-go on **commit-collapse** (the ~40× headline). You deferred this in favour of the state-snapshot, which shipped (PR #1209). **#209 has since landed, so it is no longer blocked** | One batched multi-row `transform_handoff` per message: extend the `Store` protocol + **all 3 backends**, preserving claim→produce→complete atomicity, FIFO `seq` order and at-least-once | XL | **YES — new** |

---

## Wave 5 — Externally blocked (park; do not schedule)

| # | Item | The blocker | Note |
|---|---|---|---|
| **#105** | Deterministic Corepoint-import tooling | **A real Corepoint action-list export.** The parsed schema is *synthetic-until-validated* (ADR 0086 §2) — schema reconciliation is the entire remaining correctness question and is unbuildable without a real artifact | ADR 0086 already pre-authorizes the remainder; no new ADR |
| **#157** | Direct Project / HIE connector | **#23's IMAP/POP read half** (the SMTP send half shipped, ADR 0029). Remaining phases = inbound Direct, MDN receipts, DNS-CERT discovery — all named-but-*not-decided* in ADR 0085 | **YES — new/amendment.** ADR 0085 scoped itself to "PR1 outbound-only" and lists these under *Out of scope*, so nothing on `main` authorizes the build | 
| **#87** | Competitive-intelligence study | Owner-executed, non-code | ⚠️ The subject's identity must stay **out of every in-repo/published/mirrored doc** — private strategy notes only |

---

## ADR register — allocate at build time, never up front

Per the standing decision: the plan **names** each ADR and the decision it must make; the ADR is
allocated and written **when that item is actually built**, with the real design.

> **Allocate atomically — never grep for the next free number:**
> `pwsh -NoProfile -File scripts\coord\alloc.ps1 -Kind adr -Title "<title>"`, and add the `docs/adr/README.md`
> index row **in the same commit**. A pre-commit hook rejects a number you did not allocate. Two sessions that
> both grep pick the *same* number, create differently-named files, and **merge clean** — this has fired three
> times (see `docs/LEDGER-GATE.md`).

| Item | New ADR? | The decision the ADR must record |
|---|---|---|
| **#214** | **Yes** | May the routed→outbound handoff become a **multi-row transaction** (N sibling routed rows consumed + their outbound rows produced + state/meta ops applied in **one** commit)? What that does to ADR 0001's at-least-once guarantee, crash-recovery granularity, and per-destination FIFO `seq` ordering |
| **#122** | **Yes** | Whether the engine owns an application-log **file handler** at all (reversing stdout-only + NSSM rotation), and whether an unwritable log may **stop a connection** — a data-plane consequence of a logging fault |
| **#278** | **Yes** | The replacement term (or the decision to decline) **and the rename boundary** — operator-facing surfaces only, vs API/store identifiers — plus the answer to "DLQ is the industry term" |
| **#157** | **Yes** (or a substantive ADR 0085 amendment) | Inbound Direct (IMAP/POP + S/MIME decrypt/verify), MDN receipts, and DNS-CERT discovery — named but never decided in ADR 0085 |
| **#98** | **Conditional** | Only if the spike shows the acceptor **enforces** a client CBT. Otherwise the outcome is recorded as an **ADR 0068 §9 amendment**, whose open-items list already poses exactly this question |
| #97 / #117 | No | **ADR 0124 + ADR 0067 §9 already written and allocated** — do not re-mint |
| #274 | No | ADR 0142 exists; held at *Proposed — code complete, awaiting lab validation* → flips to Accepted on L6a + L9 + L18 |
| #306 | No | Amend ADR 0136 / 0027; DDL mechanics governed by ADR 0064 |
| #102/#223/#237/#270/#273/#99/#105/#119/#87 | No | Covered by existing ADRs (0048/0049/0102, 0118+0143+0148, 0068+0142, 0086, 0137) or need none |

---

## Execution protocol (applies to every wave)

1. **Claim before code.** Flip the item's banner `🔢 → 🚧` in its own commit *before* writing. No gate enforces
   this; it is the only control against a double-build across ~35 worktrees.
2. **Re-verify at pickup.** Banners rot in both directions. Grep the item's **code** symbol on `origin/main`, and
   scan branches — *not-on-main ≠ not-built* (that is exactly why #97/#117 and #160/#172 nearly got rebuilt).
3. **One worktree per lane, short path.** `scripts\worktree\new.ps1`; use a **short** path to dodge the
   `MAX_PATH` venv failure. Use that worktree's own `.venv`.
4. **CI-only gates that a green local quartet misses** — front-load these when the change fits:
   - **crypto-inventory** (any module importing `cryptography`/`ssl`/`hashlib`/`secrets`/`hmac`/`argon2`) →
     `scripts/security/crypto_inventory_check.py` **and** `ASVS-L2-PHASE0-CHANGES.md §4`. A DRY refactor that
     *removes* a module's crypto use must **remove** its stale entry too.
   - **secret-rotation inventory** (any new `MEFOR_*` name ending `_PASSWORD`/`_TOKEN`/`_SECRET`/`_KEY`) →
     `CRITICAL_SECRETS` **and** the rotation-schedule table.
   - **route doc-drift** (any new API route) → `docs/SECURITY.md` route map + the count constants.
   - **forbidden-content** — runs locally: `python scripts/publish/scan_forbidden.py --published`. ⚠️ It flags any
     dotted-decimal string as a routable IP, so a bare **X.509 OID literal** (e.g. the subjectAltName OID) trips
     it — use the symbolic constant (`x509.SubjectAlternativeName.oid`) instead. It also blocks the **customer
     name** anywhere outside the allowlisted `docs/security/*` — say "the ASVS drive-to-green cluster", never the
     customer's name. Both of these bit this very plan document on its first push.
   - **bandit** `B105` fires on env-var *name* constants.
5. **Store-touching change ⇒ 3 backends.** SQLite + Postgres + SQL Server, and the SS legs silently **skip**
   locally. A schema change moves `_schema_hash` (ADR 0064).
6. **Known flake:** SQL Server 2025 `HYT00` query-timeout is *not* covered by the native-crash retry wrapper
   (that only catches 139/134), so it needs a manual `gh run rerun --failed`. Triage: SS red **but SS-2022 and
   Postgres green on the same commit** + a store-free diff ⇒ the flake; confirm by grepping the job log for
   `HYT00` before re-running.
7. **Commits are Claude's judgment; push/PR/merge need owner approval.** Never `--no-verify`.
8. **Verify before declaring done.** `ruff check` + `ruff format --check`, `mypy` (strict), `pytest`. For
   invariant-touching work (FIFO/at-least-once/ACK), add an adversarial pass — and check the regression test can
   actually **fail**: #214's original guard passed even when the feature was reverted.

## Suggested order

**Wave 0** (banner truth, 1 PR) → **Wave 1** (dg-s5, needs your ADR-0124 claim approval) → **Wave 2** (#119) →
**Wave 4 decisions** (#306 and #278 are one-line answers; #122 and #214 are real architecture calls) →
**Wave 3** (book the AD lab window once, run #275 → #98/#99(e) + #274 together) → **Wave 5** stays parked.

Waves 0–2 need almost nothing from you. Wave 3 needs a lab. Wave 4 needs four decisions.
