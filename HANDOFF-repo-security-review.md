# Handoff — repo security review / #323 SMTP TLS

**Branch/worktree:** the repo-security-review pair (slug omitted — the leak gate's worktree-slug
detector blocks it, correctly; find it with `git branch --list '*repo-security-review*'`).
**2026-08-01 → 02** · all work **merged and pushed**; no claim held; nothing in flight.

---

## STATE

| PR | Status | SHA |
|---|---|---|
| **#126** | **MERGED** | `b4665b10` — disclosure audit: 5 removals + BACKLOG #321–#338 |
| **#132** | **MERGED** | `093db339` — #323 layers 1–2, SMTP hops now verify certificates |

Working tree clean. Branch merged (squash) — **prunable**. This handoff commit is the only thing on it
past `093db339`.

## DONE

**#126** — audited the tracked tree against `docs/SECURITY-DOCS-POLICY.md`. Almost nothing qualified:
most candidates are honest prose already stated in shipped docstrings. Removed: an estate site code +
partner product name, a de-identified HL7 corpus, an operator hostname, an operator account name, a
private-ledger token census. Filed 18 items for what removal cannot fix.

**#132** — `smtplib` takes no context and falls back to `ssl._create_stdlib_context`, which **is**
`ssl._create_unverified_context` (`CERT_NONE`, `check_hostname=False`; confirmed on CPython 3.14.6).
`use_tls=true` bought encryption without authentication. Worse: `RevocationHopGuard` was registered on
that hop while its own definition requires *"the caller has already built a verifying context"* — so an
enforcing PHI instance refused to start over a possibly-**revoked** cert on a hop that never validated
one. Added `build_smtp_tls_context()` (`config/tls_policy.py`), a three-arm branch in
`transports/{email,direct}.py`, and `tls_verify`/`tls_ca_file`/`tls_check_hostname` on `Email()`/`Direct()`.

## IN FLIGHT

Nothing. The seam for the next task is below.

## BLOCKED ON / NEXT

1. **#323 alerts cell** — `pipeline/alert_sinks.py:384` still calls `starttls()` bare. Deferred for a
   reason: it needs a `[security].allow_unverified_alert_smtp_tls` **acknowledgment switch**, not the
   clamp the connectors use, because the contextvar hop posture is never stamped for that cell. Full
   design in workflow run `wf_719c5d96-04b` (layers 3–5). ⚠️ **BACKLOG #139's premise stays FALSE
   until this lands**; #139 carries a correction block saying so.
2. **`enforce_admins` is `false`** on `main` — owner clears.
   `gh api -X PATCH repos/MEFORORG/MessageFoundry/branches/main/protection/enforce_admins`
   Memory had it recorded as fixed; corrected this session.
3. **#329** — reframed (credit: ASVS-sweep session) from "five leaks" into one repo-wide invariant.
   Census at `main` by **`ast.Call`**: six real sites outside `settings.py` — `auth/ldap.py`,
   `pipeline/alert_sinks.py`, `transports/{ai_broker,database,direct,remotefile}.py`. `database.py` is
   the documented unstamped fallback; `mllp.py` is a **docstring, not a call**.

## RETRACTIONS (corrected forms)

1. **"Squash merges leave a merged branch blocking files forever."** FALSE, withdrawn in the commit
   that used it. Measured: three-dot 7 files, two-dot 9, **intersection 0**; `overlap.ps1` intersects
   both forms and `collision_gate.ps1` delegates to it. Later confirmed by observation — a holder row
   self-cleared the moment its PR merged.
2. **Call-site census wrong twice.** Reported `direct.py 0` (measured my own unlanded branch as repo
   state) and `mllp.py 1` (regex excluded `#` comments but **not docstrings**). Corrected form in
   §NEXT-3. I amended the commit after re-measuring rather than trusting either of two peers.
3. **"Not one of ~20 defects was found by its own author."** A completeness claim where the evidence
   supported **"at least eleven"** — written while narrating that very defect class, having cited
   `CLAUDE.md` §11 against completeness claims earlier the same evening. Corrected form: *of roughly
   twenty, **two** were author-found — one before shipping, one immediately after reading a peer's
   finding — neither by native self-audit.* Recorded against myself: knowing a rule does not make it
   bind.
4. **"BACKLOG.md is DENY."** Wrong. #133 changed `collision_gate` from a deny **decision** to an
   advisory **context**; my check tested *"is there output?"* as a proxy for *"was it denied?"* and was
   written against the old contract. It had been allowing me for minutes.

## TRAPS — each a fact plus its measurement

1. **The instrument is a premise.** "Compare the files" / "count the call sites" / "hash the corpus" /
   "was it denied?" are meaningless until the operation is named. Measured: `Get-FileHash`-over-redirect
   vs `git hash-object` → *opposite* answers; regex-over-lines vs `ast.Call` → disagreed on a
   **docstring**; output-presence vs the decision field → opposite. Third+ instance the same night.
2. **A green earned against a different base is not evidence about this one.** Re-run gates after every
   rebase. Measured: #132 rebased 4× and was re-verified each time.
3. **A correction sent as a message cannot catch a claim published as ambient state.** Measured: PR #132's
   body described **2 commits when there were 4** — found by deliberately looking for my own instance
   immediately after reading a peer's finding. Suspicion transferred through a *message*, applied within
   minutes to a different system and artifact class.
4. **Holding requires a mechanism, not an intention.** An armed auto-merge does not know you decided to
   wait. Measured: #132 was armed when a peer asked me to hold; I disarmed and *verified* the disarm.
   #119 had been killed 3× by merges nobody intended as interference.
5. **Prove timing-dependence before calling it a flake — and write the prediction first.** Measured:
   `sql server 2022` attempt 1 FAIL (`HYT00`, 20-way concurrent `MERGE cipher_meta`), attempt 2 PASS,
   `2025` green both times, same commit. Falsified the stated prediction, which is only a result because
   the alternative was written down in advance.
6. **A strict-up-to-date policy with no merge queue converts N ready PRs into N sequential cycles.**
   Measured: #132 took **four full CI cycles**, none from failures, all from `BEHIND` — ~80 min of scarce
   runner time for a change correct on the first pass. At merge time #137/#136/#134 were simultaneously
   `BEHIND` with auto-merge armed, i.e. none could fire. Evidence for BACKLOG #340.

## ENVIRONMENT

- **`.venv` was created in this worktree** (`python -m venv .venv`; `pip install -e ".[dev]"`). It did
  not exist before and dies with the worktree.
- **Commit gotcha:** pre-commit uses `language: system`, so `ruff` must be on PATH —
  `export PATH="$(pwd)/.venv/Scripts:$PATH"`. Otherwise every hook fails "Executable `ruff` not found".
  Never `--no-verify`.
- `collision_gate` fix (#133) takes effect only once the **primary checkout** advances past it:
  `grep -c MatchedDirty <primary>/scripts/hooks/collision_gate.ps1`.

## MEMORY

Written this session: `mf-public-mirror.md` (`enforce_admins` corrected to `false`);
`mf-leak-gate-blindness.md` (mode **G** — fully loaded, every floor passed, class never enumerated;
plus the recursive placeholder trap). **Not yet written:** the six traps above. Memory is shared —
confirm ownership before writing.
