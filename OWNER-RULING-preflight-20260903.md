# OWNER RULING -- the store-privilege startup preflight. 2026-09-03.

Anchored 2026-09-07 by the Lander seat, because until now this ruling's only proof lived in a
session-log file on one machine, outside git. If that file rotates, the ruling loses its evidence.

## THE RULING

KEEP THE STORE-PRIVILEGE STARTUP PREFLIGHT DEFERRED. The demand gate on BACKLOG #1008 STANDS and
its banner does not flip.

## WHERE IT LIVES ON MAIN

`docs/BACKLOG.md`, inside item **#1008. Startup preflight on the store principal's effective
privileges (ASVS 13.2.2)**. It reached main in **PR 785**, merge commit `20ee0fdc1`, merged
2026-09-04T19:00:17Z, **with zero reviews**.

## WHAT WAS ACTUALLY MEASURED, AND WHAT WAS NOT

**No file in git can prove a person spoke.** Git records what a session wrote down. This anchor
does not change that and does not claim to. What it does is stop the surrounding evidence from
depending on one machine.

**The primary record is outside git.** It was read on 2026-09-07 during an adversarial review, in
the session transcript under the `.claude-account-5` projects directory, worktree
`contractor-533440`, file `d756228c-1884-4304-ae04-aa73a2d514d8.jsonl`.

At **2026-09-03T21:21:50.757Z** a question offered three options, labelled `"Keep it deferred
(Recommended)"`, `"Lift the gate and build it"` and `"Fix only the ungated probe defect"`. At
**21:40:57.557Z** the recorded answer reads, verbatim:

    "What is your ruling?" = "Keep it deferred (Recommended)"

The ruling commit followed at 21:42:54Z. The same submission carried a second question where the
owner typed free text rather than selecting a label: `"hand this issue to the lander"`. One typed
answer beside one selected label is a person answering, not a template.

**PROVENANCE OF THAT READING, stated because it matters.** The Lander seat did not read that file
itself. It was read and quoted by a subagent during the review; the Lander verified everything else
in this document directly. Treat the session-log quotation as one instrument's reading, corroborated
by the checkable claims below rather than by a second reading of the same file.

## THE BLOCK'S CHECKABLE CLAIMS, VERIFIED

| Claim in the block | Verified |
|---|---|
| Three prior passes asked for a ruling | Yes. Entries dated 2026-08-11, 2026-08-12, 2026-08-12 |
| The 2026-08-12 entry records a DELEGATION, not a ruling | Yes, quoted accurately in the block |
| The runbook fix removed the cause and has landed | Yes. Engine `1e9cc4c1`, PR 173, 2026-08-04, on main |
| The gate stands and the banner does not flip | Yes. #1008 still reads DEMAND-GATE |
| Three live options were stated to the owner | Yes, verbatim in the session log |
| #1234's defect lives only on one branch | **NO. FALSE. See below** |

Five of six hold. The one that fails is a side effect, not the ruling.

## THE FALSE SIDE EFFECT, RECORDED SO IT IS NOT INHERITED

The block states that BACKLOG #1234's defect *"lives only on `w3-store-privilege-preflight`"*, and
concludes the defer therefore leaves that defect with nowhere to go. Measured 2026-09-07:

    w3-store-privilege-preflight          store/privilege.py   present, 412 lines
    feat/store-privilege-preflight-carry  store/privilege.py   present, 412 lines
    origin/main                           store/privilege.py   ABSENT

There are two paths, not one. The second is **PR 764**, opened 2026-09-03T20:28:24Z -- **74 minutes
BEFORE** the ruling commit. So the "nowhere to go" premise was already stale when written.

## AN OPEN QUESTION THIS RULING RAISES FOR PR 764

PR 764 carries that preflight onto main and wires it in: callers in `api/app.py`, `store/store.py`,
`store/sqlserver.py`, `store/postgres.py`. It is gated by `[store].require_least_privilege`, which
defaults to `False` at `config/settings.py:569`, so nothing runs unless an operator opts in. PR 764
cites BACKLOG #1234 seven times and **#1008 zero times**.

Whether shipping a default-off detector counts as building what this ruling defers is a judgement,
not a measurement. It is recorded here as an open question, NOT decided. The Lander placed a hold on
PR 764 pending that call.

## ONE MORE THING THE BLOCK DOES NOT DISCLOSE

The option the owner selected was labelled `"Keep it deferred (Recommended)"` -- it carried the
asking session's own recommendation, and the block's "grounds as put to the owner" are near-verbatim
that option's supporting text. That does not make the answer less real. It is disclosed because a
reader weighing how independent the ruling was cannot see it from the ledger.

## THE RULING TEXT, VERBATIM FROM MAIN

Captured from `origin/main:docs/BACKLOG.md` on 2026-09-07, unedited:

> **OWNER RULING 2026-09-03 -- KEEP THE PREFLIGHT DEFERRED. This is the ruling ON THE SUBSTANCE that
> this item has spent three passes asking for, and it is recorded here so a fourth does not re-derive
> it.** Put by the Contractor seat with the three live options stated -- keep it deferred, lift the gate
> and build the preflight, or fix only the ungated probe defect -- the owner chose **keep it deferred**.
> **This is a ruling and not a delegation**, which is the distinction the 2026-08-12 entry below draws:
> that entry records the owner answering *do what you judge best*, and the coordinator was right to
> refuse to read it as a decision. This one names an outcome. **THE GATE STANDS and the banner does not
> flip.** Grounds as put to the owner: the runbook fix removed the CAUSE and has landed, the preflight
> detects a SYMPTOM whose cause is gone, and at zero deployments demand for the detector is weak.
> **WHAT THIS RULING DOES NOT DECIDE.** The correctness defect on the held branch -- the SQL Server probe
> returning OBSERVED unconditionally while NULL role results fold to `False`, i.e. a clean bill of health
> from a probe that read nothing -- is untouched by this. It is filed as **#1234**, it is not gated by
> this item, and it stays worth fixing whichever way the gate ever goes. Nor does this rule on Blocker B,
> the delivered refusal being narrower than this item's stated Scope; that question is moot while the
> gate stands and returns if it is ever lifted.
> **ONE SIDE EFFECT OF THIS RULING, recorded because neither item says it.** The defer keeps **#1234**
> unstartable. That item's defect lives only on `w3-store-privilege-preflight`, which lands only if the
> preflight lands, so deferring the preflight leaves the defect with nowhere to go. #1234 is correct that
> it is not hostage to this POLICY question; it is nonetheless blocked by the same branch. Measured
> 2026-09-03 and recorded there.
>
> **Filed 2026-08-04 — not started. Scored 2026-08-04 → DEMAND-GATE.** The engine documents a least-privilege store grant it can
> **never observe**: there is no fixed-server-role probe and no database-role-membership probe in
> any of the four packages the scorecard scans, and `[store].require_managed_identity` constrains
> credential *kind*, not privilege — a `sysadmin` gMSA satisfies it — so an over-granted principal
> would go unobserved on first deployment. This item is the probe that closes that. Its **named
> prerequisite has fired** (engine `1e9cc4c1`, 2026-08-04, PR #173 removed the `db_owner`
> instruction), but the **owner's ruling of record is still *defer the startup preflight***, so
> the tier override applies and this stays DEMAND-GATE at any score.
> ⚠️ **PUT TO THE OWNER 2026-08-12; HE DELEGATED THE CALL AND THE GATE STANDS. Recorded precisely, because this item is the repo's own example of over-reading an authorization.** The owner did **not** rule on the substance -- asked to choose, he answered *do what you judge best*. **That is a delegation, not a ruling**, and it must not later be cited as *"the owner decided the gate stands"*. The coordinator kept the gate on these grounds: the item's own Verdict is *build the runbook fix only; defer the startup preflight*, and **that runbook fix has LANDED**, so the item's stated scope is complete; the fix addressed the **cause** (a runbook instructing `db_owner`) while the preflight detects the **symptom**; and with the cause removed and zero deployments, demand for the detector is weak. **Two lanes arguing from a sequencing technicality is not demand.** The substantive question -- should the engine observe the store principal's privileges at startup at all -- remains **open and unanswered**, and an owner ruling on it is still what lifts this gate.
> **The probe defect below is now BACKLOG #1234 and is NOT gated by this item.**
> ⚠️ **RE-RAISED AND RE-REJECTED 2026-08-12, ON THE SAME ARGUMENT. Recorded so a fourth pass does not re-derive it.** A lane relayed that the owner had lifted the gate, reasoning that the 2026-08-03 defer was **sequencing** rather than siting -- it waited on the runbook fix, which landed `1e9cc4c1` on 2026-08-04. The coordinator **verified that commit against the repo** (it exists, it is on `main`, it is the AOAG `db_owner` removal) and initially recommended lifting on that basis.
> **That recommendation was WRONG, and the item itself is why.** The paragraph above ALREADY records the prerequisite as fired, and already states that the ruling of record is separately still *defer*. **The sequencing argument is not new evidence; it is the inference this item pre-rejects.** Verifying the commit measured a premise the item never disputed, and produced confidence about a conclusion it had already ruled on -- a correct measurement aimed one question to the left. **The prerequisite firing has now been offered as grounds for the lift twice, by different lanes, and rejected twice.**
> **WHAT WOULD ACTUALLY LIFT IT:** an owner ruling on the SUBSTANCE -- build the startup preflight, or not -- recorded here. Not a prerequisite, not a relay, not a coordinator's judgement. **Nothing short of that should flip this banner**, and a session that finds itself reasoning from `1e9cc4c1` to a lift has re-derived a rejected argument.
> **SEPARATE FROM THE GATE, and true whichever way it goes:** the held branch carries a correctness defect reported by its reviewing lane -- the SQL Server probe returns `OBSERVED` unconditionally while NULL role results fold to `False`, i.e. a clean bill of health from a probe that read nothing. With refusal gated off by default, WARN is the only arm most installs would ever see, so that false-clean is the whole control silently doing nothing. **That needs fixing regardless of the demand gate, and does not need it lifted to be worth fixing.**
> ⚠️ **AMENDED 2026-08-11 — A BUILT, VERIFIED BRANCH EXISTS, AND ITS AUTHORIZATION IS UNVERIFIED. The item STAYS OPEN and the DEMAND-GATE STANDS.** `w3-store-privilege-preflight` (`94cb72e6`, pushed, **deliberately unlanded**) ships the startup preflight: `messagefoundry/store/privilege.py` reads the store principal's effective privileges after the store opens and before any listener binds. Full quartet green — `ruff format` 1086 files, `ruff check` clean, **mypy strict clean on 266 files**, `pytest` **11,676 passed / 834 skipped / 0 failed** across both testpaths with the web-console package confirmed collected at 356. Baseline measured at the merge-base by the building lane, delta reconciling to exactly its own new file. Red-first evidence for every new check, each failure printing what it scanned.
> **THE PROBLEM IS NOT THE CODE.** One lane recorded that *"the owner lifted the defer"*; a second lane, verifying the same branch, refused to flip this banner because it had *"not seen"* such a decision. **The second lane was right, and the disagreement is resolved against the first: no record reachable from this repo supports the lift.** This item's own **Verdict** line still reads *"build the runbook fix only; defer the startup preflight"*, the banner above still says the owner's ruling of record is **defer**, and the item states in terms that a prerequisite clearing is *"a fact about the world, not a decision by the owner"*. The demand-gate decision packet, the G26 sitting records and the pending-ledger-edit register were all searched: **none mentions #1008 at all.** So the branch was built against a gate that, on every checkable record, is still closed. **Do not read the existence of working code as authorization** — that inference is what this amendment exists to block.
> **BLOCKER A — the ASVS 13.2.2 absence claim FLIPS, and the paired edit is OUT OF THIS REPO.** Grepping `IS_SRVROLEMEMBER|IS_ROLEMEMBER|db_owner|sysadmin` over the four packages `scorecard.py::_python_sources` scans: **0 at `751ca08a`, 15 on the branch** -- **UNIT CORRECTED 2026-08-12: `_grep_count` returns `sum(1 for f in files if rx.search(...))`, so it counts FILES CONTAINING A MATCH, not matches**, and its caller assigns it to a variable named `hits` (`scorecard.py:1107`), which is how the misnomer reached this item. **The figure needs RE-DERIVING rather than relabelling:** 15 matching files cannot be reconciled with the three files named immediately after it, so either the parenthetical under-enumerates without saying so or the number is not what it appears. Re-measure and state the unit; do not patch a second number in on top of the first (`store/privilege.py`, `store/sqlserver.py`, `config/settings.py`). This item already requires the vault scorecard edit to land *in the same pass* or the daily drift cron reds on engine-without-vault — and that cron lives in the **vault's** `asvs-scorecard.yml`, not here. **So nothing in this repository will go red; the vault will**, silently, from the public side. Landing this branch without the vault edit breaks a gate no public CI leg can see.
> **BLOCKER B — the delivered refusal is WEAKER than this item's stated Scope, and that is an owner question in its own right.** Scope point 1 and the **What** paragraph both say *warn on defaults, and refuse when `enforcing` and the instance is production-PHI*. What is built refuses only under opt-in `[store].require_least_privilege` (default false). **So a production-PHI instance with a `sysadmin` login and shipped defaults WARNS AND STARTS** — precisely the posture the item was filed to refuse. Both patterns exist in the tree (`require_managed_identity` is enforcement-keyed; the keyless-PHI refusal is data-class-keyed), so precedent does not settle it. Note this is a *narrower* question than the gate above and is moot until the gate is ruled.
> **AND THE SQL SERVER PROBE HAS NEVER EXECUTED ANYWHERE.** Its T-SQL (`IS_SRVROLEMEMBER` / `IS_ROLEMEMBER` / `HAS_PERMS_BY_NAME`, 17 bound parameters) was never run: no reachable local instance, and the lane correctly declined to go looking for an `sa` password. PostgreSQL **was** exercised live both directions against a real 16.14, including a purpose-made least-privilege negative arm. CI is the SQL Server probe's only coverage. The first live run will settle whether `pyodbc` binds parameters into `IS_SRVROLEMEMBER(?)` in a `FROM`-less `SELECT` at all.
> **What the branch DID legitimately establish, separately from the gate question:** the original WIP was **INCOMPLETE, not merely unverified**. It broke `tests/test_webconsole_seam_snapshot.py` (measured RED), its four live DB legs were wired into no workflow step and so executed nowhere while reporting as skips — making the file's own docstring claim that CI was *"a standing positive control"* **false when written** — and `postgres_excess` read four of five role attributes off the principal's own row rather than across assumable roles, contradicting `DEPLOY-SERVER-DB.md` §1.3's shipped promise. Those are real findings and they survive whatever the owner rules.

## WHY THIS ANCHOR EXISTS AT ALL

CLAUDE.md section 5 cites `refs/liaison/owner-ruling-20260829-push` at commit `987705dfb` as the
model for anchoring an owner ruling. Measured 2026-09-07: that ref is **not on the remote**
(`git ls-remote origin 'refs/liaison/*'` returns 0, against a positive control of
`refs/heads/main` returning 1), and its commit is reachable from no remote branch. The anchor the
project points at as its example of a durable record exists in exactly one clone.

This anchor is pushed. That is the difference, and it is the entire point.
