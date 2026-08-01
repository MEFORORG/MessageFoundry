# ADR 0156 — ASVS scorecard as data: a derived count, verified evidence anchors, and a fail-closed drift gate

**Status:** **Accepted (2026-08-01)** — built and merged the same day; §7 amended at ratification, see below
**Date:** 2026-08-01
**Supersedes:** —
**Related:** ADR 0155 (DAST) · BACKLOG #205 (risk-acceptance register) · ASVS cell 15.1.3

---

## Context

The ASVS L3 score is maintained as **prose**. A dated assessment states a count; later dated documents
supersede it; a risk-acceptance register carries a row per residual; each asserts facts about the code
in sentences. Nothing checks any of it.

On **2026-08-01** a single re-anchoring session produced the following, all in one day:

| Observed | Count |
|---|---|
| Times the headline count was re-derived from scratch | 6 |
| Residuals of record that were **factually false** at `HEAD` | 12 |
| Of those, **absence claims** that had silently stopped being true | 5 |
| Cells missing from an enumeration described as *"arithmetic-checked and complete"* | 10 |
| Documents asserting a superseded count as current | 5 |
| Register-vs-scorecard contradictions | 4 |
| The same documentation defect fixed independently by two sessions | 1 |
| Subagent tokens spent on verification | **~23 million** |

Most of that spend was not discovery. It was **re-deriving facts already known but never durably
recorded**, then re-verifying them because the recorded version had gone quietly false.

Three failure modes account for all of it:

1. **Prose asserts facts about code, and the code moves.** A residual says *"no privilege probe of any
   kind exists"*; the code grows two; the sentence rots in place. The next session funds work that is
   already done, or trusts a control that is not there.
2. **A completeness claim cannot be checked by the thing that makes it.** The dropped-ten defect
   survived because the arithmetic closed to 345 and closure was read as proof. **Closure only proves
   the four buckets sum — not that every cell landed in one.** No self-consistent count can detect an
   absent cell.
3. **The guards that would catch this are blind.** Six `*_doc_drift` test modules exist, one with ~88
   assertions written specifically to stop this class. `git ls-files docs/security/` in the development
   repo returns **0** — the documents are vault-only, so every doc-anchored assertion has nothing to
   read in the tree where CI runs. **This is ASVS 15.1.3**, currently open, and it is why none of the
   above was caught by a machine.

The lineage convention — dated documents, superseded rather than edited — is **correct for audit** and
is not the problem. The problem is that it is also being used as the *source of truth* for facts that
change under it.

## Decision

**Make the scorecard data. Derive the count. Verify the evidence. Fail closed.**

### 1. One record per requirement, all 345

A single structured file — `docs/security/asvs-scorecard.toml`, TOML per the project's config
preference — holds one `[[cell]]` per ASVS 5.0.0 requirement:

```toml
[[cell]]
id            = "12.1.1"
level         = 1                     # from the held corpus, not typed
verdict       = "partial"             # pass | partial | fail | na | unverified
posture       = "single"
residual      = "The SQL Server ODBC PHI hop has no engine-side TLS version floor…"
last_verified = "2026-08-01"
verified_at   = "f8d11685"            # the commit the evidence was read on
  [[cell.evidence]]
  path   = "messagefoundry/__main__.py"
  line   = 1978
  expect = "probe_tls_floor"          # a token CI asserts is still there
```

### 2. The count is computed, never typed

`scripts/asvs/scorecard.py` sums the verdicts. **No document states a count; documents render it.**
Five documents can no longer assert three counts, because there is only one place a count exists.

### 3. Completeness is asserted, not claimed

A test asserts **every one of the 345 ids in the held corpus appears exactly once**, and that no id
outside it appears at all. This is the check whose absence cost ten cells: it would have failed the
moment the enumeration dropped one, rather than closing to 345 and looking correct.

### 4. Evidence anchors are machine-verified

For every cell, CI opens each `evidence.path` and asserts `expect` is present at or near `line`. When
the code moves, **the test goes red instead of the document going quietly false.** This is the direct
countermeasure to the twelve false residuals, and specifically to the five false *absence* claims —
which is why an absence claim must record the **search that proved it**, not merely its conclusion:

```toml
  [[cell.absence]]
  pattern          = "clamav|clamd|ICAP|MpCmdRun|yara"
  positive_control = "ScanRejected"   # must MATCH, or the search is blind
```

A zero result is evidence only if the positive control still hits. **A grep naming the wrong token
returns zero and reads exactly like proof** — that is how five of them survived.

### 5. `unverified` is a first-class verdict

Cells inherited from an earlier assessment and never re-read against the requirement text are
`unverified`, **not** `pass`. The renderer reports *verified Pass* and *inherited Pass* separately.

This makes the largest standing exposure **visible and countable** rather than a caveat in prose: as of
2026-08-01, ~219 Passes have never been checked against the ASVS text, and the one pass that did apply
an adversarial layer caught **three attempted unearned upgrades out of six proposals**.

### 6. Fail closed, never skip

The verifier **refuses** when the scorecard is absent but expected, rather than skipping. Skipping is
precisely what 15.1.3 does today and why a green CI proves nothing about these documents.

### 7. Placement, and how 15.1.3 closes

| Artifact | Lives in | Why |
|---|---|---|
| Verifier + schema + unit tests (fixture data) | **Development repo** | Generic tooling, no posture data; runs in public CI on every PR |
| `asvs-scorecard.toml` (real verdicts + evidence) | **Vault** | Posture data; `docs/security/`-class |
| Enforcement against the real data | **Vault pre-commit hook + one narrow vault workflow** | See the amendment — the obvious answer was wrong |

That last row is the fix for **15.1.3**: the guards stop being inspection-only theatre.

> ### ⚠️ Amendment at ratification (2026-08-01) — §7's original placement was WRONG
>
> This ADR was drafted proposing *"a vault CI job runs the verifier against the real data"*, reasoning
> from the fact that the vault has `ci.yml`, `tests/` and `pyproject.toml`. **Open question 1 asked
> whether that CI actually executes. It does not.**
>
> The GitHub actions API reports **every vault workflow as `disabled_manually`** — CI, Security,
> CodeQL, backlog-hygiene, release, all of them. The last run was **2026-07-27**, and the two vault
> PRs merged on 2026-08-01 both merged with **zero checks**. The estate was switched off at the
> cutover to avoid duplicating public CI, which is a reasonable decision and is not being reversed.
>
> **A CI-only design would have shipped dead.** The built design is therefore:
>
> 1. **A vault pre-commit hook** — the enforcement that works *today*, needs no CI, and fires at
>    authoring time, which is when the drift is introduced.
> 2. **One narrow new workflow** (`asvs-scorecard.yml`) — new workflows are active by default even
>    though the estate is disabled, so this runs without resurrecting any of it. Stdlib-only, no
>    install step, path-filtered, 5-minute cap. It additionally fails if the rendered
>    `ASVS-CURRENT.md` has drifted from the data.
>
> **The lesson is the ADR's own thesis applied to itself.** §7 was a confident, plausible statement
> about system state that nobody had checked — exactly the failure mode the rest of this document
> exists to prevent. It was caught only because ratification was gated on answering the open question
> rather than on the argument reading well.

### 8. A generated entry point

`ASVS-CURRENT.md` is rendered, never hand-written: the count, the anchor commit, the open cells, and
what awaits an owner decision. The dated lineage stays for audit; a new session reads one generated
page instead of reconstructing state from ten superseding documents.

## Consequences

**Good.**

- A dropped cell becomes **impossible** rather than undetected.
- A rotted evidence claim becomes a **red test** rather than a misleading sentence.
- A re-score becomes *"re-verify the cells whose anchors moved"* instead of *"re-derive all 345."*
- Inherited-versus-verified Pass becomes countable, so the real exposure is legible.
- 15.1.3 closes as a by-product.

**Costs, stated plainly.**

- **Populating 345 cells is real work.** Mitigated by generating the skeleton from the held corpus
  (ids, levels, chapter/section come free) and marking everything not verified today `unverified` —
  which is honest, and is itself the finding.
- **Evidence anchors will break on refactors.** That is the feature; it is also maintenance. `expect`
  is a token rather than a line number precisely so ordinary edits do not thrash it.
- **Two homes for one system** (tool public, data vault). Accepted: the alternative is either posture
  data in the public repo or a tool nothing runs.
- **This does not make the score correct.** It makes it *consistent, derived, and drift-detecting*.
  A wrong verdict recorded carefully is still wrong — adversarial verification remains the only cure
  for that, and this ADR does not replace it.

**Rejected alternatives.**

- *Keep prose, review harder.* Six documented failure modes in one day survived careful review by
  construction: every false residual **read as true**. The project's own standard says the mitigation
  must be structural, not diligence.
- *One document to rule them all.* Tried — that is what the current lineage is. It produces five
  documents asserting three counts, because a superseding document cannot retract a copy it does not
  know about.
- *Put the vault documents in the public repo so the guards see them.* Refused: they are an attacker
  roadmap (`SECURITY-DOCS-POLICY.md`). Running the guards in the vault achieves the same end.

## Status at ratification

Built and merged 2026-08-01, same day as the decision:

- **Tool** — `scripts/asvs/scorecard.py` (development repo), stdlib only, no new dependency.
- **Tests** — `tests/test_asvs_scorecard.py`, 17 tests. **Every check is proved to go RED before it is
  trusted green**: dropped cell, duplicate cell, an id ASVS retired, a level disagreeing with the
  corpus, a moved token, a deleted file, a blind absence search, an absence that became false.
  Exit codes verified by hand — **0** clean, **1** findings, **2** could-not-measure on a missing file.
- **Data** — `docs/security/asvs-scorecard.toml` (vault), **all 345 cells** seeded from the held
  corpus. 14 carry verified 2026-08-01 evidence; **331 are `unverified`, not `pass`**. The file
  therefore does **not** reproduce the published headline and must not be read as doing so — what it
  reports today is the state of *verification*, which had never been visible.
- **Entry point** — `docs/security/ASVS-CURRENT.md`, generated, never hand-written.

## Open questions

1. ~~**Does the vault CI run `pytest` today?**~~ **ANSWERED 2026-08-01 — no.** Every vault workflow is
   `disabled_manually`. §7 was amended accordingly *before* ratification. This is the question that
   would have shipped a broken control had it been waved through.
2. **Do ADR and BACKLOG numbers collide across the two repos?** The allocator is per-clone. BACKLOG
   spaces are being partitioned; ADR is unresolved and this ADR was allocated in the development repo
   deliberately.
3. **Should `ASVS-CURRENT.md` be publishable** in redacted form (count + levels, no residual text) so
   adopters see a posture summary without the roadmap? Not decided here.
