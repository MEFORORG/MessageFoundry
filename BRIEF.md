# BRIEF — Stream A: absence claims, and making the prover real

You own a **new** workflow, `.github/workflows/asvs-prove-absences.yml`, and the observable-authoring
worklist. Three other streams run in parallel. **`scripts/asvs/scorecard.py` is Stream V's and is
actively changing — do not edit it.** `.github/workflows/asvs-scorecard.yml` is Stream C's.

**Read first:** `docs/security/HANDOFF-ASVS-TRACKING-REWORK-2026-08-08.md` and
`ASVS-P2-RECUT-2026-08-09.md` in the **vault** repo (`<sibling>/MessageFoundry-vault`, on
`origin/main`).

## The state of play, measured 2026-08-09

```
absence claims in the scorecard : 276
  carrying `observable`         :   0
  carrying `mutation_path`      :   0
--prove-absences invoked in CI  :   0 references, in EITHER repo
```

`prove_absences` shipped on 2026-08-07. It copies the tree to a scratch dir, asserts a named
observable is green, applies a stated mutation, and requires the observable to go red. It is real
mutation testing of a control, and **it is wired to nothing.** A mode nothing invokes cannot go red
whatever you put inside it, so the 276 green absence claims are today exactly as strong as they were
before that merge landed.

**That is the ordering constraint for this whole stream: wire it before hardening it.** Making it
fail on zero adoption is correct and completely inert until something runs it.

## Tasks, in order

### A1 — wire it, in the right repo

Create `.github/workflows/asvs-prove-absences.yml` in **this** repo (the engine).

It must **not** go in the vault's `asvs-scorecard.yml`. That job is `timeout-minutes: 5`, has no
install step, and its own comment states stdlib-only is deliberate "so this job cannot rot on a
lockfile it does not own." Presence/absence proving needs a full engine install plus pytest. Put it
in a separate **scheduled** job here, where the environment already exists, reading the vault
scorecard as an input.

Start it advisory (report, do not block) until adoption is non-zero — then Stream C or the owner can
make it blocking. Report **what it scanned**: claims seen, proved, statically screened, skipped.

### A2 — two load-time guards on the prover

Both stdlib, both cheap, and they are the difference between a proof and a decoration. These are
defects in the shipped code worth fixing regardless. Coordinate with Stream V before touching
`scorecard.py` — propose them as a patch and let V land them, or take ownership by agreement.

- **Signature identity.** Compare the mutation's `ast.arguments` against the real symbol: name,
  posonly, args, kwonly, vararg, kwarg, default counts. A wrong-arity mutation reddens the observable
  via `TypeError` at every call site and reads as a surgical ablation. Measured rot: 8 signature
  edits across the anchored surface in 149 commits — and the mutation is a verbatim copy of a
  signature living in a **different repo** from the code it copies.
- **No `raise` in an ablation body.** An ablation is a weaker return, never a throw. This is the only
  thing that catches a wrecking ball; `counter_observable` provably does not — a wrecking ball and a
  surgical ablation are indistinguishable to it. Keep `counter_observable` (it costs one cached run
  and catches import-level breakage) but do not write it up as attribution, because it is not.

Two efficiency defects in `_prove_one` while you are there: it copies the whole tree per claim, and
re-runs the baseline per claim though the baseline is by definition pristine. `copytree` measures
1.2s; at 276 claims that is 5.7 minutes of pure copying. One pristine copy, save/restore per claim,
baselines cached by node id.

### A3 — the observable worklist, ranked and honest

Produce a ranked list of which absence claims can realistically carry an `observable`, and what each
costs.

- **38 of 276 decided cells already carry a test-file anchor** (13.8%). For those the work is
  *choosing the right node*, roughly 15-30 minutes each — not writing TOML.
- For the rest the observable must be **written**: a new engine test, reviewed, CI'd, merged here,
  then referenced by node id from a string in another repo. Price that as a **standing obligation**,
  not a one-time cost: the node id is an un-refactorable name in a foreign repo.

**State the ceiling honestly in the deliverable.** An `ablate` proves the *named observable* is
sensitive to the *named symbol*, and it inherits that observable's vacuity completely.
`tests/test_connection_api.py:175` says so in its own docstring — it derives its sentinels from the
frozenset it tests. An ablation naming that node passes today while a signing key walks out in
plaintext. Choosing an application observable over a completeness observable is judgment, per cell,
and there is no mechanical discriminator. A forced-but-bad claim is **worse than none**, because it
prints a proof.

## What NOT to build

**`widen` was refuted by execution.** An adversarial pass authored the strongest available widen,
ran it (red), applied the repair it pointed at (green), and the signing key was still returned
verbatim — because the observable scanned *factory parameter names* while the control operated on
*emitted setting names*. Do not resurrect it. The thing that actually finds that class is: enumerate
the domain independently by AST, then **execute the control against every member.** That work is
already assigned to another session — coordinate, do not duplicate.

## Hard rules

- Make every check **fail on purpose** before believing it passes, and confirm the injected defect
  actually landed. A mutation that never applied reads exactly like a pass.
- Print **what you scanned**. A broken run and a clean run must not look alike.
- Do not derive a `mutation` from its own `pattern`. A value generated from the thing it validates
  satisfies the check by construction — the same defect class the field exists to close, arriving
  through the fix.
- Allocate any BACKLOG number with `scripts\coord\alloc.ps1`, never by grepping.
- No emoji or glyphs, including in commit messages (CLAUDE.md §11).

## Coordination

Commit and push freely on `asvs-assurance`; open PRs. **Do not merge to main** without the owner.
A2 needs agreement with Stream V before any edit to `scorecard.py` — one file, one editor.
