# BRIEF — Stream V: the verifier

You own **`scripts/asvs/scorecard.py`** in this repo, exclusively. Three other streams are running in
parallel and none of them may touch that file. If your work seems to need a change outside your
owned paths, stop and say so rather than reaching.

**Read first:** `docs/security/HANDOFF-ASVS-TRACKING-REWORK-2026-08-08.md` in the **vault** repo
(the sibling `MessageFoundry-vault` checkout, on `origin/main`). Then `ASVS-P2-RECUT-2026-08-09.md`
beside it. Do not re-derive the analysis; it cost a lot to produce and its numbers are current as of
2026-08-09.

## Owned paths

```
scripts/asvs/scorecard.py          EXCLUSIVE
tests/test_asvs_scorecard.py       EXCLUSIVE
```

Not yours: `scripts/asvs/apply.py`, the vault scorecard TOML, `.github/**`, any other test file.

## Tasks, strictly in order

### V1 — `form` classification, and fix the summary line

Add a derived `form` field to each anchor: `code` | `doc` | `foreign`.

- Classify by **docstring position** (the anchor's matched text falls inside the first statement of a
  module, class or function) plus `#` comments. **Do NOT use a token mask.** Measured: a token mask
  misfiles the Content Security Policy string in `messagefoundry_webconsole/_security.py` and the
  entire SQL Server and Postgres DDL as prose. Docstring-position yields 1,443 code anchors against
  the mask's 1,368 and recovers every CSP and DDL string.
- **580 anchors (29%) resolve into prose or non-Python files** — 198 `.md`, 17 `.ts`, 16 `.js`,
  13 `.yml`, plus the comment/docstring subset. No structural or executable check reaches any of
  them, ever. The record currently presents them as code evidence.
- `form = doc` is a **label, never a demotion.** 17 cells rest genuinely on documentation, which is a
  legitimate ground for a documentation requirement. **Render the split; do not wire it into
  `check_completeness`.**
- In the same change, fix the summary line. It currently claims the run "verified" N evidence
  anchors. It did not. It resolved them. Replace with wording to the effect of *"resolved N anchors
  (the token is present; this is not evidence that the control operates)"*, and print the `form`
  split beside it. The rendered face of the record currently asserts something the check does not
  establish.

### V2 — query mode, step one only

Spec: `docs/security/ASVS-QUERY-MODE-SPEC-2026-08-09.md` in the vault. Build **only** the provenance
line plus `--status`. Do not build `--cell`, `--cells-for` or `--cells-since` yet.

The provenance line is the point, not the brevity:

```
# asvs-status scorecard=<sha>[+dirty] engine=<sha>[+dirty]
#   freshness=CURRENT | BEHIND <n> | AHEAD <n> | DIVERGED | NO-UPSTREAM
#   remote-knowledge=<age of FETCH_HEAD> generated=<iso8601>
```

- **No implicit `git fetch`.** An explicit `--fetch` flag is permitted; the default is a pure read.
  A query tool that mutates remote-tracking refs as a side effect is wrong, and the vault remote is
  intermittently unauthenticated on this machine, so fail-closed-on-network would fire constantly and
  the tool would be bypassed within a day.
- Staleness needs **zero network**: `git rev-list --count HEAD..origin/main` counts against the
  last-fetched remote-tracking ref, and the mtime of `.git/FETCH_HEAD` says how old that knowledge
  is. Measured against the checkout that caused a real error in this programme: *BEHIND 37, remote
  knowledge 23 minutes old.* That line would have stopped it dead.
- **The freshness field is mandatory and always populated.** `NO-UPSTREAM` and an unresolvable
  remote-tracking ref are **loud labelled values, never an omitted field.** An absent qualifier is
  what produced three separate wrong-base errors in this programme.

### V3 — `sym` + `ctx` validation support, ADDITIVE

Accept and validate `sym` (enclosing symbol) and `ctx` (block-node chain, e.g. `Try.body`) on an
anchor. Derive with `ast`, which this module already imports.

- **Additive to the drift advisory, never a replacement.** 38.4% of sited anchors live in a
  `(sym, ctx)` region wider than the window that PR #295 retired, so `sym`/`ctx` alone is *looser*
  for 639 anchors. Each catches what the other cannot.
- **`ctx`, not raw indentation.** Cell 12.3.5 has the identical 4-vs-8 indent mismatch as 10.5.4 and
  is a non-event — a hand-trimming slip, `ctx` unchanged at both ends. Indentation flags it; `ctx`
  correctly does not.
- **This sentence must appear in the docstring beside the check, in the same commit, or the check
  does not land:** *this is a displacement signal, not a defect detector; its security-relevant
  precision measured 0 of 1 on the only datum the corpus offers (10.5.4's red was a hardening).* A
  signal described as a defect detector where people read it will be quoted as one.

You are validating the field, not backfilling it. Stream D backfills the data.

## Hard rules

- **Never propose "re-anchor to the nearest occurrence" on a GONE token.** A GONE token splits four
  ways and only one is mechanical: moved (re-anchor), renamed (re-anchor with judgment), **the gap
  the anchor certified was closed** (retire and rewrite the residual — cell 3.7.5 is the worked
  case), and control removed (re-score). Suggesting a nearest match manufactures the third case into
  a stale-but-resolving anchor. Report candidates; never suggest one. There is already a test
  enforcing this — do not weaken it.
- Every check prints **what it scanned**, not only what it found. A broken run and a clean run must
  not look alike.
- Make each new check **fail on purpose** before believing it passes, and confirm the injected defect
  actually landed.
- `ruff format --check`, `ruff check`, `mypy` strict, and `pytest` all clean before you commit.
- No emoji or glyphs anywhere, including commit messages (CLAUDE.md §11).

## Coordination

Commit and push freely on `asvs-verifier`; open PRs. **Do not merge to main** without the owner. One
file, one editor: if you believe you need `apply.py` or the vault TOML, say so and it will be
sequenced rather than shared.
