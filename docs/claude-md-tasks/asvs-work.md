# mefor-asvs-work

> Split out of [CLAUDE.md](../../CLAUDE.md) on 2026-09-05. Prohibitions that bind
> before this task starts stay in that file, which loads automatically. Read it first.

- **ASVS vocabulary: the SUBJECT is the engine, and the record lives elsewhere — never let the storage
  location name the thing.** An **ASVS cell** is one requirement's graded row (verdict + reasoning +
  citations; the scorecard is literally `[[cell]]`). An **anchor** is a citation from a cell to a line
  of engine code. The **verifier** is `scripts/asvs/scorecard.py` — the INSTRUMENT, not the record.
  When a cell's anchor points at code that has moved or gone, say **"the cell has a stale anchor"**:
  the engine is not insecure and the vault is not broken, the *evidence* went stale — usually
  **because the code got better and the fix deleted the line the anchor quoted**.
  - **"Elsewhere" is where, and reading it is one command.** The record is
    `docs/security/asvs-scorecard.toml` in the separate `MessageFoundry-vault` clone, checked out
    **beside this repository** (the same clone [`docs/LEDGER-GATE.md`](../../docs/LEDGER-GATE.md) describes).
    `docs/security/` is gitignored here, so from an engine checkout `git ls-files docs/security`
    returns **zero** — the record does not look misplaced, it looks like it does not exist, which is
    why sessions conclude there is nothing to read. The current score, with **no** engine tree, corpus
    or network needed, in well under a second:

    ```
    python scripts/asvs/scorecard.py --scorecard <vault>/docs/security/asvs-scorecard.toml --status
    ```

    A full verify additionally needs `--corpus` and an **explicit `--root`** naming the engine tree.
    `--root` is REQUIRED in verify mode and `verify` refuses a root that CONTAINS the scorecard:
    resolving anchors against the repository that stores the record produces a self-consistent, wrong
    answer, and the vault carries its own tracked copy of `messagefoundry/` for exactly that trap to
    fall into. **No number this tool prints is a fact without the ref pair it prints beside it** — the
    `# asvs-verify scorecard=X engine=Y` header is part of the measurement, not decoration.
  - **Never say "vault cell", "gate cell", or "vault gate cell".** All three name the filing cabinet
    instead of the subject, and the third also fuses the checker with the checked — a cell exists
    whether or not any job is running. Measured 2026-08-12: that phrasing sent a reader looking at the
    vault, where nothing was wrong, for a defect that lived in engine code.
  - **Keep "verifier" and "verification" apart.** *Verifier drift* = a copy of the tool differs from
    the engine's. *Stale anchors* = the evidence moved. Different failures with adjacent names; the
    gate's own comment says the two "are easy to confuse", and instrument drift once made the gate
    **not run at all** on every matching pull request.
