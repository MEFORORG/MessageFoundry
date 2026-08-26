# Contributing to MessageFoundry

Thanks for your interest in contributing! MessageFoundry is a code-first HL7 v2.x integration
engine. This guide covers the license, the Contributor License Agreement, and the local checks a
change must pass.

By participating you agree to abide by our [Code of Conduct](CODE_OF_CONDUCT.md). How the project is
governed, what we welcome, and what to **discuss first** before writing code are described in
[GOVERNANCE.md](GOVERNANCE.md) — please skim it before a non-trivial change so effort lands where it
can be merged.

## License

MessageFoundry is licensed under the **GNU Affero General Public License v3.0 or later**
(`AGPL-3.0-or-later`) — see [LICENSE](LICENSE). By contributing, you agree your contributions are
licensed under the same terms (and see the CLA below). The AGPL's §13 network clause means anyone
who runs a modified version as a network service must offer its source to users.

## Contributor License Agreement (CLA)

Before your first contribution can be merged, you must agree to the **[Contributor License
Agreement](CLA.md)**. It confirms you have the right to contribute your code and grants MessageFoundry
Organization (the Project Owner) the rights needed to keep MessageFoundry sustainable — including the
ability to offer a separately-licensed commercial edition under the standard "open-core" model
(planned; the CLA and the commercial terms are pending legal review — see [CLA.md](CLA.md)). You keep
the copyright to your contributions.

How to sign: our **CLA Assistant** bot comments on every new pull request. Agree by replying with:

```
I have read the CLA and I agree to its terms.
```

The bot records your signature (on the `cla-signatures` branch) and updates the PR's CLA status
check — you only sign once. (For a corporate contribution, your employer must agree — contact the
maintainer.)

## Development workflow

1. **Branch + PR.** Work on a feature branch and open a pull request against `main`; direct pushes
   to `main` are blocked. Keep commits coherent (one logical layer per commit) with clear messages.
2. **Set up the environment** (Windows/PowerShell shown; adapt for your OS):
   ```powershell
   py -3.14 -m venv .venv
   .\.venv\Scripts\Activate.ps1
   pip install -e ".[dev,harness]"
   ```
3. **Add a test for new behavior.**
4. **Run the gates** — a change isn't ready until these pass (the PySide6 harness/Qt tests need the
   offscreen platform):
   ```powershell
   ruff check .
   ruff format --check .
   mypy messagefoundry
   $env:QT_QPA_PLATFORM = "offscreen"; pytest -q
   ```
   You can also run the project's own commit/CI gate: `python -m messagefoundry check`.
5. **Install the commit hooks — including the leak gate — before your first commit:**
   ```powershell
   pip install pre-commit
   pre-commit install
   pwsh -NoProfile -File scripts\dev\setup-leak-gate.ps1 -Synthetic
   ```
   See *Leak gate* below for what that last line does and why it is not optional.

### Leak gate (required, and it fails closed)

One pre-commit hook — **forbidden-content** — scans for customer/PHI tokens. Its token list is
private and git-ignored, so it does **not** arrive with a clone or a `git worktree add`. Without a
token source the hook refuses to run and **every commit is blocked**:

```
scan_forbidden: no token source is configured ... refusing to run structural-only (fail closed).
```

That is deliberate. A gate that quietly loaded zero detectors would pass every commit green while
seeing nothing — the failure mode this project has hit more than once. Do not remove
`--require-tokens`, and do not reach for `--no-verify`.

- **Outside contributors** cannot have the real list; it will never be distributable. Run
  `setup-leak-gate.ps1 -Synthetic` to install the committed synthetic template. It is a DIFFERENT
  detector set, not a weaker copy of the real one: its placeholders are the fictional customer and
  partner names this project's own docs and samples use throughout, so staging one of those files
  can block a commit that leaks nothing. Read the run banner to see which set is loaded, and judge
  the hit on that. **CI runs the real detector set on your PR** — that is the authoritative check.
- **Maintainers** install the real list: `setup-leak-gate.ps1 -From <path>`.

**Writing a placeholder site code?** Use a non-numeric stand-in — `SITEA`, or the angle-bracket
`<site>` form. The token list's `[site_prefix]` guidance is written for whoever fills that list *in*;
read as advice for placeholder *values* it points you straight at a prefix this gate then detects in
your tracked prose, and the hook blocks the commit.
[`scripts/security/scan-tokens.local.txt.example`](scripts/security/scan-tokens.local.txt.example) is
the source of record for the detail.

`setup-leak-gate.ps1` always finishes by running the scanner and printing its per-section detector
counts, because a green gate is evidence only if you confirmed it can see. The scanner labels its
mode on every run, so a synthetic set can never be mistaken for a real one:

```
loaded names=7, estate=13, estate_file_scanned=12, site_prefixes=1
loaded names=5, estate=3,  ...  [SYNTHETIC EXAMPLE TOKENS — blind to real customer tokens; CI is authoritative]
loaded names=0, estate=0,  ...  [STRUCTURAL-ONLY: no token source configured]
```

Only the first is a real local scan. Note that the synthetic template is **below CI's per-section
floor** (`names=7, estate=13, site_prefixes=1`) by design — passing locally with it does not mean you
would pass CI's gate, only that nothing structural was found.

It also prints a `token source:` line naming **where those counts came from** — the
`MEFOR_FORBIDDEN_TOKENS` path, that variable carrying the list inline (named, never printed), or
`scripts/security/scan-tokens.local.txt` — and says `OVERRIDDEN` when the environment won over the
file the run just installed. That variable takes precedence, so without the line `-Synthetic` could
install the template and then truthfully report the *real* set as configured, which reads as a
contradiction. The scanner's exit code is propagated too: a refusal is reported as `VERIFY FAILED`,
not as `CONFIGURED`.

## Finding something to work on

Browse issues labeled **`good first issue`** (small, self-contained) and **`help wanted`**. For
anything larger or architectural, open an issue first — see the "discuss first" list in
[GOVERNANCE.md](GOVERNANCE.md). Questions and design discussion go in **GitHub Discussions**; bugs and
concrete features go in **Issues**; security vulnerabilities go through a
[private advisory](.github/SECURITY.md), never a public issue.

### Working on two things at once

Building two changes in parallel? Don't share one checkout — give each its own **git worktree**
(`scripts\worktree\new.ps1 -Name <x>`). See [docs/WORKTREES.md](docs/WORKTREES.md).

### If you use Claude Code: what the tracked settings file actually wires

[`.claude/settings.json`](.claude/settings.json) is **tracked**, so cloning this repo configures
Claude Code, and you should read it before you trust it. It is the only tracked file under
`.claude/`; everything else there is session state and stays ignored.

- **It wires one PowerShell script to run automatically**, and the count is asserted by a test
  rather than by this sentence:
  [`scripts/hooks/seat-declare-prompt.ps1`](scripts/hooks/seat-declare-prompt.ps1) at session
  start. It is in-repo, reviewable, and covered by the same review as any other script here.
- **The repo contains other hook scripts that this file does NOT wire, and the difference matters.**
  [`scripts/worktree/session-context.ps1`](scripts/worktree/session-context.ps1) is wired at
  **user** level by [`scripts/coord/install-coordination.ps1`](scripts/coord/install-coordination.ps1),
  which the maintainer runs from a plain terminal — so it is live on a configured box and absent on
  a fresh clone.
  [`scripts/hooks/block-blanket-git-stage.ps1`](scripts/hooks/block-blanket-git-stage.ps1) is
  **present and fully tested but wired nowhere at all**, and must not be counted as a control until
  it is (BACKLOG #1339). `tests/test_claude_settings_contract.py` asserts that every script under
  `scripts/hooks/` is either wired or named, with its reason, on an explicit unwired list — so this
  paragraph cannot drift from the code without a red test.
- **Hooks need PowerShell 7 (`pwsh`).** A hook that cannot start is **non-blocking** — the action
  proceeds and you get a notice, not a refusal. So on a machine without `pwsh` a guard is absent
  rather than failing loudly. Do not treat any of them as coverage you can rely on; the leak gate
  above is the control that fails closed.
- **The deny rules cover the directory you started the agent in.** They keep `.env`, `secrets/`,
  keys and the local `*.db` store away from the agent's file tools at any depth *below that
  directory*. A session started in one checkout that writes into a sibling worktree by absolute path
  is outside them. The rules are a guard against accident and drift, not against a determined
  operator, and they are not a substitute for the leak gate.

None of this is required to contribute. Delete the file locally if you would rather configure your
own; `git update-index --skip-worktree .claude/settings.json` keeps that local.

## PHI / safety

This engine carries PHI in real deployments. **Never** commit real patient data — tests and
fixtures use only **synthetic, PHI-free** HL7 (`python -m messagefoundry generate`). Don't redirect
`dryrun`/`generate` output (which can contain full message bodies) into committed files or CI logs.
See [docs/PHI.md](docs/PHI.md).

## Conventions

Use the **Connection / Router / Handler** vocabulary, parse on the python-hl7 hot path (hl7apy for
opt-in strict validation), keep the engine free of GUI/web-framework imports, and never manipulate
HL7 with raw string slicing. See the architecture and security docs under [docs/](docs/).
