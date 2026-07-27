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
  `setup-leak-gate.ps1 -Synthetic` to install the committed synthetic template. Your commits will
  pass, and **CI runs the real detector set on your PR** — that is the authoritative check.
- **Maintainers** install the real list: `setup-leak-gate.ps1 -From <path>`.

The script always finishes by running the scanner and printing its per-section detector counts,
because a green gate is evidence only if you confirmed it can see. The scanner labels its mode on
every run, so a synthetic set can never be mistaken for a real one:

```
loaded names=7, estate=13, estate_file_scanned=12, site_prefixes=1
loaded names=5, estate=3,  ...  [SYNTHETIC EXAMPLE TOKENS — blind to real customer tokens; CI is authoritative]
loaded names=0, estate=0,  ...  [STRUCTURAL-ONLY: no token source configured]
```

Only the first is a real local scan. Note that the synthetic template is **below CI's per-section
floor** (`names=7, estate=13, site_prefixes=1`) by design — passing locally with it does not mean you
would pass CI's gate, only that nothing structural was found.

## Finding something to work on

Browse issues labeled **`good first issue`** (small, self-contained) and **`help wanted`**. For
anything larger or architectural, open an issue first — see the "discuss first" list in
[GOVERNANCE.md](GOVERNANCE.md). Questions and design discussion go in **GitHub Discussions**; bugs and
concrete features go in **Issues**; security vulnerabilities go through a
[private advisory](.github/SECURITY.md), never a public issue.

### Working on two things at once

Building two changes in parallel? Don't share one checkout — give each its own **git worktree**
(`scripts\worktree\new.ps1 -Name <x>`). See [docs/WORKTREES.md](docs/WORKTREES.md).

## PHI / safety

This engine carries PHI in real deployments. **Never** commit real patient data — tests and
fixtures use only **synthetic, PHI-free** HL7 (`python -m messagefoundry generate`). Don't redirect
`dryrun`/`generate` output (which can contain full message bodies) into committed files or CI logs.
See [docs/PHI.md](docs/PHI.md).

## Conventions

Use the **Connection / Router / Handler** vocabulary, parse on the python-hl7 hot path (hl7apy for
opt-in strict validation), keep the engine free of GUI/web-framework imports, and never manipulate
HL7 with raw string slicing. See the architecture and security docs under [docs/](docs/).
