# Dogfood-Backlog Multi-Session Plan (#470–#475 + #124/D8)

Roadmap for addressing the consumer-deployment-path gaps surfaced by the 2026-06-22 test-server
dogfood of the ADR-0017 adopter model (config repo + pinned wheel, no engine source). The issues
were filed/verified against live code; this plan sequences them into worktree-isolated sessions.

**Source issues:** [#470](https://github.com/MEFORORG/MessageFoundry/issues/470) (Windows service
installer), [#471](https://github.com/MEFORORG/MessageFoundry/issues/471) (`messagefoundry send`),
[#472](https://github.com/MEFORORG/MessageFoundry/issues/472) (VS Code `.vsix`),
[#473](https://github.com/MEFORORG/MessageFoundry/issues/473) (config/CWD ergonomics),
[#474](https://github.com/MEFORORG/MessageFoundry/issues/474) (store-TLS posture),
[#475](https://github.com/MEFORORG/MessageFoundry/issues/475) (interpreter bounds), and the D8
secret-enumeration preflight folded into
[#124](https://github.com/MEFORORG/MessageFoundry/issues/124).

> Already closed by the dogfood pass (not in this plan): the `check` custom-env posture guard (#5)
> and the scaffold `.gitignore` `bootstrap-admin.txt` line (D11) were fixed in-tree; the standalone
> `dryrun --inbound` ambiguity message was verified already clear and dropped.

---

## Overview

**5 sessions, 2 tracks.** One bundled engine-CLI session, three serialized engine sessions behind
it, and one fully-parallel CI/docs session. **Peak concurrency = 2 worktrees.**

**Merge order:** `S1 → S2 → S4 → S3`, with **S5 running in parallel throughout.**

| Session | Issues | Effort | Branch / worktree | Runs |
|---|---|---|---|---|
| **S1** — New CLI subcommands batch | #471 send · #470 install-service · #124/D8 doctor | **L** | `feat/cli-subcommands-send-installservice-doctor` / `cli-subcommands` | First, alone |
| **S2** — Python interpreter bounds | #475 | **S** | `feat/python-interpreter-bounds-guard` / `version-guard` | After S1 |
| **S4** — Store-TLS single posture | #474 | **M** | `feat/store-tls-single-posture` / `store-tls-posture` | After S2 |
| **S3** — Config/CWD roots echo + aliases | #473 | **M** | `feat/config-roots-echo-and-aliases` / `config-ergonomics` | Last (after S1, S2, S4) |
| **S5** — VS Code `.vsix` distribution | #472 | **M** | `feat/vsix-package-and-release-asset` / `vsix-package` | Parallel, anytime |

**Total effort:** 1×L, 3×M, 1×S.

---

## The scheduling constraint: two files, not seven issues

The issues are logically independent; the *only* reason they can't all run in parallel worktrees is
that several of them edit the **same regions of two files**.

### `messagefoundry/__main__.py` — four collision regions
- **`_DISPATCH` dict (L1136–1151)** — appended by #470, #471, #124/D8 (new subcommand keys).
- **subparser block in `main()` (L81–203)** — appended by #470/#471/#124/D8 (new `sub.add_parser(...)`)
  *and* edited by #473 (adds a shared `--config-dir` alias across the existing validate/graph/check parsers).
- **usage docstring (L5–13)** — bumped by every new subcommand.
- **`_serve` body** — edited by #475 (interpreter warn/refuse) and #474 (store-TLS preflight); a region
  *separate* from `_DISPATCH`/subparsers.

Bundling #470/#471/#124/D8 into **one** session (S1) collapses three would-be three-way conflicts on
`_DISPATCH`/subparsers/docstring into a single additive edit. #473 (S3) is the only session that edits
*existing handler bodies*, so it lands **last** to absorb the already-merged additive subcommands.
#475 (S2) and #474 (S4) both insert a short preflight near the top of `_serve` — S2 lands before S4
so S4 rebases past it; both are single-direction inserts.

### `messagefoundry/checks.py` — the `run_checks` results list (L85–89)
Appended by three issues: `secrets` (#124/D8, in S1), `python` (#475, in S2), `store_tls` (#474, in S4).
#473 only *reads* `checks._find_service_toml` and adds no row. Serializing `S1 → S2 → S4` turns these
into clean single-direction merges (parallel worktrees would produce overlapping one-line hunks on the
exact same list line). Ordering lands the security-sensitive `store_tls` check last, on a list already
validated by CI.

### Soft conflict (mergeable regardless of order)
`.github/workflows/ci.yml`, `release.yml`, `docs/INSTALL-GUIDE.md`, `CHANGELOG.md` are touched by #470
(S1) and #472 (S5) — but in **disjoint jobs/sections** (S1 = windows-service-smoke + wheel asset list;
S5 = `ide` job + Node toolchain + `.vsix` asset). So S5 stays fully parallel-safe.

**Net:** only the two `.py` files force serialization. Bundling the subcommand trio (S1) and chaining
S2→S4→S3 behind it means no two concurrently-running worktrees ever edit the same region.

---

## Parallelization plan

**Track A (fully parallel, merge anytime):** **S5 (#472)** — pure TS/CI/docs, no `.py` surface.

**Track B (the engine chain, serialized on `__main__.py` + `checks.py`):**
1. **S1** first and alone on the `_DISPATCH`/subparsers/usage-docstring regions + the first
   `run_checks` append (`secrets`). Nothing else touches those regions until S1 merges.
2. **S2** next (adds the `python` row + the `_serve` interpreter guard).
3. **S4** after S2 (both append to `run_checks` and insert a `_serve` preflight; serialize to keep
   merges trivial — they *can* be developed in parallel worktrees with a hand-resolve at merge if more
   concurrency is wanted).
4. **S3** last — rewrites the existing `_validate/_graph/_check` bodies and adds `--config-dir` across
   existing subparsers, so it rebases on top of all additive `__main__.py` changes.

**Concurrency shape:** at peak, two worktrees active (one Track-B session + S5).

---

## Sessions

### S1 — New CLI subcommands batch (#471 + #470 + #124/D8) — effort L
Branch `feat/cli-subcommands-send-installservice-doctor`, worktree `cli-subcommands`.
**Internal order:** #471 → #124/D8 → #470 (smallest/least-shared first).

- **#471 `messagefoundry send [--smoke]`** — lift `samples/send_mllp.py` into the package (it already
  wraps `parsing.normalize` + `transports.mllp.frame`/`MLLPDecoder`); print the framed ACK; `--smoke`
  exits non-zero on NAK/no-ACK.
- **#124/D8 `messagefoundry doctor`** — walk every connector/lookup spec for the active env and
  **accumulate** all missing/uncastable `MEFOR_VALUE_*` keys (vs `build_check_registry`'s raise-on-first),
  printing connector + setting + key. Building block: `wiring.py` `referenced_env_keys` (~L465). Adds a
  best-effort `secrets` row to `run_checks`.
- **#470 install/uninstall service** — move `scripts/service/*.ps1` under the package
  (`messagefoundry/scripts/service/`, packaged like `auth/data/common_passwords.txt` via
  `importlib.resources`); add `install-service`/`uninstall-service` subcommands that shell the packaged
  script (off-Windows → clean exit-2, mirror `protect-key`); fix console `service_control.py` path
  resolution; repoint the ci.yml windows-service-smoke leg; attach the `.ps1` as release assets; rework
  the script's `$RepoRoot`/`$Config`/`$AppExe` defaults for the packaged location (default `$AppExe` to
  the resolved `messagefoundry.exe`, require `-Config`).

**One coherent edit** to `__main__.py` `_DISPATCH` + subparsers + usage docstring covering all three.
**Tests:** `test_send_cli.py`, `test_service_install_cli.py` (or extend `test_cli.py`), `test_wiring.py`
enumerate cases, `test_service_control.py` packaged-path update, `test_checks.py` secrets-check cases,
plus a wheel-contents smoke (`unzip -l dist/*.whl | grep messagefoundry/scripts/service/...`).
**Docs:** EARLY-ADOPTER / USER / INSTALL guides, SERVICE.md, CONNECTIONS.md, CONFIGURATION.md.

### S2 — Python interpreter bounds (#475) — effort S
Branch `feat/python-interpreter-bounds-guard`, worktree `version-guard`. **Blocked by S1.**
Add an upper bound to `pyproject` `requires-python` (e.g. `>=3.11,<3.14`), a standalone
`messagefoundry/_version_guard.py` (no engine imports — mirrors `timezone.py`/`last_resort.py`), a
serve-startup warn/refuse, and a **required** `python` row in `run_checks`. Drives a CI test-matrix
honesty decision (the bound must track CI's validated top). **Tests:** `test_version_guard.py`,
`test_checks.py` python-row cases, plus a drift test parsing `requires-python` vs the constants.

### S4 — Store-TLS single posture (#474) — effort M
Branch `feat/store-tls-single-posture`, worktree `store-tls-posture`. **Blocked by S1, S2.**
Add `[store].store_tls = verify | trust_cert | insecure` + a `model_validator` that derives/expands into
the two existing backend gates **back-compat byte-identical**; fail-closed on weakened+production in a
`_serve` preflight; `MEFOR_ALLOW_INSECURE_TLS` becomes a no-op warning; best-effort `store_tls` row in
`run_checks`. Security-sensitive — the **SQL Server CI leg + Postgres failover suite must stay green**
via the back-compat derivation. **Tests:** `test_settings.py`, `test_asvs_phase0.py`,
`test_postgres_store.py`, `test_cli.py`, `test_checks.py`; CHANGELOG note on the safe breaking change.

### S3 — Config/CWD path ergonomics (#473) — effort M
Branch `feat/config-roots-echo-and-aliases`, worktree `config-ergonomics`. **Blocked by S1, S2, S4.**
Shared root-resolution/echo helper wired into `_validate/_graph/_check` (**text → stdout header;
`--json` → stderr lines** to preserve the IDE's stdout JSON contract — validate=array, graph=object);
`add_config_arg` helper adding `--config-dir` across validate/graph/check; `--log-dir` resolution
(advisory or dropped per owner). Reuses `checks._find_service_toml`. **Tests:** `test_cli.py` locking the
JSON-array/object contracts + alias equivalence; `test_checks.py` echo-resolution case.
**Docs:** CONFIGURATION.md, CONNECTIONS.md (File-connector CWD footgun), ide/README.md.

### S5 — VS Code extension `.vsix` (#472) — effort M, fully parallel
Branch `feat/vsix-package-and-release-asset`, worktree `vsix-package`. **No `.py` edits.**
`@vscode/vsce` devDep + `package` script + version bump (0.0.1 → 0.1.0) + lockfile; `.vscodeignore`;
ci.yml `ide`-job package step + `upload-artifact`; release.yml `setup-node` + `vsce package` +
Sigstore-sign the `.vsix` + add it to the gh-release assets + a version-match smoke; Install-from-VSIX
docs + CHANGELOG. Align the shipped extension defaults (`samples/config`/`samples/messages`) with the
adopter `config/` + `messages/sets/` layout or document the `init`-scaffolded override.

---

## Owner decisions to settle before building

- **#475 (S2):** `requires-python` upper bound value (`<3.14` vs `<3.15`); **warn vs refuse** out of
  range; add a py3.14 CI leg?
- **#474 (S4):** is plaintext store-TLS forbidden-in-prod *even with* the escape hatch? `store_tls`
  enum naming; confirm SQL Server / Postgres legs stay green via back-compat derivation.
- **#470 (S1):** **move** the service scripts under the package (recommended) vs keep a shim; document
  no-source elevation + NSSM pre-staging on locked-down networks.
- **#473 (S3):** keep or **drop `--log-dir`** (recommend drop).
- **#472 (S5):** Marketplace publisher account (defer to Open VSX / release-asset only?); coordinate the
  `ide` version bump with the **staged-but-held v0.1.0 tag**.

---

## Execution mechanics

Each session: `scripts/worktree/new.ps1 -Name <worktree>`, its own `.venv`
(`.\.venv\Scripts\Activate.ps1`), a feature branch + PR. Gates (all must pass): `ruff check`,
`ruff format --check`, `mypy` (strict), `pytest` (with `QT_QPA_PLATFORM=offscreen`) — plus the
windows-service-smoke leg (S1) and the SQL Server / Postgres legs (S4). Commits carry **no
`Co-Authored-By` trailer** (CLA bot). Wait for an explicit **"go"** before building each session.
