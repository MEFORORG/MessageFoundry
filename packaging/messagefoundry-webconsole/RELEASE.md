<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# Release checklist — `messagefoundry-webconsole` (OWNER-ONLY)

> **OWNER-ONLY / outward-facing.** This is the checklist to **publish the second wheel** — everything up
> to and including the publish button. It is **not automated and deliberately not wired yet**: the engine
> `[webconsole]` extra is removed, no PyPI-publishing job for this wheel exists, and the compat ranges
> are unset, because an unpublished dependency would break `uv lock`. Do these steps only when you intend
> to publish. Until then, the console installs by path (`pip install -e packaging/messagefoundry-webconsole`)
> and the seam handshake is exercised in CI without any published artifact.

Context: the console is a separately-versioned second distribution mounted same-origin onto the engine
(Option B, [ADR 0065](../../docs/adr/0065-web-ops-dashboard.md)). Architecture, the seam, and the
version-skew gate are documented in [`docs/WEBCONSOLE-PACKAGE.md`](../../docs/WEBCONSOLE-PACKAGE.md).
The **`ENGINE_UI_SEAM` handshake means the engine and console versions can move independently within a
compat range** — you do not have to release them lockstep; you must only keep the range and the seam
integers honest.

The `messagefoundry-harness` `release-harness` job in
[`.github/workflows/release.yml`](../../.github/workflows/release.yml) is the working precedent for a
second-wheel release job — mirror it (with the console's **own** version, since it is not lockstep).

---

## 0. Decide version + compatibility

- [ ] Set `messagefoundry_webconsole/__init__.py` `__version__` to the release version.
- [ ] Confirm `SUPPORTED_ENGINE_SEAMS` lists every engine `ENGINE_UI_SEAM` this build supports.
- [ ] Choose the PEP 508 **compat range** `A..B` for the pair (the console's `messagefoundry>=X,<Y` and
      the engine's `messagefoundry-webconsole>=A,<B`). Bump `<Y`/`<B` only across a seam change.
- [ ] Update [`CHANGELOG.md`](CHANGELOG.md) with the release entry.

## 1. Re-add the engine `[webconsole]` extra

- [ ] In the **engine** [`pyproject.toml`](../../pyproject.toml) `[project.optional-dependencies]`, add
      (mirroring `[harness]`/`[webauthn]`):

      ```toml
      webconsole = ["messagefoundry-webconsole>=A,<B"]
      ```

      This is safe to re-add **only after** the wheel exists on the index (a bare/unpublished dep breaks
      `uv lock`, which is why it is removed today).

## 2. Set the package's engine dependency range

- [ ] In [`pyproject.toml`](pyproject.toml), change `dependencies = ["messagefoundry"]` to the compat
      range `["messagefoundry>=X,<Y"]` consistent with the supported seam(s).

## 3. Re-lock and audit (now resolvable)

- [ ] `uv lock` + `uv export` on the engine — the cyclic optional dep
      `messagefoundry[webconsole]` → `messagefoundry-webconsole` → `messagefoundry` resolves once the
      wheel is published. Confirm `requirements.lock` updates and stays in sync (DEP-1).
- [ ] Run the **DEP-1 audit** (`pip-audit` on the lockfile) and confirm the second distribution is
      covered — no known-CVE pins.
- [ ] Verify the cyclic optional dep resolves under **both** `uv lock` and plain `pip`.

## 4. SBOM + publish/mirror wiring

- [ ] Ensure the **SBOM** job covers the second wheel.
- [ ] Add the wheel to the **publish/mirror** wiring as needed
      ([`scripts/publish/`](../../scripts/publish/)); extend
      `scripts/publish/check_release_sync.py` if the mirror should track the console version too.

## 5. CI build + release job

- [ ] Add a `release-webconsole` job to [`release.yml`](../../.github/workflows/release.yml) modelled on
      `release-harness`: **wheel-only** build (the import package is force-included from the repo root, so
      an sdist is not self-contained), a version-smoke step, attach-to-GitHub-release, and a **gated**
      PyPI publish.

      ```bash
      python -m build --wheel ./packaging/messagefoundry-webconsole --outdir webconsole-dist
      ```

- [ ] Configure a `messagefoundry-webconsole` **PyPI Trusted Publisher** (pending publisher for the repo
      + `release.yml`) and a `PUBLISH_WEBCONSOLE`-style gate variable, so the job builds + attaches on
      every release but only publishes to PyPI once you flip the flag (mirrors the harness gating).

## 6. Tag + publish (the button)

- [ ] Tag the release using the console's own scheme (independent cadence — e.g. a
      `webconsole-vA.B.C` tag, or lockstep with the engine tag initially; document the choice).
- [ ] Publish to **PyPI** via the gated Trusted-Publishing job.

## 7. Post-publish verification

- [ ] Run `python scripts/publish/check_release_sync.py` (tag == PyPI == mirror).
- [ ] `pip install "messagefoundry[webconsole]"` resolves the pair inside the compat range.
- [ ] `serve_ui=true` boots end-to-end on the CLI/service path with the console installed, and the
      engine still **boots + refuses `serve_ui` cleanly** with the console **absent** (return 2 /
      `RuntimeError`, not a bare `ImportError`).
- [ ] Confirm the seam handshake: an out-of-range pair fails at resolve (PEP 508) and at startup
      (`UiSeamMismatch`).

---

### Reminder — what stays true regardless of publish

- A plain `pip install messagefoundry` remains **byte-identical**; `serve_ui` is default-off and the
  console is an optional extra.
- Publishing this wheel does **not** buy deploy independence — a new console build still needs an engine
  **restart** (same-origin, in-process mount). See
  [`docs/WEBCONSOLE-PACKAGE.md` §5](../../docs/WEBCONSOLE-PACKAGE.md).
