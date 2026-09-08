<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# Release checklist — `messagefoundry-webconsole` (OWNER-ONLY)

> **OWNER-ONLY / outward-facing.** This is the checklist for the **engine-side wiring** a console
> release still needs. **The publish itself is automated and the name is claimed** (corrected
> 2026-09-03, [BACKLOG #1193](../../docs/BACKLOG.md)): the `release-webconsole` job in
> [`.github/workflows/release.yml`](../../.github/workflows/release.yml) builds and publishes this wheel
> on its own `webconsole-v*` tag, and `messagefoundry-webconsole` has been registered on PyPI since the
> first such release on 2026-07-29. What is still unwired is the **engine** side: the engine
> `pyproject.toml` declares no `webconsole` extra and the compat ranges are unset, so the pair cannot yet
> be installed as one. From a checkout the console installs by path
> (`pip install -e packaging/messagefoundry-webconsole`), and the seam handshake is exercised in CI
> against the source tree.

Context: the console is a separately-versioned second distribution mounted same-origin onto the engine
(Option B, [ADR 0065](../../docs/adr/0065-web-ops-dashboard.md)). Architecture, the seam, and the
version-skew gate are documented in [`docs/WEBCONSOLE-PACKAGE.md`](../../docs/WEBCONSOLE-PACKAGE.md).
The **`ENGINE_UI_SEAM` handshake means the engine and console versions can move independently within a
compat range** — you do not have to release them lockstep; you must only keep the range and the seam
integers honest.

The console's own `release-webconsole` job already exists in
[`.github/workflows/release.yml`](../../.github/workflows/release.yml), modelled on `release-harness`
but fired by the console's **own** `webconsole-v*` tag, since it is not lockstep with the engine.

---

## 0. Decide version + compatibility

- [ ] Set `messagefoundry_webconsole/__init__.py` `__version__` to the release version.
- [ ] Confirm `SUPPORTED_ENGINE_SEAMS` equals `{ENGINE_UI_SEAM}` — one seam, the engine this
      build was released against (BACKLOG #279). A test enforces it; do not widen without also
      landing the cross-seam CI matrix.
- [ ] Choose the PEP 508 **compat range** `A..B` for the pair (the console's `messagefoundry>=X,<Y` and
      the engine's `messagefoundry-webconsole>=A,<B`). Bump `<Y`/`<B` only across a seam change.
- [ ] Update [`CHANGELOG.md`](CHANGELOG.md) with the release entry.

## 1. Re-add the engine `[webconsole]` extra

- [ ] In the **engine** [`pyproject.toml`](../../pyproject.toml) `[project.optional-dependencies]`, add
      (mirroring `[harness]`/`[webauthn]`):

      ```toml
      webconsole = ["messagefoundry-webconsole>=A,<B"]
      ```

      The wheel **is** on the index, so this dependency resolves. It was removed while the name was
      unclaimed; re-adding it is the point of this step, and step 3 re-locks to confirm the cycle
      resolves under both `uv lock` and plain `pip`.

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
      (retired at the MEFORORG cutover -- development is now direct on the public repo, so there
      is no mirror to keep in sync and no release-sync checker).

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

- [ ] Confirm the tag matches the PyPI version. (The tag == PyPI == mirror checker was retired
      with the publish machinery at the MEFORORG cutover; there is no mirror to compare against.)
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
