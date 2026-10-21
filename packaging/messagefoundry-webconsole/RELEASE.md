<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# Release checklist — `messagefoundry-webconsole` (OWNER-ONLY)

> **OWNER-ONLY / outward-facing.** This is the checklist for the **engine-side wiring** a console
> release still needs. **The publish itself is automated and the name is claimed** (corrected
> 2026-09-03, [BACKLOG #1193](../../docs/BACKLOG.md)): the `release-webconsole` job in
> [`.github/workflows/release.yml`](../../.github/workflows/release.yml) builds and publishes this wheel
> on its own `webconsole-v*` tag, and `messagefoundry-webconsole` has been registered on PyPI since the
> first such release on 2026-07-29. The engine `pyproject.toml` declares a `webconsole` extra with a
> floor on the console (step 1); engine 0.5.2 and earlier were published without it. The console
> sets a floor on the engine from 0.4.0 on (step 2). From a checkout the console installs by path
> (`pip install -e packaging/messagefoundry-webconsole`), and the seam handshake is exercised in CI
> against the source tree.

Context: the console is a separately-versioned second distribution mounted same-origin onto the engine
(Option B, [ADR 0065](../../docs/adr/0065-web-ops-dashboard.md)). Architecture, the seam, and the
version-skew gate are documented in [`docs/WEBCONSOLE-PACKAGE.md`](../../docs/WEBCONSOLE-PACKAGE.md).
The **`ENGINE_UI_SEAM` handshake means the engine and console versions can move independently above a
floor** — you do not have to release them lockstep; you must only keep the floors and the two seam
digests honest. Nobody chooses a seam value: it is derived (BACKLOG #1220), and
`docs/WEBCONSOLE-PACKAGE.md` carries the procedure for moving it.

The console's own `release-webconsole` job already exists in
[`.github/workflows/release.yml`](../../.github/workflows/release.yml), modelled on `release-harness`
but fired by the console's **own** `webconsole-v*` tag, since it is not lockstep with the engine.

---

## 0. Decide version + compatibility

- [ ] Set `messagefoundry_webconsole/__init__.py` `__version__` to the release version.
- [ ] Confirm `SUPPORTED_ENGINE_SEAMS` equals `{ENGINE_UI_SEAM}` — one seam, the engine this
      build was released against (BACKLOG #279). A test enforces it; do not widen without also
      landing the cross-seam CI matrix.
- [ ] Choose the two **floors** for the pair. X is the first engine release that carries the seam in
      `SUPPORTED_ENGINE_SEAMS`; the console gets `messagefoundry>=X`. A is this console release; the
      engine gets `messagefoundry-webconsole>=A`. Set **no ceiling** on either side.
      [`docs/WEBCONSOLE-PACKAGE.md`](../../docs/WEBCONSOLE-PACKAGE.md#the-engine-requirement-is-a-floor-with-no-ceiling) gives
      the reasons (BACKLOG #1585).
- [ ] Update [`CHANGELOG.md`](CHANGELOG.md) with the release entry.

## 1. Raise the engine `[webconsole]` floor

- [ ] In the **engine** [`pyproject.toml`](../../pyproject.toml) `[project.optional-dependencies]`, set:

      ```toml
      webconsole = ["messagefoundry-webconsole>=A"]
      ```

      Do this in a pull request after console A is on PyPI, with step 3's re-lock.
      [`docs/WEBCONSOLE-PACKAGE.md`](../../docs/WEBCONSOLE-PACKAGE.md#the-engine-requirement-is-a-floor-with-no-ceiling)
      says why it waits. The engine release already tagged carries the previous floor.

## 2. Set the package's engine dependency floor

- [ ] In [`pyproject.toml`](pyproject.toml), set the engine dependency to the floor
      `["messagefoundry>=X"]` from step 0, in the release commit. Engine X is either already on PyPI,
      or released from the same pull request: bump the engine to X there too, per CONTRIBUTING.md
      *Bumping the engine version*, and tag it first (step 6).
      [`docs/WEBCONSOLE-PACKAGE.md`](../../docs/WEBCONSOLE-PACKAGE.md#the-engine-requirement-is-a-floor-with-no-ceiling)
      says why the same pull request works. Add no upper bound and no environment marker.

      Do not skip this step. The `release-webconsole` job reads the built wheel and refuses it unless
      its `messagefoundry` requirement has a lower bound and no marker, so a first release that skips
      it fails rather than shipping a bare dependency. The job cannot tell a current floor from one
      left by an earlier release, so after the first floored release, raising X is on you.

## 3. Re-lock and audit

- [ ] `uv lock`, then the DEP-1 exports exactly as `security.yml` runs them. The cyclic optional dep
      `messagefoundry[webconsole]` → `messagefoundry-webconsole` → `messagefoundry` resolves in
      `uv.lock`. The two `--all-extras` exports leave the console out; `security.yml` says why.
- [ ] Run the **DEP-1 audit** with `python scripts/security/audit_all_platforms.py requirements.lock`
      — no known-CVE pins. The console's only dependency is the engine, whose closure that lock
      holds. Not a bare `pip-audit -r requirements.lock`;
      `messagefoundry/security/audit_all_platforms.py` says why.
- [ ] Verify the cyclic optional dep resolves under **both** `uv lock` and plain `pip`.

## 4. SBOM + publish/mirror wiring

- [ ] Ensure the **SBOM** job covers the second wheel. It does not yet: the engine SBOMs are built
      from the core lock, and `release-webconsole` builds none ([BACKLOG #2493](../../docs/BACKLOG.md)).
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
      every release but only publishes to PyPI once you flip the flag. This mirrors the harness
      gating: the variable gates the upload step alone, so with it unset the release still goes
      public, and with it set the release goes public only once the upload has run.

## 6. Tag + publish (the button)

- [ ] Tag the release `webconsole-vA.B.C`, the console's own scheme (independent cadence). The
      `release-webconsole` job, and its engine floor gate, run only on that tag namespace.
- [ ] **When the same pull request released engine X, tag `vX` first, and tag the console only once
      engine X is on PyPI.** A console published first requires an engine nobody can install, and a
      PyPI version cannot be uploaded again if the engine release then fails.
- [ ] Publish to **PyPI** via the gated Trusted-Publishing job. The console's GitHub release is a
      draft until that upload succeeds; `publish-github-release-webconsole` then publishes it. With
      `PUBLISH_WEBCONSOLE` unset, the upload is skipped and the release is published once the `pypi`
      approval is given. Set, the publish refuses while the upload has not run, which is what a
      "Re-run failed jobs" after setting it would do; re-run the `release-webconsole` job instead,
      which re-runs the jobs after it.

## 7. Post-publish verification

- [ ] Confirm the tag matches the PyPI version. (The tag == PyPI == mirror checker was retired
      with the publish machinery at the MEFORORG cutover; there is no mirror to compare against.)
- [ ] Confirm `pip install "messagefoundry[webconsole]"` resolves the pair above both floors. With
      an engine published without the extra, 0.5.2 or earlier, this command installs the engine
      alone. Consoles before 0.4.0 declare a bare `messagefoundry` dependency, so they set no floor.

The operator key is `[security].serve_web_console`. The loader refuses the old `[api].serve_ui`
spelling. [`docs/WEBCONSOLE-PACKAGE.md` section 4](../../docs/WEBCONSOLE-PACKAGE.md) states what
`serve` does when the console is absent. Run the next three checks in order, in a clean venv that
holds wheels only. An editable checkout finds the console in the repository root even after you
uninstall it, so the absent checks would pass for the wrong reason.

- [ ] Install the console with an engine whose `ENGINE_UI_SEAM` the console supports. Leave
      `serve_web_console` unset, and `serve` must boot on the CLI/service path and serve `/ui`. Bind
      to loopback with no `tls_terminated_upstream` and no `web_console_public_address`, since
      either one turns the default console off. Make sure no `MEFOR_` variable sets the console, in
      the shell or in the service's environment. Keep this setup for the rest of this section.
- [ ] Uninstall the console and run `serve` again. It must warn that the package
      `'messagefoundry-webconsole' is not installed`, serve the JSON API only, and keep running.
      That is the expected result, not a refusal.
- [ ] Still without the console, set `serve_web_console = true` under `[security]` and run `serve`.
      It must print `error: [security].serve_web_console=true needs the web console package` and
      exit with code 2. **Without the explicit key you see only the warning, which proves nothing
      about the refusal.**

The two console-absent checks exercise the engine, not the console wheel. Run them against the
engine you pair this release with.

- [ ] Confirm the startup handshake. Reinstall the console, pair it with an engine whose
      `ENGINE_UI_SEAM` is not in the console's `SUPPORTED_ENGINE_SEAMS`, and set
      `serve_web_console = true`. Startup must fail with `UiSeamMismatch`, which `assert_engine_seam`
      raises. Install metadata never refuses an engine newer than the console's seam, because the
      floor has no ceiling; this startup check is what does. A pair far enough apart fails one step earlier, at the engine's import of the console,
      with a named refusal rather than `UiSeamMismatch`. [`docs/WEBCONSOLE-PACKAGE.md` section
      2](../../docs/WEBCONSOLE-PACKAGE.md) states what `serve` and `create_app` print then.
- [ ] Confirm an engine older than X also fails at resolve (PEP 508).

---

### Reminder — what stays true regardless of publish

- A plain `pip install messagefoundry` remains **byte-identical**: the engine wheel does not contain
  the console. The console is on by default for a loopback bind, and with it absent the engine serves
  the JSON API only and prints a warning. It installs as its own distribution, or through the
  engine's `[webconsole]` extra.
- Publishing this wheel does **not** buy deploy independence — a new console build still needs an engine
  **restart** (same-origin, in-process mount). See
  [`docs/WEBCONSOLE-PACKAGE.md` §5](../../docs/WEBCONSOLE-PACKAGE.md).
