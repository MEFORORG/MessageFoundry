<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->

# The web console package (`messagefoundry-webconsole`)

The browser ops console served under `/ui` is a **separately-versioned second distribution** —
`messagefoundry-webconsole` (import `messagefoundry_webconsole`) — that the engine **mounts in-process,
same-origin**, rather than an in-tree part of the engine wheel. This is "Option B" of
[ADR 0065](adr/0065-web-ops-dashboard.md): the console's routes, rendering, and write-action registry
became independently *developable / testable / releasable* without editing engine core or bumping the
engine version, while keeping the proven same-origin security model (the console was previously the
in-engine `messagefoundry/api/webui/` tree).

This is the authoritative doc for that package: its architecture, the injection **seam** the engine and
package agree on, the **version-skew gate** that keeps the two in lockstep of *meaning* (not version),
how to develop and test it, and its **honest scope** (what the extraction does and does not decouple).

> **Publishing the second wheel is a separate, owner-only step.** The engine `[webconsole]` extra is
> deliberately **not** wired yet (an unpublished dependency breaks `uv lock`). Until the owner publishes,
> install the console by path (`pip install -e packaging/messagefoundry-webconsole`). The full publish
> checklist lives in [`../packaging/messagefoundry-webconsole/RELEASE.md`](../packaging/messagefoundry-webconsole/RELEASE.md).

---

## 1. Architecture

- **A second wheel from the monorepo.** The import package `messagefoundry_webconsole/` lives at the
  **repo root** (a distinct top-level import root — *not* under `messagefoundry.*`, which would collide
  with the engine's regular package namespace). Its build config is
  [`packaging/messagefoundry-webconsole/pyproject.toml`](../packaging/messagefoundry-webconsole/pyproject.toml)
  (hatchling), which force-includes the tree into a wheel. The **engine wheel does not contain it** — the
  same mechanic that keeps `harness/` out of the engine wheel — so a plain `pip install messagefoundry`
  stays byte-identical and, with `serve_ui` default-off, the JSON API is unchanged.
- **Independent version root.** Unlike `messagefoundry-harness` (deliberately lockstep — it reads the
  engine's `__version__`), the console has its **own** `__version__`, tag, changelog, and PyPI cadence.
  It depends on the engine through a PEP 508 **compat range** (`messagefoundry>=X,<Y`), not lockstep.
- **Mounted same-origin, in-process.** `create_app` grafts the console onto its FastAPI app with a single
  call from the `serve_ui` tail: `mount_ui(app, deps)`. Because `create_managed_app` delegates to
  `create_app` and the tests call `create_app` directly, that one call site covers the CLI/service path
  and the test path. The `/ui` routes are **clients of the reused JSON handlers by reference** (not over
  HTTP) — the single audited PHI path, per-channel RBAC, and summary redaction are reused verbatim.
- **Narrow, one-way imports.** The package imports only `fastapi`, the leaf-safe engine surface
  (`messagefoundry.api.security` / `.models` / `.auth_models` / `._ui_seam`), `messagefoundry.auth`, and
  the pure `messagefoundry.parsing` library — **never** `pipeline` / `store` / `transports` / `config`
  (CLAUDE.md §4). The direction package → engine-api-leaf is the only allowed one.

---

## 2. The seam

The engine and package agree on a small, explicit contract centred on one engine **leaf** module,
[`messagefoundry/api/_ui_seam.py`](../messagefoundry/api/_ui_seam.py). It imports no engine core and no
console package, so `import messagefoundry.api.app` still succeeds with the console **uninstalled**
(`add_auth_routes` runs unconditionally and returns an `AdminHandlers` built from this leaf, so its
concrete type must live engine-side).

### `ENGINE_UI_SEAM` — the handshake integer

`api/_ui_seam.ENGINE_UI_SEAM: int` is the contract version the engine ships (currently **1**). The
console declares `messagefoundry_webconsole.SUPPORTED_ENGINE_SEAMS: frozenset[int]` and refuses a skew
at startup via `assert_engine_seam(engine_seam)`, which raises `UiSeamMismatch` with a clear message
rather than a raw `TypeError`. The handshake is **three-layered** and fails loud at every layer:

1. **Install-time** — the PEP 508 range on the engine dependency fails an out-of-range pair at
   `pip`/`uv` resolve (wired at publish; see the RELEASE checklist).
2. **Startup-time** — `create_app`'s `serve_ui` tail calls `assert_engine_seam(ENGINE_UI_SEAM)`
   **before** it builds the deps bundle, so a package that changed the bundle *shape* for a new seam
   surfaces as `UiSeamMismatch`, not a kwargs `TypeError`. A second identical assert at the top of
   `mount_ui` is belt-and-suspenders.
3. **CI** — the package suite runs against the supported engine seam(s); the engine repo's snapshot gate
   (below) fails on an unbumped incompatible change.

### `mount_ui(app, deps)` and the injected bundle

The engine injects a single frozen `UiDeps` dataclass (defined in `api/_ui_seam.py`) into `mount_ui`:

- `engine_seam`, `get_engine`, `get_gate`, `cookie_secure`, `default_scan_limit` — module-level engine
  callables that cross the seam without closure capture;
- `core: CoreHandlers` — the ~30 `create_app`-nested JSON handlers the moved `/ui` routes call directly
  (`list_connections`, `get_message`, `replay_message`, `purge_connection`, `search_messages`, …);
- `admin: AdminHandlers` — the ~26 `add_auth_routes`-nested admin/account/audit handlers plus two sync
  DTO-projection helpers (`user_summary`, `current_user`). `add_auth_routes(app)` **returns** this
  bundle (it runs before `create_app`'s own handlers exist, so the bundle is the only way to reach them).

Handler fields are typed `Callable[..., Awaitable[Any]]` (engine/gate params inside their signatures are
`Any`) so the console never imports `Engine`/`ApprovalGate` (both pull `store`/`pipeline`). `mypy
--strict` at the engine's `deps = UiDeps(...)` construction site still catches builder-signature drift
*within* a seam.

The auth dep factories — `require`, `require_step_up`, `require_reauth_only`, `get_auth`, `authorize_ws`,
`ws_token` — are **not** injected; the console imports them directly from `messagefoundry.api.security`
(leaf-safe). Their public surface is part of the seam's compat scope even so (a re-signature there is
seam-bumping) and is captured by the snapshot gate.

### The `app.state` hooks

`mount_ui` installs three always-on couplings as `app.state` hooks so the engine boots with the console
absent and the default deployment stays byte-identical:

| `app.state` hook | Installed value | Read by (engine) | Absent behaviour |
|---|---|---|---|
| `ui_csp` | the package-provided `UI_CSP` string (co-versioned with `app.js`/`app.css`) | the security-headers middleware, applied only when present | no `/ui` CSP (the `/ui` branch matches nothing) |
| `ui_ws_authorize` | `authorize_ui_ws` (browser cookie/CSWSH auth) | `/ws/stats` handshake | native `Authorization`-header path |
| `ui_connections_render` | `pages.connections_fragment` (server-rendered enrichment) | `/ws/stats` push | counts-only push |

Because CSP moves with the client assets it governs, a package-only CSP tweak for a new `app.js`
source ships **package-only**.

---

## 3. The version-skew gate

Independent versioning is exactly what makes runtime skew possible, so the engine repo carries a
**contract-snapshot gate**. Its purpose: a silent, incompatible change to the injected contract — a
renamed handler field, a re-signatured `api.security` dep or `AuthService` method, or a renamed field on
a **DTO the console renders** (which breaks render, not import, so `mypy` alone misses it) — must fail
CI until `ENGINE_UI_SEAM` is bumped.

Three files implement it:

- [`scripts/webconsole_seam_snapshot.py`](../scripts/webconsole_seam_snapshot.py) — emits a stable,
  deterministic text serialization of the contract: `ENGINE_UI_SEAM`; the `UiDeps` / `CoreHandlers` /
  `AdminHandlers` dataclass field names; a **curated** list of the cross-seam surface consumed outside
  the bundle (the `api.security` deps' names+signatures, the `AuthService` methods, the `app.state`
  attributes); and the **live-introspected** field sets of the `api.models` / `api.auth_models` DTOs the
  console renders (so a rename on exactly those DTOs changes the snapshot).
- [`tests/golden/webconsole_seam.snapshot`](../tests/golden/webconsole_seam.snapshot) — the checked-in
  golden.
- [`tests/test_webconsole_seam_snapshot.py`](../tests/test_webconsole_seam_snapshot.py) — regenerates the
  snapshot and diffs it against the golden, failing with an actionable hint on any drift.

This gate is the **sole backstop** against a *future* engine's unbumped, render-breaking DTO rename
(the package CI matrix only covers engines that exist at package-CI time), so it must stay comprehensive
and blocking.

### Bumping the seam on an intentional contract change

When you deliberately change the injected contract (add/rename a `CoreHandlers`/`AdminHandlers` field,
change an `api.security` dep signature, rename a rendered DTO field, add/remove an `app.state` hook or a
consumed `AuthService` method):

1. Make the contract change in the engine (and the matching consumer change in the package).
2. Bump `ENGINE_UI_SEAM` in [`messagefoundry/api/_ui_seam.py`](../messagefoundry/api/_ui_seam.py)
   (e.g. `1` → `2`).
3. Update `messagefoundry_webconsole.SUPPORTED_ENGINE_SEAMS` in
   [`messagefoundry_webconsole/__init__.py`](../messagefoundry_webconsole/__init__.py): add the new seam
   (`frozenset({1, 2})` to keep supporting the old engine, or `frozenset({2})` to drop it).
4. If the change touched the *curated* surface (an `api.security` symbol, an `AuthService` method, an
   `app.state` attribute, or which DTOs the console renders), update the corresponding list in
   `scripts/webconsole_seam_snapshot.py`.
5. Refresh the golden (write UTF-8, no BOM):

   ```bash
   python scripts/webconsole_seam_snapshot.py > tests/golden/webconsole_seam.snapshot
   ```

6. Confirm green: `python -m pytest tests/test_webconsole_seam_snapshot.py -q`.
7. At release, update the compat range on both sides (the engine `[webconsole]` extra and the package's
   `messagefoundry>=X,<Y` dep) — see the RELEASE checklist.

If you see the snapshot test fail **without** having intended a contract change, that is the gate doing
its job: an incompatible change leaked in. Fix the change or bump the seam deliberately — never refresh
the golden to silence it.

---

## 4. Developing and testing the package

The console is not standalone-buildable: it needs the engine present (it imports the engine's DTOs and
`parsing.tree.TreeNode`). Develop it editable, alongside the engine, in one venv:

```bash
# from the repo root, in the engine venv
pip install -e ".[dev]" -e packaging/messagefoundry-webconsole   # engine + console, editable

# the console's OWN suite (moved /ui tests live here, not in the engine's tests/)
python -m pytest packaging/messagefoundry-webconsole/tests -q
```

- The package's `[tool.pytest.ini_options]` sets `asyncio_mode = "auto"` (the relocated ASGI/security
  tests are bare `async def` with no marker — without this they would silently **not run**), plus the
  two session loop-scope keys matching the engine and a `--timeout` addopt so a hung ASGI test fails
  fast.
- The engine's own `pytest` no longer collects the `/ui` tests (engine `testpaths = ["tests"]`); CI runs
  the package suite as a second step on the same leg (`ci.yml`), so both suites exercise the same engine
  build. Only `ENGINE_UI_SEAM == 1` exists today; when a seam 2 lands, expand that step into a matrix
  that installs the MIN/MAX `SUPPORTED_ENGINE_SEAMS` engine builds and runs the package suite against
  each.
- Lint/type-check cover both trees:
  `ruff check messagefoundry messagefoundry_webconsole` and `mypy messagefoundry messagefoundry_webconsole`.
- The **package-absent** path (engine boots + refuses `serve_ui` cleanly with the console uninstalled) is
  exercised by [`tests/test_webconsole_absent.py`](../tests/test_webconsole_absent.py) without needing a
  second venv.

---

## 5. Honest scope — what this does and does not decouple

Option B decouples **development, test, and release**. It does **not** buy deploy independence.

**Genuine wins**

- The route paths and the WebAuthn ceremony JSON contract are now co-versioned with `app.js` (all in the
  package), resolving the previous latent JS-vs-endpoint split.
- The `/ui` CSP is co-versioned with the `app.js`/`app.css` it governs (via the `ui_csp` hook), so a
  client-asset CSP change ships package-only.
- Console-internal changes — presentation, client JS, `app.js` CSP tweaks, new routes that reuse
  already-injected handlers and already-rendered DTOs, new step-up actions over existing handlers — ship
  as a **package-only** release.

**Residual coupling (unchanged by the extraction)**

- **Deploy.** The package is co-installed in the engine's venv and mounted in-process, so shipping a new
  console build still requires an **engine process restart** to rebuild the app — no hot-reload, no
  separate process/origin. This is the accepted cost of keeping the same-origin security model.
- **New engine-data features.** A console change that needs a new engine handler, a new DTO field, or a
  new `/ws` push field still requires an engine edit **plus a seam bump plus a coordinated release**.
  Only changes expressible over the existing contract are package-only.
- **Hard cross-seam import.** `api.security`'s dep surface is imported directly (outside `UiDeps`), so a
  signature change there breaks the console outside the type-checked construction site — it is in the
  seam's compat scope and the snapshot gate.
- **Same-origin security is unchanged.** The `/ui`-confined `SameSite=Strict` session cookie, the
  `Origin`/`Sec-Fetch-Site` CSRF check on every `/ui` POST, the CSWSH `Origin == Host` WS check, step-up
  re-auth + `reauth_next` unlock mapping, and dual-control all moved **verbatim** and read
  `request(.websocket).app.state`, not `create_app` locals — see [SECURITY.md](SECURITY.md).

---

## Related

- [ADR 0065 — web ops dashboard](adr/0065-web-ops-dashboard.md)
- [`packaging/messagefoundry-webconsole/RELEASE.md`](../packaging/messagefoundry-webconsole/RELEASE.md) — the owner publish checklist
- [`packaging/messagefoundry-webconsole/CHANGELOG.md`](../packaging/messagefoundry-webconsole/CHANGELOG.md)
- [SECURITY.md](SECURITY.md) — the `/ui` same-origin security model
- [ARCHITECTURE.md](ARCHITECTURE.md), [MENTAL-MODEL.md](MENTAL-MODEL.md)
