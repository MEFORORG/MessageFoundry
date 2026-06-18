# ADR 0017 — Consumer deployment model: engine as a read-only installed dependency + org-owned config repo

- **Status:** **Accepted (2026-06-16) — the seven open decisions are ratified (see "Ratified decisions"
  below).** The two **Blocker** work-packages (free-form environment names + the posture-tier split) are
  authorized to build; the remaining backlog items follow per their severity. *(Build still waits on an
  explicit "go" per the working agreement — acceptance authorizes the work, it does not start it.)* This
  ADR defines how a *deploying organization* (referred to throughout as **"HealthCenter (HC)"**, a
  stand-in for any adopter) consumes MessageFoundry: the engine as a **read-only installed dependency it
  never edits**, and HC's Connections/Routers/Handlers as its **own, separately-versioned config repo**
  that drives **multiple deployed instances** (at minimum Test + Production; optionally POC, Staging, …).
- **Built:** Nothing in this ADR is built. It builds **on** mechanisms already shipped that must **not**
  be redesigned: the directory-level engine/config split via the loader
  ([config/wiring.py](../../messagefoundry/config/wiring.py) `load_config`, the `_SiblingHelperFinder`,
  and `codesets/` + `connections.toml` resolved relative to `--config`); the per-environment value layer
  (`env()`/`EnvRef` + `environments/<env>.toml` + `MEFOR_VALUE_*` overlay, fail-loud on a missing key —
  [config/environments.py](../../messagefoundry/config/environments.py),
  [config/wiring.py](../../messagefoundry/config/wiring.py) `resolve_env_settings`); the per-instance
  operator-settings layer ([config/settings.py](../../messagefoundry/config/settings.py) `load_settings`,
  precedence CLI > env > file > default, with `_warn_file_secrets`); the audited, RBAC-gated,
  reload-root-confined promote seam (`POST /config/reload` + `dry_run`,
  [api/app.py](../../messagefoundry/api/app.py), gated by `config:deploy` in
  [auth/permissions.py](../../messagefoundry/auth/permissions.py)); the IDE Stage→Promote / Set-Up-Version-
  Control flows ([ide/src/promote.ts](../../ide/src/promote.ts),
  [ide/src/sourceControl.ts](../../ide/src/sourceControl.ts)); and the **already-shipped release pipeline**
  (WS-F: dynamic version single-sourced from [messagefoundry/__init__.py](../../messagefoundry/__init__.py),
  currently `0.1.0`; [CHANGELOG.md](../../CHANGELOG.md); the signed
  [release.yml](../../.github/workflows/release.yml) building sdist + wheel + CycloneDX SBOM + Sigstore).
- **Supersedes (on acceptance):** the editable-install-of-the-engine-repo deployment model in
  [EARLY-ADOPTER-GUIDE.md](../EARLY-ADOPTER-GUIDE.md) §4 ("`pip install -e .`", "the running service loads
  whatever branch is checked out", "treat the deployed checkout as a release artifact") and the
  contributor-centric framing in [DEPLOYMENT.md](../DEPLOYMENT.md) — both reframed around a pinned-wheel
  engine + a separate org-owned config repo.
- **Related:** [ADR 0007](0007-gui-manageable-connections-toml.md) (connections-as-data, the
  analyst-editable transport layer), [ADR 0002](0002-phase2-transport-security-and-strong-auth.md)
  (off-loopback transport security per instance), [DUAL_LICENSING_PLAN.md](../DUAL_LICENSING_PLAN.md) (the
  AGPL §13 / commercial-edition lever this ADR's licensing question feeds),
  [CONFIGURATION.md](../CONFIGURATION.md) (the two configuration surfaces),
  [SERVICE.md](../SERVICE.md) (NSSM service deployment), and the `[ai].environment` /
  `AiEnvironment` coupling in [config/ai_policy.py](../../messagefoundry/config/ai_policy.py).

## Context

An adopter ("HC") downloads MessageFoundry from the public repo and runs it in-house. HC's integration
analysts must be able to **author and maintain their own configuration** — Connections, Routers, Handlers,
code sets, per-environment values — **without modifying (ideally without being able to modify) the engine
source**. HC also runs **more than one engine instance**: a Test instance and a Production instance at
minimum, and may stand up POC or Staging instances, **all driven from one config repo**.

The good news from the codebase: the engine/config separation HC needs **already exists as a directory
boundary**. `serve --config <dir>` loads an arbitrary external directory; config never lives inside the
installed `messagefoundry` package; the per-environment value layer and per-instance operator-settings
layer are both already separated from authored logic; and a promote seam, an RBAC role split, and a
released, signed wheel pipeline are all in place.

What is **missing** is (1) the boundary is enforced only by *convention* (the documented install is an
editable clone of the engine source, so the engine sits in HC's working tree inviting edits), and (2) one
hard constraint blocks the multi-instance requirement: **the active-environment name is locked to a
three-value enum** (`dev`/`staging`/`prod`), so HC cannot name a `poc`/`test` instance without editing
engine source. This ADR turns the convention boundary into a **packaging** boundary and lifts the
env-name constraint.

## Decision — the three-tier ownership model

| Tier | Owner | What it is | Where it lives |
| --- | --- | --- | --- |
| **Engine** | MEFOR maintainers | the `messagefoundry` package — **read-only, never edited by HC** | a pinned wheel in a venv / site-packages |
| **HC config repo** | HC analysts | the `--config` dir: Connection/Router/Handler `.py`, `_`-helpers, `codesets/`, `environments/<env>.toml`, `connections.toml`, fixtures | one org-owned, separately-versioned repo |
| **Per-instance operator settings** | HC ops | `messagefoundry.toml` + `MEFOR_*` env + secrets: store/db, `[api]` host/TLS, `[inbound].bind_host`, `[egress]` allow-list, the active-env selector | per deployed instance, **never** in the config repo |

### Recommended HC config-repo layout

```
hc-mefor-config/
  pyproject.toml            # pins messagefoundry==X.Y.Z  (engine = read-only dependency)
  config/                   # the --config dir
    IB_*.py  OB_*.py        # Connections; @router / @handler modules
    _helpers.py             # _-prefixed sibling helpers (loader skips; importable by siblings)
    codesets/*.csv          # resolved relative to --config
    connections.toml        # data-authored transport config (ADR 0007)
  environments/
    poc.toml staging.toml test.toml prod.toml   # per-env NON-SECRET values (env() keys)
  messages/sets/            # synthetic fixtures for dryrun / check
  instances/                # per-instance messagefoundry.toml templates (NO secrets)
  .github/workflows/check.yml   # CI: install pinned engine + `messagefoundry check`
  .gitignore .gitattributes     # excludes secrets + captured messages; LF for the hook
```

**Never in this repo:** secrets (injected per instance via `MEFOR_VALUE_*` / `MEFOR_*`), PHI / captured
messages, or engine source.

> **Path-root caveat (tracked as engine work below):** `codesets/` resolves under `--config`, but
> `environments/` and `messagefoundry.toml` resolve under the **process CWD**. Until the engine anchors
> all of them to one project root, the documented contract is: launch each instance with CWD = config-repo
> root and `--config ./config`.

### The analyst workflow

`scaffold → author → check → dryrun → CI → promote`, against existing tools:

- **author / validate:** the VS Code extension runs the CLI against the **open workspace folder** (not the
  engine repo), so pointing it at the HC config repo works today. `messagefoundry check --config config
  --messages messages/sets` is the single gate (validate + dryrun + advisory ruff/mypy), shared by the
  IDE and the pre-commit hook.
- **version control:** the IDE "Set Up Version Control & Checks" flow bootstraps git + `.gitignore` + the
  `check` pre-commit hook in any folder.
- **promote:** IDE Stage→Promote dry-runs `POST /config/reload?dry_run=true` against each target instance
  (resolving *that instance's* `env()` values, so a missing value fails before the swap), then applies an
  atomic quiesce-and-swap reload.

### Multi-environment & multi-instance topology

The value layer is **name-agnostic** (`load_environment_values()` and `current_environment()` accept any
string; `environments/<anyname>.toml` would resolve). The **only** thing blocking HC-named instances is
the **selector**: `[ai].environment` is typed to `AiEnvironment = {dev, staging, prod}`
([config/ai_policy.py](../../messagefoundry/config/ai_policy.py)) and `serve --env` is
`choices=("dev","staging","prod")` ([__main__.py](../../messagefoundry/__main__.py)). Two compounding
problems: the enum is **overloaded** (the same value also sets the AI data-scope ceiling *and* the
prod/staging PHI-encryption / open-egress / DEBUG-refusal guards), and `[ai].environment` **defaults to
PROD** — so a Test instance that forgets to set it silently runs as Prod and resolves Prod values/secrets.

**Promotion across POC → Staging → Test → Prod** is modeled as **the same repo commit deployed to every
instance, with the environment selected per instance at runtime.** (A remote promote sends
`config_dir: null`; the instance reloads its *own* on-disk dir, so the commit must already be delivered
there by CI/CD — the engine does not push artifacts.) **Isolation** comes from each instance's own
`<env>.toml` + `MEFOR_VALUE_*` + `[egress]` allow-list, with a missing `env()` value failing loud; the
recommendation is **deny-by-default egress for every non-dev instance** so a Test box structurally cannot
dial a Prod partner.

### The boundary and the AGPL posture

Enforce the read-only-engine boundary by **packaging**: ship the engine as a non-editable wheel in the
venv; the config repo is the only writable tree. Optionally ACL-lock the engine venv (service/admin-owned)
on Windows. RBAC already separates `config:deploy`/`config:validate` from `code:edit` from operations on a
running instance, but RBAC cannot govern on-disk source edits — packaging does.

AGPL-3.0-or-later: running the **unmodified** engine internally triggers no §13 source-offer to outside
parties; a **modified**, network-exposed engine does. Whether HC's own Routers/Handlers loaded via
`--config` are separate works vs. a derivative work is **legally undefined** and is a real adoption
question for an org wanting to keep its integration logic private — see
[DUAL_LICENSING_PLAN.md](../DUAL_LICENSING_PLAN.md).

### First instance of the pattern

The first HC-pattern config repo will be an **existing integration estate currently being migrated** into
MessageFoundry, whose config today lives as a gitignored folder inside the engine repo. Lifting it into a
separate private repo that depends on a pinned engine is the validating use case. During co-development an
editable engine install (`pip install -e ../MessageFoundry`) picks up engine changes live; production HC
installs use the pinned wheel. That migration already had to repurpose the built-in `staging` name to mean
`test`, which is the concrete proof that the env-name decoupling below is necessary.

## Engine work required (prioritized)

| Sev | Item | Files |
| --- | --- | --- |
| **Blocker** | Free-form environment names — decouple the active-env selector from `AiEnvironment`; drop `--env choices`; validate that `<name>.toml` exists | [config/ai_policy.py](../../messagefoundry/config/ai_policy.py), [config/settings.py](../../messagefoundry/config/settings.py), [__main__.py](../../messagefoundry/__main__.py) |
| **Blocker** | Explicit per-instance **posture / data-class** tier driving the PHI / egress / DEBUG / AI-scope guards (not the name); make the active env **required** (kill the silent PROD default) | [config/ai_policy.py](../../messagefoundry/config/ai_policy.py), [__main__.py](../../messagefoundry/__main__.py), [config/settings.py](../../messagefoundry/config/settings.py) |
| Major | Cut the `v0.1.0` tag + **publish the wheel to PyPI** (ratified) so adopters `pip install messagefoundry==X.Y.Z` *(pipeline already built — WS-F)* | owner action + [release.yml](../../.github/workflows/release.yml) |
| Major | Document the two-repo consumer model + wheel install; rewrite the early-adopter guide around it | [EARLY-ADOPTER-GUIDE.md](../EARLY-ADOPTER-GUIDE.md), [DEPLOYMENT.md](../DEPLOYMENT.md), README |
| Major | `messagefoundry init` scaffolder (+ ship templates in the wheel) | [__main__.py](../../messagefoundry/__main__.py), packaging |
| Major | CI-check template (install pinned engine + `check`) for the config repo | new template + docs |
| Major | Anchor `environments/` + `messagefoundry.toml` to a project root, not the CWD | [config/environments.py](../../messagefoundry/config/environments.py), [__main__.py](../../messagefoundry/__main__.py), [config/settings.py](../../messagefoundry/config/settings.py) |
| Minor | `py.typed` marker (PEP 561) so external mypy sees the surface | `messagefoundry/py.typed` + packaging |
| Minor | Publish a semver/stability policy + a `docs/AUTHORING.md` public-API reference; partition `__all__` stable-vs-incidental | docs |
| Minor | Cross-instance drift visibility — real build version + a config **fingerprint** (content hash / git commit of the loaded dir) on `/status`; promote provenance | [api/models.py](../../messagefoundry/api/models.py), [api/app.py](../../messagefoundry/api/app.py), [pipeline/cluster.py](../../messagefoundry/pipeline/cluster.py) |
| Minor | Per-instance "expected environment" assertion (refuse to start if selected env ≠ expected) | [config/settings.py](../../messagefoundry/config/settings.py), [__main__.py](../../messagefoundry/__main__.py) |
| Minor | Re-export `X12Peek`/`X12Message` (close the deep-import leak); per-profile pinned locks; a container image | [__init__.py](../../messagefoundry/__init__.py), packaging, Dockerfile |
| ✅ Resolved | `Sftp`/`Ftp` are already in top-level `__all__`; the release pipeline + versioning shipped (WS-F) — only the tag is uncut | — |

## Ratified decisions (2026-06-16)

1. **Distribution channel → public PyPI.** Publish the WS-F-built wheel to PyPI; adopters
   `pip install messagefoundry==X.Y.Z` (hash-pinnable). Wire a PyPI publish step into
   [release.yml](../../.github/workflows/release.yml) once the `v0.1.0` tag is cut. (The repo carries no
   customer data, so a public wheel is safe.)
2. **Environment naming → free-form, validated against `<name>.toml`.** Drop the `serve --env` `choices`
   restriction and the `AiEnvironment`-typed selector; any environment name is valid when its
   `<name>.toml` value file exists. The value loader and `current_environment()` are already
   name-agnostic — only the selector blocks custom names today.
3. **Posture model → explicit per-instance posture flag.** A `data_class` (`synthetic`|`phi`) and/or a
   `production` flag — decoupled from the environment name — drives the PHI-at-rest / open-egress /
   DEBUG-refusal / AI data-scope guards. A custom name maps to a posture deliberately; posture is never
   inferred from the name. Decisions 2 + 3 are one change set (the two Blocker rows).
4. **Promotion model → same-commit-everywhere.** One reviewed config commit is deployed to each instance;
   the environment is selected per instance at runtime. No per-env branches.
5. **Boundary enforcement → packaging-primary.** A non-editable wheel in the venv makes the engine
   read-only by construction; an optional Windows venv ACL-lock is documented as defense-in-depth. No
   bespoke enforcement mechanism.
6. **Licensing → "config is a separate work" + commercial edition.** Adopt a written position that
   Routers/Handlers loaded via `--config` are a separate work (not a derivative of the AGPL engine), and
   route orgs wanting to modify+redistribute the engine itself to the planned dual-license/commercial
   edition ([DUAL_LICENSING_PLAN.md](../DUAL_LICENSING_PLAN.md)). **Status 2026-06-17 (owner accepted-risk):**
   the legal review is **deferred to v0.2** — `v0.1.0` ships publicly on the drafted AGPL-3.0-or-later +
   `NOTICE`/`CLA`/`COMMERCIAL-LICENSE` posture **without** prior counsel sign-off (the original "pending legal
   review before the statement is published" stance is superseded; see backlog #13). Config-repo hosting is per-adopter.
7. **Container image → fast-follow.** An official image (byte-identical multi-instance rollout) lands
   after the env-name Blocker; not on the critical path for the model.
8. **Deployment trust boundary → inside the adopter's private healthcare network.** Every instance runs
   **within the organization's private, trusted network** (on-prem / private cloud) behind its perimeter
   controls (firewall / segmentation / VPN / NAC) — **never directly internet-facing**. The management
   plane is loopback-default; the data plane (inbound feeds) is network-bound with **TLS required**
   (fail-closed bind-guard, ADR 0002 §0); the deployment-conditional security controls (MFA, mTLS,
   certificate revocation, off-box logs) are **delegated to the org's environment** (IdP/AD, PKI, SIEM)
   and documented per instance. An inbound web-service *source* (a partner calling into MEFOR) is a
   distinct, **not-yet-built** surface with its own auth/TLS. Operator detail:
   [DEPLOYMENT.md](../DEPLOYMENT.md) "Trust boundary"; threat model: [PHI.md §1](../PHI.md).

## Consequences

- The engine becomes a true **read-only, version-pinned dependency**; HC's config is an independently
  versioned, CI-gated artifact. Engine upgrades are deliberate (`pip install messagefoundry==X.Y.Z` →
  `messagefoundry check` → promote), not "whatever branch is checked out".
- The **single highest-leverage change** is decoupling the environment name from `AiEnvironment` (the two
  Blocker rows): it directly unblocks HC-named Test/Prod/POC/Staging instances from one repo and retires
  the `staging`→`test` aliasing hack. It is **not** a one-line change because the enum is overloaded with
  the security-posture tier — both Blocker rows must land together.
- Most of the model already works; the remaining effort is **packaging, documentation, scaffolding, one
  env-name lift, and a few isolation/drift guards** — not a redesign of the config or value layers.
