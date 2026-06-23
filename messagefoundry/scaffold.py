# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Scaffold a standalone **config repo** for the ``messagefoundry init`` command.

A deploying organization keeps its *configuration* (Connections/Routers/Handlers, code sets, and
per-environment values) in its **own** repo, with the engine as a **read-only, version-pinned
dependency** it never edits (ADR 0017). This module lays down that repo's skeleton: a runnable starter
feed, ``environments/<env>.toml`` value stubs, a synthetic fixture, an instance ``messagefoundry.toml``,
a pinned ``requirements.txt``, a CI ``check`` workflow, ``.vscode`` settings the extension reads, and a
README — everything an analyst needs to author + validate + deploy config without touching engine source.

The templates are plain strings (they ship in the wheel as part of this module — no package-data
config). ``scaffold()`` writes them and never overwrites an existing file.
"""

from __future__ import annotations

from pathlib import Path

from messagefoundry import __version__

# A runnable starter feed: receive ADT over MLLP, archive admit/register/update events to a file. Uses
# literals (not env()) so `messagefoundry check` is green on the first commit; the docstring shows the
# env() upgrade. The router/handler defs carry `# type: ignore[no-untyped-def]` (the engine calls them
# with a Message; user config isn't type-checked against that signature).
_STARTER_FEED = '''\
"""Starter feed — receive ADT over MLLP, archive admit/register/update events to a file.

Replace this with your own Connections, Routers, and Handlers. The authoring surface is the top-level
``messagefoundry`` package (inbound / outbound / @router / @handler / Send / Message / MLLP / File /
env / code_set / current_environment / ...). See docs/CONNECTIONS.md in the engine.

Connection names follow ``[TYPE]_[PARTNER]_[MESSAGE]``: ``IB_EXAMPLE_ADT`` is an inbound MLLP listener;
``FILE-OUT_EXAMPLE_ADT`` is an outbound file writer.

Per-environment values: replace a literal like ``port=2575`` with ``port=env("example_adt_port")`` and
add ``example_adt_port = 2575`` to ``environments/<env>.toml`` (those value files resolve against the
project root — launch ``serve`` from the repo root, or pin it via ``serve --project-root`` /
``[environments].base_dir``; see the README). Secrets come from ``MEFOR_VALUE_<KEY>`` env vars, never
the value files.
"""

from messagefoundry import File, MLLP, Send, handler, inbound, outbound, router

inbound("IB_EXAMPLE_ADT", MLLP(port=2575), router="example_adt_router")
outbound("FILE-OUT_EXAMPLE_ADT", File(directory="./out/example", filename="{MSH-10}.hl7"))


@router("example_adt_router")
def route(msg):  # type: ignore[no-untyped-def]
    # The router sees EVERY received message and returns the handler(s) to run ([] = UNROUTED).
    if msg["MSH-9.1"] != "ADT":
        return []
    return ["example_adt_archive"]


@handler("example_adt_archive")
def archive(msg):  # type: ignore[no-untyped-def]
    # Filter -> (transform) -> Send. Only admit/register/update events are archived; others FILTERED.
    if msg["MSH-9.2"] not in ("A01", "A04", "A08"):
        return None
    return Send("FILE-OUT_EXAMPLE_ADT", msg)
'''

# A synthetic ADT^A01 (NO real PHI) that routes + archives, so `check`'s dryrun delivers one message.
# HL7 segments are CR-separated.
_FIXTURE_ADT = (
    "MSH|^~\\&|EXAMPLE|FAC|DEST|DEST|20260101120000||ADT^A01|MSG00001|P|2.5.1\r"
    "EVN|A01|20260101120000\r"
    "PID|1||100^^^HOSP^MR||DOE^JANE||19800101|F\r"
    "PV1|1|I|WARD^101^A\r"
)

_ENV_DEV = """\
# DEV environment values — resolved by env("key") in your config graph (see the engine's
# docs/CONFIGURATION.md). NON-SECRET values only, versioned here so they're diffable/reviewable.
# Secrets come from MEFOR_VALUE_<KEY> environment variables, never this file. Keys are lower_snake_case.
#
# Selected by [ai].environment = "dev" (or `serve --env dev`). The starter feed uses none; add keys as
# you switch literals to env(), e.g.:
# example_adt_port = 2575
"""

_ENV_PROD = """\
# PROD environment values — same shape as dev.toml, with this instance's real (non-secret) endpoints.
# Secrets come from MEFOR_VALUE_<KEY> environment variables, never this file.
#
# Selected by [ai].environment = "prod" (or `serve --env prod`).
# example_adt_port = 2575
"""

# Service settings for ONE instance. Copy per deployed instance (Test/Prod/...) and set its environment
# + posture + store + egress. Precedence: CLI > MEFOR_<SECTION>_<KEY> env > this file > default.
_SERVICE_TOML = """\
# MessageFoundry service settings for THIS instance. Keep one per deployed instance (dev/test/prod/...).
# Precedence: CLI flag > MEFOR_<SECTION>_<KEY> env > this file > built-in default. Secrets go in env
# (MEFOR_*), never here. See the engine's docs/CONFIGURATION.md.

[store]
# path = "messagefoundry.db"   # SQLite (default). Use a server DB for Test/Prod — see docs/DEPLOY-SERVER-DB.md.

[api]
host = "127.0.0.1"             # loopback only; an off-loopback bind requires TLS — see docs/DEPLOYMENT.md.
port = 8765

[ai]
# The active-environment NAME — REQUIRED (also passable as `serve --env <name>`). Free-form: name
# instances dev/staging/test/prod/poc/... Built-in names dev/staging/prod carry a default posture; a
# CUSTOM name MUST also set data_class + production below (posture is never inferred from the name).
environment = "dev"
# Security posture, decoupled from the name (ADR 0017). Derived for dev/staging/prod when omitted:
#   data_class = "phi"    # synthetic | phi — does this instance carry REAL PHI? (drives at-rest + egress advisories)
#   production = true     # production tier? (drives the prod-DEBUG refusal + the AI data-scope ceiling)

[environments]
# Where environments/<env>.toml value files resolve FROM. Default (unset) = the process working
# directory, so `serve` must be launched from the repo root. Set base_dir to this repo's ABSOLUTE root
# — or pass `serve --project-root <repo>` — so values resolve no matter the launch CWD (REQUIRED under a
# service like NSSM, where the working directory isn't the repo root). See docs/CONFIGURATION.md.
# base_dir = "C:/srv/mefor/this-config-repo"

[egress]
# Lock down outbound destinations on any PHI-carrying instance (recommended for Test/Prod):
# deny_by_default = true
# allowed_mllp = ["receiver.test.example:2601"]
"""

_VSCODE_SETTINGS = """\
{
  "messagefoundry.configDir": "config",
  "messagefoundry.messageSetsDir": "messages/sets"
}
"""

# CI gate: verify the pinned engine wheel's build provenance, then install it and run `messagefoundry
# check` (validate + dryrun + advisory lint) on every PR. `pip install -r requirements.txt` resolves the
# engine from your configured index — public PyPI (the published releases carry SLSA + PEP 740
# attestations), the engine's GitHub Release wheel, or a private index.
_CI_WORKFLOW = """\
name: check
on:
  pull_request:
  push:
    branches: [main]

jobs:
  # Supply-chain gate (MessageFoundry WP-BL3-07): verify the pinned engine wheel's SLSA build provenance
  # BEFORE installing it, so a registry/mirror substitution of the engine fails the build instead of
  # shipping silently. Fail-closed by default. If your package index strips attestations (some private
  # mirrors do), set the repository variable MEFOR_VERIFY_ENGINE=off to skip this job (see README).
  verify-engine:
    runs-on: ubuntu-latest
    if: ${{ vars.MEFOR_VERIFY_ENGINE != 'off' }}
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.11"
      - name: Download the pinned engine wheel (no install)
        run: |
          pip download -r requirements.txt --no-deps --only-binary=:all: -d dist-verify
      - name: Verify SLSA build provenance before install
        env:
          GH_TOKEN: ${{ github.token }}
        run: gh attestation verify dist-verify/messagefoundry-*.whl --repo wshallwshall/MessageFoundry

  check:
    needs: verify-engine
    # Run when verify passed OR was intentionally skipped (MEFOR_VERIFY_ENGINE=off); never when it failed
    # — a failed/cancelled verify-engine fails the gate (fail-closed). `always()` lets this evaluate even
    # though the dependency may have been skipped.
    if: ${{ always() && needs.verify-engine.result != 'failure' && needs.verify-engine.result != 'cancelled' }}
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.11"
      - name: Install the pinned MessageFoundry engine
        run: pip install -r requirements.txt
      # `check` runs validate + dryrun (the real gate). --no-lint skips the advisory ruff/mypy pass
      # (those tools aren't in requirements.txt); add them and drop --no-lint to lint your config too.
      - name: Validate config (validate + dryrun)
        run: messagefoundry check --config config --messages messages/sets --no-lint

  # Adopter-side "your pin is now vulnerable" tripwire (MessageFoundry dependency fast-response C3):
  # audit the pinned engine + its resolved dependency closure against published advisories, so a CVE
  # disclosed against the version you're pinned to turns YOUR CI red — your remediation clock starts
  # automatically, without waiting to read an advisory email. Remediate by bumping the engine pin in
  # requirements.txt to a release that fixed it; accept a triaged advisory with
  # `pip-audit --ignore-vuln <ID>` (record why, per your own change control).
  audit-pin:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.11"
      - name: Audit the pinned engine + deps against advisories
        run: |
          pip install pip-audit
          pip-audit -r requirements.txt --desc
"""

_GITIGNORE = """\
# MessageFoundry config repo — never commit local stores, secrets, captures, or build cruft.
*.db
*.db-shm
*.db-wal
*.log
# the one-time bootstrap admin credential the engine writes next to the store
bootstrap-admin.txt
.env
.env.*
/out/
captures/
__pycache__/
.venv/
.mypy_cache/
.ruff_cache/
.pytest_cache/
.DS_Store
Thumbs.db
"""

_GITATTRIBUTES = "# Keep the generated pre-commit hook LF so its shebang works on Windows.\n.mefor-hooks/** text eol=lf\n"

_README = """\
# MessageFoundry configuration

This repository is a **MessageFoundry config repo**: it holds *your* integration configuration
(Connections, Routers, Handlers, code sets, and per-environment values) and drives one or more engine
instances (e.g. Test, Production). The **engine is a read-only, version-pinned dependency** — you never
edit it here; you author config against its public surface (ADR 0017).

## Layout
- `config/` — the `--config` directory: your Connection/Router/Handler modules (and `codesets/`).
- `environments/<env>.toml` — NON-secret per-environment values for `env("key")` lookups (versioned).
  Secrets come from `MEFOR_VALUE_<KEY>` environment variables, never these files.
- `messages/sets/` — synthetic HL7 fixtures that gate `messagefoundry check` (no real PHI).
- `messagefoundry.toml` — this instance's service settings (active environment + posture, store, API, egress).
- `requirements.txt` — pins the engine version this config targets.
- `.github/workflows/check.yml` — CI: install the pinned engine + run `messagefoundry check` on every PR.

## Use it
```bash
# 1. Install the pinned engine into a venv (the engine is a read-only dependency):
python -m venv .venv && . .venv/bin/activate          # Windows: .\\.venv\\Scripts\\Activate.ps1
pip install -r requirements.txt

# 2. Validate your config (also runs in CI on every PR):
messagefoundry check --config config --messages messages/sets

# 3. Run an instance. environments/<env>.toml resolves against the project root — by default the
#    process working directory, so launch from the repo root:
messagefoundry serve --config config --env dev
#    Or pin the root explicitly (an ABSOLUTE path) so it resolves no matter the launch directory —
#    REQUIRED under a service like NSSM, where the CWD isn't the repo root:
# messagefoundry serve --config config --env dev --project-root /srv/mefor/this-config-repo
#    (Equivalently, set [environments].base_dir to that absolute path in messagefoundry.toml.)
```

> The engine version in `requirements.txt` is resolved from your configured package index — **PyPI**
> (`pip install messagefoundry==<version>`; the published releases carry SLSA + PEP 740 attestations),
> the engine's **GitHub Release wheel**, or a **private index**.

## Engine integrity (supply-chain gate)
`.github/workflows/check.yml` **verifies the pinned engine wheel's build provenance before installing it**
(`gh attestation verify` against the MessageFoundry release attestation), so a registry/mirror swap of the
engine fails CI instead of shipping silently — pinning a version proves *which bytes*, not *who built
them*. The gate is **fail-closed by default**. If your package index strips attestations (some private
mirrors do), set the repository variable **`MEFOR_VERIFY_ENGINE=off`** (Settings → Secrets and variables →
Actions → Variables) to skip it; the `check` job still runs. See the engine's INSTALL-GUIDE for the
matching manual verify-before-install recipe.

A second supply-chain job, **`audit-pin`**, runs `pip-audit` against your pinned engine and its
dependency closure, so a vulnerability **disclosed against the version you're pinned to** turns *your*
CI red automatically — your remediation clock starts without waiting to read an advisory. Remediate by
bumping the engine pin in `requirements.txt` to a release that fixed it (accept a triaged advisory with
`pip-audit --ignore-vuln <ID>`, recorded per your own change control).

## Environments & posture
The active environment is **required** and **free-form** — name instances `dev`/`staging`/`test`/`prod`/`poc`/…
Built-in names `dev`/`staging`/`prod` carry a default security posture; a **custom** name must set
`[ai].data_class` (`synthetic`|`phi`) and `[ai].production` in `messagefoundry.toml`. One reviewed config
commit is deployed to every instance; each instance picks its environment at runtime (`--env` or
`[ai].environment`), so a Test instance never resolves Prod values.

The selected `environments/<env>.toml` resolves against the **project root**: by default the process
working directory (launch from the repo root), or pin it with `serve --project-root <abs-path>` /
`[environments].base_dir` so it resolves regardless of the launch directory — required under a service
(e.g. NSSM) where the working directory isn't the repo root.

## Secrets
Never commit secrets. Per-environment endpoints (non-secret) live in `environments/<env>.toml`; secrets
(passwords, keys, WS-Security credentials) are injected per instance via `MEFOR_VALUE_*` (graph) and
`MEFOR_*` (service) environment variables.

---
Generated by `messagefoundry init`.
"""


def _templates(version: str) -> dict[str, str]:
    """The relative-path -> file-content map for a fresh config repo, pinning ``version``."""
    return {
        "README.md": _README,
        "requirements.txt": f"messagefoundry=={version}\n",
        ".gitignore": _GITIGNORE,
        ".gitattributes": _GITATTRIBUTES,
        ".vscode/settings.json": _VSCODE_SETTINGS,
        ".github/workflows/check.yml": _CI_WORKFLOW,
        "messagefoundry.toml": _SERVICE_TOML,
        "config/IB_EXAMPLE_ADT.py": _STARTER_FEED,
        "environments/dev.toml": _ENV_DEV,
        "environments/prod.toml": _ENV_PROD,
        "messages/sets/example_adt.hl7": _FIXTURE_ADT,
    }


def scaffold(target: str | Path, *, force: bool = False, version: str = __version__) -> list[Path]:
    """Write a starter config-repo skeleton into ``target``; return the files written (sorted).

    Refuses a **non-empty** ``target`` unless ``force`` is set. An existing file is **never**
    overwritten (even with ``force``) — ``force`` only permits scaffolding the missing files into a
    directory that already has content. ``version`` pins the engine in ``requirements.txt`` (defaults
    to the running engine's version).
    """
    root = Path(target)
    if root.exists() and root.is_dir() and any(root.iterdir()) and not force:
        raise FileExistsError(
            f"{root} is not empty — pass force=True to scaffold the missing files into it "
            "(existing files are left untouched)"
        )
    if root.exists() and not root.is_dir():
        raise NotADirectoryError(f"{root} exists and is not a directory")

    written: list[Path] = []
    for rel, content in _templates(version).items():
        path = root / rel
        if path.exists():
            continue  # never clobber an existing file
        path.parent.mkdir(parents=True, exist_ok=True)
        # newline="" writes the content verbatim — LF for text, the CR-separated HL7 fixture intact.
        path.write_text(content, encoding="utf-8", newline="")
        written.append(path)
    return sorted(written)
