# Configuration UX — end-to-end surface review (research / findings)

**Date:** 2026-06-19 · **Status:** research / findings (no code) · **Owner action:** see *Candidate
follow-up items* + *Circulation* below.

This is BACKLOG **[#33](../BACKLOG.md)** — a **review/design** pass over *how* an operator or analyst
actually configures a MessageFoundry deployment, before the surfaces multiply further in v0.2+. It
**identifies and circulates** findings only; **no code or config is changed here**, and any *acted-on*
recommendation is recorded below as a **separate** backlog candidate with its real file contention
(per the #33 scope guard). An ADR is a possible *output* of those follow-ups, not a gate on this review.

**Time-box.** One focused day (2026-06-19). Grounded by reading the real symbols, then a multi-agent
adversarial verification pass (4 surface sweeps → 34 candidate findings → independent re-read of each;
**31 confirmed, 3 refuted**). Every claim below cites a `file:line`; line numbers are a 2026-06-19
snapshot and drift — re-confirm at action time.

---

## The surfaces, mapped

There is no single document that ties the configuration surfaces together; an operator assembles the
picture from `docs/CONFIGURATION.md`, three ADRs (0007/0017 + the value layer), and the code. The
surfaces, and the one fact that turns out to matter most — **what filesystem root each resolves
against**:

| Surface | File(s) | Format | Who edits | Resolves against (anchor) | Validation path |
|---|---|---|---|---|---|
| **Message graph** (Connections/Routers/Handlers, `_`-helpers) | `*.py` under `--config` | Python | analyst (code-first) | **`--config` dir** | `validate`/`check` (executes modules) |
| **Connections-as-data** (ADR 0007) | `connections.toml` in `--config` | TOML | analyst / VS Code GUI | **`--config` dir** | `Registry.validate` + `build_check` |
| **Code sets** (reference tables) | `codesets/*.csv|.toml` in `--config` | CSV/TOML | analyst | **`--config` dir** | fail-loud at load/reload |
| **Per-environment graph values** (`env()`) | `environments/<env>.toml` | TOML | analyst | **`[environments].base_dir`** (default `""`→**CWD**); `serve --project-root` | fail-loud at connector build |
| **Graph-value secrets** | `MEFOR_VALUE_<KEY>` env | env | ops | process env | overlays the file; env wins |
| **Service settings** (the catalog) | `messagefoundry.toml` | TOML | ops | **bare CWD** (`_DEFAULT_FILE`) or `--service-config` | pydantic at load |
| **Service-setting secrets/overrides** | `MEFOR_<SECTION>_<KEY>` env | env | ops | process env | pydantic; `_warn_file_secrets` |
| **Store DB** | `[store].path` | path | ops | **CWD** (or `serve --db`) | — |

Two clean design choices stand out and should be preserved: **logic is code-first, transport config may
be data** (ADR 0007), and the **two `MEFOR_*` env namespaces are cleanly separated** —
`MEFOR_VALUE_<KEY>` (graph values) is parsed only by `load_environment_values`, and the service-setting
parser rejects it because `value` is not a known section (`config/settings.py:1262`). *(We specifically
tested for a cross-namespace collision; there is none — see Investigated-but-not-a-defect.)*

---

## Bottom line

1. **The headline defect is the split anchor.** One logical config bundle resolves against **three
   different filesystem roots** (`--config`, CWD-for-`environments/`, bare-CWD-for-`messagefoundry.toml`/
   the DB). This is already named in [ADR 0017](../adr/0017-consumer-deployment-model.md) (the "Path-root
   caveat" + an open **Major** engine-work row) and is the root cause of the worst footgun: a `serve`
   launched from a non-repo CWD (**the NSSM case**) silently reads **no** `env()` values and creates the
   DB in the wrong place, with **no loud startup error**.
2. **The service-settings env layer has two real footguns**, both in `config/settings.py`: a
   **section-name-with-underscore** parse bug and **two model sections (`[pipeline]`, `[cert_monitor]`)
   that are simply unreachable via `MEFOR_*`**. This directly constrains the *shapes* downstream
   config-knob lanes may safely adopt (see *Circulation*).
3. **`connections.toml`'s "secrets via `env()` only" discipline is documented but not enforced** — an
   inline `bearer_token = "…"` loads, is only *redacted in the API view*, and is *used as-is* by the
   transport. Security-adjacent; feeds directly into the planned `[secrets]` work.
4. **Catalog drift is broad but low-severity**: one documented-but-unimplemented section (`[engine]`)
   and ~7 implemented-but-undocumented keys. Mostly docs-only fixes.

Nothing here is fixed in #33. The value of running it **first/early** is that its conventions
(§*Circulation*) should land before #34 and the secret-provider work freeze their `[section]`/key shapes.

---

## TOP finding — the split-anchor inconsistency

**Claim (confirmed).** A single config bundle has its members anchored to **three independent
filesystem roots**, and the two CWD-anchored members can be pushed to yet more roots by
`--service-config` / an absolute `base_dir`:

| Bundle member | Anchor | Symbol |
|---|---|---|
| graph `*.py`, `codesets/`, `connections.toml` | **`--config` dir** | `config/wiring.py:1835` (`directory / CODESETS_DIR_NAME`), `:1839` (`directory.glob("*.py")`), `:1850` (`directory / CONNECTIONS_FILE_NAME`) |
| `environments/<env>.toml` | **`[environments].base_dir`** (default `""`→ CWD), pinnable via `serve --project-root` | `config/environments.py:42-71` (`resolve_values_base_dir`); `__main__.py:404` |
| `messagefoundry.toml` | **bare CWD** (`_DEFAULT_FILE`) or `--service-config <path>` | `config/settings.py:91`, `:1298` |
| `[store].path` (the DB) | **CWD** (or `serve --db`) | `config/settings.py:150` |

**Why it bites — the NSSM silent miss (HIGH footgun).** Under NSSM (or any launcher whose working dir
is not the repo root), `[environments].base_dir` defaults to CWD (`config/environments.py:59`), so
`load_environment_values` reads a file that isn't there and **silently returns `{}`** (a missing file
"is **not** an error" — `config/environments.py:84-90`). Simultaneously `[store].path =
"messagefoundry.db"` resolves a DB under that same wrong CWD. The startup log prints the *computed*
`env()` path (`__main__.py:407-412`) but does **not** warn that it is unreachable. The empty-values miss
only becomes loud later, and only if a referenced `env()` key lacks a default (`config/wiring.py`
`resolve_env_settings`). [ADR 0017](../adr/0017-consumer-deployment-model.md):91-94 documents the exact
contract as a stop-gap: *"launch each instance with CWD = config-repo root and `--config ./config`."*

**Partial fix already shipped, gap remains.** `[environments].base_dir` + `serve --project-root` exist
(the value layer was anchored), but **`messagefoundry.toml`, `[store].path`, and `codesets/`/graph are
still not anchored to one project root**, and **`--project-root`/`--env`/`--service-config` are
`serve`-only** — `validate`/`graph`/`dryrun`/`check` cannot reproduce `serve`'s resolution
(`__main__.py:81-110`), so the commit-gate can validate a *different* environment view than the one that
runs. ADR 0017:161 already lists *"Anchor `environments/` + `messagefoundry.toml` to a project root, not
the CWD"* as open **Major** engine work (`config/environments.py`, `__main__.py`, `config/settings.py`).
This review corroborates and extends it (it must also cover `[store].path` and the offline subcommands)
→ candidate **A** below.

---

## Findings by axis

Severity is impact-on-an-operator. **[code]** = fixing it edits `config/`/`__main__.py` (so it becomes a
separate backlog item, not part of #33); **[docs]** = a docs-only fix.

### Footguns

| # | Sev | Finding | Evidence |
|---|---|---|---|
| F1 | **High** | **Section names with an underscore can't be set via env.** The env parser splits on the **first** `_`: `MEFOR_CERT_MONITOR_WARN_DAYS` → section `cert` (unknown) → silently dropped. Any future multi-word section (e.g. a dotted `[retention.connections.*]`) is unreachable via `MEFOR_*`. **[code]** | `config/settings.py:1261` (`.partition("_")`), `:1262` (`if section in _SECTIONS`) |
| F2 | **High** | **`connections.toml` inline secrets are accepted, not rejected.** `parse_env_setting` returns any scalar verbatim; the secret-key list is used only for *display* redaction; the transport uses the inline value directly. ADR 0007's "secrets via `env()` only" is unenforced. **[code]** | `config/connections_file.py:203`; `config/wiring.py:185-206`, `:509-532`; `transports/rest.py:197-199`; ADR 0007:109 |
| F3 | **High** | **NSSM / non-repo-CWD silent miss** (the TOP finding's failure mode): empty `env()` values + wrong DB path, no loud startup error. **[code]** | `config/environments.py:59,84-90`; `__main__.py:404,407-412`; `config/settings.py:150` |
| F4 | Low | **`Path('.')`/`os.getcwd()` inside a graph `.py` resolves to CWD**, not `--config` — `from . import _helpers` works (sibling finder), but `open(Path('.')/'x.csv')` breaks under NSSM. | `config/wiring.py:1763-1784` (sibling finder vs. CWD) |
| F5 | Low | **`env(cast=…)` typo fails late vs. `connections.toml` `cast="…"` fails at parse.** A code-first cast typo isn't caught until connector build; the TOML named-cast is validated immediately. Asymmetric feedback. | `config/wiring.py:154`, `:198-206`, `:440-443` |

### Consistency

| # | Sev | Finding | Evidence |
|---|---|---|---|
| C1 | **High** | **Three anchors for one bundle** (the TOP finding). **[code]** | see anchor table |
| C2 | Med | **Env list separators differ by section**: `[api]` lists split on **`os.pathsep`** (`;` on Windows); `[egress]`/`[alerts]` lists split on **`,`**. An operator using commas for `MEFOR_API_TRUSTED_PROXIES` on Windows silently gets one element. (A comment at `:999` even claims pathsep support the validator doesn't implement.) **[code]** | `config/settings.py:323` vs `:904` vs `:1030` |
| C3 | Med | **`serve`-only flags.** `--service-config` / `--env` / `--project-root` are on `serve` (+ some maintenance cmds) but **not** on `validate`/`graph`/`dryrun`/`check`, so the gate can't match `serve`'s egress/env resolution. **[code]** | `__main__.py:39-71` vs `:81-110`; `:561,580,670,1037` |
| C4 | Low | **Silent-empty vs. fail-loud is mixed.** A missing `codesets/` **or** `environments/` dir is silently empty, but a missing *referenced* `env()` key or code-set *name* fails loud. Internally defensible, but worth stating as one rule. | `config/code_sets.py:146-147`; `config/environments.py:84-90`; `config/wiring.py:451-460`; `config/code_sets.py:254-260` |

### Validation

| # | Sev | Finding | Evidence |
|---|---|---|---|
| V1 | Med | **`[pipeline]` and `[cert_monitor]` are model sections absent from `_SECTIONS`**, so their `MEFOR_*` env vars are silently dropped (compounds F1). 15 sections listed vs 17 model fields. **[code]** | `config/settings.py:73-89` vs `:1196-1215`; `:1261-1262` |
| V2 | Low | **`connections.toml` duplicate-name error omits the source files.** Duplicate-vs-code is correctly a hard `WiringError` (good), but the message doesn't name *which* file holds the clash, though `source_file` is tracked. **[code]** | `config/wiring.py:1326` (vs `source_file` at `:1261-1262`) |
| V3 | Low | **`[retention].audit_days` (and similar reserved/ignored keys) accept silently.** Setting `audit_days = 30` loads with no warning and is never honored ("keep-forever by design"); the *accepted-but-ignored* status lives only in prose, not a load-time notice. | `config/settings.py:570`; `docs/CONFIGURATION.md:12,386` |
| V4 | Low | **`_warn_file_secrets` coverage is a hand-maintained list.** Correct today (and `key_provider` is correctly *excluded* as a non-secret), but it's an allowlist that must be kept in lockstep as secret-bearing keys are added — a process risk, not a current bug. | `config/settings.py:96-103`, `:176-177` |

### Discoverability

| # | Sev | Finding | Evidence |
|---|---|---|---|
| D1 | Med | **`env()`'s `cast` and the code-first-vs-`connections.toml` cast asymmetry** (named casts only in data) is in ADR 0007 + a `parse_env_setting` docstring, but **not** in the `env()` docstring a code-first author reads, nor in the error message's rationale. **[code]** (docstring) | `config/wiring.py:154-168` (no `cast`), `:185-206`; ADR 0007:78-84 |
| D2 | Med | **`[reference]` settings are real but documented only as one inline bullet**, not a `###` section like every other catalog entry — easy to miss. **[docs]** | `config/settings.py:514-544`; `docs/CONFIGURATION.md:287` |
| D3 | Low | **No central env-var reference.** The `MEFOR_<SECTION>_<KEY>` pattern is documented and regular, but several keys list no explicit env name and a few aren't documented at all (see drift table); an operator infers or reads code. **[docs]** | `docs/CONFIGURATION.md:43`; e.g. `config/settings.py:170,270,644,684` |
| D4 | Low | **`[ai]` forward-compat keys (`provider`/`model`/`baa_attested`/`endpoint`) accept silently with zero discovery** that they're unused placeholders. Intentional (forward-looking files load), but `[ai].model = "…"` is a silent no-op. | `config/settings.py:809-815` |
| D5 | Low | **`codesets/` anchor under-explained.** The docstring says "next to the config bundle"/"relative to `--config`" without defining where `--config` sits relative to CWD/project-root. **[docs]** | `config/code_sets.py:8-9,20`; `__main__.py:38` |

### Documentation drift (`docs/CONFIGURATION.md` vs `config/settings.py`)

| # | Sev | Finding | Evidence |
|---|---|---|---|
| DD1 | **High** | **`[engine]` is documented (`data_dir`, `shutdown_timeout_seconds`) but has no model** — no `EngineSettings`, not in `_SECTIONS`, `grep` of `data_dir`/`shutdown_timeout` returns zero. `extra="ignore"` means a `[engine]` block is silently dropped. Worse, `data_dir` is described as the "base for relative paths" — i.e. the very anchor the bundle lacks — so an operator may set it expecting it to fix C1/F3, and it does nothing. **[docs]** (delete or implement → if implemented, that's candidate A territory) | `docs/CONFIGURATION.md:682-686`; `config/settings.py:73-89,1196-1215` |
| DD2 | Med | **`[security]` heading is a future-only placeholder** (only `encryption_at_rest`, "future") — reads like a config section but isn't one. **[docs]** | `docs/CONFIGURATION.md:691-695` |
| DD3 | Med | **Implemented-but-undocumented keys**: `[store].encryption_key_file`, `[auth].step_up_max_age_seconds`, `[auth].password_check_username`, `[auth].password_breach_corpus_file`, `[api].ws_allowed_origins`. **[docs]** | `config/settings.py:170,644,684,690,270` |
| DD4 | Low | **`[store].path` default drift**: docs say `./messagefoundry.db`, code is `messagefoundry.db` (equivalent, but literal differs — and the doc never states it's CWD-relative). **[docs]** | `docs/CONFIGURATION.md:55` vs `config/settings.py:150` |
| DD5 | Low | **`[service]` heading** correctly notes NSSM settings live in `scripts/service/`, but sitting in the catalog it can read as unimplemented. **[docs]** (by design) | `docs/CONFIGURATION.md:688-689` |

---

## Candidate follow-up items (separate backlog items — NOT done here)

Per the #33 scope guard, every *acted-on* fix is its own backlog item with real file contention. Ranked.
None is implemented in #33; this review only proposes them.

- **A — Anchor the whole bundle to one project root (Major; the TOP finding).** Resolve
  `messagefoundry.toml`, `[store].path`, and (re-confirm) `environments/` against a single
  project-root, and add `--project-root`/`--env`/`--service-config` to `validate`/`graph`/`dryrun`/`check`
  so the gate matches `serve`. Add a **loud startup warning** when CWD ≠ resolved root and a referenced
  file is absent. **Contention:** `config/environments.py`, `config/settings.py`, `messagefoundry/__main__.py`
  (the exact trio ADR 0017:161 already names). **An ADR is the likely output** (anchor precedence: does
  `--config` become the root? a new `--project-root` for everything? how do `--service-config`/`--db`
  interact?). Covers F3/C1/C3/DD1.
- **B — Make the env-settings parser total + section-complete (Med).** Add `[pipeline]`/`[cert_monitor]`
  to `_SECTIONS` and replace first-underscore `partition` with a known-section longest-prefix match (or
  a section allowlist that tolerates underscores), so multi-word/nested sections are reachable. **This is
  a prerequisite for any nested `[section]` config-knob lane** (see Circulation). **Contention:**
  `config/settings.py`. Covers F1/V1.
- **C — Enforce `connections.toml` secret discipline at load (Med; security-adjacent).** Reject a
  scalar in a known secret-bearing field with a `WiringError` naming the field + the `{ env = … }` fix,
  instead of only redacting it in the API view. **Contention:** `config/connections_file.py`,
  `config/wiring.py`. Pairs with the secret-provider work. Covers F2.
- **D — Unify env list separators (Low).** Pick one separator (or accept both) across `[api]`/`[egress]`/
  `[alerts]` list fields and fix the stale `:999` comment. **Contention:** `config/settings.py`. Covers C2.
- **E — Docs-only consolidation (Low; no code contention → could be a docs PR, not a contended lane).**
  Delete/clarify `[engine]`/`[security]`; document DD3's five keys; promote `[reference]` to a `###`
  section; note CWD-relativity of `[store].path`; add a one-line "where each file lives + what it anchors
  against" map to `docs/CONFIGURATION.md`. Covers D2/D3/D5/DD1-DD5. *(A guided/wizard editor — the #33
  brief's open question — is a larger, separate design; not recommended until A lands, since a wizard
  over a split anchor would bake the footgun into UI.)*

---

## Circulation — influence-sequencing (run #33 first)

#33 blocks nothing at the file level; the hazard is **rework if its conventions land late**. Two
consumers must hear them **before** they freeze their `[section]`/key shapes:

- **#34 — per-connection retention overlay (`[retention.connections.<name>]`).** Plan-3 §B/§F has #34
  adopting a **settings-overlay** (not a `ConnectionSpec` field). Two hard conventions from this review:
  1. **A dotted/nested section name is currently NOT reachable via `MEFOR_*`** (F1/V1): the env parser
     would read `MEFOR_RETENTION_CONNECTIONS_…` as section `retention`, key `connections_…` — it won't
     map to a nested table. So either #34's overlay must be **file-only by design** (state it), or
     candidate **B** must land first. Decide this *before* ADR 0027 fixes the shape.
  2. Inherit the **global-default + per-connection-override** precedent and the **silent-empty-vs-fail-loud**
     rule (C4) so a typo'd connection name fails loud, not silently keeps-forever.
- **Secret-provider `[secrets]` surface (Plan-3 "Then" / Lane Sec).** Before a `[secrets]` section is
  shaped, fold in: the **`connections.toml` inline-secret gap** (F2 / candidate C — enforce at load, not
  just redact), the **`_warn_file_secrets` allowlist process risk** (V4), and the **two clean `MEFOR_*`
  namespaces** (keep them separate; don't introduce a third secret prefix that the section parser would
  mis-split per F1).

---

## Investigated but **not** a defect

Recorded so they aren't re-raised:

- **No `MEFOR_*` namespace collision.** `MEFOR_VALUE_<KEY>` (graph) and `MEFOR_<SECTION>_<KEY>` (service)
  are cleanly separated — `value` is not a known section, so the service parser never consumes a graph
  value (`config/settings.py:1262`; `config/environments.py:37,110-114`).
- **`connections.toml` EnvRef syntax is shown in code** — the `{ env = "key", default = …, cast = "int" }`
  form is in `config/connections_file.py`'s module docstring (the *remaining* gap is only that it's
  absent from `parse_env_setting`'s docstring + error messages → folded into D1).
- **Server-DB `[store]` keys are implemented, not "accepted-but-ignored."** The catalog preamble's
  "some server-DB keys" wording overstates it; they validate fully under `StoreSettings`. The genuinely
  accepted-but-ignored case is `audit_days` (V3) and a couple of `[delivery]` "(planned)" keys.

---

## Verification snapshot (2026-06-19 — line numbers drift, re-confirm at action time)

Findings were produced by a 4-surface parallel sweep, then **each candidate was independently
re-read against its cited `file:line` by a separate verifier** (refute-by-default): 34 candidates → 31
confirmed, 3 refuted (the three above). Primary sources read: `config/settings.py`,
`config/environments.py`, `config/wiring.py`, `config/code_sets.py`, `config/connections_file.py`,
`messagefoundry/__main__.py`, `docs/CONFIGURATION.md`, and [ADR 0007](../adr/0007-gui-manageable-connections-toml.md)
/ [ADR 0017](../adr/0017-consumer-deployment-model.md). Treat `file:line` citations as a snapshot.
