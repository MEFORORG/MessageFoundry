# AI coding assistance — policy & governance

MessageFoundry ships an **AI coding assistant** in the VS Code IDE, and a **centrally-governed,
environment-aware policy** that controls it across the full range from **OFF** to **PHI-safe**. The
policy is set by whoever *operates* the install (ops/admin), not by the individual developer, so a
central "off" — or a cap on what data the assistant may see — is honored on every workstation that
talks to the engine.

> **Carries PHI implications.** This document covers the *policy model and its enforcement*. The
> hard PHI guarantee (the MVP assistant only ever sends **code**, never message bodies) is restated
> in [PHI.md](PHI.md#ai-coding-assistance); the RBAC permission that gates it is in
> [SECURITY.md](SECURITY.md).

> **Scope — product feature, not the dev process.** This governs the AI assistant the *shipped
> product* offers operators. The maintainers' *own* discipline for using Claude Code to **build**
> MessageFoundry — risk-tiered guardrails, the daily loop, provenance — is a **distinct,
> complementary** standard: [`Secure_AI_Development_Standards.md`](Secure_AI_Development_Standards.md).
> The two share the word "AI" and nothing else.

> **Status (MVP).** The policy model + config + RBAC + the engine policy endpoint + the CLI + gating
> of the existing **provider-agnostic, bring-your-own** IDE chat assistant are built. **No
> model-provider or engine broker integration exists yet** — `managed_claude` / `managed_claude_baa`
> are accepted as policy values but the IDE cannot service them, and the `deidentified` / `phi`
> scopes are not reachable in the MVP (see *Future direction*).

---

## The policy model — two axes under a production-posture ceiling

The policy is two independent axes, then **clamped** by the instance's **production posture**
(decoupled from the environment *name*, ADR 0017):

- **`mode`** — *what kind of AI*, on an OFF→PHI-safe spectrum:

  | `mode` | Meaning |
  |---|---|
  | `off` | No AI assistance at all. |
  | `byo` | **Bring-your-own** provider, configured in the IDE; the engine never sees the traffic. Code-only by construction (PHI-safe). |
  | `managed_claude` | Engine-brokered managed provider. **Future** — not serviceable by this IDE version. |
  | `managed_claude_baa` | Engine-brokered managed provider under a **BAA** + zero-data-retention connection — the only mode that can reach `phi` scope. **Future.** |

  > **Dev-process analogue (§4.5).** `managed_claude_baa` is the *product / runtime* path for PHI to reach an LLM under a BAA. Its **build-time** counterpart — when real PHI may enter the AI assistant used to *develop* MessageFoundry, under a signed **BAA + zero-data-retention** agreement (operator-enabled, minimum-necessary, audited) — is **§4.5** of [`Secure_AI_Development_Standards.md`](Secure_AI_Development_Standards.md). Same control (BAA + ZDR), different surface; both default to **no PHI**.

- **`data_scope`** — *the most sensitive data the assistant may be given*, least→most sensitive:

  | `data_scope` | Order | Meaning |
  |---|---|---|
  | `code_only` | 0 | Graph names + the active editor's code. **The only scope the MVP ever sends.** |
  | `synthetic` | 1 | Plus synthetic (generated) HL7 — never real patient data. |
  | `deidentified` | 2 | De-identified message data. **Requires the (unbuilt) de-id framework** — never reached today. |
  | `phi` | 3 | Real message bodies / PHI. Reachable **only** under `managed_claude_baa`. |

- **`production`** — the instance's posture flag (a `bool`, **decoupled from the environment name**).
  Sets a **ceiling** on `data_scope` (never on `mode`):

  | `production` | `data_scope` ceiling |
  |---|---|
  | `false` (non-production) | `synthetic` |
  | `true` (production) | `phi` **if** `mode == managed_claude_baa`, else `code_only` |

  Posture is derived from the built-in environment names when unset (`dev`/`staging` → non-production,
  `prod` → production); a custom env name (e.g. `test`, `poc`) sets `[ai].production` (and
  `[ai].data_class`) explicitly. When the posture can't be resolved, the policy clamps to the
  **strictest** ceiling, so an un-tuned install never accidentally widens scope.

### Resolution (clamping)

`resolve_effective_policy(mode, data_scope, production)`
([config/ai_policy.py](../messagefoundry/config/ai_policy.py)) is a **pure** function that returns the
*effective* policy after applying, in order:

1. **Posture ceiling** — `data_scope` is lowered to the production-posture ceiling (above) if the
   request exceeds it.
2. **`phi` hard rule** — `phi` survives only under `managed_claude_baa`; otherwise it falls back to
   `code_only`.
3. **`deidentified` hard rule** — `deidentified` always falls back to `code_only` today, because the
   de-identification framework is **not built** (roadmap only — see [PHI.md §9](PHI.md#9-de-identification)).
4. **`off` normalization** — when `mode == off`, `data_scope` is irrelevant and resolves to `code_only`.

**`mode` is never clamped by posture** — only `data_scope` is. Every clamp is recorded in a
human-readable `reason` so an operator can see *why* the effective policy differs from what was
configured. Representative results:

| Configured (`mode`, `data_scope`, `production`) | Effective `data_scope` | Why |
|---|---|---|
| `byo`, `code_only`, `true` | `code_only` | no clamp (this is the default) |
| `byo`, `phi`, `true` | `code_only` | production ceiling for non-BAA mode |
| `managed_claude_baa`, `phi`, `true` | `phi` | the full PHI-safe end — no clamp |
| `managed_claude_baa`, `deidentified`, `true` | `code_only` | de-id framework unbuilt |
| `managed_claude_baa`, `synthetic`, `true` | `synthetic` | under both ceiling and the phi rule |
| `byo`, `phi`, `false` | `synthetic` | non-production ceiling |
| `byo`, `deidentified`, `false` | `synthetic` | ceiling reached before the de-id rule |
| `off`, `phi`, `true` | `code_only` | AI off → scope irrelevant |

---

## Configuration — the `[ai]` section

Set in `messagefoundry.toml`, with the usual `MEFOR_AI_*` env overrides
([CONFIGURATION.md](CONFIGURATION.md#ai)). Precedence stays **CLI > env > TOML > default**.

| Key | Type | Default | Notes |
|---|---|---|---|
| `mode` | enum | `byo` | `off` · `byo` · `managed_claude` · `managed_claude_baa` |
| `data_scope` | enum | `code_only` | `code_only` · `synthetic` · `deidentified` · `phi` |
| `environment` | str | — | free-form active-environment **name** (ADR 0017); selects `environments/<name>.toml` + `current_environment()`. **Required** for `serve` (no default). |
| `data_class` | enum | derived | `synthetic` · `phi` — does this instance carry real PHI (drives the at-rest/egress advisories). Derived from a built-in name (`dev`→synthetic, `staging`/`prod`→phi) when unset; **required** for a custom name. |
| `production` | bool | derived | production-tier posture (drives the AI ceiling + prod DEBUG refusal), decoupled from the name. Derived (`dev`/`staging`→false, `prod`→true) when unset; **required** for a custom name. |
| `provider` | str | `claude` | **forward-compat, unused in MVP** (P1 broker) |
| `model` | str | `claude-opus-4-8` | **forward-compat, unused in MVP** |
| `baa_attested` | bool | `false` | **forward-compat, unused in MVP** |
| `endpoint` | str | — | **forward-compat, unused in MVP** |

```toml
# messagefoundry.toml
[ai]
mode = "byo"
data_scope = "code_only"
environment = "prod"
```

Env keys follow `MEFOR_AI_<KEY>` — e.g. `MEFOR_AI_MODE`, `MEFOR_AI_DATA_SCOPE`,
`MEFOR_AI_ENVIRONMENT`.

---

## RBAC — `ai:assist`

A new permission **`ai:assist`** ([auth/permissions.py](../messagefoundry/auth/permissions.py))
governs whether an identity may use the assistant. It is granted to the **Coding** role (and to
**Administrator**, which holds every permission). Operator, Viewer, and the other roles do **not**
get it. See [SECURITY.md](SECURITY.md#roles--permissions).

---

## Reading the policy — endpoint, CLI, and the wire shape

Both surfaces emit the **same snake_case JSON** (single source of truth):

```json
{ "mode": "byo", "data_scope": "code_only", "environment": "prod", "assist_permitted": true, "reason": null }
```

`mode` / `data_scope` / `environment` are the **effective** (clamped) values. `reason` is the clamp
note (or `null`). `assist_permitted` is the identity-dependent bit:

| `assist_permitted` | Meaning |
|---|---|
| `true` | the caller holds `ai:assist` (or is the system identity). |
| `false` | the caller is authenticated but lacks `ai:assist`. |
| `null` | RBAC could not be evaluated — no/invalid token under enabled auth (offline CLI always returns `null`). |

### `GET /ai/policy`

Returns the effective policy ([api/app.py](../messagefoundry/api/app.py)). **It deliberately does
not require a permission**: the install policy (mode/scope/environment) is non-sensitive operational
config, and must be readable so a central *off* is honored even by a **tokenless** client. The
identity-dependent part is carried only in `assist_permitted` (`null` when RBAC can't be evaluated).
Policy reads are **not audited** in the MVP — per-*use* egress auditing arrives with the future
broker.

### `messagefoundry ai-policy`

The offline fallback ([__main__.py](../messagefoundry/__main__.py)): it loads
`messagefoundry.toml` from the working directory (or `--service-config <path>`), resolves the
effective policy, and prints the **same JSON** to stdout — except `assist_permitted` is **always
`null`** (RBAC is not evaluable offline). `--json` prints only the JSON object (the IDE parses
stdout); on error it prints `{"error": "..."}`. It prints **config only, never message data**.

---

## IDE gating behavior

The IDE assistant ([ide/src/chat.ts](../ide/src/chat.ts)) resolves the policy **before** every
request: it first calls `GET /ai/policy` (authoritative); on any error it falls back to the local
`messagefoundry ai-policy` CLI; if that also fails it uses a conservative built-in default
(`byo` / `code_only` / `prod`, `assist_permitted: null`) so the safe assistant still works offline.

Then it applies the effective policy:

| Effective state | Behavior |
|---|---|
| `mode == off` | **Disabled.** "AI assistance is turned off by your MessageFoundry policy." |
| `mode == managed_claude` / `managed_claude_baa` | **Disabled.** This IDE version can't service a managed provider; it does **not** silently fall back to BYO (that would violate operator intent). |
| `mode == byo` and `assist_permitted == false` | **Disabled.** "Your role does not include the `ai:assist` permission." |
| `mode == byo` and `assist_permitted` is `true` **or** `null` | **Enabled** (proceeds as today). |

**The tokenless-IDE / `assist_permitted == null` trust note.** Under BYO, `null` (RBAC not evaluable
offline) is **allowed**. This is safe by construction: BYO sends only **code-only** context to the
developer's own provider — it never sees the engine or any message data, so there is no PHI to
protect with RBAC at this stage. The central *off* switch is still honored because `mode` is read
straight from the policy, token or not.

`messagefoundry.showAiPolicy` (command **"MessageFoundry: Show AI Policy"**) displays the current
resolved policy in the IDE.

---

## PHI guarantee (MVP)

In the MVP the assistant **only ever attaches `code_only` context** — the graph's connection/router/
handler names and the active editor's code (capped at 8000 chars), nothing more. **No message
bodies, no patient data, are ever sent — regardless of mode or provider.** Scopes above `code_only`
(`synthetic`, `deidentified`, `phi`) are not wired into the IDE; the resolver caps them and the chat
path carries an explicit guard against attaching anything beyond code. See
[PHI.md](PHI.md#ai-coding-assistance).

---

## Future direction

- **Engine-brokered managed providers** (`managed_claude`, `managed_claude_baa`) are **P1/P2**. The
  engine — not the IDE — will broker the provider connection, so egress is centrally controlled and
  **per-use auditable**. `managed_claude_baa` over a **BAA + zero-data-retention** connection is the
  **only** path by which `phi` scope ever becomes reachable.
- **De-identification** (the `deidentified` scope) is **roadmap only** — there is no de-id framework
  in the repo today, and this MVP never claims one. It falls back to `code_only`. See
  [PHI.md §9](PHI.md#9-de-identification).
- The `provider` / `model` / `baa_attested` / `endpoint` config keys are **accepted but unused**
  today; they exist so the broker can consume them without a config migration.
