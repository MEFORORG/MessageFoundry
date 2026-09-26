# AI coding assistance — policy & governance

MessageFoundry ships an **AI coding assistant** in the VS Code IDE, and a **centrally-governed,
environment-aware policy** that controls it across the full range from **OFF** to **PHI-safe**. The
policy is set by whoever *operates* the install (ops/admin), not by the individual developer, so a
central "off" — or a cap on what data the assistant may see — is honored on every workstation that
talks to the engine.

> **Carries PHI implications.** This document covers the *policy model and its enforcement*. What
> the assistant sends, and which part of that the engine enforces, is stated once, in
> [*The IDE decides what the assistant sends*](#the-ide-decides-what-the-assistant-sends-and-the-engine-checks-only-a-label)
> below; [PHI.md](PHI.md#ai-coding-assistance) links to it. The RBAC permission that gates the
> assistant is in [SECURITY.md](SECURITY.md).

> **Scope — product feature, not the dev process.** This governs the AI assistant the *shipped
> product* offers operators. The maintainers' *own* discipline for using Claude Code to **build**
> MessageFoundry — risk-tiered guardrails, the daily loop, provenance — is a **distinct,
> complementary** standard: [`Secure_AI_Development_Standards.md`](Secure_AI_Development_Standards.md).
> The two share the word "AI" and nothing else.

> **Status (MVP).** The policy model + config + RBAC + the engine policy endpoint + the CLI + gating
> of the existing **provider-agnostic, bring-your-own** IDE chat assistant are built. **One engine
> broker IS built:** `managed_endpoint` ([ADR 0135](adr/0135-engine-brokered-ai-assistance-customer-managed-llm-egress-with-per-use-audit.md))
> brokers a single prompt, labelled `code_only`, to a customer-managed / self-hosted LLM over `POST /ai/chat`,
> audited per use; it never reaches `phi` scope. `managed_claude` / `managed_claude_baa` are accepted
> as policy values but the IDE cannot service them, and the `deidentified` / `phi` scopes are not
> reachable in the MVP (see *Future direction*).

---

## The policy model — two axes under a production-posture ceiling

The policy is two independent axes, then **clamped** by the instance's **production posture**
(decoupled from the environment *name*, ADR 0017):

- **`mode`** — *what kind of AI*, on an OFF→PHI-safe spectrum:

  | `mode` | Meaning |
  |---|---|
  | `off` | No AI assistance at all. |
  | `byo` | **Bring-your-own** provider, configured in the IDE; the engine never sees the traffic. What the prompt holds is the IDE's own behaviour; the engine enforces nothing about it. |
  | `managed_endpoint` | **BUILT** ([ADR 0135](adr/0135-engine-brokered-ai-assistance-customer-managed-llm-egress-with-per-use-audit.md)) — the engine brokers one prompt, labelled `code_only`, to a **customer-managed / self-hosted** LLM over `POST /ai/chat`, audited per use, behind a fail-closed SSRF allowlist. Never reaches `phi` scope. |
  | `managed_claude` | Engine-brokered managed provider. **Future** — not serviceable by this IDE version. |
  | `managed_claude_baa` | Engine-brokered managed provider under a **BAA** + zero-data-retention connection — the only mode that can reach `phi` scope. **Future.** |

  > **Dev-process analogue (§4.5).** `managed_claude_baa` is the *product / runtime* path for PHI to reach an LLM under a BAA. Its **build-time** counterpart — when real PHI may enter the AI assistant used to *develop* MessageFoundry, under a signed **BAA + zero-data-retention** agreement (operator-enabled, minimum-necessary, audited) — is **§4.5** of [`Secure_AI_Development_Standards.md`](Secure_AI_Development_Standards.md). Same control (BAA + ZDR), different surface; both default to **no PHI**.

- **`data_scope`** — *the most sensitive data the assistant may be given*, least→most sensitive:

  | `data_scope` | Order | Meaning |
  |---|---|---|
  | `code_only` | 0 | Graph names + the active editor's code. **The only scope the MVP IDE ever claims.** It is a label on the request, not a check on its content. |
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
3. **`deidentified` hard rule** — `deidentified` always falls back to `code_only` today, because **no
   de-identification is wired into the AI-assist path**. (A de-id framework,
   [`messagefoundry/anon/`](../messagefoundry/anon/) / ADR 0030, exists to build PHI-free **test
   datasets**; it does not de-identify message bodies flowing to the assistant — see
   [PHI.md §9](PHI.md#9-de-identification).)
4. **`off` normalization** — when `mode == off`, `data_scope` is irrelevant and resolves to `code_only`.

**`mode` is never clamped by posture** — only `data_scope` is. Every clamp is recorded in a
human-readable `reason` so an operator can see *why* the effective policy differs from what was
configured. Representative results:

| Configured (`mode`, `data_scope`, `production`) | Effective `data_scope` | Why |
|---|---|---|
| `byo`, `code_only`, `true` | `code_only` | no clamp (this is the default) |
| `byo`, `phi`, `true` | `code_only` | production ceiling for non-BAA mode |
| `managed_claude_baa`, `phi`, `true` | `phi` | the full PHI-safe end — no clamp |
| `managed_claude_baa`, `deidentified`, `true` | `code_only` | no AI-path de-id wired |
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
| `mode` | enum | `byo` | `off` · `byo` · `managed_endpoint` (**built**, ADR 0135) · `managed_claude` · `managed_claude_baa` |
| `data_scope` | enum | `code_only` | `code_only` · `synthetic` · `deidentified` · `phi` |
| `environment` | str | — | free-form active-environment **name** (ADR 0017); selects `environments/<name>.toml` + `current_environment()`. **Required** for `serve` (no default). |
| `data_class` | enum | derived | `synthetic` · `phi` — does this instance carry real PHI (drives the at-rest/egress advisories). Derived from a built-in name (`dev`→synthetic, `staging`/`prod`→phi) when unset; **required** for a custom name. |
| `production` | bool | derived | production-tier posture (drives the AI ceiling + prod DEBUG refusal), decoupled from the name. Derived (`dev`/`staging`→false, `prod`→true) when unset; **required** for a custom name. |
| `provider` | str | `claude` | names the provider the broker addresses; recorded in the per-use audit. Does **not** select a request shape (the broker builds one wire shape unconditionally). **Validated at config load** — only a serviceable provider is accepted (BACKLOG #95) |
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
stdout); on error it prints `{"error": "..."}`.

It prints **no message data and no configured value**. That is narrower than the "config only, never
message data" this line used to say, and the difference is the point: no HL7 ever reaches this
subcommand, so the only thing its output could disclose was config, which that sentence said nothing
about. It did disclose config — `str(ValidationError)` carries `input_value=` for every failing
field, so a `[store]` missing `server` put `MEFOR_STORE_PASSWORD` on the stdout the IDE reads. The
error line is now rendered by `settings_error_detail` (field path and message, never the value);
that function's docstring carries the argument, and `tests/test_cli_ai_policy.py` pins it.

---

## IDE gating behavior

The IDE assistant ([ide/src/chat.ts](../ide/src/chat.ts)) resolves the policy **before** every
request: it first calls `GET /ai/policy` (authoritative, and cached on success); on any error it falls
back to that cached authoritative policy, then to the local `messagefoundry ai-policy` CLI; if none of
those can positively confirm a policy it uses a fail-closed built-in default (`mode: unverified`),
which **disables** assistance rather than re-enabling BYO — a central *off* must not be bypassable by
taking the engine offline (SEC-022).

Then it applies the effective policy:

| Effective state | Behavior |
|---|---|
| `mode == off` | **Disabled.** "AI assistance is turned off by your MessageFoundry policy." |
| `mode == managed_claude` / `managed_claude_baa` | **Disabled.** This IDE version can't service a managed provider; it does **not** silently fall back to BYO (that would violate operator intent). |
| `mode == byo` and `assist_permitted == false` | **Disabled.** "Your role does not include the `ai:assist` permission." |
| `mode == byo` and `assist_permitted` is `true` **or** `null` | **Enabled** — *unless* an authoritative `false` was previously observed; see the sticky-deny rule below. |
| `mode == unverified` (nothing could confirm a policy) | **Disabled.** Fail-closed; see above. |

**The `assist_permitted == null` trust note.** Under BYO, `null` (RBAC not evaluable) is **allowed**.
The reasoning: under BYO the prompt goes straight to the developer's own provider, and the engine is
not on that path, so engine RBAC could not protect it in any case. The IDE assembles no message data
on its own, but nothing checks what a person types or keeps in an open file; see
[*The IDE decides what the assistant sends*](#the-ide-decides-what-the-assistant-sends-and-the-engine-checks-only-a-label).
The central *off* switch is honored regardless, because `mode` is identity-independent and is read
straight from the policy, token or not.

**The IDE's gate read is authenticated (BACKLOG #330).** `assist_permitted` is computed from the
acting identity, so a tokenless caller can only ever be told `null` and the deny row above could never
fire. `resolveAiPolicy` therefore attaches the cached bearer — never prompting for one, and never over
plain `http://` to a non-loopback host. Two things this does **not** change: the engine endpoint stays
tokenless-*readable* (the `GET /ai/policy` section above is unchanged and still true), and the status
bar's **separate**, timer-driven read of the same route stays **tokenless** — it wants only the
identity-independent `environment`, and a bearer on that timer would keep refreshing the session's
idle clock and make the engine's 30-minute idle timeout unreachable (CWE-613).

**The sticky-deny rule (ADR 0035 AC-7).** Because `null` means "could not be evaluated" rather than
"permitted", a fresh `null` must not *upgrade* assistance a central policy switched off: an
authoritative `assist_permitted: false` the IDE has already observed is **retained** over a later
`null`, so under BYO that combination resolves to **Disabled**. The rule is deliberately one-way — a
cached `true` is *not* sticky, since fabricating a permit from stale state is the fail-open direction
— and any evaluable `true`/`false` replaces the cached value outright, so signing in is the escape
hatch. Anything that is not the literal `true`/`false`, **including a response that omits the field**,
counts as "not evaluated" and never as a permit.

`messagefoundry.showAiPolicy` (command **"MessageFoundry: Show AI Policy"**) displays the current
resolved policy in the IDE.

---

## The IDE decides what the assistant sends, and the engine checks only a label

In the MVP the IDE builds each prompt from these parts, several of them conditional:

1. A fixed primer describing MessageFoundry.
2. The graph's connection, router and handler names.
3. The text of the active editor, only when it is a Python file: the selection if there is one, else
   the whole file. The `messagefoundry.ai.contextCharLimit` VS Code setting caps it, **default 8000
   chars**. An oversized file is cut, on a line boundary where one exists, and marked. A limit of `0`
   sends no code at all.
4. A fixed task text, for the slash commands that carry one.
5. The request the user types.

The IDE attaches no message body on its own, and the scopes above `code_only` (`synthetic`,
`deidentified`, `phi`) are not wired into it. **That is how the IDE behaves, not an engine
guarantee.** Nothing inspects the text before it goes, so at least these would reach the model:

- a message body the user pastes into the chat request;
- a message body held in the open Python file, such as a fixture string in a test.

What the engine enforces depends on the mode:

| Mode | Who sends the prompt | What the engine checks |
|---|---|---|
| `byo` | the IDE, straight to the user's own provider | nothing: the engine is not on the path |
| `managed_endpoint` | the engine, on `POST /ai/chat` | the `ai:assist` permission; that the server-side policy is `managed_endpoint`; and that the request's `data_scope` **label** is `code_only`. An omitted label counts as `code_only`; another scope gets `403`. The prompt must be 1 to 200,000 characters. It never reads the prompt to check the label. It audits the prompt's length, never its text. |

So the `code_only` scope says what the IDE puts in a prompt. It does not stop a person from putting a
message body there. Keep real message bodies out of the chat and out of Python files open in the
editor.

---

## Future direction

- **Engine-brokered managed providers** (`managed_claude`, `managed_claude_baa`) are **P1/P2**. The
  engine — not the IDE — will broker the provider connection, so egress is centrally controlled and
  **per-use auditable**. `managed_claude_baa` over a **BAA + zero-data-retention** connection is the
  **only** path by which `phi` scope ever becomes reachable.
- **Runtime de-identification** (the `deidentified` scope) is **roadmap only** — the AI-assist path has
  no message de-identification wired in today, so the scope falls back to `code_only`. (A de-id
  framework, [`messagefoundry/anon/`](../messagefoundry/anon/) / ADR 0030, exists to build PHI-free
  **test datasets**; it does not de-identify message bodies for the live assistant.) See
  [PHI.md §9](PHI.md#9-de-identification).
- The `provider` / `model` / `baa_attested` / `endpoint` config keys are **accepted but unused**
  today; they exist so the broker can consume them without a config migration.
