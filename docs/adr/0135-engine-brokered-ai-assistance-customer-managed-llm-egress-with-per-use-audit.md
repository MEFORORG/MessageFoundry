# 0135 — Engine-brokered AI assistance: customer-managed LLM egress with per-use audit

- **Status:** Accepted
- **Date:** 2026-07-18
- **Related:** [ADR 0024](0024-smart-backend-services-token-provider.md) · [ADR 0092](0092-posture-keyed-transport-hop-refusal-refuse-the-insecure-phi-hop.md) · [ADR 0126](0126-outbound-forward-egress-web-proxy-for-the-stdlib-http-family.md) · [`docs/AI.md`](../AI.md) · CLAUDE.md §2 (auth+RBAC, deny-by-default), §4 (one-way deps), §9 (PHI) · BACKLOG #95

---

## Context

BACKLOG #95 turns the **reserved-but-unused** `[ai]` broker keys (`provider`/`model`/`endpoint`,
`baa_attested`) into a real integration: let the **engine broker** the IDE assistant's model calls to a
provider the customer already runs — a managed cloud subscription or a **self-hosted / on-prem LLM**
endpoint — under central, **per-use-auditable** egress control. The policy model, RBAC, and `GET
/ai/policy` endpoint already exist ([`docs/AI.md`](../AI.md), [`config/ai_policy.py`](../../messagefoundry/config/ai_policy.py));
this builds the broker they were designed for.

This is a NEW external LLM-egress surface, so the CLAUDE.md invariants are load-bearing:

- §9 — *"The MVP assistant only ever sends **code** (`code_only`) — never message bodies; `phi` scope is
  future (engine broker over a BAA)."* and *"AI coding assistance is centrally governed by an
  environment-clamped policy … RBAC-gated by `ai:assist`."*
- §4 — *"Dependency direction is one-way: `pipeline/ transports/ parsing/ store/ config/` never import
  `api/`. The API depends on the engine."* — the new broker lives in `transports/` and **must not**
  import `api/`.
- §6 — *"asyncio core: never block the event loop"* — the provider HTTP call runs **off** the loop.
- §9 — *"Never log full message bodies … PHI-safe metadata only."* — prompt/response payloads and the
  provider API key are **never** logged or persisted.

Two ambient hazards constrain the design. First, the `[egress].allowed_http` allowlist is **opt-in,
permissive-when-empty** (unrestricted unless `deny_by_default = true`), so it cannot be the SSRF gate for
a brand-new egress surface. Second, the IDE is untrusted for policy: an IDE-supplied `mode`/`data_scope`
must never be able to widen what the server permits.

## Decision

Add an engine-brokered AI path — **the server is the SOLE enforcement point**, `code_only` in this MVP,
SSRF-gated by a dedicated fail-closed allowlist, per-use audited on the existing hash-chained
`audit_log`, with **no store-schema change and no new dependency**.

1. **`POST /ai/chat`** ([`api/app.py`](../../messagefoundry/api/app.py)) — a NEW authenticated,
   `AI_ASSIST`-gated route (deny-by-default RBAC via `require(Permission.AI_ASSIST)`, same session/CSRF
   posture as every other authenticated mutating route: bearer for the native IDE client, `SameSite`
   cookie for a browser). It **RE-RESOLVES** `resolve_effective_policy` **server-side** from the loaded
   `[ai]` settings and **ignores any IDE-supplied scope**; a request that claims a `data_scope` above what
   the server enforces is **denied (403)**. The engine broker MVP operates strictly at **`code_only`**.
   Every use writes a `record_audit("ai.assist", …)` row carrying **PHI-safe metadata only** — never the
   prompt, the response, or the key.

2. **`transports/ai_broker.py`** — a NEW stdlib HTTP client that mirrors `smart.py`'s structure and
   **reuses `rest.py`'s hardened, TLS-verifying `_NO_REDIRECT_OPENER` + `_redact_url`**. The provider POST
   runs **off the event loop** (`asyncio.to_thread`). It **MUST NOT import `api/`** (one-way deps). MVP is
   **non-streaming**. The Anthropic Messages wire shape is used when `provider = "claude"` (default), sent
   with the `x-api-key` credential header; the response text is extracted defensively and a provider
   refusal is surfaced as an error, never as content.

3. **SSRF — a dedicated fail-closed allowlist the broker enforces ITSELF.** A new `[ai].allowed_endpoints`
   list (`host` / `host:port`) is checked at broker construction: an endpoint whose host is not explicitly
   listed is **REFUSED** (empty list ⇒ nothing permitted). This is stricter than, and independent of, the
   permissive-when-empty `[egress].allowed_http`, so the engine can never be pointed at an un-allowlisted
   LLM host. Combined with the **no-redirect opener**, a crafted or redirected endpoint cannot exfiltrate
   the prompt.

4. **`config/ai_policy.py`** gains an optional `AiMode.MANAGED_ENDPOINT` (`"managed_endpoint"`) — the mode
   the engine broker serves. It is deliberately kept **OUT** of `resolve_effective_policy`'s phi-granting
   branch: only `MANAGED_CLAUDE_BAA` reaches `phi`, so a customer-managed / self-hosted endpoint being
   on-prem never by itself unlocks PHI.

5. **`config/settings.py`** — `AiSettings` gains `api_key` (the broker credential, **env-only** via
   `MEFOR_AI_API_KEY`) and `allowed_endpoints`. `("ai", "api_key")` joins `_FILE_SECRET_KEYS` so a
   file-supplied key warns, and `api_key` is already covered by `_SECRET_SETTING_KEYS` for redaction.

6. **Per-use audit reuses the existing `audit_log`** via `record_audit` — **NO schema change, NO bespoke
   `ai_egress` table** (this lane is `store_schema = false`). The `detail` records mode, resolved scope,
   provider, model, redacted endpoint host, and character counts — never payloads or keys.

7. **`ide/src/chat.ts`** — flip the `managed_endpoint` path to call the engine broker (`POST /ai/chat`)
   instead of the VS Code LM API, keeping the **`code_only`** context assembly unchanged.

**Must not break:** the code_only MVP boundary (never PHI); one-way deps (broker never imports `api/`);
router/transform purity (this is an API/IDE path, not a pipeline stage); the count-and-log invariant (no
message flows here); no store-schema drift.

## Acceptance Criteria

- **AC-1** — WHEN an authenticated `AI_ASSIST` caller POSTs to `/ai/chat` while `[ai].mode =
  managed_endpoint`, THE SYSTEM SHALL re-resolve the effective policy server-side and return the
  broker's reply.
  → `tests/test_ai_broker.py::test_ai_chat_managed_endpoint_returns_reply`
- **AC-2** — IF the request claims a `data_scope` above the server-resolved effective scope, THEN THE
  SYSTEM SHALL deny it (403) rather than honour the IDE-supplied scope.
  → `tests/test_ai_broker.py::test_ai_chat_ignores_ide_claimed_scope_and_denies_overclaim`
- **AC-3** — IF the configured AI endpoint host is not in `[ai].allowed_endpoints`, THEN THE SYSTEM SHALL
  refuse to construct the broker (SSRF fail-closed), including when the allowlist is empty.
  → `tests/test_ai_broker.py::test_broker_refuses_endpoint_not_in_allowlist`
- **AC-4** — THE SYSTEM SHALL send only `code_only` context and SHALL NOT include message bodies / PHI,
  regardless of mode.
  → `tests/test_ai_broker.py::test_ai_chat_is_code_only`
- **AC-5** — WHEN a broker call completes, THE SYSTEM SHALL write one `ai.assist` audit row to the
  existing `audit_log` whose `detail` contains no prompt, response, or provider key.
  → `tests/test_ai_broker.py::test_ai_chat_audit_records_only_phi_safe_metadata`
- **AC-6** — THE `managed_endpoint` mode SHALL NOT reach `phi` scope through
  `resolve_effective_policy` (it stays out of the BAA phi-granting branch).
  → `tests/test_ai_broker.py::test_managed_endpoint_never_grants_phi`
- **AC-7** — THE broker SHALL run its provider POST off the event loop through the no-redirect opener and
  SHALL NOT import `api/`.
  → `tests/test_ai_broker.py::test_broker_uses_no_redirect_opener_and_no_api_import`

## Options considered

1. **Server-brokered, code_only, dedicated fail-closed allowlist, existing audit chain, stdlib urllib —
   CHOSEN.** Honours the one-way deps, the code_only MVP boundary, the no-new-dep rule, and closes the
   permissive-when-empty egress hole without touching the store schema.
2. **Reuse `[egress].allowed_http` as the AI gate.** Rejected: it is permissive-when-empty, so an
   operator who never set it would leave the broker unrestricted — the exact SSRF fail-open the phase doc
   warns about. A dedicated fail-closed list is the safe default.
3. **Bundle a vendor LLM SDK (`anthropic`, …).** Rejected: a new dependency requiring a separate DEP-1
   vet; the stdlib `urllib` opener already carries the hardened, no-redirect, TLS-verifying plumbing.
4. **Add a bespoke `ai_egress` audit table.** Rejected: a store-schema change across three backends for
   data the hash-chained `audit_log` already models; the lane stays `store_schema = false`.
5. **Trust the IDE-supplied scope.** Rejected outright — the server must be the sole enforcement point.

## Consequences

**Positive** — Central, per-use-audited AI egress to a customer-managed / self-hosted LLM; the reserved
`[ai]` keys become real; no new dependency, no store-schema change; the SSRF surface is fail-closed and
independent of the permissive egress gate; the code_only boundary is preserved server-side.

**Negative / risks** — The broker sends opaque prompt text the server cannot semantically inspect for PHI;
the `code_only` guarantee therefore rests on the IDE assembling only code + graph names (unchanged
contract) plus the server's scope re-resolution and over-claim denial. Streaming is deferred, so a long
answer arrives in one response bounded by `max_tokens`.

**Out of scope** — `phi`/`deidentified` scope (still needs a BAA + runtime AI-path de-id); streaming;
`managed_claude`/`managed_claude_baa` engine-hosted paths (P1/P2, separate); any store-schema change.

## To resolve on acceptance

- [x] SSRF gate: dedicated `[ai].allowed_endpoints` (fail-closed) rather than reusing permissive
      `allowed_http`.
- [x] Audit reuses `audit_log` (`record_audit`) with PHI-safe `detail` — no schema change.
- [x] `managed_endpoint` kept out of the phi-granting branch.
