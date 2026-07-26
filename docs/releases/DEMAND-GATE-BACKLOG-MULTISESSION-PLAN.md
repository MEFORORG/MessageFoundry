# DEMAND-GATE-BACKLOG — 32 demand-gated backlog items (multisession plan)

> **Provenance.** Produced 2026-07-17 by a multi-agent ultracode workflow (11 clusters grounded against the code, adversarially verified, synthesized → critiqued → finalized; 25 agents, 0 errors). All 32 items covered exactly once across 15 sessions.
>
> **Named, not numbered — deliberately.** `plan-13` is owned by branch `plan13-doc`; with ~10 live worktrees and no atomic allocator for plan *numbers*, this plan uses a name to avoid the numbering race.
>
> **Reconciliation with plan-11.** These 32 items were previously laned (mostly `○ Not started`) in [MULTISESSION-PLAN-11](MULTISESSION-PLAN-11.md); this plan re-scopes and **supersedes** those lanes for these items — see the [plan-11/README](plan-11/README.md) banner. Do not double-dispatch.
>
> **Per-session status lives in [demand-gate-backlog/](demand-gate-backlog/README.md).** Per-item build state stays authoritative in `docs/BACKLOG.md` (the `✅`/`⛔`/`🪦`/`🔢`/`🚧` banner).
>
> **Claim rule (mandatory, owner-set 2026-07-17 — [memory: claim-backlog-item-before-building]):** when a session STARTS an item, its first commit flips that item's `docs/BACKLOG.md` banner `🔢 → 🚧` (own commit, naming the lane/branch); the finishing PR flips `🚧 → ✅`. The `🚧` claim is the only signal that stops a parallel worktree double-building the item (no gate catches it).

---

# MessageFoundry — Final Multi-Session Build Plan (32 items, 11 clusters, 15 sessions)

## Overview & scope note

All 32 backlog items are **P3 demand-gate** work — build each only when its trigger fires (a customer feed, a procurement/compliance requirement, or explicit owner bandwidth), never on a schedule. Two items warrant a flag up front:

- **#95 Engine-brokered AI assistance (S10) is XL / speculative** — a new external LLM-egress surface. Build **only** on explicit customer/owner demand, ADR-first. The policy model, RBAC, and read endpoint already exist; this is the missing broker + audit + IDE switch.
- **#138 Operator-editable alert templates (S1a) is the primary PHI surface** of the alert cluster — it opens alert-email *content* to operator authoring and MUST enforce a **closed non-PHI variable allowlist** with reject-on-unknown at config-load.

Each session is one **git worktree + branch + PR**; commit one coherent layer at a time; **pushes/PRs/merges need owner approval**. Allocate ADR/BACKLOG numbers **atomically at the start of the owning session** via `pwsh -NoProfile -File scripts\coord\alloc.ps1 -Kind adr -Title "<title>"`, and add the index row in the **same commit** (ledger gate, `docs/LEDGER-GATE.md`) — **never grep for the next free number**.

## Session table

| Session | Items | Effort | Store? | Wave | Branch |
|---|---|---|---|---|---|
| S1a | 146, 138, 145, 144 | L | no | 2 | `claude/s1a-alert-notifier` |
| S1b | 143, 81 | XL | **yes** | 4 | `claude/s1b-alert-store` |
| S2 | 112, 128, 127 | L | no | 2 | `feat/s2-outbound-forward-proxy` |
| S3a | 114, 142 | L | **yes** | 3 | `claude/s3a-file-disposition` |
| S3b | 111 | L | no | 4 | `claude/s3b-file-alt-credential` |
| S4 | 172, 160 | L | no | 1 | `s4-compression-cron` |
| S5 | 117, 97 | M | no | 2 | `feat/s5-outbound-keepalive-nowait-ack` |
| S6 | 67, 69 | L | no | 1 | `s6-db-soap-breadth` |
| S7a | 121, 122 | L | no | 6 | `claude/s7a-log-maintenance-infra` |
| S7b | 171, 124 | M | no | 3 | `claude/s7b-logging-surfaces` |
| S8a | 76, 131, 136 | **XL** | no* | 6 | `claude/s8a-console-dashboard` |
| S8b | 125, 126, 151 | XL | **yes** | 5 | `claude/s8b-upload-search` |
| S9 | 84, 168 | L | no | 1 | `claude/s9-testbench-hex-and-collections` |
| S10 | 95 | XL | no | 5 | `feat/s10-ai-engine-broker` |
| S11 | 73 | S | no | 1 | `claude/backlog-73-fips-attestation` |

15 sessions from 11 clusters — S1, S3, S7, S8 each split along the additive-vs-stateful / notifier-vs-store fault line.
\* **S8a store fork:** the default TOML-managed-only scope keeps store_schema=false; the universal code-first-flag branch (a new 3-backend annotation table) flips it store-serialized (see *Store-serialization order*).

## Concurrency fixes applied (critic resolution)

The prior wave layout re-introduced same-file/same-store collisions the findings forbid. The 6-wave layout below eliminates every flagged conflict:

| Critic issue | Sev | Fix |
|---|---|---|
| Wave 4 = [S1b, S8b] ran two 3-backend store sessions concurrently | high | **S1b (wave 4) and S8b (wave 5) split into different waves; hard order S3a→S1b→S8b, one store session per wave.** |
| Wave 3 ran S3a + S3b (same `file.py`/`models.py`/`wiring.py` methods) concurrently | high | **S3a (wave 3) lands first; S3b (wave 4) rebases on it; credential context wraps S3a's disposition logic.** `file.py`/`remotefile.py` added to hotspot list. |
| `transports/mllp.py` contended by S5 + S8a in Wave 2 | med | **S5 (wave 2) and S8a (wave 6) separated;** mllp.py added to hotspot list; #117-no-ack × #136-waiting-state interaction decided (waiting state inapplicable when the ACK read is skipped). |
| #131/#136 depend on an unbuilt console→connections.toml write seam; conditional store not serialized | med | **S8a effort raised L→XL** (builds the first console write seam); default scope = TOML-managed only (store_schema=false); universal-flag branch flips S8a store-serialized. |
| `config/models.py` hotspot list incomplete (S2, S3a also edit it) | med | **All four touchers {S2, S3a, S3b, S8a} now sit in different waves;** hotspot list expanded. |
| S7a(#122) / S7b(#171) both edit `logging_setup.py`; intra_dep dropped | low | **S7b (wave 3) before S7a (wave 6); S7a deps=[171] restored;** logging_setup.py added to hotspot list. |
| #172 missing from the PHI census | low | **Added — census is now 14 items.** |
| #124 coupling to the search surface S8b reworks | low | **Flagged;** #124 scoped to basic search filters for MVP, sequenced before S8b's layered-search work. |

## Per-session detail

### S1a — Alert notifier (146 → 138 → 145 → 144) — wave 2
Build serially (heavy overlap in `config/settings.py`, `pipeline/alert_sinks.py`, `pipeline/alerts.py`, `config/alerts_edit.py`). **146** first establishes the `_RuleDecision → event` override plumbing #138/#144 reuse; **138** (PHI, allowlist-gated) next; **145** (new HA/DR events — thread `alert_sink` into `cluster.py` **and** `cluster_sqlserver.py` in lockstep, emit on `dr.py`'s existing sink) is orthogonal; **144** (control action) last — inject an async control callback (dispatched off-worker, never-raise), do **not** import `RegistryRunner`; ADR rationale cites the sink's decoupling + never-block emit contract. ADRs: amend 0014 (×2), new (138), new (144).

### S1b — Alert store (143 → 81) — wave 4, STORE-SERIALIZED (2nd slot)
Both ALTER `alert_instance` across all 3 backends (SQL Server via the **COL_LENGTH-gated** idempotent ADD-COLUMN DDL — there is no `_ADDITIVE_COLUMNS` symbol). Must land **after S3a, before S8b.** Suspend gates **notification only** (ADR 0044 AC-3), never hides the open condition. **#81** content-triggers stay match-only + PHI-free events off the hot path, and the ADR must reconcile Handler-emitted alerts with the transforms-must-be-pure at-least-once invariant; keep escalation occurrence/severity-driven (timed escalation is partly DECLINED, ADR 0014/#93). ADRs: amend 0044 (143), new (81).

### S2 — Outbound forward web proxy (112 → 128 → 127) — wave 2
Single tightly-coupled session — all three edit the same opener-construction sites. Build a **per-connection** proxied opener (never mutate the shared `_NO_REDIRECT_OPENER`); thread the ProxyHandler through every opener path **including the OAuth2 and SMART token-endpoint openers**. **#127 caveat**: stdlib `ProxyBasic/ProxyDigestAuthHandler` are reactive to a 407 and do **not** work for HTTPS destinations (the 407 is inside the CONNECT tunnel) — use pre-emptive tunnel-header Basic for https; Digest-over-CONNECT unsupported; NTLM deferred. Refuse a proxy credential over a cleartext-http proxy hop regardless of destination scheme. Register any proxy-credential key in `_SECRET_SETTING_KEYS` (`config/wiring.py:588`). `config/models.py` Destination edit is a hotspot (proxy fields) — disjoint from S3a/S3b/S8a, which are in other waves. ADR: new (112 covers cluster; 127 a section, 128 a paragraph).

### S3a — File disposition (114 → 142) — wave 3, STORE-SERIALIZED (1st slot)
First store slot; must land **before S1b and S8b** and **before S3b** (they share `file.py`/`remotefile.py`/`models.py`/`wiring.py` in the same methods). **#114**: place the probe at start/bind (`_start_inbound_unsafe`), **not** `build_check`. Note `_probe_dir_writable` mkdir's the dir first — for "missing dir fails startup," add a no-mkdir exists check. Fix the ADR-0031 amendment rationale (the "File connectors don't validate the dir" line is from BACKLOG #114, not the ADR). **#142**: new `processed_files` ledger, **HASH the filename key** (precedent stores hashes/ids only), record after emit success, file-as-dedup-unit, bounded prune. ADRs: amend 0031 (114), new (142).

### S3b — File alt Windows credential (111) — wave 4
**Serialize after S3a**: rebase on S3a's `file.py`/`models.py`/`wiring.py`, and make the credential context (`_run`/`_scan_once`/`_write`/`_probe_dir_writable`) **wrap** S3a's new disposition/validation logic. Win32-only runtime via `ctypes.windll` (WNetAddConnection2W / LogonUser) — cite **ADR 0113 + the tray package** (both present) and `service.py:124/270` as the no-pywin32 precedent. Password from env() only; release the mapping/token on stop/reload; validate on Windows CI legs. ADR: new (111).

### S4 — Compression + cron (172, 160) — wave 1, PARALLEL-SAFE
Disjoint files sharing only different `wiring.py` factories (File() vs Timer()). **#172** (now in the PHI census): pure `parsing/compression.py`; decompress must precede the AV scan + `_looks_like_hl7` sniff + batch split, and add a **decompressed-size ceiling** that also bounds post-split expansion (the `_oversize` check bounds only the compressed input); restrict the connector option to single-stream gzip. **#160**: prefer a stdlib DST-aware evaluator (croniter is a DEP-1 lock refresh); no t=0 fire, no busy-loop on a past next-fire. ADRs: new (172), amend 0011 (160).

### S5 — Keep-alive + no-wait ACK (117 → 97) — wave 2
**#117** first (S, MLLP-only) — reject no-ack + `capture_response` **after** the `reingress_to → capture_response` desugar; delivery-on-write = at-most-once-confirmation (document loudly, default stays ACK-waiting). **In no-ack mode there is no ACK read, so S8a's #136 waiting-for-reply window is inapplicable** — coordinate the shared `mllp.py` send-path edit across waves 2/6. **#97**: follow ADR 0067's **exactly-one reconnect-before-first-byte** model (not backlog #97's "reconnect-with-backoff"); add `aclose` overrides; X12 TA1 needs the leftover/desync guard; note the persistent=false bounded-close and TCP_NODELAY deltas in the amendment. ADRs: new (117), amend 0067 (97).

### S6 — DB & SOAP breadth (67, 69) — wave 1, PARALLEL-SAFE
**#67**: OUT/return capture must be a **same-cursor, pre-commit** read (never a post-commit SELECT); gate it with an explicit opt-in flag, not by loosening the `'output'` substring; record the proc-internal-transaction atomicity risk. **#69**: pure `parsing/xml/wsdl.py` on the already-locked `[xml]` extra (**avoid zeep**); keep remote schema fetch disabled **and** lock the distinct `wsdl:import` resolution path to no-network (a separate code path not auto-covered by the existing xmlschema config). ADRs: amend 0013 (67), new (69).

### S7a — Log-maintenance infra (121, 122) — wave 6
**S7b's `set_runtime_level` helper must land first** (shared `logging_setup.py`); S7a runs after S7b (wave 6 vs wave 3). **#121** (S, self-contained) — between-phase deadline; don't advance `_last_wal/_last_vacuum_day` for a skipped phase; add `max_pass_seconds` as its **own float validator**. **#122 is an architecture reversal** of the stdout-only/NSSM invariant → **owner sign-off**; the fail-closed stop is an injected non-async callback; a log-write failure is **process-wide** (decide blast radius — all connections or a process halt, not "the affected connection"). **Recommend shipping #121 alone and holding/deferring #122.** ADRs: light (121), new (122).

### S7b — Logging surfaces (171 → 124) — wave 3
**#171**: runtime level is **ephemeral, reset on process restart** (NOT on `/config/reload`); viewer degrades gracefully when `log_dir` is unset; it is a genuine new PHI read surface the light ADR must own. **#124** (largest PHI): stream bodies mirroring `/audit/export`, step-up + per-body audit + per-channel `_scope` + `enforce_phi_read_hop`; **loop `get_message` per id** (avoid a 3-backend bulk iterator). **Scope #124 to BASIC search filters for MVP** — it shares `search_messages` with S8b's layered-preset work (wave 5); sequence any export-from-preset after S8b. Both edit `api/app.py` + `app.js` → serialize within the session. ADRs: light (171), new (124).

### S8a — Console dashboard (76, 131, 136) — wave 6, effort XL
**Effort inflated L→XL:** #131/#136 require building the **first console→connections.toml write seam** — `connections_edit.py` is wired only into the CLI today (ADR 0007 Proposed/"Built: Not yet"). **Default scope: restrict #131/#136 to TOML-managed connections** (keeps store_schema=false). The universal code-first-flag branch needs a new name-keyed annotation table across all 3 backends → flips S8a store-serialized (after S8b). `waiting_display_delay` is a new **persisted** config field; #136 waiting-state renders only on ACK-waiting outbounds (inapplicable to S5's no-ack mode). **#76**: render the flow graph from **Registry edges only — no channel/route object** (CLAUDE.md §1); in-memory ring first (durable table would flip store-serialized); CSP `script-src 'self'` → inline SVG only. Shared `mllp.py` (with S5), `models.py` (with S2/S3a/S3b), `app.js` (with S7b/S8b) — all in different waves. ADRs: amend 0065 (76), amend 0007 (131), light under 0065 (136).

### S8b — Upload + search presets (125 → 126, 151) — wave 5, STORE-SERIALIZED (3rd slot)
Last store slot; must land **after S3a and S1b.** **#125**: new PHI-at-rest surface **outside** the encrypted store (filesystem preferred, encrypt/document the tier, step-up, audit); **`store.reingress` presupposes an origin store row an uploaded file lacks** — needs a distinct inject path. **NEW DEP python-multipart** (owner-approved + re-lock, or stdlib hand-parse). **#126** hard-depends on #125 (confirm + audit + path-traversal guard). **#151**: new per-user `search_presets` table (ADR 0045 migration precedent); encrypt or exclude PHI-shaped content criteria; layering = bounded AND-compose over `search_messages` (coupled with #124 — keep #124 basic-only). ADRs: new (125, +126 section), new (151).

### S9 — IDE Test Bench (84 → 168) — wave 1, PARALLEL-SAFE (ide/-only)
**#84 REFUTED decode design**: `dryrun --show-phi --json` UTF-8/replace-decodes bytes and never emits the `mfb64:v1:` marker → **scope to a UTF-8 byte hex dump** of `DryRunRow.raw` (real binary hex would need an engine/CLI change); the ADR note must not claim mfb64 whole-body decoding. **#168**: new PHI-at-rest surface → **machine-local extension storage only** (never a committable file, **not** `globalState` which can Settings-Sync off-machine); HL7-aware compare with a volatile-field ignore policy; **upgraded to a full ADR**. Both edit `testBench.ts` → sequential. ADRs: light (84), new (168).

### S10 — AI broker (95) — wave 5, XL / speculative / OWNER-GATED
Server-side is the **sole enforcement point** (re-resolve `resolve_effective_policy`, never trust the IDE scope); MVP context stays `code_only`; phi only under `managed_claude_baa` + BAA + ZDR. Per-use audit reuses the hash-chained `audit_log` (**no schema change**). **SSRF caveat**: `[egress].allowed_http` is permissive-when-empty — the broker must enforce endpoint membership itself + no-redirect opener. Broker client in `transports/` must not import `api/`. No new dep. Shares `api/app.py` (disjoint route) with S8b in wave 5. ADR: new (95).

### S11 — FIPS attestation (73) — wave 1, S / PARALLEL-SAFE
Report-only on the existing `GET /security/posture`; **do not touch** `APPROVED_KEX_GROUPS`/`validate_tls_ciphers`. Stdlib only; **no mypy `type:ignore`** needed (typeshed declares `get_fips_mode()->int`) — keep a runtime getattr-guard only for alt builds. **Over-claim gap**: `_hashlib`/`ssl` attest CPython's OpenSSL, **not** pyca `cryptography`'s separately-linked OpenSSL that encrypts PHI — scope the wording accordingly; say "reported," not "FIPS-140 certified." ADR: light (amend 0002 optional).

## Sequencing & parallelism map (6 waves)

Each wave is a set of sessions that can run concurrently in **separate worktrees** with no same-file or same-store collision. Waves run in order.

- **Wave 1 (high value, fully parallel):** S11, S6, S4, S9 — no store edits, disjoint files.
- **Wave 2:** S1a, S2, S5 — independent surfaces; S2/S5 share `wiring.py` (disjoint factories). **S8a moved out** (it collides with S2 on `models.py` Destination and with S5 on `mllp.py`).
- **Wave 3:** S3a (store slot 1), S7b — disjoint (S3a = transports/store, S7b = api/logging/console).
- **Wave 4:** S3b (rebases on S3a's file.py/models.py/wiring.py), S1b (store slot 2) — share `api/app.py` in disjoint routes only.
- **Wave 5:** S8b (store slot 3), S10 — share `api/app.py` in disjoint routes only.
- **Wave 6:** S8a (console dashboard), S7a (log-maintenance) — disjoint file sets; both close out coupled predecessors (S8a after S5/S2 for mllp/models; S7a after S7b for logging_setup).

**Never** run two store-editing sessions (S3a, S1b, S8b) concurrently — the wave layout guarantees one per wave, strictly ordered.

## Store-serialization order

1. **S3a** (wave 3) — new `processed_files` ledger (hashed filename key)
2. **S1b** (wave 4) — `alert_instance`: 143 suspend column, then 81 escalation state (serialize within the session)
3. **S8b** (wave 5) — new per-user `search_presets` table
4. **CONDITIONAL — S8a** — only if the owner chooses the universal code-first-connection flag (a new name-keyed annotation table); the default TOML-managed-only scope keeps S8a out of this order. If chosen, it slots **after S8b**.

`config/models.py` is an **additive-but-hotspot** file (S2, S3a, S3b, S8a — now all in different waves). 3-backend parity tests (ADR 0105) + schema-hash coordination (ADR 0111) are mandatory before each store session goes live (prod = SQL Server); coordinate the schema-hash bump explicitly between S1b and S8b.

## Cross-session hotspot files

- **`transports/file.py` + `transports/remotefile.py`** — S3a, S3b (serialize S3a first; S3b wraps S3a's logic).
- **`transports/mllp.py`** — S5, S8a (different waves; serialize if ever concurrent; #117 no-ack × #136 waiting-state decided inapplicable).
- **`config/models.py`** — S2, S3a, S3b, S8a (all different waves; additive/disjoint fields — confirm before any concurrent run).
- **`logging_setup.py`** — S7b (helper) before S7a (file handler).
- **`config/wiring.py`** — S2, S3a, S3b, S4, S5, S6, S8a (disjoint factory functions; trivial merges).
- **`api/app.py` + `api/models.py`** — S1a, S3b, S1b, S7b, S8a, S8b, S10, S11 (disjoint routes; serialize any two on the same route).
- **`messagefoundry_webconsole/static/app.js`** — S7b, S8a, S8b (all different waves).

## ADR ledger (deduped)

29 ADR actions across the sessions — see the `adr_ledger` field. Same-ADR touches: **0014** is amended twice in S1a (recipients; HA/DR events — the second retires 0014's "no protocol/engine change" self-scope). **0065** is touched twice in S8a (amend for charts/graph; light note for the waiting-state under it). Each number is allocated atomically at session start; the index row lands in the same commit.

## Cross-cutting risks
See the `cross_cutting_risks` field: store serialization (hard order S3a→S1b→S8b), the expanded hotspot-file list (file.py/remotefile.py/mllp.py/models.py/logging_setup.py added), the **14** PHI surfaces + guardrails, the invariant tripwires (#76 no-channel-object, #81 purity, #95 one-way deps, #117 confirmation contract, #117×#136 interaction, PHI-hop guards), the unbuilt console→connections.toml write seam under S8a (effort L→XL, store fork), the #124↔S8b search coupling, owner/demand gating, and the applied refuted-claim fixes.

## Next steps
1. Confirm which triggers have actually fired — these are demand-gated; do not build speculatively.
2. For any session taken up: create the worktree (`scripts/worktree/new.ps1 -Name <x>`), allocate ADR/BACKLOG numbers atomically, then build one layer per commit. Respect the wave order for any concurrent work.
3. Owner decisions needed before build: **#122** (architecture reversal — recommend deferring, ship #121 alone), **#95** (XL/speculative), **#125 python-multipart** dep vet, **#160 croniter** vs stdlib, and the **S8a universal-flag store fork** (TOML-managed-only default recommended).
4. Per-session verification bar (a task isn't done until these pass, in order): `ruff check` + `ruff format --check`, `mypy` (strict), `pytest` (`QT_QPA_PLATFORM=offscreen` for any Qt/harness tests), and `messagefoundry check`. New behavior gets a test. Validate service/store-parity changes on the Windows CI legs.
