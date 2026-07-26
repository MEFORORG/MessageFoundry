# DEMAND-GATE-BACKLOG · S2 · Outbound forward web proxy (REST/SOAP/FHIR/SMART/DICOMweb egress)

> **Phase document** — the maintainable source of truth for THIS session's status. Master index:
> [DEMAND-GATE-BACKLOG-MULTISESSION-PLAN](../DEMAND-GATE-BACKLOG-MULTISESSION-PLAN.md). Reconciles/supersedes the plan-11 lane(s) for these items.

| | |
|---|---|
| **Session** | `S2` |
| **Wave** | 2 |
| **Status** | **○ Not started** |
| **Effort** | L |
| **Backlog items** | #112 · #128 · #127 |
| **Build order** | #112 → #128 → #127 |
| **ADR(s)** | NEW — Outbound forward/egress web proxy for the stdlib HTTP family (Basic/Digest proxy-auth shipped, NTLM/Windows deferred; proxy-bypass section) |
| **Store schema / 3-backend** | No |
| **Parallel-safe** | No |
| **Branch** | `feat/s2-outbound-forward-proxy` |
| **Depends on** | 112 |

## Items

| Item | Title | Status |
|---|---|---|
| #112 | Outbound forward web-proxy address | ○ open |
| #128 | Bypass the forward proxy for local (intranet) requests | ○ open |
| #127 | Web-proxy credential types (Basic/Digest/NTLM/Windows) | ○ open |

## Owned files / seams

- `messagefoundry/transports/rest.py (per-connection _proxied_opener; thread ProxyHandler into every opener path — NEVER mutate shared _NO_REDIRECT_OPENER; reuse _redact_url)`
- `messagefoundry/transports/soap.py, fhir.py (+ FhirLookupExecutor openers), dicomweb.py`
- `messagefoundry/transports/http_auth.py (OAuth2 token opener + proxy_auth_handler_from_settings; _SECRET_SETTING_KEYS lives in config/wiring.py:588)`
- `messagefoundry/transports/smart.py (SmartBackendTokenProvider._opener must also proxy)`
- `messagefoundry/config/wiring.py (Rest/FHIR/Soap/DICOMweb factories + proxy kwargs + redaction key registration), config/settings.py (EgressSettings default proxy), config/models.py (Destination — HOTSPOT: adds proxy-cred fields; also touched by S3a/S3b/S8a — all in different waves)`

## Notes, PHI & gotchas

New network intermediary sees PHI request bodies (cleartext dest) or CONNECT host:port (https). Never log proxy URL/creds unredacted (reuse _redact_url). Proxy credential is a secret → env()/MEFOR_* only, added to _SECRET_SETTING_KEYS (wiring.py:588). A new guard must refuse a proxy credential over a cleartext-http proxy hop REGARDLESS of destination scheme. VERIFIER MATERIAL CAVEAT for #127: stdlib ProxyBasic/ProxyDigestAuthHandler are REACTIVE to a 407 on the request — they do NOT work for HTTPS destinations (the 407 arrives inside the CONNECT tunnel). For https destinations use pre-emptive tunnel-header Basic (http.client set_tunnel); Digest-over-CONNECT unsupported. NTLM/Windows deferred (urllib is connection-per-open; pyspnego present but insufficient). ADR must state whether the proxy host is in/out of the [egress].allowed_http gate scope. config/models.py Destination edit is disjoint (proxy fields) from S8a's waiting_display_delay and S3a's docstrings — different waves, but confirm additive-only before any concurrent run.

## Claim & Definition of Done

- **Claim first (mandatory):** in this worktree, `pwsh -NoProfile -File scripts\coord\alloc.ps1 -Kind adr -Title "<title>"`
  for each ADR, then **commit the `🚧` claim banner** on every item above in `docs/BACKLOG.md`
  (e.g. `> 🚧 **Status — in progress (lane \`dg-s2\`, branch \`feat/s2-outbound-forward-proxy\`).**`), in its OWN commit,
  BEFORE writing code. The finishing PR flips each `🚧 → ✅` with the PR ref.
- **Ratify the ADR before writing the code it governs.** Add the ADR index row (`docs/adr/README.md`) in the same commit as the ADR file.
- **Verification bar (in order):** `ruff check` + `ruff format --check` → `mypy` (strict) → `pytest`
  (`QT_QPA_PLATFORM=offscreen` for Qt/harness) → `messagefoundry check`. New behavior gets a test.
- **3-backend / store:** no store edits.
- Every PR: `git merge main` first; **no `Co-Authored-By: Claude` trailer** (CLA bot fails on it); carry `BACKLOG #N`.
  **Pushes / PRs / merges need owner approval.**

---
_Generated 2026-07-17 from the ultracode plan workflow. Master: [DEMAND-GATE-BACKLOG-MULTISESSION-PLAN](../DEMAND-GATE-BACKLOG-MULTISESSION-PLAN.md)._
