[← Master Test Plan index](../MASTER-TEST-PLAN.md) · *Part II — Subsystem chapters*

---

## 9. Authentication, RBAC & Active Directory Integration

**ID prefix:** `AUTH` · **Surface:** engine (API + `auth/` core), web console (`/ui`), CLI (`verify`, `audit-verify`), infra (AD lab, CI legs)
· **Primary risk:** every path that touches a *real* directory — the `ldap3` bind, the SPNEGO acceptor, the OIDC relying party — is exercised only through a mock seam or `# pragma: no cover`, so AD login, Windows SSO and federated SSO can ship fully green and be broken, or silently permissive, in the field.

### 9.1 Scope & objectives

This chapter covers the whole authentication/authorization core and, specifically, the owner-named **"AD integration"** item:

- **Local authn** — argon2id passwords (`messagefoundry/auth/passwords.py`, pinned `time_cost=3 / memory_cost=65536 KiB / parallelism=4` at `:19-29`), the anti-enumeration equalizer and concurrency-capped hashing (`auth/service.py:101` `_ARGON2_MAX_CONCURRENCY`, `:279`, `:395`), password policy (`auth/policy.py`), lockout, sliding-window rate limiting (`auth/ratelimit.py`).
- **Active Directory** — LDAPS simple-bind and nested-group resolution (`auth/ldap.py:86-282`), Kerberos/SPNEGO for both the JSON `POST /auth/negotiate` leg and the browser `GET /ui/sso` RFC 4559 flow (`auth/ldap.py:285-364`, `messagefoundry_webconsole/routes/sso.py`), AD group → role and AD group → per-connection scope maps, domain-join dependency, keytab/SPN preflight and its legible degradation, referrals / multi-domain / nested groups, AD outage and slow-LDAP behaviour, disabled / locked / expired-password accounts, service-account rights, LDAPS posture and channel binding.
- **Federated SSO** — the OIDC authorization-code + PKCE relying party (ADR 0142, `auth/oidc/`, `auth/oidc_http.py`, `messagefoundry_webconsole/routes/oidc.py`).
- **RBAC** — the 27-entry `Permission` catalog and 6 fixed `Role`s (`auth/permissions.py`, counted from the AST: `Permission=27`, `Role=6`), ADR 0045 custom roles, and the per-connection authorization scope.
- **Sessions & re-proof** — opaque tokens, idle/absolute/cap/rotation/inventory, TOTP + recovery codes, WebAuthn passkeys, session-window and ADR 0077 action-bound step-up, the new-client-IP re-anchor, bootstrap admin.
- **Audit** — the hash-chained tamper-evident `audit_log`, the ADR 0150 client address as a conditional 7th chain element, and the off-box tee.
- **The AD lab environment** itself, without which none of the directory legs can be tested for real.

> **Vocabulary note that the chapter must not paper over.** The code, the JSON API and `docs/SECURITY.md` all still spell the **per-connection authorization scope** as `allowed_channels` / "channel scope" (`auth/identity.py:36`, `auth/service.py:2687 set_channel_scope`, `PUT /users/{id}/channel-scope`, `PUT /ad-group-scope-map`). That is a retired word for a live feature. This chapter says **per-connection scope** in prose and cites the literal identifiers where a tester must type them; renaming the identifiers is out of scope here.

> **Cross-document ID convention.** This plan owns its own `AUTH-nn` ID space, and the documents it
> cites use *colliding* IDs. Every reference to another document's ID therefore carries a prefix:
> **`FCP:`** for a `docs/testing/FEATURE-COVERAGE-PLAN.md` gap ID (`FCP:AUTHN-11`, `FCP:RBAC-7`) and
> **`W25:`** for a WIN2025 test/matrix ID (`W25:S1.AC-AD`, `W25:F1`). A bare `AUTH-nn` always means
> this chapter's own row. AD-lab **cell** ids (`L0`…`L18`) and BACKLOG numbers (`#98`) keep their
> native form — neither collides with this plan's ID space.

**Explicitly NOT in this chapter:**

| Out of scope | Owned by |
|---|---|
| The per-feature coverage audit of `FCP:AUTHN-1..22` and `FCP:RBAC-1..18` (which dimension is thin per feature) | `docs/testing/FEATURE-COVERAGE-PLAN.md` §13 `[AUTHN]` and §14 `[RBAC]` — cite, do not restate |
| On-box manual closure of real-domain login, TOTP enrollment, service-account ACLs and bootstrap-file handling under Windows Server 2025 / NSSM | `docs/testing/WIN2025-TEST-PLAN.md` `W25:S1.AC-AD`, `W25:S1.AC-MFA`, `W25:S1.AC-ACL`, Appendix E (`W25:M-BOOTSTRAP`, `W25:M-DESKTOP`) |
| The matrix-row → pytest-file mapping and its executable runner | `docs/testing/WIN2025-TEST-MATRIX.md` rows `W25:F1`–`W25:F8` and `harness/acceptance/matrix.py:370-426` |
| Order of play, per-item definition of done and the AWS-specific provisioning wrapper for the AD/federation lab window | `docs/releases/HANDOFF-AD-LAB-aws.md` (boxes A/B/C, cells L0→L18) and `docs/releases/plan-11/w19-ad-lab-integration-validation.md` |
| The PASS/FAIL/SKIP/MANUAL acceptance contract and section semantics | `docs/testing/VERIFY.md` (`verify --section host,store,smoke,manual,federation`) |
| Transport TLS posture, mTLS *handshake* mechanics, hop refusal | the transport-TLS chapter; `tests/test_api_tls.py`, `tests/test_tls_policy.py`. Only the mTLS **identity resolution** half (`api/security.py:280-477`) is in scope here |
| Store schema/staged-pipeline correctness | the store chapter |

**Objective.** Move the four directory-facing P0 exposures from "asserted against a mock" to "observed against a real domain controller, an AD FS farm and a real browser", and close the cross-backend and meta-guard holes that let a silent regression through CI.

**Objective's hard constraint — the AD lab has not been stood up, so the gate is split.** Nine of this chapter's eighteen P0 rows can only run against a real Domain Controller / AD FS farm, and **that rig does not exist yet**. Standing it up is the genuine blocker — *not* a missing document. The lab's authority document (`docs/security/AD-FEDERATION-LAB-RUNBOOK.md`, cells L0–L18) exists for the owner; the whole `docs/security/` tree is simply **withheld from the public repo** (`.gitignore:144`; `docs/BACKLOG.md:271` records it as "gitignored post-cutover", and `:6041` states outright that such absences are "a publishing boundary, not evidence of completion"), so it is not readable from this worktree. A single undifferentiated P0 set would nonetheless be **unsatisfiable today**, which makes the release gate meaningless rather than strict. §9.4 splits it into a **P0-automated** gate that blocks every release and a **P0 AD campaign gate** that blocks only a release claiming AD / Kerberos / federated-SSO support; §9.7 carries **standing the lab up** — plus the chapter author's read access to the withheld runbook — as the blocking environment-phase exit item.

### 9.2 Already covered — do not re-test

| Evidence | What it proves |
|---|---|
| `tests/test_auth_service.py` (29) | Login paths, AD role sync, lockout notification + security events, bootstrap-admin lifecycle |
| `tests/test_api_auth.py` (61, 1402 lines) | End-to-end API auth: login/logout/me, session routes, users CRUD, forced first-login rotation, caller-scoped PHI-free security-event feed, ADR-0150 client reaching the audit row (`:1361`) |
| `tests/test_auth_hardening.py` (24) | Unknown-user timing equalizer, lockout window reset, LDAPS posture / RFC 4515 escaping / disabled-account / local-account conflict, session reaper, bootstrap password written to file not log, WS audit, HTTP grant/deny precision helper |
| `tests/test_auth_core.py` (13) + `tests/test_auth_store.py` (7) | argon2 roundtrip + rejections, password-policy rules, token uniqueness and hash-only storability, auth store tables |
| `tests/test_auth_entry_hardening.py` (9) | Sliding-window limiter per-IP + global + monotonic clock; entry routes fail closed |
| `tests/test_auth_session_lifecycle.py` (9) | Idle/absolute expiry, backward-clock revoke, activity-only refresh, Kerberos reject audited, AD role change revokes other sessions |
| `tests/test_session_registry.py` (8), `tests/test_session_rotation_primitive.py` (7), `tests/_session_rotation_contract.py` | Session-registry semantics and the token-rotation primitive contract |
| `tests/test_step_up.py` (14) | Session-window step-up, AD live re-bind reauth, ADR 0077 action-bound single-use grants, no MFA/AD deadlock, opt-out fallback, login and `verify_mfa` never mint a grant |
| `tests/test_mfa.py` (10) + `tests/test_mfa_access_gate.py` (13) | TOTP lifecycle, MFA-failure lockout, the ASVS 6.3.3 access gate, the method-keyed exempt set *shape* (`:145`), federated-unverified session refused, no self-promotion by binding a factor |
| `tests/test_totp.py` (6), `tests/test_totp_window.py` (9), `tests/test_totp_clock.py` (4) | RFC 6238 vectors, the SEC-014 forward skew clamp (`totp_skew_steps=0`), single-use consumption |
| `tests/test_webauthn.py` (16), `tests/test_webauthn_store.py` (5), `tests/_soft_webauthn.py`, `tests/_webauthn_store_contract.py` | Real `py_webauthn` register/assert driven by a software authenticator, challenge cache TTL/caps, sign-count CAS clone detection, RP fail-closed, three-backend credential-store contract |
| `tests/test_custom_roles.py` (16) | ADR 0045 subset validation, escalation carve-out, built-ins immutable under custom CRUD, narrowing revokes sessions, three-backend `roles.permissions` migration parity |
| `tests/test_channel_rbac.py` (10) | Per-connection scope on list/detail/replay/purge/connection-control/graph-edges + the admin endpoint roundtrip — **SQLite only** (`:99`) |
| `tests/test_ad_group_scope.py` (5) | AD group → per-connection scope map roundtrip, case-insensitive match, `*` = all, admins untouched, no-match leaves scope alone — **SQLite only** |
| `tests/test_ad_session_reconcile.py` (22) | ADR 0079 mech 2: strike/revoke arithmetic, fail-open on outage, mass-revoke breaker abort + latch + clear, same-pass role demotion, bind budget, on-by-default, unsafe settings refused |
| `tests/test_ldap_timeouts.py` (8) | Every `ldap3` `Server`/`Connection` construction site carries a finite timeout — including a static AST walker with its own self-test (`:267`, `:301`) and validators rejecting unbounded values; a rejected password still unbinds |
| `tests/test_auth_oidc.py` (42), `tests/test_auth_oidc_service.py` (16), `tests/test_auth_oidc_http.py` (10) | ADR 0142: PKCE S256, flow-cache TTL/caps/per-IP, the whole claim ladder with closed-set reasons, JWKS floor + min-refetch, MFA-claim gate, service-level exchange/validate, the hardened pinned-IdP opener |
| `packaging/messagefoundry-webconsole/tests/test_webui.py` (SSO ≈`:3928-4120`, OIDC ≈`:5096-5360`, WebAuthn `:3434-3607`) | `/ui/sso` challenge + single-leg failure, one cookie session, `seed_reauth=False`, cross-site hygiene, token-leg-only rate limit, preflight degrade; `/ui/oidc` self-gating registration, flow-cookie binding, no IdP-text reflection, zero audit rows on rate limit, full round trip; browser WebAuthn enroll + step-up e2e |
| `tests/test_audit_integrity.py` (29) | Hash-chain integrity plus ADR 0150: absent client reproduces the frozen legacy digest (`:391`), client inside the payload, no crafted detail can forge the trailing element, migration over a pre-existing store, tamper detection |
| `tests/test_audit_offbox_tee.py` (11) | The tee emits the client address as a discrete indexable field, one PHI-redaction path, never a stale inherited address |
| `tests/test_postgres_store.py:766-770`, `:3827-3890` | On real PostgreSQL: `ad_group_role_map` **and** `ad_group_scope_map` lookups, lockout columns, ADR-0150 client column + migration + chain continuity |
| `tests/test_sqlserver_store.py:423-424`, `:3866-3925` | On real SQL Server: `ad_group_role_map` lookup, lockout columns, ADR-0150 client column + migration (**not** the scope map) |
| `tests/test_security_doc_drift.py` (~40) | The route-map meta-guard: every engine and `/ui` route appears in `docs/SECURITY.md` with its exact permission set **and** gate wrapper, both directions, with planted-mutation self-tests; permission catalogue == enum; role matrix == `BUILTIN_ROLE_PERMISSIONS`; ungated allow-lists pinned |
| `tests/test_security_doc_rate_limits.py`, `tests/test_docs_security_pathways.py` | Every rate-limit setting documented with its shipped default; `/auth/providers` reports what is CONFIGURED, not what is reachable |
| `tests/test_trust_anchors.py` (27) | SHA-256 anchor pin match/mismatch (refuses at both enforcement levels), `icacls` + POSIX writability detection, dormant when unconfigured, baseline/changed/pin-mismatch audit rows |
| `tests/test_bootstrap_admin_perms.py` (4), `tests/test_dr_rbac.py` (4), `tests/test_field_authz*.py` | Bootstrap file permissions / symlink refusal, `DR_OPERATE` gating, field-level PHI redaction + metadata drift guard |
| `tests/test_approvals.py` (9) | Dual-control maker-checker release for gated high-value actions (ASVS 2.3.5) |
| `tests/test_admin_new_ip.py` (11) | New-client-IP force-step-up, re-anchor on reauth and on `verify_mfa`, dedupe, loopback equivalence, never overrides RBAC, default-OFF no-op |
| `tests/test_verify_federation.py` (17) | Offline `verify --section federation`: pinned endpoints as MANUAL, secret resolution + TLS-context build PASS/FAIL, a captured `id_token` replayed through the real ladder with a verdict per rung |
| `.github/workflows/ci.yml` job `test` (ubuntu + windows-2022 + windows-2025, py3.14), steps "Tests (pytest)" `:217` and "Web console tests (pytest)" `:245`; install line `:159` includes the `webauthn` extra | The whole auth suite (~480 nodes) runs on every push/PR with real `py_webauthn`; `ldap3>=2.9` and `pyspnego>=0.10` are **base** deps (`pyproject.toml:61-62`), so no auth test is extra-skipped |
| `.github/workflows/ci.yml` jobs `sqlserver-store` `:483` / `postgres-store` `:732` | Auth-store tables (users, sessions, roles, `ad_group_*`, `webauthn_credentials`, `audit_log`) against real SQL Server 2025 + PostgreSQL containers |
| `docs/SECURITY.md` §§"Local vs Active Directory", "Federated sign-in", "Directory session reconciliation", "Business-logic limits" (`:1174-1600`) | The authoritative, drift-guarded prose spec, including the engine-shard limiter-multiplication statement at `:1538-1541` |

**Done — do not re-plan.** The *offline* halves of this area are genuinely finished and this chapter adds nothing to them: the TOTP algorithm and its skew clamp; the WebAuthn engine layer driven by the software authenticator; opaque-token minting and hash-only storage; session idle/absolute/cap/reaper arithmetic; the password policy and argon2 roundtrip; the ADR 0045 custom-role subset/escalation algebra; the ADR 0077 grant algebra on both the JSON API **and** `/ui` (`messagefoundry_webconsole/_auth.py:578-651` uses `require_ui_step_up_action` / `require_ui_reauth_only_action` — the `FCP:AUTHN-11` note that `/ui` is still on the legacy session window is **stale**); the ADR 0079 mech-2 reconciliation arithmetic; the ADR 0150 chain algebra on SQLite; the route-map / permission-catalogue / rate-limit doc-drift meta-guards; and dual-control approvals (`FCP:RBAC-17` "none / unbuilt" is **stale** — `tests/test_approvals.py` exists with 9 nodes).

### 9.3 Risk analysis

| Risk | Failure mode | Blast radius | Detected today? | Priority |
|---|---|---|---|---|
| The real-directory acceptor path is mock-seam only. The `ldap3` `LDAPException` arms (`auth/ldap.py:252`, `:274`) and every SPNEGO acceptor line (`:298`, `:306`, `:358`, `:363`) are `# pragma: no cover`. No CI leg, no self-hosted runner, no containerised LDAP exists in `.github/workflows/` | A change to the `ldap3` / `pyspnego` call shape, or a dependency bump, ships green while AD login and Windows SSO are broken — or silently permissive | Every enterprise deployment's primary authentication path | **No.** `HANDOFF-AD-LAB-aws.md` states it outright: "The entire AD acceptor path is mock-seam only" | **P0** |
| Suspected live SPN defect. Both acceptor sites pass the *whole* SPN to `pyspnego`'s `service=`: `spnego.server(service=settings.kerberos_spn)` at `auth/ldap.py:300` and `:360`, while `config/settings.py:1846` documents `kerberos_spn` as `HTTP/host.example.com` — so the acceptor principal reads `HTTP/host.example.com/<hostname>` | Kerberos SSO can never authenticate against a real KDC, yet `kerberos_acceptor_preflight` reports the acceptor healthy and `GET /auth/providers` advertises `kerberos=true` | Windows SSO estate-wide; a working-looking feature that always fails, every failure an audited generic reject | **No test can see it.** Both sites are `pragma: no cover` | **P0** |
| ADR 0142 has never met a real IdP. Status line: "Proposed — **code COMPLETE, awaiting lab validation**"; cells L6a, L9, L18 have not run; no AD-lab run record exists under `docs/testing/` | L18 is the real-IdP proof of the AC-11 username UPN-suffix binding — a review found the unchecked-suffix path was a **live** privilege-escalation route (a guest presenting `Administrator@attacker.example` resolving to the on-prem Domain Admin). L9 can invalidate the architecture: a passwordless/smartcard AD account cannot complete the password step-up, so every sensitive route permanently 403s | Federated sign-in as a whole; potentially a domain-admin takeover | **No** | **P0** |
| AD account states beyond `ACCOUNTDISABLE` are never consulted. `_find_user` (`auth/ldap.py:182-187`) rejects only `userAccountControl & 0x2`; `accountExpires`, `lockoutTime` and `UF_LOCKOUT` are not even requested in the attribute list (`:170-177`). `resolve_principal` (`:262`) — the password-free path used by Kerberos SSO, OIDC **and** the ADR-0079 reconciler, via `_probe_principal` at `service.py:1207` — therefore accepts them | An AD account that is expired or locked but not explicitly disabled keeps a live engine session (the reconciler probes it `PRESENT` every pass) and can federate in. Offboarding-by-expiry — the common HR pattern — does not propagate | Every offboarded-by-expiry operator retains console access | **No.** `tests/test_auth_hardening.py:415-455` pins the disabled bit only | **P0** |
| SQL Server never exercises the AD group → per-connection scope map (`tests/test_sqlserver_store.py:423-424` covers `ad_group_role_map` only); PostgreSQL has one line (`test_postgres_store.py:769-770`); the store-side `allowed_channels` message filter is SQLite-only (`tests/test_channel_rbac.py:99`) | A backend-specific bug returns an empty set; `_sync_ad_channel_scope` (`auth/service.py:1147-1148`) then leaves the scope untouched **by design** and the AD operator silently keeps the all-connections default | Cross-connection PHI exposure on both production backends | **No** | **P1** |
| No meta-guard that a request-scoped audit call threads `client=`. 66 `record_audit(` call sites in `messagefoundry/` (51 in `api/`); the chain hashes a missing client as the legacy 6-element payload (`tests/test_audit_integrity.py:391`), so an omission **verifies perfectly clean** | A new PHI-read or admin-write route that forgets `client=client_ip(request)` silently loses the ADR-0150 "from where" — the exact incident question the ADR was written to answer | Post-incident forensics on any new route | **No** | **P1** |
| Two **verified** NULL-client audit paths on the unauthenticated attack surface: `audit_kerberos_reject` and `audit_oidc_reject` funnel into `_directory_reject_audit(actor, mech, reason)` (`auth/service.py:1046-1053`) which never takes or passes a `client`, so every `/ui/sso` and `/ui/oidc` route-level reject row has `client = NULL`. Separately, `auth.ad_scope_resynced` (`:1157-1161`) omits `client` while its sibling `auth.ad_roles_resynced` (`:1085-1090`) passes it at `:1089` | A Kerberos/OIDC probing campaign produces audit rows with no source address at all — the one place an address is most needed | Directory-SSO abuse is un-attributable | **No** | **P1** |
| LDAP referral chasing is neither configured nor tested. Both `ldap3.Connection` constructions (`auth/ldap.py:150-157` service bind, `:236-242` password-verifying user bind) omit `auto_referrals`, so `ldap3`'s default chase is active. No setting, no doc row, no test, no `SECURITY.md` mention | In a multi-domain forest a referral steers the **password-verifying** bind to another server; a hostile or mis-set referral target receives the user's credential over a connection whose TLS posture was never re-evaluated | Credential disclosure to an attacker-chosen host | **No** | **P1** |
| Multi-domain / cross-forest AD is untested and partly unmodelled: `ad_domain` is a single scalar (`config/settings.py:1767`) used to build the UPN (`auth/ldap.py:162`), and nested-group resolution runs one `MATCHING_RULE_IN_CHAIN` search against one `ad_group_search_base` (`:205-211`). No cell in `HANDOFF-AD-LAB-aws.md` covers a second domain | A child-domain user resolves no groups, hence no roles — a locked-out operator, or on re-login a role delta that revokes their other sessions | Enterprise AD is rarely single-domain: a first-customer failure mode | **No** | **P1** |
| AD outage / slow-LDAP behaviour is proven only at the construction layer. `tests/test_ldap_timeouts.py` asserts finite timeouts exist; nothing measures the engine against a wedged DC. `auth/ldap.py`'s own module docstring (`:10-16`) records that the `asyncio.to_thread` dispatch carries **no** `asyncio.wait_for`, so the only bound is the pair of `ldap3` timeouts (10 s each) | A DC that accepts TCP but stalls pins default-executor threads and degrades the whole API — the operator blind spot during exactly the incident when the console is needed | Whole-API responsiveness during a DC incident | **No** | **P1** |
| Engine-shard multiplication of the in-process auth budgets is documented but unasserted. `docs/SECURITY.md:1538-1541` states N engine shards multiply the four sliding windows and the two pending-flow caches; nothing tests it, and nothing asserts that a step-up grant, a WebAuthn challenge or a reconcile strike minted on one API process **re-prompts** (never bypasses) on another | An engine-sharded fleet silently gives an attacker N× the per-IP login budget; a cross-process step-up-grant miss that failed OPEN would be a direct step-up bypass | Every multi-process deployment | **No** — the fail-safe direction is prose only | **P1** |
| WebAuthn is only ever driven by a software authenticator (`tests/_soft_webauthn.py`). No roaming FIDO2 key, no platform authenticator, no real browser ceremony, no Chrome+Firefox cross-check | User-verification behaviour, attestation formats, transport hints and the RP-id/`public_origin` binding back the phishing-resistant factor the off-loopback admin posture relies on (ADR 0068 amendment) | Admins stranded out of their own console | **No** | **P1** |
| Kerberos acceptor preflight is boot-once (`api/app.py:5577-5594`; ADR 0068 §9 open item). A DC blip at startup latches `kerberos_available=False` until restart; there is no re-probe | A transient DC outage during a scheduled restart silently disables Windows SSO estate-wide, with one WARNING line and a hidden login link | Whole SSO estate until someone restarts the service | Partially — the degrade path is asserted in `test_webui.py`; the **operator-visible consequence and absence of self-healing** are not | **P1** |
| Cross-backend depth on the audit chain and PHI census. ADR-0150's client column has PG + SS cells, but the interior-row **tamper walk** is absent on both — `test_sqlserver_store.py:3877` / `test_postgres_store.py:3838` only assert `verify_audit_chain()` returns ok. PHI-view census and off-box-tee redaction stay SQLite-first (`FCP:RBAC-7` / `FCP:RBAC-8`) | If `verify_audit_chain` fails to detect an edited interior row on SQL Server or PostgreSQL, the tamper-evidence compliance claim is void on both production backends | The whole audit/compliance story | **No** | **P1** |
| No browser-level test of any `/ui` auth surface. All coverage is ASGI-client: CSP, `__Host-` cookie attributes, `SameSite=Strict`, Sec-Fetch guards, the OIDC 200+meta-refresh landing and the RFC 4559 401 challenge are asserted as strings and headers, never as browser behaviour. No Playwright/Selenium anywhere in `.github/workflows/` | An RFC 4559 challenge a browser will not answer, a cookie a browser will not set, or a CSP that blocks the login form all pass every test while no operator can sign in | Total console lockout that CI cannot see | **No** | **P1** |
| Hand-maintained gate exemption sets have no derived drift guard: `_MUST_CHANGE_EXEMPT_PATHS` (`api/security.py:54`) and `_MFA_EXEMPT_ROUTES` (`:72`). `tests/test_mfa_access_gate.py:145` pins the method-keyed **shape**, explicitly not membership against the live route table | Adding a path, or renaming a route so an exemption silently widens (the `DELETE /me/mfa` vs `GET /me/mfa` trap the code comment itself calls out at `:58-61`), lets a half-authenticated session reach a sensitive route | Authenticated-but-unverified privilege escalation | Shape only | **P2** |
| AD group → **custom** role mapping is only indirect. `roles_for_ad_groups` can return a `custom:`-prefixed id and `_custom_permissions_for_ids` resolves it (`auth/service.py:1592`, used at `:1103`), but no test drives an AD login whose group maps to a custom role | Silent mis-resolution grants an AD operator nothing (lockout) or more than intended; the audit row records only the opaque role id, so the over-grant is illegible after the fact | Any org using custom roles with AD | **No** | **P2** |
| No mutation or diff-coverage signal over the auth suite. `docs/quality-gates/HANDOFF-mutation-coverage.md` is an explicit **DRAFT / ready-to-run**; `.github/workflows/quality-advisory.yml` ships only complexity + clone gates | ~480 auth assertions of unmeasured strength guard the security boundary; a weakened predicate (an `or` where an `and` belongs inside a gate) can survive the whole suite | Any auth gate | **No** | **P2** |
| AD service-account least-privilege and gMSA logon rights unproven. `#99(e)` is the only residual and is provisioning-gated (`docs/BACKLOG.md:177`, `:4172`); nothing tests or documents the minimum directory rights the bind account needs | Deployments over-privilege the bind account; a compromised engine host then holds a directory-**write** credential | Directory-wide, on host compromise | **No** | **P2** |
| Hardened-DC interop untested. A DC with `LdapEnforceChannelBinding` / LDAP signing required may refuse the simple binds `auth/ldap.py` issues; the engine passes no `channel_bindings` anywhere (#98 unbuilt, `auth/ldap.py:299-303`) | Every AD login becomes a generic `LdapError` with no engine-side classification distinguishing it from an outage — an unsupportable first-contact failure | Any customer on Microsoft's hardened LDAP defaults | **No** | **P2** |
| Reconciler default drift. `config/settings.py:1815` ships `ad_session_recheck_seconds = 300`, but `api/app.py:5620` comments "Default OFF (`ad_session_recheck_seconds = 0`)" and `auth/service.py:1189-1191` repeats the claim | An operator reading the code believes no directory traffic is generated; enabling `ad_enabled` silently starts a 300 s bind loop against their DC | Unexpected DC load; misjudged blast radius during an outage | **No** — the setting default is asserted, the two comments are not | **P2** |
| No validator floor on any limiter. `docs/SECURITY.md:1571-1575` records that none of the eleven `*_rate_limit_*` fields nor `lockout_threshold`/`lockout_minutes` carries a Pydantic validator, so `per_key=0` or `window_seconds=0` disables enforcement **while the limiter still reports enabled** | A typo or a copy-pasted profile silently removes brute-force protection with no startup complaint | Password spray against the whole user base | Documented, not asserted | **P2** |

### 9.4 Test matrix

**Row class (`Cls`).** **T** = *Test* — a falsifiable assertion with an observable pass criterion; **only T rows count toward the release gate**. **C** = *Characterisation* — produces a recorded measurement, finding or dated owner decision with no threshold yet; legitimate work, but it **cannot fail**, so it never gates a release, and it becomes a T row the day its threshold or decision is recorded. **A** = *Assurance* — an external engagement (penetration test, third-party review, DAST); blocking only for an off-loopback / production-exposure release, advisory otherwise, and excluded from the ordinary P0 count.

**This chapter has 65 rows: 59 T, 6 C, 0 A.** The six C rows are AUTH-10 (confirm-or-refute the SPN defect — both verdicts pass), AUTH-16 (the #98 EPA spike, which self-reports INCONCLUSIVE), AUTH-18 (L9, *designed* to fail), AUTH-33 (multi-domain: resolve, or characterise the limitation), AUTH-46 (Windows Hello — in scope or a recorded declination) and AUTH-62 (advisory mutation coverage, `--exit-zero` by construction). None of the six may be counted as gate evidence; each names the T row that actually gates its subject.

**The P0 set is split in two, because the AD lab has not been stood up.** 18 rows are P0 (16 T + the 2 C rows AUTH-10 and AUTH-18). They are **not one gate**:

| Gate | Rows | Blocks what |
|---|---|---|
| **P0-automated** — runnable in CI or on a dev PC | AUTH-01, 02, 03, 05 (the `directory-ldap` container leg, pending Q5), AUTH-09, 19 *(pytest seam half)*, 26, 27, 29, 65 | **Every release.** No release ships with one of these red. All are Cls `T`; nothing here needs a directory |
| **P0 AD campaign gate** — needs a real Domain Controller / AD FS farm | AUTH-08, 10 *(C)*, 11, 12, 17, 18 *(C)*, 19 *(lab half)*, 20, 28 | **Only a release that claims AD / Kerberos / federated-SSO support.** A loopback-only, local-authn-only release is **not** gated on these — but it must then ship with `ad_enabled`, `kerberos_enabled` and `oidc_enabled` documented as **unvalidated against a real directory**, and `GET /auth/providers` must not advertise them as proven |

Nine of the eighteen P0 rows sit behind the AD campaign gate, and that gate is **unsatisfiable today** for one reason only: **the lab has not been stood up**. Its authority document is not the obstacle — `docs/security/AD-FEDERATION-LAB-RUNBOOK.md` exists for the owner and is merely withheld from the public repo (`.gitignore:144`), so its cell numbers remain sound evidence to cite. §9.7 carries provisioning the rig, plus read access to that runbook, as the blocking environment-phase exit item. Wiring those nine into the ordinary release gate would block every release on infrastructure the project does not own, so the split is a correctness fix, not a relaxation.

| ID | Test | Type | Method | Env | Backend | Cls | Pri | Pass criteria |
|---|---|---|---|---|---|---|---|---|
| AUTH-01 | `LdapAuthenticator.authenticate` against a **live** directory: service bind → `_find_user` → password-verifying user bind → `AdPrincipal` | Functional | pytest (opt-in `directory` marker) | container-CI | n/a | T | P0 | A real `ldap3` round trip returns `AdPrincipal(username=…, dn=…, groups=…)` with `groups` lower-cased and containing both the group DN and its `sAMAccountName`; coverage of `auth/ldap.py:219-260` shows no line skipped by `pragma: no cover` in this run |
| AUTH-02 | Nested-group resolution against a live directory via `LDAP_MATCHING_RULE_IN_CHAIN` (`1.2.840.113556.1.4.1941`) | Functional | pytest | container-CI | n/a | T | P0 | With `ad_use_nested_groups=true` and a user in `mefor-ops` nested inside `mefor-admins`, the returned `groups` frozenset contains **both** groups' DN and `sAMAccountName`; with the flag off it contains only the direct `memberOf` entries |
| AUTH-03 | Rejected credential and unknown user against a live directory | Negative/Security | pytest | container-CI | n/a | T | P0 | Wrong password returns `None` (never raises `LdapError`); unknown username returns `None`; an empty password returns `None` **without** issuing a bind (no anonymous bind on the wire); the user `Connection` is unbound on both the success and the rejection path |
| AUTH-04 | `LDAPException` arms: DC refuses the connection, TLS handshake fails, search base invalid | Negative/Security | pytest | container-CI | n/a | T | P1 | Each raises `LdapError`; the message classifies the cause (connect-refused vs TLS vs search-base vs credential) distinctly enough for an operator to act; **no password, bind DN or DC hostname appears in the audit `detail`** |
| AUTH-05 | LDAPS certificate posture against a live directory | Negative/Security | pytest | container-CI | n/a | T | P0 | An untrusted CA fails the bind with `LdapError`; the same bind succeeds with the CA pinned via `ad_tls_ca_cert_file`; `ad_tls_verify=false` raises `LdapError` at `LdapAuthenticator.__init__` unless `MEFOR_ALLOW_INSECURE_TLS=1`, and with the escape set emits exactly one WARNING |
| AUTH-06 | Referral posture pinned statically at both `ldap3.Connection` sites | Negative/Security | pytest | dev-PC | n/a | T | P1 | An AST walk (modelled on `tests/test_ldap_timeouts.py:267`) finds both `Connection(...)` sites in `auth/ldap.py` and asserts each carries an **explicit** `auto_referrals` keyword whose value is not a bare literal `True`; the walker self-test proves it sees the bare-import call form |
| AUTH-07 | Referral chase does not redirect the password-verifying bind to an untrusted target | Negative/Security | manual | AD-lab | n/a | T | P1 | With a referral configured from domain A to domain B, a login as an A user either (a) never opens a bind to B carrying the user's password, or (b) is refused; captured by a packet count / connection log on the B side showing **zero** simple binds with the user's DN |
| AUTH-08 | Real-domain AD login end to end with RBAC applied and the AD identity on the audit row | Functional | manual | AD-lab | SQLite | T | P0 | Domain user `jdoe@mefor.lab` authenticates; a role-gated route returns 200 and a route outside the role returns 403; an `auth.login_success` row exists with `actor=jdoe`, `detail` containing `{"provider":"ad","roles":[…]}` and a non-NULL `client`. (Closes `W25:S1.AC-AD` / matrix `W25:F1` — record evidence there, not a second time) |
| AUTH-09 | Pin the exact kwargs handed to `spnego.server` at **both** acceptor sites | Negative/Security | pytest | dev-PC | n/a | T | P0 | With `kerberos_spn="HTTP/engine.mefor.lab"`, both `kerberos_principal` (`auth/ldap.py:300`) and `kerberos_acceptor_preflight` (`:360`) call `spnego.server(service="HTTP", hostname="engine.mefor.lab")`; a call passing the whole SPN to `service=` fails the test. Test is written to fail RED against today's code until the SPN fix lands (tracked by the owner as **#275**, above the published #231 baseline — `docs/BACKLOG.md:177` and `:4172` both gate the #99(e) residual behind it) |
| AUTH-10 | #275 confirmation on a real acceptor (handoff cell **L1**) | Functional | manual | AD-lab | n/a | C | P0 | The acceptor principal is captured verbatim. Defect **confirmed** if it reads `HTTP/engine.mefor.lab/<hostname>` (or `/unspecified`); **refuted** if it reads `HTTP/engine.mefor.lab@MEFOR.LAB`. Verdict recorded verbatim in the run record; L6 and the #99(e) cells stay blocked until it reports |
| AUTH-11 | `POST /auth/negotiate` single-leg SPNEGO against a real KDC | Functional | manual | AD-lab | SQLite | T | P0 | A ticket for `HTTP/engine.mefor.lab` obtained on a domain-joined client is accepted; the response carries a session token; `auth.login_success` records `actor=<sAMAccountName>` with `provider=ad`; **no** `WWW-Authenticate` continuation is sent (single-leg is a hard line) |
| AUTH-12 | Browser Kerberos SSO `GET /ui/sso` from a domain-joined client, Chrome **and** Firefox | Functional | browser | AD-lab | SQLite | T | P0 | First navigation returns 401 with `WWW-Authenticate: Negotiate`; the browser re-issues with `Authorization: Negotiate …`; the response is a 303 to `/ui` with exactly one session cookie set; the session has **no** step-up window (`seed_reauth=False`) so the first sensitive action bounces to `/ui/reauth`. **Both** browsers must pass — a failure in either is a FAIL for that browser, recorded per browser and never averaged into one verdict |
| AUTH-13 | Kerberos preflight is boot-once, and its operator-visible consequence | HA/Resilience | pytest + manual | dev-PC, AD-lab | n/a | T | P1 | pytest: after `mark_kerberos_unavailable("x")`, `kerberos_available` is False, `GET /auth/providers` reports `kerberos=false`, and `GET /ui/sso` 303s to `/ui/login?e=sso_unavailable`; a subsequent healthy call does **not** clear the latch. AD-lab: stop the DC, restart the engine, restore the DC — SSO stays dead until a second restart, and this is recorded as the shipped behaviour |
| AUTH-14 | `/ui/sso` reject audit rows carry the client address | Negative/Security | pytest | dev-PC | SQLite | T | P1 | After a non-navigation fetch, a malformed base64 token and a failed acceptor step, each `auth.login_failed` row with `mech="kerberos"` has a **non-NULL** `client` equal to the request's source address. Requires threading `client` through `audit_kerberos_reject` → `_directory_reject_audit` → `_audit` |
| AUTH-15 | Hardened DC: LDAP signing + `LdapEnforceChannelBinding` required | Compat | manual | AD-lab | n/a | T | P2 | Either the simple bind still succeeds over LDAPS, or it fails with an `LdapError` whose message distinguishes "channel binding / signing required" from a generic outage; the classification is asserted by a paired pytest over the `LdapError` message |
| AUTH-16 | Kerberos EPA / channel-binding acceptor-enforcement spike — the complete 2×3 matrix (#98) | Compat | manual | AD-lab | n/a | C | P2 | All six cells report, and every verdict cell negotiated `kerberos` with the baseline accepted. **Anything less self-reports INCONCLUSIVE** — no rounding up. If cell L5a (`out_token`) is skipped, the #98 banner must say `out_token` stays open |
| AUTH-17 | OIDC pivot cell **L6a** against AD FS | Functional | manual | AD-lab | SQLite | T | P0 | All three hold: the loopback redirect URI is accepted by the IdP; `code_challenge_method=S256` is accepted from a **confidential** client; a custom `amr` rule lands in the `id_token`. Any failure triggers the documented fallback rig (hostname + self-signed cert on the engine) **before** cell L7 |
| AUTH-18 | **L9** — step-up as a passwordless / smartcard-required AD account (`psmith`) | Negative/Security | manual | AD-lab | SQLite | C | P0 | Outcome recorded verbatim either way. Expected FAIL: a simple bind cannot succeed for such an account, so every step-up route returns a permanent 403. If it fails, ADR 0142's step-up advantage is **void** — the documented fallback is recorded and the architecture re-argued before ADR 0142 flips |
| AUTH-19 | **L18** — username collision: foreign UPN suffix whose local part matches a privileged on-prem `sAMAccountName` | Negative/Security | manual + pytest | AD-lab, dev-PC | SQLite | T | P0 | A principal `Administrator@attacker.example` is refused with closed-set reason `username_domain_not_allowed`; **no LDAP lookup is issued** (asserted by a bind counter on the lab DC / a spy on the pytest seam) and **no session row is created**; exactly one `auth.login_failed` row with `mech="oidc"` |
| AUTH-20 | **L11** — the MFA-claim gate with MFA removed from the claim rule | Negative/Security | manual | AD-lab | SQLite | T | P0 | Sign-in lands on `/ui/login?e=sso_mfa_required`; an audit row records reason `mfa_claim_missing`; no session cookie is set. (`oidc_require_mfa_claim` defaults `True`, `config/settings.py:1892`) |
| AUTH-21 | **L15** — the JWKS min-refetch amplification bound | Performance | manual | AD-lab | n/a | T | P1 | Measured with a throwaway local listener that **counts HTTP requests** (or an engine-side fetch counter) — never at the security group: over a window of N unknown-`kid` logins, the engine issues **≤1** JWKS fetch per `oidc_jwks_min_refetch_seconds` (default 300, `config/settings.py:1898`) |
| AUTH-22 | Offline replay of a genuinely captured `id_token` through the real validation ladder | Functional | verify | AD-lab, dev-PC | n/a | T | P1 | `messagefoundry verify --section federation --fed-id-token <file> --fed-jwks <file> --fed-nonce <nonce> --report-md <path> --report-json <path>` emits a verdict per rung with **no rung SKIPped** and none FAIL; without `--fed-nonce` the nonce rung and everything after it report SKIP (never PASS) |
| AUTH-23 | Engine-side trust of the AD FS CA, and the anchor-snapshot trap | Functional | manual | AD-lab | n/a | T | P1 | Installing the AD FS CA into the engine host's **Local Machine → Trusted Root** makes `auth/oidc_http.py`'s back-channel token/JWKS fetches succeed **after an engine restart**; the same cert in a *user* store does not; recorded explicitly. `oidc_tls_ca_cert_file` is exercised as the pinned-only fallback (that PEM becomes the entire anchor set for the hop) |
| AUTH-24 | OIDC session capped at the verified `id_token.exp` (ADR 0079 mech 1) against a real IdP | Functional | manual | AD-lab | SQLite | T | P1 | With an IdP token lifetime shorter than `session_absolute_hours` (12 h default), the minted session's `expires_at` equals the verified `id_token.exp` (± the recorded clock skew), not the local absolute cap |
| AUTH-25 | `/ui/oidc` reject audit rows carry the client address | Negative/Security | pytest | dev-PC | SQLite | T | P1 | Flow-cookie binding failure and non-navigation fetch each produce an `auth.login_failed` row with `mech="oidc"` and a **non-NULL** `client`; a rate-limit rejection still produces **zero** audit rows (the anti-flood invariant must survive the change) |
| AUTH-26 | `accountExpires` in the past is refused on **both** AD legs | Negative/Security | pytest | dev-PC | n/a | T | P0 | With a fake `ldap3` entry carrying `accountExpires` set to a past FILETIME, `_find_user` returns `None`, so `authenticate` **and** `resolve_principal` both return `None`; `accountExpires` appears in the requested attribute list at `auth/ldap.py:170-177`; the sentinel values `0` and `9223372036854775807` ("never") are **not** treated as expired |
| AUTH-27 | `lockoutTime` / `UF_LOCKOUT` (`0x10`) refused on both AD legs | Negative/Security | pytest | dev-PC | n/a | T | P0 | A fake entry with a non-zero `lockoutTime` within the domain lockout window, or `userAccountControl & 0x10`, makes `_find_user` return `None` on both the password path and the password-free `resolve_principal` path |
| AUTH-28 | Real expired and real locked AD accounts refused on all three legs | Negative/Security | manual | AD-lab | SQLite | T | P0 | A genuinely expired account and a genuinely locked-out account are each refused by (a) the password bind, (b) Kerberos SSO, (c) the OIDC hybrid resolve — three refusals per account, nine outcomes recorded, no session in any cell |
| AUTH-29 | The ADR-0079 reconciler does not report an expired/locked principal as `PRESENT` | Negative/Security | pytest | dev-PC | SQLite | T | P0 | `_probe_principal` (`auth/service.py:1199-1220`) returns `ProbeOutcome.ABSENT` for an expired and for a locked directory entry; after `ad_session_recheck_strikes` (default 2) passes the user's sessions are revoked and an audit row records it |
| AUTH-30 | AD group mapped to a **custom** role resolves the exact permission set | Functional | pytest | dev-PC | SQLite | T | P2 | An AD login whose group maps to `custom:<id>` yields an `Identity` whose `permissions` equal `permissions_for_roles(builtins) ∪ custom_permissions` exactly; the ADR 0045 escalation carve-out still refuses a custom role granting a permission outside the creator's own set; the `auth.login_success` detail records the `custom:` id |
| AUTH-31 | AD group → per-connection scope map roundtrip on the server backends | Cross-backend | pytest | container-CI | x2 | T | P1 | On real SQL Server and real PostgreSQL: `set_ad_group_scope_map([("CN=Ops,DC=x","IB_ACME_ADT")])` then `channels_for_ad_groups(["cn=ops,dc=x"]) == {"IB_ACME_ADT"}`; a `*` entry returns `{"*"}`; an unmapped group returns `set()`. Extends `tests/test_sqlserver_store.py` (absent today) and `tests/test_postgres_store.py:769` |
| AUTH-32 | Store-side `allowed_channels` message filter on the server backends | Cross-backend | pytest | container-CI | x2 | T | P1 | On SQL Server and PostgreSQL, with synthetic messages on connections `A` and `B`: `list_messages(allowed_channels=["A"])` returns only `A`; `count_messages(allowed_channels=["A"]) == 1`; `allowed_channels=[]` returns `[]`; `allowed_channels=None` returns both — byte-parity with `tests/test_channel_rbac.py:99` |
| AUTH-33 | Multi-domain forest: a child-domain user resolves groups and roles | Functional | manual + pytest | AD-lab | SQLite | C | P1 | Either the child-domain user's `AdPrincipal.groups` is non-empty and their roles resolve, or the single-scalar `ad_domain` / single `ad_group_search_base` limitation is characterised with the exact observable symptom (empty groups → no roles → a role delta that revokes other sessions) and recorded as a known constraint in `docs/SECURITY.md` |
| AUTH-34 | Local-account conflict refusal against a real directory | Negative/Security | pytest + manual | dev-PC, AD-lab | SQLite | T | P1 | An AD principal whose `sAMAccountName` matches an existing **local** account is refused with `LoginOutcome(ok=False, error="account conflict")`, an `auth.login_failed` row with `reason=local_account_conflict`, and **no** mutation of the local user's row (`auth_provider`, roles and password hash unchanged) |
| AUTH-35 | Sinkhole LDAP: a DC that accepts TCP and never answers | Performance | load-harness | dev-PC | SQLite | T | P1 | Against a listener that accepts and stalls, with `ad_connect_timeout=ad_receive_timeout=10.0`: each AD login fails within ~10–20 s (never hangs); with 32 concurrent AD logins in flight, `GET /health` and a non-AD local login still respond in < 1 s p95; the default thread-pool executor is not exhausted (asserted by a concurrent non-AD `to_thread` call completing) |
| AUTH-36 | DC hard outage: the reconciler revokes nothing and the alert latches then clears | HA/Resilience | manual | AD-lab | SQLite | T | P1 | With the DC stopped, a reconcile pass revokes **zero** sessions and logs the pass-level WARNING summary; the console stays usable for already-signed-in operators; on DC restore the next pass completes and `directory_reconcile_alert` returns `None`. (Arithmetic is already covered by `tests/test_ad_session_reconcile.py` — this is the live confirmation only) |
| AUTH-37 | The shipped reconciler default is **300 s, ON whenever `ad_enabled`** | Functional | pytest | dev-PC | n/a | T | P2 | `AuthSettings().ad_session_recheck_seconds == 300`; with `ad_enabled=true` and a directory wired, `directory_reconcile_enabled` is True and the lifespan creates the task; a doc-drift assertion fails while `api/app.py:5620` or `auth/service.py:1189-1191` still claim the default is 0 |
| AUTH-38 | Mass-revoke circuit breaker against a real directory | HA/Resilience | manual | AD-lab | SQLite | T | P2 | Bulk-removing a lab group from many users makes one pass exceed `ad_session_revoke_max` (5) / `ad_session_revoke_max_fraction` (0.34); the pass **aborts** revoking nothing, writes an `auth.ad_reconcile_aborted` audit row, logs ERROR, and `directory_reconcile_alert` latches until a clean pass |
| AUTH-39 | Bind service account with **read-only** directory rights | Negative/Security | manual | AD-lab | n/a | T | P2 | With a deliberately read-only service account, AUTH-01/02 still pass; the exact minimum rights (read `sAMAccountName`, `userPrincipalName`, `displayName`, `mail`, `memberOf`, `userAccountControl` + the two search bases) are recorded in `docs/CONNECTIONS.md`/`docs/SECURITY.md`; a write attempt from the bind account is denied by the DC |
| AUTH-40 | gMSA service identity end-to-end smoke (#99(e), cells L2/L3/L5) | Functional | manual | AD-lab | x2 | T | P2 | The engine runs under a gMSA via NSSM with `SeServiceLogonRight` granted; integrated SQL auth connects (`[store].auth=integrated`); the gMSA-SPN Kerberos acceptor completes AUTH-11; the DPAPI machine-key read succeeds **as the gMSA** |
| AUTH-41 | Derived drift guard over the two hand-maintained gate exemption sets | Negative/Security | pytest | dev-PC | n/a | T | P2 | Every entry of `_MUST_CHANGE_EXEMPT_PATHS` and `_MFA_EXEMPT_ROUTES` resolves to a live `(method, path)` in `create_app()`'s route table; a stale entry fails; a newly added entry without a reviewed reason string fails; the existing shape assertions in `tests/test_mfa_access_gate.py:145` still hold |
| AUTH-42 | Per-connection scope enforcement on the server backends | Cross-backend | pytest | container-CI | x2 | T | P1 | On SQL Server and PostgreSQL, a scoped identity gets 200 on its own connection's list/detail/replay/purge/connection-control/graph-edges and 403 on another's — the same six assertions `tests/test_channel_rbac.py` makes on SQLite |
| AUTH-43 | mTLS client-cert → `Identity` mapping matrix (ADR 0083) | Negative/Security | pytest | dev-PC | SQLite | T | P1 | Unmapped subject → no identity (401); a CN spoofing a pinned DNS SAN → no identity; a mapped but **disabled** account → 401; `require_service_cert` refuses at **app build** to gate any route asking for `MESSAGES_VIEW_SUMMARY`/`_VIEW_RAW`; a cert identity can never satisfy a step-up or MFA gate |
| AUTH-44 | `bootstrap-admin.txt` handling on the box | Usability | manual | W2025-box | SQLite | T | P2 | Captured on first `serve`, then rotated and the file deleted or ACL'd to the service identity only; the password never appears in the general log. (Closes `docs/testing/WIN2025-TEST-PLAN.md` Appendix E **`W25:M-BOOTSTRAP`** — record there) |
| AUTH-45 | Real roaming FIDO2 hardware key: enroll + assert, Chrome **and** Firefox | Functional | browser | browser-matrix | SQLite | T | P1 | Against an off-loopback engine with `[api].public_origin` set: enrollment behind the password re-proof succeeds and the credential lands in the store with a sign count; a subsequent assertion satisfies the MFA leg; the RP id derived from `public_origin` matches or the ceremony fails **legibly** (not a 500); both browsers recorded separately |
| AUTH-46 | Windows Hello platform authenticator (scope decision pending — see Q11) | Functional | browser | browser-matrix | SQLite | C | P2 | If in scope: a platform authenticator enrolls and asserts on the same engine, and the credential is distinguishable from the roaming key in `GET /me/mfa`. If out of scope: recorded as a declined dimension with the reason |
| AUTH-47 | TOTP enrollment with a real authenticator app | Functional | manual | W2025-box | SQLite | T | P2 | A current code admits; a wrong code and a code from the previous 30 s step are both rejected (`totp_skew_steps=0`); enrollment is audited. (Closes `docs/testing/WIN2025-TEST-PLAN.md` **`W25:S1.AC-MFA`** — record there) |
| AUTH-48 | Restart durability: sessions survive; process-local grants and challenges re-prompt | HA/Resilience | pytest | dev-PC | SQLite | T | P1 | After closing and reopening the store, a valid session token still authenticates; an ADR 0077 action grant minted before the restart is **gone**, so the action re-prompts (303/403, never a silent pass); a pending WebAuthn challenge is gone and its ceremony restarts rather than succeeding |
| AUTH-49 | argon2 cost params pinned and hashing concurrency bounded | Performance | pytest | dev-PC | n/a | T | P1 | The `PasswordHasher` is constructed with `time_cost=3`, `memory_cost=65536`, `parallelism=4` (values asserted, not just presence); under 64 concurrent login attempts, no more than `_ARGON2_MAX_CONCURRENCY` (= `max(2, min(8, cpu_count))`) hashes execute simultaneously, measured by a counting wrapper around the hasher |
| AUTH-50 | Limiter zero-value trap | Negative/Security | pytest | dev-PC | n/a | T | P2 | With `login_rate_limit_window_seconds = 0` (or `login_rate_limit_per_ip = 0`) the limiter admits unlimited attempts while `login_rate_limit_enabled` still reads `True` — asserted as the shipped behaviour and cross-checked against the statement at `docs/SECURITY.md:1571-1575`, so a future validator floor is a deliberate change and not a silent one |
| AUTH-51 | `admin_new_ip_step_up` posture at off-loopback exposure | Negative/Security | pytest + manual | dev-PC, AD-lab | SQLite | T | P2 | The **tested** posture is fixed by an owner decision (see Q9) and asserted: with the flag ON, an admin route from a new client IP forces step-up exactly once and re-anchors on reauth/`verify_mfa`; with it OFF (today's default, `config/settings.py:1727`) it is a no-op. Whichever is chosen is the one exercised at off-loopback exposure |
| AUTH-52 | Reverse-proxy (IIS + ARR) mTLS front: forwarded client address on audit rows and on the new-IP signal | Functional | manual | AD-lab (pass 2) | SQLite | T | P1 | With `trusted_proxies` naming the exact ARR peer, an audit row's `client` is the **real** client address, not the proxy's; the new-IP risk signal fires on a genuinely new client; with `trusted_proxies` empty the forwarded header is ignored and the proxy address is recorded |
| AUTH-53 | AST meta-guard: every request-scoped `record_audit` threads `client=` | Negative/Security | pytest | dev-PC | n/a | T | P1 | A static walk over `messagefoundry/api/` (51 of the 66 call sites) plus `messagefoundry_webconsole/` requires `client=` on every `record_audit`/`_audit` invocation inside a function whose signature carries a `Request`; a planted-omission self-test proves the walker is not vacuous; documented engine-internal exemptions are listed explicitly with a reason |
| AUTH-54 | The three verified NULL-client audit paths | Negative/Security | pytest | dev-PC | SQLite | T | P1 | `audit_kerberos_reject`, `audit_oidc_reject` and `auth.ad_scope_resynced` each write a row whose `client` equals the request address; the frozen legacy-digest test (`tests/test_audit_integrity.py:391`) still passes for genuinely address-less engine-internal rows |
| AUTH-55 | Interior-row tamper walk on the server backends | Cross-backend | pytest | container-CI | x2 | T | P1 | On SQL Server and PostgreSQL, editing the `detail` of a **middle** `audit_log` row makes `verify_audit_chain()` return `(False, msg)` naming that row's position; deleting an interior row is also detected; the unmodified chain verifies. Closes `FCP:RBAC-7` |
| AUTH-56 | PHI-access census and off-box tee redaction on the server backends | Cross-backend, PHI | pytest | container-CI | x2 | T | P1 | A summary/raw view produces the same coalesced census row shape on all three backends; the teed record is byte-identical after redaction to the SQLite case and carries the client address as a discrete field; **no message body appears in the tee**. Closes `FCP:RBAC-8` / `FCP:RBAC-9` |
| AUTH-57 | Off-box collector actually receives the teed rows from the box | Functional | manual | W2025-box | x3 | T | P2 | The collector shows the run window's auth + PHI-access rows with matching `row_hash` values and non-NULL client addresses; no PHI body is present in any received record |
| AUTH-58 | Trust-anchor preflight against the real AD FS / AD CS PEMs | Negative/Security | pytest + manual | dev-PC, AD-lab | SQLite | T | P2 | A configured `ad_tls_ca_cert_pin` / `oidc_tls_ca_cert_pin` that does not match the PEM **refuses at both enforcement levels**; a group-/world-writable anchor refuses at `[security].enforcement = enforce` and warns + audits at `warn`; an anchor change writes exactly one `auth.trust_anchor` row; with no anchor configured the preflight is dormant (zero rows) |
| AUTH-59 | Engine-shard locality of the in-process auth budgets, fail-safe direction | Negative/Security | pytest | dev-PC | SQLite | T | P1 | Two `AuthService` instances over **one unified store**: an ADR 0077 action grant minted on A is **not** honoured on B (B re-prompts, never passes); a WebAuthn challenge started on A cannot be completed on B; a reconcile strike recorded on A is not visible to B. Every miss is a re-prompt, never a bypass |
| AUTH-60 | Engine-shard: the store-backed controls are **not** multiplied | Negative/Security | pytest | dev-PC | SQLite | T | P1 | Across the same two instances: the account lockout counter (5/15 min), the per-user session cap (5) and the bootstrap-admin expiry are shared — 3 failures on A plus 2 on B locks the account; a 6th session on B evicts A's oldest. Confirms the split stated at `docs/SECURITY.md:1538-1541` |
| AUTH-61 | Real-DOM `/ui` auth surface | Usability | browser | browser-matrix | SQLite | T | P1 | In a real browser: the login form renders and submits under the shipped CSP; the `__Host-` session cookie is actually stored with `Secure`+`SameSite=Strict`; the SSO link is hidden when the provider is degraded and no dead link is reachable; the OIDC 200 + meta-refresh landing navigates; the RFC 4559 401 is answered. Recorded per browser |
| AUTH-62 | Advisory mutation + diff coverage scoped to `messagefoundry/auth/` and `api/security.py` | Compat | CI-leg | container-CI | n/a | C | P2 | The drafted jobs from `docs/quality-gates/HANDOFF-mutation-coverage.md` run advisory (`--exit-zero`), publish a surviving-mutant list for the auth scope, and never block a merge; a planted `and`→`or` mutation inside `require()` appears in the surviving-mutant report or is killed |
| AUTH-63 | Documentation-drift closure for this area | Compat | pytest + manual | dev-PC | n/a | T | P2 | `docs/FEATURE-MAP.md` no longer says `require_mfa` is Administrator-scoped (`:129`), no longer defers federated SSO to 0.2 (`:132`), and no longer says the PySide6 desktop console "stays (additive)" (`:130`); ADR 0045 custom roles appear in the map; the two stale reconcile-default comments are fixed (see AUTH-37); the `FCP:AUTHN-11` (`docs/testing/FEATURE-COVERAGE-PLAN.md:1066`) and `FCP:RBAC-17` (`:1113`) notes are corrected |
| AUTH-64 | Post-run scrub of the AD-lab run record before commit | PHI | CI-leg + manual | AD-lab | n/a | T | P1 | The committed run record contains only RFC 2606 names (`mefor.lab`, `*.example`), RFC 5737 IPs (`192.0.2.0/24`, `198.51.100.0/24`) and `DOMAIN\svc$`; **no** routable IP, real hostname, domain, partner or site name, and **no message bodies**; the `forbidden-content` CI context is green (it is blocking) |
| AUTH-65 | AD group membership changes **while a session is live**: the authorization decision is re-evaluated within a bounded window, not at session expiry | Negative/Security | pytest | dev-PC | SQLite | T | P0 | With `ad_session_recheck_seconds=300` / `ad_session_recheck_strikes=2` (`config/settings.py:1815`, `:1821`) and a driven clock (never a real sleep): **(a)** a signed-in user removed from the group mapped to their only role is re-diffed on the **next single pass** — a role delta is same-pass, not strike-gated (`auth/reconcile.py:161-177` emits `reason="roles_changed"` with the narrowed `role_ids`), and `_apply_reconcile_revocation` (`auth/service.py:1347-1355`) persists the new roles then revokes the live sessions — so the bound is **≤ one `ad_session_recheck_seconds` interval**, never `session_absolute_hours` (12 h default); the next request on the pre-change token is 401 and a re-login carries the reduced permission set. **(b)** A user whose groups did not change keeps their session in the same pass (no collateral revoke), and the breaker budget is not consumed by (a) alone. **(c)** Removal from a group mapped **only** to a per-connection scope entry (no role change) is pinned as the **known residual**: `plan_pass` diffs role ids only and `_sync_ad_channel_scope` (`auth/service.py:1137-1162`, called only from the login path at `:1104`) never runs in a reconcile pass, so the stale scope survives the pass — the test asserts today's behaviour and a `docs/SECURITY.md` row states the bound as "role deltas ≤ one reconcile pass, per-connection-scope deltas at next login" |

### 9.5 Detailed scenarios

#### S-AUTH-A — Confirm or refute the #275 SPN defect (AUTH-09, AUTH-10) — **hard blocker**

**Why narrative:** this gates AUTH-16 and the whole #99(e) group, and it is easy to run wrong (a green preflight is not evidence — the preflight and the failing call share the defect).

**Preconditions.** Box A (DC, forest `mefor.lab`) and Box B (domain-joined engine host) per `docs/releases/HANDOFF-AD-LAB-aws.md`. An `HTTP/engine.mefor.lab` SPN registered against the engine's service identity. Cell **L0** (baseline, everything off) already recorded. Window claimed:

```powershell
pwsh -NoProfile -File scripts\coord\claim.ps1 -Take ad-lab-window -Note "AD/federation lab: 275, 98, 99e, 274"
```

**Steps.**
1. On Box B, set `[auth].kerberos_enabled = true`, `[auth].kerberos_spn = "HTTP/engine.mefor.lab"`, `[auth].ad_enabled = true` with `ad_server = "ldaps://dc.mefor.lab:636"`, and supply the bind password via `MEFOR_AUTH_AD_BIND_PASSWORD`.
2. Start the engine and capture the boot log line emitted by the preflight at `messagefoundry/api/app.py:5577-5594`.
3. **The observation point is the acceptor principal, not the preflight verdict.** In a Python REPL on Box B, under the engine's service identity, construct the acceptor exactly as `auth/ldap.py:360` does — `spnego.server(service="HTTP/engine.mefor.lab")` — and print the credential/principal the provider resolved. Record the string **verbatim**.
4. From Box C (or Box B), obtain a ticket for `HTTP/engine.mefor.lab` and drive `POST /auth/negotiate` with the SPNEGO token.
5. Repeat step 3 with the corrected split — `spnego.server(service="HTTP", hostname="engine.mefor.lab")` — and repeat step 4.

**Expected result.** Defect **confirmed** if step 3 yields a principal of the shape `HTTP/engine.mefor.lab/<hostname>` or `.../unspecified` and step 4 fails, while the split form in step 5 yields `HTTP/engine.mefor.lab@MEFOR.LAB` and step 4 succeeds. Defect **refuted** if step 3's principal is already correct.

**Cleanup/rollback.** Revert `[auth].kerberos_enabled` to `false`; leave the SPN registered (L6 needs it). Copy the run record **off instance store** immediately — a STOP/START wipes it. Do not stop or terminate any EC2 instance without the owner's say-so.

**Automation that must land regardless of the verdict.** AUTH-09 — a unit test pinning the exact `(service=, hostname=)` kwargs at both `auth/ldap.py:301` and `:360`. Written today it fails RED; that is the point.

---

#### S-AUTH-B — Interim containerised LDAP leg (AUTH-01…AUTH-05)

**Why narrative:** it is the only way to retire four P0 rows without a DC VM, and it must be built so it cannot be mistaken for Kerberos coverage.

**Preconditions.** Docker available on the CI runner. A Samba AD DC (or OpenLDAP with the AD schema for `LDAP_MATCHING_RULE_IN_CHAIN`) container image, seeded with users `jdoe`, `asmith`, groups `mefor-ops`, `mefor-admins`, and `mefor-admins` **nested inside** `mefor-ops`. An LDAPS listener with a container-generated CA whose PEM is written to a path the test can pass as `ad_tls_ca_cert_file`.

**Steps.**
1. Add a new job `directory-ldap` to `.github/workflows/ci.yml`, gated exactly like `sqlserver-store` (`:483`) — schedule / `workflow_dispatch` / auth-path-change — never on every PR.
2. New module `tests/test_ldap_directory_live.py`, all nodes behind a `directory` marker that **skips** when `MEFOR_TEST_LDAP_URI` is unset, so a dev-PC run is unaffected.
3. Drive the **real** `LdapAuthenticator` (no monkeypatching of `ldap3`): `authenticate("jdoe", <pw>)`, `authenticate("jdoe", "wrong")`, `authenticate("nobody", <pw>)`, `authenticate("jdoe", "")`, and `resolve_principal("jdoe")`.
4. Run the same suite twice — once with `ad_use_nested_groups=True`, once `False` — and diff the returned `groups` frozensets.
5. Assert the LDAPS posture arms: untrusted CA → `LdapError`; `ad_tls_ca_cert_file` pinned → success; `ad_tls_verify=false` without `MEFOR_ALLOW_INSECURE_TLS` → `LdapError` at construction.
6. Collect coverage over `messagefoundry/auth/ldap.py` for this job only.

**Observation point.** The coverage report for `auth/ldap.py:219-282` — the `pragma: no cover` arms at `:252` and `:274` must be **executed** in this leg (they can keep the pragma for the default suite).

**Expected result.** All five call shapes behave as AUTH-01/02/03/04/05 specify; the nested/direct diff is non-empty in exactly the nested group's DN and `sAMAccountName`.

**Cleanup/rollback.** Container torn down by the job; no state outside it. **This leg proves the LDAP bind half only** — it must be labelled so in the job name and in the run record, because Kerberos genuinely needs a DC VM and this leg can never substitute for AUTH-10/11/12.

---

#### S-AUTH-C — AD account-state matrix beyond `ACCOUNTDISABLE` (AUTH-26, AUTH-27, AUTH-28, AUTH-29)

**Why narrative:** it spans a code change, a unit seam, and a lab confirmation, and it touches the reconciler — getting the order wrong risks mass-revoking lab sessions.

**Preconditions.** Owner decision on Q8 (whether `_find_user` should reject these states) — the tests below are written against the **decided** behaviour, not assumed. For the lab half: a genuinely EXPIRED account (`accountExpires` in the past) and a genuinely LOCKED-OUT account on `mefor.lab`, neither of them disabled.

**Steps (unit half, runs first).**
1. New module `tests/test_ad_account_states.py`. Build a fake `ldap3` entry object exposing `distinguishedName`, `sAMAccountName`, `displayName`, `mail`, `memberOf`, `userAccountControl`, **`accountExpires`** and **`lockoutTime`**, matching the `_attr`/`_multi` accessors at `auth/ldap.py:68-78`.
2. Assert first that `accountExpires` and `lockoutTime` are present in the `attributes=[…]` list at `auth/ldap.py:170-177` — without that the values never arrive and every later assertion is vacuous.
3. Table-drive: past `accountExpires`; `accountExpires = 0`; `accountExpires = 9223372036854775807`; non-zero `lockoutTime` inside the lockout window; `lockoutTime = 0`; `userAccountControl & 0x10`; `userAccountControl & 0x2`; a clean account.
4. For each row assert **both** `authenticate(...)` and `resolve_principal(...)`. The second is the one that matters: it is the path Kerberos SSO, OIDC and `_probe_principal` all use.
5. Extend `tests/test_ad_session_reconcile.py` with an expired-account probe asserting `ProbeOutcome.ABSENT`, then a strike-count walk to revocation.

**Steps (lab half).** On Box B, with `ad_session_recheck_seconds` temporarily raised to a long interval so a pass does not fire mid-test, attempt: password bind, Kerberos SSO, and an OIDC sign-in as each of the expired and locked accounts. Then restore the interval and let one reconcile pass run against a session held by the expired account.

**Observation point.** For each of the nine cells: the HTTP status, the presence/absence of a `sessions` row for that user, and the `auth.login_failed` reason slug.

**Expected result.** Nine refusals, nine audit rows, zero sessions; the reconcile pass revokes the expired account's pre-existing session after `ad_session_recheck_strikes` passes.

**Cleanup/rollback.** Restore `ad_session_recheck_seconds`; un-expire / unlock the lab accounts only if a later cell needs them. `_find_user` returning `None` for a new state is a **behaviour change** for existing deployments — it must land with a `docs/SECURITY.md` row and a CHANGELOG entry, not silently.

---

#### S-AUTH-D — L18, the username-collision privilege-escalation cell (AUTH-19)

**Why narrative:** this is the cell that exists because a review found a live escalation route; running it loosely proves nothing.

**Preconditions.** AD FS farm on Box A with a claim rule that can emit an arbitrary `preferred_username`. `[auth].oidc_allowed_username_domains` set to `["mefor.lab"]` (or left empty so it falls back to `[auth].ad_domain` — the fallback path is the one to exercise, since an empty list plus an unset `ad_domain` is refused at load). A privileged on-prem account named `Administrator` exists in `mefor.lab`. A bind counter on the DC (or DC LDAP logging) so "no LDAP lookup" is falsifiable.

**Steps.**
1. Record the DC's current bind count.
2. Configure the AD FS claim rule to emit `preferred_username = Administrator@attacker.example` for the test principal.
3. Complete the browser authorization-code flow from Box C.
4. Immediately capture: the landing URL, the DC bind count delta, the `audit_log` rows for the window, and `SELECT count(*) FROM sessions`.

**Observation point.** The DC bind-count delta **and** the audit reason slug — both, not either.

**Expected result.** Landing on `/ui/login` with the federated failure code; exactly one `auth.login_failed` row with `mech="oidc"` and reason `username_domain_not_allowed`; DC bind-count delta **zero**; no new session row. If the local part is stripped and resolved against the on-prem `Administrator`, the cell is a **FAIL** and ADR 0142 must not flip.

**Cleanup/rollback.** Revert the claim rule. Scrub the run record: the real UPN suffix, the engine hostname and the DC name must be replaced with RFC 2606 placeholders before commit (AUTH-64).

---

#### S-AUTH-E — L9, step-up as a passwordless / smartcard-required account (AUTH-18)

**Why narrative:** it is designed to **fail**, and a tester who "fixes" the failure destroys the finding.

**Preconditions.** Lab account `psmith` configured smartcard-required / passwordless on `mefor.lab`. `psmith` signs in successfully via Kerberos SSO or OIDC first — the cell is about **step-up**, not sign-in.

**Steps.**
1. Sign `psmith` in through `/ui/sso` (or `/ui/oidc`). Confirm a session exists and non-sensitive `/ui` pages render.
2. Click any action behind a step-up gate — e.g. a message replay, which routes through `require_ui_step_up_action`.
3. At `/ui/reauth`, supply the account's password. There is none to supply; supply anything.
4. Record the outcome and the audit rows.

**Observation point.** Whether `_reauth_ad` (`auth/service.py:1750`) can ever return `True` for this account.

**Expected result (the predicted one).** Permanent 403 / an endless bounce to `/ui/reauth`; the operator can never perform a sensitive action. If so, **ADR 0142's step-up advantage is void** — record the verbatim outcome, record the documented fallback (which is: this account class cannot use step-up-gated routes), and re-argue the architecture **before** flipping ADR 0142 to Accepted. Do not work around it in the lab.

**Cleanup/rollback.** Sign `psmith` out; revoke its sessions via `DELETE /users/{id}/sessions`.

---

#### S-AUTH-F — Sinkhole LDAP and thread-pool saturation (AUTH-35)

**Why narrative:** timing-dependent, easy to run against the wrong bound, and the interesting failure is in a *different* subsystem (the shared default executor).

**Preconditions.** A local TCP listener that accepts connections and never writes a byte (a 20-line asyncio script under the scratchpad — **not** committed as a fixture unless it becomes a harness capability). Engine on the dev PC with `ad_enabled=true`, `ad_server = "ldaps://127.0.0.1:6636"` pointed at the sinkhole, `ad_allow_insecure_ldap=false`, `ad_connect_timeout = ad_receive_timeout = 10.0`. A local account that does **not** go through AD, for the control.

**Steps.**
1. Baseline: measure `GET /health` p95 and a local-account login p95 with no AD traffic.
2. Fire 32 concurrent AD logins at `POST /auth/login` for AD usernames.
3. While they are in flight, sample `GET /health` and the local-account login every 250 ms.
4. Record when the AD logins complete and with what error.
5. Repeat at 64 and 128 concurrent AD logins.

**Observation point.** Not the AD login latency (that is bounded by the two `ldap3` timeouts by construction) — it is **the control**: `GET /health` and the local login. `auth/ldap.py`'s module docstring records that the `to_thread` dispatch carries no `asyncio.wait_for`, so saturation of the default executor is the real hazard.

**Expected result.** AD logins fail within roughly `connect + receive` (~10–20 s), never hang. The control stays under 1 s p95 at 32 concurrent. If the control degrades, the finding is "the shared default executor is pinned by AD binds" and the remedy (a dedicated bounded executor, or an `asyncio.wait_for` around the dispatch) is a design change, not a test tweak.

**Cleanup/rollback.** Kill the sinkhole; restore `ad_server`. Nothing persists.

---

#### S-AUTH-G — Engine-shard budget locality and fail-safe direction (AUTH-59, AUTH-60)

**Why narrative:** the claim at `docs/SECURITY.md:1538-1541` is prose; the dangerous direction (a cross-process step-up miss failing OPEN) would be a silent bypass.

**Preconditions.** No lab needed. Two `AuthService` instances constructed over **one** SQLite store — this models N `serve --shard` engine shards over the ONE unified store (ADR 0037 + ADR 0063). This is an **engine shard** scenario, not a database shard.

**Steps.**
1. Build store S. Build `AuthService` A and B, both over S, same `AuthSettings`.
2. On A: log a user in, complete a step-up, mint an action-bound grant for action `purge` (`_grant_action_step_up` via the reauth path).
3. On B, with the **same session token**: call `has_action_step_up(token, "purge")`.
4. On A: begin a WebAuthn assertion, capture the challenge. On B: attempt to finish it.
5. On A: run a reconcile pass that records one strike for a user. On B: inspect the strike ledger.
6. Store-backed half: record 3 failed logins on A and 2 on B against the same account; then attempt a correct password on either.
7. Open 5 sessions via A, then a 6th via B; list the user's sessions from A.

**Observation point.** Steps 3–5 must each be a **miss that re-prompts**. Step 3 returning `True` on B would be the bypass.

**Expected result.** 3 → `False` (B re-prompts). 4 → the ceremony fails and restarts, never succeeds. 5 → B's ledger has no strike (fail-open, per design). 6 → the account is **locked** (store-backed, shared). 7 → A sees 5 sessions with its oldest evicted (store-backed cap, shared).

**Cleanup/rollback.** In-memory / tmp store; nothing persists.

---

#### S-AUTH-H — ADR-0150 client-address meta-guard and the three verified holes (AUTH-53, AUTH-54)

**Why narrative:** the omission is undetectable by the tamper machinery — a missing client hashes as the legacy 6-element payload and verifies perfectly clean — so the guard must be static, and it must be proven non-vacuous.

**Preconditions.** None beyond a dev PC.

**Steps.**
1. New module `tests/test_audit_client_threading.py`. Walk `messagefoundry/api/**.py` and `messagefoundry_webconsole/**.py` with `ast`, modelled on `tests/test_ldap_timeouts.py:267-300`.
2. For each function whose parameters include an annotation named `Request` (or `WebSocket`), collect every `Call` whose func resolves to `record_audit` or `_audit` and require a `client=` keyword.
3. Add a **planted-mutation self-test** in the style of `tests/test_ldap_timeouts.py:301`: parse a small inline source string with a `Request`-bearing handler calling `record_audit` without `client=` and assert the walker flags it. Without this the guard can silently go vacuous when a package moves.
4. Maintain an explicit exemption list with a one-line reason per entry (engine-internal writers such as the retention purge legitimately have no address).
5. Fix the three verified holes: thread a `client` parameter through `audit_kerberos_reject` / `audit_oidc_reject` → `_directory_reject_audit` → `_audit` (`auth/service.py:464`, `:499`, `:1046`), and pass `client` on the `auth.ad_scope_resynced` row (`:1150`) as its sibling `auth.ad_roles_resynced` (`:1085`) already does.
6. Add the behavioural counterparts (AUTH-14, AUTH-25) asserting a non-NULL `client` on those rows.
7. Re-run `tests/test_audit_integrity.py` — the frozen legacy-digest assertion at `:391` must still pass for genuinely address-less rows.

**Observation point.** The self-test in step 3, and the unchanged frozen digest in step 7.

**Expected result.** The walker flags zero real call sites after step 5, flags the planted one, and the chain algebra is untouched.

**Cleanup/rollback.** Pure test + a narrow signature change; revert by reverting the commit.

### 9.6 Automation disposition

**New pytest modules**

| Module | Rows | Effort |
|---|---|---|
| `tests/test_ad_account_states.py` — the `accountExpires` / `lockoutTime` / `UF_LOCKOUT` table over `_find_user` + `resolve_principal` | AUTH-26, AUTH-27 | **S** |
| `tests/test_spnego_acceptor_kwargs.py` — pins `(service=, hostname=)` at both `spnego.server` sites | AUTH-09 | **S** |
| `tests/test_audit_client_threading.py` — the AST meta-guard + planted-mutation self-test | AUTH-53 | **M** |
| `tests/test_auth_gate_exempt_drift.py` — `_MUST_CHANGE_EXEMPT_PATHS` / `_MFA_EXEMPT_ROUTES` against the live route table | AUTH-41 | **S** |
| `tests/test_auth_engine_shard_locality.py` — two `AuthService` instances over one unified store (an **engine shard** model, not a database shard) | AUTH-59, AUTH-60 | **M** |
| `tests/test_ldap_directory_live.py` — real `ldap3` against a container DC, behind a `directory` marker | AUTH-01…AUTH-05 | **M** |
| `tests/test_ad_referrals.py` — the `auto_referrals` AST assertion (could equally extend `test_ldap_timeouts.py`; a separate module keeps the referral **policy** decision legible) | AUTH-06 | **S** |

**Extends an existing module**

| Existing module | Added rows | Effort |
|---|---|---|
| `tests/test_ad_session_reconcile.py` | AUTH-29 (expired/locked probe → `ABSENT`), AUTH-37 (shipped default 300 s, ON with `ad_enabled`), AUTH-65 (live group-membership change → bounded re-evaluation + the per-connection-scope residual) | **S** |
| `tests/test_auth_hardening.py` | AUTH-14, AUTH-25 (non-NULL `client` on directory-reject rows), AUTH-54, AUTH-34 (local-conflict invariants) | **S** |
| `tests/test_sqlserver_store.py`, `tests/test_postgres_store.py` | AUTH-31 (scope-map roundtrip), AUTH-32 (`allowed_channels` filter), AUTH-55 (interior tamper walk), AUTH-56 (PHI census + tee) | **M** |
| `tests/test_channel_rbac.py` | AUTH-42 — parameterise the six route assertions over the three backends | **M** |
| `tests/test_custom_roles.py` | AUTH-30 — AD login whose group maps to `custom:<id>` | **S** |
| `tests/test_api_tls.py` **or** a new auth-suite home (owner call — `FCP:AUTHN-18` notes the evidence currently lives in the transport-TLS sibling) | AUTH-43 — mTLS CN/SAN mapping matrix + PHI fence | **M** |
| `tests/test_auth_core.py` | AUTH-49 (pinned argon2 params + concurrency cap), AUTH-50 (limiter zero-value trap) | **S** |
| `tests/test_auth_session_lifecycle.py` | AUTH-48 — restart durability + grant/challenge re-prompt | **S** |
| `tests/test_admin_new_ip.py` | AUTH-51 — once Q9 fixes the tested posture | **S** |
| `tests/test_trust_anchors.py` | AUTH-58 — real AD FS / AD CS PEMs as fixtures (public certs only) | **S** |
| `tests/test_security_doc_drift.py` / a doc-drift sibling | AUTH-63 — FEATURE-MAP rows and the two stale reconcile comments | **S** |

**New CI legs**

| Leg | Content | Gating | Effort |
|---|---|---|---|
| `directory-ldap` in `.github/workflows/ci.yml` | Samba AD DC / OpenLDAP container; runs the `directory`-marked module with coverage over `auth/ldap.py` | Same shape as `sqlserver-store` (`:483`): schedule / `workflow_dispatch` / auth-path change. **Never** on every PR | **M** |
| Extend `sqlserver-store` / `postgres-store` | AUTH-31, AUTH-32, AUTH-42, AUTH-55, AUTH-56 | Existing gates unchanged | **S** |
| `quality-advisory` additions | AUTH-62 — the drafted mutmut + diff-cover jobs, scoped to `messagefoundry/auth/` + `api/security.py`, advisory-only | Advisory, never required | **M** |
| `ui-browser` (Playwright) — **only if Q11 says yes** | AUTH-61, and the non-domain half of AUTH-45 | New leg; none exists today | **L** |

**Harness / probe capability**

- A **sinkhole LDAP listener** and a **request-counting HTTP listener** as reusable fixtures (AUTH-35, AUTH-21). Natural home: `tests/` helpers for the first, and a scratchpad script for the lab-side second — `HANDOFF-AD-LAB-aws.md` is explicit that the amplification bound must be measured with a counting listener, never at the security group. Effort **S**.
- A concurrent-login driver for AUTH-35, reusing the `harness/load/` runner shape rather than a new framework. Effort **M**.
- **No new acceptance framework.** `messagefoundry/verify/` already owns the PASS/FAIL/SKIP/MANUAL contract; AUTH-22 rides `verify --section federation` as built. Effort **S** (wiring only).

**Stays manual, and why**

| Row(s) | Why it cannot be automated here |
|---|---|
| AUTH-08, AUTH-10, AUTH-11, AUTH-15, AUTH-16, AUTH-28, AUTH-33, AUTH-36, AUTH-38, AUTH-39, AUTH-40 | Need a real Domain Controller. A DC is a **VM role, never a container**, and `HANDOFF-AD-LAB-aws.md` explicitly forbids wiring any of this to CI: a domain-joined self-hosted runner executing repo code is a far larger blast radius than the existing mirror-gated `windows-service-smoke` |
| AUTH-17, AUTH-18, AUTH-19, AUTH-20, AUTH-21, AUTH-23, AUTH-24 | Need a real AD FS farm and a real `id_token`; the offline replay (AUTH-22) is the automatable residue |
| AUTH-12, AUTH-45, AUTH-46, AUTH-61 | Real browser behaviour and real authenticator hardware. AUTH-61 becomes CI-able if Q11 authorises a Playwright leg; AUTH-45/46 cannot — no CI runner holds a FIDO2 key |
| AUTH-44, AUTH-47, AUTH-52, AUTH-57 | On-box operator procedures and off-box infrastructure. AUTH-44/47 are already owned by `WIN2025-TEST-PLAN` — record evidence there |
| AUTH-64 | Human scrub judgement; the `forbidden-content` CI context is the backstop, not the primary control |

### 9.7 Environment, data & prerequisites

**Must be procured or stood up (the AD lab — nothing directory-facing runs without it).** Follow `docs/releases/HANDOFF-AD-LAB-aws.md`; this section names the deltas this chapter adds.

> **Environment-phase exit item — blocking for the §9.4 P0 AD campaign gate, and for nothing else.** The **rig** is the blocker. Until Boxes A/B/C exist and cell **L0** (baseline, everything off) is recorded, none of AUTH-08 / 10 / 11 / 12 / 17 / 18 / 19 *(lab half)* / 20 / 28 can report, so the campaign gate cannot be satisfied and no release may claim AD / Kerberos / federated-SSO support. The lab's authority document is **not** part of this blocker: `docs/security/AD-FEDERATION-LAB-RUNBOOK.md` exists for the owner and is **withheld from the public repo** (`.gitignore:144` — `docs/security/`, `docs/reviews/` and `docs/marketing/` are gitignored post-cutover as attacker-roadmap material), so its cells L0–L18 remain citable evidence. The only outstanding ask against it is the chapter author's **read access** (Q1), which changes how these rows are *worded*, not whether they can run.

| Item | Detail |
|---|---|
| **Box A** — DC + AD FS | Throwaway forest `mefor.lab` (`Install-ADDSForest`). A DC is a VM role, never a container. AD FS farm on the same box with a service-communication TLS cert (self-signed is fine) |
| **Box B** — engine host | Domain-joined Windows Server 2025, engine under NSSM, loopback bind for pass 1, `[api].public_origin = http://localhost:8765`. AD FS CA installed into **Local Machine → Trusted Root** (a *user*-store cert is never seen; anchors snapshot at engine start, so trusting later needs a restart) |
| **Box C** — client | Domain-joined, Chrome **and** Firefox. May be Box B for pass 1 |
| **Second domain** — **new, no cell exists today** | A child domain or forest trust, for AUTH-07 (referral) and AUTH-33 (multi-domain). Needs an owner decision (Q6) before provisioning |
| Pass-2 only | AD CS; IIS + ARR reverse-proxy mTLS front (AUTH-52); optionally an Entra ID tenant + app registration |
| **Accounts** | `jdoe`, `asmith`; **`psmith` passwordless / smartcard-required** (AUTH-18); a **DISABLED** account; an **EXPIRED** account (`accountExpires` in the past); a **LOCKED-OUT** account (AUTH-26/27/28); a privileged `Administrator` for AUTH-19 |
| **Groups** | `mefor-ops`, `mefor-admins`, plus a **nested** group for the `MATCHING_RULE_IN_CHAIN` cell |
| **Service identities** | A gMSA with an `HTTP/<fqdn>` SPN + keytab/service credential for the SPNEGO acceptor (AUTH-40); **separately**, a directory service account with **READ-ONLY** rights for the least-privilege proof (AUTH-39) |
| **Devices** | At least one roaming **FIDO2 hardware key** (AUTH-45); a Windows Hello platform authenticator if Q11 puts it in scope |
| **Listeners** | A sinkhole / deliberately-slow LDAP listener (AUTH-35); a throwaway local HTTP listener that **counts requests** for the JWKS amplification bound (AUTH-21) |
| **Collectors** | An SMTP sink for out-of-band security-event notifications; an off-box audit/SIEM collector reachable from Box B (AUTH-57) |
| **Storage** | EBS or copy-off-box storage for run records — a STOP/START wipes instance store and **the run record is the deliverable** |
| **Process** | Owner approval before stopping or terminating any EC2 instance (standing rule); claim the window with `pwsh -NoProfile -File scripts\coord\claim.ps1 -Take ad-lab-window`, release with `-Release ad-lab-window` |

**Already CI-provisioned (no procurement).** SQL Server 2025 and PostgreSQL containers on the gated `sqlserver-store` / `postgres-store` legs. `ldap3>=2.9` and `pyspnego>=0.10` are **base** dependencies (`pyproject.toml:61-62`); the `[webauthn]` extra is installed on the CI `test` leg (`ci.yml:159`), so no auth test is extra-skipped.

**New CI provisioning.** A Samba AD DC (or OpenLDAP with the AD schema) container image for the `directory-ldap` leg, plus a container-generated CA PEM. Requires the Q5 decision.

**Configuration knobs a tester must set (all real, all verified).**

```
[auth]
ad_enabled = true
ad_server = "ldaps://dc.mefor.lab:636"          # non-ldaps refused unless ad_allow_insecure_ldap
ad_domain = "mefor.lab"                          # single scalar — see AUTH-33
ad_user_search_base  = "DC=mefor,DC=lab"
ad_group_search_base = "DC=mefor,DC=lab"
ad_bind_dn = "CN=svc-mefor,OU=Service,DC=mefor,DC=lab"
ad_use_nested_groups = true
ad_tls_ca_cert_file = "C:\\pki\\lab-root.pem"
ad_tls_ca_cert_pin  = "<sha256 lowercase hex of the PEM>"   # AUTH-58
ad_connect_timeout = 10.0
ad_receive_timeout = 10.0
ad_session_recheck_seconds = 300                 # SHIPPED DEFAULT — not 0, despite two stale comments
kerberos_enabled = true
kerberos_spn = "HTTP/engine.mefor.lab"           # the #275 string
oidc_enabled = true                              # requires ad_enabled (hybrid-only)
oidc_allowed_username_domains = ["mefor.lab"]    # the AC-11 escalation control — AUTH-19
oidc_require_mfa_claim = true                    # default; AUTH-20 turns the IdP claim rule off, not this
oidc_jwks_min_refetch_seconds = 300              # the AUTH-21 bound
```

Secrets by environment only: `MEFOR_AUTH_AD_BIND_PASSWORD`, `MEFOR_AUTH_OIDC_CLIENT_SECRET`. The insecure-TLS dev escape is `MEFOR_ALLOW_INSECURE_TLS` (`config/settings.py:179`). Never place any of these in a committed file.

**Synthetic data & PHI discipline.** No PHI is required anywhere in this chapter. The only message rows needed are for the per-connection scope filters (AUTH-32, AUTH-42) — synthesise them with `messagefoundry generate` (conformant synthetic HL7, corpus git-ignored) or with the inline synthetic ADT constant the existing `tests/test_channel_rbac.py` already uses. **`dryrun` / `generate` stdout can contain full message bodies — never redirect either into a committed file, a ticket, or a CI log.** Lab run records carry metrics, verdicts and closed-set reason slugs only; the post-run scrub (AUTH-64) is a blocking gate, not a formality.

### 9.8 Exit criteria

This area is signed off for release when **all** of the following hold and are recorded:

1. **Both P0 gates are satisfied, each on its own terms** — 18 P0 rows in total (16 Cls `T` + the 2 Cls `C` rows AUTH-10 and AUTH-18), split per §9.4 because the AD lab has not been stood up:
   - **P0-automated — blocks *every* release.** AUTH-01, 02, 03, 05, 09, 19 *(pytest seam half)*, 26, 27, 29, 65 are green. All are Cls `T`, all run in CI or on a dev PC, and none needs a directory. No release ships with one of these red.
   - **P0 AD campaign — blocks only a release claiming AD / Kerberos / federated-SSO support.** AUTH-08, 10, 11, 12, 17, 18, 19 *(lab half)*, 20, 28 each report a verdict — PASS, or FAIL with an owner-accepted disposition recorded in the run record. A loopback-only, local-authn-only release is **not** gated on these, but must then ship with `ad_enabled` / `kerberos_enabled` / `oidc_enabled` documented as **unvalidated against a real directory**, and `GET /auth/providers` must not advertise them as proven.
   - AUTH-10 and AUTH-18 are Cls `C`: they yield a recorded verdict, not a threshold, so neither counts as gate evidence for its own subject (AUTH-09 gates the SPN kwargs; AUTH-17 and AUTH-19 gate ADR 0142). AUTH-18 (L9) may legitimately FAIL; that outcome is a **release blocker for ADR 0142's status flip**, not for the release, and must be recorded verbatim.
2. **#275 is resolved, not pending.** AUTH-10 reports confirmed-and-fixed or refuted, and AUTH-09 (the kwarg pin) is green on the default CI leg. Until then `GET /auth/providers` must not advertise `kerberos=true` in any shipped default profile.
3. **The `pragma: no cover` count in `messagefoundry/auth/ldap.py` has fallen.** The two `LDAPException` arms (`:252`, `:274`) are executed by the `directory-ldap` leg; the four SPNEGO lines (`:298`, `:306`, `:358`, `:363`) are either executed in the AD lab and the run recorded, or carry an explicit "AD-lab-only, cell Lx" comment naming the cell that covers them.
4. **Zero directory-reject audit rows with a NULL client.** AUTH-14, AUTH-25 and AUTH-54 green; AUTH-53's AST guard green with a passing planted-mutation self-test and a reviewed exemption list.
5. **Cross-backend parity closed.** AUTH-31, 32, 42, 55, 56 green on both the `sqlserver-store` and `postgres-store` legs — i.e. the AD group → per-connection scope map, the `allowed_channels` filter, the interior-row tamper walk and the PHI census/tee all pass on SQL Server and PostgreSQL, not only SQLite.
6. **AD account states beyond `ACCOUNTDISABLE` have an owner-decided, tested behaviour, and a mid-session group change is bounded.** Q8 answered; AUTH-26/27/29 green; AUTH-28's nine lab cells recorded; if the behaviour changed, a `docs/SECURITY.md` row and a CHANGELOG entry landed with it. **AUTH-65 green**: removing a signed-in user from their mapped AD group narrows the authorization decision within ≤ one `ad_session_recheck_seconds` pass instead of surviving to `session_absolute_hours`, and the per-connection-scope half of that window is documented as the known residual.
7. **The referral posture is a decision, not a default.** Q7 answered; AUTH-06 green; AUTH-07 recorded.
8. **The engine-shard fail-safe direction is proven.** AUTH-59 and AUTH-60 green — every cross-process budget/grant/challenge miss re-prompts, and the three store-backed controls are demonstrably shared.
9. **Browser reality checked at least once.** AUTH-12, AUTH-45 and AUTH-61 executed in Chrome **and** Firefox with per-browser results; a failure in either is a recorded finding, not an average.
10. **ADR statuses are honest.** ADR 0142 flips Proposed → Accepted **only** when AUTH-17 (L6a), AUTH-18 (L9) and AUTH-19 (L18) have all reported. ADR 0079's Kerberos residual and #98's banner reflect the lab evidence. #99(e) closes only on AUTH-40.
11. **Doc drift closed.** AUTH-37 and AUTH-63 green: FEATURE-MAP's three stale auth rows, the two stale reconcile-default comments, and the two stale FEATURE-COVERAGE-PLAN notes (`FCP:AUTHN-11`'s `/ui` step-up claim, `FCP:RBAC-17`'s "unbuilt" dual-control) are corrected.
12. **The run record is committed and clean.** A scrubbed AD-lab run record exists under `docs/testing/`, produced by `messagefoundry verify --report-md <path> --report-json <path>` plus `GET /audit/export` for the window; `forbidden-content` is green; no routable IP, real hostname/domain/partner name, or message body appears anywhere in it.
13. **No P1 row is silently skipped.** Each of AUTH-04, 07, 13, 14, 21, 22, 23, 24, 25, 31, 32, 33, 34, 35, 36, 42, 43, 45, 48, 49, 52, 53, 54, 55, 56, 59, 60, 61, 64 is PASS, FAIL-with-disposition, or explicitly deferred with an owner-signed reason and a target release.

### 9.9 Open questions

1. **Read access to the withheld `docs/security/` tree.** `AD-FEDERATION-LAB-RUNBOOK.md` (cells L0–L18), `KERBEROS-EPA-SPIKE-RUNBOOK.md`, `THREAT-MODEL.md` and the ASVS assessment all **exist**; the whole directory is deliberately **withheld from the public repo** (`.gitignore:144`, ~32 files of posture / assessment / risk-register / runbook detail held back as an attacker roadmap; `docs/BACKLOG.md:271` records it as "gitignored post-cutover"). That is why `docs/SECURITY.md:1556` and `HANDOFF-AD-LAB-aws.md:7-9` link to paths that do not resolve from this tree — a publishing boundary, not a gap, so this chapter cites them as sound evidence. The question is operational: will the chapter author get read access, so the AD-lab rows can cite cell numbers as authoritative instead of restating acceptance criteria inline? **Blocks:** nothing structural — only whether AUTH-10/16/17/18/19/20/21 keep their inline restatements (they currently restate, which is safe either way).
2. **Where does the chapter read the fuller backlog ledger?** The committed `docs/BACKLOG.md` is a **published baseline that stops at #231** (`:269`), and `:6041` states the rule outright: an item's absence from it is "a publishing boundary, not evidence of completion". The programme continued past it, so **#274 and #275 are valid, owner-confirmed items** — they surface here only as cross-references (`:177`, `:4170`, `:4172`) because their own entries sit above the baseline. This chapter therefore cites them as sound evidence, annotating "above the published #231 baseline" only where a reader would otherwise go looking for an entry. The open question is access alone: may the author read the fuller ledger to quote #275's own acceptance criteria? **Blocks:** nothing — AUTH-09 and AUTH-10 stand on the code evidence at `auth/ldap.py:300` / `:360` regardless.
3. **May the #275 SPN fix land BEFORE the lab confirms it?** The handoff instructs that L1 runs first and hard-blocks L6 and the #99(e) cells. AUTH-09 is written to fail RED against today's code. **Blocks:** whether AUTH-09 lands now as a failing guard, lands after AUTH-10, or is written to pin today's behaviour and inverted later.
4. **May ADR 0142 / OIDC be described as shipped while its status reads "Proposed — code COMPLETE, awaiting lab validation"?** This chapter labels it *built but unvalidated* throughout. **Blocks:** the wording of AUTH-17..25 pass criteria and whether federated SSO appears in release notes as a feature.
5. **Is an interim containerised LDAP leg acceptable in CI?** The handoff says "Do not wire any of this to CI" — but that prohibition is about a **domain-joined self-hosted runner**. A Samba AD DC container on a hosted runner has none of that blast radius, and Kerberos genuinely needs a DC VM while the LDAP bind does not. **Blocks:** S-AUTH-B, and with it AUTH-01…AUTH-05 (five rows, four of them P0).
6. **Is a multi-domain / cross-forest topology in scope for the AD lab window?** No current cell covers referrals; `ad_domain` is a single scalar. **Blocks:** AUTH-07 and AUTH-33, and the second-domain line item in §9.7.
7. **Should `auto_referrals=False` be set on both `ldap3.Connection` sites?** That is a behaviour change for any deployment relying on referral chasing, so it needs an owner call, not just a test. **Blocks:** AUTH-06's pass criteria (today it asserts only that the decision is *explicit*).
8. **Should `_find_user` reject `accountExpires` / `lockoutTime` / `UF_LOCKOUT`, and would that break a known deployment?** Today only `ACCOUNTDISABLE` is honoured, on the password-free `resolve_principal` path used by Kerberos, OIDC **and** the reconciler. **Blocks:** AUTH-26, 27, 28, 29 — the tests must be written against the decided behaviour, and a change needs a SECURITY.md row plus a CHANGELOG entry.
9. **Is `admin_new_ip_step_up` intended to stay default-OFF at off-loopback exposure?** **Blocks:** AUTH-51 — the plan must know which posture is the *tested* posture.
10. **Who owns closing the `docs/FEATURE-MAP.md` drift** — federated SSO still deferred to 0.2 (`:132`), custom roles absent from §7, `require_mfa` described as Administrator-scoped (`:129`), and "The PySide6 desktop console stays (additive)" (`:130`) contradicting its retirement? **Blocks:** AUTH-63, and whether the master plan cites FEATURE-MAP at all or only code + ADRs.
11. **Do you want a real-browser (Playwright) CI leg for the `/ui` auth surfaces, or does browser behaviour stay entirely manual? And for WebAuthn, which authenticators must be proven — roaming FIDO2 only, or Windows Hello platform too — and is hardware on hand?** **Blocks:** AUTH-45, 46, 61 and the `ui-browser` leg in §9.6 (an **L** effort item).
12. **Is landing the drafted advisory mutation / diff-coverage gates** (`docs/quality-gates/HANDOFF-mutation-coverage.md`, currently DRAFT / ready-to-run) **scoped to `messagefoundry/auth/` + `api/security.py` in this plan, or a separate lane?** **Blocks:** AUTH-62.
13. **Should the retired "channel" vocabulary in the per-connection-scope identifiers** (`allowed_channels`, `set_channel_scope`, `PUT /users/{id}/channel-scope`, `PUT /ad-group-scope-map`, `channels_for_ad_groups`) **be renamed**, and if so before or after this test work? A rename touches all three store backends, the API contract and `docs/SECURITY.md`. **Blocks:** nothing in this chapter (which uses the literal identifiers where a tester must type them), but it will invalidate AUTH-31/32/42's cited symbols if it lands mid-cycle.
