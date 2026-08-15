[← Master Test Plan index](../MASTER-TEST-PLAN.md) · *Part II — Subsystem chapters*

---

## 15. Security Posture, PHI Protection & Supply Chain

**ID prefix:** `SEC` · **Surface:** engine + web console + IDE + CLI + infra (CI/release)
· **Primary risk:** the entire post-2026-07-14 security wave (ADRs 0135, 0138–0153) sits outside the project's own coverage-audit instrument, and the CI gates that hold the rest of the posture up have no guard test — so the newest, highest-blast-radius controls are exactly the ones whose regression would be silent.

---

### 15.1 Scope & objectives

This chapter owns **security as an adversarial discipline**: threat-model-driven *negative* tests that
prove a guard actually **refuses**, rather than asserting it exists. It covers:

- **Transport posture** — the TLS floor, the forward-secrecy cipher gate, KEX-group pinning, the
  bind ladder, and the cleartext-hop refusal authority
  ([`config/tls_policy.py:435` `insecure_hop_disposition`](../../../messagefoundry/config/tls_policy.py),
  `:481 enforce_insecure_hop`; ADR 0092 as amended by **ADR 0153**, which deleted the `is_phi` ALLOW arm
  and `audited_opt_out` so **no data label can permit a cleartext hop**).
- **Posture configuration** — `[security]` (ADR 0118), the `[security].enforcement` REFUSE/WARN dial
  (**ADR 0148**, `config/settings.py:3505`), the **two acknowledged production-PHI carve-outs**
  (**ADR 0140** — `allow_unencrypted_phi_under_strict_enforcement:3510`,
  `allow_single_factor_admin_when_exposed:3552`), and `allowed_client_networks` (**ADR 0151**,
  `:3480-3498` + `api/client_networks.py`).
- **Egress & SSRF** — the eight `[egress]` allow-lists (`settings.py:2395-2465`), the no-redirect
  TLS-verifying opener (`transports/rest.py:209 _NoRedirectHandler`, `:230 _no_redirect_opener`), and
  the AI broker's dedicated endpoint allow-list (`transports/ai_broker.py:80 endpoint_host_allowed`).
- **Injection** — SQL, LDAP filter, OS command, path traversal, spreadsheet formula, CRLF header,
  and **HL7-borne** payloads composed end to end through ingest → Router → Handler → outbound.
- **Untrusted-config execution** — the ADR 0144 handler-security lint (`checks.py:863`
  `_check_handler_security`) and its `--strict-handler-security` block mode
  (`__main__.py:210`), the packaged Semgrep taint rules
  (`messagefoundry/security/semgrep/handler-security.yml`), the ADR 0087 subprocess sandbox
  (`pipeline/sandbox.py`), and the disposition of **ADR 0147** (Status: *Proposed*, no code).
- **Crypto** — at rest (`store/crypto.py`), in transit (**ADR 0138** `store/crypto_transit.py`,
  `mfenc:v3`), key rotation, the persisted GCM invocation bound, and **in-use** protection
  (**ADR 0152** `config/memory_encryption.py` + `crashdump.py`).
- **Secrets** — DPAPI (`secrets_dpapi.py`), env-only `MEFOR_*` provisioning
  (`config/secretprovider.py`), rotation-age alerting, and the customer/PHI leak gate
  (`scripts/security/scan_forbidden.py`).
- **PHI protection** — the redaction chokepoint (`redaction.py:61 redact` / `:81 safe_text` /
  `:94 safe_exc`), support-bundle and metrics scrubbing, and the **ADR 0030** de-identification
  framework's fail-closed leak gate (`anon/leak.py`).
- **AI governance** — **ADR 0135** two-axis clamp and the `/ai/chat` server-side re-resolve
  (`api/app.py:1383-1454`) plus `docs/AI.md`.
- **Process-level failure containment** — the ASVS 16.5.4 last-resort handler
  (`messagefoundry/last_resort.py`: `install_loop_exception_handler`, installed at `api/app.py:5263`;
  `install_excepthook`, installed at `__main__.py:2440`), routing otherwise-unhandled asyncio-task and
  main-thread exceptions through `safe_exc` so no raw traceback — which could quote a PHI-bearing
  argument — escapes.
- **Source-address authority** — `messagefoundry/netaddr.py`, "the ONE place an IP allow-list decision
  is made", shared by the inbound connectors' per-connection `source_ip_allowlist`
  (`peer_ip_allowed`, called from `transports/mllp.py`, `dicom.py:263`, `http_listener.py:374`) and by
  `[security].allowed_client_networks` (`client_network_allowed`, called from
  `api/client_networks.py:159`) — with the loopback carve-out deliberately living on the API side only.
- **PKI helpers** — `messagefoundry/pki.py` (ASVS 11.1.3): PKCS#12 import (`load_pkcs12`), the
  read-only cert inventory (`read_cert_facts` / `CertFacts`) and self-signed dev certs
  (`make_self_signed`) behind the `cert` CLI, sharing its day-math with `pipeline/cert_expiry.py`.
- **Supply chain** — SBOM/VEX/sbomqs (**ADR 0149**), the seven-job `security.yml` gate set, CodeQL,
  zizmor, Scorecard, gitleaks, and release-artifact verification.
- **Licence & copyleft compliance** — the AGPL-3.0-or-later + commercial dual-licence posture
  (`LICENSE`, `NOTICE`, `COMMERCIAL-LICENSE.md`, `CLA.md`, `docs/DUAL_LICENSING_PLAN.md`), the
  licence-completeness of the shipped CycloneDX SBOM (`release.yml:191-196`), and the MPL-2.0
  obligations on the vendored HAPI corpus (`samples/messages/hapi-hl7v2/`).
- **The assurance that does not exist** — no third-party ASVS review, no penetration test, no DAST,
  no fuzzing. Scoping and commissioning those is a first-class deliverable of this chapter (§15.5,
  scenario F).

**Explicitly NOT in scope here** (owned elsewhere; cite, do not restate). *Foreign-ID convention:* a
bare `SEC-nn` (or `HA-nn`, `API-nn`, …) is a row of **this** plan; an `FCP:` prefix marks a
`docs/testing/FEATURE-COVERAGE-PLAN.md` gap ID and a `W25:` prefix a WIN2025 test ID. The three ID
spaces collide, so every foreign ID below is prefixed.

| Out of scope | Owner |
|---|---|
| Authentication mechanics — local/AD/Kerberos/OIDC sign-in, TOTP/WebAuthn ceremonies, session lifecycle, step-up, RBAC role catalogue, field-authz | **AUTH chapter** + `FEATURE-COVERAGE-PLAN.md` §13 `[AUTHN]`, §14 `[RBAC]` |
| At-rest cipher mechanics, key lifecycle, DPAPI round-trip, SecretProvider dispatch, backup crypto | `FEATURE-COVERAGE-PLAN.md` §11 `[CRYPTO]` (FCP:CRYPTO-1…10) |
| De-identification rule model, surrogates, engine↔tee parity, redaction unit behaviour, off-box audit tee, AI clamp truth table | `FEATURE-COVERAGE-PLAN.md` §20 `[ANON]` (FCP:ANON-1…16) |
| The P3 security-negative sweep already closed 2026-07-13 (FCP:ALERT-4, FCP:HTTPFHIR-28, FCP:AUTHN-18, FCP:CFG-16, FCP:FILE-19, FCP:RBAC-4/16/17, FCP:DICOM-18) | `FEATURE-COVERAGE-PLAN.md` §P3 (**CLOSED**) |
| Host-bound security acceptance — DPAPI admin→service identity boundary, real `encrypt=true` with a trusted cert, API loopback bind + unauthenticated reject, NSSM service-account ACLs | `WIN2025-TEST-PLAN.md` W25:S2.2 / W25:S2.6 / W25:S2.8 + `WIN2025-TEST-MATRIX.md` |
| The wheel-only on-box acceptance report split (PASS/FAIL/SKIP/MANUAL) | `docs/testing/VERIFY.md` |
| Throughput measurement rig mechanics | `docs/LOAD-TESTING.md` (`harness/load/`) |

**Recon corrections (verified against HEAD — do not carry the recon's version forward):**

1. **The ADR 0138 audit-MAC residual is CLOSED, not open.** `Cipher.audit_mac_fn()` is dispatched by
   `store/base.py:1778` into **all three** backends (`:1787`, `:1797`, `:1808`), consumed at
   `store/store.py:2178`, `postgres.py:1497`, `sqlserver.py`, and pinned end-to-end by
   `tests/test_asvs_transit_audit_mac_server_backends.py`. The Transit chain is **MAC'd inside the
   vault**, not keyless SHA-256. The genuine ADR 0138 deferrals are the `vault-benchmark`
   throughput spike, the **live** SQL Server / PostgreSQL Transit legs, and Transit↔in-process rotation
   (ADR 0138 status line `:26`).
2. **GitHub Actions ARE SHA-pinned.** Every `uses:` in `codeql.yml` and `scorecard.yml` carries a
   40-char SHA (`github/codeql-action/init@e4fba868… # v4.37.3`,
   `ossf/scorecard-action@2d1146689b… # v2.4.4`). Only the **header comments** are stale
   (`codeql.yml:16-19`, `scorecard.yml:17-19` still claim "on the v3 tag for now" / "pending a SHA-pin
   lookup"). The live control is zizmor's unpinned-uses audit, which is **blocking** but
   paths-filtered to `.github/**`. This is doc drift, not a pinning exposure.
3. **The ADR 0030 leak-check tests are NOT skipped in a source checkout.** `_NO_SCANNER`
   (`tests/test_anon_core.py:36-40`) skips only when `scripts/security/scan_forbidden.py` is absent —
   i.e. on an installed wheel; the file **is** committed. The tests inject a synthetic
   `ESTATE_TOKENS` value (`:234`, `:247`) so the mechanism is exercised locally. What is untestable
   locally is the **real token list's** coverage and the `MEFOR_MIN_DETECTORS` floor.
   `FEATURE-COVERAGE-PLAN.md` FCP:ANON-7's "scanner private" note is stale.
4. **`security.yml`'s header no longer describes its triggers — CLOSED (BACKLOG #1079).** It used to
   carry a paragraph denying a push-to-main trigger that the `on:` block declared a few lines
   beneath it, while the push arm's own comment gave the reason that denial ignored: a fork PR is
   scanned structural-only, so without that arm no fully-loaded scan ever sees fork-contributed
   content. Resolved by **deleting** the header paragraph rather than softening it, so the `on:`
   block is the single definition and each arm carries its own reason.
   `tests/test_security_posture.py::test_the_security_header_does_not_contradict_its_own_triggers`
   refuses the return of a header claim that denies a declared trigger, and fires the detector
   against the historical text in the same run, so its silence on the current header is evidence.
   *(The anchors this finding originally carried — `:11-16` and `:22-23` — had drifted to `:22-27`
   and `:33-34` by the time it was fixed. Locate by construct.)*
5. **`BACKLOG #287` and `#310` are NOT dangling — the recon hit a publishing boundary.** The committed
   `docs/BACKLOG.md` is a **published baseline** that stops at `## 231.` and says so itself
   (`:6041`: the programme "continued past this published baseline — the file you are reading ends at
   #231, while #242–#246 and their successors do not appear in it at all … their absence here is a
   publishing boundary, not evidence of completion"). So `#287` (cited by `docs/SECURITY.md:107` and
   `docs/CONFIGURATION.md:435`) and `#310` (`docs/FEATURE-MAP.md:136`) are **valid, owner-confirmed
   items in the fuller ledger**; the `/ui`-pacing and ASVS-re-score work items do have a tracked home.
   Treat every `#NNN` above #231 in this chapter as sound evidence. The only annotation permitted is
   the neutral "(above the published #231 baseline)", used sparingly — never a doubt-casting one.

6. **`docs/security/`, `docs/reviews/` and `docs/marketing/` are WITHHELD, not missing.** They are
   gitignored post-cutover (`.gitignore:144-146`), and the block's own comment says why —
   "`docs/security/` — 32 files of posture/risk-register detail; an attacker roadmap." Every
   `docs/security/ASVS-*`, `…-RISK-ACCEPTANCE-REGISTER.md`, deployment runbook and AD-federation lab
   runbook this chapter or its neighbours cite is a **real document the owner holds** — it is simply
   not readable from a public checkout of `github.com/MEFORORG/MessageFoundry`. Never write
   "missing", "absent" or "does not exist" of one; the accurate phrasing is **withheld from the
   public repo**. What is genuinely open is narrower and is what SEC-69 scopes: no *public, machine-
   readable* linkage exists for a CI drift guard to read.

---

### 15.2 Already covered — do not re-test

| Evidence | What it proves |
|---|---|
| `tests/test_tls_policy.py` (543 lines) | Cipher-string validation rejects non-forward-secret KEX; `APPROVED_KEX_GROUPS` are all ECDHE; `VERIFY_X509_STRICT` is idempotent and flag-preserving; the **full** `insecure_hop_disposition` precedence table including "no longer takes a data label" and "strictly stricter than before"; `enforce_insecure_hop` REFUSE raises / WARN logs+audits; `HopPosture.fail_closed`; every shipped context shape negotiates **zero** non-FS suites (printed as a measurement, not an assertion of intent). |
| `tests/test_hop_refusal_{http,rawtcp,db_inbound,log_forwarding,revocation,wiring,serve_clamp,residuals}.py` (~3,054 lines) | Per-cell cleartext-hop refusal across the HTTP family (REST/SOAP/FHIR/DICOMweb/SMART/http_auth), raw TCP/MLLP/X12, DB inbound + `db_lookup`, `[logging]` syslog forwarding, revocation, the serve clamp, and the ADR 0092 deferred residuals. Each pairs a REFUSE with an ALLOW so the guard bites without false-closing. |
| `tests/test_security_posture_defaults.py` (502) | Shipped `[security]` defaults are the hardened values and are not themselves loosenings; every `[security]` bool at its insecure value is named by `security_loosenings()` (`settings.py:3940`); `cleartext_accepted` / `FhirLookup` declarations are read from the loaded graph; a completeness floor over `[store]`/`[auth]` bools **with an enumerated exemption set** (`:396`, `:412`). |
| `tests/test_security_config.py` (411) + `tests/test_security_cli.py` (169) | `[security]` desugaring, rejection of relocated legacy keys as file/env input, and the `messagefoundry security show\|set` CLI (`__main__.py:330`). |
| `tests/test_client_network_allowlist.py` (725) | ADR 0151 against the **real** uvicorn `ProxyHeadersMiddleware`: only `scope["client"]` is evaluated, an attacker `X-Forwarded-For` is ignored with no declared proxy, the empty default is byte-identical from every address, a denial is diagnosable, and `/health` stays reachable. |
| `tests/test_memory_encryption_readout.py` (746) | ADR 0152 rungs 1-2: platform read-out sourcing, the four posture fields plus the in-body disclaimer, tri-state declaration/read-out contradiction reporting, and the opt-in refusal under `require_memory_encryption_declaration`. |
| `tests/test_api_security_posture.py` (301) | `GET /security/posture` shape, the two ADR 0140 carve-outs surfacing as named loosenings, and cipher **fingerprint** exposure only — never key bytes. |
| `tests/test_egress_allowlist.py` (194) + `test_direct_transport.py:375-395` + `test_remotefile_transport.py:815-870` | Per-transport egress refusal at load/`build_check` for all eight lists, `deny_by_default` over dial-out sources and lookups, and `fhir_require_structured_params` threading into the executor. |
| `tests/test_asvs_phase0.py` (404) | Security headers, WS Origin check, pinned argon2 params, log-injection control-char scrub, request length limits, webhook egress + `_NoRedirectHandler` 3xx refusal, file content sniff, refusal of insecure TLS overrides, `LdapAuthenticator` refusing disabled cert verification. |
| `tests/test_security_static.py` (1,077) | No catastrophic regex anywhere in `messagefoundry/` + `messagefoundry_webconsole/` + `harness/` (with planted-pattern meta-tests); a single JSON parser; a single URL parser; XML parsers confined to a hardened allow-list; crypto roots carry no unrecorded call site. |
| `tests/test_csv_formula_consistency.py` (570) | ASVS 1.2.10: **one** canonical spreadsheet-formula trigger set shared by `messagefoundry/spreadsheet.py` (79) and its deliberate harness mirror `harness/_spreadsheet.py` (97) — separate modules on purpose, because the harness must not import engine internals (CLAUDE.md §4/§10). Every writer's trigger set is the canonical one; every writer emits byte-identical output over a shared vector list; matching is full-value, not `value[:1]` (the original defect: `"   =evil()"` rode through); and an AST inventory of every module that binds `csv` under any import form, or imports a spreadsheet library, means a sixth writer cannot appear outside the gate. Covers the `.xlsx` half with a stubbed openpyxl. Named residual: a dynamically-imported writer is invisible to a static scan. |
| `tests/test_asvs_gcm_invocation_bound.py` (721) | ASVS 11.3.4: the per-key AES-GCM invocation count is **persisted**, survives store reopen, aggregates across handles on one unified store, warns at 2³¹ through the AlertSink, refuses at 2³², a new `key_id` starts at zero with the old row retained, and DR backup frames advance the same counter. |
| `tests/test_asvs_audit_constant_time.py` (330) + `tests/test_asvs_transit_audit_mac_server_backends.py` | ASVS 11.2.4 on all three backends: every row MAC and the external anchor go through `hmac.compare_digest` (**counted** via monkeypatch, not grepped) and the walk never returns early. The Transit rider pins `audit_mac_fn` through all five seams on SQL Server + PostgreSQL. |
| `tests/test_audit_integrity.py` (521) + `tests/test_audit_offbox_tee.py` | Hash-chain integrity, rekey-audit keying migration + idempotence, store-level refusal on a broken chain, and the single redacted metadata-only off-box tee with live SQL Server + PostgreSQL legs. |
| `tests/test_crypto_transit.py` (444) | ADR 0138: `mfenc:v3` round-trip, cell-AAD forwarded as Transit `associated_data`, fail-closed on missing config / unreachable Transit, no ciphertext or key material in exception text, default provider unchanged, unknown provider fails closed — including 2 live OpenBao 2.6.0 integration tests. |
| `tests/test_redaction.py` (123) + `tests/test_logging.py` | `redact`/`safe_exc`/`safe_text` over HL7 segment and field spans, the DOB/name heuristic, ReDoS-linearity and idempotence; redaction filters on **every** log sink, traceback/`stack_info` scrubbing, JSON newline escaping, python-hl7 value-logger silencing, and the prod-DEBUG serve refusal. |
| `tests/test_last_resort.py` (104) | ASVS 16.5.4 at unit level: the asyncio loop handler **and** `sys.excepthook` both route an unhandled exception through `safe_exc` — exception type preserved, the planted PHI fragment absent from the log record — `KeyboardInterrupt` passes to `sys.__excepthook__` untouched, and a framed MLLP listener survives a raising handler (connection drops, server stays up). What it does **not** prove: that the handlers are installed in a real serving process, or that the redacted record stays clean across *every* configured sink (SEC-73). |
| `tests/test_cert_cli.py` (446) + `tests/test_cert_expiry.py:308-312` | `messagefoundry/pki.py` exercised through the `cert` CLI: in-memory `.pfx` bundles built with `pkcs12.serialize_key_and_certificates`, `read_cert_facts` staying best-effort on an unparseable extension rather than sinking the cert, and `pki._SECONDS_PER_DAY` pinned equal to `pipeline/cert_expiry.py`'s. No adversarial PKCS#12 corpus and no key-material-egress assertion (SEC-75/SEC-76). |
| `tests/test_anon_core.py` (326) + `test_anon_integration.py` + `test_anon_parity.py` | ADR 0030 end to end: salt-keyed determinism + weak-salt reject, the two-layer rule model, structure-preserving surrogates, FREETEXT blunt redact + OBX-2 gating, MSH-separator whole-field write, fail-closed no-MSH refusal, field-anchored site-code scrub, engine↔tee byte-identical parity. |
| `tests/test_checks_handler_security.py` (1,079) | ADR 0144 lint: all five rule families across their three scoping regimes (`impure-transform` decorated-scope, `phi-to-log` every-function-body per BACKLOG #337, the rest whole-module), the operator allow-root escape, and the advisory-vs-strict `CheckResult` shape. |
| `.github/workflows/security.yml` `semgrep` job + `scripts/ci/assert_semgrep_handler_taint.py` | The packaged `handler-security.yml` rules are syntactically valid, the two recovered false-negatives fire exactly as annotated, `# ok` cases stay clean, and `samples/config` scans clean under `--error`. |
| `tests/test_sandbox.py` (293) | ADR 0087: off-mode byte-identical in-process call, worker bootstrap, forbidden-import guard, resource caps, fail-closed `SandboxError` routing to ERROR/dead-letter post-ACK, and the `db_lookup`/`fhir_lookup` refusal. |
| `tests/test_secrets_dpapi.py` (125) + `test_secretprovider.py` + `test_backup_crypto.py` | DPAPI machine- and user-scope round-trip (Windows-only), SecretProvider `none`/`env`/`vault` dispatch with fail-closed ref-without-provider and empty-value, and `.mfbak` chunked-AEAD tamper detection. |
| `tests/test_no_store_phi_coverage.py` (187) | ASVS 14.2.2 **inverse** guard: every PHI-read route's path must be matched by a `_NO_STORE_PREFIXES` entry (`api/app.py:331`), so the next uncovered PHI read reds the suite. |
| `tests/test_phi_at_rest_inventory.py` (1,130) + `tests/test_phi_logging_inventory.py` (762) | Doc-as-control drift guards: every cipher-covered `(table, column)` pair derived from `cell_aad` call sites and per-backend `_CIPHER_COLUMNS` must appear in `PHI.md` §2/§3/§8; every `purge_*` on the Store protocol must exist on all three backends and be documented. Includes a planted-omission self-test. |
| `tests/test_support_bundle.py` (236) + `test_metrics_exporter.py:122` + `test_crashdump_suppression.py` (120) | Support bundle carries counts/names only, log tail redacted, SQLite store path reduced to a basename, server host/database hidden; `/metrics` never leaks a body sentinel and the label-name set is pinned; crash-dump suppression no-ops off Windows and reports its residual. |
| `tests/test_ai_policy.py` (403) + `tests/test_ai_broker.py` (357) | AI policy truth table + exhaustive clamp sweep, posture derivation, `ai:assist` RBAC gating, tokenless-null `GET /ai/policy`; broker endpoint allow-list SSRF refusal, off-event-loop execution, exact prompt pass-through with no server-side widening, and no prompt/reply/api_key in logs or the audit row. |
| `packaging/messagefoundry-webconsole/tests/` (14 modules, 8,471 lines) | The whole `/ui` hardening surface — CSP canary (691), hardening (337), Sec-Fetch/Origin CSRF guard (287), session watchdog (492), static-mount allow-list (135), MFA gate (268). Runs as the *Web console tests (pytest)* leg at `.github/workflows/ci.yml:245`. |
| `tests/test_mllp_tls.py` (328) + `test_api_tls.py` (1,300) + `test_listener_tls_exposure.py` + `test_dicom_scp_security.py` | TLS 1.2 floor asserted on server and client contexts, mTLS `CERT_REQUIRED`, `verify_tls=false` refused without the escape, a real MLLP-over-TLS round trip, a plaintext client cannot talk to a TLS listener, non-loopback plaintext refused per connector type, DICOM SCP failing closed. |
| `tests/test_tls_trust_anchor.py` + `test_tls_expiry_relaxation.py` + `test_cert_cli.py` + `test_cert_expiry.py` + `test_runbook_proxy_tls_floor.py` | ADR 0093 pinned-CA resolution, ADR 0094 expiry-only relaxation, the `cert` CLI, cert-expiry alerting with an injective throttle key, and the documented reverse-proxy TLS floor. |
| `tests/test_security_doc_drift.py` (1,723) + `test_docs_security_pathways.py` (497) + `test_security_doc_rate_limits.py` | `SECURITY.md` route→permission map, permission catalogue, role matrix, `/ui` route map, ungated-route allow-lists, field-level authz table in both directions, contextual-input inventory, rate-limit settings coverage, authentication-pathway strength table. Includes planted-mutation self-tests. |
| `tests/test_ci_venv_pinning.py` (346) + `tests/test_release_pipeline.py` (508) | Every release-path venv install is hash-locked; `security.yml`'s unpinned installs are an **enumerated register** (`:275`) not open-ended; `security.yml`'s SBOM command is byte-identical to `release.yml`'s (`:305-325`); the PyPI publish is last, tag-gated and Trusted-Publishing; SBOM + VEX are Sigstore-signed and attached. |
| `tests/test_sbom_finalize.py` (131) + `test_crypto_inventory_scanner.py` (132) + `test_crypto_inventory_doc.py` + `test_scan_tokens_source.py` (812) + `test_scan_forbidden.py` (255) | SBOM lifecycle-phase and dynamic-version finalization; the crypto-inventory scanner flags an undocumented call site; every `[store].cipher_provider` value is documented; forbidden-token source-loading, synthetic-example recognition, and detector-floor **parsing**. |
| `FEATURE-COVERAGE-PLAN.md` §11 `[CRYPTO]`, §20 `[ANON]`, phase **P3** (CLOSED 2026-07-13) | Owns at-rest crypto / key lifecycle / DPAPI / secrets (FCP:CRYPTO-1…10) and de-identification + redaction + audit tee + AI clamp (FCP:ANON-1…16), plus the closed P3 security-negative sweep. |
| `WIN2025-TEST-PLAN.md` W25:S2.2 / W25:S2.6 / W25:S2.8 + `WIN2025-TEST-MATRIX.md` + `docs/testing/VERIFY.md` | Host-bound security acceptance: DPAPI across the admin→service identity boundary, real `encrypt=true` with a trusted cert, API loopback bind + unauthenticated reject, NSSM service-account ACLs, and the honest PASS/FAIL/SKIP/MANUAL reporting split. |
| `docs/Secure_Build_Scorecard_MEFOR.md` (150 lines, A− on 2026-07-14) | A per-signal evidence audit across 12 signals, naming **signal 10** (independent external verification) as the single grade-capping structural absence. |
| `docs/SECURITY-LOOSENING.md` (424 lines) | The deliberate-deviation register: every `[security]` switch with its secure default, what is lost, when acceptable, compensating controls, the two No-loosen invariants including the ADR 0140 carve-outs, and NIST/HIPAA control mappings. |

**What is DONE and must not be re-planned.** The cleartext-hop **decision table** and its per-cell
enforcement are exhaustively covered — do not write another precedence test; extend the existing
`test_hop_refusal_*` family if a new cell lands. The `[security]` **desugaring**, its defaults, and
the CLI are settled. The `/ui` **CSP / CSRF / session** surface is the best-covered security area in
the product (8,471 lines) — the only remaining question there is *browser* enforcement, not header
emission. The at-rest **cipher mechanics**, **GCM invocation bound**, **audit-chain constant-time
verification** (all three backends, including under Transit), and the **de-identification rule
engine** are closed; this chapter adds only the composition, the live/host legs, and the drift
guards around them. The **P3 security-negative sweep** (`FEATURE-COVERAGE-PLAN.md` §P3) is CLOSED —
its nine rows are settled evidence, not open work.

---

### 15.3 Risk analysis

| Risk | Failure mode | Blast radius | Detected today? | Priority |
|---|---|---|---|---|
| The post-2026-07-14 security wave has no coverage-plan owner | `FEATURE-COVERAGE-PLAN.md` is dated 2026-07-13/14 and contains **zero** references to ADRs 0135, 0138–0153 (verified by grep). Every "is it covered?" answer drawn from it is wrong by omission for exactly the newest controls. | The enforcement dial, both ADR 0140 carve-outs, `allowed_client_networks`, in-use protection, the cleartext-hop collapse, the Transit cipher, the handler-security lint, hardened runtime isolation, SBOM/VEX | **No** — the gap-audit instrument itself is the blind spot | **P0** |
| A one-line YAML edit disarms the whole blocking CI gate set | Adding `continue-on-error: true` or an `if:` to any of the seven blocking `security.yml` jobs converts it to advisory with a green tick. The guard pattern exists for `freethread-smoke.yml` (`tests/test_freethread_smoke_liveness.py:55`) and `quality-advisory.yml` (`test_quality_advisory_invariants.py:132`) but was **never extended to `security.yml`** | pip-audit, npm-audit, bandit, gitleaks, semgrep, crypto-inventory, forbidden-content — every SAST/SCA/secret/leak control the Secure Build Scorecard grades "Strong" | **No** | **P0** |
| The leak gate's detector floor is unasserted **in its production VALUE** — narrowed 2026-08-15 | **RE-MEASURED (BACKLOG #1100). Two of the three "nothing asserts" clauses are now FALSE**, and the anchor drifted (`security.yml:403` cited; `MEFOR_MIN_DETECTORS` is at **`:674`**, commented at `:655`). `test_scan_tokens_source.py` now carries **56 tests**: the spec **is** parse-asserted (`test_min_spec_parsing_rejects_nonsense`, `test_unrecognised_require_value_refuses`), and a **partially-mangled secret IS covered** (`test_present_but_unusable_token_source_fails_closed`, parametrized over `mangled` — its docstring records that a mangled secret once "yielded ZERO detectors"). **Materially, the estate half no longer depends on the token list at all:** BACKLOG #321's structural estate-identifier *shape* detector fires with **no token source present** (`test_estate_identifier_shape_is_flagged_without_any_token_source`, `test_the_estate_identifier_shape_detector_is_live`, and `test_allowlist_rejects_an_entry_broad_enough_to_disable_the_estate_shape`). **DEPENDENCY, STATED SO A PARTIAL LAND IS OBVIOUS: that detector is commit `c3959449`, which is on the builder branch and NOT on `main` — if this row lands without it, this cell is wrong** | Real partner/site names reaching a **public** repository. The **estate** half of that radius is now structurally covered; the **names** half still rests entirely on the token list | **Still the gap, and it is the one that cannot be closed the easy way:** every floor test uses a SYNTHETIC floor (`names=2 + estate=2 + site_prefixes=1`), so nothing asserts the real `names=7,estate=13,site_prefixes=1`. It **cannot** be asserted from a checkout — `scan-tokens.local.txt` is gitignored and the real list arrives only via `MEFOR_FORBIDDEN_TOKENS`. Any fix has to compare the floor to the list **inside the gate run**, not in pytest | **P0** |
| Nothing external has adversarially challenged the posture | No third-party ASVS review, no penetration test, no DAST, no fuzzing. No `hypothesis`/`atheris`/`schemathesis`/ZAP in `pyproject.toml` or any workflow. Held by a dated signed risk acceptance that **voids on any off-loopback or production exposure** (`Secure_Build_Scorecard_MEFOR.md:63`; `BACKLOG.md:390` — external review + pentest are the GA/v1.0 gate) | The entire security claim set is self-assessed and AI-assisted | **No, by definition** | **P0** |
| A correctly-configured Transit PHI instance is refused at startup | `__main__.py:1161` keys the keyless-PHI refusal on `settings.store.encryption_key or …encryption_key_file` — **cipher_provider-blind**. A `cipher_provider=vault_transit` deployment sets `MEFOR_STORE_TRANSIT_*` instead, so the *strongest* at-rest posture trips "no key → refuse to start" (exit 2). The documented workaround makes the operator assert `allow_unencrypted_phi` about the most-protected configuration | ADR 0138 unusable on the PHI instances it exists for; `GET /security/posture` and the loosening register report a falsehood | **No** — no test drives `serve` with `cipher_provider=vault_transit` | **P1** |
| The `/ai/chat` scope control is an honour-system label | `api/app.py:1417-1423` compares `body.data_scope` only; nothing inspects prompt **content**. Any `AI_ASSIST` holder can paste an HL7 body into a `code_only` prompt and have it brokered off-box. The audit records `prompt_chars`, not content (`:1449`) | The only sanctioned PHI-egress-shaped path in the product; a single pasted body is an unlogged PHI disclosure to a third party | **No** — no test, no detector, no written disposition | **P1** |
| The static half of the ASVS 15.2.5 defence never blocks | `--strict-handler-security` (`__main__.py:210`) runs in **no** shipped CI leg or pre-commit hook (verified by grep over `.github/` and `.pre-commit-config.yaml`). Default is advisory | Routers/Handlers execute in the engine process alongside the DEK, audit chain and every live socket | **No** — the block mode is never exercised end to end | **P1** |
| The runtime half is unavailable in practice, not merely off | `[sandbox].mode` defaults `off`; in subprocess mode `db_lookup`/`fhir_lookup` are refused fail-closed (`pipeline/sandbox.py`), and ADR 0147 (which would forward them over IPC) is **Proposed with no code**. **No shipped config, sample or harness graph sets `[sandbox]`** (verified by grep over `samples/`, `harness/config/`, `docker/`) | Every real feed using ADR 0010/0043 enrichment is structurally excluded from the boundary | **No** — the register says "off by default", not "unavailable" | **P1** |
| LDAP filter injection | `auth/ldap.py:57 _escape_filter` escapes only `\ * ( ) NUL` and is interpolated into three filters (`:166`, `:167`, `:208`) built from an attacker-supplied username/UPN and a user DN. **Zero tests** reference `_escape_filter` | User enumeration or an authentication-decision bypass against the directory; the username is the login form's free-text field | **No** — deleting the escape breaks nothing | **P1** |
| The loosening register under-reports the real posture | Seven credential-bearing switches are exempted by name: `[store].encrypt`, `trust_server_certificate`, `[auth].enabled`, `require_mfa`, `ad_tls_verify`, `ad_allow_insecure_ldap`, `oidc_require_mfa_claim` (`tests/test_security_posture_defaults.py:396-441`; `docs/SECURITY-LOOSENING.md` calls it "owed work") | An operator reading the console's loosening list sees a hardened posture while `ad_allow_insecure_ldap` or `trust_server_certificate` is on | Enumerated, not closed | **P1** |
| The TLS floor is proven by construction, never observed | Every guarantee is asserted as an `SSLContext` **attribute** (`test_tls_policy.py:426`, `test_mllp_tls.py:79`, `test_api_tls.py:81`). No test drives a client offering only TLS 1.0/1.1, or only a non-FS suite, against a live listener and observes the refusal | A call site that builds a context without `harden_cipher_suites`, or an OpenSSL/system policy override at negotiation time, is invisible | **No** | **P1** |
| Nothing validates the VEX document | `security/vex/messagefoundry.openvex.json` holds `"statements": []`. Nothing checks schema conformance, the mandatory `justification` on every `not_affected`, the version-bump-and-timestamp discipline its own README mandates, or that trivy can parse it | It ships as a **signed release artifact** operators feed their own scanners, and is applied to our own trivy gate — a malformed or over-broad statement silently suppresses real CVEs everywhere | **No** | **P1** |
| SBOM + container CVE gates are advisory *and* cron/dispatch-only | `security.yml:117`/`:121` and `:204`/`:210` — both carry `continue-on-error: true` **plus** `if: schedule \|\| workflow_dispatch`. sbomqs scores print with no floor (`:181-183`); `trivy config` is `\|\| true` (`:256`) | `docs/SUPPLY-CHAIN.md` sells the program to hospital security teams; a fixable HIGH/CRITICAL in the image never blocks a PR and surfaces ≥24h late | **No** | **P1** |
| No adversarial corpus drives HL7-borne injection end to end | Individual sinks are guarded (read-only `db_lookup`, traversal guards in `uploads.py`/`transports/file.py`/`config/codeset_edit.py`/`transports/fhir.py`/`pipeline/dr_backup.py`, alert-template header strip, formula neutralization in `spreadsheet.py`/`config/codeset_edit.py`) but nothing feeds **one** synthetic message carrying SQL + traversal + CRLF + formula + control-char payloads through ingest → Router → Handler → every outbound and asserts each sink neutralizes it | A new outbound connector or report surface joins the graph with no cross-cutting negative test | **No** | **P1** |
| `allowed_client_networks` goes inert without saying so | Documented honest limit at `settings.py:3492-3495`: behind NAT, an undeclared proxy, or a bridge-networked container every request looks like the intermediary. Only `/health`'s `observed_client` echo (`api/client_networks.py:204`) reveals it; no startup check warns | An operator who names a ward subnet believes they have a source-network control that permits everyone | Diagnosable, not detected | **P2** |
| The `/ui` write path charges no anti-automation pacing | `docs/SECURITY.md:102-108`, `:614`: `allow_admin_write` has **zero** callers in `messagefoundry_webconsole`; `POST /ui/config/reload`, the `/ui` purge and replay routes are unpaced. No test pins the currently-unpaced set. It **is** tracked — `BACKLOG #287`, above the published #231 baseline — so the gap is the missing pin, not a missing ledger item | The console is the surface a stolen session is most likely to drive; purge/replay/config-reload are exactly what ASVS 2.4.2 pacing bounds | Documented, unpinned | **P1** |
| No **public, machine-readable** linkage from the assessment to the code | The assessment corpus is real and maintained but **withheld from the public repo** — `docs/security/` is gitignored post-cutover (`.gitignore:144`) as a deliberate attacker-roadmap decision, so no in-repo job can read it. ADR 0148's per-cell re-score + owner re-signature are pending (ADR status line); `FEATURE-MAP.md:136` records scoring under reconciliation with no quotable figure, tracked as `BACKLOG #310` (above the published #231 baseline) | No automated check in a public CI run can hold the shipped code to the assessment; the corpus itself is available to an evaluator under NDA | **No** | **P1** |
| Startup wheel-integrity is alert-only by default | `messagefoundry/integrity.py` — default alert-only, `[integrity].fail_closed_on_drift` opt-in, and a **no-op on any editable install**. No test that a recommended deployment profile enables it; no coverage of what an operator sees when drift fires under NSSM | An admin with venv-write + restart rights can neuter field-authz redaction or the off-box audit tee and the engine keeps running the tampered bytes | Alert exists; enforcement is unproven | **P2** |
| ECH's central claim is unprovable, and its shipped Go code was unbuilt and untested (**resolved 2026-08-10, #1011**) | The engine-side hop (ADR 0139 Increment 1) routes egress to a loopback sidecar but **does not originate ECH**; `tests/test_ech_egress.py` (183) proves routing + fail-closed against a stub only, and now says so in its own docstring. The terminating re-originator **did** ship as `tools/ech-sidecar/` (Go, `main.go` 312 lines + `go.mod` + `README.md`) with no `setup-go`/`go build` step in any workflow and `pyproject.toml:21` keeping `tools/` out of wheel and sdist — it was **retired** on 2026-08-10 (SEC-71), and ADR 0139's status block no longer files it under "Deferred". The 2026-07-20 DoH probe found no partner publishing an ECHConfig | The unbuilt-Go half is closed by deletion. **The first half stands:** any downstream "supports SNI hiding" statement would still be unproven, and enabling `ech_egress` without a conforming operator-supplied sidecar breaks real egress for zero privacy benefit — by design, since the alternative is a silent SNI-leaking fallback | ADR 0139 and `docs/SECURITY.md` now agree with the tree; still invisible in the product | **P2** |
| Nothing measures the enforcement cost of the strongest posture | No load-harness leg quantifies `[sandbox].mode=subprocess`, `cipher_provider=vault_transit` (a network round trip **per encrypted cell** per read *and* write — `ASVS-L2-PHASE0-CHANGES.md:340`), or `ClientNetworkMiddleware` on the hot API path. ADR 0138 explicitly defers the `vault-benchmark` spike | An operator hits a throughput cliff at go-live and turns the control back off — the worst outcome, and one the project never sees | **No** | **P2** |
| Operator-facing security documentation understates the shipped posture | `docs/SECURITY.md:1809-1831` (*Supply-chain & CI security*; filed as `:1753-1775`, already 56 lines stale before #1011 and 8 more since — see SEC-07) calls pip-audit and bandit "advisory for now", lists SBOM and a gitleaks full-history scan as "Planned CI additions", and says CodeQL/secret scanning need GHAS on a **private** repo. All are built and blocking; the repo is public; `codeql.yml` exists. `FEATURE-MAP.md:132` marks Federated SSO "0.2 deferred" while ADR 0142 is code-complete with `tests/test_auth_oidc*.py`; `:211` marks release Sigstore+SBOM planned while `release.yml:194-332` ships it; `:131` and §10 present the retired PySide6 desktop console as a live operator surface | The capability catalogue an evaluator, a new contributor and this plan reason from is wrong **in both directions**, with no drift guard | **No** — `test_security_doc_drift.py` covers only the route/permission map | **P2** |

---

### 15.4 Test matrix

**Row class (`Cls`).** **T** = *Test* — a falsifiable assertion with an observable pass criterion;
**only T rows count toward the release gate**. **C** = *Characterisation* — produces a recorded
measurement, finding or dated decision with no threshold yet ("record the outcome", "publish a
number", "a dated owner decision"); legitimate work, but it **cannot fail**, so it never gates a
release. A C row becomes a T row the day its threshold or decision is recorded. **A** = *Assurance* —
an external engagement (third-party review, penetration test, DAST); blocking **only** for an
off-loopback / production-exposure release, advisory otherwise, and **excluded from the ordinary P0
count**.

This chapter has **79 rows: 66 T, 10 C, 3 A**. Among the T rows **8 are P0** — SEC-01, SEC-02,
SEC-03, SEC-04, SEC-05, SEC-06, SEC-45, SEC-67. The three **A** rows (SEC-64, SEC-65, SEC-66) were
previously carried as P0 tests; their pass criterion is a procurement event, so they cannot sit in a
countable per-release gate and their `Pri` cell reads **P0 (exposure)** rather than a plain P0. They
stay prominent for a different reason: **the project's standing signal-10 risk acceptance is void on
any off-loopback or production exposure** (`docs/Secure_Build_Scorecard_MEFOR.md:63`), so on such a
release all three become blocking and the acceptance no longer covers anything at all. The **C** rows
are SEC-38, SEC-39, SEC-43, SEC-44, SEC-54, SEC-59, SEC-68, SEC-69, SEC-70, SEC-71.

**Rows SEC-73 to SEC-79 close four unowned surfaces**: the process-level last-resort handler
(`last_resort.py` — SEC-73), the single source-address authority (`netaddr.py` — SEC-74), the PKI
helpers (`pki.py` — SEC-75, SEC-76), and **licence / copyleft compliance**, which had no coverage
anywhere in the plan despite an AGPL-3.0-or-later + commercial dual licence (SEC-77, SEC-78, SEC-79).

**Foreign IDs** carry a prefix: `FCP:` = `docs/testing/FEATURE-COVERAGE-PLAN.md`, `W25:` = the WIN2025
plan/matrix. A bare ID is this plan's own row.

| ID | Test | Type | Method | Env | Backend | Cls | Pri | Pass criteria |
|---|---|---|---|---|---|---|---|---|
| SEC-01 | ADR coverage ownership **and** ADR-status-vs-code hygiene | Negative/Security | pytest | any | n/a | T | P0 | **Owner row for the ADR-status-vs-code hygiene guard** — PIPE-35, CONN-37 and STORE-54 point here; no separate guard is scoped in those chapters. A new `tests/test_security_wave_coverage_owner.py` asserts two things over the 148 numbered records in `docs/adr/` (highest allocated **0153**). **(a) Coverage ownership:** every `docs/adr/01[3-9]*.md` whose body names a `messagefoundry/` path has its ADR number in `docs/testing/FEATURE-COVERAGE-PLAN.md` **or** in this chapter's owner table — today ADRs 0135, 0138, 0139, 0140, 0144, 0147, 0148, 0149, 0151, 0152 and 0153 fail, and once the owner table lands, adding an ADR without an owner row reds the suite. **(b) Status-vs-code hygiene:** an ADR's `Status:` line and the presence of the first-party modules it declares as its deliverable must agree — a `Proposed` ADR may not have its declared module shipped (ADR 0147 is the live case: Proposed, no code) and an `Accepted`/`Implemented` one may not be missing it — with an enumerated exemption register carrying a written reason per partial delivery. **ADR 0139 WAS the live case for this half too, in the opposite direction** — its status block filed the terminating re-originator under "Deferred (the real ECH work)" while `tools/ech-sidecar/` shipped it, a shipped deliverable an ADR called deferred. That case was **closed 2026-08-10** (SEC-71, BACKLOG #1011) by retiring the tree and reconciling the ADR, so the guard has **no live example in this direction** and must get one from its planted-omission self-test rather than from the corpus. A planted-omission self-test in **each** half proves the guard bites. |
| SEC-02 | The seven `security.yml` jobs stay BLOCKING | Negative/Security | pytest | any | n/a | T | P0 | New `tests/test_security_workflow_liveness.py` parses `.github/workflows/security.yml` and asserts each of `pip-audit`, `npm-audit`, `bandit`, `gitleaks`, `semgrep`, `crypto-inventory`, `forbidden-content` has **no** job-level `continue-on-error`, **no** job-level `if:`, and no step-level `continue-on-error` on its scanning step. Mutating any one of the seven in a tmp copy makes the test fail. |
| SEC-03 | Advisory jobs are an enumerated register, not open-ended | Negative/Security | pytest | any | n/a | T | P0 | Same module: exactly `{sbom, trivy}` may carry `continue-on-error` and a `schedule\|\|workflow_dispatch` gate, each with a recorded reason string; a NEW advisory job (or a new `\|\| true` inside a blocking job's `run:`) fails the test. Mirrors the `test_ci_venv_pinning.py:275` register pattern. |
| SEC-04 | `MEFOR_MIN_DETECTORS` floor matches the real token list | Negative/Security | CI-leg | container-CI | n/a | T | P0 | A new step in `security.yml`'s `forbidden-content` job, run **after** the secret loads, calls `scan_forbidden.py --print-detector-counts` and asserts every per-section count is **≥** the floor literal AND that the floor literal is ≥ 80% of the loaded count (so growth is noticed). Deleting the final line of the token list must fail the job, not degrade it. |
| SEC-05 | Absent secret on a non-fork run is a hard failure | Negative/Security | pytest | any | n/a | T | P0 | `tests/test_security_workflow_liveness.py` extracts the `forbidden-content` shell body and asserts the three-branch structure: secret present → `MEFOR_REQUIRE_TOKENS=1` + a per-section floor; `IS_FORK_PR == true` → structural-only; else → `::error::` + `exit 2` (`security.yml:398-413`). Removing the `exit 2` arm, or changing the floor to a bare total, fails the test. |
| SEC-06 | `LeakCheckUnavailable` is raised, never swallowed | Negative/Security | pytest | any | n/a | T | P0 | Extend `tests/test_anon_core.py`: with `anon.leak._scanner` cache cleared and the scanner path monkeypatched absent, `leak_check()` raises `LeakCheckUnavailable` (`anon/leak.py:44-48`) and `anonymize_checked` propagates it rather than returning a "clean" verdict. Asserts the wheel-install degradation path is loud. |
| SEC-07 | `docs/SECURITY.md` supply-chain section matches HEAD | Negative/Security | pytest | any | n/a | T | P2 | Extend `tests/test_security_doc_drift.py`: for every job name in `security.yml`, the doc's Supply-chain section must classify it BLOCKING/ADVISORY consistently with the YAML; the strings "advisory for now", "Planned CI additions", and both halves of the stale GHAS sentence in `docs/SECURITY.md` — "Enable via **GitHub Advanced Security** in repo settings" and "can't be added by file alone" — must be absent while `codeql.yml` exists and the repo posture is public. Currently red at `docs/SECURITY.md:1809-1831` — the *Supply-chain & CI security* section. **Anchor correction:** the filed `:1753-1775` was already 56 lines stale before #1011 (at base `b52fd844` it landed inside the in-use-memory-protection block), and #1011's rewrite of the 12.1.5 paragraph moved it 8 further. |
| SEC-08 | `docs/FEATURE-MAP.md` security rows match HEAD | Negative/Security | — | any | n/a | T | P2 | **Pointer.** Covered by MIG's consolidated FEATURE-MAP drift-guard row (one row extending `tests/test_feature_map_claims.py`); no separate work scoped. The security-specific claims that row must carry — `[security]`/`enforcement`/`allowed_client_networks`/memory-encryption/cleartext-hop collapse/Transit/ECH/handler-security lint/sandbox/SBOM+VEX/AI broker present; Federated SSO not "deferred" while `messagefoundry/auth/oidc/` exists; release SBOM not "planned" while `release.yml:194-332` ships it; the retired PySide6 desktop console never presented as a live operator surface — are handed to MIG as inputs. The separate `tests/test_feature_map_drift.py` deliverable is **dropped** from this chapter. |
| SEC-09 | Doc links and ledger references resolve | Negative/Security | — | any | n/a | T | P2 | **Pointer.** Covered by MIG's single "doc paths resolve" linter row; no separate work scoped. The security-side input is a **rule the linter must encode, not a list of defects**: `docs/BACKLOG.md` is a *published baseline* that ends at **`## 231.`** and states so itself (`:6041`), so a `BACKLOG #NNN` above 231 is a valid reference into the fuller ledger and **must not** be flagged. The linter therefore checks (a) that every cited `#NNN` **≤ 231** resolves to a heading, and (b) that every path-shaped citation resolves **or** is inside a knowingly-withheld tree (`docs/security/`, `docs/reviews/`, `docs/marketing/` — gitignored, `.gitignore:144-146`), which is reported as *withheld*, never as broken. Reference cases that must stay green: `#287` (`SECURITY.md:107`, `CONFIGURATION.md:435`) and `#310` (`FEATURE-MAP.md:136`). |
| SEC-10 | OpenVEX document is schema-valid and disciplined | Negative/Security | pytest | any | n/a | T | P1 | New `tests/test_vex_document.py`: `security/vex/messagefoundry.openvex.json` parses; `@context` is a recognised OpenVEX namespace; `version` is a positive int and `timestamp` is RFC 3339 UTC; every statement has `vulnerability`, `products`, `status`; every `not_affected` carries one of the five OpenVEX `justification` values; every product ref is a PackageURL. A planted malformed statement fails. |
| SEC-11 | VEX version/timestamp bump on content change | Negative/Security | pytest | any | n/a | T | P2 | Same module: a git-diff-aware check — if `statements` differs from the committed baseline, `version` must have incremented and `timestamp` moved forward. Enforces the discipline `security/vex/README.md` mandates. |
| SEC-12 | trivy can consume our own VEX | Negative/Security | CI-leg | container-CI | n/a | T | P1 | Promote a `trivy sbom --vex security/vex/messagefoundry.openvex.json` dry-run into the blocking path (or a dedicated tiny job): trivy exits 0 and prints no "failed to parse VEX" diagnostic. A deliberately malformed VEX in a tmp copy makes it non-zero. |
| SEC-13 | SBOM + container CVE gates promoted to the PR path | Negative/Security | CI-leg | container-CI | n/a | T | P1 | `security.yml`'s `sbom` and `trivy` jobs run on `pull_request`, carry no `continue-on-error`, sbomqs enforces a numeric floor (`sbomqs score --basic` ≥ an agreed threshold, recorded in `docs/SUPPLY-CHAIN.md`), and `trivy config` drops `\|\| true`. SEC-03's register is updated in the same commit or the register test reds. |
| SEC-14 | Live handshake refusal — obsolete TLS versions | Negative/Security | pytest | dev-PC | n/a | T | P1 | New `tests/test_tls_handshake_refusal.py`: stand up the **real** MLLP-over-TLS listener and the real uvicorn API TLS listener on loopback with a synthetic cert; a client `SSLContext` pinned to `maximum_version=TLSv1_1` raises `ssl.SSLError` on connect against **both**, and a TLS 1.2+ client succeeds against both (so the test cannot pass by failing to connect at all). |
| SEC-15 | Live handshake refusal — non-forward-secret suite only | Negative/Security | pytest | dev-PC | n/a | T | P1 | Same module: a client offering only a non-FS cipher string (e.g. static-RSA/`AES128-SHA`-class) fails the handshake against both listeners; the paired FS client negotiates and `sock.cipher()[0]` is in the approved ECDHE set. This is the observed counterpart to the attribute assertions at `test_tls_policy.py:426`. |
| SEC-16 | Every TLS context builder consumes the hardening authority | Negative/Security | pytest | any | n/a | T | P1 | Extend `tests/test_security_static.py`: AST-walk `messagefoundry/` for `ssl.create_default_context` / `SSLContext(` construction sites; each must be inside `config/tls_policy.py` or call `harden_cipher_suites` / `harden_kex_groups` / `harden_verify_flags` on the result. A planted bare-context site fails. Closes the "a call site built without hardening" hole SEC-14/15 can only sample. |
| SEC-17 | Cleartext-acceptance is audited at EVERY construction | Negative/Security | pytest | any | n/a | T | P2 | Extend `tests/test_hop_refusal_wiring.py`: build the same `cleartext_accepted` connection three times inside one `active_hop_posture` scope and assert three distinct WARN log records **and** three `cleartext_acceptance_audit_sink` records, each naming the declaring connection (`tls_policy.py:510-554`) — an accepted risk that stops being visible has stopped being accepted. |
| SEC-18 | Operator-authored `cleartext_reason` cannot inject into the log | Negative/Security | pytest | any | n/a | T | P2 | Same module: a `cleartext_reason` containing `\n`, `\r`, ANSI escapes and a fake `AUDIT:` prefix is emitted as a **parameter** (never interpolated into the format string) and the ASVS Phase-0 control-char scrub renders it on one line. Pairs with `test_asvs_phase0.py`'s log-injection control. |
| SEC-19 | A hostname resolving to loopback cannot smuggle a cleartext hop | Negative/Security | pytest | any | n/a | T | P1 | Extend `tests/test_tls_policy.py`: `is_loopback_hop_host` returns `False` for a name that resolves to `127.0.0.1` (DNS is never consulted — `tls_policy.py:414-430`), and the enclosing cell REFUSES. Guards the documented anti-rebinding property with a test rather than a docstring. |
| SEC-20 | `enforcement=warn` can only weaken to WARN, never to ALLOW | Negative/Security | pytest | any | n/a | T | P1 | Extend `tests/test_tls_policy.py` with an exhaustive 2⁴ sweep of `insecure_hop_disposition`: for every input tuple, the disposition under `enforcing=False` is WARN or ALLOW and is never *stricter* than under `enforcing=True`; and no combination without `is_loopback_hop`/`hop_attested` yields ALLOW. Encodes ADR 0153's no-loosen-by-construction claim as an executable invariant. |
| SEC-21 | ADR 0140 carve-out 1 — keyless PHI under strict enforcement | Negative/Security | pytest | dev-PC | SQLite | T | P1 | Extend `tests/test_cli.py` / a new `tests/test_serve_security_gates.py`: `serve` on a PHI instance with `allow_unencrypted_phi=true`, `enforcement=enforce`, and **no** `allow_unencrypted_phi_under_strict_enforcement` exits **2** with the `__main__.py:1185-1201` message; adding the second ack starts and emits the AUDIT line naming **both** flags. |
| SEC-22 | ADR 0140 carve-out 2 — single-factor admin at exposure | Negative/Security | pytest | dev-PC | SQLite | T | P1 | Same module: an exposed production-PHI bind with `require_mfa=false` and no `allow_single_factor_admin_when_exposed` exits 2; with the carve-out set it starts, and `GET /security/posture` names the carve-out as a loosening (already asserted shape-wise by `test_api_security_posture.py`). |
| SEC-23 | Loosening-register exemption set is proven, not just enumerated | Negative/Security | pytest | dev-PC | SQLite | T | P1 | Extend `tests/test_security_posture_defaults.py`: for each of the seven "gated elsewhere" exemptions (`[store].encrypt`, `trust_server_certificate`; `[auth].enabled`, `require_mfa`, `ad_tls_verify`, `ad_allow_insecure_ldap`, `oidc_require_mfa_claim`) the test must **drive the claimed gate** and observe the refusal/warning. An exemption whose gate cannot be demonstrated must be moved into the register. |
| SEC-24 | `allowed_client_networks` inertness is reported at startup | Negative/Security | pytest | any | n/a | T | P2 | New behaviour + test: when `allowed_client_networks` is non-empty and the observed peer of the first N requests is a single address that is **not** in the list and **not** loopback while no `trusted_proxies` is declared, the engine emits a WARNING naming the observed address and the inertness limit (`settings.py:3492-3495`). Test drives it through `ClientNetworkMiddleware` with a stubbed `scope["client"]`. |
| SEC-25 | `allowed_client_networks` demonstrated inert behind a bridge network | Negative/Security | acceptance-probe | container-CI | n/a | T | P2 | A container-compose probe: engine in a bridge-networked container with `allowed_client_networks = ["10.99.0.0/16"]`; a request from an address outside that range is **admitted** and `GET /health`'s `observed_client` (`api/client_networks.py:204`) reports the docker-gateway address. The probe's expected result is that the control is inert — the finding is that this is documented and reported, not that it blocks. |
| SEC-26 | Composite SSRF corpus across every dial-out cell | Negative/Security | pytest | any | n/a | T | P1 | New `tests/test_ssrf_corpus.py`: one table-driven suite over REST, SOAP, FHIR, webhook (alerts), DICOMweb STOW-RS, SMTP/Direct, `db_lookup`, `fhir_lookup` and the AI broker. Each cell × each hostile destination (link-local `169.254.169.254`, `0.0.0.0`, an IPv4-mapped IPv6 literal, a decimal-encoded IP, a userinfo-confusion URL `http://allowed@evil/`, a trailing-dot FQDN) must REFUSE at config-load/`build_check`, with a paired allow-listed destination that succeeds. |
| SEC-27 | 3xx PHI-diversion refusal on every HTTP-family opener | Negative/Security | pytest | any | n/a | T | P1 | Extend `tests/test_ssrf_corpus.py`: drive a real 301/302/303/307/308 from a loopback stub through each cell wired to `_no_redirect_opener` (`transports/rest.py:1288`, `:1329`) and assert an `HTTPError` classification, never a followed hop. `test_asvs_phase0.py` covers webhook + one HTTP cell; this extends it to the whole family. |
| SEC-28 | Egress allow-list coverage cannot fall behind new transports | Negative/Security | pytest | any | n/a | T | P1 | Extend `tests/test_egress_allowlist.py` with an **inventory** guard: every destination connector registered via `transports/base.py:register_destination` must map to a named `[egress]` list (`settings.py:2461-2465`) or appear in an enumerated exemption set with a reason. Adding a connector without an allow-list reds the suite. |
| SEC-29 | LDAP filter injection — unit corpus | Negative/Security | pytest | any | n/a | T | P1 | New `tests/test_ldap_filter_injection.py`: a corpus of hostile usernames/UPNs/DNs — `*`, `)(objectClass=*`, `\`, embedded NUL, `\29`, `admin)(\|(uid=*`, a 4 KiB filter-metachar run, and RFC 4515 boundary chars — round-trips through `auth/ldap.py:57 _escape_filter` such that the assembled filters at `:166`, `:167`, `:208` parse to exactly one search term. Deleting or weakening the escape fails the test. |
| SEC-30 | LDAP filter injection — live directory | Negative/Security | manual | AD-lab | n/a | T | P1 | Against the AD-lab directory: submit each SEC-29 payload through the real login form; assert authentication is **denied**, no user enumeration difference is observable (equal response body and timing class between "user exists / wrong password" and "hostile filter"), and the directory logs one malformed-DN-free search. Owned jointly with the AUTH chapter's AD lab; cite `WIN2025-TEST-PLAN.md` for the domain-join prerequisites. |
| SEC-31 | HL7-borne composite injection, end to end | Negative/Security | pytest | any | SQLite | T | P1 | New `tests/test_hl7_injection_endtoend.py`: **one** synthetic PHI-free HL7 v2 message whose fields carry `'; DROP TABLE messages;--`, `..\..\..\windows\win.ini`, `=cmd\|'/c calc'!A1`, `\r\nBcc: attacker@example.invalid`, a `\x00\x07\x1b[31m` control run, and a `${jndi:` token. Drive it through ingest → Router → Handler → **every** outbound (file, MLLP, DB, REST/FHIR, DICOMweb, SMTP/Direct) plus the audit CSV export, the codeset editor and the support bundle. Every sink neutralizes or rejects; the message reaches a terminal disposition (`PROCESSED`/`FILTERED`/`ERROR`); no file lands outside the configured root; no row escapes parameterization. |
| SEC-32 | Path-traversal corpus across every filesystem sink | Negative/Security | pytest | any | n/a | T | P1 | Same module (or a sibling): the traversal corpus (`..`, `..\\`, URL-encoded, UNC `\\\\?\\`, absolute drive path, a symlink out of the root, an overlong name) exercised against `uploads.py`, `transports/file.py`, `config/codeset_edit.py`, `transports/fhir.py`, `pipeline/dr_backup.py`, `config/impact.py`, `corepoint_import.py`. Each refuses with a specific exception; a paired legitimate relative path succeeds. |
| SEC-33 | Spreadsheet-formula neutralization on every export | Negative/Security | pytest | any | n/a | T | P2 | The neutralizer itself and its two-mirror discipline are **already owned** — `messagefoundry/spreadsheet.py` (79 lines) is the engine writer, `harness/_spreadsheet.py` (97) is its deliberate harness mirror (a test harness must not import engine internals, CLAUDE.md §4/§10), and `tests/test_csv_formula_consistency.py` (570) is the gate that holds them together: one canonical trigger set, byte-identical output over a shared vector list, full-value (not `value[:1]`) matching, and an AST inventory of every module that binds `csv` or a spreadsheet library so a sixth writer cannot appear outside the gate. **This row adds only the end-to-end arm** — extend that module so a hostile value arriving as HL7 field content (not a hand-written vector) is neutralized in the audit CSV export, the acceptance report/`.xlsx` write-back and the codeset export (`config/codeset_edit.py`), and record the module's own named residual (a dynamically-imported writer is invisible to a static scan). |
| SEC-34 | OS-command surface stays argv-only | Negative/Security | pytest | any | n/a | T | P2 | Extend `tests/test_security_static.py`: every `subprocess.*` call in `messagefoundry/` and `scripts/` passes a **list**, never `shell=True`, and any operator-supplied component is validated (e.g. `is_safe_service_name`, `settings.py` service-name validator). A hostile service name containing `& calc` is rejected at load. |
| SEC-35 | `--strict-handler-security` block mode runs in CI | Negative/Security | CI-leg | container-CI | n/a | T | P1 | A new step in `.github/workflows/ci.yml` (or the `semgrep` job): `python -m messagefoundry check --config samples/config --strict-handler-security` exits **0**; the same command against a fixture config carrying one planted finding per rule family exits **non-zero** and names all five families. Proves the block mode (`__main__.py:210`, `checks.py:186`) still works and that shipped samples pass it. |
| SEC-36 | A shipped graph runs under the ADR 0087 sandbox | Negative/Security | pytest | any | SQLite | T | P1 | New leg in `tests/test_sandbox.py`: serve `harness/config` (the disposition-coverage graph) with `[sandbox].mode=subprocess` and assert the full RECEIVED→ROUTED→PROCESSED path completes for a synthetic message, with the forbidden-import guard active. Today **no** shipped config sets `[sandbox]` (verified by grep) — the boundary has never been exercised on a real graph. |
| SEC-37 | The sandbox residual is stated as "unavailable", not "off" | Negative/Security | pytest | any | n/a | T | P1 | `GET /security/posture` (or `messagefoundry security show`) reports, when `[sandbox].mode=subprocess` is set, that `db_lookup`/`fhir_lookup` are refused in this mode, and the loaded graph is scanned for either call so an operator is told **at load** that the boundary is incompatible with their config. Test drives both a compatible and an incompatible graph. |
| SEC-38 | Subprocess-sandbox throughput cost is published | Performance | load-harness | dev-PC | SQLite | C | P2 | Run a reference `harness/load/` profile with `[sandbox].mode=off` and `=subprocess` on the same graph and hardware; the report records achieved msg/s and p95 intake latency for both, and the delta is written into `docs/SECURITY-LOOSENING.md` / ADR 0087. Pass = a published, reproducible number, not a threshold. |
| SEC-39 | ADR 0147 has a written disposition | Negative/Security | manual | any | n/a | C | P1 | Either ADR 0147 moves to Accepted with a scheduled increment, **or** the ASVS 15.2.5 runtime residual is recorded as an owner-signed acceptance in the risk register naming the ADR 0010/0043 incompatibility as its cause. Pass = the ADR status line is no longer `Proposed` with no code and no dated decision. |
| SEC-40 | A `vault_transit` PHI instance starts | Negative/Security | pytest | dev-PC | SQLite | T | P1 | New `tests/test_serve_security_gates.py` leg: `serve` with `data_class=phi`, `cipher_provider=vault_transit`, `MEFOR_STORE_TRANSIT_*` set (Transit stubbed) and **no** `MEFOR_STORE_ENCRYPTION_KEY` must **start**, and `GET /security/posture` must NOT report keyless PHI. Today `__main__.py:1161` exits 2. Paired negative: `cipher_provider=vault_transit` with unreachable Transit still refuses. |
| SEC-41 | Transit ↔ in-process rotation | Functional | pytest | dev-PC | SQLite | T | P1 | A store written under `aesgcm` (`mfenc:v1`/`v2`) reopened under `vault_transit` decrypts every existing row and writes new rows as `mfenc:v3`; the reverse direction likewise. Closes the ADR 0138 deferral with a test rather than a note (`ADR 0138:26`). |
| SEC-42 | Transit call-site legs on the server backends | Cross-backend | pytest | container-CI | x2 | T | P1 | Run the `tests/test_crypto_transit.py` round-trip and cell-AAD assertions against **live** SQL Server and PostgreSQL with a live Vault/OpenBao Transit mount, not the stub. Complements `test_asvs_transit_audit_mac_server_backends.py`, which pins the wiring without a live server. |
| SEC-43 | Transit throughput cost is published | Performance | load-harness | dev-PC | x2 | C | P2 | A reference load profile under `cipher_provider=aesgcm` vs `vault_transit` against a co-located Vault: achieved msg/s, p95 end-to-end, and Vault round trips per message recorded. Pass = a published number and an explicit statement of whether `batch_input` is used (it is not today). Closes ADR 0138's deferred `vault-benchmark` spike. |
| SEC-44 | `ClientNetworkMiddleware` hot-path cost | Performance | load-harness | dev-PC | SQLite | C | P2 | API-plane load with `allowed_client_networks` empty vs a 64-entry list: the p95 request-latency delta is measured and published. **C, not T, because the budget is proposed (1 ms at p95) and not ratified** — there is no threshold this row can fail against. It converts to **T** the day the owner ratifies a budget, at which point the criterion becomes "p95 delta ≤ the ratified budget" and a regression reds it. |
| SEC-45 | Full-body log redaction under sustained load | PHI | load-harness | dev-PC | SQLite | T | P0 | Run a reference load profile with a **synthetic** PHI sentinel embedded in PID-5 of every generated message; assert the sentinel appears **zero** times across the engine stdout capture, every configured log sink, the syslog forwarder output, `/metrics`, and a `messagefoundry support-bundle` taken during the run. Extends `test_logging.py`'s unit-level proof to volume and concurrency. |
| SEC-46 | No PHI in exception text on any raise path | PHI | pytest | any | SQLite | T | P1 | New `tests/test_phi_exception_sweep.py`: drive a decode failure, a strict-validate failure, a transform failure, a delivery failure, a cipher failure, a DPAPI failure, a Transit failure and a store-constraint violation with a sentinel-bearing synthetic message; assert the sentinel appears in **neither** `str(exc)` nor the stored `last_error`/`detail` nor `caplog` at DEBUG. Closes `FEATURE-COVERAGE-PLAN.md` FCP:CRYPTO-10's "only the two Vault legs" residual for the non-crypto paths. |
| SEC-47 | Alerts, reports and crash paths carry no bodies | PHI | pytest | any | SQLite | T | P1 | Extend `tests/test_support_bundle.py` and the alert-sink tests: every alert payload (webhook, SMTP, syslog), the acceptance report, the `verify --report-md/--report-json` output, and the crash-dump suppression report carry the sentinel **zero** times. Pin the allowed field set per surface so a new field cannot smuggle a body. |
| SEC-48 | `/ai/chat` prompt-content disposition | PHI | pytest | any | SQLite | T | P1 | Either (a) `/ai/chat` gains an HL7-shape / sentinel screen before brokering and a test proves a pasted MSH-bearing prompt is **refused** with a 4xx and audited as a refusal, or (b) `docs/AI.md` records the owner-signed boundary ("the engine enforces the declared scope, not the content") and a test asserts the audit row names `prompt_chars` only and the response is unaltered. Pass = **either**, but not the current silence. |
| SEC-49 | IDE cannot attach a message body to an AI prompt | PHI | ide-mocha | dev-PC | n/a | T | P1 | New `ide/src/test/suite/chat-scope.test.ts`: with a `.hl7` file and an engine message-detail view open, every code path that builds an `/ai/chat` request body attaches only editor **code** (via `capCode`) and never a message body or a `messages/{id}/raw` response. A planted body-attaching call fails the test. `chat.test.ts` today covers truncation only. |
| SEC-50 | Anonymization leak gate with the real token list | PHI | CI-leg | container-CI | n/a | T | P1 | A CI step (secret-bearing, non-fork only) runs `pytest tests/test_anon_core.py tests/test_anon_integration.py` with `MEFOR_FORBIDDEN_TOKENS` loaded so the ADR 0030 `anonymize_checked` fail-closed path is exercised against the **real** detector set, not just the synthetic `ESTATE_TOKENS` injection. Skipped-with-reason on fork PRs; a hard failure if the secret is absent on a non-fork run. |
| SEC-51 | `/ui` unpaced write set is pinned | Negative/Security | pytest | any | n/a | T | P1 | New test in `packaging/messagefoundry-webconsole/tests/` (14 modules today): enumerate every non-GET `/ui` route and assert the set that charges **no** admin-write pacing is exactly the currently-documented set (`docs/SECURITY.md:102-108`). A NEW unpaced `/ui` write route reds the suite; a route that *gains* pacing requires updating the pin and the doc together. The pin cites its tracking item, **BACKLOG #287** — a live ledger item, not a dangling reference; nothing needs filing. |
| SEC-52 | Browser-level CSP / SameSite / Sec-Fetch enforcement | Negative/Security | browser | browser-matrix | n/a | T | P2 | On Edge, Chrome and Firefox against a real `/ui`: an inline `<script>` injected into a rendered field is blocked with a CSP violation report; a cross-site form POST to a `/ui` write route is rejected (`Sec-Fetch-Site` guard); the session cookie is not sent on a cross-site navigation. The pytest canary asserts the **header**; this asserts the browser's **enforcement**. |
| SEC-53 | Wheel-integrity fail-closed profile and operator visibility | Negative/Security | pytest + manual | W2025-box | SQLite | T | P2 | (a) pytest: with `[integrity].fail_closed_on_drift=true`, a mutated first-party module byte causes `IntegrityError` **before listeners bind**, and a `startup_integrity` audit row is written; (b) manual on W2025: under NSSM with the default alert-only posture, confirm the operator actually sees the drift (stdout capture location, alert delivery) and record where it lands. |
| SEC-54 | Recommended deployment profile enables the tripwire | Usability | manual | W2025-box | n/a | C | P2 | `docs/SERVICE.md` / the NSSM install script's recommended production profile sets `[integrity].fail_closed_on_drift`, or records the reason it does not. Pass = a written, dated decision plus a `verify` MANUAL row that surfaces the current setting. |
| SEC-55 | Secrets never reach a config file, log, bundle or posture route | Negative/Security | pytest | any | x3 | T | P2 | Extend `tests/test_secretprovider.py` + `test_support_bundle.py`: a `MEFOR_*` secret value planted in every credential-bearing setting appears **zero** times in `messagefoundry security show` output, `GET /security/posture`, `GET /metadata`, the support bundle, `/metrics`, and any log record at DEBUG. Complements the existing exhaustive secret-scrub test (`FEATURE-COVERAGE-PLAN.md` FCP:CFG-16, P3 closed) by covering the newer surfaces. |
| SEC-56 | DPAPI cross-account boundary | Negative/Security | manual | W2025-box | n/a | T | P1 | **Owned by `WIN2025-TEST-PLAN.md` W25:S2.2 / `FEATURE-COVERAGE-PLAN.md` FCP:CRYPTO-7** — mint the key as an administrator (`messagefoundry protect-key`, user scope), run the service under a distinct gMSA/virtual account, assert the fail-closed `DpapiError` at startup; machine scope + `--grant-account` succeeds. Cited here for completeness; do not re-plan. |
| SEC-57 | Crash-dump machine-policy residual on a real host | Negative/Security | manual | W2025-box | n/a | T | P2 | On Windows Server 2025: run `scripts/service/install-service.ps1 -SuppressCrashDumps`, then force a fault in a scratch process under the service image name and confirm no dump is written under `HKLM\…\Windows Error Reporting\LocalDumps` paths and no `AeDebug` debugger attaches. Records whether `crashdump.py`'s named residual is actually closed at install time. |
| SEC-58 | Memory-encryption read-out on confidential-computing silicon | Functional | manual | cloud | n/a | T | P2 | On an AMD SEV-SNP or Intel TDX host, `GET /security/posture` reports a **non-null** platform read-out (`config/memory_encryption.py`), the operator declaration and the read-out agree, and no contradiction is reported. On Windows the read-out is always null — this row can only be closed on such a host. |
| SEC-59 | ADR 0152 rung 3 disposition | Negative/Security | manual | any | n/a | C | P2 | CPU-signed attestation verified against silicon-vendor PKI is **not built**. Pass = the ADR 0152 status table and the risk register carry a dated owner decision (build / accept as residual) and `GET /security/posture` continues to name the field `operator_declared`, never `attested`. |
| SEC-60 | Revocation refusal exercised both ways off-loopback | Negative/Security | manual | W2025-box | n/a | T | P1 | Against the off-loopback lab: in-process TLS on a non-loopback host with neither `tls_terminated_upstream`+`trusted_proxies` nor `MEFOR_TLS_REVOCATION_ATTESTED=1` exits 2 with the `__main__.py:1587-1609` message; setting either starts. Then present a **revoked-but-unexpired** leaf at the proxy and confirm the proxy rejects it — proving the delegation is real, not nominal. |
| SEC-61 | Pinned internal-CA trust anchor against a real PKI | Negative/Security | manual | W2025-box | n/a | T | P2 | With the test PKI: a leaf signed by the pinned internal CA is accepted; a leaf signed by a different CA present in the machine store is **rejected** (`tls_policy.py:799-870`); an expired leaf is rejected unless `relax_verify_expiry` is explicitly on (`:159-196`), and then only for expiry, not for chain or hostname. |
| SEC-62 | Off-loopback exposure ladder, honestly walked | Negative/Security | manual | W2025-box | SQLite | T | P1 | Walk the full ladder on a standing lab instance: loopback → `--allow-insecure-bind` → in-process TLS → proxy-terminated with and without `trusted_proxies` declared. At each rung record which gates fire (exposed-bind, revocation, MFA-at-exposure, Posture-B declarations, `allowed_client_networks`) and confirm the `security_loosenings()` output matches what is actually loose. |
| SEC-63 | Release artifacts verified as a downstream consumer | Negative/Security | manual | any | n/a | T | P1 | Against a published tag, from a clean machine with no repo checkout: `gh attestation verify` on the wheel and sdist, `sigstore verify identity` on the SBOM and VEX, `trivy sbom --vex` on the published pair, and a `pip install --require-hashes` from the published lock. All succeed; a tampered copy of each fails. |
| SEC-64 | Independent third-party ASVS L2/L3 source review | Negative/Security | external | any | n/a | A | P0 (exposure) | **Assurance, not a countable test** — the pass criterion is a procurement event, so it is **excluded from the ordinary P0 count** and cannot sit in a per-release gate. An external firm under NDA delivers a written report against OWASP ASVS 5.0 covering the engine, `/ui`, the IDE extension and the container image. Pass = report received, every finding triaged with an owner and a date, and `docs/Secure_Build_Scorecard_MEFOR.md` signal 10 moves off "Absent". **Blocking for any off-loopback / production-exposure release; advisory for a loopback-only release** — because the project's standing signal-10 risk acceptance (`docs/Secure_Build_Scorecard_MEFOR.md:63`) is **void on exactly that exposure**, so on such a release there is no acceptance left to fall back on. See §15.5 scenario F for scoping. |
| SEC-65 | Penetration test of the off-loopback topology | Negative/Security | external | cloud | x3 | A | P0 (exposure) | **Assurance, not a countable test** — excluded from the ordinary P0 count. A human tester against a standing lab instance (operator API + `/ui` + MLLP/DICOM/HTTP ingest listeners, TLS with real certs, a reverse proxy). Scope, rules of engagement and a data-handling clause (synthetic test data only, PHI-free) signed by the owner. Pass = report received and triaged; any Critical/High closed or risk-accepted with a date. **Blocking for an off-loopback / production-exposure release, advisory otherwise** — the lab instance is itself off-loopback, and the standing risk acceptance voids on exposure. |
| SEC-66 | Authenticated DAST against a running engine | Negative/Security | external | cloud | SQLite | A | P0 (exposure) | **Assurance, not a countable test** — excluded from the ordinary P0 count. A DAST tool driving real sessions and the step-up ceremonies against a standing instance, with an authenticated scan profile. Pass = a completed scan with triaged results and a decision on whether it becomes a recurring (quarterly) run. Requires tooling choice, licensing and triage ownership — all owner decisions. **Blocking for an off-loopback / production-exposure release, advisory otherwise**; on such a release the standing risk acceptance no longer covers its absence. |
| SEC-67 | Fuzzing / property-testing of the attacker-exposed parsers | Negative/Security | external | container-CI | n/a | T | P0 | A campaign (in-CI leg or off-repo) over `parsing/peek.py`, `parsing/x12/`, `parsing/dicom/`, `parsing/binary.py` (the `mfb64:v1:` carriage) and the hardened XML/JSON parsers. Pass = a documented corpus + runner, zero unhandled exceptions outside the sanctioned parse-fail → dead-letter path, and no non-linear time blow-up. No fuzzing tooling exists anywhere today. |
| SEC-68 | CVE tabletop + security-advisory dry run | Usability | manual | any | n/a | C | P2 | Recorded as unrun in `docs/Secure_Build_Scorecard_MEFOR.md` signal 9. Run one: a simulated CVE in a pinned dependency exercised end to end — pip-audit red → triage → VEX statement (SEC-10/SEC-11 discipline) → lock bump → release → advisory published. Pass = a dated written record and any process gaps filed. |
| SEC-69 | ASVS assessment corpus is reachable by a drift guard | Negative/Security | manual | any | n/a | C | P1 | The ASVS assessment corpus is **real and maintained** — it is simply **withheld from the public repo**: `docs/security/` is gitignored post-cutover (`.gitignore:144`, ~32 files of posture / assessment / risk-register / runbook detail deliberately not published as an attacker roadmap), as are `docs/reviews/` and `docs/marketing/` (`:145-146`). Nothing here is missing; what is missing is a **linkage a public CI job can read**. Pass = a dated decision plus action: either a machine-readable **public** subset (requirement → control → code artefact) lands in-tree so a drift test can hold the shipped code to the assessment, or the risk register records that no automated linkage exists and names who re-checks it by hand and how often. `FEATURE-MAP.md:136`'s citation of **BACKLOG #310** is sound (above the published #231 baseline) and stays. |
| SEC-70 | ADR 0148 re-score and owner re-signature | Usability | manual | any | n/a | C | P1 | The ADR 0148 status line records the per-cell scorecard re-score and owner re-signature as **pending**. Pass = the re-score is complete and signed, or the pending note carries a date and an owner. Blocks any quotable ASVS figure. |
| SEC-71 | ECH disposition — **including the shipped `tools/ech-sidecar/` tree** | Negative/Security | manual | any | n/a | C | P2 | **DISCHARGED 2026-08-10 (BACKLOG #1011) — the owner ruled RETIRE.** All three artefacts are dispositioned: (a) the engine-side routing (`ech_sidecar_url_from_settings` / `egress_route_from_settings` in `transports/rest.py` — by symbol, because the line number this row used to carry landed on a blank line and could never self-resolve) **stays** — it does not itself originate ECH and its docstring no longer claims a path that exists; (b) the stdlib-only Go re-originator was **deleted** from the tree, recoverable at `git show 62fd628d:tools/ech-sidecar/main.go`; (c) the operator recipe `samples/ech-sidecar/README.md` **stays**, re-aimed at the generic contract and carrying that retrieval SHA. ADR 0139's status line, *Implementation status* block and acceptance checklist are reconciled to the ruling, and `docs/SECURITY.md`'s 12.1.5 paragraph is rewritten off "infeasible" — a false premise the tree itself refuted — onto the true one: **buildable off-stdlib, deliberately not owned, inert because no partner publishes an `ECHConfig` (2026-07-20 DoH probe)**. ASVS 12.1.5 is recorded as a **standing accepted `fail`**, unchanged by the ruling in either direction. The original evidence stands for the record: nothing built, tested, linted, version-pinned or shipped the Go tree — zero `setup-go` / `go build` hits across `.github/workflows/`, `ci/`, `scripts/`, `.pre-commit-config.yaml` and `tests/`, and `pyproject.toml:21` `only-include` kept `tools/` out of both sdist and wheel. `tests/test_ech_egress.py` stays as the fail-closed guard and now states its own scope limit (the far end is always a stub; nothing in the suite originates or observes ECH). **Recorded as discharged rather than converted to a T row:** the ruling creates no new automatable criterion, and the fail-closed guard is already owned. |
| SEC-72 | `security.yml` header matches its own triggers | Negative/Security | pytest | any | n/a | T | P2 | **The `security.yml` half is BUILT (BACKLOG #1079)**, in `tests/test_security_posture.py::test_the_security_header_does_not_contradict_its_own_triggers` rather than the `tests/test_security_workflow_liveness.py` this row named — that module does not exist, and the posture module is where every other `security.yml` assertion already lives. It reads the `on:` block (handling the YAML 1.1 `on` -> `True` key), locates the header by construct, and refuses a header denial adjacent to any declared event name, with the historical claim kept as a live positive control. Its scope is stated in the test: a tripwire on the shape that occurred, not a proof that English agrees with YAML. **STILL OPEN:** the `codeql.yml` and `scorecard.yml` header comments still claim version-tag pinning / a pending SHA-pin lookup while every `uses:` in both carries a 40-char SHA (finding 2 above) — nothing asserts that, and this row is not closed until it does. |
| SEC-73 | Last-resort handler leaks no PHI on either unhandled path | PHI | pytest | any | SQLite | T | P1 | The PHI-egress twin of SEC-46, one layer up: `messagefoundry/last_resort.py` (ASVS 16.5.4) routes otherwise-unhandled exceptions through `redaction.safe_exc` on **both** paths — the asyncio loop handler (`install_loop_exception_handler`, installed at `api/app.py:5263`) and the main-thread hook (`install_excepthook`, installed at `__main__.py:2440`) — so no raw traceback, which could quote a PHI-bearing argument, escapes. `tests/test_last_resort.py` (104) proves this at unit level and names its own residual: it does not prove the handlers are **installed in a real serving process**, nor that the redacted record stays clean across *every* configured sink. Extend `tests/test_phi_exception_sweep.py` (SEC-46's module) with that arm: (a) after a real `serve` startup, assert `loop.get_exception_handler()` and `sys.excepthook` are the project's, not the interpreter defaults; (b) induce an unhandled exception on **each** path — a fire-and-forget asyncio task and a main-thread raise — whose argument carries a synthetic PHI sentinel; (c) assert the sentinel appears **zero** times in the stdout capture, every `[logging]` file sink, the syslog forwarder stub, the audit row, `/metrics` and a support bundle taken afterwards, while the exception **type** still appears (so the row cannot pass by swallowing the failure). `KeyboardInterrupt` must still reach `sys.__excepthook__` untouched. |
| SEC-74 | `netaddr` allow-list parity across its two callers | Negative/Security | pytest | any | n/a | T | P1 | New `tests/test_netaddr_parity.py`. `messagefoundry/netaddr.py` exists to be "the ONE place an IP allow-list decision is made" — its entire value is that its two callers cannot disagree about what an entry means: the inbound connectors' per-connection `source_ip_allowlist` (`peer_ip_allowed`, called from `transports/mllp.py:1419`, `tcp.py:495`, `dicom.py:263`, `http_listener.py:374`) and `[security].allowed_client_networks` (`client_network_allowed`, called from `api/client_networks.py:159`). Drive **one shared table** of (address, allow-list) cases through **both** callers and assert an identical decision per cell: bare IPv4, IPv4 CIDR, bare IPv6, IPv6 CIDR, an IPv4-mapped IPv6 peer (`::ffff:a.b.c.d`) against an IPv4 entry, `/32` and `/128`, a host-bits-set entry (`strict=False`), a malformed entry (skipped defensively), an unresolvable/`None` peer (fail closed), a non-parsing literal such as starlette's `"testclient"` (denied), and an empty/`None` list (permit all). **Exactly one divergence is sanctioned and the test must assert it is the only one:** loopback is unconditionally allowed by `client_network_allowed` (`netaddr.py:95-108`) and is **not** allowed by `peer_ip_allowed`, because an ingest listener allow-listing a partner must never silently also admit the local box. A new divergence in either direction reds the suite. Today `tests/test_client_network_allowlist.py` (725) and `tests/test_x12_source_ip_allowlist.py` each exercise one caller; nothing compares them — which is precisely the drift the co-location was built to prevent. |
| SEC-75 | PKCS#12 import survives an adversarial bundle corpus | Negative/Security | pytest | any | n/a | T | P2 | New `tests/test_pki_import_corpus.py` over `messagefoundry/pki.py` (ASVS 11.1.3), today exercised only along the happy path of the `cert` CLI (`tests/test_cert_cli.py`, 446, which builds in-memory `.pfx` bundles with `pkcs12.serialize_key_and_certificates`). Feed `load_pkcs12` an adversarial corpus generated in `tmp_path`: wrong passphrase, empty passphrase vs `None`, truncated/garbage DER, a zero-byte file, a bundle with no private key, one with no leaf certificate, a multi-certificate chain with the leaf last, an oversized (>10 MiB) bundle, a deliberately deep chain, and a key algorithm the PEM exporters do not support. Each must raise a **specific** typed error that the CLI renders as an operator message — never a bare `except`, never an unhandled crash, and never a partial write of key material to disk (assert `tmp_path` holds no `.pem`/`.key` after a failed import). Paired positive: a well-formed bundle imports and `cert_to_pem` / `ca_chain_to_pem` / `key_to_pem` round-trip. |
| SEC-76 | No key material escapes the PKI surface; inventory stays best-effort | Negative/Security | pytest | any | n/a | T | P2 | Same module, three assertions. **(a) Egress:** no private-key byte, passphrase or PEM key block appears in any `load_pkcs12` / `make_self_signed` exception text, in a log record at DEBUG, in `cert` CLI stdout, in `GET /security/posture`, or in a support bundle — only fingerprints and `CertFacts` metadata (the fingerprint-only shape `tests/test_api_security_posture.py` (301) already pins for cipher keys, applied to PKI). **(b) Best-effort inventory:** `read_cert_facts` must keep sinking neither the cert nor the caller when a field will not parse — extend the single case `test_cert_cli.py` samples to a malformed SAN, an unknown critical extension, a negative/absurd validity window and a far-future `notAfter`, each yielding facts with that field absent rather than an exception. **(c) Day-math:** the pin `pki._SECONDS_PER_DAY == pipeline/cert_expiry.py:_SECONDS_PER_DAY` (`tests/test_cert_expiry.py:312`) is extended from the constant to the **computed days-remaining** for a shared cert fixture, so the `cert` CLI and the expiry-alerting path can never report different day counts for the same certificate. |
| SEC-77 | A copyleft-incompatible dependency fails CI | Negative/Security | CI-leg | container-CI | n/a | T | P1 | **New gate — licence/copyleft compliance has zero coverage today.** No `pip-licenses`, `reuse`, `licensecheck` or licence-allow-list step exists in any workflow (verified by grep over `.github/workflows/`), yet the product is **dual-licensed**: AGPL-3.0-or-later plus a commercial arm (`LICENSE`, `NOTICE`, `COMMERCIAL-LICENSE.md`, `CLA.md`, `docs/DUAL_LICENSING_PLAN.md`; `pyproject.toml:29-30` declares `license = "AGPL-3.0-or-later"` and `license-files = ["LICENSE", "NOTICE"]`). Add a **blocking** `security.yml` job that resolves the licence of every component in the hash-locked core runtime (`docker/locks/requirements-core.lock`) and of each optional extra, and fails on any licence outside a **recorded allow-list** with a reason string per entry (the `test_ci_venv_pinning.py:275` register pattern). The dual-licence rule must be stated explicitly and enforced: a term that is acceptable for AGPL distribution but **cannot be sublicensed under the commercial arm** (a strong-copyleft or SSPL-class dependency) is a **failure**, not a warning — the commercial arm cannot ship it. An unknown or unparsed licence is a failure, not a skip. Planted-dependency self-test: a fixture requirement carrying a disallowed licence reds the job. |
| SEC-78 | MPL-2.0 per-file obligation survives on the vendored corpus | Negative/Security | pytest | any | n/a | T | P2 | New `tests/test_vendored_corpus_notices.py`. The vendored corpus is real and its path is `samples/messages/hapi-hl7v2/` (7 message files + `README.md`) — verbatim fixtures from `hapifhir/hapi-hl7v2` at commit `de1503651040`, **MPL-2.0**, whose own README states the obligation: files are copied byte-unchanged, and "if any file is ever modified, MPL-2.0 requires that file to carry its source notice." MPL-2.0 is a **per-file** copyleft, so a silent edit is the failure mode. Assert: every file in the README manifest exists and every file present is in the manifest (no silent addition or deletion); each file's digest matches a recorded per-file manifest (add `MANIFEST.sha256` alongside the README — today provenance is prose with no hashes, so an edit lands unnoticed); and a modified file must carry an MPL-2.0 source notice naming its upstream path, enforced rather than merely documented. Also assert the corpus stays out of the distribution (`pyproject.toml:21` `only-include` keeps `samples/` out of wheel and sdist, so no redistribution obligation reaches an installer) and that `NOTICE` gains and keeps a third-party entry for it — today `NOTICE`'s only third-party attribution block is pydicom's "MIT AND BSD-3-Clause" note; there is **no MPL-2.0 entry at all**. |
| SEC-79 | `NOTICE` and the shipped SBOM stay consistent | Negative/Security | pytest | any | n/a | T | P2 | Same module. The shipped CycloneDX SBOM is generated in `cyclonedx-py environment` mode **specifically so component licences populate** — a draft-2025 CISA minimum element (`release.yml:191-196`; `security.yml`'s SBOM command is already pinned byte-identical by `tests/test_release_pipeline.py:305-325`). Nothing checks that the licence data is actually there or that it agrees with `NOTICE`. Assert: **(a)** every component in the shipped SBOM carries a non-empty licence field — a licence-less component reds the job rather than printing a warning, which is the whole reason `environment` mode was chosen over the requirements parser; **(b)** every attribution obligation `NOTICE` states by hand — today pydicom's "MIT AND BSD-3-Clause" from its vendored GDCM/CREATIS data dictionaries under the `[dicom]` extra, plus pynetdicom (and Phase-2 dicomweb-client) MIT — is present and licence-consistent in the SBOM for the matching extra, **and conversely** any SBOM component whose licence carries an attribution obligation appears in `NOTICE`; the two can drift in either direction today with nothing holding them together; **(c)** `pyproject.toml:29-30`'s declared `license` / `license-files` match `LICENSE` + `NOTICE` as actually present in the built wheel and sdist. |

---

### 15.5 Detailed scenarios

#### Scenario A — SEC-14 / SEC-15: observed TLS refusal against live listeners

**Why narrative.** Every existing TLS assertion reads an `SSLContext` attribute. This is the only test
that puts a hostile client on a socket, and it is easy to write a version that passes because the
listener never came up.

**Preconditions.** A dev PC with the project venv. A synthetic self-signed cert + key generated for
the test (`messagefoundry self-signed`, into `tmp_path` — never committed). No PHI anywhere: the
handshake never carries a message.

**Steps.**
1. Generate the cert into `tmp_path`: `python -m messagefoundry self-signed --host 127.0.0.1
   --out <tmp>/tls` (pytest fixture; delete on teardown).
2. Start the real MLLP-over-TLS listener on an ephemeral loopback port with that cert, and the real
   uvicorn API with `[api].tls_cert_file` pointing at it.
3. **Positive control first.** Connect with a stock hardened client context
   (`config/tls_policy.build_verifying_client_context`, CA = the synthetic cert). Assert the
   handshake succeeds and `sock.version()` is `TLSv1.2` or better and `sock.cipher()[0]` names an
   ECDHE suite. *If this fails, the test is broken, not the engine.*
4. Build a client context with `maximum_version = ssl.TLSVersion.TLSv1_1`. Connect. Assert
   `ssl.SSLError` (or `ConnectionResetError` on the platforms where OpenSSL aborts hard) — and assert
   the error is raised during the handshake, not on read.
5. Build a client context with `set_ciphers("AES128-SHA:AES256-SHA")` (static-RSA, non-FS) and
   `minimum_version = TLSv1_2`. Connect. Assert the handshake fails.
6. Repeat 4-5 against the API listener.

**Observation point.** The exception raised by `ssl.SSLSocket.do_handshake()` on the client, plus
`sock.cipher()` on the positive control.

**Expected result.** Steps 4 and 5 raise on both listeners; step 3 succeeds on both. A skipped or
xfailed step is a FAIL for this row — the whole point is an observed refusal.

**Cleanup.** Close both listeners in a fixture finalizer; `tmp_path` removes the cert material.
Assert no listener is left bound (the ephemeral port is re-bindable).

---

#### Scenario B — SEC-31: one message, every injection sink

**Why narrative.** This is the only cross-cutting composition test in the chapter, it touches every
outbound, and it is destructive if pointed at anything real.

**Preconditions.** SQLite store in `tmp_path`. A dedicated test config directory wiring one MLLP
inbound → one Router → one Handler → **every** shipped outbound family, each pointed at a loopback
stub or a `tmp_path` directory. `[egress]` allow-lists populated for exactly those stubs.
`data_class` synthetic. **No real endpoints, no real PHI** — the payload is a synthetic ADT built by
`messagefoundry generate` and then field-edited to carry the hostile strings.

**Steps.**
1. Build the message: start from `python -m messagefoundry generate adt --count 1` output (a
   synthetic patient), then set — via the parsed model, never string slicing (CLAUDE.md §8) —
   PID-5.1 = `O'Brien'); DROP TABLE messages;--`, PID-11.1 = `..\..\..\windows\win.ini`,
   PID-13.1 = `=cmd|'/c calc'!A1`, PV1-3.1 = `ward\r\nBcc: attacker@example.invalid`,
   OBX-5 = `\x00\x07\x1b[31m${jndi:ldap://127.0.0.1/x}`.
   **Do not** redirect `generate` output to any committed file.
2. Serve the config: `python -m messagefoundry serve --config <tmp>/config --db <tmp>/mf.db --env dev`.
3. Send it: `python samples/send_mllp.py <tmp>/msg.hl7`.
4. Poll the store until the message reaches a terminal disposition (`PROCESSED`, `FILTERED` or
   `ERROR`) or a 30 s timeout. A timeout is a FAIL — an accept-and-drop.
5. Assert per sink:
   - **File / RemoteFile** — every written path resolves inside the configured root; no file exists
     at `<tmp>/../win.ini` or any `..`-derived location.
   - **DB outbound / `db_lookup`** — the `messages` table still exists and the statement was executed
     with bound parameters (assert via a driver-level statement recorder, not by grepping SQL text).
   - **REST / FHIR / DICOMweb** — the stub records exactly one request; no header line in the raw
     request contains an injected `Bcc:`; no redirect was followed.
   - **SMTP / Direct** — the stub SMTP server sees exactly the configured recipients; no extra
     header line.
   - **Audit CSV export** (`messages:export`) and the acceptance report — the `=cmd|…` value is
     emitted neutralized.
   - **Support bundle** — `messagefoundry support-bundle` taken after the run contains none of the
     five hostile strings and no message body.
   - **Logs** — no control character survives to a log record (the ASVS Phase-0 scrub), and no
     sentinel PHI value appears at INFO or above.

**Observation point.** The store disposition row, the per-stub request recorders, the filesystem
under `tmp_path`, and the captured log stream.

**Expected result.** One terminal disposition, zero escapes, zero files outside the root, zero
unparameterized statements, zero injected headers.

**Cleanup.** Stop the engine (ASGI lifespan `engine.stop()`); `tmp_path` teardown removes the store,
the config and every written file. Assert the stub servers logged no request after shutdown.

---

#### Scenario C — SEC-40: a Transit-configured PHI instance must start

**Why narrative.** This is a *defect reproduction* that must first FAIL, then pass after the gate is
made `cipher_provider`-aware. Getting the fixture wrong makes it pass for the wrong reason.

**Preconditions.** A running Vault or OpenBao with the Transit engine enabled and a data key created,
**or** the `tests/test_crypto_transit.py` Transit stub. `MEFOR_STORE_VAULT_ADDR`,
`MEFOR_STORE_VAULT_TOKEN`, `MEFOR_STORE_TRANSIT_KEY` set from the environment only.
`MEFOR_STORE_ENCRYPTION_KEY` and `MEFOR_STORE_ENCRYPTION_KEY_FILE` **explicitly unset**.

**Steps.**
1. Write a service TOML with `[store] backend = "sqlite"`, `cipher_provider = "vault_transit"`,
   `[ai] environment = "prod"` (so `data_class` derives to `phi`), `[security] enforcement = "enforce"`.
2. Run `python -m messagefoundry serve --config <tmp>/config --service-config <tmp>/mf.toml`
   with a short-lived lifespan (the test drives the app factory, not a real listener).
3. **Current expected (defect):** exit code 2 and the `__main__.py:1161-1180` keyless-PHI message.
   Record this as the reproduction.
4. **Target expected (after fix):** the engine starts; `build_store_cipher` returns a `TransitCipher`
   (`store/base.py:1723`); `GET /security/posture` reports encryption **on** with a Transit provider
   and does **not** list keyless-PHI or `allow_unencrypted_phi` as a loosening.
5. Paired negative: with `MEFOR_STORE_TRANSIT_KEY` unset, `serve` must still refuse (`crypto_transit.py:188`)
   — the fix must not turn the gate into a hole.
6. Paired negative: with Transit unreachable, `serve` must refuse rather than degrade to plaintext
   (`crypto_transit.py:211`).

**Observation point.** Process exit code, the constructed cipher type, and the `GET /security/posture`
body.

**Expected result.** Step 4 succeeds and steps 5-6 refuse. Until the gate is fixed, step 3 is the
recorded evidence and the row stays open.

**Cleanup.** Revoke the Transit token used by the test; delete `tmp_path`. Never write the token to a
file.

---

#### Scenario D — SEC-04 / SEC-05: proving the leak gate's floor still means something

**Why narrative.** This is the one control whose efficacy cannot be observed in this worktree, and the
obvious way to test it (writing the real token list somewhere) is exactly what must never happen.

**Preconditions.** A CI run on the source repository (non-fork) with the `MEFOR_FORBIDDEN_TOKENS`
repository secret available. **The token list must never be written to a file in the workspace** —
`security.yml:399-401` already documents why, and the current job deliberately passes it only as a
step-level env var.

**Steps.**
1. Add a `--print-detector-counts` mode to `scripts/security/scan_forbidden.py` that emits **only**
   the per-section counts (`names=N,estate=N,site_prefixes=N`) — integers, never tokens.
2. In the `forbidden-content` job, after the token source loads, run it and compare each section
   against the `MEFOR_MIN_DETECTORS` literal. Fail if any loaded count is **below** the floor
   (a mangled secret) **or** if the floor is below 80% of the loaded count (a floor left behind by a
   grown list).
3. Negative rehearsal, on a branch: truncate the secret to its first line via a scratch secret in a
   throwaway environment and confirm the job **fails** rather than passing structural-only.
4. Negative rehearsal: unset the secret on a non-fork run and confirm `::error::` + `exit 2`
   (`security.yml:405-413`).
5. Add SEC-05's static test so the three-branch shell structure and the per-section floor form cannot
   be replaced by a bare total.

**Observation point.** The job's exit code and its printed counts (integers only).

**Expected result.** Steps 3 and 4 red; the normal path green with counts printed.

**Cleanup.** Delete the throwaway scratch secret. Confirm no workspace file, artifact, log line or
job summary contains a token — grep the run log for the count line only.

---

#### Scenario E — SEC-45: no full body reaches any sink under load

**Why narrative.** Unit-level redaction is proven; volume, concurrency and the forwarder path are not.
This is also the scenario most likely to be run wrong by pointing the load rig at a real feed.

**Preconditions.** `harness/load/` with a reference profile. The engine served against the load config
(`harness/config/load`) on a SQLite store in a scratch directory. **Synthetic corpus only** — the
generated traffic is `messagefoundry generate` output (`docs/LOAD-TESTING.md` states this
explicitly). A recognisable synthetic sentinel is planted in PID-5 of every generated message
(e.g. `ZZSENTINEL^LOADTEST`), which is not PHI.

**Steps.**
1. Serve: `MEFOR_LOAD_FANOUT=20 MEFOR_LOAD_SINK_PORT=2700 python -m messagefoundry serve
   --config harness/config/load --db <scratch>/load.db --env dev`, with `[logging]` configured to a
   file sink **and** a loopback TLS-syslog forwarder stub.
2. Drive: `python -m harness --load fanout-baseline --engine http://127.0.0.1:8765 --token <T>
   --sink-port 2700 --report-json <scratch>/run.json`.
3. During the run, take `messagefoundry support-bundle` and scrape `GET /metrics`.
4. After drain, grep for the sentinel across: the engine stdout capture, the file log sink, the
   syslog stub's received records, `<scratch>/run.json`, the support bundle, and the `/metrics`
   scrape.

**Observation point.** Sentinel occurrence counts per artefact.

**Expected result.** Zero in every artefact. Non-zero anywhere is a P0 finding.

**Cleanup.** Stop the engine and the syslog stub; delete `<scratch>` including `load.db`, the run
report and the support bundle. **Do not** attach any of these artefacts to a ticket or CI log — the
report is metrics-only but the bundle and logs are not committed material.

---

#### Scenario F — SEC-64 / SEC-65 / SEC-66: commissioning the external assurance

**Why narrative.** This is procurement and scoping, not a test run, and it is the single grade-capping
absence (`docs/Secure_Build_Scorecard_MEFOR.md:63`). It needs a written scope before anyone is
approached.

**Preconditions.** Owner decision on budget, timing and counterparty. An NDA template. A decision on
whether the private `docs/security/` corpus — real and maintained, but **withheld from the public
repo** (`.gitignore:144`) — is released to the counterparty under NDA.

**Proposed scope — a three-lot engagement, priced separately so lots can be dropped.**

| Lot | Deliverable | Assets in scope | Assets explicitly out |
|---|---|---|---|
| **1 — ASVS L2/L3 source review** | Written report per ASVS 5.0 requirement with verdicts and evidence; a reviewed version of our own self-assessment | `messagefoundry/` (engine, `auth/`, `api/`, `store/`, `transports/`, `config/`, `parsing/`), `messagefoundry_webconsole/`, `scripts/security/`, the release + security workflows | The PySide6 harness (`harness/`) beyond its API-client boundary; `tee/` vendored SOUP beyond its bandit/semgrep bar |
| **2 — Penetration test** | Findings report with reproduction steps, severity and remediation guidance | A standing off-loopback lab instance: operator API + `/ui` + MLLP, DICOM C-STORE SCP and HTTP ingest listeners, behind a reverse proxy with and without `trusted_proxies` declared; the container image | Any production or customer estate; any real PHI |
| **3 — Authenticated DAST** | A repeatable authenticated scan profile plus a triaged first run | `/ui` and the JSON API with real sessions, MFA and step-up ceremonies | Destructive purge/replay against anything but the lab store |

**Rules of engagement to fix in writing.**
- All test data is **synthetic and PHI-free**; the lab store is seeded only by
  `messagefoundry generate`. No real PHI may be introduced by either party.
- The lab is disposable and rebuilt from scratch before and after.
- Findings referencing message content must quote synthetic values only.
- The standing risk acceptance for signal 10 is **void on any off-loopback or production exposure**
  (`Secure_Build_Scorecard_MEFOR.md:63`) — the lab instance is off-loopback, so the engagement itself
  is the event that discharges rather than voids it. Record that reading explicitly with the owner.

**Trigger decision the owner must make.** Commission at (a) GA/v1.0 as `docs/BACKLOG.md:390` currently
states, (b) the first off-loopback customer, or (c) a fixed date. The acceptance's void condition
means (b) is the latest defensible trigger.

**Expected result.** A signed scope, a counterparty, and a date. Pass for SEC-64/65/66 is the report
received and triaged — not the absence of findings. That is precisely why all three are **Cls A
(Assurance)** and not tests: a procurement event has no observable pass criterion the project can
fail, so they are **excluded from the ordinary P0 count**. They are still the most consequential rows
in the chapter — **blocking for any off-loopback or production-exposure release, advisory for a
loopback-only one** — because the standing signal-10 risk acceptance is *void on that same exposure*,
so a release that crosses the line has neither the assurance nor an acceptance covering its absence.

---

#### Scenario G — SEC-35 / SEC-36: making the 15.2.5 defence real

**Why narrative.** Two halves of one control, both currently unexercised, and the runtime half is
structurally incompatible with the features most feeds use — so the test must not accidentally imply
the incompatibility has been solved.

**Preconditions.** A fixture config directory `tests/fixtures/handler_security_findings/` carrying
exactly one planted finding per ADR 0144 rule family (phi-to-log, unsafe-db-lookup, ambient-authority,
impure-transform, unvetted-import), each annotated with the expected rule name.

**Steps (static half — SEC-35).**
1. `python -m messagefoundry check --config samples/config --strict-handler-security` → exit **0**.
2. `python -m messagefoundry check --config tests/fixtures/handler_security_findings
   --strict-handler-security` → non-zero, and stdout names all five rule families.
3. Same fixture **without** `--strict-handler-security` → exit **0** with advisory text (proving the
   default posture is unchanged).
4. Add step 1 and step 2 as a CI leg. Add a pytest that asserts the leg exists in `ci.yml` (so it
   cannot be deleted silently) — the same shape as SEC-02.

**Steps (runtime half — SEC-36).**
5. Serve `harness/config` (the disposition-coverage graph) with `[sandbox] mode = "subprocess"`.
6. Send one synthetic message; assert it reaches `PROCESSED` and that the worker child process
   existed (assert via the sandbox's own worker bookkeeping, not by inspecting the OS process table).
7. Assert the forbidden-import guard fires on a fixture handler that imports `socket`, producing a
   `SandboxError` routed to ERROR/dead-letter **post-ACK** — never a NAK.
8. Assert, with a fixture handler calling `db_lookup`, that the sandbox **refuses** it fail-closed and
   that the refusal is surfaced at load (SEC-37), not first discovered at message time.

**Observation point.** Exit codes and stdout for the static half; store dispositions and the
`SandboxError` path for the runtime half.

**Expected result.** Static: 0 / non-zero / 0. Runtime: PROCESSED, guard fires, `db_lookup` refused
and announced.

**Cleanup.** Terminate the sandbox worker via the normal stop path and assert no orphan child
survives; delete the scratch store.

---

### 15.6 Automation disposition

**New pytest modules** (name them exactly):

| Module | Rows | Effort |
|---|---|---|
| `tests/test_security_workflow_liveness.py` | SEC-02, SEC-03, SEC-05, SEC-72 | **S** |
| `tests/test_security_wave_coverage_owner.py` | SEC-01 | **S** |
| `tests/test_vex_document.py` | SEC-10, SEC-11 | **S** |
| `tests/test_tls_handshake_refusal.py` | SEC-14, SEC-15 | **M** |
| `tests/test_ldap_filter_injection.py` | SEC-29 | **S** |
| `tests/test_ssrf_corpus.py` | SEC-26, SEC-27 | **M** |
| `tests/test_hl7_injection_endtoend.py` | SEC-31, SEC-32 | **L** |
| `tests/test_serve_security_gates.py` | SEC-21, SEC-22, SEC-40 | **M** |
| `tests/test_phi_exception_sweep.py` | SEC-46, SEC-73 | **M** |
| `tests/test_netaddr_parity.py` | SEC-74 | **S** |
| `tests/test_pki_import_corpus.py` | SEC-75, SEC-76 | **M** |
| `tests/test_vendored_corpus_notices.py` | SEC-78, SEC-79 | **M** |
| `ide/src/test/suite/chat-scope.test.ts` | SEC-49 | **S** |
| `packaging/messagefoundry-webconsole/tests/test_ui_write_pacing_pin.py` | SEC-51 | **S** |

**Dropped from this chapter:** the separate `tests/test_feature_map_drift.py` deliverable (SEC-08) —
the FEATURE-MAP drift guard is now **one consolidated MIG row** extending
`tests/test_feature_map_claims.py`, and the "doc paths resolve" linter (SEC-09) is a single MIG row
too. Both SEC rows are pointers that hand their security-specific inputs to MIG; no module is built
here.

**Extensions to existing modules** (do not fork a parallel suite):

| Existing module | Rows added | Effort |
|---|---|---|
| `tests/test_tls_policy.py` | SEC-19, SEC-20 | **S** |
| `tests/test_hop_refusal_wiring.py` | SEC-17, SEC-18 | **S** |
| `tests/test_security_static.py` | SEC-16, SEC-34 | **M** |
| `tests/test_csv_formula_consistency.py` | SEC-33 (end-to-end arm only — the neutralizer, its harness mirror and the writer inventory are already owned there) | **S** |
| `tests/test_security_posture_defaults.py` | SEC-23 | **M** |
| `tests/test_security_doc_drift.py` | SEC-07 | **S** |
| `tests/test_client_network_allowlist.py` | SEC-24 | **S** |
| `tests/test_egress_allowlist.py` | SEC-28 | **M** |
| `tests/test_anon_core.py` | SEC-06 | **S** |
| `tests/test_sandbox.py` | SEC-36, SEC-37 | **M** |
| `tests/test_crypto_transit.py` | SEC-41, SEC-42 | **M** |
| `tests/test_support_bundle.py` + alert-sink tests | SEC-47, SEC-55 | **M** |
| `tests/test_api_security_posture.py` | SEC-48 (option b) | **S** |

**New CI legs:**

| Leg | Rows | Effort |
|---|---|---|
| `ci.yml` — `messagefoundry check --strict-handler-security` over `samples/config` + the findings fixture | SEC-35 | **S** |
| `security.yml` — detector-count assertion in `forbidden-content` (requires the `--print-detector-counts` scanner mode) | SEC-04 | **M** |
| `security.yml` — secret-bearing anon leak-gate leg | SEC-50 | **S** |
| `security.yml` — promote `sbom` + `trivy` to the PR path, blocking, with an sbomqs floor and a `trivy sbom --vex` parse check | SEC-12, SEC-13 | **M** |
| `security.yml` — **new blocking licence job**: resolve every component licence over `docker/locks/requirements-core.lock` + each extra against a recorded allow-list, failing on a commercially-unsublicensable term or an unknown licence | SEC-77 | **M** |

**New harness / probe capability:**

| Capability | Rows | Effort |
|---|---|---|
| `harness/acceptance/probes.py` — a `probe_client_network_inertness` reporting the observed client vs the configured allow-list (the module currently ships nine probes, `:200 PROBES`) | SEC-25 | **S** |
| `harness/load/` — a security-overhead profile pair (`sandbox=off/subprocess`, `cipher_provider=aesgcm/vault_transit`, allow-list empty/64-entry) emitting a comparison table | SEC-38, SEC-43, SEC-44 | **M** |
| `harness/load/` — sentinel-bearing corpus + a post-run multi-sink grep step | SEC-45 | **M** |

**Stays manual, and why:**

- **SEC-56 (DPAPI cross-account), SEC-57 (crash-dump machine policy), SEC-60 (revocation off-loopback),
  SEC-61 (real PKI), SEC-62 (exposure ladder), SEC-53b (drift under NSSM)** — host and PKI facts a
  container cannot reproduce. SEC-56 is already owned by `WIN2025-TEST-PLAN.md` W25:S2.2 /
  `FEATURE-COVERAGE-PLAN.md` FCP:CRYPTO-7 — reference it, do not duplicate. Effort **M** (mostly lab
  standing-up).
- **SEC-30 (LDAP injection live)** — needs a directory that will accept hostile usernames. **S** once
  the AD lab exists.
- **SEC-52 (browser enforcement)** — the pytest canary asserts the header; only a browser proves
  enforcement. **S** per browser, **M** across the matrix.
- **SEC-58 (SEV-SNP/TDX read-out)** — the read-out is always null on Windows; only confidential-computing
  silicon can close it. **S** given the host.
- **SEC-39, SEC-54, SEC-59, SEC-69, SEC-70, SEC-71** — owner decisions and signatures, not
  automatable. These are the chapter's **Cls C** rows: each yields a dated written decision, so none
  of them gates a release, and each converts to a **T** row the day its decision or threshold is
  recorded. **S** each. **SEC-71 is discharged** (2026-08-10, BACKLOG #1011 — retire): it landed at
  **S**, since the **M** sizing was contingent on *keeping* the ECH sidecar and the Go build/test leg
  and distribution answer that would have implied. It is recorded as discharged rather than converted
  to a **T** row — the ruling adds no automatable criterion — so the chapter's row counts above are
  unchanged.
- **SEC-63 (downstream artifact verification)** — needs a clean machine and a published tag. **S**.
- **SEC-64, SEC-65, SEC-66** (**Cls A**, Assurance) **and SEC-67, SEC-68** — external engagements and
  campaigns. **L** (procurement-bound). The three A rows are excluded from the ordinary P0 count and
  are blocking only for an off-loopback / production-exposure release; SEC-67 stays a **T** row
  because a fuzzing campaign has a falsifiable criterion (zero unhandled exceptions outside the
  sanctioned parse-fail → dead-letter path, no non-linear time blow-up).

---

### 15.7 Environment, data & prerequisites

**Hosts and infrastructure**

- **Windows Server 2025 host**, domain-joined to a test AD domain, with NSSM, a distinct service
  account (gMSA or virtual), and administrator access — SEC-53, SEC-56, SEC-57, SEC-60, SEC-61,
  SEC-62. (Provisioning is specified by `WIN2025-TEST-PLAN.md` W25:S0 / W25:S1 — reuse it.)
- **A standing off-loopback lab deployment**: TLS with real certificates, a reverse proxy configured
  both with and without `trusted_proxies` declared, and all ingest listeners bound — SEC-62, SEC-65,
  SEC-66. This is also the asset the pentest scope (Scenario F, lot 2) is written against.
- **A confidential-computing host** (AMD SEV-SNP or Intel TDX) — SEC-58 only. Cloud instance is fine.
- **Live SQL Server 2025 and PostgreSQL** (containers acceptable; `ci.yml` already provisions both) —
  SEC-42, SEC-55.
- **A NAT'd and a bridge-networked container topology** — SEC-25.
- **A browser matrix** (Edge, Chrome, Firefox) — SEC-52.
- **VS Code with `@vscode/test-electron`** (already wired at `ci.yml:315`) — SEC-49.

**Services and PKI**

- **HashiCorp Vault or OpenBao** with the **Transit** engine enabled (the suite already exercises
  OpenBao 2.6.0) plus a **KV v2** mount for SecretProvider — SEC-40, SEC-41, SEC-42, SEC-43.
- **A test PKI**: an internal CA for the ADR 0093 pinned trust anchor, expired and near-expiry leaf
  certificates, and a client-cert chain for mTLS — SEC-61, SEC-15, SEC-62.
- **A CRL/OCSP-capable terminator**, or an explicit `MEFOR_TLS_REVOCATION_ATTESTED=1` posture, so the
  ADR 0078 refusal can be exercised **both** ways — SEC-60.
- **An LDAP/AD directory** (or a controllable LDAP server) that will accept hostile usernames — SEC-30.
- **A customer-managed or self-hosted Anthropic-compatible LLM endpoint** for the ADR 0135 broker
  path, plus a deliberately non-allow-listed endpoint for the SSRF refusal — SEC-48.
- **Loopback stub servers** for the SSRF and injection corpora: HTTP (with configurable 3xx), SMTP,
  DICOMweb, syslog-over-TLS. Build these as pytest fixtures, not standing services.

**Credentials, secrets and licences — must be procured or provisioned**

- `MEFOR_FORBIDDEN_TOKENS` repository secret (exists) — **required non-fork** for SEC-04 and SEC-50.
  A locally provisioned `scripts/security/scan-tokens.local.txt` (gitignored, `.gitignore:126`;
  a synthetic `.example` ships) is the developer-side equivalent. **Never commit either.**
- GitHub Actions with `security-events: write` and a public-repo posture (already true) — CodeQL,
  Scorecard, SARIF upload. A Sigstore / PyPI Trusted-Publishing identity for SEC-63.
- **An external security firm engagement under NDA** — SEC-64, SEC-65. Not currently procured.
- **A DAST tool and licence** with an authenticated scan profile — SEC-66. Tool choice is open.
- **A fuzzing/property-testing dependency decision** — none of `hypothesis`, `atheris` or
  `schemathesis` is in `pyproject.toml` today; adding one requires the §7 dependency-verification
  step and a re-lock — SEC-67.
- **A licence-resolution tool decision and a ratified licence allow-list** — SEC-77. Nothing resolves
  dependency licences in CI today, so this needs a tool (`pip-licenses` / `reuse` / `licensecheck` or
  the CycloneDX SBOM's own licence field), the §7 dependency-verification step and a re-lock, plus an
  owner-ratified allow-list that distinguishes "acceptable under AGPL distribution" from
  "sublicensable under the commercial arm".
- A decision on releasing the private `docs/security/` corpus under NDA — SEC-64, SEC-69. The corpus
  is withheld from the public repo, not missing, so this is a disclosure decision, not a
  reconstruction effort.

**Synthetic data — the only data permitted**

- All HL7 comes from `python -m messagefoundry generate` (conformant synthetic generators,
  `messagefoundry/generators/`). The generated corpus is git-ignored.
- Injection payloads (SEC-31/32/33) are **hostile strings written into synthetic messages**, never
  real identifiers.
- The load sentinel (SEC-45) is a fabricated token (`ZZSENTINEL^LOADTEST`) placed in PID-5 — it is a
  detector, not PHI.
- The de-identification corpora already exist as golden + adversarial fixtures under the ADR 0030
  parity suite; reuse them, do not create new ones.
- **`dryrun` and `generate` output can contain full message bodies.** Never redirect either into a
  committed file, a ticket, a job summary or a CI log. Load reports carry metrics and metadata only.

---

### 15.8 Exit criteria

This area is signed off for release when **all** of the following hold:

1. **Every P0 *test* row is closed.** The eight **T/P0** rows — SEC-01, SEC-02, SEC-03, SEC-04,
   SEC-05, SEC-06, SEC-45 and SEC-67 — are closed by passing tests/legs. The three **A** rows
   (SEC-64, SEC-65, SEC-66) are **not** part of that count: for a loopback-only release they are
   advisory and need only a signed, dated risk acceptance naming its own void condition; for an
   **off-loopback or production-exposure** release they are **blocking and must be delivered**,
   because the standing acceptance is void on exactly that exposure and covers nothing thereafter.
   Whichever applies must be stated explicitly in the release record, not inferred.
2. **Coverage ownership is unambiguous.** Every ADR from 0135 to 0153 with a `messagefoundry/` code
   surface appears in exactly one owner table (this chapter or an extended
   `FEATURE-COVERAGE-PLAN.md` phase), and SEC-01's guard test enforces it. Zero ADRs unowned.
3. **The CI gate set is guarded.** SEC-02 and SEC-03 pass; mutating any of the seven blocking
   `security.yml` jobs to advisory, or adding a new advisory job outside the register, fails the
   suite. Demonstrated by a planted-mutation self-test, not by inspection.
4. **The leak gate is provably alive.** SEC-04's per-section floor assertion runs in CI, SEC-05's
   structural test passes, and the two negative rehearsals in Scenario D have been run once and
   recorded.
5. **The TLS floor is observed, not merely constructed.** SEC-14, SEC-15 and SEC-16 pass; there is at
   least one recorded handshake refusal per listener family.
6. **Injection is proven compositionally.** SEC-29, SEC-31, SEC-32 and SEC-33 pass. SEC-30 has been
   run once against the AD lab and recorded.
7. **Both halves of ASVS 15.2.5 are exercised.** SEC-35 runs as a CI leg; SEC-36 and SEC-37 pass; and
   SEC-39 records an owner decision on ADR 0147 (build or accept).
8. **The Transit posture is usable and honest.** SEC-40 passes (a Transit PHI instance starts and the
   posture surface reports it correctly), SEC-41 and SEC-42 pass, and SEC-43 publishes a throughput
   figure.
9. **PHI containment is proven at volume.** SEC-45, SEC-46 and SEC-47 pass with zero sentinel
   occurrences. SEC-48 has a written disposition plus its test. SEC-49 passes. SEC-50 runs in CI.
10. **The posture surface tells the truth.** SEC-23 passes — every `[store]`/`[auth]` exemption either
    reports as a loosening or has a demonstrated gate. SEC-51 pins the unpaced `/ui` write set and
    cites its tracking item `BACKLOG #287`.
11. **Supply chain is enforced, not advertised.** SEC-10, SEC-11, SEC-12 and SEC-13 pass; the SBOM and
    container CVE gates are blocking on the PR path with a numeric sbomqs floor; SEC-63 has been run
    once against a published tag.
12. **Documentation drift is guarded.** SEC-07 and SEC-72 pass, and MIG's consolidated FEATURE-MAP
    drift guard and doc-path linter (which SEC-08 and SEC-09 point at) pass with the security-side
    inputs folded in. `docs/SECURITY.md`, `docs/FEATURE-MAP.md` and the workflow headers match HEAD;
    every path-shaped citation resolves or is correctly reported as *withheld* (`docs/security/`,
    `docs/reviews/`, `docs/marketing/`); and every `BACKLOG #NNN` **≤ 231** resolves, with references
    above the published baseline left untouched rather than flagged.
13. **The host-bound rows are closed by their owners.** `WIN2025-TEST-PLAN.md` W25:S2.2 / W25:S2.6 / W25:S2.8 are
    PASS on a real Windows Server 2025 box, and SEC-57, SEC-60, SEC-61, SEC-62 are recorded in the
    WIN2025 matrix with real verdicts (never faked; `VERIFY.md`'s PASS/FAIL/SKIP/MANUAL discipline).
14. **`docs/Secure_Build_Scorecard_MEFOR.md` is re-graded** against the post-2026-07-14 wave, with
    signal 10's status updated to reflect the SEC-64/65/66 outcome, and SEC-70's ADR 0148 re-score is
    signed.
15. **No test in this chapter passes by skipping.** Any row whose method is `pytest`/`CI-leg` and
    which currently `skipif`s must either run in at least one shipped leg or be reclassified as
    `manual`/`external` with its environment prerequisite named in §15.7. Equally, **no C row is
    counted as a pass** — a characterisation row contributes a recorded number or a dated decision
    and never gates the release; if a threshold is agreed for one, it converts to **T** and joins the
    gate in the same commit.
16. **The four newly-owned surfaces have real coverage.** SEC-73 proves the last-resort handler
    (`last_resort.py`) is installed in a real serving process and leaks no sentinel on either path;
    SEC-74 proves `netaddr.py`'s two callers agree on every cell of a shared address table with the
    loopback carve-out as the **only** sanctioned divergence; SEC-75 and SEC-76 give `pki.py` an
    adversarial PKCS#12 corpus and a key-material-egress assertion; and SEC-77, SEC-78 and SEC-79
    make **licence / copyleft compliance** an enforced CI property — a copyleft-incompatible or
    commercially-unsublicensable dependency fails the build, the MPL-2.0 per-file obligation on
    `samples/messages/hapi-hl7v2/` is held by a digest manifest, and `NOTICE` and the shipped SBOM
    cannot drift apart. Before this chapter, all four had zero coverage anywhere in the plan.

---

### 15.9 Open questions

1. **Does `docs/testing/FEATURE-COVERAGE-PLAN.md` gain a new phase covering ADRs 0135 and 0138–0153,
   or does this SEC chapter become the standing owner of that wave with the FCP frozen at its
   2026-07-13 scope?**
   *Blocks:* SEC-01's guard-test design (which document it reads) and every "is this covered?" answer
   for eleven ADRs.

2. **When is the independent assessment + penetration test + DAST commissioned — at GA, at the first
   off-loopback customer, or on a fixed date? What budget and scope (engine only, or engine + `/ui` +
   IDE extension + container image)? Who is the counterparty, and may they receive the private
   `docs/security/` corpus under NDA?**
   *Blocks:* SEC-64, SEC-65, SEC-66 and the validity of the standing risk acceptance, which voids on
   the very exposure the pentest requires.

3. **`docs/security/` is deliberately withheld from the public repo (gitignored, `.gitignore:144`) —
   the documents exist, they are just not readable here. Is any subset — the risk-acceptance
   register, or a requirement→control→artefact mapping — published or made machine-readable so a
   drift guard running in public CI can hold the code to the assessment?**
   *Blocks:* SEC-69 and any automated ASVS-conformance claim. Note the question is about **linkage**,
   not existence; the same applies to `docs/reviews/` and `docs/marketing/` (`:145-146`).

4. **Is the `vault_transit` keyless-PHI serve-gate defect a release blocker, or does ADR 0138 stay
   demand-gated and explicitly unsupported for PHI until `__main__.py:1161` is made
   `cipher_provider`-aware?**
   *Blocks:* SEC-40 (whether it is a fix-and-test or a documented-unsupported row) and the honesty of
   `GET /security/posture` for that configuration.

5. **Should the ADR 0144 handler-security lint flip to blocking by default in `messagefoundry check`
   for a PHI instance, or stay operator-opt-in? If opt-in, does the project ship a reference CI leg
   proving the block mode still works?**
   *Blocks:* SEC-35's shape — a default-posture change versus a reference leg.

6. **ADR 0147 is Proposed with no code. Is hardened runtime isolation on the roadmap, or is the ASVS
   15.2.5 runtime residual formally accepted given the sandbox cannot coexist with
   `db_lookup`/`fhir_lookup`?**
   *Blocks:* SEC-39, and whether SEC-36/37 are progress toward a boundary or documentation of a
   permanent limitation.

7. **Should `/ai/chat` screen prompt CONTENT (an HL7-shape or redaction pass before brokering), or is
   "the engine enforces the declared scope, not the content" the accepted boundary?**
   *Blocks:* SEC-48. Either answer needs a written disposition in `docs/AI.md` **and** a test; the
   current state is silence on the only sanctioned PHI-egress-shaped path in the product.

8. **Do the `sbom` and `trivy` jobs get promoted to blocking and moved back onto the PR path, and does
   sbomqs get a numeric floor?**
   *Blocks:* SEC-12, SEC-13. The current cron-only advisory posture is a deliberate CI-cost decision
   that `docs/SUPPLY-CHAIN.md`'s promise to hospital security teams does not reflect.

9. **Is the `security_loosenings()` `[store]`/`[auth]` exemption set closed in this cycle, or does
   `GET /security/posture` keep its documented blind spot over `trust_server_certificate`,
   `ad_allow_insecure_ldap`, `ad_tls_verify` and `oidc_require_mfa_claim`?**
   *Blocks:* SEC-23 — whether it is a closure test or a "prove the alternative gate" test.

10. **Is `/ui` write-path pacing parity in scope for the next release?** The tracking item exists —
    `BACKLOG #287`, cited by `docs/SECURITY.md:107` and `docs/CONFIGURATION.md:435`, above the
    published #231 baseline — so the open question is scheduling, not filing.
    *Blocks:* SEC-51 — whether the pin records a gap that is about to close or one that stands.

11. **ANSWERED 2026-08-10 (BACKLOG #1011): retire.** The question was whether to keep the shipped
    terminating re-originator `tools/ech-sidecar/` (Go, 312 lines) — which no workflow built, tested or
    version-pinned and `pyproject.toml:21` kept out of the distribution — or delete it. The owner ruled
    **retire**: the tree is deleted (recoverable at `62fd628d`), ADR 0139's status block and checklist
    are reconciled, `docs/SECURITY.md`'s 12.1.5 paragraph no longer rests on "infeasible", and ASVS
    12.1.5 stands as an accepted `fail`. **Still open, and not answered by this ruling:** any external
    statement about SNI hiding remains unsupported — the engine ships routing, never ECH origination.
    *Unblocked:* SEC-71 (discharged), SEC-01's status-vs-code half.

12. **Is a fuzzing / property-testing capability in scope, and if so is it a CI leg or an off-repo
    campaign? Which dependency (`hypothesis` / `atheris` / `schemathesis`) is approved?**
    *Blocks:* SEC-67. The HL7, X12, DICOM and base64-carriage parsers are the most
    attacker-exposed code in the product and today have only hand-written adversarial cases — and two
    of them sit on single-maintainer upstreams with no dormancy contingency (BACKLOG #89).

13. **Which licence-resolution tool becomes the SEC-77 gate, and who ratifies the allow-list —
    specifically the rule that a term acceptable for AGPL distribution but not sublicensable under
    the commercial arm is a build failure rather than a warning?**
    *Blocks:* SEC-77, SEC-79. The product is dual-licensed (`LICENSE` + `COMMERCIAL-LICENSE.md` +
    `CLA.md` + `docs/DUAL_LICENSING_PLAN.md`) and nothing in CI checks a dependency licence at all
    today, so the first incompatible dependency would ship unnoticed under the commercial arm.

14. **Who owns re-grading `docs/Secure_Build_Scorecard_MEFOR.md` after this chapter's rows land, and
    on what cadence?**
    *Blocks:* exit criterion 14 — the scorecard is the artefact an evaluator reads first, and it is
    currently graded against a 2026-07-14 snapshot that predates eleven security ADRs.
