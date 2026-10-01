# Security loosening guide (`[security]`)

> The inverse of a hardening guide. MessageFoundry ships **secure by default** — every `[security]`
> switch defaults to the protective position ([ADR 0118](adr/0118-secure-by-default-security-configuration-section.md)).
> This document is the deliberate-deviation register CISA *Secure by Design* prescribes: for each
> protection you can turn off, **what you lose**, **when it is acceptable**, and the **compensating
> controls**. Loosening a protection is warned at `serve` (a plain-language line naming the risk) and is
> surfaced read-only in the web console (`GET /security/posture`).

**Two invariants hold no matter what you set here** ([ADR 0092](adr/0092-posture-keyed-transport-hop-refusal-refuse-the-insecure-phi-hop.md) §5, the *No-loosen rule*):

1. **A PHI weakening under strict enforcement is still refused — with two explicitly-acknowledged
   exceptions.** No `[security]` value — and no `--allow-insecure-bind` / `MEFOR_ALLOW_INSECURE_TLS` escape —
   can start a **PHI instance at `enforcement = enforce`** (the default) with a **cleartext off-box bind, no
   auth, open egress, or unbounded PHI retention**. Those four still fail closed (`serve` exits 2),
   unconditionally. At the default this is **byte-identical to the former production-PHI refusal** — [ADR
   0148](adr/0148-phi-default-posture-and-an-explicit-security-enforcement-level.md) (GIVEN 2) re-keyed the
   refuse/warn dial off the *derived* `production` tier and onto the *explicit* `enforcement` level;
   `enforcement = warn` reproduces the historical non-production warn-and-start (a loud, audited loosening —
   see the `enforcement = warn` deviation below). **Two of these controls may be lifted while staying at
   `enforce`, but only behind a dedicated acknowledgment switch that does nothing else** (the No-loosen
   carve-out, [ADR 0092](adr/0092-posture-keyed-transport-hop-refusal-refuse-the-insecure-phi-hop.md) §5 as amended, [ADR 0140](adr/0140-two-acknowledged-production-phi-no-loosen-carve-outs-single-factor-admin-at-exposure-keyless-phi-in-production.md)):
   `allow_single_factor_admin_when_exposed` (single-factor admin at exposure) and
   `allow_unencrypted_phi_under_strict_enforcement` (keyless PHI under strict enforcement, which *also*
   requires `allow_unencrypted_phi`). Each defaults `false` — byte-identical to today's refusal — and when set
   drops the refusal to a **loud, audited warning** (the same warn-and-start `enforcement = warn` takes
   globally, but scoped to exactly one control, plus a startup **AUDIT** line) and is surfaced read-only in
   `GET /security/posture`. Without its ack, each still fails closed under strict enforcement.
2. **ePHI access is always audited.** The tamper-evident audit hash-chain and the message-event compliance
   floor are unconditional — independent of every switch here (including `audit_all_authorization_decisions`).

Editing is **IDE-only** (the VS Code *Edit Security Settings* command, which shells `messagefoundry
security show|set`); the web console is **read-only**. See [CONFIGURATION.md](CONFIGURATION.md) for the
section reference.

---

## The switches

| Group | Switch | Secure default |
|---|---|---|
| Network access | `local_access_only` | `true` (loopback bind) |
| | `listen_address` | `127.0.0.1` |
| | `require_encryption_for_remote` | `true` |
| | `serve_web_console` | `true` (on by default, ADR 0143 — *not* a loosening; disabling shrinks surface) |
| | `web_console_public_address` | `""` |
| | `allowed_client_networks` | `[]` (*conditional* — see below: empty is the SECURE position on a loopback bind, a loosening only once exposed) |
| Encryption | `encrypt_stored_data` | `true` |
| | `allow_unencrypted_phi` | `false` |
| | `allow_unencrypted_phi_under_strict_enforcement` | `false` |
| In-use data protection | `memory_encryption_operator_declared` | `false` (ADR 0152 — *not* a loosening: it ASSERTS a host property rather than giving one up. Its absence on an exposed PHI instance warns at every start) |
| | `require_memory_encryption_declaration` | `false` (*not* a loosening either — it TIGHTENS, turning that warning into a refusal. Opt-in because the property is a host property that cannot be satisfied on Windows) |
| Sign-in & identity | `require_sign_in` | `true` |
| | `require_mfa` | `true` |
| | `allow_single_factor_admin_when_exposed` | `false` |
| | `sign_out_after_idle_minutes` | `30` |
| | `max_session_hours` | `12` |
| Alert transport | `allow_unverified_alert_smtp_tls` | `false` |
| Store principal | `allow_over_granted_store_principal` | `false` (ADR 0199: accept an over-granted store login under `enforce`, audited) |
| Backend credentials | `require_nonstatic_credentials` | `false` (*not* a loosening — it TIGHTENS, refusing backend hops on a static credential or none. Opt-in by owner decision, because several hops have no compliant kind in the product) |
| | `static_credential_accepted` | `{}` (each opt-out is a loosening while `require_nonstatic_credentials` is on, and is reported as `static_credential_accepted`; with the refusal off an opt-out does nothing and is not reported) |
| Data handling | `block_unlisted_outbound` | `true` |
| | `delete_message_bodies_after_days` | `30` (`0` = keep forever) |
| | `allow_keeping_phi_indefinitely` | `false` |
| | `allow_keeping_transform_state_indefinitely` | `false` |
| | `allow_keeping_search_presets_indefinitely` | `false` |
| | `allow_keeping_app_logs_indefinitely` | `false` |
| | `allow_keeping_backup_archives_indefinitely` | `false` |
| | `audit_all_authorization_decisions` | `true` (see note) |
| Enforcement dial | `enforcement` | `enforce` (refuse; `warn` = loud audited loosening) |
| Production tier | `production_instance` | *derived from environment* |
| Outside `[security]` | `[store].aad_bind` | `true` (at-rest values bound to their cell) |
| | `[store].allow_unmarked_ciphertext` | `false` (an unmarked value in an encrypted column is refused) |
| | `[auth].ad_session_recheck_seconds` | `300` s (*conditional* — a loosening only once `ad_enabled`) |
| | `[auth].ad_allow_insecure_ldap` | `false` (*conditional* — a loosening only with `ad_enabled` and an `ldap://` `ad_server`, which loads only under `enforcement = warn`) |
| | `[auth].admin_new_ip_step_up` | `true` (*conditional* — a loosening only while auth is on) |
| | `[auth].login_rate_limit_enabled`, `login_rate_limit_per_ip`, `login_rate_limit_global`, `login_rate_limit_window_seconds` | `true` / `10` / `60` / `60` s (*conditional* — a loosening only while auth is on; `false`, a count of `0` or above its default, or a window below `60` s is named, and `0` or a window of `0` or less turns a limit off) |
| | `[auth].lockout_minutes`, `lockout_threshold`, `lockout_max_minutes` | `15` / `5` / `1440` (*conditional* — a loosening only while auth is on; minutes below `15` or a ceiling below `1440` is named, and so is a threshold above `5`; minutes of `0` or less means no lock ever holds) |
| | `[auth].phi_read_rate_limit_enabled`, `phi_read_rate_limit_per_actor`, `phi_read_rate_limit_window_seconds` | `true` / `120` / `60` s (*conditional* — a loosening only while auth is on; `false`, a count of `0` or above `120`, or a window below `60` s) |
| | `[auth].admin_write_rate_limit_enabled`, `admin_write_rate_limit_per_actor`, `admin_write_rate_limit_window_seconds`, `admin_write_min_interval_seconds` | `true` / `12` / `15` s / `0.15` s (*conditional* — a loosening only while auth is on; `false`, a count of `0` or above `12`, a window below `15` s, or a gap below `0.15` s) |
| | `[auth].mfa_verify_min_elapsed_seconds`, `oidc_callback_min_elapsed_seconds` | `1.0` s / `1.0` s (*conditional* — a loosening only while auth is on, and the second only with OIDC on; a floor below `1.0` s, and `0` turns it off) |
| | `[auth].max_sessions_per_user` | `5` (*conditional* — a loosening only while auth is on; `0` or less means unlimited, and so is named, as is any cap above `5`) |
| | `[auth].oidc_flow_cache_max` | `512` (*conditional* — a loosening only while auth and OIDC are on; a cap above `512`. `0` or less refuses every flow, which is stricter) |
| | `[api].trusted_proxies` | `[]` (entries covering every address, such as `0.0.0.0/0` or `::/0`, trust `X-Forwarded-For` from every peer, as the refused `*` would) |
| | `[secret_rotation].enforce_store_key_expiry` | `true` (a calendar-overdue store DEK refuses to start) |
| | `[api].plaintext_upstream_hop_acknowledged` | `false` (*conditional* — a loosening only while `[api].tls_terminated_upstream` is set with no `[api].tls_cert_file`, the one topology where the engine serves the proxy-to-engine hop in plaintext) |
| Per-connection | `cleartext_accepted` | `false` on every outbound / `FhirLookup` (*connection-scoped* — see below) |
| | `tls_allow_expired` | `false` on all six outbound connectors that take it (*connection-scoped*) |
| | `tls_hop_attested` | `false` on every inbound / outbound / `FhirLookup` / `DatabaseLookup` / `DatabaseRef` (*connection-scoped*) |
| | generic-ODBC `DATABASE` TLS | a verifying `odbc_params` keyword (*connection-scoped*; inbound **and** outbound) |
| | `tls_revocation_attested` | `false` on every inbound / outbound / `FhirLookup` (*connection-scoped*) |

**At least thirty of these do not live in `[security]`.** `[store].aad_bind`,
`[store].allow_unmarked_ciphertext`, `[auth].ad_session_recheck_seconds`,
`[auth].ad_allow_insecure_ldap`, `[auth].admin_new_ip_step_up`, the four `[auth].login_rate_limit_*` keys, the three `[auth].lockout_*`
keys, the three named `[auth].phi_read_rate_limit_*` keys, the four `[auth].admin_write_*` keys,
`[auth].mfa_verify_min_elapsed_seconds`, `[auth].oidc_callback_min_elapsed_seconds`,
`[auth].max_sessions_per_user`, `[auth].oidc_flow_cache_max`,
`[secret_rotation].enforce_store_key_expiry`, `[api].trusted_proxies` and
`[api].plaintext_upstream_hop_acknowledged` sit in their own sections for cohesion, and the per-connection rows are per-**connection** facts, not service
settings at all. They are listed and reported here anyway, because the rule is *one shipped
posture, loosen only* — a deviation the registry cannot see is a second posture by the back door. The
section settings are named by `security_loosenings()` from the loaded
`[store]`/`[auth]`/`[secret_rotation]`/`[api]` sections; the per-connection
rows are resolved from the loaded connection graph and passed in by name (see their entries below for
exactly which surfaces see them, and which cannot).

> **Scope, stated plainly.** The registry covers *every* `[security]` switch (a completeness floor in
> `tests/test_security_posture_defaults.py` fails on an unreported, unexempted one), the connection
> factories' TLS-shaped parameters (a second floor in the same file censuses the factory signatures,
> because a per-connection deviation is outside `model_fields`' reach by construction) and the
> enumerated deviations above. It is **not yet** an exhaustive register of every security-relevant
> switch in every section: `[store].encrypt` / `trust_server_certificate` and
> `[auth].enabled` / `require_mfa` / `ad_tls_verify` /
> `oidc_require_mfa_claim` are gated by their own serve-time refusals and are **not** reported here.
> That gap is enumerated in the floor test's exemption set, so it is a written decision rather than an
> accident, and a *new* switch in either section cannot join it silently. Closing it is owed work.

`enforcement` (ADR 0148 GIVEN 2) is the serve-gate **refuse/warn dial** + the [ADR 0092](adr/0092-posture-keyed-transport-hop-refusal-refuse-the-insecure-phi-hop.md)
escape-clamp key, defaulting to `enforce` (byte-identical to the former production-tier refusal). It is
**decoupled** from `production_instance` — a PHI *staging* box is now strict by default too. `enforcement`
gates every "still refused" clause below; `enforcement = warn` downgrades them all to loud, audited warnings.

`production_instance` defaults to the value **derived from the active environment name** (`dev` →
non-prod, `staging` → non-prod, `prod` → prod); a custom-named environment must declare it or `serve`
fails closed. It is the production **tier** — it drives the AI data-scope ceiling and the DEBUG-log
refusal, not the serve-gate dial.

**There is no data-class lever on this page any more.** `handles_real_patient_data` sat beside it and
was retired in [ADR 0186](adr/0186-retire-the-synthetic-data-declaration-every-instance-carries-patient-data.md): **every instance carries patient data**, and the PHI gates apply
unconditionally. It is refused at load. Each gate it used to relax now has to be reached by its own
switch, which is the point — the retired lever reached all nineteen without naming any of them, and
`security_loosenings()` never named it either, so the serve-time warning that fires for every
deviation on this page did not fire for the widest one the product shipped. **Not all nineteen have a
heading below**; the retired lever's own section names the two that do not, and where to reach them.

`audit_all_authorization_decisions` **changed sides on 2026-09-02** (BACKLOG #1277). It used to default
`false` and this page called that "a deliberate secure-and-usable default, not a loosening", on the
ground that full authz tracing would flood the hash-chained audit log through console polling and the
`/ws/stats` feed. **That named a surface the switch cannot reach:** the web console is server-rendered
in-process and never traverses `require()`, and `authorize_ws` fires once per *connection*. The default
is now `true`, turning it **off** is a deviation, and it has its own entry below. The owner delegated
the call to the Console on 2026-09-02; the Console decided ([ADR 0118](adr/0118-secure-by-default-security-configuration-section.md)
§5, amended).

---

## Deliberate deviations

### `local_access_only = false` — expose the operator API/console off this machine
- **What you lose:** the API + web console become reachable from the network, not just this host.
- **When acceptable:** a real remote-operations need, on a trusted/segmented network, with TLS.
- **Compensating controls:** keep `require_encryption_for_remote = true` (TLS required); front with a
  revocation-checking reverse proxy (`[api].tls_terminated_upstream` + `trusted_proxies`); a managed admin
  host / mTLS (OFF-LOOPBACK-DEPLOYMENT.md).
- **Still refused:** an off-box bind without TLS (unless `require_encryption_for_remote = false`, below).
- **`serve --host <non-loopback>` counts as this deviation**, even with no `[security]` block in the file.
  The flag is merged after the `[security]` desugar so it wins over the config, and the loader then folds
  the effective bind back into the posture view: `local_access_only` reads `false` and `listen_address`
  names the host actually bound. The exposure is therefore reported wherever loosenings are. The fold is
  **one-way**: it only ever adds this deviation, so a declared `local_access_only = false` keeps
  reporting even when the socket ends up on loopback.

### `allowed_client_networks = []` (empty) **while the console is exposed** — no source-network allow-list
> **Conditional, unlike every other entry here.** An empty list is the **secure** position on the default
> loopback bind (there is nothing off-box to restrict) and is reported as a loosening **only once the
> surface is actually exposed** — `local_access_only = false`, *or* a set `web_console_public_address`.
> That second term matters: the recommended off-box topology keeps the **loopback bind** behind a reverse
> proxy, so a bind-only test would never fire in the most-exposed supported posture.
- **What you lose:** every host that can route to the bind — or to the proxy in front of it — may reach the
  sign-in page. The engine asserts nothing about *which* networks may reach the operator surface, so the
  restriction exists (if at all) only in firewall config that `GET /security/posture` cannot see.
- **When acceptable:** whenever the host firewall (or the proxy's own `allow`/`deny`) already enforces the
  restriction — which is the **stronger** placement, at SYN rather than after TLS. Leaving this empty is a
  perfectly defensible choice; it is listed so the absence is *visible*, not to push you into setting it.
- **Compensating controls:** the host-firewall `-RemoteAddress` rule
  ([ANTIVIRUS-FIREWALL.md](ANTIVIRUS-FIREWALL.md)); nginx/Caddy `allow`/`deny`; network segmentation.
- **Before setting it:** read the section in
  OFF-LOOPBACK-DEPLOYMENT.md — it is **inert behind an undeclared
  proxy or NAT**, it tightens `[api].trusted_proxies` to single hosts, and a lockout costs a service
  restart ([ADR 0151](adr/0151-operator-surface-source-network-allow-list-security-allowed-client-networks.md)).
- **Still refused:** nothing — this is advisory only. An exposed bind with an empty list starts normally.

### `require_encryption_for_remote = false` — accept off-machine access without an operator certificate
- **What you lose:** it differs by surface. This is the config-file twin of the `--allow-insecure-bind`
  dev escape.
  - **The API** still serves TLS, on the engine's generated self-signed placeholder
    ([ADR 0172](adr/0172-the-engine-always-serves-tls-minting-a-self-signed-certificate-on-first-run.md)).
    No trust store vouches for it, so a remote client can authenticate the engine only by pinning that
    exact certificate. Any other client cannot tell the engine from an on-path attacker.
  - **An inbound MLLP, HTTP, DICOM SCP, raw-TCP or X12 listener** without `tls` binds in cleartext, so
    PHI crosses the network unencrypted.
- **When acceptable:** a lab/loopback-adjacent trusted, firewalled segment; never for real remote PHI.
- **Compensating controls:** network isolation; prefer in-process TLS (`[api].tls_cert_file`) or a
  TLS-terminating proxy instead.
- **Still refused:** either bind under `[security].enforcement = enforce`, the shipped default — the
  [ADR 0092](adr/0092-posture-keyed-transport-hop-refusal-refuse-the-insecure-phi-hop.md)
  clamp cannot be relaxed by this switch or by `--allow-insecure-bind`.

### `serve_web_console = false` — do **not** mount the browser ops console at `/ui` (surface-reducing opt-out)
> **Not a loosening — the inverse.** The console is **on by default** ([ADR 0143](adr/0143-web-console-on-by-default-disableable-with-loopback-secure-context-browser-hardening.md))
> because it is the operator UI, effectively core. Setting `serve_web_console = false` **removes** the `/ui`
> HTML/session-cookie attack surface, leaving a smaller JSON-only deployment — a surface-*reducing* opt-out
> (a hardening), listed here only for completeness. It does **not** appear in `security_loosenings()`.
- **When to disable:** a headless JSON-only deployment, or a hardened bastion where the browser console is
  not wanted.
- **Off-box note:** the default-on applies to **local loopback** binds only. On an **exposed** instance
  (a non-loopback host, a declared TLS-terminating proxy, a set `[api].trusted_proxies`, or a set
  `web_console_public_address`) a
  *default-on* console **auto-degrades to JSON-only** — serving it off-box is a deliberate opt-in
  (`serve_web_console = true` with TLS + `web_console_public_address`). The `/ui` surface stays *stricter*
  than the JSON API: an explicitly-enabled console off-loopback requires `exposure_protected` (TLS or a
  declared proxy) and `web_console_public_address`, and is refused even under `--allow-insecure-bind`.

### `encrypt_stored_data = false` — let a PHI instance start with no encryption key
- **What it does:** it sets the **same** keyless-PHI opt-out that turning on `allow_unencrypted_phi` sets. The
  settings loader folds both into one internal switch, `[store].allow_unencrypted_phi`, and the refusals
  read that switch, not this key. So everything the next entry says about `allow_unencrypted_phi` applies
  here too, with one wording gap: the startup AUDIT line, the warning and the strict-enforcement refusal
  all name `[security].allow_unencrypted_phi` even when this key is the one you set. Search for both
  names.
- **What you lose:** the keyless-PHI refusal. A PHI instance with **no** key starts, and its message bodies,
  summary/metadata (MRN + patient name) and error columns are stored **unencrypted** at rest (only volume
  encryption would protect them). A configured key **still encrypts**: this key does not turn encryption off.
- **When acceptable:** the same cases as `allow_unencrypted_phi` below. Prefer that name, which says what the
  switch does.
- **Compensating controls:** OS/volume encryption; restricted DB file permissions.
- **Still refused:** the same refusals as `allow_unencrypted_phi` below, and nothing more.
  `[store].require_encryption = true` still wins, and under **strict enforcement** (`enforcement = enforce`,
  the default) a keyless start also needs `allow_unencrypted_phi_under_strict_enforcement = true`. This
  bullet used to say a PHI instance still refuses **unless `allow_unencrypted_phi` is also set**. The code
  never did that; it treats this key as that opt-out (BACKLOG #1906).
- **The audit chain:** a store that runs keyless also writes a keyless audit chain, and adding a key later
  does not key it. The rule is stated once, in [ASVS-L2-PHASE0-CHANGES.md](ASVS-L2-PHASE0-CHANGES.md)
  section 4, the *Audit chain* row.

### `allow_unencrypted_phi = true` — start a PHI instance with no encryption key
- **What you lose:** the keyless-PHI refusal; a PHI instance boots and stores PHI unencrypted at rest.
- **When acceptable:** a deliberate, audited operational choice on a host where volume encryption protects
  the data path, pending key provisioning.
- **Compensating controls:** volume encryption; a startup **AUDIT** line records the override.
- **Still refused:** `[store].require_encryption = true` (the plumbing "force a key even on synthetic") wins
  over this; and under **strict enforcement** (`enforcement = enforce`, the default) this flag alone is **no
  longer enough** — keyless start additionally requires `allow_unencrypted_phi_under_strict_enforcement = true`
  (below), otherwise `serve` exits 2.

### `require_sign_in = false` — disable authentication
- **What you lose:** every request runs as a full-privilege *system* identity; no RBAC.
- **When acceptable:** a **loopback-only** embedding/dev harness.
- **Compensating controls:** a loopback bind with no declared TLS terminator only.
- **Still refused:** an exposed instance with auth off — a non-loopback bind, **or** a loopback bind behind a
  declared TLS terminator — is a **hard refuse** — serving full-privilege admin to the network is never one "I
  accept the risk" away, at any posture.

### `require_mfa = false` — single-factor admin
- **What you lose:** the Administrator role authenticates with a password only (no native TOTP second
  factor). Directory accounts lose it too (BACKLOG #1144): a Kerberos session mints MFA-pending, and
  this knob is the only thing that lets it through the gate without an engine factor.
- **When acceptable:** a loopback single-operator box where the second factor adds friction without a
  network exposure.
- **Compensating controls:** keep the bind loopback; enable `admin_new_ip_step_up` if exposed.
- **Still refused:** an **exposed PHI** bind with `require_mfa` off refuses to start under **strict
  enforcement** (`enforcement = enforce`, the default; warns at `enforcement = warn`) — unless
  `allow_single_factor_admin_when_exposed = true` (below) explicitly lifts that refusal to the same audited
  warning while staying at `enforce`.

### `sign_out_after_idle_minutes` / `max_session_hours` — longer sessions
- **What you lose:** a longer idle/absolute session window widens the hijack replay window.
- **When acceptable:** operational ergonomics on a trusted host.
- **Compensating controls:** keep them bounded; shorter is safer.

### `block_unlisted_outbound = false` — allow-any outbound egress
- **What you lose:** deny-by-default egress; a transform may send to **any** destination (PHI exfiltration
  risk) once a transport's `[egress].allowed_*` list is empty.
- **When acceptable:** a synthetic/dev instance, or where every destination is otherwise controlled.
- **Compensating controls:** enumerate `[egress].allowed_*` per transport; network egress filtering.
- **Still refused:** a **PHI** instance with fully-open egress refuses to start under **strict enforcement**
  (`enforcement = enforce`, the default; warns at `enforcement = warn`); a PHI instance that leaves this unset
  gets deny-by-default flipped **on**.

### `delete_message_bodies_after_days = 0` / `allow_keeping_phi_indefinitely = true` — unbounded PHI retention
- **What you lose:** PHI message bodies accumulate at rest without bound (data-minimization failure).
- **When acceptable:** a documented retention requirement that genuinely needs keep-forever, accepted in
  writing.
- **Compensating controls:** a bounded window (e.g. 30 days); a startup **AUDIT** line records the override.
- **Still refused:** a **PHI** instance whose PHI-body window is set **explicitly to `0`** refuses under
  **strict enforcement** (`enforcement = enforce`, the default) unless `allow_keeping_phi_indefinitely = true`
  (which downgrades the refusal to a loud audited warning). This bullet used to say the 30-day auto-bound of
  an *unset* window happened only at `enforcement = warn`. It happens on **both** dials, so the refusal above
  is reached only by an explicit `0` — or by the opt-out itself, which suppresses the auto-bound and therefore
  leaves an unset window unbounded.

### `allow_keeping_<tier>_indefinitely = true` — one retention tier with no window
- **What it covers:** one tier each, never several. `allow_keeping_transform_state_indefinitely`,
  `allow_keeping_search_presets_indefinitely`, `allow_keeping_app_logs_indefinitely` and
  `allow_keeping_backup_archives_indefinitely` acknowledge `state_max_age_days`, `search_preset_days`,
  `app_log_days` and `[backup].retention_keep` at `0` (BACKLOG #1967, owner ruling 2026-09-24).
- **What you lose:** that tier accumulates without bound. Transform state and search presets are PL-2;
  app logs and backup archives are PL-1.
- **When acceptable:** for transform state, until state has an eviction key that a read moves. A window
  there deletes by write time and can remove a correlation entry a Handler still reads. For the other
  three, a documented reason to keep the tier.
- **Compensating controls:** a window on the tier. Each honoured switch writes a WARNING-level startup
  **AUDIT** line naming the tier.
- **Still refused:** under `enforcement = enforce`, a tier with neither a window nor its own switch.
  `allow_keeping_phi_indefinitely` does not count here.

### `audit_all_authorization_decisions = false` — narrow the authorization trail to the sensitive surface
- **What you lose:** every authenticated **read** is authorized and **not recorded**. Only the fixed
  state-changing / configuration / user-management set leaves an `auth.permission_granted` row, so the
  trail can no longer answer *what did this account actually reach*. The loss is silent and cannot be
  repaired afterwards: the rows were never written, and nothing anywhere reports the gap.
- **When acceptable:** a measured audit-volume problem on a busy JSON-API deployment, taken as an interim
  step. The volume this switch adds is one row per authenticated request per `require()`-gated route,
  bounded by your API clients' polling cadence — the browser console contributes none of it, because it
  never traverses `require()`.
- **Compensating controls:** ePHI access stays audited either way (the tamper-evident chain and the
  message-event compliance floor are unconditional), and `auth.permission_denied` is still written on
  every refusal at either value. Prefer slowing the polling client, or ask for the rate/sampling bound on
  read grants, over turning the trail off.
- **Still refused:** nothing. This switch is advisory-only — it changes what is recorded, never what is
  permitted, so no serve gate keys on it at any posture.

### `allow_single_factor_admin_when_exposed = true` — lift the strict-enforcement single-factor-admin refusal
- **What you lose:** on a **PHI** instance under **strict enforcement** (`enforcement = enforce`, the default)
  whose admin surface is exposed (off-loopback bind or a declared reverse proxy) with `require_mfa` off,
  MessageFoundry normally **refuses to start** — the Administrator role would authenticate with a single
  factor over the network. This ack **downgrades that refusal to a loud, audited warning** (the same
  warn-and-start `enforcement = warn` takes, but scoped to this one control), so the instance boots
  single-factor while staying at `enforce`.
- **Scope correction ([BACKLOG #326](BACKLOG.md)):** "a declared reverse proxy" above means exactly
  `[api].tls_terminated_upstream` — the bind-and-proxy posture, **independent of the browser console**. The
  shipped predicate additionally required the console to be *served*, which the ADR 0143 auto-degrade had
  already turned off, so a loopback-behind-a-declared-proxy instance would not have reached this refusal at
  all on first deployment and this ack would have had nothing to lift there. The wording in this section was
  already the intended scope; the code now matches it, and the ack itself is unchanged. An **undeclared**
  proxy (a set `web_console_public_address` with no `tls_terminated_upstream`) stays outside the predicate
  — nothing was declared, so exposure there is an inference, and an inference must not refuse. It has its
  own startup **warning**, which names single-factor admin directly on a PHI instance with `require_mfa`
  off; read that arm, not the ADR 0068 §8 undeclared-proxy warning, as the control for this case (§8 is
  about the `/ui` cookie and HSTS, and the ADR 0143 auto-degrade suppresses it in the same posture).
- **When acceptable:** a production exposure where the second factor is supplied by a **compensating control
  outside MessageFoundry** — an authenticating reverse proxy / mTLS admin gateway. AD/Kerberos MFA
  delegated to the directory is **no longer** one of them: BACKLOG #1144 retired that delegation, so
  this flag gates every Administrator, directory ones included.
- **Compensating controls:** front the admin surface with an MFA-enforcing proxy; prefer `require_mfa = true`
  (native TOTP); enable `admin_new_ip_step_up`. A startup **AUDIT** line records the override and the posture
  view (`GET /security/posture`) names it.
- **Still refused:** every **other** strict-enforcement PHI floor item (cleartext off-box bind, auth-off to
  the network, open egress, unbounded retention) — this ack lifts **only** the single-factor-admin refusal,
  and only at exposure. `require_mfa` off on a **loopback** bind was never refused (no exposure), so this ack
  is a no-op there.

### `allow_unencrypted_phi_under_strict_enforcement = true` — permit keyless PHI under strict enforcement
- **What you lose:** a **PHI** instance under **strict enforcement** (`enforcement = enforce`, the default)
  may start **keyless**, storing PHI unencrypted at rest. This ack is required **in addition to**
  `allow_unencrypted_phi` (which alone permits keyless PHI only once `enforcement = warn`); with both set, the
  strict-enforcement keyless refusal drops to a loud audited warning while staying at `enforce`.
- **When acceptable:** a deliberate, audited choice on a host where **volume/disk encryption** protects the
  data path, pending application-key provisioning — the same rationale as `allow_unencrypted_phi`, raised to
  strict enforcement where it must be stated twice.
- **Compensating controls:** volume encryption; restricted DB file permissions; provision
  `MEFOR_STORE_ENCRYPTION_KEY` and drop both acks. A startup **AUDIT** line records the override.
- **Still refused:** `[store].require_encryption = true` still wins (unconditional); and
  `allow_unencrypted_phi_under_strict_enforcement` **alone**, without `allow_unencrypted_phi`, does **not**
  permit keyless PHI — both are required at `enforce`.
- **Note (behaviour change):** before this switch existed, `allow_unencrypted_phi` alone booted a
  production keyless instance (the keyless gate had no production branch). Requiring the second ack under
  strict enforcement is a deliberate, slight **tightening** ([ADR 0140](adr/0140-two-acknowledged-production-phi-no-loosen-carve-outs-single-factor-admin-at-exposure-keyless-phi-in-production.md);
  the ack was renamed from `allow_unencrypted_phi_in_production` by [ADR 0148](adr/0148-phi-default-posture-and-an-explicit-security-enforcement-level.md) when the dial moved from the `production` tier to `enforcement`).

### `allow_unverified_alert_smtp_tls = true` — permit an unauthenticated `[alerts]` SMTP hop
- **What you lose:** the hop carrying operator alert bodies, **every per-user security-event email**
  (lockout, password/roles change, new-IP admin action) and the SMTP login credential no longer
  authenticates the mail relay. It covers **both** unauthenticated shapes: `[alerts].email_use_tls = false`
  (cleartext) and `[alerts].email_tls_verify = false` (encrypted, but any certificate is accepted). An
  on-path attacker who can answer for the relay reads all of it — and, since stream 12 is the ASVS
  6.3.5/6.3.7 out-of-band channel, can also *deny* a user the notice that their account was just taken over.
- **When acceptable:** a lab/dev relay with a self-signed certificate you cannot re-issue, on a trusted
  network. Prefer pointing `[alerts].email_tls_ca_file` or `[tls].internal_ca_file` at that relay's CA —
  that keeps verification on and needs no deviation at all.
- **Compensating controls:** trusted-network placement; a relay on the same host; a startup **AUDIT** line
  records the override, `security_loosenings()` names it, and `messagefoundry check`'s `alert-smtp-tls`
  advisory prints the hop's posture and whether it is acknowledged.
- **Why an acknowledgment and not the clamped escape:** the EMAIL/DIRECT connectors key their verify-off
  refusal on `MEFOR_ALLOW_INSECURE_TLS` read through the **clamped**
  `weakened_tls_escape_permitted_here()`, which reads the construction-time hop posture. The alerts
  notifier is built in the API lifespan, **outside** `build_check_registry`'s `active_hop_posture` scope,
  where that clamp reads no posture. It used to degrade to the *unclamped* escape there and provide no
  refusal at all; since vault BACKLOG #2354 a missing posture fails closed instead, which would refuse
  the hop with no way across. Either way the clamp cannot express an acknowledgment, so this cell
  gets an explicit `[security]` acknowledgment instead — the first verify-off hop governed that way.
- **Still refused:** nothing here relaxes the connectors. This switch reaches the `[alerts]` cell only.

### `static_credential_accepted` — a backend hop runs on an unchanging credential while the refusal is on
This deviation exists only while `require_nonstatic_credentials = true`. With the refusal off, nothing
is refused, so an opt-out does nothing and is not reported.

- **What you lose:** for each hop you name, ASVS 13.2.1's ask that a backend hop use a service
  account, a short-term token or a certificate. The named hop presents a password, an API key, a static
  bearer token or a Vault token, or presents nothing at all. Whoever holds that credential can use it
  until someone rotates it by hand.
- **When acceptable:** the hop has no compliant credential kind in the product. Each hop's
  `compliant_kind` says so, and the table in
  [`CONNECTIONS.md`](CONNECTIONS.md#static-credentials-on-every-backend-hop) is the one list of
  those hops. Where a compliant kind exists, move the hop to it rather than opting out.
- **Compensating controls:** every opt-out needs a written reason, and a blank one is refused at load.
  Serve logs each honoured opt-out at WARNING with the hop name and the reason, and it also logs an
  opt-out that matches no hop. `security_loosenings()` names the opt-outs.
  `GET /security/posture` marks each opted-out hop `accepted`, and `messagefoundry check` marks it
  `[opted out]`.
- **What the reports show:** each hop's detail names what it presents and its peer, as scheme, host
  and port only. It never shows the credential, a URL path or a query.

### `enforcement = warn` — warn instead of refuse on the PHI serve-gate floor
- **What you lose:** the serve-gate **refuse/warn dial** flips from *refuse* to *warn-and-continue*, and the
  [ADR 0092](adr/0092-posture-keyed-transport-hop-refusal-refuse-the-insecure-phi-hop.md) blunt escapes
  (`--allow-insecure-bind` / `MEFOR_ALLOW_INSECURE_TLS`) and `[auth].ad_allow_insecure_ldap` are
  **honoured** again, the first two only where the
  code knows this posture. A check that reads no posture refuses the escape whatever the dial says
  (vault BACKLOG #2354): at least the CLI commands that open the store without one. This reproduces the
  historical **non-production** PHI behaviour on a box that is otherwise strict-by-default: the cleartext
  off-box bind, open-egress, and single-factor-admin-at-exposure refusals downgrade to loud audited warnings,
  and an explicitly-zeroed PHI retention window warns rather than refusing. (The 30-day auto-bound of an
  **unset** window is not part of this dial — it applies under `enforce` too.) Named once by
  `security_loosenings()` and in `GET /security/posture`.
- **When acceptable:** a PHI **staging / pre-prod** box that must mirror production's *config* (so the
  encryption / egress / retention paths are exercised, not first met in production) but is deliberately run at
  warn severity during bring-up; or a custom PHI-loopback env. A stock production instance never needs it (it
  is `enforce`-equivalent already).
- **Compensating controls:** return to `enforce` before carrying real patient traffic; the warnings + startup
  **AUDIT** line + posture view keep the deviation visible.
- **Still refused (even at `warn`):** the **no-auth-to-the-network** hard refuse (`require_sign_in = false` on
  an exposed instance — a non-loopback bind, or a loopback bind behind a declared TLS terminator) is
  unconditional at **any** enforcement level — `enforcement = warn` does **not** open it — and the unconditional ePHI audit floor is untouched. A declared TLS terminator whose proxy-to-engine hop is plaintext (no `[api].tls_cert_file`) also still needs `[api].plaintext_upstream_hop_acknowledged` at any enforcement level (BACKLOG #1179; [CONFIGURATION.md](CONFIGURATION.md) `[api]` table). `enforcement` is **binary** (no `off`), and **nothing silences a
  cleartext hop entirely any more**: [ADR 0153](adr/0153-collapse-the-posture-gradient-no-data-label-may-allow-a-cleartext-hop.md)
  removed the data label from that decision and [ADR 0186](adr/0186-retire-the-synthetic-data-declaration-every-instance-carries-patient-data.md) removed the label itself. The
  per-connection `cleartext_accepted` declaration is the way to cross one, recorded per hop.

### `handles_real_patient_data = false` — RETIRED, and refused at load
This section is kept rather than deleted, because the claim it used to make is the reason the lever went.
- **It said:** *"it is a loud, audited opt-out — named by `security_loosenings()`, surfaced in
  `GET /security/posture`, and warned at `serve`"*. **Measured, the first and third were false.**
  `security_loosenings()` contained no reference to it, and the serve-time loosening warning reads that
  registry — so the widest relaxation the product shipped produced no warning line. The posture view did
  carry it, in a separate field the console rendered one style-class quieter than a real loosening.
- **What replaced it:** nothing, deliberately. Relax the one you mean — `allow_unencrypted_phi`,
  `block_unlisted_outbound`, `allow_keeping_phi_indefinitely`,
  `allow_single_factor_admin_when_exposed`, `allow_unverified_alert_smtp_tls`, a per-connection
  `cleartext_accepted`, or the `enforcement` dial. **That list is at least, not every:** the retired
  lever reached nineteen gates and this page does not carry a heading for each of them. Two it reached
  are named here because they have no heading of their own —
  `[alerts].security_notifications_required` accepts the pull-only security-event feed instead of a
  configured channel, and revocation is attested either **per connection** with
  [`tls_revocation_attested`](#tls_revocation_attested--true-on-a-connection--revocation-checked-outside-the-engine)
  or **process-wide** with the environment variable `MEFOR_TLS_REVOCATION_ATTESTED`, which no longer
  crosses an enforcing outbound hop.
- **Setting it now fails the start**, with a message naming those switches. See [ADR 0186](adr/0186-retire-the-synthetic-data-declaration-every-instance-carries-patient-data.md).

### `[store].aad_bind = false` — at-rest values are no longer bound to their cell
- **What you lose:** the per-value GCM tag stops covering the `(table, column, row)` cell the value lives
  in, so a ciphertext **cut and pasted from one cell into another decrypts successfully** instead of
  failing its auth tag. An attacker (or a bug) with write access to the store can move a body, a TOTP
  secret or an audit detail into a different row and have the engine accept it as that row's content.
  Confidentiality is unchanged; what is lost is at-rest **integrity binding** (ASVS 11.3.3).
- **When acceptable:** when you need the frozen `mfenc:v1` at-rest format specifically — a byte-identical
  restore target, an external tool that parses the v1 marker, or a forensic comparison against a v1
  backup. It is also a no-op either way with **no `[store].encryption_key`**: the identity cipher has no
  tag to bind, so on a keyless store this switch changes nothing. The registry still *reports* it (the
  key is env-only and not on `[store]`, so `security_loosenings()` cannot gate on it) — the risk text
  carries the caveat instead, so a keyless dev box reads "no effect without a store key" rather than a
  weakness it does not have.
- **Compensating controls:** database-level access control (the cell-move attack needs store write
  access); `[store].cipher_provider = "vault_transit"`, which binds the AAD **unconditionally**
  (`mfenc:v3`) regardless of this switch; the tamper-evident audit chain, which detects reordering of
  audit rows independently.
- **Reversible:** yes, in both directions. Legacy `v1` rows always decrypt (dual-read) and
  `messagefoundry rotate-key` upgrades them `v1`→`v2` in place, so turning it back on does not strand an
  existing store. See [ADR 0019](adr/0019-pluggable-keyprovider-hsm-kms-vault.md) (2026-07-28 amendment).

### `[store].allow_unmarked_ciphertext = true` — an unmarked value in an encrypted column reads back as plaintext
- **What you lose:** the refusal that protects an encrypted column against a **downgrade**. On a keyed
  store, a non-blank value with no `mfenc:` marker is a stripped marker or a planted plaintext row, and
  with this off it is refused (`CipherError`) and alerted (`integrity_drift`, subject `store-cipher`).
  With it on, that value is returned as the row's content, and the next keyed open or `rotate-key`
  seals it into genuine ciphertext, after which no evidence of the substitution survives. Cell binding
  (`aad_bind`) does not cover this: a moved ciphertext has a tag to fail, and a plaintext value has none
  (ASVS 11.3.3, BACKLOG #1169).
- **When acceptable:** a store that holds legitimate unmarked values beside ciphertext in one column —
  for example rows written by a keyless run of a store that was keyed before. Turn it on for one keyed
  open to seal them, then turn it back off. It is a no-op with **no `[store].encryption_key`**.
- **Compensating controls:** database-level access control, because planting a row needs store write
  access. Nothing in the engine detects the plant once this is on.
- **Reversible:** yes. Turning it back off refuses unmarked values again from the next read; anything
  it sealed while on stays sealed.
- **Uploads too:** on a keyed store a plaintext uploaded file is refused until `rotate-key` seals it
  (owner ruling 2026-09-23), alerting under its own subject `upload-cipher`. With this on, it is served as plaintext instead. Under
  `cipher_provider = "vault_transit"` uploads pass through either way; [PHI.md](PHI.md) §3 says why.
- **Not covered either way:** the DIRECT S/MIME connector's enveloped body.

### `[secret_rotation].enforce_store_key_expiry = false` — the store DEK's calendar expiry stops the engine no more
- **What you lose:** the **hard stop** on a calendar-expired data-encryption key. With it on, a DEK past
  `store_key_max_age_days + enforce_grace_days` (365 + 30 as shipped) aborts engine start under
  `[security].enforcement = enforce`, and so does a DEK whose age cannot be determined at all. With it
  off, that same key keeps encrypting PHI at rest indefinitely and the only remaining signal is a
  `secret_rotation_due` alert — which nobody has to answer. The engine documents an annual DEK cadence
  (ASVS 13.3.4); this switch is what makes that cadence a control rather than a suggestion.
- **What you keep:** the alert. The opt-out suppresses the refusal and nothing else, deliberately — an
  operator who accepted the risk still needs to be told the key is stale. The same key's **usage** axis
  is also untouched: it still refuses unconditionally at 2^32 encrypts, with no opt-out at all.
- **When acceptable:** a scheduled maintenance start where rotating first is genuinely impossible, or a
  restore/forensic bring-up against an old store whose key you must not rotate. Both are bounded windows.
  Leaving it off permanently means the annual cadence is unenforced.
- **Compensating controls:** none that substitute. Route `event_type = "secret_rotation"` to a transport
  somebody reads and treat `enforced = true` as an incident; the alert is the whole remaining signal.
  `GET /security/posture` and the `serve` warning name the switch on every boot, so at least the gap is
  visible.
- **Reversible:** yes, immediately — set it back to `true` (or delete the line) and restart. Nothing
  about the key or the store changes either way; only whether the engine agrees to start.

### `[auth].ad_session_recheck_seconds = 0` **with `ad_enabled`** — directory revocation stops propagating
> **Conditional**, like `allowed_client_networks`. With no directory to reconcile against, `0` is not a
> weaker choice — it is the only meaningful one — so it is reported as a deviation **only** when
> `[auth].ad_enabled` is true. The shipped `300` default is inert on a non-AD box (the reconciler also
> requires an LDAP client), which is why it does not break one.
- **What you lose:** an AD account that is **disabled or deleted keeps its live engine sessions**. The
  only remaining bound is the `[security].max_session_hours` cap (12 h) and idle timeout — so a
  terminated employee can hold an authenticated operator session, with PHI access, for up to half a day
  after the directory says otherwise. The same loop also revokes on **group-membership change**, so role
  removals stop propagating too.
- **When acceptable:** a directory whose service-account bind budget genuinely cannot absorb one bind per
  signed-in user per interval; a deployment where operator sessions are already short-lived by policy; or
  a break-glass window while a DC problem is diagnosed. Prefer **raising the interval** (it is floored at
  60 s, not capped) over turning it off.
- **Compensating controls:** lower `[security].max_session_hours` and `sign_out_after_idle_minutes` so an
  orphaned session expires sooner; revoke sessions manually on offboarding; keep the audit trail
  (`auth.ad_session_revoked`) under review. The reconciler is **fail-open** on DC unavailability by
  design, so it was never a substitute for these.
- **See:** [ADR 0079](adr/0079-kerberos-idp-session-coordination.md) (2026-07-28 amendment).

### `[auth].ad_allow_insecure_ldap = true` **with a plain `ldap://` `ad_server`** — AD binds in cleartext
> **Conditional**, and reachable only at `[security].enforcement = warn`. Under `enforce` the switch is
> inert and the config is refused at load, like every other weakened-TLS escape (vault BACKLOG #2354).
> Beside an `ldaps://` address, or with `ad_enabled = false`, it changes nothing and is not reported.
- **What you lose:** the encryption and the server authentication on the AD hop. Both binds are SIMPLE
  binds, so the service-account password and the password of every user who signs in or steps up cross
  the network in cleartext. Nothing proves the far end is your domain controller, so a host on the path
  can read the passwords or answer as the directory.
- **When acceptable:** a trusted-network dev or test box with a lab directory and throwaway accounts.
  Never with a real domain account.
- **Compensating controls:** none that substitute. Use `ldaps://`, and anchor an internal CA with
  `ad_tls_ca_cert_file` rather than turning verification off. Startup logs a WARNING from the
  authenticator, and `serve` and `GET /security/posture` name the switch on every boot. No audit row
  is written, as for the other settings-scoped loosenings.
- **Reversible:** yes, immediately — point `ad_server` at `ldaps://`, or delete the line, and restart.

### `[auth].admin_new_ip_step_up = false` — a new client address mid-session goes unchallenged
> **Conditional** on sign-in. With `[security].require_sign_in = false` there is no session for the signal to
> guard, so it is reported **only** while auth is on. The default is `true` since BACKLOG #288
> (owner ruling 2026-09-26); before that it shipped off, with an exposure-time advisory.
- **What you lose:** a session token presented from a **client address it has not verified from**
  can perform a sensitive admin action on the strength of the ordinary step-up window alone. Nothing
  writes `auth.admin_action_new_ip`, nothing notifies the account holder, and nothing forces a fresh
  step-up. A stolen token replayed from another host is the case this signal exists for.
- **When acceptable:** a deployment whose operators reach the console through a pool of egress
  addresses that rotates between requests (some NAT and VPN concentrators do), where every sensitive
  action would otherwise re-prompt. Declaring `[api].trusted_proxies` correctly fixes the proxy case
  and is preferred over turning this off.
- **Compensating controls:** keep `[auth].step_up_max_age_seconds` short and `require_action_step_up`
  on, restrict the operator surface with `[security].allowed_client_networks`, and review the
  `auth.login_new_ip` rows the sign-in signal still writes. That signal has no switch.
- **Reversible:** yes, immediately — set it back to `true` (or delete the line) and restart.

### `[auth].login_rate_limit_enabled = false`, or a limit looser than its default — sign-in attempts go less paced
> **Conditional** on sign-in, like `admin_new_ip_step_up`: with `[security].require_sign_in = false` there
> is no sign-in to limit. Each of these values is reported under its own key
> ([BACKLOG #1131](BACKLOG.md), ASVS 6.1.1). The owner ruled on 2026-09-27 that a silent weakening here
> keeps ASVS 6.1.1 at partial.
>
> | Value | What loosens |
> |---|---|
> | `login_rate_limit_enabled = false` | Both sign-in limits, per address and across all clients, and the per-user limit on credential ceremonies. None is built. |
> | `login_rate_limit_window_seconds` of `0` or less | The same three are off. The limiter ages every attempt out before it counts it, while the enable switch still reads as on. |
> | `login_rate_limit_window_seconds` below `60` | The same three admit their counts once per that window instead of once per minute. A tiny window, such as `1e-6`, admits nearly every attempt. |
> | `login_rate_limit_per_ip = 0`, or above `10` | The per-address sign-in limit, and the per-user ceremony limit, which reads the same number. `0` turns both off. |
> | `login_rate_limit_global = 0`, or above `60` | The all-clients sign-in limit. `0` turns it off. |
>
> The **credential ceremonies** are re-auth, password change, MFA enrolment, and the console's
> second-factor step at sign-in (`POST /ui/mfa`); [SECURITY.md](SECURITY.md) lists the routes. With the
> limiter off, a count or window changes nothing, so only `login_rate_limit_enabled` is named, and a
> window of `0` or less likewise stands in for its counts. A short window is not named when every count
> it paces is `0`, since it then paces nothing; each zeroed count is named instead. **The cutoff is the shipped default, not a
> judged threshold.** Any value looser than the default is named, so a huge count or a tiny window is
> reported like an off value, with text that says *looser than the default of* rather than *off*. A
> value at or stricter than the default is not reported. That includes a **negative** count, and a
> window that is not a number or is `+inf`, each of which refuses *more* attempts, not fewer.
- **What you lose:** a password spray across many usernames never trips one account's lockout, and these
  limits are what slow it. With the per-address limit off, one client may try as fast as the all-clients
  limit allows. With the all-clients limit off, a spray spread across many addresses grows with the number
  of addresses the attacker holds. With the ceremony limit off, a session holder guessing a password at
  re-auth meets no rate limit, only the per-session cap and the account's lockout (each failed re-proof
  counts toward it), and a second factor at the console's sign-in step is guessed at no set rate.
- **When acceptable:** load testing on a host no untrusted client can reach. A reverse proxy or web
  application firewall in front of the engine can replace the per-address and all-clients limits, but it
  cannot replace the per-user ceremony limit, which keys on the signed-in user. A modest raise for a
  site whose operators share one address behind NAT is the usual case; it is still named, so the
  posture review sees it. Prefer **raising** a limit to turning it off.
- **Compensating controls:** front the API with a proxy or WAF limiter, restrict the sign-in surface with
  `[security].allowed_client_networks`, keep `lockout_minutes` above `0`, and watch the
  `auth.login_failed` audit rows.
- **Reversible:** yes, immediately — restore the default (or delete the line) and restart.

### `[auth].lockout_minutes`, `lockout_threshold` or `lockout_max_minutes` looser than its default — the account lock protects less
> **Conditional** on sign-in, as above ([BACKLOG #1131](BACKLOG.md)). Each key is named when it is looser
> than its shipped default, and each says whether it is off or only looser.
>
> | Value | What loosens |
> |---|---|
> | `lockout_minutes` of `0` or less | No lock holds. A lock is still set at `lockout_threshold` failures, but it ends the moment it is set, on the sign-in and the second-step counter alike. |
> | `lockout_minutes` below `15` | Each lock is shorter, so a run of wrong guesses resumes sooner. |
> | `lockout_threshold` above `5` | More wrong guesses are checked before a lock is set. Above the **100** consecutive failures NIST SP 800-63B allows (SP 800-63B-4 section 3.2.2, rev. 3 section 5.2.2), the text says so: a threshold that large never arms in practice. |
> | `lockout_max_minutes` below `1440` | An escalating lock ([ADR 0197](adr/0197-cap-repeated-lock-cycles-on-one-account-without-making-malicious-lockout-cheaper.md)) stops doubling sooner. Equal to `lockout_minutes`, escalation is off, and the text says so. |
>
> No `lockout_threshold` is read as off, since `0` or less locks on the *first* failure, which is
> stricter. With no lock holding, the ceiling changes nothing, so it is not named beside a
> `lockout_minutes` of `0` or less. A ceiling at `1440` or above is not named even when it equals
> `lockout_minutes`, because every lock then lasts at least as long as the default's longest.
- **What you lose:** at `lockout_minutes` of `0` or less, a run of wrong guesses at one account's password
  or second factor is never refused by a lock. The failures are still counted and audited. Each session is
  still revoked after `lockout_threshold` failed re-proofs, because that cap does not read
  `lockout_minutes`. A shorter lock shortens the wait between runs of guesses, and a lower ceiling
  shortens the longest lock that repeated runs can reach. A higher
  threshold lets that many wrong guesses through before any lock is set, and a session may fail that many
  re-proofs before it is revoked.
- **When acceptable:** rarely. A site whose own sign-in front end already locks accounts may prefer the
  engine not to set a second lock that a stranger could trigger on purpose. Under
  [ADR 0197](adr/0197-cap-repeated-lock-cycles-on-one-account-without-making-malicious-lockout-cheaper.md)
  a local account with TOTP enrolled can already sign in past a sign-in lock a stranger set, and an
  engine-generated credential arms no sign-in lock at all, so check whether that answers the concern first.
- **Compensating controls:** keep the sign-in limits on, enroll every account in MFA, and review
  `auth.login_failed` and `auth.mfa_failed` rows.
- **Reversible:** yes, immediately — restore `15`, `5` and `1440` (or delete the lines) and restart.

### `[auth].phi_read_rate_limit_*` looser than its default — PHI reads go less paced
> **Conditional** on sign-in ([BACKLOG #1131](BACKLOG.md), ASVS 2.4.1). Named: `phi_read_rate_limit_enabled
> = false`; a `phi_read_rate_limit_window_seconds` of `0` or less (off) or below `60` s (looser); a
> `phi_read_rate_limit_per_actor` of `0` (off) or above `120` (looser). The same parts rule applies as for
> sign-in: with the limiter off, or its window at `0` or less, its count is not named again.
> `phi_read_rate_limit_global` ships **off** (`0`), so no value of it is looser than the default and it is
> never named.
- **What you lose:** the per-account pace on the PHI-read routes and console views
  ([SECURITY.md](SECURITY.md) lists them). A stolen session, or a script with a real one, reads message
  bodies and dead letters faster, up to as fast as the engine answers. Every PHI read is still audited.
- **When acceptable:** a bulk export or migration run by one known account, on a host no untrusted
  client can reach. Prefer a modest raise to turning it off, and put it back afterwards.
- **Compensating controls:** keep sessions short, restrict the operator surface with
  `[security].allowed_client_networks`, and review the PHI-access audit rows.
- **Reversible:** yes, immediately — restore the default (or delete the line) and restart.

### `[auth].admin_write_*` looser than its default — state-changing admin actions go less paced
> **Conditional** on sign-in ([BACKLOG #1131](BACKLOG.md), ASVS 2.4.2). Named:
> `admin_write_rate_limit_enabled = false`; an `admin_write_rate_limit_window_seconds` below `15` s; an
> `admin_write_rate_limit_per_actor` of `0` (off) or above `12`; an `admin_write_min_interval_seconds` of
> `0` (off) or below `0.15` s. The window cannot be `0` or less (the load refuses it), but a tiny one,
> such as `1e-6`, loads and admits nearly every write, and the gap must then be shorter still. With the
> limiter off, its parts are not named again.
- **What you lose:** the per-actor pace on purge, replay, config deploy and reload, and every other non-GET
  sensitive action. Both the count and the minimum gap are provisional human-timing floors; see
  [SECURITY.md](SECURITY.md). Looser values let a script holding a session spend them faster than a
  person could. Step-up and RBAC still apply to each action.
- **When acceptable:** a scripted maintenance run by a known account. Prefer a modest raise to turning it
  off, and put it back afterwards.
- **Compensating controls:** keep `require_action_step_up` on, keep `[auth].step_up_max_age_seconds`
  short, and review the admin-action audit rows.
- **Reversible:** yes, immediately — restore the default (or delete the line) and restart.

### `[auth].mfa_verify_min_elapsed_seconds` or `oidc_callback_min_elapsed_seconds` below `1.0` s — a second step may come at machine speed
> **Conditional** on sign-in ([BACKLOG #1131](BACKLOG.md), ASVS 2.4.2), and the callback floor only while
> `[auth].oidc_enabled` is on. These are the BACKLOG #2301 time floors, beside
> `admin_write_min_interval_seconds` above. Each refuses an action that comes sooner than the floor and
> skips the check at `0`, so a floor below its default of `1.0` s is named as looser and `0` as off. A
> higher floor refuses more and is not named.
- **What you lose:** the MFA floor refuses a code or passkey that completes an MFA-pending session too
  soon after sign-in. It applies to any account with a factor, whether or not `require_mfa` is on. The
  callback floor refuses a federated step-up, or a sign-in whose `auth_time` falls inside the flow, that
  returns too soon after it started. Below the default, a script holding a password, or driving a flow,
  may finish the second step faster than a person could read the prompt and answer it. The floors bound
  only the first moments after sign-in; they do not pace guessing after that.
- **When acceptable:** rarely; the floors cost a person nothing at the default. An automated test
  harness on a host no untrusted client can reach is the usual case.
- **Compensating controls:** keep the sign-in limits and the lockout at their defaults, and review the
  audit rows with `reason=too_early` (under `auth.mfa_failed`, `auth.webauthn_failed`,
  `auth.login_failed` and `auth.reauth`).
- **Reversible:** yes, immediately — restore `1.0` (or delete the line) and restart.

### `[auth].max_sessions_per_user` of `0` or above `5` — more live sessions per user
> **Conditional** on sign-in ([BACKLOG #1131](BACKLOG.md), ASVS 7.1.2). `0` or less means unlimited, so it
> is named as off; any cap above `5` is named as looser.
- **What you lose:** a new sign-in beyond the cap revokes the user's oldest live session. With a higher
  cap, or none, a stolen or forgotten session stays live beside the owner's for longer.
- **When acceptable:** an account used from more devices or console instances than five, where each is
  known.
- **Compensating controls:** keep the idle and absolute session limits short, and revoke sessions on
  offboarding.
- **Reversible:** yes, immediately — restore `5` (or delete the line) and restart.

### `[auth].oidc_flow_cache_max` above `512` — more pending federated sign-ins held in memory
> **Conditional** on sign-in and on `[auth].oidc_enabled`, since the cache is built only with federation on
> ([BACKLOG #1131](BACKLOG.md)). The cache refuses a new flow once it holds this many, so a cap of `0` or
> less refuses **every** federated sign-in. That is stricter, not looser, and it is not named. A cap above
> `512` is named. A very large one, such as `1e9`, removes the engine-wide bound in practice.
- **What you lose:** each abandoned login start holds a slot until its time-to-live ends. A higher cap lets
  a flood of starts hold more memory before new ones are refused; the per-address cap still bounds one
  address.
- **When acceptable:** a large site where many people start a federated sign-in within one flow lifetime.
- **Compensating controls:** keep `[auth].oidc_flow_ttl_seconds` short, and front the sign-in routes with
  a proxy limiter.
- **Reversible:** yes, immediately — restore `512` (or delete the line) and restart.

### `[api].trusted_proxies` covering every address, such as `0.0.0.0/0` or `::/0` — every peer may set its own source address
> **Not conditional on sign-in** ([BACKLOG #1131](BACKLOG.md)): a forged source address poisons the audit
> trail either way. The load refuses `*` for this reason, but an entry of `0.0.0.0/0` or `::/0` loads and
> does the same thing for its address family, so it is named instead. So are ranges whose union covers a
> whole family, such as the two `/1` halves of `0.0.0.0/0` listed separately. The check parses each
> entry the way uvicorn does, strictly. An entry with host bits set, such as `10.1.2.3/0`, loads here but
> becomes a literal in uvicorn that matches no peer, so it is not this loosening.
- **What you lose:** uvicorn trusts `X-Forwarded-For` from every peer the entries cover, so any client can
  declare its own source address. That poisons the audit source address, the per-address sign-in limit and
  the new-client-IP step-up signal. With `[security].allowed_client_networks` set, the load already
  refuses any range wider than one host.
- **When acceptable:** never in production. List the reverse proxy's exact address instead.
- **Compensating controls:** none replace it; fix the entry.
- **Reversible:** yes, immediately — list the proxy's own address and restart.

### `[api].plaintext_upstream_hop_acknowledged = true` — a plaintext proxy-to-engine hop, taken on by the site
> **Conditional**, like `allowed_client_networks`. It is reported **only** while `[api].tls_terminated_upstream`
> is set and no `[api].tls_cert_file` is. With an operator certificate the engine serves that hop over TLS,
> so the acknowledgement is inert and is not reported. It is refused at load without
> `tls_terminated_upstream`.
- **What you lose:** a reverse proxy terminates TLS, and the engine mints no certificate behind it
  ([ADR 0172](adr/0172-the-engine-always-serves-tls-minting-a-self-signed-certificate-on-first-run.md)
  decision 3). So the hop from the proxy to the engine is **plaintext**, and the engine does nothing to
  protect it. At least sign-in credentials, session tokens and PHI reads cross that hop unencrypted.
- **When acceptable:** the site keeps the hop private by means the engine cannot see: a same-host
  loopback hop, an isolated network segment, or a host firewall. Without the acknowledgement, `serve`
  refuses this topology in every mode (BACKLOG #1179).
- **Compensating controls:** set `[api].tls_cert_file` so the engine serves that hop over TLS, and point
  the proxy at https with that certificate trusted. Short of that, keep the proxy on the same host.
  Isolation limits who can read the hop; it does not encrypt it.
- **Visibility:** each start with the acknowledgement honoured writes a WARNING-level startup **AUDIT**
  line, and `GET /security/posture` names it. That makes the loosening visible; it protects nothing.
- **Reversible:** yes. Supply `[api].tls_cert_file` and restart; the acknowledgement then does nothing
  and may stay. To drop the terminator instead, remove `tls_terminated_upstream`, the acknowledgement
  and `trusted_proxies` together, or the load refuses.

### `cleartext_accepted = true` on a connection — a declared cleartext hop
> **Connection-scoped, unlike every other entry here.** It is not a `[security]` switch; it is a field on
> one connection — an `outbound(...)` or a `FhirLookup(...)` — declared next to the host it governs, with
> a mandatory `cleartext_reason` recorded for the audit trail.
> [ADR 0153](adr/0153-collapse-the-posture-gradient-no-data-label-may-allow-a-cleartext-hop.md).
- **What you lose:** the payload — and any credential that connection carries — crosses that hop
  **unencrypted and unauthenticated**, readable and modifiable by anything on the path. There is no
  partial protection here: it is plaintext PHI on the wire for that connection.
- **When acceptable:** a peer that genuinely cannot do TLS — vendor firmware that predates it, or a
  transport with no TLS support at all. For `Tcp()` and `X12()` the declaration is **permanent and
  structural**: those connectors have no `tls` parameter, so there is nothing to migrate to
  (BACKLOG #311). For MLLP / HTTP / DICOM / SMTP / FTP it should be **transitional** — it names work to
  be done, and it should disappear when the peer gains TLS.
- **Do not use it to describe a hop that *is* secure.** If a proxy terminates TLS in front of the hop, or
  the segment is genuinely isolated, that is a different claim entirely — `tls_hop_attested`, which ALLOWs
  the hop silently. The two are deliberately separate so the audit trail can tell a proxy-terminated hop
  from plaintext on a flat network. Writing an attestation about a hop that is not secure puts a false
  statement into the one field that exists to be trustworthy when audited. The attestation has its own
  entry, [next](#tls_hop_attested--true-on-a-connection--a-hop-attested-secure-by-means-the-engine-cannot-see).
- **Compensating controls:** network segmentation and physical/link-layer controls on that specific path;
  narrow the blast radius by declaring it on the single connection that needs it rather than broadly.
- **It is never silent:** WARN + a dedicated record at **every** connector construction, naming the
  declaring connection, the cell, the host and the reason; a `cleartext-accepted` line in
  `messagefoundry check` listing the **whole** accepted set (outbound connections *and* `FhirLookup`
  read connections); and a `cleartext_accepted` entry in `GET /security/posture`'s loosening list naming
  every declaring connection. The construction record is a distinct WARNING **log line**, not a
  tamper-evident `audit` table row — the hop decision is pure `config/`-level code and cannot reach the
  engine's store across the one-way dependency boundary. The ADR 0092 attestation record has the same
  shape for the same reason.
- **Where it is NOT reported, and why:** `messagefoundry security show` reads a settings file and never
  loads the connection graph, so it cannot see these declarations; it says so explicitly in its
  `loosenings_scope` output rather than reporting a settings-only list as if it were the whole posture.
  `GET /security/posture` carries the same `loosenings_scope` marker in the one case it is blind — an
  engine with no loaded graph (an embedding, or a query before start); it is `null` on a running engine.
  The `serve`-time loosening warning fires before the graph is loaded for the same reason — the
  construction gate's own per-connection WARN covers it moments later, at startup, with more detail.
- **What it cannot do:** it never yields ALLOW. An accepted hop is always a WARN, so it can never become
  invisible — an accepted risk that stops being visible has stopped being accepted and started being
  forgotten. It also cannot relax a hop ADR 0153 does not govern: inbound binds are still decided by the
  exposed-gates, and **revocation / weakened-TLS (`verify_tls = false`) refusals are unaffected** — a
  verify-off hop is encrypted-but-unauthenticated, not cleartext, so this declaration does not reach it.
  At least the connector verify-off cells keep the clamped `MEFOR_ALLOW_INSECURE_TLS` escape; the
  `[alerts]` SMTP hop is governed instead by the `allow_unverified_alert_smtp_tls` acknowledgment above
  (its construction sits outside the posture scope the clamp reads), so "the clamped escape" is not a
  universal statement about verify-off hops and should not be read as one. Nor does this declaration
  reach an SMTP `AUTH` over cleartext, which is refused outright.

### `tls_hop_attested = true` on a connection — a hop attested secure by means the engine cannot see
> **Connection-scoped**, like `cleartext_accepted` above, and settable in both directions. It is a
> keyword on `inbound(...)`, `outbound(...)`, `FhirLookup(...)`, `DatabaseLookup(...)` or
> `DatabaseRef(...)`. It is also a top-level key on a `connections.toml` `[[inbound]]` / `[[outbound]]`
> table. It needs a mandatory `tls_hop_attested_reason`, and it cannot be combined with
> `cleartext_accepted`. Owner ruling 2026-09-24; the attestation itself is
> [ADR 0092](adr/0092-posture-keyed-transport-hop-refusal-refuse-the-insecure-phi-hop.md).
> It is **not** a transport setting: written into a connection's `settings`, it is refused at load.
- **What you lose:** the engine stops protecting that hop and takes your word that something else does.
  A cleartext or verify-off hop the enforcing gates would refuse is **allowed**: this is the one per-hop
  declaration that yields ALLOW rather than WARN. The crossing is logged, but the hop is recorded as
  secure, not as an accepted risk. That covers at least a non-loopback inbound bind without TLS, a cleartext egress hop, a verify-off HTTP-family egress hop (at least the MLLP, FTPS and email verify-off refusals do not read it) and a weakened database TLS
  hop. If the claim is false, the payload and any credential the connection carries cross in the clear,
  and nothing about the hop looks wrong afterwards.
- **When acceptable:** the hop really is secure, and the engine cannot see why. A TLS-terminating proxy or
  sidecar in front of the connection is the usual case. An isolated, point-to-point segment with its
  own link-layer encryption is the other.
- **Do not use it for a hop that is not secure.** That is `cleartext_accepted`, which WARNs every time. An
  attestation about a plaintext hop on a flat network puts a false statement into the one field that
  exists to be trusted when audited.
- **Compensating controls:** whatever the reason names. Keep it true: when the proxy or the segment
  changes, the attestation has to change with it.
- **It is always reported, though not always logged:** at least the inbound bind gates and the
  raw-TCP/MLLP hop guard log a suppressed enforcing refusal at WARNING with the reason. The OAuth2 and
  SMART token-endpoint seams and the database weakened-TLS line do not put the reason on it, and a
  `DatabaseRef` source writes that same line. The complete record is the two reports. `messagefoundry check` prints a
  `tls-hop-attested` line listing the **whole** attested set, and `GET /security/posture` carries a
  `tls_hop_attested` loosening naming every attesting declaration of each kind above. Each gate and
  both reports read the attestation from the same place, so a hop cannot be crossed on an attestation
  the reports do not name.
- **Where it is NOT reported, and why:** the same two gaps as `cleartext_accepted` above.
  `messagefoundry security show` never loads the connection graph, and the `serve`-time warning fires
  before the graph loads. Both say so in their scope text.
- **What it cannot do:** it does not reach a revocation refusal. That is `tls_revocation_attested`, a
  different claim. It does not permit SMTP `AUTH` over cleartext, which is refused outright.

### `tls_allow_expired = true` on a connection — an expired certificate accepted indefinitely
> **Connection-scoped**, like `cleartext_accepted` above: a parameter on one outbound connection —
> `MLLP`, `Rest`, `Soap`, `FHIR`, `DICOM` C-STORE SCU or `Ftp` (FTPS) — and therefore also a
> `connections.toml` `[settings]` key. `FhirLookup` does not take it, and no inbound does.
> [ADR 0094](adr/0094-granular-expiry-only-tls-relaxation.md).
- **What you lose:** the certificate **validity-period** check on that hop, and nothing else. An expired
  server certificate is accepted **indefinitely** — the relaxation has no end date, and nothing removes
  it when the peer renews.
- **What you keep, and it is most of it:** the chain signature, name constraints, key usage / EKU, basic
  constraints and the hostname match all still apply — it ORs exactly one flag
  (`X509_V_FLAG_NO_CHECK_TIME`). A wrong-host or broken-chain peer is still rejected. This is genuinely
  narrower than `tls_verify = false`, which is the entire point of it: the alternative operators reach
  for otherwise is the blunt switch.
- **When acceptable:** a short bridge while a partner renews a lapsed certificate. It should be
  transitional, and the *only* thing that makes it transitional is you — see the last bullet.
- **Compensating controls:** none that the engine applies. The hop is still encrypted and still
  authenticated to the named host, so the residual risk is a certificate whose issuer no longer stands
  behind it.
- **It is never silent:** a WARN at each construction naming the host; a `tls-allow-expired` line in
  `messagefoundry check` naming every declaring connection and its peer; and a `tls_allow_expired` entry
  in `security_loosenings()`, and so in `GET /security/posture` on a running engine. **Not** the
  serve-time loosening warning — that fires before the graph is loaded, exactly as for
  `cleartext_accepted`, and the construction WARN covers the same ground moments later.
- **What it cannot do — and the one thing you must supply:** it is **advisory only**. No posture gate
  keys on it, `[security].enforcement = enforce` does not touch it, and no `MEFOR_ALLOW_INSECURE_TLS`
  is needed to set it. Reported is not gated. The engine will tell you *which* connections have it set,
  for as long as they have it set; it has no notion of *until when*, so the removal date belongs in your
  own risk register. Where it is NOT reported is the same list as `cleartext_accepted` above —
  `messagefoundry security show` and a graphless `GET /security/posture` say so in `loosenings_scope`.

### `tls_revocation_attested = true` on a connection — revocation checked outside the engine
> **Connection-scoped**, both directions: an `inbound()`/`outbound()` keyword, or a **top-level**
> `connections.toml` key (not under `[settings]`), always paired with a mandatory
> `tls_revocation_attested_reason`.
> [ADR 0173](adr/0173-tls-peer-revocation-checking-and-ocsp-stapling-across-terminating-and-originating-surfaces.md)
> §1.5 item 4.
- **What you lose:** the engine's refusal of a *verifying* TLS hop that checks no certificate
  revocation. On an outbound hop that is the `RevocationHopGuard` refusal (stdlib `ssl` fetches no
  OCSP or CRL). On an mTLS listener it is the `check_inbound_revocation` refusal of a listener with
  `tls_ca_file` and no `tls_crl_file`. With the attestation set, a revoked but unexpired certificate on
  that hop is accepted **unless your PKI or terminator stops it**, because the engine will not.
- **When acceptable:** a revocation-checking PKI or terminator really does cover this hop, and you can
  name it. That name belongs in the reason. On a listener, prefer `tls_crl_file`, which checks
  revocation in the engine and needs no attestation.
- **What it cannot do:** it never reaches a cleartext or verify-off hop, which keep their own
  refusals. It is a claim about one named hop, which is why it crosses an enforcing instance where the
  process-wide `MEFOR_TLS_REVOCATION_ATTESTED` does not (BACKLOG #299).
- **How it is recorded:** a flag without a reason, a blank reason, or a reason without the flag fails
  at load, on both authoring surfaces. Each time the attestation lets a hop through that an enforcing
  instance would otherwise refuse, the engine logs a WARNING naming the hop and your reason, at every
  construction. That record is a log line, not an `audit` table row, for the reason given under
  `cleartext_accepted` above.
- **It is never silent:** the WARNING above at each construction where it suppresses a refusal; a
  `tls-revocation-attested` line in `messagefoundry check` naming every attesting connection and its
  reason; and a `tls_revocation_attested` entry in `security_loosenings()`, and so in
  `GET /security/posture` on a running engine. All three walk inbound, outbound and `FhirLookup`
  connections; inbound names are prefixed `inbound:` and lookups `fhir_lookup:`. **Not** the
  serve-time loosening warning, which fires before the graph is loaded, exactly as for
  `cleartext_accepted`. Where it is NOT reported is the same list as `cleartext_accepted` above:
  `messagefoundry security show` and a graphless `GET /security/posture` say so in `loosenings_scope`.

### A generic-ODBC `DATABASE` hop with TLS unenforced
> **Connection-scoped**, and unlike the flag entries above it is not a flag anyone sets — it is the *absence* of a
> verifying keyword. It applies to a `Database(...)` outbound **or** a `DatabasePoll(...)` inbound with
> `dialect='generic'`. [ADR 0092](adr/0092-posture-keyed-transport-hop-refusal-refuse-the-insecure-phi-hop.md)
> (2026-07-12 amendment).
- **What you lose:** on `dialect='generic'` MessageFoundry cannot introspect an arbitrary ODBC driver's
  TLS posture, so the posture-keyed weakened-TLS refusal does not apply and TLS is delegated entirely to
  the driver's own keyword. With no such keyword — or with one pinned to a no-TLS value — the rows, and
  the credential in the DSN, may cross in plaintext.
- **Why it is a delegation rather than a refusal:** the engine cannot enumerate an arbitrary driver's
  keywords, and a guess-based refusal would break legitimate drivers. The delegation is correct; what
  was wrong, until #333, was that its only control was a log line.
- **When acceptable:** never, on a hop carrying PHI. Set the driver's verifying keyword —
  `SSLmode=verify-full` (psqlODBC), `SSLMODE=VERIFY_IDENTITY` (MySQL), or the equivalent — and treat it
  as a deployment requirement. The `dialect='sqlserver'` default is unaffected and keeps its refusal.
- **How it is detected, precisely:** a TLS-shaped `odbc_params` key (`ssl`/`tls`/`encrypt`) whose
  **value** is not one of the known no-TLS spellings. The value check matters: matching the key alone
  read `SSLmode=disable` as TLS ownership. A passphrase-shaped key such as `sslpassword` is not
  TLS-shaped for this check, and its value is never classified or reported (BACKLOG #1352).
  **Known residual:** an *encrypted-but-unverified* value
  (psqlODBC `require`) is not classified — the payload is not in plaintext, and the per-driver spellings
  for "verified" are not consistent enough to grade without guessing.
- **It is never silent:** a WARN at each construction naming the connection and the offending keyword;
  a `generic-db-tls` line in `messagefoundry check`; and a `generic_odbc_tls_unenforced` entry in
  `security_loosenings()` / `GET /security/posture`. Inbound names are prefixed `inbound:`.
- **What it cannot do:** it is advisory only, on every posture, in both directions. Nothing refuses it.

### `store_principal_over_granted` — the engine's database credential holds more than its runbook allows

> **An OBSERVATION, not a switch.** Nobody sets this; the serve-time preflight reads the store
> principal's *effective* privileges and compares them against the grant
> [`DEPLOY-SERVER-DB.md` §1.1/§1.2](DEPLOY-SERVER-DB.md) prescribes. BACKLOG #1008, ASVS 13.2.2.
- **What you lose:** the store credential can reach data and administrative operations the engine
  never uses. A `sysadmin` / `db_owner` login can read and alter every database on the instance; a
  Postgres `SUPERUSER`, database owner, or member of `pg_read_all_data` / `pg_execute_server_program`
  can do the equivalent. Any code path that reaches the store — an injection, a compromised process,
  a mistaken statement — inherits that reach, so the blast radius of every other store defect widens.
- **What the engine does about it:** under the shipped `[security].enforcement = enforce` it
  **refuses to start** ([ADR 0199](../docs/adr/0199-an-over-granted-store-login-refuses-start-under-enforce-with-an-audited-opt-out.md), owner ruling 2026-09-27). This entry then appears
  only under `enforcement = warn`, or beside `allow_over_granted_store_principal` below, which is the
  audited way to accept it.
- **When acceptable:** during bring-up, while a DBA reduces the grant. Not as a steady state.
- **It is never silent:** a WARN at every start naming each excess grant; a `store_privilege_preflight`
  audit row; a `store_principal_over_granted` entry here and in `GET /security/posture`, whose
  `store_privilege` field carries the full observation.
- **How it refuses:** by default under `enforce`. `[store].require_least_privilege = true`
  ([`CONFIGURATION.md`](CONFIGURATION.md)) makes the refusal outrank the opt-out and extends it to an
  unobservable probe. The refuse/warn split is `[security].enforcement`.
- **`require_managed_identity` does NOT cover this.** It constrains the credential's *kind* — a
  `sysadmin` gMSA satisfies it clean. The two are orthogonal and a site needs both.
- **Before concluding it has misfired**, read [`DEPLOY-SERVER-DB.md` §1.3](DEPLOY-SERVER-DB.md): two
  entries surprise sites that are trying to do the right thing. A SQL Server **user-defined** database
  role is named even when it wraps exactly the three prescribed ones (the probe reads membership, not
  a role's contents), and a PostgreSQL role **attribute** is named when it sits on any role the
  principal may assume rather than on the principal itself (`CREATEROLE via role site_ops`) — reachable
  by `SET ROLE`, so held in practice. Both are real deviations from the prescribed grant, not noise.

### `allow_over_granted_store_principal = true` — start on an over-granted store login

> **A switch.** `[security].allow_over_granted_store_principal`, default `false`.
> [ADR 0199](../docs/adr/0199-an-over-granted-store-login-refuses-start-under-enforce-with-an-audited-opt-out.md), ASVS 13.2.2.
- **What you lose:** the refusal an over-granted store login earns under `enforce`. The engine starts
  with a credential that can reach more than it needs, with every consequence listed under
  `store_principal_over_granted` above.
- **When acceptable:** during bring-up, while a DBA reduces the grant, or on a lab box that logs in
  as a database superuser (the `ha` profile in `docker/compose.yaml` sets it for that reason).
- **It is never silent:** a WARNING line starting `AUDIT:` at every start it lets through,
  `over_grant_accepted: true` on the `store_privilege_preflight` audit row, and an entry here and in
  `GET /security/posture`. The warning and the `store_privilege_warning` alert still fire.
- **What it does not do:** it never lifts the refusal `[store].require_least_privilege = true`
  declares, and it has nothing to lift on an unobservable probe, which only warns.
- **How to turn it off:** remove it, after the grant matches [`DEPLOY-SERVER-DB.md`](DEPLOY-SERVER-DB.md)
  §1.1 or §1.2. `messagefoundry check-privileges` shows the grant and what `serve` would do with it.

### `schema_management` — the engine's runtime login runs its own schema DDL

> **A switch at a non-default value.** `[store].schema_management = "auto"` on a SQL Server or
> PostgreSQL store. BACKLOG #305, ASVS 13.2.2. The server-DB default is `"external"`.
- **What you lose:** the runtime login needs standing DDL rights (`db_ddladmin` on SQL Server,
  `CREATE` on the store's schema on PostgreSQL) that steady-state operation never uses. Any code path
  that reaches the store can then create, alter or drop the engine's own tables, not only read and
  write their rows.
- **What the default does instead:** `serve` runs no schema DDL. A DBA runs
  `messagefoundry store provision-schema` as a separate, DDL-capable principal, before the first start
  and before the first start of any upgrade whose schema moved. Until then `serve` refuses to start and
  names that command ([`DEPLOY-SERVER-DB.md`](DEPLOY-SERVER-DB.md) §2).
- **When acceptable:** a lab or a single-operator install where the DBA and the engine are the same
  person, and the provisioning step buys nothing.
- **It is never silent:** an entry here and in `GET /security/posture` on every server-DB start in
  `auto`. The startup privilege probe also changes what it expects: under `auto` it treats the DDL
  grant as prescribed, under `external` it names it as excess (`store_principal_over_granted`).
- **On SQLite this entry never fires.** A local file has no server principal to split, so SQLite is
  always `auto` by construction.
- **How to turn it off:** remove the setting, or set `[store].schema_management = "external"`, then run
  `provision-schema` and drop the DDL grant from the runtime login.

### `store_principal_privileges_unobserved` — the privilege posture could not be read

> The complement of the entry above, and it is reported **separately** on purpose: an over-grant and an
> un-run probe demand different operator actions, and merging them would let "nobody looked" render as
> a finding about what was seen.
- **What you lose:** nothing is asserted about the store principal, in either direction. The
  least-privilege grant both runbooks prescribe is **unverified** on this instance, so an over-granted
  credential would not be detected here. This is the *absence* of a clean result, not one.
- **How it happens:** the principal is denied the privilege query, the driver errors, or the store
  handle implements no probe.
- **On SQLite this entry never fires.** A local file has no server principal, so the probe reports
  `not_applicable` — a third, distinct status — and reports nothing here. Treating SQLite as
  "unobserved" would put a permanent, unactionable entry on every single-node install, and a
  permanently-true warning is read as noise.
- **It does not refuse by default** (owner choice, ADR 0199): an unobservable probe only warns, even
  under `enforce`.
- **How to refuse:** `[store].require_least_privilege = true` refuses on this condition too.

### `audit_chain_unkeyed` — the store has a key, but its audit chain is keyless

> **An OBSERVATION, not a switch.** Nobody sets this. The store reports it when it opens with a key
> (or an isolated-module MAC) onto an audit chain that has rows but no keying watermark. BACKLOG #1905.
- **What you lose:** tamper evidence against forgery. Every existing audit row is plain SHA-256, so
  anyone who can write `audit_log` can rewrite a row and recompute the chain, and `audit-verify`
  reports it clean. A keyed chain would need the store key to do that.
- **How it happens:** rows were written while no key was in hand, then a key was added. Opening with
  a key keys a store only when its `audit_log` is empty, and never re-keys rows that already exist,
  because that would bless a forged row. The documented install order used to produce this: run
  `provision-admin` with the key only in the service's environment, and the first audit row is
  keyless. `provision-admin` now refuses under the same condition `serve` refuses to start.
- **It is never silent:** a WARNING each time the store opens, naming `messagefoundry rekey-audit`,
  and an `audit_chain_unkeyed` entry in `GET /security/posture`. It is not in the serve-time
  settings warning or `messagefoundry security show`, because neither opens the store.
- **How to clear it:** stop the engine, then run `messagefoundry rekey-audit` with the key
  configured. A running engine keeps the watermark it read at open, so it would go on appending
  keyless rows above the new one and the next verify would report a break. `rekey-audit` verifies the
  existing chain first, refuses a broken one, and keys every row after it. The existing rows keep
  their SHA-256 hashes, but the first keyed row folds in the last keyless hash, so a later edit to
  any earlier row breaks the keyed suffix.
- **On a store with no key at all this entry never fires.** That chain is keyless by the audited
  at-rest opt-out, which `allow_unencrypted_phi` already reports.

---

## Standards mapping (ASVS v5.0 · NIST SP 800-53r5 · HIPAA §164.312)

Assembled, not asserted per switch. **Provenance:** the NIST SP 800-53r5 control IDs/titles and the HIPAA
Security Rule technical-safeguard citations are HIGH-confidence (verified against the primary catalogs —
see *Sources*); the **HIPAA → 800-53r5 crosswalk** is [NIST SP 800-66r2](https://csrc.nist.gov/pubs/sp/800/66/r2/final)
Appendix D. The **OWASP ASVS 5.0 chapters** (V6 Authentication, V7 Session Management, V8 Authorization, V11
Cryptography, V12 Secure Communication, V13 Configuration, V14 Data Protection, V16 Security Logging) are
verified against the [ASVS v5.0.0](https://github.com/OWASP/ASVS/tree/v5.0.0) primary source and match the
project's own ASVS-5.0 L3 drive-to-pass mappings (BACKLOG #242–246); **exact ASVS sub-requirement IDs are
carried from that drive-to-pass, not re-derived here.** The V2 rows (Validation and Business Logic) were
added with BACKLOG #1131 and carry the 2.4.1 / 2.4.2 citations the limiters' own settings make; that
chapter was not part of the verification above.

| `[security]` switch(es) | OWASP ASVS v5.0 | NIST SP 800-53r5 | HIPAA §164.312 |
|---|---|---|---|
| `local_access_only`, `listen_address`, `require_encryption_for_remote` | V12 Secure Communication | **SC-7** Boundary Protection · **SC-8** Transmission Confidentiality and Integrity | §164.312(e)(1) Transmission Security |
| `serve_web_console`, `web_console_public_address` | V13 Configuration · V3 Web Frontend Security | **SC-7** Boundary Protection · **AC-3** Access Enforcement | §164.312(a)(1) Access Control |
| `encrypt_stored_data`, `allow_unencrypted_phi` | V11 Cryptography | **SC-28** Protection of Information at Rest · **SC-13** Cryptographic Protection | §164.312(a)(2)(iv) Encryption and Decryption |
| `allow_unencrypted_phi_under_strict_enforcement` (strict-enforcement ack) | V11 Cryptography | **SC-28** Protection of Information at Rest · **SC-13** Cryptographic Protection | §164.312(a)(2)(iv) Encryption and Decryption |
| `require_sign_in` | V6 Authentication | **IA-2** Identification and Authentication (Organizational Users) | §164.312(d) Person or Entity Authentication |
| `require_mfa` | V6 Authentication (multi-factor) | **IA-2(1)/(2)** MFA to Privileged / Non-Privileged Accounts | §164.312(d) Person or Entity Authentication |
| `allow_single_factor_admin_when_exposed` (production ack) | V6 Authentication (multi-factor) | **IA-2(1)/(2)** MFA to Privileged / Non-Privileged Accounts | §164.312(d) Person or Entity Authentication |
| `sign_out_after_idle_minutes`, `max_session_hours` | V7 Session Management | **AC-12** Session Termination | §164.312(a)(2)(iii) Automatic Logoff |
| `block_unlisted_outbound` | V14 Data Protection | **AC-4** Information Flow Enforcement · **SC-7(5)** Deny by Default — Allow by Exception | §164.312(e)(1) Transmission Security |
| `delete_message_bodies_after_days`, `allow_keeping_phi_indefinitely` | V14 Data Protection | **SI-12** Information Management and Retention | §164.316(b)(2) documentation retention · data-minimization (§164.502(b)) |
| `audit_all_authorization_decisions` | V16 Security Logging and Error Handling | **AU-2** Event Logging · **AU-3** Content of Audit Records | §164.312(b) Audit Controls |
| `production_instance` (production tier) | V13 Configuration (risk-based) | **RA-2** Security Categorization | §164.308(a)(1) Risk Analysis / Management |
| `enforcement` (refuse/warn dial) | V13 Configuration (secure defaults) | **CM-6** Configuration Settings · **CM-7** Least Functionality (secure-by-default) | §164.308(a)(1) Risk Analysis / Management |
| `[store].aad_bind` (at-rest cell binding) | V11 Cryptography | **SC-28(1)** Cryptographic Protection · **SI-7** Software, Firmware, and Information Integrity | §164.312(c)(1) Integrity · §164.312(a)(2)(iv) Encryption and Decryption |
| `[store].allow_unmarked_ciphertext` (unmarked-value refusal) | V11 Cryptography | **SC-28(1)** Cryptographic Protection · **SI-7** Software, Firmware, and Information Integrity | §164.312(c)(1) Integrity · §164.312(c)(2) Mechanism to Authenticate ePHI |
| `[auth].ad_session_recheck_seconds` (directory revocation propagation) | V7 Session Management · V6 Authentication | **AC-2(3)** Disable Accounts · **AC-12** Session Termination | §164.312(a)(2)(i) Unique User Identification · §164.308(a)(3)(ii)(C) Termination Procedures |
| `[auth].ad_allow_insecure_ldap` (plain `ldap://` AD bind) | V12 Secure Communication | **SC-8** Transmission Confidentiality and Integrity · **SC-8(1)** Cryptographic Protection | §164.312(e)(1) Transmission Security · §164.312(d) Person or Entity Authentication |
| `[auth].admin_new_ip_step_up` (mid-session new-address step-up) | V8 Authorization (adaptive, 8.2.4) · V6 Authentication | **AC-2(12)** Account Monitoring for Atypical Usage · **IA-11** Re-authentication | §164.312(d) Person or Entity Authentication · §164.308(a)(5)(ii)(C) Log-in Monitoring |
| `[auth].login_rate_limit_*`, `[auth].lockout_minutes`, `[auth].lockout_threshold`, `[auth].lockout_max_minutes` (sign-in limits and account lockout) | V6 Authentication (6.1.1) | **AC-7** Unsuccessful Logon Attempts | §164.312(d) Person or Entity Authentication · §164.308(a)(5)(ii)(C) Log-in Monitoring |
| `[auth].phi_read_rate_limit_*`, `[auth].admin_write_*`, `[auth].mfa_verify_min_elapsed_seconds`, `[auth].oidc_callback_min_elapsed_seconds` (PHI-read and admin-write pacing, second-step time floors) | V2 Validation and Business Logic (anti-automation, 2.4.1 / 2.4.2) | **SC-5** Denial-of-Service Protection | §164.312(a)(1) Access Control |
| `[auth].max_sessions_per_user` (concurrent-session cap) | V7 Session Management (7.1.2) | **AC-10** Concurrent Session Control | §164.312(a)(1) Access Control |
| `[auth].oidc_flow_cache_max` (pending federated sign-in bound) | V2 Validation and Business Logic (anti-automation) | **SC-5** Denial-of-Service Protection | §164.312(d) Person or Entity Authentication |
| `[api].trusted_proxies` (trust-every-peer forwarded header) | V13 Configuration · V16 Security Logging and Error Handling | **AU-3** Content of Audit Records · **SC-7** Boundary Protection | §164.312(b) Audit Controls |
| `[api].plaintext_upstream_hop_acknowledged` (plaintext proxy-to-engine hop, site-secured) | V12 Secure Communication (12.3.3) | **SC-8** Transmission Confidentiality and Integrity · **SC-7** Boundary Protection | §164.312(e)(1) Transmission Security |
| `cleartext_accepted` (per-connection declared cleartext hop) | V12 Secure Communication | **SC-8** Transmission Confidentiality and Integrity · **SC-8(1)** Cryptographic Protection | §164.312(e)(1) Transmission Security · §164.312(e)(2)(ii) Encryption |
| `tls_allow_expired` (per-connection expiry-only relaxation) | V12 Secure Communication | **SC-8(1)** Cryptographic Protection · **SC-12** Cryptographic Key Establishment and Management | §164.312(e)(1) Transmission Security · §164.312(e)(2)(ii) Encryption |
| `tls_hop_attested` (per-connection hop attested secure) | V12 Secure Communication | **SC-8** Transmission Confidentiality and Integrity · **SC-8(1)** Cryptographic Protection | §164.312(e)(1) Transmission Security · §164.312(e)(2)(ii) Encryption |
| generic-ODBC `DATABASE` TLS unenforced (per-connection, driver-owned) | V12 Secure Communication | **SC-8** Transmission Confidentiality and Integrity · **SC-8(1)** Cryptographic Protection | §164.312(e)(1) Transmission Security · §164.312(e)(2)(ii) Encryption |
| `store_principal_over_granted` / `store_principal_privileges_unobserved` (observed store-principal privilege) | V13 Configuration (backend component accounts, 13.2.2) | **AC-6(5)** Privileged Accounts · **AC-6(9)** Log Use of Privileged Functions · **CM-7(5)** Authorized Software / least functionality | §164.312(a)(1) Access Control · §164.308(a)(4) Information Access Management |
| `audit_chain_unkeyed` (observed keyless audit chain on a keyed store) | V16 Security Logging and Error Handling | **AU-9** Protection of Audit Information · **AU-9(3)** Cryptographic Protection | §164.312(b) Audit Controls · §164.312(c)(1) Integrity |

> **There is no longer a synthetic-vs-PHI split to crosswalk.** It was risk-based tailoring keyed on
> `handles_real_patient_data` — an instance carrying no ePHI being out of scope for the ePHI-specific
> safeguards, which 800-53r5 supports via RA-2 and AC-6. The tailoring was sound in principle; what did
> not hold was the control that made it visible. [ADR 0186](adr/0186-retire-the-synthetic-data-declaration-every-instance-carries-patient-data.md) removed the declaration, so every instance
> is categorized as carrying ePHI and each safeguard is relaxed individually or not at all.

### Sources

- [OWASP Application Security Verification Standard v5.0.0](https://github.com/OWASP/ASVS/tree/v5.0.0) — chapter structure.
- [NIST SP 800-53 Rev. 5, Security and Privacy Controls](https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final) — control catalog (SC-7, SC-8, SC-28, SC-13, IA-2, AC-12, AC-4, AU-2, AU-3, SI-12, RA-2, AC-6, AC-7, AC-10, SC-5).
- [NIST SP 800-63B-4, Digital Identity Guidelines: Authentication and Authenticator Management](https://pages.nist.gov/800-63-4/sp800-63b.html) — section 3.2.2 (section 5.2.2 in the superseded rev. 3), the ceiling of 100 consecutive failed attempts that `[auth].lockout_threshold` is checked against.
- [NIST SP 800-66 Rev. 2, Implementing the HIPAA Security Rule](https://csrc.nist.gov/pubs/sp/800/66/r2/final) — Appendix D HIPAA → 800-53r5 crosswalk.
- [45 CFR §164.312 — Technical safeguards](https://www.hhs.gov/hipaa/for-professionals/security/index.html) (HHS).
- [CISA — Secure by Design](https://www.cisa.gov/securebydesign) — secure defaults + the loosening-guide model.
