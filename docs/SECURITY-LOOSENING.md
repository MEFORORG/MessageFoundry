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
| Alert transport | `allow_unverified_alert_smtp_tls` | `false` |
| | `sign_out_after_idle_minutes` | `30` |
| | `max_session_hours` | `12` |
| Data handling | `block_unlisted_outbound` | `true` |
| | `delete_message_bodies_after_days` | `30` (`0` = keep forever) |
| | `allow_keeping_phi_indefinitely` | `false` |
| | `audit_all_authorization_decisions` | `true` (see note) |
| Enforcement dial | `enforcement` | `enforce` (refuse; `warn` = loud audited loosening) |
| Posture lever | `handles_real_patient_data` | *derived from environment* |
| | `production_instance` | *derived from environment* |
| Outside `[security]` | `[store].aad_bind` | `true` (at-rest values bound to their cell) |
| | `[auth].ad_session_recheck_seconds` | `300` s (*conditional* — a loosening only once `ad_enabled`) |
| Per-connection | `cleartext_accepted` | `false` on every outbound / `FhirLookup` (*connection-scoped* — see below) |
| | `tls_allow_expired` | `false` on all six outbound connectors that take it (*connection-scoped*) |
| | generic-ODBC `DATABASE` TLS | a verifying `odbc_params` keyword (*connection-scoped*; inbound **and** outbound) |

**Five of these do not live in `[security]`.** `[store].aad_bind` and `[auth].ad_session_recheck_seconds`
sit in their own sections for cohesion, and the last three are per-**connection** facts, not service
settings at all. They are listed and reported here anyway, because the rule is *one shipped
posture, loosen only* — a deviation the registry cannot see is a second posture by the back door. The
first two are named by `security_loosenings()` from the loaded `[store]`/`[auth]` sections; the last
three are resolved from the loaded connection graph and passed in by name (see their entries below for
exactly which surfaces see them, and which cannot).

> **Scope, stated plainly.** The registry covers *every* `[security]` switch (a completeness floor in
> `tests/test_security_posture_defaults.py` fails on an unreported, unexempted one), the connection
> factories' TLS-shaped parameters (a second floor in the same file censuses the factory signatures,
> because a per-connection deviation is outside `model_fields`' reach by construction) and the
> enumerated deviations above. It is **not yet** an exhaustive register of every security-relevant
> switch in every section: `[store].encrypt` / `trust_server_certificate` and
> `[auth].enabled` / `require_mfa` / `ad_tls_verify` / `ad_allow_insecure_ldap` /
> `oidc_require_mfa_claim` are gated by their own serve-time refusals and are **not** reported here.
> That gap is enumerated in the floor test's exemption set, so it is a written decision rather than an
> accident, and a *new* switch in either section cannot join it silently. Closing it is owed work.

`enforcement` (ADR 0148 GIVEN 2) is the serve-gate **refuse/warn dial** + the [ADR 0092](adr/0092-posture-keyed-transport-hop-refusal-refuse-the-insecure-phi-hop.md)
escape-clamp key, defaulting to `enforce` (byte-identical to the former production-tier refusal). It is
**decoupled** from `production_instance` — a PHI *staging* box is now strict by default too. `enforcement`
gates every "still refused" clause below; `enforcement = warn` downgrades them all to loud, audited warnings.

`handles_real_patient_data` / `production_instance` default to the value **derived from the active
environment name** (ADR 0148 GIVEN 1: **`dev` → PHI/non-prod**, `staging` → PHI/non-prod, `prod` → PHI/prod);
a custom-named environment must declare them or `serve` fails closed. `handles_real_patient_data` is the
*master data-class lever* — the PHI-only gates below key on it — and now defaults to PHI on every built-in
env (a genuinely-synthetic box must set it `false` explicitly; see its deviation below).

`audit_all_authorization_decisions` **now defaults `true`, and turning it OFF is a loosening**
([ADR 0168](adr/0168-default-the-authorization-grant-audit-on-the-console-cannot-flood-it.md),
BACKLOG #1277). It is listed among the deviations below like any other switch.

**This reverses what this note used to say**, and the retraction is kept rather than deleted because
the reasoning is the useful part. The old text called `false` a *secure-and-usable* default on the
ground that full tracing *"would flood the hash-chained audit log (console polling + the `/ws/stats`
feed)"* — ADR 0118 §5, owner-confirmed. **That flood was measured afterwards and is not connected to
this switch:** the browser console never traverses the JSON gate that records grants (it is
server-rendered in-process behind its own gate, which records denials only), and WebSocket
authorization fires once per *connection* rather than per message. What the ON default does cost is
one grant row per authenticated request on the `require()`-gated JSON API — bounded by client polling
cadence. ePHI access is audited unconditionally at **either** setting; what an operator gives up by
turning this off is the **read** history.

---

## Deliberate deviations

### `local_access_only = false` — expose the operator API/console off this machine
- **What you lose:** the API + web console become reachable from the network, not just this host.
- **When acceptable:** a real remote-operations need, on a trusted/segmented network, with TLS.
- **Compensating controls:** keep `require_encryption_for_remote = true` (TLS required); front with a
  revocation-checking reverse proxy (`[api].tls_terminated_upstream` + `trusted_proxies`); a managed admin
  host / mTLS (OFF-LOOPBACK-DEPLOYMENT.md).
- **Still refused:** an off-box bind without TLS (unless `require_encryption_for_remote = false`, below).

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

### `require_encryption_for_remote = false` — accept cleartext for off-machine access
- **What you lose:** bearer tokens and PHI cross the network **in cleartext**. This is the config-file twin
  of the `--allow-insecure-bind` dev escape.
- **When acceptable:** a lab/loopback-adjacent trusted, firewalled segment; never for real remote PHI.
- **Compensating controls:** network isolation; prefer in-process TLS (`[api].tls_cert_file`) or a
  TLS-terminating proxy instead.
- **Still refused:** a **production-PHI** cleartext bind — the [ADR 0092](adr/0092-posture-keyed-transport-hop-refusal-refuse-the-insecure-phi-hop.md)
  clamp cannot be relaxed by this switch or by `--allow-insecure-bind`.

### `serve_web_console = false` — do **not** mount the browser ops console at `/ui` (surface-reducing opt-out)
> **Not a loosening — the inverse.** The console is **on by default** ([ADR 0143](adr/0143-web-console-on-by-default-disableable-with-loopback-secure-context-browser-hardening.md))
> because it is the operator UI, effectively core. Setting `serve_web_console = false` **removes** the `/ui`
> HTML/session-cookie attack surface, leaving a smaller JSON-only deployment — a surface-*reducing* opt-out
> (a hardening), listed here only for completeness. It does **not** appear in `security_loosenings()`.
- **When to disable:** a headless JSON-only deployment, or a hardened bastion where the browser console is
  not wanted.
- **Off-box note:** the default-on applies to **local loopback** binds only. On an **exposed** instance
  (a non-loopback host, a declared TLS-terminating proxy, or a set `web_console_public_address`) a
  *default-on* console **auto-degrades to JSON-only** — serving it off-box is a deliberate opt-in
  (`serve_web_console = true` with TLS + `web_console_public_address`). The `/ui` surface stays *stricter*
  than the JSON API: an explicitly-enabled console off-loopback requires `exposure_protected` (TLS or a
  declared proxy) and `web_console_public_address`, and is refused even under `--allow-insecure-bind`.

### `encrypt_stored_data = false` — do not encrypt PHI at rest
- **What you lose:** message bodies, the summary/metadata (MRN + patient name), and error columns are stored
  **unencrypted** at rest (only volume encryption would protect them).
- **When acceptable:** a synthetic/CI instance (which carries no ePHI) — where it is a no-op anyway.
- **Compensating controls:** OS/volume encryption; restricted DB file permissions.
- **Still refused:** a **PHI** instance keyless — unless you also set `allow_unencrypted_phi = true` (the
  explicit, audited escape).

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
  factor). AD/Kerberos MFA is delegated to the directory and is unaffected.
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
- **Still refused:** a **PHI** instance with an unbounded PHI-body window refuses under **strict enforcement**
  (`enforcement = enforce`, the default) unless `allow_keeping_phi_indefinitely = true` (which downgrades the
  refusal to a loud audited warning); at `enforcement = warn` a PHI instance auto-bounds each unset window to
  30 days.

### `audit_all_authorization_decisions = false` — record only the sensitive authorization grants
- **What you lose:** the **read** history. Only the state-changing / configuration / user-management
  surface writes an `auth.grant` row, so every authenticated read is authorized and **not recorded** —
  and it cannot be reconstructed afterwards, because the rows were never written. The question an audit
  trail exists to answer, *what did this account actually reach*, stops having an answer.
- **What you do NOT lose:** ePHI access. That is audited unconditionally at either setting (the
  tamper-evident chain and the message-event compliance floor), and PHI-view grants are excluded from
  this switch at **both** settings so the two paths do not write double rows.
- **When acceptable:** a measured volume problem on a specific deployment. **Note the remedy that is
  not this switch:** a rate or sampling bound on read grants keeps the trail; turning the trail off
  does not.
- **Compensating controls:** none that restore the lost rows. `[retention].audit_days` is reserved and
  not enforced, so audit volume is a storage question rather than a retention one.
- **Direction of travel:** this default was `false` until
  [ADR 0168](adr/0168-default-the-authorization-grant-audit-on-the-console-cannot-flood-it.md)
  (BACKLOG #1277) measured the flood risk it rested on and found it unconnected to the switch.

### `allow_single_factor_admin_when_exposed = true` — lift the strict-enforcement single-factor-admin refusal
- **What you lose:** on a **PHI** instance under **strict enforcement** (`enforcement = enforce`, the default)
  whose admin surface is exposed (off-loopback bind or a declared reverse proxy) with `require_mfa` off,
  MessageFoundry normally **refuses to start** — the Administrator role would authenticate with a single
  factor over the network. This ack **downgrades that refusal to a loud, audited warning** (the same
  warn-and-start `enforcement = warn` takes, but scoped to this one control), so the instance boots
  single-factor while staying at `enforce`.
- **Scope correction ([BACKLOG #326](archive/backlog/BACKLOG-CLOSED.md#326-mfa-at-exposure-refusal-reads-serve_ui-after-it-is-flipped-off)):** "a declared reverse proxy" above means exactly
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
  outside MessageFoundry** — an authenticating reverse proxy / mTLS admin gateway, or AD/Kerberos MFA
  delegated to the directory (this flag gates only local Administrator accounts).
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
  where that clamp degrades to the *unclamped* escape and would provide no refusal at all. So this cell
  gets an explicit `[security]` acknowledgment instead — the first verify-off hop governed that way.
- **Still refused:** nothing here relaxes the connectors. This switch reaches the `[alerts]` cell only.

### `enforcement = warn` — warn instead of refuse on the PHI serve-gate floor
- **What you lose:** the serve-gate **refuse/warn dial** flips from *refuse* to *warn-and-continue*, and the
  [ADR 0092](adr/0092-posture-keyed-transport-hop-refusal-refuse-the-insecure-phi-hop.md) blunt escapes
  (`--allow-insecure-bind` / `MEFOR_ALLOW_INSECURE_TLS`) are **honoured** again. This reproduces the
  historical **non-production** PHI behaviour on a box that is otherwise strict-by-default: the cleartext
  off-box bind, open-egress, and single-factor-admin-at-exposure refusals downgrade to loud audited warnings,
  and an unset PHI retention window auto-bounds to 30 days rather than refusing. Named once by
  `security_loosenings()` and in `GET /security/posture`.
- **When acceptable:** a PHI **staging / pre-prod** box that must mirror production's *config* (so the
  encryption / egress / retention paths are exercised, not first met in production) but is deliberately run at
  warn severity during bring-up; or a custom PHI-loopback env. A stock production instance never needs it (it
  is `enforce`-equivalent already).
- **Compensating controls:** return to `enforce` before carrying real patient traffic; the warnings + startup
  **AUDIT** line + posture view keep the deviation visible.
- **Still refused (even at `warn`):** the **no-auth-to-the-network** hard refuse (`require_sign_in = false` on
  an exposed instance — a non-loopback bind, or a loopback bind behind a declared TLS terminator) is
  unconditional at **any** enforcement level — `enforcement = warn` does **not** open it — and the unconditional ePHI audit floor is untouched. `enforcement` is **binary** (no `off`): silencing
  a PHI cleartext hop *entirely* is only reachable by declaring the box synthetic
  (`handles_real_patient_data = false`), never by the dial ([ADR 0148](adr/0148-phi-default-posture-and-an-explicit-security-enforcement-level.md)).

### `handles_real_patient_data = false` — declare a genuinely-synthetic (no-ePHI) instance
- **What you lose (nothing — it is an honest scope declaration):** the instance asserts it carries **no real
  patient data**, so the ePHI-specific gates (at-rest-encryption requirement, deny-by-default egress, bounded
  PHI retention, the PHI transport-hop refusals) relax to their synthetic posture — a no-op on data that is
  not PHI. Since [ADR 0148](adr/0148-phi-default-posture-and-an-explicit-security-enforcement-level.md) GIVEN 1
  the built-in `dev` / `staging` / `prod` envs all derive **PHI**, so a genuinely-throwaway CI / dev box must
  set this **explicitly** — it is no longer the `dev` default.
- **When acceptable:** a CI runner, a local dev box, or a demo that only ever processes synthetic / sample
  HL7. **Never** on an instance that touches real patient data — a false declaration silently disables the
  ePHI safeguards.
- **Compensating controls:** it is a **loud, audited opt-out** — named by `security_loosenings()`, surfaced in
  `GET /security/posture`, and warned at `serve`. Keep it out of any config a PHI instance could inherit.
- **Still refused:** `[store].require_encryption = true` still forces a key even on synthetic; and this is a
  **data-class** declaration, **orthogonal to `enforcement`** — it does not lower the AI data-scope ceiling or
  re-enable DEBUG-with-PHI logging (both keyed on the retained `production` tier fact, not on `data_class`).

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
  statement into the one field that exists to be trustworthy when audited.
  **Note (accurate as of 2026-07-28):** `tls_hop_attested` has **no authoring surface on a connection**
  today — no transport factory takes it and it is not a `connections.toml` key, so an inbound/outbound
  cannot set it (the `[logging].forward_hop_attested` sibling *is* settable). `cleartext_accepted` is
  therefore the only per-connection declaration an operator can currently write. Giving attestation an
  authoring surface would add a **silent-ALLOW** loosening and needs its own registry entry here first;
  it is owed, not shipped.
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

### A generic-ODBC `DATABASE` hop with TLS unenforced
> **Connection-scoped**, and unlike the two above it is not a flag anyone sets — it is the *absence* of a
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
  read `SSLmode=disable` as TLS ownership. **Known residual:** an *encrypted-but-unverified* value
  (psqlODBC `require`) is not classified — the payload is not in plaintext, and the per-driver spellings
  for "verified" are not consistent enough to grade without guessing.
- **It is never silent:** a WARN at each construction naming the connection and the offending keyword;
  a `generic-db-tls` line in `messagefoundry check`; and a `generic_odbc_tls_unenforced` entry in
  `security_loosenings()` / `GET /security/posture`. Inbound names are prefixed `inbound:`.
- **What it cannot do:** it is advisory only, on every posture, in both directions. Nothing refuses it.

---

## Standards mapping (ASVS v5.0 · NIST SP 800-53r5 · HIPAA §164.312)

Assembled, not asserted per switch. **Provenance:** the NIST SP 800-53r5 control IDs/titles and the HIPAA
Security Rule technical-safeguard citations are HIGH-confidence (verified against the primary catalogs —
see *Sources*); the **HIPAA → 800-53r5 crosswalk** is [NIST SP 800-66r2](https://csrc.nist.gov/pubs/sp/800/66/r2/final)
Appendix D. The **OWASP ASVS 5.0 chapters** (V6 Authentication, V7 Session Management, V8 Authorization, V11
Cryptography, V12 Secure Communication, V13 Configuration, V14 Data Protection, V16 Security Logging) are
verified against the [ASVS v5.0.0](https://github.com/OWASP/ASVS/tree/v5.0.0) primary source and match the
project's own ASVS-5.0 L3 drive-to-pass mappings (BACKLOG #242–246); **exact ASVS sub-requirement IDs are
carried from that drive-to-pass, not re-derived here.**

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
| `handles_real_patient_data`, `production_instance` (posture lever) | V13 Configuration (risk-based) | **RA-2** Security Categorization · **AC-6** Least Privilege (risk-based tailoring) | §164.308(a)(1) Risk Analysis / Management |
| `enforcement` (refuse/warn dial) | V13 Configuration (secure defaults) | **CM-6** Configuration Settings · **CM-7** Least Functionality (secure-by-default) | §164.308(a)(1) Risk Analysis / Management |
| `[store].aad_bind` (at-rest cell binding) | V11 Cryptography | **SC-28(1)** Cryptographic Protection · **SI-7** Software, Firmware, and Information Integrity | §164.312(c)(1) Integrity · §164.312(a)(2)(iv) Encryption and Decryption |
| `[auth].ad_session_recheck_seconds` (directory revocation propagation) | V7 Session Management · V6 Authentication | **AC-2(3)** Disable Accounts · **AC-12** Session Termination | §164.312(a)(2)(i) Unique User Identification · §164.308(a)(3)(ii)(C) Termination Procedures |
| `cleartext_accepted` (per-connection declared cleartext hop) | V12 Secure Communication | **SC-8** Transmission Confidentiality and Integrity · **SC-8(1)** Cryptographic Protection | §164.312(e)(1) Transmission Security · §164.312(e)(2)(ii) Encryption |
| `tls_allow_expired` (per-connection expiry-only relaxation) | V12 Secure Communication | **SC-8(1)** Cryptographic Protection · **SC-12** Cryptographic Key Establishment and Management | §164.312(e)(1) Transmission Security · §164.312(e)(2)(ii) Encryption |
| generic-ODBC `DATABASE` TLS unenforced (per-connection, driver-owned) | V12 Secure Communication | **SC-8** Transmission Confidentiality and Integrity · **SC-8(1)** Cryptographic Protection | §164.312(e)(1) Transmission Security · §164.312(e)(2)(ii) Encryption |

> The synthetic-vs-PHI relaxation (a synthetic instance keeps the PHI-only gates relaxed) is **risk-based
> tailoring** keyed on `handles_real_patient_data`: an instance carrying no ePHI is out of scope for the
> ePHI-specific safeguards, which 800-53r5 supports via security categorization (RA-2) and the least-
> privilege / need-to-apply principle (AC-6). The posture view **states** the relaxation so it is never
> silent (ADR 0118 AC-6).

### Sources

- [OWASP Application Security Verification Standard v5.0.0](https://github.com/OWASP/ASVS/tree/v5.0.0) — chapter structure.
- [NIST SP 800-53 Rev. 5, Security and Privacy Controls](https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final) — control catalog (SC-7, SC-8, SC-28, SC-13, IA-2, AC-12, AC-4, AU-2, AU-3, SI-12, RA-2, AC-6).
- [NIST SP 800-66 Rev. 2, Implementing the HIPAA Security Rule](https://csrc.nist.gov/pubs/sp/800/66/r2/final) — Appendix D HIPAA → 800-53r5 crosswalk.
- [45 CFR §164.312 — Technical safeguards](https://www.hhs.gov/hipaa/for-professionals/security/index.html) (HHS).
- [CISA — Secure by Design](https://www.cisa.gov/securebydesign) — secure defaults + the loosening-guide model.
