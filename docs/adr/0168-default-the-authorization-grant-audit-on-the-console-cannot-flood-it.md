# ADR 0168: Default the authorization-grant audit ON -- the console cannot flood it

- **Status:** Accepted (2026-08-17)
- **Supersedes the default only:** [ADR 0118](0118-secure-by-default-security-configuration-section.md)
  section 5's owner-confirmed `audit_all_authorization_decisions = false`. Everything else in ADR 0118
  stands, including the relocation itself and the refusal of the old `[diagnostics]` TOML spelling.
- **Item:** BACKLOG #1277.

## Context

`[security].audit_all_authorization_decisions` (internal field `[diagnostics].audit_all_authz`) turns
on an `auth.grant` audit row for **every** satisfied authorization decision. It shipped `false`, so
only a fixed set of state-changing, configuration and user-management permissions on a non-GET request
wrote a row: **every authenticated read was authorized and not recorded.**

ADR 0118 section 5 records that default as an owner-confirmed judgement, and the code carried its
reason in two comments -- forcing it on *"risks flooding the audit log"*, the named flooders being
*"console polling + the `/ws/stats` feed"*.

**That reason was never measured when it was written.** BACKLOG #1197, the ASVS 16.3.2 research item,
says so in as many words: flipping the switch *"while the cost the owner confirmed it against is still
unmeasured"* would not be an honest pass, and **the measurement has to come first**. This ADR is the
other half of that sentence -- the measurement was taken, and it does not support the default.

## The measurement

Taken at `origin/main` `3a7a2cd1f`, and re-taken independently in this lane before the change. Method
beside each number, because a count without its scope is not a result.

| Question | Answer | How |
|---|---|---|
| Grant-recording call sites, whole tree | **exactly 2** | `grep -rn "_grant_audit_permission("` over `--include=*.py`, excluding `tests/`: `api/security.py:249` (`require`) and `:773` (`authorize_ws`), plus the definition at `:124` |
| Grant calls in `messagefoundry_webconsole/` | **zero** | same sweep over that package. **Positive control in the same run:** `audit_permission_denied` returns `_auth.py:258`, so the sweep can see the console's auth code |
| Does the console traverse `require()` at all? | **no** | it imports `client_ip`, `get_auth` and `enforce_phi_read_pacing` from `api.security` and never `require`. The three `require(` matches in that package are all **comments** |
| `authorize_ws` frequency | **once per CONNECTION** | `api/security.py:787` returns the identity after one grant; it is not re-entered per message |
| Rows written per request | **at most 1** | `_grant_audit_permission` returns a single permission even on a multi-permission route (`api/security.py:124-144`) |

**So the named flooder is not connected to the switch.** The browser console is server-rendered
in-process behind its own cookie-world gate (`require_ui`), which records **denials only**; its roughly
15-second `/ui/nav-status` poller cannot write an authorization-grant row at any setting. And the
`/ws/stats` feed authorizes once per connect, so it cannot flood at either setting either -- that is a
property of the code, not of the default.

## What does change, because "the console cannot flood" is not "nothing changes"

The JSON API is a different surface, and it is the one that pays. Measured here by an AST walk over
route-decorated functions whose **signature defaults** call `require(`:

    messagefoundry/api/app.py           GET  22 of 36 gated      POST 2 of 27
    messagefoundry/api/auth_routes.py   GET  13 of 14 gated      POST 4 of 12
    total require()-gated GET routes    35

Each of those goes from zero grant rows to **one row per authenticated request**, for the harness,
`apiclient`, the IDE and operator scripts -- and the harness does poll `/stats`
([`harness/__main__.py`](../../harness/__main__.py)). WebSocket authorization is once per connect.
**Net volume is bounded by JSON-API client polling cadence, not by console page views.**

**The 35 is this lane's own number and it does not match the 33 in BACKLOG #1277.** Both are stated
rather than reconciled: the item does not record its instrument, so the two counts are not comparable
and picking one would manufacture agreement. The decision does not turn on the difference -- neither
number is a flood, and both are the same surface.

**If that volume ever proves genuinely too much, the answer is a rate or sampling bound on read
grants, not an off switch on the whole trail.** Recorded here so the next reader does not re-derive
the off switch as the remedy.

## Decision

**`[security].audit_all_authorization_decisions` and its internal `[diagnostics].audit_all_authz` both
default `true`.**

Three consequences that are part of the decision rather than side effects:

1. **Turning it OFF is now a loosening**, and `security_loosenings()` reports it like any other
   deviation. It was exempt from the completeness floor in
   `tests/test_security_posture_defaults.py` on the ground that turning it *on* was the hardening
   move; with the default flipped that ground is gone, so the exemption is removed and the floor now
   covers the switch. The registry entry names what an operator gives up: the **read** history.
2. **PHI-view grants stay excluded at both settings.** The PHI-access audit path already records
   those, and double rows would make the chain harder to read without adding a fact.
3. **`create_app(audit_all_authz=False)` is unchanged**, and that is deliberate: every keyword on that
   factory (`serve_ui`, `allow_no_auth`, `expose_docs`, `oidc_enabled`) is the embedding default, not
   the product default, and the serve path passes the resolved setting. Changing it would have
   re-pointed 212 call sites, none of which is the engine.

## Why a deploying site is better off

An audit trail that records only the decisions somebody already judged sensitive cannot answer the
question a trail exists to answer -- **what did this account actually reach.** A read history cannot be
reconstructed after the fact, because the rows were never written. Under CLAUDE.md section 0 there are
**zero deployments**, so nothing is missing a trail today and no upgrade breaks anyone; the point is
that the first deployment should not have to find the switch.

**This is not a HIPAA requirement and is not claimed as one.** PHI access is audited unconditionally
either way (the tamper-evident chain and the message-event compliance floor). This is defence in
depth, and it is what ASVS 16.3.2 asks for at L3.

## Consequences

- `docs/SECURITY-LOOSENING.md` moves the switch out of its "not a loosening" note and into the table.
- `docs/CONFIGURATION.md`, `docs/SECURITY.md` and `docs/PHI.md` state the new default; PHI.md's
  volume note stands, since the multiplied stream is now the shipped one.
- [ADR 0014](0014-alerting-rules-engine.md) and [ADR 0118](0118-secure-by-default-security-configuration-section.md)
  carry a pointer here rather than being rewritten -- a superseded decision is more useful with its
  original reasoning intact.
- **BACKLOG #1197 is not closed by this.** That item asks what an honest ASVS 16.3.2 pass requires;
  this ADR supplies the measurement it named as the precondition, and the scoring question is
  separate and belongs to whoever holds that item.
