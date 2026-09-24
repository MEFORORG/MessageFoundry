# 0194 — Refuse to start a keyless audit chain at the store-open seam

- **Status:** Accepted (2026-09-24) -- built with the change.
- **Date:** 2026-09-24
- **Related:** BACKLOG #1916 (the defect), #1905 (the CLI gate this generalises), #190 (the keyed
  chain and its watermark), [ADR 0193](0193-audit-chain-key-ranges-survive-a-store-key-rotation.md)
  (key ranges), [ADR 0140](0140-two-acknowledged-production-phi-no-loosen-carve-outs-single-factor-admin-at-exposure-keyless-phi-in-production.md) (the
  second acknowledgment under strict enforcement)

---

## Context

A store with no key writes a keyless audit chain: every row is plain SHA-256, which anyone who can
write `audit_log` can forge. A later keyed open keys the chain only if `audit_log` is EMPTY; keying
rows that already exist would bless a forged row, so the store never does it silently. So **a chain
that starts keyless stays keyless** until an operator runs `rekey-audit`.

BACKLOG #1905 closed that for `serve` and `provision-admin` with a CLI gate, `_keyless_store_gate`,
that each of those two commands calls before it opens anything. Every other command that opens the
store skipped it. Reproduced here with synthetic data at engine `9f51a2ada`, on a SQLite store whose
schema existed and whose `audit_log` was empty (the state a fresh server database is in):

- `backup` wrote a keyless `dr_backup` row as row 1. It did so even when it then refused to write
  an unencrypted archive and exited 1, because a failed backup is audited too.
- `admin-unlock` wrote a keyless `auth.admin_unlocked` row as row 1 and exited 0.

A second defect sat beside it. `provision-admin` writes the account before its audit row. With a
keyed store (the service created it) and a shell holding no key but a leftover audited opt-out, the
CLI gate passed on the opt-out, the account row was written, and the audit append then refused
(the keyed chain will not take a keyless row). The result was an administrator with no audit row
and a traceback.

Zero deployments (CLAUDE.md section 0): this is what a first deployment would have inherited.

## Decision

**Move the decision into `open_store`, the one function every command opens the store through.**

1. `keyless_opt_out_refusal(store, security)` in `config/settings.py` states the at-rest opt-out
   rule once: `[store].require_encryption` refuses; no `allow_unencrypted_phi` refuses; under
   `enforcement = enforce`, no `allow_unencrypted_phi_under_strict_enforcement` refuses. It does not
   ask whether a key is configured. `_keyless_store_gate` in `__main__.py` now calls it.
2. `open_store` takes `keyless_chain_refusal: str | None`. When the opened store holds **no keying
   secret** (no in-heap HMAC key and no isolated-module MAC), **`audit_log` is empty, and no keying
   watermark is recorded** -- so the next append would be a keyless row 1 -- a non-`None` value
   closes the store and raises `KeylessAuditChainRefused`, naming the deciding setting. A SQLite file
   the same call created is removed again. **The default is the refusal**
   (`[security].allow_unencrypted_phi`), so a caller that does not decide is refused rather than
   waved through.
3. Every CLI command that opens the store passes `keyless_opt_out_refusal(...)` and turns the
   refusal into exit 2 with the message. `rotate-key` needs a key before it opens anything and keeps
   the refusing default. `serve`'s lifespan passes the verdict whenever `security_settings` is given,
   which `serve` always does.
4. A store method, `audit_append_refusal()`, answers "would an audit append be refused now" without
   appending. `provision-admin`, `admin-unlock` and `backup` call it before their first write. It
   also covers the case step 2 deliberately leaves alone: an EMPTY chain that is already keyed,
   opened with no key. That is not a keyless start, since its appends refuse on their own, so the
   seam's message would give the wrong remedy.
5. `open_store(warn_unkeyed_chain=False)` silences the #1905 keyless-chain WARNING for one open.
   Only `rekey-audit` passes it, since the warning names `rekey-audit` as its fix.

A source guard, `tests/test_keyless_chain_every_command.py`, walks every `open_store` call in
`messagefoundry/`, `harness/` and `scripts/`. A caller passing `None` must be on an allow-list with
its reason. Any other value must be the shared rule. A backend `.open` outside `store/` must be
named. The CLI openers must be exactly the set the behavioural tests exercise.

## Why the seam, and why at open

**Why not the CLI gate on every command.** That was #1905's shape, and it left a hole because each
command had to remember to call it. A default that refuses turns forgetting into a refusal.

**Why at open and not at the first audit append.** The append path is spread across three backends
and several writers, and the permission would have to reach each one. At open, the check is one
place above the backends. It reads the audit count through `audit_anchor()`, which is already on the
`Store` protocol, and the keying secret, which `open_store` itself derived. The cost is that a
read-only open of a fresh keyless store with no opt-out is also refused. That open starts nothing,
so the refusal is stricter than needed. Such a store would not start under `serve` either. Read-only
callers that must work on one pass `None` with their reason (the support bundle, the deployment
verifier, the full restore-verify snapshot, the load harness).

**Why "fresh" means an empty `audit_log`.** That is the only state in which this open's first row
starts the chain. A store whose chain already has rows is not started by this open, so an operator
can still verify a deliberately keyless store from a shell without the opt-out. A server backend has
built its schema before the check runs. That starts no chain: a later keyed open still keys the
empty log from row 1.

**Why the rule is key-independent.** A key named in the settings that `[store].key_provider` does not
resolve still opens the store keyless. Asking "is a key configured" would wave that through, which
is the case #1905 had to special-case inside `provision-admin`. Asking "does the opt-out apply" over
a store that turned out keyless covers it for every command. The message names that cause when a key
is configured.

**Why refuse before writing, not a transaction.** Making `provision-admin`'s account rows and audit
row one transaction would mean a store-protocol change across three backends for three commands. The
state that makes the append refuse is read at open, so asking first covers every case where it does
not change during the command. **One case it does not cover:** `admin-unlock` may run while `serve`
starts for the first time. With the opt-out in the admin's shell and a key in the service's, the
admin's open can read an empty, unkeyed chain, and `serve` can write its keying watermark before the
admin's append lands. That append is then a keyless row above the watermark, which `audit-verify`
reports as a break. It needs a misconfigured shell and a race of one short command, and it fails
loud rather than silent, so it is recorded here rather than closed.

## Rejected

- **Refuse at the first audit append.** See above: more places, same outcome for writers.
- **Auto-key the chain at open when rows exist.** Forbidden by the store's own contract: it would
  bless a forged row into a keyed chain. `rekey-audit` stays the explicit, chain-verifying step.
- **Keep the CLI gate and add it to every command.** Leaves the next command to remember it.
- **A permissive default on `open_store`.** Makes omission a bypass, which is the defect.

## Consequences

- A command run on a fresh store with no key and no opt-out now exits 2 where it used to succeed:
  `backup`, `admin-unlock`, `audit-anchor`, `audit-verify`, `rekey-audit`. Anchoring a fresh instance
  as `0:` (BACKLOG #328) still works with a key or under the opt-out. `serve` with a key named that
  the provider did not resolve now fails at startup inside the lifespan, which uvicorn reports as its
  own startup failure, where it used to start keyless.
- `create_managed_app` without `security_settings` (the embedding and test convenience) opens as
  before. That path is not how a service opens its store; the guard records the exemption.
- The backend `.open` classmethods decide nothing. They are library primitives, and the tests use
  them to build fixtures. `Engine.create(db_path)` is the one product caller of one, and it is the
  documented tests and embedding convenience.
