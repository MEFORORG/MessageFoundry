<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<!-- Copyright (C) 2026 MessageFoundry Organization and contributors -->

# ADR 0167 — PHI security-notification readiness gates on a deliverable address, checked early in the ASGI lifespan

- **Status:** Proposed (2026-08-15) — the predicate is built (`29a026e2`); the gate that consumes it is not yet written
- **Date:** 2026-08-15
- **Related:** [BACKLOG #1020](../BACKLOG.md) (the item, owner-ruled 2026-08-13) · [BACKLOG #1257](../BACKLOG.md) (a startup refusal after `engine.start()` hangs) · [`__main__.py`](../../messagefoundry/__main__.py) (the existing SMTP-only gate) · [`api/app.py`](../../messagefoundry/api/app.py) (the lifespan) · [`auth/service.py`](../../messagefoundry/auth/service.py) (`has_notifiable_admin`) · [DEPLOYMENT.md](../DEPLOYMENT.md) (exit codes) · [CLAUDE.md](../../CLAUDE.md) §0 (not deployed), §11 (SDS-3.8)

---

## Context

### The gate answers the adjacent question

On a PHI instance under `enforcement=enforce`, `serve` refuses to start without a security-notification
channel. It computes readiness as:

```python
security_channel_ready = bool(
    settings.auth.notify_security_events
    and settings.alerts.email_smtp_host
    and settings.alerts.email_from
)
```

That is **SMTP wiring alone**. It asks *"is a transport configured"* and never *"can the account that
matters actually receive"* — **SDS-3.8**, the instrument answering a neighbouring question.

The two come apart on exactly the instance the gate exists to protect. `_ensure_bootstrap_admin` calls
`create_user` with no `email=`, so on a first run the only account — the one holding
`frozenset(Permission)` — has a NULL address, and `SecurityEventNotifier.notify` opens
`if not event.email: return`. **All ten notice types no-op for the most privileged account on the
instance while the gate reports a healthy channel.**

Per **CLAUDE.md §0** this is written in the conditional: there are zero deployments, so nothing is
exposed today. It is wrong in the shipped code, and it is wrong in the direction a first deployment
would not notice.

### Owner ruling

**2026-08-13: option (b) — gate startup on a deliverable channel.** The design question was settled
before this ADR. What was not settled, and what this ADR is for, is **where the check runs**.

---

## Decision

**1. Gate on a deliverable address, scoped to the ROLE.** `AuthService.has_notifiable_admin()` is true
iff at least one **enabled** administrator has an email on file. Not the bootstrap account: `email` is
optional in `UserCreateRequest` and is not required for the Administrator role, so a hand-created
privileged account has the identical hole. Keying on the bootstrap user would close the instance this
was found on and leave the class open.

**2. Run the check EARLY IN THE LIFESPAN — after the store opens, before `engine.start()`.**

Measured on `api/app.py`: `async def lifespan` at `:5512`, `store = await open_store(...)` at `:5540`,
`await engine.start()` at `:5731`. **The window is 191 lines wide**, and inside it the store is open
and no engine tasks exist.

### Placements considered

| name | placement | store access | terminates? | exit code |
|---|---|---|---|---|
| **LIFESPAN** | after `engine.start()` | open | **NO — hangs** (BACKLOG #1257) | n/a |
| **PREFLIGHT** | `_serve`, before the ASGI app | **none available** | yes | **2** |
| **EARLY-LIFESPAN** | after the store opens, before `engine.start()` | **open, plain `await`** | **yes, measured** | **3** |

**LIFESPAN is out on a measurement, not a preference.** #1257 records that an exception after
`engine.start()` unwinds nothing, so the refusal hangs the process instead of exiting — **strictly
worse than the defect this ADR fixes**, because an operator can see a wrong readiness answer but
cannot see a process that never finishes starting.

**PREFLIGHT was recommended and withdrawn by its author on measurement.** `_serve` (lines 1042-2833)
runs entirely before the lifespan and never opens a store — zero `open_store` calls across the whole
function. `list_users()` is async. So PREFLIGHT is not "one cheap read": it is **the first store open
in a preflight that has never opened one, driven from sync code**, ahead of whatever `open_store` does
on first touch. That machinery would be bought to preserve an exit code (see below) that the shipped
service wrapper ignores.

**EARLY-LIFESPAN gets the store as a plain `await`** — no extra open, no sync/async bridge — and its
refusal exits.

---

## The exit code changes, and the divergence is forced

**Measured** (uvicorn, CPython 3.14.6, minimal ASGI app, probe kept out of tree):

| arm | result |
|---|---|
| raise early in the lifespan | **exited 0.49s, code 3** — `ERROR: Application startup failed. Exiting.` |
| `sys.exit(2)` early in the lifespan | **exited 0.50s, code 3** — stderr shows `SystemExit: 2`, then the same uvicorn line |
| **positive control**, no raise | reached a **RUNNING** server, self-stopped with a distinct code **99** |

**The control is what makes the exits mean anything.** A non-exit was observable in the same rig, so
"it exited" was not the only outcome the harness could produce.

**uvicorn catches `SystemExit`, treats it as a startup failure like any other exception, and exits 3
regardless of the code requested.** From inside the lifespan there is **no spelling of a refusal that
keeps exit 2**. The divergence is forced, not chosen.

### What that costs, stated no larger than it is

`_serve` returns **2** at 32 sites, and `DEPLOYMENT.md` states "(exit 2)" twice — at `:210` for the
PHI/enforce TLS preconditions and at `:564` for the off-loopback bind refusal. **Both citations are
scoped to specific refusals. No line generalises exit 2 to all refusals.**

So a new refusal exiting 3 is **an inconsistency with two documented specific refusals, not a
contradiction of a published universal claim.** An earlier draft of this reasoning called it a
"documented-contract divergence"; that was stronger than the text supports and is corrected here
rather than quietly dropped.

**And it must not be claimed that exit 2 gives operators a clean stop today:**
`scripts/service/install-service.ps1:463` sets NSSM `AppExit Default Restart`, which restarts on **any**
exit code. Under the shipped service wrapper the operational delta between 2 and 3 is approximately
nil. **The cost is a reader's surprise, not a broken script.**

**Accepted, with the cheap honest fix:** `DEPLOYMENT.md` gains a line recording that a **startup-stage**
refusal exits 3, beside the existing exit-2 statements. That converts an undocumented inconsistency
into a documented one for the cost of a sentence, and it is the only part of this decision an operator
will ever see.

---

## Rejected: a sentinel that re-exits 2

`uvicorn.run()` does not return on the startup-failure path — it exits the process itself. **If** that
exit is a catchable `SystemExit` at the call site, a caller could catch it and re-exit 2 off a flag set
by the refusal, preserving the exit code with the lifespan placement.

**Considered and declined. It is untested — that "if" was never measured.** It is a **cross-layer
mechanism** (lifespan sets state, caller intercepts, re-exits) bought to remove an inconsistency that
the NSSM finding above makes nearly free. **The sentinel costs more than the thing it fixes.**

Recorded rather than omitted, because an unmentioned alternative gets re-derived by the next reader and
a declined one with a reason does not.

---

## Consequences

- A PHI instance under `enforce` with a configured SMTP transport and **no notifiable administrator**
  will refuse to start, where today it starts and reports a healthy channel.
- **That refusal exits 3, not 2**, and is the first refusal in this codebase to do so.
- The check runs on **every** serve of a PHI instance, adding one `list_users()` plus a role lookup per
  enabled user at startup only.
- **There are now three independent copies of "who is an enabled administrator"** in `auth/service.py`
  (`has_notifiable_admin`, `is_last_enabled_admin`, `_other_enabled_admin_exists`). Their agreement is a
  convention with nothing binding it. Extracting a shared enumeration is worth its own item and is
  deliberately not done here.

## What is NOT demonstrated

**The termination evidence is a minimal repro, not the real gate.** It proves uvicorn's
lifespan-startup-failure path exits; it does **not** prove the real refusal exits with a real store open
and everything `api/app.py` has constructed by `:5540`.

**BACKLOG #1020's rider asks for the refusal to be demonstrated to terminate under `uvicorn`, and a
rider that exists because someone inferred is not satisfied by an inference.** **This ADR must not be
cited as discharging it.** The real gate carries that obligation when it lands.
