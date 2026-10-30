<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<!-- Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors -->

# 0216 — The gravest Vault token grants refuse start under enforce, with an audited opt-out

- **Status:** Proposed (2026-10-30) -- built as slice A of vault BACKLOG #2903. Its basis is the
  owner ruling of 2026-10-04 (17:06:09Z UTC) recorded on that row; merging records it as Proposed and
  accepts nothing.
- **Date:** 2026-10-30
- **Related:** vault BACKLOG #2903 (this change), #305 (its parent), #2851 (the providers no longer
  fall back to `VAULT_TOKEN`), ASVS 13.2.2 ·
  [ADR 0199](0199-an-over-granted-store-login-refuses-start-under-enforce-with-an-audited-opt-out.md)
  (the store login's refusal, whose shape this follows) ·
  [ADR 0148](0148-phi-default-posture-and-an-explicit-security-enforcement-level.md) (the
  `[security].enforcement` dial) ·
  [ADR 0140](0140-two-acknowledged-production-phi-no-loosen-carve-outs-single-factor-admin-at-exposure-keyless-phi-in-production.md)
  (the acknowledged opt-out shape)

---

## Context

`messagefoundry check-privileges` probes each Vault token the engine uses: a token self-lookup for
its policies, then one capabilities read for the paths the engine calls and the administrative paths
it never calls (`messagefoundry/privilege_probes.py`). `messagefoundry/privilege_check.py` judges the
reading. Until this change `serve` never ran that probe: `privilege_probes` was imported at run time
only inside the command. So on a first deployment a Vault token holding the root policy or the right
to export the store key would have started with no warning, no audit row and no refusal.

The store login has had a startup preflight since BACKLOG #1008, and ADR 0199 made an over-grant
there refuse start under `enforce`. The `serve_verdict` docstring left whether a Vault over-grant
should refuse "to its own change". This is that change.

**The owner ruled on 2026-10-04 (17:06:09Z UTC), in these terms:** *"Gravest grants only"* --
*"Root policy, admin paths and Transit key control refuse by default, with an audited opt-out.
Everything else warns, alerts and audits."* That selection replaced an earlier one the same day
(17:01:13Z) that would have refused on any over-grant. The declined options were *"Any over-grant, as
picked"* and *"Any over-grant, fix probe first"*. An adversarial review that day found the coded
over-grant definition is a report definition and too wide for a start refusal: one token shared by
two hops, and an extra capability beside the one the engine needs, are ordinary setups.

## Decision

**The over-grant reasons `vault_hop` reports fall in two classes.**

- **The refusing class:** the `root` policy; any capability but `deny` on an administrative path the
  probe asks about. Those paths are `VAULT_ADMIN_PATHS`, a write of each policy the token carries
  (so a token able to rewrite its own policy is caught), and each Transit key's `config`, `rotate`,
  `export` and `backup` paths. `HopPrivilege.refusing` carries these reasons.
- **The warning class:** every other over-grant the probe reports. At least these three are in it:
  one token serving two hops; an extra capability on a path the engine calls; and a policy name that
  is not plain printable ASCII, which the probe cannot tell from root by reading it, so it cannot
  judge rather than having seen root.

**`vault_preflight_outcome` in `privilege_check.py` states the decision once.** The startup
preflight and `check-privileges` both call it, and it returns the store preflight's own
`PreflightOutcome`.

| Finding | `enforcement` | `allow_over_granted_vault_token` | Outcome |
|---|---|---|---|
| none (clean, or no Vault consumer) | any | any | start |
| refusing class | `warn` | any | warn and start |
| refusing class | `enforce` | `false` | **refuse** |
| refusing class | `enforce` | `true` | start, audited |
| warning class only | any | any | warn and start |
| unobservable: a network failure, a timeout or a 403 | any | any | warn and start |
| probe failed for any other reason | `warn` | any | warn and start |
| probe failed for any other reason | `enforce` | any | **refuse** |

**Only a network failure, a timeout or a 403 is an unobservable probe in the ruling's sense.**
`excused_failure` in `privilege_probes.py` names them, by class; its docstring lists the classes.
It is not every `OSError`: a malformed address or header, a missing CA file and a TLS verification
failure are configuration. Any other failure left the token unjudged for a reason the ruling does
not excuse. At least these are in that class: a `TypeError` or `AttributeError` after an hvac
rename or signature drift, an engine refusal such as an unset token variable, another Vault error
status, and an answer that names no capabilities for a path. The hop names each in `unexcused`,
whether the probe caught it or raised it, and under `enforce` `vault_preflight_outcome` refuses on
one. The opt-out does not lift that refusal: it accepts a grant that was seen, and this token was
never fully read. `check-privileges` says so for a hop it read in part; a hop it could not read at
all it names as unread, because its own run may lack what `serve` has, such as the token. A
catch-all that read every failure as unobservable would have let a code defect start an enforcing
instance on a root token, with nothing but the exception's type in the log.

**The preflight runs at every `serve` start**, in `messagefoundry/vault_preflight.py`, called from
the managed lifespan in `api/app.py` after the store privilege preflight and before any listener
binds, with the same teardown on a refusal. It names the consumers from the resolved service
settings (`vault_consumers`), probes each through `probe_vault` -- a client from the provider's own
constructor, the token and address read from the provider's own sources, the instance hop posture
and the hop's revocation attestation -- and runs the probe off the event loop. Since BACKLOG #2851
the providers refuse an unset `MEFOR_*_VAULT_TOKEN` rather than fall back to `VAULT_TOKEN`, so the
probe reads the token from the source the provider reads, and the row's first closing point needs no
change of its own. The probe reads it again rather than sharing the provider's client, so a token
replaced between the store open and the probe is the one judged. Each probed hop writes
one `vault_privilege_preflight` audit row, best effort, before any refusal. With no Vault consumer
configured nothing is probed and no row is written.

**The opt-out is `[security].allow_over_granted_vault_token`.** It follows
`allow_over_granted_store_principal`: a `[security]` acknowledgment switch, default `false`, read
directly by the serve lifespan. When it lets a token start, the preflight logs a WARNING line that
starts `AUDIT:` and names the switch, the audit row carries `over_grant_accepted: true` beside
`refused: false`, and `security_loosenings()` names it, so `GET /security/posture` shows it. It lifts
that one refusal and nothing else.

**`check-privileges` prints what serve would do.** Its `serve:` line now refuses on a Vault hop in
the refusing class, names an accepted one, and says a warning-class finding does not refuse. Its exit
codes are unchanged: an over-grant of either class exits 3.

## Consequences

- **A Vault token holding the root policy or an administrative grant no longer starts under the
  shipped defaults.** A Vault dev server's root token is the common case. The cost of this breaking
  change is currently zero, because MessageFoundry is a not-deployed beta with no running instance.
  The fix is to reduce the token's policy, set the opt-out, or set `enforcement = warn`.
- **It is the third recorded exception to the scoping rule "a new refusal fires only on a new
  opt-in"** (`docs/CONFIGURATION.md`, on `require_memory_encryption_declaration`), beside the ADR 0140
  amendment and ADR 0199. It rests on the 2026-10-04 ruling. None of the three generalises.
- **`serve` makes two read-only Vault calls per token at every start**: the self-lookup and the
  capabilities read, both in Vault's `default` policy. A token made with `-no-default-policy` reads
  as unobservable at every start unless its policy grants the two paths, and that only warns,
  because Vault answers it with a 403.
- **An unset token variable, or a Vault error status other than 403, such as a sealed Vault's
  503, refuses an enforcing start at the preflight.** None is a network failure, a timeout or a
  403. Neither was measured against a live Vault or a connector-secret hop that resolves its
  secrets later; under `warn` both still only warn.
- **The probe's limits are unchanged and are not fixed here.** It asks about exact paths only, so a
  wildcard grant such as `secret/data/*` would read clean. Neither limit, nor the classes, was
  measured against a live Vault.
- **Two more limits follow from the ruling and the seam, and are stated rather than fixed.** A
  token whose policy denies the probe's two paths reads as unobservable, which only warns by the
  ruling, so it never refuses however wide its other grants are. And the probe runs at start only:
  a token replaced in the secrets directory after start is used by the provider and not judged
  until the next start.
- **Not built in this slice: the alert.** The ruling says a warning-class finding warns, alerts and
  audits. This slice warns and audits. The alert, with an inverse that resolves it on a clean start
  as `store_privilege_clean` does for the store, needs a new event type in the notifier and is the
  row's remaining slice.

## Alternatives considered

- **Refuse on any over-grant** (the 17:01:13Z selection, and *"Any over-grant, as picked"*).
  Rejected by the owner's later selection: it would refuse a token shared by two hops, or one with
  `list` beside `read`, which are ordinary setups.
- **Refuse on any over-grant once the probe is fixed** (*"Any over-grant, fix probe first"*).
  Declined by the owner; the tiered scope does not wait on the probe.
- **Reuse `allow_over_granted_store_principal` for Vault.** Rejected: a store login and a Vault token
  are different credentials with different remedies, and one switch would accept both when an
  operator meant one.
- **A new outcome type for Vault.** Rejected: the store preflight's `PreflightOutcome` already names
  the four outcomes, and one type keeps the two read-outs alike.
