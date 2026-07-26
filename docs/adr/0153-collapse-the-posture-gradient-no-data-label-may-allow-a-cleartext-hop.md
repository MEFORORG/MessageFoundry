# ADR 0153 — Collapse the posture gradient: no data label may allow a cleartext hop

**Status:** Accepted (2026-07-25) -- owner-ratified after an adversarial review returned REWORK on the first
draft; the three open questions the rework raised were answered the same day and are folded in below. NOT yet
built. Amends
[ADR 0092](0092-posture-keyed-transport-hop-refusal-refuse-the-insecure-phi-hop.md) decisions 1 and 2 —
specifically the `is_phi` ALLOW arm and the escape clamp. Keeps 0092's one-authority structure, its loopback
carve-out, its attestation (decision 3), its two-layer construction/send gating (decision 4) and its
no-loosen rule (decision 5). Preserves the `[security].enforcement` dial of
[ADR 0148](0148-phi-default-posture-and-an-explicit-security-enforcement-level.md). Extends
[ADR 0002](0002-phase2-transport-security-and-strong-auth.md) §4. Related:
`docs/security/TLS-ONLY-POSTURE-PLAN.md`.

**Scope:** the **cleartext transport-hop** decision only. Every other authority that reads `HopPosture`
keeps its inputs and its behaviour — see *Explicitly out of scope*.

## Context

ADR 0092 keys the insecure-hop decision on the instance's posture, with a per-connection attestation as the
surgical escape. Its precedence arm 3 is `not is_phi → ALLOW`: an instance whose environment file declares
`data_class = "synthetic"` crosses **every** cleartext hop, silently, with no warning and no audit record.

This was found by upgrading a dogfood instance whose environment file had been quietly unparseable for some
time. The moment it loaded and `data_class = "phi"` took effect, a cleartext MLLP egress that had been
crossing without comment became a refusal. Nothing about the hop had changed — only a label in a different
file. The guard had been off for as long as the file had been malformed, and nothing reported that.

That is the wrong shape for a security control. `data_class` is authored in the same file as the hosts it
governs, by the same hand; a typo in it is indistinguishable from a deliberate declaration, and its blast
radius is every transport hop in the product.

Separately, `tls_hop_attested` is being asked to carry a meaning it does not have. It documents that a hop is
**secure by other means** — proxy-terminated, trusted segment. A legacy peer whose firmware has no TLS is not
that. Using attestation for it writes a false statement into a field that exists to be audited.

Nothing is deployed yet, so both can be fixed now without a migration burden.

## Decision

### 1. The cleartext-hop authority stops reading the data label

`insecure_hop_disposition` loses its `is_phi` parameter. The new precedence:

1. `is_loopback_hop` → **ALLOW** (unchanged — an on-box hop is not a network exposure);
2. `hop_attested` → **ALLOW** (unchanged — per-connection, load-validated, audited: the hop *is* secure);
3. `cleartext_accepted` → **WARN** (new — decision 2: the hop is *not* secure and that is accepted);
4. not `enforcing` → **WARN** (the `[security].enforcement` dial of ADR 0148, preserved — see below);
5. else → **REFUSE**.

Only 0092's arm 3 (`not is_phi → ALLOW`) is deleted. Because the deleted arm returned ALLOW, removing it can
only ever turn a crossing into a WARN or a REFUSE — never the reverse. **0092 decision 5 (no-loosen) holds by
construction**, and an unchanged configuration is byte-identical unless it was relying on the data label.

**`enforcing` is deliberately retained.** ADR 0148 GIVEN 2 makes `[security].enforcement` the refuse/warn
dial and its AC-3 requires it to work on every gate; deleting it here would leave the dial advertised in
`GET /security` while silently inert for transport hops. It is also categorically different from the arm
being removed: it is an explicit operator dial rather than a data-classification label, and it yields
**WARN**, which still logs and audits every hop. Nothing goes silent.

**`data_class` itself is not removed.** The hop authority no longer *reads* it. The key,
`[security].handles_real_patient_data`, `derived_posture()`, the `posture` line `check` prints, and every
non-transport gate that consumes them are unchanged. `HopPosture` keeps its fields, because
`revocation_hop_disposition` (ADR 0078), `_inbound_insecure_bind_permitted` and
`weakened_tls_escape_permitted` all still read them.

### 2. An honest per-connection escape for a peer that cannot do TLS

A new pair on **`Destination`** and in `connections.toml`:

```toml
cleartext_accepted = true
cleartext_reason   = "vendor firmware predates TLS; segment is not isolated"
```

Load-validated: the flag without a reason fails loud, a blank or whitespace-only reason fails loud, and a
reason without the flag fails loud. **The same rule is retro-fitted to `tls_hop_attested`**, which today
accepts the flag with no reason at all -- an attestation asserting *this hop is secure by means the engine
cannot see* is precisely the claim that most needs a written justification when it is audited. Nothing is
deployed, so there is no config to migrate. It yields **WARN**, never ALLOW — the hop is crossed, but it is logged at
every construction and recorded in the audit trail, because an accepted risk that stops being visible has
stopped being accepted and started being forgotten.

It is deliberately **separate** from `tls_hop_attested`, with the opposite claim:

| field | claim | disposition |
|---|---|---|
| `tls_hop_attested` | this hop **is** secure, by means the engine cannot see | ALLOW, silent |
| `cleartext_accepted` | this hop is **not** secure, and we accept that | WARN, logged + audited |

Collapsing the two would leave the audit trail unable to distinguish a proxy-terminated hop from plaintext
PHI on a flat network, which is the one distinction it exists to preserve.

**Destination-only.** Inbound binds are governed by a different mechanism —
`_inbound_insecure_bind_permitted` and the four exposed-gates, keyed on `--allow-insecure-bind` and
`tls_hop_attested` — which this ADR does not change. Putting the field on `Source` would add a setting
nothing consumes.

### 3. No TLS default is flipped

An earlier draft of this ADR proposed `tls: bool = True` on the transport factories. That is **not** part of
this decision, for three reasons found while sizing it:

* **It is redundant.** Under decision 1 an undeclared cleartext outbound hop already REFUSES. The author must
  act either way, and a refusal naming the hop is a better diagnostic than a TLS handshake failure against a
  peer that never spoke TLS.
* **It breaks every listener.** `_mllp_ssl_context(server=True)` raises
  `ValueError("MLLP inbound tls=true requires tls_cert_file")` (`transports/mllp.py:506`) *before* any policy
  runs, so no posture, attestation or acceptance flag can suppress it — including on the loopback binds
  arm 1 exempts, because that path never consults `is_loopback_hop_host`. Measured: 14 of 14 inbound MLLP
  listeners across the repo's six loadable config dirs hard-fail. `DICOM()` carries the identical trap.
* **It would disarm a working control.** The four inbound exposed-gates early-return when
  `source.settings.get("tls")` is truthy (`pipeline/wiring_runner.py:6137`, `:6173`, `:6208`, `:6249`). With
  the default flipped that branch always fires, replacing the actionable "binds non-loopback host without
  TLS" error with a generic missing-certificate one.

Four factories declare `tls: bool = False` — `MLLP()` (`wiring.py:768`), `Http()` (`:1050`), `DICOM()`
(`:1545`), `Ftp()` (`:2111`). All keep that default. "Secure by default" is delivered by the refusal in
decision 1, not by the parameter default.

### 4. Transports with no TLS support carry a standing declaration

`Tcp()` (`wiring.py:897-963`) and `X12()` have **no TLS support at all** — no `tls` parameter, no `ssl`
import in the connector, and `wiring_runner.py:6237-6239` records them in-code as plaintext-only with "no TLS
escape hatch". For those transports `cleartext_accepted` is a **permanent, structural declaration**, not a
transitional one: there is no `tls = true` for them to migrate to. The ADR says so explicitly so that a
future reader does not mistake a standing declaration for un-finished migration work.

Adding TLS to raw TCP and X12 is net-new transport work with no current requester. Recorded as **BACKLOG
#311** rather than opened as a follow-up ADR (owner, 2026-07-25); the backlog item exists so the permanent
declaration is not later mistaken for unfinished migration work.

### 5. `MEFOR_ALLOW_INSECURE_TLS` is unhooked, not deleted

The four-arm precedence in decision 1 has no `audited_opt_out` parameter, so the variable can no longer
influence a cleartext-hop decision — that follows from the precedence itself and needs no separate removal.

The **variable survives** for the six non-connection cells that still consume it (engine→store TLS, LDAPS,
the webhook alert sink, the AI-broker endpoint, and the CI legs that exercise them). Those are not
connections and cannot carry a per-connection field, so deleting the variable outright would leave them with
no expressible escape and would break roughly 17 CI legs, `docker/compose.yaml` and `docker/k8s/
ha-postgres.yaml` in the same change. Giving each of those cells its own declaration is worth doing and is
out of scope here.

## Explicitly out of scope

These read the authority or its posture and are **unchanged** by this ADR -- a ratified scope decision
(owner, 2026-07-25), not an oversight or a deferral. Each is listed so a reader knows it was considered:

| consumer | why unchanged |
|---|---|
| `phi_read_hop_disposition` (`tls_policy.py:501-531`) | the API PHI-read serve hop is not a connection; it hardcodes `hop_attested=False` and has no per-connection field to carry a declaration. Stays keyed on posture. |
| `settings.forward_hop_disposition` (`settings.py:2304-2317`) | the `[logging]` syslog/SIEM forwarder defaults to plaintext UDP (`settings.py:1315`) and is not a connection. Stays keyed on posture; a `[logging]` sibling of `cleartext_accepted` is a follow-up. |
| `rest._shipped_strict_disposition` (`rest.py:296-318`) | governs shipped-strict REST behaviour, not a cleartext hop decision. |
| `revocation_hop_disposition` (`tls_policy.py:551-590`) | ADR 0078 / #201 revocation gate; reads `HopPosture`'s fields, which this ADR retains. |
| `_inbound_insecure_bind_permitted` (`wiring_runner.py:6100-6124`) | the inbound bind gate; keyed on `--allow-insecure-bind` + `tls_hop_attested`, untouched (see decision 2). |
| `weakened_tls_escape_permitted` | reads posture fields, which are retained. |
| the ~11 non-transport PHI serve gates in `__main__.py` | read `require_posture()`, not this authority. |

## Consequences

### Positive

* **No environment-file label can disable a transport guard.** The only way to cross a cleartext hop is a
  declaration on the connection that crosses it, next to the host it names.
* **Strictly stricter, provably.** The only deleted arm returned ALLOW, so no hop that refuses today begins
  to cross. An unchanged configuration that was not relying on the data label is byte-identical.
* **The audit trail gains a distinction it did not have** — "secure by other means" versus "insecure and
  accepted" are now different fields with different dispositions.
* **No migration for existing configurations.** `cleartext_accepted` defaults off and no default is flipped,
  so nothing changes shape until an operator declares something.

### Negative / risks

* **A synthetic-data instance loses its blanket carve-out.** A test instance sending to a cleartext sink must
  now declare `cleartext_accepted` per destination, or run with `[security].enforcement = warn`. This is more
  ceremony than before, and it is the cost of the change.
* **Raw TCP and X12 can never satisfy the gate.** Their declaration is permanent (decision 4). An operator
  reading only decision 2 might expect a migration path that does not exist for them.
* **`cleartext_accepted` can be applied broadly.** Nothing stops an operator declaring it on every
  destination, which would approximate the blanket escape being removed. The mitigations are that it is
  per-connection (so it appears in review next to the host), that it warns and audits every construction, and
  that `check` surfaces the whole accepted set — but the ADR does not, and cannot, prevent it.
* **Reason quality is unenforceable.** The engine checks a reason is present and non-blank; it cannot check
  that it is true. A placeholder reason is a review problem, not a load problem.
* **Audit volume rises.** Every accepted cleartext hop warns per construction, where previously a
  synthetic-labelled instance emitted nothing. Proportionate if the declarations are honest, large only when
  there is a lot to see.
* **"Secure by default" is only delivered outbound.** Inbound binds remain governed by the exposed-gates
  rather than by this authority. That is a deliberate scope limit (decision 3), not a claim that the inbound
  side is finished.

### Out of scope but adjacent

Per-cell declarations for the API PHI-read hop, the `[logging]` forwarder and the four other non-connection
consumers of `MEFOR_ALLOW_INSECURE_TLS` (BACKLOG-worthy, not opened here); TLS support for raw TCP and X12
(**BACKLOG #311**).

## Alternatives considered

**Keep the gradient, validate the label harder.** Require `data_class`, reject unknown values, fail loud when
the environment file is unparseable. Fixes the specific bug that surfaced this but not its shape: a
correct-looking label would still switch off every guard, and a reviewer of a connection would still have to
read another file to know whether the hop is guarded.

**Flip the TLS defaults as well.** Sized and rejected — see decision 3. Redundant given the refusal, and it
breaks all 14 inbound listeners while disarming the exposed-gates.

**Reuse `tls_hop_attested` for legacy peers.** No new setting, no new validation. Rejected: it records "this
hop is secure" about a hop that is not, and the attestation's only value is being trustworthy when audited.

**Delete `MEFOR_ALLOW_INSECURE_TLS` outright.** Cleanest end state, rejected for now — six non-connection
cells have no other expressible escape, and it would break roughly 17 CI legs and the container manifests in
a change that is supposed to be about the hop authority.
