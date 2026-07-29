# ADR 0153 — Collapse the posture gradient: no data label may allow a cleartext hop

**Status:** Accepted (2026-07-25) -- owner-ratified after an adversarial review returned REWORK on the first
draft; the three open questions the rework raised were answered the same day and are folded in below.
**BUILT 2026-07-28** (see *Build notes* at the end for the three implementation questions this ADR left
open and how they were resolved). Amends
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
| `rest._shipped_strict_disposition` (`rest.py:296-318`) | **AMENDED AT BUILD (2026-07-28) — see Build note 1.** Its *floor* is not reworked, but the floor's KEY moved from the global escape to `cleartext_accepted` for the cleartext cells it serves, because a literal port would have made decision 2 inert for the whole HTTP family. The `verify_tls=false` cell it also serves is genuinely unchanged: it keeps the clamped global escape and does **not** take `cleartext_accepted`. |
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
  now declare `cleartext_accepted` per destination. This is more ceremony than before, and it is the cost of
  the change. **Correction (build, 2026-07-28):** the alternative this bullet also offered — "or run with
  `[security].enforcement = warn`" — works only for the raw transports. The HTTP family
  (REST/SOAP/FHIR/DICOMweb/`FhirLookup`) shipped these refusals unconditionally, so
  `rest._shipped_strict_disposition`'s ADR 0092 §5 no-loosen floor turns that WARN back into a REFUSE
  there. The per-connection declaration is the only route for those cells, which is exactly why Build
  note 1 re-keys the floor on it.
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

## Build notes (2026-07-28)

Built as specified. Five questions the ADR did not settle had to be answered to implement it; each is
recorded here because leaving them to an implementer's silent choice is exactly how a scope decision
becomes an accident. (Notes 1 and 3 were corrected on 2026-07-28 after an adversarial review — the
first draft of note 1 over-reached, and note 3 claimed a threading that had not been done. Notes 4 and
5 record what that review found.)

**1. `rest._shipped_strict_disposition`'s no-loosen floor is re-keyed on `cleartext_accepted` — for its
CLEARTEXT cells only.** The floor read `if disposition is WARN and not audited_opt_out: return REFUSE`,
which is how `MEFOR_ALLOW_INSECURE_TLS` relaxed an HTTP-family cleartext hop. A naive port would have
left `if disposition is WARN: return REFUSE`, converting decision 2's WARN straight back to REFUSE and
making `cleartext_accepted` **inert** for REST, SOAP, FHIR, DICOMweb, the HTTP credential cells and the
`fhir_lookup` read path — the largest cleartext-egress family in the product, and the only one where the
declaration is a genuine escape (`Tcp()`/`X12()` never reach that cell). For those cells the floor is now
keyed on `cleartext_accepted`, which preserves 0092 §5 exactly (a hop reaching WARN via the non-enforcing
dial alone is still floored to REFUSE, as today) and makes decision 2 effective where it matters. The
stated side effect: an instance that set `MEFOR_ALLOW_INSECURE_TLS` to cross a non-enforcing HTTP
**cleartext** hop no longer can. That is a **tightening**, and it is what decision 5 asks for.

The same function also serves the **`verify_tls=false`** cell, and that one is NOT re-keyed. A verify-off
hop is encrypted-but-unauthenticated, not cleartext, so this ADR — scoped to "the cleartext transport-hop
decision only" — does not govern it. It keeps the pre-0153 clamped global escape (`weakened_tls=True` in
`_shipped_strict_disposition`), exactly as the MLLP and FTPS `tls_verify=false` cells do through
`weakened_tls_escape_permitted_here()`. Threading `cleartext_accepted` into it was tried and **reverted**:
it would have LOOSENED a hop that refuses on an enforcing instance today (0092 decision 5 forbids that),
attached an operator's written "this peer cannot do TLS" reason to a peer that plainly does TLS, and split
the HTTP family from MLLP on the same question. The only 0153 change that reaches the verify-off cell is
the deleted `not is_phi` ALLOW arm, which can only tighten it. Pinned by
`tests/test_rest_transport.py::test_rest_verify_tls_false_not_relaxed_by_a_cleartext_declaration`.

**2. The two out-of-scope *delegating* callers restate the deleted arm explicitly.**
`phi_read_hop_disposition` and `settings.forward_hop_disposition` are the only out-of-scope consumers
that **call** the authority rather than reading `HopPosture` directly, so dropping `is_phi` would have
silently taken their synthetic-ALLOW arm with it — turning a synthetic instance's plaintext-UDP
`[logging]` forwarder and its non-loopback API PHI-read hop into refusals under `enforce`, contradicting
this ADR's own "keeps its inputs and its behaviour". Each now carries `if not posture.is_phi: return
ALLOW` before delegating, and passes the clamped global escape as the new arm-3 argument (byte-identical
— arm 3 occupies exactly the slot the old arm 4 did). Both are non-connections with nowhere to carry a
declaration, so refusing them would create a deviation the loosening registry cannot express. Restated,
not inherited: the scope limit is now a written decision at the one place it applies.

**3. `cleartext_accepted` reaches the CREDENTIAL hops as well as the body hops.** The ADR is silent, and
putting a password on the wire is a materially worse claim than putting a body on it. It is threaded
anyway — to HTTP Digest, the OAuth2 **and SMART** token endpoints, the forward-proxy credential and the
SOAP WS-Security / body-secret cells — because the alternative leaves an operator whose legacy peer needs
Basic auth over a cleartext segment with no honest declaration, and therefore pushes them toward writing
a **false `tls_hop_attested`**: precisely the defect this ADR exists to remove. SMTP AUTH over cleartext
remains refused **outright** in `transports/email.py`; that is a hard refusal, not a posture decision,
and is untouched.

The **SMART** token endpoint (`transports/smart.py`) needed more than threading. It did not consume the
hop authority at all: it read the raw, *unclamped* `insecure_tls_allowed()`, so one process-wide
environment variable put a signed `client_assertion` on cleartext http even on an enforcing PHI instance,
and that escape appeared in no loosening registry. It is now routed through
`refuse_cleartext_credential_hop`, exactly like its OAuth2 sibling — a **tightening**, and the last place
`MEFOR_ALLOW_INSECURE_TLS` was still alive on a connection-scoped cleartext decision.

**4. `FhirLookup()` gained the declaration as a real parameter, and the loosening reader walks the
lookups.** A `FhirLookup` connection has no `Destination`, and its read executor honours the pair off the
spec settings. Left there alone, the only way to declare it would have been mutating `spec.settings` by
hand: an escape with no load validation and no entry in `accepted_cleartext_hops`, so a live cleartext
**PHI-read** hop could cross while `check`, `security_loosenings()` and `GET /security/posture` all
reported the accepted set as empty. The pair is now a `FhirLookup()` parameter, coherence-checked at that
one authoring surface, and `accepted_cleartext_hops` walks `registry.fhir_lookups` as well as
`registry.outbound` (lookup entries are named `fhir_lookup:<name>`, a separate namespace).

**5. Found while building, NOT fixed here: `tls_hop_attested` has no authoring surface on a
connection.** No transport factory takes it, it is not a `connections.toml` key, and it is absent from
`_INBOUND_KEYS` / `_OUTBOUND_KEYS` — the connectors read it off `Destination`/`Source`, but the only way
to populate it is constructing the model by hand. So the ALLOW arm this ADR keeps (decision 1 arm 2) is
unreachable from config today, and decision 2's framing — "using attestation for a legacy peer writes a
false statement" — describes a mistake an operator currently *cannot* make on a connection. (The
`[logging].forward_hop_attested` sibling in `messagefoundry.toml` IS settable, and the retro-fitted
mandatory-reason rule bites there.)

This was left unbuilt deliberately. Wiring it would ADD a **silent-ALLOW** per-connection loosening, and
under "one shipped posture, loosen only" that needs its own `docs/SECURITY-LOOSENING.md` entry and its
own owner ratification — it is not a correction to this ADR's build. What was corrected is the
documentation: `docs/CONNECTIONS.md` had begun listing `tls_hop_attested = true` as one of "exactly
three ways such a hop crosses", so an operator following it got a hard load error and the only row that
loaded was `cleartext_accepted` — pushing them to declare "this hop is NOT secure" about a hop that is,
inverting the one distinction this ADR says the audit trail exists to preserve. Both operator docs now
say plainly that attestation is present in the engine and unreachable from config. **Owed.**

**Also built, beyond the decision list.** The retro-fitted flag-implies-reason rule on
`tls_hop_attested` (decision 2) reaches `[logging].forward_hop_attested` too — it shares
`_check_hop_attestation`, is documented as "the `[logging]` sibling", and `docs/PHI.md` already described
its reason as mandatory, so scoping the rule away from it would have left a documented guarantee
unenforced exactly where an auditor would look. `mllp.InsecureHopGuard`'s and
`rest._enforce_shipped_hop`'s attestation-audit branches dropped their `posture.is_phi` conjunct: with
the authority no longer reading the label, gating the audit on it would have silenced the record for the
very hops that newly depend on an attestation to cross.

**Visibility surfaces (owner requirement).** A declared acceptance appears in: a WARN plus a dedicated
record at **every** connector construction, naming the declaring connection, the cell, the host and the
reason; the `cleartext-accepted` line of `messagefoundry check`, which lists the whole accepted set; and
the `cleartext_accepted` entry in `security_loosenings()` / `GET /security/posture`, naming every
declaring connection. The construction record is a distinct WARNING log line, not a `store.record_audit`
row — the decision helper is pure `config/`-level code and cannot reach the engine's store across the
one-way dependency boundary (the ADR 0092 attestation record has the same shape and the same reason).

Three surfaces cannot see the whole set, and each SAYS so rather than reporting a subset:
`messagefoundry security show` and `GET /security/posture` on an engine with no loaded graph both emit a
`loosenings_scope` marker; the `serve`-time loosening warning fires before the graph is loaded and says
the construction gate reports them separately (it does, moments later, per connection).
