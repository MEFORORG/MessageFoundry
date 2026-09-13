# Proposed backlog items from Fable review packet 11 (pipeline remainder)

**These are proposals, not items.** No number is allocated and nothing here is written into
`docs/BACKLOG.md`. The Manager allocates serially after the packets land (owner instruction relayed
2026-09-12) and files from this list. Each proposal is in the house format minus the heading number,
with the duplicate search recorded. The byte-level reproductions are in the vaulted findings document
`docs/reviews/FABLE-PACKET-11-PIPELINEREST-2026-09-11-FINDINGS.md` (vault branch
`vault/fable-packet11-pipelinerest`); this file names the subject, the mechanism and the fix only.

Engine ref measured: `70063ab55`. Every impact claim is conditional: there are zero deployments
(`CLAUDE.md` section 0).

**Findings deliberately not filed here.** P11-10 (three stale doc texts) goes to packet 18's
documentation pass. The dry-run's blindness to `[sandbox].mode` is already the fifth consequence in
open BACKLOG #1278 and is cited, not re-filed. P11-09 is folded into proposal 3. Every refuted candidate
is listed in the findings document's part 7 and needs no item.

---

## Proposal 1. A Handler that returns a value the partitioner does not recognise (its own `Message`, a `str`, a `dict`) is silently `FILTERED` in every mode, and a test pins the drop

> Filed 2026-09-12 - not started. Found by Fable review packet 11 (finding P11-01). `pipeline/dryrun.py`
> `_partition` turns any return that `config/wiring.py` `handler_result_items` does not recognise as a
> container into a single item, matches it against `Send`, `SetState` and `SetMeta`, and drops it;
> `_sandbox_codec.py` `_enc_item` describes the same item as `{"o": "other"}` so `mode=subprocess`
> agrees. Measured on `70063ab55`: `dry_run` reported `FILTERED` with no error for handlers returning
> `msg`, `msg.encode()`, a `dict` and a `(str, Message)` tuple; the live `RegistryRunner` in the default
> pooled mode finalized the message `filtered` with events `received`/`routed`/`transformed`, nothing
> delivered, and zero WARNING-or-above log records. `messagefoundry check` passes such a fixture unless a
> sidecar demands otherwise. `tests/test_dryrun.py::test_a_bare_message_return_still_drops_and_never_raises`
> pins the drop.

**Cluster:** Correctness / data loss. **Priority:** P1. **Verdict:** build (small).
**Severity:** high (silent non-delivery of an entire feed, recorded as deliberate filtering, with no
operator signal and a green pre-deploy gate), medium likelihood (an author slip; two shipped texts,
`transports/x12.py`'s module docstring and `docs/CONNECTIONS.md`'s X12 inbound section, still say a
Handler's returned payload is "written back verbatim", and returning the transformed message is the
Mirth idiom this engine positions against).

**Relation to closed #341.** That item widened `_partition` to any non-`str` iterable under an owner
ruling of WIDEN, not raise, for containers. Its closing note records that a bare `Message` "still drops
silently rather than newly raising, because the gate is `isinstance(..., Iterable)` and never a
duck-typed `list(result)`". That is a mechanism reason (no duck-typed `list()`), not a ruling that the
drop is correct; the item's own "why it is not merely cosmetic" paragraph makes this proposal's argument.
The Manager should confirm whether the owner meant it as a ruling before filing.

**Fix.** In `_partition`, after materialisation, raise `ValueError` for any non-`None` item that is not
a `Send`, `SetState` or `SetMeta`, naming the handler and the type; apply the identical rule in
`_enc_item` so the two modes cannot diverge (the #341 build constraint). The live path already routes a
transform-stage `ValueError` to the internal-error policy (`ERROR` dead-letter, replayable); dry-run
reports `ERROR`; `check` goes red. No duck-typed `list()` is involved, so the `Message.__getitem__`
concern in #341 does not arise. Rewrite the pinning test to assert the raise, and add the live-runner
case. Correct the two "written back verbatim" texts in the same change or under packet 18's item.

**Duplicate search.** No open item. #341 (closed) is the container half and scoped this out. Searched
both ledgers for `_partition`, `handler_result_items`, `return msg`, `bare Message`, `returns its
Message`, `FILTERED` with `silent`/`indistinguishable`/`accept-and-drop`.

---

## Proposal 2. Two of the three M-7 pins stay green with the router-stage fail-closed deleted, because a downstream path produces the same `ERROR`

> Filed 2026-09-12 - not started. Found by Fable review packet 11 (finding P11-02) as a negative control.
> With `route_only`'s `raise ValueError(...)` for an unknown handler replaced by `pass`,
> `tests/test_dryrun.py::test_route_only_unknown_handler_raises` went red and
> `test_router_to_unknown_handler_is_error` (the dry-run pin),
> `tests/test_wiring_engine.py::test_inbound_unknown_handler_dead_letters_at_ingress` (the runner pin)
> and all of `tests/test_checks.py` stayed green. In dry-run, `transform_one`'s `registry.handlers[name]`
> raises `KeyError`, which `dry_run` maps to `ERROR` with the name in the text. In the runner, a routed
> row is committed for the ghost handler and the transform worker's missing-handler branch dead-letters
> it; the test asserts `ERROR` and no delivered file, and nothing about the stage.

**Cluster:** Test quality. **Priority:** P2. **Verdict:** build (small). **Severity:** medium (the
router-stage fail-closed exists so no routed row is ever committed for a handler that cannot run; a
regression that removed it would keep both integration pins green and the one unit pin is the kind of
test a refactor of `route_only` rewrites).

**Fix.** Make the dry-run pin assert the error text contains the router-stage message (`returned unknown
handler`), not merely the ghost name. Make the runner pin assert the dead row's stage is `ingress` and
that no `routed` row was created for the message, or assert on the recorded error text. Rename the
runner test only if the stage assertion is added.

**Duplicate search.** No open or closed item. Searched both ledgers for `M-7`, `unknown handler`,
`route_only`, `dead_letters_at_ingress`.

---

## Proposal 3. Dry-run does not apply the ingress guards the live handler applies before routing, so `check` passes fixtures the engine would NAK

> Filed 2026-09-12 - not started. Found by Fable review packet 11 (findings P11-04 and P11-09). The
> runner's `_handle_inbound` decodes with the connection's `encoding` and `errors="strict"`, rejects a
> NUL in the decoded text (added in vault commit `522fe9f0`, 2026-07-13), enforces the 16 MiB ceiling
> and runs strict validation under a timeout with `ERROR` plus `AE` on expiry. `pipeline/dryrun.py`
> `dry_run` calls `normalize(raw)` with the `utf-8`/`replace` defaults, has no NUL or size guard, and
> calls `validate` inline with no timeout; the CLI's `read_messages` decodes through `split_batch`, also
> `utf-8`/`replace`, while the file source it claims to mirror decodes with the declared encoding and
> `errors="strict"`. `_dry_run_raw` decodes bytes as strict UTF-8 outside any `try`. Measured on
> `70063ab55`: a NUL in PID-5 previewed `RECEIVED` with one delivery; a latin-1 fixture came back with
> U+FFFD in place of the byte; non-UTF-8 bytes on a non-HL7 inbound raised `UnicodeDecodeError` out of
> `dry_run`.

**Cluster:** Dry-run and gate fidelity. **Priority:** P2. **Verdict:** build. **Severity:** medium (a
deploying site would use `check` and the Test Bench to decide a feed is ready; a fixture that previews
`RECEIVED` and NAKs on the first live message is a gate that lies, and the encoding case leaves the
preview looking routed and transformed).

**Fix.** Thread the inbound's `encoding` into `dry_run` and `read_messages` (strict; a failure is an
`ERROR` result with the runner's text); add the NUL and size guards before `Peek.parse`; run strict
validation under the connection's timeout; wrap `_dry_run_raw`'s decode. Extract the runner's
post-decode guard sequence into one function the runner and `dry_run` both call, so a fourth copy of
the rule cannot drift either. Add a parity test that drives one synthetic message through both
`dry_run` and a `RegistryRunner` and compares dispositions for each guard.

**Duplicate search.** No open or closed item. Searched both ledgers for `read_messages`,
`split_messages`, `NUL`, `\x00`, `normalize`, `dry-run`/`dryrun` with `encoding`/`latin`/`fixture`,
`diverge`/`parity` with `dry-run`. #1128 (open, ASVS 5.2.2 file-content validation) mentions
`read_messages` in passing and does not cover this.

---

## Proposal 4. Dry-run reports a message whose every `Send` was declined as `FILTERED`; the live path records `NOT_DEPLOYED`, and the `.expect` vocabulary cannot say so

> Filed 2026-09-12 - not started. Found by Fable review packet 11 (finding P11-03). `disposition_for`
> maps a routed outcome with no deliveries to `FILTERED` unconditionally; `DryRunResult` carries no
> `declined` field and `dry_run` drops `RouteOutcome.declined`. The store's finalizer returns
> `NOT_DEPLOYED` when a `not_deployed` event was recorded in the handoff (pinned by
> `tests/test_not_deployed.py`). `checks.py` `_DRYRUN_DISPOSITIONS` is `{RECEIVED, UNROUTED, FILTERED,
> ERROR}`. Measured on `70063ab55`: a handler sending only to an outbound with `deployed=False` previewed
> `FILTERED` with no `declined` attribute while `route_message` returned `declined=['out']`.

**Cluster:** Dry-run and gate fidelity. **Priority:** P2. **Verdict:** build (small). **Severity:**
medium (#233 ruled that a decline must not be indistinguishable from an intentional filter; the
pre-deploy gate collapses them again, and `checks.py`'s own comment works around it by excluding
not-deployed feeds from the cross-product rather than reporting the truth).

**Fix.** Add `declined: list[str]` to `DryRunResult` and populate it in both `dry_run` paths; give
`disposition_for` a `NOT_DEPLOYED` branch for a routed outcome with no deliveries and a non-empty
`declined`; add `NOT_DEPLOYED` to `_DRYRUN_DISPOSITIONS`; emit `declined` in the `dryrun` CLI's JSON.

**Duplicate search.** No open or closed item. Searched both ledgers for `NOT_DEPLOYED` with
`dryrun`/`check`/`expect`, `disposition_for`, `declined`. #233 (closed) built the live disposition and
did not touch dry-run.

---

## Proposal 5. Dry-run ignores `stream_threshold_bytes`: a Handler previews against the original OBX-5 document and runs live against the `mfdoc:` skeleton

> Filed 2026-09-12 - not started. Found by Fable review packet 11 (finding P11-05). On a streaming inbound
> the runner's `_detach_documents` replaces each qualifying OBX-5.5 with an `mfdoc:v1:ref:` handle and
> `enqueue_ingress` receives the skeleton, so the Router and every Handler see the handle. `dry_run`
> has no detach step. Measured on `70063ab55`: an inbound with `stream_threshold_bytes=1` and a synthetic
> ORU carrying a base64 ED document; the handler saw the base64 in dry-run and `dry_run` reported
> `RECEIVED`.

**Cluster:** Dry-run and gate fidelity. **Priority:** P3. **Verdict:** build or document. **Severity:**
low-medium (opt-in only, `stream_threshold_bytes` defaults to `None`; but a site that enables streaming
for a document feed would find every Handler that reads OBX-5 previewing one thing and delivering
another, and the difference is exactly the bytes the feature keeps out of the pipeline).

**Fix.** Either apply the detach in dry-run against an in-memory attachment stub (the handle is a
SHA-256 of the verbatim base64, so it is deterministic) so the preview shows the skeleton, or refuse to
preview an over-threshold fixture on a streaming inbound with an explicit `ERROR` naming the reason.
Document the choice beside `stream_threshold_bytes` in `docs/CONNECTIONS.md`.

**Duplicate search.** No open or closed item. Searched both ledgers for `stream_threshold`, `mfdoc`,
`detach` with `dry-run`. #149 (closed) built the streaming path; #1127 (open, ASVS 5.1.1 inventory)
mentions the setting in passing.

---

## Proposal 6. `DryRunResult.meta_ops` has never been populated, and the `dryrun` CLI prints neither metadata ops nor declines

> Filed 2026-09-12 - not started. Found by Fable review packet 11 (finding P11-06). `dry_run` and
> `_dry_run_raw` build `DryRunResult` without `meta_ops=outcome.meta_ops`; the field has been empty since
> `MetaOpPreview` arrived in vault commit `bc31c4c7` (2026-07-10), whose docstring says the CLI gates the
> value behind `--show-phi`. The CLI's output dict has no `meta_ops` and no `declined` key. Measured on
> `70063ab55`: `transform_one` returned one `MetaOpPreview` and `dry_run` on the same graph returned
> `meta_ops == []`.

**Cluster:** Dry-run and gate fidelity. **Priority:** P3. **Verdict:** build (small). **Severity:** low
(a preview omission; a Handler's `SetMeta` writes are invisible to the Test Bench and the CLI).

**Fix.** Populate `meta_ops` in both `dry_run` paths; emit it in the CLI under the same `--show-phi`
gate as `state_ops`; emit `declined` beside it once proposal 4 lands; correct the `MetaOpPreview`
docstring.

**Duplicate search.** No open or closed item. Searched both ledgers for `meta_ops`, `MetaOpPreview`,
`SetMeta` with `dryrun`. #150 (closed, ADR 0081) built `SetMeta`.

---

## Proposal 7. Under `[sandbox].mode=subprocess`, a worker whose bootstrap cannot succeed dead-letters every message on its inbound, one spawn attempt per message, with no alert and the runner reporting healthy

> Filed 2026-09-12 - not started. Found by Fable review packet 11 (finding P11-07). `_sandbox_for` builds
> the session lazily and `SandboxSession._live_worker` spawns on first dispatch; `_spawn` raises
> `SandboxError` on a `bootfail` reply, an EOF, or `startup_seconds` (30 s) elapsing, and the router
> worker's catch-all routes it to `_apply_router_internal_error` as a content fault: `dead_letter_now`
> under the default `CONTINUE`. Nothing at `start()` spawns or verifies a child, and no branch
> distinguishes "the worker could not start" from "the Router raised". Measured on `70063ab55` with a
> `RegistryRunner`, `SandboxPolicy(mode=SUBPROCESS)` and a config source that does not exist: three
> synthetic messages all finalized `error`, each with one WARNING, the alert sink received no call,
> `degraded_connections()` was empty. The bootstrap failed fast here; a child that hangs in
> `load_config` would hold each message for `startup_seconds` first.

**Cluster:** Sandbox and operator signal. **Priority:** P2. **Verdict:** build. **Severity:** medium
(count-and-log holds: every message is `ERROR` and replayable; but the operator signal is per-message
and identical to a Router bug, the lane keeps acknowledging, and a site that flips the sandbox on with a
config directory the service account cannot read, or a `mem_mb` too small for its config, would
dead-letter a whole feed with every connection showing green).

**Fix.** Spawn each inbound's worker at `start()` and on reload, where the runner already knows the
config source, and treat a bootstrap failure as a startup fault: a degraded connection with the reason,
which the API and console already render, or a refusal to start under `[security].enforcement=ENFORCE`.
Independently, classify a `SandboxError` raised by `_spawn` as an infrastructure fault rather than
content: stop the lane with a `connection_stopped` alert and release the row, the shape the
credential-fault policy already uses. Add a runner-level test that injects a failing bootstrap and
asserts the alert and the retained row.

**Duplicate search.** No open or closed item covers the failure mode. #1278 (open, sandbox-by-default)
lists `startup_seconds` among the costs the flip arms and notes the first message pays it; #1458 (open)
is the per-inbound worker-tree cost. Neither names a bootstrap that never succeeds. Searched both
ledgers for `_sandbox_for`, `startup_seconds`, `bootfail`, `bootstrap`, `sandbox worker did not start`.

---

## Proposal 8. The traced dry-run reports `routed_to: []` for a Router that returns a tuple or set

> Filed 2026-09-12 - not started. Found by Fable review packet 11 (finding P11-08).
> `pipeline/dryrun_trace.py` `_routed_from` handles `str` and `list` only, while `dryrun._handler_names`
> accepts any non-`str` iterable, so the message-level `handlers` is right and the router invocation's
> `routed_to` is empty with no `lazy_result` flag (that flag covers one-shot iterators only). Measured on
> `70063ab55`.

**Cluster:** Dry-run and gate fidelity. **Priority:** P3. **Verdict:** build (small). **Severity:** low
(trace-only; the disposition is byte-identical).

**Fix.** Reuse `_handler_names`' rule in `_routed_from`, keeping the iterator carve-out, and add the
tuple case to `tests/test_dryrun_trace.py`.

**Duplicate search.** No open or closed item. Searched both ledgers for `routed_to`, `_routed_from`,
`trace` with `tuple`. #341 (closed) touched the handler half of the tracer only.

---

## Ledger row for the plan (for the Manager to write)

| # | Packet | Status | Date | Findings doc | Health verdict | Checks |
|---|---|---|---|---|---|---|
| 11 | Pipeline remainder | findings written | 2026-09-12 | `FABLE-PACKET-11-PIPELINEREST-2026-09-11-FINDINGS.md` | `adequate`, unchanged. **Split declared:** 11b owed for `cluster.py`, `cluster_sqlserver.py`, `config_convergence.py`, `state_convergence.py`, `secret_rotation.py`, `reference_sync.py`, `cert_expiry.py`, `security_notify.py`, `update_check.py`; `retention.py`, `dr.py`, `dr_backup.py` to packet 15 | ruff, format, mypy strict (274 files) green; 20 covering suites 543 passed / 95 skipped (94 server-DB legs); 4 negative controls red for the right reason; 51 pinning tests green |
