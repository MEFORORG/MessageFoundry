# Proposed backlog items from Fable review packet 12 (clients)

Four proposals, in the house format minus the heading number. **No number is allocated here**; the
Manager allocates serially after the packets land. Each proposal was searched for a duplicate by
symptom, file path and symbol in both `docs/BACKLOG.md` and
`docs/archive/backlog/BACKLOG-CLOSED.md`, and item status was read through `parse_items`. The
byte-level reproductions live in the vaulted `FABLE-PACKET-12-CLIENTS-2026-09-11-FINDINGS.md`.

One finding was **not** proposed because it is already filed: the web console's orphaned export,
log-tail and log-level client code (P12-07) is recorded under #124 and #171, both open, each saying
the feature is "wired to nothing".

---

## Proposal 1 (P12-01). The VS Code extension cannot connect to a stock engine because it has no way to trust the minted self-signed certificate

**Filed - not started.** Since ADR 0172 (Accepted 2026-08-22, shipped under #1276) the engine
always serves TLS, minting a self-signed certificate beside the store when none is configured. The
extension's engine client (`ide/src/engineClient.ts` `tlsOptions`) pins a `TLSv1.2` floor and
otherwise relies on Node's default CA set, and its default `messagefoundry.engineUrl` is
`http://127.0.0.1:8765`. Measured 2026-09-12 against a default-posture engine started from the
tree at `70063ab55`: the extension's https request fails with `DEPTH_ZERO_SELF_SIGNED_CERT`, its
default http request fails with `ECONNRESET`, and a control with verification disabled returns
200. The http failure is reported as "engine not reachable ... start it" while the engine is
running. Promote, sign-in, live status and every authenticated command would fail on a fresh
install at defaults. #1179's research names "client scheme agreement across tray, apiclient,
harness and IDE" as unallocated work; this is the IDE's share of it. The harness's `--insecure`
records the same wall (`harness/__main__.py` 91-100).

- **Cluster:** IDE / client TLS
- **Priority:** P1
- **Verdict:** defect
- **Severity:** High (reachability, not disclosure; conditional on first use at defaults)

**Fix.** Either read the generated certificate path from the service TOML the extension already
reads (`messagefoundry.serviceConfig`) and pass it as the request's `ca`, or implement
trust-on-first-use with the certificate fingerprint stored in `SecretStorage` keyed by engine URL
behind an explicit confirmation that names the fingerprint. In both cases: change the default
`engineUrl` to `https://127.0.0.1:8765`, and make `networkError` distinguish a TLS-trust failure
from a refused connection so the message offers the remedy. Add a unit test for the trust decision
(the `engine-target.test.ts` pattern) and a note in `ide/README.md`. Whether VS Code's
`http.systemCertificates` would make an OS-store import work is unmeasured and should be measured
in the same change.

---

## Proposal 2 (P12-02). The harness scenario runner still false-passes against a prior run, because control ids are deterministic and the M-32 fix keys on them

**Filed - not started.** June's M-32 was fixed in `f25f8fac` by filtering the dead-letter list to
"this run's" control ids, and low-23 by querying `/messages` per control id. Both keys are
deterministic: `messagefoundry/generators/_core.py` `control_id("ADT","A01",1)` returns
`MEFORADTA0100001` on every run and `generate_message` is byte-identical across calls (measured
2026-09-12). So the rows a prior run of the same scenario left in a long-lived database carry
exactly the ids the next run looks for. Measured: `harness/scenarios.py` `_verify_dead_letter`
called with a client returning only a prior run's two rows, and nothing sent, returned `ok=True`
with the detail "2/2 of this run's messages dead-lettered"; `_verify_disposition` behaves the same.
The pinning test `tests/test_harness_scenarios.py::test_verify_dead_letter_ignores_preexisting_rows`
uses foreign ids (`OTHER1`, `OTHER2`) for its stale rows, a shape the generator never produces, so
it certifies the fix against the wrong case; a negative control that removed the id filter turned it
red, so the test can see the filter go but not the filter fail. The June row's "CI masks
regressions" half does not hold: no workflow runs `python -m harness --scenario`; the runner is a
manual instrument against a running engine, which is the case the row named.

- **Cluster:** harness / test quality
- **Priority:** P2
- **Verdict:** defect
- **Severity:** Medium (a pass/fail instrument that can report success without the engine doing anything)

**Fix.** Make each run distinguishable: pass a per-run nonce as the generator `seed` and match on
the ids it produces, or snapshot the matching ids before sending and require new ids after. Rewrite
the pinning test so its stale rows carry the ids a prior run of the same scenario produces. Apply
the same to `_verify_disposition`. Consider the same question of the load and failover verifications
in `harness/load/`, which packet 12b will read.

---

## Proposal 3 (P12-03). The web console's single-connection purge step-up gate has no test that would catch its removal, and the golden write-actions file records the registry's claim rather than the route's enforcement

**Filed - not started.** `POST /ui/connections/{name}/purge/{scope}`
(`messagefoundry_webconsole/routes/connection_writes.py` `ui_purge_connection`) is gated by
`require_ui_step_up`. A negative control on 2026-09-12 downgraded that dependency to `require_ui`
and ran `test_webui.py -k "stale or purge"` (23 passed), then `test_golden_surface.py`,
`test_ui_hardening.py` and `tests/test_webconsole_seam_snapshot.py` (46 passed): 69 tests green
with the gate gone. The four purge tests assert a permission refusal, a cross-site refusal, a
cookie-on-JSON-route refusal, and that a fresh login reaches the handler; none sends the request
with a stale step-up window. The existing stale-window tests cover user delete, edit-resend, the
upload family and cluster stepdown. `packaging/messagefoundry-webconsole/tests/golden/ui_write_actions.txt`
records `step_up=1` for the purge path, but that value comes from `register_ui_action`, a separate
call from the route's dependency, so the record stays `step_up=1` while enforcement is gone. The
console calls `core.purge_connection` in-process through the ADR 0065 seam, so the JSON API's own
`require_step_up(MESSAGES_PURGE)` never runs for a browser purge; the console gate is the only
step-up control on that path.

- **Cluster:** web console / test quality
- **Priority:** P2
- **Verdict:** defect
- **Severity:** Medium (an untested step-up on a PHI-delivery-cancelling action; SDS-3.7 shape in the golden record)

**Fix.** One stale-window test for the purge path asserting the 303 to `/ui/reauth?next=...` and
that `purge_connection` was not reached, modelled on
`test_stale_stepup_bounces_body_less_action_via_reauth`. Make the golden generator derive
`step_up` from the route's resolved dependencies rather than from the registry, so the record and
the enforcement cannot disagree, and add a test that the two agree for every registered action.

---

## Proposal 4 (P12-04). The client dependency rule is broken in eight harness files and nothing enforces it for any client

**Filed - not started.** `CLAUDE.md` section 4 and `harness/CLAUDE.md` allow a client to import
`parsing/` and nothing else from the engine. Measured at `70063ab55`: eleven direct imports of
`messagefoundry.transports.mllp`, `messagefoundry.config`, `config.models`, `config.wiring` and
`pipeline.sharding` across `harness/mllp.py`, `harness/scenarios.py`, `harness/load/sender.py`,
`harness/load/sink.py`, `harness/load/shardcert.py`, `harness/reconcile/__main__.py`,
`harness/reconcile/capture.py` and `samples/send_mllp.py`. In a fresh interpreter
`import harness.scenarios` loads 119 engine modules including `transports`.
`tests/test_dependency_boundaries.py` forbids only `fastapi`, `pyside6`, `messagefoundry.api` and
`messagefoundry.console` from the five engine packages and has no inward rule, so Signal 1 is
documented rather than enforced for every client (packet 1's P1-03 recorded the same gap for
`parsing/`). The recurring need is one thing: MLLP framing (`frame`, `MLLPDecoder`, `build_ack`)
and the `AckMode` enum have no client-importable home. Related detail for whoever touches
`harness/monitor.py`: its "Purge" button calls purge-all with no confirmation (June's M-28, moved
with the rehomed widgets), no `EngineClient` step-up or MFA handler is wired under `harness/`, and
a 401 inside `_poll` becomes a status line with no re-sign-in; and
`harness/_console_widgets.py` line 11 still says calls run synchronously on the GUI thread while the
code runs them on a worker.

- **Cluster:** architecture / dependency boundaries
- **Priority:** P2
- **Verdict:** defect
- **Severity:** Medium (a governing invariant for parallel work, broken and unchecked)

**Fix.** Move MLLP framing and `AckMode` into a leaf module that imports nothing from
`transports/`, `config/` or the package root (under `parsing/`, or a new `messagefoundry/mllpcodec.py`),
re-export from the current homes, and rewrite the eight import sites. Add an inward assertion to
`tests/test_dependency_boundaries.py` that `harness/`, `tee/`, `samples/` and
`messagefoundry_webconsole/` import nothing from `messagefoundry.{store,pipeline,transports,config}`
except a named allow-list (the web console's `_ui_seam` and `auth` imports are a designed, golden-
pinned seam under ADR 0065 and #1220 and belong on that list). Land it with P1-03's inward rule for
`parsing/`. `harness/load/shardcert.py` deliberately runs the loader and the sharding planner and
needs its own allow-list entry or a ruling; packet 12b owns that file.
