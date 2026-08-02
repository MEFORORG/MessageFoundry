# Backlog

The **Next up** item is the active priority (the next major effort). The numbered items below it are
intentionally deferred — not blocking, and not an open security exposure on the shipping
configuration (SQLite store, single uvicorn worker, localhost + auth). Each numbered item names the
originating review finding(s) so the full context (file:line + proposed fix) can be looked up in the
cited report. Several of those reports — the `docs/reviews/` and `docs/security/` sets — are
maintainer-internal and will not resolve here; [`SECURITY-DOCS-POLICY.md`](SECURITY-DOCS-POLICY.md)
states the rule that decides what is withheld and what you can request.

### Ledger erratum (2026-07-30) — read this before citing or allocating a number

**`#242`–`#246` as written in the ADRs are not indices into this file.**
[ADR 0115](adr/0115-asvs-l3-drive-to-pass-secure-by-default-flips-and-residual-closure.md) partitioned
the ASVS L3 drive-to-Pass programme across five work packages and writes them `BACKLOG #242`–`#246`;
ADRs 0004, 0014, 0018, 0019, 0068, 0077, 0080 and 0105 cite the same numbers as `WP #243`–`WP #246`.
Those items were filed in the maintainer-internal ledger that **this file is a published baseline of**,
and the published baseline stops at **#231** — as the #185 banner and the `#313` reference further down
already say. They were never published here, and they are not back-filled: their per-cell scope is
defined only in the `docs/security/` remediation plan, which
[`SECURITY-DOCS-POLICY.md`](SECURITY-DOCS-POLICY.md) withholds. Read those citations the way the
`docs/reviews/` and `docs/security/` paths above are read — **provenance into the internal ledger, not a
pointer into this file.** Whether any of it is republished here is an owner decision.

**The resolution rule, stated generally — it is not only the ASVS numbers.** For **any** cited `#N`
above **#231** (in an ADR, a plan, a commit message, a code comment, or an operator-facing string),
resolve it against the **internal** ledger unless the citation is demonstrably about this file. The two
sequences diverged at #231 and have been allocated independently since, so a number appearing both here
and in a citation is *not* evidence they are the same item. If you cannot see the internal ledger,
**ask rather than resolving it here** — landing on a same-numbered but unrelated item is the failure
mode, and it looks like success.

**Consequently the numbers in this file above #231 are a second, independent sequence**, and items
#232–#239 and #248–#251 do not correspond to the internal items sharing those numbers. This is recorded,
not repaired: renumbering would rewrite ratified ADRs, and republishing would cross the policy above.

⚠️ **This has already shipped once, and nothing in CI can catch it.** On 2026-07-30 an item was filed
here at a number the internal ledger had already used for unrelated work, and it reached `main` before
anyone noticed; the number was cited in a gate comment, an operator-facing refusal message, a test
docstring, two docs and the CHANGELOG. It was corrected on 2026-07-31 by re-allocating against the fixed
floor. **`backlog_status_check.py`'s duplicate detection cannot see this class of collision** — it reads
this one file, where the number appears exactly once. The published baseline is not a safe place to
check a number against; only the allocator is.

**#240–#247 are permanent holes — do not file there.** They were allocated on 2026-07-30 by repeated
runs for the same four titles; only the last run's numbers (#248–#251) were filed. #240–#243 are held by
a worktree that no longer exists, and `alloc.ps1` has no release verb by design ("holes are free,
collisions are not"), so those claims stand permanently and the ledger gate will refuse a commit that
files there. **#315** and **#317** are deliberate probe allocations used to verify the floor fix below;
they are holes too. Always allocate with `scripts/coord/alloc.ps1`; never pick a number by reading this
file.

**If you allocated a backlog number before 2026-07-31T00:31Z, re-check it — the trigger is the
timestamp, not the value.** That is when the floor fix landed. Any number issued before it came from a
floor that could not see most of the namespace, so it is suspect **regardless of how low or high it
looks**; a bounded "suspect range" is the wrong instrument and gave at least one session false comfort.
To check one, search **every** ref, not the published file and not a single branch:

```bash
for r in $(git for-each-ref --format='%(refname)' refs/heads refs/remotes); do
  git show "$r:docs/BACKLOG.md" 2>/dev/null | grep -qE '^## <N>\.' && echo "$r"
done
```

Checking one ref is not checking the namespace — the numbers are scattered across hundreds of refs,
which is exactly why the floor sweeps them all. A single-ref check reported one number as free that was
in fact in use on 28 refs.

The root cause is fixed: the backlog floor in `alloc.ps1` now sweeps **every** local and remote ref, as
its own header comment always promised and as the ADR path already did. Before the fix it read only
`origin/main` + `HEAD`, so numbers living on refs this branch does not carry were invisible and were
handed out as free — which is exactly how #240–#247 were issued over cited numbers.

---

## Shipped — v0.1.0 (enterprise / HA milestone)

**Released 2026-06-18.** `v0.1.0` is tagged, signed, and published to PyPI — the GitHub release (marked
Latest) carries the wheel + sdist + CycloneDX SBOM + Sigstore signatures + SLSA build provenance. The
`v0.1.0-rc1` pre-release (2026-06-16) preceded it. Full scope and the hard-gate record:
[`releases/v0.1-PLAN.md`](releases/v0.1-PLAN.md). Capability catalog across every area, with status:
[`FEATURE-MAP.md`](FEATURE-MAP.md).

v0.1 delivered a **server DB as the supported production path (PostgreSQL + SQL Server)**, **engine HA
via active-passive (primary/failover)** with DB-tier HA delegated to the DB admins, and **native TLS**.
All four hard gates were met before the tag: (1) PHI log redaction · (2) no "experimental" backends ·
(3) published throughput + tuning baseline · (4) native off-loopback TLS. **Active-active horizontal
scale-out was parked at v0.1 and is now dropped (not a planned milestone, 2026-06-18); its active-active-specific
code has since been removed** (per-lane ownership, the `renew_leases` heartbeat, the `lane_leases` table — plus a
`DROP TABLE IF EXISTS lane_leases` migration). Of the deferred items below, **#1** (SQL Server) shipped *promoted*,
**#2** (console threading) and **#6** (IDE tests) landed, and **#3** (per-key ordering) stays 0.2.

> **Status (2026-06-18): `v0.1.0` released.** Everything below the four-gate line landed and was verified
> against `origin/main`; the engine side of v0.1 is done:
> - **Gate #3** (throughput + tuning baseline + active-passive failover-load run) — **DONE**:
>   [`benchmarks/TUNING-BASELINE.md`](benchmarks/TUNING-BASELINE.md) is published with measured 3-backend
>   throughput/latency + a failover-load result, backed by committed metrics-only artifacts, the
>   failover-load harness (`harness/load/failover.py`), and an on-demand benchmark CI workflow (#283/#290/#294).
> - **Workstream F** (release mechanics) — **DONE**: single-sourced version, CHANGELOG, and a signed
>   `release.yml` (build → CycloneDX SBOM → Sigstore keyless signing → SLSA build provenance → GitHub release →
>   PyPI Trusted Publishing). The `v0.1.0-rc1` pre-release (#296/#332) and then the final `v0.1.0` tag were cut.
> - **Workstream G** (console HA operability) — **DONE**: leader/cluster view on Engine Status + off-thread
>   reads (#299), with the per-page off-thread polling completed in #341 — which also closes deferred **#2**.
>
> The public `0.1.0` tag shipped **without** gating on the licensing/legal decision — that formal
> counsel review was **deferred as a dated accepted-risk decision (2026-06-17)**: `v0.1.0` shipped on
> the drafted AGPL-3.0-or-later + `NOTICE`/`COMMERCIAL-LICENSE`/`CLA` posture **without** counsel sign-off.
> *Optional non-gating follow-up:* re-run the Postgres failover after fix #293 to refresh the
> published ~60 s recovery figure (the hard conformance tier — zero loss, order-preserving, drain-to-zero —
> passes on all three backends regardless).

---

## Next up — post-0.2.10

`v0.2.0` through **`v0.2.10`** are shipped to PyPI (engine + `messagefoundry-harness`, lockstep). The v0.2
marquee (FHIR codec + REST client #20, observability/metrics #21, console Alerts/Dead-Letters #22, user
guide #19) and the entire Plan-3 / Plan-4 / Plan-5 connector + codec + parity wave landed — see the per-item
✅ banners below and the `CHANGELOG.md` `[0.2.x]` entries (**authoritative for build state**). **Active-active
horizontal scale-out is dropped and its code removed** (2026-06-18).

**What remains is small and mostly demand-gated.** Ordering now comes from the [ranked
table](#ranked-backlog--value--difficulty-on-a-ten-level-scale-re-scored-2026-07-10) below. Its top is the
**ASVS 5.0 L3 remediation set** — **#186** (secure-by-default flips) · **#201** (certificate revocation) ·
**#194** (step-up bound to the action) · **#187** (auth defaults) · **#202** (off-box audit forwarding) ·
**#188** (out-of-band security notifications) — plus **#102**, a confirmed data-loss defect on the
server-DB DR path. The cheap wins beside them are **#74** (host CPU/mem metrics), **#100** (AOAG
`MultiSubnetFailover`) and **#82** (MSA-2↔MSH-10 ACK correlation), each value 6 at difficulty 2.

Everything else is **demand-gated** — kept in the ranking with an intrinsic-worth score, but built only when
its named trigger fires (the discipline that protects the minimal-dep, on-prem, code-first identity) — or
**declined-by-design** (#18 / #25 / #26 / #27). A build-state audit during this re-score flipped **#33**
(config-UX review — its findings doc shipped in #421) to ✅ and **reopened #91** (the free-threading A/B gate
had been declined on a premise its own ADR 0053 contradicts). **#40** self-hosted CI, **#60** turnkey DR,
**#41** cloud / Kubernetes HA packaging and **#61** third-tier DR standby have all shipped; **#11** WebAuthn
shipped (ADR 0068 L5a); **#39** (frozen console installer Phase B) was built then retired (2026-07-01,
superseded by the #75 browser ops dashboard). Sequencing context for the earlier wave lives in
[`releases/MULTISESSION-PLAN-6.md`](releases/MULTISESSION-PLAN-6.md).

---

## Ranked backlog — value × difficulty on a ten-level scale (re-scored 2026-07-10)

> **What changed, and why to trust it.** The 2026-07-09 pass below scored open items on a **five**-level
> scale that had collapsed — **105 of 113** scored items sat on value `2`/`3` — and it never reached the 21
> ASVS 5.0 L3 findings (**#185–#205**), which landed in [#854](https://github.com/wshallwshall/MessageFoundry/pull/854)
> after the [#851](https://github.com/wshallwshall/MessageFoundry/pull/851) prioritization. All **134
> open items are re-scored here on a ten-level scale**, from each item's own `Scope` / `Why` / `Trigger` /
> `Nearest existing mechanism` text — not rescaled from the old numbers.
>
> This ranking was produced and then **adversarially audited against the code**, not just re-judged:
> - Every item was scored twice independently (the two runs agreed on **129/134** values); every score that
>   nobody had yet argued against got a dedicated **refuter**; disagreements were adjudicated against the text.
> - **`Verdict` and `Trigger` were read from each item's own lines**, not inferred — 120
>   of 134 verdicts come straight from the item's `**Verdict:**` line.
> - **Every schedulable banner's factual claims were checked against the repository.** This surfaced real rot:
>   #33, #48, #64, #84 and #97 were each described as open work that had wholly or partly shipped; their banners are corrected and #33 is closed. A backlog that lies about build state silently misdirects planning — the reason
>   [`scripts/docs/backlog_status_check.py`](../scripts/docs/backlog_status_check.py) exists.
> - All **69 shipped/declined/retired items were audited** for merge evidence; **1**
>   (#91, declined on a premise ADR 0053 contradicts — now reopened) failed and was corrected.
> - **Value = intrinsic worth if built.** An earlier version of this table capped value at 5 for any item
>   whose trigger had not fired; that conflated *worth* with *schedule* and pinned 31 items at exactly 5. The
>   cap is gone. Scheduling is expressed only by the **tier**: an item stays `DEMAND-GATE` however high it
>   scores, driven by its own `Verdict` line.
>
> Shipped (✅), declined (⛔) and retired (🪦) items are out of scope and keep their banners.
> **Items #206–#222** (the throughput/harness cluster from #860 and the IDE low-code pair from #865) landed *after* the main table below; they are ranked in the **Post-re-score additions** section that 
> follows it, and now carry ten-level banners. (#206–#220 were scored by the same evidence-based, code-fact-checked pass; #221–#222 keep the scores set when they were filed.)

**VALUE 1–10** — worth if built. `10` a live defect on shipping defaults or a hard block on the Corepoint
cutover · `9` an ASVS L3 **Fail** on as-shipped defaults, or a named adopter is waiting · `8` an ASVS L3
**Partial** on defaults, or a production blind spot with no workaround · `7` real gap, no workaround · `6`
real gap, awkward workaround · `5` parity/breadth with a clean workaround · `4` DX or console polish · `3`
niche interop knob · `2` marginal, already substantially covered · `1` ships nothing runnable.

**DIFFICULTY 1–10** — cost to land the remainder through `ruff` + `mypy --strict` + `pytest` (and, for the
store, all three backends). `1` a default flip or doc edit · `2` small additive change on an existing seam ·
`3` a new setting into one connector · `4` a feature across a seam, tested on SQLite + PostgreSQL + SQL
Server · `5` a new connector/codec behind the transport registry, maybe a vetted dependency · `6`
cross-cutting pipeline + store + API + console, or Windows-CI-gated · `7` a new ADR plus a 3-backend
migration · `8` a new architectural seam, touching the stage handoff or the ACK contract · `9` a
security-critical rewrite, or multi-week behind a hard correctness gate · `10` would change the
at-least-once / strict-FIFO invariant, or needs a component the project refuses.

**Quadrant** splits the value×difficulty plane at 5/6: _quick win_ (high value, low cost) · _big bet_ (high
value, high cost) · _fill-in_ (low value, low cost) · _money pit_ (low value, high cost).

**Tier** derives from the score, with one override: an item whose named trigger has not fired stays
`DEMAND-GATE` regardless of score, read from its own `**Verdict:**` line. Otherwise `P1` = value ≥ 8, or
value ≥ 6 at difficulty ≤ 2 · `P2` = value ≥ 5 · `P3` = the rest.

**Distribution.** Value: **1**:3 · **2**:18 · **3**:20 · **4**:18 · **5**:29 · **6**:35 · **7**:5 · **8**:5 · **9**:1. Difficulty: **1**:5 · **2**:29 · **3**:38 · **4**:23 · **5**:16 · **6**:15 · **7**:3 · **8**:3 · **9**:2.
Tiers: **P1** 9 · **P2** 15 · **P3** 9 · **DEMAND-GATE** 101.
Quadrants: _quick win_ 34 · _big bet_ 12 · _fill-in_ 77 · _money pit_ 11.
*(⚠️ These three lines are the **frozen 2026-07-10 snapshot** and are NOT recomputed as items close or
re-price — the 2026-07-28 reconcile closed 31 items and re-priced #94 from difficulty 8 to 5–6, none of
which is reflected above. Treat the counts as a dated record of the original scoring pass, never as a
current census; the per-item banners are the live state.)*

Ordered by value descending, then difficulty ascending (cheapest first at equal value).

| # | Item | Title | V | D | Quadrant | Tier | Why |
|--:|---|---|--:|--:|---|---|---|
| 1 | **#201** | Certificate revocation checking (OCSP/CRL) | 9 | 6 | _big bet_ | P1 | Fail in both postures, no OCSP/CRL anywhere; high/P1 value, but revocation on every verifying TLS context (stdlib offers none) is cross-cutting. |
| 2 | **#102** | Server-DB DR seed verification has no teeth (P2) | 8 | 4 | _quick win_ | ✅ SHIPPED | **SHIPPED (banner re-verified 2026-07-28):** the fail-closed seed gate is on all three backends (`Store.has_prior_backup_history()`; gate at `pipeline/dr.py:413-478`), requiring a DBA attestation **and** a live restore-provenance probe. Its vintage residual **#223** is closed too. |
| 3 | **#186** | Secure-by-default: retention, at-rest encryption, egress allowlists | 8 | 4 | _quick win_ | P1 | Closes five ASVS L3 Partials on as-shipped defaults (retention 0, egress allow-any, LocalSystem); built-but-off, LocalSystem flip Windows-CI-gated. |
| 4 | **#194** | Bind step-up re-verification to the action, not the login window | 8 | 4 | _quick win_ | P1 | Most exploitable item: a hijacked session can bind an attacker's factor for durable takeover on defaults; extends the existing action-tied password step-up. |
| 5 | **#187** | Authentication defaults: require MFA, tighten TOTP skew, phishing-resistant factor | 8 | 5 | _quick win_ | ✅ SHIPPED | **SHIPPED (banner re-verified 2026-07-28):** `require_mfa=True` + `totp_skew_steps=0`; WebAuthn via the `[webauthn]` extra by design. The Kerberos residual closed with ADR 0079 **Accepted**, mechanism 2 built 2026-07-22 (`auth/reconcile.py`). The `ad_session_recheck_seconds` default flip is a separate lane. |
| 6 | **#202** | Off-box log/audit forwarding: default-on, TLS transport, synchronized time | 8 | 5 | _quick win_ | P1 | Built but off — no audit copy survives host compromise; P1/high; adds native TLS-syslog and a startup time-sync gate atop a default flip. |
| 7 | **#188** | Out-of-band security notifications on by default | 7 | 2 | _quick win_ | P1 | ASVS notifier + SMTP transport are built but the push ships off — a Partial on as-shipped defaults, closed by wiring the push on by default. |
| 8 | **#192** | Browser ops-console hardening: headers + cookie prefixes | 7 | 3 | _quick win_ | P2 | Clears five of Posture B's ten Fails with no operator workaround, but on the opt-in console rather than defaults; header/cookie tweaks plus a CSP nonce refactor. |
| 9 | **#65** | Generic outbound HTTP auth — OAuth2 client-credentials / HTTP Digest / NTLM | 7 | 4 | _quick win_ | ✅ SHIPPED | **SHIPPED 2026-07-12:** OAuth2 client-credentials (symmetric `client_secret`) + HTTP Digest on REST/SOAP/FHIR via a pluggable auth-provider seam (`transports/http_auth.py`, ADR 0024 amendment). **NTLM/Negotiate scoped out** — connection-bound handshake needs a keep-alive client urllib can't provide (pyspnego follow-up). |
| 10 | **#154** | HTTP response-header capture on delivery response | 7 | 4 | _quick win_ | ✅ SHIPPED | **SHIPPED 2026-07-12:** a per-connection allow-list captures REST/FHIR/SOAP response headers (Location/ETag) into `DeliveryResponse.headers` → new encrypted `resp_headers` column across 3 backends → `response_get(dest).headers` on re-ingress (ADR 0013 amendment). |
| 11 | **#134** | Outbound batch aggregation - N messages into one BHS/BTS envelope on send | 7 | 6 | _big bet_ | DEMAND-GATE | Real outbound-batch gap with no in-engine workaround: Handler purity bars cross-message accumulation and delivery is strictly one-row-one-message. |
| 12 | **#74** | Host / system metrics — CPU / memory | 6 | 2 | _quick win_ | P1 | Real observability gap on the existing metrics surface, a one-day build whose only cost is vetting and re-locking the new psutil dep. |
| 13 | **#82** | Sender transport-polish bundle — pacing · MSA-2↔MSH-10 matching · TCP keep-alive | 6 | 2 | _quick win_ | ✅ SHIPPED | **SHIPPED (banner re-verified 2026-07-28).** ⚠️ The former *"Confirmed gap: `_check_ack` matches MSA-1/MSA-3 only"* reason is **retracted as false** — `verify_ack_control_id` (`transports/mllp.py:663`) correlates MSA-2↔MSH-10, and `send_min_interval_seconds` supplies pacing. |
| 14 | **#100** | `MultiSubnetFailover=Yes` opt-in for the SQL Server store connection (P2) | 6 | 2 | _quick win_ | P1 | Real AOAG-failover gap with a DNS-TTL workaround (v6); a single validated bool emitting one ODBC keyword before the TLS tail, one test (d2). |
| 15 | **#118** | Test the alert mail server (send test email / SMTP verification) | 6 | 2 | _quick win_ | ✅ SHIPPED | **SHIPPED (banner re-verified 2026-07-28):** `POST /alerts/test-email` (`api/app.py:2427`) does a live, PHI-free SMTP send through the built email sink (commit `37613ef0`, PR #1200). |
| 16 | **#115** | Per-connection Auto-Start toggle | 6 | 3 | _quick win_ | DEMAND-GATE | Real operational gap; only awkward workarounds — delete it from config or re-stop it after every restart; a persisted flag gated at startup. |
| 17 | **#144** | Alert-triggered connection-control action | 6 | 3 | _quick win_ | ✅ SHIPPED | **SHIPPED (banner re-verified 2026-07-28, ADR 0128):** `_ALERT_CONTROL_ACTIONS` (`config/settings.py:2472`) dispatched at `pipeline/alert_sinks.py:945-947`. ⚠️ The *"notify-only"* premise is **retracted as false**. |
| 18 | **#145** | HA / DR failover event alert | 6 | 3 | _quick win_ | ✅ SHIPPED | **SHIPPED (banner re-verified 2026-07-28, ADR 0014 amendment):** `leadership_acquired`/`lost` (`alert_sinks.py:800`) + `dr_activated`/`released` (`pipeline/alerts.py:215`, `:223`). ⚠️ The *"only log at INFO"* premise is **retracted as false**. |
| 19 | **#199** | Input-handling hardening: CSV escaping, content sniff, cleartext-egress refusal | 6 | 3 | _quick win_ | P2 | Cleartext-PHI-egress refusal is a real default guardrail gap, plus low-risk CSV/content-sniff; three small changes reusing existing helpers. |
| 20 | **#204** | Enforce lookup-input encoding, content scanning, and SMART AS assumptions | 6 | 3 | _quick win_ | ✅ SHIPPED | Live FHIR injection from HL7-derived values, but bounded by pinned-host/GET/read-only; the encoding fix is localized to fhir.py plus docs. **SHIPPED 2026-07-12: (1) `fhir_lookup` value-encoding closed via the safe `params=` form (#870); (2) the pre-ingest file scan-hook is an enforced fail-closed precondition on local + remote sources (a scanner malfunction also never emits) — no ICAP client bundled, contract documented; (3) the SMART `private_key_jwt` enforcement trust boundary (AS's responsibility) documented in SECURITY.md.** |
| 21 | **#101** | `[cluster]` leader preference / non-promotable standby (P2) | 6 | 4 | _quick win_ | DEMAND-GATE | Warm-DR enabler; cold DR is a safe but awkward fallback (manual failover), and a naive warm standby silently loses leadership cross-WAN. |
| 22 | **#109** | Invalid-credential sender auto-stop (partner-account lockout protection) | 6 | 4 | _quick win_ | ✅ SHIPPED | Real partner-lockout hazard whose only workaround is a reactive manual stop. **SHIPPED 2026-07-12 (ADR 0095): a permanent auth failure is marked `credential_fault` (remotefile FTP login-refused / SFTP auth-failed → `NegativeAckError.credential_fault`); under `credential_fault_policy=stop` (default) the outbound STOPs the lane IMMEDIATELY and RETAINS the queued rows UN-ERRORED (`store.release_claimed` back to PENDING — never dead-lettered), reusing the ADR 0070/InternalErrorPolicy STOP muscle + `connection_stopped` alert, so a backlog can't re-auth-storm the partner account. `dead_letter` policy keeps the historical fail-fast; a content-permanent reject (AR/CR, no-such-dir) still dead-letters just that one message; a transient fault still retries.** |
| 23 | **#123** | Resend a stored message to an ALTERNATE connection | 6 | 4 | _quick win_ | ✅ SHIPPED | Real replay/resend gap — no operator-chosen redirect to an alternate connection. **SHIPPED 2026-07-11 (ADR 0090): API/engine + 3-backend store; console UI residual.** |
| 24 | **#143** | Alert suspend / mute (windowed) | 6 | 4 | _quick win_ | ✅ SHIPPED | **SHIPPED (banner re-verified 2026-07-28, ADR 0044 amendment):** `POST /alerts/{id}/suspend` (`api/app.py:2372`) with `suspended_until` durable on all three backends; deliberately notification-only, so a muted alert stays open and counted. |
| 25 | **#147** | Per-connection active-window scheduler | 6 | 4 | _quick win_ | ✅ SHIPPED | Real gap; the only workaround was wiring an external OS scheduler to the per-connection start/stop API. **SHIPPED 2026-07-12 (ADR 0095): a declarative pydantic `Schedule` (`config/models.py`) = a list of `ActiveWindow`s (`datetime.weekday()` day-set + local time-of-day start/end + IANA timezone, default UTC) + a maintenance `invert` flag; same-day `[start,end)`, past-midnight wrap, `start==end` rejected; `schedule=None` = always-on (byte-identical). The RegistryRunner spawns one cooperatively-cancellable scheduler task per scheduled connection that reconciles up/down state against the calendar every `schedule_tick_seconds` via the SAME `start_inbound`/`stop_inbound` (or `start_outbound`/`stop_outbound`) the API uses — a park is a clean stop (an outbound park RETAINS its queue); clock injectable (`schedule_clock`, mirrors dry-run `ingest_time`). Code-first AND connections.toml. Distinct from #115 boot-flag and the TIMER source.** |
| 26 | **#153** | Edit-and-resend a stored message | 6 | 4 | _quick win_ | ✅ SHIPPED | Corepoint operator-parity gap. **SHIPPED 2026-07-11 (ADR 0090 §9): client-side ephemeral edit + re-route-default re-ingress + direct power-path; 3-backend store + API + web console; original byte-identical, idempotent, PHI-safe.** |
| 27 | **#169** | Author-appendable per-message processing history | 6 | 4 | _quick win_ | DEMAND-GATE | Genuine Corepoint MsgAddHistory parity with no clean equivalent; the only workaround stuffs breadcrumbs into a Z-segment, polluting message content. |
| 28 | **#170** | Filterable / exportable audit report ✅ | 6 | 4 | _quick win_ | SHIPPED | **SHIPPED 2026-07-12.** `Store.list_audit` gained parameterized actor/action/since/until filters across all three backends; `GET /audit` exposes them; new `GET /audit/export?format=csv` streams a filtered, self-audited CSV report gated by a dedicated `audit:export` permission. |
| 29 | **#179** | Archive-aged-rows to separate store | 6 | 4 | _quick win_ | DEMAND-GATE | Real CIEArchive parity gap: retention is delete-only; the only workaround is whole-store .mfbak snapshots or disabling purge—awkward, not clean. |
| 30 | **#195** | Audit completeness: log all authorization decisions; enforce secret rotation | 6 | 4 | _quick win_ | P2 | Real audit/rotation gaps but medium, awkward workarounds exist (denials logged, manual rotate-key); rotation-enforcement is the real build cost. |
| 31 | **#66** | Non-SQL-Server database connectors — Postgres / Oracle / MySQL / generic ODBC DSN | 6 | 5 | _quick win_ | DEMAND-GATE | Mainstream Corepoint-parity DB breadth (Postgres/Oracle/MySQL/ODBC); the only workaround is hand-writing a full custom connector — awkward but real. |
| 32 | **#91** | GIL-on-vs-FT A/B harness on a real hot feed — free-threading final commit gate (P2) | 6 | 5 | _quick win_ | ⛔ DECLINED | **DECLINED 2026-07-20** on four unavailable rig inputs, and the premise is gone: engine CPU measures ~0.06–0.36 cores/shard (`PLAN-ENGINE-ATTRIBUTION.md:81`), so there is no CPU saturation for free-threading to relieve. Re-open only if a real feed approaches ADR 0053's stated transform-CPU threshold. |
| 33 | **#96** | Built-in "setup tester" — self-service capacity estimator that benchmarks the deployed setup and reports how much traffic it can handle (P2, adopter-facing) | 6 | 5 | _quick win_ | DEMAND-GATE | Adopter capacity self-test; the manual dev-harness workaround is awkward; net-new is a ramp-to-knee estimator plus backend-aware diagnosis. |
| 34 | **#129** | Granular 'Allow Expired Certificate' TLS relaxation | 6 | 5 | _quick win_ | DEMAND-GATE | Only workaround is the blunt tls_verify=false, which also drops chain+hostname — awkward but real (v6); custom expiry-only verify across ~5 TLS connectors (d5). |
| 35 | **#141** | TCP connection role selectable independently of direction (act-as-server vs act-as-client) | 6 | 5 | _quick win_ | DEMAND-GATE | Firewall role-inversion gap; no knob, but an external TCP relay (socat/stunnel) inverts direction — awkward-yet-real workaround → 6. |
| 36 | **#180** | Cross-backend store migration tool | 6 | 5 | _quick win_ | DEMAND-GATE | Real gap; only workaround (drain-before-cutover) discards retained history/audit — awkward not clean; offline cross-backend re-encrypting row copy. |
| 37 | **#68** | Dynamic per-message outbound HTTP headers | 6 | 6 | _big bet_ | DEMAND-GATE | Real per-message header gap; only workaround is forking a connector. Handler-set values must ride a new outbound-row carry channel across 3 backends. |
| 38 | **#93** | Engine + database performance monitoring — engine-wide volume/connection KPI roll-up + a throughput-overload (saturation) alert (P2) | 6 | 6 | _big bet_ | ✅ SHIPPED | **SHIPPED 2026-07-12:** the two net-new slivers + DB signals — engine-wide KPI roll-up on `/status` (+ console + #75 dashboard, reusing `recent_done`); a `saturation` alert on the rising-backlog **derivative** (ADR 0014 amendment — fires on ingest>drain sustained, NOT on a bursty-but-draining lane); and DB throughput metrics (commit/body-copy counters + connection-pool saturation/acquire-wait on `/metrics`). The rest cross-links already-shipped #21/#56/#74/#75. |
| 39 | **#99** | AD/gMSA production-deployment hardening — turnkey enterprise (Windows/AD) install (P3, on-trigger) | 6 | 6 | _big bet_ | DEMAND-GATE | **AMENDED 2026-07-28 — no longer a 6/6 build.** (g) shipped via #274/ADR 0142 (`oidc_require_mfa_claim`, `settings.py:1854`); (b) closed via #224; (c) is a documented stdlib scope-out. **Only (e) remains and it is PROVISIONING, not code** (a real DC + AD CS + gMSA), gated behind #275 — no engineering capacity closes it. |
| 40 | **#142** | 'Leave source file' - process-in-place file/FTP source disposition | 6 | 6 | _big bet_ | ✅ SHIPPED | **SHIPPED (banner re-verified 2026-07-28, ADR 0129):** `after_read='leave'` (`transports/file.py:298-302`) over the `ProcessedFileLedger` / `processed_files` dedup ledger on all three backends — the very ledger this row called missing. |
| 41 | **#150** | User-writable per-message metadata bag | 6 | 6 | _big bet_ | P2 | Trigger fired by the committed Corepoint cutover and SetState is no equivalent (not a per-message bag); spans pipeline, store, API and console. |
| 42 | **#198** | In-use memory protection: zeroization, mlock, and the unwrapped-DEK residual | 6 | 6 | _big bet_ | ✅ CLOSED (accept) | **CLOSED 2026-07-13 (partial-accept):** code-feasible half BUILT (best-effort `mlock`/`memset`-zeroize of every code-owned mutable key/plaintext buffer, `store/crypto.py`, `mfenc:v1` byte-identical); residual (immutable `str`/`bytes` + OpenSSL copy) + 11.7.1 full in-use memory encryption accepted as a documented deployment requirement + signed risk-acceptance (register theme 5). Scorecard verdicts unchanged (accept, not full close). |
| 43 | **#200** | Transport enforcement: make the code refuse the insecure hop | 6 | 6 | _big bet_ | P2 | Real off-loopback gap across 8 cells with no fail-closed, but medium/Posture-B; cross-cutting via mTLS-identity plus cert-auth intra-service auth. |
| 44 | **#190** | PHI data-plane integrity defaults: JWS signing, GCM rekey counter, keyed audit chain | 6 | 7 | _big bet_ | P2 | Removes real audit-forgery and GCM-nonce integrity blind spots; cross-cutting crypto plus keying the persisted audit chain across three store backends. |
| 45 | **#94** | External BLOB-server offload for embedded documents — replace inline base64 with a stored-object pointer (OBX-5 RP) (P2, on-trigger) | 6 | 5–6 | _big bet_ | DEMAND-GATE | **RE-PRICED 2026-07-28 (difficulty 8 → 5–6; row left in its original position, so ordering here is stale by one slot).** Still the strongest store-bloat lever, but ADR 0105/#149 shipped the substrate and **reserved the deref seam** (`parsing/binary.py:55-62`, `:252`), so the remainder sits behind an existing seam. Still ADR-first, still demand-gated. |
| 46 | **#149** | Streaming path for very-large single messages | 6 | 9 | _big bet_ | ✅ SHIPPED | **COMPLETE 2026-07-13 (ADR 0105):** all phases shipped — substrate + ingress detach + delivery re-attach + retention decref + SS/PG parity + operator read/download surface, all three backends. Lifted the 16 MiB engine ceiling for monolithic bodies #94/split can't decompose. |
| 47 | **#114** | Directory validation toggle (perform vs suppress startup validation) | 5 | 2 | _fill-in_ | DEMAND-GATE | **PARTIAL (2026-07-28 sweep):** the INBOUND half is BUILT; the outbound half has no hook at all, and `File(validate_directory=True)` on an outbound is silently accepted-and-ignored with no `WiringError`. Corepoint-parity File toggle to fail-fast on an invalid startup directory; clean workaround via the on-demand test probe plus existing run-time deferral. |
| 48 | **#120** | Application log-file retention (auto-delete after N days) | 5 | 2 | _fill-in_ | DEMAND-GATE | Real gap: NSSM rotates by size but never deletes old log files, so disk grows unbounded; external log rotation is a clean workaround; additive sweep. |
| 49 | **#132** | Fixed 'now' test-time override (frozen clock for reproducible transform tests) | 5 | 2 | _fill-in_ | DEMAND-GATE | Corepoint-parity frozen-clock aid for reproducible dry-run testing; route_message already accepts ingest_time, only a CLI --now flag is missing. |
| 50 | **#146** | Per-rule alert recipients | 5 | 2 | _fill-in_ | ✅ SHIPPED | **SHIPPED (2026-07-28 sweep, ADR 0014 amendment):** per-rule `recipients` re-targeting the email transport, fail-closed on blanks. Email-only; addresses are never read back through the API. Corepoint-parity alert routing with a clean global-email_to workaround; small additive recipients field on the pure-data AlertRule. |
| 51 | **#177** | Effective-permission inspector for a user | 5 | 2 | _fill-in_ | 🚧 PARTIAL | ⚠️ **CORRECTED 2026-07-28 — this row previously read SHIPPED, which is wrong.** The API half only: `GET /users/{id}/permissions` resolves the FLATTENED effective permission set (built-in-role ∪ custom-role ∪ extras) for an arbitrary user via the same `Identity.build` path `/auth/me` uses (`AuthService.identity_for_user_id`, reusing `_build_identity` — no re-derived union); deny-by-default behind `USERS_READ` like `/users`, unknown id 404s. Typed `UserPermissions` response carries user id/username, sorted flattened permissions, and the held role ids (built-in + `custom:`) for troubleshooting. API-only (no console/webconsole route → no golden drift). |
| 52 | **#89** | hl7apy security hardening — dormant-upstream contingency + fuzz the strict-validate path (P2/P3) | 5 | 3 | _fill-in_ | P2 | Bounded DoS on the opt-in strict path, no shipping-default Fail; work is a fork-on-CVE doc plus reusing the existing fuzz harness and a caps check. |
| 53 | **#112** | Outbound forward web-proxy address ('Use Default Web Proxy') | 5 | 3 | _fill-in_ | ✅ SHIPPED | **SHIPPED (2026-07-28 sweep, ADR 0126):** `"default"` sentinel = the OS/environment proxy. `FhirLookup()` has no per-lookup proxy kwarg (ADR-scoped out). Corepoint egress-proxy parity; process-wide HTTP_PROXY already covers the common all-egress case cleanly, and adding a per-connection ProxyHandler setting is small. |
| 54 | **#124** | Batch-export message bodies from a connection log to a file | 5 | 3 | _fill-in_ | DEMAND-GATE | **PARTIAL (2026-07-28 sweep):** the API half is BUILT (`GET /messages/export`, step-up + audit, ADR 0131); the console half is DEAD CODE — its JS binds an attribute no page emits and fetches a route that does not exist. Corepoint-parity bulk export; the search plus per-message audited raw API is a real, scriptable workaround, so useful breadth, not a blocker. |
| 55 | **#158** | Per-message dynamic FTP host/path/credentials | 5 | 3 | _fill-in_ | DEMAND-GATE | Dynamic-FTP-destination parity gap (FTP analog of #68); a config fan-out to per-host/per-folder RemoteFile connections covers the common case. |
| 56 | **#160** | Timer-source cron / calendar schedule | 5 | 3 | _fill-in_ | ✅ SHIPPED | **SHIPPED (2026-07-28 sweep, ADR 0011 amendment):** pure stdlib 5-field cron evaluator incl. the Vixie OR rule. `croniter` was REJECTED, not added — no dep to look for. Corepoint scheduling parity with a clean code-first time-filter workaround; only a cron next-fire calc plus a dep and tests remain. |
| 57 | **#172** | Gzip/zip compression codec + file-connector option | 5 | 3 | _fill-in_ | DEMAND-GATE | **PARTIAL (2026-07-28 sweep):** the pure codec + the connector's gzip option are BUILT (ADR 0123); ZIP is foreclosed at three layers and REMOTEFILE has no compression at all. Corepoint file-feed parity (gzip/zip in/out) with a clean code-first workaround: a Handler already calls stdlib gzip/zipfile against RawMessage. |
| 58 | **#189** | Validation + dual-control defaults | 5 | 3 | _fill-in_ | P2 | Approvals maker-checker already exists as a flip and part is a documented-deviation decision against core parsing design; a config default flip plus tests. |
| 59 | **#193** | Anti-automation: human-timing / minimum-inter-submission pacing floor | 5 | 3 | _fill-in_ | P2 | Genuine Posture-A Fail but one medium cell on admin writes already behind auth/RBAC, owner leans decline; a build reuses the 2.4.1 rate-limiter seam. |
| 60 | **#203** | Delegated identity + admin device posture: enforce or state the precondition | 5 | 3 | _fill-in_ | P2 | Enterprise identity gaps the org largely owns; owner-decision, medium, closable by docs or a start-time precondition check through config. |
| 61 | **#81** | Alert escalation tiers + day/time thresholds + content (Action-Point) alerting | 5 | 4 | _fill-in_ | DEMAND-GATE | **PARTIAL (2026-07-28 sweep):** escalation tiers + schedule-aware thresholds are BUILT across 3 backends (ADR 0133); the remainder is content (Action-Point) alerting, which has NO reachable trigger. Do not rebuild the built halves. Corepoint alert-parity; clean external-notifier / code-first-Handler workaround; remainder = escalation-state + schedule config across 3 backends. |
| 62 | **#127** | Web-proxy credential types (Basic / Digest / NTLM / Windows) | 5 | 4 | _fill-in_ | DEMAND-GATE | 'New dep' for D5 is false: pyspnego (NTLM/SSPI/Negotiate) already core dep+locked. No re-lock -> D4. Value 5 stands (env-var/cntlm workarounds, parity). |
| 63 | **#162** | Unmapped-value policy on code-set lookups ✅ | 5 | 4 | _fill-in_ | SHIPPED | **SHIPPED 2026-07-11.** Declared per-set miss policy (default/passthrough/flag) applied by `code_set().translate()`, re-run-safe PHI-aware capture of unmapped inputs, policy shown in the grid; ADR 0033 amended. |
| 64 | **#85** | Cloud object-store + generic message-bus destinations | 5 | 5 | _fill-in_ | DEMAND-GATE | Corepoint-parity breadth: new cloud object-store + generic-bus outbound connectors; the pluggable transport registry is a code-first workaround. |
| 65 | **#111** | File-endpoint alternate Windows / network-share credentials | 5 | 5 | _fill-in_ | ✅ SHIPPED | **SHIPPED (2026-07-28 sweep, ADR 0132):** per-endpoint alternate Windows credential via ctypes `LogonUser`, no pywin32. The live win32 path is not exercised in CI. Corepoint-parity File UNC alt-identity gap; granting the engine service account share access is a clean workaround for most deployments, coarse only for per-endpoint isolation. |
| 66 | **#125** | Uploaded Logs page - import external message files and browse them offline | 5 | 5 | _fill-in_ | DEMAND-GATE | **PARTIAL (2026-07-28 sweep):** page/upload/browse/resend/delete/quota/retention all BUILT (ADR 0134); the remainder is the Scope's "SAVE" — there is no download route and browse is metadata-only by construction. Corepoint-parity offline file viewer; dryrun and File()->store->browser cover the inspect need cleanly, so it is console breadth not a blocker. |
| 67 | **#151** | Saved / layered Log-Search filter presets | 5 | 5 | _fill-in_ | ✅ SHIPPED | **SHIPPED (2026-07-28 sweep, ADR 0136):** saved presets + bounded AND-compose (≤ 8 layers, exactly one content predicate). Not free boolean composition. Corepoint parity for saved/layered log searches; ad-hoc filters work so workaround is clean; build spans new per-user store, API and console. |
| 68 | **#165** | DB schema browser + ad-hoc query runner | 5 | 5 | _fill-in_ | DEMAND-GATE | External SQL client is a clean workaround; still a useful Corepoint-parity authoring aid spanning API, console, and per-backend introspection. |
| 69 | **#78** | Custom message-definition data model + conformance validator; NCPDP codec | 5 | 6 | _money pit_ | DEMAND-GATE | Corepoint-parity definition model + report-only validator + a new NCPDP codec class; clean code-first-Handler workaround keeps it at useful breadth. |
| 70 | **#95** | Engine-brokered AI assistance — integrate the IDE coding assistant with a customer's managed AI subscription or in-house LLM instance (P3, on-trigger) | 5 | 6 | _money pit_ | DEMAND-GATE | **PARTIAL (2026-07-28 sweep):** the engine broker + per-use audit + IDE flip are BUILT (ADR 0135); the remainder is the generic customer-endpoint mode — `provider` is accepted but never read, so non-Anthropic backends fail as opaque 502s. BYO vscode.lm cleanly covers the mainstream case; the broker adds real but narrow central per-use AI-egress audit and in-house-only-LLM support. |
| 71 | **#196** | Hardware-backed secrets custody (HSM/KMS/Vault) | 5 | 6 | _money pit_ | P2 | Single 13.3.1 cell with an env+DPAPI residual workaround; promoting the design-stub key_provider to a real external integration adds a dep and a cross-cutting seam. |
| 72 | **#62** | Binary body carriage — store ciphertext / raw bodies as `VARBINARY`/`BLOB`/`bytea` instead of base64-in-`NVARCHAR` (storage efficiency) (P3, measure-gated) | 5 | 7 | _money pit_ | DEMAND-GATE | Corepoint-class storage win (~60% on SQL Server), clean bigger-disk workaround; format change needing an ADR + dual-read migration on three backends. |
| 73 | **#130** | Message queues shared by name across connections + shared-name delete protection | 5 | 8 | _money pit_ | DEMAND-GATE | Parity breadth; per-connection staged queue + graph wiring is a clean workaround (v5); new shared-queue seam + per-lane FIFO across 3 backends (d8). |
| 74 | **#197** | Runtime sandbox for admin-authored Router/Handler code | 5 | 8 | _money pit_ | P2 | Nonexistent control but P3, high-blast/low-likelihood over admin code the code-first model already trusts; a new hard-isolation runtime seam is multi-week work. |
| 75 | **#3** | Per-key (partition-key) message ordering (long-term, nice-to-have) | 5 | 9 | _money pit_ | DEMAND-GATE | Scales one ordered feed past a core; FIFO already correct and feeds split, so a workaround exists; multi-week build behind the strict-FIFO gate. |
| 76 | **#48** | IDE "Insert Element" — grow the scaffold-snippet library + a most-used-idiom quick-pick (P2) | 4 | 2 | _fill-in_ | ✅ SHIPPED | **SHIPPED (banner re-verified 2026-07-28):** base (#595) + L1 (#794) both on main — 36 idiom snippets in `ide/snippets/messagefoundry.code-snippets`, with `buildPicks`/`detectContext` in `ide/src/insertElement.ts` reading the same file. The row already said *"done"*; the banner now agrees. |
| 77 | **#84** | Diagnostic panes — hex body view + HL7-aware before/after diff + profiling/coverage | 4 | 2 | _fill-in_ | DEMAND-GATE | Client-side hex pane for binary/mfb64 bodies — DX/console polish, nobody blocked; not interop, and no existing view renders raw bytes. |
| 78 | **#137** | Configurable server display name in the operator console | 4 | 2 | _fill-in_ | DEMAND-GATE | Console-title polish so operators can tell multiple instances apart at a glance; purely cosmetic DX, nobody is blocked from operating. |
| 79 | **#161** | Code-set editor in-grid row search | 4 | 2 | _fill-in_ | DEMAND-GATE | Console/IDE polish — a search box on the existing code-set grid; nobody blocked (scroll or edit the raw set file), no interop dimension. |
| 80 | **#164** | Console dark-mode / theming | 4 | 2 | _fill-in_ | DEMAND-GATE | Console theming polish behind the existing active_tokens() seam; no native dark-console option today, but nobody is blocked. |
| 81 | **#167** | Test Bench metadata seeding | 4 | 2 | _fill-in_ | DEMAND-GATE | IDE Test Bench DX input to seed per-message metadata for transform tests; no such seam exists today, but nobody is blocked — small dry_run + Test Bench add. |
| 82 | **#175** | Clone-a-connection editor action | 4 | 2 | _fill-in_ | DEMAND-GATE | IDE clone action saves retyping near-identical feeds, but a clean copy-the-TOML-block workaround exists and nobody's blocked; pure editor polish. |
| 83 | **#45** | Per-store TLS CA-file knob for server-DB backends (trust a private DB CA without a machine-wide install) — on-trigger | 4 | 3 | _fill-in_ | DEMAND-GATE | Postgres half shipped (settings.py:288); SQL Server slice needs real ODBC-18.1 ServerCertificate verification on the SS CI leg (cert-pin, not CA) — remainder is D3 not D2. |
| 84 | **#76** | Historical-metrics charting + status-colored data-flow graph | 4 | 3 | _fill-in_ | ✅ SHIPPED | **SHIPPED — first slice (2026-07-28 sweep, ADR 0065 amendment):** `GET /metrics/history` + `GET /graph/edges`. ⚠️ History is in-memory, process-local, and accrues only while a dashboard is open. Cosmetic console charts plus a by-name status-colored flow graph over metrics that already show point-in-time; nobody is blocked. |
| 85 | **#131** | Object flagging - mark objects of interest + a Flagged Objects filter | 4 | 3 | _fill-in_ | DEMAND-GATE | DX/console-polish flag+filter; not interop, nobody blocked, no existing marker covers it (v4); model field + render/filter in both consoles (d3). |
| 86 | **#133** | User-chosen display colour on configuration objects | 4 | 3 | _fill-in_ | DEMAND-GATE | Cosmetic per-object display colour; genuine console/IDE polish, nobody blocked; a display field threaded config model to API to console. |
| 87 | **#138** | Customisable alert-email subject and body templates | 4 | 3 | _fill-in_ | ✅ SHIPPED | **SHIPPED (2026-07-28 sweep, ADR 0127):** operator-editable subject/body over a CLOSED non-PHI variable allowlist. Message-derived variables are excluded BY REQUIREMENT, not missing. Nobody-blocked alert-email cosmetics; fixed PHI-free subject already carries severity/type/connection. Diff 3: settings + allowlist-gate tests. |
| 88 | **#171** | Runtime log-verbosity control + in-product log viewer | 4 | 3 | _fill-in_ | DEMAND-GATE | Ops/console polish: runtime log level plus a viewer over the already-produced redacted tail; the config dial (restart) and support-bundle pulls work, nobody blocked. |
| 89 | **#176** | Unused-object (dead-config) detection | 4 | 3 | _fill-in_ | DEMAND-GATE | DX aid surfacing dead config; nobody blocked, no partner/format dimension so not interop (v4). Reverse-reachability needs AST analysis of router/handler bodies + tests (d3). |
| 90 | **#168** | Test Bench saved regression collections | 4 | 4 | _fill-in_ | ✅ SHIPPED | **SHIPPED (2026-07-28 sweep, ADR 0121):** persisted named collections + HL7-aware compare reusing `hl7diff`. ⚠️ Adds a NEW PHI-at-rest surface (plaintext VS Code workspace storage). IDE Test Bench regression tooling; manual re-load+eyeball diff validates today so nobody's blocked; a sizable but self-contained TypeScript feature. |
| 91 | **#152** | Reverse-dependency / impact analysis | 4 | 5 | _fill-in_ | DEMAND-GATE | DX rename-safety tooling: a string-literal reverse index plus a check/IDE rename pre-flight that safely rewrites referents; grep is the workaround. |
| 92 | **#103** | Retire the PySide6 desktop console in favor of the web console (P3, owner decision) | 4 | 6 | _money pit_ | ✅ SHIPPED | Desktop console removed (2026-07-13): `console/` deleted, Qt widgets rehomed to `harness/`, `[console]`→`[harness]` extra, ADR 0032 RETIRED; the web console `/ui` is the sole operator UI. |
| 93 | **#166** | Server-side per-user console preferences | 4 | 6 | _money pit_ | DEMAND-GATE | DX/console polish, nobody blocked; per-machine QSettings is a clean workaround. Store-backed per-user surface spans store, API, auth, and console. |
| 94 | **#108** | Receiver-side 'Prefer BOM if present' encoding auto-detect | 3 | 2 | _fill-in_ | DEMAND-GATE | Encoding setting cleanly covers single-encoding feeds; only the niche mixed-BOM auto-detect override remains, a small decode-path sniff. |
| 95 | **#148** | X12 TA1 interchange-acknowledgement generation | 3 | 2 | _fill-in_ | DEMAND-GATE | Niche X12 knob most partners never need — 997/999 already covers the common ack free — and a code-first Handler can emit TA1 on the existing codec. |
| 96 | **#178** | SFTP cipher / KEX / MAC allow-lists | 3 | 2 | _fill-in_ | DEMAND-GATE | Niche interop knob a FIPS-restricted SFTP partner needs; paramiko disabled_algorithms plumbed into the one existing sftp client seam + tests. |
| 97 | **#184** | Serve own endpoint WSDL | 3 | 2 | _fill-in_ | DEMAND-GATE | Niche SOAP interop knob most partners never need; out-of-band WSDL is a clean workaround; small GET ?wsdl branch on the built HTTP listener. |
| 98 | **#67** | Stored-procedure OUT-param / return-value binding | 3 | 3 | _fill-in_ | ✅ SHIPPED | **SHIPPED (2026-07-28 sweep, ADR 0013 amendment):** `capture_out_params` on the DATABASE outbound, captured pre-commit inside `send()`. ⚠️ Readback-SELECT, NOT native OUT-param binding; a real defect on the `{ ? = CALL }` shape is disclosed in the banner. Niche DB stored-proc OUT/return knob; RETURNING/OUTPUT covers the common case and a SELECT-wrapper statement is a clean workaround. |
| 99 | **#83** | Rich file-output disposition + FTPS / SFTP variants | 3 | 3 | _fill-in_ | DEMAND-GATE | Niche file/FTP interop (implicit-FTPS, SFTP-KBI, append/archive/framing) most partners never need; per-driver additive on two connectors. |
| 100 | **#97** | Keep-alive / persistent outbound connections — per-connector setting (P3, on-trigger) | 3 | 3 | _fill-in_ | ✅ SHIPPED | **SHIPPED — merged 2026-07-24 (PR #1220):** the residual landed. `persistent` on `transports/tcp.py:124` + `x12.py:94`, with ADR 0067 §8 checked off and a §9 amendment fixing the reconnect model. |
| 101 | **#98** | Kerberos SSO channel-binding (EPA) opt-in + acceptor-enforcement spike (P3, on-trigger) | 3 | 3 | _fill-in_ | DEMAND-GATE | Narrow EPA channel-binding hardening for the opt-in in-process-TLS SSO mode; distinct from the proxy posture but nobody's blocked and it's largely a spike. |
| 102 | **#107** | Override HL7 v2 escape sequences | 3 | 3 | _fill-in_ | ✅ SHIPPED | Per-outbound `hl7_raw_separators` escape-hatch (default OFF) emits reserved structural separators as raw bytes for a partner that can't decode HL7 escapes; MSH-derived, model-based, byte-identical when off. |
| 103 | **#113** | Outbound source-IP binding for sender connections | 3 | 3 | _fill-in_ | DEMAND-GATE | Niche interop knob a source-IP-allowlisting partner needs on a multi-homed host; OS policy routing usually selects egress, so value stays modest. |
| 104 | **#117** | Sender no-wait-for-ACK (fire-and-forward) option | 3 | 3 | _fill-in_ | ✅ SHIPPED | **SHIPPED — merged 2026-07-24 (PR #1220):** `no_ack` on `transports/mllp.py:620`; **ADR 0124 is on main** (`docs/adr/README.md:151`), and the #117×#82 conflict is a `WiringError` at `config/wiring.py:3388-3405`, not just documentation. |
| 105 | **#159** | TCP stream-until-close (no-framing) mode | 3 | 3 | _fill-in_ | DEMAND-GATE | Niche TCP interop knob for connection-close framing the delimiter codec can't express; new framing=none path spans Tcp source, destination, and codec. |
| 106 | **#163** | Static-string inbound ACK | 3 | 3 | _fill-in_ | DEMAND-GATE | Niche legacy canned-ACK interop knob most partners never need; a static ack_mode + literal field through config into MLLP build_ack, plus tests. |
| 107 | **#181** | Multipart/form-data outbound encoder | 3 | 3 | _fill-in_ | DEMAND-GATE | Niche multipart upload; a hand-built Handler body covers partners; boundary encoder + per-request Content-Type across str-typed REST/SOAP send. |
| 108 | **#183** | SOAP MTOM/XOP binary packaging | 3 | 3 | _fill-in_ | DEMAND-GATE | Niche IHE MTOM/XOP packaging format most SOAP partners never need; base64-inline serves accepting partners; spec-fiddly XOP confined to one connector. |
| 109 | **#63** | `message_events` verbosity knob — operator dial to suppress routine lifecycle events (store-size / observability) (P3) | 3 | 4 | _fill-in_ | P3 | Niche store-size knob, pruning workaround; but threading a policy through three backend _event()s + inline INSERTs via open_store is a cross-backend feature (d4). |
| 110 | **#110** | DICOM Study/Series Instance UID de-duplication on the C-STORE SCP | 3 | 4 | _fill-in_ | DEMAND-GATE | Niche DICOM-only C-STORE de-dup most partners never need; the SR→HL7 case can already filter to SR objects code-first. |
| 111 | **#182** | Per-message base-address override for web-service senders | 3 | 4 | _fill-in_ | DEMAND-GATE | Niche interop knob with a clean one-connection-per-address workaround; an override through 3 HTTP clients needs a delivery-time SSRF re-check (d4). |
| 112 | **#69** | WSDL import — SOAP type-tree + validate-against-WSDL | 3 | 5 | _fill-in_ | ✅ SHIPPED | **SHIPPED (2026-07-28 sweep, ADR 0122):** pure WSDL 1.1 type-tree + validate-against-embedded-XSD at `parsing/xml/wsdl.py`, no `zeep`, no new dep. Does NOT close #70 or #184. Niche SOAP interop knob: WSDL type-tree + envelope validation, but envelopes are hand-buildable in a code-first Handler today — a clean workaround exists. |
| 113 | **#157** | Direct Project / HIE secure-messaging connector | 3 | 7 | _money pit_ | ⛔ DECLINED | **DECLINED — owner 2026-07-24.** Zero live feed; the HISP + XDR remainder is not worth carrying. ⚠️ **Not a removal instruction: do NOT delete `messagefoundry/transports/direct.py` — the outbound S/MIME half (ADR 0085) ships and stays.** |
| 114 | **#155** | Server-to-server migration runbook | 2 | 1 | _fill-in_ | DEMAND-GATE | Pure-docs runbook consolidating already-built, separately-documented steps; existing docs substantially cover it, so a modest single doc edit. |
| 115 | **#191** | SMART/OAuth outbound: exercise the built path, or scope it out | 2 | 1 | _fill-in_ | P3 | Pure scoping decision that flips five ASVS Partials to Pass with zero code since transports/smart.py is already correct; an owner call, not a build. |
| 116 | **#205** | Documented risk acceptances (ASVS L3 residuals) | 2 | 1 | _fill-in_ | P3 | Ships nothing runnable — a signed risk-acceptance record; residuals stay Partial/Fail after sign-off; cheap doc-only work, no code. |
| 117 | **#72** | Self-signed / dev certificate generation | 2 | 2 | _fill-in_ | ✅ SHIPPED | **SHIPPED as CLI (2026-07-28 sweep):** `messagefoundry cert self-signed` → EC P-256 dev cert, key `0o600`, NON-PROD only. No console button. openssl already mints throwaway dev certs, so an existing mechanism substantially covers this; the build is a tiny additive CLI helper. |
| 118 | **#73** | Explicit FIPS-mode attestation | 2 | 2 | _fill-in_ | ✅ SHIPPED | **SHIPPED (2026-07-28 sweep, ADR 0120):** `fips_attestation()` on the security posture — report-only by design, and it attests the interpreter's OpenSSL, NOT the at-rest `cryptography` backend. Marginal convenience: MeFor owns none of the crypto — the OS OpenSSL FIPS provider already attests FIPS mode, so surfacing it duplicates an existing mechanism. |
| 119 | **#116** | File-size integrity re-check before disposition | 2 | 2 | _fill-in_ | DEMAND-GATE | min_age_seconds quiescence window plus single-shot whole-file read already guard partial writes; a size re-stat is a marginal additive hardening. |
| 120 | **#128** | Bypass the forward proxy for local (intranet) requests | 2 | 2 | _fill-in_ | ✅ SHIPPED | **SHIPPED (2026-07-28 sweep, ADR 0126):** NO_PROXY-style per-connection bypass list, IPv6-safe. Evaluated per fixed destination host at construction, not per request. A per-connection proxy-bypass host list; the common case is already met by not configuring a proxy on intranet-only connectors, so it adds marginal convenience only. |
| 121 | **#135** | Configurable statistics push / refresh interval | 2 | 2 | _fill-in_ | DEMAND-GATE | Marginal tuning knob over the fixed 1s /ws/stats cadence; no interop dimension, and the existing cadence already serves live monitoring fine. |
| 122 | **#173** | Segment/segment-group subtree-copy helper | 2 | 2 | _fill-in_ | DEMAND-GATE | One-call sugar over the shipped segments()/groups()/add_segment API; a Handler author can already copy subtrees by hand. |
| 123 | **#174** | Scheduled automatic statistics reset | 2 | 2 | _fill-in_ | DEMAND-GATE | Manual re-snapshot ships (POST /statistics/reset + console) and OTel covers daily volume; only an auto-timer reusing reset_stats is left. |
| 124 | **#71** | PKCS#12 / .pfx cert import + read-only cert inventory | 2 | 3 | _fill-in_ | ✅ SHIPPED | **SHIPPED as CLI (2026-07-28 sweep):** `messagefoundry cert import` + `cert inventory` over `pki.py`. No console page; SOAP mTLS certs are missed by auto-enumeration (banner). openssl already converts .pfx to the PEM the loaders read, so value is marginal; in-dep cryptography loader plus a small read-only inventory view. |
| 125 | **#119** | Nightly automatic application-log compression | 2 | 3 | _fill-in_ | ✅ SHIPPED | **SHIPPED (2026-07-28 sweep, ADR 0137 amendment):** in-place gzip of aged app-log files, free-space-prechecked, fail-closed. ⚠️ Runs on the retention cadence, NOT an off-peak nightly pin. NSSM size rotation already bounds log-file disk and a scheduled OS-level compress task is a clean workaround; only a self-contained maintenance runner is new. |
| 126 | **#121** | Maximum log-maintenance task duration cap | 2 | 3 | _fill-in_ | ✅ SHIPPED | **SHIPPED — mechanism (2026-07-28 sweep, ADR 0137):** latching between-phase deadline gating every retention phase. ⚠️ Ships OFF (`0.0`), not the "four hours" the item asked for; the cap is soft. Off-peak vacuum_at plus purge cadence already blunt the overrun risk, and VACUUM isn't cleanly interruptible mid-pass, so a hard cap adds little. |
| 127 | **#126** | Delete an uploaded data file from the server | 2 | 3 | _fill-in_ | ✅ SHIPPED | **SHIPPED (2026-07-28 sweep, ADR 0134):** `DELETE /uploads/{file_id}`, step-up + audit. Bounded to #125-uploaded files, not arbitrary server files. Marginal operator file-cleanup that OS-level delete + after_read/retention already cover; guarded delete API + console UI + audit is a small build. |
| 128 | **#156** | Alert hysteresis (separate fire/clear thresholds) | 2 | 3 | _fill-in_ | DEMAND-GATE | Minor anti-flap refinement; shipped realert/cooldown throttle already dampens flapping; no interop dimension; deadband adds fields plus edge-tracking. |
| 129 | **#136** | 'Waiting for Reply' per-message connection state + display delay | 2 | 4 | _fill-in_ | ✅ SHIPPED | **SHIPPED (2026-07-28 sweep, ADR 0065 amendment):** display-only waiting marker + pre-display delay on BOTH MLLP send paths. MLLP-only by construction. Cosmetic per-message waiting-for-reply state (ACK already awaited; connection health/counts already surfaced), spanning transport, API and console. |
| 130 | **#122** | Corrupted application-log detection, rollover, and connection-stop | 2 | 5 | _fill-in_ | DEMAND-GATE | Stdout+NSSM and #50 disk metering substantially cover log durability/visibility; the added file-log lifecycle is marginal and non-interop. |
| 131 | **#105** | Deterministic Corepoint-import tooling — Action-List → code-first scaffold (P3, deferred, owner decision) | 2 | 6 | _money pit_ | P3 | **AMENDED 2026-07-28.** The *"input schema SYNTHETIC-until-validated"* blocker is discharged (ADR 0086 Amendment §2(a′): validated XML via `defusedxml`, `corepoint_import.py:81`). ⚠️ **Not a green light** — the real gate is **#313**, which is invisible from this baseline (it ends at #231). Still P3, still demand-gated. |
| 132 | **#87** | Competitive intelligence — study the closest code-first scripted commercial engine (non-code, recon) | 1 | 1 | _fill-in_ | ⛔ DECLINED | **DECLINED — owner 2026-07-24.** Non-code recon that ships nothing runnable and blocks nobody; positioning is owner work, not tracked engineering scope. |
| 133 | **#185** | ASVS 5.0 Level-3 re-score — 67 open findings (tracking index) | 1 | 1 | _fill-in_ | ✅ CLOSED | **CLOSED 2026-07-28 — SUPERSEDED** by the ADR 0115 re-partition into #242–#246. An index-only umbrella owning no findings; once its contents move, it has nothing left to index. ⚠️ **Not a claim that ASVS is done** — the programme continued past this baseline and `docs/security/` is gitignored post-cutover. |
| 134 | **#64** | Throughput parity with Corepoint — measure-first performance roadmap (group-commit + lean-writes, gated on the enterprise-box validation) (P2, owner / measure-gated) | 1 | 2 | _fill-in_ | DEMAND-GATE | Index-only roadmap umbrella; its throughput levers (#62/#63/#47/#34, group-commit) are separate items, so it ships nothing runnable. |

*(Per-item banners under each `##` entry carry the same numbers. The status banner — ✅ / ⛔ / 🪦 / 🔢 /
🚧 — remains the source of truth for **build state**; this table ranks only what is still open. This is the **2026-07-10 re-score snapshot of #1–#205**; items filed since are ranked in the addendum immediately below, and shipped items keep their ✅ banner as the source of truth.)*

### Post-re-score additions — #206–#222 (scored 2026-07-10)

> Filed *after* the main table: the throughput/harness cluster **#206–#220** (#860) and the IDE low-code
> pair **#221–#222** (#865). #206–#220 were scored by the same evidence-based pass — every code claim
> fact-checked against the harness/engine (which flipped **#206 → ✅ shipped**, already merged in #861,
> and confirmed **#217**'s group-commit lever measures ~0 payoff per ADR 0069). #221–#222 carry the
> scores set when they were filed. Same 1–10 scale and tier rule as the main table; #206 (shipped) is out.

| # | Item | V | D | Quadrant | Tier | Why |
|---|---|--:|--:|---|---|---|
| **#219** | Harness-invariant property test + cross-observer INCONCLUSIVE guard ✅ | 7 | 3 | _quick win_ | ✅ BUILT | Structural CI guard codifying the anti-fabrication invariant that stops the B-class harness bug from recurring in any future throughput gate. **BUILT 2026-07-10** (A4a property test + A4b `observers_inconclusive`). |
| **#208** | Fix the per-PID engine CPU collector (attribution is blind without it) | 7 | 6 | _big bet_ | ✅ CLOSED | **CLOSED — shipped 2026-07-20; the residual is OFF-REPO and no in-repo change can close it.** The blocking premise is discharged: an admissible aggregate verdict bounds engine CPU at ≤ 0.36 cores/shard (`PLAN-ENGINE-ATTRIBUTION.md:81`, `:280`). Deliberately published with **no sizing figure**. |
| **#211** | Claim-mode lane-count sweep (16 → 1,500 lanes) — NOT a default flip | 7 | 6 | _big bet_ | ✅ CLOSED | **CLOSED — owner-ratified 2026-07-17, characterization-only.** The A/B ran and is published (`THROUGHPUT-STATUS-2026-07-10.md:256`, `:259`, `:664`). ⚠️ **Not a licence to flip the `claim_mode` default, and not a rig ask** — the 1,500-lane claim storm is precisely why the default stands. |
| **#215** | Shard-scaling curve N = 1, 2, 4, 8, 16 on one unified store | 7 | 6 | _big bet_ | ✅ CLOSED | **CLOSED — Phase 5 is DONE; the answer is DECLINING** (`THROUGHPUT-STATUS-2026-07-10.md:942`), per-shard ceiling `R ∈ [2, 3)` at N=8. The *"unmeasured"* framing is retracted. ⚠️ The `m7i.8xlarge` upsize it asks for is **retired** (`:1719`) — do not fund it. |
| **#216** | 1,500-connection traffic-driving harness mode (the demo shape) | 7 | 6 | _big bet_ | ✅ SHIPPED | **SHIPPED (verified 2026-07-28).** ⚠️ The *"no existing harness covers it"* premise is **retracted as false**: `harness/load/estate/` + `harness/config/estate/` + `python -m harness --estate`, with `count = 1500` in `estate-demo.toml`. ⚠️ `simple_fraction=0.72` and `hub_fanout=3` still need **OWNER SIGN-OFF**. |
| **#218** | 2-point shard probe (N=1 vs N=4) — the cheap early killer | 7 | 6 | _big bet_ | ✅ CLOSED | **CLOSED — the experiment RAN (C1, 2026-07-10) and answered DECLINING:** 11.33 → 15.42 ingress/s = **1.36× for 4× shards** (`THROUGHPUT-STATUS-2026-07-10.md:265`). Direction firm, magnitudes soft (both soaks collapsed). Re-running re-derives a published verdict. |
| **#210** | Remove the tempdb table variables from the pooled claim query | 7 | 7 | _big bet_ | ⛔ DECLINED | **DECLINED — withdrawn, owner-ratified 2026-07-17** (*"Do not build it"*, `THROUGHPUT-STATUS-2026-07-10.md:675`). ⚠️ **ADR 0114 deliberately PRESERVES the four table variables** (`store/sqlserver.py:702-717`) — they are load-bearing for per-lane FIFO. Removing them is a rejected design, not an unfinished one. |
| **#209** | Teach the ladder routed_fanout ≠ delivered (H ≠ N) | 6 | 5 | _quick win_ | ✅ SHIPPED | **SHIPPED (code) — verified 2026-07-28.** The `H = N = dests` hardwiring is gone: `dests` is topology, `handlers` is H, `delivering` is D (`shardcert_ladder.py:875-878`, `:1063-1064`), defaults byte-identical. ⚠️ The **H=20 rig run is bench time, not code** — it does not reopen this. |
| **#222** | Structured action-list lens over real Python Handlers — typed action vocabulary (ADR 0076) | 6 | 6 | _big bet_ | ✅ SHIPPED | **SHIPPED — all three phases (verified 2026-07-28):** `messagefoundry/actions.py` (15 verbs), `lens.py` + the `lens` subcommand (`__main__.py:374`), `ide/src/stepsView.ts`; ADRs 0076/0103/0106/0108. Plain `.py` stays the only artifact and execution path. |
| **#212** | fifo_claim_batch: decide the default (verification DONE 2026-07-11 — it is NOT a no-op) | 6 | 2 | _quick win_ | ✅ CLOSED | **CLOSED — owner-ratified 2026-07-17. DECIDED: it ships OFF.** `settings.py:295` already carries `default=1`, so **no code change closes it**. Priced at an upper bound of ~+4.7% against the +8% PROCEED bar (ADR 0107). Revisit only on a **latency or store-load** rationale, never a throughput one. |
| **#207** | txn/msg and bytes/msg counters in the harness | 5 | 4 | _fill-in_ | ✅ SHIPPED | **SHIPPED — closed by ADR 0141 (Accepted 2026-07-20), which names this item.** txn/msg is *measured* via `Store.committed_txns` → `txn_per_message_measured` (`harness/load/report.py:676-682`), reporting `None` rather than a fabricated 0. ⚠️ **bytes/msg stays REFUSED** — copies-per-message ships as the sizing proxy. |
| **#213** | accepts= seam (pure router-stage predicate) plus an advisory lint | 5 | 7 | _money pit_ | ✅ SHIPPED | **SHIPPED (verified 2026-07-28, ADR 0084):** `HandlerAccepts` + fail-closed `_check_accepts_predicate` (`config/wiring.py:2291`), `Registry.handler_accepts`, dry-run `_accepted` (`pipeline/dryrun.py:206`), lint at `checks.py:388`, `tests/test_accepts_seam.py` (749 ln). **Was the highest double-build risk in the set.** |
| **#214** | Intra-message concurrent transform of a message's routed rows | 5 | 8 | _money pit_ | 🚧 PARTIAL | **AMENDED 2026-07-28 — mechanism MERGED and tested** (`wiring_runner.py:4790`, `tests/test_transform_concurrency.py` 586 ln), so the *"transform sequentially today"* premise is stale. ⚠️ **Exposing `transform_concurrency` is DECLINED**: unmeasured, and inert unless `per_lane` **and** `fifo_claim_batch>1` **and** not the SQL Server fused path (`:4819`). |
| **#221** | IDE native-surface polish — walkthrough, custom editors, status bar, TOML association | 4 | 2 | _fill-in_ | ✅ SHIPPED | **SHIPPED (verified 2026-07-28, ADR 0100 Accepted):** 3 registered `customEditors` (`ide/package.json:527`), a 9-step walkthrough, `ide/src/statusBar.ts`, `ide/src/multiStepInput.ts`, TOML association. IDE chrome only — #26 untouched. |
| **#220** | CPU delta is differenced across a subtree that can change between ticks | 4 | 3 | _fill-in_ | ✅ SHIPPED | **SHIPPED (verified 2026-07-28):** `ProcSample.cpu_pids` records the summed-over PID set (`connscale/probe.py:50-70`) and `_drain_proc` sums CPU **piecewise over same-PID-set intervals**, degrading the rest to a gap (`connscale/runner.py:928-1014`; estate twin `estate/runner.py:513`). |
| **#217** | Group-commit / durable-write — sequenced AFTER the claim path | 4 | 7 | _money pit_ | ⛔ DECLINED | **DECLINED — dead by measurement three times over:** ADR 0069 (commit tier ~9% utilised) → ADR 0099 (withdrew the build) → ADR 0107 (*"Do not build F2 or F3"*, which also stamps ADR 0057 ⛔ DO NOT PROMOTE). Re-open only on new measurement contradicting ADR 0107. |

---

---

## Value & priority analysis (recorded 2026-06-19) — superseded

> ⬆️ **Superseded for scoring by the ten-level re-score above (2026-07-10).** The Med/Low values and S/M/L/XL efforts here are kept as the historical record of the 2026-06-19 evaluation. Where this table and the ranked table disagree on a number, the ranked table wins; on **build state**, the per-item ✅/⛔/🪦 banner wins.

> **Why this is here.** A multi-agent value / "good-idea" evaluation of every open item — value × strategic
> fit × cost, each verdict **adversarially challenged** against the code-first / minimal-dependency / on-prem
> identity. Recorded so the prioritization is not re-derived each cycle. **Verdicts:** `do-now` · `do-next` ·
> `on-trigger` (build only when the named trigger fires) · `defer` · `drop` · `confirm-decline` · `done`.
>
> **Headline.** The v0.2 marquee shipped, so the real job now is **closing out and ratifying, not building.**
> The worth-doing set is small and cheap; almost everything else is **speculative against zero feed demand**
> and should be **demand-gated, not scheduled.** The discipline that protects the identity is refusing to build
> transports/codecs before a real feed validates the contract.
>
> **Update (2026-06-28).** Since this 2026-06-19 snapshot, **most rows below shipped** (through `0.2.10`) — the
> per-item ✅ banners + `CHANGELOG.md` are authoritative, and the now-shipped on-trigger rows are flipped to
> **done** inline. The remaining *buildable* set is **#33 / #40 / #41** (actionable) + **#52 / #60 / #61**
> (owner-decision), planned ADRs-first in [`releases/MULTISESSION-PLAN-6.md`](releases/MULTISESSION-PLAN-6.md).
> (**#39** frozen console installer Phase B was built then **🪦 retired** on 2026-07-01 — no longer buildable-set.)

| Item | Value | Verdict | Effort | Why / trigger |
|---|---|---|---|---|
| **Meta — lock v0.2 scope** | Med | **done** | S | ✅ v0.2 shipped through `0.2.10`; #20–#27 ratified/shipped or declined; #22b Alerts page shipped (PR #420). |
| **#28 load test** | Med | **done** | S | ✅ Executed on the local test boxes (2026-06-27) — no-loss/latency result in `TUNING-BASELINE.md`. These are the **consumer-hardware floor**; the enterprise-hardware run is slated for the **#40** self-hosted box. |
| **#29 throughput test** | Med | **done** | S | ✅ Re-measured on the local test boxes + `TUNING-BASELINE.md` refreshed (2026-06-27). Consumer-hardware floor numbers; the enterprise re-measure is slated for the **#40** self-hosted box. |
| **#22b Alerts GUI page** | Med | **done** | S | ✅ Endpoint `/alerts/rules` shipped (#415); console Alerts page shipped (**PR #420**, merged 2026-06-20). Operator-parity polish, not a migration-unblocker. |
| **#33 config-UX audit** | Med | do-next | M | Right timing to audit config sprawl — but value realizes **only if** the spawned follow-ups are funded. Keep bounded to transport/service config (logic stays code-first — never drift toward #26). |
| **FEATURE-MAP refresh** | Med | do-next → **done** | S | Verified stale (Dead-Letters row); ASVS score synced to 212/0/0/133 (#425). |
| **#7 inbound HTTP listener (+ SOAP/FHIR-facade tail)** | Med | **done (first slice) / on-trigger (tail)** | XL | ✅ REST body-POST listener shipped `0.2.10` (ADR 0023, PR #624). Intake auth (ADR 0154 increment A) and the SOAP sync-reply (`reply_from`, increment B) have since shipped. **Deferred tail (on-trigger):** routing-metadata, inbound FHIR-server facade (#20) / DICOMweb receiver (#24). |
| **#16 eventlog (0021 half)** | Med | **done** | L | ✅ Shipped `0.2.3` (#541): metadata-only `connection_event` log + "Response Sent" ACK/NAK capture + console Event Log (jointly with #46). **ADR 0020 raw protocol-trace stays dropped** (raw-PHI-at-rest tier nobody named). |
| **#34 per-connection retention** | Med | **done** | M | ✅ Shipped `0.2.9` (ADR 0027): per-connection `messages_days` / `dead_letter_days` over the global default, across all 3 backends. |
| **least-priv service-account default** | Med | on-trigger | S | Account + ACLs already built; only the default flip off LocalSystem remains. Ride the next green `windows-service-smoke`. |
| **#11 WebAuthn (WP-14b)** | Low | **done** | L | ✅ Shipped (ADR 0068 L5a): browser passkeys for local users via the `[webauthn]` extra at the step-up boundary. Still zero delta on 6.3.3 (already Pass via TOTP) — the payoff is the L3 phishing-resistance preference gating off-loopback admin exposure, plus 6.7.2/6.5.7 now applicable-and-Pass. |
| **connector SecretProvider seam** | Low | on-trigger | M | Already a conditional Pass; managed-identity (gMSA/Entra) covers the audience. Build on real Vault/KMS demand. |
| **#31 `.xml()` accessor + `[xml]` layer** | Low | **done** | S | ✅ Core `.xml()` (defusedxml) shipped PR #422; the `[xml]` structured layer (hardened lxml + xmlschema + signxml) shipped `0.2.10` (PR #619). |
| **#32 X12-strict (`pyx12`)** | Low | **done** | M | ✅ Shipped `0.2.10` (PR #619): opt-in `[x12]` pyx12 strict-validate behind the dependency-free tolerant codec; completes ADR 0012's SEF validator. |
| **#23 email** | Low | **done (SMTP) / on-trigger (IMAP-POP)** | M | ✅ SMTP-send shipped `0.2.10` (ADR 0029, PR #618). The IMAP/POP + XOAUTH2 *source* (Phase 2) stays deferred absent a real mailbox feed. |
| **#3 per-key ordering** | Low | on-trigger | XL | Trigger: a *proven* single-feed transform bottleneck. Needs a new ADR; ⚠️ A40 patient-merge reorder hazard. |
| **#17 py3.11 race** | — | **OBSOLETE (3.14-only)** | — | **Moot as of the Python 3.14-only migration** — the engine requires `>=3.14` and CI runs a single 3.14 matrix (ubuntu + Win Server 2022/2025), so the `py3.11`/`py3.13` test legs no longer exist and the hang cannot occur. The race never reproduced on 3.13/3.14. Forensic history retained in the §17 banner. |
| **#24 DICOM** | **Med–High** | **done (Phases 1 + 2)** | L | **Adopter-driven** — a radiology practice on Corepoint DICOM Gear wants to adopt. ✅ **Phases 1 + 2 SHIPPED** ([ADR 0025](adr/0025-dicom-codec-store-connectors.md) Accepted): pure codec + DIMSE **C-STORE SCP** + code-first SR→HL7 Handler (Phase 1, PR #439); **C-STORE SCU + C-ECHO + DICOMweb STOW-RS** outbound (Phase 2, `rest.py` reuse — no new dep). **MWL/Q-R/inbound-DICOMweb declined/deferred.** Did **not** need #7. |
| **Meta — v0.3 cut** | Low | **done** | S | ✅ The v0.3-candidate wave was cut as **`0.2.10`** (Plan-5; ADR 0023 inbound-HTTP among others). Next buildable set planned in PLAN-6. |
| **#30 version-update check** | Low | **done** | M | ✅ Shipped `0.2.10` (ADR 0026, PR #618) — but as a **zero-egress local lock-diff** (no PyPI call), resolving the on-prem tension; the live-egress variant stays off-by-default / deferred. |
| **ASVS 11.7.1 in-use memory encryption** | Low | **drop (N/A)** | XL | Already scored **N/A** — a hardware/OS/hypervisor capability, unachievable for pure-Python on-prem. |
| **#18 git-offering** | Low | **confirm-decline** | M | Buyers already run git/ADO/GHE — a non-problem. Fold conventions into #33; AGPL-compat entanglement. |
| **#25 JMS** | Low | **confirm-decline** (as named) | M | Java-broker artifact vs the **no-broker identity** (the staged SQLite queue *is* the durability story). Keep only a *generic* AMQP/Kafka on-trigger candidate. |
| **#26 visual/template authoring** | Low | **confirm-decline** | S | Code-first IS the differentiator (recorded #411). The failure mode is a "guided editor" drifting toward declarative *logic* authoring. |
| **#27 Serial / ASTM** | Low | **confirm-decline** | S | Out-of-scope niche, no demand (recorded #411). Revisit only on a concrete lab-analyzer requirement. |
| **ASVS 13.3.3 HSM/KMS/Vault KeyProvider** | Med | **done** | — | #377 merged (`d35dbde`). Prune the stale `asvs-1333-keyprovider` worktree — don't fund twice. |
| **ASVS 4.1.5 per-message signing** | Med | **done** | — | #378 merged (`9c00b88`). Prune the stale `asvs-415-msg-signing` worktree. |
| **#74 host CPU/mem metrics** | Med | **do-next** | S | Promoted from the #52 gap synthesis (2026-06-28) — the one zero-identity-tension additive win: host CPU/mem (psutil) on the metrics surface beside the #50 disk meter. Adds `psutil` (vet + re-lock). SQL-internals sub-scope demand-gated. |
| **Publish the VS Code extension (Marketplace + Open VSX)** | Med | do-next | M | Publish the `ide/` extension to the **VS Code Marketplace** + **Open VSX** (`.vsix` via `vsce`/`ovsx`) so users install it instead of F5-from-source; add a CI publish leg + publisher accounts. **Owner: do soon, AFTER the planned IDE-focused improvements land** (not now — recorded 2026-06-26). Not a PyPI artifact (different ecosystem). |
| **#95 engine-brokered AI assist** | Low | on-trigger | L | BYO already covers "use our existing AI subscription" (Copilot/Claude via `vscode.lm`, or an in-house model surfaced through VS Code) with **zero** engine work; this is the documented P1/P2 broker — engine-centralized, **per-use-audited** egress to a customer's managed subscription or self-hosted/in-house endpoint, wiring in the reserved `[ai]` `endpoint`/`provider`/`model` keys. ADR-first. **Trigger:** a customer wants engine-brokered AI to their own instance, or we have bandwidth. |

**Top strategic calls** *(2026-06-19; updated 2026-06-28)*:
1. ✅ **v0.2 locked and shipped** through `0.2.10` (#28/#29 evidence published; #22b shipped). The release-close move is done.
2. **The connector + codec backlog largely shipped, on its triggers** — #7 (first slice) / #23 (SMTP) / #24 / #31 / #32 all landed; #25 stays declined. The discipline held: each shipped against a real adopter/contract or as an additive opt-in, never speculative. The remaining transport tails (#23 IMAP/POP, #7 SOAP-reply) stay demand-gated.
3. **Treat the ASVS L3 residuals as closed/N-A, not a staffing queue** — #377 + #378 merged; 11.7.1 is N/A; WebAuthn #11 buys zero ASVS movement. The only live security item is the cheap least-priv default flip.
4. ✅ **The v0.3-candidate set was cut as `0.2.10`** (anchored on ADR 0023 inbound-HTTP). The next buildable set is the actionable **#33** + the **#40** AWS campaigns + owner-decision **#60** — planned in PLAN-6, still ADRs-first and demand-aware. (**#41** shipped as ADR 0047; **#61** as ADR 0048 / #641; **#52** is the parity index → #65–#85; **#39** was built then 🪦 retired 2026-07-01.)
5. **Re-confirm the #26 visual-authoring decline loudly** — the strategic failure mode is an audit or "guided editor" quietly drifting toward declarative *logic* authoring.

*(This table is the recorded conclusion; full per-item reasoning + the adversarial challenge notes live in the 2026-06-19 evaluation. The per-item status banners under each `##` entry below remain the source of truth for build state.)*

---

## Security posture — known gaps & hardening (tracked; not an open exposure on the shipping config)

The shipping configuration (SQLite/server-DB, single uvicorn worker, **localhost bind + required auth**)
carries no open network exposure. The gaps below are **by design and tracked** — full context in
[`releases/v0.1-PLAN.md`](releases/v0.1-PLAN.md) (the gates + the *Security posture* subsection),
`security/CISO-REVIEW.md` (30-risk register), and the ASVS-L2 assessment.

**Known gaps (by design):**
- **MFA is built but off by default** — native RFC 6238 TOTP for local accounts (WP-14, #336/#338), enabled
  per deployment via `[auth].require_mfa`. Still single-factor until switched on, and the factor is TOTP
  (shared-secret, replayable within its ~30 s step window) — phishing-resistant WebAuthn/FIDO2 is the WP-14b
  follow-up. AD/Kerberos MFA is delegated to the directory.
- **Off-box log shipping is built but opt-in** — the structured-JSON + syslog/SIEM forwarder + cross-backend
  `audit_log` off-box tee shipped (sec-offbox-log #357/#361/#363); enabling it + pointing at a SIEM endpoint
  is the per-deployment step, and native TLS-syslog (vs a local TLS-forwarding agent) is the residual.
- **Some safeguards are opt-in** — at-rest encryption (`[store].require_encryption`), data retention/purge,
  and outbound `[egress].allowed_*` allow-lists must be switched on for each deployment.
- **No backup/disaster-recovery or incident-response tooling**, and **no independent security test** has
  been performed (the external code review + penetration test are the **GA / v1.0** gate, not v0.1).
- **Two single-maintainer untrusted-input parsers have no upstream-dormancy contingency** — `python-hl7`
  (latest PyPI release >4 yr old) and `hl7apy` (~16 mo since last commit) parse attacker-influenceable HL7
  on/near the ingress hot path. Both are pure-Python (DoS-class worst case, contained by the pre-parse
  size/segment caps + parse-fail→dead-letter routing), but no vendored-patch / migration plan exists if a
  parsing CVE is disclosed while upstream stays dormant. *(Source:
  `reviews/DEPENDENCY-INFOSEC-POSTURE-2026-06-23.md`.)*

**Recommended next steps (sequenced in the plan):**
- *Before any network exposure:* **enable `[auth].require_mfa`** (MFA is built — WP-14 native TOTP; the
  off-loopback no-MFA posture is now **enforced at startup**, #356), **ship logs off-box** (the
  structured-JSON + syslog/SIEM forwarder + cross-backend audit-tee are now **built** — #357/#361/#363;
  enabling + the SIEM endpoint is the remaining per-deployment step), and **commission an independent
  security test** — pairs with Gate #4 (native off-loopback TLS).
- *Before any off-loopback exposure:* **verify pre-authentication HTTP rate-limiting / throttling exists**
  at the network edge. Login lockout + the argon2 concurrency cap are built, but general per-IP request
  throttling — DoS protection for the pre-auth HTTP/TLS parsers (uvicorn/httptools, OpenSSL) and the argon2
  path, which off-loopback become remotely reachable before auth — is unconfirmed. Provide it at the WP-15
  reverse proxy or in-engine. *(Source:
  `reviews/DEPENDENCY-INFOSEC-POSTURE-2026-06-23.md`,
  off-loopback delta.)*
- ✅ **DONE — close (or formally accept) the remaining ASVS L3 Fails:** **0 open Fails — all controls
  built or documented-residual.** 6.3.3 MFA, 8.4.2 admin defense, and 16.4.3 off-box logs closed earlier;
  the last three (4.1.5, 12.1.4, 13.3.3) are **now built controls with documented residuals (4.1.5 #378,
  12.1.4 #376, 13.3.3 #377)** — each a *conditional* Pass, not an unqualified one. Per
  `security/ASVS-L3-ASSESSMENT.md` +
  `security/ASVS-L3-REMEDIATION-PLAN.md`:
  - *Off-loopback-conditional* (build at off-loopback exposure, ADR 0002):
    - **8.4.2 — multi-layer administrative-interface defense.** ✅ **BUILT (WP-L3-13, #342):** admin routes
      now layer MFA step-up (WP-14) **+** a new-client-IP contextual-risk signal that forces step-up **+**
      deny-by-default RBAC + the fail-closed `127.0.0.1` bind guard; device-posture is deployment-delegated.
      Off-loopback-activated (default-off / byte-identical on loopback).
    - **16.4.3 — off-box log / audit shipping.** *To Pass:* structured JSON logging + **syslog/SIEM
      forwarding** — **✅ now BUILT (#357/#361/#363):** opt-in structured-JSON logs + a TCP/UDP syslog/SIEM
      forwarder, with `audit_log` records tee'd off-box as **PHI-redacted metadata** across all three backends
      via one shared path. Flips to Pass once enabled per-deployment + pointed at a SIEM endpoint (operational).
      Compensating meanwhile: the local `audit_log` is append-only, SHA-256 hash-chained, and read-gated on a
      restricted host. Plan: **BEYOND WP-BL3-20**.
    - **12.1.4 — TLS certificate revocation.** ✅ **Pass *(conditional, delegated)* (PR #376; ADR 0002 new
      subsection "Certificate revocation (12.1.4)").** Built: the engine ORs `ssl.VERIFY_X509_STRICT` into every
      verifying TLS context (`config/tls_policy.py` `harden_verify_flags`; wired in `api/tls.py` and
      `transports/mllp.py` server + verifying-outbound paths; skipped on the `CERT_NONE` / `tls_verify=false`
      path), enforcing RFC 5280-conformant chains. Revocation itself is **delegated** to the deploying org PKI —
      OCSP-must-staple at the WP-15 reverse proxy + the OS trust store — because stdlib `ssl` exposes no OCSP/CRL
      fetch and the engine deliberately attempts none. **Residual:** the in-process uvicorn API-TLS / direct
      MLLP-over-TLS termination paths do no live in-engine revocation; `VERIFY_X509_STRICT` is chain strictness,
      **not** revocation checking.
  - *Now built controls with documented residuals* (formerly deferred-by-design):
    - **4.1.5 — per-message digital signatures on the PHI data plane.** ✅ **Pass *(conditional, opt-in)*
      (PR #378; ADR 0018 amended 2026-06-18).** Built: opt-in per-connection **detached-JWS** signing (RFC 7515
      App F; RS256/PS256/ES256 via core `cryptography`, no new dep) on the REST/SOAP outbound connectors, minted
      in the connector `send()` boundary over the exact wire bytes (for SOAP the WS-* wrapped envelope), past the
      queue boundary so retries stay pure (`transports/signing.py`; `config/models.py` `OutboundSigning` +
      `Destination.sign`); a `verify_detached_jws` counterpart pins the algorithm against downgrade. Layers
      message-level integrity+origin **on top of** TLS — the exact 4.1.5 trigger for highly-sensitive PHI
      traversing multiple systems. **Residual:** OFF by default (opt-in per partner contract) so the default
      loopback path carries no per-message signature; outbound-only (inbound verify lands with an HTTP source);
      operator-supplied PEM key via `env()` (managed HSM/KMS is ADR 0019). A strict auditor may still score
      Partial; this is Pass-with-documented-residual on the shipped opt-in control.
    - **13.3.3 — HSM / vault for key material.** ✅ **Pass *(conditional, operator-activated)* (PR #377; ADR 0019
      amended 2026-06-18).** Built: a pluggable **KeyProvider** seam (`store/keyprovider.py`) routes the store
      at-rest DEK sourcing through the `[store].key_provider` setting — built-in `auto`/`env`/`dpapi` (default
      `auto` is byte-identical to the prior env-then-DPAPI ladder) plus lazy `aws_kms`/`azure_kv`/`gcp_kms`/
      `vault`/`pkcs11` hooks that envelope-decrypt a wrapped DEK inside an isolated security module; selecting an
      unbuilt/unknown provider **fails closed** (`KeyProviderError`), never silently to the identity cipher. An
      operator activates an external HSM/KMS/Vault so the root KEK is managed non-extractable inside the module
      (same operator-activated shape as 16.4.3 off-box logging and TLS). **Residual:** on-prem `auto` (env/DPAPI)
      is the **managed** residual (in-process software crypto until a provider is activated); even with a provider
      the unwrapped DEK is in process heap during bulk AES-GCM, the separately-deferred ASVS 11.7.1 / WP-BL3-28
      residual.
- **ASVS L3 Partials — all 20 now closed with documented residuals (PR #383, 2026-06-18).** The
  self-assessment moved **192/20/0/133 → 212/0/0/133** (`security/ASVS-L3-ASSESSMENT.md`): six lanes
  shipped real controls (12.2.1 https-only webhook, 15.3.7 + 4.2.1 HPP/CL.TE framing, 6.5.1 single-use
  TOTP, 12.3.5 console mTLS client cert, 5.4.3 file scan-hook seam); the rest were stale-doc or
  documented-conditional flips. **Two residual follow-ups were deliberately deferred** (each kept as a
  loud residual line in the assessment — not an open exposure on the shipping config):
    - **Least-privilege service account as the install *default* (ASVS 13.2.2 / 13.3.2).** The virtual
      `NT SERVICE\MessageFoundry` / gMSA account + auto-applied minimal ACLs are already *built* and
      operator-selectable (`scripts/service/install-service.ps1 -ServiceAccount`). Flipping the default
      off LocalSystem (behind a `-AllowLocalSystem` opt-out), with the repo/venv ACLs guaranteed, must be
      proven on the Windows **`windows-service-smoke`** CI leg before it can ship without breaking
      out-of-tree-config installs — so it could not be verified in the sandbox-only #383 sweep.
    - **Connector-credential `SecretProvider` seam (ASVS 13.3.1 / 13.2.1).** The store DEK already sources
      through the KeyProvider seam (#377, ADR 0019); generalize the same pattern to AD/SQL/SMTP connector
      credentials — today env-sourced (`MEFOR_*` / `MEFOR_VALUE_*`) — so they can resolve from an external
      vault/KMS. Spans `config/settings.py` env-var resolution + `config/environments.py`; ADR 0019 §5
      explicitly deferred this generalization. *(Source: the #383 partials sweep; verdicts in
      `security/ASVS-L3-ASSESSMENT.md` rows 13.2.2 / 13.3.2 / 13.3.1 / 13.2.1.)*
- **MFA hardening follow-ups (WP-14b):** (a) **WebAuthn / FIDO2** as the phishing-resistant L3
  factor at the same step-up boundary — ✅ **DONE (ADR 0068, web-console L5a):** browser passkeys for
  local users via the `[webauthn]` extra; the assertion satisfies the MFA leg only (the mandatory
  password leg keeps step-up freshness + the new-IP re-anchor); sign-count CAS clone detection; no
  recovery codes by design (`admin_reset_mfa` clears passkeys too). (b) **TOTP single-use within its
  step window** — ✅ **DONE (PR #383):** the highest
  accepted RFC 6238 step is now recorded per user (`users.last_totp_step` compare-and-set across all
  three backends) and an in-window replay is rejected, flipping **6.5.1 Partial→Pass**. *(from the WP-14
  adversarial security review.)*
- **Silent-cleartext + open-egress on a production store — now fail-closed on production posture.**
  `serve` already warned (prod/staging) / refused (`require_encryption`) on a keyless store, and warned
  on fully-unrestricted egress for any PHI instance. It now **refuses to start** (`return 2`) a
  **production** PHI instance that is either (a) keyless — the prod analogue of `require_encryption`, no
  flag needed — or (b) running fully-unrestricted egress (no `[egress].deny_by_default`, no
  `allowed_*`). staging/dev keep the softer warn/quiet posture. *(Deliberately scoped to
  `production` posture to avoid breaking dev/staging or keyless adopters; flipping the schema defaults
  globally stays out of scope.)* The reference-source dial-out also now honours
  `[egress].deny_by_default` (parity with the DATABASE source / `db_lookup` gates). The remaining
  opt-in safeguard is the **dev keyless warning** (left quiet by design — alarm-fatigue) and a global
  `require_encryption=true`/`deny_by_default=true` default (deferred — breaking).
  *(Signed releases + SBOM are now **shipped** — Sigstore + CycloneDX + SLSA build provenance + PyPI
  Trusted Publishing/PEP 740, #317/#332/#333 — moved out of this to-do list.)*

---

## Staged-pipeline architecture — BUILT (ADR 0001, Steps A + B)

> **ADR accepted + built:** [`adr/0001-staged-pipeline-architecture.md`](adr/0001-staged-pipeline-architecture.md)
> (Status: **Accepted**; **Step A and Step B both built**). The staged pipeline is now the live model:
> `ingress → routed → outbound`, ACK-on-receipt, a per-inbound **router worker** + **transform worker**,
> and the store finalizer as the single disposition authority. CLAUDE.md §2 + ARCHITECTURE.md + the
> invariant/staged tests track it; the realized cost is in
> [`benchmarks/step-b-write-amplification.md`](benchmarks/step-b-write-amplification.md). The design
> questions below are retained as the decision record. The **Postgres and SQL Server staged backends have
> since shipped** (both set ``supports_ingest_stage = True`` and run the full `ingress → routed → outbound`
> pipeline; FEATURE-MAP §5). **Remaining/optional follow-ons:** per-key ordering lanes (#3) and the
> per-connection `ack_after=delivered` gate. (FIFO clock-regression robustness is handled per backend —
> the SQLite `outbox` clamps each row's `created_at` non-decreasing per lane via `_fifo_created_at`; the
> server-DB backends use a monotonic key.)

**Priority / foundational** (decided: per-stage durable queues are the target architecture). A
**staged, decoupled pipeline**: durable queues between every stage (ingress → router → transformer →
outbound), each drained by its own worker with FIFO + the configurable error policy from
[`message-ordering-design.md`](message-ordering-design.md). This **supersedes the inline model**
(routers/handlers run in the inbound path today; the only durable queue is the per-outbound outbox).

**It is a pipeline-core rewrite that revises two "do-not-break" invariants** (CLAUDE.md): today the
inbound is ACKed only after the outbox is committed, and the disposition is recorded before the ACK.
Staging moves to **ACK-on-receipt** + **disposition-recorded-as-it-flows**. So the **first task is a
design doc / ADR — before any code** — nailing down:

1. **ACK semantics** — ACK-on-receipt + the partner-contract change (transform failures no longer NAK
   back to the sender).
2. **Transactional stage handoff** — the claim → produce-next → complete transaction, and the
   idempotency rule for transforms (every stage becomes at-least-once).
3. **Revised invariants** — rewrite the reliability + count-and-log statements and their tests.
4. **Per-stage queue schema + recovery** — queue table + status lifecycle + stale-inflight reset per
   stage; per-stage DLQ/replay ("replay from which stage?").
5. **Store strategy** — accept the extra per-stage writes on single-writer SQLite (throughput/latency
   cost), or plan the SQL Server path (item 1).
6. **Incremental build order** — prove the durable-queue + transactional handoff at *one* boundary (an
   explicit ingress queue) before extending to router and transformer. Don't restructure all at once.

**Consequences in brief:** more durable writes/message (single-writer SQLite contention); per-stage
at-least-once (transforms must be idempotent or handoffs transactional); FIFO/ordering becomes a
concern at *every* stage (intertwines with per-key, item 3); config/API/console surface multiplies
per stage. Benefits: true per-stage isolation, uniform FIFO + error policy, backpressure/durable
buffering, a natural home for per-key lanes.

**Phase 1 lands first, independently** — FIFO + configurable failure policy + the global/override
settings layer on the *current* model. Its settings layer and failure-policy semantics carry straight
into the staged pipeline, and it fixes a live ordering gap (today's rotate-on-failure can reorder
ADT→ORM→ORU). See [`message-ordering-design.md`](message-ordering-design.md).

**Source:** `docs/message-ordering-design.md`; the decision (this design discussion) that per-stage
durable queues are foundational.

---

## Load-testing harness — BUILT

**What:** a headless, asyncio load engine (`harness/load/`) + a synthetic high-fan-out
system-under-test (`harness/config/load/`) that drive the engine under heavy MLLP traffic and measure
max throughput, latency under load, and **no message loss**. Persistent pipelined sender pool +
open/closed-loop rate governor + data-driven profiles (warmup→ramp→sustained→spike→soak) + a fast
correlation sink (true end-to-end latency, no DB access) + engine-side polling (backlog, DB growth,
drain) + a no-loss reconciliation + SLO verdict + JSON/CSV report with baseline comparison. CLI:
`python -m harness --load <profile> --engine URL`. Store-agnostic (SQLite / Postgres; SQL Server once
**item 1** lands). Profiles model the *shape* of a large estate (the Corepoint baseline) with generic,
synthetic values only — guarded by a denylist test. Full guide: [`docs/LOAD-TESTING.md`](LOAD-TESTING.md).

**Found + fixed along the way:** under concurrent load + API polling, three SQLite read methods
(`db_status`, `stats`, `connection_metrics`) executed on the shared aiosqlite connection **without**
`self._lock`, so a metrics read could interleave between a write's `BEGIN` and `commit` and corrupt
the connection's transaction state (`cannot commit - SQL statements in progress`). Fixed by serializing
those three on the write lock (the fix landed via the concurrent Track B Step 5 PR #200).

**✅ DONE — broader lock-free reads fix (2026-06-17, PR #359).** All SQLite-store reads now run on a
dedicated bounded **read-only WAL connection pool** (`query_only=ON`), so reads take **no write lock** —
closing both the serialization and the mid-transaction interleave hazard for ~36 read methods (incl. the
4 metrics reads + `integrity_check`, which previously held the write lock). The Postgres/SQL Server
backends were verified to have no equivalent hazard (asyncpg/aioodbc pools + MVCC, no read/write lock).
Original deferred note kept below for history.

**Deferred follow-up (the broader pattern):** the *other* lock-free read methods on the SQLite store
(`list_messages`, `get_message`, `list_dead`, `count_*`, `outbox_for`, `events_for`,
`roles_for_ad_groups`, …) share the same latent bug — fine at normal volumes, but unsafe if browsed
concurrently with heavy delivery. The right fix is a design choice (a dedicated read-only connection,
exploiting SQLite WAL's one-writer/many-readers, rather than serializing every read behind the write
lock) and should be made deliberately — the load harness only exercised the three metrics reads.

**✅ DONE — stage-aware drain gauge.** `/stats` now exposes an **`in_pipeline`** gauge (count of
NOT-DONE `pending`/`inflight` rows across **all** stages — ingress + routed + outbound) on all three
store backends, and `await_drain`/the no-loss reconciliation require it to reach zero. A fully
**stalled** router/transform (zero outbound backlog but `in_pipeline > 0`) no longer reads as drained,
closing the prior blind spot. Folded into the Gate #3 work per the v0.1 execution plan.

**Deferred follow-up (publish-guard token drift):** the harness's denylist test enumerates more real
estate tokens (the vendor/partner names and site-code pattern that live only in the private
token list — see `scripts/security/scan-tokens.local.txt.example`) than `scripts/security/scan_forbidden.py`'s
`FORBIDDEN` set (the core customer/partner/vendor names, …). The publish guard is the real gate over the public
mirror, so it should be the single source of truth — but extending it touches owner-managed
publish-guard config and risks flagging innocent existing tracked content, so it's left for a
deliberate owner pass rather than bundled into this harness change.

---

## 1. SQL Server store backend — concurrency safety (review H-6, H-7, H-8, M-6, low-2 + low-3 store half)

> ✅ **DONE / RESOLVED — all five defects fixed; SQL Server is a supported production backend.**
> Verified defect-by-defect in [`store/sqlserver.py`](../messagefoundry/store/sqlserver.py) (2026-06-15):
> (1) audit hash-chain append race → serialized under `_audit_lock`, with `_backfill_audit_chain` run in
> `open()` before the store is returned; (2) finalize deadlock / missing RCSI → RCSI enabled pre-pool
> (`_ensure_database_options`, enabling RCSI + snapshot isolation) + per-message transaction-scoped `sp_getapplock`; (3) inert pyodbc timeout → real
> `command_timeout` set on the underlying `pyodbc.Connection` per-acquire; (4) rollback hygiene →
> `_fetchall`/`_execute` roll back before re-raise; (5) non-atomic `upsert_role` → single
> `MERGE … WITH (HOLDLOCK)`. Gated by the CI SQL Server service-container store suite. The backend is
> **promoted to production** (`supports_ingest_stage` + `supports_response_capture` both `True`;
> #242/#249/#255), so this is no longer "experimental / fix-before-promoting" deferred work. Original
> description kept below for history.

**Type:** correctness / data-integrity on the **experimental** backend. Not a security exposure on
the production SQLite path (the reliability + count-and-log invariants were verified to hold there).

**What:** the SQL Server backend (`store/sqlserver.py`) is not concurrency-safe:
- audit hash-chain append race (compliance/integrity flavor),
- per-message finalize deadlock / missing RCSI (read-committed-snapshot) assumption,
- the STORE-3 pyodbc timeout fix is inert (no real `command_timeout` plumbed through),
- rollback hygiene in `_fetchall` / `_ensure_schema`,
- `upsert_role` UPDATE-then-INSERT is not atomic (concurrent role seeding → PK violation).

**Why deferred:** the backend is labeled EXPERIMENTAL / not-production-ready; nobody should run PHI
on it yet. Fix this **before** promoting the SQL Server backend toward production.

**Validation:** only exercisable via the CI service-container job (`gh workflow run ci.yml --ref
<branch>` → `sql server store` + `windows-service-smoke`). These are PR-gated and spend Windows/
container CI minutes — confirm cost before dispatching.

**Source:** `docs/reviews/FULL-REVIEW-2026-06-10.md` §3 (High) and §6 step 5.

---

## 2. Console: off-thread API polling (review M-25)

> ✅ **DONE.** WP-WS-G (#299) moved the two periodic pollers (nav health + Engine Status) off the main
> thread via `console/_async.py` `AsyncRunner`, and the follow-up converted the remaining **per-page
> refreshes** — Connections, Log Search (message list + detail), Users — to the same off-thread
> `_fetch`/`_apply` seam, so a slow/wedged engine no longer freezes the window on any auto-refreshed
> page. Crucially it also **closed the cross-thread-shared-client hazard #299 introduced**: a dedicated
> read-only **poll `EngineClient`** (`EngineClient.for_polling()` — own `httpx.Client`, no
> step-up/MFA handlers, token copied) now serves *all* background reads, while the handler-bearing,
> token-mutating primary client stays **main-thread-only** (actions + modal auth). Offscreen-Qt tests
> assert off-thread execution via `threading.get_ident()` (refuting the original "not verifiable
> offscreen" note). The full single-background-worker-queue rework (routing modal step-up/MFA through a
> worker) was **not** pursued — unnecessary once each client is single-threaded-by-construction.

**Type:** GUI reliability / UX. No security dimension (no PHI exposure, no auth/RBAC implication).

**What:** the console health poll and per-page refreshes run on the main thread, so a slow API call
freezes the window. A partial fix (off-loading only the health poll) is unsafe because the health
poll and page refreshes share one `httpx.Client`, which is not safe for concurrent cross-thread use.

**Why deferred:** a correct fix is an architectural rework — route **all** `EngineClient` calls
through a single background worker thread (fetch/render split per page), or give the poller its own
client. "Moderate risk"; not verifiable in offscreen Qt tests, so it deserves a focused pass.

**Source:** `docs/reviews/FULL-REVIEW-2026-06-10.md` §3 (Medium, M-25).

---

## 3. Per-key (partition-key) message ordering (long-term, nice-to-have)

> 🛠 **Decline overturned (2026-07-09).** A prioritization pass recommended DECLINE; the stated reason was **invalid**. Purity binds `@router` / `@handler` — **not connectors** (CLAUDE.md §8: “side effects (DB, network) belong in connections/transports”). This is an unfired **demand-gate**, not an architectural impossibility.

> 🔢 **Re-scored 2026-07-10 → DEMAND-GATE.** Value **5/10** · Difficulty **9/10** · _money pit_. Scales one ordered feed past a core; FIFO already correct and feeds split, so a workaround exists; multi-week build behind the strict-FIFO gate. _(was DEMAND-GATE · V2/5 · D4/5)_

**Type:** feature — throughput/ordering enhancement. Deferred by design: the near-term model is
**FIFO per outbound connection** (simple, safe). Per-key ordering is the leading-edge refinement to
revisit once FIFO is solid and a real workload needs the parallelism.

**Naming (locked 2026-06-30):** the canonical vocabulary for this concept is **sequence key** (the
per-message partition value — ADT = `facility + MRN`; same key → same lane → FIFO preserved,
different keys → parallel), **sequence group** (the set of messages sharing a sequence key), and
**sequence-keyed lanes** / **sequence sharding** (the mechanism). The older terms used elsewhere in
this item — `partition_key` (config setting) and "order-group sharding" — refer to the same thing.
"Order-group" was retired because "order" collides with clinical orders (CPOE/ORM); "partition key"
was retired because "partition" is reserved for the planned store-sharding-by-channel axis.

**What:** preserve order only *within* a partition key (e.g. MRN / encounter / sending facility)
while processing *across* keys in parallel — the sweet spot between strict per-connection FIFO (safe,
serial) and unordered parallelism (fast, unsafe). Same idiom as a broker partition key. Recent
engines are starting to ship this natively (e.g. InterSystems IRIS 2025.3 FIFO-with-pool>1; Mirth's
hand-built thread-assignment-by-key); the opportunity is to make it a **first-class Router/Connection
setting with an explicit `partition_key` expression** rather than a manual workaround.

**Shape (when built):** a configurable `partition_key` expression over the message (PID-3 MRN, PV1
visit, MSH sending facility); same key → same ordered lane, different keys → parallel; the durable
outbox stays the source of truth for order (monotonic sequence + single-writer-per-lane). Default
remains FIFO (one lane) unless a key is set.

**Hazard to design around:** per-key parallelism is only safe if no single message's correctness
depends on another key's ordering. The canonical trap is an **A40 patient merge**, which legitimately
spans two MRNs — cross-key events need a serialization fallback or explicit dual-key handling, not
naive parallelization.

**Why deferred:** strict FIFO-per-connection (the chosen near-term model) already gives correct
ordering for healthcare dependencies (ADT→ORM→ORU, no stale overwrite). Per-key is an optimization
for when head-of-line blocking on a busy shared connection becomes a real throughput problem.

**Throughput framing (owner discussion 2026-06-13):** this is the **order-preserving way to scale a
*single* high-volume ordered feed** past one worker/core's transform rate. The owner has confirmed he
never wants an `UNORDERED` queue (HL7 carries order dependencies; strict FIFO is *the* model), so this
— not relaxing order — is the sanctioned escape hatch when one feed outgrows a single core. With
multi-node active-active scale-out dropped (2026-06-18), per-key parallelizes *within* one lane by
independent order-group (e.g. per-MRN), ordered inside each group — there is no separate horizontal
scale-out track for it to complement. A single strictly-
ordered stream is capped at one core in **every** engine (Mirth serial-per-channel by default, etc.);
order-group sharding is how you exceed that without sacrificing order. **Long-term, low-priority** —
revisit only if a real single-feed workload demands it. (See [THROUGHPUT-IMPROVEMENTS.md](archive/throughput/THROUGHPUT-IMPROVEMENTS.md)
for the complementary per-inbound / multi-process scaling axes.)

**Source:** `docs/hl7-message-ordering-reference.md` (engine survey + design implications); owner
throughput discussion 2026-06-13.

---

## 4. ACK-code-aware retry — AE vs AR (near-term, pairs with FIFO)

> ✅ **DONE — shipped in ordering Phase 1 Layer 3 (PR #136).** `NegativeAckError` carries the MSA-1
> family; AR/CR fail-fast (dead-letter immediately), AE/CE retry; per-connection overridable. Kept
> below for history.

**Type:** delivery-reliability. **Near-term**, not deferred-indefinitely: it pairs with the FIFO
ordering work in [`message-ordering-design.md`](message-ordering-design.md) and is what makes FIFO
genuinely usable rather than merely correct.

**What:** outbound `_check_ack` ([`transports/mllp.py`](../messagefoundry/transports/mllp.py))
collapses every negative ACK to one `DeliveryError`, so **AR (permanent reject)** is retried exactly
like **AE (transient error)**. Under the FIFO **retry-forever default**, that means a
permanently-rejected message **blocks the whole connection indefinitely** (until an operator sees the
build-up alert and purges it) — for a message the partner will never accept.

- **AR** (application reject — permanent) → **fail-fast**: dead-letter immediately, skip the retries.
- **AE** (application error — transient) → retry to `max_attempts` (today's behavior).
- Make the classification a **per-connection-overridable** setting (some partners misuse AE/AR), per
  the global-default + per-connection-override model in the design doc.

**Why it matters:** `RetryPolicy.max_attempts` already prevents a *permanent* FIFO stall on a NAK;
AR-fail-fast minimizes the *blocking window* so one permanently-rejected message doesn't hold the
lane for its full backoff schedule.

**Source:** `docs/message-ordering-design.md` ("ACK-code-aware retry").

---

## 5. Alerting framework + FIFO operational alerts (near-term — the FIFO defaults depend on it)

> ✅ **DONE — emit-points in Phase 1 Layer 4 (PRs #137/#138); real notifier in PR #139.** The FIFO
> worker emits `connection_stopped` + `queue_buildup` to an `AlertSink`; the default `LoggingAlertSink`
> logs them, and a configurable **webhook + email** notifier (`[alerts]` settings,
> [`pipeline/alert_sinks.py`](../messagefoundry/pipeline/alert_sinks.py)) routes them for real. Richer
> destinations / templating / send-retry / named-policy rules remain future work behind the same seam.
> Kept below for history.

**Type:** operational reliability. **Near-term**: the conservative FIFO defaults
([`message-ordering-design.md`](message-ordering-design.md)) are only *safe* if the operator is
notified — a stopped connection or a building queue that nobody sees is worse than a dropped message.

**What:** there is no alerting framework yet (rules / thresholds / notification routing). The console
surfaces only raw signals (errored count, queue depth, `backlog_seconds`). Build a configurable
alerting layer; the first two alerts it must support are the ones the FIFO model emits:

- **`connection_stopped`** — an outbound connection halted on an internal/engine error (FIFO default
  action). The operator must intervene.
- **`queue_buildup`** — an outbound connection's backlog crossed a **depth / oldest-in-lane-age**
  threshold (e.g. a NAK'd or unreachable head is blocking the lane). Threshold is a global-default +
  per-connection-override setting.

Longer-term it should also carry named policies like legacy engines (queue-depth/priority,
time-on-queue, stalled/stopped detection, office-hours awareness) with notification routing.

**Placeholder until built:** the FIFO worker emits these as alert *events* to a **no-op sink**
(logged), so the wiring exists and only the notification backend is missing. Do not block the FIFO
work on alerting; do ship the no-op emit points with it.

**Source:** `docs/message-ordering-design.md` ("Failure policy", "Operator controls & observability").

---

## 6. IDE functional tests (vscode-test harness)

> ✅ **DONE (2026-06-17, PR #351).** A `@vscode/test-electron` + mocha integration harness now launches
> headless VS Code, activates the extension, and asserts its commands register/run — wired into the `ide`
> CI job with a new Windows leg (`ide build (ubuntu-latest)` + `(windows-latest)`). Original description
> kept below for history.

**Type:** test infrastructure. The VS Code extension has **no functional/runtime tests**. CI now
builds + type-checks it (the `ide` job: `npm ci` → `tsc --noEmit` → esbuild bundle), but nothing
exercises the extension *running* — commands registering/firing, no runtime errors. A dep bump or
logic change can compile and type-check yet still break at runtime; today only a manual **F5** smoke
in the Extension Development Host would catch that.

**What:** add a `@vscode/test-electron` + mocha harness (an `npm test` script) that launches a
headless VS Code, activates the extension, and asserts its commands register and run; wire it into
the `ide` CI job so IDE behavior is covered on every PR, not just the build.

**Why deferred:** non-trivial setup (test runner, headless VS Code in CI, fixtures). The
build+type-check gate already catches compile/type breakage, so this is the next increment, not
urgent.

**Source:** surfaced merging the esbuild bump (PR #132) — built/type-checked clean but never
functionally tested; the `ide` build job (PR #133) closes the compile gap, not the runtime gap.

---

## 7. Inbound SOAP/REST listener — web-service *source* (v0.3)

> ✅ **First slice SHIPPED in 0.2.10 (ADR 0023 Accepted, Plan-5 Wave 2, PR #624).** The connector-owned
> inbound HTTP/1.1 listener (`transports/http_listener.py`, `ConnectorType.HTTP`) accepts a partner's body
> POST, feeds it to payload-agnostic ingress (ADR 0004) as a `RawMessage`, and returns **respond-with-
> receipt** under ACK-on-receipt — living in `transports/`, not `api/` (the one-way dependency rule holds).
> **Intake auth SHIPPED** (2026-08-01, ADR 0154 increment A, `f2ef0ea9`) and the synchronous
> **SOAP-envelope reply SHIPPED** (ADR 0154 increment B, `reply_from`, PR #119) — naming
> `reply_from` blocks the HTTP turn until the named outbound's reply is captured **and committed**,
> then returns it as the response body. Its `capture_error_responses` gap is open: a partner 4xx
> still yields a fixed-JSON `502` rather than the partner's own status and body.
> **Deferred tail (still open):** **routing-metadata**, and the inbound **FHIR-server
> facade** (#20) / **DICOMweb STOW-RS receiver** (#24). Original deferred-to-v0.3 description kept below for history.

**Type:** feature — a new inbound transport direction (HTTP-listener source). Deferred by design:
every non-HL7 feed in the near-term migration wave is **MEFOR-outbound** (the engine is the client),
so nothing yet requires MEFOR to *host* a web service.

**What:** an inbound HTTP listener, **owned by the connector** (a `SOAP`/`REST` *source*), that
accepts a partner's web-service call, hands the request body to the **payload-agnostic ingress**
([`adr/0004-payload-agnostic-ingress.md`](adr/0004-payload-agnostic-ingress.md)) as a `RawMessage`,
and returns a **synchronous** HTTP/SOAP response (status, or a SOAP envelope / a captured downstream
reply) in the same request. ADR 0003 explicitly left this open: the non-HL7 **source** direction is
"decided: payload-agnostic ingress … but its detailed design is a **follow-up ADR before any non-HL7
source is built**"
([`adr/0003-non-hl7-transports-database-rest-soap.md`](adr/0003-non-hl7-transports-database-rest-soap.md) §3/§5).
That follow-up ADR + the listener are unwritten and unbuilt.

**Design constraints (for the ADR):**
- The listener lives in **`transports/`, owned by the connector** — *not* in `api/`. The engine API
  stays the auth/RBAC surface on `127.0.0.1`; an inbound web-service listener is a separate bound
  socket with its own host/port/TLS/auth posture (it inherits ADR 0002's off-loopback TLS + the
  egress/ingress allowlist model). Mixing it into `api/` would break the one-way dependency direction.
- A **synchronous-response seam**: unlike a fire-and-forget source, the caller blocks for a reply, so
  the design must reconcile "return a response in the HTTP turn" with the staged pipeline + ACK-on-
  receipt + count-and-log invariants (e.g. respond with receipt, or block on a captured downstream
  reply via the ADR 0013 response machinery).

**Why deferred to v0.3:** the outbound connectors (ADR 0003 destinations) plus the two outbound ADRs
in flight — **WS-* SOAP outbound** (ADR 0015) and **synchronous X12 request/response** (ADR 0016) —
cover the current estate, which has no feed where a partner POSTs *into* MEFOR. Pull this forward when
an inbound web-service feed is actually required.

**Source:** ADR 0003 §3/§5 (non-HL7 source direction deferred to a follow-up ADR); on-prem test
scoping (2026-06-15) confirmed no inbound web-service feed in the current wave.

---

## 8. Console: step-up re-verification UX (pairs with WP-L3-16, ASVS 7.5.3)

> ✅ **DONE (PR #319, `baa5c4b`).** The PySide6 console now catches the `403 + X-Step-Up-Required`,
> prompts via `ReauthDialog` (local password, or AD password → live re-bind), and retries the original
> request once (`EngineClient._request` `_allow_step_up` flag + `set_step_up_handler` +
> `reauth()`). 10 offscreen-Qt tests in `tests/test_console_step_up.py`. The MFA-prompt sibling
> (`X-MFA-Required`) shipped alongside (WP-14). **Still open (the *optional owner decision* below):**
> gating the dual-control **approve** route with its own step-up — not done, an explicit owner call.

**Type:** GUI / UX — the **client half** of the step-up control. No new engine work.

**What:** the engine now returns **403 with an `X-Step-Up-Required: 1` header** on the 13 highly
sensitive routes (user admin, dead-letter / message replay, connection purge, config reload/deploy)
when the session's step-up window (`[auth].step_up_max_age_seconds`, default 300s) has lapsed
(WP-L3-16, PR #312). The PySide6 console does not yet handle this — it should catch the 403, prompt the
operator to **re-authenticate** (`POST /me/reauth`: local password, or AD password → live re-bind), and
**retry** the original request. Until then a console admin action taken more than ~5 min after login
surfaces as an unhandled 403.

**Why deferred:** the engine-side control shipped first (it's the security boundary); the console is a
separate process over the API, and the reauth-prompt + retry loop is a focused, testable UI change
(offscreen-Qt test of 403 → prompt → retry). Pairs naturally with the Workstream-G console pass
(item #2 — HA view + off-thread polling).

**Optional owner decision (same area):** the dual-control **approver** (`POST /approvals/{id}/approve`)
does **not** currently require its own step-up — only the requester does (documented as intended
composition in SECURITY.md). If defense-in-depth on the highest-value flows (bulk replay, purge) is
wanted, gating the approve route with `require_step_up` too is a one-line change.

**Source:** WP-L3-16 / PR #312 (engine-side step-up) + its adversarial review.

---

## 10. Worktree tooling: `new.ps1 -Base` resolves the *local* branch, which can lag `origin`

> ✅ **DONE (2026-06-17, PR #348).** `new.ps1`/`spawn.ps1` now `git fetch origin` first and default `-Base`
> to `origin/main`, warning loudly when the resolved local base lags its `origin/` upstream. Kept below for history.

**Type:** developer tooling / papercut. No product impact.

**What:** `scripts/worktree/new.ps1 -Base main` runs `git worktree add … <Base>` against the **local**
`main` ref, which is only as fresh as the last local update. In a parallel-session workflow local
`main` routinely lags `origin/main` by several merged PRs, so a new worktree is silently created on a
**stale base** (caught this session only because the worktree's ASVS scorecard numbers looked wrong — it
was 3 PRs behind). Fix: have `new.ps1` `git fetch origin` first and default `-Base` to `origin/main`,
or warn loudly when the resolved local base is behind its `origin/` upstream.

**Why deferred:** a convenience/safety improvement to the worktree helper, not a product correctness
bug; the workaround (`-Base origin/main`, or fetch first) is known.

**Source:** surfaced building WP-L3-16 in a dedicated worktree (PR #312) — it landed on a 3-PR-stale
local `main` and needed a rebase onto `origin/main` before merge.

---

## 11. `check` dry-run cross-products fixtures × inbounds — no use for a multi-feed config repo

> ✅ **DONE (2026-06-17, PR #349).** `_check_dryrun` now maps a fixture to its intended inbound via a
> `messages/sets/<inbound_name>/` convention (a fixture under `messages/sets/IB_FOO/` is dry-run only against
> `IB_FOO`), falling back to all-×-all when no mapping is given. Kept below for history.

**Type:** tooling / validation — `messagefoundry check`. No product/runtime impact.

**What:** `_check_dryrun` ([`checks.py`](../messagefoundry/checks.py)) runs **every fixture against every
inbound** (`for fixture: for inbound: dry_run(...)`). For a single-feed scaffold that is one clean run,
but for a config repo with many inbounds it **cross-products**: a feed's fixture is routed through the
*other* feeds' handlers, which error on the unexpected message shape (missing segments, wrong type). In
production each inbound only ever receives its own feed (its own port/connection), so these never occur —
the dry-run simply has no notion of which inbound a fixture belongs to. Net effect: a large multi-feed
repo cannot get a clean `check` dry-run even when every feed is correct, so the gate gets downgraded to
**validate-only**.

**Proposed fix:** map a fixture to its **intended inbound** instead of cross-producting — e.g. a
`messages/sets/<inbound_name>/…` directory convention (a fixture under `messages/sets/IB_FOO/` is
dry-run only against `IB_FOO`), or a sidecar/header declaring the target. Fall back to today's all-×-all
only when no mapping is given (preserves the scaffold's single-feed behavior).

**Why deferred:** not blocking — `validate` (the structural gate: modules load, inbound→router refs
resolve, no port collisions) covers wiring correctness, and a multi-feed repo can run validate-only
meanwhile. This makes dry-run a *meaningful* CI gate for multi-feed repos.

**Source:** surfaced standing up a multi-feed config repo against the pinned engine (the ADR 0017
consumer-deployment pattern) — the all-×-all dry-run reported cross-feed errors on a correctly-wired
estate; a per-feed re-run confirmed every feed was clean (the only true errors were the by-design
`db_lookup`-unavailable-in-dry-run, ADR 0010).

---

## 12. `content_type` accepts a raw string but the pipeline assumes the `ContentType` enum

> ✅ **DONE (2026-06-17, PR #347).** `inbound()` / `connections.toml` now coerce a recognized content-type
> string to the `ContentType` enum at the boundary (clear error otherwise), so a string `"x12"` no longer
> crashes deep in dry-run with a bare `AttributeError`. Kept below for history.

**Type:** correctness / robustness — config surface + pipeline. Small, well-scoped hardening.

**What:** `inbound(…, content_type=…)` accepts a value that reaches the pipeline as the connection's
`content_type`, and the route/dry-run path does `ic.content_type.value`
([`pipeline/dryrun.py`](../messagefoundry/pipeline/dryrun.py)), which assumes a `ContentType` **enum**.
So a connection authored with the **string** `"x12"` (instead of `ContentType.X12`) raises a cryptic
`AttributeError: 'str' object has no attribute 'value'` deep in dry-run, with no hint that the
content_type is the cause. The factory neither coerces the string to the enum nor rejects it at load.

**Proposed fix:** at the `inbound()` / `connections.toml` boundary, **coerce** a recognized content-type
string to the `ContentType` enum (the `connections.toml` data path inherently carries strings, so
coercion is the consistent behavior), **or** validate and raise a clear `WiringError` naming the
connection + the bad value. Either way the cryptic late `AttributeError` goes away.

**Why deferred:** low-frequency (most config uses the enum) and trivially worked around
(`content_type=ContentType.X12`), but it is a sharp edge that turns a one-token typo into an inscrutable
pipeline crash.

**Source:** surfaced standing up a multi-feed config repo — one inbound used `content_type="x12"` (string)
where the rest used `ContentType.X12`; `check` failed with the bare `AttributeError` until the string was
traced.

---

## 14. Parallel-run "tee" for the Corepoint → MEFOR cutover

> ✅ **BUILT — shipped #335 (relay) + #340 (purge/export).** The standalone, dependency-free MLLP tee relay
> lives in [`tee/`](../tee/) (`relay.py`/`mllp.py`/`store.py`/`__main__.py`; guide
> [`docs/TEE-RELAY.md`](TEE-RELAY.md)) and verifiably implements the decided architecture below: it **always
> AAs Epic on receipt** (its own ACK authority), fans the unchanged message out to Corepoint (production)
> **and** a shadow MEFOR, **fails closed** (shuts the Epic listener) on a Corepoint transport failure while a
> **shadow-leg failure is only logged/dropped** (never trips, never back-pressures), **logs every NAK** to a
> SQLite-only relay log, and ships `run`/`naks`/`export`/`purge` CLI commands behind a test-data-only guard.
> The shadow-egress-suppression dependency (**#15**) is also **built**. **✅ The parity-comparison tooling is
> now DONE** (2026-06-17 — endpoint #354 + the tee `compare` stack #364): the engine exposes each message's
> transformed outbound payload via `GET /messages/{id}/outbound` (PHI-gated, audited), and the standalone tee
> gained a `tee compare` command — vendored HL7 field reader + pure diff engine + hybrid MSH-10/content-key
> correlation (A40-merge aware) + a PHI-safe parity report — that diffs MEFOR's routed/transformed output
> against Corepoint's captured output. **This closes #14.** Design discussion kept below for history.

**Type:** migration / cutover enabler — a shadow **parallel-run** rig that lets MEFOR observe **live**
production traffic and be validated for output parity against Corepoint *before* it carries any real
feed. No new core invariant; mostly wiring + a suppress-egress / compare posture. Owner-driven, tied to
the active migration.

**What:** stand up a **tee** so MEFOR runs alongside the live Corepoint installation on real traffic without
being in — or altering — the production path:

- **Epic → Corepoint direction (the tee / fan-out):** repoint Epic's outbound at the tee; the tee
  forwards the **unchanged** message to **both** Corepoint (the live path, untouched) **and** MEFOR
  (shadow ingest). MEFOR processes the copy through the migrated Router/Handler graph but **does not
  deliver to real downstream partners** (suppressed / sandboxed egress, or a compare-only capture sink),
  so production is unaffected and MEFOR's transformed/routed output can be diffed against Corepoint's.
- **Corepoint → Epic direction (passive copy via Corepoint action-list):** MEFOR can't be inserted here
  without changing the path, so add a **duplicate message-send to the relevant Corepoint action-lists**
  that mirrors those outbound messages to MEFOR as a passive copy, for the same parity comparison.

**Decided architecture (owner, 2026-06-17): a simple, *separate* standalone application — just an MLLP
relay** in front of Corepoint. **MEFOR is *not* the tee**, so it stays fully out of the Epic ↔ Corepoint
production path. The relay:
- **Always ACKs Epic itself** (its own AA, on receipt) — it is the ACK authority to Epic, not a
  pass-through of Corepoint's ACK — then fans the unchanged message out to **both** Corepoint
  (production) and MEFOR (shadow).
- **On failure, shuts down the connection** (closes the Epic-facing listener) rather than keep ACKing
  messages it can't relay. Epic then sees the connection drop and holds/queues/retries on its side — a
  clean **fail-closed** posture (no silent accept-and-drop), and rollback is just "stop the relay."
- **Keep it deliberately simple — runs on SQLite.** A small standalone app with **SQLite** as its only
  store (the NAK log, any capture, and any short durable buffer) — no server DB, no broker, no MEFOR
  engine dependency. Resist scope creep; it is a relay, not a second engine.

**Design points to settle when built:**
- **What counts as "failing" (the shutdown trigger):** a **production-leg (Corepoint) or relay-internal**
  failure should trip the shutdown. A **shadow-leg (MEFOR) failure must NOT** — the MEFOR copy is
  best-effort; if MEFOR is down or slow, **log-and-drop the copy and keep relaying to Corepoint**. The
  shadow leg must never back-pressure or take down the production path.
- **ACK trade-off (consequence of always-ACK):** because the relay always AAs on receipt, a Corepoint
  *application-level* NAK (AE/AR) no longer propagates back to Epic — Epic sees the relay, not Corepoint.
  Accepted for the parallel run (Corepoint is still the real path and still NAKs internally); transport-
  level failures are surfaced instead via the connection shutdown above. Note a message in flight at the
  instant of a Corepoint-leg failure can be ACKed-but-undelivered — shutting the connection bounds
  further loss and Epic's own resend/queue covers recovery.
- **Log every NAK:** since a Corepoint (or MEFOR-leg) NAK no longer reaches Epic, the relay **must log
  every NAK it receives** — capturing the responding leg (Corepoint vs MEFOR), the ACK code (AE/AR/CR),
  the MSA text, and enough message identity (MSH-10 control ID, type) to correlate it — so those
  otherwise-invisible application-level rejects are recorded for review/audit. They are the only signal
  that a message Epic was told AA was actually declined downstream; a sustained NAK pattern is also a
  candidate alert.
- **No double-delivery (MEFOR shadow leg):** MEFOR's outbounds in shadow mode must not send to live
  downstreams (Corepoint is still doing the real sending) — a compare-only / egress-suppressed posture,
  gated so a shadow deployment can't accidentally egress to production partners. This needs a first-class
  per-outbound **simulate** mode that **MEFOR does not have today** — tracked as **item #15** below.
- **Parity comparison:** tooling to diff MEFOR's routed/transformed output against Corepoint's for the
  same input (and against the Corepoint → Epic copies) — the actual point of the exercise.

**Why:** de-risks the cutover — proves MEFOR produces equivalent output on **real** production volume
and message shapes before any feed is actually switched over, with rollback being "just stop the tee."

**Source:** Corepoint → MEFOR migration cutover planning (owner, 2026-06-17). See the migration topic.

---

## 15. Per-outbound "simulate" (shadow / egress-suppressed) connection mode

> ✅ **DONE — shipped #337 (2026-06-17).** `Destination.simulate` (+ the `outbound()` / `connections.toml`
> equivalents) is built: the delivery worker runs the **full** route → transform → persist + count-and-log and
> finalizes **`PROCESSED`** but suppresses real egress (`response = None`, no `send()` — no bytes leave the
> box), with a deployment-wide **`[shadow].simulate_all_egress`** master switch (per-connection override). A
> simulated lane shows as **`simulated`** on `GET /connections` + `/metadata` and **`[SIMULATED]`** in the
> console, with a one-time WARNING per lane. Covered by `tests/test_outbound_simulate.py`. The text below
> (drafted before the build) is kept for history — the "MEFOR does not have this today" framing is now stale.

**Type:** feature — outbound connector + config surface. The mechanism item #14's shadow side depends
on, and a generally useful operational / testing mode. **MEFOR does not have this today** (verified
2026-06-17: no `simulate` / `enabled` flag on the `Destination` model, no NULL/SINK connector type; the
running engine always delivers — only the CLI `dryrun` skips delivery, and `db_lookup` is the only thing
that no-ops in dry-run). The shipping outbound `Destination` is just `name` / `type` / `settings` /
`retry`.

**What:** a per-outbound-connection **simulate** flag — MEFOR's analog to Corepoint's per-face **"Simulate
Connect"** — that runs the message through the **entire** pipeline (route → transform → outbound stage →
delivery worker, with full count-and-log + raw/transformed persistence) but **suppresses the final
egress**: the connector accepts the payload, records/captures it, and returns success **without sending
any bytes** to the live downstream. So a shadow MEFOR instance processes real traffic and produces
comparable output without ever double-delivering to production partners (Corepoint is still the one
really sending).

**Shape (to design):**
- **A flag on the outbound, not a new connector type** — e.g. `Destination.simulate: bool` (plus the
  `outbound()` / `connections.toml` equivalents), implemented as a thin wrapper over *any*
  `DestinationConnector` that short-circuits `send()` to a capture. This keeps the shadow config
  **identical to production with one flag flipped** (cutover = flip simulate off), instead of swapping
  connector types and losing parity.
- **Capture target:** the suppressed payload should stay inspectable for the parity diff (#14) —
  persisted on the outbound row / written to a capture sink, not dropped on the floor.
- **Make it unmissable:** a simulated outbound must be obvious in `/connections`, the console, and the
  audit log, so nobody mistakes a shadow lane for a live one (or vice-versa). Consider a deployment-wide
  **"simulate all egress"** master switch for a whole shadow instance, with per-connection override, so a
  shadow stand-up can't accidentally leave one outbound live.
- **Disposition semantics:** decide whether a simulated delivery finalizes as `PROCESSED` (capture-as-
  delivery — likely, so metrics/disposition look like production) or carries a distinct simulated marker.

**Why:** without it, the only ways to keep a shadow MEFOR from egressing are brittle (point every outbound
at a throwaway FILE dir or an unroutable host), which lose connector parity and still *attempt* delivery.
A first-class simulate flag is the clean, safe primitive for the parallel run **and** for load-testing /
staging against real configs.

**Source:** the tee parallel-run (#14) no-double-delivery requirement (owner, 2026-06-17); mirrors
Corepoint's per-face "Simulate Connect".

---

## 16. Corepoint event-log parity — protocol-trace capture + inbound-ACK "Response Sent" (ADRs 0020/0021)

> ✅ **0021 half SHIPPED in 0.2.3 (#541, ADR 0021 §7).** The retained slice is built (jointly with #46): a
> metadata-only `connection_event` log (inbound lifecycle + pre-ingress failures with no `message_id` +
> outbound lane transitions) **plus** the ADR 0021 "Response Sent" ACK/NAK capture, a `[diagnostics]` block,
> a `GET /events` read API, and a console **Event Log** page; reasons scrubbed + encrypted at rest. **The
> ADR 0020 raw-frame `protocol_trace` tier stays DROPPED** (the scope-decision banner below). The original
> two-ADR design is kept below for history.

> **⚠️ SCOPE DECISION 2026-06-19 (value review): DROP the ADR 0020 raw-frame tier; keep ADR 0021.** ADR 0020's
> `protocol_trace` table persists **literal transport frames (potential full PHI) in a new raw-PHI-at-rest tier**
> across all backends — the most sensitive new data-at-rest surface in the backlog — for a diagnostic with **no
> customer pull** (internal Corepoint-checklist origin). **Do not build the raw-frame capture.** Capture the one
> genuinely valuable slice instead — **pre-message failures that have no `message_id`** (bad framing, TLS-accept
> failure, peer reset, allowlist refuse) — as a **lightweight structured connection-error *event* log (metadata
> only, no raw bytes)**. **ADR 0021 ("Response Sent" ACK/NAK capture) is RETAINED** — cheap, PHI-safe, reuses the
> merged ADR 0013 machinery. (Source: 2026-06-19 backlog value review.)

**Type:** feature — operational/diagnostic observability. Both are **design-only** (ADRs 0020/0021, Status:
Proposed — no code yet). Their sequencing dependency is now **satisfied**: both append to the same `store.py`
`_SCHEMA`/`_migrate`/cipher sites as the auth (MFA) and tee-relay work, and **those have now merged** (MFA
#336/#338, tee #335/#340), so the build can rebase cleanly on top — it is no longer blocked, just not yet started.

**What:** evaluating MessageFoundry against Corepoint's system-event-log taxonomy (the Transport /
Diagnostic / Alert / Miscellaneous filter, 21 event types) surfaced two real gaps worth closing, each
designed via an adversarially-verified workflow:
- **[`adr/0020-protocol-diagnostic-capture.md`](adr/0020-protocol-diagnostic-capture.md)** — Corepoint
  **"Protocol Data" + "Protocol Text"**. A per-connection, OFF-by-default, bounded **RAM ring** (durable
  only on a transport error or operator snapshot) + a live WebSocket, capturing literal transport frames
  and the **pre-message failures that have no `message_id`** (bad framing, TLS-accept failure, peer reset,
  allowlist refuse) — the motivating gap. Adds a new sibling `protocol_trace` table across all 3 backends
  (a new raw-PHI-at-rest tier; SQL Server needs its own id-keyed cipher pass). The larger of the two
  (~6–8d).
- **[`adr/0021-inbound-ack-nak-capture-response-sent.md`](adr/0021-inbound-ack-nak-capture-response-sent.md)**
  — Corepoint **"Response Sent"** (the ACK/NAK MEFOR returns to an inbound sender), framed as **ADR 0013
  Increment 3**: extend the existing `response` table with a `kind` discriminator (+ `ack_code`/`ack_phase`),
  **zero new cipher/purge code**, captured synchronously in `_handle_inbound`. AA bodies stored encrypted;
  every NAK stores `body=NULL` + a `safe_text`-scrubbed reason only (#120). Cheaper (~3–4d).

**Build order when un-deferred:** **0021 first** (cheap, reuses ADR 0013), then **0020**. Both ADRs are now
registered (Proposed) in [`adr/README.md`](adr/README.md); ADR 0019 — the KeyProvider seam they were drafted
alongside — is already merged (#334). Ratify both (Status → Accepted) before building. Full impl plan / test
matrix / risks live in the two ADRs.

**Why deferred:** owner chose to stop at design and review the ADRs; not blocking v0.1. Open ratification
items: `trace_text` RBAC tier, the SQL Server `ADD … NOT NULL DEFAULT` metadata-only timing, and
console-view scope.

**Source:** Corepoint event-log gap analysis (2026-06-17); ADRs 0020 + 0021.

**See also #46** — the complementary *happy-path* connection-state lifecycle log (established / connecting /
retrying / lost). #16's retained scope is pre-message *failure* events + "Response Sent" ACK; #46 is the
routine Transport-event transitions. Build them together (one event log) if either is un-deferred.

---

## 17. CI: the `py3.11` test leg hangs (pytest deadlock) — OBSOLETE (py3.11/3.13 legs removed)

> ✅ **OBSOLETE as of the Python 3.14-only migration.** The engine now requires `>=3.14` and CI runs a
> single 3.14 test matrix (ubuntu + Windows Server 2022/2025) — the `py3.11` and `py3.13` legs are gone,
> so this hang can no longer occur and it is no longer a required-status-check concern. Everything below
> is retained as forensic history only.
>
> ⚠️ **(Historical) REOPENED / ADVISORY 2026-06-19** (superseded the earlier "✅ RESOLVED" mark — that was premature).
> Root cause (from CI thread dumps) is a mid-test asyncio↔aiosqlite **cross-loop lost wakeup** from per-test
> event-loop churn — **not** the logging-teardown race first hypothesized. The teardown-logging finalizer
> (**PR #409**) + the shared session event loop (`asyncio_default_test_loop_scope = "session"` +
> `asyncio_default_fixture_loop_scope = "session"`, **PR #414**) **reduced but did not eliminate** the hang:
> it **recurred intermittently after #414**, stalling a **docs-only** PR (#417) and the FHIR PR (#416) with
> the identical thread-dump signature — so the "5/5 consecutive green" was intermittent luck, not a fix.
> **`test (ubuntu-latest, py3.11)` is therefore RE-DE-REQUIRED → advisory:** the required gate is
> **py3.13 × {ubuntu, win-2022, win-2025}** + `bandit` + `pip-audit` + `cla`; py3.11 still runs for signal
> but does **not** block merges. The `scripts/soak/store_soak.py` production-shaped soak passes clean on
> py3.11 (5×), confirming this is a **pytest-lifecycle artifact, not a MessageFoundry product defect**.
> Residual fix = **Lane X.2** (`ci-py311-residual`, Plan 3, **PR #423**): py3.11-advisory is now **encoded
> declaratively** — `continue-on-error: ${{ matrix.python-version == '3.11' }}` on the test job (the leg still
> runs for signal, but a wedge no longer reds the workflow) **plus** an off-by-default py3.11-only quarantine
> lever (`MEFOR_PY311_QUARANTINE=1`, seeded with the CI-dump-observed `test_tee_relay` + `test_harness_monitor`)
> as the re-promotion bridge. **Do NOT re-add py3.11 as a *required* status check while `continue-on-error` is
> in place** — that would create a false-green. Re-promote py3.11 to required **only** once provably green
> across repeated runs on a **real py3.11 box** (none in dev/CI — both are py3.13). History below for context.

**Type:** CI / test reliability. **Severity:** medium — it never *fails*, it **hangs**, so the required
check never completes and the PR stays `BLOCKED`.

**Symptom.** The `test (ubuntu-latest, py3.11)` GitHub Actions matrix leg hangs on the **Tests (pytest)**
step for hours (observed **~2.5–2.8 h, twice in a row**) while the *identical* suite passes in **~3 min**
on py3.13 across ubuntu-latest + windows-2022 + windows-2025. First seen on **PR #369**, a docs-only
change (markdown cannot affect test behaviour) — so the hang is **interpreter/environment-specific, not
change-induced**. Two identical hangs argue against a one-off bad runner and for a real py3.11-specific
deadlock that would also affect `main`'s py3.11 leg.

**Hypothesis.** A py3.11-specific deadlock in an asyncio/socket/MLLP test (loop/timeout semantics differ
from 3.13), or a test that waits on a socket/subprocess that never returns under 3.11.

**Action.** (1) Add **`pytest-timeout`** with a per-test wall-clock so a hang **fails fast** instead of
stalling a runner for hours — the cheapest immediate guard, independent of the root cause. (2) Reproduce
locally on py3.11 and bisect to the hanging test (`pytest -x --timeout=60`). (3) Fix the underlying
deadlock. (4) Decide whether py3.11 stays a *required* status check until fixed.

**Source:** surfaced 2026-06-18 while merging **PR #369**, which was admin-merged (`--admin`) because the
hang is unrelated to that docs change and the suite was green on py3.13 across three platforms.

**Update (2026-06-18) — guard shipped, race diagnosed as systemic, `raiseExceptions=False` fix shipped.**
- **(1) DONE — `pytest-timeout` shipped (PR #375):** `addopts = "--timeout=60 --timeout-method=thread"`
  + a 15-min job cap on the `test` job. A hang now **fails fast in ~3 min with a full thread-stack dump**
  instead of wedging for hours; the operational impact is mitigated and a re-run clears it (it is
  intermittent, ~1-in-N).
- **(2) DONE — culprit pinned (the guard's dump named it):**
  `tests/test_tee_relay.py::test_capture_corepoint_copy_only`. The event-loop thread is caught
  **synchronously inside `logging.emit`** at `TeeRelay.start()`'s WARNING banner (`tee/relay.py:193`),
  with a `ValueError: I/O operation on closed file` — i.e. the relay's log record reaches pytest's
  **root log-capture handler while that captured stream is being torn down** (a cross-test window), with
  aiosqlite's background thread also logging. It is a **log-plumbing race, not a relay or asyncio bug**,
  and because the loop is blocked in *synchronous* code it is **not `asyncio.wait_for`-cancellable**. (This
  was the *first* manifestation; see (3) — it is actually a **suite-wide** late-emit race, not relay-only.)
- **(3) Systemic fix SHIPPED — `tests/conftest.py` sets `logging.raiseExceptions = False` for the test
  session.** A second occurrence proved the race is **not relay-specific**: the same `ValueError: I/O
  operation on closed file` floods from the **engine, harness monitor, tee relay, and starlette** (next CI
  run flaked in `test_harness_monitor::test_monitor_observes_engine`, not the relay) — *any* async component
  that emits a log record **after** pytest closed the per-test capture stream. `logging.Handler.emit` routes
  that write error to `handleError`, which (with the default `raiseExceptions = True`) writes a traceback to
  `sys.stderr`; under py3.11 + background threads that path floods and can wedge the event-loop thread
  *inside* the synchronous emit (it holds the handler lock). `raiseExceptions = False` makes `handleError`
  a no-op, so a late emit into a closed stream fails **fast and silent** instead of flooding/deadlocking —
  the stdlib's documented switch for exactly this, scoped to the session (production keeps the default).
  Rejected predecessors: a relay-`start()`-banner-only filter (**insufficient** — race isn't relay-specific)
  and a blanket `tee.relay` `propagate = False` + `NullHandler` (**hid** the records the `caplog` relay tests
  assert on).
- **(4) ROOT CAUSE (corrected) — a py3.11 asyncio↔aiosqlite lost-wakeup deadlock; logging was a downstream
  symptom.** With `raiseExceptions = False` the `I/O operation on closed file` flood vanished **but py3.11
  still timed out**. The `pytest-timeout` thread dump now shows the real deadlock: the **MainThread event
  loop is idle in `asyncio` `_run_once` (selector poll)** *and* **aiosqlite's `_connection_worker_thread` is
  idle in `tx.get()`** — both waiting, nothing in flight. That is a classic **lost wakeup**: a coroutine
  `await`s a DB op, the worker finishes and calls `loop.call_soon_threadsafe(future.set_result, …)`, but the
  loop never wakes, so the `await` hangs forever (py3.11 loop/aiosqlite timing; does **not** reproduce on
  py3.13). The earlier "logging.emit" framing was the *first* dump's symptom, not the cause. **Three
  test-side fixes (banner filter, `propagate=False`, `raiseExceptions=False`) each refined the diagnosis but
  none cleared the hang**, because the deadlock is in the asyncio/aiosqlite layer, not logging.
  **Not blind-fixable** without a py3.11 repro. Real options for whoever has a py3.11 box: (a) bump/bisect
  **aiosqlite** (lost-wakeup fixes land across versions), (b) reproduce + add a loop self-wake / bound the DB
  `await` with `asyncio.wait_for`, or (c) pin/skip the heaviest aiosqlite-backed async tests on **py3.11
  only**. Operationally it stays **mitigated** by the `pytest-timeout` guard (fast-fail ~3 min + re-run; the
  ASVS milestone PRs all landed this way). `tests/conftest.py` keeps `raiseExceptions = False` as a genuine
  CI-noise/secondary-vector improvement, **not** a claim that #17 is fixed.
- **(5) Production-bug check ADDED — `py3.11 store soak` CI job (`scripts/soak/store_soak.py`).** To settle
  whether this is a real product defect or a test-only artifact, a dedicated job runs the store the way the
  engine does in **production** — one `asyncio.run()` loop, **no pytest** — hammering aiosqlite with
  concurrent DB ops on **py3.11** (5×, each bounded by `timeout`). A **clean pass = evidence it is a
  test-lifecycle artifact** (the per-test loop churn / log-capture teardown that production never does); a
  **hang there = a real, pytest-free repro** confirming a product bug. (Local py3.13 baseline: 12k cycles
  clean in ~21 s.) This is the decisive experiment the diagnosis above calls for.
- **(6) RESULT — NOT a product bug (confirmed by A/B on one commit, PR #384).** On the same commit, same
  py3.11 runner: the **production-shaped soak PASSED** (5× clean) while the **pytest `test (ubuntu, py3.11)`
  leg FAILED** on the flake. The engine's real runtime pattern — a single long-lived `asyncio` loop under
  heavy concurrent aiosqlite load — is **stable on py3.11**; the hang is confined to **pytest's** per-test
  loop churn + log-capture teardown. **Conclusion: a test-harness artifact, not a MessageFoundry defect.**
  The soak job stays as a permanent regression guard (it would catch a genuine production-path regression);
  the `pytest-timeout` guard keeps the pytest leg fast-fail + re-run. The remaining tidy-up (so the pytest
  leg stops flaking) is test-infra only: e.g. pin the heaviest aiosqlite async tests to a session-scoped
  loop, or skip them on py3.11 — no product code change.
- **(7) py3.11 leg DE-REQUIRED — now ADVISORY (owner decision, 2026-06-18).** With (6) proving the hang is a
  test-harness artifact and the flake having blocked a **4th** otherwise-green PR (the docs-only **#385**;
  ~75% fail rate that session), `test (ubuntu-latest, py3.11)` was **removed from `main`'s required status
  checks** (branch protection; `strict` preserved). It **still runs for signal** but no longer blocks
  merges — coverage is preserved by **py3.13 × {ubuntu, win-2022, win-2025}** + the **`py3.11 store soak`**
  guard. **Re-add it as required once the test-infra fix lands.** (This stops the recurring admin-merges:
  #379/#381/#384 were admin-merged past this leg; #385 was the last.)
- **Best fix lead (corroborated by a second session).** A separate session independently reproduced it —
  including on the docs-only #385 — and captured the **same** dump: aiosqlite `_connection_worker_thread`
  alive + MainThread parked in `selectors.select` (the lost wakeup), this time from a **store/engine**
  late-emit rather than the relay banner, confirming the race **roams across async tests** (one root cause).
  Recommended fix: a **suite-wide teardown-ordering finalizer** that detaches the root log-capture handlers
  / quiesces background-component loggers (aiosqlite worker, engine, harness monitor, starlette) **before**
  caplog teardown — *not* per-emit banner drops. Repro to name the culprit nodeid (the CI `-q` hides it):
  `pytest -v -p no:cacheprovider --timeout=60 --timeout-method=thread` on a real py3.11 env. **Caveat:** the
  residual is a selector *lost wakeup*, not a logging *block*, so even a clean logging-teardown fix may be
  partial — validate against py3.11 (the soak job is the production-path regression guard meanwhile).

---

## 18. Decide whether to bundle an open-source git offering in the basic package — decision: decline-by-design (no build)

> ⛔ **DECLINED (2026-06-19 value review) — decline-by-design.** Do not bundle a git client/server into the base package; it contradicts the loopback-default, minimal-attack-surface posture. Detail below.

> **⚠️ DECISION 2026-06-19 (value review): DECLINE bundling.** Do **not** bundle a git client/server into the base
> package. An embedded git service contradicts the loopback-default, minimal-attack-surface posture and bloats the
> thin AGPL wheel, for **zero demand**. The valuable half — **bring-your-own-git + the IDE "Set Up Version Control"
> wiring — already ships** and is the supported model. Re-open only if a bundled VCS becomes a strategic onboarding
> requirement. (Source: 2026-06-19 backlog value review; ADR 0017 decision #6.)

**Type:** product / packaging decision — open question. No code yet; decide first.

**What:** decide **whether or not** the basic (shipped) package should include some **open-source git
offering** rather than relying on the adopter to bring their own VCS. The config model is already
code-/data-as-files (Router/Handler Python modules + `connections.toml`, [ADR
0007](adr/0007-gui-manageable-connections-toml.md)) deployed from an adopter-owned repo ([ADR
0017](adr/0017-consumer-deployment-model.md)), and the IDE extension already has `promote`/`deploy`
flows — so the natural question is whether MEFOR should **bundle** a git capability (config version
control / change-tracking / rollback / audited promote) in the base package, or keep assuming the
adopter supplies git out-of-band.

**Points to settle:**
- **Scope of "offering":** a vendored git client/integration for the config-as-code workflow, an
  embedded lightweight git server for the config repo, or just documented git conventions + IDE wiring
  over the adopter's existing remote — these are very different commitments.
- **Licensing fit:** any bundled component must be license-compatible with the AGPL engine and the
  config-as-separate-work posture (ties into ADR 0017 decision #6, pending legal).
- **Dependency/footprint cost:** adding a git dependency to the base install vs. keeping the engine
  lean and leaving VCS to the operator.

**Why deferred:** a product-direction call, not a v0.1 gate — the engine runs without it, and adopters
can already version their config in their own git today. Resolve deliberately before it shapes the
packaging/onboarding story.

**Source:** owner request 2026-06-18.

---

## 19. Build a user guide

> ✅ **DONE — shipped in PR #412** ([`docs/USER-GUIDE.md`](USER-GUIDE.md)): an end-to-end, task-oriented
> guide (install/run as a Windows service, first-message quickstart on `samples/config` + `send_mllp.py`,
> author Connections/Routers/Handlers, console + IDE, dispositions/dead-letter troubleshooting) that links
> the reference docs rather than duplicating them. History below.

**Type:** documentation deliverable. No code.

**What:** write a comprehensive **user guide** — an end-to-end, task-oriented guide for operators and
config authors (install/run the engine as a service, author Connections/Routers/Handlers, use the
console + IDE extension, monitor dispositions, troubleshoot the error/dead-letter path). Today the docs
are reference- and decision-oriented (ARCHITECTURE / CONNECTIONS / CONFIGURATION / SERVICE / SECURITY /
the ADRs) plus [`EARLY-ADOPTER-GUIDE.md`](EARLY-ADOPTER-GUIDE.md); there is no single guided "how to use
MessageFoundry" walkthrough that ties them together for a new user.

**Points to settle when started:**
- **Scope/audience split:** operator (run/monitor/troubleshoot) vs. config author (code-first
  Router/Handler authoring + `connections.toml`) — likely one guide with clear sections, not two.
- **Relationship to existing docs:** the guide should **link to**, not duplicate, the reference docs and
  ADRs (keep one source of truth per topic).
- **Worked example:** anchor it on a concrete end-to-end feed (e.g. the `samples/config` scaffold +
  `send_mllp.py`) so a reader can follow along.

**Why deferred:** a derived deliverable, not a release gate — sequence it once the v0.1 surface is
stable so the guide doesn't churn against a moving target.

**Source:** owner request 2026-06-18.

---

## Connector & feature-breadth gaps vs. Mirth Connect — ranked for v0.2+ (#20–#27)

These items came from mapping MessageFoundry against the **Mirth Connect "Cost-Effective
Interoperability" brochure** — its base connector list + the Gold/Platinum extension matrix
(owner request, 2026-06-18). The gaps are almost entirely **connector/protocol breadth** and
**console-surface completeness**; the operational / security / reliability core is at or ahead of
Mirth's paid tiers (see [`FEATURE-MAP.md`](FEATURE-MAP.md) §§4–9 — staged pipeline, dead-letter/
replay, RBAC, native MFA/TOTP, LDAP, TLS, hash-chained audit + off-box forwarding, alerting,
active-passive HA). Ranked for v0.2+; the priority tier is on each item.

**Already tracked elsewhere — not re-listed below (so the ranking reads as the *full* picture):**
- **REST / SOAP inbound listeners** (the brochure's HTTP/SOAP *receive* direction) — **#7** above
  (**P1**; v0.3, gated on the follow-up ADR per ADR 0003 §3/§5). The outbound destinations already ship.
- **Active-active horizontal scale-out** — **dropped (2026-06-18); code removed; not a planned milestone.**
  Maps to Mirth's Platinum "Advanced clustering"; **active-passive HA already ships** and covers the HA requirement.
- **Federated SSO / mTLS / Kerberos-SSO** — already FEATURE-MAP §7 (⏭️/🧭).
- **SMART Backend Services (FHIR client OAuth2)** — **#35** below (✅ SHIPPED — ADR 0024 Accepted, PR #432); the SMART *App Launch /
  authorization-server* half stays FEATURE-MAP §7 (🧭, out of lane).

**Ranking at a glance:**
- **P1 — close first (most visible Mirth gaps):** FHIR (#20) · observability / metrics export (#21)
  · *(+ REST/SOAP inbound, existing #7)*
- **P2:** console page completeness (#22) · Email connectors (#23)
- **P3 — situational:** DICOM (#24 — ✅ **Phases 1 + 2 SHIPPED; ADR 0025 Accepted; PR #439 (P1) + C-STORE SCU/C-ECHO/DICOMweb STOW-RS (P2)**) · JMS (#25)
- **Decline-by-design — recorded, not scheduled:** visual/template-driven authoring (#26) ·
  Serial + ASTM (#27)

---

## 20. FHIR support — connector + resource parsing/conversion (P1)

> ✅ **SHIPPED — FHIR codec + REST destination (ADR 0022, 2026-06-19).** Detail below.

**✅ DONE — FHIR codec + REST destination (ADR 0022, 2026-06-19).** Shipped: the pure `parsing/fhir/` codec
(`FhirPeek` routing tier + `FhirResource` validated model over `fhir.resources`, the `fhirpathpy` FHIRPath
evaluator) behind the `messagefoundry[fhir]` optional extra; `ContentType.FHIR` riding payload-agnostic
ingress (ADR 0004) as a `RawMessage`; and a `FHIR()` REST **destination** (`transports/fhir.py`) that reuses
`rest.py`'s hardened HTTP plumbing (sibling, not a `RestDestination` wrapper) — create/update/transaction +
the three conditional knobs (`if-none-exist`/`conditional-update`/`if-match`) + `OperationOutcome`
classification, folded into the `[egress].allowed_http` gate. **`fhir_version` defaults to `R4B`** (R5/STU3
opt-in — pydantic-v2 `fhir.resources` has no plain-R4); **JSON-only MVP** (FHIR-XML deferred to a
hardened-lxml path, ADR 0022 Options #5). **Now shipped (was the bounded follow-up):** **SMART Backend Services
client OAuth2** (the token-acquisition flow real EHR FHIR servers require, where today's static `env()` bearer is
insufficient) → **#35** ✅ SHIPPED (ADR 0024 Accepted, PR #432). **Deferred / still open:** the inbound **FHIR server
facade** → **ADR 0023** (sequenced with the inbound HTTP listener, #7); bidirectional **HL7 v2 ↔ FHIR mapping**
stays code-first Handlers (no production-ready pure-Python converter); profile/terminology conformance; a FHIR
*read/search* client. See [`docs/CONNECTIONS.md`](CONNECTIONS.md) (the `FHIR — FHIR(...)` section) +
`samples/config/IB_FHIR_INTAKE.py`.

**Type:** feature — a new format **and** transport. The single highest-value brochure gap.

**What:** Mirth lists **FHIR** in the base connector set *and* ships **"FHIR R5"** + an
**"Interoperability connector suite"** as Gold/Platinum extensions. MessageFoundry has **zero FHIR
today** — no resource model, no parser/serializer, no `ContentType.FHIR`, no FHIR transport. *(Original-gap
framing, 2026-06-18; now shipped — see the DONE banner above. The SMART-on-FHIR **client** OAuth2
slice tracked separately as **#35 / ADR 0024** ✅ shipped (PR #432); the App-Launch / authorization-server half stays deferred —
FEATURE-MAP §7 is now split client ⏭️ vs server/App-Launch 🧭.)* FHIR is the modern interoperability standard;
its absence was the most likely single reason a prospect picks Mirth over MEFOR.

**Scope (when built):** a FHIR resource codec (R4 + R5; JSON + XML) parallel to `parsing/x12/`,
riding payload-agnostic ingress (ADR 0004) as a first-class content type; a FHIR REST transport —
**client first** (engine as a FHIR client / outbound) then a FHIR **server facade** sequenced with
the inbound-listener work (#7). HL7 v2 ↔ FHIR *mapping* is a separate, larger effort — leave it to
handlers initially. Build the codec before the server facade.

**Components (research 2026-06-19 — [`research/non-hl7-transform-components.md`](research/non-hl7-transform-components.md)):**
the resource codec can be **adopted, not hand-rolled** — FHIR is the *one* non-HL7 format with a mature,
offline, permissively-licensed model. Pair **`fhir.resources`** (BSD-3, pydantic-v2 — the typed
`FhirResource` model: construct/read/set/validate/encode; offline, zero terminology calls) with
**`fhirpathpy`** (MIT — FHIRPath, the `msg["PID-3.1.1"]` field-path analog), behind a
`messagefoundry[fhir]` optional extra in a pure `parsing/fhir/` (the `parsing/x12/` pattern). Two-tier:
`fhirpathpy` peek for routing + `fhir.resources` strict structural validate (the hl7apy analog).
**Explicitly defer** (genuinely unsolved in pure Python): profile/StructureDefinition + terminology/
code-binding conformance, and **bidirectional v2↔FHIR mapping** — no production-ready pure-Python
converter exists, so mapping stays code-first Handlers (confirming the "leave it to handlers initially"
note above). The FHIR **REST transport** half is a separate `transports/` connector (network — never in
`parsing/`). Avoid `fhirpath` (nazrulworld, GPLv3) and `fhirpy`/`fhirclient` (network REST clients).

**Why P1:** high effort, but it is the standout gap. Pull into v0.2 if any target customer needs FHIR.

**Source:** Mirth brochure gap analysis (2026-06-18); component picks from the 2026-06-19 non-HL7
transform-support research ([`research/non-hl7-transform-components.md`](research/non-hl7-transform-components.md)).

---

## 21. Observability — metrics export + per-connection throughput/latency (P1)

> ✅ **DONE — shipped in PR #407.** A `/metrics` Prometheus exporter (+ optional OpenTelemetry) in a new
> `api/metrics.py`: per-connection counters/gauges/histograms (received, delivered, errored, queue_depth,
> delivery-latency p50/p95/p99) over new read-only store counters across all backends. **No PHI in labels**
> (asserted by test). History below.

**Type:** feature — observability. Closes the **"Mirth Command Center" / "channel analytics"** gap.

**What:** Mirth's paid tiers headline a **Command Center** (environment metrics) + per-tier
**channel analytics** (50/100/200). MEFOR has point-in-time signals (`/stats`, `/connections` queue
depth + error/read/write counts, `/ws/stats`) and the console Engine Status page, but **no
time-series throughput/latency (msg/sec, p50/p95/p99), no per-connection error-rate history, and no
metrics export** — Prometheus/OpenTelemetry is 🧭 in FEATURE-MAP §9. Ops teams expect a scrapeable
endpoint for Grafana/Datadog.

**Scope:** a `/metrics` Prometheus exporter (+ optional OTel) of per-connection counters/gauges/
histograms (received, delivered, errored, queue depth, delivery latency). Retain enough series for
dashboards; this is *not* a full in-app Command Center, just the metrics surface ops already know how
to consume.

**Why P1:** low effort, high visibility — answers the "where's the dashboard?" objection cheaply.

**Source:** Mirth brochure gap analysis (2026-06-18); FEATURE-MAP §9.

---

## 22. Console page completeness — Alerts + Dead Letters (P2)

> ✅ **DONE + RE-SCOPED (2026-06-19; completed 2026-06-20).** This item's premise — that a `GET /alerts` API already
> existed — was a **defect: no `/alerts` route existed** (`alerts_active` was a hardcoded-0 stub). Re-scoped and shipped:
> **#22a Dead Letters page** ✅ (**PR #413**, GUI-only over the existing `GET /dead-letters` +
> `POST /dead-letters/replay`); **#22b Alerts** → a NEW read-only **`GET /alerts/rules`** endpoint ✅
> (**PR #415**, exposes the loaded ADR-0014 `[alerts]` rules/transports-present/thresholds; **no secrets**,
> `monitoring:read`-gated) **+ the thin Alerts GUI page** ✅ (**PR #420**, merged 2026-06-20; consumes
> `/alerts/rules`, replaced the `PlaceholderPage`). A **fired-alert-history** view is separate engine work (out of scope here).

**Type:** feature — console UX. The capability exists; only the GUI surface is missing.

**What:** the alerting framework (#5 — done) and the dead-letter list/replay (FEATURE-MAP §4) are
built and reachable via **API/CLI**, but the PySide6 console **Alerts page and Dead Letters page are
stubs** (FEATURE-MAP §10, ⏭️). Mirth surfaces both in-console; an operator-facing replacement should
too. Fold the alert-rule view/test (ADR 0014 rules) into the Alerts page.

**Why P2:** no new engine work — purely the console surface. Matters for operator parity, but the
API/CLI already cover the underlying capability.

> **#22c Event Log page (from #46).** ✅ **SHIPPED in 0.2.3 (#541), jointly with #16 / #46.** The **#46** Corepoint-style
> event logging landed engine-side ("logging like Corepoint", owner go 2026-06-25) with the operator-facing
> **console Event Log page** as its committed fast-follow: a filterable PySide6 page
> (by connection / direction / kind / time, Corepoint Transport/Diagnostic/Alert/Misc filter) over
> `GET /events` + `GET /connections/{name}/events`, plus the Response-Sent ("ACK returned") view off
> `GET /messages/{id}/responses?kind=ack_sent`. Replaced the `PlaceholderPage`, same pattern as #22a/#22b. See **#16** / **#46**.

**Source:** Mirth brochure gap analysis (2026-06-18); FEATURE-MAP §10.

---

## 23. Email connectors — SMTP send + IMAP/POP read (OAuth) (P2)

> ✅ **SMTP-send half SHIPPED in 0.2.10 (ADR 0029 Accepted, Plan-5 Wave 1, PR #618).** A stdlib
> `smtplib`/`email` outbound (`transports/email.py`, `ConnectorType.EMAIL`, `Email()`/`SMTP()` factory),
> STARTTLS-by-default, a deny-by-default `[egress].allowed_smtp` arm, `DeliveryError`→staged-queue retry
> (transform stays pure; SMTP is the side effect). **Deferred (Phase 2, the #23 tail — still open):** the
> **IMAP/POP inbound read + XOAUTH2** mailbox *source* (M365/Google), speculative absent a real mailbox
> feed. Original two-transport description kept below for history.

**Type:** feature — two new transports.

**What:** Mirth lists **Email** in the base connectors and ships **"Email reader with OAuth"** as a
Gold/Platinum extension. MEFOR has **no email transport** — SMTP is wired internally for security/
alert notifications only (`[alerts]`), not exposed as a message connector, and there is no IMAP/POP
source.

**Scope:** an SMTP **destination** (deliver a message as email) and an IMAP/POP **source** (poll a
mailbox, hand the body to payload-agnostic ingress, ADR 0004), with **OAuth2 / XOAUTH2** for M365 +
Google. Leader-gate the mailbox poll like the File/DB sources. SMTP-send is the cheaper half and can
land first.

**Why P2:** real but situational (notification + inbound-document workflows); moderate effort.

**Source:** Mirth brochure gap analysis (2026-06-18).

---

## 24. DICOM connector + parsing (Phases 1 + 2 SHIPPED — adopter-driven; ADR 0025 Accepted)

> ✅ **PHASES 1 + 2 SHIPPED (ADR 0025 Accepted).** Phase 1 (PR #439): the pure `parsing/dicom/` codec + inbound
> **C-STORE SCP** + the worked code-first **SR→HL7 Handler** — the direct Corepoint "DICOM Gear" replacement.
> **Phase 2 (now built):** the outbound **C-STORE SCU** + **C-ECHO** verification (`DICOM()` outbound) and the
> **DICOMweb STOW-RS** destination (`DICOMweb()`, a stdlib sibling of `transports/rest.py` — no new dependency).
> (Promoted to NOW 2026-06-20, reversing the 2026-06-19 defer:
> a **named adopter — a radiology practice on Corepoint's DICOM option ("DICOM Gear")** with a live imaging feed
> overrode the earlier "narrow audience, zero feed" defer.) See
> **[ADR 0025](adr/0025-dicom-codec-store-connectors.md)**.

**Type:** feature — imaging transport + format.

**What:** Mirth lists **DICOM** (a C-STORE SCP listener + SCU sender only — **no MWL, no Query/Retrieve**).
Corepoint's **"DICOM Gear"** is primarily a *transformation* tool: it parses the DICOM **header** and **DICOM
Structured Reports (SR)** and maps them into **HL7 v2** (e.g. SR measurements → ORU/OBX feeding PowerScribe 360
dictation; header → orders to a RIS). MEFOR has none today.

**Scope (ADR 0025 — meet-or-exceed both incumbents):**
- **Phase 1 (✅ SHIPPED — PR #439):** a pure `parsing/dicom/` codec (`DicomPeek`/`DicomDataset` + SR→HL7 mapping
  helpers over optional **pydicom**) + `content_type=dicom` RawMessage ingress + an inbound **C-STORE SCP**
  (via **pynetdicom**, run off the asyncio loop, commit-before-SUCCESS) + a worked **code-first SR→ORU/OBX
  Handler** — the direct Corepoint "DICOM Gear" replacement. The differentiator: the SR→HL7 mapping is
  **code-first pure Python**, not a proprietary GUI mapper.
- **Phase 2 (✅ SHIPPED):** outbound **C-STORE SCU** (full Mirth-sender parity, off-loop association,
  status→retry classification) + **C-ECHO** verification (`test_connection`) + a **DICOMweb STOW-RS destination**
  (reuses `transports/rest.py` as a sibling, like SOAP/FHIR — the modern HTTP-imaging path that *exceeds* both
  incumbents; **no new dependency** — `rest.py` reuse chosen over `dicomweb-client`).
- **Declined / out of scope:** **MWL / serving a modality worklist (owner explicitly declined)**, MPPS,
  Query/Retrieve (C-FIND/C-MOVE/C-GET), DICOMweb QIDO/WADO retrieval, an **inbound** DICOMweb (STOW-RS) receiver
  (gated on the future inbound HTTP listener #7 / ADR 0023), and pixel-data transformation / numpy.

**Correction to the prior entry:** the earlier "DICOMweb-HTTP only, never DIMSE" note was **wrong for radiology** —
real imaging integration is overwhelmingly **DIMSE C-STORE** (modalities/PACS push images/SR to the engine), so
Phase 1 **is** DIMSE. DICOMweb is the additive *exceed* arm, not the only arm. Phase 1 does **not** depend on #7
(that gates only the inbound DICOMweb receiver).

**Dependencies:** pydicom + pynetdicom (both pure-Python, permissive/MIT; headers/SR only → no numpy) for the
DIMSE connectors. Phase 2 STOW-RS reuses `transports/rest.py` (stdlib urllib) — **`dicomweb-client` was NOT
needed** (it drags numpy+pillow+requests), so no new dependency landed and DICOMweb needs no extra.

**Source:** Mirth/Corepoint DICOM capability research (2026-06-20); ADR 0025.

---

## base64 binary-carriage codec (+ HL7 OBX-5 ED embedding) — ADR 0028

> ✅ **SHIPPED (ADR 0028 Accepted, PR #437).** A pure-stdlib (`base64`) `parsing/` codec that carries arbitrary
> **bytes** over the str/TEXT ingress+store as unbroken standard base64 behind a self-describing **`mfb64:v1:`**
> marker, exposed as one encode / one decode on `RawMessage` (`from_bytes`, `.raw_bytes`, `.binary()`,
> `.is_binary`) plus OBX-5 ED embed/extract helpers — so binary bodies no longer hit the lossy/NUL-corrupting
> latin-1 round-trip. No new dependency. The substrate the **DICOM** codec (#24, ADR 0025) builds on. See
> [ADR 0028](adr/0028-base64-binary-carriage-codec.md).

---

## 25. JMS connector — decision: decline-by-design (no build)

> ⛔ **DECLINED (2026-06-19 value review) — decline-by-design.** JMS is Java/JNDI-broker interop with near-zero pull for a Python on-prem HL7 engine, and it pulls against the no-external-broker reliability invariant. Detail below.

> **⚠️ DECISION 2026-06-19 (value review): DECLINE.** JMS is Java/JNDI-broker interop with near-zero pull for a
> Python on-prem HL7 engine, and it pulls against the **no-external-broker reliability invariant** (the SQLite
> staged queue is the deliberate alternative to a broker). Do **not** put a generic AMQP/Kafka placeholder on the
> board either. If broker interop ever becomes a real, demanded feed, it is a **fresh ADR + a thin `aio-pika` AMQP
> source/destination decided on demand** — not a scheduled v0.2 item. (Source: 2026-06-19 backlog value review.)

**Type:** feature — message-queue transport.

**What:** Mirth lists **JMS** (Java Message Service). MEFOR has none. JMS is Java-broker-centric;
from Python it means an AMQP/STOMP bridge or a vendor client.

**Why P3:** niche for a Python engine. Before building JMS specifically, evaluate a **generic broker
connector** (AMQP / Kafka) — most modern queue interop is better served that way, and it would cover
more demand than JMS alone.

**Source:** Mirth brochure gap analysis (2026-06-18).

---

## 26. Visual / template-driven channel authoring — decision: decline-by-design (no build)

> ✅ **DECISION RECORDED — declined-by-design (v0.2+); marker landed in PR #411** (`CLAUDE.md` §12). Code-first
> Routers/Handlers *are* the differentiator; no visual/template/drag-drop authoring is built, by design.

> 🔁 **AMENDMENT — narrowed, not reversed (2026-07-10, owner-directed re-evaluation).** Findings:
> [`docs/research/ide-low-code-options.md`](research/ide-low-code-options.md). Still declined: drag-drop /
> canvas *logic* authoring, declarative field-mapping, and any declarative logic **execution** layer.
> **Carved out:** a **structured action-list *lens*** — a VS Code custom editor that renders/edits real
> Python Handlers expressed in a typed action vocabulary (**#222**, ADR-gated) — because the artifact and
> the only execution path remain plain reviewable `.py` (the decline's rationale, diffable code-first
> config, is preserved). Mirrored by the CLAUDE.md §12 clarifier in the same PR; merging this amendment
> ratifies the carve-out, the #222 ADR gates the build.

**Type:** product-direction decision, **not** a build item — recorded so the gap is a conscious
non-goal, not an oversight.

**What:** Mirth's headline selling point is a **"template-driven architecture … quick, easy, flexible
channel development"** — a GUI/drag-drop transformer with declarative field mappings. MEFOR is
**deliberately code-first**: Python Routers/Handlers for logic; `connections.toml` + the IDE GUI for
*transport* config only; the New Route Wizard scaffolds code; the Test Bench validates. There is **no
declarative field-mapping or visual transformer, by design** (CLAUDE.md §1/§4; the README contrasts
"guided wizards" with "Python for full control").

**Decision / why:** record as a conscious non-goal — code-first *is* the product's differentiator
(diffable, reviewable, version-controlled config). Re-open only if low-/no-code authoring becomes a
strategic requirement; the mutable `Message` API was kept reusable so a future declarative layer
*could* sit on top without a rewrite. Lowest priority; likely **won't do**.

**Source:** Mirth brochure gap analysis (2026-06-18); CLAUDE.md §1/§4.

---

## 27. Serial (RS-232) + ASTM E1381/E1394/E1318 — decision: decline unless lab-analyzer demand (no build)

> ✅ **DECISION RECORDED — declined-by-design (v0.2+); marker landed in PR #411** (`CLAUDE.md` §12 +
> `docs/CONNECTIONS.md` Serial row). Out of the HL7/FHIR/X12 scope; no real feed demand. Revisit only on a
> concrete lab-analyzer requirement.

**Type:** feature / product-scope decision.

**What:** Mirth lists **Serial** and **ASTM E1381** (base) + **ASTM E1394/E1318** (Gold/Platinum).
These are **lab-analyzer / point-of-care** protocols. MEFOR has none, and they are **not on the
roadmap** ([`docs/CONNECTIONS.md`](CONNECTIONS.md) marks Serial "legacy/niche").

**Decision / why:** explicitly **decline** unless a customer specifically needs lab-instrument
integration — legacy, narrow, and high-effort relative to the audience. If pursued: a Serial source/
destination in `transports/` + an ASTM codec in `parsing/` (same shape as X12, ADR 0012). Lowest
priority; situational.

**Source:** Mirth brochure gap analysis (2026-06-18); docs/CONNECTIONS.md.

---

## 28. Run a load test (execute the load harness on the current build)

> ✅ **DONE — executed on the local test boxes (2026-06-27).** The no-loss / latency-under-load harness was
> run against the current `0.2.9` build and [`benchmarks/TUNING-BASELINE.md`](benchmarks/TUNING-BASELINE.md)
> carries the result. **Caveat:** these are the **consumer-hardware floor** figures (a ~15 W APU + consumer
> SSD with the engine + DB co-located — a deliberately conservative floor, *not* the enterprise number). A
> single-box-NVMe / enterprise-shaped run to pin the real ceiling is **slated for #40** (the self-hosted
> Windows Server 2025 + SQL Server 2025 CI leg), which will be the standing home for the recurring perf runs.

**Type:** validation / verification — *running* existing tooling, not new code. The load harness is
**BUILT** ([`harness/load/`](../harness/load/), [`docs/LOAD-TESTING.md`](LOAD-TESTING.md)) and a Gate-#3
baseline is published ([`benchmarks/TUNING-BASELINE.md`](benchmarks/TUNING-BASELINE.md)).

**What:** actually run the harness against the **current** build — a full warmup→ramp→sustained→spike→soak
profile — and capture a fresh **no-message-loss** + latency-under-load + SLO verdict on the shipping config
(SQLite + the server-DB backends). The tooling and a Gate-#3 baseline exist, but a current v0.2 run hasn't
been done; in particular, re-run it to confirm **no regression after the active-active code removal** (and
any other change to the staged pipeline / delivery path).

**Why:** a load run is point-in-time — the result drifts as the engine changes. A current no-loss / SLO
pass is the evidence for a pilot/cutover and the regression guard for pipeline/store/delivery changes.

**Source:** owner request 2026-06-18.

---

## 29. Run a throughput test (re-measure + refresh the tuning baseline)

> ✅ **DONE — re-measured on the local test boxes (2026-06-27).** Throughput (msg/s + p50/p95/p99) was
> re-run across the store backends and [`benchmarks/TUNING-BASELINE.md`](benchmarks/TUNING-BASELINE.md)
> refreshed. As with #28 these are the **consumer-hardware floor** numbers; the enterprise-hardware
> re-measure is **slated for #40** (the self-hosted Windows Server 2025 + SQL Server 2025 leg), the standing
> home for recurring throughput runs.

**Type:** validation / benchmark — *running* the existing benchmark, not new tooling.

**What:** re-run the throughput benchmark (msg/sec + p50/p95/p99 latency) across the supported store
backends and **refresh** [`benchmarks/TUNING-BASELINE.md`](benchmarks/TUNING-BASELINE.md), including the
active-passive failover-load figure. The on-demand benchmark CI workflow (#283/#290/#294) is the vehicle;
this item is to **execute it on the current build and update the published numbers** — notably after the
active-active code removal, which reworks the per-lane claim path.

**Why:** the published baseline is the headline performance evidence; keep it accurate as the code
changes, and confirm the active-active removal / claim-path simplification didn't regress throughput.

**Source:** owner request 2026-06-18.

---

## 30. Automatic dependency + MessageFoundry version-update check, surfaced in the console + IDE

> ✅ **SHIPPED in 0.2.10 (ADR 0026 Accepted, Plan-5 Wave 1, PR #618).** The MEFOR-version update-check is
> built as a **zero-egress local "pinned-vs-current lock diff"** (the air-gap-safe default + only MVP build;
> a `mode=live` outbound call is rejected-at-load), surfaced on `/status` + an ADR-0014 `update_available`
> alert for the console/IDE to render. **On by default** (the local diff makes no network call). The
> constrained live-egress check stays an off-by-default future option per ADR 0026. (The dep-vuln-scan half
> was dropped — `requirements.lock` + DEP-1 cover it.) Original description kept below for history.

**Type:** feature — operational observability. New engine signal + two consuming surfaces (console, IDE).

**What:** an automatic check for available updates to (a) the engine's **Python dependencies** and (b)
**MessageFoundry itself** (a newer `messagefoundry` release than the one running). When an update is
available, show a message in **both** the monitoring console and the **VS Code extension** so an operator
sees it without manually diffing `pyproject.toml` / `requirements.lock` against PyPI. Today the engine has
no notion of "newer version exists" — deps are pinned in the hash-locked `requirements.lock` and the
version is single-sourced (Workstream F), but nothing surfaces drift to an operator.

**Shape (to design):**
- **Where the check runs:** the engine performs the check (it knows its own version + locked deps) and
  exposes the result on the API (e.g. an `update_available` signal on `/stats` or a dedicated endpoint),
  so the **console** (PySide6, over the API — never its own PyPI call) and the **IDE extension**
  (`ide/`, TypeScript) both consume one authoritative signal. Consider routing it through the existing
  **alerting framework (#5)** as an `update_available` alert rather than a bespoke channel.
- **Update source:** compare the running version + locked deps against PyPI (or a configurable index);
  the MEFOR-version half is the cheaper, higher-value piece and can land first.
- **On-prem / air-gapped posture (must settle):** a version check is an **outbound network call**, which
  conflicts with the on-premises-by-default, no-egress posture (CLAUDE.md §9). It must be **opt-in /
  configurable** (off or pointed at an internal mirror by default for air-gapped sites) and must **never
  send PHI or any message content** — it only reports versions. This is the main design constraint.
- **Surface treatment:** a non-blocking, dismissible banner/notice (console Engine Status; IDE
  notification), not a hard gate — distinguish a security-relevant dep update from a routine one if the
  source provides that signal.

**Why deferred:** a convenience/observability enhancement, not a release gate — operators can audit deps
out-of-band today (`requirements.lock` + CI's DEP-1 audit). Sequence after the v0.2 observability work
(#21) since it shares the "engine emits a signal the console/IDE render" shape.

**Source:** owner request 2026-06-19.

---

## 31. Safe `.xml()` RawMessage accessor + structured XML support (XML / SOAP / CDA) (P2)

> ✅ **SHIPPED — verified on `origin/main` (2026-07-09).** Both layers landed: the core `RawMessage.xml()` accessor over `defusedxml` (PR #422) **and** the structured `[xml]` layer — `parsing/xml/` (`harden.py`, `XmlMessage` XPath read/set, `schema.py` XSD strict tier, `signature.py` XML-DSig) with tests, shipped in 0.2.10 (PR #619). A C-CDA→HL7 section mapper, if ever wanted, is a separate demand-gated item. *(An earlier status scan mistook this item's own "SHIPPED" prose for a closed marker and skipped it — the canonical banner prevents that.)*

> 🟢 **Core `.xml()` accessor SHIPPED (PR #422)** — `RawMessage.xml()` backed by `defusedxml` (`forbid_dtd` /
> `forbid_entities` / `forbid_external` all ON; raise-don't-parse on a DOCTYPE, mirroring
> `transports/soap.py::_assert_well_formed_fragment`), closing the XXE footgun ADR 0004 flagged. The
> `[xml]` extra / `parsing/xml/` `XmlMessage` (hardened lxml + `xmlschema` XSD + `signxml`) structured layer
> then **SHIPPED in 0.2.10 (Plan-5 Wave 1, PR #619)** — lxml hardened directly (`resolve_entities=False,
> no_network=True, huge_tree=False, load_dtd=False`) and `signxml` registered in the crypto-inventory. **#31
> is now fully shipped** (core accessor + structured layer).

**Type:** feature — a `RawMessage` accessor (core) + an optional `parsing/xml/` library. Closes the
`.xml()` gap ADR 0004 explicitly flagged, and is the highest-*leverage* single non-HL7 move: one safe XML
door structurally serves FHIR-XML, SOAP, C-CDA, and NCPDP SCRIPT.

**What:** a non-HL7 inbound gets `RawMessage` with `.raw` / `.text` / `.json()` but **no `.xml()`** — so
an XML/SOAP/CDA Handler must bring its own parser, and a naive `xml.etree.ElementTree.fromstring()` on
**untrusted, PHI-bearing** inbound XML is an XXE / billion-laughs liability. ADR 0004's §"To resolve"
already leaned `.xml()` "later … needs a safe parser — `defusedxml`."

**Scope (two layers):**
- **Core (small):** `RawMessage.xml()` backed by **`defusedxml`** (PSF, pure-Python, zero-dep) over the
  stdlib ElementTree, **hardened by default** (`forbid_dtd` / `forbid_external` / `forbid_entities`). The
  quick win — and it removes a real XXE footgun.
- **`[xml]` extra (medium, follow-on):** a pure `parsing/xml/` with a thin **`XmlMessage`** (XPath read/set
  + namespace-aware re-encode — the `Message`/`X12Message` analog) over **hardened `lxml`** (`defusedxml`
  does **not** cover lxml; `defusedxml.lxml` is deprecated — harden the parser directly:
  `resolve_entities=False, no_network=True, huge_tree=False, load_dtd=False`, and verify the current lxml
  CVE posture at adoption). Optional `[xml]` companions: **`xmlschema`** for opt-in XSD strict-validate
  (the slow tier — pin schemas locally; it can fetch a remote `schemaLocation`) and **`signxml`** for
  XMLDSig / WS-Security sign+verify (pairs with WS-SOAP outbound, ADR 0015).

**Why P2:** the core `.xml()` accessor is small/high-value (and closes an XXE footgun); the
`XmlMessage` + validation/signature layer earns its keep mainly for namespace-heavy SOAP/CDA and can
follow. (A generic JSON/XML *model* is otherwise low-value — `RawMessage.json()` already hands back a
navigable tree, and XML has no fixed domain to model outside SOAP/CDA.)

**Source:** non-HL7 transform-support research (2026-06-19),
[`research/non-hl7-transform-components.md`](research/non-hl7-transform-components.md); ADR 0004 §"To
resolve" (the flagged `.xml()` accessor).

---

## 32. X12 strict implementation-guide validation — `pyx12` (completes ADR 0012's deferred SEF validator) (P3)

> ✅ **SHIPPED in 0.2.10 (Plan-5 Wave 1, PR #619).** `parsing/x12/validate.py` adds **`pyx12`** as the opt-in
> `[x12]` strict implementation-guide slow path behind the dependency-free tolerant `X12Peek`/`X12Message`
> (two-tier intact), called on demand against `RawMessage.raw`; completes ADR 0012's deferred SEF validator.
> `pyx12`'s sole runtime dep (`defusedxml`) was already in-tree. Original description kept below for history.

**Type:** feature — an optional `[x12]` strict-validation tier. Completes the piece ADR 0012 explicitly
**deferred**.

**What:** `parsing/x12/` ships a hand-rolled, dependency-free **tolerant** codec (peek/edit), but ADR 0012
deferred **strict implementation-guide validation** (the hl7apy analog for X12) to avoid "a
heavy/uncertain/possibly-hallucinated dependency." Research (2026-06-19) clears that concern: **`pyx12`**
(BSD-3, Python 3.11+, actively maintained) ships HIPAA implementation-guide maps + code lists, is **fully
offline**, and its **only runtime dependency is `defusedxml`** (already on the roadmap), so net new weight
is ~zero.

**Scope:** add `pyx12` as the **opt-in strict-validate slow path** behind the existing tolerant
`X12Peek` / `X12Message` (two-tier intact — the hand-rolled codec stays the dependency-free hot path),
called on demand from a Handler against `RawMessage.raw`, shipped as `messagefoundry[x12]`. Also yields
free **997/999** acknowledgement generation. **Before committing, confirm the shipped map coverage**
matches the partners' specific guide versions (e.g. `005010X222A1` 837P, `X223A2` 837I, `X221A1` 835,
`X279A1` 270/271).

**Why P3:** the tolerant codec already covers routing/transform for current X12 feeds; strict guide
validation is a slow path few feeds need at MVP — pull forward when a partner contract requires
conformance checking (or 997/999 acks).

**Source:** non-HL7 transform-support research (2026-06-19),
[`research/non-hl7-transform-components.md`](research/non-hl7-transform-components.md); ADR 0012 §5 + §"Out
of scope (deferred / known limitations)".

---

## 33. Review the end-to-end configuration method across every surface (config-UX consolidation)

> ✅ **SHIPPED — verified on `origin/main` (2026-07-10).** #33's deliverable was a findings doc, not a PR: [`docs/research/config-ux-review.md`](research/config-ux-review.md) (31 findings, follow-ups A–E as separate items) merged in #421 (`9e9ffc6`). Re-scored to value 1 (ships a document, blocks nobody), then flipped: an already-delivered review is closed, not open buildable work.

**Type:** review / design — a holistic pass over *how* an operator or analyst actually configures a
deployment, before the surfaces multiply further in v0.2+. Not a single bug; a consolidation/usability
audit that will likely spawn concrete follow-up items.

**What:** configuration today is spread across several distinct surfaces, each with its own format and
authoring path, and there is no single map tying them together. Review the whole set for consistency,
discoverability, validation, and UX, then decide per surface what (if anything) to unify, document, or
put behind a guided editor. In scope:
- **Git for the config repo, in the IDE** — how the VS Code extension helps an analyst init/clone, edit,
  validate, commit, and Stage→Promote the config repo (ADR 0017), including the local-hosted-git vs
  online/hosted-git workflows (relates to #18).
- **Store backend — type & location** — `[store]` in `messagefoundry.toml` (SQLite path vs
  PostgreSQL/SQL Server server/database/credentials), and how it is selected, discovered, and validated.
- **AD / user authentication** — `[auth]` LDAP/Kerberos directory config for AD-backed users, role
  mapping, and the local-account/MFA bootstrap.
- **Everything else** — `connections.toml` (ADR 0007), `environments/<env>.toml` + `MEFOR_VALUE_*`, the
  rest of `messagefoundry.toml` (`[api]`/`[inbound]`/`[delivery]`/`[egress]`/`[logging]`/`[retention]`/
  `[cluster]`/`[ai]`), and `MEFOR_*` secrets — the full settings catalog ([`CONFIGURATION.md`](CONFIGURATION.md)).

**Scope:** inventory each surface (file, format, who edits it, validation path, env/secret overlay);
flag inconsistencies, gaps, and footguns (e.g. a silently-wrong `env()` base path, an
accepted-but-ignored knob, a setting with no validation); then decide per surface whether to leave
as-is, document better, add validation, or provide a guided (wizard/GUI) editor. Output is a findings
doc + ranked follow-up items, not a single PR.

**Why:** the surfaces grew incrementally (ADRs 0007/0017 + the service-settings catalog); a deliberate
review now keeps configuration coherent and approachable (the wizards / "Python is the power tool, not
the price of entry" goal) before more knobs land in v0.2+.

**Source:** owner request (2026-06-19); relates to [`CONFIGURATION.md`](CONFIGURATION.md) (settings
catalog), ADR 0007 (`connections.toml`), ADR 0017 (config repo), and #18 (bundled git offering).

> **Review delivered (2026-06-19, Lane L / Plan-3 §B).** Findings doc:
> [`docs/research/config-ux-review.md`](research/config-ux-review.md) (date-stamped, time-boxed; 4-surface
> sweep → adversarial verification, 31 findings confirmed). **#33 identifies + circulates only — no code or
> config was changed.** Headline: the **split-anchor inconsistency** — one logical bundle resolves against
> three filesystem roots (`--config` vs CWD-for-`environments/` vs bare-CWD-for-`messagefoundry.toml`/the
> DB), root-causing the **NSSM non-repo-CWD silent miss** (empty `env()` values + wrong DB path, no loud
> error); already named in ADR 0017 (Path-root caveat + open Major row). Other confirmed footguns:
> env section-name-with-underscore parse drops `MEFOR_<multi_word>_*`; `[pipeline]`/`[cert_monitor]` are
> model sections unreachable via `MEFOR_*`; `connections.toml` inline secrets load unenforced (redacted in
> the API view, used as-is by the transport); env list separators differ by section; `[engine]` documented
> but unimplemented; ~7 implemented-but-undocumented keys.
>
> **Candidate follow-up items (each a SEPARATE item with real contention — NOT part of #33):**
> **A** anchor the whole bundle to one project root + extend `--project-root`/`--env`/`--service-config` to
> `validate`/`graph`/`dryrun`/`check` (contends `config/environments.py` + `config/settings.py` +
> `__main__.py`; likely an ADR output); **B** make the env-settings parser total + section-complete
> (`config/settings.py`); **C** enforce `connections.toml` secret discipline at load
> (`config/connections_file.py` + `config/wiring.py`); **D** unify env list separators (`config/settings.py`);
> **E** docs-only catalog consolidation (no code contention).
>
> **Circulation (influence-sequencing, not a merge-gate — run #33 first):** two consumers must hear these
> conventions **before** freezing `[section]`/key shapes — (1) **#34** (`[retention.connections.<name>]`
> overlay): a dotted/nested section is **not** `MEFOR_*`-reachable today (finding B above), so the overlay
> must be file-only by design or candidate **B** lands first — decide in ADR 0027; inherit the
> global-default+override + fail-loud-on-typo rules; (2) the planned **secret-provider `[secrets]`** surface:
> fold in finding C (enforce, don't just redact), the `_warn_file_secrets` allowlist process risk, and keep
> the two `MEFOR_*` namespaces separate.

---

## 34. Per-connection retention / pruning windows (per-channel message storage, Mirth parity) (P2)

> ✅ **SHIPPED in 0.2.9 (ADR 0027 Accepted).** A per-connection `messages_days` (inbound) / `dead_letter_days`
> (outbound) override layered over the global `[retention]` default (`None` inherits, `0` keeps forever),
> authored on the connection spec or `connections.toml`; the `RetentionRunner` threads a `{connection →
> cutoff}` map through the body + dead-letter purge on **all three** store backends, with the in-flight
> guard + one per-pass audit row (now recording the overrides) preserved. Original description kept below for history.

**Type:** feature — retention granularity. Closes the Mirth **per-channel message storage / pruning**
gap (today retention is deployment-wide only).

**What:** data retention is a **single, store-wide policy**. The `[retention]` service-settings section
([`config/settings.py`](../messagefoundry/config/settings.py) `RetentionSettings`) is enforced by **one**
global [`RetentionRunner`](../messagefoundry/pipeline/retention.py) (one per process), and its windows
(`messages_days`, `dead_letter_days`, `state_max_age_days`) drive the store purge methods
(`purge_message_bodies` / `purge_dead_letters` / `purge_state` in
[`store/store.py`](../messagefoundry/store/store.py)), each of which takes a **single `older_than`
cutoff and purges store-wide by message age only** — there is no per-connection dimension. `Source` /
`Destination` / `ConnectionSpec` ([`config/models.py`](../messagefoundry/config/models.py),
[`config/wiring.py`](../messagefoundry/config/wiring.py)) carry no retention field. So every feed shares
one retention window: an operator cannot keep ADT for 90 days while pruning a high-volume / low-value
lab feed at 7, or null bodies sooner for one chatty connection to bound its PHI footprint.

Mirth, by contrast, sets **message storage + pruning per channel** (metadata vs content retention,
prune-after-N-days, store/don't-store content) — the standard operator lever for bounding PHI
footprint feed-by-feed.

**Scope (when built):**
- A **per-connection retention override** (at least `messages_days` / `dead_letter_days`) layered over
  the global `[retention]` default — the same **global-default + per-connection-override** model already
  used for FIFO ordering, `RetryPolicy`, and `BuildupThreshold`. Author it on the inbound
  `ConnectionSpec` and/or as `connections.toml` keys (transport-config-as-data, ADR 0007) so it stays
  hand- and GUI-editable.
- Thread the per-connection cutoff into the purge SQL: `purge_message_bodies` keys off the **inbound**
  that received each message; `purge_dead_letters` keys off the **outbound** that dead-lettered the row.
  Today both take one global `older_than`; this becomes a per-connection cutoff (a connection→cutoff map
  or a join), with the global window as the fallback for any connection without an override. Must land on
  **all three** store backends (SQLite / Postgres / SQL Server).
- Preserve the existing invariants: still **null-body-keep-metadata** (never delete the row — counts /
  disposition / audit stay intact), and still emit **one audit entry per pass** recording the
  per-connection cutoffs + counts (no message content).

**Out of scope / leave global:** `audit_days` (keep-forever by design — tamper-evident hash chain,
~6-yr HIPAA expectation) and the `state_max_age_days` transform-state purge (already flagged for a
per-namespace, not per-connection, follow-up). `max_db_mb` / WAL / VACUUM stay process-wide (they govern
the one store file, not a feed).

**Why P2:** PHI data-minimization is feed-specific — a chatty/low-value feed shouldn't force the whole
store to a short window, and a clinically-important feed shouldn't be capped by a noisy one. It's a
standard Mirth operator expectation and a HIPAA minimization lever; moderate effort (settings model +
the purge path across three backends), no new invariant.

**Source:** owner question (2026-06-19) — "can each connection be configured for its own log retention
period?" (no: retention is the store-wide `[retention]` section today); Mirth per-channel message
storage/pruning. Relates to #21 (per-connection observability) and #33 (config-UX consolidation).

---

## 35. SMART Backend Services token provider — FHIR/REST client OAuth2 (P2) — ADR 0024

> ✅ **SHIPPED (ADR 0024 Accepted, PR #432).** `transports/smart.py` `SmartBackendTokenProvider` + `with_smart_backend()`
> composer; the ADR 0018 signer extended with `RS384`/`ES384` + an attached-compact JWT
> (`CompactJwtSigner`, no new dependency); the bearer injected per-request in `transports/fhir.py`/
> `rest.py` with a 401 re-mint; the `smart_token_url` egress-gated; `smart_private_key*` redacted. App
> Launch / authorization-server stay deferred (FEATURE-MAP §7 🧭). History below.

**Type:** feature — outbound authentication. The bounded, high-value half of "SMART on FHIR" — split out
from the original single FEATURE-MAP §7 SMART item, which **overstated the work** by bundling this small
client slice with the genuinely-deferred App-Launch / authorization-server pieces.

**What:** ADR 0022 shipped the FHIR data plane (codec + outbound REST destination), but its auth is a
**static** `bearer_token` / basic credential read **once** from `env()` at construction
([`transports/fhir.py`](../messagefoundry/transports/fhir.py) `_build_headers`,
[`transports/rest.py`](../messagefoundry/transports/rest.py)). A real **SMART-secured** FHIR server (Epic,
Oracle Health / Cerner) does **not** accept a long-lived static token: it requires **SMART Backend Services**
authorization — OAuth2 `client_credentials` with an **asymmetric, signed `client_assertion` JWT**
(`RS384`/`ES384`), returning a **short-lived** (~300 s) bearer with **no** refresh token (re-mint the
assertion to renew). Nothing in the engine acquires or renews such a token, so today's FHIR outbound cannot
reach those endpoints. This is the single concrete gap between "FHIR is built" and "delivers to a production
SMART FHIR API."

**Scope (when built — ADR 0024):**
- A code-first **`with_smart_backend()` composer** over `FHIR()`/`Rest()` (mirroring `with_signing()`),
  carrying `smart_*` settings (`token_url`, `client_id`, `scope` e.g. `system/*.rs`, `private_key` via
  `env()`, `algorithm` default `RS384`, `key_id`), every secret via `env()`.
- **Extend the ADR 0018 signing core** ([`transports/signing.py`](../messagefoundry/transports/signing.py))
  with `RS384`/`ES384` (SHA-384, P-384) + an **attached compact JWS** encoder beside the existing detached
  form — **no new dependency** (core `cryptography`).
- A **`transports/smart.py`** `SmartBackendTokenProvider`: mint the `client_assertion`, `POST` it to the token
  endpoint over rest.py's hardened no-redirect/TLS opener, cache the bearer with **expiry-skew refresh**, and
  **inject it per-request in `_post`** (not the frozen `_build_headers`), with a **re-mint-on-401** backstop.
- **Egress parity:** gate the `smart_token_url` host through `[egress].allowed_http` (it is a *second* egress
  host — left ungated it is a fail-open hole).
- **Secret hygiene:** add `smart_private_key*` to `_SECRET_SETTING_KEYS`; the minted token + assertion are
  never logged or persisted (status + redacted host only).

**Explicitly out of scope (stays FEATURE-MAP §7 🧭 / ADR 0023):** SMART **App Launch** (authorization-code +
PKCE, EHR/standalone launch context, OIDC `fhirUser`, user refresh tokens — human-user-app only); the SMART
**authorization/resource server** facade (publishing `.well-known/smart-configuration`, scope *enforcement*,
token introspection — the system-of-record's role, and for mefor gated on the unbuilt inbound facade, ADR
0023); JWKS hosting; Bulk Data `$export` (unlocked by this provider, built later). `.well-known` discovery is
an optional later increment; the MVP takes an explicit `token_url`.

**Why P2:** small, bounded effort on existing seams (no new dependency, reuses the signer + rest helpers), but
it is the difference between "FHIR-capable" and "can actually talk to Epic/Oracle." Pull to P1 / into the next
FHIR increment if a target customer needs live EHR FHIR delivery. Also unlocks Bulk Data `$export` later (same
auth flow).

**Source:** owner question (2026-06-20) — "does an interface engine need anything extra beyond FHIR for SMART
on FHIR?" Multi-agent FHIR-vs-SMART gap analysis: the client token flow is the one real gap; the user-facing
+ server-facade pieces are out of lane. Splits the former single SMART item (FEATURE-MAP §7) in two. See ADR
0024.

## 36. Anonymization (de-identification) for the test harness + tee — build PHI-free testing datasets from real traffic (ADR 0030)

> ✅ **SHIPPED (ADR 0030 Accepted, PR #440).** A pure-stdlib, dependency-free `messagefoundry/anon/` package
> (vendored byte-identical into `tee/anon/`), a two-layer rule model (declarative field-*selection* map over a
> code surrogate-function registry), deterministic per-run-salted keyed pseudonymization with **no persisted
> re-identification map**, and `scan_forbidden` reconciled as the fail-closed leak gate. First bounded slice of
> the de-id capability CLAUDE.md §9 / PHI.md §9 call planned-not-built. History below.

**Type:** feature — test/migration tooling. A shared **anonymizer** that strips/replaces PHI while
preserving message *structure*, consumed by both the standalone send/receive **test harness**
([`harness/`](../harness/)) and the parallel-run **tee relay** ([`tee/`](../tee/), #14), so real-world
message shapes can be captured and replayed as **testing datasets without exposing PHI**. Not built.

**What:** today the only PHI-free message sources are the synthetic conformant **generators**
([`generators/`](../messagefoundry/generators/)) — they produce *valid* HL7 but not the *messy, real*
shapes (quirky vendor segments, odd repetitions, non-conformant fields) that actually break a migration.
The richest source of realistic shapes is live traffic, which is exactly what the **tee** already sees
(it fans Epic's real messages to Corepoint + shadow MEFOR) and what the **test harness** sends/receives —
but both carry PHI, so neither output can be committed, shared, or used as a fixture today. An anonymizer
closes that gap: feed it a real message and it returns a structurally-faithful, **de-identified** copy
safe to land as a test dataset.

- **Tee side:** an opt-in `anonymize` pass on the tee's capture/`export` path (e.g. `tee
  anonymize-captures`) so captured live traffic is written out **already de-identified** — turning the
  cutover rig into a (governed) source of realistic regression fixtures. Must compose with the existing
  test-data-only guard + the `scan_forbidden` publish denylist, never the other way around.
- **Test-harness side:** the harness can **send** an anonymized dataset and **anonymize-on-capture** what
  it receives, so a tester can build/replay a PHI-free corpus end-to-end without ever handling real PHI.

**Shape (to design — do not inline ad-hoc de-id, per CLAUDE.md §9):**
- This is the **first concrete consumer of the planned-but-unbuilt de-identification framework** (CLAUDE.md
  §9: "centralize the rules — don't inline ad-hoc de-id logic"). The rules engine should live as a shared,
  pure component both tools import — **not** duplicated copy-paste logic in `harness/` and `tee/`. (`tee/`
  is deliberately dependency-free/standalone, so settle whether the shared anonymizer ships as a tiny
  self-contained module both can vendor, or whether the tee keeps its own minimal port.)
- **Structure-preserving by default:** operate via the parsed model + re-encode (never raw string
  slicing — §8); replace PHI fields (names, MRNs, addresses, DOB, SSN, identifiers, free-text notes) with
  realistic synthetic surrogates rather than blanking, so the dataset still exercises field widths,
  repetitions, and routing keys. Read separators from MSH; keep MSH-10/control-IDs and the segment/field
  *grammar* intact so correlation + parity diffing (#14) still work on the anonymized set.
- **Consistency:** a stable pseudonymization map within a dataset (same MRN → same surrogate across
  messages) so cross-message ordering/merge logic (e.g. A40) stays testable; the map itself is PHI and
  must never be persisted alongside the de-identified output.
- **Verifiability:** pair the output with a denylist/leak check (extend `scan_forbidden`'s token set as the
  single source of truth) so an anonymized dataset is *proven* PHI-free before it can be committed/shared —
  anonymization that silently misses a field is worse than none.
- **Payload-agnostic eventually:** HL7 v2 first (the migration need); leave seams for X12 / FHIR / raw so
  it tracks the payload-agnostic ingress model, but don't build those until a feed needs them.

**Why:** realistic, non-conformant message shapes are the highest-value test inputs *and* the ones you
can't legally keep — so the corpus that would best harden the engine and de-risk the Corepoint cutover
is exactly the one PHI rules forbid committing. A shared anonymizer is what makes "test against real
shapes" and "never expose PHI" both true at once, and it gives the long-planned de-id framework its first
real driver instead of a speculative build.

**Why deferred / trigger:** demand-gated like the rest of the de-id work — pull it forward when the
migration (or a pilot) needs a committed corpus of real-shaped messages, or when the de-identification
framework (CLAUDE.md §9) is funded and wants a concrete first consumer. Until then the synthetic
generators cover the conformant-fixture need.

**Source:** owner request (2026-06-20) — anonymization for the test harness + tee, "to be used for
testing data sets without exposing PHI." Design recorded in [ADR 0030](adr/0030-anonymization-test-harness-tee.md).
Builds on the tee (#14) capture/export path, the synthetic generators, and the planned de-identification
framework (CLAUDE.md §9).

---

## 37. Resilience test — a problem connection must not crash the engine or block its restart

> ✅ **SHIPPED — connection-fault isolation (ADR 0031, PR #451) + the resilience tests.** Detail below.

> **Update (2026-06-21) — DONE (conn-fault-iso effort; ADR 0031 / PR #451 + the resilience tests).**
> This item assumed "no product change — the supervision is built and behaves correctly." That held
> at runtime but **not at startup**: a single connection that failed to build/bind (bad `env()`/cert,
> port-in-use, egress/exposure refusal, capture/backend mismatch) **aborted the whole engine start**
> (uvicorn "Application startup failed. Exiting."). PR #451 fixed that — **ADR 0031**: startup now
> isolates per connection (logged + `failed`/`AlertSink` + the rest of the graph starts; a failed
> outbound retries and never drops; reload stays fail-fast). Coverage map for the failure modes:
> - inbound bind failure / connector-construction failure / "other connections still start" /
>   isolated+logged+alerted / reload+restart recovery → `tests/test_startup_fault_isolation.py` + the
>   inbound-bind, capture-gate, and ack_after cases in `test_wiring_engine.py` /
>   `test_response_capture.py` / `test_staged_pipeline.py` (PR #451);
> - an **outbound that hangs in `send()`** must not block graceful stop, and a problem connection must
>   not block a clean **stop → restart** → `tests/test_connection_resilience.py`;
> - listener **decode** failure → `test_wiring_engine.py::test_inbound_decode_error_records_error_and_naks`
>   (a per-client handler exception is isolated by the supervised listener task);
> - stuck **in-flight row** recovered on a fresh `serve` → `reset_stale_inflight` (covered in
>   `test_store.py` / `test_staged_pipeline.py` / `test_cluster_graph_gating.py`).

**Type:** test coverage / reliability invariant. No product change — asserts an existing design
guarantee (RegistryRunner task supervision, CLAUDE.md §2: listeners/pollers/retry-timers are
supervised tasks "so a crash in one is isolated", and each outbound drains independently so a
slow/failing one never blocks siblings).

**What:** add tests proving a **single misbehaving connection cannot take down the whole engine or
wedge a restart**. A "problem connection" covers the realistic failure modes:
- an **inbound** that fails to start (port already bound / address-in-use), or whose listener raises
  on accept/decode;
- an **outbound** that raises on connect or during `send()`, or that **hangs** (never returns);
- a connector that raises during construction/registration.

For each, assert: (a) the engine **still starts and runs the other connections** — one bad endpoint
doesn't abort startup; (b) the failure is **isolated and logged** (the supervised task crash doesn't
propagate up and kill the asyncio service), with the appropriate `ERROR`/dead-letter disposition +
AlertSink signal where applicable; (c) the engine **shuts down and restarts cleanly** afterward — no
leaked task, unreleased port, or stuck in-flight row blocks a fresh `serve` (pairs with
`reset_stale_inflight` recovering in-flight rows on startup).

**Why this matters:** the `RegistryRunner` is supposed to supervise listeners/workers/timers so a
crash in one is isolated, and each outbound drains independently. That guarantee is today asserted
only indirectly; a regression — an unhandled exception escaping a supervised task, or a hung task
blocking graceful stop — would silently break the "never crash the engine / nothing silently
dropped" promise. A direct test makes the invariant a gate.

**Why deferred:** not blocking — the supervision is built and behaves correctly in practice; this
hardens the test net around it.

**Source:** owner request (2026-06-20).

---

## 38. Resilience test — a problem engine connection must not crash the console (monitoring app) or block its reconnect/restart

> ✅ **SHIPPED — console resilience under a faulting engine connection (conn-fault-iso effort).** Detail below.

> **Update (2026-06-21) — DONE (conn-fault-iso effort).** Reviewed against the existing console test
> suite: most modes were already covered; the genuine gap — the **(c) "reconnects/recovers cleanly
> once the engine returns"** clause — is now tested, and a spec inaccuracy was corrected.
> **The console reaches the engine ONLY over HTTP and POLLS `/stats` — it has no WebSocket client**,
> so the "stats WebSocket drops/reconnects" mode is **N/A** (corrected here and in CLAUDE.md §10; the
> `/ws/stats` endpoint is server-side and not consumed by the console). Coverage map:
> - engine **down/unreachable** mid-session → `test_console_status.py::test_status_page_engine_unreachable_emits_error`,
>   `test_console_widgets.py::test_heart_reflects_health`; **401** session-expiry → `test_health_poll_401_emits_session_expired` (status + widgets);
> - engine **slow/wedged** → all engine I/O is off the main thread (`test_*_reads_off_main_thread`,
>   `test_async_runner_*`) so a slow read can't freeze the GUI; integrity uses a generous timeout
>   (`test_integrity_check_uses_generous_timeout`);
> - **error status / malformed-garbage body** → `test_console_client.py::test_404_raises_apierror` +
>   `test_decode_maps_{schema_mismatch,malformed_json}_to_apierror` + `test_decode_list_maps_bad_payload_to_apierror`
>   (every bad response becomes an `ApiError`, never a raw crash), surfaced per-page
>   (`test_connections_unexpected_error_clears_loading`, `test_health_poll_preserves_page_error`);
> - **(c) reconnect/recover once the engine returns** (the gap, NEW) →
>   `test_console_status.py::test_health_poll_recovers_after_engine_returns` (nav heart red→green +
>   reachability error auto-cleared) and `::test_status_page_recovers_after_engine_returns`;
> - clean teardown on close → `test_app_window_close_stops_timers`, `test_async_runner_stop_drops_late_result`.
> **Known limitation (not a crash; left as a follow-up):** on-demand actions (Start/Stop/Replay/Purge)
> call the main-thread client synchronously, so a wedged engine blocks the GUI for up to the client's
> request timeout (~5s) before surfacing an `ApiError` — bounded and self-recovering, but not fully
> non-blocking. Moving actions off-thread is a product change, out of scope for this test-coverage item.

**Type:** test coverage / reliability invariant — the **console** (the PySide6 app that *monitors* +
operates the engine). Mirror of #37 on the monitoring side. No product change.

**What:** the console is a separate process that reaches the engine **only** over the localhost
HTTP/WebSocket API (CLAUDE.md §2/§10). Add tests proving a **problem engine connection cannot crash
the console or wedge it**, covering the realistic failure modes:
- the engine is **down / unreachable / refuses the connection** at launch and mid-session;
- the engine is **slow or wedged** (a request that hangs) — the GUI must stay responsive
  (off-thread polling/refresh, item #2);
- the **stats WebSocket drops** mid-stream or fails to (re)connect;
- the API returns an **error status or malformed/garbage body** (API responses are untrusted data,
  never assumed well-formed).

For each, assert: (a) the **window stays responsive and alive** — no unhandled exception on a worker
thread tears down the GUI, no main-thread freeze; (b) the failure surfaces as a **visible,
recoverable state** (a status/banner, not a crash); (c) the console **reconnects/recovers cleanly**
once the engine returns, and can be **restarted** without leftover state — pairs with the off-thread
`AsyncRunner` + read-only poll `EngineClient` (item #2).

**Why this matters:** §10 requires GUI on the main thread with all engine I/O off-thread via
`Signal`/`Slot`; an exception escaping a background fetch, or a slow engine blocking the main thread,
would break the "the monitor never goes dark while the engine is in trouble" expectation — exactly
when an operator needs it most. Run under `QT_QPA_PLATFORM=offscreen` (§10).

**Why deferred:** not blocking — the off-thread seam is built and behaves correctly; this hardens the
test net around the console's failure handling. Companion to #37 on the monitoring side.

**Source:** owner request (2026-06-20) — companion to #37.

---

## 39. Frozen, zero-Python console installer (Phase B) — P3 — ADR 0032 — 🪦 RETIRED

> 🪦 **RETIRED (2026-07-01) — built then removed.** Shipped on the installer lane (ADR 0032 Phase B,
> ratified Accepted 2026-06-28) and pulled back out on 2026-07-01: the packaging assets
> (`packaging/console-installer/`), the `release-console-installer` job in `.github/workflows/release.yml`,
> and the AC-linked tests were **deleted**. See the [ADR 0032 *Amendment (2026-07-01) — Phase B
> retired*](adr/0032-console-desktop-launch.md). **Rationale:** zero uptake (the CI leg failed on every
> tag release v0.2.11–v0.2.14; one out-of-band `.exe` with 0 downloads on a private repo), the no-Python/
> no-IT demand gate never fired (adopters are pip + IT-covered), and the OV/EV signing cert was never
> provisioned so it only ever shipped unsigned. The zero-install audience is now served by **#75** (the
> browser ops dashboard, served from the engine's FastAPI app). Phase A (the `gui-script` +
> shortcuts + `pip install messagefoundry[console]`) is **unaffected** — the desktop console stays fully
> installable; only the *frozen* conveyance is gone. The freeze recipe remains in git history if a
> genuine no-Python/no-IT site appears before #75 covers it.

**Type:** distribution. The deferred second half of [ADR 0032](adr/0032-console-desktop-launch.md): a
standalone desktop installer for the admin console that needs **no Python on the machine at all**.

**What:** ADR 0032 Phase A (built) makes the console a clickable icon via a windowed `gui-script`
(`messagefoundry-console.exe`) + Desktop/Start-Menu shortcuts, but still assumes whoever sets up the box ran
`pip install messagefoundry[console]` once. Phase B removes that prerequisite: freeze the console
(PyInstaller / Nuitka / briefcase) into a self-contained executable and wrap it in a Windows installer
(Inno Setup or MSIX) that creates the shortcuts and an uninstall entry. The Phase A gui-script entry point is
exactly what the freezer wraps, so this layers on top — nothing from Phase A is thrown away.

**Scope (when built):**
- Freeze `messagefoundry.console` to a single-folder exe (PySide6 bundle, ~150 MB+); reuse `app.ico`.
- An Inno Setup / MSIX installer: Desktop + Start-Menu shortcuts, Add/Remove-Programs uninstall.
- **Code-signing** the exe + installer (Authenticode) to avoid SmartScreen / AV false positives.
- A Windows CI **build + sign** leg producing the installer as a release asset.
- **PySide6 LGPL compliance** for a frozen binary (relinking ability / notice).

**Why P3:** current adopters install the engine via an elevated NSSM flow, so IT already touches the box and
Phase A's "install Python once, then click an icon" covers them. Pull forward only when shipping to a site
with **no Python and no IT involvement**, where a download-and-run installer is the only acceptable UX.

**Source:** owner question (2026-06-20) — "how will users run the console? easy, not a command line." Phase A
chosen and built; the zero-Python installer split out here as the heavyweight follow-up.

---

## 40. CI leg against the local Windows Server 2025 + SQL Server 2025 box (real-hardware coverage) (P2)

> ✅ **DONE (first cut, 2026-06-28).** A **self-hosted GitHub Actions runner** (label
> `mefor-win2025-sql`) on a **Windows Server 2025 VM** (dev-PC hypervisor; runner installed as a
> Windows service so it auto-starts with the guest) + a **`workflow_dispatch`-only** leg
> (`.github/workflows/selfhosted-win2025-sql.yml`) that installs the package + `sqlserver` extra +
> ODBC Driver 18 and runs the **SQL Server store + coordinator + production DB-connector** suites
> against the **local SQL Server 2025** instance — **76 passed** on real Windows hardware. Dispatch-only
> + non-required, so the VM is never a merge dependency (the self-hosted-runner security guidance below
> is honoured: `workflow_dispatch` on `main` only, never fork PRs; SQL creds from runner-local env).
> **Follow-ups — runbook drafted 2026-07-06; execute as on-demand AWS campaigns.** These run on the
> AWS two-box bench rig (Windows engine box + an `i4i` SQL Server store box in one VPC — the
> enterprise-hardware rig), **not** the local Win2025 VM and **not** a GitHub Actions leg (backlog #86,
> declined). Step-by-step procedure with the exact `serve`/harness/service commands + rig gotchas lives
> in the `aws-bench` kit as `05-backlog40-followups-runbook.md` (mirrors `ci.yml`'s
> `windows-service-smoke` + `benchmark.yml`): (1) the **NSSM Windows-service smoke** against a **real
> SQL Server store** on the AWS engine box (CI smokes the SQLite graph only); (2) the **load/throughput
> runs (#28/#29)** — the AWS rig is where the enterprise-hardware *ceiling* gets pinned (the local box
> published only the consumer-hardware *floor*); (3) the timing-sensitive **2-coordinator
> failover-lifecycle** suite (`tests/test_cluster_failover_sqlserver.py`) — re-run on the AWS rig, whose
> fast local-NVMe I/O should clear the slower-VM hang that keeps it off the self-hosted leg (it stays
> green on the hosted Linux SQL leg). **Caveats (accepted):** the AWS store box runs **SQL Server 2022**
> (not 2025), and its instance-store NVMe is **ephemeral** with the rig normally stopped between
> campaigns — so these are **on-demand campaigns**, not an always-on recurring leg; the on-prem
> SQL-Server-2025-specific coverage stays on the local `mefor-win2025-sql` leg.

**Type:** CI / test infrastructure. A **self-hosted runner** leg that exercises the Windows-service
deployment and the SQL Server store/connector against a **real Windows Server 2025 + SQL Server 2025**
install — the one production-shaped combination the hosted CI can't reach.

**What:** today's CI proves SQL Server 2025 only on a **Linux** service container (the `sql server
(store + connector) 2025` matrix leg, PR #459) and Windows only on **GitHub-hosted** `windows-2025`
runners with **no SQL Server** and a synthetic, SQLite-backed NSSM smoke. Neither covers the real
target: the engine running as a **Windows service (NSSM)** on **Windows Server 2025**, talking to a
**local SQL Server 2025** over ODBC Driver 18. Stand up a **self-hosted GitHub Actions runner** on the
dedicated Windows Server + SQL Server test box and add a leg that:
- installs the package (built wheel / PyPI) + the `sqlserver` extra + the OS-level ODBC Driver 18;
- registers + starts the engine as a Windows service via `scripts/service/`, hits `/health`, and runs
  the `windows-service-smoke`-style check on **real Windows Server 2025**;
- runs the SQL Server store + coordinator + DATABASE-connector suites against the **local SQL Server
  2025** instance (`MEFOR_TEST_SQLSERVER=1`, real DSN) — exercising RCSI on a real engine, real
  `db_lookup`, and the AVX-capable hardware 2025 requires.
- the **load + throughput runs (#28 / #29)** publish the consumer-hardware *floor* from the local
  box; the enterprise-hardware *ceiling* gets pinned on the **AWS two-box bench rig** (see the
  Follow-ups banner above), not this box.

**Scope / open questions (when built):**
- **Self-hosted runner security:** it executes repo code — gate to **push / `workflow_dispatch` on
  `main` only**, never `pull_request` from forks; isolate the box; scope the runner token tightly.
- **Trigger + serialization:** nightly or on-demand vs. on push to `main`; the box is one shared
  resource — guard with a `concurrency` group so two runs don't collide on the same DB.
- **Creds:** SA / connection secrets come from runner-local env (`MEFOR_*`), never the repo.
- Optionally extend the existing `windows service smoke` job to a self-hosted `os` once the runner
  exists, rather than a wholly separate job.

**Why this matters:** the SQL Server backend and the NSSM deployment are "production" status, but every
automated proof is on hosted Linux/Windows surrogates. A real Windows-Server-2025 + SQL-Server-2025 leg
is the only thing that catches OS / driver / service-manager-specific regressions (ODBC packaging,
service-account perms, integrated/AD auth shape, AVX) before an adopter does.

**Why deferred:** needs the self-hosted runner provisioned on the test box + a security review of the
self-hosted-runner exposure; not blocking the hosted-CI 2025 coverage that already merged (#459).

**Source:** owner request (2026-06-21).

---

## 41. Cloud / Kubernetes HA deployment packaging (container fast-follow follow-ons)

> ✅ **DONE — ratified as [ADR 0047](adr/0047-cloud-kubernetes-ha-deployment-packaging.md) (Accepted
> 2026-06-28) and built.** All six deliverables shipped: (1) the multi-replica HA reference manifest
> [`docker/k8s/ha-postgres.yaml`](../docker/k8s/ha-postgres.yaml) (Postgres `replicas: 3`,
> `[cluster].enabled`, PDB `maxUnavailable: 1`, lease-TTL-aware grace) + a `ha`-profile Postgres service in
> [`docker/compose.yaml`](../docker/compose.yaml); (2) Postgres-led [`docs/CLOUD-DEPLOYMENT.md`](CLOUD-DEPLOYMENT.md)
> (SQLite/single-node framed POC/edge); (3) the MLLP L4-LB recipe + (4) the hybrid edge-relay template (same
> doc); (5) [`docs/CLOUD-PHI-HIPAA.md`](CLOUD-PHI-HIPAA.md); (6) the raw-TCP/X12 startup TLS guard ratified
> as already-shipped (`check_tcp_tls_exposure`, PR #558) + the stale "unguarded" comments rewritten; plus a
> `kubeconform`/policy-lint CI leg ([`.github/workflows/manifest-lint.yml`](../.github/workflows/manifest-lint.yml)).
> The single-node manifest + default compose stay unchanged; no engine reliability code changed.

**Type:** deployment packaging + docs — the follow-ons that turn the shipped engine container (ADR 0017
fast-follow, PR #480) from single-node into a real cloud/Kubernetes deployment target. **Demand-gated, no
version target** — build when a cloud or k8s adopter actually materializes; nothing here is an exposure on
the on-prem shipping config.

**Context:** the engine image (slim + `-sqlserver`), a Topology-A `compose.yaml`, and a single-node k8s
StatefulSet shipped in PR #480. Cloud tiers **(a)** run-on-any-platform and **(b)** single-node are
**done**; the **(c)** multi-node HA tier is **code-complete but unpackaged** — the Postgres / SQL Server
staged backends + self-fencing leader election (`DbCoordinator` / `SqlServerCoordinator`, `/cluster/*`)
exist, but there is no example manifest, load balancer, or managed-DB wiring to copy. Full analysis +
competitor comparison (Mirth / IRIS / Corepoint / Rhapsody) + confidence caveats:
[`research/cloud-deployment-research-2026-06.md`](research/cloud-deployment-research-2026-06.md).

**What (ranked, when picked up):**
1. **Multi-replica HA reference manifest** — Postgres-backed `replicas: 3`, `[cluster].enabled=true`,
   PodDisruptionBudget `maxUnavailable: 1`, lease-TTL-aware `terminationGracePeriodSeconds`, plus a
   Postgres service in compose. Highest leverage (Mirth/IRIS ship the chart; we ship only the engine + docs).
2. **Lead cloud docs with managed Postgres** (RDS / Cloud SQL / Azure DB for PostgreSQL); frame
   SQLite/single-node as POC/edge only — SQLite + a ReadWriteOnce PVC physically blocks multiple replicas,
   and the `[cluster]` validator refuses the SQLite backend. (SQL Server stays the on-prem enterprise backend.)
3. **MLLP L4 load-balancer guidance** — one NLB listener per MLLP port with a **primary-only** TCP health
   check so the VIP follows failover; idle-timeout > socket keepalive; drain via `deregistration_delay`.
   Explicit **"no L7/HTTP ingress and no HPA for MLLP"** (sticky long-lived senders won't rebalance; it
   conflicts with FIFO / single-writer-per-lane — scale via parallel lanes / order-group sharding).
4. **Hybrid edge-relay topology template** — MLLP terminated near the EHR, forwarded over a private link
   (VPN / Direct Connect / ExpressRoute); the realistic on-prem-adopter cloud path, with the staged
   at-least-once store as the WAN buffer.
5. **Cloud PHI/HIPAA secure-architecture doc** — BAA, HIPAA-eligible services only, KMS-backed at-rest
   (RDS/EBS CMEK), region pinning, private subnets + PrivateLink, no public MLLP ingress.
6. **(small, do-anytime) startup TLS guard for raw-TCP / X12 listeners** (parallel to
   `check_mllp_tls_exposure`; today only MLLP / DICOM SCP / API are guarded) + flip TLS off-box log
   forwarding on in the prod-posture HA manifest.

**Strategic note (from the research):** invest *moderately* — make cloud a credible fast-follow via the
hybrid/edge topology; **do not chase a hosted SaaS** (a different business; the wedge is self-host control
+ no per-communication-point licensing). Container-readiness is now table stakes in evals and is largely
already delivered — the container pays off for on-prem + single-node regardless of how far the cloud path goes.

**Why deferred:** the near-term reality is on-prem-first, PHI, hospital-adopter-targeted; there is no cloud/k8s
adopter yet, and building the HA assembly kit before a real cloud feed validates the topology repeats the
exact speculative-build trap the connector/codec backlog is demand-gated to avoid.

**Source:** cloud-containerization research + codebase assessment (2026-06-22,
[`research/cloud-deployment-research-2026-06.md`](research/cloud-deployment-research-2026-06.md)); ADR 0017
container fast-follow (PR #480); [`CONTAINER-EXPOSURE-EVALUATION.md`](CONTAINER-EXPOSURE-EVALUATION.md).

---

## 42. `verify --smoke live` is ACK-only — add `--check-disposition` (post-ACK dead-letter catch) (P3)

> ✅ **SHIPPED — verified on `origin/main` (2026-07-09).** `messagefoundry verify --check-disposition` is in CHANGELOG and implemented in `verify/smoke.py` (`check_smoke_disposition`), wired as the `smoke.disposition` row.

**Type:** verify enhancement. **Source:** 0.2.1 on-box acceptance validation (2026-06-23).

`verify --smoke live` PASSes on any AA ACK and defers final disposition to the MANUAL console row, so a
message that **ACKs then dead-letters** (a bad transform, a delivery failure, or the service-identity
db-grant trap) still reports PASS. On a headless / CI acceptance run there is no console, so post-ACK
failures pass unnoticed. Proposal: an opt-in `verify --smoke live --check-disposition` (given
`--service-config`) that, after the ACK, polls the store for the sent message's final status and FAILs
unless it reached `PROCESSED`; default behavior unchanged.

> **Update (2026-06-23) — BUILT.** Implemented as a new `smoke.disposition` verify row: a pure
> `_classify_disposition` + a `check_smoke_disposition` store poll correlated by MSH-10 (with a
> baseline-id snapshot so a re-used synthetic control id can't match a prior run), wired through
> `run_verify` and the `--check-disposition` / `--disposition-timeout` CLI flags
> (`messagefoundry/verify/smoke.py`, `runner.py`, `__main__.py`).

---

## 43. `verify store.connect` runs as the calling user — it doesn't prove the service account (docs)

> ✅ **SHIPPED — verified on `origin/main` (2026-07-09).** `docs/testing/VERIFY.md` now carries the “runs as the calling user … does not prove the service identity” caveat.

**Type:** verify docs/emphasis. **Source:** 0.2.1 on-box acceptance validation (2026-06-23).

`verify --section store` opens the store from the verify process (interactive user / Administrator). On
integrated-auth SQL Server a sysadmin connection PASSes even when the NSSM service account lacks a
login/grant — a false-green vs the identity that will actually run the engine. `host.writable` already
MANUAL-flags the service-account ACLs; `store.connect` should carry the same caveat so a green
store-connect isn't read as "the service can reach the store".

> **Update (2026-06-23) — BUILT.** `store.connect`'s PASS detail now states it opened "as the calling
> user (NOT proof the NSSM service account can connect — confirm the service-identity grants)", and the
> load-bearing MANUAL disposition row is emphasized in [`docs/testing/VERIFY.md`](testing/VERIFY.md).

---

## 44. `protect-key` file DACL strips the service account — DPAPI machine-scope key path fails to start

> ✅ **SHIPPED — verified on `origin/main` (2026-07-09).** `store/store.py` grants an extra service principal (`NT SERVICE\…` or a SID) read on the DPAPI key file.

**Type:** correctness / Windows production key-at-rest — defeats a documented, recommended path (fails
closed; not a PHI leak). **Source:** 0.2.1 consumer-path validation on Windows Server 2025 / py3.14
(2026-06-24).

`protect-key` writes the DPAPI key file, then `_protect_key` calls `_secure_file(out)`, which on Windows
runs `icacls <file> /inheritance:r /grant:r <minting-user>:F` (`store/store.py`). `/inheritance:r` strips
the parent dir's inheritable service-account ACE and `/grant:r` leaves a single ACE for the interactive
operator who ran the command — **no ACE for the service account and none for SYSTEM**. At startup the
engine reads the file as its service principal (`open_store` → `resolve_active_key` →
`load_protected_key`), hits `PermissionError` → `DpapiError` → uvicorn "Application startup failed"
(fail-closed). This defeats the DPAPI **machine scope** the help text, `secrets_dpapi.py`, and
`docs/SERVICE.md` all promise ("so the service account can read the key at startup"); the install
script's inheritable `(OI)(CI)M` data-dir grant can't reach a file that ran `/inheritance:r`. Breaks
**both** a LocalSystem service and a virtual/gMSA account whenever the engine principal differs from the
minting operator. **Secondary:** the cross-account decrypt error blamed "same machine" even when the real
cause was a different USER (`--user` scope).

> **Update (2026-06-24) — BUILT.** `protect-key` now grants the service principal read on the key file:
> SYSTEM (`*S-1-5-18`) by default plus a new `--grant-account <principal>` (name or SID) for virtual/gMSA
> accounts, via a new `extra_read_grants` parameter on `_secure_file` (the generic store DB/WAL path stays
> owner-only). The `--user` decrypt error now names the same-USER case, and `docs/SERVICE.md` is corrected
> (the data-dir ACL does not cover the key file).

---

## 45. Per-store TLS CA-file knob for server-DB backends (trust a private DB CA without a machine-wide install) — on-trigger

> ✅ **SHIPPED (2026-07-12).** The shared `[store].ssl_root_cert` (a PATH, not a secret) now pins the DB server certificate on the secure posture (`encrypt = true`, `trust_server_certificate = false`) for **both** server-DB backends — never weakening verification: **Postgres** loads it as an asyncpg `ssl.create_default_context(cafile=…)` CA-bundle (`_build_ssl`, the already-shipped half), and **SQL Server** now appends the ODBC Driver **18.1+** `ServerCertificate={<brace-quoted path>}` keyword in `connection_string` (a leaf/exact-cert pin; STORE-5 brace-quoted). It is **rejected for SQLite** (no TLS) and a **missing file fails loud at load** (new existence validator); unset stays byte-identical. Docs: `docs/CONFIGURATION.md` `[store]` row + `docs/CONNECTIONS.md` + `docs/DEPLOY-SERVER-DB.md` §5; tests in `tests/test_store_ssl.py` (Postgres `_build_ssl` + SQL Server `connection_string`, both validated in CI). _(was 🔢 DEMAND-GATE · Value 4/10 · Difficulty 3/10.)_

**Type:** enhancement / ergonomics on the secure store-TLS path. **No security exposure** — the secure
default does real chain + hostname validation and any weakened posture fails closed
(`MEFOR_ALLOW_INSECURE_TLS` gate). **Source:** 0.2.1 consumer-path validation on Windows Server 2025 /
py3.14 (2026-06-24).

In the secure posture (`encrypt=true`, `trust_server_certificate=false`) both server-DB backends rely
solely on the OS/interpreter default trust store, with no per-store CA-file knob to trust a
private/self-signed DB CA. Postgres `_build_ssl` returns Python `True` (`store/postgres.py`) → asyncpg
builds a default verifying context (no `load_verify_locations`); SQL Server `connection_string` emits only
`Encrypt`/`TrustServerCertificate` (`store/sqlserver.py`), never ODBC Driver 18's `ServerCertificate=<pem>`
keyword; `StoreSettings` exposes only `encrypt`/`trust_server_certificate` (`config/settings.py`). So a
private-CA estate must install the DB CA machine-wide, which can nudge operators toward the insecure
escape (a usability-driven risk, not a vuln).

**Proposed fix (when triggered):** add one shared `StoreSettings.ssl_root_cert: str | None = None` (a
PATH, not a secret — may live in config / `connections.toml`; optional load-time existence validator). In
`postgres._build_ssl`, when set return `ssl.create_default_context(cafile=ssl_root_cert)` (keep
`check_hostname=True` / `CERT_REQUIRED`) instead of `True`; unset keeps `True` (unchanged). In
`sqlserver.connection_string`, when set and the secure posture holds, append
`ServerCertificate={_odbc_brace(ssl_root_cert)}` (brace-quoted, STORE-5-safe). Verify ODBC Driver 18
`ServerCertificate` semantics + minimum driver version on Windows Server 2025. Docs:
`docs/CONFIGURATION.md` + `docs/CONNECTIONS.md`; tests mirroring the existing TLS-posture tests.

**Why deferred (on-trigger):** Low value with no current private-CA-DB demand; building it before a real
estate hits the friction repeats the speculative-build trap the connector/codec backlog is demand-gated to
avoid. Build when a private-CA adopter is blocked.

---

## 46. Connection lifecycle event log — "established / lost / connecting / retrying" (Corepoint Transport-event parity)

> ✅ **SHIPPED in 0.2.3 (#541).** The unified metadata-only `connection_event` log + PySide6 console **Event
> Log** page are built (scoped 2026-06-25, shipped the next day in 0.2.3): inbound lifecycle (accept/close),
> the ADR 0021 §7 pre-ingress failures, outbound lane transitions, a `[diagnostics]` config block, `GET
> /events` + `GET /connections/{name}/events`, and the filterable Event Log viewer. Raw protocol trace (ADR
> 0020) stays declined. The original build-scope banner is kept below for history.

> **✅ Build scope (owner go, 2026-06-25): "logging like Corepoint."** Build a unified, metadata-only
> `connection_event` log capturing **inbound lifecycle** (established/closed) + the **ADR 0021 §7 failures**
> (allowlist/capacity/oversize/peer-reset/framing) + **outbound lifecycle** (connection_lost/restored,
> edge-triggered — no per-delivery spam), plus **Response Sent ACK/NAK** (ADR 0021 §§1-6, PHI, encrypted).
> **ON by default** for the no-PHI connection events (master `[diagnostics].connection_events`). Engine
> capture-first; the **console "Event Log" viewer is a committed fast-follow, NOT optional** — see
> *Console deliverable* below. Raw protocol trace (ADR 0020) stays declined. Build increments + the two
> confirm-items are in the 2026-06-25 plan.
>
> **Console deliverable (do NOT drop).** The point of "like Corepoint" is the *operator-facing* event log, so
> the engine increments are not "done" until the **PySide6 console Event Log page** ships: a filterable view
> (by connection / direction / kind / time) over `GET /events` + `GET /connections/{name}/events`, with the
> Corepoint-style Transport / Diagnostic / Alert / Misc filter, plus the Response-Sent ("ACK returned") view
> off `GET /messages/{id}/responses?kind=ack_sent`. This rides the **#22** console-page workstream (its natural
> home) — tracked there too so it can't fall through the gap between the engine work and the GUI work.

**Type:** feature — operational/diagnostic observability. Closely related to **#16** (Corepoint event-log
parity) — see *Relationship* below; this is the broader, happy-path slice #16's narrowed scope does **not**
cover.

**What:** MessageFoundry's technical log does **not** emit the routine per-connection lifecycle play-by-play
that Corepoint/Mirth surface under their **Transport** event filter — "connection established", "connection
lost", "trying to connect", "reconnecting". Today the connection layer is silent on the happy path and only
records the *exceptional* edges:
- **Inbound (MLLP/TCP listeners):** a successful client accept is **not logged** — only refusals
  (`source_ip_allowlist`), at-capacity (silent), frame-over-cap, and unexpected per-connection errors are
  ([`transports/mllp.py`](../messagefoundry/transports/mllp.py) `_serve_client`,
  [`transports/tcp.py`](../messagefoundry/transports/tcp.py)). When a peer connects and sends normally, the
  **message** is what's counted/dispositioned in the store — there is no "accepted connection from <peer>" event.
- **Outbound (delivery):** [`MLLPDestination`](../messagefoundry/transports/mllp.py) opens a **fresh connection
  per delivery** (connect → send → ACK → close), so there is no persistent connection to "lose" or
  "reconnect". A connect/IO failure becomes a `DeliveryError` → retry-with-backoff, and **each failed attempt
  is not written to the technical log** — the detail goes to the store row's `last_error`, surfaced to
  operators only via the `AlertSink` `queue_buildup` when a lane backs up
  ([`pipeline/wiring_runner.py`](../messagefoundry/pipeline/wiring_runner.py) delivery loop, the
  `except DeliveryError` arm). So there is no "trying to connect… refused… retrying" stream.

What the technical log *does* carry at connection level: engine/wiring lifecycle (`wiring started: N inbound,
M outbound`, `wiring stopped/reloaded`), connection-failed-to-bind (isolated, ADR 0031), worker
crashed/respawned, STOP-policy halts, and egress/connect allowlist denials.

**Proposed shape (when triggered):** a lightweight **structured connection *event* log — metadata only, no raw
bytes / no PHI** (peer, direction, connection name, transition, timestamp, reason) recording the lifecycle
transitions: inbound accept/close, outbound connect-attempt/connected/failed/retry-scheduled, and lane
stop/resume. Reuse the existing `AlertSink` seam + the planned lightweight connection-error event log from
#16's narrowed ADR 0020 scope rather than a second mechanism; emit-points are connector lifecycle hooks in
`transports/` (accept/close on the listeners; connect/send/close on the outbound) plus the delivery-worker
retry transitions in `wiring_runner.py`. Keep it **off-by-default / metadata-only** so it never reintroduces a
raw-PHI-at-rest tier (the exact reason #16 dropped ADR 0020's raw-frame capture).

**Relationship to #16:** #16's *retained* slice is **pre-message *failure* events that have no `message_id`**
(bad framing, TLS-accept failure, peer reset, allowlist refuse) + ADR 0021's "Response Sent" ACK/NAK capture.
This item is the complementary **happy-path connection-state lifecycle** (established / connecting / retrying /
lost) — the routine Transport-event transitions a successful connection goes through, which today are silent.
Build the two together (one event log, two event classes) if either is un-deferred, to avoid a split design.

**Why deferred (on-trigger):** no customer pull yet — internal Corepoint-checklist origin, same posture as
ADR 0020. Operator visibility for *failures* is already met via per-message disposition + `last_error` + the
`queue_buildup`/`connection_stopped` alerts; this adds **diagnostic** visibility of normal connection churn,
valuable mainly to operators migrating from an engine that shows it. Build when an adopter needs Corepoint-style
connection-event visibility. **Trigger:** a pilot/adopter asks for a connection-state/transport event log.

**Source:** session question 2026-06-25 ("do our connection logs show connection established / lost / trying to
connect?") — confirmed against `transports/mllp.py`, `transports/tcp.py`, and the `wiring_runner.py` delivery
loop; relationship to the #16 Corepoint event-log gap analysis (2026-06-17) + ADRs 0020/0021.

## 48. IDE "Insert Element" — grow the scaffold-snippet library + a most-used-idiom quick-pick (P2)

> ✅ **SHIPPED — verified against `origin/main` (2026-07-28).** Base (#595) **and** the L1 expansion (#794) are both on `main`, so the 🔶 "EXPANDING" note below is historical: `ide/snippets/messagefoundry.code-snippets` holds **36** snippets — **32** body-level idioms (past the ~30 L1 target) plus the 4 pre-existing module-frame scaffolds `meforinbound`/`meforoutbound`/`meforrouter`/`meforhandler`, which are not idioms — and `ide/src/insertElement.ts` provides the category quick-pick (`buildPicks`, `:42`) plus the `@router`/`@handler` cursor-context filter (`detectContext`, `:69`, applied at `:114`) that reads the *same* snippets file — one source of truth. Stays inside CLAUDE.md §12 / #26: the snippets emit **editable Python**, never a declarative surface. _(was 🔢 P3 · Value 4/10 · Difficulty 2/10.)_

> 🔶 **Base shipped (PR #595 — ~14 idioms + the `messagefoundry.insertElement` quick-pick); EXPANDING under [MULTISESSION-PLAN-7](releases/MULTISESSION-PLAN-7.md) L1.** L1 adds ~16 more editable-Python idioms (→ ~30: string format, `re.sub`, `match/case`, fan-out, `fhir_lookup`, non-HL7 body access, router idioms), surfaces *Insert Element…* in the editor-title dropdown + a keybinding + a discoverability CodeLens, and adds an `@router`/`@handler` cursor-context filter. Deterministic sibling for the AI `/transform` — see [`docs/AI-OFF-MATRIX.md`](AI-OFF-MATRIX.md). Stays inside #26 (emits editable Python, never a declarative surface).

**The code-first answer to Corepoint's Action-List "Add Action" palette.** Handlers and Routers are the core
authoring surface; developers repeatedly drop the same ~12–15 idioms (field copy, format, date convert, code
lookup, loop over repetitions, decision branch, `db_lookup`). Today's IDE scaffold snippets
(`meforinbound`/`meforoutbound`/`meforrouter`/`meforhandler`) jump-start the *module* frame but not the in-body
idioms — authors hand-type or hunt the docs. Grounded in a catalog of Corepoint's **71 Action-List actions**
(2026-06-27) mapped to our model: the pure `have`/`snippet` ones are exactly the high-frequency transform building
blocks (`ItemCopy`/`ItemFormat`/`ItemTransformDate`/`ItemCodeLookup`/`ForEach`/`If-Else`/`ChooseFrom`/`Filter`/
`MsgSend`/`MsgPass`).

**Proposed shape (code-first — NOT #26's declined visual/declarative builder):**
1. **Expand `ide/snippets/messagefoundry.code-snippets`** with ~12–15 *body-level* snippets that drop real,
   editable Python inside a handler — e.g. `ItemCopy` → `msg.set("${1:dest}", msg.field("${2:src}"))`;
   ForEach-reps → `for rep in msg.repetitions("${1:path}"):`; code lookup → `code_set("${1:name}").get(...)`;
   date → `convert_hl7_timestamp(...)`; a `db_lookup(...)` template; `return Send("${1:outbound}", msg)`.
2. **Add a `messagefoundry.insertElement` Command-Palette quick-pick** grouped by category (Field / Decision /
   Loop / Lookup / Date / Data source / Send), each choice inserting its snippet via `editor.insertSnippet()`.

Lean on the existing HL7-path completion (unchanged); assume handler-body context (the `newHandler`/`newRouter`
scaffolds still own the outer frame). No new editor toolbar or sidebar — one Command-Palette command, keybindable.

**Why this is not #26:** snippets drop **editable Python**, not declarative "configure-a-step" boxes — a typing
accelerator, not a builder. Reaffirms the code-first identity (the strategic failure mode #26 guards against).
**Effort:** S–M (snippets + one command + offscreen tests + `ide/README.md`). **Source:** Corepoint Action-List
"Add Action" palette review (2026-06-27) + the 71-action catalog / code-first mapping.

**Status / follow-up:** shipped in **#595** (14 body-level idiom snippets + a `messagefoundry.insertElement`
quick-pick that reads the same snippets file — one source of truth). Optional follow-up: also surface
*Insert Element…* in the editor-title MessageFoundry dropdown (#593) for discoverability — #595 ships it
Command-Palette-only by design.

## 49. Export-to-Support diagnostic bundle — PHI-safe (P3, on-trigger)

> ✅ **SHIPPED in 0.2.10 (Plan-5 Wave 1, PR #618).** A `messagefoundry support-bundle` CLI collects the engine
> version/uptime, a **secret-free** config summary (inbound/outbound/router/handler counts), a `GET /status`
> snapshot, and a redacted app-log tail — **no raw message bodies, no secrets** — run through PHI redaction
> before zipping. Original description kept below for history.

Corepoint's Console exports logs + config + version info for support escalation. We have no equivalent.
**Proposed shape:** a `messagefoundry support-bundle` CLI (and/or admin-gated, step-up `POST /support/bundle`)
that collects the engine version/uptime, a **secret-free** config summary (inbound/outbound/router/handler
counts), a `GET /status` snapshot (DB size, disk-free, row counts — already exposed), and recent **app-log**
lines, run through the existing PHI redaction before zipping. **No raw message bodies.** Good for the OSS support
story (a one-attach bundle for a GitHub issue). **Why on-trigger:** nice-to-have; pull forward when an adopter
must escalate a production issue. **Source:** Corepoint Service-menu + connection-log "Export to Support" review
(2026-06-27).

## 50. Operational-health gaps: app-log disk metering + a message-stall alert rule (P3)

> ✅ **SHIPPED in 0.2.9.** Both deltas built: **app-log disk metering** (`GET /status` now meters the app-log
> directory's disk usage alongside the DB) and a first-class per-connection **message-stall** alert rule
> (oldest-undelivered age crossing a configurable threshold) wired as an ADR 0014 rule. Original description
> kept below for history.

Most of Corepoint's Monitor Health/Metrics surface is **already built** — `GET /status` carries DB `size_bytes` +
`disk_free_bytes`; the Connections dashboard carries per-connection `queue_depth`/`idle`/`delivered_age`/`errored`;
the ADR 0014 alert engine already ships `queue_buildup`/`connection_stopped` rules. Two small deltas remain:
- **App-log storage metering** — meter the app-log directory's disk usage (`shutil.disk_usage` / `pathlib.stat`)
  and surface it in `GET /status` alongside the DB size, so operators see log-disk growth (Corepoint's
  "Application Log Storage" health tile). Distinct from retention **#34** (which prunes the *store*).
- **Message-stall alert rule** — a first-class alert when a connection's oldest-undelivered age (`delivered_age`)
  crosses a per-connection threshold (Corepoint's "Max Message Stall"). The metric already exists; this just binds
  it as an ADR 0014 rule.

**Effort:** S each. **Source:** Corepoint Monitor Health + Metrics review (2026-06-27).

## 51. Message-content search — HL7 field-path / raw-content matching in Log Search (P3)

> ✅ **SHIPPED in 0.2.10 (Plan-5 Wave 2, PR #624).** First slice built per [ADR 0046](adr/0046-message-content-search.md)
> (Accepted): **scan-and-decrypt-per-row** (the store is AES-GCM-encrypted at rest, so a plain `LIKE` is
> impossible) — metadata-pre-filtered, hard row/result caps, decrypt off the event loop, behind `messages:view_*`
> + step-up + a `message_search` audit row that never logs the needle. The cleartext key-field index was
> **declined** (PHI-at-rest); a keyed-token (HMAC) field-path index is a deferred 2nd slice.

Corepoint operators search the message store by **content** ("PID-3 = A123456", "OBX-3 contains K7"). Our Log
Search filters on metadata (status / time / channel / control-id) plus the per-message parse tree, but not by
field-path/content **across** the store. **Proposed shape:** extend the `/messages` query with a content filter —
start with a bounded raw-substring match, escalate to structured `HL7-path = value` if a field index is added.
**Needs an ADR** on the indexing strategy (scan raw vs. pre-index key fields) and on **PHI-query auditing** (every
content search touches PHI → audit + step-up + a bounded result count, reusing the existing message-access gates).
**Why deferred:** indexing design + PHI-audit implications; pull forward when an operator needs clinical-content
search. **Source:** Corepoint connection-log "Message Filters (HL7 path = value)" review (2026-06-27).

## 53. Dual-control `config:deploy` — require a second approver for a reload (ADR 0041 D2) (P2)

> ✅ **SHIPPED in 0.2.9 (ADR 0041 D2).** `config_reload` is now a gateable `[approvals].operations` op — a
> distinct second approver must release a live reload (the requester can never self-approve; both identities
> land in the hash-chained audit). Opt-in / deny-by-default, so single-operator deployments are unchanged.
> Original description kept below for history.

`POST /config/reload` is the broadest-blast-radius runtime action (it swaps the entire live graph, including any
planted code) yet is gated by step-up re-verification **only** — a single re-authenticated operator applies it
alone. The dual-control maker-checker machinery already exists ([`api/approvals.py`](../messagefoundry/api/approvals.py),
used today for bulk dead-letter replay + connection purge); `config:deploy` is simply not in the gated set.
**Shape:** add `config_reload` to the configurable `[approvals].operations`, so a **distinct** second approver
releases it (the requester can never self-approve; both identities written to the hash-chained audit). **Opt-in /
deny-by-default** — single-operator deployments are unchanged until enabled. Pairs with the ADR 0041 D1 fingerprint
(the approver sees *which bytes* they are releasing). **Source:** insider-code-tampering review (2026-06-27);
[ADR 0041](adr/0041-load-path-attestation-and-change-attribution.md) D2.

## 54. Startup engine self-attestation vs `dist-info/RECORD` + enforced non-editable wheel (ADR 0041 D3) (P2)

> ✅ **SHIPPED in 0.2.9 (ADR 0041 D3 / ADR 0017 amendment).** At startup the engine hashes its loaded modules
> against the wheel's `dist-info/RECORD`; on drift it writes a hash-chained, off-box-teed `startup_integrity`
> audit row + raises an alert (alert-only by default; opt-in `[integrity].fail_closed_on_drift` refuses to
> start). A no-op on an editable (`pip install -e .`) install. The non-editable, hash-locked wheel is now the
> enforced production default. Original description kept below for history.

Install-time supply-chain integrity (hash-pinned `requirements.lock`, SLSA provenance, Sigstore signing) is never
re-checked against the *running* bytes, so an admin with venv-write + restart rights can edit installed
`messagefoundry` code in place (e.g. neuter `field_authz` redaction or the off-box audit tee) and it runs with **no
audit row at all** — `messagefoundry verify` checks host/flow and `integrity-check` checks the DB, neither checks the
code. **Shape:** at startup (and on demand) hash the loaded engine module files against the wheel's
`*.dist-info/RECORD` (a zero-new-artifact baseline already shipped in the wheel); on drift, **fail-closed or alert
(policy-driven)** and write a `startup_integrity` row to the hash-chained, off-box-teed audit. Tighten
[ADR 0017](adr/0017-consumer-deployment-model.md)'s non-editable, hash-locked wheel from recommendation to the
**enforced production default** (retire editable `pip install -e .` from prod docs); the attestation must be a
no-op/advisory off an editable dev install so it never bricks development. **Source:** insider-code-tampering review
(2026-06-27); [ADR 0041](adr/0041-load-path-attestation-and-change-attribution.md) D3.

---

## 52. Corepoint capability-parity gaps — prioritized roadmap input (2026-06-27)

> ✅ **Synthesized into numbered candidates (2026-06-28).** The NEW (untracked) gaps below were promoted to **#65–#85** (1 do-next · 14 demand-gate · 3 declined-by-design · #77 tombstoned as already-built), each adversarially reviewed against the code-first/on-prem identity. #52 stays the cross-reference index; the per-item entries are the source of truth.

> 🔎 **Extended by a help-export coverage sweep (2026-07-09) → items #107–#142.** The analysis above was built from the product's capability surface; a five-pass sweep of the **v8.1.0 HTML help export** (1,569 pages) then found **36 further capabilities** absent from both this analysis and the backlog — **8 moderate · 28 minor, and no new MAJOR gap**. Narrative + a post-mortem of one void (prompt-biased) pass: `marketing/corepoint-gap-analysis-addendum.md`.

> 🧭 **Coverage audit (2026-07-09) → items #143–#184. Every gap in this analysis now has a disposition.** All **246** capabilities were triaged against **current `origin/main`**: **55 already shipped · 77 already tracked · 50 declined-by-design · 7 not-a-gap · 55 open+untracked (→ 42 distinct, filed as #143–#184)**.
>
> ⚠️ **This analysis is ~22% obsolete — do not read it as current.** A fifth of it describes work that is done. Its three **MAJOR** rows today: (1) *REST/SOAP/FHIR inbound listener* — **partially closed**; the generic HTTP body-POST source shipped (ADR 0023 first slice, 0.2.10), typed REST-IN/SOAP-IN/FHIR-IN remain deferred, so **#7** stays open. (2) *Operator alert state* — **closed** (**#56**, ADR 0044). (3) *Turnkey DR* — **partially closed**; standby **#61** done (ADR 0048), config-tier backup/restore-verify **#60** open. Also shipped since: **#20**, **#32**, **#34**, **#35**, **#46**, **#47**, **#49**, **#50**, **#51**, **#57**, **#58**, **#59**.
>
> **No MAJOR gap remains unaccounted for.** The 42 new items are **12 moderate · 30 minor**; severity follows this analysis's own rating wherever it rated the row (an automated pass tried to promote Direct/HIE to *major* and was overruled back to *minor* — 11 such disagreements reconciled). Together, **#107–#142** (newly discovered) + **#143–#184** (this analysis's untracked gaps) make the Corepoint parity surface **fully tracked**.

**Type:** competitive analysis → roadmap input (not a single build). A capability gap analysis of
**Corepoint Integration Engine v8.1.0** vs MessageFoundry: **393 distinct capabilities**, each classified
**HAS / PARTIAL / GAP / EXCEEDS / DECLINED** and **grep-verified against the codebase**.
Tally: **HAS 133 · PARTIAL 147 · GAP 65 · EXCEEDS 27 · DECLINED 21**. Full report (local-only, gitignored):
`marketing/corepoint-gap-analysis.md`.

This item is the **tracking anchor + cross-reference index**; promote individual rows below to their own
numbered items as they're scheduled. Each line notes whether it maps to an **existing** backlog item/ADR or
is a **NEW** candidate.

**Major gaps (buyer-visible).**
- **Inbound HTTP/REST/SOAP/FHIR listener** — no message-ingest HTTP surface; outbound clients only; the lone
  HTTP surface is the loopback management API. *Already tracked:* **#7** (inbound HTTP listener) + ADR 0023
  facade; FEATURE-MAP REST-IN/SOAP-IN/FHIR-IN deferred.
- **Operator alert *state*** — active-vs-unresolved alert instances, acknowledge/resolve/suspend, escalation
  tiers, content-based (Action-Point) alerting, day/time-aware thresholds. `alerts_active` is hard-stubbed to
  0 (`api/models.py:250`). *Partly bounded by ADR 0014 (alerting scope); the resolvable-alert-state + escalation
  model is **NEW** candidate work.*
- **Turnkey disaster recovery** — engine-managed scheduled/on-demand backups, standby failover/failback, DR
  reports. Today: config DR = redeploy-from-git, DB DR delegated to the DBA. **NEW** candidate.

**Moderate-gap clusters.**
- **Declarative HL7 modeling** — persistent custom message-definition model, derivatives/inheritance tree,
  conformance tester + auto-repair (Fix-All), CDA/C-CDA/HL7-v3, NCPDP. *XML/CDA partly **#31**; X12-strict/999
  **#32**; the custom-definition + derivatives + NCPDP pieces are **NEW**.* (MeFor works at the data layer; this
  is the code-first identity, but real migration friction for modeling-heavy estates.)
- **Correlation object UX** — first-class bidirectional multi-partner *correlation* artifact, auto-match-by-
  description, qualified/non-singular correlations, visual correlation editor (plain code sets/lookups **are**
  covered — ADR 0006). **NEW**.
- **Operational / monitoring** — browser/web monitor (MeFor console is PySide6 desktop), host/system metrics
  (CPU/mem/SQL internals), historical metrics charting, live status-colored data-flow graph, bulk/multi-select
  console connection control. *App-log disk metering + message-stall alert = **#50**; HL7-path/content log search
  = **#51**; per-connection start/stop **API already exists** (`POST /connections/{name}/start|stop|restart`).
  Web monitor + host metrics + historical charts + bulk console control are **NEW**.*
- **DB & web-service breadth** — Oracle / MySQL / generic-ODBC-DSN; stored-proc OUT/return-value binding;
  WSDL import → type-tree + validate-against-WSDL; synchronous in-transform WSCall (vs MeFor's pure-transform
  invariant); generic OAuth2-client-credentials / Digest / NTLM; FHIR search/read + CapabilityStatement;
  dynamic per-message HTTP headers. *FHIR base = **#20** / **#35**; Oracle/MySQL = FEATURE-MAP "Later"; the rest **NEW**.*
- **Security** — user-definable custom RBAC roles (6 fixed roles + per-channel scope today); PKCS#12/.pfx cert
  import + cert inventory + trust-flag UX (PEM-only today); self-signed cert generation; explicit FIPS-mode
  attestation. **NEW** (openssl/PKI-replaceable).

**Minor gaps (summarized — full list in the report).** sender inter-message pacing; MSA-2↔MSH-10 response
matching; FTPS implicit/active-passive + SFTP keyboard-interactive; TCP keep-alive/persistent-reconnect;
rich file-output disposition (archive-to-dated-subfolder, append, header/trailer, enqueue-empty toggle);
SMTP/POP3-IMAP mail + S3/cloud-blob + JMS transports; HL7 timestamp/age/LOS helpers; integrated hex +
profiling/coverage panes + HL7-aware before/after diff; inbound ACK/NAK persistence (*ADR 0021 / **#16***);
per-connection retention windows (***#34***); embedded-doc pruning (***#47***); Export-to-Support bundle
(***#49***); auto-generated interface docs; searchable in-product KB; edit-a-stored-message-before-resend
(*tension with the purity/at-least-once invariant — bordering on declined*).

**Declined by design (NOT gaps).** No-code / visual / template-driven authoring (***#26***, CLAUDE.md §12);
the "channel"/"route" bundling element — hence no Org→App→Connection hierarchy/health-roll-up or subscription
pools (CLAUDE.md §1); side-effecting / synchronous-external-call transforms incl. CommandLineCall/COM (purity
invariant; sole carve-out = read-only `db_lookup`, ADR 0010); license-key / per-seat gating; active-active
horizontal scale-out (dropped 2026-06-18); DB-tier backup/HA/restore mechanics (delegated to the DBA);
serial / ASTM lab-instrument connectivity (***#27***).

**Where MeFor already exceeds Corepoint (so gaps stay in context).** Broker-free transactional staged
at-least-once pipeline; full-Python transforms (superset of the action-list DSL); git-native config/repository;
hash-chained tamper-evident audit + off-box PHI-redacted SIEM tee; Prometheus/OTel telemetry; DICOMweb STOW-RS
+ SMART Backend Services (neither shipped by Corepoint); a real debugpy step-through debugger + Test Bench;
fail-closed de-identification framework (ADR 0030). Across the great majority of the 16 domains MeFor matches
or exceeds Corepoint — the gaps concentrate in inbound-HTTP, operator-alert-state, declarative
modeling/correlation UX, and packaged DR/ops tooling.

**Caveat.** Capability **presence ≠ production maturity** — a HAS/PARTIAL marks that a code-first or built
mechanism exists, not that it is hardened or feature-complete to Corepoint's depth. Where the models differ
structurally (code-first vs no-code; flat by-name graph vs object hierarchy; one store vs four DBs; git vs
proprietary repository), "equivalent" means the buyer-facing *outcome* is met even when ergonomics differ.

**Source:** owner request (2026-06-27) — identify the capability gaps between Corepoint and MessageFoundry.
Per-domain gap classification, grep-verified against the codebase, with adversarial review. Relates to
**#7**, **#16**, **#20**, **#26**, **#27**, **#31**, **#32**, **#34**, **#35**, **#46**, **#47**, **#49**,
**#50**, **#51**, and ADRs 0010 / 0014 / 0021 / 0023.

## 55. CI: intermittent `windows-2022` pytest hang — whole job times out at the 15-min cap (P2)

> ✅ **SHIPPED in 0.2.9.** Fixed: `MLLPSource`/`TcpSource`/`X12Source` no longer `await wait_closed()`
> unbounded on the Windows Proactor loop during teardown (the stall class below), plus the CI guards from
> the proposal — a per-test `faulthandler` stack dump and a step-level no-output watchdog so a future hang
> fails fast and names itself instead of silently timing out at 15m. Original investigation kept below for history.

**Symptom:** the `test (windows-2022, py3.14)` leg **intermittently hangs ~25% into the suite** and emits **no
further output for ~12 minutes** until the job hits its 15-minute cap and is cancelled — a red ✗, not a test
assertion failure. `pytest-timeout` does **not** fire, so the hang is something its (thread-based) method can't
interrupt on Windows — a blocking syscall / socket-accept / subprocess wait rather than a Python-level deadlock.
The other legs (`ubuntu`, `windows-2025`) pass.

**Evidence (2026-06-27):** PR #596 — a **one-line `BACKLOG.md` edit** — timed out on `windows-2022` **twice**
(run 28296717204, original + a `--failed` re-run), each at exactly 15m. The same suite **passed** on
`windows-2022` for #595 minutes earlier (~5m34s). Last pytest progress line at `[ 25%]` (17:58:28), then silence
to `##[error]The operation was canceled.` at 18:10:26. #596 was ultimately **admin-merged** past the flaky check.

**Impact:** flaky red on **unrelated** PRs (incl. docs-only); because `windows-2022` is a **required** check it
wedges merges until a re-run happens to pass or an admin override is used (~15 min burned per hang).

**Prior art:** the resolved/obsolete **#17** (the old `py3.11` leg hang — a CPython 3.11 asyncio cancellation
race in `TeeRelay.stop()`, fixed via a sentinel shutdown; the py3.11/3.13 legs were since removed). This is a
**new** occurrence on `windows-2022` / py3.14 — same *class* (a Windows asyncio/socket hang `pytest-timeout`
can't interrupt), different test.

**Proposed (when picked up):**
1. **Surface the culprit** — add a tight per-test `--timeout=<n>` so a hang **fails that one test fast** and
   names it instead of silently cancelling the whole job at 15m; dump a `faulthandler` traceback on timeout to
   pin the stuck frame. (Note the limits of `--timeout-method=thread` on Windows: a true socket-accept hang is
   not interruptible by it.)
2. **Find + fix the test** — the stall is ~25% into collection order on `windows-2022`; likely an MLLP/TCP
   listener or subprocess test whose teardown wedges on that runner. Make its teardown forcibly cancel + close
   the listener (the #17 sentinel-shutdown pattern).
3. **CI guard** — a step-level no-output watchdog that fails the job well before 15m so a flake doesn't burn the
   full budget.

**Priority:** **P2** — intermittent, but a *required* check that wedges unrelated PRs. **Source:** #596 CI
investigation (2026-06-27).

---

## 47. Embedded-document (base64 attachment) pruning — strip OBX-5 / `mfb64:` blobs after a per-connection window (Mirth attachment-handler parity) (P2)

> ✅ **SHIPPED in 0.2.9 (ADR 0042 Accepted).** Optional `prune_documents_after` (+ a size threshold) per
> inbound connection: after the window, base64 embedded documents — HL7 **OBX-5 ED** and the generic
> `mfb64:v1:` carriage (ADR 0028) — are stripped **in place** to a small size/content-type tombstone (via
> the parsed model/codec, never string-slicing HL7), keeping the rest of the message parseable; the row is
> never deleted and a `documents_pruned` flag is set. All three backends; one audit row per pass. (The
> ingest-time offload variant **(b)** stays deferred to a future ADR.) Original description kept below for history.

**Type:** feature — selective PHI/storage minimization. Large **base64-encoded embedded documents** (PDF
reports, CCD/C-CDA, scanned images) ride inline in messages — in HL7 they arrive in **OBX-5** (ED data
type), and generically anywhere via the ADR 0028 `mfb64:v1:` carriage marker
([`adr/0028-base64-binary-carriage-codec.md`](adr/0028-base64-binary-carriage-codec.md)). These blobs are
often tens to hundreds of KB each and are stored verbatim in the raw message at **every** persisted stage
(`ingress` → `routed` → `outbound`), so a chatty document feed bloats the store far out of proportion to
its message *count*. The ask: let **each connection** carry a setting to **purge just the embedded
documents** after a timeframe, keeping the rest of the message (segments, fields, metadata, disposition)
intact.

**Gap today.** Retention is all-or-nothing on the whole body: the global `RetentionRunner`
([`pipeline/retention.py`](../messagefoundry/pipeline/retention.py)) calls `purge_message_bodies`
([`store/store.py`](../messagefoundry/store/store.py)), which **nulls the entire raw body** keep-metadata,
store-wide, by message age only. There is no way to evict *only the bulky attachment* while preserving the
surrounding HL7 (the segments an operator still wants to see), and no per-connection window (that broader
gap is **#34**). Nothing offloads the blob at ingest either — it rides the pipeline inline.

**What Mirth does (researched 2026-06-26).** Mirth solves this with **two** complementary mechanisms, and
it's worth deciding which we mirror:
- **Attachment Handler (offload at ingest).** A per-channel handler on the source connector extracts bulky
  embedded content *before* the message is stored/transformed — e.g. a **Regex** handler pulls the base64
  PDF out of OBX-5, a **DICOM**/**JavaScript**/**Custom** handler for other shapes. The extracted bytes go
  to a **separate attachment table** (`d_ma<channelId>`) and the inline blob is replaced in the message by
  an **attachment token** (`${ATTACH:...}`); it's reattached on the outbound via the same token. A Base64
  decode option ([MIRTH-2799](https://www.mirthcorp.com/community/issues/si/jira.issueviews:issue-html/MIRTH-2799/MIRTH-2799.html))
  stores the *decoded* bytes, not the base64 string. This keeps the main message rows small and avoids
  loading the blob through every transformer step — the recommended lever to bound DB growth.
- **Data Pruner (prune after a window).** A scheduled task prunes message **content** and **metadata** on
  *independent* clocks per channel's Message Storage settings — e.g. keep metadata indefinitely but prune
  content (incl. attachments) after 1 day. Attachments live in their own tables and are pruned with the
  content. Pruning runs only when the scheduler is enabled, and *which* messages prune is governed by the
  per-channel storage/`max_message_age` settings.
  *(Sources: [Zen Healthcare — The Data Pruner](https://consultzen.com/mirth-connect-tutorial-data-pruner/);
  [NextGen — Message Pruning Settings](https://docs.nextgen.com/en-US/mirth%C2%AE-connect-by-nextgen-healthcare-user-guide-3273569/message-pruning-settings-14245);
  [CapMinds — high-volume CCD/C-CDA channels](https://www.capminds.com/blog/optimizing-mirth-connect-channels-for-high-volume-ccd-c-cda-document-workflows/).)*

**Design fork (for the ADR).** The user's literal ask is the **prune-after-a-window** half (Mirth's Data
Pruner, attachment-scoped). The more impactful half is **offload-at-ingest** (Mirth's Attachment Handler),
which stops the bloat at the source instead of carrying it through three stages first. Decide whether to
build (a) an in-place **selective strip** of the embedded document after a per-connection window — cheaper,
matches the request, but the blob still bloats the store until the window elapses and is duplicated across
stages meanwhile; (b) an **ingest-time offload** to a separate attachment store with a placeholder marker
(true Mirth parity, bounds growth from the start, but a larger build touching the pipeline + a new store
table + reattach-on-outbound); or (c) both, with (a) as the near-term increment.

**Scope (when built — increment (a)):**
- A **per-connection `prune_documents_after` window** (with an embedded-doc size threshold), layered over a
  global default — the same **global-default + per-connection-override** model used for FIFO,
  `RetryPolicy`, `BuildupThreshold`, and proposed for **#34** retention. Author it on the inbound
  `ConnectionSpec` and/or as `connections.toml` keys (ADR 0007) so it stays hand-/GUI-editable.
- A new store purge path (sibling to `purge_message_bodies`) that **rewrites the stored raw in place**,
  replacing each embedded document with a small **placeholder/tombstone** (size + content-type + a
  "pruned <ts>" marker) while leaving the rest of the message byte-stable. Target both carriage forms: the
  generic `mfb64:v1:` marker and HL7 **OBX-5 ED** embeds. **Never string-slice raw HL7** (CLAUDE.md §8) —
  edit via the parsed model / codec and re-encode. Must land on **all three** backends (SQLite / Postgres /
  SQL Server).
- Preserve every invariant: **never delete the row** (counts / disposition / audit stay intact), the
  message remains parseable after the strip, and emit **one audit entry per pass** recording the
  per-connection window + counts + bytes reclaimed (no message content). Pruning a document is irreversible —
  surface it as a distinct disposition/flag so an operator viewing the message knows the attachment was
  evicted vs never present.

**Out of scope / leave to siblings:** whole-message retention windows and dead-letter pruning are **#34**
(this is the *document-only*, finer-grained cut — they should share the per-connection-override plumbing).
`audit_days` stays keep-forever. The ingest-time offload (fork (b)) is its own ADR if pursued.

**Why P2 / on-trigger.** Real document feeds (radiology results with embedded PDFs, CCDs) are exactly where
store bloat bites, and PHI data-minimization wants the bulky attachment gone on a *shorter* clock than the
clinical metadata — a standard Mirth operator expectation. But it's not an open exposure on the shipping
config and wants an ADR (the design fork above) before code. **Trigger:** a feed carrying large OBX-5 / base64
embedded documents whose volume bloats the store. Relates to **#34** (per-connection retention — shared
override plumbing), **ADR 0028** (base64 carriage), and **#21**/**#33** (per-connection observability /
config-UX).

**Source:** owner request (2026-06-26) — "let each connection purge base64 embedded documents (OBX-5 in
HL7, or other message types) after a timeframe; they bloat the logs — research what Mirth does." Mirth
attachment-handler + data-pruner behavior researched the same day (citations above).

---

## 56. Operator alert-state — resolvable alert instances (ack / resolve) + a real `alerts_active` count (Corepoint parity) (P2)

> ✅ **SHIPPED in 0.2.10 (Plan-5 Wave 2, PR #624).** The `alert_instance` table (3 backends), `GET /alerts/active`
> + ack/resolve (RBAC `MONITORING_DIAGNOSE`), the real `ConnectionRow.alerts_active` count, and a console Alerts
> tab are built — [ADR 0044](adr/0044-operator-alert-state.md) (Accepted). See
> [`releases/MULTISESSION-PLAN-5.md`](releases/MULTISESSION-PLAN-5.md) Lane L7.

**Type:** feature — operator monitoring. Today alerts are stateless emit-points (ADR 0014) and the
`ConnectionRow.alerts_active` field is **stubbed `0`**. Add a persisted `alert_instance` store table
(open / acknowledged / resolved + first/last-seen + count) de-duped on the existing `_emit` throttle key,
`GET /alerts/active` + ack/resolve endpoints (RBAC `MONITORING_DIAGNOSE`), the real `alerts_active` count,
and a console Alerts-page tab. **Metadata only — no new at-rest PHI tier.** Surfaced by the #52 Corepoint
parity gap analysis.

---

## 57. User-definable custom RBAC roles over the existing Permission catalog (Corepoint parity) (P2)

> ✅ **SHIPPED in 0.2.10 (Plan-5 Wave 2, PR #624).** Admin-defined custom roles (permission subset, no new
> kinds) persisted via an additive `roles` migration on all 3 backends, gated by `USERS_MANAGE`; built-ins stay;
> narrowing revokes on live sessions — [ADR 0045](adr/0045-custom-rbac-roles.md) (Accepted). See
> [`releases/MULTISESSION-PLAN-5.md`](releases/MULTISESSION-PLAN-5.md) Lane L8.

**Type:** feature — RBAC. Today there are **6 fixed built-in roles**. Add admin-defined named roles, each a
chosen **subset** of the existing `Permission` catalog (no new permission kinds), persisted via a `roles`-table
migration across all three backends (SQLite + Postgres + SQL Server), gated by `USERS_MANAGE`; the built-ins
stay; custom roles are an additive overlay; deny-by-default preserved. Surfaced by the #52 Corepoint parity
gap analysis.

---

## 58. FHIR client read / search lookup — `fhir_lookup` (read-only, like `db_lookup`) (P2)

> ✅ **SHIPPED (Plan-5 Wave 1, PR #618, 2026-06-27).** `fhir_lookup(connection, query)` is built — a read-only
> GET / search that extends the `db_lookup` carve-out to FHIR ([ADR 0043](adr/0043-fhir-read-lookup.md),
> Accepted), off the event loop, raises on a Router / in dry-run. See
> [`releases/MULTISESSION-PLAN-5.md`](releases/MULTISESSION-PLAN-5.md) Lane L2.

**Type:** feature — live enrichment. The FHIR client (ADR 0022) is **write-only** today. Add a handler-callable,
read-only `fhir_lookup(connection, query)` (read-by-id GET / search) that **extends** the ADR 0010 `db_lookup`
carve-out to FHIR: reuses the SMART Backend bearer (ADR 0024) + `[egress].allowed_http`, runs off the event
loop, raises on a Router / in dry-run, re-run-divergent by design (read-side only). GET-only — writes stay on
`FhirDestination`. Surfaced by the #52 Corepoint parity gap analysis.

---

## 59. HL7 timestamp / age / length-of-stay helpers on `Message` (P3)

> ✅ **SHIPPED (Plan-5 Wave 1, PR #618, 2026-06-27).** `Message` now exposes age-from-DOB, length-of-stay, and
> the tolerant HL7-TS parse (reusing `timezone.py`, no duplicate parser). See
> [`releases/MULTISESSION-PLAN-5.md`](releases/MULTISESSION-PLAN-5.md) Lane L1.

**Type:** feature — transform ergonomics. **`messagefoundry/timezone.py` already provides the tolerant
HL7-TS→`datetime` parse** (`_parse_hl7_timestamp` / `convert_hl7_timestamp` / `to_zone`); this item adds only
the **new** helpers (age-from-DOB, length-of-stay between two timestamps, an `hl7_now()` / TS-format if missing)
and surfaces the existing parser on the `Message` surface. MSH-encoding-aware, **no I/O**, console-importable
(§4 carve-out). **Do not** build a duplicate parser. Surfaced by the #52 Corepoint parity gap analysis.

---

## 60. Turnkey disaster recovery — scheduled config/store backup + restore-verify (config-tier slice) (P3, owner decision)

> ✅ **SHIPPED — verified on `origin/main` (2026-07-09).** **CHANGELOG: “Turnkey DR backup + restore-verify (#60, [ADR 0049](adr/0049-turnkey-dr-backup-restore-verify.md))”** — `messagefoundry backup` / `restore-verify` CLI ships, off by default (`[backup].enabled = false`). This item's banner was never updated, which caused it to be reported as OPEN in PR #850's `#52` anchor — corrected there.

> 📌 **PRE-RESERVED (Plan-5, 2026-06-27).** See [`releases/MULTISESSION-PLAN-5.md`](releases/MULTISESSION-PLAN-5.md)
> §G (deferred tail). **Owner-gated** (backup cadence / retention / restore-verify posture).

**Type:** operations — DR. An engine-managed scheduled backup of the config bundle + store (config-tier slice
first) with a restore-verify pass. Tracked for a future wave; **not staffed** until the owner sets the backup
cadence / retention / restore-verify posture.

---

## 61. Third-tier DR standby — right-sized box that takes over when the HA pair fails, running only high-priority feeds (P3, owner decision)

> ✅ **DONE — ratified as [ADR 0048](adr/0048-third-tier-disaster-recovery-standby.md) (Accepted
> 2026-06-28) and built (#641).** A **third recovery tier** *below* the shipped active-passive HA — distinct from **#60**
> (scheduled backup + restore-verify) and from the v0.1 HA failover. Owner DR posture: **cold-seed from
> #60 · manual activation · cold standby · feed-priority tiers**. Shipped: a per-connection **`priority`
> tier** (critical/normal/low + `[dr].priority_threshold`), a **DR run-profile** (on activation, start
> only feeds ≥ threshold; the rest report `status:"filtered"`) with an **acquire-VIP-or-abort** fence,
> **cold-seed-from-#60** (restore + verify a `.mfbak`, fail-closed, new audit-chain segment), and a
> **`dr:operate`** permission gating `POST /dr/activate`|`/dr/release`. SQLite split-brain accepted
> (VIP-or-abort + manual pair-down are the fence). **This was the final PLAN-6 lane.**

**Type:** operations — disaster recovery (site / HA-pair-loss tier).

**What:** a **right-sized DR box** that takes over when the **HA setup itself fails** — i.e. the primary
*and* its active-passive partner are both gone (whole-site / shared-store loss, e.g. the production database
goes down), not just a single engine-process crash. The DR server is intentionally **under-provisioned** — a
small box, not a second full-size hot standby that mostly sits idle — so DR survivability doesn't require
provisioning duplicate full-capacity hardware. On activation it brings up only a **prioritized subset** of
connections — the **high-priority feeds** — and runs in a deliberately **degraded mode**, accepting reduced
throughput/coverage as the cost of cheap DR.

**The three tiers (this item = tier 3):**
1. **Primary** — normal operation.
2. **Active-passive HA (shipped, v0.1)** — same-tier engine failover at *full* capacity; DB-tier HA delegated
   to the DBA. Handles a node failure, **not** loss of the whole HA pair/site.
3. **Third-tier DR (this item)** — a smaller box elsewhere that activates only when tier 2 is also gone, and
   runs *less* (high-priority feeds only), not more.

This is **not** active-active scale-out (dropped 2026-06-18, code removed) — DR here runs a *reduced* feed
set on smaller hardware, the opposite of scale-out. It would **consume #60's backups** (or DB replication
delegated to the DBA) to seed the DR store; #60 is the backup/restore mechanic, this is the
**standby-takeover + degraded-operation** mechanic on top of it.

**New building block this needs — a per-connection priority tier.** For DR to "run only the high-priority
feeds," each Connection needs a **priority / DR-tier** classification (e.g. `priority = critical|normal|low`
or explicit `dr_profile` membership), layered as the same **global-default + per-connection-override** model
used for FIFO, `RetryPolicy`, `BuildupThreshold`, per-connection retention (**#34**), and embedded-doc
pruning (**#47**). Authored on the `ConnectionSpec` and/or as `connections.toml` keys (ADR 0007) so it stays
hand-/GUI-editable. A **DR run-profile** is then "start only connections at tier ≥ X" — leaning on the
per-connection start + startup fault-isolation path already built (ADR 0031). The priority signal is reusable
beyond DR (load-shedding, ordered startup, alert severity).

**Open questions for the ADR:**
- **How the DR box gets state** — DB replication to the DR site (delegated to the DBA, consistent with the
  declined "DB-tier backup/HA/restore" stance) vs. restore-from-#60-backups; the warm/cold choice sets RPO/RTO.
  The engine owns the feed-priority + selective-startup half, not the DB-replication half.
- **Activation trigger & arbitration** — who declares the HA pair down and promotes DR (manual runbook vs.
  automated probe), and how split-brain is prevented so DR and a recovering primary don't both run the
  high-priority feeds.
- **Degraded-mode partner behavior** — low-priority inbound feeds are *down* on DR; senders see a refused
  connection (their own resend/queue covers the gap) vs. an explicit maintenance NAK.
- **Fail-back** — returning to the restored primary without losing or double-processing what DR handled (the
  at-least-once + idempotency invariants must hold across the handoff).

**Why P3 / owner-gated.** DR-beyond-HA is a recognized enterprise expectation and a Corepoint-parity gap (the
gap analysis lists "standby failover/failback"), but it's a larger build touching deployment topology, the
store-replication boundary (partly the DBA's), and a new priority-tier config surface — and it's not an open
exposure on the shipping config. **Trigger:** an adopter requires site / HA-pair-loss DR on a budget (no
second full hot standby) with a defined critical-feed set.

**Relation to siblings:** **#60** (backup/restore-verify — seeds the DR state), the shipped active-passive HA
(tier 2), **#34** / **#47** (shared per-connection-override plumbing for the priority tier), **ADR 0031**
(startup fault isolation — DR starts a *subset* of connections via the same path), **ADR 0007**
(`connections.toml` for the GUI-editable priority key).

**Source:** owner request (2026-06-27) — "a disaster recovery option beyond HA: a third tier that takes over
when the HA pair fails (e.g. the primary database goes down). A small, right-sized DR box — not a full-size
server sitting unused — spins up and runs only the high-priority feeds."

---

## 62. Binary body carriage — store ciphertext / raw bodies as `VARBINARY`/`BLOB`/`bytea` instead of base64-in-`NVARCHAR` (storage efficiency) (P3, measure-gated)

> 🔢 **Re-scored 2026-07-10 → DEMAND-GATE.** Value **5/10** · Difficulty **7/10** · _money pit_. Corepoint-class storage win (~60% on SQL Server), clean bigger-disk workaround; format change needing an ADR + dual-read migration on three backends. _(was DEMAND-GATE · V3/5 · D4/5)_

**Type:** storage efficiency — at-rest carriage. The store carries encrypted bodies as
`mfenc:v1:<key_id>:<base64(nonce‖ct‖tag)>` ([`store/crypto.py`](../messagefoundry/store/crypto.py)) in **text**
columns — `NVARCHAR(MAX)` on SQL Server ([`store/sqlserver.py`](../messagefoundry/store/sqlserver.py),
`raw`/`payload`). On SQL Server that is **doubly** wasteful: base64 (+33%) layered on `NVARCHAR`'s 2-bytes/char
UTF-16, so a body of *B* bytes lands at ≈ **2 × 1.33 × (B+28) ≈ 2.66·B**. Corepoint's qualified-45M-spec collation
`SQL_Latin1_General_CP1_CI_AS` implies **1-byte `VARCHAR`** plaintext — so a large slice of the
MessageFoundry-vs-Corepoint storage gap is *carriage*, not data.

**Scope.** Carry the body as **bytes** — `VARBINARY(MAX)` (SQL Server) / `BLOB` (SQLite) / `bytea` (Postgres) —
dropping the base64 and (on SQL Server) the Unicode doubling: an encrypted body becomes ≈ *B + 28*, i.e. roughly
Corepoint-class, with **no security change** (app-layer AES-256-GCM intact, key still outside the DB). Wins:
~**60%** on SQL Server, ~**33%** (the base64) on SQLite/Postgres. Coheres with the ADR 0028 binary-payload direction.

**The catch — this is a format change, not a column retype.** It touches the `find-all` / `rotate-key` / re-encrypt
scans that `LIKE`-match the `mfenc:` **text** prefix (a `VARBINARY` value can't be `LIKE`-matched the same way —
needs a byte-prefix test or a separate format-version column); needs a **data migration or dual-read** for existing
`mfenc:v1` base64 rows (the `rotate-key` pass is the natural vehicle); and it **revisits ADR 0028's** deliberate
"carry everything over str/TEXT for NUL-safety" decision → so it warrants its own **ADR**. All three backends.

**Priority / gating.** Enterprise/parity storage optimization — **gated on confirming storage is actually binding**
(the pending E_core / real-footprint measurement), not an L1 need. Part of the **storage-efficiency cluster** with
**#34** (retention) / **#47** (embedded-doc pruning) / **#63** (event verbosity). Surfaced by the 2026-06-28
Corepoint 45M/day spec parity analysis.

---

## 63. `message_events` verbosity knob — operator dial to suppress routine lifecycle events (store-size / observability) (P3)

> ✅ **BUILT 2026-07-10 (PLAN-9 Wave 2, branch `plan9-store`).** `[diagnostics].message_events` operator verbosity dial to suppress routine lifecycle events (store-size / observability). The gate is applied at **every** emission path — SQLite `_event` + its 3 direct `INSERT INTO message_events` sites, Postgres `_event`, and SQL Server `_event`/`_event_sync` + its 2 batched sites — threaded through `open_store`. **Compliance floor preserved:** `viewed` (PHI-access) + terminal `dead`/`error`/`failed` are always recorded even at the most-suppressed level, and the messages/queue disposition rows are never touched.

**Type:** storage efficiency + observability — operator knob. Every message writes ~**3 + H + N** `message_events`
rows (`received` / `routed` / `transformed` / `delivered`) via `_event()`
([`store/store.py`](../messagefoundry/store/store.py)) — and they are **ungated today**: there is no per-message
"store verbosity" setting (only after-the-fact retention/pruning, and the `[diagnostics]` toggles for
`response_sent` / `connection_events`). On a high-volume feed these routine rows can dominate the store's row count.

**Scope.** Add `[diagnostics].message_events` = `full` (default — no behavior change) / `received-only` / `off`.
Gate at the `_event()` chokepoint on the **event type**: suppress the routine lifecycle events
(`received`/`routed`/`transformed`/`delivered`) at lower verbosity; **always** keep the significant ones (`dead` /
`replayed` / **`viewed`** [PHI-access] / dead-letter). First funnel the few inline `message_events` INSERTs through
`_event()` so there's a single gate; thread the policy through `open_store`; mirror on all three backends.

**Honest framing — bytes, not fsyncs.** `_event()` has **no own commit** (the event rides the handoff/claim commit
that already happens), so this saves **rows / bytes / index churn + WAL/checkpoint pressure — not commits**; it does
**not** move the per-commit throughput ceiling (that's group-commit's job). Correctness-neutral: the disposition
finalizer reads `messages.status` + queue rows, **never** `message_events`; and these are **not** the hash-chained
`audit_log` (**do not** gate audit). Bill it as a store-size / observability control.

**Priority.** P3, do-anytime (small, safe, ships independently of group-commit). Part of the **storage-efficiency
cluster** with **#34** / **#47** / **#62**. Surfaced by the 2026-06-28 DB write-amplification analysis.

---

## 64. Throughput parity with Corepoint — measure-first performance roadmap (group-commit + lean-writes, gated on the enterprise-box validation) (P2, owner / measure-gated)

> 🔢 **Re-scored 2026-07-10 → DEMAND-GATE.** Value **1/10** · Difficulty **2/10** · _fill-in_. Index-only roadmap umbrella; its throughput levers (#62/#63/#47/#34, group-commit) are separate items, so it ships nothing runnable. _(was DEMAND-GATE · V3/5 · D5/5)_

**Type:** roadmap / performance — the umbrella for reaching Corepoint-class throughput, anchored on the
**qualified Corepoint 45M/day spec** (owner-supplied, 05/2026): a 20-core app server + a **16-core / 128 GB /
15 TB-RAID10-Tier-1** SQL Server qualified for **9,200 8 KB-random-write IOPS**, multi-DB (Queues/Logs 9 TB +
Audit + PerfStats) under **AlwaysOn AG**, ~**11 KB/msg** — and Corepoint names **DB durable-write I/O as the
leading performance driver**. The strategy + the **no-rewrite / no-broker** decision are
[**ADR 0051**](adr/0051-corepoint-throughput-parity-strategy.md); the engineering note is
[`THROUGHPUT-IMPROVEMENTS.md`](archive/throughput/THROUGHPUT-IMPROVEMENTS.md) §5.

**Honest verdict (2026-06-28).** NOT at demonstrated parity at 45M/day (the earlier "at parity" claim was vs
Rhapsody *marketing*, not this spec): **compute** unvalidated (only `E_core ≈ 42 msg/s` measured on an
under-powered box; 84/400 estimated); **durable-write** behind (~7 commits/msg, group-commit unbuilt);
**storage** higher but mostly **by construction** — carriage (`NVARCHAR(MAX)` 2 B/char + base64) +
encrypt-by-default, **not** inefficiency (the "~2× vs Corepoint" was estimate-vs-brochure, **retracted**);
**HA / multi-DB maturity** behind; **cost / openness** ahead.

**Ordered plan (each step gated on the one before):**
1. **Measure first (the gate).** Enterprise-hardware `E_core` + sustained durable-write IOPS run — the
   **Windows Server 2025 + SQL Server 2025 box (#40)** via the load harness (#28 / #29) — against the
   **9,200-IOPS / ~11 KB-msg / 20 + 16-core** target. Pins `E_core` (42 vs 84 vs 400) + the binding axis.
   **Nothing builds before it.**
2. **Group-commit** — the #1 unbuilt durable-write lever ([`THROUGHPUT-IMPROVEMENTS.md`](archive/throughput/THROUGHPUT-IMPROVEMENTS.md)
   §2); its **own ADR** when built — *iff* the run shows durable-write-bound.
3. **Lean-writes / carriage cluster** — **#62** (VARBINARY carriage) / **#63** (`message_events` knob) /
   **#47** (embedded-doc pruning) / **#34** (retention).
4. **Multi-DB log split** — **shared-server backend only** (the atomic staged-queue transaction can't be split).
5. **Deferred contingencies** — the scoped native engine-service core, free-threading (ADR 0040), DBSHARD
   (ADR 0039) — revisited only if the measurement shows machinery-bound and/or the single-hot-feed case matters.

**Priority / gating.** P2, **owner / measure-gated** — the roadmap exists; the build of each lever waits on the
validation run. Sibling to **#52** (Corepoint *capability* parity). Decision:
[ADR 0051](adr/0051-corepoint-throughput-parity-strategy.md). Plan doc:
[`THROUGHPUT-IMPROVEMENTS.md`](archive/throughput/THROUGHPUT-IMPROVEMENTS.md) §5. Surfaced by the 2026-06-28 Corepoint 45M/day spec
parity analysis.

---

## 65. Generic outbound HTTP auth — OAuth2 client-credentials / HTTP Digest / NTLM

> ✅ **SHIPPED (2026-07-12) — OAuth2 client-credentials (symmetric) + HTTP Digest; NTLM/Negotiate scoped out.** A pluggable auth-provider seam ([`transports/http_auth.py`](../messagefoundry/transports/http_auth.py), [ADR 0024 amendment 2026-07-12](adr/0024-smart-backend-services-token-provider.md)) selected per connection on REST/SOAP/FHIR, additive (off by default → byte-identical): **(1) OAuth2 client-credentials with a SYMMETRIC `client_secret`** — a `BearerTokenProvider` (`OAuth2ClientCredentialsProvider`) that slots into the destinations' existing per-request bearer-injection seam beside the SMART provider (`bearer_provider_from_settings` unifies them; mutually exclusive), `client_secret_basic`/`client_secret_post`, mint+cache+invalidate-on-401, cleartext-token-endpoint refused; **(2) HTTP Digest (RFC 7616)** via the stdlib `urllib.request.HTTPDigestAuthHandler` folded into a per-connection opener (never the shared one), cleartext-refused. Composers `with_oauth2_client_credentials()` / `with_http_digest()` mirror `with_smart_backend`; secrets are `env()`-resolved + redacted (`oauth2_client_secret`/`http_auth_password` in `_SECRET_SETTING_KEYS`), never logged. No new dependency (stdlib urllib + rest.py's hardened opener). Tests: `tests/test_http_auth.py`. **Scoped out (honest): NTLM/Negotiate.** Its handshake is **connection-bound** (type1/type2/type3 must ride one keep-alive TCP connection), which `urllib.request` (a fresh connection per `open()`) cannot satisfy; a correct build needs a keep-alive HTTP client driven by `pyspnego` (already in `requirements.lock`, backing the AD/SSO server path) — a separate follow-up the provider seam is shaped to admit. _(was 🔢 DEMAND-GATE · Value 7/10 · Difficulty 4/10.)_

**Cluster:** DB & web-service breadth. **Priority:** P2. **Verdict:** shipped (OAuth2-CC symmetric + HTTP Digest; NTLM/Negotiate scoped out).

**Scope:** A pluggable auth provider on REST/SOAP/FHIR destinations beyond what ships.

**Trigger:** build when a partner endpoint requires generic OAuth2 client-credentials, **HTTP** Digest, or NTLM.

**Why:** Real gap. Today: SMART OAuth2-CC (a token-provider usable on any REST/FHIR destination) + static bearer/basic + SOAP **WS-Security UsernameToken PasswordDigest** (a SOAP-message digest, *not* HTTP Digest). Additive, no identity tension.

**Source:** promoted from [#52](#52-corepoint-capability-parity-gaps--prioritized-roadmap-input-2026-06-27) gap synthesis (adversarially reviewed, 2026-06-28).

---

## 66. Non-SQL-Server database connectors — Postgres / Oracle / MySQL / generic ODBC DSN

> ✅ **SHIPPED (2026-07-12).** The DATABASE source/destination gained a **generic ODBC dialect** (`dialect="generic"`) decoupled from the Driver-18 / T-SQL hardcoding: the operator names any OS-installed ODBC driver (`odbc_driver`) + supplies driver-specific keywords (`odbc_params`, brace-quoted/injection-safe) so PostgreSQL / Oracle / MySQL reach over their own ODBC drivers — **no new Python DB dependency** (reuses the present `aioodbc`; the OS-level driver install is documented). Credentials stay in the `env()`-resolved/redacted top-level `username`/`password` under `odbc_user_key`/`odbc_password_key` (default `UID`/`PWD`). The SQL Server preset (`dialect="sqlserver"`, default) is **byte-identical** and stays the supported/CI-exercised path; the `:name` parameterization, error classification, pooling and `[egress].allowed_db` gate are unchanged. **TLS on the generic path is operator-owned** (configured via the driver's own `odbc_params` keyword, e.g. `SSLmode=verify-full`) — MessageFoundry can't introspect an arbitrary driver's TLS posture, so the posture-keyed weakened-TLS refusal (#200 / ADR 0092) is intentionally exempt here, documented in the [ADR 0092 amendment (2026-07-12)](adr/0092-posture-keyed-transport-hop-refusal-refuse-the-insecure-phi-hop.md); to keep that delegation from being silent, generic-dialect construction logs a **WARNING** when no TLS keyword is set (DEBUG when one is). Docs: `docs/CONNECTIONS.md` (*Generic ODBC*) + `docs/CONFIGURATION.md`; tests in `tests/test_database_transport.py`. **Scoped out (honest):** native async drivers (`asyncpg`-as-connector / `oracledb` / `mysqlclient`) stay dep-heavy/out-of-scope; the `SELECT 1` reachability probe needs `FROM DUAL` on Oracle; read-only `db_lookup` (ADR 0010) stays SQL-Server-only. _(was 🔢 DEMAND-GATE · Value 6/10 · Difficulty 5/10.)_

**Cluster:** DB & web-service breadth. **Priority:** P2. **Verdict:** shipped (generic-ODBC subset; native async drivers scoped out).

**Scope:** Extend the aioodbc DATABASE source/destination beyond SQL Server.

**Trigger:** build when an adopter feed targets Postgres/Oracle/MySQL or a DSN the bundled driver can't cover.

**Why:** The DATABASE **connector** is **SQL-Server-only** (`database.py`: hardcoded ODBC Driver 18, T-SQL). Postgres exists only as a *store* backend, **not** an outbound connector. Mostly driver + CI-matrix work; build per real adopter (the #24 DICOM discipline).

**Source:** promoted from [#52](#52-corepoint-capability-parity-gaps--prioritized-roadmap-input-2026-06-27) gap synthesis (adversarially reviewed, 2026-06-28).

---

## 67. Stored-procedure OUT-param / return-value binding

> ✅ **SHIPPED — verified against `origin/main` (2026-07-28).** [ADR 0013](adr/0013-query-response-orchestration.md) **Amendment (2026-07-17)** (`:534`). A DATABASE outbound may capture a stored-proc call's OUT parameters + scalar RETURN value: `capture_out_params` (`messagefoundry/transports/database.py:561-567`, implying `capture_response` at `:568-570`), captured **pre-commit inside `send()`** (`:601`) via `_capture_merged`, which walks every `nextset()` (`:657-664`); wired at `messagefoundry/config/wiring.py:1732` and gated to real proc calls by `_is_db_proc_call` (`:1682-1685`, gate at `:3425-3439`); reachable from `connections.toml` (`config/connections_file.py:262-280`); `tests/test_database_out_params_capture.py` (12 tests).
>
> ⚠️ **Three things this close does NOT say.** **(a) Mechanism:** it is a **trailing readback `SELECT` inside the proc batch**, *not* native ODBC output-parameter bindvar binding — pyodbc/aioodbc cannot bind those (ADR 0013:553-558). Do not describe it as native OUT-param binding. **(b) A REAL DEFECT rides this close, unfixed:** the ODBC escape `{ ? = CALL proc(:x) }` is the canonical example in `wiring.py:1755`, in the gate's error text (`:3437`) and in the test fixture — but `_parse_named_params` (`database.py:374-383`) substitutes **only** `:name`, so the leading return-value `?` is never bound. Against a real driver that is a parameter-count error (SQLSTATE 07xxx, permanent → dead-letter). Only `DECLARE @rv INT; EXEC @rv = proc :x; SELECT @rv` actually works today. **This warrants a new item.** **(c) Coverage** is fake-cursor only — no live SQL Server round-trip — and a proc that COMMITs internally defeats the pre-commit-capture assumption (ADR 0013:570-577). _(was 🔢 DEMAND-GATE · Value 3/10 · Difficulty 3/10.)_

**Cluster:** DB & web-service breadth. **Priority:** P3. **Verdict:** demand-gate.

**Scope:** Bind a proc's OUT params + scalar return value back into the response (not just RETURNING/OUTPUT result-sets).

**Trigger:** build when a destination proc returns status via OUT/return rather than a result-set.

**Why:** Partial: ADR 0013 captures RETURNING/OUTPUT result-sets via `fetchall()`, not OUT/return-value bindvars. Narrow additive extension.

**Source:** promoted from [#52](#52-corepoint-capability-parity-gaps--prioritized-roadmap-input-2026-06-27) gap synthesis (adversarially reviewed, 2026-06-28).

---

## 68. Dynamic per-message outbound HTTP headers

> ✅ **SHIPPED — verified on this branch (2026-07-12).** A Handler stamps a per-message REST/FHIR request header (idempotency key, trace id, …) into the **shipped ADR 0081 metadata bag** — `SetMeta("http.header.X-Idempotency-Key", value)` — so it needed **no new outbound-row carry column and no ADR** (the re-scoring's feared 3-backend carry was avoided by reusing the crash-safe, exactly-once metadata channel). Opt in per connection with `Rest(..., dynamic_headers=True)` / `FHIR(..., dynamic_headers=True)`; the destination projects the `http.header.*` entries onto the outgoing request, **merged OVER the construction-static headers** (per-message wins), default off = byte-identical. Header-injection-safe: an invalid RFC 7230 header-name token is dropped and CR/LF/NUL/control chars are stripped from the value, and `Authorization` is never settable per-message (auth stays connection config). Pure/re-run-safe (headers re-derive from the message's metadata). Delivery worker reads the small metadata column ONLY when the connector opts in (new lightweight `store.message_metadata_json`, 3 backends) — the perf-critical claim path is untouched. `messagefoundry/transports/rest.py` (`outbound_headers_from_metadata`), `fhir.py`, `base.py` (`send(payload, *, metadata=…)`, `consumes_metadata`), `pipeline/wiring_runner.py`, `config/wiring.py`.


> **On-trigger / demand-gate.** Numbered for tracking only — build when the trigger below fires (“demand-gate, don’t schedule”).

**Cluster:** DB & web-service breadth. **Priority:** P3. **Verdict:** demand-gate.

**Scope:** Let a Handler set per-message REST/FHIR request headers (idempotency key, trace id) vs construction-static only.

**Trigger:** build when a partner requires a per-message header a transform must compute.

**Why:** `rest.py`/`fhir.py` build headers once at `__init__`. Small surface; stays pure (the header value is derived in the transform and carried as data — no side effect).

**Source:** promoted from [#52](#52-corepoint-capability-parity-gaps--prioritized-roadmap-input-2026-06-27) gap synthesis (adversarially reviewed, 2026-06-28).

---

## 69. WSDL import — SOAP type-tree + validate-against-WSDL

> ✅ **SHIPPED — verified against `origin/main` (2026-07-28).** [ADR 0122](adr/0122-wsdl-import-pure-soap-type-tree-validate-against-wsdl-no-zeep.md), **Accepted 2026-07-17**, index row `docs/adr/README.md:149`. A pure WSDL 1.1 importer lives at `messagefoundry/parsing/xml/wsdl.py:3-14` — a typed read-only operation/message tree (`parse_wsdl`, frozen `WsdlDefinition` at `:90-101`) plus `validate_request`/`validate_response` against the embedded XSD (`:103-149`), with the SSRF seam closed by `_refuse_remote_imports` (`:212-228`) and PHI-safe `WsdlError`/`WsdlSecurityError` (`parsing/xml/errors.py:57-69`). **No `zeep`, no new dependency.** `tests/test_wsdl_import.py` (14 tests incl. DOCTYPE and remote-import refusal).
>
> ⚠️ **Scope boundaries — do not over-read this close.** WSDL **1.1 only**; document/literal is first-class and **rpc/encoded raises** (`wsdl.py:126-129`); multi-document import graphs are **not resolved** (a remote import is refused, a local one is not fetched — split contracts must be inlined by the operator); validation covers the SOAP **body** against the embedded XSD only — not headers, WS-Security or MTOM. `transports/soap.py` is deliberately **untouched**: a WSDL checks an envelope, it never drives one, so **#70** (synchronous WSCall) stays declined-by-design and is *not* closed by this, and **#184** (serving our *own* endpoint WSDL) remains open. ⚠️ **Two undisclosed limits worth a follow-up:** `WsdlPart` is exported but no public API returns one, and `_body_element_for_message` unconditionally takes `parts[0].element` — the binding's `<soap:body parts="…">` selector is never read, so a WS-I-conformant multi-part `wsdl:message` can select the wrong part. _(was 🔢 DEMAND-GATE · Value 3/10 · Difficulty 5/10.)_

**Cluster:** DB & web-service breadth. **Priority:** P3. **Verdict:** demand-gate.

**Scope:** Parse a WSDL into a typed operation/message tree and validate envelopes against it.

**Trigger:** build when a SOAP partner ships a WSDL a migration depends on.

**Why:** `soap.py` builds raw envelopes by string concatenation, no WSDL import. New dep (zeep-class); contract-first but speculative.

**Source:** promoted from [#52](#52-corepoint-capability-parity-gaps--prioritized-roadmap-input-2026-06-27) gap synthesis (adversarially reviewed, 2026-06-28).

---

## 70. Synchronous in-transform web-service call (WSCall)

> ⛔ **Declined-by-design (2026-06-28).** Recorded so it is not re-proposed as an “easy parity win.”

**Cluster:** DB & web-service breadth. **Verdict:** decline-by-design.

**Scope:** A blocking external WS call inside a transform (Corepoint WSCall parity).

**Why:** Violates the **purity / at-least-once** invariant (CLAUDE.md §8). The sole sanctioned non-pure inputs are **read-only** `db_lookup` (ADR 0010) / `fhir_lookup` (ADR 0043) — a write/RPC mid-transform is exactly what that carve-out excludes. The most important identity call in the synthesis.

**Source:** promoted from [#52](#52-corepoint-capability-parity-gaps--prioritized-roadmap-input-2026-06-27) gap synthesis (adversarially reviewed, 2026-06-28).

---

## 71. PKCS#12 / .pfx cert import + read-only cert inventory

> ✅ **SHIPPED as CLI — verified against `origin/main` (2026-07-28).** `messagefoundry/pki.py:3` ("PKI helpers (BACKLOG #71/#72)"): `load_pkcs12` (`:58-68`) over `cryptography`'s `pkcs12.load_key_and_certificates`, PEM writers (`:71-90`), and `CertFacts` + `read_cert_facts` (`:42-56`, `:93-133`) sharing one day-math path with the expiry monitor. Surfaced as `messagefoundry cert import` / `cert inventory` (`messagefoundry/__main__.py:509-523`, `:525-547`, dispatched at `:4271`), with private keys written `O_CREAT|O_EXCL|O_WRONLY` `0o600` (`:2981-2993`) and the `.pfx` password taken **from `MEFOR_PFX_PASSWORD` only**, scrubbed on failure (`:3005`). Inventory auto-enumerates from the registry (`pipeline/cert_expiry.py:98-130`). `tests/test_cert_cli.py` — 19 tests. The item's own Why **drops the trust-flag half** (`docs/BACKLOG.md` #71 Why: trust is delegated to the OS store / reverse proxy), so that is satisfied scope, not a gap.
>
> ⚠️ **CLI only — there is no console page and no API endpoint.** The 2026-07-10 re-score line called this "a small read-only inventory view", which a later reader could mistake for a console pane. ⚠️ **Auto-enumeration misses SOAP mTLS certs:** `certs_from_registry` reads only the `tls_cert_file` key, while the SOAP connector presents its identity under `client_cert_file` (ADR 0015) — so a wired SOAP client cert is never listed *and is equally unwatched by the expiry alerter*. Pre-existing, inherited from the ADR 0002 monitor; worth a follow-up. ⚠️ `cert import` **refuses cert-only bundles** (`__main__.py:3038`), so a public-only partner `.p12` cannot be imported. _(was 🔢 DEMAND-GATE · Value 2/10 · Difficulty 3/10.)_

**Cluster:** Security. **Priority:** P3. **Verdict:** demand-gate.

**Scope:** Import .pfx bundles; list installed certs with expiry/trust (PEM-only today).

**Trigger:** build when operators managing partner certs need .pfx import / an inventory view instead of hand-PEM.

**Why:** Gap real (PEM loaders only, no PKCS12; `cryptography` already a dep, so the loader is in-dep). The **trust-flag-management UX is dropped** — PKI trust is delegated to the deploying org's OS trust store / reverse proxy. Complements the built `cert_expiry.py` alerter.

**Source:** promoted from [#52](#52-corepoint-capability-parity-gaps--prioritized-roadmap-input-2026-06-27) gap synthesis (adversarially reviewed, 2026-06-28).

---

## 72. Self-signed / dev certificate generation

> ✅ **SHIPPED as CLI — verified against `origin/main` (2026-07-28).** `make_self_signed(cn, sans, days)` at `messagefoundry/pki.py:136-162` mints an **EC P-256 / SHA-256 self-issued** cert (subject == issuer, `BasicConstraints CA=false`, SAN = CN first then de-duped DNS names, 1-minute clock-skew slack) returning cert PEM + PKCS#8 key PEM, with a DEV-ONLY warning in its own docstring. Surfaced as `messagefoundry cert self-signed` (`messagefoundry/__main__.py:549-568`: required `--cn`, repeatable `--san`, `--days` default 365, `--out-dir`, `--json`; help states NON-PROD only), writing the key `O_EXCL` `0o600` and refusing to overwrite (`:2981-2993`).
>
> ⚠️ **CLI form only — no console or IDE button.** The item's Scope reads "A CLI/console helper" (either/or) and the D2 re-score prices "a tiny additive CLI helper", so this satisfies it — but state it plainly rather than implying a UI exists. *(The only near-hit, `api/tls_client_cert.py`, is mTLS client-cert **verification** per ADR 0083, not generation.)* ⚠️ There is **no dedicated ADR** for #71/#72. _(was 🔢 DEMAND-GATE · Value 2/10 · Difficulty 2/10.)_

**Cluster:** Security. **Priority:** P3. **Verdict:** demand-gate.

**Scope:** A CLI/console helper to mint a self-signed cert+key for TLS bring-up.

**Trigger:** build when operators repeatedly need a throwaway cert for non-prod TLS testing.

**Why:** No cert builder today; openssl-replaceable so low buyer value; cheap if bundled with #71.

**Source:** promoted from [#52](#52-corepoint-capability-parity-gaps--prioritized-roadmap-input-2026-06-27) gap synthesis (adversarially reviewed, 2026-06-28).

---

## 73. Explicit FIPS-mode attestation

> ✅ **SHIPPED — verified against `origin/main` (2026-07-28).** [ADR 0120](adr/0120-fips-provider-mode-attestation-report-only-on-security-posture.md). `fips_attestation()` at `messagefoundry/config/tls_policy.py:88-107` reads `(fips_mode, openssl_version)` from `_hashlib.get_fips_mode()` + `ssl.OPENSSL_VERSION` — its docstring states "a read-out, never enforcement (#73)", returns `None` when undeterminable and **never raises**. Surfaced on the security posture (`messagefoundry/api/app.py:1495-1497`, `:1533-1534`) with `fips_mode: bool | None` / `openssl_version: str | None` on the model (`api/models.py:930-936`).
>
> ⚠️ **Two ratified narrowings, not oversights.** **(a)** The attestation covers **only** the OpenSSL that CPython's `ssl`/`_hashlib` link against — **not** the separately-linked OpenSSL inside the `cryptography` wheel that encrypts **PHI at rest**. ADR 0120 records this deliberately and names attesting that backend as a possible follow-up *if a buyer requires it*; anyone needing it must **file a new item** rather than reopen this one. **(b) Report-only by design** — no `serve` refusal, no cipher change, no warning keyed on the value. ADR 0120 explicitly rejects enforcement. _(was 🔢 DEMAND-GATE · Value 2/10 · Difficulty 2/10.)_

**Cluster:** Security. **Priority:** P3. **Verdict:** demand-gate.

**Scope:** Surface/attest OpenSSL FIPS-provider mode (beyond the permitted-curve comment) for compliance buyers.

**Trigger:** build when a procurement / compliance requirement demands a FIPS attestation.

**Why:** Only a FIPS-permitted-**curve** comment exists (`tls_policy.py`). Attestation is reporting over the OS OpenSSL, not crypto we own.

**Source:** promoted from [#52](#52-corepoint-capability-parity-gaps--prioritized-roadmap-input-2026-06-27) gap synthesis (adversarially reviewed, 2026-06-28).

---

## 74. Host / system metrics — CPU / memory

> ✅ **SHIPPED (2026-07-10, BACKLOG #74).** Host CPU%, host memory used/total, and process RSS as **label-less** gauges on the Prometheus `/metrics` surface (`psutil`, read inline in `gather_snapshot` off the pure-sync scrape path; absent if the counters are unreadable, so a scrape never fails). Adds `psutil` to core deps + re-synced all four lock files (DEP-1). Unit-tested (`test_host_metrics.py`); the PHI label-allowlist guard still passes.

> 📌 **do-next — scheduled (2026-06-28).** The single promote-now outcome of the #52 gap synthesis.

**Cluster:** Operational/monitoring. **Priority:** P2. **Verdict:** do-next.

**Scope:** Expose host CPU/mem (psutil) on the metrics surface alongside the existing app-log disk metering (#50).

**Why:** The single zero-identity-tension, trivial-cost, additive item from the #52 synthesis — it strengthens the Prometheus/OTel surface MeFor already leads on (confirmed gap: no psutil repo-wide, only `shutil.disk_usage`). **CAVEAT: adds `psutil` — vet + add to `pyproject.toml` + re-lock (`uv lock`/`uv export`) before merging.** The **SQL-internal** metrics sub-scope stays **demand-gate** (DBA-delegated, parity with the DB-tier-HA decline).

**Source:** promoted from [#52](#52-corepoint-capability-parity-gaps--prioritized-roadmap-input-2026-06-27) gap synthesis (adversarially reviewed, 2026-06-28).

---

## 75. Browser / web operator monitor

> ✅ **SHIPPED — verified on `origin/main` (2026-07-09).** The `messagefoundry_webconsole` package (29 files) is on `main`; the browser ops dashboard ships. Residual: off-loopback exposure + WebAuthn (tracked by **#11**), per the owner's stop-after-L4c decision.

> **Promoted demand-gate → scheduled (2026-06-29).** The trigger FIRED — the owner locked the audience: the ops view must be viewable **without a Python/desktop install** (browser/URL). Was P3/demand-gate.

> **Evaluation (2026-07-01) — "expand #75 to a full console port + delete the Inno installer".** The owner
> asked whether to expand this item into a **full port of the admin console to a web app** and, in the same
> move, **remove the frozen Inno installer**. A structured multi-agent evaluation (6 evidence tracks,
> adversarially verified; 3-lens judge panel — delivery-risk, security/compliance, product-strategy)
> returned a **unanimous verdict: stage option b first; do not commit to the full port (option c) now; and
> remove the installer *separately, now*.** The two halves point in opposite directions and were decoupled:
> - **Full port (option c) — DEFERRED, not adopted.** It is a rewrite of ~5,700 LOC of security-critical
>   *admin* UI (not "monitoring" — it does user/RBAC/MFA admin, purge, replay, service control) plus ~4,170
>   lines of Qt tests, against this item's own gate (below) that a solo dev does not meet. **Strict parity
>   is impossible:** Windows service control (start a *stopped* engine, UAC install) cannot exist in a
>   browser and cannot move behind the API by design (stopping the engine kills the API). A browser console
>   also flips **44 architecturally-N/A ASVS L3 requirements to applicable** (all of V3, 14.3.2/14.3.3,
>   6.2.7), fires the WebAuthn **#11** off-loopback trigger, and needs a **new WS auth channel** (browsers
>   can't set the `Authorization` header; the query-token fallback was removed). Since **b ⊂ c**, shipping
>   the dashboard first forecloses nothing.
> - **Installer removal — DONE (2026-07-01), decoupled.** Retired as **#39**; see the [ADR 0032 *Amendment
>   (2026-07-01)*](adr/0032-console-desktop-launch.md). Its zero-install audience transfers **here** (the
>   dashboard serves "viewable without a Python install" from the engine's own FastAPI app).
>
> **Decision:** keep this item scoped to **option b**; treat option c as a gated *direction*, not committed
> work; the desktop console stays pip-distributed (ADR 0032 Phase A) and must remain working through the
> WIN2025 Phase-2 customer test (~mid-July). Any future option-c decision requires an explicit
> parity-loss record (service control), a token-storage/CSRF/CSP/WS-auth design ADR, and an ASVS L3
> re-assessment as gate artifacts.

**Cluster:** Operational/monitoring. **Priority:** P2. **Verdict:** do — **"option b"** (a separate web dashboard; see decision basis).

> **M1 status (2026-07-02):** the read-only slice is **built** on branch `feat/web-ops-dashboard-m1`
> ([ADR 0065](adr/0065-web-ops-dashboard.md)) — same-origin `/ui` behind `[api].serve_ui` (default off),
> HttpOnly+SameSite cookie confined to `/ui` (JSON API stays header-only), strict CSP + `no-store`,
> autoescape-by-default rendering, connections dashboard (live poll) + message log + audited raw view +
> dead-letter list, stdlib renderer (no new dependency), 12 tests. **Held for owner review; not merged.**
>
> **M2a status (2026-07-02):** the **connection controls** slice is built on the stacked branch
> `feat/web-ops-dashboard-m2` — inbound **start / stop / restart** (reusing the `connections:control`
> handlers) with a token-free **Origin / Sec-Fetch-Site** CSRF check on top of SameSite=Strict (no crypto
> import), + control buttons on the dashboard, + 4 security tests. **Held; stacked on M1.**
>
> **M2b status (2026-07-02):** the **message replay + browser step-up** slice is built on the stacked
> branch `feat/web-ops-dashboard-m2b` — single-message replay (Replay button on the message detail),
> gated by `require_ui_step_up` (the cookie-world analogue of `require_step_up`): a stale step-up
> **redirects to a /ui re-auth page** (password + TOTP-if-MFA) instead of a 403 header, then **auto-retries**
> the pending replay; the `next` target is validated to a /ui replay action only (anti open-redirect). +7
> security tests. **Held; stacked on M2a.** Still deferred: **bulk dead-letter replay** (approval-gated),
> the `/ws/stats` browser channel, a parse-tree endpoint, and the full ASVS L3 re-assessment sign-off.

> **MERGED (2026-07-02):** M1 (#714), M2a + M2b (#721, cherry-picked clean onto main after the stacked
> #717/#720 hit the post-squash-merge add/add wall) are **on main**. **M3 — dead-letter bulk replay**
> built next (branch `feat/web-ops-dashboard-dlreplay`): a per-channel "Replay all dead" action reusing
> `replay_dead_letters` with `require_ui_step_up` (channel in the path so the auto-retry re-POST carries
> it) and the dual-control approval gate surfaced as a "held for approval" page. Still deferred: the
> **`/ws/stats` live browser channel** (WS cookie-auth + CSWSH — building next) and a parse-tree endpoint;
> plus the full ASVS L3 re-assessment sign-off (owner).

**Scope:** A **zero-install browser UI** served by the engine's FastAPI app, consuming the existing API + the `/ws/stats` WebSocket. Beyond the original read-only mirror, a **real-time ops dashboard**: per-connection **In/Out msgs/sec** (live over `/ws/stats`), **Queued / Errors / Last-Activity** with click-through to a filtered log view, **log search**, **dead-letters**, plus the **safe operational actions the API already exposes** — message **resubmit/replay**, connection **start/stop**. **Read + act, NOT web authoring** (authoring stays #26-declined).

**Trigger:** ~~build when demand for browserless / remote monitoring~~ — **FIRED 2026-06-29** (owner audience decision: "viewable without a Python install").

**Net-new engine + security work — NOT "front-end only"** (verified in-code, adversarial review 2026-06-29): the API is a **pure JSON service** (no `CORSMiddleware`, no `StaticFiles` mount, no HTML/`FileResponse`) → add CORS + static/SPA serving; the native console reads its bearer token from the **OS keyring**, a browser has none → token moves to `localStorage`/cookies → add **CSRF on the destructive POSTs** (replay, start/stop, purge, `config:deploy`) + **XSS-safe HL7 rendering** on the raw-view path; the **`[api].ws_allowed_origins`** allowlist **defaults empty → browser Origins are rejected** today (an anti-CSWSH guard for the native client, *not* a built-in browser path).

**Reuse + hard rules.** 60+ **RBAC/PHI-field-gated** REST routes + `/ws/stats` + auth + **hash-chain audit** + the `127.0.0.1`/TLS-or-refuse posture already exist. **Must be built as a *client* of the existing engine API** (CLAUDE.md §2/§4 one-way dependency; ADR 0023/0032 precedent), never a second bound socket reaching into the engine; **never render full PHI bodies** except via the audited raw-view path. Read + safe-actions only, never web *authoring* (would drift toward #26). Pairs with **#74** (host metrics), **#76** (historical charting / flow graph), **#21** (per-connection throughput).

**Staged path / gated future ("option c").** Option b is a **strict prefix** of a full **web console** that could later absorb the desktop console's other ops views and **retire the ~5,350-line PySide6 Qt console at parity** (→ two UI surfaces instead of three). That consolidation is a **multi-thousand-line JS/TS reimplementation of PHI/RBAC/MFA/audit-aware Qt — pursue ONLY if the team staffs JS/TS frontend capability**; otherwise ship the dashboard and keep PySide6 indefinitely (no rework lost, since b ⊂ c). **Gate detail (2026-07-01 evaluation — see the Evaluation block above):** "at parity" is **not fully achievable** — Windows **service control** (start a stopped engine + UAC service install, `console/service_control.py`) is browser-impossible and cannot cross the API by design, so option c must pre-accept that parity loss (or keep a small local tool). Other desktop-only carve-outs a port must re-home or drop: OS-keyring token custody, `--cacert`/mTLS self-signed trust, multi-shard fan-out (per-engine keyring auth), and client-side QSettings table/prefs state. And the console is **shared infrastructure** — `harness/` imports `messagefoundry.console.client`/`widgets`/`login` — so "retire the console" can never mean deleting `messagefoundry/console/` without first carving those out. The security surface (token storage, CSRF on ~35 destructive routes, XSS-safe HL7 rendering, CSP, a browser WS auth channel) and the ASVS L3 re-assessment are the real cost, not the widget layer.

**Source:** promoted from [#52](#52-corepoint-capability-parity-gaps--prioritized-roadmap-input-2026-06-27) gap synthesis (2026-06-28); trigger fired + scoped by the **#87** competitive DX deep-dive + the console-medium judge-panel evaluation (2026-06-29).

---

## 76. Historical-metrics charting + status-colored data-flow graph

> ✅ **SHIPPED (first slice) — verified against `origin/main` (2026-07-28).** [ADR 0065](adr/0065-web-ops-dashboard.md) amendment (2026-07-19). Both halves the item asked for exist: a historical-metrics ring (`messagefoundry/api/metrics.py:58-62`, `MetricsSample`/`MetricsHistory` at `:68`/`:79`), instantiated at `api/app.py:1133` and fed from counts the ~1s `/ws/stats` loop **already** fetched — zero extra store I/O (`:4860-4867`) — exposed as `GET /metrics/history` (`:4122-4140`); and a status-colored data-flow graph via `GET /graph/edges` (`:4142-4150`), which joins `build_wiring_graph` edges with live `RegistryRunner` status and whose docstring states it constructs **no** channel/route object (CLAUDE.md §12 holds).
>
> ⚠️ **History is in-memory and process-local** — lost on restart, and accrues **only while a browser holds the Connections dashboard open** (the page says so itself). That is the deliberate first slice: ADR 0065's amendment scopes a durable table out **by name** because it would flip `store_schema`. #76 asked for charts, not durability — but do not read this close as durable metrics history. The trend chart plots outbox-by-status counts only. _(was 🔢 DEMAND-GATE · Value 4/10 · Difficulty 3/10.)_

**Cluster:** Operational/monitoring. **Priority:** P3. **Verdict:** demand-gate.

**Scope:** Time-series charts + a status-colored connection graph in the console.

**Trigger:** build when operators need trend charts / a visual flow view beyond point-in-time status.

**Why:** Pure visualization of existing metrics (no logic authoring) so identity-safe, but cosmetic. **Render the by-name graph — reject any "channel"/route object backing it** (CLAUDE.md §1).

**Source:** promoted from [#52](#52-corepoint-capability-parity-gaps--prioritized-roadmap-input-2026-06-27) gap synthesis (adversarially reviewed, 2026-06-28).

---

## 77. Multi-select console connection control — ALREADY BUILT (tombstone)

> 🪦 **Already built — not a gap (tombstone, 2026-06-28).**

**Cluster:** Operational/monitoring. **Verdict:** already-built.

**Scope:** (multi-select start/stop/restart in the console)

**Why:** **Not a gap.** `console/connections.py` `_inbound_action` (lines 307-322) already loops over **all** selected source rows for start/stop/restart, and `widgets.py` uses `ExtendedSelection`. The #52 summary was wrong to list it as NEW; the live code disproves it. Tombstoned (number consumed, not reused) so #52 cross-references stay stable.

**Source:** promoted from [#52](#52-corepoint-capability-parity-gaps--prioritized-roadmap-input-2026-06-27) gap synthesis (adversarially reviewed, 2026-06-28).

---

## 78. Custom message-definition data model + conformance validator; NCPDP codec

> 🔢 **Re-scored 2026-07-10 → DEMAND-GATE.** Value **5/10** · Difficulty **6/10** · _money pit_. Corepoint-parity definition model + report-only validator + a new NCPDP codec class; clean code-first-Handler workaround keeps it at useful breadth. _(was DEMAND-GATE · V3/5 · D4/5)_

> **On-trigger / demand-gate.** Numbered for tracking only — build when the trigger below fires (“demand-gate, don’t schedule”).

**Cluster:** Declarative HL7 modeling. **Priority:** P3. **Verdict:** demand-gate.

**Scope:** A stored custom HL7 definition model (data the code reads) + a report-only conformance validator; an NCPDP codec.

**Trigger:** build when a modeling-heavy estate migration needs persisted custom definitions, **or** a real NCPDP feed appears.

**Why:** Split from the draft. The persisted-definition model + report-only validator are NEW and migration-relevant — but **must be data the code reads, never a GUI modeler**. NCPDP is a clean additive codec (like X12 / DICOM). The **"Fix-All" auto-repair half is pulled out — see #80 (declined)**.

**Source:** promoted from [#52](#52-corepoint-capability-parity-gaps--prioritized-roadmap-input-2026-06-27) gap synthesis (adversarially reviewed, 2026-06-28).

---

## 79. Correlation-object UX — visual bidirectional correlation editor

> ⛔ **Declined-by-design (2026-06-28).** Recorded so it is not re-proposed as an “easy parity win.”

**Cluster:** Correlation-object UX. **Verdict:** decline-by-design.

**Scope:** A visual correlation editor (auto-match-by-description, qualified/non-singular correlations).

**Why:** The visual correlation *editor* is declarative-logic authoring (#26) and edges toward a §1 bundling object. The plain persisted-correlation *data* half is **already covered by ADR 0006 code sets / lookups** (a non-gap).

**Source:** promoted from [#52](#52-corepoint-capability-parity-gaps--prioritized-roadmap-input-2026-06-27) gap synthesis (adversarially reviewed, 2026-06-28).

---

## 80. "Fix-All" conformance auto-repair

> ⛔ **Declined-by-design (2026-06-28).** Recorded so it is not re-proposed as an “easy parity win.”

**Cluster:** Declarative HL7 modeling. **Verdict:** decline-by-design.

**Scope:** Auto-mutate non-conformant messages to conform via a stored rule set (Corepoint Fix-All parity).

**Why:** Pulled out of #78. Auto-mutation by a stored rule set is exactly the no-code / template-driven *logic* authoring declined by #26 (CLAUDE.md §12). The item most likely to quietly reintroduce declarative authoring — recorded so it isn't re-proposed.

**Source:** promoted from [#52](#52-corepoint-capability-parity-gaps--prioritized-roadmap-input-2026-06-27) gap synthesis (adversarially reviewed, 2026-06-28).

---

## 81. Alert escalation tiers + day/time thresholds + content (Action-Point) alerting

> 🔢 **Re-scored 2026-07-10 → DEMAND-GATE.** Value **5/10** · Difficulty **4/10** · _fill-in_. Corepoint alert-parity; clean external-notifier / code-first-Handler workaround; remainder = escalation-state + schedule config across 3 backends. _(was DEMAND-GATE · V3/5 · D3/5)_
> **On-trigger / demand-gate.** Numbered for tracking only — build when the trigger below fires (“demand-gate, don’t schedule”).

> **AMENDED 2026-07-28 — two of the three named sub-capabilities are BUILT; do not rebuild them.** Adversarial verification (2 lenses) refuted a full close, so this stays open — but narrowed. **BUILT and persisted across all three backends:** escalation tiers and schedule-aware thresholds ([ADR 0133](adr/0133-alert-escalation-tiers-schedule-aware-thresholds-and-content-triggered-alerts-the-56-remainder.md)), including the per-key escalation state the notifier drops on resolve (`messagefoundry/api/app.py:2367`, `:2541`) and the occurrence-driven tier count surfaced on the rules API (`:4316`).
>
> ⚠️ **The REMAINDER is the third sub-capability — content (Action-Point) alerting — and it is plumbing with no reachable trigger.** `content_match` exists on the concrete notifier (`messagefoundry/pipeline/alert_sinks.py:669`, event shape at `:677`, label routing at `:553`) but is **not on the `AlertSink` Protocol** (`messagefoundry/pipeline/alerts.py:27`), and the engine holds its sink as `self._alert_sink: AlertSink` (`messagefoundry/pipeline/wiring_runner.py:731`) — which is also `LoggingAlertSink` whenever no `[alerts]` transport is configured. A Handler is passed only the payload and no alert emitter is exported, so **nothing outside the tests can ever fire it**. Second, smaller gap: the persisted `escalation_tier` is never surfaced on `AlertInstanceInfo` / `GET /alerts/active`, which does not match ADR 0133 D1's stated outcome. Build **only** those two things.

**Cluster:** Operational/monitoring (alert remainder). **Priority:** P2. **Verdict:** demand-gate.

**Scope:** Escalation tiers, schedule-aware thresholds, and payload-content-triggered alerts on top of the shipped resolvable alert-state (#56).

**Trigger:** build when operators need escalation / scheduling / content-alerting beyond the #56 ack/resolve model.

**Why:** #56 shipped the resolvable-state half (0.2.10, ADR 0044). Escalation / day-time / Action-Point is the confirmed NEW remainder. Metadata-only (no new PHI tier).

**Source:** promoted from [#52](#52-corepoint-capability-parity-gaps--prioritized-roadmap-input-2026-06-27) gap synthesis (adversarially reviewed, 2026-06-28).

---

## 82. Sender transport-polish bundle — pacing · MSA-2↔MSH-10 matching · TCP keep-alive

> ✅ **SHIPPED — verified against `origin/main` (2026-07-28).** Both remaining halves of the bundle are built. **MSA-2↔MSH-10 correlation:** the per-outbound `verify_ack_control_id` knob (`messagefoundry/transports/mllp.py:663`) makes the ACK check reject a positive ACK whose MSA-2 does not echo the sent MSH-10 — raising a *retryable* `DeliveryError` and, on a persistent lane, discarding the cached socket as desynced (`:793`, `:1196`, `:1215-1226`; control ids only in the exception text, never a payload). **Pacing:** the per-outbound `send_min_interval_seconds` lane pacer (`messagefoundry/config/wiring.py:763`, documented `:845-853`, threaded `:883`, validated `:3347-3352`). ⚠️ **The claim *"`_check_ack` reads MSA-1/MSA-3 only, never matches MSA-2↔MSH-10"* is FALSE against `origin/main`.** This banner retracts it, **but the identical claim is still published in this item's own `**Why:**` prose below** (and in the equivalent bodies of #97 and #117) — that prose is **stale and superseded by this banner**, which the file declares the source of truth for build state. Rewriting item bodies was out of scope for the 2026-07-28 reconcile; read the banner, not the body. Keep-alive was promoted out to [#97](#97-keep-alive--persistent-outbound-connections--per-connector-setting-p3-on-trigger), also shipped. _(was 🔢 DEMAND-GATE · Value 6/10 · Difficulty 2/10.)_

**Cluster:** Minor gaps. **Priority:** P3. **Verdict:** demand-gate.

**Scope:** Per-connection send pacing and verify the reply's MSA-2 == the sent MSH-10. *(Keep-alive / persistent-reconnect on MLLP/TCP outbounds was promoted out to its own tracked item — see [#97](#97-keep-alive--persistent-outbound-connections--per-connector-setting-p3-on-trigger).)*

**Trigger:** build when a partner needs paced sending or strict response-correlation.

**Why:** Both confirmed (no pacing; `MLLPDestination._check_ack` reads MSA-1/MSA-3 only, never matches MSA-2↔MSH-10). Cheap per-connection-override additions; bundle on real partner need. Keep-alive is tracked separately at #97.

**Source:** promoted from [#52](#52-corepoint-capability-parity-gaps--prioritized-roadmap-input-2026-06-27) gap synthesis (adversarially reviewed, 2026-06-28).

---

## 83. Rich file-output disposition + FTPS / SFTP variants

> 🔢 **Re-scored 2026-07-10 → DEMAND-GATE.** Value **3/10** · Difficulty **3/10** · _fill-in_. Niche file/FTP interop (implicit-FTPS, SFTP-KBI, append/archive/framing) most partners never need; per-driver additive on two connectors. _(was DEMAND-GATE · V3/5 · D3/5)_

> **On-trigger / demand-gate.** Numbered for tracking only — build when the trigger below fires (“demand-gate, don’t schedule”).

**Cluster:** Minor gaps. **Priority:** P3. **Verdict:** demand-gate.

**Scope:** Append mode, dated-subfolder archiving, header/trailer framing on FileDestination; FTPS implicit + active/passive + SFTP keyboard-interactive on remotefile.

**Trigger:** build when a partner file feed needs append/archive/framing, or an FTPS-implicit / KBI-auth server.

**Why:** Gaps confirmed; **basic control-id/type archive-naming already exists** (`file.py`) — the gap is **append / dated-subfolder-archive / header-trailer framing**, plus `remotefile.py` is **explicit-FTPS only** (no implicit/passive toggle or KBI). Per-driver additive.

**Source:** promoted from [#52](#52-corepoint-capability-parity-gaps--prioritized-roadmap-input-2026-06-27) gap synthesis (adversarially reviewed, 2026-06-28).

---

## 84. Diagnostic panes — hex body view + HL7-aware before/after diff + profiling/coverage

> 🔢 **Re-scored 2026-07-10 → DEMAND-GATE.** Value **4/10** · Difficulty **2/10** · _fill-in_. Client-side hex pane for binary/mfb64 bodies — DX/console polish, nobody blocked; not interop, and no existing view renders raw bytes. _(was DEMAND-GATE · V2/5 · D2/5)_

> **On-trigger / demand-gate.** Numbered for tracking only — build when the trigger below fires (“demand-gate, don’t schedule”).

> 📐 **Partly promoted by [MULTISESSION-PLAN-7](releases/MULTISESSION-PLAN-7.md):** the **HL7-segment/field-aware before/after diff** (lane **L4**, client-side TS, no engine change) and **profiling + coverage** panes (lane **L7**, consuming the [ADR 0072](adr/0072-traced-dryrun-mode.md) traced dry-run) are scheduled as part of the no-AI build experience. The **hex / `mfb64:` pane** stays demand-gated.

**Cluster:** Minor gaps (console/IDE). **Priority:** P3. **Verdict:** demand-gate.

**Scope:** A hex pane for binary / `mfb64:` bodies, an HL7-aware before/after diff in the Test Bench, and coverage/profiling panes.

**Trigger:** build when operators / authors need hex / diff / coverage diagnostics beyond the current views.

**Why:** An explicit #52 Minor-gap line. Console/IDE-only, no engine change. **Visualization / diagnostics, not logic authoring — does not trip #26.** Identity-safe.

**Source:** promoted from [#52](#52-corepoint-capability-parity-gaps--prioritized-roadmap-input-2026-06-27) gap synthesis (adversarially reviewed, 2026-06-28).

---

## 85. Cloud object-store + generic message-bus destinations

> 🔢 **Re-scored 2026-07-10 → DEMAND-GATE.** Value **5/10** · Difficulty **5/10** · _fill-in_. Corepoint-parity breadth: new cloud object-store + generic-bus outbound connectors; the pluggable transport registry is a code-first workaround. _(was DEMAND-GATE · V2/5 · D3/5)_

> **On-trigger / demand-gate.** Numbered for tracking only — build when the trigger below fires (“demand-gate, don’t schedule”).

**Cluster:** Minor gaps. **Priority:** P3. **Verdict:** demand-gate.

**Scope:** S3 / Azure Blob / GCS outbound; a *generic* AMQP/Kafka destination.

**Trigger:** build when a real cloud-blob drop or a generic-bus feed appears (NOT a Java JMS broker).

**Why:** An explicit #52 Minor-gap transport line, distinct from the #25 JMS decline. S3/cloud-blob is a destination (not a broker coupling) — identity-neutral; the generic AMQP/Kafka lane is the on-trigger candidate #25 explicitly preserved. **JMS-specific stays #25-declined.**

**Source:** promoted from [#52](#52-corepoint-capability-parity-gaps--prioritized-roadmap-input-2026-06-27) gap synthesis (adversarially reviewed, 2026-06-28).

---

## 86. Offload the recurring load / throughput runs (#28/#29) to the self-hosted VM (cut billed CI minutes) — ⛔ DECLINED

> ⛔ **DECLINED (2026-07-06) — not a CI Actions leg.** Owner decision: the recurring load / throughput
> runs (#28/#29) are **run directly on the local server boxes** (real hardware, driven by the harness),
> **not** wired as a self-hosted GitHub Actions job. A throughput measurement belongs on a box the
> operator controls and drives directly — repeatable and inspectable, with no CI-runner scheduling /
> VM-uptime coupling (a self-hosted `schedule` silently no-ops when the VM is down anyway). The
> enterprise-hardware *ceiling* likewise runs on the **AWS two-box bench rig** (see [#40](#40)'s
> Follow-ups) — also a direct harness run, not CI. The billed-minute concern was already handled by the
> #637 move to a nightly `schedule`, so there is no remaining cost driver. Original proposal retained
> below as the decision record.

**Type:** CI — cost + test infrastructure. **Priority:** P3. **Verdict:** ~~do-when-convenient (cost win)~~ **declined (run on local server boxes / AWS directly, not CI)**.

**What:** move the recurring **load / throughput runs ([#28](#28) / [#29](#29))** off **billed
GitHub-hosted minutes** onto the **self-hosted Windows Server 2025 VM runner** (`mefor-win2025-sql`, stood
up for [#40](#40)). The load legs are the most minute-expensive jobs — long-running, and on Windows the
**2× multiplier** applies — and the #637 cost reduction already moved them to a **nightly `schedule`**.
Running them on the self-hosted runner (which incurs **no per-minute charge**) removes them from the bill
entirely, and pins the enterprise-hardware *ceiling* (#28/#29) on real hardware on a recurring basis —
something the consumer-floor local runs and the hosted Linux/Windows surrogates can't.

**Scope:**
- Add a `runs-on: [self-hosted, windows, mefor-win2025-sql]` variant of the load legs (a label-gated
  matrix arm), **`workflow_dispatch` + `schedule` only** — never `pull_request` (the #40 self-hosted
  security rule: dispatch/cron on `main` only, never fork PRs; creds from runner-local env).
- Keep any hosted load **smoke** as the PR-facing signal; the self-hosted leg is the heavy recurring
  run, **not** a merge gate (non-required, like the #40 SQL leg).
- Serialize against the other self-hosted job (the #40 SQL leg) with a `concurrency` group so two runs
  don't collide on the one VM / shared SQL Server instance.

**Depends on:** the self-hosted runner from **[#40](#40)** (done) + the VM being online when the cron
fires (the #40 VM auto-start follow-up — `vmrun … nogui` via Task Scheduler).

**Why:** the load runs are the biggest remaining billed-minutes line after the #637 reduction; the VM
runner already exists and sits idle. Pure upside (cost ↓, real-hardware coverage ↑) once the runner is
reliably online. Caveat: a self-hosted **`schedule`** only fires if the VM is up at cron time — so this
is gated on the auto-start follow-up, else the nightly silently no-ops.

**Source:** owner request (2026-06-28); [#40](#40) follow-on.

---

## 87. Competitive intelligence — study the closest code-first scripted commercial engine (non-code, recon)

> ⛔ **DECLINED — owner ruling 2026-07-24** (*"close 87"*). A non-code recon task that ships nothing runnable and blocks nobody (its own score was Value 1 / Difficulty 1). Competitive positioning is owner work picked up when the owner wants it, not a tracked engineering item — carrying it on the ledger only implies unfunded scope. _(was 🔢 P3 · Value 1/10 · Difficulty 1/10.)_

**Type:** competitive intelligence / strategy. **No code.** A research/learning task, not a feature.

**What:** Run a structured competitive study of the low-profile **commercial code-first *scripted***
integration engine whose architecture most closely mirrors MessageFoundry's model (a fast native core
with an embedded scripting language as the transform surface). **Its identity is deliberately not named
in-repo** — it is a low-profile competitor and naming it in a public/mirrored doc only gives it
exposure/SEO; the name and findings live in **private strategy notes only**. (Public positioning names
only the well-known incumbents — Mirth Connect, Corepoint — per [POSITIONING.md](POSITIONING.md).)
Study: its scripting/authoring ergonomics, deployment + ops model, throughput claims and how they are
substantiated, licensing/pricing, target customers, and docs/marketing — for what MEFOR can learn and
where it most sharply differentiates.

**Why:** it is the nearest analog to MEFOR's code-first identity, so it's the most instructive
competitor to learn *from* (and to differentiate *against* on open-source AGPL + the Python ecosystem +
payload-agnostic ingress). It is not a throughput-parity target (native engines lead on per-core speed);
the value is product/strategy learning. Naming it publicly would only advertise it.

**Why deferred / non-blocking:** strategy input, not a shipping dependency. Pick it up during a
positioning / go-to-market pass.

**Source:** owner direction 2026-06-29 (competitive-landscape discussion). Keep the subject's identity
out of any published or mirrored document.

---

## 88. Low-allocation built-ins HL7 parser — free-threading keystone + ~14× single-thread peek speedup (P2)

> ✅ **Parser DONE — built + merged #655 (2026-06-29).** The low-allocation built-ins parser shipped as the
> **default tolerant hot-path backend** ([ADR 0054](adr/0054-low-allocation-builtins-hl7-parser.md), Accepted;
> `Peek`/`Message` drop-in). What remains open is the **downstream free-threading exploitation** it unblocks
> ([ADR 0053](adr/0053-free-threaded-multicore-engine.md) WS4 go/no-go, tracked separately) — not the parser.

**Type:** core parsing / performance. The single highest-leverage perf item — it unlocks free-threaded
multi-core scaling **and** speeds up every deployment.

**What:** replace the hot-path HL7 parse (today [`parsing/peek.py`](../messagefoundry/parsing/peek.py)'s
`Peek`, built on **python-hl7**) with a **low-allocation parser that returns built-in types (dict/list/str)**
instead of a user-defined-class object tree. Measured (ADR 0053 WS3, 2026-06-29, cp314t / 265KF, 8 P-cores):
a dict/list/str parse scales **6.44× under free-threading and runs ~14× faster single-thread** (158k vs 11k
msg/s), whereas **python-hl7 caps at 2.02×** and **hl7apy at 2.04×** — both because their
`Container(collections.abc.Sequence)` object trees serialize on shared class/type machinery under
free-threading (built-in *immortal* types don't). Not allocation in general (pure dict/list/str scales
5.7–7.6×), not GC.

**Why it matters (dual win):**
- **Free-threading keystone:** ADR 0053's free-threaded multi-core path is a NO-GO with python-hl7 (~2×) but
  a **GO with this parser** (~6.4×). It is the gating dependency for [ADR 0053](adr/0053-free-threaded-multicore-engine.md).
- **Single-thread / sharding win regardless:** a ~14× faster peek raises per-core throughput → it helps the
  single-process and [ADR 0037](adr/0037-multi-process-sharding-l3.md) sharded paths **even if free-threading
  never ships**.

**Scope / hard parts:** must stay **tolerant** (real feeds are non-conformant — the python-hl7 contract),
read encoding chars from **MSH-2** (don't hardcode `|^~\&`), handle escapes / repetitions / components /
subcomponents, and back the engine's `Peek` field-path API (`MSH-9.1`, filters) + the transform `Message`
model ([`parsing/message.py`](../messagefoundry/parsing/message.py)). Strict validation (hl7apy) stays the
opt-in slow path (it won't scale, but it's rare).

**Sequencing:** the **parser is built + merged — [ADR 0054](adr/0054-low-allocation-builtins-hl7-parser.md)**
(Accepted 2026-06-29, shipped as #655 — design + the `Peek`/`Message` drop-in contract + the migration, now
the default tolerant hot-path backend). The remaining downstream is ADR 0053's WS4 / the free-threading go/no-go.

**Source:** ADR 0053 Phase-1 spike WS3 (2026-06-29). Subsumes the earlier "lazy/lean routing peek" idea.

---

## 89. hl7apy security hardening — dormant-upstream contingency + fuzz the strict-validate path (P2/P3)

> ✅ **BUILT 2026-07-10 (PLAN-9 Wave 1, branch `plan9-validate`).** hl7apy strict-validate now runs under an `asyncio.wait_for` wall-clock timeout at both inbound sites (MLLP + HTTP): a hang records `ERROR` / dead-letters (AE-NAK on MLLP) instead of pinning the listener. Owner default `_STRICT_VALIDATE_TIMEOUT_SECONDS = 5.0`; per-connection `validation.strict_timeout_s` override (code-first + `connections.toml`; `None` inherits, `≤0` disables). Ships a hand-built adversarial fuzz corpus (no `hypothesis`) + `docs/security/HL7APY-FORK-ON-CVE-RUNBOOK.md`; the 16 MiB / segment size caps were confirmed already enforced. Bounded residual: `wait_for` cannot cancel the `to_thread` worker (accepted — mirrors the `_run_lookup` precedent).

**Type:** security / supply-chain. Closes the dormant-parser gap for **hl7apy** now that ADR 0054's
built-ins parser took **python-hl7** off the tolerant hot path.

**Context:** the security posture flags python-hl7 + hl7apy as two **single-maintainer, dormant-upstream**
parsers on the untrusted-input path with **no vendored-patch contingency**
(`DEPENDENCY-INFOSEC-POSTURE-2026-06-23`). ADR 0054
removed python-hl7 from the tolerant **hot path** (we own that parser now); python-hl7's residual uses
(`transports/mllp.py`, `anon/hl7.py`, the Peek/Message fallback, the `ParseException` import) retire in
its Phase-2 removal. **hl7apy remains** for the **opt-in** `validation.strict` tier (+ the synthetic
generators, which are *not* untrusted-input). Residual risk: pure-Python **DoS** (not RCE) on a
strict-validation inbound, already bounded by the pre-parse size/segment caps + parse-fail→dead-letter
routing.

**Decision — harden, do NOT preemptively vendor hl7apy.** Vendoring gives patch-*control*, not security
*assurance*; hl7apy is large (~15–20k lines incl. v2.1–2.8.2 structure tables), high carrying cost, and
doesn't subset cleanly. Instead:
- **(a) Contingency plan** — keep hl7apy hash-locked (DEP-1, done) + document a ready-to-execute
  **fork-on-CVE** process (vendor the *patch* only if/when a CVE drops on dead upstream). This closes the
  actual "no vendored-patch plan" gap cheaply.
- **(b) Fuzz the strict-validate path** — point the ADR 0054 adversarial audit harness at hl7apy's
  parse+validate path with malformed/pathological HL7. *This* gives real security **status** (what a copy
  cannot).
- **(c) Blast-radius check** — verify the size/segment caps + a timeout apply on the strict path and that
  a hang **dead-letters** rather than wedging intake.

**Reserve actual vendoring for** a fork-on-CVE event, OR the strategic decision to **own the strict-validate
tier** — build/replace hl7apy, paralleling what ADR 0054 did for the tolerant tier (the HL7-lib-independence
endgame). Vendoring entrenches the dependency; building replaces it.

**Source:** owner discussion 2026-06-29 (post-ADR-0054 dependency review). Refines the security-posture
"two single-maintainer untrusted-input parsers" gap.

---

## 90. Free-threading reliability re-arch — H1a DB-owner-loop + H2/H3/H4 (ADR 0053 committed scope) (P2)

> ⛔ **DECLINED (2026-07-09).** Free-threading was a **NO-GO** — [ADR 0053](adr/0053-free-threaded-multicore-engine.md) records the thread-hop-fusion lever below the 10 % bar. The committed scale path is engine sharding (ADR 0037/0063). Reopen only if a real feed's transform CPU is far higher.

**Type:** core concurrency / reliability. The engine changes to run the staged-pipeline workers as real OS
threads under free-threading (cp314t), preserving the invariants. Gated on #91 (the A/B that confirms a real
engine-level win) before building.

**What** (from [ADR 0053](adr/0053-free-threaded-multicore-engine.md) WS4, all ~0 reliability cost):
- **H1a** — a dedicated store-owned event loop owns `self._db` + `self._lock`; every store call marshals onto
  it via `run_coroutine_threadsafe`, **generalizing the existing `wiring_runner._run_lookup` seam**. Keeps
  the single-writer-connection model byte-for-byte. (REJECT H1b — threading.Lock + per-loop writer pool — it
  dismantles that model = a reliability-core rewrite.)
- **H2** — immutable-swap the `_state_cache`/`_reference_cache` (build-then-flip, as `_reference_cache` does).
- **H3** — make the reload-rebinds-a-fresh-`Registry` contract enforceable (`MappingProxyType` the per-name dicts).
- **H4** — route cross-thread wakes via `loop.call_soon_threadsafe` (one `_wake_threadsafe` helper; forbid bare `event.set()` off-loop).
- **Per-lane single-claimer enforcement** — never two claimers on one lane (SQLite has no row-leasing); safe
  parallelism = across-lane + the off-loop pure-transform fan-out only.

**Scope caveat:** free-threading parallelizes only the **off-loop pure router/transform CPU** (the single-hot-feed
gap) — it does **not** move the store fsync ceiling. Complementary to ADR 0037 sharding, not a store-throughput win.

**Source:** ADR 0053 WS4 (2026-06-29).

---

## 91. GIL-on-vs-FT A/B harness on a real hot feed — free-threading final commit gate (P2)

> ⛔ **DECLINED 2026-07-20 — on four unavailable rig inputs, and on a premise measurement has since removed.** The 2026-07-10 re-score reopened this because the earlier decline misquoted ADR 0053; that correction was right at the time, but the A/B is no longer decisive.
>
> **Why it cannot pay off at the current wall.** Free-threading buys parallel CPU across cores, and the engine is **not** CPU-bound: per-shard engine CPU measures **~0.06–0.36 cores** (`docs/benchmarks/PLAN-ENGINE-ATTRIBUTION.md:81`). There is no engine-CPU saturation for FT to relieve. [ADR 0053](adr/0053-free-threaded-multicore-engine.md) itself gates on exactly that condition — **NO-GO unless a real feed's transform CPU is far higher** (`:33`: *">~23 % for +25 %, ~57 % for 2×"*) — and the related fusion lever already returned **NO-GO** at +6.5/+9.3/+10.0 % against a ≥10 % bar ([ADR 0071](adr/0071-cut-executor-round-trips-b5.md)`:3`). The wall is **store-side**, and — this matters — it is **not** transaction-shaped and remains **unnamed**: [ADR 0098](adr/0098-store-side-scaling-levers-are-exhausted-transaction-amortization-is-the-only-path-to-45m-day.md)'s authoritative H1 is *"Four store-side scaling levers are measured dead ends"*, and its **filename's** *"transaction amortization is the only path"* was **withdrawn as WRONG** the same day as an elimination inference (`0098:3-11`); [ADR 0107](adr/0107-phase-4-is-closed-transaction-reduction-is-a-measured-dead-end.md) then measured transaction-reduction elasticity at **−0.115** and closed that lever too (`0107:57-59`). ⚠️ Cite neither ADR as naming the wall. What is established is narrower and sufficient here: the wall is **not engine CPU**, and engine CPU is the only thing a GIL-vs-FT A/B could move. **Re-open only if a real feed shows transform CPU near ADR 0053's stated threshold** — that is the trigger, not a general interest in free-threading. _(was 🔢 P2 · Value 6/10 · Difficulty 5/10.)_

**Type:** measurement / gate. The GO/NO-GO confirmation for ADR 0053's scoped throughput claim **before**
building #90.

**What:** provision a **clean GIL-on control** (a genuine non-free-threaded 3.14, not just `PYTHON_GIL=1` on a
cp314t build) and measure the **engine-level** transform-path speedup on a **single hot feed end-to-end** —
the ADR 0054 parser's 6.93× is a *microbenchmark*; the real-feed engine number is what justifies the H1a rework.
Also (per ADR 0053 WS4 open items): re-measure the H1a marshal cost on enterprise NVMe-PLP, and quantify how
often real deployments are single-feed-CPU-bound on transform vs multi-feed (where across-lane asyncio already
suffices) — that determines whether #90 is worth doing now or behind the durable-throughput levers.

**Source:** ADR 0053 WS4 (2026-06-29).

---

## 92. Interactive live-debug loop in the IDE — sample-driven edit→rerun with inline annotations (P1, DX)

> ✅ **SHIPPED — verified on `origin/main` (2026-07-09).** Live-debug **v1** (#793) and **v2** (#805, per-statement inline values + hover) are both merged; `ide/src` carries the debug lanes.

> 📐 **Phased in [MULTISESSION-PLAN-7](releases/MULTISESSION-PLAN-7.md).** **v1** (L2 — IDE-only, no engine change): a debounced on-save watcher shells `dryrun --json` against a synthetic sample and renders CodeLens summaries (router routed-to · disposition · single-handler Send count — accurate multi-handler attribution is a v2 feature, since today's `--json` flattens handler→delivery). **v2** (L6): per-statement inline values + hover, driven by the new traced dry-run mode ([ADR 0072](adr/0072-traced-dryrun-mode.md)) — **PHI-redacted by default**, synthetic samples only. The deterministic sibling to an interactive AI loop (offline, no breakpoints) — see [`docs/AI-OFF-MATRIX.md`](AI-OFF-MATRIX.md).

**Type:** developer-experience feature — the highest-leverage DX investment surfaced by the **#87** competitive
recon, and the one genuine DX *differentiator* of the code-first commercial engine class.

**Gap today.** `messagefoundry dryrun` runs a Router/Handler against a sample message **once** and prints the
result — a one-shot CLI. The leading code-first **commercial** engines differentiate on an *interactive* loop:
editing the script **or** the sample instantly re-runs the logic start-to-finish against the current sample and
shows **inline annotations** — live values + expandable nested data — beside each executed line. The **#87** DX
deep-dive verified (3-0, adversarial) this breakpoint-free live-rerun-with-inline-annotations loop is **unique
among the rival engines** (the leading commercial engines use explicit-trigger models — a deploy-in-debug-mode
breakpoint step debugger, CI/scenario filter testing, or manual capture-to-file + diff — none is a live
rerun-on-edit loop). Per-connection monitoring/replay is table-stakes everyone has (that's **#75**); this loop
is not.

**Build.** A VS Code extension feature over the **existing `dryrun` engine** (no engine change): a file-watcher /
debounce re-invokes `dryrun` on every save of the script or the selected sample; parse `dryrun`'s per-step output
into structured records; render as VS Code **inline decorations / CodeLens** or a **side webview** ("annotation
windows"). Add a **sample picker** (navigate many samples; import from the message store / logs) + step-into
navigation. Rendering fork to weigh — inline decorations vs a notebook-style (`.ipynb`) surface — per the VS Code
UX guidelines the IDE already follows. Adjacent: **#84** (Test Bench before/after diff), **#48** (scaffold
snippets), **#6** (IDE functional tests).

**Leverage + known gap.** Routers/Handlers are **pure** (the at-least-once reliability invariant), so re-running
them against a fixed sample is deterministic and safe — a structural fit for this loop. **Caveat:** `db_lookup`
(ADR 0010) is non-pure and **raises in dry-run**, so live-DB-enrichment paths can't be fully annotated — surface
that limitation to users.

**Priority:** **P1** within the DX track — it is the differentiator, not catch-up. **Source:** #87 competitive DX
deep-dive + console-medium evaluation (2026-06-29).

---

## 93. Engine + database performance monitoring — engine-wide volume/connection KPI roll-up + a throughput-overload (saturation) alert (P2)

> ✅ **SHIPPED — 2026-07-12.** The two genuine net-new slivers this connective item owns, plus the DB-signals sliver, landed; the rest is cross-linked as already-shipped. **(1) Engine-wide KPI headline** — `SystemStatus.kpis` on `/status` (total messages, combined inbound+outbound endpoint count with running/stopped, engine-wide msg/s) **reusing the existing `recent_done` rate window** (no second sampler), surfaced on the console Engine Status page and the #75 web dashboard (seam v3). **(2) Saturation alert on the derivative** — a new `saturation` `AlertSink` event + `SaturationDetector` (bounded per-`(stage,lane)` depth-sample history) + `[delivery].saturation_sustain_samples` knob (deny-by-default), firing on *sustained rising backlog* (ingest > drain) and provably **NOT** on a bursty-but-draining lane, routed through the existing rules/throttle path ([ADR 0014 amendment](adr/0014-alerting-rules-engine.md); the declined timed-escalation scope is settled explicitly). **(3) DB signals** — `/metrics` gains store commit/body-copy counters + connection-pool **saturation** + acquire-wait percentiles (the `[store].pool_size` gap). Sibling monitoring surfaces (#21/#56/#74/#75/#81) were already shipped — not duplicated.

**Type:** feature — observability + alerting. A **connective** item: most of the operator-facing monitoring
surface this asks for is **already tracked** (and partly shipped) under sibling items — this entry exists to name
the two genuine **net-new** slivers none of them owns and to cross-link the rest, not to re-pitch built work.

**Already tracked / shipped (don't duplicate).** The request — "display total message volume + connection count;
monitor everything that affects throughput; alert when the system is becoming overloaded" — is largely covered:
- **#21 (DONE, PR #407)** — the Prometheus `/metrics` exporter (+ optional OpenTelemetry): per-connection
  received / delivered / errored / `queue_depth` counters + a `delivery_latency_seconds` histogram (p50/p95/p99).
  A scraping team gets per-connection throughput/latency and can `rate()`/`sum()` it in Grafana today.
- **#56 (SHIPPED 0.2.10, ADR 0044)** — resolvable alert-state: the `alert_instance` table, `GET /alerts/active` +
  ack/resolve, and the real `ConnectionRow.alerts_active` count (no longer the stubbed `0`).
- **#74 (do-next)** — host CPU / memory via `psutil` on the metrics surface.
- **#75 (scheduled)** — the zero-install **browser ops dashboard**: live per-connection **In/Out msgs/sec** over
  `/ws/stats`, Queued / Errors / Last-Activity. The natural home for a live throughput view.
- **#76 (demand-gate)** — historical-metrics charting + a status-colored data-flow graph.
- **#81 (demand-gate)** — alert escalation tiers + day/time thresholds + content (Action-Point) alerting on top of #56.
- **#64 (measure-gated)** — the throughput-*performance* roadmap (group-commit, DB durable-write IOPS as the
  leading driver). That item makes the engine *faster*; this item *warns* when load approaches capacity — they pair.
- **#50 (P3)** — app-log disk metering + a message-stall rule. **#28/#29** — the load/throughput runs that set the baseline.

**Net-new gap (what no sibling owns):**
1. **An engine-wide aggregate KPI headline.** Every count above is **per-connection** (#21) or a live per-connection
   rate (#75); nothing rolls them up into the operator's literal ask — a single **total messages through the engine**
   figure, a **combined inbound + outbound connection count** (with running / stopped breakdown), and an **engine-wide
   msg/s rate** — surfaced as first-class top-line KPIs on `/status` (or a sibling route), the console Engine Status
   page, and the #75 dashboard. Reuse the existing `recent_done` rate window that already powers `backlog_seconds`
   — don't add a second sampler. Small; mostly rides #75.
2. **A throughput-overload / saturation alert.** Every shipped alert (the **#5** framework, **#56** state, **#81**
   escalation) keys on an **absolute** per-connection/per-resource snapshot — depth/oldest-age ceilings — so a bursty-
   but-draining lane and a genuinely-overloaded engine look identical until the ceiling trips. Nothing fires on the
   *derivative*: a **rising** `backlog_seconds`, a **growing** `in_pipeline`, or **ingest rate exceeding drain rate**
   over a sampling window = "the system is *becoming* overloaded." Add a new ADR 0014 alert event keyed on that
   comparison (new `AlertSink` event + emit site + `AlertRule` dimension + a small per-lane / engine-wide rate
   history), bounded by the existing `realert_seconds` throttle and routed through the same notifier/rules path. It is
   distinct from #81 (a policy layer *on top of* existing alerts, not a new detector) and from #64 (performance tuning,
   not operational alerting). ADR 0014 already declined timed multi-stage escalation; this adds a rate/saturation
   **dimension**, which wants that scope decision settled first.

**Database performance monitoring.** Surface the throughput-affecting **DB** signals — write/commit latency and
connection-pool busy/wait/saturation (the pipeline is commit-bound; `[store].pool_size` exists but emits no
saturation metric) and router/transform-worker lag — as **metrics first** (extend `/metrics` + `db_status()`), then
optionally as overload-alert inputs. `storage_threshold` today alerts only on DB **file size** vs
`[retention].max_db_mb`, not commit/pool health. **SQL-internal** DB metrics stay **DBA-delegated / demand-gated**
(parity with #74's SQL-internal sub-scope and the DB-tier-HA decline).

**Why P2 / on-trigger.** #21 + the scheduled #74/#75 already answer the "where's the dashboard?" ask cheaply; the
net-new is the small aggregate KPI roll-up (rides #75) + the overload/saturation alert, which is genuine new engine
work and matters most once a real high-volume estate exists to overload. **Trigger:** a pilot/production estate
approaching the commit-bound capacity ceiling that needs an *early-warning* overload signal rather than after-the-fact
`queue_buildup`; calibrating the threshold wants a #28/#29/#64 capacity baseline first. Relates to **#21**, **#56**,
**#64**, **#74**, **#75**, **#76**, **#81**, **#50**, **#28**/**#29**, and the **#5** AlertSink/rules framework it extends.

**Source:** owner request (2026-06-30) — "engine + database performance monitoring and alerting; display the total
volume of messages going through the engine and the number of connections; monitor for all the things that affect
throughput and alert when the system(s) are becoming overloaded." Overlap against the existing observability/alerting
items (#21/#56/#64/#74/#75/#76/#81) reconciled the same day.

---

## 94. External BLOB-server offload for embedded documents — replace inline base64 with a stored-object pointer (OBX-5 RP) (P2, on-trigger)

> 🛠 **Decline overturned (2026-07-09).** A prioritization pass recommended DECLINE; the stated reason was **invalid**. Purity binds `@router` / `@handler` — **not connectors** (CLAUDE.md §8: “side effects (DB, network) belong in connections/transports”). This is an unfired **demand-gate**, not an architectural impossibility.

> 🔢 **Re-priced 2026-07-28 → DEMAND-GATE.** Value **6/10** · Difficulty **5–6/10** (was 8/10) · _big bet_. Strongest store-bloat lever for document-heavy feeds; only awkward workarounds (more disk, purge history) — no clean Handler fix at the persisted ingress stage. **Difficulty drops because the substrate already shipped**: [#149](#149-streaming-path-for-very-large-single-messages) / [ADR 0105](adr/0105-streaming-very-large-hl7-attachments-detach-the-opaque-document-from-the-transformable-skeleton.md) landed complete 2026-07-13, and it **deliberately reserved the deref seam for this item** — one pointer format serves both the in-store chunked attachment and #94's external BLOB (`messagefoundry/parsing/binary.py:55-62`, the `DOC_REF_MARKER = "mfdoc:v1:ref:"` handle; the shared-seam note at `:252`; the content-address contract at `:266`). So the remaining work is an external-store deref implementation behind an existing seam, not a new architectural seam at the persisted ingress stage. ⚠️ **Still ADR-first and still demand-gated** — the trigger is a document-heavy feed, and the re-price is not a licence to schedule. _(was 🔢 DEMAND-GATE · Value 6/10 · Difficulty 8/10.)_

**Type:** feature — storage minimization + customer-infrastructure integration. The ingest-time **offload**
half of **#47** (its deferred fork (b)), but targeting the **customer's existing object/BLOB store** instead
of a MessageFoundry-internal attachment table — and replacing the inline blob with an **in-message pointer**,
not a private reattach token.

**The ask.** Large base64 embedded documents (PDF reports, CCD/C-CDA, scanned images) ride inline in **OBX-5**
(ED data type) and generically via the ADR 0028 `mfb64:v1:` carriage marker
([`adr/0028-base64-binary-carriage-codec.md`](adr/0028-base64-binary-carriage-codec.md)). Today they are stored
verbatim in the raw message at **every** persisted stage (`ingress` → `routed` → `outbound`), bloating the store
far out of proportion to message count (#47's premise). Instead of pruning them *after* a window (#47(a)) or
carrying them more compactly *inside* our store (#62), **offload the blob to the customer's BLOB server at
ingest, take back the storage key/URL it returns, and embed that pointer into the corresponding OBX segment** —
so the bulky document never persists in our store at all.

**Why distinct from the siblings.**
- **#47(a)** prunes the embedded doc *after* a per-connection window — the blob still bloats all three stages
  until the window elapses, and it stays in our store meanwhile. This eliminates it *from the start*.
- **#47(b)** is the same ingest-time-offload shape but offloads to a **MessageFoundry-managed attachment store**
  (Mirth's `d_ma<channelId>` table + `${ATTACH:...}` token, reattached on outbound). This offloads to
  **infrastructure the customer already owns** and leaves a **standards-shaped pointer in the message**, not a
  private token.
- **#62** keeps the bytes in our store, just as `VARBINARY`/`BLOB`/`bytea` instead of base64-in-text. Here the
  bytes **leave** our store entirely.

**Design forks (for the ADR):**
- **Pointer representation.** Replace the OBX-5 **ED** embed with the HL7 **RP (reference pointer)** data type — a
  `<pointer>^<application ID>^<type of data>^<subtype>` reference downstream systems understand natively — versus
  an opaque MessageFoundry token (#47(b)-style) that we must reattach before delivery. RP is interoperable but
  assumes the partner can dereference the BLOB; a token keeps the message self-contained but makes us re-fetch +
  re-embed on outbound. For the generic `mfb64:v1:` carriage, a sibling `mfref:`-style pointer marker. **Never
  string-slice raw HL7** (CLAUDE.md §8) — rewrite via the parsed model/codec and re-encode.
- **Credential-bearing pointers — embed a reference, not a capability.** The message must carry a pointer a
  consumer can resolve, but a BLOB store often hands back (or we would mint) a **presigned URL / SAS token with the
  access grant baked into the string**. That must **not** be what we persist: a presigned URL in OBX-5 is a bearer
  credential to PHI living in a persisted-and-forwarded artifact (store, outbox, the partner's inbox, our logs), it
  **expires** — colliding with at-least-once **replay**, queued **retries**, **dead-letter**, and **retention** (a
  message re-sent past the TTL carries a dead pointer) — and it can't be revoked independently of the document.
  Separate the two capabilities: the **upload** grant (the presigned PUT, or MessageFoundry's own write creds) is
  used **once and discarded**; what we **embed** is a **stable, opaque, non-capability reference** — ideally a
  content-addressed object key plus the store identity (the HL7 **RP** components map cleanly: *Application ID* =
  which BLOB store, *Pointer* = the opaque key), with the consumer authenticating to the store with its **own**
  credentials (it owns the store — the premise of this feature). If a partner genuinely needs a no-auth
  dereferenceable URL, **mint a short-lived presigned URL late, at delivery** (the reattach-on-outbound fork below),
  never at ingest and never persisted — so the capability exists only transiently on the wire within a bounded TTL.
  Clean default: MessageFoundry writes with its own creds, embeds the opaque key, readers use theirs, and no
  credential URL ever touches the store or the logs.
- **Reattach-on-outbound or not.** If the receiving partner reads the BLOB itself, the pointer *is* the
  deliverable. If it needs the actual document, MessageFoundry must **re-fetch from the BLOB and re-embed** on the
  outbound — or **mint a fresh short-lived pointer** at send time (above) — a new read side-effect + egress
  dependency on delivery. Per-outbound choice.
- **Where the offload runs vs the reliability invariant.** This is a **write side-effect**, which collides with
  the "routers/transforms must be pure, every stage is at-least-once / re-runnable" invariant (CLAUDE.md §2). A
  stage re-run must not double-store or orphan blobs — favor **content-addressed keys** (hash of the bytes) so a
  PUT is idempotent. And it adds an **external dependency** to the path: if the offload sits *before* the ACK
  (alongside ingress persistence), a BLOB-server outage blocks intake/ACK; if it sits as its own pipeline stage
  *after* the ACK, intake survives but a failed offload dead-letters post-ACK (no NAK) — the ADR must pick.

**Scope (when built):**
- A **pluggable BLOB connector** registered like the destination transports (`transports/`, registry — never
  special-cased in `pipeline/`): S3 / Azure Blob / GCS / on-prem object store / plain HTTP PUT, selected +
  configured per connection. Gated by `[egress].allowed_*` allow-lists; credentials via `env()` / `MEFOR_*` (the
  connector-credential SecretProvider-seam candidate). Off the event loop.
- A **per-connection offload setting** (size threshold + target BLOB connection), layered over a global default —
  the same **global-default + per-connection-override** model as FIFO / `RetryPolicy` / #34 / #47, authored on the
  inbound `ConnectionSpec` and/or `connections.toml` (ADR 0007) so it stays hand-/GUI-editable.
- Target **both** carriage forms (HL7 OBX-5 ED and the generic `mfb64:v1:` marker) across **all three** backends
  (SQLite / Postgres / SQL Server). Preserve every invariant — never delete the row, message stays parseable after
  the rewrite, **one audit entry per offload** (key + size + content-type + connection, no content). Offload is
  irreversible from our side once the inline bytes are dropped — surface a distinct flag so an operator viewing the
  message knows the document was externalized vs never present, and audit any later **retrieval**.

**PHI note + scope boundary.** Offloading *shrinks our* at-rest PHI footprint (a data-minimization win) — the
bulky document leaves our store for the customer's BLOB. **The security of that BLOB server is explicitly out of
scope:** PHI handling, **encryption-at-rest**, and access control on the customer's store are the **customer's**
responsibility — the same trust posture we already take toward a customer database in `db_lookup`
([ADR 0010](adr/0010-handler-callable-db-lookup.md)). MessageFoundry treats the BLOB server as trusted customer-owned
infrastructure and does **not** encrypt the offloaded objects or enforce remote-store PHI controls itself. What
stays **in** scope (our responsibility): **never log a presigned/SAS URL or an identifier-bearing object key**
(§9) — the former is a bearer credential to PHI, the latter is PHI itself; an opaque, auth-gated reference is safe
to log. And **audit each retrieval** as a PHI access. (Logging is still stdlib with no structlog redaction yet, so
this is a deliberate connector-level "log the object key/length, never the signed URL" discipline, not an
automatic scrub.) The customer's BAA must cover the BLOB store; restate this boundary in [`PHI.md`](PHI.md) when
built.

**Why P2 / on-trigger.** This is the strongest store-bloat lever for heavy document feeds (radiology PDFs, CCDs)
and the cleanest fit for a customer who **already runs** object/BLOB infrastructure and wants their documents
living there. But it is a side-effecting pipeline change touching the purity / at-least-once invariant **plus** a
new connector family — it wants its own ADR (the forks above) before code, and is not an open exposure on the
shipping config. **Trigger:** an adopter with an existing BLOB/object store and a document-heavy feed who wants the
documents offloaded out of our store. Relates to **#47** (the in-store prune/offload sibling — shared
per-connection plumbing; this realizes its deferred fork (b) against external storage), **#62** (in-store binary
carriage), **#34** (per-connection retention), **ADR 0028** (base64 carriage), **ADR 0007** (`connections.toml`),
and the connector-credential **SecretProvider** seam.

**Source:** owner request (2026-06-30) — "integrate with the customer's existing BLOB servers to offload base64
documents; eliminate the base64 documents from our data store — instead get a pointer back from the BLOB and embed
that into the corresponding OBX segment." Reconciled against the in-store siblings #47 / #62 the same day.

---

## 95. Engine-brokered AI assistance — integrate the IDE coding assistant with a customer's managed AI subscription or in-house LLM instance (P3, on-trigger)

> 🔢 **Re-scored 2026-07-10 → DEMAND-GATE.** Value **5/10** · Difficulty **6/10** · _money pit_. BYO vscode.lm cleanly covers the mainstream case; the broker adds real but narrow central per-use AI-egress audit and in-house-only-LLM support. _(was DEMAND-GATE · V2/5 · D3/5)_

> **AMENDED 2026-07-28 — the engine broker IS built; the remainder is narrower than this item reads.** Adversarial verification refuted a full close. **BUILT:** the engine-side broker (`messagefoundry/transports/ai_broker.py`), its per-use AI-egress audit, and the IDE flip — [ADR 0135](adr/0135-engine-brokered-ai-assistance-customer-managed-llm-egress-with-per-use-audit.md), `code_only` + non-streaming MVP.
>
> ⚠️ **The REMAINDER is the generic customer-endpoint mode, and it is half-merged in a way that fails confusingly.** `provider` is **accepted but never read** — stored at `ai_broker.py:143` and used nowhere — and `chat()` unconditionally sends the **Anthropic Messages** wire body with `anthropic-version` / `x-api-key` headers regardless of it (the shape is documented as the MVP provider at `ai_broker.py:62`). So every backend this item names — Azure OpenAI, Bedrock, an internal gateway, vLLM, Ollama — rejects that body as an **opaque 502 rather than a config error**, and no validator refuses a non-`claude` provider. Also `docs/AI.md` still declares *"No model-provider or engine broker integration exists yet"* and omits `api_key`/`allowed_endpoints` — stale, since the broker shipped.

**Type:** feature — AI governance + customer-infrastructure integration. Turns the **reserved-but-unused**
`[ai]` broker config keys into a real integration: let the **engine broker** the IDE assistant's model calls to a
provider the *customer already runs* — their own cloud AI subscription (Azure OpenAI, Anthropic/Bedrock, an internal
Copilot-compatible gateway) or a **self-hosted / on-prem LLM endpoint** (vLLM, Ollama, an internal inference service)
— under central, **per-use-auditable** egress control. The policy model, config schema, RBAC, and policy endpoint
**already exist** ([`AI.md`](AI.md)); this builds the broker they were designed for.

**Already there (don't duplicate).** A customer's existing AI **subscription** is *already* the integration point
today, via **BYO** ([`../ide/src/chat.ts`](../ide/src/chat.ts)): the assistant is provider-agnostic and uses whatever
model the developer picked in VS Code's Chat view (Copilot / Copilot Enterprise under the org BAA, Claude, etc.)
through the `vscode.lm` Language Model API — and **any in-house instance that registers as a VS Code language-model
provider** (a Copilot-compatible internal proxy or a custom chat-model extension) is picked up the same way,
engine-blind. The governance around it is built too — the `[ai]` policy (`mode` × `data_scope`,
production-posture-clamped), the `ai:assist` RBAC permission, `GET /ai/policy` + the `messagefoundry ai-policy` CLI,
and the central-*off* switch honored on every workstation. What is **not** built is the **engine-brokered** path:
`managed_claude` / `managed_claude_baa` are accepted as policy values but the IDE deliberately refuses to service them
(it will **not** silently fall back to BYO), and the `provider` / `model` / `baa_attested` / `endpoint` config keys
are **accepted but unused** — placeholders the broker was meant to consume.

**Net-new gap (what no sibling owns):**
1. **The engine-side broker.** AI.md's *Future direction* (P1/P2) puts model egress behind the **engine** — not the
   dev's IDE — so a central operator controls and **per-use audits** every call, and `phi` scope becomes reachable
   only under `managed_claude_baa` over a **BAA + zero-data-retention** connection. None of this exists: it needs a
   new engine API surface (the engine proxies the chat request), the IDE client switching from `vscode.lm` to the
   engine for managed modes, and per-use egress auditing (today even policy *reads* aren't audited — that arrives
   *with* the broker).
2. **A generic customer-endpoint mode, beyond Anthropic-managed Claude.** The only future modes named today
   (`managed_claude` / `managed_claude_baa`) are framed around an **Anthropic-managed** Claude. A customer's **own
   subscription** (their Azure OpenAI / Bedrock keys, their internal gateway) or a **self-hosted endpoint** is a
   *different* shape: the customer supplies `endpoint` + `provider` + `model` + credentials and MEFOR just brokers to
   it. That wants either a new `managed_endpoint` (engine-brokered, customer-keyed) mode or an explicit
   generalization of `managed_claude`, finally wiring in the reserved `endpoint` / `provider` / `model` keys.

**Design forks (for the ADR):**
- **Why broker at all when BYO already works?** BYO's limit is that it is **dev-machine-local and engine-blind** —
  ops can centrally turn it *off* and cap scope, but cannot *see* or *audit* individual calls, and the model is
  whatever the dev configured in VS Code. The broker buys central egress control, per-use audit, and a single
  operator-pinned `endpoint` / `model` — at the cost of routing AI traffic through the engine. Some customers want
  exactly the opposite (keep AI entirely off the engine), so this is **additive, never a replacement** for BYO.
- **`managed_endpoint` vs generalize `managed_claude`.** A new mode keeps the existing Claude modes clean;
  generalizing avoids mode-proliferation. Either way the IDE's current "managed → disabled" branch flips to
  "managed → call the engine broker."
- **Credentials + egress.** Customer keys / endpoint via `env()` / `MEFOR_*` (the connector-credential
  **SecretProvider** seam), gated by an `[egress].allowed_http` allow-list like `fhir_lookup` / SMART; the broker
  call runs **off the event loop**. A self-hosted endpoint (vLLM / Ollama) often needs no BAA (on-prem) — but the
  **`data_scope` ceiling still applies**: `phi` stays reachable *only* under the BAA + ZDR attestation, never merely
  because the endpoint is on-prem.
- **PHI boundary unchanged for the MVP scopes.** Until de-id wiring into the AI scope path and the broker land
  together, the assistant still attaches **`code_only`** context regardless of mode — the broker changes *who makes
  the call and how it's audited*, not *what data* may be sent without a posture change.

**Why P3 / on-trigger.** BYO already covers "use our existing AI subscription" for the common case
(Copilot-under-BAA, or an in-house model surfaced through VS Code) with **zero** engine work — so this is genuine new
engine + IDE + audit surface that earns its cost only when a customer specifically wants **engine-centralized,
audited** AI egress to **their** managed / self-hosted endpoint (e.g. a security team that mandates all AI traffic
flow through one audited choke point, or an estate whose only LLM is an internal one not exposed to VS Code).
**Trigger:** a customer asks for engine-brokered AI to their own subscription / in-house instance, **or** we have the
bandwidth to build out the documented P1/P2 broker. ADR-first (the forks above). Relates to [`AI.md`](AI.md) (the
policy model + reserved keys this realizes), [`PHI.md`](PHI.md) §9 (de-id, the gate to scopes above `code_only`), the
**SMART** / `fhir_lookup` egress-allow-list + off-loop precedent ([ADR 0024](adr/0024-smart-backend-services-token-provider.md) /
[ADR 0043](adr/0043-fhir-read-lookup.md)), and the connector-credential **SecretProvider** seam.

**Source:** owner request (2026-06-30) — add the engine-brokered "integrate the IDE coding assistant with a
customer's existing AI subscriptions or in-house instances" capability as a demand-/bandwidth-gated item; build when
a customer wants it or when we have bandwidth. The already-shipped BYO coverage + the reserved broker config keys were
reconciled the same day.

---

## 96. Built-in "setup tester" — self-service capacity estimator that benchmarks the deployed setup and reports how much traffic it can handle (P2, adopter-facing)

> 🔢 **Re-scored 2026-07-10 → DEMAND-GATE.** Value **6/10** · Difficulty **5/10** · _quick win_. Adopter capacity self-test; the manual dev-harness workaround is awkward; net-new is a ramp-to-knee estimator plus backend-aware diagnosis. _(was DEMAND-GATE · V3/5 · D3/5)_
>
> ⚠️ **BUILD GATED (2026-07-14) — the MEASUREMENT layer only.** A validity re-check of the governing
> [ADR 0074](adr/0074-adopter-capacity-estimator.md) against STEP-4 Arm 0 returned **14 confirmed blockers**, each
> over-reporting capacity to an adopter: the named *"only success gate"* admits **3–5.5×** the true sustainable rate
> (`R ≤ C·(1 + D/H)`); the **poller-zero failure mode satisfies that gate**; the per-step estimand is **intake
> acceptance, not delivery**; the *sum-across-interfaces* aggregate is **measured-false (~11×)**; the ceiling is an
> unstated **instant-partner** bound; and *"reuse, don't reinvent"* does **not** hold — **there is no knee-finder and
> no per-step gate in the harness** (`grep -rn "knee" harness/` → only TOML comments, zero code), so **v1 must be
> re-priced** (the _quick win_ / Difficulty 5 score above is no longer trustworthy).
> **Still valid and buildable:** the premise, the hard requirements, and the fail-closed **guard** layer
> (isolated-store refusal, synthetic-only, backend-aware *negative* rule, sink-cap **with an `INCONCLUSIVE`
> outcome**). **Do not build the measurement layer** until the owner re-ratifies the sustain gate + estimand —
> the required changes are listed in the ADR's 2026-07-14 Amendment.

**Type:** feature — an operator/adopter-facing **capacity self-test** shipped *with the engine*. It runs the
same style of measurement we do for throughput testing, but as a first-class, on-demand command an adopter
points at **their own** setup (this box, this store backend, this config) to get back an **estimate of how
much traffic that setup can sustain**.

**What:** a `messagefoundry` subcommand (e.g. `messagefoundry capacity` / `setup-test`) that drives a
controlled synthetic load through the real engine and reports an **estimated sustainable throughput** — a
headline **msg/s** and **msg/day** figure, ideally **per-inbound-interface** *and* engine-wide, plus the
**limiting factor** (commit-bound / pool-saturated / CPU / disk) and a confidence caveat. It ramps to the
saturation knee (where `in_pipeline`/`backlog_seconds` start rising faster than drain — the #93 signal) and
reports the last rate that drained cleanly with no loss, rather than a raw peak. Reuses the **BUILT load
harness** measurement machinery ([`harness/load/`](../harness/load/), [`docs/LOAD-TESTING.md`](LOAD-TESTING.md))
— the rate governor, the fast correlation sink (true end-to-end latency), the drain gauge (`in_pipeline`), and
the no-loss reconciliation — packaged as a supported engine capability rather than a dev-only tool.

**Distinct from what already exists (don't duplicate):**
- **#28 / #29 (DONE)** are the *developer/benchmark* runs of the harness against a synthetic high-fan-out
  system-under-test, producing the **project** [`benchmarks/TUNING-BASELINE.md`](benchmarks/TUNING-BASELINE.md)
  baseline. This item is the *adopter-run* inverse: point it at **the real deployed config on the real box** and
  get a sizing number for *that* deployment — not a project baseline, and not something that needs the harness's
  synthetic SUT config or the denylist-guarded estate profiles.
- **#93 (P2)** is the *passive, runtime* counterpart — it watches real traffic and **warns** when live load is
  approaching capacity. This item is the *active, pre-cutover* counterpart — it **measures** where that capacity
  is in the first place, so #93's overload threshold can be calibrated against it. They pair.
- **#40** is the enterprise-hardware CI leg; this tester is what an adopter would run **on their own hardware**
  to reproduce a sizing number without CI access.

**Design constraints (for the eventual ADR):**
- **Must not pollute production.** A capacity run generates real store writes and would otherwise inflate the
  true inbound counts (the count-and-log invariant persists *every* received message). It must run against an
  **isolated/ephemeral store** (temp DB) or a clearly-marked test namespace, and never leave synthetic rows in,
  or skew the metrics of, the live message store.
- **Synthetic payloads only — never real PHI.** Drive it from the conformant generators
  ([`generators/`](../messagefoundry/generators/)) / the anon framework (ADR 0030), consistent with the
  dryrun/generate PHI rule (never against real PHI, never redirected to a committed file/CI log).
- **Respect the per-interface bound.** Report capacity **per inbound interface** and note that a single strictly-
  ordered feed is core-bound (owner principle: fan out feeds at source, not infinite single-feed speed) — an
  engine-wide total is the sum across interfaces, not a single-feed number. Sequence-keyed lanes (#3) are the
  sanctioned single-feed escape hatch when one feed outgrows a core.
  > ⚠️ **CORRECTION (2026-07-14):** the *"engine-wide total is the **sum** across interfaces"* rule is
  > **MEASURED-FALSE and over-reports** — interfaces are **not independent**; they contend on a shared upstream
  > (store-side) wall, so per-interface ceilings do **not** add.
  > [`benchmarks/THROUGHPUT-STATUS-2026-07-10.md`](benchmarks/THROUGHPUT-STATUS-2026-07-10.md) §4 measured **87
  > delivered/s across 16 lanes — 5.44/s per lane**, far below the ~60/s per-lane ceiling, because *"those lanes are
  > starved **upstream** by a **store-side** wall"*; summing predicts 16 × 60 = **960/s vs a measured 87/s (~11×)**.
  > **Take `min(measured concurrent multi-interface aggregate, Σ per-interface)` and prefer the measured concurrent
  > run — never compose the aggregate.** (Blocker **B4**, [ADR 0074 Amendment](adr/0074-adopter-capacity-estimator.md);
  > the same rule is corrected in [`THROUGHPUT.md`](THROUGHPUT.md) §7.)
- **Name the limiting factor**, reusing the #93/#64 signals (commit/write latency, `[store].pool_size`
  busy/wait, CPU/mem via #74, `in_pipeline` growth) so the output is *"~N msg/s, engine-CPU-bound"* rather than
  a bare number. The named factor must be **store-backend-aware**: the 2026-07 throughput campaign (evidence
  below) refined the earlier "commit-bound" read — on a two-box SQL Server deployment the *per-box* ceiling is
  **engine-CPU-bound** (async/executor plumbing, not the store) and the *connection-scale* wall is a **store
  claim-storm** (lock/latch contention, fixed by pooled claim mode — ADR 0066), while store *commit* throughput
  itself carries ~11–36× headroom. A single fixed "commit-bound" label would mislead.

**Supporting evidence from the throughput campaign (2026-07, AWS two-box SQL Server bench; synthetic HL7 on an
isolated `mfbench` DB — no PHI).** The WS-B / WS-C / pooled-A/B work produced the concrete measurement toolbox and
the PASS/FAIL methodology this tester would productize — recorded here so the eventual ADR/build *reuses* it
rather than rediscovering it. Facts below are **MEASURED**; the shaping suggestions are **RECOMMENDATIONS** (the
scoping is the ADR's call).

> ⚠️ **CORRECTION (2026-07-14) — two pieces of the guidance below are now known-unsafe. Read them with these fixes.**
> (Source: the [ADR 0074 Amendment](adr/0074-adopter-capacity-estimator.md), a validity re-check vs STEP-4 Arm 0.)
>
> 1. **"delivered/offered with loss reconciled … as the *only* trustworthy success gate" is NOT sufficient — on its
>    own it OVER-REPORTS by 3–5.5×.** A rung can be lossless-and-eventually-drained yet have been **FILLING** the
>    whole hold (Arm 0: E2E climbed **455 ms → 50,672 ms** while no-loss *and* drain both passed — it drained only
>    because the offer stopped). Drain-clearance admits `R ≤ C·(1 + D/H)`. **Note the same bullet already names the
>    right companion signal — *"`in_pipeline` trajectory (flat vs climbing) is the clearest pass/fail"*. Keep BOTH:
>    a rung is sustained only if it is no-loss AND non-filling.** ADR 0074 took the loss gate and dropped the
>    trajectory signal; that is the regression the amendment gates.
> 2. **The poller-zero remedy is CIRCULAR.** *"detect it and **default to a sub-ceiling rate-walk** (report the clean
>    no-loss knee)"* does not work: `/stats` zeroes **`in_pipeline`** under overload, the drain gate *requires*
>    `in_pipeline == 0`, and the knee is read from **the same zeroed fields** — so the failure mode **satisfies** the
>    gate and the fallback inherits the contamination. A `/stats` staleness detector must be a **hard precondition**;
>    a poller-zeroed rung is **INCONCLUSIVE**, not "fallen back"; **sink-side counters** must be the primary
>    loss/backlog authority.

- *Metrics that actually discriminated good vs bad config — report these, not one blended "throughput" number:*
  **intake (acked/s) and delivery (delivered/s) are separate walls** (runs saw ~517/s acked at 98.5% while
  delivery lagged ~5× at ~33% — a single number hides it); **`in_pipeline` trajectory** (flat vs climbing) is the
  clearest pass/fail; **ACK-latency p50/p95/p99** (overload hid a p99 of 44–54 s behind a benign mean);
  **`pool_wait_p95`** (pegged at 5000 ms under the store claim-storm, ~25 ms once fixed — a direct read on pool
  saturation); **store-side DMVs** (`LCK_M_U`, `PAGELATCH_EX`, `WRITELOG`, SQL CPU%) — these, *not* engine
  counters, named the actual wall in both WS-B and WS-C, so an engine-only tester would mis-diagnose; and
  **delivered/offered with loss reconciled across all sinks** as the only trustworthy success gate.
- *Which knobs mattered vs were inert (so the tester rates the right things, store-backend-aware):* **claim mode
  (per-lane vs pooled)** and **engine count / engine-CPU** dominated — at 1500 lanes per-lane claiming storms the
  store to 92% CPU *at zero messages* while pooled claimers (ADR 0066) collapse that to 20–25%; the per-box engine
  ceiling ~193/s is **engine-CPU-bound** (~76% of GIL-holding CPU is async/executor/lock plumbing —
  `ENGINE_CPU_PROFILE.md`; N=1 = 193/s, N=2 = 383/s). **`poll_interval`, `pool_size`, `per_lane_wake`/B12 were
  inert** at the connection-scale wall — do **not** present them as tuning levers without measuring; B12/per-lane-
  wake looked like a big win on **SQLite** (a call-count artifact) but had **no benefit on SQL Server**, so never
  carry SQLite-derived knob rankings onto SQL Server. The **store commit ceiling has large headroom** (~29k
  commits/s vs the ~2,600/s the engines used, ~11–36×), so the connection-scale wall is store **contention**, not
  commit throughput (`DELAYED_DURABILITY=FORCED` cut WRITELOG 75× without raising throughput — a symptom, not the
  ceiling). And **host TCP** (TIME_WAIT / ephemeral-port exhaustion) plus **outbound connection reuse** gate
  *delivery* independently of engine config — widening `dynamicport` + `TcpTimedWaitDelay=30` moved delivery
  40%→58% (connect-per-delivery MLLP is the culprit; see #97 persistent outbound).
- *Pitfalls a productized tester must handle (they bit the campaign):* (1) **poller-zero contamination** — the
  engine `/stats` poller returns 0 for `engine_read`/`delivered`/`in_pipeline`/`pool.idle` under overload, so the
  exact pass criteria go unmeasured in the runs that most need them; detect it and **default to a sub-ceiling
  rate-walk** (report the clean no-loss knee), treating a single saturating hold as a stress check, not the
  capacity number. (2) **Sink-capping** — local sinks cap ~135–144/s *per sink process*, so too few sinks
  measures the tester, not the config (need ≥5–6 sinks; success = delivered ≈ offered). (3) **Saturated-backlog
  artifacts** — a raw "429/s" was an overload artifact; report ceilings from the rate-walk, not the saturating
  run. (4) **Loss reconciliation + BOM-tolerant input** — correlate loss across all sinks; real configs feed
  messier input than a clean generator.
- *Prior-art artifacts to mine (all under the operator's off-repo `aws-bench/` tree — synthetic only):* the
  fixed-rate-hold / rate-walk loop, `multishard.py` (N-engines-on-one-store driver + `foreign_rows` lane-isolation
  check), `commit_storm.py` / `ws_b_storm.py` (driver-free store-only ceiling), the `store_capture_*` DMV probe,
  `ws_b_profile.py` / `ENGINE_CPU_PROFILE.md` (py-spy `--gil` engine profile), `capture_engine_cpu_auto.py`
  (per-process engine-vs-driver CPU split), and `test_staged_pipeline.py` (the 42/42 correctness gate — run it *at
  the rated config*, not just raw rate). See the recorded sizing arc (throughput matrix / per-interface bound /
  commit-bottleneck / WS-B engine-CPU-wall analyses) for context.

**Why P2 / on-trigger.** Turns capacity sizing — today a manual "run the dev harness + read TUNING-BASELINE by
hand" exercise — into a **supported operation** an adopter can self-serve before a cutover (*"will this box carry
our ~1.6M ADT/day?"*). The measurement machinery already exists; the net-new is the operator-facing command, the
isolated-store harness, the ramp-to-knee estimator, and the capacity report. **Trigger:** a pilot/adopter needing
a self-service pre-cutover capacity check on their own hardware (the ADR 0017 consumer-deployment pattern), or the
#93 overload-alert threshold needing a per-deployment capacity baseline to calibrate against. Relates to
**#28**/**#29** (the harness it wraps), **#40** (enterprise-box runs), **#64** (the throughput-performance
roadmap), **#93** (the runtime overload-alert counterpart), and the recorded sizing work (throughput matrix /
per-interface bound / commit-bottleneck analyses).

**Source:** owner request (2026-06-30) — "add a setup tester to the engine … do tests like we're doing for
throughput testing and report back an estimate of how much traffic the setup can handle." Supporting evidence
appended 2026-07-04 from the AWS throughput-campaign handoff (WS-B / WS-C / pooled-A/B), which the operator
filed against this item.

---

## 97. Keep-alive / persistent outbound connections — per-connector setting (P3, on-trigger)

> ✅ **SHIPPED — merged 2026-07-24 (PR #1220); verified against `origin/main` (2026-07-28).** The residual — porting MLLP's persistent-connection pattern to the `Tcp()`/`X12()` outbounds — is built behind a per-outbound `persistent=false` opt-in with the same knobs and semantics as MLLP minus TLS (raw TCP has none): `self.persistent` + `idle_timeout_seconds` + `max_connection_age_seconds` at `messagefoundry/transports/tcp.py:124` and `messagefoundry/transports/x12.py:94`. [ADR 0067](adr/0067-persistent-outbound-mllp.md) now carries the `Tcp()`/`X12()` parity box checked at `:128` and a full **§9 amendment** (`:130`) fixing the reconnect model to exactly-one-redial-before-first-byte (**not** this item's original "reconnect-with-backoff" wording — a failed redial is a normal charged `DeliveryError` the delivery worker retries). **This supersedes any framing that the work is stranded on the `dg-s5` lane: it is on `main`.** _(was 🔢 DEMAND-GATE · Value 3/10 · Difficulty 3/10.)_

**Type:** feature — a per-outbound-connection option to **hold the TCP link open across deliveries** (keep-alive / persistent) instead of the current connect-per-message behavior.

**What:** an opt-in **per-connector setting** (e.g. `keepalive = true` / a `connection_mode = "persistent" | "on_demand"` knob in the outbound's `settings`, default `on_demand` so existing configs stay byte-identical) on the MLLP / raw-TCP / X12 outbound connectors. When enabled, the delivery worker reuses one open connection (reconnecting on drop/idle), rather than opening + closing a fresh socket every message as it does today. Wants: a bounded idle-close / max-lifetime, reconnect-with-backoff on a dropped link, and clean teardown on `stop()`/reload — all per-connection, with the setting validated at build (dry-run / `check`), consistent with the other outbound knobs.

**Why:** confirmed gap — every TCP-family outbound opens a **fresh connection per delivery** today and there is no toggle: `MLLPDestination` ([`transports/mllp.py`](../messagefoundry/transports/mllp.py), *"Phase 1 opens a fresh connection per delivery … a persistent/pooled connection can come later"*) and `TcpDestination` ([`transports/tcp.py`](../messagefoundry/transports/tcp.py), *"Opens a fresh connection per delivery … pooling can come later"*); listed as an unbuilt MLLP feature gap in [`CONNECTIONS.md`](CONNECTIONS.md) ("keep-connection-open/pooling"). Inbound listeners are already persistent (peer-driven, idle-bounded by `receive_timeout`) — this closes the outbound half. The connect-per-message default is simple and robust to flaky peers, so this is genuinely additive and stays **off by default**; the at-least-once / idempotent-receiver contract is unchanged (a reused link that drops mid-ACK still retries, same as today). **Trigger:** a partner that needs a held-open link (a persistent-session receiver, or a high-rate feed where per-message connect setup is measurable overhead). Relates to **#82** (the sender-polish bundle this splits from — pacing + MSA-2↔MSH-10 matching stay there), **#46** (connection lifecycle events would gain reconnect/retry signals), and **#65** (outbound-connector option surface).

**Source:** owner request (2026-06-30) — "add keepalive feature for outbound connections, controlled by a setting per outbound connector."

---

## 98. Kerberos SSO channel-binding (EPA) opt-in + acceptor-enforcement spike (P3, on-trigger)

> 🔢 **Re-scored 2026-07-10 → DEMAND-GATE.** Value **3/10** · Difficulty **3/10** · _fill-in_. Narrow EPA channel-binding hardening for the opt-in in-process-TLS SSO mode; distinct from the proxy posture but nobody's blocked and it's largely a spike. _(was DEMAND-GATE · V2/5 · D2/5)_

> **On-trigger / demand-gate.** Recorded from the ADR 0068 open items (browser Kerberos SSO, L5c).

**Type:** security hardening spike + (conditionally) a per-mode opt-in knob.

**What:** (a) **Spike:** determine whether pyspnego's server acceptor ENFORCES a client-supplied
channel-binding token when constructed with `channel_bindings=None` (GSSAPI acceptors traditionally
ignore client CBT unless the acceptor supplies bindings; Windows SSPI may enforce under registry/EPA
policy) — this decides whether the WP-15 reverse-proxy posture works untouched or needs an explicit
CBT-off knob. (b) If enforcement is possible and wanted: an opt-in `tls-server-end-point` binding for
the **in-process-TLS** termination mode only (behind a TLS-terminating proxy EPA is structurally
broken — the browser hashed the proxy's certificate — so it must never be silently enforced there;
see OFF-LOOPBACK-DEPLOYMENT.md). Also fold in the other two
recorded SSO open items when a lab DC exists: a domain-joined end-to-end smoke of `GET /ui/sso`
(mock-seam coverage proves the HTTP state machine, not SSPI/keytab/browser reality) and the
mutual-auth `out_token` browser-behavior question.

**Why:** ADR 0068 §9 ships browser SSO with `channel_bindings=None` always and records the CBT
question as a spike; the L5c code is deliberately containment-first (off by default, boot-once
preflight, single-leg). **Trigger:** a deployment that wants EPA, or the first domain-joined lab box
(project memory: the test-server box has no AD). The Phase-2 AD-fidelity lab in **#99(e)** is exactly
that first domain-joined box — run this spike alongside it.

---

## 99. AD/gMSA production-deployment hardening — turnkey enterprise (Windows/AD) install (P3, on-trigger)

> 🚧 **PARTIAL (built 2026-07-12).** Turnkey polish shipped; the **live domain-lab smoke deferred** (needs a real DC + AD CS + gMSA, same gate as #98). **Shipped:** (a) `install-service.ps1` gMSA preflight — `Test-ADServiceAccount` for a `-ServiceAccount` ending in `$` + `secedit`-granted **`SeServiceLogonRight`** before NSSM registration, both **degrading gracefully** on a non-domain/RSAT-less box (skip-with-message, never abort); `-SkipGmsaPreflight` to opt out. (b) `-AllowLocalSystem` opt-out + enhanced LocalSystem warning — enforced **now** as warn + acknowledgement; the **default-FLIP to refuse** is honestly recorded as **gated on the `windows-service-smoke` CI leg** (not flipped live, so no unattended install breaks). (d) **IIS + ARR** reverse-proxy-mTLS reference config added to `docs/security/OFF-LOOPBACK-DEPLOYMENT.md` (require client cert, preserve `X-Forwarded-Proto`/`-For`, exact-peer `trusted_proxies`, placeholders only) beside the existing nginx/Caddy. (f) integrated + gMSA **worked example** in `docs/DEPLOY-SERVER-DB.md §1.1` (`[store].auth=integrated` → `Trusted_Connection=yes`, NSSM `ObjectName=CORP\svc$`, `CREATE LOGIN [CORP\svc$] FROM WINDOWS` least-priv grant) + cross-ref in `CONFIGURATION.md`; **SPN checklist finalized** in OFF-LOOPBACK-DEPLOYMENT.md (gMSA SPN on the account object, "Log on as a service", `PrincipalsAllowedToRetrieveManagedPassword`, IIS/ARR `Negotiate` pass-through). **(c) Windows cert-store (thumbprint) sourcing for `[api]` TLS — SCOPED OUT** (documented, not built): Python `ssl` is OpenSSL not SChannel, and `load_cert_chain` needs cert+key **files**; a non-exportable CNG key in `LocalMachine\My` cannot be handed to OpenSSL, so a store-thumbprint `[api]` TLS source is stdlib-infeasible (same shape as the ECH scope-out, ADR 0093) — supported paths documented instead (terminate at IIS/ARR which *can* use the machine store by thumbprint, or export an AD CS cert to PEM). **Deferred/scoped-out:** (e) real domain-lab gMSA/SSO/reverse-proxy smoke (live DC + AD CS + gMSA — same gate as #98); (g) engine-side "require an AD MFA claim" hook (build only on a customer requirement). No ADR (decisions folded into the deployment docs, per the item plan). _(was 🔢 DEMAND-GATE · Value 6/10 · Difficulty 6/10.)_

> **AMENDED 2026-07-28 — this is no longer a 6/6 engineering build; ONE sub-item remains, and it is PROVISIONING, not code.** ⚠️ **Do not schedule this as a build.**
>
> * **(g) — engine-side "require an AD MFA claim" hook: SHIPPED**, not "build only on a customer requirement". It landed via **#274** / [ADR 0142](adr/0142-federated-sso-oidc-authorization-code-pkce-relying-party-hybrid-ad-backed.md) as `oidc_require_mfa_claim: bool = True` (`messagefoundry/config/settings.py:1854`, enforced at `:2102`) — note it ships **on by default**. *(ADR 0142's own status line reads "Proposed — code COMPLETE, awaiting lab validation": the code is merged and green; the ADR flips to Accepted only when its runbook cells report. The **hook exists** either way.)*
> * **(b)** was closed separately via **#224**. **(c)** remains a documented stdlib scope-out (OpenSSL, not SChannel) — a decision, not a task.
> * **(e) — the live domain-lab gMSA/SSO/reverse-proxy smoke — is the ONLY residual**, and it needs a real DC + AD CS + gMSA. That is **rig/provisioning the project does not own** (same gate as [#98](#98-kerberos-sso-channel-binding-epa-opt-in--acceptor-enforcement-spike-p3-on-trigger)); it is gated behind **#275**. No engineering capacity closes it.
>
> ⚠️ **Two cross-references above resolve to paths that no longer exist from this baseline** (`docs/security/OFF-LOOPBACK-DEPLOYMENT.md`): `docs/security/` is **gitignored post-cutover**. The deployment content is intact for operators with the working tree; the links simply do not resolve in the public repo. See [`SECURITY-DOCS-POLICY.md`](SECURITY-DOCS-POLICY.md).

**Type:** deployment hardening — close the last-mile gaps between "the identity primitives exist" and a
turnkey, documented, validated enterprise Windows/AD install.

**What:**
- **(a) Installer AD-side gMSA provisioning (S).** `install-service.ps1` sets the NSSM `ObjectName` to a
  gMSA but stops there — it does **not** run `Install-ADServiceAccount`/`Test-ADServiceAccount` (verify the
  host can retrieve the managed password before registering a service that would else fail to start) nor
  grant **`SeServiceLogonRight`** ("Log on as a service"). Today an operator does both out of band or the
  service start silently fails. Add an optional preflight + logon-right grant so the gMSA path is turnkey.
- **(b) Least-priv default flip (S).** Make a least-priv service account the default behind a
  `-AllowLocalSystem` opt-out — the pending piece of the **least-priv service-account default** row above.
  Gated on a green `windows-service-smoke` leg; the enterprise-lab smoke (item e) helps prove it.
- **(c) Windows cert-store (thumbprint) sourcing for `[api]` TLS (M).** `build_api_ssl_context` /
  `load_cert_chain` take **PEM file paths only** (`api/tls.py`), so **AD CS autoenrolled** certs (which
  live in `LocalMachine\My`) must be hand-exported to PEM and rotated manually. Optionally source the
  `[api]` cert/key (and the mTLS client-CA) from a **cert-store thumbprint** to close the AD-CS-autoenroll +
  gMSA story (no PEM on disk, no manual rotation).
- **(d) IIS + ARR reverse-proxy-mTLS reference config (S).** `OFF-LOOPBACK-DEPLOYMENT.md` documents nginx +
  Caddy only. A Windows shop fronts with **IIS + Application Request Routing** — add an IIS/ARR reference
  (require client certificate; preserve `X-Forwarded-Proto`/`-For`; exact-peer `trusted_proxies`) as the
  Windows-native sibling for the ASVS 8.4.2 managed-admin-host posture.
- **(e) Real end-to-end TLS/proxy + gMSA-SSO smoke (M — infra, not code).** Every serve-path TLS/proxy
  assertion today monkeypatches `uvicorn.run` and checks kwargs; the reverse-proxy behavior and the
  SSPI-under-gMSA acceptor are unit-tested / mock-seam only (`kerberos_principal` is `# pragma: no cover`).
  A domain-lab smoke (DC + AD CS + a gMSA-service engine + a reverse-proxy-mTLS front + a domain-joined
  client) is the first real validation — required **before recommending** the AD/SSO story to a customer
  (ties to ADR 0068 §9 open items + #98's acceptor-enforcement spike).
- **(f) Docs (S).** Add an `integrated` + gMSA worked example to `CONFIGURATION.md`/`DEPLOY-SERVER-DB.md`
  (`MEFOR_STORE_AUTH=integrated`, NSSM `ObjectName=DOMAIN\svc$`, GRANT the gMSA a SQL login) and finalize
  the SPN checklist in `OFF-LOOPBACK-DEPLOYMENT.md`.
- **(g) Optional — "require an AD MFA claim" hook (L).** Today the engine trusts a valid LDAPS bind /
  Kerberos ticket and cannot assert that the directory (e.g. Entra Conditional Access) *actually* enforced
  MFA for a session (ADR 0002 records this as an optional future hook). Build only on a customer security
  requirement for engine-side proof; normally CA enforces MFA at device logon, outside the engine.

**Why:** the recon found the hard parts (passwordless gMSA identity, integrated SQL auth, gMSA-SPN Kerberos
acceptor, CA-agnostic TLS) are **already built and shipping** — so an enterprise Windows/AD install is close,
and the residual is turnkey polish + one default flip + a real lab validation, not new architecture. Doing it
removes the "works but hand-assembled + never end-to-end tested against a domain" caveat before the story is
put in front of a customer.

**Scope boundary (not this item):** the engine's user-auth is **on-prem AD** (LDAPS + Kerberos), not cloud
Entra OIDC/SAML — a hybrid-joined shop's on-prem AD DS is what the engine binds, so an on-prem AD lab
validates it fully. Direct cloud-Entra token consumption is the separate, unbuilt **federated-SSO** roadmap
item, not part of this hardening.

**Source:** grounded deployment-fidelity recon (2026-07-03) off the ADR 0068 browser-SSO + off-loopback
lane; demand-gated on a first enterprise Windows/AD deployment.

---

## 100. `MultiSubnetFailover=Yes` opt-in for the SQL Server store connection (P2)

> ✅ **SHIPPED (2026-07-10, BACKLOG #100).** Opt-in `[store].multi_subnet_failover` emits ODBC `MultiSubnetFailover=Yes` (SQL Server only) **before** the last-wins `Encrypt`/`TrustServerCertificate` tail, so an AOAG-listener client reaches the current primary promptly across subnets. Default off; unit-tested (`test_store_file_hardening.py`).

**Type:** feature (small) — an opt-in `[store]` setting emitting the ODBC `MultiSubnetFailover=Yes`
keyword for Availability-Group-listener deployments.

**What:** a `multi_subnet_failover = true|false` bool on `StoreSettings` (default `false`, SQL Server
backend only) that makes `connection_string()`
([`store/sqlserver.py`](../messagefoundry/store/sqlserver.py)) emit `MultiSubnetFailover=Yes` —
inserted **before** the `Encrypt`/`TrustServerCertificate` tail so the last-wins TLS posture is
unchanged. No injection surface (it's a bool riding the existing validated-settings machinery); env
override rides the standard `MEFOR_STORE_*` path. Decide-at-build rider while in there: whether to
also surface ODBC 18's idle-connection-resiliency knobs (`ConnectRetryCount` /
`ConnectRetryInterval`), which today sit at driver defaults because the DSN cannot set them
(relevant to the [`AOAG-DEPLOYMENT.md`](AOAG-DEPLOYMENT.md) §5.3 reconnect-after-failover posture).

**Why:** the store's ODBC connection string is a **fixed keyword list with no passthrough** — by
design (STORE-5 anti-injection) — so it cannot emit AG-aware keywords at all
(`ApplicationIntent=ReadOnly` exists only on the separate `db_lookup` connector, not the store).
Against a **cross-subnet AOAG listener** (primary DC + DR DC, `RegisterAllProvidersIP=1`), a client
without `MultiSubnetFailover=Yes` tries the listener's IPs sequentially, each attempt bounded by
`[store].connect_timeout` (default 15 s), so post-failover reconnects are slow exactly when speed
matters; with the keyword, ODBC Driver 18 attempts all listener IPs in parallel. The documented
interim workaround — listener-side `RegisterAllProvidersIP=0` + `HostRecordTTL 300` — works but
shifts cross-subnet client recovery onto DNS TTL expiry + cross-site DNS replication
([`AOAG-DEPLOYMENT.md`](AOAG-DEPLOYMENT.md) §4.5, which this item unblocks).

**Source:** owner request (2026-07-03) during the AOAG deployment-guide build ("if that's something
to fix, add it to the backlog"); gap confirmed by adversarial review of `connection_string()`.

---

## 101. `[cluster]` leader preference / non-promotable standby (P2)

> ✅ **BUILT (2026-07-12, ADR 0096, #101).** Two per-node `[cluster]` knobs in the expired-lease branch of `_claim_or_renew_lease` (both Postgres + SQL Server coordinators): `acquire_delay_seconds` handicaps ONLY take-over of an EXPIRED lease (delay added to the expiry side — a strictly stricter predicate, so **no two-leader window**; renews are never delayed) and `promotable = false` short-circuits to not-held before the DB (never acquires/renews; a somehow-already-leader node steps down cleanly). Surfaced per-node in `GET /cluster/nodes`. Default `(0.0, True)` = byte-identical. **Rider built:** a cross-section guard refuses `[dr].activate` + `[cluster].enabled`. At least one promotable node required (documented). Preserves the self-fencing lease + at-least-once + FIFO invariants.

**Type:** feature.

**What:** a per-node cluster knob — an `acquire_delay_seconds` handicap **or** a
`promotable = false` flag — evaluated in the expired-lease branch of the leadership claim
([`pipeline/cluster_sqlserver.py`](../messagefoundry/pipeline/cluster_sqlserver.py) /
[`cluster.py`](../messagefoundry/pipeline/cluster.py) `_claim_or_renew_lease`), surfaced in
`GET /cluster/nodes`, so a designated node (e.g. a remote DR-site engine) never wins a routine
first-lease-wins race and only becomes leader when no preferred node can.

**Why:** MEFOR leadership is today an **unweighted first-MERGE-wins race** with no site
preference, node priority, or non-promotable flag (confirmed: no such setting in
[`config/settings.py`](../messagefoundry/config/settings.py) `ClusterSettings` or the cluster
modules). A warm standby at a remote DR site therefore wins ~1-in-2 to ~1-in-3 of routine
leadership transitions (leader-host death, patching restarts, config-restarts, DB blips), binding
listeners and driving the primary-site DB cross-WAN (~7 commits × WAN-RTT/msg) silently and with
no auto-fail-back. This is the prerequisite for ever running a DR engine **warm**; until it ships,
the only safe posture is a **cold** (service-stopped) DR engine. The `[dr]`/ADR 0048
priority-threshold run-profile does **not** help — it gates which connections start, never lease
acquisition. **Rider (interim stopgap):** a config guard that rejects or warns when `[dr].activate`
is combined with `[cluster]` membership.

**Source:** adversarial HA/DR topology review (2026-07-05).

---

## 102. Server-DB DR seed verification has no teeth (P2)

> ✅ **SHIPPED — verified against `origin/main` (2026-07-28)** (built 2026-07-10, lane `plan8-102`, commit `b912aee`, PR #890). The empty/fresh-bootstrap data-loss hole is closed fail-closed on **all three backends**: `Store.has_prior_backup_history()` is on the protocol at `messagefoundry/store/base.py:1401` and implemented at `store/store.py:7463`, `store/postgres.py:5679` and `store/sqlserver.py:8366`. Server-DB DR activation now requires **both** an explicit per-activation DBA attestation **and** a live restore-provenance probe (≥ 1 `dr_backup` audit row — written on every leader-gated backup success, absent on a fresh DR-box bootstrap since a passive standby is never leader), aborting **even when falsely attested** and aborting on an unreachable DB (`messagefoundry/pipeline/dr.py:413-478`, probed off the event loop; `tests/test_dr_server_seed_gate.py`). The vintage/completeness residual it hands off is **#223 — also closed**, so nothing here is outstanding. _(was 🚧 PARTIAL · Value 8/10 · Difficulty 4/10.)_

**Type:** bug / hardening.

**What:** on the server-DB backends, `run_restore_verify` **passes a config-only archive**
([`pipeline/dr_backup.py`](../messagefoundry/pipeline/dr_backup.py) lines 655-662), so
`POST /dr/activate` can bless priority-feed activation against an empty or arbitrarily stale store
on a SQL Server estate — **worse** than the fail-closed behavior ADR 0048 promises on SQLite.
**Fix:** make server-DB DR activation verify that a DBA-attested restored `mefor` database is
actually present and fresh (or extend #60 / ADR 0049 with a real server-DB store seed), so
activation cannot silently seed an empty store.

**Why:** a tertiary/DR activation that "succeeds" against an empty store would silently drop the
very priority clinical feeds it exists to protect.

**Source:** adversarial HA/DR topology review (2026-07-05).

---

## 103. Retire the PySide6 desktop console in favor of the web console (P3, owner decision)

> ✅ **SHIPPED / COMPLETE (2026-07-13).** The PySide6 desktop console is retired. `messagefoundry/console/`
> deleted; the reusable Qt view widgets (`ConfigurableTable` / `MessagesPanel` / `MessageDetailPanel` /
> `LoginDialog`) rehomed verbatim to `harness/` (`_console_widgets.py` / `_login.py` / `_async.py`); every
> `messagefoundry.console` importer repointed (harness + tests → `apiclient`); the desktop-console tests
> (`tests/test_console_*.py`) removed; the `[project.gui-scripts]` windowed launcher + `scripts/console/`
> shortcut tooling deleted; the `[console]` extra renamed to `[harness]` (PySide6 + httpx + truststore;
> `keyring` — the launcher-only OS-token cache — dropped, lock re-exported). The browser web console
> (`/ui`, [ADR 0065](adr/0065-web-ops-dashboard.md)) is the sole operator UI; PySide6 is now harness-only.
> [ADR 0032](adr/0032-console-desktop-launch.md) flipped to **RETIRED**. Completes the deferred remainder of
> the [ADR 0088](adr/0088-apiclient-service-cli-extraction.md) partial.

**Partial (PLAN-9 W3, 2026-07-10 — [ADR 0088](adr/0088-apiclient-service-cli-extraction.md)) — now COMPLETE:**
`apiclient/` + the `messagefoundry service` CLI were extracted first (the reusable-core half: the Qt-free
`EngineClient` client + local Windows service control). The 2026-07-13 retirement (banner above) finished the
job — deleting `console/`, rehoming the Qt widgets to `harness/`, and renaming the `[console]` extra — and
flipped [ADR 0032](adr/0032-console-desktop-launch.md) to RETIRED.

**Type:** architecture / feature (large) — collapse the two operator UIs to one, keeping the
browser `/ui` console ([#75](#75-browser--web-operator-monitor)) as the sole operator client.

**What:** retire the PySide6 desktop console (`console/`) once the
browser ops console reaches operator parity. The earlier "impossible" verdict rested on two
blockers; the owner has now waived the first (moving harness code is acceptable), leaving three
concrete moves:
- Extract the **Qt-free** HTTP API client `console/client.py`
  (`EngineClient` / `ApiError` — verified zero Qt imports) into a shared home (e.g.
  `messagefoundry/apiclient/`); the harness ([`harness/monitor.py`](../harness/monitor.py),
  `scenarios.py`, `load/…`) and any other consumer import it there.
- Rehome the shared Qt widgets the harness reuses
  (`console/widgets.py` `ConfigurableTable` /
  `MessagesPanel` / `MessageDetailPanel`, `console/login.py`
  `LoginDialog`) into `harness/` (already a PySide6 app).
- Move the one browser-impossible capability — **local Windows service control**
  (`console/service_control.py`: `sc query` state +
  elevated `net start/stop`/install; a browser can't UAC-elevate and can't stop the very engine
  hosting its own API) — to the CLI (`messagefoundry service install|start|stop|status`, wrapping
  the existing [`scripts/service/`](../scripts/service/) NSSM scripts) or a tiny standalone
  tray/service-manager.

Then audit remaining web-vs-desktop parity gaps (the ADR 0065 full port already reached additive
near-parity), delete `console/`, drop the `[console]` extra + the `[project.gui-scripts]` windowed
launcher, and collapse the two-console docs (`ARCHITECTURE.md` / `SECURITY.md` / `MENTAL-MODEL.md`)
to one. Pairs with the in-progress **web-console-as-a-mounted-package** effort (Option B — the
console shipped as a separately-versioned package the engine mounts same-origin), so the sole UI
keeps its proven same-origin in-process security model rather than a cross-origin rewrite.

**Why:** two operator clients (a PySide6 desktop app + the `/ui` browser console) double the
maintenance + parity + security surface. The web console is zero-install and already the primary
monitor ([#75](#75-browser--web-operator-monitor)); the only genuine capability the desktop app
holds that a browser cannot is local OS service control, which is CLI-shaped anyway. Retiring the
desktop app leaves **one** UI to build, test, and secure.

**Source:** owner decision (2026-07-06) — backlog it (not now); grounded in a session architecture
evaluation (`console/client.py` confirmed Qt-free; `service_control.py` confirmed
browser-impossible per its own docstring). Sequence the extraction / rehoming / CLI-service-control
**before** deleting `console/`.

---

## 104. Cookbook + Walkthrough — offline solved-problems gallery + VS Code onboarding (P2, IDE/DX)

> ✅ **SHIPPED — Cookbook gallery + VS Code onboarding walkthrough (PLAN-7 L3, PR #798).** `ide/src/cookbook.ts` + `cookbookRecipes.ts` + the five `ide/media/walkthrough/*.md` steps, with `ide/src/test/suite/cookbook.test.ts`. The deterministic sibling of the AI `/explain` ([`AI-OFF-MATRIX.md`](AI-OFF-MATRIX.md)) and the code-first analogue of Corepoint's Cookbook.


> 📐 **Scoped in [MULTISESSION-PLAN-7](releases/MULTISESSION-PLAN-7.md) L3 (owner-promote to build).** The deterministic sibling for the AI `/explain` ([`docs/AI-OFF-MATRIX.md`](AI-OFF-MATRIX.md)) and the code-first analogue of Corepoint's Cookbook.

**Type:** developer-experience / onboarding.

**What:** a VS Code `contributes.walkthroughs` onboarding flow + a searchable "solved problems" gallery webview (patterned after `ide/src/home.ts`'s `HomeView`) whose entries insert **static, editable Python** via `editor.insertSnippet()` — e.g. "rearrange segments," "code-set crosswalk," "split a batch by OBR," "enrich via `db_lookup`," "route by message type." All examples **synthetic HL7 only**.

**Bright line (#26):** a static-snippet **index only** — **no** input-driven code synthesis, **no** field-mapping form, **no** "customize this recipe" inputs, **no** persisted declarative artifact. Same rule as #48's palette, restated because this lane owns a webview UI (the surface most able to drift into a builder).

**Why:** a no-AI builder in a PHI environment can't ask the assistant "how do I do X"; the Cookbook is the offline answer, mirroring the tool Corepoint analysts rely on. Closes the one *partial* gap in the AI-off matrix (`/explain`).

**Source:** MULTISESSION-PLAN-7 (2026-07-06) — from the Corepoint IDE / no-code review.

---

## 105. Deterministic Corepoint-import tooling — Action-List → code-first scaffold (P3, deferred, owner decision)

> 🔢 **Re-scored 2026-07-10 → P3.** Value **2/10** · Difficulty **6/10** · _money pit_. Adopter already hand-ported and AI /migrate covers the rest, no named demand (v2); large greenfield 71-action mapper needing its own ADR (d6). _(was DEMAND-GATE · V2/5 · D4/5)_

> **AMENDED 2026-07-28 — the stated blocker is discharged; the real gate is a different item.** This item has been carried as blocked on an *"input schema SYNTHETIC-until-validated"* premise. That premise no longer holds: [ADR 0086](adr/0086-deterministic-corepoint-import.md) **Amendment 2026-07-24 §2(a′)** supersedes the old JSON model (`:46-49` marks the synthetic format *SUPERSEDED*) — the input is now a **validated XML** format, parsed through `defusedxml` (`messagefoundry/corepoint_import.py:81`, with the security rationale at `0086:124`). ⚠️ **This does NOT make the item schedulable.** The real gate is **#313** (the multi-message Handler model — the import refuses ~2,000 statements without it), and #313 is **invisible from this published baseline**, which ends at #231. Do not read the discharged blocker as a green light; the item stays P3 and demand-gated behind #313.

**Type:** migration / DX (large). The deterministic sibling for the AI `/migrate` — the **one open gap** in the AI-off completeness matrix ([`docs/AI-OFF-MATRIX.md`](AI-OFF-MATRIX.md)).

**Partial build (PLAN-9 Wave 3, 2026-07-10 — branch `plan9-ideimport`):** the **deterministic importer + CLI is BUILT** ([ADR 0086](adr/0086-deterministic-corepoint-import.md)): `messagefoundry import corepoint <export> --out <dir>` — a pure, stdlib-only parser emitting one code-first `@router`/`@handler` module per channel calling the ADR 0076 vocabulary (the **inverse** of ADR 0076 §2's mapping); unmapped actions become in-place `# TODO` + best-effort stubs (never dropped); untrusted export values ride as `json.dumps`-escaped literals. **Correctness gate met** — emitted modules pass `messagefoundry check` **and** round-trip through `lens parse`. **Item stays OPEN** — the Corepoint **input schema is SYNTHETIC-until-validated** (no real export in-repo; #87 recon git-ignored), so its field names / nesting / ~71-action inventory must be reconciled against a real Corepoint export before production use; the optional `ide/` TS wrapper is deferred.

**What:** a non-AI import path that reads exported Corepoint Action-Lists / connection config and scaffolds **editable code-first Router/Handler Python** (best-effort, human-finished) — so a PHI-environment migrator who cannot use the AI `/migrate` subcommand still has a deterministic starting point.

**Why deferred / owner-gated:** larger than the PLAN-7 lanes — needs its own scope (which Corepoint export format; how much of the ~71-action catalog maps deterministically vs. needs hand-finishing) and its own ADR. Not agent-buildable in the PLAN-7 waves; surfaced here so the gap is tracked, not silently built. Stays inside #26 (emits editable Python, not a declarative logic surface).

**Source:** MULTISESSION-PLAN-7 AI-off completeness audit (2026-07-06).

---

## 106. Per-connection "keep forever" retention breaks on the server-DB backends (`float('-inf')` cutoff) (P2) — ✅ FIXED (PR #818)

> ✅ **SHIPPED — fixed in PR #818** (`float('-inf')` keep-forever cutoff on the server-DB backends). Detail below.

**Type:** bug / cross-backend parity.

**Resolution (2026-07-07, PR #818):** ✅ FIXED. Reproducing against real containers showed **two
independent** root causes (the original note conflated them): (a) **SQL Server** — pyodbc/TDS rejects
`-inf` as a `FLOAT` bind; (b) **Postgres** — the cutoff CASE's bare `THEN`/`ELSE` params default to
`text`, so `received_at (double precision) < (CASE … text …)` fails with `operator does not exist:
double precision < text` — a type-inference bug **independent of `-inf`**. Fix (store layer, since the
tests pass `-inf` directly to `purge_message_bodies`): `_finite_cutoff()` clamps `-inf` → a finite
floor (`-1e30`, below any epoch `received_at`, still always-false) in `_qmark_cutoff_case` +
`_pg_cutoff_case`; PG additionally casts the CASE branches `::double precision`. Verified retention
9/9/9 (sqlite/ss/pg) + SS store 73 + PG store 81; CI's SQL Server 2022/2025 + Postgres legs ran the
gated retention tests and passed. The existing skipif-gated `test_per_connection_retention[sqlserver|
postgres]` cases are the regression guard (no new test file needed).

**What:** per-connection retention (#34 / ADR 0027) maps a **keep-forever** override to a
`float('-inf')` cutoff, bound as a `FLOAT` parameter by `_qmark_cutoff_case`
([`store/store.py`](../messagefoundry/store/store.py)) inside `purge_message_bodies` on all three
backends. SQLite's dynamic typing accepts `-inf`, but the **server backends reject it**: SQL Server
via pyodbc raises `('42000', …) not a valid instance of data type float`, and Postgres via asyncpg
raises `UndefinedFunctionError`. So a purge pass on SQL Server / Postgres with **any** keep-forever
connection configured **throws and aborts** — retention silently stops running for that store.
Repro: `tests/test_per_connection_retention.py[postgres|sqlserver]` +
`test_sqlserver_store` reencrypt-purge fail deterministically against a server DB with **unpinned**
recent pyodbc/asyncpg. **Latent in CI today** — the hash-locked driver versions currently tolerate
`-inf`, so the store legs are green; a routine driver bump would surface it in CI.

**Fix:** stop binding non-finite floats to a SQL `FLOAT`. Map keep-forever to a **large finite
sentinel cutoff** (e.g. `0.0` — nothing is older than the epoch — or a far-past value per the
comparison direction), or emit a **NULL / absent-cutoff CASE arm** the `WHERE received_at < …` clause
treats as "never purge", in `_qmark_cutoff_case` + the three `purge_message_bodies` impls. Add a
regression test that runs the per-connection retention suite against **SQL Server and Postgres** (not
only SQLite) so the parity gap can't reopen.

**Why:** a purge that aborts leaves PHI-bearing bodies un-pruned past their retention window on the
exact backends the adopter's Test/Prod run (SQL Server) — a HIPAA-retention correctness gap, and a CI
time-bomb a driver upgrade detonates.

**Source:** discovered during ADR 0073 (PR #803) local verification, 2026-07-06 — pre-existing since
#612 (per-connection retention), unrelated to sharding.

---

*Everything else from the 2026-06-10 full-codebase review (1 critical, 13 high, 33 medium, 31 low —
78 findings) has been remediated; see the review report's §6 action order. The two items it still
sourced — **#1 (SQL Server concurrency)** and **#2 (console off-thread)** — are now both **DONE**
(#2 completed in #341).*
---

## Corepoint help-export coverage sweep — items #107–#142 (2026-07-09)

> ✅ **Delta only — not the total Corepoint gap surface.** These 36 items are the features found in the
> **Corepoint v8.1.0 HTML help export** that were *absent* from both `marketing/corepoint-gap-analysis.md`
> (local-only, gitignored) and this backlog. The analysis's own **65 GAP / 147 PARTIAL** rows remain the primary
> record of Corepoint parity — including all **three MAJOR** gaps, which are already tracked: the inbound
> REST/SOAP/FHIR listener (**#7**), operator alert *state* (**#56**), and turnkey disaster recovery (**#60**/**#61**).
>
> **The sweep found no new MAJOR gap.** Tally: **8 moderate · 28 minor**. Method: 5 passes (broad sweep →
> transformation deep-read → critic resolution → `resources/` field-level → transport re-audit), each gated by an
> automated completeness critic; every survivor adversarially verified, then re-checked against `origin/main`
> before filing. Full narrative + the void-run post-mortem: `marketing/corepoint-gap-analysis-addendum.md`.
>
> Three items are **not clean wins** and say so in place: **#138** (PHI review required), **#139**
> (decline-by-default anti-feature), **#140** (structurally N/A). **#127**/**#128** are meaningless without **#112**.

---

## 107. Override HL7 v2 escape sequences

> ✅ **SHIPPED — per-outbound `hl7_raw_separators` escape-hatch (2026-07-11).** A default-OFF per-outbound flag emits the four reserved **structural** separators as RAW bytes (`\F\ \S\ \R\ \T\` → the message's own field/component/repetition/subcomponent char) instead of their escape sequences, for a partner that cannot decode HL7 escapes. The codec (`unescape_separators` / `encode_raw_separators` in `parsing/_builtin_hl7.py`, `Message.encode_raw_separators` / `emit_raw_separators` in `parsing/message.py`) reads the reserved chars from the payload's own MSH and re-serializes via the parsed model — never string-slicing; the escape char is protected by a state machine so a literal-`\F\` datum (`\E\F\E\`) is never mis-raw-ized. Typed `Destination.hl7_raw_separators` (config/models.py) surfaced through `_dest_config` and the `MLLP()` factory; applied in `MLLPDestination.send()` before framing (composes after `encoding_characters`). Default OFF = **byte-identical** output. Contained default-off knob (sibling of the `encoding_characters` override) — **no standalone ADR**; documented in code + `docs/CONNECTIONS.md`. HL7v2/MLLP outbound only.

**Cluster:** HL7 / Messaging. **Priority:** P2. **Verdict:** demand-gate. **Severity (vs Corepoint):** moderate.

**Scope:** Emit reserved separators as raw bytes instead of HL7 escape sequences, per-connection and per-output, for partners that cannot decode escapes.

**Trigger:** build when a trading partner cannot decode HL7 escape sequences and requires reserved separators emitted as raw bytes.

**Why:** Real gap. MessageFoundry always escapes reserved HL7 delimiters via the parsing layer's `escape_leaf`/`Message.set` and has no per-connection or per-outbound setting to instead emit those separators as raw bytes for partners that cannot decode escapes.

**Nearest existing mechanism:** Parsing-layer HL7 escape/unescape (parsing/message.py `Message._escape_leaf` / `.set`, parsing/_builtin_hl7.py `escape_leaf`/`unescape`), which always escapes structural delimiters on write and unescapes on read; no per-connection or per-outbound serialization knob exists in config/models.py.

**Source:** Corepoint v8.1.0 help-export coverage sweep (2026-07-09) — five adversarially-verified passes over the full help export (1,569 pages); absence re-verified against `origin/main` before filing. Cross-ref [#52](#52-corepoint-capability-parity-gaps--prioritized-roadmap-input-2026-06-27).

---

## 108. Receiver-side 'Prefer BOM if present' encoding auto-detect

> 🔢 **Re-scored 2026-07-10 → DEMAND-GATE.** Value **3/10** · Difficulty **2/10** · _fill-in_. Encoding setting cleanly covers single-encoding feeds; only the niche mixed-BOM auto-detect override remains, a small decode-path sniff. _(was DEMAND-GATE · V2/5 · D2/5)_

> **On-trigger / demand-gate.** Numbered for tracking only — build when the trigger below fires (“demand-gate, don’t schedule”).

**Cluster:** Connections & Transports. **Priority:** P3. **Verdict:** demand-gate. **Severity (vs Corepoint):** minor.

**Scope:** A receiver-side option where a byte-order mark detected on the incoming file overrides the connection's configured encoding (notably UTF-16 LE/BE).

**Trigger:** build when an inbound feed delivers UTF-16 (or mixed-encoding) files whose byte-order mark must override the configured encoding.

**Why:** Partial. Per-connection text encoding is already built — every connector (File/TCP/MLLP/REST/SOAP/DB/SFTP) takes an `encoding` setting (default `utf-8`, any Python codec name, so `utf-8-sig`/`utf-16-le`/`utf-16-be` all work); the only residual gap is a receiver-side "prefer BOM if present" auto-detect that overrides the configured encoding, since today only a leading UTF-8 BOM is sniffed/stripped and a UTF-16 LE/BE BOM is not detected to switch the decode.

**Nearest existing mechanism:** Per-connection `encoding` setting on every transport (File source/destination, TCP, MLLP, X12, REST, SOAP, database, remotefile/SFTP) — `settings.encoding`, default `"utf-8"`, plumbed to `.encode()`/`.decode()` and to `parsing/peek.py::normalize(encoding=...)`; accepts any Python codec name including `utf-8-sig` (UTF-8 w/ BOM), `utf-16`, `utf-16-le`, `utf-16-be`.

**Source:** Corepoint v8.1.0 help-export coverage sweep (2026-07-09) — five adversarially-verified passes over the full help export (1,569 pages); absence re-verified against `origin/main` before filing. Cross-ref [#52](#52-corepoint-capability-parity-gaps--prioritized-roadmap-input-2026-06-27).

---

## 109. Invalid-credential sender auto-stop (partner-account lockout protection)

> ✅ **SHIPPED — verified against `origin/main` (2026-07-28).** [ADR 0095](adr/0095-connection-lifecycle-scheduler-and-credential-fault-stop.md). `credential_fault_policy: Literal["stop", "dead_letter"] = Field(default="stop")` (`messagefoundry/config/settings.py:1111-1118`, asserted at construction `pipeline/wiring_runner.py:922-923`). On a permanent auth failure the lane **STOPs and RETAINS its queue un-errored** — `release_claimed` back to PENDING, never dead-lettered — plus a `connection_stopped` alert (`wiring_runner.py:4051-4074`), so a backlog cannot re-auth-storm the partner account. `transports/remotefile.py:118-121` threads `credential_fault` through `NegativeAckError`.
>
> ⚠️ **The ledger was self-contradictory here:** the ranked-table row already read ✅ SHIPPED while this banner still said demand-gate — the table was right. ⚠️ **Live-server validation is still outstanding:** all merged coverage is unit-level against a stub connector; a real FTP/SFTP handshake pass is tracked at `docs/releases/plan-11/w19-ad-lab-integration-validation.md:48`, which itself frames #109 as "built and unit-green". That pointer is preserved here deliberately so the lab pass is not lost by this close. _(was 🔢 DEMAND-GATE · Value 6/10 · Difficulty 4/10.)_

**Cluster:** Connections & Transports. **Priority:** P2. **Verdict:** demand-gate. **Severity (vs Corepoint):** moderate.

**Scope:** On bad credentials a File/FTP sender overrides retry, stops immediately, logs a protocol event, and retains the queue un-errored so the partner account is not locked out.

**Trigger:** build when a partner account is locked out by an outbound sender retrying with stale credentials.

**Why:** Real gap. On invalid credentials an outbound file/FTP sender dead-letters the message and keeps draining the lane rather than auto-stopping and retaining the queue un-errored, so a queue backlog can repeatedly re-authenticate and lock out the partner account; the nearest mechanism, ADR 0070's infra_fault_stop_after lane STOP, only fires after ~10 consecutive transient infra faults and never triggers on a permanent auth failure.</why_line>
<parameter name="evidence">transports/remotefile.py: FTP/FTPS/SFTP auth failures map to _RemoteError(permanent=True) -> NegativeAckError(permanent=True) -> dead-letter. No sender auto-stop on bad credentials and no un-errored queue retention. pipeline/stage_dispatcher.py: the only auto-stop is infra_fault_stop_after (ADR 0070) after N consecutive transient infra faults with zero progress; is_infra_fault=True is set ONLY on the T17 machinery-fault path (default streak 10, ~4min). A permanent auth failure is a content STOP/dead-letter, keeps is_infra_fault=False, never counts toward the streak. config/settings.py: infra_fault_policy (stop|retry_forever), infra_fault_stop_after, infra_fault_backoff_cap — no credential/lockout knob. Grep across messagefoundry/ for circuit|breaker|auto_disable|max_consecutive|lockout|account.?lock: no matches. BACKLOG.md / FEATURE-MAP.md: no numbered item for sender-side credential lockout protection.

**Nearest existing mechanism:** infra_fault_stop_after / infra_fault_policy="stop" (ADR 0070 lane STOP in pipeline/stage_dispatcher.py + config/settings.py) plus remotefile's permanent-vs-transient auth classification in transports/remotefile.py (auth failure -> _RemoteError(permanent=True) -> NegativeAckError(permanent=True) -> dead-letter).

**Source:** Corepoint v8.1.0 help-export coverage sweep (2026-07-09) — five adversarially-verified passes over the full help export (1,569 pages); absence re-verified against `origin/main` before filing. Cross-ref [#52](#52-corepoint-capability-parity-gaps--prioritized-roadmap-input-2026-06-27).

---

## 110. DICOM Study/Series Instance UID de-duplication on the C-STORE SCP

> 🛠 **Decline overturned (2026-07-09).** A prioritization pass recommended DECLINE; the stated reason was **invalid**. Purity binds `@router` / `@handler` — **not connectors** (CLAUDE.md §8: “side effects (DB, network) belong in connections/transports”). This is an unfired **demand-gate**, not an architectural impossibility.
>
> **Build constraints:** Build at the connector, not in a Router/Handler. (1) Honor count-and-log: suppressed duplicate instances (the 2..N objects per Study/Series UID) must still be persisted with an explicit disposition such as FILTERED — never silently dropped, since each C-STORE object is a received-and-ACKed message. (2) The de-dup "seen-UID" state lives on the connector (analogous to FileSource's processed-file tracking); it must survive connector/engine restart, or a bounded reset window on restart must be explicitly documented…

> 🔢 **Re-scored 2026-07-10 → DEMAND-GATE.** Value **3/10** · Difficulty **4/10** · _fill-in_. Niche DICOM-only C-STORE de-dup most partners never need; the SR→HL7 case can already filter to SR objects code-first. _(was DEMAND-GATE · V2/5 · D3/5)_

> **On-trigger / demand-gate.** Numbered for tracking only — build when the trigger below fires (“demand-gate, don’t schedule”).

**Cluster:** Connections & Transports. **Priority:** P2. **Verdict:** demand-gate. **Severity (vs Corepoint):** moderate.

**Scope:** Storage-SCP option to forward only the FIRST instance per Study/Series Instance UID, collapsing a multi-image study into one downstream message at the connector.

**Trigger:** build when an adopter routes DICOM studies and needs one downstream message per study rather than per image.

**Why:** Real gap. The C-STORE SCP commits every received object as its own ingress message (`_on_c_store`/`_commit` in transports/dicom.py) and has no Study/Series-Instance-UID de-duplication to forward only the first instance per study; the closest lever, DicomPeek exposing those UIDs to a Router, cannot collapse a study because Routers/Handlers must stay pure (no cross-message "seen-UID" state), so this connector-level first-instance-only behavior is absent.

**Nearest existing mechanism:** The inbound DICOM C-STORE SCP (`transports/dicom.py`, `_on_c_store`/`_commit`) plus `DicomPeek` (`parsing/dicom/peek.py`), which exposes `StudyInstanceUID`/`SeriesInstanceUID` for code-first Router/Handler routing — but has no cross-message state to suppress subsequent instances.

**Source:** Corepoint v8.1.0 help-export coverage sweep (2026-07-09) — five adversarially-verified passes over the full help export (1,569 pages); absence re-verified against `origin/main` before filing. Cross-ref [#52](#52-corepoint-capability-parity-gaps--prioritized-roadmap-input-2026-06-27).

---

## 111. File-endpoint alternate Windows / network-share credentials

> ✅ **SHIPPED — verified against `origin/main` (2026-07-28).** [ADR 0132](adr/0132-per-endpoint-alternate-windows-credential-for-file-unc-shares-win32-ctypes-no-pywin32-no-impersonation-privilege.md). `messagefoundry/transports/wincred.py:3` gives the File connector a per-endpoint alternate Windows credential: a real `advapi32.LogonUserW` `LOGON32_LOGON_NEW_CREDENTIALS` + `ImpersonateLoggedOnUser` via **ctypes — no pywin32** (`:182-227`), fully bracketed LogonUser → Impersonate → call → RevertToSelf → CloseHandle on a dedicated single-worker executor (`:109-139`, `:151-165`), and `ensure_supported` raising `CredentialUnsupportedError` off Windows — **loud, never silent** (`:101-106`). Modelled at `config/models.py:476-530`, authored as `File(credential_username=…, credential_domain=…, …)` (`config/wiring.py:1123-1125`).
>
> ⚠️ **The live win32 path is not exercised in CI** — `tests/test_file_alt_credential.py` fakes all four ctypes primitives; a real `LogonUser` against a real alt-credential UNC share is a Windows-CI / manual gate. That is an accepted, ADR-documented limitation (`wincred.py:29-31`), so this close does **not** claim share-level verification. ⚠️ **Not SMB remote-scheme support:** `docs/CONNECTIONS.md:1827` still lists "SMB / network share" as a *planned* File remote scheme — a genuinely separate gap. _(was 🔢 DEMAND-GATE · Value 5/10 · Difficulty 5/10.)_

**Cluster:** Connections & Transports. **Priority:** P2. **Verdict:** demand-gate. **Severity (vs Corepoint):** moderate.

**Scope:** A File endpoint authenticates to a local/UNC share under its own Windows credential, distinct from the engine service account, with a credentialed endpoint tester.

**Trigger:** build when a File connection must read or write a UNC share under an identity other than the engine service account.

**Why:** Real gap. The File connector accesses local/UNC paths only under the engine service account's ambient Windows identity (no per-endpoint credential in FileSettings), and remotefile.py's username/password auth covers FTP/FTPS/SFTP protocols — not SMB/UNC Windows-share credentials or impersonation; SMB/network-share is listed "planned" in CONNECTIONS.md with no tracking item.

**Nearest existing mechanism:** The local File connector (transports/file.py, FILE-IN/OUT) reads local/UNC paths under the engine service account's ambient Windows token — FileSettings (config/models.py) has no credential fields; transports/remotefile.py carries username/password but only for FTP/FTPS/SFTP protocols, not SMB/Windows-share auth or impersonation. A generic credentialed connection probe/tester exists (CONNECTIONS.md), but not for a File Windows credential.

**Source:** Corepoint v8.1.0 help-export coverage sweep (2026-07-09) — five adversarially-verified passes over the full help export (1,569 pages); absence re-verified against `origin/main` before filing. Cross-ref [#52](#52-corepoint-capability-parity-gaps--prioritized-roadmap-input-2026-06-27).

---

## 112. Outbound forward web-proxy address ('Use Default Web Proxy')

> ✅ **SHIPPED — verified against `origin/main` (2026-07-28).** [ADR 0126](adr/0126-outbound-forward-egress-web-proxy-for-the-stdlib-http-family.md). `messagefoundry/transports/rest.py:513-522` carries the forward/egress proxy seam (BACKLOG #112/#127/#128) with a `_PROXY_DEFAULT = "default"` sentinel meaning *use the OS/environment proxy via `getproxies()`* — the item's literal "Use Default Web Proxy". `ProxyConfig` (`:586-611`) exposes `use_default`, `_build_proxy_handler` and per-host `for_host`; `proxy_config_from_settings` (`:695-746`) resolves unset → `None` and `"default"` → the OS proxy.
>
> ⚠️ **`FhirLookup()` exposes no proxy kwarg** (`config/wiring.py:483-535`): a `fhir_lookup` read connection can only inherit the site-wide `[egress].proxy_url`/`proxy_no_proxy` and cannot authenticate to a proxy per-lookup. ADR 0126 declares that out of scope **by name**, and the item's own trigger (a site mandating all outbound HTTP traverse a corporate proxy) is served by the site-wide default — so this is a bounded, ratified edge, not an unbuilt half. _(was 🔢 DEMAND-GATE · Value 5/10 · Difficulty 3/10.)_

**Cluster:** Web Services & HTTP. **Priority:** P2. **Verdict:** demand-gate. **Severity (vs Corepoint):** moderate.

**Scope:** Route outbound REST/SOAP/FHIR calls through a configured corporate egress/forward proxy. The engine today knows only reverse proxies (inbound TLS termination) - the opposite direction.

**Trigger:** build when a site mandates that all outbound HTTP egress traverse a corporate forward proxy.

**Why:** Real gap. No configured outbound forward/egress web-proxy setting exists on REST/SOAP/FHIR/SMART/DICOMweb connections; all share the urllib `_NO_REDIRECT_OPENER` in transports/rest.py, which only picks up a proxy incidentally from process-wide `HTTP_PROXY`/`HTTPS_PROXY` env vars (undocumented, not per-connection), while every in-repo "proxy" setting is the reverse-proxy inbound direction.

**Nearest existing mechanism:** The shared urllib opener `_NO_REDIRECT_OPENER` (urllib.request.build_opener) in transports/rest.py, reused by soap.py/fhir.py/smart.py/dicomweb.py. Because build_opener is called without an explicit ProxyHandler, urllib's default ProxyHandler incidentally honors process-wide HTTP_PROXY/HTTPS_PROXY/NO_PROXY env vars — but there is no per-connection forward-proxy setting in config/settings.py or config/models.py.

**Source:** Corepoint v8.1.0 help-export coverage sweep (2026-07-09) — five adversarially-verified passes over the full help export (1,569 pages); absence re-verified against `origin/main` before filing. Cross-ref [#52](#52-corepoint-capability-parity-gaps--prioritized-roadmap-input-2026-06-27).

---

## 113. Outbound source-IP binding for sender connections

> 🔢 **Re-scored 2026-07-10 → DEMAND-GATE.** Value **3/10** · Difficulty **3/10** · _fill-in_. Niche interop knob a source-IP-allowlisting partner needs on a multi-homed host; OS policy routing usually selects egress, so value stays modest. _(was DEMAND-GATE · V2/5 · D2/5)_

> **On-trigger / demand-gate.** Numbered for tracking only — build when the trigger below fires (“demand-gate, don’t schedule”).

**Cluster:** Connections & Transports. **Priority:** P3. **Verdict:** demand-gate. **Severity (vs Corepoint):** minor.

**Scope:** Bind an outbound socket to a specific local source IP on a multi-homed host (TCP/IP senders and FTP endpoints).

**Trigger:** build when an engine runs on a multi-homed host and a partner requires traffic to originate from a specific source IP.

**Why:** Real gap. Outbound sender sockets cannot be pinned to a specific local source IP on a multi-homed host: the per-connection bind_address / [inbound].bind_host binding controls only inbound listeners, and every outbound dial (MLLP/TCP/X12 asyncio.open_connection, FTP/SFTP connect) omits local_addr/source_address, leaving egress source selection to OS routing.

**Nearest existing mechanism:** InboundConnection.bind_address (per-connection listen-interface override, canonicalized via _normalize_bind_host in config/wiring.py) plus the service-level [inbound].bind_host setting — but both are inbound-listener-only. Outbound senders (transports/mllp.py, tcp.py, x12.py via asyncio.open_connection; remotefile.py FTP via ftp.connect and paramiko SFTP) dial with no local_addr/source_address, so the OS picks the source IP by route.

**Source:** Corepoint v8.1.0 help-export coverage sweep (2026-07-09) — five adversarially-verified passes over the full help export (1,569 pages); absence re-verified against `origin/main` before filing. Cross-ref [#52](#52-corepoint-capability-parity-gaps--prioritized-roadmap-input-2026-06-27).

---

## 114. Directory validation toggle (perform vs suppress startup validation)

> 🔢 **Re-scored 2026-07-10 → DEMAND-GATE.** Value **5/10** · Difficulty **2/10** · _fill-in_. Corepoint-parity File toggle to fail-fast on an invalid startup directory; clean workaround via the on-demand test probe plus existing run-time deferral. _(was DEMAND-GATE · V2/5 · D2/5)_
> **On-trigger / demand-gate.** Numbered for tracking only — build when the trigger below fires (“demand-gate, don’t schedule”).

> **AMENDED 2026-07-28 — the INBOUND half is fully BUILT; only the outbound half remains.** Adversarial verification refuted a full close. **BUILT:** `validate_directory` on the File source (`messagefoundry/transports/file.py:311`) with its opt-in at-start check (`:389-398`) — a no-mkdir probe that reports the connection `failed` at start rather than deferring to first poll (`:170`).
>
> ⚠️ **The REMAINDER is the outbound half, and today it fails SILENTLY.** `DestinationConnector` has **no `validate_startup` hook at all**: `FileDestination` never reads the setting and still `mkdir`s on write, and the runner's outbound start path never validates. Worse, `File(validate_directory=True)` on an **outbound** is accepted and ignored with **no `WiringError`** — an operator can ask for fail-fast validation, get none, and see no error. ADR 0031's amendment scopes the outbound out as *"out of scope here"*, which is a **deferral, not a decline**. Minimum viable fix is the wiring rejection; the hook is the fuller build.

**Cluster:** Connections & Transports. **Priority:** P3. **Verdict:** demand-gate. **Severity (vs Corepoint):** minor.

**Scope:** Per-connection File option: validate directory paths at startup (invalid means not-started) or defer validation to run time, for intermittently-available remote directories.

**Trigger:** build when a File connection points at an intermittently-available remote directory and must not fail startup validation.

**Why:** Partial. MessageFoundry always defers File directory validation to run time (FileSource._run logs-and-retries when the poll directory is unreachable; FileDestination mkdir's on write), which matches Corepoint's defer mode, but there is no per-connection toggle to instead validate the directory at startup and refuse to start (mark not-started) on an invalid path — the writability probe (_probe_dir_writable / test_connection) runs only on demand via POST /connections/{name}/test, not at startup.

**Nearest existing mechanism:** The on-demand reachability probe POST /connections/{name}/test (api/app.py), backed by FileSource/FileDestination.test_connection → _probe_dir_writable (transports/file.py); plus the implicit run-time tolerance already built into FileSource._run (a scan error when the watch dir is missing/unreadable is logged and retried next poll, never crashes the connection) and FileDestination._write (mkdir(parents=True, exist_ok=True) on each write). Startup fault-isolation (ADR 0031) isolates connectors that fail to build/bind, but File connectors do not validate the directory at construction, so a missing directory never fails startup.

**Source:** Corepoint v8.1.0 help-export coverage sweep (2026-07-09) — five adversarially-verified passes over the full help export (1,569 pages); absence re-verified against `origin/main` before filing. Cross-ref [#52](#52-corepoint-capability-parity-gaps--prioritized-roadmap-input-2026-06-27).

---

## 115. Per-connection Auto-Start toggle

> ✅ **SHIPPED (2026-07-10, BACKLOG #115, PLAN-10 Wave 1).** Per-connection `auto_start: bool = True` on `InboundConnection`/`OutboundConnection` (code-first via `inbound(...)`/`outbound(...)` **and** `connections.toml`). At engine start the `RegistryRunner` skips binding/building an `auto_start=False` connection — it reports status:`stopped` (distinct from DR `filtered` / ADR-0031 `failed`), its workers still spawn so any backlog self-heals, and `POST /connections/{name}/start` still brings it up at runtime. Byte-identical when `auto_start=True` (the default). Tested (`test_auto_start.py`); full wiring/reload/connections.toml regression green.

> **On-trigger / demand-gate.** Numbered for tracking only — build when the trigger below fires (“demand-gate, don’t schedule”).

**Cluster:** Connections & Transports. **Priority:** P3. **Verdict:** demand-gate. **Severity (vs Corepoint):** minor.

**Scope:** A persisted per-connection flag controlling whether that connection starts when the engine service starts (on for production, off for test connections).

**Trigger:** build when an adopter needs a defined connection to stay stopped across service restarts without removing it from config.

**Why:** Real gap. No persisted per-connection auto-start/enabled flag exists — the RegistryRunner starts every configured connection at boot and the only start/stop control (POST /connections/{name}/start|stop) is a transient runtime action that a service restart discards, so an operator cannot declare a connection start-disabled (e.g. a test endpoint) across restarts.

**Nearest existing mechanism:** Runtime connection control only: POST /connections/{name}/start|stop|restart in api/app.py (Permission.CONNECTIONS_CONTROL, routed through _ui_seam start_connection/stop_connection/restart_connection). These are transient manual actions — not persisted. On engine/service (re)start the RegistryRunner in pipeline/wiring_runner.py binds and starts every configured inbound/outbound; there is no per-connection persisted enable/autostart field on InboundConnection or OutboundConnection in config/wiring.py. The closest persisted gating knobs are the outbound `simulate` flag (suppresses egress but still starts/runs the connection) and the per-connection DR `priority` tier (which only conditionally binds listeners under the [dr] run-profile, not for normal startup).

**Source:** Corepoint v8.1.0 help-export coverage sweep (2026-07-09) — five adversarially-verified passes over the full help export (1,569 pages); absence re-verified against `origin/main` before filing. Cross-ref [#52](#52-corepoint-capability-parity-gaps--prioritized-roadmap-input-2026-06-27).

---

## 116. File-size integrity re-check before disposition

> 🔢 **Re-scored 2026-07-10 → DEMAND-GATE.** Value **2/10** · Difficulty **2/10** · _fill-in_. min_age_seconds quiescence window plus single-shot whole-file read already guard partial writes; a size re-stat is a marginal additive hardening. _(was DEMAND-GATE · V2/5 · D2/5)_

> **On-trigger / demand-gate.** Numbered for tracking only — build when the trigger below fires (“demand-gate, don’t schedule”).

**Cluster:** Connections & Transports. **Priority:** P3. **Verdict:** demand-gate. **Severity (vs Corepoint):** minor.

**Scope:** Compare a source file's size at read time against its size at disposition; if it changed, error the message rather than enqueue a partially-written file.

**Trigger:** build when a partner writes files in place (no temp-then-rename) and the mtime cutoff proves insufficient.

**Why:** Real gap. File and RemoteFile sources guard against partial writes only proactively via `min_age_seconds` (a mtime quiescence window) and read the whole file in one shot before moving it, but never re-compare the source file's size between read and disposition to error a file that grew or was truncated mid-processing.

**Nearest existing mechanism:** FileSource/RemoteFile source setting `min_age_seconds` (transports/file.py `_candidates`, docs/CONNECTIONS.md) — skips files modified within a quiescence window to avoid reading partial writes; plus the whole-file single-shot `read_bytes()`/`retrieve` before move/delete. No size-at-read vs size-at-disposition comparison exists.

**Source:** Corepoint v8.1.0 help-export coverage sweep (2026-07-09) — five adversarially-verified passes over the full help export (1,569 pages); absence re-verified against `origin/main` before filing. Cross-ref [#52](#52-corepoint-capability-parity-gaps--prioritized-roadmap-input-2026-06-27).

---

## 117. Sender no-wait-for-ACK (fire-and-forward) option

> ✅ **SHIPPED — merged 2026-07-24 (PR #1220); verified against `origin/main` (2026-07-28).** The opt-in per-outbound MLLP toggle is built: `self.no_ack` at `messagefoundry/transports/mllp.py:620` — default `False` = today's ACK-waiting behaviour, byte-identical; when on, `send()` frames, writes, drains and finalizes on the TCP write, reading no ACK (*at-most-once-confirmation*: no NAK-/timeout-driven retry). [ADR 0124](adr/0124-outbound-mllp-fire-and-forward-no-wait-for-ack-delivery-on-write.md) **is on `main`**, with its index row at `docs/adr/README.md:151`. The build constraints above were met, and the interaction with #82 is **guarded, not merely documented**: `messagefoundry/config/wiring.py:3388-3405` raises a `WiringError` at `check`/dry-run time for `no_ack` on a non-MLLP outbound, for `no_ack` + `capture_response`/`reingress_to`, and for `no_ack` + `verify_ack_control_id` (no ACK is read, so there is no MSA-2 to correlate) — pinned by `tests/test_no_ack_wiring.py:47-60`. _(was 🔢 DEMAND-GATE · Value 3/10 · Difficulty 3/10.)_

> 🛠 **Decline overturned (2026-07-09) — historical.** A prioritization pass recommended DECLINE; the stated reason was **invalid**. Purity binds `@router` / `@handler` — **not connectors** (CLAUDE.md §8: “side effects (DB, network) belong in connections/transports”). This was an unfired **demand-gate**, not an architectural impossibility — and it has since been built (see the banner above).
>
> **Build constraints (all met by the shipped build):** Ship as an opt-in per-connection toggle on the MLLP outbound; the default MUST remain ACK-waiting (read one ACK, validate MSA-1 in _check_ack) so existing feeds are unchanged. Mirror the existing expect_reply=false semantics: mark the outbox row PROCESSED/delivered on successful TCP write, and document explicitly that delivery is confirmed on write, not on a positive MSA-1 ACK — there is no NAK-driven or timeout-driven retry in this mode. Preserve per-lane send ORDER (pipelining must not reorder within a lane)…

**Cluster:** Connections & Transports. **Priority:** P3. **Verdict:** demand-gate. **Severity (vs Corepoint):** minor.

**Scope:** An outbound setting that transmits the next message without waiting for the previous message's acknowledgement.

**Trigger:** build when a downstream peer does not acknowledge and the ACK wait becomes the throughput bottleneck.

**Why:** Real gap. The HL7/MLLP outbound (MLLPDestination) always requires a positive ACK and delivers strictly serially per lane, with no per-connection option to send the next message without waiting for the previous ACK; the only fire-and-forget MessageFoundry has is `expect_reply=false` on the non-HL7 generic Tcp()/X12() connectors.

**Nearest existing mechanism:** Generic Tcp()/X12() outbound `expect_reply=false` (fire-and-forget after the write, transports/tcp.py + transports/x12.py). But the HL7 path — MLLPDestination (transports/mllp.py) — always frames one message, reads one ACK, and validates MSA-1 in _check_ack before completing; there is no ACK-skip toggle, and per-lane delivery is strictly serial (ADR 0067 per-lane FIFO), so the next message never sends until the prior ACK is read.

**Source:** Corepoint v8.1.0 help-export coverage sweep (2026-07-09) — five adversarially-verified passes over the full help export (1,569 pages); absence re-verified against `origin/main` before filing. Cross-ref [#52](#52-corepoint-capability-parity-gaps--prioritized-roadmap-input-2026-06-27).

---

## 118. Test the alert mail server (send test email / SMTP verification)

> ✅ **SHIPPED — verified against `origin/main` (2026-07-28)** (commit `37613ef0`, PR #1200). The additive test-send endpoint is built exactly as scoped: `POST /alerts/test-email` (`messagefoundry/api/app.py:2427`) performs a live SMTP send of a synthetic, **PHI-free** message reusing the built email sink, with the connector `SecretProvider` exposed to it so a configured credential resolves (`:5453`). Its request/result models carry this item's number in their own docstrings (`messagefoundry/api/models.py:1063`, `:1072`); an empty body tests the configured server as-is. _(was 🔢 DEMAND-GATE · Value 6/10 · Difficulty 2/10.)_

**Cluster:** Alerting. **Priority:** P3. **Verdict:** demand-gate. **Severity (vs Corepoint):** minor.

**Scope:** Send a live test email through the configured alert mail server to verify SMTP configuration before alerts go live.

**Trigger:** build when operators need to validate the alert mail-server configuration before an incident depends on it.

**Why:** Real gap. MessageFoundry can send operator alerts over SMTP (`EmailTransport`/`send_plain_email` from `[alerts]` settings) and exposes a read-only `/alerts/rules` config view, but has no on-demand "send test email" action to verify the mail server before alerts go live — SMTP config is only exercised when a real alert fires.

**Nearest existing mechanism:** The alert SMTP send path itself — `EmailTransport` / `send_plain_email` in `messagefoundry/pipeline/alert_sinks.py` (built from `[alerts].email_smtp_*` settings via `notifier_from_settings`) — plus the read-only config view at API `GET /alerts/rules` (`AlertsConfig`) and the console `alerts_page.py`, which display SMTP host/port/TLS/recipient count but offer no send action.

**Source:** Corepoint v8.1.0 help-export coverage sweep (2026-07-09) — five adversarially-verified passes over the full help export (1,569 pages); absence re-verified against `origin/main` before filing. Cross-ref [#52](#52-corepoint-capability-parity-gaps--prioritized-roadmap-input-2026-06-27).

---

## 119. Nightly automatic application-log compression

> ✅ **SHIPPED — verified against `origin/main` (2026-07-28).** [ADR 0137](adr/0137-time-boxed-retention-maintenance-pass-between-phase-cap.md) (2026-07-24 amendment). `messagefoundry/pipeline/retention.py:514-530` gzips application-log **files** older than `app_log_compress_days` **in place**, dispatched off the event loop via `asyncio.to_thread`, **free-space-prechecked and integrity-validated before the original is removed** — `_has_free_space` (`:788-813`) uses `shutil.disk_usage` with a `size + max(size//10, 1 MiB)` bar and **fails closed** on `OSError`. Entry point `_compress_app_logs` (`:705`).
>
> ⚠️ **Not a nightly clock.** Compression runs on the **retention-pass cadence** (`[retention].purge_interval_seconds`, default 3600 s), not on an off-peak daily pin analogous to `vacuum_at`; there is no `app_log_compress_at` knob. That is a superset of "nightly" in *frequency* but not in *placement* — an operator who specifically wants heavy compression confined to an off-peak hour does not have that dial, and would need a new item. _(was 🔢 DEMAND-GATE · Value 2/10 · Difficulty 3/10.)_

**Cluster:** Logging & Audit. **Priority:** P3. **Verdict:** demand-gate. **Severity (vs Corepoint):** minor.

**Scope:** Engine-managed nightly compression of its own application/connection log files, with a configurable window, a free-space precheck, and integrity validation before deleting the original.

**Trigger:** build when engine application logs consume material disk on a long-running production box.

**Why:** Real gap. Engine-owned nightly compression of application/connection log files (configurable window + free-space precheck + integrity-validate-before-delete) does not exist; log file lifecycle is delegated wholesale to NSSM, which only rotates stdout/stderr at a byte threshold (no compression, no window, no precheck/validate), while BACKLOG #50 merely meters app-log disk usage and #34 retention prunes the store rather than the logs.

**Nearest existing mechanism:** NSSM stdout/stderr rotation configured in scripts/service/install-service.ps1 (AppRotateFiles / AppRotateOnline / AppRotateBytes ~10MB); the engine adds no Python file handlers by design (logging_setup.py). BACKLOG #50 meters app-log disk usage into GET /status but does not compress or lifecycle-manage the files.

**Source:** Corepoint v8.1.0 help-export coverage sweep (2026-07-09) — five adversarially-verified passes over the full help export (1,569 pages); absence re-verified against `origin/main` before filing. Cross-ref [#52](#52-corepoint-capability-parity-gaps--prioritized-roadmap-input-2026-06-27).

---

## 120. Application log-file retention (auto-delete after N days)

> ✅ **SHIPPED 2026-07-11 (PR #922).** `[retention].app_log_days` deletes application log files (`.log`/`.txt`, one level, by mtime) from `[logging].log_dir` older than N days — off-thread, metadata-only, audited; opt-in (`0` = keep). Threaded `Engine` → `RetentionRunner` via `create_app`.

**Cluster:** Logging & Audit. **Priority:** P3. **Verdict:** demand-gate. **Severity (vs Corepoint):** minor.

**Scope:** A configurable number of days to keep the engine's daily application log FILES, after which the maintenance job deletes them.

**Trigger:** build when an operator needs the engine to bound its own application-log disk footprint without external log rotation.

**Why:** Real gap. MessageFoundry never deletes captured application log files by age — NSSM rotates them only by size (AppRotateBytes, install-service.ps1) and BACKLOG #50 only meters the log directory's disk usage; the [retention] RetentionRunner prunes the message store, not log files.

**Nearest existing mechanism:** NSSM size-based stdout/stderr rotation (AppRotateBytes ~10 MB in scripts/service/install-service.ps1) + app-log disk metering (log_dir surfaced in GET /status, BACKLOG #50). The [retention]/RetentionRunner purge (pipeline/retention.py) is store-only, not log files. None delete log files by age.

**Source:** Corepoint v8.1.0 help-export coverage sweep (2026-07-09) — five adversarially-verified passes over the full help export (1,569 pages); absence re-verified against `origin/main` before filing. Cross-ref [#52](#52-corepoint-capability-parity-gaps--prioritized-roadmap-input-2026-06-27).

---

## 121. Maximum log-maintenance task duration cap

> ✅ **SHIPPED (mechanism) — verified against `origin/main` (2026-07-28).** [ADR 0137](adr/0137-time-boxed-retention-maintenance-pass-between-phase-cap.md). The between-phase duration cap is `messagefoundry/pipeline/retention.py:392-409` — `cap = s.max_pass_seconds`, a monotonic `pass_start` and a **latching** `_deadline_hit()` gating **every** phase (`:420`, `:427`, `:443`, `:459`, `:467`, `:481`, `:501`, `:511`, `:527`) and the maintenance block (`:530-552`). A cap-skipped phase leaves its marker unadvanced (`:536-543`, `:546-549`), so skipped work is retried next pass rather than silently lost.
>
> ⚠️ **The shipped default deviates from the item's ask, deliberately.** The Scope said "default four hours"; the build ships `max_pass_seconds = 0.0` (**OFF**) and *recommends* 14400 — an ADR 0137:79-83 decision to honour the `[retention]` keep/off convention so an upgrade stays byte-identical. The **mechanism is complete; only the default differs.** ⚠️ **The cap is soft** — checked between phases, so a single long-running phase can overrun it. ⚠️ `max_pass_seconds` is **missing from the `[retention]` table in `docs/CONFIGURATION.md`** (its sibling `app_log_compress_days` is documented) — a small doc gap. _(was 🔢 DEMAND-GATE · Value 2/10 · Difficulty 3/10.)_

**Cluster:** Logging & Audit. **Priority:** P3. **Verdict:** demand-gate. **Severity (vs Corepoint):** minor.

**Scope:** A ceiling (default four hours) on how long a log-maintenance pass may run; if exceeded it stops and resumes in the next maintenance period.

**Trigger:** build when a log-maintenance pass on a large store runs long enough to overlap the next maintenance window.

**Why:** Real gap. The RetentionRunner runs body-purge, WAL-checkpoint, and VACUUM passes to completion with no maximum-duration cap that would stop a long pass and resume it next interval — the closest controls are the fixed purge_interval_seconds cadence and the off-peak vacuum_at window, neither of which time-boxes a running pass.

**Nearest existing mechanism:** RetentionRunner (messagefoundry/pipeline/retention.py) with the [retention] settings in config/settings.py — purge_interval_seconds sets the pass cadence, vacuum_at pins VACUUM to a daily off-peak clock time, and each run_once pass is exception-isolated (logged, retried next interval). None of these bounds how long a single maintenance pass may run.

**Source:** Corepoint v8.1.0 help-export coverage sweep (2026-07-09) — five adversarially-verified passes over the full help export (1,569 pages); absence re-verified against `origin/main` before filing. Cross-ref [#52](#52-corepoint-capability-parity-gaps--prioritized-roadmap-input-2026-06-27).

---

## 122. Corrupted application-log detection, rollover, and connection-stop

> 🔢 **Re-scored 2026-07-10 → DEMAND-GATE.** Value **2/10** · Difficulty **5/10** · _fill-in_. Stdout+NSSM and #50 disk metering substantially cover log durability/visibility; the added file-log lifecycle is marginal and non-interop. _(was DEMAND-GATE · V2/5 · D3/5)_

> **On-trigger / demand-gate.** Numbered for tracking only — build when the trigger below fires (“demand-gate, don’t schedule”).

**Cluster:** Logging & Audit. **Priority:** P3. **Verdict:** demand-gate. **Severity (vs Corepoint):** minor.

**Scope:** On a corrupted or unwritable application log, rename it, roll to a fresh file, record the event, and stop the affected connection if the new file also cannot be written.

**Trigger:** build when a corrupted or unwritable application log silently stops recording engine activity.

**Why:** Real gap. The engine writes logs only to stdout (rotation is delegated to NSSM) and has no engine-managed log-file lifecycle, so there is no detection of a corrupted/unwritable application log, no rename-and-roll to a fresh file, no recorded rollover event, and no fail-closed connection stop when the replacement file is also unwritable; the nearest existing pieces are logging_setup.py's stdout handler, BACKLOG #50's GET /status app-log disk metering (visibility only), and ADR 0014's connection_stopped rule (which does not react to log-write failures).

**Nearest existing mechanism:** logging_setup.py (stdout StreamHandler + optional off-box SysLogHandler; NSSM externally rotates the captured stdout files) and BACKLOG #50's app-log disk metering in GET /status (visibility only); ADR 0014's connection_stopped alert rule reports a stop but is not driven by a log-write failure.

**Source:** Corepoint v8.1.0 help-export coverage sweep (2026-07-09) — five adversarially-verified passes over the full help export (1,569 pages); absence re-verified against `origin/main` before filing. Cross-ref [#52](#52-corepoint-capability-parity-gaps--prioritized-roadmap-input-2026-06-27).

---

## 123. Resend a stored message to an ALTERNATE connection

> ✅ **SHIPPED (2026-07-11, [ADR 0090](adr/0090-resend-a-stored-message-to-an-alternate-outbound-connection.md) Accepted).** The API/engine capability is built: `store.resend_to(...)` on all three backends (SQLite/Postgres/SQL Server) + an additive `resend_log(resend_key UNIQUE)` idempotency table, `engine.resend`, `POST /messages/{id}/resend` (new `Permission.MESSAGES_RESEND` step-up, cross-channel authorization to BOTH the origin's and the alternate outbound's channel, `message_resend` audit — never the body). Ships the retained transformed body (never re-runs the transform); one new `stage='outbound'` row on the origin at the alternate lane's TAIL; FIFO-safe under the second control-plane writer (SQLite process-lock, SQL Server #285 blocking claim, Postgres per-lane `pg_advisory_xact_lock` funnel); 409 on a retention-nulled source. Was re-scored 2026-07-10 → DEMAND-GATE (V6/D4, _quick win_); trigger fired (Corepoint cutover operator-parity). **Residual:** the **console/webconsole Resend UI** (a desired-if-clean follow-on — the API/engine capability is the #123 deliverable). **[#153](#153-edit-and-resend-a-stored-message) (edit-and-resend) has since SHIPPED on this seam ([ADR 0090](adr/0090-resend-a-stored-message-to-an-alternate-outbound-connection.md) §9), adding a web-console editor.**

**Cluster:** Store / Operations. **Priority:** P3. **Verdict:** demand-gate. **Severity (vs Corepoint):** minor.

**Scope:** When resending from a connection log, redirect the resend to a different connection than the one the message originally traversed.

**Trigger:** build when an operator must replay a captured message to a different destination than the one it originally traversed.

**Why:** Real gap. Replay/resend (Store.replay, Store.replay_dead, POST /messages/{id}/replay) only re-queues a message's existing outbound rows to their original destination — there is no facility to redirect a resend to an operator-chosen alternate connection.

**Nearest existing mechanism:** Store.replay (message-level "re-send" of done rows) and Store.replay_dead (bulk DLQ replay), surfaced by Engine.replay/replay_dead and the API routes POST /messages/{id}/replay and POST /dead-letters/replay — all re-queue the message's EXISTING outbound rows to their original destination; ADR 0013 re-ingress feeds a captured outbound back through a loopback inbound, but the target is fixed at config time (reingress_to=), not operator-chosen at resend.

**Source:** Corepoint v8.1.0 help-export coverage sweep (2026-07-09) — five adversarially-verified passes over the full help export (1,569 pages); absence re-verified against `origin/main` before filing. Cross-ref [#52](#52-corepoint-capability-parity-gaps--prioritized-roadmap-input-2026-06-27).

---

## 124. Batch-export message bodies from a connection log to a file

> 🔢 **Re-scored 2026-07-10 → DEMAND-GATE.** Value **5/10** · Difficulty **3/10** · _fill-in_. Corepoint-parity bulk export; the search plus per-message audited raw API is a real, scriptable workaround, so useful breadth, not a blocker. _(was DEMAND-GATE · V2/5 · D3/5)_
> **On-trigger / demand-gate.** Numbered for tracking only — build when the trigger below fires (“demand-gate, don’t schedule”).

> **AMENDED 2026-07-28 — the API half is BUILT; the console half is DEAD CODE.** Adversarial verification refuted a full close. **BUILT:** `GET /messages/export` (`messagefoundry/api/app.py:3001`) behind a dedicated `MESSAGES_EXPORT` permission with step-up + audit ([ADR 0131](adr/0131-bulk-raw-message-body-export-from-a-search-result-step-up-audited-phi-egress.md)), with 11 tests. A scripted operator can export today.
>
> ⚠️ **The REMAINDER is the console affordance, and it is worse than missing — it is wired to nothing.** The console JS registers a handler on `[data-mf-msg-export]`, but **no page builder emits that attribute** (`pages/messages.py` contains zero `data-mf-*` attributes and no per-row checkboxes), and the URL the JS fetches, `/ui/messages/export`, **has no route** — it would be swallowed by `/ui/messages/{message_id}`. So the progress bar and stop control the Scope names by name are unreachable. ⚠️ **ADR 0131 and its index row at `docs/adr/README.md:157` overstate this** and should be amended when the console half lands.

**Cluster:** Logging & Audit. **Priority:** P3. **Verdict:** demand-gate. **Severity (vs Corepoint):** minor.

**Scope:** Save-selected / save-all downloads a log search result's message bodies to a text file, with a progress bar and a stop control.

**Trigger:** build when an operator needs to hand a batch of message bodies to a partner or support engineer for offline analysis.

**Why:** Real gap. There is no batch/multi-select export of message bodies from a log-search result to a file (with progress/stop); the nearest mechanism is `/messages/search` plus one-at-a-time raw retrieval via `/messages/{id}` (each an audited PHI view), and BACKLOG #49's support-bundle explicitly carries no raw message bodies.

**Nearest existing mechanism:** The `/messages/search` API route plus single-message raw retrieval via `/messages/{message_id}` (both in messagefoundry/api/app.py, raw body gated by `messages:view_raw` and audited per view); the tee `export` CLI is test-data/anonymized-captures only, and BACKLOG #49 `support-bundle` deliberately excludes raw bodies.

**Source:** Corepoint v8.1.0 help-export coverage sweep (2026-07-09) — five adversarially-verified passes over the full help export (1,569 pages); absence re-verified against `origin/main` before filing. Cross-ref [#52](#52-corepoint-capability-parity-gaps--prioritized-roadmap-input-2026-06-27).

---

## 125. Uploaded Logs page - import external message files and browse them offline

> 🔢 **Re-scored 2026-07-10 → DEMAND-GATE.** Value **5/10** · Difficulty **5/10** · _fill-in_. Corepoint-parity offline file viewer; dryrun and File()->store->browser cover the inspect need cleanly, so it is console breadth not a blocker. _(was DEMAND-GATE · V2/5 · D3/5)_
> **On-trigger / demand-gate.** Numbered for tracking only — build when the trigger below fires (“demand-gate, don’t schedule”).

> **AMENDED 2026-07-28 — nearly all of this is BUILT; one named capability is absent by construction.** Adversarial verification refuted a full close. **BUILT** ([ADR 0134](adr/0134-offline-uploaded-logs-viewer-connection-decoupled-upload-browse-resend-deletion-phi-at-rest-posture-stdlib-multipart.md)): the Uploaded Logs page, opt-in `uploads_dir`, encrypted upload, filter/search browse, per-message **resend**, delete (**#126**, closed), quotas, retention and audit.
>
> ⚠️ **The REMAINDER: the Scope and Why both ask to "resend AND SAVE", and there is no save/download route anywhere.** The complete surface is `POST /uploads`, `GET /uploads`, `GET /uploads/{id}/messages`, `POST …/resend`, `DELETE /uploads/{id}` — no read-one and no download. Browse is **metadata-only by construction** (a test asserts `PID` is *not* in the response), so an operator can neither **read** nor **save** an uploaded message body. "Save" appears nowhere in ADR 0134 — not even in its out-of-scope list — so this is an undocumented gap, not a ratified narrowing. Decide it explicitly: build the download, or record the decline.

**Cluster:** Monitoring. **Priority:** P3. **Verdict:** demand-gate. **Severity (vs Corepoint):** minor.

**Scope:** An operator page to upload arbitrary .hl7/.txt/.xml files and browse each as a filterable, searchable log with per-message resend and save, decoupled from any live connection.

**Trigger:** build when support engineers need to inspect a partner-supplied message file without ingesting it into the live store.

**Why:** Real gap. There is no operator page to upload arbitrary external .hl7/.txt/.xml files and browse them offline as a filterable/searchable log with per-message resend and save; the nearest mechanisms are the `File()` inbound connector (live ingest into the store, not offline browsing), the message browser / dead-letter replay (store-only), and the one-shot `dryrun` CLI.

**Nearest existing mechanism:** The `File()` inbound connector (transports/file.py) plus the console/web message browser and dead-letter replay (api/app.py) — all of which operate on messages that entered through a wired connection and were persisted to the store; and the CLI `messagefoundry dryrun`, which runs a Router/Handler against one sample file one-shot. None imports arbitrary external files into an ad-hoc, connection-decoupled offline log viewer.

**Source:** Corepoint v8.1.0 help-export coverage sweep (2026-07-09) — five adversarially-verified passes over the full help export (1,569 pages); absence re-verified against `origin/main` before filing. Cross-ref [#52](#52-corepoint-capability-parity-gaps--prioritized-roadmap-input-2026-06-27).

---

## 126. Delete an uploaded data file from the server

> ✅ **SHIPPED — verified against `origin/main` (2026-07-28).** [ADR 0134](adr/0134-offline-uploaded-logs-viewer-connection-decoupled-upload-browse-resend-deletion-phi-at-rest-posture-stdlib-multipart.md), **Accepted 2026-07-18**. `DELETE /uploads/{file_id}` (`messagefoundry/api/app.py:3890`) — docstring "destructive + irreversible" — behind `require_step_up(Permission.FILES_DELETE)` (`:3895`), calling `uploads.delete` (`:3901`, which unlinks **both** the blob and its metadata, `uploads.py:466-483`), writing an `upload.delete` audit row (`:3905`), and 503-ing when `uploads_dir` is unset (`:3609-3615`).
>
> ⚠️ **Scope boundary:** this deletes only files uploaded through the **#125 uploaded-logs** subsystem — **not arbitrary server-side files**. The item's title, Scope and Trigger all bound the ask that way, so it matches; stated here so a future need to delete non-uploaded server files is filed as new work rather than assumed covered. Deletion is per-file (no bulk sweep). _(was 🔢 DEMAND-GATE · Value 2/10 · Difficulty 3/10.)_

**Cluster:** Monitoring. **Priority:** P3. **Verdict:** demand-gate. **Severity (vs Corepoint):** minor.

**Scope:** Select and delete previously uploaded message/log files from the server as an explicit cleanup action.

**Trigger:** build when uploaded diagnostic files accumulate and need an operator-facing cleanup action. Pairs with #125.

**Why:** Real gap. MessageFoundry has no interactive server-side file-management action to browse and delete previously received message/log files; the nearest mechanisms are the File connector's automatic `after_read=delete`/move on consumed input files and the age-based store purge in pipeline/retention.py, both automatic and neither an operator-invoked cleanup of arbitrary server files.

**Nearest existing mechanism:** File source connector's `after_read` setting (`move`|`delete`) in transports/file.py, which auto-moves/deletes consumed input files after processing; plus pipeline/retention.py store purge (`purge_message_bodies`/`purge_dead_letters`). Neither is an operator-facing "select and delete a server file" action.

**Source:** Corepoint v8.1.0 help-export coverage sweep (2026-07-09) — five adversarially-verified passes over the full help export (1,569 pages); absence re-verified against `origin/main` before filing. Cross-ref [#52](#52-corepoint-capability-parity-gaps--prioritized-roadmap-input-2026-06-27).

---

## 127. Web-proxy credential types (Basic / Digest / NTLM / Windows)

> 🔢 **Re-scored 2026-07-10 → DEMAND-GATE.** Value **5/10** · Difficulty **4/10** · _fill-in_. 'New dep' for D5 is false: pyspnego (NTLM/SSPI/Negotiate) already core dep+locked. No re-lock -> D4. Value 5 stands (env-var/cntlm workarounds, parity). _(was DEMAND-GATE · V2/5 · D3/5)_

> **On-trigger / demand-gate.** Numbered for tracking only — build when the trigger below fires (“demand-gate, don’t schedule”).

> **AMENDED 2026-07-30 — Basic is BUILT, Digest is BUILT for http destinations, and NTLM/Windows are REFUSED at construction.** Adversarial verification refuted a full close. **BUILT** ([ADR 0126](adr/0126-outbound-forward-egress-web-proxy-for-the-stdlib-http-family.md), landed with #112/#128): `proxy_user` / `proxy_password` / `proxy_auth_type` on **`Rest`** (`messagefoundry/config/wiring.py:1332`), **`FHIR`** (`:1412`), **`DICOMweb`** (`:1659`) and **`Soap`** (`:2004`), dispatched by `proxy_auth_handler_from_settings` (`messagefoundry/transports/rest.py:929`). **Basic** — the default once a credential is set — is a **pre-emptive** `Proxy-Authorization` header and works for **both** http and https destinations, because urllib moves it into the `CONNECT` tunnel headers (`:981-984`). **Digest** is the reactive stdlib handler and is supported for an **http destination only**; an https destination is refused **at construction** because the `407` arrives inside the `CONNECT` tunnel (`:985-992`). A credential over a cleartext `http` proxy hop is refused posture-keyed regardless of destination scheme (`:971-979`). Tests: `tests/test_outbound_forward_proxy.py`.
>
> ⚠️ **NTLM and Windows are NOT built — the engine REFUSES them, so do not read this banner as four-scheme parity.** `proxy_auth_type` in `{ntlm, windows}` raises at construction (`messagefoundry/transports/rest.py:993-998`): the handshake is **connection-bound** (type1/type2/type3 must ride one keep-alive TCP connection) and `urllib.request` opens a new connection per `open()`, so a correct build needs a keep-alive client driven by `pyspnego` — the same reasoning that scoped them out of **#65** (`messagefoundry/transports/http_auth.py:27-31`). ADR 0126 records them as **deferred, refused loudly** (`0126:65-68`, `:154`) and lists NTLM/Windows/Negotiate under **Out of scope** (`:159`); the documented workaround is a local authenticating proxy such as `cntlm`. Locked by `tests/test_outbound_forward_proxy.py::test_digest_https_and_ntlm_windows_refused` (ADR AC-6, `0126:116-119`).

**Cluster:** Web Services & HTTP. **Priority:** P3. **Verdict:** demand-gate. **Severity (vs Corepoint):** minor.

**Scope:** Authenticate outbound web-service traffic to the forward proxy itself, selecting the proxy credential type. Meaningless without the forward-proxy address item - build together.

**Trigger:** build when the forward proxy of #112 requires authentication. **Build with #112** — meaningless alone.

**Why:** Real gap. No outbound connector can authenticate to a forward web proxy (no proxy-address item and no Basic/Digest/NTLM/Windows proxy-credential type); the nearest mechanism is REST/SOAP endpoint auth headers (`_build_headers`) which authenticate to the destination service, not to an intervening proxy, and the only "proxy" config models an inbound reverse proxy (`trusted_proxies`), not egress.

**Nearest existing mechanism:** REST()/SOAP() outbound connectors build endpoint auth headers (`_build_headers` Basic/Bearer, plus the ADR 0024 SMART token provider) in messagefoundry/transports/rest.py, but these authenticate to the target web service, not to an intermediary forward proxy; outbound HTTP uses a stdlib urllib opener with no proxy handler or proxy-credential surface, and config/settings.py only models an inbound reverse proxy (trusted_proxies, tls_terminated_upstream).

**Source:** Corepoint v8.1.0 help-export coverage sweep (2026-07-09) — five adversarially-verified passes over the full help export (1,569 pages); absence re-verified against `origin/main` before filing. Cross-ref [#52](#52-corepoint-capability-parity-gaps--prioritized-roadmap-input-2026-06-27).

---

## 128. Bypass the forward proxy for local (intranet) requests

> ✅ **SHIPPED — verified against `origin/main` (2026-07-28).** [ADR 0126](adr/0126-outbound-forward-egress-web-proxy-for-the-stdlib-http-family.md). `_proxy_bypasses` (`messagefoundry/transports/rest.py:550-568`) does NO_PROXY-style matching of a host against a per-connection bypass list: exact host, `.suffix`/`*.suffix`, `*`, port and trailing dot stripped, IPv6 literals matched intact (helper `_strip_proxy_host_port` at `:540-547` is IPv6-safe). A bypassed host gets **no proxy handler *and* no `Proxy-Authorization`** — byte-identical to no proxy at all (`ProxyConfig.for_host`, `:586-611`).
>
> ⚠️ **Evaluated per fixed destination host at construction, not per request.** That is correct for this engine — a connection's destination and token-endpoint hosts are fixed — and is reasoned explicitly at ADR 0126:68-76, but it is **not** request-time `NO_PROXY` evaluation; in `"default"` mode the system `no_proxy` is delegated to urllib instead. ⚠️ Direct test coverage is **REST-only**; SOAP/FHIR inherit the same helper without their own cases. _(was 🔢 DEMAND-GATE · Value 2/10 · Difficulty 2/10.)_

**Cluster:** Web Services & HTTP. **Priority:** P3. **Verdict:** demand-gate. **Severity (vs Corepoint):** minor.

**Scope:** Skip the configured forward proxy for local/intranet destinations on REST/SOAP clients. Meaningless without the forward-proxy address item - build together.

**Trigger:** build when the forward proxy of #112 must be skipped for intranet destinations. **Build with #112** — meaningless alone.

**Why:** Real gap. Neither the REST nor SOAP outbound connector supports a configured forward proxy (urllib build_opener with no ProxyHandler), so there is no proxy address item for local/intranet requests to bypass; the only proxy support present is the unrelated inbound reverse-proxy trust config in settings.py.

**Nearest existing mechanism:** None for an outbound forward proxy. The REST/SOAP destination connectors (transports/rest.py, transports/soap.py) build their client via urllib.request.build_opener with no ProxyHandler configuration or bypass list. All "proxy" support in the codebase is the inbound reverse-proxy posture (settings.py trusted_proxies / behind_tls_proxy, X-Forwarded-For), which is unrelated.

**Source:** Corepoint v8.1.0 help-export coverage sweep (2026-07-09) — five adversarially-verified passes over the full help export (1,569 pages); absence re-verified against `origin/main` before filing. Cross-ref [#52](#52-corepoint-capability-parity-gaps--prioritized-roadmap-input-2026-06-27).

---

## 129. Granular 'Allow Expired Certificate' TLS relaxation

> ✅ **SHIPPED (2026-07-12).** Per-connection opt-in `tls_allow_expired` (default off = byte-identical) honours a partner **server cert whose validity period has lapsed** while STILL validating chain + hostname + key-usage — the granular, non-MITM-able alternative to the blunt `tls_verify=false`. Mechanism: OR OpenSSL's `X509_V_FLAG_NO_CHECK_TIME` (`0x200000`, stable public constant; `verify_flags` accepts the raw int) onto an already-**verifying** context via shared `config/tls_policy.py:relax_verify_expiry` (guarded no-op on `CERT_NONE`; PHI-free construction WARN), threaded on the **verify path only** through `_mllp_ssl_context` / `_ftps_ssl_context` / `_client_ssl_context` (DICOM-SCU) + the urllib HTTP family (`_expiry_relaxed_opener`, reused by soap.py incl. mTLS + fhir.py); factories `MLLP`/`Rest`/`FHIR`/`Soap`/`DICOM`/`Ftp` expose it. NEVER disables verification → composes with (never weakens) the fail-closed no-CA / `tls_verify=false` / #200 cleartext refusals, and an expiry-relaxed hop stays a *verified* hop so the #200 posture gate never keys on it. Chose the context-level OpenSSL flag over post-handshake `cryptography.x509.verification` `.time()` (available but needs `CERT_NONE`-then-reverify, only cleanly reachable for asyncio MLLP — not ftplib/pynetdicom/urllib). **ADR 0094**; tests `tests/test_tls_expiry_relaxation.py` (expired accepted only-with-flag over a real TLS handshake; wrong-host + broken-chain still rejected with the flag; #200 not keyed on it). _(was 🔢 DEMAND-GATE · Value 6/10 · Difficulty 5/10.)_

**Cluster:** Security. **Priority:** P3. **Verdict:** shipped. **Severity (vs Corepoint):** minor.

**Scope:** A per-connection TLS override that honours a partner certificate whose NotAfter has passed, while still validating chain and hostname.

**Trigger:** build when a partner presents an expired certificate that cannot be reissued in time and chain/hostname validation must still hold.

**Why:** Real gap. Outbound TLS verification is all-or-nothing (`tls_verify` in transports/mllp.py and siblings — false drops chain, hostname, AND expiry together via CERT_NONE), so there is no granular "honour an expired partner certificate while still validating chain and hostname" override, only the blunt insecure-TLS kill switch.

**Nearest existing mechanism:** The coarse per-connection `tls_verify` boolean in `_mllp_ssl_context` (transports/mllp.py), mirrored in remotefile.py (`_ftps_ssl_context`), rest.py, soap.py, and dicom.py — plus the `MEFOR_ALLOW_INSECURE_TLS` / `insecure_tls_allowed()` dev gate and the `cert_expiry.py` expiry alerter. `tls_verify=false` drops ALL checks (chain + hostname + NotAfter) via `check_hostname=False` / `CERT_NONE`; the engine otherwise only strengthens verification (`harden_verify_flags` → `VERIFY_X509_STRICT`). There is no per-connection flag or `ssl` `verify_flags` manipulation that relaxes only the validity-period (NotAfter) check.

**Source:** Corepoint v8.1.0 help-export coverage sweep (2026-07-09) — five adversarially-verified passes over the full help export (1,569 pages); absence re-verified against `origin/main` before filing. Cross-ref [#52](#52-corepoint-capability-parity-gaps--prioritized-roadmap-input-2026-06-27).

---

## 130. Message queues shared by name across connections + shared-name delete protection

> 🛠 **Decline overturned (2026-07-09).** A prioritization pass recommended DECLINE; the stated reason was **invalid**. Purity binds `@router` / `@handler` — **not connectors** (CLAUDE.md §8: “side effects (DB, network) belong in connections/transports”). This is an unfired **demand-gate**, not an architectural impossibility.
>
> **Build constraints:** 1) The shared queue is a store/config abstraction referenced by name — it must NOT become a "channel"/"route" bundling element (must not enclose the inbound->router->handler->outbound graph). 2) When multiple connections drain one shared queue, strict per-lane FIFO must be preserved via sequence-key lanes + claim-time per-lane FIFO so competing consumers cannot reorder within a sequence key. 3) Reference-counted delete must never orphan or silently drop persisted messages: rows in a shared queue retain their…

> 🔢 **Re-scored 2026-07-10 → DEMAND-GATE.** Value **5/10** · Difficulty **8/10** · _money pit_. Parity breadth; per-connection staged queue + graph wiring is a clean workaround (v5); new shared-queue seam + per-lane FIFO across 3 backends (d8). _(was DEMAND-GATE · V2/5 · D4/5)_

> **On-trigger / demand-gate.** Numbered for tracking only — build when the trigger below fires (“demand-gate, don’t schedule”).

**Cluster:** Store / Operations. **Priority:** P3. **Verdict:** demand-gate. **Severity (vs Corepoint):** minor.

**Scope:** Several connections may reference the same named queue; deleting a connection removes its queue only when no other active connection still references that name.

**Trigger:** build when two connections must share one durable queue by name, with delete protection while any referent remains.

**Why:** Real gap. MessageFoundry has no named, connection-shared queue abstraction — its durable queues are internal per-connection stages in the SQLite store keyed by connection name (store/store.py) and connections are wired by name in the Registry (config/wiring.py), so there is neither a shared-by-name queue nor any reference-counted delete protection guarding it.

**Nearest existing mechanism:** The staged-queue store (store/store.py, SQLite WAL) with per-connection outbound rows, plus the name-wired Registry in config/wiring.py — queues are internal per-connection stage tables, not named shared entities, and connection removal is a config edit with no reference-count check.

**Source:** Corepoint v8.1.0 help-export coverage sweep (2026-07-09) — five adversarially-verified passes over the full help export (1,569 pages); absence re-verified against `origin/main` before filing. Cross-ref [#52](#52-corepoint-capability-parity-gaps--prioritized-roadmap-input-2026-06-27).

---

## 131. Object flagging - mark objects of interest + a Flagged Objects filter

> 🔢 **Re-scored 2026-07-10 → DEMAND-GATE.** Value **4/10** · Difficulty **3/10** · _fill-in_. DX/console-polish flag+filter; not interop, nobody blocked, no existing marker covers it (v4); model field + render/filter in both consoles (d3). _(was P3 · V2/5 · D2/5)_

> **On-trigger / demand-gate.** Numbered for tracking only — build when the trigger below fires (“demand-gate, don’t schedule”).

> **AMENDED 2026-07-30 — the CONNECTION flag and the Flagged-only filter are BUILT; "every configuration object" is a ratified scope fork.** Adversarial verification refuted a full close. **BUILT** ([ADR 0007 amendment 2026-07-19](adr/0007-gui-manageable-connections-toml.md)): a display-only `flagged` field on `InboundConnection` / `OutboundConnection` (`messagefoundry/config/wiring.py:2531`, `:2589` — **no runtime path reads it**), authored code-first **and** in `connections.toml` (`config/connections_file.py:118`, `:139`, round-tripped by `tests/test_connections_roundtrip.py`); `POST /connections/{name}/flag` (`messagefoundry/api/app.py:1944`) → `Engine.set_connection_flag` (`messagefoundry/pipeline/engine.py:1286`) through the comment-preserving validate-before-persist writer — the FIRST console→`connections.toml` write seam — reachable from the console at `POST /ui/connections/{name}/flag` (`messagefoundry_webconsole/routes/connection_writes.py:103`); and the **Flagged-only** filter itself (`messagefoundry_webconsole/pages/connections.py:297`, re-applied after each poll/ws swap by `static/app.js:943-961`). 6 tests in `tests/test_connection_flag.py`.
>
> ⚠️ **The REMAINDER is the word "every" in the Scope.** This item's own Why names **Connection/Router/Handler**; only *connections* carry the flag, and only `connections.toml`-managed ones are console-settable — a code-first connection is refused **409** (it can still declare `flagged=True` in Python). ADR 0007's amendment records that fork deliberately (`0007:190-197`): a durable console-settable flag on *every* object would need a new name-keyed annotation table across all three store backends, which it declines, leaving the universal-object-flag branch "for a future, owner-chosen, store-serialized effort". So this is a **ratified narrowing, not an accidental one** — keep the item open at that reduced scope, and do **not** rebuild the connection half.

**Cluster:** Repository & Config. **Priority:** P3. **Verdict:** demand-gate. **Severity (vs Corepoint):** minor.

**Scope:** A user-settable flag on every configuration object, plus a flagged-only filter over the objects list.

**Trigger:** build when an adopter with a large config repository needs to mark and filter objects of interest.

**Why:** Real gap. No config object (Connection/Router/Handler) carries a user-settable flag/annotation and neither console offers a flagged-only filter; the nearest mechanisms are the existing filtered list views and the functional enabled/simulate connection booleans, none of which is an operator "object of interest" marker.

**Nearest existing mechanism:** The console/web-console connection list and event-log views support filtering (e.g. the kind-filtered connection event log in console/connections.py and the /ui connections/monitoring lists), and connections carry functional booleans (enabled, simulate) — but there is no user-settable "flag" attribute on any config object (config/models.py has no annotation/tag/note field) and no flagged-only filter.

**Source:** Corepoint v8.1.0 help-export coverage sweep (2026-07-09) — five adversarially-verified passes over the full help export (1,569 pages); absence re-verified against `origin/main` before filing. Cross-ref [#52](#52-corepoint-capability-parity-gaps--prioritized-roadmap-input-2026-06-27).

---

## 132. Fixed 'now' test-time override (frozen clock for reproducible transform tests)

> 🔢 **Re-scored 2026-07-10 → DEMAND-GATE.** Value **5/10** · Difficulty **2/10** · _fill-in_. Corepoint-parity frozen-clock aid for reproducible dry-run testing; route_message already accepts ingest_time, only a CLI --now flag is missing. _(was P1 · V3/5 · D1/5)_

> **On-trigger / demand-gate.** Numbered for tracking only — build when the trigger below fires (“demand-gate, don’t schedule”).

**Cluster:** IDE / Test tooling. **Priority:** P3. **Verdict:** demand-gate. **Severity (vs Corepoint):** minor.

**Scope:** Hard-code the value of 'now' so time- and date-sensitive transform logic produces identical output on re-run, enabling deterministic regression comparison.

**Trigger:** build when a transform reads wall-clock time and its Test Bench output must be reproducible for regression comparison.

**Why:** Real gap. MessageFoundry gives transforms a re-run-stable "now" in production via current_ingest_time() (the persisted enqueue timestamp) and dryrun.route_message accepts an ingest_time argument, but the dryrun/check CLI hardwires ingest_time=time.time() with no way to pin a fixed value, so time-sensitive transforms cannot be re-run against a frozen clock for deterministic regression comparison.

**Nearest existing mechanism:** current_ingest_time() + the run-scoped ingest-time provider (messagefoundry/config/ingest_time.py); and dryrun.route_message's ingest_time parameter — but the CLI-facing dry_run()/trace_dry_run() (pipeline/dryrun.py) hardwire ingest_time=time.time() and expose no --now/frozen-clock flag.

**Source:** Corepoint v8.1.0 help-export coverage sweep (2026-07-09) — five adversarially-verified passes over the full help export (1,569 pages); absence re-verified against `origin/main` before filing. Cross-ref [#52](#52-corepoint-capability-parity-gaps--prioritized-roadmap-input-2026-06-27).

---

## 133. User-chosen display colour on configuration objects

> 🛠 **Decline overturned (2026-07-09).** A prioritization pass recommended DECLINE; the stated reason was **invalid**. Purity binds `@router` / `@handler` — **not connectors** (CLAUDE.md §8: “side effects (DB, network) belong in connections/transports”). This is an unfired **demand-gate**, not an architectural impossibility.
>
> **Build constraints:** Colour/label is display-only console/IDE metadata on config objects (add to config/models.py, render via console/theme.py); it must remain a pure presentation attribute with no engine behaviour, routing decision, or disposition depending on it — logic stays code-first Routers/Handlers, so it must not grow into a no-code/visual authoring surface. If any accompanying free-text label field is added, restrict it to non-PHI operational metadata (a bare colour value carries no PHI risk; free-text labels must not…

> 🔢 **Re-scored 2026-07-10 → DEMAND-GATE.** Value **4/10** · Difficulty **3/10** · _fill-in_. Cosmetic per-object display colour; genuine console/IDE polish, nobody blocked; a display field threaded config model to API to console. _(was DEMAND-GATE · V1/5 · D2/5)_

> **On-trigger / demand-gate.** Numbered for tracking only — build when the trigger below fires (“demand-gate, don’t schedule”).

**Cluster:** UX / Console. **Priority:** P3. **Verdict:** demand-gate. **Severity (vs Corepoint):** minor.

**Scope:** Assign a display colour to a configuration object (a schedule on a calendar, source/destination colours on code sets) for visual identification.

**Trigger:** build when an adopter asks for visual identification of configuration objects in the console or IDE.

**Why:** Real gap. Configuration objects (Connections/Routers/Handlers) carry no user-assignable display colour or tag for visual identification; the console has only a single global theme palette (console/theme.py) and a proposed status-derived graph colouring (BACKLOG #76), neither of which lets an operator pick a colour per object.

**Nearest existing mechanism:** console/theme.py (a single global console palette with fixed accent/status colours) and BACKLOG #76 (a status-colored data-flow graph, where colour is derived from live connection status, not user-assigned). No user-chosen per-object colour field exists on the config models (config/models.py has no colour/label/display metadata).

**Source:** Corepoint v8.1.0 help-export coverage sweep (2026-07-09) — five adversarially-verified passes over the full help export (1,569 pages); absence re-verified against `origin/main` before filing. Cross-ref [#52](#52-corepoint-capability-parity-gaps--prioritized-roadmap-input-2026-06-27).

---

## 134. Outbound batch aggregation - N messages into one BHS/BTS envelope on send

> 🛠 **Decline overturned (2026-07-09).** A prioritization pass recommended DECLINE; the stated reason was **invalid**. Purity binds `@router` / `@handler` — **not connectors** (CLAUDE.md §8: “side effects (DB, network) belong in connections/transports”). This is an unfired **demand-gate**, not an architectural impossibility.
>
> **Build constraints:** see above

> ✅ **BUILT (2026-07-10, [ADR 0082](adr/0082-outbound-batch-aggregation.md)).** Opt-in per-outbound `batch = { max_count, max_wait_ms }` (MLLP/HL7v2 only; rejected on a capturing/reingressing outbound). The delivery worker coalesces the lane's contiguous FIFO head-prefix — count-**or**-head-age trigger — into ONE `BHS`…`BTS` envelope (`parsing.encode_batch`, the encode-side inverse of `split_batch`) on a single send, then completes all N in **one** store transaction (`mark_batch_done` / `mark_batch_failed` / `dead_letter_batch`, atomic). **Invariants preserved:** strict per-lane FIFO (members are the oldest contiguous rows in seq order), at-least-once (every member INFLIGHT throughout → a crash recovers the whole set via `reset_stale_inflight`), and a re-run re-derives the **byte-identical** envelope (BHS-7 from the head's re-run-stable `created_at`, BHS-11 from the head member's control id — no clock). Runs **inside the pooled claim** (ADR 0066 decision #5 — no forced `per_lane`): the injected `_dispatch_delivery` routes a batching lane to the shared batch body with **zero** changes to the `StageDispatcher` state machine (the held slot spans the bounded `max_wait_ms` window). A permanent NAK dead-letters all N; a graceful stop flushes the partial. Verified on **SQLite + SQL Server** across all six ADR 0082 acceptance criteria (`tests/test_outbound_batch.py`, `test_batch_completion.py`, `test_batch_config.py`, `test_encode_batch.py`); adversarially verified (FIFO / at-least-once / determinism / atomicity).

> **On-trigger / demand-gate.** Numbered for tracking only — build when the trigger below fires (“demand-gate, don’t schedule”).

**Cluster:** Messaging / Dataflow. **Priority:** P2. **Verdict:** demand-gate. **Severity (vs Corepoint):** moderate.

**Scope:** An egress sink that accumulates multiple messages and emits them as ONE framed outbound batch (for example FHS/BHS...BTS) - the inverse of the inbound batch split.

**Trigger:** build when a partner requires N messages delivered as one framed batch (FHS/BHS…BTS) rather than one message per delivery.

**Why:** Real gap. The engine splits INBOUND batch envelopes via `split_batch` (parsing/split.py) but has no outbound sink that accumulates N messages and emits them as one BHS/BTS-framed batch — outbound delivery is strictly one-row-one-message, and the only outbound "batch" machinery is store-side SQL/claim batching (ADR 0075/0058), not HL7 envelope aggregation.

**Nearest existing mechanism:** parsing/split.py `split_batch` (the INBOUND inverse — explodes an FHS/BHS/FTS/BTS envelope into N per-message hand-offs, invoked by transports/file.py); the outbound delivery workers in transports/mllp.py and file.py send one outbox row per message with no accumulation or batch framing.

**Source:** Corepoint v8.1.0 help-export coverage sweep (2026-07-09) — five adversarially-verified passes over the full help export (1,569 pages); absence re-verified against `origin/main` before filing. Cross-ref [#52](#52-corepoint-capability-parity-gaps--prioritized-roadmap-input-2026-06-27).

---

## 135. Configurable statistics push / refresh interval

> 🔢 **Re-scored 2026-07-10 → DEMAND-GATE.** Value **2/10** · Difficulty **2/10** · _fill-in_. Marginal tuning knob over the fixed 1s /ws/stats cadence; no interop dimension, and the existing cadence already serves live monitoring fine. _(was P3 · V2/5 · D1/5)_

> **On-trigger / demand-gate.** Numbered for tracking only — build when the trigger below fires (“demand-gate, don’t schedule”).

**Cluster:** Monitoring. **Priority:** P3. **Verdict:** demand-gate. **Severity (vs Corepoint):** minor.

**Scope:** A tunable interval governing how often live connection statistics are pushed to the operator console, to cut bandwidth in very-high-volume deployments.

**Trigger:** build when console/monitor bandwidth becomes material at very high connection counts or message rates.

**Why:** Real gap. The engine's live monitor feed pushes over /ws/stats on a hardcoded ~1s cadence with no per-connection or global tuning knob, so operators cannot throttle stats push frequency to cut bandwidth in very-high-volume deployments; the nearest mechanism is the fixed asyncio.sleep(1.0) in the ws_stats loop.

**Nearest existing mechanism:** The /ws/stats WebSocket in api/app.py, whose push loop is hardcoded to a fixed ~1.0s cadence (await asyncio.sleep(1.0)) and re-auth cadence _WS_REVALIDATE_SECONDS; no config surface (settings.py has ws_allowed_origins but no stats-interval knob).

**Source:** Corepoint v8.1.0 help-export coverage sweep (2026-07-09) — five adversarially-verified passes over the full help export (1,569 pages); absence re-verified against `origin/main` before filing. Cross-ref [#52](#52-corepoint-capability-parity-gaps--prioritized-roadmap-input-2026-06-27).

---

## 136. 'Waiting for Reply' per-message connection state + display delay

> ✅ **SHIPPED — verified against `origin/main` (2026-07-28).** [ADR 0065](adr/0065-web-ops-dashboard.md) amendment (2026-07-19). The cosmetic "Waiting for Reply" side-band marker plus its pre-display delay is `messagefoundry/transports/mllp.py:634-640` — explicitly **display-only**, with the delay independent of `timeout_seconds`/pacing. `waiting_for_reply(now)` (`:731-738`) returns True only once `waiting_display_delay` has elapsed, and the flag is stamped/cleared in a `finally` around the ACK read on **both** send paths — `_send_once` (`:843-849`) and `_send_persistent` (`:930-945`).
>
> ⚠️ **MLLP-only.** The runner's probe is duck-typed, so REST/HTTP, DICOM C-STORE/C-ECHO and every other reply-waiting outbound report `False`. That matches the item's own Why (which scoped the gap to outbound MLLP's ACK wait), so it is a by-construction boundary rather than an unbuilt remainder — but extending it to other reply-waiting connectors would be **new work**. _(was 🔢 DEMAND-GATE · Value 2/10 · Difficulty 4/10.)_

**Cluster:** Monitoring. **Priority:** P3. **Verdict:** demand-gate. **Severity (vs Corepoint):** minor.

**Scope:** A per-sender delay after send before the connection is shown in a waiting-for-reply state, explicitly independent of the response-wait and pacing settings.

**Trigger:** build when operators need to distinguish “sent, awaiting reply” from “idle” on a per-message basis in the console.

**Why:** Real gap. MessageFoundry's outbound MLLP does block on the ACK under `timeout_seconds`, but exposes no per-message "Waiting for Reply" live connection state in the console/API and no cosmetic display-delay knob (independent of the response-wait/pacing settings) to govern when that state is shown.

**Nearest existing mechanism:** Outbound MLLP synchronously waits for the ACK bounded by `timeout_seconds`/`connect_timeout` (transports/mllp.py `_send_once`/`_send_persistent`), and connection health/counts surface via the API and console — but there is no per-message "waiting-for-reply" connection *display state* and no configurable pre-display delay.

**Source:** Corepoint v8.1.0 help-export coverage sweep (2026-07-09) — five adversarially-verified passes over the full help export (1,569 pages); absence re-verified against `origin/main` before filing. Cross-ref [#52](#52-corepoint-capability-parity-gaps--prioritized-roadmap-input-2026-06-27).

---

## 137. Configurable server display name in the operator console

> 🔢 **Re-scored 2026-07-10 → DEMAND-GATE.** Value **4/10** · Difficulty **2/10** · _fill-in_. Console-title polish so operators can tell multiple instances apart at a glance; purely cosmetic DX, nobody is blocked from operating. _(was P3 · V2/5 · D1/5)_

> **On-trigger / demand-gate.** Numbered for tracking only — build when the trigger below fires (“demand-gate, don’t schedule”).

**Cluster:** Monitoring. **Priority:** P3. **Verdict:** demand-gate. **Severity (vs Corepoint):** minor.

**Scope:** Render the server/instance name in the console title as the hostname, the IP address, or a custom label.

**Trigger:** build when an operator runs several engine instances and needs to tell their consoles apart at a glance.

**Why:** Real gap. The operator console window title is hardcoded to "MessageFoundry Console" (console/shell.py setWindowTitle) with no configurable server display name to show a hostname, IP, or custom label; the closest existing identifiers, the free-form `[ai].environment` name and `[cluster].node_id`, are engine-side and never rendered in the console title.

**Nearest existing mechanism:** The console's hardcoded window title `setWindowTitle("MessageFoundry Console")` in messagefoundry/console/shell.py; adjacent identity settings exist but are not surfaced in the title — the free-form `[ai].environment` name (config/settings.py, EnvironmentsSettings/AiSettings) and `[cluster].node_id` (host:pid identity).

**Source:** Corepoint v8.1.0 help-export coverage sweep (2026-07-09) — five adversarially-verified passes over the full help export (1,569 pages); absence re-verified against `origin/main` before filing. Cross-ref [#52](#52-corepoint-capability-parity-gaps--prioritized-roadmap-input-2026-06-27).

---

## 138. Customisable alert-email subject and body templates

> ✅ **SHIPPED — verified against `origin/main` (2026-07-28).** [ADR 0127](adr/0127-operator-editable-alert-email-templates-with-a-non-phi-variable-allowlist.md). `_ALERT_TEMPLATE_VARS` (`messagefoundry/config/settings.py:2474-2490`) is a **closed, non-PHI variable allowlist** — severity / type / connection / timestamp / depth / oldest_age_seconds / cooldown_seconds / rule_id — a name-for-name match with the item's own Build-constraints list. `validate_alert_template` (`:2493-2521`) parses with `string.Formatter().parse` and **never** `str.format`, rejecting unknown names, attribute/index access and conversions.
>
> ⚠️ **The Scope's phrase "alert *and message* variables" is deliberately NOT delivered** — no message-derived variable is admitted. That is **required** by the item's own Build-constraints and PHI caveat ("NEVER raw message body or arbitrary HL7 fields … or be declined") and is recorded as safe-by-design in ADR 0127. It is a **satisfied constraint, not an outstanding half** — do not re-open it as a gap. _(was 🔢 DEMAND-GATE · Value 4/10 · Difficulty 3/10.)_

**Cluster:** Alerting. **Priority:** P3. **Verdict:** demand-gate — **PHI review required**. **Severity (vs Corepoint):** minor.

**Scope:** An operator-editable alert-email subject and body (plain text or HTML) that interpolates alert and message variables into the notification.

**Trigger:** build when operators require alert emails carrying context beyond the fixed metadata set. **PHI review required** — see below.

**Why:** Real gap. Alert-email content is fixed by the internal `_subject()`/`_body()` helpers in alert_sinks.py (plain-text only, no interpolation knobs); operators can customize alert severity/routing/cooldown via `[alerts].rules` but cannot edit the notification subject or body or emit HTML.

**PHI caveat:** MessageFoundry alert emails are deliberately fixed, **PHI-free metadata**. A template that interpolates message fields would carry PHI into e-mail, which CLAUDE.md §9 / [`PHI.md`](PHI.md) forbid at INFO+ and off-box. Any build must gate interpolation to non-PHI variables, or be declined.

**Nearest existing mechanism:** The hardcoded `_subject()` and `_body()` helpers in messagefoundry/pipeline/alert_sinks.py (fixed "[MessageFoundry] SEVERITY type — connection" subject + a key:value dump body), plus `AlertRuleSet`/`AlertRule` in config/settings.py which lets operators tune severity, transport routing, and cooldown per event — but not the email subject or body text.

**Source:** Corepoint v8.1.0 help-export coverage sweep (2026-07-09) — five adversarially-verified passes over the full help export (1,569 pages); absence re-verified against `origin/main` before filing. Cross-ref [#52](#52-corepoint-capability-parity-gaps--prioritized-roadmap-input-2026-06-27).

---

## 139. 'Always accept the mail server's TLS certificate' on the alert SMTP sink

> ⛔ **DECLINED (2026-07-09) — decline-by-default.** Unconditionally trusting an SMTP server's TLS certificate defeats TLS. Recorded for Corepoint parity completeness, not as a want; build only if a partner mandates an unverifiable mail server, and prefer fixing the trust chain.

> **On-trigger / demand-gate.** Numbered for tracking only — build when the trigger below fires (“demand-gate, don’t schedule”).

**Cluster:** Alerting. **Priority:** P3. **Verdict:** **decline-by-default** (anti-feature). **Severity (vs Corepoint):** minor.

**Scope:** A per-mail-server option to unconditionally trust the SMTP server's TLS certificate when sending alert email.

**Trigger:** build when a partner mandates an SMTP server whose TLS certificate cannot be validated. **Prefer fixing the trust chain.**

**Why:** Real gap. The alert SMTP sink (EmailTransport in pipeline/alert_sinks.py) calls starttls() with the default SSL context and exposes only email_use_tls plus the global MEFOR_ALLOW_INSECURE_TLS cleartext escape, so there is no per-mail-server option to keep TLS on yet unconditionally trust a self-signed/mismatched certificate.

**Why it is an anti-feature:** unconditionally trusting an SMTP server's certificate defeats TLS. The only escape (`MEFOR_ALLOW_INSECURE_TLS`) is global and deliberately loud. Recorded for parity completeness, not as a want.

> ⚠️ **CORRECTED 2026-08-01 — this item previously asserted "The engine's `EmailAlertSink` uses STARTTLS with a verifying context by design." That was FALSE**, and it is the shape [`CLAUDE.md`](../CLAUDE.md) §11 names as worst: *a compensating control resting on a false premise*. `smtplib.starttls()` with no context falls back to `ssl._create_stdlib_context`, which **is** `ssl._create_unverified_context` (`CERT_NONE`, `check_hostname=False`) — so the alert sink was encrypting without authenticating, and a reader of this item would have concluded alert email was TLS-verified when it was not. #323 fixed the two **connectors** (`EmailDestination` / `DirectDestination`); it did **not** fix the alert sink, so the **Why:** paragraph above remains accurate and this item's premise stays false until #323's alerts-cell residual lands. Do not re-assert verification here before then.

**Nearest existing mechanism:** EmailTransport / send_plain_email in pipeline/alert_sinks.py (SMTP alert sink, built by notifier_from_settings from AlertsSettings in config/settings.py); its only TLS knob is email_use_tls (STARTTLS on/off) plus the global MEFOR_ALLOW_INSECURE_TLS / insecure_tls_allowed() escape, which permits CLEARTEXT SMTP — not a keep-TLS-but-trust-any-cert override.

**Source:** Corepoint v8.1.0 help-export coverage sweep (2026-07-09) — five adversarially-verified passes over the full help export (1,569 pages); absence re-verified against `origin/main` before filing. Cross-ref [#52](#52-corepoint-capability-parity-gaps--prioritized-roadmap-input-2026-06-27).

---

## 140. Legacy-encryption warnings + one-click re-encrypt of configuration objects

> 🪦 **RETIRED (2026-07-09) — structurally N/A.** MessageFoundry has no encrypted configuration-object repository to warn about: config is plaintext Python in git, secrets come from the environment (`MEFOR_*`), and store secrets use versioned `mfenc` under uniform AES-256-GCM. Kept as a landing row for the Corepoint parity matrix.

> **On-trigger / demand-gate.** Numbered for tracking only — build when the trigger below fires (“demand-gate, don’t schedule”).

**Cluster:** Security. **Priority:** P3. **Verdict:** **likely N/A** (structural). **Severity (vs Corepoint):** minor.

**Scope:** A warnings view listing configuration objects still stored under a deprecated encryption scheme, with a right-click action to re-encrypt them to the current scheme.

**Trigger:** build when — (structural; see Why). Numbered for traceability against the Corepoint parity matrix only.

**Why:** Real gap. MessageFoundry encrypts only the message store (PHI-at-rest) and re-encrypts it via the offline `rotate-key` CLI with mfenc:v1/v2 crypto-agility; it has no encrypted configuration objects, no warnings view listing objects under a deprecated encryption scheme, and no one-click/right-click re-encrypt action.

**Why it is structural:** MessageFoundry has **no encrypted configuration-object repository** to warn about — config is plaintext Python in git, connection secrets come from the environment (`MEFOR_*`), and store-level secrets use versioned `mfenc` (v1/v2) under uniform AES-256-GCM with key rotation. There is no “legacy-encrypted object” concept. Numbered so the Corepoint parity matrix has a landing row.

**Nearest existing mechanism:** The message-store at-rest cipher: `store/crypto.py` mfenc:v1/v2 crypto-agility + keyring, the offline `messagefoundry rotate-key` CLI (re-encrypts store values under the active key), and `GET /security/posture` (`cipher_info` → encrypts on/off + active key fingerprint).

**Source:** Corepoint v8.1.0 help-export coverage sweep (2026-07-09) — five adversarially-verified passes over the full help export (1,569 pages); absence re-verified against `origin/main` before filing. Cross-ref [#52](#52-corepoint-capability-parity-gaps--prioritized-roadmap-input-2026-06-27).

---

## 141. TCP connection role selectable independently of direction (act-as-server vs act-as-client)

> 🔢 **Re-scored 2026-07-10 → DEMAND-GATE.** Value **6/10** · Difficulty **5/10** · _quick win_. Firewall role-inversion gap; no knob, but an external TCP relay (socat/stunnel) inverts direction — awkward-yet-real workaround → 6. _(was DEMAND-GATE · V3/5 · D3/5)_

> **On-trigger / demand-gate.** Numbered for tracking only — build when the trigger below fires (“demand-gate, don’t schedule”).

**Cluster:** Connections & Transports. **Priority:** P2. **Verdict:** demand-gate. **Severity (vs Corepoint):** moderate.

**Scope:** A TCP connection may listen or dial out regardless of whether it sends or receives, so the role can be inverted to match a partner's firewall posture.

**Trigger:** build when a partner's firewall posture requires the engine to dial out and then receive, or to listen and then send.

**Why:** Real gap. TCP/MLLP socket role is hard-bound to message direction — an inbound connection always listens (start_server) and an outbound always dials (open_connection); there is no per-connection setting to invert the role (dial-out inbound or listening outbound) to match a partner's firewall posture, the way Corepoint allows.

**Nearest existing mechanism:** Socket role is fixed by direction in transports/: TcpSource/MLLPSource always asyncio.start_server (listen), TcpDestination/MLLPDestination always asyncio.open_connection (dial). Adjacent settings bind_host/source_ip_allowlist (inbound) and host/port (outbound) tune the endpoint but never invert the role. No decoupling knob exists.

**Source:** Corepoint v8.1.0 help-export coverage sweep (2026-07-09) — five adversarially-verified passes over the full help export (1,569 pages); absence re-verified against `origin/main` before filing. Cross-ref [#52](#52-corepoint-capability-parity-gaps--prioritized-roadmap-input-2026-06-27).

---

## 142. 'Leave source file' - process-in-place file/FTP source disposition

> ✅ **SHIPPED — verified against `origin/main` (2026-07-28).** [ADR 0129](adr/0129-process-in-place-file-disposition-and-cross-backend-processed-file-dedup-ledger.md). `after_read='leave'` is a validated third disposition on the file source (`messagefoundry/transports/file.py:298-302`) and is honoured where the disposition is applied — `_after_processing` returns without moving or deleting the source (`:762-765`). It correctly relaxes the two write preconditions a read-only share cannot satisfy: the poll-directory write check (`:400`) and best-effort `.processed`/`.error` subdir creation (`:355`). The re-poll dedup it needs is the cross-backend ledger the banner said was missing: the `ProcessedFileLedger` protocol at `messagefoundry/transports/base.py:65` over a `processed_files` table (`:250`) implemented on **all three** store backends. _(was 🔢 DEMAND-GATE · Value 6/10 · Difficulty 6/10.)_

**Cluster:** Connections & Transports. **Priority:** P2. **Verdict:** demand-gate. **Severity (vs Corepoint):** moderate.

**Scope:** A File/FTP receiver processes a file in place, neither moving nor deleting it, for read-only shares or directories another system owns.

**Trigger:** build when an inbound feed lands on a read-only share, or on a directory whose files another system owns.

**Why:** Real gap. Both the local and SFTP/FTP(S) file sources always consume a read file via `after_read` ("move" to .processed, or "delete") with no leave-in-place option, and adding one requires a processed-file ledger (name+mtime/hash dedup) the poller lacks, so a read-only share whose files another system owns cannot be polled without moving or deleting them.

**Nearest existing mechanism:** FileSource / RemoteFileSource `after_read` setting (transports/file.py, transports/remotefile.py), which offers only "move" (→ .processed) or "delete".

**Source:** Corepoint v8.1.0 help-export coverage sweep (2026-07-09) — five adversarially-verified passes over the full help export (1,569 pages); absence re-verified against `origin/main` before filing. Cross-ref [#52](#52-corepoint-capability-parity-gaps--prioritized-roadmap-input-2026-06-27).

---

## Corepoint gap-analysis coverage audit — items #143–#184 (2026-07-09)

> ✅ **Closes the loop: every gap in the analysis now has a disposition.** `marketing/corepoint-gap-analysis.md` (2026-06-27) was triaged capability-by-capability against **current `origin/main`** and this backlog. Of **246** capabilities:
>
> | Disposition | Count |
> |---|---:|
> | **Already shipped** since the analysis was written | **55** |
> | **Already tracked** by an open numbered item | **77** |
> | **Declined by design** (not gaps) | **50** |
> | Not a real capability gap | **7** |
> | **Open + untracked → filed below as #143–#184** | **55 → 42 distinct** |
>
> **The analysis is ~22% obsolete** — a fifth of it describes work that is done. Status of its three **MAJOR** gaps: inbound REST/SOAP/FHIR listener is **partially closed** (the generic HTTP body-POST source shipped, ADR 0023 first slice in 0.2.10; typed REST-IN/SOAP-IN/FHIR-IN remain deferred — **#7** stays open); operator alert *state* is **closed** (**#56**, ADR 0044); turnkey DR is **closed** — BOTH halves shipped: standby **#61** (ADR 0048) and config-tier backup/restore-verify **#60** (ADR 0049). ⚠️ **Correction (2026-07-09):** an earlier revision of this anchor claimed #60 was still open, because #60's own banner was never updated when the work landed. All three of the analysis's MAJOR rows are now closed except the typed REST-IN/SOAP-IN/FHIR-IN sources (**#7**).
>
> **No new MAJOR gap.** These 42 are **12 moderate · 30 minor**. Severity follows the analysis's own rating wherever it rated the row — an automated pass tried to promote Direct/HIE to *major* and was overruled back to the analysis's *minor* (see **#157**). 11 severity disagreements were reconciled this way.
>
> Distinct from **#107–#142**, which are the *newly discovered* gaps from the v8.1.0 help-export sweep. Together the two batches make the Corepoint parity surface fully tracked.

---

## 143. Alert suspend / mute (windowed)

> ✅ **SHIPPED — verified against `origin/main` (2026-07-28).** [ADR 0044](adr/0044-operator-alert-state.md) amendment. The windowed mute is built as a deliberately **notification-only** gate (`messagefoundry/pipeline/alert_sinks.py:842`, cache at `:598`) — a suspended alert stays open, counted and visible, so muting never hides a live condition. Driven by `POST /alerts/{alert_id}/suspend` (`messagefoundry/api/app.py:2372`, returning the updated `AlertInstanceInfo`; surfaced at `:2300`), with the window persisted **durably** as `suspended_until` on all three store backends (`messagefoundry/store/store.py:603`, column `:1444`, migrated at `:3038`; plus `store/postgres.py` and `store/sqlserver.py`) — so it survives a restart rather than living in the notifier's memory. _(was 🔢 DEMAND-GATE · Value 6/10 · Difficulty 4/10.)_

**Cluster:** Alerting. **Priority:** P3. **Verdict:** demand-gate. **Severity (vs Corepoint):** moderate.

**Scope:** An operator-invoked, time-windowed suspend/resume (mute) of an alert instance or rule that silences re-alerts for a chosen window while the connection keeps running and queuing, persisted alongside the #56 alert-instance state and exposed as POST /alerts/{id}/suspend (+ per-rule mute).

**Trigger:** build when operators need to silence alert-storms during planned downstream maintenance without stopping the connection or editing+reloading config.

**Why:** Real gap. The nearest mechanism is the static per-rule transports:[] suppression (a config edit + reload) plus the re-alert cooldown; #56 shipped ack/resolve state only, and #81's remainder covers escalation/schedule/content, not suspend.

**Source:** BACKLOG coverage audit of the 2026-06-27 Corepoint gap analysis against `origin/main` (2026-07-09) — 246 capabilities triaged; this one verified **open and untracked**. Cross-ref [#52](#52-corepoint-capability-parity-gaps--prioritized-roadmap-input-2026-06-27).

---

## 144. Alert-triggered connection-control action

> ✅ **SHIPPED — verified against `origin/main` (2026-07-28).** [ADR 0128](adr/0128-alert-rule-connection-control-action-auto-stop-restart-on-fire.md). An alert rule may now carry a control action from a closed, validated vocabulary — `_ALERT_CONTROL_ACTIONS = frozenset({"restart_inbound", "restart_outbound"})` (`messagefoundry/config/settings.py:2472`, rejected at `:2666` if the rule names anything else) — dispatched **off-worker and never-raising**, and deliberately **before** the transport-suppression return, so a rule can auto-remediate *quietly* (`transports=[]`) or alongside a page (`messagefoundry/pipeline/alert_sinks.py:945-947`). ⚠️ **Half the item's title is deliberately NOT built:** a bare `stop` (and a bare `start`) is **declined by design** — the whitelist is exactly the two *warm-restart* primitives, because "a bare stop with no re-arm is an easy way to silently wedge a feed" (`0128:31-32`). Auto-*stop* is closed as declined, not pending. ⚠️ **The banner's *"notify-only"* characterisation is FALSE against `origin/main` and is retracted here.** _(was 🔢 DEMAND-GATE · Value 6/10 · Difficulty 3/10.)_

**Cluster:** Alerting. **Priority:** P3. **Verdict:** demand-gate. **Severity (vs Corepoint):** moderate.

**Scope:** An action outcome on an AlertRule that automatically stops or restarts the affected named connection when the rule fires, beyond today's notify-only outcomes.

**Trigger:** build when an adopter needs an alert (queue_buildup / connection_stopped) to auto-restart or stop a connection rather than only notify an operator.

**Why:** Partial. AlertRule outcomes are notify-only and connection control is manual via POST /connections/{name}/start|stop|restart; ADR 0070's infra_fault STOP and #109's credential auto-stop are fault-driven, never alert-rule-driven and never restart.

**Merged from 2 analysis entries** describing the same capability.

**Source:** BACKLOG coverage audit of the 2026-06-27 Corepoint gap analysis against `origin/main` (2026-07-09) — 246 capabilities triaged; this one verified **open and untracked**. Cross-ref [#52](#52-corepoint-capability-parity-gaps--prioritized-roadmap-input-2026-06-27).

---

## 145. HA / DR failover event alert

> ✅ **SHIPPED — verified against `origin/main` (2026-07-28).** [ADR 0014](adr/0014-alerting-rules-engine.md) amendment. Both transition edges are first-class alert events, not log lines: `leadership_acquired` / `leadership_lost` (`messagefoundry/pipeline/alert_sinks.py:800`, with `leadership_lost` registered as the **auto-resolving inverse** of `leadership_acquired` at `:101-103`, so a step-down/clean-release/self-fence closes the open alert instead of leaving it stuck), and `dr_activated` / `dr_released` emitted by the `DrCoordinator` at its real fire sites — `messagefoundry/pipeline/dr.py:281` (on promotion) and `:341` (on fail-back), through the `_alert_dr` helper at `:645`; the fail-back auto-resolves the open instance and deliberately pages nobody (`:340`). *(The same names on `messagefoundry/pipeline/alerts.py:215`/`:223` are the `AlertSink` **Protocol** stubs — the contract, not the emit sites.)* Payloads carry node / role / epoch only: cluster-topology facts, **no PHI**. ⚠️ **The banner's *"only log at INFO"* premise is FALSE against `origin/main` and is retracted here.** _(was 🔢 DEMAND-GATE · Value 6/10 · Difficulty 3/10.)_

**Cluster:** Alerting. **Priority:** P3. **Verdict:** demand-gate. **Severity (vs Corepoint):** moderate.

**Scope:** A new AlertSink event (plus AlertRule event_type and emit sites) fired on HA leadership change/failover in the cluster coordinators and on DR activate/release, routed through the existing notifier/rules path.

**Trigger:** build when an operator needs a proactive page on a failover / DR transition instead of polling GET /cluster/status and /dr/status.

**Why:** Real gap. The ADR 0014 AlertSink routes operator alerts but carries no cluster/HA/DR event, and shipped active-passive leadership transitions and DR activate/release only log at INFO, never reaching the notifier.

**Merged from 2 analysis entries** describing the same capability.

**Source:** BACKLOG coverage audit of the 2026-06-27 Corepoint gap analysis against `origin/main` (2026-07-09) — 246 capabilities triaged; this one verified **open and untracked**. Cross-ref [#52](#52-corepoint-capability-parity-gaps--prioritized-roadmap-input-2026-06-27).

---

## 146. Per-rule alert recipients

> ✅ **SHIPPED — verified against `origin/main` (2026-07-28).** [ADR 0014](adr/0014-alerting-rules-engine.md) amendment (2026-07-17). `recipients: list[str] | None = None` on `AlertRule` (`messagefoundry/config/settings.py:2586-2593`): `None` keeps the global `[alerts].email_to`; a non-empty list re-targets the email transport for events that rule matches (the Corepoint-parity routing the item asked for). It is an **internal routing key popped before any webhook payload**, and `_check_recipients` (`:2644-2660`) rejects empty/all-blank lists **fail-closed**.
>
> ⚠️ **Email-only by design:** a rule that sets `recipients` while routing solely to a webhook silently no-ops (a webhook has no recipient concept) — ADR 0014's amendment states this explicitly. ⚠️ **Configured addresses are never readable back through the API:** `GET /alerts/rules` reports only an integer `recipient_count`, for secret-guard parity — so the console cannot display who is targeted. _(was 🔢 DEMAND-GATE · Value 5/10 · Difficulty 2/10.)_

**Cluster:** Alerting. **Priority:** P3. **Verdict:** demand-gate. **Severity (vs Corepoint):** moderate.

**Scope:** A per-rule recipients override on AlertRule so a matching event's email goes to that rule's address list instead of the single global AlertsSettings.email_to, letting different events/connections notify different teams.

**Trigger:** build when operators need different alert events or connections to notify different recipient groups (e.g. IB stop → integrations, storage_threshold → ops).

**Why:** Partial. The ADR 0014 AlertRule engine routes severity, transport-kind, and cooldown per event, but the outcome side has no recipient dimension — email always goes to the global email_to list.

**Source:** BACKLOG coverage audit of the 2026-06-27 Corepoint gap analysis against `origin/main` (2026-07-09) — 246 capabilities triaged; this one verified **open and untracked**. Cross-ref [#52](#52-corepoint-capability-parity-gaps--prioritized-roadmap-input-2026-06-27).

---

## 147. Per-connection active-window scheduler

> ✅ **SHIPPED — verified against `origin/main` (2026-07-28).** [ADR 0095](adr/0095-connection-lifecycle-scheduler-and-credential-fault-stop.md). `ActiveWindow` (`messagefoundry/config/models.py:278-346`, docstring citing BACKLOG #147) is a declarative `datetime.weekday()` day-set + local start/end + IANA timezone: same-day `[start,end)`, past-midnight wrap anchored on the start weekday, `start == end` rejected as ambiguous. `Schedule` (`:349-374`) adds an `invert` flag selecting availability vs **maintenance** windows, with `is_active(now_utc)` at `:369-374`; `schedule=None` is always-on and byte-identical (no task spawned). The runner reconciles up/down state through the **same** `start_inbound`/`stop_inbound` the API uses, so a park is a clean stop.
>
> ⚠️ **The ledger was self-contradictory here:** the ranked-table row already read ✅ SHIPPED while this banner still said demand-gate — the table was right. ⚠️ **Genuine remainder, verified by grep:** `_start_schedulers` is called **only** from `start()` (`pipeline/wiring_runner.py:2274`) and **not** from the config-reload path — so a schedule added or edited by `/config/reload` does not take effect until the engine restarts. Worth a small follow-up item; it does not keep #147 open. _(was 🔢 DEMAND-GATE · Value 6/10 · Difficulty 4/10.)_

**Cluster:** Connections & Transports. **Priority:** P3. **Verdict:** demand-gate. **Severity (vs Corepoint):** moderate.

**Scope:** A per-connection time-of-day/day-of-week active/maintenance-window calendar the RegistryRunner honors to auto-start and auto-stop that connection on schedule, distinct from #115's boot-time on/off boolean.

**Trigger:** build when an adopter needs a partner connection to auto-enable only during defined hours or auto-park during a recurring maintenance window.

**Why:** Real gap. #115's persisted auto-start boolean is boot-time only, the TIMER source emits a body but never gates a connection's up/down state, and DR priority-parking parks by run-profile not by clock — none is a run-window calendar.

**Merged from 3 analysis entries** describing the same capability.

**Source:** BACKLOG coverage audit of the 2026-06-27 Corepoint gap analysis against `origin/main` (2026-07-09) — 246 capabilities triaged; this one verified **open and untracked**. Cross-ref [#52](#52-corepoint-capability-parity-gaps--prioritized-roadmap-input-2026-06-27).

---

## 148. X12 TA1 interchange-acknowledgement generation

> 🔢 **Re-scored 2026-07-10 → DEMAND-GATE.** Value **3/10** · Difficulty **2/10** · _fill-in_. Niche X12 knob most partners never need — 997/999 already covers the common ack free — and a code-first Handler can emit TA1 on the existing codec. _(was DEMAND-GATE · V3/5 · D2/5)_

> **On-trigger / demand-gate.** Numbered for tracking only — build when the trigger below fires (“demand-gate, don’t schedule”).

**Cluster:** HL7 / Messaging. **Priority:** P3. **Verdict:** demand-gate. **Severity (vs Corepoint):** moderate.

**Scope:** Validate an inbound ISA/IEA envelope (control-number match, segment-count/integrity) and emit a TA1 interchange acknowledgement with the appropriate A/E/R code plus note code, callable on demand from a Handler against a RawMessage.

**Trigger:** build when an X12 trading-partner contract mandates a TA1 interchange-level structural accept/reject acknowledgement.

**Why:** Partial. parsing/x12/validate.py yields free 997/999 functional acks from the pyx12 walk, but no TA1 interchange ack is generated anywhere — the outbound path only classifies a partner's inbound TA1 (ADR 0016).

**Source:** BACKLOG coverage audit of the 2026-06-27 Corepoint gap analysis against `origin/main` (2026-07-09) — 246 capabilities triaged; this one verified **open and untracked**. Cross-ref [#52](#52-corepoint-capability-parity-gaps--prioritized-roadmap-input-2026-06-27).

---

## 149. Streaming path for very-large single messages

> 🛠 **Decline overturned (2026-07-09).** A prioritization pass recommended DECLINE; the stated reason was **invalid**. Purity binds `@router` / `@handler` — **not connectors** (CLAUDE.md §8: “side effects (DB, network) belong in connections/transports”). This is an unfired **demand-gate**, not an architectural impossibility.
>
> **Build constraints:** 1) The full body must still be durably committed to the store (streamed to a store-backed/chunked BLOB) BEFORE the ACK, preserving ACK-on-receipt and count-and-log — the ACK simply waits until the stream is fully persisted; nothing accepted-and-dropped. 2) The stored body is the canonical re-run input so each stage handoff (ingress->routed->outbound) re-derives identically, keeping at-least-once safe. 3) Strict hl7apy validation stays whole-body/synchronous, so the streaming path targets content-types where…

> ✅ **COMPLETE — Phase 0 substrate + Phase 1a ingress detach + Phase 1b delivery re-attach + Phase 3a retention decref + Phase 4 SS+PG parity + Phase 3b operator read/download surface ALL shipped (Phase 3b 2026-07-13, [ADR 0105](adr/0105-streaming-very-large-hl7-attachments-detach-the-opaque-document-from-the-transformable-skeleton.md)). Streaming very-large HL7 attachments works on ALL THREE store backends WITH the operator read surface — go-live parity met (the production store is SQL Server).** Streaming a single very-large HL7 message (a base64 PDF in `OBX-5.5` past the 16 MiB cap) into Epic by **detaching the opaque document from the transformable skeleton**. **Phase 0** = the content-addressed, chunked, per-chunk-`mfenc`-sealed **attachment substrate** (`attachment`/`attachment_chunk` tables + `put_attachment`/`read_attachment`/`attachment_incref`/`attachment_decref`/`sweep_orphan_attachments`, generalizing the `shared_body` refcount+GC; startup orphan/incomplete sweep so no PHI chunk is left at rest; key-rotation re-seals chunks; `supports_streaming_attachments` capability flag — SQLite True, SS/PG raise) + the `mfdoc:v1:ref:` live document-handle helpers in `parsing/binary.py`. **Phase 1a** = the **ingress wiring**: a per-inbound `stream_threshold_bytes` opt-in detaches each oversized OBX-5 ED document **verbatim** into the substrate before the ingress commit (`iter_obx_documents`/`chunk_b64` + the parsed-model replace), replaces it with a `mfdoc:v1:ref:` handle, and `enqueue_ingress` increfs the attachment **in the same transaction** as the skeleton row (the two-object commit) so the ACK fires only after the document is durable; a header NAK still fires synchronously before any commit; strict validation downgrades to header-only over threshold; the per-connection `max_message_bytes` OOM guard + the aggregate `[inbound].stream_inflight_budget_bytes` DoS budget replace the frame-cap-as-only-guard; below-/no-threshold is byte-identical. **Owner rulings:** inline MLLP MDM delivery (no FHIR-Binary), pure pass-through (doc-mutating transforms a non-goal), store the `OBX-5.5` value **verbatim** (Approach B), 3-backend parity before go-live. **SQLite-only.** **Phase 1b** = the **delivery wiring** completing the round-trip: the pure `reattach_documents_in_hl7(text, reader)` (injected async reader) splices the stored **verbatim** base64 back into `OBX-5.5` byte-for-byte at the terminal egress, hydrated by `RegistryRunner._hydrate_payload` before `connector.send` on both the single-item and batch paths; a no-handle payload short-circuits to a byte-identical passthrough (single substring check, no store read), and hydration is **fail-loud** (a missing/GC'd attachment → retryable `DeliveryError`, so the connector **never** receives a raw `mfdoc:v1:ref:` handle = no silent corruption) and a **pure read** (never decref → retry-idempotent + fan-out-safe). The outbound MLLP send is **uncapped** so the large hydrated MDM (shape A) and a Handler-built large MDM (shape B) stream inline; `max_frame_bytes` bounds only the ACK read. Worked end-to-end samples: `samples/config/IB_STREAM_MDM.py` (detach→hydrate round-trip) + `samples/config/IB_PDF_TO_MDM.py` (PDF→base64→MDM). **Phase 3a** = the **message→attachment linkage + retention decref** (SQLite): a `message_attachment(message_id, attachment_id)` join table persists which attachments a message holds (inserted **atomically with the ingress incref** in `enqueue_ingress`), and `purge_message_bodies` **decrefs each referenced attachment + deletes its join rows in the body-purge transaction** — ordered so a crash-re-run is a no-op (a re-run finds the join rows gone → no double-decref, no refcount underflow, no premature GC of a **shared** attachment a sibling message still references). Delivery stays a pure read (fan-out decrefs **once** at purge, never per-delivery); below-/no-attachment retention is byte-identical. This **closes the over-retention gap** — a purged-but-referenced document is now reclaimed at its last referrer instead of over-retaining PHI at rest. **Phase 4** = **SQL Server + Postgres substrate parity** (the go-live gate — the production store is SQL Server): the whole Phase-0→3a substrate (the `attachment`/`attachment_chunk`/`message_attachment` schema, `put_attachment`/`read_attachment`/`attachment_incref`/`attachment_decref`/`sweep_orphan_attachments`, the ingress two-object commit, the retention decref + dead-row split across `purge_message_bodies`/`purge_dead_letters`, and the key-rotation re-seal) is implemented on both server backends at **byte-for-byte behavioral parity** with the SQLite reference — dialect (SS `NVARCHAR(MAX)`/`CASE`-clamp vs PG `TEXT`/`GREATEST`, `?` vs `$N` placeholders) and each backend's transaction model adapted only, the SQLite implementation itself untouched — with `supports_streaming_attachments` flipped **True** so the startup orphan sweep + ingress detach now run on all three, and SS/PG parity tests (`test_sqlserver_store.py`/`test_postgres_store.py`) on the CI legs covering the same round-trip/dedup/refcount/ingress-rollback/purge-idempotence/dead-row-split/fan-out/seal/reseal assertions as the SQLite suite. **Streaming now works identically on SQLite + SQL Server + Postgres — go-live parity met.** **Phase 3b** = the **operator read/download surface**: a store `attachments_for(message_id)` read method (metadata-only `message_attachment` JOIN `attachment`, all three backends), an additive `MessageDetail.attachments` list (`id`/`content_type`/`total_bytes`, populated by `get_message`), and an audited, `MESSAGES_VIEW_RAW`-gated `GET /messages/{id}/attachments/{attachment_id}` download that reconstructs the verbatim base64 and **base64-decodes once** to the original document bytes (byte-for-byte round-trip) — behind the SAME channel-scope **404-not-403** guard as `get_message` **plus** a `(message_id, attachment_id)` **linkage existence** check (content-addressing shares one blob across messages/tenants, so the linkage is what scopes access — a guessed content address unlinked to an in-scope message is a 404), a **validated** `Content-Type` (attacker-influenced OBX-5.2 label defaulted to `application/octet-stream` — no header injection), and a `record_view` + tamper-evident `attachment_download` audit **before the bytes leave** (bytes/base64 never logged). The **web console** message-detail view renders an Attachments panel (content type + human size + a Download link to a `/ui` route that reuses the engine's audited handler in-process — a browser GET carries the session cookie, not the bearer). Reuses `MESSAGES_VIEW_RAW` (a detached document is the same PHI as the raw body — no new permission); API + web console only (the PySide6 desktop console is deprecated — no new surface). Seam bumped to v4. **#149 COMPLETE** (streaming very-large HL7 attachments — all three backends + operator read surface).

> **On-trigger / demand-gate.** Numbered for tracking only — build when the trigger below fires (“demand-gate, don’t schedule”).

**Cluster:** Messaging / Dataflow. **Priority:** P3. **Verdict:** demand-gate. **Severity (vs Corepoint):** moderate.

**Scope:** A chunked/streamed ingress→store→delivery path that carries one very-large message body through parse→route→transform→deliver without full in-memory materialization, lifting the 16 MiB frame cap for such messages.

**Trigger:** build when an adopter must process single messages larger than the frame cap (very-large embedded documents or X12 interchanges) that #94 offload cannot handle.

**Why:** Partial. parsing/split.py splits batches into per-message rows and #94 offloads embedded OBX-5 docs to a BLOB store, but every single body is still buffered whole into memory (FrameDecoder) and capped at the MLLP frame limit.

**Merged from 2 analysis entries** describing the same capability.

**Source:** BACKLOG coverage audit of the 2026-06-27 Corepoint gap analysis against `origin/main` (2026-07-09) — 246 capabilities triaged; this one verified **open and untracked**. Cross-ref [#52](#52-corepoint-capability-parity-gaps--prioritized-roadmap-input-2026-06-27).

---

## 150. User-writable per-message metadata bag

> ✅ **BUILT (2026-07-10, [ADR 0081](adr/0081-per-message-metadata-bag.md)).** A Handler returns `SetMeta(key, value)` (a declarative op alongside `Send`/`SetState`, ADR 0005 template); it is merged under the row's `metadata.user` sub-key **inside** the exactly-once `transform_handoff` transaction — no separate write, idempotent on a crash re-run, and it never clobbers the ADR 0013 correlation lineage sharing the `messages.metadata` column. Values are `str`, capped ≤32 keys / ≤4 KiB per message (over-cap dead-letters). The bag surfaces **read-only** and PHI-redacted on `MessageSummary.metadata` (internal lineage keys stripped — this also closed a pre-existing lineage-leak on that field); there is no write route. Merge is verified byte-for-byte on **all three store backends** (SQLite, SQL Server incl. the fused B5 sync path, Postgres) — `tests/test_metadata_bag.py` + `tests/test_sqlserver_sync_handoff.py::test_transform_handoff_sync_merges_setmeta`. All five ADR 0081 acceptance criteria met. _Follow-up (not in the ratified spec): server-side search-by-metadata-key filtering + console Log-Search columns._

> **On-trigger / demand-gate.** Numbered for tracking only — build when the trigger below fires (“demand-gate, don’t schedule”).

**Cluster:** Messaging / Dataflow. **Priority:** P2. **Verdict:** demand-gate. **Severity (vs Corepoint):** moderate.

**Scope:** A transform-writable per-message key/value bag a Router/Handler declares (e.g. a SetMeta return applied exactly-once in the routed→outbound handoff, mirroring ADR 0005 SetState) that persists in the existing messages.metadata column and surfaces as searchable Log Search columns/filters and in message detail.

**Trigger:** build when a Corepoint/Mirth migration needs channelMap/userdata-style values attached to a message for later pipeline steps, search, or operator inspection.

**Why:** Partial. The messages.metadata column exists but is written only by system correlation and the inject path; ADR 0005 SetState/state_get is cross-message correlation KV, not a per-message bag on Message/Send surfaced as searchable columns.

**Merged from 3 analysis entries** describing the same capability.

**Source:** BACKLOG coverage audit of the 2026-06-27 Corepoint gap analysis against `origin/main` (2026-07-09) — 246 capabilities triaged; this one verified **open and untracked**. Cross-ref [#52](#52-corepoint-capability-parity-gaps--prioritized-roadmap-input-2026-06-27).

---

## 151. Saved / layered Log-Search filter presets

> ✅ **SHIPPED — verified against `origin/main` (2026-07-28).** [ADR 0136](adr/0136-per-user-saved-and-layered-log-search-filter-presets-extends-the-adr-0046-search-seam.md). Saved presets: `GET /search/presets` (`messagefoundry/api/app.py:3917`), `POST /search/presets` (`:3945`, step-up, create-or-replace). Layering is `_compose_preset_layers` (`:782-830`), AND-composing up to `_MAX_PRESET_LAYERS = 8` (`:314-316`).
>
> ⚠️ **Layering is a bounded AND-compose, not free boolean composition:** metadata scalars take the first non-empty value and a conflicting second is a **400**; **exactly one** preset across the layer set may carry a content predicate (0 or >1 → 400); capped at 8 layers. That sits within the item's Scope wording ("layer several into a single combined filter") but is narrower than arbitrary boolean logic — say so rather than implying a general query builder. _(was 🔢 DEMAND-GATE · Value 5/10 · Difficulty 5/10.)_

**Cluster:** Monitoring. **Priority:** P3. **Verdict:** demand-gate. **Severity (vs Corepoint):** moderate.

**Scope:** Let an operator save named Log Search filter presets (metadata + content filters) server-side per user, then recall and layer several into a single combined query.

**Trigger:** build when an operator repeatedly re-enters the same multi-field Log Search filters or needs to combine saved filters during high-volume triage.

**Why:** Real gap. #51's ad-hoc /messages metadata+content filters are entered fresh each time — nothing names, persists, recalls, or composes a filter set (only table column order persists, client-side).

**Severity note:** the analysis rates this **moderate**; recorded as **moderate**. The capability maps to the gap-analysis top-gaps row at line 53 ("Connection-log searching by HL7 path value + saved/layered searches"), which the analysis rates MODERATE. The scoped capability here (save named presets + layer several into one combined query) is precisely the "save/retrieve, layered searches" component that row names as a Corepoint feature. Per the reconciliation rule, the analysis rating…

**Source:** BACKLOG coverage audit of the 2026-06-27 Corepoint gap analysis against `origin/main` (2026-07-09) — 246 capabilities triaged; this one verified **open and untracked**. Cross-ref [#52](#52-corepoint-capability-parity-gaps--prioritized-roadmap-input-2026-06-27).

---

## 152. Reverse-dependency / impact analysis

> ✅ **SHIPPED — CLI rename/delete impact pre-flight (BACKLOG #152).** `messagefoundry impact <kind> <name>` reports an object's referrers; `--rename-to NEW` plans a tokenize-safe referent rewrite — a plain `str` literal equal to the old name inside a referrer's source span, the inbound `router=` binding, and the `connections.toml` value, never a substring / identifier / comment / f-string / bytes / adjacent-string-concat — **dry-run by default**, `--apply` writes; `--delete` lists the live referrers that would dangle. Built on the #919 reverse-reference index (`config/impact.py` = its I/O twin). The in-editor **IDE rename action is a named RESIDUAL** (deferred). _(was P2 · V3/5 · D3/5)_

> **On-trigger / demand-gate.** Numbered for tracking only — build when the trigger below fires (“demand-gate, don’t schedule”).

**Cluster:** Repository & Config. **Priority:** P3. **Verdict:** demand-gate. **Severity (vs Corepoint):** moderate.

**Scope:** A reverse-reference index over the config bundle that, given a named object (connection/router/handler/code set/reference set), lists the modules and edges referencing it — resolving the inbound→router binding plus router-return, Send(), and code_set() string literals — surfaced as a check/IDE impact report and as a delete/rename pre-flight that can rewrite referents.

**Trigger:** build when an operator needs an object's referrers before renaming or deleting a shared connection, handler, or code set.

**Why:** Partial. check/validate resolves the inbound→router edge forward and the codeset CLI edits/renames tables, but neither reports a given object's referrers nor guards a rename/delete, and the router→handler/Send()/code_set() edges are unindexed string literals.

**Merged from 3 analysis entries** describing the same capability.

**Source:** BACKLOG coverage audit of the 2026-06-27 Corepoint gap analysis against `origin/main` (2026-07-09) — 246 capabilities triaged; this one verified **open and untracked**. Cross-ref [#52](#52-corepoint-capability-parity-gaps--prioritized-roadmap-input-2026-06-27).

---

## 153. Edit-and-resend a stored message

> ✅ **SHIPPED (2026-07-11, [ADR 0090](adr/0090-resend-a-stored-message-to-an-alternate-outbound-connection.md) §9 amendment, Accepted).** Stacked on #123's resend seam. **The editable copy is client-side + ephemeral** (no stored edited-PHI draft); **Resubmit re-routes by default** — the edited raw re-enters on the ORIGINAL channel as a fresh `RECEIVED`, correlated child and flows the normal router→transform→outbound pipeline (`store.reingress` on all 3 backends) — with an **optional direct power-path** to a chosen outbound (`store.resend_to(body_override=...)`). **The original stays byte-identical** (only read, never written; count-and-log). **Idempotent re-ingress** fixes the `enqueue_ingress` uuid4/no-dedup double-deliver: the key is claimed in `resend_log` first (bound to `(origin, "@reingress:<channel>")`) + a content-addressed child id, so a retry delivers exactly once. `POST /messages/{id}/edit-resend` (`{raw, idempotency_key, reroute, to?}`, new `Permission.MESSAGES_EDIT` step-up implying `messages:view_raw`, `message_edit_resend` audit — never the body); a PHI-safe `RequestValidationError` handler strips the offending value from a 422 so a malformed edited body never leaks. Web console: message-detail **"Edit & resubmit →"** → an editor page with an editable **copy**, a **"Modified"** badge, **Revert**, and **Resubmit** (the original detail view is untouched). **Residuals:** the **PySide6 desktop-console editor** (desired-if-clean; web console is the deliverable) + browser-textarea newline normalization (re-parsed tolerantly). 3-backend Postgres/SQL Server parity + the offscreen-Qt console + TS/ide legs are **CI-gated**. _(was P1 · V4/5 · D3/5; re-scored 2026-07-10 → DEMAND-GATE V6/D4; trigger fired — Corepoint cutover operator-parity.)_

**Cluster:** Store / Operations. **Priority:** P3. **Verdict:** ✅ shipped. **Severity (vs Corepoint):** moderate.

**Scope:** An operator action that loads a stored message, lets them edit its body, and re-queues the edited copy as a new re-ingress inbound row (never mutating the original) so it flows through routing/transform/delivery afresh.

**Trigger:** build when a Corepoint migrator needs the message-monitor edit-and-resend workflow to correct a bad field on a stuck message and re-drive it.

**Why:** Real gap. Store.replay / POST /messages/{id}/replay and ADR 0013 re-ingress re-queue a stored body verbatim — none provides an operator edit step before re-delivery.

**Source:** BACKLOG coverage audit of the 2026-06-27 Corepoint gap analysis against `origin/main` (2026-07-09) — 246 capabilities triaged; this one verified **open and untracked**. Cross-ref [#52](#52-corepoint-capability-parity-gaps--prioritized-roadmap-input-2026-06-27).

---

## 154. HTTP response-header capture on delivery response

> ✅ **SHIPPED (2026-07-12).** A per-connection **allow-list** of HTTP response header names (`capture_response_headers` on `Rest()`/`FHIR()`/`Soap()`) is captured from a capturing reply into `DeliveryResponse.headers` ([ADR 0013 amendment 2026-07-12](adr/0013-query-response-orchestration.md)) — **only the allow-listed names**, never all headers (PHI gate: a partner reply header may carry sensitive data). The captured map JSON-encodes into a new nullable **`resp_headers`** column on the `response` table across all 3 backends (SQLite/Postgres/SQL Server — schema + idempotent add-column migration), **encrypted at rest** and **rekey/retention-covered** exactly like `detail`, and surfaces through `correlate_response` as `CapturedResponse.headers`. A re-ingressed answer's Handler reads them via the shipped **`response_get(dest).headers`** seam (no new reader — the response_view already flows to the loopback Handler in both the normal and fused paths). Default (no allow-list) is **byte-identical** (`headers == {}`, column `NULL`). Captured headers are documented as a **captured external value** (like the `fhir_lookup` read-only carve-out) — deterministic per reply, so re-ingress stays re-run-stable from the immutable stored copy. Tests: `tests/test_response_headers_capture.py`. _(was 🔢 DEMAND-GATE · Value 7/10 · Difficulty 4/10.)_

**Cluster:** Web Services & HTTP. **Priority:** P3. **Verdict:** shipped. **Severity (vs Corepoint):** moderate.

**Scope:** Capture a configured allow-list of HTTP response headers (Location, ETag, etc.) from a REST/FHIR/SOAP reply into the captured DeliveryResponse and surface them on the re-ingress path so a Handler can read them.

**Trigger:** build when a partner's REST/FHIR reply carries the actionable result in a header (created-resource id in Location, version in ETag) rather than the body.

**Why:** Partial. ADR 0013 DeliveryResponse round-trips the reply body/outcome/detail to the store and re-ingress path but reads no response headers, so a Location/ETag from a FHIR create is unreachable.

**Source:** BACKLOG coverage audit of the 2026-06-27 Corepoint gap analysis against `origin/main` (2026-07-09) — 246 capabilities triaged; this one verified **open and untracked**. Cross-ref [#52](#52-corepoint-capability-parity-gaps--prioritized-roadmap-input-2026-06-27).

---

## 155. Server-to-server migration runbook

> 🔢 **Re-scored 2026-07-10 → DEMAND-GATE.** Value **2/10** · Difficulty **1/10** · _fill-in_. Pure-docs runbook consolidating already-built, separately-documented steps; existing docs substantially cover it, so a modest single doc edit. _(was P3 · V2/5 · D1/5)_

> **On-trigger / demand-gate.** Numbered for tracking only — build when the trigger below fires (“demand-gate, don’t schedule”).

**Cluster:** Admin & Deployment. **Priority:** P3. **Verdict:** demand-gate. **Severity (vs Corepoint):** minor.

**Scope:** A single documented runbook for moving a MEFOR install to new server hardware: stand up the new box, install the pinned engine + NSSM service, clone config, quiesce/drain and restore the store (SQLite triple-file backup or server-DB cut-over) plus the escrowed key, repoint senders, verify health/integrity/dispositions, then decommission the old host in a no-loss ordering.

**Trigger:** build when an adopter does a hardware refresh or server relocation and asks how to move engine + store + config without message loss.

**Why:** Partial. Every constituent step is built and documented separately (install, store backup + key escrow + restore drill, decommission, the ADR 0050 portable-config bundle) but no doc stitches them into an end-to-end server-to-server migration runbook.

**Source:** BACKLOG coverage audit of the 2026-06-27 Corepoint gap analysis against `origin/main` (2026-07-09) — 246 capabilities triaged; this one verified **open and untracked**. Cross-ref [#52](#52-corepoint-capability-parity-gaps--prioritized-roadmap-input-2026-06-27).

---

## 156. Alert hysteresis (separate fire/clear thresholds)

> 🔢 **Re-scored 2026-07-10 → DEMAND-GATE.** Value **2/10** · Difficulty **3/10** · _fill-in_. Minor anti-flap refinement; shipped realert/cooldown throttle already dampens flapping; no interop dimension; deadband adds fields plus edge-tracking. _(was DEMAND-GATE · V2/5 · D2/5)_

> **On-trigger / demand-gate.** Numbered for tracking only — build when the trigger below fires (“demand-gate, don’t schedule”).

**Cluster:** Alerting. **Priority:** P3. **Verdict:** demand-gate. **Severity (vs Corepoint):** minor.

**Scope:** An optional lower clear-threshold (clear_depth / clear_oldest_seconds) on the queue_buildup AlertRule so a fired threshold alert auto-resolves only below the separate lower bound (deadband) instead of oscillating around one threshold.

**Trigger:** build when operators report threshold-alert flapping that the flat realert/cooldown throttle does not adequately damp.

**Why:** Partial. AlertsSettings.realert_seconds / per-rule cooldown_seconds throttle re-notification and #56 gives resolvable instances, but neither adds a distinct lower clear-threshold so a rule fires at X and clears only below a lower Y.

**Source:** BACKLOG coverage audit of the 2026-06-27 Corepoint gap analysis against `origin/main` (2026-07-09) — 246 capabilities triaged; this one verified **open and untracked**. Cross-ref [#52](#52-corepoint-capability-parity-gaps--prioritized-roadmap-input-2026-06-27).

---

## 157. Direct Project / HIE secure-messaging connector

> ⛔ **DECLINED — owner ruling 2026-07-24** (*"if it is Direct, then close it"*). Zero live feed, declining relevance, and the remainder is a multi-component HISP + XDR subsystem needing new dependencies and its own ADR — not breadth worth carrying.
>
> ⚠️ **This decline is NOT a removal instruction. Do NOT delete `messagefoundry/transports/direct.py`; the outbound S/MIME half ships and stays.** That module is a working Direct-Project **S/MIME-over-SMTP destination** ([ADR 0085](adr/0085-direct-hisp-smime-connector.md), PR1, outbound only — it signs/encrypts the clinical payload as an S/MIME message independent of transport TLS and submits it over STARTTLS SMTP off the event loop; `messagefoundry/transports/direct.py:3-15`). What is declined is the *rest* of the connector — the inbound half, HISP integration and XDR. Reading this ⛔ as "rip out Direct" would delete shipped, working code. _(was 🔢 P3 · Value 3/10 · Difficulty 7/10.)_

**Cluster:** Connections & Transports. **Priority:** P3. **Verdict:** **owner go/no-go**. **Severity (vs Corepoint):** minor.

**Scope:** A Direct/HISP secure-clinical-messaging transport on the SMTP path — S/MIME sign+encrypt outbound with trust-anchor/X.509 handling, cert discovery (DNS CERT/LDAP), and MDN, plus an S/MIME decrypt+verify inbound mail source — and/or IHE XDR ITI-41 document-set push with optional XDM packaging.

**Trigger:** build when an adopter has a live Direct or XDR HIE / referral-CCD feed to migrate off Corepoint.

**Partial build (PLAN-9 Wave 3, 2026-07-10 — branch `plan9-directhisp`):** **PR1 — outbound S/MIME-over-SMTP — is BUILT** ([ADR 0085](adr/0085-direct-hisp-smime-connector.md)): a new `ConnectorType.DIRECT` + `DirectDestination` that **SIGNs then ENCRYPTs** the Handler body via core `cryptography` `serialization.pkcs7` (**no new dependency** — `endesive` rejected, `dnspython` deferred) and submits `application/pkcs7-mime; smime-type=enveloped-data` over the reused EMAIL STARTTLS / `refuse_cleartext_credentials` posture; signing key+cert / per-partner recipient cert / trust anchor cross-validated at construction (fail-loud); a fail-closed `[egress].allowed_direct` host gate kept separate from `allowed_smtp`. **Item stays OPEN** (demand-gated) — the inbound Direct mail source + MDN + DNS-CERT/LDAP discovery + IHE XDR/XDM are **deferred later phases** (ADR 0085), to be built when a live Direct/XDR feed triggers.

**Why:** Partial. The plain-SMTP EmailDestination (ADR 0029) delivers over STARTTLS only and the generic SOAP client exists, but neither implements S/MIME message-level security, HISP trust bundles, cert discovery, MDN, an inbound mail path, or IHE XDR/XDM packaging.

**Merged from 3 analysis entries** describing the same capability.

**Owner decision required.** The analysis rates Direct/HIE **minor** on the stated rationale *“no analog; reachable via generic transports; proprietary/declining relevance.”* That is a business judgement, not a technical one: this is a coherent standalone build (S/MIME sign+encrypt over SMTP, HISP trust anchors, DNS CERT / LDAP certificate discovery, MDN, optionally IHE XDR/XDM). An automated severity pass rated it **major**. Decide go/no-go explicitly rather than letting it sit at P3 by default.

**Source:** BACKLOG coverage audit of the 2026-06-27 Corepoint gap analysis against `origin/main` (2026-07-09) — 246 capabilities triaged; this one verified **open and untracked**. Cross-ref [#52](#52-corepoint-capability-parity-gaps--prioritized-roadmap-input-2026-06-27).

---

## 158. Per-message dynamic FTP host/path/credentials

> 🔢 **Re-scored 2026-07-10 → DEMAND-GATE.** Value **5/10** · Difficulty **3/10** · _fill-in_. Dynamic-FTP-destination parity gap (FTP analog of #68); a config fan-out to per-host/per-folder RemoteFile connections covers the common case. _(was DEMAND-GATE · V2/5 · D2/5)_

> **On-trigger / demand-gate.** Numbered for tracking only — build when the trigger below fires (“demand-gate, don’t schedule”).

**Cluster:** Connections & Transports. **Priority:** P3. **Verdict:** demand-gate. **Severity (vs Corepoint):** minor.

**Scope:** On the RemoteFile (SFTP/FTP/FTPS) destination, resolve the target subdirectory under remote_dir — and optionally the host/credential set — from message fields per delivery instead of fixing them at construction.

**Trigger:** build when one FTP interface must fan out to per-message target subdirectories or a message-selected host rather than a single static remote_dir.

**Why:** Real gap. RemoteFile fixes host, credentials, and remote_dir at construction and only the filename is message-driven (constrained to one path component); it is the direct FTP analog of the HTTP-only #68 per-message override.

**Merged from 2 analysis entries** describing the same capability.

**Source:** BACKLOG coverage audit of the 2026-06-27 Corepoint gap analysis against `origin/main` (2026-07-09) — 246 capabilities triaged; this one verified **open and untracked**. Cross-ref [#52](#52-corepoint-capability-parity-gaps--prioritized-roadmap-input-2026-06-27).

---

## 159. TCP stream-until-close (no-framing) mode

> 🔢 **Re-scored 2026-07-10 → DEMAND-GATE.** Value **3/10** · Difficulty **3/10** · _fill-in_. Niche TCP interop knob for connection-close framing the delimiter codec can't express; new framing=none path spans Tcp source, destination, and codec. _(was DEMAND-GATE · V2/5 · D2/5)_

> **On-trigger / demand-gate.** Numbered for tracking only — build when the trigger below fires (“demand-gate, don’t schedule”).

**Cluster:** Connections & Transports. **Priority:** P3. **Verdict:** demand-gate. **Severity (vs Corepoint):** minor.

**Scope:** A framing="none" mode on the Tcp source/destination that treats the whole connection stream as one message: the source buffers all bytes and emits one message on EOF (bounded by max_frame_bytes/receive_timeout), and the destination writes the raw body and closes to delimit it.

**Trigger:** build when a partner TCP feed frames each message by connection-close with no start/end delimiter.

**Why:** Real gap. The Tcp() connector's delimiter framing codec (framing.py presets or explicit start/end bytes) mandates delimiter bytes and cannot treat a whole connection as a single message.

**Severity note:** the analysis rates this **unrated**; recorded as **minor**. The capability is prose-only (line 88 GAP bullet in the Connections & Transports section) with no severity column, so the analysis rating is "unrated." Per the conservative rule for unrated items, this defaults to minor unless it is a real migration/ops blocker — it is not. It is a niche transport-breadth adjunct to the already-built MLLP/TCP framing core (a whole-stream, close-to-delimit mode), and every…

**Source:** BACKLOG coverage audit of the 2026-06-27 Corepoint gap analysis against `origin/main` (2026-07-09) — 246 capabilities triaged; this one verified **open and untracked**. Cross-ref [#52](#52-corepoint-capability-parity-gaps--prioritized-roadmap-input-2026-06-27).

---

## 160. Timer-source cron / calendar schedule

> ✅ **SHIPPED — verified against `origin/main` (2026-07-28).** [ADR 0011](adr/0011-timer-scheduled-source.md) amendment (2026-07-17). `_CronSchedule` (`messagefoundry/transports/timer.py:48-56`) is a **pure, stdlib-only 5-field cron next-fire evaluator**: `*`, lists, ranges and steps; Sunday as 0 **or** 7; and the Vixie OR rule when both DOM and DOW are restricted. `parse` (`:80-110`) takes exactly 5 fields and **fails loud** on an unsatisfiable expression via a horizon check; `matches` (`:112-124`); `next_after` (`:126-141`) is strictly future and timezone-preserving.
>
> ⚠️ **The re-score line's "plus a dep" was RESOLVED, not satisfied:** `croniter` was considered and **rejected** in favour of the pure-stdlib evaluator (ADR 0011:126-134). Do not go looking for a dependency that was never added. ⚠️ **Documented MVP limits:** numeric fields only (no `JAN`/`MON` names), 5 fields only (no seconds field), and no `@reboot`-style macros. _(was 🔢 DEMAND-GATE · Value 5/10 · Difficulty 3/10.)_

**Cluster:** Connections & Transports. **Priority:** P3. **Verdict:** demand-gate. **Severity (vs Corepoint):** minor.

**Scope:** Cron/calendar next-fire evaluation for the timer source's already-reserved cron_expression setting, so a scheduled poll fires on a time-of-day/weekday calendar instead of only a fixed interval.

**Trigger:** build when a feed must fire on a calendar (time-of-day/weekday/business-hours) schedule a fixed interval_seconds can't express.

**Why:** Partial. The timer source ships interval_seconds + run_once and reserves cron_expression (fails loud as not-yet-implemented, ADR 0011); only the cron/calendar next-fire computation is missing.

**Severity note:** the analysis rates this **unrated**; recorded as **minor**. The scoped capability (timer SOURCE firing a scheduled poll on a cron/calendar instead of a fixed interval) maps to the analysis's prose bullet "run-on-schedule (interval-only, no cron/calendar)" under Gears & Data Flow — a PARTIAL prose item with NO severity (unrated). The downstream agent's "moderate" appears to borrow the MODERATE from the line-61 row "Connection scheduling (run-window/maintenance-window…

**Source:** BACKLOG coverage audit of the 2026-06-27 Corepoint gap analysis against `origin/main` (2026-07-09) — 246 capabilities triaged; this one verified **open and untracked**. Cross-ref [#52](#52-corepoint-capability-parity-gaps--prioritized-roadmap-input-2026-06-27).

---

## 161. Code-set editor in-grid row search

> ✅ **SHIPPED 2026-07-11 (PR #921).** An in-grid row filter in the code-set editor narrows displayed rows by case-insensitive key/value substring. Display-only — a hidden row keeps its inputs in the DOM so Save still writes every row; re-applied after add/remove row/column; shows a shown/total count.

**Cluster:** Correlation & Code Sets. **Priority:** P3. **Verdict:** demand-gate. **Severity (vs Corepoint):** minor.

**Scope:** An in-grid row search/filter box in the code-set editor (and optionally codeset show --filter <substr> on the CLI) that narrows displayed rows by key/value substring within a large set.

**Trigger:** build when operators maintain code sets large enough that scrolling the full grid to locate a row is impractical.

**Why:** Real gap. The code-set grid editor and codeset show render every row with only +row/+column/remove controls — no way to search or filter within a set.

**Source:** BACKLOG coverage audit of the 2026-06-27 Corepoint gap analysis against `origin/main` (2026-07-09) — 246 capabilities triaged; this one verified **open and untracked**. Cross-ref [#52](#52-corepoint-capability-parity-gaps--prioritized-roadmap-input-2026-06-27).

---

## 162. Unmapped-value policy on code-set lookups

> ✅ **SHIPPED (2026-07-11).** Declared per-code-set unmapped-value policy (`none`/`default`/`passthrough`/`flag`) authored via a `codesets/<name>.policy.toml` sidecar and applied by `code_set(name).translate(key)` on a miss, plus **re-run-safe, PHI-aware capture** of unmapped inputs (a pure lookup + a run-scoped deduplicated buffer drained once by the runner — non-PHI counts on the observability path, values via an optional `(message_id,…)`-keyed sink), plus the policy **shown read-only in the grid editor**. Backward-compatible: no sidecar ⇒ today's `.get()`/`[]` behavior. **ADR 0033 amended**; Python model/lookup/capture + tests built (`tests/test_code_sets_policy.py`); the grid TS (`ide/src/codeSetEditor.ts`) is gated by the **ide CI leg**. _(was 🔢 DEMAND-GATE · Value 5/10 · Difficulty 4/10.)_

**Cluster:** Correlation & Code Sets. **Priority:** P3. **Verdict:** shipped. **Severity (vs Corepoint):** minor.

**Scope:** A declared per-code-set unmapped-value policy (default value / passthrough-original / flag-for-review) applied by the lookup itself and shown in the editor grid, plus capture of unmapped inputs for operator reconciliation, so handlers don't hand-code the miss case per crosswalk.

**Trigger:** build when a Corepoint migration brings translation tables whose behavior depends on a default/passthrough/flag-on-miss rule rather than an in-code None check.

**Why:** Partial. Code sets exist (ADR 0033) and a handler can spell the miss with code_set(...).get(key, default), but no unmapped-value policy is declared on the set and no flag-for-review reconciliation is surfaced — unmapped inputs go unrecorded.

**Source:** BACKLOG coverage audit of the 2026-06-27 Corepoint gap analysis against `origin/main` (2026-07-09) — 246 capabilities triaged; this one verified **open and untracked**. Cross-ref [#52](#52-corepoint-capability-parity-gaps--prioritized-roadmap-input-2026-06-27).

---

## 163. Static-string inbound ACK

> 🔢 **Re-scored 2026-07-10 → DEMAND-GATE.** Value **3/10** · Difficulty **3/10** · _fill-in_. Niche legacy canned-ACK interop knob most partners never need; a static ack_mode + literal field through config into MLLP build_ack, plus tests. _(was DEMAND-GATE · V2/5 · D2/5)_

> **On-trigger / demand-gate.** Numbered for tracking only — build when the trigger below fires (“demand-gate, don’t schedule”).

**Cluster:** HL7 / Messaging. **Priority:** P3. **Verdict:** demand-gate. **Severity (vs Corepoint):** minor.

**Scope:** A per-inbound ack_mode (e.g. static) that replies with a fixed operator-supplied literal string as the acknowledgement, bypassing the generated MSH+MSA HL7 ACK, for legacy partners expecting a canned response.

**Trigger:** build when a legacy partner's MLLP receiver expects a fixed canned acknowledgement string rather than a correlated HL7 MSA.

**Why:** Partial. AckMode (original/enhanced/none) only selects among generated MSH+MSA acks in build_ack, and a Tcp() source that frames a verbatim reply abandons the HL7 MLLP ACK path — no inbound option substitutes a fixed literal for the generated HL7 ack (the omit-trigger half is already MF behavior).

**Merged from 2 analysis entries** describing the same capability.

**Source:** BACKLOG coverage audit of the 2026-06-27 Corepoint gap analysis against `origin/main` (2026-07-09) — 246 capabilities triaged; this one verified **open and untracked**. Cross-ref [#52](#52-corepoint-capability-parity-gaps--prioritized-roadmap-input-2026-06-27).

---

## 164. Console dark-mode / theming

> ⛔ **MOOT / DECLINED (2026-07-13, #103).** This item's trigger required the PySide6 desktop console to be **retained rather than retired**. #103 **retired** the desktop console, so the trigger can never fire — there is no PySide6 console theme layer to add a dark palette to. The browser web console (`/ui`) owns its own theming. Retained below only as historical context.

> 🛠 **Decline overturned (2026-07-09).** A prioritization pass recommended DECLINE; the stated reason was **invalid**. Purity binds `@router` / `@handler` — **not connectors** (CLAUDE.md §8: “side effects (DB, network) belong in connections/transports”). This is an unfired **demand-gate**, not an architectural impossibility.
>
> **Build constraints:** Build only when the trigger fires: an operator requests a dark console / runs it on a dark desktop AND the PySide6 console is retained rather than retired (#103) — do not schedule ahead of that. Confine all changes to the console (theme layer) — add a second dark TOKENS set behind the existing token-driven active_tokens()/QPalette/QSS seam plus a light/dark (optionally OS-appearance-honoring) toggle; never touch engine packages (pipeline/transports/parsing/store/config), consistent with §2/§10 (console reaches…

> **On-trigger / demand-gate.** Numbered for tracking only — build when the trigger below fires (“demand-gate, don’t schedule”).

**Cluster:** IDE / DX. **Priority:** P3. **Verdict:** demand-gate. **Severity (vs Corepoint):** minor.

**Scope:** A second (dark) Tokens palette in console/theme.py plus a light/dark toggle (optionally honoring OS appearance) so the PySide6 console is no longer light-only.

**Trigger:** build when an operator requests a dark console or runs it on a dark desktop and the PySide6 console is retained rather than retired (#103).

**Why:** Partial. console/theme.py ships a token-driven QPalette/QSS behind active_tokens() but defines only one light TOKENS set with no dark palette or switch, and the go-forward web console is conversely dark-only.

**Source:** BACKLOG coverage audit of the 2026-06-27 Corepoint gap analysis against `origin/main` (2026-07-09) — 246 capabilities triaged; this one verified **open and untracked**. Cross-ref [#52](#52-corepoint-capability-parity-gaps--prioritized-roadmap-input-2026-06-27).

---

## 165. DB schema browser + ad-hoc query runner

> 🔢 **Re-scored 2026-07-10 → DEMAND-GATE.** Value **5/10** · Difficulty **5/10** · _fill-in_. External SQL client is a clean workaround; still a useful Corepoint-parity authoring aid spanning API, console, and per-backend introspection. _(was DEMAND-GATE · V2/5 · D3/5)_

> **On-trigger / demand-gate.** Numbered for tracking only — build when the trigger below fires (“demand-gate, don’t schedule”).

**Cluster:** IDE / DX. **Priority:** P3. **Verdict:** demand-gate. **Severity (vs Corepoint):** minor.

**Scope:** A read-only DB schema browser (tables/columns) plus an ad-hoc SELECT runner in the console/IDE, scoped to the db_lookup [egress].allowed_db connections, so an author can discover table/column names and validate a query while writing db_lookup / DATABASE-connector SQL.

**Trigger:** build when adopters authoring db_lookup or DATABASE-connector SQL repeatedly leave for an external SQL client to discover schema and test queries.

**Why:** Partial. The nearest mechanisms are the reachability-only connection probe (SELECT 1 behind POST /connections/{name}/test) and the dry-run Test Bench where db_lookup raises — neither browses schema nor runs an author-supplied query.

**Source:** BACKLOG coverage audit of the 2026-06-27 Corepoint gap analysis against `origin/main` (2026-07-09) — 246 capabilities triaged; this one verified **open and untracked**. Cross-ref [#52](#52-corepoint-capability-parity-gaps--prioritized-roadmap-input-2026-06-27).

---

## 166. Server-side per-user console preferences

> 🔢 **Re-scored 2026-07-10 → DEMAND-GATE.** Value **4/10** · Difficulty **6/10** · _money pit_. DX/console polish, nobody blocked; per-machine QSettings is a clean workaround. Store-backed per-user surface spans store, API, auth, and console. _(was DEMAND-GATE · V2/5 · D3/5)_

> **On-trigger / demand-gate.** Numbered for tracking only — build when the trigger below fires (“demand-gate, don’t schedule”).

**Cluster:** IDE / DX. **Priority:** P3. **Verdict:** demand-gate. **Severity (vs Corepoint):** minor.

**Scope:** An authenticated server-side per-user preferences surface (store-backed, keyed by acting user) the console reads/writes so UI settings — poll interval, table/column state, multi-shard registry — roam across workstations instead of living only in local per-machine QSettings.

**Trigger:** build when operators run the console from multiple workstations and need settings to follow them, or the web console needs server-persisted per-user state.

**Why:** Real gap. The console persists all UI settings only in local per-machine QSettings; there is no authenticated server-side per-user preference surface, so nothing roams across workstations.

**Source:** BACKLOG coverage audit of the 2026-06-27 Corepoint gap analysis against `origin/main` (2026-07-09) — 246 capabilities triaged; this one verified **open and untracked**. Cross-ref [#52](#52-corepoint-capability-parity-gaps--prioritized-roadmap-input-2026-06-27).

---

## 167. Test Bench metadata seeding

> 🔢 **Re-scored 2026-07-10 → DEMAND-GATE.** Value **4/10** · Difficulty **2/10** · _fill-in_. IDE Test Bench DX input to seed per-message metadata for transform tests; no such seam exists today, but nobody is blocked — small dry_run + Test Bench add. _(was DEMAND-GATE · V2/5 · D2/5)_

> **On-trigger / demand-gate.** Numbered for tracking only — build when the trigger below fires (“demand-gate, don’t schedule”).

**Cluster:** IDE / DX. **Priority:** P3. **Verdict:** demand-gate. **Severity (vs Corepoint):** minor.

**Scope:** A Test Bench input that seeds per-message metadata key/values onto a dry-run test message so a Router/Handler can read them during transform testing.

**Trigger:** build when the per-message metadata bag ships and transforms read metadata that must be exercised in the Test Bench before deployment.

**Why:** Partial. The store/API reserve an (encrypted) per-message metadata column but the Test Bench dry_run takes only raw+inbound with no channel to seed those values — meaningful only once the per-message metadata-bag runtime feature ships.

**Source:** BACKLOG coverage audit of the 2026-06-27 Corepoint gap analysis against `origin/main` (2026-07-09) — 246 capabilities triaged; this one verified **open and untracked**. Cross-ref [#52](#52-corepoint-capability-parity-gaps--prioritized-roadmap-input-2026-06-27).

---

## 168. Test Bench saved regression collections

> ✅ **SHIPPED — verified against `origin/main` (2026-07-28).** [ADR 0121](adr/0121-test-bench-saved-regression-collections-phi-at-rest-posture-hl7-aware-compare.md). `ide/src/testCollections.ts:1-5` is a pure, dependency-free model + compare for saved Test Bench regression collections, deliberately **reusing** `hl7diff.diffMessages` rather than reimplementing it. `TestCase{name, input, expected}` + `TestCollection{name, cases}` (`:15-25`) are the persisted, named, groupable unit the item asked for; `DEFAULT_VOLATILE_FIELDS` (`:42-45`) ignores MSH-7 / MSH-10 so the compare is meaningful; `compareMessages` at `:97-147`.
>
> ⚠️ **This adds a NEW PHI-at-rest surface:** case bodies persist in **plaintext** VS Code per-workspace storage, mitigated only by an in-UI notice and a steer toward synthetic cases. ADR 0121 **defers** encrypting `workspaceState` — an operator handling real messages in the Test Bench should know this. ⚠️ The volatile-field ignore policy is a **fixed module constant** (MSH-7/MSH-10); per-collection custom ignore policies are not available. _(was 🔢 DEMAND-GATE · Value 4/10 · Difficulty 4/10.)_

**Cluster:** IDE / DX. **Priority:** P3. **Verdict:** demand-gate. **Severity (vs Corepoint):** minor.

**Scope:** Persisted named, groupable collections of Test Bench message cases with recorded expected outputs plus one-click rerun flagging pass/fail against those expectations, versus today's ad-hoc file-picker load that saves no case and asserts no result.

**Trigger:** build when a migrating analyst needs to save and re-run named regression suites in the Test Bench instead of re-selecting files each session.

**Why:** Partial. The IDE Test Bench (testBench.ts) dry-runs ad-hoc message sets with a before/after diff and coverage panes, but loads files through a one-shot picker with no persisted, grouped, expected-output-asserting collection.

**Severity note:** the analysis rates this **unrated**; recorded as **minor**. The analysis does not rate this in its top-gaps severity table — it lives only as a prose PARTIAL item ("test-collection management"), so it is unrated. Per the conservative rule for unrated/prose-only items, it defaults to minor unless it is a real migration/ops blocker. It is not: the Test Bench already exists (dry-run before/after diff), and a migration can be validated today with the ad-hoc file-picker load.…

**Source:** BACKLOG coverage audit of the 2026-06-27 Corepoint gap analysis against `origin/main` (2026-07-09) — 246 capabilities triaged; this one verified **open and untracked**. Cross-ref [#52](#52-corepoint-capability-parity-gaps--prioritized-roadmap-input-2026-06-27).

---

## 169. Author-appendable per-message processing history

> 🔢 **Re-scored 2026-07-10 → DEMAND-GATE.** Value **6/10** · Difficulty **4/10** · _quick win_. Genuine Corepoint MsgAddHistory parity with no clean equivalent; the only workaround stuffs breadcrumbs into a Z-segment, polluting message content. _(was DEMAND-GATE · V3/5 · D3/5)_

> **On-trigger / demand-gate.** Numbered for tracking only — build when the trigger below fires (“demand-gate, don’t schedule”).

**Cluster:** Logging & Audit. **Priority:** P3. **Verdict:** demand-gate. **Severity (vs Corepoint):** minor.

**Scope:** A transform-callable Message helper that appends an author+timestamped free-text entry to a per-message processing history operators can view alongside the message (persisted as metadata, distinct from Z-segments and engine audit rows), with re-run-safe de-duplication.

**Trigger:** build when a Corepoint migration relies on MsgAddHistory breadcrumbs for message-level troubleshooting/audit parity.

**Why:** Real gap. add_segment (in-message Z-segment notes) and the engine audit timeline (record_audit) are HL7-content edits and engine-authored audit respectively, neither a transform-callable append onto an operator-visible message-processing history.

**Source:** BACKLOG coverage audit of the 2026-06-27 Corepoint gap analysis against `origin/main` (2026-07-09) — 246 capabilities triaged; this one verified **open and untracked**. Cross-ref [#52](#52-corepoint-capability-parity-gaps--prioritized-roadmap-input-2026-06-27).

---

## 170. Filterable / exportable audit report

> ✅ **SHIPPED 2026-07-12.** `Store.list_audit` gained optional, fully **parameterized** filters — `actor` (exact identity), `action` (exact event type), and an inclusive `since`/`until` epoch-float window — added portably across all three backends (SQLite / Postgres / SQL Server), keeping the existing limit + most-recent-first ordering + hash-chain read semantics. `GET /audit` exposes the matching query params behind the existing `audit:read` permission. A new `GET /audit/export?format=csv` streams the filtered rows as a downloadable CSV report (PHI-safe metadata columns only: `ts, actor, action, channel_id, detail`), gated by a dedicated `audit:export` permission (granted to Auditor + Administrator), and records the export itself as an `audit.export` audit event (who, which filter, row count). No SIEM required. _(was demand-gate · V6/10 · D4/10)_

**Cluster:** Logging & Audit. **Priority:** P3. **Verdict:** demand-gate. **Severity (vs Corepoint):** minor.

**Scope:** Actor/date/action filter parameters on the audit trail query (GET /audit / Store.list_audit, today limit-only) plus a filtered CSV/file export, so a compliance officer can produce a scoped, downloadable audit report.

**Trigger:** build when a compliance/security officer needs a filtered, exportable audit report for a HIPAA review without a downstream SIEM.

**Why:** Partial. The hash-chained audit data, a plain read-only view, and a SIEM tee exist, but there is no filter-by-actor/date/action or CSV/file export on top of GET /audit.

**Severity note:** the analysis rates this **minor**; recorded as **minor**. The gap analysis rates this minor in its top-gaps table (row 82), grouping "audit retention/report-export" among "Various ops/security conveniences" with rationale "Data exists (audit log, union perms, reset); dedicated views/exports absent." That rationale is still factually correct: the audit trail, its query (Store.list_audit / GET /audit), and hash-chained tamper-evident storage all exist and EXCEED Corepoint…

**Source:** BACKLOG coverage audit of the 2026-06-27 Corepoint gap analysis against `origin/main` (2026-07-09) — 246 capabilities triaged; this one verified **open and untracked**. Cross-ref [#52](#52-corepoint-capability-parity-gaps--prioritized-roadmap-input-2026-06-27).

---

## 171. Runtime log-verbosity control + in-product log viewer

> 🔢 **Re-scored 2026-07-10 → DEMAND-GATE.** Value **4/10** · Difficulty **3/10** · _fill-in_. Ops/console polish: runtime log level plus a viewer over the already-produced redacted tail; the config dial (restart) and support-bundle pulls work, nobody blocked. _(was DEMAND-GATE · V2/5 · D3/5)_

> **On-trigger / demand-gate.** Numbered for tracking only — build when the trigger below fires (“demand-gate, don’t schedule”).

> **AMENDED 2026-07-30 — the API half is BUILT; the console half is DEAD CODE.** Adversarial verification refuted a full close. **BUILT** ([ADR 0130](adr/0130-runtime-ephemeral-log-verbosity-control-and-phi-redacted-log-tail-viewer.md)): the restart-free runtime verbosity control — `set_runtime_level` / `current_log_level` (`messagefoundry/logging_setup.py:417`, `:440`; root + uvicorn, ephemeral, survives `/config/reload`) behind `GET`/`PATCH /logging/level` (`messagefoundry/api/app.py:4527`, `:4541`), gated by `monitoring:diagnose` and audited as `logging_level_change` — plus the paginated **redacted** tail `GET /logs/tail` (`:4570`) behind the new `logs:view` PHI-read permission (`messagefoundry/auth/permissions.py:57`), reusing the #49 redactor, hop-guarded and audited as `logs_view`. 11 tests in `tests/test_logging_surfaces.py`.
>
> ⚠️ **The REMAINDER is the in-console viewer the Scope names, and it is worse than missing — it is wired to nothing.** `messagefoundry_webconsole/static/app.js` registers both features, `[data-mf-log-level]` (`:1252`) and `[data-mf-log-viewer]` (`:1294`), but **no page builder emits either attribute** (`data-mf-log` occurs nowhere outside `app.js`), and the URLs the JS fetches — `/ui/logging/level` (`:1259`) and `/ui/logs/tail` (`:1308`) — **have no route**: neither appears in the golden `/ui` surface (`packaging/messagefoundry-webconsole/tests/golden/ui_routes.txt`). During an incident an operator still reaches both only through the JSON API. ⚠️ ADR 0130's **Built:** block correctly lists routes + DTOs only, but its Related line calls [ADR 0065](adr/0065-web-ops-dashboard.md) "the console that renders it" (`0130:13-14`) — nothing renders it today; amend that when the console half lands. Per-logger/per-area targeting is an ADR-recorded MVP scope-out (`0130:97-98`), not a gap.

**Cluster:** Logging & Audit. **Priority:** P3. **Verdict:** demand-gate. **Severity (vs Corepoint):** minor.

**Scope:** An RBAC-gated runtime verbosity control that adjusts the service log level (optionally per-area/per-logger) without restarting the engine, plus a paginated in-console/web viewer over the redacted application-log tail the support bundle already produces.

**Trigger:** build when operators need to raise service-log detail and read the application log during a live incident without restarting the engine or pulling a full support bundle.

**Why:** Partial. The static [logging].level / --log-level startup dial and the support bundle's one-shot redacted app-log tail exist, but there is no runtime/per-area verbosity control and no interactive in-console log viewer.

**Severity note:** the analysis rates this **unrated**; recorded as **minor**. The analysis does NOT rate this capability — it lives only in the §Logging prose summary (line 120), not as a row in the severity-bearing top-gaps table, so it is unrated. Downstream assigned moderate; I lower to minor. Applying the conservative rule for prose-only items (minor unless a real migration/ops blocker), this is an ops convenience, not a blocker: log level is settable via config, and the redacted…

**Source:** BACKLOG coverage audit of the 2026-06-27 Corepoint gap analysis against `origin/main` (2026-07-09) — 246 capabilities triaged; this one verified **open and untracked**. Cross-ref [#52](#52-corepoint-capability-parity-gaps--prioritized-roadmap-input-2026-06-27).

---

## 172. Gzip/zip compression codec + file-connector option

> 🔢 **Re-scored 2026-07-10 → DEMAND-GATE.** Value **5/10** · Difficulty **3/10** · _fill-in_. Corepoint file-feed parity (gzip/zip in/out) with a clean code-first workaround: a Handler already calls stdlib gzip/zipfile against RawMessage. _(was DEMAND-GATE · V2/5 · D2/5)_
> **On-trigger / demand-gate.** Numbered for tracking only — build when the trigger below fires (“demand-gate, don’t schedule”).

> **AMENDED 2026-07-28 — the codec is BUILT; the connector covers gzip only.** Adversarial verification refuted a full close. **BUILT:** the pure three-algorithm compression codec (`messagefoundry/parsing/compression.py`, Handler-callable) and the File connector's gzip/gunzip option ([ADR 0123](adr/0123-compression-codec-gzip-zip-deflate-file-connector-compress-decompress-option.md)).
>
> ⚠️ **The REMAINDER is ZIP on the connector, which is foreclosed at three separate layers** — the wiring type (`decompress: Literal['gzip'] | None`), `_SUPPORTED_COMPRESSION = frozenset({"gzip"})` (`messagefoundry/transports/file.py:88`, enforced at `:145`), and a validator that raises on `'zip'`. The item's Scope asks for a connector option to "gunzip/**unzip** inbound archived drops" and its Trigger fires on a partner feed delivering "gzipped/**zipped** archives", so a zip-delivering partner is **not** served — a Handler must call the codec by hand. ADR 0123 records the narrowing deliberately, but it **is** a narrowing. Second gap: the sibling **REMOTEFILE** connector has **zero** compression support.

**Cluster:** Modeling & Codecs. **Priority:** P3. **Verdict:** demand-gate. **Severity (vs Corepoint):** minor.

**Scope:** A pure gzip/zip/deflate compress-and-decompress codec (bytes in→bytes out, callable from a Handler against RawMessage/Message alongside the ADR 0028 base64 carriage) plus a file-connector option to gzip outbound drops and gunzip/unzip inbound archived drops.

**Trigger:** build when a partner file feed delivers gzipped/zipped archives or requires compressed outbound files.

**Why:** Real gap. The nearest mechanism, the ADR 0028 base64 binary carriage codec (parsing/binary.py), encodes NUL-safe transport but does not compress or decompress; no gzip/zip codec or connector option exists.

**Severity note:** the analysis rates this **unrated**; recorded as **minor**. The analysis lists this only as a prose GAP bullet ("file zip/unzip/gzip action", line 94) with no severity, so it is unrated. Per the conservative rule, an unrated item is minor unless it's a genuine migration/ops blocker. A gzip/zip/deflate codec is a code-first convenience: a Handler can already call stdlib gzip/zipfile against RawMessage alongside the ADR 0028 base64 carriage, and the file-connector…

**Source:** BACKLOG coverage audit of the 2026-06-27 Corepoint gap analysis against `origin/main` (2026-07-09) — 246 capabilities triaged; this one verified **open and untracked**. Cross-ref [#52](#52-corepoint-capability-parity-gaps--prioritized-roadmap-input-2026-06-27).

---

## 173. Segment/segment-group subtree-copy helper

> 🔢 **Re-scored 2026-07-10 → DEMAND-GATE.** Value **2/10** · Difficulty **2/10** · _fill-in_. One-call sugar over the shipped segments()/groups()/add_segment API; a Handler author can already copy subtrees by hand. _(was DEMAND-GATE · V2/5 · D2/5)_

> **On-trigger / demand-gate.** Numbered for tracking only — build when the trigger below fires (“demand-gate, don’t schedule”).

**Cluster:** Modeling & Codecs. **Priority:** P3. **Verdict:** demand-gate. **Severity (vs Corepoint):** minor.

**Scope:** A one-call Message helper that copies a named segment or segment-group subtree from a source Message into a destination Message (position- and MSH-encoding-aware, re-encoding byte-for-byte), instead of iterating segments(), filtering the group by hand, and re-add_segment()-ing each line.

**Trigger:** build when a mapping-heavy Corepoint migration repeatedly hand-rolls segment/group copies (e.g. lifting repeating OBX/OBR groups) and the boilerplate becomes error-prone.

**Why:** Partial. add_segment(line) grafts a single raw line and groups()/segments() read a source subtree, but there is no single-call cross-message copy — the author must iterate raw lines, find the group boundary, and re-add each segment.

**Source:** BACKLOG coverage audit of the 2026-06-27 Corepoint gap analysis against `origin/main` (2026-07-09) — 246 capabilities triaged; this one verified **open and untracked**. Cross-ref [#52](#52-corepoint-capability-parity-gaps--prioritized-roadmap-input-2026-06-27).

---

## 174. Scheduled automatic statistics reset

> 🔢 **Re-scored 2026-07-10 → DEMAND-GATE.** Value **2/10** · Difficulty **2/10** · _fill-in_. Manual re-snapshot ships (POST /statistics/reset + console) and OTel covers daily volume; only an auto-timer reusing reset_stats is left. _(was P3 · V2/5 · D2/5)_

> **On-trigger / demand-gate.** Numbered for tracking only — build when the trigger below fires (“demand-gate, don’t schedule”).

**Cluster:** Monitoring. **Priority:** P3. **Verdict:** demand-gate. **Severity (vs Corepoint):** minor.

**Scope:** A scheduled (e.g. daily at a configured off-peak time) automatic re-snapshot of per-connection dashboard stat baselines, so the visible cumulative console counters roll over on a timer without an operator POST.

**Trigger:** build when operators on the built-in console (not Prometheus/OTel) want daily volume views without manually resetting stats.

**Why:** Partial. reset_stats already re-snapshots per-connection baselines on demand via POST /statistics/reset; only the scheduled auto-trigger (daily rollover) is missing.

**Source:** BACKLOG coverage audit of the 2026-06-27 Corepoint gap analysis against `origin/main` (2026-07-09) — 246 capabilities triaged; this one verified **open and untracked**. Cross-ref [#52](#52-corepoint-capability-parity-gaps--prioritized-roadmap-input-2026-06-27).

---

## 175. Clone-a-connection editor action

> ✅ **SHIPPED 2026-07-11 (PR #921).** A Clone action on a data-authored connection opens the editor in create mode pre-filled from the source connection's config with the name cleared (a new name is required; direction stays editable). New `messagefoundry.cloneConnection` command on the connection tree context menu.

**Cluster:** Repository & Config. **Priority:** P3. **Verdict:** demand-gate. **Severity (vs Corepoint):** minor.

**Scope:** A Clone action in the connection editor that opens create mode pre-filled from an existing connection's config, requiring a new name before save.

**Trigger:** build when analysts retype near-identical partner connections (e.g. many ADT feeds differing only by host/port) during a Corepoint migration.

**Why:** Partial. The connection editor (connectionEditor.ts + connection upsert) creates and edits connections but only from a blank form or in-place edit — there is no new-from-existing pre-fill to duplicate under a new name.

**Source:** BACKLOG coverage audit of the 2026-06-27 Corepoint gap analysis against `origin/main` (2026-07-09) — 246 capabilities triaged; this one verified **open and untracked**. Cross-ref [#52](#52-corepoint-capability-parity-gaps--prioritized-roadmap-input-2026-06-27).

---

## 176. Unused-object (dead-config) detection

> ✅ **SHIPPED — dead-config detection (BACKLOG #176).** The reverse-reachability index (`config/reachability.py`, #919) walks the loaded Registry from its inbound roots via the structured `inbound→router` binding plus the string-literal `router→handler` / `handler→Send()`/`code_set()`/… edges read from each function's `co_consts`, and the advisory `dead-config` check in `messagefoundry check` names every registered Handler / outbound Connection / table nothing references. Delivered by #919 + this session's #152 close-out. _(was P3 · V2/5 · D2/5)_

> **On-trigger / demand-gate.** Numbered for tracking only — build when the trigger below fires (“demand-gate, don’t schedule”).

**Cluster:** Repository & Config. **Priority:** P3. **Verdict:** demand-gate. **Severity (vs Corepoint):** minor.

**Scope:** An advisory report (in messagefoundry check and/or the IDE) that walks the loaded Registry from its inbound roots and lists registered Handlers, outbound Connections, and _-prefixed helper modules that no other registered object references, so authors find and remove dead config.

**Trigger:** build when adopter config graphs grow large enough that abandoned Handlers/Connections accumulate and operators ask for a cleanup aid.

**Why:** Real gap. check validates the forward direction and the startup sweep dead-letters rows pointing at missing handlers/destinations, but nothing reports the reverse — a registered Handler/Connection/helper that no other object references.

**Source:** BACKLOG coverage audit of the 2026-06-27 Corepoint gap analysis against `origin/main` (2026-07-09) — 246 capabilities triaged; this one verified **open and untracked**. Cross-ref [#52](#52-corepoint-capability-parity-gaps--prioritized-roadmap-input-2026-06-27).

---

## 177. Effective-permission inspector for a user

> 🔢 **Re-scored 2026-07-10 → DEMAND-GATE.** Value **5/10** · Difficulty **2/10** · _fill-in_. Corepoint-parity RBAC audit capability; manual /users×/roles cross-ref is a real workaround; reuses Identity.build flattening + a console pane. _(was P3 · V2/5 · D2/5)_
> **On-trigger / demand-gate.** Numbered for tracking only — build when the trigger below fires (“demand-gate, don’t schedule”).

> **AMENDED 2026-07-28 — the API half is BUILT; the console view is the remainder. ⚠️ This item was nearly closed in error.** A first pass read the merged endpoint as the whole item; two independent adversarial lenses **both refuted** that, and they were right. **BUILT:** `GET /users/{user_id}/permissions` (`messagefoundry/api/auth_routes.py:610`, docstring citing BACKLOG #177 at `:615`) resolving the flattened effective set via `AuthService.identity_for_user_id` (`:622`) — the same `Identity.build` path `/auth/me` uses — with tests and `docs/SECURITY.md` coverage.
>
> ⚠️ **The REMAINDER: the Scope says "An admin endpoint … PLUS console view", and the re-score explicitly prices in "a console pane".** `user_detail_page` returns only Profile / Roles / Channel-scope / Account-actions cards, `_user_detail` never calls the inspector, the golden `/ui` route surface contains **no** permission-inspector route, and `apiclient/` has **no wrapper** for the endpoint — so the console cannot even reach it. An admin still cross-references `/users` × `/roles` by hand, which is the exact workaround the item exists to remove. Build the pane; do not rebuild the endpoint.

**Cluster:** Security. **Priority:** P3. **Verdict:** demand-gate. **Severity (vs Corepoint):** minor.

**Scope:** An admin endpoint (e.g. GET /users/{id}/permissions) plus console view that resolves the flattened effective permission set (built-in-role ∪ custom-role ∪ extras) for a specified user id, not just the caller's own via /auth/me.

**Trigger:** build when an operator needs to audit or troubleshoot what a specific non-self user can actually do rather than manually cross-referencing /users against /roles.

**Why:** Partial. /auth/me flattens the caller's own effective permissions and /roles + /users expose the role→permission and user→role maps, but no endpoint resolves the flattened effective set for an arbitrary user.

**Source:** BACKLOG coverage audit of the 2026-06-27 Corepoint gap analysis against `origin/main` (2026-07-09) — 246 capabilities triaged; this one verified **open and untracked**. Cross-ref [#52](#52-corepoint-capability-parity-gaps--prioritized-roadmap-input-2026-06-27).

---

## 178. SFTP cipher / KEX / MAC allow-lists

> 🔢 **Re-scored 2026-07-10 → DEMAND-GATE.** Value **3/10** · Difficulty **2/10** · _fill-in_. Niche interop knob a FIPS-restricted SFTP partner needs; paramiko disabled_algorithms plumbed into the one existing sftp client seam + tests. _(was DEMAND-GATE · V3/5 · D2/5)_

> **On-trigger / demand-gate.** Numbered for tracking only — build when the trigger below fires (“demand-gate, don’t schedule”).

**Cluster:** Security. **Priority:** P3. **Verdict:** demand-gate. **Severity (vs Corepoint):** minor.

**Scope:** Operator-configurable SFTP cipher/KEX/MAC algorithm allow-lists (paramiko disabled_algorithms plus preferred-ordering on the SSH Transport) on the REMOTEFILE sftp source and destination.

**Trigger:** build when a partner SFTP endpoint requires a specific or FIPS-restricted cipher/KEX/MAC set that paramiko's defaults do not offer or would down-negotiate below policy.

**Why:** Real gap. The REMOTEFILE sftp client negotiates ciphers/KEX/MACs entirely from paramiko defaults with no operator knob — host-key verification and FTPS ECDHE-group hardening are configurable, but neither pins the SSH transport's algorithm sets.

**Source:** BACKLOG coverage audit of the 2026-06-27 Corepoint gap analysis against `origin/main` (2026-07-09) — 246 capabilities triaged; this one verified **open and untracked**. Cross-ref [#52](#52-corepoint-capability-parity-gaps--prioritized-roadmap-input-2026-06-27).

---

## 179. Archive-aged-rows to separate store

> 🔢 **Re-scored 2026-07-10 → DEMAND-GATE.** Value **6/10** · Difficulty **4/10** · _quick win_. Real CIEArchive parity gap: retention is delete-only; the only workaround is whole-store .mfbak snapshots or disabling purge—awkward, not clean. _(was DEMAND-GATE · V3/5 · D3/5)_

> **On-trigger / demand-gate.** Numbered for tracking only — build when the trigger below fires (“demand-gate, don’t schedule”).

**Cluster:** Store / Operations. **Priority:** P3. **Verdict:** demand-gate. **Severity (vs Corepoint):** minor.

**Scope:** An archive-to-separate-store step in the retention pass that copies aged message-body and dead-letter rows into a configured archive store before purge deletes them, keeping the operational store lean while archived history stays retrievable.

**Trigger:** build when a migrating Corepoint site relies on CIEArchive-style archived-but-searchable history that retention's delete-only purge would discard.

**Why:** Real gap. The [retention] RetentionRunner purges aged bodies and dead-letters store-wide by age with no copy-to-archive step, and the DR .mfbak backup snapshots the whole store rather than tiering aged rows into a separate queryable archive.

**Severity note:** the analysis rates this **unrated**; recorded as **minor**. Capability is prose-only in the analysis (the "log archive DBs/CIEArchive" gap under Logging, Audit & Log Archives, line 120) — no top-gaps table row, so analysis_severity is unrated. The Message Store prose (line 122) treats retention/purge/VACUUM as present and names stored-message editing as the sole "real gap," not archive-to-separate-store. Applying the unrated conservative rule: minor unless it is a real…

**Source:** BACKLOG coverage audit of the 2026-06-27 Corepoint gap analysis against `origin/main` (2026-07-09) — 246 capabilities triaged; this one verified **open and untracked**. Cross-ref [#52](#52-corepoint-capability-parity-gaps--prioritized-roadmap-input-2026-06-27).

---

## 180. Cross-backend store migration tool

> 🔢 **Re-scored 2026-07-10 → DEMAND-GATE.** Value **6/10** · Difficulty **5/10** · _quick win_. Real gap; only workaround (drain-before-cutover) discards retained history/audit — awkward not clean; offline cross-backend re-encrypting row copy. _(was DEMAND-GATE · V3/5 · D4/5)_

> **On-trigger / demand-gate.** Numbered for tracking only — build when the trigger below fires (“demand-gate, don’t schedule”).

**Cluster:** Store / Operations. **Priority:** P3. **Verdict:** demand-gate. **Severity (vs Corepoint):** minor.

**Scope:** An offline tool that copies an existing SQLite store's rows (in-flight staged ingress/routed/outbound plus retained message/dead-letter history, preserving disposition and re-encrypting under the target key) into a SQL Server or Postgres store, so an adopter switches backends without draining history.

**Trigger:** build when an adopter must promote an in-production SQLite store to a server backend without losing retained history/audit.

**Why:** Real gap. open_store selects among SQLite/Postgres/SQL Server and retention/encryption exist per backend, but there is no cross-backend data-copy tool — the only documented path is greenfield drain-before-cutover, which discards retained history.

**Severity note:** the analysis rates this **unrated**; recorded as **minor**. Analysis rates this unrated (prose-only, PARTIAL in Database Connectivity §106; a listed gap in Administration §126 where only DR tooling is flagged major). Per the conservative rule for unrated items, this is minor rather than the downstream's moderate: it is a one-time, rare backend switch with a viable workaround — quiesce/drain in-flight staged rows, then cut over to the new backend and start fresh. Only…

**Source:** BACKLOG coverage audit of the 2026-06-27 Corepoint gap analysis against `origin/main` (2026-07-09) — 246 capabilities triaged; this one verified **open and untracked**. Cross-ref [#52](#52-corepoint-capability-parity-gaps--prioritized-roadmap-input-2026-06-27).

---

## 181. Multipart/form-data outbound encoder

> 🔢 **Re-scored 2026-07-10 → DEMAND-GATE.** Value **3/10** · Difficulty **3/10** · _fill-in_. Niche multipart upload; a hand-built Handler body covers partners; boundary encoder + per-request Content-Type across str-typed REST/SOAP send. _(was DEMAND-GATE · V2/5 · D2/5)_

> **On-trigger / demand-gate.** Numbered for tracking only — build when the trigger below fires (“demand-gate, don’t schedule”).

**Cluster:** Web Services & HTTP. **Priority:** P3. **Verdict:** demand-gate. **Severity (vs Corepoint):** minor.

**Scope:** A multipart/form-data body encoder on the REST/SOAP outbound clients that frames one or more parts (text fields plus a binary attachment part from mfb64/raw_bytes) with a generated boundary and sets the multipart Content-Type, instead of only a single flat encoded payload.

**Trigger:** build when a partner REST/SOAP endpoint requires a multipart/form-data upload (e.g. a document-upload API expecting a file part).

**Why:** Partial. REST()/SOAP() clients can set any content_type and body but have no multipart/form-data encoder; the nearest is DICOMweb multipart/related framing (DICOM-only) plus mfb64 base64 in a single flat body.

**Source:** BACKLOG coverage audit of the 2026-06-27 Corepoint gap analysis against `origin/main` (2026-07-09) — 246 capabilities triaged; this one verified **open and untracked**. Cross-ref [#52](#52-corepoint-capability-parity-gaps--prioritized-roadmap-input-2026-06-27).

---

## 182. Per-message base-address override for web-service senders

> 🔢 **Re-scored 2026-07-10 → DEMAND-GATE.** Value **3/10** · Difficulty **4/10** · _fill-in_. Niche interop knob with a clean one-connection-per-address workaround; an override through 3 HTTP clients needs a delivery-time SSRF re-check (d4). _(was DEMAND-GATE · V2/5 · D2/5)_

> **On-trigger / demand-gate.** Numbered for tracking only — build when the trigger below fires (“demand-gate, don’t schedule”).

**Cluster:** Web Services & HTTP. **Priority:** P3. **Verdict:** demand-gate. **Severity (vs Corepoint):** minor.

**Scope:** Let a Handler set the target base endpoint URL per message on a REST/SOAP/FHIR Send (carried as data), so delivery overrides the connector's fixed url with a message-computed address.

**Trigger:** build when a partner requires the outbound endpoint computed from message content (e.g. a per-facility/registry address) rather than fixed in connector settings.

**Why:** Real gap. REST/SOAP/FHIR outbounds resolve a single fixed url at construction; the sibling per-message-headers knob is tracked as #68 but no path carries a message-computed target base address.

**Severity note:** the analysis rates this **minor**; recorded as **minor**. The downstream agent rated this "moderate," but the gap analysis explicitly rates the covering row "minor" (line 71, top-gaps table). The rule is that the analysis rating wins unless its rationale is factually wrong now — it is not: the override remains per-connection/env-resolved with no runtime per-message path (wiring.py:1229-1312), exactly as stated. This is a sender-control convenience, not a migration/ops…

**Source:** BACKLOG coverage audit of the 2026-06-27 Corepoint gap analysis against `origin/main` (2026-07-09) — 246 capabilities triaged; this one verified **open and untracked**. Cross-ref [#52](#52-corepoint-capability-parity-gaps--prioritized-roadmap-input-2026-06-27).

---

## 183. SOAP MTOM/XOP binary packaging

> 🔢 **Re-scored 2026-07-10 → DEMAND-GATE.** Value **3/10** · Difficulty **3/10** · _fill-in_. Niche IHE MTOM/XOP packaging format most SOAP partners never need; base64-inline serves accepting partners; spec-fiddly XOP confined to one connector. _(was DEMAND-GATE · V2/5 · D3/5)_

> **On-trigger / demand-gate.** Numbered for tracking only — build when the trigger below fires (“demand-gate, don’t schedule”).

**Cluster:** Web Services & HTTP. **Priority:** P3. **Verdict:** demand-gate. **Severity (vs Corepoint):** minor.

**Scope:** MTOM/XOP outbound packaging on the SOAP destination: when a <Body> fragment carries a binary payload via the mfb64 marker, serialize the envelope as multipart/related with an xop:Include reference and the bytes as a separate MIME part, instead of base64-inline in the XML.

**Trigger:** build when a SOAP document-exchange partner (e.g. IHE XDS.b) requires MTOM/XOP-encoded binary attachments a migration depends on.

**Why:** Real gap. The SOAP destination emits a single string-concatenated envelope with binary inline-base64 in the <Body>; there is no multipart/related XOP packaging, so an MTOM-expecting partner cannot be served.

**Severity note:** the analysis rates this **unrated**; recorded as **minor**. MTOM/XOP appears only in a prose PARTIAL list (line 110), not in the analysis's top-gaps severity table, so the analysis itself assigns no severity (unrated). The downstream agent rated it "moderate"; I lower to minor. Per the unrated rule, minor is the default unless the item is a real migration/ops blocker, and MTOM/XOP is not: MeFor already carries binary payloads over SOAP via base64-inline XML (the mfb64…

**Source:** BACKLOG coverage audit of the 2026-06-27 Corepoint gap analysis against `origin/main` (2026-07-09) — 246 capabilities triaged; this one verified **open and untracked**. Cross-ref [#52](#52-corepoint-capability-parity-gaps--prioritized-roadmap-input-2026-06-27).

---

## 184. Serve own endpoint WSDL

> 🔢 **Re-scored 2026-07-10 → DEMAND-GATE.** Value **3/10** · Difficulty **2/10** · _fill-in_. Niche SOAP interop knob most partners never need; out-of-band WSDL is a clean workaround; small GET ?wsdl branch on the built HTTP listener. _(was DEMAND-GATE · V2/5 · D2/5)_

> **On-trigger / demand-gate.** Numbered for tracking only — build when the trigger below fires (“demand-gate, don’t schedule”).

**Cluster:** Web Services & HTTP. **Priority:** P3. **Verdict:** demand-gate. **Severity (vs Corepoint):** minor.

**Scope:** Serve a partner-facing WSDL document at the inbound HTTP/SOAP listener (e.g. GET ?wsdl) so a SOAP partner can fetch our endpoint's contract for their client tooling.

**Trigger:** build when a migrating SOAP partner requires fetching a WSDL from our inbound endpoint to generate/validate their client.

**Why:** Partial. The inbound HTTP listener (ADR 0023) receives SOAP-over-HTTP bodies and answers GET with only a static health response — it publishes no WSDL, and #69 covers importing a partner's WSDL, not serving our own.

**Source:** BACKLOG coverage audit of the 2026-06-27 Corepoint gap analysis against `origin/main` (2026-07-09) — 246 capabilities triaged; this one verified **open and untracked**. Cross-ref [#52](#52-corepoint-capability-parity-gaps--prioritized-roadmap-input-2026-06-27).


---

## 185. ASVS 5.0 Level-3 re-score — 67 open findings (tracking index)

> ✅ **CLOSED 2026-07-28 — SUPERSEDED by the [ADR 0115](adr/0115-asvs-l3-drive-to-pass-secure-by-default-flips-and-residual-closure.md) re-partition into #242–#246.** This is an **index-only umbrella that owns no findings and ships nothing runnable** (its own score was Value 1 / Difficulty 1) — a tracking wrapper, not work. ADR 0115 (**Accepted 2026-07-16**, owner-directed scope decision) re-partitioned the ASVS L3 programme into phased builds across **BACKLOG #242–#246**, which is where the findings now live and are tracked. An index whose contents have been re-partitioned elsewhere has nothing left to index, so it closes as superseded rather than as delivered.
>
> ⚠️ **This is NOT a claim that "ASVS is done".** It is a statement about *this index*, nothing more. The programme **continued past this published baseline** — the file you are reading ends at #231, while #242–#246 and their successors do not appear in it at all — so the state of ASVS L3 cannot be read off this item in either direction. The assessment, remediation and risk-acceptance documents ADR 0115 references live under `docs/security/`, which is **gitignored post-cutover** and therefore not readable from the public repo; their absence here is a publishing boundary, not evidence of completion (see [`SECURITY-DOCS-POLICY.md`](SECURITY-DOCS-POLICY.md)). _(was 🔢 P3 · Value 1/10 · Difficulty 1/10 · _fill-in_. Filed by the independent ASVS 5.0 L3 re-score, PR #854.)_

**Cluster:** Security & Compliance. **Priority:** P1. **Verdict:** build (indexed below). **Severity:** n/a (index).

**Scope:** Umbrella item for the 2026-07-09 independent re-score of the engine against **OWASP ASVS 5.0.0 Level 3** (`security/ASVS-L3-ASSESSMENT-2026-07-09.md`). Owns no findings itself; items **#186–#205** below partition all 67 open cells, each exactly once.

**Why:** The prior assessment reported **214 Pass / 0 Partial / 0 Fail / 131 N/A** by introducing a "conditional Pass" — a verdict ASVS does not define — which absorbed every off-by-default, operator-activated and deployment-delegated control, plus one control that does not exist at all (15.2.5, the runtime sandbox). Scored strictly, the shipped default posture is:

| Posture | Pass | Partial | Fail | N/A |
|---|---:|---:|---:|---:|
| **A** — as-shipped defaults (loopback, `serve_ui` off) | 179 | 51 | 5 | 110 |
| **B** — hardened off-loopback ops console | 189 | 57 | 10 | 89 |

68 of 345 cells moved (46 downgraded, 19 reclassified, 3 upgraded). Of the 18 rows previously marked *Pass (conditional…)*, **only 3 survive as real Passes**. The requirement **inventory** was verified correct (345 reqs, 253 L1+L2, 92 L3-only; every ID and level tag matches canonical ASVS 5.0.0) — what changed is the verdicts, not the scope.

Two findings are worth surfacing here. **Posture B scores worse on Fails than Posture A (10 vs 5)** — enabling the browser console pulls five previously-N/A V3 controls into scope as Fails, so "hardened" is not a superset of "safe". And the prior blanket-N/A over V9+V10 (43 requirements, on the premise "no JWT, no OAuth/OIDC") was **false**: `transports/smart.py` runs an OAuth 2.0 `client_credentials` grant and mints a signed JWT `client_assertion`, so those chapters are applicable and now score 0 Pass.

**Coverage rule:** every Partial and every Fail in either posture is owned by exactly one of #186–#205. A finding with no owning item is a bug in this index.

**Source:** `security/ASVS-L3-ASSESSMENT-2026-07-09.md` §6 (findings table + the four remediation classes). Supersedes the scoring in `security/ASVS-L3-ASSESSMENT.md`.

---

## 186. Secure-by-default: retention, at-rest encryption, egress allowlists

> ✅ **BUILT 2026-07-10 (lane `plan8-alerts`, commit `479986d`; PR #889).** Ships the built controls secure-by-default with an audited opt-out: a production-PHI instance now refuses to start with unbounded PHI retention (`[retention].allow_unbounded_phi`, covering both `messages_days` and `dead_letter_days`) and `[egress]` flips to effective deny-by-default; staging-PHI warns, dev/synthetic loopback is byte-identical. At-rest encryption is already fail-closed by posture. The LocalSystem → least-privilege service-account flip is split out as #224 (Windows-CI-gated).

**Cluster:** Security & Compliance. **Priority:** P1. **Verdict:** build. **Severity:** high.

**Closes (ASVS 5.0 L3):** 14.2.4, 14.2.7, 13.2.4, 13.2.5, 13.2.2 · *(remediation class 1 — flip a default)*

**Scope:** Ship the already-built controls **enabled**: default a non-zero `[retention]` window (or refuse to start on `data_class=phi` without one); make at-rest encryption effective by default rather than only on a `data_class=phi` box; flip `[egress]` and alerts host allowlists from *empty ⇒ allow-any* to **deny-by-default**; make the least-privilege virtual service account the installer default instead of LocalSystem.

**Why:** These are the highest-value, lowest-cost fixes in the whole re-score — the code is built and correct, it simply does not ship on. `RetentionRunner` performs **no deletion at all** until an operator sets a window, and every window defaults to `0`; the hardened off-loopback runbook never turns it on. Egress is *empty = allow-any* with `deny_by_default` off, so a Handler can reach any host. LocalSystem grants far more privilege than the engine needs (flipping it safely is Windows-CI-gated, hence bundled here rather than in #203).

**Source:** ASVS re-score 2026-07-09, remediation class 1.

---

## 187. Authentication defaults: require MFA, tighten TOTP skew, phishing-resistant factor

> ✅ **SHIPPED — verified against `origin/main` (2026-07-28).** All three parts are built. **Defaults:** `require_mfa: bool = True` (`messagefoundry/config/settings.py:1662`) and the strict `totp_skew_steps: int = 0` (`:1682`, values > 2 rejected) — ASVS 6.3.3 / 6.5.5. **Phishing-resistant factor:** WebAuthn passkeys ship via the `[webauthn]` extra **by design, NOT a core dep** ([ADR 0068](adr/0068-browser-webauthn-passkeys-offloopback.md) §3: its pyOpenSSL transitive hard-caps `cryptography<50`, so keeping it an extra leaves the core PHI crypto upgrade-agile). **The "sole deferred residual" is closed:** [ADR 0079](adr/0079-kerberos-idp-session-coordination.md) is no longer Proposed — its status line reads **Accepted, mechanism 2 built 2026-07-22** — shipping the directory reconciler (`messagefoundry/auth/reconcile.py`; `_directory_reconciler` at `messagefoundry/api/app.py:5066`, which re-resolves principals holding live sessions and revokes those AD has disabled or deleted) behind five `[auth]` settings at `messagefoundry/config/settings.py:1777-1803`. ⚠️ **Scope note, not a residual of this item:** `ad_session_recheck_seconds` still ships at `0` (`:1777`), so no reconciler task is created until an operator sets it (`docs/SECURITY.md:1321` recommends `300` for an off-loopback PHI deployment serving AD accounts). Flipping that default is owner-approved but is a **separate code+test change on a separate lane**, deliberately not folded into this docs-only reconcile. _(was 🚧 core shipped / Kerberos residual · Value 8/10 · Difficulty 5/10.)_

**Cluster:** Security & Compliance. **Priority:** P1. **Verdict:** build. **Severity:** high.

**Closes (ASVS 5.0 L3):** 6.3.3, 6.5.5, 6.5.7, 6.7.2, 7.1.3 · *(class 1)*

**Scope:** Default `[auth].require_mfa` on for privileged roles (today the engine's hard refusal fires only for a production-**and**-PHI exposed instance). Narrow the TOTP skew window from `DEFAULT_WINDOW=1` to `0`. Make WebAuthn passkeys (ADR 0068) a shipped default rather than an optional `[webauthn]` extra. Coordinate Kerberos SSO session lifetime with the IdP instead of minting an independent local session.

**Why:** **6.5.5 is a one-line constant with a real defect behind it:** a ±1 skew window accepts a code for up to ~90 s of wall clock against the 30 s the requirement mandates — 3× the permitted first-use lifetime. Single-use consumption bounds replay but does not narrow that window. And even in the hardened posture the required second factor is **phishable TOTP**; the phishing-resistant hardware factor exists (WP-14b) but is off and optional, so 6.5.7 / 6.7.2 never engage in a default deployment.

**Source:** ASVS re-score 2026-07-09, remediation class 1.

---

## 188. Out-of-band security notifications on by default

> ✅ **BUILT 2026-07-10 (lane `plan8-alerts`, commit `d1393fd`; PR #889).** The per-user security-event notifier is now always injected, and a production-PHI instance refuses to start (staging-PHI warns) when no effective out-of-band notification channel (`[alerts]` SMTP + `[auth].notify_security_events`) is configured — `[alerts].security_notifications_required` (default on) is the audited opt-out. No fake transport shipped; dev/synthetic loopback byte-identical.

**Cluster:** Security & Compliance. **Priority:** P2. **Verdict:** build. **Severity:** medium.

**Closes (ASVS 5.0 L3):** 6.3.5, 6.3.7 · *(class 1)*

**Scope:** Make suspicious-login and credential/profile/role-change notifications effective without operator SMTP setup — either ship a default transport, or have the exposure runbook mandate SMTP configuration, or treat the always-on `/me/security-events` feed as insufficient and say so.

**Why:** Both controls are built (Phase L3-B) but the actual **push** is off unless the operator configures SMTP, which neither the defaults nor the off-loopback runbook do. A pull-only feed the user must visit is not a notification: an attacker who changes a victim's credentials produces no signal the victim will see.

**Source:** ASVS re-score 2026-07-09, remediation class 1.

---

## 189. Validation + dual-control defaults

> ✅ **BUILT 2026-07-10 (PLAN-9 Wave 2, branch `plan9-gate`).** Two halves shipped: (1) a **dual-control-at-exposure WARN serve-gate** — an off-loopback PHI instance with `[approvals].enabled` off gets a startup stderr warning (naming `[approvals].enabled` + the gated flows + the 2.3.5 single-caller-authority note) and still starts; loopback + synthetic stay byte-identical. Default is **warn-only**; the sec-mfa-on-style **prod-refuse** arm is a documented owner-fork TODO. (2) The tolerant-peek design tension (ASVS **2.2.1/2.2.3**) recorded as a **signed accepted deviation** citing `Validation.strict`, reconciled across all three ASVS docs so none claims both "0 Partials" and an open Partial. Reads the already-shipped `settings.approvals.enabled` — no new config field.

**Cluster:** Security & Compliance. **Priority:** P2. **Verdict:** build. **Severity:** medium.

**Closes (ASVS 5.0 L3):** 2.2.1, 2.2.3, 2.3.5 · *(class 1)*

**Scope:** Default `[approvals].enabled` on for high-value flows (or force it on for `data_class=phi`). Decide the shipped default for `Validation.strict` and cross-field consistency rules: either default-on robust structural validation, or record the tolerant-peek default as an accepted deviation from L3's "all input" clause.

**Why:** The maker-checker workflow ships (`api/approvals.py`) but defaults **off**, so every high-value flow completes on a single caller's authority. At L3 "all input" binds, and HL7 content gets only the tolerant peek (parseable + MSH + size/segment caps) by default; hl7apy structural validation is opt-in per feed. There is no engine-level enforcement that a feed defines *any* combined-item rule. Note the tension with CLAUDE.md §8's payload-agnostic ingress and the two-tier parsing rule — this is a deliberate-design decision to make explicitly, not drift.

**Source:** ASVS re-score 2026-07-09, remediation class 1.

---

## 190. PHI data-plane integrity defaults: JWS signing, GCM rekey counter, keyed audit chain

> ✅ **SHIPPED 2026-07-11 (ADR 0093) — remainder resolved: pinned internal-CA trust anchor BUILT; JWS scoped out (shipped, ADR 0018); ECH scoped out (infeasible).** The two sharpest cells shipped earlier (11.3.4 GCM invocation counter; 16.4.2 HMAC-keyed audit chain — see the partial-build note below). The remaining three parts are now closed: (1) **BUILT** — a pinned internal-CA TLS trust anchor: a small opt-in `[tls]` section (`internal_ca_file` + `trust_anchor_mode` = `system`/`augment`/`pinned`) + a pure `resolve_trust_anchor` wired into the internal-outbound connector client-verify contexts (MLLP/DICOM-SCU/FTPS), composing with (never weakening) the existing fail-closed no-CA/`tls_verify=false`/cleartext refusals; default `system` = byte-identical. (2) **SCOPED OUT** — detached-JWS signing (4.1.5/12.3.4) is already shipped (ADR 0018 / `transports/signing.py`); every PHI-plane surface already has integrity (bodies=ADR 0018, audit=HMAC chain, at-rest=GCM AEAD). (3) **SCOPED OUT** — ECH for outbound SNI (12.1.5): Python 3.14 stdlib `ssl` has no ECH API, no SVCB/HTTPS resolver, and it would need a new dependency — recorded as a documented risk acceptance. See [ADR 0093](adr/0093-pinned-internal-ca-trust-anchor.md) and [SECURITY.md](SECURITY.md) ("Outbound TLS trust anchor" + "PHI data-plane integrity residuals — scope-outs"). _Re-scored 2026-07-10 → P2, value 6/10 · difficulty 7/10 · big bet (ASVS 5.0 L3 re-score, PR #854)._

**Cluster:** Security & Compliance. **Priority:** P2. **Verdict:** build. **Severity:** medium.

**Closes (ASVS 5.0 L3):** 4.1.5, 11.3.4, 16.4.2, 12.3.4, 12.1.5 · *(class 1)*

**Scope:** Detached-JWS message signing (ADR 0018) is off by default, outbound-only, and mandated by no shipped guidance — decide whether the exposure runbook requires it. Add a per-key AES-GCM **invocation counter with rekey-before-2^32 enforcement**. Key the audit hash chain (HMAC) and verify it automatically rather than only via the manual `verify-audit` CLI. Default the TLS trust anchor to a pinned internal CA rather than the OS store. Evaluate ECH for outbound SNI-leaking handshakes (12.1.5).

**Why:** 11.3.4 is the sharpest: a nonce collision under a single GCM key is catastrophic, and there is no invocation counter or rekey enforcement — only the fact that the nonce-producing cipher is off by default keeps it latent. 16.4.2's chain is **tamper-evident, not forgery-proof**: unkeyed, so an attacker with DB write can recompute it, and tail-truncation needs an out-of-band anchor. 12.1.5 (ECH) leaks partner/EHR identity on every outbound TLS handshake under the currently-unrestricted default egress allowlist — it is a **Fail in both postures**, and may be the right candidate for a documented risk acceptance if stdlib support is not ready.

**Source:** ASVS re-score 2026-07-09, remediation class 1.

**Partial build (PLAN-9 Wave 2, 2026-07-10 — branch `plan9-store`):** the two sharpest cells are BUILT — **11.3.4** (a per-key AES-GCM invocation counter with fail-closed rekey-before-2³², soft-warn near 2³¹) and **16.4.2** (the audit hash-chain is now HMAC-**keyed** via HKDF-over-DEK, with a byte-identical keyless/legacy path, alert-only startup auto-verify gated by `[integrity].audit_verify_on_start`, a non-silent versioned keyless→keyed migration via an `audit_chain_meta` watermark + a `messagefoundry rekey-audit` CLI that refuses on any keyless-chain break — across all three store backends). The remaining #190 parts are now **resolved** (2026-07-11, ADR 0093 — see the SHIPPED banner above): the pinned-internal-CA TLS trust anchor is **built**; detached-JWS signing (4.1.5/12.3.4) is **scoped out** (already shipped via ADR 0018); and ECH for outbound SNI (12.1.5) is **scoped out** as a documented risk acceptance (no stdlib API / no SVCB resolver / no-new-dep).

---

## 191. SMART/OAuth outbound: exercise the built path, or scope it out

> ✅ **SHIPPED 2026-07-11 (PR #926) — exercised + scoped out.** The SMART/OAuth outbound path is driven end-to-end by `tests/test_smart_backend.py::test_asvs_191_smart_oauth_controls_exercised` (alg-allowlist/no-'None', `aud` binding, no-token-leak, scope-**absence** when unset, `private_key_jwt` with no shared secret) — proving the code is correct. Per the owner decision the five ASVS cells (9.1.2/9.2.4/10.1.1/10.2.3/10.4.10) are recorded **N/A in both assessed postures** (scope-out) rather than folded into the documented deployment; they re-score to Pass the moment a SMART outbound is configured. Scorecard counts reconciled (Posture A 179/46/5/115; B 189/52/10/94); disposition documented in `ASVS-L3-RISK-ACCEPTANCE-REGISTER.md` §1d.

**Cluster:** Security & Compliance. **Priority:** P3. **Verdict:** owner decision. **Severity:** low.

**Closes (ASVS 5.0 L3):** 9.1.2, 9.2.4, 10.1.1, 10.2.3, 10.4.10 · *(class 1)*

**Scope:** These five cells score **Partial only because the default posture never exercises correct code.** Either mark the SMART outbound as a supported-and-configured surface in the reference deployment (whereupon all five become Pass automatically), or scope them out with a stated precondition.

**Why:** The prior assessment marked all of V9 + V10 (43 requirements) N/A on "no JWT, no OAuth/OIDC". That premise is **false** — `transports/smart.py` performs an OAuth 2.0 `client_credentials` grant with a signed JWT `client_assertion` (RFC 7523), and the closed asymmetric `SignatureAlgorithm` enum with no `None` is hard-enforced at mint and verify. The code is right; it is simply never reached by default. No engineering work is implied — this is a scoping decision.

**Source:** ASVS re-score 2026-07-09, remediation class 1. See #185 on the false blanket-N/A.

---

## 192. Browser ops-console hardening: headers + cookie prefixes

> ✅ **BUILT 2026-07-10 (lane `plan8-192`, commit `070adbd`; PR #888).** Self-contained in `messagefoundry_webconsole` (no engine file touched): a scheme-derived `__Host-` session cookie + `Secure` over effective-https (plain `mf_session` byte-identical on loopback http), a per-response nonce CSP (`'strict-dynamic'`), COOP/CORP `same-origin`, and a `POST /ui/csp-report` reporting endpoint — all via an outermost pure-ASGI middleware; `MEFOR_WEBCONSOLE_DISABLE_BROWSER_HARDENING` is the org opt-out.

**Cluster:** Security & Compliance. **Priority:** P1. **Verdict:** build. **Severity:** high (Posture B).

**Closes (ASVS 5.0 L3):** 3.1.1, 3.3.1, 3.3.3, 3.4.3, 3.4.7, 3.4.8, 3.5.8, 3.7.5 · *(class 2, plus 3.3.1 from class 3)*

**Scope:** For the opt-in `/ui` console (`messagefoundry_webconsole`): rename the session cookie to a `__Host-` prefix and always set `Secure` when the effective scheme is https; add a COOP header (and consider COEP/CORP); add a CSP violation-reporting endpoint (`report-to`); move from a static `'self'` CSP to per-response nonce/hash; add a `Sec-Fetch`-validated resource policy; document a browser-security-feature support contract with a defined warn/block fallback.

**Why:** **This item alone clears five of Posture B's ten Fails** (3.1.1, 3.3.3, 3.4.7, 3.4.8, 3.7.5), and each is a few lines. It is the single highest ratio of Fails-closed to effort in the whole re-score. It also captures the counter-intuitive headline: enabling the hardened browser console *adds* Fails, because it pulls controls into scope that the headless default never has to answer for. `3.3.1` is class-3 in the assessment (its Secure-under-undeclared-proxy half is deployment-delegated) but shares one code change with `3.3.3`, so it is owned here.

**Source:** ASVS re-score 2026-07-09, remediation classes 2 and 3.

---

## 193. Anti-automation: human-timing / minimum-inter-submission pacing floor

> ✅ **BUILT 2026-07-10 (PLAN-9 Wave 2, branch `plan9-auth`).** Anti-automation admin-write pacing floor (ASVS 2.4.2): a per-actor sliding-window limiter (modelled on the existing `phi_read_rate_limit_*` block) folded into `require_step_up` scoped `request.method != "GET"` — every write (POST/PUT/DELETE) is paced (429 + `Retry-After` on breach), while GET/login/PHI-read stay unthrottled and the sole step-up GET `/messages/search` is exempt. Tuned so a legit `403 → /me/reauth → retry` burst is not 429'd. Consumes the self-authored `[auth].admin_write_rate_limit_{enabled,per_actor,window_seconds}` fields; touches only `api/security.py` + `auth/**` (no `api/app.py`).

**Cluster:** Security & Compliance. **Priority:** P2. **Verdict:** owner decision (currently declined-by-design). **Severity:** medium.

**Closes (ASVS 5.0 L3):** 2.4.2 · *(class 2)*

**Scope:** Either build a minimum-inter-submission pacing floor on sensitive admin write flows, or convert the existing "deliberately not implemented" note into a formal, signed risk acceptance against ASVS 2.4.2.

**Why:** A **Fail in both postures.** `docs/SECURITY.md:67-73` documents the absence as deliberate, but a documented decision is not a control, and the 2.4.1 volume rate limiter covers only login and PHI-read — sensitive admin **writes** have no pacing floor at all. The honest options are to build it or to accept it in writing; leaving it as prose in a security doc satisfies neither ASVS nor a reviewer.

**Source:** ASVS re-score 2026-07-09, remediation class 2.

---

## 194. Bind step-up re-verification to the action, not the login window

> ✅ **SHIPPED 2026-07-10 (ADR 0077, PR #873).** Action-bound single-use step-up (process-local (token, action) grant, minted only by reauth(purpose=)) on the factor-enrollment JSON routes — a hijacked session can no longer bind a factor within the login window; opt-out `[auth].require_action_step_up=false`. ASVS 7.5.1 / 8.2.4. Residual: the browser /ui + WebAuthn-register step-up binding (a Wave-1-owned messagefoundry_webconsole follow-on).

**Cluster:** Security & Compliance. **Priority:** P1. **Verdict:** build. **Severity:** high.

**Closes (ASVS 5.0 L3):** 7.5.1, 8.2.4 · *(class 2)*

**Scope:** Require a fresh factor **at the moment of** each sensitive action (MFA config, recovery-code regeneration, admin email edit), not merely a valid login-seeded step-up window. Add an adaptive/contextual signal at session establishment rather than only the binary client-IP-change trigger.

**Why:** This is the most exploitable Partial in the set. Only the *password* prong is action-tied (`verify_current_password`); MFA configuration, recovery codes and admin email edits gate on the **login-seeded step-up window**, so a hijacked session inside that window **can bind an attacker's own second factor** and achieve durable account takeover. The contextual-risk signal that might catch it is advisory-only and opt-in.

**Source:** ASVS re-score 2026-07-09, remediation class 2.

---

## 195. Audit completeness: log all authorization decisions; enforce secret rotation

> ✅ **BUILT 2026-07-10 (PLAN-9 Wave 2).** Both halves landed: **#195a** — every authorization decision is now audited (an `audit_permission_granted` twin beside the existing denial path, scoped to the sensitive/write surface so console polling can't flood the hash-chained audit log, with a documented 16.3.2 read-polling deviation) — merged in the AUTH lane (`plan9-auth`). **#195b** — a `CertExpiryRunner`-style **secret-rotation reminder** (ASVS 13.3.4, ADR 0019 §5.1): a pure, PHI-free `SecretRotationRunner` (label + dates only, never the secret value) emitting `secret_rotation_due` via the AlertSink when a tracked secret is overdue — `plan9-secrets`. Closes 16.3.2 + 13.3.4.

**Cluster:** Security & Compliance. **Priority:** P2. **Verdict:** build. **Severity:** medium.

**Closes (ASVS 5.0 L3):** 16.3.2, 13.3.4 · *(class 2)*

**Scope:** Record a decision row for **successful** non-PHI authorizations, not only denials and sensitive-data-access successes (`api/app.py:831`). Give the store key and backend service passwords a configured expiry with application-enforced rotation and operator reminders, rather than a purely manual `messagefoundry rotate-key`.

**Why:** L3's 16.3.2 clause is "log **all** authorization decisions"; today a successful non-PHI authorization leaves no trace, so an audit cannot reconstruct what a compromised principal was permitted to do. Rotation exists as a mechanism (11.2.2 keyring + `rotate-key`) but nothing expires, reminds, or enforces — so in practice keys never rotate.

**Source:** ASVS re-score 2026-07-09, remediation class 2.

---

## 196. Hardware-backed secrets custody (HSM/KMS/Vault)

> ✅ **BUILT 2026-07-10 (PLAN-9 Wave 2, branch `plan9-secrets`).** External **Vault KeyProvider** (ASVS 13.3.1) — a HashiCorp Vault **Transit** envelope-decrypt of the store DEK (ADR 0019 §3), behind the optional `[vault]` extra (`hvac`, lazy-imported → fail-closed `KeyProviderError` naming the extra when absent; the base install pulls zero Vault SDK). Only the KEK-wrapped DEK sits at rest; the plaintext DEK never persists. Registered by name (no edit to `keyprovider.py`); DEP-1 re-locked.
>
> ✅ **RESIDUAL BUILT 2026-07-12 (connector `SecretProvider`, ADR 0019 §5 promoted).** The connector-secret twin of the KeyProvider seam: `config/secretprovider.py` (a `@runtime_checkable SecretProvider` protocol + `resolve_connector_secret` helper, selected by name via **`[secrets].provider`** = `none`|`env`|`vault`) + the lazy **Vault KV v2** backend `config/secretprovider_vault.py` behind the **same** `[vault]`/`hvac` extra (**no new dependency**). **Wired end-to-end:** the **AD LDAP bind password** (`[auth].ad_bind_password_secret` → `auth/ldap.py`) and the **SMTP password** (`[alerts].email_password_secret` → the alert sink + security notifier). Default (`provider=none`, no `*_secret` reference) = **env-sourced, byte-identical**. Fail-closed: a reference with no provider / a missing extra / an unresolvable secret raises `SecretProviderError` at load/connect (never a blank credential; the value is never logged). **Seam-only (documented, not wired):** the **SQL Server auth password** — integrated/Entra managed identity is the preferred SS posture (`require_managed_identity`), so a static password there is the fallback case; adding an `[store].password_secret` credential point is a mechanical follow-on through the same helper. Does **not** close ASVS 13.3.3 (the unwrapped DEK in heap is #198).

**Cluster:** Security & Compliance. **Priority:** P2. **Verdict:** build. **Severity:** medium.

**Closes (ASVS 5.0 L3):** 13.3.1 · *(class 2)*

**Scope:** Promote the `[store].key_provider` seam (ADR 0019) from design-stub to a shipped, tested integration for at least one external provider, and generalize it to a connector **SecretProvider** so AD/SQL/SMTP credentials stop being env-sourced.

**Why:** No hardware-backed vault exists in shipped code — the external providers fail closed, leaving env vars plus machine-bound DPAPI as the managed residual. L3's HSM requirement is simply unmet. Note this does **not** close 13.3.3: even with a provider, the unwrapped DEK sits in process heap during bulk AES-GCM (see #198).

**Source:** ASVS re-score 2026-07-09, remediation class 2. Depends on ADR 0019 §5.

---

## 197. Runtime sandbox for admin-authored Router/Handler code

> ✅ **SHIPPED 2026-07-10 (ADR 0087, PLAN-9 Wave 3).** Opt-in `[sandbox]` subprocess isolation built: `mode=off` (default) runs Routers/Handlers in-process **byte-identically, zero overhead**; `mode=subprocess` runs each inbound's Router/Handler in a **persistent per-inbound worker child** (`pipeline/sandbox.py` + `_sandbox_worker.py`; stdlib-only, no new dep — RestrictedPython rejected), never a per-message fork. The OS-process boundary denies admin code reach to the parent DEK/audit-chain/sockets (the child loads only the message *graph*); plus a forbidden-import guard (socket/store/crypto), a parent-enforced wall-clock cap (+ POSIX `RLIMIT_CPU`/`RLIMIT_AS`), and a **fail-closed** refusal of the live `db_lookup`/`fhir_lookup` bridges. Interposed at the `route_only`/`transform_one` seam (the in-process `mode=off` path composes with the ADR 0072 tracer; `mode=subprocess` bypasses the tracer — see residuals); engine-side handler/outbound-name validation stays engine-side; a denial → `ERROR`/dead-letter **post-ACK** (no NAK, never dropped). Wired live through `wiring_runner`/`engine`/`app`; RunContext re-marshalled across the boundary. **Closes the WP-L3-17 (ASVS 15.2.5) residual** (residual-closure — `ASVS-L3-REMEDIATION-PLAN.md` + `THREAT-MODEL.md` flipped). **Deferred residuals:** default-off (opt-in); the ADR 0072 protocol-tracer is not forwarded across the subprocess boundary (`mode=subprocess` bypasses it; `mode=off` composes); `db_lookup`/`fhir_lookup` forward-over-IPC (sandboxed live-enrichment Handlers run `mode=off`); load-time top-level config exec not sandboxed (unchanged safe-source DACL gate); least-privilege service account default is environment-delegated.

**Cluster:** Security & Compliance. **Priority:** P3. **Verdict:** build (large). **Severity:** high (blast radius), low (likelihood).

**Closes (ASVS 5.0 L3):** 15.2.5 · *(class 2)*

**Scope:** Hard isolation — in-process, subprocess, container, or network — of admin-authored Router/Handler Python from the in-memory encryption key and the audit-integrity chain.

**Why:** **This is the heaviest residual in the assessment, and the prior doc scored it Pass.** There is no hard sandbox in any posture: a compromised or malicious Handler runs in the same process and under the same account as the DEK and the audit chain, and is one call from both. The prior assessment justified a Pass with an OR-list of adjacent mitigations (fail-closed egress allowlist, read-only `db_lookup`, parser caps, the one-way import boundary). Under strict scoring, listing adjacent controls does not satisfy a requirement that asks for a sandbox. Tracked deferred-by-design in `THREAT-MODEL.md`; this item makes the deferral explicit and costed.

**Source:** ASVS re-score 2026-07-09, remediation class 2.

---

## 198. In-use memory protection: zeroization, mlock, and the unwrapped-DEK residual

> ✅ **CLOSED 2026-07-13 — code-partial + documented deployment-requirement risk-acceptance (owner partial-accept, NOT a full technical close).** The honest disposition of an item that pure-Python cannot fully close: **(1) code-feasible half BUILT** — best-effort `mlock`/`VirtualLock` + `memset`-zeroize of **every** key/plaintext buffer the cipher owns as a *mutable* `bytearray` (the unwrapped DEK, retired decrypt-only keys, and the `encrypt`/`decrypt` plaintext buffers) landed in `store/crypto.py` (`_install_key`/`_secure_zero`/`_lock_memory`), fail-safe (a lock/wipe failure degrades, never raises or corrupts) and `mfenc:v1` byte-identical; a full-path zeroize-verification test pins every owned secret buffer ends all-zero (`tests/test_store_encryption.py`). **No additional code-owned mutable buffer remains to wipe** — the residual copies are CPython-**immutable** `str`/`bytes` (caller plaintext, the returned ciphertext-only marker, `cryptography`'s `decrypt()` output, the transient `bytes(dek)` constructor copies) + OpenSSL's internal `EVP` key copy, all unreachable to scrub. **(2) 13.3.3 = best-effort partial + accepted residual; 11.7.2 = active on a keyed instance (already true); 11.7.1 (full in-use memory *encryption*) = ACCEPTED as a stated DEPLOYMENT REQUIREMENT** (disabled/encrypted swap, restricted local admin, confidential-compute host where memory forensics is in scope — [PHI.md §10](PHI.md#10-secure-deployment--operations-checklist), [SECURITY.md](SECURITY.md) "In-use memory protection") with a signed risk-acceptance (ASVS-L3-RISK-ACCEPTANCE-REGISTER.md theme 5). The ASVS scorecard verdicts (13.3.3 Fail / 11.7.1 Fail / 11.7.2 Partial) are **unchanged** — an accepted risk stays an unmet requirement; what changed is that the gap is owned, dated, and scheduled for review. _Re-scored 2026-07-10 → P2 (Value 6 · Difficulty 6, big bet; ASVS 5.0 L3 re-score, PR #854)._

**Cluster:** Security & Compliance. **Priority:** P3. **Verdict:** owner decision — **partial-accept (code-partial + documented deployment-requirement risk-acceptance)**. **Severity:** medium.

**Build history.** *Partial build (PLAN-9 Wave 1, 2026-07-10 — branch `plan9-secmem`):* best-effort `mlock`/`VirtualLock` + `memset`-zeroize of the unwrapped DEK and the plaintext buffers the code owns landed in `store/crypto.py`; `mfenc:v1` ciphertext byte-identity is preserved and the public cipher seam is unchanged. *Close (2026-07-13):* the partial was verified complete against the full code-owned mutable-buffer surface (DEK + retired keys + `encrypt`/`decrypt` plaintext — no further mutable buffer remains to wipe), a full-path zeroize-verification test was added, and the residual disposition was documented and risk-accepted (see the banner). The residual is a documented *partial* of ASVS 13.3.3, not a technical close: CPython immutable `str`/`bytes` (caller plaintext, the returned marker, cryptography's `decrypt()` output) and cryptography's internal OpenSSL key copy are unreachable to wipe (documented in the module docstring), and **11.7.1** full in-use memory encryption is a host/hypervisor deployment requirement accepted via signed risk-acceptance, not code.

**Closes (ASVS 5.0 L3):** 11.7.1, 11.7.2, 13.3.3 · *(classes 2 and 4)* — **scope addressed, not verdict**: 13.3.3/11.7.1 remain **Fail** and 11.7.2 **Partial** (accepted with a deployment requirement + signed risk-acceptance, see banner), not passing.

**Scope:** Add zeroization of plaintext PHI and key material after use, and mlock-style anti-swap protection where the platform allows. Decide the disposition of full memory encryption (TME/SGX/SEV, confidential VM) — enforce as a deployment requirement, or accept and document.

**Why:** Plaintext PHI persists in heap for the whole processing window with no zeroization, and the unwrapped DEK is resident during bulk AES-GCM — so 13.3.3 is a **Fail even with an external key provider configured**, which is precisely the residual the prior doc's conditional-Pass concealed. Full memory encryption (11.7.1) is arguably host/hypervisor territory rather than application code; the honest close is a stated deployment requirement plus a signed acceptance for the application-layer remainder. 11.7.2's guarantee is only active on a keyed instance at all.

**Source:** ASVS re-score 2026-07-09, remediation classes 2 and 4.

---

## 199. Input-handling hardening: CSV escaping, content sniff, cleartext-egress refusal

> ✅ **SHIPPED 2026-07-10 (PR #871).** Cleartext-`http://` egress refused to non-loopback hosts across all four HTTP destinations (opt-out `MEFOR_ALLOW_INSECURE_TLS`; loopback exempt), RemoteFileSource HL7 content-sniff (content_type-gated), and CSV formula-injection escaping in the engine codeset writer + acceptance harness — ASVS 1.2.10 / 5.2.2 / 12.2.1.

**Cluster:** Security & Compliance. **Priority:** P2. **Verdict:** build. **Severity:** medium.

**Closes (ASVS 5.0 L3):** 1.2.10, 5.2.2, 12.2.1 · *(class 2)*

**Scope:** Add leading-quote formula-injection escaping to the engine codeset CSV writer (`codeset_edit.py:445-455`) and the acceptance harness — it exists only in the load-test harness. Give `RemoteFileSource` the `_looks_like_hl7` accept-time content check the local source has. **Refuse** a plaintext `http://` outbound REST/SOAP/FHIR/DICOMweb destination that carries no `Authorization` header, instead of permitting PHI over cleartext.

**Why:** 12.2.1 is the serious one: today the engine will happily ship PHI to a plaintext `http://` destination with no refusal and no warning — safety depends entirely on the operator choosing `https`. Formula injection (1.2.10) is low-risk because codeset cells are operator code/description rather than PHI, but the L3 clause is unconditional.

**Source:** ASVS re-score 2026-07-09, remediation class 2.

---

## 200. Transport enforcement: make the code refuse the insecure hop

> ✅ **SHIPPED 2026-07-13 (ADR 0092 + 2026-07-13 amendment) — the posture-keyed transport-hop refusal and ALL its DEFERRED residuals are closed.** The core (2026-07-11): the #200 cleartext-hop refusal **enforces on the primary `serve`/`reload` path, not only at `build_check`** — the live connector-build sites in `pipeline/wiring_runner.py` (`_start_outbound`, `_start_inbound_unsafe`, `_reconcile_outbounds`) stamp the derived `active_hop_posture`, so the raw-TCP/X12/MLLP/DICOM/anon-ftp guards **refuse a production-PHI cleartext outbound at serve**, and the strict verify-off cells (engine⇄store weakened TLS, MLLP/FTPS `tls_verify=false`, credentialed plain-ftp) route `MEFOR_ALLOW_INSECURE_TLS` through the **production-PHI clamp** (`config.settings.weakened_tls_escape_permitted`) so the escape can no longer relax a production-PHI hop. **Residuals now closed (2026-07-13):** (1) the **API PHI-read data-path guard** — `create_app` derives the API serve-hop disposition via the new pure `tls_policy.phi_read_hop_disposition` (reusing the ONE authority + the production-PHI clamp) and `api/security.enforce_phi_read_hop` (folded into `require_phi_read`; explicit on the step-up `search` route) **refuses (403, PHI-free)** a raw-view/attachment-download/summary read on a prod-PHI instance whose serve hop is not proven secure — loopback/TLS/proxy-terminated/synthetic/no-`[ai]` stay byte-identical; (2) the **`db_lookup`/`fhir_lookup` live-read posture stamp** — `_build_lookup_executor`/`_build_fhir_lookup_executor` now wrap construction in `active_hop_posture(self._hop_posture)`, so a prod-PHI weakened-TLS live read is refused (it previously keyed on the UNCLAMPED escape, posture unstamped) and a synthetic cleartext read is no longer false-closed; (3) **`messagefoundry check`** now runs the posture-stamped `build_check_registry` (new required `build-check` in `checks.py`; fail-safe SKIP with no `messagefoundry.toml`), so a prod-PHI cleartext hop is caught at commit/CI; (4) the **Posture-B tails** — a cert-authenticated `GET /service/identity` writes a `service_cert_auth` audit row, a real mutual-TLS handshake is handshake-tested (**corrected 2026-07-29:** the companion "runtime-KEX enforcement" claim here was wrong — `SSLContext.set_groups` is a Python 3.15 API, so `harden_kex_groups` pins nothing on today's interpreters and the test that asserted the FFDHE refusal self-skipped; measured, the context ACCEPTS ffdhe2048. Both fixed and the residual is now asserted — see the ADR 0092 2026-07-29 amendment and PHI.md §4). All compose with the #201 revocation guard / #199 cleartext-egress / #129 expiry-relaxation and never double-refuse a legitimate lane. Tests: `tests/test_hop_refusal_residuals.py` + `tests/test_api_tls.py`. **Genuinely deferred (infra-bound):** a full uvicorn-on-a-real-socket mTLS handshake through the live serve bind (Windows TLS CI legs) — the handshake tests exercise the same `build_api_ssl_context` context, so only the uvicorn wiring is uncovered. _(Re-scored 2026-07-10 → P2; filed by the ASVS 5.0 L3 re-score, PR #854.)_

**Cluster:** Security & Compliance. **Priority:** P2. **Verdict:** build. **Severity:** medium.

**Closes (ASVS 5.0 L3):** 4.2.1, 4.4.1, 11.6.2, 12.1.3, 12.2.2, 12.3.1, 12.3.3, 12.3.5 · *(class 3)*

**Scope:** Extend the existing exposed-gate pattern (which already refuses a non-loopback plaintext bind) to the remaining unencrypted and unauthenticated paths: the Posture-B proxy→engine cleartext `ws://` / `http://` hop, the `--allow-insecure-bind` escape, mTLS as an *identity* rather than a bare admission gate, KEX/cipher validation when TLS is proxy-terminated, and cert-authenticated (rather than IP-trusted) intra-service auth.

**Why:** Eight cells, one theme: the controls are built but **delegated and merely documented**, so the engine never fails closed when the precondition is absent. In the recommended off-loopback topology (`tls_terminated_upstream`) `build_api_ssl_context` never runs, so the engine neither builds nor validates the KEX its own docs specify; the internal proxy→engine WebSocket hop is cleartext; and intra-service auth is an opaque bearer token, not PKI mutual auth. The engine cannot encrypt a same-host loopback hop, but it *can* refuse to start when the topology it was told to expect is not actually present.

**Source:** ASVS re-score 2026-07-09, remediation class 3.

**Partial build (PLAN-9 Wave 2, 2026-07-10 — branch `plan9-tls`):** the **fail-closed core is BUILT and live** — an off-loopback **Posture-B** bind now **refuses to start** (`return 2`) on production PHI unless the operator affirmatively declares both the proxy→engine intra-service-auth posture (`[api].proxy_intra_service_auth`) and the proxy TLS/KEX floor (`proxy_tls_min_version`), attestations made fail-closed like the `require_mfa` ladder; `--allow-insecure-bind` provably cannot bypass it (it lives only in the mutually-exclusive no-TLS arm); loopback/synthetic start byte-identically. The **mTLS-as-Identity** resolver ([ADR 0083](adr/0083-mtls-client-certificate-identity.md)) is deny-by-default, `CERT_REQUIRED`-rooted, and spoof-resistant. **mTLS-identity is now ACTIVATED** (PLAN-9 Wave 3, branch `plan9-tlsact`): a fork-free scope-populating shim (`api/tls_client_cert.py` — a uvicorn protocol subclass reading `getpeercert()` in `connection_made`) surfaces the verified peer cert under the pinned uvicorn, and `resolve_client_cert_identity` is wired behind a **cert-only, PHI-fenced** `require_service_cert` dependency on `GET /service/identity` — a cert-mapped Identity (even a full admin) is provably **401'd on any PHI/step-up route** (tested), never bypassing `require_step_up`/`require_mfa`; loopback/no-mTLS stay byte-identical. **Item stays OPEN** pending the remaining gaps: a real-socket uvicorn+mTLS **integration test** (activation is unit-verified, not yet handshake-tested — it would guard two uvicorn internals against version drift), an **audit event** on successful cert auth, and true runtime KEX enforcement (vs the operator attestation shipped here).

---

## 201. Certificate revocation checking (OCSP/CRL)

> ✅ **SHIPPED 2026-07-10 (ADR 0078, PR #872); OUTBOUND residual shipped 2026-07-12 (ADR 0078 amendment).** Enforced start-time revocation refusal for off-loopback in-process API TLS unless proven in front (trusted TLS-terminating proxy) or attested (opt-out `MEFOR_TLS_REVOCATION_ATTESTED=1`); no in-engine OCSP (stdlib has none). ASVS 12.1.4 documented-residual → enforced-delegation. **Residual now built:** the same posture-keyed refusal (`revocation_hop_disposition` + `RevocationHopGuard` in `config/tls_policy.py`) extends to the **OUTBOUND verifying-TLS** connectors — MLLP-over-TLS egress, the REST/SOAP/FHIR/DICOMweb https paths (`refuse_unrevoked_verified_hop`), SMTP-over-TLS email (`RevocationHopGuard` directly — smtplib is a different seam), and the Postgres asyncpg store hop (`_refuse_store_revocation`); per-connection `tls_revocation_attested` + the blanket env are the opt-outs, composing with #200 (fires only on a VERIFYING hop, never double-refuses). **Still out of scope (documented):** DICOM-SCU/FTPS verifying contexts, the FhirLookup read path, SQL-Server/SChannel (already OS-managed). Still no in-engine OCSP — by design.

**Cluster:** Security & Compliance. **Priority:** P1. **Verdict:** build. **Severity:** high.

**Closes (ASVS 5.0 L3):** 12.1.4 · *(class 3)*

**Scope:** Either in-engine OCSP stapling / CRL validation on every verifying TLS context, or a hard start-time refusal unless a revocation-checking proxy is proven in front.

**Why:** **The single most important item in the deployment-enforced class, and a Fail in both postures.** No OCSP/CRL checking exists anywhere in the codebase. `VERIFY_X509_STRICT` is *chain strictness, not revocation* — the prior assessment scored this a conditional Pass on exactly that conflation. Today **a revoked-but-chain-valid peer certificate is accepted**, and the proxy delegation that supposedly covers it is neither configured in the reference deployment nor enforced by the engine.

**Source:** ASVS re-score 2026-07-09, remediation class 3.

---

## 202. Off-box log/audit forwarding: default-on, TLS transport, synchronized time

> ✅ **SHIPPED 2026-07-10 (ADR 0080, PR #874).** Native TLS-syslog (`forward_protocol=tls`, verified, bounded), forwarding default-on when a collector host is configured (opt-out `forward_enabled=false`; no-collector installs byte-identical), and an opt-in startup time-sync gate — ASVS 16.4.3 / 16.2.2.

**Cluster:** Security & Compliance. **Priority:** P1. **Verdict:** build. **Severity:** high.

**Closes (ASVS 5.0 L3):** 16.4.3, 16.2.2 · *(class 3)*

**Scope:** Default `[logging].forward_enabled` on (or mandate it in the exposure runbook), add native TLS-syslog so the transport is not plaintext, and add a startup time-source synchronization check with a skew alarm or refuse-to-run gate.

**Why:** The forwarder + audit-tee ship, but forwarding is **off by default and the off-loopback runbook never turns it on**, so no independent copy of the audit trail survives a host compromise — which is the entire point of the control. The syslog transport is plaintext with no native TLS. 16.2.2's "time sources synchronized" conjunct is neither implemented nor enforced (no startup check, skew alarm, or gate), and it is materially applicable given multi-host engine-shard deployments where audit ordering across hosts depends on it.

**Source:** ASVS re-score 2026-07-09, remediation class 3.

---

## 203. Delegated identity + admin device posture: enforce or state the precondition

> ✅ **SHIPPED 2026-07-11 (PR #920).** Opt-in `[store].require_managed_identity`: `serve` refuses (production) / warns (non-production) unless the store uses a managed/delegated identity (SQL Server `auth=integrated`/`entra`); SQLite exempt, Postgres cannot satisfy it. The delegation boundary (device posture stays deployment-delegated; AD/SMTP secrets stay env-supplied) is documented in `docs/SECURITY.md`. The "enforce" reading of enforce-or-state.

**Cluster:** Security & Compliance. **Priority:** P3. **Verdict:** owner decision. **Severity:** medium.

**Closes (ASVS 5.0 L3):** 13.2.1, 13.3.2, 8.4.2 · *(class 3)*

**Scope:** Prefer gMSA/Entra managed identity over long-lived static passwords for AD/SQL/SMTP (today the token option is SQL-only and operator-activated). Make least-privilege secret access a checked precondition rather than an assumption. Decide whether admin device-posture assessment stays 100% deployment-delegated (proxy mTLS + MDM) or becomes an engine-checked gate.

**Why:** Three cells whose controls are genuinely the organization's to provide, but which the engine currently neither checks nor refuses to run without. The honest close is either a start-time precondition check or an explicit statement of the delegation boundary in the exposure runbook — not silence.

**Source:** ASVS re-score 2026-07-09, remediation class 3.

---

## 204. Enforce lookup-input encoding, content scanning, and SMART AS assumptions

> ✅ **SHIPPED 2026-07-12 — all three parts closed.** **(1) Encoding (ASVS 1.2.2):** the `fhir_lookup` injection path is closed by the safe structured `params=` search form (shipped in #870) — each value is percent-encoded (`urlencode(quote_via=quote, safe="")`), so an HL7-derived value like `"123&_count=99999"` becomes a single literal `identifier` value and can never inject an extra FHIR search parameter (`transports/fhir.py::_encode_search_params`/`_resolve_read_url`, tested in `tests/test_fhir_lookup.py`). The flat `?`-query form stays a documented author-responsibility escape hatch (defense-in-depth-screened for `#`/second-`?`/control chars), the FHIR analog of raw-SQL-string vs bound `db_lookup` params. **(2) Content-scan contract (ASVS 5.4.3):** the pre-ingest scan-hook seam (shipped in #199) is now an **enforced, fail-closed precondition** on both the local `File(...)` and remote `Sftp/Ftp(...)` sources — a `ScanRejected` quarantines to `.error`, and a scanner **malfunction** (any other exception — AV/ICAP unreachable, a plugin bug) also fails closed: the file is never emitted and is left in place to re-scan (this change, `transports/file.py`/`remotefile.py`, tested). **No ICAP client is bundled** — that stays an operator/plugin integration; the contract + trust boundary is documented in [CONNECTIONS.md](CONNECTIONS.md#file-handling--quarantine-policy-asvs-511). **(3) SMART AS boundary (ASVS 10.4.16):** `private_key_jwt` *enforcement* is documented in [SECURITY.md](SECURITY.md) as the **authorization server's responsibility** — the client engine only *presents* the assertion — an explicit trust boundary. _(was P2 · re-scored 2026-07-10; filed by the ASVS 5.0 L3 re-score, PR #854.)_

**Cluster:** Security & Compliance. **Priority:** P2. **Verdict:** build. **Severity:** medium.

**Closes (ASVS 5.0 L3):** 1.2.2, 5.4.3, 10.4.16 · *(class 3)*

**Scope:** URL-encode `fhir_lookup` query **values** in the engine rather than delegating it, unenforced, to the Handler author. Define the AV/ICAP scanning contract for the file drop directory as an enforced precondition rather than an operator-provided hook. State the SMART authorization-server assumptions (private_key_jwt enforcement is the AS's job) as an explicit, documented trust boundary.

**Why:** 1.2.2 is a live injection path: `fhir_lookup` query values after `?` ride **verbatim** (`fhir.py:512-515`, only control characters screened), so an **HL7-derived value** — attacker-influenceable data — can inject additional FHIR search parameters. It is bounded today only by the pinned host, GET-only, and read-only posture; that is defense-in-depth, not encoding. Fix the encoding at the boundary, per CLAUDE.md §5's rule that inbound HL7 is untrusted data before it reaches a downstream message.

**Source:** ASVS re-score 2026-07-09, remediation class 3.

---

## 205. Documented risk acceptances (ASVS L3 residuals)

> ✅ **SHIPPED 2026-07-11 (PR #924).** The risk-acceptance register is drafted at `docs/security/ASVS-L3-RISK-ACCEPTANCE-REGISTER.md`: every residual ASVS L3 Partial/Fail/N-A grouped by theme with reason, compensating controls, and a re-score trigger, plus per-theme sign-off blocks. Acceptance does **not** change scorecard status (residuals stay Partial/Fail); the **owner signature** is the one remaining act (placeholders provided). Companion to the assessment + remediation plan.

**Cluster:** Security & Compliance. **Priority:** P1. **Verdict:** accept + sign off. **Severity:** low.

**Closes (ASVS 5.0 L3):** 7.1.1, 7.5.2, 11.3.3, 13.4.7 · *(class 4)*

**Scope:** Produce a signed risk-acceptance record for four residuals whose design decisions are defensible and whose remediation cost exceeds the benefit. Cheap, and it is what converts "we didn't do it" into "we decided not to do it".

**Why:** Each is small and deliberate. **7.1.1** — the session-timeout doc states values and operational rationale but omits the NIST SP 800-63B citation and justification-of-deviations the requirement's third prong asks for (a documentation fix, not a code one). **7.5.2** — terminating *other* sessions does not force a fresh factor, explicitly by design. **11.3.3** — the at-rest cipher passes `None` AAD (`store/crypto.py:162`) so ciphertext is not bound to its `(table, column, row)` context; impact is low because the row is already integrity-chained, but a cut-and-paste of ciphertext between rows is not detected by the cipher itself. **13.4.7** — the console asset directory relies on curation (a fixed 2-file dir) plus traversal protection rather than an explicit extension allowlist.

Note the honest framing: an accepted risk is still an unmet requirement. These four stay **Partial/Fail** on the scorecard after acceptance; what changes is that they are owned.

**Source:** ASVS re-score 2026-07-09, remediation class 4.

---

## 206. Fix the harness target: gate on total events, not ingress

> ✅ **SHIPPED in #861 (2026-07-10).** The shard-cert ladder now gates on **total events** (`TARGET_EVENTS_PER_S`), not ingress — verified merged (commit 96cd1aa, ancestor of `origin/main`). The re-score fact-check found the item's central claim stale: nothing left to build.

**Cluster:** Throughput & Scale. **Priority:** P1. **Verdict:** build. **Severity:** high.

**Scope:** 🧠 **ULTRACODE** — this redefines the pass/fail gate, so a wrong version silently re-publishes a phantom. `harness/load/shardcert_ladder.py` defines `TARGET_INGRESS_PER_S = 45_000_000 / 86_400` and gates on `pinned_ingress_rate >= TARGET_INGRESS_PER_S`, comparing an **ingress** rate against a **total-events** budget. Change the gate to `ingress_rate × (1 + dests) >= 520.83`, fix the module docstring (which states the wrong reading explicitly), and restate every published figure in total events/s.

**Why:** 45M/day counts every message the engine handles inbound **and** outbound = **520.83 total events/s**; `total events = ingress × (1 + dests)`. The current gate is `(1 + dests)`× too strict — **9× at the bench** (`dests=8`) — and this single defect inflated every "we are ~52× short" statement by a factor of 9. Owner ruling 2026-07-10: the target is a flat, sustained 520.83 events/s, HL7 in/out only.

**Source:** 2026-07-10 throughput audit, §2 (B10) and the units defect box.

---

## 207. txn/msg and bytes/msg counters in the harness

> ✅ **SHIPPED — verified against `origin/main` (2026-07-28).** Closed by [ADR 0141](adr/0141-publish-copies-per-message-as-the-207-sizing-proxy-the-bytes-per-message-figure-stays-refused.md), **Accepted 2026-07-20**, whose own text names this item — *"BACKLOG **#207** (this closes it)"* (`:10`). **txn/msg is measured, not modelled:** the engine-side counter is `Store.committed_txns` (`messagefoundry/store/base.py:220-233` — write-path commits only; read-snapshot-release commits are excluded so it stays the currency ADR 0051 sizes on), self-differenced over the run into `EngineSummary.committed_txns` + `txn_per_message_measured` (`harness/load/report.py:112-113`, `:676-682`). A zero delta reports `None` — *"not measured"* — rather than a fabricated `0/msg`. ⚠️ **Backend caveat:** the counter is **not wired on PostgreSQL** — `messagefoundry/store/postgres.py:793` hardcodes `self.committed_txns = 0` (its commits happen implicitly inside scattered `conn.transaction()` blocks; live wiring is a separate pass), so on a Postgres run both figures degrade to *"not measured"* rather than being measured. SQLite and SQL Server report real values. **The second counter resolved differently, by design:** `bytes/msg` **stays refused**; `body_copies` / copies-per-message ships as the sizing proxy instead (`harness/load/report.py:114`, `:132`; `SCHEMA_VERSION = 3` at `:24`). That is the ADR's decision, not an unbuilt residual. _(was 🔢 P2 · Value 5/10 · Difficulty 4/10.)_

**Cluster:** Throughput & Scale. **Priority:** P1. **Verdict:** build. **Severity:** medium.

**Scope:** 🔍 **FABLE REVIEW** — instrumentation plumbing; a wrong counter is caught by a diff review and a test, and the first published value is ULTRACODE-verified where it is reported (#211/#215). Add two per-run counters: **`txn/msg`** (committed transactions per message) and **`bytes/msg`** (durable bytes written per message).

**Why:** Both are first-class parity numbers the incumbent publishes outright, and **neither has ever been measured by MessageFoundry.** `txn/msg` is the currency the disk actually serves (cost model `txn/msg = 3 + 2H + 2N`). `bytes/msg` is checkable against the incumbent's stated budget of **10.9 KB/message** (`500 GB/day ÷ 45M`) — the number that sizes the 15 TB / 30-day drive an adopter is told to buy. `ingress` and `routed` rows each hold a full raw-body copy (`store.py`), so write volume scales as `(1 + H + N)`; the ADT hub writes 25 rows, 21 raw copies.

**Source:** 2026-07-10 throughput audit, §3 (Phase 0) and §7 (storage amplifier).

---

## 208. Fix the per-PID engine CPU collector (attribution is blind without it)

> ✅ **CLOSED — shipped 2026-07-20. The in-repo work is done; the residual is OFF-REPO and no in-repo change can close it.** The blocking premise — *"no engine CPU verdict is admissible until it reads true"* — is discharged: an admissible **aggregate** engine-CPU verdict already exists and exonerates the engine, bounding it at **≤ 0.36 cores per shard** (`docs/benchmarks/PLAN-ENGINE-ATTRIBUTION.md:81`, `:280`, which recommends closing this item as superseded and cites the `py_all_cpu%` bound). Per-PID attribution would refine a number already known to be small, so it was **killed as a soak slot**; two things survived and were folded in — the engine exoneration itself, and `store_service_ms = claim_mean_ms − acquire_wait_mean_ms`, the first split of a store round-trip into engine-side pool queueing vs real store service (carried with its own caveat: `acquire_wait` is one global histogram across ~68 call sites, so that subtraction is an estimate, not an identity).
>
> ⚠️ **Deliberately published without a sizing figure.** Any residual here is **off-repo measurement**; this ledger states no implementation estimate for it, because a prior sizing claim was refuted and repeating one would re-invite the build. **Related but separate:** [#220](#220-cpu-delta-is-differenced-across-a-subtree-that-can-change-between-ticks) — the harness-side same-PID-set CPU differencing — is a distinct item and is shipped. _(was 🔢 P2 · Value 7/10 · Difficulty 6/10.)_

**Cluster:** Throughput & Scale. **Priority:** P1. **Verdict:** build. **Severity:** high.

**Scope:** 🧠 **ULTRACODE** — its failure mode is a **plausible-but-wrong CPU number**, the exact B-class disease, and **no CPU verdict is admissible until it reads true**; it sits on the critical path to the shard probe (#218) and gates every CPU-attributed rig verdict, so the fixed sampler must be adversarially reconciled against the whole-box telemetry, not merely diffed. Restore the per-process engine CPU collector so it reports real utilization per engine PID instead of a constant `0.00`, and validate it by reconciling the per-PID sum against the whole-box counters (engine p95 88.4% / max 91.9% on the sustained `per_lane` 28/s run) to within sampling error — it must not still read `0.00` or a constant under any run whose whole-box CPU is demonstrably > 50%.

**Why:** Attribution today is **rigorous store-side and blind engine-side** — the per-PID collector reads `0.00` on the SQL Server rig, so a GIL-bound core cannot be formally excluded, only circumstantially. **No CPU claim is admissible until this is fixed** (open question #4). It is also a hard prerequisite for #215: on a bigger box with more shard processes, whole-box percentages alone cannot attribute anything.

**Source:** 2026-07-10 throughput audit, §4 honest caveat and §8 open question #4.

---

## 209. Teach the ladder routed_fanout ≠ delivered (H ≠ N)

> ✅ **SHIPPED (code) — verified against `origin/main` (2026-07-28).** The `H = N = dests` hardwiring is gone: `dests` now keeps **one** meaning (topology), while `handlers` (H) and `delivering` (D) are separate inputs — `harness/load/shardcert_ladder.py:875-878`, `:1063-1064`, `:1154-1155`, with `schema_version` 4 adding the two fields (`:55`). Delivery arithmetic is keyed on `delivering`, **never** `dests` (`outbound_rate`, `:807-810`; the module contract states it at `:39-41`), and `txn_per_message` reports `3 + 2H + 2D` (`:1318-1320`, `:1806-1808`, `:2503`). Defaults reproduce the old shape exactly, pinned by `tests/test_shardcert_config.py:154+` including `test_default_shape_is_byte_identical` (`:172`). ⚠️ **Residual is bench time, not code:** the `H = 20` hub-shape rig run is a soak-slot ask against rig capacity the project does not own — it does not reopen this item. _(was 🔢 P2 · Value 6/10 · Difficulty 5/10.)_

**Cluster:** Throughput & Scale. **Priority:** P2. **Verdict:** build. **Severity:** medium.

**Scope:** 🧠 **ULTRACODE** — this changes the measurement semantics of the instrument (which shape it models), and the wrong shape yields the wrong ceiling. Teach the ladder to drive `routed_fanout ≠ delivered` — a handler count `H` independent of the destination count `N`, exercised at the production hub shape `H=20, N=4`. Report `txn/msg` and IOPS/msg at that shape.

**Why:** The bench ties one handler to one destination (`routed == delivered`), which **understates transform-stage work by 2.5× and overstates outbound work by 2×** relative to the real ADT hub — and the outbound claim is precisely the wall it went looking for. The reference estate's ADT hub selects **20** handlers and delivers to **~4** (`txn/msg = 51`, of which 32 produce no counted message). *Falsifier:* if the ceiling at `(H=20, N=4)` matches the ceiling at `(8, 8)`, then `H` does not matter and the `2H` thesis is wrong.

**Depends on:** #206 (fixed gate) and #207 (counters, to report `txn/msg` at the production shape).

**Source:** 2026-07-10 throughput audit, §6 (cost model) and §3 (Phase 2).

---

## 210. Remove the tempdb table variables from the pooled claim query

> ⛔ **DECLINED — withdrawn, owner-ratified 2026-07-17.** `docs/benchmarks/THROUGHPUT-STATUS-2026-07-10.md` §Phase 1 (`:652`) says it plainly at `:675` — **"Do not build it."** — and the tempdb rewrite is struck through as **WITHDRAWN** at `:1760`. ⚠️ **Critically, the four table variables are PRESERVED ON PURPOSE — do not "clean them up".** [ADR 0114](adr/0114-phase-4-claim-path-call-complexity-reduction-driver-interface-redesign-ingress-routed-reset-fold.md) redesigned this exact claim path and **deliberately kept** the `@heads` / `@locked` / `@keep` / `@claimed` declarations in the shared probe-then-claim body (`messagefoundry/store/sqlserver.py:702-717`, `_fifo_heads_steps`, implementing ADR 0066 §3.2 with the #285 inversion fix). They are load-bearing for strict per-lane FIFO, not incidental scaffolding. Removing them is a **rejected** design, not an unfinished one. _(was 🔢 P2 · Value 7/10 · Difficulty 7/10.)_

**Cluster:** Throughput & Scale. **Priority:** P1. **Verdict:** build. **Severity:** high.

**Scope:** 🧠 **ULTRACODE** — this rewrites the binding-wall path, and a plausible-but-wrong SQL "improvement" is exactly this programme's failure class; the latency drop must be adversarially verified against the runaway curve. Rewrite the **pooled** outbound claim query to eliminate its tempdb table variables while preserving pooled's connection-scale behaviour. **Do NOT flip `claim_mode` to `per_lane`** (catastrophic at 1,500 lanes — see #211).

**Why:** The engine's binding wall is the pooled outbound claim query's **tempdb-metadata churn**: `claim_mean` **33.6 ms** returning ~1 row, and it is a runaway — 12 → 20 → 33 → 43 → **127 ms** under load. **tempdb table-variables = 43% of the fixed claim cost.** This is NOT engine CPU, NOT store commit bandwidth (store ~27–29k commits/s = 36× headroom), NOT `mark_done`. Removing the table-vars attacks the shipped default path at every lane count — a targeted rewrite, not a mode flip.

**Depends on:** #211 (its lane-count sweep supplies the falsifier — pooled `claim_mean` must rise with lane count — and confirms the churn is scale-driven) and #208 (to attribute the improvement).

**Source:** 2026-07-10 throughput audit, §1 and §3 (claim-runaway row); `outbound-claim-wall.md`.

---

## 211. Claim-mode lane-count sweep (16 → 1,500 lanes) — NOT a default flip

> ✅ **CLOSED — owner-ratified 2026-07-17, as CHARACTERIZATION-ONLY.** The claim-mode A/B was run and its findings are published: `per_lane` sustains ≥ 28 ingress/s at 16 lanes over a 540 s soak, and its per-delivered-row claim cost is **~4.5× cheaper** than pooled (5.6 ms vs 25.03 ms) — `docs/benchmarks/THROUGHPUT-STATUS-2026-07-10.md:256`, `:259` — **but at 1,500 lanes `per_lane` degenerates into a claim storm** (~18k empty `UPDLOCK` claims/s saturating the store at *zero messages*, 92% CPU, `LCK_M_U` convoy 40–70 ms) and **drops messages at high fan-out** (`:664`). §8 stays unflipped and `per_lane` stays off (`:302`, `:654`).
>
> ⚠️ **Two things this closure is explicitly NOT.** It is **not a licence to flip the `claim_mode` default** — the measured 1,500-lane behaviour is the reason the default stands, and the document warns in terms against exactly that flip (`:654`). And it is **not a rig ask**: no further sweep is funded or scheduled. Characterization was the deliverable; it is delivered. _(was 🔢 P2 · Value 7/10 · Difficulty 6/10.)_

**Cluster:** Throughput & Scale. **Priority:** P1. **Verdict:** measure. **Severity:** high.

**Scope:** 🧠 **ULTRACODE** — this interprets rig results and drives a mode decision; the whole programme's failures were confident, self-consistent, wrong numbers. Run the `pooled` vs `per_lane` A/B as a **lane-count sweep** — 16 → 100 → 500 → 1,500 lanes — on the fixed harness at a 900 s soak, recording whole-box **and** per-PID CPU, and find the crossover. **This is explicitly NOT a licence to flip the `claim_mode` default to `per_lane`.**

**Why:** Both modes have a *measured* pathology in **different regimes**: `pooled`'s tempdb churn was measured at **16 lanes**; `per_lane`'s claim storm — **~18k empty `UPDLOCK` claims/s at zero messages, 92% CPU, dropped messages at high fan-out** — was measured at **1,500 lanes** (ADR 0066). `per_lane`'s 4.5×-cheaper claim is real at 16 lanes; `pooled` is the default *because* `per_lane` is untenable at 1,500. Neither number generalises to the other's regime, and the target deployment is ~1,500 connections. *Falsifier:* if pooled's `claim_mean` stays flat as lane count rises, the tempdb churn is not scale-driven and the crossover story is wrong (this also gates #210).

**Depends on:** #206 (fixed gate), #216 (a driver that can reach 1,500 lanes with traffic), #208 (per-PID CPU, so an engine ceiling is not misread as a store one).

**Source:** 2026-07-10 throughput audit, §3 (Phase 1) and the claim-mode inversion note.

---

## 212. fifo_claim_batch: decide the shipped default (verification DONE — it is NOT a no-op)

> ✅ **CLOSED — owner-ratified 2026-07-17. DECIDED: `fifo_claim_batch` SHIPS OFF.** This item asked for exactly one thing — the default decision — and it has been made. **The shipped code already matches the decision:** `fifo_claim_batch: int = Field(default=1, ge=1, …)` at `messagefoundry/config/settings.py:295`, where `1` is documented as OFF and byte-identical to the single `TOP(1)`/`LIMIT 1` claim (the batch method is never invoked); `> 1` stays available as opt-in throughput tuning. **No code change is required to close this.** The rationale is measured, not assumed: the lever prices out at an **upper bound of ~+4.7%** (`docs/benchmarks/THROUGHPUT-STATUS-2026-07-10.md:749`, `:1930`) against the pre-registered **+8% PROCEED bar** ([ADR 0107](adr/0107-phase-4-is-closed-transaction-reduction-is-a-measured-dead-end.md)`:62`), and the published row already marks it *"ships OFF"* (`THROUGHPUT-STATUS §Phase 3(2)`, `:549`). **Revisit only on a latency or store-load rationale — not a throughput one**, which is settled. _(was 🔢 P2 · Value 6/10 · Difficulty 2/10.)_

**Cluster:** Throughput & Scale. **Priority:** P2. **Verdict:** build (decide the default). **Severity:** medium.

### ✅ RESOLVED 2026-07-11 — and this item's original premise was **inverted**

The code read is done (`pipeline/stage_dispatcher.py:797-800`, `pipeline/wiring_runner.py:237`, ADR 0058's own non-goals list). Findings:

1. **The claim is batched; the handoff is not** — one commit per row, by explicit design (ADR 0058: *"the `N`/msg handoff commits remain the floor"*).
2. **But that is exactly what `2H → H+1` describes.** H claim commits collapse to 1; the H handoff commits remain. **`H+1` IS the claim-only figure.** This item (and status-doc open question #3) had it backwards — they treated `H+1` as *conditional on the handoff also batching*. Had the handoff also batched, the cost would be **~2**, not `H+1`.
3. **So "flipping the default is a no-op" is a non-sequitur, and the published 13.6 msg/s lane ceiling was never conditional on anything.** The lever is real: a **~33–37%** txn/msg cut at the H=20 hub.
4. **Correction:** the steady-state cost is `H·(1 + 1/K)`, not a flat `H+1`. **`H+1 = 21` requires `K ≥ H = 20`**; at the shipped guidance **K = 8–16** the hub lands ~34 txn/msg (~33% cut, lane ceiling ~12.7 msg/s).
5. **Scope limit — it is a cost-model lever, not a shard-wall lever.** `per_lane_limit` is hard-clamped to 1 for OUTBOUND/RESPONSE in three layers (`wiring_runner.py:237`, `stage_dispatcher.py:246`, `store/sqlserver.py:4302`), so it **cannot batch the outbound claim** — the one C1/C2/C3 measured. Its contribution to the tempdb churn is **not zero but unmeasured** (see **#227**).

**What remains (the actual work):** decide the shipped default. `default=1` = OFF today. The cut is real but the risks are K-scaled and must be sized, not assumed: **K decrypted PHI bodies resident per lane** between the one claim and the K handoffs (size K against worst-case message size, not average); and in `per_lane` mode (the opt-out) a mid-batch store exception leaves the unprocessed tail INFLIGHT until the next `reset_stale_inflight` (ADR 0058 INV-3). FIFO is **not** at risk — ordering is preserved by construction (in-batch head-of-line drain, prefix truncation at a not-due/locked head, FIFO-neutral tail release, `seq` never re-minted).

**Source:** 2026-07-10 throughput audit §7/§8; **resolved by the 2026-07-11 code read** (status doc §8 Phase 3(2)).

---

## 213. accepts= seam (pure router-stage predicate) plus an advisory lint

> ✅ **SHIPPED — re-verified against `origin/main` (2026-07-28).** The [ADR 0084](adr/0084-accepts-router-seam.md) `accepts=` router-stage seam is built end to end: the `HandlerAccepts` predicate type plus the fail-closed `_check_accepts_predicate` (`messagefoundry/config/wiring.py:2291`, which REJECTS a predicate naming the transform-only `state_get`/`response_get` — those fail *open* in the router phase and would silently invert a migrated suppression filter); `Registry.handler_accepts` (`:2760`, registered `:2817`, validated `:2845-2848`, re-checked on load `:4179-4186`); the component-wise `message_type_of(...)` helper (`:2355`); dry-run parity via `_accepted` (`messagefoundry/pipeline/dryrun.py:206`); sandbox parity (`messagefoundry/pipeline/_sandbox_worker.py:115`); the advisory lint `_check_accepts_candidate` (`messagefoundry/checks.py:388`); and `tests/test_accepts_seam.py` (749 lines). _(was 🔢 P1 · Value 8/10 · Difficulty 7/10 — the highest double-build risk in this reconcile: the banner described ~1,500 already-merged lines as unstarted work.)_

**Cluster:** Throughput & Scale. **Priority:** P1. **Verdict:** build (**ADR 0084 ratified — go**). **Severity:** medium.

> ⚠️ **Re-prioritized 2026-07-11 — this is no longer an optional follow-on to the claim-path work.** The capacity frontier (status doc §8) establishes that **clearing N=16 is necessary but NOT sufficient**: even a fully successful pooled-claim rewrite (#210) leaves the fleet **~1.81× short** of 520.83 events/s at the swept load. The `txn/event` levers therefore have to **compose** with the claim-path fix, not queue behind it — and this seam is the largest of them (estate **4.64 → 3.55** txn/event; ADT hub `txn/msg` **51 → 19**). **Do not sequence this behind C4/the rewrite.**
>
> **ADR 0084 ruling (owner, 2026-07-11):** `FILTERED → UNROUTED` for the all-declined case is **accepted**; the `message_events` declined-handler mitigation is **deferred from v1** and must ride the existing `message_events` verbosity gate (#63) when built. The §9 open items (predicate signature, payload sharing, hot-path cost, error-classification exactness) are **this lane's** to resolve.

**Scope:** 🧠 **ULTRACODE** — it touches the count-and-log invariant and produces a published `txn/msg` reduction, so the design and the number both need adversarial review; it also needs an ADR. Add an **`accepts=`** seam: a pure predicate evaluated in the **router** stage, before any `routed` row is materialized, so declined handlers cost 0 transactions instead of 2. It is a Python callable (does not violate the no-declarative-`Filter` rule), and purity is enforced for free — `db_lookup`/`fhir_lookup` already raise outside a live Handler. Ship a companion **advisory lint** in `messagefoundry check` that flags handlers whose leading statements are pure guards ending in `return None` and prices them.

**Why:** The `2H` term is charged **before** a handler can filter, so a Router filter costs **0 transactions** and a Handler filter costs **2** for the same conceptual act — and the engine gives the author no signal. The reference ADT hub selects 20 handlers, delivers to ~4; **32 of its 51 transactions (63%) produce no counted message**, and all 20 of its gates are pure message-field reads (its `db_lookup` runs inside the transform, after the gate). The seam cuts ADT `txn/msg` **51 → 19 (2.68×)** and that feed's lane ceiling ×5. *Cost:* the per-destination `FILTERED` disposition row disappears — hence the ADR against the count-and-log invariant.

**Depends on:** #209 (production shape modeled, to measure the 51 → 19 benefit).

**Source:** 2026-07-10 throughput audit, §6 (router vs handler filter) and §3 (Phase 3.1/3.3).

---

## 214. Intra-message concurrent transform of a message's routed rows

> 🚧 **PARTIAL — the intra-message transform-overlap mechanism is MERGED and tested; a SEPARATE, UNBUILT XL residual remains (see below). Re-priced 2026-07-28.** The banner's *"routed rows transform sequentially today"* premise is out of date: `RegistryRunner._process_routed_batch` (`messagefoundry/pipeline/wiring_runner.py:4790`) already overlaps the pure off-loop transforms of a message's co-claimed sibling rows, while **every store handoff stays serial and in claim order** — so the single-serial-writer invariant that per-destination outbound FIFO depends on is untouched — and the same cap doubles as the live-lookup (`db_lookup`/`fhir_lookup`) fan-out guard. Covered by `tests/test_transform_concurrency.py` (586 ln). Difficulty **8/10** priced *building* that seam, which no longer needs building.
>
> ⚠️ **Residual (a) — COMMIT-COLLAPSE — is UNBUILT, XL, and ADR-gated. It is NOT a settings field, and this item must not be read as nearly done.** The ~40× headline in the old banner comes from collapsing the serial commit chain, **not** from the transform overlap that shipped — and the banner above concedes the gap itself: *every store handoff stays serial and in claim order*. The code confirms it: `Store.transform_handoff` is **strictly single-row** (`routed_id: str`, `messagefoundry/store/base.py:331-334`), with no batched multi-row variant on any backend. The in-repo plan sizes the remainder as *"one batched multi-row `transform_handoff` per message: extend the `Store` protocol + **all 3 backends**, preserving claim→produce→complete atomicity, FIFO `seq` order and at-least-once"* — **XL, needs a new ADR** (`docs/releases/BACKLOG-EXECUTION-PLAN-2026-07-24.md:129`, open question at `:156`). It is **owner-deferred (2026-07-24)**, not done.
>
> **Residual (b) — DECLINED 2026-07-28: `transform_concurrency` will NOT be exposed as a public setting.** It is deliberately a module constant / instance attribute rather than a `[transform]` settings section, and the code states the reason: *"owner-coordinated; a user-facing knob is a deliberate follow-up"* (`messagefoundry/pipeline/wiring_runner.py:250`, with `_DEFAULT_TRANSFORM_CONCURRENCY = 1` at `:251`). Two facts drive the decline. The benefit is **unmeasured**. And the lever is **triply dark**: the overlap path short-circuits unless concurrency > 1, the run is not fused, and ≥ 2 rows were co-claimed (`wiring_runner.py:4819`) — and co-claiming ≥ 2 rows itself requires `claim_mode="per_lane"` **and** `[store].fifo_claim_batch > 1`, which are set elsewhere and which **#212 decided ships OFF** (`config/settings.py:295`). Public surface that is inert on every default configuration, for no demonstrated benefit, is the wrong trade. **Re-open (b) only on a measured need**; (a) needs an owner go and an ADR. _(was 🔢 P2 · Value 5/10 · Difficulty 8/10 · _money pit_. Difficulty stays high — (a) is the reason.)_

**Cluster:** Throughput & Scale. **Priority:** P3. **Verdict:** build. **Severity:** low.

**Scope:** 🧠 **ULTRACODE** — a new engine concurrency primitive whose ordering-safety and speedup both require adversarial verification. Transform the multiple `routed` rows of a **single** message concurrently while preserving message-level FIFO, instead of the current sequential `for item in items:` handoff loop.

**Why:** The 20 routed rows of one ADT message target **20 different destinations** and carry **no mutual ordering dependency** — per-destination FIFO is enforced *across* messages by the outbound lane (keyed on `destination_name`), not *within* one message. Transforming them concurrently collapses the serial chain from ~40 txn to ~1 and lifts the hub lane ceiling from 7.1 toward ~286 ingress msg/s. **No ADR contemplates this; it is a verified, unexploited opportunity.**

**Depends on:** #209 (hub shape, to measure the speedup); touches the same ROUTED dispatcher as #212.

**Source:** 2026-07-10 throughput audit, §7 (levers table last row + unexploited-opportunity note).

---

## 215. Shard-scaling curve N = 1, 2, 4, 8, 16 on one unified store

> ✅ **CLOSED — the curve was measured and Phase 5 is DONE (C1 → C2 → C3, then C5, 2026-07-10/12).** The banner's *"decisive **unmeasured** experiment"* framing no longer holds: `docs/benchmarks/THROUGHPUT-STATUS-2026-07-10.md:942` records *"Phase 5 is **done**; the answer is DECLINING"*, and the per-shard ceiling at N=8 is pinned at **`R ∈ [2, 3)`** (`:34`, `:118`, `:274`) — 2/shard passes at 100%, 3/shard collapses, reproduced 3×. Since `R < 3 < 3.62/shard`, **N-sizing alone cannot reach the target rate**, which cleared the remaining rungs *by inequality* rather than by running them. Artifacts are in-repo under `docs/benchmarks/results/2026-07-12-throughput-c4-c7/`. ⚠️ **The `m7i.8xlarge` upsize this item still asks for was RETIRED** — the same document's rig table states it outright at `:1719`: *"Phase 5 is closed (DECLINING; `R ∈ [2, 3)`) — no further shard-curve runs are planned, so the m7i.8xlarge N=16 upsize is NOT needed."* Do not fund it. _(was 🔢 P2 · Value 7/10 · Difficulty 6/10.)_

**Cluster:** Throughput & Scale. **Priority:** P1. **Verdict:** measure. **Severity:** high.

**Scope:** 🧠 **ULTRACODE** — the decisive experiment; it interprets rig results that separate a sizing problem from an engine problem, and it has never been run. Hold per-shard load fixed and vary engine-shard count `N = 1, 2, 4, 8, 16` on **one unified store**, measuring whether per-shard throughput stays flat as `N` grows. Engine shards are subprocesses on the **one active box** (ADR 0037); a second box is the HA passive node and adds zero capacity — do not certify a two-box split.

**Why:** **Fleet N-shard scaling is UNMEASURED** — `N` was never varied by any throughput run (open question #1, "everything else is downstream of this"). If **flat**, parity is an `N`-sizing exercise on the 20-core spec (publish `N × per-shard × 0.5` per the D4 rule). If **declining**, a shared bottleneck (the store's claim path) means Phases 3–4 become the whole game and shards buy nothing. It is cheaper than any lever and every lever's value depends on it. Rig note: `N=16` on 8 vCPU measures core contention, not store scaling — needs a larger single box.

**Depends on:** #206 (fixed gate), #208 (per-PID CPU attribution — "fix first"), and **#218** (the 2-point `N=1` vs `N=4` probe — **this full sweep is SKIPPED if #218 already shows a clear decline**). Uses the **existing/extended `shardcert` traffic harness** at `dests=8`, fixed per-shard load on **bigger boxes** (m7i.4xlarge for N≤8, m7i.8xlarge for N=16) — it does **NOT** drive 1,500 connections, so it does **not** depend on the 1,500-connection demo instrument (#216).

**Source:** 2026-07-10 throughput audit, §3 (Phase 5) and §8 open question #1.

---

## 216. 1,500-connection traffic-driving harness mode (the demo shape)

> ✅ **SHIPPED — verified against `origin/main` (2026-07-28).** ⚠️ **The banner's premise — *"no existing harness covers it"* — is FALSE**: the whole estate mode exists as `harness/load/estate/` (`profile.py` 360 ln, `driver.py` 200 ln, `runner.py` 568 ln, `report.py` 214 ln) plus the graph under `harness/config/estate/`, driven by `python -m harness --estate` (`harness/__main__.py:167`, with `--estate-api-port` and `--list-estate-profiles` beside it). The demo profile `harness/load/profiles/estate-demo.toml` declares `count = 1500` (`:20`) at a calibrated per-connection event rate converging on the target total (`:24`).
>
> ⚠️ **Two calibration constants still require OWNER SIGN-OFF before the demo is run** — they describe the *shape* of the estate and must come from the operator's own recon, not from this harness: `simple_fraction = 0.72` (`estate-demo.toml:21`) and `hub_fanout = 3` (`:22`), both marked `OWNER-CONFIRM` in the file (`:8-9`) and named as the calibration pair in `harness/load/estate/profile.py:9`. Note the **shape discrepancy** against this item's own text: the profile encodes a 72/28 simple-to-hub split at fan-out 3, whereas the item asked for "17% hub, H=20, N=4". The instrument is built; which shape it drives is the owner's call. _(was 🔢 P2 · Value 7/10 · Difficulty 6/10.)_

**Cluster:** Throughput & Scale. **Priority:** P1. **Verdict:** build. **Severity:** high.

**Scope:** 🧠 **ULTRACODE** — a mis-calibrated driver silently fabricates the demo shape, which is precisely the B-class failure mode; the driven mix and rates must be adversarially verified against the target. Build a harness mode that drives ~1,500 connections at ~0.35 events/s each with the estate's **72%-simple / hub** mix (17% of events hub-shaped `H=20, N=4`, the rest simple `H=1, N=1`).

**Why:** **No existing instrument drives the demo shape** — this is the actual investment. `connscale` proved the 1,500-lane *idle* claim storm (ADR 0066); `shardcert` drives *traffic* over only 4 shards × 8 destinations. Neither runs ~1,500 connections at ~0.35 events/s each with the estate mix. `520.83 events/s ÷ 1,500 = 0.347 events/s per connection` = ~1/20th of even the `H=20` lane ceiling; the demo load is ~2,416 committed txn/s = **9% of the store's ~27k commits/s ceiling.** This mode gates #211 (reaching 1,500 lanes with traffic) and the Phase-D demo. The shard-scaling curve (#218/#215) does **not** use it — it varies shard count `N` at fixed per-shard load on the extended `shardcert` harness and never drives 1,500 connections.

**Depends on:** #206 (fixed gate/denominator).

**Source:** 2026-07-10 throughput audit, §8 (harness gap) and the demo-load table.

---

## 217. Group-commit / durable-write — sequenced AFTER the claim path

> ⛔ **DECLINED — dead by measurement, three times over.** [ADR 0069](adr/0069-durable-write-throughput-lever.md) found the server-side commit tier only ~9% utilised, so there is nothing for group-commit to amortize. [ADR 0099](adr/0099-phase-4-group-commit-amortize-the-per-event-transaction-cost.md) (**Accepted 2026-07-12** *for the withdrawal + the gate*) then formally **withdrew group-commit itself** — superseding [ADR 0055](adr/0055-group-commit-durable-write.md) (`0099:95`) — and gated a *different*, still-unfunded build, inline stage-fusion ([ADR 0057](adr/0057-inline-step-a-fast-path.md); `0099:23-24`, `:30`). [ADR 0107](adr/0107-phase-4-is-closed-transaction-reduction-is-a-measured-dead-end.md) (**Accepted 2026-07-13**) closes Phase 4 entirely — its status line reads *"closes options; authorizes no build. **Do not build F2 or F3.**"* (`:3`) — and terminates the adjacent inline fast-path, stamping [ADR 0057](adr/0057-inline-step-a-fast-path.md) **⛔ DO NOT PROMOTE** (`0107:7`, `0057:3`). Transaction reduction is a **measured dead end**: the residual carriage-byte trim does not justify the seam. Do not re-open on a modelled or analytical argument — only new *measurement* contradicting ADR 0107 would. _(was 🔢 P3 · Value 4/10 · Difficulty 7/10.)_

**Cluster:** Throughput & Scale. **Priority:** P2. **Verdict:** build. **Severity:** medium.

**Scope:** 🧠 **ULTRACODE** — its payoff is a measured `txn/s`-vs-commit-ceiling comparison gated by an explicit falsifier, so the interpretation is what decides go/no-go. Build group-commit to amortize fsyncs across concurrent transactions, and reduce carriage bytes (`NVARCHAR(MAX)` at 2 B/char + base64 of the `mfenc` ciphertext). **Sequence this after the claim path (Phase 1), not before.**

**Why:** Group-commit is ADR 0051's own **#1 lever** and is **not built**. But *falsifier:* if measured `txn/s` at the rig sits far below the store's ~27–29k commits/s ceiling, group commit buys little and the wall is the **claim query**, not the commit — which is what the evidence currently says. That is why it is sequenced after #211/#210: fix the claim path first, then re-measure whether commit amortization has any headroom left to recover.

**Depends on:** #211 (claim path resolved) and #210 (tempdb rewrite landed).

**Source:** 2026-07-10 throughput audit, §3 (Phase 4) and §4 (store commit vs claim query).

---

## 218. 2-point shard probe (N=1 vs N=4) — the cheap early killer

> ✅ **CLOSED — the experiment RAN and answered (C1, 2026-07-10).** This is a *measurement* item, and the measurement is published: whole-fleet peak **11.33 → 15.42 ingress/s = 1.36× for 4× shards** (N=1 → N=4) — per-shard capacity **DECLINES** with N (`docs/benchmarks/THROUGHPUT-STATUS-2026-07-10.md:265`, expanded at `:878-881` where `claim_mean` rises 12.6 → 48.8 ms tracking the penalty). Direction is firm; the magnitudes are explicitly soft (both 900 s soaks collapsed, so climb-peak overstates — the doc says so at `:265`, and that caveat travels with the number). **Re-running it would re-derive a published verdict.** *(The two run artifacts named in that row, `c1-arm-a-n1.json` / `c1-arm-b-n4.json`, are held off-repo — they are not under `docs/benchmarks/results/` on `origin/main`.)* _(was 🔢 P2 · Value 7/10 · Difficulty 6/10.)_

**Cluster:** Throughput & Scale. **Priority:** P1. **Verdict:** measure. **Severity:** high.

**Scope:** 🧠 **ULTRACODE** — it interprets the rig result that gates the entire "parity is an `N`-sizing exercise" thesis; a naive read is this programme's signature failure. Run a **2-point** shard probe — `N=1` vs `N=4` at fixed per-shard offered load, `dests=8`, 900 s soak, whole-box **and** per-PID CPU recorded — on the **current 8-vCPU boxes** using the existing `shardcert` traffic fleet (4 shards × 8 dests). Two points cheaply distinguish a **flat** per-shard curve from one that is **already declining**.

**Why:** This is **the single cheapest experiment that could kill the whole effort**, and it needs no bigger box and no 1,500-connection instrument (#216). The 90 events/s definitive point is a **4-shard-fleet** number; `N` was never varied by any throughput run. If per-shard events/s at `N=4` is materially below `N=1`, the curve is **declining** with two points → the shard-scaling thesis is dead → the full `N=1,2,4,8,16` sweep (#215) is **skipped** and the levers (#210/#213/#214/#217) become the whole game. Fire it **as early as the rig allows**, in parallel with the rest of the zero-rig work, gated only by #208.

**Depends on:** #206 (fixed gate), #208 (per-PID CPU — "fix first", so a box-CPU wall is distinguishable from a store-claim wall). **Gates** #215 (the full sweep, skipped if this already declines), #216 (demo instrument), and the Phase-F levers.

**Source:** 2026-07-10 throughput audit, §3 (Phase 5, the 2-point probe) and §8 open question #1.

---

## 219. Harness-invariant property test + cross-observer INCONCLUSIVE guard

> ✅ **BUILT 2026-07-10.** Both halves landed: (a) the property test (`tests/test_harness_invariants.py`,
> A4a — every `_derive_*_timeout` strictly dominates its guarded interval over the `(hold, drain)` grid; the
> sustainable-ingress rate is invariant to hold) and (b) the **cross-observer INCONCLUSIVE guard** (A4b —
> `harness/load/shardcert_ladder.py::observers_inconclusive`, wired into `classify_rung`/`build_rung_outcome`,
> covered by the A4b block in `tests/test_shardcert_ladder_two_box.py`). A rung now downgrades to
> INCONCLUSIVE (never a fabricated SUSTAINED/COLLAPSED) when the ENGINE store-truth tally and the DRIVE sink
> count contradict beyond tolerance, or a required collector reads zero on a non-zero-volume run; it
> propagates to the ladder `result`/JSON via the existing `store_truth_unconfirmed` → `SETUP_DEGRADED`
> path, schema_version 3 preserved (additive — the `inconclusive` enum value already existed).

**Cluster:** Throughput & Scale. **Priority:** P1. **Verdict:** build. **Severity:** high.

**Scope:** 🔍 **FABLE REVIEW** — test/guard code whose correctness CI catches cheaply. (a) A property test asserting, for `hold ∈ {60..1800}` and `drain ∈ {30..300}`, that every `_derive_*_timeout` **strictly exceeds** the interval it guards, and that the sustainable-ingress-rate reduction is **invariant to `hold`** when the true rate is held fixed. (b) Make the reduction emit **`INCONCLUSIVE`** unless all four observers agree they measured the same window (generalising the B9 `SOAK_UNCONFIRMED` label into a cross-observer consistency check).

**Why:** The nine harness defects (B1/B6/B7/B8/B9/B10 + D-series) are **one bug class** — a fixed constant bounding a parameter-scaled interval that, on expiry, **silently fabricates a plausible result** — and that fabrication is the audit's central finding. Point fixes (#206 and the merged B6/B7/B8/B9 derivations) close individual instances; this is the **structural guard** that stops the class from recurring in any future gate. *Falsifier:* re-run the four burned artifact configs through the guarded harness; if any previously *fabricated* collapse now reproduces as a *real* one, or the observers disagree without emitting `INCONCLUSIVE`, the guard is incomplete.

**Source:** 2026-07-10 throughput audit, §2 (the one-bug-class finding) and §3 (Phase 0).

---

## 220. CPU delta is differenced across a subtree that can change between ticks

> ✅ **SHIPPED — verified against `origin/main` (2026-07-28).** The fix is the one the item asked for: the probe now records **which** PIDs it summed, so a changing subtree can be detected rather than silently differenced. `ProcSample.cpu_pids` carries the exact PID set per tick (`harness/load/connscale/probe.py:50-70`, whose docstring names this item and states the invariant — `None` **iff** `cpu_seconds` is `None`). `_drain_proc` then derives CPU as a **piecewise sum over consecutive intervals whose summed-over PID set is unchanged**, degrading the rest to a gap instead of a bogus delta (`harness/load/connscale/runner.py:928-1014`), with the twin `_cpu_from` on the estate side (`harness/load/estate/runner.py:513`). Falsifiers in `tests/test_connscale_cpu_probe.py`. _(was 🔢 P3 · Value 4/10 · Difficulty 3/10.)_

**Cluster:** Throughput & Scale. **Priority:** P3. **Verdict:** build. **Severity:** low.

**Scope:** ⚙️ **SOLO** — a bounded harness fix with a deterministic test. `harness/load/connscale/runner.py::_drain_proc` derives CPU as `last − first` over per-tick readings, where each reading is a **sum across the engine process subtree**. The subtree is re-resolved periodically (A3), so it can gain a PID (a `serve --shard` worker spawns) or lose one (a worker exits) mid-window. Differencing sums taken over **different process sets** is not a CPU delta: a joining PID inflates the total by that process's entire lifetime CPU, and a departing PID drives the difference negative, where `max(0.0, …)` silently clamps it to zero. Fix by carrying the per-tick PID set (or its size) on `ProcSample` and summing only intervals whose PID set is unchanged, degrading the rest to a gap.

**Why:** It is the same disease as the B-class — a plausible number where the arithmetic does not hold — and it sits in the collector that **gates every CPU attribution** (C1, C2, C3b, C4, E2, G1 of the execution plan). In practice the subtree grows once at engine start and is then stable, so the window endpoints usually agree; that is why this is low severity and not high. But "usually agree" is exactly the property this programme has been burned by assuming. *Falsifier:* spawn a CPU-burning child mid-window and assert the derived `cpu_seconds_total` does not jump by the child's pre-window CPU.

**Source:** Discovered 2026-07-10 while writing the A3 value-level tests; the launcher-confound reproduction (a venv `python.exe` redirector whose grandchild burns the CPU) exposed it.

---

## 221. IDE native-surface polish — walkthrough, registered custom editors, status bar, TOML association (DX)

> ✅ **SHIPPED — verified against `origin/main` (2026-07-28).**
> [ADR 0100](adr/0100-ide-native-surface-polish-and-open-to-messagefoundry-startup-experience-backlog-221.md)
> is **Accepted (2026-07-12)**, names this item in its own filename and title, and every surface it
> claims exists in `ide/`: **3** registered `customEditors` (`ide/package.json:527`) with
> Reopen-With-Text; a **9**-step Get-Started walkthrough; the engine-target status-bar item
> (`ide/src/statusBar.ts:107`, created at `:136` — the separate `MEFOR Live` toggle is
> `ide/src/liveDebug.ts`, which `statusBar.ts:2` is at pains to distinguish); the keyboard-first QuickInput connection wizard
> (`ide/src/multiStepInput.ts`, whose header cites "#221e" at `:5`); and the TOML language
> association. This is IDE **chrome** around the code-first model — #26 untouched.
> _(was 🔢 Open · Value 4/10 · Difficulty 2/10 · _fill-in_.)_

**Type:** developer-experience feature — small, high-visibility wiring of sanctioned VS Code surfaces the
extension doesn't use yet, plus one extension of a shipped one. No engine change.

**What:** (a) extend the shipped Get Started walkthrough (PR #798) with the missing steps (point at the
engine → open the config dir → live debug → promote); (b) register the existing
`connections.toml` form and code-set grid as **`customEditors`** by file glob, so opening the file lands in
the form with "Reopen With → text editor" always available (the AWS Workflow Studio
default-editor-with-opt-out pattern; today the forms are command-opened webviews the analyst must know to
invoke); (c) a status-bar engine indicator (target URL / environment / reachable); (d) a TOML language
association for config-dir files; (e) a native **multi-step QuickInput** new-connection wizard (the official
`multiStepInput` pattern) as the keyboard-first fallback to the webview form.

**Why:** the deep-research verified (3-0) that these are the platform's sanctioned "friendlier" surfaces —
the remaining felt clunkiness is largely *unused platform* (customEditors, engine status item, TOML
association, QuickInput), not *platform limits*. Also the cheap half of
the Marketplace-publish gate (the publish do-next explicitly waits on "planned IDE-focused improvements").

**Adjacent:** #92 (shipped live-debug — the walkthrough should feature it), #33 (config-UX consolidation),
#84 (Test Bench panes). **Source:** IDE low-code deep-research (2026-07-10), §6 option A.

---

## 222. Structured action-list lens over real Python Handlers — typed action vocabulary + custom editor (ADR 0076)

> ✅ **SHIPPED — all three phases, verified against `origin/main` (2026-07-28).** The typed action
> vocabulary is `messagefoundry/actions.py` (**15** verbs: `set_field`, `copy_field`, `copy_segment`,
> `delete_segment`, `code_lookup`, `format_date`, `date_diff_field`, `arith_field`, `split_field`,
> `substring_field`, `pad_field`, `trim_field`, `append_to_field`, `convert_case`, `replace_literal`).
> The projection engine is `messagefoundry/lens.py`, driven by a `messagefoundry lens` subcommand
> (`messagefoundry/__main__.py:374`) that **statically parses** a config module into the per-`@handler`
> row contract and never imports it. The custom editor is `ide/src/stepsView.ts`.
> [ADR 0076](adr/0076-typed-action-vocabulary-action-list-lens.md) plus
> [ADR 0106](adr/0106-steps-view-add-dropdown-vocabulary-expansion-adr-0076-phase-b.md) (phase-B
> palette), [ADR 0108](adr/0108-steps-view-accumulator-send-fan-out-copy-on-send-authoring.md) and the
> [ADR 0103](adr/0103-steps-view-row-context-menu.md) follow-up recorded below are all built. The
> **#26 amendment** this required is ratified and recorded in CLAUDE.md §12: the Steps view is a
> *projection* — plain `.py` stays the only artifact and the only execution path.
> _(was 🔢 Open · Value 6/10 · Difficulty 6/10 · _big bet_.)_
>
> **Follow-up (2026-07-12, IDE v0.0.22, [ADR 0103](adr/0103-steps-view-row-context-menu.md)):** the
> Steps view gains a right-click **row context menu** (Insert before/after, Delete, Move up/down) as a new
> surface over the *existing* insert/delete/move ops (no new engine path) — plus a `[blank]` placeholder on
> empty editable param inputs. Additive; the toolbar Insert dropdown is unchanged (its "insert-collapse"
> deferred to the owner).

**Type:** feature — the analyst-facing low-code layer; the deliberate, narrow revisit of #26. The target
user is the healthcare interface analyst who doesn't know Python (the Corepoint audience).

**What (phased):**
- **Phase 1 — typed action vocabulary (engine only, standalone value).** Small composable helpers on the
  `messagefoundry` surface mirroring the Corepoint action classes — `copy`/`replace`/`append`/
  `format_date`/`split`/`convert`, `code_lookup` (→ code sets), the existing `db_lookup`/`fhir_lookup`,
  if/else + for-each-segment idioms. Plain Python, usable directly; becomes the scaffold vocabulary for
  snippets, completion, and `@messagefoundry` generation.
- **Phase 2 — read-only action-list lens (IDE).** A `CustomTextEditorProvider` over Handler `.py` files
  that AST-parses (server-side via the CLI, the InterSystems pattern) and renders any *parseable* handler
  as a Corepoint-style ordered action-list — typed rows with parameter forms for vocabulary code,
  in-place read-only `code` rows for everything else — plus an in-editor toolbar and a Test button (Test
  Bench inline); the shipped live-debug values (#92/ADR 0072 — PHI-redacted by default, synthetic samples
  only) render beside each action row. Whole-file refusal (notice + text editor) only on parse failure
  (ADR 0076 §4 degradation ladder; InterSystems graceful degradation).
- **Phase 3 — editing.** Form edits emit AST-based rewrites of the same file. Sync on save only;
  one-editor-at-a-time; "Reopen With: Python" always.

**Guardrails (verified in the research, §4):** the lens round-trips only the *structural* vocabulary —
never arbitrary Python (behavioral code doesn't round-trip); refuse-to-represent instead of guess;
scaffold-vs-hand-code stays in separate files (the only mechanism that guarantees hand edits survive);
guard the webview↔document update loop. **The artifact and only execution path stay plain reviewable
`.py`** — no runtime interpreter, no opaque graph object, no second product; that is what keeps #26's
rationale intact.

**Why:** verified practitioner evidence: Corepoint's approachability = typed actions; its documented
ceiling = no code underneath in-product ("felt a bit fenced in", "simple tasks took lots of steps"); Iguana's praise =
the live loop (shipped here as #92). The combination — Corepoint-familiar action rows + live values + real
Python underneath — is one no rival ships in VS Code. **Depends on:** #26 amendment; ADR 0076 for
phases 2–3. **Composes with:** #92 (shipped), #84, #33, #48, the AI participant.
**Source:** IDE low-code deep-research (2026-07-10), §6 option C.

---

## 223. Server-DB DR restore vintage/completeness attestation (the #102 residual)

> ✅ **SHIPPED — verified against `origin/main` (2026-07-28).** [ADR 0102](adr/0102-server-db-dr-restore-vintage-completeness-attestation-residual.md) is **Accepted (2026-07-12)** and the mechanism it authorized is built. **(c)** the vintage/completeness residual is formally risk-accepted; **(b)** the opt-in cross-check ships: `[dr].restore_token` (`messagefoundry/config/settings.py:3314` — default `""` = OFF, leaving the #102 gate byte-unchanged and a SQLite no-op; a cloud URL is rejected by the `_no_cloud_restore_token` validator at `:3347`) is cross-checked by `_verify_restore_token` (`messagefoundry/pipeline/dr.py:480`, invoked from the gate at `:478`) against the restored DB's **own** latest `dr_backup` anchor — a **vintage floor** a bare boolean attestation cannot give (a stale or wrong native restore is refused closed). It is deliberately **not** completeness proof. **(a) — the full engine-driven server-DB store seed — is OUT OF THIS ITEM'S SCOPE by ADR 0102's own construction:** it is *"explicitly deferred as a separate, owner-scheduled decision"* (`0102:67`, section header at `:128`), because it re-opens the #52 DBA-delegation boundary. ⚠️ **State of (a), stated precisely:** the in-repo record is **DEFERRED (owner decision)**; the 2026-07-28 reconcile carries an owner ruling **declining** it dated 2026-07-20, which is **not recorded anywhere in this repo**. Either way it is a separately-scheduled owner call, not a residual of #223 — so with (b)+(c) built, this item closes. Do not restate the decline as an in-repo fact until an ADR or amendment records it. _(was 🚧 DESIGN + RISK-ACCEPTANCE RECORDED.)_

**Cluster:** Security & Compliance. **Priority:** P2. **Verdict:** owner decision (design first). **Severity:** medium.

**What:** #102's `has_prior_backup_history()` gate proves a server-DB DR store is *restored, not freshly bootstrapped* (≥ 1 `dr_backup` audit row) and requires an explicit per-activation DBA attestation — closing the concrete data-loss case (activation blessing an empty store). It does **not** prove the restore is the intended *vintage* (a stale-but-real DB carrying old `dr_backup` rows passes) nor *complete* (a partial restore that carried `audit_log` but not the message tables passes). The adversarial review found no in-scope engine artifact that can cross-check vintage: the config-only `.mfbak` seed is a decoupled artifact from the DBA's native DB backup, and message/queue row-counts are unsafe signals (legitimately 0 on a drained store).

**Options:** (a) extend #60 / ADR 0049 with a real engine-driven server-DB store seed (the engine restores + fingerprints the DB itself, so vintage is engine-verifiable) — the strongest but largest; (b) a DBA-runbook artifact (a restore token / recorded source anchor the DBA places on the DR box) that the gate cross-checks; (c) accept the residual formally as an attestation-guarded, runbook-documented risk acceptance (ASVS-style).

**Why:** the #102 fix is deliberately weaker than the SQLite fail-closed default (which verifies a full snapshot + per-table row counts). This item makes the residual explicit and forces a design decision rather than leaving it implicit in the code.

**Source:** BACKLOG #102 build + adversarial review (2026-07-10).

---

## 224. Least-privilege service-account installer default (deferred #186d)

> ✅ **BUILT 2026-07-12 (this PR; Windows-service-CI-gated).** `scripts/service/install-service.ps1` now **defaults** the service run-as to the least-privilege per-service virtual account `NT SERVICE\<ServiceName>` (no password) instead of LocalSystem; `-AllowLocalSystem` is the explicit LocalSystem opt-out (built on the #99 opt-out + warning), and an explicit `-ServiceAccount` still wins. Includes the **S4 ACL-ordering restructure**: `Set-SecureDataDirAcl` / `Set-ConfigReadAcl` / `Set-SecureConfigAcl` now run **after** `nssm set <svc> ObjectName ...`, because a per-service virtual-account SID does not resolve for `icacls` until the service exists — this also keeps the DPAPI machine-key path startable (the account retains read on the data dir + key file; #44 / WIN2025 S2.2). The `windows-service-smoke` CI leg (a bare `-LockConfigDir` install) now installs under the virtual account, so it exercises the new default on both Windows Server SKUs. `docs/SERVICE.md` updated. **Verification is CI-gated** (NSSM + a real Windows service) — not runnable in the ruff/mypy/pytest loop; the AST parse check is clean and the leg must be green on the mirror-nightly run before this is considered proven.

**Cluster:** Security & Compliance. **Priority:** P2. **Verdict:** build (Windows-service-CI-gated). **Severity:** medium.

**Closes (ASVS 5.0 L3):** the LocalSystem half of #186 (least-privilege service account).

**What:** make `scripts/service/install-service.ps1` default the service to a least-privilege virtual account (`NT SERVICE\<name>`) instead of LocalSystem, with an explicit `-AllowLocalSystem` opt-out. Requires the S4 ACL-ordering restructure: move `Set-SecureDataDirAcl` / `Set-ConfigReadAcl` to run **after** `Invoke-Nssm set <svc> ObjectName ...` (a per-service SID does not resolve for `icacls` until the service exists).

**Why:** LocalSystem grants far more privilege than the engine needs. Split from #186 because a wrong DACL strips the account and the DPAPI machine-key path fails to start (WIN2025 S2.2 / #44 footgun), and the whole flip is only exercisable on the `windows-service-smoke` CI leg — it must NOT land until that leg is green.

**Source:** BACKLOG #186 build (2026-07-10); deferred per the secure-by-default landing plan.

---

## 225. Wire live values into the action-list lens (ADR 0076 follow-up)

> ✅ **SHIPPED 2026-07-10 (this PR).** (Was: Value **5/10** · Difficulty **4/10** · _fill-in_, DX / IDE — filed 2026-07-10.) `liveValuesFor` now acquires values via a **second traced dry-run** (`dryrun --trace json`, ADR 0072) against a chosen synthetic sample, folded onto rows by `mergeLiveValues` (line containment) — the (b) path, decided over reading `LiveDebugController` private state. PHI: redacted-by-default (`buildLensTraceArgs` structurally cannot emit `--show-phi`), never auto-reveal, never persisted; dirty-buffer guard prevents wrong-row markers. Design recorded in the ADR 0076 **Addendum (2026-07-10)**. Deferred: an in-lens reveal control (must match liveDebug's off-by-default per-session convention).

**Cluster:** DX / IDE. **Priority:** P2. **Verdict:** build. **Severity:** low.

**What:** the action-list lens (ADR 0076 phase 2b/3, shipped in #893/#903) renders each recognized row and reserves a slot for the shipped #92 live-debug value beside it, but the **acquisition is stubbed** — `ide/src/actionLens.ts` `liveValuesFor` returns `[]` with a documented TODO. Wire it so the lens shows the actual per-row values flowing through the open Handler against the selected sample (**PHI-redacted by default; never auto-`--show-phi`** — the redacted-merge logic already exists and is tested). This completes the "Corepoint-familiar action rows **+** live values + real Python underneath" combination — the differentiator the IDE deep-research identified ([`docs/research/ide-low-code-options.md`](research/ide-low-code-options.md)).

**Why (needs a design decision, not just a wire-up):** the review of #893 found the only two acquisition paths are (a) reach into the shipped `LiveDebugController`'s private last-trace + reveal-gate state, or (b) run a **second** traced dry-run from the lens (a new invocation of the ADR 0072 trace path). (b) is cleaner but is a PHI-carrying path that must reuse the ADR 0072 redaction gate exactly — so pick the approach in a short design note / ADR-0076 addendum before building. Line-addressed trace rows already map to lens row line ranges (the `mergeLiveValues` seam).

**Source:** ADR 0076 phase-2b/3 build + review (MULTISESSION-PLAN-8, 2026-07-10); deferred by owner (live-value wiring = "do what you judge best" → filed as a follow-up rather than bolted onto the editing lane).

---

## 226. Revise the ported migration estate to the per-feed "Hybrid" config layout (split monolithic feeds)

> 🔢 **Filed 2026-07-11.** Value **4/10** · Difficulty **4/10** · _fill-in_. Mechanical estate-wide sweep converting ported Corepoint feeds from one monolithic module each to the per-feed connections / router / handler / transforms split the project now documents.

**Cluster:** Migration / DX. **Priority:** P2. **Verdict:** build (per-feed, mechanical). **Severity:** low.

**What:** The ported migration estate currently lands each feed as a **single monolithic `.py`** bundling the inbound/outbound connections, the `@router`, and the `@handler(s)` with inline transform logic (e.g. the `IB_400` EKG/ECG → vendor ECG management system port). Convert each migrated feed to the per-feed **Hybrid** layout the project now documents — transport config → `connections.toml`; `@router` → `<INBOUND>_router.py`; `@handler` → `<INBOUND>_handler.py`; the field-level transform steps → a `_<feed>_transforms.py` helper. Reference: [`docs/CONNECTIONS.md`](CONNECTIONS.md) §"Decomposing by role" + the runnable `samples/config/IB_DEMO_ORU_*` worked example. Sweep the estate feed-by-feed, verifying parity with `messagefoundry check` (+ dry-run fixtures) after each split.

**Why:** The monolith co-mingles three concerns — transport config, routing, and a large pile of transform logic — in one file, which is hard to review, unit-test, and GUI-edit. The engine **already supports** the split (the graph is name-wired and flat-merged across the config dir — zero engine change); this is authoring hygiene plus Corepoint-familiar separation, and it moves connections onto the data surface (ADR 0007) and the transform steps into small, testable helpers.

**Also:** align the IDE Corepoint-import / scaffold path (`ide/`) to **emit** the Hybrid layout so future ports start compliant; and consider a recursive-glob / folder-per-feed loader enhancement if the **flat** config dir gets unwieldy at estate scale (hundreds of feeds → hundreds of flat prefixed files, since `load_config` globs `*.py` non-recursively today).

**Source:** config-convention decision (2026-07-11, Scott Hall); motivated by the `IB_400` EKG/ECG → vendor ECG management system port review.

---

## 227. Per-stage claim-call telemetry — the claim timer is outbound-only, so a whole class of question is unmeasurable

> ✅ **SHIPPED (primary ask) — verified against `origin/main` (2026-07-28).** The claim timer is no longer outbound-only: `ClaimPhaseTiming.maybe_emit(*, stage: str, claimers: int)` (`messagefoundry/pipeline/phase_timing.py:219-243`) emits per-stage claim counts and latencies — `claim phase timing (stage=%s): claim n=… mean=…ms max=…ms | lanes/claim=… rows/claim=… rearm=… empty=… claimers=…` — accumulated per dispatcher (`pipeline/stage_dispatcher.py:295-296`) and called with `stage=self._stage.value` at `:643-645`, i.e. for **every** stage, not just OUTBOUND. So the per-stage claim-call rate the item said was unmeasurable is now measurable.
>
> ⚠️ **The secondary "also fix while in here" is NOT delivered and CANNOT be delivered from this repo.** `claim_stats` appears in exactly **one** place in the whole worktree — the #227 line in this file. It is a **rig-side** tool that lives outside this repository, so leaving #227 open could never produce it. That residual is off-repo; do not re-open this item for it. _(was 🔢 · filed post-re-score.)_

**Cluster:** Throughput & Scale. **Priority:** P2. **Verdict:** build. **Severity:** medium.

**What:** the outbound-claim timer (#845) records `stage=outbound` **only**. Every `claim_phase_soak.txt` artifact from C1/C2/C3 contains outbound lines and nothing else (1042/1042 at `c2-8`; 920/920 at `c3-8`). Extend the timer to emit **per-stage** claim-call counts and latencies (INGRESS / ROUTED / OUTBOUND / RESPONSE), so a run can report the claim-*call rate* per stage, not just the outbound claim's latency.

**Why:** the pooled claim declares its 4 tempdb table variables **per claim call**, on **every** stage (`stage_dispatcher.py:559` wires `claim_fifo_heads` for all four). The tempdb system-catalog latch that C2 fingered and C3 removed is a **store-wide shared** resource. So the INGRESS/ROUTED claim calls contribute to it too — and `fifo_claim_batch > 1` can cut *their* call count (up to 8× at the swept shape, where a message's 8 routed rows share one lane), even though it is hard-clamped out of OUTBOUND.

That makes a real question **unmeasurable today**: *does `fifo_claim_batch` relieve any of the shard wall, or none of it?* We cannot say — and the honest status-doc entry currently reads "not zero, but UNMEASURED." Without this telemetry, any claim either way is telemetry-adjacency reasoning, which is the exact inference class that got C2 retracted. It also bears directly on the **pooled-claim rewrite** (#210): if a large share of claim calls turn out to be INGRESS/ROUTED, the rewrite's blast radius is bigger than the outbound-only telemetry suggests.

**Also fix while in here:** `claim_stats.py` KeyErrors on a collapsed-arm report JSON (so the arms we most want to read are the ones the tool refuses to parse).

**Source:** 2026-07-11 code read resolving old open question #3 (status doc §8 Phase 3(2), §9 #4); telemetry gap found while trying to size `fifo_claim_batch` against the shard wall.

## 228. Steps / config search finds handlers, routers, and transforms by name (not just connections)

> 🔢 **Logged 2026-07-11 (unscored).** Preview-driven UX gap; to be value/difficulty-scored at the next backlog pass.

> **AMENDED 2026-07-28 — the index IS built; two clauses of the Proposed line are not.** Adversarial verification refuted a full close. **BUILT:** `ide/src/symbolIndex.ts` scans and surfaces handlers / routers / transforms **by name** in the MEFOR view's Definitions section, unit-tested — which fixes the item's headline complaint (a transform is a Python symbol inside a file named for the *connection*, so neither the sidebar search nor Ctrl+P could find it).
>
> ⚠️ **REMAINDER (a): a hit cannot open straight into the Steps view.** The Proposed line asks to reuse the CodeLens / `openSteps` entry point, but Definitions rows carry **no `contextValue`**, so the inline "View as Steps" action — gated on `viewItem == meforElementHandler` — never renders on them, and a click runs plain `openSource`. ⚠️ **REMAINDER (b): "(and the outbound connections a handler sends to)" is outside the index** — `SymbolKind` is `handler|router|transform` only, and the definition regex matches **top-level `def`** only. Both are small; neither is done.

**Cluster:** IDE & Authoring. **Priority:** P2. **Verdict:** build. **Severity:** low.

**What:** the MessageFoundry sidebar search (the box over the MESSAGEFOUNDRY view) matches **connection** names only. Searching for a **handler / router / transform** name — e.g. `xform_SITEA_to_erp_mfn` — returns “No matching results” even though that handler exists (it is defined inside `IB_FILE_HR_Materials_SITEA_MFN.py`, a role-combined feed module whose *filename* is the connection, not the handler). VS Code's own `Ctrl+P` also misses it, because the name is a symbol inside a file, not a filename.

**Why:** operators think in terms of the **transform / message name**, not the feed file it happens to live in. The connection→router→handler wiring is a graph (CLAUDE.md §1), so a user who knows the transform name has no direct path to its definition. It is sharper for the ported migration estate where feeds are still monolithic (see #226): one file holds the connection + router + handler, so the handler name appears nowhere in the tree or the filename.

**Proposed:** index handlers / routers / transforms (and the outbound connections a handler sends to) by name in the MEFOR view search, and jump to the `@handler`/`@router`/`inbound`/`outbound` definition on a match — reusing the CodeLens / `openSteps` entry point so a hit can open straight into the Steps view. A `lens parse` (or a light `findElements` scan) over the config dir already yields the handler/router names.

**Source:** owner report 2026-07-11 while previewing the shipped IDE against the ported migration estate — searched a transform name in the MEFOR view, got “No matching results”. Related: #226 (split monolithic feeds, which would also surface handler names as files).

---

## 229. A4b guard: per-stage strand breakdown for a sound H>D delivery permit

> ✅ **SHIPPED — verified against `origin/main` (2026-07-28).** `QueueBreakdown` (`harness/load/shardcert.py:1199-1220`) — its docstring names BACKLOG #229 — carries the three `*_stranded` fields with the exact per-stage weights the item specified: an INGRESS strand blocks all D copies (the message never routed), an OUTBOUND strand blocks exactly one delivery, a ROUTED strand blocks in [0,1]. The pure `_summarize_queue_rows` reducer the plan asked to be factored out is at `:1228-1240` over `_PIPELINE_STAGES` (`:1223-1225`), derived from the existing `GROUP BY stage,status` scan with **no extra round trip**, and unit-tested against synthetic rows.
>
> ⚠️ **"No more `free` guessing" is only partly literal:** `free = acked*(H-D)` is **not removed** — it is *narrowed* to the ROUTED term (`max(0, routed_stranded - free)`), while ingress and outbound are charged their true weights unconditionally. That is deliberate and documented in-code; charging routed strands ×1 with no `free` term would make the permit pathologically strict. Read the close as "the permit is now per-stage sound", not as "the heuristic is gone". _(was 🔢 · filed post-re-score.)_

**Cluster:** Throughput & Scale. **Priority:** P2. **Verdict:** build. **Severity:** medium (guard precision, conservative-direction; not a fabrication-in-the-dangerous-direction).

**What:** `observers_inconclusive` (`harness/load/shardcert_ladder.py`) reconciles the drive sink socket-truth against the engine store-truth. #209 gave it `handlers`/`delivering` and a `free = acked × (handlers − delivering)` budget so a genuine H>D collapse (routed strands scaling with H, deliveries with D, sink honestly short) is not mis-stamped INCONCLUSIVE. A lossless-sink clause fires first so a lossless sink coincident with strands is not force-forgiven (the second HIGH the ADR-0084/#209 verify pass caught). **But `free` is still applied stage-blind to the opaque `stranded + dead` total** on the *under-counting* branch: an INGRESS strand (blocks D copies) or a delivering-path strand (blocks ≥1) within the `free` window is credited as blocking 0, so a partial over-count (sink counts more than the store's *real* capacity, yet less than A×D) is missed at H>D — the guard returns a definite verdict where it should downgrade to INCONCLUSIVE.

**Why it's cheap:** `_queue_breakdown` (`harness/load/shardcert.py:499`) **already runs `GROUP BY stage, status`** and returns a `stage/status=n …` summary — the per-stage strand counts exist; they are collapsed to a single non-terminal total before reaching the guard. Thread `ingress_stranded` / `routed_stranded` / `outbound_stranded` through the drive report → `RungOutcome` → `classify_rung` → `observers_inconclusive`, and compute `blocked` soundly: an ingress strand blocks D, an outbound strand blocks 1, a routed strand is bounded below by 0 (could be a self-filtering handler) and above by 1 — no more `free` guessing.

**Why it's non-blocking (why the seam shipped without it):** it bites **only at H>D** (the ADT-hub shape #209 just enabled — never yet run on the rig), and only in the **conservative** direction (a missed downgrade to INCONCLUSIVE, never a fabricated definite verdict from nothing). At H==D — every published run — the guard is byte-identical to the pre-#209 arithmetic (modulo one *sound* stricter lossless corner). So it must land **before anyone trusts an H>D ladder result**, not before the seam merges.

**Source:** the ADR-0084/#209 adversarial verify pass (2026-07-11) — the soundness lens found the stage-blind over-forgiveness; triage fixed the catastrophic (lossless) instance and filed this precision residual.

## 230. ADR 0104 build: copy-on-Send message model + `message_type_of` + HL7 field picker

> ✅ **SHIPPED — verified against `origin/main` (2026-07-28).** [ADR 0104](adr/0104-copy-on-send-outbound-message-model-recognition-first-handler-message-type-and-hl7-field-picker.md). **Both** remainders this item names are merged. **(a) The copy-on-Send default flip:** `snapshot_on_send: bool = Field(default=True)` (`messagefoundry/config/settings.py:1164-1175`) — the gate was satisfied on the record (the conservative estate AST scan flagged 1/152 handlers, genuine divergence 0, and `Message.copy()` is now genuine copy-on-write), resolved at `docs/adr/0104-…md:164-178` §8.1. **(b) The HL7 field picker:** the cascading segment→field→component quick-pick at `ide/src/hl7Picker.ts:163`, wired into the Steps-view Set-Field path slot per ADR 0104 §2.3. `message_type_of` ships as the ADR 0084 `accepts=` helper (see **#213**).
>
> ⚠️ **Two items under this entry's own "Optional fast-follow" line are NOT built and must be re-filed rather than dropped by this close:** freezing `RawMessage.raw` to close the cross-handler leak — `messagefoundry/parsing/message.py:756-762` openly calls it "a separate scan-gated fast-follow" — and a non-HL7 builder. Neither is covered here. _(was 🔢 · filed post-re-score.)_

**Cluster:** IDE & Authoring / Engine. **Priority:** P2. **Verdict:** build (partially shipped). **Severity:** low.

**What:** the build tracker for [ADR 0104](adr/0104-copy-on-send-outbound-message-model-recognition-first-handler-message-type-and-hl7-field-picker.md) (the message-model design + competitor-research eval; backing memo `docs/research/message-model-eval.md`).

**Shipped (engine-only, PRs #991 ADR + #995 build):**
- **Q1 copy-on-Send** — `Message.copy()`/`RawMessage.copy()`/`snapshot_payload` structural clones (deepcopy of the parsed model, backend-preserving — never `parse(encode())`); `Send.__post_init__` snapshots the payload **at construction** when a run-scoped flag is active, so a divergent fan-out (mutate the same message between two Sends) delivers per-destination bytes. The flag rides a `ContextVar` (`config/send_snapshot.py`) activated by a TRANSFORM-phase run-context provider, so it fires uniformly on the split / inline / fused / subprocess-sandbox paths. Gated by `[pipeline].snapshot_on_send`, **default OFF** (byte-identical), threaded `engine`→`RegistryRunner`→`api/app`→serve; read once at engine start.
- **Q2** — `message_type_of(*specs)`, a pure `accepts=` predicate (ADR 0084 seam): component-wise MSH-9.1+9.2 via the message's own MSH-2 (fixes 3-component `ADT^A01^ADT_A01` + custom separators); code-only/exact/wildcard/variadic grammar; **fails loud** (`MessageTypeError` → ERROR/dead-letter) on `RawMessage`/BHS-FHS envelope/multi-`MSH` batch/empty MSH-9.1; grammar errors are `WiringError` at load.
- `dryrun.route_message`/`dry_run` gained a `snapshot_on_send` preview param (default OFF = the engine default) so the Test Bench can reflect copy-on-Send.

**Remaining:**
- **Q3 — HL7 field picker** for the Set-Field `path` in the Steps view. Extend the **already-shipping** `ide/src/completion.ts` inline path autocomplete first (message-type ranking + occurrence/repetition hints); a Steps-view picker is gated on ADR 0089 Acceptance **and** a measured, nonzero adoption signal for the recognition lens — path-arg splice only, occurrence/repetition read-only, version-pinned trigger→structure resolver (centralize `generators/adt.py`'s map), no false-complete rows. **IDE lane** (owner's parallel `ide/` sessions).
- **copy-on-Send default-flip** — flip `snapshot_on_send` to default-ON only after an estate AST scan (find any handler that constructs a `Send` then mutates the same message before returning) + a throughput/pickle-cost benchmark clear it.
- Optional fast-follow: freeze `RawMessage.raw` (scan-gated) + a non-HL7 builder; an editable occurrence/repetition phase in the picker; thread the service setting into the CLI `dryrun`/`check` for full Test-Bench parity.

**Source:** message-model eval + adversarially-validated ADR 0104 (2026-07-12→13); ADR 0104 §8 "to resolve on acceptance." Engine slice done; Q3 stays the IDE lane per the parallel-session split.

## 231. Steps view: decorative collapsible block grouping (Corepoint Block analog)

> ⛔ **DECLINED by owner ruling 2026-07-20 — superseding [ADR 0106](adr/0106-steps-view-add-dropdown-vocabulary-expansion-adr-0076-phase-b.md)'s deferral.** ⚠️ **This banner previously read *"🔢 Filed"*, which made it a live double-build trap: the ruling had been made, but the published file still invited the work.** ⚠️ **Chronology, so the authority is not overstated:** ADR 0106 (Accepted 2026-07-12) did **not** decline Block — it explicitly *deferred* it to this item (*"**'Block' is deferred to BACKLOG #231**"*, `0106:20`, `:64`, `:146`), having weighed and rejected `with block(...)` / bare header comment / nested `def`. The **decline is the later owner ruling**, not a pre-existing [#26](#26-visual--template-driven-channel-authoring--decision-decline-by-design-no-build) finding. The rationale invoked is #26's: a decorative, collapsible, labeled grouping whose only purpose is to organize the Steps view is chrome authored in the canvas. The #26 amendment's carve-out is deliberately narrower than this: it permits a **structured Steps view over real Python Handlers via a typed action vocabulary** ([#222](#222-structured-action-list-lens-over-real-python-handlers--typed-action-vocabulary--custom-editor-adr-0076), shipped), where every row projects code that already exists. A Block row would project **nothing executable** — it is chrome authored in the canvas, which is exactly the line #26 draws. The open question below is therefore **answered: out of scope.** Organize long handlers with the existing control-flow rows and ordinary comments. _(was 🔢 Filed 2026-07-12.)_

**Cluster:** IDE & Authoring. **Priority:** P3 (nice-to-have). **Verdict:** defer / revisit after the palette ships. **Severity:** none (cosmetic/organizational only).

**What:** find an idiomatic way to represent Corepoint's **Block** action in the Steps view — a purely **decorative, non-functional, collapsible grouping** of steps with a descriptive header line. In Corepoint's action-list editor the developer collapses/expands a block; when collapsed only the block's description is shown and every inner step is hidden. It exists solely to make a long action-list readable (e.g. a header "Evaluate Ordering Provider — Is EIHC Provider?" wrapping a ForEach/If/Try group). It carries **zero runtime behavior** — think of it as a labeled, foldable indent level, like a decorative indented block in most languages.

**Why deferred:** no clean idiomatic-Python representation is obviously right, and the recognition-first lens ([ADR 0089](adr/0089-recognition-first-lens-native-idioms.md)) should not impose a construct developers don't naturally write. Options weighed (2026-07-12), none adopted:
- **`# region <label>` / `# endregion`** — the leading candidate: a labeled, hard-boundaried, nestable, zero-runtime region that **VS Code already folds natively**, so the Steps-view Section collapse would equal the text-editor fold. Downside: `#region` is slightly non-idiomatic vs PEP-8.
- **Bare section-header comment `# ── <label> ──`** — the most idiomatic, but a **soft boundary** (no explicit end; membership is a heuristic; no arbitrary nesting).
- **`with block("<label>"):` no-op context manager** — a real foldable container, but an **invented, non-idiomatic wrapper** that litters every grouped section and cuts against ADR 0076's "handlers read as ordinary code" — rejected.
- **Nested `def _section(msg): …` + call** — a `def` creates a variable **scope**, so a value assigned in one group and used later would break — rejected.

**Open question:** how to render a purely-decorative, collapsible, labeled grouping in the Steps view that round-trips to real Python, keeps the `.py` idiomatic, and preserves the lens coverage-partition — or decide it is out of scope (organize via the existing control-flow rows + comments). Revisit once the [ADR 0106](adr/0106-steps-view-add-dropdown-vocabulary-expansion-adr-0076-phase-b.md) palette ships and there is real usage signal.

**Related:** [ADR 0106](adr/0106-steps-view-add-dropdown-vocabulary-expansion-adr-0076-phase-b.md) (the authoring palette this defers from), [ADR 0076](adr/0076-typed-action-vocabulary-action-list-lens.md) / [ADR 0089](adr/0089-recognition-first-lens-native-idioms.md) (the lens), #222 (Steps view), #26 (the declined visual-authoring line + its structured-Steps-view carve-out).

**Source:** ADR 0106 palette design (2026-07-12); owner deferred Block pending an idiomatic fit.

## 232. Steps view for routers

> 🔢 **Filed 2026-07-30 — not started.** ADR-first: a `route` row kind widens the ADR 0076 §3 grammar, so the amendment lands before any build.

**Cluster:** IDE & Authoring. **Priority:** P2. **Verdict:** build (ADR-first). **Severity:** low (capability gap; no correctness or security risk).

**What:** `lens parse` emits rows per `@handler` only — [ADR 0076](adr/0076-typed-action-vocabulary-action-list-lens.md) §3 states routers are "**out of v1 scope**" — so a `@router` function gets **no Steps view at all**: no "Reopen in Steps view" CodeLens on the def, no rows. An analyst who can read a Handler as steps drops back to raw Python the moment *routing* is the question, which is exactly where destination selection and fan-out are decided.

**Why this is not simply "point the lens at routers":** a router does not mutate `msg` — it **selects destinations**. The shipped shape is a guard-and-return of handler names:

```python
@router("demo_oru_router")
def route_demo_oru(msg):
    if msg["MSH-9.1"] != "ORU":
        return []
    return ["demo_oru_relay"]
```

(`samples/config/IB_DEMO_ORU_router.py:22-27`). The §3 row contract has no kind that fits: `send` rows model `Send(...)` to an **outbound**, a router returns **handler** names, and a bare `return []` already means *filter* inside a Handler. So the build needs (a) a `route` row kind (or an explicit widening of `send`), (b) `return []` disambiguated by the enclosing decorator, (c) a router-specific Add-palette group, and (d) the same coverage-partition + byte-stable splice guarantees the handler path holds.

**Gate:** widening the row *grammar* requires **amending ADR 0076** (§2: "widening the roster is an ordinary addition, widening the *grammar* requires amending this ADR"). ADR-first, not a straight build.

**Related:** #222 (the Steps view), ADR 0076 §3 (routers out of v1), [ADR 0089](adr/0089-recognition-first-lens-native-idioms.md) (recognition-first), [ADR 0108](adr/0108-steps-view-accumulator-send-fan-out-copy-on-send-authoring.md) (send fan-out), #228 (sidebar search already finds routers by name).

**Source:** Windmill/Kestra evaluation (2026-07-30) — surfaced while comparing the Steps view's coverage against general-purpose flow editors; owner filed the same day.

## 233. Steps view move-drop logic implemented twice (model + webview)

> 🔢 **Filed 2026-07-30 — not started.** Prerequisite for #237; option (c), a differential test across both implementations, can land first on its own.

**Cluster:** IDE & Authoring. **Priority:** P2. **Verdict:** build (de-duplicate). **Severity:** medium — a silent-divergence class, not a visible bug.

**What:** the row move/drop semantics exist in **two independent implementations** that must agree and are not mechanically kept in agreement:

| Function | Tested TS model | CSP-isolated webview |
|---|---|---|
| `blockExtent` | `ide/src/stepsModel.ts:1767` | `ide/media/stepsWebview.js:68` |
| `walkMove` | `ide/src/stepsModel.ts:1861` | `ide/media/stepsWebview.js:126` |
| `resolveDrop` | `ide/src/stepsModel.ts:1531` | `ide/media/stepsWebview.js:404` |

The webview cannot import from `src/` (it is loaded as a plain script into a `default-src 'none'` webview, `stepsView.ts:917`), so the drag/drop *preview* the user sees is computed by the webview copy while the *committed* splice is computed by the model copy. They can drift, and the fixture tests only cover the model side — so a divergence shows up as "the drop landed somewhere other than where the indicator said", with green tests.

**Why it matters beyond tidiness:** these functions decide the line ranges handed to `lens rewrite`. ADR 0076 §5's byte-stability guarantee is only as good as the extent computation that feeds it, and ADR 0089 §6 already records that "each native form is a new corruption-risk class — the ADR 0076 review history shows this is where bugs hide".

**Options (pick at build time):** (a) build the shared pure functions into a small bundled module the webview loads as a local resource (esbuild already runs — `ide/esbuild.js`); (b) move the preview computation into the extension host and post results to the webview; (c) keep both but add a differential test that runs the same fixture corpus through **both** implementations and asserts identical output. (c) is the cheapest guard and could land first regardless of which structural fix is chosen.

**Related:** #222, [ADR 0103](adr/0103-steps-view-row-context-menu.md) (row context menu — move/paste entry points), ADR 0076 §5 (byte-stable splice).

**Source:** Windmill/Kestra evaluation (2026-07-30); duplication verified by direct read of both files.

## 234. Steps view projection refreshes on save only

> 🔢 **Filed 2026-07-30 — not started. Re-framed 2026-07-30 to match the instruction that filed it.** This was originally recorded as "revisit — do not treat as a bug", which contradicted the owner's actual words: *"Put that fix on the backlog too."* It is a **fix**, gated on an ADR amendment — not a question about whether to act. The engineering caveat that motivated the softer framing is preserved below and is unchanged.

**Cluster:** IDE & Authoring. **Priority:** P3. **Verdict:** **build (ADR-first)** — owner asked for the fix; the save-gate it touches is a deliberate ADR 0076 §5 guardrail, so the amendment lands before the change. **Severity:** low (UX latency).

**What:** the Steps view re-projects the handler on **save**, not on edit. Type in the split text editor and the rows do not follow until the buffer is written. Live values go further and are **skipped entirely while `document.isDirty`**.

**Read this before building:** sync-on-save is a **deliberate guardrail**, not an oversight. ADR 0076 §5 adopts the verified InterSystems/VS Code set *wholesale*: "**Sync on save only; one editor at a time; update-loop guard; Reopen With: Python always available**". And the live-value skip is a **correctness** fix, not laziness (#225): the trace reads the module **from disk** while rows are projected from the **live buffer**, so after an unsaved structural edit the disk trace's line numbers describe the pre-edit file and mapping them by line containment would attach a value marker to the **wrong row**.

**So the item is:** decide whether a *bounded* relaxation is safe — e.g. debounced re-projection of **rows only** (already partly present: `RERENDER_DEBOUNCE_MS = 250`, `stepsView.ts:89`) while keeping live values save-gated; and whether the update-loop guard (`EditLoopGuard`) still holds if projection races an in-flight `lens rewrite`. Any change here **amends ADR 0076 §5** and must re-argue the guardrail it removes.

**Non-goal:** removing the save gate on live values. #225's dirty-buffer misalignment is a real correctness hazard and its fix (re-attach on save) should stand unless the trace itself learns to read the buffer.

**Related:** #222, #225 (live values + the dirty-buffer skip), ADR 0076 §5.

**Source:** Windmill/Kestra evaluation (2026-07-30); owner asked for it to be filed the same day.

## 235. Generate Steps view parameter forms from Python type hints

> 🔢 **Filed 2026-07-30 — not started.** Widens what is *editable* without widening the recognition grammar; sequence deliberately against #237.

**Cluster:** IDE & Authoring. **Priority:** P2. **Verdict:** build (evaluate as its own lane). **Severity:** low.

**What:** today a recognized row exposes **enabled inputs only for literal params**; anything else renders visibly disabled (`stepsView.ts:11-13`). Windmill's pattern is to derive a **JSON Schema from the script's Python type hints** and render the step's parameter form from that schema. Applied here: `lens parse` (or a sibling `lens schema`) emits, per recognized action, a small parameter schema derived from the vocabulary helper's own **type hints** — which ADR 0076 §2 already requires to be "fully type-hinted, mypy-strict".

**Why it is attractive:** it widens what is *editable* without widening the **recognition grammar** — the expensive, ADR-amendment-gated axis. The row set stays exactly as recognized today; only the input widgets get richer (enum → dropdown, `Literal["upper","lower","title"]` → radio, int → number field with validation, code-set name → the existing `codesetList` picker).

**Build sketch:** engine side, derive the schema from `messagefoundry/actions.py` signatures (stdlib `inspect`/`typing`, no new runtime dep — ADR 0076 §6.5 forbids one in phases 1–2); IDE side, replace the hand-rolled per-op input rendering in `stepsModel.ts` (`ADD_MENU_CATALOG`, `TOOLBAR_INSERT_DEFAULTS`) with a schema-driven renderer. Keep `code`/`control` rows read-only.

**Open question:** whether the schema is emitted by the engine (one source of truth beside the vocabulary, matching the ADR 0072 L5/L6 split the lens already follows) or hard-coded in the IDE. Engine-side is the consistent choice and is the recommendation to test first.

**Related:** #222, ADR 0076 §2 (typed, mypy-strict vocabulary), [ADR 0106](adr/0106-steps-view-add-dropdown-vocabulary-expansion-adr-0076-phase-b.md) (the 27-item palette this would re-render), #237 (per-argument input modes — same form surface, land them together or in a deliberate order).

**Source:** Windmill/Kestra evaluation (2026-07-30) — "borrow the idea, not the product"; owner approved testing it as a separate lane.

## 236. Test-this-step and test-up-to-step with pinned upstream values

> 🔢 **Filed 2026-07-30 — not started.** Largely a stop condition + state dump on ADR 0072's traced dry-run; lookup rows must mock by default, not as an afterthought.

**Cluster:** IDE & Authoring. **Priority:** P2. **Verdict:** build (evaluate as its own lane). **Severity:** low.

**What:** the Steps view's Test control delegates to the Test Bench — it runs the **whole** handler. Windmill's OSS editor offers *test this step*, *test up to this step*, and **step mocking** (pin an upstream step's output and run from there). The analog: run a handler **up to row N** against a chosen synthetic sample and show the message state at that point; optionally pin an upstream row's result so a lower row can be exercised without re-running an expensive lookup.

**Why it fits the existing machinery:** the pieces are already shipped. ADR 0072's traced dry-run (`dryrun --trace json`) already produces per-line values and the lens already folds them onto rows by line containment (`mergeLiveValues`, `traceRowValues`), and the sample picker already exists (Test Bench pattern, defaulting to `messageSetsDir`). "Up to row N" is largely a **stop condition + a state dump** on a path that already runs.

**Hard parts:** (a) `db_lookup`/`fhir_lookup` rows do real I/O — "pin/mock upstream" is what makes partial runs safe and must be the default for lookup rows, not an afterthought; (b) the dirty-buffer misalignment of #225 applies identically (the trace reads disk); (c) **PHI**: any state dump reuses ADR 0072's `--show-phi` redaction gate unchanged, adds no second gate, and persists nothing — the lens's trace argv must remain incapable of emitting `--show-phi` (`buildLensTraceArgs`).

**Related:** #222, #225 (live values), [ADR 0072](adr/0072-traced-dryrun-mode.md) (traced dry-run + the redaction gate), Test Bench (`ide/src/testBench.ts`).

**Source:** Windmill/Kestra evaluation (2026-07-30); owner approved testing it as a separate lane from #235.

## 237. Per-argument input modes (static templated dynamic) in the Steps view

> 🔢 **Filed 2026-07-30 — not started.** Gated on #233: the duplicated move/drop logic is a prerequisite for touching this form surface.

**Cluster:** IDE & Authoring. **Priority:** P2. **Verdict:** build. **Severity:** low.

**What:** today a parameter slot is effectively **literal-or-refused** — a literal is editable, anything else (a `msg[...]` read, a concat, a conditional) collapses the row's editability. Windmill's flow editor instead gives every argument an explicit **mode**: *static* (a literal), *templated* (an interpolation over upstream values), or *dynamic* (an expression), with a picker over what is available upstream. Adopting the mode concept turns "this row is not editable" into "this argument is in dynamic mode", which is both more honest and more useful.

**Why it matters here specifically:** ADR 0089's estate scan found the editable/opaque split is driven by **value-expression shape** — it classifies every `msg.set` value as literal / field-copy / conditional / lookup / concat / replace / split / substring / trim / case. Those classes map almost one-to-one onto modes, so this is a presentation of a distinction the lens **already computes**, not new recognition.

**Build sketch:** surface the value-expression class in the `lens parse` row contract; render a mode selector per argument; static mode keeps today's plain input; templated mode offers the HL7 path picker (`hl7Picker.ts`) over the segment scope already built by `hl7scope.ts`; dynamic mode stays read-only in v1 (shows the verbatim source) so no new rewrite class is introduced.

**Sequencing:** shares the parameter-form surface with **#235**. Deciding the schema shape first (#235) and layering modes on top (#237) avoids reworking the renderer twice — but they are separately valuable and can be evaluated independently.

**Related:** #222, #235 (schema-driven forms), ADR 0089 §5 (the value-expression classifier this reuses), ADR 0104 §2.3 / `hl7Picker.ts` (the path picker).

**Source:** Windmill/Kestra evaluation (2026-07-30); owner approved.

## 238. OpenFlow step-attribute completeness pass over the engine vocabulary

> 🔢 **Filed 2026-07-30 — not started.** A review whose output is findings, not a feature; OpenFlow is explicitly **not** a compatibility target.

**Cluster:** IDE & Authoring / Engine. **Priority:** P3. **Verdict:** build (a review, not a feature). **Severity:** none — this is a gap-analysis task whose output is findings.

**What:** read Windmill's **OpenFlow** step-attribute vocabulary as a **completeness checklist** against MessageFoundry's own step/connector semantics, and record what is missing, what is deliberately absent, and what is already covered under a different name. The attributes to walk: `retry`, `timeout`, `stop_after_if`, `skip_if`, `continue_on_error`, `mock`, `cache_ttl`.

**Explicitly NOT the goal — do not target OpenFlow compatibility.** OpenFlow is an open standard (Apache-2.0, so safe to read and cite) but its `info.version` tracks Windmill's own release tag, i.e. one vendor's weekly train. Emitting or consuming OpenFlow is a **separate** question and is not authorized by this item. Adopting a *declarative artifact* remains declined by ADR 0076 §7 and #26.

**Expected output:** a short findings note (a research doc or an amendment to this item) listing, per attribute: covered / not covered / deliberately declined, with the MessageFoundry construct that covers it. Some will already be covered engine-side rather than in the Steps view (retry/timeout live in connector + delivery semantics, not in a handler row), and saying so precisely is most of the value.

**Related:** #222, ADR 0076 §7 (declarative artifact declined), #26 (the visual/declarative-authoring line).

**Source:** Windmill/Kestra evaluation (2026-07-30); owner approved the checklist framing explicitly ("don't target compatibility").

## 239. Re-measure Steps view estate coverage (opaque vs editable rows) after the palette

> ✅ **SHIPPED (2026-07-30, PR #81).** `scripts/quality/lens_coverage.py` drives the shipped `lens parse --json` — not a second `ast` walk — so the number cannot drift from what the Steps view actually renders. Measured against the de-identified estate: 388 files · 145 handlers · 1,423 rows · **0 parse refusals**; editable share **42.0%**, fully-typed handlers **14.5%** (21/145), median opaque rows/handler **3**. Full result and the pre-registered decision rule are recorded on PR #81.
>
> ⚠️ **The pre-registered rule fired 🔴 RED, and the RED prescription was *not* adopted** — both triggers landed exactly on their boundaries (B = 14.5% missed the 15% floor by 0.5pp; median opaque = 3 hit `≥ 3` exactly), while A = 42.0% sat mid-AMBER. The AMBER prescription (breadth before depth) was taken instead, on the argument that the opacity is *mechanical* — comment-only rows (28%) plus helper delegation (41.8%) are ~70% of the opaque mass and both are addressable within the projection model. **This override was a delegated judgment call, never explicitly ratified by the owner**; treat it as open if the next measurement does not move. See **#248** (comment-only rows — [ADR 0076](adr/0076-typed-action-vocabulary-action-list-lens.md) Amendment A, ratified 2026-07-30). ⚠️ **The other half of that "~70% of the opaque mass" argument no longer stands:** helper delegation was to be addressed by ADR 0089 Phase D, which the owner **declined 2026-07-30 as too risky** (ADR 0076 Amendment B) — and its 41.8% was a heuristic superset whose real yield may be negative. So the breadth-before-depth case now rests on comment-only rows alone; re-measure before assuming the number moves.

**Cluster:** IDE & Authoring. **Priority:** P1 — this number decides how much further Steps-view investment is justified. **Verdict:** build (cheap, reproducible). **Severity:** none (measurement).

**What:** re-run [ADR 0089](adr/0089-recognition-first-lens-native-idioms.md) §5's AST coverage scan against the current production estate and publish the delta. **The measurement already exists and must not be re-invented:** ADR 0089 §1 scanned **87 files / 486 `msg`-manipulating functions / 3,852 statements** and found **~66% of projected rows opaque** (`code` / `UNRECOGNIZED control`) with **100% of handlers rendering zero editable action rows**; the index row records **~42% editable after Phase A**. §5 states the scan is explicitly "a **repeatable** coverage check — re-running it after each phase measures the coverage lift and surfaces the shrinking residual".

**What is genuinely unknown:** the number *today*, after Phase A **plus** ADR 0106's 27-item palette, ADR 0108's send fan-out, and ADR 0104's picker landed. ADR 0089 §4 projects Phases A–D reaching **~80–90%** of transform statements against ~13% at baseline; nobody has confirmed where the current build actually sits, so the decision to build Phases B–E (or to stop) is being taken without the number that was designed to inform it.

**Estate note (owner, 2026-07-30):** the production corpus this scan runs against has been **renamed** since ADR 0089 was written — confirm the current path with the owner before scanning rather than assuming the ADR's. (Estate identifiers are customer tokens and stay out of the repo; the forbidden-content gate enforces this.) Note also that the ADR 0104 estate scan cites **152 handlers**, a different slice than ADR 0089's **486** `msg`-manipulating functions — state which population any new number describes.

**PHI:** the scan "reads only code (no PHI) and runs on any estate" (ADR 0089 §5) — keep that property; publish counts and shapes, never message content.

**Why P1:** if the residual opaque fraction is still high, the palette is decorating a surface most production handlers fall out of, and Phases B–E (or a different bet entirely) matter more than any new row type. If it is low, #232/#235/#236/#237 are the right next investments. Either way this is a scan re-run, not a build.

**Related:** ADR 0089 (the scan, the phases, and the erratum that phase work is tracked per-item at filing time — **not** by the stale #226–#230 range), #222, #235, #236, #237.

**Source:** Windmill/Kestra evaluation (2026-07-30). ⚠️ That evaluation initially asserted "nobody has measured" this — **incorrect**; the owner corrected it the same day and ADR 0089 carries the prior numbers. Filed as a **re-measure**, not a first measurement.

## 248. Steps view: reclassify comment-only rows as a non-opaque note row

> 🔢 **Filed 2026-07-30 — not started. UNBLOCKED 2026-07-30:** the ADR gate is cleared — **ADR 0076 Amendment A is ACCEPTED and in force** (owner-ratified 2026-07-30), so the grammar widening this item needs is authorized and the build may proceed. Treat Amendment A §A.4's invariants as **build gates, not caveats**, and note §A.6: this item does **not** fix comment re-attachment on move/delete, nor the parent-nesting of a comment at the end of an `if`/`for` body.

**Cluster:** IDE & Authoring. **Priority:** P2. **Verdict:** build (ADR-first). **Severity:** medium — three of the sub-defects are shipped user-visible breakage, not a coverage gap.

**What:** a run of standalone comment lines inside a handler body projects as an opaque `code` row. "Comment" is already an Add-palette item ([ADR 0106](adr/0106-steps-view-add-dropdown-vocabulary-expansion-adr-0076-phase-b.md) §5 (L)) that emits `# <text>`, so the palette writes a step the lens cannot read back as its own kind. Add a `note` row kind; see [ADR 0076](adr/0076-typed-action-vocabulary-action-list-lens.md) Amendment A for the row shape, the invariants it must preserve, and AC-N1…N6.

**Why this is not merely cosmetic — three defects reproducible on `main` today:**

1. **A Comment inserted after a handler's last statement is not rendered at all.** The partition covers `[body[0].lineno, node.end_lineno]` and `end_lineno` is the last *statement's* last line (`messagefoundry/lens.py:20-21`, by design), so the comment falls outside every row. Not degraded — absent. The row context menu offers **Insert after** on any non-return row, so it is one click away.
2. **A Comment adjacent to any other opaque or blank line produces no row of its own.** `_merge_code_rows` coalesces contiguous same-nesting `code` rows; an existing Code row silently grows by one line and the insert is invisible as a step.
3. **An inserted Comment cannot be edited, deleted, or moved.** `rewrite_source` gates on `_EDITABLE_KINDS` (`messagefoundry/lens.py:1377`), which excludes `code`. This contradicts the shipped user doc — `docs/STEPS-PALETTE.md:71`, "**Everything is editable after insert**" — for which Comment is the sole exception.

The existing test is too weak to catch any of it: `test_insert_comment_reads_back_as_code_row` asserts only `any(r["kind"] == "code" …)`, which passes even when the comment merged into an unrelated row. **Land failing tests for (1) and (2) first.**

**Coverage context (secondary, and must be re-derived, not quoted):** the #239 scan attributed **28% of opaque `code` rows (146 of 522)** to comment/blank-only content. That split was reported in PR #81's comments and is **not committed as data**; `scripts/quality/lens_coverage.py` is now on `main`, so re-run it rather than citing this line. Note also that counting notes as *editable* would move the #239 editable share by roughly ten points without converting a single transform statement — Amendment A §A.8 requires notes to be counted in their own bucket and excluded from the editable-share numerator.

**Gate:** a new row kind is a **grammar** widening — [ADR 0076](adr/0076-typed-action-vocabulary-action-list-lens.md) §2: "widening the roster is an ordinary addition, widening the *grammar* requires amending this ADR." Amendment A also **supersedes an owner-ratified decision** (ADR 0106 §5 (L) called the `code` degrade an "honest degrade"), so the owner must rule before any build.

**Explicitly not this item:** grouping, collapse, `#region` folding, or any "the steps below belong to this note" membership — that is #231, **declined by owner ruling 2026-07-20**, and Amendment A §A.5 restates the boundary so it is not re-litigated in good faith.

**Related:** #222 (the Steps view), #231 (declined Block grouping), #233 (duplicated move/drop logic — gates comment *attachment*), #239 (the scan), ADR 0076 Amendment A, ADR 0106 §5 (L).

**Source:** Windmill/Kestra evaluation (2026-07-30); the three defects were verified against `origin/main` on 2026-07-30 while drafting Amendment A.

## 249. `lens graph`: mermaid and dot export formats

> 🔢 **Filed 2026-07-30 — not started, and not yet accepted.** Salvaged from a declined design; the owner has not ruled on whether to fund it.

**Cluster:** IDE & Authoring. **Priority:** P3. **Verdict:** **owner decision pending** — proposed, not approved. **Severity:** none (additive capability).

**What:** add `--format mermaid|dot` to the existing `graph --json` command, so an interface's topology can be rendered as a diagram from the CLI without a second tool.

**Where it came from:** the 2026-07-30 Windmill/Kestra evaluation scored five integration designs. The one called "Tracing Paper" — a one-way OpenFlow export — **scored 5.7 and was declined**. This is the salvage from it: the estimate recorded at the time was **2–3 days**, and unlike the declined design it introduces no foreign artifact format and no second execution path.

**Why it is filed rather than built:** it was a recommendation in a design memo that the owner never answered, and that memo has since been deleted. Filing preserves the option at its stated price; it does not approve it.

**Related:** #238 (OpenFlow attribute checklist — the other salvage from the same evaluation), ADR 0076 (the lens CLI surface).

**Source:** Windmill/Kestra evaluation (2026-07-30), "Tracing Paper" design, declined; salvage recorded here so the estimate is not lost with the memo.

## 250. Frozen ops OpenAPI + `messagefoundry-ops` wheel

> ⛔ **DECLINED by owner ruling 2026-07-30 — decline-by-design.** The premise is rejected, not the price: *"a customer can drive MessageFoundry from tooling they already run"* is **not a direction this project takes**. The ~6-week estimate below was never the question. Recorded so it is not re-proposed as an obvious ops win — it is the shape that is refused, not the cost.
>
> ⚠️ **This ruling is broader than this item.** It rejects the whole *external-tooling-drives-MessageFoundry* line, which is why **#251 falls with it** (see below). It does **not** touch capabilities MessageFoundry drives itself and merely *emits* from — e.g. #249's `--format mermaid|dot` export is unaffected, because nothing external is driving anything. The distinction that matters is **direction of control**, not whether an interface exists.

**Cluster:** Operations. **Verdict:** **⛔ declined-by-design (2026-07-30)** — the premise is refused; do not re-score. **Severity:** none.

**The buyer question below is now moot for this item, and is NOT the reason it was declined.** It was filed as unresolved because the source memo's ranking assumed a small-team buyer and inverted for health systems with platform teams. The owner declined on the *shape of the integration*, without needing that question answered — so nothing here is waiting on a buyer-segment decision, and a future session must not reopen this item by claiming the assumption has since been settled.

**What:** a frozen, versioned OpenAPI description of the operational surface plus a `messagefoundry-ops` client wheel, so a customer can drive MessageFoundry from tooling they already run.

**Why it was surfaced:** the 2026-07-30 evaluation of Windmill and Kestra concluded **against** adopting either as a runtime or an authoring UI. This is the finding that survived that conclusion: the estimate recorded at the time was **~6 weeks**, and it was described as paying off against a customer's existing Ansible/Jenkins/PowerShell **with no orchestrator adopted at all** — i.e. its value does not depend on the orchestrator question being reopened.

**Unresolved, and material to the decision:** the same memo flagged that its ranking assumed a **small-team buyer**, and that the ranking **inverts** if MessageFoundry is targeting health systems with platform teams. That assumption was never confirmed with the owner and should be settled before this is priced seriously.

**Related:** #251 (the reduced Kestra-only form of the same ops surface), ADR 0072 (traced dry-run).

**Source:** Windmill/Kestra evaluation (2026-07-30). Recorded here because the design memo holding it has been deleted.

## 251. Kestra-only read-only ops tasks (reduced "Anvil Ops")

> ⛔ **DECLINED 2026-07-30 — falls with #250, under the same owner ruling.** This item *is* the rejected idea in reduced form: exposing MessageFoundry as tasks inside a customer's existing Kestra instance is exactly *"a customer drives MessageFoundry from tooling they already run."* Read-only scope and a ticket-not-replay dead-letter rule narrow the blast radius; they do not change the direction of control, which is what was refused. Its own stated precondition — *"only if #250 is funded first"* — is independently unmet, since #250 is declined.
>
> ⚠️ **Provenance:** the owner ruled explicitly on **#250**. This item was declined by the session recording that ruling, as a direct consequence of it plus the unmet precondition — **not by a separate owner ruling on #251**. If the intent was to refuse only the OpenAPI/wheel and keep a reduced Kestra-only form alive, this banner is the thing to correct.

**Cluster:** Operations. **Verdict:** **⛔ declined (2026-07-30)** — consequent to #250; do not re-score. **Severity:** none.

**What:** expose MessageFoundry as a small set of **read-only** tasks inside a customer's existing Kestra instance — Health, Status, ClusterStatus, SecurityPosture, DeadLetters-list — with dead-letter handling that raises a **ticket rather than replaying**, and a hard 12-month review. Estimate recorded at the time: **~5 weeks**.

**The conditions are the point.** The full "Anvil Ops Tasks" design scored **6.3** and was accepted **in reduced form only, Kestra-only, if ever** — never as a general orchestrator integration. The message path stays entirely inside MessageFoundry: no orchestrator owns route → transform → deliver (that design, "Two-Queue Windmill", scored **1.0** and was declined). Anything that lets the orchestrator mutate or replay messages is a different item and was rejected.

**Related:** #250 (the ops API this would sit on), #238, #26 (the declined visual-authoring line — why a declarative artifact interpreted by a second execution path is out).

**Source:** Windmill/Kestra evaluation (2026-07-30), "Anvil Ops Tasks" design. Recorded here because the design memo holding the conditions has been deleted.
## 316. DICOM SCP peer-control gate counts a spoofable AE-title list as sufficient

> ✅ **SHIPPED — 2026-07-30. Option (a): pair, do not remove.** Off-loopback, the gate now requires a **verifiable** control — `source_ip_allowlist` or mTLS. `calling_ae_allowlist` no longer satisfies it alone, but is **kept and still enforced** at association time as a filter, so nothing that was useful about it is lost. Measured: AE-title-only off-loopback goes STARTS → REFUSED; AE-title **paired** with an IP allowlist starts; IP-only and mTLS-only are unchanged; every loopback case is unchanged. Breaking for a site relying on AE-title-alone off-loopback — see CHANGELOG. Options (b) audited-opt-out and (c) document-only were declined by the owner in favour of (a).

**Type:** security hardening — authentication strength of a fail-closed gate.

**What:** `transports/dicom.py` refuses a non-loopback C-STORE SCP that has *no* peer control, but the check **counts controls rather than weighing them**:

```python
mtls_on = bool(s.get("tls")) and bool(s.get("tls_ca_file"))
if self._host not in _LOOPBACK_HOSTS and not (
    self._calling_ae_allowlist or self._source_ip_allowlist or mtls_on
):
```

So `calling_ae_allowlist` **alone** satisfies a gate whose stated purpose is to fail closed. A DICOM Calling AE Title is a **caller-asserted string with no cryptographic binding** — any peer that guesses or learns one AE Title is admitted. Empirically confirmed: an SCP on `0.0.0.0` with only `calling_ae_allowlist=["MOD1"]` constructs without error.

**Why it is filed rather than fixed:** the three-control set is a documented contract — [ADR 0025](adr/0025-dicom-codec-store-connectors.md) §9 and the `docs/SECURITY.md` decision-table row both enumerate `calling_ae_allowlist` / `source_ip_allowlist` / mTLS as co-equal satisfiers. Demoting one is an ADR amendment and a breaking change for any site relying on it, so it needs its own decision rather than being a rider on a message correction.

**Options:** (a) keep three satisfiers but require AE-title to be paired with an IP allowlist or mTLS off-loopback; (b) demote AE-title to *not* satisfying the gate alone, with an explicit audited opt-out mirroring the other loosenings; (c) accept as-is and document the weakness at the gate (the refusal message now warns about it in-band).

**Related:** ADR 0025 §9, `docs/SECURITY.md` DICOM peer-control row, `tests/test_dicom_scp_security.py::test_nonloopback_scp_with_calling_ae_allowlist_ok` (pins the current behaviour, so it changes with the decision).

**Source:** adversarial documentation security review (2026-07-30); the message/doc half shipped alongside this filing.

## 318. DAST — authenticated dynamic security testing of the running engine

> 🚧 **In progress 2026-07-31.** Increment 1 built: an authenticated authorization sweep against a live loopback listener in front of a real engine (negative / authorized-reach / viewer BFLA), with fail-closed floors and two canaries. Increment 2 — schema-driven breadth, the unauthenticated MLLP/TCP/X12 ingress plane, the /ui console plane and a TLS black-box target — is not built.

**Type:** security testing — dynamic (DAST) tier of [`Secure_Development_Standards`](Secure_Development_Standards.md) §6.1.

**What:** a self-run, deterministic, **zero-new-dependency** authorization sweep against a real HTTP listener. One `uvicorn` server binds loopback on an ephemeral port, on one event loop, in front of a real `Engine` and a real `AuthService`; an administrator and a viewer identity are minted **over the wire** through `POST /auth/login`. The authorization expectation is **derived from the live route table** — a single shared `require*()`-closure walk in `scripts/security/route_gates.py`, hoisted out of the security doc-drift guard so exactly one derivation exists — never a hand-kept route→permission list. Three passes: **negative** (every gated HTTP row sent with no credential and with an invalid bearer; anything but 401 is a finding), **authorized reach** (how many gated `GET` rows a *privileged* token got past authentication and authorization on), and **viewer BFLA** (anything but a refusal, including 404, is a finding). The run writes a receipt naming what it examined and **fails closed** — below any floor it exits 2 (could not measure), never 0.

**Why:** every security test in the tree is static or in-process; nothing had ever driven the HTTP surface over a real socket with real credentials, so the §6.1 *Dynamic* row was empty. The specific hazard is that a deny-by-default API rewards a lazy scanner: point an unauthenticated crawler at it, get 401 everywhere, exit 0, and read it as *all endpoints protected* having proved nothing. The **authorized reach** count is the direct answer to that, and the two canaries — built from **supported configuration, not source patches**, so there is nothing anchored to line numbers to rot — prove each run that the sweep can still see a real defect. The merge-blocking half is deliberately elsewhere: the sweep and canaries run as ordinary pytest inside the **existing required** test legs (so blinding the detector reds a PR), while the nightly workflow is advisory — no `pull_request` trigger, and deliberately **not** `continue-on-error`.

**Boundary:** see ADR 0155 §*Scope boundary*. It is stated once, there; this item deliberately carries a pointer and no wording of its own, because a paraphrase here would survive the next revision of that section and become a second, contradictory answer.

**Increment 2 (not built):** schema-driven breadth (needs an OpenAPI security overlay and a fifth DEP-1 lock); protocol fuzzing of the unauthenticated MLLP / raw-TCP / X12 ingress (highest-value deferred item — note that BACKLOG #89's *"ADR 0054 adversarial audit harness"* does not exist, so there is no mutator to extend); DICOM DIMSE (pynetdicom owns the socket, so there is no engine-owned reader to drive); the `/ui` console plane; a TLS black-box target for the https-gated controls; a shipped-defaults controls probe (the scan relaxes MFA, four limiters, lockout and step-up freshness, and prints every relaxation in the receipt); and non-`GET` reach/BFLA.

**Known gap carried by increment 1 (follow-up, not deferred scope):** a red DAST nightly notifies nobody. `nightly-notice.yml` opens an issue only for the workflow named `CI`, and `dast.yml` has no `pull_request` arm and is not a required context, so a genuine finding surfaces in the Actions tab and nowhere else. Widening the notice workflow's `workflows:` list (with the matching edit to `tests/test_nightly_notice.py`, which pins that name) is the fix; it is recorded here so it is a tracked item rather than a footnote.

**Related:** ADR 0155, `.github/workflows/dast.yml`, `scripts/security/dast_auth_sweep.py`, `scripts/security/route_gates.py`, `scripts/security/dast-policy.json`, `tests/test_dast_auth_sweep.py`, `tests/test_dast_claims.py`, [`Secure_Development_Standards`](Secure_Development_Standards.md) §6.1 / §A.6.

**Source:** the empty §6.1 *Dynamic* tier row, filed and built 2026-07-31.

## 320. windows-2025 MLLP ingress is ~10x slower than a healthy runner

> 🚧 **Status: OPEN INVESTIGATION (filed 2026-08-01, not started).** Diagnosis only — the CI symptom is already fixed (#115, `06fd327d`) by widening the reconcile's stranding budget. This item is the **underlying capacity fact**, which that fix does not address and deliberately did not try to. Tooling to measure it landed in #118 (`harness/load/ingress_probe.py` + a dispatch-only sweep across ubuntu / windows-2022 / windows-2025). The decisive experiment — the same sweep on the **self-hosted WS2025 rig** — is blocked: that runner is unregistered (`actions/runners` → `total_count: 0`) and `selfhosted-win2025-sql.yml` has never run.

**Type:** CI/runner capacity — not a correctness defect. No message was ever lost in any observed instance.

**What:** the `test (windows-2025, py3.14)` leg cannot service the load smoke's offered rate. `tests/test_load_runner.py` offers **60 msg/s for 1.5s** (90 messages, `pool_size = 4`) at a listener whose ingress is **strictly serial per connection** — `mllp.py:1433` is `read chunk → for each frame → await handler → next`, where the handler is the durable ingress commit the ACK depends on. Total ingress throughput is therefore `pool_size ÷ per-message-commit-latency`. On windows-2025 that product is under 60/s, so roughly half the offered run is never ingested inside the measurement window and strands unacknowledged at teardown.

**Measured (2026-08-01), and one measurement RETRACTED — read this before quoting a number.**

The first write-up of this item claimed the CI signature reproduces on a healthy developer box purely by raising the offered rate, on the strength of a single 600/s run that stranded **456 of 900 (50.7%)** — a near-exact match for windows-2025's 51.1%. **Four repeats of that same command on that same box then stranded 0, every time.** The outlier was taken while an unrelated test suite was running concurrently.

So that reproduction is **withdrawn**. Stranding on a developer box is a **contention** artifact, not a clean function of offered rate, and n=1 is not a measurement — which is exactly the failure mode this item is about, committed while documenting it.

What the repeats support:

| offered | runs | stranded | engine_read |
|---|---|---|---|
| 60/s | 1 | **0 (0.0%)** | 90 of 90 |
| 300/s | 1 | **0 (0.0%)** | 450 of 450 |
| 600/s | 5 | **0 in 4 runs**; 50.7% in the 1 contended run | ~899 of ~899 when unloaded |

**The surviving claim is weaker and still worth acting on:** an unloaded box strands **zero** at up to 10× the CI profile's offered rate, while windows-2025 stranded ~51% at the profile's own **60/s** — twice, on `9b03057f` and `56f7d240`, with **byte-identical** counters (90 sent / 44 acked / 46 stranded / 52 read). Byte-identical repetition is what rules out weather *on that leg*; it is not evidence about a developer box, and the earlier entry conflated the two.

**Why it matters even though nothing is lost:** it recurs, it will recur on any profile whose offered rate approaches that leg's service rate, and it is invisible to a correctness check because delivery is complete every time (104 written, 104 received, backlog drained in 4.7s of a 30s bound).

**Tooling:** `harness/load/ingress_probe.py` + `.github/workflows/ingress-rate-probe.yml` (dispatch-only) now sweep the rate across ubuntu / windows-2022 / windows-2025 with `--repeat`, so the next person reads a distribution instead of a lucky row.

**Correcting the record:** `harness/load/report.py` previously justified the stranding budget with *"observed teardown stranding is ~16%, so half is ~3x the worst seen."* Both halves are wrong. **Healthy stranding at this rate is 0%**, not 16% — the 16% figure was itself measured on a partially-saturated run — and "half" was ~1.0x the worst seen by the time it red `main`, not 3x.

**Not yet determined:** *why* that runner's per-message commit is ~10x slower. Disk/fsync characteristics of the hosted windows-2025 image, Defender scanning the temp SQLite DB, and CPU contention are all plausible; none has been measured, and it cannot be measured from outside the runner.

**Adjacent finding, unverified:** at saturation `engine_read` (452) cleared the reconcile's unconditional anti-vacuity floor `read >= sent // 2` (450) by **two messages**. A breach of that floor is a hard failure no budget widening can rescue. A probe at 1200/s did *not* reproduce it, but that run is not comparable — its drain timed out (`max_drain_seconds` observed `-1.0`) and it took the branch that skips the settle-poll. Untested, not disproven.

**Related:** #115 (`06fd327d`, the budget fix), `harness/load/report.py` `_reconcile`, `harness/load/connscale/runner.py`, `harness/load/estate/runner.py`, `tests/test_load_runner.py`, `tests/test_harness_reconcile.py`, `messagefoundry/transports/mllp.py:1433`, and the sibling windows-2025 failure `test_coord_lock` (fixed in #109) — a *different* mechanism on the same leg.

**Source:** investigation of the `test_run_load_end_to_end_no_loss` failures on `main` at `9b03057f` and `56f7d240`, 2026-08-01.

---

## 321. Leak gate is blind to the ported-estate site-code and partner-product token class

> 🔢 **Filed 2026-08-01 — not started.** Value **7/10** · Difficulty **3/10** · _fill-in_. The forbidden-content gate exits 0 on content carrying a ported-estate site code and a partner product name; the class was never gated, so the redaction that removed them was not a duplicate of any control.

**Cluster:** Security / Supply chain. **Priority:** P1. **Verdict:** build. **Severity:** medium.

**What:** `scripts/security/scan_forbidden.py` does **not** detect the estate tokens that were sitting in `docs/BACKLOG.md` items #226/#228 until `f3c6d348` removed them — a six-digit ported-estate site code embedded in a feed-module identifier (`IB_FILE_HR_Materials_<site>_MFN.py`, `xform_<site>_to_erp_mfn`) and a partner ECG product name. Measured 2026-08-01 against the **real** token set (`loaded names=7, estate=13, estate_file_scanned=12, site_prefixes=1` — the CI-authoritative load, not the synthetic example):

```
git show HEAD~1:docs/BACKLOG.md > $T/docs/BACKLOG.md
python scripts/security/scan_forbidden.py --path $T   # -> exit 0, clean
```

`.md` is **not** in `_SITE_SKIP_SUFFIXES` (`{".lock", ".svg"}`) and `docs/BACKLOG.md` is not in `scan-allowlist.txt`, so the file *was* scanned — the detectors simply do not cover these values. The configured `[site_prefix]` does not match this site code's prefix, and the partner product is absent from `[names]`/`[estate]`.

**Why:** this is the repo's evergreen lesson firing again — *a GREEN gate is evidence only if you proved it can SEE that class.* The gate is a **required merge context**, so a green run reads to a reviewer as "no customer tokens present." Here it was green on content that contained two. Nothing stops the next estate-derived identifier landing the same way, and the migration estate is an active source of them (#226 is an open estate-wide sweep whose examples are drawn from real ported feeds).

Note the item is **not** "the scanner is broken" — it is that the token *source* is incomplete and there is no test proving the detector set covers the classes the project actually leaks. Presence of a source is not sufficiency.

**Proposed:**
1. Add the real site-code prefix and the partner product name to the private token source (owner-run; the file is git-ignored and never committed), and to the `MEFOR_FORBIDDEN_TOKENS` Actions **and Dependabot** secret stores — both, or every Dependabot PR hard-fails the required check.
2. Add a **negative** regression test: a fixture line carrying a synthetic value of each class must make the scanner exit 1. Today no test asserts the detectors can see a site code at all, which is why the hole was invisible.
3. Consider a structural backstop for the estate-identifier *shape* (`[A-Z]{2}_[A-Z]+_[A-Z]+_\d{6}_[A-Z]{3}\.py`) so a NEW site code trips even before anyone adds it to the token list — the same argument #320-adjacent work makes for MRN/SSN/DOB detectors in `anon/leak.py` (ADR 0030 §5's known gap).

**Related:** `scripts/security/scan_forbidden.py`, `scripts/security/scan-tokens.local.txt.example`, `tests/test_scan_forbidden.py`, `messagefoundry/anon/leak.py`, [`docs/SECURITY-DOCS-POLICY.md`](SECURITY-DOCS-POLICY.md), #322.

**Source:** public-repo disclosure audit, 2026-08-01 (commit `f3c6d348`). The tokens were found by reading, not by the gate.

---

## 322. Synthetic leak-gate placeholders can collide with the real gate's own guards

> 🔢 **Filed 2026-08-01 — not started.** Value **4/10** · Difficulty **2/10** · _fill-in_. Redacting a real token to a placeholder built on the example token file's **own** designated synthetic site prefix blocks every commit for any contributor running the synthetic set — because that prefix is exactly what the synthetic `[site_prefix]` detector looks for. Caught pre-commit; nothing shipped.

**Cluster:** Security / DX. **Priority:** P3. **Verdict:** build (small). **Severity:** low.

> **This item deliberately does not spell out the offending value.** Writing the prefix, or the prefix followed by four digits, would trip the very detector described — `[site_prefix]` builds *two* patterns from its entry: the prefix plus four digits, **and** the pattern written out as an x-run or quantifier. That recursion is the whole point of the item, so it is demonstrated rather than described.

**What:** while redacting the #321 tokens, the first replacement chosen followed `scripts/security/scan-tokens.local.txt.example`'s own stated convention — that file designates a specific non-real numeric prefix for synthetic use, and the replacement was built from it. Under the **real** token set that value is clean. Under the **synthetic** set it is a site-code hit, twice, and the scan exits 1:

```
MEFOR_FORBIDDEN_TOKENS=scripts/security/scan-tokens.local.txt.example \
  python scripts/security/scan_forbidden.py --path $T
# -> docs/BACKLOG.md:<line>: site code  (x2), exit 1
```

`scripts/dev/setup-leak-gate.ps1 -Synthetic` is a **documented, supported contributor setup** (the example file calls it so in its own header), and the pre-commit hook passes `--require-tokens`, so it blocks *every* commit — not just ones touching that file. A contributor with no access to the real token list would hit an unexplained hard block on unrelated work. The final commit uses the non-numeric `SITEA` instead, which cannot collide with any numeric detector.

**Why:** the example file's synthetic-prefix guidance is written for the person filling in the **token list**, where it is correct and necessary. But it reads as general guidance for *placeholder values*, and a placeholder written into tracked prose is then scanned by the gate that list configures. The convention is self-colliding for its second audience, and nothing warns you. The same trap caught [#325](BACKLOG.md), whose worked examples had to be rewritten to the exempt `<name>` form for exactly this reason.

**Proposed:** state in `scan-tokens.local.txt.example` (and in the redaction guidance) that a placeholder written **into tracked content** must not use any prefix appearing in `[site_prefix]` in *either* the real or the example set — prefer a non-numeric stand-in (`SITEA`, `<site>`), matching the `<…>` convention `_HOME_PATH` already exempts. Optionally have the scanner's hit message name the loaded set, so a synthetic-set false positive is self-diagnosing rather than reading as a real leak.

**Related:** `scripts/security/scan-tokens.local.txt.example`, `scripts/dev/setup-leak-gate.ps1`, `.pre-commit-config.yaml` (the `--require-tokens` arm), #321.

**Source:** public-repo disclosure audit, 2026-08-01; found by testing the redaction under both token sets before committing `f3c6d348`.


---

## 323. SMTP TLS is unverified on all three send paths

> 🚧 **Status 2026-08-01 — PARTIALLY SHIPPED, 2 of 3 cells** (PR #132). The two **connectors** verify: `EmailDestination` and `DirectDestination` build an explicit verifying context via the new `tls_policy.build_smtp_tls_context()` and pass it on both `smtplib` arms, with per-connection `tls_verify` / `tls_ca_file` / `tls_check_hostname` on the `Email()` and `Direct()` factories. Proven by **negative control**: with the code change stashed and the tests kept, all eight new assertions in `tests/test_email_destination.py` go **red** — the pre-existing "STARTTLS was issued" assertions stayed green throughout the insecure period and could never have caught this. ⚠️ **The alerts cell is NOT fixed**: `pipeline/alert_sinks.py:384` still calls `smtp.starttls()` bare, so alert + security-notify email remains unverified. That is the residual below, and it is why [#139](#139)'s premise is still false.
>
> 🔢 **Filed 2026-08-01.** Value **8/10** · Difficulty **4/10** · _fill-in_. All SMTP send paths called `starttls()` / `SMTP_SSL()` with **no** SSL context, so Python 3.14's stdlib default applied (`ssl._create_stdlib_context` **is** `ssl._create_unverified_context` — `CERT_NONE`, `check_hostname=False`) — the EMAIL destination put Handler PHI *and* the SMTP AUTH password over an encrypted-but-unauthenticated hop, while the #201 revocation guard, the cleartext-credential rule and `DEPLOYMENT.md` all described that same hop as **verified**.

**Residual — the alerts cell (~1 layer).** `pipeline/alert_sinks.py` `send_plain_email` and `pipeline/security_notify.py` need the same context, plumbed from new `[alerts].email_tls_verify` / `email_tls_ca_file`, plus a `[security].allow_unverified_alert_smtp_tls` acknowledgment switch at the serve gate. It needs an **acknowledgment switch rather than the clamp** because the contextvar hop posture is never stamped for that cell — which is why it was deferred rather than folded in. The shared `refuse_unverified_smtp_tls()` helper belongs in `config/settings.py` at that point; the connectors currently **inline** the refusal, matching the `mllp.py` / `remotefile.py` house style. Then: register the deviation in `security_loosenings()` (see [#333](#333)), add a `checks.py` advisory, and correct `docs/PHI.md` and [#139](#139).

**Also landed, called out rather than folded in silently.** `transports/direct.py`'s cleartext arm read the **unclamped** `insecure_tls_allowed()` while its sibling arm one branch away read the clamped `weakened_tls_escape_permitted_here()`. Two different escapes in one connector is how the next bug gets written, so it now reads the clamped one. Strictly **adds** refusals (ADR 0092 decision 5). Partially closes the [#329](#329) concern.

**Correction to this item's own text.** The "Migration risk, stated plainly" framing filed with this item presumed existing deployments. The owner confirmed on 2026-08-01 that **there are none**, so secure-by-default was simply correct and no phased rollout, CHANGELOG breaking entry or migration guide was warranted. Do not resurrect that framing from this item's history.

**Cluster:** Security & Compliance. **Priority:** P1. **Verdict:** build. **Severity:** high.

**What:** Every SMTP send in the product opens TLS with no `context` argument:

| Site | Call |
|---|---|
| `messagefoundry/transports/email.py:216` | `smtp.starttls()` |
| `messagefoundry/transports/email.py:213` | `smtplib.SMTP_SSL(self.host, self.port, timeout=self.timeout)` |
| `messagefoundry/transports/direct.py:323` | `smtp.starttls()` |
| `messagefoundry/transports/direct.py:320` | `smtplib.SMTP_SSL(self.host, self.port, timeout=self.timeout)` |
| `messagefoundry/pipeline/alert_sinks.py:384` | `smtp.starttls()` |

Measured against the interpreter the project requires (`>=3.14`; local 3.14.6), that resolves to an **unverified** context on both arms — this is stdlib source, not inference:

```
Lib/smtplib.py:789-790   if context is None:
                             context = ssl._create_stdlib_context()     # SMTP.starttls
Lib/smtplib.py:1031-1032 if context is None:
                             context = ssl._create_stdlib_context()     # SMTP_SSL.__init__
Lib/ssl.py:789           _create_stdlib_context = _create_unverified_context
Lib/ssl.py:730-731       def _create_unverified_context(protocol=None, *, cert_reqs=CERT_NONE,
                                                        check_hostname=False, ...)
```

Nothing in the product moves that default: grep for `_create_default_https_context` / `_create_stdlib_context` / `_create_unverified_context` across `messagefoundry/` and `tee/` returns **zero** hits. There is also no knob to fix it per connection — the Email factory exposes only `use_tls` (`config/wiring.py:1615-1640`, read at `transports/email.py:110`); there is no `tls_verify`, no `ca_cert`.

**Three compensating controls rest on the false premise that this hop verifies** — the failure mode CLAUDE.md §11 names explicitly:

1. `transports/email.py:173` — *"STARTTLS (587) / implicit-TLS SMTP_SSL (465) verifies the server cert"*. It does not.
2. `transports/email.py:182-187` runs `RevocationHopGuard` on that hop, labelled `cell="Email destination (verified SMTP TLS, no revocation check)"` and `description="delivers over verified SMTP TLS but performs no certificate revocation checking"` (`:184-185`). The guard is defined for *"a **VERIFYING** outbound TLS hop"* (`config/tls_policy.py:685`, `:721`) and its docstring asserts *"the caller has already built a verifying context"* (`:703`). So on an enforcing production-PHI instance the engine **refuses to start** because a verified certificate might be *revoked*, on a hop that never checked the certificate at all.
3. `transports/email.py:147-151` refuses SMTP AUTH only when `use_tls=false` (*"refused — credentials require STARTTLS/implicit TLS"*). With `use_tls=true` the password is sent over the unverified hop, so an on-path attacker presenting any self-signed certificate harvests it.

The same false premise is published to operators: `docs/DEPLOYMENT.md:129` counts *"SMTP/EMAIL"* among *"**seven** verifying outbound TLS hops"*, and #201's shipped banner (`docs/BACKLOG.md:6430`) says the guard *"fires only on a VERIFYING hop"*.

`docs/PHI.md:916` is the one place that is **honest** — it states the `send_plain_email` defect plainly and correctly notes *"PR #1163 hardened the EMAIL message destination connector, not the `[alerts]` SMTP path"*. That doc is right about the alerts path and stays; what it does not say is that the destination connector it points at has the identical defect.

**Why:** The EMAIL destination is a PHI egress — the Handler payload **is** the body (`transports/email.py:197-205`). "Encrypted but unauthenticated" means an active on-path attacker terminates the TLS session with any self-signed certificate and reads the PHI in clear, then relays. The engine's own posture machinery cannot see this: #200 keys on `use_tls=false` / `tls_verify=false` and #201 keys on revocation, so a `use_tls=true` EMAIL connection passes **every** hop gate as a secure hop.

Honestly bounded — this is not remotely exploitable on its own:

- It **requires network position** (on-path MITM: ARP/DNS/BGP interception, or a compromised intermediate) between the engine and the SMTP server. An attacker without that position gets nothing.
- **`direct.py` is materially less bad.** Its clinical payload is S/MIME signed+encrypted at the *message* layer, independent of transport TLS (ADR 0085; `transports/direct.py:3-15`), so a TLS MITM there gets envelope metadata, recipients and the AUTH credential — not the clinical body. It is also the one path with no `RevocationHopGuard` at all (grep: the guard appears in `mllp.py:736`, `rest.py:642`, `email.py:182`, never `direct.py`).
- **The credential exposure is bounded.** It is a mail-submission password; an attacker already on that hop can already read the messages, so it mostly buys persistence and relay abuse rather than a larger PHI win.
- **No other transport is affected.** MLLP/FTPS/REST/SOAP/FHIR/DICOM-SCU all build explicit contexts through `config/tls_policy.py` helpers (`_mllp_ssl_context` and siblings, per #129's write-up at `docs/BACKLOG.md:5046`). This is specific to the `smtplib` seam — which is precisely *why* it escaped: the shared TLS-policy helpers are never called on it.
- **Nothing here is a regression.** It has been the behaviour since ADR 0029; #201's amendment layered a guard on top without checking the premise.

The reason to rate this high anyway is the second-order damage: a green posture gate and a `DEPLOYMENT.md` table currently tell an operator this hop is verified. A control that lies is worse than an absent one.

**Proposed:**

1. Add one shared verifying-context factory for the `smtplib` seam in `config/tls_policy.py` (reusing the existing hardening helpers, so `VERIFY_X509_STRICT` and the expiry-relaxation path compose), and pass it as `context=` at all five call sites above.
2. Expose per-connection `tls_verify` + `ca_cert` on the `Email()` / `Direct()` factories and the `[alerts].email_*` settings, so a private-CA or self-signed mail server is served by **trust configuration**, not by silent non-verification.
3. Route any resulting `tls_verify=false` through the **same** #200 posture gate as MLLP/FTPS (`docs/BACKLOG.md:6410`), so a production-PHI instance refuses it. Then #201's `RevocationHopGuard` on this path becomes true rather than aspirational.
4. Correct the false-premise prose in the same commit: `transports/email.py:173`, the guard labels at `:184-185`, `config/tls_policy.py:703`, `docs/DEPLOYMENT.md:129`, and the #201 banner at `docs/BACKLOG.md:6430`. Update `docs/PHI.md:916` to cover all three paths once fixed.
5. Tests: the three fake SMTPs (`tests/test_email_destination.py:57`, `tests/test_direct_transport.py:182`, `tests/test_alert_sinks.py:247`) all declare `def starttls(self) -> None:` with **no** `context` parameter and none asserts verification — they will need the kwarg, plus a positive assertion that the passed context has `check_hostname=True` / `verify_mode=CERT_REQUIRED`. A real-handshake test against a wrong-host certificate is the one that would actually have caught this.

**Migration risk, stated plainly:** turning verification on is a **breaking change** for any deployment currently pointed at a self-signed or private-CA mail server — those sends begin failing at `starttls()`. Step 2 is the mitigation and must land in the same release, with a release note.

**Related:** [`messagefoundry/transports/email.py`](../messagefoundry/transports/email.py), [`messagefoundry/transports/direct.py`](../messagefoundry/transports/direct.py), [`messagefoundry/pipeline/alert_sinks.py`](../messagefoundry/pipeline/alert_sinks.py), [`messagefoundry/config/tls_policy.py`](../messagefoundry/config/tls_policy.py), [ADR 0029](adr/0029-email-smtp-destination.md), [ADR 0078](adr/0078-certificate-revocation-posture.md), [ADR 0085](adr/0085-direct-hisp-smime-connector.md), [ADR 0092](adr/0092-posture-keyed-transport-hop-refusal-refuse-the-insecure-phi-hop.md), [`docs/PHI.md`](PHI.md) §7 stream 11, [`docs/DEPLOYMENT.md`](DEPLOYMENT.md), #200, #201, #139.

**Amends #139:** its rationale at `docs/BACKLOG.md:5264` — *"The engine's `EmailAlertSink` uses STARTTLS with a verifying context by design"* — is **false** and should be retracted there. Note that #139's own **Why:** two lines earlier at `:5262` is accurate (*"calls `starttls()` with the default SSL context"*), so the item contradicts itself; fix both lines together. Note also the inversion: #139 declines building an opt-in trust-any-certificate toggle because *"unconditionally trusting an SMTP server's TLS certificate defeats TLS"*, while the code already does exactly that, unconditionally, with no toggle to turn it off. Once this item lands, #139's decline becomes coherent for the first time.

**Source:** public-repo disclosure audit, 2026-08-01. Classified CLOSE-THE-WEAKNESS-INSTEAD: `docs/PHI.md:916` is accurate and stays; the defect it describes is wider than the doc's scope.

---

---

## 324. Custom role with `messages:edit` alone reads raw PHI via the `/ui` editor

> 🔢 **Filed 2026-08-01 — not started.** Value **7/10** · Difficulty **2/10** · _fill-in_. `GET /ui/messages/{id}/edit` renders the stored raw body on `messages:edit` alone, and nothing stops an admin minting a custom role that holds it without `messages:view_raw` — so a role meaning "may resubmit, must not read" reads PHI.

**Cluster:** Security / RBAC. **Priority:** P1. **Verdict:** build. **Severity:** medium.

**What:** four links, each individually reasonable, compose into a PHI read that no permission authorizes.

1. A custom role may hold `messages:edit` alone. The carve-out set is three permissions wide — [`auth/permissions.py:178-180`](../messagefoundry/auth/permissions.py):

```python
CUSTOM_ROLE_FORBIDDEN_PERMISSIONS: frozenset[Permission] = frozenset(
    {Permission.USERS_MANAGE, Permission.APPROVALS_APPROVE, Permission.DR_OPERATE}
)
```

and `permissions.py:212` (`forbidden = perms & CUSTOM_ROLE_FORBIDDEN_PERMISSIONS`) is the only capability check `validate_custom_role_permissions` applies, so `{"messages:edit"}` is an accepted role set.

2. The `/ui` editor gates on that permission and nothing else — [`messagefoundry_webconsole/routes/core.py:597-604`](../messagefoundry_webconsole/routes/core.py):

```python
@app.get("/ui/messages/{message_id}/edit", response_class=HTMLResponse)
async def ui_message_edit(
    ...
    identity: Identity = Depends(require_ui_step_up(Permission.MESSAGES_EDIT)),
) -> HTMLResponse:
    detail = await core.get_message(message_id, request, engine=engine, identity=identity)
```

3. The JSON twin's own gate does not fire. `api/app.py:3150` declares `Depends(require_phi_read(Permission.MESSAGES_VIEW_RAW))`, but the console calls the handler as a plain function with `identity=` supplied, so the default is never evaluated. That skip is deliberate and documented at [`api/_ui_seam.py:92`](../messagefoundry/api/_ui_seam.py) — the `/ui` route "re-asserts the equivalent permission via `require_ui*`". Here it re-asserts a *different* one.

4. No per-property backstop catches it. `MessageDetail`'s entry in `PHI_FIELDS` ([`api/field_authz.py:64-68`](../messagefoundry/api/field_authz.py)) lists `summary`/`error`/`metadata` only — `raw` is deliberately left to the route gate ("The raw body stays on this route's view_raw gate"). So `redact_unauthorized` (`field_authz.py:89-95`) returns the body untouched and [`pages/messages.py:440,454`](../messagefoundry_webconsole/pages/messages.py) renders it: `original = detail.raw` → `data_original=original` in the editor textarea.

**Two details beyond the original write-up.** The `POST /ui/messages/{id}/edit-resend` rejection path (`routes/core.py:637-644`) re-calls `core.get_message` and re-renders `pages.message_edit(detail, ...)`, so the **pristine stored** body ships again via `data_original` — the same leak on a second verb. And `require_ui_step_up` builds its base as `require_ui(*permissions, allow_mfa_pending=True)` (`_auth.py:521`) with no `phi=`, so the `_auth.py:260` `allow_phi_read` per-actor throttle never runs here, while the sibling `/ui/messages/{id}`, `/parse-tree` and `/attachments` routes all pass `phi=True` (`routes/core.py:473,483,501`). That second point is **not unique to this route** — `/ui/messages/search`, `/ui/messages/search/layered` and `/ui/uploaded-logs/file/{id}` ride `require_ui_step_up` too — so it may warrant its own item rather than being fixed only here.

**Why:** it is a least-privilege failure, not a privilege boundary an attacker crosses unaided — and the blast radius is narrower than "PHI exposure" sounds:

- **No shipped configuration is affected.** Only `ADMINISTRATOR` and `OPERATOR` grant `messages:edit` (`permissions.py:111,129-152`) and both also grant `messages:view_raw`. Reaching the gap requires an administrator holding `users:manage` to have deliberately minted and assigned a custom role — and that administrator could grant `view_raw` outright anyway, so **no one gains PHI they could not otherwise obtain**. The victim is the *org's stated intent*, not the trust boundary.
- **`/ui` only.** The JSON plane is clean: `GET /messages/{id}` gates on `view_raw`, and `EditResendResult` "Carries ids only, never a body" (`api/models.py:198-209`). An engine run with `serve_ui=False` does not have this route.
- **Every read is audited.** `core.get_message` fires `record_view` + `record_audit("message_view")` (`api/app.py:3162-3163`), so this is a silent *authorization* gap, not a silent *access* gap — an auditor sees it after the fact.
- **What it does cost:** a custom role is exactly the mechanism an org reaches for to build "resubmit-only, must not read" for lower-trust or outsourced staff (and an AD group map delivers it — `auth/service.py:1103-1111` feeds the same `_custom_permissions_for_ids` into `Identity.build`). The role is accepted without warning and silently exceeds its stated scope, which is a HIPAA minimum-necessary problem for the deploying org. `docs/SECURITY.md:213` and `:474-477` already state this honestly in both the catalogue row and the PHI-route list, so the doc is not the defect — the code is.

**Proposed:** pick one of two, not both blindly.

1. *Preferred — enforce the implication at the gate.* Change `routes/core.py:602` (and the `/edit-resend` gate at `:609-620`, which re-renders the same body) to `require_ui_step_up(Permission.MESSAGES_EDIT, Permission.MESSAGES_VIEW_RAW)`. This makes the catalogue's "implies `view_raw`" true by construction, is local, and leaves the permission assignable so a future write-only edit surface stays possible.
2. *Alternative — forbid the combination.* Add `Permission.MESSAGES_EDIT` to `CUSTOM_ROLE_FORBIDDEN_PERMISSIONS`. Blunter: it also blocks legitimate custom roles that pair edit *with* view_raw, and it is an [ADR 0045](adr/0045-custom-rbac-roles.md) D1 amendment (that set is scoped to escalation primitives, which `messages:edit` is not). Prefer 1.

Either way: add `phi=True` equivalence for this route (a `phi` parameter threaded through `require_ui_step_up` into its `require_ui` base at `_auth.py:521`), and add the missing regression test. `packaging/messagefoundry-webconsole/tests/test_webui.py:546-555` only exercises `Role.VIEWER`, which holds *neither* permission — nothing today asserts what an edit-without-view_raw identity gets. The new test must mint a `custom:` role holding `messages:edit` alone and assert 403.

**Fix ordering:** `tests/test_security_doc_drift.py:1167-1196` derives the Operator PHI-capability sentence from the catalogue's PHI column and specifically names `messages:edit` as PHI-marked "and it renders the raw body". Fixing the gate makes `docs/SECURITY.md:213` and `:474-477` false, so the doc edit and the code edit must land in the **same commit** or that guard reds.

**Related:** [`messagefoundry_webconsole/routes/core.py`](../messagefoundry_webconsole/routes/core.py), [`messagefoundry_webconsole/_auth.py`](../messagefoundry_webconsole/_auth.py), [`messagefoundry/auth/permissions.py`](../messagefoundry/auth/permissions.py), [`messagefoundry/api/field_authz.py`](../messagefoundry/api/field_authz.py), [`messagefoundry/api/_ui_seam.py`](../messagefoundry/api/_ui_seam.py), [ADR 0045](adr/0045-custom-rbac-roles.md) (custom roles), [ADR 0090](adr/0090-resend-a-stored-message-to-an-alternate-outbound-connection.md) §9 (edit-and-resubmit), [ADR 0065](adr/0065-mount-the-web-console-in-process.md) (the `/ui` mount that creates the gate-skip seam), `docs/SECURITY.md` (catalogue row + PHI-route list), `packaging/messagefoundry-webconsole/tests/test_webui.py`, `tests/test_security_doc_drift.py`, #153 (shipped edit-and-resubmit — the origin of the unenforced "implying `messages:view_raw`" phrasing; closed, do not amend), #177 (effective-permission inspector — would surface such a role).

**Source:** public-repo disclosure audit, 2026-08-01. Classified close-the-weakness-instead: the doc is honest and stays; the code is what changes.

---

---

## 325. Leak gate's home-path detector is case-blind on Windows paths

> 🔢 **Filed 2026-08-01 — not started.** Value **6/10** · Difficulty **2/10** · _fill-in_. The leak gate's home-path detector matches a literal capital-U `Users`, so `c:\users\<name>\proj` — the same path as `C:\Users\<name>\proj` on a case-insensitive filesystem — passes the required merge check while the canonical form is blocked.

> **Note on the examples below.** Every path here writes the account segment as the placeholder `<name>`, because `_HOME_PATH`'s negative lookahead exempts a segment beginning `<` — a literal account name in this item would trip the very gate it describes. Read `<name>` as "a real login name"; the FIRES/MISSED column describes what happens once one is substituted. This is [#322](BACKLOG.md) in miniature: a placeholder written into tracked prose is itself scanned.

**Cluster:** Security / Supply chain. **Priority:** P2. **Verdict:** build. **Severity:** medium.

**What:** `scripts/security/scan_forbidden.py:99-106` compiles the structural home-path detector with **no flags argument**:

```python
_HOME_PATH = re.compile(
    r"(?:[A-Za-z]:[\\/]Users|/home|/Users)[\\/]"
    ...
```

The drive letter is class-matched (`[A-Za-z]`) but `Users` is a **literal**, so only the canonical casing fires. Measured at HEAD by executing the module's own compiled pattern:

| probe | result |
|---|---|
| `C:\Users\<name>\proj` | **FIRES** |
| `c:\users\<name>\proj` | **MISSED** |
| `c:/users/<name>/proj` | **MISSED** |
| `C:\USERS\<name>\proj` | **MISSED** |

Windows filesystems are case-insensitive, so all four name the **same** directory and disclose the same OS account. The gate blocks one spelling of it and waves through three.

This detector is the odd one out in its own module: `[names]` token patterns default to case-insensitive (`scan_forbidden.py:347`, `flags = 0 if case == "s" else re.I`) and the estate file detectors pass `re.IGNORECASE` explicitly (`:440`). The module also states its own tie-breaking rule at `:336-338` — *"under-detection is the dangerous direction … Fail toward more detection"* — which this line violates.

No test covers it. `tests/test_scan_tokens_source.py:559-583` (`test_absolute_home_path_is_flagged_but_placeholders_are_not`) is the only home-path test, and both its positive fixtures — a `C:\Users\<name>\Code\thing` form and a `/home/<name>/src` form, written there with real-looking account segments — are canonical case. Nothing asserts a casing variant in either direction.

**Why:** `forbidden-content (customer/PHI leak guard)` is a **required merge context** (`.github/required-contexts.txt`), and `.github/workflows/security.yml:449-452` names *"absolute home paths"* among the things it scans the whole tracked tree for. A green run therefore reads to a reviewer as "no internal-environment disclosure present." For the lowercased spelling that reading is unearned. It is a **structural** detector, so it is the control that is supposed to work even in a fork with no token source at all. There is no compensating control: `scan_forbidden.py:10-12` is explicit that gitleaks finds *secrets*, not this class.

**Bounded honestly — this is latent blindness, not a live leak.** Scanning every git-tracked file at HEAD, the current pattern finds **0** home-path hits and the proposed fix also finds **0**: there is no lowercased home path sitting in the tree right now. The disclosure it fails to catch is an **OS account name** — not a credential, not PHI, not customer data. Nobody needs privilege or an exploit to trip it; the failure mode is a developer pasting a stack trace or a shell transcript in non-canonical case and the gate not noticing. The blast radius is one developer login name reaching a public repo, which is exactly what this detector exists for and no more than that.

**Proposed:**

1. Case-fold **only the drive-letter arm**, inline, leaving the POSIX arms alone:

   ```python
   r"(?:(?i:[A-Za-z]:[\\/]users)|/home|/Users)[\\/]"
   ```

2. **Do not reach for whole-pattern `re.IGNORECASE`** — measured, it adds **47 false positives** across the tracked tree, every one of them the web console's `/ui/users/…` REST route (`messagefoundry_webconsole/routes/admin.py:38`, `:91`; `docs/SECURITY.md:575`). That would red the required context on the first run. `/users/` is an extremely common URL path segment; `/Users/` is not. The asymmetry in the current pattern is load-bearing, and the inline form preserves it: measured **0** new false positives.

3. Keep the exemption list (`Public|Default|runner|me|svc|you|…`) **case-sensitive**. Case-folding it would widen the exemptions on POSIX, where an upper-cased and a lower-cased spelling of the same exempt word are genuinely different accounts — and widening an exemption is the under-detection direction. (Note a pre-existing, unchanged over-match: a Windows path whose account segment is a **lower-cased** spelling of one of those exempt words fires today, because the exemption compares case-sensitively and the lower-cased form misses the literal. That is the safe direction; out of scope here.)

4. Add the regression case to `tests/test_scan_tokens_source.py:559`, alongside the existing canonical fixtures — a lowercased and an upper-cased Windows path must both produce a hit, and the POSIX `/users/…` non-match should be asserted deliberately so the next person does not "fix" it into the 47-false-positive form.

5. **Same fix site, sibling defect:** `_WORKTREE_SLUG` at `scripts/security/scan_forbidden.py:92` is case-blind the same way (`[a-z0-9]+`); `claude/Some-Task-a1b2c3` is MISSED. `scripts/worktree/new.ps1:43,86` passes `-Name` through verbatim with no lowercasing, so an upper-cased worktree name is reachable. Narrower than the home-path case (agent-created slugs are lowercase by convention), but it is a two-character edit in the same block — take it in the same change or say why not.

**Related:** `scripts/security/scan_forbidden.py` (`_HOME_PATH` :99-106, `_WORKTREE_SLUG` :92, call site :758-759), `tests/test_scan_tokens_source.py:559-583`, `.github/workflows/security.yml:446-493`, `.github/required-contexts.txt`, `scripts/worktree/new.ps1`. Sibling **#321** — same gate, same "green gate that cannot see the class" root cause, but the **opposite mechanism**: #321 is an incomplete *token source* (data, fixed by the owner updating a private secret) and explicitly scopes itself away from scanner defects at `docs/BACKLOG.md:7356`; this is a *structural detector* defect (code, fixed by a regex edit) that is live even with no token source. Also **#322**, and the anonymizer's structural-detector item from this same audit. Note #321's **Related:** line at `docs/BACKLOG.md:7363` cites `tests/test_scan_forbidden.py` for regression tests, but the home-path test actually lives in `tests/test_scan_tokens_source.py` — worth correcting when someone next touches #321.

**Source:** public-repo disclosure audit, 2026-08-01. Verified open at HEAD (`12efbffc`) by executing the compiled pattern and by diffing the current, proposed and naive-`re.I` variants across every git-tracked file.

---

---

## 326. MFA-at-exposure refusal reads `serve_ui` after it is flipped off

> 🔢 **Filed 2026-08-01 — not started.** Value **6/10** · Difficulty **3/10** · _fill-in_. The ADR 0143 console auto-degrade flips `settings.api.serve_ui` to `False` **in place** before `ui_exposed` is derived from it, so `admin_exposed` is `False` in the recommended loopback-behind-a-declared-proxy topology and the ASVS 6.3.3 single-factor-admin refusal never evaluates — measured: a production PHI instance under `enforce` with `[security].require_mfa = false` starts **rc=0**.

**Cluster:** Security & Compliance. **Priority:** P1. **Verdict:** build. **Severity:** medium.

**What:** the `serve` startup ladder derives its admin-exposure predicate from a field an earlier arm has already mutated. In [`messagefoundry/__main__.py`](../messagefoundry/__main__.py):

```python
console_exposed = (                                             # :1741
    not settings.api.is_loopback
    or settings.api.tls_terminated_upstream
    or bool(settings.api.public_origin)
)
if settings.api.serve_ui and not settings.api.serve_ui_explicit and console_exposed:
    ...
    settings.api.serve_ui = False                               # :1755  (ADR 0143 auto-degrade)

ui_exposed = settings.api.serve_ui and (                        # :1834  reads the flipped field
    not settings.api.is_loopback or settings.api.tls_terminated_upstream
)
admin_exposed = not settings.api.is_loopback or ui_exposed      # :1879
```

`serve_ui` defaults to `True` and `serve_ui_explicit` to `False` (`messagefoundry/config/settings.py:674`, `:680`), so on a **loopback bind behind a declared terminator** — the topology the gate's own comment at `:1874-1878` names as the one it exists to cover, *"the runbook's RECOMMENDED topology (loopback bind BEHIND a declared proxy, `ui_exposed`)"* — an operator who never touches `serve_web_console` gets `serve_ui=False` at `:1755`, `ui_exposed=False` at `:1834`, and `admin_exposed=False` at `:1879`. The MFA refusal at `:1888` and the #189 dual-control warning at `:1936` are both gated on that flag and never evaluate.

Measured 2026-08-01 against HEAD (`prod`, PHI, `enforcement=enforce`, loopback bind, `[api].tls_terminated_upstream` + `trusted_proxies`, `[security].require_mfa = false`, retention/alerts pre-satisfied):

| arm | `serve_web_console` | result |
|---|---|---|
| A | explicit `true` | **rc=2** — `error: browser console exposed through a declared reverse proxy … require_mfa off; refusing to start` |
| B | default, `web_console_public_address` set | MFA refusal **absent**; rc=2 only from the unrelated ASVS 12.1.1 TLS-floor probe (`:1978-2009`) |
| C | default, no `web_console_public_address` | **rc=0 — starts.** MFA refusal absent, #189 approvals warning absent |

Arm C is the load-bearing one: the TLS-floor probe is itself gated on `settings.api.public_origin` (`:1982`), and once the console degrades nothing requires that key (the `:1779` refusal only applies while `serve_ui` is on), so a JSON-only proxied deployment skips it. In that same rc=0 run the ADR 0152 arm printed `warning: EXPOSED PHI instance ('prod') …` — because it computes the predicate this gate wants, `instance_exposed = not settings.api.is_loopback or settings.api.tls_terminated_upstream` (`:2223`). The engine calls one instance *exposed* for ASVS 11.7.1 and *not exposed* for ASVS 6.3.3 in a single boot.

Test coverage never caught it because the only test of this arm, `tests/test_cli.py:1230-1252` `test_serve_ui_declared_proxy_requires_mfa_on_prod_phi`, sets `security.serve_web_console = true` **explicitly** — the one input that keeps the refusal reachable. [ADR 0143](adr/0143-web-console-on-by-default-disableable-with-loopback-secure-context-browser-hardening.md) does not mention `require_mfa`, `admin_exposed`, or single-factor admin anywhere, so the interaction was introduced rather than adjudicated.

**Why:** ASVS 6.3.3's admin-MFA backstop is inert in the deployment shape the project recommends, and the operator gets no signal — arm C starts clean with the Administrator role single-factor over a network-facing proxy. **Bounded, and the bound matters.** `require_mfa` still **defaults on** (`settings.py:1696`), so this is only reachable after an operator has *explicitly* written `require_mfa = false`; `security_loosenings()` names that opt-out on every boot (`settings.py:4044-4050`, seen in the arm-C log) and `GET /security/posture` reports it. **The blast radius is NOT** a default deployment, **NOT** an off-loopback bind (`admin_exposed` is `True` from the `not is_loopback` arm regardless of `serve_ui` — arm A's non-loopback sibling is pinned at `tests/test_cli.py:768`), **NOT** an authentication bypass, and **NOT** a way in for an unauthenticated attacker: it removes a *refusal to start*, not a credential check. What is lost is the hard stop that was supposed to make the explicit opt-out impossible to combine with exposure — i.e. exactly the case ADR 0140 built `allow_single_factor_admin_when_exposed` to force an operator to acknowledge. The same flag also silences the #189 dual-control warning (`:1936`) in the same topology, so a second control degrades with it. Finally, the docs at `docs/CONFIGURATION.md:1437` and `docs/REMOTE-CONSOLE.md:182` currently have to carry a *"the gate will not catch you"* caveat; closing the defect is what lets that prose go.

**Proposed:** stop deriving admin exposure from a mutated presentation flag.

1. Key `:1879` on a `serve_ui`-independent predicate. The house-consistent one **already exists in this file**: reuse/hoist `instance_exposed` from `:2223` (`not settings.api.is_loopback or settings.api.tls_terminated_upstream`), which is precisely the intent stated at `:1874-1878`. Keying on `console_exposed` (`:1741`) also works but is **wider** — its `bool(public_origin)` branch would turn the undeclared-proxy heuristic, today a warning at `:1811`, into a hard refusal. Pick the narrow predicate unless the owner wants that widening.
2. Fix `exposure_desc` at `:1881-1886`: its else-branch hardcodes *"browser console exposed through a declared reverse proxy (`[api].serve_ui` + `tls_terminated_upstream`)"*, which becomes false as soon as the gate fires without a served console. Same for the `:1937-1942` twin.
3. Owner fork to settle before building — this makes a currently-starting configuration **refuse on upgrade**, against the repo's own rule at `docs/CONFIGURATION.md:1439` (*"a new refusal fires only on a new opt-in"*). The rule is weaker here than in its ADR 0152 precedent: the affected population is only deployments that explicitly disabled MFA, and the remedy is one line they already know (`require_mfa = true`, or the existing audited `allow_single_factor_admin_when_exposed = true`). Refuse-on-upgrade is defensible; warn-first-then-refuse is the conservative alternative.
4. Tests: add the arm-C case (declared proxy, console left at default, no `public_origin`) to `tests/test_cli.py` beside `test_serve_ui_declared_proxy_requires_mfa_on_prod_phi`, plus a `serve_web_console = false` variant — an operator who *explicitly disables* the console is in the same exposure posture and must also be caught.
5. Docs to update once it lands: strike the blind-spot sentences at `docs/CONFIGURATION.md:1437` and `docs/REMOTE-CONSOLE.md:182`, and re-state the two `admin_exposed` decision-table rows at `docs/SECURITY.md:1083-1084`.

**Related:** [`messagefoundry/__main__.py`](../messagefoundry/__main__.py) `:1741`/`:1755`/`:1834`/`:1879`/`:1936`/`:2223`, [`messagefoundry/config/settings.py`](../messagefoundry/config/settings.py) `:674`/`:680`/`:1696`/`:4044`, [ADR 0143](adr/0143-web-console-on-by-default-disableable-with-loopback-secure-context-browser-hardening.md) (introduced the in-place flip; silent on this gate), [ADR 0140](adr/0140-two-acknowledged-production-phi-no-loosen-carve-outs-single-factor-admin-at-exposure-keyless-phi-in-production.md) (the refusal + its acknowledged escape), [ADR 0068](adr/0068-browser-webauthn-passkeys-offloopback.md) §8 (the exposure ladder), [ADR 0152](adr/0152-in-use-data-protection-for-phi-platform-memory-encryption-attestation-asvs-11-7-1.md) (source of the correct predicate at `:2223`), `tests/test_cli.py:1230-1252`, `tests/test_checks_gate_parity.py:185-194` (its MFA row uses a non-loopback bind, so it is unaffected), `docs/SECURITY-LOOSENING.md` §`allow_single_factor_admin_when_exposed`, #187 (the `require_mfa` default), #189 (the dual-control arm that shares the flag).

**Source:** public-repo disclosure audit, 2026-08-01 — classified close-the-weakness-instead: the disclosure at `docs/CONFIGURATION.md:1437` / `docs/REMOTE-CONSOLE.md:182` is honest and stays until the defect is fixed.

---

---

## 327. No test asserts the private-path `.gitignore` block still ignores anything

> 🔢 **Filed 2026-08-01 — not started.** Value **6/10** · Difficulty **2/10** · _fill-in_. Six `.gitignore` rules are the sole control keeping maintainer-internal security docs out of a public commit since the publish deny-list was retired, and no test, hook or workflow asserts they still match.

**Cluster:** Security / Publishing boundary. **Priority:** P2. **Verdict:** build. **Severity:** medium.

**What:** `.gitignore:128` opens the block that replaced the retired publish deny-list, and states its own stakes at `.gitignore:131-132`:

```
# repo, a gitignore rule is now the ONLY thing keeping them out of a commit -- and the cutover runbook
# runs `git add -A`. Same failure shape as the leak-scanner token file, different files.
```

The rules are `/.claude/`, `/TRANSCRIPTS.md`, `/docs/security/`, `/docs/reviews/`, `/docs/marketing/` (`.gitignore:142-146`) and `/docs/CI-TOPOLOGY.md` (`.gitignore:160` — a **sixth** rule in the same block, in the same posture). All six match at HEAD and no tracked file sits under any of them, both confirmed directly:

```
git check-ignore -v docs/security/x.md   # -> .gitignore:144:/docs/security/  docs/security/x.md
git ls-files -- .claude docs/security docs/reviews docs/marketing TRANSCRIPTS.md docs/CI-TOPOLOGY.md
# -> (empty)
```

Nothing asserts either half stays true. A repo-wide search for `check-ignore` matches exactly two files: the untracked `.claude/settings.local.json`, and `scripts/dev/setup-leak-gate.ps1:58` — which checks **one** path (`scripts/security/scan-tokens.local.txt`), and only when an operator runs that setup script by hand. `scripts/security/scan_forbidden.py` enumerates tracked files (`_git_tracked()`, `scan_forbidden.py:679-683`) but every check downstream is content-based — tokens, IPs, home paths — so it has no opinion about a path. None of `.pre-commit-config.yaml`'s hooks (ledger-gate, ruff, forbidden-content, gitleaks, actionlint, bandit) is path-prefix based, and `ci.yml` / `security.yml` contain no reference to `docs/security`, `publish-denylist`, `private-path` or `check-ignore`.

The two nearest-looking guards are neither: `tests/test_scaffold.py:51-52` asserts a gitignore substring for the **scaffolded config repo** `messagefoundry init` writes, not for this repo; `tests/test_release_pipeline.py:38`'s `PRIVATE_CANARY = "docs/security/THREAT-MODEL.md"` guards the **sdist/PyPI** channel (the hatchling `only-include` vs `release.yml` leak-gate cross-check), which is a different publication path from `git commit`.

**Why:** this is the project's own evergreen lesson pointed at the highest-consequence boundary it has — the one deciding whether maintainer-internal security material (threat model, ASVS assessments, point-in-time review findings, per `docs/SECURITY-DOCS-POLICY.md`) is public. It is defended today by a text file nobody checks and by review attention.

**Bounded honestly — the blast radius is what it is and no more:**

- **Nothing is exposed right now.** All six rules match and zero files are tracked under them. This is a preventive gap, not a live leak.
- **It is not an attacker-exploitable defect.** Reaching it needs push access to this repo — reordering a rule, adding an un-ignore above one, resolving a merge conflict in the block, or `git add -f`. Anyone with that access could publish those documents deliberately in one commit. The guard defends against **accident and drift**, not against a hostile committer, and should be valued that way.
- **No PHI, no credentials.** The private set is prose about the system's posture. Real secrets are covered separately (`.env`, `*.key`, `*.pem` at `.gitignore` lines above, plus gitleaks in `.pre-commit-config.yaml`).
- **The obvious compensating control does not actually travel.** `scripts/hooks/block-blanket-git-stage.ps1` denies `git add -A` — the exact command `.gitignore:132` warns about — but it is wired through `.claude/settings.json`, which is itself inside the now-gitignored `/.claude/` tree and **untracked** (`git ls-files .claude/settings.json` is empty while the file exists on disk). It is a local Claude Code session control, fail-open by design, absent from a fresh clone or a new `git worktree add`. Do not count it as coverage.

**Proposed:**

1. Add `tests/test_private_paths_stay_ignored.py` with a **pinned literal list** of the six rules and two assertions per entry: (a) `git check-ignore -q` exits 0 for a synthetic probe child (`docs/security/__probe__.md`) — probing a synthetic path, not a real private file, so the test is valid in a public checkout where the private tree is absent by definition (the groundedness problem `tests/test_release_pipeline.py:117-127` already worked through); (b) `git ls-files` returns nothing under the prefix, since a gitignore rule never un-tracks a file that got added first.
2. **Pin the list in the test; do not parse it out of `.gitignore`.** Guarding a file by parsing that same file is how this repo already burned itself once — `tests/test_feature_map_claims.py:52-55` records a `.gitignore` marker-block parser whose marker existed only inside the test, exercised against a `tmp_path` fixture: *"It was a check that could not fail."*
3. **Wire it where it will fire on the PR that breaks it.** `ci.yml:472` puts `^\.gitignore$` in the docs-only `noncode` allowlist, so a `.gitignore`-only PR sets `code=false` and the `Tests (pytest)` step (`ci.yml:226-227`) is skipped — a pytest-only guard would go green on exactly the change it exists to catch, and would only fire on the post-merge push to `main`. Fix by dropping `^\.gitignore$` from that regex (a `.gitignore` edit is not a docs edit; it is the publishing boundary), and/or adding a `local` pre-commit hook alongside `ledger-gate` with `always_run: true` / `pass_filenames: false`. The CI arm is the load-bearing one — `.pre-commit-config.yaml`'s own header shows the hooks need a per-clone `pre-commit install`.
4. Consider promoting the resulting context per `.github/required-contexts.txt` rather than adding a paths-filtered workflow — a paths-filtered required check is the required-but-absent trap `manifest-lint.yml` documents.

**Also (small, same block):** `docs/SESSION-DRIFT-CONTROLS.md:69-71` links to `[.claude/settings.json](../.claude/settings.json)`, which `/.claude/` now ignores and which is untracked — the link cannot resolve in the public repo, and the paragraph presents the blanket-`git add -A` guard as an active control while pointing at a file no public reader has. Fix in the same commit. The stale comment above the `.claude/settings.local.json` rule ("settings.json is shared/tracked") is contradicted by the later `/.claude/` rule at `:142` and should go with it.

**Related:** `.gitignore` (lines 128-146, 160), `scripts/security/scan_forbidden.py`, `scripts/dev/setup-leak-gate.ps1`, `.pre-commit-config.yaml`, `.github/workflows/ci.yml` (`noncode` at :472, pytest gate at :226), `tests/test_release_pipeline.py`, `tests/test_feature_map_claims.py`, `tests/test_scaffold.py`, `scripts/hooks/block-blanket-git-stage.ps1`, [`docs/SECURITY-DOCS-POLICY.md`](SECURITY-DOCS-POLICY.md), [`docs/SESSION-DRIFT-CONTROLS.md`](SESSION-DRIFT-CONTROLS.md), #321, #322.

**Source:** public-repo disclosure audit, 2026-08-01. Verified against HEAD `12efbffc`; the audit flagged the finding as unconfirmed, and the absence of any such test/hook/gate is confirmed here.

---

---

## 328. `audit-verify` cannot detect a truncated audit tail

> 🔢 **Filed 2026-08-01 — not started.** Value **5/10** · Difficulty **3/10** · _fill-in_. The tail-truncation detector exists and is correct on all three store backends, but no CLI flag, config key, or API route can supply it an anchor — so `audit-verify` **and** the startup auto-verify both report a truncated audit log as CLEAN.

**Cluster:** Security / Audit integrity. **Priority:** P2. **Verdict:** build. **Severity:** medium.

**What:** the audit hash chain links each row to its predecessor, so deleting the **newest** rows leaves a shorter prefix that still verifies. The store layer already solves this. `verify_audit_chain` takes an optional out-of-band anchor and compares it in constant time ([`store/store.py:7475-7486`](../messagefoundry/store/store.py)), returning `"audit log diverges from recorded anchor … — truncated or rewritten"`; the producing side, `audit_anchor() -> tuple[int, str]`, is implemented on **all three** backends ([`store/store.py:7387`](../messagefoundry/store/store.py), [`store/sqlserver.py:8591`](../messagefoundry/store/sqlserver.py), [`store/postgres.py:5676`](../messagefoundry/store/postgres.py)). Its docstring states the contract plainly:

> "Recording this anchor out-of-band … and passing it back to :meth:`verify_audit_chain` is what makes truncation/rewrite detectable" — `store/store.py:7390-7393`

Nothing an operator can run does that. **Both** shipped verification surfaces call the method bare:

```python
messagefoundry/__main__.py:3451      return await store.verify_audit_chain()
messagefoundry/pipeline/engine.py:834    ok, msg = await self.store.verify_audit_chain()
```

and the `audit-verify` subparser declares exactly two arguments, neither of them an anchor ([`__main__.py:570-578`](../messagefoundry/__main__.py): `--service-config`, `--db`). `audit_anchor()`'s only callers in the tree are the DR cold-seed marker ([`pipeline/dr.py:569`](../messagefoundry/pipeline/dr.py), `:585`), which reads it to fingerprint a restored chain and never persists it as a verifiable anchor. There is no API route either — `audit_anchor`/`expected_anchor` appear nowhere under `messagefoundry/api/`. The capability is built, tested at the store boundary, and unreachable.

This is **wider than the disclosure describes.** [`CONFIGURATION.md:718`](CONFIGURATION.md) and [`:1363-1368`](CONFIGURATION.md) name only the CLI; the `[integrity].audit_verify_on_start` check at `engine.py:834` is equally truncation-blind, so enabling it does not close the gap.

**Why:** the sharp case is the **keyed** chain, which is the normal PHI posture — a PHI instance cannot start keyless without a deliberate acknowledgment ([`CONFIGURATION.md:1357-1361`](CONFIGURATION.md)). There, an attacker with DB write **cannot forge** rows (the MAC is HKDF-derived from the DEK) but **can still delete** the tail, and truncation is precisely the residue the anchor was built to catch. So the missing plumbing removes the one local defense that a keyed chain actually depends on. On a *keyless* chain the anchor buys much less: that attacker can recompute the whole chain end-to-end anyway.

**Bounding it honestly — what this is NOT.** It is not an access path. It presupposes DB-level write access or filesystem access to the store file, i.e. the attacker is already inside; this is post-compromise **anti-forensics**, not a way in. There is no unauthenticated reach, no PHI disclosure, no authz bypass, and no remote trigger. The documented compensating control is real — every committed audit row is teed off-box PHI-redacted ([`store/audit_tee.py:3-9`](../messagefoundry/store/audit_tee.py)) — but it is **opt-in and off by default** (`forward_host: str | None = None`, [`config/settings.py:1347`](../messagefoundry/config/settings.py)), so on a default install there is no truncation detection at all, local or remote.

**Proposed:**
1. Add `messagefoundry audit-anchor` (`--service-config` / `--db` / `--json`, mirroring `audit-verify`) printing the `(count, head_hash)` pair. It is PHI-free by construction — a row count and a digest — so it is safe for a compliance job to snapshot off-box.
2. Add `--expected-anchor COUNT:HEAD` (or `--expected-anchor-file`) to `audit-verify` and plumb it into the existing `expected_anchor=` keyword at [`__main__.py:3451`](../messagefoundry/__main__.py). The comparison logic needs no change.
3. Consider an `[integrity]` key pointing at a stored anchor file so the startup auto-verify at [`engine.py:834`](../messagefoundry/pipeline/engine.py) can use it too — alert-only, matching that path's existing never-crash-startup contract (`engine.py:827-834`). Without this, item 2 leaves the automatic check still blind.
4. Only **after** 1–3 ship, update [`CONFIGURATION.md:718`](CONFIGURATION.md) and [`:1363-1368`](CONFIGURATION.md). That row is the source of record and explicitly forbids the edit until then: *"do not upgrade this to 'the anchor detects it' without also shipping a way to pass one."* While there, refresh its two stale citations — it cites `__main__.py:3418` for a call now at `:3451` and `store/store.py:7385` for a docstring now at `:7390-7393`.

**Related:** [`messagefoundry/__main__.py`](../messagefoundry/__main__.py) (`_audit_verify`, subparser), [`messagefoundry/store/store.py`](../messagefoundry/store/store.py) / [`sqlserver.py`](../messagefoundry/store/sqlserver.py) / [`postgres.py`](../messagefoundry/store/postgres.py) (`audit_anchor`, `verify_audit_chain`), [`messagefoundry/store/base.py:1398-1405`](../messagefoundry/store/base.py) (the protocol), [`messagefoundry/pipeline/engine.py`](../messagefoundry/pipeline/engine.py) (`_verify_audit_chain_on_start`), [`messagefoundry/pipeline/dr.py`](../messagefoundry/pipeline/dr.py) (today's only anchor consumer), [`messagefoundry/store/audit_tee.py`](../messagefoundry/store/audit_tee.py), [`docs/CONFIGURATION.md`](CONFIGURATION.md) `[retention].audit_days` + `[integrity]`, #190 (shipped 2026-07-11 — keyed the chain and added the startup auto-verify; the anchor surfacing was never in its built scope, and it is closed, so this is a new item rather than an amendment).

**Source:** public-repo disclosure audit, 2026-08-01. Classified close-the-weakness-instead: the two `CONFIGURATION.md` passages are accurate and stay.

---

---

## 329. Five `MEFOR_ALLOW_INSECURE_TLS` cells bypass the ADR 0092 clamp

> 🔢 **Filed 2026-08-01 — not started.** Value **6/10** · Difficulty **4/10** · _fill-in_. Five weakening cells still call the raw `insecure_tls_allowed()` instead of the ADR 0092 clamp, so one process-wide env var crosses an enforcing production-PHI posture — including LDAPS certificate verification and an unknown SSH host key — while their in-file siblings are clamped.

**Cluster:** Security / TLS posture. **Priority:** P2. **Verdict:** build. **Severity:** medium.

**What:** ADR 0092 decision 2 introduced `weakened_tls_escape_permitted(posture)` so the blunt global `MEFOR_ALLOW_INSECURE_TLS` can never relax a hop on an enforcing PHI instance (`config/settings.py:226-230` — *"if not insecure_tls_allowed(): return False … return not (posture.enforcing and posture.is_phi)"*). Five cells never adopted it and still call the raw predicate. Confirmed at HEAD:

| Cell | Site | What the env var buys |
| --- | --- | --- |
| SFTP host key | `transports/remotefile.py:375` | `self._accept_unknown = insecure_tls_allowed()` → paramiko `AutoAddPolicy` instead of `RejectPolicy` (`:392-394`) |
| Direct (S/MIME) SMTP | `transports/direct.py:170` | `if not insecure_tls_allowed():` → cleartext SMTP submission |
| LDAPS | `auth/ldap.py:113` | `if not insecure_tls_allowed():` → `ad_tls_verify=false`, i.e. `ssl.CERT_NONE` on the bind (`:131`) |
| Webhook alert sink | `pipeline/alert_sinks.py:290` | `if scheme == "http" and not insecure_tls_allowed():` → cleartext alert POST |
| AI broker | `transports/ai_broker.py:140` | `if scheme == "http" and not insecure_tls_allowed():` → the `[ai].api_key` credential on cleartext http |

The inconsistency is sharpest *within a single file*. `transports/remotefile.py` decides three escape questions: FTPS `tls_verify=false` at `:176` and credentialed plain-ftp at `:577` both go through `weakened_tls_escape_permitted_here()`; the unknown-host-key question three hundred lines away does not. Likewise `transports/email.py:134` gates cleartext SMTP on `weakened_tls_escape_permitted_here() or config.tls_hop_attested or config.cleartext_accepted`, while its near-identical Direct sibling at `direct.py:170` consults nothing but the env var.

This is an omission, not a recorded decision. [ADR 0092](adr/0092-posture-keyed-transport-hop-refusal-refuse-the-insecure-phi-hop.md):14-19 lists six non-connection cells the escape "survives for" — engine→store TLS, LDAPS, the webhook alert sink, the AI broker, the `[logging]` forwarder, the API PHI-read serve hop — but *survives* is a statement about the variable, not about the clamp: three of those six are clamped in code (store via `store/sqlserver.py:1498`, the forwarder and the PHI-read hop via `hop_insecure_escape_downgrades`) and three are not. And `config/settings.py:203-207`, which enumerates the surviving clamped cells, names only the forwarder and the PHI-read hop — LDAPS, the webhook sink and the AI broker appear in no list at all.

**Not** part of this: `transports/database.py:110-113` reads `insecure_tls_allowed()` only on the `posture is None` arm and `hop_insecure_escape_downgrades(...)` otherwise. That is the documented unstamped fallback (`config/settings.py:228-229`), same as the store's, and was examined and excluded.

**Why:** the clamp exists to contain an *operator mistake*, and that is the whole of the blast radius here. `MEFOR_ALLOW_INSECURE_TLS` is not attacker-influenceable — setting it on a Windows service means editing the NSSM service definition or machine environment, which needs Administrator, and an Administrator can already do strictly worse (the config dir is executed as the service account; `config/settings.py:247-256`). Nobody reaches these cells over the network. So this is **not** a remotely exploitable vulnerability and should not be described as one.

What it *is*: the realistic failure is a dev/CI environment variable riding into a production service definition — the exact scenario ADR 0092 decision 2 was written for, and the reason the store, MLLP, FTPS and plain-ftp cells were converted. With it set, an enforcing production-PHI instance silently accepts an unknown SSH host key (trust-on-first-use against a MITM on a PHI file feed), disables LDAPS certificate validation on the service-account and user binds, and puts the `[ai].api_key` on the wire. The LDAPS case is the one worth ranking first: it is instance-wide rather than per-connection, it is the authentication substrate for every AD identity, and `auth/ldap.py`'s own comment claims the refusal means it "can no longer be silently turned on in production" — which is true of the refusal but not of the clamp.

The AI-broker cell has an additional argument: `transports/smart.py:126-149` moved the *same* question — a credential on a cleartext token endpoint — off the raw escape and onto `refuse_cleartext_credential_hop` in commit `a3015196`, with a comment describing exactly this defect (*"It used to read the raw, UNCLAMPED `MEFOR_ALLOW_INSECURE_TLS`"*). `ai_broker.py:140` is the un-migrated twin of a cell fixed days ago.

**Additionally — converting all five is what makes the property *checkable*, not just true.** While these five remain, "no unclamped escape survives on an enforcing PHI posture" is five separate per-site facts, each verifiable only by opening the site and reading it, and each silently falsified by a sixth cell added later. Convert them all and it collapses into **one repo-wide invariant**: the raw `insecure_tls_allowed()` becomes unreachable outside `config/settings.py`'s own clamp, so the absence of the raw predicate is checkable everywhere at once, with `weakened_tls_escape_permitted_here` as the thing that must still be present. Today the property is a convention enforced by review; afterwards it is an invariant enforced by a grep — and a *new* unclamped cell fails immediately instead of waiting for the next audit to enumerate it.

That distinction matters concretely for the ASVS record. The scorecard's absence-claim mechanism runs regexes over the whole `*.py` corpus and **cannot scope a grep to one file**, so a per-connector claim ("`direct.py`'s escape is clamped") is not expressible and has to be carried as stated-but-unchecked prose. A repo-wide claim is expressible and machine-verified on every commit. So this item is not only five leaks to plug: it is the difference between a security property that must be re-audited by hand and one that a gate can hold. *(Framing contributed by the ADR 0156 ASVS-sweep session, 2026-08-02.)*

**Scope note, because the count is moving and two censuses will disagree.** #323 routes `transports/direct.py` and `transports/email.py` through the clamp, taking the remaining set to four once it lands — so a census taken on that branch disagrees with one taken on `main`, and neither is wrong. Measured at `main` by counting **`ast.Call` nodes**, not matching lines: six real call sites outside `config/settings.py` — `auth/ldap.py`, `pipeline/alert_sinks.py`, `transports/ai_broker.py`, `transports/database.py`, `transports/direct.py`, `transports/remotefile.py`. `transports/database.py` is the documented unstamped fallback, excluded above; `transports/mllp.py` matches a naive grep for the raw name but its occurrence is **prose inside a docstring, not a call at all**. A line-based census reports it as a further site; an AST-based one does not — which is the instrument distinction, not a detail about this item.

**Proposed:** convert all five, but note that a blanket swap to `weakened_tls_escape_permitted_here()` would silently fix only two of them.

1. **In-gate cells — a one-line swap each.** `remotefile.py:375` and `direct.py:170` are built inside `build_check_registry`/`wiring_runner`'s `active_hop_posture` scope (`config/tls_policy.py:587-603`; the stamping sites are all in `pipeline/wiring_runner.py`), so `weakened_tls_escape_permitted_here()` reads a real posture there — byte-identical to how `remotefile.py:176`/`:577` and `email.py:134` already behave.
2. **Out-of-gate cells — thread an explicit posture.** `auth/ldap.py`, `pipeline/alert_sinks.py` and `transports/ai_broker.py` are constructed from `create_app`/`AuthService` (`auth/service.py:275`, `api/app.py:5335`), which never stamp the contextvar; `current_hop_posture()` returns `None` there and `weakened_tls_escape_permitted(None)` returns `True` (`config/settings.py:228-229`), so `_here()` would be **inert** — the fix would ship green and change nothing for LDAPS, the highest-value cell. Pass a posture explicitly, as the store does at `store/sqlserver.py:1498`. `create_app` already derives one at `api/app.py:1174-1179` (`_phi_read_posture = hop_posture_from_ai(ai_settings, enforcement=…)`) — thread that into the three constructors rather than deriving a fourth.
3. **Prefer the credential authority for `ai_broker.py:140`** — `refuse_cleartext_credential_hop` (`transports/rest.py:478-515`), matching the SMART fix, since it fail-closes on an unstamped posture (`rest.py:292-300`) and gives the same error contract.
4. **Consider whether the SFTP host-key cell belongs on this env var at all.** It is an SSH TOFU decision, not TLS; a dedicated per-connection `known_hosts` requirement (or a `host_key_accepted` declaration in the ADR 0153 idiom) would express it better than a global TLS switch. Filing the swap does not settle that; call it out in the fix PR.
5. Update the `docs/DEPLOYMENT.md`:408-418 bullet list (three *(Not clamped)* / *(raw escape)* annotations become *(Clamped)*) and the `config/settings.py:200-208` surviving-cells docstring in the same commit, and add regression tests asserting each cell refuses under `enforcement=enforce` + PHI **with the escape set** — the assertion that does not exist today for any of the five.

**Related:** [ADR 0092](adr/0092-posture-keyed-transport-hop-refusal-refuse-the-insecure-phi-hop.md) decision 2 (+ its ADR 0153 amendment banner), [ADR 0153](adr/0153-collapse-the-posture-gradient-no-data-label-may-allow-a-cleartext-hop.md) decision 5, [ADR 0148](adr/0148-phi-default-posture-and-an-explicit-security-enforcement-level.md); `messagefoundry/config/settings.py` (`insecure_tls_allowed` / `weakened_tls_escape_permitted` / `_here`), `messagefoundry/config/tls_policy.py`, `messagefoundry/transports/remotefile.py`, `messagefoundry/transports/direct.py`, `messagefoundry/transports/email.py`, `messagefoundry/auth/ldap.py`, `messagefoundry/pipeline/alert_sinks.py`, `messagefoundry/transports/ai_broker.py`, `messagefoundry/transports/smart.py` (the shipped precedent, `a3015196`); [`docs/DEPLOYMENT.md`](DEPLOYMENT.md) §*The `MEFOR_ALLOW_INSECURE_TLS` escape hatch*, [`docs/SECURITY-LOOSENING.md`](SECURITY-LOOSENING.md); tests `tests/test_asvs_phase0.py`, `tests/test_remotefile_transport.py`, `tests/test_direct_transport.py`, `tests/test_email_destination.py`, `tests/test_hop_refusal_residuals.py`; #200 (closed — it built the clamp for the store/MLLP/FTPS/plain-ftp cells but never enumerated these five); the SMTP-unverified-TLS item from this same audit (`transports/direct.py` appears in both, at different lines and with a different fix).

**Source:** public-repo disclosure audit, 2026-08-01. The audit classified the `docs/DEPLOYMENT.md` disclosure as honest and keep-as-is — the doc correctly names all five as unclamped; this item is the weakness the doc describes.

---

---

## 330. The IDE's `ai:assist` gate can never fire

> 🔢 **Filed 2026-08-01 — not started.** Value **5/10** · Difficulty **3/10** · _fill-in_. The IDE fetches `GET /ai/policy` with no bearer, so the engine can only ever answer `assist_permitted: null` and the `ai:assist` deny branch is unreachable — the documented control is inert whether or not the operator signs in.

**Cluster:** Security & Compliance / IDE & Authoring. **Priority:** P2. **Verdict:** build. **Severity:** medium.

**What:** `resolveAiPolicy` reads the authoritative policy **without attaching the session bearer** it already holds:

```ts
// ide/src/aiPolicy.ts:78
const policy = fromWire(await getJson<AiPolicyWire>(engineUrl(), "/ai/policy"));
```

`getJson`'s third parameter is the token (`ide/src/engineClient.ts:128`), and the header is attached only when it is present — `const headers: Record<string, string> = token ? { Authorization: \`Bearer ${token}\` } : {};` (`engineClient.ts:141`). With no bearer, `optional_identity` returns `None` under enabled auth (`messagefoundry/api/security.py:708`), so the endpoint computes `permitted = None if identity is None else identity.has(Permission.AI_ASSIST)` (`messagefoundry/api/app.py:1372`) and answers `assist_permitted: null` **on every IDE read**.

The consequence is that `assistantState`'s deny branches take an input the engine path can never produce:

```ts
// ide/src/aiPolicy.ts:128-131
if (p.mode === "byo" && p.assistPermitted === false) {
  return { enabled: false, message: "Your role does not include the ai:assist permission." };
}
// BYO with assistPermitted true OR null (RBAC not evaluable offline) — allowed.
```

The same holds for the `managed_endpoint` arm at `aiPolicy.ts:116`. **This is wider than the originating audit described.** The audit framed it as an operator defeating org intent *by never signing in*; in fact signing in changes nothing, because the token is never sent on this route. The two remaining sources of a policy are also incapable of returning `false`: `allow_no_auth` yields `_SYSTEM_IDENTITY` holding every role (`security.py:56-58`, `:707`) → `true`, and the CLI fallback hard-codes `"assist_permitted": None` (`messagefoundry/__main__.py:3771`). So no code path in the shipped extension can produce the `false` the gate tests for.

**A second, latent defect in the same function.** The cache write at `aiPolicy.ts:79` is unconditional:

```ts
await ctx.globalState.update(LAST_POLICY_KEY, policy); // remember the authoritative answer
```

This does **not** currently clobber anything: line 79 is the sole writer of `LAST_POLICY_KEY` (`aiPolicy.ts:29`/`:79`/`:84` are its only occurrences in `ide/`), and its input is always the same tokenless read — so a cached `false` can never exist to be overwritten. The missing guard is real and must be fixed, but it is **latent**: it becomes live the moment the bearer is attached, not before. SEC-022's primary purpose is also intact — `mode` is identity-independent, so a central `mode:"off"` still caches and still survives going offline exactly as `docs/adr/0035-ide-extension-workspace-trust-and-scope.md:49-51` intends.

**Why:** ADR 0035's SEC-022 entry names the control this breaks — the cache exists so that *"a central `mode='off'` (or `ai:assist` deny)"* cannot be re-enabled by stopping the engine (`0035-…:28-32`). The `mode` half works; the `ai:assist` half was never wired, so an org that assigns a role without `ai:assist` gets no enforcement at the IDE at all. `docs/AI.md:188` publishes the deny row as live behavior, which makes the gap a documentation-vs-code divergence as well as a control gap.

Honestly bounded — this is a **governance-enforcement** defect, not a data or privilege defect:

- **No PHI is at risk, by construction.** BYO attaches `code_only` context only, capped unconditionally in `chat.ts:122-130`; ADR 0035 makes the same concession about the original SEC-022 (*"No PHI was ever at risk … but it defeats a governance control"*).
- **The brokered path is correctly gated server-side.** `POST /ai/chat` carries `Depends(require(Permission.AI_ASSIST))` (`app.py:1388`), so `managed_endpoint` egress is enforced at the engine regardless of the IDE. The inert client-side branch there costs a clean local message, not authorization — the user gets a 403 instead.
- **Nothing on the engine becomes reachable, and no credential is exposed.** The whole payoff is "use the BYO assistant your org told you not to, against your own model provider, with your own source code."
- **No privilege is needed to hit it** — it is the default state under the default fail-closed posture (`security.py:153-155`), not an attack.

Nothing caught it because `ide/src/test/suite/ai-policy.test.ts:31-40` tests the **pure predicate** (`assistantState({assistPermitted:false}) → disabled`) with a hand-built object. The predicate is correct; it is the input that never arrives. `resolveAiPolicy`'s fetch-and-cache is untested, which is exactly where both defects live.

**Proposed:**
1. Guard the cache write at `:79` **first**, so a null can never downgrade a known-negative once step 2 lands: preserve a cached `assistPermitted === false` when the fresh answer is `null`, or skip the write entirely when the fetch carried no bearer.
2. Attach the cached bearer in `resolveAiPolicy` — `peekToken` (`ide/src/auth.ts:93`), never `ensureToken`, so a chat turn cannot pop a sign-in modal. Gate it on `assertTargetAllowed(url).ok` first, following the SEC-005 precedent at `ide/src/liveStatus.ts:79-81`, so a bearer never goes in clear to a non-loopback `http://` target.
3. **Leave `statusBar.ts:312` tokenless.** That is a second `/ai/policy` reader (`POLICY_ROUTE`, `engineStatusModel.ts:159`) that only wants the environment name and runs on the status-bar path, where the CWE-613 idle-clock rule at `engineStatusModel.ts:17-20`/`:146-148` forbids a bearer — a naive "add the token to the `/ai/policy` call" fix would make the engine's idle timeout unreachable. `resolveAiPolicy` is user-initiated (`chat.ts:110`, `showAiPolicy` at `aiPolicy.ts:137`), so a bearer there is honest activity under that module's own `VERIFY_PLAN` rationale (`:151-155`). Worth expressing the distinction as a plan constant rather than a comment, matching how `POLL_PLAN`/`VERIFY_PLAN` already make it CI-assertable data.
4. Test `resolveAiPolicy` itself with an injected fetch + fake `globalState`: (a) a bearer is attached when a session exists, (b) a `null` response does not overwrite a cached `false`, (c) the tokenless status-bar probe is unaffected.
5. Once the gate can actually fire, re-check `docs/AI.md:188-191` — the trust note's reasoning is sound, but the "`assist_permitted == false` → Disabled" row only becomes true after this change.

**Related:** [`../ide/src/aiPolicy.ts`](../ide/src/aiPolicy.ts), [`../ide/src/engineClient.ts`](../ide/src/engineClient.ts), [`../ide/src/chat.ts`](../ide/src/chat.ts), [`../ide/src/statusBar.ts`](../ide/src/statusBar.ts), [`../ide/src/engineStatusModel.ts`](../ide/src/engineStatusModel.ts), [`../ide/src/auth.ts`](../ide/src/auth.ts), [`../ide/src/test/suite/ai-policy.test.ts`](../ide/src/test/suite/ai-policy.test.ts), `messagefoundry/api/app.py` (`/ai/policy`, `/ai/chat`), `messagefoundry/api/security.py` (`optional_identity`), [ADR 0035](adr/0035-ide-extension-workspace-trust-and-scope.md) (SEC-022 — the control this completes; note its own Related line miscites "ADR 0024 (AI policy)", which is the SMART token provider), [ADR 0135](adr/0135-engine-brokered-ai-assistance-customer-managed-llm-egress-with-per-use-audit.md) (the brokered path, server-gated), [`AI.md`](AI.md), #95.

**Source:** public-repo disclosure audit, 2026-08-01.

---

---

## 331. Anonymizer's fail-closed leak-check has no structural PHI detectors

> 🔢 **Filed 2026-08-01 — not started.** Value **6/10** · Difficulty **4/10** · _fill-in_. `anonymize_checked()`'s fail-closed leak-check only looks for known partner/site *strings*, so PHI left in any field the rule map omits passes it clean — and on a checkout with no token source it silently degrades to a routable-IP check over an HL7 body.

**Cluster:** Security & Compliance. **Priority:** P2. **Verdict:** build. **Severity:** medium.

**What:** `anonymize_checked()` is the function that "earns the right" to write a de-identified dataset somewhere shareable, and its entire verification is one call ([`messagefoundry/anon/__init__.py:88-96`](../messagefoundry/anon/__init__.py)):

```python
output = anonymize(raw, salt=salt, overlay=overlay, rules=rules)
hits = leak_check(output)
if hits:
    raise LeakError(...)
```

`leak_check` ([`anon/leak.py:59-61`](../messagefoundry/anon/leak.py)) is `_scanner().scan_text(text, include_estate=True)` plus `message_has_site_code(text)`. `scan_text`'s full body ([`scripts/security/scan_forbidden.py:784-795`](../scripts/security/scan_forbidden.py)) is: the `FORBIDDEN` name patterns, one routable-`_IPV4` check, and the `ESTATE_TOKENS` substrings. There is no MRN-shape, SSN-shape, DOB-shape, phone-shape or name detector anywhere on this path. The module's other structural detectors, `_WORKTREE_SLUG` (:92) and `_HOME_PATH` (:99), are called **only** from `scan_file` (:756, :758) and are unreachable from `leak_check` — so on the anonymizer path the live structural detector set is routable-IPv4 alone.

Three of the four live detectors are token-sourced and load **empty** without a token file — the scanner "degrades to STRUCTURAL-ONLY (routable-IPv4 only)" (:23-25), and `message_has_site_code` is "Always False when no site-code prefix is configured" ([`anon/surrogates.py:335-341`](../messagefoundry/anon/surrogates.py)). The fail-closed floor that exists for exactly this case, `token_floor_failure()` (:547), is consulted only inside `main()` (:881); the module-level `reload_tokens()` (:671) that the anonymizer's import path uses never checks it. So on a fork or a token-less checkout, `anonymize_checked` returns a green "leak-check passed" having verified that the HL7 body contains no routable IP address — and says nothing about it.

**This was hit in practice.** De-identifying `samples/messages/hapi-hl7v2/batch_18_messages.txt` in `f3c6d348` required a hand-authored overlay for the fields the default map omits — GT1-8/16/17/18, IN1-4/5/6/7/11/18/44, OBR-35, and a non-standard DST segment (per that commit's own message). Those omissions are real at HEAD: `DEFAULT_RULES` ([`anon/rules.py:68-121`](../messagefoundry/anon/rules.py)) covers GT1-3/5/6/7/12, IN1-16/19/36/49 and OBR-16/32 and nothing else, and `git log -- messagefoundry/anon/rules.py` shows the file unchanged since the clean snapshot. Nothing flagged their absence — a human reading the corpus did. The overlay was never committed (`git show --stat f3c6d348` lists 7 files, no `anon.toml`), so the derived knowledge is gone and the next corpus starts from the same blind map.

**Why:** the framework's promise is that a leak-check makes a dataset *proven* PHI-free before it may be committed or shared. What it actually proves is the absence of a **known string list**; a real MRN is not a denylisted string. The gap is honestly documented — [ADR 0030](adr/0030-anonymization-test-harness-tee.md):265-266 states it verbatim ("a field whose PHI the rule map **missed** sails through the fail-closed gate *clean*") and :268-270 / :339-343 defer structural detectors as a candidate improvement. This item is to build that deferral, not to report it.

Bounded honestly:
- **This is not a runtime data-plane defect.** Nothing under `pipeline/`, `store/`, `api/` or `transports/` imports `anon` — the only production caller is `tee anonymize-captures` ([`tee/__main__.py:47,519`](../tee/__main__.py)), and the harness's `anonymizer=` hook is optional and unwired by default ([`harness/reconcile/capture.py:46,57`](../harness/reconcile/capture.py)). No attacker-reachable path exists; no inbound message triggers it.
- **Exploitation is not the failure mode.** Reaching this code means already holding real captures — i.e. someone legitimately handling PHI, who could mishandle it more directly. The risk is a *human* one: a green result reading as an assurance it does not carry, and a PHI-bearing corpus being committed on the strength of it.
- **The primary control genuinely is rule-map completeness**, and the ADR says so. This is a missing backstop, not a broken control. The residual is the ordinary case of a corpus using a field nobody thought to map — which is precisely what happened in `f3c6d348`.
- **Free-text is already handled**: OBX-5/NTE-3 default to a blunt full-redact (ADR 0030 §3), so the highest-risk residual is not this one.

**Proposed:**
1. **Scope shape detection to what the anonymizer did not touch.** ADR 0030 (~:255) is right that a broad shape search over HL7 mass-false-positives — bodies are dense with 6-9 digit runs. But `anonymize` knows exactly which fields it rewrote, so run structural detectors **only over the fields no rule matched**. That makes SSN/NANP-phone/date/MRN shapes tractable without a false-positive storm.
2. **Add a cheaper coverage report first.** Have `anonymize_checked` surface every segment/field present in the input with no rule and no explicit keep-decision ("N unmapped fields: GT1-16, DST-4, …"). This alone would have caught the batch_18 case, needs no shape heuristics, and is a much smaller change than (1).
3. **Stop degrading silently.** Wire the existing `token_floor_failure()` (`scan_forbidden.py:547`) into the `leak_check` bridge so `anonymize_checked` refuses — or demands an explicit opt-out — when the token tables load empty, instead of returning clean. Have `LeakError`/the clean path name which detector tables were live.
4. **Land the batch_18 overlay** as a committed `anon.toml` fixture, or fold those fields into `DEFAULT_RULES`, so the hand-derived rule set is reusable rather than re-derived.
5. **Negative tests.** No test asserts the leak-check can see structural PHI, and none asserts behaviour on an empty token load — which is why the hole is invisible. Same lesson as #321: a green gate is evidence only once you have proved it can see that class. Mirror any change into `tee/anon/leak.py` (`test_anon_parity` pins the two).

**Related:** [`messagefoundry/anon/leak.py`](../messagefoundry/anon/leak.py), [`messagefoundry/anon/__init__.py`](../messagefoundry/anon/__init__.py), [`messagefoundry/anon/rules.py`](../messagefoundry/anon/rules.py), [`tee/anon/leak.py`](../tee/anon/leak.py), [`scripts/security/scan_forbidden.py`](../scripts/security/scan_forbidden.py), [`tee/__main__.py`](../tee/__main__.py), `tests/test_anon_core.py`, `tests/test_anon_parity.py`, [ADR 0030](adr/0030-anonymization-test-harness-tee.md) §5 + Consequences (the deferral this item builds), #36 (shipped — its "Verifiability" bullet is the claim this narrows; closed, so not an amendment target), #321 (sibling: the publish-path token *source* is incomplete — a different mechanism; its Proposed §3 cross-references this gap, and its "#320-adjacent" phrasing there is a mis-reference, since #320 is the windows-2025 MLLP ingress item), and the case-blind `_HOME_PATH` item from this same audit (a third, disjoint leak-gate mechanism).

**Source:** public-repo disclosure audit, 2026-08-01.

---

---

## 332. Release signing toolchain is unhashed

> 🔢 **Filed 2026-08-01 — not started.** Value **6/10** · Difficulty **5/10** · _fill-in_. The signing step installs `sigstore==4.4.0` with plain pip inside the job holding `contents`/`id-token`/`attestations: write`, so ~30 transitive dependencies resolve live from PyPI in the seconds before that job signs the wheel, sdist, SBOM and VEX and publishes to PyPI — and no Dependabot ecosystem can move the top pin either.

**Cluster:** Security / Supply chain. **Priority:** P2. **Verdict:** build. **Severity:** medium.

**What:** `.github/workflows/release.yml:253-255` says so in its own comment and then does it:

```
# NOTE: this pins the TOP only; sigstore's ~30 transitive deps still float at signing time.
# Closing the Scorecard alert outright needs the hashed release-tools lock (ADR 0034 option B).
python -m pip install "sigstore==4.4.0"
```

No `--require-hashes`, no lock. `sigstore` is absent from every committed lock — `grep -c sigstore uv.lock` → **0**, and no `*.lock` in the tree matches. `ci/locks/` holds exactly two files (`ci-scanners.lock`, `ci-quality.lock`) and `pyproject.toml:244` `[dependency-groups]` declares exactly two groups, `ci-scanners` (:256) and `ci-quality` (:280). There is no `release-tools` group.

The install sits in the job declared at `release.yml:67-71`:

```
contents: write       # create the release + upload its assets
id-token: write       # Sigstore signing, PyPI Trusted Publishing, + provenance — all via the GitHub OIDC identity
attestations: write   # write the SLSA build-provenance attestation
```

The next command (`:258-259`) signs the wheel, sdist, SBOM and VEX; the SLSA attestation (`:277-279`) and the PyPI Trusted Publishing step (`:340`) run later in that **same** job.

**Two things the finding as originally written understates, both verified here:**

1. **The top pin has no updater.** `.github/dependabot.yml` registers three ecosystems — `uv` (:17), `github-actions` (:42), `npm` (:61). None parses an inline `pip install X==Y` inside a workflow `run:` block. `tests/test_ci_venv_pinning.py:26-32` already records the consequence: *"a stale pin rots invisibly and a DELETED pin is invisible twice over."* So ADR 0034's *"Re-evaluate when 4.5.0 ages out"* (`:350`) has no trigger and no owner — it is a manual action nothing will ever prompt.
2. **`sigstore` is not the only one.** Two sibling installs in the same privileged job float their transitives identically: `release.yml:104` `python -m pip install "pip==26.1.2" "build==1.5.0"` (the PEP 517 frontend that produces the published wheel) and `release.yml:207` `python -m pip install "pip==26.1.2" "cyclonedx-bom~=7.3.1"` — the latter a `~=` *range*, into the main interpreter. Only the scratch venv at `:210` uses `--require-hashes`. Fixing `sigstore` alone narrows the window; it does not close the class.

**Correction to the audit's framing:** it cites ADR 0034's *"Option B … remains the only thing that closes the alert"* (`:206-208`), but the ADR's own 2026-07-29 amendment at `:263-265` states it **supersedes that sentence**. The mechanism is no longer hypothetical — it was built for CI tooling and is running. What is open is that `sigstore` was deliberately left out of it, for a reason at `:350` that a naive "just add it to the lock" fix would silently invert (see **Proposed**).

**Why:** exploitation is an **upstream** compromise, not a repo-local weakness — an attacker needs to own one of ~30 PyPI packages in `sigstore`'s closure (or land a hijack/typosquat) during the window a maintainer pushes a tag. The release job is **not reachable from a pull request**; it is gated on a tag push or `workflow_dispatch` (`release.yml:66` also pins it to `MEFORORG/MessageFoundry`). Anyone who can already trigger it is a maintainer who could do worse directly.

What makes it worth fixing anyway is the **blast radius if it lands**: arbitrary code executing at `:255` runs with the OIDC identity that then signs the artifacts, writes the SLSA attestation, and publishes to PyPI. That is not "a bad build" — it is a backdoored wheel carrying a *valid* Sigstore bundle and *valid* SLSA provenance. The compromise defeats the exact controls it is standing next to, and every downstream verifier (`gh attestation verify`, PEP 740) reports success.

Honestly bounded: **this is build-time only.** No PHI path, no running-engine surface, no operator-reachable behaviour. It does not touch the store, the API, or any connector. And per ADR 0034 §3 (`:162-170`) the fix moves the OPEN Scorecard count only for the lines it actually converts to `--require-hashes`; the two genuinely-open `PinnedDependenciesID` alerts named at `:336-341` are the SBOM scratch-venv pair, not this one.

**Proposed:** repeat the mechanism ADR 0034's 2026-07-29 amendment already proved, and handle the version question the residual row raises rather than stepping over it.

1. **Resolve the 4.4.0-vs-4.5.0 decision first, explicitly.** ADR 0034:350 keeps `sigstore` out of the lock *because* routing it through would resolve **4.5.0**, which was `<48 h` old against `.github/dependabot.yml`'s `cooldown: default-days: 5` (:26-30). That was written 2026-07-29. By the ADR's own arithmetic the window closes around 2026-08-01/02 — i.e. now — but **confirm the actual PyPI publish date before acting**; this item does not verify it, and the whole rationale hangs on it. If the window has closed, the objection is spent and the residual row should be amended, not quietly contradicted. This is a recorded owner decision; do not invert it silently.
2. **Add a PEP 735 `release-tools` group** to `pyproject.toml` alongside `ci-scanners`/`ci-quality`, non-default (ADR 0034:283-287, decision 2 — an extra becomes a real install target; a default group lands in the release SBOM and in what `pip-audit` audits as runtime).
3. **Export it as a seventh lock** in `.github/workflows/security.yml:87-89`, added to the `git diff --exit-code` gate on `:89`, to `dependabot-lock-resync.yml`, and to `tests/test_dep1_lock_resync_lockstep.py` (which asserts the export set, the per-file flags, and that everything exported is staged — currently six-place). Install it at `release.yml:255` with `--require-hashes`.
4. **Measure the resolve contamination before committing.** This is the known failure mode: ADR 0034:354 records that `semgrep` was excluded by decision precisely because a new group *"still forces a `click 8.4.1 → 8.4.2` re-resolve across all four artifacts."* `sigstore` pulls `cryptography`, `requests` and `pydantic`-adjacent packages that the runtime closure also carries. Acceptance criterion is the one that ADR used at :287 — re-export all existing locks and require `git diff --exit-code` → 0. If it is non-zero, this becomes the same excluded-by-decision call semgrep got, recorded as a residual rather than forced through.
5. **Update the guard.** `tests/test_ci_venv_pinning.py:204-210` `RELEASE_PINNED_TOOLS` asserts a `sigstore` pin *exists* at an inline install site; a lock install removes that site, so the non-vacuity backstop needs re-pointing at the lock rather than deleting (deleting it is exactly the regression `:202-203` exists to catch).
6. **Then take `build` and `cyclonedx-bom` in the same group** — but note `cyclonedx-bom` is half of the byte-identity pair `test_sbom_install_is_byte_identical_in_release_and_security` enforces, so per ADR 0034:336-341 both halves must move in lockstep or the test reds.

**Testability caveat, stated up front:** ADR 0034:218-225 records that `release.yml` runs **only on a tag push**, so no PR CI leg executes this path — the first real run of any change here is a release. Follow that section's own protocol: dry-run via `workflow_dispatch` and read the log before the next tag.

**Related:** `.github/workflows/release.yml:104,207,244-259`, `.github/workflows/security.yml:87-89`, `.github/dependabot.yml:17,26-30,42,61`, `pyproject.toml:244-284`, `ci/locks/`, `tests/test_ci_venv_pinning.py`, `tests/test_dep1_lock_resync_lockstep.py`, [ADR 0034](adr/0034-static-analysis-triage-policy-accepted-risk-register.md) §3 + the 2026-07-29 amendment (esp. the residuals table, `:350`), #321, and the Dependabot auto-merge item from this same audit (a different file and a different fix — the two are siblings, not one change).

**Source:** public-repo disclosure audit, 2026-08-01. Classified close-the-weakness-instead: the `release.yml:253-254` note and ADR 0034's residual row are honest and stay — the unhashed install is what needs fixing.

---

---

## 333. Per-connection TLS deviations are invisible to the loosening registry

> 🔢 **Filed 2026-08-01 — not started.** Value **6/10** · Difficulty **3/10** · _fill-in_. Two per-connection TLS deviations — `tls_allow_expired` on six outbound connectors, and the generic-ODBC DATABASE hop's warn-and-cross delegation — never reach `security_loosenings()`, so `GET /security/posture`, `messagefoundry security show`, `messagefoundry check` and the VS Code `[security]` editor all report a clean posture while either is set.

*(Filed as one item, not two: both are fixed by the same edits to the same four files — a reader beside `accepted_cleartext_hops`, an entry in `security_loosenings()`, an advisory beside `_check_cleartext_accepted`, and threading at `api/app.py`. Stated once rather than twice, per the docs rule against restating a load-bearing fact.)*

**Cluster:** Security / Posture reporting. **Priority:** P2. **Verdict:** build. **Severity:** low.

**What:** two different weakenings, one shared blind spot. `security_loosenings()` ([`config/settings.py:3955-4140`](../messagefoundry/config/settings.py)) covers neither: the function was read end to end, and the last entry is the ADR 0153 `cleartext_accepted` block at `:4130-4139`, immediately followed by `return out` at `:4140`. Its own scope paragraph enumerates the deviations it covers from outside `[security]` — `settings.py:3967-3968`:

> …an ENUMERATED set of deviations that live elsewhere: `[store].aad_bind`, `[auth].ad_session_recheck_seconds`, and the per-connection `cleartext_accepted`.

**(a) `tls_allow_expired`.** A repo-wide grep confirms it reaches no reporting surface: it appears only in `config/wiring.py` (the six factory parameters at `:811`, `:1470`, `:1550`, `:1733`, `:2126`, `:2291` — `MLLP`/`Rest`/`FHIR`/`DICOM`/`Soap`/`Ftp`), in `config/tls_policy.py`, in the six transports that consume it, in `tests/test_tls_expiry_relaxation.py`, and in docs. It is absent from `config/settings.py`, `api/app.py:1517` (the `GET /security/posture` registry call), `__main__.py:1468` (the serve-time loosening warning), `__main__.py:4342` (`security show`), `checks.py`, the web console, and `ide/src/securityEditor.ts`. The one thing that *does* fire is a construction-time log WARNING naming the host — [`config/tls_policy.py:221-227`](../messagefoundry/config/tls_policy.py).

**(b) The generic-ODBC DATABASE hop.** `_build_connection` returns the weakened flag hard-coded false for that dialect — `messagefoundry/transports/database.py:325`, `if dialect == "generic": return _build_odbc_dsn(s), False` — so the send-time re-assertion `_assert_send_hop` (`:129`) short-circuits at `if weakened and not _weakened_tls_permitted(...)` (`:134`) and never fires. `_warn_generic_tls_unenforced` (`:286`) logs at `:304-308` and returns. That much is deliberate and correctly documented ([ADR 0092's 2026-07-12 amendment](adr/0092-posture-keyed-transport-hop-refusal-refuse-the-insecure-phi-hop.md):111-127, [`DEPLOYMENT.md:300`](DEPLOYMENT.md) / `:377-381`, [`CONNECTIONS.md:1014-1019`](CONNECTIONS.md)). The defect is that the warning is the *entire* control, and it has two further holes:

- **The detector is value-blind, so the one signal is defeatable.** `_ODBC_TLS_HINT_RE` (`:217`) is `re.compile(r"ssl|tls|encrypt", re.IGNORECASE)` and `:298` matches it against **keys only** (`if any(_ODBC_TLS_HINT_RE.search(str(k)) for k in params):`). So `odbc_params={"SSLmode": "disable"}` — psqlODBC's explicit *no TLS* value — is read as "the operator has taken TLS ownership" and the WARNING drops to `logger.debug` (`:299-302`). Same for `sslmode=prefer` and `Encrypt=no`. The comment at `:213-216` concedes the regex "cannot prove the value *verifies* the cert, only that TLS was addressed", but `disable` is not "addressed" — and it lands in the quieter branch. `tests/test_database_transport.py:202-212` pins the present behaviour by asserting the WARNING is absent whenever any TLS-ish key exists.
- **The line names no connection.** `_warn_generic_tls_unenforced(params)` (`:286`) receives only the params mapping, so with several generic DB connections it is not actionable. Both directions are affected — `DatabaseDestination.__init__` (`:547`) and `DatabaseSource.__init__` (`:770`) share `_build_connection` — and the credential rides the same DSN (`:263-270`).

**The shared root cause, stated once:** the registry's only completeness floor, `tests/test_security_posture_defaults.py:177-211`, iterates `SecuritySettings.model_fields` (`:203-204`) with an exemption set at `:189-202`. A **connection-scoped** deviation is outside its reach by construction. That is why `cleartext_accepted` needed a hand-written entry (`config/wiring.py:3078-3104`, `accepted_cleartext_hops`), why these two have none, and why nothing would catch the next one either.

**Why:** under ADR 0148's "one posture, loosen only", the governing rule is that every deviation is visible in the registry — `settings.py:3981-3988` and `wiring.py:3091-3094` both argue that a deviation the registry cannot see is a second posture by the back door. The practical loss is review and audit visibility over time: an auditor querying `GET /security/posture`, or an operator opening the VS Code `[security]` editor, gets a list that says nothing, and `security show`'s `loosenings_scope` string (`__main__.py:4349-4351`) names only `cleartext_accepted` as the known omission — so the declared scope is itself incomplete. `docs/DEPLOYMENT.md:349-351` states the concrete consequence for (a): a two-week bridge set when a partner's certificate lapses "has **nothing that expires it or surfaces it**". For (b) it is the repo's own rule that *a compensating control must not rest on a false premise* — ADR 0092 accepted the exemption on the strength of one mitigation ("construction **logs it**"), and that mitigation is defeatable, anonymous, and lives in a log stream rather than any surface a reviewer reads.

**Bounded honestly, in three directions.**

1. **Neither is a MITM primitive.** `tls_allow_expired` ORs only `_X509_V_FLAG_NO_CHECK_TIME` (`0x200000`), documented at `tls_policy.py:182-192` as disabling *only* the validity-period check while "the chain signature, name constraints, key usage / EKU, basic constraints, and — separately — the hostname match (`check_hostname`) all still apply"; `tests/test_tls_expiry_relaxation.py` proves a wrong-host and a broken-chain peer are still rejected with the flag set, and `tls_policy.py:217-220` makes it a guarded no-op on a `CERT_NONE` context. For (b) the engine does not create the cleartext hop — a driver keyword does, and `dialect` defaults to `sqlserver` (`database.py:318`), which keeps the byte-identical posture-keyed refusal (`:319-323`).
2. **Neither is an attacker capability.** Both require write access to the connection config — a `.py` module in the config dir or `connections.toml` — and anyone with that access could instead set `tls_verify=false`, repoint the host, or add an outbound to a destination they control. Nothing in an inbound payload selects a dialect, params, or the expiry flag. `db_lookup` is not on the generic path at all: the ADR 0010 read executor calls `_build_dsn` directly (`database.py:986`) and stays SQL-Server-only.
3. **Neither is silent.** Both log at construction. What is missing is that a log line emitted once at startup is not the surface anyone queries three months later, and today it is the *only* one.

**Proposed** (all advisory — do **not** convert the generic-ODBC delegation into a refusal; ADR 0092:113-118 is right that the engine cannot enumerate arbitrary driver keywords, and a guess-based refusal would break legitimate drivers):

1. **Fix the value-blind detector first.** Keep `_ODBC_TLS_HINT_RE` (`database.py:217`) as the key finder, and add a small deny-list of known no-TLS / no-verify *values* — psqlODBC `disable`/`allow`/`prefer`, MySQL `DISABLED`/`PREFERRED`, `Encrypt` in `no`/`0`/`false` — that keeps the branch at `:304` (WARNING) instead of `:299` (DEBUG). Invert `tests/test_database_transport.py:202-212` into a pair: `verify-full` stays quiet, `disable` warns. **This must precede steps 3–4** or any new surface inherits the false negative and reports the worst real case as clean.
2. **Name the connection** in `_warn_generic_tls_unenforced` (`:286`). `DatabaseDestination` already has `config.name` (`config/models.py:579`); `Source` (`config/models.py:235-242`) carries no name field, so the inbound name has to come from the registry at the construction site (`:770`).
3. **Add two readers beside `accepted_cleartext_hops`** (`config/wiring.py:3078-3104`): an `expiry_relaxed_hops(registry)` returning `(name, host)` for every `registry.outbound` entry whose `settings` dict has `tls_allow_expired` truthy — the flag lands in `Destination.settings` (`config/models.py:581`), not in a model field like `cleartext_accepted` (`:615`) — and a generic-ODBC reader that walks **both** `registry.outbound` *and* the inbound table, since `accepted_cleartext_hops` reads only outbound + FHIR-lookup today and DATABASE sources need coverage. Note that only the outbound table is needed for the expiry flag right now: `FhirLookup` (`wiring.py:485-499`) exposes `verify_tls` but no `tls_allow_expired`. Say that in the docstring so adding it later cannot silently escape the reader.
4. **Add both entries to `security_loosenings()`** immediately after the `cleartext_accepted` block (`settings.py:4130-4139`), taking the names as **required** parameters per the function's stated rule at `settings.py:3976-3979` (an optional parameter is a detector that silently fails to fire). Risk text must state both halves honestly for the expiry flag: an expired server certificate is accepted indefinitely on the named hop; chain, hostname and key usage are still verified.
5. **Thread at the two call sites that have a graph** — `api/app.py:1503` (alongside the existing `accepted_cleartext_hops` resolution) and sibling advisory `CheckResult`s in `checks.py` modelled on `_check_cleartext_accepted` (`checks.py:1317-1360`), same `required=False` shape and same SKIP-on-unloadable-config behaviour. For the two graphless callers (`__main__.py:1468`, `:4342`) extend the `loosenings_scope` string at `:4349-4351` to name all three connection-scoped deviations rather than only `cleartext_accepted`.
6. **Update the docstring's enumerated deviation list** (`settings.py:3964-3974`) and add rows to [`docs/SECURITY-LOOSENING.md`](SECURITY-LOOSENING.md), which mentions neither today.
7. **Move `docs/DEPLOYMENT.md` in the same commit** — `:250`, `:342-344`, `:442` and the maintenance note at `:629` all assert that no loosening register covers `tls_allow_expired`, and each becomes false the moment step 4 lands. While there, tighten `:348`: "with nothing refusing it, warning at posture level, or reporting it" — the trailing clause overreaches against the construction WARNING the same section acknowledges four lines earlier at `:343-344`. The rest of that section was verified accurate: the "six connectors" list, the "chain, hostname and key usage are still fully verified" claim, and the DICOMweb exclusion at `:352-353`.
8. **The durable half:** extend the completeness floor (`tests/test_security_posture_defaults.py`) with a connection-scoped arm, so the next per-connection deviation is a test failure rather than a re-audit.

**Related:** [`messagefoundry/config/settings.py`](../messagefoundry/config/settings.py) (`security_loosenings`), [`messagefoundry/config/tls_policy.py`](../messagefoundry/config/tls_policy.py) (`relax_verify_expiry`), [`messagefoundry/config/wiring.py`](../messagefoundry/config/wiring.py) (`accepted_cleartext_hops` + the six factories), [`messagefoundry/transports/database.py`](../messagefoundry/transports/database.py) (`_ODBC_TLS_HINT_RE` `:217`, `_warn_generic_tls_unenforced` `:286`, `_build_connection` `:311`), [`messagefoundry/checks.py:1317`](../messagefoundry/checks.py), [`messagefoundry/api/app.py:1503,1515`](../messagefoundry/api/app.py), `messagefoundry/__main__.py`, `ide/src/securityEditor.ts`, `tests/test_security_posture_defaults.py`, `tests/test_tls_expiry_relaxation.py`, `tests/test_database_transport.py:186-212`, [ADR 0092 amendment 2026-07-12](adr/0092-posture-keyed-transport-hop-refusal-refuse-the-insecure-phi-hop.md), [ADR 0094](adr/0094-tls-expiry-relaxation.md), [ADR 0118](adr/0118-security-loosening-warning-and-posture-view.md) (AC-4/AC-5), [ADR 0148](adr/0148-phi-default-posture-and-an-explicit-security-enforcement-level.md), [ADR 0153](adr/0153-collapse-the-posture-gradient-no-data-label-may-allow-a-cleartext-hop.md) (the `cleartext_accepted` precedent), [`docs/DEPLOYMENT.md`](DEPLOYMENT.md), [`docs/CONNECTIONS.md`](CONNECTIONS.md), [`docs/SECURITY-LOOSENING.md`](SECURITY-LOOSENING.md); #129 (shipped — built the expiry relaxation; its write-up says "PHI-free construction WARN" and never claimed registry coverage), #66 (shipped — introduced the generic ODBC dialect and recorded the exemption as intentional), #200.

**Source:** public-repo disclosure audit, 2026-08-01. Classified *close-the-weakness-instead*: the `DEPLOYMENT.md` and `CONNECTIONS.md` prose is accurate and stays — this item is the defect behind it.

---

---

## 334. semgrep, a required blocking gate, scans a two-directory allow-list

> 🔢 **Filed 2026-08-01 — not started.** Value **5/10** · Difficulty **2/10** · _fill-in_. The blocking semgrep gate scans `messagefoundry tee` only, so 56 tracked `.py` files that bandit's own scope declares in-bounds — including the 32-file web-console wheel and `scripts/` — never see the project's curated rules, and the parity test that exists to stop exactly this drift has no semgrep arm.

**Cluster:** Security / CI gates. **Priority:** P2. **Verdict:** build. **Severity:** low.

**What:** `.github/workflows/security.yml:413` runs the project SAST gate as an allow-list:

```
semgrep --config .semgrep --error --metrics off messagefoundry tee
```

It is a **required merge context** (`.github/required-contexts.txt:78`) and **blocking** (`security.yml:396`). Its sibling on the same file was moved off that shape deliberately — `security.yml:359-360` is `bandit -r .` minus an explicit `--exclude` list, and the rationale at `:348-352` names the failure by name: *"It was `-r messagefoundry tee` while the hook scanned everything except tests/harness/samples — so scripts/ (security tooling, subprocess-heavy) was gated locally and by nothing in CI."* semgrep was never given the same treatment.

Taking bandit's exclude set as the project's own declaration of what SAST is supposed to cover, the delta is **56 tracked `.py` files**: `messagefoundry_webconsole/` (32 files, which ships as its own separately-versioned wheel — `packaging/messagefoundry-webconsole/pyproject.toml:17`, force-included at `:55-58`), `scripts/` (22 — the security tooling the bandit comment was written about), and `docker/` (2). `packaging/`'s 14 files are all tests and are excluded on both sides.

`tests/test_lint_scope_parity.py` is cited at `security.yml:358` as the control that stops this ("fails if this and the hook drift apart again"), and it does hold that line for ruff and bandit — `test_ci_bandit_scans_the_repo_not_an_allow_list` (`:119-125`) asserts `bandit\s+-r\s+\.` against the workflow directly. **The string "semgrep" does not appear anywhere in that file.** There is no semgrep pre-commit hook either, so semgrep is CI-only and that CI-only assertion at `:119` is the exact template a semgrep arm would follow.

**Why:** the honest blast radius is **drift, not exposure** — three things bound it, and the item is worth filing anyway:

1. **Nothing is being missed today.** Grepping `messagefoundry_webconsole/` for every sink the five rules match (`shell=True`, `os.system`, `eval(`, `exec(`, `pickle.`, `marshal.`, `yaml.load(`, `verify=False`) returns **zero** hits. The console makes no outbound HTTP calls of its own — `routes/oidc.py` delegates code redemption to `messagefoundry.auth.oidc`, which *is* scanned.
2. **bandit is a real compensating control on the same PR.** It is also required (`required-contexts.txt:74`), it does scan all 56 files, and its built-in checks for `exec`/`eval`, pickle/marshal, `yaml.load` and `shell=True` are **not** in the `--skip` list at `:359` (that list is only `B101,B110,B311,B404,B608`). So four of the five rules have overlapping enforcement. *(Confirm the specific bandit check-id mapping before leaning on this in review; the skip list is what was read, not bandit's plugin source.)*
3. **CodeQL also covers it** — `codeql.yml:55` analyses python repo-wide with `security-extended` (`:66`) and has no paths filter. But it is **deliberately not a required context** (`required-contexts.txt:108-110`: fork-PR tokens lack `security-events: write`), so it is a detector, not a gate.

What is *not* covered is the thing that will grow: `.semgrep/messagefoundry.yml` is where **project-specific** rules land — rules bandit will never ship. A future rule written because of something an operator hit in the console would silently not run on the console. The second step in the same job (`security.yml:414-424`, the ADR 0144 handler-taint rules) is scoped to `samples/config` only, so it does not close this either.

**Correcting the audit that produced this item:** the source finding claimed the five rules "cover exactly the sinks that matter in an HTML-rendering console." They do not — `.semgrep/messagefoundry.yml:5-53` contains no HTML, template, escaping or XSS rule at all. The rules are generic dangerous-sink rules (`:6`, `:14`, `:21`, `:30`, `:43`). The finding also named only the web console; `scripts/` is out of scope on the same line and is the directory the bandit widening was specifically about.

**Proposed:**

1. Change `security.yml:413` to scan the tree the way bandit does — `semgrep --config .semgrep --error --metrics off --exclude … .` — mirroring bandit's `--exclude` set exactly so the two gates cannot disagree about what "the project" is. **Verify the tree is clean at that bar in the same PR**: `--error` is blocking, and `tests/` (563 files) very plausibly contains `pickle`/`yaml.load`/`eval` test idioms, which is presumably why `tests`/`harness`/`samples` are excluded on the bandit side too.
2. Add `test_ci_semgrep_scans_the_repo_not_an_allow_list` to `tests/test_lint_scope_parity.py`, modelled on `:119-125`, so the next narrowing has to be deliberate. This is the durable half — without it, step 1 can rot again exactly as bandit's did.
3. If a full widening is rejected, the fallback is appending `messagefoundry_webconsole scripts docker` to the argument list — but note that this is the allow-list shape `:348-352` explicitly retired, and it will go stale the next time a directory is added.

**Related:** `.github/workflows/security.yml:348-360` (the bandit precedent) and `:393-424` (the semgrep job), `.semgrep/messagefoundry.yml`, `tests/test_lint_scope_parity.py`, `.github/required-contexts.txt:74`/`:78`/`:108-110`, `.github/workflows/codeql.yml`, `packaging/messagefoundry-webconsole/pyproject.toml`, [ADR 0065](adr/0065-web-ops-dashboard.md) (the console is a distinct distribution), [ADR 0144](adr/0144-handler-config-taint-rules.md) Inc 3 (the second, `samples/config`-scoped semgrep step).

**Source:** public-repo disclosure audit, 2026-08-01.

---

---

## 335. Control-char scrub misses `exc_text`/`stack_info`

> 🔢 **Filed 2026-08-01 — not started.** Value **4/10** · Difficulty **3/10** · _fill-in_. `ControlCharScrubFilter` escapes only the rendered message, so a CR/LF inside a logged exception traceback reaches the human-readable text sink verbatim and can forge a whole log record; the JSON sink is unaffected and the reachable call sites are few.

**Cluster:** Security / Logging. **Priority:** P3. **Verdict:** build (small). **Severity:** low.

**What:** `ControlCharScrubFilter` ([logging_setup.py:81-87](../messagefoundry/logging_setup.py)) covers the rendered message and nothing else:

```python
def filter(self, record: logging.LogRecord) -> bool:
    message = record.getMessage()
    scrubbed = message.translate(_CTRL_TRANSLATION)
    if scrubbed != message:
        record.msg = scrubbed
        record.args = ()
    return True
```

`_CTRL_TRANSLATION` is defined at `logging_setup.py:65-69` and referenced exactly once more, at `:83` — nowhere else in the tree. `record.exc_text` and `record.stack_info` are touched only by `RedactionFilter` (`logging_setup.py:124-131`), which applies `redact()` — an HL7/date/name-shaped **span** rewriter, not a control-character escaper. `logging.Formatter.format` then appends `exc_text` verbatim, and `_LOG_FORMAT` (`:54`) is `"%(asctime)s %(levelname)-8s %(name)s: %(message)s"`, so a payload only has to pad the level to eight columns to be byte-indistinguishable from a real record.

Reproduced at HEAD (worktree source on `sys.path[0]`, `configure_logging("INFO", fmt="text")`):

```
2026-08-01T15:29:08Z ERROR    messagefoundry.demo: delivery failed
Traceback (most recent call last):
  ...
ValueError: boom
2026-08-01T00:00:00Z INFO messagefoundry.auth: FORGED admin login ok
2026-08-01T15:29:08Z INFO     messagefoundry.demo: arg path: boom\nFORGED-VIA-ARG
```

The forged line lands at column 0 on its own physical line; the identical payload passed as a `%`-arg in the same run comes out escaped. The filter order is already right for the fix — `_install_phi_filters` (`:309-311`) adds `RedactionFilter` → `CredentialQueryScrubFilter` → `ControlCharScrubFilter`, so `exc_text` is populated before the scrub filter runs.

This is the residual [ADR 0034](adr/0034-static-analysis-triage-policy-accepted-risk-register.md) already discloses at `:131` and `:144-147` (*"Open hardening (not done)"*). The ADR is honest — its older register line at `:40` is superseded in place by the correction block opened at `:126` — so **the defect is what needs fixing, not the disclosure.**

**Why:** it defeats the ASVS 16.4.1 control the project claims, on the sink an operator actually reads during an incident: a forged `… INFO messagefoundry.auth: …` line in the NSSM-captured stdout is indistinguishable from a real one, and a line-oriented SIEM parser ingests it as a record.

Honestly bounded — this is **not**:

- **Not the JSON sink.** `JsonFormatter` emits through `json.dumps(payload, ensure_ascii=False)` (`logging_setup.py:197`), which escapes C0 regardless of `ensure_ascii`. The off-box forwarder defaults to `fmt="json"` (`:215`).
- **Not PHI exposure.** `RedactionFilter` runs first and rewrites HL7/date/name-shaped spans to `[redacted]`, which also neuters the obvious HL7-shaped forgery payload. The surviving vector is a *non*-HL7-shaped CR/LF-bearing string.
- **Not widely reachable.** Contrary to ADR 0034:140-142's list, the router/transform **content**-fault catches log the exception **type only**, with no `exc_info` — `wiring_runner.py:4525-4531` and `:4541-4546` (docstring `:4521-4523`: *"the log emits the exception TYPE only"*), same shape in `_apply_transform_internal_error` at `:4550-4571`. `messagefoundry/transports/` contains **zero** `exc_info` sites. Of the 107 `log.exception(`/`exc_info=` sites engine-wide, the ones on the message path are the ADR 0054 built-ins-parser fallback guards (`parsing/peek.py:209`, `parsing/message.py:107`) and the respawn callbacks (`wiring_runner.py:2651`, `:2724`, `exc_info=task.exception()`); the rest are pollers and store/OS faults whose text is not peer-derived.
- **Not remote-code/privilege anything.** It is log-record integrity only.

One correction *widening* the bounding: the residual is not stdout/NSSM alone. `SyslogForward.fmt` accepts `"text"` (`logging_setup.py:215`) and `:401` honours it (`fwd_handler.setFormatter(_make_formatter(forward.fmt))`), so a `forward_format = "text"` collector receives the same unescaped `exc_text`.

**Proposed:**

1. Extend `ControlCharScrubFilter.filter` to apply `_CTRL_TRANSLATION` to `record.exc_text` and `record.stack_info` as well as the message. It runs last (`:309-311`), so both fields are already populated and redacted.
2. **Make the readability call ADR 0034:146 defers.** A blanket translate collapses every traceback to one physical line, which is a real operator-facing regression — and is precisely why this few-line fix has been deferred. The cheaper option that keeps both properties: escape CR/LF **and** re-indent — split on newline, escape all other control chars, and rejoin with `"\n    | "` (or any fixed non-empty prefix). A continuation line can then never start at column 0, so it can never match `_LOG_FORMAT`, and the traceback stays readable. Pick one explicitly and record it as an ADR 0034 amendment rather than a drive-by edit.
3. Add the missing tests. `tests/test_asvs_phase0.py:60-80` has three `ControlCharScrubFilter` tests and all three build records with `exc_info=None` (`_record` at `:56-57`); `tests/test_logging.py:231-237` covers PHI in `stack_info` but asserts nothing about control chars. Add a record carrying `exc_text`/`stack_info` with an embedded CRLF and assert the formatted output has no line matching the record prefix.
4. Update ADR 0034 `:144-147` from "not done" to the shipped state in the same commit.

**Related:** [`messagefoundry/logging_setup.py`](../messagefoundry/logging_setup.py) (`ControlCharScrubFilter`, `RedactionFilter`, `_install_phi_filters`, `JsonFormatter`, `SyslogForward`), [`messagefoundry/redaction.py`](../messagefoundry/redaction.py) (`redact`/`safe_text`/`safe_exc` — `:81-101`; these do not strip control chars either, but their output is a `%`-arg and so *is* covered), `tests/test_asvs_phase0.py`, `tests/test_logging.py`, [ADR 0034](adr/0034-static-analysis-triage-policy-accepted-risk-register.md) §"Class-rationale corrections" §1, [ADR 0080](adr/0080-tls-syslog-forwarding.md) (the off-box text-format sink), ASVS 5.0 16.4.1.

**Source:** public-repo disclosure audit, 2026-08-01. Classified close-the-weakness-instead: ADR 0034's prose is accurate and self-correcting and stays as written.

---

---

## 336. Dependabot auto-merge shields review with a deny-list

> 🔢 **Filed 2026-08-01 — not started.** Value **5/10** · Difficulty **3/10** · _fill-in_. Auto-merge clears everything a 16-name Python deny-list does not name, and the same workflow also auto-merges `github-actions` bumps — an ecosystem its own header says is cooldown-aged but which has no `cooldown:` configured.

**Cluster:** Security / Supply chain. **Priority:** P3. **Verdict:** build. **Severity:** low.

**What:** `.github/workflows/dependabot-auto-merge.yml` decides unattended merges by exclusion. Guardrail #3 is a hard-coded shield list at `.github/workflows/dependabot-auto-merge.yml:78-79`:

```
denylist="cryptography argon2-cffi argon2-cffi-bindings paramiko ldap3 pyspnego \
  fastapi starlette uvicorn pydantic pydantic-core python-jose pyjwt passlib bcrypt cffi"
```

Anything not on that list, on any ecosystem, auto-merges if it is a patch — the merge gate at `:155-161` keys only on `update-type == 'version-update:semver-patch'` (plus dev-only minors), with no ecosystem or dependency-type qualifier. The workflow itself already names the residual at `:31-34`: "a malicious patch that BOTH rides a real concurrent published advisory AND is not on the deny-list would still auto-merge."

Two things measured at HEAD make the exposed set **wider than that comment implies**:

1. **All 16 names are Python distributions, but the job has no ecosystem filter.** The only gate is `if: github.event.pull_request.user.login == 'dependabot[bot]'` (`:58`), so the npm (`/ide`) and `github-actions` ecosystems configured in `.github/dependabot.yml` run this same path with **zero** deny-list coverage — no npm or action name can ever match a Python token.
2. **The `github-actions` ecosystem has no cooldown.** `.github/dependabot.yml:42-56` carries `schedule` + `groups` only; there is no `cooldown:` key, unlike uv (`default-days: 5`, `:26-30`) and npm (`default-days: 3`, `:66-68`). That falsifies the compensating-control claim in the workflow header at `.github/workflows/dependabot-auto-merge.yml:16-18` — "Fresh-release supply-chain poisoning is handled upstream by the dependabot.yml `cooldown`" — for the one ecosystem whose artifacts execute inside CI. Actions are SHA-pinned (e.g. `actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1`, `.github/workflows/release.yml:73`), and a Dependabot patch bump rewrites that SHA with no aging and no shield.

Two smaller corrections to the record. The deny-list is 16 names but only **13** are real dependencies: `python-jose`, `pyjwt` and `passlib` do not appear in `requirements.lock` (98 pinned distributions), so the shield covers 13 of 98. And `tests/test_dependabot_automerge_guardrails.py:97-108` asserts a cooldown only for `package-ecosystem == "uv"` — nothing tests that the other two ecosystems have one, which is why the gap is invisible to CI.

**Why:** this is the "compensating control resting on a false premise" rule (CLAUDE.md §11) firing on a supply-chain gate. The header's stated backstop is weaker than it reads in a second way too: `.github/workflows/security.yml:261` says in the repo's own words that "pip-audit (lockfile only) and bandit/semgrep (source only)" never see a dependency's contents — semgrep targets `messagefoundry tee` (`security.yml:413`) — and the required contexts `pip-audit (dependency vulnerabilities)` / `npm-audit (ide dependency vulnerabilities)` (`.github/required-contexts.txt`) are known-advisory scanners, which by construction cannot flag a package that was malicious at publish time. So "main's required CI backstops both" (`.yml:33-34`) does not hold against the specific threat the deny-list exists to cover.

**Bounding this honestly — the blast radius is NOT what it first looks like:**

- **The attacker must already own an upstream publisher account.** That is a capability with worse uses than this repo; nothing here is a privilege escalation for a lesser attacker.
- **On the security track the GHSA gate is real and fails closed** (`:136-145`): an API error or a no-matching-advisory result routes to manual review. Because it queries `ecosystem=pip` (`:132-135`), npm and actions security PRs can never match and always fall to manual — a false negative in the *safe* direction.
- **On the version track the uv and npm ecosystems are cooldown-aged** (5 and 3 days). Only `github-actions` is unaged.
- **Merging to main is not publication.** `.github/workflows/release.yml:30-41` gates PyPI on a `vX.Y.Z` tag push, and `workflow_dispatch` explicitly does not publish (`release.yml:5-8`), so reaching a downstream install still requires the owner to cut a tag. The sharpest theoretical path — a poisoned action riding in `release.yml`, whose job holds `id-token: write` for Trusted Publishing (`release.yml:70`) — needs that same owner tag push to execute at all.
- **This is hardening, not an incident.** No evidence of exploitation; the item is that the control's stated premise and its configuration disagree.

**Proposed:**

1. **Invert guardrail #3 to an allow-set.** Replace the 16-name deny-list at `:78-79` with an explicit list of packages eligible for unattended patch merge; everything else routes to manual review. The current default is "merge unless named"; it should be "hold unless named." Keep the fail-safe whole-group denial semantics (`:81-92`).
2. **Add a `cooldown:` to the `github-actions` ecosystem** in `.github/dependabot.yml:42-56`, matching uv's 5/7. This is the one-line change that makes the header's claim at `:16-18` true instead of aspirational.
3. **Extend `tests/test_dependabot_automerge_guardrails.py:97-108` to assert a cooldown on every ecosystem**, not just `uv` — the test's narrowness is why item 2 was invisible.
4. **Security-track aging must be workflow-side, not dependabot-side.** "Extend the cooldown to the security track" is *not* implementable in `.github/dependabot.yml`: that file records at `:22-25` that security updates ignore cooldown by Dependabot design. The equivalent is a release-age check in the workflow — require the candidate version to have been published for N hours before auto-merging — placed alongside the GHSA step and failing closed the same way.
5. **Correct the header comment.** `:33-34` should stop citing pip-audit/bandit/semgrep as a backstop against a fresh malicious publish, since `security.yml:261` already states they cannot see it. Either drop the clause or scope it to "known-CVE regressions."
6. **Prune or annotate the three non-dependency deny-list entries** (`python-jose`, `pyjwt`, `passlib` are absent from `requirements.lock`) so the list's apparent breadth matches its effective breadth. If they are deliberately prophylactic, say so in the comment.

**Related:** `.github/workflows/dependabot-auto-merge.yml`, `.github/dependabot.yml`, `.github/workflows/security.yml`, `.github/workflows/release.yml`, `.github/required-contexts.txt`, `requirements.lock`, `tests/test_dependabot_automerge_guardrails.py`, `.github/workflows/dependabot-lock-resync.yml`; #321, #322, and the unhashed release-toolchain item from this same audit (a different file and a different fix).

**Source:** public-repo disclosure audit, 2026-08-01.

---

---

## 337. handler-security lint: `getattr` indirection and the undecorated helper

> 🔢 **Filed 2026-08-01 — not started.** Value **3/10** · Difficulty **3/10** · _fill-in_. One level of indirection (`getattr(os, "system")(...)`) walks past the `ambient-authority` rule even in strict block mode, and `phi-to-log` never opens the undecorated `_<feed>_transforms.py` helper the project's own Hybrid layout tells authors to put transform logic in.

**Cluster:** Security & Compliance. **Priority:** P3. **Verdict:** build (small). **Severity:** low.

**What:** Two execution-verified coverage holes in `_check_handler_security` ([`checks.py`](../messagefoundry/checks.py), ADR 0144), both still open at HEAD.

*(1) `ambient-authority` sees only a literal name chain.* `_ambient_authority_hit` (`checks.py:690-721`) matches a bare `ast.Name` against `_AMBIENT_BARE_NAMES` — `frozenset({"eval", "exec", "compile", "__import__"})` at `checks.py:464` — then falls through to `_dotted_call_name`, which by its own docstring returns `None` "when it is not a pure Name/Attribute chain (e.g. the receiver is itself a call or subscript)" (`checks.py:549-560`). `getattr(os, "system")("…")` is precisely that shape: the outer call's `func` is an `ast.Call`, and the inner call's `func` is `Name("getattr")`, which is in no deny-list. Measured, in **strict** mode:

```python
# <config_dir>/IB_T_handler.py
@handler("H")
def h(msg):
    getattr(os, "system")("whoami")          # line 7  — NOT flagged
    globals()["__builtins__"]["eval"]("1")   # line 8  — NOT flagged
    mod = __import__("subprocess")           # line 9  — flagged
```
```
_check_handler_security(cfg, strict=True)
# -> ok=False, required=True, "1 handler-security finding(s) … IB_T_handler.py:9 [ambient-authority]"
```

The opt-in Semgrep leg does not recover it either: `messagefoundry/security/semgrep/handler-security.yml:148-151` lists `eval(...)` / `exec(...)` / `compile(...)` / `__import__(...)` and no `getattr` pattern. ADR 0144:189-192 states this outright ("`getattr(os, "system")` remains a false-negative") — the defect is that nothing executable pins it, and the cheap resolution was never taken.

*(2) `phi-to-log` is decorated-scope only, which excludes the documented transforms helper.* The rule loop is gated by `if _message_fn_decorator(node) is None: continue` (`checks.py:921-934`), `_body_calls` refuses to descend into nested defs (`checks.py:762-778`), and `_message_fn_decorator` is `FunctionDef`-only so an `async def` handler is out too (`checks.py:536`). Measured, in **strict** mode:

```python
# <config_dir>/_feed_transforms.py   (undecorated — the documented Hybrid helper)
def xform(msg):
    log.info("transforming %s", msg.raw)
```
```
_check_handler_security(cfg, strict=True)  -> ok=True, skipped=True, "no handler-security findings"
```

ADR 0144:193-195 records the decorated-scope trade, but justifies it with an **`impure-transform`** false positive ("the trade that keeps the shipped `_pdf_mdm_transforms.py` timestamp fallback clean") and then applies it to `phi-to-log` as well. `samples/config/_demo_oru_transforms.py` and `_pdf_mdm_transforms.py` exist, [`docs/CONNECTIONS.md`](CONNECTIONS.md) §"Decomposing by role" tells authors to put field-level transform logic there, and #226 is an estate-wide sweep to do exactly that — so the one CLAUDE.md §9 rule the lint encodes systematically skips the file the convention steers PHI handling into.

**The third gap the audit named is narrower than described.** The non-recursive `base.glob("*.py")` at `checks.py:893`/`:898` (ADR 0144:196) is **not** an unscanned execution path. `load_config` globs `directory.glob("*.py")` non-recursively too (`config/wiring.py:3969`, and `:4392` for `validate_config`), and `_SiblingHelperFinder.find_spec` returns `None` for any dotted name and serves only `_`-prefixed top-level helpers from the config dir (`wiring.py:3902`, `:3908-3912`). A `.py` in a config subdirectory is therefore neither executed by the loader nor importable by a sibling — and `_assert_safe_config_source` is non-recursive for the same reason (`wiring.py:4194`, `:4324`). The lint's file set already equals the executable set. A recursive walk here would make the lint report on files the safe-source ownership gate never vets — an asymmetry in the other direction. #226 (`docs/BACKLOG.md:6917`) already parks recursion as a *loader* question; it belongs there, not here.

**Why:** Bounded, and bounded hard. The lint is advisory by default (`checks.py:953`, `ok=not strict, required=strict`), so a finding blocks nobody unless an adopter opts into `--strict-handler-security` on their own CI. It governs code the adopter's own administrator authors, inside a directory whose write access is already the trust boundary (`_assert_safe_config_source`, `wiring.py:4194`/`:4324`) — anyone who can drop a `.py` there already has arbitrary in-process execution under the engine account, so this is **not** a privilege boundary and evading it buys an attacker nothing they did not already have.

> ⚠️ **Rationale amended 2026-08-01 (ADR 0087 sandbox session) — the severity is right, the reason was not.** "The author already has in-process execution" is true at the **default** `[sandbox].mode=off`, and **false** under `mode=subprocess`, where the entire premise is that the author is *not* trusted with it. A severity floor resting on a posture-specific claim reads as settled and misleads the next reader. The rationale that holds in **both** postures: the lint is advisory and pre-deployment; under `mode=off` the author already has in-process execution, and under `mode=subprocess` an evasion still only reaches **host** actions the sandbox does not confine — `DEFAULT_FORBIDDEN_MODULES` (`pipeline/sandbox.py:84-95`) blocks `socket`, `ssl`, `asyncio`, `multiprocessing`, the I/O-bearing `messagefoundry.*` subpackages and `cryptography`, but **not `os` or `subprocess`** (verified at HEAD). ADR 0087 confines the **address space** (the child cannot reach the parent's DEK, audit chain or sockets), not the **host**; OS-level default-deny is ADR 0147, *Proposed with no code*. So an evasion reaches neither the DEK nor the audit chain in either posture. **Re-score upward when ADR 0147 lands**, at which point the lint becomes load-bearing for exactly the class OS confinement is meant to close. ADR 0144:171-174 and the `_check_handler_security` docstring (`checks.py:878`) both say so: "a filter, not a fix." There is no PHI-exposure path and no runtime behaviour change of any kind.

What it *is*: an adopter who turns on the strict gate gets a **green build** on a Handler containing `getattr(os, "system")`, and gets a green build on a transforms helper logging `msg.raw` at INFO. Gap (2) is the one that actually costs something, because the miss is not a malicious bypass — it is the ordinary fallible-author case ADR 0144 exists for, landing in the exact file the project's own layout guidance created. Gap (1) is mostly a claim-hygiene problem: the ADR asserts the false negative in prose and no test proves it, so nobody notices if a future change silently widens or narrows it.

**Proposed:**
1. **Resolve `getattr` on a known-dangerous root** in `_ambient_authority_hit` (`checks.py:690`): when the call's `func` is `getattr(<name-chain>, <const str>)`, splice the constant into the chain and re-run the existing predicate; when the second arg is **non-constant** on a root already in `_AMBIENT_ROOTS`/`_AMBIENT_OS_PATHS`, flag it directly (it is unresolvable statically, and that is the honest answer). ~15 lines, no new dependency, reuses `_dotted_call_name`.
2. **Widen `phi-to-log` past the decorated scope** — scan module-level functions in `_*.py` helpers (and nested defs inside a decorated body) for the same rule, keying on a parameter whose name matches the caller's message symbol or on `.raw`/subscript access. `impure-transform` stays decorated-scope: the ADR's stated FP rationale is specific to it, so widening only `phi-to-log` costs nothing against that rationale. Recalibrate against `samples/config/_demo_oru_transforms.py` + `_pdf_mdm_transforms.py` before landing.
3. **Pin both with tests** in `tests/test_checks_handler_security.py` — a positive for the `getattr` form and a positive for the undecorated-helper PHI log; today only the *negative* undecorated cases are pinned (`:205`, `:287`, `:298`), so the gaps are asserted in prose and nowhere in code.
4. **Update ADR 0144's residual list** (`:189-196`) as part of the same change: strike the getattr and decorated-scope-`phi-to-log` bullets when fixed, and rewrite the "Non-recursive" bullet to state *why* it is correct (the loader is non-recursive too) rather than listing it as a gap.
5. Optional: add a `getattr` pattern to `security/semgrep/handler-security.yml` for the opt-in taint leg, and fix the `_body_calls` docstring (`checks.py:763-766`), which claims "each nested def is scanned on its own iteration" — true only for a nested def that itself carries `@handler`/`@router`.

**Related:** [`messagefoundry/checks.py`](../messagefoundry/checks.py) (`_ambient_authority_hit`, `_check_handler_security`, `_body_calls`, `_message_fn_decorator`), [`messagefoundry/security/semgrep/handler-security.yml`](../messagefoundry/security/semgrep/handler-security.yml), [`tests/test_checks_handler_security.py`](../tests/test_checks_handler_security.py), [ADR 0144](adr/0144-security-lint-gate-over-admin-authored-router-handler-config.md) (this lint), [ADR 0087](adr/0087-sandbox-subprocess-isolation.md) + #197 (the runtime half — SHIPPED), [`docs/ADOPTER-CI.md`](ADOPTER-CI.md) (the operator control listing, line 178), [`docs/CONNECTIONS.md`](CONNECTIONS.md) §"Decomposing by role", #226 (the Hybrid-layout sweep, and the loader-recursion question).

**Source:** public-repo disclosure audit, 2026-08-01. ADR 0144 is honest and stays — the defect is what needs fixing.

---

---

## 338. TLS key-exchange groups are inherited, not pinned

> 🔢 **Filed 2026-08-01 — not started.** Value **3/10** · Difficulty **2/10** · _fill-in_. `harden_kex_groups` pins nothing on every interpreter this project supports, and after the 2026-07-29 correction sweep two surfaces plus #200's own ASVS roll-up still describe the engine's own contexts as having pinned/hardened key-exchange groups.

**Cluster:** Security & Compliance. **Priority:** P3. **Verdict:** build. **Severity:** low.

**What:** [`config/tls_policy.py`](../messagefoundry/config/tls_policy.py):150-152 returns without pinning whenever the API is absent —

```python
set_groups = getattr(ctx, "set_groups", None)
if set_groups is None:
    return None
```

`SSLContext.set_groups` is a **Python 3.15** addition, so on this tree (3.14.6 / OpenSSL 3.5.7) `hasattr(ctx, "set_groups")` is `False` and `APPROVED_KEX_GROUPS` (`tls_policy.py`:89) reaches **zero** of its six call sites — [`api/tls.py`](../messagefoundry/api/tls.py):55, [`transports/mllp.py`](../messagefoundry/transports/mllp.py):543 and :582, [`transports/dicom.py`](../messagefoundry/transports/dicom.py):145 and :463, [`transports/remotefile.py`](../messagefoundry/transports/remotefile.py):213. Every built context inherits OpenSSL's default group list. Re-measured 2026-08-01 against the real `build_api_ssl_context`, at both `tls_min_version` 1.2 and 1.3 (identical results):

```
approved     = {'X25519': True, 'secp384r1': True, 'prime256v1': True}
non_approved = {'ffdhe2048': True, 'ffdhe3072': True, 'secp521r1': True,
                'secp224r1': False, 'sect571r1': False}
```

**The code and the primary docs are already honest about this.** The 2026-07-29 correction sweep fixed the docstrings (`tls_policy.py`:11-15, :114-148), [`PHI.md`](PHI.md):638 (now scored `[PARTIAL — … the group pin is INERT until Python 3.15]`) and :648-655, [`ASVS-L2-PHASE0-CHANGES.md`](ASVS-L2-PHASE0-CHANGES.md):230-231, and struck §4(b) of [ADR 0092](adr/0092-posture-keyed-transport-hop-refusal-refuse-the-insecure-phi-hop.md):170-172 with an amendment at :215-247. Three restatements survived it:

1. [`CONTAINER-EXPOSURE-EVALUATION.md`](CONTAINER-EXPOSURE-EVALUATION.md):50 — under a heading that reads *"What is actually built (verification, not re-derivation)"*, the `build_api_ssl_context` row's **Confirmed behavior** cell says `optional ciphers, hardened KEX groups + strict X.509`, unqualified. This is the strongest surviving instance: the column asserts verification.
2. `BACKLOG.md`:6416 — #200's `**Closes (ASVS 5.0 L3):** 4.2.1, 4.4.1, 11.6.2, …` still claims 11.6.2 closed, while `PHI.md`:638 scores the same cell PARTIAL. #200's banner at :6412 carries the correction, so the item contradicts itself two lines later.
3. `ASVS-L2-PHASE0-CHANGES.md`:253 — the PQC migration row says *"add it to the pinned group/cipher policy"*, presupposing a pin.

Separately: the docstring argues *"the return value is the point"*, but all six call sites discard it, so the report exists only in tests. `SecurityPosture` already carries a report-only read-out sourced from this same module (`api/app.py`:1528, `fips_attestation()`), and carries nothing for KEX groups.

**Why:** the residual is **wider than policy, not weak**, and this item is documentation accuracy plus observability — not a transport weakness. Every group that gets in is forward-secret; `ffdhe2048`/`ffdhe3072`/`secp521r1` are the whole delta, and the genuinely weak `secp224r1` (112-bit) and `sect571r1` (binary-field) are refused. The forward-secrecy property ASVS 11.6.2's first clause is about comes from the enforced TLS 1.2+ floor, and `harden_cipher_suites` (`tls_policy.py`:334-364) **raises** on any non-forward-secret suite at every one of the same six sites — so nothing here admits static RSA/DH. There is no exploit path: an attacker cannot downgrade to anything the floor does not already permit; the only reachable effect is a *client* choosing a still-forward-secret group outside the preferred three. It is immaterial on the default `127.0.0.1` bind, where no TLS is presented at all. The cost of leaving it is a reader of `CONTAINER-EXPOSURE-EVALUATION.md` §0 or of #200's Closes line concluding the pin is enforced and not looking again — which is exactly how the "3.13+" error survived three assessments.

**Proposed:**
1. Correct `CONTAINER-EXPOSURE-EVALUATION.md`:50 to say the groups are **inherited** (attempted pin inert until Python 3.15) and point at `PHI.md` §4 rather than restating the measured set — per CLAUDE.md §11, state it once and link.
2. Reconcile the ledger: drop `11.6.2` from #200's Closes line at `BACKLOG.md`:6416, or annotate it to match `PHI.md`:638's PARTIAL score. Two ledger surfaces must not disagree on one ASVS cell.
3. Reword `ASVS-L2-PHASE0-CHANGES.md`:253 to "the approved group/cipher policy".
4. Consider an additive report-only `kex_groups: str | None` on `SecurityPosture` fed by the discarded `harden_kex_groups` return (same shape as `fips_mode`/`openssl_version`, `api/app.py`:1528) so the inertness is operator-visible, not test-only. Additive → a `_ui_seam` bump.
5. **Do not delete or relax the tripwires.** `tests/test_tls_policy.py`:117 asserts the `None` unconditionally and `tests/test_api_tls.py`:1278 measures the accepted-group set with an assertion at :1318 that a non-approved group *does* get in. Both go red the day an interpreter grows the API — that red **is** the "re-evaluate when 3.15 lands" trigger, so no dated review is needed. Their failure messages already name the docs to re-derive.
6. **Do not** substitute `set_ecdh_curve`. It takes exactly one OpenSSL curve short name, so pinning through it would refuse two of the three approved groups (`tls_policy.py`:139-148 records the trap, including that `secp256r1` is a valid group-list alias but not a valid curve name — the curve spelling is `prime256v1`).

**Related:** [`config/tls_policy.py`](../messagefoundry/config/tls_policy.py) `harden_kex_groups` / `APPROVED_KEX_GROUPS` / `harden_cipher_suites`; the six call sites listed above; [ADR 0092](adr/0092-posture-keyed-transport-hop-refusal-refuse-the-insecure-phi-hop.md) 2026-07-29 amendment; [`PHI.md`](PHI.md) §4; [`ASVS-L2-PHASE0-CHANGES.md`](ASVS-L2-PHASE0-CHANGES.md) §*TLS key-exchange & cipher posture*; [`Secure_Development_Standards`](Secure_Development_Standards.md) §3 (this defect is its worked example); `tests/test_tls_policy.py`, `tests/test_api_tls.py`; #200 (closed — its Closes line is fix (2) above; amending a closed item's prose is fine, but it must not gain an OPEN banner).

**Source:** public-repo disclosure audit, 2026-08-01. Re-verified and re-measured at HEAD on the same date.

---

## 340. Enable a GitHub merge queue: strict + no queue makes every merge a race that fails silently

> 🔢 **Filed 2026-08-01 — not started.** Value **8/10** · Difficulty **3/10** · _fill-in_. `strict = true` with no merge queue and a ~20-minute suite means a PR must go green *and* have `main` hold still, or it flips to `BEHIND` and stops. Measured this date: **9 open PRs green (0 failing, 0 pending) and none able to merge**, 6 with auto-merge armed that will never fire.

**Cluster:** Developer Experience & CI. **Priority:** P2. **Verdict:** build. **Severity:** medium.

**What:** branch protection on `main` sets `required_status_checks.strict = true` — a PR must be up to date with the base to merge — and the repo has **no merge queue** (`repository.mergeQueue` is null; `allow_auto_merge` is true). The slowest required leg runs ~20–25 minutes. Those three facts compose into a race: a PR is mergeable only in the window between its checks going green and the next thing landing on `main`.

Losing that race is **silent**. Armed auto-merge does *not* update a `BEHIND` branch — it waits on checks that already passed — so the PR sits armed and stalled with no failing check, no notification, and no run in flight. Measured 2026-08-01:

```
PR     mergeState  failing  pending  auto-merge
#128   BEHIND      0        0        ARMED
#125   BEHIND      0        0        ARMED
#107   BEHIND      0        0        -
#106   BEHIND      0        0        ARMED
#101   BEHIND      0        0        ARMED
#96    BEHIND      0        0        ARMED
#71    BEHIND      0        0        ARMED
#60    BEHIND      0        0        -
```

(Nine at the hand survey; eight when [`check_stalled_prs.py`](../scripts/ci/check_stalled_prs.py) ran ~20 minutes later, because #120 had been re-synced in between. The set moves — the condition does not.)

Two worked instances the same day. **#74** went green on 2026-07-30 and sat unmergeable until 2026-08-01, found only by someone hunting "stuck CI" by hand; it took three merges from `main` to land. **#119** was green with 25 passing checks and armed, stalled, was re-synced, and lost the window again — on two separate heads its last required check completed *after* another PR had already merged (by 2m11s on `2a2900cb`, by 2m38s on `8c407fb5`), so it was never simultaneously green and up to date. A hand-coordinated merge freeze was declared across the parallel sessions and did **not** hold `main` still: `main` advanced four times between #119's first fully-green head and its merge, one of those 8m26s after the freeze was recorded in a work claim. #119 did land in the end, at 2026-08-02T01:45:00Z, 12h15m after auto-merge was armed. That is the evidence that hand coordination is not the fix.

**Why:** the cost is finished work sitting undelivered while everyone believes it is landing. This is the repo's recurring defect shape — a signal accurate about what it looks at and silent about what it does not ([`Secure_Development_Standards`](Secure_Development_Standards.md) §3) — but the worst variant, because every other instance has *someone waiting on a result*. Here the author already had their full pass and has no reason to look again. It also scales the wrong way: the more sessions working in parallel, the more often `main` moves, so the race gets harder to win exactly as throughput rises.

**Measured cost, re-derived 2026-08-02.** The first account of this instance was wrong in every load-bearing figure, and a peer caught it rather than its author — so every number below is re-derived from the Actions API and carries its unit.

*One worked instance.* #132 dispatched **nine CI runs — ten attempts — across eleven head moves** in a 3h28m open window. `main` moved **five times** underneath it. Five of the eleven head moves were rebases, four of them onto a tip that had landed 1–14 minutes earlier; **four runs were cancelled in flight** by `ci.yml`'s `cancel-in-progress` concurrency when a newer push superseded them. Cost: **212.7 min of run wall-clock**, or **442.5 min of job wall-clock** summed across matrix legs — the two differ by 2.08x, so neither is meaningful without its unit, and neither is *billable* minutes (`/timing` reports 0 billable ms on every run; these legs are self-hosted, so no billable figure exists to quote). Note what this instance is **not**: two of its attempts failed on real defects — one of them on the very head it opened at — so it is not a change that was right on the first pass and re-run anyway. The cost that generalises is the four superseded runs and the four rebase-driven re-runs — the ones that carried no new information about the change.

*The general form.* N ready PRs become N sequential suite-length cycles, because each merge invalidates every other. `main` moved **22 times on 2026-08-01**. Re-measured 2026-08-02T04:10Z: **0 of 14 open PRs were `CLEAN`** — not one could merge. Nine were green (0 failing, 0 pending) and stopped only by staleness or conflict; separately, nine of the fourteen carried armed auto-merge that could not fire. The cohort tabulated above **did not drain**: all eight are still open, and #96 has now been armed 39h at 26 commits behind. Re-read **nine hours later at 13:25Z** — 15 open, 10 armed, still **0 `CLEAN`**. The membership churns constantly; the condition has not lifted once.

*It is also a measurement cost, which is how this joins #344.* Supersession-and-re-run turns this population into one that **two different filters prune in two different ways**, and a margin read off either without naming it is not a margin. Filtering by **job** conclusion deletes rows where the job was cancelled but the *step* succeeded — the tightest rows, by construction, because a step near the cap is exactly what pushes its job past the job cap. The default **latest-attempt** view (`actions/runs/{id}/jobs`, `gh run list`) instead hides *failed earlier* attempts; it does not move a step-success maximum, but it conceals that the sample is **right-censored** — the largest step observable is the largest that *fit* under the cap, never the largest the suite wanted. Read `?filter=all` to see the censoring, and key on the **step's** own conclusion, not the job's.

*The readiness signal cannot be distinguished from its own absence.* Re-measured 2026-08-02T13:41Z: of 14 open PRs, **9 carried armed auto-merge and 6 of those were inert** — five `BEHIND`, plus #71 armed *and* `DIRTY`, which cannot land at all. **Zero armed PRs were `CLEAN`.** Every session here reads `autoMergeRequest != null` as *"this will land"* — the author of this paragraph did exactly that about their own PR an hour earlier — when for two-thirds of them it means *"this waits until a human runs `gh pr update-branch`"*, with nothing reporting the difference. That is what lifts this item out of efficiency and into correctness: *"merges are slow"* has a **"then be patient"** answer; *"the merge-readiness signal is unfalsifiable from outside without a second query nobody runs"* does not. Same defect class as ADR 0158's — a green signal that means nothing — observed live rather than in retrospect.

*The largest cost is protocol, not throughput.* With no queue, sessions invent an ordering ritual to compensate — and the ritual is less reliable than the mechanism it replaces. Self-reported instance from the same night: a session assured a peer it would not jump the queue **while its own PR had auto-merge armed** and would have landed with nobody deciding anything. [`WORKTREES.md`](WORKTREES.md) already names that failure — *"'Don't do X' is the wrong primitive when automation already has X armed"* — and that session had read the line, about this very freeze, hours earlier. Effort spent negotiating a merge order is effort a queue spends for free, and it is where the night's stale facts and unenforceable promises came from. Wall-clock a reader can dismiss as impatience; this is not that.

**What a merge queue does not fix.** Stated level with the cost, because filing an overclaim inside the ticket about overclaiming would be its own instance:

- The overnight run of eight merges was strictly serialized (min gap 26m06s, mean 35m16s over 7 gaps) — but **serialization is not evidence that hand coordination worked.** It is entailed by `strict = true` plus a full-suite cycle, human or no human. `strict` also does not always serialize: #110 and #111 merged **24 seconds apart** on 2026-08-01, #111's squash commit parented directly on #110's. That mechanism is **not established** — only the timestamps and the parentage are.
- A queue does not shorten the suite. It reorders the same cycles; the wall-clock bounds tracked in #344 are untouched by it.
- **A queue would not report at all today.** Measured 2026-08-02: **no workflow under `.github/workflows/` carries a `merge_group:` trigger**, against 13 required contexts in branch protection — so by the mechanism step 2 describes, zero of them would report. Enabling the queue before step 2 lands would wedge every open PR. Step 2 is a precondition, not a follow-up.

**Proposed:**
1. Enable a merge queue on `main` (branch protection → *Require merge queue*), squash method to match the existing history.
2. Reconcile the required set against it: a queue runs checks on a `gh-readonly-queue/**` ref, so any workflow that must gate the queue needs a `merge_group:` trigger. Every context in [`.github/required-contexts.txt`](../.github/required-contexts.txt) lacking one will never report there — that file's own required-but-absent trap, in a new place.
3. Decide the interaction with `strict = true`. A queue makes it largely redundant; leaving both on is safe but keeps the re-sync burden for anything bypassing the queue.
4. Once landed, [`check_stalled_prs.py`](../scripts/ci/check_stalled_prs.py) goes quiet on its own. Keep it — it is the detector for this class returning.

**Related:** [`scripts/ci/check_stalled_prs.py`](../scripts/ci/check_stalled_prs.py) + [`.github/workflows/stalled-prs.yml`](../.github/workflows/stalled-prs.yml) (built alongside this filing — it reports the condition, it does not remove it); [`.github/required-contexts.txt`](../.github/required-contexts.txt); [`scripts/ci/check_required_workflow_state.py`](../scripts/ci/check_required_workflow_state.py) (sibling: "can this context ever report?" to this one's "can this PR ever merge?"); #344 (the wall-clock bounds that killed one of #119's runs, and the sibling half of the measurement cost above); #320.

**Source:** stuck-CI triage, 2026-08-01. Measured live against `MEFORORG/MessageFoundry` branch protection and the open-PR set that date; independently reached by three parallel sessions from separate evidence. Cost evidence and both corrections above re-derived from the Actions API on 2026-08-02 under adversarial verification, after the first hand account of #132 proved wrong in every load-bearing figure.

---

## 344. Fixed wall-clock bounds have drifted out of proportion to the work they bound

> 🚧 **Status 2026-08-02 — PARTIAL: instances 1 and 3 fixed, instance 2 open.** Value **6/10** · Difficulty **4/10** · _fill-in_. Hardcoded real-time budgets — a CI `step_timeout`, a CI `job_timeout`, a test helper's poll deadline — were sized when the work was smaller or the machine faster, and nothing re-derives them. Three confirmed instances; each presents as an unrelated flake.

**Cluster:** Developer Experience & CI. **Priority:** P2. **Verdict:** build. **Severity:** medium.

**What:** a fixed wall-clock bound with no relationship to the work it bounds fails the day the work grows, and it fails as a **timeout with zero assertion failures** — which reads as a broken branch when nothing is broken.

*Instance 1 (fixed 2026-08-01, this filing).* `ci.yml`'s Windows `step_timeout: 26`. windows-2025's max PASSING `Tests (pytest)` step was **25:51** — a **1.006x** margin, nine seconds — and PR #119 was killed at 26:07 with zero test failures after #74 added a 1,506-line test file. The comment beside the cap asserted "~2x headroom", a figure that matched no leg. Raised to 36:00 (1.393x) with the measurement, its pool and its date recorded in place of the multiple. Pool: every `ci.yml` run created 2026-08-01 UTC — 70 runs, per-leg n = 42 ubuntu / 39 windows-2022 / 36 windows-2025 — timing the STEP and filtering on the STEP's own conclusion. That pool is **right-censored**: it predates the raise, so every observation survived a 26:00 cap and 25:51 is a *lower bound* on what the suite wants. Confirmed the next day, once the cap no longer censored it: windows-2025 produced **26:23 twice, both passing** — runs that the old cap would have killed. The API hides this by default: the jobs endpoint returns only the latest attempt, so a step killed at the cap is invisible behind its passing re-run unless you ask for `?filter=all`.

*Instance 2 (open).* `tests/test_stage_dispatcher.py`'s `_wait_until` (:356) polls `loop.time()` against a hardcoded **8.0s** budget while the dispatcher under test is driven by an injected `ManualClock`. On PR #129 — whose diff is provably AST-identical to main, docstrings only — `test_adr0070_9_content_retry_is_not_an_infra_fault[sqlserver]` failed on that bound alone against a Dockerised SQL Server; every logic assertion in the same loop passed. A real-time deadline gating a virtual-clock system has no principled value.

*Instance 2, RE-DIAGNOSED 2026-08-02 — and the original diagnosis was wrong.* It recurred on PR #138, on a different test (`test_adr0070_1_stop_policy_bounds_deterministic_infra_head[sqlserver]`, run 30733129076), and the timings refute "the bound is too small": the failing test took **8.185s**, i.e. `_wait_until` burned its full 8.000s and setup+teardown cost 0.185s — the store was *fast* at the moment of failure. In the same process, against the same container, the sibling `test_adr0070_1_retry_forever_never_stops_alerts_stuck[sqlserver]` drove **seven** identical fault cycles in **0.364s**, and the `[sqlite]` variant of the failing test passed in 0.144s. One fault cycle costs ~30-45 ms against an 8000 ms bound. Over a sample of green sqlserver jobs this test passes in min 0.185s / median 0.196s / max 0.204s, so the bound is ~39x its worst passing run; a wider 21-day pass put the worst passing observation at 0.576s, still ~14x. Rate: 2 failures in ~479 observations of the two affected tests (~0.4%), **zero** on postgres (119 observations) and zero across 1,105 sqlite executions. Both failures sit ~7x beyond the entire passing distribution — a gap, not a tail, which is the signature of a categorically different event rather than latency creep.

**This instance therefore inverts the item's own generic remedy, and that is the useful part.** "Size the bound against the work" (proposal 2) would derive ~1-2s here — *tighter* than the 8.0s already in place. There is no larger number to justify. Raising it would convert a 0.4% visible failure into a 0.4% invisible 30-60s pause. **What is settled is the negative: not latency, and the remedy is not a bigger number.**

What is NOT settled is the mechanism. Two independent passes reached different answers — one proposes a sanctioned EMPTY claim dropping the lane to IDLE, terminal because these tests deliberately disable the production sweep (`lane_provider=set()`, `sweep_interval=3600`) that recovers it; the other returned NOT PROVEN, and is right that the evidence cannot distinguish that from a genuine stall, because the assertion is a bare `assert await _wait_until(...)` that prints only `assert False` — recording no phase, no park deadline, no streak, no task state. **The first fix is observability, not a bound** (proposal 6): a failure that cannot say why it failed will be re-diagnosed wrongly every time, which is exactly what happened here.

*Instance 3 (fixed 2026-08-02).* The same `ci.yml`'s `job_timeout`, sized by a `+4`-over-`step_timeout` convention nobody ever summed against what it had to hold. **Two** steps in that job carry `step_timeout` — `Tests (pytest)` and `Web console tests (pytest)` — so the job must cover their sum plus setup, a quantity `step_timeout` cannot bound. Recomputed from measured maxima, ubuntu stood at **−0:20** and windows-2025 at **−0:53** against their own caps: both already underwater, unnoticed because the bound was derived from the other bound instead of from the work. It presents as a **green first step followed by an unattributed job-level kill** (run `30724385719`: `Tests` 25:51 SUCCESS, then the job cancelled at 30:13) — a signature instance 1's proposed step-level margin check would *not* catch, because the step it measures passed. Raised to 26:00 / 46:00. **Still open underneath:** the nesting invariant `ci.yml` asserts holds for the first gated step and for the second on *no* leg, since reaching it already spends setup plus `Tests`; satisfying it would need `job_timeout` past 39:24 (ubuntu) / 73:21 (Windows). The fix is proposal 5.

*A note on this item's own measurements.* Instance 1's figures have now been published wrong twice — first as 24:35 over "11 passing runs" (a `gh run list` default page, filtered on the **job's** conclusion while timing the **step**, which deletes the tightest rows by construction), then as the right maxima over "101 runs" with an `n` that no pool definition reproduces. The maxima survived both passes; the *pools* did not. An item about bounds stated independently of the work is an uncomfortable place to state a sample size independently of the sample, so: the pool is named in instance 1 and is recomputable from the API in one query.

**Why:** these fail *individually blameless*. The remaining CI margin is a **shared budget nobody accounts for** — three PRs each adding a minute of Windows time reproduce #119's death, with no single PR at fault. And this repo has twice mislabelled such a failure: the two famous "flakes" turned out to be a livelock and a test that was right. A timeout with no failing assertion is the exact signature that invites the wrong diagnosis.

**Proposed:**
1. **A mechanical margin check** (suggested by the ASVS-scorecard session, whose framing this is): compare each leg's actual `Tests (pytest)` step duration against its configured `step_timeout` and fail below ~1.3x. Computable from data CI already emits. It would have flagged windows-2025 *before* #119 died — it was already at 1.006x and nothing said a word — and unlike the "re-check the margin when the suite grows" instruction in `ci.yml`, it does not depend on anyone remembering. **The case for a computed gate over an instruction is now evidential, not a matter of diligence.** Across the 2026-08-01/02 CI-triage cluster, *seven* published claims were retracted — margin figures, pool sizes, "#119 died", "26:07 does not exist", a runner count read off an endpoint that cannot see org runners. Not one was caught by re-reading. Every one was caught by a mechanism that could return "no": an adversarial re-derivation, an independent query, or an assertion. The single error its own author caught was found by running exact arithmetic over all fifteen ratios in a block, not by looking at them again. **Re-reading confirms what you meant; only a check can test what you wrote** — and as a method it is 0-for-7 here. Three traps for whoever builds it: time the **STEP**, not the job (the job is ~3 min longer with its own cap — `c53f752b`'s job ran 28:41 and passed against job cap 30 / step cap 26, and two sessions misread job for step while triaging this); and size against the **max passing** run, not the mean (windows-2025's mean ~21 min looks comfortable, its max passing 25:51 is what bites); and treat that max as a **lower bound**, because the pool is censored by whatever cap was in force when it was collected — the runs that would have exceeded it were killed, so they are missing from exactly the tail you are trying to measure.
2. Size the remaining bounds: `grep` hardcoded `timeout=` / deadline floats under `tests/` and judge each against the work it bounds.
3. ~~Where a virtual clock drives the system under test, the poll deadline should follow that clock, not `loop.time()`.~~ **WITHDRAWN 2026-08-02 — this proposal was wrong and would have made things worse.** `_wait_until` waits on real asynchronous I/O (store round-trips), never on virtual time, and `ManualClock.now` advances *only* inside `advance()`, which nothing calls from within the poll loop. A `mc.now + timeout` deadline is therefore never reached: the poll spins forever, converting a bounded `assert False` into an **unbounded hang** stopped only by `pytest_timeout` or the job cap — i.e. it manufactures the exact signature instances 1 and 3 are about. Verified by reading `ManualClock` (`tests/test_stage_dispatcher.py`:182-204). The lesson generalises: *a virtual clock can only bound work the virtual clock drives.*
4. Prefer bounds expressed as a measured ratio with a date **and its pool** over round multiples, per instance 1's post-mortem. A ratio whose pool is not stated cannot be rechecked, and a pool stated but never recomputed is how instance 1 was published wrong twice.
5. **Stop two steps sharing one `timeout-minutes` budget.** Give `Web console tests (pytest)` its own cap sized to its own work (max observed 3:33) so `job_timeout` no longer has to absorb a budget that belongs to a step. Until then the nesting invariant `ci.yml` asserts is unenforceable for the second gated step on every leg — instance 3 is the worked example.
6. **Make a bound's expiry diagnostic before tuning it — and for instance 2 the instrument already ships.** A bare `assert await _wait_until(...)` reports `assert False` and nothing else, so every occurrence is re-diagnosed from scratch; instance 2 was read as latency for a day on exactly that basis. Have the helper raise on timeout carrying the lane's phase, park deadline and streak, whether its task is alive or holds an exception, the store row's status, and the clock. **One assertion settles instance 2's open mechanism:** `StageDispatcher.empty_claims` ([`stage_dispatcher.py`](../messagefoundry/pipeline/stage_dispatcher.py):1230) returns `(total, wake_fanout, idle_poll)` and is fed by `_record_empty`, called from exactly one site — the EMPTY branch of `_claim_and_dispatch` (:686). Under these tests' topology a clean run must read `(0, 0, 0)`, so `empty_claims[0] > 0` at the moment of failure is proof of a spurious EMPTY, and `== 0` is proof the claim never returned at all. A second, free signature is already in the captured log: a healthy run emits **four** `re-pending head with backoff` records (at `1001.000 / 1003.500 / 1008.000 / 1016.500`); the failing run emitted **one**. This proposal cannot itself be wrong about the cause, which is why it comes before the others.

**Related:** [`.github/workflows/ci.yml`](../.github/workflows/ci.yml) §*Tests (pytest)* (instance 1 and its measurement table); `tests/test_stage_dispatcher.py`:356 (instance 2); #320 (windows-2025 slowness — the capacity fact that shrinks every Windows margin); #340 (the other half of this triage); [`Secure_Development_Standards`](Secure_Development_Standards.md) §3 (prose asserting a margin the numbers do not support — five instances found on 2026-08-01 alone).

**Source:** stuck-CI triage, 2026-08-01. Instance 1 re-measured 2026-08-02 across 36 step-success windows-2025 rows (pool: 70 `ci.yml` runs created 2026-08-01 UTC), by two agents deriving it independently after the first two measurements both reported pools that did not reproduce; instance 2 reported and diagnosed by the HA-construct-recheck session from PR #129's sqlserver leg; instance 3 from the same 2026-08-02 re-measurement.

---
