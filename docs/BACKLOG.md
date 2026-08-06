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

## Ranked backlog — value × difficulty on a ten-level scale (re-scored 2026-08-03)

> **What this pass is, and what it replaces.** Every one of the **102 open items** is re-scored here
> against the code as it stands on 2026-08-03. The 2026-07-10 table below is kept as the record of
> that pass and is **superseded** by this one: it scored 134 items, ~40 of which have since closed,
> and its frozen distribution lines were never recomputed. The closed items it ranked now live in
> [`archive/backlog/BACKLOG-CLOSED.md`](archive/backlog/BACKLOG-CLOSED.md) with their banners intact.
>
> Method, unchanged from the pass it supersedes: scored from each item's own `Scope` / `Why` /
> `Trigger` / `Nearest existing mechanism` text rather than rescaled from the old number, then
> **adversarially verified against the repository** — a second reader per batch attacking build state
> first, then verdict/tier, then value and difficulty. **26 of 92 scores were overturned** by that
> pass and carry the refuter's number.
>
> **Value is worth-if-built, independent of schedule.** Scheduling is expressed only by the tier, and
> an item whose named trigger has not fired stays `DEMAND-GATE` however high it scores — read from its
> own `**Verdict:**` line. Only **two** tiers moved: **#64** DEMAND-GATE → P3 (an index over levers
> that live in other items, so it ships nothing runnable of its own) and **#105** P3 → DEMAND-GATE.
>
> ⚠️ **24 items were found to misdescribe their own build state** — prose asserting a gap that has
> since shipped, or citing `messagefoundry/console/`, a package retired with #103. Those are banner
> corrections, tracked separately from the scores; the scores here already price the *remainder*.
>
> The per-item `🔢` banner is the live record. This table is a view of it, and where the two disagree
> the banner wins.

**Distribution.** Recomputed from the table below, not carried forward.
Value: **1**:3 · **2**:9 · **3**:19 · **4**:16 · **5**:23 · **6**:29 · **7**:7 · **8**:2. Difficulty: **1**:4 · **2**:22 · **3**:39 · **4**:23 · **5**:6 · **6**:9 · **7**:2 · **8**:2 · **9**:1.
Tiers: **P1** 8 · **P2** 25 · **P3** 22 · **DEMAND-GATE** 53.
Quadrants: _quick win_ 33 · _big bet_ 5 · _fill-in_ 61 · _money pit_ 9.

*All four lines sum to 108, the open-item count. They are recomputed with the table,
never carried forward — a stale census reads exactly like a current one.*

Ordered by value descending, then difficulty ascending (cheapest first at equal value).

| # | Item | Title | V | D | Quadrant | Tier | Why |
|--:|---|---|--:|--:|---|---|---|
| 1 | **#1004** | ASVS 13.3.4 — the store DEK's calendar expiry alerts and never refuses; build the enforced stop with a loud opt-out | 8 | 4 | _quick win_ | P1 | The DEK's usage axis refuses unconditionally at 2**32 (`store/crypto.py:135`, raise `:683-688`) while its calendar axis only alerts (`pipeline/secret_rotation.py:341-351`), so the annual cadence the shipped docs promise (`docs/ASVS-L2-PHASE0-CHANGES.md:141,147,151`) is unenforced and ASVS 13.3.4 sits `partial` on defaults; owner-decided 2026-08-04 to build, and the remainder is one exception plus one function plus a call site sited *outside* the blanket `except Exception` at `pipeline/engine.py:1062` whose entire body is `log.exception` (`:1065-1067`), one `[secret_rotation]` boolean defaulting ON, a `security_loosenings()` entry, and a paired vault scorecard change that must ride the same act because the build makes the cell's absence claim false and reds the drift gate (`scripts/asvs/scorecard.py:387,409-413`). |
| 2 | **#1005** | CRL checking of partner client certs on the mTLS-terminating listeners (ASVS 12.1.4 band B1) | 8 | 5 | _quick win_ | P1 | Three mTLS-terminating listeners require and verify a partner client cert and none checks revocation, so a revoked credential would authenticate to a PHI interface until its notAfter on first deployment with no in-engine workaround; cheap in code but fail-closed by construction, with two measured failure modes that turn a careless build into an every-partner outage. |
| 3 | **#321** | Leak gate is blind to the ported-estate site-code and partner-product token class | 7 | 3 | _quick win_ | P2 | A required merge context exited 0 on content carrying a real site code and a partner product name, with no compensating control (`scan_forbidden.py:10-12` is explicit that gitleaks finds secrets, not this class) and nothing stopping the next estate-derived identifier landing the same way; `.md` is not in `_SITE_SKIP_SUFFIXES` (`scan_forbidden.py:119`, `{".lock", ".svg"}`) so the file was scanned — the fix is owner-run token data across the private file plus the Actions *and* Dependabot secret stores, a negative test per class, and optionally a structural shape backstop. |
| 4 | **#1000** | Prove each required merge context can fail: negative controls for the gates that block merge | 7 | 3 | _quick win_ | P1 | Thirteen contexts are the entire merge gate and not one is proven able to go red, a class that has fired at least four times here (#334, #327, #321, #325) with no CI signal and each caught by hand; the build is a negative-control fixture per context plus a job that fails when one has none, no new dependency and no change to what the gates check. |
| 5 | **#1010** | No licence-header gate exists in any language, and 196 first-party sources carry no SPDX tag | 7 | 3 | _quick win_ | P2 | AGPL-3.0-or-later is asserted in LICENSE and pyproject and then left to habit per file: 196 of 1,181 tracked sources across six languages carry no SPDX tag, 17 of them in a package the wheel ships, five more declare the wrong licence, and no hook, workflow or test checks a header in any language. |
| 6 | **#1003** | Validate the lab and discharge the four hardware-gated residuals | 7 | 4 | _quick win_ | P2 | Four items (#99, #98, #320, #351) are parked on one missing multi-VM lab and each asserts a premise that expires when it lands, so the alternative to running them is four items telling every planning pass they are unreachable; the runs are already specified by the items they discharge and need no new design, but the lab itself has to be stood up and proven against what each residual actually requires. |
| 7 | **#1013** | The `[auth] enabled=false` startup arm keys on the bind alone, so auth-off behind a declared terminator still starts | 7 | 4 | _quick win_ | P1 | The auth-off arm (`__main__.py:1112`) tests `not settings.auth.enabled and not settings.api.is_loopback`, so it does not fire for a declared TLS-terminating proxy — a PHI instance with authentication entirely OFF behind a declared terminator starts with no refusal and no warning, while the same topology with auth ON but MFA off is refused by the gate #326 fixed. Value one above **#326** (6/3, P2): that was single-factor admin, this is no factor at all, and the two arms disagree about what "exposed" means in the same file. Difficulty 4 not 3 because the remedy is UNPROVEN — `instance_exposed` is defined 805 lines BELOW at `:1917`, so the arm cannot reference it without hoisting, and whether the settings it reads are resolved that early in the startup ladder is the actual work. (Anchors re-derived at `17374679` now that #326 has merged; the pre-#326 figures were `:1080`, `:2368` and 1,288 lines.) |
| 8 | **#1015** | OIDC relying party keys federated accounts on a reassignable username claim while the non-reassignable `sub` is discarded (ASVS 10.5.2) | 7 | 4 | _quick win_ | P1 | The RP keys federated identity on `oidc_username_claim` (default `preferred_username`), which an IdP may reassign, while the non-reassignable `sub` is verified and then dropped into an audit field — so on first deployment a new holder of a retired username would be handed the prior holder's account. Value matches **#1013** (7/4): both are auth-gate defects that admit an unauthenticated or wrong principal, and this one is more conditional (needs an IdP reassignment) but lands on an existing account rather than an empty one. Difficulty 4 and no migration cost, because there are no deployments to migrate (section 0) — key on `sub`, keep the username as a display attribute. |
| 9 | **#318** | DAST — authenticated dynamic security testing of the running engine | 7 | 6 | _big bet_ | P2 | Increment 1 genuinely closed the §6.1 Dynamic row on the HTTP plane (`scripts/security/dast_auth_sweep.py`, `scripts/security/route_gates.py`, `.github/workflows/dast.yml` all present), but the unauthenticated MLLP/raw-TCP/X12 ingress — the one attacker-reachable surface — has no dynamic coverage and no mutator to extend, and a red nightly still notifies nobody (`.github/workflows/nightly-notice.yml:24` watches only `workflows: ["CI"]`); the remainder is a protocol fuzzer, an OpenAPI security overlay behind a fifth DEP-1 lock, a TLS black-box target and the `/ui` plane — cross-cutting and CI-gated. |
| 10 | **#325** | Leak gate's home-path detector is case-blind on Windows paths | 6 | 2 | _quick win_ | P1 | A structural detector in a required merge context — the one control meant to work in a fork with no token source — fires on one of four spellings of the same Windows home path (`_HOME_PATH` compiles with no flags and matches a literal `Users`, `scripts/security/scan_forbidden.py:99-106`), against the module's own "fail toward more detection" rule, though the disclosure is an OS account name and the tree holds zero live hits; an inline `(?i:)` on the drive-letter arm only (whole-pattern `re.I` measured 47 false positives), the sibling two-character `_WORKTREE_SLUG:92` edit, and casing fixtures beside the sole canonical-case test at `tests/test_scan_tokens_source.py:559-577`. |
| 11 | **#327** | No test asserts the private-path `.gitignore` block still ignores anything | 6 | 2 | _quick win_ | P1 | Six `.gitignore` rules are the sole control keeping maintainer-internal security material out of a public commit since the publish deny-list was retired, and the repo-wide search for `check-ignore` matches exactly one hand-run script (`scripts/dev/setup-leak-gate.ps1:58`) covering a different file, so the boundary is defended by review attention plus a hook that lives inside the now-ignored `/.claude/` tree and no fresh clone gets; a pinned-literal test with a synthetic probe child, plus dropping `^\.gitignore$` from the `noncode` allowlist at `.github/workflows/ci.yml:658` — without that edit the guard goes green on exactly the PR it exists to catch. |
| 12 | **#353** | Gate the risk-acceptance register against the scorecard: nothing compares its cell lists to the record | 6 | 2 | _quick win_ | DEMAND-GATE | Build state and gating both check out: `git ls-files docs/security` returns nothing in this checkout, so the gate genuinely lands vault-side, and the DEMAND-GATE tier is correct — the verdict is "file now, build on owner green-light" and the body carries "⛔ Not to be built without the owner's go-ahead", a named trigger that has not fired. Value 8 is the error. The rubric's `8` is "an ASVS L3 Partial on defaults, or a production blind spot with no workaround"; this is neither — it gates a compliance ARTIFACT (a signed risk-acceptance register) against another artifact, touches no shipped default and no production path. A workaround exists and has already been executed once: the manual cross-check of all eight blocks against `asvs-scorecard.toml` is what produced the 29-entry finding in the first place. That is "real gap, awkward workaround" = 6 (awkward because it is manual, unrepeatable and unalarmed). Difficulty 2 stands (~15 stdlib lines, `tomllib` + regex + compare, no new dependency). Value 6 at difficulty 2 would read P1 on the thresholds, but the DEMAND-GATE override is correctly applied and the tier is unchanged; quadrant stays quick win. |
| 13 | **#1011** | Rule on the shipped `tools/ech-sidecar/` Go tree: keep it and own it, or retire it | 6 | 2 | _quick win_ | P1 | A 312-line Go TLS re-originator sits in the tracked tree that nothing builds, tests, lints or version-pins — there is no Go toolchain anywhere in CI — while ADR 0139 still files it under "Deferred" and SECURITY.md still calls it "infeasible", so the security record misstates build state in two places and an unowned second language sits in the repo by default rather than by decision. |
| 14 | **#95** | Engine-brokered AI assistance — customer-managed subscription or in-house LLM | 6 | 3 | _quick win_ | DEMAND-GATE | A customer's own Azure OpenAI / Bedrock / in-house endpoint is precisely this item's ask and today fails as an opaque 502 rather than a config error, with BYO the only workaround and one that forfeits the central audit the customer wanted; the broker, audit and egress allow-list already ship, so the remainder is per-provider wire shapes behind `chat()`, a validator that refuses an unserviced `provider`, and the stale `docs/AI.md:22` line. |
| 15 | **#114** | Directory validation toggle (perform vs suppress startup validation) | 6 | 3 | _quick win_ | DEMAND-GATE | The remainder is worse than a missing toggle — `File(validate_directory=True)` on an outbound is accepted and silently ignored, so an operator asks for fail-fast and gets neither validation nor an error, with only the on-demand `POST /connections/{name}/test` probe as a workaround; the fix adds a `validate_startup` hook to the `DestinationConnector` contract (`transports/base.py:459`, which today exposes only `send` at `:480`) plus a runner outbound start-path call, mirroring the source seam already at `transports/base.py:436`. |
| 16 | **#158** | Per-message dynamic FTP host/path/credentials | 6 | 3 | _quick win_ | DEMAND-GATE | Real dynamic-destination gap the shipped code closes off at both ends — host/credentials/`remote_dir` freeze at construction (`messagefoundry/transports/remotefile.py:626-627`) and `render_filename` is hard-capped to one path component (`messagefoundry/transports/file.py:105-127`), so a data-driven target subdirectory cannot be expressed by a static per-folder connection fan-out nor smuggled through the filename; awkward workaround, not a clean one. Build rides the already-shipped #68 per-message metadata carry (`messagefoundry/pipeline/wiring_runner.py:4526-4531`) plus a multi-component path sanitizer — a setting into one connector. |
| 17 | **#328** | `audit-verify` cannot detect a truncated audit tail | 6 | 3 | _quick win_ | P2 | Both shipped verification surfaces call `verify_audit_chain()` bare (`messagefoundry/__main__.py:3596`, `pipeline/engine.py:860`) and the `audit-verify` subparser declares only `--service-config` and `--db` (`__main__.py:571-578`), so a truncated keyed chain — the residue the anchor exists to catch — reports CLEAN with no way for an operator to supply one; the remainder is a new `audit-anchor` subcommand, an `--expected-anchor` flag into the already-present `expected_anchor=` keyword, and an `[integrity]` key for the startup path, with no change to the comparison logic and no store migration. |
| 18 | **#344** | Fixed wall-clock bounds have drifted out of proportion to the work they bound | 6 | 3 | _quick win_ | P2 | A mechanical margin check would have flagged windows-2025 at 1.006x before #119 died where the manual alternative was published wrong twice, and the shared Windows budget still admits the three-PRs-each-adding-a-minute death nobody is individually at fault for; `_wait_until` already raises with a full dispatcher/store dump citing proposal 6 (`tests/test_stage_dispatcher.py:485-497`) and no margin script exists under `scripts/ci/`, so the remainder is that script — timing the STEP, keyed on the step's own conclusion, against a right-censored max — plus giving `Web console tests (pytest)` its own cap instead of the shared `matrix.step_timeout` at `ci.yml:442`. |
| 19 | **#1006** | A mutation that matches is not a mutation that bites: the absence-claim gate proves syntax, never behaviour | 6 | 3 | _quick win_ | P2 | `check_absences` admits an ASVS absence claim on `re.search(a.pattern, a.mutation)` (`scripts/asvs/scorecard.py:395`) — one string field of a TOML row matched against another, with the corpus never consulted and the mutation never applied — so a well-formed, honestly-authored reintroduction that would change nothing if written into the code passes all three of the gate's failure modes and certifies a non-control into the record, a mode the `Absence` docstring did not anticipate even while it closed the adjacent one; the remainder is a required per-claim observable plus a mode that applies the mutation and requires that observable to go red, in one stdlib script and its fixture tests. |
| 20 | **#1007** | Sweep all 345 ASVS cells for present-tense impact language — the record asserts live exposures that do not exist | 6 | 3 | _quick win_ | P2 | The scorecard's 146 residual-prose cells (~64,000 words) and the risk register's 55 signed cell rows were written before the owner ruled the product a not-deployed beta, so cells assert live exposures that do not exist — the "compensating control must not rest on a false premise" defect `docs/Secure_Development_Standards.md:98` forbids — with the only workaround a reader silently discounting every impact sentence by hand; the fix is a wording-only pass under a hard invariant (the `(id, verdict, level)` tuple set byte-identical before and after), a crude screen already sizes it at 77 of 146 candidates spanning every verdict class, one worked example has already landed vault-side, and it moves no verdict, touches no product surface and adds no dependency. |
| 21 | **#1026** | The ASVS 12.1.1 TLS-floor probe silently does not run with the console off, and its own comment names three of its four conditions | 6 | 3 | _quick win_ | P2 | The probe's gate in `__main__.py` requires FOUR conditions — `tls_terminated_upstream and PHI and enforcing and public_origin` — while the comment directly above names three ("a declared terminator, PHI, and `enforce`") and asserts "every other posture never reaches here", so a reader concludes it runs whenever a PHI instance sits behind a declared terminator under enforce. The undocumented fourth is not self-satisfying: the refusal for an unset `public_origin` is itself gated on `serve_ui`, so with the console OFF nothing requires it, it keeps its `None` default (`config/settings.py:693`), and the probe silently never runs while the API is still off-loopback behind a terminator carrying PHI. ⭐ The same block `return 2`s when the probe's MECHANISM is unavailable, explicitly because "a check that degrades to a no-op when its mechanism disappears reports success forever afterwards" — it refuses a silent no-op one level down and performs one one level up (ADR 0158's class). Value 6: an ASVS 12.1.1 control inert in a legitimate posture with nothing reporting the skip. Difficulty 3 because the design choice is the work, not the code: require `public_origin` in that posture (adds a refusal to a posture that starts today), make the skip loud, or correct only the comment and leave the control inert. ⚠️ The originating report's mechanism was WRONG — it said the console "auto-degrades" so `public_origin` stays unset; the real link is that the requirement for `public_origin` is gated on `serve_ui`. |
| 22 | **#169** | Author-appendable per-message processing history | 6 | 4 | _quick win_ | DEMAND-GATE | Genuine MsgAddHistory parity with only an awkward workaround: `message_events` is NOT author-appendable — its writer is engine-only (`messagefoundry/store/base.py:1039-1062`, reachable from `pipeline/` alone) and its `event` vocabulary is a closed frozenset (`messagefoundry/store/store.py:1004-1020`) — leaving `SetMeta` as the sole transform-callable channel, capped at 32 keys / 4096 bytes with last-writer-wins and no timestamp or ordering, so an unbounded append-only history cannot ride it. Build is an append op on the ADR 0081 exactly-once `transform_handoff` template plus an operator surface across three backends. |
| 23 | **#179** | Archive-aged-rows to separate store | 6 | 4 | _quick win_ | DEMAND-GATE | Real CIEArchive parity gap — `RetentionRunner` deletes and never tiers, and the fallback it names is a whole-store snapshot two backends refuse outright; a copy-then-purge step across the store seam, tested on SQLite, PostgreSQL and SQL Server. |
| 24 | **#248** | Steps view: reclassify comment-only rows as a non-opaque note row | 6 | 4 | _quick win_ | P2 | Three shipped, reproducible defects on the Add-palette's own Comment step — a comment after the last statement renders nowhere (the partition stops at `node.end_lineno`, `messagefoundry/lens.py:19-21`), an adjacent one is swallowed by `_merge_code_rows` (`lens.py:1245`), and none is editable, contradicting `docs/STEPS-PALETTE.md:71`'s "Everything is editable after insert" — though dropping to the `.py` text remains a real if awkward escape; ADR 0076 Amendment A is already ACCEPTED and in force (`docs/adr/0076-typed-action-vocabulary-action-list-lens.md:3`), so the grammar cost is spent, leaving a `note` kind threaded through the partition, the coalescer, `_EDITABLE_KINDS` (`lens.py:1377`) and the IDE JSON contract. |
| 25 | **#329** | Five `MEFOR_ALLOW_INSECURE_TLS` cells bypass the ADR 0092 clamp | 6 | 4 | _quick win_ | P2 | The LDAPS bind (`ssl.CERT_NONE` on the authentication substrate for every AD identity), the SFTP host key, the webhook sink and the `[ai].api_key` still cross an enforcing production-PHI posture on one env var, and converting them is what collapses five per-site facts into one repo-wide invariant the ASVS scorecard's regex mechanism can actually express — bounded because setting the variable needs Administrator, who can already do worse; the cheap in-gate half shipped with #323, so what remains is threading an explicit posture into `AuthService`/`create_app`'s three out-of-gate constructors, where `_here()` would otherwise ship green and inert. |
| 26 | **#331** | Anonymizer's fail-closed leak-check has no structural PHI detectors | 6 | 4 | _quick win_ | P2 | The function that earns the right to share a de-identified dataset verifies a known-string denylist — `leak_check` is `scan_text` (FORBIDDEN patterns, one routable-IPv4 check, estate substrings; `scripts/security/scan_forbidden.py:772-795`) plus a field-anchored site code, and a real MRN is not a denylisted string — and on a token-less checkout it degrades to the IPv4 check alone over an HL7 body and still returns clean, a gap `f3c6d348` hit in practice with a hand overlay that was never committed; wiring `token_floor_failure()` into the bridge is small, but the unmapped-field report and detectors scoped to fields no rule matched cross the `anonymize` seam and must be mirrored into `tee/anon/leak.py` for `test_anon_parity`. |
| 27 | **#333** | Per-connection TLS deviations are invisible to the loosening registry | 6 | 4 | _quick win_ | P2 | Build state confirmed OPEN: `tls_allow_expired` appears in none of `config/settings.py`, `api/app.py`, `checks.py`, `__main__.py`; `config/wiring.py:3271` still carries only `accepted_cleartext_hops`; `security_loosenings` at `settings.py:4062` takes the fifth `alerts` parameter #323 added; `transports/database.py:298` still matches `_ODBC_TLS_HINT_RE` against keys only. Value 6 holds. Difficulty 3 prices a copy of #323's precedent and misses that the remainder is not one connector's setting: step 1 inverts a test (`test_database_transport.py:202-212`) that PINS the current DEBUG branch, step 2 needs an inbound name that `config/models.py` Source does not carry (registry plumbing at the construction site), step 4 adds TWO required parameters to `security_loosenings`, breaking all four caller signatures (`api/app.py`, `checks.py`, `__main__.py` x2), step 5 adds sibling advisory CheckResults, step 7 rewrites five DEPLOYMENT.md assertions that become false the moment step 4 lands, and step 8 extends the completeness floor with a connection-scoped arm. That is the rubric's `4` — "a feature across a seam" — not `3`, "a new setting into one connector". Quadrant and tier are unaffected (value 6, difficulty <=5 = quick win, P2). |
| 28 | **#340** | Enable a GitHub merge queue: strict + no queue makes every merge a race that fails silently | 6 | 4 | _quick win_ | P2 | Build state confirmed: zero of the 21 files under `.github/workflows/` carries a `merge_group:` trigger, so difficulty 4 and the step-2-is-a-precondition reasoning are right. Value 8 is not. The rubric's `8` is "an ASVS L3 Partial on defaults, or a production blind spot with no workaround" — this is neither. It is a repo-workflow blind spot, and a workaround demonstrably exists and is exercised: `gh pr update-branch` (#74 landed via three merges from main, #119 landed via re-sync), plus a detector the project already BUILT for exactly this condition and which the item itself cites — `scripts/ci/check_stalled_prs.py` + `.github/workflows/stalled-prs.yml`. So the readiness signal is not in fact unfalsifiable from outside: a scheduled job reports the stalled set. That makes it "real gap, awkward workaround" = 6, one rung above the rubric's `4` for DX (the item's own cluster is Developer Experience & CI), and 6 is generous for a cluster the ladder caps at 4. At value 6, difficulty 4: quadrant stays quick win, but tier is P2 (P1 needs value >= 8, or value >= 6 at difficulty <= 2 — and this one is 4). |
| 29 | **#1008** | Startup preflight on the store principal's effective privileges (ASVS 13.2.2) | 6 | 4 | _quick win_ | DEMAND-GATE | The engine documents a least-privilege store grant it can never observe — no fixed-server-role or database-role probe exists anywhere, and require_managed_identity gates credential kind not privilege, so a sysadmin gMSA passes — and the deferral that blocked this cleared on 2026-08-04 when the runbook fix landed; a serve-time refuse/warn probe on an existing seam, across three backends, coupled to a vault scorecard change it must not silently break. |
| 30 | **#1002** | AG-rig validation: prove the multi-subnet failover reconnect | 6 | 4 | _quick win_ | P2 | Hardware-gated test execution, not a decision: `[store].multi_subnet_failover` shipped 2026-07-10 and is unit-tested only, so [`AOAG-DEPLOYMENT.md`](AOAG-DEPLOYMENT.md) §4.5 must keep mandating a planned DB outage until a real two-subnet AG proves the reconnect. Value anchored on **#1003** (7/4), one below because #1003 discharges four hardware-gated residuals where this discharges one documentation mandate; difficulty matches — same rig, a failover and a failback. Distinct from #1003, which covers #99/#98/#320/#351, none of them the cross-subnet reconnect. |
| 31 | **#1021** | The MFA enrollment confirm verifies the activating TOTP through a bool wrapper that discards the step, so it is never consumed (ASVS 6.5.1) | 6 | 4 | _quick win_ | P2 | `confirm_mfa_enrollment` verifies the enrolling code with `totp.verify_totp` (`auth/service.py:1979`), a documented thin bool wrapper that computes the matched step then collapses it to a bool (`auth/totp.py:150`), so the step is never passed to `consume_totp_step`. It is reachable rather than incidentally blocked because `enable_totp` leaves `users.last_totp_step` NULL in all three backends (`store/store.py:7752-7764`, `sqlserver.py:9095`, `postgres.py:6165`) and the compare-and-set accepts any step against a NULL mark (`store/store.py:7824`) — so on first deployment the activating code would still be accepted by `POST /auth/mfa-verify` on a separate password-authenticated session for the remainder of its own 30-second step (`totp_skew_steps` defaults to 0, `config/settings.py:1736`). Value 6 not higher: exploitation needs the password plus a same-step code capture, and the enrollment route already sits behind an action-bound step-up. Difficulty 4 is test collateral rather than code — the production change is three lines reusing the primitive that already exists on the login path, but at least four tests confirm an enrollment then assert a live verify inside the same step, and `fresh_totp` guarantees headroom within a step without advancing one, so each needs restructuring. |
| 32 | **#180** | Cross-backend store migration tool | 6 | 5 | _quick win_ | DEMAND-GATE | Real gap — `open_store` picks a backend but nothing moves rows between them (no such subcommand exists in messagefoundry/__main__.py), so the only path discards retained history and audit; an offline row copy that re-wraps every `mfenc` body and reproduces the staged plus history shapes on all three backends. |
| 33 | **#332** | Release signing toolchain is unhashed | 6 | 5 | _quick win_ | P2 | Arbitrary code from any of ~30 floating transitives at `.github/workflows/release.yml:255` runs with the OIDC identity that then signs the wheel, writes the SLSA attestation and publishes to PyPI — a backdoored artifact carrying a *valid* Sigstore bundle and valid provenance — and no Dependabot ecosystem parses an inline `pip install X==Y`, so the pin rots with no trigger and no owner (the two siblings at `:104` and `:207`, the latter a `~=` range, float identically); the ADR 0034 hashed-lock mechanism is proven and running for `ci-scanners`/`ci-quality`, but `sigstore` is absent from every lock (`grep -c sigstore uv.lock` → 0), adding a seventh is a six-place lockstep edit, the resolve contamination may force the same excluded-by-decision call semgrep got, and no PR leg ever executes this path. |
| 34 | **#1017** | worktree_gate rule 3d has no ownership signal, so it denies a session removing a worktree it created itself | 6 | 5 | _quick win_ | P3 | Rule 3d denies on three conditions only — a git token, a `worktree remove|move` match, and a target resolving under a governed root (`scripts/hooks/worktree_gate.ps1:509-531`) — and consults nothing about ownership: grepping the block for `cwd` returns zero hits and the gate never reads `session_id`. Ownership is inferred from an invalid premise in the rule's own header (`:500`), that a remove reaching git is aimed at somebody else's tree by construction, and the deny then asserts as fact that it belongs to another session (`:535`). Measured rather than inferred: the gate's receipt log records 4 rule=3d denies and 4 of 4 came from a session standing in its own nested checkout. It bites because the remediation it offers cannot act on that class — `prune-merged.ps1:123-124` excludes the `.claude/worktrees` and scratchpad layouts by contract — and G11 already records that nested worktrees have no scripted removal, so the denied command is the only route. Value 6 for a measured false positive on a control whose efficacy rests on its deny text being believed (G10); held below 7 as Claude-process tooling with working fallbacks. Difficulty 5 because the payload carries no session identity, so a fix means recording creation provenance at `add` time — a new mechanism, not a new condition. |
| 35 | **#94** | External BLOB-server offload for embedded documents — stored-object pointer (OBX-5 RP) | 6 | 6 | _big bet_ | DEMAND-GATE | The strongest store-bloat lever for document-heavy feeds with only awkward workarounds (more disk, purge history), and ADR 0105 already reserved the pointer format and deref seam it plugs into (`messagefoundry/parsing/binary.py:55-62` `DOC_REF_MARKER`, shared-seam note at `:252`, content-address contract at `:264-266`); the remainder is still a pluggable BLOB connector family, a per-connection offload setting across three backends, and an ADR fixing where a write side-effect sits against the at-least-once invariant. |
| 36 | **#96** | Built-in "setup tester" — self-service capacity estimator | 6 | 6 | _big bet_ | DEMAND-GATE | An adopter-run pre-cutover capacity number has no substitute but the manual dev-harness-plus-TUNING-BASELINE exercise, so a real gap with an awkward workaround. The reuse premise is measured false — `knee` appears in `harness/` only in TOML profile comments and `__main__.py` has no `capacity`/`setup-test` subcommand — so the knee-finder, the non-filling per-step gate, the `/stats` staleness precondition and the isolated-store guard are net-new across CLI + engine + store + metrics: rubric band 6. It is not a 7: there is no 3-backend migration, and ADR 0074 already exists and needs amending, not writing. Quadrant stays big bet. |
| 37 | **#141** | TCP connection role selectable independently of direction (act-as-server vs act-as-client) | 6 | 6 | _big bet_ | DEMAND-GATE | Real firewall role-inversion gap that an external relay (socat/stunnel) works around awkwardly but genuinely, which is why it stays at moderate severity and P2; the outbound half is not a knob — `DestinationConnector` (`transports/base.py:459`) exposes only `send` (`:480`) and every destination dials (`tcp.py:189`, `mllp.py:849`, `x12.py:158`), so a listening outbound needs an accept loop handing a peer socket to the per-outbound delivery worker and reconciled with retry/backoff and the connection-lifecycle status vocabulary. |
| 38 | **#3** | Per-key (partition-key) message ordering (long-term, nice-to-have) | 6 | 9 | _big bet_ | DEMAND-GATE | The only order-preserving way to push one ordered feed past the ~60 msg/s one-lane-one-core bound; the engine-shard "workaround" is void (shards partition by connection) and the in-engine router-fanout substitute leaves transform serialized, so a real gap with only an awkward workaround. Nothing keyed exists (`partition_key`/`sequence_key`: zero hits in `messagefoundry/`), and keyed lane assignment with single-writer-per-lane over the durable outbox plus the A40 cross-key hazard is multi-week work sitting directly on the strict-FIFO invariant. Quadrant becomes big bet. |
| 39 | **#1009** | SOAP `body_secret_value_<i>` is redacted, registered and documented — and never fingerprinted | 5 | 2 | _fill-in_ | P2 | `connector_secret_env_values`, the ASVS 13.3.4 runtime rotation fingerprinter, filters on bare `_SECRET_SETTING_KEYS` membership at `config/wiring.py:725` while `body_secret_value_<i>` (emitted at `:2305`) reaches secrecy only through the prefix branch of `_is_secret_setting` at `:686`, so the class is masked on `/metadata`, registered in `CRITICAL_SECRETS` and given a documented rotation cadence yet never MAC'd — and the registration gate whose own comment promises the two sets "can never disagree" walks past it because it enumerates from the set the class never joined; one predicate swap onto the helper 53 lines above, plus the reverse assertion that gate is missing and a `Soap(body_secrets=...)` regression test. |
| 40 | **#1012** | ASVS gate summary line silently drops a verdict state: components sum to 344 against its own stated 345 | 5 | 2 | _fill-in_ | P3 | The gate prints five verdict states whose components sum to 344 while the same line states a 345 total — it omits `needs-review`, so the line cannot be reconciled against itself. Low value because no verdict is mis-scored and the scorecard remains the record of record; the cost is that the summary was quoted as "the distribution" across a full session and the omission propagated every time. Difficulty 2: emit the missing state and assert the components equal the stated total, which is the check whose absence allowed a count not to reconcile. |
| 41 | **#1016** | claims.py 500s on two malformed-IdP shapes with no closed-set audit row | 5 | 2 | _fill-in_ | P2 | Two narrow attacker-influenceable paths raise past the `ClaimsError` contract, so the response is a 500 with no closed-set audit row instead of a named claim rejection: `hmac.compare_digest` raises `TypeError` on a NON-ASCII str nonce (ASCII str-vs-str is legal, and the `isinstance` guard plus `or` short-circuit means non-ASCII is the ONLY remaining path — the fix belongs at the encoding boundary, not in a type check that already exists), and `set(aud)` raises on a list containing UNHASHABLE elements such as `[{"a": 1}]` (every non-list shape already falls through cleanly). Value 5: availability and audit completeness, not an auth bypass. Difficulty 2. |
| 42 | **#1025** | Three `require_ui_step_up` routes emit PHI with no `phi=`, so they charge no per-actor read budget | 5 | 2 | _fill-in_ | P2 | `GET /ui/messages/search`, `/ui/messages/search/layered` and `/ui/uploaded-logs/file/{file_id}` put PHI on the wire through `require_ui_step_up` without `phi=`. `require_ui` declares `phi: bool = False` and throttles at `messagefoundry_webconsole/_auth.py:260` (`if phi and not auth.allow_phi_read(...)`), and `require_ui_step_up` builds its base as `require_ui(*permissions, allow_mfa_pending=True)`, so unless `phi=` is threaded the arm is unreachable — `GET /ui/messages/search` is on `require_ui_step_up(Permission.MESSAGES_READ)`. **A missing RATE LIMIT, not a missing authorization check**: all three still gate on the right permission, so the exposure is that an authorised-but-abusive actor could enumerate without hitting the 429 the sibling browse routes enforce. Difficulty 2 is inherited work: #324 already threaded `phi=` into `require_ui_step_up` (`_auth.py:498`) and used it at `routes/core.py:612`, so this is three call sites plus tests, copying the siblings at `routes/core.py:473`, `:483`, `:501`. Reported by the #324 lane rather than fixed in it, per the owner's settle that it thread `phi=` for its own route only. |
| 43 | **#81** | Alert escalation tiers + day/time thresholds + content (Action-Point) alerting | 5 | 3 | _fill-in_ | DEMAND-GATE | Content-triggered ("Action Point") alerting is genuine Corepoint parity that nothing outside the tests can fire, but the escalation and schedule two-thirds already ship, leaving metadata-only breadth rather than a blocker; the remainder is hoisting `content_match` (`messagefoundry/pipeline/alert_sinks.py:726`) onto the `AlertSink` Protocol (`messagefoundry/pipeline/alerts.py:27`), exporting an emitter a Handler can reach without breaking re-run purity, and surfacing the already-durable `escalation_tier` (`messagefoundry/store/postgres.py:449`) on `AlertInstanceInfo`, which omits it (`messagefoundry/api/models.py:255-275`). |
| 44 | **#99** | AD/gMSA production-deployment hardening — turnkey enterprise (Windows/AD) install | 5 | 3 | _fill-in_ | DEMAND-GATE | Every code half is built — gMSA preflight + logon-right grant (`scripts/service/install-service.ps1:42-46`, `:286-303`), the MFA-claim hook on by default (`config/settings.py:1914`, enforced `:2184`), IIS/ARR and gMSA docs — leaving only (e), a live domain-lab smoke, whose fallback (ship with the caveat, validate at the first deployment) is workable: parity assurance with a clean workaround, value 5. Difficulty is 3, not 6: the residual lands almost no code through ruff/mypy/pytest; its cost is DC + AD CS + gMSA + proxy + joined-client provisioning the project does not own, which this rubric does not price as engineering — and the item's own 2026-07-28 amendment explicitly retires the 6/6 engineering framing. Quadrant becomes fill-in; still DEMAND-GATE behind #275. |
| 45 | **#125** | Uploaded Logs page - import external message files and browse them offline | 5 | 3 | _fill-in_ | DEMAND-GATE | The build-state finding is right (the five routes exist at api/app.py:3685/:3786/:3803/:3889/:3946 and `browse_uploaded_file`'s own docstring says "Returns metadata only — never a decrypted body"), but value 6 rests on the claim that the item's trigger — "inspect a partner-supplied message file without ingesting it" — is "still unserved". It is substantially served: the shipped browse route filters and searches by `content`, `field_path`/`field_value`, `message_type` and `control_id` over the decrypted split, and per-message resend exists, all without live ingest. What is missing is only the body DISPLAY, and for that the workaround is clean, not awkward: the operator personally uploaded the file, so it is already in their hands and readable in any text editor, and `dryrun --show-phi` prints bodies as well. That is rubric 5 — "parity/breadth with a clean workaround" — not 6's "awkward workaround". Difficulty 3 stands (a read-one/download route over the existing encrypted store plus the audited PHI-view treatment and an ADR 0134 amendment). Quadrant becomes fill-in, not quick win; tier is unchanged. |
| 46 | **#132** | Fixed 'now' test-time override (frozen clock for reproducible transform tests) | 5 | 3 | _fill-in_ | DEMAND-GATE | Value 5 stands (a wall-clock-free transform or a tolerant diff gets regression comparison today — "parity/breadth with a clean workaround"), and the seam claim is verified: `route_message` takes `ingest_time` at dryrun.py:517 and the two internal call sites hardwire `time.time()` at :679 (`_dry_run_raw`) and :753 (`dry_run`). But "a --now flag threaded through two entry points" undercounts the surfaces, and the ones it misses are the ones the item is ABOUT. `checks.py:1058,1126` calls `dry_run(reg, raw, inbound=..., snapshot_on_send=...)` with no ingest_time — and checks.py is the `.expect` fixture comparator, i.e. the repo's actual deterministic-regression gate. `trace_dry_run` is a separate module (`dryrun_trace`, invoked from __main__.py:2926-2931). And the item's own Trigger names the Test Bench: ide/src/testBench.ts shells `dryrun` at five sites (:240, :325, :354, :440) and would need the flag plus an affordance. Engine + CLI + fixture gate + a TypeScript extension is D3 work, not D2's "small additive change on an existing seam". Quadrant stays fill-in; tier stays DEMAND-GATE. |
| 47 | **#172** | Gzip/zip compression codec + file-connector option | 5 | 3 | _fill-in_ | DEMAND-GATE | File-feed parity breadth with a clean code-first workaround: the reusable codec shipped including `zip_compress`/`zip_decompress` (`messagefoundry/parsing/compression.py:40-48`), so a zip-delivering partner is served by a Handler call today. What remains is connector-level — widening `_SUPPORTED_COMPRESSION` (`messagefoundry/transports/file.py:88`), which forces an archive-member-to-message decision, plus REMOTEFILE, which has zero compression to extend. |
| 48 | **#1014** | connscale smoke test's fixed 24-port block is not parallel-safe across worktrees; the flaky marker hides the collision | 5 | 3 | _fill-in_ | P3 | `test_connscale_smoke_end_to_end` hard-codes `base_port = 41000` and needs 24 CONTIGUOUS inbound ports, so two checkouts running the suite at once contend for the same block — which is the normal topology here (24 worktrees were live on 2026-08-04). It self-heals via `@pytest.mark.flaky(reruns=2)` commented "CI runners are noisy", so a determinate resource collision wears a noise label and the retry does work the port allocation should be doing. Value 5: it costs retries and misdiagnosis rather than correctness. Difficulty 3: allocate the block dynamically and assert contiguity, rather than widening the retry. |
| 49 | **#1020** | The first-run bootstrap Administrator is created with no email address, and the PHI notification gate cannot see it | 5 | 3 | _fill-in_ | P2 | `_ensure_bootstrap_admin` calls `create_user` with no `email=` (`auth/service.py:527-533`), so the account holding `frozenset(Permission)` has a NULL email and `SecurityEventNotifier.notify` returns before enqueueing (`pipeline/security_notify.py:130`), making all ten notice types no-op for it — including LOGIN_AFTER_FAILURES, the compromise signal. The part with teeth is gate blindness: the PHI startup gate refuses to serve without a notification channel but computes readiness from `notify_security_events` plus `email_smtp_host` plus `email_from` alone (`__main__.py:2260`), so it would report a healthy channel while no notice about the all-permission account could be delivered. The allocated title's second half is REFUTED and the body says so: lockout is time-bounded (15 minutes by default, `settings.py:1769`), an admin reset clears it (`store/store.py:7693`), the documented break-glass is a sealed file (`api/app.py:5104`), and no email-driven recovery flow exists anywhere in the code. Value 5 because every event is still an audit row surfaced by `GET /me/security-events`. Difficulty 3 with no schema change; the only judgment is which of three candidate fixes the owner wants. |
| 50 | **#1019** | install-selfheal.ps1 has no installed-vs-source payload-parity instrument, and it wires the most privileged hook in the estate | 5 | 3 | _fill-in_ | P3 | The installer copies `worktree-selfheal.ps1` to `~/.claude-hooks/` and wires it as a user-scope SessionStart hook with no divergence detection: no `-Status` (the surface is `-ConfigDir` plus `-HookPath`), no version stamp, a bare `Copy-Item -Force` (`:57`), and no test that reads the installed copy — every selfheal test binds `ROOT` under a synthetic home, and the repo's only installed-vs-source parity test names the gate copy alone (`tests/test_gate_installed_parity.py:44`). The title's "no parity instrument at all" is narrowed in the body: source-level guard parity DOES exist (`test_both_installers_carry_the_same_refusal`), as do the CLAUDECODE refusal, the backup-validate-rollback, and an unconditional payload refresh — what is absent is payload parity. The claimed comparator is also wrong, and PR #191 has since sharpened this: it landed payload parity on `install-git-hooks.ps1` (SHA256, IN SYNC/STALE, plus a pytest-side assertion), so `install-selfheal.ps1` is now the ONLY installer in the estate without one, with two worked examples to copy. Privilege is substantiated: user scope in every config dir, and a hook that runs `git checkout` on the shared primary unattended (`worktree-selfheal.ps1:106`). Measured 2026-08-04, installed and source agree (`c41c70ecf885`), so detection is absent rather than divergence present. Difficulty 3 with four constraints, chiefly folding CRLF exactly as the existing instruments do. |
| 51 | **#1027** | The documented `pytest` command silently excludes the webconsole package, so a local green is not evidence about ~344 tests | 5 | 3 | _fill-in_ | P3 | `pyproject.toml` sets `testpaths = ["tests"]`, so the command CLAUDE.md:333 documents as the verification gate (`QT_QPA_PLATFORM=offscreen pytest -q`) never collects `packaging/messagefoundry-webconsole/tests` — while CLAUDE.md section 5 states a task is not done until it passes. Not hypothetical: on 2026-08-04 `test_webui.py::test_webauthn_rp_fail_closed_legible` was FAILING on main all day and no lane saw it, surfacing only when one lane named both paths explicitly for a webconsole-touching change (`1 failed, 10681 passed, 851 skipped`). ⚠️ NOT a CI gap, verified rather than assumed: `ci.yml:250` installs `-e ".[dev,harness,fhir,dicom,x12,xml,webauthn]" -e packaging/messagefoundry-webconsole` and runs `Web console tests (pytest)` as a separate required step, so PRs merged on real coverage — the gap is local only, which is exactly why nothing red ever reached anyone. Difficulty 3 because the naive fix reds every local run: adding the path to `testpaths` makes that same `[webauthn]` failure the default local experience, since worktree venvs bootstrap a narrower extra set than CI. ⛔ Whichever option is chosen, a skip must announce itself — trading a silent exclusion for a silent skip is not a fix. |
| 52 | **#236** | Test-this-step and test-up-to-step with pinned upstream values | 5 | 4 | _fill-in_ | P2 | Real debug breadth — whole-handler traced values already fold onto rows (`mergeLiveValues`, ide/src/stepsModel.ts:544) so partial runs are a convenience, but pinning an expensive `db_lookup`/`fhir_lookup` has no equivalent at all; largely a stop condition plus state dump on ADR 0072's shipped trace, with the lookup mock and keeping `buildLensTraceArgs` (:674) incapable of emitting `--show-phi` the real work. |
| 53 | **#1022** | disable_mfa has no last-factor guard where delete_webauthn_credential does, so the two removal paths can be ordered to reach zero factors | 5 | 4 | _fill-in_ | P2 | `delete_webauthn_credential` computes `last_second_factor` and refuses when MFA is required (`auth/service.py:2426-2432`); `disable_mfa` does nothing between `get_user` and `disable_totp` (`:2086-2087`), so a user holding TOTP plus one passkey can delete the passkey (permitted while `totp_enabled` is True) and then disable TOTP, arriving at zero enrolled factors — the state ADR 0068 AC-10 says the system shall refuse. (Corrected: the false doc claim was the `DELETE /me/mfa` **route-table row** at `docs/SECURITY.md:329`, since fixed to state the absence; `:752` is passkey-scoped and defensible, so the remaining doc obligation is ADR 0068 line 140.) The consequence is overstated in the obvious reading and the body corrects it: login enforcement is NOT missing, since `mfa_verified=not mfa_required` (`:718`) plus the ASVS 6.3.3 access gate in `require()` (`api/security.py:224-234`) make the outcome a forced re-enrollment rather than single-factor access. Value 5: genuine, demonstrable, defeats a numbered acceptance criterion by ordering and makes a shipped doc guarantee untrue, but no bypass and no PHI consequence. Difficulty 4 because the raise needs mapping at two call sites that would otherwise 500, one existing test breaks by construction (`tests/test_mfa.py:189`), and two docs move with it. Filed because ADR 0068 line 140 promised this parity follow-up and no item carries it. |
| 54 | **#165** | DB schema browser + ad-hoc query runner | 5 | 5 | _fill-in_ | DEMAND-GATE | Corepoint-parity authoring aid whose external-SQL-client workaround is fully clean — the only DB reach today is the `SELECT 1` reachability probe (`messagefoundry/transports/database.py:484-501`) and dry-run refuses `db_lookup` (`messagefoundry/pipeline/dryrun.py:570`); the build is a net-new API surface plus per-dialect introspection, read-only statement gating, a permission, audit and a console pane. |
| 55 | **#232** | Steps view for routers | 5 | 5 | _fill-in_ | P2 | Real Steps-view breadth gap exactly where destination selection is decided, with a workaround — read a five-line guard-and-return — clean enough to hold it off the top; a `route` row kind widens the ADR 0076 §3 grammar, so an amendment lands first, then `return []` disambiguation in a lens that skips routers outright today (messagefoundry/lens.py:306, :344-347), a router palette, and byte-stable rewrite parity. |
| 56 | **#78** | Custom message-definition data model + conformance validator; NCPDP codec | 5 | 6 | _money pit_ | DEMAND-GATE | Corepoint-parity persisted-definition model plus a report-only validator and an additive NCPDP codec, all cleanly worked around today by a code-first Handler, so useful breadth rather than a blocker; the whole scope is still remainder — NCPDP appears nowhere in `messagefoundry/` and `profile` is merely "reserved for a conformance-profile" (`messagefoundry/parsing/validate.py:56`) — spanning a new stored model the code reads, a validator, and a new codec class. |
| 57 | **#85** | Cloud object-store + generic message-bus destinations | 5 | 6 | _money pit_ | DEMAND-GATE | Corepoint-parity transport breadth with a clean workaround — the pluggable destination registry lets an adopter write the connector code-first — and nothing exists today (`transports/` carries no object-store or bus driver; `pyproject.toml` names no boto3/azure/google-cloud/kafka dependency). But the scored remainder is the whole scope: four-plus drivers, four vetted dependencies through the hash-locked lock file, plus credential sourcing and egress allow-listing on each, which exceeds the single-connector band 5. Quadrant becomes money pit. |
| 58 | **#127** | Web-proxy credential types (Basic / Digest / NTLM / Windows) | 5 | 6 | _money pit_ | DEMAND-GATE | Breadth with a clean, ADR-ratified workaround — `cntlm` in front of the engine covers the enterprise NTLM proxy, and Basic already tunnels through `CONNECT`; the remainder is not a knob but a keep-alive HTTP client under `transports/rest.py`, because `urllib.request` opens a new connection per `open()` and the NTLM type1/2/3 handshake is connection-bound — the refusal is asserted at `messagefoundry/transports/rest.py:993-997` for the same reason #65 scoped it out (`transports/http_auth.py:27-31`), across four connector factories plus an ADR 0126 amendment. |
| 59 | **#342** | Sandbox worker kill does not reap a grandchild holding the response pipe | 5 | 6 | _money pit_ | P2 | Build state confirmed open: `pipeline/sandbox.py:327` is a bare `proc.kill()` and the module contains no `creationflags` and no `start_new_session`. Value 5 holds — #339's per-dispatch `secrets.token_hex(16)` really does bound this to availability and orphan accumulation on an opt-in posture. Difficulty 5 is the error, and the scorer's own why states the disqualifying fact: the fix "wants verifying on the Windows CI leg". The rubric prices `6` as "cross-cutting ... or Windows-CI-gated", and `5` as "a new connector/codec behind the transport registry" — which this is not. On top of the CI gate, the Windows half has no stdlib API (a kill-on-close job object means ctypes against `CreateJobObject`/`SetInformationJobObject` or a vetted new dependency), and the POSIX half is a different mechanism (`start_new_session` + `killpg`), so it is two platform implementations plus a platform-gated test. At value 5 / difficulty 6 the quadrant is money pit, not fill-in; tier stays P2 (value >= 5). |
| 60 | **#62** | Binary body carriage — store ciphertext / raw bodies as `VARBINARY`/`BLOB`/`bytea` instead of base64-in-`NVARCHAR` | 5 | 7 | _money pit_ | DEMAND-GATE | Corepoint-class ~60% at-rest win on SQL Server where the only workaround is a bigger disk, but it is measure-gated and never load-bearing on correctness; a carriage format change that re-opens ADR 0028's NUL-safe str/TEXT decision, needs its own ADR, and drags a dual-read migration over three backends and two live `mfenc:` versions. |
| 61 | **#130** | Message queues shared by name across connections + shared-name delete protection | 5 | 8 | _money pit_ | DEMAND-GATE | Parity breadth with a clean workaround — the name-wired graph already fans a router across handlers and a handler across outbounds, and nothing (zero `shared_queue`/`queue_name` hits in `messagefoundry/`) suggests a named queue is needed to express a real feed; building it adds a store seam keyed by name rather than connection, competing consumers claiming under per-lane FIFO, and reference-counted delete, on all three backends without letting the abstraction become the "channel" element CLAUDE.md forbids. |
| 62 | **#137** | Configurable server display name in the operator console | 4 | 2 | _fill-in_ | DEMAND-GATE | Value 4 is right (console polish; the URL/port already disambiguate, and monitoring.py:508 already renders a "Node id" row, so nobody is blocked), and the stale-module finding is right — there is no messagefoundry/console/, and the live title is `el("title", f"{title} — MessageFoundry")` at _html.py:171. But D2→3 rests on a false premise: "the console never imports the engine, so the label has to ride an API status response rather than being read from settings in-process". The console does not import the engine, yet the engine INJECTS a typed bundle into it at mount time — `mount_ui(app: FastAPI, deps: UiDeps)` (messagefoundry_webconsole/mount.py:69), and `UiDeps` (messagefoundry/api/_ui_seam.py:199) already carries settings-derived display values of exactly this shape, e.g. `organization_domains` (:224) and `oidc_authorization_host` (:231-234), the latter documented as "Derived from settings, never from request input". A server display name is one more UiDeps field plus a read in `page()` — no HTTP boundary crossing, no status-response plumbing. That is D2, "small additive change on an existing seam". Quadrant stays fill-in; tier stays DEMAND-GATE. |
| 63 | **#167** | Test Bench metadata seeding | 4 | 2 | _fill-in_ | DEMAND-GATE | IDE Test Bench DX input to seed the per-message metadata bag for transform tests; nobody is blocked, and the seam is small — a `--meta` flag threaded through `dry_run`/`route_message` (`messagefoundry/pipeline/dryrun.py:512-521`, `:702-709`) into the Test Bench's CLI-only channel (`ide/src/testBench.ts:240`). The bag itself already shipped (#150/ADR 0081, `messagefoundry/config/wiring.py:2604`) but write-only — no `meta_get` on `Message` — which is a clause of this item's OWN trigger, so it holds the tier at DEMAND-GATE without discounting worth-if-built. |
| 64 | **#171** | Runtime log-verbosity control + in-product log viewer | 4 | 2 | _fill-in_ | DEMAND-GATE | Ops convenience whose live-incident use case the built API half already answers — `set_runtime_level`/`current_log_level` (`messagefoundry/logging_setup.py:429`, `:452`) behind `GET`/`PATCH /logging/level` and `GET /logs/tail` (`messagefoundry/api/app.py:4566`, `:4580`, `:4609`); the remainder is pure wiring, since the console JS is already written (`messagefoundry_webconsole/static/app.js:1252`, `:1294`) and only needs a page builder to emit its attributes plus the two absent `/ui` routes and a golden-surface update. |
| 65 | **#177** | Effective-permission inspector for a user | 4 | 2 | _fill-in_ | DEMAND-GATE | The endpoint shipped (`GET /users/{user_id}/permissions`, `messagefoundry/api/auth_routes.py:610`), so the manual `/users`×`/roles` cross-ref the 5 priced is already gone and the remainder is console polish over a built surface; an apiclient wrapper plus a card on the existing `/ui/users/{user_id}` page — whose builder renders only profile/roles/scope/actions (`messagefoundry_webconsole/pages/admin.py:152-158`) — and a golden-surface update. |
| 66 | **#228** | Steps / config search finds handlers, routers, and transforms by name (not just connections) | 4 | 2 | _fill-in_ | P3 | Authoring polish on an index that already ships — a hit opens source instead of the Steps view and send targets stay unindexed; both are small additive edits, (a) a `contextValue` on rows that already carry `elementKind`/`elementName`. |
| 67 | **#124** | Batch-export message bodies from a connection log to a file | 4 | 3 | _fill-in_ | DEMAND-GATE | Console polish now that the capability itself ships — a scripted operator exports today through the audited step-up route, leaving only the save-selected affordance; the JS is already written (`messagefoundry_webconsole/static/app.js:1380`), so the cost is emitting the `data-mf-*` attributes and row checkboxes in `pages/messages.py` and registering `/ui/messages/export` ahead of `/ui/messages/{message_id}` (`routes/core.py:468`) so the path parameter cannot swallow it. |
| 68 | **#133** | User-chosen display colour on configuration objects | 4 | 3 | _fill-in_ | DEMAND-GATE | Value 4 ("DX or console polish") is right and the stale-citation finding is right (no messagefoundry/console/ package; the live chrome is _html.py's page() head). But D3→2 rests on "a colour is that same shape [as `flagged`] plus a render", and that is false in a way this codebase enforces. `flagged` is a bool with no rendering sink; a colour is an operator-supplied STRING rendered into console markup, and the /ui CSP is `style-src 'self'` with no 'unsafe-inline' (_security.py:205, _auth.py:141, and app.css:2 states the constraint outright). An inline `style="…"` colour would simply not render, so the build must either bind a fixed palette to CSS classes shipped in app.css or add a nonce'd style mechanism the CSP does not currently grant for styles — a design decision plus value validation on untrusted config input, on top of the config-model → TOML → API → console thread. That is D3 ("a new setting into one connector"-scale work), not D2's "default flip or doc edit"-adjacent band. Quadrant stays fill-in; tier stays DEMAND-GATE. |
| 69 | **#234** | Steps view projection refreshes on save only | 4 | 3 | _fill-in_ | P3 | UX latency on an opt-in authoring surface, not a correctness gap — the rows merely lag the buffer while live values stay correctly save-gated (ide/src/stepsView.ts:327); the debounce already exists at :89, but relaxing a deliberate ADR 0076 §5 guardrail means an amendment plus proving `EditLoopGuard` holds when projection races an in-flight `lens rewrite`. |
| 70 | **#343** | Sandbox child stderr is inherited unframed into the engine log stream | 4 | 3 | _fill-in_ | P3 | The worker is still spawned `stderr=None` (`pipeline/sandbox.py:266`), so a sandboxed Handler's bytes land in the engine's own log stream unattributed and a `print()` of a body writes PHI at whatever level the operator runs — but the same `print()` under the default `mode=off` reaches the same stream, so the sandbox-specific loss is attribution and the fd-1 framing that survives on luck rather than design; a `stderr=subprocess.PIPE` relay thread through the stdlib logger (inheriting the existing PHI filters) plus a bootstrap redirect of the child's `sys.stdout`, all inside one module. |
| 71 | **#346** | The sandbox import boundary is enforced only at runtime, under an off-by-default flag | 4 | 3 | _fill-in_ | P3 | The scorer verified the item's own measurement (`FORBIDDEN_MODULES` appears nowhere under `tests/`, confirmed) and inherited its conclusion — but the conclusion is the part that is false. The item's load-bearing claim is that "a re-violation is invisible to a green suite" because the guard runs only in the child under a non-default flag. `tests/test_sandbox.py` runs REAL `mode=SUBPROCESS` sessions across roughly a dozen tests (`test_subprocess_parity_router_and_handler`, `test_subprocess_marshals_live_store_run_context`, `test_generator_router_routes_under_mode_subprocess`, `test_setstate_tuple_and_nonfinite_values_survive_mode_subprocess`, ...) — the child is genuinely spawned, since the OFF test asserts `off._proc is None` as the distinguishing property. Decisively, `test_response_view_reaches_a_sandboxed_handler` (~:617-645) drives a `CapturedResponse` through a live subprocess round-trip, i.e. the exact violation instance the item is built on would now be caught red by CI. So the compensating control is a live test file, not absent, and the residual narrows to a FUTURE codec type added without an accompanying subprocess-mode test. That is test-coverage hardening = value 4, not "real gap, awkward workaround" = 6. Difficulty 3 stands (an `ast` walker anchored on the constant, falsified against a planted import). At value 4 the tier is P3 (P2 needs value >= 5) and the quadrant is fill-in. |
| 72 | **#351** | SQL Server failover test asserts on a 0.35s wall-clock margin across a real DB round-trip | 4 | 3 | _fill-in_ | P3 | One observation on one leg, with the 2022 leg passing the same commit and a sibling PR passing both, bounds this to a marginal test whose red misattributes to whichever PR it fires on — the residual worth is settling whether #348's work at the `_acquire` chokepoint merely spent latency the test had no headroom for or tipped a real delay-predicate regression; the edit is confined to one test file, but it cannot be validated locally by default (the SQL Server leg silently skips) and must not be landed as a wider margin before the question is answered. |
| 73 | **#1018** | The raw-text gate-rule scan exists in three independent copies with nothing tying them together | 4 | 3 | _fill-in_ | P3 | The two regexes that read a gate script as text and extract every dispatched tool are implemented three times, not two: `tests/test_install_gate_wiring.py:29-39`, `tests/test_gate_installed_parity.py:55-56` and `:110-114`, and `scripts/worktree/install-gate.ps1:171-179` in PowerShell. They compute the same quantity — copy 2 reads the same file as copy 1 at `:336`, and all three return the identical 10 names — so this is duplication, not resemblance. They do NOT disagree today; the hazard is a synchronised edit, demonstrated by changing the quote pattern in one copy and observing a symmetric difference. The value is the failure direction: an under-matching copy 2 shrinks `required` (`:320`) so the wiring test passes having checked less, and an under-matching copy 3 prints no UNWIRED line — both false greens in the files written because a rule once shipped dead while 85 tests stayed green. A shared Python helper cannot absorb the PowerShell copy, so the honest end state is one helper plus a cross-language agreement test; without that second half the item reads done while two implementations still float. Value 4: tooling hygiene, no engine effect, cannot fire today, and copy 1 is already partly pinned. |
| 74 | **#1024** | install-gate.ps1's config-dir glob is over-wide AND it is the WRITER that manufactured the wiring the reader validated against | 4 | 3 | _fill-in_ | P3 | `scripts/worktree/install-gate.ps1:91` discovers config dirs with `Get-ChildItem -LiteralPath $HomeDir -Directory -Filter ".claude-account-*"` — unanchored, so it matches any directory whose name merely BEGINS with `.claude-account-`. Measured 2026-08-04: `~/.claude-account-2.lock` IS a directory (created 2026-07-29), so the filter matches it, and its `settings.json` carries `worktree_gate.ps1` wiring that this installer put there and re-writes on every run. ⭐ It is not a passive mirror of the reader defect #199 just fixed — it is the WRITER. The Python reader used the same unanchored glob, so it read back, as evidence of correct wiring, a file this installer had manufactured; the two agreed because both globs were wrong the same way. That is a validator satisfied by construction, [ADR 0158](adr/0158-silent-controls-green-signals-that-mean-nothing-and-shape-over-detection.md)'s exact class. #199 anchored the reader (`\A\.claude-account-\d+\Z`) and deliberately left the writer, so the circular evidence is broken but the discrepancy is still being re-created. Value 4: developer tooling with no product surface, and extra wiring in a stale directory is fail-SAFE rather than fail-open — the cost was the circular evidence, already broken. Difficulty 3 not lower because a session must NOT execute this installer to verify a change (it writes machine-global user-scope wiring), so verification is by inspection plus a test exercising the predicate; the session that fixed the reader could not verify a writer change for exactly that reason. |
| 75 | **#166** | Server-side per-user console preferences | 4 | 4 | _fill-in_ | DEMAND-GATE | Roaming console settings stay polish nobody is blocked on; the cost the 6 priced is gone — the Qt half is retired and #151 already shipped the owner-keyed per-user store + route template (`messagefoundry/store/store.py:1667-1681`), so the remainder is a second additive table across three backends plus web-console wiring, no pipeline. |
| 76 | **#235** | Generate Steps view parameter forms from Python type hints | 4 | 4 | _fill-in_ | P3 | Authoring polish — the recognized row set is unchanged and only the widgets get richer over the literal-only slots the lens marks today (messagefoundry/lens.py:255); a stdlib `inspect` schema emitter beside the 315-line `actions.py` plus replacing the hand-rolled per-op rendering in a 2,328-line model (`ADD_MENU_CATALOG`, ide/src/stepsModel.ts:886). |
| 77 | **#237** | Per-argument input modes (static templated dynamic) in the Steps view | 4 | 4 | _fill-in_ | P3 | Authoring polish that renames "not editable" honestly without unlocking a new edit class — dynamic mode stays read-only in v1 by its own sketch; the value classifier is net-new in `lens.py`, then a mode selector on the same form surface #235 rewrites, sequenced behind #233. |
| 78 | **#108** | Receiver-side 'Prefer BOM if present' encoding auto-detect | 3 | 2 | _fill-in_ | DEMAND-GATE | A configured per-connection `encoding` already covers any single-encoding feed cleanly — it is plumbed through to `normalize(raw, *, encoding=…)` on the hot path (`messagefoundry/parsing/peek.py:152-162`) and accepts `utf-8-sig`/`utf-16-le`/`utf-16-be` — leaving only the niche mixed-BOM override, a niche interop knob; the remainder is a small additive sniff on the decode path, since no UTF-16 byte-order mark is detected anywhere today. |
| 79 | **#148** | X12 TA1 interchange-acknowledgement generation | 3 | 2 | _fill-in_ | DEMAND-GATE | Niche X12 knob most partners never need — the pyx12 walk yields a conforming 997/999 free (`parsing/x12/validate.py:18`, `:69`), covering the common ack, and only a contract that specifically mandates interchange-level accept/reject reaches for TA1; the build is a pure codec addition beside the existing splitter and delimiters in `messagefoundry/parsing/x12/`, which today contains no TA1 generator at all — only the outbound classifies a partner's returned TA1 (`transports/x12.py:73-74`). |
| 80 | **#184** | Serve own endpoint WSDL | 3 | 2 | _fill-in_ | DEMAND-GATE | Niche SOAP interop knob with a clean out-of-band-WSDL workaround; a configured document served off the listener's existing GET/HEAD health short-circuit (messagefoundry/transports/http_listener.py:796-797), which already returns before any ingress row. |
| 81 | **#249** | `lens graph`: mermaid and dot export formats | 3 | 2 | _fill-in_ | P3 | `graph --json` already ships (`messagefoundry/__main__.py:156-159`), so a mermaid/dot emitter is convenience over an already-complete surface rather than a capability anyone lacks; two pure-string emitters over the existing graph model, no new dependency and no seam crossed. |
| 82 | **#338** | TLS key-exchange groups are inherited, not pinned | 3 | 2 | _fill-in_ | P3 | `harden_kex_groups` still returns `None` when `set_groups` is absent, and all three restatements survive the 2026-07-29 sweep — `CONTAINER-EXPOSURE-EVALUATION.md` still says "hardened KEX groups" under a *verification* heading, `BACKLOG.md:6422` still lists 11.6.2 in #200's Closes line against PHI.md's PARTIAL, and `ASVS-L2-PHASE0-CHANGES.md:254` still presupposes a pin — but every group that gets in is forward-secret and the floor plus `harden_cipher_suites` admit nothing static, so this is documentation accuracy plus observability; three doc edits and one additive report-only `SecurityPosture` field beside `fips_attestation()`, with the two tripwire tests left alone as the 3.15 trigger. |
| 83 | **#83** | Rich file-output disposition + FTPS / SFTP variants | 3 | 3 | _fill-in_ | DEMAND-GATE | Niche file/FTP interop knobs most partners never need, and the ones that bite are transport-side where no Handler can substitute; all of it is per-driver additive on two connectors — `FileDestination` still has no append, dated-subfolder archive or header/trailer framing knob, and `remotefile` is explicit-`FTP_TLS` only with no implicit/passive toggle or keyboard-interactive auth (`messagefoundry/transports/remotefile.py:13`, `:256-262`). |
| 84 | **#98** | Kerberos SSO channel-binding (EPA) opt-in + acceptor-enforcement spike | 3 | 3 | _fill-in_ | DEMAND-GATE | Narrow EPA hardening on an opt-in in-process-TLS SSO mode nobody is blocked on, and structurally void behind a TLS-terminating proxy, so a niche interop knob at best; the acceptors are still constructed with no bindings at all (`spnego.server(service=…)` / `spnego.server()` at `messagefoundry/auth/ldap.py:300-302`, `:360-362`, with no `channel_bindings` argument or CBT knob anywhere), so the work is a spike plus one conditional per-mode flag — but the answer needs the same domain lab #99(e) is blocked on. |
| 85 | **#159** | TCP stream-until-close (no-framing) mode | 3 | 3 | _fill-in_ | DEMAND-GATE | Niche close-framed TCP interop knob: `codec_for` requires both delimiter bytes and `FrameCodec` rejects `start == end` (`messagefoundry/transports/framing.py:62-63`, `:167-170`), so connection-close framing is inexpressible today; a `framing=none` path bypasses the shared codec on the Tcp read loop (`messagefoundry/transports/tcp.py:508-515`) and the destination's write-then-close. |
| 86 | **#163** | Static-string inbound ACK | 3 | 3 | _fill-in_ | DEMAND-GATE | Canned-ACK interop knob most partners never need — `AckMode` offers only original/enhanced/none (`messagefoundry/config/models.py:98-103`) and `build_ack` always assembles MSH+MSA (`messagefoundry/transports/mllp.py:329-350`); a new mode plus a literal setting through wiring into the one MLLP listener, with the synchronous NAK path decided. |
| 87 | **#178** | SFTP cipher / KEX / MAC allow-lists | 3 | 3 | _fill-in_ | DEMAND-GATE | Niche knob a FIPS-restricted partner needs — `client.connect` passes no `disabled_algorithms` (`messagefoundry/transports/remotefile.py:396-405`), so only host-key posture is operator-configurable. Cost is a new validated operator setting into one connector, and the Scope's second clause (preferred-ordering on the SSH Transport) is not reachable through `SSHClient.connect` — it must be set on the Transport before negotiation, so `_make_client` restructures rather than gaining one kwarg. |
| 88 | **#181** | Multipart/form-data outbound encoder | 3 | 3 | _fill-in_ | DEMAND-GATE | Niche multipart upload most REST/SOAP partners never ask for and a hand-built Handler body covers; a boundary encoder plus a per-request Content-Type on a connector whose type is fixed at construction (messagefoundry/transports/rest.py:1355), with the collision-checked boundary idiom already written at messagefoundry/transports/dicomweb.py:262-290 to copy. |
| 89 | **#183** | SOAP MTOM/XOP binary packaging | 3 | 3 | _fill-in_ | DEMAND-GATE | Niche IHE packaging format that base64-inline already serves for any accepting partner; XOP framing is spec-fiddly but confined to one connector's string-concatenated envelope (messagefoundry/transports/soap.py:643-702), with no body signature to disturb and the DICOMweb boundary generator to borrow. |
| 90 | **#320** | windows-2025 is the slowest CI leg (1.8x-3.5x), but that does not explain the 60/s failures | 3 | 3 | _fill-in_ | P3 | The item retracts its own product premise — the CI symptom is absorbed by #115 and a 36-run sweep shows a 1.8x-3.5x latency gap rather than a capacity cliff, leaving only an unexplained red at `rate_start = 60.0` (`tests/test_load_runner.py:150`, `pool_size = 4` at `:120`) and an unverified near-breach of the `read >= sent // 2` floor; the honest next experiment is a concurrent-load arm on the dispatch-only probe that already exists (`harness/load/ingress_probe.py`, `.github/workflows/ingress-rate-probe.yml`), not the self-hosted rig, which `ci.yml:49` records as retired. |
| 91 | **#337** | handler-security lint: `getattr` indirection and the undecorated helper | 3 | 3 | _fill-in_ | P3 | `_AMBIENT_BARE_NAMES` (`checks.py:476`) still matches a literal name chain and `checks.py` contains no `getattr` resolution at all, and the rule loop still bails on `_message_fn_decorator(node) is None` (`:937`) so the `_<feed>_transforms.py` helper CONNECTIONS.md steers PHI handling into is never opened — but the lint is advisory unless an adopter opts into `--strict-handler-security`, and evading it reaches neither the DEK nor the audit chain in either sandbox posture; ~15 lines splicing a constant into `_dotted_call_name` plus a `phi-to-log` widening that must be recalibrated against the two shipped sample helpers before it lands. |
| 92 | **#110** | DICOM Study/Series Instance UID de-duplication on the C-STORE SCP | 3 | 4 | _fill-in_ | DEMAND-GATE | Niche DICOM-only study collapse most partners never need, and the SR→HL7 case can already filter to SR objects code-first because `DicomPeek` exposes both UIDs (`messagefoundry/parsing/dicom/peek.py:105-106`), though no pure Router can hold the cross-message state; the remainder is a connector-side seen-UID ledger modelled on the existing durable `processed_files` precedent (`messagefoundry/store/base.py:844`, `prune_processed_files` at `:857`) plus an explicit FILTERED disposition on the suppressed 2..N objects at `_on_c_store`/`_commit` (`messagefoundry/transports/dicom.py:273`, `:368`), tested on all three backends. |
| 93 | **#113** | Outbound source-IP binding for sender connections | 3 | 4 | _fill-in_ | DEMAND-GATE | Niche interop knob only a source-IP-allowlisting partner on a multi-homed host needs, and OS routing already settles egress selection for everyone else; the bind must reach five dial sites — `transports/tcp.py:189`, `mllp.py:849`, `x12.py:158` via `asyncio.open_connection`, `remotefile.py:259` ftplib and `:396` paramiko, which takes a pre-bound `sock=` rather than a kwarg — plus the TOML/edit allowlists. |
| 94 | **#182** | Per-message base-address override for web-service senders | 3 | 4 | _fill-in_ | DEMAND-GATE | Niche sender-control knob with a clean one-connection-per-address fan-out, and its own severity note rates it minor; the difficulty is a per-message carry key on the ALREADY-SHIPPED ADR 0081 metadata channel — a reserved `http.url`-style key read where `outbound_headers_from_metadata` is read today (rest.py:1373) — plus wiring `consumes_metadata` onto SOAP and a delivery-time SSRF/egress re-check across three HTTP clients. No new store column and no 3-backend change. |
| 95 | **#131** | Object flagging - mark objects of interest + a Flagged Objects filter | 3 | 7 | _money pit_ | DEMAND-GATE | Difficulty 7 is right — ADR 0007's amendment declines the universal flag precisely because it needs a name-keyed annotation table across all three store backends, which is literally D7 ("a new ADR plus a 3-backend migration"). Value 2 is not: it rests on "connections are the objects an operator actually lists and filters, leaving only a marker on Routers/Handlers", and that understates the remainder. I read the write path: `Engine.set_connection_flag` (pipeline/engine.py:1401) raises WiringError when the connection is not in connections.toml — "a CODE-FIRST connection has no TOML home, so the console flag is refused there" — and api/app.py:1969-1972 maps that to 409. So the shipped half serves only TOML-managed connections, while this project's default authoring mode for connections is code-first Python, and this item's own Trigger names "an adopter with a LARGE CONFIG REPOSITORY" — exactly the case the shipped half refuses. The remainder is therefore a console-settable flag for code-first connections AND Routers/Handlers, not a cosmetic residue, so it is not "already substantially covered" (=2); it is reduced-scope console polish with partial coverage. Quadrant stays money pit; tier stays DEMAND-GATE per the verdict line. |
| 96 | **#214** | Intra-message concurrent transform of a message's routed rows | 3 | 8 | _money pit_ | P3 | Marginal residual on a lever an Accepted ADR closed — the transform-overlap half is merged and tested (`_process_routed_batch`, wiring_runner.py:5311), and ADR 0107 (Accepted 2026-07-13, 'authorizes no build. Do not build F2 or F3') bounds the ENTIRE `2H` transaction term this residual removes: arm E measured a ×2.95 swing in committed txn/msg moving throughput −11.7%, elasticity d(ln throughput)/d(ln txn) = −0.115, capping the residual's absolute best case at +13.2% at H=8; the remainder is still a batched multi-row `transform_handoff` on the stage handoff itself, ADR-gated, preserving claim→produce→complete atomicity on three backends. |
| 97 | **#155** | Server-to-server migration runbook | 2 | 1 | _fill-in_ | DEMAND-GATE | Every constituent step already ships documented — install, backup/restore/DR, decommission at `docs/EARLY-ADOPTER-GUIDE.md` §4/§10/§16 — so the gap is prose stitching, not capability; one new doc that orders them end-to-end, no code. |
| 98 | **#116** | File-size integrity re-check before disposition | 2 | 2 | _fill-in_ | DEMAND-GATE | Marginal additive hardening — the `min_age_seconds` quiescence window (`transports/file.py:728`) plus the single-shot whole-file read already close the partial-write hole this guards; a re-stat before move/delete in FileSource and RemoteFile is a small additive change on an existing seam. |
| 99 | **#135** | Configurable statistics push / refresh interval | 2 | 2 | _fill-in_ | DEMAND-GATE | Marginal tuning knob with no interop dimension — the fixed cadence serves live monitoring fine and no deployment has reported console bandwidth as material; the build is a validated settings field read by the push loop, where the cadence is a single `await asyncio.sleep(1.0)` at `messagefoundry/api/app.py:4945` and `config/settings.py:701` already carries the sibling `ws_allowed_origins`. |
| 100 | **#173** | Segment/segment-group subtree-copy helper | 2 | 2 | _fill-in_ | DEMAND-GATE | One-call sugar over an API that already does the hard part — `groups()` hands back the span view (`messagefoundry/parsing/message.py:470`) and `add_segment` grafts lines (`:377`), so the 'find the group boundary' boilerplate the item cites is mostly already solved; a small additive helper whose only subtlety is re-encoding across two messages' MSH separators. |
| 101 | **#174** | Scheduled automatic statistics reset | 2 | 2 | _fill-in_ | DEMAND-GATE | Manual re-snapshot ships (`Engine.reset_stats`, `messagefoundry/pipeline/engine.py:1772-1792`, behind `POST /statistics/reset` at `messagefoundry/api/app.py:2208`) and OTel covers daily volume, so a timer is convenience only; it assembles two shipped primitives — the ADR 0095 timezone-aware `Schedule` and the #160 stdlib cron evaluator — against an existing call. |
| 102 | **#84** | Diagnostic panes — hex body view + HL7-aware before/after diff + profiling/coverage | 2 | 3 | _fill-in_ | DEMAND-GATE | Substantially covered — hex, HL7-aware diff and coverage/profiling panes all ship, so what is left is a true-binary dump nobody is blocked on; the remainder is no longer client-side-only, since the dry-run read path must first surface the wire bytes the pure pane deliberately cannot recover (`ide/src/hexdump.ts:5-10`). |
| 103 | **#156** | Alert hysteresis (separate fire/clear thresholds) | 2 | 3 | _fill-in_ | DEMAND-GATE | Anti-flap refinement the shipped `realert_seconds` / per-rule `cooldown_seconds` throttle already damps (`messagefoundry/config/settings.py:2678`, `:2823`), with single-sided `min_depth`/`min_oldest_seconds` matching confirmed at `messagefoundry/pipeline/alert_sinks.py:617-623`; two new AlertRule fields plus clear-edge state in the sink, no store or migration. |
| 104 | **#105** | Deterministic Corepoint-import tooling — Action-List → code-first scaffold | 2 | 4 | _fill-in_ | DEMAND-GATE | The adopter already hand-ported and the AI `/migrate` covers the rest, with no named demand, so it ships little worth even if finished; the mapper and CLI are built, leaving reconciliation of the emitted mapping against a real Corepoint export and the deferred `ide/` wrapper — behind #313's multi-message Handler model, which this item cannot buy. |
| 105 | **#122** | Corrupted application-log detection, rollover, and connection-stop | 2 | 6 | _money pit_ | DEMAND-GATE | Value 2 stands — stdout + NSSM rotation, the RFC 5425 TLS syslog forwarder (`_TlsSysLogHandler`, logging_setup.py:281) and #50's disk metering already carry log durability and visibility, so this is marginal and substantially covered. But difficulty 5 prices the wrong shape of work. D5 is "a new connector/codec behind the transport registry" — this is not a connector. logging_setup.py's module docstring (lines 3-13) records that the engine "deliberately do[es] not add file handlers here" because NSSM owns rotation, and `grep FileHandler |
| 106 | **#64** | Throughput parity with Corepoint — measure-first performance roadmap (group-commit + lean-writes) | 1 | 1 | _fill-in_ | P3 | An index over levers that live in #62/#63/#47/#34, so it ships nothing runnable of its own, and the remainder is reconciling roadmap prose against a measurement that has already run and a lever already abandoned — a doc edit. But the gate this item was demand-gated ON has FIRED (ADR 0051 measure-first complete 2026-07-12; ADR 0099 → ABANDON; ADR 0107 closes Phase 4), so the DEMAND-GATE override no longer applies and the tier derives from the score: P3, fill-in. |
| 107 | **#238** | OpenFlow step-attribute completeness pass over the engine vocabulary | 1 | 1 | _fill-in_ | P3 | Ships nothing runnable — the output is a findings note, and the item itself concedes most attributes are already covered engine-side under other names (retry/timeout in connector and delivery semantics), with OpenFlow compatibility explicitly declined under ADR 0076 §7 and #26; a read of seven attributes against the vocabulary and a short write-up. |
| 108 | **#352** | Consult on enterprise AV coverage for SFTP- and file-connector ingest from outside the domain (ASVS 5.4.3 premise check) | 1 | 1 | _fill-in_ | P3 | The scan seam is real — `set_scan_hook` at `transports/file.py:802`, `scan_inbound_file` at `:828`, called via `asyncio.to_thread` from `transports/remotefile.py:901` — so the citations hold. The scoring does not. The rubric's value floor is written for exactly this item: `1` ships nothing runnable. The scorer's own why closes with "the deliverable is one conversation and its recorded answer, no code", which is self-refuting against a value of 6 ("real gap, awkward workaround" — there is no gap being closed here and nothing to work around; there is a question being asked). Worth-if-built for a consult item is the answer, and the answer alone changes no shipped behaviour; if it comes back "no", the WORK that follows (reopening 5.4.3, or shipping an ICAP-backed scan control) is a different, unfiled item that would carry its own score. Difficulty 1 is right. At value 1 the quadrant is fill-in and the tier is P3; the verdict "consult, then decide" is not one of the three DEMAND-GATE verdicts, so no override applies. |

---

## Ranked backlog — value × difficulty on a ten-level scale (re-scored 2026-07-10)

> ⬆️ **Superseded by the 2026-08-03 re-score above.** Kept as the record of the 2026-07-10
> pass. It scored 134 open items; ~40 have since closed and moved to the archive, and the
> distribution lines below were frozen at that date and never recomputed. Where this table and
> the one above disagree on a number, the one above wins; on **build state**, the per-item banner
> wins over both.

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
| 47 | **#114** | Directory validation toggle (perform vs suppress startup validation) | 5 | 2 | _fill-in_ | DEMAND-GATE | **PARTIAL (2026-08-03):** the INBOUND half is BUILT, and the outbound now raises a `WiringError` instead of silently ignoring the option. **Remainder = the outbound validation hook**, whose score needs revisiting: the "clean workaround via the on-demand test probe" holds for the inbound only — the outbound probe *creates* the directory, so a typo'd target is fabricated and reports delivered. Corepoint-parity File toggle to fail-fast on an invalid startup directory. |
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
| **ASVS 11.7.1 in-use memory encryption** | Low | **drop (N/A)** | XL | **`na` on the record** (closed by owner decision 2026-08-02; do not re-score). ⚠️ The verdict is right but the *reason* here is not: "unachievable for pure-Python on-prem" is **not** the ground. The engine does ship rungs 1–2 — they **report on** the platform property rather than **provide** it. The ground is that the verb names a CPU/firmware/hypervisor property, outside the declared scope of three software artifacts. See `docs/ASVS-ASSESSMENT-METHOD.md` §2. |
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
3. **Treat the ASVS L3 residuals as closed/N-A, not a staffing queue** — #377 + #378 merged; 11.7.1 is N/A (still true, and re-confirmed on the record 2026-08-02 — but on a different ground than this line assumed; see the 11.7.1 row above); WebAuthn #11 buys zero ASVS movement. The only live security item is the cheap least-priv default flip. ⚠️ **Do not read "residuals are closed" as a posture summary** — the survey is incomplete and most cells have never been read against the requirement text, so this line describes a *staffing* judgement, not coverage.
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

## 3. Per-key (partition-key) message ordering (long-term, nice-to-have)

> 🛠 **Decline overturned (2026-07-09).** A prioritization pass recommended DECLINE; the stated reason was **invalid**. Purity binds `@router` / `@handler` — **not connectors** (CLAUDE.md §8: “side effects (DB, network) belong in connections/transports”). This is an unfired **demand-gate**, not an architectural impossibility.

> 🔢 **Re-scored 2026-08-03 → DEMAND-GATE.** Value **6/10** · Difficulty **9/10** · _big bet_. The only order-preserving way to push one ordered feed past the ~60 msg/s one-lane-one-core bound; the engine-shard "workaround" is void (shards partition by connection) and the in-engine router-fanout substitute leaves transform serialized, so a real gap with only an awkward workaround. Nothing keyed exists (`partition_key`/`sequence_key`: zero hits in `messagefoundry/`), and keyed lane assignment with single-writer-per-lane over the durable outbox plus the A40 cross-key hazard is multi-week work sitting directly on the strict-FIFO invariant. Quadrant becomes big bet. _(was 5/10 · 9/10.)_

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

## base64 binary-carriage codec (+ HL7 OBX-5 ED embedding) — ADR 0028

> ✅ **SHIPPED (ADR 0028 Accepted, PR #437).** A pure-stdlib (`base64`) `parsing/` codec that carries arbitrary
> **bytes** over the str/TEXT ingress+store as unbroken standard base64 behind a self-describing **`mfb64:v1:`**
> marker, exposed as one encode / one decode on `RawMessage` (`from_bytes`, `.raw_bytes`, `.binary()`,
> `.is_binary`) plus OBX-5 ED embed/extract helpers — so binary bodies no longer hit the lossy/NUL-corrupting
> latin-1 round-trip. No new dependency. The substrate the **DICOM** codec (#24, ADR 0025) builds on. See
> [ADR 0028](adr/0028-base64-binary-carriage-codec.md).

---

## 62. Binary body carriage — store ciphertext / raw bodies as `VARBINARY`/`BLOB`/`bytea` instead of base64-in-`NVARCHAR` (storage efficiency) (P3, measure-gated)

> 🔢 **Re-scored 2026-08-03 → DEMAND-GATE.** Value **5/10** · Difficulty **7/10** · _money pit_. Corepoint-class ~60% at-rest win on SQL Server where the only workaround is a bigger disk, but it is measure-gated and never load-bearing on correctness; a carriage format change that re-opens ADR 0028's NUL-safe str/TEXT decision, needs its own ADR, and drags a dual-read migration over three backends and two live `mfenc:` versions.

> ⚠️ **AMENDED 2026-08-03 — the format this item plans to migrate is no longer `mfenc:v1`, and the default writer now binds each ciphertext to its cell.** The Type paragraph describes stored bodies as `mfenc:v1:<key_id>:<base64(nonce‖ct‖tag)>` and the catch plans a dual-read over "existing `mfenc:v1` base64 rows", but cell-bound **`mfenc:v2`** is the default writer: `[store].aad_bind` defaults `True` (`messagefoundry/config/settings.py:383`) and is passed straight through as `write_v2` when the cipher is built (`messagefoundry/store/base.py:1841`; `messagefoundry/store/crypto.py:36`), while legacy v1 rows still read dual-read and are upgraded in place by `rotate-key` (`settings.py:379`) — so a migration must expect **both** markers, not one. That **tightens** the catch rather than easing it: v2 folds `(table, column, primary-key)` into the GCM tag (`messagefoundry/store/crypto.py:155-175`), and the two columns this item would retype are bound that way on the write path today — `cell_aad("messages", "raw", mid)` and `cell_aad("queue", "payload", row_id)` (`messagefoundry/store/sqlserver.py:3430`, `:3452`) — so a carriage that lands a body under a different column name must **re-encrypt**, not merely re-encode. The carriage itself is untouched — `messages.raw` and `queue.payload` are still `NVARCHAR(MAX)` (`messagefoundry/store/sqlserver.py:1105`, `:1123`) — so the win, the own-ADR requirement and the measure-gate all stand as written.


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

## 64. Throughput parity with Corepoint — measure-first performance roadmap (group-commit + lean-writes, gated on the enterprise-box validation) (P2, owner / measure-gated)

> 🔢 **Re-scored 2026-08-03 → P3.** Value **1/10** · Difficulty **1/10** · _fill-in_. An index over levers that live in #62/#63/#47/#34, so it ships nothing runnable of its own, and the remainder is reconciling roadmap prose against a measurement that has already run and a lever already abandoned — a doc edit. But the gate this item was demand-gated ON has FIRED (ADR 0051 measure-first complete 2026-07-12; ADR 0099 → ABANDON; ADR 0107 closes Phase 4), so the DEMAND-GATE override no longer applies and the tier derives from the score: P3, fill-in. _(was 1/10 · 2/10.)_

> ⚠️ **AMENDED 2026-08-03 — the measure-first gate has RUN, and step 2 of the ordered plan is REFUSED, not gated.** The plan below still reads live — "Nothing builds before it" at step 1, and group-commit as "the #1 unbuilt durable-write lever … when built — *iff* the run shows durable-write-bound" at step 2 — but the measure-first phase completed 2026-07-12 on rig runs C1–C7 ([ADR 0051](adr/0051-corepoint-throughput-parity-strategy.md), banner at `:3`), group-commit itself was withdrawn ([ADR 0055](adr/0055-group-commit-durable-write.md)`:3-4`, "⛔ SUPERSEDED / WITHDRAWN … DO NOT BUILD THIS"), and the one surviving transaction-reduction lever was falsified by the pre-registered P0 run of 2026-07-13 — the intervention engaged (`committed_txns/msg` −28.5%) while throughput moved −0.56%, inside the pre-registered null band — closing Phase 4 ([ADR 0107](adr/0107-phase-4-is-closed-transaction-reduction-is-a-measured-dead-end.md)`:3` "Do not build F2 or F3", `:7` terminating ADR 0057 as "⛔ DO NOT PROMOTE", table at `:38-40`). ⚠️ **Do not read step 2 as schedulable.** What survives is at least step 3 — this item's index role over the storage-efficiency cluster (#62/#63/#47/#34), which the throughput measurement does not bear on; **re-read steps 4–5 against [ADR 0098](adr/0098-store-side-scaling-levers-are-exhausted-transaction-amortization-is-the-only-path-to-45m-day.md) before scheduling either**, and read the 2026-06-28 "honest verdict" figures below as pre-measurement history, not as the current state.


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

## 78. Custom message-definition data model + conformance validator; NCPDP codec

> 🔢 **Re-scored 2026-08-03 → DEMAND-GATE.** Value **5/10** · Difficulty **6/10** · _money pit_. Corepoint-parity persisted-definition model plus a report-only validator and an additive NCPDP codec, all cleanly worked around today by a code-first Handler, so useful breadth rather than a blocker; the whole scope is still remainder — NCPDP appears nowhere in `messagefoundry/` and `profile` is merely "reserved for a conformance-profile" (`messagefoundry/parsing/validate.py:56`) — spanning a new stored model the code reads, a validator, and a new codec class.

> **On-trigger / demand-gate.** Numbered for tracking only — build when the trigger below fires (“demand-gate, don’t schedule”).

**Cluster:** Declarative HL7 modeling. **Priority:** P3. **Verdict:** demand-gate.

**Scope:** A stored custom HL7 definition model (data the code reads) + a report-only conformance validator; an NCPDP codec.

**Trigger:** build when a modeling-heavy estate migration needs persisted custom definitions, **or** a real NCPDP feed appears.

**Why:** Split from the draft. The persisted-definition model + report-only validator are NEW and migration-relevant — but **must be data the code reads, never a GUI modeler**. NCPDP is a clean additive codec (like X12 / DICOM). The **"Fix-All" auto-repair half is pulled out — see #80 (declined)**.

**Source:** promoted from [#52](archive/backlog/BACKLOG-CLOSED.md#52-corepoint-capability-parity-gaps--prioritized-roadmap-input-2026-06-27) gap synthesis (adversarially reviewed, 2026-06-28).

---

## 81. Alert escalation tiers + day/time thresholds + content (Action-Point) alerting

> 🔢 **Re-scored 2026-08-03 → DEMAND-GATE.** Value **5/10** · Difficulty **3/10** · _fill-in_. Content-triggered ("Action Point") alerting is genuine Corepoint parity that nothing outside the tests can fire, but the escalation and schedule two-thirds already ship, leaving metadata-only breadth rather than a blocker; the remainder is hoisting `content_match` (`messagefoundry/pipeline/alert_sinks.py:726`) onto the `AlertSink` Protocol (`messagefoundry/pipeline/alerts.py:27`), exporting an emitter a Handler can reach without breaking re-run purity, and surfacing the already-durable `escalation_tier` (`messagefoundry/store/postgres.py:449`) on `AlertInstanceInfo`, which omits it (`messagefoundry/api/models.py:255-275`). _(was 5/10 · 4/10.)_
> **On-trigger / demand-gate.** Numbered for tracking only — build when the trigger below fires (“demand-gate, don’t schedule”).

> **AMENDED 2026-07-28 — two of the three named sub-capabilities are BUILT; do not rebuild them.** Adversarial verification (2 lenses) refuted a full close, so this stays open — but narrowed. **BUILT and persisted across all three backends:** escalation tiers and schedule-aware thresholds ([ADR 0133](adr/0133-alert-escalation-tiers-schedule-aware-thresholds-and-content-triggered-alerts-the-56-remainder.md)), including the per-key escalation state the notifier drops on resolve (`messagefoundry/api/app.py:2367`, `:2541`) and the occurrence-driven tier count surfaced on the rules API (`:4316`).
>
> ⚠️ **The REMAINDER is the third sub-capability — content (Action-Point) alerting — and it is plumbing with no reachable trigger.** `content_match` exists on the concrete notifier (`messagefoundry/pipeline/alert_sinks.py:669`, event shape at `:677`, label routing at `:553`) but is **not on the `AlertSink` Protocol** (`messagefoundry/pipeline/alerts.py:27`), and the engine holds its sink as `self._alert_sink: AlertSink` (`messagefoundry/pipeline/wiring_runner.py:731`) — which is also `LoggingAlertSink` whenever no `[alerts]` transport is configured. A Handler is passed only the payload and no alert emitter is exported, so **nothing outside the tests can ever fire it**. Second, smaller gap: the persisted `escalation_tier` is never surfaced on `AlertInstanceInfo` / `GET /alerts/active`, which does not match ADR 0133 D1's stated outcome. Build **only** those two things.

**Cluster:** Operational/monitoring (alert remainder). **Priority:** P2. **Verdict:** demand-gate.

**Scope:** Escalation tiers, schedule-aware thresholds, and payload-content-triggered alerts on top of the shipped resolvable alert-state (#56).

**Trigger:** build when operators need escalation / scheduling / content-alerting beyond the #56 ack/resolve model.

**Why:** #56 shipped the resolvable-state half (0.2.10, ADR 0044). Escalation / day-time / Action-Point is the confirmed NEW remainder. Metadata-only (no new PHI tier).

**Source:** promoted from [#52](archive/backlog/BACKLOG-CLOSED.md#52-corepoint-capability-parity-gaps--prioritized-roadmap-input-2026-06-27) gap synthesis (adversarially reviewed, 2026-06-28).

---

## 83. Rich file-output disposition + FTPS / SFTP variants

> 🔢 **Re-scored 2026-08-03 → DEMAND-GATE.** Value **3/10** · Difficulty **3/10** · _fill-in_. Niche file/FTP interop knobs most partners never need, and the ones that bite are transport-side where no Handler can substitute; all of it is per-driver additive on two connectors — `FileDestination` still has no append, dated-subfolder archive or header/trailer framing knob, and `remotefile` is explicit-`FTP_TLS` only with no implicit/passive toggle or keyboard-interactive auth (`messagefoundry/transports/remotefile.py:13`, `:256-262`).

> **On-trigger / demand-gate.** Numbered for tracking only — build when the trigger below fires (“demand-gate, don’t schedule”).

**Cluster:** Minor gaps. **Priority:** P3. **Verdict:** demand-gate.

**Scope:** Append mode, dated-subfolder archiving, header/trailer framing on FileDestination; FTPS implicit + active/passive + SFTP keyboard-interactive on remotefile.

**Trigger:** build when a partner file feed needs append/archive/framing, or an FTPS-implicit / KBI-auth server.

**Why:** Gaps confirmed; **basic control-id/type archive-naming already exists** (`file.py`) — the gap is **append / dated-subfolder-archive / header-trailer framing**, plus `remotefile.py` is **explicit-FTPS only** (no implicit/passive toggle or KBI). Per-driver additive.

**Source:** promoted from [#52](archive/backlog/BACKLOG-CLOSED.md#52-corepoint-capability-parity-gaps--prioritized-roadmap-input-2026-06-27) gap synthesis (adversarially reviewed, 2026-06-28).

---

## 84. Diagnostic panes — hex body view + HL7-aware before/after diff + profiling/coverage

> 🔢 **Re-scored 2026-08-03 → DEMAND-GATE.** Value **2/10** · Difficulty **3/10** · _fill-in_. Substantially covered — hex, HL7-aware diff and coverage/profiling panes all ship, so what is left is a true-binary dump nobody is blocked on; the remainder is no longer client-side-only, since the dry-run read path must first surface the wire bytes the pure pane deliberately cannot recover (`ide/src/hexdump.ts:5-10`). _(was 4/10 · 2/10.)_

> **On-trigger / demand-gate.** Numbered for tracking only — build when the trigger below fires (“demand-gate, don’t schedule”).

> 📐 **Partly promoted by [MULTISESSION-PLAN-7](releases/MULTISESSION-PLAN-7.md):** the **HL7-segment/field-aware before/after diff** (lane **L4**, client-side TS, no engine change) and **profiling + coverage** panes (lane **L7**, consuming the [ADR 0072](adr/0072-traced-dryrun-mode.md) traced dry-run) are scheduled as part of the no-AI build experience. The **hex / `mfb64:` pane** stays demand-gated.

**Cluster:** Minor gaps (console/IDE). **Priority:** P3. **Verdict:** demand-gate.

**Scope:** A hex pane for binary / `mfb64:` bodies, an HL7-aware before/after diff in the Test Bench, and coverage/profiling panes.

**Trigger:** build when operators / authors need hex / diff / coverage diagnostics beyond the current views.

**Why:** An explicit #52 Minor-gap line. Console/IDE-only, no engine change. **Visualization / diagnostics, not logic authoring — does not trip #26.** Identity-safe.

**Source:** promoted from [#52](archive/backlog/BACKLOG-CLOSED.md#52-corepoint-capability-parity-gaps--prioritized-roadmap-input-2026-06-27) gap synthesis (adversarially reviewed, 2026-06-28).

---

## 85. Cloud object-store + generic message-bus destinations

> 🔢 **Re-scored 2026-08-03 → DEMAND-GATE.** Value **5/10** · Difficulty **6/10** · _money pit_. Corepoint-parity transport breadth with a clean workaround — the pluggable destination registry lets an adopter write the connector code-first — and nothing exists today (`transports/` carries no object-store or bus driver; `pyproject.toml` names no boto3/azure/google-cloud/kafka dependency). But the scored remainder is the whole scope: four-plus drivers, four vetted dependencies through the hash-locked lock file, plus credential sourcing and egress allow-listing on each, which exceeds the single-connector band 5. Quadrant becomes money pit. _(was 5/10 · 5/10.)_

> **On-trigger / demand-gate.** Numbered for tracking only — build when the trigger below fires (“demand-gate, don’t schedule”).

**Cluster:** Minor gaps. **Priority:** P3. **Verdict:** demand-gate.

**Scope:** S3 / Azure Blob / GCS outbound; a *generic* AMQP/Kafka destination.

**Trigger:** build when a real cloud-blob drop or a generic-bus feed appears (NOT a Java JMS broker).

**Why:** An explicit #52 Minor-gap transport line, distinct from the #25 JMS decline. S3/cloud-blob is a destination (not a broker coupling) — identity-neutral; the generic AMQP/Kafka lane is the on-trigger candidate #25 explicitly preserved. **JMS-specific stays #25-declined.**

**Source:** promoted from [#52](archive/backlog/BACKLOG-CLOSED.md#52-corepoint-capability-parity-gaps--prioritized-roadmap-input-2026-06-27) gap synthesis (adversarially reviewed, 2026-06-28).

---

## 94. External BLOB-server offload for embedded documents — replace inline base64 with a stored-object pointer (OBX-5 RP) (P2, on-trigger)

> 🛠 **Decline overturned (2026-07-09).** A prioritization pass recommended DECLINE; the stated reason was **invalid**. Purity binds `@router` / `@handler` — **not connectors** (CLAUDE.md §8: “side effects (DB, network) belong in connections/transports”). This is an unfired **demand-gate**, not an architectural impossibility.

> 🔢 **Re-scored 2026-08-03 → DEMAND-GATE.** Value **6/10** · Difficulty **6/10** · _big bet_. The strongest store-bloat lever for document-heavy feeds with only awkward workarounds (more disk, purge history), and ADR 0105 already reserved the pointer format and deref seam it plugs into (`messagefoundry/parsing/binary.py:55-62` `DOC_REF_MARKER`, shared-seam note at `:252`, content-address contract at `:264-266`); the remainder is still a pluggable BLOB connector family, a per-connection offload setting across three backends, and an ADR fixing where a write side-effect sits against the at-least-once invariant. _(was 6/10 · 5/10.)_

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

> 🔢 **Re-scored 2026-08-03 → DEMAND-GATE.** Value **6/10** · Difficulty **3/10** · _quick win_. A customer's own Azure OpenAI / Bedrock / in-house endpoint is precisely this item's ask and today fails as an opaque 502 rather than a config error, with BYO the only workaround and one that forfeits the central audit the customer wanted; the broker, audit and egress allow-list already ship, so the remainder is per-provider wire shapes behind `chat()`, a validator that refuses an unserviced `provider`, and the stale `docs/AI.md:22` line. _(was 5/10 · 6/10.)_

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

> 🔢 **Re-scored 2026-08-03 → DEMAND-GATE.** Value **6/10** · Difficulty **6/10** · _big bet_. An adopter-run pre-cutover capacity number has no substitute but the manual dev-harness-plus-TUNING-BASELINE exercise, so a real gap with an awkward workaround. The reuse premise is measured false — `knee` appears in `harness/` only in TOML profile comments and `__main__.py` has no `capacity`/`setup-test` subcommand — so the knee-finder, the non-filling per-step gate, the `/stats` staleness precondition and the isolated-store guard are net-new across CLI + engine + store + metrics: rubric band 6. It is not a 7: there is no 3-backend migration, and ADR 0074 already exists and needs amending, not writing. Quadrant stays big bet. _(was 6/10 · 5/10.)_
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

## 98. Kerberos SSO channel-binding (EPA) opt-in + acceptor-enforcement spike (P3, on-trigger)

> 🔢 **Re-scored 2026-08-03 → DEMAND-GATE.** Value **3/10** · Difficulty **3/10** · _fill-in_. Narrow EPA hardening on an opt-in in-process-TLS SSO mode nobody is blocked on, and structurally void behind a TLS-terminating proxy, so a niche interop knob at best; the acceptors are still constructed with no bindings at all (`spnego.server(service=…)` / `spnego.server()` at `messagefoundry/auth/ldap.py:300-302`, `:360-362`, with no `channel_bindings` argument or CBT knob anywhere), so the work is a spike plus one conditional per-mode flag — but the answer needs the same domain lab #99(e) is blocked on.

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

> 🚧 **PARTIAL (built 2026-07-12).** Value **5/10** · Difficulty **3/10** · _fill-in_. Turnkey polish shipped; the **live domain-lab smoke deferred** (needs a real DC + AD CS + gMSA, same gate as #98). **Shipped:** (a) `install-service.ps1` gMSA preflight — `Test-ADServiceAccount` for a `-ServiceAccount` ending in `$` + `secedit`-granted **`SeServiceLogonRight`** before NSSM registration, both **degrading gracefully** on a non-domain/RSAT-less box (skip-with-message, never abort); `-SkipGmsaPreflight` to opt out. (b) `-AllowLocalSystem` opt-out + enhanced LocalSystem warning — enforced **now** as warn + acknowledgement; the **default-FLIP to refuse** is honestly recorded as **gated on the `windows-service-smoke` CI leg** (not flipped live, so no unattended install breaks). (d) **IIS + ARR** reverse-proxy-mTLS reference config added to `docs/security/OFF-LOOPBACK-DEPLOYMENT.md` (require client cert, preserve `X-Forwarded-Proto`/`-For`, exact-peer `trusted_proxies`, placeholders only) beside the existing nginx/Caddy. (f) integrated + gMSA **worked example** in `docs/DEPLOY-SERVER-DB.md §1.1` (`[store].auth=integrated` → `Trusted_Connection=yes`, NSSM `ObjectName=CORP\svc$`, `CREATE LOGIN [CORP\svc$] FROM WINDOWS` least-priv grant) + cross-ref in `CONFIGURATION.md`; **SPN checklist finalized** in OFF-LOOPBACK-DEPLOYMENT.md (gMSA SPN on the account object, "Log on as a service", `PrincipalsAllowedToRetrieveManagedPassword`, IIS/ARR `Negotiate` pass-through). **(c) Windows cert-store (thumbprint) sourcing for `[api]` TLS — SCOPED OUT** (documented, not built): Python `ssl` is OpenSSL not SChannel, and `load_cert_chain` needs cert+key **files**; a non-exportable CNG key in `LocalMachine\My` cannot be handed to OpenSSL, so a store-thumbprint `[api]` TLS source is stdlib-infeasible (same shape as the ECH scope-out, ADR 0093) — supported paths documented instead (terminate at IIS/ARR which *can* use the machine store by thumbprint, or export an AD CS cert to PEM). **Deferred/scoped-out:** (e) real domain-lab gMSA/SSO/reverse-proxy smoke (live DC + AD CS + gMSA — same gate as #98); (g) engine-side "require an AD MFA claim" hook (build only on a customer requirement). No ADR (decisions folded into the deployment docs, per the item plan). _(was 🔢 DEMAND-GATE · Value 6/10 · Difficulty 6/10.)_

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

## 105. Deterministic Corepoint-import tooling — Action-List → code-first scaffold (P3, deferred, owner decision)

> 🔢 **Re-scored 2026-08-03 → DEMAND-GATE.** Value **2/10** · Difficulty **4/10** · _fill-in_. The adopter already hand-ported and the AI `/migrate` covers the rest, with no named demand, so it ships little worth even if finished; the mapper and CLI are built, leaving reconciliation of the emitted mapping against a real Corepoint export and the deferred `ide/` wrapper — behind #313's multi-message Handler model, which this item cannot buy. _(was 2/10 · 6/10.)_

> **AMENDED 2026-07-28 — the stated blocker is discharged; the real gate is a different item.** This item has been carried as blocked on an *"input schema SYNTHETIC-until-validated"* premise. That premise no longer holds: [ADR 0086](adr/0086-deterministic-corepoint-import.md) **Amendment 2026-07-24 §2(a′)** supersedes the old JSON model (`:46-49` marks the synthetic format *SUPERSEDED*) — the input is now a **validated XML** format, parsed through `defusedxml` (`messagefoundry/corepoint_import.py:81`, with the security rationale at `0086:124`). ⚠️ **This does NOT make the item schedulable.** The real gate is **#313** (the multi-message Handler model — the import refuses ~2,000 statements without it), and #313 is **invisible from this published baseline**, which ends at #231. Do not read the discharged blocker as a green light; the item stays P3 and demand-gated behind #313.

**Type:** migration / DX (large). The deterministic sibling for the AI `/migrate` — the **one open gap** in the AI-off completeness matrix ([`docs/AI-OFF-MATRIX.md`](AI-OFF-MATRIX.md)).

**Partial build (PLAN-9 Wave 3, 2026-07-10 — branch `plan9-ideimport`):** the **deterministic importer + CLI is BUILT** ([ADR 0086](adr/0086-deterministic-corepoint-import.md)): `messagefoundry import corepoint <export> --out <dir>` — a pure, stdlib-only parser emitting one code-first `@router`/`@handler` module per channel calling the ADR 0076 vocabulary (the **inverse** of ADR 0076 §2's mapping); unmapped actions become in-place `# TODO` + best-effort stubs (never dropped); untrusted export values ride as `json.dumps`-escaped literals. **Correctness gate met** — emitted modules pass `messagefoundry check` **and** round-trip through `lens parse`. **Item stays OPEN** — the Corepoint **input schema is SYNTHETIC-until-validated** (no real export in-repo; #87 recon git-ignored), so its field names / nesting / ~71-action inventory must be reconciled against a real Corepoint export before production use; the optional `ide/` TS wrapper is deferred.

**What:** a non-AI import path that reads exported Corepoint Action-Lists / connection config and scaffolds **editable code-first Router/Handler Python** (best-effort, human-finished) — so a PHI-environment migrator who cannot use the AI `/migrate` subcommand still has a deterministic starting point.

**Why deferred / owner-gated:** larger than the PLAN-7 lanes — needs its own scope (which Corepoint export format; how much of the ~71-action catalog maps deterministically vs. needs hand-finishing) and its own ADR. Not agent-buildable in the PLAN-7 waves; surfaced here so the gap is tracked, not silently built. Stays inside #26 (emits editable Python, not a declarative logic surface).

**Source:** MULTISESSION-PLAN-7 AI-off completeness audit (2026-07-06).

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

## 108. Receiver-side 'Prefer BOM if present' encoding auto-detect

> 🔢 **Re-scored 2026-08-03 → DEMAND-GATE.** Value **3/10** · Difficulty **2/10** · _fill-in_. A configured per-connection `encoding` already covers any single-encoding feed cleanly — it is plumbed through to `normalize(raw, *, encoding=…)` on the hot path (`messagefoundry/parsing/peek.py:152-162`) and accepts `utf-8-sig`/`utf-16-le`/`utf-16-be` — leaving only the niche mixed-BOM override, a niche interop knob; the remainder is a small additive sniff on the decode path, since no UTF-16 byte-order mark is detected anywhere today.

> **On-trigger / demand-gate.** Numbered for tracking only — build when the trigger below fires (“demand-gate, don’t schedule”).

> ⚠️ **AMENDED 2026-08-04 — the hardware blocker has an EXPIRY DATE now.** This item is gated on a
> controlled multi-VM lab that the project did not own; one is ~2 weeks out as of 2026-08-04, so any
> sentence below saying the rig is unavailable, unregistered or not the project's to provide is
> **true today and scheduled to become false**. Do not read it as a permanent block. Tracked by
> **[#1003](#1003-validate-the-lab-and-discharge-the-four-hardware-gated-residuals)**, which fires on
> *lab available for validation* and carries this item's run: its residual is the live domain-lab gMSA / SSO / reverse-proxy smoke, and that is the ONLY thing left on this item.

> ⚠️ **AMENDED 2026-08-04 — the hardware blocker has an EXPIRY DATE now.** This item is gated on a
> controlled multi-VM lab that the project did not own; one is ~2 weeks out as of 2026-08-04, so any
> sentence below saying the rig is unavailable, unregistered or not the project's to provide is
> **true today and scheduled to become false**. Do not read it as a permanent block. Tracked by
> **[#1003](#1003-validate-the-lab-and-discharge-the-four-hardware-gated-residuals)**, which fires on
> *lab available for validation* and carries this item's run: it needs the same real DC + AD CS the #99 smoke does.

**Cluster:** Connections & Transports. **Priority:** P3. **Verdict:** demand-gate. **Severity (vs Corepoint):** minor.

**Scope:** A receiver-side option where a byte-order mark detected on the incoming file overrides the connection's configured encoding (notably UTF-16 LE/BE).

**Trigger:** build when an inbound feed delivers UTF-16 (or mixed-encoding) files whose byte-order mark must override the configured encoding.

**Why:** Partial. Per-connection text encoding is already built — every connector (File/TCP/MLLP/REST/SOAP/DB/SFTP) takes an `encoding` setting (default `utf-8`, any Python codec name, so `utf-8-sig`/`utf-16-le`/`utf-16-be` all work); the only residual gap is a receiver-side "prefer BOM if present" auto-detect that overrides the configured encoding, since today only a leading UTF-8 BOM is sniffed/stripped and a UTF-16 LE/BE BOM is not detected to switch the decode.

**Nearest existing mechanism:** Per-connection `encoding` setting on every transport (File source/destination, TCP, MLLP, X12, REST, SOAP, database, remotefile/SFTP) — `settings.encoding`, default `"utf-8"`, plumbed to `.encode()`/`.decode()` and to `parsing/peek.py::normalize(encoding=...)`; accepts any Python codec name including `utf-8-sig` (UTF-8 w/ BOM), `utf-16`, `utf-16-le`, `utf-16-be`.

**Source:** Corepoint v8.1.0 help-export coverage sweep (2026-07-09) — five adversarially-verified passes over the full help export (1,569 pages); absence re-verified against `origin/main` before filing. Cross-ref [#52](archive/backlog/BACKLOG-CLOSED.md#52-corepoint-capability-parity-gaps--prioritized-roadmap-input-2026-06-27).

---

## 110. DICOM Study/Series Instance UID de-duplication on the C-STORE SCP

> 🛠 **Decline overturned (2026-07-09).** A prioritization pass recommended DECLINE; the stated reason was **invalid**. Purity binds `@router` / `@handler` — **not connectors** (CLAUDE.md §8: “side effects (DB, network) belong in connections/transports”). This is an unfired **demand-gate**, not an architectural impossibility.
>
> **Build constraints:** Build at the connector, not in a Router/Handler. (1) Honor count-and-log: suppressed duplicate instances (the 2..N objects per Study/Series UID) must still be persisted with an explicit disposition such as FILTERED — never silently dropped, since each C-STORE object is a received-and-ACKed message. (2) The de-dup "seen-UID" state lives on the connector (analogous to FileSource's processed-file tracking); it must survive connector/engine restart, or a bounded reset window on restart must be explicitly documented…

> 🔢 **Re-scored 2026-08-03 → DEMAND-GATE.** Value **3/10** · Difficulty **4/10** · _fill-in_. Niche DICOM-only study collapse most partners never need, and the SR→HL7 case can already filter to SR objects code-first because `DicomPeek` exposes both UIDs (`messagefoundry/parsing/dicom/peek.py:105-106`), though no pure Router can hold the cross-message state; the remainder is a connector-side seen-UID ledger modelled on the existing durable `processed_files` precedent (`messagefoundry/store/base.py:844`, `prune_processed_files` at `:857`) plus an explicit FILTERED disposition on the suppressed 2..N objects at `_on_c_store`/`_commit` (`messagefoundry/transports/dicom.py:273`, `:368`), tested on all three backends.

> **On-trigger / demand-gate.** Numbered for tracking only — build when the trigger below fires (“demand-gate, don’t schedule”).

**Cluster:** Connections & Transports. **Priority:** P2. **Verdict:** demand-gate. **Severity (vs Corepoint):** moderate.

**Scope:** Storage-SCP option to forward only the FIRST instance per Study/Series Instance UID, collapsing a multi-image study into one downstream message at the connector.

**Trigger:** build when an adopter routes DICOM studies and needs one downstream message per study rather than per image.

**Why:** Real gap. The C-STORE SCP commits every received object as its own ingress message (`_on_c_store`/`_commit` in transports/dicom.py) and has no Study/Series-Instance-UID de-duplication to forward only the first instance per study; the closest lever, DicomPeek exposing those UIDs to a Router, cannot collapse a study because Routers/Handlers must stay pure (no cross-message "seen-UID" state), so this connector-level first-instance-only behavior is absent.

**Nearest existing mechanism:** The inbound DICOM C-STORE SCP (`transports/dicom.py`, `_on_c_store`/`_commit`) plus `DicomPeek` (`parsing/dicom/peek.py`), which exposes `StudyInstanceUID`/`SeriesInstanceUID` for code-first Router/Handler routing — but has no cross-message state to suppress subsequent instances.

**Source:** Corepoint v8.1.0 help-export coverage sweep (2026-07-09) — five adversarially-verified passes over the full help export (1,569 pages); absence re-verified against `origin/main` before filing. Cross-ref [#52](archive/backlog/BACKLOG-CLOSED.md#52-corepoint-capability-parity-gaps--prioritized-roadmap-input-2026-06-27).

---

## 113. Outbound source-IP binding for sender connections

> 🔢 **Re-scored 2026-08-03 → DEMAND-GATE.** Value **3/10** · Difficulty **4/10** · _fill-in_. Niche interop knob only a source-IP-allowlisting partner on a multi-homed host needs, and OS routing already settles egress selection for everyone else; the bind must reach five dial sites — `transports/tcp.py:189`, `mllp.py:849`, `x12.py:158` via `asyncio.open_connection`, `remotefile.py:259` ftplib and `:396` paramiko, which takes a pre-bound `sock=` rather than a kwarg — plus the TOML/edit allowlists. _(was 3/10 · 3/10.)_

> **On-trigger / demand-gate.** Numbered for tracking only — build when the trigger below fires (“demand-gate, don’t schedule”).

**Cluster:** Connections & Transports. **Priority:** P3. **Verdict:** demand-gate. **Severity (vs Corepoint):** minor.

**Scope:** Bind an outbound socket to a specific local source IP on a multi-homed host (TCP/IP senders and FTP endpoints).

**Trigger:** build when an engine runs on a multi-homed host and a partner requires traffic to originate from a specific source IP.

**Why:** Real gap. Outbound sender sockets cannot be pinned to a specific local source IP on a multi-homed host: the per-connection bind_address / [inbound].bind_host binding controls only inbound listeners, and every outbound dial (MLLP/TCP/X12 asyncio.open_connection, FTP/SFTP connect) omits local_addr/source_address, leaving egress source selection to OS routing.

**Nearest existing mechanism:** InboundConnection.bind_address (per-connection listen-interface override, canonicalized via _normalize_bind_host in config/wiring.py) plus the service-level [inbound].bind_host setting — but both are inbound-listener-only. Outbound senders (transports/mllp.py, tcp.py, x12.py via asyncio.open_connection; remotefile.py FTP via ftp.connect and paramiko SFTP) dial with no local_addr/source_address, so the OS picks the source IP by route.

**Source:** Corepoint v8.1.0 help-export coverage sweep (2026-07-09) — five adversarially-verified passes over the full help export (1,569 pages); absence re-verified against `origin/main` before filing. Cross-ref [#52](archive/backlog/BACKLOG-CLOSED.md#52-corepoint-capability-parity-gaps--prioritized-roadmap-input-2026-06-27).

---

## 114. Directory validation toggle (perform vs suppress startup validation)

> 🔢 **Re-scored 2026-08-03 → DEMAND-GATE.** Value **6/10** · Difficulty **3/10** · _quick win_. The old score's "clean workaround via the on-demand test probe" does not exist in the direction that remains — both destinations' `test_connection` *create* the target directory, so the probe cannot answer the question the toggle asks, which is what lifts this off the parity-with-a-workaround band; the silent-ignore half is closed (PR #162 raises `WiringError` on `File(validate_directory=True)` for an outbound), leaving only the validation hook — a `validate_startup` on the `DestinationConnector` contract plus a runner outbound start-path call, mirroring the source seam already at `transports/base.py:436`. _(was 5/10 · 2/10.)_
> **On-trigger / demand-gate.** Numbered for tracking only — build when the trigger below fires (“demand-gate, don’t schedule”).

> **AMENDED 2026-08-03 — the INBOUND half and the outbound WIRING REJECTION are BUILT; only the outbound validation HOOK remains.** Adversarial verification refuted a full close. **BUILT 2026-07-28:** `validate_directory` on the File/RemoteFile source (`messagefoundry/transports/file.py:311`, `remotefile.py:735`) with its opt-in at-start check (`file.py:389-398`) — a no-mkdir probe that reports the connection `failed` at start rather than deferring to first poll (`file.py:170`). **BUILT 2026-08-03:** the option on an **outbound** is now a **`WiringError` at bind** (`build_outbound_connection`, `messagefoundry/config/wiring.py`) instead of being accepted and silently ignored. That is the single choke point both code-first `outbound()` and the `connections.toml` loader (ADR 0007) pass through, so one guard covers both authoring surfaces; it is truthy-only, so the `False` the factories always write into settings is unaffected and every outbound authored today builds byte-identically.
>
> ⚠️ **REMAINDER: the outbound validation HOOK — and this item's scoring rationale is WRONG for that direction.** `DestinationConnector` still has no `validate_startup` hook and `FileDestination` still `mkdir`s on write. The "clean workaround via the on-demand test probe" cited in the score above **does not exist on an outbound**: both destinations' `test_connection` *create* the target directory (see ADR 0031's 2026-08-03 follow-on for the call chain), so nothing shipped can tell "the directory exists" from "I just made it" — a typo'd target path is fabricated and every message reports delivered. **Re-score against that.** And if the hook is built, build it **together with** suppressing the mkdir-on-write under the flag: a start-time-only check leaves the run-time fabrication intact under a setting name that promises otherwise.

**Cluster:** Connections & Transports. **Priority:** P3. **Verdict:** demand-gate. **Severity (vs Corepoint):** minor.

**Scope:** Per-connection File option: validate directory paths at startup (invalid means not-started) or defer validation to run time, for intermittently-available remote directories.

**Trigger:** build when a File connection points at an intermittently-available remote directory and must not fail startup validation.

**Why:** Partial. MessageFoundry always defers File directory validation to run time (FileSource._run logs-and-retries when the poll directory is unreachable; FileDestination mkdir's on write), which matches Corepoint's defer mode, but there is no per-connection toggle to instead validate the directory at startup and refuse to start (mark not-started) on an invalid path — the writability probe (_probe_dir_writable / test_connection) runs only on demand via POST /connections/{name}/test, not at startup.

**Nearest existing mechanism:** The on-demand reachability probe POST /connections/{name}/test (api/app.py), backed by FileSource/FileDestination.test_connection → _probe_dir_writable (transports/file.py); plus the implicit run-time tolerance already built into FileSource._run (a scan error when the watch dir is missing/unreadable is logged and retried next poll, never crashes the connection) and FileDestination._write (mkdir(parents=True, exist_ok=True) on each write). Startup fault-isolation (ADR 0031) isolates connectors that fail to build/bind, but File connectors do not validate the directory at construction, so a missing directory never fails startup.

**Source:** Corepoint v8.1.0 help-export coverage sweep (2026-07-09) — five adversarially-verified passes over the full help export (1,569 pages); absence re-verified against `origin/main` before filing. Cross-ref [#52](archive/backlog/BACKLOG-CLOSED.md#52-corepoint-capability-parity-gaps--prioritized-roadmap-input-2026-06-27).

---

## 116. File-size integrity re-check before disposition

> 🔢 **Re-scored 2026-08-03 → DEMAND-GATE.** Value **2/10** · Difficulty **2/10** · _fill-in_. Marginal additive hardening — the `min_age_seconds` quiescence window (`transports/file.py:728`) plus the single-shot whole-file read already close the partial-write hole this guards; a re-stat before move/delete in FileSource and RemoteFile is a small additive change on an existing seam.

> **On-trigger / demand-gate.** Numbered for tracking only — build when the trigger below fires (“demand-gate, don’t schedule”).

**Cluster:** Connections & Transports. **Priority:** P3. **Verdict:** demand-gate. **Severity (vs Corepoint):** minor.

**Scope:** Compare a source file's size at read time against its size at disposition; if it changed, error the message rather than enqueue a partially-written file.

**Trigger:** build when a partner writes files in place (no temp-then-rename) and the mtime cutoff proves insufficient.

**Why:** Real gap. File and RemoteFile sources guard against partial writes only proactively via `min_age_seconds` (a mtime quiescence window) and read the whole file in one shot before moving it, but never re-compare the source file's size between read and disposition to error a file that grew or was truncated mid-processing.

**Nearest existing mechanism:** FileSource/RemoteFile source setting `min_age_seconds` (transports/file.py `_candidates`, docs/CONNECTIONS.md) — skips files modified within a quiescence window to avoid reading partial writes; plus the whole-file single-shot `read_bytes()`/`retrieve` before move/delete. No size-at-read vs size-at-disposition comparison exists.

**Source:** Corepoint v8.1.0 help-export coverage sweep (2026-07-09) — five adversarially-verified passes over the full help export (1,569 pages); absence re-verified against `origin/main` before filing. Cross-ref [#52](archive/backlog/BACKLOG-CLOSED.md#52-corepoint-capability-parity-gaps--prioritized-roadmap-input-2026-06-27).

---

## 122. Corrupted application-log detection, rollover, and connection-stop

> 🔢 **Re-scored 2026-08-03 → DEMAND-GATE.** Value **2/10** · Difficulty **6/10** · _money pit_. Value 2 stands — stdout + NSSM rotation, the RFC 5425 TLS syslog forwarder (`_TlsSysLogHandler`, logging_setup.py:281) and #50's disk metering already carry log durability and visibility, so this is marginal and substantially covered. But difficulty 5 prices the wrong shape of work. D5 is "a new connector/codec behind the transport registry" — this is not a connector. logging_setup.py's module docstring (lines 3-13) records that the engine "deliberately do[es] not add file handlers here" because NSSM owns rotation, and `grep FileHandler _(was 2/10 · 5/10.)_

> **On-trigger / demand-gate.** Numbered for tracking only — build when the trigger below fires (“demand-gate, don’t schedule”).

**Cluster:** Logging & Audit. **Priority:** P3. **Verdict:** demand-gate. **Severity (vs Corepoint):** minor.

**Scope:** On a corrupted or unwritable application log, rename it, roll to a fresh file, record the event, and stop the affected connection if the new file also cannot be written.

**Trigger:** build when a corrupted or unwritable application log silently stops recording engine activity.

**Why:** Real gap. The engine writes logs only to stdout (rotation is delegated to NSSM) and has no engine-managed log-file lifecycle, so there is no detection of a corrupted/unwritable application log, no rename-and-roll to a fresh file, no recorded rollover event, and no fail-closed connection stop when the replacement file is also unwritable; the nearest existing pieces are logging_setup.py's stdout handler, BACKLOG #50's GET /status app-log disk metering (visibility only), and ADR 0014's connection_stopped rule (which does not react to log-write failures).

**Nearest existing mechanism:** logging_setup.py (stdout StreamHandler + optional off-box SysLogHandler; NSSM externally rotates the captured stdout files) and BACKLOG #50's app-log disk metering in GET /status (visibility only); ADR 0014's connection_stopped alert rule reports a stop but is not driven by a log-write failure.

**Source:** Corepoint v8.1.0 help-export coverage sweep (2026-07-09) — five adversarially-verified passes over the full help export (1,569 pages); absence re-verified against `origin/main` before filing. Cross-ref [#52](archive/backlog/BACKLOG-CLOSED.md#52-corepoint-capability-parity-gaps--prioritized-roadmap-input-2026-06-27).

---

## 124. Batch-export message bodies from a connection log to a file

> 🔢 **Re-scored 2026-08-03 → DEMAND-GATE.** Value **4/10** · Difficulty **3/10** · _fill-in_. Console polish now that the capability itself ships — a scripted operator exports today through the audited step-up route, leaving only the save-selected affordance; the JS is already written (`messagefoundry_webconsole/static/app.js:1380`), so the cost is emitting the `data-mf-*` attributes and row checkboxes in `pages/messages.py` and registering `/ui/messages/export` ahead of `/ui/messages/{message_id}` (`routes/core.py:468`) so the path parameter cannot swallow it. _(was 5/10 · 3/10.)_
> **On-trigger / demand-gate.** Numbered for tracking only — build when the trigger below fires (“demand-gate, don’t schedule”).

> **AMENDED 2026-07-28 — the API half is BUILT; the console half is DEAD CODE.** Adversarial verification refuted a full close. **BUILT:** `GET /messages/export` (`messagefoundry/api/app.py:3001`) behind a dedicated `MESSAGES_EXPORT` permission with step-up + audit ([ADR 0131](adr/0131-bulk-raw-message-body-export-from-a-search-result-step-up-audited-phi-egress.md)), with 11 tests. A scripted operator can export today.
>
> ⚠️ **The REMAINDER is the console affordance, and it is worse than missing — it is wired to nothing.** The console JS registers a handler on `[data-mf-msg-export]`, but **no page builder emits that attribute** (`pages/messages.py` contains zero `data-mf-*` attributes and no per-row checkboxes), and the URL the JS fetches, `/ui/messages/export`, **has no route** — it would be swallowed by `/ui/messages/{message_id}`. So the progress bar and stop control the Scope names by name are unreachable. ⚠️ **ADR 0131 and its index row at `docs/adr/README.md:157` overstate this** and should be amended when the console half lands.

**Cluster:** Logging & Audit. **Priority:** P3. **Verdict:** demand-gate. **Severity (vs Corepoint):** minor.

**Scope:** Save-selected / save-all downloads a log search result's message bodies to a text file, with a progress bar and a stop control.

**Trigger:** build when an operator needs to hand a batch of message bodies to a partner or support engineer for offline analysis.

**Why:** Real gap. There is no batch/multi-select export of message bodies from a log-search result to a file (with progress/stop); the nearest mechanism is `/messages/search` plus one-at-a-time raw retrieval via `/messages/{id}` (each an audited PHI view), and BACKLOG #49's support-bundle explicitly carries no raw message bodies.

**Nearest existing mechanism:** The `/messages/search` API route plus single-message raw retrieval via `/messages/{message_id}` (both in messagefoundry/api/app.py, raw body gated by `messages:view_raw` and audited per view); the tee `export` CLI is test-data/anonymized-captures only, and BACKLOG #49 `support-bundle` deliberately excludes raw bodies.

**Source:** Corepoint v8.1.0 help-export coverage sweep (2026-07-09) — five adversarially-verified passes over the full help export (1,569 pages); absence re-verified against `origin/main` before filing. Cross-ref [#52](archive/backlog/BACKLOG-CLOSED.md#52-corepoint-capability-parity-gaps--prioritized-roadmap-input-2026-06-27).

---

## 125. Uploaded Logs page - import external message files and browse them offline

> 🔢 **Re-scored 2026-08-03 → DEMAND-GATE.** Value **5/10** · Difficulty **3/10** · _fill-in_. The build-state finding is right (the five routes exist at api/app.py:3685/:3786/:3803/:3889/:3946 and `browse_uploaded_file`'s own docstring says "Returns metadata only — never a decrypted body"), but value 6 rests on the claim that the item's trigger — "inspect a partner-supplied message file without ingesting it" — is "still unserved". It is substantially served: the shipped browse route filters and searches by `content`, `field_path`/`field_value`, `message_type` and `control_id` over the decrypted split, and per-message resend exists, all without live ingest. What is missing is only the body DISPLAY, and for that the workaround is clean, not awkward: the operator personally uploaded the file, so it is already in their hands and readable in any text editor, and `dryrun --show-phi` prints bodies as well. That is rubric 5 — "parity/breadth with a clean workaround" — not 6's "awkward workaround". Difficulty 3 stands (a read-one/download route over the existing encrypted store plus the audited PHI-view treatment and an ADR 0134 amendment). Quadrant becomes fill-in, not quick win; tier is unchanged. _(was 5/10 · 5/10.)_
> **On-trigger / demand-gate.** Numbered for tracking only — build when the trigger below fires (“demand-gate, don’t schedule”).

> **AMENDED 2026-07-28 — nearly all of this is BUILT; one named capability is absent by construction.** Adversarial verification refuted a full close. **BUILT** ([ADR 0134](adr/0134-offline-uploaded-logs-viewer-connection-decoupled-upload-browse-resend-deletion-phi-at-rest-posture-stdlib-multipart.md)): the Uploaded Logs page, opt-in `uploads_dir`, encrypted upload, filter/search browse, per-message **resend**, delete (**#126**, closed), quotas, retention and audit.
>
> ⚠️ **The REMAINDER: the Scope and Why both ask to "resend AND SAVE", and there is no save/download route anywhere.** The complete surface is `POST /uploads`, `GET /uploads`, `GET /uploads/{id}/messages`, `POST …/resend`, `DELETE /uploads/{id}` — no read-one and no download. Browse is **metadata-only by construction** (a test asserts `PID` is *not* in the response), so an operator can neither **read** nor **save** an uploaded message body. "Save" appears nowhere in ADR 0134 — not even in its out-of-scope list — so this is an undocumented gap, not a ratified narrowing. Decide it explicitly: build the download, or record the decline.

**Cluster:** Monitoring. **Priority:** P3. **Verdict:** demand-gate. **Severity (vs Corepoint):** minor.

**Scope:** An operator page to upload arbitrary .hl7/.txt/.xml files and browse each as a filterable, searchable log with per-message resend and save, decoupled from any live connection.

**Trigger:** build when support engineers need to inspect a partner-supplied message file without ingesting it into the live store.

**Why:** Real gap. There is no operator page to upload arbitrary external .hl7/.txt/.xml files and browse them offline as a filterable/searchable log with per-message resend and save; the nearest mechanisms are the `File()` inbound connector (live ingest into the store, not offline browsing), the message browser / dead-letter replay (store-only), and the one-shot `dryrun` CLI.

**Nearest existing mechanism:** The `File()` inbound connector (transports/file.py) plus the console/web message browser and dead-letter replay (api/app.py) — all of which operate on messages that entered through a wired connection and were persisted to the store; and the CLI `messagefoundry dryrun`, which runs a Router/Handler against one sample file one-shot. None imports arbitrary external files into an ad-hoc, connection-decoupled offline log viewer.

**Source:** Corepoint v8.1.0 help-export coverage sweep (2026-07-09) — five adversarially-verified passes over the full help export (1,569 pages); absence re-verified against `origin/main` before filing. Cross-ref [#52](archive/backlog/BACKLOG-CLOSED.md#52-corepoint-capability-parity-gaps--prioritized-roadmap-input-2026-06-27).

---

## 127. Web-proxy credential types (Basic / Digest / NTLM / Windows)

> 🔢 **Re-scored 2026-08-03 → DEMAND-GATE.** Value **5/10** · Difficulty **6/10** · _money pit_. Breadth with a clean, ADR-ratified workaround — `cntlm` in front of the engine covers the enterprise NTLM proxy, and Basic already tunnels through `CONNECT`; the remainder is not a knob but a keep-alive HTTP client under `transports/rest.py`, because `urllib.request` opens a new connection per `open()` and the NTLM type1/2/3 handshake is connection-bound — the refusal is asserted at `messagefoundry/transports/rest.py:993-997` for the same reason #65 scoped it out (`transports/http_auth.py:27-31`), across four connector factories plus an ADR 0126 amendment. _(was 5/10 · 4/10.)_

> **On-trigger / demand-gate.** Numbered for tracking only — build when the trigger below fires (“demand-gate, don’t schedule”).

> **AMENDED 2026-07-30 — Basic is BUILT, Digest is BUILT for http destinations, and NTLM/Windows are REFUSED at construction.** Adversarial verification refuted a full close. **BUILT** ([ADR 0126](adr/0126-outbound-forward-egress-web-proxy-for-the-stdlib-http-family.md), landed with #112/#128): `proxy_user` / `proxy_password` / `proxy_auth_type` on **`Rest`** (`messagefoundry/config/wiring.py:1332`), **`FHIR`** (`:1412`), **`DICOMweb`** (`:1659`) and **`Soap`** (`:2004`), dispatched by `proxy_auth_handler_from_settings` (`messagefoundry/transports/rest.py:929`). **Basic** — the default once a credential is set — is a **pre-emptive** `Proxy-Authorization` header and works for **both** http and https destinations, because urllib moves it into the `CONNECT` tunnel headers (`:981-984`). **Digest** is the reactive stdlib handler and is supported for an **http destination only**; an https destination is refused **at construction** because the `407` arrives inside the `CONNECT` tunnel (`:985-992`). A credential over a cleartext `http` proxy hop is refused posture-keyed regardless of destination scheme (`:971-979`). Tests: `tests/test_outbound_forward_proxy.py`.
>
> ⚠️ **NTLM and Windows are NOT built — the engine REFUSES them, so do not read this banner as four-scheme parity.** `proxy_auth_type` in `{ntlm, windows}` raises at construction (`messagefoundry/transports/rest.py:993-998`): the handshake is **connection-bound** (type1/type2/type3 must ride one keep-alive TCP connection) and `urllib.request` opens a new connection per `open()`, so a correct build needs a keep-alive client driven by `pyspnego` — the same reasoning that scoped them out of **#65** (`messagefoundry/transports/http_auth.py:27-31`). ADR 0126 records them as **deferred, refused loudly** (`0126:65-68`, `:154`) and lists NTLM/Windows/Negotiate under **Out of scope** (`:159`); the documented workaround is a local authenticating proxy such as `cntlm`. Locked by `tests/test_outbound_forward_proxy.py::test_digest_https_and_ntlm_windows_refused` (ADR AC-6, `0126:116-119`).

**Cluster:** Web Services & HTTP. **Priority:** P3. **Verdict:** demand-gate. **Severity (vs Corepoint):** minor.

**Scope:** Authenticate outbound web-service traffic to the forward proxy itself, selecting the proxy credential type. Meaningless without the forward-proxy address item - build together.

**Trigger:** build when the forward proxy of #112 requires authentication. **Build with #112** — meaningless alone.

**Why:** Real gap. No outbound connector can authenticate to a forward web proxy (no proxy-address item and no Basic/Digest/NTLM/Windows proxy-credential type); the nearest mechanism is REST/SOAP endpoint auth headers (`_build_headers`) which authenticate to the destination service, not to an intervening proxy, and the only "proxy" config models an inbound reverse proxy (`trusted_proxies`), not egress.

**Nearest existing mechanism:** REST()/SOAP() outbound connectors build endpoint auth headers (`_build_headers` Basic/Bearer, plus the ADR 0024 SMART token provider) in messagefoundry/transports/rest.py, but these authenticate to the target web service, not to an intermediary forward proxy; outbound HTTP uses a stdlib urllib opener with no proxy handler or proxy-credential surface, and config/settings.py only models an inbound reverse proxy (trusted_proxies, tls_terminated_upstream).

**Source:** Corepoint v8.1.0 help-export coverage sweep (2026-07-09) — five adversarially-verified passes over the full help export (1,569 pages); absence re-verified against `origin/main` before filing. Cross-ref [#52](archive/backlog/BACKLOG-CLOSED.md#52-corepoint-capability-parity-gaps--prioritized-roadmap-input-2026-06-27).

---

## 130. Message queues shared by name across connections + shared-name delete protection

> 🛠 **Decline overturned (2026-07-09).** A prioritization pass recommended DECLINE; the stated reason was **invalid**. Purity binds `@router` / `@handler` — **not connectors** (CLAUDE.md §8: “side effects (DB, network) belong in connections/transports”). This is an unfired **demand-gate**, not an architectural impossibility.
>
> **Build constraints:** 1) The shared queue is a store/config abstraction referenced by name — it must NOT become a "channel"/"route" bundling element (must not enclose the inbound->router->handler->outbound graph). 2) When multiple connections drain one shared queue, strict per-lane FIFO must be preserved via sequence-key lanes + claim-time per-lane FIFO so competing consumers cannot reorder within a sequence key. 3) Reference-counted delete must never orphan or silently drop persisted messages: rows in a shared queue retain their…

> 🔢 **Re-scored 2026-08-03 → DEMAND-GATE.** Value **5/10** · Difficulty **8/10** · _money pit_. Parity breadth with a clean workaround — the name-wired graph already fans a router across handlers and a handler across outbounds, and nothing (zero `shared_queue`/`queue_name` hits in `messagefoundry/`) suggests a named queue is needed to express a real feed; building it adds a store seam keyed by name rather than connection, competing consumers claiming under per-lane FIFO, and reference-counted delete, on all three backends without letting the abstraction become the "channel" element CLAUDE.md forbids.

> **On-trigger / demand-gate.** Numbered for tracking only — build when the trigger below fires (“demand-gate, don’t schedule”).

**Cluster:** Store / Operations. **Priority:** P3. **Verdict:** demand-gate. **Severity (vs Corepoint):** minor.

**Scope:** Several connections may reference the same named queue; deleting a connection removes its queue only when no other active connection still references that name.

**Trigger:** build when two connections must share one durable queue by name, with delete protection while any referent remains.

**Why:** Real gap. MessageFoundry has no named, connection-shared queue abstraction — its durable queues are internal per-connection stages in the SQLite store keyed by connection name (store/store.py) and connections are wired by name in the Registry (config/wiring.py), so there is neither a shared-by-name queue nor any reference-counted delete protection guarding it.

**Nearest existing mechanism:** The staged-queue store (store/store.py, SQLite WAL) with per-connection outbound rows, plus the name-wired Registry in config/wiring.py — queues are internal per-connection stage tables, not named shared entities, and connection removal is a config edit with no reference-count check.

**Source:** Corepoint v8.1.0 help-export coverage sweep (2026-07-09) — five adversarially-verified passes over the full help export (1,569 pages); absence re-verified against `origin/main` before filing. Cross-ref [#52](archive/backlog/BACKLOG-CLOSED.md#52-corepoint-capability-parity-gaps--prioritized-roadmap-input-2026-06-27).

---

## 131. Object flagging - mark objects of interest + a Flagged Objects filter

> 🔢 **Re-scored 2026-08-03 → DEMAND-GATE.** Value **3/10** · Difficulty **7/10** · _money pit_. Difficulty 7 is right — ADR 0007's amendment declines the universal flag precisely because it needs a name-keyed annotation table across all three store backends, which is literally D7 ("a new ADR plus a 3-backend migration"). Value 2 is not: it rests on "connections are the objects an operator actually lists and filters, leaving only a marker on Routers/Handlers", and that understates the remainder. I read the write path: `Engine.set_connection_flag` (pipeline/engine.py:1401) raises WiringError when the connection is not in connections.toml — "a CODE-FIRST connection has no TOML home, so the console flag is refused there" — and api/app.py:1969-1972 maps that to 409. So the shipped half serves only TOML-managed connections, while this project's default authoring mode for connections is code-first Python, and this item's own Trigger names "an adopter with a LARGE CONFIG REPOSITORY" — exactly the case the shipped half refuses. The remainder is therefore a console-settable flag for code-first connections AND Routers/Handlers, not a cosmetic residue, so it is not "already substantially covered" (=2); it is reduced-scope console polish with partial coverage. Quadrant stays money pit; tier stays DEMAND-GATE per the verdict line. _(was 4/10 · 3/10.)_

> **On-trigger / demand-gate.** Numbered for tracking only — build when the trigger below fires (“demand-gate, don’t schedule”).

> **AMENDED 2026-07-30 — the CONNECTION flag and the Flagged-only filter are BUILT; "every configuration object" is a ratified scope fork.** Adversarial verification refuted a full close. **BUILT** ([ADR 0007 amendment 2026-07-19](adr/0007-gui-manageable-connections-toml.md)): a display-only `flagged` field on `InboundConnection` / `OutboundConnection` (`messagefoundry/config/wiring.py:2531`, `:2589` — **no runtime path reads it**), authored code-first **and** in `connections.toml` (`config/connections_file.py:118`, `:139`, round-tripped by `tests/test_connections_roundtrip.py`); `POST /connections/{name}/flag` (`messagefoundry/api/app.py:1944`) → `Engine.set_connection_flag` (`messagefoundry/pipeline/engine.py:1286`) through the comment-preserving validate-before-persist writer — the FIRST console→`connections.toml` write seam — reachable from the console at `POST /ui/connections/{name}/flag` (`messagefoundry_webconsole/routes/connection_writes.py:103`); and the **Flagged-only** filter itself (`messagefoundry_webconsole/pages/connections.py:297`, re-applied after each poll/ws swap by `static/app.js:943-961`). 6 tests in `tests/test_connection_flag.py`.
>
> ⚠️ **The REMAINDER is the word "every" in the Scope.** This item's own Why names **Connection/Router/Handler**; only *connections* carry the flag, and only `connections.toml`-managed ones are console-settable — a code-first connection is refused **409** (it can still declare `flagged=True` in Python). ADR 0007's amendment records that fork deliberately (`0007:190-197`): a durable console-settable flag on *every* object would need a new name-keyed annotation table across all three store backends, which it declines, leaving the universal-object-flag branch "for a future, owner-chosen, store-serialized effort". So this is a **ratified narrowing, not an accidental one** — keep the item open at that reduced scope, and do **not** rebuild the connection half.

> ⚠️ **AMENDED 2026-08-03 — the `console/` citations here name a package that no longer exists.** The Why says "**neither** console offers a flagged-only filter" and the Nearest-existing-mechanism cites "the kind-filtered connection event log in `console/connections.py`", but there is no `messagefoundry/console/` package — [ADR 0032](adr/0032-console-desktop-launch.md) records it **removed in full** (`0032:439`) when **#103** closed, leaving the browser web console as the sole operator UI. Read the `console/` paths here as `messagefoundry_webconsole/` (the flag cell is `pages/connections.py:171`; the Flagged-only toggle `:270`/`:297`). This corrects the **citations only** — the 2026-07-30 ruling above still states the build state, and the remainder is still the universal-object flag at that reduced scope.


**Cluster:** Repository & Config. **Priority:** P3. **Verdict:** demand-gate. **Severity (vs Corepoint):** minor.

**Scope:** A user-settable flag on every configuration object, plus a flagged-only filter over the objects list.

**Trigger:** build when an adopter with a large config repository needs to mark and filter objects of interest.

**Why:** Real gap. No config object (Connection/Router/Handler) carries a user-settable flag/annotation and neither console offers a flagged-only filter; the nearest mechanisms are the existing filtered list views and the functional enabled/simulate connection booleans, none of which is an operator "object of interest" marker.

**Nearest existing mechanism:** The console/web-console connection list and event-log views support filtering (e.g. the kind-filtered connection event log in console/connections.py and the /ui connections/monitoring lists), and connections carry functional booleans (enabled, simulate) — but there is no user-settable "flag" attribute on any config object (config/models.py has no annotation/tag/note field) and no flagged-only filter.

**Source:** Corepoint v8.1.0 help-export coverage sweep (2026-07-09) — five adversarially-verified passes over the full help export (1,569 pages); absence re-verified against `origin/main` before filing. Cross-ref [#52](archive/backlog/BACKLOG-CLOSED.md#52-corepoint-capability-parity-gaps--prioritized-roadmap-input-2026-06-27).

---

## 132. Fixed 'now' test-time override (frozen clock for reproducible transform tests)

> 🔢 **Re-scored 2026-08-03 → DEMAND-GATE.** Value **5/10** · Difficulty **3/10** · _fill-in_. Value 5 stands (a wall-clock-free transform or a tolerant diff gets regression comparison today — "parity/breadth with a clean workaround"), and the seam claim is verified: `route_message` takes `ingest_time` at dryrun.py:517 and the two internal call sites hardwire `time.time()` at :679 (`_dry_run_raw`) and :753 (`dry_run`). But "a --now flag threaded through two entry points" undercounts the surfaces, and the ones it misses are the ones the item is ABOUT. `checks.py:1058,1126` calls `dry_run(reg, raw, inbound=..., snapshot_on_send=...)` with no ingest_time — and checks.py is the `.expect` fixture comparator, i.e. the repo's actual deterministic-regression gate. `trace_dry_run` is a separate module (`dryrun_trace`, invoked from __main__.py:2926-2931). And the item's own Trigger names the Test Bench: ide/src/testBench.ts shells `dryrun` at five sites (:240, :325, :354, :440) and would need the flag plus an affordance. Engine + CLI + fixture gate + a TypeScript extension is D3 work, not D2's "small additive change on an existing seam". Quadrant stays fill-in; tier stays DEMAND-GATE. _(was 5/10 · 2/10.)_

> **On-trigger / demand-gate.** Numbered for tracking only — build when the trigger below fires (“demand-gate, don’t schedule”).

**Cluster:** IDE / Test tooling. **Priority:** P3. **Verdict:** demand-gate. **Severity (vs Corepoint):** minor.

**Scope:** Hard-code the value of 'now' so time- and date-sensitive transform logic produces identical output on re-run, enabling deterministic regression comparison.

**Trigger:** build when a transform reads wall-clock time and its Test Bench output must be reproducible for regression comparison.

**Why:** Real gap. MessageFoundry gives transforms a re-run-stable "now" in production via current_ingest_time() (the persisted enqueue timestamp) and dryrun.route_message accepts an ingest_time argument, but the dryrun/check CLI hardwires ingest_time=time.time() with no way to pin a fixed value, so time-sensitive transforms cannot be re-run against a frozen clock for deterministic regression comparison.

**Nearest existing mechanism:** current_ingest_time() + the run-scoped ingest-time provider (messagefoundry/config/ingest_time.py); and dryrun.route_message's ingest_time parameter — but the CLI-facing dry_run()/trace_dry_run() (pipeline/dryrun.py) hardwire ingest_time=time.time() and expose no --now/frozen-clock flag.

**Source:** Corepoint v8.1.0 help-export coverage sweep (2026-07-09) — five adversarially-verified passes over the full help export (1,569 pages); absence re-verified against `origin/main` before filing. Cross-ref [#52](archive/backlog/BACKLOG-CLOSED.md#52-corepoint-capability-parity-gaps--prioritized-roadmap-input-2026-06-27).

---

## 133. User-chosen display colour on configuration objects

> 🛠 **Decline overturned (2026-07-09).** A prioritization pass recommended DECLINE; the stated reason was **invalid**. Purity binds `@router` / `@handler` — **not connectors** (CLAUDE.md §8: “side effects (DB, network) belong in connections/transports”). This is an unfired **demand-gate**, not an architectural impossibility.
>
> **Build constraints:** Colour/label is display-only console/IDE metadata on config objects (add to config/models.py, render via console/theme.py); it must remain a pure presentation attribute with no engine behaviour, routing decision, or disposition depending on it — logic stays code-first Routers/Handlers, so it must not grow into a no-code/visual authoring surface. If any accompanying free-text label field is added, restrict it to non-PHI operational metadata (a bare colour value carries no PHI risk; free-text labels must not…

> 🔢 **Re-scored 2026-08-03 → DEMAND-GATE.** Value **4/10** · Difficulty **3/10** · _fill-in_. Value 4 ("DX or console polish") is right and the stale-citation finding is right (no messagefoundry/console/ package; the live chrome is _html.py's page() head). But D3→2 rests on "a colour is that same shape [as `flagged`] plus a render", and that is false in a way this codebase enforces. `flagged` is a bool with no rendering sink; a colour is an operator-supplied STRING rendered into console markup, and the /ui CSP is `style-src 'self'` with no 'unsafe-inline' (_security.py:205, _auth.py:141, and app.css:2 states the constraint outright). An inline `style="…"` colour would simply not render, so the build must either bind a fixed palette to CSS classes shipped in app.css or add a nonce'd style mechanism the CSP does not currently grant for styles — a design decision plus value validation on untrusted config input, on top of the config-model → TOML → API → console thread. That is D3 ("a new setting into one connector"-scale work), not D2's "default flip or doc edit"-adjacent band. Quadrant stays fill-in; tier stays DEMAND-GATE.

> **On-trigger / demand-gate.** Numbered for tracking only — build when the trigger below fires (“demand-gate, don’t schedule”).

**Cluster:** UX / Console. **Priority:** P3. **Verdict:** demand-gate. **Severity (vs Corepoint):** minor.

**Scope:** Assign a display colour to a configuration object (a schedule on a calendar, source/destination colours on code sets) for visual identification.

**Trigger:** build when an adopter asks for visual identification of configuration objects in the console or IDE.

**Why:** Real gap. Configuration objects (Connections/Routers/Handlers) carry no user-assignable display colour or tag for visual identification; the console has only a single global theme palette (console/theme.py) and a proposed status-derived graph colouring (BACKLOG #76), neither of which lets an operator pick a colour per object.

**Nearest existing mechanism:** console/theme.py (a single global console palette with fixed accent/status colours) and BACKLOG #76 (a status-colored data-flow graph, where colour is derived from live connection status, not user-assigned). No user-chosen per-object colour field exists on the config models (config/models.py has no colour/label/display metadata).

**Source:** Corepoint v8.1.0 help-export coverage sweep (2026-07-09) — five adversarially-verified passes over the full help export (1,569 pages); absence re-verified against `origin/main` before filing. Cross-ref [#52](archive/backlog/BACKLOG-CLOSED.md#52-corepoint-capability-parity-gaps--prioritized-roadmap-input-2026-06-27).

---

## 135. Configurable statistics push / refresh interval

> 🔢 **Re-scored 2026-08-03 → DEMAND-GATE.** Value **2/10** · Difficulty **2/10** · _fill-in_. Marginal tuning knob with no interop dimension — the fixed cadence serves live monitoring fine and no deployment has reported console bandwidth as material; the build is a validated settings field read by the push loop, where the cadence is a single `await asyncio.sleep(1.0)` at `messagefoundry/api/app.py:4945` and `config/settings.py:701` already carries the sibling `ws_allowed_origins`.

> **On-trigger / demand-gate.** Numbered for tracking only — build when the trigger below fires (“demand-gate, don’t schedule”).

**Cluster:** Monitoring. **Priority:** P3. **Verdict:** demand-gate. **Severity (vs Corepoint):** minor.

**Scope:** A tunable interval governing how often live connection statistics are pushed to the operator console, to cut bandwidth in very-high-volume deployments.

**Trigger:** build when console/monitor bandwidth becomes material at very high connection counts or message rates.

**Why:** Real gap. The engine's live monitor feed pushes over /ws/stats on a hardcoded ~1s cadence with no per-connection or global tuning knob, so operators cannot throttle stats push frequency to cut bandwidth in very-high-volume deployments; the nearest mechanism is the fixed asyncio.sleep(1.0) in the ws_stats loop.

**Nearest existing mechanism:** The /ws/stats WebSocket in api/app.py, whose push loop is hardcoded to a fixed ~1.0s cadence (await asyncio.sleep(1.0)) and re-auth cadence _WS_REVALIDATE_SECONDS; no config surface (settings.py has ws_allowed_origins but no stats-interval knob).

**Source:** Corepoint v8.1.0 help-export coverage sweep (2026-07-09) — five adversarially-verified passes over the full help export (1,569 pages); absence re-verified against `origin/main` before filing. Cross-ref [#52](archive/backlog/BACKLOG-CLOSED.md#52-corepoint-capability-parity-gaps--prioritized-roadmap-input-2026-06-27).

---

## 137. Configurable server display name in the operator console

> 🔢 **Re-scored 2026-08-03 → DEMAND-GATE.** Value **4/10** · Difficulty **2/10** · _fill-in_. Value 4 is right (console polish; the URL/port already disambiguate, and monitoring.py:508 already renders a "Node id" row, so nobody is blocked), and the stale-module finding is right — there is no messagefoundry/console/, and the live title is `el("title", f"{title} — MessageFoundry")` at _html.py:171. But D2→3 rests on a false premise: "the console never imports the engine, so the label has to ride an API status response rather than being read from settings in-process". The console does not import the engine, yet the engine INJECTS a typed bundle into it at mount time — `mount_ui(app: FastAPI, deps: UiDeps)` (messagefoundry_webconsole/mount.py:69), and `UiDeps` (messagefoundry/api/_ui_seam.py:199) already carries settings-derived display values of exactly this shape, e.g. `organization_domains` (:224) and `oidc_authorization_host` (:231-234), the latter documented as "Derived from settings, never from request input". A server display name is one more UiDeps field plus a read in `page()` — no HTTP boundary crossing, no status-response plumbing. That is D2, "small additive change on an existing seam". Quadrant stays fill-in; tier stays DEMAND-GATE.

> **On-trigger / demand-gate.** Numbered for tracking only — build when the trigger below fires (“demand-gate, don’t schedule”).

**Cluster:** Monitoring. **Priority:** P3. **Verdict:** demand-gate. **Severity (vs Corepoint):** minor.

**Scope:** Render the server/instance name in the console title as the hostname, the IP address, or a custom label.

**Trigger:** build when an operator runs several engine instances and needs to tell their consoles apart at a glance.

**Why:** Real gap. The operator console window title is hardcoded to "MessageFoundry Console" (console/shell.py setWindowTitle) with no configurable server display name to show a hostname, IP, or custom label; the closest existing identifiers, the free-form `[ai].environment` name and `[cluster].node_id`, are engine-side and never rendered in the console title.

**Nearest existing mechanism:** The console's hardcoded window title `setWindowTitle("MessageFoundry Console")` in messagefoundry/console/shell.py; adjacent identity settings exist but are not surfaced in the title — the free-form `[ai].environment` name (config/settings.py, EnvironmentsSettings/AiSettings) and `[cluster].node_id` (host:pid identity).

**Source:** Corepoint v8.1.0 help-export coverage sweep (2026-07-09) — five adversarially-verified passes over the full help export (1,569 pages); absence re-verified against `origin/main` before filing. Cross-ref [#52](archive/backlog/BACKLOG-CLOSED.md#52-corepoint-capability-parity-gaps--prioritized-roadmap-input-2026-06-27).

---

## 141. TCP connection role selectable independently of direction (act-as-server vs act-as-client)

> 🔢 **Re-scored 2026-08-03 → DEMAND-GATE.** Value **6/10** · Difficulty **6/10** · _big bet_. Real firewall role-inversion gap that an external relay (socat/stunnel) works around awkwardly but genuinely, which is why it stays at moderate severity and P2; the outbound half is not a knob — `DestinationConnector` (`transports/base.py:459`) exposes only `send` (`:480`) and every destination dials (`tcp.py:189`, `mllp.py:849`, `x12.py:158`), so a listening outbound needs an accept loop handing a peer socket to the per-outbound delivery worker and reconciled with retry/backoff and the connection-lifecycle status vocabulary. _(was 6/10 · 5/10.)_

> **On-trigger / demand-gate.** Numbered for tracking only — build when the trigger below fires (“demand-gate, don’t schedule”).

**Cluster:** Connections & Transports. **Priority:** P2. **Verdict:** demand-gate. **Severity (vs Corepoint):** moderate.

**Scope:** A TCP connection may listen or dial out regardless of whether it sends or receives, so the role can be inverted to match a partner's firewall posture.

**Trigger:** build when a partner's firewall posture requires the engine to dial out and then receive, or to listen and then send.

**Why:** Real gap. TCP/MLLP socket role is hard-bound to message direction — an inbound connection always listens (start_server) and an outbound always dials (open_connection); there is no per-connection setting to invert the role (dial-out inbound or listening outbound) to match a partner's firewall posture, the way Corepoint allows.

**Nearest existing mechanism:** Socket role is fixed by direction in transports/: TcpSource/MLLPSource always asyncio.start_server (listen), TcpDestination/MLLPDestination always asyncio.open_connection (dial). Adjacent settings bind_host/source_ip_allowlist (inbound) and host/port (outbound) tune the endpoint but never invert the role. No decoupling knob exists.

**Source:** Corepoint v8.1.0 help-export coverage sweep (2026-07-09) — five adversarially-verified passes over the full help export (1,569 pages); absence re-verified against `origin/main` before filing. Cross-ref [#52](archive/backlog/BACKLOG-CLOSED.md#52-corepoint-capability-parity-gaps--prioritized-roadmap-input-2026-06-27).

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

## 148. X12 TA1 interchange-acknowledgement generation

> 🔢 **Re-scored 2026-08-03 → DEMAND-GATE.** Value **3/10** · Difficulty **2/10** · _fill-in_. Niche X12 knob most partners never need — the pyx12 walk yields a conforming 997/999 free (`parsing/x12/validate.py:18`, `:69`), covering the common ack, and only a contract that specifically mandates interchange-level accept/reject reaches for TA1; the build is a pure codec addition beside the existing splitter and delimiters in `messagefoundry/parsing/x12/`, which today contains no TA1 generator at all — only the outbound classifies a partner's returned TA1 (`transports/x12.py:73-74`).

> **On-trigger / demand-gate.** Numbered for tracking only — build when the trigger below fires (“demand-gate, don’t schedule”).

**Cluster:** HL7 / Messaging. **Priority:** P3. **Verdict:** demand-gate. **Severity (vs Corepoint):** moderate.

**Scope:** Validate an inbound ISA/IEA envelope (control-number match, segment-count/integrity) and emit a TA1 interchange acknowledgement with the appropriate A/E/R code plus note code, callable on demand from a Handler against a RawMessage.

**Trigger:** build when an X12 trading-partner contract mandates a TA1 interchange-level structural accept/reject acknowledgement.

**Why:** Partial. parsing/x12/validate.py yields free 997/999 functional acks from the pyx12 walk, but no TA1 interchange ack is generated anywhere — the outbound path only classifies a partner's inbound TA1 (ADR 0016).

**Source:** BACKLOG coverage audit of the 2026-06-27 Corepoint gap analysis against `origin/main` (2026-07-09) — 246 capabilities triaged; this one verified **open and untracked**. Cross-ref [#52](archive/backlog/BACKLOG-CLOSED.md#52-corepoint-capability-parity-gaps--prioritized-roadmap-input-2026-06-27).

---

## 155. Server-to-server migration runbook

> 🔢 **Re-scored 2026-08-03 → DEMAND-GATE.** Value **2/10** · Difficulty **1/10** · _fill-in_. Every constituent step already ships documented — install, backup/restore/DR, decommission at `docs/EARLY-ADOPTER-GUIDE.md` §4/§10/§16 — so the gap is prose stitching, not capability; one new doc that orders them end-to-end, no code.

> **On-trigger / demand-gate.** Numbered for tracking only — build when the trigger below fires (“demand-gate, don’t schedule”).

**Cluster:** Admin & Deployment. **Priority:** P3. **Verdict:** demand-gate. **Severity (vs Corepoint):** minor.

**Scope:** A single documented runbook for moving a MEFOR install to new server hardware: stand up the new box, install the pinned engine + NSSM service, clone config, quiesce/drain and restore the store (SQLite triple-file backup or server-DB cut-over) plus the escrowed key, repoint senders, verify health/integrity/dispositions, then decommission the old host in a no-loss ordering.

**Trigger:** build when an adopter does a hardware refresh or server relocation and asks how to move engine + store + config without message loss.

**Why:** Partial. Every constituent step is built and documented separately (install, store backup + key escrow + restore drill, decommission, the ADR 0050 portable-config bundle) but no doc stitches them into an end-to-end server-to-server migration runbook.

**Source:** BACKLOG coverage audit of the 2026-06-27 Corepoint gap analysis against `origin/main` (2026-07-09) — 246 capabilities triaged; this one verified **open and untracked**. Cross-ref [#52](archive/backlog/BACKLOG-CLOSED.md#52-corepoint-capability-parity-gaps--prioritized-roadmap-input-2026-06-27).

---

## 156. Alert hysteresis (separate fire/clear thresholds)

> 🔢 **Re-scored 2026-08-03 → DEMAND-GATE.** Value **2/10** · Difficulty **3/10** · _fill-in_. Anti-flap refinement the shipped `realert_seconds` / per-rule `cooldown_seconds` throttle already damps (`messagefoundry/config/settings.py:2678`, `:2823`), with single-sided `min_depth`/`min_oldest_seconds` matching confirmed at `messagefoundry/pipeline/alert_sinks.py:617-623`; two new AlertRule fields plus clear-edge state in the sink, no store or migration.

> **On-trigger / demand-gate.** Numbered for tracking only — build when the trigger below fires (“demand-gate, don’t schedule”).

**Cluster:** Alerting. **Priority:** P3. **Verdict:** demand-gate. **Severity (vs Corepoint):** minor.

**Scope:** An optional lower clear-threshold (clear_depth / clear_oldest_seconds) on the queue_buildup AlertRule so a fired threshold alert auto-resolves only below the separate lower bound (deadband) instead of oscillating around one threshold.

**Trigger:** build when operators report threshold-alert flapping that the flat realert/cooldown throttle does not adequately damp.

**Why:** Partial. AlertsSettings.realert_seconds / per-rule cooldown_seconds throttle re-notification and #56 gives resolvable instances, but neither adds a distinct lower clear-threshold so a rule fires at X and clears only below a lower Y.

**Source:** BACKLOG coverage audit of the 2026-06-27 Corepoint gap analysis against `origin/main` (2026-07-09) — 246 capabilities triaged; this one verified **open and untracked**. Cross-ref [#52](archive/backlog/BACKLOG-CLOSED.md#52-corepoint-capability-parity-gaps--prioritized-roadmap-input-2026-06-27).

---

## 158. Per-message dynamic FTP host/path/credentials

> 🔢 **Re-scored 2026-08-03 → DEMAND-GATE.** Value **6/10** · Difficulty **3/10** · _quick win_. Real dynamic-destination gap the shipped code closes off at both ends — host/credentials/`remote_dir` freeze at construction (`messagefoundry/transports/remotefile.py:626-627`) and `render_filename` is hard-capped to one path component (`messagefoundry/transports/file.py:105-127`), so a data-driven target subdirectory cannot be expressed by a static per-folder connection fan-out nor smuggled through the filename; awkward workaround, not a clean one. Build rides the already-shipped #68 per-message metadata carry (`messagefoundry/pipeline/wiring_runner.py:4526-4531`) plus a multi-component path sanitizer — a setting into one connector. _(was 5/10 · 3/10.)_

> **On-trigger / demand-gate.** Numbered for tracking only — build when the trigger below fires (“demand-gate, don’t schedule”).

**Cluster:** Connections & Transports. **Priority:** P3. **Verdict:** demand-gate. **Severity (vs Corepoint):** minor.

**Scope:** On the RemoteFile (SFTP/FTP/FTPS) destination, resolve the target subdirectory under remote_dir — and optionally the host/credential set — from message fields per delivery instead of fixing them at construction.

**Trigger:** build when one FTP interface must fan out to per-message target subdirectories or a message-selected host rather than a single static remote_dir.

**Why:** Real gap. RemoteFile fixes host, credentials, and remote_dir at construction and only the filename is message-driven (constrained to one path component); it is the direct FTP analog of the HTTP-only #68 per-message override.

**Merged from 2 analysis entries** describing the same capability.

**Source:** BACKLOG coverage audit of the 2026-06-27 Corepoint gap analysis against `origin/main` (2026-07-09) — 246 capabilities triaged; this one verified **open and untracked**. Cross-ref [#52](archive/backlog/BACKLOG-CLOSED.md#52-corepoint-capability-parity-gaps--prioritized-roadmap-input-2026-06-27).

---

## 159. TCP stream-until-close (no-framing) mode

> 🔢 **Re-scored 2026-08-03 → DEMAND-GATE.** Value **3/10** · Difficulty **3/10** · _fill-in_. Niche close-framed TCP interop knob: `codec_for` requires both delimiter bytes and `FrameCodec` rejects `start == end` (`messagefoundry/transports/framing.py:62-63`, `:167-170`), so connection-close framing is inexpressible today; a `framing=none` path bypasses the shared codec on the Tcp read loop (`messagefoundry/transports/tcp.py:508-515`) and the destination's write-then-close.

> **On-trigger / demand-gate.** Numbered for tracking only — build when the trigger below fires (“demand-gate, don’t schedule”).

**Cluster:** Connections & Transports. **Priority:** P3. **Verdict:** demand-gate. **Severity (vs Corepoint):** minor.

**Scope:** A framing="none" mode on the Tcp source/destination that treats the whole connection stream as one message: the source buffers all bytes and emits one message on EOF (bounded by max_frame_bytes/receive_timeout), and the destination writes the raw body and closes to delimit it.

**Trigger:** build when a partner TCP feed frames each message by connection-close with no start/end delimiter.

**Why:** Real gap. The Tcp() connector's delimiter framing codec (framing.py presets or explicit start/end bytes) mandates delimiter bytes and cannot treat a whole connection as a single message.

**Severity note:** the analysis rates this **unrated**; recorded as **minor**. The capability is prose-only (line 88 GAP bullet in the Connections & Transports section) with no severity column, so the analysis rating is "unrated." Per the conservative rule for unrated items, this defaults to minor unless it is a real migration/ops blocker — it is not. It is a niche transport-breadth adjunct to the already-built MLLP/TCP framing core (a whole-stream, close-to-delimit mode), and every…

**Source:** BACKLOG coverage audit of the 2026-06-27 Corepoint gap analysis against `origin/main` (2026-07-09) — 246 capabilities triaged; this one verified **open and untracked**. Cross-ref [#52](archive/backlog/BACKLOG-CLOSED.md#52-corepoint-capability-parity-gaps--prioritized-roadmap-input-2026-06-27).

---

## 163. Static-string inbound ACK

> 🔢 **Re-scored 2026-08-03 → DEMAND-GATE.** Value **3/10** · Difficulty **3/10** · _fill-in_. Canned-ACK interop knob most partners never need — `AckMode` offers only original/enhanced/none (`messagefoundry/config/models.py:98-103`) and `build_ack` always assembles MSH+MSA (`messagefoundry/transports/mllp.py:329-350`); a new mode plus a literal setting through wiring into the one MLLP listener, with the synchronous NAK path decided.

> **On-trigger / demand-gate.** Numbered for tracking only — build when the trigger below fires (“demand-gate, don’t schedule”).

**Cluster:** HL7 / Messaging. **Priority:** P3. **Verdict:** demand-gate. **Severity (vs Corepoint):** minor.

**Scope:** A per-inbound ack_mode (e.g. static) that replies with a fixed operator-supplied literal string as the acknowledgement, bypassing the generated MSH+MSA HL7 ACK, for legacy partners expecting a canned response.

**Trigger:** build when a legacy partner's MLLP receiver expects a fixed canned acknowledgement string rather than a correlated HL7 MSA.

**Why:** Partial. AckMode (original/enhanced/none) only selects among generated MSH+MSA acks in build_ack, and a Tcp() source that frames a verbatim reply abandons the HL7 MLLP ACK path — no inbound option substitutes a fixed literal for the generated HL7 ack (the omit-trigger half is already MF behavior).

**Merged from 2 analysis entries** describing the same capability.

**Source:** BACKLOG coverage audit of the 2026-06-27 Corepoint gap analysis against `origin/main` (2026-07-09) — 246 capabilities triaged; this one verified **open and untracked**. Cross-ref [#52](archive/backlog/BACKLOG-CLOSED.md#52-corepoint-capability-parity-gaps--prioritized-roadmap-input-2026-06-27).

---

## 165. DB schema browser + ad-hoc query runner

> 🔢 **Re-scored 2026-08-03 → DEMAND-GATE.** Value **5/10** · Difficulty **5/10** · _fill-in_. Corepoint-parity authoring aid whose external-SQL-client workaround is fully clean — the only DB reach today is the `SELECT 1` reachability probe (`messagefoundry/transports/database.py:484-501`) and dry-run refuses `db_lookup` (`messagefoundry/pipeline/dryrun.py:570`); the build is a net-new API surface plus per-dialect introspection, read-only statement gating, a permission, audit and a console pane.

> **On-trigger / demand-gate.** Numbered for tracking only — build when the trigger below fires (“demand-gate, don’t schedule”).

**Cluster:** IDE / DX. **Priority:** P3. **Verdict:** demand-gate. **Severity (vs Corepoint):** minor.

**Scope:** A read-only DB schema browser (tables/columns) plus an ad-hoc SELECT runner in the console/IDE, scoped to the db_lookup [egress].allowed_db connections, so an author can discover table/column names and validate a query while writing db_lookup / DATABASE-connector SQL.

**Trigger:** build when adopters authoring db_lookup or DATABASE-connector SQL repeatedly leave for an external SQL client to discover schema and test queries.

**Why:** Partial. The nearest mechanisms are the reachability-only connection probe (SELECT 1 behind POST /connections/{name}/test) and the dry-run Test Bench where db_lookup raises — neither browses schema nor runs an author-supplied query.

**Source:** BACKLOG coverage audit of the 2026-06-27 Corepoint gap analysis against `origin/main` (2026-07-09) — 246 capabilities triaged; this one verified **open and untracked**. Cross-ref [#52](archive/backlog/BACKLOG-CLOSED.md#52-corepoint-capability-parity-gaps--prioritized-roadmap-input-2026-06-27).

---

## 166. Server-side per-user console preferences

> 🔢 **Re-scored 2026-08-03 → DEMAND-GATE.** Value **4/10** · Difficulty **4/10** · _fill-in_. Roaming console settings stay polish nobody is blocked on; the cost the 6 priced is gone — the Qt half is retired and #151 already shipped the owner-keyed per-user store + route template (`messagefoundry/store/store.py:1667-1681`), so the remainder is a second additive table across three backends plus web-console wiring, no pipeline. _(was 4/10 · 6/10.)_

> **On-trigger / demand-gate.** Numbered for tracking only — build when the trigger below fires (“demand-gate, don’t schedule”).

> ⚠️ **AMENDED 2026-08-03 — the `QSettings` premise names a retired surface; today's console keeps its table state in the browser.** The Why asserts the console "persists all UI settings only in local per-machine QSettings", but the PySide6 operator console was retired (**#103**) and `QSettings` now survives only in the standalone test harness (`harness/_console_widgets.py:136`, `:143`); the live web console persists **table state — column widths and the last sort — in browser `localStorage`**, keyed by pathname plus the table's ordinal on the page (`messagefoundry_webconsole/static/app.js:556-575`, prefix `mfcols:v2:`), degrading to session-only when storage is unavailable. The gap stands as stated — per-browser storage roams no further than per-machine storage did, and there is still no authenticated server-side per-user preference surface — so what remains is unchanged in substance, only in which client the settings must be lifted out of.


**Cluster:** IDE / DX. **Priority:** P3. **Verdict:** demand-gate. **Severity (vs Corepoint):** minor.

**Scope:** An authenticated server-side per-user preferences surface (store-backed, keyed by acting user) the console reads/writes so UI settings — poll interval, table/column state, multi-shard registry — roam across workstations instead of living only in local per-machine QSettings.

**Trigger:** build when operators run the console from multiple workstations and need settings to follow them, or the web console needs server-persisted per-user state.

**Why:** Real gap. The console persists all UI settings only in local per-machine QSettings; there is no authenticated server-side per-user preference surface, so nothing roams across workstations.

**Source:** BACKLOG coverage audit of the 2026-06-27 Corepoint gap analysis against `origin/main` (2026-07-09) — 246 capabilities triaged; this one verified **open and untracked**. Cross-ref [#52](archive/backlog/BACKLOG-CLOSED.md#52-corepoint-capability-parity-gaps--prioritized-roadmap-input-2026-06-27).

---

## 167. Test Bench metadata seeding

> 🔢 **Re-scored 2026-08-03 → DEMAND-GATE.** Value **4/10** · Difficulty **2/10** · _fill-in_. IDE Test Bench DX input to seed the per-message metadata bag for transform tests; nobody is blocked, and the seam is small — a `--meta` flag threaded through `dry_run`/`route_message` (`messagefoundry/pipeline/dryrun.py:512-521`, `:702-709`) into the Test Bench's CLI-only channel (`ide/src/testBench.ts:240`). The bag itself already shipped (#150/ADR 0081, `messagefoundry/config/wiring.py:2604`) but write-only — no `meta_get` on `Message` — which is a clause of this item's OWN trigger, so it holds the tier at DEMAND-GATE without discounting worth-if-built.

> **On-trigger / demand-gate.** Numbered for tracking only — build when the trigger below fires (“demand-gate, don’t schedule”).

**Cluster:** IDE / DX. **Priority:** P3. **Verdict:** demand-gate. **Severity (vs Corepoint):** minor.

**Scope:** A Test Bench input that seeds per-message metadata key/values onto a dry-run test message so a Router/Handler can read them during transform testing.

**Trigger:** build when the per-message metadata bag ships and transforms read metadata that must be exercised in the Test Bench before deployment.

**Why:** Partial. The store/API reserve an (encrypted) per-message metadata column but the Test Bench dry_run takes only raw+inbound with no channel to seed those values — meaningful only once the per-message metadata-bag runtime feature ships.

**Source:** BACKLOG coverage audit of the 2026-06-27 Corepoint gap analysis against `origin/main` (2026-07-09) — 246 capabilities triaged; this one verified **open and untracked**. Cross-ref [#52](archive/backlog/BACKLOG-CLOSED.md#52-corepoint-capability-parity-gaps--prioritized-roadmap-input-2026-06-27).

---

## 169. Author-appendable per-message processing history

> 🔢 **Re-scored 2026-08-03 → DEMAND-GATE.** Value **6/10** · Difficulty **4/10** · _quick win_. Genuine MsgAddHistory parity with only an awkward workaround: `message_events` is NOT author-appendable — its writer is engine-only (`messagefoundry/store/base.py:1039-1062`, reachable from `pipeline/` alone) and its `event` vocabulary is a closed frozenset (`messagefoundry/store/store.py:1004-1020`) — leaving `SetMeta` as the sole transform-callable channel, capped at 32 keys / 4096 bytes with last-writer-wins and no timestamp or ordering, so an unbounded append-only history cannot ride it. Build is an append op on the ADR 0081 exactly-once `transform_handoff` template plus an operator surface across three backends.

> **On-trigger / demand-gate.** Numbered for tracking only — build when the trigger below fires (“demand-gate, don’t schedule”).

**Cluster:** Logging & Audit. **Priority:** P3. **Verdict:** demand-gate. **Severity (vs Corepoint):** minor.

**Scope:** A transform-callable Message helper that appends an author+timestamped free-text entry to a per-message processing history operators can view alongside the message (persisted as metadata, distinct from Z-segments and engine audit rows), with re-run-safe de-duplication.

**Trigger:** build when a Corepoint migration relies on MsgAddHistory breadcrumbs for message-level troubleshooting/audit parity.

**Why:** Real gap. add_segment (in-message Z-segment notes) and the engine audit timeline (record_audit) are HL7-content edits and engine-authored audit respectively, neither a transform-callable append onto an operator-visible message-processing history.

**Source:** BACKLOG coverage audit of the 2026-06-27 Corepoint gap analysis against `origin/main` (2026-07-09) — 246 capabilities triaged; this one verified **open and untracked**. Cross-ref [#52](archive/backlog/BACKLOG-CLOSED.md#52-corepoint-capability-parity-gaps--prioritized-roadmap-input-2026-06-27).

---

## 171. Runtime log-verbosity control + in-product log viewer

> 🔢 **Re-scored 2026-08-03 → DEMAND-GATE.** Value **4/10** · Difficulty **2/10** · _fill-in_. Ops convenience whose live-incident use case the built API half already answers — `set_runtime_level`/`current_log_level` (`messagefoundry/logging_setup.py:429`, `:452`) behind `GET`/`PATCH /logging/level` and `GET /logs/tail` (`messagefoundry/api/app.py:4566`, `:4580`, `:4609`); the remainder is pure wiring, since the console JS is already written (`messagefoundry_webconsole/static/app.js:1252`, `:1294`) and only needs a page builder to emit its attributes plus the two absent `/ui` routes and a golden-surface update. _(was 4/10 · 3/10.)_

> **On-trigger / demand-gate.** Numbered for tracking only — build when the trigger below fires (“demand-gate, don’t schedule”).

> **AMENDED 2026-07-30 — the API half is BUILT; the console half is DEAD CODE.** Adversarial verification refuted a full close. **BUILT** ([ADR 0130](adr/0130-runtime-ephemeral-log-verbosity-control-and-phi-redacted-log-tail-viewer.md)): the restart-free runtime verbosity control — `set_runtime_level` / `current_log_level` (`messagefoundry/logging_setup.py:417`, `:440`; root + uvicorn, ephemeral, survives `/config/reload`) behind `GET`/`PATCH /logging/level` (`messagefoundry/api/app.py:4527`, `:4541`), gated by `monitoring:diagnose` and audited as `logging_level_change` — plus the paginated **redacted** tail `GET /logs/tail` (`:4570`) behind the new `logs:view` PHI-read permission (`messagefoundry/auth/permissions.py:57`), reusing the #49 redactor, hop-guarded and audited as `logs_view`. 11 tests in `tests/test_logging_surfaces.py`.
>
> ⚠️ **The REMAINDER is the in-console viewer the Scope names, and it is worse than missing — it is wired to nothing.** `messagefoundry_webconsole/static/app.js` registers both features, `[data-mf-log-level]` (`:1252`) and `[data-mf-log-viewer]` (`:1294`), but **no page builder emits either attribute** (`data-mf-log` occurs nowhere outside `app.js`), and the URLs the JS fetches — `/ui/logging/level` (`:1259`) and `/ui/logs/tail` (`:1308`) — **have no route**: neither appears in the golden `/ui` surface (`packaging/messagefoundry-webconsole/tests/golden/ui_routes.txt`). During an incident an operator still reaches both only through the JSON API. ⚠️ ADR 0130's **Built:** block correctly lists routes + DTOs only, but its Related line calls [ADR 0065](adr/0065-web-ops-dashboard.md) "the console that renders it" (`0130:13-14`) — nothing renders it today; amend that when the console half lands. Per-logger/per-area targeting is an ADR-recorded MVP scope-out (`0130:97-98`), not a gap.

**Cluster:** Logging & Audit. **Priority:** P3. **Verdict:** demand-gate. **Severity (vs Corepoint):** minor.

**Scope:** An RBAC-gated runtime verbosity control that adjusts the service log level (optionally per-area/per-logger) without restarting the engine, plus a paginated in-console/web viewer over the redacted application-log tail the support bundle already produces.

**Trigger:** build when operators need to raise service-log detail and read the application log during a live incident without restarting the engine or pulling a full support bundle.

**Why:** Partial. The static [logging].level / --log-level startup dial and the support bundle's one-shot redacted app-log tail exist, but there is no runtime/per-area verbosity control and no interactive in-console log viewer.

**Severity note:** the analysis rates this **unrated**; recorded as **minor**. The analysis does NOT rate this capability — it lives only in the §Logging prose summary (line 120), not as a row in the severity-bearing top-gaps table, so it is unrated. Downstream assigned moderate; I lower to minor. Applying the conservative rule for prose-only items (minor unless a real migration/ops blocker), this is an ops convenience, not a blocker: log level is settable via config, and the redacted…

**Source:** BACKLOG coverage audit of the 2026-06-27 Corepoint gap analysis against `origin/main` (2026-07-09) — 246 capabilities triaged; this one verified **open and untracked**. Cross-ref [#52](archive/backlog/BACKLOG-CLOSED.md#52-corepoint-capability-parity-gaps--prioritized-roadmap-input-2026-06-27).

---

## 172. Gzip/zip compression codec + file-connector option

> 🔢 **Re-scored 2026-08-03 → DEMAND-GATE.** Value **5/10** · Difficulty **3/10** · _fill-in_. File-feed parity breadth with a clean code-first workaround: the reusable codec shipped including `zip_compress`/`zip_decompress` (`messagefoundry/parsing/compression.py:40-48`), so a zip-delivering partner is served by a Handler call today. What remains is connector-level — widening `_SUPPORTED_COMPRESSION` (`messagefoundry/transports/file.py:88`), which forces an archive-member-to-message decision, plus REMOTEFILE, which has zero compression to extend.
> **On-trigger / demand-gate.** Numbered for tracking only — build when the trigger below fires (“demand-gate, don’t schedule”).

> **AMENDED 2026-07-28 — the codec is BUILT; the connector covers gzip only.** Adversarial verification refuted a full close. **BUILT:** the pure three-algorithm compression codec (`messagefoundry/parsing/compression.py`, Handler-callable) and the File connector's gzip/gunzip option ([ADR 0123](adr/0123-compression-codec-gzip-zip-deflate-file-connector-compress-decompress-option.md)).
>
> ⚠️ **The REMAINDER is ZIP on the connector, which is foreclosed at three separate layers** — the wiring type (`decompress: Literal['gzip'] | None`), `_SUPPORTED_COMPRESSION = frozenset({"gzip"})` (`messagefoundry/transports/file.py:88`, enforced at `:145`), and a validator that raises on `'zip'`. The item's Scope asks for a connector option to "gunzip/**unzip** inbound archived drops" and its Trigger fires on a partner feed delivering "gzipped/**zipped** archives", so a zip-delivering partner is **not** served — a Handler must call the codec by hand. ADR 0123 records the narrowing deliberately, but it **is** a narrowing. Second gap: the sibling **REMOTEFILE** connector has **zero** compression support.

**Cluster:** Modeling & Codecs. **Priority:** P3. **Verdict:** demand-gate. **Severity (vs Corepoint):** minor.

**Scope:** A pure gzip/zip/deflate compress-and-decompress codec (bytes in→bytes out, callable from a Handler against RawMessage/Message alongside the ADR 0028 base64 carriage) plus a file-connector option to gzip outbound drops and gunzip/unzip inbound archived drops.

**Trigger:** build when a partner file feed delivers gzipped/zipped archives or requires compressed outbound files.

**Why:** Real gap. The nearest mechanism, the ADR 0028 base64 binary carriage codec (parsing/binary.py), encodes NUL-safe transport but does not compress or decompress; no gzip/zip codec or connector option exists.

**Severity note:** the analysis rates this **unrated**; recorded as **minor**. The analysis lists this only as a prose GAP bullet ("file zip/unzip/gzip action", line 94) with no severity, so it is unrated. Per the conservative rule, an unrated item is minor unless it's a genuine migration/ops blocker. A gzip/zip/deflate codec is a code-first convenience: a Handler can already call stdlib gzip/zipfile against RawMessage alongside the ADR 0028 base64 carriage, and the file-connector…

**Source:** BACKLOG coverage audit of the 2026-06-27 Corepoint gap analysis against `origin/main` (2026-07-09) — 246 capabilities triaged; this one verified **open and untracked**. Cross-ref [#52](archive/backlog/BACKLOG-CLOSED.md#52-corepoint-capability-parity-gaps--prioritized-roadmap-input-2026-06-27).

---

## 173. Segment/segment-group subtree-copy helper

> 🔢 **Re-scored 2026-08-03 → DEMAND-GATE.** Value **2/10** · Difficulty **2/10** · _fill-in_. One-call sugar over an API that already does the hard part — `groups()` hands back the span view (`messagefoundry/parsing/message.py:470`) and `add_segment` grafts lines (`:377`), so the 'find the group boundary' boilerplate the item cites is mostly already solved; a small additive helper whose only subtlety is re-encoding across two messages' MSH separators.

> **On-trigger / demand-gate.** Numbered for tracking only — build when the trigger below fires (“demand-gate, don’t schedule”).

**Cluster:** Modeling & Codecs. **Priority:** P3. **Verdict:** demand-gate. **Severity (vs Corepoint):** minor.

**Scope:** A one-call Message helper that copies a named segment or segment-group subtree from a source Message into a destination Message (position- and MSH-encoding-aware, re-encoding byte-for-byte), instead of iterating segments(), filtering the group by hand, and re-add_segment()-ing each line.

**Trigger:** build when a mapping-heavy Corepoint migration repeatedly hand-rolls segment/group copies (e.g. lifting repeating OBX/OBR groups) and the boilerplate becomes error-prone.

**Why:** Partial. add_segment(line) grafts a single raw line and groups()/segments() read a source subtree, but there is no single-call cross-message copy — the author must iterate raw lines, find the group boundary, and re-add each segment.

**Source:** BACKLOG coverage audit of the 2026-06-27 Corepoint gap analysis against `origin/main` (2026-07-09) — 246 capabilities triaged; this one verified **open and untracked**. Cross-ref [#52](archive/backlog/BACKLOG-CLOSED.md#52-corepoint-capability-parity-gaps--prioritized-roadmap-input-2026-06-27).

---

## 174. Scheduled automatic statistics reset

> 🔢 **Re-scored 2026-08-03 → DEMAND-GATE.** Value **2/10** · Difficulty **2/10** · _fill-in_. Manual re-snapshot ships (`Engine.reset_stats`, `messagefoundry/pipeline/engine.py:1772-1792`, behind `POST /statistics/reset` at `messagefoundry/api/app.py:2208`) and OTel covers daily volume, so a timer is convenience only; it assembles two shipped primitives — the ADR 0095 timezone-aware `Schedule` and the #160 stdlib cron evaluator — against an existing call.

> **On-trigger / demand-gate.** Numbered for tracking only — build when the trigger below fires (“demand-gate, don’t schedule”).

**Cluster:** Monitoring. **Priority:** P3. **Verdict:** demand-gate. **Severity (vs Corepoint):** minor.

**Scope:** A scheduled (e.g. daily at a configured off-peak time) automatic re-snapshot of per-connection dashboard stat baselines, so the visible cumulative console counters roll over on a timer without an operator POST.

**Trigger:** build when operators on the built-in console (not Prometheus/OTel) want daily volume views without manually resetting stats.

**Why:** Partial. reset_stats already re-snapshots per-connection baselines on demand via POST /statistics/reset; only the scheduled auto-trigger (daily rollover) is missing.

**Source:** BACKLOG coverage audit of the 2026-06-27 Corepoint gap analysis against `origin/main` (2026-07-09) — 246 capabilities triaged; this one verified **open and untracked**. Cross-ref [#52](archive/backlog/BACKLOG-CLOSED.md#52-corepoint-capability-parity-gaps--prioritized-roadmap-input-2026-06-27).

---

## 177. Effective-permission inspector for a user

> 🔢 **Re-scored 2026-08-03 → DEMAND-GATE.** Value **4/10** · Difficulty **2/10** · _fill-in_. The endpoint shipped (`GET /users/{user_id}/permissions`, `messagefoundry/api/auth_routes.py:610`), so the manual `/users`×`/roles` cross-ref the 5 priced is already gone and the remainder is console polish over a built surface; an apiclient wrapper plus a card on the existing `/ui/users/{user_id}` page — whose builder renders only profile/roles/scope/actions (`messagefoundry_webconsole/pages/admin.py:152-158`) — and a golden-surface update. _(was 5/10 · 2/10.)_
> **On-trigger / demand-gate.** Numbered for tracking only — build when the trigger below fires (“demand-gate, don’t schedule”).

> **AMENDED 2026-07-28 — the API half is BUILT; the console view is the remainder. ⚠️ This item was nearly closed in error.** A first pass read the merged endpoint as the whole item; two independent adversarial lenses **both refuted** that, and they were right. **BUILT:** `GET /users/{user_id}/permissions` (`messagefoundry/api/auth_routes.py:610`, docstring citing BACKLOG #177 at `:615`) resolving the flattened effective set via `AuthService.identity_for_user_id` (`:622`) — the same `Identity.build` path `/auth/me` uses — with tests and `docs/SECURITY.md` coverage.
>
> ⚠️ **The REMAINDER: the Scope says "An admin endpoint … PLUS console view", and the re-score explicitly prices in "a console pane".** `user_detail_page` returns only Profile / Roles / Channel-scope / Account-actions cards, `_user_detail` never calls the inspector, the golden `/ui` route surface contains **no** permission-inspector route, and `apiclient/` has **no wrapper** for the endpoint — so the console cannot even reach it. An admin still cross-references `/users` × `/roles` by hand, which is the exact workaround the item exists to remove. Build the pane; do not rebuild the endpoint.

**Cluster:** Security. **Priority:** P3. **Verdict:** demand-gate. **Severity (vs Corepoint):** minor.

**Scope:** An admin endpoint (e.g. GET /users/{id}/permissions) plus console view that resolves the flattened effective permission set (built-in-role ∪ custom-role ∪ extras) for a specified user id, not just the caller's own via /auth/me.

**Trigger:** build when an operator needs to audit or troubleshoot what a specific non-self user can actually do rather than manually cross-referencing /users against /roles.

**Why:** Partial. /auth/me flattens the caller's own effective permissions and /roles + /users expose the role→permission and user→role maps, but no endpoint resolves the flattened effective set for an arbitrary user.

**Source:** BACKLOG coverage audit of the 2026-06-27 Corepoint gap analysis against `origin/main` (2026-07-09) — 246 capabilities triaged; this one verified **open and untracked**. Cross-ref [#52](archive/backlog/BACKLOG-CLOSED.md#52-corepoint-capability-parity-gaps--prioritized-roadmap-input-2026-06-27).

---

## 178. SFTP cipher / KEX / MAC allow-lists

> 🔢 **Re-scored 2026-08-03 → DEMAND-GATE.** Value **3/10** · Difficulty **3/10** · _fill-in_. Niche knob a FIPS-restricted partner needs — `client.connect` passes no `disabled_algorithms` (`messagefoundry/transports/remotefile.py:396-405`), so only host-key posture is operator-configurable. Cost is a new validated operator setting into one connector, and the Scope's second clause (preferred-ordering on the SSH Transport) is not reachable through `SSHClient.connect` — it must be set on the Transport before negotiation, so `_make_client` restructures rather than gaining one kwarg. _(was 3/10 · 2/10.)_

> **On-trigger / demand-gate.** Numbered for tracking only — build when the trigger below fires (“demand-gate, don’t schedule”).

**Cluster:** Security. **Priority:** P3. **Verdict:** demand-gate. **Severity (vs Corepoint):** minor.

**Scope:** Operator-configurable SFTP cipher/KEX/MAC algorithm allow-lists (paramiko disabled_algorithms plus preferred-ordering on the SSH Transport) on the REMOTEFILE sftp source and destination.

**Trigger:** build when a partner SFTP endpoint requires a specific or FIPS-restricted cipher/KEX/MAC set that paramiko's defaults do not offer or would down-negotiate below policy.

**Why:** Real gap. The REMOTEFILE sftp client negotiates ciphers/KEX/MACs entirely from paramiko defaults with no operator knob — host-key verification and FTPS ECDHE-group hardening are configurable, but neither pins the SSH transport's algorithm sets.

**Source:** BACKLOG coverage audit of the 2026-06-27 Corepoint gap analysis against `origin/main` (2026-07-09) — 246 capabilities triaged; this one verified **open and untracked**. Cross-ref [#52](archive/backlog/BACKLOG-CLOSED.md#52-corepoint-capability-parity-gaps--prioritized-roadmap-input-2026-06-27).

---

## 179. Archive-aged-rows to separate store

> 🔢 **Re-scored 2026-08-03 → DEMAND-GATE.** Value **6/10** · Difficulty **4/10** · _quick win_. Real CIEArchive parity gap — `RetentionRunner` deletes and never tiers, and the fallback it names is a whole-store snapshot two backends refuse outright; a copy-then-purge step across the store seam, tested on SQLite, PostgreSQL and SQL Server.

> **On-trigger / demand-gate.** Numbered for tracking only — build when the trigger below fires (“demand-gate, don’t schedule”).

> ⚠️ **AMENDED 2026-08-03 — the delete side is per-connection, not store-wide, and the `.mfbak` fallback this item names does not snapshot the store on two of three backends.** The Why says the `RetentionRunner` "purges aged bodies and dead-letters **store-wide by age**", but the pass resolves a **per-connection** window off the live registry every run — `_resolve_overrides` reads each inbound's `messages_days` and each outbound's `dead_letter_days` (`messagefoundry/pipeline/retention.py:625`), `_cutoff_map` turns them into the `connection_cutoffs=` the purges take (`:681`, applied at `:427-437`), and `0` means keep-forever (`_KEEP_FOREVER`, `:76`) — beside a separate per-inbound embedded-document strip on its own window (`_resolve_document_prune`, `:649`, #47/ADR 0042). The named fallback is narrower still: the store snapshot applies **only** to `[store].backend = "sqlite"` (`messagefoundry/pipeline/dr_backup.py:15`) and a server-DB store is forced config-only (`:294`), so on Postgres and SQL Server there is no whole-store `.mfbak` to fall back to. ⚠️ **The gap itself stands, unchanged** — every purge path in that pass still deletes without tiering — but the build must now tier **per connection** to match the window it is tiering out of, and cannot lean on `.mfbak` as the interim answer on a server backend.


**Cluster:** Store / Operations. **Priority:** P3. **Verdict:** demand-gate. **Severity (vs Corepoint):** minor.

**Scope:** An archive-to-separate-store step in the retention pass that copies aged message-body and dead-letter rows into a configured archive store before purge deletes them, keeping the operational store lean while archived history stays retrievable.

**Trigger:** build when a migrating Corepoint site relies on CIEArchive-style archived-but-searchable history that retention's delete-only purge would discard.

**Why:** Real gap. The [retention] RetentionRunner purges aged bodies and dead-letters store-wide by age with no copy-to-archive step, and the DR .mfbak backup snapshots the whole store rather than tiering aged rows into a separate queryable archive.

**Severity note:** the analysis rates this **unrated**; recorded as **minor**. Capability is prose-only in the analysis (the "log archive DBs/CIEArchive" gap under Logging, Audit & Log Archives, line 120) — no top-gaps table row, so analysis_severity is unrated. The Message Store prose (line 122) treats retention/purge/VACUUM as present and names stored-message editing as the sole "real gap," not archive-to-separate-store. Applying the unrated conservative rule: minor unless it is a real…

**Source:** BACKLOG coverage audit of the 2026-06-27 Corepoint gap analysis against `origin/main` (2026-07-09) — 246 capabilities triaged; this one verified **open and untracked**. Cross-ref [#52](archive/backlog/BACKLOG-CLOSED.md#52-corepoint-capability-parity-gaps--prioritized-roadmap-input-2026-06-27).

---

## 180. Cross-backend store migration tool

> 🔢 **Re-scored 2026-08-03 → DEMAND-GATE.** Value **6/10** · Difficulty **5/10** · _quick win_. Real gap — `open_store` picks a backend but nothing moves rows between them (no such subcommand exists in messagefoundry/__main__.py), so the only path discards retained history and audit; an offline row copy that re-wraps every `mfenc` body and reproduces the staged plus history shapes on all three backends.

> **On-trigger / demand-gate.** Numbered for tracking only — build when the trigger below fires (“demand-gate, don’t schedule”).

**Cluster:** Store / Operations. **Priority:** P3. **Verdict:** demand-gate. **Severity (vs Corepoint):** minor.

**Scope:** An offline tool that copies an existing SQLite store's rows (in-flight staged ingress/routed/outbound plus retained message/dead-letter history, preserving disposition and re-encrypting under the target key) into a SQL Server or Postgres store, so an adopter switches backends without draining history.

**Trigger:** build when an adopter must promote an in-production SQLite store to a server backend without losing retained history/audit.

**Why:** Real gap. open_store selects among SQLite/Postgres/SQL Server and retention/encryption exist per backend, but there is no cross-backend data-copy tool — the only documented path is greenfield drain-before-cutover, which discards retained history.

**Severity note:** the analysis rates this **unrated**; recorded as **minor**. Analysis rates this unrated (prose-only, PARTIAL in Database Connectivity §106; a listed gap in Administration §126 where only DR tooling is flagged major). Per the conservative rule for unrated items, this is minor rather than the downstream's moderate: it is a one-time, rare backend switch with a viable workaround — quiesce/drain in-flight staged rows, then cut over to the new backend and start fresh. Only…

**Source:** BACKLOG coverage audit of the 2026-06-27 Corepoint gap analysis against `origin/main` (2026-07-09) — 246 capabilities triaged; this one verified **open and untracked**. Cross-ref [#52](archive/backlog/BACKLOG-CLOSED.md#52-corepoint-capability-parity-gaps--prioritized-roadmap-input-2026-06-27).

---

## 181. Multipart/form-data outbound encoder

> 🔢 **Re-scored 2026-08-03 → DEMAND-GATE.** Value **3/10** · Difficulty **3/10** · _fill-in_. Niche multipart upload most REST/SOAP partners never ask for and a hand-built Handler body covers; a boundary encoder plus a per-request Content-Type on a connector whose type is fixed at construction (messagefoundry/transports/rest.py:1355), with the collision-checked boundary idiom already written at messagefoundry/transports/dicomweb.py:262-290 to copy.

> **On-trigger / demand-gate.** Numbered for tracking only — build when the trigger below fires (“demand-gate, don’t schedule”).

**Cluster:** Web Services & HTTP. **Priority:** P3. **Verdict:** demand-gate. **Severity (vs Corepoint):** minor.

**Scope:** A multipart/form-data body encoder on the REST/SOAP outbound clients that frames one or more parts (text fields plus a binary attachment part from mfb64/raw_bytes) with a generated boundary and sets the multipart Content-Type, instead of only a single flat encoded payload.

**Trigger:** build when a partner REST/SOAP endpoint requires a multipart/form-data upload (e.g. a document-upload API expecting a file part).

**Why:** Partial. REST()/SOAP() clients can set any content_type and body but have no multipart/form-data encoder; the nearest is DICOMweb multipart/related framing (DICOM-only) plus mfb64 base64 in a single flat body.

**Source:** BACKLOG coverage audit of the 2026-06-27 Corepoint gap analysis against `origin/main` (2026-07-09) — 246 capabilities triaged; this one verified **open and untracked**. Cross-ref [#52](archive/backlog/BACKLOG-CLOSED.md#52-corepoint-capability-parity-gaps--prioritized-roadmap-input-2026-06-27).

---

## 182. Per-message base-address override for web-service senders

> 🔢 **Re-scored 2026-08-03 → DEMAND-GATE.** Value **3/10** · Difficulty **4/10** · _fill-in_. Niche sender-control knob with a clean one-connection-per-address fan-out, and its own severity note rates it minor; the difficulty is a per-message carry key on the ALREADY-SHIPPED ADR 0081 metadata channel — a reserved `http.url`-style key read where `outbound_headers_from_metadata` is read today (rest.py:1373) — plus wiring `consumes_metadata` onto SOAP and a delivery-time SSRF/egress re-check across three HTTP clients. No new store column and no 3-backend change.

> **On-trigger / demand-gate.** Numbered for tracking only — build when the trigger below fires (“demand-gate, don’t schedule”).

> ⚠️ **AMENDED 2026-08-03 — the sibling knob is not "tracked", it SHIPPED; and the line this item cites for the fixed-url resolution now points at unrelated code.** The Why says "the sibling per-message-headers knob is **tracked as #68**", but [#68](archive/backlog/BACKLOG-CLOSED.md#68-dynamic-per-message-outbound-http-headers) closed **2026-07-12**: a Handler's `http.header.*` `SetMeta` entries are projected onto the outgoing request, read at `messagefoundry/transports/rest.py:1373` and opted into per connection via `consumes_metadata` (`rest.py:1177`, `fhir.py:261` — **not** SOAP, which has neither). The Severity note's `wiring.py:1229-1312` anchor has drifted off the url resolution entirely — that range is now the ADR 0154 sync-reply helpers (`messagefoundry/config/wiring.py:1231`, `:1243`, `:1283`); the fixed `url` is a construction parameter at `:1625` (`Rest`), `:1696` (`FHIR`) and `:2311` (`Soap`), which is where the "resolved once at construction" claim actually reads true. ⚠️ **The gap stands** — the carriage channel is built and proven for headers, but no reserved key carries a target base address — so the remainder is a reserved key on a shipped mechanism plus the delivery-time SSRF/egress re-check, not a new channel.


**Cluster:** Web Services & HTTP. **Priority:** P3. **Verdict:** demand-gate. **Severity (vs Corepoint):** minor.

**Scope:** Let a Handler set the target base endpoint URL per message on a REST/SOAP/FHIR Send (carried as data), so delivery overrides the connector's fixed url with a message-computed address.

**Trigger:** build when a partner requires the outbound endpoint computed from message content (e.g. a per-facility/registry address) rather than fixed in connector settings.

**Why:** Real gap. REST/SOAP/FHIR outbounds resolve a single fixed url at construction; the sibling per-message-headers knob is tracked as #68 but no path carries a message-computed target base address.

**Severity note:** the analysis rates this **minor**; recorded as **minor**. The downstream agent rated this "moderate," but the gap analysis explicitly rates the covering row "minor" (line 71, top-gaps table). The rule is that the analysis rating wins unless its rationale is factually wrong now — it is not: the override remains per-connection/env-resolved with no runtime per-message path (wiring.py:1229-1312), exactly as stated. This is a sender-control convenience, not a migration/ops…

**Source:** BACKLOG coverage audit of the 2026-06-27 Corepoint gap analysis against `origin/main` (2026-07-09) — 246 capabilities triaged; this one verified **open and untracked**. Cross-ref [#52](archive/backlog/BACKLOG-CLOSED.md#52-corepoint-capability-parity-gaps--prioritized-roadmap-input-2026-06-27).

---

## 183. SOAP MTOM/XOP binary packaging

> 🔢 **Re-scored 2026-08-03 → DEMAND-GATE.** Value **3/10** · Difficulty **3/10** · _fill-in_. Niche IHE packaging format that base64-inline already serves for any accepting partner; XOP framing is spec-fiddly but confined to one connector's string-concatenated envelope (messagefoundry/transports/soap.py:643-702), with no body signature to disturb and the DICOMweb boundary generator to borrow.

> **On-trigger / demand-gate.** Numbered for tracking only — build when the trigger below fires (“demand-gate, don’t schedule”).

**Cluster:** Web Services & HTTP. **Priority:** P3. **Verdict:** demand-gate. **Severity (vs Corepoint):** minor.

**Scope:** MTOM/XOP outbound packaging on the SOAP destination: when a <Body> fragment carries a binary payload via the mfb64 marker, serialize the envelope as multipart/related with an xop:Include reference and the bytes as a separate MIME part, instead of base64-inline in the XML.

**Trigger:** build when a SOAP document-exchange partner (e.g. IHE XDS.b) requires MTOM/XOP-encoded binary attachments a migration depends on.

**Why:** Real gap. The SOAP destination emits a single string-concatenated envelope with binary inline-base64 in the <Body>; there is no multipart/related XOP packaging, so an MTOM-expecting partner cannot be served.

**Severity note:** the analysis rates this **unrated**; recorded as **minor**. MTOM/XOP appears only in a prose PARTIAL list (line 110), not in the analysis's top-gaps severity table, so the analysis itself assigns no severity (unrated). The downstream agent rated it "moderate"; I lower to minor. Per the unrated rule, minor is the default unless the item is a real migration/ops blocker, and MTOM/XOP is not: MeFor already carries binary payloads over SOAP via base64-inline XML (the mfb64…

**Source:** BACKLOG coverage audit of the 2026-06-27 Corepoint gap analysis against `origin/main` (2026-07-09) — 246 capabilities triaged; this one verified **open and untracked**. Cross-ref [#52](archive/backlog/BACKLOG-CLOSED.md#52-corepoint-capability-parity-gaps--prioritized-roadmap-input-2026-06-27).

---

## 184. Serve own endpoint WSDL

> 🔢 **Re-scored 2026-08-03 → DEMAND-GATE.** Value **3/10** · Difficulty **2/10** · _fill-in_. Niche SOAP interop knob with a clean out-of-band-WSDL workaround; a configured document served off the listener's existing GET/HEAD health short-circuit (messagefoundry/transports/http_listener.py:796-797), which already returns before any ingress row.

> **On-trigger / demand-gate.** Numbered for tracking only — build when the trigger below fires (“demand-gate, don’t schedule”).

**Cluster:** Web Services & HTTP. **Priority:** P3. **Verdict:** demand-gate. **Severity (vs Corepoint):** minor.

**Scope:** Serve a partner-facing WSDL document at the inbound HTTP/SOAP listener (e.g. GET ?wsdl) so a SOAP partner can fetch our endpoint's contract for their client tooling.

**Trigger:** build when a migrating SOAP partner requires fetching a WSDL from our inbound endpoint to generate/validate their client.

**Why:** Partial. The inbound HTTP listener (ADR 0023) receives SOAP-over-HTTP bodies and answers GET with only a static health response — it publishes no WSDL, and #69 covers importing a partner's WSDL, not serving our own.

**Source:** BACKLOG coverage audit of the 2026-06-27 Corepoint gap analysis against `origin/main` (2026-07-09) — 246 capabilities triaged; this one verified **open and untracked**. Cross-ref [#52](archive/backlog/BACKLOG-CLOSED.md#52-corepoint-capability-parity-gaps--prioritized-roadmap-input-2026-06-27).


---

## 214. Intra-message concurrent transform of a message's routed rows

> 🚧 **PARTIAL — the intra-message transform-overlap mechanism is MERGED and tested; a SEPARATE, UNBUILT XL residual remains (see below). Re-priced 2026-07-28.** Value **3/10** · Difficulty **8/10** · _money pit_. The banner's *"routed rows transform sequentially today"* premise is out of date: `RegistryRunner._process_routed_batch` (`messagefoundry/pipeline/wiring_runner.py:4790`) already overlaps the pure off-loop transforms of a message's co-claimed sibling rows, while **every store handoff stays serial and in claim order** — so the single-serial-writer invariant that per-destination outbound FIFO depends on is untouched — and the same cap doubles as the live-lookup (`db_lookup`/`fhir_lookup`) fan-out guard. Covered by `tests/test_transform_concurrency.py` (586 ln). Difficulty **8/10** priced *building* that seam, which no longer needs building.
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

## 228. Steps / config search finds handlers, routers, and transforms by name (not just connections)

> ✅ **CLOSED 2026-08-05 — both 2026-07-28 remainders built.** Value **4/10** · Difficulty **2/10**. **(a)** Definitions rows now carry a `contextValue` of their own — `meforSymbolHandler` on a handler row — gating the inline **View as Steps** action, which resolves through the row's *file*. They deliberately do **not** borrow `graphModel`'s `meforElementHandler` / `meforElement`, and no row claims an `elementKind` / `elementName`: a row's name is the Python **function** name (`def handle`) while the graph is keyed by the registered **decorator** name (`@handler("acme_adt_handler")`), and every `samples/config/` module makes the two differ — so the element vocabulary would render a **Show in Wiring Map** action that could only ever land on "the focused element no longer exists in the graph". Router / transform / send rows carry no action. **(b)** `SymbolKind` gains `send`: a separate extraction pass (a `Send(…)` sits inside a def body, out of reach of the column-0 def regex) indexes the connection each call addresses, at the call-site line; its comment guard is quote-aware, so a *trailing* `# was Send("OB_OLD", …)` is not a call site while a `#` inside a string literal does not truncate the line. **This is a bound, not a completeness claim:** at least quoted-literal targets and module-level `NAME = "literal"` constants are indexed; at least a computed, imported, or f-string target — and a ruff-wrapped call whose target is not on the `Send(` line — is dropped rather than guessed. **That is NOT the `graph --json` bound:** that extractor marks an unresolvable target `dynamic` and *surfaces* it ([ADR 0091](adr/0091-element-centric-connections-view.md) AC-3), and its module-constant rule validates against the whole module, neither of which this flat text scan does. The graph views remain the authority on resolved wiring. Twenty-one new tests, all node-side (so they run on every `ide` CI leg, not only the Windows Extension Host leg), each falsified.

> **AMENDED 2026-08-05 — both remainders described below are now BUILT; the 2026-07-28 block that follows is the historical record, not current state.** Read it as the finding that scoped this work, not as a live gap. The one correction worth carrying forward: remainder (a)'s diagnosis named `viewItem == meforElementHandler` as the gate to satisfy, and adopting that value verbatim is precisely what the close had to avoid — see the CLOSED banner above.

> **AMENDED 2026-07-28 — the index IS built; two clauses of the Proposed line are not.** Adversarial verification refuted a full close. **BUILT:** `ide/src/symbolIndex.ts` scans and surfaces handlers / routers / transforms **by name** in the MEFOR view's Definitions section, unit-tested — which fixes the item's headline complaint (a transform is a Python symbol inside a file named for the *connection*, so neither the sidebar search nor Ctrl+P could find it).
>
> ⚠️ **REMAINDER (a): a hit cannot open straight into the Steps view.** The Proposed line asks to reuse the CodeLens / `openSteps` entry point, but Definitions rows carry **no `contextValue`**, so the inline "View as Steps" action — gated on `viewItem == meforElementHandler` — never renders on them, and a click runs plain `openSource`. ⚠️ **REMAINDER (b): "(and the outbound connections a handler sends to)" is outside the index** — `SymbolKind` is `handler|router|transform` only, and the definition regex matches **top-level `def`** only. Both are small; neither is done.

**Cluster:** IDE & Authoring. **Priority:** P2. **Verdict:** build. **Severity:** low.

**What:** the MessageFoundry sidebar search (the box over the MESSAGEFOUNDRY view) matches **connection** names only. Searching for a **handler / router / transform** name — e.g. `xform_SITEA_to_erp_mfn` — returns “No matching results” even though that handler exists (it is defined inside `IB_FILE_HR_Materials_SITEA_MFN.py`, a role-combined feed module whose *filename* is the connection, not the handler). VS Code's own `Ctrl+P` also misses it, because the name is a symbol inside a file, not a filename.

**Why:** operators think in terms of the **transform / message name**, not the feed file it happens to live in. The connection→router→handler wiring is a graph (CLAUDE.md §1), so a user who knows the transform name has no direct path to its definition. It is sharper for the ported migration estate where feeds are still monolithic (see #226): one file holds the connection + router + handler, so the handler name appears nowhere in the tree or the filename.

**Proposed:** index handlers / routers / transforms (and the outbound connections a handler sends to) by name in the MEFOR view search, and jump to the `@handler`/`@router`/`inbound`/`outbound` definition on a match — reusing the CodeLens / `openSteps` entry point so a hit can open straight into the Steps view. A `lens parse` (or a light `findElements` scan) over the config dir already yields the handler/router names.

**Source:** owner report 2026-07-11 while previewing the shipped IDE against the ported migration estate — searched a transform name in the MEFOR view, got “No matching results”. Related: #226 (split monolithic feeds, which would also surface handler names as files).

---

## 232. Steps view for routers

> 🔢 **Filed 2026-07-30 — not started.** Value **5/10** · Difficulty **5/10** · _fill-in_. ADR-first: a `route` row kind widens the ADR 0076 §3 grammar, so the amendment lands before any build.

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

## 234. Steps view projection refreshes on save only

> 🔢 **Filed 2026-07-30. PARTLY LANDED 2026-08-04 — the race half is fixed; the save-gate relaxation this item was filed for is STILL OPEN. Re-framed 2026-07-30 to match the instruction that filed it.** Value **4/10** · Difficulty **3/10** · _fill-in_. This was originally recorded as "revisit — do not treat as a bug", which contradicted the owner's actual words: *"Put that fix on the backlog too."* It is a **fix**, gated on an ADR amendment — not a question about whether to act. **Landed:** a user save arriving while a `lens rewrite` held the single edit slot was **discarded**, leaving the view on a pre-save projection with no signal until the next save; it is now deferred to slot release and re-projected exactly once ([ADR 0076](adr/0076-typed-action-vocabulary-action-list-lens.md) Amendment C — written **PROPOSED, not ratified**; owner ratification still needed). **Still open:** whether a *bounded relaxation* of the save gate is safe. Argue it against the corrected premise, not the old one: `render()` pipes `document.getText()` to `lens parse -` over stdin, so rows are projected from the **live buffer**, not from disk — the "stale disk content" justification the gate's own comment carried was false. The surviving reasons are re-shelling Python per keystroke and the fact that a re-projection replaces the entire webview HTML. `RERENDER_DEBOUNCE_MS` is now at `stepsView.ts:91`, not `:89` as the text below says. The engineering caveat that motivated the softer framing is preserved below and is unchanged.

**Cluster:** IDE & Authoring. **Priority:** P3. **Verdict:** **build (ADR-first)** — owner asked for the fix; the save-gate it touches is a deliberate ADR 0076 §5 guardrail, so the amendment lands before the change. **Severity:** low (UX latency).

**What:** the Steps view re-projects the handler on **save**, not on edit. Type in the split text editor and the rows do not follow until the buffer is written. Live values go further and are **skipped entirely while `document.isDirty`**.

**Read this before building:** sync-on-save is a **deliberate guardrail**, not an oversight. ADR 0076 §5 adopts the verified InterSystems/VS Code set *wholesale*: "**Sync on save only; one editor at a time; update-loop guard; Reopen With: Python always available**". And the live-value skip is a **correctness** fix, not laziness (#225): the trace reads the module **from disk** while rows are projected from the **live buffer**, so after an unsaved structural edit the disk trace's line numbers describe the pre-edit file and mapping them by line containment would attach a value marker to the **wrong row**.

**So the item is:** decide whether a *bounded* relaxation is safe — e.g. debounced re-projection of **rows only** (already partly present: `RERENDER_DEBOUNCE_MS = 250`, `stepsView.ts:89`) while keeping live values save-gated; and whether the update-loop guard (`EditLoopGuard`) still holds if projection races an in-flight `lens rewrite`. Any change here **amends ADR 0076 §5** and must re-argue the guardrail it removes.

**Non-goal:** removing the save gate on live values. #225's dirty-buffer misalignment is a real correctness hazard and its fix (re-attach on save) should stand unless the trace itself learns to read the buffer.

**Related:** #222, #225 (live values + the dirty-buffer skip), ADR 0076 §5.

**Source:** Windmill/Kestra evaluation (2026-07-30); owner asked for it to be filed the same day.

## 235. Generate Steps view parameter forms from Python type hints

> 🔢 **Filed 2026-07-30 — not started.** Value **4/10** · Difficulty **4/10** · _fill-in_. Widens what is *editable* without widening the recognition grammar; sequence deliberately against #237.

**Cluster:** IDE & Authoring. **Priority:** P2. **Verdict:** build (evaluate as its own lane). **Severity:** low.

**What:** today a recognized row exposes **enabled inputs only for literal params**; anything else renders visibly disabled (`stepsView.ts:11-13`). Windmill's pattern is to derive a **JSON Schema from the script's Python type hints** and render the step's parameter form from that schema. Applied here: `lens parse` (or a sibling `lens schema`) emits, per recognized action, a small parameter schema derived from the vocabulary helper's own **type hints** — which ADR 0076 §2 already requires to be "fully type-hinted, mypy-strict".

**Why it is attractive:** it widens what is *editable* without widening the **recognition grammar** — the expensive, ADR-amendment-gated axis. The row set stays exactly as recognized today; only the input widgets get richer (enum → dropdown, `Literal["upper","lower","title"]` → radio, int → number field with validation, code-set name → the existing `codesetList` picker).

**Build sketch:** engine side, derive the schema from `messagefoundry/actions.py` signatures (stdlib `inspect`/`typing`, no new runtime dep — ADR 0076 §6.5 forbids one in phases 1–2); IDE side, replace the hand-rolled per-op input rendering in `stepsModel.ts` (`ADD_MENU_CATALOG`, `TOOLBAR_INSERT_DEFAULTS`) with a schema-driven renderer. Keep `code`/`control` rows read-only.

**Open question:** whether the schema is emitted by the engine (one source of truth beside the vocabulary, matching the ADR 0072 L5/L6 split the lens already follows) or hard-coded in the IDE. Engine-side is the consistent choice and is the recommendation to test first.

**Related:** #222, ADR 0076 §2 (typed, mypy-strict vocabulary), [ADR 0106](adr/0106-steps-view-add-dropdown-vocabulary-expansion-adr-0076-phase-b.md) (the 27-item palette this would re-render), #237 (per-argument input modes — same form surface, land them together or in a deliberate order).

**Source:** Windmill/Kestra evaluation (2026-07-30) — "borrow the idea, not the product"; owner approved testing it as a separate lane.

## 236. Test-this-step and test-up-to-step with pinned upstream values

> 🔢 **Filed 2026-07-30 — not started.** Value **5/10** · Difficulty **4/10** · _fill-in_. Largely a stop condition + state dump on ADR 0072's traced dry-run; lookup rows must mock by default, not as an afterthought.

**Cluster:** IDE & Authoring. **Priority:** P2. **Verdict:** build (evaluate as its own lane). **Severity:** low.

**What:** the Steps view's Test control delegates to the Test Bench — it runs the **whole** handler. Windmill's OSS editor offers *test this step*, *test up to this step*, and **step mocking** (pin an upstream step's output and run from there). The analog: run a handler **up to row N** against a chosen synthetic sample and show the message state at that point; optionally pin an upstream row's result so a lower row can be exercised without re-running an expensive lookup.

**Why it fits the existing machinery:** the pieces are already shipped. ADR 0072's traced dry-run (`dryrun --trace json`) already produces per-line values and the lens already folds them onto rows by line containment (`mergeLiveValues`, `traceRowValues`), and the sample picker already exists (Test Bench pattern, defaulting to `messageSetsDir`). "Up to row N" is largely a **stop condition + a state dump** on a path that already runs.

**Hard parts:** (a) `db_lookup`/`fhir_lookup` rows do real I/O — "pin/mock upstream" is what makes partial runs safe and must be the default for lookup rows, not an afterthought; (b) the dirty-buffer misalignment of #225 applies identically (the trace reads disk); (c) **PHI**: any state dump reuses ADR 0072's `--show-phi` redaction gate unchanged, adds no second gate, and persists nothing — the lens's trace argv must remain incapable of emitting `--show-phi` (`buildLensTraceArgs`).

**Related:** #222, #225 (live values), [ADR 0072](adr/0072-traced-dryrun-mode.md) (traced dry-run + the redaction gate), Test Bench (`ide/src/testBench.ts`).

**Source:** Windmill/Kestra evaluation (2026-07-30); owner approved testing it as a separate lane from #235.

## 237. Per-argument input modes (static templated dynamic) in the Steps view

> 🔢 **Filed 2026-07-30 — not started.** Value **4/10** · Difficulty **4/10** · _fill-in_. Gated on #233: the duplicated move/drop logic is a prerequisite for touching this form surface.

> ⚠️ **AMENDED 2026-08-03 — the value-expression class this item plans to "surface" is not computed in the shipped `lens parse` row contract; step 1 of the build sketch is a new classifier, not an exposure.** The Why prices this as "a presentation of a distinction the lens **already computes**, not new recognition", but `lens parse` computes only a **binary** split per argument: `params` renders a literal as its value and anything else as verbatim source, and `literal_params` is the subset that is an `ast.Constant` (`messagefoundry/lens.py:245-249`, `:255`, emitted at `:260` and at `:750`/`:760`/`:770`; derived by `_literal_param_names` at `:934`). The ten-way literal / field-copy / conditional / lookup / concat / … taxonomy is ADR 0089 §5's own one-off `ast` scan ([ADR 0089](adr/0089-recognition-first-lens-native-idioms.md):85), and its successor **declines to reimplement it on the record** — `scripts/quality/lens_coverage.py:12-16` drives the shipped `lens parse --json` precisely to avoid "a second implementation of the grammar that could drift", and its own `classify_code_row` (`:84`) buckets opaque rows by first-statement shape, not by value class. ⚠️ **This narrows nothing — no part of the mode selector exists** — but the difficulty was priced against a field that does not, so re-price before scheduling. The reuse dependencies the sketch names do check out: `ide/src/hl7Picker.ts` and `ide/src/hl7scope.ts` are present, and both named backlog dependencies (#233, #235) are still open.


**Cluster:** IDE & Authoring. **Priority:** P2. **Verdict:** build. **Severity:** low.

**What:** today a parameter slot is effectively **literal-or-refused** — a literal is editable, anything else (a `msg[...]` read, a concat, a conditional) collapses the row's editability. Windmill's flow editor instead gives every argument an explicit **mode**: *static* (a literal), *templated* (an interpolation over upstream values), or *dynamic* (an expression), with a picker over what is available upstream. Adopting the mode concept turns "this row is not editable" into "this argument is in dynamic mode", which is both more honest and more useful.

**Why it matters here specifically:** ADR 0089's estate scan found the editable/opaque split is driven by **value-expression shape** — it classifies every `msg.set` value as literal / field-copy / conditional / lookup / concat / replace / split / substring / trim / case. Those classes map almost one-to-one onto modes, so this is a presentation of a distinction the lens **already computes**, not new recognition.

**Build sketch:** surface the value-expression class in the `lens parse` row contract; render a mode selector per argument; static mode keeps today's plain input; templated mode offers the HL7 path picker (`hl7Picker.ts`) over the segment scope already built by `hl7scope.ts`; dynamic mode stays read-only in v1 (shows the verbatim source) so no new rewrite class is introduced.

**Sequencing:** shares the parameter-form surface with **#235**. Deciding the schema shape first (#235) and layering modes on top (#237) avoids reworking the renderer twice — but they are separately valuable and can be evaluated independently.

**Related:** #222, #235 (schema-driven forms), ADR 0089 §5 (the value-expression classifier this reuses), ADR 0104 §2.3 / `hl7Picker.ts` (the path picker).

**Source:** Windmill/Kestra evaluation (2026-07-30); owner approved.

## 238. OpenFlow step-attribute completeness pass over the engine vocabulary

> 🔢 **Filed 2026-07-30 — not started.** Value **1/10** · Difficulty **1/10** · _fill-in_. A review whose output is findings, not a feature; OpenFlow is explicitly **not** a compatibility target.

**Cluster:** IDE & Authoring / Engine. **Priority:** P3. **Verdict:** build (a review, not a feature). **Severity:** none — this is a gap-analysis task whose output is findings.

**What:** read Windmill's **OpenFlow** step-attribute vocabulary as a **completeness checklist** against MessageFoundry's own step/connector semantics, and record what is missing, what is deliberately absent, and what is already covered under a different name. The attributes to walk: `retry`, `timeout`, `stop_after_if`, `skip_if`, `continue_on_error`, `mock`, `cache_ttl`.

**Explicitly NOT the goal — do not target OpenFlow compatibility.** OpenFlow is an open standard (Apache-2.0, so safe to read and cite) but its `info.version` tracks Windmill's own release tag, i.e. one vendor's weekly train. Emitting or consuming OpenFlow is a **separate** question and is not authorized by this item. Adopting a *declarative artifact* remains declined by ADR 0076 §7 and #26.

**Expected output:** a short findings note (a research doc or an amendment to this item) listing, per attribute: covered / not covered / deliberately declined, with the MessageFoundry construct that covers it. Some will already be covered engine-side rather than in the Steps view (retry/timeout live in connector + delivery semantics, not in a handler row), and saying so precisely is most of the value.

**Related:** #222, ADR 0076 §7 (declarative artifact declined), #26 (the visual/declarative-authoring line).

**Source:** Windmill/Kestra evaluation (2026-07-30); owner approved the checklist framing explicitly ("don't target compatibility").

## 248. Steps view: reclassify comment-only rows as a non-opaque note row

> 🔢 **Filed 2026-07-30 — not started. UNBLOCKED 2026-07-30:** Value **6/10** · Difficulty **4/10** · _quick win_. the ADR gate is cleared — **ADR 0076 Amendment A is ACCEPTED and in force** (owner-ratified 2026-07-30), so the grammar widening this item needs is authorized and the build may proceed. Treat Amendment A §A.4's invariants as **build gates, not caveats**, and note §A.6: this item does **not** fix comment re-attachment on move/delete, nor the parent-nesting of a comment at the end of an `if`/`for` body.

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

> 🔢 **Filed 2026-07-30 — not started, and not yet accepted.** Value **3/10** · Difficulty **2/10** · _fill-in_. Salvaged from a declined design; the owner has not ruled on whether to fund it.

**Cluster:** IDE & Authoring. **Priority:** P3. **Verdict:** **owner decision pending** — proposed, not approved. **Severity:** none (additive capability).

**What:** add `--format mermaid|dot` to the existing `graph --json` command, so an interface's topology can be rendered as a diagram from the CLI without a second tool.

**Where it came from:** the 2026-07-30 Windmill/Kestra evaluation scored five integration designs. The one called "Tracing Paper" — a one-way OpenFlow export — **scored 5.7 and was declined**. This is the salvage from it: the estimate recorded at the time was **2–3 days**, and unlike the declined design it introduces no foreign artifact format and no second execution path.

**Why it is filed rather than built:** it was a recommendation in a design memo that the owner never answered, and that memo has since been deleted. Filing preserves the option at its stated price; it does not approve it.

**Related:** #238 (OpenFlow attribute checklist — the other salvage from the same evaluation), ADR 0076 (the lens CLI surface).

**Source:** Windmill/Kestra evaluation (2026-07-30), "Tracing Paper" design, declined; salvage recorded here so the estimate is not lost with the memo.

## 318. DAST — authenticated dynamic security testing of the running engine

> 🚧 **In progress 2026-07-31.** Value **7/10** · Difficulty **6/10** · _big bet_. Increment 1 built: an authenticated authorization sweep against a live loopback listener in front of a real engine (negative / authorized-reach / viewer BFLA), with fail-closed floors and two canaries. Increment 2 — schema-driven breadth, the unauthenticated MLLP/TCP/X12 ingress plane, the /ui console plane and a TLS black-box target — is not built.

**Type:** security testing — dynamic (DAST) tier of [`Secure_Development_Standards`](Secure_Development_Standards.md) §6.1.

**What:** a self-run, deterministic, **zero-new-dependency** authorization sweep against a real HTTP listener. One `uvicorn` server binds loopback on an ephemeral port, on one event loop, in front of a real `Engine` and a real `AuthService`; an administrator and a viewer identity are minted **over the wire** through `POST /auth/login`. The authorization expectation is **derived from the live route table** — a single shared `require*()`-closure walk in `scripts/security/route_gates.py`, hoisted out of the security doc-drift guard so exactly one derivation exists — never a hand-kept route→permission list. Three passes: **negative** (every gated HTTP row sent with no credential and with an invalid bearer; anything but 401 is a finding), **authorized reach** (how many gated `GET` rows a *privileged* token got past authentication and authorization on), and **viewer BFLA** (anything but a refusal, including 404, is a finding). The run writes a receipt naming what it examined and **fails closed** — below any floor it exits 2 (could not measure), never 0.

**Why:** every security test in the tree is static or in-process; nothing had ever driven the HTTP surface over a real socket with real credentials, so the §6.1 *Dynamic* row was empty. The specific hazard is that a deny-by-default API rewards a lazy scanner: point an unauthenticated crawler at it, get 401 everywhere, exit 0, and read it as *all endpoints protected* having proved nothing. The **authorized reach** count is the direct answer to that, and the two canaries — built from **supported configuration, not source patches**, so there is nothing anchored to line numbers to rot — prove each run that the sweep can still see a real defect. The merge-blocking half is deliberately elsewhere: the sweep and canaries run as ordinary pytest inside the **existing required** test legs (so blinding the detector reds a PR), while the nightly workflow is advisory — no `pull_request` trigger, and deliberately **not** `continue-on-error`.

**Boundary:** see ADR 0155 §*Scope boundary*. It is stated once, there; this item deliberately carries a pointer and no wording of its own, because a paraphrase here would survive the next revision of that section and become a second, contradictory answer.

**Increment 2 (not built):** schema-driven breadth (needs an OpenAPI security overlay and a fifth DEP-1 lock); protocol fuzzing of the unauthenticated MLLP / raw-TCP / X12 ingress (highest-value deferred item — note that BACKLOG #89's *"ADR 0054 adversarial audit harness"* does not exist, so there is no mutator to extend); DICOM DIMSE (pynetdicom owns the socket, so there is no engine-owned reader to drive); the `/ui` console plane; a TLS black-box target for the https-gated controls; a shipped-defaults controls probe (the scan relaxes MFA, four limiters, lockout and step-up freshness, and prints every relaxation in the receipt); and non-`GET` reach/BFLA.

**Known gap carried by increment 1 (follow-up, not deferred scope):** a red DAST nightly notifies nobody. `nightly-notice.yml` opens an issue only for the workflow named `CI`, and `dast.yml` has no `pull_request` arm and is not a required context, so a genuine finding surfaces in the Actions tab and nowhere else. Widening the notice workflow's `workflows:` list (with the matching edit to `tests/test_nightly_notice.py`, which pins that name) is the fix; it is recorded here so it is a tracked item rather than a footnote.

**Related:** ADR 0155, `.github/workflows/dast.yml`, `scripts/security/dast_auth_sweep.py`, `scripts/security/route_gates.py`, `scripts/security/dast-policy.json`, `tests/test_dast_auth_sweep.py`, `tests/test_dast_claims.py`, [`Secure_Development_Standards`](Secure_Development_Standards.md) §6.1 / §A.6.

**Source:** the empty §6.1 *Dynamic* tier row, filed and built 2026-07-31.

## 320. windows-2025 is the slowest CI leg (1.8x-3.5x), but that does not explain the 60/s failures

> 🚧 **Status: OPEN INVESTIGATION (filed 2026-08-01, not started).** Value **3/10** · Difficulty **3/10** · _fill-in_. Diagnosis only — the CI symptom is already fixed (#115, `06fd327d`) by widening the reconcile's stranding budget. This item is the **underlying capacity fact**, which that fix does not address and deliberately did not try to. Tooling to measure it landed in #118 (`harness/load/ingress_probe.py` + a dispatch-only sweep across ubuntu / windows-2022 / windows-2025). The decisive experiment — the same sweep on the **self-hosted WS2025 rig** — is blocked: that runner is unregistered (`actions/runners` → `total_count: 0`) and `selfhosted-win2025-sql.yml` has never run.

**Type:** CI/runner capacity — not a correctness defect. No message was ever lost in any observed instance.

**What:** `tests/test_load_runner.py` offers **60 msg/s for 1.5s** (90 messages, `pool_size = 4`) at a listener whose ingress is **strictly serial per connection** — `mllp.py:1433` is `read chunk → for each frame → await handler → next`, where the handler is the durable ingress commit the ACK depends on. Total ingress throughput is therefore `pool_size ÷ per-message-commit-latency`. That leg red `main` twice on runs that lost nothing, stranding ~51% of sends at teardown.

> ⚠️ **THE ORIGINAL DIAGNOSIS HERE WAS WRONG AND IS CORRECTED BELOW.** This item first claimed windows-2025 "cannot service 60/s" and is "~10x slower". A 36-run measured sweep (#118, run `30705885914`) does not support either: windows-2025 strands **0% at 60/s, 150/s and 300/s**, and is **1.8x-3.5x** slower than ubuntu, not 10x. The leg *is* reproducibly the slowest — that part holds — but the 60/s CI failures remain **unexplained**.

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

**MEASURED ACROSS ALL THREE HOSTED SKUs (2026-08-01, run `30705885914`, 36 runs, 3 per cell).** This supersedes every rate claim above it.

Stranded fraction:

| offered | ubuntu | windows-2022 | windows-2025 |
|---|---|---|---|
| 60/s | 0, 0, 0 | 0, 0, 0 | **0, 0, 0** |
| 150/s | 0, 0, 0 | 0, 0, 0 | **0, 0, 0** |
| 300/s | 0, 0, 0 | 0, 0, 0 | **0, 0, 0** |
| 600/s | 0, 0, 0 | 4.6%, 8.9%, 19.2% | **25.4%, 30.7%, 31.1%** |

Wall time (the cleaner signal — all three still ingest everything up to 300/s):

| offered | ubuntu | win-2022 | win-2025 | 2025 vs ubuntu |
|---|---|---|---|---|
| 60/s | 2.8s | 4.7s | 4.9s | **1.8x** |
| 150/s | 4.3s | 10.1s | 11.9s | **2.8x** |
| 300/s | 8.4s | 22.0s | 29.8s | **3.5x** |

**What this settles.** A consistent ordering — ubuntu > windows-2022 > windows-2025 — and windows-2025 strands ~3x more than windows-2022 at saturation, tightly clustered. It is genuinely the slowest leg, and measurably slower than its sibling on identical hosted infrastructure.

**What it refutes.** "~10x slower" and "cannot service 60/s" are both wrong. The gap is a **latency** gap of 1.8x-3.5x, not a capacity cliff: windows-2025 ingests **everything** up to 300/s, five times the rate the failing test offers.

**So the 60/s failures are still unexplained** — real (byte-identical twice) but not a property of the SKU at that rate, or this sweep would show them.

**The untested variable is CONTENTION, and it is now the leading hypothesis.** The probe runs the engine **alone** on an idle runner; the CI failure happens with the full suite running alongside it inside a ~20-minute job. That also matches the one developer-box outlier retracted above, which appeared only while an unrelated suite was running. The honest next experiment is measuring under concurrent load — not another quiet-runner sweep, which would answer nothing new.

**Consequence for priority: this is a TOLERANCE problem, not a throughput one.** A leg 3x slower than ubuntu, occasionally contended by its own test suite, will occasionally strand at 60/s — which is exactly what #115's widened stranding budget absorbs. That fix is now better supported than when it was made, and the product concern this item originally raised (a shipping deployment target being 10x slow) is **not supported by measurement**. A 1.8x-3.5x gap on a hosted VM image says nothing about Windows Server 2025 as a deployment target.

**Still not determined:** why the hosted windows-2025 image is 1.8x-3.5x slower than ubuntu — disk/fsync, Defender scanning the temp SQLite DB, CPU contention are all plausible and none is measurable from outside the runner. Low value now that the magnitude is unremarkable.

**Adjacent finding, unverified:** at saturation `engine_read` (452) cleared the reconcile's unconditional anti-vacuity floor `read >= sent // 2` (450) by **two messages**. A breach of that floor is a hard failure no budget widening can rescue. A probe at 1200/s did *not* reproduce it, but that run is not comparable — its drain timed out (`max_drain_seconds` observed `-1.0`) and it took the branch that skips the settle-poll. Untested, not disproven.

**Related:** #115 (`06fd327d`, the budget fix), `harness/load/report.py` `_reconcile`, `harness/load/connscale/runner.py`, `harness/load/estate/runner.py`, `tests/test_load_runner.py`, `tests/test_harness_reconcile.py`, `messagefoundry/transports/mllp.py:1433`, and the sibling windows-2025 failure `test_coord_lock` (fixed in #109) — a *different* mechanism on the same leg.

**Source:** investigation of the `test_run_load_end_to_end_no_loss` failures on `main` at `9b03057f` and `56f7d240`, 2026-08-01.

---

## 321. Leak gate is blind to the ported-estate site-code and partner-product token class

> 🔢 **Filed 2026-08-01 — not started.** Value **7/10** · Difficulty **3/10** · _quick win_. A required merge context exited 0 on content carrying a real site code and a partner product name, with no compensating control (`scan_forbidden.py:10-12` is explicit that gitleaks finds secrets, not this class) and nothing stopping the next estate-derived identifier landing the same way; `.md` is not in `_SITE_SKIP_SUFFIXES` (`scan_forbidden.py:119`, `{".lock", ".svg"}`) so the file was scanned — the fix is owner-run token data across the private file plus the Actions *and* Dependabot secret stores, a negative test per class, and optionally a structural shape backstop.

> ⚠️ **AMENDED 2026-08-03 — the "no negative test" premise is false; the detector-coverage half of Proposed 2 is already in the tree.** The item says "Today no test asserts the detectors can see a site code at all, which is why the hole was invisible", but `tests/test_scan_forbidden.py` carries per-class hit tests for at least the site code (`:126`), a customer name (`:83`), a case-sensitive code (`:91`) and a routable IP (`:107`), plus the boundary and skip-suffix controls at `:136` and `:152`, with the structural classes covered separately in `tests/test_scan_tokens_source.py` (`:539`, `:559`). ⚠️ **What those tests cannot prove is exactly what this item is about.** They monkeypatch a **synthetic** site-code pattern over `SITE_CODE_RE` / `_SITE_CODE_FILE` (`:50-52`, `:66-67`), so they exercise the machinery and never the loaded token set — and with no prefix loaded both detectors fall back to the always-failing sentinel `_NEVER` (`scripts/security/scan_forbidden.py:111`, `:453-454`). **Both remaining halves stand untouched:** the owner-run token data (Proposed 1) and the prefix-free estate-identifier shape backstop (Proposed 3) — the committed structural detectors are at least the routable-IPv4 pattern, `_WORKTREE_SLUG` (`:92`) and `_HOME_PATH` (`:99`), none of which match that shape. The item's own two anchors still resolve exactly (`scan_forbidden.py:10-12`, `:119`).


> ⚠️ **AMENDED 2026-08-04 — the hardware blocker has an EXPIRY DATE now.** This item is gated on a
> controlled multi-VM lab that the project did not own; one is ~2 weeks out as of 2026-08-04, so any
> sentence below saying the rig is unavailable, unregistered or not the project's to provide is
> **true today and scheduled to become false**. Do not read it as a permanent block. Tracked by
> **[#1003](#1003-validate-the-lab-and-discharge-the-four-hardware-gated-residuals)**, which fires on
> *lab available for validation* and carries this item's run: its decisive experiment needs a registered self-hosted WS2025 runner, which the lab supplies.

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

## 325. Leak gate's home-path detector is case-blind on Windows paths

> 🔢 **Filed 2026-08-01 — not started.** Value **6/10** · Difficulty **2/10** · _quick win_. A structural detector in a required merge context — the one control meant to work in a fork with no token source — fires on one of four spellings of the same Windows home path (`_HOME_PATH` compiles with no flags and matches a literal `Users`, `scripts/security/scan_forbidden.py:99-106`), against the module's own "fail toward more detection" rule, though the disclosure is an OS account name and the tree holds zero live hits; an inline `(?i:)` on the drive-letter arm only (whole-pattern `re.I` measured 47 false positives), the sibling two-character `_WORKTREE_SLUG:92` edit, and casing fixtures beside the sole canonical-case test at `tests/test_scan_tokens_source.py:559-577`.

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

5. **Same fix site, sibling defect:** `_WORKTREE_SLUG` at `scripts/security/scan_forbidden.py:92` is case-blind the same way (`[a-z0-9]+`); an upper-cased slug — `claude/` followed by `Some-Task-a1b2c3` — is MISSED. (Written split on purpose, for the reason in the note above: once the fix lands, the joined literal trips the very detector it documents, and unlike `_HOME_PATH` the slug pattern has no `<…>` exemption to write it into.) `scripts/worktree/new.ps1:43,86` passes `-Name` through verbatim with no lowercasing, so an upper-cased worktree name is reachable. Narrower than the home-path case (agent-created slugs are lowercase by convention), but it is a two-character edit in the same block — take it in the same change or say why not.

**Related:** `scripts/security/scan_forbidden.py` (`_HOME_PATH` :99-106, `_WORKTREE_SLUG` :92, call site :758-759), `tests/test_scan_tokens_source.py:559-583`, `.github/workflows/security.yml:446-493`, `.github/required-contexts.txt`, `scripts/worktree/new.ps1`. Sibling **#321** — same gate, same "green gate that cannot see the class" root cause, but the **opposite mechanism**: #321 is an incomplete *token source* (data, fixed by the owner updating a private secret) and explicitly scopes itself away from scanner defects at `docs/BACKLOG.md:7356`; this is a *structural detector* defect (code, fixed by a regex edit) that is live even with no token source. Also **#322**, and the anonymizer's structural-detector item from this same audit. Note #321's **Related:** line at `docs/BACKLOG.md:7363` cites `tests/test_scan_forbidden.py` for regression tests, but the home-path test actually lives in `tests/test_scan_tokens_source.py` — worth correcting when someone next touches #321.

**Source:** public-repo disclosure audit, 2026-08-01. Verified open at HEAD (`12efbffc`) by executing the compiled pattern and by diffing the current, proposed and naive-`re.I` variants across every git-tracked file.

---

---

## 327. No test asserts the private-path `.gitignore` block still ignores anything

> 🔢 **Filed 2026-08-01 — not started.** Value **6/10** · Difficulty **2/10** · _quick win_. Six `.gitignore` rules are the sole control keeping maintainer-internal security material out of a public commit since the publish deny-list was retired, and the repo-wide search for `check-ignore` matches exactly one hand-run script (`scripts/dev/setup-leak-gate.ps1:58`) covering a different file, so the boundary is defended by review attention plus a hook that lives inside the now-ignored `/.claude/` tree and no fresh clone gets; a pinned-literal test with a synthetic probe child, plus dropping `^\.gitignore$` from the `noncode` allowlist at `.github/workflows/ci.yml:658` — without that edit the guard goes green on exactly the PR it exists to catch.

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

> 🚧 **Status OPEN — Proposed 1-2 SHIPPED 2026-08-04, Proposed 3 DEFERRED.** `messagefoundry audit-anchor` (`--service-config` / `--db` / `--json`, with the same SQLite missing-DB refusal as its verify twin, so a typo'd path cannot mint an empty database and print an anchor OF NOTHING) prints `COUNT:HEAD`, and `audit-verify --expected-anchor COUNT:HEAD` / `--expected-anchor-file PATH` feeds it into the already-present `expected_anchor=` keyword — no comparison-logic change and no store migration, as filed. `docs/FEATURE-MAP.md`'s hand-maintained CLI count moved 30 to 31 with it. **Proposed 3 — the `[integrity]` startup-anchor key — is NOT built, which is why this stays OPEN.** The reason is measured, and pinned by `test_an_anchor_goes_stale_on_the_next_appended_row`: the shipped comparator is an EXACT point-in-time seal (row count *and* head hash), so a stored anchor consumed by the startup auto-verify would fire a false `integrity_drift` on essentially every restart, because any running instance writes audit rows. It needs a seal-on-stop / check-on-start design (or a monotonic-prefix comparator) before it is worth wiring, and the plumbing is a THREE-file edit — `config/settings.py`, `pipeline/engine.py`, and `api/app.py`'s `create_managed_app`, which is the only route an `[integrity]` key reaches the Engine by, and which the multi-session plan had scope-dropped. `[integrity].audit_verify_on_start` therefore remains a bare walk and still cannot see a truncated tail; that limit is now stated on its own `docs/CONFIGURATION.md` row and in ADR 0014 §16.4.2. The SQL Server and Postgres `audit_anchor` CLI tests are written and collect cleanly but have **never executed locally** (no Docker daemon) — they are CI-verified only. _(was 5/10 · 3/10.)_

> ⚠️ **AMENDED 2026-08-04 — `api/app.py` is IN scope; the multisession plan was wrong to drop it.**
> `SCHEDULABLE-BACKLOG-MULTISESSION-PLAN.md` scoped this item as "CLI + settings" and said **DROP
> `api/app.py`**. Verified against HEAD: every `[integrity]` setting reaches the Engine **only** through
> `create_managed_app` — `audit_verify_on_start=integ.audit_verify_on_start` at
> `messagefoundry/api/app.py:5467`, fed from `__main__.py`. Building to the plan's scope would ship a
> **dead setting**: configurable, documented, and never read. Caught by the lane doing recon before
> building, which is the only reason it was caught at all.

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

> 🔢 **Filed 2026-08-01 — not started.** Value **6/10** · Difficulty **4/10** · _quick win_. The LDAPS bind (`ssl.CERT_NONE` on the authentication substrate for every AD identity), the SFTP host key, the webhook sink and the `[ai].api_key` still cross an enforcing production-PHI posture on one env var, and converting them is what collapses five per-site facts into one repo-wide invariant the ASVS scorecard's regex mechanism can actually express — bounded because setting the variable needs Administrator, who can already do worse; the cheap in-gate half shipped with #323, so what remains is threading an explicit posture into `AuthService`/`create_app`'s three out-of-gate constructors, where `_here()` would otherwise ship green and inert.

> ⚠️ **AMENDED 2026-08-03 — the census is FOUR, not five: #323 landed and took the Direct SMTP cell.** The heading, the evidence table (*"Confirmed at HEAD"*) and Proposed §1 all still name `transports/direct.py:170` as an unclamped cell, but that file now holds **no call to the raw predicate at all** — it imports only `weakened_tls_escape_permitted_here` (`messagefoundry/transports/direct.py:63`) and gates both arms on it (`:197` cleartext SMTP, `:215` `tls_verify=false`), with the #323 rationale — including its own warning that this absence is scoped to that file and never repo-wide — at `:182-196`; `:170` is now unrelated cert-loading. The Scope note called this in future tense and the 2026-08-03 banner already enumerates only four cells while still calling them *"five per-site facts"*, so read the table as **at least four** sites still reading the unclamped `insecure_tls_allowed()`: the SFTP host key (`messagefoundry/transports/remotefile.py:375`, feeding `AutoAddPolicy`/`RejectPolicy` at `:392-394`), LDAPS (`messagefoundry/auth/ldap.py:113`), the webhook alert sink (`messagefoundry/pipeline/alert_sinks.py:291` — the item cites `:290`) and the AI broker (`messagefoundry/transports/ai_broker.py:140`).
>
> ⚠️ **Do not read the banner's "the cheap in-gate half shipped with #323" as discharging Proposed §1.** #323 took `direct.py`; it did **not** take `remotefile.py:375`, the other in-gate cell §1 names, which still reads the raw predicate. §1 therefore shrinks to a single one-line swap rather than closing, and §2's out-of-gate work is entirely untouched — LDAPS, the webhook sink and the AI broker are all still raw, including the LDAPS cell this item ranks first.


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

## 331. Anonymizer's fail-closed leak-check has no structural PHI detectors

> 🔢 **Filed 2026-08-01 — not started.** Value **6/10** · Difficulty **4/10** · _quick win_. The function that earns the right to share a de-identified dataset verifies a known-string denylist — `leak_check` is `scan_text` (FORBIDDEN patterns, one routable-IPv4 check, estate substrings; `scripts/security/scan_forbidden.py:772-795`) plus a field-anchored site code, and a real MRN is not a denylisted string — and on a token-less checkout it degrades to the IPv4 check alone over an HL7 body and still returns clean, a gap `f3c6d348` hit in practice with a hand overlay that was never committed; wiring `token_floor_failure()` into the bridge is small, but the unmapped-field report and detectors scoped to fields no rule matched cross the `anonymize` seam and must be mirrored into `tee/anon/leak.py` for `test_anon_parity`.

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

> 🔢 **Filed 2026-08-01 — not started.** Value **6/10** · Difficulty **5/10** · _quick win_. Arbitrary code from any of ~30 floating transitives at `.github/workflows/release.yml:255` runs with the OIDC identity that then signs the wheel, writes the SLSA attestation and publishes to PyPI — a backdoored artifact carrying a *valid* Sigstore bundle and valid provenance — and no Dependabot ecosystem parses an inline `pip install X==Y`, so the pin rots with no trigger and no owner (the two siblings at `:104` and `:207`, the latter a `~=` range, float identically); the ADR 0034 hashed-lock mechanism is proven and running for `ci-scanners`/`ci-quality`, but `sigstore` is absent from every lock (`grep -c sigstore uv.lock` → 0), adding a seventh is a six-place lockstep edit, the resolve contamination may force the same excluded-by-decision call semgrep got, and no PR leg ever executes this path.

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

> 🔢 **Filed 2026-08-01 — not started.** Value **6/10** · Difficulty **4/10** · _quick win_. Build state confirmed OPEN: `tls_allow_expired` appears in none of `config/settings.py`, `api/app.py`, `checks.py`, `__main__.py`; `config/wiring.py:3271` still carries only `accepted_cleartext_hops`; `security_loosenings` at `settings.py:4062` takes the fifth `alerts` parameter #323 added; `transports/database.py:298` still matches `_ODBC_TLS_HINT_RE` against keys only. Value 6 holds. Difficulty 3 prices a copy of #323's precedent and misses that the remainder is not one connector's setting: step 1 inverts a test (`test_database_transport.py:202-212`) that PINS the current DEBUG branch, step 2 needs an inbound name that `config/models.py` Source does not carry (registry plumbing at the construction site), step 4 adds TWO required parameters to `security_loosenings`, breaking all four caller signatures (`api/app.py`, `checks.py`, `__main__.py` x2), step 5 adds sibling advisory CheckResults, step 7 rewrites five DEPLOYMENT.md assertions that become false the moment step 4 lands, and step 8 extends the completeness floor with a connection-scoped arm. That is the rubric's `4` — "a feature across a seam" — not `3`, "a new setting into one connector". Quadrant and tier are unaffected (value 6, difficulty <=5 = quick win, P2). _(was 6/10 · 3/10.)_

*(Filed as one item, not two: both are fixed by the same edits to the same four files — a reader beside `accepted_cleartext_hops`, an entry in `security_loosenings()`, an advisory beside `_check_cleartext_accepted`, and threading at `api/app.py`. Stated once rather than twice, per the docs rule against restating a load-bearing fact.)*

**Partial delivery from [#323](#323) layer 3 (2026-08-02) — this item stays OPEN.** #323 added the `[alerts]` SMTP hop's deviations (`email_use_tls` / `email_tls_verify`) to `security_loosenings()`, which required giving it a 5th **required** `alerts` parameter, and added an `alert-smtp-tls` advisory beside `_check_cleartext_accepted`. So the *shape* this item asks for now exists and has a worked precedent — but **neither of this item's two deviations is closed**: `tls_allow_expired` on the six outbound connectors and the generic-ODBC DATABASE hop are both still invisible, and no connection-scoped `unverified_smtp_hops()` reader was built (that would report the **connectors'** `tls_verify=false`, which is this item's territory, not #323's). The completeness floor in `tests/test_security_posture_defaults.py` still iterates `SecuritySettings.model_fields` only, so per-connection settings and `[alerts]` fields remain structurally invisible to it — #323's entries are guarded by hand-written tests, not by the floor. Do not read this note as progress toward closure; read it as one worked example to copy.

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

## 337. handler-security lint: `getattr` indirection and the undecorated helper

> 🔢 **Filed 2026-08-01 — not started.** Value **3/10** · Difficulty **3/10** · _fill-in_. `_AMBIENT_BARE_NAMES` (`checks.py:476`) still matches a literal name chain and `checks.py` contains no `getattr` resolution at all, and the rule loop still bails on `_message_fn_decorator(node) is None` (`:937`) so the `_<feed>_transforms.py` helper CONNECTIONS.md steers PHI handling into is never opened — but the lint is advisory unless an adopter opts into `--strict-handler-security`, and evading it reaches neither the DEK nor the audit chain in either sandbox posture; ~15 lines splicing a constant into `_dotted_call_name` plus a `phi-to-log` widening that must be recalibrated against the two shipped sample helpers before it lands.

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

> 🔢 **Filed 2026-08-01 — not started.** Value **3/10** · Difficulty **2/10** · _fill-in_. `harden_kex_groups` still returns `None` when `set_groups` is absent, and all three restatements survive the 2026-07-29 sweep — `CONTAINER-EXPOSURE-EVALUATION.md` still says "hardened KEX groups" under a *verification* heading, `BACKLOG.md:6422` still lists 11.6.2 in #200's Closes line against PHI.md's PARTIAL, and `ASVS-L2-PHASE0-CHANGES.md:254` still presupposes a pin — but every group that gets in is forward-secret and the floor plus `harden_cipher_suites` admit nothing static, so this is documentation accuracy plus observability; three doc edits and one additive report-only `SecurityPosture` field beside `fips_attestation()`, with the two tripwire tests left alone as the 3.15 trigger.

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

> 🔢 **Filed 2026-08-01 — not started.** Value **6/10** · Difficulty **4/10** · _quick win_. Build state confirmed: zero of the 21 files under `.github/workflows/` carries a `merge_group:` trigger, so difficulty 4 and the step-2-is-a-precondition reasoning are right. Value 8 is not. The rubric's `8` is "an ASVS L3 Partial on defaults, or a production blind spot with no workaround" — this is neither. It is a repo-workflow blind spot, and a workaround demonstrably exists and is exercised: `gh pr update-branch` (#74 landed via three merges from main, #119 landed via re-sync), plus a detector the project already BUILT for exactly this condition and which the item itself cites — `scripts/ci/check_stalled_prs.py` + `.github/workflows/stalled-prs.yml`. So the readiness signal is not in fact unfalsifiable from outside: a scheduled job reports the stalled set. That makes it "real gap, awkward workaround" = 6, one rung above the rubric's `4` for DX (the item's own cluster is Developer Experience & CI), and 6 is generous for a cluster the ladder caps at 4. At value 6, difficulty 4: quadrant stays quick win, but tier is P2 (P1 needs value >= 8, or value >= 6 at difficulty <= 2 — and this one is 4). _(was 8/10 · 3/10.)_

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

> 🚧 **Status OPEN (filed 2026-08-01).** Value **6/10** · Difficulty **3/10** · _quick win_. A mechanical margin check would have flagged windows-2025 at 1.006x before #119 died where the manual alternative was published wrong twice, and the shared Windows budget still admits the three-PRs-each-adding-a-minute death nobody is individually at fault for; `_wait_until` already raises with a full dispatcher/store dump citing proposal 6 (`tests/test_stage_dispatcher.py:485-497`) and no margin script exists under `scripts/ci/`, so the remainder is that script — timing the STEP, keyed on the step's own conclusion, against a right-censored max — plus giving `Web console tests (pytest)` its own cap instead of the shared `matrix.step_timeout` at `ci.yml:442`. _(was 6/10 · 4/10.)_

**Cluster:** Developer Experience & CI. **Priority:** P2. **Verdict:** build. **Severity:** medium.

**What:** a fixed wall-clock bound with no relationship to the work it bounds fails the day the work grows, and it fails as a **timeout with zero assertion failures** — which reads as a broken branch when nothing is broken.

*Instance 1 (fixed 2026-08-01, this filing).* `ci.yml`'s Windows `step_timeout: 26`. windows-2025's max PASSING `Tests (pytest)` step was **25:51** — a **1.006x** margin, nine seconds — and PR #119 was killed at 26:07 with zero test failures after #74 added a 1,506-line test file. The comment beside the cap asserted "~2x headroom", a figure that matched no leg. Raised to 36:00 (1.393x) with the measurement, its pool and its date recorded in place of the multiple. Pool: every `ci.yml` run created 2026-08-01 UTC — 70 runs, per-leg n = 42 ubuntu / 39 windows-2022 / 36 windows-2025 — timing the STEP and filtering on the STEP's own conclusion. That pool is **right-censored**: it predates the raise, so every observation survived a 26:00 cap and 25:51 is a *lower bound* on what the suite wants. Confirmed the next day, once the cap no longer censored it: windows-2025 produced **26:23 twice, both passing** — runs that the old cap would have killed. The API hides this by default: the jobs endpoint returns only the latest attempt, so a step killed at the cap is invisible behind its passing re-run unless you ask for `?filter=all`.

*Instance 2 (**RESOLVED 2026-08-02 — and it was never a bound problem**).* Presented as `tests/test_stage_dispatcher.py`'s `_wait_until` 8.0s budget expiring on the SQL Server leg with zero logic assertions failing (two occurrences in 21 days: `test_adr0070_1_stop_policy_bounds_deterministic_infra_head`, run 30733129076; `test_adr0070_9_content_retry_is_not_an_infra_fault`, run 30716979773 attempt 1 — ~0.4%/test over ~479 observations, zero on Postgres/119 and zero on SQLite/1,105). **The bound was never the cause and must not be raised**: the test passes in max 0.204s on green SQL Server jobs and 0.576s at worst across 241 runs, so 8.0s is 14–39× the worst passing run and both failures sit ~7× beyond the *entire* passing distribution — a gap, not a tail. Past ~31s a raise would convert a real 30-second store hang into a silent PASS.

The actual mechanism, **proven by forcing it on a live SQL Server** rather than argued: `claim_fifo_heads` runs under `SET LOCK_TIMEOUT 0`, so a momentarily contended head raises native error **1222** instantly; the store **catches 1222 and returns a normal EMPTY result** (`store/sqlserver.py`, the `_is_lock_timeout` branch — deliberate, the "never-block" yield, logged only at DEBUG). The dispatcher's EMPTY branch then takes **T12**: `phase=IDLE` with **no timer armed**. In production the periodic sweep re-readies exactly such a lane; the ADR 0070 tests set `sweep_interval=3600` with an empty `lane_provider` **on purpose**, so IDLE is **terminal** there and the lane can never be re-claimed — the poll then cannot succeed at any budget. Holding a conflicting row lock across the post-unpark re-claim reproduces it deterministically: `empty_claims` goes `(0,0,0)` → `(1,0,1)`, the lane sits `IDLE` with `park_until=None` and no armed timer, the head is still `pending` and **due**, and releasing the lock does *not* recover it. The same stranding was then observed **unforced** on a local full-file run (`test_adr0070_1_retry_forever_never_stops_alerts_stuck[sqlserver]`). This is a **test-rig gap, not an engine defect** — production's backstop (the sweep) is intact, and arming a timer on every EMPTY instead would re-introduce the very spin ADR 0070's fix-A backoff exists to collapse.

**"SQL Server-only" is the wrong reading, and the distribution does not say otherwise.** There is a *second*, quieter route to the same spurious EMPTY on SQL Server: the batch claim's lock probe runs `WITH (UPDLOCK, ROWLOCK, READPAST)`, so a contended head is **skipped**, and the head-pinned contiguity step then drops the whole lane ("rn=1 missing drops the whole lane => EMPTY") — with **no log line at all**, not even the DEBUG one. And Postgres is **not structurally immune**: its claim uses `FOR UPDATE SKIP LOCKED` ([`store/postgres.py`](../messagefoundry/store/postgres.py)), the same head-of-line skip; its 119 observations at a ~0.4% rate expect ~0.5 events, so they exonerate nothing. Only **SQLite's** 0/1,105 is structural (in-process, no lock-timeout translation and no skip-locked semantics). Read the symptom as **server-backed store**, and note that the counters cannot separate the two SQL Server routes — both read `(1, 0, 1)`.

Fixed two ways in [`tests/test_stage_dispatcher.py`](../tests/test_stage_dispatcher.py): `_wait_until` now **raises on expiry** carrying the lane's phase, park deadline, streak, task state, the store row's status/`next_attempt_at`, the clock, and `empty_claims` — plus a one-line **verdict** naming which hypothesis the reading proves, so no future occurrence needs re-diagnosing from scratch; and the ADR 0070 waits now stand in for the sweep those tests disable — re-readying a lane found in terminal IDLE, but **counted and capped at one**, so a genuine contention regression still fails loudly instead of being absorbed. Both halves are falsification-tested: with the stand-in disabled the same injected EMPTY reproduces the original failure, now carrying the full diagnostic instead of a bare `assert False`.

*Instance 2, RE-DIAGNOSED 2026-08-02 — and the original diagnosis was wrong.* It recurred on PR #138, on a different test (`test_adr0070_1_stop_policy_bounds_deterministic_infra_head[sqlserver]`, run 30733129076), and the timings refute "the bound is too small": the failing test took **8.185s**, i.e. `_wait_until` burned its full 8.000s and setup+teardown cost 0.185s — the store was *fast* at the moment of failure. In the same process, against the same container, the sibling `test_adr0070_1_retry_forever_never_stops_alerts_stuck[sqlserver]` drove **seven** identical fault cycles in **0.364s**, and the `[sqlite]` variant of the failing test passed in 0.144s. One fault cycle costs ~30-45 ms against an 8000 ms bound. Over a sample of green sqlserver jobs this test passes in min 0.185s / median 0.196s / max 0.204s, so the bound is ~39x its worst passing run; a wider 21-day pass put the worst passing observation at 0.576s, still ~14x. Rate: 2 failures in ~479 observations of the two affected tests (~0.4%). Postgres saw zero in 119 observations, which **exonerates nothing** — at ~0.4% that sample expects ~0.5 events, and Postgres claims via `FOR UPDATE SKIP LOCKED`, the same head-of-line skip; only SQLite's 0 in 1,105 is structural, because its global lock totally orders producers and claimers. Both failures sit ~7x beyond the entire passing distribution — a gap, not a tail, which is the signature of a categorically different event rather than latency creep.

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
6. **Make a bound's expiry diagnostic before tuning it — and for instance 2 the instrument already ships.** A bare `assert await _wait_until(...)` reports `assert False` and nothing else, so every occurrence is re-diagnosed from scratch; instance 2 was read as latency for a day on exactly that basis. Have the helper raise on timeout carrying the lane's phase, park deadline and streak, whether its task is alive or holds an exception, the store row's status, and the clock. **One assertion settles instance 2's open mechanism:** `StageDispatcher.empty_claims` ([`stage_dispatcher.py`](../messagefoundry/pipeline/stage_dispatcher.py):1230) returns `(total, wake_fanout, idle_poll)` and is fed by `_record_empty`, called from exactly one site — the EMPTY branch of `_claim_and_dispatch` (:686). Under these tests' topology a clean run must read `(0, 0, 0)`, so `empty_claims[0] > 0` at the moment of failure is proof of a spurious EMPTY, and `== 0` is proof the claim never returned at all. A second, free signature is in the captured log, **for the infra-fault test only**: a healthy `test_adr0070_1_*` emits **four** `re-pending head with backoff` records (at `1001.000 / 1003.500 / 1008.000 / 1016.500`) and the failing run emitted **one**. It does NOT generalise — `test_adr0070_9_*` takes the content path, which uses `mark_failed` and never emits that line, so **zero** there is expected and is not a second mechanism. Read the counter, not the log, when in doubt. This proposal cannot itself be wrong about the cause, which is why it comes before the others.

**Related:** [`.github/workflows/ci.yml`](../.github/workflows/ci.yml) §*Tests (pytest)* (instance 1 and its measurement table); [`tests/test_stage_dispatcher.py`](../tests/test_stage_dispatcher.py) (instance 2 — `_wait_until`'s raising expiry report and the counted `_wait_lane` sweep stand-in); [`store/sqlserver.py`](../messagefoundry/store/sqlserver.py) (`_is_lock_timeout` — the 1222-as-EMPTY yield that instance 2 turned on); ADR 0070 (the infra-fault machinery the affected tests cover); #320 (windows-2025 slowness — the capacity fact that shrinks every Windows margin); #340 (the other half of this triage); [`Secure_Development_Standards`](Secure_Development_Standards.md) §3 (prose asserting a margin the numbers do not support — five instances found on 2026-08-01 alone).

**Source:** stuck-CI triage, 2026-08-01. Instance 1 re-measured 2026-08-02 across 36 step-success windows-2025 rows (pool: 70 `ci.yml` runs created 2026-08-01 UTC), by two agents deriving it independently after the first two measurements both reported pools that did not reproduce; instance 2 reported and diagnosed by the HA-construct-recheck session from PR #129's sqlserver leg; instance 3 from the same 2026-08-02 re-measurement.

---
## 342. Sandbox worker kill does not reap a grandchild holding the response pipe

> 🚧 **Status OPEN (filed 2026-08-01).** Value **5/10** · Difficulty **6/10** · _money pit_. `SandboxSession._kill` ([pipeline/sandbox.py:323](../messagefoundry/pipeline/sandbox.py)) calls `proc.kill()`, which terminates **only the direct worker child**. Admin-authored Handler code running in that child can spawn a grandchild, which **inherits fd 1 — the response pipe** — and survives the kill. It can then write frames onto a pipe the parent believes belongs to a freshly-spawned worker, and it leaks as an orphan process for the engine's lifetime.

**Cluster:** Security & Compliance. **Priority:** P2. **Verdict:** build (small). **Severity:** medium, low (likelihood: requires Handler-authoring rights, i.e. the same admin threat model as #339).

**Bounded by the #339 correlation fix, not closed by it:** a grandchild cannot make the parent accept a *forged answer* — the per-dispatch `secrets.token_hex(16)` id is unguessable and the unsolicited-frame check is fatal to the worker. So the residual is **availability and process hygiene**, not misdelivery: the orphan can force repeated kill+respawn cycles on its own feed (each dead-lettering the message in hand, fail-closed) and accumulate leaked processes.

**Fix direction:** spawn into a job object on Windows (`CREATE_NEW_PROCESS_GROUP` + a kill-on-close job) and a process group on POSIX (`start_new_session=True`, then `killpg`), so the whole tree dies with the worker. Note the platform asymmetry is the same one ADR 0147 already documents for confinement, so the two should be designed together rather than twice.

**Related:** #339, ADR 0087 (residual now stated there), ADR 0147 (OS-level confinement — the natural home for the job-object work), #343 (the sibling fd-2 issue).

**Source:** adversarial review of the ADR 0087 sandbox codec, 2026-08-01.

---

## 343. Sandbox child stderr is inherited unframed into the engine log stream

> 🚧 **Status OPEN (filed 2026-08-01).** Value **4/10** · Difficulty **3/10** · _fill-in_. The worker is spawned with `stderr=None` ([pipeline/sandbox.py:266](../messagefoundry/pipeline/sandbox.py)), so the child's stderr is the **engine's own stderr**, unframed and unattributed. fd 1 is the IPC channel and is strictly framed; fd 2 has no such discipline. Admin-authored Handler code can therefore write arbitrary bytes straight into the engine's log stream — including forged log lines, ANSI control sequences, or content that breaks whatever consumes those logs (NSSM captures stdout/stderr to files; see [docs/SERVICE.md](SERVICE.md)).

**Cluster:** Security & Compliance. **Priority:** P3. **Verdict:** build (small). **Severity:** medium (log forgery / audit confusion), low (likelihood — same admin threat model).

**Two distinct problems, worth separating when fixed:** (a) **attribution** — a line from a sandboxed Handler is indistinguishable from an engine line, so an operator cannot tell which inbound produced it; (b) **PHI** — a Handler that `print()`s a message body to stderr writes a full payload into the general log at whatever level the operator is running, which CLAUDE.md §9 forbids for INFO and above. (b) is the one that matters for a PHI deployment.

**Fix direction:** capture the child's stderr (`stderr=subprocess.PIPE`) and relay it through the engine's stdlib logger on a reader thread, prefixed with the inbound + worker identity and rate-limited. That also removes the interleaving hazard of two processes writing one fd concurrently.

**Adjacent, same fd-discipline root:** a Handler that `print()`s to **stdout** is a latent landmine in both the pre- and post-#339 code — it lands in the `TextIOWrapper` buffer rather than the `BufferedWriter` the frames use, so it happens not to corrupt a frame today. That is luck, not design, and should be closed with this item (redirect the child's `sys.stdout` to stderr at bootstrap, leaving the raw fd 1 exclusively for frames).

**Related:** #339, #342 (sibling fd-1 issue), CLAUDE.md §9 (PHI logging), ADR 0087.

**Source:** adversarial review of the ADR 0087 sandbox codec, 2026-08-01.

---

## 346. The sandbox import boundary is enforced only at runtime, under an off-by-default flag

> 🚧 **Status OPEN (filed 2026-08-02).** Value **4/10** · Difficulty **3/10** · _fill-in_. A type the sandbox child must **construct or receive** cannot live under a prefix on `DEFAULT_FORBIDDEN_MODULES` ([pipeline/sandbox.py](../messagefoundry/pipeline/sandbox.py)) — the child's import guard raises and the dispatch fails. That rule is real, it has already been violated once in shipped code, and **nothing enforces it**. `CapturedResponse` lived in `messagefoundry.store`; the child could not import it, which made `mode=subprocess` + ADR 0013 loopback re-ingress **DOA** until #339 relocated it to [config/response.py](../messagefoundry/config/response.py). The only guard runs **in the child, at dispatch time, and only when `[sandbox].mode=subprocess`** — which is not the default, so a re-violation is invisible to a green suite.

**Cluster:** Correctness / test coverage. **Priority:** P2. **Verdict:** build (small). **Severity:** medium (blast radius: a feature is DOA for everyone who opted in), medium (likelihood: the codec's constructor set is precisely the surface that grows as the payload model does).

**Why it fails selectively — the reason this wants a test and not a comment.** The population that could report the breakage is the population *not* running the default. A future violation yields a green CI suite, a byte-identical `mode=off`, and a hard failure **only** on installs that turned the sandbox on for security reasons. The failure mode is inverted: the more security-conscious the deployment, the worse its experience, and the quieter the signal reaching the maintainer.

**Measured, not assumed (2026-08-02):** `git grep -l "FORBIDDEN_MODULES" -- tests/` returns nothing — no test references the constant in any form. [`_sandbox_codec.py`](../messagefoundry/pipeline/_sandbox_codec.py) imports exactly the types the two ends construct (`CodeSet`/`UnmappedKind`/`UnmappedPolicy`, `ContentType`, `CapturedResponse`, `RunContext`, `Send`/`SetMeta`/`SetState`/`WiringError`, `Message`/`RawMessage`), today all under `config/` and `parsing/` — so the invariant **currently holds**. This item is about keeping it that way, not repairing it.

**Fix direction.** A static test that walks the imports of `_sandbox_codec.py` and `_sandbox_worker.py` (stdlib `ast`, transitively across first-party modules) and asserts none resolves under a `DEFAULT_FORBIDDEN_MODULES` prefix. Anchor it on the **constant**, never a copied list — two copies of a rule drift, and the copy that drifts is the one nobody is testing.

**Measurement discipline — the part that decides whether this is worth building.** The test must be demonstrated to **fail** against a deliberately introduced forbidden import *before* it is trusted. An import-walker that silently resolves nothing passes for exactly the same reason a correct one does, so a green run proves neither. Have it report what it walked, not merely that it walked.

**Related:** #339 (surfaced it; relocated `CapturedResponse`), ADR 0087 (the boundary), ADR 0013 (the loopback re-ingress that was DOA), #342 / #343 (the other two findings the #339 review filed but did not fix).

**Source:** adversarial review of the ADR 0087 sandbox codec, 2026-08-01; the `CapturedResponse` violation is measured, not hypothetical.

---

## 353. Gate the risk-acceptance register against the scorecard: nothing compares its cell lists to the record

> 🚧 **Status OPEN (filed 2026-08-02).** Value **6/10** · Difficulty **2/10** · _quick win_. The ASVS risk-acceptance register is **ungated prose**. No CI check has ever compared the cell ids in its signed sign-off blocks against the verdict of record, and a manual cross-check found the lists had drifted substantially with **zero** alarm.

**Cluster:** Security & Compliance. **Priority:** P2. **Verdict:** file now, build on owner green-light. **Severity:** medium-high — the artifact that records *accepted risk* can disagree with the artifact that records *what the risks are*, indefinitely and silently.

**The finding that motivates it.** Asked to fix one sign-off block, a cross-check of **all eight** against `asvs-scorecard.toml` returned **29 entries that are not carried residuals**, in three classes:

| Class | Count | Why it is wrong |
|---|---:|---|
| `unverified` | 22 | ⛔ **A signed acceptance of a risk that was never assessed.** The cell has never been read against the ASVS requirement text at any commit. Present in **every one of the eight blocks**. |
| `na` | 3 | Out of declared scope — there is no residual to carry. |
| `pass` | 4 | The cell passes — there is no residual to accept. |

⚠️ **Those counts are ONE measurement by ONE session and are not independently confirmed.** They should not be load-bearing for any decision until a second implementation reproduces them — **which is exactly what this gate would be.** Treat the number as the reason to build the check, never as an established fact. *(Caveat raised by the coordinator session, and it is the right one.)*

**What the check is.** Roughly fifteen lines, stdlib only: `tomllib`-load the scorecard, regex the register's sign-off table rows, and for every cell id in every block compare against the record. Fail on `unverified`, `na` or `pass` appearing in an acceptance list. It needs no new dependency and runs in milliseconds.

**Design notes, because a gate written carelessly here would be worse than none:**

- **Print what it scanned.** Block count, row count, ids-per-block. A gate that finds nothing because its regex stopped matching the table is indistinguishable from a clean one — that failure mode has already fired twice on this project.
- **Prove it can go red before trusting a green.** Plant a known-bad id in a fixture and assert the check rejects it, and plant a clean fixture and assert it passes. Both directions, or the check is measuring nothing.
- **Do not auto-correct.** The gate must **report**, never rewrite. The cell lists sit inside *signed* acceptances, and silently editing signed content to satisfy a checker is a worse defect than the drift it fixes.
- **The register lives in the vault**, so this belongs with the existing `asvs-scorecard.yml` workflow rather than in the public engine repo.

**⛔ Not to be built without the owner's go-ahead.** A new security-doc gate can block merges, and that is the owner's decision like any other enforcing control. This item exists so the finding is durable, not to authorise the build.

**Related:** ADR 0156 (scorecard as data — the record this would check against); the §2 banner in the register recording the same finding; and the standing question this does **not** answer, which is the owner's alone: *what the 2026-07-14 signature actually covered*, given 22 of its ids had never been examined on that date either.

---

## 352. Consult on enterprise AV coverage for SFTP- and file-connector ingest from outside the domain (ASVS 5.4.3 premise check)

> 🚧 **Status OPEN (filed 2026-08-02).** Value **1/10** · Difficulty **1/10** · _fill-in_. ASVS **5.4.3** was recorded `na` on 2026-08-02 on the ground that antivirus scanning is an **enterprise-provided** control. This item exists to *test that premise* against the one ingest path most likely to fall outside it, rather than assume it.

**Cluster:** Security & Compliance. **Priority:** P2. **Verdict:** consult, then decide. **Severity:** medium — the verdict of a closed cell rests on the answer.

**The question, for Gabe (enterprise security):** how does the enterprise scanning stack handle files that MessageFoundry *collects* rather than receives — specifically the **SFTP/FTPS remote-file source** and the **file connector** — when the origin is **outside the organisation's domain**?

The distinction matters because these two paths do not look like the case AV coverage is usually designed around:

- **The engine pulls, the perimeter doesn't see a delivery.** A gateway or mail-path scanner inspects content arriving *at* the enterprise. `RemoteFileSource` reaches *out* to a partner's SFTP/FTPS server and retrieves bytes over an encrypted session, landing them straight in the engine's working area. There is no inbound delivery event for a perimeter scanner to act on.
- **On-access scanning depends on where the file lands.** If the drop directory is on a host and volume the EDR agent actually watches, on-access scanning may cover it. If it is a network share, a container volume, or a path excluded for performance (integration hosts frequently are), it may not.
- **The origin is a partner, not the enterprise.** These feeds come from outside the domain by definition, so "internal traffic is trusted" does not apply.

**What we need out of the conversation, stated as answers not opinions:**
1. Is content retrieved by an outbound-initiated SFTP/FTPS pull scanned at all — and by what, at what point?
2. Are integration hosts' drop/working directories inside on-access scanning, or excluded?
3. What happens on detection — quarantine, delete, alert-only — and does MessageFoundry learn about it, or does the file simply vanish underneath a running connector?
4. Is there an ICAP or equivalent service endpoint the engine *could* call, if we later decide to make scanning a shipped, configurable control?

**Why this is filed rather than assumed.** The `na` on 5.4.3 records its own three exposures, and the load-bearing one is that **the engine ships a scan seam** (`set_scan_hook` / `scan_inbound_file`, fail-closed on both axes when installed) — so unlike full memory encryption, this is a control the product *could* implement. The cell's ground therefore depends on the enterprise actually covering these paths. If the answer to (1) or (2) is "no", the deployment requirement attached to that `na` is not satisfied for this class of feed and the cell should be reopened by the owner.

**Do not** treat this item's existence as reopening 5.4.3. That cell is closed by owner decision; only the owner reopens it, and only with an explicit instruction.

**Related:** the scan seam at [`transports/file.py`](../messagefoundry/transports/file.py) (`set_scan_hook`, `scan_inbound_file`) and its remote sibling in [`transports/remotefile.py`](../messagefoundry/transports/remotefile.py); the deployment requirement recorded with the 5.4.3 ruling.

---

## 351. SQL Server failover test asserts on a 0.35s wall-clock margin across a real DB round-trip

> 🚧 **Status OPEN (filed 2026-08-02).** Value **4/10** · Difficulty **3/10** · _fill-in_. `tests/test_cluster_failover_sqlserver.py::test_preferred_delay0_wins_expired_lease_race_over_delayed_node` sleeps `_TTL + 0.15` so the lease is expired by ~0.15s, then requires a node carrying a **0.5s** acquire handicap to be rejected. Correctness therefore rests on **less than 0.35s of wall clock** elapsing between the sleep and `dr._maintain_leadership()` — across a real SQL Server round-trip, on a shared CI runner. Observed failing as `assert dr.is_leader() is False → assert True is False`.

> ⚠️ **AMENDED 2026-08-04 — the hardware blocker has an EXPIRY DATE now.** This item is gated on a
> controlled multi-VM lab that the project did not own; one is ~2 weeks out as of 2026-08-04, so any
> sentence below saying the rig is unavailable, unregistered or not the project's to provide is
> **true today and scheduled to become false**. Do not read it as a permanent block. Tracked by
> **[#1003](#1003-validate-the-lab-and-discharge-the-four-hardware-gated-residuals)**, which fires on
> *lab available for validation* and carries this item's run: its patch has never been executed against a real SQL Server, and the `_acquire` latency question it reserves needs a benchmark rather than a lease-election test.

**Cluster:** Testing & CI. **Priority:** P3. **Verdict:** triage — **do not "fix" by widening the margin until the question below is answered.** **Severity:** medium (a red that reads as the PR's own defect), unknown (likelihood: one observation).

**The discriminating evidence.** On the **same commit**, the `sql server (store + connector) 2022` leg PASSED while `2025` FAILED. A genuinely broken delay predicate would fail on both — that logic is backend-version independent. The job log also states `Command failed with exit 1 (not a native crash) — not retrying`, so this is **not** the pyodbc 3.14 segfault and its retry mitigation is not involved. Across the last 12 runs it was the **only** sql-server-leg failure, and a sibling PR on the same `main` passed both legs — so it is **not** repo-wide either.

**⚠️ What this does NOT establish.** It does not exonerate the PR it fired on. That PR (BACKLOG #348 / ADR 0159) adds work at the `_acquire` chokepoint — **the exact connection path this test round-trips through** — so it may be the *trigger* without being *wrong*: it spent latency the test had no headroom for. **Distinguishing "marginal test tipped by added latency" from "real regression in the delay predicate" needs that change's author**, and is why this is filed rather than patched. Widening the margin before answering it would convert a visible question into a silent one.

**Related:** #349 (same defect class: an environmental assumption asserted as fact), #347, ADR 0158.

**Source:** CI on an unrelated PR, 2026-08-02, observed while driving the merge queue.

## 1000. Prove each required merge context can fail: negative controls for the gates that block merge

> 🔢 **Filed 2026-08-03 — not started.** Value **7/10** · Difficulty **3/10** · _quick win_. Thirteen contexts are the entire merge gate and not one of them is proven able to go red — a gate nobody has watched fail is an assumption wearing a green tick, and the class has now fired at least four times in this repo with no CI signal; the build is a negative-control fixture per context plus a job that fails if a context has none, no new dependency and no change to what the gates check.

**Cluster:** Security / CI gates. **Priority:** P1. **Verdict:** build. **Severity:** medium.

**What:** `.github/required-contexts.txt` names **13** contexts that block merge. For each one, add a **negative control**: a fixture carrying the exact violation that context exists to catch, plus a proof that the context fails on it. The deliverable is not a doc — it is a `tests/`-resident fixture set plus a CI job that **fails when a required context has no negative control**, so the coverage cannot silently regress.

This is deliberately scoped **narrower** than "test the gates". It does not re-test what each gate checks — the gates' own suites do that. It asserts one property per context: *this gate is capable of going red*.

**Why:** the instance that prompted it is already fixed, and is the argument for the general case. `backlog-hygiene.yml` — the required context *"a PR that implements BACKLOG #N must update BACKLOG.md"* — computed its changed-file list with a **two-dot** `git diff "$BASE_SHA" "$HEAD_SHA"`, which reports main-side changes as reverse deltas. Its pass test is a literal `grep -qx 'docs/BACKLOG.md'`, so after **any** main-side edit to that file every PR with an older base was credited for touching it. The gate went green *while enforcing nothing*, on precisely the population it exists to police: PRs claiming to implement an item while changing engine code. Fixed to three-dot in the same change that found it, and only found because the archive move forced someone to ask what the gate actually reads.

The repo has now recorded this class at least four separate times, each found by hand and none by CI:

- **#334** — semgrep, required and blocking, scans a two-directory allow-list; 56 tracked `.py` files its sibling declares in scope never see the project's own rules.
- **#327** — six `.gitignore` rules are the sole control keeping maintainer-internal security docs out of a public commit, and no test, hook or workflow asserts they still match anything.
- **#321** — the forbidden-content gate exited `0` on content carrying a real site code and a partner product name.
- **#325** — the same gate's home-path detector matches a literal capital-`U` `Users`, so one of four spellings of the same Windows path walks through a required check.

Each was filed as its own defect, which is right. What none of them establishes is the property that would have caught all four **before** they shipped: a green run is evidence only if the gate has been shown it can go red on that class. That is a different artifact from any of the individual fixes, and it is the one thing this item builds.

**At least five further instances landed on 2026-08-05 alone, across three sessions, every one found by hand and none by CI.** They are recorded here because the rate is the argument: this is not a backlog of four historical mistakes, it is an ongoing yield.

- **A guard that did not enforce its own stated shape.** `new.ps1`'s `-Name` was validated `^[A-Za-z0-9._-]+$`, and `"abc" + newline` **matches** it — .NET's `$` also matches before a final newline. The pattern that an entire defect (#1032) rested on admitted a newline into a directory name. Fixed to `\A..\z` in all four copies of the literal.
- **A test that rendered the broken output and asserted a substring of it.** `tests/test_worktree_gate_hijack.py` asserted `"new.ps1" in reason`, with a fixture branch that already had the defect's shape. It passed for the whole life of #1032 while producing a command that could not run. A test hard-coding the expected hint would have been equally blind: the emitted string was never wrong, the *receiving contract* rejected it.
- **An exit code that masked the failure being asserted.** Running an emitted command via `pwsh -File script.ps1` returns **0** even when the script inside died at parameter binding. Without an explicit `exit $LASTEXITCODE`, every execution assertion built on the return code is vacuously green. Found only by writing a control that had to fail and watching it pass.
- **A probe that could not tell "found nothing" from "did not look".** A coordinator's PR-drain passed `--arg` to `gh --jq`; the call errored, printed usage, and the script read the **empty output** as "nothing eligible" for two minutes with two PRs sitting eligible. The generalisable remedy is the useful part: a probe must **validate the shape of its own output** — the fixed drain asserts every `gh` probe returned a number before branching on it — rather than treating an empty result as a negative answer.
- **A control that was too uniform to locate the layer doing the work.** See the asymmetry rule below; this one is a finding about negative controls themselves.

**Nearest existing mechanism:** partial and uneven. Some gates already carry a canary — `dast.yml` has two, and `alloc.ps1`'s floor now has a documented plant-and-observe procedure. `tests/test_lint_scope_parity.py` guards *scope drift* between ruff, bandit and the pre-commit hook, which is adjacent but different: it proves two tools agree on what they scan, not that either can fail. Nothing enumerates the required-context list and asserts a control exists per entry, so a context added to branch protection tomorrow starts life unproven and nothing says so.

**Proposed:**

1. Enumerate `.github/required-contexts.txt` and, for each entry, record the violation it exists to catch and whether a negative control already exists. Publish the gaps — a count, not a claim of completeness.
2. Add the missing fixtures. Prefer the cheapest form that actually exercises the gate: a planted file for a scanner, a crafted diff shape for a workflow-logic gate like `backlog-hygiene.yml`, an inverted assertion for a test-suite context.
3. Add a CI job that fails when a required context has no registered control. Without this the set decays the moment a new context is added, which is the same decay mode as every item above.
4. Run each control **against the pre-fix gate where one exists**, so the record shows the observed failure rather than an assertion that it would have failed.

**A NEGATIVE CONTROL MUST BE ASYMMETRIC, and this is the part most likely to be skipped by whoever starts this item.** It is not enough that neutering the rule turns the control red. The control must fail for exactly the shapes that rule covers and **keep passing** for the shapes some other layer catches — otherwise it cannot tell you *which layer does the work*, and it cannot distinguish "the other cases are safe by design" from "safe by luck".

Measured 2026-08-05, and this is why the rule is stated rather than assumed. A rule-1b fix was believed to protect two NTFS alternate-data-stream spellings. With the fix reverted, its eight-case control failed on **one** of them, not both: the `::$DATA` forms were already refused by a *different* layer (an extension backstop), and the new code was load-bearing for exactly one shape — a stream named to end in a document extension. The author's first draft of the accompanying comment credited the new code with both, **an overstatement in the direction that flatters one's own code**, which is the worst direction for it to be wrong in. A control that failed on all eight would have looked stronger, confirmed the overstatement, and taught nothing.

So the registered control for a context should record **what it does not break**, not only what it does. A uniform red is a weaker result than a specific one.

**Trigger:** none — this is not demand-gated. The trigger already fired four times.

**Related:** #334, #327, #325, #321 (instances of the class); #322 (a synthetic control colliding with the real gate's own detectors — the trap this work must avoid creating); #353 (an ungated compliance artifact, same "nothing compares it to the record" shape).

**Source:** the two-dot `backlog-hygiene.yml` defect found 2026-08-03 while making the number-space gates span an archive, and escalated by the coordinator session on the ground that it outlives the PR that fixed it — *"it was a required gate, not an advisory one."*

## 1003. Validate the lab and discharge the four hardware-gated residuals

> 🔢 **Filed 2026-08-04 — not started.** Value **7/10** · Difficulty **4/10** · _quick win_. Four open items are blocked on the same missing thing — a controlled multi-VM environment — and each currently asserts a premise that expires when it arrives; the work is the validation runs themselves, which are bounded, already specified by the items they discharge, and need no new design.

**Cluster:** Testing & CI. **Priority:** P2. **Verdict:** build when the trigger fires. **Severity:** medium (four items are parked on a blocker that is about to stop existing, and their own text will keep saying otherwise).

**Trigger:** the lab is **available for validation** — reachable, with VMs provisionable. **Not** "lab validated": proving the lab does what these items need is this item's own first deliverable, so gating on validation would mean the trigger can never fire.

**Scope.** Two halves, in order.

1. **Validate the lab against what the residuals actually require** — a real Domain Controller, AD CS, a gMSA, a registered self-hosted Windows runner, and a real SQL Server instance. Each is a precondition of a specific item below; an environment that is merely *up* is not one that can discharge them. Record what was stood up and what was verified, because "the lab exists" and "the lab can answer question X" are different claims and only the second unblocks anything.
2. **Run the four residuals** and record their results.

**What it discharges** (each already fully specified in its own item — this item adds no new design):

| Item | The run | What it needs |
|---|---|---|
| **#99** | the live domain-lab gMSA / SSO / reverse-proxy smoke — the **only** residual left on that item | real DC + AD CS + gMSA |
| **#98** | Kerberos SSO channel-binding (EPA) opt-in + acceptor-enforcement spike | same gate as #99 |
| **#320** | the decisive windows-2025 capacity sweep, currently blocked because the runner is unregistered (`actions/runners` → `total_count: 0`) | a registered self-hosted WS2025 runner |
| **#351** | execute the failover patch against a real SQL Server, **and** measure ADR 0159's `_acquire` cost — the question that item reserves | a real SQL Server |

⚠️ **#351's measurement is the one that is easy to lose.** Its patch makes the test deterministic, which removes the only thing currently raising the latency question. The item says plainly that a lease-election test is the wrong instrument for discovering latency — so the measurement belongs here, as a benchmark or an explicit budget assertion, not there. Landing the patch without doing this drops the question rather than answering it.

**Why this is not a roadmap umbrella.** Its deliverables are runs with recorded outcomes, not an index of other work — the distinction that scored #64 a 1/10. It ships something: a validated lab, four discharged residuals, and the corrected trigger text below.

**Also, and it is the part that rots if nobody does it:** four items assert a premise that becomes false the moment the lab lands. #99 says its residual is *"rig/provisioning the project does not own"*; #320 says its experiment is blocked on an unregistered runner. Left alone, those sentences keep telling every future planning pass that the work is unreachable — the same stale-premise rot the 2026-07-28 reconcile found on five items and the 2026-08-03 re-score found on twenty-four. Each of the four gets its trigger line amended in this item's first commit, whether or not the runs have started.

**Source:** owner, 2026-08-04 — a server for multi-VM testing is ~2 weeks out.

## 1004. ASVS 13.3.4 — the store DEK's calendar expiry alerts and never refuses; build the enforced stop with a loud opt-out

> 🔢 **Filed 2026-08-04 — not started. Scored 2026-08-04 → P1.** Value **8/10** · Difficulty
> **4/10** · _quick win_. The store DEK has two expiry axes and only one of them stops. The
> **usage** axis refuses unconditionally — `AesGcmCipher._count_invocation` raises `CipherError`
> at `_GCM_MAX_INVOCATIONS = 2**32` (`messagefoundry/store/crypto.py:135`, the raise at
> `:683-688`), reads no setting, and is `encrypt()`'s first statement (`:698`). The **calendar**
> axis computes the same overdue condition and emits one alert: `_maybe_escalate_dek` guards a
> body containing exactly one `alert_sink.secret_rotation_due(..., enforced=True)` in a
> try/except that logs a *sink* failure (`messagefoundry/pipeline/secret_rotation.py:341-351`)
> — no raise, no exit, no invalidation. **Owner-decided 2026-08-04: build the refusal, with a
> setting that lets an operator turn the enforced expiration off.** It is also the ASVS 13.3.4
> cell's own named up-trigger.

**Cluster:** Security & Compliance. **Priority:** P1. **Verdict:** build — owner-decided
2026-08-04. **Severity:** medium — the shipped code documents an annual DEK cadence
(`docs/ASVS-L2-PHASE0-CHANGES.md:151`) and enforces only the usage half of it, so a first
deployment would run a calendar-overdue key indefinitely with an alert as the only signal.
Nothing is deployed today; this is **wrong in the shipped code**, not an exposure in the field.

> **The value of this item is load-bearing on ONE vault fact, named here so a re-scorer knows
> which number to re-check.** Value 8 matches rung 8's FIRST limb — *"an ASVS L3 **Partial** on
> defaults"* — which is an assertion about the 13.3.4 cell in the vault-only
> `docs/security/asvs-scorecard.toml`, unreadable from the public repo (`docs/security/` is
> gitignored; `git ls-tree -r origin/main -- docs/security` is empty). The second limb is **not**
> available as a fallback: `_maybe_escalate_dek` does fire `secret_rotation_due(...,
> enforced=True)`, so an operator gets a signal and can rotate by hand — a workaround, which
> disqualifies *"a production blind spot with no workaround"*. If the cell is not Partial at L3,
> this drops to rung 6 (*"real gap, awkward workaround"*) and from P1 to P2.

### What ships today, read at `origin/main`

| Axis | Where | Behaviour |
|---|---|---|
| **Usage** (2^32 encrypts) | `store/crypto.py:651` `_count_invocation`; ceiling `:135`; raise `:683-688`; sole call site `:698` | **Refuses.** Non-configurable, no opt-out, halts ingest — no encrypt/write path catches `CipherError`. |
| **Calendar** (`store_key_max_age_days`) | `pipeline/secret_rotation.py:319` `_maybe_escalate_dek`; guard `:341`; body `:342-351` | **Alerts only.** One `secret_rotation_due(..., enforced=True)`; the surrounding `except` at `:350-351` catches a *sink* failure, not the overdue condition. |

Both are live on shipped defaults: `[security].enforcement` defaults to
`SecurityEnforcement.ENFORCE` (`config/settings.py:3558`), which is the gate `_maybe_escalate_dek`
returns early on (`:330-331`), and the reconcile that calls it runs whenever `[secret_rotation]`
is present (`pipeline/engine.py:1039`, awaited at `:1051`, reaching `_maybe_escalate_dek` at
`secret_rotation.py:309`).

### Trap 1 — the refusal MUST sit OUTSIDE `engine.py:1062`, or it is a non-control

`reconcile_rotation_meta` is awaited at `pipeline/engine.py:1051` inside a `try` whose handler is
a blanket `except Exception:` at **`:1062`** whose **entire body is `log.exception(...)`**
(`:1065-1067`); execution resumes at `:1068`. **A raise sited anywhere beneath that await is
logged and stepped over** — you get a traceback in the log and a normal engine start.

This is not hypothetical, and it is why this trap is written first. The 13.3.4 cell's own absence
claim was found to have exactly this defect: its stated reintroduction landed inside
`_maybe_escalate_dek`, so it satisfied the drift gate's pattern check while describing a refusal
that refuses nothing. That claim's mutation has since been re-sited outside the handler — **read
it before designing, because it is effectively the implementation sketch** — and it names the
propagation path: out of `Engine.start()`, aborting the ASGI lifespan, since `await
engine.start()` (`messagefoundry/api/app.py:5532`) sits directly inside `async def lifespan`
(`:5323`) with no enclosing `try`. Note the re-siting has **not itself been proved by
execution** — see the absence-claim-gate item filed in this batch, which is exactly about that.

The handler at `:1062` is **not itself a defect** — its stated purpose (a reconcile failure
must never take the engine down) is correct, and narrowing it is a real decision with its own
risk. Do **not** widen this item into "remove the try/except". Site the new gate after it.

### Trap 1b — the second-order swallow, which nothing has named yet

`self._secret_rotation_stamps` initialises to `{}` (`pipeline/engine.py:313`) and is assigned only
on the *successful* path at `:1051`. `_maybe_escalate_dek` prefers the operator override
`store_key_last_rotated` when set (`secret_rotation.py:333-335`) and otherwise falls back to the
stamp, returning silently when neither exists (`:338`).

So when the operator has **not** set the override — the live-by-default posture, which is the
shipped one — a swallowed reconcile failure leaves the stamps empty and a gate written in that
same shape **silently does not fire**. The blanket handler would then disable the refusal one
level removed, through code that reads correct.

**Ruling, not a decision to make later: under `ENFORCE`, with a keyed cipher and a store
implementing `SecretRotationMetaStore`, an undetermined DEK age MUST REFUSE.** An undetermined
age is not a young one. A loud alert recording *why* is required **in addition**, never instead —
alert-only in this branch would re-create, on shipped defaults and one level removed, precisely
the defect this item's title names. This case is a **required test**, listed below, not a design
question. And **make it fail on purpose first**: force `reconcile_rotation_meta` to raise and
watch what the gate does before trusting that it does anything.

### The opt-out — name, default, and the justification from secure-by-default

Add exactly **one** field to `SecretRotationSettings` (`config/settings.py:3048`):

```toml
[secret_rotation]
enforce_store_key_expiry = true   # default; false = refusal disabled, alert-only
```

**Reuse the existing knobs for the arithmetic** — `store_key_max_age_days` (`:3078`, ships 365),
`enforce_grace_days` (`:3085`, ships 30), `warn_days` (`:3066`, ships 14). Do **not** add a second
max-age or a second grace: the refusal fires on the expression `_maybe_escalate_dek` already
computes at `:340`, so the ENFORCE alert and the refusal cannot disagree.

**There are already TWO overdue computations in this file, and a third consumer.** `:340` is
`days_overdue = age_days - settings.store_key_max_age_days` (the DEK escalation);
`SecretRotationRunner.run_once` computes `days_overdue = age_days - secret.max_age_days` at `:441`
and applies a `warn_days` window at `:451` (the periodic per-secret scan). The instruction above
is still right — reuse `:340`, add nothing — but do not read it as "there is one definition in
the codebase," because an implementer who checks will find two and distrust the instruction.

**Default `true`. The reasons are on merit:**

1. **The axis beside it has no opt-out at all.** The usage ceiling refuses unconditionally on the
   same key. A calendar axis shipping OFF would be strictly weaker than its own sibling, with no
   principled basis for the asymmetry.
2. **A default-off build does not move the cell, so it buys the setting and not the posture.**
   13.3.4 grades the engine against its own documentation, and the documented cadence is the
   annual one. If the shipped default still does not enforce it, the requirement is unchanged and
   the work is spent for nothing. This is the decisive argument.
3. **A fresh install running the SHIPPED values with no override cannot trip it for 395 days.**
   The refusal is double-gated: `[security].enforcement = ENFORCE` **and** age > `365 + 30`, and
   `tracked_since` is an age floor by design (an upgraded install stamps its DEK as new). Two
   configurations DO trip it at first start and both are required tests: an operator declaring a
   true prior rotation date more than 395 days back via `store_key_last_rotated`
   (`secret_rotation.py:333-335`, `datetime.date.fromisoformat`), and a short
   `store_key_max_age_days` (`settings.py:3078` is operator-settable, as is `enforce_grace_days`
   at `:3085`). "No configuration can be surprised" is false; "the shipped configuration cannot
   be surprised" is true.
4. **"It would break existing installs" is not available as a reason.** There are none. Zero
   deployments removes the migration cost from the ledger; it does not lower the bar.

**Make the opt-out loud.** Wire `enforce_store_key_expiry = false` into `security_loosenings()`
(`config/settings.py:4062`) so an off-by-choice posture is named on every boot, the way every
other deliberate relaxation in this codebase is. A silent opt-out is indistinguishable from a
defect.

### Where it goes, and where it does not

**Serve path only.** `messagefoundry check` **has no store** (`messagefoundry/checks.py:1498`) so
it cannot read the DEK stamp at all, and it is an advisory gate. The precedent for the split is
already written down at `checks.py:1505-1506` — *"the engine-start gate is the backstop for that,
which is why both halves exist."* An advisory arm in `check` reading only the operator override is
welcome; it does **not** substitute for the engine-start refusal, and must not be described as
discharging this item.

### Trap 2 — the paired scorecard change must land in the same act

Building this makes the 13.3.4 **absence claim false by construction**: the claim asserts the
corpus contains no raise of a rotation/overdue-named exception, and this feature introduces
exactly one. `scripts/asvs/scorecard.py`'s `check_absences` (`:387`) greps every `.py` under
`messagefoundry`, `messagefoundry_webconsole`, `harness` and `scripts` (`:416-426`) and reports
`absence claim is FALSE — … now matches N time(s)` (`:409-413`). **The vault drift gate goes red
on the commit that ships the feature.**

That is the gate working, not a reason to hesitate. It is a reason to land the pair together. The
protocol has been executed correctly twice, both on 2026-08-04:

| Engine (public, on `main`) | Vault (private) | What moved |
|---|---|---|
| `1e9cc4c1` (PR #173) | `f2c017ce` | 13.2.2 re-anchored onto the runbook's new prohibition |
| `62fd628d` (PR #176) | `a8a5a1c2` | 12.1.5 re-anchored onto the corrected ECH recipe |

**There is a verified trap inside the protocol itself.** Both vault commits cross-reference the
engine by the **pre-squash branch SHA** — `01b11b81` and `268181f7` — not the squash-merge SHA
that is actually on `main`. Both branch SHAs still resolve in the engine repo, so the pairing is
followable, but **neither is reachable from `main`**, and a future reader asking "did this land?"
against them gets the wrong answer. Cite the merged SHA, or cite both and label which is which.

The vault side of *this* item is larger than a re-anchor: **remove or rewrite the absence claim**
(the thing it records as missing now exists), re-derive the verdict against the requirement text,
re-point the evidence anchors, and re-read the residual's own down-triggers — several name the
`[secret_rotation]` shipped defaults and `_maybe_escalate_dek` directly, so they fire on this
change too.

### The measuring-document edit is legitimate HERE — and the PR must say why

`docs/ASVS-L2-PHASE0-CHANGES.md:141` states the engine *"does **not** force-rotate or hard-expire
a secret"*, and `:147` says a DEK past max-age + grace **escalates** at restart. Both become false
for the DEK's calendar axis the moment this lands, and leaving them standing is the *"compensating
control must not rest on a false premise"* defect (`docs/Secure_Development_Standards.md:98`).

The 13.3.4 cell separately **forbids editing that document as a lever** — it is the standard the
requirement measures against, so an edit alone moves the cell with zero posture change and is
indistinguishable in the record from a real remediation. **These are not in conflict, and the
distinction is the whole point:** an edit that *follows* a shipped code change is a record
correction; an edit that *substitutes* for one is the forbidden lever. State which one you are
doing, in those terms, in the PR body. Note also that editing either sentence is itself one of the
cell's re-score triggers — a third reason the vault change cannot lag the engine change.

### Tests that must exist, and the one that must go red first

- Refuses past `store_key_max_age_days + enforce_grace_days` under `ENFORCE`; silent within
  grace; silent under `WARN`/`OFF`. Model on the three that already exist for the alert arm:
  `tests/test_secret_rotation_watcher.py:331`, `:349`, `:364`.
- **`enforce_store_key_expiry = false` suppresses the refusal and the alert still fires.** The
  opt-out must not also silence the reminder.
- **The refusal propagates out of `Engine.start()` and aborts the lifespan.** This is the
  assertion that separates this build from the defect it replaces. Write it first against a raise
  sited *inside* the try at `engine.py:1051` and **watch it fail**; only then move the gate out
  and watch it pass. A green here is evidence only after the red.
- **Undetermined age REFUSES** — `reconcile_rotation_meta` forced to raise, no
  `store_key_last_rotated` set, `ENFORCE` + keyed cipher: assert refusal, not merely an alert.
- **First-start trip cases:** `store_key_last_rotated` set >395 days back, and a short
  `store_key_max_age_days`. Both must refuse at first start, and both must be silent when
  `enforce_store_key_expiry = false`.
- `security_loosenings()` names the opt-out when it is off.

**Related:** the ASVS 13.3.4 cell and its named up-trigger (vault-only
`docs/security/asvs-scorecard.toml`); #353 (gating a compliance artifact against the record —
same "nothing compares it to the record" shape, and the reason the paired change matters); #1000
(prove a required gate can go red — note the inversion here: the drift gate's red is the
*expected* outcome, which is a different property from an unproven green); the absence-claim-gate
item in this batch (the re-sited mutation this design borrows is itself unproven by execution);
`docs/ASVS-L2-PHASE0-CHANGES.md:138-151`, the rotation schedule this is measured against.

**Source:** owner decision, 2026-08-04 — build the enforced calendar expiry with an operator
opt-out. The not-deployed framing follows the owner's standing ruling in `CLAUDE.md` §0, **which
is on `origin/main` at `88703a3a` (PR #177, 2026-08-04)**. An earlier draft of this item cited
that ruling as `4fbcee2b` and claimed it was *not* on `origin/main` — `4fbcee2b` is the
**pre-squash branch SHA**, and the claim was false. That is the same trap this item documents two
sections above; it fired on the item that documented it. Every engine line cited above was read at
`origin/main` `88703a3a` for this filing; the two paired-landing precedents and the pre-squash SHA
trap were verified by resolving all four commits.

## 1005. CRL checking of partner client certs on the mTLS-terminating listeners (ASVS 12.1.4 band B1)

> 🔢 **Filed 2026-08-04 — not started. Scored 2026-08-04 → P1.** Value **8/10** · Difficulty
> **5/10** · _quick win_. Three server-side `SSLContext` builders already require and verify a
> partner client certificate and **not one checks revocation** — measured on this tree, a
> revoked-but-chain-valid client is `ACCEPTED`, so a partner certificate revoked this morning
> would keep authenticating to an HL7 interface until its `notAfter` on first deployment. Bought
> for the posture, not the number — the ceiling is `partial`, never `pass`, and the item must not
> be described as clearing the cell. Sized 5 rather than 3 because the control is **fail-closed by
> construction** (two measured failure modes turn it from a security add into an availability
> hazard) and because it spans three connector factories + `ApiSettings`, a new `tls_policy`
> helper, a posture-keyed refusal, a freshness alarm on the `CertExpiryRunner` seam, and a
> real-handshake test rig that exists today for one of the three builders.

**Cluster:** Security & Compliance. **Priority:** P1. **Verdict:** build — **band B1 only** (defined
immediately below); the accepted decision authorises this band and nothing above it.
**Severity:** medium-high on the control (a revoked partner credential would authenticate to a PHI
interface for the certificate's remaining life), high on the blast radius if built without both
traps below.

> **"Band B1" is defined HERE, because it exists nowhere else.** `git grep "band B1" origin/main
> -- docs/` returns **zero hits** — the term lives only in the 2026-08-03 decision memo, which a
> future session has no path to, so a Verdict forbidding "anything above B1" would forbid work the
> reader cannot identify. **B1 = exactly the four numbered Scope items below**: (1) a
> `tls_crl_file` per-inbound setting, (2) CA+CRL load via `cafile=` with `VERIFY_CRL_CHECK_LEAF`,
> (3) the posture-keyed fail-closed refusal, (4) the freshness preflight + pre-expiry alarm.
> **Above B1, and NOT authorised: OCSP stapling, any in-engine CRL fetch or auto-refresh, and the
> outbound verifying hop.**

### Why "no workaround" holds, and exactly where it stops

`harden_verify_flags`' own docstring states the shipped posture: live revocation is *delegated to
the deploying org's PKI — OCSP-must-staple at the WP-15 proxy plus the OS trust store*. That is a
real, documented out-of-engine compensating control, and for the **HTTP** surface it is credible.
**It cannot reach the other two.** An HTTP proxy cannot terminate MLLP framing and cannot
terminate DIMSE, so for `transports/mllp.py`'s MLLP listener and `transports/dicom.py`'s C-STORE
SCP the named delegation does not apply and **no workaround remains** — which is the sentence that
holds this item at rung 8 rather than 7. Do not soften it to "no in-engine workaround"; the
narrower phrasing is what the rubric rung actually requires.

**What:** each of the three builders loads a CA, sets `CERT_REQUIRED`, and finishes with
`harden_verify_flags` — which is *strict RFC 5280 path validation, not revocation*, as
[`config/tls_policy.py`](../messagefoundry/config/tls_policy.py):170-172 says in its own
docstring. Add an opt-in per-inbound CRL: a `tls_crl_file` setting,
`load_verify_locations(cafile=…)` for CA **and** CRL, `ssl.VERIFY_CRL_CHECK_LEAF` OR-ed into
`verify_flags`, a fail-closed refusal when mTLS is on with no CRL on an enforcing PHI instance,
and a freshness preflight plus a pre-expiry alarm.

| Builder | CA load | `CERT_REQUIRED` | Serves |
|---|---|---|---|
| [`transports/mllp.py`](../messagefoundry/transports/mllp.py) `_mllp_ssl_context(…, server=True)` | `:541` | `:542` | the MLLP listener **and** the inbound HTTP listener — [`transports/http_listener.py`](../messagefoundry/transports/http_listener.py):419 calls the same builder, consumed at `:460-461` `asyncio.start_server(…, ssl=self._ssl)`. One builder, two listeners. |
| [`transports/dicom.py`](../messagefoundry/transports/dicom.py) (C-STORE SCP) | `:143` | `:144` | the DICOM SCP |
| [`api/tls.py`](../messagefoundry/api/tls.py) `build_api_ssl_context` | `:61` | `:62` | the API/UI listener |

**The ceiling, stated before the scope so nobody reads past it.** This lands **`partial`**, and
no amount of work in this item reaches **`pass`**. 12.1.4's named example is OCSP **stapling** — a
*server-side* act — and no terminating surface here can staple. Measured 2026-08-04 on CPython
3.14.6 / OpenSSL 3.5.7: `ssl.SSLContext` exposes **zero** attributes matching status/ocsp/staple,
so stdlib offers no status-request API at all. The obvious substitute does not compose either:
`OpenSSL.SSL.Context` **has** `set_ocsp_server_callback`, but `hasattr(OpenSSL.SSL.Context,
"wrap_bio")` is `False` — and `asyncio/sslproto.py` drives TLS through
`self._sslcontext.wrap_bio(…)`, which is the path both terminating surfaces take
(`asyncio.start_server(…, ssl=…)` for MLLP/HTTP, uvicorn's `loop.create_server(…,
ssl=config.ssl)` for the API). A pyOpenSSL context cannot be handed to either. *(pyOpenSSL is
already a transitive dependency — `requirements.lock:723` pins **26.4.0** via `webauthn`; the
probe above ran against **26.3.0**, the version installed in this worktree's `.venv`. Two
different numbers; do not conflate them.)* **Do not let this item be reported as closing 12.1.4.**

### Scope — this is band B1 in full

**1. A `tls_crl_file` per-inbound setting** on `MLLP()`
([`config/wiring.py`](../messagefoundry/config/wiring.py):771, TLS block `:799-811`), `Http()`
(`:1070`, `:1083-1088`) and `DICOM()` (`:1903`, `:1917-1927`), plus an `ApiSettings` field beside
`tls_client_ca_file`.

> **There is no separate `connections.toml` key list to edit.**
> [`config/connections_file.py`](../messagefoundry/config/connections_file.py):286 is `return
> factory(**settings)` and `:290` states the rule — *"the factory IS the schema"*. `_INBOUND_KEYS`
> allow-lists the **top-level entry** keys (`name`, `transport`, `settings`, `router`, …), not
> settings keys. Adding the factory parameter **is** the entire TOML surface. Budget accordingly.

**2. Load CA + CRL via `cafile=` and OR `VERIFY_CRL_CHECK_LEAF` into `verify_flags`,** beside the
existing `harden_verify_flags` call (`mllp.py:545`, `dicom.py:147`, `api/tls.py:57`). Put it in a
`harden_crl_check(ctx, crl_file)` sibling in `config/tls_policy.py` so the three sites cannot
drift, and make it assert what it loaded:

```python
ctx.load_verify_locations(cafile=crl_file)   # cafile= ONLY — see trap 1
if ctx.cert_store_stats()["crl"] < 1:        # "loaded" vs "silently ignored"
    raise ValueError(...)
ctx.verify_flags |= ssl.VERIFY_CRL_CHECK_LEAF
```

**3. A fail-closed refusal** when mTLS is configured with **no** CRL on an enforcing PHI instance.
The seam exists in shape:
[`pipeline/wiring_runner.py`](../messagefoundry/pipeline/wiring_runner.py):6679-6700
`_inbound_insecure_bind_permitted` already refuses an off-loopback cleartext inbound bind on a
production-PHI instance (#200, ADR 0092). This is its revocation sibling.

**4. CRL-freshness preflight + pre-expiry alarm — load-bearing availability controls, not
polish.** Read `nextUpdate` at build / `messagefoundry check` / dry-run time and refuse an
already-expired CRL loudly at startup rather than at the first partner handshake. The monitor seam
is already built and is the right host:
[`pipeline/cert_expiry.py`](../messagefoundry/pipeline/cert_expiry.py) `CertExpiryRunner` reads
`notAfter` from every served cert via [`pki.py`](../messagefoundry/pki.py):93 `read_cert_facts`
and raises `AlertSink.cert_expiry`
([`pipeline/alerts.py`](../messagefoundry/pipeline/alerts.py):93). It watches `tls_cert_file`
paths only — `:114-115` (api), `:123` / `:127` (per-connection) — and **never** `tls_ca_file`, so a
CRL path is an additive entry plus a `read_crl_facts` sibling and one new AlertSink method.

### Two traps. Both must be in the implementation plan or this ships broken.

Executed 2026-08-04 on this worktree's `.venv` (CPython 3.14.6, OpenSSL 3.5.7), TLS **1.2 pinned**
so client auth happens in-handshake and the server-side outcome is unambiguous. Re-run before
building; do not inherit this table.

| Server context | good client | revoked client |
|---|---|---|
| CA only, no CRL flag — **the shipped posture** | ACCEPTED | **ACCEPTED** (`peer CN=revoked-client`) ← *the gap* |
| `cafile=` CA + **fresh** CRL, flag ON | ACCEPTED | REFUSED — verify **23** `certificate revoked` ← *the control works* |
| `cadata=` CA + fresh CRL (same bytes), flag ON | **REFUSED — verify 3 `unable to get certificate CRL`** | REFUSED — verify 3 |
| `cafile=` CA + **stale** CRL (`nextUpdate` past), flag ON | **REFUSED — verify 12 `CRL has expired`** | REFUSED — verify 12 |

**Trap 1 — `cadata=` silently loads ZERO CRLs; `cafile=` works; `capath=` was NOT measured.** The
same PEM bytes through `cadata=` yield a context with the CRL-check flag set and **no CRL to check
against** (`cert_store_stats()["crl"] == 0`, measured directly), and the observable is not a
skipped check — it is *every* client refused with `unable to get certificate CRL`. No error, no
warning, at load time. A `cadata=` implementation reads correct and produces a total outage.
**Assert `cert_store_stats()["crl"] >= 1` after loading**, or the control cannot distinguish
"loaded" from "silently ignored". `load_verify_locations` takes a **third** parameter,
`capath=`, and OpenSSL does read CRLs from a hashed directory (`.r0` files) — which is the natural
shape for the refreshable CRL directory trap 2 says nothing in the engine provides. **`capath=`
was never tested and must be measured before it is either adopted or ruled out**; the four rows
above say nothing about it.

**Trap 2 — a CRL past `nextUpdate` refuses every client, not just revoked ones.** A CRL is a file
with an expiry and nothing in the engine refreshes it. On first deployment an unrefreshed CRL
would take a live HL7 interface down — every partner failing to connect at once, which is also the
operator's *first* symptom. This is why item 4 above is not optional: without the preflight and
the pre-expiry alarm, this feature converts a PKI housekeeping lapse into an unplanned outage.

### The test, and why it is not optional

On the two builders this item touches most there is **no** real client-cert handshake anywhere.
`_mllp_ssl_context(server=True)` and the DICOM SCP context are asserted **by construction only** —
`tests/test_mllp_tls.py:83-88` is `assert ctx.verify_mode == ssl.CERT_REQUIRED` and stops there.
The two live MLLP round-trips that exist (`tests/test_mllp_tls.py:117-164`,
`tests/test_mllp_persistent.py`) are **server-cert-only**: the listener carries no `tls_ca_file`,
and the `tls_ca_file` at `:152` is the *outbound's* anchor for verifying the server.
`verify_mode` is unchanged by a CRL bit, so **a CRL bit would satisfy every existing assertion and
go green on every CI leg while broken in the field.**

There is exactly one real mutual-TLS handshake in the suite — `tests/test_api_tls.py:1332`
`test_real_mutual_tls_handshake_on_built_context` — and it is the model to copy, with its helpers
`_handshake` (`:1104`), `_strict_ca_and_leaf` (`:1178`), `_verifying_client_ctx` (`:1252`). Per
the measurement-gate rule: **make the new test fail on purpose first.** The four rows above are
the fixture; row 1 (revoked accepted) and rows 3-4 (good client refused) are the ones that must be
watched going red before any green is trusted.

> **Fixture trap found while measuring.** `harden_verify_flags` already sets
> `VERIFY_X509_STRICT` on all three builders, and a fixture leaf without an Authority Key
> Identifier is refused with verify **85** `Missing Authority Key Identifier` — the first probe
> run refused all eight cases for that reason alone and looked exactly like a CRL bug. Give the
> fixture CA a `SubjectKeyIdentifier`, and every leaf **and the CRL** an `AuthorityKeyIdentifier`.

### Prose this falsifies — sweep it in the same PR

The load-bearing statements assert the engine performs no revocation check *at all*:
`config/tls_policy.py:16-19`, `:170-172` (inside `harden_verify_flags`' own docstring),
`:253-257`, `:663-668`, `:776-782`. Building B1 makes several false. **A compensating control must
not rest on a false premise** (CLAUDE.md §11) — leaving that prose standing is the defect, not a
documentation chore. [ADR 0002](adr/0002-phase2-transport-security-and-strong-auth.md) and [ADR
0078](adr/0078-certificate-revocation-posture.md) both need amending: this partially retires the
"no in-engine OCSP/CRL" posture on the inbound side only.

### What this item is NOT

**Do not take the "one `verify_flags` assignment via `truststore`" shortcut — it is falsified, and
taking it would be worse than doing nothing.** Read at source in the pinned wheel:
`truststore/_openssl.py::_configure_context` **never reads or writes `verify_flags`** — it only
calls `set_default_verify_paths()` / `load_verify_locations(cafile=…)`. The CRL-flag mapping
exists solely in `_windows.py:366-368` and `_macos.py:403,418`. The shipped container is **Debian
12 bookworm** (`docker/Dockerfile:28`, `:31`), so on the image that ships, the OpenSSL backend is
the one in play: the flag is unmediated, lands on a context with no CRL loaded, and produces
exactly the measured row 3 — a working handshake becomes `unable to get certificate CRL`.
Separately, both `truststore` sites are **client** contexts talking to the engine's *own* API
([`apiclient/client.py`](../messagefoundry/apiclient/client.py):173,
[`tray/probe.py`](../messagefoundry/tray/probe.py):121, gated at `:113`), never a partner-facing
PHI hop, and `[api].tls_cert_file` ships `None`
([`config/settings.py`](../messagefoundry/config/settings.py):707). It moves neither the posture
nor the scorecard and regresses availability. **This item is the mTLS listeners.**

### Unpriced, deliberately

Whether B1 interacts with **12.1.3** (mTLS cert → Identity); the full sweep cost of the falsified
prose; and the still-unread ASVS cells, which can add `fail`s faster than this removes them. Treat
the count as a moving target and buy posture.

**Related:** #201 (closed — its shipped `revocation_hop_disposition` / `RevocationHopGuard` at
`config/tls_policy.py:678-700`, `:776-782` is the **outbound** sibling that *refuses* an unrevoked
verifying hop rather than checking revocation, which is the shape this item deliberately does
**not** copy; amending a closed item's prose is fine, but it must not gain an OPEN banner); the
deferred 13.2.2 startup preflight (same accepted batch, filed in this batch as its own item);
#338 (`harden_kex_groups` — the adjacent "attempted hardening is inert" defect in the same
module); #1000 (this item's new test is a negative control in exactly its sense); [ADR
0002](adr/0002-phase2-transport-security-and-strong-auth.md), [ADR
0078](adr/0078-certificate-revocation-posture.md), [ADR
0092](adr/0092-posture-keyed-transport-hop-refusal-refuse-the-insecure-phi-hop.md).

**Source:** ASVS 12.1.4 build-or-accept decision memo, 2026-08-03 (owner-accepted: **build band B1
only**). Every code citation above was re-resolved against `origin/main` at `88703a3a` on
2026-08-04; the four-row handshake table, the `cadata`/`cafile` behaviour, the OCSP-ceiling probes
and the `truststore` refutation were **executed for this filing**, not inherited. The verdict of
record and the cell's current score live in the vault scorecard and are not restated here.

## 1006. A mutation that matches is not a mutation that bites: the absence-claim gate proves syntax, never behaviour

> 🔢 **Filed 2026-08-04 — not started. Scored 2026-08-04 → P2.** Value **6/10** · Difficulty
> **3/10** · _quick win_. `check_absences` admits an ASVS absence claim on `re.search(a.pattern,
> a.mutation)` (`scripts/asvs/scorecard.py:395`) — one string field of a TOML row matched against
> another — so a well-formed reintroduction that would change nothing if applied passes all three
> of the gate's failure modes and certifies a non-control into the compliance record; the
> remainder is a required per-claim observable plus a mode that applies the mutation and requires
> that observable to go red, in one stdlib script and its fixture tests.

**Cluster:** Security & Compliance. **Priority:** P2. **Verdict:** build. **Severity:** medium —
the defect is in the instrument, not the engine, and a green instrument that cannot go red is the
class [ADR
0158](adr/0158-silent-controls-green-signals-that-mean-nothing-and-shape-over-detection.md) exists
to name.

**What.** `check_absences` ([`scripts/asvs/scorecard.py`](../scripts/asvs/scorecard.py):387,
called from `verify` at `:495`) admits an *absence claim* — a scorecard assertion that some thing
is **not** in the corpus — and rejects it three ways:

| Mode | Line | The question it actually asks |
|---|--:|---|
| INERT | `:395` | does `a.pattern` match `a.mutation`? |
| BLIND | `:401` | does `a.positive_control` still match the Python corpus? |
| FALSE | `:408` | does `a.pattern` match the Python corpus? |

`:395` is `re.search(a.pattern, a.mutation)`. `mutation` is a plain `str` field of the same TOML
row (`Absence`, `:107-109`); the corpus is never consulted for it and it is **never applied to
anything**. So a claim whose `mutation` is a syntactically perfect, honestly-authored
reintroduction that *would change nothing observable if written into the code* passes all three
tests, is recorded as a verified absence, and is counted in the "verified N absence claims" line
at `:625`.

There is a fourth failure mode and the gate has no name for it: **the mutation is well-formed, the
pattern fires on it, the control speaks, the corpus is quiet — and applying the mutation changes
nothing.**

**Why — the worked instance, and why it generalises.** The claim is **ASVS cell 13.3.4's absence
claim**, which lives in the vault-only `docs/security/asvs-scorecard.toml` (`docs/security/` is
gitignored in this public repo — `git ls-tree -r origin/main -- docs/security` returns nothing, so
a session reading this here cannot open it; it is in the **MessageFoundry vault repository**). Its
mutation inserted a `raise` inside `_maybe_escalate_dek`
(`messagefoundry/pipeline/secret_rotation.py:319`, under the guard at `:341`, called from
`reconcile_rotation_meta` at `:309`).

That exception has **exactly one destination in the engine**: `reconcile_rotation_meta` is awaited
at `messagefoundry/pipeline/engine.py:1051`, inside a `try:` opened at `:1050` whose `except
Exception:` at `:1062` has a body of one `log.exception(...)` call (`:1065-1067`). Applying the
mutation verbatim yields a logged traceback, a normal engine start, and an absence-claim regex
that now matches. The instrument would have gone from green to green.

**`reconcile_rotation_meta` is ALSO awaited directly by three tests** —
`tests/test_secret_rotation_watcher.py:107`, `:423`, `:435` — where the raise propagates uncaught.
That distinction is load-bearing for the proposal below: it is the difference between *"no
observable exists for this mutation"* and *"an observable exists and the gate never names it."*
Step 1's design turns on which is true, so establish it before writing the field. The engine
destination is singular; the test call sites are not.

**The handler at `:1062` is not the defect and must not be "fixed" by this item.** Its purpose
is correct and is written down at `:1063-1064` — *"A reconcile failure must never take the engine
down … Logged, not raised."* The defect is that nothing in the instrument asks where a mutation's
effect lands.

It generalises because nothing about the mechanism was special. A mutation that raises into a
swallow, writes a field nobody reads, sets a flag nobody branches on, or edits a docstring
satisfies `:395` exactly as well as a real one. The instance is closed; the property that let it
through is not, and that property covers every absence claim already authored and every one
authored next.

**The instance's replacement is itself unproven.** That mutation has been re-sited outside the
handler on the record side — the re-siting the DEK calendar-expiry item filed in this batch treats
as its implementation sketch — but **the replacement has not been proved by execution either**,
which is the whole point of this item.

**Nearest existing mechanism.** Two, and both are the seam this extends rather than a substitute
for it.

- The loader **already refuses** an absence claim carrying no `mutation` at all (`:236-244`) — so
  "a required field, enforced at load, with a message telling the author what to write" is a shape
  this file already has and can be copied rather than invented.
- The `Absence` docstring (`:88-104`) already anticipates **one** vacuity mode and closes it in
  prose: *"Do NOT derive `mutation` from `pattern`. A value generated from the thing it validates
  satisfies the check by construction, which would make this the most authoritative-looking
  vacuous gate in the file."* That is the right instinct aimed at a different mode — it guards a
  mutation *dishonestly* constructed. This item is about one constructed honestly and still not a
  control.

**Proposed.**

1. **A required `observable` per absence claim** — the named artifact that goes red when the
   mutation is applied: a `tests/test_x.py::test_y` node id, or a documented startup/handshake
   refusal. Refuse to load a claim without one, reusing the `:236-244` refusal shape and its
   message style.
2. **Prove it by execution, at least once per claim.** A `--prove-absences` mode that, per claim,
   applies the mutation to a scratch tree, runs the named observable, requires it to **fail**, and
   reverts. Without this, step 1 adds a *name* for a control rather than a control — and #1000
   states the standing rule in one sentence: a green run is evidence only once the gate has been
   shown it can go red on that class.
3. **A cheap static backstop for the mode actually found**, filed honestly as a heuristic: flag a
   mutation whose landing site is lexically inside a `try:` whose handler is a bare `except
   Exception:` with a log-only body. It would have caught this instance. It proves nothing in
   general and must not be written up as if it does.
4. **Negative controls for each new mode**, beside the existing per-mode tests in
   `tests/test_asvs_scorecard.py` (`:233` INERT-on-prose, `:260` INERT-decided-before-the-corpus,
   `:195` BLIND, `:214` FALSE). The file already has the pattern; match it.

**The trap this fix must not walk into.** An `observable` field that is recorded and never
executed is the same defect one level further out — a field validated for *shape* while the
property goes unmeasured, which is precisely what `:395` already does to `mutation`. If only one
of steps 1 and 2 can be built, build **2**: an executed proof with no schema field is worth more
than a schema field with no proof.

**Step 2 is the item; steps 1, 3 and 4 are its trim.** A mutation-testing harness — scratch-tree
management, subprocess test invocation, red-assertion, rollback — is materially larger than the
other three combined. Split, step 2 alone prices at 4 and the rest at 2; the filed **3** is the
honest blend of the two, and an implementer who builds only step 1 has not built this item.

**Scope note, and the cost deliberately excluded from the difficulty.** The public repo holds the
script and its fixture tests; the real posture data lives in the **vault repository** and this item
does not touch it (`scorecard.py:14-16`, ADR 0156 §7). Landing steps 1–2 **invalidates every
absence claim already authored** — **81 cells carry one** — until each is given an observable.
That re-authoring is the real schedule cost, is named here deliberately, and is **not** priced
into the difficulty number, which prices only the `ruff` + `mypy --strict` + `pytest` remainder in
the public repo. **Restate that exclusion in the PR body**, or a reader who sees difficulty 3 and
then discovers 81 claims need observables will believe the estimate lied.

**Trigger:** none — it has fired. The instance was found by hand, by executing a mutation the gate
had already passed.

**Related:** #1000 (prove each required merge context can fail — the same property one level down,
on CI gates rather than a compliance instrument); #353 (a compliance artifact nothing compares to
the record); #347, archived (an assertion that passes for a reason unrelated to the property it
claims to test); the DEK calendar-expiry item in this batch (whose design borrows the re-sited
mutation this item says is still unproven); ADR 0158 (the defect class); ADR 0156 (scorecard as
data — the ADR that introduced `Absence`).

**Source:** an ASVS build-or-accept costing pass, 2026-08-03. The instance's own mutation has been
replaced on the record side; this item is the class it exposed, not the instance.
`check_absences`, the `Absence` dataclass and the loader refusal were read at `origin/main`
`88703a3a` for this filing, as were the swallow at `engine.py:1050-1067`, the mutation's landing
site at `secret_rotation.py:341`, and the three direct test call sites.

## 1007. Sweep all 345 ASVS cells for present-tense impact language — the record asserts live exposures that do not exist

> 🔢 **Filed 2026-08-04 — not started. Scored 2026-08-04 → P2.** Value **6/10** · Difficulty
> **3/10** · _quick win_. The owner has ruled MessageFoundry a **not-deployed beta with zero
> production instances**. The ASVS scorecard and the risk-acceptance register are **records of
> record**, so a cell asserting a **live** exposure that does not exist is precisely the
> *"compensating control must not rest on a false premise"* defect the project's own review
> standards forbid (`docs/Secure_Development_Standards.md:98`, the source CLAUDE.md §11 names).
> The correction is to the **wording of impact** and **never to the score** — a Fail or Partial
> stays exactly as severe, and nothing here is softened because nothing is deployed.

**Cluster:** Security & Compliance. **Priority:** P2. **Verdict:** build. **Severity:** medium —
the artifact an assessor or an adopter reads overstates the present tense and understates nothing;
the scores are right and the prose around them is not. A record that cries wolf about a live
exposure is exactly as untrustworthy as one that hides a real one, and it is the same instrument.

### This is VAULT work, not engine work

`docs/security/asvs-scorecard.toml` and `docs/security/ASVS-L3-RISK-ACCEPTANCE-REGISTER.md` live
in the private vault repository; `docs/security/` is gitignored in the public engine repo and `git
ls-tree -r origin/main -- docs/security` returns nothing. **This ledger is public and those files
are not.** The item is filed here so the work is durable and schedulable; the edits happen
vault-side, and cell text, register rows and residual prose must **not** be quoted into this
ledger, a public commit message, or a PR body on the public remote. Same disposition and same
reason as #353.

### Scope, measured 2026-08-04

| Surface | Size | In scope |
|---|---|---|
| `asvs-scorecard.toml` cells | **345** | the population |
| cells carrying a `residual` prose field | **146** | this is where impact prose lives |
| total residual prose | **383,058 characters** (~64,000 words); max **16,785** | the read |
| `ASVS-L3-RISK-ACCEPTANCE-REGISTER.md` | **829** lines, **55** rows keyed by a cell id, 5 sections | densest impact prose, and these acceptances are **signed** |
| `evidence` entries / `absence` claims | **1,041** across 146 cells / **81** cells | mechanical — see *Out of scope* |

**Two measurement caveats, recorded so the numbers are re-derivable.** (a) The per-cell
distribution figures quoted in the source pass (median 642, p90 8,457) are **method-dependent**:
642 reproduces under `statistics.median_high` (the plain mean-of-middles is 636.5), and 8,457
reproduces under the index method `L[int(0.9*n)]` (`statistics.quantiles` gives 7,790 inclusive /
9,002 exclusive). Name the method or drop the figures. (b) The source pass reported that a crude
screen — a deployment-dependent subject term AND a present-indicative verb in the same residual —
matched **77 of the 146**, spanning every verdict class including `pass` and `na`. **That regex
was never recorded, so 77 is not reproducible from this filing.** Treat it as a rough sizing
signal only; the sweep must **re-derive the screen and inline the exact pattern** in its own PR,
and must never quote 77 as a defect count. All 146 residuals get read regardless: a cell the
screen misses is not thereby clean, and one it flags is not thereby wrong. Do not let this number
harden into a fact the way an unrecomputed census does.

### The mechanical test for "this sentence asserts a live exposure"

A sentence needs correcting **iff** its subject or object exists only when the software is running
somewhere, **and** the verb is present indicative. Three questions, in order:

1. **Whose state is asserted?** If it is an **artifact** — the shipped code, a default, a file, a
   test, a workflow, a doc — present tense is **correct and stays**. *"the default is `False`"*,
   *"no test asserts X"*, *"the engine never inspects Y"* are all true of `main` today. Leave them
   alone.
2. **If it is a person, a deployment, or data in motion** — an operator, an admin, a partner, an
   attacker, a tenant, a site, a customer, PHI at rest or in flight, a production instance — then
   present indicative asserts something that does not exist. **Rewrite to the conditional**:
   *"would expose X on first deployment"*, *"a deploying site would hit Y"*, *"is wrong in the
   shipped code"*.
3. **Did the rewrite change the severity?** If yes, the rewrite is wrong. Revert and try again. A
   Partial is a Partial. The tense moves; the verdict, the level and the risk class do not.

**The ambiguous middle, stated so it is not re-litigated per cell.** *"the engine cannot enforce
OS-level least privilege"* passes question 1 (subject is the engine) and stays. *"least privilege
depends on operator configuration"* has an artifact-ish subject but an implied live operator —
read as a claim about the **design** it stays; read as a claim about **someone's current
deployment** it does not. **When ambiguous, prefer the artifact reading and leave the sentence
alone.** This sweep's own failure mode is over-editing a record of record, and an unnecessary edit
to a signed artifact is worse than a sentence that reads slightly strong.

### The invariant that must be gated, not merely intended

Snapshot the `(id, verdict, level)` tuple for all 345 cells **before** the sweep and diff it
**after**. The sweep is correct only if that set is byte-identical. Do not rely on care: a
per-sentence pass over ~64,000 words, through residuals that run to 16,785 characters each, will
move a score by accident if nothing is watching. **Print the compared count** — a checker that
finds nothing because its parse stopped matching is indistinguishable from a clean one, which is
the failure mode this project has already recorded more than once.

Same discipline for the register: the verdict column and the signature blocks are out of bounds,
and the tool must **report, never rewrite**. Silently editing signed content to satisfy a checker
is a worse defect than the drift it would fix.

### The worked example — copy its shape

One instance is already corrected. The register's §1h row for **13.2.2** was fixed in place
vault-side on 2026-08-04 (`b0b21122`): one file, one insertion, one deletion, the verdict left at
`partial`, and the staleness **recorded rather than silently overwritten**. That commit is also
this item's source — it explicitly scoped the full 345-cell sweep out of itself rather than
half-doing it. Reproduce that shape: correct in place, say what changed and why, move no score.

### Out of scope, deliberately

- **`evidence` anchors (1,041 entries) and `absence` claims (81 cells).** These are quoted code
  lines, regexes and stated reintroductions — mechanical assertions about what the corpus
  contains, not impact prose. Sweeping them here mixes two unrelated correctness questions into
  one unreviewable diff, and that is the **whole** justification.

  > **An earlier draft justified this exclusion by saying these fields "already have their own
  > drift gate (`scripts/asvs/scorecard.py`)". That justification is DELETED and must not be
  > restored.** The absence-claim-gate item filed in this same batch establishes that
  > `check_absences` admits a claim on `re.search(a.pattern, a.mutation)` (`scorecard.py:395`) —
  > one TOML string matched against another, never applying the mutation, never consulting the
  > corpus for it. Resting an exclusion on that gate would be the exact *"compensating control
  > must not rest on a false premise"* defect **inside the item whose entire subject is that
  > defect.** Note also that *"not impact prose"* is currently **asserted, not measured**: run
  > the re-derived screen over the `evidence` strings and report the count the way the residual
  > screen is reported, with the same "a screen, not a finding" caveat, before the exclusion is
  > final.
- **Any verdict, level, or risk classification.** If reading a cell for tense surfaces a
  substantive error, **file it separately**. Fixing it inside a wording sweep destroys the
  invariant above and makes the diff unreviewable.
- **The dated prose assessments and handoffs** (`ASVS-L3-ASSESSMENT-*.md`,
  `ASVS-L3-RESCORE-*.md`, the handoff set). Those are records of what was believed on a date;
  correcting them rewrites history rather than the record. `asvs-scorecard.toml` is the verdict of
  record (ADR 0156) and the register is the acceptance of record — sweep those two.

**Related:** #353 (the same two artifacts, the same vault-side disposition, and the gate that
would compare them to each other); the absence-claim-gate item in this batch (why the mechanical
fields' own gate cannot carry an exclusion argument); ADR 0156 (scorecard as data — establishes
which artifact is the record and why prose is not);
`docs/Secure_Development_Standards.md:72-98` (§3 *"Reviewing security prose"* — the standard being
applied, and the source CLAUDE.md §11 defers to).

**Source:** the owner's standing not-deployed ruling, recorded in `CLAUDE.md` §0, **which is on
`origin/main` at `88703a3a` (PR #177, 2026-08-04)**. An earlier draft cited that ruling as
`4fbcee2b` and said it was *not* on `origin/main`; `4fbcee2b` is the **pre-squash branch SHA** and
the claim was false. Shipping an item about a record that asserts untrue things, containing an
untrue statement about where its own governing ruling lives, is the defect it exists to fix. Also
sourced: the vault-side 13.2.2 correction of 2026-08-04 (`b0b21122`) that applied the ruling once
and scoped this sweep out of itself. Every count above was measured against the vault checkout on
2026-08-04 for this filing; the engine-side facts were read at `origin/main` `88703a3a`.

## 1008. Startup preflight on the store principal's effective privileges (ASVS 13.2.2)

> 🔢 **Filed 2026-08-04 — not started. Scored 2026-08-04 → DEMAND-GATE.** Value **6/10** ·
> Difficulty **4/10** · _quick win_. The engine documents a least-privilege store grant it can
> **never observe**: there is no fixed-server-role probe and no database-role-membership probe in
> any of the four packages the scorecard scans, and `[store].require_managed_identity` constrains
> credential *kind*, not privilege — a `sysadmin` gMSA satisfies it — so an over-granted principal
> would go unobserved on first deployment. This item is the probe that closes that. Its **named
> prerequisite has fired** (engine `1e9cc4c1`, 2026-08-04, PR #173 removed the `db_owner`
> instruction), but the **owner's ruling of record is still *defer the startup preflight***, so
> the tier override applies and this stays DEMAND-GATE at any score.

**Cluster:** Security & Compliance. **Priority:** DEMAND-GATE (would be **P2** on score alone).
**Verdict:** **the owner's ruling of record is *"build the runbook fix only; defer the startup
preflight"*. The runbook half has landed; a cleared prerequisite is NOT a green-light. Confirm the
decision before starting.** **Severity:** medium (drift detection on a privilege the engine
documents but cannot observe).

> **Why DEMAND-GATE and not P2.** The rubric's one override is literal — *"an item whose named
> trigger has not fired stays `DEMAND-GATE` regardless of score, read from its own `**Verdict:**`
> line."* This item's Verdict line names the owner's ruling as *defer*, and a prerequisite
> clearing is a fact about the world, not a decision by the owner. #353 is the in-ledger
> precedent: scored 6/2 — which reads P1 under the *"value ≥ 6 at difficulty ≤ 2"* clause — and
> filed DEMAND-GATE on exactly this reading. **If the owner reads the runbook fix AS the
> green-light, this becomes P2 immediately and nothing else in the score moves.**

**What:** a startup preflight that probes the store principal's **effective** privileges and
**WARNS on shipped defaults** — and on the production-PHI posture **REFUSES** — when the login
holds `sysadmin` / `db_owner` or materially more than the documented set.

### Why this was deferred, and what has and has not changed

Until 2026-08-04 the engine's own shipped runbook told the operator to grant `db_owner` on the PHI
database — `docs/AOAG-DEPLOYMENT.md` prescribed it as a *"known-good interim posture"*, justified
by the exact bootstrap privileges being a filled-by-staging open question. **A preflight shipped
before that was fixed would have had the engine warn the operator about the posture its own
runbook told them to adopt.** That is not a control; it is a contradiction with a log line. The
build order was forced, not preferential.

The **prerequisite** is done. `1e9cc4c1` derived the real set from the store and reconciled both
runbooks: [`AOAG-DEPLOYMENT.md`](AOAG-DEPLOYMENT.md):334-342 now reads *"least privilege, never
`db_owner`"* with `db_datareader` + `db_datawriter` + `db_ddladmin` and **no server-level role**,
matching [`DEPLOY-SERVER-DB.md`](DEPLOY-SERVER-DB.md):81-84, which already carried the correct
T-SQL. Two facts from that derivation constrain the probe's target set and must not be
re-litigated: `db_ddladmin` is a **schema-change-window** grant, not a first-run-only one (the ADR
0064 schema-hash fast path means steady state issues zero DDL, but the first start of any build
whose schema *moved* runs the batch and fails outright without it), and `EXECUTE` on a **user**
procedure is conditional on `[store].fifo_claim_proc` (default `False`) — `sp_getapplock` is a
SYSTEM procedure `public` may already execute and needs no grant.

**The decision is not done.** See the Verdict line.

### Nothing in the engine probes privilege today

A grep over **the four packages the ASVS scorecard scans** — `messagefoundry`,
`messagefoundry_webconsole`, `harness`, `scripts`
([`scripts/asvs/scorecard.py`](../scripts/asvs/scorecard.py):416-426 `_python_sources`) — for
`IS_SRVROLEMEMBER`, `IS_ROLEMEMBER`, `HAS_PERMS_BY_NAME`, `pg_has_role`, `rolsuper` and
`fn_my_permissions` returns **exactly two hits**, both in one statement:
[`store/sqlserver.py`](../messagefoundry/store/sqlserver.py):922 and `:929`.

> **The instrument and the claim must be the same sentence** (CLAUDE.md §11). An earlier draft
> called this a *"repo-wide grep over `messagefoundry`"* — which is self-contradictory, and
> narrower than the claim it supports, since "the corpus" in this codebase means those four
> packages. The four-package grep was executed for this filing and returns the same two hits, so
> the claim survives; the wording is corrected rather than the finding.

Those two are a **conditional-DDL guard** for the ADR 0114 claim proc — it asks *"may I create
this procedure?"* so the must-succeed `_ensure_schema` transaction cannot fail a flag-off open,
degrading loudly to the ad-hoc batch when denied. Same primitive, opposite question: this item
asks *"do I hold more than I should?"*. The guard reports nothing, is gated on
`[store].fifo_claim_proc`, and never runs when the flag is off.

**`require_managed_identity` is orthogonal and must not be mistaken for this.**
[`config/settings.py`](../messagefoundry/config/settings.py):548-568
`managed_identity_precondition` branches **only** on `self.backend` and `self.auth`: SQLite
exempt, SQL Server satisfied by `SqlAuth.INTEGRATED` or `ENTRA` (`:557-559`), Postgres
unsatisfiable. It gates the credential's **kind**, never its privilege — **a `sysadmin` gMSA
passes it clean.**

### Nearest existing mechanism, and the default it does NOT justify

The serve-time shape is already built and should be copied rather than invented:
[`__main__.py`](../messagefoundry/__main__.py):1142-1153 calls `managed_identity_precondition()`,
prints an error and `return 2` when `enforcing`, and warns otherwise. Note the split reads
`[security].enforcement`, **not** the deployment tier, so a staging box that turns the setting on
and leaves an over-granted login is refused, not warned.

> **REVERSED FROM AN EARLIER DRAFT — do not restore "ship it default-off."** That draft argued
> the setting should default off *"for the same reason `require_managed_identity` does (`:483`,
> `False`)"*. **The precedent's real reason is backend-unsatisfiability, and it does not
> transfer.** `settings.py:481-482` records it verbatim: *"Postgres has no managed-identity auth
> mode, so it cannot satisfy it"* — defaulting **that** setting ON would refuse every Postgres
> install. A store-**privilege** probe is satisfiable on all three backends, so the analogy fails.
> Worse, default-off makes the shipped default warn about nothing, leaving open the exact blind
> spot this item exists to close — and the DEK calendar-expiry item in this same batch rejects
> precisely that trade (*"A default-off build does not move the cell, so it buys the setting and
> not the posture"*).
>
> **Split the arms:** the **WARN** arm ships **ON** (a log line; it cannot block any install), and
> only the **REFUSE** arm is gated behind an operator-declared setting. State in the
> implementation which arm the default governs.

### The landmine: cell 13.2.2 carries an absence claim over the tokens this probe needs

ASVS cell 13.2.2's absence claim is `pattern =
"IS_SRVROLEMEMBER|IS_ROLEMEMBER|db_owner|sysadmin"`, scanned by `scorecard.py:416-426` over those
same four packages — recorded, with that exact pattern, at
[`tests/test_docs_db_grants.py`](../tests/test_docs_db_grants.py):16-20, which is why that gate
file is pinned under `tests/`.

**A preflight written with those tokens in any of those four packages flips the absence claim to
FALSE.** That is not a lint failure to be worked around by obfuscating the SQL — it is the
scorecard correctly noticing the code changed. Plan for it: the paired vault scorecard edit must
land in the **same pass** as the engine change, exactly as `1e9cc4c1` did, or the daily drift cron
reds on engine-without-vault. `check_absences` (`scorecard.py:387-388`) proves an absence only
when the pattern is quiet **and** its positive control still speaks, so retiring or re-scoping
this claim is a deliberate act with its own evidence, not a deletion. See the absence-claim-gate
item in this batch: that proof is weaker than it looks, and the new claim must carry a real
observable.

### A verify-hosted probe does NOT discharge the cell's trigger

The trigger as pinned demands **a startup preflight**. A probe living in a verification harness, a
CI leg, or an operator-run script satisfies the *spirit* and **not the trigger as written**. Do
not promise a re-scorer will credit one. If a hosted probe is what gets built, that is a
legitimate choice — file it as such and leave this item open, rather than closing it against a
trigger it does not meet.

**And the cell stays `partial` under every option here.** The startup preflight is one limb of
four; the separable schema bootstrap (so steady state provably runs without `db_ddladmin`) and
least-privilege defaults for the AD bind / SMTP / SMART scopes are untouched by it, as is the
install-side LocalSystem half tracked separately. [ADR
0115](adr/0115-asvs-l3-drive-to-pass-secure-by-default-flips-and-residual-closure.md):27 books
13.2.1/13.2.2 among the residuals that stay Partial but become explicitly owned. **Buy the
posture, not the number.**

### Scope, and the part that should probably be split out

1. **SQL Server** — probe role membership and effective permissions; compare against the derived
   set; **warn on defaults**, and refuse when `enforcing` and the instance is production-PHI.
2. **Postgres — the target set does not exist yet and must be derived first.** `1e9cc4c1`'s own
   record states it deliberately: the SQL Server set does not transfer (no fixed database roles,
   `BIGSERIAL` vs `IDENTITY`, no stored-procedure path) and **no Postgres grant instruction exists
   anywhere in the repo**. **This is a documentation deliverable folded into a code item, and
   splitting it is recommended.** Its output — a Postgres least-privilege section in
   `DEPLOY-SERVER-DB.md` — is useful even if the probe is never built, which is exactly the
   relationship the SQL Server runbook fix had to this item and which was correctly split out and
   shipped as PR #173. Splitting lets the Postgres runbook land while the probe waits on the owner
   green-light.
3. **SQLite** — exempt and explicitly so: a local file has no network principal to probe.
4. **The setting + the `serve` gate**, mirroring `__main__.py:1142-1153`, with the WARN/REFUSE
   split above.

> **The tests only run on CI.** A local `pytest` silently skips the SQL Server and Postgres
> store legs, so a probe that is wrong on either backend goes green locally and red only in CI.
> Repro locally against the containers before pushing.

**Related:** the runbook fix that gated this (engine `1e9cc4c1`, PR #173, plus its
`tests/test_docs_db_grants.py` shape-pin); the CRL-checking item on the mTLS listeners (same
accepted batch); `store/sqlserver.py:920-932` (the primitive, different question);
`config/settings.py:483` / `:476-482` / `:548-568` and `__main__.py:1142-1153` (the seam to copy,
and the default-off precedent that does **not** apply); the install-side least-privilege
service-account item at `BACKLOG.md:670-675` (a distinct limb of the same cell — note `:676-681`
is the SecretProvider seam, a different item); [ADR
0115](adr/0115-asvs-l3-drive-to-pass-secure-by-default-flips-and-residual-closure.md); #353 (the
ungated risk-acceptance register — the same "nothing compares it to the record" shape as the
absence claim above).

**Source:** ASVS 13.2.2 build-or-accept decision memo, 2026-08-03 — owner-accepted as **build the
runbook fix only; defer the startup preflight**. The runbook half landed 2026-08-04; this filing
re-derives the deferral argument against the *post-fix* tree rather than restating the memo. Every
code citation was resolved against `origin/main` at `88703a3a` on 2026-08-04; the "no privilege
probe anywhere" claim is a **four-package** grep result, and the absence-claim pattern was read
from `tests/test_docs_db_grants.py`, not from the vault scorecard, which this session did not
open.

## 1009. SOAP `body_secret_value_<i>` is redacted, registered and documented — and never fingerprinted

> 🔢 **Filed 2026-08-04 — not started. Scored 2026-08-04 → P2.** Value **5/10** · Difficulty
> **2/10** · _fill-in_. `connector_secret_env_values`, the ASVS 13.3.4 runtime rotation
> fingerprinter, filters on bare `_SECRET_SETTING_KEYS` membership at `config/wiring.py:725`,
> while `body_secret_value_<i>` reaches secrecy only through the prefix branch of
> `_is_secret_setting` (`:686`) — so a rotation of a SOAP injected body secret is not
> auto-detected the way every sibling class is, and the registration gate whose comment promises
> the two sets "can never disagree" walks straight past it; the fix is one line plus the reverse
> assertion that gate is missing.

**Cluster:** Security & Compliance. **Priority:** P2. **Verdict:** build. **Severity:** low — a
monitoring gap on an opt-in connector secret class, **not** a disclosure.

**The defect.** `connector_secret_env_values`
([`messagefoundry/config/wiring.py`](../messagefoundry/config/wiring.py):702) collects the
`env()`-sourced credential values the wired graph references; `pipeline/secret_rotation.
reconcile_rotation_meta` then keyed-MACs each with the DEK-derived MAC so a changed value
auto-detects a rotation. Its filter, at `:725`:

```python
if name in _NON_ROTATABLE_SECRET_SETTING_KEYS or name not in _SECRET_SETTING_KEYS:
    continue
```

`body_secret_value_<i>` — emitted at `:2305` when a `Soap(body_secrets={token: env(...)})` map is
desugared to flat top-level settings — is **not** a member of `_SECRET_SETTING_KEYS`
(`:614-662`; grepped, zero hits). It is secret only via the prefix branch of `_is_secret_setting`
(`:686`): `return name in _SECRET_SETTING_KEYS or name.startswith("body_secret_value_")`. The
redaction path calls that helper. The fingerprint path does not. So the class is masked on
`/metadata` and in `graph --json`, registered as a critical secret, documented with a rotation
cadence — and invisible to the rotation watcher.

**On "nothing is exposed" — the enumerable version.** No disclosure follows from this, because
both redaction consumers call `_is_secret_setting`, not the frozenset: `config/wiring.py:742`
(`is_secret = _is_secret_setting(name)`, the settings serializer) and
`config/connection_schema.py:107` (`"secret": _is_secret_setting(name)`, which is what
`connection schema --json` emits and what the VS Code form at `ide/src/connectionForm.ts:51`
consumes downstream). Those are the two, enumerated by `git grep -n "_is_secret_setting"` — **not
a closed-set claim about "every serializer surface,"** which no instrument in this filing
establishes. Re-run the grep rather than trusting the enumeration.

**The fix is one line**, using the helper the module's own docstring (`:673-686`) names as the
single source of truth for both settings serializers:

```python
if name in _NON_ROTATABLE_SECRET_SETTING_KEYS or not _is_secret_setting(name):
    continue
```

`_is_secret_setting` is defined at `:672`, above the call site, and `body_secret_value_<i>` is not
in `_NON_ROTATABLE_SECRET_SETTING_KEYS` (`:697`), so the change is additive: it enrols the class
and moves nothing else. The factory already forbids an inline literal, a `default=` and a `cast=`
on each body secret, so every one is a bare `EnvRef` that the `isinstance` check at `:727`
accepts.

**Why it survived: the gate that should have caught it asserts the invariant it violates.**
`tests/test_secret_rotation_inventory.py:101` registers the class **by hand** — `"body_secret_
value": "SOAP body_secret_value_<i> injected secrets (ADR 0015)"` — and
`test_registry_secrets_appear_in_rotation_schedule` (`:157`) requires it to carry a
rotation-schedule row. So the secret is inventoried and documented as rotatable. But
`test_secret_setting_keys_are_registered` (`:182`) enumerates **`_SECRET_SETTING_KEYS`** (`:204`:
`rotatable = set(_SECRET_SETTING_KEYS) - _NON_ROTATABLE_SECRET_SETTING_KEYS`) to find things that
must be registered — and `body_secret_value` entered `CRITICAL_SECRETS` without ever passing
through that set, so the gate cannot see the direction that is actually broken. Its own comment,
at `:188-189`, states the invariant that does not hold: the set is *"the single source of truth …
ALSO read by the ASVS-13.3.4 runtime fingerprinter `connector_secret_env_values`, so the
registration gate and the runtime rotation set can never disagree."* They disagree for exactly
this class, and that sentence is the reason nobody looked.

**So the fix is two changes, not one.** The predicate at `:725`, **and the reverse assertion** —
every `CRITICAL_SECRETS` entry naming a connector setting must be reachable by
`connector_secret_env_values` — plus a regression test that builds a `Soap(body_secrets=...)`
outbound and asserts its env key appears in the returned map. Without the reverse assertion the
next entry added by hand repeats this exactly, and the comment at `:188-189` stays false.

**Do not assume the rest of the set is clean.** An earlier draft asserted *"every other
rotatable connector credential rides `:725` correctly today"*; no check in this filing establishes
that, and the reverse assertion above is precisely the instrument that would. Treat the sweep of
the frozenset as part of the work, not as a settled fact.

**"Moves no verdict" is right about the score and wrong about the record.** ASVS 13.3.4 stays
`partial` either way. But that cell's residual names this gap as extant and its re-anchor trigger
names `body_secret_value_*` joining or leaving the fingerprint set — so **landing this obliges a
same-day re-verify of the residual**. **The residual and its trigger live in the vault-only
`docs/security/asvs-scorecard.toml`** — `docs/security/` is gitignored here and `git ls-tree -r
origin/main -- docs/security` returns nothing, so a session that greps this repo for 13.3.4 will
find nothing and wrongly conclude the obligation is stale. The engine PR and the vault edit must
land **as a pair**, as the 13.2.2 (`1e9cc4c1` / `f2c017ce`) and 12.1.5 (`62fd628d` / `a8a5a1c2`)
pairings did. Say so in the PR body, or the code and the record drift apart in the very commit
that closes the gap.

**Nearest existing mechanism:** none to build against — this *is* the mechanism, already shipped
and one predicate short.

**Citation trap, flagged so it is not propagated.** `wiring.py:681-682` sources the prefix
branch to *"ADR 0015 amendment / BACKLOG #236"*. **That `#236` is an internal-ledger number and
does not resolve here** — public `docs/BACKLOG.md` #236 (`:2469`) is *"Test-this-step and
test-up-to-step with pinned upstream values"*, unrelated work. The two number spaces diverged
around #231 and overlap below 1000 by design; the overlap was deliberately left unrepaired
(`8e6e7fa3`: renumbering *"would only make stale citations resolve uniquely and WRONGLY"*). Cite
**ADR 0015** for this class, not a bare `#236`.

**Trigger:** none — it is a defect, not demand-gated.

**Related:** the absence-claim gate that proves syntax rather than behaviour (filed in the same
batch — the other instrument problem on the same ASVS cell); [ADR
0015](adr/0015-ws-soap-outbound-mtls-wssecurity.md) and its amendment, whose desugar
(`_hoist_body_secrets`) lives at `wiring.py:2249-2306` and is called at `:2414`; ADR 0158 (green
signals that mean nothing — the reverse-assertion half of this is an instance).

**Source:** noticed during the ASVS build-or-accept costing pass, 2026-08-03, unrelated to any
cell that pass decided, and filed rather than folded into one. Re-verified against `origin/main`
`88703a3a` for this filing: the filter at `:725`, the frozenset at `:614-662`, the prefix branch
at `:686`, the exclusion set at `:697`, the desugar at `:2305`, the two `_is_secret_setting`
consumers at `:742` and `connection_schema.py:107`, and the registration plus gate comment at
`tests/test_secret_rotation_inventory.py:101` / `:182-209` were each read directly.

## 1010. No licence-header gate exists in any language, and 196 first-party sources carry no SPDX tag

> 🔢 **Scored 2026-08-04 → P2.** Value **7/10** · Difficulty **3/10** · _quick win_. AGPL-3.0-or-later is asserted twice — in `LICENSE` and at `pyproject.toml:29` — and then per-file provenance is left to habit. 981 of 1,044 tracked `.py` carry `SPDX-License-Identifier`, which makes the convention real and near-universal; the 63 that do not include **all 17 files of `messagefoundry/tray/`**, a package `only-include` puts in the wheel and `[project.gui-scripts]` gives its own entry point. Widen past Python and it is **196 of 1,181 tracked sources across six languages**. Five more files declare **Apache-2.0** in an AGPL project. Nothing — no hook, no workflow, no test — checks a licence header in any language.

**Cluster:** Supply chain / licensing. **Priority:** P2. **Verdict:** build. **Severity:** medium.

**What:** a language-agnostic licence-header gate — a checker asserting that every first-party source carries `SPDX-License-Identifier: AGPL-3.0-or-later`, wired as a `local` **pre-commit** hook beside `ledger-gate` and `forbidden-content` (which are the same shape) and mirrored in **CI**, plus the backfill it demands. It must assert the **value**, not the presence of the string: five files carry a header naming the wrong licence today, and a presence-only check passes all five.

**The measurement.** Per-file, over `origin/main`, one grep per tracked file:

| Language | Tracked | Carry a header | **Missing** |
|---|--:|--:|--:|
| `.py` | 1,044 | 981 | **63** |
| `.ts` | 98 | 0 | **98** |
| `.ps1` | 33 | 2 | **31** |
| `.js` | 4 | 2 | **2** |
| `.go` | 1 | 0 | **1** |
| `.sh` | 1 | 0 | **1** |
| **Total** | **1,181** | **985** | **196** |

The 63 Python files break down as: **17** `messagefoundry/tray/` · **37** `tests/` modules · **3** `scripts/quality` · **3** `scripts/hooks` · **1** `scripts/tray` · **1** `scripts/security` · **1** `tests/fixtures/handler_taint`. Every one of those sub-counts was re-derived here and matches the figure this item was split out of. What did **not** match is the headline: that draft scoped the gap to Python plus one Go file and reported **64 across two languages**. Scoped as a *language-agnostic* gate actually would be, it is **196 across six**. The 132-file difference is entirely `.ts`, `.ps1`, `.js` and `.sh` — files a Python-only reading never looks at, which is precisely the reading this item exists to replace.

**Scope — `tests/` are in scope, and the repo already says so.** This was the open question, and it resolves on evidence rather than assumption. `tests/` is at **560 of 598 (93.6 %)** — a tree that is deliberately exempt does not carry a header on nine files in ten. Nor is the exemption written anywhere: `CONTRIBUTING.md` has a full *License* section and mentions SPDX headers **zero** times, and no config, hook or workflow excludes `tests/` from anything header-related (there is nothing to exclude it *from*). The 38 are drift, not policy. `messagefoundry/` is the cleaner signal still: **245 of 262**, and the only subpackage missing anything is `tray/` — at **17 of 17**. That is not scattered decay, it is one package that landed (ADR 0113) without headers and nothing noticed, which is the failure mode a gate removes.

**No gate exists, and here is exactly what was scanned.** A negative result is only worth what its scan list is worth, so:

- **`.pre-commit-config.yaml`**, read in full — hooks are `ledger-gate`, `ruff-format`, `ruff-check`, `forbidden-content`, `gitleaks`, `actionlint`, `bandit`. No header hook.
- **All 21 files in `.github/workflows/`** — grepped for `spdx|reuse|license.header|licence|addlicense|licenseheader`, excluding each file's own header. Four hits, every one the word *reuse* or *licence* in unrelated prose (`ci.yml:536`, `ci.yml:833`, `codeql.yml:17`, `scorecard.yml:17`).
- **`tests/`, `scripts/`, `ci/`** — same grep. **One** hit: `tests/test_sbom_finalize.py:89`, `bomFormat="SPDX"`, an unrelated CycloneDX format string.
- **`.mefor-hooks/`, `.semgrep/`** — nothing.

The release SBOM does not cover this either: `release.yml:211` runs `cyclonedx-py environment`, which inventories **installed third-party distributions**, not first-party per-file headers. So no existing signal reports the gap, and none would.

**Why it matters.** Three concrete consequences, none of them speculative:

1. **Seventeen headerless files are distribution content.** `pyproject.toml:21` `only-include = ["messagefoundry", …]` puts the whole package in both sdist and wheel, and `:214` gives `messagefoundry.tray` its own `gui-scripts` launcher. A recipient of `messagefoundry/tray/app.py` on its own has no licence statement on the file. The *distribution* is correctly licensed — PEP 639 `license` + `license-files` ship `LICENSE` and `NOTICE` every time — so this is a per-file provenance defect, not an AGPL coverage failure. Stating it any stronger would be overstating it.
2. **Five files assert the wrong licence.** `tests/test_bytes_per_message_amplification.py`, `test_connscale_cpu_probe.py`, `test_harness_invariants.py`, `test_live_cost_counters.py` and `test_txn_per_message_cost_model.py` carry `SPDX-License-Identifier: Apache-2.0`. An affirmative misstatement is worse than an omission, and it is the specific case a presence-only gate would bless.
3. **Per-file provenance is load-bearing for the open-core path.** `docs/DUAL_LICENSING_PLAN.md` and the CLA both turn on knowing which files are contributed under which terms. Adjacent and verified: `ide/package.json` declares `"license": "SEE LICENSE IN LICENSE"` and **no `ide/LICENSE` exists** — the only tracked licence files in the repo are `LICENSE`, `NOTICE`, and the two under `packaging/messagefoundry-webconsole/`. A published extension manifest points at a file that is not there.

**This is a convention with no enforcing control**, which is the shape of **#327** (six `.gitignore` rules are the sole guard on maintainer-internal docs and nothing asserts they still match) and of **#1000** generally. The convention has held at 93 %+ on its own for a long time, and that is exactly why it is worth gating: it is one careless package away from decaying, and it already decayed once — silently, across a whole package, in the tree that ships.

**Proposed:**

1. **Decide the scope explicitly and write it down**, since nothing currently does: which extensions, which trees, and what is exempt (vendored code under `tee/` is already at 18 of 18, so it may need none; generated files and test fixtures may). Publish the in-scope count, not a completeness claim.
2. **Write the checker** — extension → comment-prefix map, assert the first N lines contain `SPDX-License-Identifier: AGPL-3.0-or-later` **exactly**. Reject a wrong identifier as loudly as a missing one.
3. **Prove it can go red before wiring it in.** Plant a violation of each class — missing, and wrong-value — and record the observed failure. Per **#1000**, a green gate is evidence only once it has been watched fail on that class; this gate should ship with its negative control rather than acquire one later.
4. **Wire it as a `local` pre-commit hook and a CI step**, matching how `ledger-gate` and `forbidden-content` are already wired, so a local commit and a PR see the same rule.
5. **Backfill**, largest tree first: `messagefoundry/tray/` (17, wheel content), then `scripts/` (8), then `tests/` (38), then the non-Python trees. Fix the five Apache-2.0 headers in the same pass.
6. **Fix the dangling `ide/LICENSE` pointer** — either add the file or correct the manifest field.

**Cost of getting this wrong is zero right now.** MessageFoundry is a not-yet-deployed beta with no production instances, so there is no migration and nothing to sequence around: the gate can be turned on the day it is written, at whatever strictness is right, without a grace period. That is an argument for doing it now and for doing it strictly — it is not an argument that it matters less.

**Trigger:** none — this is not demand-gated. It is owed regardless of how **#1011** rules on `tools/ech-sidecar/`: whether that Go tree is kept or deleted, the other 195 files are unaffected.

**Related:** #1011 (split from the same draft — the ECH keep-or-retire ruling; the Go file is 1 of the 196 and its disposition is independent), #1000 (negative controls: the new gate must ship with proof it can fail), #327 (a convention guarded only by habit, with no test asserting it).

**Source:** a drafted claim that *"every first-party Python source carries `# SPDX-License-Identifier`"*, found false on re-measurement (981/1,044) during the ECH sidecar disposition review, 2026-08-04. Re-measured here per language; the two-language framing of the original finding was itself an undercount.

## 1011. Rule on the shipped `tools/ech-sidecar/` Go tree: keep it and own it, or retire it

> 🔢 **Scored 2026-08-04 → P1.** Value **6/10** · Difficulty **2/10** · _quick win_. A 312-line TLS-terminating Go re-originator is tracked at `tools/ech-sidecar/`, and **nothing builds, tests, lints or version-pins it** — a grep for `setup-go|go build|go vet|golangci|GOPROXY|gofmt|GOTOOLCHAIN` across all 21 workflows, `ci/`, `scripts/`, `.pre-commit-config.yaml` and `tests/` returns **zero hits**. Meanwhile ADR 0139's *Implementation status* still files that exact artefact under **"Deferred (the real ECH work)"** and `docs/SECURITY.md` still calls ECH **"infeasible … not buildable here"**. The repo carries a second language by accident rather than by decision, and the security record says it does not exist.

**Cluster:** Supply chain / security record. **Priority:** P1. **Verdict:** decide. **Severity:** medium (a compensating control in `SECURITY.md` rests on a premise the tree refutes).

**What:** a **dated owner decision** on the Go tree, plus the record reconciliation it forces. Two outcomes, and the item is done when one is chosen and written down.

**The state at HEAD, measured.**

| Fact | Evidence |
|---|---|
| The tree is real and non-trivial | `tools/ech-sidecar/` = `main.go` (**312 lines**), `go.mod`, `README.md`, `.gitignore` |
| It is the whole Go footprint | full extension inventory of `origin/main`: **exactly one** `.go` and one `.mod` in 1,959 tracked files |
| Nothing builds, tests, lints or pins it | the toolchain grep above → **zero hits**, repo-wide |
| Its own floor is unread | `go.mod` declares `go 1.26` — a version constraint no CI consumes |
| It reaches no user | `pyproject.toml:21` `only-include = ["messagefoundry", …]` — `tools/` is in **neither** sdist nor wheel |
| The ADR says it is not built | ADR 0139 `:27` — "**Deferred (the real ECH work):** that terminating re-originator sidecar + its packaging (no Go toolchain ships in the wheel)" |
| …and its own checklist agrees | ADR 0139 `:99` — `- [ ] Decide the sidecar (sing-box vs a ~500-line purpose-built Go binary)`, still unchecked next to a purpose-built 312-line Go binary |
| `SECURITY.md` says it is impossible | `:1697` — "**infeasible** … **not buildable here** … would require a **third-party TLS stack** — violating the no-new-dependency rule" |
| …while the engine points straight at it | `transports/rest.py`, `ech_sidecar_url_from_settings` docstring — "the TLS-**terminating** re-originator at `tools/ech-sidecar/` (**proven to hide the SNI against a real ECH endpoint**)" |

**The `SECURITY.md` line is the sharpest part.** It is not a stale sentence in a changelog; it is the reasoning inside a **documented risk acceptance** for 12.1.5, and the reason offered for accepting the residual is that the control cannot be built. HEAD contains a stdlib-only Go implementation of that control — no third-party TLS stack, no new Python dependency — so the stated ground is refuted by the repository the document ships in. CLAUDE.md §11 names this shape by hand: *a compensating control must not rest on a false premise*. Whatever the ruling, that paragraph has to change.

**This does not move the ASVS score, either way.** 12.1.5 is `fail` and stays `fail`. ECH is an **OpenSSL 4.0** feature (RFC 9849); the interpreter here links **OpenSSL 3.5.7** — measured directly, `import ssl; ssl.OPENSSL_VERSION` → `OpenSSL 3.5.7 9 Jun 2026` — so the in-engine native path is unbuildable, and the 2026-07-20 DoH type-65 probe found **no** partner endpoint (Epic, Oracle Health/Cerner, athenahealth, Google Cloud Healthcare, SMART, 1upHealth) publishing even an HTTPS record, let alone an ECHConfig. Keeping the tree buys no cell; deleting it costs no cell. That is what makes this a disposition question rather than a security one, and it is why the answer should be driven by ownership cost, not by score anxiety.

**Recommendation: retire.** The argument turns on one fact — **`git rm` does not destroy the work.** The 312 lines stay in history; ADR 0139 can cite the commit that carried them and a future session recovers them with one `git show` on the day a partner starts publishing ECH configs. Against that near-zero cost, *keep* is a permanent obligation: a `setup-go` leg, a pinned toolchain, `gofmt`/`go vet`/a linter, a build-and-test job, and the distribution answer ADR 0139 itself flags as unsolved ("its packaging — no Go toolchain ships in the wheel") — a whole second-language CI surface, maintained indefinitely, for an artefact that is excluded from every published artifact, has zero beneficiaries today, and closes nothing. A repo that adopts a second language should do it deliberately, and this one has not decided to.

Retiring the tree costs the engine nothing operationally: **`tests/test_ech_egress.py` and the fail-closed routing stay exactly as they are.** `ech_sidecar_url_from_settings` / `egress_route_from_settings` in `transports/rest.py` are independently valuable — they refuse a non-loopback sidecar, refuse `ech_egress` without `ech_sidecar`, and error rather than silently falling back to a SNI-leaking direct hop. That behaviour is worth keeping on its own terms and is covered by a stub-proxy behavioural test. Only the Go implementation of the far end goes.

**If the owner rules *keep* instead**, the item's remainder is materially larger — a Go build/test leg, a pinned toolchain, a linter, and a signed-distribution answer — call it difficulty ~4 rather than 2. That asymmetry is itself part of the case: *retire* is cheap and reversible, *keep* is expensive and open-ended, and neither changes the score.

**Proposed (retire path):**

1. **Record the dated owner decision** in ADR 0139 — including the commit SHA that carries `main.go`, so the work is retrievable by reference rather than by memory.
2. **Reconcile ADR 0139 to HEAD** — the *Implementation status* block (stop calling the re-originator "Deferred" when it was written, then retired), the Status line, and the unchecked "Decide the sidecar" item, which this ruling closes.
3. **Rewrite the `SECURITY.md` 12.1.5 paragraph** so the residual rests on the true ground: not "infeasible", but *buildable off-stdlib and deliberately not owned, because no partner endpoint publishes an ECHConfig and the engine's own TLS stack cannot originate ECH until OpenSSL 4.0*. Same accepted residual; a premise that survives inspection.
4. **Re-point `rest.py`'s docstring** — `ech_sidecar_url_from_settings` names `tools/ech-sidecar/` by path and asserts it is "proven to hide the SNI". After deletion that path resolves to nothing; the reference becomes the historical commit, and the "proven" claim needs whatever evidence actually backs it or should go.
5. **Decide `samples/ech-sidecar/README.md`** — the operator recipe (the only file under that sample dir) describes running a sidecar the repo no longer contains. Re-aim it at the generic contract (any loopback ECH-terminating proxy) or retire it with the tree.
6. **Mark SEC-71 discharged** in `docs/testing/master-test-plan/16-security-phi-and-supply-chain.md`, which specifies this exact disposition and is currently the only place in the repo that records the true state.

**Migration cost: none.** MessageFoundry is a not-yet-deployed beta with zero production instances, and `tools/` has never been in an sdist or a wheel — so no consumer of any published artifact is affected by deleting it. There is no deprecation window to run and nothing to sequence.

**Trigger:** already fired — not the ECH build trigger (ADR 0139's is *a partner endpoint begins publishing ECH configs*, and it has not), but this item's own: **an unowned tree is in the repository and two security documents contradict it today**. The ruling is owed now and does not wait on ECH deployment.

**Related:** #1010 (split from the same draft — the licence-header gate; `main.go` is 1 of the 196 headerless sources and gets a header only if this rules *keep*), #272 (ADR 0139's owning item), #353 (an ungated compliance artifact — same "nothing compares it to the record" shape), #1000 (a gate that has never been watched fail; here the failure is a *language* nothing gates at all).

**Source:** master test plan **SEC-71** (`docs/testing/master-test-plan/16-security-phi-and-supply-chain.md`), which specifies this disposition; escalated 2026-08-04 when the SPDX half of the original draft was found to rest on a false claim and was split out as **#1010**. Every fact above was re-executed against `origin/main` at `df9c4d54`.

## 1002. AG-rig validation: prove the multi-subnet failover reconnect

> 🔢 **Filed 2026-07-31 — not started. This needs HARDWARE, not a decision.** `[store].multi_subnet_failover` shipped (#100, 2026-07-10) and is **unit-tested only** — it has never been pointed at a real cross-subnet availability group. Until it is, [`AOAG-DEPLOYMENT.md`](AOAG-DEPLOYMENT.md) §4.5 must keep mandating a planned DB outage, because "the setting exists" is not the same claim as "the reconnect works".

**Cluster:** Server DB / HA. **Priority:** P2. **Verdict:** build (test execution). **Severity:** medium — no defect is known; the cost is a maintenance window every multi-subnet adopter takes and may not need.

**What:** stand up a two-subnet WSFC with an Always On availability group and a listener, run the engine against it with `[store].multi_subnet_failover = true`, force a failover, and measure whether the engine reconnects — and how that compares to the DNS-side workaround §4.5 currently prescribes.

**Why it is worth hardware:** §4.5 tells a DBA to run `Stop-ClusterResource` / `Start-ClusterResource` on the AG listener to apply Microsoft's `RegisterAllProvidersIP=0` workaround. That is a planned DB outage, and the doc's own comment schedules it "like a §5.2 short planned DB blip". The premise for it was that the engine had no AG-aware connection keyword — which stopped being true on 2026-07-10. The premise is corrected (PR #99) but the instruction stands, deliberately: telling a hospital DBA they can skip a maintenance window on the strength of an unvalidated setting risks converting a scheduled outage into an unplanned one during a real failover. Only a rig can retire it.

**Set the listener back to the default first.** If the rig's listener is already at `RegisterAllProvidersIP = 0` — because someone followed §4.5 — you are measuring the workaround, not the keyword. Confirm `RegisterAllProvidersIP = 1` before starting, and state that you did.

**What to measure:**

1. Does the engine reconnect at all after a cross-subnet failover, with the workaround **not** applied?
2. How long, from failover to first successful store write — against the workaround path (DNS TTL expiry plus cross-site DNS/AD replication) as the comparison. If the keyword is not clearly better, that is a real result and changes the answer.
3. What happens to in-flight messages across the gap — lost, duplicated, or held? The engine is at-least-once; confirm rather than assume.
4. Failover **and** failback.
5. A control run with `multi_subnet_failover = false` on the same rig. Without it the improvement cannot be attributed to the setting.

**The three questions the §4.5 rewrite is waiting on:**

- Does the keyword remove the need for the listener restart on a **greenfield** listener (still at `RegisterAllProvidersIP = 1`)?
- What does a **brownfield** site do — one already at `RegisterAllProvidersIP = 0`? The keyword only helps when every subnet IP is published, so the expectation is that undoing the workaround still costs a restart. Confirm or refute; it decides whether the rewrite can promise existing deployments anything.
- What is the **engine-version floor**? The setting shipped 2026-07-10; `AOAG-DEPLOYMENT.md` carries no version vocabulary today.

**Explicitly not this item:** the `db_lookup` gap. `transports/database.py` builds its own connection string and emits no `MultiSubnetFailover`, so a deployment reaching the same listener through the DATABASE connector needs the DNS-side configuration regardless of what this rig measures. Whether that connector should get the keyword is a separate owner decision — do not let a green result here be read as "the workaround is obsolete".

**Do not extrapolate from the AD lab.** [`plan-11/w19-ad-lab-integration-validation.md`](releases/plan-11/w19-ad-lab-integration-validation.md) covers AD/Kerberos integration and records this as *"needs the SQL AG rig"*. Its note that "all shipped — this is confirmation, nothing is blocked" is true of the code and false of the documentation.

**Related:** #100 (the shipped setting), [`AOAG-DEPLOYMENT.md`](AOAG-DEPLOYMENT.md) §4.5 / §5.3, `messagefoundry/config/settings.py` (`multi_subnet_failover`, default `false`), `messagefoundry/store/sqlserver.py` (`connection_string`), [`CONFIGURATION.md`](CONFIGURATION.md).

**Source:** filed 2026-07-31 while correcting two stale claims in `AOAG-DEPLOYMENT.md` (PR #99). The validation gap was visible only as a line in a plan-11 doc and was not tracked work — a closed item with outstanding validation, which is the shape that goes missing.

## 1013. The `[auth] enabled=false` startup arm keys on the bind alone, so auth-off behind a declared terminator still starts

> 🔢 **Filed 2026-08-04 — not started.** Value **7/10** · Difficulty **4/10** · _quick win_. The auth-off startup arm reads `not settings.auth.enabled and not settings.api.is_loopback`, so it does not fire for a declared TLS-terminating proxy. A PHI instance with authentication **entirely off** behind a declared terminator starts with **no refusal and no warning** — while the same topology with auth ON but MFA off is refused by the gate #326 fixed. The two arms disagree about what "exposed" means, in the same file, for the same topology.

**Cluster:** Security / startup gates. **Priority:** P1. **Verdict:** build. **Severity:** high on first deployment — no authentication at all on an off-loopback PHI instance.

**Anchors, re-derived on `origin/main` at 17374679 now that #326 has merged.** These resolve today; verify them before starting.

- `messagefoundry/__main__.py:1112` — `if not settings.auth.enabled and not settings.api.is_loopback:` — the auth-off arm.
- `messagefoundry/__main__.py:1917` — `instance_exposed = not settings.api.is_loopback or settings.api.tls_terminated_upstream` — the definition that already encodes the declared-terminator case, and now the ONLY one.
- `messagefoundry/__main__.py:1939` — `admin_exposed = instance_exposed` — #326's post-fix form, re-keyed onto the definition above.

**The separation is the reason this is a separate item and not a one-line follow-on to #326.** `instance_exposed` is defined **805 lines BELOW** the auth-off arm, so the arm cannot reference it without hoisting the definition. #326 could re-key `admin_exposed` because the definition already sat above it; this cannot.

**Why it is arguably worse than #326.** #326 was single-factor admin over the network. This is **no factor at all**. A deployment that follows the documented off-loopback topology, with a declared terminator and `[auth] enabled=false`, starts silently.

⚠️ **THE REMEDY IS UNPROVEN — do not read this item as prescribing one.** Nobody has established that hoisting `instance_exposed` to the auth-off arm is safe. That arm runs **early** in the startup ladder, and whether the settings it reads are fully resolved at that point is unknown. **That ordering question is the actual work of this item**, not the two-line re-key it superficially resembles.

**#326 HAS LANDED** (PR #189), and the re-verification this paragraph asked for was performed at `17374679`: the arm moved `:1080` to `:1112`, `instance_exposed` moved `:2368` to `:1917`, `admin_exposed` is now `admin_exposed = instance_exposed` at `:1939`, and the separation narrowed from 1,288 lines to **805**. The duplicate definition at the former `:2368` is **gone**, replaced by a pointer comment at `:2454` ("`instance_exposed` is NOT re-derived here. It is defined ONCE, above"), so there is now exactly ONE definition site to move rather than two to keep in sync. **The load-bearing property survives the move and so does the difficulty-4 pricing:** the arm at `:1112` still sits ABOVE the definition at `:1917`, so it still cannot reference it without hoisting, and the ordering question is still the actual work. Only the numbers changed.

⚠️ **A consequence of #326 that this item does not cover, and that no gate can see.** Re-keying `admin_exposed` onto `instance_exposed` means the MFA-at-exposure refusal now fires on a declared-TLS-terminator topology where it previously could not — a posture change under **ASVS 6.3.3**, whose citations all still resolve, so nothing went red. Raised by the vault drift-repair pass of 2026-08-04; 6.3.3 needs re-validating against the code rather than being assumed still correct. Not folded in here.

**Related:** #326 (the sibling arm, same file, same gate family), #328. The ADR 0140 amendment on `plan-cli-exposure` records this residual but names no number, having been written before one existed — worth a follow-up edit now that this item is filed.

**Source:** found by the #326 lane's own recon and handed over because filing needs `alloc.ps1` plus a ranked-table row, both outside a lane's permitted surface. The measurements are the lane's; the main-side anchors were re-derived at filing because the lane's numbers describe its post-fix tree and would not have resolved here.

## 1012. ASVS gate summary line silently drops a verdict state: components sum to 344 against its own stated 345

> 🔢 **Filed 2026-08-04 — not started.** Value **5/10** · Difficulty **2/10** · _fill-in_. The gate's summary line prints five verdict states whose components sum to **344**, while the same line states a total of **345**. It omits `needs-review`. So the line cannot be reconciled against itself, and a reader who trusts it under-counts one state entirely.

**Cluster:** Security / ASVS tooling. **Priority:** P3. **Verdict:** build (small).

**Severity is low and worth saying why**, so nobody inflates it: no verdict is mis-scored, and the vault scorecard remains the record of record. The cost is that the summary is the line people quote — it was quoted as "the distribution" across a full session, and the omission propagated every time it was repeated.

**Why it matters more than a cosmetic count.** A count that does not reconcile with its own stated total is the tell for a missing category, and the check that would have caught it does not exist. This is the same shape as several defects found the same day: an instrument that answers a narrower question than the one asked, and reports success.

**Proposed fix.** Emit the missing state, and add an assertion that the printed components **equal** the printed total. The assertion is the durable half; the missing state alone would leave the next added verdict able to vanish the same way.

**Related:** the ASVS scorecard tooling under `docs/security/` in the vault (not tracked here — see [`SECURITY-DOCS-POLICY.md`](SECURITY-DOCS-POLICY.md)). Recorded in vault `d0c5736a` §2.

**Source:** handed over by the ASVS-cleanup session on 2026-08-04, which found it after quoting the line all day, and which could not file it because the ledger was held elsewhere.

## 1015. OIDC relying party keys federated accounts on a reassignable username claim while the non-reassignable `sub` is discarded (ASVS 10.5.2)

> 🔢 **Filed 2026-08-04 — not started.** Value **7/10** · Difficulty **4/10** · _quick win_. The relying party keys federated identity on `oidc_username_claim` (default `preferred_username`), which an IdP is free to **reassign**, while the non-reassignable `sub` is verified and then dropped into an audit field. On first deployment a new holder of a retired username would be handed the prior holder's account.

**Cluster:** Security / authentication. **Priority:** P1. **Verdict:** build. **Severity:** high on first deployment — account takeover without any credential compromise.

**What is wrong.** `sub` is the only claim OIDC guarantees is stable and non-reassignable within an issuer. The RP verifies it and then discards it as identity, keying the local account on a display-oriented claim instead. Directory products reassign `preferred_username` routinely — a departed employee's name freed and reissued is ordinary lifecycle, not an attack.

**Why value 7 and not higher.** It matches **#1013** (7/4): both are authentication-gate defects that admit the wrong principal. This one is more conditional — it needs an IdP-side reassignment — but it lands on an **existing** account rather than an empty one, which is why it does not sit below #1013.

**Difficulty 4, and there is no migration cost.** Key on `(issuer, sub)` and keep the username as a mutable display attribute. Normally that is a data migration; here there are **zero deployments** (see CLAUDE.md §0), so there is no installed base to migrate. What remains is the model change, the AD/local-account interaction, and deciding what happens when an existing local username collides with a federated display name.

**Related:** #1016 (same module, different failure class), ASVS 10.5.2. The V10 chapter report in the vault carries the full 14-item re-triage.

**Source:** found during the ASVS V10 re-verification, 2026-08-04, and handed over because filing needs `alloc.ps1` plus a ranked-table row, neither of which is inside a build session's permitted surface. Confirmed as reported.

## 1016. claims.py 500s on two malformed-IdP shapes with no closed-set audit row

> 🔢 **Filed 2026-08-04 — not started.** Value **5/10** · Difficulty **2/10** · _fill-in_. Two narrow, attacker-influenceable inputs raise **past** the `ClaimsError` contract, so the response is a 500 with no closed-set audit row instead of a named claim rejection.

**Cluster:** Security / authentication robustness. **Priority:** P2. **Verdict:** build (small). **Severity:** low — availability and audit completeness, not an auth bypass. Neither path admits a bad principal; both turn a rejectable token into an unclassified 500.

⚠️ **The two mechanisms below are NOT the ones originally reported, and the difference decides the fix.** Both were re-derived against the code at 32d0cef9 and tested directly. Filing the reported versions would have sent a fixer at checks that already exist.

**1. `hmac.compare_digest` raises on a NON-ASCII str nonce.** Not "on two str" — two ASCII strings compare fine and return a bool. Measured: `compare_digest('abc','abc')` returns `True`; a non-ASCII operand raises `TypeError: comparing strings with non-ASCII characters is not supported`. And the guard reads `if not isinstance(token_nonce, str) or not hmac.compare_digest(...)`, so the `or` short-circuit means a non-str nonce can never reach the call — **type confusion is already closed, and non-ASCII is the ONLY remaining path.** The fix therefore belongs at the encoding boundary, not in an `isinstance` check that is already present.

**2. `set(aud)` raises on a list containing UNHASHABLE elements.** Not "on a non-iterable". The line reads `audiences = {aud} if isinstance(aud, str) else set(aud) if isinstance(aud, list) else set()`, and measured, every non-list shape falls through cleanly — a bare int, `None` and a dict all yield an empty set with no error. The residual is a list whose elements are unhashable: a list containing a dict raises `TypeError: cannot use 'dict' as a set element`.

**Why it matters more than a 500.** Both paths bypass the closed-set audit row that every other claim rejection emits, so a malformed or hostile IdP response becomes an unclassified error rather than a named, audited refusal — which is the record an operator would need to tell a broken IdP from an attacked one.

**Related:** #1015 (same module, an identity-keying defect rather than a robustness one).

**Source:** found during the ASVS V10 re-verification, 2026-08-04. The conclusions were reported correctly; both mechanisms were misstated and are corrected here, with the correction verified independently by the reporting session.

## 1014. connscale smoke test's fixed 24-port block is not parallel-safe across worktrees; the flaky marker hides the collision

> 🔢 **Filed 2026-08-04 — not started.** Value **5/10** · Difficulty **3/10** · _fill-in_. `test_connscale_smoke_end_to_end` hard-codes `base_port = 41000` and requires 24 **contiguous** inbound ports, so two checkouts running the suite at once contend for the same block. A `@pytest.mark.flaky` marker retries past the collision, so a determinate resource conflict wears a noise label.

**Cluster:** Testing / CI reliability. **Priority:** P3. **Verdict:** build (small). **Severity:** low — it costs retries and misdiagnosis, not correctness.

**Why this is not a flake.** It was traced rather than assumed. There is no global `--reruns` in `addopts`, so only an explicitly-marked test can retry at all, and exactly two are marked; one skips locally. That leaves this test, carrying `@pytest.mark.flaky(reruns=2, reruns_delay=3)` with the comment *"CI runners are noisy: re-run clears"*. Three suites were run in parallel across three worktrees; two needed their retry and the third did not, because it won the race for the fixed block.

**Why the label is the defect.** The retry is doing work the port allocation should be doing. Labelled *noisy runner*, a real contention bug becomes invisible — and this repo's own guidance is that a failure must be **proven** timing-dependent before being called a flake, precisely because the two previously-famous flakes here turned out to be a livelock and a test that was right.

**The topology makes it routine, not exotic.** This project runs many checkouts of the same repo at once — **24 worktrees were live on 2026-08-04** — so "two checkouts at once" is the normal case rather than an edge case.

**Proposed fix.** Allocate the block dynamically, assert contiguity at acquisition, and fail loudly if it cannot be obtained. Then remove the `flaky` marker, so a future collision is a red rather than a retry. Do not widen the retry count.

**Related:** #340 (merge-queue serialisation — the other place this repo's parallelism outgrew a fixed assumption).

**Source:** found by a build session while re-verifying five rebased lanes, 2026-08-04. It attributed the immediate trigger to its own parallel harness rather than to the branches under test, and handed the underlying defect over because filing needs a number and a ranked-table row.

## 1021. The MFA enrollment confirm verifies the activating TOTP through a bool wrapper that discards the step, so it is never consumed (ASVS 6.5.1)

> 🔢 **Filed 2026-08-04 — not started.** Value **6/10** · Difficulty **4/10** · _quick win_. `confirm_mfa_enrollment` verifies the enrolling code with `totp.verify_totp`, a documented thin bool wrapper that computes the matched time-step and then collapses it to a bool, so the step cannot be recorded. `enable_totp` leaves `last_totp_step` NULL, and `consume_totp_step` rejects only when `last is not None and last >= step` — so on first deployment the activating code would remain usable on the login path for the remainder of its own step.

**Cluster:** Security / authentication. **Priority:** P2. **Verdict:** build (small). **Severity:** would leave a narrow second-factor replay window at enrollment on first deployment — bounded, not a bypass.

**Two facts combine, and the body needs both.** The confirm path discards the step (`auth/service.py:1979` calls `totp.verify_totp`; `auth/totp.py:150` computes the step then returns `... is not None`), and nothing seeds the high-water mark, so the discarded step is genuinely reachable rather than incidentally blocked: `enable_totp` updates only `totp_enabled`, `totp_enrolled_at`, `totp_recovery_codes`, `updated_at` in all three backends (`store/store.py:7752-7764`, `sqlserver.py:9095`, `postgres.py:6165`), leaving `users.last_totp_step` NULL, and the compare-and-set at `store/store.py:7824` accepts any matched step against a NULL mark.

**The replay target is the login path, not a second confirm.** Code `C` proven at `POST /me/mfa/confirm` would still be accepted by `POST /auth/mfa-verify` on a separate, password-authenticated session for the same account. `totp_skew_steps` defaults to `0` (`config/settings.py:1736`), so the window is the remainder of `C`'s own 30-second step — roughly 60 or 90 seconds only under the documented 1/2 opt-in. Do not size it as plus-or-minus-one step. `confirm_mfa_enrollment` also lacks a `totp_enabled` guard, so a second confirm would re-succeed, but that route needs a fresh action-bound password step-up (`api/auth_routes.py:408`) and is the lesser path — do not build the fix around it.

⛔ **The replay guard already exists. Do not rebuild it.** `verify_totp_step` already returns the matched step and already clamps a tolerated fast-clock code down to the current step (`auth/totp.py:90-132`, SEC-014); `_verify_second_factor` already does verify-then-consume on the login path (`auth/service.py:2061-2073`); the atomic compare-and-set exists in all three backends (`store/store.py:7811-7828`, `sqlserver.py:9155-9177` with UPDLOCK/ROWLOCK, `postgres.py:6217-6231` with FOR UPDATE), declared at `store/base.py:1588`; and login-path single-use is pinned by `tests/test_mfa.py:139`. **The only thing missing is the call at the enrollment site.** Note also that `disable_totp` leaves `last_totp_step` untouched — that direction is conservative and must not be "fixed" by clearing it.

**Difficulty 4, and the cost is test collateral rather than code.** The production change is about three lines: switch `:1979` to `verify_totp_step`, keep the step, and require `consume_totp_step` before activating — consuming **before** `enable_totp`/`mark_session_mfa_verified`/minting recovery codes, and treating a `False` as a failed confirm on the existing `auth.mfa_failed` phase=enroll branch. At least four tests confirm an enrollment then assert a live verify inside the same step and would go failing or intermittently failing: `tests/test_mfa.py:81-94`, `:147-157` (sharpest — it reuses the same code object), `:272-281`, and `tests/test_step_up.py:314-318`. The obvious remedy does not work: `tests/_totp_clock.py`'s `fresh_totp` guarantees headroom **within** the current step and cannot advance one, so each affected test needs restructuring rather than a CI sleep across a 30-second boundary.

**Both operator surfaces reach this through the one service method** — `POST /me/mfa/confirm` (`api/auth_routes.py:403-427`) and `POST /ui/account/mfa/verify` (`messagefoundry_webconsole/routes/account.py:239-272`) — so fixing the service method fixes both and no route change is needed.

**Open question, not a blocker:** whether any security document states TOTP single-use in terms broad enough to be made inaccurate by this gap. `docs/BACKLOG.md:698` describes the per-user compare-and-set and is true as written. The vault scorecard was not readable from this checkout, so if 6.5.1 is scored fully met there, that cell needs re-validating against the code rather than being assumed still correct.

**Source:** found during the ASVS V6 re-verification, 2026-08-04, and adversarially re-verified against the code at `6e481c14` before filing. Confirmed as stated.

## 1017. worktree_gate rule 3d has no ownership signal, so it denies a session removing a worktree it created itself

> 🔢 **Filed 2026-08-04 — not started.** Value **6/10** · Difficulty **5/10** · _quick win_. Rule 3d denies on three conditions — a git token, a `worktree remove|move` match, and a target resolving under a governed root — and consults nothing about who owns the target. Ownership is instead **inferred** from a premise in the rule's own header: git refuses to remove the tree you are standing in, "so a `worktree remove` that reaches git is, by construction, aimed at somebody else's". That inference is invalid: not-the-tree-I-stand-in does not imply not-mine.

**Cluster:** Developer tooling / session-drift controls. **Priority:** P3. **Verdict:** build. **Severity:** developer-tooling correctness with no product surface — the rule is in a PreToolUse hook, not the engine, so nothing reaches a shipped artifact and there is no PHI or security dimension. Unlike most items here it is **not conditional**: the gate is armed and its own receipt log records the false positive.

**Measured, not inferred.** The gate's receipt log records **4 rule=3d denies, and 4 of 4 came from a session standing in its own `.claude/worktrees/<slug>` checkout** — never from the primary. Two of those slugs still own orphaned scratchpad worktrees visible in `git worktree list` today. The deny text asserts as fact that the target "belongs to ANOTHER SESSION" (`scripts/hooks/worktree_gate.ps1:535`), which in the self-created case is false.

**The fault is the rule, not a faulty identification routine.** There is nothing to repair in identification because none is attempted: grepping the 3d block (`:508-549`) for `cwd` returns zero hits, and the file never reads `session_id` or `transcript_path` from the hook payload. The session's own cwd enters the 3d path only as a field in the receipt line. Note also that `worktree add` is **not** in the matched verb pair (`:510`), so creating the tree was never gated — only tearing it down is.

**Why it bites rather than merely annoys.** The remediation the deny offers (`:543`, `prune-merged.ps1`) provably cannot act on that class: `prune-merged` requires a `<primary>-` sibling prefix and its own contract says it "NEVER touches ... the `.claude/worktrees` Claude-managed worktrees, the Temp scratchpad worktrees" (`scripts/worktree/prune-merged.ps1:123-124`), while `remove.ps1` addresses only `<parent>/<repo>-<Name>` (`:30`). `docs/SESSION-DRIFT-CONTROLS.md` G11 already records the underlying gap — "nested worktrees still have no scripted removal" — so for the nested and scratchpad layouts raw `git worktree remove` is the only route, and it is the route 3d denies. G11 does **not** record this false positive, so this is a new item rather than a duplicate.

**Secondary prose error in the same block, worth fixing in the same pass.** `:537` says "Removing it deletes that session's working tree and its branch". `git worktree remove` does not delete a branch — `remove.ps1` needs a separate `git branch -D` behind `-DeleteBranch` (`:43-49`). The block also covers `move`, for which "Removing it deletes" is the wrong verb entirely.

**Why value 6.** A confirmed, measured false positive on a control whose entire efficacy rests on its deny text being believed — and the project's own G10 entry makes that erosion the stated reason false positives matter. Held below 7 because it is Claude-process tooling rather than shipped engine code, the fallbacks (a plain terminal, or asking the owner) still work, and for the sibling layout the scripted tools remain usable, so nothing is permanently wedged.

**Difficulty 5.** The fail-open paths for a non-worktree, nonexistent or ungoverned target already exist and must not be disturbed. The work is deciding what an ownership signal actually is — the payload carries no reliable session identity, so a fix likely means recording creation provenance at `worktree add` time and reading it at removal, which is a new mechanism rather than a new condition.

**Related:** #1019 (the same estate's missing payload-parity instrument), #340. This file family is slated to move to a separate public repo, which is context for sequencing, not a reason to leave the rule wrong.

**Source:** found while auditing the worktree gate, 2026-08-04, and adversarially re-verified against the code and the live receipt log at `6e481c14`. Confirmed as stated, including the "while standing elsewhere" half — standing elsewhere is what makes the command reach git at all.

## 1020. The first-run bootstrap Administrator is created with no email address, and the PHI notification gate cannot see it

> 🔢 **Filed 2026-08-04 — not started.** Value **5/10** · Difficulty **3/10** · _fill-in_. `_ensure_bootstrap_admin` calls `create_user` with no `email=`, so the account holding `frozenset(Permission)` has a NULL email and `SecurityEventNotifier.notify`'s `if not event.email: return` makes all ten notice types no-op for it. The PHI startup gate that refuses to serve without a notification channel computes readiness from the SMTP transport alone, so it would report a healthy channel while no notice about the all-permission account could be delivered.

**Cluster:** Security / authentication. **Priority:** P2. **Verdict:** build (small). **Severity:** on first deployment all ten out-of-band notices about the most privileged account would silently no-op, including lockout and success-after-failures. No present-tense exposure is claimed — this is wrong in the shipped code, with zero running instances.

⚠️ **The allocated title's second half is REFUTED and the body must say so, or a fixer will hunt for a missing unlock guard that is not missing.** The title read "and there is no administrative unlock path". Three independent paths exist, none involving email: lockout is **time-bounded** (`locked_until = now + lockout_minutes * 60`, `auth/service.py:755-759`, default 15 at `config/settings.py:1769`, enforced only while `now < locked_until` at `:659`); `POST /users/{id}/reset-password` clears `failed_attempts`/`locked_until` through `set_password` (`store/store.py:7693`); and the documented break-glass is the sealed `bootstrap-admin.txt` file (`api/app.py:5104-5146`, `docs/SECURITY.md:1750-1751`). Decisively: **there is no email-driven reset, unlock or recovery flow anywhere in the shipped code** — the notice body carries no link or token and ends "contact your MessageFoundry administrator" (`pipeline/security_notify.py:72-91`) — so the absent address removed no unlock path.

**What is actually wrong.** `_ensure_bootstrap_admin` (`auth/service.py:522-547`) passes `user_id`, `username`, `auth_provider`, `display_name`, `password_hash`, `must_change_password` and no `email=`; every backend defaults `email: str | None = None` and inserts it (`store/store.py:7626-7644`, `postgres.py:6083-6100`, `sqlserver.py:9011-9028`). Nothing later fills it: the forced change-password flow collects passwords only (`messagefoundry_webconsole/pages/account.py:644`) and there is no self-service email route. `_notify_security` is called at 16 sites and always passes `email=user.email`, so all ten event types drop — the one that matters most being `LOGIN_AFTER_FAILURES` (`auth/service.py:725-734`), the classic "someone guessed it" signal.

**The gate-blindness angle is the part with teeth.** On a PHI instance under `enforcement=enforce`, `serve` refuses to start without a security-notification channel (`__main__.py:2259-2280`), but `security_channel_ready` is computed purely from `notify_security_events` + `email_smtp_host` + `email_from`. At the moment that gate passes on a first run, the only account that exists has no address — so the gate proves the transport exists, not that any notice is deliverable.

⛔ **Do not write that the notices are lost, and do not rebuild these.** The email push is dropped; every event is also an audit row surfaced by `GET /me/security-events` (`api/auth_routes.py:453`, `auth/service.py:2458`), which `auth/notifications.py:15-17` documents as the companion "so a user with no deliverable mailbox can still review their security history". Also already present: last-admin guards on disable/delete/role-removal (`api/auth_routes.py:681-688`, `:714-715`, `:746-749`), and a settable address on any account (`PATCH /users/{id}` at `:696`, console form at `messagefoundry_webconsole/pages/admin.py:171`).

**Scope the fix wider than `admin`.** `email` is optional in `UserCreateRequest` (`api/auth_models.py:86`) and is not required for the Administrator role, so any hand-created privileged account has the same hole. A fix that hardcodes an address for the bootstrap account only would leave that open.

**Difficulty 3, no schema change, no migration cost.** Candidate fixes are each a handful of lines plus a test: warn at `_emit_bootstrap_admin` or on the forced change-password page; extend the `__main__.py:2259` gate to require a deliverable address on at least one enabled Administrator when notifications are required; or add a self-service email field. Which one the owner wants is the only judgment needed — `auth/notifications.py:55` and `security_notify.py:128-131` explicitly contemplate "no mailbox on file", so "warn/gate for privileged accounts" may be preferable to "require an email".

**Mentioned, deliberately not folded in:** a *sole* claimed Administrator that loses its password genuinely has no reset path, because reset needs a second `users:manage` holder and there is no `users` CLI subcommand. That is independent of email and would be unchanged by adding one. The AD/OIDC-provisioned path in `auth/reconcile.py` was not audited, so the finding may narrow to local accounts.

**Source:** found during the ASVS V6 re-verification, 2026-08-04. The conclusion is correct and the mechanism was **misstated**: the unlock-path half is false and is corrected above, verified against the code at `6e481c14`.

## 1022. disable_mfa has no last-factor guard where delete_webauthn_credential does, so the two removal paths can be ordered to reach zero factors

> 🔢 **Filed 2026-08-04 — not started.** Value **5/10** · Difficulty **4/10** · _fill-in_. `delete_webauthn_credential` computes `last_second_factor` and refuses when MFA is required; `disable_mfa` has no equivalent test at all. A user with TOTP plus one passkey can delete the passkey (permitted, because `totp_enabled` is still True) and then disable TOTP (permitted, no guard), arriving at zero enrolled factors — the state ADR 0068 AC-10 says the system shall refuse.

**Cluster:** Security / authentication policy consistency. **Priority:** P2. **Verdict:** build (small). **Severity:** low, and confined to policy consistency plus a documentation guarantee — **not an MFA bypass**.

⚠️ **Lead with the correction: MFA enforcement at login is NOT missing and must not be touched.** The obvious reading of the title sends a fixer at enforcement that already exists. Disabling TOTP under `require_mfa` would not leave the account reachable with a single factor: `login` resolves `mfa_required` and issues the session with `mfa_verified=not mfa_required` (`auth/service.py:715-718`), and `require()` applies the second factor as an ASVS 6.3.3 **access** gate, 403ing every request whose (method, path) is not one of the six exempt pairs (`api/security.py:189-234`, `:79-88`). So the post-disable state is a **forced re-enrollment** — recoverable, because the enroll routes ride `require_reauth_only*` with `mfa_gate=False` (`api/security.py:586-589`) — not a factor downgrade and not a lockout.

**The defect that survives.** The invariant is defeated by ordering. `disable_mfa` (`auth/service.py:2083-2099`) does nothing between `get_user` at `:2086` and `disable_totp` at `:2087` — it consults neither `has_webauthn_credentials` nor `_mfa_required_for`. It is the single enforcement point: both `api/auth_routes.py:438` and `messagefoundry_webconsole/routes/account.py:281` reach it unguarded.

⚠️ **CORRECTED 2026-08-04, and the correction narrows the doc half of this item.** This body originally cited `docs/SECURITY.md:752` as stating the refusal "as an unconditional property of the system". **That citation was wrong.** Line 752 sits inside a WebAuthn paragraph, describes *passkey* removal, and quotes the passkey guard's own error string ("enroll another factor first") — the path where the guard genuinely **does** exist. It is defensible as written. The false claim was one line in a **route table**: `docs/SECURITY.md:329`, the row for `DELETE /me/mfa`, which asserted "refused when it would remove the last factor while MFA is required". That route resolves to `disable_my_mfa` (`api/auth_routes.py:429`) whose own docstring says "turn off the caller's **TOTP** MFA", and there is **no WebAuthn credential DELETE route in `api/` at all** — passkey removal is console-only. `:329` has been corrected to state the absence and point here; the remaining doc obligation for this item is **ADR 0068 line 140**, not a `SECURITY.md` line.

**This is a promised follow-up that was never filed, which is the main reason to file it rather than close it.** ADR 0068 line 140 records "TOTP-disable keeps its existing behavior this lane (parity follow-up recorded)" — and no backlog item carries that follow-up. Searches for `disable_mfa`, "TOTP-disable", "parity follow-up" and "last factor" across `docs/BACKLOG.md` and the closed archive return zero hits. So the asymmetry is a recorded decision, not an oversight.

**Guard shape, so it is not written as a TOTP-only check.** It must consult `has_webauthn_credentials` — a user who keeps a passkey is still enrolled and must stay allowed to drop TOTP — and gate on `_mfa_required_for(user, identity.roles, second_factor_enrolled=False)`, mirroring `auth/service.py:2426-2432`. `disable_mfa` already receives an `Identity`, so `identity.roles` is available without an extra store read.

**Difficulty 4 because the change is not local.** The guard is about six lines, but the raise must be mapped at two call sites that today have no `ValueError` handling and would 500: `api/auth_routes.py:438` (follow the confirm pattern at `:423-424`) and `messagefoundry_webconsole/routes/account.py:281` (follow `ui_webauthn_delete` at `:439-446`). One existing test **breaks by construction**: `tests/test_mfa.py:189` disables TOTP on the bootstrap admin under defaults with no passkey enrolled — its failure is the expected consequence of the fix, not a regression, and it needs a second factor enrolled first or an explicitly relaxed setting. Add a positive test mirroring `tests/test_webauthn.py::test_last_factor_delete_refused_while_required`. Two docs move in the same change: ADR 0068 line 140 becomes wrong once parity lands, and `docs/SECURITY.md:752` becomes true rather than aspirational.

⛔ **Already handled — do not rebuild.** `admin_reset_mfa` already clears TOTP and every passkey and revokes sessions (`auth/service.py:2101-2127`), so lost-authenticator recovery is complete; and `require_step_up_action` re-checks `mfa_satisfied` (`api/security.py:638-648`) so `DELETE /me/mfa` cannot be reached by a half-authenticated session.

**Open question for the owner:** whether to add parity, or to ratify ADR 0068's "existing behavior" as the settled end state. If the guard is added, whether it keys on `_mfa_required_for` as the passkey path does — which means a voluntarily-enrolled user under `require_mfa_scope=administrators` can still turn their own TOTP off — or on a stricter "any enrolled user keeps one factor" rule, which would reintroduce the asymmetry in the other direction.

**Adjacent, deliberately out of scope:** `disable_mfa` does not check `user is not None` or that `auth_provider` is LOCAL, unlike `begin_mfa_enrollment` (`auth/service.py:1952-1956`), and unlike `admin_reset_mfa` it does not revoke the user's other sessions. Context only; neither is this item's claim.

**Source:** found during the ASVS V6 re-verification, 2026-08-04. Structurally confirmed; the **consequence was overstated** and is corrected above, verified against the code at `6e481c14`.

## 1019. install-selfheal.ps1 has no installed-vs-source payload-parity instrument, and it wires the most privileged hook in the estate

> 🚧 **PARTLY LANDED 2026-08-04 — the instrument exists now; the installer-side half is deliberately NOT built.** Value **5/10** · Difficulty **3/10** · _fill-in_. **Shipped:** `tests/test_selfheal_installed_parity.py` asserts the installed backstop payload at `~/.claude-hooks/worktree-selfheal.ps1` matches the committed source, folding CRLF on bytes exactly as `Get-GateHash` and `content_hash` do, with a negative control proving the folded comparison still detects a one-character change. **Deliberately not built:** `-Status`, a version stamp, and a hash at the `Copy-Item`. Adding `-Status` would have meant narrowing the `CLAUDECODE` refusal so a session could run it, which is weakening a security control on a broad task bundle that never named it — a sub-agent proposing exactly that was correctly blocked. It is also unnecessary: `install-gate.ps1 -Status` refuses in-session too, so **plain-terminal-only is the precedent, not a gap**, and the observability is delivered from the pytest side, which needs no privilege. `install-selfheal.ps1` is byte-unchanged (verified). **Item stays OPEN** for the installer-side readout, if it is ever wanted. ⚠️ Do not read this as closed. Filed 2026-08-04. The installer lays down a copy of `worktree-selfheal.ps1` at `~/.claude-hooks/` and wires it as a user-scope SessionStart hook, with no way to detect that the copy and the checkout have diverged: no `-Status`, no version stamp, no hash at the `Copy-Item`, and no test that reads the installed copy.

**Cluster:** Developer tooling / session-drift controls. **Priority:** P3. **Verdict:** build (small). **Severity:** developer-box tooling integrity, not product or PHI, and nothing here touches a deployment.

⚠️ **The allocated title overstates in two ways, and both matter.** It read "no parity instrument at all" — the same overclaim as an earlier "no instrument of ANY kind" that had to be narrowed. **A parity instrument covering this installer does exist:** `tests/test_worktree_selfheal_wiring.py::test_both_installers_carry_the_same_refusal` compares `install-gate.ps1` and `install-selfheal.ps1` source text, its docstring noting "the asymmetry existed for months precisely because nothing compared them". That is **source-level guard parity**. What is absent is **installed-vs-source payload parity**. Second, the comparator in the claim is wrong: it named `scripts/coord/install-git-hooks.ps1`, which installs copies (`claim_check.py`, `push_guard.py`) of its own. The instrument to mirror is `install-gate.ps1 -Status` (`Get-GateHash`/`Get-GateVersion`, "parity : IN SYNC" versus "*** STALE ***") plus `tests/test_gate_installed_parity.py`.

⚠️ **AMENDED, and it SHARPENS the item.** The verification behind this body was performed at `6e481c14`, where `install-git-hooks.ps1` had no payload parity either — so the original wording put the asymmetry against `install-gate.ps1` alone. **PR #191 then landed payload parity on `install-git-hooks.ps1`**: SHA256 content hashing, an explicit PAYLOAD-parity section, IN SYNC / STALE reporting, and `tests/test_installed_coord_hooks.py` asserting the same property from the pytest side on the same folded-comparison basis. So the correct statement is now stronger and simpler: **`install-selfheal.ps1` is the ONLY installer in the estate with no payload-parity instrument**, and two worked examples exist to copy rather than one. Nothing else here is affected — #191 did not touch `install-selfheal.ps1`, whose parameter surface is still `-ConfigDir` plus `-HookPath`, and it added no selfheal reference to either parity test.

**Where the file is:** `scripts/worktree/install-selfheal.ps1`, **not** `scripts/coord/`. A fixer sent to `scripts/coord/` finds `install-git-hooks.ps1`, `install-coordination.ps1` and no selfheal installer.

**What is missing, precisely, all four:** no `-Status` (the parameter surface is `-ConfigDir` plus `-HookPath`, `:23-30`); no version stamp in `worktree-selfheal.ps1`; no hash or comparison at the payload install (`:57`, a bare `Copy-Item -Force`); and no test that reads the installed copy — every test in `tests/test_worktree_selfheal_wiring.py` binds `ROOT` and uses synthetic `tmp_path` homes. The repo's only installed-vs-source parity test names the gate copy only (`tests/test_gate_installed_parity.py:44`). The installer's one detection is a regex for the **wiring's** presence in one config dir (`:85`), which says nothing about the payload the wiring points at.

**"More privileged" is substantiated on two axes.** Scope: user-scope `settings.json` in a Claude config dir, machine-global across every repo and session, versus a repo-scoped `.git/hooks`. Action: the hook it wires **mutates a working tree unattended** — `git -C $root checkout $homeBranch` at every session start (`scripts/worktree/worktree-selfheal.ps1:106`) — whereas the claim gate and push guard only refuse. The installer's own refusal text says as much.

⛔ **Already present — do not re-report as absent.** The `CLAUDECODE` refusal (`:39-41`, with the parameter default deliberately removed at `:24-31` so binding cannot preempt it), pinned twice; backup then write then validate JSON then roll back (`:104-118`); the wiring-presence idempotency scan (`:83-90`); and an unconditional payload refresh on every run (`:57`) — so "the installed copy can never be updated" is **not** the defect. `docs/SESSION-DRIFT-CONTROLS.md` G8's "the higher-privilege installer was the LESS PROTECTED one" describes a **closed** defect; restating it in the present tense would be false. Also out of scope: `install-git-hooks.ps1` has no `CLAUDECODE` guard at all — do not "harmonize" the pair in the direction the title implies.

**Measured, so this is not read as an incident:** on 2026-08-04 the installed copy and the committed source agree — content hash CRLF-folded `c41c70ecf885`, 10,050 bytes, both sides. Nothing has drifted; nothing would notice if it did.

**Difficulty 3, with four constraints a fixer would otherwise get wrong.** Fold CRLF on **bytes** exactly as `Get-GateHash` and `content_hash` do — a byte-exact hash made every Windows checkout read STALE on 2026-08-04 and prescribed a re-install that would have downgraded a machine-global file. Assert parity only when the source is committed, since mid-edit the copies are supposed to differ. Print what was scanned **before** any skip, because pytest here runs without `-rs`. Never mutate the installed copy in a test — live sessions read it — so exercise the predicate directly and include a negative control proving the folded comparison still detects a one-character change. And note that `install-selfheal.ps1` takes one mandatory `-ConfigDir` per run while `install-gate.ps1` defaults to all of them, which is why the estate doc records the backstop as present in 4 of 5 dirs.

**Not established, and distinct from this item:** whether every Claude config dir currently carries the selfheal SessionStart entry. That is a **wiring**-coverage gap, separate from the payload-parity gap here; if both are wanted, say so rather than letting a fixer fold them together. `docs/SESSION-DRIFT-CONTROLS.md:169` scopes the parity row to the gate only, so there is no false compensating-control claim to correct — the gap is unrecorded, not misrecorded.

**Related:** #1017 (the same estate, a different failure class).

**Source:** found while auditing the session-drift installers, 2026-08-04, and adversarially re-verified at `6e481c14`. Confirmed with the title narrowed as above.

## 1018. The raw-text gate-rule scan exists in three independent copies with nothing tying them together

> 🔢 **Filed 2026-08-04 — not started.** Value **4/10** · Difficulty **3/10** · _fill-in_. Two regexes that read a gate script as text and extract every tool it dispatches on are implemented three times — twice in Python, once in PowerShell — and no test compares any two of them. They agree today; the defect is a synchronised-edit hazard whose failure direction is a false green in the machinery built to stop rules shipping dead.

**Cluster:** Testing / developer tooling. **Priority:** P3. **Verdict:** build (small). **Severity:** no engine impact and none on first deployment; every file involved is developer session-drift tooling.

⚠️ **There are THREE copies, not two — state the count so nobody consolidates two and closes the item.** `tests/test_install_gate_wiring.py:29-39` (`TOOL_BRANCH`/`QUOTED` plus `tools_the_gate_handles()`), `tests/test_gate_installed_parity.py:55-56` and `:110-114` (`handled_tools(text)`), and `scripts/worktree/install-gate.ps1:171-179` (`Get-HandledTools`, the same two pattern strings transcribed into PowerShell).

**They compute the same quantity, not merely lookalikes.** Copy 2 is applied to the same file as copy 1 at `tests/test_gate_installed_parity.py:336`. All three return the identical 10 names against the source gate (Agent, Bash, Edit, EnterWorktree, MultiEdit, NotebookEdit, PowerShell, Task, Workflow, Write), and the two Python pattern strings compare equal.

⛔ **Do not write that the copies currently disagree — they do not.** The divergence was demonstrated rather than asserted: change `"([^"]+)"` to `["\']([^"\']+)["\']` in **one** copy — the obvious one-token fix if a rule is ever written `$tool -in @('Foo')`, which PowerShell treats identically at runtime — and that copy returns a different set from the others on the same gate text (symmetric difference `['MFNewRule']`). Word it as a synchronised-edit hazard.

**Name the failure direction, because it is what gives the item its value.** If copy 2 under-matches, `required = handled - OPT_IN_TOOLS` (`tests/test_gate_installed_parity.py:320`) shrinks and `test_every_non_optional_rule_is_wired_in_every_config_dir` **passes having checked less**. If copy 3 under-matches, `-Status` prints no UNWIRED line and reads as a clean audit. Both are false greens in files written precisely because a rule once shipped dead while 85 tests stayed green.

**A shared Python helper cannot absorb the third copy.** `install-gate.ps1` is PowerShell. The honest end state is one helper (`tests/_gate_rule_scan.py`, following the existing `tests/_workflow_contexts.py` convention) **plus** a test asserting `Get-HandledTools` agrees with it on `scripts/hooks/worktree_gate.ps1`. Without that second half the item is half done and reads as done.

⛔ **Do not add a pin that exists.** `tests/test_install_gate_wiring.py:78-91` already pins copy 1's output to a 10-name literal, and `tests/test_gate_installed_parity.py:333-338` already asserts copy 2 sees `EnterWorktree`. Say what neither does: the pin guards **regression**, not a new rule in an unmatched form — appending `if ($tool -in @('MFNewRule'))` to the gate leaves the assertion passing — and nothing anywhere compares any two of the three copies.

**Fix the second triplication in the same pass:** the opt-in exemption is stated three times too, at `tests/test_gate_installed_parity.py:53`, `tests/test_install_gate_wiring.py:139` and `scripts/worktree/install-gate.ps1:243`, also with no cross-check.

**The coupling this item is really about** is visible in the gate's own source: `scripts/hooks/worktree_gate.ps1:272` says the rule was "Expressed as `$tool -in @(\"EnterWorktree\")` so tests/test_install_gate_wiring.py SEES this tool as handled". The gate was contorted into the one syntax the scan recognises.

**Difficulty 3.** The Python half is a mechanical move plus two call-site changes. The remaining cost is the cross-language pin — a `pwsh` subprocess with a skip where `pwsh` is absent, which by this project's standard needs the announce-before-skip treatment `tests/test_gate_installed_parity.py` already uses — plus deciding whether the helper also owns `OPT_IN_TOOLS`.

**Open, and possibly its own item:** the scan misses `$tool -eq "X"`, `switch ($tool)`, `$tool -in $SomeVariable` and single-quoted names, all valid PowerShell that would run and be invisible to all three copies. Consolidating gives that blind spot one address to fix; it does not fix it.

**Related:** #1017, #1019 (the same estate).

**Source:** found while auditing the gate wiring tests, 2026-08-04, and adversarially re-verified at `6e481c14`. Confirmed, with the copy count corrected from two to three. **Anchors into `tests/test_gate_installed_parity.py` were re-derived BY CONTENT at `17374679`** after PR #191 edited that file and displaced four of them (`handled_tools` `:105` to `:110`, the `required` line `:277` to `:320`, the source-gate call `:293` to `:336`, the opt-in test `:290` to `:333`).

## 1024. install-gate.ps1's config-dir glob is over-wide AND it is the WRITER that manufactured the wiring the reader validated against

> 🔢 **Filed 2026-08-04 — not started.** Value **4/10** · Difficulty **3/10** · _fill-in_. The installer discovers config dirs with an **unanchored** glob, so it wires any directory whose name merely begins with `.claude-account-`. It is the **writer** that put gate wiring into `~/.claude-account-2.lock`, which the Python reader then read back as evidence that wiring was correct — both globs wrong the same way, so they agreed.

**Cluster:** Developer tooling / session-drift controls. **Priority:** P3. **Verdict:** build (small). **Severity:** developer-tooling correctness, no product surface and no deployment effect. Extra wiring in a stale directory is **fail-safe**, not fail-open.

**Measured, 2026-08-04, not inferred.** `scripts/worktree/install-gate.ps1:91` reads
`Get-ChildItem -LiteralPath $HomeDir -Directory -Filter ".claude-account-*"`. `~/.claude-account-2.lock`
**is a directory** (mode `drwxr-xr-x`, created 2026-07-29 13:32), so `-Directory` does not exclude it and
the unanchored filter matches it. Its `settings.json` carries `worktree_gate.ps1` wiring. Nothing else
writes that file, so the installer put it there — and will put it back on every run.

⭐ **Why this is the interesting half, and not a duplicate of the reader fix.** The reader
(`tests/test_gate_installed_parity.py`) used the *same* unanchored glob, so it validated wiring against a
file **its own subject had manufactured**. The two agreed not because the wiring was right but because
both globs were wrong identically. A validator whose input is derived from its subject is satisfied by
construction — [ADR 0158](adr/0158-silent-controls-green-signals-that-mean-nothing-and-shape-over-detection.md)
names that class, and this is a clean instance of it.

**What #199 did and did not do.** It anchored the reader
(`_ACCOUNT_DIR_NAME = re.compile(r"\A\.claude-account-\d+\Z")`, with the reasoning recorded in the
module: unanchored, `.match()` accepts `.claude-account-2.lock` on its prefix). It **deliberately did not
touch the writer.** So the circular evidence is broken — the reader no longer confirms the installer's own
output — but the installer keeps re-creating the discrepancy the reader now correctly rejects.

**Proposed fix.** Anchor the writer's discovery the same way the reader is anchored, so a name is an
account only when it is `.claude-account-` followed by digits and nothing else. Do **not** widen the
reader to match the writer; that is the direction that restores the circularity.

⛔ **A session must not execute this installer to verify the change.** It writes user-scope wiring into
every Claude config dir on the box, machine-global across repos and sessions. Verify by inspection plus a
test that exercises the discovery predicate directly — the pattern
`tests/test_gate_installed_parity.py` already uses. The session that fixed the reader stated it could not
verify a writer change for exactly this reason, which is why the writer half was handed over rather than
attempted.

**Adjacent, and NOT this item:** `~/.claude-account-4` is a live launcher with **no `settings.json` at
all**, so no PreToolUse wiring and no gate — confirmed independently 2026-08-04. That is an owner
decision about whether every launcher profile should be wired, not a glob defect, and it is reported by
the scanning tests rather than asserted.

**Related:** #1018 (three copies of the rule scan), #1019 (the selfheal payload-parity instrument), ADR 0158.

**Source:** found by the gate-parity session while anchoring the reader, 2026-08-04, and handed over
because filing needs `alloc.ps1` plus a ranked-table row. Every claim above was re-verified against the
box and the code at `a26db133` before filing — including that the `.lock` path is a directory rather than
a file, which is the fact the whole finding rests on.

## 1026. The ASVS 12.1.1 TLS-floor probe silently does not run with the console off, and its own comment names three of its four conditions

> 🔢 **Filed 2026-08-05 — not started.** Value **6/10** · Difficulty **3/10** · _quick win_. The probe's gate requires **four** conditions; the comment directly above it names **three** and asserts that "every other posture never reaches here". The undocumented fourth is `public_origin` — and `public_origin` is only *mandatory* when `serve_ui` is also on. So with the console **off**, a PHI instance behind a declared terminator under `enforce` can start with it unset and the probe never runs.

**Cluster:** Security / startup gates, ASVS 12.1.1. **Priority:** P2. **Verdict:** build (small). **Severity:** would leave an ASVS 12.1.1 control silently inert in a legitimate deployment posture on first deployment — the TLS floor of the terminator in front of a PHI API would go unmeasured, with nothing reporting the skip.

**The gate, measured at `e0482aea`.** `messagefoundry/__main__.py` runs the probe under:

```
settings.api.tls_terminated_upstream and data_class is DataClass.PHI and enforcing and settings.api.public_origin
```

The comment immediately above says *"Scope is deliberately the posture the requirement is about: a declared terminator, PHI, and `enforce`. Every other posture never reaches here and is byte-identical."* That names three of the four and characterises the remainder as out-of-scope postures — so a reader concludes the probe runs whenever a PHI instance sits behind a declared terminator under `enforce`. It does not.

**Why the fourth condition is not self-satisfying.** There *is* a refusal for an unset `public_origin`, but it is gated on the console: `if settings.api.serve_ui and settings.api.tls_terminated_upstream:` then `if not settings.api.public_origin: ... return 2`. **With `serve_ui` false, nothing requires `public_origin`**, it keeps its `None` default (`config/settings.py:693`), and the probe's fourth condition is false. The API is still bound off-loopback behind a terminator carrying PHI, so the requirement the probe exists for still applies — only the probe does not.

⭐ **The sharpest part, because the file already knows better.** That same block **`return 2`s** when the probe's *mechanism* is unavailable, with the explicit reason that *"a check that degrades to a no-op when its mechanism disappears reports success forever afterwards"*. It refuses a silent no-op one level down and performs one, silently, one level up. Same defect class as [ADR 0158](adr/0158-silent-controls-green-signals-that-mean-nothing-and-shape-over-detection.md).

**Difficulty 3, and the design choice is the work, not the code.** Three candidate ends, and they are not equivalent: (a) require `public_origin` in the declared-terminator PHI posture regardless of `serve_ui` — closes it but adds a refusal to a posture that starts today; (b) keep the gate and make the skip **loud** (an advisory naming `public_origin` as the reason) — no new refusal, but a warning nobody reads is the weaker control; (c) correct only the comment — honest, and leaves the control inert. Owner call. The comment fix is a line either way and must not be mistaken for the item.

⚠️ **Correcting the report this came from.** The originating analysis said the console "auto-degrades" so `public_origin` stays unset. That is **not** the mechanism — `public_origin` is an independent optional setting and `serve_web_console` maps to `api.serve_ui`; neither derives the other. The real link is that the *requirement* for `public_origin` is itself gated on `serve_ui`. The conclusion held; the mechanism did not, and filing the reported version would have sent a fixer looking for a degradation path that does not exist.

**Related:** #1004 (the other ASVS cell whose control is weaker than its record), ADR 0158.

**Source:** raised as RANK 1 by the vault drift-repair pass, 2026-08-04; mechanism re-derived and corrected against the code at `e0482aea` before filing. Held back from an earlier ledger pass precisely because the reported mechanism was unverified.

## 1025. Three `require_ui_step_up` routes emit PHI with no `phi=`, so they charge no per-actor read budget

> 🔢 **Filed 2026-08-05 — not started.** Value **5/10** · Difficulty **2/10** · _fill-in_. `GET /ui/messages/search`, `/ui/messages/search/layered` and `/ui/uploaded-logs/file/{file_id}` put PHI on the wire through `require_ui_step_up` without `phi=`, so `require_ui`'s `allow_phi_read` throttle never runs for them. **A missing rate limit, not a missing authorization check** — all three still gate on the right permission.

**Cluster:** Security / PHI anti-automation. **Priority:** P2. **Verdict:** build (small). **Severity:** would leave three PHI-emitting console routes outside the per-actor read budget on first deployment, so an authorised-but-abusive actor could enumerate through them without hitting the 429 the sibling browse routes enforce. No unauthorised access.

**Mechanism, verified at `e0482aea`.** `require_ui` declares `phi: bool = False` and throttles at `messagefoundry_webconsole/_auth.py:260` with `if phi and not auth.allow_phi_read(identity.user_id):`. `require_ui_step_up` builds its base as `require_ui(*permissions, allow_mfa_pending=True)`; unless `phi=` is passed through, the arm is unreachable. The three routes above pass nothing — `GET /ui/messages/search` is on `require_ui_step_up(Permission.MESSAGES_READ)`.

**The plumbing already exists, so this is three call sites and tests.** #324 threaded `phi=` into `require_ui_step_up` (`_auth.py:498`, whose docstring records that `phi=True` "forwards to `require_ui`'s `phi` arm ... the same throttle the plain `require_ui(..., phi=True)` browse routes and the JSON `require_phi_read` routes charge") and used it on the edit route (`routes/core.py:612`). **Difficulty 2 is that inheritance** — before #324 this would have been the plumbing plus the call sites.

**Copy the siblings that already do it right:** `routes/core.py:473`, `:483`, `:501`, each `require_ui(Permission.MESSAGES_VIEW_RAW, phi=True)`.

**Related:** #324 (built the seam and the two edit routes; closed), #1027.

**Source:** reported by the #324 lane rather than fixed in it, per the owner's settle that the lane thread `phi=` for its own route only and report the rest. Mechanism re-verified independently before filing.

## 1027. The documented `pytest` command silently excludes the webconsole package, so a local green is not evidence about ~344 tests

> 🔢 **Filed 2026-08-05 — not started.** Value **5/10** · Difficulty **3/10** · _fill-in_. `testpaths = ["tests"]` means the command CLAUDE.md documents as the verification gate never collects `packaging/messagefoundry-webconsole/tests`. A **failing** webconsole test sat on `main` through a full day of lanes because every quartet used the documented single path.

**Cluster:** Testing / verification integrity. **Priority:** P3. **Verdict:** build (small). **Severity:** no product effect; the defect is that the project's own verification instruction produces a green that is not evidence about roughly 344 tests, and CLAUDE.md §5 states a task is not done until it passes.

**It is the documented command, which is what makes it more than a config default.** `CLAUDE.md:333` gives `QT_QPA_PLATFORM=offscreen pytest -q` as the way to run the suite, and `pyproject.toml`'s `[tool.pytest.ini_options]` sets `testpaths = ["tests"]`. Every session that followed the instruction measured a tree it believed was covered.

**The evidence, and it is not hypothetical.** On 2026-08-04 `packaging/messagefoundry-webconsole/tests/test_webui.py::test_webauthn_rp_fail_closed_legible` was failing on `main` all day and no lane saw it. It surfaced only when one lane named both paths explicitly because it was editing `messagefoundry_webconsole/` directly — `pytest tests packaging/messagefoundry-webconsole/tests` returned `1 failed, 10681 passed, 851 skipped`.

⚠️ **Not a CI gap — verified, not assumed.** CI runs `Web console tests (pytest)` as a separate required step and installs the extra the failing test needs (`.github/workflows/ci.yml:250` installs `-e ".[dev,harness,fhir,dicom,x12,xml,webauthn]" -e packaging/messagefoundry-webconsole`, and `:245` records that `[webauthn]` is there "so the passkey ceremony tests run real `verify_*` assertions"). So PRs have been merging on real coverage. **The gap is local only**, which is why it went unnoticed: nothing red ever reached anyone.

**Difficulty 3 because the naive fix reds every local run.** Adding the packaging path to `testpaths` makes that same `[webauthn]` failure the default local experience, since worktree venvs bootstrap a narrower extra set than CI. So the item is really "make local coverage honest", and the options interact: widen `testpaths` **and** make the webauthn tests skip-with-reason without the extra; or leave `testpaths` and correct `CLAUDE.md` to document both paths; or have the venv bootstrap install the extra. Whichever is chosen, ⛔ **a skip must announce itself** — this project's own standard is that a skip reading as a pass is the failure being fixed here, so do not trade a silent exclusion for a silent skip.

⭐ **The general shape, worth keeping when this is fixed.** *A citation nobody has broken yet and a citation nobody has noticed is broken look identical in a grep; only the change that breaks it can tell them apart.* The same is true of a test path: an excluded suite and a passing suite look identical in a green summary line. The fix is not to remember, it is to make the exclusion visible.

**Related:** #1018 (guards that go quiet), #344 (the two test steps sharing one budget), ADR 0158.

**Source:** found by the #324 lane on 2026-08-04 when it named both pytest paths for a webconsole-touching change; the CI-coverage half was flagged by that lane as an inference and verified against `ci.yml` before filing.

## 1029. `/simplify` shipped as a local skill with no entry in the quality-standards record, so the one review tool that edits the tree had no written placement or scope

> ✅ **SHIPPED 2026-08-05 — the documentation is the whole deliverable.** Value **3/10** · Difficulty **1/10** · _quick win_. `/simplify` is now recorded in [`docs/Code_Quality_Standards.md`](Code_Quality_Standards.md) §5.1 as a local, human-invoked **advisory** review that **applies** its fixes, ordered before the `ruff` / `mypy` / `pytest` quartet, with the justified-duplication carve-outs written down. A new §5.1, a scoping clause in §5's intro, a mapping row in §6, and a `Before you verify` heading in `CLAUDE.md` §5.

**Cluster:** Documentation / quality-control record. **Priority:** P3. **Verdict:** build (small). **Severity:** no product effect and no security effect. The gap was in the record: the quality-standards document enumerated five measurement gates and named no review tool that rewrites code, so the one ordering constraint that matters and the scope limits that already follow from earlier decisions were unwritten and uncitable.

**What the record now says.** §5.1 is a new subsection and the single home for the tool. §5's placement table is **unchanged at five rows** — an earlier draft added a sixth and was reverted, because a row declaring itself "not a gate" contradicted both that table's `Gate` column and the §5 heading, and forced the same caveat into three other places. §5's intro instead gains one scoping clause naming §5.1 as a review tool deliberately not among the five. §6's companion-mapping table lists it in the same local, human-invoked, advisory tier as `/code-review` and `/security-review`, with the one difference that separates them stated **once**: those two report findings a human arbitrates, this one applies edits.

**No status is claimed for it, and that is deliberate.** Every other entry in this document names a tracked artifact and a pull request. `/simplify` ships with Claude Code rather than with this project, so there is no `.claude/` entry, pin, or other artifact in the checkout to score — **Built** is therefore a claim the document explicitly declines to make, citing the Appendix A honesty taxonomy. §4.0's liveness rule does not reach it either, because there is no green check to trust.

**The ordering is a consequence of the report-versus-apply difference, not a convention.** A tool that applies fixes, run after the quartet, would mutate the tree the quartet had just certified. `CLAUDE.md` carries it as a `Before you verify` heading placed *ahead of* the verification-expectations list rather than inside it — it is a mandated pre-step, not a gate, and "a task isn't done until these pass" cannot govern something that emits no pass or fail.

**The carve-outs are the part most easily lost, and they are an open class.** §5.1 records **at least** these deliberately-justified duplications as out of scope: the SQL Server / Postgres store-backend parity that signal 9's clone detection already whitelists, and the `messagefoundry/anon/` package vendored to `tee/anon/` under [ADR 0030](adr/0030-anonymization-test-harness-tee.md), which signal 9 cannot see at all because its `jscpd` scan covers `messagefoundry/` only. The defensive branching tolerant HL7 parsing requires (`CLAUDE.md` §8) is recorded separately as a signal 11 *complexity* concern rather than a duplication one. Nothing the tool produces certifies quality (§4.1); the maintainer owns every applied edit under the *reject code you cannot explain* floor.

**Difficulty 1 because nothing was built.** The skill already existed and is unchanged; the deliverable is a subsection, a table row, a heading and a clause. It is filed closed rather than skipped so the placement decision has a number to cite.

**Related:** #1027 (the quartet this ordering sits in front of, and the same class of defect — a verification instruction that does not say what it actually covers), #1006 (an advisory gate from the same rubric), #1000 (gate liveness, the rule §5.1 explicitly records as not reaching a non-gate).

**Source:** filed alongside the documentation change itself, 2026-08-05, and rewritten before filing because the first draft described a structure that was subsequently reverted. Every claim above was read from the working tree at commit `17c52129` rather than recalled: §5.1 at line 221, the five-row gate table, the §6 row at line 242, `CLAUDE.md`'s heading at line 288, and both `Built` mentions confirmed to be negations. The same change removed all 41 status glyphs from that document (rubric v0.12) and marked its pull-request citations as `PR #N`, the bare form having already resolved to the wrong item for `#1020`.

## 1030. Non-cp1252 characters in source are gated one file at a time, so the class keeps recurring

> 🔢 **Filed 2026-08-05 — not started.** Value **6/10** · Difficulty **4/10** · _quick win_. At least two gates exist and each covers exactly one thing: `tests/test_cli.py:43-58` asserts one string (`messagefoundry --help`) is cp1252-encodable, and `tests/test_announce_hook.py:810` asserts one file (`scripts/hooks/announce-session.ps1`) is ASCII-only. Neither generalises, so a glyph reaching `print()` from any other script is caught only by a human reading the diff.

**Cluster:** Tooling / verification integrity. **Priority:** P3. **Verdict:** build (small). **Severity:** no product effect — the affected surfaces are `scripts/`, not the engine. The defect is that CLAUDE.md §11 states a correctness rule whose enforcement is per-file and hand-placed, so coverage decays between sweeps and each recurrence costs a fresh manual audit.

**The mechanism, measured — and the usual statement of it is wrong.** `sys.stdout` carries `errors='surrogateescape'`, **not** `'strict'` (Python 3.14.6 on this box, `PYTHONIOENCODING` unset, confirmed under `-I`). `surrogateescape` only round-trips lone surrogates in `DC80`-`DCFF`; every other unencodable codepoint still raises. `sys.stderr` carries `errors='backslashreplace'`, which never raises. That asymmetry — not a strict/non-strict split — is why the same text survives on stderr and aborts on stdout. Anyone building the gate should measure this rather than repeat the strict claim, which is stated in at least one commit message in this repo's history.

**Prior recurrences, and the fixes were per-surface.** `tests/test_cli.py:46-49` records the first: *"`messagefoundry --help` crashed with UnicodeEncodeError on a cp1252/charmap console because of a U+2192 arrow in the adr-analyze subparser help"*. That fix was not only the test — `messagefoundry/__main__.py:42-56` hardens `sys.stdout` and `sys.stderr` for the whole CLI, and its comment names the same failure. `harness/__main__.py:97-101` and `harness/acceptance/__main__.py:39` carry the same remedy, as does `scripts/bench/stage_residency.py:1057-1059`. The second recurrence is the sweep this item comes from: 43 non-cp1252 characters across four `scripts/` files, one of which (`scripts/kerberos_epa_spike.py`) had 11 string literals that raise on a cp1252 stdout.

**Measured 2026-08-05: the backlog gate's own `--help` crashes.** `python scripts/docs/backlog_status_check.py --help` raises `UnicodeEncodeError: 'charmap' codec can't encode character '\u2705'`. Its argparse description is the module docstring, which carries the banner-alphabet table, so five non-cp1252 codepoints (U+2705, U+26D4, U+1FAA6, U+1F522, U+1F6A7) reach stdout. U+2014 is in that help text too and is cp1252-representable, so it is not part of the failure.

**That case also shows why the naive gate is wrong.** Those five are the sanctioned machine-parsed alphabet CLAUDE.md §11 protects, and the remediation text must quote them to be actionable — an author told to add a closed banner without being shown the character cannot comply. So the fix there is a stdout reconfigure in that one script, **not** removing the characters. A gate that cannot express that exemption would either fire on correct code or be switched off.

**Difficulty 4 is the scope decision, not the scanner.** The scanner is thirty lines — encode each character to cp1252 and report the failures. The design questions are: which paths (source only, or docs too, where `docs/BACKLOG.md` is a deliberate holdout); whether to gate on *encodability* or on *reaching an unguarded stream*, since those give different answers for a file that reconfigures; and how the exemption is declared so it is auditable rather than a hardcoded filename list. `tests/test_announce_hook.py:810` is the precedent worth copying — it gates source bytes, states its reason, and the guarded file declares its own constraint at `announce-session.ps1:54`.

**Three properties to keep.** Print what was scanned — a filtered scan that skips a file type reads as clean when it never looked. Check the whole file, not line by line: `splitlines()` consumes U+2028/U+2029, so a line-oriented scan is structurally blind to them. Do not silently drop files that fail to decode as UTF-8.

**Related:** #1018 (guards that go quiet), #1027 (a green that is not evidence), #1031, ADR 0158.

**Source:** raised by the `scripts/` glyph sweep on 2026-08-05, then rewritten after an adversarial pass refuted the first draft's "exactly one gate exists" and its `errors='strict'` mechanism. The `--help` crash and the stream-handler values were measured, not inferred.

## 1031. The STEP4 bench doc restates the stage_residency docstring in the glyphs its source shed, and carries emoji

> ✅ **SHIPPED 2026-08-05.** All 101 non-cp1252 characters removed from `docs/benchmarks/STEP4-bracket-and-littles-law.md` — the **whole file**, not just the §5.2 block enumerated below, which was written as a floor and was one. U+2264/U+2265/U+2212/U+2192/U+2190/U+2260/U+21D2 to their ASCII forms; U+03BB/U+03C3 to `lambda`/`sigma`; U+2261 to `==`; U+2227 to the word `AND`; the four U+26A0 + U+FE0F pairs to the word `WARNING`. U+2248 became the file's **own** bare-tilde idiom (`~62 ms`, `rho ~0.23`) rather than `~=` — `~=` is the PEP 440 compatible-release operator everywhere else in `docs/` and means NOT-EQUAL in MATLAB and Lua, which would have inverted the verdict rows at lines 373-375. U+00D7 deliberately KEPT (14 occurrences): it is cp1252-representable typography, not a glyph, and the source keeps 4.

**Cluster:** Docs / consistency. **Priority:** P4. **Verdict:** build (trivial). **Severity:** none operationally. It is a documentation defect: a reader comparing the doc to the tool sees two renderings of one definition and cannot tell whether the difference is meaningful.

**Where — lines 414-425, and at least these.** U+2264 twice and U+2212 once on line 416 (`N(t) = #transformed<=t - #delivered<=t`, which the source now writes in ASCII, matching what `stage_residency.py:557` already used); U+2192 on 417; U+2248 on 422, in the sentence the source now reads as "N is about 8, therefore the lanes are saturated"; U+03BB on 425; and U+26A0 + U+FE0F on 421 and 425. Enumerated by scan rather than by eye, but treat it as a floor and re-scan the range.

**Do not "fix" U+00D7 — the source keeps it.** `stage_residency.py` still contains four multiplication signs, including on the same sentence as doc line 425. It is cp1252-representable and out of scope for §11. Converting the doc's copy would *create* a divergence rather than remove one.

**The source is cp1252-safe, not ASCII.** It retains 70 em dashes and those four multiplication signs. Em dashes, ellipses and section signs in the doc are cp1252-representable typography and stay.

**Nothing machine-compares them, which is the point.** No gate reads both, so this did not go red and will not. It is the shape #1030 exists to catch, and if #1030 lands with docs in scope this closes as a side effect — check that before doing it by hand.

**Related:** #1030 (the missing gate that would have caught this), #1027.

**Source:** found by the completeness pass over the `scripts/` glyph sweep on 2026-08-05; the codepoint enumeration was corrected by an adversarial pass that caught the first draft claiming U+00D7 as a divergence and missing the U+26A0/U+FE0F pair entirely.

## 1032. `worktree_gate` Rule 3b prints a `new.ps1` command that `new.ps1` rejects

> ✅ **SHIPPED 2026-08-05 — merged as PR #214 (`fdaf53f7`).** Value **6/10** · Difficulty **3/10** · _fill-in_. The Rule 3b deny's escape hatch could not be executed for the case that triggers it: it interpolated a slash-bearing branch name into a parameter that forbids slashes, which is 143 of 196 local branches. Reproduced by running it, not by reading it. `new.ps1` gained a `-Branch` parameter distinct from `-Name` and the rule now emits both. The same work closed a refname **command injection** in that deny text (#1040) and a hijack **bypass** the first attempt introduced — rule 3b deferred to a git guard that `--ignore-other-worktrees`, `--detach` and `-d` all switch off, on both `checkout` and `switch`, so the fix is an allowlist (deny on ANY flag) rather than a list of known bypasses (#1039). Verified in main: `ConvertTo-WorktreeSlug` present in `scripts/hooks/worktree_gate.ps1`.

**What.** `scripts/hooks/worktree_gate.ps1:388`, inside the Rule 3b deny ("BLOCKED: would switch a LINKED WORKTREE onto the existing branch"), tells the caller to give the branch its own worktree with:

```
pwsh -NoProfile -File $newHint -Name $dest
```

`$dest` is the **branch** name. `scripts/worktree/new.ps1:26` validates `-Name` against `^[A-Za-z0-9._-]+$`, which every slash-bearing branch fails. Measured 2026-08-05: a branch of the form `claude/<task>-<suffix>` is REJECTED while the bare `<task>` component is accepted, and **140 of 193 local branches carry a slash**. The gate's motivating case is a branch that already exists — which is exactly why it carries a `claude/` prefix — so the escape hatch fails in the default case, not an edge case.

**Why it survived.** The other three sites (`:411`, `:685`, `:794`) print the placeholder `-Name <short-kebab-task-name>`, which is valid. `:388` is the only interpolating one, so a grep for the common form finds three healthy instances and misses the defect. Two independent readers hit exactly that; the one who found it had run the command and held the failure in hand first.

**DO NOT fix this by relaxing the ValidatePattern.** `$Name` does two jobs and the pattern is load-bearing for the first:

| line | use |
|---|---|
| `new.ps1:43` | `Join-Path $Parent "$RepoName-$Name"` — a **path component** |
| `new.ps1:58`, `:72`, `:86`, `:97` | `git branch --list` / `worktree add` / the `mefor-home-branch` marker — a **ref** |

A slash satisfies git as a refname but makes `Join-Path` build a nested directory. Measured: a `claude/<task>` branch yields `MessageFoundry-claude\<task>` instead of a sibling `MessageFoundry-<name>`, so the worktree lands one level deeper than every other one. Loosening the pattern alone converts a **loud correct failure into a quiet wrong success** — the worse direction of error.

**Preferred fix.** Add a `-Branch` parameter distinct from `-Name` (name = directory component, branch = ref), defaulting `-Branch` to `-Name` so every existing caller is unchanged; then `:388` emits `-Branch $dest -Name <sanitized>`. **Fallback** if a new parameter is unwanted: stop printing a command that cannot work, and print the supported procedure instead.

**Verification this item must demand.** A test that **executes the string the gate prints**, not one that asserts a copy of it — a test hard-coding the expected hint passes throughout this defect, which is the "guard tests a copy of the rule" trap and is how it survived. It must also assert the resulting worktree directory is a **sibling**, since that is the regression the current validation prevents and that a naive fix would introduce.

**Related:** #1030 (the missing general gate), #1027.

**Source:** found by session `sleepy-villani-df328d` while gate-blocked twice, correctly, from another session's branch; reproduced independently by the coordinator against `new.ps1:26` and `Join-Path`. A Claude Code task chip (`task_fb78da2c`) covers the same defect but carries no allocated number and will not survive the session, so this ledger entry is the durable record.

## 1033. The rubric cites its own signals as `#N`, and six of those numbers are real backlog items

> 🔢 **Filed 2026-08-05 — not started.** Value **4/10** · Difficulty **2/10** · _fill-in_. [`docs/Code_Quality_Standards.md`](Code_Quality_Standards.md) refers to its own eleven rubric signals as `#6`, `#7`, `#9`, `#10`, `#11`. In this corpus a bare `#N` reads as a backlog item, and six of those numbers **are** backlog items. Owner ruled 2026-08-05 that they get disambiguated. The four-digit PR citations in the same file were already fixed (PR #209); this is the short-number half that was deliberately left out of scope there.

**What.** Ten citations on four lines, measured against `origin/main` at 780ee1d9:

| Line | Tokens |
|---|---|
| L282 | `#10` |
| L299 | `#7`, `\#8`, `\#9`, `\#11`, `\#10` |
| L319 | `#10` |
| L420 | `#6`, `#7`, `#9` |

Resolved against both ledger files with `parse_items`: **`#3` is an OPEN item today**; `#6`, `#7`, `#8`, `#10` and `#11` are closed items; only `#9` does not exist in the namespace. So six of the seven distinct numbers already resolve to something real and unrelated.

**This is not inventing a convention.** L219 already reads *"Complexity (11) and clone (9) shipped first"* and *"the ruff-breadth expansion (signal 10, PR \#1047)"* — the word form and the bare-parenthesis form both appear in the file already, and L420 carries a `signal N` phrasing and a bare `(#N)` on the same line. The change makes the file self-consistent rather than imposing something new. `signal 7` is the target form; `PR #NNNN` is already the settled form for pull requests.

**Two traps, both of which have already caught a reader.**

1. **`#3` at L120 is a markdown ANCHOR FRAGMENT, not a citation:**
   `[Secure AI-Assisted Development Standards §3](Secure_AI_Development_Standards.md#3-the-problem-this-standard-attacks)`.
   Converting it silently breaks the link. It must be left alone, and a census that counts tokens without printing context will not see the difference. A prior census listed it as *"#3 x1 rubric signal"* and was wrong.
2. **L299 and L319 use backslash-escaped forms** (`\#8`, `\#9`, `\#11`, `\#10`). A pattern requiring a literal space or paren before `#` misses them, and a `grep -oE` attempt during this triage returned **zero matches on a file that demonstrably contains them** — the pattern silently matched nothing and was believed. Prove the pattern fires on a known string before trusting a count from it.

**Verification bar for whoever does it.** Print the token list with line numbers, not a count. Confirm zero bare one-or-two-digit `#N` remain outside link targets, that the L120 anchor is untouched, that the forty four-digit citations are still forty marked and zero bare, and that every markdown link still resolves — the anchor is the one that breaks silently.

**Related:** PR #209 (the four-digit half, and the source of the `PR #NNNN` convention), \#1029 (the same document), \#1032 (same class: a census that counted without printing context).

**Source:** raised by session `sleepy-villani-df328d` while sweeping the four-digit citations, and correctly kept out of that PR's scope. Owner ruled on it 2026-08-05. Counts here were re-measured against 780ee1d9 with a self-tested pattern after an unverified one reported zero.


## 1034. The pre-push shim fails OPEN when python is not on PATH, so the push guard silently does not run

> ✅ **SHIPPED 2026-08-05 — merged as PR #215 (`09c6fe8e`) and PR #217 (`e75cff02`).** Value **7/10** · Difficulty **3/10** · _fill-in_. The headline defect and both "adjacent gaps" below are fixed. #215: both generated shims now refuse instead of exiting 0 when neither `python` nor `python3` resolves, and name `--no-verify` so a fail-closed gate does not get "fixed" by deleting it. #217: `MEFOR_ALLOW_DIRECT_PUSH` is scoped to the protected-branch guard alone, so it no longer disarms the namespace and content guards it was never named for; and a tip tree the guard cannot READ is refused rather than assumed clean, because "there is nothing there" and "I could not look" are different facts. Proven against the pre-fix code rather than asserted: the old shims exit 0 with no interpreter on PATH, and the old guard permits both a branch and a tag carrying `docs/security`. **What did NOT ship is this item's own prescription** — "the durable answer is server-side" is measured DEAD on both halves (a push ruleset returns `422 Source public repos cannot have push rules`; `enforce_admins` governs protected branches and so cannot see a feature branch). That residual, and the fact that no server-side content control exists here at all, is **#1056** — this item is closed on its title, not on that finding.

**What.** The shim is generated by `scripts/coord/install-git-hooks.ps1` and shared by every worktree through `core.hooksPath`. When it cannot find python it prints its notice to stderr and returns 0, allowing the push. That is the correct posture for a *workflow* guard that should not wedge a developer, and the wrong one for the only remaining control on a publication path — the same fail-open-versus-fail-closed distinction the security standards already draw between the git-staging guard and the engine's bind guard.

**Why it matters more since 2026-08-05.** `push_guard.py` gained two further checks that day: a namespace allowlist (refusing a `--mirror`-shaped push) and a tip-tree check (refusing a ref carrying `docs/security`). Both are defeated by the same fail-open, so the shim now switches off three guards rather than one, and the failure is silent in the noisiest possible place — a terminal line above a successful push.

**Two adjacent gaps in the same class**, worth deciding together rather than separately:

- A **fresh clone or a newly created worktree has no hook at all** until `install-git-hooks.ps1` runs. Nothing prompts for it.
- `git push --no-verify` and `MEFOR_ALLOW_DIRECT_PUSH=1` skip every check by design, and the latter returns 0 before any guard runs despite reading like it permits one specific thing.

**A client-side hook cannot be the sole control, and that is the real finding.** Any fix here reduces the likelihood of an accident; it does not close the path. The durable answer is server-side — re-enabling `enforce_admins`, or a push ruleset — with the shim hardened as defence in depth rather than as the boundary. Whatever is decided, no prose may describe the hook as a security boundary; its own docstring already refuses that framing and should keep refusing it.

**Related:** \#1032 (same file family, and the same shape of a remediation that cannot execute), PR #209.

**Source:** surfaced 2026-08-05 while adding the two new guards, from the observation that a guard everything else leans on can be switched off by a missing interpreter. Held for the owner: session `nice-payne-4dcee0` has it as analysis only, with no build decision taken.

## 1035. Gate remediations interpolate an unquoted `-File` path into a command the reader is told to run

> 🔢 **Filed 2026-08-05 — not started.** Value **5/10** · Difficulty **2/10** · _quick win_. Every `pwsh -NoProfile -File $x` the gate prints interpolates a governed-root path with no quoting. A root whose path contains a space produces a command that cannot run. Latent today only because the single allowlist entry has no space in it.

**What.** `scripts/hooks/worktree_gate.ps1` emits remediation commands of the form `pwsh -NoProfile -File <interpolated path>`. At least six such sites exist across five rules. One of them (Rule 3b's) was quoted while fixing #1032; the rest were left, deliberately, as untouched code in rules that change was not opening.

**Measured, not reasoned.** With a primary at `<tmp>/Pri mary`, the emitted line exits **64** with a usage dump and the message `The argument 'C:\...\Pri' is not recognized as the name of a script file`. Quoted, the identical line exits 0. This is pinned in `tests/test_worktree_gate_hijack.py`, whose execution test is parametrised over a plain and a space-bearing primary precisely so the quoting is under test rather than assumed.

**Why it is worth doing despite being latent.** It is the same defect class as #1032 — a remediation the receiving side rejects — and #1032 demonstrated that the class is not caught by review: three healthy placeholder sites hid one broken interpolating site, and two independent readers missed it. The condition that makes this live is a user choosing a checkout path with a space, which is an ordinary thing to do and not something the repo controls.

**Scope note.** Two categories must NOT be swept up. Relative file *references* with trailing prose (Rule 1a telling a human where the source lives) are deliberately not runnable command forms. Comment-based help inside a `.NOTES` block is never emitted at runtime. Both look similar to grep and neither is a defect.

**Related:** #1032 (same class, the instance that was fixed), #1040 (the deny-text output surface these sit in).

**Source:** identified 2026-08-05 while fixing #1032, and deliberately deferred rather than swept in, so that fix stayed scoped to one rule. Recorded here because a deferral nobody files is a deferral dropped.

## 1036. A Rule 4 deny names the first allowlisted repo's tooling regardless of which repo fired it

> 🔢 **Filed 2026-08-05 — not started.** Value **3/10** · Difficulty **2/10** · _quick win_. The `EnterWorktree` deny hardcodes the first governed root when building the command it tells the session to run. Rule 4 computes no root of its own and fires for every session regardless of repo, so with a second governed primary in the allowlist it would point the reader at the wrong repository's script.

**What.** Rule 4 denies the `EnterWorktree` tool and prints a remediation naming `sessions.ps1` under the first allowlist entry. Unlike the path-scoped rules, Rule 4 never resolves which governed root the session belongs to — it fires on the tool name alone.

**Why it is latent.** The allowlist currently holds one entry, so the first entry is trivially the right repo. The defect appears the moment a second primary is governed, and it appears as a remediation pointing into an unrelated checkout — which is worse than no remediation, because the path exists and the command runs.

**Severity.** No product effect and no security effect; the gate still denies correctly. The failure is in the instruction, not the decision.

**Related:** #1035 and #1032 (remediations that cannot be acted on as printed), #1040.

**Source:** identified 2026-08-05 during the #1032 work, from reading every remediation site in the file rather than only the one being fixed.

## 1037. `remove.ps1` cannot be execution-tested, because it hardcodes its repo root

> 🔢 **Filed 2026-08-05 — not started.** Value **4/10** · Difficulty **3/10** · _fill-in_. `scripts/worktree/remove.ps1` derives its repo root from its own script location with no override, so no test can drive it against a synthetic repository. Its sibling `prune-merged.ps1` accepts a root and IS execution-tested; that is the whole difference.

**What.** `remove.ps1` computes its repo root from where it lives. A test therefore cannot point it at a fixture repo, and the only way to exercise it is against the real checkout — which no test may do, since the script removes worktrees and can delete branches.

**Why it matters now.** `remove.ps1` gained real behaviour on 2026-08-05: `-DeleteBranch` stopped assuming the branch equals the directory name and adopted `prune-merged.ps1`'s lossless discipline (`-d` first, `-D` only after re-verifying the branch carries nothing beyond `origin/main`). That logic is covered by **review only**. It is the code path that force-deletes refs, and the one place in `scripts/worktree/` where getting it wrong loses commits reachable from no ref and no reflog.

**The shape of the fix** is already in the repo: `prune-merged.ps1` takes a root parameter and has an execution test. Adding the same override is mechanical; the value is that it converts the most destructive script in the directory from review-covered to test-covered.

**Related:** #1032 (the change that gave `remove.ps1` behaviour worth testing), and `tests/test_worktree_prune_merged.py` as the pattern to copy.

**Source:** identified 2026-08-05 while changing `remove.ps1`, and stated in that change's own commit as covered by review rather than test.

## 1038. Rule 3b's remediation names `new.ps1` siblings while most live worktrees are harness-created and nested

> 🔢 **Filed 2026-08-05 — not started.** Value **4/10** · Difficulty **4/10** · _fill-in_. Two mechanisms create worktrees here and they use different layouts. `new.ps1` makes siblings at `<repo-parent>/<repo-name>-<Name>`; the Claude Code harness makes nested ones under `<primary>/.claude/worktrees/<slug>`. Rule 3b fires for both and its remediation only ever names the first.

**What.** A session blocked by Rule 3b is told to run `new.ps1`, which produces a sibling worktree. If that session is itself harness-created and nested, the remediation hands it a worktree in a different layout from the one it lives in — functional, but not what the reader expects, and not made by the mechanism that made theirs.

**Both layouts are live.** Measured 2026-08-05: sibling and nested worktrees both exist in quantity against this one `.git`. Two source comments asserted that `new.ps1` creates the *nested* layout; both were false and were corrected during the #1032 work, in `worktree_gate.ps1` and `scripts/coord/occupancy.ps1`. That the same false premise had been independently written twice is the reason this is worth settling rather than leaving to be re-derived a third time.

**The open question, which is design and not a bug.** Should Rule 3b name the harness path first, name both, or keep naming `new.ps1` and say why? #1032 deliberately did not settle it — that change made the command it already printed runnable, and nothing more. Whichever way it goes, the answer belongs in one place with the other site linking to it.

**Related:** #1032 (made the printed command work without settling which command is right), #1035.

**Source:** identified 2026-08-05 during the #1032 investigation, when the sibling-versus-nested contradiction surfaced from reading `git worktree list` rather than the comments.

## 1039. `git worktree add --force` also defeats the already-checked-out guard, so "git will refuse this" must be written as conditional

> 🔢 **Filed 2026-08-05 — not started.** Value **5/10** · Difficulty **2/10** · _quick win_. At least three git flags defeat the guard that stops a branch being checked out in two worktrees. Any code or comment reasoning that "git already refuses this" is making a claim about a **configuration**, not about git, and must say so.

**Measured 2026-08-05**, against a branch live in another worktree:

| command | result |
| --- | --- |
| `checkout`/`switch <b>` | `fatal: already used by worktree at ...` |
| `checkout`/`switch --force <b>`, `switch --discard-changes <b>` | `fatal` — do NOT bypass |
| `switch --no-ignore-other-worktrees <b>` | `fatal` — correctly does NOT bypass |
| `checkout`/`switch --ignore-other-worktrees <b>` | **switches** |
| `checkout`/`switch --detach <b>`, and `-d <b>` | **switches** |

`--detach` bypasses by never taking the branch lock, yet it still swaps the other session's files to that commit, which is the harm. `-d` is a live short form on **both** verbs.

**Not yet measured, and the reason for this item:** `git worktree add --force` overrides the same guard. Nothing in the gate is known to depend on that today, but the assumption "git will refuse a second checkout" appears in reasoning about worktrees generally, and it should be recorded as conditional wherever it appears.

**This is a documentation-and-audit item, not a code fix.** #1032's fix already handles the checkout/switch path, and it does so with an **allowlist** — the early return fires only when there are no flags at all — precisely because a denylist was written twice there and was wrong twice. The work here is to find every other place that defers to a guard it does not own, and write down what switches that guard off.

**Related:** #1032 (where the bypass was introduced and closed), #1040.

**Source:** the bypass was found 2026-08-05 by a session auditing its own change after a peer noted that `ledger_check.py`'s ownership model depends on the worktree gate; `--detach` and `-d` were then found by asking the same question a second time rather than patching the first flag.

## 1040. Hook deny text is attacker-influenceable output that an agent is instructed to act on, and nothing treats it as such

> 🔢 **Filed 2026-08-05 — not started.** Value **8/10** · Difficulty **5/10** · _do it_. Two separate injections into gate deny text were found independently on the same file within hours, by two sessions, through different values. The general form is bigger than either instance and bigger than the gate: a deny reason is **output built from attacker-influenceable input**, and it carries a command block a model is told to run.

**Instance one — a refname into a command.** `git check-ref-format` accepts `;`, `$`, `|`, `"` and `'` in a refname. A legal, creatable branch carrying a quote and a comment marker made Rule 3b emit a line that parses as **two statements**, the second arbitrary, with the comment marker hiding the remainder. A branch with a bare interior quote emitted an unparseable line. Fixed by doubling the quotes in the single-quoted emission.

**Instance two — a file path into prose.** A `Write` whose `file_path` carried embedded newlines produced a reason with **two** `Do this instead:` blocks, the forged one **first**, so a model reading top-down reaches the injected command before the real remedy. This one needed nothing on disk — only the JSON field — so no other gate saw it.  Fixed with a shared fold helper.

**The two fixes are different, and the wrong one at either site would look like it worked.** Quote-doubling is for a value entering a **command**; folding CR/LF/TAB is for a value entering **prose**. Both produce output that reads fine to a human skimming it.

**Why this is the most valuable item in this group.** The repo already knew half of it: `Write-Deny` has always folded its **log** line, with a note that a crafted path could otherwise forge records in a log whose purpose is counting. The **reason** never got the same treatment, in the same function. And every hook in `scripts/hooks/` that emits a remediation an agent is told to run has this shape — the gate is where it was noticed, not where it is confined.

**What the work is.** Enumerate every deny and remediation surface across `scripts/hooks/`, classify each interpolated value as command-bound or prose-bound, and apply the matching treatment through one shared helper per class rather than at each site. The audit is the deliverable; the individual fixes are small.

**Related:** #1032 and #1035 (the same output surface, viewed as runnability rather than injection), #1039.

**Source:** the two instances were found independently on 2026-08-05 by sessions `trusting-wu-c2e6d5` (refname, in Rule 3b) and `sharp-chatelet-f33072` (file path, in Rule 1b), the second after the first asked whether the new rule interpolated an attacker-influenceable value into a command form. Filed separately from the five deferrals it was grouped with, because the general form is a different and larger item than any of them.

## 1042. The `[vault]` key/secret/transit providers build a redirect-following HTTP client, so a diverted 3xx could carry `X-Vault-Token` off-path

> 🔢 **Filed 2026-08-05 — not started.** Value **4/10** · Difficulty **2/10** · _fill-in_. Every shipped HTTP egress routes through a no-redirect urllib opener (`transports/rest.py` `_NO_REDIRECT_OPENER`), except the `[vault]` provider clients, which build a `requests`-based hvac client with no redirect policy. A deploying site on `messagefoundry[vault]` would carry `X-Vault-Token` over a redirect-following client to the operator-set `VAULT_ADDR`.

**Cluster:** Egress / secret handling. **Priority:** P3. **Verdict:** build (small). **Severity:** conditional, not an exposure on the shipping config. The vault provider is behind an optional pip extra and off by default; when selected it points at operator-trusted infrastructure. On first deployment, an on-path 3xx (absent TLS integrity) or a spoofed Vault could divert the bearer token, while every default egress refuses redirects.

**The fix.** Set a no-redirect policy on the hvac session (or wrap the three vault clients: `store/keyprovider_vault.py`, `config/secretprovider_vault.py`, and `store/crypto_transit.py` via `_build_client`), OR document redirect-following-to-Vault as intended per the verb's "unless it is intended functionality" clause.

**Related:** ASVS 15.3.2 (the re-verification that surfaced it), 1.3.6 (SSRF).

**Source:** ASVS 5.0.0 V15 re-verification, 2026-08-05. Full file:line detail is in the maintainer-internal ASVS V15 chapter report (`docs/security/`, withheld per SECURITY-DOCS-POLICY.md).

## 1043. The threat-model drift guard's doc-content assertions go inert when the vault doc is absent, so on the public tree they enforce nothing

> 🔢 **Filed 2026-08-05 — not started.** Value **4/10** · Difficulty **3/10** · _fill-in_. `tests/test_threat_model_doc_drift.py` skips every doc-content assertion (heading-enumeration, planted-omission) when `docs/security/THREAT-MODEL.md` is absent, which it is on the public tree (the doc is deny-listed from the OSS mirror). The compensating control's enforced half lives outside the tree it runs in; the code-only assertions (subprocess-site inventory, default-value locks) still fire.

**Cluster:** Measurement / doc-drift integrity. **Priority:** P3. **Verdict:** build (small). **Severity:** no product effect. The defect is a green that is not evidence: on the assessed public tree, the identification of resource-demanding and dangerous functionality (which several ASVS 15.1.x verdicts lean on) has zero drift enforcement, and nothing announces the skip.

**The fix, and its constraint.** Make the doc-absent skip loud rather than silent (the project's own standard, ADR 0158's class), or ship a public-tree stand-in the content assertions can run against. A skip that reads as a pass is the failure being fixed; do not trade a silent skip for another.

**Related:** #1027 (a documented gate that silently covers less than it appears to), ADR 0158, ASVS 15.1.3 / 15.1.5.

**Source:** ASVS 5.0.0 V15 re-verification, 2026-08-05. Detail in the maintainer-internal ASVS V15 chapter report.

## 1044. There is no request-timeout on HTTP handlers, so the "response within the consumer's timeout" limb has no server-side enforcement

> 🔢 **Filed 2026-08-05 — not started.** Value **3/10** · Difficulty **3/10** · _fill-in_. The only `asyncio.wait_for` in `api/` is the connection-test probe; there is no request-timeout middleware. ASVS 15.1.3's limb "avoid building a response that takes longer than the consumer's timeout" has no server-side enforcement (properly 15.2.2 territory, surfaced during the 15.1.3 re-verification).

**Cluster:** Availability. **Priority:** P3. **Verdict:** build (small). **Severity:** no exposure on the shipping config (localhost + auth, single worker). On first deployment a slow handler holds a worker for as long as it runs, with nothing bounding the response time from the server side.

**The fix.** Add a request-timeout middleware (or per-route deadline) that returns a bounded error rather than building unboundedly.

**Related:** ASVS 15.1.3 / 15.2.2, #1042.

**Source:** ASVS 5.0.0 V15 re-verification, 2026-08-05. Detail in the maintainer-internal ASVS V15 chapter report.

## 1045. `redact_unauthorized` fails open, so a future PHI route that forgets the call returns every field unmasked

> 🔢 **Filed 2026-08-05 — not started.** Value **4/10** · Difficulty **2/10** · _fill-in_. `api/field_authz.py` `redact_unauthorized` fails open: field masking happens only where the call is made, and coverage is pinned only by an enumerated test (`tests/test_field_authz_enforcement_sites.py`). A new PHI-returning route added without the call, and not added to the test, would return the whole model unmasked.

**Cluster:** Defensive coding / field authorization. **Priority:** P3. **Verdict:** build (small). **Severity:** not an exposure today, verified rather than assumed: every documented PHI surface at HEAD is covered (which is why ASVS 15.3.1 still grades pass). A latent defensive-coding weakness, not a live leak.

**The fix.** A fail-closed default (mask unless explicitly allowed) or app-level enforcement middleware, so a forgotten call denies rather than exposes.

**Related:** ASVS 15.3.1, #1043 (the same enumerated-test coverage shape).

**Source:** ASVS 5.0.0 V15 re-verification, 2026-08-05. Detail in the maintainer-internal ASVS V15 chapter report.

## 1046. The inbound archive move uses a non-atomic exists-check instead of the `O_EXCL` claim used on the delivery path

> 🔢 **Filed 2026-08-05 — not started.** Value **2/10** · Difficulty **2/10** · _fill-in_. `transports/file.py` `_move` relocates via `_unique`, which uses a non-atomic `if not target.exists()` rather than the `O_EXCL` claim (`_claim_unique`) the delivery path uses. A check-then-act TOCTOU window exists on the archive move.

**Cluster:** Concurrency. **Priority:** P3. **Verdict:** build (small). **Severity:** no integrity consequence on the default config, verified: the canonical raw message is already durable in the store at ingress (ACK-on-receipt), and the default is one poller per source over an engine-owned `processed_dir`. It would only race under a non-default config where two FileSources share one `processed_dir`, worst case a benign archived-copy name collision.

**The fix.** Route the archive move through `_claim_unique` (the same `O_EXCL` claim as the delivery path).

**Related:** ASVS 15.4.4.

**Source:** ASVS 5.0.0 V15 re-verification, 2026-08-05. Detail in the maintainer-internal ASVS V15 chapter report.

## 1047. The apiclient measures URL length before the query string is appended, so a query-bearing GET can exceed the limit unchecked

> 🔢 **Filed 2026-08-05 — not started.** Value **3/10** · Difficulty **2/10** · _fill-in_. `apiclient/client.py` measures only `len(base_url) + len(path)` against `MAX_REQUEST_URL_LEN`, then `_request` hands `params=` to httpx, which appends the query AFTER the check (the `Authorization` header IS bounded). A query-bearing GET can construct a URI over the limit with nothing refusing it. The apiclient is the frontend ASVS 4.2.5 explicitly names.

**Cluster:** Outbound length bounding / DoS. **Priority:** P3. **Verdict:** build (small). **Severity:** the primary attacker-influenced message-derived HTTP family (REST/SOAP/FHIR) IS bounded at construction + send-time; this is the residual under the 4.2.5 `partial`. On first deployment an operator action (tray/harness/monitor) producing a long query could build an over-long URI the receiving component rejects with a persistent error status.

**The fix.** Measure the resolved URL including the query (or reuse `transports/rest.py` `enforce_send_time_length_limits`). Note `test_apiclient_length_bounds_match_the_transport_constants` keeps the constants in step but does not cover this query-string gap.

**Related:** #1048 (the sibling 4.2.5 gap), ASVS 4.2.5.

**Source:** ASVS 5.0.0 V4 re-verification, 2026-08-05. Detail in the maintainer-internal ASVS V4 chapter report.

## 1048. The OIDC token-exchange outbound request has no send-time length guard

> 🔢 **Filed 2026-08-05 — not started.** Value **2/10** · Difficulty **2/10** · _fill-in_. `messagefoundry/auth` carries zero `enforce_send_time_length_limits` / `MAX_REQUEST_URL_LEN` calls; the token-exchange `urllib.request.Request` at `auth/oidc/flow.py` has no send-time length guard.

**Cluster:** Outbound length bounding. **Priority:** P3. **Verdict:** build (small). **Severity:** the weaker limb of the two 4.2.5 gaps: `token_endpoint` is operator-static config (validated https at load), not attacker-influenced, so the 4.2.5 `partial` does not depend on it.

**The fix.** Add a send-time length check on the token-exchange request line + headers.

**Related:** #1047 (the primary 4.2.5 gap), ASVS 4.2.5.

**Source:** ASVS 5.0.0 V4 re-verification, 2026-08-05. Detail in the maintainer-internal ASVS V4 chapter report.

## 1049. `XmlMessage` exposes only string-expression XPath, so a Handler interpolating tainted data has no framework-provided safe path

> 🔢 **Filed 2026-08-05 — not started.** Value **3/10** · Difficulty **3/10** · _fill-in_. `XmlMessage.find` / `get` / `get_all` / `exists` / `set` all take an `expression: str` into the sole sink `self._root.xpath(...)`; there is zero `etree.XPath()` / `XPathEvaluator` / `$`-bound XPath tree-wide. No first-party dynamic XPath from taint ships today, but `XmlMessage` is exported to code-first Handlers (`parsing/__init__`), so a Handler interpolating HL7/request data into an XPath expression would, on first deployment, have an injection vector with no framework-provided safe alternative.

**Cluster:** Injection hardening / defensive API. **Priority:** P3. **Verdict:** build (small). **Severity:** not a shipped vulnerability (nothing in-tree reaches `.xpath()` with tainted data); a hardening item for the code-first authoring surface, unlike SQL where the driver binds values regardless of the author's statement.

**The fix.** Add a `$var`-parameterized or precompiled `XmlMessage` XPath API so a Handler has a safe option. Separately, the ASVS scorecard record for 1.2.7 was corrected in the same re-verification (a prior `na` on a false "no XPath anywhere" premise moved to `needs-review`); that record correction is already done and is not part of this code item.

**Related:** ASVS 1.2.7, 1.3.4 (the structurally parallel SVG cell).

**Source:** ASVS 5.0.0 V1 re-verification, 2026-08-05. Detail in the maintainer-internal ASVS V1 chapter report.
## 1051. Async-delivery `retry_max_attempts=None` (retry forever) contradicts the engine's own documented sync-HTTP guidance

> 🔢 **Filed 2026-08-05 — not started.** Value **3/10** · Difficulty **2/10** · _fill-in_. `CONNECTIONS.md:2240` discloses the shipped async-delivery default `retry_max_attempts=None` as "retry forever", while `:2242` mandates a finite retry with a short timeout for synchronous HTTP. The default and the guidance disagree.

**Cluster:** Availability / delivery. **Priority:** P3. **Verdict:** build (small). **Severity:** no exposure on the shipping config (localhost + auth, single worker). On first deployment a forever-retrying FIFO lane head would block its lane until an operator purges it -- a behavioural DoS residual, honestly disclosed in-tree (the doc discloses the default and instructs the safe override), which is why it does not lower the ASVS 13.1.x documentation cells.

**The fix.** Ship a finite `retry_max_attempts` default (or a per-connection cap with dead-lettering on exhaustion) so the shipped default matches the documented sync-HTTP posture.

**Related:** ASVS 13.1.3 / 13.2.6, #1052 (the sibling unbounded-acquire residual).

**Source:** ASVS 5.0.0 V13 re-verification, 2026-08-05. Detail in the maintainer-internal ASVS V13 chapter report (`docs/security/`, withheld per SECURITY-DOCS-POLICY.md).

## 1052. Three services have an unbounded connector-tier / store pool acquire (no acquire timeout)

> 🔢 **Filed 2026-08-05 — not started.** Value **3/10** · Difficulty **3/10** · _fill-in_. `CONNECTIONS.md:2330` names "the one remaining unbounded connector-tier pool acquire"; the store SQL-Server / Postgres acquire and the DatabaseRef throwaway pool acquire have no hard cap. Documented (so the ASVS 13.1.x doc cells pass) but a behavioural residual.

**Cluster:** Availability / resource management. **Priority:** P3. **Verdict:** build (small). **Severity:** no exposure on the shipping SQLite config. On first deployment on a server backend, a pool-exhausted or unresponsive DB could block an acquiring task indefinitely with no bounding timeout, unlike the DATABASE connector acquire which is bounded by `acquire_timeout` 30s.

**The fix.** Apply a bounded acquire timeout (and a documented behaviour-at-limit) to the store SS/PG and DatabaseRef pool acquires, matching the connector-tier `acquire_timeout`.

**Related:** ASVS 13.2.6, #1051 (the sibling retry-forever residual).

**Source:** ASVS 5.0.0 V13 re-verification, 2026-08-05. Detail in the maintainer-internal ASVS V13 chapter report.

## 1053. `SERVICE.md` calls structured JSON + off-box logging "planned" while both are built and default-wired

> 🔢 **Filed 2026-08-05 — not started.** Value **2/10** · Difficulty **1/10** · _quick win_. `docs/SERVICE.md:370` still describes structured JSON logging and off-box syslog/SIEM forwarding as "planned", but both ship at HEAD: `JsonFormatter` (`logging_setup.py`), `[logging].format=json`, and the `SyslogForward` off-box forwarder with `forward_format` defaulting to JSON. A doc claiming a built feature is planned is stale.

**Cluster:** Documentation / built-vs-planned accuracy. **Priority:** P3. **Verdict:** build (trivial). **Severity:** no product effect; a doc-drift correction. It does not lower ASVS 16.1.1 -- `docs/PHI.md`'s logging inventory is the accurate inventory of record, and this drift is quarantined from scoring.

**The fix.** Update `SERVICE.md` to describe JSON logging and off-box forwarding as built (with their `[logging]` settings), removing the "planned" framing.

**Related:** ASVS 16.1.1 / 16.2.4 / 16.4.3.

**Source:** ASVS 5.0.0 V16 re-verification, 2026-08-05. Detail in the maintainer-internal ASVS V16 chapter report.

## 1054. The opt-in subprocess sandbox child logs through an unfiltered root logger, bypassing the redaction + log-injection scrub

> 🔢 **Filed 2026-08-05 — not started.** Value **3/10** · Difficulty **2/10** · _fill-in_. The ADR 0087 subprocess sandbox child calls a bare `basicConfig`, so its log records do not pass through the three PHI/redaction/control-char filters that `_install_phi_filters` attaches unconditionally to the engine's stdout handler and off-box forwarder.

**Cluster:** Logging / PHI redaction. **Priority:** P3. **Verdict:** build (small). **Severity:** off by default (`[sandbox].mode="off"`), so the default posture's redaction/scrub coverage (ASVS 16.4.1 / 16.2.5) is intact. On a deploying site that opts into `mode="subprocess"`, a child log line carrying message-derived content would reach the inherited stderr without redaction or CR/LF neutralization.

**The fix.** Install the same `_install_phi_filters` chain on the sandbox child's logging setup (or route the child's records through the parent's filtered handlers).

**Related:** ASVS 16.4.1 / 16.2.5, ADR 0087, #1055 (the sibling sandbox last-resort gap).

**Source:** ASVS 5.0.0 V16 re-verification, 2026-08-05. Detail in the maintainer-internal ASVS V16 chapter report.

## 1055. `threading.excepthook` is unreplaced on the raw sandbox-reader engine thread, so a non-`OSError` traceback there reaches the stdlib hook unredacted

> 🔢 **Filed 2026-08-05 — not started.** Value **2/10** · Difficulty **2/10** · _fill-in_. The engine replaces the asyncio loop exception handler (the last-resort handler for the event loop) but does NOT replace `threading.excepthook`, so a non-`OSError` exception in the raw sandbox-reader daemon thread reaches the stdlib default hook, which prints an unredacted traceback to stderr.

**Cluster:** Error handling / PHI redaction. **Priority:** P3. **Verdict:** build (small). **Severity:** a 16.2.5-class redaction-quality gap, not a missing last-resort handler -- both stated purposes of ASVS 16.5.4 still hold (the details reach NSSM-captured stderr rather than being lost, and a dead daemon thread does not take down the process). On a deploying site an unexpected non-`OSError` in that thread could emit a traceback that skips the redaction filters.

**The fix.** Replace `threading.excepthook` with a handler that routes through the engine's filtered logging (the same redaction chain as the loop exception handler).

**Related:** ASVS 16.5.4 / 16.2.5, #1054 (the sibling sandbox-logging gap).

**Source:** ASVS 5.0.0 V16 re-verification, 2026-08-05. Detail in the maintainer-internal ASVS V16 chapter report.

## 1041. Rule 3d tells a session removing its OWN worktree that it belongs to another session

> 🔢 **Filed 2026-08-05 — not started.** Value **4/10** · Difficulty **2/10** · _fill-in_. `scripts/hooks/worktree_gate.ps1:528` justifies rule 3d with *"git refuses to remove the worktree you are STANDING in -- so a `worktree remove` that reaches git is, by construction, aimed at somebody else's."* The gate is a **PreToolUse** hook, so it runs **before** git: git's refusal never happens, the inference is never tested, and the deny at `:563` asserts *"belongs to ANOTHER SESSION ... so this one is not yours"* for every governed worktree including the caller's own.

**Cluster:** Session-drift controls / refusal accuracy. **Priority:** P3. **Verdict:** build (small). **Severity:** no data loss — the deny is *correct as a decision* and it does prevent an accidental self-deletion. The defect is entirely in what the text tells the reader to do next, which CLAUDE.md §11 treats as a correctness property: *"a gate that misdescribes the thing it blocked trains people to route around it"* (recorded at `worktree_gate.ps1:646` for the sibling case #308 already fixed).

**Reproduced first-hand on 2026-08-05, not reasoned from source.** A session standing in a linked worktree under `<primary>/.claude/worktrees/` ran `git worktree remove <that same path>` and received rule 3d's refusal verbatim: *"acts on a worktree of `<primary>` that belongs to ANOTHER SESSION -- git refuses to remove the worktree you are standing in, so this one is not yours."* Both clauses are false in that run. Nothing was deleted, because the hook denied the whole command before git executed — which is also precisely why the premise cannot hold.

**Why the inference fails, stated once.** The premise is a claim about what reaches git. A PreToolUse hook decides *whether anything reaches git at all*, so it can never observe the state its own premise depends on. Any rule that defers to a downstream layer's guard has this shape; here the deferral is unconditional and the guard is unreachable.

**The remedy text compounds it.** The refusal closes with *"I want to remove the worktree `<path>` and I need you to confirm it is not in use."* For the caller's own worktree that sends the operator to verify a fact that is false by construction — the worktree is in use by the session asking. The other two suggestions (`prune-merged.ps1`, `git worktree list`) stay correct.

**The fix is local and the value is already computed.** Rule 3d resolves `$victimCmp` at `:554` for its governed-root test at `:557`. Comparing it against the session's own toplevel — `git -C $cwdRaw rev-parse --show-toplevel`, the same call rule 3b already makes — splits the two cases: a peer's worktree keeps the current text, and the caller's own gets an accurate one (git will refuse this itself; if you mean to discard the worktree, that is the user's call from a plain terminal). Difficulty 2: one comparison, one branch, and a regression test per branch. Do not simply *allow* the self case — the deny is the right decision, and blocking an accidental self-deletion is worth keeping.

**Do not fix by deleting the premise sentence.** It is load-bearing documentation of *why* rule 3d has no cwd check, so removing it leaves the missing check unexplained. Replace it with what is actually true: git's guard is unreachable from here, therefore the rule must decide ownership itself.

**Related:** #308 (the same defect class — a refusal describing something the reader cannot act on — fixed for the nested-worktree subpath), #1018 (guards that go quiet), ADR 0158.

**Source:** reported by a concurrent session while it was fixing rule 3b's remediation text, verified independently against the source rather than relayed, then reproduced live by accident when a second session ran the command against its own worktree. Filed by the session that verified it, which is not building it; the reporting session offered to take it if the owner scopes it there.

## 1056. No server-side content control exists for this repo, so the client-side push guard is the only prevention

> 🔢 **Filed 2026-08-05 — not started.** Value **7/10** · Difficulty **6/10** · _decide_. Successor to #1034, which is closed on its title. That item's stated remedy — "the durable answer is server-side" — is **unavailable**, measured rather than inferred. So the only thing preventing `docs/security` from reaching the public remote is a client-side hook that `git push --no-verify` skips and a fresh clone does not have until an installer is run by hand. That is the posture; the question is whether it is acceptable.

**The measurement, stated once here so nobody re-derives it.** Both halves of #1034's server-side answer are dead:

```
gh api -X POST repos/MEFORORG/MessageFoundry/rulesets -f name='block-private-docs' \
  -f target='push' -f enforcement='active' \
  -f 'rules[][type]=file_path_restriction' \
  -f 'rules[][parameters][restricted_file_paths][]=docs/security/**'
-> 422  "Source public repos cannot have push rules"
```

and `enforce_admins` governs **protected branches**. Re-enabling it would refuse an admin's direct push to `main` — worth doing on its own merits, and orthogonal to this — but branch protection never sees an ordinary feature branch, which is the ref a leak actually rides on. GitHub offers this repository no way to refuse a push by its CONTENT.

**What therefore stands, and what each layer can and cannot do.** State this precisely, because the failure mode is a reader assuming the stack is stronger than it is:

- **Prevention, client-side only.** `scripts/hooks/push_guard.py` refuses a pushed tip tree carrying `docs/security`, on every namespace including tags. It is bypassed by `--no-verify`, and absent entirely in any clone or worktree where `scripts/coord/install-git-hooks.ps1` has not been run. A client hook is advisory by construction and no prose may describe it as a boundary.
- **Detection, post-hoc.** PR #221 (OPEN at filing) adds a branch-push leak scan, because the leak gate in `security.yml` triggers on `pull_request`, push to `main`, and cron — so a branch pushed with no PR is scanned by none of them. It cannot prevent: on a public repo the content is public the instant the push completes.
- **Commit-time.** `scripts/security/scan_forbidden.py` gained a path detector for `docs/security` (#215), which catches a staged file. It does NOT catch the realistic vector, where files arrive inside a commit TREE taken from another ref and never pass through the index.

**The open question, which is the deliverable.** Is "bypassable prevention plus post-hoc detection" the accepted posture for the private security corpus on a public repo? Reasonable answers include: accept it and say so in `docs/SECURITY.md` so no later document overstates it; make the vault corpus unable to reach this repo's object store at all (it arrived once, via a direct-URL `git fetch` on 2026-07-28 — see #1034's lineage); or move to a hosting arrangement where push rules exist. **Do not answer it by hardening the hook further** — that raises the cost of an accident and changes nothing about `--no-verify`.

**Related:** #1034 (closed; the shim fail-open and its two adjacent gaps), #1040 (deny text as attacker-influenceable output — the `ls-tree`-fed surface was measured NOT injectable, because git C-quotes control characters in path output independently of `core.quotePath`), PR #221.

**Source:** surfaced 2026-08-05 when the owner ran the ruleset call drafted for #1034's server-side remedy and it returned 422. The session that had twice recommended AGAINST adding branch-push detection reversed on that evidence, since detection stops being the weaker option once prevention is unavailable. Filed so the reversal's premise is recorded rather than living only in a session transcript.

