# MessageFoundry — Delta Security-Fixes Multisession Plan (2026-07-01)

**Scope.** Remediate the **seven verified findings** from the delta security audit
([`docs/reviews/DELTA-REVIEW-2026-07-01.md`](../reviews/DELTA-REVIEW-2026-07-01.md)) — the code surface
that landed since the 2026-06-10 full review (v0.2.0 → v0.2.13). No new features, **no ADRs** (these are
bug fixes, not decision records). The six candidates the audit *refuted* are out of scope.

**This is a plan, not a build.** Per the project convention, nothing is built until the owner gives an
explicit "go".

**Why it parallelizes cleanly.** The seven findings touch **five disjoint source-file sets** — there is no
source-file overlap between lanes. The only shared files are `CHANGELOG.md` and the review doc's status
column (handled in §D). So all five lanes can run **fully in parallel** with near-zero contention; Lane A
just takes **merge priority** because it is the only High.

**Autonomy: L1** — workers build + verify (full quartet) + commit **local**; the **owner** opens/merges PRs.
Single-writer coordination ledger in AI memory. Worktree-per-lane off `origin/main` @ `0febba9`.

---

## A. Findings → lanes

| Lane | Finding(s) | Severity | Fix in one line | Primary file(s) |
|---|---|---|---|---|
| **L-A hl7-parser-hardening** | DELTA-01, DELTA-02 | **High** + Medium | Clamp + guard the repetition-escape count in built-in unescape | `parsing/_builtin_hl7.py`, `parsing/peek.py` |
| **L-B xml-dsig-anchor** | DELTA-03 | Medium | Require an explicit trust anchor in `verify()` (no OS-CA default-trust) | `parsing/xml/signature.py` |
| **L-C fhir-lookup-egress** | DELTA-04 | Medium | Gate `smart_token_url` against `[egress].allowed_http` on the lookup arm | `pipeline/wiring_runner.py` |
| **L-D support-bundle-disclosure** | DELTA-05, DELTA-07 | Low + Low | Strip store host/db-name from the bundle; align its redactor with the engine's | `support/bundle.py`, `support/redact.py` |
| **L-E http-listener-framing** | DELTA-06 | Low | Reject ambiguous CL/TE framing in the request parser | `transports/http_listener.py` |

Each lane = **one coherent PR**. L-A and L-D each fix two findings that share a file/theme, so they stay
one PR apiece; the rest are one finding = one PR.

---

## B. Lane detail (worktree per lane off `origin/main` @ `0febba9`)

> `scripts/worktree/new.ps1 -Name <lane>` (isolated checkout + branch + `.venv`); cleanup `remove.ps1`.
> See [`docs/WORKTREES.md`](../WORKTREES.md). Every lane: **new behavior gets a test**, then the full quartet
> green before the owner PRs it.

### L-A — HL7 parser hardening (DELTA-01 High, DELTA-02 Medium) — **P0, merge first**
- **Root cause (one line, one block):** `parsing/_builtin_hl7.py:527-528` —
  `out.append(default_map[value[:3]] * int(value[3:]))` — the repetition count is **unbounded** (DELTA-01
  DoS) **and** `int(value[3:])` is **unguarded** (DELTA-02 `ValueError`). Contrast the hex branch just below
  (lines 534-539), which already wraps its `int(...)` in `try/except ValueError: continue`.
- **Fix:**
  1. Introduce a small module constant (e.g. `MAX_ESCAPE_REPEAT`, a few hundred) and, in the `.`-prefix
     repetition branch, wrap the conversion + multiply in `try/except ValueError` and reject counts above the
     cap. Treat an over-limit or non-numeric count as an **unmappable** sequence → `continue` (drop it),
     matching the existing "log-and-discard" behavior for other unmappable escapes.
  2. Defense-in-depth: broaden `parsing/peek.py` `_resolve_builtin` (~lines 189-192) to map `ValueError` to
     `None` like it already does `IndexError`, so a stray conversion error can never escape a `Peek.field`
     read.
- **Tests:** unit — `\.in2000000000\` expands to a **bounded / dropped** result (no multi-GB allocation);
  `\.inX\`, `\.in \`, `\.br9z\` do **not** raise and the field reads cleanly. Pipeline/integration — a
  message whose `PID-3.1` carries a malformed count is still **persisted with a disposition** (`RECEIVED`),
  proving the **count-and-log invariant** holds (DELTA-02's real bite). Use synthetic HL7 only.
- **Verify:** this is the **default hot-path parser** — run the **full** suite (not a subset), and confirm
  the parse-fallback guard + count-and-log paths behave. No new deps.

### L-B — XML-DSig anchor enforcement (DELTA-03 Medium)
- **Fix:** in `parsing/xml/signature.py` `verify()` (~lines 44-60), **raise** `XmlError`/`ValueError` when
  **both** `x509_cert` and `ca_pem_file` are `None`, instead of forwarding to signxml's "trust any
  system-CA cert" default. Update the docstring to state an anchor is **mandatory**. Mirror the explicit-key
  posture already in `transports/signing.py`.
- **Tests:** a document signed by an arbitrary system-trusted cert **fails** `verify()` when no anchor is
  passed (now raises); a document verified **with** a pinned `x509_cert` / partner `ca_pem_file` still passes.
- **Callout (owner sign-off):** this is an intentional **secure-by-default behavior change** — `verify()`
  now requires an anchor. The audit's caller grep found **no in-repo consumer** relying on the old default
  (only package `__init__` re-exports import it), so blast radius is a hypothetical external Handler. Flag it
  in the PR / CHANGELOG as a breaking change for that opt-in codec.

### L-C — FhirLookup egress gate (DELTA-04 Medium)
- **Fix:** in `pipeline/wiring_runner.py` `check_fhir_lookup_allowed` (~lines 2831-2842), after validating the
  FHIR base `url`, read `settings.get("smart_token_url")`; if set, require
  `_http_egress_allowed(token_url, egress.allowed_http)` and honor `deny_by_default` — the exact check the
  **outbound** arm already performs (~lines 3086-3097). **Factor a shared helper** so the read-side lookup and
  write-side outbound gates stay in lockstep (they diverged, which is how this gap opened). This realizes
  ADR 0043 §D3 ("`smart_token_url` must be checked against `[egress].allowed_http`").
- **Tests:** a FhirLookup with an **un-allow-listed** `smart_token_url` is **rejected** at load (mirror the
  existing outbound test); an allow-listed one loads.
- **Note:** sole toucher of the large `wiring_runner.py` among these lanes; if a sibling wave lands there,
  rebase and re-run the start / reload / dry-run guard tests.

### L-D — Support-bundle disclosure (DELTA-05 Low, DELTA-07 Low)
- **Fix DELTA-05:** in `support/bundle.py` (~line 137), **omit/redact** the SQL Server store **host** and
  **database name** from `status.json` — the bundle's stated no-host/no-path contract. Keep the useful
  non-identifying status (backend kind, health) but drop the DSN-derived host/db.
- **Fix DELTA-07:** in `support/redact.py` (~line 27), replace the fixed segment allowlist with alignment to
  the **engine redactor** (`messagefoundry/redaction.py`) — ideally **reuse** it rather than maintain a
  weaker second redactor — so free-text name/DOB heuristics are applied to bundled logs.
- **Tests:** bundle `status.json` contains **no** store host/db-name; the bundle log redactor scrubs the
  free-text PHI patterns the engine redactor catches (parametrize against a synthetic sample).
- **Note:** two `support/` files, one theme (off-box bundle info-disclosure) → one PR. PHI rule: build the
  fixtures from **synthetic** data only.

### L-E — HTTP listener framing (DELTA-06 Low)
- **Fix:** in `transports/http_listener.py` (~line 180) reject **ambiguous framing** per RFC 7230 — a request
  bearing both `Content-Length` and `Transfer-Encoding`, or **multiple/duplicate** `Content-Length` values →
  respond `400` and close, rather than parsing one interpretation. (Self-desync is currently blunted by
  `Connection: close`, so this is hardening the surface, not closing a live smuggle.)
- **Tests:** a request with duplicate `Content-Length` or `CL`+`TE` is **rejected** (400), not parsed; a
  well-formed request is unaffected.

---

## C. Land-order

1. **L-A first** — the only High, and it is on the unauthenticated pre-ACK hot path. Merge before a release.
2. **L-B / L-C / L-D / L-E** — parallel, any order; all lower severity and fully independent. No lane blocks
   another (disjoint files).
3. Each lane: **full quartet** green — `ruff format --check` + `ruff check` + `mypy` (strict) +
   `pytest` (with `QT_QPA_PLATFORM=offscreen`) — **before** the owner opens the PR. Run the **whole** pytest
   suite, never a subset (the leak-gate / forbidden-content jobs only fire on a full run).

**Suggested session mapping** (they collapse to fit however many sessions you want to run):
- *Max parallelism:* five worktrees, one per lane.
- *Recommended (2–3 sessions):* one session owns **L-A** (priority, verify-heavy); a second session sweeps
  **L-B → L-C** (both small logic + test); a third (or the second, sequentially) sweeps **L-D → L-E**.
- *Minimum:* a single session does all five sequentially in one worktree, one PR at a time (still five PRs).

---

## D. Contention matrix

| File(s) | Lanes | Resolution |
|---|---|---|
| **Source files** (`_builtin_hl7.py`+`peek.py`; `xml/signature.py`; `wiring_runner.py`; `support/*`; `http_listener.py`) | disjoint per lane | **No overlap.** No cross-lane rebasing of product code. |
| **`CHANGELOG.md`** | all five | Each PR adds its own line (additive). Last-writer rebases, or the **owner consolidates** the five lines at merge. |
| **`docs/reviews/DELTA-REVIEW-2026-07-01.md`** (status column) | all five | **Do not** have each lane edit the review doc (write contention). The **coordinator/owner** flips each finding's status to *fixed (PR #…)* **once**, after merge. |
| **Test files** | per lane | Each lane adds tests in its subsystem's existing test module or a new one — disjoint. |

---

## E. Coordination rules

1. **Worktree per lane**, branched off `origin/main` @ `0febba9`. **Never edit a sibling worktree.** Use the
   lane's own `.venv` (`.\.venv\Scripts\Activate.ps1`) — the six other active worktrees share this repo's
   history but **not** the checkout.
2. **Single-writer coord ledger** in AI memory (one session writes live status; others read). One logical
   lane per session. **This session does not own memory writes unless the owner confirms it** (parallel
   sessions; last write wins).
3. **Autonomy L1:** build + verify + commit **local**; the **owner** opens/merges PRs. Do **not** push, open a
   PR, or merge without an explicit owner "go".
4. **`git add` explicit paths** — the repo pre-tool hook blocks `git add -A` / `git add .`. Stage the exact
   files.
5. **Commit trailer:** **omit** the `Co-Authored-By: Claude` trailer — the CLA bot fails on it (project
   convention; supersedes the older note in `MULTISESSION-PLAN-6.md`). One coherent layer per commit.
6. **Auto-merge + CI gate:** branches off `0febba9` post-date the CI-gate roll-up, so no `git merge main`
   catch-up is needed; still, rebase if `origin/main` advances before your PR merges.

---

## F. Build gotchas (checklist — apply per lane)

1. **SPDX header** on every **new** `.py` (e.g. a new test module) — the header sweep only covered
   pre-existing files. Editing an existing file needs none.
2. **No new runtime deps expected** — all five are logic/validation changes. If a lane somehow needs one,
   follow **DEP-1**: add to `pyproject.toml`, then re-lock from the **repo root** (`uv lock` / `uv export`),
   never `uv export --directory`. Verify the package is real before adding (§7 of `CLAUDE.md`).
3. **Crypto-inventory gate does NOT trip here:** L-B (`signature.py`/signxml) and L-C (SMART JWT signing)
   touch **existing** modules already in `scripts/security/crypto_inventory_check.py`. The gate only fires on
   a **new** `.py` importing `hashlib`/`hmac`/`secrets`/`ssl`/`cryptography`/`argon2` — none is introduced.
4. **L-A is the default hot-path parser:** run the **full** suite and add a **pipeline-level** test that a
   malformed-count message still records a disposition — the DELTA-02 fix must preserve **count-and-log** and
   **at-least-once**, not just stop the crash.
5. **PHI rule:** all fixtures are **synthetic** HL7/XML. Never real PHI; never customer host/IP/port/site
   names in code, tests, or the CHANGELOG. L-D specifically asserts the *absence* of host/db-name — build its
   fixtures with fake DSNs.
6. **L-B behavior change** (`verify()` now raises without an anchor) — call it out in the PR and CHANGELOG as
   an intentional secure-by-default break for the opt-in XML codec.

---

## G. Owner-gated / decision callouts

- **Merge order & PRs (all lanes):** L1 autonomy — the owner opens and merges every PR. Recommended: merge
  **L-A before the next release**; the rest can trail.
- **L-B secure-by-default break:** owner sign-off that requiring an explicit anchor is acceptable (it is the
  correct posture; the audit found no in-repo caller depending on the old default).
- **L-D redactor unification:** owner call on whether L-D should **reuse** the engine redactor outright
  (preferred) vs. only strengthen the bundle's local one — the former is cleaner but touches the shared
  redaction seam.

---

## H. Definition of done (per lane)

- The finding's fix is in place with a **regression test** that fails before / passes after.
- Full quartet green on the lane's own `.venv`: `ruff format --check` · `ruff check` · `mypy` (strict) ·
  `pytest` (offscreen, **full** suite).
- One coherent local commit (no co-author trailer), explicit-path staged, ready for the owner to PR.
- CHANGELOG line drafted; the review-doc status flip is left to the coordinator/owner (§D).

**Aggregate done:** all five PRs merged; `docs/reviews/DELTA-REVIEW-2026-07-01.md` status column updated to
*fixed (PR #…)* for DELTA-01 … DELTA-07 by the coordinator.
