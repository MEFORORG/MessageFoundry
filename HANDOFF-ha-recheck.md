# HANDOFF — HA re-check / ADR 0157

Updated 2026-08-02. Supersedes the stop-work handoff written earlier the same day.

**The authoritative status is [ADR 0157](docs/adr/0157-demotion-safety-fence-scope-on-post-claim-writes-and-a-bounded-graph-stop.md) itself** — it carries the decisions, the corrections and the per-increment build state. This file holds only what does not belong in an ADR: what is left, and the traps that cost time.

## 1. State

| | |
|---|---|
| ADR 0157 | **Accepted.** Increments **1, 4, 5 built**; 0, 2, 3 not built |
| PR | [#139](https://github.com/MEFORORG/MessageFoundry/pull/139) |
| Earlier | #129 merged (`884036f8`) — the doc corrections |

## 2. What is left

**Inc 0 — make the margin real.** The demotion budget does not subtract the lease-renew round trip, which is bounded only by `[store].command_timeout` (30.0) — *equal* to the stock lease TTL. Until that is clamped, the derived 4.5s budget is nominal, not guaranteed. The floor clamp means a bad margin degrades to *overlap* (duplicates, permitted) rather than hard-cancel-always (INFLIGHT residue, strand-direction on SQL Server), so this is a real gap and not an emergency.

**Inc 2 — ⛔ MIS-SPECIFIED IN THE ADR. Do not build it as written.** It proposes an owner-blind, age-based periodic sweep. SQL Server has **no populated `owner` column** to discriminate with, so that sweep would re-pend rows a live leader is actively working. The verified defect is narrower — there is no recovery at **graph re-start**, because `RegistryRunner.reload()` is a quiesce-and-swap that calls no recovery — and the fix is a scoped reset there. Re-scope first.

**Inc 3 — SQL Server fences.** Blocked on Inc 2. Its own gate: pin empirically, on the live CI leg, whether a coroutine cancelled mid-`execute` leaves an aioodbc transaction committed or rolled back (`except Exception: await conn.rollback()` does **not** catch `CancelledError`).

> **A green Postgres run does not license the same edit on `sqlserver.py`.** The two backends' recovery guarantees differ, and that difference is the whole argument for D1.

**Also deferred (D10):** the own-owner promotion-recovery statement. It must be lease-expiry-bounded to be safe, and every claim stamps `lease_until = now + lease_ttl_seconds`, so it is a no-op exactly when it would be needed.

## 3. Traps that cost real time

- **Local `pytest` SILENTLY SKIPS the Postgres and SQL Server legs.** A green laptop run proves nothing about either backend. There is a `mefor-pg-ci` container (postgres:16) on **port 5433** matching CI's fixtures — use it:
  ```
  MEFOR_TEST_POSTGRES=1 MEFOR_STORE_BACKEND=postgres MEFOR_STORE_SERVER=localhost \
  MEFOR_STORE_PORT=5433 MEFOR_STORE_DATABASE=messagefoundry MEFOR_STORE_USERNAME=postgres \
  MEFOR_STORE_PASSWORD=mefor MEFOR_STORE_ENCRYPT=false MEFOR_ALLOW_INSECURE_TLS=1
  ```
- **A new module-gated suite executes NOWHERE until it is named in a workflow.** `tests/test_serverdb_ci_coverage.py` catches this; it caught this branch. Add the file to the `sqlserver-store` / `postgres-store` job **and** to the `serverdb` change-detection alternation in `ci.yml`.
- **`leader_lease` is not in `tests/test_postgres_store.py`'s `_TABLES`**, so a row seeded by one test survives into the next. Any test whose premise is "no lease row" must delete it explicitly — `test_epoch_guard_disabled_when_none_is_byte_identical`'s own comment is a false premise for exactly this reason.
- **`mypy` reports 21 phantom errors** unless the venv has the full extras: `pip install --constraint constraints.lock -e ".[dev,harness,postgres,sqlserver,fhir,dicom,x12,xml,webauthn,sftp,vault,otel]"`.
- **Pre-commit needs `ruff` on PATH** in the worktree. Activate `.venv` or prepend it. **Never `--no-verify`.**
- **A full local suite with the Postgres env set produces failures that isolation does not** — the `[postgres]`-parametrized suites share one database and contaminate each other. Before attributing any failure, re-run the same set the same way with your diff reverted. Measuring a different quantity is not a measurement.

## 4. The methodological point worth keeping

Two gates written for this work were **blind to the exact class they existed to catch**, and only a deliberate mutation found it:

- The structural fence gate keyed on whether a method *mentioned* `_EPOCH_GUARD_CLAIM`. Deleting `{epoch_guard}` from `claim_fifo_heads`' SQL — the precise regression — left the mention intact and the gate stayed **green**. It now keys on the emitted SQL.
- An earlier session's first version of the `c20295c0` tests asserted a row was `PENDING` with `attempts=0`, which passes against the *pre-fix* code because a seeded row is already in that state.

Both were caught by attacking the control, not by reading it. Build the gate, then try to slip the defect past it.
