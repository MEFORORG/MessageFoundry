# WIN2025 Acceptance Harness

Executable runner for [`WIN2025-TEST-MATRIX.md`](WIN2025-TEST-MATRIX.md). Each matrix row is bound to
a **probe** (a live host check), the existing **pytest** suites that already assert it, a **harness**
command, or a **manual** step. The runner executes what it can on the box it runs on, marks the rest
MANUAL (never faked green), and prints/writes a PASS/FAIL/SKIP/MANUAL report.

It lives at [`harness/acceptance/`](../../harness/acceptance/) and reuses the existing test suites and
load/failover harness — it is **not** a parallel test framework. Build it on the dev PC; run the full
pass on the Windows Server 2025 box (see the matrix's dev-PC-vs-server split).

## Run it

```powershell
# Full pass: live host probes + the backing pytest suites (server-DB suites self-skip if unreachable)
python -m harness.acceptance

# Fast host check only — no suite run (good first smoke on a fresh box)
python -m harness.acceptance --no-pytest

# Only some sections (A=environment, B=DB setup, …, H=perf/security)
python -m harness.acceptance --section A,B,C

# Write reports, and stamp verdicts back into the matrix workbook's Status column (needs openpyxl)
python -m harness.acceptance --report-md out.md --report-csv out.csv --xlsx WIN2025-TEST-MATRIX.xlsx
```

**Exit codes:** `0` = no FAIL/ERROR (MANUAL/SKIP do not fail the run), `1` = at least one FAIL/ERROR,
`2` = bad usage / report write error.

## Make the per-DB rows actually run

The `Per-DB x3` rows run against whatever backends the environment exposes. Off-server (dev PC) the
two server-DB suites **self-skip** and report `SKIP`. On the target box, set the gates so they run for
real (same env the CI legs use):

```powershell
# SQL Server
$env:MEFOR_TEST_SQLSERVER = "1"
$env:MEFOR_STORE_BACKEND = "sqlserver"; $env:MEFOR_STORE_SERVER = "<host>"
$env:MEFOR_STORE_DATABASE = "MessageFoundry"; $env:MEFOR_STORE_AUTH = "sql"
$env:MEFOR_STORE_USERNAME = "<user>"; $env:MEFOR_STORE_PASSWORD = "<secret>"

# PostgreSQL
$env:MEFOR_TEST_POSTGRES = "1"
$env:MEFOR_STORE_BACKEND = "postgres"; $env:MEFOR_STORE_SERVER = "<host>"
$env:MEFOR_STORE_DATABASE = "messagefoundry"; $env:MEFOR_STORE_USERNAME = "<user>"
$env:MEFOR_STORE_PASSWORD = "<secret>"
```

Run each backend in its own invocation (the gates select one backend at a time), then merge the
reports — or just read the Status column after each pass.

## Coverage kinds

| Kind | How it runs | Reported |
|---|---|---|
| **probe** | live host check in [`probes.py`](../../harness/acceptance/probes.py) | PASS/FAIL/SKIP/MANUAL |
| **pytest** | the existing suites, once via `pytest --junitxml` | per-file PASS/FAIL/SKIP/ERROR |
| **harness** | `python -m harness …` against a live engine | MANUAL + the command to run |
| **manual** | a human step the box gates (AD login, NSSM, visual no-flash) | MANUAL + instructions |

The matrix↔code binding is guarded by [`tests/test_win2025_acceptance.py`](../../tests/test_win2025_acceptance.py):
every probe key is registered, every referenced pytest file exists, and no probe raises. That guard
runs in normal CI, so the matrix can't silently rot.

## What CI already covers vs. what only the server can

The automatable rows (B/C backend parity, D connector round-trips, G failover) already run per-merge
in CI against real SQL Server (2022 **and** 2025) and Postgres service containers. What CI cannot
replicate — and what this on-server pass exists for — is the **host**: the OS ODBC driver (A3),
firewall (A5), service-account ACLs (A6), a real desktop session (A7), AD/Kerberos against your
domain (F1), the visual no-console-flash check (F7), and NSSM on Server 2025 (G1).
