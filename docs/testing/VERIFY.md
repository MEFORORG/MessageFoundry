# `messagefoundry verify` — on-box deployment acceptance

A **wheel-only** acceptance check a real deployment runs with just the installed engine — no source
tree, no test suite. It answers "is *this* box set up right, and does a message actually flow?", which
is the on-box complement to CI (CI proves engine *conformance*: staged pipeline, FIFO, store parity,
parsing — against SQL Server 2025 + Postgres containers; `verify` proves the *deployment*).

It runs four sections — **host**, **store**, **smoke**, **manual** — and prints a PASS/FAIL/SKIP/MANUAL
report. Host/domain steps it can't self-check (AD login, NSSM, the visual no-console-flash check) are
reported **MANUAL**, never faked.

## Quick start

```powershell
# Everything (default smoke = self, which is side-effect-free):
messagefoundry verify --config <your config dir>

# Fast host-only check on a fresh box:
messagefoundry verify --section host --smoke none

# Live end-to-end against the running engine (sends ONE synthetic message):
messagefoundry verify --section smoke --smoke live --mllp-port 2575

# Per backend: point [store] at each DB, then check connectivity + a live message:
messagefoundry verify --section store,smoke --smoke live --service-config messagefoundry.toml

# Live + confirm the message actually PROCESSED (not just ACKed) — catches post-ACK dead-letters:
messagefoundry verify --section smoke --smoke live --check-disposition --service-config messagefoundry.toml

# Save reports:
messagefoundry verify --report-md verify.md --report-json verify.json
```

**Exit codes:** `0` = no FAIL/ERROR (MANUAL/SKIP don't fail), `1` = a FAIL/ERROR, `2` = bad usage.

## Sections

| Section | What it does |
|---|---|
| **host** | Python 3.11+ & engine import; optional driver extras (asyncpg / aioodbc+pyodbc / pydicom); **ODBC Driver 18** discoverable via `pyodbc.drivers()`; listener ports bindable (+ firewall = MANUAL); store/working dir writable (+ service-account ACLs = MANUAL); console importable; `CREATE_NO_WINDOW` present (no-flash). |
| **store** | Opens the configured store backend (`[store]`/`MEFOR_STORE_*`) and confirms it connects — **no test-data writes** beyond the idempotent schema-ensure. Run once per backend the box is pointed at. |
| **smoke** | `self` (default) routes a synthetic HL7 through your config via dry-run — **no store, no network, no side effects**; `live` MLLP-sends one synthetic message to the running engine and confirms an **AA ACK**; `none` skips. Add **`--check-disposition`** (+ `--service-config`) to also poll the store and **FAIL unless the message reached `PROCESSED`** (a new `smoke.disposition` row). |
| **manual** | Echoes the human-only steps (AD/Kerberos login, TOTP MFA, API bind+TLS, NSSM service, end-to-end disposition in the console) as MANUAL with instructions. |

## self vs live smoke
- **`--smoke self`** — safe anywhere (CI, a fresh box, before the engine is even running). Proves your
  routers/handlers load and route a message cleanly. Needs `--config <your config>` (and `--inbound
  NAME` if the config has several inbounds).
- **`--smoke live`** — proves the real listener accepts + ACKs on the running engine. It persists **one**
  synthetic message (recognizable synthetic patient); confirm its `RECEIVED→ROUTED→PROCESSED`
  disposition and outbound delivery in the **console** (the `manual.disposition` row), or automate that
  last mile with **`--check-disposition`** (below).

## What a green run proves — and what it doesn't
The **automated** rows prove "host OK + store reachable **as the calling user** + the listener **ACKs**" —
not that messages actually *process*. Two deliberate gaps to internalize:
- **`store.connect` opens the store as *you*** (the interactive / Administrator user), **not** the NSSM
  service account. A green `store.connect` does **not** prove the *service* identity can reach the store —
  confirm the service-account login/grants (the `host.writable` + `manual.disposition` rows flag this).
- **`smoke.live` is ACK-only.** An AA ACK means *received + persisted*, **not** *processed* — a message can
  ACK and then dead-letter (a bad transform, a delivery failure, the service-identity db-grant trap). The
  **`manual.disposition` console row is load-bearing**; for a headless / CI run, add **`--check-disposition`**
  so a post-ACK dead-letter **FAILs** the run instead of passing unnoticed. It correlates the sent message
  by MSH-10 control id and FAILs unless it reaches `PROCESSED` within `--disposition-timeout` (default 15s);
  it needs `--service-config` pointing at the engine's store.

## Per-DB validation (all three backends)
The box "has all three databases", so validate each the way a real user would — point the engine's
`[store].backend` (or `MEFOR_STORE_BACKEND` + `MEFOR_STORE_*`) at each, then:

```powershell
$env:MEFOR_STORE_BACKEND = "sqlserver"   # then the sqlserver connection env
messagefoundry verify --section store,smoke --smoke live
# repeat for postgres, and for sqlite
```

Secrets (DB creds) come from `MEFOR_*` env only — never a file or the report.

## What CI covers vs. what only the box can
CI already runs the engine-conformance suites per-merge against **SQL Server 2025 + Postgres**
containers. What CI can't replicate — and what `verify` is for — is the **host**: the OS ODBC driver,
firewall, service-account ACLs, a real desktop session, AD/Kerberos against your domain, the visual
no-console-flash check, and NSSM on Server 2025. Those are the MANUAL/host rows here.
