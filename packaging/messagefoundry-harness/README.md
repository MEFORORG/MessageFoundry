# messagefoundry-harness

The standalone **test harness** for
[**MessageFoundry**](https://github.com/MEFORORG/MessageFoundry) — the open-source healthcare
integration engine (HL7 v2.x and more). This package is synthetic-only tooling to exercise a running
engine: an interactive **send/receive (MLLP)** GUI, a headless **load** engine (rate/concurrency
profiles, latency + throughput, drain / no-loss checks), and a two-node **failover-under-load** harness
for the clustered SQL Server / PostgreSQL store.

> Published **in lockstep with the engine** — install the version that matches your `messagefoundry`.
> All traffic is **synthetic, PHI-free** generators. This is a test/ops tool, **not** part of the
> engine runtime — the `messagefoundry` engine wheel does not contain it.

## Install

```bash
pip install "messagefoundry-harness==<version>"   # pulls messagefoundry[console] (engine + API client + PySide6)
```

## Use

```bash
python -m harness                                                                 # send/receive/compose/monitor GUI
python -m harness --list-profiles                                                 # list built-in load profiles
python -m harness --load reference --engine http://127.0.0.1:8765 --token <T>     # headless load run
python -m harness --failover failover --db-backend sqlserver                      # two-node SIGKILL-under-load
```

See the [load-testing guide](https://github.com/MEFORORG/MessageFoundry/blob/main/docs/LOAD-TESTING.md)
and the `harness/` sources in the repo for details.
