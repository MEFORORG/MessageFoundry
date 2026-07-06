# Test-message generators

Generators that emit **conformant HL7 v2.x** messages for testing channels and the engine.
Everything is synthetic — **no real PHI**.

## ADT (`adt.py`)

Generates HL7 **v2.5.1 ADT** messages for every trigger event (A01–A62, excluding the query
event A19 and reserved A56–A59 — 57 triggers across 25 message structures). Segment order and
the allowed segment set are driven by **hl7apy's own 2.5.1 reference tree**, and every message is
gated through the engine's strict validator (`messagefoundry.parsing.validate`) before it counts.

```powershell
# all triggers, 50 each -> samples/messages/adt/<TRIGGER>/0001.hl7 …
python -m messagefoundry.generators.adt

# a subset, fewer each, custom output
python -m messagefoundry.generators.adt --triggers A01,A04 --count 5 --out out/adt
```

The output corpus (`samples/messages/adt/`) is **git-ignored and regenerable** — it isn't
committed. The tests don't need it on disk: [tests/test_generated_adt.py](../../tests/test_generated_adt.py)
generates messages in-process (deterministic, seeded). The default run checks one message per
trigger plus the generator's units; set `MEFOR_FULL_CORPUS=1` to generate and re-validate all 2,850.

`_hl7data.py` holds the HL7 datatype encoders (CX/XPN/XAD/XCN/PL/CWE/TS) and the synthetic data
pools the generator draws from.
