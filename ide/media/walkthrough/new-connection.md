A **Connection** receives (inbound) or sends (outbound) messages — MLLP, file, and more. Every
message a connection takes in or puts out is counted and logged; nothing is silently dropped.

```python
inbound("IB_ACME_ADT", MLLP(port=2575), router="adt_router")
outbound("OB_ACME_ADT", File(directory="./out/adt", filename="{MSH-10}.hl7"))
```

The Connection Wizard scaffolds one of these for you, named `[TYPE]_[PARTNER]_[MESSAGE]`.
