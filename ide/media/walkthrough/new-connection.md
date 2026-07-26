A **Connection** receives (inbound) or sends (outbound) messages — MLLP, file, and more. Every
message a connection takes in or puts out is counted and logged; nothing is silently dropped.

```python
inbound("IB_ACME_ADT", MLLP(port=2575), router="adt_router")
outbound("OB_ACME_ADT", File(directory="./out/adt", filename="{MSH-10}.hl7"))
```

A connection can be authored two ways. **In code**, as above, which is what you want when the
connection is part of a feed you are already writing. **As data**, in `connections.toml`, which is
what the editor manages — handy for a shared endpoint several feeds sink to, and for anything an
operator should be able to retune without touching Python. Routing and transform logic always stays
in `.py`; `connections.toml` holds transport configuration only.

The Connection Wizard scaffolds one for you, named `[TYPE]_[PARTNER]_[MESSAGE]`, then opens the
editor. You can also open `connections.toml` directly — it has its own form editor — or use the gear
on any connection in the MessageFoundry view.

The form is built from **the engine you have installed**, not a fixed list: pick a transport and it
shows every setting that transport actually accepts, with its type, its default, and the explanation
from the engine itself. Essential settings come first; the rest are grouped and collapsed (TLS,
connection guards, and so on) so a long list stays readable.

A few behaviours worth knowing:

- **Credentials are never stored in the file.** A setting the engine marks as a secret offers only an
  environment-key box, so `connections.toml` carries `{ env = "KEY" }` and the value lives in your
  environment.
- **Blank means "use the engine's default".** Leaving a control empty omits the key entirely, so the
  file stays small and you inherit whatever the engine defaults to — including after an upgrade that
  changes that default.
- **Nothing you did not touch is lost.** Saving preserves every setting already on the connection,
  including keys this engine's version does not describe; those appear in their own group rather
  than disappearing.
- **A connection authored in `.py` is read-only here.** The gear opens its source instead — the
  editor only writes `connections.toml`.

Saves are validated before they land: a bad endpoint, an unknown router or a host your instance's
egress policy forbids is refused with the reason, and the file is left untouched.
