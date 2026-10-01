Turn on **Live Debug** to get a Corepoint-style feedback loop over your real Python — no engine, no
sending. Toggle it from the **MEFOR Live** status-bar item; then every time you save a config module
it re-runs a dry-run against a **synthetic** sample and annotates your code in place:

- a routing/disposition summary above each `inbound()` / `@router` / `@handler`;
- per-line values of the locals and `msg[...]` writes each executed line produced.

Message-derived values are PHI, so they render **redacted by default**. While Live Debug is on, click
**Values: Hidden** in the status bar to re-run once with real values shown. The command **Reveal
Values for One Run** does the same, and turns Live Debug on first if it is off. The reveal covers that
one run: your next save runs masked again. On a masked run, hovering the summary tells you how many
messages failed, not why; reveal to read the error. Use synthetic samples only. Live Debug never
contacts a real engine.
