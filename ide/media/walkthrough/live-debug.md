Turn on **Live Debug** to get a Corepoint-style feedback loop over your real Python — no engine, no
sending. Toggle it from the **MEFOR Live** status-bar item; then every time you save a config module
it re-runs a dry-run against a **synthetic** sample and annotates your code in place:

- a routing/disposition summary above each `inbound()` / `@router` / `@handler`;
- per-line values of the locals and `msg[...]` writes each executed line produced.

Message-derived values are PHI, so they render **redacted by default**. Click **Values: Hidden** in the
status bar (or run **Reveal Values for One Run**) to re-run once with real values shown. The reveal
covers that one run: your next save runs masked again. Use synthetic samples only. Live Debug never
contacts a real engine.
