- **BREAKING -- an unknown top-level section in `messagefoundry.toml`, or a key written above the
  first `[section]` header, now fails the start instead of loading silently.** This extends the
  0.4.0 refusal of an unrecognized key one level up. A misspelt section dropped every key under it
  at once: `[integrty]` with `fail_closed_on_drift = true` loaded clean and left the opt-in
  integrity tripwire alert-only while the operator believed it failed closed. The error names the
  section and the nearest real section name, and never the value. The scope is the config FILE
  only, as for keys: a `MEFOR_*` variable naming no section is still dropped by the env layer.
  `[engine]`, which [CONFIGURATION.md](../docs/CONFIGURATION.md) used to describe as a tolerated
  section with no model, is refused like any other.
  **Who this would bite on first deployment:** a config file carrying a section the engine does
  not model, such as a typo or a section copied from newer documentation. **Remedy:** correct the
  spelling, or remove the section; it was doing nothing before. (2026-10-02 full review,
  decision 10)
