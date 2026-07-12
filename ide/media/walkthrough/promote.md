When the graph is ready, **Stage → Promote** ships it to a running engine. The flow is guided and
safe:

1. **Stage** — validates the local config; any error blocks the promote (it opens Problems).
2. **Target** — pick the environment (and engine instance, if several) from `messagefoundry.environments`.
3. **Pre-flight** — dry-runs the graph against that target, resolving its `env()` values there, so a
   missing value fails *before* anything goes live.
4. **Confirm & apply** — an atomic quiesce-and-swap reload on the engine; nothing changes until you confirm.

Promotion is authenticated to the (auth-required) engine, and an off-box target must be confirmed by
host name before any credential is sent.
