# MessageFoundry review notes

MessageFoundry is an HL7 and healthcare message engine. It is a not-deployed beta: no site runs it.
The structured rules in `config.json` cover the high-severity checks. These notes cover how to word
findings and what to leave alone.

## Read the review sheet first

`docs/REVIEW-STANDARDS.md` holds rules R1 to R17. Cite the rule number in a finding, for example
"R12: SQL built by string formatting". Do not raise anything its "Already enforced" table covers.
CI runs Ruff and strict mypy (`ci.yml`) and bandit and gitleaks (`security.yml`). The table's hook
rows run only where a contributor installed the pre-commit hooks.

## Word findings in the conditional

- Write "would expose X on first deployment", never "PHI is exposed" or "users are affected".
- Never cite "not deployed" to lower a finding's severity.
- Do not ask for a compatibility shim, deprecation window or staged migration. Nobody runs the old
  version, so the simple end state is preferred.
- Write plain words. No emoji or other glyphs in comments or suggested code.

## Project terms

- The building blocks are Connection, Router and Handler. Flag new code or docs that call them
  "source", "destination", "filter step" or "transformer", where the project term fits. The
  existing `SourceConnector` and `DestinationConnector` class names are fine.
- Always write "engine shard" or "database shard", never a bare "shard".
- Routers and Handlers are pure. A Handler may call the read-only `db_lookup` or `fhir_lookup`. A
  Router may not.

## Layering

- The operator UI is the web console at `/ui`. Flag any new PySide6 operator screen.
- Async code never blocks the event loop and every worker loop honours its stop signal. Flag a
  handler that catches `CancelledError` and carries on.

## Test data and secrets

- The `synthetic-test-data` rule in `config.json` covers test, fixture and sample data.
- Secrets come from `MEFOR_*` environment variables. Flag a real-looking key, password or token in
  code or config examples. A throwaway password in a test, or a key a test mints at runtime, is
  fine.
