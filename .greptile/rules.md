# MessageFoundry review notes

MessageFoundry is an HL7 and healthcare message engine. It is a not-deployed beta: no site runs it.
The structured rules in `config.json` cover the high-severity checks. These notes cover how to word
findings and what to leave alone.

## Read the review sheet first

`docs/REVIEW-STANDARDS.md` holds rules R1 to R17. Cite the rule number in a finding, for example
"R12: SQL built by string formatting". Do not raise anything its "Already enforced" table covers.
Ruff, strict mypy, bandit, gitleaks and the pre-commit hooks already run on every change.

## Word findings in the conditional

- Write "would expose X on first deployment", never "PHI is exposed" or "users are affected".
- Never cite "not deployed" to lower a finding's severity.
- Do not ask for a compatibility shim, deprecation window or staged migration. Nobody runs the old
  version, so the simple end state is preferred.
- Write plain words. No emoji or other glyphs in comments or suggested code.

## Project terms

- The building blocks are Connection, Router and Handler. Flag new code or docs that call them
  "source", "destination", "filter step" or "transformer". The existing `SourceConnector` and
  `DestinationConnector` class names are fine.
- Always write "engine shard" or "database shard", never a bare "shard".
- Routers and Handlers are pure. A Handler may call the read-only `db_lookup` or `fhir_lookup`. A
  Router may not.

## Layering

- The operator UI is the web console at `/ui`. Flag any new PySide6 operator screen.
- Async code never blocks the event loop and every worker loop honours its stop signal. Flag a
  handler that catches `CancelledError` and carries on.

## Test data

- HL7 in tests, fixtures and `samples/` must be synthetic. Flag anything that looks like a real
  person: a plausible name with a real-shaped MRN, SSN or address.
- Secrets come from `MEFOR_*` environment variables. Flag a key, password or token in code, tests or
  config examples.
