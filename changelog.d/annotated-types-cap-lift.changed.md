- **The `[fhir]` extra now needs `fhir-core>=1.1.11`, and annotated-types is no longer capped.**
  `pyproject.toml` capped annotated-types below 0.8 because fhir-core 1.1.9 imported the `SLOTS`
  constant that 0.8.0 removed. fhir-core 1.1.10 defines it itself, so the cap is gone from the core
  dependencies and from `[fhir]`, and the lock moves to annotated-types 0.8.0. fhir-core 1.1.11 also
  refuses negative `positiveInt` and `unsignedInt` values, which its own changelog says earlier releases let through.
