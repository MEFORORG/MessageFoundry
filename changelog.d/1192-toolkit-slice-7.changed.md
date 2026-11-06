- **The synthetic HL7 generators and the HL7 schema emitters leave the engine wheel.** ADR 0201
  slice 7 moves `messagefoundry/generators/`, `messagefoundry/hl7schema.py` and
  `messagefoundry/hl7structures.py` into `messagefoundry_toolkit/`, so they ship in the
  `messagefoundry-toolkit` distribution and an engine-only install no longer carries them. Import
  them as `messagefoundry_toolkit.generators`, `messagefoundry_toolkit.hl7schema` and
  `messagefoundry_toolkit.hl7structures`, and run the ADT corpus writer as
  `python -m messagefoundry_toolkit.generators.adt`. What they produce is unchanged, and so are
  `messagefoundry-toolkit generate`, `hl7schema` and `hl7structures`. The test harness now depends
  on `messagefoundry-toolkit` at its own version, beside its engine pin. The release member gate
  now refuses an engine wheel or sdist that carries a member under `messagefoundry/generators/`, or
  `messagefoundry/hl7schema.py` or `messagefoundry/hl7structures.py`. (BACKLOG #1192)
