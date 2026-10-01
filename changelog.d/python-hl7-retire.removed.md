- **python-hl7 is no longer a dependency.** The engine's own tolerant parser (ADR 0054) has been the
  default since it merged, and python-hl7 was only its fallback. The fallback is gone, and so are
  the `parsing/_backend.py` switch and the logger silencer that existed for python-hl7. A fault
  inside the parser is now refused as `HL7PeekError`, which the listener NAKs `AR` and records as
  `ERROR`; before, it fell back to python-hl7. **BREAKING:** `Message.parse` on a body with no
  leading `MSH`, `FHS` or `BHS`, or with a header too short to read, now raises `HL7PeekError`, a
  `ValueError`, where it raised `hl7.ParseException` or an `IndexError`. A Handler that catches
  `ValueError` around it now catches that refusal too.
  The outbound MSH encoding-character override now re-encodes through the engine's parser too. A
  field whose escape character is never closed now reads with that text kept: `SMITH\` reads as
  `SMITH\`, where python-hl7 dropped it and read `SMITH` (upstream python-hl7 issue 84). The
  parity suite holds the parser to python-hl7 0.4.5's answers, recorded once before it left. (ADR
  0054 amendment)
