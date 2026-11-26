- **A bytes body reaches the dry run's public entry points carried or decoded for its inbound.**
  `route_message`, `route_only` and `transform_one` took `bytes` but decoded them as UTF-8, so a
  DICOM or latin-1 body raised a bare `UnicodeDecodeError`, a binary body that happened to be
  UTF-8 reached the Handler without its base64 carriage (ADR 0028), and a latin-1 HL7 body reached
  it with its accented letters replaced. `route_message` and `route_only` now base64-carry a
  binary type's `bytes` and decode any other type's with the inbound's declared charset, raising
  `IngressGuardError` for a body that carriage or decode refuses. They do not run every listener
  guard. `transform_one` has no inbound: it carries a binary type's bytes, and refuses bytes for a
  text type, HL7 included, with a `TypeError`, since it cannot know their charset.
  (`BACKLOG #6819`)
