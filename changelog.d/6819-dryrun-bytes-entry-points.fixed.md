- **A bytes body reaches the dry run's public entry points in the listener's form.**
  `route_message`, `route_only` and `transform_one` took `bytes` but decoded them as UTF-8, so a
  DICOM or latin-1 body raised a bare `UnicodeDecodeError`, a binary body that happened to be
  UTF-8 reached the Handler without its base64 carriage (ADR 0028), and a latin-1 HL7 body reached
  it with its accented letters replaced. `route_message` and `route_only` now carry or decode
  `bytes` as the listener does, with the inbound's declared charset, and raise
  `IngressGuardError` for a body the decode, carriage or size guards refuse. `transform_one` has no
  inbound: it carries a binary type's bytes, and refuses bytes for a non-HL7 text type with a
  `TypeError`, since it cannot know their charset. (`BACKLOG #6819`)
