- **Strict validation refuses a dropped envelope or acknowledgment segment in an "any HL7 segment"
  structure.** In a structure such as `MFN_M01`, a `BHS`, `BTS`, `FHS`, `FTS`, `MSA` or `ERR` line
  that `hl7apy` could not place was passed and listed in `unvalidated_segments`. It is now refused,
  as `MSH` already was. (`BACKLOG #5920`)
