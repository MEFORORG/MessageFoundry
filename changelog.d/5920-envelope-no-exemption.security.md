- **Strict validation refuses a dropped header, continuation or acknowledgment segment in an "any
  HL7 segment" structure.** In a structure such as `MFN_M01`, a `BHS`, `FHS`, `DSC`, `MSA` or `ERR`
  line that `hl7apy` could not place was passed and listed in `unvalidated_segments`. It is now
  refused. (`BACKLOG #5920`)
