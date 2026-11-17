- **Strict validation refuses a dropped continuation or acknowledgment segment in an "any HL7
  segment" structure.** In a structure such as `MFN_M01`, a `DSC`, `MSA`, `ERR`, `QAK` or `MFA`
  line that `hl7apy` could not place was passed and listed in `unvalidated_segments`. It is now
  refused. Batch and file envelope lines keep the exemption. (`BACKLOG #5920`)
