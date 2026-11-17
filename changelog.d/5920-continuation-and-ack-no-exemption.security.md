- **Strict validation refuses a dropped header, continuation or acknowledgment segment in an "any
  HL7 segment" structure.** In a structure such as `MFN_M01`, an `MSH`, `DSC`, `MSA`, `ERR`, `QAK`
  or `MFA` line that `hl7apy` could not place was passed and listed in `unvalidated_segments`. It
  is now refused. Other defined segments, the batch and file envelope lines among them, keep the
  exemption. (`BACKLOG #5920`)
