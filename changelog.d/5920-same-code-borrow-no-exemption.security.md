- **Strict validation compares MSH-9.2 before a borrowed "any HL7 segment" structure keeps its
  exemption.** A message that names such a structure in MSH-9.3 under its own message code, as
  `MFN^M02^MFN_M01` does, had dropped defined segments passed and listed in
  `unvalidated_segments`. They are now refused where MSH-9.2 names a trigger event that has a
  structure of its own in `hl7apy`'s tables, or one that is not in the version's HL7 table 0003
  as `hl7apy` ships it. A message with no MSH-9.3 is unchanged. (`BACKLOG #5920`)
