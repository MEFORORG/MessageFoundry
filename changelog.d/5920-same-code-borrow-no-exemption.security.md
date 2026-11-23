- **Strict validation checks MSH-9.2 against MSH-9.3 before a borrowed "any HL7 segment"
  structure keeps its exemption.** This is a consistency check on what a message says about
  itself, not a barrier: a sender controls all of MSH-9, and one that names a structure's own
  event keeps the exemption. A message that names such a structure in MSH-9.3 under its own
  message code, as `MFN^M02^MFN_M01` does, had dropped defined segments passed and listed in
  `unvalidated_segments`. They are now refused where MSH-9.2 names a trigger event that has a
  structure of its own in `hl7apy`'s tables, or a non-Z event that is not in the version's HL7
  table 0003 as `hl7apy` ships it. A site-defined Z event (`QBP^Z44^QBP_Q15`) and a message with
  no MSH-9.3 are unchanged. (`BACKLOG #5920`)
