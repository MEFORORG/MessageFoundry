- **The anonymizers' coverage record for a bare line now gives its position, and a header that
  is only `MSH|^~\&` is refused.** A passed bare line is recorded in each message's report as,
  for example, `PV2 at line 3 (line with no fields)` rather than `PV2 (line with no fields)`, on
  the engine and the tee. The position counts only lines that hold something. The run summary
  still counts such lines by segment id alone. A header of only `MSH|^~\&` holds no MSH-12, so
  every other line used to be judged against the segment ids of every HL7 version; both
  anonymizers now refuse it as a line no rule can reach. A header of three or more split fields
  with an empty MSH-12 is not refused, and still gets that any-version reading. See
  [PHI.md](../docs/PHI.md) section 9. (`BACKLOG #3001`)
