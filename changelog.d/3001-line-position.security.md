- **The anonymizers' coverage record for a bare line now gives its position, and a bare line
  under a header with no readable HL7 version is refused.** A passed bare line is recorded in
  each message's report as, for example, `PV2 at line 3 (line with no fields)` rather than
  `PV2 (line with no fields)`, on the engine and the tee. The position counts only lines that
  hold something. The run summary counts such lines by segment id alone, once per message. A
  header of only `MSH|^~\&` is refused as a line no rule can reach. When the header's MSH-12 holds
  no readable version (at least: empty, not digits joined by single dots, or older than 2.1), at
  any field count, a bare line used to be judged against the segment ids of every HL7 version;
  both anonymizers now refuse it unless a rule that rewrites a field names its segment. The
  text of a line no rule can reach, in the `AnonError`, the leak report's hits and the tee's
  output, changed, so a caller that matches the old text must change. See
  [PHI.md](../docs/PHI.md) section 9. (`BACKLOG #3001`)
