- **The anonymizers' coverage record for a bare line now gives its line position, and a header
  that is only `MSH|^~\&` is refused.** A passed bare line is recorded as, for example,
  `PV2 at line 3 (line with no fields)` rather than `PV2 (line with no fields)`, on the engine and
  the tee, so a long run keeps one entry per segment id and line position. A header with fewer
  than three split fields holds no MSH-12, and every other line used to be judged against the
  segment ids of every HL7 version; both anonymizers now refuse it as a line no rule can reach.
  See [PHI.md](../docs/PHI.md) section 9. (`BACKLOG #3001`)
