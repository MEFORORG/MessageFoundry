- **The default anonymization rule map scrubs twelve more dates and job titles.** Inside segments
  the map already scrubbed, the dates `PID-33`, `NK1-8/9`, `GT1-13/14/31/32` and `PV1-25/30/35`
  and the job titles `NK1-10` and `GT1-49` had no rule, so plain `anonymize` passed them through
  as captured. Each date now takes the `date` kind, which keeps the year, and each job title
  takes `freetext`, in both copies of `DEFAULT_RULES`. An `anon.toml` overlay that points one of
  these fields at a kind other than its new default, `drop`, `freetext` or a keep is now a
  retarget of a default, so `load_rules` refuses it unless the field is listed under
  `[hl7].retarget_acknowledged`. See [PHI.md](../docs/PHI.md). (`BACKLOG #5533`)
