- **The default anonymization rule map scrubs twelve more dates and job titles, and `MRG-4`
  takes the identifier kind.** Inside segments the map already scrubbed, the dates `PID-33`,
  `NK1-8/9`, `GT1-13/14/31/32` and `PV1-25/30/35` and the job titles `NK1-10` and `GT1-49` had
  no rule, so plain `anonymize` passed them through as captured. Each date now takes the `date`
  kind, which keeps the year, and each job title takes `freetext`, in both copies of
  `DEFAULT_RULES`. `MRG-4`, the prior patient id, a CX, moves from `name` to `mrn`, the kind of
  `PID-2`, so a value written identically in both gets one surrogate, and its CX.3 to CX.6, CX.9
  and CX.10 components are kept as captured. An `anon.toml` overlay that points one of these
  fields at a kind other than its new default, `drop`, `freetext` or a keep is now a retarget of
  a default, so `load_rules` refuses it unless the field is listed under
  `[hl7].retarget_acknowledged`. See [PHI.md](../docs/PHI.md). (`BACKLOG #5533`)
