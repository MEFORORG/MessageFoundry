- **The default anonymization rule map scrubs twenty more identity, contact, date and location
  fields.** Inside segments the map already scrubbed, `GT1-4/19/21/24/29/42/45/46/51/56`,
  `NK1-12/26/38`, `MRG-2/5/6` and `PV1-5/37/50/52` passed into a dataset as captured unless
  `require_full_coverage` was on. Each now takes a kind in both copies of `DEFAULT_RULES`. An
  `anon.toml` overlay that points one of these fields at a kind other than its new default,
  `drop`, `freetext` or a keep is now a retarget of a default, so `load_rules` refuses it unless
  the field is listed under `[hl7].retarget_acknowledged`. A keep on one of them still loads, and
  turns the new scrub off with a warning. See [PHI.md](../docs/PHI.md). (`BACKLOG #5533`)
