- **The default anonymization rule map scrubs twenty more identity, contact, date and location
  fields.** Inside segments the map already scrubbed, `GT1-4/19/21/24/29/42/45/46/51/56`,
  `NK1-12/26/38`, `MRG-2/5/6` and `PV1-5/37/50/52` had no rule. Plain `anonymize` passed them
  through, apart from what the site-code pass rewrites. `anonymize_checked` refused at least a
  dashed SSN, a phone written `NNN-NNN-NNNN` or `(NNN) NNN-NNNN`, or an `MR`- or `MRN`-typed id
  in them. Under the default rules, only `require_full_coverage` refused a message with any value
  in them. Each now takes a kind in both copies of `DEFAULT_RULES`. Two of them are not fully
  scrubbed: `GT1-19` and `NK1-12`, the guarantor's and the next of kin's employee ids, take the
  `id` kind, which fabricates the id but keeps the CX.4 assigning authority and CX.6 assigning
  facility components as captured, so an employer named there survives. An `anon.toml` overlay that
  points one of these fields at a kind other than its new default, `drop`, `freetext` or a keep
  is now a retarget of a default, so `load_rules` refuses it unless the field is listed under
  `[hl7].retarget_acknowledged`. A keep on one of them still loads, and turns the new scrub off
  with a warning. See [PHI.md](../docs/PHI.md). (`BACKLOG #5533`)
