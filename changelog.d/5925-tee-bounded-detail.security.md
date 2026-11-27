- **The off-box audit tee's `detail` is bounded as `safe_text` bounds it.** A value the 64 KiB
  cut left last in an audit row's detail, such as `a|b|mrn: 12345` then the cut, printed in the
  tee line, since the tee redacted the head without being told the bound note follows it. Both
  of the tee's detail paths are now told, so that value is masked. Where the detail holds a C0
  control, the handler chain's scrub of the head is still read with no note, so its answer can
  show the value; the tee then ships that detail hidden whole, with its note. The tee's other
  fields are bounded as before, so a value at their cut can still print. (`BACKLOG #5925`)
