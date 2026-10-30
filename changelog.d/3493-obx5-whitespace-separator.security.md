- **No `OBX-5` value is kept under a whitespace separator.** A space is how words and digit groups
  are written apart. So a message that declared a space as its repetition separator split
  `000 12 3456` into three valid numbers under `NM`, and a sentence into bare tokens under `ID`,
  `IS`, `CE` or `CWE`, and either would have left whole. A message whose component, repetition or
  subcomponent separator is a whitespace character now keeps no numeric or coded `OBX-5` value.
  A `DT` or `TS` value still takes the `date` kind, which [PHI.md](../docs/PHI.md) section 9
  describes under that separator. The vendored `tee/anon/surrogates.py` copy changes the same
  way. (vault `BACKLOG #3493`)
