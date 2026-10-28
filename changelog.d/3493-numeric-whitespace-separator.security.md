- **A numeric `OBX-5` is no longer kept under a whitespace separator.** A space is how an
  identifier is written without punctuation. So a message that declared a space as its repetition
  separator split `000 12 3456` into three valid numbers, and under `NM` the value would have left
  whole. A message whose component, repetition or subcomponent separator is a whitespace character
  now keeps no numeric `OBX-5` value, as one whose separator is a digit or a grammar mark already
  did. The vendored `tee/anon/surrogates.py` copy changes the same way. (vault `BACKLOG #3493`)
