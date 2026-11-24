- **The credential scrubber hides one more braced `MEFOR_` shape, in both the write-time pass and
  the support bundle.** A `MEFOR_` value in braces that holds a space, with lower case text glued
  after its closer, as `MEFOR_X={pp ww}x rest`, is now hidden up to the end of that text, where the
  part after the space printed before. The shape is narrow: the braces may hold anything the
  scrubber's braced form takes up to their first space, except ";", "&" and "{", but after that
  space, and in the glued text, only lower case letters (and ";", "," and "&" in the glued text)
  with no word another pass reads, such as `mrn`. Any other text there prints as before, and so
  does a key-material value of the same shape (BACKLOG #2966).
