- **The credential scrubber hides one more braced shape, in both the write-time pass and the
  support bundle.** A `MEFOR_` or key-material value in braces that holds a space, with lower case
  text glued after its closer, as `MEFOR_X={pp ww}x rest` or `private_key={pp ww},rest`, is now
  hidden up to the end of that text, where the part after the space printed before. The shape is
  narrow: braces or glued text holding at least a capital, a digit, most punctuation, or a word
  another pass reads, such as `mrn`, print as before (BACKLOG #2966).
