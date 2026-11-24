- **The credential scrubber hides two more shapes, in both the write-time pass and the support
  bundle.** A `MEFOR_` or key-material value in braces that holds a space, with lower case text
  glued after its closer, as `MEFOR_X={pp ww}x rest` or `private_key={pp ww},rest`, is now hidden
  up to the end of that text, where the part after the space printed before. And a keyword spelled
  with a fold character for its first letter, such as U+017F for the "s" of `secret`, now stops an
  earlier plain value the way its ASCII spelling does, so the value after it is hidden or masked as
  that spelling's is. Glued text holding a capital, a digit, or punctuation beyond the separators
  that value's plain reading already ran over, still prints as before (BACKLOG #2966, #3114).
