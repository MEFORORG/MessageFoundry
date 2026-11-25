- **The credential scrubber hides one more braced `MEFOR_` shape, in both the write-time pass and
  the support bundle.** A `MEFOR_` value in braces that holds a space, with lower case text glued
  after its closer, as `MEFOR_X={pp ww}x rest`, is now hidden up to the end of that text, where the
  part after the space printed before. The shape is narrow. Before the first plain space (U+0020)
  the braces may hold any character except white space, a quote, ";", "&", "{" and "}" (a doubled
  "}}" is allowed), so a tab or a U+00A0 there refuses it. After that space, the braces may hold only
  lower case ASCII letters and spaces; the glued text, only lower case ASCII letters, ";", "," and
  "&"; and neither may hold a word from a fixed list of words other passes read, at least `mrn`,
  `nonnumeric` and the scheme words. The glued text must end at white space or the end of the
  text, and the branch is refused when white space and then ":", "=" or a quote follows it, or
  white space, `bearer`, `basic` or `digest`, and white space. Anything else prints as before, and
  so does a key-material value of the same shape (BACKLOG #2966).
