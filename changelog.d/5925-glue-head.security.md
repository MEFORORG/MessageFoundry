- **A surname after a malformed XML end tag at the end of a text is masked.** Words after a
  vocabulary end tag's name that end the text, as in `<family>Smith</family Kim`, printed whole
  where their last word ended on the start of a word some pass reads with no word boundary before
  it (`MSH`, the credential backstop's `nonnumeric`, a credential label such as `Password`), since
  a caller's text glued after the answer could complete that word. They are now masked except for
  that ending, which is kept as it stood: `</family Kim` becomes `</family Xxm`, and `zqxP` becomes
  `xxxP`, so the passes this change models read text glued after the answer as they did before;
  a last word that is all such a start, such as `shared`, is kept whole while the words before it
  are masked. An ending a caller's text could complete into a connection-string member key, such
  as `creden` before a caller's `tial=`, is kept as it stood from wherever it starts in the word,
  since the credential filter reads that key with any word characters before it:
  `</family Zqcreden` becomes `</family Xxcreden`. The same holds where an HL7 field run
  took the end tag's name (`a|b|<family>Smith</family Kim`). A short last word before a closing
  line break, as in `</family Li` then a line break, is now masked too. Some words after a
  malformed end tag still print, at least these: every word of a rest whose last word holds a
  digit at the end of the text, as in `</family Zqx 4455`, where `Zqx` prints too; a rest ended by
  at least a tab, a form feed, a vertical tab, a next-line or a line-separator character, as in
  `</family Kim` then a tab, since only a space, carriage return or line feed is read as the
  text's end there; and the shapes the docstring
  of `_end_tag_rest` in `messagefoundry/redaction.py` lists. (`BACKLOG #5925`)
