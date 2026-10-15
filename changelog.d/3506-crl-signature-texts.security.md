- **The CRL signature texts now say only what the engine does.** On a CRL's signature, a start
  refuses the file only where the engine proves that signature bad. Its other CRL refusals are
  unchanged. The configuration guide now says what counts as proof,
  and names cases that load with a WARNING although the CRL names a CA's key: at least a
  signature the engine cannot check with that key, and an issuer name that differs from the CA's
  only in letter case. The reload's `bad_signature` remedy sentence and the start WARNING are
  reworded to match. The reload's two signature reasons are reworded too: one uses the WARNING's
  words, and the other no longer says a handshake fails where the engine only could not confirm
  the signature. The guide also says when the WARNING is logged again for an earlier version of
  the file, that the engine does not check the signature of a CRL that reaches a hop through its
  CA file alone, and which alert the held-copy paragraphs describe. No check changed. See
  [CONFIGURATION.md](../docs/CONFIGURATION.md), under "CRL files". (`vault BACKLOG #3506`)
