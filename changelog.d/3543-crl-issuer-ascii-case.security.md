- **A CRL's issuer name is matched to the hop's CA as OpenSSL matches it, for ASCII letter case.**
  The CRL signature check, at a start and at a reload, compared a CRL's issuer name with each
  listed CA's subject exactly. OpenSSL folds the case of ASCII letters, so it judged peers by a CRL
  the engine had matched to no listed CA. A badly signed CRL that named that CA's key, under a name
  that differed only in ASCII case, started with a WARNING and then failed every handshake it
  judged. A start now refuses it, as it refuses the same CRL under the exact name. The issuer name
  a CRL's authority key identifier may carry is folded the same way. A letter outside ASCII is
  still compared exactly, as OpenSSL compares it. A name that differs only in white space still
  reads as unlisted and loads with the WARNING, although OpenSSL treats the two names as one. See [CONFIGURATION.md](../docs/CONFIGURATION.md),
  under "CRL files". (`vault BACKLOG #3543`, `vault BACKLOG #2905`)
