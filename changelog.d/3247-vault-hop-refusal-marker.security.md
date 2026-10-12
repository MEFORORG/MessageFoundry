- **A Vault provider keeps the text of the Vault hop's own refusal only.** The three Vault clients
  print a hop refusal in its own fixed words, which name no address, proxy URL or token. That rule
  accepted every `InsecureHopRefused`, a type other parts of the engine raise with a host in the
  text, so a Vault handler that met one of those would have printed the host. The Vault hop's
  refusals are now a marked subclass, `VaultHopRefused`, and only that subclass keeps its text.
  Any other hop refusal gives its type name, as every other failure does. No refusal the Vault hop
  raises today changes its wording. (vault BACKLOG #3247)
