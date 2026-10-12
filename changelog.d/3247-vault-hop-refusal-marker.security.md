- **A Vault provider's error keeps the text of the Vault hop's own refusal only.** The three Vault
  clients put a hop refusal into their error in its own fixed words, which name no address, proxy
  URL or token. That rule accepted every `InsecureHopRefused`, a type other parts of the engine
  raise with a host in the text, so a provider that met one of those would have put the host in
  its error. The Vault hop's refusals are now a marked subclass, `VaultHopRefused`, and only that
  subclass keeps its text there. The provider's error names any other hop refusal by type, as it
  names every other failure. No refusal the Vault hop raises today changes its wording.
  (vault BACKLOG #3247)
