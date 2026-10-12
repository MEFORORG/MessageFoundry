- **A Vault provider's error keeps the text of the Vault hop's own refusal only.** The three Vault
  clients put a hop refusal into their error in its own fixed words, which name no address, proxy
  URL or token. That rule accepted every `InsecureHopRefused`, a type other parts of the engine
  raise with a host in the text, so a provider that met one of those would have put the host in
  its error. The Vault hop's refusals are now a marked subclass, `VaultHopRefused`, and only that
  subclass keeps its text there. The provider's error names any other hop refusal by type, as it
  names every other failure. No refusal the Vault hop raises today changes its wording.
  (vault BACKLOG #3247)
- **The Vault client build no longer raises a parser error that quotes a proxy URL.** For an
  `http://` Vault address it read the proxy's scheme with a parser that rejects some URLs the
  HTTP library accepts. That parser's error quotes the proxy's user and password, and a command
  would have printed it. The scheme is now read the way the credential check reads it, and such a
  hop is refused with fixed text. (vault BACKLOG #3247)
