- **The store key resolution and the store cipher build leave no byte of a codec error in a
  refusal when that codec error is still on the refused error's chain, of any class, at least as
  the error itself, its cause, its context, an argument or a group member.** A codec error no
  longer on the chain is not detected, so an error whose text was built from one that has since
  left the chain keeps that text and its byte. A key source
  error whose own text was built from a codec error, one whose codec error was a context beside a
  cause, and a `RuntimeError` such as a `KeyProviderError` or `DpapiError` that chained one each
  kept the byte the codec error quotes. Each is now refused with a fixed text naming its class and
  the codec error without its bytes, and with no chain: a `ValueError` as
  `StoreCipherConfigError`, any other class as `KeyProviderError`, which at least every CLI
  command with a key arm, `rotate-key` among them, reports as a key that could not be resolved,
  exit 2. An error whose chain cannot be read whole is refused the same way, and says so, whether
  or not it holds a codec error. A `KeyboardInterrupt` or `SystemExit` raised while the chain is
  read still propagates, with no cause and no context, so it does not carry the error being
  judged. Any other error is unchanged. (`BACKLOG #4882`, `BACKLOG #3471`)
- **`check-privileges`' AD bind probe keeps a hop refusal's text only when the LDAPS revocation
  guard raised it.** Any other hop refusal on that probe, at least one from resolving a Vault-held
  bind password, is named by its type, as on the Vault probe. (`BACKLOG #4883`, `BACKLOG #3471`)
