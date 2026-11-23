- **A malformed Vault Transit key name is refused with its own text.** The refusals for
  `MEFOR_STORE_VAULT_TRANSIT_KEY`, `MEFOR_STORE_TRANSIT_KEY` and `MEFOR_STORE_TRANSIT_AUDIT_KEY`,
  the refusal of an unset `MEFOR_STORE_TRANSIT_KEY`, and the `vault` key provider's refusal of an unwrapped DEK that is not base64 of 32 bytes, now
  reach the operator as written, naming the variable to fix, where a store open used to show a
  generic "the key source failed" or "the Vault Transit cipher could not be built". A data key name
  and an audit key name that are both wrong are named in one refusal. The Transit key type check
  and the Transit cipher itself now check the name too. (`BACKLOG #6010`, `BACKLOG #6710`)
