- **A refused loopback re-ingress is bounded by the refused-body allowance too.** A captured reply
  that fails its peek or size check on re-ingress is still recorded as an `ERROR` child of its
  origin, but it is now charged to the loopback's `[inbound].refused_body_allowance_bytes` like a
  listener's refusal: inside the allowance it is stored whole, past it only the head is, the error
  opens with the allowance note, and the child's metadata records the reply's length and keyed
  digest. The whole reply stays in the origin's captured response until retention erases it, and
  edit-and-resubmit of a head-only child points there without naming the origin's id. See
  [CONFIGURATION.md](../docs/CONFIGURATION.md). (`BACKLOG #4796`)
