- **A mail relay that refuses every recipient with a `5xx` reply now fails the delivery for good.**
  On the Email and Direct destinations the row dead-letters on its first attempt, as a partial
  refusal already did, rather than being retried to the attempt ceiling. A refusal with any `4xx`
  reply, such as greylisting, or with `552`, is still retried. The error names the relay, a count
  and the reply codes, never an address or the relay's reply text, and the `[alerts]` mail logs it
  the same way. (`BACKLOG #2924`, `#2884`)
