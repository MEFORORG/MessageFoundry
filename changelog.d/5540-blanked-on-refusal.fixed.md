- **A refused message no longer adds to the anonymizer's `blanked` list.** The `blanked` list
  names each field the `date` kind scrubbed to empty. Both the toolkit and the tee recorded that
  address before the checks that refuse a field had run, so a caller that kept one list across a
  run and went on past an `AnonError` held an address for a message that was never emitted. Both
  now add the addresses only once the message has been written. (`BACKLOG #5540`)
