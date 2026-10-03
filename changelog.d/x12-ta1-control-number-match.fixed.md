- **An X12 outbound acts on a TA1 only when its TA1-01 names the interchange it just sent.** The
  TA1 classifier read TA1-04 without checking TA1-01 against the sent ISA13, so a stale,
  misdirected or wrongly-echoed TA1\*R would have dead-lettered a delivered interchange on first
  deployment, and a stale TA1\*A would have confirmed one the partner never acknowledged. A TA1
  naming another interchange is now logged at WARNING with the two control numbers only and the
  delivery is retried; a persistent connection is discarded instead of reused. The TA1\*R reject
  message and the TA1\*E warning now name `TA1-01` (the acknowledged interchange) where they
  named the reply's own `ISA-13`. The matching rule is in the X12 section of
  [CONNECTIONS.md](../docs/CONNECTIONS.md).
