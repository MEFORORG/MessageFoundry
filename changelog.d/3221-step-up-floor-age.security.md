- **A federated callback's age stops when its flow is consumed.** The ASVS 2.4.2 floor on the
  step-up's start-to-callback pair read the callback's age only after the two store reads that
  name the refusal's account, so a slow store counted as the person's time and could carry a
  too-early callback past the floor. The flow cache now stamps the instant it consumes a flow, and
  the age on both federated legs runs to that instant, so at least the store reads after the
  consume no longer count. The code exchange never counted: both legs read the age before it.
  (`BACKLOG #3221`)
