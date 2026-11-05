- **A federated step-up's callback age is read before any store read.** The ASVS 2.4.2 floor on
  the step-up's start-to-callback pair read the callback's age only after the two store reads that
  name the refusal's account, so a slow store counted as the person's time and could carry a
  too-early callback past the floor. The age is now read as the flow is redeemed, as the sign-in
  leg already reads it. (`BACKLOG #3221`)
