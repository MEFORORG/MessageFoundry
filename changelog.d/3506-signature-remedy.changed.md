- **A refused CRL reload now says which signature finding held the file back.** The reload's
  signature check used to give one remedy, `bad_signature`, for a CRL proven badly signed and for
  one it could not confirm, so its words hedged across both and could not say which one held. A
  proof keeps `bad_signature`: fix the file, which a start that finds the same proof refuses at any
  time, so that refusal carries neither `start_refuses` nor the "at least until" caveat for a file
  not yet in effect. While some issuer in the file has no CRL in effect yet, the reload still
  judges that refusal again every pass. So a `lapses_first` it finds for the same file later is
  reported, such as once the hop lists a CA that the CRL names by key identifier and that verifies
  it. A CRL that names no key of the CA its issuer matches, and that CA's key does not verify, now
  reads `unproven_signature`. One whose signature the engine cannot check with the key of a CA it
  judges, the one the CRL names or, where it names none, one that fits it, such as a signature of
  another kind than the key, now reads `uncheckable_signature`. Both ask you to check the file and
  then restart, and both carry `start_refuses` while the file is not yet in effect. Both rank under
  every class that fixes the file, so a `lapses_first` refusal for the same file is no longer
  hidden behind them. Where a CA file holds the same CRL file, the CRL expiry alert still orders
  the CA-file hop's restart after either, as after `bad_signature`.
  Which CRL the reload reports is unchanged: the first in the file that a listed CA matches and
  does not verify, or failing that the first no listed CA matches. It judges none after the one it
  reports, so both new remedies ask you to check every CRL in the file: a start refuses the file
  where it proves any of them badly signed. (vault BACKLOG #3506)
