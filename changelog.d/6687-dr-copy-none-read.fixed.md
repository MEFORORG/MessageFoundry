- A no-key DR backup's archive copy, a plaintext verify's copy and a config-bundle restore refuse a
  read that returns `None` (a non-blocking source with no data ready), naming the copy, instead of
  ending the copy short. On a no-key box that refusal is reported as an `encrypt` failure at
  backup and as `decrypt failed` at verify, the codec's wording. (`BACKLOG #6687`)
