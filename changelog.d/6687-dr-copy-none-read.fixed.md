- A no-key DR backup's archive copy, a plaintext verify's copy and a config-bundle restore refuse a
  read that returns `None` (a non-blocking source with no data ready), naming the copy, instead of
  ending the copy short. Each reports the refusal as the read failure it is: a `write` failure at
  backup, a verify `FAIL`, and a restore refusal. (`BACKLOG #6687`)
