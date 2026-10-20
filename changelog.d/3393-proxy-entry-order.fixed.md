- **The `trusted_proxies` loosening names each range once, keeping list order within each wording.**
  The warning listed every IPv4 range before every IPv6 one, whatever the input order, and removed a
  repeat only when it was spelled the same way. So `10.0.0.0/08` beside `10.0.0.0/8`, or
  `::ffff:10.0.0.0/104` beside it, was named twice. Each network is now named once, under the first
  spelling given for it, with any other spelling in parentheses, as in
  `10.0.0.0/8 (also written as ::ffff:10.0.0.0/104)`; to clear it, remove every spelling. An IPv4
  entry now also counts toward the IPv6 family as its mapped twin, which uvicorn is handed too, so
  `0.0.0.0/0` beside IPv6 ranges covering the rest of `::/0` names those ranges with the
  every-address wording rather than the narrower range wording. (`BACKLOG #3393`)
