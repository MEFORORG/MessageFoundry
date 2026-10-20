- **The `trusted_proxies` loosening names each range once, in the order the list gives it.** The
  warning listed every IPv4 range before every IPv6 one, whatever the input order, and removed a
  repeat only when it was spelled the same way. So `10.0.0.0/08` beside `10.0.0.0/8`, or
  `::ffff:10.0.0.0/104` beside it, was named twice. Each network is now named once, under the first
  spelling given for it. Which networks are named, and with which wording, is unchanged.
  (`BACKLOG #3393`)
