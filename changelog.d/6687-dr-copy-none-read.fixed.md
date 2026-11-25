- A no-key DR backup's archive copy, a plaintext verify's copy and a config-bundle restore refuse a
  read that returns `None` (a non-blocking source with no data ready), naming the copy, instead of
  ending the copy short. So do the store-member copy of a verify and a restore, a restore's copy of
  a plaintext archive, and the copy fallback that places the restored store. These sources are
  blocking files or tar members, which do not answer `None` in the shipped code, so the change is
  defence in depth: no earlier restore is known to have placed a short store. The refusal is an
  `OSError`, reported as each site reports any `OSError` in that copy: a `write` failure at backup,
  a verify `FAIL`, and a restore refusal. (`BACKLOG #6687`)
