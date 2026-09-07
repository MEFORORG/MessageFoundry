# ASVS packet B (cryptography) — vault handoff

**PR 946, open.** All 13 rows stay OPEN: their `Closing-act` is a scorecard re-score in the vault,
which a Builder cannot perform. Full per-row reasoning is in each item's `RE-VERIFIED 2026-09-06`
block in `docs/BACKLOG.md`; this page is the summary the vault holder asked for.

**Measurement note that applies throughout.** Every library fact was measured against the
`requirements.lock` **pin** (`cryptography` 50.0.1) in a clean venv, not against the available
interpreter, which reports 49.0.0. Where the introspected version matched the lock
(`argon2-cffi` 25.1.0, row #1352) that is stated on the row.

| Item | Cell | PR | What the verdict should become |
|---|---|---|---|
| #1162 | 11.1.1 | 946 | Stay **partial**. Both named gaps are closed in the shipped document, but the lifecycle table is unguarded — proven by mutation: deleting a row left all 25 doc-guard tests green, against a control that does turn one red. |
| #1163 | 11.1.2 | 946 | Stay **partial**. The stated residual is dead (a test classifies every row, and the clause-less rows are explicit non-key findings). The seam list had drifted two behind the gate; fixed. |
| #1164 | 11.1.3 | 946 | Stay **partial**, re-anchor. Premise dead on all three named claims. The signing seam was added: the gate went 77 to 78 sites, and `transports/fhir.py` had been UNSEEN, not undocumented. |
| #1165 | 11.2.2 | 946 | Stay **partial**. No code. The at-rest AEAD limb is a reasoned cannot-pass, and the TLS allow-list pattern does not transfer: an algorithm id is read from stored data, not configuration. Needs an ADR and an owner ruling. |
| #1166 | 11.2.3 | 946 | Stay **partial**. The Direct path accepted RSA-1024 on all three surfaces; now floored at 2048. That is still short of the 128-bit verb, since RSA-2048 is roughly 112. |
| #1167 | 11.2.4 | 946 | Stay **partial**, on the keyring loop only. The named site's premise is dead (ADR 0170 closed it) and the BACKLOG summary-table row is stale. The row's amplification arithmetic is wrong: the verifies are sequential, so 64 MiB per attempt, not 640. |
| #1168 | 11.3.1 | 946 | Stay **partial**, and record the cannot-pass. The signing half is now operator-selectable (RSASSA-PSS). The key-transport half cannot be reached: `add_recipient` takes no padding parameter and no OAEP is reachable on the pinned library. |
| #1169 | 11.3.3 | — | **Not worked** — already claimed by another session for an open PR. Premise holds; re-verification is recorded in the ledger so that session need not re-derive it. |
| #1170 | 11.3.5 | 946 | Stay **partial**, record as terminal. The operator-knob hole was closed by #1317. RFC 7366 is unsatisfiable *by observation*: Python's `ssl` exposes no encrypt-then-MAC state at all. |
| #1171 | 11.4.1 | 946 | The last SHA-1 with a cryptographic job is gone — `ws_password_type='digest'` is retired. Only `auth/policy.py`'s HIBP corpus key remains, carrying `usedforsecurity=False`. The keyed BLAKE2b limb is untouched and still decides the cell. |
| #1173 | 11.5.2 | 946 | Best **pass** candidate in the packet. Premise dead; nothing was built, deliberately. The nonce draws 144 bits from `node:crypto` and the absence is pinned by two instruments, both with working positive controls. |
| #1174 | 11.7.2 | 946 | Reasoned **cannot-pass**, and the residual needs rewriting. Its stated mechanism is false: `decrypt_into` exists on the pinned 50.0.1. The binding wall is `decode()`, not the library. |
| #1352 | 11.4.4 | 946 | **Owner ruling needed.** Research pass done. The argon2 parameters are byte-identical to the library defaults, under two comments denying it; corrected. The verdict forks on a reading: `na` (no key is derived and then used as a key) versus graded. |

## Two things deliberately not done

**Did not switch `AesGcmCipher.decrypt` to `decrypt_into`.** It would be a better wipe than the
module has today and would close nothing for 11.7.2. Shipping it under #1174 would be the
zeroization-counted-as-encryption substitution that row exists to refuse.

**Did not work #1169**, which another session holds.

## Two delegated claims checked and rejected

- That `postgres.py`'s "mirrors `MessageStore._CIPHER_COLUMNS`" comment is untrue. It is true.
  The real asymmetry is that SQL Server declares no such constant at all.
- An observation of concurrent edits in this worktree. Those were this branch's own commits.

## Checks

Green: `ruff` (check and format), `mypy` strict across 268 files, the crypto-inventory gate at 78
sites, the backlog status check at 680 items, and pytest on every suite covering a touched file.

**Not run:** the full pytest suite did not finish inside the session. Hosted-runner-only legs were
never visible here and must be read on the PR.
