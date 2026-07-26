# 0134 — Offline uploaded-logs viewer (connection-decoupled upload / browse / per-message resend + deletion; PHI-at-rest posture; stdlib multipart)

- **Status:** Accepted (2026-07-18) — DEMAND-GATE-BACKLOG Wave 5 (lane `dg-s8b`); build phased, pushes/PR owner-approved
- **Date:** 2026-07-18
- **Related:** BACKLOG #125 (uploaded-logs page) · BACKLOG #126 (delete uploaded file — the *deletion* section below) · [ADR 0001](0001-staged-pipeline-architecture.md) (ingress stage) · [ADR 0090](0090-resend-a-stored-message-to-an-alternate-outbound-connection.md) (reingress seam — the one this deliberately does **not** reuse) · [ADR 0046](0046-message-content-search.md) (browse filter/search) · [ADR 0019](0019-pluggable-keyprovider-hsm-kms-vault.md) (store cipher + cell-bound AAD) · [ADR 0092](0092-posture-keyed-transport-hop-refusal-refuse-the-insecure-phi-hop.md) (PHI-read hop guard) · [ADR 0065](0065-web-ops-dashboard.md) (console seam) · CLAUDE.md §2 (count-and-log, reliability invariant), §9 (PHI)

---

## Context

Support engineers routinely receive a partner-supplied `.hl7`/`.txt`/`.xml` message file and need to
inspect it *without* ingesting it into the live store through a wired connection (BACKLOG #125). The
nearest existing mechanisms — the `File()` inbound connector (live ingest), the message browser /
dead-letter replay (store-only), and the one-shot `dryrun` CLI — none imports an arbitrary external
file into an ad-hoc, **connection-decoupled** offline log viewer with per-message resend.

Two CLAUDE.md invariants bind the design:

- **Count-and-log / reliability invariant** — *"every received message is persisted before the ACK …
  routers and transforms must be pure … at-least-once now relies on a re-run re-deriving identical
  output."* An uploaded file is **not** a received message; it must not corrupt inbound counts or the
  staged queue until an operator explicitly resends an individual message into a chosen inbound.
- **PHI rules (§9)** — *"Never log full message bodies at INFO or above … no PHI leaves the local
  environment without explicit, reviewed configuration … every PHI access is audited with the acting
  user."* An uploaded file is **real HL7 PHI at rest, outside the AES-256-GCM message store** — the
  single largest new at-rest PHI surface in this lane.

A verifier gap forces a design decision: [ADR 0090](0090-resend-a-stored-message-to-an-alternate-outbound-connection.md)'s `reingress`
seam re-enters an *edited* body onto **an existing origin message's channel** — it reads the origin
`messages` row for its `channel_id`. An uploaded, never-ingested file **has no origin row**, so
`reingress` cannot be reused. A distinct inject path is required.

A dependency decision is also forced: accepting a browser `multipart/form-data` upload conventionally
pulls in `python-multipart`. The console (`routes/core.py`) already carries a documented **no-multipart
stance** (every body-carrying POST is hand-parsed from the urlencoded body with stdlib
`urllib.parse.parse_qsl`). Adding the dependency would contradict that stance and require an owner
dep-vet + re-lock.

## Decision

Build an **offline uploaded-logs subsystem** that stores uploaded files on the **filesystem**
(connection-decoupled), **encrypted at rest under the store DEK**, gated **step-up + audited** on every
access, and injects a resent message through a **distinct ingest path** — never `reingress`.

1. **Filesystem storage, opt-in.** A new `[store].uploads_dir` (`MEFOR_STORE_UPLOADS_DIR`) names an
   uploaded-files directory. **Unset ⇒ the feature is disabled** (every route 503s "uploaded logs not
   configured") — no new PHI-at-rest surface exists unless an operator opts in. `[store].max_upload_bytes`
   (default 25 MiB) caps a single upload. The subsystem is a leaf `messagefoundry/uploads.py`
   (`UploadStore`) that imports only `store.crypto` (cipher) + `parsing.split` (split_batch) + `parsing.peek`
   — **never** the store instance, a connection, or `api/`. All file I/O and batch-splitting run **off the
   event loop** (`asyncio.to_thread`).

2. **Encrypted at rest under the store DEK.** Each upload is stored as two files under a random 32-hex
   `file_id`: `<file_id>.blob` (the body) and `<file_id>.meta` (JSON metadata). The body bytes are
   base64-carried to a `str` (NUL-safe, [ADR 0028](0028-base64-binary-carriage-codec.md) spirit) and both
   files are **AES-256-GCM-encrypted** through the **same `store/crypto.py` cipher** the message store uses
   (built from the same `resolve_active_key` DEK + retired keyring), each bound with a cell-AAD
   `cell_aad("uploaded_file","body"|"meta", file_id)` so a ciphertext cannot be swapped between file_ids
   (v2 writer; v1 default stays byte-identical). With **no key configured** the cipher is the identity — the
   uploaded files are then plaintext-on-disk, **exactly the same at-rest tier as the File-connector spill
   dirs**, and are documented as such in the PHI data-at-rest inventory (`docs/PHI.md` §2), with directory
   ACL + volume encryption as the deployment backstop.

3. **Step-up + audit on every access; never log bodies.** Upload, browse, resend and delete each require
   a **deny-by-default permission** (`files:upload` / `files:browse` / `files:delete`, granted to
   OPERATOR + administrator) and write an audit row (`upload.create` / `upload.browse` / `upload.resend` /
   `upload.delete`) carrying **metadata only** — file_id, filename, size, message count, and for browse the
   search-needle **shape** (never its value, reusing the ADR 0046 `_needle_shape`). Browse (which decrypts
   and returns PHI bodies) additionally requires **step-up** re-auth and `enforce_phi_read_hop`
   ([ADR 0092](0092-posture-keyed-transport-hop-refusal-refuse-the-insecure-phi-hop.md)), the same posture
   as content search. No body ever reaches the log at INFO+.

4. **Browse = split + filter/search, bounded.** Browsing an uploaded file decrypts the blob, splits it
   into individual HL7 messages via `parsing.split.split_batch` (the same splitter the File source uses),
   peeks each with python-hl7 for its metadata, and applies the ADR 0046 typed filters (message_type /
   control_id / a substring or HL7-field-path/value needle) in memory, paginated. The per-file message count
   is bounded by `max_upload_bytes`, so the whole-file split is bounded.

5. **Distinct inject path — NOT `reingress`.** Per-message resend takes the operator-chosen **target
   inbound connection** and injects the selected message through **`store.enqueue_ingress(channel_id=…,
   raw=…)`** — the *same primitive the live listener uses* — creating a fresh `RECEIVED` message + ingress
   queue row on that inbound's channel, which its router worker drains normally. This is the required
   distinct path: `enqueue_ingress` takes a channel **directly** and presupposes **no origin row**, whereas
   `reingress` reads an origin `messages` row that an uploaded file never had. The target inbound must be
   **registered, owned-by-this-shard, and running** (mirroring #123 resend validation), and the caller must
   be channel-scoped to it. The injected message is marked `source_type="upload"` with the file_id + index
   in its metadata; it then flows the ordinary count-and-log pipeline as a genuine receipt.

6. **Stdlib multipart hand-parse — no new dependency.** The upload body is `multipart/form-data`; a small
   leaf `api/multipart.py` (`parse_single_file_upload`) parses the boundary out of the `Content-Type`,
   splits the body on the boundary delimiter, and extracts the single file part's filename + bytes, with a
   **hard size cap** enforced before buffering. **No `python-multipart`** — honouring the `routes/core.py`
   no-multipart stance and avoiding an owner dep-vet + re-lock. The global 1 MiB request-body middleware is
   made path-aware so only the upload route admits up to `max_upload_bytes`.

7. **Web console.** A new `/ui/uploaded-logs` page (list + upload form + per-file browse + per-message
   resend) reaches the engine only through new `CoreHandlers` seam handlers (ADR 0065; `ENGINE_UI_SEAM`
   bumps), re-asserting the equivalent permission/step-up via `require_ui*`.

### Uploaded-file deletion + audit (BACKLOG #126 — section under this ADR)

Deleting an uploaded file is **destructive and irreversible**, so #126 is built as a guarded action under
this same subsystem (no separate ADR number):

- **Confirm step.** The console delete flows through an explicit GET confirm page → body-less POST, so a
  single stray click never destroys a file; the JSON API `DELETE /uploads/{file_id}` is likewise an explicit
  call.
- **Path-traversal validation on the attacker-influenced identifier.** `file_id` is **never** joined into a
  filesystem path without canonicalize-and-verify-within-root. `UploadStore._resolve(file_id)` first rejects
  any `file_id` not matching `^[0-9a-f]{32}\Z` (the exact shape `token_hex(16)` mints — no `.`, `/`, `\`, or
  NUL can pass), then resolves the candidate path and asserts its parent **is** the canonical uploads root;
  a mismatch raises `UploadPathError` (404), never touching the filesystem. This same guard fronts browse,
  read and resend — every route that takes a `file_id`.
- **Deny-by-default + audit.** Delete requires `files:delete` (+ console step-up) and writes an
  `upload.delete` audit row (actor + file_id + filename + size) **after** the removal, so the destructive
  action is attributable in the tamper-evident chain.

## Acceptance Criteria

- **AC-1** — WHEN an operator uploads a file with `files:upload` and `[store].uploads_dir` set, THE SYSTEM
  SHALL persist it encrypted-at-rest (when a key is set) and record an `upload.create` audit row with
  metadata only. → `tests/test_uploads.py::test_save_encrypts_and_lists`
- **AC-2** — WHEN `[store].uploads_dir` is unset, THE SYSTEM SHALL 503 every uploaded-logs route (no PHI
  surface). → `tests/test_upload_api.py::test_routes_503_when_unconfigured`
- **AC-3** — IF a `file_id` does not match the 32-hex shape or resolves outside the uploads root, THEN THE
  SYSTEM SHALL refuse (404/`UploadPathError`) without a filesystem touch. → `tests/test_uploads.py::test_path_traversal_rejected`
- **AC-4** — WHEN an operator resends a browsed message to a running inbound, THE SYSTEM SHALL inject it via
  `enqueue_ingress` (fresh `RECEIVED` on that channel), NOT `reingress`, and audit `upload.resend`. →
  `tests/test_upload_api.py::test_resend_injects_via_enqueue_ingress`
- **AC-5** — WHEN an operator deletes a file with `files:delete`, THE SYSTEM SHALL remove both files and
  write an `upload.delete` audit row. → `tests/test_upload_api.py::test_delete_confirm_audits`
- **AC-6** — WHILE the browse route runs, THE SYSTEM SHALL require step-up + the PHI-read hop guard and
  record the needle **shape** only. → `tests/test_upload_api.py::test_browse_requires_step_up_and_audits_shape`

## Options considered

1. **Filesystem + store-DEK encryption + `enqueue_ingress` inject + stdlib multipart — CHOSEN.**
   Connection-decoupled, encrypted at rest under the existing key management, distinct-and-correct inject,
   no new dependency.
2. **Store the upload in the message store (a new blob table).** Rejected: couples the offline viewer to a
   live connection/ingress identity, inflates the store with never-routed bodies, and muddies count-and-log.
3. **Reuse `reingress` for resend.** Rejected: it presupposes an origin `messages` row an uploaded file
   never had (the verifier gap) — it would 404 or require a fake origin.
4. **Add `python-multipart`.** Rejected: contradicts the `routes/core.py` no-multipart stance and needs an
   owner dep-vet + re-lock; a single-file `multipart/form-data` part is trivially hand-parsed with stdlib.
5. **Plaintext-on-disk, documented only.** Available (matches File-connector spill dirs) but weaker; we take
   it only as the **no-key** degradation and document it, preferring encryption when a DEK is set.

## Consequences

**Positive** — A genuine offline viewer closes the Corepoint parity gap; PHI at rest is encrypted under the
same DEK/rotation story as the store; resend is correct-by-construction (the live ingress primitive); no new
dependency; the console stays same-origin/seam-clean.

**Negative / risks** — A second at-rest PHI location the operator must harden (ACL + volume encryption) —
documented in PHI.md. Uploaded blobs are **not** re-encrypted by `rotate-key` (they live outside the store);
they stay readable via the decrypt keyring (retired keys), and are transient diagnostic artifacts an operator
deletes — documented. The whole-file split is in-memory, bounded by `max_upload_bytes`.

**Out of scope** — Non-HL7 deep parsing of uploaded `.xml`/`.txt` (they browse as split text); pixel/binary
document extraction; retention/auto-purge of the uploads dir (operator-managed, like spill dirs).

## To resolve on acceptance

- [x] Reuse `enqueue_ingress` (not a bespoke store method) for the distinct inject path — resolved.
- [x] Encrypt vs. document-only the at-rest tier — resolved: **encrypt under the store DEK when a key is set**,
      and document the no-key plaintext degradation in PHI.md.
