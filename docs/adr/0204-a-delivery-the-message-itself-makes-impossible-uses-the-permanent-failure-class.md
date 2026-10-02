# 0204 -- A delivery the message itself makes impossible uses the permanent failure class

- **Status:** Accepted (2026-10-02, on build; decision delegated by the owner under the driver rule
  and taken by the batch 186 Manager; the owner may overrule at review)
- **Date:** 2026-10-02
- **Related:** vault BACKLOG #2562 (the output file name, built here), #2557 (the framer refusal),
  #2559 (the re-encode refusal); the vault's injection remediation drafts of 2026-10-01, draft 3,
  which this ADR adopts; the vault's injection audit of 2026-10-01, section A6 and probes P8 and P14;
  [ADR 0001](0001-staged-pipeline-architecture.md) (the staged pipeline);
  [ADR 0067](0067-persistent-outbound-mllp.md); [`CLAUDE.md`](../../CLAUDE.md) sections 0 and 2

---

## Context

The engine already has two kinds of delivery failure. A plain `DeliveryError` is transient: the
delivery worker retries it, up to the shipped cap of 100 attempts, then dead-letters it.
`NegativeAckError(permanent=True)` is permanent: the worker dead-letters it at once. At least one
sender of the permanent class is `encode_wire_body` in `messagefoundry/transports/base.py`, which
`FileDestination._write` already calls.

The reliability invariant in `CLAUDE.md` section 2 says, verbatim, *"Each outbound connection drains
independently (a slow/failing one never blocks siblings)"*. A lane is FIFO, so its head blocks the
rows behind it. A head that can never succeed but is retried as transient holds the lane for the
whole retry budget.

The audit found three paths that make a delivery impossible because of the message itself, and do
not use the permanent class.

1. **The FILE output name.** `render_filename` in `messagefoundry/transports/file.py` puts a message
   field into the name with no length bound, and the default template is `{MSH-10}.hl7`, in
   `FileDestination` and in `RemoteFileDestination`. Probe P8 rendered a 404-character name from a
   400-character control id. Writing it raised `OSError`, which `FileDestination.send` wraps as a
   plain `DeliveryError("file write failed")`. On first deployment, one such message would hold its
   FIFO lane for 100 attempts.
2. **The framer refusal** that #2557 adds. It is new, and would be transient if it raised a plain
   `DeliveryError`.
3. **The MLLP delimiter override** re-encode, #2559, which raises a plain `DeliveryError` when the
   re-encode fails.

The same function had a second, smaller gap. The reserved-device test compared the stem exactly, so
`NUL ` with a trailing space and `CONIN$` passed it, and trailing dots and spaces were not stripped.
Windows strips trailing dots and spaces when it opens a name, so `NUL .hl7` would open the device.

**An upstream bound on one store, and why it does not narrow this.** `messages.control_id` is
`NVARCHAR(256)` in `messagefoundry/store/sqlserver.py`, and no code clips the control id before the
insert. With `ANSI_WARNINGS` on, as the store's own comments assume, a longer value makes the insert
raise rather than truncate. So on SQL Server a control id over 256 UTF-16 units never reaches
delivery. That bounds one field on one store. A template may name any field, and SQLite and Postgres
store `control_id` as unbounded `TEXT`, so this decision still needs its own bound. What the failing
insert does to the message is a separate question, reported with #2562 and not decided here.

## Decision

**A refusal the payload causes raises the existing permanent class. No new class, and no change to
the delivery worker.** The five rules of draft 3 are adopted as written. The open points are settled
under each rule.

1. **A refusal the payload causes raises `NegativeAckError(permanent=True)`.** It covers at least
   the framer refusal, the re-encode refusal, and a file name the destination itself judges
   unwritable. **This ADR builds the file name half only.** The framer refusal lands with #2557, and
   the re-encode refusal with #2559. For the FILE destination, the one raise left after rules 2 to 4
   is the path-escape refusal in `FileDestination._write`, a plain `DeliveryError` until now.
   *Settled:* it splits in two. A name that itself holds a separator, or is `.` or `..`, came from
   the message, and a retry renders it again, so it is permanent with code `filename`. A name that
   is a single component but resolves outside the directory is the environment: a link at that
   name, or a share that changes form between the two resolves. That stays transient. Neither
   text quotes the name any more, because the error reaches the store's `last_error` and a
   template may name a field that carries PHI.
2. **The destination judges the final name before the write, in encoded bytes.** `render_filename`
   takes the suffix as an argument, so the name it judges is the name written: `FileDestination`
   passes `.gz` when it compresses, where it used to append it after rendering. A final name over
   the cap falls back, so the common case never fails at all.
   - *The cap is `FILENAME_MAX_BYTES`, 200 UTF-8 bytes.* The common per-component limit is 255:
     bytes on ext4 and XFS, UTF-16 units on NTFS. A UTF-8 byte count is never below the UTF-16 unit
     count, so one byte cap holds on both. The 55 bytes left cover the names a destination derives
     from this one: the remote upload's temp, `.{name}.{32 hex}.part`, adds 39, and the collision
     counter `-N` adds a few more.
   - *"The configured fallback" is the existing fixed fallback.* It stays `message.hl7` for both
     destinations. No new setting is added.
   - *Lone surrogates join the unsafe set.* A lone surrogate has no encoding, so a POSIX write of it
     would raise `UnicodeEncodeError` outside the `DeliveryError` contract. It is replaced like any
     other unsafe character.
3. **`render_filename` strips trailing dots and spaces before the reserved-name test.** The test is
   now the standard library's `ntpath.isreserved` rather than the engine's own list. It drops
   trailing spaces from the stem, so `NUL .hl7` is caught, and it knows `CONIN$`, `CONOUT$` and the
   superscript-digit `COM` and `LPT` ports, which the old list missed.
4. **A target directory too deep for the cap is refused at configuration time.** The platform limit
   is cheap to know, so this is built. On Windows it is `MAX_PATH`, unless `RtlAreLongPathsEnabled`
   says the process may use long paths or the directory carries the long-path prefix. That call
   checks both the registry switch and the host executable's long-path declaration; the registry
   value alone would not. On macOS it is 1024 bytes, and on Linux 4096. *Settled:* the directory
   does not need room for the full 200-byte cap. `FileDestination` measures the room its absolute
   path leaves, less 16 for a derived name, and lowers its own cap to fit. It refuses the
   configuration, with a `ValueError` when the connector is built, only when the room left is too
   small for the fallback name and its suffix. Refusing every directory too deep for 200 bytes
   would refuse ordinary Windows paths of about 43 characters where long paths are off. A lowered
   cap is logged once, as a `WARNING` at build, and the warning says so when `overwrite` is on. A
   template whose fixed text alone is over the cap is refused at build too, since every message
   would fall back. *The remote file destination gets no directory check.* The remote path limit
   is the partner's server's and is not knowable here; a server refusal is classified by its own
   reply, as today. It does get the template check, against the default cap.
5. **An `OSError` from the filesystem stays transient.** The engine cannot tell a full disk from a
   bad name by the exception alone. Rules 2 to 4 keep a bad name off this path.

## Acceptance Criteria

- **AC-1** -- WHEN a message's control id is 400 characters and the template is `{MSH-10}.hl7`,
  THE SYSTEM SHALL write the file under the fallback name rather than raise.
  → `tests/test_file_output_name_bound.py::test_p8_a_400_character_control_id_is_delivered_under_the_fallback_name`
- **AC-2** -- THE SYSTEM SHALL cap the rendered name in UTF-8 bytes, keeping a name exactly at the
  cap and falling back one byte over it.
  → `tests/test_file_output_name_bound.py::test_the_cap_counts_utf8_bytes_not_characters`,
  `tests/test_file_output_name_bound.py::test_a_name_exactly_at_the_cap_is_kept_and_one_byte_over_falls_back`
- **AC-3** -- WHERE a FILE destination compresses, THE SYSTEM SHALL count the `.gz` suffix in the
  cap and add it to the fallback.
  → `tests/test_file_output_name_bound.py::test_a_gzip_destination_caps_the_name_with_its_gz_suffix`,
  `tests/test_file_output_name_bound.py::test_the_suffix_is_counted_and_is_added_to_the_fallback`
- **AC-4** -- WHEN a field holds a lone surrogate, THE SYSTEM SHALL replace it in the name.
  → `tests/test_file_output_name_bound.py::test_a_lone_surrogate_never_reaches_the_name`
- **AC-5** -- IF a rendered name is a reserved device name once trailing dots and spaces are
  stripped, THEN THE SYSTEM SHALL use the fallback.
  → `tests/test_file_output_name_bound.py::test_a_device_name_hidden_by_trailing_dots_or_spaces_falls_back`,
  `tests/test_file_output_name_bound.py::test_a_space_before_the_extension_does_not_hide_a_device_name`,
  `tests/test_file_output_name_bound.py::test_trailing_dots_and_spaces_are_stripped_from_the_final_name`
- **AC-6** -- IF a rendered name holds a path separator, THEN THE SYSTEM SHALL raise a permanent
  `NegativeAckError` whose text does not quote the name.
  → `tests/test_file_output_name_bound.py::test_a_name_that_escapes_the_directory_is_a_permanent_failure`
- **AC-6a** -- IF a single-component name resolves outside the destination directory, THEN THE
  SYSTEM SHALL raise a transient `DeliveryError` whose text does not quote the name.
  → `tests/test_file_output_name_bound.py::test_a_resolve_outside_the_directory_for_another_reason_stays_transient`
- **AC-7** -- IF the write raises `OSError`, THEN THE SYSTEM SHALL raise a transient
  `DeliveryError`.
  → `tests/test_file_output_name_bound.py::test_an_os_error_from_the_write_stays_transient`
- **AC-8** -- IF the target directory leaves too little room under the platform path limit for the
  fallback name and its suffix, THEN THE SYSTEM SHALL refuse the configuration when the connector
  is built.
  → `tests/test_file_output_name_bound.py::test_a_directory_too_deep_for_the_fallback_name_is_refused_at_build`,
  `tests/test_file_output_name_bound.py::test_a_gzip_destination_needs_room_for_the_fallback_and_its_suffix`
- **AC-9** -- WHILE the target directory leaves less than the full cap, THE SYSTEM SHALL lower the
  cap to the room left.
  → `tests/test_file_output_name_bound.py::test_a_deep_directory_shrinks_the_cap_so_a_long_name_falls_back`
- **AC-9a** -- WHEN the cap is lowered for a directory, THE SYSTEM SHALL log it once at build, and
  say so when `overwrite` is on.
  → `tests/test_file_output_name_bound.py::test_a_reduced_cap_is_logged_once_at_build_and_names_overwrite`
- **AC-9b** -- IF a template's fixed text with its suffix is over the cap, THEN THE SYSTEM SHALL
  refuse the configuration when the connector is built.
  → `tests/test_file_output_name_bound.py::test_a_template_whose_fixed_text_is_over_the_cap_is_refused_at_build`,
  `tests/test_file_output_name_bound.py::test_a_remote_template_whose_fixed_text_is_over_the_cap_is_refused_at_build`,
  `tests/test_file_output_name_bound.py::test_the_template_check_counts_a_suffix_the_template_already_carries_once`
- **AC-10** -- WHEN a remote file upload's control id is 400 characters, THE SYSTEM SHALL upload
  under the fallback name.
  → `tests/test_file_output_name_bound.py::test_p8_a_remote_upload_falls_back_instead_of_a_404_character_name`

## Options considered

1. **Cap in encoded bytes, fall back, judge the directory at build, and keep `OSError` transient.**
   **CHOSEN.**
2. **Classify the `OSError` by errno in the destination.** Errno values for a bad name differ by
   platform and overlap with other faults; the audit saw errno 22 on Windows. Rejected as the main
   guard.
3. **Lower the retry cap.** It shortens the hold and hurts every real outage. Rejected.
4. **Cap the name in characters only.** It misses the `.gz` suffix, multi-byte characters and a
   deep directory. Rejected.
5. **Truncate an over-long name and add a short hash, instead of falling back.** It keeps names
   distinct and readable. Rejected for this cut: draft 3 names the fallback, and a truncated name
   can look like a real control id that it is not.
6. **Refuse any directory too deep for the full 200-byte cap.** Simple, and it would refuse ordinary
   Windows paths. Rejected for the per-directory cap in rule 4.

## Consequences

**Positive** -- One hostile or malformed message can no longer hold a FILE lane for the retry budget
through its name. The one refusal left is permanent, so it shows at once in the dead-letter queue
rather than as a lane that looks down. No new failure class, and no change to the worker.

**Negative / risks** --
- A long name that still reaches the filesystem, by a route rules 2 to 4 miss, keeps today's
  behaviour: up to 100 attempts. One known route is a filesystem whose component limit is below
  255, such as eCryptfs at 143.
- Several over-long messages share the fallback name. With `overwrite` off they get `-1`, `-2` and
  so on, as before. With `overwrite` on, each replaces the last, which is what an unresolvable
  placeholder already does there. A deep directory lowers the cap and makes this happen with
  ordinary names; the build-time warning is the only signal, and this ADR does not refuse that
  combination.
- A shared fallback hides which message a file came from. The rows and the message log still say.
- The Windows long-path answer is read once per process. An operator who changes it must restart
  the engine, which Windows itself also requires.
- A single-component name that resolves outside the directory is still retried, as before, because
  a link or a share hiccup can clear. A link an attacker plants at a name
  would hold the lane for the retry budget; planting it needs write access to the directory.

**Out of scope** -- the framer refusal (#2557) and the re-encode refusal (#2559), which use the
class this ADR records. The SQL Server insert of an over-long `control_id`, and of an over-long
`message_type` against its `NVARCHAR(64)` column, which is reported with #2562 as a candidate row.
`RemoteFileDestination._upload` encodes with `payload.encode` rather than `encode_wire_body`, which
is a separate question. So is `FileDestination.send` wrapping an `OSError` with its full text: an
error from the link or rename names the target path, so the rendered name can reach `last_error`.
