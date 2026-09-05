# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""The uploaded-file store's key migration + rotation pass, and its scan's per-cause logging.

Both are **preconditions** for the strict-ciphertext read BACKLOG #1169 researches (ASVS 11.3.3), and
both were missing:

* The store's cipher columns have ridden ``reencrypt_to_active`` since WP-5. This surface had no pass
  of any kind, so ``rotate-key`` re-sealed every database cell and left every uploaded file under the
  retired key. That is a **data-loss defect standing on its own merits** — the operator's documented
  next step is to drop the retired key, and every upload written before the rotation then stops
  decrypting. It is also a precondition, because a refusal that fires on unmarked values would fire on
  legitimate pre-key uploads for as long as nothing could seal them.
* ``_scan_metas_sync`` folded every failure into one blanket ``except Exception`` and one generic
  warning, so a cipher REFUSAL was indistinguishable in the log from a routine post-rotation skip —
  on the surface where planting a file is easiest (two plain files in a directory, no database write).

The refusal itself is deliberately NOT built here: it awaits an owner ruling, and
``test_a_planted_plaintext_sidecar_is_still_accepted`` pins the standing behaviour so the builder who
ships the refusal is told to convert it rather than discovering it in CI.
"""

from __future__ import annotations

import base64
import json
import logging
from pathlib import Path

import pytest

from messagefoundry.store.crypto import CipherError, cell_aad, generate_key, make_cipher
from messagefoundry.uploads import ResealResult, UploadStore

_ADT = "MSH|^~\\&|A|B|C|D|202601011200||ADT^A01|MSGID1|P|2.5\rPID|1||MRN123^^^HOSP||DOE^JOHN\r"


def _keyed_store(root: Path, key: str | None, retired: tuple[str, ...] = ()) -> UploadStore:
    # write_v2=True is the shipped posture ([store].aad_bind defaults on), so the cell AAD is live.
    return UploadStore(root, make_cipher(key, list(retired), write_v2=True), max_bytes=1 << 20)


def _write_sealed_meta(root: Path, fid: str, key: str, payload: str) -> None:
    """Hand-write one sealed sidecar. The cell AAD lives in ONE place here, so a test that means to
    vary the KEY cannot accidentally vary the binding too."""
    (root / f"{fid}.meta").write_text(
        make_cipher(key, write_v2=True).encrypt(
            payload, aad=cell_aad("uploaded_file", "meta", fid)
        ),
        encoding="utf-8",
    )


async def _seed(store: UploadStore) -> str:
    meta = await store.save(
        data=_ADT.encode(), filename="acme.hl7", uploader="op", uploader_id="u-op"
    )
    return meta.file_id


# --- the rotation half: without this pass, rotate-key destroys uploads ------------------------


async def test_rotation_reseals_so_the_prior_key_can_be_dropped(tmp_path: Path) -> None:
    """The defect this pass closes, stated as the operator's own sequence.

    Rotate to B with A retired, then drop A — which is what the ``rotate-key`` docstring tells the
    operator to do once it finishes. Before this pass existed the upload was still sealed under A at
    that point and became permanently unreadable.
    """
    root = tmp_path / "uploads"
    key_a, key_b = generate_key(), generate_key()
    fid = await _seed(_keyed_store(root, key_a))

    result = await _keyed_store(root, key_b, (key_a,)).reseal_to_active()
    assert result == ResealResult(resealed=2, skipped=0)  # the body and the sidecar

    dropped = _keyed_store(root, key_b)  # key A is gone, exactly as the runbook says it may be
    assert (await dropped.read_bytes(fid)).decode() == _ADT
    assert (await dropped.get_meta(fid)).filename == "acme.hl7"


async def test_without_the_reseal_dropping_the_prior_key_loses_the_file(tmp_path: Path) -> None:
    """The negative control for the test above: prove the loss is real, not assumed.

    A guard that only ever runs the fixed path cannot tell you the defect existed. This skips the
    reseal and asserts the file is unreadable — so if some other change ever makes uploads survive a
    rotation on their own, this test reds and says the pass above is no longer load-bearing.
    """
    root = tmp_path / "uploads"
    key_a, key_b = generate_key(), generate_key()
    fid = await _seed(_keyed_store(root, key_a))

    with pytest.raises(CipherError):
        await _keyed_store(root, key_b).read_bytes(fid)


async def test_reseal_is_idempotent(tmp_path: Path) -> None:
    """A second pass re-seals nothing: values already under the active key are skipped, so an
    interrupted rotation can simply be re-run."""
    root = tmp_path / "uploads"
    key_a, key_b = generate_key(), generate_key()
    await _seed(_keyed_store(root, key_a))

    rotator = _keyed_store(root, key_b, (key_a,))
    assert (await rotator.reseal_to_active()).resealed == 2
    assert await rotator.reseal_to_active() == ResealResult(resealed=0, skipped=0)


# --- the migration half: keyless -> keyed ------------------------------------------------------


async def test_reseal_seals_a_keyless_upload_once_a_key_is_configured(tmp_path: Path) -> None:
    """The transition the store handles at open (``_encrypt_existing_rows``) and this surface did
    not handle anywhere: a file written before encryption was enabled stayed plaintext on disk."""
    root = tmp_path / "uploads"
    fid = await _seed(_keyed_store(root, None))
    blob = root / f"{fid}.blob"
    assert not blob.read_text(encoding="utf-8").startswith("mfenc:")  # plaintext base64

    key = generate_key()
    keyed = _keyed_store(root, key)
    assert (await keyed.reseal_to_active()).resealed == 2
    assert blob.read_text(encoding="utf-8").startswith("mfenc:")
    assert (await keyed.read_bytes(fid)).decode() == _ADT


# --- contracts mirrored from the store's own rotation ------------------------------------------


async def test_reseal_returns_zeros_for_a_cipher_it_cannot_rotate(tmp_path: Path) -> None:
    """Identity (no key) and a Vault-Transit cipher whose DEK never enters the heap both rotate
    nothing in-process — the same limitation ``reencrypt_to_active`` documents."""
    root = tmp_path / "uploads"
    await _seed(_keyed_store(root, generate_key()))
    assert await _keyed_store(root, None).reseal_to_active() == ResealResult()


async def test_reseal_raises_rather_than_dropping_a_file_it_cannot_open(tmp_path: Path) -> None:
    """A missing prior key aborts BEFORE any write, so the operator is told to supply it instead of
    losing data. Asserting the file still opens under the original key is the half that matters: a
    pass that raised *after* rewriting would leave a shredded file behind."""
    root = tmp_path / "uploads"
    key_a, key_b = generate_key(), generate_key()
    fid = await _seed(_keyed_store(root, key_a))

    with pytest.raises(CipherError):
        await _keyed_store(root, key_b).reseal_to_active()  # key A never supplied

    assert (await _keyed_store(root, key_a).read_bytes(fid)).decode() == _ADT


async def test_an_unreadable_file_is_counted_as_skipped_not_as_success(tmp_path: Path) -> None:
    """A half-deleted pair must not be reported as re-sealed.

    ``skipped`` is what tells the operator NOT to retire the prior key yet, so it has to be non-zero
    here — counting the pass as clean is the failure that loses the file two commands later.
    """
    root = tmp_path / "uploads"
    key_a, key_b = generate_key(), generate_key()
    fid = await _seed(_keyed_store(root, key_a))
    (root / f"{fid}.blob").unlink()  # sidecar without a body

    result = await _keyed_store(root, key_b, (key_a,)).reseal_to_active()
    assert result == ResealResult(resealed=1, skipped=1)


async def test_reseal_ignores_a_foreign_file_in_the_uploads_root(tmp_path: Path) -> None:
    """Anything that is not a well-formed ``<32-hex>.meta`` is not ours and is left untouched."""
    root = tmp_path / "uploads"
    key = generate_key()
    await _seed(_keyed_store(root, key))  # already under the active key, so it is skipped
    stray = root / "notes.txt"
    stray.write_text("operator scratch", encoding="utf-8")
    bad_id = root / "zzz.meta"
    bad_id.write_text("not an upload", encoding="utf-8")

    result = await _keyed_store(root, key).reseal_to_active()
    assert result == ResealResult()  # nothing matched, so nothing was opened or rewritten
    assert stray.read_text(encoding="utf-8") == "operator scratch"
    assert bad_id.read_text(encoding="utf-8") == "not an upload"


# --- the scan's per-cause logging ---------------------------------------------------------------


async def test_the_scan_names_each_failure_cause_distinctly(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """Three unrelated conditions must produce three distinguishable log lines.

    The blanket handler emitted the identical "skipping unreadable uploaded-file sidecar <id>" for
    all three, which is what would have made a future strict-read REFUSAL invisible: it would have
    read exactly like a routine post-rotation skip.
    """
    root = tmp_path / "uploads"
    root.mkdir(parents=True)
    key, other = generate_key(), generate_key()
    store = _keyed_store(root, key)

    # 1. decrypts, but the plaintext is not the JSON object the sidecar promises.
    _write_sealed_meta(root, "1" * 32, key, "not json")
    # 2. the cipher declines it — a rotated-away key today; a strict-read refusal tomorrow.
    _write_sealed_meta(root, "2" * 32, other, "{}")
    # 3. the bytes never reach the cipher at all.
    (root / f"{'3' * 32}.meta").write_bytes(b"\xff\xfe\x00 not utf-8")

    with caplog.at_level(logging.WARNING, logger="messagefoundry.uploads"):
        assert await store.list_files() == []
    assert len(caplog.messages) == 3, caplog.messages
    by_id = {m.split()[2].rstrip(":"): m for m in caplog.messages}
    assert "malformed metadata (JSONDecodeError)" in by_id["1" * 32]
    assert "cipher declined it" in by_id["2" * 32]
    assert "unreadable on disk" in by_id["3" * 32]


async def test_the_scan_never_logs_a_decrypted_body(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """PHI rule (CLAUDE.md section 9): naming the cause must not start printing content.

    The malformed branch logs the exception TYPE only, because a ``ValueError`` raised coercing a
    metadata field embeds that field's value in its message.
    """
    root = tmp_path / "uploads"
    root.mkdir(parents=True)
    key = generate_key()
    store = _keyed_store(root, key)
    fid = "4" * 32
    _write_sealed_meta(root, fid, key, json.dumps({"file_id": fid, "size": "MRN123-NOT-AN-INT"}))

    with caplog.at_level(logging.WARNING, logger="messagefoundry.uploads"):
        assert await store.list_files() == []
    joined = " ".join(caplog.messages)
    assert "MRN123" not in joined, joined
    assert "malformed metadata (ValueError)" in joined


# --- the standing defect, pinned so the refusal's builder converts it ---------------------------


async def test_a_planted_plaintext_sidecar_is_still_accepted(tmp_path: Path) -> None:
    """TRIGGER, not an endorsement. BACKLOG #1169's refusal is NOT built and awaits an owner ruling.

    The cipher's read passthrough (``store/crypto.py`` ``decrypt``: an unmarked value is returned
    unchanged) means a hand-written sidecar is accepted by a KEYED store, with every field
    attacker-chosen. This test records that as the behaviour on this branch. **When the strict read
    ships, this test fails — that is the intended signal.** Convert it to assert the refusal; do not
    delete it, because the assertion below about laundering is what makes the refusal worth having.
    """
    root = tmp_path / "uploads"
    root.mkdir(parents=True)
    key = generate_key()
    store = _keyed_store(root, key)
    fid = "f" * 32
    (root / f"{fid}.meta").write_text(
        json.dumps(
            {
                "file_id": fid,
                "filename": "planted.hl7",
                "uploader": "attacker",
                "uploader_id": "attacker-id",
                "size": 3,
                "uploaded_at": 1.0,
            }
        ),
        encoding="utf-8",
    )
    (root / f"{fid}.blob").write_text(base64.b64encode(b"PWN").decode("ascii"), encoding="utf-8")

    got = await store.get_meta(fid)
    assert (got.filename, got.uploader, got.uploader_id) == (
        "planted.hl7",
        "attacker",
        "attacker-id",
    )
    assert await store.read_bytes(fid) == b"PWN"

    # And the reseal pass LAUNDERS it into a genuine AAD-bound ciphertext, after which nothing
    # distinguishes it from a file the engine wrote. The store's own rotation has this property too;
    # it is the reason #1169 wants a refusal at the read, and the reason this pass is a precondition
    # for one rather than a substitute.
    assert (await store.reseal_to_active()).resealed == 2
    assert (root / f"{fid}.meta").read_text(encoding="utf-8").startswith("mfenc:")
    assert (await store.get_meta(fid)).uploader == "attacker"
