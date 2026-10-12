# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A CA directory holding an encrypted PEM block never prompts or waits (BACKLOG #3090).

The Vault hop can be handed a CA directory, and it does not refuse one. OpenSSL reads a ``capath``
directory while it verifies a peer, not when the directory is loaded, so no check before the load
can cover it. BACKLOG #3090 asked what a directory file with a ``Proc-Type: 4,ENCRYPTED`` header
does at that moment. It was measured with a real handshake, and the client never prompted and
never waited: it refused the peer at once. So the engine does not refuse a CA directory, and this
file pins the reading that decision rests on, on every platform CI runs.

**If this goes red, do not loosen it.** A handshake that prompts or waits means a CA directory can
hang a Vault connection on a file with an encrypted block, and BACKLOG #3090 re-opens for the
directory. Refusing a directory would break ``VAULT_CAPATH``, ``REQUESTS_CA_BUNDLE`` and
``CURL_CA_BUNDLE`` users, so that choice is the owner's.

Measured 2026-10-12 with ``tests/_encrypted_pem_probe.py``. Each client is a fresh child process
that loads the directory and then verifies a loopback TLS server, itself a child process, whose
certificate the probe's CA signed:

==========================  ==========================================  ==========================
Platform                    Handshake through a CA directory            Controls, same run
==========================  ==========================================  ==========================
Windows 11, CPython 3.14.6  An encrypted ``CERTIFICATE`` block as       The plain CA under the same
/ OpenSSL 3.5.7             ``<hash>.0`` raised ``unable to get local   name verified the server.
                            issuer certificate`` in under 0.1 s, in     Under another name it did
                            all 4 conditions (hidden console or no      not. ``cadata=`` reached
                            console, stdin null or an open pipe). An    the prompt in all 4: still
                            encrypted ``X509 CRL`` block as             waiting at 4 s in 3, and
                            ``<hash>.r0`` raised ``unable to get        with no console and stdin
                            certificate CRL`` as fast. No prompt seen.  null it wrote the prompt
                                                                        and raised.
Linux (WSL2 Ubuntu),        The same two refusals in under 0.4 s, in    The same. ``cadata=`` wrote
CPython 3.12.3 / OpenSSL    all 3 conditions (pty, and no terminal      the prompt and was still
3.0.13                      with stdin null or an open pipe). No        waiting at 5 s under the
                            prompt.                                     pty and the open pipe.
==========================  ==========================================  ==========================

On both, in every condition:

* The store held no certificate after the load and one after a handshake that verified. That is
  the reading that the directory is read during the handshake.
* An encrypted block as ``<hash>.0`` beside the plain CA as ``<hash>.1`` still refused the peer.
  The plain file was not reached. That fails closed, and it is recorded here, not pinned.
* The plain CA with an encrypted private-key block beside it, as ``<hash>.0``, verified the server.
* With a CRL check on, the plain CA alone refused (``unable to get certificate CRL``) and the plain
  CA with its plain CRL verified. So the ``<hash>.r0`` file is what the CRL check reads.
* The positional call ``load_verify_locations(None, directory, None)``, the shape the Vault hop
  uses, read the same as ``capath=``.

The Linux reading is OFF-VERSION: the engine needs CPython 3.14, and the directory sat on a Windows
drive mounted in WSL. The on-version POSIX reading is this file's run on the hosted
``ubuntu-latest`` leg. On Windows a console prompt is not visible to the caller, so "no prompt
seen" there rests on the handshake returning in under 0.1 s.

The file name is OpenSSL's subject hash, worked out by ``subject_hash`` with no ``openssl``
program. For the probe's CA it is ``cd3a2265``. ``openssl x509 -subject_hash`` (OpenSSL 3.0.13) and
pyOpenSSL's ``subject_name_hash`` printed the same value on the day. The binding proof is the
control: the plain CA verifies the server under that name, and does not under another.

No handshake runs in the pytest process. The server and every client are child processes, each
killed on a deadline, so a regression fails a test and does not hang the suite.
"""

from __future__ import annotations

import sys
from collections.abc import Iterator
from pathlib import Path

import pytest

from messagefoundry.auth.trust_anchors import _has_encryption_header
from tests._encrypted_pem_probe import (
    CA_COMMON_NAME,
    CAPATH_CERTIFICATE_AND_KEY,
    CAPATH_ENCRYPTED,
    CAPATH_ENCRYPTED_CRL,
    CAPATH_ENCRYPTED_THEN_PLAIN,
    CAPATH_PLAIN,
    CAPATH_PLAIN_CRL,
    CAPATH_WRONG_NAME,
    CONDITIONS,
    Trial,
    run_trial,
    subject_hash,
    tls_server,
    write_shapes,
)

# Each trial starts an interpreter, and a real regression costs one _ANSWER_WITHIN wait before the
# first assertion fails. The suite's default cap is 60 s.
pytestmark = pytest.mark.timeout(300)

#: Seconds a handshake may take after the child is ready. It measured under 0.4 s. It must exceed
#: the child's 15 s socket timeout, so a stalled server reads as a ``TimeoutError`` and not a wait.
_ANSWER_WITHIN = 20.0
#: Seconds the control is left before it is counted as waiting for a password.
_CONTROL_WAIT = 3.0

_REFUSED_THE_PEER = "SSLCertVerificationError"


@pytest.fixture(scope="module")
def shapes(tmp_path_factory: pytest.TempPathFactory) -> Path:
    directory = tmp_path_factory.mktemp("encrypted-pem-capath")
    write_shapes(directory)
    return directory


@pytest.fixture(scope="module")
def port(shapes: Path) -> Iterator[int]:
    """The loopback TLS server, in a child process of its own. If it does not start, every test
    that needs it errors: nothing here skips."""
    with tls_server(shapes) as listening:
        yield listening


def test_the_directory_files_are_the_ones_the_engine_calls_encrypted(shapes: Path) -> None:
    """The pin's premise. Each encrypted directory file sits under the subject-hash name, and is
    text the engine's own header check refuses. The plain file is not."""
    stem = subject_hash(CA_COMMON_NAME)
    encrypted = (
        shapes / CAPATH_ENCRYPTED / f"{stem}.0",
        shapes / CAPATH_ENCRYPTED_THEN_PLAIN / f"{stem}.0",
        shapes / CAPATH_ENCRYPTED_CRL / f"{stem}.r0",
    )
    for path in encrypted:
        assert _has_encryption_header(path.read_text("ascii")), path
    assert not _has_encryption_header((shapes / CAPATH_PLAIN / f"{stem}.0").read_text("ascii"))


def test_the_subject_hash_is_the_value_openssl_printed() -> None:
    """A known answer for the arithmetic. ``openssl x509 -noout -subject_hash`` (OpenSSL 3.0.13)
    and pyOpenSSL's ``subject_name_hash`` both printed this for the probe's CA on 2026-10-12."""
    assert subject_hash(CA_COMMON_NAME) == "cd3a2265"
    with pytest.raises(ValueError, match="lower-case"):
        subject_hash("Mixed Case")


def _handshake(shapes: Path, port: int, condition: str, shape: str, mode: str = "capath") -> Trial:
    return run_trial(mode, shapes / shape, condition, wait=_ANSWER_WITHIN, port=port)


def _assert_never_waited(trial: Trial, where: str) -> None:
    assert trial.outcome != "WAITING", (
        f"{where} was still running after {_ANSWER_WITHIN:g} s. A CA directory can wait for a "
        f"password, so BACKLOG #3090 re-opens for the directory. Saw: {trial}"
    )
    assert not trial.prompted, f"{where} wrote a password prompt. Saw: {trial}"


def _assert_a_ca_directory_never_waits(shapes: Path, port: int, condition: str) -> None:
    plain = _handshake(shapes, port, condition, CAPATH_PLAIN)
    assert plain.outcome == "VERIFIED", (
        "the harness could not verify the server through a plain CA directory, so the directory "
        f"is not being read: the hash name, the server or the probe is wrong. Saw: {plain}"
    )
    with_crl = _handshake(shapes, port, condition, CAPATH_PLAIN_CRL, "capath-crl")
    assert with_crl.outcome == "VERIFIED", (
        f"the harness could not pass a CRL check through a plain CA directory: {with_crl}"
    )

    control = run_trial(
        "cadata-positional", shapes / "certificate.pem", condition, wait=_CONTROL_WAIT
    )
    assert control.outcome != "BROKEN", f"the control child never started: {control}"
    assert control.reached_the_prompt, (
        "the positive control did not fire: a cadata load of an encrypted block neither waited "
        f"nor wrote a password prompt under {condition!r}, so this harness cannot tell a prompt "
        f"from a refusal on this build. Re-take the BACKLOG #3090 measurement. Saw: {control}"
    )

    refusals = (
        (CAPATH_ENCRYPTED, "capath"),
        (CAPATH_ENCRYPTED, "capath-positional"),
        (CAPATH_ENCRYPTED_CRL, "capath-crl"),
    )
    for shape, mode in refusals:
        trial = _handshake(shapes, port, condition, shape, mode)
        where = f"a {mode} handshake through {shape} under {condition!r}"
        _assert_never_waited(trial, where)
        assert trial.outcome == "RAISED" and _REFUSED_THE_PEER in trial.detail, (
            f"{where} did not refuse the peer with a verification error: {trial}"
        )

    # Measured: the encrypted .0 file hides the plain .1 file, and the peer is refused. Only "no
    # wait, no prompt" is pinned, so an OpenSSL that reads on to the plain file does not fail this.
    hidden = _handshake(shapes, port, condition, CAPATH_ENCRYPTED_THEN_PLAIN)
    where = f"a handshake through {CAPATH_ENCRYPTED_THEN_PLAIN} under {condition!r}"
    _assert_never_waited(hidden, where)
    assert hidden.outcome == "VERIFIED" or (
        hidden.outcome == "RAISED" and _REFUSED_THE_PEER in hidden.detail
    ), f"{where} neither verified nor refused the peer: {hidden}"

    beside_a_key = _handshake(shapes, port, condition, CAPATH_CERTIFICATE_AND_KEY)
    where = f"a handshake through {CAPATH_CERTIFICATE_AND_KEY} under {condition!r}"
    _assert_never_waited(beside_a_key, where)
    # The certificate beside the encrypted key loads; the key block is not decrypted.
    assert beside_a_key.outcome == "VERIFIED", f"{where} did not verify the server: {beside_a_key}"


@pytest.mark.parametrize("condition", [c for c in CONDITIONS if c != "pty"])
def test_a_ca_directory_with_an_encrypted_block_never_waits_with_no_terminal(
    shapes: Path, port: int, condition: str
) -> None:
    """Runs on every platform. On POSIX the client has no controlling terminal. On Windows it has a
    hidden console of its own, or none."""
    _assert_a_ca_directory_never_waits(shapes, port, condition)


@pytest.mark.skipif(sys.platform == "win32", reason="a pty needs POSIX: no pty module on win32")
def test_a_ca_directory_with_an_encrypted_block_never_waits_on_a_terminal(
    shapes: Path, port: int
) -> None:
    """An operator's shell, where OpenSSL can open the terminal and ask. The client's controlling
    terminal is a pty that nobody types on."""
    _assert_a_ca_directory_never_waits(shapes, port, "pty")


def test_the_file_name_is_what_makes_a_directory_answer(shapes: Path, port: int) -> None:
    """Why the plain-directory control proves the directory is read. The same plain CA under
    another name does not verify the server, and with a CRL check on, the CA with no ``.r0`` file
    is refused. So a verified handshake means OpenSSL opened the file under the hash name."""
    condition = CONDITIONS[-1]
    wrong_name = _handshake(shapes, port, condition, CAPATH_WRONG_NAME)
    assert wrong_name.outcome == "RAISED" and _REFUSED_THE_PEER in wrong_name.detail, wrong_name
    no_crl = _handshake(shapes, port, condition, CAPATH_PLAIN, "capath-crl")
    assert no_crl.outcome == "RAISED" and "CRL" in no_crl.detail, no_crl
