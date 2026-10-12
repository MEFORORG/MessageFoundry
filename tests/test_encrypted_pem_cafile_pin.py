# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A path load of an encrypted PEM block refuses at once and never prompts (BACKLOG #3090).

The engine loads CA and CRL files from a path at 14 sites that ``anchor_cadata`` does not cover,
and the Vault hop makes a fifteenth such load. BACKLOG #2270 found that a ``cadata=`` load of a
block with a ``Proc-Type: 4,ENCRYPTED`` header waits for a password. The row asked whether a
``cafile=`` load can wait too. It was measured, and it cannot, so those sites got no check. This
file pins that reading on every platform CI runs, because the engine's safety at those sites now
rests on it.

**If this goes red, do not loosen it.** A path load that prompts or waits means every one of those
sites can hang a start, a reload or a connection build on a file with an encrypted block, and
BACKLOG #3090 re-opens at full size.

Measured 2026-10-12 with ``tests/_encrypted_pem_probe.py``, each load in a fresh child process:

==========================  ==========================================  ==========================
Platform                    Path load (``cafile=``, positional,         Control (``cadata=`` and
                            ``create_default_context``)                 ``(None, None, text)``)
==========================  ==========================================  ==========================
Windows 11, CPython 3.14.6  Encrypted ``CERTIFICATE`` and ``X509 CRL``   Reached the prompt in all
/ OpenSSL 3.5.7             blocks raised ``[X509] PEM lib`` in under   4: still waiting at 4 s in
                            0.01 s, in all 4 conditions (hidden         3, and with no console and
                            console or no console, stdin null or an     stdin null it wrote the
                            open pipe). No prompt seen.                 prompt and raised.
Linux (WSL2 Ubuntu),        The same refusal in under 0.06 s, in all 3  Reached the prompt in all
CPython 3.12.3 / OpenSSL    conditions (pty, and no terminal with       3: still waiting at 5 s
3.0.13                      stdin null or an open pipe). No prompt.     under the pty and the open
                                                                        pipe; prompt and raise with
                                                                        stdin null.
==========================  ==========================================  ==========================

On both, an encrypted private-key block beside a plain certificate loaded the certificate through
a path at once, with no prompt, and a plain certificate loaded both ways. The Linux reading is
OFF-VERSION: the engine needs CPython 3.14. The on-version POSIX reading is this file's run on the
hosted ``ubuntu-latest`` leg. ``capath=`` was not measured anywhere.

Every load runs in a child process the probe kills on a deadline, never in the pytest process, so
a regression fails a test and does not hang the suite. Each test first shows that the harness can
see a prompt (the ``cadata`` control) and can see a load succeed (the plain file). Without those,
a harness that saw nothing would pass.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from tests._encrypted_pem_probe import (
    CAFILE_MODES,
    CONDITIONS,
    ENCRYPTED_SHAPES,
    PLAIN_SHAPE,
    Trial,
    run_trial,
    write_shapes,
)

# Each trial starts an interpreter. On a busy box that can take seconds, and a real regression
# costs one _REFUSE_WITHIN wait before the first assertion fails. The suite's default cap is 60 s.
pytestmark = pytest.mark.timeout(300)

#: Seconds a path load may take after the child is ready. It measured under 0.1 s.
_REFUSE_WITHIN = 20.0
#: Seconds the control is left before it is counted as waiting for a password.
_CONTROL_WAIT = 3.0


@pytest.fixture(scope="module")
def shapes(tmp_path_factory: pytest.TempPathFactory) -> Path:
    directory = tmp_path_factory.mktemp("encrypted-pem")
    write_shapes(directory)
    return directory


def _path_loads() -> list[tuple[str, str]]:
    """Every load call shape on the certificate, and the plain path load on the other two files."""
    loads = [("certificate.pem", mode) for mode in CAFILE_MODES]
    return loads + [(shape, "cafile") for shape in ENCRYPTED_SHAPES if shape != "certificate.pem"]


def _assert_path_loads_never_wait(shapes: Path, condition: str) -> None:
    plain = run_trial("cafile", shapes / PLAIN_SHAPE, condition, wait=_REFUSE_WITHIN)
    assert plain.outcome == "LOADED", f"the harness could not load a plain certificate: {plain}"

    control = run_trial(
        "cadata-positional", shapes / "certificate.pem", condition, wait=_CONTROL_WAIT
    )
    assert control.outcome != "BROKEN", f"the control child never started: {control}"
    assert control.reached_the_prompt, (
        "the positive control did not fire: a cadata load of an encrypted block neither waited "
        f"nor wrote a password prompt under {condition!r}, so this harness cannot tell a prompt "
        f"from a refusal on this build. Re-take the BACKLOG #3090 measurement. Saw: {control}"
    )

    for shape, mode in _path_loads():
        trial: Trial = run_trial(mode, shapes / shape, condition, wait=_REFUSE_WITHIN)
        where = f"{mode} load of {shape} under {condition!r}"
        assert trial.outcome != "WAITING", (
            f"a {where} was still running after {_REFUSE_WITHIN:g} s. A path load can wait for a "
            f"password, so BACKLOG #3090 re-opens for every cafile site. Saw: {trial}"
        )
        assert not trial.prompted, f"a {where} wrote a password prompt. Saw: {trial}"
        if shape == "certificate-and-key.pem":
            # The certificate beside the encrypted key loads; the key block is not decrypted.
            assert trial.outcome == "LOADED", f"a {where} did not load its certificate: {trial}"
        else:
            assert trial.outcome == "RAISED" and "SSLError" in trial.detail, (
                f"a {where} did not refuse with an SSLError: {trial}"
            )


@pytest.mark.parametrize("condition", [c for c in CONDITIONS if c != "pty"])
def test_a_path_load_of_an_encrypted_block_refuses_at_once_with_no_terminal(
    shapes: Path, condition: str
) -> None:
    """Runs on every platform. On POSIX the child has no controlling terminal. On Windows it has a
    hidden console of its own, or none."""
    _assert_path_loads_never_wait(shapes, condition)


@pytest.mark.skipif(sys.platform == "win32", reason="a pty needs POSIX: no pty module on win32")
def test_a_path_load_of_an_encrypted_block_refuses_at_once_on_a_terminal(shapes: Path) -> None:
    """The case BACKLOG #2270 was filed for: an operator's shell, where OpenSSL can open the
    terminal and ask. The child's controlling terminal is a pty that nobody types on."""
    _assert_path_loads_never_wait(shapes, "pty")


def test_der_bytes_holding_the_same_text_refuse_at_once(shapes: Path) -> None:
    """Why the Vault hop checks only ``str`` CA data: ``bytes`` are read as DER, so the PEM
    password path is never reached and the load refuses."""
    condition = CONDITIONS[-1]
    trial = run_trial("cadata-bytes", shapes / "certificate.pem", condition, wait=_REFUSE_WITHIN)
    assert trial.outcome == "RAISED" and not trial.prompted, trial
