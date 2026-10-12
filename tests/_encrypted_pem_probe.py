# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Measure what a TLS trust load does with an encrypted PEM block (BACKLOG #3090).

A PEM block with a ``Proc-Type: 4,ENCRYPTED`` header can send OpenSSL to a password prompt. This
module is the instrument that says, for one load call and one terminal condition, whether the load
refused, loaded, or was still waiting when it was killed. ``tests/test_encrypted_pem_cafile_pin.py``
runs it as a pin, and it also runs by hand, on a Python that has no engine installed::

    python tests/_encrypted_pem_probe.py write <dir>   # needs the cryptography package
    python tests/_encrypted_pem_probe.py table <dir>   # standard library only

**Every load runs in a fresh child process, and the parent kills it on a deadline.** Never load one
of these files in the calling process: a load that waits would hang it. A bare ``os.fork`` child is
not a fresh process: it inherits the parent's C ``stdin`` state, and a ``cadata=`` control run that
way returned at once and read as "no prompt". So each trial is a new interpreter.

**The clock starts when the child says it is ready.** The child reads the file, prints ``READY``,
and only then calls the load, so interpreter start-up on a busy box is not counted as a wait.

Terminal conditions (:data:`CONDITIONS`):

* ``pty``, POSIX only. The child's controlling terminal is a pseudo-terminal nobody types on. This
  is an operator starting the engine in a shell. A second fresh process makes the terminal and
  starts the child in it, so the calling process never forks.
* ``no terminal, stdin null`` and ``no terminal, stdin open pipe``, POSIX. The child is in its own
  session, so it has no controlling terminal to open.
* ``hidden console`` and ``no console``, Windows, each with stdin on the null device or an open
  pipe. The child never shares the caller's console: OpenSSL turns echo off on the console it
  reads, and a killed child would leave it off.

On Windows the child is the BASE interpreter, not the virtual environment's ``python.exe``. That
file is a launcher which starts the real interpreter as its own child, so killing it could leave
the real one waiting. The trial script uses the standard library only, so it needs no environment.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path

__all__ = [
    "CAFILE_MODES",
    "CONDITIONS",
    "ENCRYPTED_SHAPES",
    "PLAIN_SHAPE",
    "Trial",
    "run_trial",
    "write_shapes",
]

#: The RFC 1421 headers of an encrypted PEM block, as ``tests/test_trust_anchors.py`` writes them.
_ENCRYPTED = "Proc-Type: 4,ENCRYPTED\nDEK-Info: AES-256-CBC,00112233445566778899AABBCCDDEEFF\n\n"

#: File name of each shape :func:`write_shapes` writes that carries an encryption header.
ENCRYPTED_SHAPES = ("certificate.pem", "crl.pem", "certificate-and-key.pem")
#: The same certificate with no header. A load of it must succeed, or a refusal proves nothing.
PLAIN_SHAPE = "plain.pem"

#: The load calls that read a path. The engine's CA and CRL load sites use these three shapes.
CAFILE_MODES = ("cafile", "cafile-positional", "default-context")
#: The load calls handed PEM text. They are the positive control: these reach the password prompt.
CONTROL_MODES = ("cadata", "cadata-positional")

if sys.platform == "win32":
    CONDITIONS: tuple[str, ...] = (
        "hidden console, stdin null",
        "hidden console, stdin open pipe",
        "no console, stdin null",
        "no console, stdin open pipe",
    )
else:
    CONDITIONS = ("pty", "no terminal, stdin null", "no terminal, stdin open pipe")

#: Seconds a child may take to start and print ``READY`` before the trial is called broken.
_START_DEADLINE = 45.0
_PROMPT = "pass phrase"

# The child. Standard library only, and it must run on any Python 3 this is measured on.
_TRIAL = r"""
import ssl, sys, time
mode, path = sys.argv[1], sys.argv[2]
with open(path, encoding="ascii") as handle:
    text = handle.read()
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
sys.stdout.write("READY\n")
sys.stdout.flush()
began = time.monotonic()
try:
    if mode == "cafile":
        ctx.load_verify_locations(cafile=path)
    elif mode == "cafile-positional":
        ctx.load_verify_locations(path, None, None)
    elif mode == "default-context":
        ctx = ssl.create_default_context(cafile=path)
    elif mode == "cadata":
        ctx.load_verify_locations(cadata=text)
    elif mode == "cadata-positional":
        ctx.load_verify_locations(None, None, text)
    elif mode == "cadata-bytes":
        ctx.load_verify_locations(cadata=text.encode("ascii"))
    else:
        raise SystemExit("unknown mode " + mode)
except ssl.SSLError as exc:
    result = "RAISED SSLError " + str(exc)
except Exception as exc:
    result = "RAISED " + type(exc).__name__ + " " + str(exc)
else:
    result = "LOADED x509_ca=%d crl=%d" % (
        ctx.cert_store_stats()["x509_ca"], ctx.cert_store_stats()["crl"])
sys.stdout.write("%s [%.3fs]\n" % (result, time.monotonic() - began))
sys.stdout.flush()
"""

# The pty arm's middle process, POSIX only. pty.fork gives the child a new session whose
# controlling terminal is the pty, and the child then replaces itself with a fresh interpreter.
_PTY_LAUNCHER = r"""
import json, os, pty, select, signal, sys, time
trial, mode, path = sys.argv[1], sys.argv[2], sys.argv[3]
start_deadline, wait = float(sys.argv[4]), float(sys.argv[5])
pid, fd = pty.fork()
if pid == 0:
    os.execv(sys.executable, [sys.executable, "-I", "-c", trial, mode, path])
seen = b""
deadline = time.monotonic() + start_deadline
ready = False
expired = False
while True:
    if not ready and b"READY" in seen:
        ready = True
        deadline = time.monotonic() + wait
    left = deadline - time.monotonic()
    if left <= 0:
        expired = True
        break
    if not select.select([fd], [], [], min(left, 0.05))[0]:
        if os.waitpid(pid, os.WNOHANG)[0] == pid:
            pid = 0
            break
        continue
    try:
        chunk = os.read(fd, 4096)
    except OSError:  # EIO: the child closed its end
        break
    if not chunk:
        break
    seen += chunk
waited = False
if pid:
    # A child that closed its end is on its way out: reap it, and do not count it as waiting.
    # One look is enough for a child that ran into the deadline.
    for _ in range(1 if expired else 40):
        if os.waitpid(pid, os.WNOHANG)[0] == pid:
            pid = 0
            break
        time.sleep(0.025)
if pid:
    waited = True
    os.kill(pid, signal.SIGKILL)
    os.waitpid(pid, 0)
sys.stdout.write(json.dumps({"waited": waited, "seen": seen.decode("ascii", "replace")}))
"""


@dataclass(frozen=True)
class Trial:
    """One load, in one terminal condition."""

    #: ``RAISED``, ``LOADED``, ``WAITING`` (killed on the deadline) or ``BROKEN`` (never ready).
    outcome: str
    #: The child's own result line, or what it wrote before it was killed.
    detail: str
    #: Whether OpenSSL's password prompt text was seen. On Windows a console prompt is not visible
    #: to the caller, so ``False`` there does not prove no prompt was written.
    prompted: bool

    @property
    def reached_the_prompt(self) -> bool:
        """The child waited for a password, or wrote the prompt for one."""
        return self.outcome == "WAITING" or self.prompted


def _child_python() -> str:
    # The module docstring says why this is not the virtual environment's launcher on Windows.
    base = getattr(sys, "_base_executable", None)
    return str(base) if sys.platform == "win32" and base else sys.executable


def _trial_from(text: str, *, waited: bool) -> Trial:
    lines = [line.strip() for line in text.replace("\r", "\n").split("\n") if line.strip()]
    prompted = _PROMPT in text.lower()
    if "READY" not in lines:
        return Trial("BROKEN", " | ".join(lines), prompted)
    after = lines[lines.index("READY") + 1 :]
    if waited:
        return Trial("WAITING", " | ".join(after), prompted)
    result = next((line for line in after if line.startswith(("RAISED", "LOADED"))), None)
    if result is None:
        return Trial("BROKEN", " | ".join(after), prompted)
    return Trial(result.split(" ", 1)[0], result, prompted)


def _run_in_a_pty(mode: str, path: str, wait: float) -> Trial:
    done = subprocess.run(
        [
            sys.executable,
            "-I",
            "-c",
            _PTY_LAUNCHER,
            _TRIAL,
            mode,
            path,
            str(_START_DEADLINE),
            str(wait),
        ],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=_START_DEADLINE + wait + 30,
        start_new_session=True,
        check=False,
    )
    try:
        report = json.loads(done.stdout)
    except ValueError:
        return Trial("BROKEN", f"the pty launcher failed: {done.stderr.strip()[-400:]}", False)
    return _trial_from(report["seen"], waited=report["waited"])


def _run_without_a_pty(mode: str, path: str, condition: str, wait: float) -> Trial:
    flags = 0
    if sys.platform == "win32":
        flags = (
            subprocess.CREATE_NO_WINDOW
            if condition.startswith("hidden console")
            else subprocess.DETACHED_PROCESS
        )
    open_pipe = condition.endswith("stdin open pipe")
    with tempfile.TemporaryDirectory(prefix="mefor-pem-probe-") as scratch:
        out_path, err_path = Path(scratch, "out"), Path(scratch, "err")
        with out_path.open("wb") as out, err_path.open("wb") as err:
            proc = subprocess.Popen(
                [_child_python(), "-I", "-c", _TRIAL, mode, path],
                stdin=subprocess.PIPE if open_pipe else subprocess.DEVNULL,
                stdout=out,
                stderr=err,
                creationflags=flags,
                # Its own session on POSIX, so the child has no controlling terminal to open.
                start_new_session=sys.platform != "win32",
            )
            waited = False
            try:
                deadline = time.monotonic() + _START_DEADLINE
                ready = False
                while proc.poll() is None:
                    if not ready and b"READY" in out_path.read_bytes():
                        ready = True
                        deadline = time.monotonic() + wait
                    if time.monotonic() >= deadline:
                        waited = True
                        break
                    time.sleep(0.02)
            finally:
                if proc.poll() is None:
                    proc.kill()
                proc.wait()
                if proc.stdin is not None:
                    proc.stdin.close()
        text = (
            out_path.read_text("ascii", "replace") + "\n" + err_path.read_text("ascii", "replace")
        )
    return _trial_from(text, waited=waited)


def run_trial(mode: str, path: str | os.PathLike[str], condition: str, *, wait: float) -> Trial:
    """Run one load of ``path`` in a fresh child under ``condition``, and kill it after ``wait``.

    ``wait`` is counted from the child's ``READY`` line. A child still running then is ``WAITING``.
    """
    if condition not in CONDITIONS:
        raise ValueError(f"{condition!r} is not a terminal condition on this platform")
    if condition == "pty":
        return _run_in_a_pty(mode, os.fspath(path), wait)
    return _run_without_a_pty(mode, os.fspath(path), condition, wait)


def write_shapes(directory: str | os.PathLike[str]) -> None:
    """Write the synthetic PEM files the probe loads into ``directory``.

    A real self-signed CA certificate and a real CRL it signed, so each body is valid base64 and
    the PEM reader gets as far as the header. The encrypted shapes add the two RFC 1421 headers
    after the BEGIN line, as ``tests/test_trust_anchors.py`` does for BACKLOG #2270. Needs the
    ``cryptography`` package, which the trial child does not."""
    import datetime

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "encrypted-pem-probe-ca")])
    now = datetime.datetime.now(datetime.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    ).public_bytes(serialization.Encoding.PEM)
    crl = (
        x509.CertificateRevocationListBuilder()
        .issuer_name(subject)
        .last_update(now - datetime.timedelta(days=1))
        .next_update(now + datetime.timedelta(days=30))
        .sign(key, hashes.SHA256())
    ).public_bytes(serialization.Encoding.PEM)

    def with_headers(pem: bytes) -> str:
        begin, rest = pem.decode("ascii").split("\n", 1)
        return f"{begin}\n{_ENCRYPTED}{rest}"

    label = "RSA PRIVATE" + " KEY"  # split, so a secret scanner does not read a real key
    key_block = f"-----BEGIN {label}-----\n{_ENCRYPTED}AAAA\n-----END {label}-----\n"
    out = Path(directory)
    shapes = {
        PLAIN_SHAPE: cert.decode("ascii"),
        "certificate.pem": with_headers(cert),
        "crl.pem": with_headers(crl),
        "certificate-and-key.pem": cert.decode("ascii") + key_block,
    }
    for name, text in shapes.items():
        # newline="": the bytes are the same on every platform.
        (out / name).write_text(text, encoding="ascii", newline="")


def _print_table(directory: Path, wait: float) -> None:
    import platform
    import ssl

    print(f"python   : {platform.python_implementation()} {platform.python_version()}")
    print(f"openssl  : {ssl.OPENSSL_VERSION}")
    print(f"platform : {platform.platform()}")
    print(f"deadline : {wait:g} s after READY")
    rows = [(PLAIN_SHAPE, mode) for mode in ("cafile", "cadata")]
    rows += [(shape, mode) for shape in ENCRYPTED_SHAPES for mode in CAFILE_MODES]
    rows += [("certificate.pem", mode) for mode in (*CONTROL_MODES, "cadata-bytes")]
    rows += [("certificate-and-key.pem", "cadata")]
    for condition in CONDITIONS:
        print(f"\n== {condition}")
        for shape, mode in rows:
            trial = run_trial(mode, directory / shape, condition, wait=wait)
            prompt = "prompt seen" if trial.prompted else "no prompt seen"
            print(f"{shape:24} {mode:18} {trial.outcome:8} {prompt:15} {trial.detail}")


if __name__ == "__main__":
    command, target = sys.argv[1], Path(sys.argv[2])
    if command == "write":
        target.mkdir(parents=True, exist_ok=True)
        write_shapes(target)
    elif command == "table":
        _print_table(target, wait=float(sys.argv[3]) if len(sys.argv) > 3 else 6.0)
    else:
        raise SystemExit("usage: _encrypted_pem_probe.py write|table <dir> [seconds]")
