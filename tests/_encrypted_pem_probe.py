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

**A CA directory is measured with a handshake, because that is when OpenSSL reads it.** A
``capath`` load only records the directory's name. OpenSSL opens a file in it while it verifies a
peer, and it finds that file by the hash of the issuer's name: ``<hash>.0`` for a certificate and
``<hash>.r0`` for a CRL. So the ``capath`` modes (:data:`CAPATH_MODES`) load the directory and then
make a TLS handshake with a loopback server whose certificate chains to the probe's CA.
:func:`tls_server` runs that server in one more fresh child, so the calling process never
handshakes. The trial child sets a socket timeout, and :func:`run_trial` refuses a deadline that
does not exceed two of them, one to connect and one to handshake. So a server that stalls shows as
a ``TimeoutError``, and only a child stuck outside the socket shows as ``WAITING``.

:func:`subject_hash` works the file name out with ``hashlib``, so the probe needs no ``openssl``
program. Two directory shapes prove the name: the plain CA under that name verifies the server,
and the same plain CA under another name does not.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import time
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

__all__ = [
    "CAFILE_MODES",
    "CAPATH_CERTIFICATE_AND_KEY",
    "CAPATH_ENCRYPTED",
    "CAPATH_ENCRYPTED_CRL",
    "CAPATH_ENCRYPTED_THEN_PLAIN",
    "CAPATH_MODES",
    "CAPATH_PLAIN",
    "CAPATH_PLAIN_CRL",
    "CAPATH_WRONG_NAME",
    "CA_COMMON_NAME",
    "CONDITIONS",
    "ENCRYPTED_SHAPES",
    "ENCRYPTION_HEADERS",
    "PLAIN_SHAPE",
    "Trial",
    "assert_the_control_reaches_the_prompt",
    "run_trial",
    "subject_hash",
    "tls_server",
    "write_shapes",
]

#: The RFC 1421 headers of an encrypted PEM block, as ``tests/test_trust_anchors.py`` writes them.
ENCRYPTION_HEADERS = (
    "Proc-Type: 4,ENCRYPTED\nDEK-Info: AES-256-CBC,00112233445566778899AABBCCDDEEFF\n\n"
)

#: File name of each shape :func:`write_shapes` writes that carries an encryption header.
ENCRYPTED_SHAPES = ("certificate.pem", "crl.pem", "certificate-and-key.pem")
#: The same certificate with no header. A load of it must succeed, or a refusal proves nothing.
PLAIN_SHAPE = "plain.pem"

#: The load calls that read a path. The engine's CA and CRL load sites use these three shapes.
CAFILE_MODES = ("cafile", "cafile-positional", "default-context")
#: The load calls handed PEM text. They are the positive control: these reach the password prompt.
CONTROL_MODES = ("cadata", "cadata-positional")
#: The handshake modes. Each loads a directory as ``capath`` and then verifies the loopback
#: server. ``capath-positional`` passes it as ``(None, directory, None)``, the shape the Vault hop
#: uses. ``capath-crl`` also turns on a CRL check of the server's certificate.
CAPATH_MODES = ("capath", "capath-positional", "capath-crl")

#: Subject of the probe's CA. :func:`subject_hash` gives the name OpenSSL looks it up under.
CA_COMMON_NAME = "encrypted-pem-probe-ca"
#: The directory shapes :func:`write_shapes` writes for the ``capath`` modes.
CAPATH_PLAIN = "capath-plain"  # the plain CA under its hash name: the server verifies
CAPATH_WRONG_NAME = "capath-wrong-name"  # the plain CA under another name: it does not
CAPATH_ENCRYPTED = "capath-encrypted"  # the CA block with an encryption header
CAPATH_ENCRYPTED_THEN_PLAIN = "capath-encrypted-then-plain"  # that as .0, the plain CA as .1
CAPATH_CERTIFICATE_AND_KEY = "capath-certificate-and-key"  # plain CA, encrypted key block beside
CAPATH_PLAIN_CRL = "capath-plain-crl"  # plain CA and its plain CRL: the CRL check passes
CAPATH_ENCRYPTED_CRL = "capath-encrypted-crl"  # plain CA, and the CRL block with the header
#: The loopback server's certificate and private key, in one file. The CA signed the certificate.
SERVER_CHAIN = "server.pem"

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
#: Seconds the loopback server lives if nothing kills it first, so an orphan cannot stay.
_SERVER_LIFETIME = 900.0
#: Seconds a capath child's socket waits, once to connect and once more to handshake.
_SOCKET_TIMEOUT = 8.0

# The child. Standard library only, and it must run on any Python 3 this is measured on.
# A capath mode is handed a directory, the server's port and its socket timeout. run_trial keeps
# the deadline above two timeouts, or a stalled server would read as a wait for a password.
_TRIAL = r"""
import socket, ssl, sys, time
mode, path = sys.argv[1], sys.argv[2]
handshake = mode in ("capath", "capath-positional", "capath-crl")
if not handshake:
    with open(path, encoding="ascii") as handle:
        text = handle.read()
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
def store():
    stats = ctx.cert_store_stats()
    return "x509_ca=%d crl=%d" % (stats["x509_ca"], stats["crl"])
note = ""
sys.stdout.write("READY\n")
sys.stdout.flush()
began = time.monotonic()
try:
    if handshake:
        if mode == "capath-crl":
            ctx.verify_flags |= ssl.VERIFY_CRL_CHECK_LEAF
        if mode == "capath-positional":
            ctx.load_verify_locations(None, path, None)
        else:
            ctx.load_verify_locations(capath=path)
        note = " store after the load: " + store()
        address = ("127.0.0.1", int(sys.argv[3]))
        with socket.create_connection(address, timeout=float(sys.argv[4])) as raw:
            with ctx.wrap_socket(raw, server_hostname="localhost") as tls:
                version = tls.version()
    elif mode == "cafile":
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
except ssl.SSLCertVerificationError as exc:
    result = "RAISED SSLCertVerificationError " + str(exc)
except ssl.SSLError as exc:
    result = "RAISED SSLError " + str(exc)
except Exception as exc:
    result = "RAISED " + type(exc).__name__ + " " + str(exc)
else:
    result = "VERIFIED " + str(version) if handshake else "LOADED " + store()
if handshake:
    note += "; after the handshake: " + store()
sys.stdout.write("%s [%.3fs]%s\n" % (result, time.monotonic() - began, note))
sys.stdout.flush()
"""

# The loopback TLS server, in its own fresh child. Standard library only. It prints its port, then
# serves each connection on a thread, so one client that stops mid-handshake blocks no other trial.
# It ends itself after the lifetime it is handed, in case the caller dies before killing it.
_SERVER = r"""
import os, socket, ssl, sys, threading
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain(sys.argv[1])
ender = threading.Timer(float(sys.argv[2]), os._exit, [0])
ender.daemon = True
ender.start()
listener = socket.create_server(("127.0.0.1", 0))
sys.stdout.write("PORT %d\n" % listener.getsockname()[1])
sys.stdout.flush()
def serve(raw):
    try:
        raw.settimeout(120)
        with ctx.wrap_socket(raw, server_side=True) as tls:
            tls.recv(1)
    except OSError:  # includes ssl.SSLError: the client refused the certificate, or was killed
        pass
    finally:
        raw.close()
while True:
    raw = listener.accept()[0]
    threading.Thread(target=serve, args=(raw,), daemon=True).start()
"""

# The pty arm's middle process, POSIX only. pty.fork gives the child a new session whose
# controlling terminal is the pty, and the child then replaces itself with a fresh interpreter.
_PTY_LAUNCHER = r"""
import json, os, pty, select, signal, sys, time
trial, mode, path = sys.argv[1], sys.argv[2], sys.argv[3]
start_deadline, wait = float(sys.argv[4]), float(sys.argv[5])
pid, fd = pty.fork()
if pid == 0:
    os.execv(sys.executable, [sys.executable, "-I", "-c", trial, mode, path] + sys.argv[6:])
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
# The child can write its result and end between the last read and the look that found it gone.
# Whatever it left in the pty is read here, or that result would be lost.
while select.select([fd], [], [], 0.2)[0]:
    try:
        chunk = os.read(fd, 4096)
    except OSError:
        break
    if not chunk:
        break
    seen += chunk
sys.stdout.write(json.dumps({"waited": waited, "seen": seen.decode("ascii", "replace")}))
"""


@dataclass(frozen=True)
class Trial:
    """One load, or one load and handshake, in one terminal condition."""

    #: ``RAISED``, ``LOADED``, ``VERIFIED`` (a ``capath`` mode's handshake verified the server),
    #: ``WAITING`` (killed on the deadline) or ``BROKEN`` (never ready).
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
    # A result line means the load returned, even if the child was slow to exit and was killed.
    done = ("RAISED", "LOADED", "VERIFIED")
    result = next((line for line in after if line.startswith(done)), None)
    if result is not None:
        return Trial(result.split(" ", 1)[0], result, prompted)
    return Trial("WAITING" if waited else "BROKEN", " | ".join(after), prompted)


def _run_in_a_pty(mode: str, path: str, wait: float, extra: tuple[str, ...]) -> Trial:
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
            *extra,
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


def _run_without_a_pty(
    mode: str, path: str, condition: str, wait: float, extra: tuple[str, ...]
) -> Trial:
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
                [_child_python(), "-I", "-c", _TRIAL, mode, path, *extra],
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


def run_trial(
    mode: str,
    path: str | os.PathLike[str],
    condition: str,
    *,
    wait: float,
    port: int | None = None,
) -> Trial:
    """Run one load of ``path`` in a fresh child under ``condition``, and kill it after ``wait``.

    ``wait`` is counted from the child's ``READY`` line. A child still running then is ``WAITING``.
    A ``capath`` mode takes a directory as ``path`` and the ``port`` :func:`tls_server` yielded.
    """
    if condition not in CONDITIONS:
        raise ValueError(f"{condition!r} is not a terminal condition on this platform")
    if (mode in CAPATH_MODES) != (port is not None):
        raise ValueError(
            f"mode {mode!r} and port {port!r}: a capath mode, and only one, has a port"
        )
    if port is not None and wait <= 2 * _SOCKET_TIMEOUT:
        raise ValueError(
            f"a capath trial needs a deadline above {2 * _SOCKET_TIMEOUT:g} s, not {wait:g} s: "
            "a server that stalls must end as a TimeoutError, not as WAITING"
        )
    extra = () if port is None else (str(port), str(_SOCKET_TIMEOUT))
    if condition == "pty":
        return _run_in_a_pty(mode, os.fspath(path), wait, extra)
    return _run_without_a_pty(mode, os.fspath(path), condition, wait, extra)


def assert_the_control_reaches_the_prompt(
    shapes: str | os.PathLike[str], condition: str, *, wait: float
) -> None:
    """The positive control both pins run first: a ``cadata`` load of the encrypted certificate
    waits for a password or writes the prompt. Without it, a harness that saw nothing would pass."""
    control = run_trial("cadata-positional", Path(shapes, "certificate.pem"), condition, wait=wait)
    assert control.outcome != "BROKEN", f"the control child never started: {control}"
    assert control.reached_the_prompt, (
        "the positive control did not fire: a cadata load of an encrypted block neither waited "
        f"nor wrote a password prompt under {condition!r}, so this harness cannot tell a prompt "
        f"from a refusal on this build. Re-take the BACKLOG #3090 measurement. Saw: {control}"
    )


@contextlib.contextmanager
def tls_server(directory: str | os.PathLike[str]) -> Iterator[int]:
    """Serve TLS on a loopback port from a fresh child process, and yield the port.

    The server presents ``server.pem`` from ``directory``, which :func:`write_shapes` signed with
    the probe's CA. It is killed when the block ends, and it ends itself after
    ``_SERVER_LIFETIME`` seconds if the caller died first. The server loads only its own plain
    certificate and key, so it cannot be the process that waits for a password."""
    flags = 0
    if sys.platform == "win32":
        flags = subprocess.CREATE_NO_WINDOW
    chain = os.fspath(Path(directory, SERVER_CHAIN))
    with tempfile.TemporaryDirectory(prefix="mefor-pem-probe-") as scratch:
        out_path = Path(scratch, "out")
        with out_path.open("wb") as out:
            proc = subprocess.Popen(
                [_child_python(), "-I", "-c", _SERVER, chain, str(_SERVER_LIFETIME)],
                stdin=subprocess.DEVNULL,
                stdout=out,
                stderr=subprocess.STDOUT,
                creationflags=flags,
                start_new_session=sys.platform != "win32",
            )
            try:
                yield _port_of(proc, out_path)
            finally:
                if proc.poll() is None:
                    proc.kill()
                proc.wait()


def _port_of(proc: subprocess.Popen[bytes], out_path: Path) -> int:
    deadline = time.monotonic() + _START_DEADLINE
    while True:
        text = out_path.read_text("ascii", "replace")
        if text.startswith("PORT ") and "\n" in text:
            return int(text.split()[1])
        if proc.poll() is not None or time.monotonic() >= deadline:
            raise RuntimeError(f"the loopback TLS server did not start: {text.strip()[-400:]!r}")
        time.sleep(0.02)


def subject_hash(common_name: str) -> str:
    """The name OpenSSL looks a subject up under in a ``capath`` directory, without its suffix.

    OpenSSL hashes the name's canonical form with SHA-1 and reads the first four bytes as a
    little-endian number, printed as eight hex digits. The canonical form is the DER of each
    relative name, with the value as a lower-case UTF8String and no outer SEQUENCE header. This
    builds that for the one case the probe needs: a name of one short, lower-case ``commonName``.
    So the probe needs no ``openssl`` program. The proof that the name is right is a measurement,
    not this arithmetic: the plain CA under this name verifies the server, and under another name
    it does not."""
    value = common_name.encode("ascii")
    if common_name != " ".join(common_name.lower().split()) or not 0 < len(value) <= 100:
        raise ValueError("subject_hash covers one short lower-case commonName only")
    # commonName is OID 2.5.4.3. Tags: 0x06 OID, 0x0C UTF8String, 0x30 SEQUENCE, 0x31 SET.
    attribute = b"\x06\x03\x55\x04\x03" + bytes([0x0C, len(value)]) + value
    relative_name = bytes([0x31, len(attribute) + 2, 0x30, len(attribute)]) + attribute
    digest = hashlib.sha1(relative_name, usedforsecurity=False).digest()
    return f"{int.from_bytes(digest[:4], 'little'):08x}"


def write_shapes(directory: str | os.PathLike[str]) -> None:
    """Write the synthetic PEM files the probe loads into ``directory``.

    A real self-signed CA certificate and a real CRL it signed, so each body is valid base64 and
    the PEM reader gets as far as the header. The encrypted shapes add the two RFC 1421 headers
    after the BEGIN line, as ``tests/test_trust_anchors.py`` does for BACKLOG #2270. Needs the
    ``cryptography`` package, which the trial child does not.

    It also writes what the ``capath`` modes need: ``server.pem``, a certificate the CA signed for
    ``localhost`` with its private key, and one directory per ``CAPATH_*`` name, each holding the
    same blocks under the name :func:`subject_hash` gives."""
    import datetime

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, CA_COMMON_NAME)])
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
        return f"{begin}\n{ENCRYPTION_HEADERS}{rest}"

    label = "RSA PRIVATE" + " KEY"  # split, so a secret scanner does not read a real key
    key_block = f"-----BEGIN {label}-----\n{ENCRYPTION_HEADERS}AAAA\n-----END {label}-----\n"
    out = Path(directory)
    shapes = {
        PLAIN_SHAPE: cert.decode("ascii"),
        "certificate.pem": with_headers(cert),
        "crl.pem": with_headers(crl),
        "certificate-and-key.pem": cert.decode("ascii") + key_block,
    }
    server_key = ec.generate_private_key(ec.SECP256R1())
    server_cert = (
        x509.CertificateBuilder()
        .subject_name(
            x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "encrypted-pem-probe-server")])
        )
        .issuer_name(subject)
        .public_key(server_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False)
        .sign(key, hashes.SHA256())
    ).public_bytes(serialization.Encoding.PEM)
    # A real key, made here and written only to the caller's scratch directory.
    server_key_pem = server_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    shapes[SERVER_CHAIN] = (server_cert + server_key_pem).decode("ascii")

    stem = subject_hash(CA_COMMON_NAME)
    other = f"{int(stem, 16) ^ 1:08x}"
    plain = shapes[PLAIN_SHAPE]
    directories = {
        CAPATH_PLAIN: {f"{stem}.0": plain},
        CAPATH_WRONG_NAME: {f"{other}.0": plain},
        CAPATH_ENCRYPTED: {f"{stem}.0": shapes["certificate.pem"]},
        CAPATH_ENCRYPTED_THEN_PLAIN: {f"{stem}.0": shapes["certificate.pem"], f"{stem}.1": plain},
        CAPATH_CERTIFICATE_AND_KEY: {f"{stem}.0": shapes["certificate-and-key.pem"]},
        CAPATH_PLAIN_CRL: {f"{stem}.0": plain, f"{stem}.r0": crl.decode("ascii")},
        CAPATH_ENCRYPTED_CRL: {f"{stem}.0": plain, f"{stem}.r0": shapes["crl.pem"]},
    }
    for directory_name, files in directories.items():
        (out / directory_name).mkdir(exist_ok=True)
        shapes.update({f"{directory_name}/{file}": text for file, text in files.items()})
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
    capath_rows = [
        (CAPATH_PLAIN, "capath"),
        (CAPATH_WRONG_NAME, "capath"),
        (CAPATH_ENCRYPTED, "capath"),
        (CAPATH_ENCRYPTED, "capath-positional"),
        (CAPATH_ENCRYPTED_THEN_PLAIN, "capath"),
        (CAPATH_CERTIFICATE_AND_KEY, "capath"),
        (CAPATH_PLAIN, "capath-crl"),
        (CAPATH_PLAIN_CRL, "capath-crl"),
        (CAPATH_ENCRYPTED_CRL, "capath-crl"),
    ]
    # run_trial says why a handshake trial's deadline has a floor.
    handshake_wait = max(wait, 20.0)
    print(f"deadline : {handshake_wait:g} s after READY for the capath rows")
    # A directory an older `write` made has no server.pem. Its load rows still print.
    has_server = (directory / SERVER_CHAIN).is_file()
    with tls_server(directory) if has_server else contextlib.nullcontext() as port:
        for condition in CONDITIONS:
            print(f"\n== {condition}")
            for shape, mode in rows:
                _print_row(shape, mode, run_trial(mode, directory / shape, condition, wait=wait))
            if port is None:
                print(f"capath rows skipped: no {SERVER_CHAIN} here. Run `write` again.")
                continue
            for shape, mode in capath_rows:
                trial = run_trial(
                    mode, directory / shape, condition, wait=handshake_wait, port=port
                )
                _print_row(shape, mode, trial)


def _print_row(shape: str, mode: str, trial: Trial) -> None:
    prompt = "prompt seen" if trial.prompted else "no prompt seen"
    print(f"{shape:28} {mode:18} {trial.outcome:8} {prompt:15} {trial.detail}")


if __name__ == "__main__":
    command, target = sys.argv[1], Path(sys.argv[2])
    if command == "write":
        target.mkdir(parents=True, exist_ok=True)
        write_shapes(target)
    elif command == "table":
        _print_table(target, wait=float(sys.argv[3]) if len(sys.argv) > 3 else 6.0)
    else:
        raise SystemExit("usage: _encrypted_pem_probe.py write|table <dir> [seconds]")
