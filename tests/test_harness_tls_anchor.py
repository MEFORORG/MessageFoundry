# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""The harness's TLS trust anchor (BACKLOG #1276 fallout).

The engine always serves TLS and mints a self-signed placeholder when no operator certificate is
configured. The harness supplies its own certificate instead, so the anchor exists before any engine
is spawned. These pin the three properties that makes that work, each of which had a plausible
way to be silently wrong.
"""

from __future__ import annotations

import contextlib
import os
import socket
import ssl
import subprocess
import sys
import threading
from pathlib import Path

import pytest

from harness.load.enginepoll import EnginePoller
from harness.load.tlsmat import harness_ssl_context, harness_tls_material


def test_the_anchor_is_minted_once_and_reused() -> None:
    """Minting per call would hand different nodes different anchors."""
    first = harness_tls_material()
    assert harness_tls_material() == first
    cert, key = first
    assert Path(cert).read_bytes().startswith(b"-----BEGIN CERTIFICATE-----")
    assert Path(key).stat().st_size > 0


def test_the_context_completes_a_handshake_a_default_context_rejects() -> None:
    """The anchor is proved by an actual handshake, not by inspecting the context.

    ``get_ca_certs()`` reports NOTHING here even though verification works, because it lists only
    certificates carrying CA basic constraints and the engine's is a self-signed leaf. Asserting on
    it looked like a stronger check and was simply false -- so this stands up a socket serving the
    harness's certificate and verifies that our context completes the handshake where a stock
    default context (OS trust store) refuses it.
    """
    cert, key = harness_tls_material()
    server_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_ctx.load_cert_chain(cert, key)

    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        port = listener.getsockname()[1]

        def serve() -> None:
            with contextlib.suppress(OSError, ssl.SSLError):
                conn, _ = listener.accept()
                with (
                    contextlib.suppress(OSError, ssl.SSLError),
                    server_ctx.wrap_socket(conn, server_side=True) as tls,
                ):
                    tls.recv(1)

        for ctx, should_verify in (
            (harness_ssl_context(), True),
            (ssl.create_default_context(), False),
        ):
            thread = threading.Thread(target=serve, daemon=True)
            thread.start()
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=5) as raw:
                    if should_verify:
                        with ctx.wrap_socket(raw, server_hostname="127.0.0.1") as tls:
                            assert tls.getpeercert() is not None
                    else:
                        with pytest.raises(ssl.SSLCertVerificationError):
                            ctx.wrap_socket(raw, server_hostname="127.0.0.1")
            finally:
                thread.join(timeout=5)


def test_a_child_process_inherits_the_parents_anchor() -> None:
    """batchbox spawns `connscale-remote` to poll engines the PARENT started.

    A per-process mint would give that child a DIFFERENT certificate from the one those engines
    were handed, so every poll would fail verification. No single-process test can see this.
    """
    parent_cert, _ = harness_tls_material()
    child = subprocess.run(
        [
            sys.executable,
            "-c",
            "from harness.load.tlsmat import harness_tls_material;print(harness_tls_material()[0])",
        ],
        capture_output=True,
        text=True,
        env=os.environ,
        check=True,
    )
    assert child.stdout.strip() == parent_cert


@pytest.mark.parametrize(
    ("url", "pinned"),
    [
        ("https://127.0.0.1:8765", True),
        ("https://localhost:8765", True),
        # Plain http is the in-process uvicorn path (ingress_probe) -- httpx ignores TLS settings
        # there and pinning would be meaningless.
        ("http://127.0.0.1:8765", False),
        # An engine on ANOTHER box (shardcert's two-box rig) mints its own cert that this process
        # has never seen. Pinning ours would break a path that is not ours to fix here.
        ("https://10.0.0.5:8765", False),
    ],
)
def test_only_a_loopback_https_engine_pins_to_the_harness_anchor(url: str, pinned: bool) -> None:
    assert (EnginePoller._cacert_for(url) is not None) is pinned


def test_a_spawned_node_is_handed_the_anchor_as_operator_material() -> None:
    """The engine honours [api].tls_cert_file FIRST, so handing it ours makes its own mint path
    unreachable -- which is what removes the wait-for-a-file-to-appear race."""
    from harness.load.failover import EngineNode

    node = EngineNode("n1", 8765, env={}, config_dir=".", cwd=Path("."))
    cert, key = harness_tls_material()
    assert node._env["MEFOR_API_TLS_CERT_FILE"] == cert
    assert node._env["MEFOR_API_TLS_KEY_FILE"] == key
    assert node.cacert == cert
    assert node.url.startswith("https://")
