# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
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


def test_the_context_is_cached_and_always_verifies() -> None:
    """Everything this returns goes straight to ``httpx``'s ``verify=``, where a falsy value means
    *verification off* -- so the one thing this function must never do is hand back something other
    than a verifying context. It previously cached into ``_CONTEXT: ssl.SSLContext | None = None``,
    which made the literal ``None`` a provable return value and put a high-severity
    ``py/request-without-cert-validation`` finding on all four load-harness httpx clients.

    This pins the runtime half (a real, verifying, reused context). The static half -- that ``None``
    is not even expressible here -- is what the decorator-based cache buys, and only CodeQL sees it.
    """
    ctx = harness_ssl_context()
    assert isinstance(ctx, ssl.SSLContext)
    assert ctx.verify_mode is ssl.CERT_REQUIRED
    assert ctx.check_hostname is True
    # Reused, not minted per call: eleven poller call sites hit this on every tick.
    assert harness_ssl_context() is ctx


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


# --- BACKLOG #1179: the three `--insecure` hints stop promising a fix the flag cannot deliver ------


def _harness_sources() -> list[Path]:
    root = Path(__file__).resolve().parents[1] / "harness"
    files = sorted(root.rglob("*.py"))
    assert len(files) > 20, f"the harness corpus did not load: {len(files)} files"
    return files


def test_the_retired_insecure_hint_is_gone_from_the_harness() -> None:
    """The three two-box drives printed "(hint: pass --insecure for a trusted-network http engine)"
    on an ``ApiError`` exit. That promised a fix the flag cannot deliver: measured 2026-09-05 against
    a real TLS listener, ``--insecure`` clears only THIS CLIENT's construction-time refusal, and a
    stock engine has served TLS since ADR 0172 -- so the poll then dies at the handshake with an
    opaque ``httpx.ReadError`` instead. An operator who follows the hint trades a named refusal for
    an unnamed transport error.

    The positive control is the point: a pattern that finds nothing anywhere is indistinguishable
    from a clean repo, so this asserts the corpus is searchable in the SAME run.

    Mutation: restore any one of the three old strings. Red: it is named with its file."""
    retired = "pass --insecure for a trusted-network http engine"
    control = "--insecure"
    offenders: list[str] = []
    control_hits = 0
    for path in _harness_sources():
        text = path.read_text(encoding="utf-8")
        if retired in text:
            offenders.append(str(path))
        control_hits += text.count(control)
    assert control_hits > 0, "the search found no `--insecure` at all -- the instrument is broken"
    assert offenders == [], f"the retired hint survives in: {offenders}"


def test_the_corrected_hint_is_single_sourced_at_three_sites() -> None:
    """Three copies of one sentence is how they drifted apart in the first place, so the correction
    is a module constant the three exits interpolate (SDS-3.5: state a load-bearing fact once).

    Mutation: inline the text at one site. Red: the reference count is 2, not 3."""
    from harness.__main__ import _INSECURE_HINT

    source = (Path(__file__).resolve().parents[1] / "harness" / "__main__.py").read_text(
        encoding="utf-8"
    )
    interpolations = source.count("{_INSECURE_HINT}")
    assert interpolations == 3, f"expected 3 hint sites, found {interpolations}"
    # It must say what the flag CANNOT do -- that is the whole correction.
    assert "cannot make a TLS-serving engine" in _INSECURE_HINT
    assert "ADR 0172" in _INSECURE_HINT
    assert "carries no credential" in _INSECURE_HINT


def test_the_insecure_flag_help_no_longer_asserts_the_engine_api_is_http() -> None:
    """The three ``--insecure`` help strings carried the same false premise as the hints -- "REQUIRED
    when the engine API is http" / "REQUIRED for a two-box http engine" -- which reads as a statement
    that the engine API IS http. Since ADR 0172 a stock engine serves TLS, so the flag is required
    only where the operator DECLARED the engine plaintext.

    Mutation: restore any "REQUIRED ... http engine" phrasing. Red: the count is not 3."""
    source = (Path(__file__).resolve().parents[1] / "harness" / "__main__.py").read_text(
        encoding="utf-8"
    )
    assert "REQUIRED when the engine API is http" not in source
    assert "REQUIRED for a two-box http engine" not in source
    # Each of the three flags now conditions the permission on the engine genuinely serving plaintext.
    # Counted on the BARE WORD: two of the three wrap mid-phrase, so "GENUINELY serves" is not
    # contiguous in the source and a phrase count would silently read 2 and still pass a `>=` bound.
    assert source.count("GENUINELY") == 3, (
        "expected all three --insecure help strings to condition on a genuinely-plaintext engine, "
        f"found {source.count('GENUINELY')}"
    )
