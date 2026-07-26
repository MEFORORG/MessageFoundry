"""Tray configuration + engine-URL discovery (ADR 0113 §5).

The pure core — :func:`compose_config`, :func:`parse_serve_args`, :func:`build_engine_url`,
:func:`is_local_engine` — takes already-read TOML data and registry hints and returns a
:class:`TrayConfig`; it does no file or registry I/O, so it is fully unit-testable on any OS.
:func:`load_config` is the thin I/O wrapper (read ``tray.toml``, the engine's service-settings
TOML, and a :class:`RegistryReader`), and :class:`WinregReader` is the real Windows registry
source, guarded to no-op off Windows.

Registry values are **untrusted data** (ADR 0113 §5 / CLAUDE.md §8): they are validated and
used only as display/default hints, never executed. Precedence is TOML › registry hint › built-in
default.

**Scheme is not locality** (ADR 0113 amendment 2026-07-22). ``[api].tls_cert_file`` makes the
engine serve ``https`` on the *same* loopback bind, so "is this engine reachable over TLS" and
"is this engine on my box" are independent facts. :func:`is_local_engine` answers only the second
— it accepts ``http`` **and** ``https`` — because that is what actually gates service control and
Open-Repo (both are local-box operations). Keying monitor-only on the scheme instead made a
TLS-hardened loopback engine render as unmanageable, punishing the safer configuration.
"""

from __future__ import annotations

import re
import sys
import tomllib
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol
from urllib.parse import urlsplit

from messagefoundry.service_status import is_safe_service_name

DEFAULT_ENGINE_URL = "http://127.0.0.1:8765"
DEFAULT_SERVICE_NAME = "MessageFoundry"
DEFAULT_POLL_SECONDS = 5.0
_POLL_MIN_S = 1.0
_POLL_MAX_S = 3600.0

_LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1"})
_ENGINE_SCHEMES = frozenset({"http", "https"})
_VALID_HOST = re.compile(r"^[A-Za-z0-9._:\[\]-]{1,255}$")
_MAX_PATH_LEN = 4096
# The engine's own default when `serve --service-config` is absent (see messagefoundry/__main__.py),
# resolved against the service's working directory — which NSSM records as AppDirectory.
_DEFAULT_SERVICE_TOML = "messagefoundry.toml"


@dataclass(frozen=True)
class TrayConfig:
    """Resolved tray settings. ``monitor_only`` derives the local-single-box scope (ADR 0113 §5)."""

    engine_url: str = DEFAULT_ENGINE_URL
    service_name: str = DEFAULT_SERVICE_NAME
    repo_path: str | None = None
    poll_seconds: float = DEFAULT_POLL_SECONDS
    log_path: str | None = None

    @property
    def monitor_only(self) -> bool:
        """A **remote** engine → monitor-only (service control + Open-Repo disabled).

        Keyed on locality alone: a loopback engine is controllable whether it serves http or
        https (see the module docstring). Only a non-loopback host degrades the tray, because
        only then are "start the local service" and "open the local repo" meaningless.
        """
        return not is_local_engine(self.engine_url)


@dataclass(frozen=True)
class ServiceRegistryInfo:
    """The NSSM ``Parameters`` values relevant to discovery (all optional, all untrusted)."""

    app_directory: str | None = None  # repo root (nssm AppDirectory) → repo_path hint
    app_parameters: str | None = None  # `serve ... --host H --port P ...` → engine_url hint
    app_stdout: str | None = None  # service.out.log path (nssm AppStdout) → log_path hint


class RegistryReader(Protocol):
    """Reads a service's NSSM ``Parameters`` values, or ``None`` if unavailable."""

    def read_service_params(self, service_name: str) -> ServiceRegistryInfo | None: ...


def is_local_engine(url: str) -> bool:
    """True for a loopback engine URL over ``http`` **or** ``https`` — the tray's control scope.

    Deliberately scheme-tolerant across the engine's two supported API transports: enabling
    ``[api].tls_cert_file`` flips the *same* loopback bind to https, which changes nothing about
    whether the service runs on this box. Any other scheme (``file``, ``ftp``, a typo) is not an
    engine URL at all and is rejected.
    """
    try:
        parts = urlsplit(url)
    except ValueError:
        return False
    host = (parts.hostname or "").lower()
    return parts.scheme in _ENGINE_SCHEMES and host in _LOOPBACK_HOSTS


def is_tls_url(url: str) -> bool:
    """True when the engine URL is ``https`` — i.e. the probe client must verify a server cert."""
    try:
        return urlsplit(url).scheme == "https"
    except ValueError:
        return False


def _valid_host(host: str) -> bool:
    return bool(_VALID_HOST.match(host))


def _iter_options(app_parameters: str, wanted: frozenset[str]) -> Iterator[tuple[str, str]]:
    """Yield ``(flag, value)`` for each ``--flag value`` / ``--flag=value`` in a command line.

    Tolerant and side-effect-free: unknown tokens are skipped, a trailing flag with no value is
    dropped. ``wanted`` keeps the consume-the-next-token rule from swallowing an unrelated token.
    """
    toks = app_parameters.split()
    i = 0
    while i < len(toks):
        tok = toks[i]
        val: str | None = None
        key = tok
        if "=" in tok:
            key, val = tok.split("=", 1)
        if key in wanted:
            if val is None and i + 1 < len(toks):
                val = toks[i + 1]
                i += 1
            if val is not None:
                yield key, val
        i += 1


_SERVE_BIND_FLAGS = frozenset({"--host", "--port"})
_SERVE_CONFIG_FLAGS = frozenset({"--service-config"})


def parse_serve_args(app_parameters: str) -> tuple[str | None, int | None]:
    """Best-effort scan of a ``serve`` command line for ``--host``/``--port`` (``X`` or ``=X``).

    Tolerant and side-effect-free: unknown tokens are ignored; a malformed host/port yields
    ``None`` for that field rather than raising.
    """
    host: str | None = None
    port: int | None = None
    for key, val in _iter_options(app_parameters, _SERVE_BIND_FLAGS):
        if key == "--host" and _valid_host(val):
            host = val
        elif key == "--port":
            try:
                p = int(val)
            except ValueError:
                continue
            if 1 <= p <= 65535:
                port = p
    return host, port


def parse_service_config_arg(app_parameters: str) -> str | None:
    """The ``serve --service-config <path>`` value, or ``None`` when the flag is absent/hostile.

    That TOML is where ``[api].tls_cert_file`` lives, so it is the only place the tray can learn
    that the engine's bind speaks https (there is no ``serve`` TLS *flag* to sniff).
    """
    found: str | None = None
    for _key, val in _iter_options(app_parameters, _SERVE_CONFIG_FLAGS):
        found = _clean_path_hint(val) or found
    return found


def build_engine_url(host: str | None, port: int | None, *, tls: bool = False) -> str | None:
    """A validated ``http(s)://host:port`` URL, or ``None`` if either part is missing/invalid.

    ``tls`` selects the scheme rather than hardcoding ``http``: the engine serves https on the
    same bind whenever ``[api].tls_cert_file`` is set, and a discovered URL that names the wrong
    scheme probes a dead socket (the tray then renders a live engine as WEDGED).
    """
    if host is None or port is None:
        return None
    if not _valid_host(host) or not (1 <= port <= 65535):
        return None
    # A bare IPv6 literal must be bracketed or the ':'s read as the port separator — `serve
    # --host ::1` would otherwise yield the unparseable "http://::1:8765".
    authority = f"[{host}]" if ":" in host and not host.startswith("[") else host
    return f"{'https' if tls else 'http'}://{authority}:{port}"


def _clean_path_hint(value: object) -> str | None:
    """Accept a plausible filesystem-path hint; reject non-strings, NUL, and oversized values."""
    if not isinstance(value, str):
        return None
    if not value or "\x00" in value or len(value) > _MAX_PATH_LEN:
        return None
    return value


def _normalize_url(url: str) -> str:
    return url.rstrip("/")


def service_toml_uses_tls(service_toml: dict[str, object] | None) -> bool:
    """True when the engine's service settings set ``[api].tls_cert_file`` — i.e. it serves https.

    Pure, and deliberately narrow: presence of the cert path is exactly the engine's own
    ``ServiceSettings.tls_enabled`` predicate. Nothing else is read out of this file — it is
    operator data reached via an untrusted registry hint, so the tray takes one boolean from it
    and no paths, hosts, or secrets.
    """
    if not service_toml:
        return False
    api = service_toml.get("api")
    if not isinstance(api, dict):
        return False
    cert = api.get("tls_cert_file")
    return isinstance(cert, str) and bool(cert.strip())


def compose_config(
    toml_data: dict[str, object] | None,
    reg: ServiceRegistryInfo | None,
    *,
    engine_tls: bool = False,
) -> TrayConfig:
    """Merge built-in defaults ← registry hints ← TOML (TOML wins). Pure.

    ``engine_tls`` scheme-corrects the *registry-derived* URL only; an explicit ``engine_url`` in
    ``tray.toml`` already carries its own scheme and always wins.
    """
    engine_url = DEFAULT_ENGINE_URL
    service_name = DEFAULT_SERVICE_NAME
    repo_path: str | None = None
    poll_seconds = DEFAULT_POLL_SECONDS
    log_path: str | None = None

    # Registry hints (untrusted; validated).
    if reg is not None:
        host_hint, port_hint = parse_serve_args(reg.app_parameters or "")
        url_hint = build_engine_url(host_hint, port_hint, tls=engine_tls)
        if url_hint is not None:
            engine_url = url_hint
        repo_path = _clean_path_hint(reg.app_directory) or repo_path
        log_path = _clean_path_hint(reg.app_stdout) or log_path

    # TOML overrides.
    if toml_data:
        raw_url = toml_data.get("engine_url")
        if isinstance(raw_url, str) and raw_url:
            engine_url = raw_url
        raw_name = toml_data.get("service_name")
        if isinstance(raw_name, str) and is_safe_service_name(raw_name):
            service_name = raw_name
        repo_path = _clean_path_hint(toml_data.get("repo_path")) or repo_path
        log_path = _clean_path_hint(toml_data.get("log_path")) or log_path
        raw_poll = toml_data.get("poll_seconds")
        if isinstance(raw_poll, (int, float)) and not isinstance(raw_poll, bool):
            poll_seconds = max(_POLL_MIN_S, min(_POLL_MAX_S, float(raw_poll)))

    return TrayConfig(
        engine_url=_normalize_url(engine_url),
        service_name=service_name,
        repo_path=repo_path,
        poll_seconds=poll_seconds,
        log_path=log_path,
    )


def _resolve_service_name(toml_data: dict[str, object] | None) -> str:
    """The service name to read the registry with — TOML if safe, else the default."""
    if toml_data:
        raw = toml_data.get("service_name")
        if isinstance(raw, str) and is_safe_service_name(raw):
            return raw
    return DEFAULT_SERVICE_NAME


def _read_toml(path: Path) -> dict[str, object] | None:
    """Parse a TOML file, or ``None`` on any read/parse failure. Never raises."""
    try:
        with path.open("rb") as fh:
            data: dict[str, object] = tomllib.load(fh)
    except (OSError, ValueError):  # ValueError covers TOMLDecodeError + odd decode errors
        return None
    return data


def service_toml_path(reg: ServiceRegistryInfo | None) -> Path | None:
    """Where the engine service's settings TOML lives, per its NSSM registry entry — or ``None``.

    Mirrors ``serve``'s own resolution: an explicit ``--service-config`` (relative paths resolve
    against the service's working directory, which NSSM records as ``AppDirectory``), else
    ``<AppDirectory>/messagefoundry.toml``. Both inputs are untrusted registry strings, already
    length/NUL-validated by :func:`_clean_path_hint`; the result is only ever *read*.
    """
    if reg is None:
        return None
    base = _clean_path_hint(reg.app_directory)
    explicit = parse_service_config_arg(reg.app_parameters or "")
    if explicit is not None:
        candidate = Path(explicit)
        if candidate.is_absolute():
            return candidate
        return Path(base) / candidate if base else None
    return Path(base) / _DEFAULT_SERVICE_TOML if base else None


def load_config(config_dir: Path, reader: RegistryReader | None = None) -> TrayConfig:
    """Read ``<config_dir>/tray.toml`` (if present) and the service registry hints, then compose.

    Missing file → all defaults. A malformed TOML file is treated as absent (defaults + hints).
    The engine's *own* settings TOML is also read — read-only, fail-soft — for the single fact
    the registry cannot carry: whether ``[api].tls_cert_file`` makes the bind serve https.
    """
    toml_data = _read_toml(config_dir / "tray.toml")

    reg: ServiceRegistryInfo | None = None
    if reader is not None:
        reg = reader.read_service_params(_resolve_service_name(toml_data))

    svc_path = service_toml_path(reg)
    engine_tls = service_toml_uses_tls(_read_toml(svc_path) if svc_path is not None else None)

    return compose_config(toml_data, reg, engine_tls=engine_tls)


def default_config_dir() -> Path:
    """``%LOCALAPPDATA%\\MessageFoundry`` on Windows; a home-dir fallback elsewhere (tests)."""
    if sys.platform == "win32":
        import os

        base = os.environ.get("LOCALAPPDATA")
        if base:
            return Path(base) / "MessageFoundry"
    return Path.home() / ".messagefoundry"


TRAY_TOML_TEMPLATE = """\
# MessageFoundry tray settings  —  %LOCALAPPDATA%\\MessageFoundry\\tray.toml
# Every key is optional; a missing key uses the default shown. Uncomment a line to override it,
# then restart the tray (its menu "Exit", then relaunch) so the change takes effect.

# The engine's API base URL the tray polls for status. Both http and https loopback engines are
# fully managed; use https when the engine sets [api].tls_cert_file. Only a REMOTE host puts the
# tray in monitor-only mode (service control + Open-Repo disabled — they need the local box).
# An https engine's certificate is verified against the Windows trust store, so a self-signed
# engine cert must be installed under Trusted Root Certification Authorities on this machine.
# engine_url = "http://127.0.0.1:8765"

# The NSSM Windows service name the tray shows and controls.
# service_name = "MessageFoundry"

# The folder that "Open Repo in VS Code" opens. When unset it defaults to the engine service's own
# install directory (read from its NSSM registry entry). Set this to the repo/estate you actually
# work in — e.g. your config or conversion estate — so the menu opens THAT, not the engine checkout.
# repo_path = 'C:\\Path\\To\\Your\\Estate'

# Status poll interval, in seconds (clamped to 1–3600).
# poll_seconds = 5
"""


def ensure_tray_toml(config_dir: Path) -> Path:
    """Return the ``tray.toml`` path, writing a commented template first if it does not yet exist.

    Never overwrites an existing file. Used by the "Edit Tray Settings" action so the operator always
    opens a self-documenting file (with ``repo_path`` explained) rather than an empty folder.
    """
    config_dir.mkdir(parents=True, exist_ok=True)
    path = config_dir / "tray.toml"
    if not path.exists():
        path.write_text(TRAY_TOML_TEMPLATE, encoding="utf-8")
    return path


class WinregReader:
    """Real Windows registry reader for a service's NSSM ``Parameters`` values (read-only).

    The ``HKLM\\SYSTEM\\CurrentControlSet\\Services\\<name>\\Parameters`` key is readable by a
    standard interactively-logged-on user with no elevation (ADR 0113). Any failure (key absent,
    access denied, non-Windows) yields ``None`` — the tray falls back to defaults.
    """

    def read_service_params(self, service_name: str) -> ServiceRegistryInfo | None:
        if sys.platform != "win32":
            return None
        if not is_safe_service_name(service_name):
            return None
        import winreg  # Windows-only; guarded above

        key_path = f"SYSTEM\\CurrentControlSet\\Services\\{service_name}\\Parameters"
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path) as key:
                return ServiceRegistryInfo(
                    app_directory=_read_value(key, "AppDirectory"),
                    app_parameters=_read_value(key, "AppParameters"),
                    app_stdout=_read_value(key, "AppStdout"),
                )
        except OSError:
            return None


def _read_value(key: object, name: str) -> str | None:
    """Read one string registry value, or ``None`` if absent/not a string. Windows-only helper."""
    import winreg  # Windows-only; only reached from WinregReader under a win32 guard

    try:
        value, kind = winreg.QueryValueEx(key, name)  # type: ignore[arg-type]
    except OSError:
        return None
    if kind not in (winreg.REG_SZ, winreg.REG_EXPAND_SZ) or not isinstance(value, str):
        return None
    if kind == winreg.REG_EXPAND_SZ:
        value = winreg.ExpandEnvironmentStrings(value)
    return value
