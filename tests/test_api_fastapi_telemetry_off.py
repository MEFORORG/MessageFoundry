# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The engine app turns fastapi's built-in OpenTelemetry telemetry off (CLAUDE.md section 9).

fastapi 0.142 reads ``OTEL_EXPORTER_OTLP_*`` before lifespan startup and installs its own OTLP
exporters unless the app says otherwise. ``create_app`` passes a telemetry config with every switch
off, so an environment variable alone cannot make the engine export anything.

fastapi's lifespan catches a failed auto-configuration and logs a warning instead of raising, so
the warning is the observable. Each test pairs the engine app with a bare ``FastAPI()`` under the
same conditions and shows the bare app DOES react; without that control a probe that could never
fire would pass too.
"""

from __future__ import annotations

import importlib.util
import logging

import pytest
from fastapi import FastAPI
from opentelemetry import _logs, metrics, trace
from starlette.testclient import TestClient

from messagefoundry.api import create_app

_WARNING = "FastAPI automatic telemetry configuration failed"
_SDK_INSTALLED = importlib.util.find_spec("opentelemetry.sdk") is not None

# Each case makes fastapi's auto-configuration fail before it touches a global provider, so the
# control never installs a real exporter. "no-sdk" fails on the SDK import, which needs the SDK to
# be absent. "grpc" fails on the protocol check first, so it holds whether or not the SDK is there.
_CASES = [
    pytest.param(
        {},
        id="no-sdk",
        marks=pytest.mark.skipif(_SDK_INSTALLED, reason="the case needs the SDK absent"),
    ),
    pytest.param({"OTEL_EXPORTER_OTLP_PROTOCOL": "grpc"}, id="grpc"),
]


def _run_lifespan(app: FastAPI) -> None:
    with TestClient(app):
        pass


def _providers_unconfigured() -> bool:
    return (
        type(trace.get_tracer_provider()).__name__ == "ProxyTracerProvider"
        and type(metrics.get_meter_provider()).__name__ == "_ProxyMeterProvider"
        and type(_logs.get_logger_provider()).__name__ == "ProxyLoggerProvider"
    )


@pytest.mark.parametrize("extra_env", _CASES)
def test_an_otlp_endpoint_in_the_environment_configures_nothing(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture, extra_env: dict[str, str]
) -> None:
    for name in (
        "OTEL_SDK_DISABLED",
        "OTEL_TRACES_EXPORTER",
        "OTEL_METRICS_EXPORTER",
        "OTEL_LOGS_EXPORTER",
    ):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://127.0.0.1:4318")
    for name, value in extra_env.items():
        monkeypatch.setenv(name, value)
    assert _providers_unconfigured()

    # Control: a bare app under the same environment does try to configure exporters.
    with caplog.at_level(logging.WARNING, logger="fastapi"):
        _run_lifespan(FastAPI())
    assert _WARNING in caplog.text
    caplog.clear()

    with caplog.at_level(logging.WARNING, logger="fastapi"):
        _run_lifespan(create_app())
    assert _WARNING not in caplog.text
    assert _providers_unconfigured()


def test_a_configured_provider_does_not_switch_request_telemetry_on(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Stand in for any component that configures a global provider. fastapi then wraps every
    # request in its telemetry, which extracts trace headers and records spans, metrics and logs.
    monkeypatch.setattr(trace, "get_tracer_provider", lambda: object())
    monkeypatch.setattr(metrics, "get_meter_provider", lambda: object())
    monkeypatch.setattr(_logs, "get_logger_provider", lambda: object())

    # Control: the bare app turns its request telemetry on.
    assert FastAPI()._native_telemetry.enabled() is True
    assert create_app()._native_telemetry.enabled() is False


def test_every_fastapi_telemetry_switch_is_off() -> None:
    # The behavioral tests above stay green if auto_configure or operation_spans alone is dropped,
    # because the other switches mask them today. Pin each one so a later fastapi cannot unmask it.
    config = create_app()._telemetry
    for key in ("tracing", "metrics", "logs", "operation_spans", "auto_configure"):
        assert config[key] is False, key
