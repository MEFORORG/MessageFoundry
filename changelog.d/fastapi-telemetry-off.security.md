- **The engine API turns fastapi's built-in OpenTelemetry telemetry off.** fastapi 0.142 turns it
  on by default. An `OTEL_EXPORTER_OTLP_*` endpoint in the service environment, with the OpenTelemetry
  SDK installed, would have made fastapi install its own OTLP exporters before startup. Its logs
  carry unhandled-exception messages and stack traces, either of which can hold PHI. `create_app` now passes a
  telemetry config with every switch off, so no environment variable can start that export. The
  engine's own optional OTLP metrics export is separate and unchanged. The FastAPI floor is now
  0.142.0, the first release with the `telemetry` argument.
