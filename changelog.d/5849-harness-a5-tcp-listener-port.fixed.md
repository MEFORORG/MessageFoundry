- **The harness acceptance A5 probe now reports the raw-TCP listener port.** Row A5 names the MLLP,
  DICOM, TCP and API listeners, but the probe reported bindability only for MLLP, DICOM and API. It
  now also reports TCP port 2580, the default of the harness's `IB_Harness_TCP` inbound.
