- **An MLLP, HTTP or DICOM listener's CRL refusal now names the connection and its
  `tls_crl_file`.** A missing or bad per-connection CRL used to be reported only as
  `CRL file '<path>'`, so the operator had to work out which connection it belonged to. It now
  reads `inbound connection '<name>' tls_crl_file ('<path>')`, the shape the inbound CA's refusals
  already use. (`BACKLOG #1997`)
