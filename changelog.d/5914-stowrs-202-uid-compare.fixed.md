- **A DICOMweb STOW-RS 202 is now confirmed by the instance that was sent, not by any instance.**
  The ReferencedSOPInstanceUID the reply names is compared with the Media Storage SOP Instance UID
  (0002,0003) in the File Meta group of the object sent, read without `pydicom`, and, with the
  `[dicom]` extra installed, with the data set's SOP Instance UID (0008,0018). A 202 that the
  earlier reply rules do not refuse, and that names neither, or that is for an object with neither
  UID to compare, is a permanent refusal (`unconfirmed-202`), not a delivery; the reason names why
  the File Meta has no UID. A 200 is not compared. The refusal text names no UID. The rule in full
  is docs/CONNECTIONS.md *DICOMweb*, *Status classification*. (`BACKLOG #5914`)
