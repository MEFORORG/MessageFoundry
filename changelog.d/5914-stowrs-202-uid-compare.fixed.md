- **A DICOMweb STOW-RS 202 is now confirmed only by the instance that was sent.** The
  ReferencedSOPInstanceUID the reply names is compared with the Media Storage SOP Instance UID
  (0002,0003) in the File Meta group of the object sent. A 202 that names only other instances, or
  any 202 for an object with no such UID to compare, is a permanent refusal (`unconfirmed-202`), not
  a delivery. A 200 is not compared. The File Meta group is read without `pydicom`. The refusal
  text names no UID. The rule in full is docs/CONNECTIONS.md *DICOMweb*, *Status classification*.
  (`BACKLOG #5914`)
