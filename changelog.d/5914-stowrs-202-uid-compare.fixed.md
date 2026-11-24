- **A DICOMweb STOW-RS 202 is now confirmed by the instance that was sent, not by any instance, except where nothing can be compared after a data set read fault.**
  The ReferencedSOPInstanceUID the reply names is compared with the Media Storage SOP Instance UID
  (0002,0003) in the File Meta group of the object sent, read without `pydicom`, and, with the
  `[dicom]` extra installed, with the data set's SOP Instance UID (0008,0018). A 202 that the
  earlier reply rules do not refuse, and that names neither, or that is for an object with neither
  UID to compare, is a permanent refusal (`unconfirmed-202`), not a delivery, except as below
  where the data set read raised a fault the codec does not wrap; the reason names why the File Meta has no UID. Both UIDs are read before the POST, whatever the partner then answers.
  An object the codec cannot parse is still sent, and so is one whose read raised a fault of a
  class the codec takes as a parse failure, even from a broken extra. An installed extra that does
  not load is taken as absent, so only the File Meta UID is compared, and one WARNING per process
  says to repair or remove it. Any other fault in that read, except a `MemoryError`, reads as no
  data set UID too, with one WARNING per process naming its class; where the object also has no
  File Meta UID, a 202 is confirmed as before, by any UID it names. A 200 is not compared. The
  refusal text names no UID. The
  rule in full is docs/CONNECTIONS.md *DICOMweb*, *Status classification*. (`BACKLOG #5914`)
