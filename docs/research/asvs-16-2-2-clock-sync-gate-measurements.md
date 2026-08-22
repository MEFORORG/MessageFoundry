<!--
Measurements taken for BACKLOG #1196 (research: an honest pass for ASVS 16.2.2). Produced by a
builder lane on 2026-08-22 after the dispatcher ordered the container precondition measured before
any gate was written.

SCOPE, because the title is narrower than the item. This memo measures ONE thing: whether the
2026-08-20 research pass's proposed control -- a default-ON, peer-free startup gate that reads the
host's own time-discipline state and refuses -- survives contact with the deployment surfaces the
engine actually ships on. It does not re-open the standard-reading question the pass settled, and it
does not propose a replacement control.

The pass itself lives in the item body and is the authority on everything else. Where this memo and
the pass differ, they differ only on the buildable-control conclusion, and the difference is stated
in section 4 rather than left to be inferred.
-->

# ASVS 16.2.2: what a host clock-sync gate actually returns

**The 2026-08-20 pass concluded an honest pass is reachable through a default-ON refusing gate. That
gate refuses to start the engine on the documented primary deployment surface, today, in the shipped
enforcing posture.** That is a measurement, not an argument, and it is the reason this memo exists.

Everything below was measured on 2026-08-22 against engine tree `00cfbc86`. Every negative carries
the positive control that makes it mean something; where a control failed, the failure is written
down rather than the finding.

*The commit is given because a date is not checkable and a commit is. Code citations here name a
symbol rather than a line for the same reason: a line number rots silently, a symbol does not, and a
commit fails loudly when wrong.*

## 1. The container question, which was the smaller one

The pass files its own eighth subject as a precondition: measure what the probe returns inside
`docker/Dockerfile`'s image, which has no service manager, because a gate that refuses on an
unreadable probe would refuse on every container start.

**The image cannot answer a service-manager probe, established by construction.** `runtime-base`
installs exactly `tini` and `curl` over `python:slim`. There is no systemd, so there is no
`timedatectl`. PID 1 is `tini`. The engine runs as UID 10001 on a read-only root filesystem.

**A syscall probe needs nothing the image lacks.** `ntp_adjtime` through `ctypes` requires only
glibc, which the base image has. Measured unprivileged (euid 1000) on Linux:

| Reading | Value |
|---|---|
| `ntp_adjtime` return | 0 (`TIME_OK`) |
| `status` word | `0x2000`, `STA_UNSYNC` clear |
| `status` field offset | 40 on x86_64 |

Two controls, because a probe that always reports success is worthless:

1. **An independent instrument agrees.** `timedatectl show -p NTPSynchronized` returned `yes` on the
   same host at the same time.
2. **The struct carries live kernel data.** `maxerror` read 5117991, then 5118491, then 5118991 on
   consecutive seconds -- exactly 500 microseconds per second, the kernel's own accumulation rate. A
   zeroed or failed read cannot produce monotonic drift at that rate.

**So the design answer is to key any such gate on `ntp_adjtime`, not on a service manager.** The
pass's eighth-subject worry is real for one candidate probe and not for the other.

## 2. The namespace assumption, which was the load-bearing one

The whole gate rests on an assumption the pass does not state: that a container's view of clock
discipline is the host's. If a time namespace gave the container its own view, the gate would report
confidently about a subject other than the one it claims to verify.

**Measured, and it holds.** Docker's daemon was unavailable, so this was tested with `unshare`, which
is the harder case: Docker does not enable time namespaces by default, so the shipped container has
no namespace at all and reads host state by construction.

| | time namespace | `CLOCK_MONOTONIC` | `ntp_adjtime` |
|---|---|---|---|
| outside | `time:[4026531834]` | 79.70 | rc 0, `STA_UNSYNC` clear |
| inside, `--monotonic 100000` | `time:[4026532230]` | **100079.73** | rc 0, `STA_UNSYNC` clear |

**The control is the finding.** The namespace demonstrably rewrote the process's monotonic clock by
exactly the offset requested, and the discipline probe read identically anyway. The one thing a time
namespace is documented to virtualize moved; the thing the gate depends on did not.

**The first attempt at that control failed, and the failure is the more useful half.** The offset was
first read from `/proc/uptime`: 51.66 on the host, 51.67 inside. No jump. Treating the identical
probe readings as a result at that point would have published a vacuous negative -- identical because
nothing had been applied. The cause was that `--mount-proc` needs privilege and had failed, so the
process was reading the host's procfs from inside the namespace. Moving the control from a procfs
file to a syscall is what made it fire.

*Measured on one kernel, 6.18 under WSL2. This matches documented time-namespace behaviour, which
virtualizes monotonic and boottime offsets only, but one kernel is what was measured.*

## 3. The Windows surface, which nobody had measured

[`docs/SERVICE.md`](../SERVICE.md) and CLAUDE.md section 2 make a Windows service under NSSM the
deployment path. `ntp_adjtime` is Linux-only, and the pass's eight subjects name no Windows probe.

Measured on a developer and test box, read-only:

| Probe | Reading |
|---|---|
| `w32tm /query /status` leap indicator | **3 (not synchronized)** |
| stratum | 0 (unspecified) |
| source | **Local CMOS Clock** |
| last successful sync | **unspecified** |
| `W32Time` service | **Running**, start type Manual |
| `GetSystemTimeAdjustment` | `disabled=True`, adjustment equal to increment |

**The service is up and the clock is undisciplined.** It free-runs at the nominal rate against the
CMOS clock with no reference. This is the finding with the sharpest operational edge: **a probe that
checks service state rather than sync state would call this box healthy.**

### 3.1 Two surfaces disagree about one physical clock

The same machine, in the same minute, reports opposite answers depending on which operating system is
asked. Windows `w32tm` says not synchronized; WSL2 on that host says synchronized, by both
`timedatectl` and `ntp_adjtime`.

**Reported as measured. The mechanism is not established** -- WSL2 maintaining its own discipline is
the obvious candidate, and a plausible candidate must not ship as a cause.

The consequence does not depend on the mechanism. *Is the host clock disciplined* is not one question
with one answer on one box. **A gate must name which clock it asserts about**, or it will refuse and
pass on identical hardware depending on where the engine happens to run.

## 4. What this means for the pass

The pass narrowed an honest 16.2.2 pass to a single control. That control does not survive:

- It refuses to start the engine on the primary deployment surface, in the posture that ships. Not a
  container edge case and not a tuning problem.
- It has no Windows probe, on the platform the deployment documentation is written for.
- It cannot state which clock it is asserting about, on a box where two surfaces disagree.

**None of this reinstates the options the pass ruled out**, and they should not be revisited on the
strength of this memo. Flipping `require_time_sync` remains a load failure without a peer
(`config/settings.py`, the `require_time_sync`/`ntp_peer` validator); shipping a default peer was
ruled out on 2026-08-10; and declaring the cell operator-substrate remains wrong because the engine
built the mechanism.

**The item's filing says "cannot honestly reach pass" is a valid finding.** This memo does not assert
that conclusion -- it removes the one control that had been offered against it, and the gap between
those two sentences is real. What a replacement control would have to do is now three things rather
than one: work on Windows, distinguish service state from sync state, and name its subject.

### 4.1 A structural bind the pass understates

The pass records that `require_time_sync` cannot be flipped alone because the validator demands
`ntp_peer`. The chain is one link longer: `time_sync_fail_closed` requires `require_time_sync`, which
requires `ntp_peer`. **All three knobs are bound, and none is a single-knob flip.** This strengthens
the pass's own structural-bind finding rather than denting it.

## 5. Not established

- **What the probe returns inside the actual `python:slim` image.** The Docker daemon was down. The
  image's inventory above is from the Dockerfile, not from execution. Ruled soft: it does not block
  design, because the namespace question -- the one that did -- is answered in section 2.
- **The mechanism behind the two-surface disagreement in section 3.1.**
- **Behaviour on kernels other than the one named in section 2.**
- **Whether any replacement control is reachable.** Out of scope here by design; this memo measures
  the offered one.
