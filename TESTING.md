# Verification ledger

This ledger records the boundary actually exercised by the default suite and by
the disposable privileged VM suite. A structural check or injected seam is not
reported as a real installed-system result.

## Default unprivileged suite

The default Release suite has deterministic coverage for:

- strict capability, configuration, command-line, scado-file, digest, verified
  copy, install-path, and state-preserving uninstall behavior;
- stale updates, competing creation, delete-versus-edit ordering, source
  mutation, and destination-generation checks in the transaction core;
- malformed and unchanged edits, recovery retention, recovery disposal, and
  editor HUP, INT, and QUIT disposition restoration;
- a phase-controlled edit-core signal matrix for SIGHUP, SIGINT, SIGQUIT,
  SIGTERM, SIGKILL, and a test-only SIGUSR1 handler that calls `_exit` during
  editor execution, hashing, PAM authentication, and commit;
- commit-phase synchronization that polls `/proc/<pid>/syscall` against
  `SYS_flock` under one 15-second monotonic deadline, so each signal is sent
  only after the transaction is blocked in the actual directory-lock syscall;
- protected-destination preservation, exactly one armed recovery whose length
  and bytes match the edited fixture, uncommitted `.cado-stage.*` cleanup, and
  recovery/staging guard termination for every parent-loss case in that matrix;
- execution of the complete matrix from a parent that ignores HUP, INT, and
  QUIT. The top-level test driver restores the normal dispositions before
  starting workers, while the private editor helper modes leave their incoming
  dispositions untouched so the editor child's restoration remains observable;
- an injected failure from the editor child's existing full capability-drop
  operation, with editor failure reported, the protected destination unchanged,
  and exactly one byte-identical recovery retained;
- link-time PAM fault ordering for `pam_start`, `pam_authenticate`, and
  `pam_end`, including authentication-plus-teardown failure precedence and
  diagnostic ordering.

Run the default boundary with warnings promoted to errors:

```console
$ cmake -S . -B build-default \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_COMPILE_WARNING_AS_ERROR=ON \
    -DCADO_RUN_POST_INSTALL=OFF
$ cmake --build build-default --parallel 4
$ ctest --test-dir build-default --output-on-failure
```

## Disposable privileged VM suite

The complete privileged suite passed in fresh attempt `20260827T013946Z` on a
Debian 13.6 GenericCloud amd64 VM and an ext4 guest filesystem with Linux
`6.12.101+deb13-cloud-amd64`, GCC 14.2.0, CMake 3.31.6, Linux-PAM 1.7.0,
libexecs 1.4, mhash 0.9.9.9, and strace 6.13. The immutable base was the
2026-08-19 Debian 13 GenericCloud image with SHA-512:

```text
77429b411b39b43f914dc9d14bf34aa315489a1a12b5429f72e5b483bdda23c65698d33443c85d3f3ad7c3a0828ae60845406d6b99646342554d17abae29c2a3
```

The Release warning-as-error default suite passed 12 of 12 CTests and the
privileged suite passed 11 of 11 CTests, with no failures or skips. The
privileged CTests verified:

- PAM permit and deny, capability policy, setuid/setgid ownership, installed
  setid bits, file capabilities, ambient capabilities, force mode, scado
  digest success and mismatch, verified-copy cleanup, and state-preserving
  manifest uninstall;
- two simultaneous installed `scado -e` writers, `-u` versus `-U`, forced
  `-U` versus `-e`, and forced `-D` versus `-e`, including exactly one stale
  writer, losing-editor recovery, deletion without resurrection, no silently
  lost committed update, and no staging leak. An external spool lock held both
  PAM-recorded transaction PIDs until the private syscall helper observed both
  blocked in `flock`; forced losing editors were stopped only after that gate;
- mutation of the editable recovery file by its owning user while real PAM was
  blocked, with stale-source rejection, protected-destination preservation,
  and retention of the mutated recovery;
- real `pam_start` rejection from the malformed module token
  `auth required ?`, real `pam_authenticate` rejection through
  `pam_deny.so`, and installed-setgid `scado` termination while blocked inside
  the bounded test PAM module;
- all real, effective, saved, and filesystem UID/GID fields plus the complete
  supplementary-group set after the editor privilege drop. The caller had a
  benign supplementary fixture group, making retention and removal observable;
- a private identity driver launched through installed `cado` with
  `cap_chown` in both `CapEff` and `CapAmb`. The driver recorded
  `0000000000000001` for both masks, while its editor recorded zero for both
  after `scado` called the existing full capability-drop operation;
- cleanup of an editor blocked in the bounded PAM module and an independently
  held spool lock while both background jobs were still active. Each helper is
  started in its own verified process group, and cleanup resumes, terminates,
  reaps, and checks the complete group plus any fixture executable that escaped
  it;
- a real install with an absolute `CMAKE_INSTALL_BINDIR`, post-install owner,
  mode, and capability checks, manifest uninstall, and preservation of the
  configuration, spool, and `_cado` state through uninstall.

The final focused probes delayed transaction `fsync` under strace for each of
the six commit-loss signals. Every trace ordered the worker's delayed `fsync`
before an unfinished `flock`, and the unfinished `flock` before the parent
sent its process-group signal. A separate adversarial probe truncated every
live recovery it observed; the matrix failed with its recovery-content
diagnostic, and the unmodified matrix immediately passed afterward.

The privileged cleanup traps preserve an existing nonzero scenario status and
otherwise turn background-process, account/group, PAM/config, recovery, spool,
or bounded-fixture cleanup failure into a failing test. The matrix harness arms
its account and group creation flags only after successful creation, and runs
exact account and group preflights before creating any fixture or cleanup trap.
A focused collision probe made the prospective same-name group first: the
scenario returned skip status 77 and preserved that group. The final audit
found all temporary users, groups, PAM/config/spool state, recoveries, stages,
verified copies, fixtures, and orphan processes absent; `_cado` remained
intentionally.

All privileged tests are `RUN_SERIAL`, have bounded timeouts, carry the
`privileged` label, and retain skip status 77 for an unconfirmed environment. A
skip means the privileged boundary is incomplete; it is not acceptance. Check
the JUnit result and require `skipped="0"` as well as zero failures.

On a disposable root VM with unique absent configuration and spool paths, run:

```console
$ sudo install -o root -g root -m 0600 /dev/null \
    /.cado-disposable-test-root
$ cmake -S . -B build-privileged \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_COMPILE_WARNING_AS_ERROR=ON \
    -DCADO_RUN_POST_INSTALL=OFF \
    -DCADO_ENABLE_PRIVILEGED_TESTS=ON \
    -DCADO_PRIVILEGED_CONFIRMATION=DISPOSABLE_ROOT_ENVIRONMENT \
    -DCADO_CONFIG_FILE=/etc/cado-test-ATTEMPT.conf \
    -DCADO_SPOOL_DIR=/var/spool/cado-test-ATTEMPT
$ cmake --build build-privileged --parallel 4
$ sudo env CADO_DISPOSABLE_ROOT_CONFIRMED=YES \
    ctest --test-dir build-privileged -L privileged \
      --verbose --output-on-failure \
      --output-junit privileged-junit.xml
```

## PAM teardown boundary

Linux-PAM service modules return from authentication entry points, but standard
Linux-PAM provides no service-controlled return value from `pam_end`. A normal
PAM service file or test module therefore cannot inject a teardown failure.
Real PAM covers initialization and authentication above; teardown failure,
authentication-plus-teardown ordering, and diagnostics are verified through the
dedicated link-time `pam_end` seam in the default suite. This is the verified
boundary, not a claim of end-to-end teardown-failure injection.

No verification-ledger item remains open inside these stated boundaries.
