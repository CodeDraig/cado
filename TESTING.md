# Testing status and follow-up ledger

This ledger separates regressions exercised by the default unprivileged CTest
suite from projected or environment-dependent behavior. An entry marked
projected or unverified is not a claim that the defect occurs on the current
host.

## Reproduced regressions

The default suite contains deterministic coverage for:

- stale and competing-creation scado transactions, including destination
  generation conflicts and delete-versus-edit ordering;
- strict validation of an unchanged edited file, with malformed input retained
  as a recovery copy and valid input discarded without PAM;
- SIGTERM after the editor exits, with the protected file unchanged and the
  sparse edited recovery copy retained;
- SIGKILL during the pre-editor copy, with the unarmed partial recovery file
  removed by its guard;
- SIGKILL while a rendered transaction waits for the spool lock, with the
  partial `.cado-stage.*` file removed and the destination unchanged;
- editor execution with the caller's HUP, INT, and QUIT dispositions restored
  instead of inheriting scado's temporary ignored dispositions;
- injected `pam_start` failure with an invalid output handle, proving that the
  handle and all later PAM operations remain unused;
- interruption after a verified executable copy begins, with its watchdog
  removing the partial named file;
- relative and absolute `CMAKE_INSTALL_BINDIR` generation without performing an
  installation.

Run these and the rest of the unprivileged suite with:

```console
$ cmake -S . -B build -DCADO_RUN_POST_INSTALL=OFF
$ cmake --build build
$ ctest --test-dir build --output-on-failure
```

## Further testing required

### Concurrent scado commands — projected

The transaction tests exercise the shared directory lock and generation checks,
but have not run overlapping installed `scado -u`, `scado -U`, `scado -D`, and
`scado -e` processes through real PAM and setgid execution. Use barriers after
both writers have authenticated and captured their source snapshots. Exactly one
stale writer must fail, no committed update may be silently lost, deletion must
not be undone by a stale editor, and every failed edit must retain its recovery
copy.

### Edited input changed during PAM — unverified end to end

The transaction core rejects a source whose digest changed after the pre-PAM
hash. A live test still needs a deliberately delayed PAM module or conversation:
change the editable temporary file after the editor exits but before PAM returns.
The installed scado file must remain unchanged, the operation must fail, and the
changed editable file must be reported and retained.

### PAM integration failures — stub verified, system path unverified

The isolated stub test injects a `pam_start` failure, returns an invalid output
handle, and proves that the handle, `pam_strerror`, `pam_authenticate`, and
`pam_end` are not used. A real PAM module or service has not injected
initialization, authentication, or teardown failures end to end. Run those only
in the disposable privileged environment and verify the same call ordering and
diagnostics without changing this host's PAM service.

### Recovery signal matrix — partially verified

SIGKILL during initial copying, editor HUP/INT/QUIT disposition restoration, and
SIGTERM after editor completion are covered. Repeat phase-controlled parent-loss
tests for SIGHUP, SIGINT, SIGQUIT, SIGKILL, and abrupt `_exit` while the editor
runs, during hashing, during authentication, and during commit. Every armed loss
must retain the recovery file; successful validation or commit must leave no
recovery guard or temporary file.

### Privileged lifecycle — not run

Run only in a disposable root container or VM that satisfies all confirmation
gates documented in the README. Cover PAM allow/deny, user and group matching,
condition commands, setuid/setgid ownership, file capabilities, ambient
capabilities observed through `caprint`, force mode, digest success and mismatch,
watchdog cleanup, absolute-bindir installation, final permissions, and
state-preserving uninstall. Record a skipped privileged suite as not run rather
than passing.
