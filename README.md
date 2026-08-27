# cado

Cado delegates selected Linux ambient capabilities without giving a process a
root identity. The repository installs four programs:

- `cado` authenticates a user and runs a command with an authorized ambient
  capability set.
- `scado` manages that user's protected executable-specific authorizations.
- `cadrop` removes ambient capabilities before running a command.
- `caprint` displays a process's ambient capability set.

## Platform and dependencies

Cado supports current Linux with `/proc`, ambient capabilities, PAM, libcap,
mhash, and libexecs 1.4. Both development headers and libraries are required.
On a Debian-family system the package names are commonly:

```console
$ sudo apt install libpam0g-dev libcap-dev libmhash-dev libexecs-dev
```

Libexecs must expose `EXECS_SOVERSION == 1` and `system_execsqa`. Older sequence
APIs are not supported.

## Build and test

```console
$ cmake -S . -B build
$ cmake --build build
$ ctest --test-dir build --output-on-failure
```

Default tests are unprivileged and do not alter accounts, PAM configuration,
installed programs, file capabilities, `/etc/cado.conf`, or scado spool data.
See [TESTING.md](TESTING.md) for the verified default and disposable-VM
boundaries, the reproducible privileged command, and the PAM teardown limit.
Privileged tests are disabled by default. They are registered only with both:

```console
-DCADO_ENABLE_PRIVILEGED_TESTS=ON
-DCADO_PRIVILEGED_CONFIRMATION=DISPOSABLE_ROOT_ENVIRONMENT
```

The test itself additionally requires root, the marker
`/.cado-disposable-test-root`, and `CADO_DISPOSABLE_ROOT_CONFIRMED=YES`. This is
for a disposable container or VM, never an ordinary host.

## Configuration

Create `/etc/cado.conf` before installation. Every nonblank, noncomment line is
exactly one of:

```text
capability-list : principal-list
capability-list : principal-list : condition-sequence
```

Lines whose first non-whitespace character is `#` are comments. Extra fields,
missing principals, empty or malformed list items, invalid capabilities, and
empty condition sequences invalidate the entire file. Cado reports the file
and line and grants nothing from a malformed file.

A capability list is comma-separated. Each item is either a libcap name (with
or without `cap_`) or an unsigned, unprefixed hexadecimal mask. Surrounding
whitespace is ignored. Empty lists/items, signs, `0x` prefixes, overflow,
trailing text, and bits above `CAP_LAST_CAP` are rejected.

A principal is a username or a group name prefixed by `@`. For example:

```text
# Capability Ambient DO configuration
net_admin: @netadmin,renzo
cap_kill: renzo
setgid,setuid: giovanni: /usr/bin/logger cado identity caps for $USER
c0: giovanni,@idgroup
```

Conditions are libexecs command sequences. Environment variables are expanded;
every condition child drops its ambient capabilities. A nonzero condition
denies that entry.

## Installation model

Install after the configuration exists:

```console
$ sudo cmake --install build
```

The checked post-install step creates `_cado` only when it is absent, then
validates the account and group. It requires nonzero UID/GID values and rejects
supplementary `_cado` members. The protected spool is owned by `root:_cado` with
mode `2770`.

`cado` is setuid to the unprivileged `_cado` account rather than UID 0. It also
holds only the file capabilities computed from `/etc/cado.conf` plus
`cap_dac_read_search`. `scado` is owned by `root:_cado` and setgid `_cado`.
`cadrop` and `caprint` are ordinary root-owned executables. The post-install
step verifies every final owner, mode, and the `cado` file capability.

A `DESTDIR` staging install must be configured with
`-DCADO_RUN_POST_INSTALL=OFF`; the privileged post-install step refuses to
mutate a staging tree. Run the checked post-install operation only in the final
system containing the installed paths.

`CMAKE_INSTALL_BINDIR` may be relative or absolute. Relative values follow the
effective install-time prefix, including `cmake --install --prefix`; absolute
values are passed unchanged to the checked post-install step.

After changing `/etc/cado.conf`, recompute the file capability as root:

```console
$ sudo cado --setcap
$ sudo cado --setcap --verbose
```

## `cado`

```console
$ cado [options] capability-list [command [args...]]
```

If the command is omitted, cado uses `$SHELL`. `--force` (`-f`) grants the
intersection when only part of the request is authorized; without it, any
unavailable bit denies the request. `--verbose` (`-v`) prints the requested,
available, unavailable, and granted sets. `cado -v` alone lists the current
user's authorized capabilities.

`--scado` (`-S`) requires an explicit absolute command path. A matching scado
entry replaces the PAM prompt. If that entry has a digest, cado copies the
executable first, verifies that protected copy, drops the setuid identity,
grants ambient capabilities, and executes the copy with the command's original
`argv[0]`.

## `scado`

Each persisted entry is exactly:

```text
absolute path : capability-list
absolute path : capability-list : 64-hexadecimal-character SHA-256
```

A trailing `#` begins a comment. Field edges are trimmed, internal path spaces
are preserved, and backslashes are literal. A persisted digest is either absent
(two fields) or exactly 64 hexadecimal characters. During `scado -e` only, an
empty third field requests digest calculation; it is filled before installation
and is never persisted empty.

`scado -e` edits, authenticates, validates, then atomically installs a mode-0600
staging file in the spool. It checks that the edited input did not change during
authentication. Every post-editor failure preserves and reports the editable
recovery copy. `scado -u /absolute/path` updates one existing digest and fails if
the path is absent or has no digest; `scado -U` updates all persisted digests.
`scado -l` lists the file and `scado -D` deletes it after authentication. Exactly
one action is required.

## `cadrop` and `caprint`

`cadrop` accepts three forms for dropping every ambient capability: omit the
capability argument, use `all`, or use `-`. An empty string is invalid. A
specific capability list uses the same strict grammar as cado.

`caprint [options] [pid]` accepts only a strict positive decimal PID. Its
default, compact (`-c`), prompt (`-p`), and long (`-l`) formats retain their
documented output; the three format options are mutually exclusive.

## Uninstall and preserved state

```console
$ cmake --build build --target uninstall
```

Uninstall removes and verifies only files listed in `install_manifest.txt`. It
preserves `/etc/cado.conf`, the configured spool directory, every user's scado
file, and the `_cado` account/group. There is no automatic purge target. Removing
that state is a separate destructive administrator operation: inspect and name
the exact configuration, spool contents, and account/group to remove before
doing it.
