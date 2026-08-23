#!/usr/bin/env bash

set -Eeuo pipefail

readonly skip_status=77

skip() {
	printf 'SKIP: %s\n' "$*" >&2
	exit "$skip_status"
}

fail() {
	printf 'FAIL: %s\n' "$*" >&2
	exit 1
}

require_command() {
	command -v "$1" >/dev/null 2>&1 || skip "required command is absent: $1"
}

expect_status() {
	local expected=$1
	shift
	local actual=0

	"$@" >/dev/null 2>&1 || actual=$?
	[[ $actual -eq $expected ]] ||
		fail "expected status $expected, got $actual: $*"
}

expect_compact() {
	local expected=$1
	shift
	local output

	output=$(run_as_test "$@") || fail "capability command failed: $*"
	[[ $output == "$expected" ]] ||
		fail "expected compact capabilities '$expected', got '$output'"
}

run_as_test() {
	runuser -u "$test_user" -- env \
		PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
		SHELL=/bin/true \
		"$@"
}

temporary_copies_exist() {
	find /tmp -maxdepth 1 -type f -name 'cado-exe-copy.*' -print -quit |
		grep -q .
}

poll_no_temporary_copies() {
	local attempt

	for attempt in {1..50}; do
		if ! temporary_copies_exist; then
			return 0
		fi
		sleep 0.1
	done
	return 1
}

[[ $# -eq 9 ]] || fail "privileged_tests.sh requires nine path arguments"

readonly cado_source=$1
readonly scado_source=$2
readonly cadrop_source=$3
readonly caprint_source=$4
readonly post_install_script=$5
readonly uninstall_script=$6
readonly config_file=$7
readonly spool_dir=$8
readonly cmake_command=$9
readonly pam_file=/etc/pam.d/cado
readonly marker_file=/.cado-disposable-test-root

[[ $(id -u) -eq 0 ]] || skip "privileged lifecycle requires root"
[[ ${CADO_DISPOSABLE_ROOT_CONFIRMED:-} == YES ]] ||
	skip "set CADO_DISPOSABLE_ROOT_CONFIRMED=YES in a disposable system"
[[ -f $marker_file && ! -L $marker_file ]] ||
	skip "create the regular marker $marker_file in a disposable system"

for command in chmod chown dirname find getcap getent grep groupadd groupdel id \
	install mkdir mktemp nologin rm runuser sleep stat useradd userdel; do
	require_command "$command"
done
[[ -x $cmake_command ]] || skip "configured CMake command is not executable"
for path in "$cado_source" "$scado_source" "$cadrop_source" \
	"$caprint_source" "$post_install_script" "$uninstall_script"; do
	[[ -f $path && ! -L $path ]] || fail "required regular file is absent: $path"
done
[[ $config_file == /* && $config_file != / ]] ||
	fail "unsafe configured cado.conf path: $config_file"
[[ $spool_dir == /* && $spool_dir != / ]] ||
	fail "unsafe configured spool path: $spool_dir"
[[ -d $(dirname "$config_file") ]] ||
	fail "configuration parent directory is absent: $(dirname "$config_file")"
[[ ! -e $config_file && ! -L $config_file ]] ||
	skip "refusing to replace existing configuration: $config_file"
[[ ! -e $spool_dir && ! -L $spool_dir ]] ||
	skip "refusing to replace existing spool: $spool_dir"
[[ ! -e $pam_file && ! -L $pam_file ]] ||
	skip "refusing to replace existing PAM service: $pam_file"
temporary_copies_exist &&
	skip "refusing to conflate pre-existing /tmp/cado-exe-copy.* state"

readonly suffix=$$
readonly test_user="cadotest${suffix}"
readonly test_group="cadotest${suffix}"
getent passwd "$test_user" >/dev/null 2>&1 &&
	skip "test account already exists: $test_user"
getent group "$test_group" >/dev/null 2>&1 &&
	skip "test group already exists: $test_group"

fixture=
config_created=0
pam_created=0
spool_created=0
user_created=0
group_created=0

cleanup() {
	local status=$?
	local cleanup_failed=0
	trap - EXIT
	set +e
	if [[ $user_created -eq 1 ]]; then
		if ! userdel "$test_user" >/dev/null 2>&1; then
			printf 'FAIL: cannot remove test account %s\n' "$test_user" >&2
			cleanup_failed=1
		fi
	fi
	if [[ $group_created -eq 1 ]]; then
		if ! groupdel "$test_group" >/dev/null 2>&1; then
			printf 'FAIL: cannot remove test group %s\n' "$test_group" >&2
			cleanup_failed=1
		fi
	fi
	if [[ $pam_created -eq 1 ]]; then
		rm -f -- "$pam_file" || cleanup_failed=1
	fi
	if [[ $config_created -eq 1 ]]; then
		rm -f -- "$config_file" || cleanup_failed=1
	fi
	if [[ $spool_created -eq 1 && -n $spool_dir && $spool_dir != / ]]; then
		rm -rf -- "$spool_dir" || cleanup_failed=1
	fi
	find /tmp -maxdepth 1 -type f -name 'cado-exe-copy.*' -delete ||
		cleanup_failed=1
	if [[ -n $fixture && $fixture == /var/tmp/cado-privileged.* ]]; then
		rm -rf -- "$fixture" || cleanup_failed=1
	fi
	if [[ $cleanup_failed -ne 0 && $status -eq 0 ]]; then
		status=1
	fi
	exit "$status"
}
trap cleanup EXIT

fixture=$(mktemp -d /var/tmp/cado-privileged.XXXXXX)
readonly fixture
readonly bin_dir="$fixture/bin"
readonly edit_dir="$fixture/edit"
readonly manifest="$fixture/install_manifest.txt"
mkdir -p "$bin_dir" "$edit_dir"
chmod 0755 "$fixture" "$bin_dir"

install -m 0755 "$cado_source" "$bin_dir/cado"
install -m 0755 "$scado_source" "$bin_dir/scado"
install -m 0755 "$cadrop_source" "$bin_dir/cadrop"
install -m 0755 "$caprint_source" "$bin_dir/caprint"

group_created=1
nologin_path=$(command -v nologin)
readonly nologin_path
groupadd --system "$test_group"
user_created=1
useradd --system --no-create-home --home-dir /nonexistent \
	--shell "$nologin_path" --gid "$test_group" "$test_user"
chown "$test_user:$test_group" "$edit_dir"
chmod 0700 "$edit_dir"

config_created=1
install -m 0600 /dev/null "$config_file"
cat >"$config_file" <<EOF
chown : $test_user
kill : @$test_group
setuid : $test_user : /bin/true
setgid : $test_user : /bin/false
EOF

pam_created=1
cat >"$pam_file" <<'EOF'
# cado disposable privileged test
auth required pam_permit.so
EOF

spool_created=1
"$cmake_command" \
	-DBINDIR="$bin_dir" \
	-DCADO_CONFIG_FILE="$config_file" \
	-DCADO_SPOOL_DIR="$spool_dir" \
	-P "$post_install_script"
[[ -d $spool_dir ]] || fail "post-install did not create the spool"

[[ $(stat -c '%U:%G %a' "$spool_dir") == 'root:_cado 2770' ]] ||
	fail "wrong protected spool metadata"
[[ $(stat -c '%U:%G %a' "$bin_dir/cado") == '_cado:_cado 4755' ]] ||
	fail "wrong cado metadata"
[[ $(stat -c '%U:%G %a' "$bin_dir/scado") == 'root:_cado 2755' ]] ||
	fail "wrong scado metadata"
[[ $(stat -c '%U:%G %a' "$bin_dir/cadrop") == 'root:root 755' ]] ||
	fail "wrong cadrop metadata"
[[ $(stat -c '%U:%G %a' "$bin_dir/caprint") == 'root:root 755' ]] ||
	fail "wrong caprint metadata"
getcap "$bin_dir/cado" | grep -q 'cap_dac_read_search' ||
	fail "cado lacks the protected-read file capability"

expect_compact chown "$bin_dir/cado" chown "$bin_dir/caprint" -c
expect_compact kill "$bin_dir/cado" kill "$bin_dir/caprint" -c
expect_compact setuid "$bin_dir/cado" setuid "$bin_dir/caprint" -c
expect_status 2 run_as_test "$bin_dir/cado" setgid "$bin_dir/caprint" -c
expect_compact chown "$bin_dir/cado" -f chown,sys_admin \
	"$bin_dir/caprint" -c
expect_status 2 run_as_test "$bin_dir/cado" chown,sys_admin \
	"$bin_dir/caprint" -c

prompt_output=$(run_as_test "$bin_dir/cado" chown "$bin_dir/caprint" -p) ||
	fail "caprint prompt format failed"
[[ $prompt_output == 'chown#' ]] ||
	fail "unexpected caprint prompt format: $prompt_output"
long_output=$(run_as_test "$bin_dir/cado" chown "$bin_dir/caprint" -l) ||
	fail "caprint long format failed"
[[ $long_output == *cap_chown* ]] ||
	fail "caprint long format omitted cap_chown: $long_output"

readonly shell_wrapper="$fixture/cado-shell"
cat >"$shell_wrapper" <<'EOF'
#!/bin/sh
exec "$CADO_TEST_CAPRINT" -c
EOF
chmod 0755 "$shell_wrapper"
shell_output=$(run_as_test env SHELL="$shell_wrapper" \
	CADO_TEST_CAPRINT="$bin_dir/caprint" "$bin_dir/cado" chown) ||
	fail "cado shell fallback failed"
[[ $shell_output == chown ]] ||
	fail "cado shell fallback lost ambient capability: $shell_output"

cat >"$pam_file" <<'EOF'
# cado disposable privileged test
auth required pam_deny.so
EOF
expect_status 2 run_as_test "$bin_dir/cado" chown "$bin_dir/caprint" -c
cat >"$pam_file" <<'EOF'
# cado disposable privileged test
auth required pam_permit.so
EOF

readonly editor="$fixture/write-scado"
cat >"$editor" <<'EOF'
#!/bin/sh
printf '%s : chown :\n' "$CADO_TEST_SCADO_TARGET" >"$1"
printf '%s : chown :\n' "$CADO_TEST_SHELL_TARGET" >>"$1"
EOF
chmod 0755 "$editor"
run_as_test env \
	EDITOR="$editor" \
	TMPDIR="$edit_dir" \
	CADO_TEST_SCADO_TARGET="$bin_dir/caprint" \
	CADO_TEST_SHELL_TARGET=/bin/sh \
	"$bin_dir/scado" -e

readonly user_scado="$spool_dir/$test_user"
[[ -f $user_scado && ! -L $user_scado ]] ||
	fail "scado edit did not install the user file"
[[ $(stat -c '%a' "$user_scado") == 600 ]] ||
	fail "persisted scado file is not mode 0600"
scado_output=$(run_as_test "$bin_dir/scado" -l) || fail "scado -l failed"
mapfile -t scado_lines <<<"$scado_output"
[[ ${#scado_lines[@]} -eq 2 ]] ||
	fail "scado -l returned ${#scado_lines[@]} entries, expected two"
for expected_path in "$bin_dir/caprint" /bin/sh; do
	matching_line=
	for line in "${scado_lines[@]}"; do
		if [[ $line == "$expected_path : chown : "* ]]; then
			matching_line=$line
			break
		fi
	done
	[[ -n $matching_line ]] || fail "missing persisted entry: $expected_path"
	digest=${matching_line#"$expected_path : chown : "}
	[[ $digest =~ ^[[:xdigit:]]{64}$ ]] ||
		fail "persisted digest is malformed for $expected_path: $digest"
done

expect_compact chown "$bin_dir/cado" -S chown "$bin_dir/caprint" -c
poll_no_temporary_copies || fail "verified-copy watchdog left a temporary file"
run_as_test "$bin_dir/cado" -S chown /bin/sh -c \
	'test "$0" = /bin/sh' || fail "verified copy changed the original argv[0]"
poll_no_temporary_copies || fail "argv[0] probe left a temporary copy"
expect_status 2 run_as_test "$bin_dir/cado" -S 0 /bin/true
expect_status 2 run_as_test "$bin_dir/cado" -S -f chown /bin/true
run_as_test "$bin_dir/cado" -S 0 /bin/sh -c ':' ||
	fail "matching zero-capability scado authorization was rejected"
poll_no_temporary_copies || fail "zero-capability probe left a temporary copy"

printf '\0' >>"$bin_dir/caprint"
expect_status 2 run_as_test "$bin_dir/cado" -S chown \
	"$bin_dir/caprint" -c
poll_no_temporary_copies || fail "digest mismatch left a temporary copy"
install -m 0755 "$caprint_source" "$bin_dir/caprint"
run_as_test "$bin_dir/scado" -u "$bin_dir/caprint" ||
	fail "scado -u failed for a persisted digest"
expect_compact chown "$bin_dir/cado" -S chown "$bin_dir/caprint" -c
poll_no_temporary_copies || fail "updated verified copy was not removed"

printf '%s\n' "$bin_dir/cado" "$bin_dir/scado" "$bin_dir/cadrop" \
	"$bin_dir/caprint" >"$manifest"
"$cmake_command" -DMANIFEST="$manifest" -P "$uninstall_script"
for program in cado scado cadrop caprint; do
	[[ ! -e $bin_dir/$program && ! -L $bin_dir/$program ]] ||
		fail "uninstall retained manifest program: $program"
done
[[ -f $config_file ]] || fail "uninstall removed cado.conf"
[[ -d $spool_dir && -f $user_scado ]] ||
	fail "uninstall removed protected scado state"
getent passwd _cado >/dev/null || fail "uninstall removed the _cado account"
getent group _cado >/dev/null || fail "uninstall removed the _cado group"

printf 'privileged lifecycle passed; _cado account/group intentionally preserved\n'
