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

[[ $# -eq 3 ]] || fail "privileged_absolute_install.sh requires three arguments"
readonly source_dir=$1
readonly cmake_command=$2
readonly marker_file=$3

[[ $(id -u) -eq 0 ]] || skip "absolute install test requires root"
[[ ${CADO_DISPOSABLE_ROOT_CONFIRMED:-} == YES ]] ||
	skip "set CADO_DISPOSABLE_ROOT_CONFIRMED=YES in a disposable system"
[[ -f $marker_file && ! -L $marker_file ]] ||
	skip "create the regular disposable-root marker $marker_file"
for command in getcap getent rm stat; do
	command -v "$command" >/dev/null 2>&1 ||
		skip "required command is absent: $command"
done

readonly suffix=$$
readonly bindir="/opt/cado-verify-bin-$suffix"
readonly prefix="/opt/cado-verify-prefix-$suffix"
readonly config_file="/etc/cado-absolute-$suffix.conf"
readonly spool_dir="/var/spool/cado-absolute-$suffix"
readonly build_dir="/var/tmp/cado-absolute-build-$suffix"
for path in "$bindir" "$prefix" "$config_file" "$spool_dir" "$build_dir"; do
	[[ ! -e $path && ! -L $path ]] || skip "refusing existing absolute-install path $path"
done

cleanup() {
	local status=$?
	local cleanup_failed=0
	trap - EXIT
	set +e
	rm -f -- "$config_file" || cleanup_failed=1
	if [[ $bindir == /opt/cado-verify-bin-* ]]; then
		rm -rf -- "$bindir" || cleanup_failed=1
	else
		cleanup_failed=1
	fi
	if [[ $prefix == /opt/cado-verify-prefix-* ]]; then
		rm -rf -- "$prefix" || cleanup_failed=1
	else
		cleanup_failed=1
	fi
	if [[ $spool_dir == /var/spool/cado-absolute-* ]]; then
		rm -rf -- "$spool_dir" || cleanup_failed=1
	else
		cleanup_failed=1
	fi
	if [[ $build_dir == /var/tmp/cado-absolute-build-* ]]; then
		rm -rf -- "$build_dir" || cleanup_failed=1
	else
		cleanup_failed=1
	fi
	if [[ $cleanup_failed -ne 0 && $status -eq 0 ]]; then
		status=1
	fi
	exit "$status"
}
trap cleanup EXIT

printf 'chown : root\n' >"$config_file"
"$cmake_command" -S "$source_dir" -B "$build_dir" \
	-DCMAKE_BUILD_TYPE=Release \
	-DCMAKE_COMPILE_WARNING_AS_ERROR=ON \
	-DBUILD_TESTING=OFF \
	-DCMAKE_INSTALL_PREFIX="$prefix" \
	-DCMAKE_INSTALL_BINDIR="$bindir" \
	-DCMAKE_INSTALL_MANDIR=share/man \
	-DCADO_CONFIG_FILE="$config_file" \
	-DCADO_SPOOL_DIR="$spool_dir" \
	-DCADO_RUN_POST_INSTALL=ON
"$cmake_command" --build "$build_dir" --parallel 4
"$cmake_command" --install "$build_dir"

for program in cado scado cadrop caprint; do
	[[ -f $bindir/$program && ! -L $bindir/$program ]] ||
		fail "absolute install omitted $bindir/$program"
done
[[ ! -e $prefix/bin && ! -L $prefix/bin ]] ||
	fail "absolute CMAKE_INSTALL_BINDIR was incorrectly prefixed"
[[ $(stat -c '%U:%G %a' "$bindir/cado") == '_cado:_cado 4755' ]] ||
	fail "absolute cado install metadata is wrong"
[[ $(stat -c '%U:%G %a' "$bindir/scado") == 'root:_cado 2755' ]] ||
	fail "absolute scado install metadata is wrong"
getcap "$bindir/cado" | grep -q 'cap_dac_read_search' ||
	fail "absolute cado install lacks file capability"
[[ -s $build_dir/install_manifest.txt ]] || fail "absolute install manifest is absent"

"$cmake_command" -DMANIFEST="$build_dir/install_manifest.txt" \
	-P "$source_dir/Uninstall.cmake"
for program in cado scado cadrop caprint; do
	[[ ! -e $bindir/$program && ! -L $bindir/$program ]] ||
		fail "manifest uninstall retained $program"
done
[[ -f $config_file ]] || fail "manifest uninstall removed configuration state"
[[ -d $spool_dir ]] || fail "manifest uninstall removed spool state"
getent passwd _cado >/dev/null || fail "manifest uninstall removed _cado account"
getent group _cado >/dev/null || fail "manifest uninstall removed _cado group"

printf 'privileged absolute-bindir install and state-preserving uninstall passed\n'
