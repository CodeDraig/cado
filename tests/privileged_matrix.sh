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

wait_for_file() {
	local path=$1
	local attempt

	for attempt in {1..750}; do
		[[ -f $path && ! -L $path ]] && return 0
		sleep 0.02
	done
	fail "timed out waiting for $path"
}

stage_count() {
	find "$spool_dir" -maxdepth 1 -type f -name '.cado-stage.*' -printf x |
		wc -c
}

wait_for_flock() {
	"$test_helper" --wait-flock "$@" ||
		fail "transactions did not all block in flock: $*"
}

same_group_set() {
	local expected=$1
	local actual=$2
	local group
	local expected_count=0
	local actual_count=0

	for group in $expected; do
		expected_count=$((expected_count + 1))
		[[ " $actual " == *" $group "* ]] || return 1
	done
	for group in $actual; do
		actual_count=$((actual_count + 1))
	done
	[[ $actual_count -eq $expected_count ]]
}

has_cap_chown() {
	local capabilities=$1

	[[ $capabilities =~ ^[[:xdigit:]]+$ ]] || return 1
	(( (16#$capabilities & 1) == 1 ))
}

recovery_count() {
	find /tmp -maxdepth 1 -type f -name 'cado-scado.*' -printf x |
		wc -c
}

expect_one_winner() {
	local first=$1
	local second=$2

	if ! { [[ $first -eq 0 && $second -eq 255 ]] ||
			[[ $first -eq 255 && $second -eq 0 ]]; }; then
		fail "expected one success and one stale failure, got $first and $second"
	fi
}

run_as_test() {
	setpriv --reuid="$test_uid" --regid="$test_gid" --init-groups env \
		PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
		HOME="$fixture/home" TMPDIR="$edit_dir" SHELL=/bin/true "$@"
}

start_in_group() {
	local attempt
	local process_group

	setsid "$@" &
	started_pid=$!
	for attempt in {1..100}; do
		if [[ -r /proc/$started_pid/stat ]]; then
			process_group=$(awk '{print $5}' "/proc/$started_pid/stat")
			[[ $process_group == "$started_pid" ]] && return 0
		elif ! kill -0 "$started_pid" 2>/dev/null; then
			wait "$started_pid" 2>/dev/null || true
			fail "background command exited before creating process group $started_pid"
		fi
		sleep 0.01
	done
	kill -TERM "$started_pid" 2>/dev/null || true
	wait "$started_pid" 2>/dev/null || true
	fail "background command did not create process group $started_pid"
}

start_as_test() {
	start_in_group setpriv --reuid="$test_uid" --regid="$test_gid" \
		--init-groups env \
		PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
		HOME="$fixture/home" TMPDIR="$edit_dir" SHELL=/bin/true "$@"
}

set_pam_permit() {
	printf '%s\n' \
		'# cado disposable privileged test' \
		'auth required pam_permit.so' >"$pam_file"
}

set_pam_deny() {
	printf '%s\n' \
		'# cado disposable privileged test' \
		'auth required pam_deny.so' >"$pam_file"
}

set_pam_barrier() {
	printf '%s\n' \
		'# cado disposable privileged test barrier' \
		"auth required $pam_fixture $control_dir timeout=15" >"$pam_file"
}

release_pam() {
	local token=$1
	local disposition=${2:-success}

	printf '%s\n' "$disposition" >"$control_dir/release.$token"
}

entered_pid() {
	local token=$1
	local process

	read -r process <"$control_dir/entered.$token"
	[[ $process =~ ^[1-9][0-9]*$ ]] ||
		fail "PAM barrier wrote an invalid process id for $token: $process"
	printf '%s\n' "$process"
}

start_spool_lock() {
	lock_entered="$fixture/lock-entered"
	lock_release="$fixture/lock-release"
	start_in_group flock -x "$spool_dir" sh -c '
		: >"$1"
		count=0
		while [ ! -e "$2" ] && [ "$count" -lt 1500 ]; do
			sleep 0.02
			count=$((count + 1))
		done
		[ -e "$2" ]
	' sh "$lock_entered" "$lock_release"
	lock_pid=$started_pid
	wait_for_file "$lock_entered"
}

release_spool_lock() {
	: >"$lock_release"
	wait "$lock_pid" || fail "spool lock helper failed"
	lock_pid=
}

wait_two() {
	local first_pid=$1
	local second_pid=$2

	set +e
	wait "$first_pid"
	first_status=$?
	wait "$second_pid"
	second_status=$?
	set -e
}

terminate_background_group() {
	local leader=$1
	local attempt
	local failed=0

	if kill -0 -- "-$leader" 2>/dev/null; then
		if ! kill -CONT -- "-$leader" 2>/dev/null &&
				kill -0 -- "-$leader" 2>/dev/null; then
			printf 'FAIL: cannot resume background process group %s\n' \
				"$leader" >&2
			failed=1
		fi
		if ! kill -TERM -- "-$leader" 2>/dev/null &&
				kill -0 -- "-$leader" 2>/dev/null; then
			printf 'FAIL: cannot terminate background process group %s\n' \
				"$leader" >&2
			failed=1
		fi
		sleep 0.1
		if kill -0 -- "-$leader" 2>/dev/null &&
				! kill -KILL -- "-$leader" 2>/dev/null &&
				kill -0 -- "-$leader" 2>/dev/null; then
			printf 'FAIL: cannot kill background process group %s\n' \
				"$leader" >&2
			failed=1
		fi
	fi
	wait "$leader" 2>/dev/null || true
	for attempt in {1..250}; do
		if ! kill -0 -- "-$leader" 2>/dev/null; then
			return "$failed"
		fi
		sleep 0.02
	done
	printf 'FAIL: background process group %s survived cleanup\n' "$leader" >&2
	return 1
}

fixture_process_pids() {
	local executable
	local process
	local target

	[[ -n ${fixture:-} ]] || return 0
	for executable in /proc/[1-9]*/exe; do
		target=$(readlink "$executable" 2>/dev/null) || continue
		case "$target" in
		"$fixture/"*)
			process=${executable#/proc/}
			printf '%s\n' "${process%/exe}"
			;;
		esac
	done
}

terminate_lingering_fixture_processes() {
	local attempt
	local process
	local -a processes=()

	for attempt in {1..250}; do
		mapfile -t processes < <(fixture_process_pids)
		[[ ${#processes[@]} -eq 0 ]] && return 0
		sleep 0.02
	done
	printf 'FAIL: fixture processes survived process-group cleanup: %s\n' \
		"${processes[*]}" >&2
	for process in "${processes[@]}"; do
		kill -CONT "$process" 2>/dev/null || true
		kill -TERM "$process" 2>/dev/null || true
	done
	sleep 0.1
	for process in "${processes[@]}"; do
		kill -KILL "$process" 2>/dev/null || true
	done
	for attempt in {1..250}; do
		mapfile -t processes < <(fixture_process_pids)
		[[ ${#processes[@]} -eq 0 ]] && return 1
		sleep 0.02
	done
	printf 'FAIL: fixture processes remain after forced cleanup: %s\n' \
		"${processes[*]}" >&2
	return 1
}

install_initial_scado() {
	local contents

	contents=$(printf '%s : chown : \n%s : kill : \n' "$target_one" "$target_two")
	set_pam_permit
	run_as_test env EDITOR="$editor" CADO_EDITOR_CONTENT="$contents" \
		"$bin_dir/scado" -e || fail "cannot create initial scado file"
	[[ -f $user_scado && ! -L $user_scado ]] ||
		fail "initial scado file was not installed"
}

case_edit_edit() {
	local one two pid_one pid_two process_one process_two

	install_initial_scado
	one=$(printf '%s : chown : \n# writer-one\n' "$target_one")
	two=$(printf '%s : kill : \n# writer-two\n' "$target_two")
	set_pam_barrier
	start_spool_lock
	start_as_test env CADO_TEST_TOKEN=editone EDITOR="$editor" \
		CADO_EDITOR_CONTENT="$one" "$bin_dir/scado" -e \
		>"$fixture/edit-one.out" 2>"$fixture/edit-one.err"
	pid_one=$started_pid
	start_as_test env CADO_TEST_TOKEN=edittwo EDITOR="$editor" \
		CADO_EDITOR_CONTENT="$two" "$bin_dir/scado" -e \
		>"$fixture/edit-two.out" 2>"$fixture/edit-two.err"
	pid_two=$started_pid
	wait_for_file "$control_dir/entered.editone"
	wait_for_file "$control_dir/entered.edittwo"
	process_one=$(entered_pid editone)
	process_two=$(entered_pid edittwo)
	release_pam editone
	release_pam edittwo
	wait_for_flock "$process_one" "$process_two"
	release_spool_lock
	wait_two "$pid_one" "$pid_two"
	expect_one_winner "$first_status" "$second_status"
	[[ $(recovery_count) -eq 1 ]] ||
		fail "simultaneous editors did not retain exactly one losing recovery"
	[[ $(stage_count) -eq 0 ]] || fail "simultaneous editors leaked staging files"
	if [[ $first_status -eq 0 ]]; then
		grep -Fq '# writer-one' "$user_scado" || fail "writer one won but was lost"
		grep -Fq '# writer-two' /tmp/cado-scado.* ||
			fail "writer two recovery is missing its edit"
	else
		grep -Fq '# writer-two' "$user_scado" || fail "writer two won but was lost"
		grep -Fq '# writer-one' /tmp/cado-scado.* ||
			fail "writer one recovery is missing its edit"
	fi
}

case_update_path_update_all() {
	local before_one before_two after_one after_two pid_one pid_two
	local process_one process_two

	install_initial_scado
	before_one=$(sha256sum "$target_one" | awk '{print $1}')
	before_two=$(sha256sum "$target_two" | awk '{print $1}')
	printf 'changed-one\n' >>"$target_one"
	printf 'changed-two\n' >>"$target_two"
	after_one=$(sha256sum "$target_one" | awk '{print $1}')
	after_two=$(sha256sum "$target_two" | awk '{print $1}')
	set_pam_barrier
	start_spool_lock
	start_as_test env CADO_TEST_TOKEN=updateone "$bin_dir/scado" -u "$target_one" \
		>"$fixture/update-one.out" 2>"$fixture/update-one.err"
	pid_one=$started_pid
	start_as_test env CADO_TEST_TOKEN=updateall "$bin_dir/scado" -U \
		>"$fixture/update-all.out" 2>"$fixture/update-all.err"
	pid_two=$started_pid
	wait_for_file "$control_dir/entered.updateone"
	wait_for_file "$control_dir/entered.updateall"
	process_one=$(entered_pid updateone)
	process_two=$(entered_pid updateall)
	release_pam updateone
	release_pam updateall
	wait_for_flock "$process_one" "$process_two"
	release_spool_lock
	wait_two "$pid_one" "$pid_two"
	expect_one_winner "$first_status" "$second_status"
	grep -Fqx "$target_one : chown : $after_one" "$user_scado" ||
		fail "winning updater did not persist the new first digest"
	if [[ $first_status -eq 0 ]]; then
		grep -Fqx "$target_two : kill : $before_two" "$user_scado" ||
			fail "path-only winner changed or lost the second digest"
	else
		grep -Fqx "$target_two : kill : $after_two" "$user_scado" ||
			fail "update-all winner did not persist the second digest"
	fi
	[[ $before_one != "$after_one" && $before_two != "$after_two" ]] ||
		fail "digest mutation fixture did not change"
	[[ $(stage_count) -eq 0 ]] || fail "competing updaters leaked staging files"
}

case_update_all_edit() {
	local edited pid_update pid_edit edit_process update_process
	local update_status edit_status

	install_initial_scado
	printf 'changed-before-update-all\n' >>"$target_one"
	edited=$(printf '%s : kill : \n# forced-editor-loser\n' "$target_two")
	set_pam_barrier
	start_spool_lock
	start_as_test env CADO_TEST_TOKEN=allwinner "$bin_dir/scado" -U \
		>"$fixture/all-winner.out" 2>"$fixture/all-winner.err"
	pid_update=$started_pid
	start_as_test env CADO_TEST_TOKEN=editloser EDITOR="$editor" \
		CADO_EDITOR_CONTENT="$edited" "$bin_dir/scado" -e \
		>"$fixture/edit-loser.out" 2>"$fixture/edit-loser.err"
	pid_edit=$started_pid
	wait_for_file "$control_dir/entered.allwinner"
	wait_for_file "$control_dir/entered.editloser"
	update_process=$(entered_pid allwinner)
	edit_process=$(entered_pid editloser)
	release_pam allwinner
	release_pam editloser
	wait_for_flock "$update_process" "$edit_process"
	kill -STOP "$edit_process" || fail "cannot stop the editor transaction"
	release_spool_lock
	set +e
	wait "$pid_update"
	update_status=$?
	set -e
	[[ $update_status -eq 0 ]] || fail "forced update-all winner returned $update_status"
	kill -CONT "$edit_process" || fail "cannot resume the editor transaction"
	set +e
	wait "$pid_edit"
	edit_status=$?
	set -e
	[[ $edit_status -eq 255 ]] || fail "forced editor loser returned $edit_status"
	! grep -Fq '# forced-editor-loser' "$user_scado" ||
		fail "stale editor resurrected its content"
	[[ $(recovery_count) -eq 1 ]] || fail "stale editor did not retain recovery"
	grep -Fq '# forced-editor-loser' /tmp/cado-scado.* ||
		fail "stale editor recovery lost its content"
	[[ $(stage_count) -eq 0 ]] || fail "update-all/edit race leaked staging files"
}

case_delete_edit() {
	local edited pid_delete pid_edit edit_process delete_process
	local delete_status edit_status

	install_initial_scado
	edited=$(printf '%s : kill : \n# no-resurrection\n' "$target_two")
	set_pam_barrier
	start_spool_lock
	start_as_test env CADO_TEST_TOKEN=deletewinner "$bin_dir/scado" -D \
		>"$fixture/delete-winner.out" 2>"$fixture/delete-winner.err"
	pid_delete=$started_pid
	start_as_test env CADO_TEST_TOKEN=editafterdelete EDITOR="$editor" \
		CADO_EDITOR_CONTENT="$edited" "$bin_dir/scado" -e \
		>"$fixture/edit-after-delete.out" 2>"$fixture/edit-after-delete.err"
	pid_edit=$started_pid
	wait_for_file "$control_dir/entered.deletewinner"
	wait_for_file "$control_dir/entered.editafterdelete"
	delete_process=$(entered_pid deletewinner)
	edit_process=$(entered_pid editafterdelete)
	release_pam deletewinner
	release_pam editafterdelete
	wait_for_flock "$delete_process" "$edit_process"
	kill -STOP "$edit_process" || fail "cannot stop edit before deletion"
	release_spool_lock
	set +e
	wait "$pid_delete"
	delete_status=$?
	set -e
	[[ $delete_status -eq 0 ]] || fail "forced deletion winner returned $delete_status"
	kill -CONT "$edit_process" || fail "cannot resume edit after deletion"
	set +e
	wait "$pid_edit"
	edit_status=$?
	set -e
	[[ $edit_status -eq 255 ]] || fail "post-delete editor returned $edit_status"
	[[ ! -e $user_scado && ! -L $user_scado ]] ||
		fail "stale editor resurrected the deleted file"
	[[ $(recovery_count) -eq 1 ]] || fail "post-delete editor lost recovery"
	grep -Fq '# no-resurrection' /tmp/cado-scado.* ||
		fail "post-delete recovery lost its edit"
	[[ $(stage_count) -eq 0 ]] || fail "delete/edit race leaked staging files"
}

case_edit_mutation() {
	local edited pid recovery status

	install_initial_scado
	cp "$user_scado" "$fixture/protected-before"
	edited=$(printf '%s : chown : \n# before-pam-mutation\n' "$target_one")
	set_pam_barrier
	start_as_test env CADO_TEST_TOKEN=mutation EDITOR="$editor" \
		CADO_EDITOR_CONTENT="$edited" "$bin_dir/scado" -e \
		>"$fixture/mutation.out" 2>"$fixture/mutation.err"
	pid=$started_pid
	wait_for_file "$control_dir/entered.mutation"
	[[ $(recovery_count) -eq 1 ]] || fail "editable file is absent at PAM barrier"
	recovery=$(find /tmp -maxdepth 1 -type f -name 'cado-scado.*' -print)
	run_as_test sh -c 'printf "# mutated-while-pam-blocked\n" >>"$1"' \
		sh "$recovery" || fail "test user cannot mutate the editable PAM fixture"
	release_pam mutation
	set +e
	wait "$pid"
	status=$?
	set -e
	[[ $status -eq 255 ]] || fail "PAM-time source mutation returned $status"
	cmp -s "$fixture/protected-before" "$user_scado" ||
		fail "PAM-time mutation changed the protected destination"
	[[ -f $recovery ]] || fail "PAM-time mutation discarded the recovery"
	grep -Fq '# mutated-while-pam-blocked' "$recovery" ||
		fail "retained recovery omitted the PAM-time mutation"
	[[ $(stage_count) -eq 0 ]] || fail "PAM-time mutation leaked staging files"
}

case_pam_integration() {
	local status

	install_initial_scado
	printf '%s\n' 'auth required ?' >"$pam_file"
	set +e
	run_as_test "$bin_dir/scado" -D >"$fixture/pam-start.out" \
		2>"$fixture/pam-start.err"
	status=$?
	set -e
	[[ $status -eq 254 ]] || fail "malformed PAM service returned $status"
	grep -Fq 'PAM initialization failed' "$fixture/pam-start.err" ||
		fail "real pam_start failure diagnostic is absent"
	[[ -f $user_scado ]] || fail "pam_start failure mutated protected state"
	set_pam_deny
	set +e
	run_as_test "$bin_dir/scado" -D >"$fixture/pam-deny.out" \
		2>"$fixture/pam-deny.err"
	status=$?
	set -e
	[[ $status -eq 254 ]] || fail "real PAM authentication rejection returned $status"
	grep -Fq 'PAM authentication failed' "$fixture/pam-deny.err" ||
		fail "real PAM rejection diagnostic is absent"
	[[ -f $user_scado ]] || fail "PAM rejection mutated protected state"
}

case_setgid_pam_signal() {
	local pid process status real_gid effective_gid saved_gid filesystem_gid
	local cado_gid

	install_initial_scado
	set_pam_barrier
	start_as_test env CADO_TEST_TOKEN=termscadosetgid "$bin_dir/scado" -D \
		>"$fixture/setgid-term.out" 2>"$fixture/setgid-term.err"
	pid=$started_pid
	wait_for_file "$control_dir/entered.termscadosetgid"
	process=$(entered_pid termscadosetgid)
	read -r real_gid effective_gid saved_gid filesystem_gid < <(
		awk '/^Gid:/{print $2, $3, $4, $5}' "/proc/$process/status")
	cado_gid=$(getent group _cado | cut -d: -f3)
	[[ $effective_gid == "$cado_gid" && $saved_gid == "$cado_gid" ]] ||
		fail "blocked installed scado is not running setgid _cado"
	kill -TERM "$process" || fail "cannot terminate scado inside real PAM"
	set +e
	wait "$pid"
	status=$?
	set -e
	[[ $status -ne 0 ]] || fail "terminated setgid scado reported success"
	wait_process_attempts=0
	while kill -0 "$process" 2>/dev/null && [[ $wait_process_attempts -lt 250 ]]; do
		sleep 0.02
		wait_process_attempts=$((wait_process_attempts + 1))
	done
	! kill -0 "$process" 2>/dev/null || fail "terminated setgid scado remains alive"
	[[ -f $user_scado ]] || fail "termination inside PAM deleted protected state"
}

case_cleanup_active_jobs() {
	local edited

	edited=$(printf '%s : chown : \n# cleanup-active-jobs\n' "$target_one")
	set_pam_barrier
	start_spool_lock
	start_as_test env CADO_TEST_TOKEN=cleanupactive EDITOR="$editor" \
		CADO_EDITOR_CONTENT="$edited" "$bin_dir/scado" -e \
		>"$fixture/cleanup-active.out" 2>"$fixture/cleanup-active.err"
	wait_for_file "$control_dir/entered.cleanupactive"
	[[ $(recovery_count) -eq 1 ]] ||
		fail "active-job cleanup fixture did not reach blocked PAM"
	printf 'leaving PAM worker and spool-lock helper for EXIT cleanup\n'
}

case_editor_identity() {
	local caller_uid caller_gid cado_gid auxiliary_gid expected_groups groups
	local real_uid effective_uid saved_uid filesystem_uid
	local real_gid effective_gid saved_gid filesystem_gid
	local cap_eff cap_amb driver_cap_eff driver_cap_amb

	install_initial_scado
	set_pam_deny
	run_as_test env EDITOR="$identity_editor" \
		CADO_IDENTITY_OUTPUT="$installed_identity_dir" "$bin_dir/scado" -e ||
		fail "unchanged identity editor failed"
	caller_uid=$(id -u "$test_user")
	caller_gid=$(id -g "$test_user")
	cado_gid=$(getent group _cado | cut -d: -f3)
	auxiliary_gid=$(getent group "$test_aux_group" | cut -d: -f3)
	expected_groups=$(id -G "$test_user")
	read -r real_uid effective_uid saved_uid filesystem_uid \
		<"$installed_identity_dir/uids"
	read -r real_gid effective_gid saved_gid filesystem_gid \
		<"$installed_identity_dir/gids"
	read -r groups <"$installed_identity_dir/groups"
	read -r cap_eff <"$installed_identity_dir/cap-eff"
	read -r cap_amb <"$installed_identity_dir/cap-amb"
	[[ $real_uid == "$caller_uid" && $effective_uid == "$caller_uid" &&
		$saved_uid == "$caller_uid" && $filesystem_uid == "$caller_uid" ]] ||
		fail "editor retained a non-caller UID field"
	[[ $real_gid == "$caller_gid" && $effective_gid == "$caller_gid" &&
		$saved_gid == "$caller_gid" && $filesystem_gid == "$caller_gid" ]] ||
		fail "editor retained a non-caller GID field"
	same_group_set "$expected_groups" "$groups" ||
		fail "editor groups '$groups' differ from caller groups '$expected_groups'"
	[[ " $groups " == *" $auxiliary_gid "* ]] ||
		fail "editor omitted the benign supplementary test group"
	[[ " $groups " != *" $cado_gid "* ]] ||
		fail "editor retained supplementary _cado group"
	[[ $cap_eff == 0000000000000000 && $cap_amb == 0000000000000000 ]] ||
		fail "editor retained effective or ambient capabilities"

	set_pam_permit
	run_as_test env EDITOR="$identity_editor" \
		CADO_IDENTITY_OUTPUT="$capability_identity_dir" \
		"$bin_dir/cado" chown "$bin_dir/test-helper" --identity-driver \
		"$test_user" "$identity_protected" "$edit_dir" "$identity_editor" \
		"$capability_identity_dir" ||
		fail "capability-bearing identity driver failed"
	read -r driver_cap_eff <"$capability_identity_dir/driver-cap-eff"
	read -r driver_cap_amb <"$capability_identity_dir/driver-cap-amb"
	read -r cap_eff <"$capability_identity_dir/cap-eff"
	read -r cap_amb <"$capability_identity_dir/cap-amb"
	printf 'identity capabilities: driver effective=%s ambient=%s; editor effective=%s ambient=%s\n' \
		"$driver_cap_eff" "$driver_cap_amb" "$cap_eff" "$cap_amb"
	has_cap_chown "$driver_cap_eff" && has_cap_chown "$driver_cap_amb" ||
		fail "identity driver lacks cap_chown: effective=$driver_cap_eff ambient=$driver_cap_amb"
	[[ $cap_eff == 0000000000000000 && $cap_amb == 0000000000000000 ]] ||
		fail "capability-bearing editor retained capabilities: effective=$cap_eff ambient=$cap_amb"
}

[[ $# -eq 12 ]] || fail "privileged_matrix.sh requires twelve arguments"

readonly scenario=$1
readonly cado_source=$2
readonly scado_source=$3
readonly cadrop_source=$4
readonly caprint_source=$5
readonly pam_module_source=$6
readonly test_helper_source=$7
readonly post_install_script=$8
readonly config_file=$9
readonly spool_dir=${10}
readonly cmake_command=${11}
readonly marker_file=${12}
readonly pam_file=/etc/pam.d/cado

[[ $(id -u) -eq 0 ]] || skip "privileged matrix requires root"
[[ ${CADO_DISPOSABLE_ROOT_CONFIRMED:-} == YES ]] ||
	skip "set CADO_DISPOSABLE_ROOT_CONFIRMED=YES in a disposable system"
[[ -f $marker_file && ! -L $marker_file ]] ||
	skip "create the regular disposable-root marker $marker_file"
for command in awk chmod chown cmp cut find flock getent grep groupadd groupdel \
	id install kill mkdir mktemp nologin readlink rm setpriv setsid sha256sum sleep \
	stat useradd userdel wc; do
	require_command "$command"
done
for path in "$cado_source" "$scado_source" "$cadrop_source" \
	"$caprint_source" "$pam_module_source" "$test_helper_source" \
	"$post_install_script"; do
	[[ -f $path && ! -L $path ]] || fail "required regular file is absent: $path"
done
[[ $config_file == /* && $config_file != / && $spool_dir == /* && \
	$spool_dir != / ]] || fail "unsafe configured test state paths"
[[ ! -e $config_file && ! -L $config_file ]] ||
	skip "refusing existing configuration $config_file"
[[ ! -e $spool_dir && ! -L $spool_dir ]] ||
	skip "refusing existing spool $spool_dir"
[[ ! -e $pam_file && ! -L $pam_file ]] ||
	skip "refusing existing PAM service $pam_file"
if find /tmp -maxdepth 1 -type f -name 'cado-scado.*' -print -quit |
		grep -q .; then
	skip "refusing pre-existing /tmp/cado-scado.* recovery state"
fi

readonly suffix=$$
readonly test_user="cadom${suffix}"
readonly test_group="cadom${suffix}"
readonly test_aux_group="cadoaux${suffix}"
getent passwd "$test_user" >/dev/null 2>&1 &&
	skip "test account already exists: $test_user"
getent group "$test_group" >/dev/null 2>&1 &&
	skip "test group already exists: $test_group"
getent group "$test_aux_group" >/dev/null 2>&1 &&
	skip "supplementary test group already exists: $test_aux_group"
fixture=
lock_pid=
started_pid=
config_created=0
pam_created=0
spool_created=0
user_created=0
group_created=0
aux_group_created=0

cleanup() {
	local status=$?
	local cleanup_failed=0
	local process
	local -a processes=()
	trap - EXIT
	set +e
	mapfile -t processes < <(jobs -p)
	for process in "${processes[@]}"; do
		terminate_background_group "$process" || cleanup_failed=1
	done
	terminate_lingering_fixture_processes || cleanup_failed=1
	if [[ $user_created -eq 1 ]] &&
			! userdel "$test_user" >/dev/null 2>&1; then
		printf 'FAIL: cannot remove test account %s\n' "$test_user" >&2
		cleanup_failed=1
	fi
	if [[ $group_created -eq 1 ]] &&
			getent group "$test_group" >/dev/null 2>&1 &&
			! groupdel "$test_group" >/dev/null 2>&1; then
		printf 'FAIL: cannot remove test group %s\n' "$test_group" >&2
		cleanup_failed=1
	fi
	if [[ $aux_group_created -eq 1 ]] &&
			getent group "$test_aux_group" >/dev/null 2>&1 &&
			! groupdel "$test_aux_group" >/dev/null 2>&1; then
		printf 'FAIL: cannot remove supplementary test group %s\n' \
			"$test_aux_group" >&2
		cleanup_failed=1
	fi
	if [[ $pam_created -eq 1 ]]; then
		rm -f -- "$pam_file" || cleanup_failed=1
	fi
	if [[ $config_created -eq 1 ]]; then
		rm -f -- "$config_file" || cleanup_failed=1
	fi
	find /tmp -maxdepth 1 -type f -name 'cado-scado.*' -delete ||
		cleanup_failed=1
	if [[ $spool_created -eq 1 ]]; then
		if [[ $spool_dir == /var/spool/cado-test-* ]]; then
			rm -rf -- "$spool_dir" || cleanup_failed=1
		else
			printf 'FAIL: refusing unsafe spool cleanup path %s\n' \
				"$spool_dir" >&2
			cleanup_failed=1
		fi
	fi
	if [[ -n $fixture ]]; then
		if [[ $fixture == /var/tmp/cado-matrix.* ]]; then
			rm -rf -- "$fixture" || cleanup_failed=1
		else
			printf 'FAIL: refusing unsafe matrix fixture cleanup path %s\n' \
				"$fixture" >&2
			cleanup_failed=1
		fi
	fi
	if [[ $cleanup_failed -ne 0 && $status -eq 0 ]]; then
		status=1
	fi
	exit "$status"
}
trap cleanup EXIT

fixture=$(mktemp -d /var/tmp/cado-matrix.XXXXXX)
readonly fixture
readonly bin_dir="$fixture/bin"
readonly edit_dir="$fixture/edit"
readonly control_dir="$fixture/control"
readonly pam_dir="$fixture/pam"
readonly pam_fixture="$pam_dir/pam_cado_test.so"
readonly test_helper="$bin_dir/test-helper"
readonly target_one="$fixture/target-one"
readonly target_two="$fixture/target-two"
readonly user_scado="$spool_dir/$test_user"
readonly editor="$fixture/editor"
readonly identity_editor="$fixture/identity-editor"
readonly identity_protected="$fixture/identity-protected"
readonly installed_identity_dir="$fixture/editor-identity-installed"
readonly capability_identity_dir="$fixture/editor-identity-capability"
mkdir -p "$bin_dir" "$edit_dir" "$control_dir" "$pam_dir" "$fixture/home"
chmod 0755 "$fixture" "$bin_dir" "$pam_dir" "$fixture/home"
chmod 1777 "$control_dir"
install -o root -g root -m 0755 "$pam_module_source" "$pam_fixture"
install -m 0755 "$cado_source" "$bin_dir/cado"
install -m 0755 "$scado_source" "$bin_dir/scado"
install -m 0755 "$cadrop_source" "$bin_dir/cadrop"
install -m 0755 "$caprint_source" "$bin_dir/caprint"
install -m 0755 "$test_helper_source" "$test_helper"
printf 'target one\n' >"$target_one"
printf 'target two\n' >"$target_two"
identity_digest=$(sha256sum /bin/true | awk '{print $1}')
readonly identity_digest
[[ $identity_digest =~ ^[[:xdigit:]]{64}$ ]] ||
	fail "cannot construct the valid unchanged identity fixture"
printf '/bin/true : chown : %s\n' "$identity_digest" >"$identity_protected"
chmod 0755 "$target_one" "$target_two"

groupadd --system "$test_group"
group_created=1
groupadd --system "$test_aux_group"
aux_group_created=1
useradd --system --no-create-home --home-dir /nonexistent \
	--shell "$(command -v nologin)" --gid "$test_group" \
	--groups "$test_aux_group" "$test_user"
user_created=1
readonly test_uid=$(id -u "$test_user")
readonly test_gid=$(id -g "$test_user")
chown "$test_user:$test_group" "$edit_dir" "$fixture/home" \
	"$identity_protected"
chmod 0700 "$edit_dir" "$fixture/home"
chmod 0600 "$identity_protected"
mkdir "$installed_identity_dir" "$capability_identity_dir"
chown "$test_user:$test_group" "$installed_identity_dir" \
	"$capability_identity_dir"
chmod 0700 "$installed_identity_dir" "$capability_identity_dir"

cat >"$editor" <<'EOF'
#!/bin/sh
printf '%s' "$CADO_EDITOR_CONTENT" >"$1"
EOF
chmod 0755 "$editor"
cat >"$identity_editor" <<'EOF'
#!/bin/sh
set -eu
mkdir -p "$CADO_IDENTITY_OUTPUT"
status_file=/proc/$$/status
awk '/^Uid:/{print $2, $3, $4, $5}' "$status_file" >"$CADO_IDENTITY_OUTPUT/uids"
awk '/^Gid:/{print $2, $3, $4, $5}' "$status_file" >"$CADO_IDENTITY_OUTPUT/gids"
id -G >"$CADO_IDENTITY_OUTPUT/groups"
awk '/^CapEff:/{print $2}' "$status_file" >"$CADO_IDENTITY_OUTPUT/cap-eff"
awk '/^CapAmb:/{print $2}' "$status_file" >"$CADO_IDENTITY_OUTPUT/cap-amb"
EOF
chmod 0755 "$identity_editor"

config_created=1
printf 'chown : %s\nkill : @%s\n' "$test_user" "$test_group" >"$config_file"
pam_created=1
set_pam_permit
spool_created=1
"$cmake_command" -DBINDIR="$bin_dir" -DCADO_CONFIG_FILE="$config_file" \
	-DCADO_SPOOL_DIR="$spool_dir" -P "$post_install_script"

case "$scenario" in
	edit-edit) case_edit_edit ;;
	update-path-update-all) case_update_path_update_all ;;
	update-all-edit) case_update_all_edit ;;
	delete-edit) case_delete_edit ;;
	edit-mutation) case_edit_mutation ;;
	pam-integration) case_pam_integration ;;
	setgid-pam-signal) case_setgid_pam_signal ;;
	cleanup-active-jobs) case_cleanup_active_jobs ;;
	editor-identity) case_editor_identity ;;
	*) fail "unknown privileged scenario: $scenario" ;;
esac

printf 'privileged scenario passed: %s\n' "$scenario"
