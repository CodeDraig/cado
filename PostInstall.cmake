if(NOT DEFINED BINDIR OR NOT DEFINED CADO_SPOOL_DIR OR
		NOT DEFINED CADO_CONFIG_FILE)
	message(FATAL_ERROR
		"post-install requires BINDIR, CADO_SPOOL_DIR, and CADO_CONFIG_FILE")
endif()
if(NOT IS_ABSOLUTE "${BINDIR}" OR NOT IS_ABSOLUTE "${CADO_SPOOL_DIR}" OR
		NOT IS_ABSOLUTE "${CADO_CONFIG_FILE}")
	message(FATAL_ERROR
		"post-install paths must be absolute: BINDIR='${BINDIR}', spool='${CADO_SPOOL_DIR}', config='${CADO_CONFIG_FILE}'")
endif()

function(require_program variable)
	find_program(${variable} NAMES ${ARGN})
	if(NOT ${variable})
		string(JOIN ", " names ${ARGN})
		message(FATAL_ERROR "post-install preflight: missing command ${names}")
	endif()
	set(${variable} "${${variable}}" PARENT_SCOPE)
endfunction()

function(run_checked step)
	execute_process(
		COMMAND ${ARGN}
		RESULT_VARIABLE result
		OUTPUT_VARIABLE output
		ERROR_VARIABLE error
		OUTPUT_STRIP_TRAILING_WHITESPACE
		ERROR_STRIP_TRAILING_WHITESPACE)
	if(NOT result EQUAL 0)
		message(FATAL_ERROR
			"post-install step '${step}' failed (${result}): ${error}")
	endif()
	set(CADO_STEP_OUTPUT "${output}" PARENT_SCOPE)
endfunction()

require_program(GETENT getent)
require_program(GROUPADD groupadd)
require_program(USERADD useradd)
require_program(NOLOGIN nologin)
require_program(ID id)
require_program(CHOWN chown)
require_program(CHMOD chmod)
require_program(STAT stat)
require_program(GETCAP getcap)

run_checked("verify root" "${ID}" -u)
if(NOT CADO_STEP_OUTPUT STREQUAL "0")
	message(FATAL_ERROR "post-install must run as root")
endif()

foreach(program cado scado cadrop caprint)
	if(NOT EXISTS "${BINDIR}/${program}" OR IS_DIRECTORY "${BINDIR}/${program}" OR
			IS_SYMLINK "${BINDIR}/${program}")
		message(FATAL_ERROR
			"post-install preflight: ${BINDIR}/${program} must be a regular, non-symlink file")
	endif()
	run_checked("inspect ${program} file type" "${CMAKE_COMMAND}" -E env
		LC_ALL=C "${STAT}" -c "%F" "${BINDIR}/${program}")
	if(NOT CADO_STEP_OUTPUT STREQUAL "regular file")
		message(FATAL_ERROR
			"post-install preflight: ${BINDIR}/${program} is ${CADO_STEP_OUTPUT}, expected a regular file")
	endif()
endforeach()
if(NOT EXISTS "${CADO_CONFIG_FILE}" OR IS_DIRECTORY "${CADO_CONFIG_FILE}" OR
		IS_SYMLINK "${CADO_CONFIG_FILE}")
	message(FATAL_ERROR
		"post-install preflight: ${CADO_CONFIG_FILE} must be an existing regular, non-symlink file")
endif()
run_checked("inspect cado configuration file type" "${CMAKE_COMMAND}" -E env
	LC_ALL=C "${STAT}" -c "%F" "${CADO_CONFIG_FILE}")
if(NOT CADO_STEP_OUTPUT STREQUAL "regular file")
	message(FATAL_ERROR
		"post-install preflight: ${CADO_CONFIG_FILE} is ${CADO_STEP_OUTPUT}, expected a regular file")
endif()
if(IS_SYMLINK "${CADO_SPOOL_DIR}" OR
		(EXISTS "${CADO_SPOOL_DIR}" AND NOT IS_DIRECTORY "${CADO_SPOOL_DIR}"))
	message(FATAL_ERROR
		"post-install preflight: ${CADO_SPOOL_DIR} must be absent or a real directory")
endif()

execute_process(COMMAND "${GETENT}" group _cado RESULT_VARIABLE group_exists
	OUTPUT_VARIABLE group_lookup_output ERROR_VARIABLE group_lookup_error
	OUTPUT_STRIP_TRAILING_WHITESPACE ERROR_STRIP_TRAILING_WHITESPACE)
if(group_exists EQUAL 2)
	run_checked("create _cado group" "${GROUPADD}" --system _cado)
elseif(NOT group_exists EQUAL 0)
	message(FATAL_ERROR
		"post-install preflight: getent group _cado failed with status ${group_exists}: ${group_lookup_error}")
endif()

execute_process(COMMAND "${GETENT}" passwd _cado RESULT_VARIABLE user_exists
	OUTPUT_VARIABLE user_lookup_output ERROR_VARIABLE user_lookup_error
	OUTPUT_STRIP_TRAILING_WHITESPACE ERROR_STRIP_TRAILING_WHITESPACE)
if(user_exists EQUAL 2)
	run_checked("create _cado account" "${USERADD}"
		--no-create-home
		--home-dir /nonexistent
		--system
		--shell "${NOLOGIN}"
		--gid _cado
		_cado)
elseif(NOT user_exists EQUAL 0)
	message(FATAL_ERROR
		"post-install preflight: getent passwd _cado failed with status ${user_exists}: ${user_lookup_error}")
endif()

run_checked("read _cado group" "${GETENT}" group _cado)
if(NOT CADO_STEP_OUTPUT MATCHES "^_cado:[^:]*:[0-9]+:$")
	message(FATAL_ERROR
		"existing _cado group is invalid or has supplementary members: ${CADO_STEP_OUTPUT}")
endif()
run_checked("read _cado account" "${GETENT}" passwd _cado)
if(NOT CADO_STEP_OUTPUT MATCHES
		"^_cado:[^:]*:[0-9]+:[0-9]+:[^:]*:/nonexistent:/[^:]*nologin$")
	message(FATAL_ERROR
		"existing _cado account must use /nonexistent, a nologin shell, and a valid passwd entry: ${CADO_STEP_OUTPUT}")
endif()
string(REGEX REPLACE "^.*:" "" CADO_ACCOUNT_SHELL "${CADO_STEP_OUTPUT}")
get_filename_component(CADO_ACCOUNT_SHELL_REAL "${CADO_ACCOUNT_SHELL}" REALPATH)
get_filename_component(NOLOGIN_REAL "${NOLOGIN}" REALPATH)
if(NOT "${CADO_ACCOUNT_SHELL_REAL}" STREQUAL "${NOLOGIN_REAL}")
	message(FATAL_ERROR
		"existing _cado shell ${CADO_ACCOUNT_SHELL} does not resolve to ${NOLOGIN}")
endif()
run_checked("verify _cado primary group" "${ID}" -gn _cado)
if(NOT CADO_STEP_OUTPUT STREQUAL "_cado")
	message(FATAL_ERROR
		"existing _cado account has primary group '${CADO_STEP_OUTPUT}', expected _cado")
endif()
run_checked("verify _cado uid" "${ID}" -u _cado)
if(NOT CADO_STEP_OUTPUT MATCHES "^[1-9][0-9]*$")
	message(FATAL_ERROR
		"_cado must have a nonzero numeric UID: ${CADO_STEP_OUTPUT}")
endif()
run_checked("verify _cado gid" "${ID}" -g _cado)
if(NOT CADO_STEP_OUTPUT MATCHES "^[1-9][0-9]*$")
	message(FATAL_ERROR
		"_cado must have a nonzero numeric primary GID: ${CADO_STEP_OUTPUT}")
endif()
run_checked("verify _cado supplementary groups" "${ID}" -Gn _cado)
if(NOT CADO_STEP_OUTPUT STREQUAL "_cado")
	message(FATAL_ERROR
		"_cado must not have supplementary groups: ${CADO_STEP_OUTPUT}")
endif()

run_checked("create spool directory" "${CMAKE_COMMAND}" -E make_directory
	"${CADO_SPOOL_DIR}")
run_checked("set spool ownership" "${CHOWN}" root:_cado "${CADO_SPOOL_DIR}")
run_checked("set spool mode" "${CHMOD}" 2770 "${CADO_SPOOL_DIR}")

run_checked("set cado ownership" "${CHOWN}" _cado:_cado "${BINDIR}/cado")
run_checked("set cado mode" "${CHMOD}" 4755 "${BINDIR}/cado")
run_checked("set scado ownership" "${CHOWN}" root:_cado "${BINDIR}/scado")
run_checked("set scado mode" "${CHMOD}" 2755 "${BINDIR}/scado")
foreach(program cadrop caprint)
	run_checked("set ${program} ownership" "${CHOWN}" root:root
		"${BINDIR}/${program}")
	run_checked("set ${program} mode" "${CHMOD}" 0755 "${BINDIR}/${program}")
endforeach()

run_checked("compute cado file capabilities" "${BINDIR}/cado" --setcap)

run_checked("verify spool metadata" "${STAT}" -c "%U:%G %a" "${CADO_SPOOL_DIR}")
if(NOT CADO_STEP_OUTPUT STREQUAL "root:_cado 2770")
	message(FATAL_ERROR
		"spool metadata verification failed: ${CADO_STEP_OUTPUT}")
endif()
run_checked("verify cado metadata" "${STAT}" -c "%U:%G %a" "${BINDIR}/cado")
if(NOT CADO_STEP_OUTPUT STREQUAL "_cado:_cado 4755")
	message(FATAL_ERROR "cado metadata verification failed: ${CADO_STEP_OUTPUT}")
endif()
run_checked("verify scado metadata" "${STAT}" -c "%U:%G %a" "${BINDIR}/scado")
if(NOT CADO_STEP_OUTPUT STREQUAL "root:_cado 2755")
	message(FATAL_ERROR "scado metadata verification failed: ${CADO_STEP_OUTPUT}")
endif()
foreach(program cadrop caprint)
	run_checked("verify ${program} metadata" "${STAT}" -c "%U:%G %a"
		"${BINDIR}/${program}")
	if(NOT CADO_STEP_OUTPUT STREQUAL "root:root 755")
		message(FATAL_ERROR
			"${program} metadata verification failed: ${CADO_STEP_OUTPUT}")
	endif()
endforeach()
run_checked("verify cado file capabilities" "${GETCAP}" "${BINDIR}/cado")
if(NOT CADO_STEP_OUTPUT MATCHES "cap_dac_read_search" OR
		NOT CADO_STEP_OUTPUT MATCHES "=p$")
	message(FATAL_ERROR
		"cado file-capability verification failed: ${CADO_STEP_OUTPUT}")
endif()

message(STATUS "cado post-install ownership, modes, and capabilities verified")
