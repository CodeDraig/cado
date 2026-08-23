set(fixture "${CMAKE_CURRENT_BINARY_DIR}/cado-uninstall-fixture")
file(REMOVE_RECURSE "${fixture}")
file(MAKE_DIRECTORY "${fixture}/installed" "${fixture}/spool")
file(WRITE "${fixture}/installed/cado" "installed binary\n")
file(WRITE "${fixture}/installed/cado.1" "installed manual\n")
file(WRITE "${fixture}/cado.conf" "preserved configuration\n")
file(WRITE "${fixture}/spool/alice" "preserved scado state\n")
file(WRITE "${fixture}/install_manifest.txt"
	"${fixture}/installed/cado\n${fixture}/installed/cado.1\n")
file(WRITE "${fixture}/unsafe_manifest.txt" "${fixture}/spool\n")

execute_process(COMMAND "${CMAKE_COMMAND}"
	"-DMANIFEST=${fixture}/unsafe_manifest.txt"
	-P "${UNINSTALL_SCRIPT}"
	RESULT_VARIABLE unsafe_result
	OUTPUT_QUIET ERROR_QUIET)
if(unsafe_result EQUAL 0 OR NOT EXISTS "${fixture}/spool/alice")
	message(FATAL_ERROR "uninstall accepted a manifest directory entry")
endif()

set(MANIFEST "${fixture}/install_manifest.txt")
include("${UNINSTALL_SCRIPT}")

if(EXISTS "${fixture}/installed/cado" OR EXISTS "${fixture}/installed/cado.1")
	message(FATAL_ERROR "manifest-installed files were not removed")
endif()
if(NOT EXISTS "${fixture}/cado.conf" OR NOT EXISTS "${fixture}/spool/alice")
	message(FATAL_ERROR "uninstall removed preserved configuration or spool state")
endif()

file(REMOVE_RECURSE "${fixture}")
