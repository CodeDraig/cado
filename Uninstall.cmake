if(NOT DEFINED MANIFEST)
	set(MANIFEST "${CMAKE_CURRENT_BINARY_DIR}/install_manifest.txt")
endif()
if(NOT EXISTS "${MANIFEST}")
	message(FATAL_ERROR "Cannot find install manifest: '${MANIFEST}'")
endif()

file(STRINGS "${MANIFEST}" installed_files)
foreach(installed_file IN LISTS installed_files)
	if(installed_file STREQUAL "")
		continue()
	endif()
	if(NOT IS_ABSOLUTE "${installed_file}" OR installed_file STREQUAL "/")
		message(FATAL_ERROR
			"Refusing unsafe non-file manifest entry: '${installed_file}'")
	endif()
	if(IS_DIRECTORY "${installed_file}" AND NOT IS_SYMLINK "${installed_file}")
		message(FATAL_ERROR
			"Refusing to remove manifest directory: '${installed_file}'")
	endif()
	if(EXISTS "${installed_file}" OR IS_SYMLINK "${installed_file}")
		message(STATUS "Removing manifest file: '${installed_file}'")
		execute_process(
			COMMAND "${CMAKE_COMMAND}" -E remove -f "${installed_file}"
			RESULT_VARIABLE remove_result
			ERROR_VARIABLE remove_error
			ERROR_STRIP_TRAILING_WHITESPACE)
		if(NOT remove_result EQUAL 0)
			message(FATAL_ERROR
				"Failed to remove manifest file '${installed_file}' (${remove_result}): ${remove_error}")
		endif()
		if(EXISTS "${installed_file}" OR IS_SYMLINK "${installed_file}")
			message(FATAL_ERROR
				"Manifest file still exists after removal: '${installed_file}'")
		endif()
	else()
		message(STATUS "Manifest file already absent: '${installed_file}'")
	endif()
endforeach()

message(STATUS
	"State preserved: /etc/cado.conf, the cado spool, user scado files, and the _cado account/group were not removed")
