foreach(required
		SOURCE_DIR TEST_BINARY_DIR C_COMPILER
		CAP_INCLUDE_DIR CAP_LIBRARY
		PAM_INCLUDE_DIR PAM_MISC_INCLUDE_DIR PAM_LIBRARY PAM_MISC_LIBRARY
		MHASH_INCLUDE_DIR MHASH_LIBRARY EXECS_INCLUDE_DIR EXECS_LIBRARY)
	if(NOT DEFINED ${required} OR "${${required}}" STREQUAL "")
		message(FATAL_ERROR "missing install-path test argument: ${required}")
	endif()
endforeach()

set(probe_root "${TEST_BINARY_DIR}/install-bindir-probe")
set(absolute_bindir "${probe_root}/absolute-bin")
set(absolute_build "${probe_root}/absolute-build")
set(relative_build "${probe_root}/relative-build")
file(REMOVE_RECURSE "${probe_root}")
file(MAKE_DIRECTORY "${probe_root}")

set(dependency_arguments
	"-DCMAKE_C_COMPILER=${C_COMPILER}"
	"-DCAP_INCLUDE_DIR=${CAP_INCLUDE_DIR}"
	"-DCAP_LIBRARY=${CAP_LIBRARY}"
	"-DPAM_INCLUDE_DIR=${PAM_INCLUDE_DIR}"
	"-DPAM_MISC_INCLUDE_DIR=${PAM_MISC_INCLUDE_DIR}"
	"-DPAM_LIBRARY=${PAM_LIBRARY}"
	"-DPAM_MISC_LIBRARY=${PAM_MISC_LIBRARY}"
	"-DMHASH_INCLUDE_DIR=${MHASH_INCLUDE_DIR}"
	"-DMHASH_LIBRARY=${MHASH_LIBRARY}"
	"-DEXECS_INCLUDE_DIR=${EXECS_INCLUDE_DIR}"
	"-DEXECS_LIBRARY=${EXECS_LIBRARY}")

function(configure_probe build_directory bindir)
	execute_process(
		COMMAND "${CMAKE_COMMAND}"
			-S "${SOURCE_DIR}"
			-B "${build_directory}"
			-DBUILD_TESTING=OFF
			-DCADO_RUN_POST_INSTALL=ON
			"-DCMAKE_INSTALL_PREFIX=${probe_root}/configured-prefix"
			"-DCMAKE_INSTALL_BINDIR=${bindir}"
			${dependency_arguments}
		RESULT_VARIABLE configure_result
		OUTPUT_VARIABLE configure_output
		ERROR_VARIABLE configure_error)
	if(NOT configure_result EQUAL 0)
		message(FATAL_ERROR
			"install-path probe configuration failed (${configure_result})\n${configure_output}\n${configure_error}")
	endif()
endfunction()

configure_probe("${absolute_build}" "${absolute_bindir}")
file(READ "${absolute_build}/src/cmake_install.cmake" absolute_script)
string(FIND "${absolute_script}" "-DBINDIR=${absolute_bindir}"
	absolute_match)
if(absolute_match EQUAL -1)
	message(FATAL_ERROR
		"absolute CMAKE_INSTALL_BINDIR was not passed through unchanged")
endif()

configure_probe("${relative_build}" "cado-bin")
file(READ "${relative_build}/src/cmake_install.cmake" relative_script)
string(FIND "${relative_script}"
	"-DBINDIR=\${CMAKE_INSTALL_PREFIX}/cado-bin" relative_match)
if(relative_match EQUAL -1)
	message(FATAL_ERROR
		"relative CMAKE_INSTALL_BINDIR no longer follows the install-time prefix")
endif()
