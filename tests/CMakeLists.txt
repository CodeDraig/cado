add_executable(test_capabilities test_capabilities.c)
target_link_libraries(test_capabilities PRIVATE
	cado_build_options cado_capability_core cado_policy_core)
add_test(NAME capabilities-and-policy COMMAND test_capabilities)

add_executable(test_config test_config.c)
target_link_libraries(test_config PRIVATE cado_build_options cado_auth_core)
add_test(NAME identity-and-config COMMAND test_config)

add_executable(test_pam_check
	test_pam_check.c
	${PROJECT_SOURCE_DIR}/src/pam_check.c)
target_link_libraries(test_pam_check PRIVATE cado_build_options)
add_test(NAME pam-fault-ordering COMMAND test_pam_check)

add_executable(test_io_digest test_io_digest.c)
target_link_libraries(test_io_digest PRIVATE cado_build_options cado_io_core)
add_test(NAME io-and-digest COMMAND test_io_digest)

add_executable(test_scado test_scado.c)
target_link_libraries(test_scado PRIVATE cado_build_options cado_scado_core)
add_test(NAME scado-parser-and-transactions COMMAND test_scado)

add_executable(test_scado_edit test_scado_edit.c)
target_link_libraries(test_scado_edit PRIVATE
	cado_build_options cado_scado_edit_core)
add_test(NAME scado-edit-recovery COMMAND test_scado_edit)

add_executable(test_scado_signal_matrix test_scado_signal_matrix.c)
target_link_libraries(test_scado_signal_matrix PRIVATE
	cado_build_options cado_scado_edit_core)
target_link_options(test_scado_signal_matrix PRIVATE
	"LINKER:--wrap=compute_digest_nofollow_regular"
	"LINKER:--wrap=drop_all_capabilities")
add_test(NAME scado-edit-signal-matrix COMMAND test_scado_signal_matrix)
set_tests_properties(scado-edit-signal-matrix PROPERTIES TIMEOUT 120)
add_test(NAME scado-edit-signal-inheritance
	COMMAND /bin/sh -c "trap '' HUP INT QUIT; exec \"$1\""
		sh "$<TARGET_FILE:test_scado_signal_matrix>")
set_tests_properties(scado-edit-signal-inheritance PROPERTIES TIMEOUT 120)

add_executable(test_verified_copy test_verified_copy.c)
target_link_libraries(test_verified_copy PRIVATE
	cado_build_options cado_verified_core)
add_test(NAME verified-copy-watchdog COMMAND test_verified_copy)

add_test(NAME cli-probes
	COMMAND "${CMAKE_COMMAND}"
		-DCADO=$<TARGET_FILE:cado>
		-DSCADO=$<TARGET_FILE:scado>
		-DCADROP=$<TARGET_FILE:cadrop>
		-DCAPRINT=$<TARGET_FILE:caprint>
		-P "${CMAKE_CURRENT_SOURCE_DIR}/cli_probes.cmake")

add_test(NAME state-preserving-uninstall
	COMMAND "${CMAKE_COMMAND}"
		-DUNINSTALL_SCRIPT=${PROJECT_SOURCE_DIR}/Uninstall.cmake
		-P "${CMAKE_CURRENT_SOURCE_DIR}/test_uninstall.cmake")

add_test(NAME install-bindir-resolution
	COMMAND "${CMAKE_COMMAND}"
		-DSOURCE_DIR=${PROJECT_SOURCE_DIR}
		-DTEST_BINARY_DIR=${CMAKE_CURRENT_BINARY_DIR}
		-DC_COMPILER=${CMAKE_C_COMPILER}
		-DCAP_INCLUDE_DIR=${CAP_INCLUDE_DIR}
		-DCAP_LIBRARY=${CAP_LIBRARY}
		-DPAM_INCLUDE_DIR=${PAM_INCLUDE_DIR}
		-DPAM_MISC_INCLUDE_DIR=${PAM_MISC_INCLUDE_DIR}
		-DPAM_LIBRARY=${PAM_LIBRARY}
		-DPAM_MISC_LIBRARY=${PAM_MISC_LIBRARY}
		-DMHASH_INCLUDE_DIR=${MHASH_INCLUDE_DIR}
		-DMHASH_LIBRARY=${MHASH_LIBRARY}
		-DEXECS_INCLUDE_DIR=${EXECS_INCLUDE_DIR}
		-DEXECS_LIBRARY=${EXECS_LIBRARY}
		-P "${CMAKE_CURRENT_SOURCE_DIR}/test_install_bindir.cmake")

if(CADO_ENABLE_PRIVILEGED_TESTS)
	set(CADO_PRIVILEGED_CONFIRMATION "" CACHE STRING
		"Must equal DISPOSABLE_ROOT_ENVIRONMENT before privileged tests are registered")
	if(NOT CADO_PRIVILEGED_CONFIRMATION STREQUAL "DISPOSABLE_ROOT_ENVIRONMENT")
		message(FATAL_ERROR
			"CADO_ENABLE_PRIVILEGED_TESTS requires -DCADO_PRIVILEGED_CONFIRMATION=DISPOSABLE_ROOT_ENVIRONMENT")
	endif()
	add_library(pam_cado_test MODULE pam_cado_test.c)
	target_link_libraries(pam_cado_test PRIVATE cado_build_options ${PAM_LIBRARY})
	set_target_properties(pam_cado_test PROPERTIES
		PREFIX "" OUTPUT_NAME "pam_cado_test")
	add_test(NAME privileged-lifecycle
		COMMAND "${CMAKE_CURRENT_SOURCE_DIR}/privileged_tests.sh"
			"$<TARGET_FILE:cado>" "$<TARGET_FILE:scado>"
			"$<TARGET_FILE:cadrop>" "$<TARGET_FILE:caprint>"
			"${PROJECT_SOURCE_DIR}/PostInstall.cmake"
			"${PROJECT_SOURCE_DIR}/Uninstall.cmake"
			"${CADO_CONFIG_FILE}" "${CADO_SPOOL_DIR}"
			"${CMAKE_COMMAND}")
	set_tests_properties(privileged-lifecycle PROPERTIES
		LABELS privileged RUN_SERIAL TRUE SKIP_RETURN_CODE 77 TIMEOUT 180)
	foreach(privileged_scenario
			edit-edit
			update-path-update-all
			update-all-edit
			delete-edit
			edit-mutation
			pam-integration
			setgid-pam-signal
			cleanup-active-jobs
			editor-identity)
		add_test(NAME privileged-${privileged_scenario}
			COMMAND "${CMAKE_CURRENT_SOURCE_DIR}/privileged_matrix.sh"
				"${privileged_scenario}"
				"$<TARGET_FILE:cado>" "$<TARGET_FILE:scado>"
				"$<TARGET_FILE:cadrop>" "$<TARGET_FILE:caprint>"
				"$<TARGET_FILE:pam_cado_test>"
				"$<TARGET_FILE:test_scado_signal_matrix>"
				"${PROJECT_SOURCE_DIR}/PostInstall.cmake"
				"${CADO_CONFIG_FILE}" "${CADO_SPOOL_DIR}"
				"${CMAKE_COMMAND}" "/.cado-disposable-test-root")
		set_tests_properties(privileged-${privileged_scenario} PROPERTIES
			LABELS privileged RUN_SERIAL TRUE SKIP_RETURN_CODE 77 TIMEOUT 180)
	endforeach()
	add_test(NAME privileged-absolute-install
		COMMAND "${CMAKE_CURRENT_SOURCE_DIR}/privileged_absolute_install.sh"
			"${PROJECT_SOURCE_DIR}" "${CMAKE_COMMAND}"
			"/.cado-disposable-test-root")
	set_tests_properties(privileged-absolute-install PROPERTIES
		LABELS privileged RUN_SERIAL TRUE SKIP_RETURN_CODE 77 TIMEOUT 300)
endif()
