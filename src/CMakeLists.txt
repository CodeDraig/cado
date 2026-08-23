add_library(cado_capability_core STATIC
	capset_from_namelist.c
	set_ambient_cap.c)
target_link_libraries(cado_capability_core
	PUBLIC cado_build_options ${CAP_LIBRARY})

add_library(cado_io_core STATIC
	file_utils.c
	compute_digest.c)
target_link_libraries(cado_io_core
	PUBLIC cado_build_options ${MHASH_LIBRARY})

add_library(cado_scado_temp_core STATIC scado_temp_guard.c)
target_link_libraries(cado_scado_temp_core
	PUBLIC cado_build_options cado_io_core)

add_library(cado_scado_core STATIC scado_parse.c)
target_link_libraries(cado_scado_core
	PUBLIC cado_build_options cado_capability_core cado_io_core
		cado_scado_temp_core)

add_library(cado_auth_core STATIC
	pam_check.c
	get_user_groups.c
	read_conf.c)
target_link_libraries(cado_auth_core
	PUBLIC cado_build_options cado_capability_core
		${PAM_LIBRARY} ${PAM_MISC_LIBRARY} ${EXECS_LIBRARY})

add_library(cado_verified_core STATIC cado_scado_check.c)
target_link_libraries(cado_verified_core
	PUBLIC cado_build_options cado_scado_core cado_capability_core cado_io_core)

add_library(cado_scado_edit_core STATIC scado_edit.c)
target_link_libraries(cado_scado_edit_core
	PUBLIC cado_build_options cado_auth_core cado_scado_core cado_io_core
		${PAM_LIBRARY} ${PAM_MISC_LIBRARY} ${EXECS_LIBRARY})

add_library(cado_policy_core STATIC cado_policy.c)
target_link_libraries(cado_policy_core PUBLIC cado_build_options)

add_executable(cado cado.c)
target_link_libraries(cado PRIVATE
	cado_build_options cado_auth_core cado_verified_core cado_policy_core)

add_executable(cadrop cadrop.c)
target_link_libraries(cadrop PRIVATE cado_build_options cado_capability_core)

add_executable(scado scado.c)
target_link_libraries(scado PRIVATE
	cado_build_options cado_auth_core cado_scado_core cado_scado_edit_core
	cado_io_core
	${PAM_LIBRARY} ${PAM_MISC_LIBRARY} ${EXECS_LIBRARY})

add_executable(caprint caprint.c)
target_link_libraries(caprint PRIVATE cado_build_options ${CAP_LIBRARY})

install(TARGETS cado cadrop scado caprint
	RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})

if(CADO_RUN_POST_INSTALL)
	if(IS_ABSOLUTE "${CMAKE_INSTALL_BINDIR}")
		set(cado_post_install_bindir "${CMAKE_INSTALL_BINDIR}")
	else()
		set(cado_post_install_bindir
			"\${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_BINDIR}")
	endif()
	install(CODE "
		if(NOT \"\$ENV{DESTDIR}\" STREQUAL \"\")
			message(FATAL_ERROR
				\"CADO_RUN_POST_INSTALL cannot mutate a DESTDIR staging tree; configure with -DCADO_RUN_POST_INSTALL=OFF\")
		endif()
			execute_process(
				COMMAND \"${CMAKE_COMMAND}\"
					\"-DBINDIR=${cado_post_install_bindir}\"
				\"-DCADO_CONFIG_FILE=${CADO_CONFIG_FILE}\"
				\"-DCADO_SPOOL_DIR=${CADO_SPOOL_DIR}\"
				-P \"${PROJECT_SOURCE_DIR}/PostInstall.cmake\"
			RESULT_VARIABLE cado_post_install_result)
		if(NOT cado_post_install_result EQUAL 0)
			message(FATAL_ERROR
				\"cado post-install failed with status \${cado_post_install_result}\")
		endif()
	")
endif()
