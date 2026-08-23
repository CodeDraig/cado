cmake_minimum_required(VERSION 3.13)

project(cado
	VERSION 0.9.6
	DESCRIPTION "Capability Ambient DO. Provide users just the capabilities they need."
	HOMEPAGE_URL "https://github.com/rd235/cado"
	LANGUAGES C)

if(NOT CMAKE_SYSTEM_NAME STREQUAL "Linux")
	message(FATAL_ERROR "cado requires Linux ambient capabilities and /proc")
endif()

include(CheckCSourceCompiles)
include(CTest)
include(GNUInstallDirs)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS ON)

option(CADO_RUN_POST_INSTALL "Run the checked privileged post-install steps" ON)
option(CADO_ENABLE_PRIVILEGED_TESTS
	"Enable tests that mutate a confirmed disposable root environment" OFF)
set(WITHEDITOR "/usr/bin/vi" CACHE FILEPATH "Default editor used by scado")
set(CADO_CONFIG_FILE "/etc/cado.conf" CACHE FILEPATH "System cado configuration")
set(CADO_SPOOL_DIR
	"${CMAKE_INSTALL_FULL_LOCALSTATEDIR}/spool/${PROJECT_NAME}"
	CACHE PATH "Protected per-user scado spool directory")

find_path(CAP_INCLUDE_DIR NAMES sys/capability.h)
find_library(CAP_LIBRARY NAMES cap)
find_path(PAM_INCLUDE_DIR NAMES security/pam_appl.h)
find_path(PAM_MISC_INCLUDE_DIR NAMES security/pam_misc.h)
find_library(PAM_LIBRARY NAMES pam)
find_library(PAM_MISC_LIBRARY NAMES pam_misc)
find_path(MHASH_INCLUDE_DIR NAMES mhash.h)
find_library(MHASH_LIBRARY NAMES mhash)
find_path(EXECS_INCLUDE_DIR NAMES execs.h)
find_library(EXECS_LIBRARY NAMES execs)

foreach(required_dependency
		CAP_INCLUDE_DIR CAP_LIBRARY
		PAM_INCLUDE_DIR PAM_MISC_INCLUDE_DIR PAM_LIBRARY PAM_MISC_LIBRARY
		MHASH_INCLUDE_DIR MHASH_LIBRARY EXECS_INCLUDE_DIR EXECS_LIBRARY)
	if(NOT ${required_dependency})
		message(FATAL_ERROR
			"required dependency component was not found: ${required_dependency}")
	endif()
endforeach()

set(CMAKE_REQUIRED_INCLUDES "${EXECS_INCLUDE_DIR}")
set(CMAKE_REQUIRED_LIBRARIES "${EXECS_LIBRARY}")
check_c_source_compiles("#include <execs.h>
#if !defined(EXECS_SOVERSION) || EXECS_SOVERSION != 1
#error libexecs sequence API unavailable
#endif
int main(void) { return system_execsqa(\"\"); }"
	CADO_HAS_LIBEXECS_SEQUENCE_API)
unset(CMAKE_REQUIRED_INCLUDES)
unset(CMAKE_REQUIRED_LIBRARIES)
if(NOT CADO_HAS_LIBEXECS_SEQUENCE_API)
	message(FATAL_ERROR
		"cado requires libexecs 1.4 with EXECS_SOVERSION == 1 and system_execsqa")
endif()

set(CMAKE_REQUIRED_INCLUDES "${CAP_INCLUDE_DIR}")
check_c_source_compiles("#include <sys/prctl.h>
#include <sys/capability.h>
#ifndef PR_CAP_AMBIENT
#error ambient capability API unavailable
#endif
#if CAP_LAST_CAP >= 64
#error cado capability masks require CAP_LAST_CAP below 64
#endif
int main(void) { return CAP_LAST_CAP < 0; }" CADO_HAS_AMBIENT_CAPABILITIES)
unset(CMAKE_REQUIRED_INCLUDES)
if(NOT CADO_HAS_AMBIENT_CAPABILITIES)
	message(FATAL_ERROR
		"cado requires current Linux ambient-capability headers with CAP_LAST_CAP below 64")
endif()

configure_file(include/config.h.in include/config.h @ONLY)

add_library(cado_build_options INTERFACE)
target_include_directories(cado_build_options INTERFACE
	${PROJECT_SOURCE_DIR}/include
	${PROJECT_BINARY_DIR}/include
	${CAP_INCLUDE_DIR}
	${PAM_INCLUDE_DIR}
	${PAM_MISC_INCLUDE_DIR}
	${MHASH_INCLUDE_DIR}
	${EXECS_INCLUDE_DIR})
target_compile_definitions(cado_build_options INTERFACE
	_GNU_SOURCE=1
	$<$<OR:$<CONFIG:Release>,$<CONFIG:RelWithDebInfo>,$<CONFIG:MinSizeRel>>:_FORTIFY_SOURCE=2>)
target_compile_options(cado_build_options INTERFACE
	-Wall -Wextra -Wpedantic)

add_subdirectory(man)
add_subdirectory(src)
if(BUILD_TESTING)
	add_subdirectory(tests)
endif()

add_custom_target(uninstall
	COMMAND "${CMAKE_COMMAND}"
		-DMANIFEST=${CMAKE_BINARY_DIR}/install_manifest.txt
		-P "${PROJECT_SOURCE_DIR}/Uninstall.cmake"
	COMMENT "Remove only files recorded in the install manifest")
