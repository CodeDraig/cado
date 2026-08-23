#ifndef CADO_SCADO_CHECK_H
#define CADO_SCADO_CHECK_H

#include <limits.h>
#include <stdint.h>

struct cado_verified_executable {
	char path[PATH_MAX];
	int cleanup_fd;
};

enum cado_scado_status {
	CADO_SCADO_OK = 0,
	CADO_SCADO_NOT_AUTHORIZED,
	CADO_SCADO_PATH_ERROR,
	CADO_SCADO_CAPABILITY_ERROR,
	CADO_SCADO_FILE_ERROR,
	CADO_SCADO_COPY_ERROR,
	CADO_SCADO_MODE_ERROR,
	CADO_SCADO_DIGEST_MISMATCH,
	CADO_SCADO_PIPE_ERROR,
	CADO_SCADO_FORK_ERROR,
	CADO_SCADO_WATCHDOG_ERROR,
	CADO_SCADO_CLEANUP_ERROR
};

struct cado_scado_result {
	enum cado_scado_status status;
	uint64_t capabilities;
	int error_number;
	int cleanup_error;
};

void cado_verified_executable_init(struct cado_verified_executable *handle);
struct cado_scado_result cado_verified_executable_create(const char *path,
		const char *expected_digest,
		const char *temporary_directory,
		struct cado_verified_executable *handle);
int cado_verified_executable_release(struct cado_verified_executable *handle);
struct cado_scado_result cado_scado_prepare(const char *username,
		const char *executable_path,
		struct cado_verified_executable *handle);
const char *cado_scado_status_string(enum cado_scado_status status);

#endif
