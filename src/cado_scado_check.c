/*
 * cado: digest-verified executable copies with an exec-lifetime watchdog
 * Copyright (C) 2016 Davide Berardi and Renzo Davoli, University of Bologna
 *
 * This file is part of cado and is distributed under the GNU GPL v2 or later.
 */

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <cado_const.h>
#include <cado_scado_check.h>
#include <compute_digest.h>
#include <file_utils.h>
#include <get_scado_file.h>
#include <scado_parse.h>
#include <set_ambient_cap.h>

struct watchdog_ack {
	int status;
	int error_number;
};

static struct cado_scado_result scado_result(enum cado_scado_status status,
		int error_number)
{
	struct cado_scado_result result = {
		.status = status,
		.error_number = error_number
	};

	return result;
}

void cado_verified_executable_init(struct cado_verified_executable *handle)
{
	if (handle == NULL)
		return;
	handle->path[0] = '\0';
	handle->cleanup_fd = -1;
}

static int close_child_fd(int descriptor, const char *context)
{
	if (descriptor < 0 || close(descriptor) == 0)
		return 1;
	dprintf(STDERR_FILENO, "cado watchdog: %s close failed: %s\n",
			context, strerror(errno));
	return 0;
}

static void watchdog_remove(const char *path)
{
	if (unlink(path) < 0 && errno != ENOENT)
		dprintf(STDERR_FILENO, "cado watchdog: cannot unlink %s: %s\n",
				path, strerror(errno));
}

static void watchdog_process(const char *path, int lifetime_fd, int setup_fd)
{
	struct watchdog_ack ack = { .status = 0 };
	char byte;

	if (setsid() < 0) {
		ack.status = -1;
		ack.error_number = errno;
	}
	if (cado_write_all(setup_fd, &ack, sizeof(ack)).status != CADO_IO_OK) {
		(void)close_child_fd(setup_fd, "setup pipe");
		(void)close_child_fd(lifetime_fd, "lifetime pipe");
		watchdog_remove(path);
		_exit(1);
	}
	if (!close_child_fd(setup_fd, "setup pipe")) {
		(void)close_child_fd(lifetime_fd, "lifetime pipe");
		watchdog_remove(path);
		_exit(1);
	}
	if (ack.status != 0) {
		(void)close_child_fd(lifetime_fd, "lifetime pipe");
		watchdog_remove(path);
		_exit(1);
	}
	for (;;) {
		ssize_t count = read(lifetime_fd, &byte, sizeof(byte));

		if (count > 0)
			continue;
		if (count < 0 && errno == EINTR)
			continue;
		break;
	}
	(void)close_child_fd(lifetime_fd, "lifetime pipe");
	watchdog_remove(path);
	_exit(0);
}

static int wait_for_child(pid_t child)
{
	int status;
	pid_t waited;

	do {
		waited = waitpid(child, &status, 0);
	} while (waited < 0 && errno == EINTR);
	if (waited != child)
		return -1;
	if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
		errno = ECHILD;
		return -1;
	}
	return 0;
}

static int read_exact(int descriptor, void *buffer, size_t length)
{
	unsigned char *scan = buffer;

	while (length > 0) {
		ssize_t count = read(descriptor, scan, length);

		if (count < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		if (count == 0) {
			errno = EPIPE;
			return -1;
		}
		scan += (size_t)count;
		length -= (size_t)count;
	}
	return 0;
}

static enum cado_scado_status start_watchdog(const char *path,
		int *lifetime_descriptor, int *error_number)
{
	int descriptors[2];
	int lifetime_read = -1;
	int lifetime_write = -1;
	int setup_read = -1;
	int setup_write = -1;
	int own_lifetime_read = 0;
	int own_lifetime_write = 0;
	int own_setup_read = 0;
	int own_setup_write = 0;
	int intermediate_waited = 0;
	pid_t intermediate = -1;
	struct watchdog_ack ack = { .status = -1, .error_number = EIO };
	enum cado_scado_status status = CADO_SCADO_OK;

	if (pipe2(descriptors, O_CLOEXEC) < 0) {
		*error_number = errno;
		return CADO_SCADO_PIPE_ERROR;
	}
	lifetime_read = descriptors[0];
	lifetime_write = descriptors[1];
	own_lifetime_read = 1;
	own_lifetime_write = 1;
	if (pipe2(descriptors, O_CLOEXEC) < 0) {
		*error_number = errno;
		status = CADO_SCADO_PIPE_ERROR;
		goto out;
	}
	setup_read = descriptors[0];
	setup_write = descriptors[1];
	own_setup_read = 1;
	own_setup_write = 1;
	intermediate = fork();
	if (intermediate < 0) {
		*error_number = errno;
		status = CADO_SCADO_FORK_ERROR;
		goto out;
	}
	if (intermediate == 0) {
		pid_t watcher;
		int initial_close_failed = 0;

		if (!close_child_fd(lifetime_write, "intermediate lifetime write"))
			initial_close_failed = 1;
		if (!close_child_fd(setup_read, "intermediate setup read"))
			initial_close_failed = 1;
		if (initial_close_failed)
			_exit(1);
		watcher = fork();
		if (watcher < 0) {
			struct watchdog_ack failed = {
				.status = -1,
				.error_number = errno
			};

			(void)cado_write_all(setup_write, &failed, sizeof(failed));
			_exit(1);
		}
		if (watcher == 0)
			watchdog_process(path, lifetime_read, setup_write);
		{
			int close_failed = 0;

			if (!close_child_fd(lifetime_read,
					"intermediate lifetime read"))
				close_failed = 1;
			if (!close_child_fd(setup_write, "intermediate setup write"))
				close_failed = 1;
			_exit(close_failed ? 1 : 0);
		}
	}

	if (close(lifetime_read) < 0) {
		*error_number = errno;
		status = CADO_SCADO_WATCHDOG_ERROR;
	}
	lifetime_read = -1;
	own_lifetime_read = 0;
	if (close(setup_write) < 0 && status == CADO_SCADO_OK) {
		*error_number = errno;
		status = CADO_SCADO_WATCHDOG_ERROR;
	}
	setup_write = -1;
	own_setup_write = 0;
	if (status == CADO_SCADO_OK &&
			read_exact(setup_read, &ack, sizeof(ack)) < 0) {
		*error_number = errno;
		status = CADO_SCADO_WATCHDOG_ERROR;
	}
	if (close(setup_read) < 0 && status == CADO_SCADO_OK) {
		*error_number = errno;
		status = CADO_SCADO_WATCHDOG_ERROR;
	}
	setup_read = -1;
	own_setup_read = 0;
	if (wait_for_child(intermediate) < 0) {
		if (status == CADO_SCADO_OK) {
			*error_number = errno;
			status = CADO_SCADO_FORK_ERROR;
		}
	}
	intermediate_waited = 1;
	if (status == CADO_SCADO_OK && ack.status != 0) {
		*error_number = ack.error_number;
		status = CADO_SCADO_WATCHDOG_ERROR;
	}
	if (status == CADO_SCADO_OK) {
		*lifetime_descriptor = lifetime_write;
		lifetime_write = -1;
		own_lifetime_write = 0;
	}

out:
	if (own_lifetime_read && close(lifetime_read) < 0)
		dprintf(STDERR_FILENO,
				"cado watchdog: parent lifetime read cleanup failed: %s\n",
				strerror(errno));
	if (own_lifetime_write && close(lifetime_write) < 0)
		dprintf(STDERR_FILENO,
				"cado watchdog: parent lifetime write cleanup failed: %s\n",
				strerror(errno));
	if (own_setup_read && close(setup_read) < 0)
		dprintf(STDERR_FILENO,
				"cado watchdog: parent setup read cleanup failed: %s\n",
				strerror(errno));
	if (own_setup_write && close(setup_write) < 0)
		dprintf(STDERR_FILENO,
				"cado watchdog: parent setup write cleanup failed: %s\n",
				strerror(errno));
	if (intermediate > 0 && !intermediate_waited &&
			wait_for_child(intermediate) < 0)
		dprintf(STDERR_FILENO,
				"cado watchdog: intermediate cleanup wait failed: %s\n",
				strerror(errno));
	return status;
}

static int remove_copy(const char *path)
{
	if (unlink(path) == 0 || errno == ENOENT)
		return 0;
	return -1;
}

struct cado_scado_result cado_verified_executable_create(const char *path,
		const char *expected_digest,
		const char *temporary_directory,
		struct cado_verified_executable *handle)
{
	struct cado_scado_result result = scado_result(CADO_SCADO_OK, 0);
	struct cado_digest_result copy_result;
	struct stat input_stat;
	char actual_digest[DIGESTSTRLEN + 1];
	char created_path[PATH_MAX] = "";
	char *watchdog_path = MAP_FAILED;
	int input = -1;
	int output = -1;
	int watcher_started = 0;
	int created = 0;
	int rendered;

	if (path == NULL || expected_digest == NULL || temporary_directory == NULL ||
			handle == NULL || temporary_directory[0] != '/' ||
			!cado_digest_is_valid(expected_digest))
		return scado_result(CADO_SCADO_PATH_ERROR, EINVAL);
	cado_verified_executable_init(handle);
	input = open(path, O_RDONLY | O_CLOEXEC | O_NONBLOCK);
	if (input < 0)
		return scado_result(CADO_SCADO_COPY_ERROR, errno);
	if (fstat(input, &input_stat) < 0) {
		result = scado_result(CADO_SCADO_COPY_ERROR, errno);
		goto fail_copy;
	}
	if (!S_ISREG(input_stat.st_mode)) {
		result = scado_result(CADO_SCADO_COPY_ERROR, EINVAL);
		goto fail_copy;
	}

	watchdog_path = mmap(NULL, PATH_MAX, PROT_READ | PROT_WRITE,
			MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	if (watchdog_path == MAP_FAILED) {
		result = scado_result(CADO_SCADO_WATCHDOG_ERROR, errno);
		goto fail_copy;
	}
	rendered = snprintf(watchdog_path, PATH_MAX, "%s/%s",
			temporary_directory, COPY_TEMPLATE);
	if (rendered < 0 || rendered >= PATH_MAX) {
		result = scado_result(CADO_SCADO_PATH_ERROR, ENAMETOOLONG);
		goto fail_copy;
	}
	result.status = start_watchdog(watchdog_path, &handle->cleanup_fd,
			&result.error_number);
	if (result.status != CADO_SCADO_OK)
		goto fail_copy;
	watcher_started = 1;

	output = mkstemp(watchdog_path);
	if (output < 0) {
		result = scado_result(CADO_SCADO_COPY_ERROR, errno);
		goto fail_copy;
	}
	created = 1;
	memcpy(created_path, watchdog_path, (size_t)rendered + 1);
	memcpy(handle->path, watchdog_path, (size_t)rendered + 1);
	if (munmap(watchdog_path, PATH_MAX) < 0) {
		result = scado_result(CADO_SCADO_WATCHDOG_ERROR, errno);
		goto fail_copy;
	}
	watchdog_path = MAP_FAILED;
	if (fcntl(output, F_SETFD, FD_CLOEXEC) < 0 || fchmod(output, 0600) < 0) {
		result = scado_result(CADO_SCADO_COPY_ERROR, errno);
		goto fail_copy;
	}
	copy_result = cado_copy_digest_fd(input, output, actual_digest);
	if (copy_result.status != CADO_DIGEST_OK) {
		result = scado_result(CADO_SCADO_COPY_ERROR,
				copy_result.error_number);
		result.cleanup_error = copy_result.cleanup_error;
		goto fail_copy;
	}
	if (close(input) < 0) {
		input = -1;
		result = scado_result(CADO_SCADO_COPY_ERROR, errno);
		goto fail_copy;
	}
	input = -1;
	if (fchmod(output, 0611) < 0) {
		result = scado_result(CADO_SCADO_MODE_ERROR, errno);
		goto fail_copy;
	}
	if (close(output) < 0) {
		output = -1;
		result = scado_result(CADO_SCADO_COPY_ERROR, errno);
		goto fail_copy;
	}
	output = -1;
	if (strcasecmp(actual_digest, expected_digest) != 0) {
		fprintf(stderr, "%s", DIGEST_WARNING);
		result = scado_result(CADO_SCADO_DIGEST_MISMATCH, 0);
		goto fail_copy;
	}
	return result;

fail_copy:
	if (input >= 0 && close(input) < 0 && result.cleanup_error == 0)
		result.cleanup_error = errno;
	if (output >= 0 && close(output) < 0 && result.cleanup_error == 0)
		result.cleanup_error = errno;
	if (watchdog_path != MAP_FAILED && munmap(watchdog_path, PATH_MAX) < 0 &&
			result.cleanup_error == 0)
		result.cleanup_error = errno;
	if (created && remove_copy(created_path) < 0) {
		result.status = CADO_SCADO_CLEANUP_ERROR;
		result.error_number = errno;
	}
	if (watcher_started && close(handle->cleanup_fd) < 0 &&
			result.cleanup_error == 0)
		result.cleanup_error = errno;
	handle->cleanup_fd = -1;
	handle->path[0] = '\0';
	return result;
}

int cado_verified_executable_release(struct cado_verified_executable *handle)
{
	int result = 0;

	if (handle == NULL) {
		errno = EINVAL;
		return -1;
	}
	if (handle->cleanup_fd >= 0) {
		result = close(handle->cleanup_fd);
		handle->cleanup_fd = -1;
	}
	handle->path[0] = '\0';
	return result;
}

struct cado_scado_result cado_scado_prepare(const char *username,
		const char *executable_path,
		struct cado_verified_executable *handle)
{
	char scado_file[PATH_MAX];
	struct scado_path_result path_result;
	struct cado_scado_result result;
	int raise_error = 0;
	int lower_error = 0;

	if (username == NULL || executable_path == NULL || handle == NULL ||
			executable_path[0] != '/')
		return scado_result(CADO_SCADO_PATH_ERROR, EINVAL);
	cado_verified_executable_init(handle);
	if (get_scado_file(username, scado_file) < 0)
		return scado_result(CADO_SCADO_PATH_ERROR, ENAMETOOLONG);
	memset(&path_result, 0, sizeof(path_result));
	if (raise_cap_dac_read_search() < 0)
		raise_error = errno;
	else
		path_result = scado_path_getinfo(scado_file, executable_path);
	if (lower_cap_dac_read_search() < 0)
		lower_error = errno;
	if (raise_error != 0) {
		result = scado_result(CADO_SCADO_CAPABILITY_ERROR, raise_error);
		result.cleanup_error = lower_error;
		return result;
	}
	if (lower_error != 0)
		return scado_result(CADO_SCADO_CAPABILITY_ERROR, lower_error);
	if (path_result.status != SCADO_FILE_OK) {
		result = scado_result(CADO_SCADO_FILE_ERROR,
				path_result.error_number);
		result.cleanup_error = path_result.cleanup_error;
		return result;
	}
	if (!path_result.found)
		return scado_result(CADO_SCADO_NOT_AUTHORIZED, 0);
	if (path_result.digest[0] == '\0') {
		result = scado_result(CADO_SCADO_OK, 0);
		result.capabilities = path_result.capabilities;
		return result;
	}
	result = cado_verified_executable_create(executable_path,
			path_result.digest, COPY_DIR, handle);
	if (result.status == CADO_SCADO_OK)
		result.capabilities = path_result.capabilities;
	return result;
}

const char *cado_scado_status_string(enum cado_scado_status status)
{
	switch (status) {
	case CADO_SCADO_OK: return "scado authorization succeeded";
	case CADO_SCADO_NOT_AUTHORIZED: return "command is not in the scado file";
	case CADO_SCADO_PATH_ERROR: return "invalid scado executable path";
	case CADO_SCADO_CAPABILITY_ERROR: return "cannot scope scado read capability";
	case CADO_SCADO_FILE_ERROR: return "cannot read a valid scado file";
	case CADO_SCADO_COPY_ERROR: return "cannot make verified executable copy";
	case CADO_SCADO_MODE_ERROR: return "cannot set verified-copy mode";
	case CADO_SCADO_DIGEST_MISMATCH: return "executable digest mismatch";
	case CADO_SCADO_PIPE_ERROR: return "cannot create watchdog pipes";
	case CADO_SCADO_FORK_ERROR: return "cannot fork watchdog";
	case CADO_SCADO_WATCHDOG_ERROR: return "cannot initialize watchdog";
	case CADO_SCADO_CLEANUP_ERROR: return "cannot remove verified executable copy";
	}
	return "unknown scado authorization error";
}
