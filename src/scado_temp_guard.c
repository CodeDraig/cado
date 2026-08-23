/*
 * cado: crash-lifetime ownership for named scado temporary files
 * Copyright (C) 2016 Davide Berardi, University of Bologna
 *
 * This file is part of cado and is distributed under the GNU GPL v2 or later.
 */

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/wait.h>

#include <file_utils.h>
#include <scado_temp_guard.h>

enum guard_message {
	GUARD_ARM = 'A',
	GUARD_DISCARD = 'D',
	GUARD_KEEP = 'K',
	GUARD_TRANSFER = 'T'
};

static void guard_init(struct scado_temp_guard *guard)
{
	guard->path = MAP_FAILED;
	guard->lifetime_fd = -1;
	guard->child = -1;
	guard->armed = 0;
}

static int close_guard_fd(int descriptor, const char *context)
{
	if (descriptor < 0 || close(descriptor) == 0)
		return 0;
	dprintf(STDERR_FILENO, "scado: %s close failed: %s\n", context,
			strerror(errno));
	return -1;
}

static int unlink_guard_path(const char *path)
{
	if (unlink(path) == 0 || errno == ENOENT)
		return 0;
	dprintf(STDERR_FILENO, "scado: temporary-file cleanup failed for %s: %s\n",
			path, strerror(errno));
	return -1;
}

static int wait_for_guard(pid_t child)
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

static struct cado_io_result write_guard_pipe(int descriptor,
		const void *buffer, size_t length)
{
	struct sigaction ignored;
	struct sigaction previous;
	struct cado_io_result result;
	int write_error;

	memset(&ignored, 0, sizeof(ignored));
	ignored.sa_handler = SIG_IGN;
	sigemptyset(&ignored.sa_mask);
	if (sigaction(SIGPIPE, &ignored, &previous) < 0) {
		result.status = CADO_IO_WRITE;
		result.bytes = 0;
		result.error_number = errno;
		return result;
	}
	result = cado_write_all(descriptor, buffer, length);
	write_error = result.error_number;
	if (sigaction(SIGPIPE, &previous, NULL) < 0) {
		if (result.status == CADO_IO_OK) {
			result.status = CADO_IO_WRITE;
			result.error_number = errno;
		} else {
			result.error_number = write_error;
		}
	}
	return result;
}

static void guard_process(const char *path, int lifetime_fd, int setup_fd)
{
	int setup_error = 0;
	int armed = 0;
	int discard = 1;
	int protocol_error = 0;
	char message;

	if (setsid() < 0)
		setup_error = errno;
	if (write_guard_pipe(setup_fd, &setup_error,
			sizeof(setup_error)).status != CADO_IO_OK) {
		(void)close_guard_fd(setup_fd, "temporary guard setup pipe");
		(void)close_guard_fd(lifetime_fd, "temporary guard lifetime pipe");
		(void)unlink_guard_path(path);
		_exit(1);
	}
	if (close(setup_fd) < 0 || setup_error != 0) {
		(void)close_guard_fd(lifetime_fd, "temporary guard lifetime pipe");
		(void)unlink_guard_path(path);
		_exit(1);
	}

	for (;;) {
		ssize_t count = read(lifetime_fd, &message, sizeof(message));

		if (count < 0 && errno == EINTR)
			continue;
		if (count < 0) {
			protocol_error = 1;
			discard = !armed;
			break;
		}
		if (count == 0) {
			discard = !armed;
			break;
		}
		switch ((enum guard_message)message) {
		case GUARD_ARM:
			if (armed) {
				protocol_error = 1;
				discard = 0;
				break;
			}
			armed = 1;
			continue;
		case GUARD_DISCARD:
			discard = 1;
			break;
		case GUARD_KEEP:
			if (!armed) {
				protocol_error = 1;
				discard = 1;
			} else {
				discard = 0;
			}
			break;
		case GUARD_TRANSFER:
			discard = 0;
			break;
		default:
			protocol_error = 1;
			discard = !armed;
			break;
		}
		break;
	}
	if (close(lifetime_fd) < 0)
		protocol_error = 1;
	if (discard && unlink_guard_path(path) < 0)
		protocol_error = 1;
	_exit(protocol_error ? 1 : 0);
}

int scado_temp_guard_start(struct scado_temp_guard *guard,
		const char *directory, const char *template_name)
{
	int lifetime[2] = {-1, -1};
	int setup[2] = {-1, -1};
	int setup_error = 0;
	int failure_error;
	int rendered;
	pid_t child = -1;

	if (guard == NULL || directory == NULL || template_name == NULL) {
		errno = EINVAL;
		return -1;
	}
	guard_init(guard);
	guard->path = mmap(NULL, PATH_MAX, PROT_READ | PROT_WRITE,
			MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	if (guard->path == MAP_FAILED)
		return -1;
	rendered = snprintf(guard->path, PATH_MAX, "%s/%s", directory,
			template_name);
	if (rendered < 0 || rendered >= PATH_MAX) {
		errno = ENAMETOOLONG;
		goto fail;
	}
	if (pipe2(lifetime, O_CLOEXEC) < 0)
		goto fail;
	if (pipe2(setup, O_CLOEXEC) < 0)
		goto fail;
	child = fork();
	if (child < 0)
		goto fail;
	if (child == 0) {
		int close_failed = 0;

		if (close_guard_fd(lifetime[1],
				"child temporary lifetime write") < 0)
			close_failed = 1;
		if (close_guard_fd(setup[0], "child temporary setup read") < 0)
			close_failed = 1;
		if (close_failed) {
			(void)unlink_guard_path(guard->path);
			_exit(1);
		}
		guard_process(guard->path, lifetime[0], setup[1]);
	}
	if (close(lifetime[0]) < 0) {
		lifetime[0] = -1;
		goto fail;
	}
	lifetime[0] = -1;
	if (close(setup[1]) < 0) {
		setup[1] = -1;
		goto fail;
	}
	setup[1] = -1;
	if (read_exact(setup[0], &setup_error, sizeof(setup_error)) < 0)
		goto fail;
	if (setup_error != 0) {
		errno = setup_error;
		goto fail;
	}
	if (close(setup[0]) < 0) {
		setup[0] = -1;
		goto fail;
	}
	setup[0] = -1;
	guard->lifetime_fd = lifetime[1];
	guard->child = child;
	return 0;

fail:
	failure_error = errno;
	(void)close_guard_fd(lifetime[0], "parent temporary lifetime read");
	(void)close_guard_fd(setup[0], "parent temporary setup read");
	(void)close_guard_fd(setup[1], "parent temporary setup write");
	if (lifetime[1] >= 0)
		(void)close_guard_fd(lifetime[1], "parent temporary lifetime write");
	if (child > 0 && wait_for_guard(child) < 0)
		dprintf(STDERR_FILENO,
				"scado: temporary guard setup cleanup failed: %s\n",
				strerror(errno));
	if (guard->path != MAP_FAILED && munmap(guard->path, PATH_MAX) < 0)
		dprintf(STDERR_FILENO,
				"scado: temporary guard path cleanup failed: %s\n",
				strerror(errno));
	guard_init(guard);
	errno = failure_error;
	return -1;
}

char *scado_temp_guard_path(struct scado_temp_guard *guard)
{
	if (guard == NULL || guard->path == MAP_FAILED)
		return NULL;
	return guard->path;
}

static int send_guard_message(struct scado_temp_guard *guard,
		enum guard_message message)
{
	struct cado_io_result result;
	char encoded = (char)message;

	if (guard == NULL || guard->lifetime_fd < 0 || guard->child < 0) {
		errno = EINVAL;
		return -1;
	}
	result = write_guard_pipe(guard->lifetime_fd, &encoded, sizeof(encoded));
	if (result.status != CADO_IO_OK) {
		errno = result.error_number;
		return -1;
	}
	return 0;
}

int scado_temp_guard_arm(struct scado_temp_guard *guard)
{
	if (guard == NULL || guard->armed) {
		errno = guard != NULL ? EALREADY : EINVAL;
		return -1;
	}
	if (send_guard_message(guard, GUARD_ARM) < 0)
		return -1;
	guard->armed = 1;
	return 0;
}

int scado_temp_guard_finish(struct scado_temp_guard *guard,
		enum scado_temp_disposition disposition)
{
	enum guard_message message;
	int failure_error = 0;

	if (guard == NULL || guard->path == MAP_FAILED || guard->lifetime_fd < 0 ||
			guard->child < 0 || disposition < SCADO_TEMP_DISCARD ||
			disposition > SCADO_TEMP_TRANSFER ||
			(disposition == SCADO_TEMP_KEEP && !guard->armed)) {
		errno = EINVAL;
		return -1;
	}
	switch (disposition) {
	case SCADO_TEMP_DISCARD:
		message = GUARD_DISCARD;
		break;
	case SCADO_TEMP_KEEP:
		message = GUARD_KEEP;
		break;
	case SCADO_TEMP_TRANSFER:
		message = GUARD_TRANSFER;
		break;
	}
	if (send_guard_message(guard, message) < 0)
		failure_error = errno;
	if (close(guard->lifetime_fd) < 0 && failure_error == 0)
		failure_error = errno;
	guard->lifetime_fd = -1;
	if (wait_for_guard(guard->child) < 0 && failure_error == 0)
		failure_error = errno;
	guard->child = -1;
	if (munmap(guard->path, PATH_MAX) < 0 && failure_error == 0)
		failure_error = errno;
	guard->path = MAP_FAILED;
	guard->armed = 0;
	if (failure_error != 0) {
		errno = failure_error;
		return -1;
	}
	return 0;
}
