/*
 * scado: editor, authentication, recovery, and commit lifecycle
 * Copyright (C) 2016 Davide Berardi, University of Bologna
 *
 * This file is part of cado and is distributed under the GNU GPL v2 or later.
 */

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <execs.h>
#include <security/pam_appl.h>

#include <cado_const.h>
#include <compute_digest.h>
#include <file_utils.h>
#include <pam_check.h>
#include <scado_edit.h>
#include <scado_parse.h>
#include <scado_temp_guard.h>
#include <set_ambient_cap.h>

#define EDIT_PAM_MAX_TRIES 3

static struct scado_edit_result edit_result(enum scado_edit_status status,
		int error_number)
{
	struct scado_edit_result result;

	memset(&result, 0, sizeof(result));
	result.status = status;
	result.error_number = error_number;
	return result;
}

static int cleanup_unlink(const char *path, const char *context)
{
	if (unlink(path) == 0 || errno == ENOENT)
		return 0;
	fprintf(stderr, "scado: %s cleanup failed for %s: %s\n", context, path,
			strerror(errno));
	return -1;
}

static int wait_checked(pid_t child)
{
	int status;
	pid_t waited;

	do {
		waited = waitpid(child, &status, 0);
	} while (waited < 0 && errno == EINTR);
	if (waited != child)
		return -1;
	if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
		errno = WIFSIGNALED(status) ? EINTR : ECHILD;
		return -1;
	}
	return 0;
}

static void record_recovery_path(struct scado_edit_result *result,
		const char *path)
{
	int rendered = snprintf(result->recovery_path,
			sizeof(result->recovery_path), "%s", path);

	if (rendered < 0 || (size_t)rendered >= sizeof(result->recovery_path))
		result->recovery_path[0] = '\0';
}

static struct scado_edit_result keep_recovery(struct scado_temp_guard *guard,
		const char *path, struct scado_edit_result result)
{
	int original_error = result.error_number;

	if (scado_temp_guard_finish(guard, SCADO_TEMP_KEEP) < 0) {
		int guard_error = errno;

		fprintf(stderr, "scado: failed to secure the recovery copy: %s\n",
				strerror(guard_error));
		fprintf(stderr, "scado: recovery copy preservation is uncertain at %s\n",
				path);
		if (original_error == 0)
			result.error_number = guard_error;
	} else {
		fprintf(stderr, "A copy of the edited scado file has been saved as %s\n",
				path);
	}
	record_recovery_path(&result, path);
	return result;
}

static struct scado_edit_result discard_recovery(struct scado_temp_guard *guard,
		const char *path)
{
	struct scado_edit_result result = edit_result(SCADO_EDIT_OK, 0);
	int guard_error;

	if (scado_temp_guard_finish(guard, SCADO_TEMP_DISCARD) == 0)
		return result;
	guard_error = errno;
	result.status = SCADO_EDIT_ERROR;
	result.error_number = guard_error;
	if (access(path, F_OK) == 0) {
		fprintf(stderr,
				"scado: temporary-file cleanup failed; recovery remains at %s\n",
				path);
		record_recovery_path(&result, path);
	} else {
		fprintf(stderr, "scado: temporary-file watchdog failed: %s\n",
				strerror(guard_error));
	}
	return result;
}

static int create_default_edit_file(char *path)
{
	int descriptor = mkstemp(path);
	struct cado_io_result write_result;
	int result = -1;

	if (descriptor < 0)
		return -1;
	if (fcntl(descriptor, F_SETFD, FD_CLOEXEC) < 0 ||
			fchmod(descriptor, 0600) < 0)
		goto out;
	write_result = cado_write_all(descriptor, DEFAULT_MESSAGE,
			strlen(DEFAULT_MESSAGE));
	if (write_result.status != CADO_IO_OK) {
		errno = write_result.error_number;
		goto out;
	}
	result = 0;

out:
	if (close(descriptor) < 0)
		result = -1;
	if (result < 0) {
		int saved_errno = errno;

		(void)cleanup_unlink(path, "default edit file");
		errno = saved_errno;
	}
	return result;
}

static int restore_signals(const struct sigaction old_actions[3]);

static int run_editor(const char *editor, const char *path,
		const struct sigaction old_actions[3])
{
	pid_t child = fork();

	if (child < 0)
		return -1;
	if (child == 0) {
		char **parsed_editor;
		char **arguments;
		size_t argument_count;
		size_t i;

		if (restore_signals(old_actions) < 0)
			_exit(255);
		if (setgid(getgid()) < 0 || setuid(getuid()) < 0)
			_exit(255);
		if (drop_all_capabilities() < 0)
			_exit(255);
		parsed_editor = s2argv(editor);
		if (parsed_editor == NULL)
			_exit(255);
		argument_count = s2argc(parsed_editor);
		if (argument_count == 0 || parsed_editor[argument_count + 1] != NULL) {
			s2argv_free(parsed_editor);
			_exit(255);
		}
		arguments = calloc(argument_count + 2, sizeof(*arguments));
		if (arguments == NULL) {
			s2argv_free(parsed_editor);
			_exit(255);
		}
		for (i = 0; i < argument_count; i++)
			arguments[i] = parsed_editor[i];
		arguments[argument_count] = (char *)path;
		execvp(arguments[0], arguments);
		perror(arguments[0]);
		free(arguments);
		s2argv_free(parsed_editor);
		_exit(255);
	}
	return wait_checked(child);
}

static int set_ignored_signals(struct sigaction old_actions[3])
{
	const int signals[3] = {SIGHUP, SIGINT, SIGQUIT};
	struct sigaction ignored;
	int i;

	memset(&ignored, 0, sizeof(ignored));
	ignored.sa_handler = SIG_IGN;
	sigemptyset(&ignored.sa_mask);
	for (i = 0; i < 3; i++) {
		if (sigaction(signals[i], &ignored, &old_actions[i]) < 0) {
			int saved_errno = errno;

			while (--i >= 0) {
				if (sigaction(signals[i], &old_actions[i], NULL) < 0)
					fprintf(stderr,
							"scado: signal rollback failed for %d: %s\n",
							signals[i], strerror(errno));
			}
			errno = saved_errno;
			return -1;
		}
	}
	return 0;
}

static int restore_signals(const struct sigaction old_actions[3])
{
	const int signals[3] = {SIGHUP, SIGINT, SIGQUIT};
	int saved_error = 0;
	int i;

	for (i = 0; i < 3; i++) {
		if (sigaction(signals[i], &old_actions[i], NULL) < 0 &&
				saved_error == 0)
			saved_error = errno;
	}
	if (saved_error != 0) {
		errno = saved_error;
		return -1;
	}
	return 0;
}

static struct scado_edit_result abort_before_editor(
		struct scado_temp_guard *guard, const char *path, int error_number)
{
	if (scado_temp_guard_finish(guard, SCADO_TEMP_DISCARD) < 0)
		fprintf(stderr, "scado: recovery guard abort failed: %s\n",
				strerror(errno));
	if (cleanup_unlink(path, "edit file") < 0 && error_number == 0)
		error_number = errno;
	return edit_result(SCADO_EDIT_ERROR,
			error_number != 0 ? error_number : EIO);
}

struct scado_edit_result scado_edit_execute(
		const struct scado_edit_request *request)
{
	char edit_file[PATH_MAX];
	char digest_before[DIGESTSTRLEN + 1] = "";
	char digest_after[DIGESTSTRLEN + 1];
	char *guard_path;
	struct cado_digest_result copy_result;
	struct cado_digest_result digest_result;
	struct scado_temp_guard guard;
	struct sigaction old_actions[3];
	struct scado_transaction_request transaction_request;
	struct scado_file_result file_result;
	struct scado_edit_result result;
	int rendered;
	int tries;

	if (request == NULL || request->username == NULL ||
			request->protected_path == NULL ||
			request->temporary_directory == NULL ||
			request->editor == NULL || request->editor[0] == '\0')
		return edit_result(SCADO_EDIT_ERROR, EINVAL);

	if (scado_temp_guard_start(&guard, request->temporary_directory,
			TMP_TEMPLATE) < 0)
		return edit_result(SCADO_EDIT_ERROR, errno);
	guard_path = scado_temp_guard_path(&guard);
	copy_result = copytemp_digest_nofollow_regular(request->protected_path,
			guard_path, 0600, digest_before);
	rendered = snprintf(edit_file, sizeof(edit_file), "%s", guard_path);
	if (rendered < 0 || (size_t)rendered >= sizeof(edit_file))
		return abort_before_editor(&guard, "", ENAMETOOLONG);
	if (copy_result.status != CADO_DIGEST_OK) {
		if (copy_result.status != CADO_DIGEST_OPEN_INPUT ||
				copy_result.error_number != ENOENT)
			return abort_before_editor(&guard, edit_file,
					copy_result.error_number);
		if (create_default_edit_file(guard_path) < 0) {
			int create_error = errno;

			(void)snprintf(edit_file, sizeof(edit_file), "%s", guard_path);
			return abort_before_editor(&guard, edit_file, create_error);
		}
		rendered = snprintf(edit_file, sizeof(edit_file), "%s", guard_path);
		if (rendered < 0 || (size_t)rendered >= sizeof(edit_file))
			return abort_before_editor(&guard, "", ENAMETOOLONG);
		digest_before[0] = '\0';
	}
	if (set_ignored_signals(old_actions) < 0) {
		int saved_errno = errno;

		return abort_before_editor(&guard, edit_file, saved_errno);
	}
	if (scado_temp_guard_arm(&guard) < 0) {
		int saved_errno = errno;

		if (restore_signals(old_actions) < 0)
			fprintf(stderr, "scado: signal restoration failed: %s\n",
					strerror(errno));
		return abort_before_editor(&guard, edit_file, saved_errno);
	}
	if (run_editor(request->editor, edit_file, old_actions) < 0) {
		int editor_error = errno;

		if (restore_signals(old_actions) < 0)
			fprintf(stderr, "scado: signal restoration failed: %s\n",
					strerror(errno));
		result = edit_result(SCADO_EDIT_ERROR, editor_error);
		return keep_recovery(&guard, edit_file, result);
	}
	if (restore_signals(old_actions) < 0) {
		result = edit_result(SCADO_EDIT_ERROR, errno);
		return keep_recovery(&guard, edit_file, result);
	}

	digest_result = compute_digest_nofollow_regular(edit_file, digest_after);
	if (digest_result.status != CADO_DIGEST_OK) {
		result = edit_result(SCADO_EDIT_ERROR, digest_result.error_number);
		return keep_recovery(&guard, edit_file, result);
	}
	if (digest_before[0] != '\0' &&
			strcmp(digest_before, digest_after) == 0) {
		file_result = scado_validate_file(edit_file);
		if (file_result.status != SCADO_FILE_OK) {
			scado_report_file_failure(&file_result);
			result = edit_result(SCADO_EDIT_ERROR,
					file_result.error_number != 0 ?
					file_result.error_number : EIO);
			result.has_file_result = 1;
			result.file_result = file_result;
			return keep_recovery(&guard, edit_file, result);
		}
		return discard_recovery(&guard, edit_file);
	}

	for (tries = 0; tries < EDIT_PAM_MAX_TRIES; tries++) {
		if (pam_check(request->username) == PAM_SUCCESS)
			break;
		if (tries + 1 < EDIT_PAM_MAX_TRIES)
			fprintf(stderr, "PAM authorization failed\n");
	}
	if (tries == EDIT_PAM_MAX_TRIES) {
		result = edit_result(SCADO_EDIT_AUTH_ERROR, EACCES);
		return keep_recovery(&guard, edit_file, result);
	}

	memset(&transaction_request, 0, sizeof(transaction_request));
	transaction_request.source_path = edit_file;
	transaction_request.destination_path = request->protected_path;
	transaction_request.operation.kind = SCADO_ADD_MISSING;
	transaction_request.source.kind = SCADO_SOURCE_DIGEST;
	transaction_request.source.digest = digest_after;
	transaction_request.destination.kind = digest_before[0] == '\0' ?
			SCADO_DESTINATION_ABSENT : SCADO_DESTINATION_DIGEST;
	transaction_request.destination.digest = digest_before;
	file_result = scado_update_transaction(&transaction_request);
	if (file_result.status != SCADO_FILE_OK) {
		scado_report_file_failure(&file_result);
		result = edit_result(SCADO_EDIT_ERROR,
				file_result.error_number != 0 ?
				file_result.error_number : EIO);
		result.has_file_result = 1;
		result.file_result = file_result;
		return keep_recovery(&guard, edit_file, result);
	}
	return discard_recovery(&guard, edit_file);
}
