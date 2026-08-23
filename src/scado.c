/*
 * scado: manage per-user executable capability authorization files
 * Copyright (C) 2016 Davide Berardi, University of Bologna
 *
 * This file is part of cado and is distributed under the GNU GPL v2 or later.
 */

#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <libgen.h>
#include <limits.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <security/pam_appl.h>

#include <cado_const.h>
#include <config.h>
#include <file_utils.h>
#include <get_scado_file.h>
#include <pam_check.h>
#include <scado_edit.h>
#include <scado_parse.h>

#define SCADO_SUCCESS 0
#define SCADO_ERROR 255
#define SCADO_AUTH_ERROR 254

enum scado_action {
	SCADO_ACTION_NONE = 0,
	SCADO_ACTION_UPDATE_PATH,
	SCADO_ACTION_UPDATE_ALL,
	SCADO_ACTION_DELETE,
	SCADO_ACTION_LIST,
	SCADO_ACTION_EDIT
};

struct scado_request {
	enum scado_action action;
	const char *path;
};

static const struct option long_options[] = {
	{"help",       no_argument,       NULL, 'h'},
	{"update",     required_argument, NULL, 'u'},
	{"update-all", no_argument,       NULL, 'U'},
	{"delete",     no_argument,       NULL, 'D'},
	{"list",       no_argument,       NULL, 'l'},
	{"edit",       no_argument,       NULL, 'e'},
	{0, 0, 0, 0}
};

static int usage(const char *program, const char *message)
{
	fprintf(stderr, "%s - manage per-user executable capability authorizations\n",
			program);
	fprintf(stderr, "usage: %s OPTIONS\n", program);
	fprintf(stderr, "Options:\n");
	fprintf(stderr, "   -h --help               display help message and exit\n");
	fprintf(stderr, "   -u --update <command>   update the digest of an absolute command\n");
	fprintf(stderr, "   -U --update-all         update all persisted digests\n");
	fprintf(stderr, "   -D --delete             delete the scado file\n");
	fprintf(stderr, "   -l --list               print the scado file\n");
	fprintf(stderr, "   -e --edit               edit the scado file\n");
	if (message != NULL)
		fprintf(stderr, "\n%s\n", message);
	return SCADO_ERROR;
}

static int select_action(struct scado_request *request, enum scado_action action,
		const char *path)
{
	if (request->action != SCADO_ACTION_NONE)
		return -1;
	request->action = action;
	request->path = path;
	return 0;
}

static int parse_request(int argc, char **argv, struct scado_request *request)
{
	int option;

	memset(request, 0, sizeof(*request));
	opterr = 0;
	while ((option = getopt_long(argc, argv, "hu:UDle", long_options, NULL)) >= 0) {
		switch (option) {
		case 'h':
			return 1;
		case 'u':
			if (optarg[0] != '/' || select_action(request,
					SCADO_ACTION_UPDATE_PATH, optarg) < 0)
				return -1;
			break;
		case 'U':
			if (select_action(request, SCADO_ACTION_UPDATE_ALL, NULL) < 0)
				return -1;
			break;
		case 'D':
			if (select_action(request, SCADO_ACTION_DELETE, NULL) < 0)
				return -1;
			break;
		case 'l':
			if (select_action(request, SCADO_ACTION_LIST, NULL) < 0)
				return -1;
			break;
		case 'e':
			if (select_action(request, SCADO_ACTION_EDIT, NULL) < 0)
				return -1;
			break;
		default:
			return -1;
		}
	}
	if (optind != argc || request->action == SCADO_ACTION_NONE)
		return -1;
	return 0;
}

static int scado_list(const char *username)
{
	char path[PATH_MAX];
	int input;
	struct cado_io_result copy_result;
	int close_error = 0;

	if (get_scado_file(username, path) < 0) {
		errno = ENAMETOOLONG;
		return SCADO_ERROR;
	}
	input = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
	if (input < 0)
		return SCADO_ERROR;
	copy_result = cado_copy_fd(input, STDOUT_FILENO);
	if (close(input) < 0)
		close_error = errno;
	if (copy_result.status != CADO_IO_OK) {
		errno = copy_result.error_number;
		return SCADO_ERROR;
	}
	if (close_error != 0) {
		errno = close_error;
		return SCADO_ERROR;
	}
	return SCADO_SUCCESS;
}

static int scado_delete(const char *username)
{
	char path[PATH_MAX];
	struct scado_file_result result;

	if (get_scado_file(username, path) < 0) {
		errno = ENAMETOOLONG;
		return SCADO_ERROR;
	}
	if (pam_check(username) != PAM_SUCCESS)
		return SCADO_AUTH_ERROR;
	result = scado_delete_transaction(path);
	if (result.status == SCADO_FILE_OK)
		return SCADO_SUCCESS;
	scado_report_file_failure(&result);
	errno = result.error_number != 0 ? result.error_number : EIO;
	return SCADO_ERROR;
}

static int scado_update(const char *username, const struct scado_request *request)
{
	char path[PATH_MAX];
	struct scado_transaction_request transaction;
	struct scado_file_result result;

	if (get_scado_file(username, path) < 0) {
		errno = ENAMETOOLONG;
		return SCADO_ERROR;
	}
	if (pam_check(username) != PAM_SUCCESS)
		return SCADO_AUTH_ERROR;
	memset(&transaction, 0, sizeof(transaction));
	transaction.source_path = path;
	transaction.destination_path = path;
	transaction.operation.kind = request->action == SCADO_ACTION_UPDATE_PATH ?
			SCADO_UPDATE_PATH : SCADO_UPDATE_ALL;
	transaction.operation.path = request->path;
	transaction.source.kind = SCADO_SOURCE_CURRENT;
	transaction.destination.kind = SCADO_DESTINATION_SOURCE_SNAPSHOT;
	result = scado_update_transaction(&transaction);
	if (result.status != SCADO_FILE_OK) {
		scado_report_file_failure(&result);
		errno = result.error_number != 0 ? result.error_number : EIO;
		return SCADO_ERROR;
	}
	return SCADO_SUCCESS;
}

static int scado_edit(const char *username, const char *temporary_directory)
{
	char protected_path[PATH_MAX];
	const char *editor;
	struct scado_edit_request request;
	struct scado_edit_result result;

	if (get_scado_file(username, protected_path) < 0) {
		errno = ENAMETOOLONG;
		return SCADO_ERROR;
	}
	editor = getenv("VISUAL");
	if (editor == NULL || editor[0] == '\0')
		editor = getenv("EDITOR");
	if (editor == NULL || editor[0] == '\0')
		editor = EDITOR;
	request.username = username;
	request.protected_path = protected_path;
	request.temporary_directory = temporary_directory;
	request.editor = editor;
	result = scado_edit_execute(&request);
	if (result.status == SCADO_EDIT_OK)
		return SCADO_SUCCESS;
	if (result.status == SCADO_EDIT_AUTH_ERROR)
		return SCADO_AUTH_ERROR;
	errno = result.error_number != 0 ? result.error_number : EIO;
	return SCADO_ERROR;
}

static char *current_username(void)
{
	struct passwd *password = getpwuid(getuid());

	return password == NULL ? NULL : strdup(password->pw_name);
}

int main(int argc, char **argv)
{
	const char *program = basename(argv[0]);
	struct scado_request request;
	char *username;
	const char *temporary_directory;
	int parse_status;
	int result;

	parse_status = parse_request(argc, argv, &request);
	if (parse_status > 0)
		return usage(program, NULL);
	if (parse_status < 0)
		return usage(program,
				"select exactly one option; -u requires an absolute path and no trailing operands are accepted");

	username = current_username();
	if (username == NULL) {
		fprintf(stderr, "Your UID isn't in the passwd file.\n");
		return SCADO_ERROR;
	}
	temporary_directory = getenv("TMPDIR");
	if (temporary_directory == NULL || temporary_directory[0] == '\0')
		temporary_directory = TMPDIR;

	switch (request.action) {
	case SCADO_ACTION_UPDATE_PATH:
	case SCADO_ACTION_UPDATE_ALL:
		result = scado_update(username, &request);
		break;
	case SCADO_ACTION_DELETE:
		result = scado_delete(username);
		break;
	case SCADO_ACTION_LIST:
		result = scado_list(username);
		break;
	case SCADO_ACTION_EDIT:
		result = scado_edit(username, temporary_directory);
		break;
	case SCADO_ACTION_NONE:
	default:
		result = SCADO_ERROR;
		break;
	}
	if (result == SCADO_AUTH_ERROR)
		fprintf(stderr, "%s: Authorization failure.\n", program);
	else if (result != SCADO_SUCCESS)
		fprintf(stderr, "%s: %s\n", program, strerror(errno));
	free(username);
	return result;
}
