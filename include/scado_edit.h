#ifndef CADO_SCADO_EDIT_H
#define CADO_SCADO_EDIT_H

#include <limits.h>

#include <scado_parse.h>

enum scado_edit_status {
	SCADO_EDIT_OK = 0,
	SCADO_EDIT_ERROR,
	SCADO_EDIT_AUTH_ERROR
};

struct scado_edit_request {
	const char *username;
	const char *protected_path;
	const char *temporary_directory;
	const char *editor;
};

struct scado_edit_result {
	enum scado_edit_status status;
	int error_number;
	int has_file_result;
	struct scado_file_result file_result;
	char recovery_path[PATH_MAX];
};

struct scado_edit_result scado_edit_execute(
		const struct scado_edit_request *request);

#endif
