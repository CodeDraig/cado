#ifndef CADO_SCADO_PARSE_H
#define CADO_SCADO_PARSE_H

#include <stddef.h>
#include <stdint.h>

#include <compute_digest.h>

struct scado_span {
	const char *data;
	size_t length;
};

enum scado_line_kind {
	SCADO_LINE_BLANK = 0,
	SCADO_LINE_COMMENT,
	SCADO_LINE_ENTRY
};

enum scado_parse_status {
	SCADO_PARSE_OK = 0,
	SCADO_PARSE_EMBEDDED_NUL,
	SCADO_PARSE_FIELD_COUNT,
	SCADO_PARSE_PATH_MISSING,
	SCADO_PARSE_PATH_NOT_ABSOLUTE,
	SCADO_PARSE_CAPABILITIES,
	SCADO_PARSE_DIGEST_EMPTY,
	SCADO_PARSE_DIGEST_INVALID,
	SCADO_PARSE_NO_MEMORY
};

struct scado_line {
	enum scado_line_kind kind;
	struct scado_span path;
	struct scado_span capabilities;
	struct scado_span digest;
	int has_digest;
	uint64_t capability_set;
};

enum scado_parse_status scado_parse_line(const char *line, size_t length,
		int allow_empty_digest, struct scado_line *parsed);
const char *scado_parse_status_string(enum scado_parse_status status);

enum scado_update_kind {
	SCADO_ADD_MISSING = 0,
	SCADO_UPDATE_ALL,
	SCADO_UPDATE_PATH
};

struct scado_update_operation {
	enum scado_update_kind kind;
	const char *path;
};

enum scado_source_expectation_kind {
	SCADO_SOURCE_CURRENT = 0,
	SCADO_SOURCE_DIGEST
};

struct scado_source_expectation {
	enum scado_source_expectation_kind kind;
	const char *digest;
};

enum scado_destination_expectation_kind {
	SCADO_DESTINATION_ABSENT = 0,
	SCADO_DESTINATION_DIGEST,
	SCADO_DESTINATION_SOURCE_SNAPSHOT
};

struct scado_destination_expectation {
	enum scado_destination_expectation_kind kind;
	const char *digest;
};

struct scado_transaction_request {
	const char *source_path;
	const char *destination_path;
	struct scado_update_operation operation;
	struct scado_source_expectation source;
	struct scado_destination_expectation destination;
};

enum scado_file_status {
	SCADO_FILE_OK = 0,
	SCADO_FILE_INVALID_ARGUMENT,
	SCADO_FILE_OPEN_SOURCE,
	SCADO_FILE_SOURCE_STAT,
	SCADO_FILE_SOURCE_NOT_REGULAR,
	SCADO_FILE_OPEN_DIRECTORY,
	SCADO_FILE_CREATE_STAGE,
	SCADO_FILE_STAGE_GUARD,
	SCADO_FILE_SET_CLOEXEC,
	SCADO_FILE_SET_MODE,
	SCADO_FILE_HASH_INIT,
	SCADO_FILE_HASH_UPDATE,
	SCADO_FILE_PARSE,
	SCADO_FILE_READ,
	SCADO_FILE_WRITE,
	SCADO_FILE_DIGEST,
	SCADO_FILE_TARGET_MISSING,
	SCADO_FILE_TARGET_HAS_NO_DIGEST,
	SCADO_FILE_SOURCE_CHANGED,
	SCADO_FILE_SYNC_STAGE,
	SCADO_FILE_CLOSE_SOURCE,
	SCADO_FILE_CLOSE_STAGE,
	SCADO_FILE_LOCK_DIRECTORY,
	SCADO_FILE_OPEN_DESTINATION,
	SCADO_FILE_DESTINATION_CHANGED,
	SCADO_FILE_RENAME,
	SCADO_FILE_REMOVE,
	SCADO_FILE_SYNC_DIRECTORY,
	SCADO_FILE_UNLOCK_DIRECTORY,
	SCADO_FILE_CLOSE_DIRECTORY
};

struct scado_file_result {
	enum scado_file_status status;
	size_t line;
	size_t matched;
	size_t changed;
	int error_number;
	int cleanup_error;
	int committed;
};

struct scado_file_result scado_validate_file(const char *path);
struct scado_file_result scado_update_transaction(
		const struct scado_transaction_request *request);
struct scado_file_result scado_delete_transaction(const char *path);

struct scado_path_result {
	enum scado_file_status status;
	int found;
	uint64_t capabilities;
	char digest[DIGESTSTRLEN + 1];
	size_t line;
	int error_number;
	int cleanup_error;
};

struct scado_path_result scado_path_getinfo(const char *input_path,
		const char *path);
const char *scado_file_status_string(enum scado_file_status status);
void scado_report_file_failure(const struct scado_file_result *result);

#endif
