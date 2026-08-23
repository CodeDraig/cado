/*
 * cado: strict scado parsing and transactional updates
 * Copyright (C) 2016 Renzo Davoli and Davide Berardi, University of Bologna
 *
 * This file is part of cado and is distributed under the GNU GPL v2 or later.
 */

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/file.h>
#include <sys/stat.h>

#include <mhash.h>

#include <capset_from_namelist.h>
#include <compute_digest.h>
#include <file_utils.h>
#include <scado_parse.h>
#include <scado_temp_guard.h>

static struct scado_span trim_span(const char *data, size_t length)
{
	struct scado_span span = { .data = data, .length = length };

	while (span.length > 0 && isspace((unsigned char)*span.data)) {
		span.data++;
		span.length--;
	}
	while (span.length > 0 &&
			isspace((unsigned char)span.data[span.length - 1]))
		span.length--;
	return span;
}

static int span_equal_string(struct scado_span span, const char *string)
{
	return string != NULL && strlen(string) == span.length &&
		memcmp(span.data, string, span.length) == 0;
}

static char *span_string(struct scado_span span)
{
	char *string = malloc(span.length + 1);

	if (string == NULL)
		return NULL;
	memcpy(string, span.data, span.length);
	string[span.length] = '\0';
	return string;
}

enum scado_parse_status scado_parse_line(const char *line, size_t length,
		int allow_empty_digest, struct scado_line *parsed)
{
	const char *comment;
	size_t grammar_length;
	struct scado_span grammar;
	size_t colons[3];
	size_t colon_count = 0;
	size_t i;
	char *capabilities;
	enum cado_cap_parse_status cap_status;

	if (line == NULL || parsed == NULL)
		return SCADO_PARSE_FIELD_COUNT;
	memset(parsed, 0, sizeof(*parsed));
	if (memchr(line, '\0', length) != NULL)
		return SCADO_PARSE_EMBEDDED_NUL;
	if (length > 0 && line[length - 1] == '\n')
		length--;
	comment = memchr(line, '#', length);
	grammar_length = comment == NULL ? length : (size_t)(comment - line);
	grammar = trim_span(line, grammar_length);
	if (grammar.length == 0) {
		parsed->kind = comment == NULL ? SCADO_LINE_BLANK : SCADO_LINE_COMMENT;
		return SCADO_PARSE_OK;
	}

	for (i = 0; i < grammar_length; i++) {
		if (line[i] == ':') {
			if (colon_count == 3)
				return SCADO_PARSE_FIELD_COUNT;
			colons[colon_count++] = i;
		}
	}
	if (colon_count != 1 && colon_count != 2)
		return SCADO_PARSE_FIELD_COUNT;

	parsed->kind = SCADO_LINE_ENTRY;
	parsed->path = trim_span(line, colons[0]);
	parsed->capabilities = trim_span(line + colons[0] + 1,
			(colon_count == 2 ? colons[1] : grammar_length) - colons[0] - 1);
	parsed->has_digest = colon_count == 2;
	if (parsed->has_digest)
		parsed->digest = trim_span(line + colons[1] + 1,
				grammar_length - colons[1] - 1);

	if (parsed->path.length == 0)
		return SCADO_PARSE_PATH_MISSING;
	if (parsed->path.data[0] != '/')
		return SCADO_PARSE_PATH_NOT_ABSOLUTE;
	capabilities = span_string(parsed->capabilities);
	if (capabilities == NULL)
		return SCADO_PARSE_NO_MEMORY;
	cap_status = capset_from_namelist(capabilities, &parsed->capability_set);
	free(capabilities);
	if (cap_status != CADO_CAP_PARSE_OK)
		return cap_status == CADO_CAP_PARSE_NO_MEMORY ? SCADO_PARSE_NO_MEMORY :
				SCADO_PARSE_CAPABILITIES;

	if (parsed->has_digest) {
		if (parsed->digest.length == 0)
			return allow_empty_digest ? SCADO_PARSE_OK :
					SCADO_PARSE_DIGEST_EMPTY;
		if (parsed->digest.length != DIGESTSTRLEN)
			return SCADO_PARSE_DIGEST_INVALID;
		for (i = 0; i < parsed->digest.length; i++) {
			if (!isxdigit((unsigned char)parsed->digest.data[i]))
				return SCADO_PARSE_DIGEST_INVALID;
		}
	}
	return SCADO_PARSE_OK;
}

const char *scado_parse_status_string(enum scado_parse_status status)
{
	switch (status) {
	case SCADO_PARSE_OK:
		return "valid scado line";
	case SCADO_PARSE_EMBEDDED_NUL:
		return "embedded NUL byte";
	case SCADO_PARSE_FIELD_COUNT:
		return "expected exactly two or three colon-delimited fields";
	case SCADO_PARSE_PATH_MISSING:
		return "missing executable path";
	case SCADO_PARSE_PATH_NOT_ABSOLUTE:
		return "executable path is not absolute";
	case SCADO_PARSE_CAPABILITIES:
		return "invalid capability list";
	case SCADO_PARSE_DIGEST_EMPTY:
		return "empty persisted digest";
	case SCADO_PARSE_DIGEST_INVALID:
		return "digest must be exactly 64 hexadecimal characters";
	case SCADO_PARSE_NO_MEMORY:
		return "out of memory while parsing scado line";
	}
	return "unknown scado parse error";
}

static void render_binary_digest(const unsigned char binary[DIGESTLEN],
		char ascii[DIGESTSTRLEN + 1])
{
	static const char digits[] = "0123456789abcdef";
	int i;

	for (i = 0; i < DIGESTLEN; i++) {
		ascii[i * 2] = digits[binary[i] >> 4];
		ascii[i * 2 + 1] = digits[binary[i] & 0x0f];
	}
	ascii[DIGESTSTRLEN] = '\0';
}

static int hash_bytes(MHASH hash, const unsigned char *data, size_t length)
{
	while (length > 0) {
		mutils_word32 chunk = length > UINT32_MAX ? UINT32_MAX :
				(mutils_word32)length;

		if (mhash(hash, data, chunk) != MUTILS_OK)
			return -1;
		data += chunk;
		length -= chunk;
	}
	return 0;
}

static enum scado_file_status write_piece(int output, const void *data,
		size_t length, int *error_number)
{
	struct cado_io_result write_result = cado_write_all(output, data, length);

	if (write_result.status == CADO_IO_OK)
		return SCADO_FILE_OK;
	*error_number = write_result.error_number;
	return SCADO_FILE_WRITE;
}

static enum scado_file_status write_updated_line(int output, const char *line,
		size_t length, const struct scado_line *parsed, const char *digest,
		int *error_number)
{
	size_t prefix = (size_t)(parsed->digest.data - line);
	size_t suffix = prefix + parsed->digest.length;
	enum scado_file_status status;

	status = write_piece(output, line, prefix, error_number);
	if (status != SCADO_FILE_OK)
		return status;
	status = write_piece(output, digest, DIGESTSTRLEN, error_number);
	if (status != SCADO_FILE_OK)
		return status;
	return write_piece(output, line + suffix, length - suffix, error_number);
}

static enum scado_file_status update_line(int output, const char *line,
		size_t length, const struct scado_line *parsed,
		const struct scado_update_operation *operation,
		struct scado_file_result *result)
{
	int update_digest = 0;
	char digest[DIGESTSTRLEN + 1];
	char *path;
	struct cado_digest_result digest_result;

	if (parsed->kind != SCADO_LINE_ENTRY)
		return write_piece(output, line, length, &result->error_number);

	switch (operation->kind) {
	case SCADO_ADD_MISSING:
		update_digest = parsed->has_digest && parsed->digest.length == 0;
		break;
	case SCADO_UPDATE_ALL:
		update_digest = parsed->has_digest;
		break;
	case SCADO_UPDATE_PATH:
		if (span_equal_string(parsed->path, operation->path)) {
			result->matched++;
			if (!parsed->has_digest) {
				result->error_number = EINVAL;
				return SCADO_FILE_TARGET_HAS_NO_DIGEST;
			}
			update_digest = 1;
		}
		break;
	}
	if (!update_digest)
		return write_piece(output, line, length, &result->error_number);

	path = span_string(parsed->path);
	if (path == NULL) {
		result->error_number = ENOMEM;
		return SCADO_FILE_DIGEST;
	}
	digest_result = compute_digest(path, digest);
	free(path);
	if (digest_result.status != CADO_DIGEST_OK) {
		result->error_number = digest_result.error_number;
		return SCADO_FILE_DIGEST;
	}
	result->changed++;
	return write_updated_line(output, line, length, parsed, digest,
			&result->error_number);
}

static int destination_directory(const char *destination, char output[PATH_MAX])
{
	const char *slash = strrchr(destination, '/');
	size_t length;

	if (slash == NULL) {
		output[0] = '.';
		output[1] = '\0';
		return 0;
	}
	length = slash == destination ? 1 : (size_t)(slash - destination);
	if (length >= PATH_MAX) {
		errno = ENAMETOOLONG;
		return -1;
	}
	memcpy(output, destination, length);
	output[length] = '\0';
	return 0;
}

static void cleanup_stage(const char *stage, struct scado_file_result *result)
{
	if (*stage != '\0' && unlink(stage) < 0 && errno != ENOENT) {
		if (result->cleanup_error == 0)
			result->cleanup_error = errno;
	}
}

static enum scado_file_status check_destination(
		const struct scado_transaction_request *request,
		const char source_digest[DIGESTSTRLEN + 1], int *error_number)
{
	struct stat destination_stat;
	struct cado_digest_result digest_result;
	char destination_digest[DIGESTSTRLEN + 1];
	const char *expected_digest;

	if (request->destination.kind == SCADO_DESTINATION_ABSENT) {
		if (lstat(request->destination_path, &destination_stat) < 0) {
			if (errno == ENOENT)
				return SCADO_FILE_OK;
			*error_number = errno;
			return SCADO_FILE_OPEN_DESTINATION;
		}
		*error_number = ESTALE;
		return SCADO_FILE_DESTINATION_CHANGED;
	}

	expected_digest = request->destination.kind ==
			SCADO_DESTINATION_SOURCE_SNAPSHOT ? source_digest :
			request->destination.digest;
	digest_result = compute_digest_nofollow_regular(request->destination_path,
			destination_digest);
	if (digest_result.status != CADO_DIGEST_OK) {
		if ((digest_result.status == CADO_DIGEST_OPEN_INPUT &&
				(digest_result.error_number == ENOENT ||
				digest_result.error_number == ELOOP)) ||
				digest_result.status == CADO_DIGEST_INPUT_NOT_REGULAR) {
			*error_number = ESTALE;
			return SCADO_FILE_DESTINATION_CHANGED;
		}
		*error_number = digest_result.error_number != 0 ?
				digest_result.error_number : EIO;
		return SCADO_FILE_OPEN_DESTINATION;
	}
	if (strcasecmp(destination_digest, expected_digest) != 0) {
		*error_number = ESTALE;
		return SCADO_FILE_DESTINATION_CHANGED;
	}
	return SCADO_FILE_OK;
}

struct scado_file_result scado_update_transaction(
		const struct scado_transaction_request *request)
{
	struct scado_file_result result = { .status = SCADO_FILE_OK };
	const char *source_path;
	const char *destination_path;
	const struct scado_update_operation *operation;
	char directory[PATH_MAX];
	char stage[PATH_MAX] = "";
	int directory_fd = -1;
	int source_fd = -1;
	int stage_fd = -1;
	FILE *source = NULL;
	struct stat source_stat;
	char *line = NULL;
	size_t capacity = 0;
	ssize_t length;
	size_t line_number = 0;
	MHASH source_hash = MHASH_FAILED;
	unsigned char binary_digest[DIGESTLEN];
	char source_digest[DIGESTSTRLEN + 1];
	struct scado_temp_guard stage_guard;
	int source_hash_finished = 0;
	int stage_created = 0;
	int stage_guard_started = 0;
	int directory_locked = 0;
	int rendered;

	if (request == NULL) {
		result.status = SCADO_FILE_INVALID_ARGUMENT;
		result.error_number = EINVAL;
		return result;
	}
	source_path = request->source_path;
	destination_path = request->destination_path;
	operation = &request->operation;
	if (source_path == NULL || destination_path == NULL ||
			operation->kind < SCADO_ADD_MISSING ||
			operation->kind > SCADO_UPDATE_PATH ||
			(operation->kind == SCADO_UPDATE_PATH &&
			(operation->path == NULL || operation->path[0] != '/')) ||
			request->source.kind < SCADO_SOURCE_CURRENT ||
			request->source.kind > SCADO_SOURCE_DIGEST ||
			request->destination.kind < SCADO_DESTINATION_ABSENT ||
			request->destination.kind > SCADO_DESTINATION_SOURCE_SNAPSHOT) {
		result.status = SCADO_FILE_INVALID_ARGUMENT;
		result.error_number = EINVAL;
		return result;
	}
	if ((request->source.kind == SCADO_SOURCE_DIGEST &&
			!cado_digest_is_valid(request->source.digest)) ||
			(request->destination.kind == SCADO_DESTINATION_DIGEST &&
			!cado_digest_is_valid(request->destination.digest))) {
		result.status = SCADO_FILE_INVALID_ARGUMENT;
		result.error_number = EINVAL;
		return result;
	}
	if (destination_directory(destination_path, directory) < 0) {
		result.status = SCADO_FILE_OPEN_DIRECTORY;
		result.error_number = errno;
		return result;
	}
	if (scado_temp_guard_start(&stage_guard, directory,
			".cado-stage.XXXXXX") < 0) {
		result.status = SCADO_FILE_STAGE_GUARD;
		result.error_number = errno;
		return result;
	}
	stage_guard_started = 1;
	directory_fd = open(directory, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	if (directory_fd < 0) {
		result.status = SCADO_FILE_OPEN_DIRECTORY;
		result.error_number = errno;
		goto out;
	}
	stage_fd = mkstemp(scado_temp_guard_path(&stage_guard));
	if (stage_fd < 0) {
		result.status = SCADO_FILE_CREATE_STAGE;
		result.error_number = errno;
		goto out;
	}
	stage_created = 1;
	rendered = snprintf(stage, sizeof(stage), "%s",
			scado_temp_guard_path(&stage_guard));
	if (rendered < 0 || (size_t)rendered >= sizeof(stage)) {
		result.status = SCADO_FILE_CREATE_STAGE;
		result.error_number = ENAMETOOLONG;
		goto out;
	}
	if (fcntl(stage_fd, F_SETFD, FD_CLOEXEC) < 0) {
		result.status = SCADO_FILE_SET_CLOEXEC;
		result.error_number = errno;
		goto out;
	}
	if (fchmod(stage_fd, 0600) < 0) {
		result.status = SCADO_FILE_SET_MODE;
		result.error_number = errno;
		goto out;
	}

	source_fd = open(source_path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
	if (source_fd < 0) {
		result.status = SCADO_FILE_OPEN_SOURCE;
		result.error_number = errno;
		goto out;
	}
	if (fstat(source_fd, &source_stat) < 0) {
		result.status = SCADO_FILE_SOURCE_STAT;
		result.error_number = errno;
		goto out;
	}
	if (!S_ISREG(source_stat.st_mode)) {
		result.status = SCADO_FILE_SOURCE_NOT_REGULAR;
		result.error_number = EINVAL;
		goto out;
	}
	source = fdopen(source_fd, "r");
	if (source == NULL) {
		result.status = SCADO_FILE_OPEN_SOURCE;
		result.error_number = errno;
		goto out;
	}
	source_fd = -1;

	if (mhash_get_block_size(MHASH_SHA256) != DIGESTLEN) {
		result.status = SCADO_FILE_HASH_INIT;
		result.error_number = EINVAL;
		goto out;
	}
	source_hash = mhash_init(MHASH_SHA256);
	if (source_hash == MHASH_FAILED) {
		result.status = SCADO_FILE_HASH_INIT;
		result.error_number = ENOMEM;
		goto out;
	}
	while ((length = getline(&line, &capacity, source)) >= 0) {
		struct scado_line parsed;
		enum scado_parse_status parse_status;

		line_number++;
		if (hash_bytes(source_hash, (const unsigned char *)line,
				(size_t)length) < 0) {
			result.status = SCADO_FILE_HASH_UPDATE;
			result.error_number = EIO;
			goto out;
		}
		parse_status = scado_parse_line(line, (size_t)length,
				operation->kind == SCADO_ADD_MISSING, &parsed);
		if (parse_status != SCADO_PARSE_OK) {
			fprintf(stderr, "%s:%zu: %s\n", source_path, line_number,
					scado_parse_status_string(parse_status));
			result.status = SCADO_FILE_PARSE;
			result.error_number = EINVAL;
			result.line = line_number;
			goto out;
		}
		result.status = update_line(stage_fd, line, (size_t)length, &parsed,
				operation, &result);
		if (result.status != SCADO_FILE_OK) {
			result.line = line_number;
			goto out;
		}
	}
	if (ferror(source)) {
		result.status = SCADO_FILE_READ;
		result.error_number = errno != 0 ? errno : EIO;
		result.line = line_number + 1;
		goto out;
	}
	if (operation->kind == SCADO_UPDATE_PATH && result.matched == 0) {
		result.status = SCADO_FILE_TARGET_MISSING;
		result.error_number = ENOENT;
		goto out;
	}
	mhash_deinit(source_hash, binary_digest);
	source_hash_finished = 1;
	render_binary_digest(binary_digest, source_digest);
	if (request->source.kind == SCADO_SOURCE_DIGEST &&
			strcasecmp(source_digest, request->source.digest) != 0) {
		result.status = SCADO_FILE_SOURCE_CHANGED;
		result.error_number = ESTALE;
		goto out;
	}
	if (fsync(stage_fd) < 0) {
		result.status = SCADO_FILE_SYNC_STAGE;
		result.error_number = errno;
		goto out;
	}
	if (fclose(source) != 0) {
		source = NULL;
		result.status = SCADO_FILE_CLOSE_SOURCE;
		result.error_number = errno;
		goto out;
	}
	source = NULL;
	if (close(stage_fd) < 0) {
		stage_fd = -1;
		result.status = SCADO_FILE_CLOSE_STAGE;
		result.error_number = errno;
		goto out;
	}
	stage_fd = -1;
	if (flock(directory_fd, LOCK_EX) < 0) {
		result.status = SCADO_FILE_LOCK_DIRECTORY;
		result.error_number = errno;
		goto out;
	}
	directory_locked = 1;
	result.status = check_destination(request, source_digest,
			&result.error_number);
	if (result.status != SCADO_FILE_OK)
		goto out;
	if (rename(stage, destination_path) < 0) {
		result.status = SCADO_FILE_RENAME;
		result.error_number = errno;
		goto out;
	}
	stage_created = 0;
	result.committed = 1;
	if (fsync(directory_fd) < 0) {
		result.status = SCADO_FILE_SYNC_DIRECTORY;
		result.error_number = errno;
		goto out;
	}
	if (flock(directory_fd, LOCK_UN) < 0) {
		result.status = SCADO_FILE_UNLOCK_DIRECTORY;
		result.error_number = errno;
		goto out;
	}
	directory_locked = 0;

out:
	if (directory_locked && flock(directory_fd, LOCK_UN) < 0) {
		if (result.status == SCADO_FILE_OK) {
			result.status = SCADO_FILE_UNLOCK_DIRECTORY;
			result.error_number = errno;
		} else if (result.cleanup_error == 0) {
			result.cleanup_error = errno;
		}
	}
	if (source_hash != MHASH_FAILED && !source_hash_finished)
		mhash_deinit(source_hash, binary_digest);
	free(line);
	if (source != NULL && fclose(source) != 0) {
		if (result.status == SCADO_FILE_OK) {
			result.status = SCADO_FILE_CLOSE_SOURCE;
			result.error_number = errno;
		} else if (result.cleanup_error == 0) {
			result.cleanup_error = errno;
		}
	}
	if (source_fd >= 0 && close(source_fd) < 0) {
		if (result.status == SCADO_FILE_OK) {
			result.status = SCADO_FILE_CLOSE_SOURCE;
			result.error_number = errno;
		} else if (result.cleanup_error == 0) {
			result.cleanup_error = errno;
		}
	}
	if (stage_fd >= 0 && close(stage_fd) < 0) {
		if (result.status == SCADO_FILE_OK) {
			result.status = SCADO_FILE_CLOSE_STAGE;
			result.error_number = errno;
		} else if (result.cleanup_error == 0) {
			result.cleanup_error = errno;
		}
	}
	if (stage_guard_started) {
		enum scado_temp_disposition disposition = result.committed ?
				SCADO_TEMP_TRANSFER : SCADO_TEMP_DISCARD;

		if (scado_temp_guard_finish(&stage_guard, disposition) < 0) {
			if (result.status == SCADO_FILE_OK) {
				result.status = SCADO_FILE_STAGE_GUARD;
				result.error_number = errno;
			} else if (result.cleanup_error == 0) {
				result.cleanup_error = errno;
			}
		} else if (!result.committed) {
			stage_created = 0;
		}
	}
	if (stage_created)
		cleanup_stage(stage, &result);
	if (directory_fd >= 0 && close(directory_fd) < 0) {
		if (result.status == SCADO_FILE_OK) {
			result.status = SCADO_FILE_CLOSE_DIRECTORY;
			result.error_number = errno;
		} else if (result.cleanup_error == 0) {
			result.cleanup_error = errno;
		}
	}
	return result;
}

struct scado_file_result scado_validate_file(const char *path)
{
	struct scado_file_result result = { .status = SCADO_FILE_OK };
	int descriptor = -1;
	struct stat stats;
	FILE *input = NULL;
	char *line = NULL;
	size_t capacity = 0;
	ssize_t length;
	size_t line_number = 0;

	if (path == NULL) {
		result.status = SCADO_FILE_INVALID_ARGUMENT;
		result.error_number = EINVAL;
		return result;
	}
	descriptor = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
	if (descriptor < 0) {
		result.status = SCADO_FILE_OPEN_SOURCE;
		result.error_number = errno;
		return result;
	}
	if (fstat(descriptor, &stats) < 0) {
		result.status = SCADO_FILE_SOURCE_STAT;
		result.error_number = errno;
		goto out;
	}
	if (!S_ISREG(stats.st_mode)) {
		result.status = SCADO_FILE_SOURCE_NOT_REGULAR;
		result.error_number = EINVAL;
		goto out;
	}
	input = fdopen(descriptor, "r");
	if (input == NULL) {
		result.status = SCADO_FILE_OPEN_SOURCE;
		result.error_number = errno;
		goto out;
	}
	descriptor = -1;
	while ((length = getline(&line, &capacity, input)) >= 0) {
		struct scado_line parsed;
		enum scado_parse_status parse_status;

		line_number++;
		parse_status = scado_parse_line(line, (size_t)length, 0, &parsed);
		if (parse_status != SCADO_PARSE_OK) {
			fprintf(stderr, "%s:%zu: %s\n", path, line_number,
					scado_parse_status_string(parse_status));
			result.status = SCADO_FILE_PARSE;
			result.error_number = EINVAL;
			result.line = line_number;
			goto out;
		}
	}
	if (ferror(input)) {
		result.status = SCADO_FILE_READ;
		result.error_number = errno != 0 ? errno : EIO;
		result.line = line_number + 1;
	}

out:
	free(line);
	if (input != NULL && fclose(input) != 0) {
		if (result.status == SCADO_FILE_OK) {
			result.status = SCADO_FILE_CLOSE_SOURCE;
			result.error_number = errno;
		} else if (result.cleanup_error == 0) {
			result.cleanup_error = errno;
		}
	}
	if (descriptor >= 0 && close(descriptor) < 0) {
		if (result.status == SCADO_FILE_OK) {
			result.status = SCADO_FILE_CLOSE_SOURCE;
			result.error_number = errno;
		} else if (result.cleanup_error == 0) {
			result.cleanup_error = errno;
		}
	}
	return result;
}

struct scado_file_result scado_delete_transaction(const char *path)
{
	struct scado_file_result result = { .status = SCADO_FILE_OK };
	char directory[PATH_MAX];
	int directory_fd = -1;
	int directory_locked = 0;

	if (path == NULL) {
		result.status = SCADO_FILE_INVALID_ARGUMENT;
		result.error_number = EINVAL;
		return result;
	}
	if (destination_directory(path, directory) < 0) {
		result.status = SCADO_FILE_OPEN_DIRECTORY;
		result.error_number = errno;
		return result;
	}
	directory_fd = open(directory, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	if (directory_fd < 0) {
		result.status = SCADO_FILE_OPEN_DIRECTORY;
		result.error_number = errno;
		return result;
	}
	if (flock(directory_fd, LOCK_EX) < 0) {
		result.status = SCADO_FILE_LOCK_DIRECTORY;
		result.error_number = errno;
		goto out;
	}
	directory_locked = 1;
	if (unlink(path) < 0) {
		result.status = SCADO_FILE_REMOVE;
		result.error_number = errno;
		goto out;
	}
	result.committed = 1;
	if (fsync(directory_fd) < 0) {
		result.status = SCADO_FILE_SYNC_DIRECTORY;
		result.error_number = errno;
		goto out;
	}
	if (flock(directory_fd, LOCK_UN) < 0) {
		result.status = SCADO_FILE_UNLOCK_DIRECTORY;
		result.error_number = errno;
		goto out;
	}
	directory_locked = 0;

out:
	if (directory_locked && flock(directory_fd, LOCK_UN) < 0) {
		if (result.status == SCADO_FILE_OK) {
			result.status = SCADO_FILE_UNLOCK_DIRECTORY;
			result.error_number = errno;
		} else if (result.cleanup_error == 0) {
			result.cleanup_error = errno;
		}
	}
	if (close(directory_fd) < 0) {
		if (result.status == SCADO_FILE_OK) {
			result.status = SCADO_FILE_CLOSE_DIRECTORY;
			result.error_number = errno;
		} else if (result.cleanup_error == 0) {
			result.cleanup_error = errno;
		}
	}
	return result;
}

struct scado_path_result scado_path_getinfo(const char *input_path,
		const char *path)
{
	struct scado_path_result result = { .status = SCADO_FILE_OK };
	int descriptor;
	struct stat stats;
	FILE *input = NULL;
	char *line = NULL;
	size_t capacity = 0;
	ssize_t length;
	size_t line_number = 0;

	if (input_path == NULL || path == NULL || path[0] != '/') {
		result.status = SCADO_FILE_INVALID_ARGUMENT;
		result.error_number = EINVAL;
		return result;
	}
	descriptor = open(input_path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
	if (descriptor < 0) {
		result.status = SCADO_FILE_OPEN_SOURCE;
		result.error_number = errno;
		return result;
	}
	if (fstat(descriptor, &stats) < 0) {
		result.status = SCADO_FILE_SOURCE_STAT;
		result.error_number = errno;
		if (close(descriptor) < 0)
			result.cleanup_error = errno;
		return result;
	}
	if (!S_ISREG(stats.st_mode)) {
		result.status = SCADO_FILE_SOURCE_NOT_REGULAR;
		result.error_number = EINVAL;
		if (close(descriptor) < 0)
			result.cleanup_error = errno;
		return result;
	}
	input = fdopen(descriptor, "r");
	if (input == NULL) {
		result.status = SCADO_FILE_OPEN_SOURCE;
		result.error_number = errno;
		if (close(descriptor) < 0)
			result.cleanup_error = errno;
		return result;
	}
	while ((length = getline(&line, &capacity, input)) >= 0) {
		struct scado_line parsed;
		enum scado_parse_status parse_status;

		line_number++;
		parse_status = scado_parse_line(line, (size_t)length, 0, &parsed);
		if (parse_status != SCADO_PARSE_OK) {
			fprintf(stderr, "%s:%zu: %s\n", input_path, line_number,
					scado_parse_status_string(parse_status));
			result.status = SCADO_FILE_PARSE;
			result.error_number = EINVAL;
			result.line = line_number;
			result.found = 0;
			goto out;
		}
		if (!result.found && parsed.kind == SCADO_LINE_ENTRY &&
				span_equal_string(parsed.path, path)) {
			size_t i;

			result.found = 1;
			result.line = line_number;
			result.capabilities = parsed.capability_set;
			if (parsed.has_digest) {
				for (i = 0; i < parsed.digest.length; i++)
					result.digest[i] = (char)tolower(
							(unsigned char)parsed.digest.data[i]);
				result.digest[parsed.digest.length] = '\0';
			}
		}
	}
	if (ferror(input)) {
		result.status = SCADO_FILE_READ;
		result.error_number = errno != 0 ? errno : EIO;
		result.found = 0;
	}

out:
	free(line);
	if (fclose(input) != 0) {
		if (result.status == SCADO_FILE_OK) {
			result.status = SCADO_FILE_CLOSE_SOURCE;
			result.error_number = errno;
			result.found = 0;
		} else if (result.cleanup_error == 0) {
			result.cleanup_error = errno;
		}
	}
	return result;
}

const char *scado_file_status_string(enum scado_file_status status)
{
	switch (status) {
	case SCADO_FILE_OK: return "scado operation succeeded";
	case SCADO_FILE_INVALID_ARGUMENT: return "invalid scado operation";
	case SCADO_FILE_OPEN_SOURCE: return "cannot open scado source";
	case SCADO_FILE_SOURCE_STAT: return "cannot inspect scado source";
	case SCADO_FILE_SOURCE_NOT_REGULAR: return "scado source is not a regular file";
	case SCADO_FILE_OPEN_DIRECTORY: return "cannot open scado spool directory";
	case SCADO_FILE_CREATE_STAGE: return "cannot create scado staging file";
	case SCADO_FILE_STAGE_GUARD: return "cannot manage scado staging cleanup";
	case SCADO_FILE_SET_CLOEXEC: return "cannot set staging close-on-exec";
	case SCADO_FILE_SET_MODE: return "cannot set staging mode";
	case SCADO_FILE_HASH_INIT: return "cannot initialize source hash";
	case SCADO_FILE_HASH_UPDATE: return "cannot update source hash";
	case SCADO_FILE_PARSE: return "invalid scado syntax";
	case SCADO_FILE_READ: return "cannot read scado source";
	case SCADO_FILE_WRITE: return "cannot write scado staging file";
	case SCADO_FILE_DIGEST: return "cannot compute executable digest";
	case SCADO_FILE_TARGET_MISSING: return "requested update path was not found";
	case SCADO_FILE_TARGET_HAS_NO_DIGEST: return "requested update path has no digest field";
	case SCADO_FILE_SOURCE_CHANGED: return "edited input changed after authentication";
	case SCADO_FILE_SYNC_STAGE: return "cannot sync scado staging file";
	case SCADO_FILE_CLOSE_SOURCE: return "cannot close scado source";
	case SCADO_FILE_CLOSE_STAGE: return "cannot close scado staging file";
	case SCADO_FILE_LOCK_DIRECTORY: return "cannot lock scado spool directory";
	case SCADO_FILE_OPEN_DESTINATION: return "cannot inspect protected scado file";
	case SCADO_FILE_DESTINATION_CHANGED: return "protected scado file changed during the operation";
	case SCADO_FILE_RENAME: return "cannot install scado staging file";
	case SCADO_FILE_REMOVE: return "cannot remove protected scado file";
	case SCADO_FILE_SYNC_DIRECTORY: return "cannot sync scado spool directory";
	case SCADO_FILE_UNLOCK_DIRECTORY: return "cannot unlock scado spool directory";
	case SCADO_FILE_CLOSE_DIRECTORY: return "cannot close scado spool directory";
	}
	return "unknown scado file error";
}

void scado_report_file_failure(const struct scado_file_result *result)
{
	if (result == NULL)
		return;
	fprintf(stderr, "scado: %s", scado_file_status_string(result->status));
	if (result->line != 0)
		fprintf(stderr, " at line %zu", result->line);
	if (result->error_number != 0)
		fprintf(stderr, ": %s", strerror(result->error_number));
	fputc('\n', stderr);
	if (result->cleanup_error != 0)
		fprintf(stderr, "scado: cleanup also failed: %s\n",
				strerror(result->cleanup_error));
	if (result->committed)
		fprintf(stderr,
				"scado: the protected file changed before the later failure\n");
}
