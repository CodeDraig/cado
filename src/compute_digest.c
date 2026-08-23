/*
 * scado: checked SHA-256 digest and copy operations
 * Copyright (C) 2016 Davide Berardi and Renzo Davoli, University of Bologna
 *
 * This file is part of cado and is distributed under the GNU GPL v2 or later.
 */

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <mhash.h>

#include <compute_digest.h>
#include <file_utils.h>

#define DIGEST_BUFFER_SIZE 16384

static struct cado_digest_result digest_error(enum cado_digest_status status,
		uint64_t bytes, int error_number)
{
	struct cado_digest_result result = {
		.status = status,
		.bytes = bytes,
		.error_number = error_number
	};

	return result;
}

static void render_digest(const unsigned char binary[DIGESTLEN],
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

static struct cado_digest_result digest_fd(int input, int output,
		char digest[DIGESTSTRLEN + 1])
{
	unsigned char buffer[DIGEST_BUFFER_SIZE];
	unsigned char binary[DIGESTLEN];
	MHASH context;
	uint64_t bytes = 0;

	if (mhash_get_block_size(MHASH_SHA256) != DIGESTLEN)
		return digest_error(CADO_DIGEST_INITIALIZE, 0, EINVAL);
	context = mhash_init(MHASH_SHA256);
	if (context == MHASH_FAILED)
		return digest_error(CADO_DIGEST_INITIALIZE, 0, ENOMEM);

	for (;;) {
		ssize_t count = read(input, buffer, sizeof(buffer));

		if (count < 0) {
			if (errno == EINTR)
				continue;
			mhash_deinit(context, binary);
			return digest_error(CADO_DIGEST_READ, bytes, errno);
		}
		if (count == 0)
			break;
		if (mhash(context, buffer, (mutils_word32)count) != MUTILS_OK) {
			mhash_deinit(context, binary);
			return digest_error(CADO_DIGEST_UPDATE, bytes, EIO);
		}
		if (output >= 0) {
			struct cado_io_result write_result = cado_write_all(output,
					buffer, (size_t)count);

			if (write_result.status != CADO_IO_OK) {
				mhash_deinit(context, binary);
				return digest_error(CADO_DIGEST_WRITE,
						bytes + write_result.bytes,
						write_result.error_number);
			}
		}
		if (UINT64_MAX - bytes < (uint64_t)count) {
			mhash_deinit(context, binary);
			return digest_error(CADO_DIGEST_READ, bytes, EOVERFLOW);
		}
		bytes += (uint64_t)count;
	}
	mhash_deinit(context, binary);
	render_digest(binary, digest);
	return digest_error(CADO_DIGEST_OK, bytes, 0);
}

struct cado_digest_result cado_copy_digest_fd(int input, int output,
		char digest[DIGESTSTRLEN + 1])
{
	if (input < 0 || output < 0 || digest == NULL)
		return digest_error(CADO_DIGEST_INVALID_ARGUMENT, 0, EINVAL);
	return digest_fd(input, output, digest);
}

static struct cado_digest_result compute_digest_internal(const char *path,
		char digest[DIGESTSTRLEN + 1], int input_flags)
{
	struct cado_digest_result result;
	struct stat input_stat;
	int input;

	if (path == NULL || digest == NULL)
		return digest_error(CADO_DIGEST_INVALID_ARGUMENT, 0, EINVAL);
	input = open(path, O_RDONLY | O_CLOEXEC | O_NONBLOCK | input_flags);
	if (input < 0)
		return digest_error(CADO_DIGEST_OPEN_INPUT, 0, errno);
	if (fstat(input, &input_stat) < 0)
		result = digest_error(CADO_DIGEST_INSPECT_INPUT, 0, errno);
	else if (!S_ISREG(input_stat.st_mode))
		result = digest_error(CADO_DIGEST_INPUT_NOT_REGULAR, 0, EINVAL);
	else
		result = digest_fd(input, -1, digest);
	if (close(input) < 0) {
		if (result.status == CADO_DIGEST_OK) {
			result.status = CADO_DIGEST_CLOSE_INPUT;
			result.error_number = errno;
		} else {
			result.cleanup_error = errno;
		}
	}
	return result;
}

struct cado_digest_result compute_digest(const char *path,
		char digest[DIGESTSTRLEN + 1])
{
	return compute_digest_internal(path, digest, 0);
}

struct cado_digest_result compute_digest_nofollow_regular(const char *path,
		char digest[DIGESTSTRLEN + 1])
{
	return compute_digest_internal(path, digest, O_NOFOLLOW);
}

static void remove_digest_temp(const char *path,
		struct cado_digest_result *result)
{
	if (unlink(path) < 0 && errno != ENOENT) {
		if (result->cleanup_error == 0)
			result->cleanup_error = errno;
	}
}

static struct cado_digest_result copytemp_digest_internal(const char *input_path,
		char *output_template, mode_t mode,
		char digest[DIGESTSTRLEN + 1], int input_flags)
{
	struct cado_digest_result result = { .status = CADO_DIGEST_OK };
	struct stat input_stat;
	int input = -1;
	int output = -1;
	int created = 0;

	if (input_path == NULL || output_template == NULL || digest == NULL)
		return digest_error(CADO_DIGEST_INVALID_ARGUMENT, 0, EINVAL);
	input = open(input_path, O_RDONLY | O_CLOEXEC | input_flags);
	if (input < 0)
		return digest_error(CADO_DIGEST_OPEN_INPUT, 0, errno);
	if (fstat(input, &input_stat) < 0) {
		result = digest_error(CADO_DIGEST_INSPECT_INPUT, 0, errno);
		goto out;
	}
	if (!S_ISREG(input_stat.st_mode)) {
		result = digest_error(CADO_DIGEST_INPUT_NOT_REGULAR, 0, EINVAL);
		goto out;
	}
	output = mkstemp(output_template);
	if (output < 0) {
		result = digest_error(CADO_DIGEST_CREATE_OUTPUT, 0, errno);
		goto out;
	}
	created = 1;
	if (fcntl(output, F_SETFD, FD_CLOEXEC) < 0) {
		result = digest_error(CADO_DIGEST_SET_CLOEXEC, 0, errno);
		goto out;
	}
	if (fchmod(output, mode) < 0) {
		result = digest_error(CADO_DIGEST_SET_MODE, 0, errno);
		goto out;
	}
	result = digest_fd(input, output, digest);

out:
	if (close(input) < 0) {
		if (result.status == CADO_DIGEST_OK) {
			result.status = CADO_DIGEST_CLOSE_INPUT;
			result.error_number = errno;
		} else if (result.cleanup_error == 0) {
			result.cleanup_error = errno;
		}
	}
	if (output >= 0 && close(output) < 0) {
		if (result.status == CADO_DIGEST_OK) {
			result.status = CADO_DIGEST_CLOSE_OUTPUT;
			result.error_number = errno;
		} else if (result.cleanup_error == 0) {
			result.cleanup_error = errno;
		}
	}
	if (created && result.status != CADO_DIGEST_OK)
		remove_digest_temp(output_template, &result);
	return result;
}

struct cado_digest_result copytemp_digest(const char *input_path,
		char *output_template, mode_t mode,
		char digest[DIGESTSTRLEN + 1])
{
	return copytemp_digest_internal(input_path, output_template, mode, digest,
			O_NONBLOCK);
}

struct cado_digest_result copytemp_digest_nofollow_regular(
		const char *input_path, char *output_template, mode_t mode,
		char digest[DIGESTSTRLEN + 1])
{
	return copytemp_digest_internal(input_path, output_template, mode, digest,
			O_NOFOLLOW | O_NONBLOCK);
}

int cado_digest_is_valid(const char *digest)
{
	size_t i;

	if (digest == NULL || strlen(digest) != DIGESTSTRLEN)
		return 0;
	for (i = 0; i < DIGESTSTRLEN; i++) {
		if (!isxdigit((unsigned char)digest[i]))
			return 0;
	}
	return 1;
}
