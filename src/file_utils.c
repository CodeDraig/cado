/*
 * cado: checked file-copy primitives
 * Copyright (C) 2016 Renzo Davoli, University of Bologna
 *
 * This file is part of cado and is distributed under the GNU GPL v2 or later.
 */

#include <errno.h>
#include <stdint.h>
#include <unistd.h>

#include <file_utils.h>

#define COPY_BUFFER_SIZE 16384

static struct cado_io_result io_error(enum cado_io_status status,
		uint64_t bytes, int error_number)
{
	struct cado_io_result result = {
		.status = status,
		.bytes = bytes,
		.error_number = error_number
	};

	return result;
}

struct cado_io_result cado_write_all(int descriptor, const void *buffer,
		size_t length)
{
	const unsigned char *scan = buffer;
	size_t remaining = length;
	uint64_t written = 0;

	if (descriptor < 0 || (buffer == NULL && length != 0))
		return io_error(CADO_IO_INVALID_ARGUMENT, 0, EINVAL);
	while (remaining > 0) {
		ssize_t count = write(descriptor, scan, remaining);

		if (count < 0) {
			if (errno == EINTR)
				continue;
			return io_error(CADO_IO_WRITE, written, errno);
		}
		if (count == 0)
			return io_error(CADO_IO_WRITE, written, EIO);
		scan += (size_t)count;
		remaining -= (size_t)count;
		written += (uint64_t)count;
	}
	return io_error(CADO_IO_OK, written, 0);
}

struct cado_io_result cado_copy_fd(int input, int output)
{
	unsigned char buffer[COPY_BUFFER_SIZE];
	uint64_t copied = 0;

	if (input < 0 || output < 0)
		return io_error(CADO_IO_INVALID_ARGUMENT, 0, EINVAL);
	for (;;) {
		ssize_t count = read(input, buffer, sizeof(buffer));

		if (count < 0) {
			if (errno == EINTR)
				continue;
			return io_error(CADO_IO_READ, copied, errno);
		}
		if (count == 0)
			return io_error(CADO_IO_OK, copied, 0);
		{
			struct cado_io_result write_result = cado_write_all(output,
					buffer, (size_t)count);

			if (write_result.status != CADO_IO_OK) {
				write_result.bytes += copied;
				return write_result;
			}
		}
		if (UINT64_MAX - copied < (uint64_t)count)
			return io_error(CADO_IO_READ, copied, EOVERFLOW);
		copied += (uint64_t)count;
	}
}
