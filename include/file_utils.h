#ifndef CADO_FILE_UTILS_H
#define CADO_FILE_UTILS_H

#include <stddef.h>
#include <stdint.h>

enum cado_io_status {
	CADO_IO_OK = 0,
	CADO_IO_INVALID_ARGUMENT,
	CADO_IO_READ,
	CADO_IO_WRITE
};

struct cado_io_result {
	enum cado_io_status status;
	uint64_t bytes;
	int error_number;
};

struct cado_io_result cado_write_all(int descriptor, const void *buffer,
		size_t length);
struct cado_io_result cado_copy_fd(int input, int output);

#endif
