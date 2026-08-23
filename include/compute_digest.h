#ifndef CADO_COMPUTE_DIGEST_H
#define CADO_COMPUTE_DIGEST_H

#include <stdint.h>
#include <sys/stat.h>

#define DIGESTLEN 32
#define DIGESTSTRLEN 64

enum cado_digest_status {
	CADO_DIGEST_OK = 0,
	CADO_DIGEST_INVALID_ARGUMENT,
	CADO_DIGEST_OPEN_INPUT,
	CADO_DIGEST_INSPECT_INPUT,
	CADO_DIGEST_INPUT_NOT_REGULAR,
	CADO_DIGEST_CREATE_OUTPUT,
	CADO_DIGEST_SET_MODE,
	CADO_DIGEST_SET_CLOEXEC,
	CADO_DIGEST_INITIALIZE,
	CADO_DIGEST_UPDATE,
	CADO_DIGEST_READ,
	CADO_DIGEST_WRITE,
	CADO_DIGEST_CLOSE_INPUT,
	CADO_DIGEST_CLOSE_OUTPUT
};

struct cado_digest_result {
	enum cado_digest_status status;
	uint64_t bytes;
	int error_number;
	int cleanup_error;
};

struct cado_digest_result compute_digest(const char *path,
		char digest[DIGESTSTRLEN + 1]);
struct cado_digest_result compute_digest_nofollow_regular(const char *path,
		char digest[DIGESTSTRLEN + 1]);
struct cado_digest_result cado_copy_digest_fd(int input, int output,
		char digest[DIGESTSTRLEN + 1]);
struct cado_digest_result copytemp_digest(const char *input_path,
		char *output_template, mode_t mode,
		char digest[DIGESTSTRLEN + 1]);
struct cado_digest_result copytemp_digest_nofollow_regular(
		const char *input_path, char *output_template, mode_t mode,
		char digest[DIGESTSTRLEN + 1]);
int cado_digest_is_valid(const char *digest);

#endif
