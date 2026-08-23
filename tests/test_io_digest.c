#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <compute_digest.h>
#include <file_utils.h>

static int failures;

#define CHECK(expression) do { \
	if (!(expression)) { \
		fprintf(stderr, "%s:%d: check failed: %s\n", __FILE__, __LINE__, \
				#expression); \
		failures++; \
	} \
} while (0)

static int create_file(const char *path, const void *data, size_t length)
{
	int descriptor = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
	struct cado_io_result result;

	if (descriptor < 0)
		return -1;
	result = cado_write_all(descriptor, data, length);
	if (close(descriptor) < 0 || result.status != CADO_IO_OK)
		return -1;
	return 0;
}

static void test_pipe_partial_writes(void)
{
	int pipe_descriptors[2] = {-1, -1};
	pid_t child;
	unsigned char *data = malloc(1024 * 1024);
	struct cado_io_result result;
	int status;

	CHECK(data != NULL);
	if (data == NULL)
		return;
	memset(data, 0x5a, 1024 * 1024);
	if (pipe(pipe_descriptors) < 0) {
		CHECK(0 && "pipe creation");
		free(data);
		return;
	}
	child = fork();
	if (child < 0) {
		CHECK(0 && "fork");
		close(pipe_descriptors[0]);
		close(pipe_descriptors[1]);
		free(data);
		return;
	}
	if (child == 0) {
		unsigned char buffer[127];
		size_t total = 0;
		ssize_t count;

		close(pipe_descriptors[1]);
		while ((count = read(pipe_descriptors[0], buffer, sizeof(buffer))) > 0)
			total += (size_t)count;
		close(pipe_descriptors[0]);
		_exit(total == 1024 * 1024 ? 0 : 1);
	}
	close(pipe_descriptors[0]);
	result = cado_write_all(pipe_descriptors[1], data, 1024 * 1024);
	CHECK(result.status == CADO_IO_OK);
	CHECK(result.bytes == 1024 * 1024);
	CHECK(close(pipe_descriptors[1]) == 0);
	CHECK(waitpid(child, &status, 0) == child);
	CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
	free(data);
}

static void test_descriptor_exhaustion(const char *input_path,
		const char *directory)
{
	struct rlimit original;
	struct rlimit limited;
	int descriptors[128];
	size_t count = 0;
	char output_template[256];
	char digest[DIGESTSTRLEN + 1];
	struct cado_digest_result result;
	int probe;

	if (getrlimit(RLIMIT_NOFILE, &original) < 0 || original.rlim_cur < 16)
		return;
	limited = original;
	if (limited.rlim_cur > 64)
		limited.rlim_cur = 64;
	if (setrlimit(RLIMIT_NOFILE, &limited) < 0)
		return;
	while (count < sizeof(descriptors) / sizeof(descriptors[0])) {
		int descriptor = open("/dev/null", O_RDONLY | O_CLOEXEC);

		if (descriptor < 0)
			break;
		descriptors[count++] = descriptor;
	}
	CHECK(errno == EMFILE);
	snprintf(output_template, sizeof(output_template), "%s/exhausted.XXXXXX",
			directory);
	result = copytemp_digest(input_path, output_template, 0600, digest);
	CHECK(result.status == CADO_DIGEST_OPEN_INPUT);
	CHECK(result.error_number == EMFILE);
	CHECK(count > 0);
	if (count > 0) {
		CHECK(close(descriptors[--count]) == 0);
		snprintf(output_template, sizeof(output_template),
				"%s/output-exhausted.XXXXXX", directory);
		result = copytemp_digest(input_path, output_template, 0600, digest);
		CHECK(result.status == CADO_DIGEST_CREATE_OUTPUT);
		CHECK(result.error_number == EMFILE);
		probe = open("/dev/null", O_RDONLY | O_CLOEXEC);
		CHECK(probe >= 0);
		if (probe >= 0)
			CHECK(close(probe) == 0);
	}
	while (count > 0)
		CHECK(close(descriptors[--count]) == 0);
	CHECK(setrlimit(RLIMIT_NOFILE, &original) == 0);
}

int main(void)
{
	char directory[] = "/tmp/cado-io-test.XXXXXX";
	char empty_path[256];
	char abc_path[256];
	char link_path[256];
	char fifo_path[256];
	char template_path[256];
	char digest[DIGESTSTRLEN + 1];
	struct cado_digest_result digest_result;
	struct cado_io_result io_result;
	int full;

	CHECK(mkdtemp(directory) != NULL);
	snprintf(empty_path, sizeof(empty_path), "%s/empty", directory);
	snprintf(abc_path, sizeof(abc_path), "%s/abc", directory);
	snprintf(link_path, sizeof(link_path), "%s/link", directory);
	snprintf(fifo_path, sizeof(fifo_path), "%s/fifo", directory);
	CHECK(create_file(empty_path, "", 0) == 0);
	CHECK(create_file(abc_path, "abc", 3) == 0);
	CHECK(symlink(abc_path, link_path) == 0);
	CHECK(mkfifo(fifo_path, 0600) == 0);
	digest_result = compute_digest(empty_path, digest);
	CHECK(digest_result.status == CADO_DIGEST_OK);
	CHECK(strcmp(digest,
			"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855") == 0);
	digest_result = compute_digest(abc_path, digest);
	CHECK(digest_result.status == CADO_DIGEST_OK);
	CHECK(strcmp(digest,
			"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad") == 0);

	full = open("/dev/full", O_WRONLY | O_CLOEXEC);
	CHECK(full >= 0);
	if (full >= 0) {
		io_result = cado_write_all(full, "x", 1);
		CHECK(io_result.status == CADO_IO_WRITE);
		CHECK(io_result.error_number == ENOSPC);
		CHECK(close(full) == 0);
	}

	snprintf(template_path, sizeof(template_path), "%s/digest-failed.XXXXXX",
			directory);
	digest_result = copytemp_digest("/proc/self/mem", template_path, 0600,
			digest);
	CHECK(digest_result.status == CADO_DIGEST_READ);
	CHECK(access(template_path, F_OK) < 0 && errno == ENOENT);
	snprintf(template_path, sizeof(template_path), "%s/nofollow.XXXXXX", directory);
	digest_result = copytemp_digest_nofollow_regular(link_path, template_path,
			0600, digest);
	CHECK(digest_result.status == CADO_DIGEST_OPEN_INPUT);
	CHECK(access(template_path, F_OK) < 0 && errno == ENOENT);
	snprintf(template_path, sizeof(template_path), "%s/nonregular.XXXXXX",
			directory);
	digest_result = copytemp_digest_nofollow_regular(fifo_path, template_path,
			0600, digest);
	CHECK(digest_result.status == CADO_DIGEST_INPUT_NOT_REGULAR);
	CHECK(access(template_path, F_OK) < 0 && errno == ENOENT);

	test_pipe_partial_writes();
	test_descriptor_exhaustion(abc_path, directory);
	unlink(empty_path);
	unlink(abc_path);
	unlink(link_path);
	unlink(fifo_path);
	rmdir(directory);
	return failures == 0 ? 0 : 1;
}
