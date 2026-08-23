#include <dirent.h>
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

#include <cado_scado_check.h>
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

static int find_copy(const char *directory, char path[PATH_MAX], off_t minimum)
{
	DIR *stream = opendir(directory);
	struct dirent *entry;
	struct stat stats;
	int found = 0;

	if (stream == NULL)
		return -1;
	while ((entry = readdir(stream)) != NULL) {
		if (strncmp(entry->d_name, "cado-exe-copy.", 14) != 0)
			continue;
		if (snprintf(path, PATH_MAX, "%s/%s", directory, entry->d_name) >=
				PATH_MAX || stat(path, &stats) < 0) {
			closedir(stream);
			return -1;
		}
		if (stats.st_size < minimum)
			continue;
		if (found) {
			closedir(stream);
			errno = EEXIST;
			return -1;
		}
		found = 1;
	}
	if (closedir(stream) < 0)
		return -1;
	return found;
}

int main(void)
{
	char directory[] = "/tmp/cado-verified-test.XXXXXX";
	char source[PATH_MAX];
	char sparse[PATH_MAX];
	char copy_path[PATH_MAX];
	char digest[DIGESTSTRLEN + 1];
	char wrong[DIGESTSTRLEN + 1];
	int source_fd;
	int sparse_fd;
	struct cado_io_result write_result;
	struct cado_digest_result digest_result;
	struct cado_verified_executable handle;
	struct cado_scado_result result;
	struct stat stats;
	int flags;
	int attempts;
	pid_t child;
	int status;

	CHECK(mkdtemp(directory) != NULL);
	CHECK(snprintf(source, sizeof(source), "%s/source", directory) <
			(int)sizeof(source));
	CHECK(snprintf(sparse, sizeof(sparse), "%s/sparse", directory) <
			(int)sizeof(sparse));
	source_fd = open(source, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
	CHECK(source_fd >= 0);
	write_result = cado_write_all(source_fd, "verified executable\n", 20);
	CHECK(write_result.status == CADO_IO_OK);
	CHECK(close(source_fd) == 0);
	digest_result = compute_digest(source, digest);
	CHECK(digest_result.status == CADO_DIGEST_OK);

	result = cado_verified_executable_create(source, digest, directory, &handle);
	CHECK(result.status == CADO_SCADO_OK);
	CHECK(handle.path[0] != '\0' && handle.cleanup_fd >= 0);
	strncpy(copy_path, handle.path, sizeof(copy_path));
	copy_path[sizeof(copy_path) - 1] = '\0';
	CHECK(stat(copy_path, &stats) == 0);
	CHECK((stats.st_mode & 0777) == 0611);
	flags = fcntl(handle.cleanup_fd, F_GETFD);
	CHECK(flags >= 0 && (flags & FD_CLOEXEC) != 0);
	CHECK(cado_verified_executable_release(&handle) == 0);
	for (attempts = 0; attempts < 200 && access(copy_path, F_OK) == 0;
			attempts++)
		usleep(5000);
	CHECK(access(copy_path, F_OK) < 0 && errno == ENOENT);

	memset(wrong, '0', DIGESTSTRLEN);
	wrong[DIGESTSTRLEN] = '\0';
	result = cado_verified_executable_create(source, wrong, directory, &handle);
	CHECK(result.status == CADO_SCADO_DIGEST_MISMATCH);
	CHECK(handle.path[0] == '\0' && handle.cleanup_fd < 0);
	CHECK(find_copy(directory, copy_path, 0) == 0);
	result = cado_verified_executable_create("/not/present", digest, directory,
			&handle);
	CHECK(result.status == CADO_SCADO_COPY_ERROR);
	CHECK(handle.path[0] == '\0' && handle.cleanup_fd < 0);

	sparse_fd = open(sparse, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
	CHECK(sparse_fd >= 0);
	CHECK(ftruncate(sparse_fd, (off_t)1 << 40) == 0);
	CHECK(close(sparse_fd) == 0);
	child = fork();
	CHECK(child >= 0);
	if (child == 0) {
		result = cado_verified_executable_create(sparse, wrong, directory,
				&handle);
		_exit(result.status == CADO_SCADO_OK ? 0 : 1);
	}
	if (child > 0) {
		for (attempts = 0; attempts < 400 &&
				find_copy(directory, copy_path, 1) != 1; attempts++)
			usleep(5000);
		CHECK(find_copy(directory, copy_path, 1) == 1);
		CHECK(kill(child, SIGKILL) == 0);
		CHECK(waitpid(child, &status, 0) == child);
		CHECK(WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL);
		for (attempts = 0; attempts < 400 &&
				find_copy(directory, copy_path, 0) != 0; attempts++)
			usleep(5000);
		CHECK(find_copy(directory, copy_path, 0) == 0);
	}

	unlink(source);
	unlink(sparse);
	rmdir(directory);
	return failures == 0 ? 0 : 1;
}
