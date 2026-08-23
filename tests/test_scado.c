#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/capability.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include <compute_digest.h>
#include <file_utils.h>
#include <get_scado_file.h>
#include <scado_parse.h>

static int failures;

#define CHECK(expression) do { \
	if (!(expression)) { \
		fprintf(stderr, "%s:%d: check failed: %s\n", __FILE__, __LINE__, \
				#expression); \
		failures++; \
	} \
} while (0)

static int write_text(const char *path, const char *text)
{
	int descriptor = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
	struct cado_io_result result;

	if (descriptor < 0)
		return -1;
	result = cado_write_all(descriptor, text, strlen(text));
	if (close(descriptor) < 0 || result.status != CADO_IO_OK)
		return -1;
	return 0;
}

static char *read_text(const char *path)
{
	FILE *file = fopen(path, "r");
	char *data = NULL;
	size_t used = 0;
	size_t capacity = 0;
	unsigned char buffer[1024];
	size_t count;
	int read_failed = 0;
	int close_failed;

	if (file == NULL)
		return NULL;
	for (;;) {
		char *resized;

		count = fread(buffer, 1, sizeof(buffer), file);
		if (used + count + 1 > capacity) {
			capacity = (used + count + 1) * 2;
			resized = realloc(data, capacity);
			if (resized == NULL) {
				free(data);
				fclose(file);
				return NULL;
			}
			data = resized;
		}
		memcpy(data + used, buffer, count);
		used += count;
		if (count < sizeof(buffer)) {
			read_failed = ferror(file);
			break;
		}
	}
	close_failed = fclose(file) != 0;
	if (read_failed || close_failed) {
		free(data);
		return NULL;
	}
	if (data == NULL) {
		data = malloc(1);
		if (data == NULL)
			return NULL;
	}
	data[used] = '\0';
	return data;
}

static void parse_tests(void)
{
	static const char digest[] =
		"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
	char line[256];
	struct scado_line parsed;

	CHECK(scado_parse_line("/bin/tool : chown", strlen("/bin/tool : chown"), 0, &parsed) ==
			SCADO_PARSE_OK);
	CHECK(parsed.kind == SCADO_LINE_ENTRY);
	CHECK(!parsed.has_digest);
	CHECK(parsed.path.length == strlen("/bin/tool"));
	CHECK(scado_parse_line("  # comment\n", strlen("  # comment\n"), 0, &parsed) ==
			SCADO_PARSE_OK && parsed.kind == SCADO_LINE_COMMENT);
	CHECK(scado_parse_line(" \t\n", strlen(" \t\n"), 0, &parsed) ==
			SCADO_PARSE_OK && parsed.kind == SCADO_LINE_BLANK);
	CHECK(scado_parse_line("/opt/my tool : cap_chown # trailing",
			strlen("/opt/my tool : cap_chown # trailing"), 0,
			&parsed) == SCADO_PARSE_OK);
	CHECK(parsed.path.length == strlen("/opt/my tool"));
	CHECK(memcmp(parsed.path.data, "/opt/my tool", parsed.path.length) == 0);
	CHECK(scado_parse_line("/tmp/a\\ b : chown", strlen("/tmp/a\\ b : chown"), 0, &parsed) ==
			SCADO_PARSE_OK);
	CHECK(memchr(parsed.path.data, '\\', parsed.path.length) != NULL);
	snprintf(line, sizeof(line), "/bin/tool:chown:%s", digest);
	CHECK(scado_parse_line(line, strlen(line), 0, &parsed) == SCADO_PARSE_OK);
	CHECK(parsed.has_digest && parsed.digest.length == DIGESTSTRLEN);
	CHECK(scado_parse_line("/bin/tool:chown:", strlen("/bin/tool:chown:"), 0, &parsed) ==
			SCADO_PARSE_DIGEST_EMPTY);
	CHECK(scado_parse_line("/bin/tool:chown:", strlen("/bin/tool:chown:"), 1, &parsed) ==
			SCADO_PARSE_OK);
	CHECK(scado_parse_line("relative:chown", strlen("relative:chown"), 0, &parsed) ==
			SCADO_PARSE_PATH_NOT_ABSOLUTE);
	CHECK(scado_parse_line("/bin/tool:", strlen("/bin/tool:"), 0, &parsed) ==
			SCADO_PARSE_CAPABILITIES);
	CHECK(scado_parse_line("/bin/tool:chown:x", strlen("/bin/tool:chown:x"), 0, &parsed) ==
			SCADO_PARSE_DIGEST_INVALID);
	CHECK(scado_parse_line("/bin/tool:chown:x:y", strlen("/bin/tool:chown:x:y"), 0, &parsed) ==
			SCADO_PARSE_FIELD_COUNT);
}

static int find_staging_file(const char *directory, char path[PATH_MAX],
		off_t minimum_size)
{
	DIR *stream = opendir(directory);
	struct dirent *entry;
	struct stat stats;
	int found = 0;

	if (stream == NULL)
		return -1;
	while ((entry = readdir(stream)) != NULL) {
		if (strncmp(entry->d_name, ".cado-stage.", 12) != 0)
			continue;
		if (snprintf(path, PATH_MAX, "%s/%s", directory, entry->d_name) >=
				PATH_MAX || stat(path, &stats) < 0) {
			closedir(stream);
			return -1;
		}
		if (stats.st_size < minimum_size)
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

static int no_staging_files(const char *directory)
{
	char path[PATH_MAX];

	return find_staging_file(directory, path, 0) == 0;
}

static struct scado_transaction_request make_transaction_request(
		const char *source, const char *destination,
		struct scado_update_operation operation,
		enum scado_source_expectation_kind source_kind,
		const char *source_digest,
		enum scado_destination_expectation_kind destination_kind,
		const char *destination_digest)
{
	struct scado_transaction_request request = {
		.source_path = source,
		.destination_path = destination,
		.operation = operation,
		.source = {
			.kind = source_kind,
			.digest = source_digest
		},
		.destination = {
			.kind = destination_kind,
			.digest = destination_digest
		}
	};

	return request;
}

int main(void)
{
	char directory[] = "/tmp/cado-scado-test.XXXXXX";
	char executable_one[512];
	char executable_two[512];
	char source[512];
	char source_two[512];
	char destination[512];
	char stage_path[PATH_MAX];
	char digest_one[DIGESTSTRLEN + 1];
	char digest_two[DIGESTSTRLEN + 1];
	char source_before[DIGESTSTRLEN + 1];
	char source_two_before[DIGESTSTRLEN + 1];
	char destination_before[DIGESTSTRLEN + 1];
	char wrong_digest[DIGESTSTRLEN + 1];
	char *input = NULL;
	char *expected = NULL;
	char *actual;
	struct cado_digest_result digest_result;
	struct scado_update_operation operation;
	struct scado_transaction_request transaction_request;
	struct scado_file_result update_result;
	struct scado_path_result path_result;
	struct stat stats;
	char spool_path[PATH_MAX];
	int lock_fd;
	pid_t child;
	int child_status;
	int attempts;

	parse_tests();
	CHECK(get_scado_file("alice", spool_path) == 0);
	CHECK(get_scado_file("", spool_path) < 0);
	CHECK(get_scado_file(".", spool_path) < 0);
	CHECK(get_scado_file("..", spool_path) < 0);
	CHECK(get_scado_file("../alice", spool_path) < 0);
	CHECK(mkdtemp(directory) != NULL);
	snprintf(executable_one, sizeof(executable_one), "%s/program one", directory);
	snprintf(executable_two, sizeof(executable_two), "%s/program-two", directory);
	snprintf(source, sizeof(source), "%s/source", directory);
	snprintf(source_two, sizeof(source_two), "%s/source-two", directory);
	snprintf(destination, sizeof(destination), "%s/destination", directory);
	CHECK(write_text(executable_one, "first executable\n") == 0);
	CHECK(write_text(executable_two, "second executable\n") == 0);
	digest_result = compute_digest(executable_one, digest_one);
	CHECK(digest_result.status == CADO_DIGEST_OK);
	digest_result = compute_digest(executable_two, digest_two);
	CHECK(digest_result.status == CADO_DIGEST_OK);
	memset(wrong_digest, '0', DIGESTSTRLEN);
	wrong_digest[DIGESTSTRLEN] = '\0';

	CHECK(asprintf(&input,
			"# keep exactly\n%s : chown : %s # note\n%s : kill",
			executable_one, wrong_digest, executable_two) >= 0);
	CHECK(write_text(source, input) == 0);
	operation.kind = SCADO_UPDATE_PATH;
	operation.path = executable_one;
	transaction_request = make_transaction_request(source, destination, operation,
			SCADO_SOURCE_CURRENT, NULL, SCADO_DESTINATION_ABSENT, NULL);
	update_result = scado_update_transaction(&transaction_request);
	CHECK(update_result.status == SCADO_FILE_OK);
	CHECK(update_result.matched == 1 && update_result.changed == 1);
	CHECK(update_result.committed);
	CHECK(asprintf(&expected,
			"# keep exactly\n%s : chown : %s # note\n%s : kill",
			executable_one, digest_one, executable_two) >= 0);
	actual = read_text(destination);
	CHECK(actual != NULL && strcmp(actual, expected) == 0);
	free(actual);
	CHECK(stat(destination, &stats) == 0);
	CHECK((stats.st_mode & 0777) == 0600);
	path_result = scado_path_getinfo(destination, executable_one);
	CHECK(path_result.status == SCADO_FILE_OK && path_result.found);
	CHECK(path_result.capabilities == (UINT64_C(1) << CAP_CHOWN));
	CHECK(strcmp(path_result.digest, digest_one) == 0);
	path_result = scado_path_getinfo(destination, executable_two);
	CHECK(path_result.status == SCADO_FILE_OK && path_result.found);
	CHECK(path_result.digest[0] == '\0');
	free(input);
	free(expected);
	input = NULL;
	expected = NULL;

	CHECK(asprintf(&input, "%s : chown :   # fill\n%s : kill\n",
			executable_one, executable_two) >= 0);
	CHECK(write_text(source, input) == 0);
	operation.kind = SCADO_ADD_MISSING;
	operation.path = NULL;
	digest_result = compute_digest(destination, destination_before);
	CHECK(digest_result.status == CADO_DIGEST_OK);
	transaction_request = make_transaction_request(source, destination, operation,
			SCADO_SOURCE_CURRENT, NULL, SCADO_DESTINATION_DIGEST,
			destination_before);
	update_result = scado_update_transaction(&transaction_request);
	CHECK(update_result.status == SCADO_FILE_OK && update_result.changed == 1);
	path_result = scado_path_getinfo(destination, executable_one);
	CHECK(path_result.status == SCADO_FILE_OK && path_result.found);
	CHECK(strcmp(path_result.digest, digest_one) == 0);
	free(input);
	input = NULL;

	CHECK(write_text(destination, "ORIGINAL") == 0);
	CHECK(write_text(source, "/bin/true:chown\nmalformed\n") == 0);
	operation.kind = SCADO_UPDATE_ALL;
	transaction_request = make_transaction_request(source, destination, operation,
			SCADO_SOURCE_CURRENT, NULL,
			SCADO_DESTINATION_SOURCE_SNAPSHOT, NULL);
	update_result = scado_update_transaction(&transaction_request);
	CHECK(update_result.status == SCADO_FILE_PARSE);
	actual = read_text(destination);
	CHECK(actual != NULL && strcmp(actual, "ORIGINAL") == 0);
	free(actual);
	CHECK(no_staging_files(directory));

	CHECK(asprintf(&input, "%s : chown : %s\n",
			executable_one, wrong_digest) >= 0);
	CHECK(write_text(source, input) == 0);
	CHECK(write_text(destination, "ORIGINAL") == 0);
	operation.kind = SCADO_UPDATE_PATH;
	operation.path = "/missing/path";
	transaction_request = make_transaction_request(source, destination, operation,
			SCADO_SOURCE_CURRENT, NULL,
			SCADO_DESTINATION_SOURCE_SNAPSHOT, NULL);
	update_result = scado_update_transaction(&transaction_request);
	CHECK(update_result.status == SCADO_FILE_TARGET_MISSING);
	actual = read_text(destination);
	CHECK(actual != NULL && strcmp(actual, "ORIGINAL") == 0);
	free(actual);
	free(input);
	input = NULL;

	CHECK(asprintf(&input, "%s : chown\n", executable_one) >= 0);
	CHECK(write_text(source, input) == 0);
	operation.path = executable_one;
	transaction_request = make_transaction_request(source, destination, operation,
			SCADO_SOURCE_CURRENT, NULL,
			SCADO_DESTINATION_SOURCE_SNAPSHOT, NULL);
	update_result = scado_update_transaction(&transaction_request);
	CHECK(update_result.status == SCADO_FILE_TARGET_HAS_NO_DIGEST);
	free(input);
	input = NULL;

	CHECK(write_text(source, "/definitely/not/present : chown :\n") == 0);
	operation.kind = SCADO_ADD_MISSING;
	operation.path = NULL;
	transaction_request = make_transaction_request(source, destination, operation,
			SCADO_SOURCE_CURRENT, NULL,
			SCADO_DESTINATION_SOURCE_SNAPSHOT, NULL);
	update_result = scado_update_transaction(&transaction_request);
	CHECK(update_result.status == SCADO_FILE_DIGEST);

	CHECK(asprintf(&input, "%s : chown : %s\n",
			executable_one, wrong_digest) >= 0);
	CHECK(write_text(source, input) == 0);
	digest_result = compute_digest(source, source_before);
	CHECK(digest_result.status == CADO_DIGEST_OK);
	CHECK(asprintf(&expected, "%s# changed while authentication ran\n", input) >= 0);
	CHECK(write_text(source, expected) == 0);
	free(expected);
	expected = NULL;
	CHECK(write_text(destination, "ORIGINAL") == 0);
	operation.kind = SCADO_UPDATE_ALL;
	transaction_request = make_transaction_request(source, destination, operation,
			SCADO_SOURCE_DIGEST, source_before,
			SCADO_DESTINATION_SOURCE_SNAPSHOT, NULL);
	update_result = scado_update_transaction(&transaction_request);
	CHECK(update_result.status == SCADO_FILE_SOURCE_CHANGED);
	actual = read_text(destination);
	CHECK(actual != NULL && strcmp(actual, "ORIGINAL") == 0);
	free(actual);
	free(input);
	input = NULL;

	CHECK(write_text(source, "") == 0);
	digest_result = compute_digest(destination, destination_before);
	CHECK(digest_result.status == CADO_DIGEST_OK);
	transaction_request = make_transaction_request(source, destination, operation,
			SCADO_SOURCE_CURRENT, NULL, SCADO_DESTINATION_DIGEST,
			destination_before);
	update_result = scado_update_transaction(&transaction_request);
	CHECK(update_result.status == SCADO_FILE_OK);
	actual = read_text(destination);
	CHECK(actual != NULL && strcmp(actual, "") == 0);
	free(actual);
	operation.kind = (enum scado_update_kind)99;
	transaction_request = make_transaction_request(source, destination, operation,
			SCADO_SOURCE_CURRENT, NULL,
			SCADO_DESTINATION_SOURCE_SNAPSHOT, NULL);
	update_result = scado_update_transaction(&transaction_request);
	CHECK(update_result.status == SCADO_FILE_INVALID_ARGUMENT);

	CHECK(write_text(source, "/bin/true:chown:\n") == 0);
	path_result = scado_path_getinfo(source, "/bin/true");
	CHECK(path_result.status == SCADO_FILE_PARSE && !path_result.found);
	CHECK(write_text(source,
			"/bin/true:chown\n/bin/false:chown:bad\n") == 0);
	path_result = scado_path_getinfo(source, "/bin/true");
	CHECK(path_result.status == SCADO_FILE_PARSE && !path_result.found);
	CHECK(no_staging_files(directory));

	CHECK(write_text(destination, "/bin/true:chown\n") == 0);
	digest_result = compute_digest(destination, destination_before);
	CHECK(digest_result.status == CADO_DIGEST_OK);
	CHECK(write_text(source, "/bin/true:chown\n# edit one\n") == 0);
	CHECK(write_text(source_two, "/bin/true:chown\n# edit two\n") == 0);
	digest_result = compute_digest(source, source_before);
	CHECK(digest_result.status == CADO_DIGEST_OK);
	digest_result = compute_digest(source_two, source_two_before);
	CHECK(digest_result.status == CADO_DIGEST_OK);
	operation.kind = SCADO_ADD_MISSING;
	operation.path = NULL;
	transaction_request = make_transaction_request(source, destination, operation,
			SCADO_SOURCE_DIGEST, source_before, SCADO_DESTINATION_DIGEST,
			destination_before);
	update_result = scado_update_transaction(&transaction_request);
	CHECK(update_result.status == SCADO_FILE_OK && update_result.committed);
	transaction_request = make_transaction_request(source_two, destination,
			operation, SCADO_SOURCE_DIGEST, source_two_before,
			SCADO_DESTINATION_DIGEST, destination_before);
	update_result = scado_update_transaction(&transaction_request);
	CHECK(update_result.status == SCADO_FILE_DESTINATION_CHANGED);
	actual = read_text(destination);
	CHECK(actual != NULL && strcmp(actual,
			"/bin/true:chown\n# edit one\n") == 0);
	free(actual);
	CHECK(no_staging_files(directory));

	CHECK(unlink(destination) == 0);
	transaction_request = make_transaction_request(source, destination, operation,
			SCADO_SOURCE_DIGEST, source_before, SCADO_DESTINATION_ABSENT,
			NULL);
	update_result = scado_update_transaction(&transaction_request);
	CHECK(update_result.status == SCADO_FILE_OK && update_result.committed);
	transaction_request = make_transaction_request(source_two, destination,
			operation, SCADO_SOURCE_DIGEST, source_two_before,
			SCADO_DESTINATION_ABSENT, NULL);
	update_result = scado_update_transaction(&transaction_request);
	CHECK(update_result.status == SCADO_FILE_DESTINATION_CHANGED);
	actual = read_text(destination);
	CHECK(actual != NULL && strcmp(actual,
			"/bin/true:chown\n# edit one\n") == 0);
	free(actual);

	update_result = scado_delete_transaction(destination);
	CHECK(update_result.status == SCADO_FILE_OK && update_result.committed);
	transaction_request = make_transaction_request(source_two, destination,
			operation, SCADO_SOURCE_DIGEST, source_two_before,
			SCADO_DESTINATION_DIGEST, source_before);
	update_result = scado_update_transaction(&transaction_request);
	CHECK(update_result.status == SCADO_FILE_DESTINATION_CHANGED);
	CHECK(access(destination, F_OK) < 0 && errno == ENOENT);

	CHECK(write_text(destination, "/bin/true:chown\n") == 0);
	digest_result = compute_digest(destination, destination_before);
	CHECK(digest_result.status == CADO_DIGEST_OK);
	transaction_request = make_transaction_request(source_two, destination,
			operation, SCADO_SOURCE_DIGEST, source_two_before,
			SCADO_DESTINATION_DIGEST, destination_before);
	lock_fd = open(directory, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	CHECK(lock_fd >= 0 && flock(lock_fd, LOCK_EX) == 0);
	child = fork();
	CHECK(child >= 0);
	if (child == 0) {
		struct scado_file_result child_result;

		close(lock_fd);
		child_result = scado_update_transaction(&transaction_request);
		_exit(child_result.status == SCADO_FILE_OK ? 0 : 1);
	}
	if (child > 0) {
		for (attempts = 0; attempts < 200 && no_staging_files(directory);
				attempts++)
			usleep(5000);
		CHECK(!no_staging_files(directory));
		CHECK(waitpid(child, &child_status, WNOHANG) == 0);
		actual = read_text(destination);
		CHECK(actual != NULL && strcmp(actual, "/bin/true:chown\n") == 0);
		free(actual);
		CHECK(flock(lock_fd, LOCK_UN) == 0);
		CHECK(close(lock_fd) == 0);
		lock_fd = -1;
		CHECK(waitpid(child, &child_status, 0) == child);
		CHECK(WIFEXITED(child_status) && WEXITSTATUS(child_status) == 0);
		actual = read_text(destination);
		CHECK(actual != NULL && strcmp(actual,
				"/bin/true:chown\n# edit two\n") == 0);
		free(actual);
	}
	if (lock_fd >= 0) {
		flock(lock_fd, LOCK_UN);
		close(lock_fd);
	}

	CHECK(write_text(destination, "/bin/true:chown\n") == 0);
	digest_result = compute_digest(destination, destination_before);
	CHECK(digest_result.status == CADO_DIGEST_OK);
	transaction_request = make_transaction_request(source_two, destination,
			operation, SCADO_SOURCE_DIGEST, source_two_before,
			SCADO_DESTINATION_DIGEST, destination_before);
	lock_fd = open(directory, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	CHECK(lock_fd >= 0 && flock(lock_fd, LOCK_EX) == 0);
	child = fork();
	CHECK(child >= 0);
	if (child == 0) {
		struct scado_file_result child_result;

		close(lock_fd);
		child_result = scado_update_transaction(&transaction_request);
		_exit(child_result.status == SCADO_FILE_OK ? 0 : 1);
	}
	if (child > 0) {
		for (attempts = 0; attempts < 400 &&
				find_staging_file(directory, stage_path, 1) != 1; attempts++)
			usleep(5000);
		CHECK(find_staging_file(directory, stage_path, 1) == 1);
		CHECK(waitpid(child, &child_status, WNOHANG) == 0);
		CHECK(kill(child, SIGKILL) == 0);
		CHECK(waitpid(child, &child_status, 0) == child);
		CHECK(WIFSIGNALED(child_status) && WTERMSIG(child_status) == SIGKILL);
		CHECK(flock(lock_fd, LOCK_UN) == 0);
		CHECK(close(lock_fd) == 0);
		lock_fd = -1;
		for (attempts = 0; attempts < 400 && !no_staging_files(directory);
				attempts++)
			usleep(5000);
		CHECK(no_staging_files(directory));
		if (find_staging_file(directory, stage_path, 0) == 1)
			CHECK(unlink(stage_path) == 0);
		actual = read_text(destination);
		CHECK(actual != NULL && strcmp(actual, "/bin/true:chown\n") == 0);
		free(actual);
	}
	if (lock_fd >= 0) {
		flock(lock_fd, LOCK_UN);
		close(lock_fd);
	}

	CHECK(write_text(source, "malformed\n") == 0);
	update_result = scado_validate_file(source);
	CHECK(update_result.status == SCADO_FILE_PARSE && update_result.line == 1);
	CHECK(write_text(source, "/bin/true:chown") == 0);
	update_result = scado_validate_file(source);
	CHECK(update_result.status == SCADO_FILE_OK);
	CHECK(write_text(source, "/bin/true:chown:\n") == 0);
	update_result = scado_validate_file(source);
	CHECK(update_result.status == SCADO_FILE_PARSE && update_result.line == 1);
	CHECK(no_staging_files(directory));

	unlink(executable_one);
	unlink(executable_two);
	unlink(source);
	unlink(source_two);
	unlink(destination);
	rmdir(directory);
	return failures == 0 ? 0 : 1;
}
