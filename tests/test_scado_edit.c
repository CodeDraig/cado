#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <cado_const.h>
#include <file_utils.h>
#include <pam_check.h>
#include <scado_edit.h>

static int failures;
static int pam_calls;

int pam_check(const char *username)
{
	(void)username;
	pam_calls++;
	return -1;
}

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
	FILE *input = fopen(path, "r");
	char *line = NULL;
	size_t capacity = 0;
	ssize_t length;
	int close_failed;

	if (input == NULL)
		return NULL;
	length = getline(&line, &capacity, input);
	close_failed = fclose(input) != 0;
	if (length < 0 || close_failed) {
		free(line);
		return NULL;
	}
	return line;
}

static int find_recovery(const char *directory, char path[PATH_MAX])
{
	DIR *stream = opendir(directory);
	struct dirent *entry;
	int found = 0;

	if (stream == NULL)
		return -1;
	while ((entry = readdir(stream)) != NULL) {
		if (strncmp(entry->d_name, "cado-scado.", 11) != 0)
			continue;
		if (found) {
			closedir(stream);
			errno = EEXIST;
			return -1;
		}
		if (snprintf(path, PATH_MAX, "%s/%s", directory, entry->d_name) >=
				PATH_MAX) {
			closedir(stream);
			errno = ENAMETOOLONG;
			return -1;
		}
		found = 1;
	}
	if (closedir(stream) < 0)
		return -1;
	return found;
}

static int find_recovery_at_least(const char *directory, char path[PATH_MAX],
		off_t minimum_size)
{
	struct stat stats;
	int found = find_recovery(directory, path);

	if (found != 1)
		return found;
	if (stat(path, &stats) < 0)
		return -1;
	return stats.st_size >= minimum_size;
}

static int worker_child_count(pid_t worker)
{
	char path[128];
	char contents[128];
	int descriptor;
	ssize_t count;
	int children = 0;
	ssize_t i;
	int in_number = 0;

	if (snprintf(path, sizeof(path), "/proc/%ld/task/%ld/children",
			(long)worker, (long)worker) >= (int)sizeof(path))
		return -1;
	descriptor = open(path, O_RDONLY | O_CLOEXEC);
	if (descriptor < 0)
		return -1;
	do {
		count = read(descriptor, contents, sizeof(contents));
	} while (count < 0 && errno == EINTR);
	if (close(descriptor) < 0 || count < 0)
		return -1;
	for (i = 0; i < count; i++) {
		if (contents[i] >= '0' && contents[i] <= '9') {
			if (!in_number)
				children++;
			in_number = 1;
		} else {
			in_number = 0;
		}
	}
	return children;
}

static int sparse_editor(const char *marker, const char *edit_path)
{
	static const char edited[] = "/bin/true:chown\n# edited\n";
	const off_t sparse_size = (off_t)1 << 40;
	int descriptor = open(edit_path, O_WRONLY | O_TRUNC | O_CLOEXEC);
	struct cado_io_result result;

	if (descriptor < 0)
		return 1;
	result = cado_write_all(descriptor, edited, sizeof(edited) - 1);
	if (result.status != CADO_IO_OK || ftruncate(descriptor, sparse_size) < 0 ||
			close(descriptor) < 0)
		return 1;
	return write_text(marker, "editor complete\n") == 0 ? 0 : 1;
}

static int signal_editor(void)
{
	const int signals[] = {SIGHUP, SIGINT, SIGQUIT};
	struct sigaction action;
	size_t i;

	for (i = 0; i < sizeof(signals) / sizeof(signals[0]); i++) {
		if (sigaction(signals[i], NULL, &action) < 0 ||
				action.sa_handler != SIG_DFL)
			return 1;
	}
	return 0;
}

static int set_default_editor_signals(void)
{
	const int signals[] = {SIGHUP, SIGINT, SIGQUIT};
	struct sigaction action;
	size_t i;

	memset(&action, 0, sizeof(action));
	action.sa_handler = SIG_DFL;
	sigemptyset(&action.sa_mask);
	for (i = 0; i < sizeof(signals) / sizeof(signals[0]); i++) {
		if (sigaction(signals[i], &action, NULL) < 0)
			return -1;
	}
	return 0;
}

int main(int argc, char **argv)
{
	char directory[] = "/tmp/cado-scado-edit-test.XXXXXX";
	char protected_path[PATH_MAX];
	char sparse_path[PATH_MAX];
	char marker[PATH_MAX];
	char recovery[PATH_MAX];
	char self[PATH_MAX];
	char editor[PATH_MAX * 2];
	char *recovery_text;
	struct scado_edit_request request;
	struct scado_edit_result result;
	struct stat stats;
	struct stat protected_before;
	struct stat protected_after;
	pid_t worker;
	int status;
	int attempts;
	int sparse_fd;

	if (argc == 4 && strcmp(argv[1], "--sparse-editor") == 0)
		return sparse_editor(argv[2], argv[3]);
	if (argc == 3 && strcmp(argv[1], "--signal-editor") == 0)
		return signal_editor();

	CHECK(realpath(argv[0], self) != NULL);
	CHECK(mkdtemp(directory) != NULL);
	CHECK(snprintf(protected_path, sizeof(protected_path), "%s/protected",
			directory) < (int)sizeof(protected_path));
	CHECK(snprintf(marker, sizeof(marker), "%s/editor-marker", directory) <
			(int)sizeof(marker));
	CHECK(snprintf(sparse_path, sizeof(sparse_path), "%s/sparse-protected",
			directory) < (int)sizeof(sparse_path));
	request.username = "unprivileged-test";
	request.protected_path = protected_path;
	request.temporary_directory = directory;
	request.editor = "/bin/true";

	CHECK(write_text(protected_path, "malformed\n") == 0);
	result = scado_edit_execute(&request);
	CHECK(result.status == SCADO_EDIT_ERROR);
	CHECK(result.has_file_result &&
			result.file_result.status == SCADO_FILE_PARSE);
	CHECK(result.recovery_path[0] != '\0');
	CHECK(pam_calls == 0);
	recovery_text = read_text(result.recovery_path);
	CHECK(recovery_text != NULL && strcmp(recovery_text, "malformed\n") == 0);
	free(recovery_text);
	CHECK(unlink(result.recovery_path) == 0);

	CHECK(write_text(protected_path, "/bin/true:chown\n") == 0);
	CHECK(stat(protected_path, &protected_before) == 0);
	result = scado_edit_execute(&request);
	CHECK(result.status == SCADO_EDIT_OK);
	CHECK(result.recovery_path[0] == '\0');
	CHECK(pam_calls == 0);
	if (result.recovery_path[0] != '\0')
		CHECK(unlink(result.recovery_path) == 0);
	CHECK(stat(protected_path, &protected_after) == 0);
	CHECK(protected_after.st_dev == protected_before.st_dev &&
			protected_after.st_ino == protected_before.st_ino);
	CHECK(find_recovery(directory, recovery) == 0);
	CHECK(waitpid(-1, &status, WNOHANG) < 0 && errno == ECHILD);

	CHECK(set_default_editor_signals() == 0);
	CHECK(snprintf(editor, sizeof(editor), "%s --signal-editor", self) <
			(int)sizeof(editor));
	request.editor = editor;
	result = scado_edit_execute(&request);
	CHECK(result.status == SCADO_EDIT_OK);
	CHECK(result.recovery_path[0] == '\0');
	CHECK(pam_calls == 0);

	sparse_fd = open(sparse_path,
			O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
	CHECK(sparse_fd >= 0);
	CHECK(ftruncate(sparse_fd, (off_t)1 << 40) == 0);
	CHECK(close(sparse_fd) == 0);
	request.protected_path = sparse_path;
	request.editor = "/bin/true";
	worker = fork();
	CHECK(worker >= 0);
	if (worker == 0) {
		result = scado_edit_execute(&request);
		_exit(result.status == SCADO_EDIT_OK ? 0 : 1);
	}
	if (worker > 0) {
		for (attempts = 0; attempts < 400 &&
				find_recovery_at_least(directory, recovery, 1) != 1;
				attempts++)
			usleep(5000);
		CHECK(find_recovery_at_least(directory, recovery, 1) == 1);
		CHECK(kill(worker, SIGKILL) == 0);
		CHECK(waitpid(worker, &status, 0) == worker);
		CHECK(WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL);
		for (attempts = 0; attempts < 400 &&
				find_recovery(directory, recovery) != 0; attempts++)
			usleep(5000);
		CHECK(find_recovery(directory, recovery) == 0);
		if (find_recovery(directory, recovery) == 1)
			CHECK(unlink(recovery) == 0);
	}
	CHECK(unlink(sparse_path) == 0);

	CHECK(snprintf(editor, sizeof(editor), "%s --sparse-editor %s", self,
			marker) < (int)sizeof(editor));
	request.protected_path = protected_path;
	request.editor = editor;
	worker = fork();
	CHECK(worker >= 0);
	if (worker == 0) {
		result = scado_edit_execute(&request);
		_exit(result.status == SCADO_EDIT_OK ? 0 : 1);
	}
	if (worker > 0) {
		for (attempts = 0; attempts < 400 && access(marker, F_OK) < 0;
				attempts++)
			usleep(5000);
		CHECK(access(marker, F_OK) == 0);
		for (attempts = 0; attempts < 400 && worker_child_count(worker) != 1;
				attempts++)
			usleep(5000);
		CHECK(worker_child_count(worker) == 1);
		CHECK(find_recovery(directory, recovery) == 1);
		CHECK(stat(recovery, &stats) == 0 && stats.st_size == ((off_t)1 << 40));
		CHECK(kill(worker, SIGTERM) == 0);
		CHECK(waitpid(worker, &status, 0) == worker);
		CHECK(WIFSIGNALED(status) && WTERMSIG(status) == SIGTERM);
		for (attempts = 0; attempts < 200 && access(recovery, F_OK) < 0;
				attempts++)
			usleep(5000);
		CHECK(access(recovery, F_OK) == 0);
		recovery_text = read_text(protected_path);
		CHECK(recovery_text != NULL && strcmp(recovery_text,
				"/bin/true:chown\n") == 0);
		free(recovery_text);
		CHECK(unlink(recovery) == 0);
	}

	unlink(marker);
	unlink(protected_path);
	rmdir(directory);
	return failures == 0 ? 0 : 1;
}
