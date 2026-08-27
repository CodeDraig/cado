#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/file.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <security/pam_appl.h>

#include <compute_digest.h>
#include <file_utils.h>
#include <scado_edit.h>

enum test_phase {
	PHASE_EDITOR,
	PHASE_HASH,
	PHASE_AUTHENTICATION,
	PHASE_COMMIT
};

static enum test_phase current_phase;
static char gate_path[PATH_MAX];
static int inherited_lock = -1;
static int hash_calls;
static int fail_capability_drop;
static const char edited_contents[] = "/bin/false:kill\n";

static int write_text(const char *path, const char *text)
{
	struct cado_io_result result;
	int descriptor = open(path,
			O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);

	if (descriptor < 0)
		return -1;
	result = cado_write_all(descriptor, text, strlen(text));
	if (close(descriptor) < 0 || result.status != CADO_IO_OK)
		return -1;
	return 0;
}

static char *read_text(const char *path, size_t *length)
{
	char *contents = NULL;
	size_t used = 0;
	size_t capacity = 0;
	char buffer[256];
	ssize_t count;
	int descriptor = open(path, O_RDONLY | O_CLOEXEC);

	if (descriptor < 0)
		return NULL;
	for (;;) {
		char *resized;

		do {
			count = read(descriptor, buffer, sizeof(buffer));
		} while (count < 0 && errno == EINTR);
		if (count < 0) {
			free(contents);
			close(descriptor);
			return NULL;
		}
		if (count == 0)
			break;
		if (used + (size_t)count + 1 > capacity) {
			capacity = (used + (size_t)count + 1) * 2;
			resized = realloc(contents, capacity);
			if (resized == NULL) {
				free(contents);
				close(descriptor);
				return NULL;
			}
			contents = resized;
		}
		memcpy(contents + used, buffer, (size_t)count);
		used += (size_t)count;
	}
	if (close(descriptor) < 0) {
		free(contents);
		return NULL;
	}
	if (contents == NULL) {
		contents = malloc(1);
		if (contents == NULL)
			return NULL;
	}
	contents[used] = '\0';
	if (length != NULL)
		*length = used;
	return contents;
}

static int write_status_field(const char *directory, const char *filename,
		const char *field)
{
	char path[PATH_MAX];
	char *status;
	char *line;
	char *value;
	char *end;
	char rendered[128];
	int result = -1;

	status = read_text("/proc/self/status", NULL);
	if (status == NULL)
		return -1;
	line = status;
	while (line != NULL) {
		char *next = strchr(line, '\n');

		if (next != NULL)
			*next = '\0';
		if (strncmp(line, field, strlen(field)) == 0 &&
				line[strlen(field)] == ':') {
			value = line + strlen(field) + 1;
			while (*value == ' ' || *value == '\t')
				value++;
			end = value + strlen(value);
			while (end > value && (end[-1] == ' ' || end[-1] == '\t'))
				*--end = '\0';
			if (snprintf(path, sizeof(path), "%s/%s", directory, filename) <
					(int)sizeof(path) &&
					snprintf(rendered, sizeof(rendered), "%s\n", value) <
					(int)sizeof(rendered))
				result = write_text(path, rendered);
			break;
		}
		line = next == NULL ? NULL : next + 1;
	}
	free(status);
	if (result < 0 && errno == 0)
		errno = EINVAL;
	return result;
}

static int identity_driver(const char *username, const char *protected_path,
		const char *temporary_directory, const char *editor,
		const char *output_directory)
{
	struct scado_edit_request request;
	struct scado_edit_result result;

	if (write_status_field(output_directory, "driver-cap-eff", "CapEff") < 0 ||
			write_status_field(output_directory, "driver-cap-amb", "CapAmb") < 0) {
		perror("identity driver status");
		return 1;
	}
	request.username = username;
	request.protected_path = protected_path;
	request.temporary_directory = temporary_directory;
	request.editor = editor;
	result = scado_edit_execute(&request);
	if (result.status != SCADO_EDIT_OK) {
		fprintf(stderr, "identity driver edit failed: status=%d error=%d\n",
				result.status, result.error_number);
		return 1;
	}
	return 0;
}

static void wait_at_gate(void)
{
	if (write_text(gate_path, "entered\n") < 0)
		_exit(120);
	for (;;)
		pause();
}

struct cado_digest_result __real_compute_digest_nofollow_regular(
		const char *path, char digest[DIGESTSTRLEN + 1]);

int __real_drop_all_capabilities(void);

int __wrap_drop_all_capabilities(void)
{
	if (fail_capability_drop) {
		errno = EPERM;
		return -1;
	}
	return __real_drop_all_capabilities();
}

struct cado_digest_result __wrap_compute_digest_nofollow_regular(
		const char *path, char digest[DIGESTSTRLEN + 1])
{
	if (current_phase == PHASE_HASH && hash_calls++ == 0)
		wait_at_gate();
	return __real_compute_digest_nofollow_regular(path, digest);
}

int pam_check(const char *username)
{
	(void)username;
	if (current_phase == PHASE_AUTHENTICATION)
		wait_at_gate();
	return PAM_SUCCESS;
}

static void abrupt_exit(int signal_number)
{
	(void)signal_number;
	_exit(99);
}

static int editor_helper(const char *marker, const char *path, int block)
{
	if (write_text(path, edited_contents) < 0)
		return 1;
	if (write_text(marker, "entered\n") < 0)
		return 1;
	while (block)
		pause();
	return 0;
}

static int wait_for_path(const char *path)
{
	int attempt;

	for (attempt = 0; attempt < 500; attempt++) {
		if (access(path, F_OK) == 0)
			return 0;
		if (errno != ENOENT)
			return -1;
		usleep(10000);
	}
	errno = ETIMEDOUT;
	return -1;
}

static int count_prefixed(const char *directory, const char *prefix,
		char only_path[PATH_MAX])
{
	DIR *stream = opendir(directory);
	struct dirent *entry;
	int count = 0;

	if (stream == NULL)
		return -1;
	while ((entry = readdir(stream)) != NULL) {
		if (strncmp(entry->d_name, prefix, strlen(prefix)) != 0)
			continue;
		count++;
		if (only_path != NULL && snprintf(only_path, PATH_MAX, "%s/%s",
				directory, entry->d_name) >= PATH_MAX) {
			closedir(stream);
			return -1;
		}
	}
	if (closedir(stream) < 0)
		return -1;
	return count;
}

static int deadline_expired(const struct timespec *deadline)
{
	struct timespec now;

	if (clock_gettime(CLOCK_MONOTONIC, &now) < 0)
		return -1;
	return now.tv_sec > deadline->tv_sec ||
			(now.tv_sec == deadline->tv_sec && now.tv_nsec >= deadline->tv_nsec);
}

static int wait_for_flock(pid_t process, const struct timespec *deadline)
{
	char path[128];
	char contents[256];
	struct timespec delay = { .tv_sec = 0, .tv_nsec = 10000000 };

	if (snprintf(path, sizeof(path), "/proc/%ld/syscall", (long)process) >=
			(int)sizeof(path)) {
		errno = ENAMETOOLONG;
		return -1;
	}
	for (;;) {
		char *end;
		long syscall_number;
		ssize_t count;
		int descriptor = open(path, O_RDONLY | O_CLOEXEC);

		if (descriptor < 0)
			return -1;
		do {
			count = read(descriptor, contents, sizeof(contents) - 1);
		} while (count < 0 && errno == EINTR);
		if (close(descriptor) < 0 || count < 0)
			return -1;
		contents[count] = '\0';
		errno = 0;
		syscall_number = strtol(contents, &end, 10);
		if (errno == 0 && end != contents && syscall_number == SYS_flock)
			return 0;
		if (deadline_expired(deadline) != 0) {
			if (errno == 0)
				errno = ETIMEDOUT;
			return -1;
		}
		while (nanosleep(&delay, &delay) < 0) {
			if (errno != EINTR)
				return -1;
		}
		delay.tv_sec = 0;
		delay.tv_nsec = 10000000;
	}
}

static int wait_for_flock_processes(size_t count, const pid_t *processes)
{
	struct timespec deadline;
	size_t i;

	if (count == 0 || processes == NULL ||
			clock_gettime(CLOCK_MONOTONIC, &deadline) < 0) {
		if (errno == 0)
			errno = EINVAL;
		return -1;
	}
	deadline.tv_sec += 15;
	for (i = 0; i < count; i++) {
		if (wait_for_flock(processes[i], &deadline) < 0)
			return -1;
	}
	return 0;
}

static int wait_for_flock_arguments(int argc, char **argv)
{
	pid_t *processes;
	int i;
	int result;

	if (argc <= 0)
		return 1;
	processes = calloc((size_t)argc, sizeof(*processes));
	if (processes == NULL)
		return 1;
	for (i = 0; i < argc; i++) {
		char *end;
		long value;

		errno = 0;
		value = strtol(argv[i], &end, 10);
		if (errno != 0 || end == argv[i] || *end != '\0' || value <= 0 ||
				(pid_t)value != value) {
			fprintf(stderr, "invalid flock-wait process id: %s\n", argv[i]);
			free(processes);
			return 1;
		}
		processes[i] = (pid_t)value;
	}
	result = wait_for_flock_processes((size_t)argc, processes);
	if (result < 0)
		perror("wait for blocked flock");
	free(processes);
	return result < 0 ? 1 : 0;
}

static size_t child_pids(pid_t parent, pid_t *children, size_t maximum)
{
	char path[128];
	char contents[512];
	char *cursor;
	char *end;
	ssize_t count;
	size_t used = 0;
	int descriptor;

	if (snprintf(path, sizeof(path), "/proc/%ld/task/%ld/children",
			(long)parent, (long)parent) >= (int)sizeof(path))
		return 0;
	descriptor = open(path, O_RDONLY | O_CLOEXEC);
	if (descriptor < 0)
		return 0;
	count = read(descriptor, contents, sizeof(contents) - 1);
	close(descriptor);
	if (count <= 0)
		return 0;
	contents[count] = '\0';
	cursor = contents;
	while (*cursor != '\0' && used < maximum) {
		long value;

		errno = 0;
		value = strtol(cursor, &end, 10);
		if (errno != 0 || end == cursor || value <= 0)
			break;
		children[used++] = (pid_t)value;
		cursor = end;
		while (*cursor == ' ')
			cursor++;
	}
	return used;
}

static int wait_process_gone(pid_t process)
{
	int attempt;

	for (attempt = 0; attempt < 500; attempt++) {
		if (kill(process, 0) < 0 && errno == ESRCH)
			return 0;
		usleep(10000);
	}
	errno = ETIMEDOUT;
	return -1;
}

static int remove_test_directory(const char *directory)
{
	DIR *stream = opendir(directory);
	struct dirent *entry;
	int failed = 0;

	if (stream == NULL)
		return -1;
	while ((entry = readdir(stream)) != NULL) {
		char path[PATH_MAX];

		if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
			continue;
		if (snprintf(path, sizeof(path), "%s/%s", directory, entry->d_name) >=
				(int)sizeof(path) || unlink(path) < 0)
			failed = 1;
	}
	if (closedir(stream) < 0)
		failed = 1;
	if (rmdir(directory) < 0)
		failed = 1;
	return failed ? -1 : 0;
}

static int run_capability_drop_failure_case(void)
{
	static const char original[] = "/bin/true:chown\n";
	char directory[] = "/tmp/cado-capability-drop.XXXXXX";
	char protected_path[PATH_MAX];
	char recovery[PATH_MAX];
	char *contents = NULL;
	size_t length = 0;
	struct scado_edit_request request;
	struct scado_edit_result result;
	int failed = 0;

	if (mkdtemp(directory) == NULL)
		return 1;
	if (snprintf(protected_path, sizeof(protected_path), "%s/protected",
			directory) >= (int)sizeof(protected_path) ||
			write_text(protected_path, original) < 0) {
		(void)remove_test_directory(directory);
		return 1;
	}
	request.username = "capability-drop-test";
	request.protected_path = protected_path;
	request.temporary_directory = directory;
	request.editor = "/bin/true";
	fail_capability_drop = 1;
	result = scado_edit_execute(&request);
	fail_capability_drop = 0;
	if (result.status != SCADO_EDIT_ERROR || result.recovery_path[0] == '\0') {
		fprintf(stderr,
				"capability-drop failure did not follow the editor recovery path\n");
		failed = 1;
	}
	if (count_prefixed(directory, "cado-scado.", recovery) != 1) {
		fprintf(stderr, "capability-drop failure recovery count is not one\n");
		failed = 1;
	} else {
		contents = read_text(recovery, &length);
		if (contents == NULL || length != sizeof(original) - 1 ||
				memcmp(contents, original, sizeof(original) - 1) != 0) {
			fprintf(stderr, "capability-drop failure changed recovery content\n");
			failed = 1;
		}
		free(contents);
		contents = NULL;
	}
	contents = read_text(protected_path, &length);
	if (contents == NULL || length != sizeof(original) - 1 ||
			memcmp(contents, original, sizeof(original) - 1) != 0) {
		fprintf(stderr, "capability-drop failure changed protected content\n");
		failed = 1;
	}
	free(contents);
	if (remove_test_directory(directory) < 0) {
		perror("capability-drop failure cleanup");
		failed = 1;
	}
	return failed;
}

static int set_default_driver_signals(void)
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

static int run_case(const char *self, enum test_phase phase, int signal_number)
{
	static const char original[] = "/bin/true:chown\n";
	char directory[] = "/tmp/cado-signal-matrix.XXXXXX";
	char protected_path[PATH_MAX];
	char editor[PATH_MAX * 2];
	char recovery[PATH_MAX];
	char *protected_contents;
	char *recovery_contents = NULL;
	size_t protected_length = 0;
	size_t recovery_length = 0;
	struct scado_edit_request request;
	struct scado_edit_result result;
	pid_t children[8];
	size_t child_count;
	size_t i;
	pid_t worker;
	int status = 0;
	int failed = 0;
	int lock_fd = -1;

	if (mkdtemp(directory) == NULL ||
			snprintf(protected_path, sizeof(protected_path), "%s/protected",
			directory) >= (int)sizeof(protected_path) ||
			snprintf(gate_path, sizeof(gate_path), "%s/gate", directory) >=
			(int)sizeof(gate_path) || write_text(protected_path, original) < 0)
		return 1;
	if (phase == PHASE_EDITOR) {
		if (snprintf(editor, sizeof(editor), "%s --blocking-editor %s", self,
				gate_path) >= (int)sizeof(editor))
			return 1;
	} else if (snprintf(editor, sizeof(editor), "%s --write-editor %s", self,
			gate_path) >= (int)sizeof(editor)) {
		return 1;
	}
	if (phase == PHASE_COMMIT) {
		lock_fd = open(directory, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
		if (lock_fd < 0 || flock(lock_fd, LOCK_EX) < 0)
			return 1;
	}
	current_phase = phase;
	hash_calls = 0;
	inherited_lock = lock_fd;
	worker = fork();
	if (worker < 0)
		return 1;
	if (worker == 0) {
		struct sigaction action;

		if (inherited_lock >= 0)
			close(inherited_lock);
		if (setpgid(0, 0) < 0)
			_exit(121);
		memset(&action, 0, sizeof(action));
		action.sa_handler = abrupt_exit;
		sigemptyset(&action.sa_mask);
		if (sigaction(SIGUSR1, &action, NULL) < 0)
			_exit(122);
		request.username = "signal-test";
		request.protected_path = protected_path;
		request.temporary_directory = directory;
		request.editor = editor;
		result = scado_edit_execute(&request);
		_exit(result.status == SCADO_EDIT_OK ? 0 : 1);
	}
	(void)setpgid(worker, worker);
	if ((phase == PHASE_COMMIT ? wait_for_flock_processes(1, &worker) :
			wait_for_path(gate_path)) < 0) {
		perror("signal matrix gate");
		failed = 1;
	}
	child_count = child_pids(worker, children,
			sizeof(children) / sizeof(children[0]));
	if (child_count == 0) {
		fprintf(stderr, "phase %d signal %d: no guard/editor child observed\n",
				phase, signal_number);
		failed = 1;
	}
	if (kill(-worker, signal_number) < 0) {
		perror("signal matrix killpg");
		failed = 1;
	}
	if (waitpid(worker, &status, 0) != worker) {
		perror("signal matrix waitpid");
		failed = 1;
	} else if (signal_number == SIGUSR1) {
		if (!WIFEXITED(status) || WEXITSTATUS(status) != 99)
			failed = 1;
	} else if (phase == PHASE_EDITOR &&
			(signal_number == SIGHUP || signal_number == SIGINT ||
			signal_number == SIGQUIT)) {
		if (!WIFEXITED(status) || WEXITSTATUS(status) != 1)
			failed = 1;
	} else if (!WIFSIGNALED(status) || WTERMSIG(status) != signal_number) {
		failed = 1;
	}
	if (lock_fd >= 0) {
		if (flock(lock_fd, LOCK_UN) < 0 || close(lock_fd) < 0)
			failed = 1;
		lock_fd = -1;
	}
	for (i = 0; i < child_count; i++) {
		if (wait_process_gone(children[i]) < 0) {
			fprintf(stderr,
					"phase %d signal %d: child %ld remained after parent loss\n",
					phase, signal_number, (long)children[i]);
			failed = 1;
		}
	}
	if (count_prefixed(directory, "cado-scado.", recovery) != 1) {
		fprintf(stderr, "phase %d signal %d: recovery count is not one\n",
				phase, signal_number);
		failed = 1;
	} else {
		recovery_contents = read_text(recovery, &recovery_length);
		if (recovery_contents == NULL ||
				recovery_length != sizeof(edited_contents) - 1 ||
				memcmp(recovery_contents, edited_contents,
					sizeof(edited_contents) - 1) != 0) {
			fprintf(stderr,
					"phase %d signal %d: recovery content changed\n",
					phase, signal_number);
			failed = 1;
		}
	}
	free(recovery_contents);
	if (count_prefixed(directory, ".cado-stage.", NULL) != 0) {
		fprintf(stderr, "phase %d signal %d: staging file leaked\n", phase,
				signal_number);
		failed = 1;
	}
	protected_contents = read_text(protected_path, &protected_length);
	if (protected_contents == NULL ||
			protected_length != sizeof(original) - 1 ||
			memcmp(protected_contents, original, sizeof(original) - 1) != 0) {
		fprintf(stderr, "phase %d signal %d: protected file changed\n", phase,
				signal_number);
		failed = 1;
	}
	free(protected_contents);
	if (remove_test_directory(directory) < 0) {
		perror("signal matrix cleanup");
		failed = 1;
	}
	if (failed)
		fprintf(stderr, "signal matrix failed: phase=%d signal=%d status=%d\n",
				phase, signal_number, status);
	return failed;
}

static int run_commit_case_argument(const char *program, const char *argument)
{
	const int signals[] = {SIGHUP, SIGINT, SIGQUIT, SIGTERM, SIGKILL, SIGUSR1};
	char self[PATH_MAX];
	char *end;
	long value;
	size_t i;

	errno = 0;
	value = strtol(argument, &end, 10);
	if (errno != 0 || end == argument || *end != '\0' || value <= 0 ||
			(int)value != value || realpath(program, self) == NULL)
		return 1;
	for (i = 0; i < sizeof(signals) / sizeof(signals[0]); i++) {
		if (value == signals[i])
			return run_case(self, PHASE_COMMIT, (int)value);
	}
	fprintf(stderr, "unsupported commit-case signal: %s\n", argument);
	return 1;
}

int main(int argc, char **argv)
{
	const int signals[] = {SIGHUP, SIGINT, SIGQUIT, SIGTERM, SIGKILL, SIGUSR1};
	char self[PATH_MAX];
	struct rlimit core_limit = { .rlim_cur = 0, .rlim_max = 0 };
	size_t phase;
	size_t signal_index;
	int failures = 0;

	(void)setrlimit(RLIMIT_CORE, &core_limit);
	if (argc >= 3 && strcmp(argv[1], "--wait-flock") == 0)
		return wait_for_flock_arguments(argc - 2, argv + 2);
	if (argc == 3 && strcmp(argv[1], "--run-commit-case") == 0) {
		if (set_default_driver_signals() < 0) {
			perror("commit-case signal normalization");
			return 1;
		}
		return run_commit_case_argument(argv[0], argv[2]);
	}
	if (argc == 7 && strcmp(argv[1], "--identity-driver") == 0)
		return identity_driver(argv[2], argv[3], argv[4], argv[5], argv[6]);
	if (argc == 4 && strcmp(argv[1], "--blocking-editor") == 0)
		return editor_helper(argv[2], argv[3], 1);
	if (argc == 4 && strcmp(argv[1], "--write-editor") == 0)
		return editor_helper(argv[2], argv[3], 0);
	if (argc != 1 || realpath(argv[0], self) == NULL)
		return 1;
	if (set_default_driver_signals() < 0) {
		perror("signal-matrix signal normalization");
		return 1;
	}
	failures += run_capability_drop_failure_case();
	for (phase = PHASE_EDITOR; phase <= PHASE_COMMIT; phase++) {
		for (signal_index = 0;
				signal_index < sizeof(signals) / sizeof(signals[0]);
				signal_index++)
			failures += run_case(self, (enum test_phase)phase,
					signals[signal_index]);
	}
	return failures == 0 ? 0 : 1;
}
