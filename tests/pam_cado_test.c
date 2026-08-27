#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <security/pam_appl.h>
#include <security/pam_modules.h>

#define DEFAULT_TIMEOUT_SECONDS 15
#define MAX_TOKEN_LENGTH 48

static int valid_token(const char *token)
{
	size_t i;
	size_t length;

	if (token == NULL || (length = strlen(token)) == 0 ||
			length > MAX_TOKEN_LENGTH)
		return 0;
	for (i = 0; i < length; i++) {
		unsigned char byte = (unsigned char)token[i];

		if (!isalnum(byte) && byte != '_' && byte != '-')
			return 0;
	}
	return 1;
}

static int parse_timeout(const char *argument)
{
	char *end;
	long value;

	if (argument == NULL || strncmp(argument, "timeout=", 8) != 0)
		return DEFAULT_TIMEOUT_SECONDS;
	errno = 0;
	value = strtol(argument + 8, &end, 10);
	if (errno != 0 || *end != '\0' || value < 1 || value > 60)
		return -1;
	return (int)value;
}

static int write_entered(const char *path)
{
	char contents[64];
	int descriptor;
	int length;
	ssize_t written;

	descriptor = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
	if (descriptor < 0)
		return -1;
	length = snprintf(contents, sizeof(contents), "%ld\n", (long)getpid());
	written = write(descriptor, contents, (size_t)length);
	if (close(descriptor) < 0 || written != length)
		return -1;
	return 0;
}

static int read_release(const char *path)
{
	char contents[16];
	int descriptor;
	ssize_t count;

	descriptor = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
	if (descriptor < 0)
		return errno == ENOENT ? PAM_INCOMPLETE : PAM_SYSTEM_ERR;
	count = read(descriptor, contents, sizeof(contents) - 1);
	if (close(descriptor) < 0 || count < 0)
		return PAM_SYSTEM_ERR;
	contents[count] = '\0';
	if (strcmp(contents, "success\n") == 0)
		return PAM_SUCCESS;
	if (strcmp(contents, "deny\n") == 0)
		return PAM_AUTH_ERR;
	return PAM_SYSTEM_ERR;
}

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *handle, int flags, int argc,
		const char **argv)
{
	const char *token = getenv("CADO_TEST_TOKEN");
	char entered[PATH_MAX];
	char release[PATH_MAX];
	struct timespec delay = { .tv_sec = 0, .tv_nsec = 20000000 };
	struct timespec started;
	struct timespec now;
	int timeout = DEFAULT_TIMEOUT_SECONDS;
	int status;

	(void)handle;
	(void)flags;
	if (argc < 1 || argv[0][0] != '/' || !valid_token(token))
		return PAM_SERVICE_ERR;
	if (argc > 1 && (timeout = parse_timeout(argv[1])) < 0)
		return PAM_SERVICE_ERR;
	if (snprintf(entered, sizeof(entered), "%s/entered.%s", argv[0], token) >=
			(int)sizeof(entered) ||
			snprintf(release, sizeof(release), "%s/release.%s", argv[0], token) >=
			(int)sizeof(release))
		return PAM_SERVICE_ERR;
	if (write_entered(entered) < 0)
		return PAM_SYSTEM_ERR;
	if (clock_gettime(CLOCK_MONOTONIC, &started) < 0)
		return PAM_SYSTEM_ERR;
	for (;;) {
		status = read_release(release);
		if (status != PAM_INCOMPLETE)
			return status;
		if (clock_gettime(CLOCK_MONOTONIC, &now) < 0)
			return PAM_SYSTEM_ERR;
		if (now.tv_sec - started.tv_sec >= timeout)
			return PAM_SYSTEM_ERR;
		while (nanosleep(&delay, &delay) < 0) {
			if (errno != EINTR)
				return PAM_SYSTEM_ERR;
		}
		delay.tv_sec = 0;
		delay.tv_nsec = 20000000;
	}
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t *handle, int flags, int argc,
		const char **argv)
{
	(void)handle;
	(void)flags;
	(void)argc;
	(void)argv;
	return PAM_SUCCESS;
}
