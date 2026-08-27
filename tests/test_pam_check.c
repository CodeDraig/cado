#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <security/pam_appl.h>
#include <security/pam_misc.h>

#include <pam_check.h>

enum fault_mode {
	FAULT_START,
	FAULT_AUTHENTICATE,
	FAULT_END,
	FAULT_AUTHENTICATE_AND_END
};

static enum fault_mode mode;
static int start_calls;
static int authenticate_calls;
static int end_calls;
static int strerror_calls;
static int end_status;

int pam_start(const char *service_name, const char *user,
		const struct pam_conv *conversation, pam_handle_t **handle)
{
	start_calls++;
	if (strcmp(service_name, "cado") != 0 || strcmp(user, "test-user") != 0 ||
			conversation->conv != misc_conv)
		return PAM_ABORT;
	*handle = (pam_handle_t *)(uintptr_t)1;
	return mode == FAULT_START ? PAM_SYSTEM_ERR : PAM_SUCCESS;
}

int pam_authenticate(pam_handle_t *handle, int flags)
{
	if (handle != (pam_handle_t *)(uintptr_t)1 || flags != 0)
		return PAM_ABORT;
	authenticate_calls++;
	return mode == FAULT_AUTHENTICATE ||
			mode == FAULT_AUTHENTICATE_AND_END ? PAM_AUTH_ERR : PAM_SUCCESS;
}

int pam_end(pam_handle_t *handle, int status)
{
	if (handle != (pam_handle_t *)(uintptr_t)1)
		return PAM_ABORT;
	end_calls++;
	end_status = status;
	return mode == FAULT_END || mode == FAULT_AUTHENTICATE_AND_END ?
			PAM_SYSTEM_ERR : PAM_SUCCESS;
}

const char *pam_strerror(pam_handle_t *handle, int status)
{
	if (handle != (pam_handle_t *)(uintptr_t)1 || status != PAM_AUTH_ERR)
		return "unexpected PAM status";
	strerror_calls++;
	return "injected authentication rejection";
}

int misc_conv(int message_count, const struct pam_message **messages,
		struct pam_response **responses, void *application_data)
{
	(void)message_count;
	(void)messages;
	(void)responses;
	(void)application_data;
	return PAM_CONV_ERR;
}

static char *run_and_capture(enum fault_mode selected, int *status)
{
	FILE *capture = tmpfile();
	char *output = NULL;
	long length;
	int saved_stderr;

	if (capture == NULL)
		return NULL;
	saved_stderr = dup(STDERR_FILENO);
	if (saved_stderr < 0 || dup2(fileno(capture), STDERR_FILENO) < 0) {
		if (saved_stderr >= 0)
			close(saved_stderr);
		fclose(capture);
		return NULL;
	}
	mode = selected;
	start_calls = 0;
	authenticate_calls = 0;
	end_calls = 0;
	strerror_calls = 0;
	end_status = -1;
	*status = pam_check("test-user");
	fflush(stderr);
	if (dup2(saved_stderr, STDERR_FILENO) < 0 || close(saved_stderr) < 0) {
		fclose(capture);
		return NULL;
	}
	if (fseek(capture, 0, SEEK_END) < 0 || (length = ftell(capture)) < 0 ||
			fseek(capture, 0, SEEK_SET) < 0) {
		fclose(capture);
		return NULL;
	}
	output = malloc((size_t)length + 1);
	if (output == NULL || fread(output, 1, (size_t)length, capture) !=
			(size_t)length) {
		free(output);
		fclose(capture);
		return NULL;
	}
	output[length] = '\0';
	if (fclose(capture) != 0) {
		free(output);
		return NULL;
	}
	return output;
}

static int check_case(enum fault_mode selected, int expected_status,
		int expected_authenticate, int expected_end, int expected_strerror,
		int expected_end_status, const char *first_diagnostic,
		const char *second_diagnostic)
{
	char *output;
	char *first;
	char *second = NULL;
	int status;
	int failed = 0;

	output = run_and_capture(selected, &status);
	if (output == NULL)
		return 1;
	first = strstr(output, first_diagnostic);
	if (second_diagnostic != NULL)
		second = strstr(output, second_diagnostic);
	if (status != expected_status || start_calls != 1 ||
			authenticate_calls != expected_authenticate ||
			end_calls != expected_end || strerror_calls != expected_strerror ||
			end_status != expected_end_status || first == NULL ||
			(second_diagnostic != NULL && (second == NULL || second <= first))) {
		fprintf(stderr,
				"mode=%d status=%d calls=%d/%d/%d/%d end_status=%d output=%s\n",
				selected, status, start_calls, authenticate_calls, end_calls,
				strerror_calls, end_status, output);
		failed = 1;
	}
	free(output);
	return failed;
}

int main(void)
{
	int failures = 0;

	failures += check_case(FAULT_START, PAM_SYSTEM_ERR, 0, 0, 0, -1,
			"PAM initialization failed with code", NULL);
	failures += check_case(FAULT_AUTHENTICATE, PAM_AUTH_ERR, 1, 1, 1,
			PAM_AUTH_ERR, "PAM authentication failed: injected", NULL);
	failures += check_case(FAULT_END, PAM_SYSTEM_ERR, 1, 1, 0, PAM_SUCCESS,
			"PAM teardown failed with code", NULL);
	failures += check_case(FAULT_AUTHENTICATE_AND_END, PAM_SYSTEM_ERR, 1, 1, 1,
			PAM_AUTH_ERR, "PAM authentication failed: injected",
			"PAM teardown failed with code");
	return failures == 0 ? 0 : 1;
}
