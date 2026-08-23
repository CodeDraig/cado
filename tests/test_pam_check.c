#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <security/pam_appl.h>
#include <security/pam_misc.h>

#include <pam_check.h>

static int authenticate_calls;
static int end_calls;
static int strerror_calls;

int pam_start(const char *service_name, const char *user,
		const struct pam_conv *conversation, pam_handle_t **handle)
{
	if (strcmp(service_name, "cado") != 0 || strcmp(user, "test-user") != 0 ||
			conversation->conv != misc_conv)
		return PAM_ABORT;
	*handle = (pam_handle_t *)(uintptr_t)1;
	return PAM_SYSTEM_ERR;
}

int pam_authenticate(pam_handle_t *handle, int flags)
{
	(void)handle;
	(void)flags;
	authenticate_calls++;
	return PAM_SUCCESS;
}

int pam_end(pam_handle_t *handle, int status)
{
	(void)handle;
	(void)status;
	end_calls++;
	return PAM_SUCCESS;
}

const char *pam_strerror(pam_handle_t *handle, int status)
{
	(void)handle;
	(void)status;
	strerror_calls++;
	return "unexpected pam_strerror call";
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

int main(void)
{
	int status = pam_check("test-user");

	if (status != PAM_SYSTEM_ERR || authenticate_calls != 0 || end_calls != 0 ||
			strerror_calls != 0) {
		fprintf(stderr,
				"status=%d authenticate=%d end=%d strerror=%d\n",
				status, authenticate_calls, end_calls, strerror_calls);
		return 1;
	}
	return 0;
}
