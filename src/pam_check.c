/*
 * cado: PAM authentication boundary
 * Copyright (C) 2016 Renzo Davoli, University of Bologna
 *
 * This file is part of cado and is distributed under the GNU GPL v2 or later.
 */

#include <stdio.h>
#include <security/pam_appl.h>
#include <security/pam_misc.h>

#include <pam_check.h>

int pam_check(const char *username)
{
	pam_handle_t *handle = NULL;
	struct pam_conv conversation = {
		.conv = misc_conv,
		.appdata_ptr = NULL
	};
	int authentication;
	int teardown;

	authentication = pam_start("cado", username, &conversation, &handle);
	if (authentication != PAM_SUCCESS) {
		fprintf(stderr, "cado: PAM initialization failed with code %d\n",
				authentication);
		return authentication;
	}

	authentication = pam_authenticate(handle, 0);
	if (authentication != PAM_SUCCESS) {
		fprintf(stderr, "cado: PAM authentication failed: %s\n",
				pam_strerror(handle, authentication));
	}
	teardown = pam_end(handle, authentication);
	if (teardown != PAM_SUCCESS) {
		fprintf(stderr, "cado: PAM teardown failed with code %d\n", teardown);
		return teardown;
	}
	return authentication;
}
