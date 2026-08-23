/*
 * cado: checked Linux capability operations
 * Copyright (C) 2016 Renzo Davoli, University of Bologna
 *
 * This file is part of cado and is distributed under the GNU GPL v2 or later.
 */

#include <errno.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sys/capability.h>
#include <sys/prctl.h>

#include <set_ambient_cap.h>

static void report_capability_error(const char *operation, cap_value_t capability,
		int error_number)
{
	char *name = cap_to_name(capability);
	int release_error = 0;

	errno = error_number;
	if (name != NULL) {
		fprintf(stderr, "cado: cannot %s %s: ", operation, name);
		if (cap_free(name) < 0)
			release_error = errno;
	} else {
		fprintf(stderr, "cado: cannot %s capability %d: ", operation,
				(int)capability);
	}
	fprintf(stderr, "%s\n", strerror(error_number));
	if (release_error != 0)
		fprintf(stderr, "cado: cannot release capability name: %s\n",
				strerror(release_error));
	errno = error_number;
}

static int update_inheritable(uint64_t capset, int clear_only)
{
	cap_t capabilities;
	cap_value_t capability;

	capabilities = cap_get_proc();
	if (capabilities == NULL) {
		perror("cado: cap_get_proc");
		return -1;
	}
	for (capability = 0; capability <= CAP_LAST_CAP; capability++) {
		cap_flag_value_t value = CAP_CLEAR;
		int selected = (capset & (UINT64_C(1) << capability)) != 0;

		if (!clear_only && selected)
			value = CAP_SET;
		if (clear_only && !selected)
			continue;
		if (cap_set_flag(capabilities, CAP_INHERITABLE, 1, &capability,
				value) < 0) {
			int saved_errno = errno;

			report_capability_error(value == CAP_SET ?
					"set inheritable" : "clear inheritable", capability,
					saved_errno);
			if (cap_free(capabilities) < 0)
				fprintf(stderr, "cado: cannot release process capabilities: %s\n",
						strerror(errno));
			errno = saved_errno;
			return -1;
		}
	}
	if (cap_set_proc(capabilities) < 0) {
		int saved_errno = errno;

		perror("cado: cap_set_proc");
		if (cap_free(capabilities) < 0)
			fprintf(stderr, "cado: cannot release process capabilities: %s\n",
					strerror(errno));
		errno = saved_errno;
		return -1;
	}
	if (cap_free(capabilities) < 0) {
		perror("cado: cap_free");
		return -1;
	}
	return 0;
}

int set_ambient_cap(uint64_t capset)
{
	cap_value_t capability;

#if CAP_LAST_CAP < 63
	if ((capset >> (CAP_LAST_CAP + 1)) != 0) {
		errno = EINVAL;
		return -1;
	}
#endif
	if (update_inheritable(capset, 0) < 0)
		return -1;

	for (capability = 0; capability <= CAP_LAST_CAP; capability++) {
		int operation = (capset & (UINT64_C(1) << capability)) != 0 ?
				PR_CAP_AMBIENT_RAISE : PR_CAP_AMBIENT_LOWER;

		if (prctl(PR_CAP_AMBIENT, operation, capability, 0, 0) < 0) {
			int saved_errno = errno;
			int cleanup_error = 0;

			report_capability_error(operation == PR_CAP_AMBIENT_RAISE ?
					"raise ambient" : "lower ambient", capability,
					saved_errno);
			if (prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0) < 0)
				cleanup_error = errno;
			if (cleanup_error != 0)
				fprintf(stderr, "cado: cannot clear ambient capabilities after failure: %s\n",
						strerror(cleanup_error));
			errno = saved_errno;
			return -1;
		}
	}
	return 0;
}

int drop_ambient_cap(uint64_t capset)
{
	cap_value_t capability;

	if (update_inheritable(capset, 1) < 0)
		return -1;
	for (capability = 0; capability <= CAP_LAST_CAP; capability++) {
		if ((capset & (UINT64_C(1) << capability)) != 0 &&
				prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_LOWER, capability,
					0, 0) < 0) {
			int saved_errno = errno;

			report_capability_error("lower ambient", capability, saved_errno);
			errno = saved_errno;
			return -1;
		}
	}
	return 0;
}

int drop_all_capabilities(void)
{
	cap_t empty;

	if (prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0) < 0)
		return -1;
	empty = cap_init();
	if (empty == NULL)
		return -1;
	if (cap_set_proc(empty) < 0) {
		int saved_errno = errno;

		if (cap_free(empty) < 0)
			fprintf(stderr, "cado: cannot release empty capability set: %s\n",
					strerror(errno));
		errno = saved_errno;
		return -1;
	}
	if (cap_free(empty) < 0)
		return -1;
	return 0;
}

static int set_dac_read_search(cap_flag_value_t value)
{
	cap_value_t capability = CAP_DAC_READ_SEARCH;
	cap_t capabilities = cap_get_proc();

	if (capabilities == NULL) {
		perror("cado: cap_get_proc");
		return -1;
	}
	if (cap_set_flag(capabilities, CAP_EFFECTIVE, 1, &capability, value) < 0) {
		int saved_errno = errno;

		report_capability_error(value == CAP_SET ? "raise effective" :
				"lower effective", capability, saved_errno);
		if (cap_free(capabilities) < 0)
			fprintf(stderr, "cado: cannot release process capabilities: %s\n",
					strerror(errno));
		errno = saved_errno;
		return -1;
	}
	if (cap_set_proc(capabilities) < 0) {
		int saved_errno = errno;

		perror("cado: cap_set_proc");
		if (cap_free(capabilities) < 0)
			fprintf(stderr, "cado: cannot release process capabilities: %s\n",
					strerror(errno));
		errno = saved_errno;
		return -1;
	}
	if (cap_free(capabilities) < 0) {
		perror("cado: cap_free");
		return -1;
	}
	return 0;
}

int raise_cap_dac_read_search(void)
{
	return set_dac_read_search(CAP_SET);
}

int lower_cap_dac_read_search(void)
{
	return set_dac_read_search(CAP_CLEAR);
}
