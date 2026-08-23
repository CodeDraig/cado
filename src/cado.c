/*
 * cado: execute a command in a capability ambient
 * Copyright (C) 2016 Renzo Davoli, University of Bologna
 *
 * This file is part of cado and is distributed under the GNU GPL v2 or later.
 */

#include <errno.h>
#include <getopt.h>
#include <inttypes.h>
#include <libgen.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/capability.h>

#include <security/pam_appl.h>

#include <cado_scado_check.h>
#include <cado_policy.h>
#include <capset_from_namelist.h>
#include <get_user_groups.h>
#include <pam_check.h>
#include <read_conf.h>
#include <set_ambient_cap.h>

enum cado_mode {
	CADO_MODE_RUN = 0,
	CADO_MODE_LIST,
	CADO_MODE_SETCAP
};

enum cado_authentication_mode {
	CADO_AUTHENTICATE_WITH_PAM = 0,
	CADO_AUTHENTICATE_WITH_SCADO
};

struct cado_request {
	enum cado_mode mode;
	int verbose;
	int force;
	enum cado_authentication_mode authentication;
	uint64_t requested;
	char **command;
};

static const struct option long_options[] = {
	{"help",    no_argument, NULL, 'h'},
	{"force",   no_argument, NULL, 'f'},
	{"verbose", no_argument, NULL, 'v'},
	{"setcap",  no_argument, NULL, 's'},
	{"scado",   no_argument, NULL, 'S'},
	{0, 0, 0, 0}
};

static int usage(const char *program)
{
	fprintf(stderr, "%s - execute a command in a different capability ambient\n\n",
			program);
	fprintf(stderr, "usage: %s OPTIONS capability_list [command [args]]\n\n",
			program);
	fprintf(stderr, "Options:\n");
	fprintf(stderr, "  -h, --help         display help message and exit\n");
	fprintf(stderr, "  -f, --force        grant the allowed intersection\n");
	fprintf(stderr, "  -v, --verbose      generate extra output\n");
	fprintf(stderr, "  -S, --scado        require an absolute scado-authorized command\n");
	fprintf(stderr, "  -s, --setcap       set the minimum caps for %s (root access)\n",
			program);
	return 1;
}

static int print_capset(uint64_t capset, const char *indent)
{
	cap_value_t capability;
	int count = 0;

	if (capset == 0) {
		printf("%s   %016" PRIx64 " NONE\n", indent, UINT64_C(0));
		return 0;
	}
	for (capability = 0; capability <= CAP_LAST_CAP; capability++) {
		if ((capset & (UINT64_C(1) << capability)) != 0) {
			char *name = cap_to_name(capability);

			if (name == NULL)
				return -1;
			count++;
			printf("%s%2d %016" PRIx64 " %s\n", indent, capability,
					UINT64_C(1) << capability, name);
			if (cap_free(name) < 0)
				return -1;
		}
	}
	if (count > 1)
		printf("%s   %016" PRIx64 "\n", indent, capset);
	return 0;
}

static int flush_capability_output(const char *program)
{
	errno = 0;
	if (fflush(stdout) == 0 && !ferror(stdout))
		return 0;
	fprintf(stderr, "%s: cannot write capability output: %s\n", program,
			strerror(errno != 0 ? errno : EIO));
	return -1;
}

static int parse_request(int argc, char **argv, struct cado_request *request)
{
	int setcap = 0;
	int option;
	enum cado_cap_parse_status parse_status;

	memset(request, 0, sizeof(*request));
	request->mode = CADO_MODE_RUN;
	request->authentication = CADO_AUTHENTICATE_WITH_PAM;
	opterr = 0;
	while ((option = getopt_long(argc, argv, "+hfvsS", long_options, NULL)) >= 0) {
		switch (option) {
		case 'h':
			return 1;
		case 'f':
			request->force = 1;
			break;
		case 'v':
			request->verbose = 1;
			break;
		case 's':
			setcap = 1;
			break;
		case 'S':
			request->authentication = CADO_AUTHENTICATE_WITH_SCADO;
			break;
		default:
			return -1;
		}
	}

	if (setcap) {
		if (request->force ||
				request->authentication == CADO_AUTHENTICATE_WITH_SCADO ||
				optind != argc)
			return -1;
		request->mode = CADO_MODE_SETCAP;
		return 0;
	}
	if (optind == argc) {
		if (!request->verbose || request->force ||
				request->authentication == CADO_AUTHENTICATE_WITH_SCADO)
			return -1;
		request->mode = CADO_MODE_LIST;
		return 0;
	}

	parse_status = capset_from_namelist(argv[optind], &request->requested);
	if (parse_status != CADO_CAP_PARSE_OK) {
		fprintf(stderr, "List of capabilities: %s\n",
				cado_cap_parse_status_string(parse_status));
		return -2;
	}
	optind++;
	if (optind < argc)
		request->command = argv + optind;
	if (request->authentication == CADO_AUTHENTICATE_WITH_SCADO &&
			(request->command == NULL ||
			request->command[0][0] != '/'))
		return -1;
	return 0;
}

static int report_config_error(const char *program,
		const struct cado_config_result *result)
{
	fprintf(stderr, "%s: %s", program,
			cado_config_status_string(result->status));
	if (result->error_number != 0)
		fprintf(stderr, ": %s", strerror(result->error_number));
	if (result->line != 0)
		fprintf(stderr, " at line %zu", result->line);
	fputc('\n', stderr);
	if (result->cleanup_error != 0)
		fprintf(stderr, "%s: configuration cleanup also failed: %s\n",
				program, strerror(result->cleanup_error));
	return 2;
}

static int execute_setcap(const char *program, const struct cado_request *request)
{
	struct cado_config_result configured;
	uint64_t required;

	if (setuid(0) != 0 || geteuid() != 0) {
		fprintf(stderr, "setcap requires root access %d\n", (int)geteuid());
		return 2;
	}
	configured = cado_config_union();
	if (configured.status != CADO_CONFIG_OK)
		return report_config_error(program, &configured);
	required = configured.capabilities |
			(UINT64_C(1) << CAP_DAC_READ_SEARCH);
	if (request->verbose) {
		printf("Capability needed by %s:\n", program);
		if (print_capset(required, "  ") < 0) {
			fprintf(stderr, "%s: cannot format capability set\n", program);
			return 2;
		}
	}
	if (request->verbose && flush_capability_output(program) < 0)
		return 2;
	if (set_self_capability(required) < 0) {
		fprintf(stderr, "Cannot set %s capabilities: %s\n", program,
				strerror(errno));
		return 2;
	}
	return 0;
}

static int load_identity(const char *program, struct cado_identity *identity)
{
	enum cado_identity_status status = cado_identity_load(getuid(), identity);

	if (status == CADO_IDENTITY_OK)
		return 0;
	if (status == CADO_IDENTITY_NO_PASSWD)
		fprintf(stderr, "No passwd entry for user '%d'\n", (int)getuid());
	else if (status == CADO_IDENTITY_GROUP_LOOKUP)
		fprintf(stderr, "%s: cannot resolve the current user's groups\n", program);
	else
		fprintf(stderr, "%s: cannot allocate the current user's identity\n", program);
	return 2;
}

static int execute_list(const char *program, const struct cado_identity *identity)
{
	struct cado_config_result authorized = cado_config_authorize(identity,
			UINT64_MAX);

	if (authorized.status != CADO_CONFIG_OK)
		return report_config_error(program, &authorized);
	printf("Allowed ambient capabilities:\n");
	if (print_capset(authorized.capabilities, "  ") < 0) {
		fprintf(stderr, "%s: cannot format capability set\n", program);
		return 2;
	}
	return flush_capability_output(program) == 0 ? 0 : 2;
}

static int execute_command(const char *program, const struct cado_request *request,
		struct cado_identity *identity)
{
	char *shell_command[] = { getenv("SHELL"), NULL };
	char **command = request->command;
	struct cado_config_result authorized;
	struct cado_verified_executable verified;
	struct cado_scado_result scado_result;
	uint64_t allowed;
	struct cado_policy_result policy;
	const char *exec_path;
	int result = 2;

	cado_verified_executable_init(&verified);
	if (command == NULL) {
		if (shell_command[0] == NULL) {
			fprintf(stderr, "Error: $SHELL env variable not set.\n");
			return 1;
		}
		command = shell_command;
	}
	if (request->verbose) {
		printf("Requested ambient capabilities:\n");
		if (print_capset(request->requested, "  ") < 0)
			return 2;
	}
	authorized = cado_config_authorize(identity, request->requested);
	if (authorized.status != CADO_CONFIG_OK)
		return report_config_error(program, &authorized);
	if (request->verbose && authorized.condition_failed)
		fprintf(stderr, "cado: one or more matching conditions denied authorization\n");
	allowed = authorized.capabilities;

	if (request->authentication == CADO_AUTHENTICATE_WITH_SCADO) {
		scado_result = cado_scado_prepare(identity->username, command[0],
				&verified);
		if (request->verbose && scado_result.status != CADO_SCADO_OK)
		{
			fprintf(stderr, "scado: %s",
					cado_scado_status_string(scado_result.status));
			if (scado_result.error_number != 0)
				fprintf(stderr, ": %s", strerror(scado_result.error_number));
			fputc('\n', stderr);
			if (scado_result.cleanup_error != 0)
				fprintf(stderr, "scado: cleanup also failed: %s\n",
						strerror(scado_result.cleanup_error));
		}
		if (request->verbose) {
			printf("Scado permitted capabilities for %s:\n", command[0]);
			if (print_capset(scado_result.status == CADO_SCADO_OK ?
					scado_result.capabilities : 0, "  ") < 0)
				goto out;
		}
		if (scado_result.status != CADO_SCADO_OK) {
			fprintf(stderr, "%s: Permission denied\n", program);
			goto out;
		}
		allowed &= scado_result.capabilities;
	}

	policy = cado_apply_policy(request->requested, allowed, request->force);
	if (policy.unavailable != 0) {
		if (request->verbose) {
			printf("Unavailable ambient capabilities:\n");
			if (print_capset(policy.unavailable, "  ") < 0)
				goto out;
		}
		if (policy.status == CADO_POLICY_DENIED) {
			fprintf(stderr, "%s: Permission denied\n", program);
			goto out;
		}
	}
	if (setuid(getuid()) < 0) {
		fprintf(stderr, "%s: setuid failure: %s\n", program, strerror(errno));
		goto out;
	}
	if (request->authentication == CADO_AUTHENTICATE_WITH_PAM &&
			pam_check(identity->username) != PAM_SUCCESS) {
		fprintf(stderr, "%s: Authentication failure\n", program);
		goto out;
	}
	if (policy.granted != 0 && set_ambient_cap(policy.granted) < 0) {
		fprintf(stderr, "%s: cannot set ambient capabilities: %s\n",
				program, strerror(errno));
		goto out;
	}
	if (request->verbose && policy.unavailable != 0) {
		printf("Granted ambient capabilities:\n");
		if (print_capset(policy.granted, "  ") < 0)
			goto out;
	}

	exec_path = verified.path[0] == '\0' ? command[0] : verified.path;
	if (flush_capability_output(program) < 0)
		goto out;
	cado_identity_free(identity);
	execvp(exec_path, command);
	fprintf(stderr, "%s: cannot execute %s: %s\n", program, command[0],
			strerror(errno));
	result = 2;

out:
	if (cado_verified_executable_release(&verified) < 0) {
		fprintf(stderr, "%s: verified-copy cleanup failed: %s\n", program,
				strerror(errno));
		result = 2;
	}
	return result;
}

int main(int argc, char **argv)
{
	const char *program = basename(argv[0]);
	struct cado_request request;
	struct cado_identity identity = {0};
	int parse_status;
	int result;

	parse_status = parse_request(argc, argv, &request);
	if (parse_status > 0)
		return usage(program);
	if (parse_status < 0)
		return parse_status == -2 ? 2 : usage(program);
	if (request.mode == CADO_MODE_SETCAP)
		return execute_setcap(program, &request);
	result = load_identity(program, &identity);
	if (result != 0)
		return result;
	if (request.mode == CADO_MODE_LIST)
		result = execute_list(program, &identity);
	else
		result = execute_command(program, &request, &identity);
	cado_identity_free(&identity);
	return result;
}
