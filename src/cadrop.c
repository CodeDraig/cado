/*
 * cadrop: execute a command after dropping ambient capabilities
 * Copyright (C) 2016 Renzo Davoli and Davide Berardi, University of Bologna
 *
 * This file is part of cado and is distributed under the GNU GPL v2 or later.
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <capset_from_namelist.h>
#include <set_ambient_cap.h>

static int is_all_form(const char *argument)
{
	return argument == NULL || strcmp(argument, "-") == 0 ||
		strcmp(argument, "all") == 0;
}

int main(int argc, char **argv)
{
	uint64_t capabilities = UINT64_MAX;
	char *shell[] = { getenv("SHELL"), NULL };
	char **command;

	if (argc == 1) {
		command = shell;
	} else {
		if (!is_all_form(argv[1])) {
			enum cado_cap_parse_status status =
					capset_from_namelist(argv[1], &capabilities);

			if (status != CADO_CAP_PARSE_OK) {
				fprintf(stderr, "error parsing capabilities: %s\n",
						cado_cap_parse_status_string(status));
				return 2;
			}
		}
		command = argv + 2;
		if (command[0] == NULL)
			command = shell;
	}
	if (command[0] == NULL) {
		fprintf(stderr, "Error: $SHELL env variable not set.\n");
		return 1;
	}
	if (drop_ambient_cap(capabilities) < 0) {
		perror("cadrop: cannot drop ambient capabilities");
		return 2;
	}
	execvp(command[0], command);
	perror("exec");
	return 2;
}
