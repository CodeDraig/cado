/*
 * caprint: print the ambient capability set of a process
 * Copyright (C) 2016 Renzo Davoli, University of Bologna
 *
 * This file is part of cado and is distributed under the GNU GPL v2 or later.
 */

#include <errno.h>
#include <getopt.h>
#include <inttypes.h>
#include <libgen.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/capability.h>

enum caprint_format {
	CAPRINT_DEFAULT = 0,
	CAPRINT_COMPACT,
	CAPRINT_PROMPT,
	CAPRINT_LONG
};

struct caprint_request {
	enum caprint_format format;
	pid_t pid;
};

static const struct option long_options[] = {
	{"help",    no_argument, NULL, 'h'},
	{"prompt",  no_argument, NULL, 'p'},
	{"compact", no_argument, NULL, 'c'},
	{"long",    no_argument, NULL, 'l'},
	{0, 0, 0, 0}
};

static int usage(const char *program)
{
	fprintf(stderr, "%s - show the current capability ambient\n\n", program);
	fprintf(stderr, "usage: %s OPTIONS [pid]\n\n", program);
	fprintf(stderr, "Options:\n");
	fprintf(stderr, "  -h, --help         display help message and exit\n");
	fprintf(stderr, "  -p, --prompt       single line output for the command prompt\n");
	fprintf(stderr, "  -c, --compact      single line without cap_ prefix\n");
	fprintf(stderr, "  -l, --long         display cap# and mask\n");
	return 1;
}

static int select_format(enum caprint_format *current,
		enum caprint_format selected)
{
	if (*current != CAPRINT_DEFAULT && *current != selected)
		return -1;
	*current = selected;
	return 0;
}

static int parse_positive_pid(const char *text, pid_t *pid)
{
	char *end;
	uintmax_t value;

	if (text == NULL || *text == '\0')
		return -1;
	{
		const unsigned char *scan = (const unsigned char *)text;

		for (; *scan != '\0'; scan++) {
			if (*scan < '0' || *scan > '9')
				return -1;
		}
	}
	errno = 0;
	value = strtoumax(text, &end, 10);
	if (errno == ERANGE || *end != '\0' || value == 0 || value > INT_MAX)
		return -1;
	*pid = (pid_t)value;
	return 0;
}

static int parse_request(int argc, char **argv, struct caprint_request *request)
{
	int option;
	int i;

	request->format = CAPRINT_DEFAULT;
	request->pid = getpid();
	for (i = 1; i < argc; i++) {
		if (argv[i][0] == '-' && argv[i][1] >= '0' && argv[i][1] <= '9') {
			fprintf(stderr, "caprint: PID must be a strict positive decimal integer\n");
			return -2;
		}
		if (strcmp(argv[i], "--") == 0)
			break;
	}
	opterr = 0;
	while ((option = getopt_long(argc, argv, "+hpcl", long_options, NULL)) >= 0) {
		switch (option) {
		case 'h':
			return 1;
		case 'p':
			if (select_format(&request->format, CAPRINT_PROMPT) < 0)
				return -1;
			break;
		case 'c':
			if (select_format(&request->format, CAPRINT_COMPACT) < 0)
				return -1;
			break;
		case 'l':
			if (select_format(&request->format, CAPRINT_LONG) < 0)
				return -1;
			break;
		default:
			return -1;
		}
	}
	if (argc - optind > 1)
		return -1;
	if (optind < argc && parse_positive_pid(argv[optind], &request->pid) < 0) {
		fprintf(stderr, "caprint: PID must be a strict positive decimal integer\n");
		return -2;
	}
	return 0;
}

static int read_capamb(pid_t pid, uint64_t *capabilities)
{
	char path[64];
	FILE *status;
	char *line = NULL;
	size_t capacity = 0;
	ssize_t length;
	int found = 0;
	int rendered;

	rendered = snprintf(path, sizeof(path), "/proc/%d/status", (int)pid);
	if (rendered < 0 || (size_t)rendered >= sizeof(path)) {
		errno = ENAMETOOLONG;
		return -1;
	}
	status = fopen(path, "r");
	if (status == NULL)
		return -1;
	errno = 0;
	while ((length = getline(&line, &capacity, status)) >= 0) {
		if (length >= 8 && memcmp(line, "CapAmb:\t", 8) == 0) {
			char *end;
			unsigned long long value;

			errno = 0;
			value = strtoull(line + 8, &end, 16);
			if (errno == ERANGE || end == line + 8) {
				errno = EINVAL;
				break;
			}
			while (*end == ' ' || *end == '\t' || *end == '\r' || *end == '\n')
				end++;
			if (*end != '\0') {
				errno = EINVAL;
				break;
			}
			*capabilities = (uint64_t)value;
			found = 1;
			break;
		}
	}
	if (!found && !ferror(status) && errno == 0)
		errno = ENODATA;
	if (ferror(status) && errno == 0)
		errno = EIO;
	free(line);
	if (fclose(status) != 0)
		found = 0;
	return found ? 0 : -1;
}

static int print_capabilities(uint64_t capabilities, enum caprint_format format)
{
	cap_value_t capability;
	const char *separator = "";
	int count = 0;

	for (capability = 0; capability <= CAP_LAST_CAP; capability++) {
		if ((capabilities & (UINT64_C(1) << capability)) != 0) {
			char *name = cap_to_name(capability);

			if (name == NULL)
				return -1;
			count++;
			if (format == CAPRINT_LONG)
				printf("%2d %016" PRIx64 " %s\n", capability,
						UINT64_C(1) << capability, name);
			else if (format == CAPRINT_COMPACT || format == CAPRINT_PROMPT)
				printf("%s%s", separator,
						strncmp(name, "cap_", 4) == 0 ? name + 4 : name);
			else
				printf("%s\n", name);
			separator = ",";
			if (cap_free(name) < 0)
				return -1;
		}
	}
	if (format == CAPRINT_PROMPT && capabilities != 0)
		printf("#");
	if ((format == CAPRINT_COMPACT || format == CAPRINT_PROMPT) &&
			capabilities != 0)
		printf("\n");
	if (format == CAPRINT_LONG && count > 1)
		printf("   %016" PRIx64 "\n", capabilities);
	return 0;
}

int main(int argc, char **argv)
{
	const char *program = basename(argv[0]);
	struct caprint_request request;
	uint64_t capabilities;
	int parse_status = parse_request(argc, argv, &request);

	if (parse_status > 0)
		return usage(program);
	if (parse_status < 0)
		return parse_status == -2 ? 2 : usage(program);
	if (read_capamb(request.pid, &capabilities) < 0) {
		fprintf(stderr, "%s: cannot read PID %d: %s\n", program,
				(int)request.pid, strerror(errno));
		return 2;
	}
	if (print_capabilities(capabilities, request.format) < 0) {
		fprintf(stderr, "%s: cannot format capabilities\n", program);
		return 2;
	}
	errno = 0;
	if (fflush(stdout) == EOF || ferror(stdout)) {
		fprintf(stderr, "%s: cannot write capability output: %s\n", program,
				strerror(errno != 0 ? errno : EIO));
		return 2;
	}
	return 0;
}
