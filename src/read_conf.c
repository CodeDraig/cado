/*
 * cado: strict configuration and executable capability management
 * Copyright (C) 2016 Renzo Davoli, University of Bologna
 *
 * This file is part of cado and is distributed under the GNU GPL v2 or later.
 */

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/capability.h>

#include <execs.h>

#include <capset_from_namelist.h>
#include <config.h>
#include <read_conf.h>
#include <set_ambient_cap.h>

#if !defined(EXECS_SOVERSION) || EXECS_SOVERSION != 1
#error "cado requires the libexecs 1.4 sequence API (EXECS_SOVERSION 1)"
#endif

struct cado_config_entry {
	uint64_t capabilities;
	char **principals;
	size_t principal_count;
	char *condition;
	size_t line;
};

struct cado_config_file {
	struct cado_config_entry *entries;
	size_t count;
	size_t capacity;
};

static void config_entry_free(struct cado_config_entry *entry)
{
	size_t i;

	for (i = 0; i < entry->principal_count; i++)
		free(entry->principals[i]);
	free(entry->principals);
	free(entry->condition);
	memset(entry, 0, sizeof(*entry));
}

static void config_file_free(struct cado_config_file *config)
{
	size_t i;

	for (i = 0; i < config->count; i++)
		config_entry_free(&config->entries[i]);
	free(config->entries);
	memset(config, 0, sizeof(*config));
}

static char *trim(char *text)
{
	char *end;

	while (isspace((unsigned char)*text))
		text++;
	end = text + strlen(text);
	while (end > text && isspace((unsigned char)end[-1]))
		end--;
	*end = '\0';
	return text;
}

static int valid_principal(const char *principal)
{
	const unsigned char *scan = (const unsigned char *)principal;

	if (*scan == '@')
		scan++;
	if (*scan == '\0')
		return 0;
	for (; *scan != '\0'; scan++) {
		if (isspace(*scan) || *scan == '@' || *scan == ':' ||
				*scan == ',' || *scan == '#')
			return 0;
	}
	return 1;
}

static enum cado_config_status parse_principals(char *field,
		struct cado_config_entry *entry)
{
	char *item = field;
	char *scan;

	for (scan = field; ; scan++) {
		if (*scan == ',' || *scan == '\0') {
			char delimiter = *scan;
			char *principal;
			char **resized;

			*scan = '\0';
			principal = trim(item);
			if (!valid_principal(principal))
				return CADO_CONFIG_SYNTAX_ERROR;
			if (entry->principal_count >= SIZE_MAX /
					sizeof(*entry->principals))
				return CADO_CONFIG_NO_MEMORY;
			resized = realloc(entry->principals,
					(entry->principal_count + 1) * sizeof(*resized));
			if (resized == NULL)
				return CADO_CONFIG_NO_MEMORY;
			entry->principals = resized;
			entry->principals[entry->principal_count] = strdup(principal);
			if (entry->principals[entry->principal_count] == NULL)
				return CADO_CONFIG_NO_MEMORY;
			entry->principal_count++;
			if (delimiter == '\0')
				break;
			item = scan + 1;
		}
	}
	return CADO_CONFIG_OK;
}

static enum cado_config_status parse_config_line(char *line, size_t line_number,
		struct cado_config_entry *entry, const char **reason)
{
	char *first;
	char *second;
	char *capabilities;
	char *principals;
	char *condition = NULL;
	enum cado_cap_parse_status cap_status;
	enum cado_config_status status;

	memset(entry, 0, sizeof(*entry));
	entry->line = line_number;
	first = strchr(line, ':');
	if (first == NULL) {
		*reason = "expected capabilities : principals";
		return CADO_CONFIG_SYNTAX_ERROR;
	}
	*first = '\0';
	second = strchr(first + 1, ':');
	if (second != NULL) {
		*second = '\0';
		if (strchr(second + 1, ':') != NULL) {
			*reason = "extra colon-delimited field";
			return CADO_CONFIG_SYNTAX_ERROR;
		}
		condition = trim(second + 1);
		if (*condition == '\0') {
			*reason = "empty condition sequence";
			return CADO_CONFIG_SYNTAX_ERROR;
		}
	}

	capabilities = trim(line);
	principals = trim(first + 1);
	if (*principals == '\0') {
		*reason = "missing principals";
		return CADO_CONFIG_SYNTAX_ERROR;
	}
	cap_status = capset_from_namelist(capabilities, &entry->capabilities);
	if (cap_status != CADO_CAP_PARSE_OK) {
		*reason = cado_cap_parse_status_string(cap_status);
		return cap_status == CADO_CAP_PARSE_NO_MEMORY ?
				CADO_CONFIG_NO_MEMORY : CADO_CONFIG_SYNTAX_ERROR;
	}
	status = parse_principals(principals, entry);
	if (status != CADO_CONFIG_OK) {
		*reason = status == CADO_CONFIG_NO_MEMORY ? "out of memory" :
				"malformed principal list";
		return status;
	}
	if (condition != NULL) {
		entry->condition = strdup(condition);
		if (entry->condition == NULL) {
			*reason = "out of memory";
			return CADO_CONFIG_NO_MEMORY;
		}
	}
	return CADO_CONFIG_OK;
}

static enum cado_config_status append_entry(struct cado_config_file *config,
		struct cado_config_entry *entry)
{
	if (config->count == config->capacity) {
		size_t capacity = config->capacity == 0 ? 8 : config->capacity * 2;
		struct cado_config_entry *resized;

		if (capacity < config->capacity)
			return CADO_CONFIG_NO_MEMORY;
		if (capacity > SIZE_MAX / sizeof(*resized))
			return CADO_CONFIG_NO_MEMORY;
		resized = realloc(config->entries, capacity * sizeof(*resized));
		if (resized == NULL)
			return CADO_CONFIG_NO_MEMORY;
		config->entries = resized;
		config->capacity = capacity;
	}
	config->entries[config->count++] = *entry;
	memset(entry, 0, sizeof(*entry));
	return CADO_CONFIG_OK;
}

static struct cado_config_result load_config(const char *path,
		struct cado_config_file *config)
{
	struct cado_config_result result = { .status = CADO_CONFIG_OK };
	FILE *file;
	char *line = NULL;
	size_t capacity = 0;
	ssize_t length;
	size_t line_number = 0;

	file = fopen(path, "r");
	if (file == NULL) {
		result.status = CADO_CONFIG_OPEN_ERROR;
		result.error_number = errno;
		return result;
	}

	while ((length = getline(&line, &capacity, file)) >= 0) {
		struct cado_config_entry entry;
		char *content;
		const char *reason = NULL;

		line_number++;
		if (memchr(line, '\0', (size_t)length) != NULL) {
			reason = "embedded NUL byte";
			result.status = CADO_CONFIG_SYNTAX_ERROR;
			goto malformed;
		}
		while (length > 0 && (line[length - 1] == '\n' ||
				line[length - 1] == '\r'))
			line[--length] = '\0';
		content = trim(line);
		if (*content == '\0' || *content == '#')
			continue;

		result.status = parse_config_line(content, line_number, &entry, &reason);
		if (result.status != CADO_CONFIG_OK) {
			config_entry_free(&entry);
			goto malformed;
		}
		result.status = append_entry(config, &entry);
		if (result.status != CADO_CONFIG_OK) {
			config_entry_free(&entry);
			reason = "out of memory";
			goto malformed;
		}
		continue;

malformed:
		result.line = line_number;
		fprintf(stderr, "%s:%zu: %s\n", path, line_number,
				reason != NULL ? reason : "invalid configuration entry");
		break;
	}
	if (result.status == CADO_CONFIG_OK && ferror(file)) {
		result.status = CADO_CONFIG_READ_ERROR;
		result.error_number = errno != 0 ? errno : EIO;
		result.line = line_number + 1;
	}
	free(line);
	if (fclose(file) != 0) {
		if (result.status == CADO_CONFIG_OK) {
			result.status = CADO_CONFIG_READ_ERROR;
			result.error_number = errno;
			result.line = line_number;
		} else {
			result.cleanup_error = errno;
		}
	}
	if (result.status != CADO_CONFIG_OK)
		config_file_free(config);
	return result;
}

static int entry_matches(const struct cado_config_entry *entry,
		const struct cado_identity *identity)
{
	size_t i;

	for (i = 0; i < entry->principal_count; i++) {
		if (cado_identity_matches_principal(identity, entry->principals[i]))
			return 1;
	}
	return 0;
}

static int drop_condition_capabilities(void *unused)
{
	(void)unused;
	return drop_all_capabilities();
}

struct cado_config_result cado_config_authorize_file(const char *path,
		const struct cado_identity *identity, uint64_t requested)
{
	struct cado_config_file config = {0};
	struct cado_config_result result;
	size_t i;

	result = load_config(path, &config);
	if (result.status != CADO_CONFIG_OK)
		return result;
	if (identity == NULL) {
		config_file_free(&config);
		result.status = CADO_CONFIG_SYNTAX_ERROR;
		result.capabilities = 0;
		return result;
	}

	s2argv_getvar = getenv;
	execs_fork_security = drop_condition_capabilities;
	execs_fork_security_arg = NULL;
	for (i = 0; i < config.count; i++) {
		const struct cado_config_entry *entry = &config.entries[i];

		if ((entry->capabilities & requested) == 0 ||
				!entry_matches(entry, identity))
			continue;
		if (entry->condition != NULL && system_execsqa(entry->condition) != 0) {
			result.condition_failed = 1;
			continue;
		}
		result.capabilities |= entry->capabilities;
	}
	result.capabilities &= requested;
	config_file_free(&config);
	return result;
}

struct cado_config_result cado_config_union_file(const char *path)
{
	struct cado_config_file config = {0};
	struct cado_config_result result;
	size_t i;

	result = load_config(path, &config);
	if (result.status != CADO_CONFIG_OK)
		return result;
	for (i = 0; i < config.count; i++)
		result.capabilities |= config.entries[i].capabilities;
	config_file_free(&config);
	return result;
}

struct cado_config_result cado_config_authorize(
		const struct cado_identity *identity, uint64_t requested)
{
	struct cado_config_result result = { .status = CADO_CONFIG_CAPABILITY_ERROR };
	int raise_error = 0;
	int lower_error = 0;

	if (raise_cap_dac_read_search() < 0)
		raise_error = errno;
	else
		result = cado_config_authorize_file(CADO_CONF_PATH, identity, requested);
	if (lower_cap_dac_read_search() < 0)
		lower_error = errno;
	if (raise_error != 0) {
		result.status = CADO_CONFIG_CAPABILITY_ERROR;
		result.error_number = raise_error;
		result.cleanup_error = lower_error;
	} else if (lower_error != 0) {
		result.status = CADO_CONFIG_CAPABILITY_ERROR;
		result.capabilities = 0;
		result.error_number = lower_error;
	}
	return result;
}

struct cado_config_result cado_config_union(void)
{
	return cado_config_union_file(CADO_CONF_PATH);
}

static void report_setcap_error(const char *operation, cap_value_t capability)
{
	int saved_errno = errno;
	char *name = cap_to_name(capability);

	if (name != NULL) {
		fprintf(stderr, "cado: cannot %s %s\n", operation, name);
		if (cap_free(name) < 0)
			fprintf(stderr, "cado: cannot release capability name: %s\n",
					strerror(errno));
	} else {
		fprintf(stderr, "cado: cannot %s capability %d\n", operation,
				(int)capability);
	}
	errno = saved_errno;
}

int set_self_capability(uint64_t capset)
{
	cap_t capabilities;
	cap_value_t capability;
	int executable = -1;
	int result = -1;
	int saved_errno = 0;

	capabilities = cap_init();
	if (capabilities == NULL) {
		perror("cado: cap_init");
		return -1;
	}
	for (capability = 0; capability <= CAP_LAST_CAP; capability++) {
		if ((capset & (UINT64_C(1) << capability)) == 0)
			continue;
		if (cap_set_flag(capabilities, CAP_PERMITTED, 1, &capability,
				CAP_SET) < 0) {
			saved_errno = errno;
			report_setcap_error("set permitted", capability);
			goto out;
		}
	}
	executable = open("/proc/self/exe", O_RDONLY | O_CLOEXEC);
	if (executable < 0) {
		saved_errno = errno;
		perror("cado: open /proc/self/exe");
		goto out;
	}
	if (cap_set_fd(executable, capabilities) < 0) {
		saved_errno = errno;
		perror("cado: cap_set_fd");
		goto out;
	}
	result = 0;

out:
	if (executable >= 0 && close(executable) < 0) {
		if (result == 0)
			saved_errno = errno;
		result = -1;
		perror("cado: close /proc/self/exe");
	}
	if (cap_free(capabilities) < 0) {
		if (result == 0)
			saved_errno = errno;
		result = -1;
		perror("cado: cap_free");
	}
	if (saved_errno != 0)
		errno = saved_errno;
	return result;
}

const char *cado_config_status_string(enum cado_config_status status)
{
	switch (status) {
	case CADO_CONFIG_OK:
		return "configuration valid";
	case CADO_CONFIG_OPEN_ERROR:
		return "cannot open configuration";
	case CADO_CONFIG_READ_ERROR:
		return "cannot read configuration";
	case CADO_CONFIG_SYNTAX_ERROR:
		return "invalid configuration";
	case CADO_CONFIG_NO_MEMORY:
		return "out of memory while reading configuration";
	case CADO_CONFIG_CAPABILITY_ERROR:
		return "cannot scope configuration read capability";
	}
	return "unknown configuration error";
}
