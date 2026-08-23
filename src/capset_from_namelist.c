/*
 * cado: execute a command in a capability ambient
 * Copyright (C) 2016 Renzo Davoli, University of Bologna
 *
 * This file is part of cado and is distributed under the GNU GPL v2 or later.
 */

#include <ctype.h>
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/capability.h>

#include <capset_from_namelist.h>

static uint64_t supported_capabilities(void)
{
#if CAP_LAST_CAP >= 63
	return UINT64_MAX;
#else
	return (UINT64_C(1) << (CAP_LAST_CAP + 1)) - UINT64_C(1);
#endif
}

static int span_is_hex(const char *start, size_t length)
{
	size_t i;

	for (i = 0; i < length; i++) {
		if (!isxdigit((unsigned char)start[i]))
			return 0;
	}
	return length > 0;
}

static enum cado_cap_parse_status parse_mask(const char *start, size_t length,
		uint64_t *mask)
{
	char *end;
	char *token;
	unsigned long long value;

	token = malloc(length + 1);
	if (token == NULL)
		return CADO_CAP_PARSE_NO_MEMORY;
	memcpy(token, start, length);
	token[length] = '\0';

	errno = 0;
	value = strtoull(token, &end, 16);
	if (errno == ERANGE) {
		free(token);
		return CADO_CAP_PARSE_OVERFLOW;
	}
	if (end != token + length) {
		free(token);
		return CADO_CAP_PARSE_INVALID_ITEM;
	}
	free(token);

	if (((uint64_t)value & ~supported_capabilities()) != 0)
		return CADO_CAP_PARSE_UNSUPPORTED;
	*mask = (uint64_t)value;
	return CADO_CAP_PARSE_OK;
}

static enum cado_cap_parse_status parse_name(const char *start, size_t length,
		uint64_t *mask)
{
	static const char prefix[] = "cap_";
	char *name;
	size_t prefix_length = 0;
	cap_value_t capability;
	int result;
	size_t i;

	for (i = 0; i < length; i++) {
		if (!isalnum((unsigned char)start[i]) && start[i] != '_')
			return CADO_CAP_PARSE_INVALID_ITEM;
	}

	if (length < sizeof(prefix) - 1 ||
			memcmp(start, prefix, sizeof(prefix) - 1) != 0)
		prefix_length = sizeof(prefix) - 1;

	name = malloc(prefix_length + length + 1);
	if (name == NULL)
		return CADO_CAP_PARSE_NO_MEMORY;
	if (prefix_length != 0)
		memcpy(name, prefix, prefix_length);
	memcpy(name + prefix_length, start, length);
	name[prefix_length + length] = '\0';

	result = cap_from_name(name, &capability);
	free(name);
	if (result < 0 || capability < 0 || capability > CAP_LAST_CAP ||
			capability >= 64)
		return CADO_CAP_PARSE_INVALID_ITEM;
	*mask = UINT64_C(1) << capability;
	return CADO_CAP_PARSE_OK;
}

static enum cado_cap_parse_status parse_item(const char *start, size_t length,
		uint64_t *mask)
{
	while (length > 0 && isspace((unsigned char)*start)) {
		start++;
		length--;
	}
	while (length > 0 && isspace((unsigned char)start[length - 1]))
		length--;
	if (length == 0)
		return CADO_CAP_PARSE_EMPTY_ITEM;
	if (span_is_hex(start, length))
		return parse_mask(start, length, mask);
	return parse_name(start, length, mask);
}

enum cado_cap_parse_status capset_from_namelist(const char *namelist,
		uint64_t *capset)
{
	const char *item;
	const char *scan;
	uint64_t parsed = 0;

	if (namelist == NULL || capset == NULL)
		return CADO_CAP_PARSE_INVALID_ITEM;

	item = namelist;
	for (scan = namelist; ; scan++) {
		if (*scan == ',' || *scan == '\0') {
			uint64_t one = 0;
			enum cado_cap_parse_status status;

			status = parse_item(item, (size_t)(scan - item), &one);
			if (status != CADO_CAP_PARSE_OK) {
				if (status == CADO_CAP_PARSE_EMPTY_ITEM &&
						item == namelist && *scan == '\0')
					return CADO_CAP_PARSE_EMPTY;
				return status;
			}
			parsed |= one;
			if (*scan == '\0')
				break;
			item = scan + 1;
		}
	}

	*capset = parsed;
	return CADO_CAP_PARSE_OK;
}

const char *cado_cap_parse_status_string(enum cado_cap_parse_status status)
{
	switch (status) {
	case CADO_CAP_PARSE_OK:
		return "valid capability list";
	case CADO_CAP_PARSE_EMPTY:
		return "empty capability list";
	case CADO_CAP_PARSE_EMPTY_ITEM:
		return "empty capability item";
	case CADO_CAP_PARSE_INVALID_ITEM:
		return "invalid capability item";
	case CADO_CAP_PARSE_OVERFLOW:
		return "capability mask overflow";
	case CADO_CAP_PARSE_UNSUPPORTED:
		return "capability mask contains unsupported bits";
	case CADO_CAP_PARSE_NO_MEMORY:
		return "out of memory while parsing capabilities";
	}
	return "unknown capability parse error";
}
