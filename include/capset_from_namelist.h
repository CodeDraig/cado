#ifndef CADO_CAPSET_FROM_NAMELIST_H
#define CADO_CAPSET_FROM_NAMELIST_H

#include <stdint.h>

enum cado_cap_parse_status {
	CADO_CAP_PARSE_OK = 0,
	CADO_CAP_PARSE_EMPTY,
	CADO_CAP_PARSE_EMPTY_ITEM,
	CADO_CAP_PARSE_INVALID_ITEM,
	CADO_CAP_PARSE_OVERFLOW,
	CADO_CAP_PARSE_UNSUPPORTED,
	CADO_CAP_PARSE_NO_MEMORY
};

enum cado_cap_parse_status capset_from_namelist(const char *namelist,
		uint64_t *capset);
const char *cado_cap_parse_status_string(enum cado_cap_parse_status status);

#endif
