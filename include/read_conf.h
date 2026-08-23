#ifndef CADO_READ_CONF_H
#define CADO_READ_CONF_H

#include <stddef.h>
#include <stdint.h>

#include <get_user_groups.h>

enum cado_config_status {
	CADO_CONFIG_OK = 0,
	CADO_CONFIG_OPEN_ERROR,
	CADO_CONFIG_READ_ERROR,
	CADO_CONFIG_SYNTAX_ERROR,
	CADO_CONFIG_NO_MEMORY,
	CADO_CONFIG_CAPABILITY_ERROR
};

struct cado_config_result {
	enum cado_config_status status;
	uint64_t capabilities;
	int condition_failed;
	size_t line;
	int error_number;
	int cleanup_error;
};

struct cado_config_result cado_config_authorize_file(const char *path,
		const struct cado_identity *identity, uint64_t requested);
struct cado_config_result cado_config_union_file(const char *path);
struct cado_config_result cado_config_authorize(
		const struct cado_identity *identity, uint64_t requested);
struct cado_config_result cado_config_union(void);

int set_self_capability(uint64_t capset);
const char *cado_config_status_string(enum cado_config_status status);

#endif
