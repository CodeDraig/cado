#ifndef CADO_IDENTITY_H
#define CADO_IDENTITY_H

#include <stddef.h>
#include <sys/types.h>

struct cado_identity {
	char *username;
	char **groups;
	size_t group_count;
};

enum cado_identity_status {
	CADO_IDENTITY_OK = 0,
	CADO_IDENTITY_NO_PASSWD,
	CADO_IDENTITY_GROUP_LOOKUP,
	CADO_IDENTITY_NO_MEMORY
};

enum cado_identity_status cado_identity_load(uid_t uid,
		struct cado_identity *identity);
void cado_identity_free(struct cado_identity *identity);
int cado_identity_has_group(const struct cado_identity *identity,
		const char *group);
int cado_identity_matches_principal(const struct cado_identity *identity,
		const char *principal);

#endif
