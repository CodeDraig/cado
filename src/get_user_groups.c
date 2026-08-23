/*
 * cado: execute a command in a capability ambient
 * Copyright (C) 2016 Renzo Davoli, University of Bologna
 *
 * This file is part of cado and is distributed under the GNU GPL v2 or later.
 */

#include <grp.h>
#include <pwd.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <get_user_groups.h>

void cado_identity_free(struct cado_identity *identity)
{
	size_t i;

	if (identity == NULL)
		return;
	for (i = 0; i < identity->group_count; i++)
		free(identity->groups[i]);
	free(identity->groups);
	free(identity->username);
	identity->username = NULL;
	identity->groups = NULL;
	identity->group_count = 0;
}

enum cado_identity_status cado_identity_load(uid_t uid,
		struct cado_identity *identity)
{
	struct passwd *password;
	struct cado_identity loaded = {0};
	gid_t *group_ids = NULL;
	gid_t primary_group;
	int group_count = 16;
	int actual_count;
	int i;

	if (identity == NULL)
		return CADO_IDENTITY_NO_MEMORY;
	*identity = loaded;
	password = getpwuid(uid);
	if (password == NULL)
		return CADO_IDENTITY_NO_PASSWD;
	primary_group = password->pw_gid;
	loaded.username = strdup(password->pw_name);
	if (loaded.username == NULL)
		return CADO_IDENTITY_NO_MEMORY;

	for (;;) {
		gid_t *resized;

		if (group_count <= 0 ||
				(size_t)group_count > SIZE_MAX / sizeof(*group_ids)) {
			free(group_ids);
			cado_identity_free(&loaded);
			return CADO_IDENTITY_NO_MEMORY;
		}
		resized = realloc(group_ids, (size_t)group_count * sizeof(*group_ids));
		if (resized == NULL) {
			free(group_ids);
			cado_identity_free(&loaded);
			return CADO_IDENTITY_NO_MEMORY;
		}
		group_ids = resized;
		actual_count = group_count;
		if (getgrouplist(loaded.username, primary_group, group_ids,
				&actual_count) >= 0)
			break;
		if (actual_count <= group_count) {
			free(group_ids);
			cado_identity_free(&loaded);
			return CADO_IDENTITY_GROUP_LOOKUP;
		}
		group_count = actual_count;
	}

	if (actual_count < 0 ||
			(size_t)actual_count > SIZE_MAX / sizeof(*loaded.groups)) {
		free(group_ids);
		cado_identity_free(&loaded);
		return CADO_IDENTITY_NO_MEMORY;
	}
	loaded.groups = calloc((size_t)actual_count, sizeof(*loaded.groups));
	if (actual_count > 0 && loaded.groups == NULL) {
		free(group_ids);
		cado_identity_free(&loaded);
		return CADO_IDENTITY_NO_MEMORY;
	}
	for (i = 0; i < actual_count; i++) {
		struct group *group = getgrgid(group_ids[i]);

		if (group == NULL) {
			free(group_ids);
			cado_identity_free(&loaded);
			return CADO_IDENTITY_GROUP_LOOKUP;
		}
		loaded.groups[loaded.group_count] = strdup(group->gr_name);
		if (loaded.groups[loaded.group_count] == NULL) {
			free(group_ids);
			cado_identity_free(&loaded);
			return CADO_IDENTITY_NO_MEMORY;
		}
		loaded.group_count++;
	}
	free(group_ids);
	*identity = loaded;
	return CADO_IDENTITY_OK;
}

int cado_identity_has_group(const struct cado_identity *identity,
		const char *group)
{
	size_t i;

	if (identity == NULL || group == NULL)
		return 0;
	for (i = 0; i < identity->group_count; i++) {
		if (strcmp(identity->groups[i], group) == 0)
			return 1;
	}
	return 0;
}

int cado_identity_matches_principal(const struct cado_identity *identity,
		const char *principal)
{
	if (identity == NULL || principal == NULL || *principal == '\0')
		return 0;
	if (*principal == '@')
		return principal[1] != '\0' &&
			cado_identity_has_group(identity, principal + 1);
	return strcmp(identity->username, principal) == 0;
}
