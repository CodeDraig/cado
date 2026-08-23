#ifndef CADO_GET_SCADO_FILE_H
#define CADO_GET_SCADO_FILE_H

#include <limits.h>
#include <stdio.h>
#include <string.h>

#include <cado_paths.h>

static inline int get_scado_file(const char *username, char path[PATH_MAX])
{
	int length;

	if (username == NULL || *username == '\0' || strchr(username, '/') != NULL ||
			strcmp(username, ".") == 0 || strcmp(username, "..") == 0)
		return -1;
	length = snprintf(path, PATH_MAX, "%s/%s", SPOOL_DIR, username);
	return length >= 0 && length < PATH_MAX ? 0 : -1;
}

#endif
