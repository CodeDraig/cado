#ifndef CADO_SCADO_TEMP_GUARD_H
#define CADO_SCADO_TEMP_GUARD_H

#include <sys/types.h>

enum scado_temp_disposition {
	SCADO_TEMP_DISCARD = 0,
	SCADO_TEMP_KEEP,
	SCADO_TEMP_TRANSFER
};

struct scado_temp_guard {
	char *path;
	int lifetime_fd;
	pid_t child;
	int armed;
};

int scado_temp_guard_start(struct scado_temp_guard *guard,
		const char *directory, const char *template_name);
char *scado_temp_guard_path(struct scado_temp_guard *guard);
int scado_temp_guard_arm(struct scado_temp_guard *guard);
int scado_temp_guard_finish(struct scado_temp_guard *guard,
		enum scado_temp_disposition disposition);

#endif
