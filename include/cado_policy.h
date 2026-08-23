#ifndef CADO_POLICY_H
#define CADO_POLICY_H

#include <stdint.h>

enum cado_policy_status {
	CADO_POLICY_GRANTED = 0,
	CADO_POLICY_DENIED
};

struct cado_policy_result {
	enum cado_policy_status status;
	uint64_t granted;
	uint64_t unavailable;
};

struct cado_policy_result cado_apply_policy(uint64_t requested,
		uint64_t allowed, int force);

#endif
