#include <cado_policy.h>

struct cado_policy_result cado_apply_policy(uint64_t requested,
		uint64_t allowed, int force)
{
	struct cado_policy_result result = {
		.status = CADO_POLICY_GRANTED,
		.granted = requested & allowed,
		.unavailable = requested & ~allowed
	};

	if (result.unavailable != 0 && !force)
		result.status = CADO_POLICY_DENIED;
	return result;
}
