#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include <sys/capability.h>

#include <cado_policy.h>
#include <capset_from_namelist.h>

static int failures;

#define CHECK(expression) do { \
	if (!(expression)) { \
		fprintf(stderr, "%s:%d: check failed: %s\n", __FILE__, __LINE__, \
				#expression); \
		failures++; \
	} \
} while (0)

static void valid(const char *text, uint64_t expected)
{
	uint64_t parsed = UINT64_C(0xfeedface);
	enum cado_cap_parse_status status = capset_from_namelist(text, &parsed);

	CHECK(status == CADO_CAP_PARSE_OK);
	CHECK(parsed == expected);
}

static void invalid(const char *text)
{
	uint64_t parsed = UINT64_C(0xfeedface);
	enum cado_cap_parse_status status = capset_from_namelist(text, &parsed);

	if (status == CADO_CAP_PARSE_OK)
		fprintf(stderr, "unexpectedly valid capability list: <%s> -> %" PRIx64 "\n",
				text, parsed);
	CHECK(status != CADO_CAP_PARSE_OK);
	CHECK(parsed == UINT64_C(0xfeedface));
}

int main(void)
{
	char unsupported[32];
	struct cado_policy_result policy;

	valid("chown", UINT64_C(1) << CAP_CHOWN);
	valid("cap_chown", UINT64_C(1) << CAP_CHOWN);
	valid("  cap_chown , kill\t",
			(UINT64_C(1) << CAP_CHOWN) | (UINT64_C(1) << CAP_KILL));
	valid("c0", UINT64_C(0xc0));
	valid("0", 0);
	invalid("");
	invalid(" \t\r\n ");
	invalid(",");
	invalid(",chown");
	invalid("chown,");
	invalid("chown,,kill");
	invalid("-1");
	invalid("+1");
	invalid("0x1");
	invalid("10000000000000000");
	invalid("cap_chown trailing");
	invalid("not_a_capability");
	invalid("chown, not_a_capability");
#if CAP_LAST_CAP < 63
	snprintf(unsupported, sizeof(unsupported), "%" PRIx64,
			UINT64_C(1) << (CAP_LAST_CAP + 1));
	invalid(unsupported);
#endif

	policy = cado_apply_policy(UINT64_C(0x7), UINT64_C(0x3), 0);
	CHECK(policy.status == CADO_POLICY_DENIED);
	CHECK(policy.granted == UINT64_C(0x3));
	CHECK(policy.unavailable == UINT64_C(0x4));
	policy = cado_apply_policy(UINT64_C(0x7), UINT64_C(0x3), 1);
	CHECK(policy.status == CADO_POLICY_GRANTED);
	CHECK(policy.granted == UINT64_C(0x3));
	CHECK(policy.unavailable == UINT64_C(0x4));

	return failures == 0 ? 0 : 1;
}
