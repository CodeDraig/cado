#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/capability.h>

#include <get_user_groups.h>
#include <read_conf.h>

static int failures;

#define CHECK(expression) do { \
	if (!(expression)) { \
		fprintf(stderr, "%s:%d: check failed: %s\n", __FILE__, __LINE__, \
				#expression); \
		failures++; \
	} \
} while (0)

static int write_text(const char *path, const char *text)
{
	FILE *file = fopen(path, "w");

	if (file == NULL)
		return -1;
	if (fputs(text, file) == EOF) {
		fclose(file);
		return -1;
	}
	return fclose(file);
}

static void expect_invalid(const char *path, const char *text,
		const struct cado_identity *identity)
{
	struct cado_config_result result;

	CHECK(write_text(path, text) == 0);
	result = cado_config_authorize_file(path, identity, UINT64_MAX);
	CHECK(result.status == CADO_CONFIG_SYNTAX_ERROR);
	CHECK(result.capabilities == 0);
}

int main(void)
{
	char directory[] = "/tmp/cado-config-test.XXXXXX";
	char path[256];
	char *groups[] = { "staff", "operators" };
	struct cado_identity identity = {
		.username = "alice",
		.groups = groups,
		.group_count = 2
	};
	struct cado_config_result result;
	struct cado_identity loaded_identity = {0};
	uint64_t expected;

	CHECK(cado_identity_load(getuid(), &loaded_identity) == CADO_IDENTITY_OK);
	CHECK(loaded_identity.username != NULL);
	CHECK(loaded_identity.group_count > 0);
	cado_identity_free(&loaded_identity);
	CHECK(loaded_identity.username == NULL && loaded_identity.groups == NULL);
	CHECK(setenv("CADO_TEST_CONFIG_EXPANSION", "expanded", 1) == 0);

	CHECK(cado_identity_has_group(&identity, "staff"));
	CHECK(!cado_identity_has_group(&identity, "missing"));
	CHECK(cado_identity_matches_principal(&identity, "alice"));
	CHECK(cado_identity_matches_principal(&identity, "@operators"));
	CHECK(!cado_identity_matches_principal(&identity, "bob"));
	CHECK(!cado_identity_matches_principal(&identity, "@"));

	CHECK(mkdtemp(directory) != NULL);
	snprintf(path, sizeof(path), "%s/cado.conf", directory);
	CHECK(write_text(path,
			"# comment\n"
			"chown,kill : alice,@other\n"
			"setuid : @staff : /usr/bin/test $CADO_TEST_CONFIG_EXPANSION = expanded ; /bin/true\n"
			"setgid : bob : /bin/false\n") == 0);
	expected = (UINT64_C(1) << CAP_CHOWN) |
			(UINT64_C(1) << CAP_KILL) |
			(UINT64_C(1) << CAP_SETUID);
	result = cado_config_authorize_file(path, &identity, UINT64_MAX);
	CHECK(result.status == CADO_CONFIG_OK);
	CHECK(result.capabilities == expected);
	CHECK(!result.condition_failed);
	result = cado_config_union_file(path);
	CHECK(result.status == CADO_CONFIG_OK);
	CHECK((result.capabilities & (UINT64_C(1) << CAP_SETGID)) != 0);

	CHECK(write_text(path, "chown: alice : /bin/false\n") == 0);
	result = cado_config_authorize_file(path, &identity, UINT64_MAX);
	CHECK(result.status == CADO_CONFIG_OK);
	CHECK(result.capabilities == 0);
	CHECK(result.condition_failed);

	expect_invalid(path, "   : alice\n", &identity);
	expect_invalid(path, "chown:\n", &identity);
	expect_invalid(path, "chown: alice,,bob\n", &identity);
	expect_invalid(path, "chown: @\n", &identity);
	expect_invalid(path, "chown: al ice\n", &identity);
	expect_invalid(path, "chown alice\n", &identity);
	expect_invalid(path, "chown: alice:\n", &identity);
	expect_invalid(path, "chown: alice: /bin/true: extra\n", &identity);
	expect_invalid(path, "chown: alice\nkill: alice: /bin/true: extra\n",
			&identity);
	expect_invalid(path, "chown,: alice\n", &identity);

	unlink(path);
	rmdir(directory);
	CHECK(unsetenv("CADO_TEST_CONFIG_EXPANSION") == 0);
	return failures == 0 ? 0 : 1;
}
