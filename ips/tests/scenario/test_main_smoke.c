#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#include "../common/unit_test.h"

static const char *resolve_main_bin(void) {
    if (0 == access("./build/bin/inline-ips", X_OK)) {
        return "./build/bin/inline-ips";
    }

    if (0 == access("./ips/build/bin/inline-ips", X_OK)) {
        return "./ips/build/bin/inline-ips";
    }

    return NULL;
}

static int run_main_and_expect_exit(const char *ruleset_dir, int expected_code) {
    const char *main_bin;
    pid_t pid;
    int   status;

    main_bin = resolve_main_bin();
    if (NULL == main_bin) {
        return -1;
    }

    pid = fork();
    if (pid < 0) {
        return -1;
    }

    if (0 == pid) {
        if (NULL == ruleset_dir) {
            unsetenv("MINI_IPS_RULESET_DIR");
        } else {
            setenv("MINI_IPS_RULESET_DIR", ruleset_dir, 1);
        }

        execl(main_bin, main_bin, (char *)NULL);
        _exit(127);
    }

    if (waitpid(pid, &status, 0) < 0) {
        return -1;
    }

    if (!WIFEXITED(status)) {
        return -1;
    }

    return WEXITSTATUS(status) == expected_code ? 0 : -1;
}

int main(void) {
    EXPECT_INT_EQ("main_smoke.missing_env", 0,
                  run_main_and_expect_exit(NULL, 1));
    EXPECT_INT_EQ("main_smoke.invalid_env_dir", 0,
                  run_main_and_expect_exit("/no/such/mini_ips_rules_dir", 1));
    return 0;
}
