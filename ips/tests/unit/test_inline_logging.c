#include "../../src/inline/logging.h"
#include "../../src/inline/http_parser.h"

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "../common/unit_test.h"

static int capture_stderr(char *buf, size_t buf_sz,
                          void (*fn)(void *), void *arg) {
    int saved_fd;
    int tmp_fd;
    char path[] = "/tmp/inline_log_testXXXXXX";
    ssize_t nread;

    saved_fd = dup(STDERR_FILENO);
    if (saved_fd < 0) {
        return -1;
    }

    tmp_fd = mkstemp(path);
    if (tmp_fd < 0) {
        close(saved_fd);
        return -1;
    }
    unlink(path);

    if (dup2(tmp_fd, STDERR_FILENO) < 0) {
        close(saved_fd);
        close(tmp_fd);
        return -1;
    }

    fn(arg);
    fflush(stderr);
    lseek(tmp_fd, 0, SEEK_SET);
    nread = read(tmp_fd, buf, buf_sz - 1U);
    if (nread < 0) {
        nread = 0;
    }
    buf[nread] = '\0';

    dup2(saved_fd, STDERR_FILENO);
    close(saved_fd);
    close(tmp_fd);
    return 0;
}

static void run_log_message(void *arg) {
    (void)arg;
    mini_ips_log_message("unit", "hello");
}

static void run_log_allow(void *arg) {
    http_message_t *msg;

    msg = (http_message_t *)arg;
    mini_ips_log_allow_message(7U, msg);
}

int main(void) {
    char output[1024];
    http_message_t msg;
    uint8_t body[] = "BODY";

    memset(&msg, 0, sizeof(msg));
    msg.uri = "/path";
    msg.headers = "Host: example\r\n";
    msg.body = body;
    msg.body_len = sizeof(body) - 1U;

    EXPECT_INT_EQ("capture_stderr.message", 0,
                  capture_stderr(output, sizeof(output), run_log_message, NULL));
    EXPECT_TRUE("mini_ips_log_message", "contains scope",
                NULL != strstr(output, "[MINI_IPS][unit] hello"));

    EXPECT_INT_EQ("capture_stderr.allow", 0,
                  capture_stderr(output, sizeof(output), run_log_allow, &msg));
    EXPECT_TRUE("mini_ips_log_allow_message", "contains allow uri",
                NULL != strstr(output, "[ALLOW_URI] session_id=7 uri=\"/path\""));
    EXPECT_TRUE("mini_ips_log_allow_message", "contains body",
                NULL != strstr(output, "BODY"));

    return 0;
}
