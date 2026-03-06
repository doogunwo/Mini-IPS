#include "project_rst.h"
#include <stdio.h>

#define CHECK(cond, msg) do { if (!(cond)) { fprintf(stderr, "FAIL: %s\n", msg); return 1; } } while (0)

int main(void)
{
    pr_session_t s = {0};
    uint32_t seq = 0, ack = 0;

    s.seen_ab = 1;
    s.seen_ba = 1;

    s.last_ack_ba = 1000;
    s.next_seq_ba = 2000;
    s.win_ba = 1024;
    s.win_scale_ba = 0;

    CHECK(pr_choose_seq_ack(&s, 1, &seq, &ack) == 0, "choose AB failed");
    CHECK(ack == 2000, "AB ack mismatch");
    CHECK(seq >= 1000 && seq <= 2024, "AB seq outside window");

    s.last_ack_ab = 5000;
    s.next_seq_ab = 6000;
    s.win_ab = 2048;
    s.win_scale_ab = 1; /* 4096 */

    CHECK(pr_choose_seq_ack(&s, 0, &seq, &ack) == 0, "choose BA failed");
    CHECK(ack == 6000, "BA ack mismatch");
    CHECK(seq >= 5000 && seq <= 5000 + (2048u << 1), "BA seq outside window");

    printf("ok: test_project_rst\n");
    return 0;
}
