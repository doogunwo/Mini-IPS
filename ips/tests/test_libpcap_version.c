/**
 * @file test_libpcap_version.c
 * @brief libpcap 사용 가능 여부 단위 테스트
 */
#include <pcap/pcap.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>

int main(void) {
    const char *ver = pcap_lib_version();
    if (!ver || ver[0] == '\0') {
        fprintf(stderr, "pcap_lib_version returned empty string\\n");
        return 1;
    }

    if (strstr(ver, "libpcap") == NULL && strstr(ver, "WinPcap") == NULL &&
        strstr(ver, "Npcap") == NULL) {
        fprintf(stderr, "unexpected libpcap version string: %s\\n", ver);
        return 1;
    }

    printf("ok: test_libpcap_version (%s)\\n", ver);
    return 0;
}
