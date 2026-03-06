/**
 * @file test_libpcap.c
 * @brief libpcap 사용 가능 여부 단위 테스트
 */
#define _DEFAULT_SOURCE
#include <sys/types.h>
#include <pcap/pcap.h>
#include <stdio.h>
#include <string.h>

int main(void)
{
    const char *ver = pcap_lib_version();
    if (!ver || ver[0] == '\0')
    {
        fprintf(stderr, "pcap_lib_version returned empty string\\n");
        return 1;
    }

    if (strstr(ver, "libpcap") == NULL &&
        strstr(ver, "WinPcap") == NULL &&
        strstr(ver, "Npcap") == NULL)
    {
        fprintf(stderr, "unexpected libpcap version string: %s\\n", ver);
        return 1;
    }

    printf("ok: test_libpcap (%s)\\n", ver);
    return 0;
}
