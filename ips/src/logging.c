
/**
@file logging.c
@brief 작성된 주석이 포함된 구조화 로그 헬퍼 구현
*/

#define _DEFAULT_SOURCE

/*
********************************************************************************
* #include
********************************************************************************
*/
#include "logging.h"

#include <ctype.h>
#include <errno.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>

/*
********************************************************************************
* Local function prototypes
********************************************************************************
*/
static void make_log_timestamp(char *out, size_t out_sz);
static int strbuf_reserve(strbuf_t *sb, size_t need);
static int strbuf_append_char(strbuf_t *sb, char c);
static int strbuf_append_str(strbuf_t *sb, const char *s);
static int strbuf_append_escaped(strbuf_t *sb, const char *s);
static const char *ctx_name(ips_context_t ctx);
static int ensure_parent_dir(const char *path);

/**
* @brief env flag 확인 함수
환경 변수 값을 읽어 boolean flag처럼 해석한다.
설정이 없거나 해석할 수 없으면 default_value를 반환한다.
* @param name 환경 변수 이름
* @param default_value 기본 값
* @return 해석된 플래그 값
*/
int env_flag_enabled(const char *name, int default_value)
{
    const char *val;

    if (!name)
    {
        return default_value;
    }

    val = getenv(name);
    if (!val || !*val)
    {
        return default_value;
    }

    if (strcmp(val, "1") == 0 ||
        strcmp(val, "true") == 0 ||
        strcmp(val, "TRUE") == 0 ||
        strcmp(val, "yes") == 0 ||
        strcmp(val, "YES") == 0 ||
        strcmp(val, "on") == 0 ||
        strcmp(val, "ON") == 0)
    {
        return 1;
    }

    if (strcmp(val, "0") == 0 ||
        strcmp(val, "false") == 0 ||
        strcmp(val, "FALSE") == 0 ||
        strcmp(val, "no") == 0 ||
        strcmp(val, "NO") == 0 ||
        strcmp(val, "off") == 0 ||
        strcmp(val, "OFF") == 0)
    {
        return 0;
    }

    return default_value;
}

/**
* @brief string buffer free 함수
동적 문자열 버퍼 메모리를 해제하고 상태를 초기화한다.
* @param sb 문자열 버퍼
* @return 없음
*/
void strbuf_free(strbuf_t *sb)
{
    if (!sb)
    {
        return;
    }

    free(sb->buf);
    sb->buf = NULL;
    sb->len = 0;
    sb->cap = 0;
}

/**
* @brief log escape duplicate 함수
로그에 안전한 문자열을 새 버퍼에 복사한다.
key=value 로그 형식을 깨는 문자만 escape한다.
* @param s 원본 문자열
* @return escape 된 새 문자열
*/
char *log_escape_dup(const char *s)
{
    strbuf_t sb = {0};

    if (strbuf_append_escaped(&sb, s) != 0)
    {
        strbuf_free(&sb);
        return NULL;
    }

    if (NULL == sb.buf)
    {
        return strdup("");
    }

    return sb.buf;
}

int app_make_timestamp(char *out, size_t out_sz)
{
    if (!out || out_sz == 0)
    {
        return -1;
    }

    make_log_timestamp(out, out_sz);
    return 0;
}

int app_make_event_id(app_shared_t *shared, char *out, size_t out_sz)
{
    struct timespec ts;
    uint64_t seq;
    uint64_t epoch_ms;

    if (!shared || !out || out_sz == 0)
    {
        return -1;
    }

    if (clock_gettime(CLOCK_REALTIME, &ts) != 0)
    {
        return -1;
    }

    seq = atomic_fetch_add(&shared->event_seq, 1) + 1;
    epoch_ms = ((uint64_t)ts.tv_sec * 1000ULL) + ((uint64_t)ts.tv_nsec / 1000000ULL);
    snprintf(out,
             out_sz,
             "evt-%013llu-%06llu",
             (unsigned long long)epoch_ms,
             (unsigned long long)(seq % 1000000ULL));
    return 0;
}

/**
* @brief match string 생성 함수
detect match list를 로그 기록용 문자열 두 개로 직렬화한다.
rule 정보와 matched text 정보를 각각 semicolon 구분 문자열로 만든다.
* @param matches 매치 리스트
* @param rules rule 문자열 버퍼
* @param texts matched text 문자열 버퍼
@return 성공 여부
*/
int append_match_strings(const detect_match_list_t *matches,
                         strbuf_t *rules,
                         strbuf_t *texts)
{
    size_t i;

    if (!matches)
    {
        return 0;
    }

    for (i = 0; i < matches->count; i++)
    {
        const detect_match_t *m = &matches->items[i];

        if (i > 0)
        {
            if (strbuf_append_str(rules, "; ") != 0 ||
                strbuf_append_str(texts, "; ") != 0)
            {
                return -1;
            }
        }

        if (strbuf_append_str(rules, ctx_name(m->context)) != 0 ||
            strbuf_append_char(rules, '|') != 0 ||
            strbuf_append_str(
                rules,
                (m->rule && m->rule->policy_name) ?
                    m->rule->policy_name : "unknown") != 0 ||
            strbuf_append_char(rules, '|') != 0 ||
            strbuf_append_str(
                rules,
                (m->rule && m->rule->pattern) ?
                    m->rule->pattern : "unknown") != 0)
        {
            return -1;
        }

        if (strbuf_append_str(texts, ctx_name(m->context)) != 0 ||
            strbuf_append_char(texts, '|') != 0 ||
            strbuf_append_escaped(
                texts,
                m->matched_text ? m->matched_text : "") != 0)
        {
            return -1;
        }
    }

    return 0;
}

/**
* @brief app log open 함수
구조화 로그 파일을 열고 mutex를 초기화한다.
LOG_FILE 환경 변수가 없으면 logs/ips.log를 사용한다.
* @param shared 공유 앱 데이터
* @return 성공 여부
*/
int app_log_open(app_shared_t *shared)
{
    const char *log_file_env;

    if (!shared)
    {
        return -1;
    }

    log_file_env = getenv("LOG_FILE");
    if (log_file_env && log_file_env[0] != '\0')
    {
        snprintf(shared->log_path,
                 sizeof(shared->log_path),
                 "%s",
                 log_file_env);
    }
    else
    {
        snprintf(shared->log_path,
                 sizeof(shared->log_path),
                 "logs/ips.log");
    }

    if (ensure_parent_dir(shared->log_path) != 0)
    {
        return -1;
    }

    shared->log_fp = fopen(shared->log_path, "a");
    if (!shared->log_fp)
    {
        return -1;
    }

    pthread_mutex_init(&shared->log_mu, NULL);
    return 0;
}

/**
* @brief app log close 함수
열린 구조화 로그 파일과 mutex를 정리한다.
* @param shared 공유 앱 데이터
* @return 없음
*/
void app_log_close(app_shared_t *shared)
{
    if (!shared || !shared->log_fp)
    {
        return;
    }

    fclose(shared->log_fp);
    shared->log_fp = NULL;
    pthread_mutex_destroy(&shared->log_mu);
}

/**
* @brief app log write 함수
printf 스타일로 구조화 로그 한 줄을 기록한다.
timestamp와 level을 먼저 기록한 뒤 caller format을 이어서 기록한다.
* @param shared 공유 앱 데이터
* @param category 로그 레벨
* @param fmt 로그 본문 format
@return 없음
*/
void app_log_write(app_shared_t *shared,
                   const char *category,
                   const char *fmt,
                   ...)
{
    va_list ap;
    char ts[40];

    if (!shared || !shared->log_fp || !fmt)
    {
        return;
    }

    make_log_timestamp(ts, sizeof(ts));
    pthread_mutex_lock(&shared->log_mu);
    fprintf(shared->log_fp,
            "ts=%s level=%s ",
            ts,
            category ? category : "INFO");

    va_start(ap, fmt);
    vfprintf(shared->log_fp, fmt, ap);
    va_end(ap);

    fputc('\n', shared->log_fp);
    fflush(shared->log_fp);
    pthread_mutex_unlock(&shared->log_mu);
}

/**
* @brief attack log write 함수
탐지 이벤트를 DB ingest가 읽기 쉬운 형식으로 기록한다.
탐지된 공격, 위치, 매치 문자열, 점수, 소요 시간을 한 줄에 남긴다.
* @param shared 공유 앱 데이터
* @param attack 공격 이름
* @param where 탐지 위치
* @param from 요청 또는 응답 정보
* @param detected 대표 탐지 문자열
* @param matched_rules 직렬화된 rule 목록
* @param matched_texts 직렬화된 text 목록
* @param ip source ip
* @param port source port
* @param score 누적 점수
* @param threshold 차단 임계치
* @param match_count 매치 개수
* @param detect_us 탐지 시간 us
* @param detect_ms 탐지 시간 ms
* @return 없음
*/
void app_log_attack(app_shared_t *shared,
                    const char *event_id,
                    const char *event_ts,
                    const char *attack,
                    const char *where,
                    const char *from,
                    const char *detected,
                    const char *matched_rules,
                    const char *matched_texts,
                    const char *ip,
                    uint16_t port,
                    int score,
                    int threshold,
                    size_t match_count,
                    uint64_t detect_us,
                    long detect_ms)
{
    char ts[40];
    char *from_esc;
    char *detected_esc;
    char *rules_esc;
    char *texts_esc;

    if (!shared || !shared->log_fp)
    {
        return;
    }

    from_esc = log_escape_dup(from);
    detected_esc = log_escape_dup(detected);
    rules_esc = log_escape_dup(matched_rules);
    texts_esc = log_escape_dup(matched_texts);
    if (!from_esc || !detected_esc || !rules_esc || !texts_esc)
    {
        free(from_esc);
        free(detected_esc);
        free(rules_esc);
        free(texts_esc);
        return;
    }

    if (event_ts && event_ts[0] != '\0')
    {
        snprintf(ts, sizeof(ts), "%s", event_ts);
    }
    else
    {
        make_log_timestamp(ts, sizeof(ts));
    }
    pthread_mutex_lock(&shared->log_mu);
    fprintf(shared->log_fp,
            "ts=%s level=WARN event=detect event_id=%s "
            "attack=%s where=%s from=\"%s\" "
            "matched=\"%s\" score=%d threshold=%d "
            "match_count=%zu matched_rules=\"%s\" "
            "matched_texts=\"%s\" src_ip=%s "
            "src_port=%u detect_us=%llu detect_ms=%ld\n",
            ts,
            (event_id && event_id[0] != '\0') ? event_id : "-",
            attack ? attack : "unknown",
            where ? where : "unknown",
            from_esc,
            detected_esc,
            score,
            threshold,
            match_count,
            rules_esc,
            texts_esc,
            ip ? ip : "unknown",
            (unsigned int)port,
            (unsigned long long)detect_us,
            detect_ms);
    fflush(shared->log_fp);
    pthread_mutex_unlock(&shared->log_mu);

    free(from_esc);
    free(detected_esc);
    free(rules_esc);
    free(texts_esc);
}

/**
* @brief ipv4 to string 함수
host order ipv4 값을 dotted decimal 문자열로 변환한다.
* @param ip ipv4 값
* @param out 출력 버퍼
* @param out_sz 출력 버퍼 크기
* @return 없음
*/
void ip4_to_str(uint32_t ip, char *out, size_t out_sz)
{
    if (!out || 0 == out_sz)
    {
        return;
    }

    snprintf(out,
             out_sz,
             "%u.%u.%u.%u",
             (ip >> 24) & 0xFF,
             (ip >> 16) & 0xFF,
             (ip >> 8) & 0xFF,
             ip & 0xFF);
}

/*
********************************************************************************
* Local functions
********************************************************************************
*/
/**
* @brief timestamp 생성 함수
로그에 기록할 local time timestamp 문자열을 만든다.
* @param out 출력 버퍼
* @param out_sz 출력 버퍼 크기
* @return 없음
*/
static void make_log_timestamp(char *out, size_t out_sz)
{
    struct timespec ts;
    struct tm tm_now;
    int ms;
    size_t n;

    if (!out || 0 == out_sz)
    {
        return;
    }

    if (clock_gettime(CLOCK_REALTIME, &ts) != 0)
    {
        snprintf(out, out_sz, "1970-01-01T00:00:00.000");
        return;
    }

    localtime_r(&ts.tv_sec, &tm_now);
    ms = (int)(ts.tv_nsec / 1000000L);
    n = strftime(out, out_sz, "%Y-%m-%dT%H:%M:%S", &tm_now);
    if (0 == n || n + 6 >= out_sz)
    {
        snprintf(out, out_sz, "1970-01-01T00:00:00.000");
        return;
    }

    snprintf(out + n, out_sz - n, ".%03d", ms);
}

/**
* @brief string buffer reserve 함수
필요한 크기만큼 string buffer capacity를 늘린다.
* @param sb 문자열 버퍼
* @param need 필요한 크기
* @return 성공 여부
*/
static int strbuf_reserve(strbuf_t *sb, size_t need)
{
    char *next;
    size_t next_cap;

    if (!sb)
    {
        return -1;
    }

    if (need <= sb->cap)
    {
        return 0;
    }

    next_cap = sb->cap ? sb->cap : 256U;
    while (next_cap < need)
    {
        next_cap *= 2U;
    }

    next = (char *)realloc(sb->buf, next_cap);
    if (!next)
    {
        return -1;
    }

    sb->buf = next;
    sb->cap = next_cap;
    return 0;
}

/**
* @brief char append 함수
문자열 버퍼 뒤에 문자 하나를 붙인다.
* @param sb 문자열 버퍼
* @param c 추가할 문자
* @return 성공 여부
*/
static int strbuf_append_char(strbuf_t *sb, char c)
{
    if (strbuf_reserve(sb, sb->len + 2U) != 0)
    {
        return -1;
    }

    sb->buf[sb->len++] = c;
    sb->buf[sb->len] = '\0';
    return 0;
}

/**
* @brief string append 함수
문자열 버퍼 뒤에 문자열을 붙인다.
* @param sb 문자열 버퍼
* @param s 추가할 문자열
* @return 성공 여부
*/
static int strbuf_append_str(strbuf_t *sb, const char *s)
{
    size_t n;

    if (!s)
    {
        s = "";
    }

    n = strlen(s);
    if (strbuf_reserve(sb, sb->len + n + 1U) != 0)
    {
        return -1;
    }

    memcpy(sb->buf + sb->len, s, n);
    sb->len += n;
    sb->buf[sb->len] = '\0';
    return 0;
}

/**
* @brief escaped string append 함수
구조화 로그를 깨는 문자를 escape 해서 문자열 버퍼에 붙인다.
* @param sb 문자열 버퍼
* @param s 입력 문자열
* @return 성공 여부
*/
static int strbuf_append_escaped(strbuf_t *sb, const char *s)
{
    size_t i;
    unsigned char c;
    char hex[5];

    if (!s)
    {
        return strbuf_append_str(sb, "");
    }

    for (i = 0; s[i] != '\0'; i++)
    {
        c = (unsigned char)s[i];
        if (c == '"' || c == '\\')
        {
            if (strbuf_append_char(sb, '\\') != 0 ||
                strbuf_append_char(sb, (char)c) != 0)
            {
                return -1;
            }
            continue;
        }

        if (c == '\n' || c == '\r' || c == '\t')
        {
            if (strbuf_append_char(sb, ' ') != 0)
            {
                return -1;
            }
            continue;
        }

        if (!isprint(c))
        {
            snprintf(hex, sizeof(hex), "\\x%02X", c);
            if (strbuf_append_str(sb, hex) != 0)
            {
                return -1;
            }
            continue;
        }

        if (strbuf_append_char(sb, (char)c) != 0)
        {
            return -1;
        }
    }

    return 0;
}

/**
* @brief ctx name 변환 함수
detect context enum 값을 로그 문자열로 변환한다.
* @param ctx detect context
* @return context 문자열
*/
static const char *ctx_name(ips_context_t ctx)
{
    switch (ctx)
    {
        case IPS_CTX_REQUEST_URI:
            return "REQUEST_URI";
        case IPS_CTX_ARGS:
            return "ARGS";
        case IPS_CTX_ARGS_NAMES:
            return "ARGS_NAMES";
        case IPS_CTX_REQUEST_HEADERS:
            return "REQUEST_HEADERS";
        case IPS_CTX_REQUEST_BODY:
            return "REQUEST_BODY";
        case IPS_CTX_RESPONSE_BODY:
            return "RESPONSE_BODY";
        case IPS_CTX_ALL:
        default:
            return "ALL";
    }
}


/**
* @brief parent dir 생성 함수
로그 파일 경로의 부모 디렉터리를 만든다.
* @param path 파일 경로
* @return 성공 여부
*/
static int ensure_parent_dir(const char *path)
{
    char dir_path[256];
    char *slash;

    if (!path || path[0] == '\0')
    {
        return -1;
    }

    snprintf(dir_path, sizeof(dir_path), "%s", path);
    slash = strrchr(dir_path, '/');
    if (!slash)
    {
        if (mkdir(".", 0755) != 0 && errno != EEXIST)
        {
            return -1;
        }
        return 0;
    }

    if (slash == dir_path)
    {
        if (mkdir("/", 0755) != 0 && errno != EEXIST)
        {
            return -1;
        }
        return 0;
    }

    *slash = '\0';
    if (mkdir(dir_path, 0755) != 0 && errno != EEXIST)
    {
        return -1;
    }

    return 0;
}
