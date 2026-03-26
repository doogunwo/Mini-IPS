/**
 * @file logging.c
 * @brief 구조화 로그 기록과 문자열 escape helper 구현
 *
 * 운영 중 남기는 `ips.log`, monitor 로그, 이벤트 ID, 구조화 문자열 직렬화를
 * 이 파일이 맡는다. data path는 아니지만 리뷰 시 운영 관측 포인트를
 * 이해하는 데 중요한 역할을 한다.
 */

#include "logging.h"

#include <ctype.h>
#include <errno.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>

/**
 * @brief 로그용 local time timestamp 문자열을 만든다.
 *
 * @param out 출력 버퍼
 * @param out_sz 출력 버퍼 크기
 */
static void make_log_timestamp(char *out, size_t out_sz) {
    /* 실시간 시각 정보 */
    struct timespec ts;
    /* localtime 변환 결과 */
    struct tm tm_now;
    /* millisecond 값 */
    int ms;
    /* strftime 결과 길이 */
    size_t n;
    /* helper 반환값 */
    int ret;

    /* 출력 버퍼가 없으면 종료 */
    if (NULL == out || 0U == out_sz) {
        return;
    }

    /* 현재 wall clock 시각 조회 */
    ret = clock_gettime(CLOCK_REALTIME, &ts);
    if (0 != ret) {
        /* 시각 조회 실패 시 고정 fallback 사용 */
        snprintf(out, out_sz, "1970-01-01T00:00:00.000");
        return;
    }

    /* 초 단위를 local time으로 변환 */
    localtime_r(&ts.tv_sec, &tm_now);
    /* 나노초를 밀리초로 축소 */
    ms = (int)(ts.tv_nsec / 1000000L);
    /* yyyy-mm-ddTHH:MM:SS 부분 먼저 기록 */
    n = strftime(out, out_sz, "%Y-%m-%dT%H:%M:%S", &tm_now);
    if (0 == n || n + 6 >= out_sz) {
        /* 버퍼가 부족하면 fallback 사용 */
        snprintf(out, out_sz, "1970-01-01T00:00:00.000");
        return;
    }

    /* 뒤에 .mmm millisecond를 이어 붙인다 */
    snprintf(out + n, out_sz - n, ".%03d", ms);
}

/**
 * @brief 이미 완성된 구조화 로그 한 줄을 파일에 기록한다.
 *
 * @param fp 대상 파일
 * @param ts timestamp 문자열
 * @param level 로그 레벨
 * @param body key=value 본문
 */
static void write_log_line_locked(FILE *fp, const char *ts, const char *level,
                                  const char *body) {
    /* 필수 입력이 없으면 기록 생략 */
    if (NULL == fp || NULL == ts || NULL == level || NULL == body) {
        return;
    }

    /* 한 줄 단위 구조화 로그 기록 */
    fprintf(fp, "ts=%s level=%s %s\n", ts, level, body);
    /* crash 전에도 파일에 남도록 즉시 flush */
    fflush(fp);
}

/**
 * @brief 문자열 버퍼 capacity를 필요한 크기까지 늘린다.
 */
static int strbuf_reserve(strbuf_t *sb, size_t need) {
    /* realloc 결과 버퍼 */
    char *next;
    /* 다음 확장 용량 */
    size_t next_cap;

    /* 출력 버퍼 포인터 검증 */
    if (NULL == sb) {
        return -1;
    }
    /* 이미 충분한 용량이면 확장 불필요 */
    if (need <= sb->cap) {
        return 0;
    }

    /* 첫 확장은 256바이트부터 시작 */
    next_cap = sb->cap ? sb->cap : 256U;
    /* 필요한 크기 이상이 될 때까지 2배 확장 */
    while (next_cap < need) {
        next_cap *= 2U;
    }

    /* 실제 힙 확장 */
    next = (char *)realloc(sb->buf, next_cap);
    if (!next) {
        return -1;
    }

    /* 확장 결과를 버퍼 상태에 반영 */
    sb->buf = next;
    sb->cap = next_cap;
    return 0;
}

/**
 * @brief 문자열 버퍼 뒤에 문자 하나를 붙인다.
 */
static int strbuf_append_char(strbuf_t *sb, char c) {
    /* reserve helper 결과 */
    int ret;

    /* 문자 1개와 NUL 종료 공간 확보 */
    ret = strbuf_reserve(sb, sb->len + 2U);
    if (0 != ret) {
        return -1;
    }

    /* 문자 1개 추가 */
    sb->buf[sb->len++] = c;
    /* 항상 NUL 종료 유지 */
    sb->buf[sb->len] = '\0';
    return 0;
}

/**
 * @brief 문자열 버퍼 뒤에 문자열을 붙인다.
 */
static int strbuf_append_str(strbuf_t *sb, const char *s) {
    /* 원본 문자열 길이 */
    size_t n;
    /* reserve helper 결과 */
    int ret;

    /* NULL 입력은 빈 문자열로 간주 */
    if (NULL == s) {
        s = "";
    }

    /* 복사 길이 계산 */
    n = strlen(s);
    /* 문자열 전체와 NUL 종료 공간 확보 */
    ret = strbuf_reserve(sb, sb->len + n + 1U);
    if (0 != ret) {
        return -1;
    }

    /* 문자열 본문 복사 */
    memcpy(sb->buf + sb->len, s, n);
    /* 길이 갱신 */
    sb->len += n;
    /* 항상 NUL 종료 유지 */
    sb->buf[sb->len] = '\0';
    return 0;
}

/**
 * @brief 구조화 로그를 깨는 문자를 escape 해 문자열 버퍼에 붙인다.
 */
static int strbuf_append_escaped(strbuf_t *sb, const char *s) {
    /* 순회 인덱스 */
    size_t i;
    /* 현재 문자 */
    unsigned char c;
    /* 비출력 문자의 hex escape 임시 버퍼 */
    char hex[5];
    /* helper 반환값 */
    int ret;

    /* NULL 문자열은 빈 문자열처럼 처리 */
    if (NULL == s) {
        return strbuf_append_str(sb, "");
    }

    /* 원본 문자열을 한 문자씩 escape 처리한다 */
    for (i = 0; s[i] != '\0'; i++) {
        c = (unsigned char)s[i];
        /* 큰따옴표와 백슬래시는 역슬래시 escape */
        if ('"' == c || '\\' == c) {
            ret = strbuf_append_char(sb, '\\');
            if (0 != ret) {
                return -1;
            }
            ret = strbuf_append_char(sb, (char)c);
            if (0 != ret) {
                return -1;
            }
            continue;
        }

        /* 줄바꿈/탭은 로그 한 줄 유지 위해 공백으로 치환 */
        if ('\n' == c || '\r' == c || '\t' == c) {
            ret = strbuf_append_char(sb, ' ');
            if (0 != ret) {
                return -1;
            }
            continue;
        }

        /* 비출력 문자는 \xNN 형태로 직렬화 */
        ret = isprint(c);
        if (0 == ret) {
            snprintf(hex, sizeof(hex), "\\x%02X", c);
            ret = strbuf_append_str(sb, hex);
            if (0 != ret) {
                return -1;
            }
            continue;
        }

        /* 일반 출력 가능 문자는 그대로 추가 */
        ret = strbuf_append_char(sb, (char)c);
        if (0 != ret) {
            return -1;
        }
    }

    return 0;
}

/**
 * @brief detect context enum 값을 로그 문자열로 변환한다.
 */
static const char *ctx_name(ips_context_t ctx) {
    switch (ctx) {
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
 * @brief 로그 파일 경로의 부모 디렉터리를 보장한다.
 */
static int ensure_parent_dir(const char *path) {
    /* 부모 디렉터리 경로 임시 버퍼 */
    char dir_path[256];
    /* 마지막 슬래시 위치 */
    char *slash;
    /* mkdir 반환값 */
    int ret;

    /* 경로 문자열 검증 */
    if (NULL == path || '\0' == path[0]) {
        return -1;
    }

    /* 원본 경로를 수정하지 않도록 로컬 버퍼로 복사 */
    snprintf(dir_path, sizeof(dir_path), "%s", path);
    slash = strrchr(dir_path, '/');
    if (!slash) {
        /* 슬래시가 없으면 현재 디렉터리만 보장하면 된다 */
        ret = mkdir(".", 0755);
        if (0 != ret && EEXIST != errno) {
            return -1;
        }
        return 0;
    }

    if (slash == dir_path) {
        /* 루트 디렉터리 경로는 "/" 자체만 보장한다 */
        ret = mkdir("/", 0755);
        if (0 != ret && EEXIST != errno) {
            return -1;
        }
        return 0;
    }

    /* 마지막 슬래시를 끊어 부모 디렉터리 문자열만 남긴다 */
    *slash = '\0';
    /* 부모 디렉터리 생성 시도 */
    ret = mkdir(dir_path, 0755);
    if (0 != ret && EEXIST != errno) {
        return -1;
    }

    return 0;
}

/* --------------------------- env / string helpers ---------------------------
 */

/**
 * @brief 환경 변수 값을 boolean 플래그처럼 해석한다.
 *
 * 설정값이 없거나 해석할 수 없으면 `default_value`를 그대로 사용한다.
 *
 * @param name 환경 변수 이름
 * @param default_value 기본값
 * @return int 해석된 플래그 값
 */
int env_flag_enabled(const char *name, int default_value) {
    /* 환경 변수 원문 값 */
    const char *val;
    /* 문자열 비교 결과 */
    int ret;

    /* 이름이 없으면 기본값 유지 */
    if (NULL == name) {
        return default_value;
    }

    /* 환경 변수 값 조회 */
    val = getenv(name);
    if (NULL == val || '\0' == *val) {
        return default_value;
    }

    /* truthy 값 집합 */
    ret = strcmp(val, "1");
    if (0 == ret) {
        return 1;
    }
    ret = strcmp(val, "true");
    if (0 == ret) {
        return 1;
    }
    ret = strcmp(val, "TRUE");
    if (0 == ret) {
        return 1;
    }
    ret = strcmp(val, "yes");
    if (0 == ret) {
        return 1;
    }
    ret = strcmp(val, "YES");
    if (0 == ret) {
        return 1;
    }
    ret = strcmp(val, "on");
    if (0 == ret) {
        return 1;
    }
    ret = strcmp(val, "ON");
    if (0 == ret) {
        return 1;
    }

    /* falsy 값 집합 */
    ret = strcmp(val, "0");
    if (0 == ret) {
        return 0;
    }
    ret = strcmp(val, "false");
    if (0 == ret) {
        return 0;
    }
    ret = strcmp(val, "FALSE");
    if (0 == ret) {
        return 0;
    }
    ret = strcmp(val, "no");
    if (0 == ret) {
        return 0;
    }
    ret = strcmp(val, "NO");
    if (0 == ret) {
        return 0;
    }
    ret = strcmp(val, "off");
    if (0 == ret) {
        return 0;
    }
    ret = strcmp(val, "OFF");
    if (0 == ret) {
        return 0;
    }

    return default_value;
}

/**
 * @brief 동적 문자열 버퍼를 해제하고 상태를 초기화한다.
 *
 * @param sb 문자열 버퍼
 */
void strbuf_free(strbuf_t *sb) {
    /* NULL 입력 방어 */
    if (!sb) {
        return;
    }

    /* 동적 버퍼 해제 */
    free(sb->buf);
    /* dangling pointer 방지 */
    sb->buf = NULL;
    /* 사용 길이 초기화 */
    sb->len = 0;
    /* 용량 초기화 */
    sb->cap = 0;
}

/**
 * @brief 로그에 안전한 escaped 문자열 복사본을 만든다.
 *
 * key=value 구조화 로그 형식을 깨는 문자만 최소한으로 escape 한다.
 *
 * @param s 원본 문자열
 * @return char* 새로 할당된 escaped 문자열
 */
char *log_escape_dup(const char *s) {
    /* 동적 문자열 버퍼 */
    strbuf_t sb = {0};
    /* escape helper 결과 */
    int ret;

    /* 로그 안전 문자열 생성 */
    ret = strbuf_append_escaped(&sb, s);
    if (0 != ret) {
        strbuf_free(&sb);
        return NULL;
    }

    if (NULL == sb.buf) {
        /* 빈 결과도 명시적 빈 문자열 버퍼로 반환 */
        char *empty = (char *)malloc(1U);

        if (NULL == empty) {
            return NULL;
        }
        empty[0] = '\0';
        return empty;
    }

    return sb.buf;
}

/**
 * @brief 현재 시각을 로그 timestamp 형식 문자열로 만든다.
 *
 * @param out 출력 버퍼
 * @param out_sz 출력 버퍼 크기
 * @return int 성공 시 0, 실패 시 -1
 */
int app_make_timestamp(char *out, size_t out_sz) {
    if (NULL == out || 0U == out_sz) {
        return -1;
    }

    make_log_timestamp(out, out_sz);
    return 0;
}

/**
 * @brief 단조 증가하는 이벤트 ID를 생성한다.
 *
 * 현재 epoch millisecond와 프로세스 내부 sequence를 조합해 차단 이벤트와
 * 탐지 로그를 묶는 식별자를 만든다.
 *
 * @param shared 공유 앱 상태
 * @param out 출력 버퍼
 * @param out_sz 출력 버퍼 크기
 * @return int 성공 시 0, 실패 시 -1
 */
int app_make_event_id(app_shared_t *shared, char *out, size_t out_sz) {
    /* 현재 wall clock 시각 */
    struct timespec ts;
    /* 프로세스 내부 단조 증가 시퀀스 */
    uint64_t seq;
    /* epoch millisecond */
    uint64_t epoch_ms;
    /* helper 반환값 */
    int ret;

    if (NULL == shared || NULL == out || 0U == out_sz) {
        return -1;
    }

    /* 현재 시각 조회 */
    ret = clock_gettime(CLOCK_REALTIME, &ts);
    if (0 != ret) {
        return -1;
    }

    /* 이벤트별 sequence를 원자적으로 하나 증가시킨다 */
    seq = atomic_fetch_add(&shared->event_seq, 1) + 1;
    /* 시각을 millisecond 단위 정수로 만든다 */
    epoch_ms =
        ((uint64_t)ts.tv_sec * 1000ULL) + ((uint64_t)ts.tv_nsec / 1000000ULL);
    /* 시각과 sequence를 조합해 event id 문자열 생성 */
    snprintf(out, out_sz, "evt-%013llu-%06llu", (unsigned long long)epoch_ms,
             (unsigned long long)(seq % 1000000ULL));
    return 0;
}

/**
 * @brief 매치 리스트를 로그용 문자열 두 개로 직렬화한다.
 *
 * rule 정보와 matched text 정보를 각각 `; ` 구분 문자열로 만든다.
 *
 * @param matches 매치 리스트
 * @param rules rule 문자열 출력 버퍼
 * @param texts matched text 문자열 출력 버퍼
 * @return int 성공 시 0, 실패 시 -1
 */
int append_match_strings(const detect_match_list_t *matches, strbuf_t *rules,
                         strbuf_t *texts) {
    /* 매치 리스트 순회 인덱스 */
    size_t i;
    /* helper 반환값 */
    int ret;

    /* 빈 리스트는 아무 것도 추가하지 않는다 */
    if (NULL == matches) {
        return 0;
    }

    /* 각 매치를 rule/text 두 문자열 버퍼로 직렬화한다 */
    for (i = 0; i < matches->count; i++) {
        /* 현재 매치 항목 */
        const detect_match_t *m = &matches->items[i];

        /* 둘째 항목부터는 "; " 구분자를 넣는다 */
        if (0 < i) {
            ret = strbuf_append_str(rules, "; ");
            if (0 != ret) {
                return -1;
            }
            ret = strbuf_append_str(texts, "; ");
            if (0 != ret) {
                return -1;
            }
        }

        /* rules 문자열에는 context|policy|pattern 형태를 기록한다 */
        ret = strbuf_append_str(rules, ctx_name(m->context));
        if (0 != ret) {
            return -1;
        }
        ret = strbuf_append_char(rules, '|');
        if (0 != ret) {
            return -1;
        }
        ret = strbuf_append_str(rules, (m->rule && m->rule->policy_name)
                                           ? m->rule->policy_name
                                           : "unknown");
        if (0 != ret) {
            return -1;
        }
        ret = strbuf_append_char(rules, '|');
        if (0 != ret) {
            return -1;
        }
        ret = strbuf_append_str(rules, (m->rule && m->rule->pattern)
                                           ? m->rule->pattern
                                           : "unknown");
        if (0 != ret) {
            return -1;
        }

        /* texts 문자열에는 context|matched_text 형태를 기록한다 */
        ret = strbuf_append_str(texts, ctx_name(m->context));
        if (0 != ret) {
            return -1;
        }
        ret = strbuf_append_char(texts, '|');
        if (0 != ret) {
            return -1;
        }
        ret = strbuf_append_escaped(texts,
                                    m->matched_text ? m->matched_text : "");
        if (0 != ret) {
            return -1;
        }
    }

    return 0;
}

/**
 * @brief 구조화 로그 파일을 열고 mutex를 초기화한다.
 *
 * `LOG_FILE` 환경 변수가 없으면 기본 경로 `logs/ips.log`를 사용한다.
 * 실시간 모니터용 요약 로그는 `MONITOR_LOG_FILE` 또는 기본 경로
 * `logs/monitor.log`로 별도 기록한다.
 *
 * @param shared 공유 앱 데이터
 * @return int 성공 시 0, 실패 시 -1
 */
int app_log_open(app_shared_t *shared) {
    /* 일반 이벤트 로그 경로 환경 변수 */
    const char *log_file_env;
    /* 모니터 로그 경로 환경 변수 */
    const char *monitor_log_file_env;
    /* helper 반환값 */
    int ret;

    /* 공유 상태 포인터 검증 */
    if (NULL == shared) {
        return -1;
    }

    /* 일반 이벤트 로그 경로 결정 */
    log_file_env = getenv("LOG_FILE");
    if (NULL != log_file_env && '\0' != log_file_env[0]) {
        snprintf(shared->log_path, sizeof(shared->log_path), "%s",
                 log_file_env);
    } else {
        memcpy(shared->log_path, "logs/ips.log", sizeof("logs/ips.log"));
    }

    /* monitor 로그 경로 결정 */
    monitor_log_file_env = getenv("MONITOR_LOG_FILE");
    if (NULL != monitor_log_file_env && '\0' != monitor_log_file_env[0]) {
        snprintf(shared->monitor_log_path, sizeof(shared->monitor_log_path),
                 "%s", monitor_log_file_env);
    } else {
        memcpy(shared->monitor_log_path, "logs/monitor.log",
               sizeof("logs/monitor.log"));
    }

    /* 로그 파일 부모 디렉터리 보장 */
    ret = ensure_parent_dir(shared->log_path);
    if (0 != ret) {
        return -1;
    }
    /* monitor 로그 부모 디렉터리 보장 */
    ret = ensure_parent_dir(shared->monitor_log_path);
    if (0 != ret) {
        return -1;
    }

    /* 일반 이벤트 로그 파일 append open */
    shared->log_fp = fopen(shared->log_path, "a");
    if (!shared->log_fp) {
        return -1;
    }

    /* monitor 로그 파일은 새 실행마다 다시 쓴다 */
    shared->monitor_log_fp = fopen(shared->monitor_log_path, "w");
    if (!shared->monitor_log_fp) {
        fclose(shared->log_fp);
        shared->log_fp = NULL;
        return -1;
    }

    /* 두 로그 파일을 보호할 공용 mutex 초기화 */
    pthread_mutex_init(&shared->log_mu, NULL);
    return 0;
}

/**
 * @brief 구조화 로그 파일과 mutex를 정리한다.
 *
 * @param shared 공유 앱 데이터
 */
void app_log_close(app_shared_t *shared) {
    /* 공유 상태 포인터 검증 */
    if (!shared) {
        return;
    }

    /* 일반 이벤트 로그 파일 닫기 */
    if (shared->log_fp) {
        fclose(shared->log_fp);
        shared->log_fp = NULL;
    }
    /* monitor 로그 파일 닫기 */
    if (shared->monitor_log_fp) {
        fclose(shared->monitor_log_fp);
        shared->monitor_log_fp = NULL;
    }
    /* 로그 mutex 정리 */
    pthread_mutex_destroy(&shared->log_mu);
}

/**
 * @brief 공통 구조화 로그 한 줄을 기록한다.
 *
 * timestamp와 level을 먼저 붙이고 caller가 넘긴 본문 format을 이어 기록한다.
 * 내부 mutex로 여러 worker의 로그 줄이 섞이지 않도록 보호한다.
 *
 * @param shared 공유 앱 데이터
 * @param category 로그 레벨
 * @param fmt 로그 본문 format
 */
void app_log_write(app_shared_t *shared, const char *category, const char *fmt,
                   ...) {
    /* 가변 인자 목록 */
    va_list ap;
    /* 현재 시각 문자열 */
    char ts[40];
    /* format 결과 본문 버퍼 */
    char body[4096];

    /* 필수 입력 검증 */
    if (!shared || !shared->log_fp || !fmt) {
        return;
    }

    /* 로그 timestamp 생성 */
    make_log_timestamp(ts, sizeof(ts));
    /* format 문자열 직렬화 */
    va_start(ap, fmt);
    vsnprintf(body, sizeof(body), fmt, ap);
    va_end(ap);

    /* 로그 한 줄 기록 중 다른 스레드와 충돌하지 않게 보호 */
    pthread_mutex_lock(&shared->log_mu);
    write_log_line_locked(shared->log_fp, ts, category ? category : "INFO",
                          body);
    pthread_mutex_unlock(&shared->log_mu);
}

/**
 * @brief 실시간 모니터 전용 구조화 로그 한 줄을 기록한다.
 *
 * monitor.log는 이벤트 원문이 아니라 주기적 성능/상태 통계를 싣는 용도다.
 *
 * @param shared 공유 앱 데이터
 * @param fmt 로그 본문 format
 */
void app_monitor_write(app_shared_t *shared, const char *fmt, ...) {
    /* 가변 인자 목록 */
    va_list ap;
    /* 현재 시각 문자열 */
    char ts[40];
    /* format 결과 본문 버퍼 */
    char body[4096];

    /* 필수 입력 검증 */
    if (!shared || !shared->monitor_log_fp || !fmt) {
        return;
    }

    /* 로그 timestamp 생성 */
    make_log_timestamp(ts, sizeof(ts));
    /* format 문자열 직렬화 */
    va_start(ap, fmt);
    vsnprintf(body, sizeof(body), fmt, ap);
    va_end(ap);

    /* monitor 로그도 같은 mutex로 한 줄 단위 보장 */
    pthread_mutex_lock(&shared->log_mu);
    write_log_line_locked(shared->monitor_log_fp, ts, "INFO", body);
    pthread_mutex_unlock(&shared->log_mu);
}

/**
 * @brief 탐지 이벤트를 DB 수집 친화적인 한 줄 로그로 기록한다.
 *
 * 이벤트 ID, 대표 정책, matched rule/text, 점수, 탐지 소요 시간을 모두
 * key=value 형식으로 남긴다.
 *
 * @param shared 공유 앱 데이터
 * @param event_id 이벤트 ID
 * @param event_ts 이벤트 timestamp
 * @param attack 대표 공격 이름
 * @param where 탐지 위치
 * @param from 요청/응답 요약
 * @param detected 대표 탐지 문자열
 * @param matched_rules 직렬화된 rule 목록
 * @param matched_texts 직렬화된 text 목록
 * @param ip source IP 문자열
 * @param port source port
 * @param score 누적 점수
 * @param threshold 차단 임계치
 * @param match_count 매치 개수
 * @param detect_us 탐지 시간(us)
 * @param detect_ms 탐지 시간(ms)
 */
void app_log_attack(app_shared_t *shared, const char *event_id,
                    const char *event_ts, const char *attack, const char *where,
                    const char *from, const char *detected,
                    const char *matched_rules, const char *matched_texts,
                    const char *ip, uint16_t port, int score, int threshold,
                    size_t match_count, uint64_t detect_us, long detect_ms) {
    /* 최종 로그 timestamp */
    char ts[40];
    /* 각 필드 escape 복사본 */
    char *from_esc;
    char *detected_esc;
    char *rules_esc;
    char *texts_esc;

    /* 로그 파일이 없으면 기록 생략 */
    if (!shared || !shared->log_fp) {
        return;
    }

    /* key=value 로그에 넣기 전 문자열 필드 escape */
    from_esc     = log_escape_dup(from);
    detected_esc = log_escape_dup(detected);
    rules_esc    = log_escape_dup(matched_rules);
    texts_esc    = log_escape_dup(matched_texts);
    /* escape 중 하나라도 실패하면 전체 기록 생략 */
    if (!from_esc || !detected_esc || !rules_esc || !texts_esc) {
        free(from_esc);
        free(detected_esc);
        free(rules_esc);
        free(texts_esc);
        return;
    }

    /* 호출자가 넘긴 event timestamp가 있으면 그대로 사용 */
    if (NULL != event_ts && '\0' != event_ts[0]) {
        snprintf(ts, sizeof(ts), "%s", event_ts);
    } else {
        /* 없으면 현재 시각으로 대체 */
        make_log_timestamp(ts, sizeof(ts));
    }
    /* DB ingest용 구조화 탐지 로그 한 줄 기록 */
    pthread_mutex_lock(&shared->log_mu);
    fprintf(shared->log_fp,
            "ts=%s level=WARN event=detect event_id=%s "
            "attack=%s where=%s from=\"%s\" "
            "matched=\"%s\" score=%d threshold=%d "
            "match_count=%zu matched_rules=\"%s\" "
            "matched_texts=\"%s\" src_ip=%s "
            "src_port=%u detect_us=%llu detect_ms=%ld\n",
            ts, (event_id && event_id[0] != '\0') ? event_id : "-",
            attack ? attack : "unknown", where ? where : "unknown", from_esc,
            detected_esc, score, threshold, match_count, rules_esc, texts_esc,
            ip ? ip : "unknown", (unsigned int)port,
            (unsigned long long)detect_us, detect_ms);
    fflush(shared->log_fp);
    pthread_mutex_unlock(&shared->log_mu);

    /* 임시 escape 버퍼 해제 */
    free(from_esc);
    free(detected_esc);
    free(rules_esc);
    free(texts_esc);
}

/**
 * @brief host order IPv4 값을 dotted decimal 문자열로 변환한다.
 *
 * @param ip IPv4 값
 * @param out 출력 버퍼
 * @param out_sz 출력 버퍼 크기
 */
void ip4_to_str(uint32_t ip, char *out, size_t out_sz) {
    /* 출력 버퍼 검증 */
    if (!out || 0 == out_sz) {
        return;
    }

    /* host-order IPv4를 dotted decimal 문자열로 직렬화 */
    snprintf(out, out_sz, "%u.%u.%u.%u", (ip >> 24) & 0xFF, (ip >> 16) & 0xFF,
             (ip >> 8) & 0xFF, ip & 0xFF);
}
