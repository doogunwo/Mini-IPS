/**
 * @file regex.h
 * @brief IPS 시그니처 및 정책 정의
 */
#ifndef REGEX_H
#define REGEX_H


#define POLICY_LIST \
    X(POLICY_SQL_INJECTION,       "SQL_INJECTION") \
    X(POLICY_XSS,                 "XSS") \
    X(POLICY_COMMAND_INJECTION,   "COMMAND_INJECTION") \
    X(POLICY_DIRECTORY_TRAVERS,   "DIRECTORY_TRAVERSAL") \
    X(POLICY_APP_WEAK,            "APP_WEAK") \
    X(POLICY_SCANNER,             "SCANNER") \
    X(POLICY_PROTOCOL_VIOLATION,  "PROTOCOL_VIOLATION") \
    X(POLICY_INFO_LEAK,           "INFO_LEAK") \
    X(POLICY_WEBSHELL,            "WEBSHELL")

/** 정규식 시그니처 테이블에서 사용하는 정책 식별자이다. */
typedef enum {
#define X(ename, sname) ename,
    // 첫 번째 값 명시적 할당 (필요 시)
    POLICY_START = 0,
    POLICY_LIST
#undef X
    POLICY_MAX
} POLICY;

/** 시그니처를 평가할 HTTP 파싱 컨텍스트이다. */
typedef enum {
    IPS_CTX_ALL = 0,
    IPS_CTX_REQUEST_URI,
    IPS_CTX_ARGS,
    IPS_CTX_ARGS_NAMES,
    IPS_CTX_REQUEST_HEADERS,
    IPS_CTX_REQUEST_BODY
} ips_context_t;

/** 탐지 엔진이 사용하는 IPS 시그니처 한 행이다. */
typedef struct {
    POLICY policy_id;          // Enum ID
    const char *policy_name;   // 상위 정책 이름 (예: SQL_INJECTION)
    const char *pattern;       // 정규식 패턴 (C-String)
    int is_high_priority;      // 높은 우선순위 여부
    ips_context_t context;     // 탐지 컨텍스트
} IPS_Signature;

/** 내장 IPS 시그니처 전역 테이블이다. */
extern const IPS_Signature g_ips_signatures[];
/** 내장 시그니처 테이블 엔트리 개수이다. */
extern const int g_signature_count;
/** 정책 식별자의 출력용 이름을 돌려준다. */
const char* get_policy_name(POLICY p);

#endif
