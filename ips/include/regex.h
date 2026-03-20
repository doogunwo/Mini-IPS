/**
 * @file regex.h
 * @brief IPS 시그니처 및 정책 정의
 */
#ifndef REGEX_H
#define REGEX_H

#include <stddef.h>

#define POLICY_LIST                                    \
    X(POLICY_SQL_INJECTION, "SQL_INJECTION")           \
    X(POLICY_XSS, "XSS")                               \
    X(POLICY_COMMAND_INJECTION, "COMMAND_INJECTION")   \
    X(POLICY_DIRECTORY_TRAVERS, "DIRECTORY_TRAVERSAL") \
    X(POLICY_APP_WEAK, "APP_WEAK")                     \
    X(POLICY_SCANNER, "SCANNER")                       \
    X(POLICY_PROTOCOL_VIOLATION, "PROTOCOL_VIOLATION") \
    X(POLICY_INFO_LEAK, "INFO_LEAK")                   \
    X(POLICY_WEBSHELL, "WEBSHELL")

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
    IPS_CTX_REQUEST_BODY,
    IPS_CTX_RESPONSE_BODY
} ips_context_t;

/** CRS operator 유형이다. */
typedef enum {
    IPS_OP_RX = 0,
    IPS_OP_PM,
    IPS_OP_PM_FROM_FILE,
    IPS_OP_CONTAINS,
    IPS_OP_BEGINS_WITH,
    IPS_OP_ENDS_WITH,
    IPS_OP_STREQ,
    IPS_OP_WITHIN,
    IPS_OP_DETECT_SQLI,
    IPS_OP_DETECT_XSS,
    IPS_OP_EQ,
    IPS_OP_GE,
    IPS_OP_GT,
    IPS_OP_LT,
    IPS_OP_VALIDATE_BYTE_RANGE,
    IPS_OP_IP_MATCH,
    IPS_OP_UNKNOWN
} ips_operator_t;

/** 탐지 엔진이 사용하는 IPS 시그니처 한 행이다. */
typedef struct {
    POLICY         policy_id;    // Enum ID
    const char    *policy_name;  // 상위 정책 이름 (예: SQL_INJECTION)
    const char    *pattern;      // 정규식 패턴 (C-String)
    int            is_high_priority;  // 높은 우선순위 여부
    ips_context_t  context;           // 탐지 컨텍스트
    ips_operator_t op;                // CRS operator
    int            op_negated;        // 부정 연산 여부
    int            rule_id;           // 원본 CRS 룰 ID
    const char    *source;            // 원본 CRS 파일명
    const char   **data_values;       // pmFromFile 로드 결과
    size_t         data_value_count;  // pmFromFile 값 개수
} IPS_Signature;

/** 내장 IPS 시그니처 전역 테이블이다. */
extern const IPS_Signature *g_ips_signatures;
/** 내장 시그니처 테이블 엔트리 개수이다. */
extern int g_signature_count;
/** 정책 식별자의 출력용 이름을 돌려준다. */
const char *get_policy_name(POLICY p);
/** CRS operator 이름을 enum으로 변환한다. */
ips_operator_t ips_operator_from_string(const char *name);
/** CRS operator enum을 출력용 문자열로 변환한다. */
const char *ips_operator_name(ips_operator_t op);
/** 기본 rules_full.jsonl 또는 지정 경로에서 룰을 적재한다. */
int regex_signatures_load(const char *jsonl_path);
/** 적재된 룰 메모리를 해제한다. */
void regex_signatures_unload(void);

#endif
