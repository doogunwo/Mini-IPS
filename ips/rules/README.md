# Rules

이 디렉터리는 OWASP CRS 원본 `.conf`와 변환된 JSONL 룰 파일을 보관한다.

## 디렉터리

- `crs_conf/`
  - 원본 CRS `.conf` 파일을 넣는 위치
- `generated/`
  - 변환된 JSONL 출력 위치
- `tools/`
  - `.conf -> JSONL` 변환 스크립트

## JSONL 스키마

한 줄이 하나의 룰이다.

```json
{
  "rid": 942100,
  "pid": "POLICY_SQL_INJECTION",
  "pname": "SQL_INJECTION",
  "pat": "(?i:select.+from)",
  "prio": 4,
  "ctx": "ARGS",
  "targets": ["ARGS", "HEADERS"],
  "op": "rx",
  "op_negated": false,
  "phase": 2,
  "severity": "ERROR",
  "transforms": ["none", "urlDecodeUni", "htmlEntityDecode"],
  "setvars": ["tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}"],
  "ctls": [],
  "chain": false,
  "msg": "SQL Injection Attack Detected",
  "tags": ["attack-sqli", "paranoia-level/1"],
  "source": "REQUEST-942-APPLICATION-ATTACK-SQLI.conf",
  "variables": "ARGS|ARGS_NAMES|REQUEST_HEADERS",
  "ver": "OWASP_CRS/4.25.0-dev",
  "rev": "1"
}
```

## 컨텍스트 값

- `URI`
- `ARGS`
- `HEADERS`
- `BODY`
- `RESPONSE_BODY`

## 사용 예시

```bash
cd /home/doogunwo/training/Mini-IPS/ips
python3 rules/tools/extract_crs_rx_to_jsonl.py \
  --input-dir rules/crs_conf \
  --output rules/generated/rules.jsonl
```

전체 SecRule operator까지 포함해서 뽑으려면:

```bash
cd /home/doogunwo/training/Mini-IPS/ips
python3 rules/tools/extract_crs_full_to_jsonl.py \
  --input-dir rules/crs_conf \
  --output rules/generated/rules_full.jsonl
```
