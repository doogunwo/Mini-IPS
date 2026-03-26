# 2026-03-25 Inline-IPS TPROXY Model Mismatch (Bridge-only ns_proxy vs L3 Delivery)

## 이슈명
`inline-ips`가 `ns_proxy`에서 리스닝(`0.0.0.0:50080`) 중인데도, TPROXY 카운터는 증가하지만 유저스페이스 `accept()`로 연결이 올라오지 않는 문제.

## 발생 일시
- 최초 관측: 2026-03-25 (UTC)

## 영향 범위
- 네임스페이스 기반 실험 토폴로지 (`ns_client`, `ns_router`, `ns_proxy`, `ns_server`)
- `inline-ips` (TPROXY listener)
- `iptables mangle PREROUTING` TPROXY 규칙

## 토폴로지 (관측 시점)
- `ns_client`: `20.0.1.100/24`
- `ns_server`: `10.0.1.100/24`, 서비스 포트 `8080`
- `ns_router`: L3 라우팅 전담 (`ip_forward=1`)
- `ns_proxy`: `br0` 브리지 + TPROXY 정책 (라우팅 비활성)

논리 경로:
`ns_client -> ns_router -> ns_proxy(br0) -> ns_server`

## 기대 동작
1. `ns_client -> 10.0.1.100:8080` 요청 발생
2. `ns_proxy`의 TPROXY 규칙 매칭
3. 트래픽이 로컬 소켓 `:50080`으로 전달
4. `inline-ips`에서 `accept()` 성공 + `accepted client=... original_dst=...` 로그 출력

## 실제 동작
1. 서버 응답은 정상 (`ns_server`에서 HTTP 200 로그 반복 확인)
2. `iptables` TPROXY 카운터는 지속 증가
3. `inline-ips`는 `LISTEN 0.0.0.0:50080` 상태 유지
4. `strace` 상 `accept(3, ...)` 대기 상태에서 진전 없음 (accept 이벤트 미발생)
5. 결과적으로 유저스페이스 처리 로그(`accepted`) 미출력

## 관측 증거

### 1) TPROXY 룰 카운터 증가
`ns_proxy`:
- `TPROXY ... tcp dpt:8080 ... redirect 0.0.0.0:50080 mark 0x1/0x1`
- 카운터 예시: `48 -> 54 -> 60 -> ... -> 487` (지속 증가)

### 2) 서버 트래픽 정상
`ns_server` python http.server 로그에서 반복적인:
- `20.0.1.100 - - [date] "GET / HTTP/1.1" 200 -`

### 3) 유저스페이스 listener 상태
`ns_proxy`:
- `ss -antp | grep 50080`
- `LISTEN 0 128 0.0.0.0:50080 ... users:(("inline-ips",pid=...,fd=3))`

### 4) accept 미진입
`ns_proxy`에서 `strace -tt -e accept,accept4,getsockname -p <inline-ips-pid>`:
- `accept(3, ...` 에서 대기
- 클라이언트 요청 중에도 accept 완료 이벤트 확인 불가

## 원인 분석 (핵심)
현재 구성은 **`ns_proxy`를 브리지(L2) 장비로 유지**하려는 요구와,
`inline-ips`가 사용하는 **TPROXY + IP_TRANSPARENT 기반 L3 local delivery 모델**이 충돌함.

정리하면:
- `iptables PREROUTING` 매칭 자체는 가능해서 카운터는 증가함
- 그러나 브리지-only 경로에서 기대한 방식의 `local socket delivery`가 성립하지 않아 `accept()`까지 도달하지 못함

즉, 문제는 단순 로그 버퍼링이 아니라 **데이터패스 모델 불일치**.

## 배제된 가설
1. 로그 레벨/조건 문제
- `ips/src/inline/main.c`의 `accepted` 출력은 `accept` 성공 시 조건 없이 실행됨

2. 버퍼링 문제
- 기존 `fflush(stdout)` 존재
- 추가로 `setvbuf(stdout/stderr)` 보강 적용 시도
- 그래도 accept 자체가 안 들어오면 출력 불가

3. 바이너리 미스매치
- 리스너 시작 로그 (`TPROXY listener started ...`)는 동일 바이너리 실행 정황

## 결론
- 현재 요구("`ns_proxy`는 라우팅하지 않음")를 유지하면,
  현재 `inline-ips`(TPROXY listener) 방식은 기대 동작을 보장하지 못함.

## 해결 옵션

### 옵션 A (요구 유지)
- `ns_proxy` 브리지-only 유지
- `inline-ips` TPROXY 모델 대신 다른 처리 모델로 전환
  - 예: 브리지 경로 패킷 캡처/검사형
- 장점: 역할 분리(`ns_router` 라우팅, `ns_proxy` 브리지) 유지
- 단점: 기존 `inline-ips` 아키텍처 변경 필요

### 옵션 B (동작 보장)
- `inline-ips` 유지
- `ns_proxy`를 L3 경로에 다시 포함시켜 local delivery 성립
- 장점: 현 구현 재사용 가능, 결과 재현 용이
- 단점: "ns_proxy 라우팅 금지" 요구와 충돌

## 다음 액션 제안
1. 아키텍처 선택 확정 (A/B)
2. 선택안 기준으로 `ips.sh` 최종 고정
3. 재현 문서(실행 순서/기대 결과/검증 명령) 업데이트
4. 성공 기준 정의
   - TPROXY 카운터 증가
   - `accept` 이벤트 발생
   - `original_dst` 로그 출력
   - 서버 응답 정상

## 관련 파일
- `/home/doogunwo/training/Mini-IPS/ips/ips.sh`
- `/home/doogunwo/training/Mini-IPS/ips/src/inline/main.c`
- `/home/doogunwo/training/Mini-IPS/ips/src/inline/tproxy.c`
