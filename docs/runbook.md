# 관제 대응 절차서 (runbook)

Discord 알림이 오면 아래 순서로 확인한다. Kibana: `https://kibana.xmcda.store`(관리자, Access 로그인 → Kibana 로그인 `elastic`).
공통 검색: Discover → 데이터 보기 `ZT 로그` → `zt.identity : "<사용자>"`, 기간 최근 1시간.

## 1. [ZT 즉시 대응]
| 이벤트(zt.event) | 의미 | 확인 | 조치 |
|---|---|---|---|
| `waf_reported` | 로그인한 사람이 앱 안에서 공격(SQL 삽입 등) → 해제 불가 위험 | 같은 사람의 `gate_deny`, WAF 원문(`tags: waf_block`), 공격 경로(`zt.path`) | 본인 확인 전까지 해제하지 않음. 오탐이면 관리자 콘솔에서 해제(해제 기록 `risk_release`가 남음) |
| `login_locked` | 5분에 5회 이상 로그인/재인증 실패 | `login_failed` 건수와 접속 IP(`zt.client_ip`, 지도 `zt.src.geo`) | IP가 여러 곳이면 크리덴셜 스터핑 의심 → 본인에게 비밀번호 변경 안내. 5분 뒤 자동 해제 |
| `pwned_password_detected` | 유출 목록에 있는 비밀번호로 로그인 | 이후 `password_changed`가 있는지 | 없으면 본인에게 변경 요청(TOTP 통과 후 변경 화면이 강제됨) |
| `device_sweep` + `device_session_revoked` | 사용 중 기기 상태가 나빠져(방화벽 꺼짐 등) 세션을 끊음 | `zt.reason` | 본인에게 원인(방화벽 켜기 등) 안내. 고쳐지면 자동 복구 |
| `decision` + `geo_velocity` / `session_country_change` | 불가능한 이동 / 세션 도중 나라 바뀜(쿠키 탈취 의심) | 이전/이후 접속 위치, 시간 간격, VPN 사용 여부 | 본인이 아니면 세션 폐기 + 비밀번호/TOTP 재설정 |
| `decision` + `threat_intel_match` | 위험 IP에서 접속(그 요청만 차단) | AbuseIPDB 점수, 같은 IP의 다른 계정 시도 | 반복되면 해당 IP 대역 확인 |
| `mtls_client_rejected` | 내부 서버에 인증서 없는 접속 | `zt.remote`(보낸 곳 사설 IP) | 내부 침해 의심 → 해당 서버 확인 |

## 2. [ZT 반복 차단] (같은 사람 10분 5회 이상 차단/재인증 요구)
1. `zt.event : "decision" and zt.identity : "<사용자>"` → `zt.signals`가 무엇인지 본다.
2. 기기 신호(`device_*`)면 직원 쪽 환경 문제(WARP 미연결, 방화벽) 가능성이 크다 → 안내.
3. 위치/IP 신호면 1번 표의 해당 줄을 따른다.

## 3. [ZT 장애] 판단 엔진 응답 없음 (`gate_deny` + `pdp_unavailable`)
전 직원이 막히는 상황(fail-closed 설계: 엔진에 못 물으면 통과시키지 않음).
1. CloudWatch → `/aws/lambda/risk-score-engine` 오류/타임아웃 확인.
2. API Gateway 5xx, DynamoDB 제한 여부 확인.
3. 복구 후 `gate_deny`가 멈추는지 Kibana에서 확인. 원인과 시간을 기록한다.

---
## Kibana 대시보드(직접 만들기, Dashboard → Create → Lens)
| 패널 | 설정 |
|---|---|
| 판단 결과 추이 | 필터 `zt.event:decision`, X축 시간, 분할 `zt.action` |
| 점수 분포 | `zt.event:decision`, 히스토그램 `zt.score` |
| 신호별 기여 | `zt.event:decision`, 상위 값 `zt.signals` |
| 접속 위치 지도 | Maps, 위치 필드 `zt.src.geo.location` |
| 차단 상위 사용자 | `zt.event:decision and zt.allow:false`, 상위 값 `zt.identity` |
| WAF 차단 | `zt.event:waf_reported`, 상위 값 `zt.path`, `zt.signals` |
| 로그인 실패/잠금 | `zt.event:(login_failed or login_locked)`, 시간별 |
