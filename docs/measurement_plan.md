# 실측 계획서

## 0. 무엇을 증명하나
같은 공격을 **세 가지 구성**으로 돌려, 위험점수 엔진이 더하는 것을 숫자로 보인다.

| 방식 | WAF (`waf_engine_mode`) | 엔진 (`decision_mode`) | 뜻 |
|---|---|---|---|
| ① 기본 | `DetectionOnly`(기록만) | `observe` | Cloudflare 로그인 + TOTP만 있는 구성 |
| ② WAF | `On`(차단) | `observe` | 로그인 + TOTP + WAF |
| ③ 우리 방식 | `On` | `enforce` | 위 + 위험점수 엔진 |

- ①②에도 **로그인 + TOTP는 켜져 있다**(아무것도 없는 상태와 비교하는 것이 아님).
- 관찰 모드(`observe`): 엔진은 점수·판정을 똑같이 계산해 기록(`would_action`)만 하고 통과시킨다.
  Microsoft Entra 조건부 액세스의 "보고 전용(Report-only)"과 같은 방식. 해제 불가 위험 저장·기기 세션 끊기도 하지 않는다.
- 엔진이 아닌 장치가 막은 것은 엔진 공으로 세지 않는다(결과표 "막은 주체" 칸).

## 1. 대표 지표 (발표 순서)
| # | 지표 | 정의 | 어디서 |
|---|---|---|---|
| 1 | **3방식 비교표** | 막마다 ①②③에서 뚫림/막힘 | 결과표 |
| 2 | **차단까지 걸린 시간** (대표) | 공격 첫 요청 → 첫 차단 판정(초), 사건 → Discord 도착(초) | Kibana ⑧ 시각 차이, Discord 시각 |
| 3 | 정상 직원 방해(오탐) | 1막 10회 중 추가 인증/차단 횟수 + 공개 데이터셋 평가(`docs/evaluation/`) | Kibana ⑧ |
| 4 | WAF 탐지율·오탐률 | GoTestWAF 공격 요청 차단 비율 / 정상 요청 잘못 차단 비율 | GoTestWAF 보고서 |
| 5 | 판단 단계 지연 | 웹 서버→엔진 왕복 ms(평균, 95% 값), 엔진 처리 ms | Kibana ⑨(`pdp_call`), ⑧(`duration_ms`) |
| 6 | 장애 모드 | 엔진 정지 중 등급별 동작 | 8막 |
| 7 | 즉흥 공격 | 기준값을 모르는 팀원의 공격 중 잡은 것 / 놓친 것 | 9막 |

## 2. 준비
| 준비물 | 상태 |
|---|---|
| 관찰 모드 스위치 `decision_mode` | stage22 |
| Kibana ⑧ 실측 결과 / ⑨ 엔진 응답 시간 + CSV 내보내기(Share → CSV) | stage22 |
| WAF 스위치 `waf_engine_mode` | 있음 |
| 브라우저 2개(일반 + InPrivate), VPN(일본), 쿠키 편집 확장, Tor Browser | 설치 |
| Kali(또는 Docker 되는 PC): GoTestWAF(Docker), sqlmap | 설치 |

**실측 전 tfvars 확인(모두 켬):** `device_signal_mode = "enforce"`, `session_binding_mode = "enforce"`,
`geo_velocity_mode = "enforce"`, `baseline_mode = "personal"`, `enable_elk = true`.
실측이 끝나면 `decision_mode = "enforce"`, `waf_engine_mode = "On"`으로 되돌린다.

계정: `employee01`(주인공), `employee02`(남의 기기·남의 자료 주인), 인사팀 계정(6막 검색창), 관리자(해제).

## 3. 하루 진행 순서
1. apply → 앱마다 한 번씩 미리 접속(첫 접속 때 Cloudflare 화면이 잠깐 뜨는 것 방지) → Kibana·Discord 연결 확인
2. **①** (`DetectionOnly` + `observe`) apply → 2~7막 → 시작/끝 시각 기록
3. **②** (`On` + `observe`) apply → 2~7막 → **GoTestWAF** 실행(WAF 단독 성능은 여기서만 잰다)
4. **③** (`On` + `enforce`) apply → 1~8막(막마다 관리자 해제 후 다음 막) → 9막(즉흥 공격)
5. Kibana ⑧·⑨ → 기간을 실측 시간으로 → CSV 내보내기 → 결과표 정리

방식 바꾸기는 tfvars 두 값만 바꾸고 apply(엔진 환경변수, 웹 서버 WAF 설정만 바뀜).

## 4. 시나리오
기준선: 최고기밀(관리자·Kibana) 20 / 기밀(인사·개발) 40 / 내부(포털·마케팅) 60. 기준선~+20은 추가 인증, 그 위는 차단.

| 막 | 상황 | 하는 일 | ③ 기대 결과 | ①② 기대 | 막은 주체(③) | 반복 |
|---|---|---|---|---|---|---|
| 1 | 평소 직원 | WARP 켬, 한국, 포털→개발 | 모두 통과, 추가 인증 0회 | 같음 | - | 10 |
| 2 | 해외에서 갑자기 접속 | 로그아웃 → VPN 일본 → 바로 로그인 | 처음 보는 나라 40 + 불가능한 이동 40 = 80: 포털 추가 인증, 개발·관리자 차단 | 통과 | 엔진 | 3 |
| 2-b | 피해자 신고 | 원래 기기에서 "아니요, 신고할게요" | 계정 전체 차단 + Discord [ZT 직원 신고] | 통과(기록만) | 엔진 | 1 |
| 3 | 기기 | ① WARP 끄기 ② employee02가 employee01 기기 ③ 방화벽 끄기 | ①② 포털 통과, 개발·관리자 차단 / ③ 관리자만 차단 + 사용 중 세션 끊김 | 통과 | 엔진 | 각 3 |
| 4 | 쿠키 탈취 | 한국 로그인 → 쿠키를 VPN 일본 브라우저로 복사 | 다시 로그인 요구, 훔친 쿠키로 못 들어감 | 통과 | 엔진 | 3 |
| 5 | 계정 공격 | ① 비밀번호 5번 틀리기 ② Tor로 접속 | ① 5분 잠금 ② 익명 네트워크 40(+위협 IP면 차단) | ① 잠금 ② 통과 | ① **로그인 서버** ② 엔진 | 각 3 |
| 6 | 웹 공격 | 인사 검색창에 SQL 삽입 1건 + sqlmap | 그 요청 차단 + **계정 전체 차단** + Discord | ① 통과 ② 그 요청만 차단 | 요청: **WAF** / 계정: 엔진 | 3 |
| 7 | 내부자(IDOR) | 남의 급여명세서 주소 3번 | 404 + 3번째에 계정 전체 차단 + Discord | 404만 | 요청: **앱** / 계정: 엔진 | 3 |
| 8 | 엔진 장애 | 엔진 정지 → 포털/개발/관리자/새 로그인 | 관리자·새 로그인 차단, 개발 10분 재사용, 포털 15분 통과 + Discord [ZT 장애] | (비교 안 함) | 판단 서비스 | 1 |
| 9 | 즉흥 공격 | 팀원이 기준값을 모른 채 30분 자유 공격 | 잡은 것/놓친 것 그대로 기록 | (비교 안 함) | - | 1 |

- 2막: VPN IP가 AbuseIPDB 위험 점수 50 이상이면 위협 IP 신호가 더해져 포털도 차단된다. 기대와 다르면 실제 신호를 그대로 적는다.
- 9막: 공격 팀원은 점수표·기준선을 보지 않는다. 방어 팀원은 끝난 뒤 Kibana로 무엇이 잡혔는지 정리. 놓친 것은 "향후 과제"로 연결.

## 5. 명령 모음
**8막 엔진 정지/복구 (AWS CLI)** — 예약 동시 실행을 0으로 두면 모든 호출이 거부된다.
```
aws lambda put-function-concurrency --function-name risk-score-engine --reserved-concurrent-executions 0
aws lambda delete-function-concurrency --function-name risk-score-engine
```

**GoTestWAF (②에서만, Docker)** — 로그인 쿠키는 브라우저 개발자 도구에서 `CF_Authorization` 값을 복사(화면·캡처에 노출 금지).
```
docker run --rm --network="host" -v ${PWD}/reports:/app/reports wallarm/gotestwaf \
  --url=https://xmcda.store/ --addHeader="Cookie: CF_Authorization=<값>" \
  --blockStatusCodes=403 --reportFormat=html --noEmailReport
```
- 결과: 공격 요청 차단 비율(true-positive) = 탐지율, 정상 요청 통과 비율(true-negative)의 나머지 = 오탐률.
- ③에서 돌리지 않는 이유: 첫 차단 때 엔진이 계정 전체를 막아 이후 요청이 모두 403이 되므로 WAF 성능이 부풀려진다.

**sqlmap (6막, ①②③ 각각)**
```
sqlmap -u "https://hr.xmcda.store/?q=test" --cookie="CF_Authorization=<값>" --batch --level=1 --risk=1
```
- 이 앱은 SQL을 쓰지 않아 실제 취약점은 없다(검색은 목록 필터). 보는 것은 "공격 요청이 어디서 막히나"이다.

## 6. 결과 기록표 양식
| 막 | 회차 | 방식 | 시작 시각 | 기대 | 실제 판정 | would_action | 점수/신호 | 막은 주체 | 차단까지(초) | 알림까지(초) | 캡처 |
|---|---|---|---|---|---|---|---|---|---|---|---|

## 7. 한계 (보고서에 같이 적을 것)
- 반복 3~10회의 **재현 시험**이며 통계적 결론이 아니다.
- 행동 신호의 탐지율·오탐률은 공개 데이터셋(RBA, CERT r4.2)으로 평가했다. 실제 직원 데이터가 아니다.
- 6·7막은 WAF와 앱이 그 요청 자체를 먼저 막는다. 엔진의 기여는 "그 계정의 다른 모든 접속까지 막는 것"이다.
- 5막 ①의 잠금은 로그인 서버 기능이라 세 방식이 같다.
- GoTestWAF 점수는 우리 WAF 설정(ModSecurity + OWASP CRS 기본값) 기준이다.

## 8. 지킬 것
- 캡처에서 이메일 일부, IP, 기기 ID, 위치, 쿠키 값은 가린다. Kibana 비밀번호와 tfvars는 화면에 띄우지 않는다.
- 막이 끝날 때마다 관리자 콘솔에서 해제하고 다음 막으로 간다.
- 실측이 끝나면 `decision_mode = "enforce"`, `waf_engine_mode = "On"`으로 되돌리고 apply.
