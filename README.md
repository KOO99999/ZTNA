# Risk Score Engine 기반 제로트러스트 접근 통제 시스템

> KDT 「실무중심 정보보안 & 클라우드 네트워크 전문가 양성 과정」 최종 팀 프로젝트
> 신원(Identity)·세션(Session) 계층에서, 로그인 순간부터 세션이 끝날 때까지 접근 권한을 지속적으로 재평가하는 제로트러스트 시스템

---

## 1. 프로젝트 개요

대부분의 접근 통제는 "로그인에 성공했는가"까지만 확인하고, 그 이후로는 세션이 끝날 때까지 다시 확인하지 않습니다. 이 프로젝트는 그 가정 자체를 깨는 것이 목표입니다.

- 로그인 시점에는 자격증명뿐 아니라 **접속 시간대, 위치, 브루트포스 여부, SQL 인젝션 시도, 기기 지문, 평판 정보(위협 인텔리전스)** 등 여러 신호를 종합해 **위험점수(Risk Score)** 를 직접 계산합니다.
- 로그인 이후에도 세션이 살아있는 동안 **웹 서버 앞단(nginx)에서 주기적으로 위험점수를 재평가**하여, 한 번 로그인에 성공했다고 그 이후 행위까지 무조건 신뢰하지 않습니다.
- 위험점수는 자원(Resource)마다 다른 임계값을 가지며, 일반 업무 자원과 관리자 자원은 서로 다른 기준·다른 장애 정책(Fail-Open/Fail-Closed)을 적용받습니다.

"제로트러스트 플랫폼을 통째로 구축"하는 것이 아니라, **로그인 관문 + 세션 재평가라는 신원/세션 계층 하나를 제대로 검증**하는 것이 이 프로젝트의 범위입니다.

## 2. 핵심 아이디어 / 차별점

- **Cloudflare Access가 대신 해주는 부분과, 우리가 직접 만든 부분을 분리**해서 보여줍니다. Access/Worker는 정책 집행(PEP) 역할만 하고, "무엇을 근거로 얼마나 위험한지"를 판단하는 **Risk Score Engine은 직접 설계·구현한 핵심 산출물**입니다.
- 위험 신호는 하나의 거대한 if문이 아니라, 신호별로 **독립된 가산 규칙 + 그룹(behavioral/security) + 회복 가능 여부(resettable)** 를 가진 구조로 설계했습니다. 예를 들어 "위치가 낯설다"는 MFA로 해소되지만, "SQL 인젝션을 시도했다"는 MFA를 통과해도 리셋되지 않습니다.
- PDP(판단)가 장애로 응답하지 못하는 상황까지 가정해, 자원별로 다른 **Fail-Open/Fail-Closed 정책**을 미리 정의해 둡니다.
- 설계만 하고 끝내지 않고, **Trust/Risk 엔진을 끈 상태로 먼저 뚫히는 모습을 보여준 뒤 켠 상태에서 막히는 모습을 보여주는 before/after 실측**으로 효과를 검증합니다.

## 3. 아키텍처

제로트러스트의 표준 구성요소인 PDP(Policy Decision Point) / PEP(Policy Enforcement Point) / PIP(Policy Information Point) 역할을 명확히 분리했습니다.

```
                         ┌─────────────────────────┐
  사용자 요청  ───────▶  │   Cloudflare Access      │  ← PEP (정책 집행)
                         │   + Cloudflare Worker    │     External Evaluation 결과를
                         └────────────┬─────────────┘     JWT로 서명해 Access에 전달
                                      │ (신호 원본 데이터 전달)
                                      ▼
                         ┌─────────────────────────┐
                         │  AWS Lambda              │  ← PDP (정책 결정)
                         │  risk_score_engine.py    │     위험 신호 종합 → 위험점수 산출
                         └────────────┬─────────────┘     → 자원별 임계값과 비교
                                      │
              ┌───────────────────────┼───────────────────────┐
              ▼                       ▼                       ▼
     AbuseIPDB / MaxMind      DynamoDB                 AWS SSM Parameter Store
     (threat_intel,           (risk_score_log,          (계정 시딩 정보,
      geo_velocity 등)         user_risk)                destroy 후에도 보존)
     ← PIP (신호 수집)

   사용자 로그인/세션 ───▶ nginx(Web) ───▶ Flask(App, SQLAlchemy) ───▶ RDS(DB)
                            (3-Tier, Security Group으로 계층간 통신 최소권한 제한)
                            세션 중 위험 재평가(B계층)도 이 앞단에서 수행
```

- **3-Tier 인프라**: Web(nginx 리버스 프록시) / App(Flask 로그인서버) / DB(RDS) 를 각각 별도 EC2로 분리하고, Security Group으로 "App은 DB로만 egress 가능" 등 계층간 통신을 최소권한 원칙으로 제한
- **IaC**: 전체 인프라를 Terraform으로 관리, 매 작업 종료 시 `terraform destroy` → 재개 시 `terraform apply`로 비용 절감 (영구 보존이 필요한 데이터는 SSM Parameter Store/DynamoDB로 분리)

## 4. 기술 스택

| 영역 | 기술 |
|---|---|
| 인프라/IaC | AWS EC2(3-Tier), RDS, Lambda, API Gateway, DynamoDB, SSM Parameter Store, Terraform |
| 접근 제어 (PEP) | Cloudflare Access (Zero Trust), Cloudflare Worker (External Evaluation, JWT 서명) |
| 위험 판단 (PDP) | AWS Lambda (`risk_score_engine.py`) |
| 애플리케이션 | Flask (로그인서버, SQLAlchemy ORM), nginx (리버스 프록시 + WAF) |
| WAF | nginx + ModSecurity + OWASP CRS |
| 인증 | TOTP(MFA), Step-up 재인증 |
| 외부 위협 인텔리전스 | AbuseIPDB(`threat_intel_match`), MaxMind GeoLite2(`geo_velocity`), Have I Been Pwned(`pwned_password`) |

## 5. 위험 신호 (Risk Signals)

`risk_score_engine.py`의 `RISK_MATRIX`에 정의된 신호들입니다. `group`이 `security`인 신호는 MFA를 통과해도 기본적으로 리셋되지 않으며, `resettable: True`로 명시된 신호만 예외적으로 해소됩니다.

| 신호 | 배점 | 그룹 | MFA로 리셋 | 설명 |
|---|---|---|---|---|
| `night_access` | +20 | behavioral | 해당 없음 | 평소와 다른 시간대(야간) 접속 |
| `unknown_location` | +40 | behavioral | 해당 없음 | 낯선 위치/국가에서의 접속 |
| `brute_force` | +58 | security | ✅ | 짧은 시간 내 반복 로그인 실패 (5분/5회 기준 즉시 잠금) |
| `device_fingerprint_mismatch` | +76 | security | ❌ | 등록되지 않은 기기로 접속 (서명된 기기 쿠키 미보유) |
| `threat_intel_match` | +86 | security | ❌ | AbuseIPDB 등 위협 인텔리전스에 등록된 IP |
| `waf_sqli` | +94 | security | ❌ | 로그인 폼 등 입력값에서 SQL 인젝션 시도 탐지 |

**추가 설계·확장 예정 신호**: `geo_velocity`(물리적으로 불가능한 단거리 이동속도 — MaxMind GeoLite2 좌표 기반), `pwned_password`(Have I Been Pwned 유출 비밀번호 — 즉시 차단 대신 MFA 통과 후 비밀번호 변경 유도), `resource_owner_mismatch`(IDOR 탐지)

## 6. 시나리오 (0~8막)

실제 공격 기법을 단계별로 재현하며 각 단계에서 Risk Score Engine이 어떻게 반응하는지 검증합니다.

| 막 | 주제 | 검증 포인트 |
|---|---|---|
| 1막 | 야간 접속 + 단말 변경 | 비정상 시간대/기기 조합 시 위험점수 상승 확인 |
| 3막 | Step-up MFA 트리거 | 임계치 초과 시 추가 인증 요구, 통과 후 점수 초기화 여부 |
| 4막 | IDOR | 타 사용자 리소스 직접 접근 시도 |
| 5막 | MFA 재인증 우회 | IDOR 발생 후에도 security 그룹 누적 점수가 유지되는지 세션 추적 |
| 6막 | DB Tier 비정상 쿼리 및 토큰 위변조 | JWT 서명 변조(`alg: none`), SQL 인젝션 탐지 후 즉시 토큰 무효화 |
| 7막 | PDP 장애 시 Fail-Open/Fail-Closed | Lambda 강제 장애 시 일반 자원(fail-open)과 관리자 자원(fail-closed)의 차등 동작 |
| 8막 | IDOR 피벗 체인 | 정찰 → IDOR을 통한 권한 확인까지의 연속 공격 흐름 |

시연은 **Risk Score Engine을 끈 상태로 공격이 통과되는 것을 먼저 보여준 뒤, 켠 상태에서 동일 공격이 차단되는 것을 보여주는 before/after 비교** 방식으로 진행합니다.

## 7. 레포 구조 (참고용)

```
.
├── terraform/              # AWS 인프라 전체 (EC2 3-Tier, Lambda, API Gateway, DynamoDB, SSM 등)
│   ├── main.tf
│   ├── ec2_web.tf
│   ├── ec2_app.tf
│   └── terraform.tfvars.example
├── access_worker/           # Cloudflare Worker (External Evaluation, JWT 서명)
│   ├── src/index.js
│   ├── wrangler.toml
│   └── generate-keys.js
├── app/                      # App Tier (Flask 로그인서버)
│   └── auth_app.py
├── lambda/                   # PDP (위험점수 계산 엔진)
│   ├── risk_score_engine.py
│   └── test_risk_score.py
└── README.md
```

> 실제 폴더명/경로는 레포 상태에 맞춰 조정해주세요.

## 8. 실행 방법 (개요)

1. **인프라 배포**: `terraform/` 에서 `terraform.tfvars` 작성 후 `terraform apply`
2. **Worker 배포**: `access_worker/` 에서 `npm install` → `npm run keys` → `wrangler login` → `wrangler secret put` (키/비밀값 등록) → `npm run deploy`
3. **Cloudflare Access 정책**: `main.tf`에 정의된 `cloudflare_access_application`/`cloudflare_access_policy`가 자동으로 적용됨 (이메일 인증 AND 위험점수 통과를 모두 요구)
4. **테스트**: `lambda/test_risk_score.py`로 위험점수 로직 단위 테스트, 실제 로그인/공격 시나리오는 위 6번 표의 막 순서대로 진행

## 9. 팀 구성

| 역할 | 담당 |
|---|---|
| 공격(Red) | 시나리오별 침투 재현, 취약점 발견 |
| 방어(Blue) | Risk Score Engine/인프라 설계·구현, 탐지 로직 개발 |

## 10. 참고 자료

- 제로트러스트 가이드라인 2.0 (과학기술정보통신부·KISA·한국제로트러스트포럼)
- 금융분야 제로트러스트 보안 안내서 (금융보안원)
- CISA Zero Trust Maturity Model
- Microsoft Entra Conditional Access, Okta Adaptive MFA (위험 기반 재인증 패턴 참고)
