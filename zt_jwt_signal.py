"""JWT 위변조 시도를 'IP 기준 신호'로 엔진에 알리는 모듈. auth_gate.py 프로세스 안에서 쓴다.

왜: auth_gate는 서명/클레임 검증에 실패한 토큰을 403(jwt_invalid)으로 막는다(1차 방어, 엔진과 무관).
    하지만 막기만 하면 "같은 곳에서 위조 토큰을 계속 던지는 중"이라는 사실을 아무도 모른다.
    그래서 검증 실패가 한 IP에서 반복되면 엔진에 jwt_tamper 신호로 알린다(관제/알림용).

IP 기준인 이유: 위조 토큰은 검증을 통과하지 못했으므로 그 안의 email은 믿을 수 없다. 믿을 수 없는 이메일에
    위험을 걸면 "남의 이메일로 위조 토큰을 만들어 그 사람을 잠그는" 공격이 가능해진다(엔진 User Risk 주석과 같은 이유).
    그래서 신원 없이(identity 없음) 접속 IP만 담아 보내고, 엔진도 이 신호는 계정에 저장하지 않는다(ip_based).

세는 사유: 토큰 내용을 건드린 흔적(서명/aud/iss/클레임/형식/alg/kid)만 센다.
    세지 않는 것: token_missing(그냥 인증 없는 접근), expired(정상 사용자의 오래된 토큰),
                 config_missing/jwks_unavailable(우리 쪽 장애) - 공격이 아니므로 오탐을 만든다.
환경변수: ZT_JWT_TAMPER_THRESHOLD(기본 5), ZT_JWT_TAMPER_WINDOW_SECONDS(기본 600)
"""
import ipaddress
import os
import threading
import time
import uuid
from collections import defaultdict, deque
from datetime import datetime, timezone

import requests

import zt_risk

THRESHOLD = int(os.environ.get("ZT_JWT_TAMPER_THRESHOLD", "5"))
WINDOW_SECONDS = int(os.environ.get("ZT_JWT_TAMPER_WINDOW_SECONDS", "600"))
MAX_TRACKED_IPS = 20000

TAMPER_REASONS = frozenset({
    "bad_signature", "bad_alg_or_kid", "unknown_kid", "malformed",
    "bad_aud", "bad_iss", "missing_claim", "no_email_claim", "invalid",
})

_hits = defaultdict(deque)       # ip -> 최근 시각들
_reported_at = {}                # ip -> 마지막으로 엔진에 알린 시각
_lock = threading.Lock()


def normalize_ip(value):
    """헤더 값 -> 정규화된 IP 문자열. 형식이 이상하면 None(남용된 헤더로 메모리를 채우지 못하게)."""
    if not value:
        return None
    try:
        return ipaddress.ip_address(str(value).split(",")[0].strip()).compressed
    except ValueError:
        return None


def record(ip, now=None):
    """1건을 세고 (이번에 엔진에 알려야 하는지, 창 안의 횟수)를 돌려준다. 알린 뒤 같은 창 안에서는 다시 알리지 않는다."""
    now = now or time.time()
    with _lock:
        if ip not in _hits and len(_hits) >= MAX_TRACKED_IPS:
            for k in [k for k, v in _hits.items() if not v or now - v[-1] > WINDOW_SECONDS]:
                del _hits[k]
                _reported_at.pop(k, None)
            if len(_hits) >= MAX_TRACKED_IPS:
                return False, 0        # 여전히 가득 차 있으면 새 IP는 세지 않는다(메모리 상한)
        q = _hits[ip]
        q.append(now)
        while q and now - q[0] > WINDOW_SECONDS:
            q.popleft()
        count = len(q)
        if count < THRESHOLD or now - _reported_at.get(ip, 0) < WINDOW_SECONDS:
            return False, count
        _reported_at[ip] = now
        return True, count


def report(ip, reason, count, host, path):
    """엔진에 알린다. 성공하면 True. 판정(점수/차단)은 엔진이 하고, 이미 gate가 막은 요청에는 영향이 없다."""
    body = {"session_id": str(uuid.uuid4()), "source": "gate_jwt", "jwt_tamper": True,
            "client_ip": ip, "request_timestamp": datetime.now(timezone.utc).isoformat(),
            "resource_path": zt_risk.resource_path_for(host, path)}
    try:
        resp = requests.post(zt_risk.PDP_EVALUATE_URL, timeout=3, json=body,
                             headers={"Content-Type": "application/json", "X-Evaluate-Secret": zt_risk.EVALUATE_SHARED_SECRET})
        ok = resp.status_code == 200
    except Exception as e:
        print(f"[JWT_TAMPER_REPORT_FAILED] ip={ip} error={type(e).__name__}", flush=True)
        ok = False
    print(f"[JWT_TAMPER_REPORTED] ip={ip} count={count} window={WINDOW_SECONDS}s reason={reason} ok={ok}", flush=True)
    # identity 자리에 "ip:<주소>"를 넣는다: 알림(ElastAlert)이 사람(identity)별로 5분 묶음을 하므로, IP마다 따로 알리기 위함
    zt_risk.log_event("jwt_tamper_reported", identity=f"ip:{ip}", client_ip=ip, count=count, window_seconds=WINDOW_SECONDS,
                      reason=reason, host=host, path=path, reported=ok)
    if not ok:
        with _lock:       # 실패했으면 다음 위조 시도 때 바로 다시 알리도록
            _reported_at.pop(ip, None)
    return ok


def handle(reason, ip_header, host, path, now=None, background=True):
    """gate가 JWT 검증에 실패했을 때 부른다. 이 함수는 어떤 경우에도 예외를 내지 않는다(차단 응답을 바꾸지 않기 위해).
    반환: 엔진에 알리는 시도를 시작했으면 True."""
    try:
        if reason not in TAMPER_REASONS:
            return False
        ip = normalize_ip(ip_header)
        if not ip:
            return False
        should, count = record(ip, now)
        zt_risk.log_event("jwt_verify_failed", client_ip=ip, reason=reason, host=host, path=path, count=count)
        if not should:
            return False
        if background:      # 요청 응답을 엔진 호출(최대 3초) 때문에 늦추지 않는다
            threading.Thread(target=report, args=(ip, reason, count, host, path), daemon=True,
                             name="zt-jwt-tamper-report").start()
        else:
            report(ip, reason, count, host, path)
        return True
    except Exception as e:
        print(f"[JWT_TAMPER_HANDLE_ERROR] {type(e).__name__}", flush=True)
        return False
