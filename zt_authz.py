"""앱의 '객체 접근 거부'(IDOR 시도)를 신원과 연결해 위험도 엔진에 알리는 모듈. auth_gate.py 프로세스 안에서 돈다.

왜: 앱(포털)은 남의 급여명세서 요청을 이미 거부한다(1차 방어, 엔진과 무관). 하지만 앱은 거부만 할 뿐이라,
    같은 사람이 번호를 바꿔 가며 계속 두드리거나 다른 앱으로 옮겨 가 정찰해도 아무도 모른다.
    앱이 거부할 때 응답에 X-ZT-Authz: owner_mismatch를 붙이면, 웹 서버 nginx(앱 단계)가 그 헤더를 지우고
    (사용자에게 안 보임) 검증된 신원과 함께 별도 로그에 한 줄 남긴다. 이 모듈이 그 로그를 따라 읽어
    사람별로 세고, 짧은 시간에 반복되면(기본 10분에 3번) 엔진에 resource_owner_mismatch로 알린다.
    엔진은 이 사람에게 해제 불가 위험(user_risk)을 걸어 모든 앱 접근을 막는다(관리자가 해제할 때까지).
    1~2번은 주소를 잘못 친 실수일 수 있어 알리지 않는다(관리자 해제 대상이 실수로 생기지 않게).

경로가 WAF(zt_waf.py)와 같은 이유: 앱 서버에는 엔진 비밀키를 두지 않는다(최소 권한). 신원은 앞단이 JWT 서명을
    검증해 덮어쓴 X-ZT-Identity라 클라이언트가 위조할 수 없다.
로그 한 줄(nginx log_format zt_authz, JSON):
    {"time":"...","identity":"kim@x","host":"xmcda.store","uri":"/payslip/210","authz":"owner_mismatch","status":"404"}
환경변수: ZT_AUTHZ_LOG(기본 /var/log/modsec/zt_authz_app.log), ZT_AUTHZ_THRESHOLD(3), ZT_AUTHZ_WINDOW_SECONDS(600)

[본인 아님 신고] 직원이 포털 '내 보안 기록'에서 "아니요, 신고할게요"를 누르면 포털이 같은 헤더로
    X-ZT-Authz: user_reported_not_me를 붙인다. 이건 본인이 직접 확인한 사건이라 세지 않고 한 번에 바로 엔진에
    user_reported_suspicious로 알린다(Microsoft Entra: 의심 활동을 신고한 사용자는 '높은 사용자 위험' -> 차단/비밀번호 변경).
"""
import json
import os
import re
import threading
import time
import uuid
from collections import defaultdict, deque
from datetime import datetime, timezone

import requests

import zt_risk
import zt_waf

AUTHZ_LOG = os.environ.get("ZT_AUTHZ_LOG", "/var/log/modsec/zt_authz_app.log")
THRESHOLD = int(os.environ.get("ZT_AUTHZ_THRESHOLD", "3"))
WINDOW_SECONDS = int(os.environ.get("ZT_AUTHZ_WINDOW_SECONDS", "600"))
# 사유 -> (엔진 신호, 알릴 횟수). 신원+사유별로 따로 센다.
REASONS = {
    "owner_mismatch": ("resource_owner_mismatch", THRESHOLD),     # 주소 실수일 수 있어 10분에 3번
    "user_reported_not_me": ("user_reported_suspicious", 1),      # 본인이 직접 신고 -> 바로
}
KNOWN_REASONS = set(REASONS)
_EMAIL_RE = re.compile(r"^[^@\s\"]{1,64}@[A-Za-z0-9.-]{1,190}$")
_HOST_RE = re.compile(r"^[A-Za-z0-9.-]{1,253}(:\d{1,5})?$")

_hits = defaultdict(deque)          # (identity, reason) -> 최근 시각들
_reported_at = {}                   # (identity, reason) -> 마지막으로 엔진에 알린 시각
_lock = threading.Lock()


def parse_line(line):
    """로그 한 줄 -> 사건 dict 또는 None. 신원이 없거나 형식이 이상하면 무시(앱은 이미 거부했음)."""
    try:
        rec = json.loads(line)
    except (ValueError, TypeError):
        return None
    if not isinstance(rec, dict):
        return None
    identity = str(rec.get("identity", "")).strip().lower()
    host = str(rec.get("host", "")).strip().lower()
    reason = str(rec.get("authz", "")).strip()
    if not _EMAIL_RE.match(identity) or not _HOST_RE.match(host) or reason not in KNOWN_REASONS:
        return None
    uri = str(rec.get("uri", "/"))[:300]
    return {"identity": identity, "host": host.split(":")[0], "path": uri.split("?")[0] or "/", "reason": reason}


def record(event, now=None):
    """1건을 세고, 이번에 엔진에 알려야 하면 True. 알린 뒤 같은 창(10분) 안에서는 다시 알리지 않는다."""
    now = now or time.time()
    who = (event["identity"], event["reason"])
    threshold = REASONS[event["reason"]][1]
    with _lock:
        q = _hits[who]
        q.append(now)
        while q and now - q[0] > WINDOW_SECONDS:
            q.popleft()
        count = len(q)
        if count < threshold or now - _reported_at.get(who, 0) < WINDOW_SECONDS:
            return False, count
        _reported_at[who] = now
        if len(_hits) > 5000:      # 오래된 사람 정리(메모리 상한)
            for k in [k for k, v in _hits.items() if not v or now - v[-1] > WINDOW_SECONDS]:
                del _hits[k]
        return True, count


def report(event, count):
    """엔진에 알린다(해제 불가 위험을 거는 판단은 엔진이 한다). 성공하면 True."""
    signal = REASONS[event["reason"]][0]
    body = {"identity": event["identity"], "session_id": str(uuid.uuid4()), "source": "app_authz",
            "persist_risk": True, signal: True,
            "request_timestamp": datetime.now(timezone.utc).isoformat(),
            "resource_path": zt_risk.resource_path_for(event["host"], event["path"])}
    try:
        resp = requests.post(zt_risk.PDP_EVALUATE_URL, timeout=3, json=body,
                             headers={"Content-Type": "application/json", "X-Evaluate-Secret": zt_risk.EVALUATE_SHARED_SECRET})
        ok = resp.status_code == 200
    except Exception as e:
        print(f"[AUTHZ_REPORT_FAILED] identity={event['identity']} error={type(e).__name__}", flush=True)
        ok = False
    zt_risk.invalidate_identity(event["identity"])     # 다음 요청은 반드시 엔진에 다시 묻게
    if event["reason"] == "owner_mismatch":
        print(f"[IDOR_REPORTED] identity={event['identity']} count={count} window={WINDOW_SECONDS}s "
              f"host={event['host']} path={event['path']} ok={ok}", flush=True)
        zt_risk.log_event("idor_reported", service="gate", identity=event["identity"], count=count,
                          window_seconds=WINDOW_SECONDS, host=event["host"], path=event["path"], reported=ok)
    else:
        print(f"[USER_REPORT_ESCALATED] identity={event['identity']} ok={ok}", flush=True)
        zt_risk.log_event("user_report_escalated", service="gate", identity=event["identity"], signal=signal, reported=ok)
    if not ok:
        with _lock:   # 실패했으면 다음 거부 때 바로 다시 알리도록
            _reported_at.pop((event["identity"], event["reason"]), None)
    return ok


def handle_line(line, now=None):
    event = parse_line(line)
    if not event:
        return
    should, count = record(event, now)
    if event["reason"] == "owner_mismatch":
        zt_risk.log_event("authz_denied", service="gate", identity=event["identity"], reason=event["reason"],
                          host=event["host"], path=event["path"], count=count)
    if should:
        report(event, count)


def _run():
    for line in zt_waf._follow(AUTHZ_LOG):
        try:
            handle_line(line)
        except Exception as e:
            print(f"[AUTHZ_HANDLE_ERROR] {type(e).__name__}: {e}", flush=True)


_started = False


def start():
    """auth_gate.py가 시작할 때 한 번 부른다(백그라운드 스레드)."""
    global _started
    with _lock:
        if _started:
            return
        _started = True
    threading.Thread(target=_run, name="zt-authz-reporter", daemon=True).start()
    print(f"[AUTHZ_REPORTER_STARTED] log={AUTHZ_LOG} threshold={THRESHOLD}/{WINDOW_SECONDS}s", flush=True)
