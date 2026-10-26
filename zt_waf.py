"""WAF(ModSecurity + OWASP CRS) 탐지를 신원과 연결해 위험도 엔진에 알리는 모듈. auth_gate.py 프로세스 안에서 돈다.

왜: WAF는 공격 요청 하나를 403으로 막을 뿐, "누가" 공격했는지는 모른다. 로그인한 사람이 앱 안에서 공격하면
    그 요청만 막히고 같은 사람의 다른 요청과 다른 앱 접근은 그대로 열려 있다. 그래서 WAF가 막은 요청을
    서명 검증된 신원(Access JWT)과 연결해 엔진에 알리고, 엔진이 이 사람에게 해제 불가 위험(user_risk)을 걸어
    모든 앱 접근을 막는다(관리자가 risk_admin으로 해제할 때까지).

구조(nginx 두 단계, user_data_web.sh.tpl):
    1) 앞단(80): 판단 서비스(auth_gate /auth)가 JWT를 검증하고 통과 시 X-ZT-Identity(검증된 email)를 돌려준다.
       nginx는 이 값으로 X-ZT-Identity 헤더를 "덮어써서" 내부 단계로 보낸다(클라이언트가 보낸 같은 이름의 헤더는 버려짐).
    2) 내부 단계(127.0.0.1:8081, 앱): ModSecurity가 검사한다. 차단 규칙(CRS 949110)의 기록 내용(logdata)에
       "zt_identity=<email> zt_host=<host> sqli=<점수> xss=<점수> ..."를 넣어 두었고(user_data_web.sh.tpl),
       이 줄은 앱 단계 전용 로그(/var/log/modsec/zt_waf_app.log)에 남는다.
       로그인 서버용 내부 단계(8082)는 신원이 없으므로 다른 로그 파일을 쓰고, 여기서 읽지 않는다.
    JSON 감사 로그(SecAuditLog)를 쓰지 않는 이유: 차단 화면(error_page)을 쓰면 감사 로그에 탐지 내용이 비어서 남았다(실측).
    nginx 오류 로그의 차단 줄은 error_page와 상관없이 남는다.
    ModSecurity는 nginx의 인증(auth_request) 단계보다 먼저 돌기 때문에, 같은 단계 안에서는 인증 결과를 볼 수 없다.
    그래서 인증 -> 검사 순서가 되도록 단계를 둘로 나눴다.

이 모듈: 앱 단계 WAF 로그를 따라 읽다가(tail)
    - "Access denied"(실제 차단) + 규칙 949110 줄만 본다(DetectionOnly 모드의 탐지는 "Access denied"가 아니라 알리지 않음).
    - CRS가 공격 종류별로 매긴 점수로 신호를 정한다: SQL 삽입 점수 > 0 -> waf_sqli,
      XSS/RCE/LFI/RFI/PHP 삽입/세션 고정 점수 > 0 -> waf_attack (프로토콜 규칙만으로 막힌 건 신호로 쓰지 않음)
    - 같은 사람/같은 종류는 60초에 한 번만 알린다(공격 도구가 수백 건을 보내도 엔진 호출이 폭주하지 않게).
    - 엔진에 persist_risk=True로 알리고, 이 사람의 위험도 캐시를 지워 다음 요청부터 바로 다시 판단하게 한다.
환경변수: ZT_WAF_LOG(기본 /var/log/modsec/zt_waf_app.log), PDP_EVALUATE_URL, EVALUATE_SHARED_SECRET(zt_risk와 같음)
"""
import os
import re
import threading
import time
import uuid
from datetime import datetime, timezone
from urllib.parse import urlsplit, unquote

import requests

import zt_risk

WAF_LOG = os.environ.get("ZT_WAF_LOG", "/var/log/modsec/zt_waf_app.log")
BLOCKING_RULE_ID = "949110"          # CRS: 요청 위험 점수(anomaly score)가 기준을 넘어 차단함
REPORT_INTERVAL_SECONDS = 60
_EMAIL_RE = re.compile(r"^[^@\s\"]{1,64}@[A-Za-z0-9.-]{1,190}$")
_HOST_RE = re.compile(r"^[A-Za-z0-9.-]{1,253}(:\d{1,5})?$")
_FIELD_RE = re.compile(r'\[(id|data|uri) "((?:[^"\\]|\\.)*)"\]')

# CRS 3.3이 공격 종류별로 매기는 점수 -> 엔진 신호
SCORE_SIGNAL = {
    "sqli": "waf_sqli",        # SQL 삽입
    "xss": "waf_attack",       # XSS
    "rce": "waf_attack",       # 원격 명령 실행
    "lfi": "waf_attack",       # 로컬 파일 포함
    "rfi": "waf_attack",       # 원격 파일 포함
    "php": "waf_attack",       # PHP 삽입
    "fixation": "waf_attack",  # 세션 고정
}

_last_reported = {}
_lock = threading.Lock()


def parse_line(line):
    """앱 단계 WAF 로그 한 줄 -> 알릴 사건 dict 또는 None(알릴 대상 아님)."""
    if "ModSecurity: Access denied" not in line:
        return None                                  # 실제 차단만(DetectionOnly 경고는 무시)
    fields = {}
    for name, value in _FIELD_RE.findall(line):
        fields.setdefault(name, value)
    if fields.get("id") != BLOCKING_RULE_ID:
        return None
    data = dict(part.split("=", 1) for part in fields.get("data", "").split() if "=" in part)
    identity = data.get("zt_identity", "").strip().lower()
    host = data.get("zt_host", "").strip().lower()
    if not _EMAIL_RE.match(identity) or not _HOST_RE.match(host):
        return None                                  # 신원이 없거나 이상하면 알리지 않음(WAF는 이미 막았음)
    scores = {}
    for key in SCORE_SIGNAL:
        try:
            scores[key] = int(data.get(key, "0") or 0)
        except ValueError:
            scores[key] = 0
    signals = sorted({SCORE_SIGNAL[k] for k, v in scores.items() if v > 0})
    if not signals:
        return None
    path = unquote(urlsplit(fields.get("uri") or "/").path) or "/"
    return {"identity": identity, "host": host.split(":")[0], "path": path, "signals": signals,
            "scores": {k: v for k, v in scores.items() if v > 0}}


def should_report(event, now=None):
    """같은 사람/같은 신호 묶음은 REPORT_INTERVAL_SECONDS에 한 번만."""
    now = now or time.time()
    key = (event["identity"], tuple(event["signals"]))
    with _lock:
        if now - _last_reported.get(key, 0) < REPORT_INTERVAL_SECONDS:
            return False
        _last_reported[key] = now
        if len(_last_reported) > 1000:
            for k in [k for k, v in _last_reported.items() if now - v >= REPORT_INTERVAL_SECONDS]:
                del _last_reported[k]
    return True


def report(event):
    """엔진에 알린다(사람에게 해제 불가 위험을 거는 판단은 엔진이 한다). 성공하면 True."""
    body = {"identity": event["identity"], "session_id": str(uuid.uuid4()), "source": "waf",
            "persist_risk": True, "request_timestamp": datetime.now(timezone.utc).isoformat(),
            "resource_path": zt_risk.resource_path_for(event["host"], event["path"])}
    for signal in event["signals"]:
        body[signal] = True
    try:
        resp = requests.post(zt_risk.PDP_EVALUATE_URL, timeout=3, json=body,
                             headers={"Content-Type": "application/json", "X-Evaluate-Secret": zt_risk.EVALUATE_SHARED_SECRET})
        ok = resp.status_code == 200
    except Exception as e:
        print(f"[WAF_REPORT_FAILED] identity={event['identity']} error={type(e).__name__}", flush=True)
        ok = False
    # 엔진 응답과 상관없이 이 사람의 '통과' 캐시는 지운다(다음 요청은 반드시 엔진에 다시 묻게)
    zt_risk.invalidate_identity(event["identity"])
    scores = ",".join(f"{k}={v}" for k, v in sorted(event["scores"].items()))
    print(f"[WAF_REPORTED] identity={event['identity']} signals={','.join(event['signals'])} "
          f"scores={scores} host={event['host']} path={event['path']} ok={ok}", flush=True)
    if not ok:
        with _lock:   # 실패했으면 다음 공격 때 바로 다시 알리도록 기록을 지운다
            _last_reported.pop((event["identity"], tuple(event["signals"])), None)
    return ok


def handle_line(line):
    event = parse_line(line)
    if event and should_report(event):
        report(event)


def _follow(path, sleep=time.sleep, stop=lambda: False):
    """tail -F처럼 파일 끝부터 새 줄을 읽는다(바이트로 읽고 줄 단위로 끊음, 덜 써진 줄은 다음에 이어 붙임).
    로그 교체(rotate: inode 변경)나 잘림(truncate: 크기 감소)이면 새 파일을 처음부터 다시 연다."""
    f, inode, buf, first = None, None, b"", True
    while not stop():
        try:
            if f is None:
                f = open(path, "rb")
                inode = os.fstat(f.fileno()).st_ino
                if first:                    # 서비스 시작 시점 이전 기록은 다시 처리하지 않는다
                    f.seek(0, os.SEEK_END)
                first, buf = False, b""
            chunk = f.read(65536)
            if chunk:
                buf += chunk
                *lines, buf = buf.split(b"\n")
                for raw in lines:
                    raw = raw.rstrip(b"\r")      # CRLF 줄 끝(Windows에서 쓴 파일 등)도 같은 줄로 본다
                    if raw.strip():
                        yield raw.decode("utf-8", errors="replace")
                continue
            st = os.stat(path)
            if st.st_ino != inode or st.st_size < f.tell():
                f.close()
                f = None
                continue
            sleep(0.5)
        except FileNotFoundError:
            if f:
                f.close()
            f, first = None, False
            sleep(2)
        except Exception as e:
            print(f"[WAF_TAIL_ERROR] {type(e).__name__}: {e}", flush=True)
            sleep(2)


def _run():
    for line in _follow(WAF_LOG):
        try:
            handle_line(line)
        except Exception as e:
            print(f"[WAF_HANDLE_ERROR] {type(e).__name__}: {e}", flush=True)


_started = False


def start():
    """auth_gate.py가 시작할 때 한 번 부른다(백그라운드 스레드)."""
    global _started
    with _lock:
        if _started:
            return
        _started = True
    threading.Thread(target=_run, name="zt-waf-reporter", daemon=True).start()
    print(f"[WAF_REPORTER_STARTED] log={WAF_LOG}", flush=True)
