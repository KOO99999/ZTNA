"""
다섯 테스트(test_risk_score.py, test_zt_risk.py, test_portal_b.py, test_auth_gate.py, test_auth_return_url.py)를 한 번에 돌리고, 긴 출력 대신
PASS/FAIL 개수만 표로 보여주는 요약 스크립트. 화면 한 장으로 캡처할 수 있게 만든 것.

사용법 (프로젝트 폴더에서): python run_all_tests.py
  로그인 서버 테스트의 2부(/stepup, /token 흐름)는 pip install flask-sqlalchemy pymysql pyotp 가 있어야 실행됨
  (없으면 1부만 실행하고 건너뛴 것으로 표시). Worker(index.js) 테스트는 node가 필요해 별도: node tests_js/test_worker.mjs
FAIL이 하나라도 있으면 그 항목 이름을 아래에 따로 보여주고, 종료 코드 1로 끝난다.
"""
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
TESTS = [
    ("엔진 (risk_score_engine.py)", "test_risk_score.py"),
    ("위험도 확인 (zt_risk.py)", "test_zt_risk.py"),
    ("앱 신원확인 (portal_app.py)", "test_portal_b.py"),
    ("판단 서비스 (auth_gate.py)", "test_auth_gate.py"),
    ("로그인 서버 (auth_app.py)", "test_auth_return_url.py"),
    ("User Risk 관리 (risk_admin.py)", "test_risk_admin.py"),
    ("계정 자동 시딩 (auth_app.py)", "test_seed_accounts.py"),
    ("유출 비밀번호 검사 (auth_app.py)", "test_pwned_password.py"),
]

env = dict(os.environ, PYTHONIOENCODING="utf-8", PYTHONUTF8="1")
total_fail = 0
rows = []
failed_names = []

for label, script in TESTS:
    path = os.path.join(HERE, script)
    if not os.path.exists(path):
        rows.append((label, script, "-", "-", "파일 없음"))
        total_fail += 1
        continue
    proc = subprocess.run(
        [sys.executable, path], cwd=HERE, env=env,
        capture_output=True, text=True, encoding="utf-8", errors="replace",
    )
    lines = (proc.stdout or "").splitlines()
    passed = sum(1 for l in lines if l.startswith("[PASS]"))
    failed = [l for l in lines if l.startswith("[FAIL]")]
    crashed = proc.returncode != 0 and not failed
    status = "OK" if (not failed and not crashed and passed > 0) else "FAIL"
    if status == "FAIL":
        total_fail += 1
    rows.append((label, script, passed, len(failed), status))
    failed_names += [f"{script}: {l}" for l in failed]
    if crashed:
        tail = (proc.stderr or "").strip().splitlines()[-3:]
        failed_names += [f"{script}: 실행 중 오류 -> {t}" for t in tail]

print()
print("=" * 62)
print(f"{'테스트':<28}{'PASS':>6}{'FAIL':>6}   결과")
print("-" * 62)
for label, script, p, f, st in rows:
    print(f"{label:<28}{str(p):>6}{str(f):>6}   {st}")
print("-" * 62)
print("전체 결과:", "모두 통과" if total_fail == 0 else "실패 있음 (아래 확인)")
print("=" * 62)
for n in failed_names:
    print("  !!", n)
sys.exit(1 if total_fail else 0)
