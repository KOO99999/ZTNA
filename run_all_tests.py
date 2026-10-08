"""
세 테스트(test_risk_score.py, test_portal_b.py, test_auth_gate.py)를 한 번에 돌리고, 긴 출력 대신
PASS/FAIL 개수만 표로 보여주는 요약 스크립트. 화면 한 장으로 캡처할 수 있게 만든 것.

사용법 (프로젝트 폴더에서): python run_all_tests.py
FAIL이 하나라도 있으면 그 항목 이름을 아래에 따로 보여주고, 종료 코드 1로 끝난다.
"""
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
TESTS = [
    ("엔진 (risk_score_engine.py)", "test_risk_score.py"),
    ("B 계층 (portal_app.py)", "test_portal_b.py"),
    ("판단 서비스 (auth_gate.py)", "test_auth_gate.py"),
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
