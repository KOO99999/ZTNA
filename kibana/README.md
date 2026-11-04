# Kibana 저장 객체 (관제 콘솔)

관제 서버(elk.tf)가 켜질 때 이 폴더의 `*.ndjson` 파일을 Kibana 저장 객체 가져오기(Saved Objects import)로 전부 불러온다.
매일 destroy해도 표와 대시보드가 다시 생기게 하려는 것(실무의 "대시보드를 코드로 관리" 방식).

- `zt_saved_searches.ndjson`: 데이터 보기 `ZT 로그`(zt-logs-*) + 저장된 검색(표) 9개
  ① 판정 기록 ② 로그인 활동 ③ 추가 인증·차단 화면 ④ WAF 공격 차단 ⑤ 기기 세션 강제 종료 ⑥ 관리자·내부 보안·장애 모드 기록
  ⑦ 남의 자료 요청(IDOR) ⑧ 실측 결과(관찰 모드 would_action, 엔진 처리 시간) ⑨ 엔진 응답 시간(웹 서버→엔진 왕복 ms)
- 실측 결과 내보내기: Discover에서 ⑧/⑨를 열고 기간을 실측 시간으로 맞춘 뒤 Share → CSV 내보내기(Generate CSV)
- 대시보드 추가 방법: Kibana에서 대시보드를 만든 뒤
  Stack Management → Saved Objects → 대시보드 선택 → Export(관련 객체 포함) → 받은 파일을 이 폴더에 `zt_dashboard.ndjson`으로 저장
  → 다음 apply부터 자동으로 불러온다.
