name = "ztna-access-evaluator"
main = "src/index.js"
compatibility_date = "2024-09-01"

# PRIVATE_KEY_PEM은 여기 적지 않고 `wrangler secret put`으로 등록한다 (아래 사용법 참고)

# 이 파일은 Terraform이 자동으로 생성합니다 (worker_automation.tf 참고).
# 직접 수정해도 다음 terraform apply 때 덮어써지니, 값을 바꾸려면
# main.tf/worker_automation.tf 쪽을 수정하세요.
[vars]
LAMBDA_EVALUATE_URL = "${lambda_evaluate_url}"
