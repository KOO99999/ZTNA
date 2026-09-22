# ==========================================
# Worker(access_worker) 자동 연동
#   AWS API Gateway 주소는 destroy/apply 때마다 새로 생성되는데(AWS 특성상 피할 수 없음),
#   지금까지는 이 값을 사람이 직접 wrangler.toml에 복사해넣고 wrangler deploy를 실행해야 했음.
#   이 파일은 그 두 단계(값 갱신 + 재배포)를 terraform apply 한 번으로 자동 처리한다.
#   전제조건: 이 컴퓨터에 node/npx가 설치되어 있어야 함.
#   CLOUDFLARE_API_TOKEN은 위 environment 블록을 통해 var.cloudflare_workers_api_token
#   (terraform.tfvars, Workers Scripts Edit 권한만 가진 최소권한 전용 토큰)에서 자동으로
#   전달되므로, wrangler login이나 로그인 캐시에 더 이상 의존하지 않음
#   (PC를 바꾸거나 CI 환경에서 실행해도 동일하게 동작함).
# ==========================================

resource "local_file" "worker_wrangler_toml" {
  filename = "${path.module}/access_worker/wrangler.toml"
  content = templatefile("${path.module}/templates/wrangler.toml.tpl", {
    lambda_evaluate_url = "${aws_apigatewayv2_api.pdp_api.api_endpoint}/evaluate"
  })
}

resource "null_resource" "deploy_worker" {
  # LAMBDA_EVALUATE_URL 값이 바뀌거나(=API Gateway 재생성) index.js 내용 자체가 바뀔 때 재배포 트리거.
  # [수정] 기존엔 wrangler_toml_content만 트리거라, index.js를 고쳐도 wrangler.toml이 안 바뀌면
  # terraform apply를 돌려도 재배포가 스킵되는 문제가 있었음(RESOURCE_THRESHOLDS 실접속 검증 중 발견 -
  # /admin 접속에도 resource_path가 계속 null로 찍혀 구버전 index.js가 그대로 떠있던 게 원인).
  triggers = {
    wrangler_toml_content = local_file.worker_wrangler_toml.content
    index_js_hash         = filemd5("${path.module}/access_worker/src/index.js")
  }

  provisioner "local-exec" {
    command     = "npx wrangler deploy"
    working_dir = "${path.module}/access_worker"
    environment = {
      CLOUDFLARE_API_TOKEN = var.cloudflare_workers_api_token
    }
  }

  depends_on = [local_file.worker_wrangler_toml]
}
