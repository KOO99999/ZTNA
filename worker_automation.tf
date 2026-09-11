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
  # LAMBDA_EVALUATE_URL 값이 바뀔 때만(=API Gateway가 재생성됐을 때만) 재배포 트리거
  triggers = {
    wrangler_toml_content = local_file.worker_wrangler_toml.content
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
