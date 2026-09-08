# ==========================================
# Worker(access_worker) 자동 연동
#   AWS API Gateway 주소는 destroy/apply 때마다 새로 생성되는데(AWS 특성상 피할 수 없음),
#   지금까지는 이 값을 사람이 직접 wrangler.toml에 복사해넣고 wrangler deploy를 실행해야 했음.
#   이 파일은 그 두 단계(값 갱신 + 재배포)를 terraform apply 한 번으로 자동 처리한다.
#   전제조건: 이 컴퓨터에 node/npx가 설치되어 있고, wrangler가 이미 로그인된 상태여야 함
#   (지금까지 wrangler deploy를 수동으로 계속 써왔으니 이미 충족된 상태).
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
  }

  depends_on = [local_file.worker_wrangler_toml]
}
