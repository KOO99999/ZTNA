output "pdp_evaluate_url" {
  value       = "${aws_apigatewayv2_stage.pdp_stage.invoke_url}evaluate"
  description = "Cloudflare Access External Evaluation Rule에 입력할 Evaluate URL"
}

output "dynamodb_table_name" {
  value = aws_dynamodb_table.trust_score_log.name
}

output "web_ec2_instance_id" {
  value = aws_instance.web_app.id
}

output "tunnel_id" {
  value       = cloudflare_zero_trust_tunnel_cloudflared.web_tunnel.id
  description = "Cloudflare Tunnel ID"
}

output "site_url" {
  value       = "https://${var.domain_name}"
  description = "터널 연결 후 접속할 주소"
}
