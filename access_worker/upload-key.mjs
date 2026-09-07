import { execSync } from 'child_process';
import { readFileSync } from 'fs';

const key = readFileSync('./private-key.pem'); // 텍스트로 변환 안 함 — 바이트 그대로
execSync('npx wrangler secret put PRIVATE_KEY_PEM', {
  input: key,
  stdio: ['pipe', 'inherit', 'inherit'],
});