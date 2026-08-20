// 사용자 컴퓨터에서 딱 한 번 실행하는 스크립트.
// 워커가 응답을 서명할 때 쓸 개인키/공개키 쌍을 만들어 keys.json에 저장합니다.
// (Cloudflare 계정키와는 무관한, 우리 워커 전용 키입니다)
//
// 실행: node generate-keys.js

import { generateKeyPair, exportJWK, exportPKCS8 } from 'jose';
import { writeFileSync } from 'fs';
import { randomUUID } from 'crypto';

const { publicKey, privateKey } = await generateKeyPair('RS256', { extractable: true });

const kid = randomUUID();

const publicJwk = await exportJWK(publicKey);
publicJwk.kid = kid;
publicJwk.alg = 'RS256';
publicJwk.use = 'sig';

const privatePem = await exportPKCS8(privateKey);

writeFileSync('public-jwks.json', JSON.stringify({ keys: [publicJwk] }, null, 2));
writeFileSync('private-key.pem', privatePem);

console.log('생성 완료:');
console.log('  public-jwks.json  -> 워커 코드 안에 그대로 포함 (공개해도 안전)');
console.log('  private-key.pem   -> wrangler secret으로 등록할 값 (절대 커밋/공유 금지)');
console.log('  kid:', kid);
