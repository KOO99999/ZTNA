// Worker(index.js)의 Access 요청 서명 검증과 fail-closed 동작을 실제 네트워크 없이 검증한다.
// 사용: 프로젝트 폴더에서  node tests_js/test_worker.mjs [access_worker 폴더 경로]
//   (access_worker 폴더에 npm으로 설치된 jose가 있어야 한다. 기본 경로: ./access_worker)
import fs from 'node:fs';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

const workerDir = path.resolve(process.argv[2] || 'access_worker');
const srcPath = path.join(workerDir, 'src', 'index.js');
const jose = await import(pathToFileURL(path.join(workerDir, 'node_modules', 'jose', 'dist', 'webapi', 'index.js')).href)
  .catch(() => import(pathToFileURL(path.join(workerDir, 'node_modules', 'jose', 'dist', 'node', 'esm', 'index.js')).href));
const { SignJWT, generateKeyPair, exportPKCS8, exportJWK, importPKCS8 } = jose;

// 테스트용 키: Access(요청 서명), 위조자, 우리 Worker(응답 서명)
const access = await generateKeyPair('RS256', { extractable: true });
const evil = await generateKeyPair('RS256', { extractable: true });
const mine = await generateKeyPair('RS256', { extractable: true });
const accessJwk = { ...(await exportJWK(access.publicKey)), kid: 'access-kid', alg: 'RS256', use: 'sig' };
const mineJwk = { ...(await exportJWK(mine.publicKey)), kid: 'worker-kid', alg: 'RS256', use: 'sig' };
const publicJwks = { keys: [mineJwk] };

// index.js를 JSON import 대신 값을 직접 넣은 임시 파일로 바꿔 불러온다(node가 확장자 없는 JSON import를 못 함)
let code = fs.readFileSync(srcPath, 'utf8');
code = code.replace(/import publicJwks from ['"]\.\.\/public-jwks\.json['"];?/, `const publicJwks = ${JSON.stringify(publicJwks)};`);
const tmpFile = path.join(workerDir, 'src', '.index_under_test.mjs');
fs.writeFileSync(tmpFile, code);
const worker = (await import(pathToFileURL(tmpFile).href)).default;
fs.unlinkSync(tmpFile);

const ENV = {
  CF_TEAM_DOMAIN: 'team-test.cloudflareaccess.com',
  LAMBDA_EVALUATE_URL: 'https://lambda.test/evaluate',
  EVALUATE_SHARED_SECRET: 'secret-for-test',
  PRIVATE_KEY_PEM: await exportPKCS8(mine.privateKey),
};

// ---- 가짜 네트워크: Access 공개키 목록, Lambda ----
let lambdaCalls = [];
let lambdaMode = { kind: 'json', status: 200, body: { allow: true, action: 'allow' } };
let certsFetches = 0;
globalThis.fetch = async (url, init) => {
  const u = String(url);
  if (u === 'https://team-test.cloudflareaccess.com/cdn-cgi/access/certs') {
    certsFetches++;
    return new Response(JSON.stringify({ keys: [accessJwk] }), { headers: { 'content-type': 'application/json' } });
  }
  if (u === ENV.LAMBDA_EVALUATE_URL) {
    lambdaCalls.push({ headers: init.headers, body: JSON.parse(init.body) });
    if (lambdaMode.kind === 'throw') throw new Error('network down');
    return new Response(JSON.stringify(lambdaMode.body), { status: lambdaMode.status, headers: { 'content-type': 'application/json' } });
  }
  throw new Error('예상 밖의 fetch: ' + u);
};

let logs = [];
const origLog = console.log;
console.log = (...a) => { logs.push(a.map(String).join(' ')); };

let fails = 0, passes = 0;
function check(name, cond, detail = '') {
  if (cond) passes++; else fails++;
  origLog(`[${cond ? 'PASS' : 'FAIL'}] ${name}` + (!cond && detail ? `\n    -> ${detail}` : ''));
}

async function accessToken({ key = access.privateKey, kid = 'access-kid', alg = 'RS256', nonce = 'nonce-123', exp = '5m', claims = {} } = {}) {
  let jwt = new SignJWT({ nonce, email: 'hana@test.com', request_url: 'dev.xmcda.store/',
    identity: { email: 'hana@test.com', geo: { country: 'KR' } }, ...claims });
  if (nonce === null) jwt = new SignJWT({ email: 'hana@test.com' });
  return await jwt.setProtectedHeader({ alg, kid }).setIssuedAt().setExpirationTime(exp).sign(key);
}

async function call(body, { env = ENV, method = 'POST', url = 'https://worker.test/' } = {}) {
  lambdaCalls = []; logs = [];
  const res = await worker.fetch(new Request(url, { method, body: method === 'POST' ? body : undefined }), env);
  let reply = null;
  try { reply = await res.clone().json(); } catch { /* JSON이 아닌 응답 */ }
  let signed = null;
  if (reply && reply.token) {
    const { payload } = await jose.jwtVerify(reply.token, mine.publicKey, { algorithms: ['RS256'] });
    signed = payload;
  }
  return { res, reply, signed };
}
const wrap = (t) => JSON.stringify({ token: t });

// ---------- 정상 요청 ----------
{
  const t = await accessToken();
  const { res, signed } = await call(wrap(t));
  check('정상 서명 + Lambda 허용 -> success:false(차단 규칙에 해당 안 함), nonce 그대로', res.status === 200 && signed.success === false && signed.nonce === 'nonce-123', JSON.stringify(signed));
  check('Lambda에 검증된 토큰의 identity/국가/경로가 전달됨',
    lambdaCalls.length === 1 && lambdaCalls[0].body.identity === 'hana@test.com' && lambdaCalls[0].body.geo_country === 'KR' && lambdaCalls[0].body.resource_path === 'dev.xmcda.store/', JSON.stringify(lambdaCalls[0]?.body));
  check('Lambda 호출에 공유비밀키 헤더', lambdaCalls[0].headers['X-Evaluate-Secret'] === 'secret-for-test');
}
{
  lambdaMode = { kind: 'json', status: 200, body: { allow: false, action: 'block' } };
  const { signed } = await call(wrap(await accessToken()));
  check('Lambda 차단 -> success:true(차단 규칙에 해당)', signed.success === true && signed.nonce === 'nonce-123');
  lambdaMode = { kind: 'json', status: 200, body: { allow: true, action: 'allow' } };
}
{
  const { signed } = await call(await accessToken({ nonce: 'old-format' }));
  check('옛 방식(본문이 JWT 문자열 그대로)도 서명 검증 후 처리', signed && signed.nonce === 'old-format' && signed.success === false);
}
{
  const { signed } = await call(wrap(await accessToken({ claims: { request_url: 'admin.xmcda.store/' } })));
  check('admin 서브도메인 요청 -> resource_path=admin.xmcda.store/ (호스트+경로)', lambdaCalls[0].body.resource_path === 'admin.xmcda.store/', lambdaCalls[0]?.body.resource_path);
}

// ---------- 서명 검증 실패 = 차단 응답 + Lambda 호출 없음 ----------
async function expectBlocked(name, body, env = ENV, expectReason) {
  const { res, signed } = await call(body, { env });
  const okShape = res.status === 200 && signed && signed.success === true;
  check(`${name} -> 차단(success:true)으로 응답, Lambda 호출 없음`, okShape && lambdaCalls.length === 0, `status=${res.status} signed=${JSON.stringify(signed)} lambda=${lambdaCalls.length}`);
  if (expectReason) check(`${name} -> 실패 기록(${expectReason})`, logs.some(l => l.includes('[ACCESS_JWT_VERIFY_FAILED]') && l.includes(expectReason)), logs.join(' | '));
  return signed;
}
{
  const s = await expectBlocked('위조 서명(다른 개인키)', wrap(await accessToken({ key: evil.privateKey })));
  check('위조 요청에도 nonce는 그대로 돌려줌(응답은 차단뿐)', s.nonce === 'nonce-123');
}
await expectBlocked('모르는 kid', wrap(await accessToken({ kid: 'unknown-kid' })));
await expectBlocked('만료된 토큰', wrap(await accessToken({ exp: Math.floor(Date.now() / 1000) - 600 })));
{
  const t = await accessToken();
  const [h, p, s] = t.split('.');
  const forged = JSON.parse(Buffer.from(p, 'base64url').toString());
  forged.email = 'admin@test.com'; forged.identity = { email: 'admin@test.com', geo: { country: 'KR' } };
  const tampered = [h, Buffer.from(JSON.stringify(forged)).toString('base64url'), s].join('.');
  await expectBlocked('payload만 바꾼 토큰(서명 불일치)', wrap(tampered));
  check('바꾼 payload의 identity(admin)는 어디에도 전달되지 않음', lambdaCalls.length === 0);
}
{
  const none = ['eyJhbGciOiJub25lIiwia2lkIjoiYWNjZXNzLWtpZCJ9', Buffer.from(JSON.stringify({ nonce: 'n1', email: 'x@y.z', exp: 9999999999 })).toString('base64url'), ''].join('.');
  await expectBlocked('alg=none 토큰', wrap(none));
}
{
  const { res } = await call(wrap(await accessToken({ nonce: null })));
  check('nonce 없는 토큰(평가 요청이 아닌 일반 Access 토큰)은 서명이 맞아도 처리하지 않음 -> 400, Lambda 호출 없음', res.status === 400 && lambdaCalls.length === 0, res.status);
}
{
  const { res } = await call('이건 토큰이 아님');
  check('토큰이 아닌 본문 -> 400, Lambda 호출 없음', res.status === 400 && lambdaCalls.length === 0, res.status);
  const r2 = await call('');
  check('빈 본문 -> 400', r2.res.status === 400 && lambdaCalls.length === 0);
}
await expectBlocked('팀 도메인 설정 없음(config_missing)', wrap(await accessToken()), { ...ENV, CF_TEAM_DOMAIN: undefined }, 'config_missing');
await expectBlocked('팀 도메인 형식이 이상함(다른 사이트의 키로 검증하는 사고 방지)', wrap(await accessToken()), { ...ENV, CF_TEAM_DOMAIN: 'evil.example.com' }, 'config_missing');

// ---------- Lambda 쪽 실패 = 차단 (fail-closed) ----------
for (const [name, mode] of [
  ['Lambda 401 {"error":"unauthorized"} (공유비밀키 불일치)', { kind: 'json', status: 401, body: { error: 'unauthorized' } }],
  ['Lambda 500 오류 응답', { kind: 'json', status: 500, body: { message: 'Internal Server Error' } }],
  ['Lambda 응답에 allow 필드 없음', { kind: 'json', status: 200, body: { score: 0 } }],
  ['Lambda allow가 문자열 "true"', { kind: 'json', status: 200, body: { allow: 'true' } }],
  ['Lambda 네트워크 오류', { kind: 'throw' }],
]) {
  lambdaMode = mode;
  const { signed } = await call(wrap(await accessToken()));
  check(`${name} -> 차단(success:true)`, signed && signed.success === true, JSON.stringify(signed));
}
lambdaMode = { kind: 'json', status: 200, body: { allow: true, action: 'allow' } };

// ---------- 로그에 토큰 원문이 남지 않음 ----------
{
  await call(wrap(await accessToken()));
  const okLogs = logs.join('\n');
  check('정상 요청 로그에 JWT 원문(eyJ...)이 없음', !/eyJ[A-Za-z0-9_-]{10,}/.test(okLogs), okLogs.slice(0, 200));
  await call(wrap(await accessToken({ key: evil.privateKey })));
  const badLogs = logs.join('\n');
  check('검증 실패 로그에도 JWT 원문이 없음', !/eyJ[A-Za-z0-9_-]{10,}/.test(badLogs) && badLogs.includes('ACCESS_JWT_VERIFY_FAILED'), badLogs.slice(0, 200));
  check('로그에 nonce 값이 남지 않음', !okLogs.includes('nonce-123') && !badLogs.includes('nonce-123'));
}

// ---------- 공개키 캐시 / 기타 경로 ----------
{
  certsFetches = 0;
  for (let i = 0; i < 5; i++) await call(wrap(await accessToken()));
  check('Access 공개키 목록은 매 요청 받지 않고 캐시됨(5요청에 1회 이하)', certsFetches <= 1, `fetches=${certsFetches}`);
}
{
  const { res, reply } = await call(null, { method: 'GET', url: 'https://worker.test/keys' });
  check('GET /keys는 그대로 공개키 목록 제공(서명 검증 대상 아님)', res.status === 200 && reply.keys[0].kid === 'worker-kid');
  const g = await call(null, { method: 'GET', url: 'https://worker.test/' });
  check('POST 외 요청(/)은 405', g.res.status === 405);
}
{
  const res = await worker.fetch(new Request('https://worker.test/', { method: 'POST', body: wrap(await accessToken()) }), ENV);
  const reply = await res.json();
  const header = JSON.parse(Buffer.from(reply.token.split('.')[0], 'base64url').toString());
  check('응답 JWT: RS256 + 우리 Worker kid, {"token": ...} 형태 유지', header.alg === 'RS256' && header.kid === 'worker-kid' && res.headers.get('content-type').includes('application/json'));
}

console.log = origLog;
console.log(`\n실패 수: ${fails}  (PASS ${passes})`);
process.exit(fails ? 1 : 0);
