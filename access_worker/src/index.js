/**
 * Cloudflare Access External Evaluation Worker
 *
 * Access가 로그인한 사용자 정보를 이 워커의 evaluate URL(POST /)로 보내면,
 * 이 워커는 우리 Trust Score Engine(Lambda)을 호출해서 판단 결과를 받아온 뒤,
 * {success: true/false} 형태로 서명해서 Access에 돌려준다.
 *
 * GET /keys 는 Access가 이 워커의 서명을 검증할 때 쓰는 공개키(JWKS)를 제공한다.
 *
 * [설계 원칙] 이 워커는 판단(PDP) 로직을 갖지 않는다. Access가 준 원본 데이터
 * (요청 시각, geo 국가코드 등)를 그대로 Lambda에 전달만 하고, "야간 접속인지",
 * "위치가 이상한지" 같은 실제 판정은 전부 risk_score_engine.py(Lambda)가 담당한다.
 * 이렇게 판정 로직을 한 곳(Lambda)에 모아두면, 판정 기준이 바뀔 때 이 워커를
 * 재배포할 필요 없이 Lambda 코드만 수정하면 된다.
 */
import { SignJWT, importPKCS8, jwtVerify, createRemoteJWKSet } from 'jose';
import publicJwks from '../public-jwks.json';

// LAMBDA_EVALUATE_URL은 wrangler.toml의 [vars]에서 관리 (destroy/apply로 API Gateway URL이
// 바뀌어도 이 파일은 안 건드리고 wrangler.toml 값만 고치면 되도록 분리)

// [RESOURCE_THRESHOLDS] Access JWT의 request_url("도메인/경로" 형태, 예: "xmcda.store/admin")에서
// 경로 부분만 뽑아낸다. 판단(이 경로가 얼마나 민감한지)은 하지 않고 원본 경로만 그대로
// 전달한다 — night_access/unknown_location과 동일하게, 실제 판정은 Lambda(PDP)가 전담.
function extractResourcePath(requestUrl) {
  if (!requestUrl) return null;
  try {
    const parsed = new URL('https://' + requestUrl);
    // [버그수정] admin_console/admin_api를 admin.xmcda.store 서브도메인으로 옮기면서,
    // 이 함수가 도메인은 버리고 경로만 봐서 "admin.xmcda.store/"가 포털의 "/"(임계값 60)와
    // 똑같이 취급되던 문제가 있었음 - resource_threshold가 20이 아니라 60으로 잘못 찍힘.
    // admin 서브도메인으로 온 요청은 RESOURCE_THRESHOLDS의 기존 /admin, /api/db-data
    // 키와 매칭되도록 호스트 정보를 경로에 반영한다.
    if (parsed.hostname.startsWith('admin.')) {
      return parsed.pathname === '/api/db-data' ? '/api/db-data' : '/admin';
    }
    return parsed.pathname || '/';
  } catch (e) {
    return null;
  }
}

// ==========================================================================
// Access가 보낸 요청의 서명 검증
//   External Evaluation 요청은 Access가 계정 키로 서명한 JWT이며 본문은 {"token": "<JWT>"} 형태다
//   (Cloudflare 공식 예제 workers-access-external-auth-example 기준). 서명 검증 없이 본문 값을 믿으면
//   누구나 이 Worker 주소로 임의의 identity/nonce를 담은 요청을 보내 평가를 일으킬 수 있으므로, 팀 도메인의
//   공개키(https://<팀도메인>/cdn-cgi/access/certs)로 서명을 확인하고 통과한 요청만 처리한다.
//   공식 예제도 서명(RS256)과 exp만 확인하며 iss/aud는 문서에 정의가 없어 확인하지 않는다. 대신 평가 요청에만
//   들어 있는 nonce가 없는 토큰(예: 일반 Access 앱 토큰)은 거부한다.
// ==========================================================================
let accessJwks = null;   // isolate 안에서 재사용 (jose가 공개키 캐시/kid 선택/재조회 간격을 처리)

function getAccessJwks(env) {
  const domain = env.CF_TEAM_DOMAIN;
  if (!domain || !/^[a-z0-9-]+\.cloudflareaccess\.com$/.test(domain)) return null;
  if (!accessJwks) {
    accessJwks = createRemoteJWKSet(new URL('https://' + domain + '/cdn-cgi/access/certs'));
  }
  return accessJwks;
}

// 본문에서 토큰 문자열 꺼내기: {"token": "..."} 또는 (옛 방식) JWT 문자열 그대로
function extractToken(bodyText) {
  const text = (bodyText || '').trim();
  try {
    const parsed = JSON.parse(text);
    if (parsed && typeof parsed.token === 'string') return parsed.token;
  } catch (e) { /* JSON이 아니면 아래에서 원문을 그대로 사용 */ }
  return text;
}

// 서명 검증 없이 payload만 읽기 - 검증 실패 때 응답용 nonce를 얻는 데만 쓰고, 판단에는 절대 쓰지 않는다.
function peekPayload(token) {
  try {
    const part = token.split('.')[1].replace(/-/g, '+').replace(/_/g, '/');
    return JSON.parse(atob(part + '='.repeat((4 - (part.length % 4)) % 4)));
  } catch (e) {
    return null;
  }
}

// 반환: {ok: true, payload} 또는 {ok: false, reason}. 토큰 원문은 로그에 남기지 않는다.
async function verifyAccessRequest(token, env) {
  const jwks = getAccessJwks(env);
  if (!jwks) return { ok: false, reason: 'config_missing' };
  if (!token) return { ok: false, reason: 'token_missing' };
  try {
    const { payload } = await jwtVerify(token, jwks, { algorithms: ['RS256'] });
    if (typeof payload.nonce !== 'string' || !payload.nonce) return { ok: false, reason: 'no_nonce' };
    return { ok: true, payload };
  } catch (e) {
    return { ok: false, reason: e && e.code ? String(e.code) : 'verify_failed' };
  }
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    // Access가 우리 서명을 검증할 때 조회하는 공개키 목록
    if (request.method === 'GET' && url.pathname === '/keys') {
      return new Response(JSON.stringify(publicJwks), {
        headers: { 'Content-Type': 'application/json' },
      });
    }

    if (request.method !== 'POST') {
      return new Response('Method Not Allowed', { status: 405 });
    }

    // Access가 보내는 요청은 서명된 JWT (identity 정보 포함). 서명을 먼저 검증한다.
    const token = extractToken(await request.text());
    const verified = await verifyAccessRequest(token, env);
    let accessPayload = {};
    let verifyFailed = false;
    if (verified.ok) {
      accessPayload = verified.payload;
    } else {
      // 검증 실패 = 판단(Lambda 호출)을 하지 않고 "차단"으로 응답한다(fail-closed). 이 Worker가 Block
      // 정책에서 success:true는 "차단 규칙에 해당"이므로 여기서 허용 쪽으로 답하는 경로는 없다.
      verifyFailed = true;
      console.log('[ACCESS_JWT_VERIFY_FAILED] reason=' + verified.reason);
      const peek = peekPayload(token);
      accessPayload = { nonce: peek && typeof peek.nonce === 'string' ? peek.nonce : undefined };
      if (!accessPayload.nonce) {
        // nonce조차 없으면 Access가 보낸 평가 요청이 아니다. 서명 응답을 만들 이유가 없음.
        return new Response(JSON.stringify({ error: 'invalid request' }), {
          status: 400,
          headers: { 'Content-Type': 'application/json' },
        });
      }
    }

    const identity = accessPayload.email || accessPayload.identity?.email || accessPayload.identity || 'unknown';
    // Access는 응답 JWT에 요청 때 보낸 nonce를 그대로 담아 돌려줘야 검증을 통과시킴
    // (success:true만으로는 부족함 - Cloudflare External Evaluation 스펙)
    const nonce = accessPayload.nonce;

    // 판단 없이 원본 값만 추출 (야간 여부/위치 이상 여부 판정은 Lambda가 담당)
    const requestTimestamp = new Date().toISOString();
    const geoCountry = accessPayload.identity?.geo?.country || null;
    const resourcePath = extractResourcePath(accessPayload.request_url);

    // 1) 우리 Trust Score Engine(Lambda) 호출
    let trustResult;
    if (verifyFailed) {
      trustResult = { allow: false, action: 'access_jwt_invalid' };
    } else {
      try {
        const lambdaResp = await fetch(env.LAMBDA_EVALUATE_URL, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            // Lambda가 이 값을 대조해 인증 없는 호출을 차단함 (env.EVALUATE_SHARED_SECRET는
            // `wrangler secret put EVALUATE_SHARED_SECRET`로 미리 등록해둬야 함)
            'X-Evaluate-Secret': env.EVALUATE_SHARED_SECRET,
          },
          body: JSON.stringify({
            identity: identity,
            session_id: accessPayload.session_id || crypto.randomUUID(),
            request_timestamp: requestTimestamp,
            geo_country: geoCountry,
            resource_path: resourcePath,
            // TODO: 실제로는 클라이언트 IP 등 추가 위협 신호도 여기서 함께 실어 보내야 함
          }),
        });
        trustResult = await lambdaResp.json();
        // 로그 확인 편의용 KST 표시 (Lambda로 보내는 실제 값은 위에서 UTC로 유지됨)
        const kstDisplay = new Date(Date.now() + 9 * 60 * 60 * 1000).toISOString().replace('Z', '+09:00');
        console.log('[DEBUG] identity:', identity, 'request_timestamp(UTC):', requestTimestamp, 'request_timestamp(KST):', kstDisplay, 'geo_country:', geoCountry, 'resource_path:', resourcePath, 'trustResult:', JSON.stringify(trustResult));
      } catch (e) {
        // Lambda 호출 자체가 실패하면 Fail-Closed (5조 피드백 반영 - admin 등급 기준)
        console.log('[DEBUG] lambda call failed:', e.message);
        trustResult = { allow: false, action: 'lambda_call_failed' };
      }
    }

    // 2) 응답을 JWT로 서명해서 Access에 돌려줌
    // [v8, Block 정책 전환] 이 워커는 이제 admin_risk_block(decision="block")의 Include에서
    // 쓰인다. Block 정책은 "매치되면(success:true) 차단"이므로, 기존과 반대로
    // "위험(allow===false)할 때 success:true"가 되어야 함 — 안전하면 매치 안 시켜서 통과시킴.
    const privateKey = await importPKCS8(env.PRIVATE_KEY_PEM, 'RS256');
    // [fail-closed] "허용(allow === true)"이 확인된 경우에만 success:false(차단 규칙에 해당 안 함)로 답한다.
    // 예전에는 allow === false일 때만 차단해서, Lambda가 {"error": "unauthorized"}(공유비밀키 불일치) 같은
    // allow 필드 없는 응답을 주면 차단이 아니라 통과로 처리되는 빈틈이 있었다.
    const responseJwt = await new SignJWT({
      success: trustResult.allow !== true,
      nonce: nonce,
    })
      .setProtectedHeader({ alg: 'RS256', kid: publicJwks.keys[0].kid })
      .setIssuedAt()
      .setExpirationTime('60s')
      .sign(privateKey);

    // [버그수정, 진짜 원인] Access는 응답을 JSON으로 감싸서 {"token": "<jwt>"} 형태로
    // 받길 기대하는데(공식 예제 코드로 확인됨), 여태까지 JWT 문자열을 그냥 날것으로
    // 보내고 있었음. Access가 이걸 파싱 못 해서 매번 조용히 "매치 안 됨"으로
    // 처리되고, Deny 정책이 사실상 한 번도 제대로 적용된 적이 없었던 것으로 보임.
    return new Response(JSON.stringify({ token: responseJwt }), {
      headers: { 'Content-Type': 'application/json' },
    });
  },
};
