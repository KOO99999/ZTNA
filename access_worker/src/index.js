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
import { SignJWT, importPKCS8 } from 'jose';
import publicJwks from '../public-jwks.json';

// LAMBDA_EVALUATE_URL은 wrangler.toml의 [vars]에서 관리 (destroy/apply로 API Gateway URL이
// 바뀌어도 이 파일은 안 건드리고 wrangler.toml 값만 고치면 되도록 분리)

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

    // Access가 보내는 요청은 서명된 JWT (identity 정보 포함)
    let accessPayload = {};
    try {
      const incomingJwt = await request.text();
      console.log('[DEBUG] incoming JWT (raw):', incomingJwt);
      // 데모/8주 과제 범위에서는 Access가 보낸 JWT의 서명 검증은 생략하고 payload만 파싱한다.
      // (정식 프로덕션이라면 Access의 팀도메인 JWKS로 이 JWT도 검증해야 함 - 아래 TODO 참고)
      const payloadPart = incomingJwt.split('.')[1];
      accessPayload = JSON.parse(atob(payloadPart));
    } catch (e) {
      accessPayload = {};
    }

    const identity = accessPayload.email || accessPayload.identity?.email || accessPayload.identity || 'unknown';
    // Access는 응답 JWT에 요청 때 보낸 nonce를 그대로 담아 돌려줘야 검증을 통과시킴
    // (success:true만으로는 부족함 - Cloudflare External Evaluation 스펙)
    const nonce = accessPayload.nonce;

    // 판단 없이 원본 값만 추출 (야간 여부/위치 이상 여부 판정은 Lambda가 담당)
    const requestTimestamp = new Date().toISOString();
    const geoCountry = accessPayload.identity?.geo?.country || null;

    // 1) 우리 Trust Score Engine(Lambda) 호출
    let trustResult;
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
          // TODO: 실제로는 클라이언트 IP 등 추가 위협 신호도 여기서 함께 실어 보내야 함
        }),
      });
      trustResult = await lambdaResp.json();
      // 로그 확인 편의용 KST 표시 (Lambda로 보내는 실제 값은 위에서 UTC로 유지됨)
      const kstDisplay = new Date(Date.now() + 9 * 60 * 60 * 1000).toISOString().replace('Z', '+09:00');
      console.log('[DEBUG] identity:', identity, 'nonce:', nonce, 'request_timestamp(UTC):', requestTimestamp, 'request_timestamp(KST):', kstDisplay, 'geo_country:', geoCountry, 'trustResult:', JSON.stringify(trustResult));
    } catch (e) {
      // Lambda 호출 자체가 실패하면 Fail-Closed (5조 피드백 반영 - admin 등급 기준)
      console.log('[DEBUG] lambda call failed:', e.message);
      trustResult = { allow: false, action: 'lambda_call_failed' };
    }

    // 2) 응답을 JWT로 서명해서 Access에 돌려줌
    // [v8, Block 정책 전환] 이 워커는 이제 admin_risk_block(decision="block")의 Include에서
    // 쓰인다. Block 정책은 "매치되면(success:true) 차단"이므로, 기존과 반대로
    // "위험(allow===false)할 때 success:true"가 되어야 함 — 안전하면 매치 안 시켜서 통과시킴.
    const privateKey = await importPKCS8(env.PRIVATE_KEY_PEM, 'RS256');
    const responseJwt = await new SignJWT({
      success: trustResult.allow === false,
      nonce: nonce,
    })
      .setProtectedHeader({ alg: 'RS256', kid: publicJwks.keys[0].kid })
      .setIssuedAt()
      .setExpirationTime('60s')
      .sign(privateKey);

    console.log('[DEBUG] outgoing JWT (raw):', responseJwt);

    return new Response(responseJwt, {
      headers: { 'Content-Type': 'application/jwt' },
    });
  },
};
