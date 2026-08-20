/**
 * Cloudflare Access External Evaluation Worker
 *
 * Access가 로그인한 사용자 정보를 이 워커의 evaluate URL(POST /)로 보내면,
 * 이 워커는 우리 Trust Score Engine(Lambda)을 호출해서 판단 결과를 받아온 뒤,
 * {success: true/false} 형태로 서명해서 Access에 돌려준다.
 *
 * GET /keys 는 Access가 이 워커의 서명을 검증할 때 쓰는 공개키(JWKS)를 제공한다.
 */
import { SignJWT, importPKCS8 } from 'jose';
import publicJwks from '../public-jwks.json';

const LAMBDA_EVALUATE_URL = 'https://1q0d4vsqe0.execute-api.ap-northeast-2.amazonaws.com/evaluate';

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
      // 데모/8주 과제 범위에서는 Access가 보낸 JWT의 서명 검증은 생략하고 payload만 파싱한다.
      // (정식 프로덕션이라면 Access의 팀도메인 JWKS로 이 JWT도 검증해야 함 - 아래 TODO 참고)
      const payloadPart = incomingJwt.split('.')[1];
      accessPayload = JSON.parse(atob(payloadPart));
    } catch (e) {
      accessPayload = {};
    }

    const identity = accessPayload.email || accessPayload.identity || 'unknown';

    // 1) 우리 Trust Score Engine(Lambda) 호출
    let trustResult;
    try {
      const lambdaResp = await fetch(LAMBDA_EVALUATE_URL, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          identity: identity,
          session_id: accessPayload.session_id || crypto.randomUUID(),
          // TODO: 실제로는 클라이언트 IP/시간대 등 위협 신호를 여기서 함께 실어 보내야 함
        }),
      });
      trustResult = await lambdaResp.json();
    } catch (e) {
      // Lambda 호출 자체가 실패하면 Fail-Closed (5조 피드백 반영 - admin 등급 기준)
      trustResult = { allow: false, action: 'lambda_call_failed' };
    }

    // 2) 응답을 JWT로 서명해서 Access에 돌려줌
    const privateKey = await importPKCS8(env.PRIVATE_KEY_PEM, 'RS256');
    const responseJwt = await new SignJWT({
      success: trustResult.allow === true,
      score: trustResult.score,
      action: trustResult.action,
    })
      .setProtectedHeader({ alg: 'RS256', kid: publicJwks.keys[0].kid })
      .setIssuedAt()
      .setExpirationTime('60s')
      .sign(privateKey);

    return new Response(responseJwt, {
      headers: { 'Content-Type': 'application/jwt' },
    });
  },
};
