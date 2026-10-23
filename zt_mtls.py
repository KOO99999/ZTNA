"""Web -> WAS 구간 mTLS(상호 TLS) 공통 코드. portal_app.py(앱 서버)와 auth_app.py(인증 서버)가 같이 쓴다.

왜: 예전엔 웹 서버(nginx)가 앱 서버로 평문 HTTP를 보냈고, 앱 서버는 "보낸 쪽 IP가 웹 서버 보안그룹인가"(SG)로만
    상대를 믿었다. 이제 둘 다 인증서로 신분을 증명한다.
    - 앱 서버: 자기 인증서를 보여주고(웹 서버가 진짜 앱 서버인지 확인), 웹 서버의 클라이언트 인증서를 요구한다.
    - 인증서는 이 프로젝트 전용 내부 CA(Terraform tls provider, mtls.tf)가 발급한다.
무엇을 확인하나:
    1) TLS 연결 단계: 클라이언트 인증서가 없거나 내부 CA가 서명하지 않았으면 연결 자체가 안 된다(CERT_REQUIRED).
    2) 요청 단계: 같은 CA가 발급한 다른 인증서(예: 앱/인증 서버의 서버 인증서)로 붙는 것까지 막기 위해,
       클라이언트 인증서의 이름(CN)이 허용된 이름(웹 서버, MTLS_ALLOWED_CLIENT)인지 한 번 더 본다.
켜는 법: 환경변수 MTLS_CERT, MTLS_KEY, MTLS_CLIENT_CA가 모두 있으면 켜진다(없으면 기존처럼 평문 - 로컬 테스트용).
"""
import os
import ssl


def mtls_settings():
    """(cert, key, client_ca, allowed_client_cn) 또는 None(설정이 하나라도 없으면 mTLS 끔)."""
    cert, key, ca = os.environ.get('MTLS_CERT'), os.environ.get('MTLS_KEY'), os.environ.get('MTLS_CLIENT_CA')
    if not (cert and key and ca):
        return None
    return cert, key, ca, os.environ.get('MTLS_ALLOWED_CLIENT', '')


def build_server_context(cert, key, client_ca):
    """서버용 TLS 설정: TLS 1.2 이상, 내 인증서 제시, 클라이언트 인증서 필수 + 내부 CA로 검증."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(cert, key)
    ctx.load_verify_locations(cafile=client_ca)
    ctx.verify_mode = ssl.CERT_REQUIRED
    return ctx


def client_cert_cn(environ):
    """Werkzeug가 environ['SSL_CLIENT_CERT']에 넣어 준 클라이언트 인증서(PEM)의 CN. 없거나 읽을 수 없으면 None."""
    pem = environ.get('SSL_CLIENT_CERT')
    if not pem:
        return None
    try:
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        cert = x509.load_pem_x509_certificate(pem.encode() if isinstance(pem, str) else pem)
        names = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        return names[0].value if names else None
    except Exception:
        return None


def client_allowed(environ, allowed_cn):
    """mTLS가 켜진 상태에서 이 요청을 보낸 쪽이 허용된 클라이언트(웹 서버)인가."""
    return bool(allowed_cn) and client_cert_cn(environ) == allowed_cn
