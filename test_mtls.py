"""Web -> WAS mTLS 검증: 실제 TLS 핸드셰이크로 확인한다(인증서는 테스트 안에서 만든 임시 CA로 발급).
- 앱 서버(portal_app.py), 인증 서버(auth_app.py)를 mTLS 설정으로 띄우고 여러 클라이언트로 접속해 본다.
- 배포 설정(nginx, cloudflared, Terraform)에 mTLS가 들어 있는지도 확인한다.
필요 패키지: flask, flask-sqlalchemy, pymysql, pyotp, pyjwt, cryptography, requests"""
import datetime, os, socket, ssl, sys, tempfile, threading, warnings
from unittest.mock import MagicMock

HERE = os.path.dirname(os.path.abspath(__file__))
fails = 0
try:
    from importlib.metadata import version as _ver
    print(f"[INFO] Python {sys.version.split()[0]} / {ssl.OPENSSL_VERSION} / werkzeug {_ver('werkzeug')} / {sys.platform}")
except Exception:
    pass
def ok(name, cond, detail=""):
    global fails
    fails += (not cond)
    print(("[PASS] " if cond else "[FAIL] ") + name + ("" if cond else f"\n    -> {detail}"))

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

TMP = tempfile.mkdtemp()
now = datetime.datetime.now(datetime.timezone.utc)

def write(name, data):
    p = os.path.join(TMP, name)
    open(p, "wb").write(data)
    return p

def make_ca(cn):
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(minutes=1))
            .not_valid_after(now + datetime.timedelta(days=1))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key()), critical=False)
            .add_extension(x509.KeyUsage(digital_signature=True, key_cert_sign=True, crl_sign=True, content_commitment=False,
                                         key_encipherment=False, data_encipherment=False, key_agreement=False,
                                         encipher_only=False, decipher_only=False), critical=True)
            .sign(key, hashes.SHA256()))
    return key, cert

def issue(ca_key, ca_cert, cn, eku, tag):
    key = ec.generate_private_key(ec.SECP256R1())
    cert = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)]))
            .issuer_name(ca_cert.subject).public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(minutes=1)).not_valid_after(now + datetime.timedelta(days=1))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(cn)]), critical=False)
            .add_extension(x509.ExtendedKeyUsage([eku]), critical=False)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
            .sign(ca_key, hashes.SHA256()))
    c = write(f"{tag}.crt", cert.public_bytes(serialization.Encoding.PEM))
    k = write(f"{tag}.key", key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    return c, k

ca_key, ca_cert = make_ca("ZT Internal CA")
CA = write("ca.crt", ca_cert.public_bytes(serialization.Encoding.PEM))
APP_CRT, APP_KEY = issue(ca_key, ca_cert, "app.zt.internal", ExtendedKeyUsageOID.SERVER_AUTH, "app")
AUTH_CRT, AUTH_KEY = issue(ca_key, ca_cert, "auth.zt.internal", ExtendedKeyUsageOID.SERVER_AUTH, "auth")
WEB_CRT, WEB_KEY = issue(ca_key, ca_cert, "web.zt.internal", ExtendedKeyUsageOID.CLIENT_AUTH, "web")
OTHER_CRT, OTHER_KEY = issue(ca_key, ca_cert, "other.zt.internal", ExtendedKeyUsageOID.CLIENT_AUTH, "other")
evil_key, evil_cert = make_ca("Evil CA")
EVIL_CRT, EVIL_KEY = issue(evil_key, evil_cert, "web.zt.internal", ExtendedKeyUsageOID.CLIENT_AUTH, "evil")

# ---------- 앱 서버/인증 서버를 mTLS로 띄우기 ----------
os.environ.update(AUTH_DOMAIN="auth.xmcda.store", CF_TEAM_DOMAIN="t.cloudflareaccess.com", CF_ACCESS_AUDS="a",
                  MTLS_CLIENT_CA=CA, MTLS_ALLOWED_CLIENT="web.zt.internal")
sys.modules.setdefault("boto3", MagicMock())
sys.path.insert(0, HERE)
from werkzeug.serving import make_server
import zt_mtls

def start(module_name, crt, key, extra_env):
    os.environ.update(MTLS_CERT=crt, MTLS_KEY=key, **extra_env)
    mod = __import__(module_name)
    ok(f"{module_name}: MTLS 환경변수가 있으면 mTLS 켜짐", mod.MTLS is not None and mod.MTLS[3] == "web.zt.internal", mod.MTLS)
    srv = make_server("127.0.0.1", 0, mod.app, threaded=True, ssl_context=zt_mtls.build_server_context(*mod.MTLS[:3]))
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv

def call(port, server_name, cert=None, key=None, ca=CA, path="/no-such-page"):
    """(상태코드, 본문) 또는 ('TLS_ERROR', 사유). nginx처럼 서버 인증서를 내부 CA + 이름으로 검증한다."""
    ctx = ssl.create_default_context(cafile=ca)
    if cert:
        ctx.load_cert_chain(cert, key)
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=5) as raw:
            with ctx.wrap_socket(raw, server_hostname=server_name) as s:
                s.sendall(f"GET {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n".encode())
                data = b""
                while True:
                    chunk = s.recv(4096)
                    if not chunk:
                        break
                    data += chunk
        head, _, body = data.partition(b"\r\n\r\n")
        parts = head.split()
        if len(parts) < 2 or not parts[1].isdigit():
            # 연결은 됐지만 응답 없이 끊김(운영체제에 따라 TLS 1.3에서 클라이언트 인증서 거부가 이렇게 보이기도 함)
            return "NO_RESPONSE", repr(data[:80])
        return int(parts[1]), body.decode(errors="replace")
    except (ssl.SSLError, ConnectionResetError, BrokenPipeError, OSError) as e:
        return "TLS_ERROR", type(e).__name__

warnings.filterwarnings("ignore")
app_srv = start("portal_app", APP_CRT, APP_KEY, {})
import flask_sqlalchemy
flask_sqlalchemy.SQLAlchemy.create_all = lambda self, *a, **k: None
auth_srv = start("auth_app", AUTH_CRT, AUTH_KEY, dict(DB_HOST="h", DB_NAME="n", DB_USER="u", DB_PASSWORD="p",
                                                     OIDC_CLIENT_ID="c", OIDC_CLIENT_SECRET="s", AUTO_MIGRATE_SCHEMA="0"))

for label, srv, name in (("앱 서버", app_srv, "app.zt.internal"), ("인증 서버", auth_srv, "auth.zt.internal")):
    port = srv.server_port
    r = call(port, name, WEB_CRT, WEB_KEY)
    ok(f"{label}: 웹 서버 인증서(web.zt.internal)로 접속 -> 통과(앱까지 도달, 없는 페이지라 404)", r[0] == 404, r)
    r = call(port, name)
    ok(f"{label}: 클라이언트 인증서 없이 접속 -> TLS 단계에서 거부", r[0] in ("TLS_ERROR", "NO_RESPONSE"), r)
    r = call(port, name, EVIL_CRT, EVIL_KEY)
    ok(f"{label}: 다른 CA가 발급한 인증서(이름은 web으로 위조) -> TLS 단계에서 거부", r[0] in ("TLS_ERROR", "NO_RESPONSE"), r)
    r = call(port, name, OTHER_CRT, OTHER_KEY)
    ok(f"{label}: 같은 CA지만 다른 이름(other.zt.internal) -> 403", r[0] == 403 and "forbidden" in r[1], r)
    r = call(port, name, APP_CRT, APP_KEY)
    ok(f"{label}: 서버용 인증서(app)를 클라이언트로 재사용 -> 거부(TLS 또는 403)", r[0] in ("TLS_ERROR", "NO_RESPONSE", 403), r)
    r = call(port, "wrong.zt.internal", WEB_CRT, WEB_KEY)
    ok(f"{label}: 웹 서버가 기대한 서버 이름과 다르면 웹 서버 쪽에서 연결 거부(가짜 서버 차단)", r[0] == "TLS_ERROR", r)
    r = call(port, name, WEB_CRT, WEB_KEY, ca=EVIL_CRT)
    ok(f"{label}: 웹 서버가 내부 CA로 검증 못 하는 서버면 연결 거부", r[0] == "TLS_ERROR", r)

# TLS 1.1 이하 거부
ctx = zt_mtls.build_server_context(APP_CRT, APP_KEY, CA)
ok("서버 TLS 최소 버전 1.2, 클라이언트 인증서 필수", ctx.minimum_version == ssl.TLSVersion.TLSv1_2 and ctx.verify_mode == ssl.CERT_REQUIRED)
for k in ("MTLS_CERT", "MTLS_KEY"):
    saved = os.environ.pop(k)
ok("MTLS 설정이 없으면 끔(로컬 실행/테스트용)", zt_mtls.mtls_settings() is None)
ok("인증서가 없는 요청 환경에서는 CN 없음 -> 허용 안 함", zt_mtls.client_allowed({}, "web.zt.internal") is False)
app_srv.shutdown(); auth_srv.shutdown()

# ---------- 배포 설정 ----------
def read(path):
    return open(os.path.join(HERE, path), encoding="utf-8").read().replace("\r\n", "\n")
web = read("templates/user_data_web.sh.tpl")
ok("nginx: 앱 서버로 https + 서버 이름 app.zt.internal 검증", "proxy_pass https://${app_private_ip}:8080;" in web and "proxy_ssl_name app.zt.internal;" in web)
ok("nginx: 인증 서버 전용 server 블록, https + auth.zt.internal 검증",
   "server_name ${auth_domain};" in web and "proxy_pass https://${auth_private_ip}:8080;" in web and "proxy_ssl_name auth.zt.internal;" in web)
ok("nginx: 클라이언트 인증서 제시 + 서버 인증서 검증 켬(두 블록 모두)",
   web.count("proxy_ssl_verify              on;") == 2 and web.count("proxy_ssl_certificate         /etc/zt-mtls/me.crt;") == 2)
ok("nginx: 평문 http로 앱/인증 서버에 가는 설정 없음", "http://${app_private_ip}" not in web and "http://${auth_private_ip}" not in web)
ok("cloudflared: 인증 서버도 nginx(localhost:80)를 거침", "  - hostname: ${auth_domain}\n    service: http://localhost:80" in web)
ok("웹 서버 개인키는 root만 읽기", "chmod 600 /etc/zt-mtls/me.key" in web)
for tpl, group in (("templates/user_data_app.sh.tpl", "ztapp"), ("templates/user_data_auth.sh.tpl", "ztauth")):
    t = read(tpl)
    ok(f"{tpl}: MTLS 환경변수(인증서/키/CA/허용 클라이언트)", all(f"{v}=" in t for v in ("MTLS_CERT", "MTLS_KEY", "MTLS_CLIENT_CA", "MTLS_ALLOWED_CLIENT")))
    ok(f"{tpl}: 개인키는 root와 서비스 계정({group})만 읽기", f"chown root:{group} /etc/zt-mtls/me.key && chmod 640 /etc/zt-mtls/me.key" in t)
    ok(f"{tpl}: zt_mtls.py 배포", "${zt_mtls_code}" in t if group == "ztapp"
       else "for name in ('auth_app.py', 'zt_mtls.py'):" in t)   # 인증 서버는 S3에서 받음(code_bucket.tf)
mt = read("mtls.tf")
ok("Terraform: 웹 인증서는 client_auth, 앱/인증 서버 인증서는 server_auth 용도만",
   'each.key == "web" ? ["digital_signature", "client_auth"] : ["digital_signature", "server_auth"]' in mt)
ok("Terraform: 개인키는 SecureString", 'type     = "SecureString"' in mt)
ok("Terraform: 각 서버 역할은 자기 인증서/키 + CA만 읽기", "aws_ssm_parameter.mtls_key[each.key].arn" in mt and "aws_ssm_parameter.mtls_cert[each.key].arn" in mt)
main = read("main.tf")
ok("Terraform: 원격 터널 설정에서도 인증 서버는 localhost:80(nginx)로", 'service  = "http://${aws_instance.auth_server.private_ip}:8080"' not in main)

print(f"\n실패 {fails}건"); sys.exit(1 if fails else 0)
