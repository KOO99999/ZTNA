"""공통 화면 디자인(로그인 서버, 포털/업무 앱, 웹 서버 안내 화면이 같이 쓴다).

왜 한 파일인가: 세 서버가 각자 HTML/CSS를 들고 있으면 화면마다 모양이 달라지고(실습용처럼 보이는 원인),
고칠 때도 세 곳을 따로 고쳐야 한다. 실무의 "디자인 시스템"처럼 색/글꼴/버튼/알림 상자를 한 곳에 정의하고,
각 서버는 S3에서 이 파일을 같이 받아 쓴다(code_bucket.tf).

원칙
  - 외부 글꼴/스크립트/이미지를 불러오지 않는다(로그인 화면이 외부 서버에 의존하지 않게, 주소창 밖으로 정보가 새지 않게).
    글꼴은 운영체제 기본 한글 글꼴(맑은 고딕, Apple SD 산돌고딕 Neo)을 쓰고, 아이콘은 SVG를 코드에 넣었다.
  - 화면에 넣는 값은 전부 esc()를 거친다(호출하는 쪽에서 이미 만든 HTML 조각만 그대로 넣는다).
  - 내부 구현 이름(판단 코드, 점수 계산 근거, 인프라 이름)은 사용자 화면에 쓰지 않는다.
"""
import html as _html

BRAND = "XMCDA"


def esc(value):
    return _html.escape("" if value is None else str(value), quote=True)


# ---------------------------------------------------------------------------
# 아이콘(24x24 선 아이콘, currentColor). 외부 아이콘 글꼴 대신 코드에 넣는다.
# ---------------------------------------------------------------------------
_ICONS = {
    "shield": '<path d="M12 3l7 3v5c0 4.6-3 8.6-7 10-4-1.4-7-5.4-7-10V6l7-3z"/>',
    "shield-check": '<path d="M12 3l7 3v5c0 4.6-3 8.6-7 10-4-1.4-7-5.4-7-10V6l7-3z"/><path d="M9 12l2 2 4-4"/>',
    "lock": '<rect x="5" y="11" width="14" height="10" rx="2"/><path d="M8 11V8a4 4 0 018 0v3"/>',
    "key": '<circle cx="8" cy="15" r="4"/><path d="M11 12l8-8M16 7l2 2M14 9l2 2"/>',
    "alert": '<path d="M12 4l9 16H3L12 4z"/><path d="M12 10v4M12 17h.01"/>',
    "block": '<circle cx="12" cy="12" r="9"/><path d="M5.6 5.6l12.8 12.8"/>',
    "check": '<circle cx="12" cy="12" r="9"/><path d="M8 12l3 3 5-6"/>',
    "info": '<circle cx="12" cy="12" r="9"/><path d="M12 11v5M12 8h.01"/>',
    "device": '<rect x="3" y="4" width="18" height="12" rx="2"/><path d="M8 20h8M12 16v4"/>',
    "globe": '<circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3c2.5 2.6 3.8 5.6 3.8 9s-1.3 6.4-3.8 9c-2.5-2.6-3.8-5.6-3.8-9S9.5 5.6 12 3z"/>',
    "logout": '<path d="M15 4h3a2 2 0 012 2v12a2 2 0 01-2 2h-3"/><path d="M10 16l-4-4 4-4M6 12h10"/>',
    "user": '<circle cx="12" cy="8" r="4"/><path d="M4 21c1.5-4 4.5-6 8-6s6.5 2 8 6"/>',
    "users": '<circle cx="9" cy="8" r="3.5"/><path d="M2.5 20c1.2-3.4 3.6-5 6.5-5s5.3 1.6 6.5 5"/><path d="M16 4.5a3.5 3.5 0 010 7M18 15c1.6.7 2.8 2.3 3.5 5"/>',
    "code": '<path d="M8 8l-4 4 4 4M16 8l4 4-4 4M14 5l-4 14"/>',
    "megaphone": '<path d="M4 10v4h3l7 4V6L7 10H4z"/><path d="M18 9a4 4 0 010 6"/>',
    "folder": '<path d="M3 7a2 2 0 012-2h4l2 2h8a2 2 0 012 2v8a2 2 0 01-2 2H5a2 2 0 01-2-2V7z"/>',
    "settings": '<circle cx="12" cy="12" r="3"/><path d="M12 2v3M12 19v3M2 12h3M19 12h3M4.9 4.9l2.1 2.1M17 17l2.1 2.1M4.9 19.1L7 17M17 7l2.1-2.1"/>',
    "clock": '<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/>',
    "arrow-right": '<path d="M5 12h14M13 6l6 6-6 6"/>',
    "list": '<path d="M9 6h11M9 12h11M9 18h11M4 6h.01M4 12h.01M4 18h.01"/>',
    "home": '<path d="M3 11l9-7 9 7v9a1 1 0 01-1 1h-5v-6H9v6H4a1 1 0 01-1-1v-9z"/>',
}


def icon(name, size=20, cls="ic"):
    path = _ICONS.get(name, _ICONS["info"])
    return (f'<svg class="{cls}" width="{size}" height="{size}" viewBox="0 0 24 24" fill="none" stroke="currentColor" '
            f'stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">{path}</svg>')


def logo(size=28):
    """회사 로고(방패 모양 + 글자). 이미지 파일 없이 SVG로 그린다."""
    return (f'<span class="logo"><svg width="{size}" height="{size}" viewBox="0 0 32 32" aria-hidden="true">'
            '<rect width="32" height="32" rx="8" fill="var(--brand)"/>'
            '<path d="M16 6.5l7.5 3v5.6c0 4.9-3.2 9.1-7.5 10.4-4.3-1.3-7.5-5.5-7.5-10.4V9.5l7.5-3z" fill="#fff" opacity=".95"/>'
            '<path d="M12.6 16.2l2.4 2.4 4.6-5" fill="none" stroke="var(--brand)" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"/>'
            f'</svg><span class="logo-text">{BRAND}</span></span>')


FAVICON = ("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'%3E%3Crect width='32' height='32' "
           "rx='8' fill='%231d4ed8'/%3E%3Cpath d='M16 6.5l7.5 3v5.6c0 4.9-3.2 9.1-7.5 10.4-4.3-1.3-7.5-5.5-7.5-10.4V9.5z' "
           "fill='white'/%3E%3C/svg%3E")

# ---------------------------------------------------------------------------
# 스타일(디자인 토큰 -> 구성 요소). 밝은 업무용 화면 기준, 좁은 화면(휴대폰)에서도 깨지지 않게.
# ---------------------------------------------------------------------------
CSS = """
:root{
  --brand:#1d4ed8;--brand-hover:#1e40af;--brand-soft:#eff4ff;--brand-line:#c7d7fe;
  --ink:#0f172a;--ink-2:#334155;--muted:#64748b;--faint:#94a3b8;
  --line:#e2e8f0;--line-2:#eef2f7;--bg:#f4f6fa;--surface:#ffffff;
  --danger:#b42318;--danger-bg:#fef3f2;--danger-line:#fecdca;
  --warn:#b54708;--warn-bg:#fffaeb;--warn-line:#fedf89;
  --ok:#067647;--ok-bg:#ecfdf3;--ok-line:#abefc6;
  --info:#175cd3;--info-bg:#eff8ff;--info-line:#b2ddff;
  --radius:12px;--radius-sm:8px;
  --shadow:0 1px 2px rgba(16,24,40,.06),0 8px 24px -6px rgba(16,24,40,.10);
  --font:"Pretendard Variable",Pretendard,-apple-system,BlinkMacSystemFont,"Apple SD Gothic Neo","Malgun Gothic","맑은 고딕","Segoe UI",Roboto,sans-serif;
  --mono:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;
}
*{box-sizing:border-box}
html,body{margin:0;padding:0}
body{font-family:var(--font);color:var(--ink);background:var(--bg);font-size:15px;line-height:1.6;
  -webkit-font-smoothing:antialiased;word-break:keep-all;overflow-wrap:anywhere}
a{color:var(--brand);text-decoration:none}
a:hover{text-decoration:underline}
h1,h2,h3{margin:0;color:var(--ink);letter-spacing:-.01em}
p{margin:0}
.ic{flex:none;vertical-align:middle}
.sr-only{position:absolute;width:1px;height:1px;overflow:hidden;clip:rect(0 0 0 0)}

/* 로고 */
.logo{display:inline-flex;align-items:center;gap:10px;color:var(--ink)}
.logo-text{font-weight:800;font-size:17px;letter-spacing:.04em}
.logo-sub{font-weight:600;color:var(--muted);font-size:14px;padding-left:10px;margin-left:2px;border-left:1px solid var(--line)}

/* 버튼 */
.btn{display:inline-flex;align-items:center;justify-content:center;gap:8px;height:44px;padding:0 18px;border-radius:var(--radius-sm);
  border:1px solid transparent;font:600 15px/1 var(--font);cursor:pointer;text-decoration:none!important;white-space:nowrap;
  transition:background .15s,border-color .15s,box-shadow .15s,color .15s}
.btn:focus-visible{outline:none;box-shadow:0 0 0 4px rgba(29,78,216,.22)}
.btn-primary{background:var(--brand);color:#fff}
.btn-primary:hover{background:var(--brand-hover)}
.btn-secondary{background:var(--surface);color:var(--ink-2);border-color:var(--line)}
.btn-secondary:hover{background:#f8fafc;border-color:#cbd5e1}
.btn-danger{background:var(--surface);color:var(--danger);border-color:var(--danger-line)}
.btn-danger:hover{background:var(--danger-bg)}
.btn-ghost{background:transparent;color:var(--ink-2)}
.btn-ghost:hover{background:var(--line-2)}
.btn-block{width:100%}
.btn-sm{height:34px;padding:0 12px;font-size:13.5px}
.btn[disabled],.btn.is-busy{opacity:.55;cursor:not-allowed}
.btn-row{display:flex;flex-wrap:wrap;gap:8px}

/* 입력 */
.field{display:block;margin-bottom:16px}
.field-label{display:block;font-size:13.5px;font-weight:600;color:var(--ink-2);margin-bottom:6px}
.input{display:block;width:100%;height:46px;padding:0 14px;border:1px solid #cfd8e3;border-radius:var(--radius-sm);
  background:#fff;color:var(--ink);font:400 15.5px var(--font);transition:border-color .15s,box-shadow .15s}
.input::placeholder{color:var(--faint)}
.input:focus{outline:none;border-color:var(--brand);box-shadow:0 0 0 4px rgba(29,78,216,.14)}
.input[disabled]{background:#f1f5f9;color:var(--faint)}
.input-code{font:600 22px/1 var(--mono);letter-spacing:.35em;text-align:center;height:54px}
.hint{font-size:13px;color:var(--muted);margin-top:6px}

/* 알림 상자 */
.alert{display:flex;gap:10px;align-items:flex-start;padding:12px 14px;border-radius:var(--radius-sm);border:1px solid;font-size:14px;margin-bottom:18px}
.alert .ic{margin-top:2px}
.alert-error{color:var(--danger);background:var(--danger-bg);border-color:var(--danger-line)}
.alert-warn{color:var(--warn);background:var(--warn-bg);border-color:var(--warn-line)}
.alert-ok{color:var(--ok);background:var(--ok-bg);border-color:var(--ok-line)}
.alert-info{color:var(--info);background:var(--info-bg);border-color:var(--info-line)}
.alert b{font-weight:700}

/* 배지 */
.chip{display:inline-flex;align-items:center;gap:5px;height:24px;padding:0 9px;border-radius:999px;font-size:12.5px;font-weight:600;
  background:var(--line-2);color:var(--ink-2);white-space:nowrap}
.chip-brand{background:var(--brand-soft);color:var(--brand)}
.chip-danger{background:var(--danger-bg);color:var(--danger)}
.chip-warn{background:var(--warn-bg);color:var(--warn)}
.chip-ok{background:var(--ok-bg);color:var(--ok)}
.tier-top{background:#fdf2f8;color:#a1185d}
.tier-high{background:var(--warn-bg);color:var(--warn)}
.tier-base{background:var(--ok-bg);color:var(--ok)}

/* ===== 인증 화면(로그인/재인증/안내) ===== */
.auth{min-height:100vh;display:flex;flex-direction:column;align-items:center;padding:56px 16px 28px;
  background:radial-gradient(1200px 520px at 50% -180px,#e3ebff 0,rgba(227,235,255,0) 70%),var(--bg)}
.auth-brand{margin-bottom:22px}
.auth-card{width:100%;max-width:420px;background:var(--surface);border:1px solid var(--line);border-radius:16px;box-shadow:var(--shadow);padding:34px 32px 30px}
.auth-card.wide{max-width:500px}
.auth-badge{width:48px;height:48px;border-radius:12px;display:flex;align-items:center;justify-content:center;margin-bottom:18px;
  background:var(--brand-soft);color:var(--brand)}
.auth-badge.danger{background:var(--danger-bg);color:var(--danger)}
.auth-badge.warn{background:var(--warn-bg);color:var(--warn)}
.auth-badge.ok{background:var(--ok-bg);color:var(--ok)}
.auth-title{font-size:22px;font-weight:700;margin-bottom:6px}
.auth-sub{color:var(--muted);font-size:14.5px;margin-bottom:22px}
.auth-meta{display:flex;align-items:center;gap:8px;padding:10px 12px;border-radius:var(--radius-sm);background:#f8fafc;border:1px solid var(--line-2);
  font-size:13.5px;color:var(--ink-2);margin-bottom:18px}
.auth-meta .ic{color:var(--muted)}
.auth-foot{margin-top:22px;padding-top:18px;border-top:1px solid var(--line-2);display:flex;justify-content:space-between;gap:10px;flex-wrap:wrap;font-size:13.5px}
.auth-legal{max-width:460px;margin-top:22px;text-align:center;font-size:12.5px;color:var(--faint);line-height:1.7}
.steps{display:flex;gap:6px;margin-bottom:22px}
.steps span{flex:1;height:4px;border-radius:4px;background:var(--line)}
.steps span.on{background:var(--brand)}
.steps-label{font-size:12.5px;font-weight:600;color:var(--brand);margin-bottom:6px;letter-spacing:.02em}
.kv{display:grid;grid-template-columns:auto 1fr;gap:8px 16px;margin:0 0 20px;padding:14px 16px;border:1px solid var(--line);border-radius:var(--radius-sm);font-size:14px}
.kv dt{color:var(--muted)}
.kv dd{margin:0;font-weight:600;color:var(--ink);text-align:right}
.reason{display:flex;gap:12px;padding:14px;border:1px solid var(--line);border-radius:var(--radius-sm);margin-bottom:10px}
.reason .ic{color:var(--warn);margin-top:2px}
.reason b{display:block;font-size:14.5px;margin-bottom:2px}
.reason p{font-size:13.5px;color:var(--muted)}
.spinner{width:36px;height:36px;border-radius:50%;border:3px solid var(--brand-line);border-top-color:var(--brand);animation:spin .8s linear infinite;margin:6px auto 18px}
@keyframes spin{to{transform:rotate(360deg)}}
.center{text-align:center}

/* ===== 업무 화면(포털/팀 앱/관리자) ===== */
.topbar{position:sticky;top:0;z-index:10;height:60px;background:rgba(255,255,255,.92);backdrop-filter:saturate(180%) blur(8px);
  border-bottom:1px solid var(--line);display:flex;align-items:center;justify-content:space-between;padding:0 24px}
.topbar a.logo{text-decoration:none}
.topbar-right{display:flex;align-items:center;gap:10px}
.user-pill{display:flex;align-items:center;gap:10px;padding:4px 12px 4px 4px;border:1px solid var(--line);border-radius:999px;font-size:13.5px;color:var(--ink-2)}
.avatar{width:30px;height:30px;border-radius:50%;background:var(--brand);color:#fff;display:flex;align-items:center;justify-content:center;font-weight:700;font-size:13px;text-transform:uppercase}
.shell{max-width:1120px;margin:0 auto;padding:28px 24px 64px}
.shell.wide{max-width:1320px}
.page-head{display:flex;align-items:flex-end;justify-content:space-between;gap:16px;flex-wrap:wrap;margin-bottom:22px}
.crumb{font-size:13px;color:var(--muted);margin-bottom:6px;display:flex;align-items:center;gap:6px}
.page-title{font-size:24px;font-weight:700}
.page-desc{color:var(--muted);margin-top:4px}
.grid{display:grid;gap:16px}
.grid-2{grid-template-columns:2fr 1fr;align-items:start}
.grid-3{grid-template-columns:repeat(3,1fr)}
.card{background:var(--surface);border:1px solid var(--line);border-radius:var(--radius);padding:22px}
.card-title{display:flex;align-items:center;gap:8px;font-size:15.5px;font-weight:700;margin-bottom:14px}
.card-title .ic{color:var(--muted)}
.card-title .right{margin-left:auto}
.muted{color:var(--muted)}
.small{font-size:13px}
.list{list-style:none;margin:0;padding:0}
.list li{display:flex;gap:10px;align-items:flex-start;padding:11px 0;border-top:1px solid var(--line-2);font-size:14px}
.list li:first-child{border-top:0;padding-top:0}
.list .ic{color:var(--muted);margin-top:2px}
.app-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(230px,1fr));gap:14px}
.app-tile{display:flex;flex-direction:column;gap:10px;padding:18px;border:1px solid var(--line);border-radius:var(--radius);background:var(--surface);
  color:inherit;text-decoration:none!important;transition:border-color .15s,box-shadow .15s,transform .15s}
.app-tile:hover{border-color:var(--brand-line);box-shadow:0 8px 20px -8px rgba(29,78,216,.35);transform:translateY(-1px)}
.app-icon{width:42px;height:42px;border-radius:10px;background:var(--brand-soft);color:var(--brand);display:flex;align-items:center;justify-content:center}
.app-name{font-weight:700;font-size:15.5px}
.app-desc{color:var(--muted);font-size:13.5px}
.app-foot{display:flex;align-items:center;justify-content:space-between;margin-top:auto;padding-top:6px;font-size:12.5px;color:var(--faint)}
.empty{padding:28px;text-align:center;color:var(--muted);border:1px dashed var(--line);border-radius:var(--radius)}
.stat{display:flex;flex-direction:column;gap:2px}
.stat .label{font-size:13px;color:var(--muted)}
.stat .value{font-size:16px;font-weight:700}
.table-wrap{overflow-x:auto;border:1px solid var(--line);border-radius:var(--radius-sm)}
table.table{width:100%;border-collapse:collapse;font-size:13.5px;background:#fff}
.table th{position:sticky;top:0;background:#f8fafc;color:var(--muted);font-weight:600;font-size:12.5px;text-align:left;padding:10px 12px;border-bottom:1px solid var(--line);white-space:nowrap}
.table td{padding:10px 12px;border-bottom:1px solid var(--line-2);vertical-align:top}
.table tr:last-child td{border-bottom:0}
.table tr:hover td{background:#fafcff}
.table .mono{font-family:var(--mono);font-size:12.5px}
.table .wrap{max-width:420px;word-break:break-all;color:var(--ink-2)}
.toolbar{display:flex;align-items:center;gap:8px;flex-wrap:wrap;margin-bottom:12px}
.toast{position:fixed;right:20px;bottom:20px;max-width:360px;display:none;gap:12px;align-items:flex-start;padding:14px 16px;background:#0f172a;color:#fff;
  border-radius:var(--radius);box-shadow:var(--shadow);font-size:14px;z-index:50}
.toast.show{display:flex}
.toast .btn{height:32px;font-size:13px}
.footer{margin-top:40px;font-size:12.5px;color:var(--faint);text-align:center}
@media (max-width:860px){.grid-2,.grid-3{grid-template-columns:1fr}.topbar{padding:0 14px}.shell{padding:20px 14px 48px}
  .user-pill .who{display:none}.logo-sub{display:none}}
@media (max-width:480px){.auth{padding-top:28px}.auth-card{padding:26px 20px 22px;border-radius:14px}}
"""

# 제출 버튼을 한 번 누르면 잠깐 막는다(두 번 눌러 같은 요청이 두 번 가는 것 방지).
_SUBMIT_ONCE = """<script>
document.addEventListener('submit',function(e){var b=e.target.querySelector('button[type=submit]');
if(b){setTimeout(function(){b.disabled=true;b.classList.add('is-busy');},0);}},true);
</script>"""


def document(title, body_html, head_extra="", body_class=""):
    return (f'<!DOCTYPE html><html lang="ko"><head><meta charset="utf-8">'
            f'<meta name="viewport" content="width=device-width,initial-scale=1">'
            f'<meta name="robots" content="noindex,nofollow">'
            f'<title>{esc(title)} · {BRAND}</title><link rel="icon" href="{FAVICON}">'
            f'<style>{CSS}</style>{head_extra}</head><body class="{esc(body_class)}">{body_html}{_SUBMIT_ONCE}</body></html>')


def alert(kind, text, title=None):
    """kind: error / warn / ok / info. text는 이스케이프한다."""
    icons = {"error": "alert", "warn": "alert", "ok": "check", "info": "info"}
    head = f"<b>{esc(title)}</b> " if title else ""
    return f'<div class="alert alert-{kind}" role="alert">{icon(icons.get(kind, "info"), 18)}<div>{head}{esc(text)}</div></div>'


def link_button(href, label, variant="primary", icon_name=None, block=False, extra=""):
    ic = icon(icon_name, 18) if icon_name else ""
    return (f'<a class="btn btn-{variant}{" btn-block" if block else ""}" href="{esc(href)}" {extra}>'
            f'{ic}<span>{esc(label)}</span></a>')


LEGAL_NOTICE = ("이 시스템은 허가된 사용자만 이용할 수 있습니다. 모든 접속과 활동은 보안 목적으로 기록되며, "
                "비정상적인 접근이 확인되면 관련 규정에 따라 조치됩니다.")


def auth_page(title, heading, body_html, subtitle=None, badge="shield", tone="", wide=False, step=None, foot_html=""):
    """로그인 서버의 화면 틀: 로고 -> 카드(아이콘, 제목, 설명, 본문) -> 하단 안내 문구.
    step: (현재 단계, 전체 단계, 단계 이름) 이면 진행 막대를 보여 준다."""
    steps = ""
    if step:
        cur, total, label = step
        bars = "".join(f'<span class="{"on" if i < cur else ""}"></span>' for i in range(total))
        steps = f'<div class="steps-label">{cur}/{total} 단계 · {esc(label)}</div><div class="steps">{bars}</div>'
    sub = f'<p class="auth-sub">{esc(subtitle)}</p>' if subtitle else ""
    badge_html = f'<div class="auth-badge {tone}">{icon(badge, 24)}</div>' if badge else ""
    foot = f'<div class="auth-foot">{foot_html}</div>' if foot_html else ""
    body = (f'<main class="auth"><div class="auth-brand">{logo()}</div>'
            f'<section class="auth-card{" wide" if wide else ""}">{steps}{badge_html}'
            f'<h1 class="auth-title">{esc(heading)}</h1>{sub}{body_html}{foot}</section>'
            f'<p class="auth-legal">{LEGAL_NOTICE}</p></main>')
    return document(title, body)


TIER_LABELS = {"top_secret": ("최고기밀", "tier-top"), "confidential": ("기밀", "tier-high"), "internal": ("내부", "tier-base")}


def tier_chip(tier_key=None, label=None):
    """보안 등급 배지. tier_key(엔진 등급 이름)나 화면용 이름(label) 중 하나."""
    if tier_key in TIER_LABELS:
        label, cls = TIER_LABELS[tier_key]
    else:
        cls = {"최고기밀": "tier-top", "기밀": "tier-high", "내부": "tier-base"}.get(label, "")
    return f'<span class="chip {cls}">{icon("shield", 14)}{esc(label or "-")}</span>' if label else ""


def app_shell(title, content_html, user=None, product="워크스페이스", crumb=None, heading=None, desc=None,
              actions_html="", wide=False, home_href="/", logout_href=None, head_extra="", foot_html=""):
    """업무 화면 틀: 상단 바(로고, 사용자, 로그아웃) -> 제목 영역 -> 본문."""
    right = ""
    if user:
        initial = esc((user.split("@")[0][:1] or "?"))
        right = (f'<div class="user-pill" title="{esc(user)}"><span class="avatar">{initial}</span>'
                 f'<span class="who">{esc(user)}</span></div>')
        if logout_href:
            right += link_button(logout_href, "로그아웃", "ghost", "logout", extra='data-logout="1"')
    crumb_html = f'<div class="crumb">{crumb}</div>' if crumb else ""
    desc_html = f'<p class="page-desc">{esc(desc)}</p>' if desc else ""
    body = (f'<header class="topbar"><a class="logo" href="{esc(home_href)}">{logo(28)}'
            f'<span class="logo-sub">{esc(product)}</span></a><div class="topbar-right">{right}</div></header>'
            f'<main class="shell{" wide" if wide else ""}"><div class="page-head"><div>{crumb_html}'
            f'<h1 class="page-title">{esc(heading or title)}</h1>{desc_html}</div>'
            f'<div class="btn-row">{actions_html}</div></div>{content_html}'
            f'<p class="footer">© {BRAND} · {esc(LEGAL_NOTICE)}</p>{foot_html}</main>')
    return document(title, body, head_extra=head_extra)


def status_page(title, message, logout_href, tone="danger", badge="block", home_href=None):
    """웹 서버/업무 앱이 요청을 막을 때 보여 주는 안내 화면(로그인 서버 화면과 같은 모양)."""
    buttons = link_button(logout_href, "로그아웃 후 다시 로그인", "primary", "logout", block=True)
    if home_href:
        buttons = link_button(home_href, "포털 홈으로", "primary", "home", block=True) + \
                  '<div style="height:8px"></div>' + link_button(logout_href, "로그아웃", "secondary", "logout", block=True)
    return auth_page(title, title, f'<p class="auth-sub">{esc(message)}</p>{buttons}', badge=badge, tone=tone)
