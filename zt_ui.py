"""공통 화면 디자인(로그인 서버, 포털/업무 앱, 웹 서버 안내 화면이 같이 쓴다).

왜 한 파일인가: 세 서버가 각자 HTML/CSS를 들고 있으면 화면마다 모양이 달라지고 고칠 때도 세 곳을 따로 고쳐야 한다.
실무의 "디자인 시스템"처럼 색/글꼴/버튼/알림 상자/표를 한 곳에 정의하고, 각 서버는 S3에서 이 파일을 같이 받아 쓴다.

원칙
  - 외부 CDN에서 글꼴/스크립트/이미지를 불러오지 않는다. 글꼴(Pretendard, SIL OFL 1.1)은 웹 서버가 직접 내려준다
    (/_zt/assets/, nginx가 인증 없이 정적 파일로 제공 - 공개 글꼴 파일이라 숨길 것이 없음). 글꼴을 못 받으면 운영체제 글꼴로 보인다.
  - 화면에 넣는 값은 전부 esc()를 거친다(호출하는 쪽에서 이미 만든 HTML 조각만 그대로 넣는다).
  - 사용자 화면에는 판단 기준(어떤 신호로 위험도를 계산하는지), 점수, 내부 구현 이름을 쓰지 않는다.
    점수와 판정 근거는 관리자 콘솔과 관제 콘솔(Kibana)에서만 본다.
"""
import html as _html

BRAND = "XMCDA"
FONT_URL = "/_zt/assets/PretendardVariable.woff2"


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
    "search": '<circle cx="11" cy="11" r="7"/><path d="M20 20l-4-4"/>',
    "server": '<rect x="3" y="4" width="18" height="7" rx="2"/><rect x="3" y="13" width="18" height="7" rx="2"/><path d="M7 7.5h.01M7 16.5h.01"/>',
    "rocket": '<path d="M5 15c-1 1-1.5 3.5-1.5 5.5 2 0 4.5-.5 5.5-1.5M9 14l-3-3 7-7c2-2 5-2 6-2 0 1 0 4-2 6l-7 7-1-1z"/><circle cx="15" cy="9" r="1.5"/>',
    "chart": '<path d="M4 20V10M10 20V4M16 20v-7M22 20H2"/>',
    "chevron-down": '<path d="M6 9l6 6 6-6"/>',
}


def icon(name, size=20, cls="ic"):
    path = _ICONS.get(name, _ICONS["info"])
    return (f'<svg class="{cls}" width="{size}" height="{size}" viewBox="0 0 24 24" fill="none" stroke="currentColor" '
            f'stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">{path}</svg>')


def logo(size=30, text=BRAND):
    """회사 로고(방패 모양 + 글자). 이미지 파일 없이 SVG로 그린다."""
    return (f'<span class="logo"><svg width="{size}" height="{size}" viewBox="0 0 32 32" aria-hidden="true">'
            '<rect width="32" height="32" rx="9" fill="var(--brand)"/>'
            '<path d="M16 7l7 2.8v5.3c0 4.6-3 8.5-7 9.8-4-1.3-7-5.2-7-9.8V9.8L16 7z" fill="#fff"/>'
            '<path d="M12.8 16l2.3 2.3 4.2-4.6" fill="none" stroke="var(--brand)" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"/>'
            f'</svg><span class="logo-text">{esc(text)}</span></span>')


FAVICON = ("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'%3E%3Crect width='32' height='32' "
           "rx='9' fill='%233182f6'/%3E%3Cpath d='M16 7l7 2.8v5.3c0 4.6-3 8.5-7 9.8-4-1.3-7-5.2-7-9.8V9.8z' "
           "fill='white'/%3E%3C/svg%3E")

# ---------------------------------------------------------------------------
# 스타일: 디자인 토큰 -> 구성 요소. 밝은 업무용 화면, 좁은 화면(휴대폰)에서도 깨지지 않게.
# ---------------------------------------------------------------------------
CSS = """
@font-face{font-family:"Pretendard";src:url(__FONT__) format("woff2");font-weight:45 920;font-style:normal;font-display:swap}
:root{
  --brand:#3182f6;--brand-hover:#1b64da;--brand-soft:#e8f3ff;--brand-ink:#1957c2;
  --ink:#191f28;--ink-2:#333d4b;--ink-3:#4e5968;--muted:#6b7684;--faint:#8b95a1;
  --line:#e5e8eb;--line-2:#f2f4f6;--bg:#f2f4f6;--surface:#ffffff;
  --danger:#e42939;--danger-bg:#ffeeee;--warn:#d9730d;--warn-bg:#fff4e6;--ok:#0a8a5f;--ok-bg:#e6f7f0;--info:#1957c2;--info-bg:#e8f3ff;
  --radius:20px;--radius-md:14px;--radius-sm:10px;
  --font:Pretendard,-apple-system,BlinkMacSystemFont,"Apple SD Gothic Neo","Malgun Gothic","맑은 고딕","Segoe UI",sans-serif;
  --mono:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;
}
*{box-sizing:border-box}
html,body{margin:0;padding:0}
body{font-family:var(--font);color:var(--ink);background:var(--bg);font-size:15px;line-height:1.55;letter-spacing:-.01em;
  -webkit-font-smoothing:antialiased;word-break:keep-all;overflow-wrap:anywhere}
a{color:var(--brand);text-decoration:none}
a:hover{text-decoration:underline}
h1,h2,h3{margin:0;color:var(--ink);letter-spacing:-.02em}
p{margin:0}
.ic{flex:none;vertical-align:middle}
.mono{font-family:var(--mono);font-size:12.5px;letter-spacing:0}
.muted{color:var(--muted)}.faint{color:var(--faint)}.small{font-size:13px}

.logo{display:inline-flex;align-items:center;gap:10px;color:var(--ink)}
.logo-text{font-weight:800;font-size:17px;letter-spacing:.02em}

/* 버튼 */
.btn{display:inline-flex;align-items:center;justify-content:center;gap:7px;height:44px;padding:0 18px;border-radius:var(--radius-sm);
  border:0;font:600 15px/1 var(--font);cursor:pointer;text-decoration:none!important;white-space:nowrap;transition:background .15s,box-shadow .15s}
.btn:focus-visible{outline:none;box-shadow:0 0 0 4px rgba(49,130,246,.25)}
.btn-primary{background:var(--brand);color:#fff}.btn-primary:hover{background:var(--brand-hover)}
.btn-secondary{background:var(--line-2);color:var(--ink-3)}.btn-secondary:hover{background:#e5e8eb}
.btn-soft{background:var(--brand-soft);color:var(--brand-ink)}.btn-soft:hover{background:#d6e8ff}
.btn-danger{background:var(--danger-bg);color:var(--danger)}.btn-danger:hover{background:#ffe0e0}
.btn-ghost{background:transparent;color:var(--ink-3)}.btn-ghost:hover{background:var(--line-2)}
.btn-block{width:100%}
.btn-sm{height:34px;padding:0 12px;font-size:13.5px;border-radius:9px}
.btn[disabled],.btn.is-busy{opacity:.5;cursor:not-allowed}
.btn-row{display:flex;flex-wrap:wrap;gap:8px;align-items:center}

/* 알림 상자 */
.alert{display:flex;gap:10px;align-items:flex-start;padding:12px 14px;border-radius:var(--radius-sm);font-size:14px;margin-bottom:18px}
.alert .ic{margin-top:2px}
.alert-error{color:#b3141f;background:var(--danger-bg)}.alert-warn{color:#a35a0b;background:var(--warn-bg)}
.alert-ok{color:#06714e;background:var(--ok-bg)}.alert-info{color:var(--info);background:var(--info-bg)}

/* 배지 */
.chip{display:inline-flex;align-items:center;gap:4px;height:24px;padding:0 9px;border-radius:7px;font-size:12.5px;font-weight:600;
  background:var(--line-2);color:var(--ink-3);white-space:nowrap}
.chip-brand{background:var(--brand-soft);color:var(--brand-ink)}.chip-danger{background:var(--danger-bg);color:var(--danger)}
.chip-warn{background:var(--warn-bg);color:var(--warn)}.chip-ok{background:var(--ok-bg);color:var(--ok)}
.tier-top{background:#fdeef6;color:#c0287b}.tier-high{background:var(--warn-bg);color:var(--warn)}.tier-base{background:var(--ok-bg);color:var(--ok)}

/* ===== 인증 화면(로그인/재인증/안내): 가운데 카드, 밑줄 입력칸 ===== */
.auth{min-height:100vh;display:flex;flex-direction:column;align-items:center;justify-content:center;padding:40px 16px;
  background:linear-gradient(135deg,#e8f0fe 0%,#f5f6f8 45%,#eaf6f3 100%)}
.auth-card{width:100%;max-width:440px;background:var(--surface);border-radius:12px;padding:44px 44px 36px;
  box-shadow:0 2px 4px rgba(0,0,0,.06),0 18px 44px rgba(17,24,39,.12)}
.auth-card.wide{max-width:500px}
.auth-card .logo{margin-bottom:26px}
.auth-badge{width:44px;height:44px;border-radius:12px;display:flex;align-items:center;justify-content:center;margin-bottom:16px;background:var(--brand-soft);color:var(--brand)}
.auth-badge.danger{background:var(--danger-bg);color:var(--danger)}.auth-badge.warn{background:var(--warn-bg);color:var(--warn)}
.auth-badge.ok{background:var(--ok-bg);color:var(--ok)}
.auth-title{font-size:24px;font-weight:700;margin-bottom:6px}
.auth-sub{color:var(--ink-3);font-size:15px;margin-bottom:24px}
.uline{display:block;width:100%;height:42px;border:0;border-bottom:1px solid #8b95a1;border-radius:0;background:transparent;padding:0 2px;
  font:400 16px var(--font);color:var(--ink);margin-bottom:20px;transition:border-color .15s}
.uline::placeholder{color:var(--faint)}
.uline:focus{outline:none;border-bottom:2px solid var(--brand)}
.uline[disabled]{color:var(--faint);border-bottom-style:dashed}
.uline.code{font:600 24px var(--mono);letter-spacing:.4em;text-align:center;height:52px}
.field-label{display:block;font-size:13px;font-weight:600;color:var(--ink-3);margin-bottom:2px}
.hint{font-size:13px;color:var(--muted);margin:-12px 0 18px}
.auth-actions{display:flex;justify-content:space-between;align-items:center;gap:12px;margin-top:8px}
.auth-actions .btn{min-width:96px}
.auth-meta{display:flex;align-items:center;gap:8px;padding:11px 13px;border-radius:var(--radius-sm);background:var(--line-2);font-size:14px;color:var(--ink-2);margin-bottom:20px}
.auth-meta .ic{color:var(--muted)}
.auth-foot{margin-top:28px;padding-top:18px;border-top:1px solid var(--line);display:flex;align-items:flex-start;gap:8px;font-size:13px;color:var(--muted)}
.auth-foot .ic{margin-top:2px}
.kv{display:grid;grid-template-columns:auto 1fr;gap:9px 16px;margin:0 0 20px;padding:14px 16px;border-radius:var(--radius-sm);background:var(--line-2);font-size:14px}
.kv dt{color:var(--muted)}.kv dd{margin:0;font-weight:600;text-align:right}
.reason{display:flex;gap:12px;padding:14px;border-radius:var(--radius-sm);background:var(--warn-bg);margin-bottom:10px}
.reason .ic{color:var(--warn);margin-top:2px}.reason b{display:block;font-size:14.5px;margin-bottom:2px}.reason p{font-size:13.5px;color:var(--ink-3)}
.spinner{width:34px;height:34px;border-radius:50%;border:3px solid var(--brand-soft);border-top-color:var(--brand);animation:spin .8s linear infinite;margin:4px 0 18px}
@keyframes spin{to{transform:rotate(360deg)}}

/* ===== 업무 화면(포털/팀 앱/관리자) ===== */
.topbar{position:sticky;top:0;z-index:10;height:64px;background:#fff;display:flex;align-items:center;justify-content:space-between;padding:0 32px;
  box-shadow:0 1px 0 var(--line)}
.topbar a.logo{text-decoration:none}
.topbar .logo-text{font-size:17px}
.topbar-right{display:flex;align-items:center;gap:8px}
.timer{display:flex;align-items:center;gap:8px;font-size:13.5px;color:var(--ink-3);margin-right:4px}
.timer b{color:var(--brand);font-variant-numeric:tabular-nums;font-weight:700;min-width:40px}
.timer.soon b{color:var(--danger)}
.avatar{width:34px;height:34px;border-radius:50%;background:var(--brand-soft);color:var(--brand-ink);display:flex;align-items:center;justify-content:center;
  font-weight:700;font-size:13.5px;text-transform:uppercase}
.shell{max-width:1120px;margin:0 auto;padding:36px 32px 64px}
.shell.wide{max-width:1280px}
.page-head{display:flex;align-items:flex-end;justify-content:space-between;gap:16px;flex-wrap:wrap;margin-bottom:26px}
.crumb{font-size:13.5px;color:var(--muted);margin-bottom:8px;display:flex;align-items:center;gap:6px}
.crumb a{color:var(--muted)}
.page-title{font-size:28px;font-weight:700;letter-spacing:-.03em}
.page-desc{color:var(--muted);margin-top:6px;font-size:15.5px}
.grid{display:grid;gap:14px}
.grid-2{grid-template-columns:1.6fr 1fr;align-items:start}
.grid-4{grid-template-columns:repeat(4,1fr)}
.card{background:var(--surface);border-radius:var(--radius);padding:24px}
.card-title{display:flex;align-items:center;gap:8px;font-size:18px;font-weight:700;margin-bottom:14px}
.card-title .right{margin-left:auto;font-size:13.5px;font-weight:500;color:var(--faint)}
.card-desc{font-size:13.5px;color:var(--muted);margin:-8px 0 14px}
.list{list-style:none;margin:0;padding:0}
.list li{display:flex;gap:12px;align-items:center;padding:13px 0;font-size:15px;border-top:1px solid var(--line-2)}
.list li:first-child{border-top:0;padding-top:4px}
.list .end{margin-left:auto;color:var(--faint);font-size:14px;white-space:nowrap}
.sec-item{display:flex;align-items:center;gap:14px;padding:10px 0}
.sec-item .bx{width:40px;height:40px;border-radius:12px;background:var(--brand-soft);color:var(--brand);display:flex;align-items:center;justify-content:center;flex:none}
.sec-item b{display:block;font-size:15px}.sec-item span{color:var(--faint);font-size:13.5px}
.app-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:14px}
.app-tile{display:flex;flex-direction:column;background:var(--surface);border-radius:var(--radius);padding:22px;color:inherit;
  text-decoration:none!important;transition:transform .15s,box-shadow .15s}
a.app-tile:hover{transform:translateY(-2px);box-shadow:0 12px 28px -12px rgba(17,24,39,.22)}
.app-tile .bx{width:48px;height:48px;border-radius:16px;display:flex;align-items:center;justify-content:center;margin-bottom:18px}
.app-name{font-weight:700;font-size:17px}
.app-desc{color:var(--faint);font-size:14px;margin-top:4px}
.app-foot{display:flex;align-items:center;justify-content:space-between;margin-top:16px}
.app-tile.locked{background:#f9fafb;box-shadow:inset 0 0 0 1px var(--line)}
.app-tile.locked .bx{background:var(--line-2)!important;color:var(--faint)!important}
.app-tile.locked .app-name{color:var(--ink-3)}
.c-indigo{background:#eef0ff;color:#5b5bd6}.c-pink{background:#fdeef6;color:#d6409f}.c-amber{background:#fff4e0;color:#e08a00}.c-sky{background:#e6f6fd;color:#0f8fd6}
.empty{padding:28px;text-align:center;color:var(--muted);background:var(--line-2);border-radius:var(--radius-md)}
.stat{background:var(--surface);border-radius:var(--radius-md);padding:18px 20px}
.stat .label{font-size:13.5px;color:var(--muted)}
.stat .value{font-size:26px;font-weight:700;margin-top:4px;letter-spacing:-.02em}
.stat .value.sm{font-size:17px;margin-top:8px}
.toolbar{display:flex;align-items:center;gap:8px;flex-wrap:wrap;margin-bottom:14px}
.search{display:flex;align-items:center;gap:8px;height:42px;padding:0 14px;border-radius:var(--radius-sm);background:var(--line-2);min-width:280px;flex:1;max-width:420px}
.search input{border:0;background:transparent;font:400 15px var(--font);color:var(--ink);width:100%;outline:none}
.search .ic{color:var(--faint)}
.demo-note{display:inline-flex;align-items:center;gap:5px;font-size:12px;color:var(--faint)}
.table-wrap{overflow-x:auto;border-radius:var(--radius-sm);box-shadow:inset 0 0 0 1px var(--line)}
table.table{width:100%;border-collapse:collapse;font-size:14px;background:#fff}
.table th{position:sticky;top:0;background:#f9fafb;color:var(--muted);font-weight:600;font-size:13px;text-align:left;padding:11px 14px;border-bottom:1px solid var(--line);white-space:nowrap}
.table td{padding:12px 14px;border-bottom:1px solid var(--line-2);vertical-align:middle;white-space:nowrap;overflow-wrap:normal}
.table tr:last-child td{border-bottom:0}
.table tbody tr:hover td,.table tr:hover td{background:#fafbfc}
.table .wrap{max-width:420px;min-width:220px;white-space:normal;word-break:break-all;color:var(--ink-3);font-size:13px}
.dot{display:inline-block;width:8px;height:8px;border-radius:50%;margin-right:6px;vertical-align:middle}
.dot-ok{background:#12b886}.dot-warn{background:#fab005}.dot-bad{background:#fa5252}
.toast{position:fixed;right:24px;bottom:24px;max-width:380px;display:none;gap:14px;align-items:center;padding:16px 18px;background:#191f28;color:#fff;
  border-radius:16px;box-shadow:0 16px 40px rgba(0,0,0,.25);font-size:14px;z-index:50}
.toast.show{display:flex}
.footer{margin-top:44px;font-size:12.5px;color:var(--faint);text-align:center}
[data-panel]{margin-top:14px}
@media (max-width:960px){.app-grid,.grid-4{grid-template-columns:repeat(2,1fr)}.grid-2{grid-template-columns:1fr}}
.topbar .logo-text{white-space:nowrap}
@media (max-width:640px){.topbar{padding:0 14px}.timer span.lbl,.timer .btn,.topbar .avatar{display:none}.topbar .logo-text{font-size:15px}.shell{padding:24px 16px 48px}.app-grid{grid-template-columns:1fr}.grid-4{grid-template-columns:repeat(2,1fr)}.stat .value{font-size:22px}
  .auth-card{padding:32px 24px 26px}.page-title{font-size:24px}.search{min-width:0;max-width:none}}
""".replace("__FONT__", FONT_URL)

# 제출 버튼을 한 번 누르면 잠깐 막는다(두 번 눌러 같은 요청이 두 번 가는 것 방지).
_SUBMIT_ONCE = """<script>
document.addEventListener('submit',function(e){var b=e.target.querySelector('button[type=submit]');
if(b){setTimeout(function(){b.disabled=true;b.classList.add('is-busy');},0);}},true);
</script>"""


def document(title, body_html, head_extra=""):
    return (f'<!DOCTYPE html><html lang="ko"><head><meta charset="utf-8">'
            f'<meta name="viewport" content="width=device-width,initial-scale=1">'
            f'<meta name="robots" content="noindex,nofollow">'
            f'<title>{esc(title)} · {BRAND}</title><link rel="icon" href="{FAVICON}">'
            f'<link rel="preload" href="{FONT_URL}" as="font" type="font/woff2" crossorigin>'
            f'<style>{CSS}</style>{head_extra}</head><body>{body_html}{_SUBMIT_ONCE}</body></html>')


def alert(kind, text, title=None):
    """kind: error / warn / ok / info. text는 이스케이프한다."""
    icons = {"error": "alert", "warn": "alert", "ok": "check", "info": "info"}
    head = f"<b>{esc(title)}</b> " if title else ""
    return f'<div class="alert alert-{kind}" role="alert">{icon(icons.get(kind, "info"), 18)}<div>{head}{esc(text)}</div></div>'


def link_button(href, label, variant="primary", icon_name=None, block=False, extra=""):
    ic = icon(icon_name, 18) if icon_name else ""
    return (f'<a class="btn btn-{variant}{" btn-block" if block else ""}" href="{esc(href)}" {extra}>'
            f'{ic}<span>{esc(label)}</span></a>')


LEGAL_NOTICE = "이 시스템은 허가된 사용자만 이용할 수 있으며, 모든 접속과 활동은 보안 목적으로 기록됩니다."


def auth_page(title, heading, body_html, subtitle=None, badge=None, tone="", wide=False):
    """로그인 서버의 화면 틀: 카드 안에 로고 -> (상태 아이콘) -> 제목/설명 -> 본문 -> 법적 고지.
    badge: 차단/완료 같은 상태 화면에서만 아이콘을 보여 준다(로그인/인증 입력 화면은 아이콘 없이 단정하게)."""
    sub = f'<p class="auth-sub">{esc(subtitle)}</p>' if subtitle else ""
    badge_html = f'<div class="auth-badge {tone}">{icon(badge, 22)}</div>' if badge else ""
    body = (f'<main class="auth"><section class="auth-card{" wide" if wide else ""}">{logo()}{badge_html}'
            f'<h1 class="auth-title">{esc(heading)}</h1>{sub}{body_html}'
            f'<div class="auth-foot">{icon("lock", 15)}<span>{LEGAL_NOTICE}</span></div></section></main>')
    return document(title, body)


TIER_LABELS = {"top_secret": ("최고기밀", "tier-top"), "confidential": ("기밀", "tier-high"), "internal": ("내부", "tier-base")}


def tier_chip(tier_key=None, label=None):
    """보안 등급 배지. tier_key(엔진 등급 이름)나 화면용 이름(label) 중 하나."""
    if tier_key in TIER_LABELS:
        label, cls = TIER_LABELS[tier_key]
    else:
        cls = {"최고기밀": "tier-top", "기밀": "tier-high", "내부": "tier-base"}.get(label, "")
    return f'<span class="chip {cls}">{esc(label)}</span>' if label else ""


# 15분 무활동 자동 로그아웃(상단 카운트다운). 마우스/키보드 입력이나 [시간 연장]을 누르면 15:00으로 돌아가고,
# 2분 남으면 숫자가 빨갛게 바뀌며 알림이 뜬다. 0이 되면 로그인 서버의 /logout(모든 앱 세션 정리)으로 이동한다.
# (국내 금융/공공 사이트의 "로그인 시간 연장" 방식. 서버 쪽에서도 Access 세션 15분, 로그인 서버 SSO 30분 무활동 만료가 따로 걸려 있다)
_TIMER_SCRIPT = """<div class="toast" id="zt-toast" role="status"><div><b>곧 자동 로그아웃됩니다</b>
<div class="small" style="opacity:.75;margin-top:2px">계속 사용하려면 시간을 연장하세요.</div></div>
<button class="btn btn-sm btn-soft" type="button" data-extend>연장</button></div>
<script>
(function(){var LIMIT=15*60,WARN=120,left=LIMIT,el=document.getElementById('zt-left'),box=document.getElementById('zt-timer'),
toast=document.getElementById('zt-toast'),out=document.querySelector('[data-logout]');if(!el)return;
function draw(){var m=Math.floor(left/60),s=left%60;el.textContent=m+':'+(s<10?'0':'')+s;var soon=left<=WARN;
box.classList.toggle('soon',soon);toast.classList.toggle('show',soon);}
function reset(){left=LIMIT;draw();}
setInterval(function(){left-=1;if(left<=0){window.location.href=out?out.getAttribute('href'):'/';return;}draw();},1000);
['mousemove','keydown','click','scroll','touchstart'].forEach(function(ev){document.addEventListener(ev,function(){if(left>WARN)left=LIMIT;},{passive:true});});
document.querySelectorAll('[data-extend]').forEach(function(b){b.addEventListener('click',reset);});draw();})();
</script>"""


def app_shell(title, content_html, user=None, product="사내 포털", crumb=None, heading=None, desc=None,
              actions_html="", wide=False, home_href="/", logout_href=None, head_extra="", foot_html=""):
    """업무 화면 틀: 상단 바(로고, 자동 로그아웃 카운트다운, 로그아웃) -> 제목 영역 -> 본문."""
    right = ""
    timer = ""
    if user:
        timer = (f'<div class="timer" id="zt-timer">{icon("clock", 16)}<span class="lbl">자동 로그아웃까지</span>'
                 f'<b id="zt-left">15:00</b><button class="btn btn-sm btn-soft" type="button" data-extend>시간 연장</button></div>')
        right = timer
        if logout_href:
            right += link_button(logout_href, "로그아웃", "secondary btn-sm", extra='data-logout="1"')
        right += f'<span class="avatar" title="{esc(user)}">{esc((user.split("@")[0][:1] or "?"))}</span>'
    crumb_html = f'<div class="crumb">{crumb}</div>' if crumb else ""
    desc_html = f'<p class="page-desc">{esc(desc)}</p>' if desc else ""
    body = (f'<header class="topbar"><a class="logo" href="{esc(home_href)}">{logo(30, f"{BRAND} {product}")}</a>'
            f'<div class="topbar-right">{right}</div></header>'
            f'<main class="shell{" wide" if wide else ""}"><div class="page-head"><div>{crumb_html}'
            f'<h1 class="page-title">{esc(heading or title)}</h1>{desc_html}</div>'
            f'<div class="btn-row">{actions_html}</div></div>{content_html}'
            f'<p class="footer">© {BRAND} · {esc(LEGAL_NOTICE)}</p>{foot_html}{_TIMER_SCRIPT if user else ""}</main>')
    return document(title, body, head_extra=head_extra)


def status_page(title, message, logout_href, tone="danger", badge="block", home_href=None):
    """웹 서버/업무 앱이 요청을 막을 때 보여 주는 안내 화면(로그인 서버 화면과 같은 모양)."""
    if home_href:
        buttons = (f'<div class="btn-row">{link_button(home_href, "포털 홈으로", "primary", "home")}'
                   f'{link_button(logout_href, "로그아웃", "secondary", "logout")}</div>')
    else:
        buttons = link_button(logout_href, "로그아웃 후 다시 로그인", "primary", "logout", block=True)
    return auth_page(title, title, buttons, subtitle=message, badge=badge, tone=tone)
