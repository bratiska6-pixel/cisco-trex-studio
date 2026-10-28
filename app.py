import os
import sys
import glob
import json
import yaml
import struct
import threading
import shutil
import spwd
import crypt
import hmac
import time
import re
import subprocess
import ipaddress
import pwd
import grp
from datetime import datetime, timedelta
from functools import wraps
from flask import Flask, jsonify, request, render_template_string, session, redirect, url_for

# TRex Python API paths
sys.path.insert(0, '/opt/trex/v3.08/automation/trex_control_plane/interactive')
sys.path.insert(0, '/opt/trex/webui/trex_client/interactive')
try:
    from trex.astf.api import ASTFClient
except ImportError:
    ASTFClient = None

app = Flask(__name__)

# Persistent Secret Key for Sessions
SECRET_FILE = '/opt/trex/webui/.secret_key'
if os.path.exists(SECRET_FILE):
    try:
        with open(SECRET_FILE, 'r') as f:
            app.secret_key = f.read().strip()
    except Exception:
        app.secret_key = os.urandom(24).hex()
else:
    app.secret_key = os.urandom(24).hex()
    try:
        with open(SECRET_FILE, 'w') as f:
            f.write(app.secret_key)
        os.chmod(SECRET_FILE, 0o600)
    except Exception:
        pass

app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=12)

TREX_DIR = '/opt/trex/v3.08'
CUSTOM_DIR = '/opt/trex/v3.08/astf/custom'
PCAP_DIR = '/opt/trex/v3.08/astf/pcaps'
HISTORY_FILE = '/opt/trex/webui/reports_history.json'
os.makedirs(CUSTOM_DIR, exist_ok=True)
os.makedirs(PCAP_DIR, exist_ok=True)

lock = threading.Lock()
client = None
is_running_flag = False

# Verdict state management
last_test_end_time = 0.0
verdict_dismissed = False

# Cache for stats to avoid hammering TRex RPC
_stats_cache = {}
_stats_cache_time = 0.0
_health_cache = {}
_health_cache_time = 0.0

# Rate limiting for login
FAILED_LOGINS = {}  # ip -> {'count': int, 'lock_until': float}

# Regular expressions for validation
DOMAIN_REGEX = re.compile(r'^(?=.{1,253}$)(?!-)[A-Za-z0-9-]+(?<!-)(\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,63}$')
USERNAME_REGEX = re.compile(r'^[a-z_][a-z0-9_-]{2,30}$')

def check_login_rate_limit(ip):
    now = time.time()
    rec = FAILED_LOGINS.get(ip)
    if rec and rec['lock_until'] > now:
        return False, int(rec['lock_until'] - now)
    return True, 0

def record_failed_login(ip):
    now = time.time()
    rec = FAILED_LOGINS.setdefault(ip, {'count': 0, 'lock_until': 0})
    rec['count'] += 1
    if rec['count'] >= 5:
        rec['lock_until'] = now + 300  # 5 min lockout

def clear_failed_login(ip):
    FAILED_LOGINS.pop(ip, None)

def authenticate_os_user(username, password):
    """Authenticate credentials against Linux PAM / /etc/shadow."""
    if not username or not password:
        return False
    try:
        shadow_entry = spwd.getspnam(username)
        hashed_pw = shadow_entry.sp_pwdp
        if not hashed_pw or hashed_pw in ('*', '!'):
            return False
        calc_hash = crypt.crypt(password, hashed_pw)
        return hmac.compare_digest(calc_hash, hashed_pw)
    except KeyError:
        return False
    except Exception:
        return False

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user' not in session:
            if request.path.startswith('/api/'):
                return jsonify({'error': 'Unauthorized', 'auth_required': True}), 401
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

def verify_csrf():
    if request.method in ('POST', 'PUT', 'DELETE'):
        x_req = request.headers.get('X-Requested-With')
        origin = request.headers.get('Origin')
        referer = request.headers.get('Referer')
        host = request.host
        if x_req == 'XMLHttpRequest':
            return True
        if origin and (host in origin):
            return True
        if referer and (host in referer):
            return True
        return False
    return True

@app.before_request
def csrf_protect():
    if request.path.startswith('/api/') and request.method in ('POST', 'PUT', 'DELETE'):
        if not verify_csrf():
            return jsonify({'error': 'Forbidden: CSRF check failed'}), 403

def get_sys_health():
    global _health_cache, _health_cache_time
    now = time.time()
    if now - _health_cache_time < 2.0 and _health_cache:
        return _health_cache

    try:
        load1, load5, load15 = os.getloadavg()
    except Exception:
        load1, load5, load15 = 0.0, 0.0, 0.0

    try:
        total, used, free = shutil.disk_usage("/")
        disk_pct = (used / total) * 100
    except Exception:
        disk_pct = 0.0

    mem_total, mem_avail = 1, 1
    try:
        with open('/proc/meminfo', 'r') as f:
            for line in f:
                if line.startswith('MemTotal:'):
                    mem_total = int(line.split()[1])
                elif line.startswith('MemAvailable:'):
                    mem_avail = int(line.split()[1])
        ram_pct = ((mem_total - mem_avail) / mem_total) * 100
    except Exception:
        ram_pct = 0.0

    _health_cache = {
        'load': f"{load1:.2f}, {load5:.2f}, {load15:.2f}",
        'disk_pct': round(disk_pct, 1),
        'ram_pct': round(ram_pct, 1)
    }
    _health_cache_time = now
    return _health_cache

def default_session():
    return {
        'id': datetime.now().strftime('%Y%m%d_%H%M%S'),
        'start_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'end_time': 'В процессе...',
        'active_profile': 'astf/http_simple.py',
        'profile_tag': 'HTTP Базовый',
        'profile_desc': 'Эталонный тест пропускной способности L7',
        'mult': 100,
        'target_duration': 120,
        'max_tx_mbps': 0.0,
        'max_rx_mbps': 0.0,
        'max_pps': 0.0,
        'max_cps': 0.0,
        'max_flows': 0,
        'max_cpu': 0.0,
        'tcp_connects': 0,
        'tcp_drops': 0,
        'tcp_rexmt': 0,
        'nic_errors': 0,
        'p0_opackets': 0,
        'p0_ipackets': 0,
        'p1_opackets': 0,
        'p1_ipackets': 0,
        'verdict': 'ГОТОВ К ЗАПУСКУ',
        'verdict_detail': 'Испытание еще не проводилось.'
    }

current_session = default_session()

PROFILE_DESCRIPTIONS = {
    'astf/http_simple.py': ('HTTP Базовый', 'Эталонный тест пропускной способности L7: непрерывный поток HTTP GET запросов и ответов.'),
    'astf/sfr.py': ('Корпоративный микс (SFR)', 'Реалистичный микс трафика предприятия: HTTP, HTTPS, DNS, Почта, Видео и FTP.'),
    'astf/http_https.py': ('HTTP + HTTPS Микс', 'Комбинированная нагрузка открытого HTTP (порт 80) и зашифрованного SSL/TLS (порт 443) трафика.'),
    'astf/emix2.py': ('EMIX Пакетный микс', 'Распределение пакетов различной длины (Enterprise Mix) для стресс-тестирования сетевого стека NGFW.')
}

def describe_profile(rel_path):
    if rel_path in PROFILE_DESCRIPTIONS:
        return PROFILE_DESCRIPTIONS[rel_path]
    name = os.path.basename(rel_path)
    if name.startswith('dpi_tls_'):
        return ('DPI TLS/SNI', 'Проверка блокировки HTTPS/TLS 1.2 Client Hello (SNI порт 443).')
    if name.startswith('dpi_http_'):
        return ('DPI HTTP Host', 'Проверка фильтрации HTTP-заголовка Host (порт 80).')
    if name.startswith('pcap_'):
        return ('Загруженный PCAP', f'Воспроизведение дампа сетевого трафика ({name}).')
    return ('ASTF Сценарий', f'Профиль генерации прикладного трафика L7 ({name}).')

def load_history():
    if not os.path.exists(HISTORY_FILE):
        return []
    try:
        with open(HISTORY_FILE, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception:
        return []

def save_to_history(sess):
    if sess.get('p0_opackets', 0) == 0 and sess.get('max_tx_mbps', 0) == 0:
        return
    sess_copy = dict(sess)
    sess_copy['end_time'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    hist = load_history()
    hist = [h for h in hist if h.get('id') != sess_copy['id']]
    hist.insert(0, sess_copy)
    try:
        with open(HISTORY_FILE, 'w', encoding='utf-8') as f:
            json.dump(hist[:25], f, ensure_ascii=False, indent=2)
    except Exception:
        pass

def get_client():
    global client
    if ASTFClient is None:
        raise RuntimeError("TRex ASTF API library not found")
    if client is None or not client.is_connected():
        client = ASTFClient(server='127.0.0.1')
        client.connect()
        client.acquire(force=True)
    return client

def cleanup_custom_dpi_profiles():
    """Limit custom generated profiles to 12 files to prevent unbounded disk growth."""
    try:
        files = glob.glob(os.path.join(CUSTOM_DIR, "dpi_*.py"))
        if len(files) > 12:
            files.sort(key=os.path.getmtime)
            for f in files[:-12]:
                try:
                    os.remove(f)
                except Exception:
                    pass
    except Exception:
        pass

def build_tls_client_hello(domain):
    dom = domain.strip().encode('utf-8')
    sni_entry = b'\x00' + struct.pack('!H', len(dom)) + dom
    sni_list = struct.pack('!H', len(sni_entry)) + sni_entry
    ext_sni = struct.pack('!HH', 0x0000, len(sni_list)) + sni_list
    ext_groups = b'\x00\x0a\x00\x08\x00\x06\x00\x1d\x00\x17\x00\x18'
    ext_ec = b'\x00\x0b\x00\x02\x01\x00'
    extensions = ext_sni + ext_groups + ext_ec
    ext_block = struct.pack('!H', len(extensions)) + extensions
    body = b'\x03\x03' + (b'\x41' * 32) + b'\x00\x00\x08\xc0\x2f\xc0\x30\x00\x9c\x00\x2f\x01\x00' + ext_block
    handshake = b'\x01' + struct.pack('!I', len(body))[1:] + body
    return b'\x16\x03\x01' + struct.pack('!H', len(handshake)) + handshake

def generate_dpi_profile(domain, proto):
    clean_domain = domain.strip().lower()
    if not DOMAIN_REGEX.match(clean_domain):
        raise ValueError(f"Некорректный формат доменного имени: {clean_domain}")
    if proto not in ('tls', 'http'):
        raise ValueError("Недопустимый протокол инкапсуляции")

    safe_name = "".join(c if c.isalnum() else "_" for c in clean_domain)
    prof_rel = f"astf/custom/dpi_{proto}_{safe_name}.py"
    prof_path = os.path.join(TREX_DIR, prof_rel)

    if proto == 'tls':
        req_bytes = build_tls_client_hello(clean_domain)
        resp_bytes = b'\x16\x03\x03\x00\x31\x02\x00\x00\x2d\x03\x03' + (b'\x42' * 32) + b'\x00\xc0\x2f\x00\x00\x05\xff\x01\x00\x01\x00'
        port = 443
    else:
        req_bytes = f"GET / HTTP/1.1\r\nHost: {clean_domain}\r\nUser-Agent: Mozilla/5.0\r\nConnection: keep-alive\r\n\r\n".encode('ascii')
        resp_bytes = b"HTTP/1.1 200 OK\r\nServer: TRex\r\nContent-Length: 2\r\n\r\nOK"
        port = 80

    code = f"""from trex.astf.api import *
req_data = {repr(req_bytes)}
resp_data = {repr(resp_bytes)}
class Prof1():
    def get_profile(self, tunables=None, **kwargs):
        prog_c = ASTFProgram(); prog_c.send(req_data); prog_c.recv(len(resp_data))
        prog_s = ASTFProgram(); prog_s.recv(len(req_data)); prog_s.send(resp_data)
        ip_gen_c = ASTFIPGenDist(ip_range=["16.0.0.1", "16.0.0.254"], distribution="seq")
        ip_gen_s = ASTFIPGenDist(ip_range=["48.0.0.1", "48.0.0.20"], distribution="seq")
        ip_gen = ASTFIPGen(glob=ASTFIPGenGlobal(ip_offset="1.0.0.0"), dist_client=ip_gen_c, dist_server=ip_gen_s)
        temp_c = ASTFTCPClientTemplate(program=prog_c, ip_gen=ip_gen, port={port})
        temp_s = ASTFTCPServerTemplate(program=prog_s, assoc=ASTFAssociationRule(port={port}))
        return ASTFProfile(default_ip_gen=ip_gen, templates=ASTFTemplate(client_template=temp_c, server_template=temp_s))
def register(): return Prof1()
"""
    with open(prof_path, 'w', encoding='utf-8') as f:
        f.write(code)

    cleanup_custom_dpi_profiles()
    return prof_rel

def read_net_cfg():
    try:
        with open('/etc/trex_cfg.yaml', 'r') as f:
            data = yaml.safe_load(f)
        pi = data[0].get('port_info', [{}, {}])
        return {
            'p0_ip': pi[0].get('ip', '192.168.1.2'),
            'p0_gw': pi[0].get('default_gw', '192.168.1.1'),
            'p1_ip': pi[1].get('ip', '172.10.1.2'),
            'p1_gw': pi[1].get('default_gw', '172.10.1.1')
        }
    except Exception:
        return {'p0_ip': '192.168.1.2', 'p0_gw': '192.168.1.1', 'p1_ip': '172.10.1.2', 'p1_gw': '172.10.1.1'}

def get_os_users():
    res = []
    current_user = session.get('user', '')
    for p in pwd.getpwall():
        if (p.pw_uid >= 1000 or p.pw_name == 'root') and p.pw_shell not in ['/usr/sbin/nologin', '/bin/false']:
            groups = [g.gr_name for g in grp.getgrall() if p.pw_name in g.gr_mem]
            is_sudo = 'sudo' in groups or p.pw_name == 'root'
            res.append({
                'username': p.pw_name,
                'uid': p.pw_uid,
                'gid': p.pw_gid,
                'home': p.pw_dir,
                'is_sudo': is_sudo,
                'is_current': (p.pw_name == current_user),
                'is_root': (p.pw_name == 'root')
            })
    res.sort(key=lambda u: (0 if u['is_root'] else 1, u['uid']))
    return res

# --- HTML TEMPLATES ---

LOGIN_PAGE = """<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Вход в систему — TRex Studio</title>
    <style>
        :root {
            --bg-base: #06070a;
            --glass-bg: rgba(22, 23, 34, 0.72);
            --glass-border: rgba(255, 255, 255, 0.12);
            --text-main: #f5f5f7;
            --text-muted: #8e8e93;
            --ai-gradient: linear-gradient(135deg, #4285f4 0%, #9b72cb 35%, #d96570 70%, #f49c46 100%);
            --accent-blue: #2997ff;
            --accent-red: #ff453a;
        }
        * { box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, "SF Pro Text", "Segoe UI", Roboto, sans-serif; }
        body {
            background-color: var(--bg-base);
            color: var(--text-main);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
            position: relative;
            overflow: hidden;
        }
        .orb {
            position: fixed;
            border-radius: 50%;
            filter: blur(120px);
            z-index: 0;
            pointer-events: none;
            opacity: 0.35;
        }
        .orb-1 { width: 500px; height: 500px; background: radial-gradient(circle, #9b72cb, #4285f4); top: -150px; left: -100px; }
        .orb-2 { width: 450px; height: 450px; background: radial-gradient(circle, #d96570, #f49c46); bottom: -120px; right: -80px; }
        .login-card {
            position: relative;
            z-index: 10;
            width: 100%;
            max-width: 420px;
            background: var(--glass-bg);
            backdrop-filter: blur(32px);
            -webkit-backdrop-filter: blur(32px);
            border: 1px solid var(--glass-border);
            border-radius: 26px;
            padding: 40px 36px;
            box-shadow: 0 30px 60px rgba(0,0,0,0.6);
        }
        .brand-header {
            text-align: center;
            margin-bottom: 28px;
        }
        .brand-icon {
            font-size: 2.4rem;
            display: inline-block;
            margin-bottom: 8px;
            filter: drop-shadow(0 0 16px rgba(155,114,203,0.5));
        }
        .brand-title {
            font-size: 1.6rem;
            font-weight: 700;
            letter-spacing: -0.02em;
        }
        .ai-text {
            background: var(--ai-gradient);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }
        .brand-sub {
            font-size: 0.85rem;
            color: var(--text-muted);
            margin-top: 6px;
        }
        .form-group {
            margin-bottom: 18px;
        }
        label {
            display: block;
            font-size: 0.78rem;
            font-weight: 600;
            color: var(--text-muted);
            text-transform: uppercase;
            letter-spacing: 0.05em;
            margin-bottom: 8px;
        }
        input {
            width: 100%;
            background: rgba(10, 10, 16, 0.75);
            border: 1px solid rgba(255, 255, 255, 0.16);
            color: var(--text-main);
            padding: 13px 16px;
            border-radius: 14px;
            font-size: 0.95rem;
            outline: none;
            transition: all 0.2s ease;
        }
        input:focus {
            border-color: #9b72cb;
            box-shadow: 0 0 0 3px rgba(155, 114, 203, 0.25);
            background: rgba(16, 16, 26, 0.9);
        }
        .btn-submit {
            width: 100%;
            padding: 13px;
            border-radius: 14px;
            border: none;
            background: var(--ai-gradient);
            color: #fff;
            font-size: 0.98rem;
            font-weight: 600;
            cursor: pointer;
            transition: transform 0.15s ease, box-shadow 0.2s ease;
            box-shadow: 0 8px 24px rgba(217, 101, 112, 0.35);
            margin-top: 8px;
        }
        .btn-submit:hover {
            transform: translateY(-1px);
            box-shadow: 0 10px 28px rgba(217, 101, 112, 0.45);
        }
        .btn-submit:active { transform: translateY(1px); }
        .alert-error {
            background: rgba(255, 69, 58, 0.16);
            border: 1px solid rgba(255, 69, 58, 0.4);
            color: #ff6961;
            padding: 10px 14px;
            border-radius: 12px;
            font-size: 0.85rem;
            margin-bottom: 18px;
            display: flex;
            align-items: center;
            gap: 8px;
        }
        .footer-note {
            text-align: center;
            font-size: 0.76rem;
            color: var(--text-muted);
            margin-top: 24px;
        }
    </style>
</head>
<body>
    <div class="orb orb-1"></div>
    <div class="orb orb-2"></div>
    <div class="login-card">
        <div class="brand-header">
            <div class="brand-icon">⚡</div>
            <h1 class="brand-title">TRex Studio <span class="ai-text">L7</span></h1>
            <p class="brand-sub">Авторизация учётной записью ОС (Linux / PAM)</p>
        </div>

        {% if error %}
        <div class="alert-error">
            <span>⚠️</span>
            <span>{{ error }}</span>
        </div>
        {% endif %}

        <form method="POST" action="/login">
            <input type="hidden" name="next" value="{{ next_url }}">
            <div class="form-group">
                <label for="username">Имя пользователя ОС</label>
                <input type="text" id="username" name="username" placeholder="user / root" required autofocus autocomplete="username">
            </div>
            <div class="form-group">
                <label for="password">Пароль</label>
                <input type="password" id="password" name="password" placeholder="••••••••" required autocomplete="current-password">
            </div>
            <button type="submit" class="btn-submit">Войти в консоль управления</button>
        </form>

        <div class="footer-note">
            Сервер: <strong>TRex ASTF Studio</strong> • Защищённый доступ
        </div>
    </div>
</body>
</html>
"""

HTML_PAGE = """<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>TRex Studio — Генератор трафика L7</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.min.js"></script>
    <style>
        :root {
            --bg-base: #06070a;
            --glass-bg: rgba(22, 23, 34, 0.65);
            --glass-border: rgba(255, 255, 255, 0.12);
            --glass-hover: rgba(255, 255, 255, 0.18);
            --text-main: #f5f5f7;
            --text-muted: #8e8e93;
            --ai-gradient: linear-gradient(135deg, #4285f4 0%, #9b72cb 35%, #d96570 70%, #f49c46 100%);
            --accent-blue: #2997ff;
            --accent-green: #30d158;
            --accent-red: #ff453a;
            --accent-orange: #ff9f0a;
            --accent-purple: #bf5af2;
            --accent-teal: #32ade6;
        }
        * { box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, "SF Pro Text", "Segoe UI", Roboto, sans-serif; }
        body {
            background-color: var(--bg-base);
            color: var(--text-main);
            min-height: 100vh;
            overflow-x: hidden;
            padding: 20px 28px;
            position: relative;
        }

        .ambient-orb-1, .ambient-orb-2 {
            position: fixed;
            border-radius: 50%;
            filter: blur(125px);
            z-index: -1;
            opacity: 0.28;
            pointer-events: none;
            animation: floatOrb 16s infinite alternate ease-in-out;
        }
        .ambient-orb-1 { width: 550px; height: 550px; background: radial-gradient(circle, #9b72cb 0%, #4285f4 60%, transparent 100%); top: -140px; left: -120px; }
        .ambient-orb-2 { width: 500px; height: 500px; background: radial-gradient(circle, #d96570 0%, #f49c46 60%, transparent 100%); bottom: -130px; right: -90px; animation-delay: -8s; }
        @keyframes floatOrb {
            0% { transform: translate(0, 0) scale(1); }
            100% { transform: translate(35px, 25px) scale(1.06); }
        }

        .glass-card {
            background: var(--glass-bg);
            backdrop-filter: blur(28px);
            -webkit-backdrop-filter: blur(28px);
            border: 1px solid var(--glass-border);
            border-radius: 20px;
            padding: 18px 22px;
            box-shadow: 0 16px 40px rgba(0,0,0,0.4);
            transition: border-color 0.2s ease;
        }
        .glass-card:hover { border-color: rgba(255, 255, 255, 0.18); }
        .ai-glow-border {
            background: linear-gradient(var(--bg-base), var(--bg-base)) padding-box, var(--ai-gradient) border-box;
            border: 1.5px solid transparent;
        }
        .ai-text {
            background: var(--ai-gradient);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            font-weight: 700;
        }

        .top-bar {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 18px;
            flex-wrap: wrap;
            gap: 14px;
        }
        .brand-title {
            font-size: 1.5rem;
            font-weight: 700;
            letter-spacing: -0.02em;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        .brand-sub {
            font-size: 0.82rem;
            color: var(--text-muted);
            margin-top: 3px;
            display: flex;
            gap: 12px;
            align-items: center;
        }

        .segmented-nav {
            display: inline-flex;
            background: rgba(255, 255, 255, 0.06);
            padding: 4px;
            border-radius: 999px;
            border: 1px solid var(--glass-border);
            gap: 2px;
            flex-wrap: wrap;
        }
        .seg-btn {
            background: transparent;
            border: none;
            color: var(--text-muted);
            padding: 8px 16px;
            border-radius: 999px;
            font-size: 0.84rem;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.22s ease;
            display: inline-flex;
            align-items: center;
            gap: 6px;
        }
        .seg-btn:hover { color: var(--text-main); }
        .seg-btn.active {
            background: rgba(255, 255, 255, 0.15);
            color: var(--text-main);
            box-shadow: 0 4px 14px rgba(0, 0, 0, 0.35);
        }

        .status-pill {
            display: inline-flex;
            align-items: center;
            gap: 8px;
            padding: 6px 14px;
            border-radius: 999px;
            font-size: 0.82rem;
            font-weight: 600;
            background: rgba(48, 209, 88, 0.14);
            color: var(--accent-green);
            border: 1px solid rgba(48, 209, 88, 0.35);
        }
        .status-dot {
            width: 8px;
            height: 8px;
            border-radius: 50%;
            background: var(--accent-green);
            box-shadow: 0 0 10px var(--accent-green);
        }
        .user-badge {
            display: inline-flex;
            align-items: center;
            gap: 6px;
            padding: 6px 12px;
            border-radius: 999px;
            font-size: 0.82rem;
            font-weight: 600;
            background: rgba(255, 255, 255, 0.08);
            border: 1px solid var(--glass-border);
            color: var(--text-main);
        }

        label {
            font-size: 0.76rem;
            font-weight: 600;
            color: var(--text-muted);
            text-transform: uppercase;
            letter-spacing: 0.05em;
            display: block;
            margin-bottom: 6px;
        }
        input, select {
            width: 100%;
            background: rgba(10, 10, 16, 0.75);
            border: 1px solid rgba(255, 255, 255, 0.15);
            color: var(--text-main);
            padding: 10px 14px;
            border-radius: 12px;
            font-size: 0.9rem;
            outline: none;
            transition: all 0.2s ease;
        }
        input[type=number]::-webkit-inner-spin-button, input[type=number]::-webkit-outer-spin-button { -webkit-appearance: none; margin: 0; }
        input[type=number] { -moz-appearance: textfield; }
        select option { background-color: #141420; color: #f5f5f7; }
        input:focus, select:focus {
            border-color: #9b72cb;
            box-shadow: 0 0 0 3px rgba(155, 114, 203, 0.25);
        }

        .btn-apple {
            border: none;
            border-radius: 12px;
            padding: 10px 16px;
            font-size: 0.88rem;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.2s ease;
            display: inline-flex;
            align-items: center;
            justify-content: center;
            gap: 8px;
            color: #fff;
            text-decoration: none;
        }
        .btn-apple:hover { transform: translateY(-1px); }
        .btn-apple:active { transform: translateY(1px); }
        .btn-ai { background: var(--ai-gradient); box-shadow: 0 4px 16px rgba(217, 101, 112, 0.3); }
        .btn-toggle-start { background: linear-gradient(135deg, #30d158, #248a3d); box-shadow: 0 4px 16px rgba(48, 209, 88, 0.3); }
        .btn-toggle-stop { background: linear-gradient(135deg, #ff453a, #c9342b); box-shadow: 0 0 20px rgba(255, 69, 58, 0.5); animation: pulseStop 1.8s infinite; }
        @keyframes pulseStop { 0% { box-shadow: 0 0 0 0 rgba(255, 69, 58, 0.6); } 70% { box-shadow: 0 0 0 10px rgba(255, 69, 58, 0); } 100% { box-shadow: 0 0 0 0 rgba(255, 69, 58, 0); } }
        .btn-ghost { background: rgba(255, 255, 255, 0.08); border: 1px solid var(--glass-border); color: var(--text-main); }
        .btn-ghost:hover { background: rgba(255, 255, 255, 0.14); }
        .btn-red { background: linear-gradient(135deg, #ff453a, #c9342b); }

        .chip {
            background: rgba(255, 255, 255, 0.08);
            border: 1px solid rgba(255, 255, 255, 0.14);
            color: var(--text-main);
            padding: 5px 12px;
            border-radius: 999px;
            font-size: 0.78rem;
            font-weight: 500;
            cursor: pointer;
            transition: all 0.18s ease;
        }
        .chip:hover {
            background: var(--ai-gradient);
            border-color: transparent;
            color: #fff;
            transform: scale(1.04);
        }

        .grid-6 { display: grid; grid-template-columns: repeat(6, 1fr); gap: 12px; margin-bottom: 16px; }
        .grid-4 { display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; margin-bottom: 16px; }
        .grid-charts { display: grid; grid-template-columns: 1.35fr 1fr 0.95fr; gap: 14px; margin-bottom: 16px; }
        @media (max-width: 1200px) {
            .grid-6 { grid-template-columns: repeat(3, 1fr); }
            .grid-charts { grid-template-columns: 1fr; }
        }
        @media (max-width: 768px) {
            .grid-6 { grid-template-columns: repeat(2, 1fr); }
            .grid-4 { grid-template-columns: repeat(2, 1fr); }
        }

        .metric-val {
            font-size: 1.65rem;
            font-weight: 700;
            letter-spacing: -0.03em;
            margin-top: 4px;
        }

        .verdict-banner {
            display: flex;
            align-items: center;
            justify-content: space-between;
            padding: 12px 18px;
            border-radius: 14px;
            margin-bottom: 16px;
            font-weight: 600;
            font-size: 0.9rem;
            border: 1px solid var(--glass-border);
            background: rgba(255, 255, 255, 0.04);
            transition: all 0.3s ease;
        }

        table { width: 100%; border-collapse: collapse; font-size: 0.85rem; }
        th, td { padding: 9px 10px; text-align: left; border-bottom: 1px solid rgba(255, 255, 255, 0.08); }
        th { color: var(--text-muted); font-weight: 600; font-size: 0.74rem; text-transform: uppercase; letter-spacing: 0.04em; }

        .tab-pane { display: none; }
        .tab-pane.active { display: block; animation: fadeIn 0.22s ease; }
        @keyframes fadeIn { from { opacity: 0; transform: translateY(4px); } to { opacity: 1; transform: translateY(0); } }

        .health-bar-container { width: 100%; height: 6px; background: rgba(255,255,255,0.12); border-radius: 3px; overflow: hidden; margin-top: 4px; }
        .health-bar { height: 100%; border-radius: 3px; transition: width 0.4s ease; }

        .custom-picker { position: relative; user-select: none; }
        .picker-trigger { width: 100%; background: rgba(10, 10, 16, 0.75); border: 1px solid rgba(255, 255, 255, 0.16); color: var(--text-main); padding: 10px 14px; border-radius: 12px; font-size: 0.9rem; cursor: pointer; display: flex; justify-content: space-between; align-items: center; }
        .picker-dropdown { display: none; position: absolute; top: calc(100% + 6px); left: 0; right: 0; background: #131422; border: 1px solid rgba(255, 255, 255, 0.2); border-radius: 16px; box-shadow: 0 24px 60px rgba(0, 0, 0, 0.85); z-index: 9999; padding: 10px; }
        .picker-dropdown.open { display: block; animation: fadeIn 0.15s ease; }
        .picker-search { margin-bottom: 8px; background: rgba(255, 255, 255, 0.08); border: 1px solid rgba(255, 255, 255, 0.18); padding: 8px 12px; border-radius: 10px; color: #fff; width: 100%; }
        .picker-list { max-height: 260px; overflow-y: auto; padding-right: 4px; }
        .picker-item { padding: 9px 12px; border-radius: 10px; cursor: pointer; margin-bottom: 4px; border: 1px solid transparent; }
        .picker-item:hover, .picker-item.selected { background: rgba(155, 114, 203, 0.22); border-color: rgba(155, 114, 203, 0.4); }
        .picker-item-head { display: flex; justify-content: space-between; align-items: center; font-weight: 600; font-size: 0.88rem; }
        .picker-item-tag { font-size: 0.7rem; padding: 2px 8px; border-radius: 999px; background: rgba(41, 151, 255, 0.18); color: var(--accent-blue); font-weight: 600; }
        .picker-item-desc { font-size: 0.76rem; color: var(--text-muted); margin-top: 3px; }
        .combo-container { position: relative; width: 100%; }
        .combo-input { width: 100%; padding-right: 32px; }
        .combo-arrow { position: absolute; right: 12px; top: 11px; color: var(--text-muted); pointer-events: none; font-size: 0.8rem; }

        /* Toast notification popup */
        #toast-box {
            position: fixed;
            bottom: 24px;
            right: 28px;
            z-index: 10000;
            display: flex;
            flex-direction: column;
            gap: 10px;
            pointer-events: none;
        }
        .toast {
            background: rgba(22, 23, 34, 0.92);
            backdrop-filter: blur(20px);
            border: 1px solid var(--glass-border);
            color: #fff;
            padding: 12px 18px;
            border-radius: 14px;
            font-size: 0.86rem;
            font-weight: 500;
            box-shadow: 0 14px 35px rgba(0,0,0,0.5);
            display: flex;
            align-items: center;
            gap: 10px;
            animation: slideUp 0.25s ease forwards;
            pointer-events: auto;
            max-width: 420px;
        }
        .toast-success { border-color: rgba(48, 209, 88, 0.4); }
        .toast-error { border-color: rgba(255, 69, 58, 0.5); color: #ff6961; }
        @keyframes slideUp { from { opacity: 0; transform: translateY(12px); } to { opacity: 1; transform: translateY(0); } }
    </style>
</head>
<body>
    <div class="ambient-orb-1"></div>
    <div class="ambient-orb-2"></div>
    <div id="toast-box"></div>

    <!-- ВЕРХНЯЯ ПАНЕЛЬ -->
    <div class="top-bar">
        <div>
            <div class="brand-title">
                <span>⚡</span>
                <span>TRex Studio <span class="ai-text">Генератор Трафика L7</span></span>
            </div>
            <div class="brand-sub">
                <span>🕒 <strong id="sys-clock" style="color:#fff;">00:00:00</strong></span>
                <span>•</span>
                <span>🌐 Платформа: <strong>TRex ASTF v3.08</strong></span>
                <span>•</span>
                <span>Комплекс испытаний NGFW / DPI</span>
            </div>
        </div>

        <div class="segmented-nav">
            <button class="seg-btn active" onclick="switchTab('tab-dash', this)">📊 Дашборд & Нагрузка</button>
            <button class="seg-btn" onclick="switchTab('tab-dpi', this)">🕵️‍♂️ Проверка DPI / Приложений</button>
            <button class="seg-btn" onclick="switchTab('tab-reports', this); loadReportsHistory();">📑 Журнал ПМИ</button>
            <button class="seg-btn" onclick="switchTab('tab-net', this)">⚙️ Сеть стенда</button>
            <button class="seg-btn" onclick="switchTab('tab-users', this); loadUsers();">👥 Пользователи ОС</button>
        </div>

        <div style="display:flex; gap:10px; align-items:center;">
            <div id="engine-pill" class="status-pill">
                <span class="status-dot" id="engine-dot"></span>
                <span id="engine-text">Подключение...</span>
            </div>
            <div class="user-badge" title="Текущий пользователь ОС">
                <span>👤</span>
                <span>{{ session.get('user', 'пользователь') }}</span>
            </div>
            <a href="/logout" class="btn-apple btn-ghost" style="padding:6px 12px; font-size:0.8rem;" title="Завершить сеанс">Выйти</a>
        </div>
    </div>

    <!-- ПАНЕЛЬ ЗДОРОВЬЯ СЕРВЕРА -->
    <div class="glass-card" style="padding: 12px 20px; margin-bottom: 16px; display: flex; justify-content: space-between; align-items: center; border-radius: 16px; flex-wrap:wrap; gap:12px;">
        <div style="font-size: 0.78rem; font-weight: 700; color: var(--text-muted); letter-spacing: 0.05em; display:flex; align-items:center; gap:8px;">
            🖥️ СОСТОЯНИЕ TREX VM:
        </div>
        <div style="font-size: 0.85rem; display:flex; gap:26px; align-items:center; flex-wrap:wrap;">
            <div><span style="color:var(--text-muted)">Load Avg:</span> <strong id="sys-load" style="color:var(--accent-blue)">0.00</strong></div>
            <div style="width: 180px;">
                <div style="display:flex; justify-content:space-between; margin-bottom:2px;"><span style="color:var(--text-muted)">RAM:</span> <strong id="sys-ram-txt">0%</strong></div>
                <div class="health-bar-container"><div id="sys-ram-bar" class="health-bar" style="background: var(--accent-blue); width: 0%;"></div></div>
            </div>
            <div style="width: 180px;">
                <div style="display:flex; justify-content:space-between; margin-bottom:2px;"><span style="color:var(--text-muted)">DISK:</span> <strong id="sys-disk-txt">0%</strong></div>
                <div class="health-bar-container"><div id="sys-disk-bar" class="health-bar" style="background: var(--accent-purple); width: 0%;"></div></div>
            </div>
        </div>
    </div>

    <!-- ВЕРДИКТ ИСПЫТАНИЙ (НЕ ЗАВИСАЕТ, МОЖНО ЗАКРЫТЬ) -->
    <div id="verdict-box" class="verdict-banner">
        <div style="display:flex; align-items:center; gap:8px;">
            <span id="verdict-icon">✦</span>
            <span id="verdict-title">Система готова к проведению испытаний</span>
        </div>
        <div style="display:flex; gap:8px; align-items:center;">
            <button class="btn-apple btn-ghost" style="padding:5px 12px; font-size:0.78rem;" onclick="saveCurrentReport()" title="Зафиксировать результат текущего теста в журнал">📌 Зафиксировать в ПМИ</button>
            <button class="btn-apple btn-ai" style="padding:5px 12px; font-size:0.78rem;" onclick="window.location.href='/api/export_report'">📥 Скачать ПМИ (.md)</button>
            <button id="dismiss-verdict-btn" class="btn-apple btn-ghost" style="padding:4px 8px; font-size:0.78rem; display:none;" onclick="dismissVerdict()" title="Скрыть статус">✕</button>
        </div>
    </div>

    <!-- ВКЛАДКА 1: ДАШБОРД И НАГРУЗКА -->
    <div id="tab-dash" class="tab-pane active">
        <div class="glass-card" style="margin-bottom: 16px;">
            <div style="display: grid; grid-template-columns: 2.2fr 0.8fr 0.8fr 1.6fr; gap: 14px; align-items: end;">
                <div>
                    <label>Сценарий / Приложение L7 (с быстрым поиском):</label>
                    <input type="hidden" id="profile" value="astf/http_simple.py">
                    <div class="custom-picker" id="profile-picker">
                        <div class="picker-trigger" id="picker-trigger" onclick="togglePicker('picker-dropdown', 'picker-trigger', 'picker-search')">
                            <span id="picker-selected-text">astf/http_simple.py — HTTP Базовый</span>
                            <span style="color:var(--text-muted); font-size:0.8rem;">▼ Поиск</span>
                        </div>
                        <div class="picker-dropdown" id="picker-dropdown">
                            <input type="text" id="picker-search" class="picker-search" placeholder="🔍 Введите сценарий (http, sfr, https, emix)..." oninput="filterProfiles('picker-search', 'picker-item')">
                            <div class="picker-list">
                                {% for p in profiles %}
                                <div class="picker-item {% if p.path == 'astf/http_simple.py' %}selected{% endif %}" data-path="{{ p.path }}" data-tag="{{ p.tag }}" data-desc="{{ p.desc }}" onclick="selectProfile('{{ p.path }}', '{{ p.tag }}', this)">
                                    <div class="picker-item-head"><span>{{ p.path }}</span><span class="picker-item-tag">{{ p.tag }}</span></div>
                                    <div class="picker-item-desc">{{ p.desc }}</div>
                                </div>
                                {% endfor %}
                            </div>
                        </div>
                    </div>
                </div>
                <div><label>Множитель (-m):</label><input type="number" id="mult" value="500"></div>
                <div><label>Длительность (-d):</label><input type="number" id="duration" value="300"></div>
                <div style="display: flex; gap: 8px;">
                    <button id="toggle-run-btn" onclick="toggleTraffic()" class="btn-apple btn-toggle-start" style="flex:1;">▶ Запустить генерацию</button>
                    <button id="arp-btn" onclick="resolveArp()" class="btn-apple btn-ghost" title="Разрешить ARP шлюзов стенда">🔄 ARP</button>
                </div>
            </div>

            <div style="display:flex; align-items:center; justify-content:space-between; margin-top: 14px; padding-top: 12px; border-top: 1px solid rgba(255,255,255,0.07); flex-wrap:wrap; gap:10px;">
                <div style="display:flex; align-items:center; gap:8px;">
                    <span style="font-size:0.78rem; color:var(--text-muted); font-weight:600;">⚡ Нагрузка на лету:</span>
                    <button class="chip" onclick="liveUpdate(10)">x10</button>
                    <button class="chip" onclick="liveUpdate(100)">x100</button>
                    <button class="chip" onclick="liveUpdate(500)">x500</button>
                    <button class="chip" onclick="liveUpdate(1000)">x1000</button>
                    <button class="chip" onclick="liveUpdate(2500)">x2500</button>
                    <button class="chip" onclick="liveUpdate(5000)">x5000</button>
                </div>
                <div style="font-size:0.8rem; color:var(--text-muted);">
                    Пик текущей сессии: <strong id="peak-mbps" style="color:var(--accent-green)">0.00 Mbps</strong> &nbsp;|&nbsp; <strong id="peak-cps" style="color:var(--accent-blue)">0.0 cps</strong>
                </div>
            </div>
        </div>
    </div>

    <!-- ВКЛАДКА 2: ПРОВЕРКА DPI / ПРИЛОЖЕНИЙ -->
    <div id="tab-dpi" class="tab-pane">
        <div class="glass-card ai-glow-border" style="margin-bottom: 16px;">
            <h4 style="margin-bottom: 6px; font-size:1rem;">🕵️‍♂️ Конструктор проверки блокировки приложений (DPI)</h4>
            <p style="font-size:0.82rem; color:var(--text-muted); margin-bottom:14px;">Генерация синтетических L7-сессий для проверки сигнатурного анализа и фильтрации доменов на NGFW.</p>
            <div style="display: grid; grid-template-columns: 1.6fr 1.2fr 0.7fr 1.5fr; gap: 14px; align-items: end;">
                <div>
                    <label>Домен (введите вручную или выберите из списка):</label>
                    <div class="combo-container" id="dpi-combo-picker">
                        <input type="text" id="dpi-domain" class="combo-input" value="vk.com" placeholder="Например: vk.com, whatsapp.com..." autocomplete="off" onfocus="togglePicker('dpi-dropdown', null, null, true)" oninput="filterDpiCombo()">
                        <span class="combo-arrow" onclick="togglePicker('dpi-dropdown', null, null, true)">▼</span>
                        <div class="picker-dropdown" id="dpi-dropdown">
                            <div class="picker-list">
                                <div class="picker-item dpi-item" onclick="setDpiCombo('vk.com')"><div class="picker-item-head">ВКонтакте (vk.com)</div></div>
                                <div class="picker-item dpi-item" onclick="setDpiCombo('web.whatsapp.com')"><div class="picker-item-head">WhatsApp (Мессенджер)</div></div>
                                <div class="picker-item dpi-item" onclick="setDpiCombo('web.telegram.org')"><div class="picker-item-head">Telegram (Мессенджер)</div></div>
                                <div class="picker-item dpi-item" onclick="setDpiCombo('discord.com')"><div class="picker-item-head">Discord</div></div>
                                <div class="picker-item dpi-item" onclick="setDpiCombo('youtube.com')"><div class="picker-item-head">YouTube (Видеохостинг)</div></div>
                                <div class="picker-item dpi-item" onclick="setDpiCombo('tiktok.com')"><div class="picker-item-head">TikTok (Соцсети)</div></div>
                                <div class="picker-item dpi-item" onclick="setDpiCombo('rutracker.org')"><div class="picker-item-head">RuTracker (Торренты)</div></div>
                                <div class="picker-item dpi-item" onclick="setDpiCombo('pornhub.com')"><div class="picker-item-head">Pornhub (Adult)</div></div>
                                <div class="picker-item dpi-item" onclick="setDpiCombo('chatgpt.com')"><div class="picker-item-head">ChatGPT (ИИ)</div></div>
                                <div class="picker-item dpi-item" onclick="setDpiCombo('ya.ru')"><div class="picker-item-head">Яндекс (Разрешенный эталон)</div></div>
                            </div>
                        </div>
                    </div>
                </div>
                <div>
                    <label>Инкапсуляция:</label>
                    <select id="dpi-proto">
                        <option value="tls">🔒 HTTPS TLS 1.2 (SNI 443)</option>
                        <option value="http">🌐 HTTP/1.1 (Host 80)</option>
                    </select>
                </div>
                <div><label>Множитель:</label><input type="number" id="dpi-mult" value="25"></div>
                <div><button id="dpi-toggle-btn" onclick="toggleDpiTraffic()" class="btn-apple btn-ai" style="width:100%;">▶ Запустить проверку DPI</button></div>
            </div>

            <div style="display:flex; align-items:center; gap:8px; margin-top: 14px; flex-wrap:wrap;">
                <span style="font-size:0.76rem; color:var(--text-muted); font-weight:600;">Быстрый выбор:</span>
                <span class="chip" onclick="setDpiCombo('vk.com')">VK (vk.com)</span>
                <span class="chip" onclick="setDpiCombo('web.telegram.org')">Telegram</span>
                <span class="chip" onclick="setDpiCombo('youtube.com')">YouTube</span>
                <span class="chip" onclick="setDpiCombo('rutracker.org')">RuTracker</span>
                <span class="chip" onclick="setDpiCombo('chatgpt.com')">ChatGPT</span>
                <span class="chip" onclick="setDpiCombo('ya.ru')">Яндекс (Эталон)</span>
            </div>
        </div>
    </div>

    <!-- ВКЛАДКА 3: ЖУРНАЛ ПМИ -->
    <div id="tab-reports" class="tab-pane">
        <div class="glass-card ai-glow-border" style="margin-bottom: 16px;">
            <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom: 14px; flex-wrap:wrap; gap:10px;">
                <div>
                    <h4 style="font-size:1.05rem;">📑 Журнал протоколов испытаний (ПМИ)</h4>
                    <p style="font-size:0.8rem; color:var(--text-muted); margin-top:2px;">Архив зафиксированных тестов с вердиктами NGFW и возможностью экспорта</p>
                </div>
                <div style="display:flex; gap:8px;">
                    <button class="btn-apple btn-ai" onclick="window.location.href='/api/export_report'">📥 Скачать текущий отчет (.md)</button>
                    <button class="btn-apple btn-red" onclick="clearReportsHistory()">🗑️ Очистить журнал</button>
                </div>
            </div>
            <table>
                <thead>
                    <tr>
                        <th>Время</th>
                        <th>Сценарий / Профиль</th>
                        <th>TX / RX Пик</th>
                        <th>Вердикт DPI/NGFW</th>
                        <th>Действие</th>
                    </tr>
                </thead>
                <tbody id="reports-table-body"></tbody>
            </table>
        </div>
    </div>

    <!-- ВКЛАДКА 4: СЕТЬ СТЕНДА -->
    <div id="tab-net" class="tab-pane">
        <div class="glass-card" style="margin-bottom: 16px;">
            <h4 style="margin-bottom: 4px; font-size:1.05rem;">⚙️ Конфигурация интерфейсов TRex (/etc/trex_cfg.yaml)</h4>
            <p style="font-size:0.8rem; color:var(--text-muted); margin-bottom:14px;">Настройка IP-адресов клиентского (Port 0) и серверного (Port 1) интерфейсов и шлюзов NGFW</p>
            <div style="display: grid; grid-template-columns: repeat(4, 1fr); gap: 14px; margin-bottom: 16px;">
                <div><label>Port 0 (Клиент) IP:</label><input type="text" id="cfg-p0-ip" value="{{ net_cfg.p0_ip }}"></div>
                <div><label>Port 0 Шлюз NGFW:</label><input type="text" id="cfg-p0-gw" value="{{ net_cfg.p0_gw }}"></div>
                <div><label>Port 1 (Сервер) IP:</label><input type="text" id="cfg-p1-ip" value="{{ net_cfg.p1_ip }}"></div>
                <div><label>Port 1 Шлюз NGFW:</label><input type="text" id="cfg-p1-gw" value="{{ net_cfg.p1_gw }}"></div>
            </div>
            <div style="display:flex; justify-content:space-between; align-items:center;">
                <span id="net-cfg-status" style="font-size:0.85rem; color:var(--accent-blue);"></span>
                <button onclick="saveNetConfig()" class="btn-apple btn-ghost">💾 Сохранить и перезапустить движок TRex</button>
            </div>
        </div>
    </div>

    <!-- ВКЛАДКА 5: УПРАВЛЕНИЕ ПОЛЬЗОВАТЕЛЯМИ ОС -->
    <div id="tab-users" class="tab-pane">
        <div style="display:grid; grid-template-columns: 1fr 1.6fr; gap:16px;">
            <!-- Форма создания пользователя -->
            <div class="glass-card ai-glow-border">
                <h4 style="margin-bottom:6px; font-size:1.05rem;">➕ Создать пользователя ОС</h4>
                <p style="font-size:0.8rem; color:var(--text-muted); margin-bottom:16px;">Новый пользователь сможет входить в веб-интерфейс и по SSH</p>
                <form id="create-user-form" onsubmit="createUser(event)">
                    <div style="margin-bottom:12px;">
                        <label for="new-username">Имя пользователя (логин):</label>
                        <input type="text" id="new-username" placeholder="например: tester" required pattern="^[a-z_][a-z0-9_-]{2,30}$" title="Только латинские буквы в нижнем регистре, цифры, дефис и подчеркивание (3-30 знаков)">
                    </div>
                    <div style="margin-bottom:12px;">
                        <label for="new-password">Пароль:</label>
                        <input type="password" id="new-password" placeholder="минимум 6 символов" required minlength="6">
                    </div>
                    <div style="margin-bottom:14px;">
                        <label for="confirm-password">Подтверждение пароля:</label>
                        <input type="password" id="confirm-password" placeholder="повторите пароль" required minlength="6">
                    </div>
                    <div style="margin-bottom:16px; display:flex; align-items:center; gap:8px;">
                        <input type="checkbox" id="new-is-sudo" style="width:16px; height:16px; accent-color:#9b72cb;">
                        <label for="new-is-sudo" style="margin:0; text-transform:none; font-size:0.85rem; cursor:pointer; color:var(--text-main);">
                            Предоставить права администратора (sudo)
                        </label>
                    </div>
                    <button type="submit" class="btn-apple btn-ai" style="width:100%;">Создать пользователя</button>
                </form>
            </div>

            <!-- Список пользователей ОС -->
            <div class="glass-card">
                <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:14px;">
                    <div>
                        <h4 style="font-size:1.05rem;">👥 Пользователи операционной системы</h4>
                        <p style="font-size:0.8rem; color:var(--text-muted);">Системные учётные записи Linux (PAM)</p>
                    </div>
                    <button onclick="loadUsers()" class="btn-apple btn-ghost" style="padding:5px 12px; font-size:0.78rem;">🔄 Обновить</button>
                </div>
                <table>
                    <thead>
                        <tr>
                            <th>Пользователь</th>
                            <th>UID / GID</th>
                            <th>Права</th>
                            <th>Действия</th>
                        </tr>
                    </thead>
                    <tbody id="users-table-body">
                        <tr><td colspan="4" style="text-align:center; color:var(--text-muted); padding:16px;">Загрузка пользователей...</td></tr>
                    </tbody>
                </table>
            </div>
        </div>
    </div>

    <!-- МЕТРИКИ РЕАЛЬНОГО ВРЕМЕНИ -->
    <div class="grid-6">
        <div class="glass-card"><label>Отправка (TX)</label><div id="tx-bps" class="metric-val" style="color:var(--accent-blue)">0.00 Mbps</div></div>
        <div class="glass-card"><label>Прием (RX)</label><div id="rx-bps" class="metric-val" style="color:var(--accent-green)">0.00 Mbps</div></div>
        <div class="glass-card"><label>Скорость PPS</label><div id="pps" class="metric-val">0.00 Kpps</div></div>
        <div class="glass-card"><label>Новых сессий (CPS)</label><div id="cps" class="metric-val" style="color:var(--accent-teal)">0.0 cps</div></div>
        <div class="glass-card"><label>Активные потоки</label><div id="flows" class="metric-val" style="color:var(--accent-orange)">0</div></div>
        <div class="glass-card"><label>Сбросы (Drops)</label><div id="drops" class="metric-val" style="color:var(--accent-red)">0</div></div>
    </div>

    <!-- РАСШИРЕННАЯ ТЕЛЕМЕТРИЯ TCP/L7 -->
    <div class="grid-4">
        <div class="glass-card" style="padding:12px 18px;"><label>Попыток соединений (SYN)</label><div id="tcp-att" style="font-size:1.25rem; font-weight:700; color:var(--accent-teal);">0</div></div>
        <div class="glass-card" style="padding:12px 18px;"><label>Успешно установлено (SYN-ACK)</label><div id="tcp-conn" style="font-size:1.25rem; font-weight:700; color:var(--accent-green);">0</div></div>
        <div class="glass-card" style="padding:12px 18px;"><label>Суммарный объем L7 (TX / RX)</label><div id="total-bytes" style="font-size:1.25rem; font-weight:700; color:var(--accent-purple);">0 / 0 MB</div></div>
        <div class="glass-card" style="padding:12px 18px;"><label>Перегрузка очередей (Queue Full)</label><div id="q-drops" style="font-size:1.25rem; font-weight:700; color:var(--accent-red);">0</div></div>

        <div class="glass-card" style="padding:12px 18px;"><label>Корректно закрыто (FIN)</label><div id="tcp-closed" style="font-size:1.25rem; font-weight:700; color:var(--text-muted);">0</div></div>
        <div class="glass-card" style="padding:12px 18px;"><label>Заблокировано NGFW (RST / Drop)</label><div id="tcp-drops" style="font-size:1.25rem; font-weight:700; color:var(--accent-red);">0</div></div>
        <div class="glass-card" style="padding:12px 18px;"><label>Таймауты / Retransmits</label><div id="tcp-rexmt" style="font-size:1.25rem; font-weight:700; color:var(--accent-orange);">0</div></div>
        <div class="glass-card" style="padding:12px 18px;"><label>Ошибки интерфейсов L2 (NIC Errors)</label><div id="nic-err" style="font-size:1.25rem; font-weight:700;">0</div></div>
    </div>

    <!-- ГРАФИКИ И СТАТИСТИКА ПОРТОВ L2 -->
    <div class="grid-charts">
        <div class="glass-card"><label>Пропускная способность L7 (Мбит/с)</label><div style="height:140px; position:relative;"><canvas id="bwChart"></canvas></div></div>
        <div class="glass-card"><label>Установка сессий (CPS)</label><div style="height:140px; position:relative;"><canvas id="cpsChart"></canvas></div></div>
        <div class="glass-card">
            <label>Порты L2 (TX / RX)</label>
            <table style="margin-top:4px;">
                <thead>
                    <tr><th>Параметр</th><th>Port 0 (Клиент)</th><th>Port 1 (Сервер)</th></tr>
                </thead>
                <tbody>
                    <tr><td>Скорость</td><td id="p0-tx">0 / 0</td><td id="p1-tx">0 / 0</td></tr>
                    <tr><td>Пакеты</td><td id="p0-pkts">0 / 0</td><td id="p1-pkts">0 / 0</td></tr>
                </tbody>
            </table>
        </div>
    </div>

    <script>
    let trafficActive = false;

    // Часы в реальном времени
    setInterval(() => {
        const d = new Date();
        document.getElementById('sys-clock').innerText = d.toLocaleTimeString('ru-RU');
    }, 1000);

    function showToast(type, text) {
        const box = document.getElementById('toast-box');
        const t = document.createElement('div');
        t.className = 'toast ' + (type === 'success' ? 'toast-success' : 'toast-error');
        t.innerHTML = `<span>${type === 'success' ? '✅' : '⚠️'}</span><span>${text}</span>`;
        box.appendChild(t);
        setTimeout(() => {
            t.style.opacity = '0';
            t.style.transition = 'opacity 0.3s ease';
            setTimeout(() => t.remove(), 300);
        }, 4000);
    }

    function switchTab(tabId, btn) {
        document.querySelectorAll('.tab-pane').forEach(el => el.classList.remove('active'));
        document.querySelectorAll('.seg-btn').forEach(el => el.classList.remove('active'));
        document.getElementById(tabId).classList.add('active');
        btn.classList.add('active');
    }

    function togglePicker(dd_id, tr_id, search_id, force_open=false) {
        const dd = document.getElementById(dd_id);
        if(tr_id) document.getElementById(tr_id).classList.toggle('open');
        if (force_open) dd.classList.add('open'); else dd.classList.toggle('open');
        if (search_id && dd.classList.contains('open')) document.getElementById(search_id).focus();
    }

    function filterProfiles(search_id, item_class) {
        const q = document.getElementById(search_id).value.toLowerCase();
        document.querySelectorAll('.' + item_class).forEach(item => {
            item.style.display = item.innerText.toLowerCase().includes(q) ? 'block' : 'none';
        });
    }

    function filterDpiCombo() {
        const q = document.getElementById('dpi-domain').value.toLowerCase();
        document.querySelectorAll('.dpi-item').forEach(item => {
            item.style.display = item.innerText.toLowerCase().includes(q) ? 'block' : 'none';
        });
    }

    function selectProfile(path, tag, el) {
        document.getElementById('profile').value = path;
        document.getElementById('picker-selected-text').innerText = path + ' — ' + tag;
        document.querySelectorAll('.picker-item').forEach(i => i.classList.remove('selected'));
        el.classList.add('selected');
        document.getElementById('picker-dropdown').classList.remove('open');
        document.getElementById('picker-trigger').classList.remove('open');
    }

    function setDpiCombo(dom) {
        document.getElementById('dpi-domain').value = dom;
        document.getElementById('dpi-dropdown').classList.remove('open');
    }

    document.addEventListener('click', function(e) {
        const pp = document.getElementById('profile-picker');
        if (pp && !pp.contains(e.target)) {
            document.getElementById('picker-dropdown').classList.remove('open');
            document.getElementById('picker-trigger').classList.remove('open');
        }
        const dp = document.getElementById('dpi-combo-picker');
        if (dp && !dp.contains(e.target)) {
            document.getElementById('dpi-dropdown').classList.remove('open');
        }
    });

    function updateRunButtons(active) {
        trafficActive = active;
        const bm = document.getElementById('toggle-run-btn'), bd = document.getElementById('dpi-toggle-btn');
        if (active) {
            bm.className = 'btn-apple btn-toggle-stop'; bm.innerText = '⏹ Остановить поток (Активен)';
            bd.className = 'btn-apple btn-toggle-stop'; bd.innerText = '⏹ Остановить проверку DPI';
        } else {
            bm.className = 'btn-apple btn-toggle-start'; bm.innerText = '▶ Запустить генерацию';
            bd.className = 'btn-apple btn-ai'; bd.innerText = '▶ Запустить проверку DPI';
        }
    }

    async function toggleTraffic() { trafficActive ? await stopTest() : await startTest(); }
    async function toggleDpiTraffic() { trafficActive ? await stopTest() : await runDpiTest(); }

    const chartOpts = {
        responsive: true,
        maintainAspectRatio: false,
        animation: false,
        elements: { point: { radius: 0 } },
        plugins: { legend: { display: false }, tooltip: { enabled: true } },
        scales: {
            x: { display: false },
            y: { grid: { color: 'rgba(255,255,255,0.06)' }, ticks: { color: '#8e8e93', font: { size: 10 } } }
        }
    };

    const bwChart = new Chart(document.getElementById('bwChart').getContext('2d'), {
        type: 'line',
        data: {
            labels: [],
            datasets: [
                { label: 'TX (Mbps)', borderColor: '#2997ff', backgroundColor: 'rgba(41,151,255,0.12)', borderWidth: 1.8, tension: 0.35, fill: true, data: [] },
                { label: 'RX (Mbps)', borderColor: '#30d158', backgroundColor: 'rgba(48,209,88,0.12)', borderWidth: 1.8, tension: 0.35, fill: true, data: [] }
            ]
        },
        options: chartOpts
    });

    const cpsChart = new Chart(document.getElementById('cpsChart').getContext('2d'), {
        type: 'line',
        data: {
            labels: [],
            datasets: [
                { label: 'CPS', borderColor: '#bf5af2', backgroundColor: 'rgba(191,90,242,0.14)', borderWidth: 1.8, tension: 0.35, fill: true, data: [] }
            ]
        },
        options: chartOpts
    });

    function fmtBytes(b) { return (b / 1048576).toFixed(1); }

    async function dismissVerdict() {
        await fetch('/api/dismiss_verdict', {
            method: 'POST',
            headers: {'X-Requested-With': 'XMLHttpRequest'}
        });
        const vb = document.getElementById('verdict-box');
        const vt = document.getElementById('verdict-title');
        const db = document.getElementById('dismiss-verdict-btn');
        vb.style.borderColor = 'rgba(255,255,255,0.12)';
        vb.style.background = 'rgba(255,255,255,0.04)';
        vt.innerHTML = '✦ Система готова к проведению испытаний';
        if (db) db.style.display = 'none';
    }

    async function updateStats() {
        try {
            const res = await fetch('/api/stats');
            if (res.status === 401) {
                window.location.href = '/login';
                return;
            }
            const d = await res.json();

            if (d.health) {
                document.getElementById('sys-load').innerText = d.health.load;
                document.getElementById('sys-ram-txt').innerText = d.health.ram_pct.toFixed(1) + '%';
                document.getElementById('sys-ram-bar').style.width = d.health.ram_pct + '%';
                document.getElementById('sys-disk-txt').innerText = d.health.disk_pct.toFixed(1) + '%';
                document.getElementById('sys-disk-bar').style.width = d.health.disk_pct + '%';
            }

            const pill = document.getElementById('engine-pill');
            if (!d.connected) {
                pill.style.background = 'rgba(255, 69, 58, 0.16)';
                pill.style.color = '#ff453a';
                pill.style.borderColor = 'rgba(255, 69, 58, 0.35)';
                document.getElementById('engine-dot').style.background = '#ff453a';
                document.getElementById('engine-dot').style.boxShadow = '0 0 10px #ff453a';
                document.getElementById('engine-text').innerText = 'Движок выключен';
                return;
            }
            pill.style.background = 'rgba(48, 209, 88, 0.14)';
            pill.style.color = '#30d158';
            pill.style.borderColor = 'rgba(48, 209, 88, 0.35)';
            document.getElementById('engine-dot').style.background = '#30d158';
            document.getElementById('engine-dot').style.boxShadow = '0 0 10px #30d158';
            document.getElementById('engine-text').innerText = 'Активен (CPU: ' + (d.cpu ? d.cpu.toFixed(1) : '0.0') + '%)';

            updateRunButtons(d.is_running);

            document.getElementById('tx-bps').innerText = (d.tx_bps / 1e6).toFixed(2) + ' Mbps';
            document.getElementById('rx-bps').innerText = (d.rx_bps / 1e6).toFixed(2) + ' Mbps';
            document.getElementById('pps').innerText = (d.total_pps / 1e3).toFixed(2) + ' Kpps';
            document.getElementById('cps').innerText = d.cps.toFixed(1) + ' cps';
            document.getElementById('flows').innerText = d.active_flows;
            document.getElementById('drops').innerText = d.tcp_drops;

            document.getElementById('tcp-att').innerText = d.tcp_attempts;
            document.getElementById('tcp-closed').innerText = d.tcp_closed;
            document.getElementById('total-bytes').innerText = fmtBytes(d.total_tx_b) + ' / ' + fmtBytes(d.total_rx_b) + ' MB';
            document.getElementById('q-drops').innerText = d.queue_full;

            document.getElementById('tcp-conn').innerText = d.tcp_connects;
            document.getElementById('tcp-drops').innerText = d.tcp_drops;
            document.getElementById('tcp-rexmt').innerText = d.tcp_rexmt;
            document.getElementById('nic-err').innerText = d.nic_errors;

            document.getElementById('peak-mbps').innerText = d.peak.max_rx_mbps.toFixed(2) + ' Mbps';
            document.getElementById('peak-cps').innerText = d.peak.max_cps.toFixed(1) + ' cps';

            if (d.p0 && d.p1) {
                document.getElementById('p0-tx').innerText = (d.p0.tx_bps / 1e6).toFixed(1) + ' / ' + (d.p0.rx_bps / 1e6).toFixed(1) + ' Mbps';
                document.getElementById('p1-tx').innerText = (d.p1.tx_bps / 1e6).toFixed(1) + ' / ' + (d.p1.rx_bps / 1e6).toFixed(1) + ' Mbps';
                document.getElementById('p0-pkts').innerText = (d.p0.opackets || 0) + ' / ' + (d.p0.ipackets || 0);
                document.getElementById('p1-pkts').innerText = (d.p1.opackets || 0) + ' / ' + (d.p1.ipackets || 0);
            }

            const vb = document.getElementById('verdict-box');
            const vt = document.getElementById('verdict-title');
            const db = document.getElementById('dismiss-verdict-btn');

            if (d.verdict_code === 'BLOCKED') {
                vb.style.borderColor = '#ff453a';
                vb.style.background = 'rgba(255, 69, 58, 0.18)';
                vt.innerHTML = '🛡️ <strong>' + d.verdict_title + '</strong>';
                if (db) db.style.display = 'inline-block';
            } else if (d.verdict_code === 'PASSED') {
                vb.style.borderColor = '#30d158';
                vb.style.background = 'rgba(48, 209, 88, 0.12)';
                vt.innerHTML = '🟢 <strong>' + d.verdict_title + '</strong>';
                if (db) db.style.display = 'inline-block';
            } else if (d.verdict_code === 'TESTING') {
                vb.style.borderColor = '#2997ff';
                vb.style.background = 'rgba(41, 151, 255, 0.14)';
                vt.innerHTML = '⚡ <strong>' + d.verdict_title + '</strong>';
                if (db) db.style.display = 'none';
            } else {
                vb.style.borderColor = 'rgba(255,255,255,0.12)';
                vb.style.background = 'rgba(255,255,255,0.04)';
                vt.innerHTML = '✦ Система готова к проведению испытаний';
                if (db) db.style.display = 'none';
            }

            if (bwChart.data.labels.length > 25) {
                bwChart.data.labels.shift();
                bwChart.data.datasets[0].data.shift();
                bwChart.data.datasets[1].data.shift();
                cpsChart.data.labels.shift();
                cpsChart.data.datasets[0].data.shift();
            }
            bwChart.data.labels.push('');
            bwChart.data.datasets[0].data.push(Number((d.tx_bps / 1e6).toFixed(2)));
            bwChart.data.datasets[1].data.push(Number((d.rx_bps / 1e6).toFixed(2)));
            bwChart.update('none');

            cpsChart.data.labels.push('');
            cpsChart.data.datasets[0].data.push(Number(d.cps.toFixed(1)));
            cpsChart.update('none');
        } catch (e) {}
    }

    async function startTest() {
        try {
            const res = await fetch('/api/start', {
                method: 'POST',
                headers: {'Content-Type': 'application/json', 'X-Requested-With': 'XMLHttpRequest'},
                body: JSON.stringify({
                    profile: document.getElementById('profile').value,
                    mult: document.getElementById('mult').value,
                    duration: document.getElementById('duration').value
                })
            });
            const d = await res.json();
            if (d.status !== 'ok') showToast('error', d.message || 'Ошибка запуска теста');
        } catch (e) {
            showToast('error', 'Сетевая ошибка при запуске');
        }
    }

    async function runDpiTest() {
        try {
            const res = await fetch('/api/dpi_test', {
                method: 'POST',
                headers: {'Content-Type': 'application/json', 'X-Requested-With': 'XMLHttpRequest'},
                body: JSON.stringify({
                    domain: document.getElementById('dpi-domain').value,
                    proto: document.getElementById('dpi-proto').value,
                    mult: document.getElementById('dpi-mult').value
                })
            });
            const d = await res.json();
            if (d.status !== 'ok') showToast('error', d.message || 'Ошибка запуска DPI теста');
        } catch (e) {
            showToast('error', 'Сетевая ошибка при запуске DPI');
        }
    }

    async function stopTest() {
        try {
            await fetch('/api/stop', {
                method: 'POST',
                headers: {'X-Requested-With': 'XMLHttpRequest'}
            });
            loadReportsHistory();
        } catch (e) {}
    }

    async function liveUpdate(m) {
        document.getElementById('mult').value = m;
        await fetch('/api/update', {
            method: 'POST',
            headers: {'Content-Type': 'application/json', 'X-Requested-With': 'XMLHttpRequest'},
            body: JSON.stringify({mult: m})
        });
    }

    async function resolveArp() {
        const btn = document.getElementById('arp-btn');
        const orig = btn.innerText;
        btn.innerText = '🔄 Разрешение...';
        btn.disabled = true;
        try {
            const res = await fetch('/api/arp', {
                method: 'POST',
                headers: {'Content-Type': 'application/json', 'X-Requested-With': 'XMLHttpRequest'}
            });
            const d = await res.json();
            if (d.status === 'ok') {
                showToast('success', d.message);
                btn.innerText = '✅ ARP OK';
            } else {
                showToast('error', d.message || 'Ошибка разрешения ARP');
                btn.innerText = '⚠️ Ошибка ARP';
            }
        } catch (e) {
            showToast('error', 'Сетевая ошибка при запросе ARP');
            btn.innerText = '⚠️ Ошибка';
        }
        setTimeout(() => {
            btn.innerText = orig;
            btn.disabled = false;
        }, 3000);
    }

    async function clearReportsHistory() {
        if (confirm('Вы действительно хотите очистить журнал протоколов испытаний?')) {
            await fetch('/api/clear_history', {
                method: 'POST',
                headers: {'X-Requested-With': 'XMLHttpRequest'}
            });
            loadReportsHistory();
            showToast('success', 'Журнал протоколов очищен');
        }
    }

    async function saveNetConfig() {
        const stat = document.getElementById('net-cfg-status');
        stat.innerText = 'Сохранение и перезапуск...';
        try {
            const res = await fetch('/api/net_config', {
                method: 'POST',
                headers: {'Content-Type': 'application/json', 'X-Requested-With': 'XMLHttpRequest'},
                body: JSON.stringify({
                    p0_ip: document.getElementById('cfg-p0-ip').value,
                    p0_gw: document.getElementById('cfg-p0-gw').value,
                    p1_ip: document.getElementById('cfg-p1-ip').value,
                    p1_gw: document.getElementById('cfg-p1-gw').value
                })
            });
            const d = await res.json();
            if (d.status === 'ok') {
                stat.innerText = d.message || 'Конфигурация сохранена!';
                showToast('success', d.message || 'Служба TRex перезапускается');
            } else {
                stat.innerText = d.message || 'Ошибка сохранения';
                showToast('error', d.message || 'Ошибка сохранения конфигурации');
            }
        } catch (e) {
            stat.innerText = 'Ошибка запроса';
            showToast('error', 'Сетевая ошибка сохранения сети');
        }
        setTimeout(() => { stat.innerText = ''; }, 6000);
    }

    async function saveCurrentReport() {
        await fetch('/api/save_report', {
            method: 'POST',
            headers: {'X-Requested-With': 'XMLHttpRequest'}
        });
        loadReportsHistory();
        showToast('success', 'Текущее испытание сохранено в журнал');
    }

    async function loadReportsHistory() {
        const res = await fetch('/api/reports');
        if (res.status === 401) return;
        const list = await res.json();
        const tb = document.getElementById('reports-table-body');
        if (!list || !list.length) {
            tb.innerHTML = '<tr><td colspan="5" style="color:var(--text-muted); text-align:center; padding:18px;">Журнал испытаний пуст.</td></tr>';
            return;
        }
        tb.innerHTML = list.map(r => `<tr>
            <td style="padding:10px;"><strong>${r.end_time.split(' ')[1] || ''}</strong><br><span style="font-size:0.75rem;color:var(--text-muted);">${r.end_time.split(' ')[0] || ''}</span></td>
            <td style="padding:10px;"><strong>${r.active_profile}</strong></td>
            <td style="padding:10px;">TX: ${(r.max_tx_mbps || 0).toFixed(1)} Mbps<br>RX: ${(r.max_rx_mbps || 0).toFixed(1)} Mbps</td>
            <td style="padding:10px; font-weight:bold; color:${(r.verdict || '').includes('ЗАБЛОК') ? '#ff453a' : '#30d158'}">${r.verdict || 'Н/Д'}</td>
            <td style="padding:10px;"><button class="btn-apple btn-ghost" style="padding:4px 10px; font-size:0.75rem;" onclick="window.location.href='/api/export_report?id=${r.id}'">📥 Скачать</button></td>
        </tr>`).join('');
    }

    // --- ФУНКЦИИ УПРАВЛЕНИЯ ПОЛЬЗОВАТЕЛЯМИ ОС ---
    async function loadUsers() {
        const tb = document.getElementById('users-table-body');
        try {
            const res = await fetch('/api/users');
            if (res.status === 401) { window.location.href = '/login'; return; }
            const users = await res.json();
            if (!users || !users.length) {
                tb.innerHTML = '<tr><td colspan="4" style="text-align:center; color:var(--text-muted); padding:16px;">Пользователи не найдены.</td></tr>';
                return;
            }
            tb.innerHTML = users.map(u => `<tr>
                <td style="padding:10px;">
                    <strong>👤 ${u.username}</strong>
                    ${u.is_current ? '<span style="font-size:0.7rem; margin-left:6px; background:rgba(41,151,255,0.2); color:var(--accent-blue); padding:2px 6px; border-radius:6px;">Вы</span>' : ''}
                </td>
                <td style="padding:10px; color:var(--text-muted);">${u.uid} / ${u.gid}</td>
                <td style="padding:10px;">
                    ${u.is_sudo ? '<span style="background:rgba(191,90,242,0.18); color:var(--accent-purple); font-size:0.72rem; padding:3px 8px; border-radius:999px; font-weight:600;">sudo / root</span>' : '<span style="color:var(--text-muted); font-size:0.8rem;">Пользователь</span>'}
                </td>
                <td style="padding:10px;">
                    <div style="display:flex; gap:6px;">
                        <button class="btn-apple btn-ghost" style="padding:3px 8px; font-size:0.75rem;" onclick="promptChangePassword('${u.username}')" title="Сменить пароль">🔑 Пароль</button>
                        ${(!u.is_root && !u.is_current) ? `<button class="btn-apple btn-red" style="padding:3px 8px; font-size:0.75rem;" onclick="deleteUser('${u.username}')" title="Удалить аккаунт">🗑️</button>` : ''}
                    </div>
                </td>
            </tr>`).join('');
        } catch (e) {
            tb.innerHTML = '<tr><td colspan="4" style="text-align:center; color:#ff6961; padding:16px;">Ошибка загрузки пользователей</td></tr>';
        }
    }

    async function createUser(e) {
        e.preventDefault();
        const username = document.getElementById('new-username').value.trim();
        const password = document.getElementById('new-password').value;
        const confirmPw = document.getElementById('confirm-password').value;
        const isSudo = document.getElementById('new-is-sudo').checked;

        if (password !== confirmPw) {
            showToast('error', 'Пароли не совпадают!');
            return;
        }

        try {
            const res = await fetch('/api/users/create', {
                method: 'POST',
                headers: {'Content-Type': 'application/json', 'X-Requested-With': 'XMLHttpRequest'},
                body: JSON.stringify({username, password, is_sudo: isSudo})
            });
            const d = await res.json();
            if (d.status === 'ok') {
                showToast('success', d.message || `Пользователь ${username} успешно создан!`);
                document.getElementById('create-user-form').reset();
                loadUsers();
            } else {
                showToast('error', d.message || 'Ошибка создания пользователя');
            }
        } catch (err) {
            showToast('error', 'Сетевая ошибка при создании пользователя');
        }
    }

    async function promptChangePassword(username) {
        const newPw = prompt(`Введите новый пароль для пользователя ${username} (минимум 6 символов):`);
        if (!newPw) return;
        if (newPw.length < 6) {
            showToast('error', 'Пароль должен содержать минимум 6 символов');
            return;
        }

        try {
            const res = await fetch('/api/users/change_password', {
                method: 'POST',
                headers: {'Content-Type': 'application/json', 'X-Requested-With': 'XMLHttpRequest'},
                body: JSON.stringify({username, password: newPw})
            });
            const d = await res.json();
            if (d.status === 'ok') {
                showToast('success', `Пароль для ${username} успешно изменен!`);
            } else {
                showToast('error', d.message || 'Ошибка изменения пароля');
            }
        } catch (e) {
            showToast('error', 'Сетевая ошибка при изменении пароля');
        }
    }

    async function deleteUser(username) {
        if (!confirm(`Вы действительно хотите удалить пользователя ОС "${username}" и его домашнюю директорию?`)) {
            return;
        }

        try {
            const res = await fetch('/api/users/delete', {
                method: 'POST',
                headers: {'Content-Type': 'application/json', 'X-Requested-With': 'XMLHttpRequest'},
                body: JSON.stringify({username})
            });
            const d = await res.json();
            if (d.status === 'ok') {
                showToast('success', `Пользователь ${username} успешно удален`);
                loadUsers();
            } else {
                showToast('error', d.message || 'Ошибка удаления пользователя');
            }
        } catch (e) {
            showToast('error', 'Сетевая ошибка при удалении пользователя');
        }
    }

    setInterval(updateStats, 1000);
    loadReportsHistory();
    </script>
</body>
</html>
"""

# --- ROUTES ---

@app.route('/login', methods=['GET', 'POST'])
def login():
    client_ip = request.remote_addr or 'unknown'
    allowed, wait_sec = check_login_rate_limit(client_ip)
    if not allowed:
        return render_template_string(
            LOGIN_PAGE,
            error=f"Слишком много неудачных попыток входа. Повторите через {wait_sec} сек.",
            next_url=request.args.get('next', '/')
        ), 429

    if request.method == 'GET':
        if 'user' in session:
            return redirect(url_for('index'))
        return render_template_string(LOGIN_PAGE, error=None, next_url=request.args.get('next', '/'))

    username = request.form.get('username', '').strip()
    password = request.form.get('password', '')
    next_url = request.form.get('next', '/')

    if authenticate_os_user(username, password):
        clear_failed_login(client_ip)
        session.permanent = True
        session['user'] = username
        return redirect(next_url or url_for('index'))
    else:
        record_failed_login(client_ip)
        return render_template_string(
            LOGIN_PAGE,
            error='Неверное имя пользователя или пароль ОС',
            next_url=next_url
        ), 401

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/')
@login_required
def index():
    profiles = [{'path': r, 'tag': describe_profile(r)[0], 'desc': describe_profile(r)[1]}
                for r in ['astf/http_simple.py', 'astf/sfr.py', 'astf/http_https.py', 'astf/emix2.py']]
    return render_template_string(HTML_PAGE, profiles=profiles, net_cfg=read_net_cfg())

@app.route('/api/stats')
@login_required
def stats():
    global client, current_session, is_running_flag, _stats_cache, _stats_cache_time, last_test_end_time, verdict_dismissed
    now = time.time()
    health = get_sys_health()

    # Fast cache (500 ms)
    if now - _stats_cache_time < 0.5 and _stats_cache:
        cached = dict(_stats_cache)
        cached['health'] = health
        return jsonify(cached)

    with lock:
        try:
            c = get_client()
            s = c.get_stats()
            g = s.get('global', {})
            p0 = s.get(0, {})
            p1 = s.get(1, {})
            tc = s.get('traffic', {}).get('client', {})

            tx_bps = g.get('tx_bps', 0)
            rx_bps = g.get('rx_bps', 0)
            pps = g.get('tx_pps', 0) + g.get('rx_pps', 0)
            cps = g.get('tx_cps', 0)

            # Auto-detect test termination
            if is_running_flag and tx_bps < 100 and cps == 0:
                is_running_flag = False
                last_test_end_time = now
                save_to_history(current_session)

            if rx_bps / 1e6 > current_session['max_rx_mbps']:
                current_session['max_rx_mbps'] = rx_bps / 1e6
            if tx_bps / 1e6 > current_session['max_tx_mbps']:
                current_session['max_tx_mbps'] = tx_bps / 1e6
            if pps / 1e3 > current_session['max_pps']:
                current_session['max_pps'] = pps / 1e3
            if cps > current_session['max_cps']:
                current_session['max_cps'] = cps

            tdrop = tc.get('tcps_drops', 0) + tc.get('tcps_conndrops', 0)
            tconn = tc.get('tcps_connects', 0)

            current_session['tcp_connects'] = tconn
            current_session['tcp_drops'] = tdrop
            current_session['tcp_rexmt'] = tc.get('tcps_rexmttimeo', 0)
            current_session['nic_errors'] = p0.get('ierrors', 0) + p1.get('ierrors', 0)
            current_session['p0_opackets'] = p0.get('opackets', 0)
            current_session['p0_ipackets'] = p0.get('ipackets', 0)
            current_session['p1_opackets'] = p1.get('opackets', 0)
            current_session['p1_ipackets'] = p1.get('ipackets', 0)

            # Verdict Logic: Only show Active or Finished verdict within 12 seconds
            is_active = is_running_flag or tx_bps > 500
            v_code = 'IDLE'
            v_title = '✦ Система готова к проведению испытаний'

            if is_active:
                verdict_dismissed = False
                if tdrop > 5 or tc.get('tcps_rexmttimeo', 0) > 20:
                    v_code = 'BLOCKED'
                    current_session['verdict'] = '🛡️ ЗАБЛОКИРОВАНО (BLOCKED BY DPI)'
                elif tconn > 5 or current_session['max_rx_mbps'] > 0.05:
                    v_code = 'PASSED'
                    current_session['verdict'] = '🟢 ПРОПУЩЕНО (PASSED)'
                else:
                    v_code = 'TESTING'
                    current_session['verdict'] = '⚡ ИДЕТ ТЕСТИРОВАНИЕ...'
                v_title = current_session['verdict']
            else:
                # Test is not active. Show final verdict for 12 seconds, then automatically disappear!
                if not verdict_dismissed and (now - last_test_end_time < 12.0) and current_session.get('verdict') not in ('ГОТОВ К ЗАПУСКУ', ''):
                    if 'ЗАБЛОК' in current_session.get('verdict', ''):
                        v_code = 'BLOCKED'
                    elif 'ПРОПУЩ' in current_session.get('verdict', ''):
                        v_code = 'PASSED'
                    v_title = current_session['verdict'] + " (Тест завершен)"
                else:
                    v_code = 'IDLE'
                    v_title = '✦ Система готова к проведению испытаний'

            payload = {
                'connected': True,
                'is_running': is_active,
                'health': health,
                'cpu': g.get('cpu_util', 0),
                'tx_bps': tx_bps,
                'rx_bps': rx_bps,
                'total_pps': pps,
                'cps': cps,
                'active_flows': tc.get('m_active_flows', 0),
                'tcp_attempts': tc.get('tcps_connattempt', 0),
                'tcp_closed': tc.get('tcps_closed', 0),
                'total_tx_b': g.get('tx_bytes', 0),
                'total_rx_b': g.get('rx_bytes', 0),
                'queue_full': g.get('queue_full', 0),
                'tcp_connects': tconn,
                'tcp_drops': tdrop,
                'tcp_rexmt': tc.get('tcps_rexmttimeo', 0),
                'nic_errors': current_session['nic_errors'],
                'verdict_code': v_code,
                'verdict_title': v_title,
                'verdict_detail': '',
                'peak': current_session,
                'p0': p0,
                'p1': p1
            }
            _stats_cache = payload
            _stats_cache_time = now
            return jsonify(payload)
        except Exception as e:
            return jsonify({'connected': False, 'health': health, 'error': str(e)})

@app.route('/api/dismiss_verdict', methods=['POST'])
@login_required
def dismiss_verdict():
    global verdict_dismissed
    verdict_dismissed = True
    return jsonify({'status': 'ok'})

@app.route('/api/start', methods=['POST'])
@login_required
def start():
    global current_session, is_running_flag, verdict_dismissed
    d = request.json or {}
    prof_path = d.get('profile', 'astf/http_simple.py')
    full_path = os.path.join(TREX_DIR, prof_path)
    if not os.path.isfile(full_path):
        return jsonify({'status': 'error', 'message': 'Указанный профиль не найден'}), 400

    try:
        mult = float(d.get('mult', 100))
        duration = float(d.get('duration', 120))
        if mult <= 0 or duration <= 0:
            return jsonify({'status': 'error', 'message': 'Параметры должны быть положительными числами'}), 400
    except ValueError:
        return jsonify({'status': 'error', 'message': 'Некорректный формат числовых параметров'}), 400

    with lock:
        c = get_client()
        c.acquire(force=True)
        c.stop()
        c.clear_stats()
        current_session = default_session()
        current_session['active_profile'] = prof_path
        c.load_profile(full_path)
        c.start(mult=mult, duration=duration)
        is_running_flag = True
        verdict_dismissed = False
    return jsonify({'status': 'ok'})

@app.route('/api/dpi_test', methods=['POST'])
@login_required
def dpi_test():
    global current_session, is_running_flag, verdict_dismissed
    d = request.json or {}
    domain = d.get('domain', '').strip()
    proto = d.get('proto', 'tls').strip().lower()

    if not domain or not DOMAIN_REGEX.match(domain):
        return jsonify({'status': 'error', 'message': 'Некорректный домен (например: vk.com, web.whatsapp.com)'}), 400
    if proto not in ('tls', 'http'):
        return jsonify({'status': 'error', 'message': 'Недопустимый протокол'}), 400

    try:
        mult = float(d.get('mult', 25))
    except ValueError:
        mult = 25.0

    with lock:
        try:
            prof_rel = generate_dpi_profile(domain, proto)
            c = get_client()
            c.acquire(force=True)
            c.stop()
            c.clear_stats()
            current_session = default_session()
            current_session['active_profile'] = f"{domain} ({proto.upper()})"
            c.load_profile(os.path.join(TREX_DIR, prof_rel))
            c.start(mult=mult, duration=120)
            is_running_flag = True
            verdict_dismissed = False
            return jsonify({'status': 'ok'})
        except Exception as e:
            return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/stop', methods=['POST'])
@login_required
def stop():
    global is_running_flag, current_session, last_test_end_time
    with lock:
        try:
            c = get_client()
            c.acquire(force=True)
            c.stop()
            c.clear_stats()
        except Exception:
            pass
        is_running_flag = False
        last_test_end_time = time.time()
        save_to_history(current_session)
    return jsonify({'status': 'ok'})

@app.route('/api/update', methods=['POST'])
@login_required
def update():
    d = request.json or {}
    try:
        mult = float(d.get('mult', 100))
        with lock:
            get_client().update(mult=mult)
        return jsonify({'status': 'ok'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 400

@app.route('/api/arp', methods=['POST'])
@login_required
def arp():
    with lock:
        try:
            c = get_client()
            c.acquire(force=True)
            c.resolve(retries=2)
            p0_cfg = c.ports[0].get_layer_cfg()
            p1_cfg = c.ports[1].get_layer_cfg()
            p0_mac = p0_cfg.get('ether', {}).get('dst', 'н/д')
            p1_mac = p1_cfg.get('ether', {}).get('dst', 'н/д')
            p0_gw = p0_cfg.get('ipv4', {}).get('dst', '192.168.1.1')
            p1_gw = p1_cfg.get('ipv4', {}).get('dst', '172.10.1.1')
            msg = f"ARP шлюзов разрешен! Port 0 ({p0_gw}) → {p0_mac} | Port 1 ({p1_gw}) → {p1_mac}"
            return jsonify({'status': 'ok', 'message': msg})
        except Exception as e:
            return jsonify({'status': 'error', 'message': f'Ошибка разрешения ARP: {str(e)}'}), 500

@app.route('/api/save_report', methods=['POST'])
@login_required
def save_report_api():
    with lock:
        save_to_history(current_session)
    return jsonify({'status': 'ok'})

@app.route('/api/reports')
@login_required
def reports():
    return jsonify(load_history())

@app.route('/api/clear_history', methods=['POST'])
@login_required
def clear_history():
    with open(HISTORY_FILE, 'w', encoding='utf-8') as f:
        f.write("[]")
    return jsonify({'status': 'ok'})

@app.route('/api/export_report')
@login_required
def export_report():
    report_id = request.args.get('id')
    hist = load_history()
    target = None
    if report_id:
        for r in hist:
            if r.get('id') == report_id:
                target = r
                break
    if not target:
        target = current_session if (current_session.get('max_tx_mbps', 0) > 0 or current_session.get('p0_opackets', 0) > 0) else (hist[0] if hist else current_session)

    md_content = f"""# Протокол испытаний сетевого оборудования (ПМИ)

**Идентификатор испытания:** `{target.get('id', 'N/A')}`  
**Период проведения:** {target.get('start_time', 'N/A')} — {target.get('end_time', 'N/A')}  
**Тестовый сценарий / Профиль:** `{target.get('active_profile', 'N/A')}` ({target.get('profile_tag', '')})  
**Оператор испытаний (ОС):** `{session.get('user', 'os_user')}`  

---

## 1. Параметры тестирования
* **Множитель нагрузки (-m):** {target.get('mult', 100)}
* **Длительность испытания:** {target.get('target_duration', 120)} сек.
* **Описание сценария:** {target.get('profile_desc', 'N/A')}

---

## 2. Ключевые метрики пропускной способности и сессий
| Метрика | Значение |
| :--- | :--- |
| **Пиковая скорость передачи (TX):** | **{target.get('max_tx_mbps', 0):.2f} Mbps** |
| **Пиковая скорость приёма (RX):** | **{target.get('max_rx_mbps', 0):.2f} Mbps** |
| **Пиковый рейт пакетов (PPS):** | **{target.get('max_pps', 0):.2f} Kpps** |
| **Максимум установки сессий (CPS):** | **{target.get('max_cps', 0):.1f} cps** |
| **Успешно установленных соединений:** | {target.get('tcp_connects', 0)} |
| **Сбросов сессий (TCP Drops):** | {target.get('tcp_drops', 0)} |
| **Повторов передачи (Retransmits):** | {target.get('tcp_rexmt', 0)} |
| **Ошибок на интерфейсах L2 (NIC Errors):** | {target.get('nic_errors', 0)} |

---

## 3. Вердикт проверки
> **Результат:** {target.get('verdict', 'НЕ ОПРЕДЕЛЕН')}  
> **Детали:** {target.get('verdict_detail', target.get('verdict', ''))}

---
*Сформировано автоматически: Комплекс тестирования Cisco TRex ASTF Studio*
"""
    filename = f"TRex_Report_{target.get('id', 'latest')}.md"
    return app.response_class(
        md_content,
        mimetype='text/markdown',
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )

@app.route('/api/net_config', methods=['POST'])
@login_required
def net_config():
    global client, is_running_flag
    d = request.json or {}
    p0_ip = d.get('p0_ip', '').strip()
    p0_gw = d.get('p0_gw', '').strip()
    p1_ip = d.get('p1_ip', '').strip()
    p1_gw = d.get('p1_gw', '').strip()

    # Validate IP addresses
    for name, val in [('Port 0 IP', p0_ip), ('Port 0 GW', p0_gw), ('Port 1 IP', p1_ip), ('Port 1 GW', p1_gw)]:
        try:
            ipaddress.IPv4Address(val)
        except ValueError:
            return jsonify({'status': 'error', 'message': f'Некорректный IPv4-адрес для {name}: {val}'}), 400

    cfg_content = f"""- version: 2
  interfaces: ['03:00.0', '0b:00.0']
  port_info:
      - ip: {p0_ip}
        default_gw: {p0_gw}
      - ip: {p1_ip}
        default_gw: {p1_gw}

  platform:
      master_thread_id: 0
      latency_thread_id: 1
      dual_if:
        - socket: 0
          threads: [2, 3]
"""
    with open('/etc/trex_cfg.yaml', 'w', encoding='utf-8') as f:
        f.write(cfg_content)

    client = None
    is_running_flag = False
    subprocess.Popen(['systemctl', 'restart', 'trex-engine.service'])
    return jsonify({'status': 'ok', 'message': 'Конфигурация сохранена! Служба trex-engine перезапускается...'})

# --- ЭНДПОИНТЫ УПРАВЛЕНИЯ ПОЛЬЗОВАТЕЛЯМИ ОС ---

@app.route('/api/users', methods=['GET'])
@login_required
def api_users_list():
    return jsonify(get_os_users())

@app.route('/api/users/create', methods=['POST'])
@login_required
def api_users_create():
    d = request.json or {}
    username = d.get('username', '').strip().lower()
    password = d.get('password', '')
    is_sudo = bool(d.get('is_sudo', False))

    if not USERNAME_REGEX.match(username):
        return jsonify({'status': 'error', 'message': 'Имя пользователя должно содержать от 3 до 30 латинских букв в нижнем регистре, цифр, дефисов'}), 400

    if len(password) < 6:
        return jsonify({'status': 'error', 'message': 'Пароль должен содержать не менее 6 символов'}), 400

    # Check if user already exists
    try:
        pwd.getpwnam(username)
        return jsonify({'status': 'error', 'message': f'Пользователь "{username}" уже существует в ОС'}), 400
    except KeyError:
        pass

    try:
        # Create user with bash shell and home dir
        subprocess.run(['useradd', '-m', '-s', '/bin/bash', username], check=True)

        # Set password securely via pipe to chpasswd
        p = subprocess.Popen(['chpasswd'], stdin=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        _, err = p.communicate(input=f"{username}:{password}\n")
        if p.returncode != 0:
            return jsonify({'status': 'error', 'message': f'Ошибка установки пароля: {err}'}), 500

        # Assign sudo if requested
        if is_sudo:
            subprocess.run(['usermod', '-aG', 'sudo', username], check=True)

        return jsonify({'status': 'ok', 'message': f'Пользователь ОС "{username}" успешно создан!'})
    except subprocess.CalledProcessError as e:
        return jsonify({'status': 'error', 'message': f'Системная ошибка: {e}'}), 500

@app.route('/api/users/change_password', methods=['POST'])
@login_required
def api_users_change_password():
    d = request.json or {}
    username = d.get('username', '').strip().lower()
    password = d.get('password', '')

    if not username:
        return jsonify({'status': 'error', 'message': 'Имя пользователя не указано'}), 400
    if len(password) < 6:
        return jsonify({'status': 'error', 'message': 'Пароль должен быть не менее 6 символов'}), 400

    try:
        p = pwd.getpwnam(username)
        if p.pw_uid < 1000 and username != 'root':
            return jsonify({'status': 'error', 'message': 'Запрещено менять пароли системных служебных служб'}), 403
    except KeyError:
        return jsonify({'status': 'error', 'message': f'Пользователь {username} не найден'}), 404

    try:
        proc = subprocess.Popen(['chpasswd'], stdin=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        _, err = proc.communicate(input=f"{username}:{password}\n")
        if proc.returncode != 0:
            return jsonify({'status': 'error', 'message': f'Ошибка: {err}'}), 500
        return jsonify({'status': 'ok', 'message': f'Пароль для {username} успешно обновлен!'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/users/delete', methods=['POST'])
@login_required
def api_users_delete():
    d = request.json or {}
    username = d.get('username', '').strip().lower()
    current_user = session.get('user', '')

    if username in ('root', current_user):
        return jsonify({'status': 'error', 'message': 'Запрещено удалять root или собственную активную учётную запись'}), 403

    try:
        p = pwd.getpwnam(username)
        if p.pw_uid < 1000:
            return jsonify({'status': 'error', 'message': 'Запрещено удалять системных пользователей'}), 403
    except KeyError:
        return jsonify({'status': 'error', 'message': f'Пользователь {username} не найден'}), 404

    try:
        subprocess.run(['userdel', '-r', username], check=True)
        return jsonify({'status': 'ok', 'message': f'Пользователь {username} успешно удален!'})
    except subprocess.CalledProcessError as e:
        return jsonify({'status': 'error', 'message': f'Ошибка удаления: {e}'}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)
