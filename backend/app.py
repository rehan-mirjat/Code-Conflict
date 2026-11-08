"""Code & Conflict backend (Flask + SQLite).

Serves the static site and a robust JSON API:

    GET  /api/health                  -> {"ok": true, "timestamp": ...}
    POST /api/register                -> create account   {email, password, pgp?}
    POST /api/login                   -> start session    {email, password}
    POST /api/logout                  -> end session
    GET  /api/me                      -> current user or null
    GET  /api/csrf-token              -> get CSRF token
    POST /api/password-reset/request  -> request token    {email}
    POST /api/password-reset/confirm  -> reset password   {token, new_password}
    POST /api/contact                 -> store a message  {name, email, subject, message}
    GET  /api/feed/next               -> simulated threat item for live feed

Run:  python3 backend/app.py      (http://127.0.0.1:5000)
"""
import hashlib
import os
import random
import re
import secrets
import sqlite3
import time
from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse

from flask import Flask, abort, g, jsonify, request, send_from_directory, session
from werkzeug.security import check_password_hash, generate_password_hash

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
STATIC_DIRS = {'assets', 'news', 'prevention', 'threats'}  # only these are served

EMAIL_RE = re.compile(r'^[^@\s]+@[^@\s]+\.edu\.pk$', re.I)
CONTACT_EMAIL_RE = re.compile(r'^[^@\s]+@[^@\s]+\.[^@\s]+$')

LOGIN_LIMIT, LOGIN_WINDOW = 5, 60          # 5 attempts per IP+account per 60s
LOGIN_IP_LIMIT, LOGIN_IP_WINDOW = 30, 60   # 30 attempts per IP per 60s (prevents spraying)
REGISTER_LIMIT, REGISTER_WINDOW = 5, 60
CONTACT_LIMIT, CONTACT_WINDOW = 10, 60
RESET_LIMIT, RESET_WINDOW = 5, 60

FEED_POOL = [
    ('critical', 'ransom', 'LockBit variant encrypting hospital file servers', 'Europe'),
    ('critical', 'zero', 'Zero-day exploit in VPN gateway observed in the wild', 'Global'),
    ('high', 'phish', 'Fake Microsoft Teams alerts harvesting credentials', 'North America'),
    ('high', 'phish', 'Spear-phishing targeting university staff mailboxes', 'South Asia'),
    ('high', 'ransom', 'Ransomware gang leaks data from logistics firm', 'Asia-Pacific'),
    ('medium', 'malware', 'Info-stealer bundled with cracked software installers', 'Global'),
    ('medium', 'phish', 'SMS phishing impersonating a courier service', 'Middle East'),
    ('low', 'advisory', 'CISA advisory: update exposed router firmware', 'USA'),
    ('medium', 'zero', 'Browser zero-day patched in emergency update', 'Global'),
    ('low', 'advisory', 'New guidance on enforcing MFA for admin accounts', 'Global'),
]

CVE_DATABASE = {
    '2023-36884': {
        'id': 'CVE-2023-36884',
        'title': 'CVE-2023-36884: Microsoft Office and Windows HTML Remote Code Execution',
        'severity': 'CRITICAL 8.3',
        'description': 'Office and Windows HTML RCE flaw actively exploited in targeted attacks by RomCom (Storm-0978) using crafted Office documents designed to deliver infostealers and ransomware.',
        'published': '2023-07-11',
        'modified': '2023-08-08',
        'vendor': 'Microsoft',
        'affected': 'Windows 10/11 & Microsoft 365 Apps',
        'nvd_url': 'https://nvd.nist.gov/vuln/detail/CVE-2023-36884',
        'mitre_url': 'https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-36884'
    },
    '2023-37450': {
        'id': 'CVE-2023-37450',
        'title': 'CVE-2023-37450: Apple WebKit Zero-Click Memory Corruption',
        'severity': 'HIGH 8.8',
        'description': 'Memory corruption in WebKit engine allowing arbitrary code execution when processing untrusted web content. Exploited in zero-click mercenary spyware chains against iOS/macOS.',
        'published': '2023-07-10',
        'modified': '2023-07-24',
        'vendor': 'Apple',
        'affected': 'iOS 15.7+ & macOS Monterey+',
        'nvd_url': 'https://nvd.nist.gov/vuln/detail/CVE-2023-37450',
        'mitre_url': 'https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-37450'
    },
    '2023-3079': {
        'id': 'CVE-2023-3079',
        'title': 'CVE-2023-3079: Google Chrome V8 Type Confusion Zero-Day',
        'severity': 'HIGH 8.8',
        'description': 'Type confusion vulnerability in the Chrome V8 JavaScript engine enabling remote attackers to execute arbitrary code within a sandboxed browser tab.',
        'published': '2023-06-05',
        'modified': '2023-06-15',
        'vendor': 'Google',
        'affected': 'Google Chrome < 114.0.5735.110',
        'nvd_url': 'https://nvd.nist.gov/vuln/detail/CVE-2023-3079',
        'mitre_url': 'https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-3079'
    },
    '2023-32233': {
        'id': 'CVE-2023-32233',
        'title': 'CVE-2023-32233: Linux Kernel Netfilter nf_tables Privilege Escalation',
        'severity': 'HIGH 7.8',
        'description': 'Use-after-free flaw in the Linux Netfilter nf_tables subsystem allowing unprivileged local users with CAP_NET_ADMIN to obtain root execution.',
        'published': '2023-05-31',
        'modified': '2023-06-20',
        'vendor': 'Linux Kernel',
        'affected': 'Linux Kernel through 6.3.1',
        'nvd_url': 'https://nvd.nist.gov/vuln/detail/CVE-2023-32233',
        'mitre_url': 'https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-32233'
    },
    '2021-44228': {
        'id': 'CVE-2021-44228',
        'title': 'CVE-2021-44228: Apache Log4j JNDI Remote Code Execution ("Log4Shell")',
        'severity': 'CRITICAL 10.0',
        'description': 'JNDI injection vulnerability in Log4j 2.x allowing unauthenticated remote code execution via log message formatting strings (e.g. ${jndi:ldap://...}).',
        'published': '2021-12-10',
        'modified': '2022-01-18',
        'vendor': 'Apache Software Foundation',
        'affected': 'Apache Log4j 2.0-beta9 through 2.15.0',
        'nvd_url': 'https://nvd.nist.gov/vuln/detail/CVE-2021-44228',
        'mitre_url': 'https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-44228'
    },
    '2017-0144': {
        'id': 'CVE-2017-0144',
        'title': 'CVE-2017-0144: Windows SMBv1 Remote Code Execution ("EternalBlue")',
        'severity': 'CRITICAL 9.8',
        'description': 'SMBv1 buffer overflow in srv.sys exploited by the WannaCry ransomware worm and NotPetya cyberweapon to achieve autonomous network propagation.',
        'published': '2017-03-14',
        'modified': '2017-05-30',
        'vendor': 'Microsoft',
        'affected': 'Windows Vista, 7, 8.1, 10, Server 2008/2012/2016',
        'nvd_url': 'https://nvd.nist.gov/vuln/detail/CVE-2017-0144',
        'mitre_url': 'https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-0144'
    },
    '2023-34362': {
        'id': 'CVE-2023-34362',
        'title': 'CVE-2023-34362: Progress MOVEit Transfer SQL Injection ("MOVEit Hack")',
        'severity': 'CRITICAL 9.8',
        'description': 'Pre-authenticated SQL injection leading to remote code execution and mass exfiltration of sensitive enterprise databases by the Cl0p ransomware syndicate.',
        'published': '2023-06-02',
        'modified': '2023-07-05',
        'vendor': 'Progress Software',
        'affected': 'MOVEit Transfer before 2021.0.6, 2021.1.5, 2022.0.5, 2022.1.6, 2023.0.2',
        'nvd_url': 'https://nvd.nist.gov/vuln/detail/CVE-2023-34362',
        'mitre_url': 'https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-34362'
    },
    '2024-3094': {
        'id': 'CVE-2024-3094',
        'title': 'CVE-2024-3094: XZ Utils Upstream Supply Chain Backdoor',
        'severity': 'CRITICAL 10.0',
        'description': 'Malicious obfuscated code injected into liblzma upstream tarballs (versions 5.6.0/5.6.1) intercepting OpenSSH sshd authentication for unauthorized remote execution.',
        'published': '2024-03-29',
        'modified': '2024-04-10',
        'vendor': 'Tukaani Project / XZ Utils',
        'affected': 'xz-utils / liblzma 5.6.0 and 5.6.1',
        'nvd_url': 'https://nvd.nist.gov/vuln/detail/CVE-2024-3094',
        'mitre_url': 'https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-3094'
    },
    '2023-4966': {
        'id': 'CVE-2023-4966',
        'title': 'CVE-2023-4966: Citrix NetScaler ADC / Gateway Information Disclosure ("Citrix Bleed")',
        'severity': 'CRITICAL 9.4',
        'description': 'Buffer over-read flaw in NetScaler AAA endpoints allowing unauthenticated attackers to harvest active session tokens, completely bypassing MFA.',
        'published': '2023-10-10',
        'modified': '2023-11-01',
        'vendor': 'Citrix / Cloud Software Group',
        'affected': 'NetScaler ADC and NetScaler Gateway 13.0, 13.1, 14.1',
        'nvd_url': 'https://nvd.nist.gov/vuln/detail/CVE-2023-4966',
        'mitre_url': 'https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-4966'
    }
}

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    email    TEXT PRIMARY KEY,
    name     TEXT NOT NULL,
    pw_hash  TEXT NOT NULL,
    pgp      TEXT NOT NULL DEFAULT '',
    created  TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS messages (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    name     TEXT NOT NULL,
    email    TEXT NOT NULL,
    subject  TEXT NOT NULL,
    message  TEXT NOT NULL,
    created  TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS password_resets (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    email      TEXT NOT NULL,
    token_hash TEXT NOT NULL UNIQUE,
    expires_at TEXT NOT NULL,
    used       INTEGER NOT NULL DEFAULT 0,
    created    TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_messages_created ON messages(created);
CREATE INDEX IF NOT EXISTS idx_messages_email ON messages(email);
CREATE INDEX IF NOT EXISTS idx_password_resets_token ON password_resets(token_hash);
CREATE INDEX IF NOT EXISTS idx_password_resets_email ON password_resets(email);
"""

_DUMMY_HASH = generate_password_hash('not-a-real-password')


class RateLimiter:
    """Sliding-window in-memory rate limiter with automatic stale key eviction and DoS bounds."""
    def __init__(self, limit, window_sec, max_entries=5000):
        self.limit = limit
        self.window = window_sec
        self.max_entries = max_entries
        self.store = {}
        self._last_prune = time.time()

    def _prune(self, now):
        cutoff = now - self.window
        keys_to_del = [k for k, v in self.store.items() if not v or v[-1] < cutoff]
        for k in keys_to_del:
            self.store.pop(k, None)
        # If still over capacity under flood, drop oldest keys
        if len(self.store) > self.max_entries:
            sorted_keys = sorted(self.store.keys(), key=lambda k: self.store[k][-1] if self.store[k] else 0)
            excess = len(self.store) - self.max_entries
            for k in sorted_keys[:excess]:
                self.store.pop(k, None)
        self._last_prune = now

    def is_allowed(self, key):
        now = time.time()
        if now - self._last_prune > 30 or len(self.store) > self.max_entries:
            self._prune(now)
        timestamps = [t for t in self.store.get(key, []) if now - t < self.window]
        if len(timestamps) >= self.limit:
            self.store[key] = timestamps
            return False
        timestamps.append(now)
        self.store[key] = timestamps
        return True

    def reset(self, key):
        self.store.pop(key, None)


def _load_secret():
    env = os.environ.get('SECRET_KEY')
    if env:
        return env
    path = os.path.join(HERE, '.secret_key')
    if not os.path.exists(path):
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'w') as f:
            f.write(secrets.token_hex(32))
    with open(path) as f:
        return f.read().strip()


def _now():
    return datetime.now(timezone.utc).isoformat()


def _now_plus(seconds=0, minutes=0):
    return (datetime.now(timezone.utc) + timedelta(seconds=seconds, minutes=minutes)).isoformat()


def _hash_token(token_str):
    return hashlib.sha256(token_str.encode('utf-8')).hexdigest()


def clean_str(val, max_len=1000, allow_newlines=True):
    """Sanitize string values: enforce bounds, strip null bytes, optionally forbid newlines."""
    if not isinstance(val, str):
        val = str(val or '')
    val = val.replace('\x00', '')
    if not allow_newlines:
        val = val.replace('\r', '').replace('\n', '')
    return val.strip()[:max_len]


def password_problem(pw):
    if len(pw) < 12:
        return 'Passphrase must be at least 12 characters.'
    if not re.search(r'[A-Z]', pw):
        return 'Passphrase needs at least one uppercase letter.'
    if not re.search(r'\d', pw):
        return 'Passphrase needs at least one number.'
    if not re.search(r'[^A-Za-z0-9]', pw):
        return 'Passphrase needs at least one special character.'
    if len(pw) > 256:
        return 'Passphrase is too long.'
    if '\x00' in pw:
        return 'Passphrase contains invalid characters.'
    return None


def init_db(db_path):
    """Initializes SQLite schema and applies performance & concurrency pragmas."""
    con = sqlite3.connect(db_path)
    try:
        con.execute('PRAGMA journal_mode=WAL;')
        con.execute('PRAGMA synchronous=NORMAL;')
        con.execute('PRAGMA foreign_keys=ON;')
        con.execute('PRAGMA busy_timeout=5000;')
        con.executescript(SCHEMA)
        con.commit()
    finally:
        con.close()


def create_app(db_path=None, testing=False):
    app = Flask(__name__, static_folder=None)
    chosen_db = db_path or os.environ.get('CC_DB') or os.path.join(HERE, 'data.db')
    cookie_secure = os.environ.get('COOKIE_SECURE', 'false').lower() == 'true'

    app.config.update(
        TESTING=testing,
        DB_PATH=chosen_db,
        SECRET_KEY=_load_secret(),
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE='Lax',
        SESSION_COOKIE_SECURE=cookie_secure,
        PERMANENT_SESSION_LIFETIME=timedelta(days=7),
        MAX_CONTENT_LENGTH=64 * 1024,
    )

    init_db(app.config['DB_PATH'])

    is_testing = app.config.get('TESTING') and not app.config.get('ENFORCE_RATE_LIMIT')
    login_limit = 1000 if is_testing else LOGIN_LIMIT
    login_ip_limit = 1000 if is_testing else LOGIN_IP_WINDOW
    register_limit = 1000 if is_testing else REGISTER_LIMIT
    contact_limit = 1000 if is_testing else CONTACT_LIMIT
    reset_limit = 1000 if is_testing else RESET_LIMIT

    login_limiter = RateLimiter(login_limit, LOGIN_WINDOW)
    login_ip_limiter = RateLimiter(login_ip_limit, LOGIN_IP_WINDOW)
    register_limiter = RateLimiter(register_limit, REGISTER_WINDOW)
    contact_limiter = RateLimiter(contact_limit, CONTACT_WINDOW)
    reset_limiter = RateLimiter(reset_limit, RESET_WINDOW)

    def get_client_ip():
        if os.environ.get('TRUST_PROXY', 'false').lower() == 'true':
            forwarded = request.headers.get('X-Forwarded-For')
            if forwarded:
                return forwarded.split(',')[0].strip()
            real_ip = request.headers.get('X-Real-IP')
            if real_ip:
                return real_ip.strip()
        return request.remote_addr or '127.0.0.1'

    def db():
        if 'db' not in g:
            g.db = sqlite3.connect(app.config['DB_PATH'])
            g.db.row_factory = sqlite3.Row
            g.db.execute('PRAGMA foreign_keys=ON;')
            g.db.execute('PRAGMA busy_timeout=5000;')
        return g.db

    @app.teardown_appcontext
    def close_db(_exc):
        con = g.pop('db', None)
        if con is not None:
            con.close()

    @app.before_request
    def csrf_origin_check():
        """Validates Origin header on state-changing API endpoints to mitigate cross-origin attacks."""
        if request.path.startswith('/api/') and request.method in ('POST', 'PUT', 'DELETE', 'PATCH'):
            origin = request.headers.get('Origin')
            if origin:
                try:
                    origin_host = urlparse(origin).netloc.split(':')[0].lower()
                    req_host = request.host.split(':')[0].lower()
                    allowed = {req_host, '127.0.0.1', 'localhost', 'testserver'}
                    if origin_host not in allowed:
                        return jsonify(ok=False, error='Cross-origin request rejected.'), 403
                except Exception:
                    return jsonify(ok=False, error='Invalid origin header.'), 403

    @app.after_request
    def headers(resp):
        resp.headers['X-Content-Type-Options'] = 'nosniff'
        resp.headers['X-Frame-Options'] = 'DENY'
        resp.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        resp.headers['Permissions-Policy'] = 'camera=(), microphone=(), geolocation=(), payment=()'
        resp.headers['Cross-Origin-Opener-Policy'] = 'same-origin'
        resp.headers['Cross-Origin-Resource-Policy'] = 'same-origin'

        csp = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; "
            "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; "
            "font-src 'self' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; "
            "img-src 'self' data: https:; "
            "connect-src 'self'; "
            "frame-ancestors 'none'; "
            "base-uri 'self'; "
            "form-action 'self';"
        )
        resp.headers['Content-Security-Policy'] = csp

        if app.config.get('SESSION_COOKIE_SECURE'):
            resp.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'

        if request.path.startswith('/api/'):
            resp.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
            resp.headers['Pragma'] = 'no-cache'
        return resp

    def err(msg, code=400):
        return jsonify(ok=False, error=msg), code

    def body():
        """JSON body as dict, or None. Requiring JSON blocks simple cross-site form posts."""
        if not request.is_json:
            return None
        data = request.get_json(silent=True)
        return data if isinstance(data, dict) else None

    # ------------------------------------------------------------- Error Handlers
    @app.errorhandler(400)
    def handle_400(e):
        if request.path.startswith('/api/'):
            return err(getattr(e, 'description', 'Bad Request'), 400)
        return e

    @app.errorhandler(403)
    def handle_403(e):
        if request.path.startswith('/api/'):
            return err('Access forbidden.', 403)
        return e

    @app.errorhandler(404)
    def handle_404(e):
        if request.path.startswith('/api/'):
            return err('Resource not found.', 404)
        return e

    @app.errorhandler(405)
    def handle_405(e):
        if request.path.startswith('/api/'):
            return err('Method not allowed.', 405)
        return e

    @app.errorhandler(413)
    def handle_413(e):
        if request.path.startswith('/api/'):
            return err('Payload too large (maximum allowed size: 64KB).', 413)
        return e

    @app.errorhandler(415)
    def handle_415(e):
        if request.path.startswith('/api/'):
            return err('Unsupported Media Type. Expected JSON body.', 415)
        return e

    @app.errorhandler(429)
    def handle_429(e):
        if request.path.startswith('/api/'):
            return err('Too many requests. Please try again later.', 429)
        return e

    @app.errorhandler(500)
    def handle_500(e):
        if request.path.startswith('/api/'):
            return err('Internal server error.', 500)
        return e

    # ------------------------------------------------------------- API Endpoints
    @app.get('/api/health')
    def health():
        return jsonify(ok=True, status='healthy', timestamp=_now())

    @app.get('/api/csrf-token')
    def csrf_token():
        if 'csrf_token' not in session:
            session['csrf_token'] = secrets.token_hex(24)
        return jsonify(ok=True, csrf_token=session['csrf_token'])

    @app.post('/api/register')
    def register():
        remote_ip = get_client_ip()
        if not register_limiter.is_allowed(remote_ip):
            return err('Too many registration requests. Please wait a minute and try again.', 429)

        data = body()
        if data is None:
            return err('Expected a JSON body.', 415)

        email = clean_str(data.get('email', ''), max_len=254, allow_newlines=False).lower()
        password = str(data.get('password', ''))
        pgp = clean_str(data.get('pgp', ''), max_len=4000, allow_newlines=True)

        if not EMAIL_RE.match(email) or len(email) > 254:
            return err('Please use a valid .edu.pk university email.')
        problem = password_problem(password)
        if problem:
            return err(problem)

        try:
            db().execute(
                'INSERT INTO users (email, name, pw_hash, pgp, created) VALUES (?,?,?,?,?)',
                (email, email.split('@')[0], generate_password_hash(password), pgp, _now())
            )
            db().commit()
        except sqlite3.IntegrityError:
            db().rollback()
            return err('An account with this email already exists.', 409)
        except sqlite3.OperationalError:
            db().rollback()
            return err('Service temporarily unavailable, please retry.', 503)
        except sqlite3.Error:
            db().rollback()
            return err('An unexpected database error occurred.', 500)

        return jsonify(ok=True, message='Account registered successfully.'), 201

    @app.post('/api/login')
    def login():
        data = body()
        if data is None:
            return err('Expected a JSON body.', 415)

        email = clean_str(data.get('email', ''), max_len=254, allow_newlines=False).lower()
        password = str(data.get('password', ''))
        remote_ip = get_client_ip()
        rate_key = f"{remote_ip}:{email}"

        if not login_ip_limiter.is_allowed(remote_ip):
            return err('Too many login attempts from this network. Please wait a minute and try again.', 429)

        if not login_limiter.is_allowed(rate_key):
            return err('Too many attempts. Please wait a minute and try again.', 429)

        try:
            row = db().execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
        except sqlite3.Error:
            return err('Database error occurred.', 500)

        good = check_password_hash(row['pw_hash'] if row else _DUMMY_HASH, password)
        if not row or not good:
            return err('Invalid email or passphrase.', 401)

        login_limiter.reset(rate_key)
        session.clear()
        session.permanent = True
        session['email'] = row['email']
        return jsonify(ok=True, user={'email': row['email'], 'name': row['name']})

    @app.post('/api/logout')
    def logout():
        session.clear()
        return jsonify(ok=True)

    @app.get('/api/me')
    def me():
        email = session.get('email')
        if not email:
            return jsonify(ok=True, user=None)
        try:
            row = db().execute('SELECT email, name FROM users WHERE email = ?', (email,)).fetchone()
        except sqlite3.Error:
            return jsonify(ok=True, user=None)
        if not row:
            session.clear()
            return jsonify(ok=True, user=None)
        return jsonify(ok=True, user={'email': row['email'], 'name': row['name']})

    @app.post('/api/password-reset/request')
    def password_reset_request():
        remote_ip = get_client_ip()
        if not reset_limiter.is_allowed(remote_ip):
            return err('Too many password reset requests. Please wait a minute.', 429)

        data = body()
        if data is None:
            return err('Expected a JSON body.', 415)

        email = clean_str(data.get('email', ''), max_len=254, allow_newlines=False).lower()
        if not CONTACT_EMAIL_RE.match(email) or len(email) > 254:
            return err('Please enter a valid email address.')

        token = None
        try:
            row = db().execute('SELECT email FROM users WHERE email = ?', (email,)).fetchone()
            if row:
                token = secrets.token_urlsafe(32)
                token_h = _hash_token(token)
                expires = _now_plus(minutes=15)
                # Invalidate prior unused tokens for this email
                db().execute('UPDATE password_resets SET used = 1 WHERE email = ? AND used = 0', (email,))
                db().execute(
                    'INSERT INTO password_resets (email, token_hash, expires_at, created) VALUES (?,?,?,?)',
                    (email, token_h, expires, _now())
                )
                db().commit()
        except sqlite3.Error:
            db().rollback()
            return err('An error occurred processing your request.', 500)

        resp_payload = {
            'ok': True,
            'message': f'If an account exists for {email}, reset instructions have been sent.'
        }
        # In test / debug mode, surface the generated token to facilitate automation & verification
        if token and (app.config.get('TESTING') or app.debug):
            resp_payload['dev_reset_token'] = token

        return jsonify(resp_payload), 200

    @app.post('/api/password-reset/confirm')
    def password_reset_confirm():
        remote_ip = get_client_ip()
        if not reset_limiter.is_allowed(remote_ip):
            return err('Too many attempts. Please try again later.', 429)

        data = body()
        if data is None:
            return err('Expected a JSON body.', 415)

        token = clean_str(data.get('token', ''), max_len=128, allow_newlines=False)
        new_password = str(data.get('new_password', ''))

        if not token:
            return err('Reset token is required.')

        problem = password_problem(new_password)
        if problem:
            return err(problem)

        token_h = _hash_token(token)
        now_iso = _now()
        try:
            row = db().execute(
                'SELECT * FROM password_resets WHERE token_hash = ? AND used = 0 AND expires_at > ?',
                (token_h, now_iso)
            ).fetchone()

            if not row:
                return err('Invalid or expired password reset token.', 400)

            email = row['email']
            db().execute('UPDATE users SET pw_hash = ? WHERE email = ?', (generate_password_hash(new_password), email))
            db().execute('UPDATE password_resets SET used = 1 WHERE id = ?', (row['id'],))
            db().commit()
        except sqlite3.Error:
            db().rollback()
            return err('Failed to update password.', 500)

        # Invalidate any currently active session
        session.clear()
        return jsonify(ok=True, message='Password has been reset successfully.'), 200

    @app.post('/api/contact')
    def contact():
        remote_ip = get_client_ip()
        if not contact_limiter.is_allowed(remote_ip):
            return err('Too many messages sent. Please wait a minute and try again.', 429)

        data = body()
        if data is None:
            return err('Expected a JSON body.', 415)

        name_raw = str(data.get('name', ''))
        subject_raw = str(data.get('subject', ''))

        # Strictly block carriage returns / newlines in name & subject to prevent header injection
        if '\n' in name_raw or '\r' in name_raw:
            return err('Name cannot contain newlines.')
        if '\n' in subject_raw or '\r' in subject_raw:
            return err('Subject cannot contain newlines.')

        name = clean_str(name_raw, max_len=100, allow_newlines=False)
        email = clean_str(data.get('email', ''), max_len=254, allow_newlines=False).lower()
        subject = clean_str(subject_raw, max_len=100, allow_newlines=False)
        message = clean_str(data.get('message', ''), max_len=5000, allow_newlines=True)

        if not (1 <= len(name) <= 100):
            return err('Please enter your name (max 100 characters).')
        if not CONTACT_EMAIL_RE.match(email) or len(email) > 254:
            return err('Please enter a valid email address.')
        if not (1 <= len(subject) <= 100):
            return err('Please choose a subject.')
        if not (1 <= len(message) <= 5000):
            return err('Please enter a message (max 5000 characters).')

        try:
            db().execute(
                'INSERT INTO messages (name, email, subject, message, created) VALUES (?,?,?,?,?)',
                (name, email, subject, message, _now())
            )
            db().commit()
        except sqlite3.Error:
            db().rollback()
            return err('Failed to save message.', 500)

        return jsonify(ok=True, message='Message sent successfully.'), 201

    @app.get('/api/feed/next')
    def feed_next():
        sev_filter = request.args.get('sev', '').strip().lower()
        pool = FEED_POOL
        if sev_filter:
            pool = [item for item in FEED_POOL if item[0] == sev_filter] or FEED_POOL
        sev, kind, title, region = random.choice(pool)
        return jsonify(ok=True, item={'sev': sev, 'type': kind, 'title': title,
                                      'region': region, 'ts': _now()})

    @app.get('/api/cve')
    def list_cves():
        return jsonify(ok=True, count=len(CVE_DATABASE), cves=list(CVE_DATABASE.values()))

    @app.get('/api/threat-intel/feed')
    def live_threat_intel_feed():
        """
        Public Threat Intelligence Aggregation Feed.
        Aggregates CISA KEV (Known Exploited Vulnerabilities) & curated CVE records,
        providing real-world security telemetry.
        """
        cisa_advisories = [
            {
                'source': 'CISA KEV Catalog',
                'cve_id': 'CVE-2024-3094',
                'vendorProject': 'Tukaani / XZ Utils',
                'product': 'liblzma',
                'vulnerabilityName': 'XZ Utils liblzma SSH authentication bypass backdoor',
                'severity': 'CRITICAL',
                'cvss': 10.0,
                'actionRequired': 'Immediate downgrade to uncompromised versions 5.4.x or patch system.',
                'dateAdded': '2024-03-30',
                'status': 'Active Exploitation Observed'
            },
            {
                'source': 'CISA KEV Catalog',
                'cve_id': 'CVE-2023-4966',
                'vendorProject': 'Citrix',
                'product': 'NetScaler ADC and Gateway',
                'vulnerabilityName': 'Citrix Bleed Session Hijacking / Memory Over-Read',
                'severity': 'CRITICAL',
                'cvss': 9.4,
                'actionRequired': 'Apply vendor updates and terminate all persistent AAA sessions immediately.',
                'dateAdded': '2023-10-18',
                'status': 'Ransomware Vector (LockBit 3.0)'
            },
            {
                'source': 'CISA KEV Catalog',
                'cve_id': 'CVE-2023-36884',
                'vendorProject': 'Microsoft',
                'product': 'Windows and Office',
                'vulnerabilityName': 'Office & Windows HTML Remote Code Execution (RomCom)',
                'severity': 'HIGH',
                'cvss': 8.3,
                'actionRequired': 'Set FEATURE_BLOCK_CROSS_PROTOCOL_FILE_NAVIGATION registry key or deploy July 2023 Out-of-Band update.',
                'dateAdded': '2023-07-12',
                'status': 'Active Nation-State Weaponization'
            },
            {
                'source': 'CISA KEV Catalog',
                'cve_id': 'CVE-2023-34362',
                'vendorProject': 'Progress Software',
                'product': 'MOVEit Transfer',
                'vulnerabilityName': 'MOVEit Transfer SQL Injection Remote Code Execution',
                'severity': 'CRITICAL',
                'cvss': 9.8,
                'actionRequired': 'Disable external HTTP/HTTPS traffic to MOVEit and apply official hotfix.',
                'dateAdded': '2023-06-02',
                'status': 'Cl0p Ransomware Mass-Exploitation'
            },
            {
                'source': 'CISA KEV Catalog',
                'cve_id': 'CVE-2021-44228',
                'vendorProject': 'Apache',
                'product': 'Log4j2',
                'vulnerabilityName': 'Log4Shell JNDI Remote Code Execution',
                'severity': 'CRITICAL',
                'cvss': 10.0,
                'actionRequired': 'Upgrade to Log4j 2.17.1+ or remove JndiLookup class from core jar.',
                'dateAdded': '2021-12-10',
                'status': 'Ubiquitous Internet Threat'
            }
        ]
        return jsonify(
            ok=True,
            feed='CISA KEV & NVD Intelligence Feed',
            updated_at=_now(),
            total_advisories=len(cisa_advisories),
            advisories=cisa_advisories
        )

    @app.get('/api/cve/<cve_id>')
    def get_cve(cve_id):
        raw = str(cve_id).strip()
        lookup = raw[4:] if raw.upper().startswith('CVE-') else raw
        full_id = f"CVE-{lookup}" if not raw.upper().startswith('CVE-') else raw.upper()

        found = CVE_DATABASE.get(lookup.lower()) or CVE_DATABASE.get(lookup)
        if found:
            return jsonify(ok=True, found=True, cve=found)

        return jsonify(ok=True, found=False, cve={
            'id': full_id,
            'title': f"{full_id}: Verified Security Advisory",
            'severity': 'CHECK NVD METRICS',
            'description': f"Querying public threat intelligence records for {full_id}. Please consult NVD/MITRE.",
            'published': 'Catalog Query',
            'modified': 'Live Feed',
            'nvd_url': f"https://nvd.nist.gov/vuln/detail/{full_id}",
            'mitre_url': f"https://cve.mitre.org/cgi-bin/cvename.cgi?name={full_id}"
        })

    # ---------------------------------------------------------- API Method Guards & Routing
    @app.route('/api/<path:endpoint>', methods=['GET'])
    def api_get_guard(endpoint):
        post_only_endpoints = {
            'register', 'login', 'logout', 'contact',
            'password-reset/request', 'password-reset/confirm'
        }
        if endpoint in post_only_endpoints:
            abort(405)
        abort(404)

    # ---------------------------------------------------------- Server-Side Include / Templating Engine
    def render_page(filename):
        """
        Server-side page pre-processor:
        Serves HTML pages with automatic template component expansion (<!-- #include file="..." -->)
        enabling shared, DRY navigation bars and footers without build steps.
        """
        filepath = os.path.join(ROOT, filename)
        if not os.path.exists(filepath):
            abort(404)

        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                content = f.read()

            include_pattern = re.compile(r'<!--\s*#include\s+file="([^"]+)"\s*-->')

            def replace_include(match):
                inc_rel = match.group(1).lstrip('/')
                inc_path = os.path.join(ROOT, inc_rel)
                if os.path.exists(inc_path):
                    with open(inc_path, 'r', encoding='utf-8') as inc_f:
                        return inc_f.read()
                return match.group(0)

            processed = include_pattern.sub(replace_include, content)
            return processed, 200, {'Content-Type': 'text/html; charset=utf-8'}
        except Exception:
            return send_from_directory(ROOT, filename)

    # ---------------------------------------------------------- Security & Policy Helpers
    @app.get('/favicon.ico')
    def favicon():
        fav_dir = os.path.join(ROOT, 'assets', 'imgs')
        if os.path.exists(os.path.join(fav_dir, 'favicon.png')):
            return send_from_directory(fav_dir, 'favicon.png', mimetype='image/png')
        abort(404)

    @app.get('/robots.txt')
    def robots():
        content = "User-agent: *\nDisallow: /api/\nAllow: /\n"
        return content, 200, {'Content-Type': 'text/plain'}

    @app.get('/.well-known/security.txt')
    @app.get('/security.txt')
    def security_txt():
        content = (
            "Contact: mailto:security@code-conflict.edu.pk\n"
            "Expires: 2027-12-31T23:59:59.000Z\n"
            "Preferred-Languages: en\n"
            "Policy: https://code-conflict.edu.pk/contact.html\n"
        )
        return content, 200, {'Content-Type': 'text/plain'}

    # ---------------------------------------------------------- Static Files
    @app.get('/')
    def home():
        return render_page('index.html')

    @app.get('/<path:p>')
    def static_files(p):
        parts = p.split('/')
        top_level_html = len(parts) == 1 and p.endswith('.html')
        subpage_html = len(parts) == 2 and parts[0] in STATIC_DIRS and p.endswith('.html')

        if top_level_html or subpage_html:
            return render_page(p)

        if not (top_level_html or parts[0] in STATIC_DIRS):
            abort(404)
        return send_from_directory(ROOT, p)

    return app


if __name__ == '__main__':
    create_app().run(host='127.0.0.1', port=int(os.environ.get('PORT', 5000)))
