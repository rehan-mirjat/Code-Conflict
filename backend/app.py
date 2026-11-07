"""Code & Conflict backend (Flask + SQLite).

Serves the static site and a small JSON API:

    GET  /api/health      -> {"ok": true}
    POST /api/register    -> create account   {email, password, pgp?}
    POST /api/login       -> start session    {email, password}
    POST /api/logout      -> end session
    GET  /api/me          -> current user or null
    POST /api/contact     -> store a message  {name, email, subject, message}
    GET  /api/feed/next   -> one simulated threat item for the live feed

Run:  python3 backend/app.py      (http://127.0.0.1:5000)
"""
import os
import random
import re
import secrets
import sqlite3
import time
from datetime import datetime, timedelta, timezone

from flask import Flask, abort, g, jsonify, request, send_from_directory, session
from werkzeug.security import check_password_hash, generate_password_hash

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
STATIC_DIRS = {'assets', 'news', 'prevention', 'threats'}  # only these are served

EMAIL_RE = re.compile(r'^[^@\s]+@[^@\s]+\.edu\.pk$', re.I)
CONTACT_EMAIL_RE = re.compile(r'^[^@\s]+@[^@\s]+\.[^@\s]+$')
LOGIN_LIMIT, LOGIN_WINDOW = 5, 60  # attempts per window (seconds)

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
"""


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
    return None


def create_app(db_path=None):
    app = Flask(__name__, static_folder=None)
    app.config.update(
        DB_PATH=db_path or os.environ.get('CC_DB') or os.path.join(HERE, 'data.db'),
        SECRET_KEY=_load_secret(),
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE='Lax',
        PERMANENT_SESSION_LIFETIME=timedelta(days=7),
        MAX_CONTENT_LENGTH=64 * 1024,
    )
    attempts = {}  # (ip, email) -> [timestamps]; in-memory login rate limit

    with sqlite3.connect(app.config['DB_PATH']) as con:
        con.executescript(SCHEMA)

    def db():
        if 'db' not in g:
            g.db = sqlite3.connect(app.config['DB_PATH'])
            g.db.row_factory = sqlite3.Row
        return g.db

    @app.teardown_appcontext
    def close_db(_exc):
        con = g.pop('db', None)
        if con is not None:
            con.close()

    @app.after_request
    def headers(resp):
        resp.headers['X-Content-Type-Options'] = 'nosniff'
        resp.headers['Referrer-Policy'] = 'same-origin'
        if request.path.startswith('/api/'):
            resp.headers['Cache-Control'] = 'no-store'
        return resp

    def err(msg, code=400):
        return jsonify(ok=False, error=msg), code

    def body():
        """JSON body as dict, or None. Requiring JSON blocks simple cross-site form posts."""
        if not request.is_json:
            return None
        data = request.get_json(silent=True)
        return data if isinstance(data, dict) else None

    # ------------------------------------------------------------- API
    @app.get('/api/health')
    def health():
        return jsonify(ok=True)

    @app.post('/api/register')
    def register():
        data = body()
        if data is None:
            return err('Expected a JSON body.', 415)
        email = str(data.get('email', '')).strip().lower()
        password = str(data.get('password', ''))
        pgp = str(data.get('pgp', ''))[:4000]
        if not EMAIL_RE.match(email) or len(email) > 254:
            return err('Please use a valid .edu.pk university email.')
        problem = password_problem(password)
        if problem:
            return err(problem)
        try:
            db().execute(
                'INSERT INTO users (email, name, pw_hash, pgp, created) VALUES (?,?,?,?,?)',
                (email, email.split('@')[0], generate_password_hash(password), pgp, _now()))
            db().commit()
        except sqlite3.IntegrityError:
            return err('An account with this email already exists.', 409)
        return jsonify(ok=True), 201

    @app.post('/api/login')
    def login():
        data = body()
        if data is None:
            return err('Expected a JSON body.', 415)
        email = str(data.get('email', '')).strip().lower()
        password = str(data.get('password', ''))

        key = (request.remote_addr, email)
        now = time.time()
        recent = [t for t in attempts.get(key, []) if now - t < LOGIN_WINDOW]
        if len(recent) >= LOGIN_LIMIT:
            attempts[key] = recent
            return err('Too many attempts. Please wait a minute and try again.', 429)

        row = db().execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
        # Always run a hash check so unknown emails and wrong passwords look alike.
        good = check_password_hash(row['pw_hash'] if row else _DUMMY_HASH, password)
        if not row or not good:
            recent.append(now)
            attempts[key] = recent
            return err('Invalid email or passphrase.', 401)

        attempts.pop(key, None)
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
        row = db().execute('SELECT email, name FROM users WHERE email = ?', (email,)).fetchone()
        if not row:
            session.clear()
            return jsonify(ok=True, user=None)
        return jsonify(ok=True, user={'email': row['email'], 'name': row['name']})

    @app.post('/api/contact')
    def contact():
        data = body()
        if data is None:
            return err('Expected a JSON body.', 415)
        name = str(data.get('name', '')).strip()
        email = str(data.get('email', '')).strip()
        subject = str(data.get('subject', '')).strip()
        message = str(data.get('message', '')).strip()
        if not (1 <= len(name) <= 100):
            return err('Please enter your name (max 100 characters).')
        if not CONTACT_EMAIL_RE.match(email) or len(email) > 254:
            return err('Please enter a valid email address.')
        if not (1 <= len(subject) <= 100):
            return err('Please choose a subject.')
        if not (1 <= len(message) <= 5000):
            return err('Please enter a message (max 5000 characters).')
        db().execute(
            'INSERT INTO messages (name, email, subject, message, created) VALUES (?,?,?,?,?)',
            (name, email, subject, message, _now()))
        db().commit()
        return jsonify(ok=True), 201

    @app.get('/api/feed/next')
    def feed_next():
        sev, kind, title, region = random.choice(FEED_POOL)
        return jsonify(ok=True, item={'sev': sev, 'type': kind, 'title': title,
                                      'region': region, 'ts': _now()})

    # ---------------------------------------------------------- static
    @app.get('/')
    def home():
        return send_from_directory(ROOT, 'index.html')

    @app.get('/<path:p>')
    def static_files(p):
        parts = p.split('/')
        top_level_html = len(parts) == 1 and p.endswith('.html')
        if not (top_level_html or parts[0] in STATIC_DIRS):
            abort(404)
        return send_from_directory(ROOT, p)

    return app


_DUMMY_HASH = generate_password_hash('not-a-real-password')

if __name__ == '__main__':
    create_app().run(host='127.0.0.1', port=int(os.environ.get('PORT', 5000)))

