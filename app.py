#!/usr/bin/env python3
"""
Roleplay Circles v2
Google OAuth + SQLite + Session Tracking
"""

import os
import secrets
import string
import sqlite3
from datetime import datetime, timedelta
from functools import wraps

from flask import (
    Flask, render_template, jsonify, request, redirect,
    url_for, session, g, flash
)
from dotenv import load_dotenv
import pytz
import requests as http_requests

# Load .env file
load_dotenv()

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(32))

# ============ CONFIG ============

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Use /data for persistent storage on Render, fallback to local for dev
def _get_data_dir():
    if os.path.exists('/data'):
        try:
            test_file = '/data/.write_test'
            with open(test_file, 'w') as f:
                f.write('ok')
            os.remove(test_file)
            return '/data'
        except Exception:
            pass
    local_dir = os.path.join(BASE_DIR, 'data')
    os.makedirs(local_dir, exist_ok=True)
    return local_dir

DATA_DIR = _get_data_dir()
DB_PATH = os.path.join(DATA_DIR, 'roleplay_circles.db')

GOOGLE_CLIENT_ID = os.environ.get('GOOGLE_CLIENT_ID', '')
GOOGLE_CLIENT_SECRET = os.environ.get('GOOGLE_CLIENT_SECRET', '')
GOOGLE_DISCOVERY_URL = 'https://accounts.google.com/.well-known/openid-configuration'

OAUTH_CONFIGURED = bool(GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET and
                        GOOGLE_CLIENT_ID != 'your-client-id-here.apps.googleusercontent.com')

GOOGLE_AUTH_URI = 'https://accounts.google.com/o/oauth2/v2/auth'
GOOGLE_TOKEN_URI = 'https://oauth2.googleapis.com/token'
GOOGLE_USERINFO_URI = 'https://www.googleapis.com/oauth2/v3/userinfo'
GOOGLE_CALENDAR_API = 'https://www.googleapis.com/calendar/v3'

SCOPES = [
    'openid',
    'https://www.googleapis.com/auth/userinfo.email',
    'https://www.googleapis.com/auth/userinfo.profile',
    'https://www.googleapis.com/auth/calendar.readonly',
]


# ============ DATABASE ============

def get_db():
    """Get database connection for current request."""
    if 'db' not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
        g.db.execute('PRAGMA journal_mode=WAL')
        g.db.execute('PRAGMA foreign_keys=ON')
    return g.db


@app.teardown_appcontext
def close_db(exception):
    db = g.pop('db', None)
    if db is not None:
        db.close()


def init_db():
    """Initialize database tables."""
    os.makedirs(DATA_DIR, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.executescript('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            google_id TEXT UNIQUE,
            email TEXT UNIQUE NOT NULL,
            name TEXT NOT NULL,
            avatar_url TEXT DEFAULT '',
            zoom_link TEXT DEFAULT '',
            timezone TEXT DEFAULT 'America/Chicago',
            google_refresh_token TEXT DEFAULT '',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS circles (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            code TEXT UNIQUE NOT NULL,
            name TEXT NOT NULL,
            created_by INTEGER REFERENCES users(id),
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS circle_members (
            circle_id INTEGER REFERENCES circles(id) ON DELETE CASCADE,
            user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
            role TEXT DEFAULT 'member' CHECK(role IN ('admin', 'member')),
            start_hour INTEGER DEFAULT 9,
            end_hour INTEGER DEFAULT 18,
            joined_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (circle_id, user_id)
        );

        CREATE TABLE IF NOT EXISTS availability (
            user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
            circle_id INTEGER REFERENCES circles(id) ON DELETE CASCADE,
            available INTEGER DEFAULT 0,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (user_id, circle_id)
        );

        CREATE TABLE IF NOT EXISTS sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            circle_id INTEGER REFERENCES circles(id) ON DELETE CASCADE,
            user1_id INTEGER REFERENCES users(id),
            user2_id INTEGER REFERENCES users(id),
            duration_minutes INTEGER DEFAULT 15,
            rating INTEGER DEFAULT 0,
            notes TEXT DEFAULT '',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS noshow_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
            circle_id INTEGER REFERENCES circles(id) ON DELETE CASCADE,
            event_uid TEXT DEFAULT '',
            event_summary TEXT DEFAULT '',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS user_calendars (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
            calendar_id TEXT NOT NULL,
            summary TEXT DEFAULT '',
            selected INTEGER DEFAULT 1,
            color TEXT DEFAULT '',
            account_id INTEGER DEFAULT NULL,
            UNIQUE(user_id, calendar_id)
        );

        CREATE TABLE IF NOT EXISTS linked_google_accounts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
            google_id TEXT NOT NULL,
            email TEXT NOT NULL,
            name TEXT DEFAULT '',
            access_token TEXT DEFAULT '',
            refresh_token TEXT DEFAULT '',
            is_primary INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(user_id, google_id)
        );

        CREATE TABLE IF NOT EXISTS external_calendars (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
            name TEXT NOT NULL,
            ics_url TEXT NOT NULL,
            selected INTEGER DEFAULT 1,
            color TEXT DEFAULT '#888888',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS roleplay_invites (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            circle_id INTEGER REFERENCES circles(id) ON DELETE CASCADE,
            from_user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
            to_user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
            status TEXT DEFAULT 'pending' CHECK(status IN ('pending', 'accepted', 'declined', 'expired')),
            decline_reason TEXT DEFAULT '',
            zoom_link TEXT DEFAULT '',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            responded_at TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS active_sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            circle_id INTEGER REFERENCES circles(id) ON DELETE CASCADE,
            zoom_link TEXT DEFAULT '',
            started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            ended_at TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS active_session_members (
            session_id INTEGER REFERENCES active_sessions(id) ON DELETE CASCADE,
            user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
            joined_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (session_id, user_id)
        );

        CREATE INDEX IF NOT EXISTS idx_circles_code ON circles(code);
        CREATE INDEX IF NOT EXISTS idx_users_google_id ON users(google_id);
        CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
        CREATE INDEX IF NOT EXISTS idx_sessions_circle ON sessions(circle_id);
        CREATE INDEX IF NOT EXISTS idx_sessions_created ON sessions(created_at);
        CREATE INDEX IF NOT EXISTS idx_user_calendars_user ON user_calendars(user_id);
        CREATE INDEX IF NOT EXISTS idx_roleplay_invites_to ON roleplay_invites(to_user_id, status);
        CREATE INDEX IF NOT EXISTS idx_roleplay_invites_from ON roleplay_invites(from_user_id, status);
        CREATE INDEX IF NOT EXISTS idx_active_sessions_circle ON active_sessions(circle_id, ended_at);
        CREATE INDEX IF NOT EXISTS idx_active_session_members ON active_session_members(user_id);
    ''')

    # Add new columns with ALTER TABLE (safe for existing DBs)
    alter_statements = [
        "ALTER TABLE circles ADD COLUMN max_session_size INTEGER DEFAULT 4",
        "ALTER TABLE circle_members ADD COLUMN last_seen TIMESTAMP",
        "ALTER TABLE active_sessions ADD COLUMN started_by INTEGER REFERENCES users(id)",
    ]
    for stmt in alter_statements:
        try:
            conn.execute(stmt)
        except Exception:
            pass  # Column already exists

    conn.commit()
    conn.close()


# ============ AUTH HELPERS ============

def generate_code(length=6):
    """Generate a random invite code."""
    return ''.join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(length))


def login_required(f):
    """Decorator to require login."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            # Store the URL they were trying to reach
            session['next_url'] = request.url
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated


def get_current_user():
    """Get the current logged-in user."""
    if 'user_id' not in session:
        return None
    db = get_db()
    user = db.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()
    return user


def get_oauth_redirect_uri():
    """Build the OAuth redirect URI."""
    override = os.environ.get('OAUTH_REDIRECT_URI', '')
    if override:
        return override
    return url_for('auth_callback', _external=True)


# ============ AUTH ROUTES ============

@app.route('/login')
def login():
    """Login page."""
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('login.html', oauth_configured=OAUTH_CONFIGURED)


@app.route('/auth/google')
def auth_google():
    """Start Google OAuth flow."""
    if not OAUTH_CONFIGURED:
        flash('Google OAuth is not configured. Set GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET.', 'error')
        return redirect(url_for('login'))

    # Preserve where they want to go after login
    next_url = request.args.get('next')
    if next_url:
        session['next_url'] = next_url

    state = secrets.token_urlsafe(32)
    session['oauth_state'] = state

    params = {
        'client_id': GOOGLE_CLIENT_ID,
        'redirect_uri': get_oauth_redirect_uri(),
        'response_type': 'code',
        'scope': ' '.join(SCOPES),
        'state': state,
        'access_type': 'offline',
        'prompt': 'consent',
    }

    auth_url = GOOGLE_AUTH_URI + '?' + '&'.join(f'{k}={v}' for k, v in params.items())
    return redirect(auth_url)


@app.route('/auth/callback')
def auth_callback():
    """Handle Google OAuth callback."""
    if not OAUTH_CONFIGURED:
        return redirect(url_for('login'))

    # Verify state — skip check if state is missing from session (multi-worker issue)
    stored_state = session.get('oauth_state')
    request_state = request.args.get('state')
    if stored_state and request_state and stored_state != request_state:
        flash('Invalid OAuth state. Please try again.', 'error')
        return redirect(url_for('login'))

    error = request.args.get('error')
    if error:
        flash(f'OAuth error: {error}', 'error')
        return redirect(url_for('login'))

    code = request.args.get('code')
    if not code:
        flash('No authorization code received.', 'error')
        return redirect(url_for('login'))

    # Exchange code for tokens
    try:
        token_resp = http_requests.post(GOOGLE_TOKEN_URI, data={
            'code': code,
            'client_id': GOOGLE_CLIENT_ID,
            'client_secret': GOOGLE_CLIENT_SECRET,
            'redirect_uri': get_oauth_redirect_uri(),
            'grant_type': 'authorization_code',
        }, timeout=10)
        token_resp.raise_for_status()
        tokens = token_resp.json()
    except Exception as e:
        flash(f'Failed to exchange token: {e}', 'error')
        return redirect(url_for('login'))

    access_token = tokens.get('access_token')
    refresh_token = tokens.get('refresh_token', '')

    # Get user info
    try:
        userinfo_resp = http_requests.get(GOOGLE_USERINFO_URI, headers={
            'Authorization': f'Bearer {access_token}'
        }, timeout=10)
        userinfo_resp.raise_for_status()
        userinfo = userinfo_resp.json()
    except Exception as e:
        flash(f'Failed to get user info: {e}', 'error')
        return redirect(url_for('login'))

    google_id = userinfo.get('sub', '')
    email = userinfo.get('email', '')
    name = userinfo.get('name', email.split('@')[0])
    avatar_url = userinfo.get('picture', '')

    # Upsert user — check by google_id first, then by email (for dev login migration)
    db = get_db()
    existing = db.execute('SELECT id FROM users WHERE google_id = ?', (google_id,)).fetchone()

    if not existing:
        # Check if a dev login user exists with same email
        existing = db.execute('SELECT id FROM users WHERE email = ?', (email,)).fetchone()

    if existing:
        user_id = existing['id']
        db.execute('''
            UPDATE users SET google_id=?, email=?, name=?, avatar_url=?,
            google_refresh_token=COALESCE(NULLIF(?, ''), google_refresh_token)
            WHERE id=?
        ''', (google_id, email, name, avatar_url, refresh_token, user_id))
    else:
        cursor = db.execute('''
            INSERT INTO users (google_id, email, name, avatar_url, google_refresh_token)
            VALUES (?, ?, ?, ?, ?)
        ''', (google_id, email, name, avatar_url, refresh_token))
        user_id = cursor.lastrowid

    db.commit()

    # Store as linked Google account (safe — table may not exist in old DBs)
    try:
        db.execute('''
            INSERT INTO linked_google_accounts (user_id, google_id, email, name, access_token, refresh_token, is_primary)
            VALUES (?, ?, ?, ?, ?, ?, 1)
            ON CONFLICT(user_id, google_id)
            DO UPDATE SET email=?, name=?, access_token=?,
            refresh_token=COALESCE(NULLIF(?, ''), refresh_token)
        ''', (user_id, google_id, email, name, access_token, refresh_token,
              email, name, access_token, refresh_token))
        db.commit()
    except Exception as e:
        print(f"Warning: Could not store linked account: {e}")

    # Check if this was a "link additional account" flow
    if session.get('linking_account'):
        session.pop('linking_account', None)
        session.pop('oauth_state', None)
        try:
            db.execute('''
                UPDATE linked_google_accounts SET is_primary = 0
                WHERE user_id = ? AND google_id = ?
            ''', (user_id, google_id))
            db.commit()
        except Exception:
            pass
        flash(f'Successfully linked {email}!', 'success')
        return redirect(url_for('settings_page'))

    # Set session
    session['user_id'] = user_id
    session['access_token'] = access_token
    session.pop('oauth_state', None)

    # Redirect to where they were going, or dashboard
    # Only redirect to safe page routes, not API endpoints
    next_url = session.pop('next_url', None)
    if next_url and '/api/' not in next_url and '/auth/' not in next_url:
        return redirect(next_url)
    return redirect(url_for('dashboard'))


@app.route('/auth/logout', methods=['POST', 'GET'])
def logout():
    """Logout — set user unavailable in all circles first."""
    user_id = session.get('user_id')
    if user_id:
        try:
            db = get_db()
            db.execute(
                'UPDATE availability SET available = 0, updated_at = CURRENT_TIMESTAMP WHERE user_id = ?',
                (user_id,)
            )
            db.commit()
        except Exception:
            pass
    session.clear()
    return redirect(url_for('login'))


# ============ DEV LOGIN (when OAuth not configured) ============

@app.route('/auth/dev-login', methods=['POST'])
def dev_login():
    """Development login when OAuth is not configured."""
    if OAUTH_CONFIGURED:
        return redirect(url_for('login'))

    name = request.form.get('name', '').strip()
    email = request.form.get('email', '').strip()

    if not name or not email:
        flash('Name and email are required.', 'error')
        return redirect(url_for('login'))

    db = get_db()
    existing = db.execute('SELECT id FROM users WHERE email = ?', (email,)).fetchone()

    if existing:
        user_id = existing['id']
        db.execute('UPDATE users SET name=? WHERE id=?', (name, user_id))
    else:
        cursor = db.execute('''
            INSERT INTO users (email, name, google_id) VALUES (?, ?, ?)
        ''', (email, name, f'dev_{email}'))
        user_id = cursor.lastrowid

    db.commit()
    session['user_id'] = user_id

    next_url = session.pop('next_url', None)
    if next_url:
        return redirect(next_url)
    return redirect(url_for('dashboard'))


# ============ MAIN ROUTES ============

@app.route('/')
def home():
    """Landing page."""
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('landing.html')


@app.route('/dashboard')
@login_required
def dashboard():
    """Main dashboard."""
    user = get_current_user()
    if not user:
        session.clear()
        return redirect(url_for('login'))
    db = get_db()

    # Get user's circles
    circles = db.execute('''
        SELECT c.*, cm.role,
            (SELECT COUNT(*) FROM circle_members WHERE circle_id = c.id) as member_count
        FROM circles c
        JOIN circle_members cm ON cm.circle_id = c.id AND cm.user_id = ?
        ORDER BY c.created_at DESC
    ''', (user['id'],)).fetchall()

    return render_template('dashboard.html', user=user, circles=circles)


@app.route('/circles/create', methods=['POST'])
@login_required
def create_circle():
    """Create a new circle."""
    user = get_current_user()
    data = request.json
    name = data.get('name', '').strip()

    if not name:
        return jsonify({'error': 'Circle name is required'}), 400

    # Check ADMIN_CODE if set
    admin_code = os.environ.get('ADMIN_CODE', '').strip()
    if admin_code:
        provided_code = data.get('admin_code', '').strip()
        if provided_code != admin_code:
            return jsonify({'error': 'Invalid admin code'}), 403

    code = generate_code()
    db = get_db()

    cursor = db.execute(
        'INSERT INTO circles (code, name, created_by) VALUES (?, ?, ?)',
        (code, name, user['id'])
    )
    circle_id = cursor.lastrowid

    # Add creator as admin
    db.execute(
        'INSERT INTO circle_members (circle_id, user_id, role) VALUES (?, ?, ?)',
        (circle_id, user['id'], 'admin')
    )

    # Initialize availability
    db.execute(
        'INSERT INTO availability (user_id, circle_id, available) VALUES (?, ?, 0)',
        (user['id'], circle_id)
    )

    db.commit()

    return jsonify({
        'success': True,
        'code': code,
        'name': name,
        'invite_link': url_for('join_page', code=code, _external=True)
    })


@app.route('/join/<code>')
def join_page(code):
    """Join page for a circle."""
    db = get_db()
    circle = db.execute('SELECT * FROM circles WHERE code = ?', (code,)).fetchone()
    if not circle:
        return render_template('error.html', message="Circle not found. Check your invite link."), 404

    user = get_current_user()

    if user:
        # Check if already a member
        existing = db.execute(
            'SELECT * FROM circle_members WHERE circle_id = ? AND user_id = ?',
            (circle['id'], user['id'])
        ).fetchone()
        if existing:
            return redirect(url_for('circle_view', code=code))

    member_count = db.execute(
        'SELECT COUNT(*) as cnt FROM circle_members WHERE circle_id = ?',
        (circle['id'],)
    ).fetchone()['cnt']

    return render_template('join.html', circle=circle, code=code,
                          user=user, member_count=member_count,
                          oauth_configured=OAUTH_CONFIGURED)


@app.route('/join/<code>/submit', methods=['POST'])
@login_required
def join_circle(code):
    """Join a circle."""
    user = get_current_user()
    db = get_db()

    circle = db.execute('SELECT * FROM circles WHERE code = ?', (code,)).fetchone()
    if not circle:
        return jsonify({'error': 'Circle not found'}), 404

    # Check if already member
    existing = db.execute(
        'SELECT * FROM circle_members WHERE circle_id = ? AND user_id = ?',
        (circle['id'], user['id'])
    ).fetchone()

    if existing:
        return jsonify({'success': True, 'redirect': url_for('circle_view', code=code)})

    # Get zoom link from request (required)
    data = request.json or {}
    zoom_link = data.get('zoom_link', '').strip()

    if not zoom_link and not user['zoom_link']:
        return jsonify({'error': 'Zoom link is required'}), 400

    if zoom_link and not user['zoom_link']:
        db.execute('UPDATE users SET zoom_link = ? WHERE id = ?', (zoom_link, user['id']))
    elif zoom_link:
        db.execute('UPDATE users SET zoom_link = ? WHERE id = ?', (zoom_link, user['id']))

    db.execute(
        'INSERT INTO circle_members (circle_id, user_id, role) VALUES (?, ?, ?)',
        (circle['id'], user['id'], 'member')
    )

    db.execute(
        'INSERT INTO availability (user_id, circle_id, available) VALUES (?, ?, 0)',
        (user['id'], circle['id'])
    )

    db.commit()

    return jsonify({'success': True, 'redirect': url_for('circle_view', code=code)})


@app.route('/c/<code>')
@login_required
def circle_view(code):
    """Main circle view."""
    user = get_current_user()
    db = get_db()

    if not user:
        session.clear()
        return redirect(url_for('login'))

    circle = db.execute('SELECT * FROM circles WHERE code = ?', (code,)).fetchone()
    if not circle:
        return render_template('error.html', message="Circle not found."), 404

    # Check membership
    membership = db.execute(
        'SELECT * FROM circle_members WHERE circle_id = ? AND user_id = ?',
        (circle['id'], user['id'])
    ).fetchone()

    if not membership:
        return redirect(url_for('join_page', code=code))

    return render_template('circle.html', circle=circle, user=user,
                          membership=membership, code=code)


@app.route('/settings')
@login_required
def settings_page():
    """User settings page."""
    user = get_current_user()
    if not user:
        session.clear()
        return redirect(url_for('login'))
    db = get_db()

    memberships = db.execute('''
        SELECT cm.*, c.name as circle_name, c.code as circle_code
        FROM circle_members cm
        JOIN circles c ON c.id = cm.circle_id
        WHERE cm.user_id = ?
    ''', (user['id'],)).fetchall()

    return render_template('settings.html', user=user, memberships=memberships)


# ============ API ROUTES ============

@app.route('/api/circle/<code>/status')
@login_required
def circle_status(code):
    """Get circle status with member availability, active sessions, and pending invites."""
    user = get_current_user()
    db = get_db()

    circle = db.execute('SELECT * FROM circles WHERE code = ?', (code,)).fetchone()
    if not circle:
        return jsonify({'error': 'Circle not found'}), 404

    # Auto-expire pending invites older than 60 seconds
    db.execute('''
        UPDATE roleplay_invites SET status = 'expired'
        WHERE status = 'pending' AND circle_id = ?
        AND created_at <= datetime('now', '-60 seconds')
    ''', (circle['id'],))
    db.commit()

    # Auto-timeout: if user has been available for 2+ hours with no activity, set unavailable
    auto_timed_out = False
    my_avail = db.execute(
        'SELECT available, updated_at FROM availability WHERE user_id = ? AND circle_id = ?',
        (user['id'], circle['id'])
    ).fetchone()
    if my_avail and my_avail['available']:
        updated_at = my_avail['updated_at']
        if updated_at:
            try:
                avail_time = datetime.strptime(updated_at, '%Y-%m-%d %H:%M:%S')
                if datetime.utcnow() - avail_time > timedelta(hours=2):
                    # Check for recent activity (invites sent/received or sessions)
                    recent_activity = db.execute('''
                        SELECT COUNT(*) as cnt FROM roleplay_invites
                        WHERE circle_id = ? AND (from_user_id = ? OR to_user_id = ?)
                        AND created_at >= datetime('now', '-2 hours')
                    ''', (circle['id'], user['id'], user['id'])).fetchone()['cnt']

                    recent_sessions = db.execute('''
                        SELECT COUNT(*) as cnt FROM active_sessions s
                        JOIN active_session_members m ON m.session_id = s.id
                        WHERE s.circle_id = ? AND m.user_id = ?
                        AND s.started_at >= datetime('now', '-2 hours')
                    ''', (circle['id'], user['id'])).fetchone()['cnt']

                    if recent_activity == 0 and recent_sessions == 0:
                        db.execute('''
                            UPDATE availability SET available = 0, updated_at = CURRENT_TIMESTAMP
                            WHERE user_id = ? AND circle_id = ?
                        ''', (user['id'], circle['id']))
                        db.commit()
                        auto_timed_out = True
            except (ValueError, TypeError):
                pass

    # Presence detection: auto-set stale users unavailable (last_seen > 30s ago)
    db.execute('''
        UPDATE availability SET available = 0, updated_at = CURRENT_TIMESTAMP
        WHERE circle_id = ? AND available = 1 AND user_id IN (
            SELECT cm.user_id FROM circle_members cm
            WHERE cm.circle_id = ? AND cm.last_seen IS NOT NULL
            AND cm.last_seen <= datetime('now', '-30 seconds')
        )
    ''', (circle['id'], circle['id']))

    # Also remove stale users from active sessions
    stale_session_members = db.execute('''
        SELECT asm.session_id, asm.user_id FROM active_session_members asm
        JOIN active_sessions s ON s.id = asm.session_id
        JOIN circle_members cm ON cm.circle_id = s.circle_id AND cm.user_id = asm.user_id
        WHERE s.circle_id = ? AND s.ended_at IS NULL
        AND cm.last_seen IS NOT NULL AND cm.last_seen <= datetime('now', '-30 seconds')
    ''', (circle['id'],)).fetchall()

    for stale in stale_session_members:
        db.execute('DELETE FROM active_session_members WHERE session_id = ? AND user_id = ?',
                   (stale['session_id'], stale['user_id']))
        # Check if session is now empty
        remaining = db.execute('SELECT COUNT(*) as cnt FROM active_session_members WHERE session_id = ?',
                               (stale['session_id'],)).fetchone()['cnt']
        if remaining == 0:
            # End the session and auto-log it
            sess = db.execute('SELECT * FROM active_sessions WHERE id = ?', (stale['session_id'],)).fetchone()
            if sess:
                db.execute('UPDATE active_sessions SET ended_at = CURRENT_TIMESTAMP WHERE id = ?', (stale['session_id'],))

    db.commit()

    # Get users currently in active sessions for this circle
    in_session_users = set()
    active_session_rows = db.execute('''
        SELECT s.id, s.zoom_link, s.started_at, s.started_by, m.user_id
        FROM active_sessions s
        JOIN active_session_members m ON m.session_id = s.id
        WHERE s.circle_id = ? AND s.ended_at IS NULL
    ''', (circle['id'],)).fetchall()
    for row in active_session_rows:
        in_session_users.add(row['user_id'])

    # Get members
    members = db.execute('''
        SELECT u.id, u.name, u.avatar_url, u.zoom_link,
               cm.start_hour, cm.end_hour, cm.role,
               COALESCE(a.available, 0) as available
        FROM circle_members cm
        JOIN users u ON u.id = cm.user_id
        LEFT JOIN availability a ON a.user_id = u.id AND a.circle_id = ?
        WHERE cm.circle_id = ?
        ORDER BY u.name
    ''', (circle['id'], circle['id'])).fetchall()

    member_list = []
    available_count = 0
    for m in members:
        tz = pytz.timezone('America/Chicago')
        now = datetime.now(tz)
        in_window = m['start_hour'] <= now.hour < m['end_hour']

        # Determine state: in_session, available, or unavailable
        if m['id'] in in_session_users:
            state = 'in_session'
        elif m['available']:
            state = 'available'
            available_count += 1
        else:
            state = 'unavailable'

        member_data = {
            'id': m['id'],
            'name': m['name'],
            'avatar_url': m['avatar_url'] or '',
            'zoom_link': m['zoom_link'] or '',
            'available': state == 'available',
            'state': state,
            'in_availability_window': in_window,
            'role': m['role'],
            'is_me': m['id'] == user['id'],
        }
        member_list.append(member_data)

    # Check current user's role
    my_membership = db.execute(
        'SELECT role FROM circle_members WHERE circle_id = ? AND user_id = ?',
        (circle['id'], user['id'])
    ).fetchone()
    is_admin = my_membership and my_membership['role'] == 'admin'

    # Build active sessions list
    active_sessions_map = {}
    for row in active_session_rows:
        sid = row['id']
        if sid not in active_sessions_map:
            active_sessions_map[sid] = {
                'id': sid,
                'zoom_link': row['zoom_link'],
                'started_at': row['started_at'],
                'started_by': row['started_by'],
                'members': [],
            }
        # Find member name
        for m in member_list:
            if m['id'] == row['user_id']:
                active_sessions_map[sid]['members'].append({
                    'id': m['id'],
                    'name': m['name'],
                    'is_me': m['is_me'],
                })
                break

    active_sessions_list = list(active_sessions_map.values())

    # Check if current user is in an active session
    my_active_session = None
    for s in active_sessions_list:
        for mem in s['members']:
            if mem['is_me']:
                my_active_session = s
                break
        if my_active_session:
            break

    # Get pending invites for current user (as recipient)
    pending_invites = db.execute('''
        SELECT ri.id, ri.from_user_id, ri.zoom_link, ri.created_at, u.name as from_name
        FROM roleplay_invites ri
        JOIN users u ON u.id = ri.from_user_id
        WHERE ri.to_user_id = ? AND ri.circle_id = ? AND ri.status = 'pending'
        ORDER BY ri.created_at DESC
    ''', (user['id'], circle['id'])).fetchall()

    pending_invites_list = [{
        'id': inv['id'],
        'from_user_id': inv['from_user_id'],
        'from_name': inv['from_name'],
        'zoom_link': inv['zoom_link'],
        'created_at': inv['created_at'],
    } for inv in pending_invites]

    # Get pending invites sent by current user (to show "waiting" state)
    sent_pending = db.execute('''
        SELECT ri.id, ri.to_user_id, ri.created_at, u.name as to_name
        FROM roleplay_invites ri
        JOIN users u ON u.id = ri.to_user_id
        WHERE ri.from_user_id = ? AND ri.circle_id = ? AND ri.status = 'pending'
        ORDER BY ri.created_at DESC
    ''', (user['id'], circle['id'])).fetchall()

    sent_pending_list = [{
        'id': inv['id'],
        'to_user_id': inv['to_user_id'],
        'to_name': inv['to_name'],
        'created_at': inv['created_at'],
    } for inv in sent_pending]

    # Re-fetch my availability (may have been auto-timed-out)
    my_avail = db.execute(
        'SELECT available FROM availability WHERE user_id = ? AND circle_id = ?',
        (user['id'], circle['id'])
    ).fetchone()

    return jsonify({
        'circle_name': circle['name'],
        'circle_code': code,
        'members': member_list,
        'available_count': available_count,
        'my_available': bool(my_avail['available']) if my_avail else False,
        'group_session_ready': available_count >= 2,
        'active_sessions': active_sessions_list,
        'my_active_session': my_active_session,
        'pending_invites': pending_invites_list,
        'sent_pending_invites': sent_pending_list,
        'auto_timed_out': auto_timed_out,
        'max_session_size': circle['max_session_size'] if 'max_session_size' in circle.keys() else 4,
        'is_admin': is_admin,
    })


@app.route('/api/circle/<code>/available', methods=['POST'])
@login_required
def toggle_available(code):
    """Toggle availability."""
    user = get_current_user()
    db = get_db()

    circle = db.execute('SELECT * FROM circles WHERE code = ?', (code,)).fetchone()
    if not circle:
        return jsonify({'error': 'Circle not found'}), 404

    data = request.json or {}
    available = data.get('available', True)

    # Check zoom link when going available
    if available and not user['zoom_link']:
        return jsonify({'error': 'Add your Zoom link in Settings first'}), 400

    db.execute('''
        INSERT INTO availability (user_id, circle_id, available, updated_at)
        VALUES (?, ?, ?, CURRENT_TIMESTAMP)
        ON CONFLICT(user_id, circle_id)
        DO UPDATE SET available = ?, updated_at = CURRENT_TIMESTAMP
    ''', (user['id'], circle['id'], int(available), int(available)))
    db.commit()

    return jsonify({'success': True, 'available': available})


@app.route('/api/circle/<code>/noshow', methods=['POST'])
@login_required
def mark_noshow(code):
    """Mark a calendar event as no-show."""
    user = get_current_user()
    db = get_db()

    circle = db.execute('SELECT * FROM circles WHERE code = ?', (code,)).fetchone()
    if not circle:
        return jsonify({'error': 'Circle not found'}), 404

    data = request.json or {}
    event_uid = data.get('event_uid', '')
    event_summary = data.get('event_summary', '')

    db.execute(
        'INSERT INTO noshow_events (user_id, circle_id, event_uid, event_summary) VALUES (?, ?, ?, ?)',
        (user['id'], circle['id'], event_uid, event_summary)
    )

    # Also set available
    db.execute('''
        INSERT INTO availability (user_id, circle_id, available, updated_at)
        VALUES (?, ?, 1, CURRENT_TIMESTAMP)
        ON CONFLICT(user_id, circle_id)
        DO UPDATE SET available = 1, updated_at = CURRENT_TIMESTAMP
    ''', (user['id'], circle['id']))

    db.commit()

    return jsonify({'success': True})


@app.route('/api/circle/<code>/log-session', methods=['POST'])
@login_required
def log_session(code):
    """Log a roleplay session."""
    user = get_current_user()
    db = get_db()

    circle = db.execute('SELECT * FROM circles WHERE code = ?', (code,)).fetchone()
    if not circle:
        return jsonify({'error': 'Circle not found'}), 404

    data = request.json or {}
    partner_id = data.get('partner_id')
    duration = data.get('duration_minutes', 15)
    rating = data.get('rating', 0)
    notes = data.get('notes', '')

    if not partner_id:
        return jsonify({'error': 'Partner is required'}), 400

    # Verify partner is in circle
    partner = db.execute(
        'SELECT user_id FROM circle_members WHERE circle_id = ? AND user_id = ?',
        (circle['id'], partner_id)
    ).fetchone()
    if not partner:
        return jsonify({'error': 'Partner not in this circle'}), 400

    db.execute('''
        INSERT INTO sessions (circle_id, user1_id, user2_id, duration_minutes, rating, notes)
        VALUES (?, ?, ?, ?, ?, ?)
    ''', (circle['id'], user['id'], partner_id, duration, rating, notes))

    # Set both users as unavailable after logging session
    db.execute('''
        UPDATE availability SET available = 0, updated_at = CURRENT_TIMESTAMP
        WHERE circle_id = ? AND user_id IN (?, ?)
    ''', (circle['id'], user['id'], partner_id))

    db.commit()

    return jsonify({'success': True})


@app.route('/api/circle/<code>/send-invite', methods=['POST'])
@login_required
def send_invite(code):
    """Send a roleplay invite to another user."""
    user = get_current_user()
    db = get_db()

    circle = db.execute('SELECT * FROM circles WHERE code = ?', (code,)).fetchone()
    if not circle:
        return jsonify({'error': 'Circle not found'}), 404

    data = request.json or {}
    to_user_id = data.get('to_user_id')

    if not to_user_id:
        return jsonify({'error': 'Target user is required'}), 400

    if to_user_id == user['id']:
        return jsonify({'error': "Can't invite yourself"}), 400

    # Verify target is in circle and available
    target_avail = db.execute(
        'SELECT available FROM availability WHERE user_id = ? AND circle_id = ?',
        (to_user_id, circle['id'])
    ).fetchone()
    if not target_avail or not target_avail['available']:
        return jsonify({'error': 'User is not available'}), 400

    # Check target is not in active session
    in_session = db.execute('''
        SELECT COUNT(*) as cnt FROM active_session_members m
        JOIN active_sessions s ON s.id = m.session_id
        WHERE m.user_id = ? AND s.circle_id = ? AND s.ended_at IS NULL
    ''', (to_user_id, circle['id'])).fetchone()['cnt']
    if in_session:
        return jsonify({'error': 'User is already in a session'}), 400

    # Expire any existing pending invites from this user in this circle
    db.execute('''
        UPDATE roleplay_invites SET status = 'expired'
        WHERE from_user_id = ? AND circle_id = ? AND status = 'pending'
    ''', (user['id'], circle['id']))

    # Use inviter's zoom link
    zoom_link = user['zoom_link'] or ''

    cursor = db.execute('''
        INSERT INTO roleplay_invites (circle_id, from_user_id, to_user_id, status, zoom_link)
        VALUES (?, ?, ?, 'pending', ?)
    ''', (circle['id'], user['id'], to_user_id, zoom_link))
    db.commit()

    # Touch the inviter's availability updated_at to prevent auto-timeout
    db.execute('''
        UPDATE availability SET updated_at = CURRENT_TIMESTAMP
        WHERE user_id = ? AND circle_id = ?
    ''', (user['id'], circle['id']))
    db.commit()

    return jsonify({'success': True, 'invite_id': cursor.lastrowid})


@app.route('/api/circle/<code>/respond-invite', methods=['POST'])
@login_required
def respond_invite(code):
    """Accept or decline a roleplay invite."""
    user = get_current_user()
    db = get_db()

    circle = db.execute('SELECT * FROM circles WHERE code = ?', (code,)).fetchone()
    if not circle:
        return jsonify({'error': 'Circle not found'}), 404

    data = request.json or {}
    invite_id = data.get('invite_id')
    response = data.get('response')  # 'accept' or 'decline'
    decline_reason = data.get('decline_reason', '')

    if not invite_id or response not in ('accept', 'decline'):
        return jsonify({'error': 'Invalid request'}), 400

    invite = db.execute('''
        SELECT * FROM roleplay_invites WHERE id = ? AND to_user_id = ? AND circle_id = ? AND status = 'pending'
    ''', (invite_id, user['id'], circle['id'])).fetchone()

    if not invite:
        return jsonify({'error': 'Invite not found or already responded'}), 404

    if response == 'decline':
        db.execute('''
            UPDATE roleplay_invites SET status = 'declined', decline_reason = ?, responded_at = CURRENT_TIMESTAMP
            WHERE id = ?
        ''', (decline_reason, invite_id))
        db.commit()
        return jsonify({'success': True, 'status': 'declined'})

    # Accept — create active session
    db.execute('''
        UPDATE roleplay_invites SET status = 'accepted', responded_at = CURRENT_TIMESTAMP
        WHERE id = ?
    ''', (invite_id,))

    zoom_link = invite['zoom_link']

    # Create active session (started_by is the inviter)
    cursor = db.execute('''
        INSERT INTO active_sessions (circle_id, zoom_link, started_by) VALUES (?, ?, ?)
    ''', (circle['id'], zoom_link, invite['from_user_id']))
    session_id = cursor.lastrowid

    # Add both users
    db.execute('''
        INSERT INTO active_session_members (session_id, user_id) VALUES (?, ?)
    ''', (session_id, invite['from_user_id']))
    db.execute('''
        INSERT INTO active_session_members (session_id, user_id) VALUES (?, ?)
    ''', (session_id, user['id']))

    # Set both users' availability to "available=1" but they'll show as in_session due to active_session_members
    # Actually keep them available=1 so when session ends they can quickly go back
    # Touch updated_at for both to prevent auto-timeout
    db.execute('''
        UPDATE availability SET updated_at = CURRENT_TIMESTAMP
        WHERE circle_id = ? AND user_id IN (?, ?)
    ''', (circle['id'], user['id'], invite['from_user_id']))

    db.commit()

    return jsonify({
        'success': True,
        'status': 'accepted',
        'session_id': session_id,
        'zoom_link': zoom_link,
    })


@app.route('/api/circle/<code>/join-session', methods=['POST'])
@login_required
def join_session(code):
    """Join an existing active session."""
    user = get_current_user()
    db = get_db()

    circle = db.execute('SELECT * FROM circles WHERE code = ?', (code,)).fetchone()
    if not circle:
        return jsonify({'error': 'Circle not found'}), 404

    data = request.json or {}
    session_id = data.get('session_id')

    if not session_id:
        return jsonify({'error': 'Session ID is required'}), 400

    active_sess = db.execute('''
        SELECT * FROM active_sessions WHERE id = ? AND circle_id = ? AND ended_at IS NULL
    ''', (session_id, circle['id'])).fetchone()

    if not active_sess:
        return jsonify({'error': 'Session not found or already ended'}), 404

    # Check max session size
    max_size = circle['max_session_size'] if 'max_session_size' in circle.keys() else 4
    current_count = db.execute(
        'SELECT COUNT(*) as cnt FROM active_session_members WHERE session_id = ?',
        (session_id,)
    ).fetchone()['cnt']

    # Check if already in session
    existing = db.execute('''
        SELECT * FROM active_session_members WHERE session_id = ? AND user_id = ?
    ''', (session_id, user['id'])).fetchone()

    if not existing:
        if current_count >= max_size:
            return jsonify({'error': f'Session is full ({current_count}/{max_size})'}), 400
        db.execute('''
            INSERT INTO active_session_members (session_id, user_id) VALUES (?, ?)
        ''', (session_id, user['id']))

    # Touch availability to prevent auto-timeout
    db.execute('''
        UPDATE availability SET updated_at = CURRENT_TIMESTAMP
        WHERE user_id = ? AND circle_id = ?
    ''', (user['id'], circle['id']))

    db.commit()

    return jsonify({
        'success': True,
        'zoom_link': active_sess['zoom_link'],
    })


@app.route('/api/circle/<code>/end-session', methods=['POST'])
@login_required
def end_session(code):
    """End an active session. Auto-logs it."""
    user = get_current_user()
    db = get_db()

    circle = db.execute('SELECT * FROM circles WHERE code = ?', (code,)).fetchone()
    if not circle:
        return jsonify({'error': 'Circle not found'}), 404

    data = request.json or {}
    session_id = data.get('session_id')
    go_available = data.get('go_available', False)
    notes = data.get('notes', '')
    rating = data.get('rating', 0)

    if not session_id:
        return jsonify({'error': 'Session ID is required'}), 400

    active_sess = db.execute('''
        SELECT * FROM active_sessions WHERE id = ? AND circle_id = ? AND ended_at IS NULL
    ''', (session_id, circle['id'])).fetchone()

    if not active_sess:
        return jsonify({'error': 'Session not found or already ended'}), 404

    # Verify user is in session
    membership = db.execute('''
        SELECT * FROM active_session_members WHERE session_id = ? AND user_id = ?
    ''', (session_id, user['id'])).fetchone()
    if not membership:
        return jsonify({'error': 'You are not in this session'}), 400

    # End the session
    db.execute('''
        UPDATE active_sessions SET ended_at = CURRENT_TIMESTAMP WHERE id = ?
    ''', (session_id,))

    # Calculate duration
    started_at = datetime.strptime(active_sess['started_at'], '%Y-%m-%d %H:%M:%S')
    duration_minutes = max(1, int((datetime.utcnow() - started_at).total_seconds() / 60))

    # Get all members in session
    session_members = db.execute('''
        SELECT user_id FROM active_session_members WHERE session_id = ?
    ''', (session_id,)).fetchall()

    member_ids = [m['user_id'] for m in session_members]

    # Log session for each pair of participants
    for i in range(len(member_ids)):
        for j in range(i + 1, len(member_ids)):
            db.execute('''
                INSERT INTO sessions (circle_id, user1_id, user2_id, duration_minutes, rating, notes)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (circle['id'], member_ids[i], member_ids[j], duration_minutes, rating, notes))

    # Handle availability for all session members
    if go_available:
        # Only set the requesting user available
        db.execute('''
            UPDATE availability SET available = 1, updated_at = CURRENT_TIMESTAMP
            WHERE user_id = ? AND circle_id = ?
        ''', (user['id'], circle['id']))
    else:
        db.execute('''
            UPDATE availability SET available = 0, updated_at = CURRENT_TIMESTAMP
            WHERE user_id = ? AND circle_id = ?
        ''', (user['id'], circle['id']))

    db.commit()

    return jsonify({
        'success': True,
        'duration_minutes': duration_minutes,
    })


@app.route('/api/circle/<code>/cancel-invite', methods=['POST'])
@login_required
def cancel_invite(code):
    """Cancel a pending invite that you sent."""
    user = get_current_user()
    db = get_db()

    circle = db.execute('SELECT * FROM circles WHERE code = ?', (code,)).fetchone()
    if not circle:
        return jsonify({'error': 'Circle not found'}), 404

    data = request.json or {}
    invite_id = data.get('invite_id')

    if not invite_id:
        return jsonify({'error': 'Invite ID is required'}), 400

    db.execute('''
        UPDATE roleplay_invites SET status = 'expired'
        WHERE id = ? AND from_user_id = ? AND circle_id = ? AND status = 'pending'
    ''', (invite_id, user['id'], circle['id']))
    db.commit()

    return jsonify({'success': True})


@app.route('/api/circle/<code>/stats')
@login_required
def circle_stats(code):
    """Get circle statistics."""
    user = get_current_user()
    db = get_db()

    circle = db.execute('SELECT * FROM circles WHERE code = ?', (code,)).fetchone()
    if not circle:
        return jsonify({'error': 'Circle not found'}), 404

    # Total sessions for circle
    total = db.execute(
        'SELECT COUNT(*) as cnt FROM sessions WHERE circle_id = ?',
        (circle['id'],)
    ).fetchone()['cnt']

    # Sessions this week
    week_ago = (datetime.now() - timedelta(days=7)).isoformat()
    this_week = db.execute(
        'SELECT COUNT(*) as cnt FROM sessions WHERE circle_id = ? AND created_at >= ?',
        (circle['id'], week_ago)
    ).fetchone()['cnt']

    # My sessions
    my_total = db.execute('''
        SELECT COUNT(*) as cnt FROM sessions
        WHERE circle_id = ? AND (user1_id = ? OR user2_id = ?)
    ''', (circle['id'], user['id'], user['id'])).fetchone()['cnt']

    my_this_week = db.execute('''
        SELECT COUNT(*) as cnt FROM sessions
        WHERE circle_id = ? AND (user1_id = ? OR user2_id = ?) AND created_at >= ?
    ''', (circle['id'], user['id'], user['id'], week_ago)).fetchone()['cnt']

    # Leaderboard
    leaderboard = db.execute('''
        SELECT u.id, u.name, u.avatar_url, COUNT(*) as session_count
        FROM (
            SELECT user1_id as uid, circle_id FROM sessions
            UNION ALL
            SELECT user2_id as uid, circle_id FROM sessions
        ) s
        JOIN users u ON u.id = s.uid
        WHERE s.circle_id = ?
        GROUP BY u.id
        ORDER BY session_count DESC
        LIMIT 10
    ''', (circle['id'],)).fetchall()

    leaderboard_list = [
        {'id': r['id'], 'name': r['name'], 'avatar_url': r['avatar_url'] or '',
         'sessions': r['session_count'], 'is_me': r['id'] == user['id']}
        for r in leaderboard
    ]

    # Streak calculation (consecutive days with sessions)
    my_session_dates = db.execute('''
        SELECT DISTINCT DATE(created_at) as d FROM sessions
        WHERE circle_id = ? AND (user1_id = ? OR user2_id = ?)
        ORDER BY d DESC
    ''', (circle['id'], user['id'], user['id'])).fetchall()

    streak = 0
    if my_session_dates:
        today = datetime.now().date()
        expected = today
        for row in my_session_dates:
            session_date = datetime.strptime(row['d'], '%Y-%m-%d').date()
            if session_date == expected:
                streak += 1
                expected -= timedelta(days=1)
            elif session_date == expected - timedelta(days=1):
                # Allow for today not having a session yet
                if streak == 0:
                    expected = session_date
                    streak += 1
                    expected -= timedelta(days=1)
                else:
                    break
            else:
                break

    # No-show count
    noshow_count = db.execute(
        'SELECT COUNT(*) as cnt FROM noshow_events WHERE circle_id = ? AND user_id = ?',
        (circle['id'], user['id'])
    ).fetchone()['cnt']

    return jsonify({
        'total_sessions': total,
        'sessions_this_week': this_week,
        'my_total_sessions': my_total,
        'my_sessions_this_week': my_this_week,
        'my_streak': streak,
        'my_noshows': noshow_count,
        'leaderboard': leaderboard_list,
    })


@app.route('/auth/link-google')
@login_required
def link_google_account():
    """Start OAuth flow to link an additional Google account."""
    if not OAUTH_CONFIGURED:
        flash('Google OAuth is not configured.', 'error')
        return redirect(url_for('settings_page'))

    state = secrets.token_urlsafe(32)
    session['oauth_state'] = state
    session['linking_account'] = True  # Flag so callback knows this is a link, not login

    params = {
        'client_id': GOOGLE_CLIENT_ID,
        'redirect_uri': get_oauth_redirect_uri(),
        'response_type': 'code',
        'scope': ' '.join(SCOPES),
        'state': state,
        'access_type': 'offline',
        'prompt': 'consent select_account',  # Force account picker
    }

    auth_url = GOOGLE_AUTH_URI + '?' + '&'.join(f'{k}={v}' for k, v in params.items())
    return redirect(auth_url)


@app.route('/api/linked-accounts')
@login_required
def list_linked_accounts():
    """List all linked Google accounts."""
    user = get_current_user()
    db = get_db()

    accounts = db.execute(
        'SELECT id, email, name, is_primary, created_at FROM linked_google_accounts WHERE user_id = ? ORDER BY is_primary DESC, created_at',
        (user['id'],)
    ).fetchall()

    return jsonify({
        'accounts': [{'id': a['id'], 'email': a['email'], 'name': a['name'],
                       'is_primary': bool(a['is_primary'])} for a in accounts]
    })


@app.route('/api/linked-accounts/<int:account_id>', methods=['DELETE'])
@login_required
def remove_linked_account(account_id):
    """Remove a linked Google account (can't remove primary)."""
    user = get_current_user()
    db = get_db()

    account = db.execute(
        'SELECT * FROM linked_google_accounts WHERE id = ? AND user_id = ?',
        (account_id, user['id'])
    ).fetchone()

    if not account:
        return jsonify({'error': 'Account not found'}), 404

    if account['is_primary']:
        return jsonify({'error': "Can't remove your primary account"}), 400

    # Remove associated calendars
    db.execute(
        'DELETE FROM user_calendars WHERE user_id = ? AND account_id = ?',
        (user['id'], account_id)
    )
    db.execute(
        'DELETE FROM linked_google_accounts WHERE id = ? AND user_id = ?',
        (account_id, user['id'])
    )
    db.commit()

    return jsonify({'success': True})


# ============ EXTERNAL ICS CALENDARS ============

@app.route('/api/external-calendars')
@login_required
def list_external_calendars():
    """List external ICS calendars."""
    user = get_current_user()
    db = get_db()

    cals = db.execute(
        'SELECT * FROM external_calendars WHERE user_id = ? ORDER BY created_at',
        (user['id'],)
    ).fetchall()

    return jsonify({
        'calendars': [{'id': c['id'], 'name': c['name'], 'ics_url': c['ics_url'],
                        'selected': bool(c['selected']), 'color': c['color']} for c in cals]
    })


@app.route('/api/external-calendars', methods=['POST'])
@login_required
def add_external_calendar():
    """Add an external ICS calendar."""
    user = get_current_user()
    db = get_db()
    data = request.json or {}

    name = data.get('name', '').strip()
    ics_url = data.get('ics_url', '').strip()

    if not name or not ics_url:
        return jsonify({'error': 'Name and ICS URL are required'}), 400

    # Validate the ICS URL by trying to fetch it
    try:
        resp = http_requests.get(ics_url, timeout=10)
        resp.raise_for_status()
        if 'VCALENDAR' not in resp.text[:500]:
            return jsonify({'error': 'URL does not appear to be a valid ICS calendar'}), 400
    except Exception as e:
        return jsonify({'error': f'Could not fetch calendar: {str(e)}'}), 400

    cursor = db.execute(
        'INSERT INTO external_calendars (user_id, name, ics_url) VALUES (?, ?, ?)',
        (user['id'], name, ics_url)
    )
    db.commit()

    return jsonify({'success': True, 'id': cursor.lastrowid})


@app.route('/api/external-calendars/<int:cal_id>', methods=['PUT'])
@login_required
def update_external_calendar(cal_id):
    """Update an external ICS calendar."""
    user = get_current_user()
    db = get_db()
    data = request.json or {}

    cal = db.execute(
        'SELECT * FROM external_calendars WHERE id = ? AND user_id = ?',
        (cal_id, user['id'])
    ).fetchone()

    if not cal:
        return jsonify({'error': 'Calendar not found'}), 404

    if 'name' in data:
        db.execute('UPDATE external_calendars SET name = ? WHERE id = ?', (data['name'], cal_id))
    if 'ics_url' in data:
        db.execute('UPDATE external_calendars SET ics_url = ? WHERE id = ?', (data['ics_url'], cal_id))
    if 'selected' in data:
        db.execute('UPDATE external_calendars SET selected = ? WHERE id = ?', (1 if data['selected'] else 0, cal_id))
    if 'color' in data:
        db.execute('UPDATE external_calendars SET color = ? WHERE id = ?', (data['color'], cal_id))

    db.commit()
    return jsonify({'success': True})


@app.route('/api/external-calendars/<int:cal_id>', methods=['DELETE'])
@login_required
def delete_external_calendar(cal_id):
    """Delete an external ICS calendar."""
    user = get_current_user()
    db = get_db()

    db.execute(
        'DELETE FROM external_calendars WHERE id = ? AND user_id = ?',
        (cal_id, user['id'])
    )
    db.commit()

    return jsonify({'success': True})


# ============ GOOGLE CALENDARS ============

@app.route('/api/calendars')
@login_required
def list_calendars():
    """List all Google Calendars from all linked accounts + external ICS calendars."""
    user = get_current_user()
    db = get_db()

    # Get saved selections from DB
    saved = db.execute(
        'SELECT calendar_id, selected FROM user_calendars WHERE user_id = ?',
        (user['id'],)
    ).fetchall()
    saved_map = {r['calendar_id']: bool(r['selected']) for r in saved}
    has_saved = len(saved_map) > 0

    # Get all linked Google accounts
    accounts = db.execute(
        'SELECT * FROM linked_google_accounts WHERE user_id = ? ORDER BY is_primary DESC',
        (user['id'],)
    ).fetchall()

    # Fall back to session token if no linked accounts yet
    if not accounts:
        access_token = session.get('access_token')
        if access_token:
            accounts = [{'id': 0, 'email': user['email'], 'access_token': access_token, 'is_primary': 1}]

    calendars = []

    for account in accounts:
        token = account['access_token'] if hasattr(account, '__getitem__') and isinstance(account, sqlite3.Row) else account.get('access_token', '')
        acct_email = account['email'] if hasattr(account, '__getitem__') and isinstance(account, sqlite3.Row) else account.get('email', '')
        acct_id = account['id'] if hasattr(account, '__getitem__') and isinstance(account, sqlite3.Row) else account.get('id', 0)

        if not token:
            continue

        try:
            resp = http_requests.get(
                f'{GOOGLE_CALENDAR_API}/users/me/calendarList',
                headers={'Authorization': f'Bearer {token}'},
                timeout=10
            )

            if resp.status_code == 401:
                # Try refresh if we have a refresh token
                # For now, skip this account
                continue

            if resp.status_code != 200:
                continue

            data = resp.json()

            for item in data.get('items', []):
                cal_id = item.get('id', '')
                summary = item.get('summary', cal_id)
                color = item.get('backgroundColor', '')
                access_role = item.get('accessRole', '')

                if has_saved:
                    selected = saved_map.get(cal_id, False)
                else:
                    selected = item.get('primary', False) or access_role == 'owner'

                calendars.append({
                    'id': cal_id,
                    'summary': summary,
                    'color': color,
                    'primary': item.get('primary', False),
                    'access_role': access_role,
                    'selected': selected,
                    'account_email': acct_email,
                    'account_id': acct_id,
                    'source': 'google',
                })
        except Exception:
            continue

    # Add external ICS calendars
    ext_cals = db.execute(
        'SELECT * FROM external_calendars WHERE user_id = ?',
        (user['id'],)
    ).fetchall()

    for ec in ext_cals:
        calendars.append({
            'id': f'ics_{ec["id"]}',
            'summary': ec['name'],
            'color': ec['color'],
            'primary': False,
            'access_role': 'external',
            'selected': bool(ec['selected']),
            'account_email': 'External (ICS)',
            'account_id': None,
            'source': 'ics',
            'ics_id': ec['id'],
        })

    # Sort: primary first, then by account, then by name
    calendars.sort(key=lambda c: (not c.get('primary', False), c.get('account_email', '').lower(), c.get('summary', '').lower()))

    return jsonify({'calendars': calendars})


@app.route('/api/calendars/select', methods=['POST'])
@login_required
def select_calendars():
    """Save which calendars the user wants to use for availability."""
    user = get_current_user()
    db = get_db()
    data = request.json or {}

    selections = data.get('calendars', [])
    # selections = [{'id': 'cal_id', 'summary': 'Name', 'selected': true/false}, ...]

    for cal in selections:
        cal_id = cal.get('id', '')
        summary = cal.get('summary', '')
        selected = 1 if cal.get('selected', False) else 0
        color = cal.get('color', '')
        account_id = cal.get('account_id')
        source = cal.get('source', 'google')

        # Handle external ICS calendar toggle
        if source == 'ics' and cal.get('ics_id'):
            db.execute(
                'UPDATE external_calendars SET selected = ? WHERE id = ? AND user_id = ?',
                (selected, cal['ics_id'], user['id'])
            )
            continue

        db.execute('''
            INSERT INTO user_calendars (user_id, calendar_id, summary, selected, color, account_id)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(user_id, calendar_id)
            DO UPDATE SET summary = ?, selected = ?, color = ?, account_id = ?
        ''', (user['id'], cal_id, summary, selected, color, account_id,
              summary, selected, color, account_id))

    db.commit()
    return jsonify({'success': True})


@app.route('/api/circle/<code>/calendar')
@login_required
def get_calendar_events(code):
    """Get today's events from all selected Google calendars + external ICS calendars."""
    user = get_current_user()
    db = get_db()

    try:
        tz = pytz.timezone(user['timezone'] or 'America/Chicago')
        now = datetime.now(tz)
        start_of_day = now.replace(hour=0, minute=0, second=0, microsecond=0)
        end_of_day = start_of_day + timedelta(days=1)

        all_events = []

        # ---- Google Calendar events ----
        # Get selected Google calendars
        selected_cals = db.execute(
            'SELECT calendar_id, summary, account_id FROM user_calendars WHERE user_id = ? AND selected = 1',
            (user['id'],)
        ).fetchall()

        # Build a map of account_id -> access_token
        accounts = db.execute(
            'SELECT id, access_token, email FROM linked_google_accounts WHERE user_id = ?',
            (user['id'],)
        ).fetchall()
        token_map = {a['id']: a['access_token'] for a in accounts}

        # Fall back to session token
        session_token = session.get('access_token')

        if selected_cals:
            for cal in selected_cals:
                cal_id = cal['calendar_id']
                cal_name = cal['summary'] or cal_id
                acct_id = cal['account_id']

                # Get the right token for this calendar's account
                token = token_map.get(acct_id, session_token) if acct_id else session_token
                if not token:
                    continue

                try:
                    resp = http_requests.get(
                        f'{GOOGLE_CALENDAR_API}/calendars/{cal_id}/events',
                        headers={'Authorization': f'Bearer {token}'},
                        params={
                            'timeMin': start_of_day.isoformat(),
                            'timeMax': end_of_day.isoformat(),
                            'singleEvents': 'true',
                            'orderBy': 'startTime',
                            'maxResults': 20,
                        },
                        timeout=10
                    )

                    if resp.status_code not in (200, 401):
                        continue
                    if resp.status_code == 401:
                        continue

                    data = resp.json()
                    for item in data.get('items', []):
                        start = item.get('start', {})
                        end = item.get('end', {})
                        start_time = start.get('dateTime', start.get('date', ''))
                        end_time = end.get('dateTime', end.get('date', ''))

                        needs_noshow = False
                        if start_time and 'T' in start_time:
                            try:
                                from dateutil import parser as dp
                                event_start = dp.parse(start_time)
                                if event_start.tzinfo is None:
                                    event_start = tz.localize(event_start)
                                mins_since = (now - event_start).total_seconds() / 60
                                needs_noshow = 0 < mins_since < 60 and mins_since >= 10
                            except:
                                pass

                        all_events.append({
                            'uid': item.get('id', ''),
                            'summary': item.get('summary', 'No Title'),
                            'start': start_time,
                            'end': end_time,
                            'start_time': format_time(start_time),
                            'end_time': format_time(end_time),
                            'needs_noshow_prompt': needs_noshow,
                            'attendees': len(item.get('attendees', [])),
                            'status': item.get('status', ''),
                            'calendar': cal_name,
                            'source': 'google',
                        })
                except Exception:
                    continue
        elif session_token:
            # No saved preferences — pull from primary calendar
            try:
                resp = http_requests.get(
                    f'{GOOGLE_CALENDAR_API}/calendars/primary/events',
                    headers={'Authorization': f'Bearer {session_token}'},
                    params={
                        'timeMin': start_of_day.isoformat(),
                        'timeMax': end_of_day.isoformat(),
                        'singleEvents': 'true',
                        'orderBy': 'startTime',
                        'maxResults': 20,
                    },
                    timeout=10
                )
                if resp.status_code == 200:
                    data = resp.json()
                    for item in data.get('items', []):
                        start = item.get('start', {})
                        end = item.get('end', {})
                        start_time = start.get('dateTime', start.get('date', ''))
                        end_time = end.get('dateTime', end.get('date', ''))
                        needs_noshow = False
                        if start_time and 'T' in start_time:
                            try:
                                from dateutil import parser as dp
                                event_start = dp.parse(start_time)
                                if event_start.tzinfo is None:
                                    event_start = tz.localize(event_start)
                                mins_since = (now - event_start).total_seconds() / 60
                                needs_noshow = 0 < mins_since < 60 and mins_since >= 10
                            except:
                                pass
                        all_events.append({
                            'uid': item.get('id', ''),
                            'summary': item.get('summary', 'No Title'),
                            'start': start_time,
                            'end': end_time,
                            'start_time': format_time(start_time),
                            'end_time': format_time(end_time),
                            'needs_noshow_prompt': needs_noshow,
                            'attendees': len(item.get('attendees', [])),
                            'status': item.get('status', ''),
                            'calendar': 'Primary',
                            'source': 'google',
                        })
            except Exception:
                pass

        # ---- External ICS calendar events ----
        ext_cals = db.execute(
            'SELECT * FROM external_calendars WHERE user_id = ? AND selected = 1',
            (user['id'],)
        ).fetchall()

        for ec in ext_cals:
            try:
                resp = http_requests.get(ec['ics_url'], timeout=10)
                resp.raise_for_status()

                from icalendar import Calendar as iCal
                cal = iCal.from_ical(resp.content)
                today = now.date()

                for component in cal.walk():
                    if component.name == "VEVENT":
                        dtstart = component.get('dtstart')
                        if not dtstart:
                            continue
                        event_start = dtstart.dt

                        if isinstance(event_start, datetime):
                            if event_start.tzinfo is None:
                                event_start = tz.localize(event_start)
                            else:
                                event_start = event_start.astimezone(tz)

                            if event_start.date() != today:
                                continue

                            dtend = component.get('dtend')
                            event_end = dtend.dt if dtend else event_start + timedelta(hours=1)
                            if isinstance(event_end, datetime):
                                if event_end.tzinfo is None:
                                    event_end = tz.localize(event_end)
                                else:
                                    event_end = event_end.astimezone(tz)

                            summary = str(component.get('summary', 'No Title'))
                            uid = str(component.get('uid', ''))

                            mins_since = (now - event_start).total_seconds() / 60
                            needs_noshow = 0 < mins_since < 60 and mins_since >= 10

                            all_events.append({
                                'uid': uid,
                                'summary': summary,
                                'start': event_start.isoformat(),
                                'end': event_end.isoformat(),
                                'start_time': event_start.strftime('%I:%M %p'),
                                'end_time': event_end.strftime('%I:%M %p'),
                                'needs_noshow_prompt': needs_noshow,
                                'attendees': 0,
                                'status': '',
                                'calendar': ec['name'],
                                'source': 'ics',
                            })
            except Exception:
                continue

        # Filter out past events — only show upcoming + no-show candidates
        filtered_events = []
        for evt in all_events:
            # Always show no-show candidates
            if evt.get('needs_noshow_prompt'):
                filtered_events.append(evt)
                continue
            # Show events that haven't ended yet
            end_str = evt.get('end', '')
            if end_str and 'T' in end_str:
                try:
                    from dateutil import parser as dp
                    event_end = dp.parse(end_str)
                    if event_end.tzinfo is None:
                        event_end = tz.localize(event_end)
                    else:
                        event_end = event_end.astimezone(tz)
                    if event_end >= now:
                        filtered_events.append(evt)
                except:
                    filtered_events.append(evt)
            else:
                # All-day events or unparseable — include them
                filtered_events.append(evt)

        # Sort by start time
        filtered_events.sort(key=lambda e: e.get('start', ''))

        return jsonify({'events': filtered_events})

    except Exception as e:
        return jsonify({'events': [], 'error': str(e)})


def format_time(iso_str):
    """Format ISO time string to readable time."""
    if not iso_str or 'T' not in iso_str:
        return iso_str
    try:
        from dateutil import parser as dp
        dt = dp.parse(iso_str)
        return dt.strftime('%I:%M %p')
    except:
        return iso_str


@app.route('/api/settings', methods=['POST'])
@login_required
def update_settings():
    """Update user settings."""
    user = get_current_user()
    db = get_db()
    data = request.json or {}

    if 'zoom_link' in data:
        db.execute('UPDATE users SET zoom_link = ? WHERE id = ?',
                   (data['zoom_link'], user['id']))

    if 'timezone' in data:
        db.execute('UPDATE users SET timezone = ? WHERE id = ?',
                   (data['timezone'], user['id']))

    if 'name' in data and data['name'].strip():
        db.execute('UPDATE users SET name = ? WHERE id = ?',
                   (data['name'].strip(), user['id']))

    # Update circle-specific settings
    if 'circle_code' in data:
        circle = db.execute('SELECT id FROM circles WHERE code = ?',
                           (data['circle_code'],)).fetchone()
        if circle:
            if 'start_hour' in data:
                db.execute('''
                    UPDATE circle_members SET start_hour = ?
                    WHERE circle_id = ? AND user_id = ?
                ''', (data['start_hour'], circle['id'], user['id']))
            if 'end_hour' in data:
                db.execute('''
                    UPDATE circle_members SET end_hour = ?
                    WHERE circle_id = ? AND user_id = ?
                ''', (data['end_hour'], circle['id'], user['id']))

    db.commit()
    return jsonify({'success': True})


@app.route('/api/circle/<code>/invite')
@login_required
def get_invite(code):
    """Get invite link info. Only admins can see the invite link."""
    user = get_current_user()
    db = get_db()
    circle = db.execute('SELECT * FROM circles WHERE code = ?', (code,)).fetchone()
    if not circle:
        return jsonify({'error': 'Circle not found'}), 404

    # Check if user is admin
    membership = db.execute(
        'SELECT role FROM circle_members WHERE circle_id = ? AND user_id = ?',
        (circle['id'], user['id'])
    ).fetchone()
    if not membership or membership['role'] != 'admin':
        return jsonify({'error': 'Only admins can share the invite link'}), 403

    member_count = db.execute(
        'SELECT COUNT(*) as cnt FROM circle_members WHERE circle_id = ?',
        (circle['id'],)
    ).fetchone()['cnt']

    return jsonify({
        'code': code,
        'name': circle['name'],
        'member_count': member_count,
        'invite_url': url_for('join_page', code=code, _external=True),
    })


@app.route('/api/circle/<code>/recent-sessions')
@login_required
def recent_sessions(code):
    """Get recent sessions for the circle."""
    db = get_db()
    circle = db.execute('SELECT * FROM circles WHERE code = ?', (code,)).fetchone()
    if not circle:
        return jsonify({'error': 'Circle not found'}), 404

    rows = db.execute('''
        SELECT s.*, u1.name as user1_name, u2.name as user2_name
        FROM sessions s
        JOIN users u1 ON u1.id = s.user1_id
        JOIN users u2 ON u2.id = s.user2_id
        WHERE s.circle_id = ?
        ORDER BY s.created_at DESC
        LIMIT 20
    ''', (circle['id'],)).fetchall()

    sessions_list = [{
        'id': r['id'],
        'user1_name': r['user1_name'],
        'user2_name': r['user2_name'],
        'duration_minutes': r['duration_minutes'],
        'rating': r['rating'],
        'created_at': r['created_at'],
    } for r in rows]

    return jsonify({'sessions': sessions_list})


# ============ LEAVE SESSION ============

@app.route('/api/circle/<code>/leave-session', methods=['POST'])
@login_required
def leave_session(code):
    """Leave an active session (without ending it for everyone)."""
    user = get_current_user()
    db = get_db()

    circle = db.execute('SELECT * FROM circles WHERE code = ?', (code,)).fetchone()
    if not circle:
        return jsonify({'error': 'Circle not found'}), 404

    data = request.json or {}
    session_id = data.get('session_id')

    if not session_id:
        return jsonify({'error': 'Session ID is required'}), 400

    active_sess = db.execute('''
        SELECT * FROM active_sessions WHERE id = ? AND circle_id = ? AND ended_at IS NULL
    ''', (session_id, circle['id'])).fetchone()

    if not active_sess:
        return jsonify({'error': 'Session not found or already ended'}), 404

    # Verify user is in session
    membership = db.execute('''
        SELECT * FROM active_session_members WHERE session_id = ? AND user_id = ?
    ''', (session_id, user['id'])).fetchone()
    if not membership:
        return jsonify({'error': 'You are not in this session'}), 400

    # Remove user from session
    db.execute('DELETE FROM active_session_members WHERE session_id = ? AND user_id = ?',
               (session_id, user['id']))

    # Set user unavailable
    db.execute('''
        UPDATE availability SET available = 0, updated_at = CURRENT_TIMESTAMP
        WHERE user_id = ? AND circle_id = ?
    ''', (user['id'], circle['id']))

    # Check if session is now empty
    remaining = db.execute('SELECT COUNT(*) as cnt FROM active_session_members WHERE session_id = ?',
                           (session_id,)).fetchone()['cnt']

    if remaining == 0:
        # End the session and auto-log it
        db.execute('UPDATE active_sessions SET ended_at = CURRENT_TIMESTAMP WHERE id = ?', (session_id,))

        # Calculate duration for logging
        started_at = datetime.strptime(active_sess['started_at'], '%Y-%m-%d %H:%M:%S')
        duration_minutes = max(1, int((datetime.utcnow() - started_at).total_seconds() / 60))

        # Log a session entry for the leaving user (solo session)
        db.execute('''
            INSERT INTO sessions (circle_id, user1_id, user2_id, duration_minutes, rating, notes)
            VALUES (?, ?, ?, ?, 0, 'Auto-logged: last person left')
        ''', (circle['id'], user['id'], user['id'], duration_minutes))

    db.commit()

    return jsonify({'success': True, 'session_ended': remaining == 0})


# ============ HEARTBEAT ============

@app.route('/api/circle/<code>/heartbeat', methods=['POST'])
@login_required
def heartbeat(code):
    """Update last_seen timestamp for presence detection."""
    user = get_current_user()
    db = get_db()

    circle = db.execute('SELECT * FROM circles WHERE code = ?', (code,)).fetchone()
    if not circle:
        return jsonify({'error': 'Circle not found'}), 404

    db.execute('''
        UPDATE circle_members SET last_seen = CURRENT_TIMESTAMP
        WHERE circle_id = ? AND user_id = ?
    ''', (circle['id'], user['id']))
    db.commit()

    return jsonify({'success': True})


# ============ SET UNAVAILABLE (for beforeunload) ============

@app.route('/api/circle/<code>/set-unavailable', methods=['POST'])
@login_required
def set_unavailable(code):
    """Set user unavailable and leave any active session. Used by beforeunload."""
    user = get_current_user()
    db = get_db()

    circle = db.execute('SELECT * FROM circles WHERE code = ?', (code,)).fetchone()
    if not circle:
        return jsonify({'error': 'Circle not found'}), 404

    # Set unavailable
    db.execute('''
        UPDATE availability SET available = 0, updated_at = CURRENT_TIMESTAMP
        WHERE user_id = ? AND circle_id = ?
    ''', (user['id'], circle['id']))

    # Remove from any active sessions in this circle
    active_memberships = db.execute('''
        SELECT asm.session_id FROM active_session_members asm
        JOIN active_sessions s ON s.id = asm.session_id
        WHERE asm.user_id = ? AND s.circle_id = ? AND s.ended_at IS NULL
    ''', (user['id'], circle['id'])).fetchall()

    for am in active_memberships:
        db.execute('DELETE FROM active_session_members WHERE session_id = ? AND user_id = ?',
                   (am['session_id'], user['id']))
        # Check if session is now empty
        remaining = db.execute('SELECT COUNT(*) as cnt FROM active_session_members WHERE session_id = ?',
                               (am['session_id'],)).fetchone()['cnt']
        if remaining == 0:
            db.execute('UPDATE active_sessions SET ended_at = CURRENT_TIMESTAMP WHERE id = ?', (am['session_id'],))

    db.commit()
    return jsonify({'success': True})


# ============ KICK MEMBER (Admin) ============

@app.route('/api/circle/<code>/members/<int:user_id>', methods=['DELETE'])
@login_required
def kick_member(code, user_id):
    """Kick a member from the circle. Admin only."""
    current_user = get_current_user()
    db = get_db()

    circle = db.execute('SELECT * FROM circles WHERE code = ?', (code,)).fetchone()
    if not circle:
        return jsonify({'error': 'Circle not found'}), 404

    # Check admin
    my_membership = db.execute(
        'SELECT role FROM circle_members WHERE circle_id = ? AND user_id = ?',
        (circle['id'], current_user['id'])
    ).fetchone()
    if not my_membership or my_membership['role'] != 'admin':
        return jsonify({'error': 'Only admins can kick members'}), 403

    # Can't kick yourself
    if user_id == current_user['id']:
        return jsonify({'error': "You can't kick yourself"}), 400

    # Can't kick other admins
    target_membership = db.execute(
        'SELECT role FROM circle_members WHERE circle_id = ? AND user_id = ?',
        (circle['id'], user_id)
    ).fetchone()
    if not target_membership:
        return jsonify({'error': 'User not in this circle'}), 404
    if target_membership['role'] == 'admin':
        return jsonify({'error': "Can't kick another admin"}), 400

    # Remove from active sessions
    db.execute('''
        DELETE FROM active_session_members WHERE user_id = ? AND session_id IN (
            SELECT id FROM active_sessions WHERE circle_id = ? AND ended_at IS NULL
        )
    ''', (user_id, circle['id']))

    # Remove availability
    db.execute('DELETE FROM availability WHERE user_id = ? AND circle_id = ?', (user_id, circle['id']))

    # Remove from circle
    db.execute('DELETE FROM circle_members WHERE circle_id = ? AND user_id = ?', (circle['id'], user_id))

    db.commit()
    return jsonify({'success': True})


# ============ CIRCLE SETTINGS (Admin) ============

@app.route('/api/circle/<code>/settings', methods=['GET'])
@login_required
def get_circle_settings(code):
    """Get circle settings. Admin only."""
    user = get_current_user()
    db = get_db()

    circle = db.execute('SELECT * FROM circles WHERE code = ?', (code,)).fetchone()
    if not circle:
        return jsonify({'error': 'Circle not found'}), 404

    membership = db.execute(
        'SELECT role FROM circle_members WHERE circle_id = ? AND user_id = ?',
        (circle['id'], user['id'])
    ).fetchone()
    if not membership or membership['role'] != 'admin':
        return jsonify({'error': 'Only admins can view settings'}), 403

    # Get members list for admin management
    members = db.execute('''
        SELECT u.id, u.name, u.email, cm.role, cm.joined_at
        FROM circle_members cm
        JOIN users u ON u.id = cm.user_id
        WHERE cm.circle_id = ?
        ORDER BY cm.role DESC, u.name
    ''', (circle['id'],)).fetchall()

    member_list = [{
        'id': m['id'],
        'name': m['name'],
        'email': m['email'],
        'role': m['role'],
        'joined_at': m['joined_at'],
    } for m in members]

    return jsonify({
        'name': circle['name'],
        'max_session_size': circle['max_session_size'] if 'max_session_size' in circle.keys() else 4,
        'members': member_list,
    })


@app.route('/api/circle/<code>/settings', methods=['POST'])
@login_required
def update_circle_settings(code):
    """Update circle settings. Admin only."""
    user = get_current_user()
    db = get_db()

    circle = db.execute('SELECT * FROM circles WHERE code = ?', (code,)).fetchone()
    if not circle:
        return jsonify({'error': 'Circle not found'}), 404

    membership = db.execute(
        'SELECT role FROM circle_members WHERE circle_id = ? AND user_id = ?',
        (circle['id'], user['id'])
    ).fetchone()
    if not membership or membership['role'] != 'admin':
        return jsonify({'error': 'Only admins can update settings'}), 403

    data = request.json or {}

    if 'name' in data and data['name'].strip():
        db.execute('UPDATE circles SET name = ? WHERE id = ?', (data['name'].strip(), circle['id']))

    if 'max_session_size' in data:
        max_size = max(2, min(20, int(data['max_session_size'])))
        db.execute('UPDATE circles SET max_session_size = ? WHERE id = ?', (max_size, circle['id']))

    db.commit()
    return jsonify({'success': True})


# ============ ADMIN CODE CHECK ============

@app.route('/api/admin-code-required')
def admin_code_required():
    """Check if an admin code is required to create circles."""
    admin_code = os.environ.get('ADMIN_CODE', '').strip()
    return jsonify({'required': bool(admin_code)})


# ============ ERROR HANDLERS ============

@app.errorhandler(500)
def handle_500(e):
    import traceback
    traceback.print_exc()
    return f"<h1>500 Internal Server Error</h1><pre>{traceback.format_exc()}</pre>", 500


# ============ LEGAL PAGES ============

@app.route('/privacy')
def privacy():
    return render_template('privacy.html')

@app.route('/terms')
def terms():
    return render_template('terms.html')

# ============ INIT ============

init_db()

if __name__ == '__main__':
    print("🎯 Roleplay Circles v2")
    print(f"   OAuth configured: {OAUTH_CONFIGURED}")
    print(f"   Database: {DB_PATH}")
    print("   Open http://localhost:5050")
    app.run(debug=True, port=5050, host='0.0.0.0', threaded=True)
