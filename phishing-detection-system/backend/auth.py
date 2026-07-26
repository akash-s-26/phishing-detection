"""
backend/auth.py
JWT-based auth: signup, login, token refresh, profile, logout.
Passwords hashed with bcrypt. Users stored in the same SQLite DB as scans.
"""

import re
import sqlite3
import datetime
import bcrypt
from flask import Blueprint, request, jsonify
from flask_jwt_extended import (
    create_access_token, create_refresh_token, jwt_required,
    get_jwt_identity, get_jwt
)

auth_bp = Blueprint('auth', __name__, url_prefix='/auth')

DB_PATH_HOLDER = {}  # set by app.py via init_auth()

EMAIL_RE = re.compile(r'^[^@\s]+@[^@\s]+\.[^@\s]+$')

# In-memory revoked-token blocklist (jti). Fine for a single-process dev/prod-lite deployment;
# swap for Redis if you scale to multiple workers.
REVOKED_JTIS = set()


def init_auth(db_path: str):
    DB_PATH_HOLDER['path'] = db_path
    conn = sqlite3.connect(db_path)
    conn.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        created_at TEXT NOT NULL
    )''')
    conn.commit()
    conn.close()


def _db():
    return sqlite3.connect(DB_PATH_HOLDER['path'])


def _user_by_email(email):
    conn = _db()
    row = conn.execute(
        'SELECT id, name, email, password_hash, created_at FROM users WHERE email = ?',
        (email,)
    ).fetchone()
    conn.close()
    return row


def _user_by_id(user_id):
    conn = _db()
    row = conn.execute(
        'SELECT id, name, email, created_at FROM users WHERE id = ?', (user_id,)
    ).fetchone()
    conn.close()
    return row


def register_blocklist_check(jwt_manager):
    """Wire up token revocation checking on the JWTManager instance."""
    @jwt_manager.token_in_blocklist_loader
    def check_if_revoked(jwt_header, jwt_payload):
        return jwt_payload['jti'] in REVOKED_JTIS


@auth_bp.route('/signup', methods=['POST'])
def signup():
    data = request.get_json(silent=True) or {}
    name = (data.get('name') or '').strip()
    email = (data.get('email') or '').strip().lower()
    password = data.get('password') or ''

    if not name or not email or not password:
        return jsonify({'error': 'name, email and password are all required'}), 400
    if not EMAIL_RE.match(email):
        return jsonify({'error': 'Invalid email address'}), 400
    if len(password) < 8:
        return jsonify({'error': 'Password must be at least 8 characters'}), 400
    if _user_by_email(email):
        return jsonify({'error': 'An account with this email already exists'}), 409

    pw_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    conn = _db()
    conn.execute(
        'INSERT INTO users (name, email, password_hash, created_at) VALUES (?,?,?,?)',
        (name, email, pw_hash, datetime.datetime.utcnow().isoformat())
    )
    conn.commit()
    user_id = conn.execute('SELECT id FROM users WHERE email = ?', (email,)).fetchone()[0]
    conn.close()

    access_token = create_access_token(identity=str(user_id))
    refresh_token = create_refresh_token(identity=str(user_id))
    return jsonify({
        'access_token': access_token,
        'refresh_token': refresh_token,
        'user': {'id': user_id, 'name': name, 'email': email}
    }), 201


@auth_bp.route('/login', methods=['POST'])
def login():
    data = request.get_json(silent=True) or {}
    email = (data.get('email') or '').strip().lower()
    password = data.get('password') or ''

    row = _user_by_email(email)
    if not row or not bcrypt.checkpw(password.encode('utf-8'), row[3].encode('utf-8')):
        return jsonify({'error': 'Invalid email or password'}), 401

    user_id, name, email, _pw_hash, _created = row
    access_token = create_access_token(identity=str(user_id))
    refresh_token = create_refresh_token(identity=str(user_id))
    return jsonify({
        'access_token': access_token,
        'refresh_token': refresh_token,
        'user': {'id': user_id, 'name': name, 'email': email}
    })


@auth_bp.route('/refresh', methods=['POST'])
@jwt_required(refresh=True)
def refresh():
    identity = get_jwt_identity()
    new_access_token = create_access_token(identity=identity)
    return jsonify({'access_token': new_access_token})


@auth_bp.route('/profile', methods=['GET'])
@jwt_required()
def profile():
    user_id = get_jwt_identity()
    row = _user_by_id(user_id)
    if not row:
        return jsonify({'error': 'User not found'}), 404
    return jsonify({'id': row[0], 'name': row[1], 'email': row[2], 'created_at': row[3]})


@auth_bp.route('/logout', methods=['POST'])
@jwt_required()
def logout():
    jti = get_jwt()['jti']
    REVOKED_JTIS.add(jti)
    return jsonify({'message': 'Logged out successfully'})
