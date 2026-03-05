"""
Student Score Management System - Restructured Version

A comprehensive Flask web application for managing student academic records,
including multi-school support, role-based access, and advanced features.

Author: OSondu Stanley
Version: 2.0.0
"""

from flask import Flask, render_template, request, redirect, url_for, session, flash, send_file, Response, g, has_request_context
from flask_wtf.csrf import CSRFProtect, CSRFError
import argparse
import json
import csv
import re
import math
import calendar
import base64
import hmac
import hashlib
import urllib.parse
from io import StringIO, BytesIO
from datetime import date, datetime, timedelta
import smtplib
from email.message import EmailMessage
from werkzeug.security import generate_password_hash, check_password_hash
import mimetypes
import time
import urllib.request

import os
import secrets
import atexit
from contextlib import contextmanager

import logging
try:
    from dotenv import load_dotenv
except Exception:
    load_dotenv = None
from services import parent_queries as parent_queries_service

if load_dotenv:
    load_dotenv()

app = Flask(__name__, template_folder='frontend/templates', static_folder='static')

PWA_HEAD_SNIPPET = """
<link rel="manifest" href="/manifest.webmanifest">
<meta name="theme-color" content="#1e3c72">
<meta name="mobile-web-app-capable" content="yes">
"""

PWA_BODY_SNIPPET = """
<script>
(function () {
  function ensureOfflineBanner() {
    if (document.getElementById('offline-status-banner')) return;
    var style = document.createElement('style');
    style.textContent = '#offline-status-banner{position:fixed;left:12px;right:12px;bottom:12px;z-index:99999;display:none;padding:10px 12px;border-radius:10px;background:#b91c1c;color:#fff;font:600 14px/1.4 Arial,sans-serif;box-shadow:0 6px 18px rgba(0,0,0,.25)}#offline-status-banner.online{background:#0f766e}';
    document.head.appendChild(style);
    var banner = document.createElement('div');
    banner.id = 'offline-status-banner';
    banner.setAttribute('role', 'status');
    banner.setAttribute('aria-live', 'polite');
    document.body.appendChild(banner);

    function showOnline() {
      banner.textContent = 'Back online';
      banner.classList.add('online');
      banner.style.display = 'block';
      setTimeout(function () {
        if (navigator.onLine) banner.style.display = 'none';
      }, 2500);
    }
    function showOffline() {
      banner.textContent = 'You are offline. Live data may be unavailable.';
      banner.classList.remove('online');
      banner.style.display = 'block';
    }
    window.addEventListener('online', showOnline);
    window.addEventListener('offline', showOffline);
    if (!navigator.onLine) showOffline();
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', ensureOfflineBanner);
  } else {
    ensureOfflineBanner();
  }

  if (!('serviceWorker' in navigator)) return;
  var isSecure = window.isSecureContext || location.protocol === 'https:' || location.hostname === 'localhost' || location.hostname === '127.0.0.1';
  if (!isSecure) return;
  window.addEventListener('load', function () {
    navigator.serviceWorker.register('/sw.js').catch(function () {});
  });
})();
</script>
"""
ALLOW_INSECURE_DEFAULTS = os.environ.get('ALLOW_INSECURE_DEFAULTS', '').strip().lower() in ('1', 'true', 'yes')
STARTUP_FALLBACK_ENV_VARS = []
secret_key = os.environ.get('SECRET_KEY')
if not secret_key:
    if ALLOW_INSECURE_DEFAULTS:
        # Explicitly opt-in fallback for local/dev only.
        secret_key = 'dev-secret-key-change-me'
        STARTUP_FALLBACK_ENV_VARS.append('SECRET_KEY')
    else:
        raise RuntimeError("SECRET_KEY is required in production. Set SECRET_KEY or enable ALLOW_INSECURE_DEFAULTS for local development.")
if not ALLOW_INSECURE_DEFAULTS and len(secret_key) < 32:
    raise RuntimeError("SECRET_KEY is too short. Use at least 32 characters in production.")
app.secret_key = secret_key
app.config['WTF_CSRF_TIME_LIMIT'] = None
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = os.environ.get('SESSION_COOKIE_SAMESITE', 'Lax')
_session_cookie_secure_env = os.environ.get('SESSION_COOKIE_SECURE', '').strip().lower()
if _session_cookie_secure_env in ('1', 'true', 'yes'):
    app.config['SESSION_COOKIE_SECURE'] = True
elif _session_cookie_secure_env in ('0', 'false', 'no'):
    app.config['SESSION_COOKIE_SECURE'] = False
else:
    # Default secure in production, relaxed for explicit local/dev mode.
    app.config['SESSION_COOKIE_SECURE'] = not ALLOW_INSECURE_DEFAULTS

# Initialize CSRF Protection
csrf = CSRFProtect(app)

# Initialize Flask-Migrate for schema management
from flask_migrate import Migrate
migrate = Migrate(app, None)  # db will be set up via raw SQL migrations

DATABASE_URL = os.environ.get('DATABASE_URL', '').strip()
if not DATABASE_URL.startswith(('postgres://', 'postgresql://')):
    raise RuntimeError("PostgreSQL is required. Set DATABASE_URL to a postgresql:// connection string.")
RUN_STARTUP_DDL = os.environ.get('RUN_STARTUP_DDL', '0').strip().lower() in ('1', 'true', 'yes')
RUN_STARTUP_BOOTSTRAP = os.environ.get('RUN_STARTUP_BOOTSTRAP', '0').strip().lower() in ('1', 'true', 'yes')
SUPER_ADMIN_USERNAME = os.environ.get('SUPER_ADMIN_USERNAME', 'osartech3@gmail.com').strip()
SUPER_ADMIN_PASSWORD = os.environ.get('SUPER_ADMIN_PASSWORD', '').strip()
if RUN_STARTUP_BOOTSTRAP:
    if not SUPER_ADMIN_PASSWORD:
        raise RuntimeError("SUPER_ADMIN_PASSWORD is required when RUN_STARTUP_BOOTSTRAP=1.")
    if len(SUPER_ADMIN_PASSWORD) < 12:
        raise RuntimeError("SUPER_ADMIN_PASSWORD is too short. Use at least 12 characters.")
DEFAULT_STUDENT_PASSWORD = os.environ.get('DEFAULT_STUDENT_PASSWORD', '').strip()
if not DEFAULT_STUDENT_PASSWORD:
    raise RuntimeError("DEFAULT_STUDENT_PASSWORD is required. Set it in environment variables.")
if not ALLOW_INSECURE_DEFAULTS and len(DEFAULT_STUDENT_PASSWORD) < 8:
    raise RuntimeError("DEFAULT_STUDENT_PASSWORD is too short. Use at least 8 characters in production.")
_default_teacher_password_env = os.environ.get('DEFAULT_TEACHER_PASSWORD', '').strip()
if _default_teacher_password_env:
    DEFAULT_TEACHER_PASSWORD = _default_teacher_password_env
elif ALLOW_INSECURE_DEFAULTS:
    DEFAULT_TEACHER_PASSWORD = 'teachers'
    STARTUP_FALLBACK_ENV_VARS.append('DEFAULT_TEACHER_PASSWORD')
else:
    raise RuntimeError("DEFAULT_TEACHER_PASSWORD is required in production. Set it in environment variables.")
if not ALLOW_INSECURE_DEFAULTS and len(DEFAULT_TEACHER_PASSWORD) < 8:
    raise RuntimeError("DEFAULT_TEACHER_PASSWORD is too short. Use at least 8 characters in production.")
ADMIN_PASSWORD_MAX_AGE_DAYS = max(1, int((os.environ.get('ADMIN_PASSWORD_MAX_AGE_DAYS', '90') or '90').strip() or '90'))
SESSION_TIMEOUT_MINUTES = max(15, int((os.environ.get('SESSION_TIMEOUT_MINUTES', '120') or '120').strip() or '120'))
# OTP retired: keep settings readable but force mode off.
ADMIN_OTP_MODE = 'off'
RESULT_VERIFY_TOKEN_TTL_MINUTES = max(5, int((os.environ.get('RESULT_VERIFY_TOKEN_TTL_MINUTES', '10080') or '10080').strip() or '10080'))
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=SESSION_TIMEOUT_MINUTES)

LOGIN_MAX_ATTEMPTS = 4
LOGIN_LOCK_MINUTES = 15
STARTUP_SCHEMA_VERSION = '2026-02-26.1'
_DB_POOL = None
_SCHOOL_LOGO_CACHE = {}
_SCHOOL_LOGO_CACHE_TTL = 600
_SCHOOL_LOGO_MAX_BYTES = 3 * 1024 * 1024
_SCHOOL_CACHE = {}
_SCHOOL_CACHE_TTL = max(5, int((os.environ.get('SCHOOL_CACHE_TTL_SECONDS', '30') or '30').strip() or '30'))
_SCHOOL_CACHE_MAX_ENTRIES = max(20, int((os.environ.get('SCHOOL_CACHE_MAX_ENTRIES', '500') or '500').strip() or '500'))
_ENABLE_RUNTIME_PWA_INJECT = os.environ.get('ENABLE_RUNTIME_PWA_INJECT', '').strip().lower() in ('1', 'true', 'yes')
_SCHEMA_DDL_ALLOWED = False

def _prune_school_cache():
    """Bound cache size and remove expired entries."""
    now = time.time()
    expired_keys = [
        key for key, item in list(_SCHOOL_CACHE.items())
        if (now - float((item or {}).get('ts', 0))) >= _SCHOOL_CACHE_TTL
    ]
    for key in expired_keys:
        _SCHOOL_CACHE.pop(key, None)
    if len(_SCHOOL_CACHE) <= _SCHOOL_CACHE_MAX_ENTRIES:
        return
    # Remove oldest entries first when still above cap.
    for key, _item in sorted(_SCHOOL_CACHE.items(), key=lambda kv: float((kv[1] or {}).get('ts', 0)))[: max(0, len(_SCHOOL_CACHE) - _SCHOOL_CACHE_MAX_ENTRIES)]:
        _SCHOOL_CACHE.pop(key, None)

def invalidate_school_cache(school_id=''):
    """Invalidate cached school rows globally and for current request context."""
    school_key = (school_id or '').strip()
    if school_key:
        _SCHOOL_CACHE.pop(school_key, None)
    else:
        _SCHOOL_CACHE.clear()
    if has_request_context():
        request_cache = getattr(g, '_school_cache', None)
        if isinstance(request_cache, dict):
            if school_key:
                request_cache.pop(school_key, None)
            else:
                request_cache.clear()

@app.context_processor
def inject_teacher_nav_flags():
    """Expose teacher sidebar flags so subject-only accounts don't see class-only links."""
    if session.get('role') != 'teacher':
        return {
            'teacher_has_class_assignment_nav': False,
            'teacher_sidebar_profile_image': '',
            'teacher_sidebar_display_name': '',
            'teacher_score_nav_tree': [],
            'teacher_selected_score_subject': '',
            'teacher_selected_score_class': '',
            'teacher_unread_notifications': 0,
        }
    school_id = (session.get('school_id') or '').strip()
    teacher_id = (session.get('user_id') or '').strip()
    if not school_id or not teacher_id:
        return {
            'teacher_has_class_assignment_nav': False,
            'teacher_sidebar_profile_image': '',
            'teacher_sidebar_display_name': '',
            'teacher_score_nav_tree': [],
            'teacher_selected_score_subject': '',
            'teacher_selected_score_class': '',
            'teacher_unread_notifications': 0,
        }
    school = get_school(school_id) or {}
    current_term = get_current_term(school)
    current_year = (school.get('academic_year', '') or '').strip()
    has_class_assignment = bool(
        get_teacher_classes(
            school_id,
            teacher_id,
            term=current_term,
            academic_year=current_year,
        )
    )
    subject_assignment_rows = get_teacher_subject_assignments(
        school_id,
        teacher_id=teacher_id,
        term=current_term,
        academic_year=current_year,
    )
    score_subject_nav_map = {}
    for row in subject_assignment_rows:
        cls = (row.get('classname') or '').strip()
        subj = normalize_subject_name(row.get('subject', ''))
        if not cls or not subj:
            continue
        score_subject_nav_map.setdefault(subj, set()).add(cls)
    teacher_score_nav_tree = [
        {
            'subject': subj,
            'classes': sorted(score_subject_nav_map.get(subj, set()), key=lambda x: str(x).lower()),
        }
        for subj in sorted(score_subject_nav_map.keys(), key=lambda x: str(x).lower())
    ]
    teacher_selected_score_subject = normalize_subject_name((request.args.get('score_subject', '') or '').strip())
    valid_subjects = {row['subject'] for row in teacher_score_nav_tree}
    if teacher_selected_score_subject not in valid_subjects:
        teacher_selected_score_subject = ''
    teacher_selected_score_class = (request.args.get('score_class', '') or '').strip()
    if teacher_selected_score_subject:
        allowed_classes = set(score_subject_nav_map.get(teacher_selected_score_subject, set()))
        if teacher_selected_score_class not in allowed_classes:
            teacher_selected_score_class = ''
    else:
        teacher_selected_score_class = ''
    teacher_profile = get_teacher(school_id, teacher_id)
    teacher_display_name = (
        f"{(teacher_profile.get('firstname') or '').strip()} {(teacher_profile.get('lastname') or '').strip()}".strip()
        or teacher_id
    )
    teacher_subject_set = {normalize_subject_name(row.get('subject', '')) for row in subject_assignment_rows if normalize_subject_name(row.get('subject', ''))}
    teacher_scope_classes = sorted(
        set(
            get_teacher_classes(
                school_id,
                teacher_id,
                term=current_term,
                academic_year=current_year,
            )
        )
        | {str(row.get('classname') or '').strip() for row in subject_assignment_rows if (row.get('classname') or '').strip()}
    )
    teacher_notifications = get_teacher_messages_for_teacher(
        school_id=school_id,
        teacher_id=teacher_id,
        classes=teacher_scope_classes,
        subjects=sorted(teacher_subject_set),
        limit=20,
    )
    unread_notifications = sum(1 for row in teacher_notifications if not row.get('is_read'))
    return {
        'teacher_has_class_assignment_nav': has_class_assignment,
        'teacher_sidebar_profile_image': (teacher_profile.get('profile_image') or '').strip(),
        'teacher_sidebar_display_name': teacher_display_name,
        'teacher_score_nav_tree': teacher_score_nav_tree,
        'teacher_selected_score_subject': teacher_selected_score_subject,
        'teacher_selected_score_class': teacher_selected_score_class,
        'teacher_unread_notifications': unread_notifications,
    }

@app.context_processor
def inject_first_login_tutorial_context():
    role = (session.get('first_login_tutorial_role') or session.get('role') or '').strip().lower()
    show = bool(session.get('show_first_login_tutorial')) and role in {'school_admin', 'teacher', 'student', 'parent'}
    return {
        'show_first_login_tutorial': show,
        'first_login_tutorial': build_first_login_tutorial(role) if show else {},
    }

@contextmanager
def schema_ddl_mode(enabled=False):
    """Temporarily allow schema DDL for explicit maintenance commands only."""
    global _SCHEMA_DDL_ALLOWED
    previous = _SCHEMA_DDL_ALLOWED
    _SCHEMA_DDL_ALLOWED = bool(enabled)
    try:
        yield
    finally:
        _SCHEMA_DDL_ALLOWED = previous

def _runtime_schema_heal_allowed():
    env_enabled = os.environ.get('ALLOW_RUNTIME_SCHEMA_HEAL', '0').strip().lower() in ('1', 'true', 'yes')
    return bool(env_enabled and _SCHEMA_DDL_ALLOWED)

def _adapt_query(query):
    return query.replace('?', '%s')

def _sanitize_db_log_params(query, params):
    """Avoid leaking sensitive material into debug logs."""
    q = (query or '').lower()
    if any(key in q for key in ('password', 'token', 'secret', 'otp', 'signature')):
        return '[REDACTED]'
    if params is None:
        return None
    try:
        if isinstance(params, (list, tuple)):
            out = []
            for item in params:
                if isinstance(item, str) and len(item) > 64:
                    out.append(f'{item[:16]}...[{len(item)} chars]')
                else:
                    out.append(item)
            return tuple(out)
        if isinstance(params, dict):
            redacted = {}
            for k, v in params.items():
                key = str(k).lower()
                if any(mark in key for mark in ('password', 'token', 'secret', 'otp', 'signature')):
                    redacted[k] = '[REDACTED]'
                elif isinstance(v, str) and len(v) > 64:
                    redacted[k] = f'{v[:16]}...[{len(v)} chars]'
                else:
                    redacted[k] = v
            return redacted
    except Exception:
        return '[UNPRINTABLE PARAMS]'
    return params

def db_execute(cursor, query, params=None):
    # log the statement at DEBUG level; production can disable via logging config
    if logging.getLogger().isEnabledFor(logging.DEBUG):
        logging.debug(
            "db_execute: %s | params=%s",
            query.strip().replace('\n', ' '),
            _sanitize_db_log_params(query, params),
        )
    try:
        cursor.execute(_adapt_query(query), params)
        try:
            conn = getattr(cursor, 'connection', None)
            # Keep psycopg transaction behavior managed by db_connection(commit=...).
            # For lightweight/dummy cursors (tests/tools), commit per statement.
            if conn is not None and not hasattr(conn, 'get_transaction_status') and hasattr(conn, 'commit'):
                conn.commit()
        except Exception:
            pass
    except Exception as e:
        try:
            # Keep connection usable when callers catch errors and continue.
            if getattr(cursor, 'connection', None):
                cursor.connection.rollback()
        except Exception:
            pass
        logging.error("Database Error: %s", e)
        raise

def _is_transient_db_transport_error(exc):
    """Best-effort detection of short-lived DB transport errors (SSL/socket drops)."""
    text = (str(exc) or '').strip().lower()
    markers = (
        'ssl error',
        'decryption failed',
        'bad record mac',
        'connection already closed',
        'server closed the connection unexpectedly',
        'ssl syscall error',
        'could not receive data from server',
        'terminating connection due to administrator command',
        'connection reset by peer',
        'broken pipe',
        'eof detected',
        'connection timed out',
    )
    return any(m in text for m in markers)

def canonicalize_classname(value):
    """Canonical class key used for shared subject catalog (e.g. 'Primary 1' -> 'PRIMARY1')."""
    return re.sub(r'[^A-Za-z0-9]+', '', (value or '').strip()).upper()

def normalize_school_logo_url(raw_url):
    """Normalize school logo URLs to direct image links when possible."""
    url = (raw_url or '').strip()
    if not url:
        return ''
    try:
        if url.startswith('//'):
            url = f'https:{url}'
        elif re.match(r'^[A-Za-z0-9.-]+\.[A-Za-z]{2,}([/:?#].*)?$', url):
            # Common admin input: "example.com/logo.png" without scheme.
            url = f'https://{url}'

        parsed = urllib.parse.urlparse(url)
        host = (parsed.netloc or '').lower()
        path = (parsed.path or '').lower()
        query = urllib.parse.parse_qs(parsed.query or '')

        # Bing image result pages often wrap real image URLs in query params.
        if 'bing.com' in host and '/images/search' in path:
            media = (query.get('mediaurl') or [''])[0].strip()
            if media:
                return urllib.parse.unquote(media).strip()
            cdn = (query.get('cdnurl') or [''])[0].strip()
            if cdn:
                return urllib.parse.unquote(cdn).strip()

        # Google image result wrapper.
        if 'google.' in host and '/imgres' in path:
            imgurl = (query.get('imgurl') or [''])[0].strip()
            if imgurl:
                return urllib.parse.unquote(imgurl).strip()
    except Exception:
        return url
    return url

def _school_logo_candidate_urls(logo_url):
    """Yield candidate URLs for logo fetch, including wrappers like Bing image search."""
    raw = (logo_url or '').strip()
    if not raw:
        return []
    candidates = []
    normalized = normalize_school_logo_url(raw)
    if normalized:
        candidates.append(normalized)

    try:
        parsed = urllib.parse.urlparse(raw)
        host = (parsed.netloc or '').lower()
        path = (parsed.path or '').lower()
        query = urllib.parse.parse_qs(parsed.query or '')
        if 'bing.com' in host and '/images/search' in path:
            media = urllib.parse.unquote((query.get('mediaurl') or [''])[0]).strip()
            cdn = urllib.parse.unquote((query.get('cdnurl') or [''])[0]).strip()
            if media:
                candidates.append(media)
            if cdn:
                candidates.append(cdn)
        elif 'google.' in host and '/imgres' in path:
            imgurl = urllib.parse.unquote((query.get('imgurl') or [''])[0]).strip()
            if imgurl:
                candidates.append(imgurl)
    except Exception:
        pass

    # Preserve order and remove duplicates.
    deduped = []
    seen = set()
    for c in candidates:
        if c and c not in seen:
            deduped.append(c)
            seen.add(c)
    return deduped

def fetch_school_logo_bytes(logo_url):
    """Fetch school logo image bytes with a small in-memory cache."""
    candidates = _school_logo_candidate_urls(logo_url)
    if not candidates:
        return None, None

    now = time.time()
    for url in candidates:
        cached = _SCHOOL_LOGO_CACHE.get(url)
        if cached and (now - cached['ts']) < _SCHOOL_LOGO_CACHE_TTL:
            return cached['data'], cached['content_type']

    for url in candidates:
        parsed = urllib.parse.urlparse(url)
        if parsed.scheme not in ('http', 'https'):
            continue
        req = urllib.request.Request(
            url,
            headers={
                'User-Agent': 'Mozilla/5.0 (compatible; SchoolResultBot/1.0)',
                'Accept': 'image/avif,image/webp,image/apng,image/*,*/*;q=0.8',
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=8) as resp:
                data = resp.read(_SCHOOL_LOGO_MAX_BYTES + 1)
                if len(data) > _SCHOOL_LOGO_MAX_BYTES:
                    continue
                if not data:
                    continue
                content_type = (resp.headers.get_content_type() or '').strip().lower()
        except Exception:
            continue

        if not content_type.startswith('image/'):
            guessed, _ = mimetypes.guess_type(url)
            if guessed and guessed.startswith('image/'):
                content_type = guessed
            else:
                continue

        _SCHOOL_LOGO_CACHE[url] = {'ts': now, 'data': data, 'content_type': content_type}
        return data, content_type

    return None, None

def _result_verify_signing_key():
    return (app.secret_key or '').encode('utf-8')

def _b64url_encode_bytes(raw):
    return base64.urlsafe_b64encode(raw).decode('ascii').rstrip('=')

def _b64url_decode_bytes(raw):
    if not raw:
        return b''
    pad = '=' * (-len(raw) % 4)
    return base64.urlsafe_b64decode((raw + pad).encode('ascii'))

def build_result_verification_token(school_id, student_id, term, academic_year='', classname=''):
    issued_at = int(time.time())
    expires_at = issued_at + (RESULT_VERIFY_TOKEN_TTL_MINUTES * 60)
    payload = {
        'v': 2,
        'school_id': (school_id or '').strip(),
        'student_id': (student_id or '').strip(),
        'term': (term or '').strip(),
        'academic_year': (academic_year or '').strip(),
        'classname': (classname or '').strip(),
        'iat': issued_at,
        'exp': expires_at,
    }
    payload_json = json.dumps(payload, separators=(',', ':'), sort_keys=True).encode('utf-8')
    payload_b64 = _b64url_encode_bytes(payload_json)
    sig = hmac.new(_result_verify_signing_key(), payload_b64.encode('ascii'), hashlib.sha256).digest()
    sig_b64 = _b64url_encode_bytes(sig)
    return f'{payload_b64}.{sig_b64}'

def parse_result_verification_token(token):
    token_str = (token or '').strip()
    if not token_str or '.' not in token_str:
        return None
    try:
        payload_b64, sig_b64 = token_str.split('.', 1)
        expected_sig = hmac.new(_result_verify_signing_key(), payload_b64.encode('ascii'), hashlib.sha256).digest()
        got_sig = _b64url_decode_bytes(sig_b64)
        if not hmac.compare_digest(expected_sig, got_sig):
            return None
        payload_raw = _b64url_decode_bytes(payload_b64)
        payload = json.loads(payload_raw.decode('utf-8'))
        if not isinstance(payload, dict):
            return None
        if int(payload.get('v', 0) or 0) != 2:
            return None
        expires_at = int(payload.get('exp', 0) or 0)
        now_ts = int(time.time())
        if not expires_at or now_ts > expires_at:
            return None
        return payload
    except Exception:
        return None

def build_result_verification_context(school_id, student_id, term, academic_year='', classname=''):
    token = build_result_verification_token(
        school_id=school_id,
        student_id=student_id,
        term=term,
        academic_year=academic_year,
        classname=classname,
    )
    verification_url = url_for('verify_result_qr', token=token, _external=True)
    # Do not send student-linked verification URLs to third-party QR providers.
    qr_image_url = ''
    return {
        'verification_token': token,
        'verification_url': verification_url,
        'verification_qr_url': qr_image_url,
    }

def _catalog_defaults_for_class(classname_key):
    key = canonicalize_classname(classname_key)
    nursery_core = [
        'English Language', 'Mathematics', 'Phonics', 'Creative Arts',
        'Health Habits', 'Social Habits', 'Rhymes', 'Handwriting',
    ]
    primary_core = [
        'English Language', 'Mathematics', 'Basic Science', 'Social Studies',
        'Civic Education', 'Christian Religious Studies', 'Computer Studies',
        'Agricultural Science', 'Physical and Health Education', 'Cultural and Creative Arts',
    ]
    jss_core = [
        'English Language', 'Mathematics', 'Basic Science', 'Basic Technology',
        'Civic Education', 'Social Studies', 'Christian Religious Studies',
        'Computer Studies', 'Agricultural Science', 'Physical and Health Education',
        'Cultural and Creative Arts',
    ]
    ss_core = ['English Language', 'Mathematics', 'Civic Education']
    ss_science = ['Biology', 'Chemistry', 'Physics']
    ss_art = ['Literature in English', 'Government', 'Christian Religious Studies']
    ss_commercial = ['Financial Accounting', 'Commerce', 'Economics']
    ss_optional = ['Data Processing', 'Agricultural Science', 'French', 'Further Mathematics']

    if key.startswith('NURSERY'):
        return {'core': nursery_core, 'science': [], 'art': [], 'commercial': [], 'optional': []}
    if key.startswith('PRIMARY'):
        return {'core': primary_core, 'science': [], 'art': [], 'commercial': [], 'optional': []}
    if key.startswith('JSS'):
        return {'core': jss_core, 'science': [], 'art': [], 'commercial': [], 'optional': []}
    if key.startswith('SS') or key.startswith('SSS'):
        return {'core': ss_core, 'science': ss_science, 'art': ss_art, 'commercial': ss_commercial, 'optional': ss_optional}
    # Fallback for unknown class names.
    return {'core': primary_core, 'science': [], 'art': [], 'commercial': [], 'optional': []}

def _upsert_global_catalog_subject_with_cursor(c, classname_key, bucket, subject_name):
    raw = ' '.join((subject_name or '').strip().split())
    if not raw:
        return
    words = []
    for word in raw.split(' '):
        if word.isupper() and len(word) <= 4:
            words.append(word)
        else:
            words.append(word[:1].upper() + word[1:].lower())
    name = ' '.join(words)
    class_key = canonicalize_classname(classname_key)
    bucket_key = (bucket or '').strip().lower()
    if not class_key or not name or bucket_key not in {'core', 'science', 'art', 'commercial', 'optional'}:
        return
    db_execute(
        c,
        """INSERT INTO global_class_subject_catalog (classname, bucket, subject_name)
           VALUES (?, ?, ?)
           ON CONFLICT(classname, bucket, subject_name) DO NOTHING""",
        (class_key, bucket_key, name),
    )

def _seed_global_subject_catalog_defaults_with_cursor(c):
    classes = [
        'NURSERY1', 'NURSERY2', 'NURSERY3',
        'PRIMARY1', 'PRIMARY2', 'PRIMARY3', 'PRIMARY4', 'PRIMARY5', 'PRIMARY6',
        'JSS1', 'JSS2', 'JSS3',
        'SS1', 'SS2', 'SS3',
    ]
    for classname in classes:
        defaults = _catalog_defaults_for_class(classname)
        for bucket, subjects in defaults.items():
            for subject in subjects:
                _upsert_global_catalog_subject_with_cursor(c, classname, bucket, subject)

def get_db():
    """Create a PostgreSQL DB connection."""
    try:
        import psycopg2
        from psycopg2.extras import DictCursor
    except ImportError as exc:
        raise RuntimeError("PostgreSQL backend requires psycopg2-binary") from exc
    return psycopg2.connect(
        DATABASE_URL,
        cursor_factory=DictCursor,
        connect_timeout=10,
        keepalives=1,
        keepalives_idle=30,
        keepalives_interval=10,
        keepalives_count=5,
        options="-c statement_timeout=25000 -c lock_timeout=8000 -c idle_in_transaction_session_timeout=20000",
    )

def _get_db_pool():
    """Lazily initialize a PostgreSQL connection pool for request-time DB access."""
    global _DB_POOL
    if _DB_POOL is not None:
        return _DB_POOL
    try:
        from psycopg2 import pool
        from psycopg2.extras import DictCursor
    except ImportError as exc:
        raise RuntimeError("PostgreSQL backend requires psycopg2-binary") from exc
    min_conn = max(2, int(os.environ.get('DB_POOL_MIN_CONN', '2') or 2))
    max_conn = max(min_conn, int(os.environ.get('DB_POOL_MAX_CONN', '20') or 20))
    _DB_POOL = pool.ThreadedConnectionPool(
        minconn=min_conn,
        maxconn=max_conn,
        dsn=DATABASE_URL,
        cursor_factory=DictCursor,
        connect_timeout=10,
        keepalives=1,
        keepalives_idle=30,
        keepalives_interval=10,
        keepalives_count=5,
        options="-c statement_timeout=25000 -c lock_timeout=8000 -c idle_in_transaction_session_timeout=20000",
    )
    return _DB_POOL

def _close_db_pool():
    global _DB_POOL
    if _DB_POOL is not None:
        _DB_POOL.closeall()
        _DB_POOL = None

atexit.register(_close_db_pool)

@contextmanager
def db_connection(commit=False):
    """Context manager for PostgreSQL pooled connections with optional commit."""
    pool = _get_db_pool()
    conn = pool.getconn()
    discard_conn = False
    try:
        yield conn
        if commit:
            conn.commit()
    except Exception:
        # Preserve original DB/network exception; rollback best-effort only.
        discard_conn = True
        try:
            if conn and not getattr(conn, 'closed', 1):
                conn.rollback()
        except Exception as rollback_exc:
            logging.warning("db_connection rollback skipped/failed: %s", rollback_exc)
        raise
    finally:
        try:
            is_closed = bool(getattr(conn, 'closed', 1))
            pool.putconn(conn, close=(discard_conn or is_closed))
        except Exception as put_exc:
            logging.warning("db_connection putconn failed: %s", put_exc)

_STUDENTS_PROMOTED_IS_BOOL = None
_STUDENTS_HAS_USER_ID = None
_STUDENTS_HAS_PARENT_ACCESS_COLS = None
_STUDENTS_HAS_ARCHIVE_COLS = None
_TEACHERS_HAS_ARCHIVE_COLS = None
_USERS_HAS_PASSWORD_CHANGED_AT = None
_USERS_HAS_TUTORIAL_SEEN_AT = None

def students_has_user_id_column():
    """Detect whether students.user_id exists on this DB."""
    global _STUDENTS_HAS_USER_ID
    if _STUDENTS_HAS_USER_ID is not None:
        return _STUDENTS_HAS_USER_ID
    try:
        with db_connection() as conn:
            c = conn.cursor()
            db_execute(
                c,
                """SELECT 1
                   FROM information_schema.columns
                   WHERE table_schema = 'public'
                     AND table_name = 'students'
                     AND column_name = 'user_id'
                   LIMIT 1""",
                None,
            )
            _STUDENTS_HAS_USER_ID = bool(c.fetchone())
    except Exception:
        _STUDENTS_HAS_USER_ID = False
    return _STUDENTS_HAS_USER_ID


def students_has_parent_access_columns():
    """Detect whether students.parent_phone + students.parent_password_hash exist."""
    global _STUDENTS_HAS_PARENT_ACCESS_COLS
    if _STUDENTS_HAS_PARENT_ACCESS_COLS is not None:
        return _STUDENTS_HAS_PARENT_ACCESS_COLS
    try:
        with db_connection() as conn:
            c = conn.cursor()
            db_execute(
                c,
                """SELECT column_name
                   FROM information_schema.columns
                   WHERE table_schema = 'public'
                     AND table_name = 'students'
                     AND column_name = ANY(%s)""",
                (['parent_phone', 'parent_password_hash'],),
            )
            cols = {str(row[0]) for row in c.fetchall() if row and row[0]}
            _STUDENTS_HAS_PARENT_ACCESS_COLS = ('parent_phone' in cols and 'parent_password_hash' in cols)
    except Exception:
        _STUDENTS_HAS_PARENT_ACCESS_COLS = False
    return _STUDENTS_HAS_PARENT_ACCESS_COLS

def students_has_archive_columns():
    """Detect whether students.is_archived + students.archived_at exist."""
    global _STUDENTS_HAS_ARCHIVE_COLS
    if _STUDENTS_HAS_ARCHIVE_COLS is not None:
        return _STUDENTS_HAS_ARCHIVE_COLS
    try:
        with db_connection() as conn:
            c = conn.cursor()
            db_execute(
                c,
                """SELECT column_name
                   FROM information_schema.columns
                   WHERE table_schema = 'public'
                     AND table_name = 'students'
                     AND column_name = ANY(%s)""",
                (['is_archived', 'archived_at'],),
            )
            cols = {str(row[0]) for row in c.fetchall() if row and row[0]}
            _STUDENTS_HAS_ARCHIVE_COLS = ('is_archived' in cols and 'archived_at' in cols)
    except Exception:
        _STUDENTS_HAS_ARCHIVE_COLS = False
    return _STUDENTS_HAS_ARCHIVE_COLS

def teachers_has_archive_columns():
    """Detect whether teachers.is_archived + teachers.archived_at exist."""
    global _TEACHERS_HAS_ARCHIVE_COLS
    if _TEACHERS_HAS_ARCHIVE_COLS is not None:
        return _TEACHERS_HAS_ARCHIVE_COLS
    try:
        with db_connection() as conn:
            c = conn.cursor()
            db_execute(
                c,
                """SELECT column_name
                   FROM information_schema.columns
                   WHERE table_schema = 'public'
                     AND table_name = 'teachers'
                     AND column_name = ANY(%s)""",
                (['is_archived', 'archived_at'],),
            )
            cols = {str(row[0]) for row in c.fetchall() if row and row[0]}
            _TEACHERS_HAS_ARCHIVE_COLS = ('is_archived' in cols and 'archived_at' in cols)
    except Exception:
        _TEACHERS_HAS_ARCHIVE_COLS = False
    return _TEACHERS_HAS_ARCHIVE_COLS

def users_has_password_changed_at_column():
    """Detect whether users.password_changed_at exists on this DB."""
    global _USERS_HAS_PASSWORD_CHANGED_AT
    if _USERS_HAS_PASSWORD_CHANGED_AT is not None:
        return _USERS_HAS_PASSWORD_CHANGED_AT
    try:
        with db_connection() as conn:
            c = conn.cursor()
            db_execute(
                c,
                """SELECT 1
                   FROM information_schema.columns
                   WHERE table_schema = 'public'
                     AND table_name = 'users'
                     AND column_name = 'password_changed_at'
                   LIMIT 1""",
                None,
            )
            _USERS_HAS_PASSWORD_CHANGED_AT = bool(c.fetchone())
    except Exception:
        _USERS_HAS_PASSWORD_CHANGED_AT = False
    return _USERS_HAS_PASSWORD_CHANGED_AT

def users_has_tutorial_seen_at_column():
    """Detect whether users.tutorial_seen_at exists on this DB."""
    global _USERS_HAS_TUTORIAL_SEEN_AT
    if _USERS_HAS_TUTORIAL_SEEN_AT is not None:
        return _USERS_HAS_TUTORIAL_SEEN_AT
    try:
        with db_connection() as conn:
            c = conn.cursor()
            db_execute(
                c,
                """SELECT 1
                   FROM information_schema.columns
                   WHERE table_schema = 'public'
                     AND table_name = 'users'
                     AND column_name = 'tutorial_seen_at'
                   LIMIT 1""",
                None,
            )
            _USERS_HAS_TUTORIAL_SEEN_AT = bool(c.fetchone())
    except Exception:
        _USERS_HAS_TUTORIAL_SEEN_AT = False
    return _USERS_HAS_TUTORIAL_SEEN_AT

def has_parent_seen_first_login_tutorial(parent_phone):
    phone = normalize_parent_phone(parent_phone)
    if not phone:
        return False
    if not ensure_extended_features_schema():
        return False
    try:
        with db_connection() as conn:
            c = conn.cursor()
            db_execute(
                c,
                """SELECT 1
                   FROM parent_tutorial_seen
                   WHERE parent_phone = ?
                   LIMIT 1""",
                (phone,),
            )
            return bool(c.fetchone())
    except Exception:
        return False

def mark_parent_first_login_tutorial_seen(parent_phone):
    phone = normalize_parent_phone(parent_phone)
    if not phone:
        return 0
    if not ensure_extended_features_schema():
        return 0
    try:
        with db_connection(commit=True) as conn:
            c = conn.cursor()
            db_execute(
                c,
                """INSERT INTO parent_tutorial_seen (parent_phone, seen_at)
                   VALUES (?, CURRENT_TIMESTAMP)
                   ON CONFLICT(parent_phone)
                   DO UPDATE SET seen_at = EXCLUDED.seen_at""",
                (phone,),
            )
            return int(c.rowcount or 0)
    except Exception:
        return 0

def has_user_seen_first_login_tutorial(username):
    uname = (username or '').strip().lower()
    if not uname:
        return False
    if not users_has_tutorial_seen_at_column():
        return False
    try:
        with db_connection() as conn:
            c = conn.cursor()
            db_execute(
                c,
                """SELECT tutorial_seen_at
                   FROM users
                   WHERE LOWER(username) = LOWER(?)
                   LIMIT 1""",
                (uname,),
            )
            row = c.fetchone()
            return bool(row and row[0])
    except Exception:
        return False

def mark_user_first_login_tutorial_seen(username):
    global _USERS_HAS_TUTORIAL_SEEN_AT
    uname = (username or '').strip().lower()
    if not uname:
        return 0
    if not users_has_tutorial_seen_at_column():
        return 0
    try:
        with db_connection(commit=True) as conn:
            c = conn.cursor()
            db_execute(
                c,
                """UPDATE users
                   SET tutorial_seen_at = CURRENT_TIMESTAMP
                   WHERE LOWER(username) = LOWER(?)""",
                (uname,),
            )
            return int(c.rowcount or 0)
    except Exception as exc:
        if 'tutorial_seen_at' in str(exc).lower():
            _USERS_HAS_TUTORIAL_SEEN_AT = False
            return 0
        return 0

def build_first_login_tutorial(role):
    role_name = (role or '').strip().lower()
    common = [
        'Use the left navigation menu to move between modules.',
        'Change your password to a strong private password.',
        'Complete your profile details before doing core tasks.',
    ]
    by_role = {
        'school_admin': [
            'Set school settings (term, year, grading, and result options).',
            'Configure class subjects before assigning teachers.',
            'Assign teachers to classes and subjects, then monitor submissions.',
        ],
        'teacher': [
            'Check your class and subject assignments on the dashboard.',
            'Enter scores only for your assigned classes/subjects.',
            'Submit completed scores/class results following workflow status.',
        ],
        'student': [
            'Open dashboard to view notices and published results.',
            'Set optional parent access phone/password if required.',
            'Use result view by published term and verify details.',
        ],
        'parent': [
            'Review linked children and open each student result.',
            'Track school notices and deadlines in dashboard alerts.',
            'Change parent password immediately for account security.',
        ],
    }
    title_map = {
        'school_admin': 'Welcome, School Admin',
        'teacher': 'Welcome, Teacher',
        'student': 'Welcome, Student',
        'parent': 'Welcome, Parent',
    }
    steps = by_role.get(role_name, []) + common
    return {
        'role': role_name,
        'title': title_map.get(role_name, 'Welcome'),
        'steps': steps,
    }

def students_promoted_is_boolean():
    """Detect whether students.promoted column is boolean on this DB."""
    global _STUDENTS_PROMOTED_IS_BOOL
    if _STUDENTS_PROMOTED_IS_BOOL is not None:
        return _STUDENTS_PROMOTED_IS_BOOL
    try:
        with db_connection() as conn:
            c = conn.cursor()
            db_execute(
                c,
                """SELECT data_type
                   FROM information_schema.columns
                   WHERE table_schema = 'public'
                     AND table_name = 'students'
                     AND column_name = 'promoted'
                   LIMIT 1""",
            )
            row = c.fetchone()
            _STUDENTS_PROMOTED_IS_BOOL = bool(row and str(row[0]).strip().lower() == 'boolean')
    except Exception:
        _STUDENTS_PROMOTED_IS_BOOL = False
    return _STUDENTS_PROMOTED_IS_BOOL

def normalize_promoted_db_value(value):
    """Return promoted value compatible with current students.promoted column type."""
    if students_promoted_is_boolean():
        return bool(value)
    return 1 if bool(value) else 0

# Set up logging
logging.basicConfig(filename='app.log', level=logging.INFO, 
                    format='%(asctime)s - %(levelname)s - %(message)s')
if ALLOW_INSECURE_DEFAULTS:
    logging.warning("ALLOW_INSECURE_DEFAULTS is enabled. Development-only fallbacks may be active.")
if STARTUP_FALLBACK_ENV_VARS:
    logging.warning(
        "Startup fallback env vars in use: %s",
        ', '.join(sorted(set(STARTUP_FALLBACK_ENV_VARS))),
    )

# Short-lived in-memory store for teacher CSV error exports.
CSV_ERROR_EXPORTS = {}

def _cleanup_csv_error_exports():
    cutoff = datetime.now() - timedelta(minutes=30)
    stale_tokens = [tok for tok, item in CSV_ERROR_EXPORTS.items() if item.get('created_at') and item['created_at'] < cutoff]
    for tok in stale_tokens:
        CSV_ERROR_EXPORTS.pop(tok, None)
    # Keep memory bounded in long-running process.
    if len(CSV_ERROR_EXPORTS) > 100:
        for tok, _item in sorted(CSV_ERROR_EXPORTS.items(), key=lambda kv: kv[1].get('created_at', datetime.min))[:len(CSV_ERROR_EXPORTS) - 100]:
            CSV_ERROR_EXPORTS.pop(tok, None)

def _store_csv_error_export(content, filename, owner_role='', owner_id='', school_id=''):
    _cleanup_csv_error_exports()
    token = secrets.token_urlsafe(18)
    CSV_ERROR_EXPORTS[token] = {
        'content': content,
        'filename': filename,
        'owner_role': (owner_role or '').strip().lower(),
        'owner_id': (owner_id or '').strip().lower(),
        'school_id': (school_id or '').strip(),
        'created_at': datetime.now(),
    }
    return token



def init_db():
    """Initialize the database with new schema for multi-school support."""
    conn = get_db()
    # we rely on db_execute committing each statement; this keeps the
    # connection in a usable state even if one DDL command fails.
    c = conn.cursor()

    # Fast path: if startup schema version is already applied, skip heavy DDL.
    try:
        db_execute(c, "SELECT to_regclass('public.app_meta')")
        row = c.fetchone()
        if row and row[0]:
            db_execute(c, 'SELECT value FROM app_meta WHERE key = ?', ('schema_version',))
            current = c.fetchone()
            if current and str(current[0] or '').strip() == STARTUP_SCHEMA_VERSION:
                logging.info("Schema already at version %s; skipping startup DDL.", STARTUP_SCHEMA_VERSION)
                conn.close()
                return
    except Exception as exc:
        # If fast-path check fails for any reason, continue with full migration path.
        logging.warning("Schema fast-path check failed; continuing with startup DDL: %s", exc)

    def safe_exec_ignore(sql):
        c.execute('SAVEPOINT ddl_ignore_stmt')
        try:
            c.execute(_adapt_query(sql))
        except Exception as e:
            c.execute('ROLLBACK TO SAVEPOINT ddl_ignore_stmt')
            logging.info("Ignored DB migration statement error: %s", e)
        finally:
            c.execute('RELEASE SAVEPOINT ddl_ignore_stmt')

    def _quote_ident(name):
        return '"' + str(name).replace('"', '""') + '"'

    def drop_school_id_foreign_keys():
        """
        Drop any FK constraints on public tables that include a school_id column.
        Legacy deployments may have varying FK names/types.
        """
        db_execute(c, 'SAVEPOINT ddl_ignore')
        try:
            db_execute(
                c,
                """SELECT ns.nspname, cls.relname, con.conname
                   FROM pg_constraint con
                   JOIN pg_class cls ON cls.oid = con.conrelid
                   JOIN pg_namespace ns ON ns.oid = cls.relnamespace
                   WHERE con.contype = 'f'
                     AND ns.nspname = 'public'
                     AND EXISTS (
                       SELECT 1
                       FROM unnest(con.conkey) AS ck(attnum)
                       JOIN pg_attribute a
                         ON a.attrelid = con.conrelid AND a.attnum = ck.attnum
                       WHERE a.attname = 'school_id'
                     )"""
            )
            for schema_name, table_name, con_name in c.fetchall() or []:
                safe_exec_ignore(
                    f'ALTER TABLE {_quote_ident(schema_name)}.{_quote_ident(table_name)} '
                    f'DROP CONSTRAINT IF EXISTS {_quote_ident(con_name)}'
                )
        except Exception:
            db_execute(c, 'ROLLBACK TO SAVEPOINT ddl_ignore')
        finally:
            db_execute(c, "RELEASE SAVEPOINT ddl_ignore")

    # Users table with roles: super_admin, school_admin, teacher, student
    db_execute(c, """CREATE TABLE IF NOT EXISTS users (
                        id SERIAL PRIMARY KEY,
                        username TEXT UNIQUE NOT NULL,
                        password_hash TEXT NOT NULL,
                        role TEXT DEFAULT 'student',
                        school_id TEXT,
                        terms_accepted INTEGER DEFAULT 0,
                        password_changed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        tutorial_seen_at TIMESTAMP,
                        current_login_at TIMESTAMP,
                        last_login_at TIMESTAMP,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )""")
    # Legacy compatibility: old databases may bind users.school_id to schools.id (INTEGER).
    # Drop old FK shape first, then keep school_id as TEXT across app tables.
    safe_exec_ignore('ALTER TABLE users DROP CONSTRAINT IF EXISTS fk_users_school')
    safe_exec_ignore('ALTER TABLE users DROP CONSTRAINT IF EXISTS users_school_id_fkey')
    safe_exec_ignore('ALTER TABLE students DROP CONSTRAINT IF EXISTS students_school_id_fkey')
    safe_exec_ignore('ALTER TABLE teachers DROP CONSTRAINT IF EXISTS teachers_school_id_fkey')
    safe_exec_ignore('ALTER TABLE class_assignments DROP CONSTRAINT IF EXISTS class_assignments_school_id_fkey')
    safe_exec_ignore('ALTER TABLE class_assignments DROP CONSTRAINT IF EXISTS class_assignments_school_id_teacher_id_fkey')
    drop_school_id_foreign_keys()
    safe_exec_ignore('ALTER TABLE users ALTER COLUMN school_id TYPE TEXT USING school_id::text')
    safe_exec_ignore(
        """ALTER TABLE users
           ADD CONSTRAINT chk_users_school_id_required
           CHECK (
             LOWER(COALESCE(role, 'student')) = 'super_admin'
             OR (school_id IS NOT NULL AND BTRIM(CAST(school_id AS TEXT)) <> '')
           ) NOT VALID"""
    )
    safe_exec_ignore('ALTER TABLE students ALTER COLUMN school_id TYPE TEXT USING school_id::text')
    safe_exec_ignore('ALTER TABLE teachers ALTER COLUMN school_id TYPE TEXT USING school_id::text')
    safe_exec_ignore('ALTER TABLE class_assignments ALTER COLUMN school_id TYPE TEXT USING school_id::text')
    safe_exec_ignore('ALTER TABLE class_subject_configs ALTER COLUMN school_id TYPE TEXT USING school_id::text')
    safe_exec_ignore('ALTER TABLE assessment_configs ALTER COLUMN school_id TYPE TEXT USING school_id::text')
    safe_exec_ignore('ALTER TABLE result_publications ALTER COLUMN school_id TYPE TEXT USING school_id::text')
    safe_exec_ignore('ALTER TABLE published_student_results ALTER COLUMN school_id TYPE TEXT USING school_id::text')
    safe_exec_ignore('ALTER TABLE result_views ALTER COLUMN school_id TYPE TEXT USING school_id::text')
    safe_exec_ignore('ALTER TABLE users ADD COLUMN terms_accepted INTEGER DEFAULT 0')
    safe_exec_ignore('ALTER TABLE users ADD COLUMN password_changed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP')
    safe_exec_ignore('UPDATE users SET password_changed_at = COALESCE(password_changed_at, CURRENT_TIMESTAMP)')
    safe_exec_ignore('ALTER TABLE users ADD COLUMN tutorial_seen_at TIMESTAMP')
    safe_exec_ignore('ALTER TABLE users ADD COLUMN current_login_at TIMESTAMP')
    safe_exec_ignore('ALTER TABLE users ADD COLUMN last_login_at TIMESTAMP')
    
    # Schools table
    db_execute(c, """CREATE TABLE IF NOT EXISTS schools (
                        id SERIAL PRIMARY KEY,
                        school_id TEXT UNIQUE NOT NULL,
                        school_name TEXT NOT NULL,
                        location TEXT,
                        school_logo TEXT,
                        academic_year TEXT,
                        current_term TEXT DEFAULT 'First Term',
                        operations_enabled INTEGER DEFAULT 1,
                        teacher_operations_enabled INTEGER DEFAULT 1,
                        test_enabled INTEGER DEFAULT 1,
                        exam_enabled INTEGER DEFAULT 1,
                        max_tests INTEGER DEFAULT 3,
                        test_score_max INTEGER DEFAULT 30,
                        exam_objective_max INTEGER DEFAULT 30,
                        exam_theory_max INTEGER DEFAULT 40,
                        grade_a_min INTEGER DEFAULT 70,
                        grade_b_min INTEGER DEFAULT 60,
                        grade_c_min INTEGER DEFAULT 50,
                        grade_d_min INTEGER DEFAULT 40,
                        pass_mark INTEGER DEFAULT 50,
                        show_positions INTEGER DEFAULT 1,
                        ss_ranking_mode TEXT DEFAULT 'together',
                        class_arm_ranking_mode TEXT DEFAULT 'separate',
                        combine_third_term_results INTEGER DEFAULT 0,
                        ss1_stream_mode TEXT DEFAULT 'separate',
                        theme_primary_color TEXT DEFAULT '#1E3C72',
                        theme_secondary_color TEXT DEFAULT '#2A5298',
                        theme_accent_color TEXT DEFAULT '#1F7A8C',
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )""")
    safe_exec_ignore('ALTER TABLE schools ADD COLUMN operations_enabled INTEGER DEFAULT 1')
    safe_exec_ignore('ALTER TABLE schools ADD COLUMN teacher_operations_enabled INTEGER DEFAULT 1')
    # Backfill grade config columns for existing databases.
    safe_exec_ignore('ALTER TABLE schools ADD COLUMN grade_a_min INTEGER DEFAULT 70')
    safe_exec_ignore('ALTER TABLE schools ADD COLUMN grade_b_min INTEGER DEFAULT 60')
    safe_exec_ignore('ALTER TABLE schools ADD COLUMN grade_c_min INTEGER DEFAULT 50')
    safe_exec_ignore('ALTER TABLE schools ADD COLUMN grade_d_min INTEGER DEFAULT 40')
    safe_exec_ignore('ALTER TABLE schools ADD COLUMN pass_mark INTEGER DEFAULT 50')
    safe_exec_ignore('ALTER TABLE schools ADD COLUMN show_positions INTEGER DEFAULT 1')
    safe_exec_ignore("ALTER TABLE schools ADD COLUMN ss_ranking_mode TEXT DEFAULT 'together'")
    safe_exec_ignore("ALTER TABLE schools ADD COLUMN class_arm_ranking_mode TEXT DEFAULT 'separate'")
    safe_exec_ignore("ALTER TABLE schools ADD COLUMN combine_third_term_results INTEGER DEFAULT 0")
    safe_exec_ignore("ALTER TABLE schools ADD COLUMN ss1_stream_mode TEXT DEFAULT 'separate'")
    safe_exec_ignore("ALTER TABLE schools ADD COLUMN theme_primary_color TEXT DEFAULT '#1E3C72'")
    safe_exec_ignore("ALTER TABLE schools ADD COLUMN theme_secondary_color TEXT DEFAULT '#2A5298'")
    safe_exec_ignore("ALTER TABLE schools ADD COLUMN theme_accent_color TEXT DEFAULT '#1F7A8C'")
    safe_exec_ignore("ALTER TABLE schools ADD COLUMN location TEXT")
    safe_exec_ignore("ALTER TABLE schools ADD COLUMN phone TEXT")
    safe_exec_ignore("ALTER TABLE schools ADD COLUMN email TEXT")
    safe_exec_ignore("ALTER TABLE schools ADD COLUMN principal_name TEXT")
    safe_exec_ignore("ALTER TABLE schools ADD COLUMN motto TEXT")
    safe_exec_ignore("ALTER TABLE schools ADD COLUMN updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP")
    safe_exec_ignore("ALTER TABLE schools ADD COLUMN principal_signature_image TEXT")

    # School term calendar (per school + academic year + term)
    db_execute(c, """CREATE TABLE IF NOT EXISTS school_term_calendars (
                        id SERIAL PRIMARY KEY,
                        school_id TEXT NOT NULL,
                        academic_year TEXT NOT NULL,
                        term TEXT NOT NULL,
                        open_date TEXT,
                        close_date TEXT,
                        midterm_break_start TEXT,
                        midterm_break_end TEXT,
                        exams_period_start TEXT,
                        exams_period_end TEXT,
                        pta_meeting_date TEXT,
                        interhouse_sports_date TEXT,
                        graduation_ceremony_date TEXT,
                        continuous_assessment_deadline TEXT,
                        school_events_date TEXT,
                        school_events TEXT,
                        next_term_begin_date TEXT,
                        program_meta_json TEXT DEFAULT '{}',
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        UNIQUE(school_id, academic_year, term)
                    )""")
    db_execute(c, 'CREATE INDEX IF NOT EXISTS idx_school_term_calendars_lookup ON school_term_calendars(school_id, academic_year, term)')
    safe_exec_ignore("ALTER TABLE school_term_calendars ADD COLUMN exams_period_start TEXT")
    safe_exec_ignore("ALTER TABLE school_term_calendars ADD COLUMN exams_period_end TEXT")
    safe_exec_ignore("ALTER TABLE school_term_calendars ADD COLUMN pta_meeting_date TEXT")
    safe_exec_ignore("ALTER TABLE school_term_calendars ADD COLUMN interhouse_sports_date TEXT")
    safe_exec_ignore("ALTER TABLE school_term_calendars ADD COLUMN graduation_ceremony_date TEXT")
    safe_exec_ignore("ALTER TABLE school_term_calendars ADD COLUMN continuous_assessment_deadline TEXT")
    safe_exec_ignore("ALTER TABLE school_term_calendars ADD COLUMN school_events_date TEXT")
    safe_exec_ignore("ALTER TABLE school_term_calendars ADD COLUMN school_events TEXT")
    safe_exec_ignore("ALTER TABLE school_term_calendars ADD COLUMN next_term_begin_date TEXT")
    safe_exec_ignore("ALTER TABLE school_term_calendars ADD COLUMN program_meta_json TEXT DEFAULT '{}'")
    
    # Migration: Add school_id column if it doesn't exist (for legacy databases)
    safe_exec_ignore("ALTER TABLE schools ADD COLUMN school_id TEXT")
    # Backfill school_id for existing schools (using id column value)
    safe_exec_ignore("UPDATE schools SET school_id = CAST(id AS TEXT) WHERE school_id IS NULL OR school_id = ''")
    # Migrate all tables to use schools.id (as text) for school_id values.
    # This normalizes legacy text IDs to index-based IDs.
    safe_exec_ignore('ALTER TABLE class_assignments DROP CONSTRAINT IF EXISTS fk_class_assignments_teacher')
    safe_exec_ignore('ALTER TABLE class_assignments DROP CONSTRAINT IF EXISTS fk_class_assignments_school')
    safe_exec_ignore('ALTER TABLE teachers DROP CONSTRAINT IF EXISTS fk_teachers_school')
    safe_exec_ignore('ALTER TABLE students DROP CONSTRAINT IF EXISTS fk_students_school')
    try:
        db_execute(
            c,
            """WITH mapping AS (
                   SELECT CAST(id AS TEXT) AS new_school_id, school_id AS old_school_id
                   FROM schools
               )
               UPDATE users u
               SET school_id = m.new_school_id
               FROM mapping m
               WHERE CAST(u.school_id AS TEXT) = m.old_school_id
                 AND CAST(u.school_id AS TEXT) <> m.new_school_id"""
        )
        db_execute(
            c,
            """WITH mapping AS (
                   SELECT CAST(id AS TEXT) AS new_school_id, school_id AS old_school_id
                   FROM schools
               )
               UPDATE students s
               SET school_id = m.new_school_id
               FROM mapping m
               WHERE s.school_id = m.old_school_id
                 AND s.school_id <> m.new_school_id"""
        )
        db_execute(
            c,
            """WITH mapping AS (
                   SELECT CAST(id AS TEXT) AS new_school_id, school_id AS old_school_id
                   FROM schools
               )
               UPDATE teachers t
               SET school_id = m.new_school_id
               FROM mapping m
               WHERE t.school_id = m.old_school_id
                 AND t.school_id <> m.new_school_id"""
        )
        db_execute(
            c,
            """WITH mapping AS (
                   SELECT CAST(id AS TEXT) AS new_school_id, school_id AS old_school_id
                   FROM schools
               )
               UPDATE class_assignments ca
               SET school_id = m.new_school_id
               FROM mapping m
               WHERE ca.school_id = m.old_school_id
                 AND ca.school_id <> m.new_school_id"""
        )
        db_execute(
            c,
            """WITH mapping AS (
                   SELECT CAST(id AS TEXT) AS new_school_id, school_id AS old_school_id
                   FROM schools
               )
               UPDATE class_subject_configs cfg
               SET school_id = m.new_school_id
               FROM mapping m
               WHERE cfg.school_id = m.old_school_id
                 AND cfg.school_id <> m.new_school_id"""
        )
        db_execute(
            c,
            """WITH mapping AS (
                   SELECT CAST(id AS TEXT) AS new_school_id, school_id AS old_school_id
                   FROM schools
               )
               UPDATE assessment_configs ac
               SET school_id = m.new_school_id
               FROM mapping m
               WHERE ac.school_id = m.old_school_id
                 AND ac.school_id <> m.new_school_id"""
        )
        db_execute(
            c,
            """WITH mapping AS (
                   SELECT CAST(id AS TEXT) AS new_school_id, school_id AS old_school_id
                   FROM schools
               )
               UPDATE result_publications rp
               SET school_id = m.new_school_id
               FROM mapping m
               WHERE rp.school_id = m.old_school_id
                 AND rp.school_id <> m.new_school_id"""
        )
        db_execute(
            c,
            """WITH mapping AS (
                   SELECT CAST(id AS TEXT) AS new_school_id, school_id AS old_school_id
                   FROM schools
               )
               UPDATE published_student_results psr
               SET school_id = m.new_school_id
               FROM mapping m
               WHERE psr.school_id = m.old_school_id
                 AND psr.school_id <> m.new_school_id"""
        )
        db_execute(
            c,
            """WITH mapping AS (
                   SELECT CAST(id AS TEXT) AS new_school_id, school_id AS old_school_id
                   FROM schools
               )
               UPDATE result_views rv
               SET school_id = m.new_school_id
               FROM mapping m
               WHERE rv.school_id = m.old_school_id
                 AND rv.school_id <> m.new_school_id"""
        )
        db_execute(
            c,
            """UPDATE users u
               SET school_id = s.school_id
               FROM students s
               WHERE (u.school_id IS NULL OR BTRIM(CAST(u.school_id AS TEXT)) = '')
                 AND LOWER(COALESCE(u.role, 'student')) = 'student'
                 AND LOWER(u.username) = LOWER(s.student_id)"""
        )
        db_execute(
            c,
            """UPDATE users u
               SET school_id = t.school_id
               FROM teachers t
               WHERE (u.school_id IS NULL OR BTRIM(CAST(u.school_id AS TEXT)) = '')
                 AND LOWER(COALESCE(u.role, 'student')) = 'teacher'
                 AND LOWER(u.username) = LOWER(t.user_id)"""
        )
        db_execute(c, 'UPDATE schools SET school_id = CAST(id AS TEXT) WHERE school_id <> CAST(id AS TEXT)')
    except Exception as exc:
        logging.warning("Legacy school_id backfill skipped due to error: %s", exc)
    
    # Students table with ID format: YY/school_id/index/start_year_yy
    db_execute(c, """CREATE TABLE IF NOT EXISTS students (
                        id SERIAL PRIMARY KEY,
                        user_id TEXT NOT NULL,
                        school_id TEXT NOT NULL,
                        student_id TEXT NOT NULL,
                        firstname TEXT NOT NULL,
                        date_of_birth TEXT,
                        gender TEXT,
                        classname TEXT NOT NULL,
                        first_year_class TEXT NOT NULL,
                        term TEXT NOT NULL,
                        stream TEXT NOT NULL,
                        number_of_subject INTEGER NOT NULL,
                        subjects TEXT NOT NULL,
                        scores TEXT,
                        promoted INTEGER DEFAULT 0,
                        parent_phone TEXT,
                        parent_password_hash TEXT,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        UNIQUE(school_id, student_id)
                    )""")
    safe_exec_ignore("ALTER TABLE students ADD COLUMN date_of_birth TEXT")
    safe_exec_ignore("ALTER TABLE students ADD COLUMN gender TEXT")
    safe_exec_ignore("ALTER TABLE students ADD COLUMN parent_phone TEXT")
    safe_exec_ignore("ALTER TABLE students ADD COLUMN parent_password_hash TEXT")
    safe_exec_ignore("ALTER TABLE students ADD COLUMN is_archived INTEGER DEFAULT 0")
    safe_exec_ignore("ALTER TABLE students ADD COLUMN archived_at TIMESTAMP")
    
    # Teachers table
    db_execute(c, """CREATE TABLE IF NOT EXISTS teachers (
                        id SERIAL PRIMARY KEY,
                        user_id TEXT NOT NULL,
                        school_id TEXT NOT NULL,
                        firstname TEXT NOT NULL,
                        lastname TEXT NOT NULL,
                        phone TEXT,
                        gender TEXT,
                        signature_image TEXT,
                        profile_image TEXT,
                        assigned_classes TEXT,
                        subjects_taught TEXT,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )""")
    safe_exec_ignore("ALTER TABLE teachers ADD COLUMN phone TEXT")
    safe_exec_ignore("ALTER TABLE teachers ADD COLUMN gender TEXT")
    safe_exec_ignore("ALTER TABLE teachers ADD COLUMN signature_image TEXT")
    safe_exec_ignore("ALTER TABLE teachers ADD COLUMN profile_image TEXT")
    safe_exec_ignore("ALTER TABLE teachers ADD COLUMN subjects_taught TEXT")
    safe_exec_ignore("ALTER TABLE teachers ADD COLUMN is_archived INTEGER DEFAULT 0")
    safe_exec_ignore("ALTER TABLE teachers ADD COLUMN archived_at TIMESTAMP")
    
    # Class assignments
    db_execute(c, """CREATE TABLE IF NOT EXISTS class_assignments (
                        id SERIAL PRIMARY KEY,
                        school_id TEXT NOT NULL,
                        teacher_id TEXT NOT NULL,
                        classname TEXT NOT NULL,
                        term TEXT NOT NULL,
                        academic_year TEXT NOT NULL
                    )""")
    db_execute(c, """CREATE TABLE IF NOT EXISTS teacher_subject_assignments (
                        id SERIAL PRIMARY KEY,
                        school_id TEXT NOT NULL,
                        teacher_id TEXT NOT NULL,
                        classname TEXT NOT NULL,
                        subject TEXT NOT NULL,
                        term TEXT NOT NULL,
                        academic_year TEXT NOT NULL
                    )""")

    # Class subject configuration (set by school admin).
    db_execute(c, """CREATE TABLE IF NOT EXISTS class_subject_configs (
                        id SERIAL PRIMARY KEY,
                        school_id TEXT NOT NULL,
                        classname TEXT NOT NULL,
                        core_subjects TEXT NOT NULL,
                        science_subjects TEXT,
                        art_subjects TEXT,
                        commercial_subjects TEXT,
                        optional_subjects TEXT,
                        optional_subject_limit INTEGER DEFAULT 0,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        UNIQUE(school_id, classname)
                    )""")
    # Global subject catalog by class (shared across all schools).
    db_execute(c, """CREATE TABLE IF NOT EXISTS global_class_subject_catalog (
                        id SERIAL PRIMARY KEY,
                        classname TEXT NOT NULL,
                        bucket TEXT NOT NULL,
                        subject_name TEXT NOT NULL,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        UNIQUE(classname, bucket, subject_name)
                    )""")

    # Per-level assessment/exam configuration (primary, jss, ss).
    db_execute(c, """CREATE TABLE IF NOT EXISTS assessment_configs (
                        id SERIAL PRIMARY KEY,
                        school_id TEXT NOT NULL,
                        level TEXT NOT NULL,
                        exam_mode TEXT NOT NULL DEFAULT 'separate',
                        objective_max INTEGER NOT NULL DEFAULT 30,
                        theory_max INTEGER NOT NULL DEFAULT 40,
                        exam_score_max INTEGER NOT NULL DEFAULT 70,
                        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        UNIQUE(school_id, level)
                    )""")
    # Result publication/ranking gate per class + term.
    db_execute(c, """CREATE TABLE IF NOT EXISTS result_publications (
                        id SERIAL PRIMARY KEY,
                        school_id TEXT NOT NULL,
                        classname TEXT NOT NULL,
                        term TEXT NOT NULL,
                        academic_year TEXT DEFAULT '',
                        teacher_id TEXT NOT NULL,
                        teacher_name TEXT DEFAULT '',
                        principal_name TEXT DEFAULT '',
                        is_published INTEGER NOT NULL DEFAULT 0,
                        published_at TIMESTAMP,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        UNIQUE(school_id, classname, term, academic_year)
                    )""")
    safe_exec_ignore("ALTER TABLE result_publications ADD COLUMN academic_year TEXT DEFAULT ''")
    safe_exec_ignore("ALTER TABLE result_publications ADD COLUMN teacher_name TEXT DEFAULT ''")
    safe_exec_ignore("ALTER TABLE result_publications ADD COLUMN principal_name TEXT DEFAULT ''")
    safe_exec_ignore("ALTER TABLE result_publications ADD COLUMN approval_status TEXT DEFAULT 'not_submitted'")
    safe_exec_ignore("ALTER TABLE result_publications ADD COLUMN submitted_at TIMESTAMP")
    safe_exec_ignore("ALTER TABLE result_publications ADD COLUMN submitted_by TEXT")
    safe_exec_ignore("ALTER TABLE result_publications ADD COLUMN reviewed_at TIMESTAMP")
    safe_exec_ignore("ALTER TABLE result_publications ADD COLUMN reviewed_by TEXT")
    safe_exec_ignore("ALTER TABLE result_publications ADD COLUMN review_note TEXT")
    # Immutable snapshot of published student results per term.
    db_execute(c, """CREATE TABLE IF NOT EXISTS published_student_results (
                        id SERIAL PRIMARY KEY,
                        school_id TEXT NOT NULL,
                        student_id TEXT NOT NULL,
                        firstname TEXT NOT NULL,
                        classname TEXT NOT NULL,
                        academic_year TEXT,
                        term TEXT NOT NULL,
                        stream TEXT NOT NULL,
                        number_of_subject INTEGER NOT NULL,
                        subjects TEXT NOT NULL,
                        scores TEXT NOT NULL,
                        behaviour_json TEXT DEFAULT '{}',
                        teacher_comment TEXT,
                        principal_comment TEXT,
                        average_marks REAL NOT NULL DEFAULT 0,
                        grade TEXT NOT NULL,
                        status TEXT NOT NULL,
                        published_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        UNIQUE(school_id, student_id, academic_year, term)
                    )""")
    db_execute(c, """CREATE TABLE IF NOT EXISTS score_audit_logs (
                        id SERIAL PRIMARY KEY,
                        school_id TEXT NOT NULL,
                        student_id TEXT NOT NULL,
                        classname TEXT NOT NULL,
                        term TEXT NOT NULL,
                        academic_year TEXT DEFAULT '',
                        subject TEXT NOT NULL,
                        old_score_json TEXT,
                        new_score_json TEXT,
                        changed_fields_json TEXT,
                        changed_by TEXT NOT NULL,
                        changed_by_role TEXT NOT NULL,
                        change_source TEXT NOT NULL,
                        change_reason TEXT DEFAULT '',
                        changed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )""")
    # Track when students view published results.
    db_execute(c, """CREATE TABLE IF NOT EXISTS result_views (
                        id SERIAL PRIMARY KEY,
                        school_id TEXT NOT NULL,
                        student_id TEXT NOT NULL,
                        term TEXT NOT NULL,
                        academic_year TEXT DEFAULT '',
                        first_viewed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        last_viewed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        view_count INTEGER NOT NULL DEFAULT 1,
                        UNIQUE(school_id, student_id, term, academic_year)
                    )""")
    safe_exec_ignore('ALTER TABLE published_student_results ADD COLUMN teacher_comment TEXT')
    safe_exec_ignore("ALTER TABLE published_student_results ADD COLUMN behaviour_json TEXT DEFAULT '{}'")
    safe_exec_ignore('ALTER TABLE published_student_results ADD COLUMN principal_comment TEXT')
    safe_exec_ignore('ALTER TABLE published_student_results ADD COLUMN academic_year TEXT')
    db_execute(c, """CREATE TABLE IF NOT EXISTS behaviour_assessments (
                        id SERIAL PRIMARY KEY,
                        school_id TEXT NOT NULL,
                        student_id TEXT NOT NULL,
                        classname TEXT NOT NULL,
                        term TEXT NOT NULL,
                        academic_year TEXT DEFAULT '',
                        behaviour_json TEXT NOT NULL DEFAULT '{}',
                        updated_by TEXT DEFAULT '',
                        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        UNIQUE(school_id, student_id, term, academic_year)
                    )""")
    db_execute(c, """CREATE TABLE IF NOT EXISTS student_attendance (
                        id SERIAL PRIMARY KEY,
                        school_id TEXT NOT NULL,
                        student_id TEXT NOT NULL,
                        classname TEXT NOT NULL,
                        term TEXT NOT NULL,
                        academic_year TEXT DEFAULT '',
                        attendance_date TEXT NOT NULL,
                        status TEXT NOT NULL,
                        note TEXT DEFAULT '',
                        marked_by TEXT DEFAULT '',
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        UNIQUE(school_id, student_id, attendance_date)
                    )""")
    safe_exec_ignore("ALTER TABLE score_audit_logs ADD COLUMN academic_year TEXT DEFAULT ''")
    safe_exec_ignore("ALTER TABLE score_audit_logs ADD COLUMN changed_by_role TEXT DEFAULT 'teacher'")
    safe_exec_ignore("ALTER TABLE score_audit_logs ADD COLUMN change_source TEXT DEFAULT 'manual_entry'")
    safe_exec_ignore("ALTER TABLE score_audit_logs ADD COLUMN change_reason TEXT DEFAULT ''")
    
    # Reports table
    db_execute(c, """CREATE TABLE IF NOT EXISTS reports (
                        id SERIAL PRIMARY KEY,
                        user_id TEXT NOT NULL,
                        description TEXT NOT NULL,
                        timestamp TEXT NOT NULL,
                        status TEXT DEFAULT 'unread',
                        read_at TEXT
                    )""")
    # Login attempt tracking for brute-force protection.
    db_execute(c, """CREATE TABLE IF NOT EXISTS login_attempts (
                        id SERIAL PRIMARY KEY,
                        endpoint TEXT NOT NULL,
                        username TEXT NOT NULL,
                        ip_address TEXT NOT NULL,
                        failures INTEGER NOT NULL DEFAULT 0,
                        first_failed_at TIMESTAMP,
                        last_failed_at TIMESTAMP,
                        locked_until TIMESTAMP,
                        UNIQUE(endpoint, username, ip_address)
                    )""")
    db_execute(c, """CREATE TABLE IF NOT EXISTS login_audit_logs (
                        id SERIAL PRIMARY KEY,
                        school_id TEXT,
                        username TEXT NOT NULL,
                        role TEXT DEFAULT '',
                        endpoint TEXT NOT NULL,
                        ip_address TEXT DEFAULT '',
                        user_agent TEXT DEFAULT '',
                        success INTEGER NOT NULL DEFAULT 0,
                        reason TEXT DEFAULT '',
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )""")
    db_execute(c, """CREATE TABLE IF NOT EXISTS class_timetables (
                        id SERIAL PRIMARY KEY,
                        school_id TEXT NOT NULL,
                        classname TEXT NOT NULL,
                        day_of_week INTEGER NOT NULL,
                        period_label TEXT NOT NULL,
                        subject TEXT NOT NULL,
                        teacher_id TEXT DEFAULT '',
                        start_time TEXT DEFAULT '',
                        end_time TEXT DEFAULT '',
                        room TEXT DEFAULT '',
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        UNIQUE(school_id, classname, day_of_week, period_label)
                    )""")
    db_execute(c, """CREATE TABLE IF NOT EXISTS period_attendance (
                        id SERIAL PRIMARY KEY,
                        school_id TEXT NOT NULL,
                        student_id TEXT NOT NULL,
                        classname TEXT NOT NULL,
                        term TEXT NOT NULL,
                        academic_year TEXT DEFAULT '',
                        attendance_date TEXT NOT NULL,
                        period_label TEXT NOT NULL,
                        subject TEXT DEFAULT '',
                        status TEXT NOT NULL,
                        note TEXT DEFAULT '',
                        marked_by TEXT DEFAULT '',
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        UNIQUE(school_id, student_id, attendance_date, period_label)
                    )""")
    db_execute(c, """CREATE TABLE IF NOT EXISTS term_edit_locks (
                        id SERIAL PRIMARY KEY,
                        school_id TEXT NOT NULL,
                        classname TEXT NOT NULL,
                        term TEXT NOT NULL,
                        academic_year TEXT DEFAULT '',
                        is_locked INTEGER NOT NULL DEFAULT 1,
                        unlocked_until TIMESTAMP,
                        unlock_reason TEXT DEFAULT '',
                        unlocked_by TEXT DEFAULT '',
                        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        UNIQUE(school_id, classname, term, academic_year)
                    )""")
    safe_exec_ignore("ALTER TABLE period_attendance ADD COLUMN subject TEXT DEFAULT ''")
    db_execute(c, """CREATE TABLE IF NOT EXISTS promotion_audit_logs (
                        id SERIAL PRIMARY KEY,
                        school_id TEXT NOT NULL,
                        student_id TEXT NOT NULL,
                        student_name TEXT DEFAULT '',
                        from_class TEXT DEFAULT '',
                        to_class TEXT DEFAULT '',
                        action TEXT NOT NULL,
                        term TEXT DEFAULT '',
                        academic_year TEXT DEFAULT '',
                        changed_by TEXT DEFAULT '',
                        note TEXT DEFAULT '',
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )""")
    db_execute(c, """CREATE TABLE IF NOT EXISTS result_disputes (
                        id SERIAL PRIMARY KEY,
                        school_id TEXT NOT NULL,
                        student_id TEXT NOT NULL,
                        classname TEXT DEFAULT '',
                        term TEXT DEFAULT '',
                        academic_year TEXT DEFAULT '',
                        parent_phone TEXT DEFAULT '',
                        title TEXT NOT NULL,
                        details TEXT NOT NULL,
                        status TEXT NOT NULL DEFAULT 'open',
                        resolution_note TEXT DEFAULT '',
                        created_by TEXT DEFAULT '',
                        resolved_by TEXT DEFAULT '',
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        resolved_at TIMESTAMP
                    )""")
    db_execute(c, """CREATE TABLE IF NOT EXISTS student_messages (
                        id SERIAL PRIMARY KEY,
                        school_id TEXT NOT NULL,
                        title TEXT NOT NULL,
                        message TEXT NOT NULL,
                        target_classname TEXT DEFAULT '',
                        target_stream TEXT DEFAULT '',
                        deadline_date TEXT DEFAULT '',
                        is_active INTEGER NOT NULL DEFAULT 1,
                        created_by TEXT DEFAULT '',
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )""")
    db_execute(c, """CREATE TABLE IF NOT EXISTS parent_tutorial_seen (
                        id SERIAL PRIMARY KEY,
                        parent_phone TEXT UNIQUE NOT NULL,
                        seen_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )""")
    db_execute(c, """CREATE TABLE IF NOT EXISTS teacher_messages (
                        id SERIAL PRIMARY KEY,
                        school_id TEXT NOT NULL,
                        title TEXT NOT NULL,
                        message TEXT NOT NULL,
                        target_classname TEXT DEFAULT '',
                        target_subject TEXT DEFAULT '',
                        deadline_date TEXT DEFAULT '',
                        is_active INTEGER NOT NULL DEFAULT 1,
                        created_by TEXT DEFAULT '',
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )""")
    db_execute(c, """CREATE TABLE IF NOT EXISTS student_message_reads (
                        id SERIAL PRIMARY KEY,
                        school_id TEXT NOT NULL,
                        message_id INTEGER NOT NULL,
                        student_id TEXT NOT NULL,
                        read_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        UNIQUE(school_id, message_id, student_id)
                    )""")
    db_execute(c, """CREATE TABLE IF NOT EXISTS teacher_message_reads (
                        id SERIAL PRIMARY KEY,
                        school_id TEXT NOT NULL,
                        message_id INTEGER NOT NULL,
                        teacher_id TEXT NOT NULL,
                        read_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        UNIQUE(school_id, message_id, teacher_id)
                    )""")
    db_execute(c, """CREATE TABLE IF NOT EXISTS parent_message_reads (
                        id SERIAL PRIMARY KEY,
                        school_id TEXT NOT NULL,
                        message_id INTEGER NOT NULL,
                        parent_phone TEXT NOT NULL,
                        read_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        UNIQUE(school_id, message_id, parent_phone)
                    )""")

    # Create indexes
    db_execute(c, 'CREATE INDEX IF NOT EXISTS idx_users_username ON users(username)')
    db_execute(c, 'CREATE INDEX IF NOT EXISTS idx_users_username_lower ON users(LOWER(username))')
    try:
        db_execute(c, 'CREATE UNIQUE INDEX IF NOT EXISTS uq_users_username_lower ON users(LOWER(username))')
    except Exception as exc:
        logging.warning("Could not enforce case-insensitive username uniqueness: %s", exc)
    db_execute(c, 'CREATE INDEX IF NOT EXISTS idx_users_role ON users(role)')
    db_execute(c, 'CREATE INDEX IF NOT EXISTS idx_students_school ON students(school_id)')
    db_execute(c, 'CREATE INDEX IF NOT EXISTS idx_students_school_archived ON students(school_id, is_archived)')
    db_execute(c, 'CREATE INDEX IF NOT EXISTS idx_students_student_id_lower ON students(LOWER(student_id))')
    db_execute(c, 'CREATE INDEX IF NOT EXISTS idx_students_class ON students(school_id, classname)')
    db_execute(c, 'CREATE INDEX IF NOT EXISTS idx_students_school_class_term ON students(school_id, classname, term)')
    db_execute(c, 'CREATE INDEX IF NOT EXISTS idx_students_school_term ON students(school_id, term)')
    db_execute(c, 'CREATE INDEX IF NOT EXISTS idx_teachers_school ON teachers(school_id)')
    db_execute(c, 'CREATE INDEX IF NOT EXISTS idx_teachers_school_archived ON teachers(school_id, is_archived)')
    db_execute(c, 'CREATE INDEX IF NOT EXISTS idx_teachers_school_user ON teachers(school_id, user_id)')
    db_execute(c, 'CREATE INDEX IF NOT EXISTS idx_teacher_subject_assignments_lookup ON teacher_subject_assignments(school_id, teacher_id, classname, term, academic_year)')
    db_execute(c, 'CREATE INDEX IF NOT EXISTS idx_class_subject_configs_school_class ON class_subject_configs(school_id, classname)')
    db_execute(c, 'CREATE INDEX IF NOT EXISTS idx_global_subject_catalog_class_bucket ON global_class_subject_catalog(classname, bucket)')
    db_execute(c, 'CREATE INDEX IF NOT EXISTS idx_assessment_configs_school_level ON assessment_configs(school_id, level)')
    db_execute(c, 'CREATE INDEX IF NOT EXISTS idx_result_views_lookup ON result_views(school_id, term, student_id)')
    db_execute(c, 'CREATE INDEX IF NOT EXISTS idx_result_views_lookup_year ON result_views(school_id, term, academic_year, student_id)')
    db_execute(c, 'CREATE INDEX IF NOT EXISTS idx_login_attempts_lookup ON login_attempts(endpoint, username, ip_address)')
    db_execute(c, 'CREATE INDEX IF NOT EXISTS idx_login_attempts_locked_until ON login_attempts(locked_until)')
    db_execute(c, 'CREATE INDEX IF NOT EXISTS idx_login_audit_school_created ON login_audit_logs(school_id, created_at DESC)')
    db_execute(c, 'CREATE INDEX IF NOT EXISTS idx_login_audit_username_created ON login_audit_logs(username, created_at DESC)')
    db_execute(c, 'CREATE INDEX IF NOT EXISTS idx_timetable_school_class_day ON class_timetables(school_id, classname, day_of_week)')
    db_execute(c, 'CREATE INDEX IF NOT EXISTS idx_period_att_school_class_date ON period_attendance(school_id, classname, attendance_date)')
    db_execute(c, 'CREATE INDEX IF NOT EXISTS idx_period_att_school_class_subject_date ON period_attendance(school_id, classname, subject, attendance_date)')
    db_execute(c, 'CREATE INDEX IF NOT EXISTS idx_period_att_school_term_year ON period_attendance(school_id, term, academic_year)')
    db_execute(c, 'CREATE INDEX IF NOT EXISTS idx_promotion_audit_school_created ON promotion_audit_logs(school_id, created_at DESC)')
    db_execute(c, 'CREATE INDEX IF NOT EXISTS idx_disputes_school_status_created ON result_disputes(school_id, status, created_at DESC)')
    db_execute(c, 'CREATE INDEX IF NOT EXISTS idx_student_messages_school_created ON student_messages(school_id, created_at DESC)')
    db_execute(c, 'CREATE INDEX IF NOT EXISTS idx_student_messages_school_active ON student_messages(school_id, is_active)')
    db_execute(c, 'CREATE INDEX IF NOT EXISTS idx_parent_tutorial_seen_phone ON parent_tutorial_seen(parent_phone)')
    db_execute(c, 'CREATE INDEX IF NOT EXISTS idx_teacher_messages_school_created ON teacher_messages(school_id, created_at DESC)')
    db_execute(c, 'CREATE INDEX IF NOT EXISTS idx_teacher_messages_school_active ON teacher_messages(school_id, is_active)')
    db_execute(c, 'CREATE INDEX IF NOT EXISTS idx_student_message_reads_lookup ON student_message_reads(school_id, student_id, message_id)')
    db_execute(c, 'CREATE INDEX IF NOT EXISTS idx_teacher_message_reads_lookup ON teacher_message_reads(school_id, teacher_id, message_id)')
    db_execute(c, 'CREATE INDEX IF NOT EXISTS idx_parent_message_reads_lookup ON parent_message_reads(school_id, parent_phone, message_id)')
    db_execute(c, 'CREATE INDEX IF NOT EXISTS idx_result_publications_school_class_term_year ON result_publications(school_id, classname, term, academic_year)')
    db_execute(c, 'CREATE INDEX IF NOT EXISTS idx_published_school_class_term_year ON published_student_results(school_id, classname, term, academic_year)')
    db_execute(c, 'CREATE INDEX IF NOT EXISTS idx_published_school_student_term_year ON published_student_results(school_id, student_id, term, academic_year)')
    db_execute(c, 'CREATE INDEX IF NOT EXISTS idx_term_edit_locks_scope ON term_edit_locks(school_id, classname, term, academic_year)')
    db_execute(c, 'CREATE INDEX IF NOT EXISTS idx_score_audit_school_student_changed ON score_audit_logs(school_id, student_id, changed_at)')
    db_execute(c, 'CREATE INDEX IF NOT EXISTS idx_score_audit_school_class_term_year ON score_audit_logs(school_id, classname, term, academic_year)')
    db_execute(c, 'CREATE INDEX IF NOT EXISTS idx_attendance_school_class_date ON student_attendance(school_id, classname, attendance_date)')
    db_execute(c, 'CREATE INDEX IF NOT EXISTS idx_attendance_school_term_year ON student_attendance(school_id, term, academic_year)')
    # Ensure upsert target exists for students ON CONFLICT(school_id, student_id).
    db_execute(
        c,
        """DELETE FROM students
           WHERE id NOT IN (
             SELECT MIN(id)
             FROM students
             GROUP BY school_id, student_id
           )"""
    )
    db_execute(c, 'CREATE UNIQUE INDEX IF NOT EXISTS uq_students_school_student ON students(school_id, student_id)')
    # Normalize and deduplicate class subject config class names (e.g. "Primary 1" -> "PRIMARY1").
    db_execute(
        c,
        """DELETE FROM class_subject_configs
           WHERE id NOT IN (
             SELECT MIN(id)
             FROM class_subject_configs
             GROUP BY school_id, REGEXP_REPLACE(UPPER(classname), '[^A-Z0-9]+', '', 'g')
           )"""
    )
    db_execute(
        c,
        """UPDATE class_subject_configs
           SET classname = REGEXP_REPLACE(UPPER(classname), '[^A-Z0-9]+', '', 'g')
           WHERE classname <> REGEXP_REPLACE(UPPER(classname), '[^A-Z0-9]+', '', 'g')"""
    )
    # Deduplicate legacy assignment rows before enforcing uniqueness.
    db_execute(
        c,
        """DELETE FROM class_assignments
           WHERE id NOT IN (
             SELECT MIN(id)
             FROM class_assignments
             GROUP BY school_id, teacher_id, classname, term, academic_year
           )"""
    )
    db_execute(
        c,
        """DELETE FROM teacher_subject_assignments
           WHERE id NOT IN (
             SELECT MIN(id)
             FROM teacher_subject_assignments
             GROUP BY school_id, classname, subject, term, academic_year
           )"""
    )
    safe_exec_ignore('DROP INDEX IF EXISTS uq_class_assignments')
    safe_exec_ignore('DROP INDEX IF EXISTS uq_teacher_subject_assignment')
    safe_exec_ignore('DROP INDEX IF EXISTS uq_class_term_assignment')
    db_execute(c, 'CREATE UNIQUE INDEX IF NOT EXISTS uq_class_assignments ON class_assignments(school_id, teacher_id, classname, term, academic_year)')
    db_execute(c, 'CREATE UNIQUE INDEX IF NOT EXISTS uq_teacher_subject_assignment ON teacher_subject_assignments(school_id, classname, subject, term, academic_year)')
    # Ensure one teacher per class per term and academic year.
    db_execute(
        c,
        """DELETE FROM class_assignments
           WHERE id NOT IN (
             SELECT MIN(id)
             FROM class_assignments
             GROUP BY school_id, classname, term, academic_year
           )"""
    )
    db_execute(c, 'CREATE UNIQUE INDEX IF NOT EXISTS uq_class_term_assignment ON class_assignments(school_id, classname, term, academic_year)')
    # Deduplicate legacy teacher rows before enforcing one profile per school/user.
    db_execute(
        c,
        """DELETE FROM teachers
           WHERE id NOT IN (
             SELECT MIN(id)
             FROM teachers
             GROUP BY school_id, user_id
           )"""
    )
    db_execute(c, 'CREATE UNIQUE INDEX IF NOT EXISTS uq_teachers_school_user ON teachers(school_id, user_id)')
    # Rebuild publication uniqueness to include academic year.
    db_execute(
        c,
        """DELETE FROM result_publications
           WHERE id NOT IN (
             SELECT MIN(id)
             FROM result_publications
             GROUP BY school_id, classname, term, COALESCE(academic_year, '')
           )"""
    )
    safe_exec_ignore('ALTER TABLE result_publications DROP CONSTRAINT IF EXISTS result_publications_school_id_classname_term_key')
    safe_exec_ignore('DROP INDEX IF EXISTS result_publications_school_id_classname_term_key')
    safe_exec_ignore('DROP INDEX IF EXISTS uq_result_publications')
    db_execute(c, 'CREATE UNIQUE INDEX IF NOT EXISTS uq_result_publications ON result_publications(school_id, classname, term, academic_year)')
    # Auto-heal legacy/orphan school references before adding FK guards.
    # This preserves rows by creating placeholder school records when needed.
    db_execute(
        c,
        """INSERT INTO schools (school_id, school_name)
           SELECT x.school_id, CONCAT('Recovered School ', x.school_id)
           FROM (
               SELECT DISTINCT school_id FROM students WHERE school_id IS NOT NULL AND school_id <> ''
               UNION
               SELECT DISTINCT school_id FROM teachers WHERE school_id IS NOT NULL AND school_id <> ''
               UNION
               SELECT DISTINCT school_id FROM class_assignments WHERE school_id IS NOT NULL AND school_id <> ''
           ) x
           LEFT JOIN schools s ON s.school_id = x.school_id
           WHERE s.school_id IS NULL"""
    )
    # Best-effort tenancy integrity constraints for multi-school isolation.
    # Use NOT VALID for legacy deployments with pre-existing dirty data.
    # This creates FK guards for new writes immediately and allows later validation.
    safe_exec_ignore('ALTER TABLE students ADD CONSTRAINT fk_students_school FOREIGN KEY (school_id) REFERENCES schools(school_id) ON DELETE CASCADE NOT VALID')
    safe_exec_ignore('ALTER TABLE teachers ADD CONSTRAINT fk_teachers_school FOREIGN KEY (school_id) REFERENCES schools(school_id) ON DELETE CASCADE NOT VALID')
    safe_exec_ignore('ALTER TABLE class_assignments ADD CONSTRAINT fk_class_assignments_school FOREIGN KEY (school_id) REFERENCES schools(school_id) ON DELETE CASCADE NOT VALID')
    safe_exec_ignore('ALTER TABLE class_assignments ADD CONSTRAINT fk_class_assignments_teacher FOREIGN KEY (school_id, teacher_id) REFERENCES teachers(school_id, user_id) ON DELETE CASCADE NOT VALID')

    # Seed global catalog defaults and backfill custom subjects from existing per-school configs.
    try:
        _seed_global_subject_catalog_defaults_with_cursor(c)
        db_execute(
            c,
            """SELECT classname, core_subjects, science_subjects, art_subjects, commercial_subjects, optional_subjects
               FROM class_subject_configs"""
        )
        for row in c.fetchall() or []:
            classname = row[0]
            fields = {
                'core': row[1],
                'science': row[2],
                'art': row[3],
                'commercial': row[4],
                'optional': row[5],
            }
            for bucket, raw_json in fields.items():
                if not raw_json:
                    continue
                try:
                    values = json.loads(raw_json) if isinstance(raw_json, str) else []
                except Exception:
                    values = []
                for subject in values:
                    _upsert_global_catalog_subject_with_cursor(c, classname, bucket, subject)
    except Exception as exc:
        logging.warning("Global subject catalog backfill skipped due to error: %s", exc)

    # Persist schema version marker so subsequent startups can skip heavy DDL.
    db_execute(
        c,
        """CREATE TABLE IF NOT EXISTS app_meta (
               key TEXT PRIMARY KEY,
               value TEXT NOT NULL,
               updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
           )"""
    )
    db_execute(
        c,
        """INSERT INTO app_meta (key, value, updated_at)
           VALUES (?, ?, CURRENT_TIMESTAMP)
           ON CONFLICT(key) DO UPDATE
             SET value = excluded.value,
                 updated_at = CURRENT_TIMESTAMP""",
        ('schema_version', STARTUP_SCHEMA_VERSION),
    )

    conn.commit()
    conn.close()

def verify_required_db_guards():
    """Verify critical multi-school constraints/indexes are present."""
    strict = os.environ.get('DB_GUARDS_STRICT', '0').strip().lower() in ('1', 'true', 'yes')
    required_indexes = {
        'uq_teachers_school_user',
        'uq_class_assignments',
        'uq_teacher_subject_assignment',
        'uq_class_term_assignment',
        'uq_result_publications',
    }
    with db_connection() as conn:
        c = conn.cursor()
        db_execute(
            c,
            """SELECT indexname
               FROM pg_indexes
               WHERE schemaname = 'public' """
        )
        present_indexes = {str(row[0]) for row in c.fetchall() if row and row[0]}
        # Validate required FK guards by relationship semantics (not constraint name),
        # because legacy deployments may have different FK names.
        db_execute(
            c,
            """SELECT EXISTS (
                   SELECT 1
                   FROM pg_constraint con
                   JOIN pg_class rel ON rel.oid = con.conrelid
                   JOIN pg_namespace relns ON relns.oid = rel.relnamespace
                   JOIN pg_class ref ON ref.oid = con.confrelid
                   JOIN pg_namespace refns ON refns.oid = ref.relnamespace
                   JOIN unnest(con.conkey) AS ck(attnum) ON TRUE
                   JOIN pg_attribute a ON a.attrelid = con.conrelid AND a.attnum = ck.attnum
                   JOIN unnest(con.confkey) AS fk(attnum) ON TRUE
                   JOIN pg_attribute b ON b.attrelid = con.confrelid AND b.attnum = fk.attnum
                   WHERE con.contype = 'f'
                     AND relns.nspname = 'public'
                     AND refns.nspname = 'public'
                     AND rel.relname = 'students'
                     AND ref.relname = 'schools'
                     AND a.attname = 'school_id'
                     AND b.attname = 'school_id'
               )"""
        )
        has_students_school_fk = bool((c.fetchone() or [False])[0])
        db_execute(
            c,
            """SELECT EXISTS (
                   SELECT 1
                   FROM pg_constraint con
                   JOIN pg_class rel ON rel.oid = con.conrelid
                   JOIN pg_namespace relns ON relns.oid = rel.relnamespace
                   JOIN pg_class ref ON ref.oid = con.confrelid
                   JOIN pg_namespace refns ON refns.oid = ref.relnamespace
                   JOIN unnest(con.conkey) AS ck(attnum) ON TRUE
                   JOIN pg_attribute a ON a.attrelid = con.conrelid AND a.attnum = ck.attnum
                   JOIN unnest(con.confkey) AS fk(attnum) ON TRUE
                   JOIN pg_attribute b ON b.attrelid = con.confrelid AND b.attnum = fk.attnum
                   WHERE con.contype = 'f'
                     AND relns.nspname = 'public'
                     AND refns.nspname = 'public'
                     AND rel.relname = 'teachers'
                     AND ref.relname = 'schools'
                     AND a.attname = 'school_id'
                     AND b.attname = 'school_id'
               )"""
        )
        has_teachers_school_fk = bool((c.fetchone() or [False])[0])

    missing_indexes = sorted(required_indexes - present_indexes)
    missing_constraints = []
    if not has_students_school_fk:
        missing_constraints.append('students.school_id -> schools.school_id FK')
    if not has_teachers_school_fk:
        missing_constraints.append('teachers.school_id -> schools.school_id FK')
    if not missing_indexes and not missing_constraints:
        return

    message = (
        f"Missing DB guards. indexes={missing_indexes or 'none'}, "
        f"constraints={missing_constraints or 'none'}"
    )
    if strict:
        raise RuntimeError(message)
    logging.warning(message)

# Initialize database (can be disabled when schema is managed by migrations).
# Default to disabled for production safety; enable explicitly via env var.
def _redact_database_url(url):
    if not url:
        return ''
    # Mask password in postgresql://user:pass@host/db
    return re.sub(r'//([^/@:]+):[^@]*@', r'//\1:***@', url)

logging.info(
    "DB startup config: RUN_STARTUP_DDL=%s, RUN_STARTUP_BOOTSTRAP=%s, DATABASE_URL=%s",
    RUN_STARTUP_DDL,
    RUN_STARTUP_BOOTSTRAP,
    _redact_database_url(DATABASE_URL),
)
# Schema management is primarily handled via Flask-Migrate, but runtime startup DDL
# can be explicitly enabled for guarded compatibility healing.
if RUN_STARTUP_DDL:
    logging.info("RUN_STARTUP_DDL enabled. Executing init_db() at startup.")
    init_db()
else:
    logging.info("RUN_STARTUP_DDL disabled. Skipping init_db() at startup.")


# Create super admin user (bootstrap-only, disabled for normal runtime startup).
def create_super_admin():
    """Ensure super admin account exists; do not reset password on every startup."""
    with db_connection(commit=True) as conn:
        c = conn.cursor()
        db_execute(c, 'SELECT username, role FROM users WHERE LOWER(username) = LOWER(?)', (SUPER_ADMIN_USERNAME,))
        row = c.fetchone()
        if not row:
            if not SUPER_ADMIN_PASSWORD:
                raise RuntimeError(
                    "SUPER_ADMIN_PASSWORD is required to bootstrap the initial super admin account."
                )
            password_hash = generate_password_hash(SUPER_ADMIN_PASSWORD)
            db_execute(c, """INSERT INTO users (username, password_hash, role, school_id) 
                           VALUES (%s, %s, %s, %s)""", (SUPER_ADMIN_USERNAME, password_hash, 'super_admin', None))
            logging.info("Super admin user created: %s", SUPER_ADMIN_USERNAME)
        else:
            # Using DictCursor - access by column name instead of index
            current_role = row['role'] if 'role' in row else None
            # Safety: do not escalate a non-super account automatically.
            if (current_role or '') != 'super_admin':
                logging.warning(
                    "SUPER_ADMIN_USERNAME '%s' exists with role '%s'; skipping automatic role escalation.",
                    SUPER_ADMIN_USERNAME,
                    current_role,
                )
        conn.commit()

if RUN_STARTUP_BOOTSTRAP:
    create_super_admin()
else:
    logging.info("RUN_STARTUP_BOOTSTRAP is disabled. Skipping super admin bootstrap at startup.")

def normalize_all_student_passwords(target_school_id=''):
    """Ensure student accounts use the configured default password for one school only."""
    scoped_school_id = (target_school_id or '').strip()
    if not scoped_school_id:
        raise ValueError('target_school_id is required for student password reset normalization.')
    default_hash = generate_password_hash(DEFAULT_STUDENT_PASSWORD)
    with db_connection(commit=True) as conn:
        c = conn.cursor()
        db_execute(
            c,
            "UPDATE users SET password_hash = %s WHERE role = 'student' AND CAST(school_id AS TEXT) = %s",
            (default_hash, scoped_school_id),
        )

def reset_student_passwords_for_class(school_id, classname, default_password, reset_by=''):
    """Reset active student login passwords for one class in one school."""
    scoped_school_id = (school_id or '').strip()
    scoped_class = (classname or '').strip()
    if not scoped_school_id or not scoped_class:
        raise ValueError('school_id and classname are required.')
    if not default_password:
        raise ValueError('default_password is required.')
    reset_hash = hash_password(default_password)
    touched = 0
    skipped = 0
    with db_connection(commit=True) as conn:
        c = conn.cursor()
        db_execute(
            c,
            """SELECT student_id
               FROM students
               WHERE school_id = ?
                 AND LOWER(classname) = LOWER(?)
                 AND COALESCE(is_archived, 0) = 0
               ORDER BY student_id""",
            (scoped_school_id, scoped_class),
        )
        student_ids = [str(r[0] or '').strip() for r in (c.fetchall() or []) if str(r[0] or '').strip()]
        for sid in student_ids:
            db_execute(
                c,
                """SELECT role, school_id
                   FROM users
                   WHERE LOWER(username) = LOWER(?)
                   LIMIT 1""",
                (sid,),
            )
            existing = c.fetchone()
            if existing:
                existing_role = (existing[0] or '').strip().lower()
                existing_school = (existing[1] or '').strip()
                if existing_role != 'student' or existing_school != scoped_school_id:
                    skipped += 1
                    continue
            upsert_user_with_cursor(c, sid, reset_hash, role='student', school_id=scoped_school_id, overwrite_identity=False)
            touched += 1
    if reset_by:
        logging.info(
            "Class student password reset by %s school_id=%s classname=%s touched=%s skipped=%s",
            reset_by,
            scoped_school_id,
            scoped_class,
            touched,
            skipped,
        )
    return {'touched': touched, 'skipped': skipped}

if os.environ.get('RESET_STUDENT_PASSWORDS_ON_STARTUP', '').strip().lower() in ('1', 'true', 'yes'):
    reset_school_id = (os.environ.get('RESET_STUDENT_PASSWORDS_SCHOOL_ID', '') or '').strip()
    if not reset_school_id:
        raise RuntimeError(
            "RESET_STUDENT_PASSWORDS_ON_STARTUP requires RESET_STUDENT_PASSWORDS_SCHOOL_ID for multi-school safety."
        )
    logging.warning(
        "RESET_STUDENT_PASSWORDS_ON_STARTUP is enabled for school_id=%s. "
        "Disable it after this one-time reset to avoid repeated password resets on each restart.",
        reset_school_id,
    )
    normalize_all_student_passwords(reset_school_id)

def get_user(username):
    """Fetch one user by username."""
    with db_connection() as conn:
        c = conn.cursor()
        # Case-insensitive lookup with index support (idx_users_username_lower).
        try:
            db_execute(
                c,
                'SELECT username, password_hash, role, school_id, terms_accepted, password_changed_at '
                'FROM users WHERE LOWER(username) = LOWER(?) LIMIT 1',
                (username,),
            )
            row = c.fetchone()
            if not row:
                return None
            return {
                'username': row[0],
                'password_hash': row[1],
                'role': row[2] or 'student',
                'school_id': row[3],
                'terms_accepted': int(row[4] or 0),
                'password_changed_at': row[5] if len(row) > 5 else None,
            }
        except Exception:
            # Backward compatibility for DBs that have not yet added users.password_changed_at.
            try:
                conn.rollback()
            except Exception:
                pass
            db_execute(
                c,
                'SELECT username, password_hash, role, school_id, terms_accepted '
                'FROM users WHERE LOWER(username) = LOWER(?) LIMIT 1',
                (username,),
            )
            row = c.fetchone()
            if not row:
                return None
            return {
                'username': row[0],
                'password_hash': row[1],
                'role': row[2] or 'student',
                'school_id': row[3],
                'terms_accepted': int(row[4] or 0),
                'password_changed_at': None,
            }

def is_default_student_password(password_hash):
    """Return True if a student hash still matches configured default password."""
    try:
        return bool(password_hash) and check_password(password_hash, DEFAULT_STUDENT_PASSWORD)
    except Exception:
        return False

def mark_terms_accepted(username):
    """Persist one-time terms/privacy acceptance for a user."""
    with db_connection(commit=True) as conn:
        c = conn.cursor()
        db_execute(c, 'UPDATE users SET terms_accepted = 1 WHERE LOWER(username) = LOWER(?)', (username,))

def upsert_user(username, password_hash, role='student', school_id=None, overwrite_identity=False):
    """Insert or update a user.

    By default, existing users keep their current role/school assignment.
    Set overwrite_identity=True only for explicit admin migration flows.
    """
    with db_connection(commit=True) as conn:
        c = conn.cursor()
        upsert_user_with_cursor(
            c,
            username=username,
            password_hash=password_hash,
            role=role,
            school_id=school_id,
            overwrite_identity=overwrite_identity,
        )

def upsert_user_with_cursor(c, username, password_hash, role='student', school_id=None, overwrite_identity=False):
    """Insert or update a user using an existing DB cursor/transaction."""
    uname = (username or '').strip()
    norm_role = (role or 'student').strip().lower() or 'student'
    norm_school_id = (school_id or '').strip()
    if norm_role != 'super_admin' and not norm_school_id:
        raise ValueError('school_id is required for non-super-admin accounts.')
    role = norm_role
    school_id = norm_school_id if norm_role != 'super_admin' else (norm_school_id or None)
    db_execute(
        c,
        """SELECT username
           FROM users
           WHERE LOWER(username) = LOWER(?)
           LIMIT 1""",
        (uname,),
    )
    row = c.fetchone()

    def _exec_with_password_changed_at(sql_with_col, params_with_col, sql_without_col, params_without_col):
        global _USERS_HAS_PASSWORD_CHANGED_AT
        if users_has_password_changed_at_column():
            try:
                db_execute(c, sql_with_col, params_with_col)
                return
            except Exception as exc:
                if 'password_changed_at' in str(exc).lower():
                    _USERS_HAS_PASSWORD_CHANGED_AT = False
                else:
                    raise
        db_execute(c, sql_without_col, params_without_col)

    if row:
        if overwrite_identity:
            _exec_with_password_changed_at(
                """UPDATE users
                   SET password_hash = ?, role = ?, school_id = ?, password_changed_at = CURRENT_TIMESTAMP
                   WHERE LOWER(username) = LOWER(?)""",
                (password_hash, role, school_id, uname),
                """UPDATE users
                   SET password_hash = ?, role = ?, school_id = ?
                   WHERE LOWER(username) = LOWER(?)""",
                (password_hash, role, school_id, uname),
            )
        else:
            _exec_with_password_changed_at(
                """UPDATE users
                   SET password_hash = ?, password_changed_at = CURRENT_TIMESTAMP
                   WHERE LOWER(username) = LOWER(?)""",
                (password_hash, uname),
                """UPDATE users
                   SET password_hash = ?
                   WHERE LOWER(username) = LOWER(?)""",
                (password_hash, uname),
            )
        return
    _exec_with_password_changed_at(
        """INSERT INTO users (username, password_hash, role, school_id, password_changed_at)
           VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)""",
        (uname, password_hash, role, school_id),
        """INSERT INTO users (username, password_hash, role, school_id)
           VALUES (?, ?, ?, ?)""",
        (uname, password_hash, role, school_id),
    )

def update_user_school_id_only(username, school_id):
    """Update only school_id for an existing user without altering role/password."""
    scoped_school_id = (school_id or '').strip()
    if not scoped_school_id:
        raise ValueError('school_id is required.')
    with db_connection(commit=True) as conn:
        c = conn.cursor()
        db_execute(
            c,
            'UPDATE users SET school_id = ? WHERE LOWER(username) = LOWER(?)',
            (scoped_school_id, (username or '').strip()),
        )

def get_client_ip():
    """Best-effort client IP extraction."""
    trust_proxy = os.environ.get('TRUST_PROXY_HEADERS', '').strip().lower() in ('1', 'true', 'yes')
    xff = (request.headers.get('X-Forwarded-For') or '').strip()
    if trust_proxy and xff:
        # Use the left-most client IP when running behind a trusted reverse proxy.
        for part in xff.split(','):
            ip = (part or '').strip()
            if ip:
                return ip
    return (request.remote_addr or '').strip() or 'unknown'

def is_login_blocked(endpoint, username, ip_address):
    """Return (blocked, wait_minutes)."""
    purge_old_login_attempts()
    endpoint = (endpoint or '').strip().lower()
    username = (username or '').strip().lower()
    ip_address = (ip_address or '').strip()
    now = datetime.now()
    with db_connection() as conn:
        c = conn.cursor()
        db_execute(
            c,
            """SELECT failures, locked_until
               FROM login_attempts
               WHERE endpoint = ? AND username = ? AND ip_address = ?
               LIMIT 1""",
            (endpoint, username, ip_address),
        )
        row = c.fetchone()
    if not row:
        return False, 0
    locked_until = row[1]
    if locked_until and locked_until > now:
        remaining = locked_until - now
        wait_minutes = max(1, int(remaining.total_seconds() // 60) + (1 if remaining.total_seconds() % 60 else 0))
        return True, wait_minutes
    return False, 0

def register_failed_login(endpoint, username, ip_address):
    """Track a failed login and lock after max attempts."""
    purge_old_login_attempts()
    endpoint = (endpoint or '').strip().lower()
    username = (username or '').strip().lower()
    ip_address = (ip_address or '').strip()
    now = datetime.now()
    window_start = now - timedelta(minutes=LOGIN_LOCK_MINUTES)
    lock_until = now + timedelta(minutes=LOGIN_LOCK_MINUTES)
    with db_connection(commit=True) as conn:
        c = conn.cursor()
        db_execute(
            c,
            """SELECT failures, last_failed_at, locked_until
               FROM login_attempts
               WHERE endpoint = ? AND username = ? AND ip_address = ?
               LIMIT 1""",
            (endpoint, username, ip_address),
        )
        row = c.fetchone()
        if not row:
            db_execute(
                c,
                """INSERT INTO login_attempts
                   (endpoint, username, ip_address, failures, first_failed_at, last_failed_at, locked_until)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (endpoint, username, ip_address, 1, now, now, None),
            )
            return
        failures = int(row[0] or 0)
        last_failed_at = row[1]
        current_locked_until = row[2]
        if current_locked_until and current_locked_until > now:
            return
        if not last_failed_at or last_failed_at < window_start:
            failures = 1
            first_failed_at = now
        else:
            failures += 1
            first_failed_at = None
        new_locked_until = lock_until if failures >= LOGIN_MAX_ATTEMPTS else None
        if first_failed_at:
            db_execute(
                c,
                """UPDATE login_attempts
                   SET failures = ?, first_failed_at = ?, last_failed_at = ?, locked_until = ?
                   WHERE endpoint = ? AND username = ? AND ip_address = ?""",
                (failures, first_failed_at, now, new_locked_until, endpoint, username, ip_address),
            )
        else:
            db_execute(
                c,
                """UPDATE login_attempts
                   SET failures = ?, last_failed_at = ?, locked_until = ?
                   WHERE endpoint = ? AND username = ? AND ip_address = ?""",
                (failures, now, new_locked_until, endpoint, username, ip_address),
            )

def clear_failed_login(endpoint, username, ip_address):
    endpoint = (endpoint or '').strip().lower()
    username = (username or '').strip().lower()
    ip_address = (ip_address or '').strip()
    with db_connection(commit=True) as conn:
        c = conn.cursor()
        db_execute(
            c,
            """DELETE FROM login_attempts
               WHERE endpoint = ? AND username = ? AND ip_address = ?""",
            (endpoint, username, ip_address),
        )

def purge_old_login_attempts():
    """Delete stale login-attempt rows to keep table size small."""
    cutoff = datetime.now() - timedelta(days=7)
    with db_connection(commit=True) as conn:
        c = conn.cursor()
        db_execute(
            c,
            """DELETE FROM login_attempts
               WHERE (locked_until IS NOT NULL AND locked_until < ?)
                  OR (locked_until IS NULL AND last_failed_at IS NOT NULL AND last_failed_at < ?)""",
            (cutoff, cutoff),
        )

def update_login_timestamps(username):
    """Shift current_login_at -> last_login_at and set current_login_at=now."""
    with db_connection(commit=True) as conn:
        c = conn.cursor()
        db_execute(
            c,
            """UPDATE users
               SET last_login_at = current_login_at,
                   current_login_at = CURRENT_TIMESTAMP
               WHERE LOWER(username) = LOWER(?)""",
            ((username or '').strip(),),
        )

def get_last_login_at(username):
    """Return last successful login timestamp for a user."""
    with db_connection() as conn:
        c = conn.cursor()
        db_execute(
            c,
            """SELECT last_login_at
               FROM users
               WHERE LOWER(username) = LOWER(?)
               LIMIT 1""",
            ((username or '').strip(),),
        )
        row = c.fetchone()
    return row[0] if row else None

def format_timestamp(ts):
    if not ts:
        return 'First login'
    try:
        return ts.strftime('%Y-%m-%d %H:%M:%S')
    except Exception:
        return str(ts)

def save_student_with_cursor(c, school_id, student_id, student_data):
    """Save one student using an existing DB cursor/transaction."""
    logging.info(f"save_student_with_cursor called: school_id={school_id}, student_id={student_id}")
    firstname = normalize_person_name(student_data.get('firstname', ''))
    subjects = _dedupe_keep_order([normalize_subject_name(s) for s in (student_data.get('subjects', []) or []) if s])
    subjects_str = json.dumps(subjects)
    scores_str = json.dumps(student_data.get('scores', {}))
    term = student_data.get('term', 'First Term')
    stream = student_data.get('stream', 'Science')
    first_year_class = student_data.get('first_year_class', student_data.get('classname', ''))
    number_of_subject = len(subjects)
    date_of_birth = (student_data.get('date_of_birth', '') or '').strip()
    gender = normalize_student_gender(student_data.get('gender', ''))
    parent_phone = (student_data.get('parent_phone', '') or '').strip()
    parent_password_hash = (student_data.get('parent_password_hash', '') or '').strip()
    has_parent_cols = students_has_parent_access_columns()
    if students_has_user_id_column():
        user_id = student_id
        if has_parent_cols:
            db_execute(
                c,
                """INSERT INTO students
                   (user_id, school_id, student_id, firstname, date_of_birth, gender, classname, first_year_class, term, stream, number_of_subject, subjects, scores, promoted, parent_phone, parent_password_hash)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                   ON CONFLICT(school_id, student_id) DO UPDATE SET
                     firstname = excluded.firstname,
                     date_of_birth = excluded.date_of_birth,
                     gender = excluded.gender,
                     classname = excluded.classname,
                     first_year_class = excluded.first_year_class,
                     term = excluded.term,
                     stream = excluded.stream,
                     number_of_subject = excluded.number_of_subject,
                     subjects = excluded.subjects,
                     scores = excluded.scores,
                     promoted = excluded.promoted,
                     parent_phone = excluded.parent_phone,
                     parent_password_hash = excluded.parent_password_hash""",
                (
                    user_id,
                    school_id,
                    student_id,
                    firstname,
                    date_of_birth,
                    gender,
                    student_data['classname'],
                    first_year_class,
                    term,
                    stream,
                    number_of_subject,
                    subjects_str,
                    scores_str,
                    normalize_promoted_db_value(student_data.get('promoted', 0)),
                    parent_phone,
                    parent_password_hash,
                ),
            )
        else:
            db_execute(
                c,
                """INSERT INTO students
                   (user_id, school_id, student_id, firstname, date_of_birth, gender, classname, first_year_class, term, stream, number_of_subject, subjects, scores, promoted)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                   ON CONFLICT(school_id, student_id) DO UPDATE SET
                     firstname = excluded.firstname,
                     date_of_birth = excluded.date_of_birth,
                     gender = excluded.gender,
                     classname = excluded.classname,
                     first_year_class = excluded.first_year_class,
                     term = excluded.term,
                     stream = excluded.stream,
                     number_of_subject = excluded.number_of_subject,
                     subjects = excluded.subjects,
                     scores = excluded.scores,
                     promoted = excluded.promoted""",
                (
                    user_id,
                    school_id,
                    student_id,
                    firstname,
                    date_of_birth,
                    gender,
                    student_data['classname'],
                    first_year_class,
                    term,
                    stream,
                    number_of_subject,
                    subjects_str,
                    scores_str,
                    normalize_promoted_db_value(student_data.get('promoted', 0)),
                ),
            )
    else:
        if has_parent_cols:
            db_execute(
                c,
                """INSERT INTO students
                   (school_id, student_id, firstname, date_of_birth, gender, classname, first_year_class, term, stream, number_of_subject, subjects, scores, promoted, parent_phone, parent_password_hash)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                   ON CONFLICT(school_id, student_id) DO UPDATE SET
                     firstname = excluded.firstname,
                     date_of_birth = excluded.date_of_birth,
                     gender = excluded.gender,
                     classname = excluded.classname,
                     first_year_class = excluded.first_year_class,
                     term = excluded.term,
                     stream = excluded.stream,
                     number_of_subject = excluded.number_of_subject,
                     subjects = excluded.subjects,
                     scores = excluded.scores,
                     promoted = excluded.promoted,
                     parent_phone = excluded.parent_phone,
                     parent_password_hash = excluded.parent_password_hash""",
                (
                    school_id,
                    student_id,
                    firstname,
                    date_of_birth,
                    gender,
                    student_data['classname'],
                    first_year_class,
                    term,
                    stream,
                    number_of_subject,
                    subjects_str,
                    scores_str,
                    normalize_promoted_db_value(student_data.get('promoted', 0)),
                    parent_phone,
                    parent_password_hash,
                ),
            )
        else:
            db_execute(
                c,
                """INSERT INTO students
                   (school_id, student_id, firstname, date_of_birth, gender, classname, first_year_class, term, stream, number_of_subject, subjects, scores, promoted)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                   ON CONFLICT(school_id, student_id) DO UPDATE SET
                     firstname = excluded.firstname,
                     date_of_birth = excluded.date_of_birth,
                     gender = excluded.gender,
                     classname = excluded.classname,
                     first_year_class = excluded.first_year_class,
                     term = excluded.term,
                     stream = excluded.stream,
                     number_of_subject = excluded.number_of_subject,
                     subjects = excluded.subjects,
                     scores = excluded.scores,
                     promoted = excluded.promoted""",
                (
                    school_id,
                    student_id,
                    firstname,
                    date_of_birth,
                    gender,
                    student_data['classname'],
                    first_year_class,
                    term,
                    stream,
                    number_of_subject,
                    subjects_str,
                    scores_str,
                    normalize_promoted_db_value(student_data.get('promoted', 0)),
                ),
            )

def _normalize_score_block_for_audit(score_block):
    if not isinstance(score_block, dict):
        return {}
    normalized = {}
    for key, value in score_block.items():
        field = str(key)
        if isinstance(value, bool):
            normalized[field] = value
            continue
        if isinstance(value, (int, float)):
            normalized[field] = float(value)
            continue
        if isinstance(value, str):
            raw = value.strip()
            if raw == '':
                normalized[field] = ''
                continue
            try:
                numeric = float(raw)
                if math.isfinite(numeric):
                    normalized[field] = numeric
                    continue
            except Exception:
                pass
            normalized[field] = raw
            continue
        normalized[field] = value
    return normalized

def _subject_score_diff(old_block, new_block):
    old_norm = _normalize_score_block_for_audit(old_block)
    new_norm = _normalize_score_block_for_audit(new_block)
    changed_fields = {}
    for field in sorted(set(old_norm.keys()) | set(new_norm.keys())):
        old_value = old_norm.get(field)
        new_value = new_norm.get(field)
        if isinstance(old_value, (int, float)) and isinstance(new_value, (int, float)):
            if abs(float(old_value) - float(new_value)) <= 1e-9:
                continue
        elif old_value == new_value:
            continue
        changed_fields[field] = {'old': old_value, 'new': new_value}
    return changed_fields, old_norm, new_norm

def log_score_audit_with_cursor(
    c,
    school_id,
    student_id,
    classname,
    term,
    academic_year,
    subject,
    old_score,
    new_score,
    changed_fields,
    changed_by,
    changed_by_role='teacher',
    change_source='manual_entry',
    change_reason='',
):
    subject_name = normalize_subject_name(subject)
    old_score_json = json.dumps(old_score or {}, sort_keys=True)
    new_score_json = json.dumps(new_score or {}, sort_keys=True)
    changed_fields_json = json.dumps(changed_fields or {}, sort_keys=True)
    changed_by_value = str(changed_by or '')
    changed_by_role_value = str(changed_by_role or 'teacher')
    change_source_value = str(change_source or 'manual_entry')
    change_reason_value = str(change_reason or '')

    attempts = [
        (
            """INSERT INTO score_audit_logs
               (school_id, student_id, classname, term, academic_year, subject,
                old_score_json, new_score_json, changed_fields_json,
                changed_by, changed_by_role, change_source, change_reason, changed_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)""",
            (
                school_id,
                student_id,
                classname,
                term,
                academic_year or '',
                subject_name,
                old_score_json,
                new_score_json,
                changed_fields_json,
                changed_by_value,
                changed_by_role_value,
                change_source_value,
                change_reason_value,
            ),
        ),
        (
            """INSERT INTO score_audit_logs
               (school_id, student_id, classname, term, academic_year, subject,
                old_score_json, new_score_json, changed_fields_json,
                changed_by, changed_by_role, change_source, changed_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)""",
            (
                school_id,
                student_id,
                classname,
                term,
                academic_year or '',
                subject_name,
                old_score_json,
                new_score_json,
                changed_fields_json,
                changed_by_value,
                changed_by_role_value,
                change_source_value,
            ),
        ),
        (
            """INSERT INTO score_audit_logs
               (school_id, student_id, classname, term, academic_year, subject,
                old_score_json, new_score_json, changed_fields_json,
                changed_by, changed_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)""",
            (
                school_id,
                student_id,
                classname,
                term,
                academic_year or '',
                subject_name,
                old_score_json,
                new_score_json,
                changed_fields_json,
                changed_by_value,
            ),
        ),
        (
            """INSERT INTO score_audit_logs
               (school_id, student_id, classname, term, subject,
                old_score_json, new_score_json, changed_fields_json,
                changed_by, changed_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)""",
            (
                school_id,
                student_id,
                classname,
                term,
                subject_name,
                old_score_json,
                new_score_json,
                changed_fields_json,
                changed_by_value,
            ),
        ),
    ]

    last_exc = None
    for query, params in attempts:
        try:
            db_execute(c, query, params)
            return
        except Exception as exc:
            last_exc = exc
            try:
                conn = getattr(c, 'connection', None)
                if conn:
                    conn.rollback()
            except Exception:
                pass
            continue
    if last_exc:
        raise last_exc

def audit_student_score_changes_with_cursor(
    c,
    school_id,
    student_id,
    classname,
    term,
    academic_year,
    old_scores,
    new_scores,
    changed_by,
    changed_by_role='teacher',
    change_source='manual_entry',
    change_reason='',
    subjects_scope=None,
):
    if not ensure_score_audit_schema():
        return
    old_map = old_scores if isinstance(old_scores, dict) else {}
    new_map = new_scores if isinstance(new_scores, dict) else {}
    if subjects_scope:
        subjects = _dedupe_keep_order([normalize_subject_name(s) for s in subjects_scope if str(s).strip()])
    else:
        subjects = sorted(set(old_map.keys()) | set(new_map.keys()))
    for subject in subjects:
        old_block = old_map.get(subject, {}) if isinstance(old_map.get(subject, {}), dict) else {}
        new_block = new_map.get(subject, {}) if isinstance(new_map.get(subject, {}), dict) else {}
        changed_fields, old_norm, new_norm = _subject_score_diff(old_block, new_block)
        if not changed_fields:
            continue
        log_score_audit_with_cursor(
            c=c,
            school_id=school_id,
            student_id=student_id,
            classname=classname,
            term=term,
            academic_year=academic_year,
            subject=subject,
            old_score=old_norm,
            new_score=new_norm,
            changed_fields=changed_fields,
            changed_by=changed_by,
            changed_by_role=changed_by_role,
            change_source=change_source,
            change_reason=change_reason,
        )

def _safe_json_object(raw_value):
    try:
        value = json.loads(raw_value) if raw_value else {}
    except Exception:
        value = {}
    return value if isinstance(value, dict) else {}

def get_audit_row_by_id(school_id, audit_id):
    if not ensure_score_audit_schema():
        return None
    try:
        aid = int(audit_id)
    except (TypeError, ValueError):
        return None
    with db_connection() as conn:
        c = conn.cursor()
        db_execute(
            c,
            """SELECT id, school_id, student_id, classname, term, COALESCE(academic_year, ''),
                      subject, old_score_json, new_score_json, changed_fields_json,
                      changed_by, changed_by_role, change_source, COALESCE(change_reason, ''), changed_at
               FROM score_audit_logs
               WHERE school_id = ? AND id = ?
               LIMIT 1""",
            (school_id, aid),
        )
        row = c.fetchone()
    if not row:
        return None
    return {
        'id': int(row[0]),
        'school_id': row[1] or '',
        'student_id': row[2] or '',
        'classname': row[3] or '',
        'term': row[4] or '',
        'academic_year': row[5] or '',
        'subject': row[6] or '',
        'old_score': _safe_json_object(row[7]),
        'new_score': _safe_json_object(row[8]),
        'changed_fields': _safe_json_object(row[9]),
        'changed_by': row[10] or '',
        'changed_by_role': row[11] or '',
        'change_source': row[12] or '',
        'change_reason': row[13] or '',
        'changed_at': row[14],
    }

def get_latest_score_audit_map_for_student(school_id, student_id, term='', academic_year=''):
    if not ensure_score_audit_schema():
        return {}
    where = ['school_id = ?', 'student_id = ?']
    params = [school_id, student_id]
    if term:
        where.append('term = ?')
        params.append(term)
    if academic_year:
        where.append("COALESCE(academic_year, '') = COALESCE(?, '')")
        params.append(academic_year)
    clause = ' AND '.join(where)
    out = {}
    with db_connection() as conn:
        c = conn.cursor()
        db_execute(
            c,
            f"""SELECT subject, changed_by, changed_by_role, change_source, changed_at
                FROM score_audit_logs
                WHERE {clause}
                ORDER BY changed_at DESC""",
            tuple(params),
        )
        for row in c.fetchall() or []:
            subject = normalize_subject_name(row[0] or '')
            if not subject or subject in out:
                continue
            out[subject] = {
                'subject': subject,
                'changed_by': row[1] or '',
                'changed_by_role': row[2] or '',
                'change_source': row[3] or '',
                'changed_at': row[4],
            }
    return out

def hash_password(password):
    """Hash a password."""
    return generate_password_hash(password)

def check_password(hashed, password):
    """Verify a password."""
    return check_password_hash(hashed, password)


def normalize_parent_phone(phone):
    """Normalize parent phone for storage + lookup."""
    value = re.sub(r'\s+', '', (phone or '').strip())
    return value


def is_valid_parent_phone(phone):
    value = normalize_parent_phone(phone)
    return bool(re.fullmatch(r'^[0-9+\-()]{7,25}$', value))

def ordinal(value):
    """Return ordinal string for an integer (e.g., 1 -> 1st)."""
    try:
        n = int(value)
    except (TypeError, ValueError):
        return str(value)
    abs_n = abs(n)
    if 10 <= (abs_n % 100) <= 20:
        suffix = 'th'
    else:
        suffix = {1: 'st', 2: 'nd', 3: 'rd'}.get(abs_n % 10, 'th')
    return f"{n}{suffix}"

app.jinja_env.filters['ordinal'] = ordinal

def is_valid_email(value):
    """Simple email validation for usernames that must be emails."""
    email = (value or '').strip()
    return bool(re.fullmatch(r'^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$', email))

def is_valid_manual_student_id(value):
    """
    Validate manually entered student IDs (Reg No.).
    Allows only letters, numbers, slash, underscore, hyphen.
    """
    text = (value or '').strip()
    if not text:
        return False
    if len(text) > 80:
        return False
    return bool(re.fullmatch(r'^[A-Za-z0-9/_-]+$', text))

def with_school_suffix_manual_id(reg_no, school_id):
    """
    Ensure a manually entered Reg No ends with '/<school_id_sanitized>'.
    Avoid double-appending when already present.
    """
    base = (reg_no or '').strip().strip('/')
    school_part = re.sub(r'[^A-Za-z0-9_-]+', '', (school_id or '').strip()) or 'school'
    if not base:
        return ''
    suffix = f"/{school_part}"
    if base.lower().endswith(suffix.lower()):
        return base
    return f"{base}{suffix}"

def generate_temp_password(length=10):
    """Generate a temporary password."""
    alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$"
    return ''.join(secrets.choice(alphabet) for _ in range(max(8, length)))

def parse_uploaded_signature(file_storage):
    """
    Validate and encode uploaded signature image as a data URL.
    Returns (data_url, error_message).
    """
    if not file_storage:
        return '', 'Signature file is required.'
    filename = (file_storage.filename or '').strip()
    if not filename:
        return '', 'Signature file is required.'
    ext = filename.rsplit('.', 1)[-1].lower() if '.' in filename else ''
    allowed_ext = {'png', 'jpg', 'jpeg', 'webp'}
    if ext not in allowed_ext:
        return '', 'Only PNG, JPG, JPEG, or WEBP files are allowed.'
    raw = file_storage.read()
    if not raw:
        return '', 'Uploaded signature file is empty.'
    if len(raw) > (2 * 1024 * 1024):
        return '', 'Signature image is too large. Maximum size is 2MB.'
    mime = (file_storage.mimetype or '').strip().lower()
    if not mime.startswith('image/'):
        mime_by_ext = {
            'png': 'image/png',
            'jpg': 'image/jpeg',
            'jpeg': 'image/jpeg',
            'webp': 'image/webp',
        }
        mime = mime_by_ext.get(ext, 'image/png')
    encoded = base64.b64encode(raw).decode('ascii')
    return f'data:{mime};base64,{encoded}', ''

def parse_uploaded_profile_image(file_storage):
    """
    Validate and encode uploaded profile image as a data URL.
    Returns (data_url, error_message).
    """
    if not file_storage:
        return '', 'Profile image file is required.'
    filename = (file_storage.filename or '').strip()
    if not filename:
        return '', 'Profile image file is required.'
    ext = filename.rsplit('.', 1)[-1].lower() if '.' in filename else ''
    allowed_ext = {'png', 'jpg', 'jpeg', 'webp'}
    if ext not in allowed_ext:
        return '', 'Only PNG, JPG, JPEG, or WEBP files are allowed.'
    raw = file_storage.read()
    if not raw:
        return '', 'Uploaded profile image file is empty.'
    if len(raw) > (2 * 1024 * 1024):
        return '', 'Profile image is too large. Maximum size is 2MB.'
    mime = (file_storage.mimetype or '').strip().lower()
    if not mime.startswith('image/'):
        mime_by_ext = {
            'png': 'image/png',
            'jpg': 'image/jpeg',
            'jpeg': 'image/jpeg',
            'webp': 'image/webp',
        }
        mime = mime_by_ext.get(ext, 'image/png')
    encoded = base64.b64encode(raw).decode('ascii')
    return f'data:{mime};base64,{encoded}', ''

def _extract_class_number(classname):
    normalized = re.sub(r'[^A-Za-z0-9]+', '', (classname or '')).upper()
    # Allow arm-suffixed classes like JSS1A / SS2B by taking the first numeric block.
    m = re.search(r'(\d+)', normalized)
    if not m:
        return None
    try:
        return int(m.group(1))
    except (TypeError, ValueError):
        return None

def _split_class_level_number_arm(classname):
    """
    Parse normalized class names into (level, number, arm_suffix).
    Examples:
    - JSS1 -> ('JSS', 1, '')
    - JSS1A -> ('JSS', 1, 'A')
    - PRIMARY6BLUE -> ('PRIMARY', 6, 'BLUE')
    """
    normalized = re.sub(r'[^A-Za-z0-9]+', '', (classname or '')).upper()
    m = re.fullmatch(r'(NURSERY|PRIMARY|JSS|SSS|SS)(\d+)([A-Z]+)?', normalized)
    if not m:
        return '', None, ''
    level = m.group(1)
    # Treat SSS and SS as same senior-secondary level for progression/ranking logic.
    if level == 'SSS':
        level = 'SS'
    try:
        number = int(m.group(2))
    except (TypeError, ValueError):
        return '', None, ''
    arm = m.group(3) or ''
    return level, number, arm

def _entry_year_for_first_level(current_year, first_year_class):
    """
    Compute the year student entered first level class.
    Examples:
    - JSS1 -> current year
    - JSS2 -> current year - 1
    - JSS3 -> current year - 2
    Same principle for primary classes.
    """
    normalized = re.sub(r'[^A-Za-z0-9]+', '', (first_year_class or '')).upper()
    class_no = _extract_class_number(first_year_class) or 1
    if normalized.startswith('JSS'):
        return current_year - max(0, class_no - 1)
    if normalized.startswith('SS') or normalized.startswith('SSS'):
        # SS entry year should trace back to the JSS1 start year.
        # In this project's ID expectation, SS1/2/3 map as offsets 4/5/6.
        return current_year - max(0, class_no + 3)
    # Primary (PRIMARY1/PRY1/PRI1/P1...) follows same rule.
    return current_year - max(0, class_no - 1)

def generate_student_id(school_id, index_number, first_year_class):
    """
    Generate student ID in format: YY/school_id/index/start_year_yy
    Example:
    - JSS1 entry now: 26/kingschool/001/26
    - JSS2 entry now: 26/kingschool/001/25
    - JSS3 entry now: 26/kingschool/001/24
    """
    current_year = datetime.now().year
    year_short = str(current_year)[-2:]  # Get last 2 digits
    index_str = str(index_number).zfill(3)  # Zero-pad to 3 digits
    school_part = re.sub(r'[^A-Za-z0-9_-]+', '', (school_id or '').strip()) or 'school'
    start_year = _entry_year_for_first_level(current_year, first_year_class)
    start_year_short = str(start_year)[-2:]
    start_year_token = start_year_short
    normalized_first = re.sub(r'[^A-Za-z0-9]+', '', (first_year_class or '')).upper()
    if normalized_first.startswith('NUR'):
        # Nursery IDs use YYN token, e.g. 26N.
        start_year_token = f"{start_year_short}N"
    elif get_class_level(first_year_class) == 'primary':
        # Primary IDs use YYP token, e.g. 26P.
        start_year_token = f"{start_year_short}P"
    return f"{year_short}/{school_part}/{index_str}/{start_year_token}"

def extract_generated_id_index(student_id):
    """Extract generated index from student ID; return None for non-generated/manual IDs."""
    sid = str(student_id or '').strip()
    if not sid:
        return None
    parts = sid.split('/')
    # New expected format: YY/school_id/index/start_year_token (e.g. 26 or 26P)
    if len(parts) == 4 and re.fullmatch(r'\d{2}', parts[0] or '') and re.fullmatch(r'\d{1,6}', parts[2] or '') and re.fullmatch(r'\d{2}[A-Za-z]?', parts[3] or ''):
        try:
            return int(parts[2])
        except (TypeError, ValueError):
            return None
    # Legacy expected format: YY/index/class
    if len(parts) == 3 and re.fullmatch(r'\d{2}', parts[0] or '') and re.fullmatch(r'\d{1,6}', parts[1] or ''):
        try:
            return int(parts[1])
        except (TypeError, ValueError):
            return None
    return None

def class_uses_stream(classname):
    """Only SS1/SS2/SS3 classes should have streams."""
    level, number, _arm = _split_class_level_number_arm(classname)
    return level == 'SS' and number in {1, 2, 3}

def is_ss1_class(classname):
    level, number, _arm = _split_class_level_number_arm(classname)
    return level == 'SS' and number == 1

def class_uses_stream_for_school(school, classname):
    if not class_uses_stream(classname):
        return False
    mode = ((school or {}).get('ss1_stream_mode') or 'separate').strip().lower()
    if is_ss1_class(classname) and mode == 'combined':
        return False
    return True

def class_arm_ranking_group(classname, mode='separate'):
    """
    Return ranking group key for class arm handling.
    - separate: keep full class key (e.g. JSS1A, JSS1S)
    - together: merge arms to base level (e.g. JSS1)
    """
    normalized_mode = (mode or 'separate').strip().lower()
    class_key = canonicalize_classname(classname)
    if normalized_mode != 'together':
        return class_key
    level, number, _arm = _split_class_level_number_arm(classname)
    if level and number is not None:
        return f"{level}{number}"
    return class_key

def get_class_level(classname):
    """Map class name to level key: primary, jss, ss."""
    normalized = re.sub(r'[^A-Za-z0-9]+', '', (classname or '')).upper()
    if normalized.startswith('SS') or normalized.startswith('SSS'):
        return 'ss'
    if normalized.startswith('JSS'):
        return 'jss'
    return 'primary'

def next_class_in_sequence(classname):
    """Return next class in progression sequence, or None if terminal/unknown."""
    progression = {
        'NURSERY1': 'NURSERY2',
        'NURSERY2': 'NURSERY3',
        'NURSERY3': 'PRIMARY1',
        'PRIMARY1': 'PRIMARY2',
        'PRIMARY2': 'PRIMARY3',
        'PRIMARY3': 'PRIMARY4',
        'PRIMARY4': 'PRIMARY5',
        'PRIMARY5': 'PRIMARY6',
        'PRIMARY6': 'JSS1',
        'JSS1': 'JSS2',
        'JSS2': 'JSS3',
        'JSS3': 'SS1',
        'SS1': 'SS2',
        'SS2': 'SS3',
        'SS3': 'GRADUATED',
    }
    level, number, arm = _split_class_level_number_arm(classname)
    if level and number is not None:
        base_key = f"{level}{number}"
        next_base = progression.get(base_key)
        if not next_base:
            return None
        # Preserve class arm across direct level progression when target is a numbered class.
        if arm and re.fullmatch(r'[A-Z]+\d+', next_base):
            return f"{next_base}{arm}"
        return next_base

    key = canonicalize_classname(classname)
    return progression.get(key)

def is_valid_promotion_target(from_class, to_class):
    """Allow direct next-class progression, including arm/base variants."""
    expected = next_class_in_sequence(from_class)
    if not expected:
        return False
    to_key = canonicalize_classname(to_class)
    if to_key == expected:
        return True
    exp_level, exp_number, _exp_arm = _split_class_level_number_arm(expected)
    if exp_level and exp_number is not None:
        expected_base = f"{exp_level}{exp_number}"
        if to_key.startswith(expected_base):
            suffix = to_key[len(expected_base):]
            return (suffix == '' or bool(re.fullmatch(r'[A-Z]+', suffix)))
    return False

def normalize_stream_for_class(classname, stream, school=None):
    """Return a valid stream for class, or (None, error_message) on invalid input."""
    if class_uses_stream_for_school(school or {}, classname):
        normalized_stream = (stream or '').strip().title()
        allowed_streams = {'Science', 'Art', 'Commercial'}
        if normalized_stream not in allowed_streams:
            return None, 'Please select a valid stream (Science, Art, or Commercial) for SS classes.'
        return normalized_stream, None
    return 'N/A', None

def normalize_person_name(value):
    """Normalize person names with leading-cap style."""
    text = ' '.join((value or '').strip().split())
    if not text:
        return ''
    out = []
    for word in text.split(' '):
        if word.isupper() and len(word) <= 3:
            out.append(word)
            continue
        pieces = []
        for piece in word.split('-'):
            if not piece:
                continue
            pieces.append(piece[:1].upper() + piece[1:].lower())
        out.append('-'.join(pieces))
    return ' '.join(out)

def normalize_student_gender(value):
    """Normalize student gender to Male/Female (or empty if invalid)."""
    text = (value or '').strip().lower()
    if text in {'male', 'm'}:
        return 'Male'
    if text in {'female', 'f'}:
        return 'Female'
    return ''

def normalize_subject_name(value):
    """Normalize subject names with leading-cap style."""
    text = ' '.join((value or '').strip().split())
    if not text:
        return ''
    words = []
    for word in text.split(' '):
        if word.isupper() and len(word) <= 4:
            words.append(word)
        else:
            words.append(word[:1].upper() + word[1:].lower())
    return ' '.join(words)

def normalize_hex_color(value, default='#1e3c72'):
    """Normalize CSS hex color (#RRGGBB), fallback to default when invalid."""
    text = (value or '').strip()
    if re.fullmatch(r'#[0-9A-Fa-f]{6}', text):
        return text.upper()
    return default.upper()

def parse_subjects_text(value):
    """Parse comma-separated subjects into a clean list."""
    return [normalize_subject_name(s) for s in (value or '').split(',') if s.strip()]

def normalize_subjects_list(items):
    """Normalize one subject list (comma string or iterable) and remove duplicates."""
    if isinstance(items, str):
        items = [s for s in items.split(',')]
    return _dedupe_keep_order([normalize_subject_name(str(s).strip()) for s in (items or []) if str(s).strip()])

def _dedupe_keep_order(items):
    seen = set()
    out = []
    for item in items:
        key = item.strip().lower()
        if key and key not in seen:
            seen.add(key)
            out.append(item.strip())
    return out

def get_class_subject_config(school_id, classname):
    """Fetch class subject config for a school/class."""
    class_key = canonicalize_classname(classname)
    level, number, _arm = _split_class_level_number_arm(classname)
    base_key = f"{level}{number}" if level and number is not None else class_key
    with db_connection() as conn:
        c = conn.cursor()
        db_execute(
            c,
            """SELECT classname, core_subjects, science_subjects, art_subjects,
                      commercial_subjects, optional_subjects
               FROM class_subject_configs
               WHERE school_id = ?
                 AND (
                   LOWER(classname) = LOWER(?)
                   OR REGEXP_REPLACE(UPPER(classname), '[^A-Z0-9]+', '', 'g') = ?
                 )
               ORDER BY
                 CASE WHEN LOWER(classname) = LOWER(?) THEN 0 ELSE 1 END,
                 id ASC
               LIMIT 1""",
            (school_id, classname, class_key, classname)
        )
        row = c.fetchone()
        if (not row) and base_key and base_key != class_key:
            # Arm classes (e.g. JSS1A) can inherit the base class config (JSS1) by default.
            db_execute(
                c,
                """SELECT classname, core_subjects, science_subjects, art_subjects,
                          commercial_subjects, optional_subjects
                   FROM class_subject_configs
                   WHERE school_id = ?
                     AND (
                       LOWER(classname) = LOWER(?)
                       OR REGEXP_REPLACE(UPPER(classname), '[^A-Z0-9]+', '', 'g') = ?
                     )
                   ORDER BY
                     CASE WHEN LOWER(classname) = LOWER(?) THEN 0 ELSE 1 END,
                     id ASC
                   LIMIT 1""",
                (school_id, base_key, base_key, base_key)
            )
            row = c.fetchone()

    if not row:
        return None

    return {
        'classname': row[0],
        'core_subjects': json.loads(row[1]) if row[1] else [],
        'science_subjects': json.loads(row[2]) if row[2] else [],
        'art_subjects': json.loads(row[3]) if row[3] else [],
        'commercial_subjects': json.loads(row[4]) if row[4] else [],
        'optional_subjects': json.loads(row[5]) if row[5] else [],
    }

def get_all_class_subject_configs(school_id):
    """Fetch all class subject configs for a school."""
    with db_connection() as conn:
        c = conn.cursor()
        db_execute(
            c,
            """SELECT classname, core_subjects, science_subjects, art_subjects,
                      commercial_subjects, optional_subjects
               FROM class_subject_configs
               WHERE school_id = ?
               ORDER BY classname""",
            (school_id,)
        )
        rows = c.fetchall()

    configs = {}
    for row in rows:
        configs[row[0]] = {
            'classname': row[0],
            'core_subjects': json.loads(row[1]) if row[1] else [],
            'science_subjects': json.loads(row[2]) if row[2] else [],
            'art_subjects': json.loads(row[3]) if row[3] else [],
            'commercial_subjects': json.loads(row[4]) if row[4] else [],
            'optional_subjects': json.loads(row[5]) if row[5] else [],
        }
    return configs

def get_global_subject_catalog_map():
    """
    Return global subject catalog grouped by class.
    Format: { 'JSS1': {'core': [...], 'science': [...], ...}, ... }
    """
    classes = [
        'NURSERY1', 'NURSERY2', 'NURSERY3',
        'PRIMARY1', 'PRIMARY2', 'PRIMARY3', 'PRIMARY4', 'PRIMARY5', 'PRIMARY6',
        'JSS1', 'JSS2', 'JSS3',
        'SS1', 'SS2', 'SS3',
    ]
    catalog = {
        cls: {k: list(v) for k, v in _catalog_defaults_for_class(cls).items()}
        for cls in classes
    }

    with db_connection() as conn:
        c = conn.cursor()
        db_execute(
            c,
            """SELECT classname, bucket, subject_name
               FROM global_class_subject_catalog
               ORDER BY classname, bucket, subject_name"""
        )
        rows = c.fetchall()

    for row in rows:
        cls = canonicalize_classname(row[0])
        bucket = (row[1] or '').strip().lower()
        subject = normalize_subject_name(row[2] or '')
        if not cls or bucket not in {'core', 'science', 'art', 'commercial', 'optional'} or not subject:
            continue
        if cls not in catalog:
            catalog[cls] = {'core': [], 'science': [], 'art': [], 'commercial': [], 'optional': []}
        exists = {s.strip().lower() for s in catalog[cls][bucket]}
        if subject.strip().lower() not in exists:
            catalog[cls][bucket].append(subject)

    return catalog

def get_school_subject_catalog_map(school_id):
    """
    Return subject catalog for one school:
    global defaults + this school's configured class subjects.
    """
    catalog = get_global_subject_catalog_map()
    if not school_id:
        return catalog
    school_configs = get_all_class_subject_configs(school_id) or {}
    for raw_class, cfg in school_configs.items():
        cls = canonicalize_classname(raw_class)
        if not cls:
            continue
        if cls not in catalog:
            catalog[cls] = {'core': [], 'science': [], 'art': [], 'commercial': [], 'optional': []}
        for bucket, key in (
            ('core', 'core_subjects'),
            ('science', 'science_subjects'),
            ('art', 'art_subjects'),
            ('commercial', 'commercial_subjects'),
            ('optional', 'optional_subjects'),
        ):
            existing = {normalize_subject_name(s).lower() for s in (catalog[cls].get(bucket) or []) if str(s).strip()}
            for subject in normalize_subjects_list(cfg.get(key, [])):
                norm = normalize_subject_name(subject)
                if not norm:
                    continue
                if norm.lower() not in existing:
                    catalog[cls][bucket].append(norm)
                    existing.add(norm.lower())
    return catalog

def save_class_subject_config(
    school_id,
    classname,
    core_subjects,
    science_subjects=None,
    art_subjects=None,
    commercial_subjects=None,
    optional_subjects=None,
):
    """Upsert class subject config."""
    classname = canonicalize_classname(classname)
    core = _dedupe_keep_order([normalize_subject_name(s) for s in (core_subjects or [])])
    science = _dedupe_keep_order([normalize_subject_name(s) for s in (science_subjects or [])])
    art = _dedupe_keep_order([normalize_subject_name(s) for s in (art_subjects or [])])
    commercial = _dedupe_keep_order([normalize_subject_name(s) for s in (commercial_subjects or [])])
    optional = _dedupe_keep_order([normalize_subject_name(s) for s in (optional_subjects or [])])

    with db_connection(commit=True) as conn:
        c = conn.cursor()
        db_execute(
            c,
            """INSERT INTO class_subject_configs
               (school_id, classname, core_subjects, science_subjects, art_subjects,
                commercial_subjects, optional_subjects, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
               ON CONFLICT(school_id, classname) DO UPDATE SET
                 core_subjects = excluded.core_subjects,
                 science_subjects = excluded.science_subjects,
                 art_subjects = excluded.art_subjects,
                 commercial_subjects = excluded.commercial_subjects,
                 optional_subjects = excluded.optional_subjects,
                 updated_at = CURRENT_TIMESTAMP""",
            (
                school_id,
                classname,
                json.dumps(core),
                json.dumps(science),
                json.dumps(art),
                json.dumps(commercial),
                json.dumps(optional),
            ),
        )

def delete_class_subject_config(school_id, classname):
    """Delete one class subject configuration for a school/class."""
    class_key = canonicalize_classname(classname)
    with db_connection(commit=True) as conn:
        c = conn.cursor()
        db_execute(
            c,
            """DELETE FROM class_subject_configs
               WHERE school_id = ?
                 AND (
                   LOWER(classname) = LOWER(?)
                   OR REGEXP_REPLACE(UPPER(classname), '[^A-Z0-9]+', '', 'g') = ?
                 )""",
            (school_id, classname, class_key),
        )
        return int(c.rowcount or 0)

def build_subjects_from_config(classname, stream, config, selected_optional_subjects, school=None):
    """Build final subject list for a student from class config."""
    if not config:
        return None, None, 'No subject configuration found for this class. Ask school admin to configure it first.'

    uses_stream = class_uses_stream_for_school(school or {}, classname)
    final_stream, stream_error = normalize_stream_for_class(classname, stream, school=school)
    if stream_error:
        return None, None, stream_error

    subjects = list(config.get('core_subjects', []))
    ss1_combined = is_ss1_class(classname) and ((school or {}).get('ss1_stream_mode', 'separate') or '').strip().lower() == 'combined'
    if ss1_combined and not uses_stream:
        subjects = _dedupe_keep_order(
            list(config.get('core_subjects', []))
            + list(config.get('science_subjects', []))
            + list(config.get('art_subjects', []))
            + list(config.get('commercial_subjects', []))
            + list(config.get('optional_subjects', []))
        )

    if uses_stream:
        track_map = {
            'Science': config.get('science_subjects', []),
            'Art': config.get('art_subjects', []),
            'Commercial': config.get('commercial_subjects', []),
        }
        track_subjects = track_map.get(final_stream, [])
        if not track_subjects:
            return None, None, f'No {final_stream} subjects configured for {classname}.'
        subjects.extend(track_subjects)

    allowed_optional = config.get('optional_subjects', []) if uses_stream else []
    selected_optional = [normalize_subject_name(s) for s in (selected_optional_subjects or []) if s and s.strip()]
    selected_optional = _dedupe_keep_order(selected_optional)

    invalid = [s for s in selected_optional if s not in allowed_optional]
    if invalid:
        return None, None, 'Invalid optional subject selection.'

    subjects.extend(selected_optional)
    subjects = _dedupe_keep_order(subjects)
    return subjects, final_stream, None

def sync_student_subjects_to_class_config(student, school_id, school=None):
    """
    Best-effort sync of one student's subject list to current class config.
    Primarily used for non-stream classes (including SS1 combined).
    Returns (changed, error_message_or_none).
    """
    if not isinstance(student, dict):
        return False, None
    classname = student.get('classname', '')
    if not classname:
        return False, None
    config = get_class_subject_config(school_id, classname)
    if not config:
        return False, None
    current_subjects = _dedupe_keep_order([str(s).strip() for s in (student.get('subjects') or []) if str(s).strip()])
    selected_optional = [s for s in current_subjects if s in (config.get('optional_subjects') or [])]
    desired_subjects, desired_stream, err = build_subjects_from_config(
        classname=classname,
        stream=student.get('stream', 'N/A'),
        config=config,
        selected_optional_subjects=selected_optional,
        school=school or {},
    )
    if err or not desired_subjects:
        return False, err
    desired_subjects = _dedupe_keep_order(desired_subjects)
    if desired_subjects == current_subjects and (student.get('stream') or 'N/A') == desired_stream:
        return False, None

    existing_scores = student.get('scores', {}) if isinstance(student.get('scores', {}), dict) else {}
    # Preserve existing score blocks with tolerant subject-key matching so
    # config sync does not silently wipe saved scores due key drift.
    aligned_scores = {}
    for subj in desired_subjects:
        block = get_subject_score_block(existing_scores, subj)
        if isinstance(block, dict) and block:
            aligned_scores[subj] = dict(block)
    student['scores'] = aligned_scores
    student['subjects'] = desired_subjects
    student['number_of_subject'] = len(desired_subjects)
    student['stream'] = desired_stream
    return True, None

def _default_assessment_config(level):
    """Default exam setup per level."""
    defaults = {
        'primary': {'exam_mode': 'combined', 'objective_max': 0, 'theory_max': 0, 'exam_score_max': 60},
        'jss': {'exam_mode': 'combined', 'objective_max': 0, 'theory_max': 0, 'exam_score_max': 70},
        'ss': {'exam_mode': 'separate', 'objective_max': 30, 'theory_max': 40, 'exam_score_max': 70},
    }
    return defaults.get(level, defaults['primary'])

def get_assessment_config(school_id, level):
    """Get one assessment config for level."""
    level = (level or 'primary').strip().lower()
    with db_connection() as conn:
        c = conn.cursor()
        db_execute(
            c,
            """SELECT exam_mode, objective_max, theory_max, exam_score_max
               FROM assessment_configs
               WHERE school_id = ? AND level = ?
               LIMIT 1""",
            (school_id, level),
        )
        row = c.fetchone()

    if not row:
        return {'level': level, **_default_assessment_config(level)}
    return {
        'level': level,
        'exam_mode': row[0] if row[0] in ('separate', 'combined') else 'separate',
        'objective_max': int(row[1] or 0),
        'theory_max': int(row[2] or 0),
        'exam_score_max': int(row[3] or 0),
    }

def get_assessment_config_for_class(school_id, classname):
    """Resolve assessment config using class name."""
    return get_assessment_config(school_id, get_class_level(classname))

def get_all_assessment_configs(school_id):
    """Get assessment configs for all levels with defaults merged."""
    configs = {}
    for level in ('primary', 'jss', 'ss'):
        configs[level] = get_assessment_config(school_id, level)
    return configs

def save_assessment_config_with_cursor(c, school_id, level, exam_mode, objective_max, theory_max, exam_score_max):
    """Upsert one level assessment config using an existing DB cursor."""
    level = level.strip().lower()
    mode = 'separate' if exam_mode == 'separate' else 'combined'
    objective_max = max(0, min(100, int(objective_max or 0)))
    theory_max = max(0, min(100, int(theory_max or 0)))
    exam_score_max = max(0, min(100, int(exam_score_max or 0)))
    if mode == 'separate':
        exam_score_max = min(100, objective_max + theory_max)
    db_execute(
        c,
        """INSERT INTO assessment_configs
           (school_id, level, exam_mode, objective_max, theory_max, exam_score_max, updated_at)
           VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
           ON CONFLICT(school_id, level) DO UPDATE SET
             exam_mode = excluded.exam_mode,
             objective_max = excluded.objective_max,
             theory_max = excluded.theory_max,
             exam_score_max = excluded.exam_score_max,
             updated_at = CURRENT_TIMESTAMP""",
        (school_id, level, mode, objective_max, theory_max, exam_score_max),
    )

def save_assessment_config(school_id, level, exam_mode, objective_max, theory_max, exam_score_max):
    """Upsert one level assessment config."""
    with db_connection(commit=True) as conn:
        c = conn.cursor()
        save_assessment_config_with_cursor(c, school_id, level, exam_mode, objective_max, theory_max, exam_score_max)

def build_subject_key_map(subjects):
    """Build stable form keys for subject names."""
    key_map = {}
    seen = set()
    for index, subject in enumerate(subjects):
        base = re.sub(r'[^A-Za-z0-9]+', '_', subject).strip('_').lower() or f"subject_{index+1}"
        key = base
        suffix = 2
        while key in seen:
            key = f"{base}_{suffix}"
            suffix += 1
        seen.add(key)
        key_map[subject] = key
    return key_map

def calculate_positions(students_list, ss_ranking_mode='together', school=None):
    """Calculate class positions, with optional SS stream-separated ranking."""
    def same_score(a, b):
        return abs(float(a or 0) - float(b or 0)) <= 1e-9

    positions = {}
    class_groups = {}
    class_arm_mode = ((school or {}).get('class_arm_ranking_mode') or 'separate').strip().lower()
    if class_arm_mode not in {'separate', 'together'}:
        class_arm_mode = 'separate'
    for student in students_list:
        class_name = student.get('class_name', '')
        term = student.get('term', '')
        stream = (student.get('stream') or '').strip()
        class_group = class_arm_ranking_group(class_name, class_arm_mode)
        rank_key = f"{class_group}__{term}"
        if ss_ranking_mode == 'separate' and class_uses_stream_for_school(school or {}, class_name):
            rank_key = f"{class_group}__{term}__{stream or 'Unassigned'}"
        if rank_key not in class_groups:
            class_groups[rank_key] = []
        class_groups[rank_key].append(student)

    for rank_key, class_students in class_groups.items():
        sorted_students = sorted(
            class_students,
            key=lambda x: safe_float(x.get('average_marks', 0), 0),
            reverse=True,
        )
        prev_score = None
        current_pos = 0
        for index, student in enumerate(sorted_students, 1):
            sid = student.get('student_id')
            if not sid:
                continue
            score = float(student.get('average_marks', 0) or 0)
            if prev_score is None or not same_score(score, prev_score):
                current_pos = index
            positions[sid] = {
                'pos': current_pos,
                'size': len(sorted_students),
                'class': student.get('class_name', ''),
                'term': student.get('term', ''),
                'stream': student.get('stream', ''),
                'group': rank_key
            }
            prev_score = score
    return positions

# ==================== SCHOOL FUNCTIONS ====================

def create_school(school_id, school_name, location='', phone='', email='', principal_name='', motto=''):
    """Create a new school with a provided school_id."""
    with db_connection(commit=True) as conn:
        c = conn.cursor()
        db_execute(
            c,
            """INSERT INTO schools (school_id, school_name, location, phone, email, principal_name, motto, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                school_id,
                school_name,
                (location or '').strip(),
                (phone or '').strip(),
                (email or '').strip().lower(),
                (principal_name or '').strip(),
                (motto or '').strip(),
                datetime.now(),
            )
        )

def create_school_with_index_id_with_cursor(c, school_name, location='', phone='', email='', principal_name='', motto=''):
    """Create one school using an existing transaction and return normalized school_id."""
    temp_school_id = f"tmp_{secrets.token_hex(8)}"
    db_execute(
        c,
        """INSERT INTO schools (school_id, school_name, location, phone, email, principal_name, motto, updated_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)
           RETURNING id""",
        (
            temp_school_id,
            school_name,
            (location or '').strip(),
            (phone or '').strip(),
            (email or '').strip().lower(),
            (principal_name or '').strip(),
            (motto or '').strip(),
            datetime.now(),
        )
    )
    row = c.fetchone()
    school_row_id = int((row or [0])[0] or 0)
    if school_row_id <= 0:
        raise ValueError('Failed to create school.')
    final_school_id = str(school_row_id)
    db_execute(c, 'UPDATE schools SET school_id = ? WHERE id = ?', (final_school_id, school_row_id))
    return final_school_id

def create_school_with_index_id(school_name, location='', phone='', email='', principal_name='', motto=''):
    """Create a new school and use the table index (id) as school_id."""
    with db_connection(commit=True) as conn:
        c = conn.cursor()
        return create_school_with_index_id_with_cursor(
            c,
            school_name=school_name,
            location=location,
            phone=phone,
            email=email,
            principal_name=principal_name,
            motto=motto,
        )

def _school_row_to_dict(row):
    if not row:
        return None
    return {
        'school_id': row['school_id'],
        'school_name': row['school_name'],
        'location': row['location'] if 'location' in row.keys() else '',
        'phone': row['phone'] if 'phone' in row.keys() else '',
        'email': row['email'] if 'email' in row.keys() else '',
        'principal_name': row['principal_name'] if 'principal_name' in row.keys() else '',
        'motto': row['motto'] if 'motto' in row.keys() else '',
        'updated_at': row['updated_at'] if 'updated_at' in row.keys() else None,
        'principal_signature_image': row['principal_signature_image'] if 'principal_signature_image' in row.keys() else '',
        'school_logo': normalize_school_logo_url(row['school_logo']),
        'academic_year': row['academic_year'],
        'current_term': row['current_term'],
        'operations_enabled': row['operations_enabled'] if 'operations_enabled' in row.keys() else 1,
        'teacher_operations_enabled': row['teacher_operations_enabled'] if 'teacher_operations_enabled' in row.keys() else 1,
        'test_enabled': row['test_enabled'],
        'exam_enabled': row['exam_enabled'],
        'max_tests': row['max_tests'],
        'test_score_max': row['test_score_max'],
        'exam_objective_max': row['exam_objective_max'],
        'exam_theory_max': row['exam_theory_max'],
        'grade_a_min': row['grade_a_min'] if 'grade_a_min' in row.keys() else 70,
        'grade_b_min': row['grade_b_min'] if 'grade_b_min' in row.keys() else 60,
        'grade_c_min': row['grade_c_min'] if 'grade_c_min' in row.keys() else 50,
        'grade_d_min': row['grade_d_min'] if 'grade_d_min' in row.keys() else 40,
        'pass_mark': row['pass_mark'] if 'pass_mark' in row.keys() else 50,
        'show_positions': row['show_positions'] if 'show_positions' in row.keys() else 1,
        'ss_ranking_mode': row['ss_ranking_mode'] if 'ss_ranking_mode' in row.keys() else 'together',
        'class_arm_ranking_mode': row['class_arm_ranking_mode'] if 'class_arm_ranking_mode' in row.keys() else 'separate',
        'combine_third_term_results': row['combine_third_term_results'] if 'combine_third_term_results' in row.keys() else 0,
        'ss1_stream_mode': row['ss1_stream_mode'] if 'ss1_stream_mode' in row.keys() else 'separate',
        'theme_primary_color': normalize_hex_color(row['theme_primary_color'] if 'theme_primary_color' in row.keys() else '', '#1E3C72'),
        'theme_secondary_color': normalize_hex_color(row['theme_secondary_color'] if 'theme_secondary_color' in row.keys() else '', '#2A5298'),
        'theme_accent_color': normalize_hex_color(row['theme_accent_color'] if 'theme_accent_color' in row.keys() else '', '#1F7A8C'),
    }

def get_school(school_id):
    """Get school details."""
    school_key = (school_id or '').strip()
    if not school_key:
        return None

    request_cache = None
    if has_request_context():
        request_cache = getattr(g, '_school_cache', None)
        if request_cache is None:
            request_cache = {}
            setattr(g, '_school_cache', request_cache)
        if school_key in request_cache:
            cached = request_cache.get(school_key)
            return dict(cached) if isinstance(cached, dict) else None

    now = time.time()
    _prune_school_cache()
    global_cached = _SCHOOL_CACHE.get(school_key)
    if global_cached and (now - float(global_cached.get('ts', 0))) < _SCHOOL_CACHE_TTL:
        data = global_cached.get('data')
        if request_cache is not None:
            request_cache[school_key] = data
        return dict(data) if isinstance(data, dict) else None

    with db_connection() as conn:
        c = conn.cursor()
        db_execute(c, 'SELECT * FROM schools WHERE school_id = ?', (school_key,))
        row = c.fetchone()
        data = _school_row_to_dict(row)
    _SCHOOL_CACHE[school_key] = {'ts': now, 'data': data}
    if request_cache is not None:
        request_cache[school_key] = data
    return dict(data) if isinstance(data, dict) else None

def get_all_schools():
    """Get all schools."""
    with db_connection() as conn:
        c = conn.cursor()
        db_execute(c, 'SELECT * FROM schools')
        schools = []
        for row in c.fetchall():
            schools.append({
                'id': row['id'],
                'school_id': row['school_id'],
                'school_name': row['school_name'],
                'location': row['location'] if 'location' in row.keys() else '',
                'phone': row['phone'] if 'phone' in row.keys() else '',
                'email': row['email'] if 'email' in row.keys() else '',
                'principal_name': row['principal_name'] if 'principal_name' in row.keys() else '',
                'motto': row['motto'] if 'motto' in row.keys() else '',
                'updated_at': row['updated_at'] if 'updated_at' in row.keys() else None,
                'principal_signature_image': row['principal_signature_image'] if 'principal_signature_image' in row.keys() else '',
                'school_logo': normalize_school_logo_url(row['school_logo']),
                'academic_year': row['academic_year'],
                'current_term': row['current_term'],
                'operations_enabled': row['operations_enabled'] if 'operations_enabled' in row.keys() else 1,
                'teacher_operations_enabled': row['teacher_operations_enabled'] if 'teacher_operations_enabled' in row.keys() else 1,
                'show_positions': row['show_positions'] if 'show_positions' in row.keys() else 1,
                'class_arm_ranking_mode': row['class_arm_ranking_mode'] if 'class_arm_ranking_mode' in row.keys() else 'separate',
                'combine_third_term_results': row['combine_third_term_results'] if 'combine_third_term_results' in row.keys() else 0,
                'ss1_stream_mode': row['ss1_stream_mode'] if 'ss1_stream_mode' in row.keys() else 'separate',
                'theme_primary_color': normalize_hex_color(row['theme_primary_color'] if 'theme_primary_color' in row.keys() else '', '#1E3C72'),
                'theme_secondary_color': normalize_hex_color(row['theme_secondary_color'] if 'theme_secondary_color' in row.keys() else '', '#2A5298'),
                'theme_accent_color': normalize_hex_color(row['theme_accent_color'] if 'theme_accent_color' in row.keys() else '', '#1F7A8C'),
            })
        return schools

def get_school_admin_username(school_id):
    """Get the school admin username/email for a school."""
    with db_connection() as conn:
        c = conn.cursor()
        db_execute(
            c,
            """SELECT username FROM users
               WHERE CAST(school_id AS TEXT) = ? AND role = 'school_admin'
               ORDER BY id ASC
               LIMIT 1""",
            (school_id,)
        )
        row = c.fetchone()
        return row[0] if row else ''

def update_school_admin_account(school_id, new_username, new_password=''):
    """Update existing school admin username/password, or create one if missing."""
    new_username = (new_username or '').strip().lower()
    if not school_id or not new_username:
        raise ValueError('School ID and school admin email are required.')
    if not is_valid_email(new_username):
        raise ValueError('School admin username must be a valid email address.')

    with db_connection(commit=True) as conn:
        c = conn.cursor()
        current_admin = get_school_admin_username(school_id)

        # Username conflict check.
        existing = get_user(new_username)
        if existing and (existing.get('role') != 'school_admin' or existing.get('school_id') != school_id):
            raise ValueError(f'Username "{new_username}" is already used by another account.')

        if current_admin:
            # Rename account if needed.
            if current_admin.lower() != new_username.lower():
                db_execute(
                    c,
                    """UPDATE users SET username = ?, school_id = ?, role = 'school_admin'
                       WHERE LOWER(username) = LOWER(?) AND role = 'school_admin' AND CAST(school_id AS TEXT) = ?""",
                    (new_username, school_id, current_admin, school_id)
                )
            # Update password only if provided.
            if (new_password or '').strip():
                db_execute(
                    c,
                    'UPDATE users SET password_hash = ? WHERE LOWER(username) = LOWER(?)',
                    (hash_password(new_password.strip()), new_username)
                )
        else:
            # No current admin user for this school: create one.
            if not (new_password or '').strip():
                raise ValueError('Provide a password to create school admin account.')
            upsert_user(new_username, hash_password(new_password.strip()), 'school_admin', school_id)

def update_school_settings_with_cursor(c, school_id, settings):
    """Update school settings using an existing DB cursor."""
    # Runtime schema guard for older DBs where settings columns may be missing.
    db_execute(c, 'ALTER TABLE schools ADD COLUMN IF NOT EXISTS grade_a_min INTEGER DEFAULT 70')
    db_execute(c, 'ALTER TABLE schools ADD COLUMN IF NOT EXISTS grade_b_min INTEGER DEFAULT 60')
    db_execute(c, 'ALTER TABLE schools ADD COLUMN IF NOT EXISTS grade_c_min INTEGER DEFAULT 50')
    db_execute(c, 'ALTER TABLE schools ADD COLUMN IF NOT EXISTS grade_d_min INTEGER DEFAULT 40')
    db_execute(c, 'ALTER TABLE schools ADD COLUMN IF NOT EXISTS pass_mark INTEGER DEFAULT 50')
    db_execute(c, 'ALTER TABLE schools ADD COLUMN IF NOT EXISTS show_positions INTEGER DEFAULT 1')
    db_execute(c, "ALTER TABLE schools ADD COLUMN IF NOT EXISTS ss_ranking_mode TEXT DEFAULT 'together'")
    db_execute(c, "ALTER TABLE schools ADD COLUMN IF NOT EXISTS class_arm_ranking_mode TEXT DEFAULT 'separate'")
    db_execute(c, 'ALTER TABLE schools ADD COLUMN IF NOT EXISTS combine_third_term_results INTEGER DEFAULT 0')
    db_execute(c, "ALTER TABLE schools ADD COLUMN IF NOT EXISTS ss1_stream_mode TEXT DEFAULT 'separate'")
    db_execute(c, "ALTER TABLE schools ADD COLUMN IF NOT EXISTS theme_primary_color TEXT DEFAULT '#1E3C72'")
    db_execute(c, "ALTER TABLE schools ADD COLUMN IF NOT EXISTS theme_secondary_color TEXT DEFAULT '#2A5298'")
    db_execute(c, "ALTER TABLE schools ADD COLUMN IF NOT EXISTS theme_accent_color TEXT DEFAULT '#1F7A8C'")

    db_execute(
               c,
               ("UPDATE schools SET "
                "school_name = ?, location = ?, school_logo = ?, academic_year = ?, "
                "current_term = ?, test_enabled = ?, exam_enabled = ?, "
                "max_tests = ?, test_score_max = ?, exam_objective_max = ?, exam_theory_max = ?, "
                "grade_a_min = ?, grade_b_min = ?, grade_c_min = ?, grade_d_min = ?, pass_mark = ?, "
                "show_positions = ?, ss_ranking_mode = ?, class_arm_ranking_mode = ?, "
                "combine_third_term_results = ?, ss1_stream_mode = ?, "
                "theme_primary_color = ?, theme_secondary_color = ?, theme_accent_color = ? "
                "WHERE school_id = ?"),
               (settings.get('school_name'), settings.get('location', ''), settings.get('school_logo'),
                settings.get('academic_year'), settings.get('current_term'),
                settings.get('test_enabled', 1), settings.get('exam_enabled', 1),
                settings.get('max_tests', 3), settings.get('test_score_max', 30),
                settings.get('exam_objective_max', 30), settings.get('exam_theory_max', 40),
                settings.get('grade_a_min', 70), settings.get('grade_b_min', 60),
                settings.get('grade_c_min', 50), settings.get('grade_d_min', 40),
                settings.get('pass_mark', 50),
                settings.get('show_positions', 1),
                settings.get('ss_ranking_mode', 'together'),
                settings.get('class_arm_ranking_mode', 'separate'),
                settings.get('combine_third_term_results', 0),
                settings.get('ss1_stream_mode', 'separate'),
                normalize_hex_color(settings.get('theme_primary_color', ''), '#1E3C72'),
                normalize_hex_color(settings.get('theme_secondary_color', ''), '#2A5298'),
                normalize_hex_color(settings.get('theme_accent_color', ''), '#1F7A8C'),
                school_id))

def update_school_settings(school_id, settings):
    """Update school settings."""
    with db_connection(commit=True) as conn:
        c = conn.cursor()
        update_school_settings_with_cursor(c, school_id, settings)
    invalidate_school_cache(school_id)

def set_school_operations_enabled(school_id, enabled):
    """Enable/disable teacher/student operations for a school."""
    with db_connection(commit=True) as conn:
        c = conn.cursor()
        db_execute(
            c,
            'UPDATE schools SET operations_enabled = ? WHERE school_id = ?',
            (1 if enabled else 0, school_id)
        )
    invalidate_school_cache(school_id)

def set_teacher_operations_enabled(school_id, enabled):
    """Enable/disable teacher editing operations for a school (set by school admin)."""
    with db_connection(commit=True) as conn:
        c = conn.cursor()
        db_execute(
            c,
            'UPDATE schools SET teacher_operations_enabled = ? WHERE school_id = ?',
            (1 if enabled else 0, school_id)
        )
    invalidate_school_cache(school_id)

def get_grade_config(school_id):
    """Get grade thresholds for a school."""
    school = get_school(school_id) or {}
    a = max(0, min(100, safe_int(school.get('grade_a_min', 70), 70)))
    b = max(0, min(100, safe_int(school.get('grade_b_min', 60), 60)))
    c = max(0, min(100, safe_int(school.get('grade_c_min', 50), 50)))
    d = max(0, min(100, safe_int(school.get('grade_d_min', 40), 40)))
    # Keep ordering valid even if legacy data is corrupted.
    a = max(a, b, c, d)
    b = min(b, a)
    c = min(c, b)
    d = min(d, c)
    pass_mark = max(0, min(100, safe_int(school.get('pass_mark', 50), 50)))
    return {
        'a': a,
        'b': b,
        'c': c,
        'd': d,
        'pass_mark': pass_mark,
    }

def grade_from_score(score, cfg):
    """Get letter grade from score."""
    score = float(score or 0)
    cfg = cfg or {}
    a = safe_float(cfg.get('a', cfg.get('grade_a_min', 70)), 70)
    b = safe_float(cfg.get('b', cfg.get('grade_b_min', 60)), 60)
    c = safe_float(cfg.get('c', cfg.get('grade_c_min', 50)), 50)
    d = safe_float(cfg.get('d', cfg.get('grade_d_min', 40)), 40)
    if score >= a:
        return 'A'
    if score >= b:
        return 'B'
    if score >= c:
        return 'C'
    if score >= d:
        return 'D'
    return 'F'

def status_from_score(score, cfg):
    """Get pass/fail status from score."""
    cfg = cfg or {}
    pass_mark = safe_float(cfg.get('pass_mark', cfg.get('passmark', 50)), 50)
    return 'Pass' if float(score or 0) >= pass_mark else 'Fail'

BEHAVIOUR_GRADE_SCALE = {
    'A': 'Excellent',
    'B': 'Very Good',
    'C': 'Good',
    'D': 'Fair',
    'E': 'Poor',
}

BEHAVIOUR_TRAITS = [
    'Punctuality',
    'Neatness',
    'Honesty',
    'Obedience',
    'Cooperation',
    'Leadership',
    'Respect for Teachers',
    'Emotional Stability',
    'Initiative',
    'Responsibility',
]

ATTENDANCE_STATUS_OPTIONS = [
    ('present', 'Present'),
    ('absent', 'Absent'),
    ('late', 'Late'),
    ('excused', 'Excused'),
]

def normalize_attendance_status(value):
    text = (value or '').strip().lower()
    allowed = {item[0] for item in ATTENDANCE_STATUS_OPTIONS}
    return text if text in allowed else ''

def ensure_student_attendance_schema():
    try:
        with db_connection(commit=True) as conn:
            c = conn.cursor()
            db_execute(
                c,
                """CREATE TABLE IF NOT EXISTS student_attendance (
                       id SERIAL PRIMARY KEY,
                       school_id TEXT NOT NULL,
                       student_id TEXT NOT NULL,
                       classname TEXT NOT NULL,
                       term TEXT NOT NULL,
                       academic_year TEXT DEFAULT '',
                       attendance_date TEXT NOT NULL,
                       status TEXT NOT NULL,
                       note TEXT DEFAULT '',
                       marked_by TEXT DEFAULT '',
                       created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                       updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                       UNIQUE(school_id, student_id, attendance_date)
                   )""",
            )
            db_execute(c, 'CREATE INDEX IF NOT EXISTS idx_attendance_school_class_date ON student_attendance(school_id, classname, attendance_date)')
            db_execute(c, 'CREATE INDEX IF NOT EXISTS idx_attendance_school_term_year ON student_attendance(school_id, term, academic_year)')
        return True
    except Exception as exc:
        logging.warning("Failed to ensure attendance schema: %s", exc)
        return False

def ensure_extended_features_schema():
    """Best-effort schema guard for optional advanced modules."""
    try:
        with db_connection(commit=True) as conn:
            c = conn.cursor()
            db_execute(c, "ALTER TABLE users ADD COLUMN IF NOT EXISTS password_changed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP")
            db_execute(c, "UPDATE users SET password_changed_at = COALESCE(password_changed_at, CURRENT_TIMESTAMP)")
            db_execute(c, "ALTER TABLE users ADD COLUMN IF NOT EXISTS tutorial_seen_at TIMESTAMP")
            db_execute(c, "ALTER TABLE students ADD COLUMN IF NOT EXISTS parent_phone TEXT")
            db_execute(c, "ALTER TABLE students ADD COLUMN IF NOT EXISTS parent_password_hash TEXT")
            db_execute(
                c,
                """CREATE TABLE IF NOT EXISTS login_audit_logs (
                       id SERIAL PRIMARY KEY,
                       school_id TEXT,
                       username TEXT NOT NULL,
                       role TEXT DEFAULT '',
                       endpoint TEXT NOT NULL,
                       ip_address TEXT DEFAULT '',
                       user_agent TEXT DEFAULT '',
                       success INTEGER NOT NULL DEFAULT 0,
                       reason TEXT DEFAULT '',
                       created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                   )""",
            )
            db_execute(c, 'CREATE INDEX IF NOT EXISTS idx_login_audit_school_created ON login_audit_logs(school_id, created_at DESC)')
            db_execute(
                c,
                """CREATE TABLE IF NOT EXISTS class_timetables (
                       id SERIAL PRIMARY KEY,
                       school_id TEXT NOT NULL,
                       classname TEXT NOT NULL,
                       day_of_week INTEGER NOT NULL,
                       period_label TEXT NOT NULL,
                       subject TEXT NOT NULL,
                       teacher_id TEXT DEFAULT '',
                       start_time TEXT DEFAULT '',
                       end_time TEXT DEFAULT '',
                       room TEXT DEFAULT '',
                       created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                       updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                       UNIQUE(school_id, classname, day_of_week, period_label)
                   )""",
            )
            db_execute(c, 'CREATE INDEX IF NOT EXISTS idx_timetable_school_class_day ON class_timetables(school_id, classname, day_of_week)')
            db_execute(
                c,
                """CREATE TABLE IF NOT EXISTS period_attendance (
                       id SERIAL PRIMARY KEY,
                       school_id TEXT NOT NULL,
                       student_id TEXT NOT NULL,
                       classname TEXT NOT NULL,
                       term TEXT NOT NULL,
                       academic_year TEXT DEFAULT '',
                       attendance_date TEXT NOT NULL,
                       period_label TEXT NOT NULL,
                       subject TEXT DEFAULT '',
                       status TEXT NOT NULL,
                       note TEXT DEFAULT '',
                       marked_by TEXT DEFAULT '',
                       created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                       updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                       UNIQUE(school_id, student_id, attendance_date, period_label)
                   )""",
            )
            db_execute(c, "ALTER TABLE period_attendance ADD COLUMN IF NOT EXISTS subject TEXT DEFAULT ''")
            db_execute(c, 'CREATE INDEX IF NOT EXISTS idx_period_att_school_class_date ON period_attendance(school_id, classname, attendance_date)')
            db_execute(c, 'CREATE INDEX IF NOT EXISTS idx_period_att_school_class_subject_date ON period_attendance(school_id, classname, subject, attendance_date)')
            db_execute(
                c,
                """CREATE TABLE IF NOT EXISTS promotion_audit_logs (
                       id SERIAL PRIMARY KEY,
                       school_id TEXT NOT NULL,
                       student_id TEXT NOT NULL,
                       student_name TEXT DEFAULT '',
                       from_class TEXT DEFAULT '',
                       to_class TEXT DEFAULT '',
                       action TEXT NOT NULL,
                       term TEXT DEFAULT '',
                       academic_year TEXT DEFAULT '',
                       changed_by TEXT DEFAULT '',
                       note TEXT DEFAULT '',
                       created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                   )""",
            )
            db_execute(c, 'CREATE INDEX IF NOT EXISTS idx_promotion_audit_school_created ON promotion_audit_logs(school_id, created_at DESC)')
            db_execute(
                c,
                """CREATE TABLE IF NOT EXISTS result_disputes (
                       id SERIAL PRIMARY KEY,
                       school_id TEXT NOT NULL,
                       student_id TEXT NOT NULL,
                       classname TEXT DEFAULT '',
                       term TEXT DEFAULT '',
                       academic_year TEXT DEFAULT '',
                       parent_phone TEXT DEFAULT '',
                       title TEXT NOT NULL,
                       details TEXT NOT NULL,
                       status TEXT NOT NULL DEFAULT 'open',
                       resolution_note TEXT DEFAULT '',
                       created_by TEXT DEFAULT '',
                       resolved_by TEXT DEFAULT '',
                       created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                       resolved_at TIMESTAMP
                   )""",
            )
            db_execute(c, 'CREATE INDEX IF NOT EXISTS idx_disputes_school_status_created ON result_disputes(school_id, status, created_at DESC)')
            db_execute(
                c,
                """CREATE TABLE IF NOT EXISTS student_messages (
                       id SERIAL PRIMARY KEY,
                       school_id TEXT NOT NULL,
                       title TEXT NOT NULL,
                       message TEXT NOT NULL,
                       target_classname TEXT DEFAULT '',
                       target_stream TEXT DEFAULT '',
                       deadline_date TEXT DEFAULT '',
                       is_active INTEGER NOT NULL DEFAULT 1,
                       created_by TEXT DEFAULT '',
                       created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                   )""",
            )
            db_execute(
                c,
                """CREATE TABLE IF NOT EXISTS teacher_messages (
                       id SERIAL PRIMARY KEY,
                       school_id TEXT NOT NULL,
                       title TEXT NOT NULL,
                       message TEXT NOT NULL,
                       target_classname TEXT DEFAULT '',
                       target_subject TEXT DEFAULT '',
                       deadline_date TEXT DEFAULT '',
                       is_active INTEGER NOT NULL DEFAULT 1,
                       created_by TEXT DEFAULT '',
                       created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                   )""",
            )
            db_execute(c, 'CREATE INDEX IF NOT EXISTS idx_student_messages_school_created ON student_messages(school_id, created_at DESC)')
            db_execute(c, 'CREATE INDEX IF NOT EXISTS idx_student_messages_school_active ON student_messages(school_id, is_active)')
            db_execute(
                c,
                """CREATE TABLE IF NOT EXISTS parent_tutorial_seen (
                       id SERIAL PRIMARY KEY,
                       parent_phone TEXT UNIQUE NOT NULL,
                       seen_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                   )""",
            )
            db_execute(c, 'CREATE INDEX IF NOT EXISTS idx_parent_tutorial_seen_phone ON parent_tutorial_seen(parent_phone)')
            db_execute(c, 'CREATE INDEX IF NOT EXISTS idx_teacher_messages_school_created ON teacher_messages(school_id, created_at DESC)')
            db_execute(c, 'CREATE INDEX IF NOT EXISTS idx_teacher_messages_school_active ON teacher_messages(school_id, is_active)')
            db_execute(
                c,
                """CREATE TABLE IF NOT EXISTS student_message_reads (
                       id SERIAL PRIMARY KEY,
                       school_id TEXT NOT NULL,
                       message_id INTEGER NOT NULL,
                       student_id TEXT NOT NULL,
                       read_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                       UNIQUE(school_id, message_id, student_id)
                   )""",
            )
            db_execute(c, 'CREATE INDEX IF NOT EXISTS idx_student_message_reads_lookup ON student_message_reads(school_id, student_id, message_id)')
            db_execute(
                c,
                """CREATE TABLE IF NOT EXISTS teacher_message_reads (
                       id SERIAL PRIMARY KEY,
                       school_id TEXT NOT NULL,
                       message_id INTEGER NOT NULL,
                       teacher_id TEXT NOT NULL,
                       read_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                       UNIQUE(school_id, message_id, teacher_id)
                   )""",
            )
            db_execute(c, 'CREATE INDEX IF NOT EXISTS idx_teacher_message_reads_lookup ON teacher_message_reads(school_id, teacher_id, message_id)')
            db_execute(
                c,
                """CREATE TABLE IF NOT EXISTS parent_message_reads (
                       id SERIAL PRIMARY KEY,
                       school_id TEXT NOT NULL,
                       message_id INTEGER NOT NULL,
                       parent_phone TEXT NOT NULL,
                       read_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                       UNIQUE(school_id, message_id, parent_phone)
                   )""",
            )
            db_execute(c, 'CREATE INDEX IF NOT EXISTS idx_parent_message_reads_lookup ON parent_message_reads(school_id, parent_phone, message_id)')
        return True
    except Exception as exc:
        logging.warning("Failed to ensure extended features schema: %s", exc)
        return False

def record_login_audit(username, role, school_id, endpoint, success, reason=''):
    if not ensure_extended_features_schema():
        return
    uname = (username or '').strip()
    role_name = (role or '').strip().lower()
    sid = (school_id or '').strip() or None
    agent = (request.headers.get('User-Agent', '') or '').strip()[:300]
    ip = get_client_ip()
    try:
        with db_connection(commit=True) as conn:
            c = conn.cursor()
            db_execute(
                c,
                """INSERT INTO login_audit_logs
                   (school_id, username, role, endpoint, ip_address, user_agent, success, reason, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)""",
                (sid, uname, role_name, (endpoint or '').strip(), ip, agent, 1 if success else 0, (reason or '').strip()[:250]),
            )
    except Exception:
        pass

def is_password_expired(user):
    role = (user or {}).get('role', '')
    if role not in {'super_admin', 'school_admin'}:
        return False
    changed_at = (user or {}).get('password_changed_at')
    if not changed_at:
        return True
    dt = changed_at if isinstance(changed_at, datetime) else None
    if not dt:
        try:
            dt = datetime.fromisoformat(str(changed_at).replace('Z', '+00:00'))
        except Exception:
            return True
    return (datetime.now() - dt).days >= ADMIN_PASSWORD_MAX_AGE_DAYS

def _complete_authenticated_login(user, user_school_id):
    role = (user.get('role') or '').strip().lower()
    username = (user.get('username') or '').strip().lower()
    session.clear()
    session.permanent = True
    session['user_id'] = username
    session['role'] = role
    session['school_id'] = user_school_id
    session.pop('must_change_password', None)
    session.pop('force_password_change', None)
    session.pop('show_first_login_tutorial', None)
    session.pop('first_login_tutorial_role', None)
    record_login_audit(username, role, user_school_id, 'login', True, '')
    update_login_timestamps(username)
    if role != 'super_admin' and not has_user_seen_first_login_tutorial(username):
        session['show_first_login_tutorial'] = True
        session['first_login_tutorial_role'] = role
    if role == 'student' and is_default_student_password(user.get('password_hash', '')):
        session['must_change_password'] = True
        flash('This is your first login. Change your default password to continue.', 'error')
        return redirect(url_for('student_change_password'))
    if role in {'super_admin', 'school_admin'} and is_password_expired(user):
        session['force_password_change'] = True
        flash(f'Password expired. Change your password now (policy: {ADMIN_PASSWORD_MAX_AGE_DAYS} days).', 'error')
        if role == 'super_admin':
            return redirect(url_for('super_admin_change_password'))
        return redirect(url_for('school_admin_change_password'))
    if role == 'super_admin':
        return redirect(url_for('super_admin_dashboard'))
    if role == 'school_admin':
        return redirect(url_for('school_admin_dashboard'))
    if role == 'teacher':
        return redirect(url_for('teacher_dashboard'))
    if role == 'student':
        return redirect(url_for('student_dashboard'))
    return redirect(url_for('menu'))

def save_attendance_record_with_cursor(c, school_id, student_id, classname, term, academic_year, attendance_date, status, note='', marked_by=''):
    db_execute(
        c,
        """INSERT INTO student_attendance
           (school_id, student_id, classname, term, academic_year, attendance_date, status, note, marked_by, updated_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
           ON CONFLICT(school_id, student_id, attendance_date)
           DO UPDATE SET
             classname = excluded.classname,
             term = excluded.term,
             academic_year = excluded.academic_year,
             status = excluded.status,
             note = excluded.note,
             marked_by = excluded.marked_by,
             updated_at = excluded.updated_at""",
        (
            school_id,
            student_id,
            classname,
            term,
            academic_year or '',
            attendance_date,
            normalize_attendance_status(status),
            (note or '').strip()[:250],
            marked_by or '',
            datetime.now(),
        ),
    )

def get_class_attendance_for_date(school_id, classname, attendance_date, term='', academic_year=''):
    if not ensure_student_attendance_schema():
        return {}
    with db_connection() as conn:
        c = conn.cursor()
        db_execute(
            c,
            """SELECT student_id, status, note, updated_at
               FROM student_attendance
               WHERE school_id = ?
                 AND LOWER(classname) = LOWER(?)
                 AND attendance_date = ?
                 AND COALESCE(term, '') = COALESCE(?, COALESCE(term, ''))
                 AND COALESCE(academic_year, '') = COALESCE(?, COALESCE(academic_year, ''))""",
            (school_id, classname, attendance_date, term or None, academic_year or None),
        )
        out = {}
        for row in c.fetchall() or []:
            out[row[0]] = {
                'status': normalize_attendance_status(row[1]),
                'note': (row[2] or '').strip(),
                'updated_at': row[3],
            }
        return out

def get_class_attendance_summary(school_id, classname, term='', academic_year=''):
    if not ensure_student_attendance_schema():
        return {'total_marked': 0, 'status_counts': {}, 'latest_date': ''}
    with db_connection() as conn:
        c = conn.cursor()
        db_execute(
            c,
            """SELECT status, COUNT(*)
               FROM student_attendance
               WHERE school_id = ?
                 AND LOWER(classname) = LOWER(?)
                 AND COALESCE(term, '') = COALESCE(?, COALESCE(term, ''))
                 AND COALESCE(academic_year, '') = COALESCE(?, COALESCE(academic_year, ''))
               GROUP BY status""",
            (school_id, classname, term or None, academic_year or None),
        )
        status_counts = {}
        total = 0
        for status, count in c.fetchall() or []:
            key = normalize_attendance_status(status)
            if not key:
                continue
            n = int(count or 0)
            status_counts[key] = n
            total += n
        db_execute(
            c,
            """SELECT attendance_date
               FROM student_attendance
               WHERE school_id = ?
                 AND LOWER(classname) = LOWER(?)
                 AND COALESCE(term, '') = COALESCE(?, COALESCE(term, ''))
                 AND COALESCE(academic_year, '') = COALESCE(?, COALESCE(academic_year, ''))
               ORDER BY attendance_date DESC
               LIMIT 1""",
            (school_id, classname, term or None, academic_year or None),
        )
        row = c.fetchone()
        return {
            'total_marked': total,
            'status_counts': status_counts,
            'latest_date': row[0] if row else '',
        }

def _coerce_to_date(value):
    if isinstance(value, datetime):
        return value.date()
    if isinstance(value, date):
        return value
    raw = (str(value or '')).strip()
    if not raw:
        return None
    for fmt in ('%Y-%m-%d', '%Y-%m-%d %H:%M:%S', '%Y-%m-%d %H:%M:%S.%f'):
        try:
            return datetime.strptime(raw, fmt).date()
        except Exception:
            continue
    try:
        normalized = raw.replace('Z', '+00:00')
        return datetime.fromisoformat(normalized).date()
    except Exception:
        return None

def get_term_instructional_dates(school_id, academic_year, term):
    calendar_row = get_school_term_calendar(school_id, academic_year, term) or {}
    program_row = get_school_term_program(school_id, academic_year, term) or {}
    start = _parse_iso_date(calendar_row.get('open_date', ''))
    end = _parse_iso_date(calendar_row.get('close_date', ''))
    if not start or not end or end < start:
        return {
            'valid_dates': [],
            'valid_iso_set': set(),
            'open_date': start,
            'close_date': end,
            'message': (
                f'Term calendar is incomplete for {term} ({academic_year}). '
                'Set term open/close dates in School Settings before publishing.'
            ),
        }

    break_start = _parse_iso_date(calendar_row.get('midterm_break_start', ''))
    break_end = _parse_iso_date(calendar_row.get('midterm_break_end', ''))
    if break_start and break_end and break_end < break_start:
        break_start, break_end = break_end, break_start

    holiday_ranges = []
    for row in extract_program_holiday_ranges(program_row):
        h_start = row.get('start') if isinstance(row.get('start'), date) else None
        h_end = row.get('end') if isinstance(row.get('end'), date) else None
        if not h_start or not h_end:
            continue
        if h_end < h_start:
            h_start, h_end = h_end, h_start
        holiday_ranges.append((h_start, h_end))

    valid_dates = []
    current = start
    one_day = timedelta(days=1)
    while current <= end:
        if current.weekday() not in (5, 6):
            in_midterm_break = bool(break_start and break_end and break_start <= current <= break_end)
            in_holiday = any(a <= current <= b for a, b in holiday_ranges)
            if not in_midterm_break and not in_holiday:
                valid_dates.append(current)
        current += one_day

    return {
        'valid_dates': valid_dates,
        'valid_iso_set': {d.isoformat() for d in valid_dates},
        'open_date': start,
        'close_date': end,
        'message': '',
    }

def get_class_attendance_publish_readiness(school_id, classname, term, academic_year, class_students_data=None):
    students_map = class_students_data if isinstance(class_students_data, dict) else load_students(
        school_id,
        class_filter=classname,
        term_filter=term,
    )
    student_items = list((students_map or {}).items())
    if not student_items:
        return {
            'ready': False,
            'days_open': 0,
            'missing_rows': [],
            'message': f'No students found in {classname}.',
        }
    instructional = get_term_instructional_dates(school_id, academic_year, term)
    valid_dates = instructional.get('valid_dates') or []
    valid_iso_set = instructional.get('valid_iso_set') or set()
    days_open = len(valid_dates)
    if days_open <= 0:
        return {
            'ready': False,
            'days_open': 0,
            'missing_rows': [],
            'message': instructional.get('message') or f'No instructional days found for {term} ({academic_year}).',
        }
    if not ensure_student_attendance_schema():
        return {
            'ready': False,
            'days_open': days_open,
            'missing_rows': [],
            'message': 'Attendance schema is unavailable. Run migration and retry.',
        }
    with db_connection() as conn:
        c = conn.cursor()
        db_execute(
            c,
            """SELECT student_id, attendance_date
               FROM student_attendance
               WHERE school_id = ?
                 AND LOWER(classname) = LOWER(?)
                 AND term = ?
                 AND COALESCE(academic_year, '') = COALESCE(?, '')""",
            (school_id, classname, term, academic_year or ''),
        )
        marked_date_sets = {}
        for row in c.fetchall() or []:
            sid = str(row[0] or '').strip()
            day = (row[1] or '').strip()
            if not sid or day not in valid_iso_set:
                continue
            marked_date_sets.setdefault(sid, set()).add(day)
        db_execute(
            c,
            """SELECT student_id, created_at
               FROM students
               WHERE school_id = ?
                 AND LOWER(classname) = LOWER(?)
                 AND term = ?""",
            (school_id, classname, term),
        )
        created_at_by_student = {
            str(row[0] or '').strip(): _coerce_to_date(row[1])
            for row in (c.fetchall() or [])
            if str(row[0] or '').strip()
        }

    term_open_date = instructional.get('open_date')
    missing_rows = []
    for sid, student in student_items:
        join_date = created_at_by_student.get(sid) or term_open_date
        expected_dates = [d for d in valid_dates if not join_date or d >= join_date]
        expected_count = len(expected_dates)
        marked_days = marked_date_sets.get(sid, set())
        if join_date:
            marked_count = sum(
                1
                for d in marked_days
                for marked_date in [_parse_iso_date(d)]
                if marked_date and marked_date >= join_date
            )
        else:
            marked_count = len(marked_days)
        if marked_count < expected_count:
            missing_rows.append({
                'student_id': sid,
                'student_name': (student or {}).get('firstname', sid) or sid,
                'marked_days': marked_count,
                'expected_days': expected_count,
                'missing_days': expected_count - marked_count,
            })
    return {
        'ready': len(missing_rows) == 0,
        'days_open': days_open,
        'missing_rows': missing_rows,
        'message': '',
    }

def get_student_absent_days(school_id, student_id, classname, term='', academic_year=''):
    if not ensure_student_attendance_schema():
        return 0
    with db_connection() as conn:
        c = conn.cursor()
        db_execute(
            c,
            """SELECT COUNT(DISTINCT attendance_date)
               FROM student_attendance
               WHERE school_id = ?
                 AND student_id = ?
                 AND LOWER(classname) = LOWER(?)
                 AND COALESCE(term, '') = COALESCE(?, COALESCE(term, ''))
                 AND COALESCE(academic_year, '') = COALESCE(?, COALESCE(academic_year, ''))
                 AND LOWER(status) = 'absent'""",
            (school_id, student_id, classname, term or None, academic_year or None),
        )
        row = c.fetchone()
        try:
            return int(row[0] or 0) if row else 0
        except Exception:
            return 0

def build_result_term_attendance_data(school_id, student_id, classname, term, academic_year):
    calendar_row = get_school_term_calendar(school_id, academic_year, term) or {}
    program_row = get_school_term_program(school_id, academic_year, term) or {}
    try:
        days_open = int(calendar_row.get('days_open', 0) or 0)
    except Exception:
        days_open = 0
    days_absent = get_student_absent_days(
        school_id=school_id,
        student_id=student_id,
        classname=classname,
        term=term,
        academic_year=academic_year,
    )
    if days_open > 0 and days_absent > days_open:
        days_absent = days_open
    days_present = max(0, days_open - max(days_absent, 0))
    next_term_begin = resolve_next_term_begin_date(
        school_id=school_id,
        academic_year=academic_year,
        term=term,
        current_value=(program_row.get('next_term_begin_date') or ''),
    )
    return {
        'term_begin': (calendar_row.get('open_date') or '').strip(),
        'term_end': (calendar_row.get('close_date') or '').strip(),
        'next_term_begin': next_term_begin,
        'days_open': days_open,
        'days_absent': max(days_absent, 0),
        'days_present': days_present,
    }

def _default_behaviour_assessment():
    return {trait: '' for trait in BEHAVIOUR_TRAITS}

def normalize_behaviour_assessment(payload):
    out = _default_behaviour_assessment()
    raw = payload if isinstance(payload, dict) else {}
    for trait in BEHAVIOUR_TRAITS:
        val = (raw.get(trait, '') or '').strip().upper()
        out[trait] = val if val in BEHAVIOUR_GRADE_SCALE else ''
    return out

def ensure_behaviour_assessment_schema():
    try:
        with db_connection(commit=True) as conn:
            c = conn.cursor()
            db_execute(
                c,
                """CREATE TABLE IF NOT EXISTS behaviour_assessments (
                       id SERIAL PRIMARY KEY,
                       school_id TEXT NOT NULL,
                       student_id TEXT NOT NULL,
                       classname TEXT NOT NULL,
                       term TEXT NOT NULL,
                       academic_year TEXT DEFAULT '',
                       behaviour_json TEXT NOT NULL DEFAULT '{}',
                       updated_by TEXT DEFAULT '',
                       updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                       UNIQUE(school_id, student_id, term, academic_year)
                   )""",
            )
            db_execute(c, "ALTER TABLE published_student_results ADD COLUMN IF NOT EXISTS behaviour_json TEXT DEFAULT '{}'")
        return True
    except Exception as exc:
        logging.warning("Failed to ensure behaviour assessment schema: %s", exc)
        return False

def save_behaviour_assessment_with_cursor(c, school_id, student_id, classname, term, academic_year, behaviour_payload, updated_by=''):
    db_execute(
        c,
        """INSERT INTO behaviour_assessments
           (school_id, student_id, classname, term, academic_year, behaviour_json, updated_by, updated_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)
           ON CONFLICT(school_id, student_id, term, academic_year)
           DO UPDATE SET
             classname = excluded.classname,
             behaviour_json = excluded.behaviour_json,
             updated_by = excluded.updated_by,
             updated_at = excluded.updated_at""",
        (
            school_id,
            student_id,
            classname,
            term,
            academic_year or '',
            json.dumps(normalize_behaviour_assessment(behaviour_payload)),
            updated_by or '',
            datetime.now(),
        ),
    )

def get_class_behaviour_assessments(school_id, classname, term, academic_year=''):
    if not ensure_behaviour_assessment_schema():
        return {}
    with db_connection() as conn:
        c = conn.cursor()
        db_execute(
            c,
            """SELECT student_id, behaviour_json
               FROM behaviour_assessments
               WHERE school_id = ? AND LOWER(classname) = LOWER(?) AND term = ?
                 AND COALESCE(academic_year, '') = COALESCE(?, '')""",
            (school_id, classname, term, academic_year or ''),
        )
        out = {}
        for sid, raw in c.fetchall() or []:
            out[sid] = normalize_behaviour_assessment(_safe_json_object(raw))
        return out

def get_student_behaviour_assessment(school_id, student_id, term, academic_year=''):
    if not ensure_behaviour_assessment_schema():
        return _default_behaviour_assessment()
    with db_connection() as conn:
        c = conn.cursor()
        db_execute(
            c,
            """SELECT behaviour_json
               FROM behaviour_assessments
               WHERE school_id = ? AND student_id = ? AND term = ?
                 AND COALESCE(academic_year, '') = COALESCE(?, '')
               LIMIT 1""",
            (school_id, student_id, term, academic_year or ''),
        )
        row = c.fetchone()
    return normalize_behaviour_assessment(_safe_json_object(row[0] if row else '{}'))

def class_behaviour_completion(school_id, classname, term, academic_year, student_ids):
    by_student = get_class_behaviour_assessments(school_id, classname, term, academic_year)
    missing_students = []
    for sid in (student_ids or []):
        payload = by_student.get(sid, _default_behaviour_assessment())
        if any((payload.get(trait, '') or '').strip() not in BEHAVIOUR_GRADE_SCALE for trait in BEHAVIOUR_TRAITS):
            missing_students.append(sid)
    return {
        'ready': len(missing_students) == 0 and bool(student_ids),
        'missing_count': len(missing_students),
        'missing_students': missing_students,
        'by_student': by_student,
    }

def _coerce_number(value, default=0.0):
    """Best-effort numeric coercion for legacy JSON score payloads."""
    if isinstance(value, (int, float)):
        number = float(value)
    elif isinstance(value, str):
        text = value.strip()
        if not text:
            return float(default)
        try:
            number = float(text)
        except (TypeError, ValueError):
            return float(default)
    else:
        return float(default)
    if not math.isfinite(number):
        return float(default)
    return number

def subject_overall_mark(subject_scores):
    """Safely compute one subject total score from stored score fields."""
    if not isinstance(subject_scores, dict):
        return 0.0
    explicit = subject_scores.get('overall_mark')

    total_test = subject_scores.get('total_test')
    if not isinstance(total_test, (int, float)):
        total_test = 0.0
        for k, v in subject_scores.items():
            if str(k).startswith('test_'):
                total_test += _coerce_number(v, 0.0)
    else:
        total_test = _coerce_number(total_test, 0.0)

    total_exam = subject_scores.get('total_exam')
    if not isinstance(total_exam, (int, float)):
        exam_score = subject_scores.get('exam_score')
        if isinstance(exam_score, (int, float, str)):
            total_exam = _coerce_number(exam_score, 0.0)
        else:
            objective = _coerce_number(subject_scores.get('objective', 0), 0.0)
            theory = _coerce_number(subject_scores.get('theory', 0), 0.0)
            total_exam = objective + theory
    else:
        total_exam = _coerce_number(total_exam, 0.0)

    # Backward-compat: if legacy rows only have overall_mark and no components, use it.
    # Treat numeric strings as valid components to avoid stale overall_mark overriding
    # real test/exam values loaded from loose imports.
    def _has_numeric(value):
        if isinstance(value, (int, float)):
            return math.isfinite(float(value))
        if isinstance(value, str):
            text = value.strip()
            if not text:
                return False
            try:
                return math.isfinite(float(text))
            except (TypeError, ValueError):
                return False
        return False

    has_components = (
        _has_numeric(subject_scores.get('total_test')) or
        _has_numeric(subject_scores.get('total_exam')) or
        _has_numeric(subject_scores.get('exam_score')) or
        _has_numeric(subject_scores.get('objective')) or
        _has_numeric(subject_scores.get('theory')) or
        any(str(k).startswith('test_') and _has_numeric(v) for k, v in subject_scores.items())
    )
    if not has_components and isinstance(explicit, (int, float, str)):
        return _coerce_number(explicit, 0.0)

    return float(total_test or 0) + float(total_exam or 0)


def _combine_student_snapshots(snapshots, school_id):
    """Merge multiple term snapshots into a single aggregated result.

    The snapshot at the end of the list is treated as the canonical source for
    metadata such as firstname/classname/stream.  Subject marks are averaged
    across all provided snapshots; overall average, grade and status are
    recomputed using the school's current grading configuration.
    """
    if not snapshots:
        return None
    # accumulate all subject names
    all_subjects = set()
    for s in snapshots:
        all_subjects.update(s.get('subjects', []) or [])
    combined_scores = {}
    for subj in all_subjects:
        marks = []
        latest_subject_comment = ''
        for s in snapshots:
            scores = s.get('scores', {}) or {}
            ss = scores.get(subj)
            if isinstance(ss, dict):
                marks.append(subject_overall_mark(ss))
        for s in reversed(snapshots):
            scores = s.get('scores', {}) or {}
            ss = scores.get(subj)
            if isinstance(ss, dict):
                c = (ss.get('subject_teacher_comment', '') or '').strip()
                if c:
                    latest_subject_comment = c
                    break
        avg_mark = sum(marks) / len(marks) if marks else 0.0
        block = {'overall_mark': avg_mark}
        if latest_subject_comment:
            block['subject_teacher_comment'] = latest_subject_comment
        combined_scores[subj] = block
    # Combined-third-term policy: overall average is the mean of each term average.
    term_averages = []
    for s in snapshots:
        try:
            term_averages.append(float(s.get('average_marks') or 0))
        except (TypeError, ValueError):
            term_averages.append(0.0)
    avg_marks = (sum(term_averages) / len(term_averages)) if term_averages else 0.0
    grade_cfg = get_grade_config(school_id)
    combined_grade = grade_from_score(avg_marks, grade_cfg)
    combined_status = status_from_score(avg_marks, grade_cfg)

    base = snapshots[-1].copy()
    base['scores'] = combined_scores
    base['subjects'] = sorted(all_subjects)
    base['number_of_subject'] = len(base['subjects'])
    base['average_marks'] = avg_marks
    base['Grade'] = combined_grade
    base['Status'] = combined_status
    return base


def safe_int(value, default):
    """Parse integer safely while preserving valid zero values."""
    try:
        return int(value)
    except (TypeError, ValueError):
        return int(default)

def safe_float(value, default):
    """Parse float safely while preserving valid zero values."""
    try:
        return float(value)
    except (TypeError, ValueError):
        return float(default)

def _pdf_escape(text):
    return str(text or '').replace('\\', '\\\\').replace('(', '\\(').replace(')', '\\)')

def _build_simple_pdf(lines):
    """
    Minimal single-file PDF generator (no external dependencies).
    Keeps output lightweight for server-side downloads.
    """
    normalized = [str(line or '') for line in (lines or [])]
    max_lines = 56
    if len(normalized) > max_lines:
        normalized = normalized[:max_lines - 1] + ['... (truncated)']

    y = 800
    rendered = ['BT', '/F1 10 Tf']
    for line in normalized:
        rendered.append(f'1 0 0 1 40 {y} Tm ({_pdf_escape(line)}) Tj')
        y -= 14
    rendered.append('ET')
    stream = '\n'.join(rendered).encode('latin-1', errors='replace')

    objects = []
    objects.append(b'1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n')
    objects.append(b'2 0 obj\n<< /Type /Pages /Kids [4 0 R] /Count 1 >>\nendobj\n')
    objects.append(b'3 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>\nendobj\n')
    objects.append(
        b'4 0 obj\n'
        b'<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] '
        b'/Resources << /Font << /F1 3 0 R >> >> /Contents 5 0 R >>\n'
        b'endobj\n'
    )
    objects.append(
        b'5 0 obj\n<< /Length ' + str(len(stream)).encode('ascii') + b' >>\nstream\n'
        + stream + b'\nendstream\nendobj\n'
    )

    out = bytearray(b'%PDF-1.4\n%\xe2\xe3\xcf\xd3\n')
    offsets = [0]
    for obj in objects:
        offsets.append(len(out))
        out.extend(obj)
    xref_pos = len(out)
    out.extend(f'xref\n0 {len(offsets)}\n'.encode('ascii'))
    out.extend(b'0000000000 65535 f \n')
    for off in offsets[1:]:
        out.extend(f'{off:010d} 00000 n \n'.encode('ascii'))
    out.extend(
        f'trailer\n<< /Size {len(offsets)} /Root 1 0 R >>\nstartxref\n{xref_pos}\n%%EOF\n'.encode('ascii')
    )
    return bytes(out)

def _build_rich_result_pdf_reportlab(report):
    """
    Rich PDF rendering with reportlab (if installed).
    Returns bytes on success, otherwise None.
    """
    try:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import getSampleStyleSheet
        from reportlab.lib.units import mm
        from reportlab.platypus import Image, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
    except Exception:
        return None

    buffer = BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        leftMargin=12 * mm,
        rightMargin=12 * mm,
        topMargin=10 * mm,
        bottomMargin=10 * mm,
        title="Academic Report Card",
    )
    styles = getSampleStyleSheet()
    story = []

    school_name = (report.get('school_name') or '').strip() or 'School Result'
    student_name = (report.get('student_name') or '').strip()
    student_id = (report.get('student_id') or '').strip()
    class_name = (report.get('class_name') or '').strip()
    term = (report.get('term') or '').strip()
    year = (report.get('year') or '').strip()
    average = report.get('average')
    grade = (report.get('grade') or '').strip()
    status = (report.get('status') or '').strip()
    teacher_name = (report.get('teacher_name') or '').strip()
    principal_name = (report.get('principal_name') or '').strip()
    teacher_signature_ref = (report.get('teacher_signature') or '').strip()
    principal_signature_ref = (report.get('principal_signature') or '').strip()
    generated_on = (report.get('generated_on') or '').strip()
    subject_rows = report.get('subject_rows') or []
    show_positions = bool(report.get('show_positions', True))

    def _decode_signature_ref(ref):
        raw = (ref or '').strip()
        if not raw:
            return None
        data_uri = re.match(r'^data:image/[^;]+;base64,(.+)$', raw, flags=re.IGNORECASE | re.DOTALL)
        if data_uri:
            try:
                return base64.b64decode(data_uri.group(1), validate=False)
            except Exception:
                return None
        if os.path.isfile(raw):
            try:
                with open(raw, 'rb') as f:
                    return f.read()
            except Exception:
                return None
        return None

    def _signature_cell(ref):
        blob = _decode_signature_ref(ref)
        if not blob:
            return Paragraph("-", styles['Normal'])
        try:
            img = Image(BytesIO(blob))
            img.drawHeight = 14 * mm
            img.drawWidth = 45 * mm
            return img
        except Exception:
            return Paragraph("-", styles['Normal'])

    story.append(Paragraph(f"<b>{_pdf_escape(school_name)}</b>", styles['Title']))
    story.append(Paragraph("Academic Report Card", styles['Heading2']))
    story.append(Spacer(1, 6))

    meta_data = [
        ["Student", student_name, "Student ID", student_id],
        ["Class", class_name, "Term", term],
        ["Academic Year", year or "-", "Generated", generated_on or "-"],
        ["Average", _format_mark(average), "Grade / Status", f"{grade} / {status}"],
    ]
    meta_table = Table(meta_data, colWidths=[28 * mm, 58 * mm, 30 * mm, 58 * mm])
    meta_table.setStyle(
        TableStyle([
            ('GRID', (0, 0), (-1, -1), 0.4, colors.grey),
            ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#f3f5f7')),
            ('BACKGROUND', (2, 0), (2, -1), colors.HexColor('#f3f5f7')),
            ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('LEFTPADDING', (0, 0), (-1, -1), 6),
            ('RIGHTPADDING', (0, 0), (-1, -1), 6),
            ('TOPPADDING', (0, 0), (-1, -1), 4),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ])
    )
    story.append(meta_table)
    story.append(Spacer(1, 8))

    if show_positions:
        subject_table_data = [[
            "Subject", "Total Exam", "Highest", "Lowest", "Total", "Grade", "Position"
        ]]
    else:
        subject_table_data = [[
            "Subject", "Total Exam", "Highest", "Lowest", "Total", "Grade"
        ]]
    for row in subject_rows:
        table_row = [
            str(row.get('subject') or ''),
            _format_mark(row.get('total_exam')),
            _format_mark(row.get('highest')),
            _format_mark(row.get('lowest')),
            _format_mark(row.get('total')),
            str(row.get('grade') or '-'),
        ]
        if show_positions:
            table_row.append(str(row.get('position') or '-'))
        subject_table_data.append(table_row)
    if len(subject_table_data) == 1:
        subject_table_data.append(['-', '-', '-', '-', '-', '-', '-'] if show_positions else ['-', '-', '-', '-', '-', '-'])

    subject_col_widths = [50 * mm, 22 * mm, 22 * mm, 22 * mm, 20 * mm, 16 * mm, 20 * mm] if show_positions else [58 * mm, 24 * mm, 24 * mm, 24 * mm, 24 * mm, 20 * mm]
    subject_table = Table(
        subject_table_data,
        repeatRows=1,
        colWidths=subject_col_widths,
    )
    subject_table.setStyle(
        TableStyle([
            ('GRID', (0, 0), (-1, -1), 0.35, colors.HexColor('#8b8f94')),
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#1f3f7a')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 8.5),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('ALIGN', (1, 0), (-1, -1), 'CENTER'),
            ('LEFTPADDING', (0, 0), (-1, -1), 4),
            ('RIGHTPADDING', (0, 0), (-1, -1), 4),
            ('TOPPADDING', (0, 0), (-1, -1), 3),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
        ])
    )
    story.append(subject_table)
    story.append(Spacer(1, 8))

    signature_table = Table(
        [
            ["Teacher Signature", "Principal Signature"],
            [_signature_cell(teacher_signature_ref), _signature_cell(principal_signature_ref)],
            [teacher_name or "-", principal_name or "-"],
            ["(Term Class Teacher)", "(Principal)"],
        ],
        colWidths=[86 * mm, 86 * mm],
    )
    signature_table.setStyle(
        TableStyle([
            ('GRID', (0, 0), (-1, -1), 0.35, colors.HexColor('#8b8f94')),
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#f3f5f7')),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('LEFTPADDING', (0, 0), (-1, -1), 4),
            ('RIGHTPADDING', (0, 0), (-1, -1), 4),
            ('TOPPADDING', (0, 0), (-1, -1), 4),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ])
    )
    story.append(signature_table)
    doc.build(story)
    return buffer.getvalue()

def _format_mark(value):
    if value is None:
        return '-'
    num = _coerce_number(value, 0.0)
    return f'{num:.1f}'

def get_current_term(school):
    return (school or {}).get('current_term') or 'First Term'

def term_sort_value(term):
    t = (term or '').strip().lower()
    if t == 'first term':
        return 1
    if t == 'second term':
        return 2
    if t == 'third term':
        return 3
    return 99

def _term_token(academic_year, term):
    return f"{(academic_year or '').strip()}::{(term or '').strip()}"

def _parse_term_token(token):
    raw = (token or '').strip()
    if '::' in raw:
        year, term = raw.split('::', 1)
        return year.strip(), term.strip()
    return '', raw

def pick_default_published_term(published_terms, current_term, current_year):
    """Prefer current year+term; otherwise use the newest published entry."""
    terms = list(published_terms or [])
    if not terms:
        return None
    year_key = (current_year or '').strip()
    term_key = (current_term or '').strip()
    preferred = next(
        (t for t in terms if (t.get('term', '') or '').strip() == term_key and (t.get('academic_year', '') or '').strip() == year_key),
        None
    )
    if preferred:
        return preferred
    return terms[-1]

def resolve_requested_published_term(published_terms, requested_term, current_term='', current_year=''):
    """
    Resolve one requested term selector against published terms.
    Supports:
    - token format: "YYYY-YYYY::First Term"
    - plain format: "First Term"
    """
    terms = list(published_terms or [])
    raw = (requested_term or '').strip()
    if not raw:
        return pick_default_published_term(terms, current_term, current_year)

    req_year, req_term = _parse_term_token(raw)
    has_token_year = bool(req_year)
    if has_token_year:
        token = _term_token(req_year, req_term)
        return next((t for t in terms if t.get('token') == token), None)

    term_key = req_term.strip().lower()
    matches = [t for t in terms if (t.get('term', '') or '').strip().lower() == term_key]
    if not matches:
        return None
    year_key = (current_year or '').strip()
    preferred = next((t for t in matches if (t.get('academic_year', '') or '').strip() == year_key), None)
    return preferred or matches[-1]

def filter_visible_terms_for_student(school, published_terms):
    """
    When school operations are OFF, hide current-term results from students.
    Students can still view previous published terms.
    """
    terms = list(published_terms or [])
    if not terms:
        return terms
    if safe_int((school or {}).get('operations_enabled', 1), 1):
        return terms

    current_term = get_current_term(school)
    current_year = ((school or {}).get('academic_year') or '').strip()
    visible = []
    for t in terms:
        t_term = (t.get('term') or '').strip()
        t_year = (t.get('academic_year') or '').strip()
        is_current_term = t_term == current_term and ((not current_year) or t_year == current_year)
        if not is_current_term:
            visible.append(t)
    return visible

def detect_max_tests_from_scores(scores, default_max_tests=3):
    """Infer max test index from score keys test_1..test_n."""
    max_seen = 0
    if isinstance(scores, dict):
        for subject_scores in scores.values():
            if not isinstance(subject_scores, dict):
                continue
            for key in subject_scores.keys():
                if isinstance(key, str) and key.startswith('test_'):
                    try:
                        idx = int(key.split('_', 1)[1])
                        if idx > max_seen:
                            max_seen = idx
                    except (TypeError, ValueError):
                        continue
    fallback = max(1, safe_int(default_max_tests, 3))
    return max_seen if max_seen > 0 else fallback


def _is_finite_number_like(value):
    if isinstance(value, (int, float)):
        return math.isfinite(float(value))
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return False
        try:
            return math.isfinite(float(text))
        except (TypeError, ValueError):
            return False
    return False


def is_score_complete_for_subject(subject_scores, school):
    if not isinstance(subject_scores, dict):
        return False
    if not _is_finite_number_like(subject_scores.get('overall_mark')):
        return False
    if school.get('test_enabled', 1) and not _is_finite_number_like(subject_scores.get('total_test')):
        return False
    if school.get('exam_enabled', 1) and not _is_finite_number_like(subject_scores.get('total_exam')):
        return False
    return True

def is_student_score_complete(student, school, term):
    """A student is complete when all configured subjects have complete score blocks for the active term."""
    if not student or student.get('term') != term:
        return False
    subjects = student.get('subjects', []) if isinstance(student.get('subjects', []), list) else []
    if not subjects:
        return False
    scores = student.get('scores', {}) if isinstance(student.get('scores', {}), dict) else {}
    for subject in subjects:
        if not is_score_complete_for_subject(get_subject_score_block(scores, subject), school):
            return False
    return True

def get_subject_score_block(scores_map, subject_name):
    """
    Resolve one subject score block with tolerant key matching.
    Handles key drift like "English" vs "English Language" when possible.
    """
    if not isinstance(scores_map, dict):
        return {}
    raw_target = (subject_name or '').strip().lower()
    norm_target = normalize_subject_name(subject_name or '').lower()
    if not raw_target and not norm_target:
        return {}
    # 1) exact case-insensitive key match
    for key, value in scores_map.items():
        if (str(key).strip().lower() == raw_target) and isinstance(value, dict):
            return value
    # 2) normalized subject name match
    for key, value in scores_map.items():
        if normalize_subject_name(str(key)).lower() == norm_target and isinstance(value, dict):
            return value
    return {}


def compute_average_marks_from_scores(scores_map, subjects=None):
    """Compute average marks, preferring active subject list when available."""
    if not isinstance(scores_map, dict):
        return 0.0
    marks = []
    subject_list = normalize_subjects_list(subjects or [])
    if subject_list:
        for subject in subject_list:
            block = get_subject_score_block(scores_map, subject)
            if isinstance(block, dict) and block:
                marks.append(subject_overall_mark(block))
    else:
        marks = [subject_overall_mark(v) for v in scores_map.values() if isinstance(v, dict)]
    return (sum(marks) / len(marks)) if marks else 0.0

def compute_class_subject_completion(school_id, classname, term, academic_year='', school=None, class_students_data=None):
    """
    Build per-subject completion progress for one class in a term.
    Used to block class result submission until all required subject scores are complete.
    """
    school = school or get_school(school_id) or {}
    classname = (classname or '').strip()
    term = (term or '').strip()
    if not classname or not term:
        return {
            'rows': [],
            'ready': False,
            'total_students': 0,
        }

    if class_students_data is None:
        class_students_data = load_students(school_id, class_filter=classname, term_filter=term)
    students = [s for s in class_students_data.values() if (s.get('classname') or '').strip() == classname and (s.get('term') or '').strip() == term]
    total_students = len(students)
    if total_students <= 0:
        return {
            'rows': [],
            'ready': False,
            'total_students': 0,
        }

    cfg = get_class_subject_config(school_id, classname) or {}
    subject_order = _dedupe_keep_order([
        normalize_subject_name(s)
        for s in (
            (cfg.get('core_subjects') or [])
            + (cfg.get('science_subjects') or [])
            + (cfg.get('art_subjects') or [])
            + (cfg.get('commercial_subjects') or [])
            + (cfg.get('optional_subjects') or [])
        )
        if str(s).strip()
    ])
    if not subject_order:
        # Fall back to actual subjects offered by students in this class/term.
        # Avoid using global defaults here because they can create false "pending"
        # requirements for schools that have not configured this class yet.
        subject_order = _dedupe_keep_order([
            normalize_subject_name(subj)
            for s in students
            for subj in normalize_subjects_list(s.get('subjects', []))
            if str(subj).strip()
        ])

    assignment_rows = get_teacher_subject_assignments(
        school_id,
        classname=classname,
        term=term,
        academic_year=academic_year,
    )
    assigned_teachers_by_subject = {}
    for row in assignment_rows:
        subject_name = normalize_subject_name(row.get('subject', ''))
        teacher_name = (row.get('teacher_name') or '').strip() or (row.get('teacher_id') or '').strip()
        if not subject_name or not teacher_name:
            continue
        assigned_teachers_by_subject.setdefault(subject_name, set()).add(teacher_name)

    progress_rows = []
    for subject in subject_order:
        eligible_students = 0
        completed_students = 0
        for s in students:
            offered_map = {x.lower(): x for x in normalize_subjects_list(s.get('subjects', []))}
            subject_key = offered_map.get(subject.lower())
            if not subject_key:
                continue
            eligible_students += 1
            score_block = get_subject_score_block((s.get('scores') or {}), subject_key)
            if is_score_complete_for_subject(score_block, school):
                completed_students += 1

        pending_students = max(0, eligible_students - completed_students)
        assigned_teachers = sorted(assigned_teachers_by_subject.get(subject, set()), key=lambda x: x.lower())
        progress_rows.append({
            'subject': subject,
            'assigned_teachers': assigned_teachers,
            'eligible_students': eligible_students,
            'completed_students': completed_students,
            'pending_students': pending_students,
            'ready': eligible_students > 0 and pending_students == 0,
        })

    ready = bool(progress_rows) and all((row.get('eligible_students', 0) > 0 and row.get('pending_students', 0) == 0) for row in progress_rows)
    return {
        'rows': progress_rows,
        'ready': ready,
        'total_students': total_students,
    }

def _set_result_published_with_cursor(
    c,
    school_id,
    classname,
    term,
    academic_year,
    teacher_id,
    is_published,
    teacher_name='',
    principal_name='',
):
    """Write result_publications row using caller-owned transaction."""
    ensure_result_publication_approval_columns()
    has_approval_cols = result_publication_has_approval_columns()
    school = get_school(school_id) or {}
    resolved_principal_name = (principal_name or school.get('principal_name', '') or '').strip()
    resolved_teacher_name = (teacher_name or '').strip()
    if not resolved_teacher_name and teacher_id:
        db_execute(
            c,
            "SELECT firstname, lastname FROM teachers WHERE school_id = ? AND user_id = ? LIMIT 1",
            (school_id, teacher_id),
        )
        row = c.fetchone()
        if row:
            resolved_teacher_name = f"{row[0] or ''} {row[1] or ''}".strip() or str(teacher_id)
        else:
            resolved_teacher_name = str(teacher_id)
    if has_approval_cols:
        db_execute(
            c,
            (
                "INSERT INTO result_publications "
                "(school_id, classname, term, academic_year, teacher_id, teacher_name, principal_name, is_published, published_at, "
                "approval_status, submitted_at, submitted_by, reviewed_at, reviewed_by, review_note, updated_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP) "
                "ON CONFLICT(school_id, classname, term, academic_year) DO UPDATE SET "
                "teacher_id = excluded.teacher_id, "
                "teacher_name = excluded.teacher_name, "
                "principal_name = excluded.principal_name, "
                "is_published = excluded.is_published, "
                "published_at = excluded.published_at, "
                "approval_status = excluded.approval_status, "
                "submitted_at = excluded.submitted_at, "
                "submitted_by = excluded.submitted_by, "
                "reviewed_at = excluded.reviewed_at, "
                "reviewed_by = excluded.reviewed_by, "
                "review_note = excluded.review_note, "
                "updated_at = CURRENT_TIMESTAMP"
            ),
            (
                school_id,
                classname,
                term,
                academic_year or '',
                teacher_id,
                resolved_teacher_name,
                resolved_principal_name,
                1 if is_published else 0,
                datetime.now().isoformat() if is_published else None,
                'approved' if is_published else 'not_submitted',
                None,
                None,
                None,
                None,
                None,
            ),
        )
    else:
        db_execute(
            c,
            (
                "INSERT INTO result_publications "
                "(school_id, classname, term, academic_year, teacher_id, teacher_name, principal_name, is_published, published_at, updated_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP) "
                "ON CONFLICT(school_id, classname, term, academic_year) DO UPDATE SET "
                "teacher_id = excluded.teacher_id, "
                "teacher_name = excluded.teacher_name, "
                "principal_name = excluded.principal_name, "
                "is_published = excluded.is_published, "
                "published_at = excluded.published_at, "
                "updated_at = CURRENT_TIMESTAMP"
            ),
            (
                school_id,
                classname,
                term,
                academic_year or '',
                teacher_id,
                resolved_teacher_name,
                resolved_principal_name,
                1 if is_published else 0,
                datetime.now().isoformat() if is_published else None,
            ),
        )

def set_result_published(school_id, classname, term, academic_year, teacher_id, is_published, teacher_name='', principal_name=''):
    """Publish/unpublish a class result for a term."""
    with db_connection(commit=True) as conn:
        c = conn.cursor()
        _set_result_published_with_cursor(
            c=c,
            school_id=school_id,
            classname=classname,
            term=term,
            academic_year=academic_year,
            teacher_id=teacher_id,
            is_published=is_published,
            teacher_name=teacher_name,
            principal_name=principal_name,
        )

def is_result_published(school_id, classname, term, academic_year=''):
    with db_connection() as conn:
        c = conn.cursor()
        db_execute(
            c,
            """SELECT is_published FROM result_publications
               WHERE school_id = ? AND classname = ? AND term = ? AND COALESCE(academic_year, '') = COALESCE(?, '')
               LIMIT 1""",
            (school_id, classname, term, academic_year or ''),
        )
        row = c.fetchone()
        return bool(row and int(row[0]) == 1)

def set_term_edit_lock(school_id, classname, term, academic_year='', is_locked=True, unlocked_minutes=0, unlock_reason='', unlocked_by=''):
    """Set or temporarily relax edit lock for one published class-term."""
    with db_connection(commit=True) as conn:
        c = conn.cursor()
        unlock_until = None
        if not is_locked and int(unlocked_minutes or 0) > 0:
            unlock_until = datetime.now() + timedelta(minutes=int(unlocked_minutes))
        try:
            db_execute(
                c,
                """INSERT INTO term_edit_locks
                   (school_id, classname, term, academic_year, is_locked, unlocked_until, unlock_reason, unlocked_by, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                   ON CONFLICT(school_id, classname, term, academic_year) DO UPDATE SET
                     is_locked = excluded.is_locked,
                     unlocked_until = excluded.unlocked_until,
                     unlock_reason = excluded.unlock_reason,
                     unlocked_by = excluded.unlocked_by,
                     updated_at = CURRENT_TIMESTAMP""",
                (
                    school_id,
                    classname,
                    term,
                    academic_year or '',
                    1 if is_locked else 0,
                    unlock_until,
                    (unlock_reason or '').strip()[:400],
                    (unlocked_by or '').strip(),
                ),
            )
        except Exception as exc:
            if 'term_edit_locks' in str(exc).lower():
                raise ValueError('Term edit lock schema is unavailable. Run migration/startup DDL and retry.')
            raise

def get_term_edit_lock_status(school_id, classname, term, academic_year=''):
    """Return lock status for a published class-term."""
    if not is_result_published(school_id, classname, term, academic_year):
        return {'locked': False, 'reason': '', 'unlocked_until': None}
    try:
        with db_connection() as conn:
            c = conn.cursor()
            db_execute(
                c,
                """SELECT is_locked, unlocked_until, unlock_reason
                   FROM term_edit_locks
                   WHERE school_id = ? AND classname = ? AND term = ?
                     AND COALESCE(academic_year, '') = COALESCE(?, '')
                   LIMIT 1""",
                (school_id, classname, term, academic_year or ''),
            )
            row = c.fetchone()
    except Exception as exc:
        if 'term_edit_locks' in str(exc).lower():
            return {'locked': True, 'reason': 'Published term lock (schema pending migration).', 'unlocked_until': None}
        raise
    if not row:
        return {'locked': True, 'reason': 'Published term lock (default).', 'unlocked_until': None}
    lock_flag = bool(int(row[0] or 0))
    unlocked_until = row[1]
    if not lock_flag and unlocked_until:
        if unlocked_until > datetime.now():
            return {'locked': False, 'reason': row[2] or '', 'unlocked_until': unlocked_until}
        set_term_edit_lock(school_id, classname, term, academic_year, is_locked=True)
        return {'locked': True, 'reason': 'Temporary unlock expired.', 'unlocked_until': None}
    if not lock_flag and not unlocked_until:
        return {'locked': False, 'reason': row[2] or '', 'unlocked_until': None}
    return {'locked': True, 'reason': row[2] or '', 'unlocked_until': unlocked_until}

_RESULT_PUBLICATION_APPROVAL_COLS = (
    'approval_status',
    'submitted_at',
    'submitted_by',
    'reviewed_at',
    'reviewed_by',
    'review_note',
)
_RESULT_PUBLICATION_APPROVAL_STATE = None
_RESULT_PUBLICATION_APPROVAL_WARNED = False

def ensure_result_publication_approval_columns():
    """Schema guard for approval workflow columns.

    By default, request-time DDL is disabled. Run migration/bootstrap to apply
    schema changes, or explicitly enable runtime schema heal via env var.
    """
    global _RESULT_PUBLICATION_APPROVAL_STATE, _RESULT_PUBLICATION_APPROVAL_WARNED
    if _RESULT_PUBLICATION_APPROVAL_STATE is True:
        return True
    allow_runtime_heal = _runtime_schema_heal_allowed()
    if not allow_runtime_heal:
        present = result_publication_has_approval_columns()
        _RESULT_PUBLICATION_APPROVAL_STATE = True if present else False
        if not present and not _RESULT_PUBLICATION_APPROVAL_WARNED:
            logging.warning(
                "Approval columns missing on result_publications. "
                "Run migrations (python migrate.py) or use explicit admin DB fix command."
            )
            _RESULT_PUBLICATION_APPROVAL_WARNED = True
        return present
    try:
        with db_connection(commit=True) as conn:
            c = conn.cursor()
            db_execute(c, "ALTER TABLE result_publications ADD COLUMN IF NOT EXISTS approval_status TEXT DEFAULT 'not_submitted'")
            db_execute(c, "ALTER TABLE result_publications ADD COLUMN IF NOT EXISTS submitted_at TIMESTAMP")
            db_execute(c, "ALTER TABLE result_publications ADD COLUMN IF NOT EXISTS submitted_by TEXT")
            db_execute(c, "ALTER TABLE result_publications ADD COLUMN IF NOT EXISTS reviewed_at TIMESTAMP")
            db_execute(c, "ALTER TABLE result_publications ADD COLUMN IF NOT EXISTS reviewed_by TEXT")
            db_execute(c, "ALTER TABLE result_publications ADD COLUMN IF NOT EXISTS review_note TEXT")
        _RESULT_PUBLICATION_APPROVAL_STATE = True
        return True
    except Exception as exc:
        logging.warning("Approval schema auto-heal failed: %s", exc)
        _RESULT_PUBLICATION_APPROVAL_STATE = False
        return False

def result_publication_has_approval_columns():
    """Check if approval workflow columns exist on result_publications."""
    global _RESULT_PUBLICATION_APPROVAL_STATE
    if _RESULT_PUBLICATION_APPROVAL_STATE is True:
        return True
    if _RESULT_PUBLICATION_APPROVAL_STATE is False:
        return False
    try:
        with db_connection() as conn:
            c = conn.cursor()
            db_execute(
                c,
                """SELECT column_name
                   FROM information_schema.columns
                   WHERE table_schema = 'public'
                     AND table_name = 'result_publications'
                     AND column_name = ANY(%s)""",
                (list(_RESULT_PUBLICATION_APPROVAL_COLS),),
            )
            present = {str(row[0]) for row in c.fetchall() if row and row[0]}
            has_all = all(col in present for col in _RESULT_PUBLICATION_APPROVAL_COLS)
            if has_all:
                _RESULT_PUBLICATION_APPROVAL_STATE = True
            return has_all
    except Exception:
        return False

_SCORE_AUDIT_SCHEMA_STATE = None
_SCORE_AUDIT_SCHEMA_WARNED = False

def score_audit_table_exists():
    global _SCORE_AUDIT_SCHEMA_STATE
    if _SCORE_AUDIT_SCHEMA_STATE is True:
        return True
    if _SCORE_AUDIT_SCHEMA_STATE is False:
        return False
    try:
        with db_connection() as conn:
            c = conn.cursor()
            db_execute(
                c,
                """SELECT EXISTS (
                       SELECT 1
                       FROM information_schema.tables
                       WHERE table_schema = 'public' AND table_name = 'score_audit_logs'
                   )""",
            )
            row = c.fetchone()
            exists = bool(row and row[0])
            if exists:
                _SCORE_AUDIT_SCHEMA_STATE = True
            return exists
    except Exception:
        return False

def ensure_score_audit_schema():
    global _SCORE_AUDIT_SCHEMA_STATE, _SCORE_AUDIT_SCHEMA_WARNED
    if _SCORE_AUDIT_SCHEMA_STATE is True:
        return True
    allow_runtime_heal = _runtime_schema_heal_allowed()
    if not allow_runtime_heal:
        present = score_audit_table_exists()
        _SCORE_AUDIT_SCHEMA_STATE = True if present else False
        if not present and not _SCORE_AUDIT_SCHEMA_WARNED:
            logging.warning(
                "score_audit_logs table is missing. Run migrations (python migrate.py) "
                "or use explicit admin DB fix command."
            )
            _SCORE_AUDIT_SCHEMA_WARNED = True
        return present
    try:
        with db_connection(commit=True) as conn:
            c = conn.cursor()
            db_execute(
                c,
                """CREATE TABLE IF NOT EXISTS score_audit_logs (
                       id SERIAL PRIMARY KEY,
                       school_id TEXT NOT NULL,
                       student_id TEXT NOT NULL,
                       classname TEXT NOT NULL,
                       term TEXT NOT NULL,
                       academic_year TEXT DEFAULT '',
                       subject TEXT NOT NULL,
                       old_score_json TEXT,
                       new_score_json TEXT,
                       changed_fields_json TEXT,
                       changed_by TEXT NOT NULL,
                       changed_by_role TEXT NOT NULL,
                       change_source TEXT NOT NULL,
                       change_reason TEXT DEFAULT '',
                       changed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                   )""",
            )
            db_execute(c, "ALTER TABLE score_audit_logs ADD COLUMN IF NOT EXISTS academic_year TEXT DEFAULT ''")
            db_execute(c, "ALTER TABLE score_audit_logs ADD COLUMN IF NOT EXISTS changed_by_role TEXT DEFAULT 'teacher'")
            db_execute(c, "ALTER TABLE score_audit_logs ADD COLUMN IF NOT EXISTS change_source TEXT DEFAULT 'manual_entry'")
            db_execute(c, "ALTER TABLE score_audit_logs ADD COLUMN IF NOT EXISTS change_reason TEXT DEFAULT ''")
            db_execute(
                c,
                'CREATE INDEX IF NOT EXISTS idx_score_audit_school_student_changed ON score_audit_logs(school_id, student_id, changed_at)',
            )
            db_execute(
                c,
                'CREATE INDEX IF NOT EXISTS idx_score_audit_school_class_term_year ON score_audit_logs(school_id, classname, term, academic_year)',
            )
        _SCORE_AUDIT_SCHEMA_STATE = True
        return True
    except Exception as exc:
        logging.warning("Score audit schema auto-heal failed: %s", exc)
        _SCORE_AUDIT_SCHEMA_STATE = False
        return False

def get_result_publication_row(school_id, classname, term, academic_year=''):
    ensure_result_publication_approval_columns()
    has_approval_cols = result_publication_has_approval_columns()
    with db_connection() as conn:
        c = conn.cursor()
        if has_approval_cols:
            db_execute(
                c,
                """SELECT school_id, classname, term, COALESCE(academic_year, ''), teacher_id, teacher_name, principal_name,
                          is_published, published_at, COALESCE(approval_status, 'not_submitted'),
                          submitted_at, submitted_by, reviewed_at, reviewed_by, review_note
                   FROM result_publications
                   WHERE school_id = ? AND classname = ? AND term = ? AND COALESCE(academic_year, '') = COALESCE(?, '')
                   LIMIT 1""",
                (school_id, classname, term, academic_year or ''),
            )
        else:
            db_execute(
                c,
                """SELECT school_id, classname, term, COALESCE(academic_year, ''), teacher_id, teacher_name, principal_name,
                          is_published, published_at
                   FROM result_publications
                   WHERE school_id = ? AND classname = ? AND term = ? AND COALESCE(academic_year, '') = COALESCE(?, '')
                   LIMIT 1""",
                (school_id, classname, term, academic_year or ''),
            )
        row = c.fetchone()
    if not row:
        return {}
    if not has_approval_cols:
        return {
            'school_id': row[0] or '',
            'classname': row[1] or '',
            'term': row[2] or '',
            'academic_year': row[3] or '',
            'teacher_id': row[4] or '',
            'teacher_name': row[5] or '',
            'principal_name': row[6] or '',
            'is_published': bool(int(row[7] or 0)),
            'published_at': row[8] or '',
            'approval_status': 'approved' if bool(int(row[7] or 0)) else 'not_submitted',
            'submitted_at': '',
            'submitted_by': '',
            'reviewed_at': '',
            'reviewed_by': '',
            'review_note': '',
        }
    return {
        'school_id': row[0] or '',
        'classname': row[1] or '',
        'term': row[2] or '',
        'academic_year': row[3] or '',
        'teacher_id': row[4] or '',
        'teacher_name': row[5] or '',
        'principal_name': row[6] or '',
        'is_published': bool(int(row[7] or 0)),
        'published_at': row[8] or '',
        'approval_status': (row[9] or 'not_submitted'),
        'submitted_at': row[10] or '',
        'submitted_by': row[11] or '',
        'reviewed_at': row[12] or '',
        'reviewed_by': row[13] or '',
        'review_note': row[14] or '',
    }

def submit_result_approval_request(school_id, classname, term, academic_year, teacher_id):
    ensure_result_publication_approval_columns()
    school = get_school(school_id) or {}
    resolved_principal_name = (school.get('principal_name', '') or '').strip()
    teacher_profile = get_teachers(school_id).get(teacher_id, {})
    resolved_teacher_name = f"{teacher_profile.get('firstname', '')} {teacher_profile.get('lastname', '')}".strip() or str(teacher_id)
    submitted_at = datetime.now().isoformat()
    has_approval_cols = result_publication_has_approval_columns()
    with db_connection(commit=True) as conn:
        c = conn.cursor()
        if has_approval_cols:
            db_execute(
                c,
                """INSERT INTO result_publications
                   (school_id, classname, term, academic_year, teacher_id, teacher_name, principal_name, is_published, published_at,
                    approval_status, submitted_at, submitted_by, reviewed_at, reviewed_by, review_note, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, 0, NULL, 'pending', ?, ?, NULL, NULL, NULL, CURRENT_TIMESTAMP)
                   ON CONFLICT(school_id, classname, term, academic_year) DO UPDATE SET
                     teacher_id = excluded.teacher_id,
                     teacher_name = excluded.teacher_name,
                     principal_name = excluded.principal_name,
                     is_published = 0,
                     published_at = NULL,
                     approval_status = 'pending',
                     submitted_at = excluded.submitted_at,
                     submitted_by = excluded.submitted_by,
                     reviewed_at = NULL,
                     reviewed_by = NULL,
                     review_note = NULL,
                     updated_at = CURRENT_TIMESTAMP""",
                (
                    school_id,
                    classname,
                    term,
                    academic_year or '',
                    teacher_id,
                    resolved_teacher_name,
                    resolved_principal_name,
                    submitted_at,
                    teacher_id,
                ),
            )
        else:
            db_execute(
                c,
                """INSERT INTO result_publications
                   (school_id, classname, term, academic_year, teacher_id, teacher_name, principal_name, is_published, published_at, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, 0, NULL, CURRENT_TIMESTAMP)
                   ON CONFLICT(school_id, classname, term, academic_year) DO UPDATE SET
                     teacher_id = excluded.teacher_id,
                     teacher_name = excluded.teacher_name,
                     principal_name = excluded.principal_name,
                     is_published = 0,
                     published_at = NULL,
                     updated_at = CURRENT_TIMESTAMP""",
                (school_id, classname, term, academic_year or '', teacher_id, resolved_teacher_name, resolved_principal_name),
            )

def publish_results_for_class_atomic(school_id, classname, term, teacher_id, academic_year='', reviewed_by='', review_note='', attendance_gate=None):
    """Publish class results in a single transaction (snapshot + publish flag)."""
    ensure_result_publication_approval_columns()
    has_approval_cols = result_publication_has_approval_columns()
    school = get_school(school_id) or {}
    publish_year = (academic_year or school.get('academic_year', '') or '').strip()
    grade_cfg = get_grade_config(school_id)
    principal_name = (school.get('principal_name', '') or '').strip()
    teacher_profile = get_teachers(school_id).get(teacher_id, {})
    teacher_name = f"{teacher_profile.get('firstname', '')} {teacher_profile.get('lastname', '')}".strip() or str(teacher_id)
    class_students = load_students(school_id, class_filter=classname, term_filter=term)
    attendance_gate = attendance_gate if isinstance(attendance_gate, dict) else get_class_attendance_publish_readiness(
        school_id=school_id,
        classname=classname,
        term=term,
        academic_year=publish_year,
        class_students_data=class_students,
    )
    if not attendance_gate.get('ready', False):
        msg = (attendance_gate.get('message') or '').strip()
        if not msg:
            rows = attendance_gate.get('missing_rows', []) or []
            sample = ', '.join(
                f"{r.get('student_name', r.get('student_id', ''))} ({int(r.get('marked_days', 0))}/{int(r.get('expected_days', attendance_gate.get('days_open', 0)) or 0)})"
                for r in rows[:6]
            )
            msg = (
                f'Attendance is incomplete for {classname} ({term}). '
                'Each student must have attendance marked for all expected instructional days. '
                f'Missing: {sample}'
                + ('...' if len(rows) > 6 else '')
            )
        raise ValueError(msg)

    with db_connection(commit=True) as conn:
        c = conn.cursor()
        behaviour_by_student = get_class_behaviour_assessments(school_id, classname, term, publish_year)
        for sid, student in class_students.items():
            scores = student.get('scores', {}) if isinstance(student.get('scores', {}), dict) else {}
            behaviour_payload = behaviour_by_student.get(sid, _default_behaviour_assessment())
            average_marks = compute_average_marks_from_scores(scores, subjects=student.get('subjects', []))
            grade = grade_from_score(average_marks, grade_cfg)
            status = status_from_score(average_marks, grade_cfg)
            principal_comment = (student.get('principal_comment') or '').strip()
            db_execute(
                c,
                """INSERT INTO published_student_results
                   (school_id, student_id, firstname, classname, academic_year, term, stream, number_of_subject, subjects, scores, behaviour_json, teacher_comment, principal_comment, average_marks, grade, status, published_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                   ON CONFLICT(school_id, student_id, academic_year, term) DO UPDATE SET
                     firstname = excluded.firstname,
                     classname = excluded.classname,
                     academic_year = excluded.academic_year,
                     stream = excluded.stream,
                     number_of_subject = excluded.number_of_subject,
                     subjects = excluded.subjects,
                     scores = excluded.scores,
                     behaviour_json = excluded.behaviour_json,
                     teacher_comment = excluded.teacher_comment,
                     principal_comment = excluded.principal_comment,
                     average_marks = excluded.average_marks,
                     grade = excluded.grade,
                     status = excluded.status,
                     published_at = excluded.published_at""",
                (
                    school_id,
                    sid,
                    student.get('firstname', ''),
                    classname,
                    publish_year,
                    term,
                    student.get('stream', 'N/A'),
                    int(student.get('number_of_subject', 0) or 0),
                    json.dumps(student.get('subjects', [])),
                    json.dumps(scores),
                    json.dumps(behaviour_payload),
                    (student.get('teacher_comment') or '').strip(),
                    principal_comment,
                    float(average_marks),
                    grade,
                    status,
                    datetime.now().isoformat(),
                ),
            )

        if has_approval_cols:
            db_execute(
                c,
                """INSERT INTO result_publications
                   (school_id, classname, term, academic_year, teacher_id, teacher_name, principal_name, is_published, published_at,
                    approval_status, reviewed_at, reviewed_by, review_note, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'approved', ?, ?, ?, CURRENT_TIMESTAMP)
                   ON CONFLICT(school_id, classname, term, academic_year) DO UPDATE SET
                     teacher_id = excluded.teacher_id,
                     teacher_name = excluded.teacher_name,
                     principal_name = excluded.principal_name,
                     is_published = excluded.is_published,
                     published_at = excluded.published_at,
                     approval_status = 'approved',
                     reviewed_at = excluded.reviewed_at,
                     reviewed_by = excluded.reviewed_by,
                     review_note = excluded.review_note,
                     updated_at = CURRENT_TIMESTAMP""",
                (
                    school_id,
                    classname,
                    term,
                    publish_year,
                    teacher_id,
                    teacher_name,
                    principal_name,
                    1,
                    datetime.now().isoformat(),
                    datetime.now().isoformat(),
                    reviewed_by or None,
                    (review_note or '').strip() or None,
                ),
            )
        else:
            db_execute(
                c,
                """INSERT INTO result_publications
                   (school_id, classname, term, academic_year, teacher_id, teacher_name, principal_name, is_published, published_at, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                   ON CONFLICT(school_id, classname, term, academic_year) DO UPDATE SET
                     teacher_id = excluded.teacher_id,
                     teacher_name = excluded.teacher_name,
                     principal_name = excluded.principal_name,
                     is_published = excluded.is_published,
                     published_at = excluded.published_at,
                     updated_at = CURRENT_TIMESTAMP""",
                (
                    school_id,
                    classname,
                    term,
                    publish_year,
                    teacher_id,
                    teacher_name,
                    principal_name,
                    1,
                    datetime.now().isoformat(),
                ),
            )
        try:
            db_execute(
                c,
                """INSERT INTO term_edit_locks
                   (school_id, classname, term, academic_year, is_locked, unlocked_until, unlock_reason, unlocked_by, updated_at)
                   VALUES (?, ?, ?, ?, 1, NULL, '', ?, CURRENT_TIMESTAMP)
                   ON CONFLICT(school_id, classname, term, academic_year) DO UPDATE SET
                     is_locked = 1,
                     unlocked_until = NULL,
                     updated_at = CURRENT_TIMESTAMP""",
                (school_id, classname, term, publish_year, reviewed_by or teacher_id or ''),
            )
        except Exception as exc:
            logging.warning("Failed to enforce term edit lock on publish: %s", exc)

def review_result_approval_request(school_id, classname, term, academic_year, admin_user_id, approve, review_note=''):
    ensure_result_publication_approval_columns()
    clean_note = (review_note or '').strip()
    try:
        row = get_result_publication_row(school_id, classname, term, academic_year)
    except Exception as exc:
        logging.exception(
            "Failed to load publication row for approval review. school_id=%s class=%s term=%s year=%s",
            school_id,
            classname,
            term,
            academic_year,
        )
        return False, f'Failed to load submission for review: {exc}'
    if not row:
        return False, 'No submission found for this class.'
    if row.get('approval_status') != 'pending':
        if row.get('is_published'):
            return False, 'This class is already published.'
        return False, 'Only pending submissions can be reviewed.'

    if approve:
        school = get_school(school_id) or {}
        try:
            gate = get_class_attendance_publish_readiness(
                school_id=school_id,
                classname=classname,
                term=term,
                academic_year=(academic_year or (school.get('academic_year', '') or '')),
            )
        except Exception as exc:
            logging.exception(
                "Attendance readiness check failed during approval. school_id=%s class=%s term=%s year=%s",
                school_id,
                classname,
                term,
                academic_year,
            )
            return False, f'Attendance readiness check failed: {exc}'
        if not gate.get('ready', False):
            msg = (gate.get('message') or '').strip()
            if not msg:
                rows = gate.get('missing_rows', []) or []
                sample = ', '.join(
                    f"{r.get('student_name', r.get('student_id', ''))} ({int(r.get('marked_days', 0))}/{int(r.get('expected_days', gate.get('days_open', 0)) or 0)})"
                    for r in rows[:6]
                )
                msg = (
                    f'Cannot approve publish for {classname} ({term}) because attendance is incomplete. '
                    f'Missing: {sample}'
                    + ('...' if len(rows) > 6 else '')
                )
            return False, msg
        try:
            publish_results_for_class_atomic(
                school_id=school_id,
                classname=classname,
                term=term,
                teacher_id=row.get('teacher_id', ''),
                academic_year=(academic_year or ''),
                reviewed_by=admin_user_id,
                review_note=clean_note,
                attendance_gate=gate,
            )
        except Exception as exc:
            if _is_transient_db_transport_error(exc):
                raise
            return False, f'Failed to publish: {exc}'
        return True, 'Results approved and published.'

    if not result_publication_has_approval_columns():
        return False, 'Approval columns are missing. Run migration and retry.'
    if not clean_note:
        return False, 'Rejection reason is required.'

    with db_connection(commit=True) as conn:
        c = conn.cursor()
        db_execute(
            c,
            """UPDATE result_publications
               SET is_published = 0,
                   published_at = NULL,
                   approval_status = 'rejected',
                   reviewed_at = ?,
                   reviewed_by = ?,
                   review_note = ?,
                   updated_at = CURRENT_TIMESTAMP
               WHERE school_id = ? AND classname = ? AND term = ? AND COALESCE(academic_year, '') = COALESCE(?, '')""",
            (
                datetime.now().isoformat(),
                admin_user_id,
                clean_note or None,
                school_id,
                classname,
                term,
                academic_year or '',
            ),
        )
    return True, 'Submission rejected. Teacher can update and resubmit.'

def get_published_terms_for_student(school_id, student_id, classname=''):
    with db_connection() as conn:
        c = conn.cursor()
        if classname:
            db_execute(
                c,
                """SELECT academic_year, term, classname, published_at FROM published_student_results
                   WHERE school_id = ? AND student_id = ? AND LOWER(classname) = LOWER(?)
                   ORDER BY published_at ASC""",
                (school_id, student_id, classname),
            )
        else:
            db_execute(
                c,
                """SELECT academic_year, term, classname, published_at FROM published_student_results
                   WHERE school_id = ? AND student_id = ?
                   ORDER BY published_at ASC""",
                (school_id, student_id),
            )
        rows = c.fetchall()
    terms = []
    seen = set()
    for row in rows:
        academic_year = row[0] or ''
        term = row[1] or ''
        row_classname = row[2] or ''
        token = _term_token(academic_year, term)
        seen_key = (token, (row_classname or '').strip().lower())
        if seen_key in seen:
            continue
        seen.add(seen_key)
        label = f"{term} ({academic_year})" if academic_year else term
        terms.append({
            'academic_year': academic_year,
            'term': term,
            'classname': row_classname,
            'token': token,
            'label': label,
        })
    return terms

def get_published_overview_for_students(school_id, student_ids):
    return parent_queries_service.get_published_overview_for_students(
        db_connection=db_connection,
        db_execute=db_execute,
        term_token_builder=_term_token,
        school_id=school_id,
        student_ids=student_ids,
    )

def load_published_student_result(school_id, student_id, term, academic_year='', classname=''):
    with db_connection() as conn:
        c = conn.cursor()
        if academic_year and classname:
            db_execute(
                c,
                """SELECT firstname, classname, academic_year, term, stream, number_of_subject, subjects, scores, behaviour_json, teacher_comment, principal_comment, average_marks, grade, status
                   FROM published_student_results
                   WHERE school_id = ? AND student_id = ? AND term = ? AND COALESCE(academic_year, '') = ? AND LOWER(classname) = LOWER(?)
                   ORDER BY published_at DESC
                   LIMIT 1""",
                (school_id, student_id, term, academic_year, classname),
            )
        elif academic_year:
            db_execute(
                c,
                """SELECT firstname, classname, academic_year, term, stream, number_of_subject, subjects, scores, behaviour_json, teacher_comment, principal_comment, average_marks, grade, status
                   FROM published_student_results
                   WHERE school_id = ? AND student_id = ? AND term = ? AND COALESCE(academic_year, '') = ?
                   ORDER BY published_at DESC
                   LIMIT 1""",
                (school_id, student_id, term, academic_year),
            )
        elif classname:
            db_execute(
                c,
                """SELECT firstname, classname, academic_year, term, stream, number_of_subject, subjects, scores, behaviour_json, teacher_comment, principal_comment, average_marks, grade, status
                   FROM published_student_results
                   WHERE school_id = ? AND student_id = ? AND term = ? AND LOWER(classname) = LOWER(?)
                   ORDER BY published_at DESC
                   LIMIT 1""",
                (school_id, student_id, term, classname),
            )
        else:
            db_execute(
                c,
                """SELECT firstname, classname, academic_year, term, stream, number_of_subject, subjects, scores, behaviour_json, teacher_comment, principal_comment, average_marks, grade, status
                   FROM published_student_results
                   WHERE school_id = ? AND student_id = ? AND term = ?
                   ORDER BY published_at DESC
                   LIMIT 1""",
                (school_id, student_id, term),
            )
        row = c.fetchone()
    if not row:
        return None
    row = list(row)
    behaviour_raw = '{}'
    teacher_comment = ''
    principal_comment = ''
    average_marks_raw = 0
    grade_value = 'F'
    status_value = 'Fail'
    # Backward-compatible row parsing for legacy/mocked tuples.
    if len(row) >= 14:
        behaviour_raw = row[8] if row[8] else '{}'
        teacher_comment = row[9] or ''
        principal_comment = row[10] or ''
        average_marks_raw = row[11]
        grade_value = row[12]
        status_value = row[13]
    elif len(row) >= 12:
        behaviour_raw = '{}'
        teacher_comment = row[8] or ''
        principal_comment = ''
        average_marks_raw = row[9]
        grade_value = row[10]
        status_value = row[11]
    elif len(row) >= 10:
        behaviour_raw = '{}'
        teacher_comment = row[8] or ''
        principal_comment = ''
        average_marks_raw = row[9]
    try:
        average_marks_val = float(average_marks_raw or 0)
    except (TypeError, ValueError):
        average_marks_val = 0.0
    snapshot = {
        'firstname': row[0],
        'classname': row[1],
        'academic_year': row[2] or '',
        'term': row[3],
        'stream': row[4],
        'number_of_subject': row[5],
        'subjects': json.loads(row[6]) if row[6] else [],
        'scores': json.loads(row[7]) if row[7] else {},
        'behaviour_assessment': normalize_behaviour_assessment(_safe_json_object(behaviour_raw)),
        'teacher_comment': teacher_comment,
        'principal_comment': principal_comment,
        'average_marks': average_marks_val,
        'Grade': grade_value,
        'Status': status_value,
    }

    # if third-term and the school wants combined results, merge earlier terms
    school = get_school(school_id) or {}
    if (term or '').strip().lower() == 'third term' and bool(school.get('combine_third_term_results')):
        extras = []
        for t in ('First Term', 'Second Term'):
            other = load_published_student_result(school_id, student_id, t, academic_year, classname)
            if other:
                extras.append(other)
        if extras:
            snaps = extras + [snapshot]
            return _combine_student_snapshots(snaps, school_id)
    return snapshot

def load_published_class_results(school_id, classname, term, academic_year='', school=None):
    # possible combination of three terms for final result
    school = school or get_school(school_id) or {}
    combine_flag = bool(school.get('combine_third_term_results'))
    with db_connection() as conn:
        c = conn.cursor()
        if combine_flag and (term or '').strip().lower() == 'third term':
            # fetch all three terms at once so we can merge per student
            if academic_year:
                db_execute(
                    c,
                    """SELECT student_id, classname, stream, average_marks, subjects, scores, term
                       FROM published_student_results
                       WHERE school_id = ? AND term IN ('First Term','Second Term','Third Term') AND COALESCE(academic_year, '') = ?""",
                    (school_id, academic_year),
                )
            else:
                db_execute(
                    c,
                    """SELECT student_id, classname, stream, average_marks, subjects, scores, term
                       FROM published_student_results
                       WHERE school_id = ? AND term IN ('First Term','Second Term','Third Term')""",
                    (school_id,),
                )
        else:
            # normal single‑term query (also include term column for consistency)
            if academic_year:
                db_execute(
                    c,
                    """SELECT student_id, classname, stream, average_marks, subjects, scores, term
                       FROM published_student_results
                       WHERE school_id = ? AND term = ? AND COALESCE(academic_year, '') = ?""",
                    (school_id, term, academic_year),
                )
            else:
                db_execute(
                    c,
                    """SELECT student_id, classname, stream, average_marks, subjects, scores, term
                       FROM published_student_results
                       WHERE school_id = ? AND term = ?""",
                    (school_id, term),
                )
        rows = c.fetchall()
    class_arm_mode = ((school or {}).get('class_arm_ranking_mode') or 'separate').strip().lower()
    if class_arm_mode not in {'separate', 'together'}:
        class_arm_mode = 'separate'
    target_group = class_arm_ranking_group(classname, class_arm_mode)

    # if we fetched multiple terms we need to collapse them per student
    if combine_flag and (term or '').strip().lower() == 'third term':
        by_student = {}
        for row in rows:
            sid = row[0]
            by_student.setdefault(sid, []).append(row)
        combined = []
        for sid, group in by_student.items():
            # Use third-term row as base when available, else newest by known term order.
            sorted_group = sorted(group, key=lambda r: term_sort_value(r[6]))
            base_row = sorted_group[-1]
            subjects_union = set()
            score_lists = []
            mark_values = []
            for r in sorted_group:
                subs = json.loads(r[4]) if r[4] else []
                subjects_union.update(subs)
                scores = json.loads(r[5]) if r[5] else {}
                score_lists.append(scores)
                mark_values.append(float(r[3] or 0))
            combined_scores = {}
            for subj in subjects_union:
                marks = []
                for scores in score_lists:
                    ss = scores.get(subj)
                    if isinstance(ss, dict):
                        marks.append(subject_overall_mark(ss))
                avg_mark = sum(marks) / len(marks) if marks else 0.0
                combined_scores[subj] = {'overall_mark': avg_mark}
            # Combined-third-term ranking policy: mean of First/Second/Third term averages.
            avg_marks = (sum(mark_values) / len(mark_values)) if mark_values else 0.0
            grade_cfg = get_grade_config(school_id)
            combined_grade = grade_from_score(avg_marks, grade_cfg)
            combined_status = status_from_score(avg_marks, grade_cfg)
            combined.append({
                'student_id': sid,
                'classname': base_row[1],
                'stream': base_row[2],
                'average_marks': avg_marks,
                'subjects': sorted(subjects_union),
                'scores': combined_scores,
            })
        # filter by target group
        out = []
        for item in combined:
            if class_arm_ranking_group(item['classname'], class_arm_mode) == target_group:
                out.append(item)
        return out
    # normal single term output
    out = []
    for row in rows:
        row_class = row[1]
        if class_arm_ranking_group(row_class, class_arm_mode) != target_group:
            continue
        out.append({
            'student_id': row[0],
            'classname': row_class,
            'stream': row[2],
            'average_marks': float(row[3] or 0),
            'subjects': json.loads(row[4]) if row[4] else [],
            'scores': json.loads(row[5]) if row[5] else {},
        })
    return out

def get_published_students_for_class(school_id, classname, term, academic_year=''):
    """List published students for one class and term."""
    if not school_id or not classname or not term:
        return []
    with db_connection() as conn:
        c = conn.cursor()
        db_execute(
            c,
            """SELECT student_id, firstname, classname, term, COALESCE(academic_year, ''),
                      average_marks, grade, status, published_at
               FROM published_student_results
               WHERE school_id = ? AND LOWER(classname) = LOWER(?) AND term = ?
                 AND COALESCE(academic_year, '') = COALESCE(?, '')
               ORDER BY firstname ASC, student_id ASC""",
            (school_id, classname, term, academic_year or ''),
        )
        rows = c.fetchall()
    out = []
    for row in rows or []:
        out.append({
            'student_id': row[0] or '',
            'firstname': row[1] or '',
            'classname': row[2] or '',
            'term': row[3] or '',
            'academic_year': row[4] or '',
            'average_marks': float(row[5] or 0),
            'grade': row[6] or '',
            'status': row[7] or '',
            'published_at': row[8] or '',
        })
    return out

def record_result_view(school_id, student_id, term, academic_year=''):
    """Mark a published result as viewed by student."""
    if not school_id or not student_id or not term:
        return
    academic_year = academic_year or ''
    now_ts = datetime.now().isoformat()
    with db_connection(commit=True) as conn:
        c = conn.cursor()
        db_execute(
            c,
            """INSERT INTO result_views
               (school_id, student_id, term, academic_year, first_viewed_at, last_viewed_at, view_count)
               VALUES (?, ?, ?, ?, ?, ?, 1)
               ON CONFLICT(school_id, student_id, term, academic_year) DO UPDATE SET
                 last_viewed_at = excluded.last_viewed_at,
                 view_count = result_views.view_count + 1""",
            (school_id, student_id, term, academic_year, now_ts, now_ts),
        )

def get_class_published_view_counts(school_id, term, academic_year='', classnames=None):
    """Return {classname: {published_count, viewed_count}} for one term."""
    classnames = [c for c in (classnames or []) if c]
    where_clause = ''
    params = [school_id, term, academic_year or '']
    if classnames:
        placeholders = ','.join(['?'] * len(classnames))
        where_clause = f' AND psr.classname IN ({placeholders})'
        params.extend(classnames)

    with db_connection() as conn:
        c = conn.cursor()
        db_execute(
            c,
            f"""SELECT psr.classname,
                       COUNT(DISTINCT psr.student_id) AS published_count,
                       COUNT(DISTINCT CASE WHEN rv.student_id IS NOT NULL THEN psr.student_id END) AS viewed_count
                FROM published_student_results psr
                LEFT JOIN result_views rv
                  ON rv.school_id = psr.school_id
                 AND rv.student_id = psr.student_id
                 AND rv.term = psr.term
                 AND COALESCE(rv.academic_year, '') = COALESCE(psr.academic_year, '')
                WHERE psr.school_id = ? AND psr.term = ?
                  AND COALESCE(psr.academic_year, '') = COALESCE(?, '')
                  {where_clause}
                GROUP BY psr.classname""",
            tuple(params),
        )
        rows = c.fetchall()
    return {
        row[0]: {
            'published_count': int(row[1] or 0),
            'viewed_count': int(row[2] or 0),
        }
        for row in rows
    }

def get_viewed_student_ids_for_classes(school_id, classnames, term, academic_year=''):
    """Return student IDs viewed at least once for the class list in a term."""
    classnames = [c for c in (classnames or []) if c]
    if not classnames:
        return set()
    placeholders = ','.join(['?'] * len(classnames))
    params = [school_id, term, academic_year or '']
    params.extend(classnames)
    with db_connection() as conn:
        c = conn.cursor()
        db_execute(
            c,
            f"""SELECT DISTINCT psr.student_id
                FROM published_student_results psr
                JOIN result_views rv
                  ON rv.school_id = psr.school_id
                 AND rv.student_id = psr.student_id
                 AND rv.term = psr.term
                 AND COALESCE(rv.academic_year, '') = COALESCE(psr.academic_year, '')
                WHERE psr.school_id = ? AND psr.term = ?
                  AND COALESCE(psr.academic_year, '') = COALESCE(?, '')
                  AND psr.classname IN ({placeholders})""",
            tuple(params),
        )
        return {row[0] for row in c.fetchall() if row and row[0]}

def get_school_publication_statuses(school_id, term, academic_year='', assignments=None):
    """Get class publication/view status for school admin dashboard."""
    ensure_result_publication_approval_columns()
    has_approval_cols = result_publication_has_approval_columns()
    source_assignments = assignments if assignments is not None else get_class_assignments(school_id)
    assignments = [
        a for a in source_assignments
        if (a.get('term') or '') == term and (a.get('academic_year') or '') == (academic_year or '')
    ]
    classes = [a.get('classname', '') for a in assignments if a.get('classname')]

    publication_rows = {}
    with db_connection() as conn:
        c = conn.cursor()
        if has_approval_cols:
            db_execute(
                c,
                """SELECT classname, teacher_id, teacher_name, is_published, published_at,
                          COALESCE(approval_status, 'not_submitted'),
                          submitted_at, submitted_by, reviewed_at, reviewed_by, review_note
                   FROM result_publications
                   WHERE school_id = ? AND term = ? AND COALESCE(academic_year, '') = COALESCE(?, '')""",
                (school_id, term, academic_year or ''),
            )
            for row in c.fetchall():
                publication_rows[row[0]] = {
                    'teacher_id': row[1],
                    'teacher_name': row[2] or '',
                    'is_published': bool(int(row[3] or 0)),
                    'published_at': row[4] or '',
                    'approval_status': row[5] or 'not_submitted',
                    'submitted_at': row[6] or '',
                    'submitted_by': row[7] or '',
                    'reviewed_at': row[8] or '',
                    'reviewed_by': row[9] or '',
                    'review_note': row[10] or '',
                }
        else:
            db_execute(
                c,
                """SELECT classname, teacher_id, teacher_name, is_published, published_at
                   FROM result_publications
                   WHERE school_id = ? AND term = ? AND COALESCE(academic_year, '') = COALESCE(?, '')""",
                (school_id, term, academic_year or ''),
            )
            for row in c.fetchall():
                publication_rows[row[0]] = {
                    'teacher_id': row[1],
                    'teacher_name': row[2] or '',
                    'is_published': bool(int(row[3] or 0)),
                    'published_at': row[4] or '',
                    'approval_status': 'approved' if bool(int(row[3] or 0)) else 'not_submitted',
                    'submitted_at': '',
                    'submitted_by': '',
                    'reviewed_at': '',
                    'reviewed_by': '',
                    'review_note': '',
                }
    all_classes = sorted(
        {c for c in classes if c} | {c for c in publication_rows.keys() if c},
        key=lambda value: str(value).lower(),
    )
    counts_by_class = get_class_published_view_counts(school_id, term, academic_year, all_classes)

    out = []
    seen_classes = set()
    for a in assignments:
        classname = a.get('classname', '')
        pub = publication_rows.get(classname, {})
        cnt = counts_by_class.get(classname, {})
        lock_status = get_term_edit_lock_status(school_id, classname, term, academic_year or '')
        seen_classes.add(classname)
        out.append({
            'classname': classname,
            'teacher_name': a.get('teacher_name', '') or pub.get('teacher_name', ''),
            'teacher_id': a.get('teacher_id', ''),
            'term': term,
            'academic_year': academic_year or '',
            'is_published': bool(pub.get('is_published', False)),
            'published_at': pub.get('published_at', ''),
            'approval_status': pub.get('approval_status', 'not_submitted'),
            'submitted_at': pub.get('submitted_at', ''),
            'submitted_by': pub.get('submitted_by', ''),
            'reviewed_at': pub.get('reviewed_at', ''),
            'reviewed_by': pub.get('reviewed_by', ''),
            'review_note': pub.get('review_note', ''),
            'published_count': int(cnt.get('published_count', 0)),
            'viewed_count': int(cnt.get('viewed_count', 0)),
            'term_locked': bool(lock_status.get('locked', False)),
            'term_unlock_reason': lock_status.get('reason', ''),
            'term_unlocked_until': lock_status.get('unlocked_until'),
        })
    for classname, pub in publication_rows.items():
        if not classname or classname in seen_classes:
            continue
        cnt = counts_by_class.get(classname, {})
        lock_status = get_term_edit_lock_status(school_id, classname, term, academic_year or '')
        out.append({
            'classname': classname,
            'teacher_name': pub.get('teacher_name', ''),
            'teacher_id': pub.get('teacher_id', ''),
            'term': term,
            'academic_year': academic_year or '',
            'is_published': bool(pub.get('is_published', False)),
            'published_at': pub.get('published_at', ''),
            'approval_status': pub.get('approval_status', 'not_submitted'),
            'submitted_at': pub.get('submitted_at', ''),
            'submitted_by': pub.get('submitted_by', ''),
            'reviewed_at': pub.get('reviewed_at', ''),
            'reviewed_by': pub.get('reviewed_by', ''),
            'review_note': pub.get('review_note', ''),
            'published_count': int(cnt.get('published_count', 0)),
            'viewed_count': int(cnt.get('viewed_count', 0)),
            'term_locked': bool(lock_status.get('locked', False)),
            'term_unlock_reason': lock_status.get('reason', ''),
            'term_unlocked_until': lock_status.get('unlocked_until'),
        })
    out.sort(key=lambda x: (x.get('classname', ''), x.get('teacher_name', '')))
    return out

def get_publication_rows_for_classes(school_id, term, academic_year, classnames):
    """Bulk-fetch publication metadata for class list (avoids N+1 lookups)."""
    classes = [c for c in (classnames or []) if c]
    if not classes:
        return {}
    ensure_result_publication_approval_columns()
    has_approval_cols = result_publication_has_approval_columns()
    placeholders = ', '.join('?' for _ in classes)
    params = [school_id, term, academic_year or '']
    params.extend(classes)
    out = {}
    with db_connection() as conn:
        c = conn.cursor()
        if has_approval_cols:
            db_execute(
                c,
                f"""SELECT classname, teacher_id, teacher_name, principal_name, is_published, published_at,
                           COALESCE(approval_status, 'not_submitted'),
                           submitted_at, submitted_by, reviewed_at, reviewed_by, review_note
                    FROM result_publications
                    WHERE school_id = ? AND term = ? AND COALESCE(academic_year, '') = COALESCE(?, '')
                      AND classname IN ({placeholders})""",
                tuple(params),
            )
            for row in c.fetchall():
                out[row[0]] = {
                    'classname': row[0] or '',
                    'teacher_id': row[1] or '',
                    'teacher_name': row[2] or '',
                    'principal_name': row[3] or '',
                    'is_published': bool(int(row[4] or 0)),
                    'published_at': row[5] or '',
                    'approval_status': row[6] or 'not_submitted',
                    'submitted_at': row[7] or '',
                    'submitted_by': row[8] or '',
                    'reviewed_at': row[9] or '',
                    'reviewed_by': row[10] or '',
                    'review_note': row[11] or '',
                }
        else:
            db_execute(
                c,
                f"""SELECT classname, teacher_id, teacher_name, principal_name, is_published, published_at
                    FROM result_publications
                    WHERE school_id = ? AND term = ? AND COALESCE(academic_year, '') = COALESCE(?, '')
                      AND classname IN ({placeholders})""",
                tuple(params),
            )
            for row in c.fetchall():
                out[row[0]] = {
                    'classname': row[0] or '',
                    'teacher_id': row[1] or '',
                    'teacher_name': row[2] or '',
                    'principal_name': row[3] or '',
                    'is_published': bool(int(row[4] or 0)),
                    'published_at': row[5] or '',
                    'approval_status': 'approved' if bool(int(row[4] or 0)) else 'not_submitted',
                    'submitted_at': '',
                    'submitted_by': '',
                    'reviewed_at': '',
                    'reviewed_by': '',
                    'review_note': '',
                }
    return out

def build_subject_positions_for_student(school_id, student, school):
    """Build subject-by-subject class position for one student."""
    def same_score(a, b):
        return abs(float(a or 0) - float(b or 0)) <= 1e-9

    classname = student.get('classname', '')
    term = student.get('term', '')
    student_id = student.get('student_id', '')
    subjects = student.get('subjects', []) if isinstance(student.get('subjects', []), list) else []
    if not classname or not term or not student_id or not subjects:
        return {}

    peers = load_students(school_id, class_filter=classname, term_filter=term)
    peer_items = list(peers.items())
    if school.get('ss_ranking_mode') == 'separate' and class_uses_stream_for_school(school, classname):
        student_stream = (student.get('stream') or '').strip()
        peer_items = [(sid, s) for sid, s in peer_items if (s.get('stream') or '').strip() == student_stream]

    subject_positions = {}
    for subject in subjects:
        ranked = []
        for sid, pdata in peer_items:
            pscores = pdata.get('scores', {}) if isinstance(pdata.get('scores', {}), dict) else {}
            subj_score = pscores.get(subject, {}) if isinstance(pscores.get(subject, {}), dict) else {}
            mark = subject_overall_mark(subj_score)
            ranked.append((sid, float(mark)))
        ranked.sort(key=lambda x: x[1], reverse=True)
        size = len(ranked)
        pos = None
        prev_score = None
        current_pos = 0
        for idx, (sid, score) in enumerate(ranked, 1):
            if prev_score is None or not same_score(score, prev_score):
                current_pos = idx
            if sid == student_id:
                pos = current_pos
                break
            prev_score = score
        if pos is not None:
            subject_positions[subject] = {'pos': pos, 'size': size}
    return subject_positions

def build_positions_from_published_results(school, classname, term, class_results, student_id, student_stream, subjects):
    """Compute overall and per-subject positions from published class result rows."""
    def same_score(a, b):
        return abs(float(a or 0) - float(b or 0)) <= 1e-9

    def pretty_stream_name(raw_stream):
        stream = (raw_stream or '').strip()
        if not stream or stream.upper() in {'N/A', 'NA', '-'}:
            return 'Unassigned'
        if stream.isupper() and len(stream) <= 5:
            return stream
        return stream[:1].upper() + stream[1:].lower()

    separate_stream_ranking = bool(
        school.get('ss_ranking_mode') == 'separate' and class_uses_stream_for_school(school, classname)
    )
    results_for_rank = list(class_results or [])
    if separate_stream_ranking:
        stream_key = (student_stream or '').strip()
        results_for_rank = [x for x in results_for_rank if (x.get('stream') or '').strip() == stream_key]

    ranking_students = [{
        'student_id': x.get('student_id', ''),
        'class_name': classname,
        'term': term,
        'stream': x.get('stream', ''),
        'average_marks': x.get('average_marks', 0),
    } for x in results_for_rank]
    positions = calculate_positions(ranking_students, school.get('ss_ranking_mode', 'together'), school=school)
    position = positions.get(student_id)
    if position:
        position = dict(position)
        position['is_stream_separate'] = separate_stream_ranking
        position['stream_label'] = pretty_stream_name(position.get('stream') or student_stream)

    subject_positions = {}
    for subject in subjects or []:
        ranked = []
        for x in results_for_rank:
            scores_map = x.get('scores', {})
            if not isinstance(scores_map, dict) or subject not in scores_map:
                continue
            sdata = scores_map.get(subject, {})
            if not isinstance(sdata, dict):
                continue
            mark = subject_overall_mark(sdata)
            ranked.append((x.get('student_id', ''), float(mark)))
        ranked.sort(key=lambda k: k[1], reverse=True)
        size = len(ranked)
        highest = ranked[0][1] if ranked else None
        lowest = ranked[-1][1] if ranked else None
        prev_score = None
        current_pos = 0
        for idx, (sid, score) in enumerate(ranked, 1):
            if prev_score is None or not same_score(score, prev_score):
                current_pos = idx
            if sid == student_id:
                subject_positions[subject] = {
                    'pos': current_pos,
                    'size': size,
                    'highest': highest,
                    'lowest': lowest,
                }
                break
            prev_score = score
    return position, subject_positions

# ==================== STUDENT FUNCTIONS ====================

def load_students(school_id, class_filter='', term_filter='', include_archived=False):
    """Load students for a school."""
    has_parent_cols = students_has_parent_access_columns()
    has_archive_cols = students_has_archive_columns()
    with db_connection() as conn:
        c = conn.cursor()
        if has_parent_cols:
            archive_col = ', COALESCE(is_archived, 0)' if has_archive_cols else ''
            query = f'SELECT student_id, firstname, date_of_birth, gender, classname, first_year_class, term, stream, number_of_subject, subjects, scores, promoted, parent_phone, parent_password_hash{archive_col} FROM students WHERE school_id = ?'
        else:
            archive_col = ', COALESCE(is_archived, 0)' if has_archive_cols else ''
            query = f'SELECT student_id, firstname, date_of_birth, gender, classname, first_year_class, term, stream, number_of_subject, subjects, scores, promoted{archive_col} FROM students WHERE school_id = ?'
        params = [school_id]
        
        if class_filter:
            query += ' AND classname = ?'
            params.append(class_filter)
        if term_filter:
            query += ' AND term = ?'
            params.append(term_filter)
        if has_archive_cols and not include_archived:
            query += ' AND COALESCE(is_archived, 0) = 0'
        
        query += ' ORDER BY student_id'
        
        db_execute(c, query, tuple(params))
        students_data = {}
        for row in c.fetchall():
            if has_parent_cols:
                if has_archive_cols:
                    student_id, firstname, date_of_birth, gender, classname, first_year_class, term, stream, number_of_subject, subjects_str, scores_str, promoted, parent_phone, parent_password_hash, is_archived = row
                else:
                    student_id, firstname, date_of_birth, gender, classname, first_year_class, term, stream, number_of_subject, subjects_str, scores_str, promoted, parent_phone, parent_password_hash = row
                    is_archived = 0
            else:
                if has_archive_cols:
                    student_id, firstname, date_of_birth, gender, classname, first_year_class, term, stream, number_of_subject, subjects_str, scores_str, promoted, is_archived = row
                else:
                    student_id, firstname, date_of_birth, gender, classname, first_year_class, term, stream, number_of_subject, subjects_str, scores_str, promoted = row
                    is_archived = 0
                parent_phone, parent_password_hash = '', ''
            subjects = json.loads(subjects_str) if subjects_str else []
            scores = json.loads(scores_str) if scores_str else {}
            students_data[student_id] = {
                'firstname': firstname,
                'date_of_birth': (date_of_birth or '').strip(),
                'gender': (gender or '').strip(),
                'classname': classname,
                'first_year_class': first_year_class,
                'term': term,
                'stream': stream,
                'number_of_subject': number_of_subject,
                'subjects': subjects,
                'scores': scores,
                'promoted': promoted,
                'parent_phone': (parent_phone or '').strip(),
                'parent_password_hash': (parent_password_hash or '').strip(),
                'is_archived': int(is_archived or 0),
            }
        return students_data

def load_students_for_classes(school_id, classnames, term_filter='', include_archived=False):
    """Load students for a school limited to a class list."""
    class_list = [str(c).strip() for c in (classnames or []) if str(c).strip()]
    if not class_list:
        return {}
    has_parent_cols = students_has_parent_access_columns()
    has_archive_cols = students_has_archive_columns()
    with db_connection() as conn:
        c = conn.cursor()
        placeholders = ','.join(['?'] * len(class_list))
        if has_parent_cols:
            archive_col = ', COALESCE(is_archived, 0)' if has_archive_cols else ''
            query = (
                'SELECT student_id, firstname, date_of_birth, gender, classname, first_year_class, term, stream, '
                f'number_of_subject, subjects, scores, promoted, parent_phone, parent_password_hash{archive_col} '
                f'FROM students WHERE school_id = ? AND classname IN ({placeholders})'
            )
        else:
            archive_col = ', COALESCE(is_archived, 0)' if has_archive_cols else ''
            query = (
                'SELECT student_id, firstname, date_of_birth, gender, classname, first_year_class, term, stream, '
                f'number_of_subject, subjects, scores, promoted{archive_col} '
                f'FROM students WHERE school_id = ? AND classname IN ({placeholders})'
            )
        params = [school_id] + class_list
        if term_filter:
            query += ' AND term = ?'
            params.append(term_filter)
        if has_archive_cols and not include_archived:
            query += ' AND COALESCE(is_archived, 0) = 0'
        query += ' ORDER BY student_id'
        db_execute(c, query, tuple(params))
        students_data = {}
        for row in c.fetchall():
            if has_parent_cols:
                if has_archive_cols:
                    student_id, firstname, date_of_birth, gender, classname, first_year_class, term, stream, number_of_subject, subjects_str, scores_str, promoted, parent_phone, parent_password_hash, is_archived = row
                else:
                    student_id, firstname, date_of_birth, gender, classname, first_year_class, term, stream, number_of_subject, subjects_str, scores_str, promoted, parent_phone, parent_password_hash = row
                    is_archived = 0
            else:
                if has_archive_cols:
                    student_id, firstname, date_of_birth, gender, classname, first_year_class, term, stream, number_of_subject, subjects_str, scores_str, promoted, is_archived = row
                else:
                    student_id, firstname, date_of_birth, gender, classname, first_year_class, term, stream, number_of_subject, subjects_str, scores_str, promoted = row
                    is_archived = 0
                parent_phone, parent_password_hash = '', ''
            students_data[student_id] = {
                'firstname': firstname,
                'date_of_birth': (date_of_birth or '').strip(),
                'gender': (gender or '').strip(),
                'classname': classname,
                'first_year_class': first_year_class,
                'term': term,
                'stream': stream,
                'number_of_subject': number_of_subject,
                'subjects': json.loads(subjects_str) if subjects_str else [],
                'scores': json.loads(scores_str) if scores_str else {},
                'promoted': promoted,
                'parent_phone': (parent_phone or '').strip(),
                'parent_password_hash': (parent_password_hash or '').strip(),
                'is_archived': int(is_archived or 0),
            }
        return students_data

def load_students_for_student_ids(school_id, student_ids):
    return parent_queries_service.load_students_for_student_ids(
        db_connection=db_connection,
        db_execute=db_execute,
        students_has_parent_access_columns=students_has_parent_access_columns,
        school_id=school_id,
        student_ids=student_ids,
    )

def get_student_filter_options(school_id, classnames=None):
    """Return (available_classes, available_terms) without loading full student payloads."""
    class_list = [str(c).strip() for c in (classnames or []) if str(c).strip()]
    with db_connection() as conn:
        c = conn.cursor()
        where = ['school_id = ?']
        params = [school_id]
        if class_list:
            placeholders = ','.join(['?'] * len(class_list))
            where.append(f'classname IN ({placeholders})')
            params.extend(class_list)
        where_sql = ' AND '.join(where)

        db_execute(
            c,
            f"""SELECT DISTINCT classname
                FROM students
                WHERE {where_sql}
                  AND classname IS NOT NULL
                  AND classname <> ''
                ORDER BY classname""",
            tuple(params),
        )
        available_classes = [(row[0] or '').strip() for row in c.fetchall() if row and (row[0] or '').strip()]

        db_execute(
            c,
            f"""SELECT DISTINCT term
                FROM students
                WHERE {where_sql}
                  AND term IS NOT NULL
                  AND CHAR_LENGTH(BTRIM(term)) > 0""",
            tuple(params),
        )
        available_terms = sorted(
            {(row[0] or '').strip() for row in c.fetchall() if row and (row[0] or '').strip()},
            key=lambda t: (term_sort_value(t), t),
        )

    return available_classes, available_terms

def load_student(school_id, student_id, include_archived=False):
    """Load a single student."""
    has_parent_cols = students_has_parent_access_columns()
    has_archive_cols = students_has_archive_columns()
    with db_connection() as conn:
        c = conn.cursor()
        if has_parent_cols:
            archived_sql = '' if (include_archived or not has_archive_cols) else ' AND COALESCE(is_archived, 0) = 0'
            archive_col = ', COALESCE(is_archived, 0)' if has_archive_cols else ''
            db_execute(c, f"""SELECT student_id, firstname, date_of_birth, gender, classname, first_year_class, term, stream, 
                           number_of_subject, subjects, scores, promoted, parent_phone, parent_password_hash{archive_col} FROM students 
                           WHERE school_id = ? AND student_id = ?{archived_sql}""",
                       (school_id, student_id))
        else:
            archived_sql = '' if (include_archived or not has_archive_cols) else ' AND COALESCE(is_archived, 0) = 0'
            archive_col = ', COALESCE(is_archived, 0)' if has_archive_cols else ''
            db_execute(c, f"""SELECT student_id, firstname, date_of_birth, gender, classname, first_year_class, term, stream, 
                           number_of_subject, subjects, scores, promoted{archive_col} FROM students 
                           WHERE school_id = ? AND student_id = ?{archived_sql}""",
                       (school_id, student_id))
        row = c.fetchone()
        if not row:
            return None
        parent_phone = (row[12] or '').strip() if has_parent_cols else ''
        parent_password_hash = (row[13] or '').strip() if has_parent_cols else ''
        archived_idx = (14 if has_parent_cols else 12) if has_archive_cols else None
        return {
            'student_id': row[0],
            'firstname': row[1],
            'date_of_birth': (row[2] or '').strip(),
            'gender': (row[3] or '').strip(),
            'classname': row[4],
            'first_year_class': row[5],
            'term': row[6],
            'stream': row[7],
            'number_of_subject': row[8],
            'subjects': json.loads(row[9]) if row[9] else [],
            'scores': json.loads(row[10]) if row[10] else {},
            'promoted': row[11],
            'parent_phone': parent_phone,
            'parent_password_hash': parent_password_hash,
            'is_archived': int(row[archived_idx] or 0) if archived_idx is not None else 0,
        }

def find_student_school_id(student_id):
    """Resolve school_id for a student ID only when unique across schools."""
    with db_connection() as conn:
        c = conn.cursor()
        db_execute(
            c,
            """SELECT DISTINCT school_id FROM students
               WHERE LOWER(student_id) = LOWER(?)
               ORDER BY school_id
               LIMIT 3""",
            (student_id,)
        )
        rows = c.fetchall() or []
        school_ids = [str(r[0]).strip() for r in rows if r and r[0] is not None and str(r[0]).strip()]
        if len(school_ids) == 1:
            return school_ids[0]
        if len(school_ids) > 1:
            logging.warning("Ambiguous student_id '%s' found in multiple schools.", (student_id or '').strip())
        return None


def get_parent_students_by_phone(parent_phone):
    """Return student rows linked to one parent phone."""
    if not students_has_parent_access_columns():
        return []
    normalized_phone = normalize_parent_phone(parent_phone)
    if not normalized_phone:
        return []
    with db_connection() as conn:
        c = conn.cursor()
        db_execute(
            c,
            """SELECT school_id, student_id, firstname, classname, term, stream, parent_password_hash
               FROM students
               WHERE parent_phone = ?
               ORDER BY school_id, classname, firstname, student_id""",
            (normalized_phone,),
        )
        rows = c.fetchall()
    out = []
    for row in rows:
        out.append({
            'school_id': row[0] or '',
            'student_id': row[1] or '',
            'firstname': row[2] or '',
            'classname': row[3] or '',
            'term': row[4] or '',
            'stream': row[5] or '',
            'parent_password_hash': row[6] or '',
        })
    return out

def save_student(school_id, student_id, student_data):
    """Save a student."""
    with db_connection(commit=True) as conn:
        c = conn.cursor()
        firstname = normalize_person_name(student_data.get('firstname', ''))
        subjects = _dedupe_keep_order([normalize_subject_name(s) for s in (student_data.get('subjects', []) or []) if s])
        subjects_str = json.dumps(subjects)
        scores_str = json.dumps(student_data.get('scores', {}))
        term = student_data.get('term', 'First Term')
        stream = student_data.get('stream', 'Science')
        first_year_class = student_data.get('first_year_class', student_data.get('classname', ''))
        number_of_subject = len(subjects)
        date_of_birth = (student_data.get('date_of_birth', '') or '').strip()
        gender = normalize_student_gender(student_data.get('gender', ''))
        parent_phone = (student_data.get('parent_phone', '') or '').strip()
        parent_password_hash = (student_data.get('parent_password_hash', '') or '').strip()
        has_parent_cols = students_has_parent_access_columns()
        if students_has_user_id_column():
            # user_id is used for student login - same as student_id
            user_id = student_id
            if has_parent_cols:
                db_execute(c, """INSERT INTO students
                                 (user_id, school_id, student_id, firstname, date_of_birth, gender, classname, first_year_class, term, stream, number_of_subject, subjects, scores, promoted, parent_phone, parent_password_hash)
                                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                                 ON CONFLICT(school_id, student_id) DO UPDATE SET
                                    firstname = excluded.firstname,
                                    date_of_birth = excluded.date_of_birth,
                                    gender = excluded.gender,
                                    classname = excluded.classname,
                                    first_year_class = excluded.first_year_class,
                                    term = excluded.term,
                                    stream = excluded.stream,
                                    number_of_subject = excluded.number_of_subject,
                                   subjects = excluded.subjects,
                                   scores = excluded.scores,
                                   promoted = excluded.promoted,
                                   parent_phone = excluded.parent_phone,
                                   parent_password_hash = excluded.parent_password_hash""",
                           (user_id, school_id, student_id, firstname, date_of_birth, gender, student_data['classname'],
                            first_year_class, term, stream, number_of_subject,
                            subjects_str, scores_str, normalize_promoted_db_value(student_data.get('promoted', 0)),
                            parent_phone, parent_password_hash))
            else:
                db_execute(c, """INSERT INTO students
                                 (user_id, school_id, student_id, firstname, date_of_birth, gender, classname, first_year_class, term, stream, number_of_subject, subjects, scores, promoted)
                                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                                 ON CONFLICT(school_id, student_id) DO UPDATE SET
                                    firstname = excluded.firstname,
                                    date_of_birth = excluded.date_of_birth,
                                    gender = excluded.gender,
                                    classname = excluded.classname,
                                    first_year_class = excluded.first_year_class,
                                    term = excluded.term,
                                    stream = excluded.stream,
                                    number_of_subject = excluded.number_of_subject,
                                   subjects = excluded.subjects,
                                   scores = excluded.scores,
                                   promoted = excluded.promoted""",
                           (user_id, school_id, student_id, firstname, date_of_birth, gender, student_data['classname'],
                            first_year_class, term, stream, number_of_subject,
                            subjects_str, scores_str, normalize_promoted_db_value(student_data.get('promoted', 0))))
        else:
            if has_parent_cols:
                db_execute(c, """INSERT INTO students
                                 (school_id, student_id, firstname, date_of_birth, gender, classname, first_year_class, term, stream, number_of_subject, subjects, scores, promoted, parent_phone, parent_password_hash)
                                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                                 ON CONFLICT(school_id, student_id) DO UPDATE SET
                                    firstname = excluded.firstname,
                                    date_of_birth = excluded.date_of_birth,
                                    gender = excluded.gender,
                                    classname = excluded.classname,
                                    first_year_class = excluded.first_year_class,
                                    term = excluded.term,
                                    stream = excluded.stream,
                                    number_of_subject = excluded.number_of_subject,
                                   subjects = excluded.subjects,
                                   scores = excluded.scores,
                                   promoted = excluded.promoted,
                                   parent_phone = excluded.parent_phone,
                                   parent_password_hash = excluded.parent_password_hash""",
                           (school_id, student_id, firstname, date_of_birth, gender, student_data['classname'],
                            first_year_class, term, stream, number_of_subject,
                            subjects_str, scores_str, normalize_promoted_db_value(student_data.get('promoted', 0)),
                            parent_phone, parent_password_hash))
            else:
                db_execute(c, """INSERT INTO students
                                 (school_id, student_id, firstname, date_of_birth, gender, classname, first_year_class, term, stream, number_of_subject, subjects, scores, promoted)
                                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                                 ON CONFLICT(school_id, student_id) DO UPDATE SET
                                    firstname = excluded.firstname,
                                    date_of_birth = excluded.date_of_birth,
                                    gender = excluded.gender,
                                    classname = excluded.classname,
                                    first_year_class = excluded.first_year_class,
                                    term = excluded.term,
                                    stream = excluded.stream,
                                    number_of_subject = excluded.number_of_subject,
                                   subjects = excluded.subjects,
                                   scores = excluded.scores,
                                   promoted = excluded.promoted""",
                           (school_id, student_id, firstname, date_of_birth, gender, student_data['classname'],
                            first_year_class, term, stream, number_of_subject,
                            subjects_str, scores_str, normalize_promoted_db_value(student_data.get('promoted', 0))))

def delete_student(school_id, student_id):
    """Delete a student."""
    with db_connection(commit=True) as conn:
        c = conn.cursor()
        db_execute(c, 'DELETE FROM students WHERE school_id = ? AND student_id = ?', (school_id, student_id))

def archive_student_account(school_id, student_id, archived_by=''):
    """Soft archive one student within one school."""
    if not students_has_archive_columns():
        raise ValueError('Student archive schema is unavailable. Run migration/startup DDL and retry.')
    with db_connection(commit=True) as conn:
        c = conn.cursor()
        db_execute(
            c,
            """UPDATE students
               SET is_archived = 1,
                   archived_at = CURRENT_TIMESTAMP
               WHERE school_id = ? AND student_id = ?""",
            (school_id, student_id),
        )
    if archived_by:
        logging.info("Student archived by=%s school_id=%s student_id=%s", archived_by, school_id, student_id)

def restore_student_account(school_id, student_id, restored_by=''):
    """Restore one archived student within one school."""
    if not students_has_archive_columns():
        raise ValueError('Student archive schema is unavailable. Run migration/startup DDL and retry.')
    with db_connection(commit=True) as conn:
        c = conn.cursor()
        db_execute(
            c,
            """UPDATE students
               SET is_archived = 0,
                   archived_at = NULL
               WHERE school_id = ? AND student_id = ?""",
            (school_id, student_id),
        )
    if restored_by:
        logging.info("Student restored by=%s school_id=%s student_id=%s", restored_by, school_id, student_id)

def get_student_count_by_class(school_id):
    """Get student count by class."""
    has_archive_cols = students_has_archive_columns()
    with db_connection() as conn:
        c = conn.cursor()
        archived_where = " AND COALESCE(is_archived, 0) = 0" if has_archive_cols else ""
        db_execute(c, f"""SELECT classname, COUNT(*) as count FROM students 
                       WHERE school_id = ?{archived_where} GROUP BY classname""", (school_id,))
        return {row[0]: row[1] for row in c.fetchall()}

def get_school_classnames(school_id):
    """Return all known class names for a school (not limited to classes with students)."""
    out = set()
    with db_connection() as conn:
        c = conn.cursor()
        db_execute(
            c,
            """SELECT DISTINCT classname
               FROM students
               WHERE school_id = ? AND classname IS NOT NULL AND BTRIM(classname) <> ''""",
            (school_id,),
        )
        for row in c.fetchall() or []:
            classname = (row[0] or '').strip()
            if classname:
                out.add(classname)
        db_execute(
            c,
            """SELECT DISTINCT classname
               FROM class_subject_configs
               WHERE school_id = ? AND classname IS NOT NULL AND BTRIM(classname) <> ''""",
            (school_id,),
        )
        for row in c.fetchall() or []:
            classname = (row[0] or '').strip()
            if classname:
                out.add(classname)
        db_execute(
            c,
            """SELECT DISTINCT classname
               FROM class_assignments
               WHERE school_id = ? AND classname IS NOT NULL AND BTRIM(classname) <> ''""",
            (school_id,),
        )
        for row in c.fetchall() or []:
            classname = (row[0] or '').strip()
            if classname:
                out.add(classname)
    return sorted(out, key=lambda value: str(value).lower())

def get_total_student_count(school_id):
    """Get total student count for one school."""
    has_archive_cols = students_has_archive_columns()
    with db_connection() as conn:
        c = conn.cursor()
        archived_where = ' AND COALESCE(is_archived, 0) = 0' if has_archive_cols else ''
        db_execute(c, f'SELECT COUNT(*) FROM students WHERE school_id = ?{archived_where}', (school_id,))
        row = c.fetchone()
        return int(row[0] or 0) if row else 0

def get_linked_parent_count(school_id):
    """Get number of unique parent accounts linked by students in one school."""
    if not students_has_parent_access_columns():
        return 0
    with db_connection() as conn:
        c = conn.cursor()
        db_execute(
            c,
            """SELECT COUNT(DISTINCT parent_phone)
               FROM students
               WHERE school_id = ?
                 AND TRIM(COALESCE(parent_phone, '')) <> ''
                 AND TRIM(COALESCE(parent_password_hash, '')) <> ''""",
            (school_id,),
        )
        row = c.fetchone()
        return int(row[0] or 0) if row else 0

def get_school_parent_links(school_id):
    """List students in one school that have parent access linked."""
    if not students_has_parent_access_columns():
        return []
    with db_connection() as conn:
        c = conn.cursor()
        db_execute(
            c,
            """SELECT student_id, firstname, classname, term, stream, parent_phone
               FROM students
               WHERE school_id = ?
                 AND TRIM(COALESCE(parent_phone, '')) <> ''
                 AND TRIM(COALESCE(parent_password_hash, '')) <> ''
               ORDER BY LOWER(parent_phone), LOWER(classname), LOWER(firstname), LOWER(student_id)""",
            (school_id,),
        )
        rows = []
        for row in c.fetchall():
            rows.append({
                'student_id': row[0] or '',
                'firstname': row[1] or '',
                'classname': row[2] or '',
                'term': row[3] or '',
                'stream': row[4] or '',
                'parent_phone': row[5] or '',
            })
        return rows

def ensure_school_term_calendar_schema():
    """Ensure school_term_calendars exists for deployments that missed startup migration."""
    try:
        with db_connection(commit=True) as conn:
            c = conn.cursor()
            db_execute(
                c,
                """CREATE TABLE IF NOT EXISTS school_term_calendars (
                        id SERIAL PRIMARY KEY,
                        school_id TEXT NOT NULL,
                        academic_year TEXT NOT NULL,
                        term TEXT NOT NULL,
                        open_date TEXT,
                        close_date TEXT,
                        midterm_break_start TEXT,
                        midterm_break_end TEXT,
                        exams_period_start TEXT,
                        exams_period_end TEXT,
                        pta_meeting_date TEXT,
                        interhouse_sports_date TEXT,
                        graduation_ceremony_date TEXT,
                        continuous_assessment_deadline TEXT,
                        school_events_date TEXT,
                        school_events TEXT,
                        next_term_begin_date TEXT,
                        program_meta_json TEXT DEFAULT '{}',
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        UNIQUE(school_id, academic_year, term)
                    )"""
            )
            db_execute(c, 'CREATE INDEX IF NOT EXISTS idx_school_term_calendars_lookup ON school_term_calendars(school_id, academic_year, term)')
            # Idempotent for old/new databases.
            db_execute(c, 'ALTER TABLE school_term_calendars ADD COLUMN IF NOT EXISTS exams_period_start TEXT')
            db_execute(c, 'ALTER TABLE school_term_calendars ADD COLUMN IF NOT EXISTS exams_period_end TEXT')
            db_execute(c, 'ALTER TABLE school_term_calendars ADD COLUMN IF NOT EXISTS pta_meeting_date TEXT')
            db_execute(c, 'ALTER TABLE school_term_calendars ADD COLUMN IF NOT EXISTS interhouse_sports_date TEXT')
            db_execute(c, 'ALTER TABLE school_term_calendars ADD COLUMN IF NOT EXISTS graduation_ceremony_date TEXT')
            db_execute(c, 'ALTER TABLE school_term_calendars ADD COLUMN IF NOT EXISTS continuous_assessment_deadline TEXT')
            db_execute(c, 'ALTER TABLE school_term_calendars ADD COLUMN IF NOT EXISTS school_events_date TEXT')
            db_execute(c, 'ALTER TABLE school_term_calendars ADD COLUMN IF NOT EXISTS school_events TEXT')
            db_execute(c, 'ALTER TABLE school_term_calendars ADD COLUMN IF NOT EXISTS next_term_begin_date TEXT')
            db_execute(c, "ALTER TABLE school_term_calendars ADD COLUMN IF NOT EXISTS program_meta_json TEXT DEFAULT '{}'")
        return True
    except Exception as exc:
        logging.warning("Failed to ensure school_term_calendars schema: %s", exc)
        return False

def _parse_iso_date(value):
    raw = (value or '').strip()
    if not raw:
        return None
    try:
        return datetime.strptime(raw, '%Y-%m-%d').date()
    except Exception:
        return None

def _term_sort_index(term_value):
    term = (term_value or '').strip()
    return {'First Term': 1, 'Second Term': 2, 'Third Term': 3}.get(term, 99)

def _academic_year_start(academic_year):
    raw = (academic_year or '').strip()
    match = re.fullmatch(r'(\d{4})-(\d{4})', raw)
    if not match:
        return None
    return int(match.group(1))

def _previous_academic_year(academic_year):
    raw = (academic_year or '').strip()
    match = re.fullmatch(r'(\d{4})-(\d{4})', raw)
    if not match:
        return ''
    return f"{int(match.group(1)) - 1}-{int(match.group(2)) - 1}"

def _next_term_and_year(term_value, academic_year):
    term = (term_value or '').strip()
    year = (academic_year or '').strip()
    if term == 'First Term':
        return 'Second Term', year
    if term == 'Second Term':
        return 'Third Term', year
    if term == 'Third Term':
        match = re.fullmatch(r'(\d{4})-(\d{4})', year)
        if match:
            start_year = int(match.group(1)) + 1
            end_year = int(match.group(2)) + 1
            return 'First Term', f'{start_year}-{end_year}'
        return 'First Term', year
    return '', year

def resolve_next_term_begin_date(school_id, academic_year, term, current_value=''):
    raw = (current_value or '').strip()
    if _parse_iso_date(raw):
        return raw
    next_term, next_year = _next_term_and_year(term, academic_year)
    if not next_term:
        return ''
    next_cal = get_school_term_calendar(school_id, next_year, next_term) or {}
    next_open = (next_cal.get('open_date') or '').strip()
    return next_open if _parse_iso_date(next_open) else ''

def _is_past_term_locked(target_year, target_term, current_year, current_term):
    t_start = _academic_year_start(target_year)
    c_start = _academic_year_start(current_year)
    if t_start is None or c_start is None:
        return False
    if t_start < c_start:
        return True
    if t_start > c_start:
        return False
    return _term_sort_index(target_term) < _term_sort_index(current_term)

def _term_program_event_keys():
    return [
        'midterm_break',
        'exams_period',
        'pta_meeting_date',
        'interhouse_sports_date',
        'graduation_ceremony_date',
        'continuous_assessment_deadline',
        'school_events_date',
        'next_term_begin_date',
    ]

def _term_program_has_content(program_row):
    if not isinstance(program_row, dict):
        return False
    for key in (
        'midterm_break_start',
        'midterm_break_end',
        'exams_period_start',
        'exams_period_end',
        'pta_meeting_date',
        'interhouse_sports_date',
        'graduation_ceremony_date',
        'continuous_assessment_deadline',
        'school_events_date',
        'school_events',
        'next_term_begin_date',
    ):
        if (program_row.get(key) or '').strip():
            return True
    meta = program_row.get('program_meta_json')
    return bool(meta) if isinstance(meta, dict) else False

def _add_months_safe(base_date, month_count):
    month_index = base_date.month - 1 + month_count
    year = base_date.year + (month_index // 12)
    month = (month_index % 12) + 1
    max_day = calendar.monthrange(year, month)[1]
    day = min(base_date.day, max_day)
    return date(year, month, day)

def _expand_recurring_dates(start_date, recurrence, until_date=None, max_occurrences=80):
    if not isinstance(start_date, date):
        return []
    mode = (recurrence or 'none').strip().lower()
    if mode not in {'none', 'weekly', 'monthly'}:
        mode = 'none'
    out = [start_date]
    if mode == 'none':
        return out
    limit = until_date if isinstance(until_date, date) else start_date
    if limit < start_date:
        limit = start_date
    current = start_date
    while len(out) < max_occurrences:
        if mode == 'weekly':
            current = current + timedelta(days=7)
        else:
            current = _add_months_safe(current, 1)
        if current > limit:
            break
        out.append(current)
    return out

def extract_program_holiday_ranges(program_row):
    meta = program_row.get('program_meta_json') if isinstance(program_row.get('program_meta_json'), dict) else {}
    raw_rows = meta.get('holidays') if isinstance(meta.get('holidays'), list) else []
    rows = []
    for item in raw_rows:
        if not isinstance(item, dict):
            continue
        name = (item.get('name') or '').strip()
        start_raw = (item.get('start') or '').strip()
        end_raw = (item.get('end') or start_raw).strip()
        start = _parse_iso_date(start_raw)
        end = _parse_iso_date(end_raw)
        if not start or not end:
            continue
        if end < start:
            start, end = end, start
        rows.append({
            'name': name or 'Holiday',
            'start': start,
            'end': end,
            'type': (item.get('type') or 'holiday').strip().lower()[:40],
        })
    return rows

def build_term_program_events(program_row):
    if not isinstance(program_row, dict):
        return []
    meta = program_row.get('program_meta_json') if isinstance(program_row.get('program_meta_json'), dict) else {}
    status_map = meta.get('event_status') if isinstance(meta.get('event_status'), dict) else {}
    tag_map = meta.get('event_tags') if isinstance(meta.get('event_tags'), dict) else {}
    note_map = meta.get('event_notes') if isinstance(meta.get('event_notes'), dict) else {}
    attachment_map = meta.get('event_attachments') if isinstance(meta.get('event_attachments'), dict) else {}
    visibility_map = meta.get('visibility') if isinstance(meta.get('visibility'), dict) else {}
    event_visibility_map = meta.get('event_visibility') if isinstance(meta.get('event_visibility'), dict) else {}
    out = []
    def _resolve_event_visibility(event_key, fallback_visibility=None):
        if isinstance(fallback_visibility, dict):
            return {
                'teachers': bool(fallback_visibility.get('teachers', True)),
                'parents': bool(fallback_visibility.get('parents', True)),
                'students': bool(fallback_visibility.get('students', True)),
            }
        row = event_visibility_map.get(event_key) if isinstance(event_visibility_map.get(event_key), dict) else {}
        return {
            'teachers': bool(row.get('teachers', visibility_map.get('teachers', True))),
            'parents': bool(row.get('parents', visibility_map.get('parents', True))),
            'students': bool(row.get('students', visibility_map.get('students', True))),
        }

    mid_start = (program_row.get('midterm_break_start') or '').strip()
    mid_end = (program_row.get('midterm_break_end') or '').strip()
    exam_start = (program_row.get('exams_period_start') or '').strip()
    exam_end = (program_row.get('exams_period_end') or '').strip()
    if mid_start or mid_end:
        out.append({
            'key': 'midterm_break',
            'label': 'Mid-term Break',
            'date': f"{mid_start} to {mid_end}" if (mid_start and mid_end) else (mid_start or mid_end),
            'date_raw': mid_start or mid_end,
            'status': status_map.get('midterm_break', 'planned'),
            'tags': tag_map.get('midterm_break', []),
            'note': note_map.get('midterm_break', ''),
            'attachment': attachment_map.get('midterm_break', ''),
            'date_end_raw': mid_end,
        })
    if exam_start or exam_end:
        out.append({
            'key': 'exams_period',
            'label': 'Exams Period',
            'date': f"{exam_start} to {exam_end}" if (exam_start and exam_end) else (exam_start or exam_end),
            'date_raw': exam_start or exam_end,
            'status': status_map.get('exams_period', 'planned'),
            'tags': tag_map.get('exams_period', []),
            'note': note_map.get('exams_period', ''),
            'attachment': attachment_map.get('exams_period', ''),
            'date_end_raw': exam_end,
        })
    for key, label in (
        ('pta_meeting_date', 'PTA Meeting'),
        ('interhouse_sports_date', 'Inter-house Sports'),
        ('graduation_ceremony_date', 'Graduation Ceremony'),
        ('continuous_assessment_deadline', 'CA Deadline'),
        ('school_events_date', 'School Event'),
        ('next_term_begin_date', 'Next Term Begins'),
    ):
        date_value = (program_row.get(key) or '').strip()
        if not date_value:
            continue
        out.append({
            'key': key,
            'label': label,
            'date': date_value,
            'date_raw': date_value,
            'date_end_raw': '',
            'status': status_map.get(key, 'planned'),
            'tags': tag_map.get(key, []),
            'note': note_map.get(key, ''),
            'attachment': attachment_map.get(key, ''),
        })
    school_events_note = (program_row.get('school_events') or '').strip()
    if school_events_note:
        out.append({
            'key': 'school_events_note',
            'label': 'School Events Notes',
            'date': '-',
            'date_raw': '',
            'date_end_raw': '',
            'status': status_map.get('school_events_note', 'planned'),
            'tags': tag_map.get('school_events_note', []),
            'note': school_events_note,
            'attachment': attachment_map.get('school_events_note', ''),
        })
    holidays = extract_program_holiday_ranges(program_row)
    for idx, holiday in enumerate(holidays, start=1):
        start_iso = holiday.get('start').isoformat()
        end_iso = holiday.get('end').isoformat()
        out.append({
            'key': f'holiday_{idx}',
            'label': f"Holiday: {holiday.get('name', 'Holiday')}",
            'date': f'{start_iso} to {end_iso}' if start_iso != end_iso else start_iso,
            'date_raw': start_iso,
            'date_end_raw': end_iso,
            'status': 'holiday',
            'tags': [holiday.get('type', 'holiday')],
            'note': '',
            'attachment': '',
        })
    external_programs = meta.get('external_programs') if isinstance(meta.get('external_programs'), list) else []
    for idx, item in enumerate(external_programs):
        if not isinstance(item, dict):
            continue
        title = (item.get('name') or '').strip()
        date_value = (item.get('date') or '').strip()
        if not title or not date_value:
            continue
        recurrence = (item.get('recurrence') or 'none').strip().lower()
        recurrence_until = _parse_iso_date(item.get('recurrence_until', ''))
        start_date = _parse_iso_date(date_value)
        occurrences = [start_date] if start_date else []
        if start_date:
            occurrences = _expand_recurring_dates(start_date, recurrence, recurrence_until)
        ext_visibility = item.get('visibility') if isinstance(item.get('visibility'), dict) else {}
        if not occurrences:
            occurrences = [None]
        for occ_index, occ_date in enumerate(occurrences, start=1):
            suffix = f'_occ{occ_index}' if len(occurrences) > 1 else ''
            key = f'external_program_{idx + 1}{suffix}'
            out.append({
                'key': key,
                'base_key': f'external_program_{idx + 1}',
                'label': f'External: {title}' + (' (Recurring)' if len(occurrences) > 1 else ''),
                'date': (occ_date.isoformat() if isinstance(occ_date, date) else date_value),
                'date_raw': (occ_date.isoformat() if isinstance(occ_date, date) else date_value),
                'date_end_raw': '',
                'status': (item.get('status') or 'planned').strip().lower(),
                'tags': item.get('tags', []) if isinstance(item.get('tags'), list) else [],
                'note': (item.get('note') or '').strip(),
                'attachment': (item.get('attachment') or '').strip(),
                'recurrence': recurrence,
                'recurrence_until': item.get('recurrence_until', ''),
                '_visibility_override': ext_visibility,
            })
    for item in out:
        event_key = item.get('base_key') or item.get('key')
        vis = _resolve_event_visibility(event_key, item.get('_visibility_override'))
        item['visible_to_teachers'] = bool(vis.get('teachers', True))
        item['visible_to_parents'] = bool(vis.get('parents', True))
        item['visible_to_students'] = bool(vis.get('students', True))
        if '_visibility_override' in item:
            item.pop('_visibility_override')
    out.sort(
        key=lambda x: (
            0 if _parse_iso_date(x.get('date_raw', '')) else 1,
            _parse_iso_date(x.get('date_raw', '')) or date.max,
            (x.get('label') or '').lower(),
        )
    )
    return out

def get_visible_term_program_events(school_id, academic_year, term, audience):
    program = get_school_term_program(school_id, academic_year, term)
    audience_key = (audience or '').strip().lower()
    if audience_key not in {'teachers', 'parents', 'students'}:
        return []
    key_name = f'visible_to_{audience_key}'
    return [e for e in build_term_program_events(program) if bool(e.get(key_name))]

def build_term_program_reminders(program_row, base_date=None):
    today = base_date or date.today()
    meta = program_row.get('program_meta_json') if isinstance(program_row.get('program_meta_json'), dict) else {}
    try:
        reminder_days = int(meta.get('reminder_days_before', 7) or 7)
    except Exception:
        reminder_days = 7
    reminder_days = max(0, min(reminder_days, 90))
    reminders = []
    for event in build_term_program_events(program_row):
        d = _parse_iso_date(event.get('date_raw', ''))
        if not d:
            continue
        days_left = (d - today).days
        if 0 <= days_left <= reminder_days:
            reminders.append({
                'label': event.get('label', ''),
                'date': d.isoformat(),
                'days_left': days_left,
                'status': event.get('status', 'planned'),
            })
    reminders.sort(key=lambda x: (x.get('days_left', 9999), x.get('label', '').lower()))
    return reminders

def calculate_open_days_excluding_weekend(open_date, close_date, break_start=None, break_end=None, extra_excluded_dates=None, extra_excluded_ranges=None):
    """
    Count open days inclusive of open/close range, excluding Saturday/Sunday and optional break dates.
    """
    start = _parse_iso_date(open_date)
    end = _parse_iso_date(close_date)
    if not start or not end or end < start:
        return 0
    b_start = _parse_iso_date(break_start)
    b_end = _parse_iso_date(break_end)
    if b_start and b_end and b_end < b_start:
        b_start, b_end = b_end, b_start
    day = start
    total = 0
    one_day = timedelta(days=1)
    excluded_dates = {d for d in (extra_excluded_dates or set()) if isinstance(d, date)}
    excluded_ranges = []
    for item in (extra_excluded_ranges or []):
        if not isinstance(item, (tuple, list)) or len(item) != 2:
            continue
        a = item[0] if isinstance(item[0], date) else None
        b = item[1] if isinstance(item[1], date) else None
        if not a or not b:
            continue
        if b < a:
            a, b = b, a
        excluded_ranges.append((a, b))
    while day <= end:
        # Exclude Saturday(5) and Sunday(6)
        if day.weekday() not in (5, 6):
            in_break = bool(b_start and b_end and b_start <= day <= b_end)
            in_extra_range = any(a <= day <= b for a, b in excluded_ranges)
            in_extra_date = day in excluded_dates
            if not in_break and not in_extra_range and not in_extra_date:
                total += 1
        day += one_day
    return total

def build_term_open_progress(calendar_row, program_row=None, today_value=None):
    """
    Build open-day progress for a term calendar.
    Progress is counted from open_date to min(today, close_date), excluding Saturday/Sunday and mid-term break.
    """
    today = today_value or date.today()
    open_date_raw = (calendar_row or {}).get('open_date', '')
    close_date_raw = (calendar_row or {}).get('close_date', '')
    break_start = (calendar_row or {}).get('midterm_break_start', '')
    break_end = (calendar_row or {}).get('midterm_break_end', '')
    holiday_ranges = [(r.get('start'), r.get('end')) for r in extract_program_holiday_ranges(program_row or {})]
    start = _parse_iso_date(open_date_raw)
    end = _parse_iso_date(close_date_raw)
    if not start or not end or end < start:
        return {
            'has_dates': False,
            'percentage': 0,
            'total_open_days': 0,
            'elapsed_open_days': 0,
            'remaining_open_days': 0,
            'status': 'Calendar not set',
            'open_date': open_date_raw,
            'close_date': close_date_raw,
        }
    total_open_days = calculate_open_days_excluding_weekend(
        open_date_raw,
        close_date_raw,
        break_start,
        break_end,
        extra_excluded_ranges=holiday_ranges,
    )
    if total_open_days <= 0:
        return {
            'has_dates': True,
            'percentage': 0,
            'total_open_days': 0,
            'elapsed_open_days': 0,
            'remaining_open_days': 0,
            'status': 'No open days',
            'open_date': open_date_raw,
            'close_date': close_date_raw,
        }
    if today < start:
        elapsed_open_days = 0
        status = 'Not started'
    elif today >= end:
        elapsed_open_days = total_open_days
        status = 'Completed'
    else:
        elapsed_close = today.isoformat()
        elapsed_open_days = calculate_open_days_excluding_weekend(
            open_date_raw,
            elapsed_close,
            break_start,
            break_end,
            extra_excluded_ranges=holiday_ranges,
        )
        status = 'In progress'
    elapsed_open_days = max(0, min(total_open_days, int(elapsed_open_days)))
    remaining_open_days = max(0, total_open_days - elapsed_open_days)
    percentage = int(round((elapsed_open_days / total_open_days) * 100.0))
    return {
        'has_dates': True,
        'percentage': max(0, min(100, percentage)),
        'total_open_days': total_open_days,
        'elapsed_open_days': elapsed_open_days,
        'remaining_open_days': remaining_open_days,
        'status': status,
        'open_date': open_date_raw,
        'close_date': close_date_raw,
    }

def build_term_program_ics_content(school, events, term_label='', year_label=''):
    school_name = (school or {}).get('school_name', 'School')
    lines = [
        'BEGIN:VCALENDAR',
        'VERSION:2.0',
        'PRODID:-//StudentScore//TermPrograms//EN',
        'CALSCALE:GREGORIAN',
        'METHOD:PUBLISH',
    ]
    now_stamp = datetime.utcnow().strftime('%Y%m%dT%H%M%SZ')
    for idx, item in enumerate(events, start=1):
        start_date = _parse_iso_date(item.get('date_raw', ''))
        if not start_date:
            continue
        end_date = _parse_iso_date(item.get('date_end_raw', '')) or start_date
        end_next = end_date + timedelta(days=1)
        uid = f"termprog-{(school or {}).get('school_id','school')}-{year_label}-{term_label}-{idx}@studentscore"
        summary = f"{item.get('label', 'Event')} ({term_label} {year_label})"
        description_parts = []
        if item.get('note'):
            description_parts.append(str(item.get('note')))
        if item.get('status'):
            description_parts.append(f"Status: {str(item.get('status')).title()}")
        if item.get('tags'):
            description_parts.append(f"Tags: {', '.join([str(x) for x in item.get('tags')])}")
        description = '\\n'.join(description_parts).replace('\n', '\\n')
        lines.extend([
            'BEGIN:VEVENT',
            f'UID:{uid}',
            f'DTSTAMP:{now_stamp}',
            f'DTSTART;VALUE=DATE:{start_date.strftime("%Y%m%d")}',
            f'DTEND;VALUE=DATE:{end_next.strftime("%Y%m%d")}',
            f'SUMMARY:{summary}',
            f'DESCRIPTION:{description}',
            f'LOCATION:{school_name}',
            'END:VEVENT',
        ])
    lines.append('END:VCALENDAR')
    return '\r\n'.join(lines) + '\r\n'

def send_term_program_notifications(school, reminders, channels, email_recipients, sms_recipients):
    sent_email = 0
    sent_sms = 0
    errors = []
    school_name = (school or {}).get('school_name', 'School')
    lines = []
    for row in reminders:
        lines.append(f"- {row.get('label','Event')} on {row.get('date','')} ({row.get('days_left',0)} day(s) left)")
    body_text = (
        f"Upcoming reminders for {school_name}:\n\n" +
        ('\n'.join(lines) if lines else 'No reminders in range.')
    )
    if channels.get('email') and email_recipients and reminders:
        smtp_host = (os.environ.get('SMTP_HOST', '') or '').strip()
        smtp_port_raw = (os.environ.get('SMTP_PORT', '587') or '587').strip()
        smtp_user = (os.environ.get('SMTP_USER', '') or '').strip()
        smtp_pass = (os.environ.get('SMTP_PASS', '') or '').strip()
        smtp_from = (os.environ.get('SMTP_FROM', smtp_user or 'noreply@localhost') or '').strip()
        try:
            smtp_port = int(smtp_port_raw)
        except Exception:
            smtp_port = 587
        if smtp_host:
            try:
                msg = EmailMessage()
                msg['Subject'] = f'{school_name} Term Program Reminder'
                msg['From'] = smtp_from
                msg['To'] = ', '.join(email_recipients)
                msg.set_content(body_text)
                with smtplib.SMTP(smtp_host, smtp_port, timeout=15) as client:
                    if smtp_user and smtp_pass:
                        client.starttls()
                        client.login(smtp_user, smtp_pass)
                    client.send_message(msg)
                sent_email = len(email_recipients)
            except Exception as exc:
                errors.append(f'Email send failed: {exc}')
        else:
            errors.append('Email channel enabled but SMTP_HOST is not configured.')
    if channels.get('sms') and sms_recipients and reminders:
        sms_webhook = (os.environ.get('SMS_WEBHOOK_URL', '') or '').strip()
        if sms_webhook:
            for phone in sms_recipients:
                payload = json.dumps({
                    'to': phone,
                    'message': body_text[:600],
                    'school': school_name,
                }).encode('utf-8')
                try:
                    req = urllib.request.Request(
                        sms_webhook,
                        data=payload,
                        headers={'Content-Type': 'application/json'},
                        method='POST',
                    )
                    with urllib.request.urlopen(req, timeout=12) as _resp:
                        sent_sms += 1
                except Exception as exc:
                    errors.append(f'SMS send failed for {phone}: {exc}')
        else:
            errors.append('SMS channel enabled but SMS_WEBHOOK_URL is not configured.')
    return {
        'sent_email': sent_email,
        'sent_sms': sent_sms,
        'errors': errors,
    }

def get_school_term_calendar(school_id, academic_year, term):
    if not ensure_school_term_calendar_schema():
        return {
            'academic_year': (academic_year or '').strip(),
            'term': (term or '').strip(),
            'open_date': '',
            'close_date': '',
            'midterm_break_start': '',
            'midterm_break_end': '',
            'next_term_begin_date': '',
            'days_open': 0,
        }
    with db_connection() as conn:
        c = conn.cursor()
        db_execute(
            c,
            """SELECT academic_year, term, open_date, close_date, midterm_break_start, midterm_break_end, next_term_begin_date
               FROM school_term_calendars
               WHERE school_id = ? AND academic_year = ? AND term = ?
               LIMIT 1""",
            (school_id, (academic_year or '').strip(), (term or '').strip()),
        )
        row = c.fetchone()
        if not row:
            return {
                'academic_year': (academic_year or '').strip(),
                'term': (term or '').strip(),
                'open_date': '',
                'close_date': '',
                'midterm_break_start': '',
                'midterm_break_end': '',
                'next_term_begin_date': '',
                'days_open': 0,
            }
        return {
            'academic_year': row[0] or '',
            'term': row[1] or '',
            'open_date': row[2] or '',
            'close_date': row[3] or '',
            'midterm_break_start': row[4] or '',
            'midterm_break_end': row[5] or '',
            'next_term_begin_date': row[6] or '',
            'days_open': calculate_open_days_excluding_weekend(row[2], row[3], row[4], row[5]),
        }

def list_school_term_calendars(school_id):
    if not ensure_school_term_calendar_schema():
        return []
    with db_connection() as conn:
        c = conn.cursor()
        db_execute(
            c,
            """SELECT academic_year, term, open_date, close_date, midterm_break_start, midterm_break_end, next_term_begin_date
               FROM school_term_calendars
               WHERE school_id = ?
               ORDER BY academic_year DESC, term""",
            (school_id,),
        )
        rows = []
        for row in c.fetchall() or []:
            rows.append({
                'academic_year': row[0] or '',
                'term': row[1] or '',
                'open_date': row[2] or '',
                'close_date': row[3] or '',
                'midterm_break_start': row[4] or '',
                'midterm_break_end': row[5] or '',
                'next_term_begin_date': row[6] or '',
                'days_open': calculate_open_days_excluding_weekend(row[2], row[3], row[4], row[5]),
            })
        return rows

def save_school_term_calendar_with_cursor(c, school_id, academic_year, term, open_date, close_date, break_start, break_end, next_term_begin_date=''):
    db_execute(
        c,
        """INSERT INTO school_term_calendars
           (school_id, academic_year, term, open_date, close_date, midterm_break_start, midterm_break_end, next_term_begin_date, updated_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
           ON CONFLICT(school_id, academic_year, term)
           DO UPDATE SET
             open_date = excluded.open_date,
             close_date = excluded.close_date,
             midterm_break_start = excluded.midterm_break_start,
             midterm_break_end = excluded.midterm_break_end,
             next_term_begin_date = excluded.next_term_begin_date,
             updated_at = excluded.updated_at""",
        (
            school_id,
            (academic_year or '').strip(),
            (term or '').strip(),
            (open_date or '').strip(),
            (close_date or '').strip(),
            (break_start or '').strip(),
            (break_end or '').strip(),
            (next_term_begin_date or '').strip(),
            datetime.now(),
        ),
    )

def get_school_term_program(school_id, academic_year, term):
    if not ensure_school_term_calendar_schema():
        return {
            'academic_year': (academic_year or '').strip(),
            'term': (term or '').strip(),
            'midterm_break_start': '',
            'midterm_break_end': '',
            'exams_period_start': '',
            'exams_period_end': '',
            'pta_meeting_date': '',
            'interhouse_sports_date': '',
            'graduation_ceremony_date': '',
            'continuous_assessment_deadline': '',
            'school_events_date': '',
            'next_term_begin_date': '',
            'school_events': '',
        }
    with db_connection() as conn:
        c = conn.cursor()
        db_execute(
            c,
            """SELECT academic_year, term,
                      midterm_break_start, midterm_break_end,
                      exams_period_start, exams_period_end,
                      pta_meeting_date, interhouse_sports_date,
                      graduation_ceremony_date, continuous_assessment_deadline,
                      school_events_date, school_events, next_term_begin_date, program_meta_json
               FROM school_term_calendars
               WHERE school_id = ? AND academic_year = ? AND term = ?
               LIMIT 1""",
            (school_id, (academic_year or '').strip(), (term or '').strip()),
        )
        row = c.fetchone()
        if not row:
            return {
                'academic_year': (academic_year or '').strip(),
                'term': (term or '').strip(),
                'midterm_break_start': '',
                'midterm_break_end': '',
                'exams_period_start': '',
                'exams_period_end': '',
                'pta_meeting_date': '',
                'interhouse_sports_date': '',
                'graduation_ceremony_date': '',
                'continuous_assessment_deadline': '',
                'school_events_date': '',
                'school_events': '',
                'next_term_begin_date': '',
                'program_meta_json': {},
            }
        meta = _safe_json_object(row[13]) if len(row) > 13 else {}
        return {
            'academic_year': row[0] or '',
            'term': row[1] or '',
            'midterm_break_start': row[2] or '',
            'midterm_break_end': row[3] or '',
            'exams_period_start': row[4] or '',
            'exams_period_end': row[5] or '',
            'pta_meeting_date': row[6] or '',
            'interhouse_sports_date': row[7] or '',
            'graduation_ceremony_date': row[8] or '',
            'continuous_assessment_deadline': row[9] or '',
            'school_events_date': row[10] or '',
            'school_events': row[11] or '',
            'next_term_begin_date': row[12] or '',
            'program_meta_json': meta if isinstance(meta, dict) else {},
        }

def list_school_term_programs(school_id):
    if not ensure_school_term_calendar_schema():
        return []
    with db_connection() as conn:
        c = conn.cursor()
        db_execute(
            c,
            """SELECT academic_year, term,
                      midterm_break_start, midterm_break_end,
                      exams_period_start, exams_period_end,
                      pta_meeting_date, interhouse_sports_date,
                      graduation_ceremony_date, continuous_assessment_deadline,
                      school_events_date, school_events, next_term_begin_date, program_meta_json
               FROM school_term_calendars
               WHERE school_id = ?
               ORDER BY academic_year DESC, term""",
            (school_id,),
        )
        rows = []
        for row in c.fetchall() or []:
            meta = _safe_json_object(row[13]) if len(row) > 13 else {}
            rows.append({
                'academic_year': row[0] or '',
                'term': row[1] or '',
                'midterm_break_start': row[2] or '',
                'midterm_break_end': row[3] or '',
                'exams_period_start': row[4] or '',
                'exams_period_end': row[5] or '',
                'pta_meeting_date': row[6] or '',
                'interhouse_sports_date': row[7] or '',
                'graduation_ceremony_date': row[8] or '',
                'continuous_assessment_deadline': row[9] or '',
                'school_events_date': row[10] or '',
                'school_events': row[11] or '',
                'next_term_begin_date': row[12] or '',
                'program_meta_json': meta if isinstance(meta, dict) else {},
            })
        return rows

def save_school_term_program_with_cursor(c, school_id, academic_year, term, payload):
    db_execute(
        c,
        """INSERT INTO school_term_calendars
           (school_id, academic_year, term,
            midterm_break_start, midterm_break_end,
            exams_period_start, exams_period_end,
            pta_meeting_date, interhouse_sports_date,
            graduation_ceremony_date, continuous_assessment_deadline,
            school_events_date, school_events, next_term_begin_date, program_meta_json, updated_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
           ON CONFLICT(school_id, academic_year, term)
           DO UPDATE SET
             midterm_break_start = excluded.midterm_break_start,
             midterm_break_end = excluded.midterm_break_end,
             exams_period_start = excluded.exams_period_start,
             exams_period_end = excluded.exams_period_end,
             pta_meeting_date = excluded.pta_meeting_date,
             interhouse_sports_date = excluded.interhouse_sports_date,
             graduation_ceremony_date = excluded.graduation_ceremony_date,
             continuous_assessment_deadline = excluded.continuous_assessment_deadline,
             school_events_date = excluded.school_events_date,
             school_events = excluded.school_events,
             next_term_begin_date = excluded.next_term_begin_date,
             program_meta_json = excluded.program_meta_json,
             updated_at = excluded.updated_at""",
        (
            school_id,
            (academic_year or '').strip(),
            (term or '').strip(),
            (payload.get('midterm_break_start') or '').strip(),
            (payload.get('midterm_break_end') or '').strip(),
            (payload.get('exams_period_start') or '').strip(),
            (payload.get('exams_period_end') or '').strip(),
            (payload.get('pta_meeting_date') or '').strip(),
            (payload.get('interhouse_sports_date') or '').strip(),
            (payload.get('graduation_ceremony_date') or '').strip(),
            (payload.get('continuous_assessment_deadline') or '').strip(),
            (payload.get('school_events_date') or '').strip(),
            (payload.get('school_events') or '').strip(),
            (payload.get('next_term_begin_date') or '').strip(),
            json.dumps(payload.get('program_meta_json') if isinstance(payload.get('program_meta_json'), dict) else {}),
            datetime.now(),
        ),
    )

def get_next_student_index(school_id, first_year_class):
    """Get next numeric index for generated IDs in a first-year class."""
    with db_connection() as conn:
        c = conn.cursor()
        # Extract numeric index from student_id and find max in one query
        db_execute(c, """SELECT COALESCE(
                           MAX(CAST(SPLIT_PART(student_id, '/', 3) AS INTEGER)), 0
                         )
                       FROM students
                       WHERE school_id = ? 
                         AND first_year_class = ?
                         AND student_id LIKE '%/%/%/%' """,
                   (school_id, first_year_class))
        row = c.fetchone()
        max_index = int(row[0] or 0) if row else 0
        return max_index + 1

def get_next_student_index_for_class(school_id, classname):
    """
    Get next numeric index for generated IDs in a class list.
    This appends after the last existing index in that class, without re-numbering.
    """
    with db_connection() as conn:
        c = conn.cursor()
        # Extract numeric index from student_id and find max in one query
        db_execute(c, """SELECT COALESCE(
                           MAX(CAST(SPLIT_PART(student_id, '/', 3) AS INTEGER)), 0
                         )
                       FROM students
                       WHERE school_id = %s 
                         AND LOWER(classname) = LOWER(%s)
                         AND student_id LIKE %s""",
                   (school_id, classname, '%/%/%/%'))
        row = c.fetchone()
        max_index = int(row[0] or 0) if row else 0
        return max_index + 1

def promote_students(school_id, from_class, to_class, action_by_student, term='', academic_year='', changed_by=''):
    """
    Apply school-admin class transition decisions for one class:
    - action=promote -> move to to_class
    - action=repeat -> remain in from_class
    - action=remove -> remove from class/school roster
    """
    school = get_school(school_id) or {}
    with db_connection(commit=True) as conn:
        c = conn.cursor()
        
        # Get all students currently in the source class.
        from_class_key = canonicalize_classname(from_class)
        where = "WHERE school_id = ? AND REGEXP_REPLACE(UPPER(COALESCE(classname, '')), '[^A-Z0-9]+', '', 'g') = ?"
        params = [school_id, from_class_key]
        if term:
            where += ' AND term = ?'
            params.append(term)
        db_execute(
            c,
            f"""SELECT student_id, firstname, first_year_class, classname, subjects FROM students
                       {where}""",
            tuple(params),
        )
        
        for row in c.fetchall():
            student_id = row[0]
            student_name = row[1] or ''
            current_first_year_class = row[2] or ''
            current_classname = row[3] or ''
            action = action_by_student.get(student_id, 'repeat')

            if action == 'promote':
                target_class = to_class
                new_first_year_class = current_first_year_class
                from_level = get_class_level(current_classname)
                current_no = _extract_class_number(current_classname)

                # Senior secondary graduation rule:
                # - SS3 promote -> Graduated
                if from_level == 'ss' and current_no == 3:
                    target_class = 'Graduated'

                to_level = get_class_level(target_class)
                normalized_to = re.sub(r'[^A-Za-z0-9]+', '', (target_class or '')).upper()
                # Reset first-level reference when entering JSS1 from non-JSS
                # so ID start-year is based on JSS entry year.
                if normalized_to in {'JSS1'} and to_level == 'jss' and from_level != 'jss':
                    new_first_year_class = 'JSS1'
                existing_subjects = json.loads(row[4] or '[]') if len(row) > 4 and row[4] else []
                new_stream = 'N/A'
                new_subjects = list(existing_subjects) if isinstance(existing_subjects, list) else []
                if target_class != 'Graduated':
                    target_config = get_class_subject_config(school_id, target_class)
                    if target_config:
                        if class_uses_stream_for_school(school, target_class):
                            # Promote into stream-based class with pending stream allocation.
                            new_subjects = _dedupe_keep_order(target_config.get('core_subjects', []) or [])
                            new_stream = 'N/A'
                        else:
                            built_subjects, built_stream, build_err = build_subjects_from_config(
                                classname=target_class,
                                stream='N/A',
                                config=target_config,
                                selected_optional_subjects=[],
                                school=school,
                            )
                            if not build_err and built_subjects:
                                new_subjects = _dedupe_keep_order(built_subjects)
                                new_stream = built_stream
                            else:
                                new_subjects = _dedupe_keep_order(target_config.get('core_subjects', []) or [])
                    else:
                        new_subjects = []
                else:
                    new_subjects = []
                    new_stream = 'N/A'
                promoted_flag = normalize_promoted_db_value(True)
                db_execute(
                    c,
                    """UPDATE students
                       SET classname = ?, first_year_class = ?, promoted = ?, stream = ?,
                           subjects = ?, number_of_subject = ?, scores = ?
                       WHERE school_id = ? AND student_id = ?""",
                    (
                        target_class,
                        new_first_year_class,
                        promoted_flag,
                        new_stream,
                        json.dumps(new_subjects),
                        len(new_subjects),
                        json.dumps({}),
                        school_id,
                        student_id
                    )
                )
                log_promotion_audit_row(
                    school_id=school_id,
                    student_id=student_id,
                    student_name=student_name,
                    from_class=current_classname,
                    to_class=target_class,
                    action='promote',
                    term=term,
                    academic_year=academic_year,
                    changed_by=changed_by,
                )
            elif action == 'remove':
                # Student left school: remove roster and login account for this school.
                db_execute(c, 'DELETE FROM students WHERE school_id = ? AND student_id = ?', (school_id, student_id))
                db_execute(c, 'DELETE FROM users WHERE school_id = ? AND username = ? AND role = ?', (school_id, student_id, 'student'))
                log_promotion_audit_row(
                    school_id=school_id,
                    student_id=student_id,
                    student_name=student_name,
                    from_class=current_classname,
                    to_class='',
                    action='remove',
                    term=term,
                    academic_year=academic_year,
                    changed_by=changed_by,
                )
            else:
                # Not passed / repeat class
                promoted_value = normalize_promoted_db_value(False)
                db_execute(
                    c,
                    """UPDATE students
                       SET promoted = %s, scores = %s
                       WHERE school_id = ? AND student_id = ?""",
                    (promoted_value, json.dumps({}), school_id, student_id)
                )
                log_promotion_audit_row(
                    school_id=school_id,
                    student_id=student_id,
                    student_name=student_name,
                    from_class=current_classname,
                    to_class=current_classname,
                    action='repeat',
                    term=term,
                    academic_year=academic_year,
                    changed_by=changed_by,
                )

def rollover_school_term_data_with_cursor(c, school_id, from_term, to_term, from_year='', to_year=''):
    """
    Roll forward working data when school term/year changes using an existing cursor:
    - copy class assignments from old term/year to new term/year (if missing)
    - move active student rows to new term and clear working scores
    Published snapshots remain untouched.
    """
    if not school_id:
        return
    src_term = (from_term or '').strip()
    dst_term = (to_term or '').strip()
    src_year = (from_year or '').strip()
    dst_year = (to_year or '').strip()
    if not src_term or not dst_term:
        return 0
    if src_term.lower() == dst_term.lower() and src_year == dst_year:
        return 0

    db_execute(
        c,
        """INSERT INTO class_assignments (school_id, teacher_id, classname, term, academic_year)
           SELECT school_id, teacher_id, classname, ?, ?
           FROM class_assignments
           WHERE school_id = ? AND LOWER(term) = LOWER(?) AND COALESCE(academic_year, '') = COALESCE(?, '')
           ON CONFLICT(school_id, classname, term, academic_year) DO NOTHING""",
        (dst_term, dst_year, school_id, src_term, src_year),
    )
    db_execute(
        c,
        """INSERT INTO teacher_subject_assignments (school_id, teacher_id, classname, subject, term, academic_year)
           SELECT school_id, teacher_id, classname, subject, ?, ?
           FROM teacher_subject_assignments
           WHERE school_id = ? AND LOWER(term) = LOWER(?) AND COALESCE(academic_year, '') = COALESCE(?, '')
           ON CONFLICT(school_id, classname, subject, term, academic_year) DO NOTHING""",
        (dst_term, dst_year, school_id, src_term, src_year),
    )
    promoted_reset_sql = 'FALSE' if students_promoted_is_boolean() else '0'
    db_execute(
        c,
        f"""UPDATE students
           SET term = ?, scores = ?, promoted = {promoted_reset_sql}
           WHERE school_id = ?
             AND LOWER(COALESCE(term, '')) = LOWER(COALESCE(?, ''))
             AND REGEXP_REPLACE(UPPER(COALESCE(classname, '')), '[^A-Z0-9]+', '', 'g') <> 'GRADUATED' """,
        (dst_term, json.dumps({}), school_id, src_term),
    )
    try:
        return int(getattr(c, 'rowcount', 0) or 0)
    except Exception:
        return 0

def rollover_school_term_data(school_id, from_term, to_term, from_year='', to_year=''):
    """
    Roll forward working data when school term/year changes:
    - copy class assignments from old term/year to new term/year (if missing)
    - move active student rows to new term and clear working scores
    Published snapshots remain untouched.
    """
    if not school_id:
        return
    src_term = (from_term or '').strip()
    dst_term = (to_term or '').strip()
    src_year = (from_year or '').strip()
    dst_year = (to_year or '').strip()
    if not src_term or not dst_term:
        return 0
    if src_term.lower() == dst_term.lower() and src_year == dst_year:
        return 0

    with db_connection(commit=True) as conn:
        c = conn.cursor()
        return rollover_school_term_data_with_cursor(c, school_id, src_term, dst_term, src_year, dst_year)

DAY_OF_WEEK_OPTIONS = [
    (1, 'Monday'),
    (2, 'Tuesday'),
    (3, 'Wednesday'),
    (4, 'Thursday'),
    (5, 'Friday'),
    (6, 'Saturday'),
    (7, 'Sunday'),
]

def _safe_json_rows(raw_value):
    try:
        value = json.loads(raw_value) if isinstance(raw_value, str) else raw_value
        return value if isinstance(value, list) else []
    except Exception:
        return []

def log_promotion_audit_row(school_id, student_id, student_name, from_class, to_class, action, term, academic_year, changed_by, note=''):
    if not ensure_extended_features_schema():
        return
    try:
        with db_connection(commit=True) as conn:
            c = conn.cursor()
            db_execute(
                c,
                """INSERT INTO promotion_audit_logs
                   (school_id, student_id, student_name, from_class, to_class, action, term, academic_year, changed_by, note, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)""",
                (
                    school_id,
                    student_id,
                    (student_name or '').strip(),
                    (from_class or '').strip(),
                    (to_class or '').strip(),
                    (action or '').strip().lower()[:20],
                    (term or '').strip(),
                    (academic_year or '').strip(),
                    (changed_by or '').strip(),
                    (note or '').strip()[:300],
                ),
            )
    except Exception:
        pass

def get_school_timetable_rows(school_id, classname=''):
    if not ensure_extended_features_schema():
        return []
    with db_connection() as conn:
        c = conn.cursor()
        params = [school_id]
        where_sql = "WHERE school_id = ?"
        if classname:
            where_sql += " AND LOWER(classname) = LOWER(?)"
            params.append(classname)
        db_execute(
            c,
            f"""SELECT id, classname, day_of_week, period_label, subject, teacher_id, start_time, end_time, room
                FROM class_timetables
                {where_sql}
                ORDER BY LOWER(classname), day_of_week, LOWER(period_label)""",
            tuple(params),
        )
        rows = []
        for row in c.fetchall() or []:
            rows.append({
                'id': int(row[0] or 0),
                'classname': row[1] or '',
                'day_of_week': int(row[2] or 0),
                'day_name': dict(DAY_OF_WEEK_OPTIONS).get(int(row[2] or 0), str(row[2] or '')),
                'period_label': row[3] or '',
                'subject': row[4] or '',
                'teacher_id': row[5] or '',
                'start_time': row[6] or '',
                'end_time': row[7] or '',
                'room': row[8] or '',
            })
        return rows

def get_timetable_period_labels_for_class(school_id, classname):
    rows = get_school_timetable_rows(school_id, classname=classname)
    labels = []
    for row in rows:
        label = (row.get('period_label') or '').strip()
        if label and label not in labels:
            labels.append(label)
    return labels

def get_period_attendance_map_for_date(school_id, classname, attendance_date, period_label, term='', academic_year='', subject=''):
    if not ensure_extended_features_schema():
        return {}
    with db_connection() as conn:
        c = conn.cursor()
        db_execute(
            c,
            """SELECT student_id, status, note
               FROM period_attendance
               WHERE school_id = ?
                 AND LOWER(classname) = LOWER(?)
                 AND attendance_date = ?
                 AND LOWER(period_label) = LOWER(?)
                 AND (COALESCE(?, '') = '' OR LOWER(COALESCE(subject, '')) = LOWER(?))
                 AND COALESCE(term, '') = COALESCE(?, COALESCE(term, ''))
                 AND COALESCE(academic_year, '') = COALESCE(?, COALESCE(academic_year, ''))""",
            (
                school_id,
                classname,
                attendance_date,
                period_label,
                subject or '',
                subject or '',
                term or None,
                academic_year or None,
            ),
        )
        out = {}
        for sid, status, note in c.fetchall() or []:
            out[str(sid or '').strip()] = {
                'status': normalize_attendance_status(status),
                'note': (note or '').strip(),
            }
        return out

def build_school_analytics_data(school_id, term, academic_year):
    class_pass_rows = []
    subject_rows = []
    attendance_impact_rows = []
    with db_connection() as conn:
        c = conn.cursor()
        db_execute(
            c,
            """SELECT classname,
                      COUNT(*) AS total_count,
                      SUM(CASE WHEN LOWER(COALESCE(status, '')) IN ('pass', 'promoted', 'promoted on trial') THEN 1 ELSE 0 END) AS pass_count,
                      AVG(COALESCE(average_marks, 0)) AS avg_marks
               FROM published_student_results
               WHERE school_id = ? AND term = ? AND COALESCE(academic_year, '') = COALESCE(?, '')
               GROUP BY classname
               ORDER BY LOWER(classname)""",
            (school_id, term, academic_year or ''),
        )
        for classname, total_count, pass_count, avg_marks in c.fetchall() or []:
            total_n = int(total_count or 0)
            pass_n = int(pass_count or 0)
            class_pass_rows.append({
                'classname': classname or '',
                'total_count': total_n,
                'pass_count': pass_n,
                'pass_rate': round((pass_n * 100.0 / total_n), 1) if total_n else 0.0,
                'avg_marks': round(float(avg_marks or 0), 1),
            })

    students = load_students(school_id, term_filter=term)
    per_subject = {}
    for _sid, student in (students or {}).items():
        scores = student.get('scores', {}) if isinstance(student.get('scores', {}), dict) else {}
        for subject, payload in scores.items():
            if not isinstance(payload, dict):
                continue
            score = subject_overall_mark(payload)
            row = per_subject.setdefault(subject, {'subject': subject, 'count': 0, 'sum': 0.0})
            row['count'] += 1
            row['sum'] += float(score or 0)
    for subject, row in sorted(per_subject.items(), key=lambda kv: kv[0].lower()):
        cnt = int(row.get('count', 0))
        subject_rows.append({
            'subject': subject,
            'count': cnt,
            'avg_score': round((row.get('sum', 0.0) / cnt), 1) if cnt else 0.0,
        })

    absent_days_by_student = {}
    if ensure_student_attendance_schema():
        with db_connection() as conn:
            c = conn.cursor()
            db_execute(
                c,
                """SELECT student_id, COUNT(DISTINCT attendance_date) AS absent_days
                   FROM student_attendance
                   WHERE school_id = ?
                     AND COALESCE(term, '') = COALESCE(?, COALESCE(term, ''))
                     AND COALESCE(academic_year, '') = COALESCE(?, COALESCE(academic_year, ''))
                     AND LOWER(status) = 'absent'
                   GROUP BY student_id""",
                (school_id, term or None, academic_year or None),
            )
            for sid, absent_days in c.fetchall() or []:
                key = str(sid or '').strip()
                if not key:
                    continue
                absent_days_by_student[key] = int(absent_days or 0)

    buckets = {
        '0-2': {'label': '0-2 days absent', 'count': 0, 'sum_avg': 0.0},
        '3-5': {'label': '3-5 days absent', 'count': 0, 'sum_avg': 0.0},
        '6+': {'label': '6+ days absent', 'count': 0, 'sum_avg': 0.0},
    }
    for sid, student in (students or {}).items():
        scores = student.get('scores', {}) if isinstance(student.get('scores', {}), dict) else {}
        avg_score = compute_average_marks_from_scores(scores, subjects=student.get('subjects', []))
        absent_days = int(absent_days_by_student.get(str(sid).strip(), 0))
        bucket_key = '0-2' if absent_days <= 2 else ('3-5' if absent_days <= 5 else '6+')
        b = buckets[bucket_key]
        b['count'] += 1
        b['sum_avg'] += float(avg_score or 0.0)
    for key in ('0-2', '3-5', '6+'):
        b = buckets[key]
        attendance_impact_rows.append({
            'label': b['label'],
            'student_count': b['count'],
            'avg_score': round((b['sum_avg'] / b['count']), 1) if b['count'] else 0.0,
        })
    return class_pass_rows, subject_rows, attendance_impact_rows

BACKUP_VERSION_CURRENT = 2
BACKUP_SUPPORTED_VERSIONS = {1, 2}
BACKUP_TABLES_V2 = (
    'students',
    'teachers',
    'class_assignments',
    'teacher_subject_assignments',
    'class_subject_configs',
    'assessment_configs',
    'school_term_calendars',
    'result_publications',
    'published_student_results',
    'result_views',
    'student_attendance',
    'period_attendance',
    'class_timetables',
    'result_disputes',
    'student_messages',
    'teacher_messages',
    'student_message_reads',
    'teacher_message_reads',
    'parent_message_reads',
    'behaviour_assessments',
    'subject_score_submissions',
    'score_audit_logs',
    'promotion_audit_logs',
)

def _backup_table_exists(c, table_name):
    db_execute(
        c,
        """SELECT 1
           FROM information_schema.tables
           WHERE table_schema = 'public'
             AND table_name = ?
           LIMIT 1""",
        (table_name,),
    )
    return bool(c.fetchone())

def _backup_table_has_column(c, table_name, column_name):
    db_execute(
        c,
        """SELECT 1
           FROM information_schema.columns
           WHERE table_schema = 'public'
             AND table_name = ?
             AND column_name = ?
           LIMIT 1""",
        (table_name, column_name),
    )
    return bool(c.fetchone())

def _serialize_backup_row(cols, row):
    payload = {}
    for idx, col in enumerate(cols):
        val = row[idx]
        if isinstance(val, (datetime, date)):
            payload[col] = val.isoformat()
        else:
            payload[col] = val
    return payload

def _build_backup_integrity(unsigned_payload):
    canonical = json.dumps(unsigned_payload, sort_keys=True, separators=(',', ':'), ensure_ascii=True)
    checksum = hashlib.sha256(canonical.encode('utf-8')).hexdigest()
    key = (os.environ.get('BACKUP_SIGNING_KEY', '') or '').strip()
    signature = hmac.new(key.encode('utf-8'), canonical.encode('utf-8'), hashlib.sha256).hexdigest() if key else ''
    return {
        'algo': 'sha256',
        'checksum': checksum,
        'hmac_sha256': signature,
        'signed': bool(signature),
    }

def _verify_backup_payload_integrity(payload):
    integrity = payload.get('integrity') if isinstance(payload.get('integrity'), dict) else {}
    if not integrity:
        return
    algo = (integrity.get('algo') or '').strip().lower()
    if algo != 'sha256':
        raise ValueError('Unsupported backup integrity algorithm.')
    expected_checksum = (integrity.get('checksum') or '').strip().lower()
    if not expected_checksum:
        raise ValueError('Backup integrity checksum is missing.')
    unsigned_payload = {k: v for k, v in payload.items() if k != 'integrity'}
    canonical = json.dumps(unsigned_payload, sort_keys=True, separators=(',', ':'), ensure_ascii=True)
    actual_checksum = hashlib.sha256(canonical.encode('utf-8')).hexdigest().lower()
    if actual_checksum != expected_checksum:
        raise ValueError('Backup checksum verification failed. File may be corrupted or modified.')
    expected_sig = (integrity.get('hmac_sha256') or '').strip().lower()
    if expected_sig:
        key = (os.environ.get('BACKUP_SIGNING_KEY', '') or '').strip()
        if not key:
            raise ValueError('Backup is signed. Set BACKUP_SIGNING_KEY before restore.')
        actual_sig = hmac.new(key.encode('utf-8'), canonical.encode('utf-8'), hashlib.sha256).hexdigest().lower()
        if actual_sig != expected_sig:
            raise ValueError('Backup signature verification failed.')

def _payload_rows(payload, table_name):
    tables = payload.get('tables') if isinstance(payload.get('tables'), dict) else {}
    if isinstance(tables.get(table_name), list):
        return tables.get(table_name) or []
    legacy = payload.get(table_name)
    return legacy if isinstance(legacy, list) else []

def _backup_table_rows(c, table_name, school_id):
    if not _backup_table_exists(c, table_name):
        return []
    if not _backup_table_has_column(c, table_name, 'school_id'):
        return []
    db_execute(c, f"SELECT * FROM {table_name} WHERE school_id = ?", (school_id,))
    cols = [d[0] for d in (c.description or [])]
    return [_serialize_backup_row(cols, row) for row in (c.fetchall() or [])]

def build_school_backup_payload(school_id):
    school = get_school(school_id) or {}
    if not school:
        raise ValueError('School not found for backup.')
    with db_connection() as conn:
        c = conn.cursor()
        table_rows = {}
        for table in BACKUP_TABLES_V2:
            rows = _backup_table_rows(c, table, school_id)
            if rows:
                table_rows[table] = rows
        if _backup_table_exists(c, 'users') and _backup_table_has_column(c, 'users', 'school_id'):
            select_cols = ['username', 'password_hash', 'role', 'school_id', 'terms_accepted']
            for optional_col in ('password_changed_at', 'tutorial_seen_at', 'current_login_at', 'last_login_at', 'created_at'):
                if _backup_table_has_column(c, 'users', optional_col):
                    select_cols.append(optional_col)
            db_execute(
                c,
                f"""SELECT {', '.join(select_cols)}
                    FROM users
                    WHERE school_id = ?
                      AND role IN ('school_admin', 'teacher', 'student')
                    ORDER BY role, username""",
                (school_id,),
            )
            user_rows = [_serialize_backup_row(select_cols, row) for row in (c.fetchall() or [])]
            if user_rows:
                table_rows['users'] = user_rows

        student_rows = table_rows.get('students', [])
        parent_phones = {
            normalize_parent_phone(row.get('parent_phone', ''))
            for row in student_rows
            if normalize_parent_phone(row.get('parent_phone', ''))
        }
        if parent_phones and _backup_table_exists(c, 'parent_tutorial_seen'):
            db_execute(
                c,
                """SELECT parent_phone, seen_at
                   FROM parent_tutorial_seen
                   WHERE parent_phone = ANY(%s)""",
                (list(parent_phones),),
            )
            cols = [d[0] for d in (c.description or [])]
            p_rows = [_serialize_backup_row(cols, row) for row in (c.fetchall() or [])]
            if p_rows:
                table_rows['parent_tutorial_seen'] = p_rows

        row_counts = {name: len(rows or []) for name, rows in table_rows.items()}
        payload = {
            'backup_version': BACKUP_VERSION_CURRENT,
            'created_at': datetime.now().isoformat(),
            'school_id': school_id,
            'school': school,
            'tables': table_rows,
            'manifest': {
                'table_count': len(table_rows),
                'row_counts': row_counts,
                'total_rows': sum(row_counts.values()),
            },
        }
        payload['integrity'] = _build_backup_integrity(payload)
    return payload

def restore_school_backup_payload(school_id, payload, mode='merge'):
    if not isinstance(payload, dict):
        raise ValueError('Invalid backup file format.')
    backup_version = int(payload.get('backup_version') or 1)
    if backup_version not in BACKUP_SUPPORTED_VERSIONS:
        raise ValueError(f'Unsupported backup version: {backup_version}.')
    if (payload.get('school_id') or '').strip() and (payload.get('school_id') or '').strip() != school_id:
        raise ValueError('Backup file belongs to a different school.')
    _verify_backup_payload_integrity(payload)
    mode_clean = (mode or 'merge').strip().lower()
    if mode_clean not in {'merge', 'replace'}:
        raise ValueError('Restore mode must be merge or replace.')
    replace_mode = mode_clean == 'replace'
    ensure_extended_features_schema()
    user_rows = _payload_rows(payload, 'users')
    student_rows = _payload_rows(payload, 'students')
    teacher_rows = _payload_rows(payload, 'teachers')
    class_assignment_rows = _payload_rows(payload, 'class_assignments')
    teacher_subject_rows = _payload_rows(payload, 'teacher_subject_assignments')
    class_subject_rows = _payload_rows(payload, 'class_subject_configs')
    assessment_rows = _payload_rows(payload, 'assessment_configs')
    term_calendar_rows = _payload_rows(payload, 'school_term_calendars')
    result_publication_rows = _payload_rows(payload, 'result_publications')
    published_result_rows = _payload_rows(payload, 'published_student_results')
    student_message_rows = _payload_rows(payload, 'student_messages')
    teacher_message_rows = _payload_rows(payload, 'teacher_messages')
    student_message_read_rows = _payload_rows(payload, 'student_message_reads')
    teacher_message_read_rows = _payload_rows(payload, 'teacher_message_reads')
    parent_message_read_rows = _payload_rows(payload, 'parent_message_reads')
    parent_tutorial_rows = _payload_rows(payload, 'parent_tutorial_seen')
    with db_connection(commit=True) as conn:
        c = conn.cursor()
        school_data = payload.get('school') if isinstance(payload.get('school'), dict) else {}
        if school_data:
            db_execute(
                c,
                """UPDATE schools
                   SET school_name = ?, location = ?, school_logo = ?, academic_year = ?, current_term = ?,
                       test_enabled = ?, exam_enabled = ?, max_tests = ?, test_score_max = ?, exam_objective_max = ?,
                       exam_theory_max = ?, grade_a_min = ?, grade_b_min = ?, grade_c_min = ?, grade_d_min = ?,
                       pass_mark = ?, show_positions = ?, ss_ranking_mode = ?, class_arm_ranking_mode = ?,
                       combine_third_term_results = ?, ss1_stream_mode = ?, theme_primary_color = ?, theme_secondary_color = ?,
                       theme_accent_color = ?, phone = ?, email = ?, principal_name = ?, motto = ?, updated_at = CURRENT_TIMESTAMP
                   WHERE school_id = ?""",
                (
                    school_data.get('school_name', ''),
                    school_data.get('location', ''),
                    school_data.get('school_logo', ''),
                    school_data.get('academic_year', ''),
                    school_data.get('current_term', ''),
                    int(school_data.get('test_enabled', 1) or 1),
                    int(school_data.get('exam_enabled', 1) or 1),
                    int(school_data.get('max_tests', 3) or 3),
                    int(school_data.get('test_score_max', 30) or 30),
                    int(school_data.get('exam_objective_max', 30) or 30),
                    int(school_data.get('exam_theory_max', 40) or 40),
                    int(school_data.get('grade_a_min', 70) or 70),
                    int(school_data.get('grade_b_min', 60) or 60),
                    int(school_data.get('grade_c_min', 50) or 50),
                    int(school_data.get('grade_d_min', 40) or 40),
                    int(school_data.get('pass_mark', 50) or 50),
                    int(school_data.get('show_positions', 1) or 1),
                    school_data.get('ss_ranking_mode', 'together'),
                    school_data.get('class_arm_ranking_mode', 'separate'),
                    int(school_data.get('combine_third_term_results', 0) or 0),
                    school_data.get('ss1_stream_mode', 'separate'),
                    school_data.get('theme_primary_color', '#1E3C72'),
                    school_data.get('theme_secondary_color', '#2A5298'),
                    school_data.get('theme_accent_color', '#1F7A8C'),
                    school_data.get('phone', ''),
                    school_data.get('email', ''),
                    school_data.get('principal_name', ''),
                    school_data.get('motto', ''),
                    school_id,
                ),
            )

        if replace_mode:
            for table in BACKUP_TABLES_V2:
                if _backup_table_exists(c, table) and _backup_table_has_column(c, table, 'school_id'):
                    db_execute(c, f"DELETE FROM {table} WHERE school_id = ?", (school_id,))
            if _backup_table_exists(c, 'users') and _backup_table_has_column(c, 'users', 'school_id'):
                db_execute(
                    c,
                    "DELETE FROM users WHERE school_id = ? AND role IN ('school_admin', 'teacher', 'student')",
                    (school_id,),
                )
            if _backup_table_exists(c, 'parent_tutorial_seen'):
                phones = {
                    normalize_parent_phone(r.get('parent_phone', ''))
                    for r in student_rows
                    if normalize_parent_phone(r.get('parent_phone', ''))
                }
                if phones:
                    db_execute(c, "DELETE FROM parent_tutorial_seen WHERE parent_phone = ANY(%s)", (list(phones),))

        for row in user_rows:
            if not isinstance(row, dict):
                continue
            uname = (row.get('username') or '').strip().lower()
            role = (row.get('role') or '').strip().lower()
            password_hash = (row.get('password_hash') or '').strip()
            if not uname or role not in {'school_admin', 'teacher', 'student'} or not password_hash:
                continue
            existing_user = get_user(uname)
            if existing_user:
                existing_role = (existing_user.get('role') or '').strip().lower()
                existing_school = (existing_user.get('school_id') or '').strip()
                if existing_role != role or existing_school != school_id:
                    raise ValueError(
                        f'Restore blocked: username "{uname}" belongs to another account/school.'
                    )
            upsert_user_with_cursor(c, uname, password_hash, role, school_id, overwrite_identity=True)
            db_execute(
                c,
                """UPDATE users
                   SET terms_accepted = ?
                   WHERE LOWER(username) = LOWER(?)
                     AND CAST(school_id AS TEXT) = ?
                     AND LOWER(COALESCE(role, '')) = LOWER(?)""",
                (int(row.get('terms_accepted', 0) or 0), uname, school_id, role),
            )
            if users_has_password_changed_at_column() and row.get('password_changed_at'):
                db_execute(
                    c,
                    """UPDATE users
                       SET password_changed_at = ?
                       WHERE LOWER(username) = LOWER(?)
                         AND CAST(school_id AS TEXT) = ?
                         AND LOWER(COALESCE(role, '')) = LOWER(?)""",
                    (row.get('password_changed_at'), uname, school_id, role),
                )
            if users_has_tutorial_seen_at_column() and row.get('tutorial_seen_at'):
                db_execute(
                    c,
                    """UPDATE users
                       SET tutorial_seen_at = ?
                       WHERE LOWER(username) = LOWER(?)
                         AND CAST(school_id AS TEXT) = ?
                         AND LOWER(COALESCE(role, '')) = LOWER(?)""",
                    (row.get('tutorial_seen_at'), uname, school_id, role),
                )

        for row in student_rows:
            if not isinstance(row, dict):
                continue
            sid = (row.get('student_id') or '').strip()
            if not sid:
                continue
            student_data = {
                'firstname': row.get('firstname', ''),
                'date_of_birth': row.get('date_of_birth', ''),
                'gender': row.get('gender', ''),
                'classname': row.get('classname', ''),
                'first_year_class': row.get('first_year_class', row.get('classname', '')),
                'term': row.get('term', ''),
                'stream': row.get('stream', 'N/A'),
                'number_of_subject': int(row.get('number_of_subject', 0) or 0),
                'subjects': _safe_json_rows(row.get('subjects')),
                'scores': _safe_json_object(row.get('scores')),
                'promoted': normalize_promoted_db_value(row.get('promoted', 0)),
                'parent_phone': row.get('parent_phone', ''),
                'parent_password_hash': row.get('parent_password_hash', ''),
            }
            save_student_with_cursor(c, school_id, sid, student_data)
            db_execute(c, "SELECT 1 FROM users WHERE LOWER(username) = LOWER(?) LIMIT 1", (sid,))
            if not c.fetchone():
                upsert_user_with_cursor(c, sid, hash_password(DEFAULT_STUDENT_PASSWORD), 'student', school_id)

        for row in teacher_rows:
            if not isinstance(row, dict):
                continue
            tid = (row.get('user_id') or '').strip()
            if not tid:
                continue
            db_execute(
                c,
                """INSERT INTO teachers
                   (school_id, user_id, firstname, lastname, phone, gender, signature_image, profile_image, assigned_classes, subjects_taught)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                   ON CONFLICT (school_id, user_id) DO UPDATE SET
                     firstname = EXCLUDED.firstname,
                     lastname = EXCLUDED.lastname,
                     phone = EXCLUDED.phone,
                     gender = EXCLUDED.gender,
                     profile_image = EXCLUDED.profile_image,
                     assigned_classes = EXCLUDED.assigned_classes,
                     subjects_taught = EXCLUDED.subjects_taught""",
                (
                    school_id,
                    tid,
                    normalize_person_name(row.get('firstname', '')),
                    normalize_person_name(row.get('lastname', '')),
                    (row.get('phone', '') or '').strip(),
                    normalize_teacher_gender(row.get('gender', '')),
                    (row.get('signature_image', '') or '').strip(),
                    (row.get('profile_image', '') or '').strip(),
                    json.dumps(_safe_json_rows(row.get('assigned_classes'))),
                    json.dumps(normalize_subjects_list(row.get('subjects_taught', ''))),
                ),
            )
            db_execute(c, "SELECT 1 FROM users WHERE LOWER(username) = LOWER(?) LIMIT 1", (tid,))
            if not c.fetchone():
                upsert_user_with_cursor(c, tid, hash_password(DEFAULT_TEACHER_PASSWORD), 'teacher', school_id)

        for row in class_assignment_rows:
            if not isinstance(row, dict):
                continue
            db_execute(
                c,
                """DELETE FROM class_assignments
                   WHERE school_id = ? AND LOWER(classname) = LOWER(?) AND LOWER(term) = LOWER(?) AND COALESCE(academic_year, '') = COALESCE(?, '')""",
                (school_id, row.get('classname', ''), row.get('term', ''), row.get('academic_year', '')),
            )
            db_execute(
                c,
                """INSERT INTO class_assignments (school_id, teacher_id, classname, term, academic_year)
                   VALUES (?, ?, ?, ?, ?)""",
                (school_id, row.get('teacher_id', ''), row.get('classname', ''), row.get('term', ''), row.get('academic_year', '')),
            )

        for row in teacher_subject_rows:
            if not isinstance(row, dict):
                continue
            db_execute(
                c,
                """INSERT INTO teacher_subject_assignments (school_id, teacher_id, classname, subject, term, academic_year)
                   VALUES (?, ?, ?, ?, ?, ?)
                   ON CONFLICT (school_id, classname, subject, term, academic_year) DO NOTHING""",
                (school_id, row.get('teacher_id', ''), row.get('classname', ''), row.get('subject', ''), row.get('term', ''), row.get('academic_year', '')),
            )

        for row in class_subject_rows:
            if not isinstance(row, dict):
                continue
            db_execute(
                c,
                """INSERT INTO class_subject_configs
                   (school_id, classname, core_subjects, science_subjects, art_subjects, commercial_subjects, optional_subjects, optional_subject_limit, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                   ON CONFLICT (school_id, classname) DO UPDATE SET
                     core_subjects = EXCLUDED.core_subjects,
                     science_subjects = EXCLUDED.science_subjects,
                     art_subjects = EXCLUDED.art_subjects,
                     commercial_subjects = EXCLUDED.commercial_subjects,
                     optional_subjects = EXCLUDED.optional_subjects,
                     optional_subject_limit = EXCLUDED.optional_subject_limit,
                     updated_at = CURRENT_TIMESTAMP""",
                (
                    school_id,
                    row.get('classname', ''),
                    row.get('core_subjects', '[]'),
                    row.get('science_subjects', '[]'),
                    row.get('art_subjects', '[]'),
                    row.get('commercial_subjects', '[]'),
                    row.get('optional_subjects', '[]'),
                    int(row.get('optional_subject_limit', 0) or 0),
                ),
            )

        for row in assessment_rows:
            if not isinstance(row, dict):
                continue
            db_execute(
                c,
                """INSERT INTO assessment_configs (school_id, level, exam_mode, objective_max, theory_max, exam_score_max, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                   ON CONFLICT (school_id, level) DO UPDATE SET
                     exam_mode = EXCLUDED.exam_mode,
                     objective_max = EXCLUDED.objective_max,
                     theory_max = EXCLUDED.theory_max,
                     exam_score_max = EXCLUDED.exam_score_max,
                     updated_at = CURRENT_TIMESTAMP""",
                (
                    school_id,
                    row.get('level', ''),
                    row.get('exam_mode', 'separate'),
                    int(row.get('objective_max', 30) or 30),
                    int(row.get('theory_max', 40) or 40),
                    int(row.get('exam_score_max', 70) or 70),
                ),
            )

        for row in term_calendar_rows:
            if not isinstance(row, dict):
                continue
            save_school_term_calendar_with_cursor(
                c,
                school_id=school_id,
                academic_year=row.get('academic_year', ''),
                term=row.get('term', ''),
                open_date=row.get('open_date', ''),
                close_date=row.get('close_date', ''),
                break_start=row.get('midterm_break_start', ''),
                break_end=row.get('midterm_break_end', ''),
                next_term_begin_date=row.get('next_term_begin_date', ''),
            )

        for row in result_publication_rows:
            if not isinstance(row, dict):
                continue
            db_execute(
                c,
                """INSERT INTO result_publications
                   (school_id, classname, term, academic_year, teacher_id, teacher_name, principal_name, is_published, published_at, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                   ON CONFLICT (school_id, classname, term, academic_year) DO UPDATE SET
                     teacher_id = EXCLUDED.teacher_id,
                     teacher_name = EXCLUDED.teacher_name,
                     principal_name = EXCLUDED.principal_name,
                     is_published = EXCLUDED.is_published,
                     published_at = EXCLUDED.published_at,
                     updated_at = CURRENT_TIMESTAMP""",
                (
                    school_id,
                    row.get('classname', ''),
                    row.get('term', ''),
                    row.get('academic_year', ''),
                    row.get('teacher_id', ''),
                    row.get('teacher_name', ''),
                    row.get('principal_name', ''),
                    int(row.get('is_published', 0) or 0),
                    row.get('published_at', None),
                ),
            )

        for row in published_result_rows:
            if not isinstance(row, dict):
                continue
            db_execute(
                c,
                """INSERT INTO published_student_results
                   (school_id, student_id, firstname, classname, academic_year, term, stream, number_of_subject, subjects, scores,
                    behaviour_json, teacher_comment, principal_comment, average_marks, grade, status, published_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                   ON CONFLICT (school_id, student_id, academic_year, term) DO UPDATE SET
                     firstname = EXCLUDED.firstname,
                     classname = EXCLUDED.classname,
                     stream = EXCLUDED.stream,
                     number_of_subject = EXCLUDED.number_of_subject,
                     subjects = EXCLUDED.subjects,
                     scores = EXCLUDED.scores,
                     behaviour_json = EXCLUDED.behaviour_json,
                     teacher_comment = EXCLUDED.teacher_comment,
                     principal_comment = EXCLUDED.principal_comment,
                     average_marks = EXCLUDED.average_marks,
                     grade = EXCLUDED.grade,
                     status = EXCLUDED.status,
                     published_at = EXCLUDED.published_at""",
                (
                    school_id,
                    row.get('student_id', ''),
                    row.get('firstname', ''),
                    row.get('classname', ''),
                    row.get('academic_year', ''),
                    row.get('term', ''),
                    row.get('stream', 'N/A'),
                    int(row.get('number_of_subject', 0) or 0),
                    row.get('subjects', '[]'),
                    row.get('scores', '{}'),
                    row.get('behaviour_json', '{}'),
                    row.get('teacher_comment', ''),
                    row.get('principal_comment', ''),
                    float(row.get('average_marks', 0) or 0),
                    row.get('grade', ''),
                    row.get('status', ''),
                    row.get('published_at', None),
                ),
            )

        for row in student_message_rows:
            if not isinstance(row, dict):
                continue
            db_execute(
                c,
                """INSERT INTO student_messages
                   (school_id, title, message, target_classname, target_stream, deadline_date, is_active, created_by, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, COALESCE(?, CURRENT_TIMESTAMP))""",
                (
                    school_id,
                    row.get('title', ''),
                    row.get('message', ''),
                    row.get('target_classname', ''),
                    row.get('target_stream', ''),
                    row.get('deadline_date', ''),
                    int(row.get('is_active', 1) or 1),
                    row.get('created_by', ''),
                    row.get('created_at', None),
                ),
            )

        for row in teacher_message_rows:
            if not isinstance(row, dict):
                continue
            db_execute(
                c,
                """INSERT INTO teacher_messages
                   (school_id, title, message, target_classname, target_subject, deadline_date, is_active, created_by, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, COALESCE(?, CURRENT_TIMESTAMP))""",
                (
                    school_id,
                    row.get('title', ''),
                    row.get('message', ''),
                    row.get('target_classname', ''),
                    row.get('target_subject', ''),
                    row.get('deadline_date', ''),
                    int(row.get('is_active', 1) or 1),
                    row.get('created_by', ''),
                    row.get('created_at', None),
                ),
            )

        for row in student_message_read_rows:
            if not isinstance(row, dict):
                continue
            db_execute(
                c,
                """INSERT INTO student_message_reads (school_id, message_id, student_id, read_at)
                   VALUES (?, ?, ?, COALESCE(?, CURRENT_TIMESTAMP))
                   ON CONFLICT (school_id, message_id, student_id) DO UPDATE
                   SET read_at = EXCLUDED.read_at""",
                (school_id, int(row.get('message_id', 0) or 0), row.get('student_id', ''), row.get('read_at', None)),
            )

        for row in teacher_message_read_rows:
            if not isinstance(row, dict):
                continue
            db_execute(
                c,
                """INSERT INTO teacher_message_reads (school_id, message_id, teacher_id, read_at)
                   VALUES (?, ?, ?, COALESCE(?, CURRENT_TIMESTAMP))
                   ON CONFLICT (school_id, message_id, teacher_id) DO UPDATE
                   SET read_at = EXCLUDED.read_at""",
                (school_id, int(row.get('message_id', 0) or 0), row.get('teacher_id', ''), row.get('read_at', None)),
            )

        for row in parent_message_read_rows:
            if not isinstance(row, dict):
                continue
            phone = normalize_parent_phone(row.get('parent_phone', ''))
            if not phone:
                continue
            db_execute(
                c,
                """INSERT INTO parent_message_reads (school_id, message_id, parent_phone, read_at)
                   VALUES (?, ?, ?, COALESCE(?, CURRENT_TIMESTAMP))
                   ON CONFLICT (school_id, message_id, parent_phone) DO UPDATE
                   SET read_at = EXCLUDED.read_at""",
                (school_id, int(row.get('message_id', 0) or 0), phone, row.get('read_at', None)),
            )

        for row in parent_tutorial_rows:
            if not isinstance(row, dict):
                continue
            phone = normalize_parent_phone(row.get('parent_phone', ''))
            if not phone:
                continue
            db_execute(
                c,
                """INSERT INTO parent_tutorial_seen (parent_phone, seen_at)
                   VALUES (?, COALESCE(?, CURRENT_TIMESTAMP))
                   ON CONFLICT (parent_phone) DO UPDATE
                   SET seen_at = EXCLUDED.seen_at""",
                (phone, row.get('seen_at', None)),
            )

# ==================== TEACHER FUNCTIONS ====================

def set_teacher_signature(school_id, teacher_id, signature_image):
    """Store teacher signature image for result authorization."""
    with db_connection(commit=True) as conn:
        c = conn.cursor()
        db_execute(
            c,
            """UPDATE teachers
               SET signature_image = ?
               WHERE school_id = ? AND user_id = ?""",
            (signature_image, school_id, teacher_id),
        )

def set_teacher_profile_image(school_id, teacher_id, profile_image):
    """Store teacher profile image for dashboard/sidebar avatar."""
    with db_connection(commit=True) as conn:
        c = conn.cursor()
        try:
            db_execute(
                c,
                """UPDATE teachers
                   SET profile_image = ?
                   WHERE school_id = ? AND user_id = ?""",
                (profile_image, school_id, teacher_id),
            )
            return True
        except Exception:
            try:
                conn.rollback()
            except Exception:
                pass
            return False

def set_principal_signature(school_id, signature_image):
    """Store principal signature image for result authorization."""
    with db_connection(commit=True) as conn:
        c = conn.cursor()
        db_execute(
            c,
            """UPDATE schools
               SET principal_signature_image = ?, updated_at = ?
               WHERE school_id = ?""",
            (signature_image, datetime.now(), school_id),
        )

def ensure_subject_score_submission_schema():
    """Ensure subject-teacher handoff table exists."""
    try:
        with db_connection(commit=True) as conn:
            c = conn.cursor()
            db_execute(
                c,
                """CREATE TABLE IF NOT EXISTS subject_score_submissions (
                       id SERIAL PRIMARY KEY,
                       school_id TEXT NOT NULL,
                       teacher_id TEXT NOT NULL,
                       classname TEXT NOT NULL,
                       term TEXT NOT NULL,
                       academic_year TEXT NOT NULL,
                       submitted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                       UNIQUE(school_id, teacher_id, classname, term, academic_year)
                   )""",
            )
            db_execute(
                c,
                'CREATE INDEX IF NOT EXISTS idx_subject_score_submissions_lookup ON subject_score_submissions(school_id, teacher_id, classname, term, academic_year)',
            )
        return True
    except Exception:
        return False

def get_subject_score_submission_map(school_id, teacher_id, term, academic_year):
    """Return class -> submitted_at for one teacher and term/year."""
    if not ensure_subject_score_submission_schema():
        return {}
    with db_connection() as conn:
        c = conn.cursor()
        db_execute(
            c,
            """SELECT classname, submitted_at
               FROM subject_score_submissions
               WHERE school_id = ? AND teacher_id = ? AND term = ? AND academic_year = ?""",
            (school_id, teacher_id, term, academic_year or ''),
        )
        out = {}
        for row in c.fetchall() or []:
            out[(row[0] or '').strip()] = row[1] or ''
    return out

def get_subject_submission_teacher_ids_for_class(school_id, classname, term, academic_year):
    """Return teacher IDs that have submitted subject scores for one class/term/year."""
    if not ensure_subject_score_submission_schema():
        return set()
    with db_connection() as conn:
        c = conn.cursor()
        db_execute(
            c,
            """SELECT DISTINCT teacher_id
               FROM subject_score_submissions
               WHERE school_id = ? AND LOWER(classname) = LOWER(?) AND LOWER(term) = LOWER(?) AND academic_year = ?""",
            (school_id, classname, term, academic_year),
        )
        rows = c.fetchall() or []
    return {(row[0] or '').strip() for row in rows if row and (row[0] or '').strip()}

def mark_subject_score_submitted(school_id, teacher_id, classname, term, academic_year):
    """Mark one class as submitted by a subject teacher."""
    if not ensure_subject_score_submission_schema():
        return False
    with db_connection(commit=True) as conn:
        c = conn.cursor()
        db_execute(
            c,
            """INSERT INTO subject_score_submissions
               (school_id, teacher_id, classname, term, academic_year, submitted_at)
               VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
               ON CONFLICT(school_id, teacher_id, classname, term, academic_year)
               DO UPDATE SET submitted_at = CURRENT_TIMESTAMP""",
            (school_id, teacher_id, classname, term, academic_year or ''),
        )
    return True

def clear_subject_score_submission(school_id, teacher_id, classname, term, academic_year):
    """Clear submission state when subject score changes after submit."""
    if not ensure_subject_score_submission_schema():
        return
    with db_connection(commit=True) as conn:
        c = conn.cursor()
        db_execute(
            c,
            """DELETE FROM subject_score_submissions
               WHERE school_id = ? AND teacher_id = ? AND LOWER(classname) = LOWER(?)
                 AND term = ? AND academic_year = ?""",
            (school_id, teacher_id, classname, term, academic_year or ''),
        )

def get_result_signoff_details(school_id, classname, term, academic_year=''):
    """Resolve signature images and signer names for published result authorization."""
    principal_signature = ''
    principal_name = ''
    school = get_school(school_id) or {}
    principal_signature = school.get('principal_signature_image', '') or ''
    principal_name = (school.get('principal_name', '') or '').strip()
    teacher_signature = ''
    teacher_name = ''
    if not school_id or not classname or not term:
        return {
            'teacher_signature': teacher_signature,
            'principal_signature': principal_signature,
            'teacher_name': teacher_name,
            'principal_name': principal_name,
        }
    with db_connection() as conn:
        c = conn.cursor()
        db_execute(
            c,
            """SELECT teacher_id, teacher_name, principal_name
               FROM result_publications
               WHERE school_id = ? AND classname = ? AND term = ? AND COALESCE(academic_year, '') = COALESCE(?, '')
               LIMIT 1""",
            (school_id, classname, term, academic_year or ''),
        )
        row = c.fetchone()
        if row and row[0]:
            teacher_id = row[0]
            published_teacher_name = (row[1] or '').strip()
            published_principal_name = (row[2] or '').strip()
            if published_principal_name:
                principal_name = published_principal_name
            db_execute(
                c,
                """SELECT firstname, lastname, signature_image
                   FROM teachers
                   WHERE school_id = ? AND user_id = ?
                   LIMIT 1""",
                (school_id, teacher_id),
            )
            teacher_row = c.fetchone()
            if teacher_row:
                live_teacher_name = f"{teacher_row[0] or ''} {teacher_row[1] or ''}".strip() or str(teacher_id)
                teacher_name = published_teacher_name or live_teacher_name
                teacher_signature = teacher_row[2] or ''
            else:
                teacher_name = published_teacher_name or str(teacher_id)
    return {
        'teacher_signature': teacher_signature,
        'principal_signature': principal_signature,
        'teacher_name': teacher_name,
        'principal_name': principal_name,
    }

def normalize_teacher_gender(value):
    raw = (value or '').strip().lower()
    if raw in {'male', 'm'}:
        return 'male'
    if raw in {'female', 'f'}:
        return 'female'
    if raw in {'other', 'o'}:
        return 'other'
    return ''

def get_teacher(school_id, teacher_id):
    """Get one teacher profile for a school."""
    sid = (school_id or '').strip()
    tid = (teacher_id or '').strip()
    if not sid or not tid:
        return {}
    with db_connection() as conn:
        c = conn.cursor()
        has_profile_image_col = True
        try:
            db_execute(
                c,
                """SELECT user_id, firstname, lastname, phone, gender, signature_image, profile_image, assigned_classes, subjects_taught
                   FROM teachers
                   WHERE school_id = ? AND user_id = ?
                   LIMIT 1""",
                (sid, tid),
            )
        except Exception:
            has_profile_image_col = False
            try:
                conn.rollback()
            except Exception:
                pass
            db_execute(
                c,
                """SELECT user_id, firstname, lastname, phone, gender, signature_image, assigned_classes, subjects_taught
                   FROM teachers
                   WHERE school_id = ? AND user_id = ?
                   LIMIT 1""",
                (sid, tid),
            )
        row = c.fetchone()
    if not row:
        return {}
    raw_subjects = row[8] if has_profile_image_col and len(row) > 8 else (row[7] if len(row) > 7 else '')
    try:
        subjects_taught = normalize_subjects_list(json.loads(raw_subjects) if raw_subjects else [])
    except Exception:
        subjects_taught = normalize_subjects_list(raw_subjects or '')
    assigned_classes_raw = row[7] if has_profile_image_col and len(row) > 7 else (row[6] if len(row) > 6 else '')
    return {
        'firstname': row[1],
        'lastname': row[2],
        'phone': (row[3] or '').strip() if len(row) > 3 else '',
        'gender': normalize_teacher_gender(row[4] if len(row) > 4 else ''),
        'signature_image': row[5] or '',
        'profile_image': (row[6] or '') if has_profile_image_col and len(row) > 6 else '',
        'assigned_classes': json.loads(assigned_classes_raw) if assigned_classes_raw else [],
        'subjects_taught': subjects_taught,
    }

def get_teachers(school_id, include_archived=False):
    """Get all teachers for a school."""
    has_archive_cols = teachers_has_archive_columns()
    with db_connection() as conn:
        c = conn.cursor()
        has_profile_image_col = True
        try:
            archived_where = '' if (include_archived or not has_archive_cols) else ' AND COALESCE(is_archived, 0) = 0'
            archive_col = ', COALESCE(is_archived, 0)' if has_archive_cols else ''
            db_execute(c, f"""SELECT user_id, firstname, lastname, phone, gender, signature_image, profile_image, assigned_classes, subjects_taught{archive_col} FROM teachers 
                           WHERE school_id = ?{archived_where}""", (school_id,))
        except Exception:
            has_profile_image_col = False
            try:
                conn.rollback()
            except Exception:
                pass
            archived_where = '' if (include_archived or not has_archive_cols) else ' AND COALESCE(is_archived, 0) = 0'
            archive_col = ', COALESCE(is_archived, 0)' if has_archive_cols else ''
            db_execute(c, f"""SELECT user_id, firstname, lastname, phone, gender, signature_image, assigned_classes, subjects_taught{archive_col} FROM teachers 
                           WHERE school_id = ?{archived_where}""", (school_id,))
        teachers = {}
        for row in c.fetchall():
            raw_subjects = row[8] if has_profile_image_col and len(row) > 8 else (row[7] if len(row) > 7 else '')
            try:
                subjects_taught = normalize_subjects_list(json.loads(raw_subjects) if raw_subjects else [])
            except Exception:
                subjects_taught = normalize_subjects_list(raw_subjects or '')
            assigned_classes_raw = row[7] if has_profile_image_col and len(row) > 7 else (row[6] if len(row) > 6 else '')
            archive_idx = (9 if has_profile_image_col else 8) if has_archive_cols else None
            teachers[row[0]] = {
                'firstname': row[1],
                'lastname': row[2],
                'phone': (row[3] or '').strip() if len(row) > 3 else '',
                'gender': normalize_teacher_gender(row[4] if len(row) > 4 else ''),
                'signature_image': row[5] or '',
                'profile_image': (row[6] or '') if has_profile_image_col and len(row) > 6 else '',
                'assigned_classes': json.loads(assigned_classes_raw) if assigned_classes_raw else [],
                'subjects_taught': subjects_taught,
                'is_archived': int(row[archive_idx] or 0) if archive_idx is not None else 0,
            }
        return teachers

def save_teacher(school_id, user_id, firstname, lastname, assigned_classes, subjects_taught=None, phone='', gender=''):
    """Save a teacher."""
    with db_connection(commit=True) as conn:
        c = conn.cursor()
        firstname = normalize_person_name(firstname)
        lastname = normalize_person_name(lastname)
        phone = (phone or '').strip()
        gender = normalize_teacher_gender(gender)
        classes_str = json.dumps(assigned_classes)
        subjects_str = json.dumps(normalize_subjects_list(subjects_taught or []))
        # Check if teacher exists
        db_execute(c, 'SELECT user_id FROM teachers WHERE school_id = ? AND user_id = ?', (school_id, user_id))
        if c.fetchone():
            # Update existing teacher
            db_execute(c, 'UPDATE teachers SET firstname = ?, lastname = ?, phone = ?, gender = ?, assigned_classes = ?, subjects_taught = ? WHERE school_id = ? AND user_id = ?',
                       (firstname, lastname, phone, gender, classes_str, subjects_str, school_id, user_id))
        else:
            # Insert new teacher
            try:
                db_execute(c, 'INSERT INTO teachers (school_id, user_id, firstname, lastname, phone, gender, signature_image, profile_image, assigned_classes, subjects_taught) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
                           (school_id, user_id, firstname, lastname, phone, gender, '', '', classes_str, subjects_str))
            except Exception:
                try:
                    conn.rollback()
                except Exception:
                    pass
                db_execute(c, 'INSERT INTO teachers (school_id, user_id, firstname, lastname, phone, gender, signature_image, assigned_classes, subjects_taught) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
                           (school_id, user_id, firstname, lastname, phone, gender, '', classes_str, subjects_str))

def archive_teacher_account(school_id, teacher_id, archived_by=''):
    """Soft archive one teacher and clear active assignments."""
    if not teachers_has_archive_columns():
        raise ValueError('Teacher archive schema is unavailable. Run migration/startup DDL and retry.')
    with db_connection(commit=True) as conn:
        c = conn.cursor()
        db_execute(
            c,
            """UPDATE teachers
               SET is_archived = 1,
                   archived_at = CURRENT_TIMESTAMP
               WHERE school_id = ? AND user_id = ?""",
            (school_id, teacher_id),
        )
        db_execute(c, 'DELETE FROM class_assignments WHERE school_id = ? AND teacher_id = ?', (school_id, teacher_id))
        db_execute(c, 'DELETE FROM teacher_subject_assignments WHERE school_id = ? AND teacher_id = ?', (school_id, teacher_id))
    if archived_by:
        logging.info("Teacher archived by=%s school_id=%s teacher_id=%s", archived_by, school_id, teacher_id)

def restore_teacher_account(school_id, teacher_id, restored_by=''):
    """Restore one archived teacher."""
    if not teachers_has_archive_columns():
        raise ValueError('Teacher archive schema is unavailable. Run migration/startup DDL and retry.')
    with db_connection(commit=True) as conn:
        c = conn.cursor()
        db_execute(
            c,
            """UPDATE teachers
               SET is_archived = 0,
                   archived_at = NULL
               WHERE school_id = ? AND user_id = ?""",
            (school_id, teacher_id),
        )
    if restored_by:
        logging.info("Teacher restored by=%s school_id=%s teacher_id=%s", restored_by, school_id, teacher_id)

def assign_teacher_to_class(school_id, teacher_id, classname, term, academic_year):
    """Assign teacher to a class."""
    with db_connection(commit=True) as conn:
        c = conn.cursor()
        if not academic_year:
            school = get_school(school_id) or {}
            academic_year = (school.get('academic_year', '') or '').strip()
        if not academic_year:
            raise ValueError('Academic year is required for class assignment.')
        classname = ' '.join((classname or '').strip().split())
        term = ' '.join((term or '').strip().split())
        db_execute(
            c,
            """SELECT 1 FROM teachers
               WHERE school_id = ? AND user_id = ?
               LIMIT 1""",
            (school_id, teacher_id),
        )
        if not c.fetchone():
            raise ValueError('Selected teacher is not registered in this school.')
        db_execute(
            c,
            """SELECT teacher_id FROM class_assignments
               WHERE school_id = ? AND LOWER(classname) = LOWER(?) AND LOWER(term) = LOWER(?) AND academic_year = ?
               LIMIT 1""",
            (school_id, classname, term, academic_year)
        )
        row = c.fetchone()
        if row and row[0] != teacher_id:
            raise ValueError(f'Class {classname} ({term}, {academic_year}) is already assigned to another teacher.')
        db_execute(c, """INSERT INTO class_assignments
                       (school_id, teacher_id, classname, term, academic_year)
                       VALUES (?, ?, ?, ?, ?)
                       ON CONFLICT(school_id, teacher_id, classname, term, academic_year)
                       DO UPDATE SET academic_year = excluded.academic_year""",
                   (school_id, teacher_id, classname, term, academic_year))

def assign_teacher_to_subjects(school_id, teacher_id, classname, subjects, term, academic_year):
    """Add/keep teacher subject assignments for a class in a term/year."""
    cleaned_subjects = normalize_subjects_list(subjects or [])
    if not cleaned_subjects:
        raise ValueError('Select at least one subject.')
    with db_connection(commit=True) as conn:
        c = conn.cursor()
        if not academic_year:
            school = get_school(school_id) or {}
            academic_year = (school.get('academic_year', '') or '').strip()
        if not academic_year:
            raise ValueError('Academic year is required for subject assignment.')
        classname = ' '.join((classname or '').strip().split())
        term = ' '.join((term or '').strip().split())
        db_execute(
            c,
            """SELECT 1 FROM teachers
               WHERE school_id = ? AND user_id = ?
               LIMIT 1""",
            (school_id, teacher_id),
        )
        if not c.fetchone():
            raise ValueError('Selected teacher is not registered in this school.')
        db_execute(
            c,
            """SELECT subject
               FROM teacher_subject_assignments
               WHERE school_id = ? AND teacher_id = ? AND LOWER(classname) = LOWER(?)
                 AND LOWER(term) = LOWER(?) AND academic_year = ?""",
            (school_id, teacher_id, classname, term, academic_year),
        )
        existing_subjects = normalize_subjects_list([row[0] for row in (c.fetchall() or []) if row and row[0]])
        merged_subjects = normalize_subjects_list(list(existing_subjects) + list(cleaned_subjects))
        for subject in merged_subjects:
            db_execute(
                c,
                """SELECT teacher_id
                   FROM teacher_subject_assignments
                   WHERE school_id = ? AND LOWER(classname) = LOWER(?) AND LOWER(subject) = LOWER(?)
                     AND LOWER(term) = LOWER(?) AND academic_year = ?
                   LIMIT 1""",
                (school_id, classname, subject, term, academic_year),
            )
            owner_row = c.fetchone()
            owner_teacher_id = (owner_row[0] or '').strip() if owner_row else ''
            if owner_teacher_id and owner_teacher_id != teacher_id:
                raise ValueError(
                    f'{subject} in {classname} ({term}, {academic_year}) is already assigned to another teacher. '
                    'Remove the current assignment first.'
                )
            db_execute(
                c,
                """INSERT INTO teacher_subject_assignments
                   (school_id, teacher_id, classname, subject, term, academic_year)
                   VALUES (?, ?, ?, ?, ?, ?)
                   ON CONFLICT(school_id, classname, subject, term, academic_year)
                   DO NOTHING""",
                (school_id, teacher_id, classname, subject, term, academic_year),
            )

def remove_teacher_subject_assignment(school_id, teacher_id, classname, subject, term, academic_year):
    """Remove one teacher-subject assignment."""
    with db_connection(commit=True) as conn:
        c = conn.cursor()
        db_execute(
            c,
            """DELETE FROM teacher_subject_assignments
               WHERE school_id = ? AND teacher_id = ? AND LOWER(classname) = LOWER(?)
                 AND LOWER(subject) = LOWER(?) AND LOWER(term) = LOWER(?) AND academic_year = ?""",
            (school_id, teacher_id, classname, subject, term, academic_year),
        )

def get_teacher_subject_assignments(school_id, teacher_id='', classname='', term='', academic_year=''):
    """List subject assignments, optionally filtered."""
    with db_connection() as conn:
        c = conn.cursor()
        where = ['tsa.school_id = ?']
        params = [school_id]
        if teacher_id:
            where.append('tsa.teacher_id = ?')
            params.append(teacher_id)
        if classname:
            where.append('LOWER(tsa.classname) = LOWER(?)')
            params.append(classname)
        if term:
            where.append('LOWER(tsa.term) = LOWER(?)')
            params.append(term)
        if academic_year:
            where.append('tsa.academic_year = ?')
            params.append(academic_year)
        db_execute(
            c,
            f"""SELECT tsa.teacher_id, tsa.classname, tsa.subject, tsa.term, tsa.academic_year,
                       t.firstname, t.lastname
                FROM teacher_subject_assignments tsa
                LEFT JOIN teachers t ON t.user_id = tsa.teacher_id AND t.school_id = tsa.school_id
                WHERE {' AND '.join(where)}
                ORDER BY tsa.classname, tsa.subject, tsa.term, tsa.teacher_id""",
            tuple(params),
        )
        rows = c.fetchall()
    out = []
    for row in rows:
        teacher_id_row, cls, subject, row_term, row_year, firstname, lastname = row
        teacher_name = f"{firstname or ''} {lastname or ''}".strip() or teacher_id_row
        out.append({
            'teacher_id': teacher_id_row,
            'teacher_name': teacher_name,
            'classname': cls,
            'subject': subject,
            'term': row_term,
            'academic_year': row_year,
        })
    return out

def remove_teacher_from_class(school_id, teacher_id, classname, term, academic_year):
    """Remove teacher assignment from a class/term."""
    with db_connection(commit=True) as conn:
        c = conn.cursor()
        db_execute(
            c,
            """DELETE FROM class_assignments
               WHERE school_id = ? AND teacher_id = ? AND LOWER(classname) = LOWER(?) AND LOWER(term) = LOWER(?) AND academic_year = ?""",
            (school_id, teacher_id, classname, term, academic_year)
        )

def get_class_assignments(school_id):
    """Get class assignments with teacher display names."""
    with db_connection() as conn:
        c = conn.cursor()
        db_execute(
            c,
            """SELECT ca.teacher_id, ca.classname, ca.term, ca.academic_year, t.firstname, t.lastname
               FROM class_assignments ca
               LEFT JOIN teachers t ON t.user_id = ca.teacher_id AND t.school_id = ca.school_id
               WHERE ca.school_id = ?
               ORDER BY ca.classname, ca.term, ca.teacher_id""",
            (school_id,)
        )
        rows = c.fetchall()

    assignments = []
    for row in rows:
        teacher_id, classname, term, academic_year, firstname, lastname = row
        teacher_name = f"{firstname or ''} {lastname or ''}".strip() or teacher_id
        assignments.append({
            'teacher_id': teacher_id,
            'teacher_name': teacher_name,
            'classname': classname,
            'term': term,
            'academic_year': academic_year,
        })
    return assignments

def get_teacher_classes(school_id, teacher_id, term='', academic_year=''):
    """Get classes assigned to a teacher."""
    with db_connection() as conn:
        c = conn.cursor()
        where = ['school_id = ?', 'teacher_id = ?']
        params = [school_id, teacher_id]
        if term:
            where.append('LOWER(term) = LOWER(?)')
            params.append(term)
        if academic_year:
            where.append('academic_year = ?')
            params.append(academic_year)
        db_execute(c, f"""SELECT DISTINCT classname FROM class_assignments 
                       WHERE {' AND '.join(where)}""",
                   tuple(params))
        return [row[0] for row in c.fetchall()]

def teacher_has_class_access(school_id, teacher_id, classname, term='', academic_year=''):
    """Check whether teacher is assigned to a class."""
    if not classname:
        return False
    target = (classname or '').strip().lower()
    classes = {(c or '').strip().lower() for c in get_teacher_classes(school_id, teacher_id, term=term, academic_year=academic_year)}
    return target in classes

def get_teacher_subjects(school_id, teacher_id):
    """Return normalized subject list configured for a teacher."""
    profile = get_teachers(school_id).get(teacher_id, {})
    return normalize_subjects_list(profile.get('subjects_taught', []))

def get_teacher_subjects_for_class_term(school_id, teacher_id, classname, term='', academic_year=''):
    """Return teacher subjects assigned for a specific class/term/year."""
    rows = get_teacher_subject_assignments(
        school_id,
        teacher_id=teacher_id,
        classname=classname,
        term=term,
        academic_year=academic_year,
    )
    return normalize_subjects_list([r.get('subject', '') for r in rows])

def get_teacher_subject_assignment_history(school_id, teacher_id):
    rows = get_teacher_subject_assignments(school_id, teacher_id=teacher_id)
    years = sorted({(r.get('academic_year') or '').strip() for r in rows if (r.get('academic_year') or '').strip()}, reverse=True)
    terms_by_year = {}
    for year in years:
        term_set = {(r.get('term') or '').strip() for r in rows if (r.get('academic_year') or '').strip() == year and (r.get('term') or '').strip()}
        terms_by_year[year] = sorted(term_set, key=lambda t: term_sort_value(t))
    return rows, years, terms_by_year

def teacher_can_score_subject(school_id, teacher_id, classname, subject_name, term='', academic_year=''):
    """Whether teacher can score one subject in a class/term."""
    if teacher_has_class_access(school_id, teacher_id, classname, term=term, academic_year=academic_year):
        return True
    assigned = get_teacher_subjects_for_class_term(
        school_id, teacher_id, classname, term=term, academic_year=academic_year
    )
    target = normalize_subject_name(subject_name or '')
    return target in set(assigned)

def create_student_message(school_id, title, message, target_classname='', target_stream='', deadline_date='', created_by=''):
    """Create one school-admin message targeted to students."""
    clean_title = (title or '').strip()[:160]
    clean_message = (message or '').strip()[:3000]
    clean_class = canonicalize_classname(target_classname) if (target_classname or '').strip() else ''
    clean_stream = (target_stream or '').strip().title()
    clean_deadline = (deadline_date or '').strip()
    if not clean_title:
        raise ValueError('Message title is required.')
    if not clean_message:
        raise ValueError('Message body is required.')
    if clean_stream and clean_stream not in {'Science', 'Art', 'Commercial'}:
        raise ValueError('Invalid stream for message target.')
    if clean_deadline and not _parse_iso_date(clean_deadline):
        raise ValueError('Deadline must be in YYYY-MM-DD format.')
    with db_connection(commit=True) as conn:
        c = conn.cursor()
        db_execute(
            c,
            """INSERT INTO student_messages
               (school_id, title, message, target_classname, target_stream, deadline_date, is_active, created_by, created_at)
               VALUES (?, ?, ?, ?, ?, ?, 1, ?, CURRENT_TIMESTAMP)""",
            (school_id, clean_title, clean_message, clean_class, clean_stream, clean_deadline, (created_by or '').strip()),
        )

def get_school_student_messages(school_id, limit=20):
    """List latest student messages for school-admin dashboard."""
    with db_connection() as conn:
        c = conn.cursor()
        db_execute(
            c,
            """SELECT id, title, message, target_classname, target_stream, deadline_date, is_active, created_by, created_at
               FROM student_messages
               WHERE school_id = ?
               ORDER BY created_at DESC
               LIMIT ?""",
            (school_id, int(max(1, min(limit, 100)))),
        )
        rows = c.fetchall() or []
    out = []
    today = date.today()
    for row in rows:
        deadline_raw = (row[5] or '').strip()
        deadline_dt = _parse_iso_date(deadline_raw) if deadline_raw else None
        out.append({
            'id': int(row[0] or 0),
            'title': row[1] or '',
            'message': row[2] or '',
            'target_classname': row[3] or '',
            'target_stream': row[4] or '',
            'deadline_date': deadline_raw,
            'is_active': bool(int(row[6] or 0)),
            'created_by': row[7] or '',
            'created_at': format_timestamp(row[8]),
            'is_expired': bool(deadline_dt and deadline_dt < today),
        })
    return out

def create_teacher_message(school_id, title, message, target_classname='', target_subject='', deadline_date='', created_by=''):
    """Create one school-admin message targeted to teachers."""
    if not ensure_extended_features_schema():
        raise ValueError('Teacher messaging schema is not ready. Run migrations/db health fixes first.')
    clean_title = (title or '').strip()[:160]
    clean_message = (message or '').strip()[:3000]
    clean_class = canonicalize_classname(target_classname) if (target_classname or '').strip() else ''
    clean_subject = normalize_subject_name(target_subject) if (target_subject or '').strip() else ''
    clean_deadline = (deadline_date or '').strip()
    if not clean_title:
        raise ValueError('Message title is required.')
    if not clean_message:
        raise ValueError('Message body is required.')
    if clean_deadline and not _parse_iso_date(clean_deadline):
        raise ValueError('Deadline must be in YYYY-MM-DD format.')
    with db_connection(commit=True) as conn:
        c = conn.cursor()
        db_execute(
            c,
            """INSERT INTO teacher_messages
               (school_id, title, message, target_classname, target_subject, deadline_date, is_active, created_by, created_at)
               VALUES (?, ?, ?, ?, ?, ?, 1, ?, CURRENT_TIMESTAMP)""",
            (school_id, clean_title, clean_message, clean_class, clean_subject, clean_deadline, (created_by or '').strip()),
        )

def get_school_teacher_messages(school_id, limit=20):
    """List latest teacher messages for school-admin dashboard."""
    if not ensure_extended_features_schema():
        return []
    with db_connection() as conn:
        c = conn.cursor()
        try:
            db_execute(
                c,
                """SELECT id, title, message, target_classname, target_subject, deadline_date, is_active, created_by, created_at
                   FROM teacher_messages
                   WHERE school_id = ?
                   ORDER BY created_at DESC
                   LIMIT ?""",
                (school_id, int(max(1, min(limit, 100)))),
            )
            rows = c.fetchall() or []
        except Exception as exc:
            msg = str(exc).lower()
            if 'teacher_messages' in msg or 'undefinedtable' in msg:
                logging.warning('Teacher messaging table missing: %s', exc)
                return []
            raise
    out = []
    today = date.today()
    for row in rows:
        deadline_raw = (row[5] or '').strip()
        deadline_dt = _parse_iso_date(deadline_raw) if deadline_raw else None
        out.append({
            'id': int(row[0] or 0),
            'title': row[1] or '',
            'message': row[2] or '',
            'target_classname': row[3] or '',
            'target_subject': row[4] or '',
            'deadline_date': deadline_raw,
            'is_active': bool(int(row[6] or 0)),
            'created_by': row[7] or '',
            'created_at': format_timestamp(row[8]),
            'is_expired': bool(deadline_dt and deadline_dt < today),
        })
    return out

def get_teacher_messages_for_teacher(school_id, teacher_id, classes=None, subjects=None, limit=30):
    """List active school messages visible to one teacher."""
    classes_set = {(c or '').strip().lower() for c in (classes or []) if (c or '').strip()}
    subjects_set = {normalize_subject_name(s).lower() for s in (subjects or []) if normalize_subject_name(s)}
    if not ensure_extended_features_schema():
        return []
    with db_connection() as conn:
        c = conn.cursor()
        try:
            db_execute(
                c,
                """SELECT tm.id, tm.title, tm.message, tm.target_classname, tm.target_subject, tm.deadline_date, tm.created_at,
                          tmr.read_at
                   FROM teacher_messages tm
                   LEFT JOIN teacher_message_reads tmr
                     ON tmr.school_id = tm.school_id
                    AND tmr.message_id = tm.id
                    AND LOWER(tmr.teacher_id) = LOWER(?)
                   WHERE tm.school_id = ? AND tm.is_active = 1
                   ORDER BY tm.created_at DESC
                   LIMIT ?""",
                ((teacher_id or '').strip(), school_id, int(max(1, min(limit, 100)))),
            )
            rows = c.fetchall() or []
        except Exception as exc:
            msg = str(exc).lower()
            if 'teacher_messages' in msg or 'teacher_message_reads' in msg or 'undefinedtable' in msg:
                logging.warning('Teacher messaging tables missing: %s', exc)
                return []
            raise
    out = []
    today = date.today()
    for row in rows:
        target_class = (row[3] or '').strip()
        target_subject = normalize_subject_name(row[4] or '')
        class_ok = (not target_class) or (target_class.lower() in classes_set)
        subject_ok = (not target_subject) or (target_subject.lower() in subjects_set)
        if not (class_ok and subject_ok):
            continue
        deadline_raw = (row[5] or '').strip()
        deadline_dt = _parse_iso_date(deadline_raw) if deadline_raw else None
        out.append({
            'id': int(row[0] or 0),
            'title': row[1] or '',
            'message': row[2] or '',
            'target_classname': target_class,
            'target_subject': target_subject,
            'deadline_date': deadline_raw,
            'created_at': format_timestamp(row[6]),
            'is_expired': bool(deadline_dt and deadline_dt < today),
            'is_due_soon': bool(deadline_dt and 0 <= (deadline_dt - today).days <= 3),
            'is_read': bool(row[7]),
        })
    return out

def mark_teacher_message_read(school_id, teacher_id, message_id):
    """Mark one visible teacher message as read."""
    tid = (teacher_id or '').strip()
    if not tid:
        return 0
    if not ensure_extended_features_schema():
        return 0
    with db_connection(commit=True) as conn:
        c = conn.cursor()
        db_execute(
            c,
            """INSERT INTO teacher_message_reads (school_id, message_id, teacher_id, read_at)
               VALUES (?, ?, ?, CURRENT_TIMESTAMP)
               ON CONFLICT(school_id, message_id, teacher_id)
               DO UPDATE SET read_at = EXCLUDED.read_at""",
            (school_id, int(message_id), tid),
        )
        return int(c.rowcount or 0)

def mark_all_teacher_messages_read(school_id, teacher_id, classes=None, subjects=None):
    """Mark all visible teacher messages as read for one teacher."""
    tid = (teacher_id or '').strip()
    if not tid:
        return 0
    visible_rows = get_teacher_messages_for_teacher(
        school_id=school_id,
        teacher_id=tid,
        classes=classes or [],
        subjects=subjects or [],
        limit=300,
    )
    changed = 0
    with db_connection(commit=True) as conn:
        c = conn.cursor()
        for row in visible_rows:
            db_execute(
                c,
                """INSERT INTO teacher_message_reads (school_id, message_id, teacher_id, read_at)
                   VALUES (?, ?, ?, CURRENT_TIMESTAMP)
                   ON CONFLICT(school_id, message_id, teacher_id)
                   DO UPDATE SET read_at = EXCLUDED.read_at""",
                (school_id, int(row.get('id') or 0), tid),
            )
            changed += int(c.rowcount or 0)
    return changed

def get_student_messages_for_student(school_id, classname, stream, student_id='', limit=30):
    """List active school messages visible to one student."""
    cls = canonicalize_classname(classname)
    stream_norm = (stream or '').strip().title()
    sid = (student_id or '').strip()
    if not ensure_extended_features_schema():
        return []
    with db_connection() as conn:
        c = conn.cursor()
        db_execute(
            c,
            """SELECT sm.id, sm.title, sm.message, sm.target_classname, sm.target_stream, sm.deadline_date, sm.created_at,
                      smr.read_at
               FROM student_messages sm
               LEFT JOIN student_message_reads smr
                 ON smr.school_id = sm.school_id
                AND smr.message_id = sm.id
                AND LOWER(smr.student_id) = LOWER(?)
               WHERE sm.school_id = ? AND sm.is_active = 1
                 AND (target_classname = '' OR LOWER(target_classname) = LOWER(?))
                 AND (target_stream = '' OR LOWER(target_stream) = LOWER(?))
               ORDER BY sm.created_at DESC
               LIMIT ?""",
            (sid, school_id, cls, stream_norm, int(max(1, min(limit, 100)))),
        )
        rows = c.fetchall() or []
    out = []
    today = date.today()
    for row in rows:
        deadline_raw = (row[5] or '').strip()
        deadline_dt = _parse_iso_date(deadline_raw) if deadline_raw else None
        out.append({
            'id': int(row[0] or 0),
            'title': row[1] or '',
            'message': row[2] or '',
            'target_classname': row[3] or '',
            'target_stream': row[4] or '',
            'deadline_date': deadline_raw,
            'created_at': format_timestamp(row[6]),
            'is_expired': bool(deadline_dt and deadline_dt < today),
            'is_due_soon': bool(deadline_dt and 0 <= (deadline_dt - today).days <= 3),
            'is_read': bool(row[7]),
        })
    return out

def get_parent_messages_for_children(parent_phone, children, limit_per_school=80):
    """Aggregate visible school messages for a parent based on linked children."""
    phone = normalize_parent_phone(parent_phone)
    if not phone:
        return []
    if not ensure_extended_features_schema():
        return []
    children = list(children or [])
    by_school = {}
    for row in children:
        school_id = (row.get('school_id') or '').strip()
        cls = canonicalize_classname(row.get('classname', ''))
        stream = (row.get('stream') or '').strip().title()
        if not school_id or not cls:
            continue
        by_school.setdefault(school_id, {'pairs': set(), 'school_name': row.get('school_name', school_id)})
        by_school[school_id]['pairs'].add((cls.lower(), stream.lower()))
    if not by_school:
        return []
    out = []
    today = date.today()
    with db_connection() as conn:
        c = conn.cursor()
        for school_id, payload in by_school.items():
            try:
                db_execute(
                    c,
                    """SELECT sm.id, sm.title, sm.message, sm.target_classname, sm.target_stream, sm.deadline_date, sm.created_at,
                              pmr.read_at
                       FROM student_messages sm
                       LEFT JOIN parent_message_reads pmr
                         ON pmr.school_id = sm.school_id
                        AND pmr.message_id = sm.id
                        AND pmr.parent_phone = ?
                       WHERE sm.school_id = ? AND sm.is_active = 1
                       ORDER BY sm.created_at DESC
                       LIMIT ?""",
                    (phone, school_id, int(max(1, min(limit_per_school, 200)))),
                )
                rows = c.fetchall() or []
            except Exception as exc:
                msg = str(exc).lower()
                if 'parent_message_reads' in msg or 'student_messages' in msg or 'undefinedtable' in msg:
                    logging.warning('Parent messaging tables missing: %s', exc)
                    continue
                raise
            pairs = payload.get('pairs', set())
            for row in rows:
                target_class = (row[3] or '').strip()
                target_stream = (row[4] or '').strip()
                class_match = (not target_class) or any(target_class.lower() == p[0] for p in pairs)
                stream_match = (not target_stream) or any(target_stream.lower() == p[1] for p in pairs)
                if not (class_match and stream_match):
                    continue
                deadline_raw = (row[5] or '').strip()
                deadline_dt = _parse_iso_date(deadline_raw) if deadline_raw else None
                out.append({
                    'school_id': school_id,
                    'school_name': payload.get('school_name', school_id),
                    'id': int(row[0] or 0),
                    'title': row[1] or '',
                    'message': row[2] or '',
                    'target_classname': target_class,
                    'target_stream': target_stream,
                    'deadline_date': deadline_raw,
                    'created_at': format_timestamp(row[6]),
                    'is_expired': bool(deadline_dt and deadline_dt < today),
                    'is_due_soon': bool(deadline_dt and 0 <= (deadline_dt - today).days <= 3),
                    'is_read': bool(row[7]),
                })
    out.sort(key=lambda row: (row.get('created_at') or ''), reverse=True)
    return out

def mark_parent_message_read(school_id, parent_phone, message_id):
    phone = normalize_parent_phone(parent_phone)
    if not phone:
        return 0
    if not ensure_extended_features_schema():
        return 0
    with db_connection(commit=True) as conn:
        c = conn.cursor()
        db_execute(
            c,
            """INSERT INTO parent_message_reads (school_id, message_id, parent_phone, read_at)
               VALUES (?, ?, ?, CURRENT_TIMESTAMP)
               ON CONFLICT(school_id, message_id, parent_phone)
               DO UPDATE SET read_at = EXCLUDED.read_at""",
            (school_id, int(message_id), phone),
        )
        return int(c.rowcount or 0)

def mark_all_parent_messages_read(parent_phone, parent_messages):
    phone = normalize_parent_phone(parent_phone)
    if not phone:
        return 0
    changed = 0
    with db_connection(commit=True) as conn:
        c = conn.cursor()
        for row in (parent_messages or []):
            school_id = (row.get('school_id') or '').strip()
            msg_id = int(row.get('id') or 0)
            if not school_id or msg_id <= 0:
                continue
            db_execute(
                c,
                """INSERT INTO parent_message_reads (school_id, message_id, parent_phone, read_at)
                   VALUES (?, ?, ?, CURRENT_TIMESTAMP)
                   ON CONFLICT(school_id, message_id, parent_phone)
                   DO UPDATE SET read_at = EXCLUDED.read_at""",
                (school_id, msg_id, phone),
            )
            changed += int(c.rowcount or 0)
    return changed

def mark_student_message_read(school_id, student_id, message_id, classname='', stream=''):
    """Mark one visible student message as read for the student."""
    sid = (student_id or '').strip()
    cls = canonicalize_classname(classname)
    stream_norm = (stream or '').strip().title()
    if not sid:
        return 0
    with db_connection(commit=True) as conn:
        c = conn.cursor()
        db_execute(
            c,
            """SELECT id
               FROM student_messages
               WHERE school_id = ? AND id = ? AND is_active = 1
                 AND (target_classname = '' OR LOWER(target_classname) = LOWER(?))
                 AND (target_stream = '' OR LOWER(target_stream) = LOWER(?))
               LIMIT 1""",
            (school_id, int(message_id), cls, stream_norm),
        )
        if not c.fetchone():
            return 0
        db_execute(
            c,
            """INSERT INTO student_message_reads (school_id, message_id, student_id, read_at)
               VALUES (?, ?, ?, CURRENT_TIMESTAMP)
               ON CONFLICT(school_id, message_id, student_id)
               DO UPDATE SET read_at = EXCLUDED.read_at""",
            (school_id, int(message_id), sid),
        )
        return int(c.rowcount or 0)

def mark_all_student_messages_read(school_id, student_id, classname='', stream=''):
    """Mark all visible student messages as read."""
    sid = (student_id or '').strip()
    cls = canonicalize_classname(classname)
    stream_norm = (stream or '').strip().title()
    if not sid:
        return 0
    with db_connection(commit=True) as conn:
        c = conn.cursor()
        db_execute(
            c,
            """INSERT INTO student_message_reads (school_id, message_id, student_id, read_at)
               SELECT sm.school_id, sm.id, ?, CURRENT_TIMESTAMP
               FROM student_messages sm
               WHERE sm.school_id = ? AND sm.is_active = 1
                 AND (sm.target_classname = '' OR LOWER(sm.target_classname) = LOWER(?))
                 AND (sm.target_stream = '' OR LOWER(sm.target_stream) = LOWER(?))
               ON CONFLICT(school_id, message_id, student_id)
               DO UPDATE SET read_at = EXCLUDED.read_at""",
            (sid, school_id, cls, stream_norm),
        )
        return int(c.rowcount or 0)

# ==================== REPORTS FUNCTIONS ====================

def load_reports(status_filter='', user_filter='', text_filter=''):
    """Load reports with optional filtering."""
    with db_connection() as conn:
        c = conn.cursor()
        where = []
        params = []
        status_val = (status_filter or '').strip().lower()
        if status_val in {'read', 'unread'}:
            where.append('LOWER(status) = ?')
            params.append(status_val)
        user_val = (user_filter or '').strip().lower()
        if user_val:
            where.append('LOWER(user_id) LIKE ?')
            params.append(f'%{user_val}%')
        text_val = (text_filter or '').strip().lower()
        if text_val:
            where.append('LOWER(description) LIKE ?')
            params.append(f'%{text_val}%')

        query = 'SELECT id, user_id, description, timestamp, status, read_at FROM reports'
        if where:
            query += ' WHERE ' + ' AND '.join(where)
        query += ' ORDER BY timestamp DESC LIMIT 1000'
        db_execute(c, query, tuple(params) if params else None)
        return [{'id': row[0], 'user_id': row[1], 'description': row[2], 
                'timestamp': row[3], 'status': row[4], 'read_at': row[5]} for row in c.fetchall()]

def mark_all_reports_read():
    """Mark unread reports as read."""
    with db_connection(commit=True) as conn:
        c = conn.cursor()
        now_ts = datetime.now().isoformat()
        db_execute(
            c,
            """UPDATE reports
               SET status = 'read',
                   read_at = COALESCE(read_at, ?)
               WHERE status = 'unread' """,
            (now_ts,),
        )

def mark_report_status(report_id, status):
    """Mark one report as read or unread."""
    state = (status or '').strip().lower()
    if state not in {'read', 'unread'}:
        return 0
    with db_connection(commit=True) as conn:
        c = conn.cursor()
        if state == 'read':
            now_ts = datetime.now().isoformat()
            db_execute(
                c,
                """UPDATE reports
                   SET status = 'read',
                       read_at = COALESCE(read_at, ?)
                   WHERE id = ?""",
                (now_ts, int(report_id)),
            )
        else:
            db_execute(
                c,
                """UPDATE reports
                   SET status = 'unread',
                       read_at = NULL
                   WHERE id = ?""",
                (int(report_id),),
            )
        return int(c.rowcount or 0)

def delete_report(report_id):
    """Delete one report by id."""
    with db_connection(commit=True) as conn:
        c = conn.cursor()
        db_execute(c, 'DELETE FROM reports WHERE id = ?', (int(report_id),))
        return int(c.rowcount or 0)

def get_public_table_names():
    """Return safe list of public table names."""
    with db_connection() as conn:
        c = conn.cursor()
        db_execute(
            c,
            """SELECT table_name
               FROM information_schema.tables
               WHERE table_schema = 'public' AND table_type = 'BASE TABLE'
               ORDER BY table_name"""
        )
        return [row[0] for row in c.fetchall() if row and row[0]]

def save_report(user_id, description):
    """Save a report."""
    with db_connection(commit=True) as conn:
        c = conn.cursor()
        db_execute(c, 'INSERT INTO reports (user_id, description, timestamp, status) VALUES (?, ?, ?, ?)',
                   (user_id, description, datetime.now().isoformat(), 'unread'))

# ==================== ROUTES ====================

@app.route('/sw.js')
def service_worker():
    return send_file('static/sw.js', mimetype='application/javascript')

@app.route('/manifest.webmanifest')
def web_manifest():
    return send_file('static/manifest.webmanifest', mimetype='application/manifest+json')

@app.route('/school-logo/<school_id>')
def school_logo_proxy(school_id):
    school = get_school((school_id or '').strip())
    if not school:
        return Response(status=404)
    logo_url = (school.get('school_logo') or '').strip()
    if not logo_url:
        return Response(status=404)

    # Support uploaded images stored as data URLs.
    if logo_url.lower().startswith('data:image/'):
        try:
            header, payload = logo_url.split(',', 1)
            mime = header.split(';', 1)[0].replace('data:', '').strip().lower()
            if ';base64' in header.lower():
                data = base64.b64decode(payload, validate=True)
            else:
                data = urllib.parse.unquote_to_bytes(payload)
            if not mime.startswith('image/') or not data:
                return Response(status=404)
            resp = Response(data, mimetype=mime)
            resp.headers['Cache-Control'] = 'public, max-age=600'
            return resp
        except Exception:
            return Response(status=404)

    # Serve local static logos directly when configured as /static/... path.
    if logo_url.startswith('/static/') or logo_url.startswith('static/'):
        rel_path = logo_url[1:] if logo_url.startswith('/') else logo_url
        static_root = os.path.abspath(app.static_folder or 'static')
        file_path = os.path.abspath(os.path.join(os.getcwd(), rel_path.replace('/', os.sep)))
        if file_path.startswith(static_root + os.sep) and os.path.isfile(file_path):
            return send_file(file_path)

    try:
        data, content_type = fetch_school_logo_bytes(logo_url)
    except Exception:
        data, content_type = None, None
    if not data:
        parsed = urllib.parse.urlparse(logo_url)
        if parsed.scheme in ('http', 'https'):
            return redirect(logo_url, code=302)
        return Response(status=404)
    resp = Response(data, mimetype=content_type)
    resp.headers['Cache-Control'] = 'public, max-age=600'
    return resp

@app.route('/')
def home():
    # Render the login page directly as the landing page
    return render_template('shared/login.html')

@app.errorhandler(CSRFError)
def csrf_error(error):
    """Handle CSRF token errors."""
    if 'user_id' in session:
        flash('Form token expired/invalid. Please retry your last action.', 'error')
        return redirect(request.referrer or url_for('menu'))
    flash('Your session has expired. Please login again.', 'error')
    return redirect(url_for('login'))

@app.before_request
def enforce_school_operations_toggle():
    """Apply school-level operation lock set by super admin."""
    endpoint = request.endpoint or ''
    if endpoint in {'static', 'login', 'logout', 'home'}:
        return None

    role = session.get('role')
    school_id = session.get('school_id')
    if not school_id:
        return None
    try:
        school = get_school(school_id)
    except Exception as exc:
        logging.warning("Skipping operations toggle check due transient DB error: %s", exc)
        return None
    if not school:
        return None
    if safe_int(school.get('operations_enabled', 1), 1):
        # School-level OFF is not active, but teacher-level OFF may still apply.
        if role != 'teacher' or safe_int(school.get('teacher_operations_enabled', 1), 1):
            return None

    teacher_blocked_endpoints = {
        'teacher_attendance',
        'teacher_period_attendance',
        'teacher_allocate_stream',
        'teacher_enter_scores',
        'teacher_enter_subject_scores',
        'teacher_upload_csv',
        'teacher_update_profile',
        'teacher_publish_results',
    }
    school_admin_blocked_endpoints = {
        'school_admin_class_subjects',
        'school_admin_settings',
        'school_admin_add_teacher',
        'school_admin_promote',
        'school_admin_add_students_by_class',
        'school_admin_assign_teacher',
        'school_admin_toggle_operations',
        'school_admin_remove_teacher_assignment',
    }

    if role == 'teacher' and endpoint in teacher_blocked_endpoints:
        if not safe_int(school.get('operations_enabled', 1), 1):
            flash('School operations are OFF by super admin. Teachers are read-only now.', 'error')
        elif not safe_int(school.get('teacher_operations_enabled', 1), 1):
            flash('Teacher operations are OFF by school admin. Teachers are read-only now.', 'error')
        else:
            return None
        return redirect(url_for('teacher_dashboard'))

    if role == 'school_admin' and endpoint != 'school_admin_change_password' and (endpoint in school_admin_blocked_endpoints or request.method == 'POST'):
        flash('School operations are OFF by super admin. School admin is currently in read-only mode.', 'error')
        return redirect(url_for('school_admin_dashboard'))

    return None

@app.before_request
def enforce_student_password_change():
    """Force students to change default password before using the app."""
    if (session.get('role') or '').strip().lower() != 'student':
        return None
    if not session.get('must_change_password'):
        return None
    endpoint = (request.endpoint or '').strip()
    allowed_endpoints = {
        'student_change_password',
        'logout',
        'static',
        'login',
        'home',
    }
    if endpoint in allowed_endpoints:
        return None
    flash('Change your default password to continue.', 'error')
    return redirect(url_for('student_change_password'))

@app.before_request
def enforce_admin_password_rotation():
    role = (session.get('role') or '').strip().lower()
    if role not in {'super_admin', 'school_admin'}:
        return None
    if not session.get('force_password_change'):
        return None
    endpoint = (request.endpoint or '').strip()
    allowed_endpoints = {
        'school_admin_change_password',
        'super_admin_change_password',
        'change_password',
        'logout',
        'static',
        'login',
        'home',
    }
    if endpoint in allowed_endpoints:
        return None
    flash(f'Password expired. Change your password (max age: {ADMIN_PASSWORD_MAX_AGE_DAYS} days).', 'error')
    if role == 'super_admin':
        return redirect(url_for('super_admin_change_password'))
    return redirect(url_for('school_admin_change_password'))

@app.after_request
def apply_pwa_and_cache_headers(response):
    """
    Safe PWA policy:
    - Inject manifest/SW registration into HTML responses.
    - Prevent browser caching of authenticated dynamic pages.
    """
    if _ENABLE_RUNTIME_PWA_INJECT:
        try:
            content_type = (response.content_type or '').lower()
            if 'text/html' in content_type:
                body = response.get_data(as_text=True)
                if '</head>' in body and '/manifest.webmanifest' not in body:
                    body = body.replace('</head>', f'{PWA_HEAD_SNIPPET}\n</head>')
                if '</body>' in body and "register('/sw.js')" not in body:
                    body = body.replace('</body>', f'{PWA_BODY_SNIPPET}\n</body>')
                response.set_data(body)
                response.headers['Content-Length'] = str(len(response.get_data()))
        except Exception:
            # Keep response delivery resilient even if HTML injection fails.
            pass

    path = (request.path or '').strip()
    is_static_or_pwa = (
        path.startswith('/static/')
        or path in {'/manifest.webmanifest', '/sw.js'}
    )
    role = (session.get('role') or '').strip().lower()
    if (session.get('user_id') or role == 'parent') and not is_static_or_pwa:
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
    return response

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Single login for all users - no role selection."""
    terms_read = request.args.get('terms_read') == '1'
    if request.method == 'POST':
        username = request.form.get('username', '').strip().lower()
        password = request.form.get('password', '')
        agreed_terms = request.form.get('agree_terms') == 'on'
        terms_read = terms_read or agreed_terms

        if not username or not password:
            flash('Please enter username and password.', 'error')
            return render_template('shared/login.html', terms_read=terms_read)
        client_ip = get_client_ip()
        blocked, wait_minutes = is_login_blocked('login', username, client_ip)
        if blocked:
            flash(f'Too many failed login attempts. Try again in about {wait_minutes} minute(s).', 'error')
            return render_template('shared/login.html', terms_read=terms_read)

        user = get_user(username)
        # Legacy self-heal: if a student record exists but corresponding users row is missing,
        # provision a student login with the configured default password.
        if not user:
            try:
                resolved_school_id = find_student_school_id(username)
            except Exception:
                resolved_school_id = None
            if resolved_school_id:
                student_row = load_student(resolved_school_id, username)
                if student_row:
                    try:
                        upsert_user(username, hash_password(DEFAULT_STUDENT_PASSWORD), 'student', resolved_school_id)
                        user = get_user(username)
                    except Exception as exc:
                        logging.warning(
                            "Student login auto-provision failed for username=%s school_id=%s: %s",
                            username,
                            resolved_school_id,
                            exc,
                        )
        
        if user and check_password(user['password_hash'], password):
            role = (user.get('role') or '').strip().lower()
            if role not in {'super_admin', 'school_admin', 'teacher', 'student'}:
                register_failed_login('login', username, client_ip)
                record_login_audit(username, role, user.get('school_id'), 'login', False, 'invalid_role')
                flash('Invalid account role configuration. Contact system administrator.', 'error')
                return render_template('shared/login.html', terms_read=terms_read)
            terms_accepted = int(user.get('terms_accepted') or 0)
            if role != 'super_admin' and not terms_accepted and not agreed_terms:
                flash('You must agree to the Terms and Privacy Policy to continue.', 'error')
                return render_template('shared/login.html', terms_read=terms_read)
            if role != 'super_admin' and not terms_accepted and agreed_terms:
                mark_terms_accepted(user.get('username'))

            user_school_id = user.get('school_id')
            if role == 'student' and not user_school_id:
                resolved_school_id = find_student_school_id(user.get('username'))
                if resolved_school_id:
                    update_user_school_id_only(user.get('username'), resolved_school_id)
                    user_school_id = resolved_school_id
            if role != 'super_admin' and not user_school_id:
                record_login_audit(username, role, user_school_id, 'login', False, 'missing_school_assignment')
                flash('Account is missing school assignment. Contact administrator.', 'error')
                return render_template('shared/login.html', terms_read=terms_read)
            if role != 'super_admin' and not get_school(user_school_id):
                record_login_audit(username, role, user_school_id, 'login', False, 'invalid_school_assignment')
                flash('Account is linked to an invalid school. Contact administrator.', 'error')
                return render_template('shared/login.html', terms_read=terms_read)
            if role == 'student':
                student_row = load_student(user_school_id, username)
                if not student_row:
                    record_login_audit(username, role, user_school_id, 'login', False, 'student_archived_or_missing')
                    flash('Student account is inactive. Contact school admin.', 'error')
                    return render_template('shared/login.html', terms_read=terms_read)
            if role == 'teacher':
                teacher_rows = get_teachers(user_school_id)
                if username not in teacher_rows:
                    record_login_audit(username, role, user_school_id, 'login', False, 'teacher_archived_or_missing')
                    flash('Teacher account is inactive. Contact school admin.', 'error')
                    return render_template('shared/login.html', terms_read=terms_read)

            clear_failed_login('login', username, client_ip)
            return _complete_authenticated_login(user, user_school_id)
        else:
            register_failed_login('login', username, client_ip)
            record_login_audit(username, '', None, 'login', False, 'invalid_credentials')
            flash('Invalid username or password.', 'error')
    
    return render_template('shared/login.html', terms_read=terms_read)

@app.route('/admin-otp', methods=['GET', 'POST'])
def admin_otp_verify():
    session.pop('admin_otp_pending', None)
    flash('OTP has been removed. Please login normally.', 'error')
    return redirect(url_for('login'))

@app.route('/terms-privacy')
def terms_privacy():
    return render_template('shared/terms_privacy.html')



@app.route('/signup', methods=['GET', 'POST'])
def signup():
    """Legacy signup is disabled; use super admin dashboard account creation."""
    flash('Signup page is disabled. Use Super Admin dashboard to create accounts.', 'error')
    if session.get('role') == 'super_admin':
        return redirect(url_for('super_admin_dashboard'))
    return redirect(url_for('login'))

@app.route('/logout', methods=['POST'])
def logout():
    session.clear()
    return redirect(url_for('home'))

@app.route('/tutorial/complete', methods=['POST'])
def complete_first_login_tutorial():
    role = (session.get('role') or '').strip().lower()
    if role == 'super_admin' or not role:
        return redirect(url_for('menu'))
    if role == 'parent':
        mark_parent_first_login_tutorial_seen(session.get('parent_phone', ''))
        session.pop('show_first_login_tutorial', None)
        session.pop('first_login_tutorial_role', None)
        return redirect(url_for('parent_dashboard'))
    username = (session.get('user_id') or '').strip().lower()
    mark_user_first_login_tutorial_seen(username)
    session.pop('show_first_login_tutorial', None)
    session.pop('first_login_tutorial_role', None)
    if role == 'school_admin':
        return redirect(url_for('school_admin_dashboard'))
    if role == 'teacher':
        return redirect(url_for('teacher_dashboard'))
    if role == 'student':
        return redirect(url_for('student_dashboard'))
    return redirect(url_for('menu'))

# ==================== SUPER ADMIN ROUTES ====================

def _build_super_admin_school_overview():
    schools = get_all_schools()
    for school in schools:
        school['admin_username'] = get_school_admin_username(school.get('school_id'))

    total = len(schools)
    operations_on = sum(1 for s in schools if safe_int(s.get('operations_enabled', 1), 1))
    operations_off = max(0, total - operations_on)
    with_admin = sum(1 for s in schools if (s.get('admin_username') or '').strip())
    without_admin = max(0, total - with_admin)

    location_counts = {}
    for school in schools:
        location = (school.get('location') or 'Unknown').strip() or 'Unknown'
        location_counts[location] = location_counts.get(location, 0) + 1
    top_locations = sorted(location_counts.items(), key=lambda item: item[1], reverse=True)[:6]
    max_location_count = max((count for _, count in top_locations), default=1)
    location_bars = [
        {
            'label': label,
            'count': count,
            'pct': round((count / max_location_count) * 100, 1),
        }
        for label, count in top_locations
    ]

    overview = {
        'total_schools': total,
        'operations_on': operations_on,
        'operations_off': operations_off,
        'with_admin': with_admin,
        'without_admin': without_admin,
        'location_bars': location_bars,
    }
    return schools, overview

@app.route('/super-admin')
def super_admin_dashboard():
    if session.get('role') != 'super_admin':
        return redirect(url_for('login'))

    schools, overview = _build_super_admin_school_overview()
    last_login_at = format_timestamp(get_last_login_at(session.get('user_id')))
    return render_template('super/super_admin_dashboard.html', overview=overview, last_login_at=last_login_at)

@app.route('/super-admin/schools/add')
def super_admin_add_school_page():
    if session.get('role') != 'super_admin':
        return redirect(url_for('login'))
    _schools, overview = _build_super_admin_school_overview()
    last_login_at = format_timestamp(get_last_login_at(session.get('user_id')))
    return render_template('super/super_admin_add_school.html', overview=overview, last_login_at=last_login_at)

@app.route('/super-admin/schools')
def super_admin_view_schools():
    if session.get('role') != 'super_admin':
        return redirect(url_for('login'))
    schools, overview = _build_super_admin_school_overview()
    last_login_at = format_timestamp(get_last_login_at(session.get('user_id')))
    return render_template('super/super_admin_schools.html', schools=schools, overview=overview, last_login_at=last_login_at)

@app.route('/super-admin/db-view')
def super_admin_db_view():
    """Simple in-app DB browser for super admin."""
    if session.get('role') != 'super_admin':
        return redirect(url_for('login'))

    table_names = get_public_table_names()
    selected_table = (request.args.get('table', '') or '').strip()
    try:
        limit = int(request.args.get('limit', 100))
    except (TypeError, ValueError):
        limit = 100
    limit = max(1, min(limit, 500))

    columns = []
    rows = []
    row_count = 0

    if selected_table:
        if selected_table not in table_names:
            flash('Invalid table selected.', 'error')
            return redirect(url_for('super_admin_db_view'))
        # Strict identifier guard; table list already comes from information_schema.
        if not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*', selected_table):
            flash('Unsafe table name.', 'error')
            return redirect(url_for('super_admin_db_view'))
        with db_connection() as conn:
            c = conn.cursor()
            db_execute(c, f'SELECT COUNT(*) FROM "{selected_table}"')
            row_count = int((c.fetchone() or [0])[0] or 0)
            db_execute(c, f'SELECT * FROM "{selected_table}" LIMIT ?', (limit,))
            fetched = c.fetchall()
            rows = [list(r) for r in fetched]
            columns = [d[0] for d in (c.description or [])]

    return render_template(
        'super/db_view.html',
        table_names=table_names,
        selected_table=selected_table,
        columns=columns,
        rows=rows,
        row_count=row_count,
        limit=limit,
    )

@app.route('/super-admin/add-school', methods=['POST'])
def super_admin_add_school():
    if session.get('role') != 'super_admin':
        return redirect(url_for('login'))
    
    raw_school_name = request.form.get('school_name', '').strip()
    school_name = raw_school_name
    location = request.form.get('location', '').strip()
    phone = request.form.get('phone', '').strip()
    school_email = request.form.get('school_email', '').strip().lower()
    principal_name = request.form.get('principal_name', '').strip()
    motto = request.form.get('motto', '').strip()
    class_arm_ranking_mode = request.form.get('class_arm_ranking_mode', 'separate').strip().lower()
    admin_username = request.form.get('admin_username', '').strip().lower()
    admin_password = request.form.get('admin_password', '').strip()
    
    if school_name and admin_username and admin_password:
        try:
            if not is_valid_email(admin_username):
                flash('School admin username must be a valid email address.', 'error')
                return redirect(url_for('super_admin_add_school_page'))
            if school_email and not is_valid_email(school_email):
                flash('School contact email must be a valid email address.', 'error')
                return redirect(url_for('super_admin_add_school_page'))

            existing_admin = get_user(admin_username)
            if existing_admin:
                flash(f'Admin username "{admin_username}" already exists. Please choose another username.', 'error')
                return redirect(url_for('super_admin_add_school_page'))

            if class_arm_ranking_mode not in {'separate', 'together'}:
                class_arm_ranking_mode = 'separate'
            with db_connection(commit=True) as conn:
                c = conn.cursor()
                db_execute(c, "ALTER TABLE schools ADD COLUMN IF NOT EXISTS class_arm_ranking_mode TEXT DEFAULT 'separate'")
                school_id = create_school_with_index_id_with_cursor(
                    c,
                    school_name,
                    location,
                    phone=phone,
                    email=school_email,
                    principal_name=principal_name,
                    motto=motto,
                )
                db_execute(
                    c,
                    'UPDATE schools SET class_arm_ranking_mode = ? WHERE school_id = ?',
                    (class_arm_ranking_mode, school_id),
                )
                # Create school admin user with the provided username and password.
                password_hash = hash_password(admin_password)
                upsert_user_with_cursor(c, admin_username, password_hash, 'school_admin', school_id)
            
            flash(f'School created successfully! School ID: {school_id} | Admin username: {admin_username}', 'success')
        except Exception as e:
            flash(f'Error creating school: {str(e)}', 'error')
    else:
        flash('Please fill in all fields.', 'error')

    return redirect(url_for('super_admin_add_school_page'))

@app.route('/super-admin/delete-school', methods=['POST'])
def super_admin_delete_school():
    if session.get('role') != 'super_admin':
        return redirect(url_for('login'))
    
    school_id = request.form.get('school_id', '').strip()
    
    if school_id:
        try:
            with db_connection(commit=True) as conn:
                c = conn.cursor()
                # Delete users associated with this school (admins, teachers, students)
                db_execute(c, 'DELETE FROM users WHERE school_id = ?', (school_id,))
                # Delete students
                db_execute(c, 'DELETE FROM students WHERE school_id = ?', (school_id,))
                # Delete teachers
                db_execute(c, 'DELETE FROM teachers WHERE school_id = ?', (school_id,))
                # Delete class assignments
                db_execute(c, 'DELETE FROM class_assignments WHERE school_id = ?', (school_id,))
                db_execute(c, 'DELETE FROM teacher_subject_assignments WHERE school_id = ?', (school_id,))
                # Delete class subject configs
                db_execute(c, 'DELETE FROM class_subject_configs WHERE school_id = ?', (school_id,))
                # Delete assessment configs
                db_execute(c, 'DELETE FROM assessment_configs WHERE school_id = ?', (school_id,))
                # Delete result publication and view history to avoid orphan records.
                db_execute(c, 'DELETE FROM result_views WHERE school_id = ?', (school_id,))
                db_execute(c, 'DELETE FROM published_student_results WHERE school_id = ?', (school_id,))
                db_execute(c, 'DELETE FROM score_audit_logs WHERE school_id = ?', (school_id,))
                db_execute(c, 'DELETE FROM result_publications WHERE school_id = ?', (school_id,))
                # Delete extended operational/audit data.
                db_execute(c, 'DELETE FROM student_attendance WHERE school_id = ?', (school_id,))
                db_execute(c, 'DELETE FROM behaviour_assessments WHERE school_id = ?', (school_id,))
                db_execute(c, 'DELETE FROM period_attendance WHERE school_id = ?', (school_id,))
                db_execute(c, 'DELETE FROM class_timetables WHERE school_id = ?', (school_id,))
                db_execute(c, 'DELETE FROM promotion_audit_logs WHERE school_id = ?', (school_id,))
                db_execute(c, 'DELETE FROM result_disputes WHERE school_id = ?', (school_id,))
                db_execute(c, 'DELETE FROM school_term_calendars WHERE school_id = ?', (school_id,))
                db_execute(c, 'DELETE FROM login_audit_logs WHERE school_id = ?', (school_id,))
                # Delete school by normalized index-based school_id (and support legacy text IDs).
                db_execute(c, 'DELETE FROM schools WHERE school_id = ? OR CAST(id AS TEXT) = ?', (school_id, school_id))
            
            flash(f'School "{school_id}" deleted successfully!', 'success')
        except Exception as e:
            flash(f'Error deleting school: {str(e)}', 'error')
    else:
        flash('School ID is required.', 'error')
    
    return redirect(url_for('super_admin_view_schools'))

@app.route('/super-admin/update-school-admin', methods=['POST'])
def super_admin_update_school_admin():
    if session.get('role') != 'super_admin':
        return redirect(url_for('login'))

    school_id = request.form.get('school_id', '').strip()
    admin_username = request.form.get('admin_username', '').strip().lower()
    admin_password = request.form.get('admin_password', '')
    if not school_id or not admin_username:
        flash('School ID and school admin email are required.', 'error')
        return redirect(url_for('super_admin_view_schools'))
    try:
        update_school_admin_account(school_id, admin_username, admin_password)
        flash(f'School admin updated for {school_id}: {admin_username}', 'success')
    except Exception as exc:
        flash(f'Error updating school admin: {str(exc)}', 'error')
    return redirect(url_for('super_admin_view_schools'))

@app.route('/super-admin/update-school', methods=['POST'])
def super_admin_update_school():
    if session.get('role') != 'super_admin':
        return redirect(url_for('login'))
    school_id = request.form.get('school_id', '').strip()
    school_name = request.form.get('school_name', '').strip()
    location = request.form.get('location', '').strip()
    phone = request.form.get('phone', '').strip()
    school_email = request.form.get('school_email', '').strip().lower()
    principal_name = request.form.get('principal_name', '').strip()
    motto = request.form.get('motto', '').strip()
    class_arm_ranking_mode = request.form.get('class_arm_ranking_mode', 'separate').strip().lower()
    if not school_id or not school_name:
        flash('School ID and school name are required.', 'error')
        return redirect(url_for('super_admin_view_schools'))
    if school_email and not is_valid_email(school_email):
        flash('School contact email must be a valid email address.', 'error')
        return redirect(url_for('super_admin_view_schools'))
    if class_arm_ranking_mode not in {'separate', 'together'}:
        class_arm_ranking_mode = 'separate'
    try:
        with db_connection(commit=True) as conn:
            c = conn.cursor()
            db_execute(c, "ALTER TABLE schools ADD COLUMN IF NOT EXISTS class_arm_ranking_mode TEXT DEFAULT 'separate'")
            db_execute(
                c,
                """UPDATE schools
                   SET school_name = ?, location = ?, phone = ?, email = ?,
                       principal_name = ?, motto = ?, class_arm_ranking_mode = ?, updated_at = ?
                   WHERE school_id = ?""",
                (school_name, location, phone, school_email, principal_name, motto, class_arm_ranking_mode, datetime.now(), school_id),
            )
        invalidate_school_cache(school_id)
        flash(f'School profile updated for {school_id}.', 'success')
    except Exception as exc:
        flash(f'Error updating school profile: {str(exc)}', 'error')
    return redirect(url_for('super_admin_view_schools'))

@app.route('/super-admin/toggle-school-operations', methods=['POST'])
def super_admin_toggle_school_operations():
    if session.get('role') != 'super_admin':
        return redirect(url_for('login'))
    school_id = request.form.get('school_id', '').strip()
    enabled = request.form.get('operations_enabled', '1').strip() == '1'
    if not school_id:
        flash('School ID is required.', 'error')
        return redirect(url_for('super_admin_view_schools'))
    set_school_operations_enabled(school_id, enabled)
    state = 'ON' if enabled else 'OFF'
    flash(f'Operations for {school_id} set to {state}.', 'success')
    return redirect(url_for('super_admin_view_schools'))

# ==================== SCHOOL ADMIN ROUTES ====================

@app.route('/school-admin')
def school_admin_dashboard():
    if session.get('role') != 'school_admin':
        return redirect(url_for('login'))
    
    school_id = session.get('school_id')
    school = get_school(school_id)
    current_term = get_current_term(school)
    current_year = (school or {}).get('academic_year', '')
    term_calendar = get_school_term_calendar(school_id, current_year, current_term)
    term_program_for_progress = get_school_term_program(school_id, current_year, current_term)
    term_open_progress = build_term_open_progress(term_calendar, term_program_for_progress)
    dashboard_term_events = build_term_program_events(term_program_for_progress)
    dashboard_term_events_payload = []
    for event in dashboard_term_events:
        dashboard_term_events_payload.append({
            'label': event.get('label', ''),
            'date_raw': event.get('date_raw', ''),
            'date_end_raw': event.get('date_end_raw', ''),
            'status': event.get('status', 'planned'),
        })
    total_students = get_total_student_count(school_id)
    parent_count = get_linked_parent_count(school_id)
    teachers_all = get_teachers(school_id, include_archived=True)
    teachers = {tid: t for tid, t in (teachers_all or {}).items() if not int(t.get('is_archived', 0) or 0)}
    archived_teachers = {tid: t for tid, t in (teachers_all or {}).items() if int(t.get('is_archived', 0) or 0)}
    class_counts = get_student_count_by_class(school_id)
    assignments = get_class_assignments(school_id)
    teacher_class_map = {}
    for assignment in assignments:
        assignment_teacher_id = (assignment.get('teacher_id') or '').strip()
        assignment_class = (assignment.get('classname') or '').strip()
        if not assignment_teacher_id or not assignment_class:
            continue
        if (assignment.get('term') or '') != current_term:
            continue
        if (assignment.get('academic_year') or '') != (current_year or ''):
            continue
        teacher_class_map.setdefault(assignment_teacher_id, [])
        if assignment_class not in teacher_class_map[assignment_teacher_id]:
            teacher_class_map[assignment_teacher_id].append(assignment_class)
    for assignment_teacher_id in teacher_class_map:
        teacher_class_map[assignment_teacher_id] = sorted(
            teacher_class_map[assignment_teacher_id],
            key=lambda value: str(value).lower(),
        )
    try:
        subject_assignments = get_teacher_subject_assignments(
            school_id,
            academic_year=current_year,
        )
    except Exception as exc:
        logging.warning("Failed to load teacher subject assignments for dashboard: %s", exc)
        subject_assignments = []

    class_subject_options = {}
    try:
        classnames_for_options = get_school_classnames(school_id)
    except Exception as exc:
        logging.warning("Failed to load school class names for dashboard subject options: %s", exc)
        classnames_for_options = []
    for cls in classnames_for_options:
        config = get_class_subject_config(school_id, cls) or {}
        subjects = normalize_subjects_list(
            (config.get('core_subjects') or [])
            + (config.get('science_subjects') or [])
            + (config.get('art_subjects') or [])
            + (config.get('commercial_subjects') or [])
            + (config.get('optional_subjects') or [])
        )
        if not subjects:
            defaults = _catalog_defaults_for_class(cls)
            subjects = normalize_subjects_list(
                (defaults.get('core') or [])
                + (defaults.get('science') or [])
                + (defaults.get('art') or [])
                + (defaults.get('commercial') or [])
                + (defaults.get('optional') or [])
            )
        class_subject_options[cls] = subjects
    publication_statuses = get_school_publication_statuses(
        school_id,
        current_term,
        current_year,
        assignments=assignments,
    )
    missing_score_alerts = []
    if class_counts:
        seen_alert_classes = set()
        for a in assignments:
            if (a.get('term') or '') != current_term or (a.get('academic_year') or '') != (current_year or ''):
                continue
            cls = (a.get('classname') or '').strip()
            if not cls or cls in seen_alert_classes:
                continue
            seen_alert_classes.add(cls)
            class_students = load_students(school_id, class_filter=cls, term_filter=current_term)
            progress = compute_class_subject_completion(
                school_id=school_id,
                classname=cls,
                term=current_term,
                academic_year=current_year,
                school=school,
                class_students_data=class_students,
            )
            pending_rows = [row for row in progress.get('rows', []) if int(row.get('pending_students', 0)) > 0]
            if not pending_rows:
                continue
            missing_score_alerts.append({
                'classname': cls,
                'pending_subjects': len(pending_rows),
                'subjects': [row.get('subject', '') for row in pending_rows],
                'total_pending_entries': sum(int(row.get('pending_students', 0)) for row in pending_rows),
            })
    approval_workflow_enabled = result_publication_has_approval_columns()
    last_login_at = format_timestamp(get_last_login_at(session.get('user_id')))
    has_principal_signature = bool((school or {}).get('principal_signature_image'))
    try:
        student_message_rows = get_school_student_messages(school_id, limit=12)
    except Exception as exc:
        logging.warning("Failed to load school student messages for dashboard: %s", exc)
        student_message_rows = []
    try:
        teacher_message_rows = get_school_teacher_messages(school_id, limit=12)
    except Exception as exc:
        logging.warning("Failed to load school teacher messages for dashboard: %s", exc)
        teacher_message_rows = []
    school_message_total = len(student_message_rows or []) + len(teacher_message_rows or [])
    
    return render_template('school/school_admin_dashboard.html', 
                         school=school, 
                         total_students=total_students,
                         parent_count=parent_count,
                         teachers=teachers,
                         archived_teachers=archived_teachers,
                         class_counts=class_counts,
                         assignments=assignments,
                         teacher_class_map=teacher_class_map,
                         subject_assignments=subject_assignments,
                         class_subject_options=class_subject_options,
                         current_term=current_term,
                         current_year=current_year,
                         term_open_progress=term_open_progress,
                         dashboard_term_events_payload=dashboard_term_events_payload,
                         last_login_at=last_login_at,
                         has_principal_signature=has_principal_signature,
                         student_message_rows=student_message_rows,
                         teacher_message_rows=teacher_message_rows,
                         school_message_total=school_message_total,
                         publication_statuses=publication_statuses,
                         missing_score_alerts=missing_score_alerts,
                         approval_workflow_enabled=approval_workflow_enabled)


@app.route('/school-admin/messages')
def school_admin_messages():
    if session.get('role') != 'school_admin':
        return redirect(url_for('login'))

    school_id = session.get('school_id')
    school = get_school(school_id) or {}
    current_term = get_current_term(school)
    current_year = (school or {}).get('academic_year', '')
    class_counts = get_student_count_by_class(school_id) or {}

    try:
        class_options = sorted(
            {str(name).strip() for name in get_school_classnames(school_id) if str(name).strip()}
            | {str(name).strip() for name in class_counts.keys() if str(name).strip()},
            key=lambda value: str(value).lower(),
        )
    except Exception:
        class_options = sorted(
            [str(name).strip() for name in class_counts.keys() if str(name).strip()],
            key=lambda value: str(value).lower(),
        )

    try:
        subject_assignments = get_teacher_subject_assignments(
            school_id,
            academic_year=current_year,
        )
    except Exception as exc:
        logging.warning("Failed to load teacher subject assignments for messages page: %s", exc)
        subject_assignments = []
    subject_options = sorted(
        {
            normalize_subject_name((row.get('subject') or '').strip())
            for row in (subject_assignments or [])
            if normalize_subject_name((row.get('subject') or '').strip())
        },
        key=lambda value: str(value).lower(),
    )

    try:
        student_message_rows = get_school_student_messages(school_id, limit=40)
    except Exception as exc:
        logging.warning("Failed to load school student messages for messages page: %s", exc)
        student_message_rows = []
    try:
        teacher_message_rows = get_school_teacher_messages(school_id, limit=40)
    except Exception as exc:
        logging.warning("Failed to load school teacher messages for messages page: %s", exc)
        teacher_message_rows = []

    school_message_total = len(student_message_rows or []) + len(teacher_message_rows or [])

    return render_template(
        'school/school_admin_messages.html',
        school=school,
        current_term=current_term,
        current_year=current_year,
        class_options=class_options,
        subject_options=subject_options,
        student_message_rows=student_message_rows,
        teacher_message_rows=teacher_message_rows,
        school_message_total=school_message_total,
    )

@app.route('/school-admin/publish-results')
def school_admin_publish_results():
    if session.get('role') != 'school_admin':
        return redirect(url_for('login'))

    school_id = session.get('school_id')
    school = get_school(school_id) or {}
    current_term = get_current_term(school)
    current_year = (school or {}).get('academic_year', '')
    assignments = get_class_assignments(school_id)
    publication_statuses = get_school_publication_statuses(
        school_id,
        current_term,
        current_year,
        assignments=assignments,
    )
    approval_workflow_enabled = result_publication_has_approval_columns()
    try:
        student_message_rows = get_school_student_messages(school_id, limit=12)
    except Exception as exc:
        logging.warning("Failed to load school student messages for publish page badge: %s", exc)
        student_message_rows = []
    try:
        teacher_message_rows = get_school_teacher_messages(school_id, limit=12)
    except Exception as exc:
        logging.warning("Failed to load school teacher messages for publish page badge: %s", exc)
        teacher_message_rows = []
    school_message_total = len(student_message_rows or []) + len(teacher_message_rows or [])
    return render_template(
        'school/school_admin_publish_results.html',
        school=school,
        current_term=current_term,
        current_year=current_year,
        publication_statuses=publication_statuses,
        approval_workflow_enabled=approval_workflow_enabled,
        school_message_total=school_message_total,
    )

@app.route('/school-admin/publish-results/corrections')
def school_admin_publish_results_corrections():
    if session.get('role') != 'school_admin':
        return redirect(url_for('login'))

    school_id = session.get('school_id')
    school = get_school(school_id) or {}
    classname = (request.args.get('classname', '') or '').strip()
    term = (request.args.get('term', '') or '').strip() or get_current_term(school)
    academic_year = (request.args.get('academic_year', '') or '').strip() or ((school or {}).get('academic_year', '') or '')
    if not classname:
        flash('Class is required to open correction list.', 'error')
        return redirect(url_for('school_admin_publish_results'))
    students = get_published_students_for_class(
        school_id=school_id,
        classname=classname,
        term=term,
        academic_year=academic_year,
    )
    term_token = _term_token(academic_year, term)
    school_message_total = 0
    try:
        student_message_rows = get_school_student_messages(school_id, limit=12)
        teacher_message_rows = get_school_teacher_messages(school_id, limit=12)
        school_message_total = len(student_message_rows or []) + len(teacher_message_rows or [])
    except Exception:
        school_message_total = 0
    return render_template(
        'school/school_admin_publish_result_corrections.html',
        school=school,
        classname=classname,
        term=term,
        academic_year=academic_year,
        term_token=term_token,
        students=students,
        school_message_total=school_message_total,
    )

@app.route('/school-admin/term-programs', methods=['GET'])
def school_admin_term_programs():
    if session.get('role') != 'school_admin':
        return redirect(url_for('login'))
    school_id = (session.get('school_id') or '').strip()
    school = get_school(school_id) or {}
    current_term = get_current_term(school)
    current_year = (school or {}).get('academic_year', '')
    selected_program_term = (request.args.get('program_term', '') or '').strip() or current_term
    if selected_program_term not in {'First Term', 'Second Term', 'Third Term'}:
        selected_program_term = current_term
    selected_program_year = (request.args.get('program_year', '') or '').strip() or current_year
    term_program = get_school_term_program(school_id, selected_program_year, selected_program_term)
    if not (term_program.get('next_term_begin_date') or '').strip():
        term_program['next_term_begin_date'] = resolve_next_term_begin_date(
            school_id=school_id,
            academic_year=selected_program_year,
            term=selected_program_term,
            current_value='',
        )
    term_program_rows = list_school_term_programs(school_id)
    for row in term_program_rows:
        row['is_locked'] = _is_past_term_locked(
            row.get('academic_year', ''),
            row.get('term', ''),
            current_year,
            current_term,
        )
    term_program_events = build_term_program_events(term_program)
    term_program_reminders = build_term_program_reminders(term_program)
    meta = term_program.get('program_meta_json') if isinstance(term_program.get('program_meta_json'), dict) else {}
    event_payload = []
    for event in term_program_events:
        event_payload.append({
            'label': event.get('label', ''),
            'date_raw': event.get('date_raw', ''),
            'date_end_raw': event.get('date_end_raw', ''),
            'status': event.get('status', 'planned'),
            'is_external': str(event.get('key', '')).startswith('external_program_'),
        })
    selected_calendar_month = (request.args.get('calendar_month', '') or '').strip()
    if not re.fullmatch(r'^\d{4}-\d{2}$', selected_calendar_month or ''):
        if event_payload and _parse_iso_date(event_payload[0].get('date_raw', '')):
            selected_calendar_month = _parse_iso_date(event_payload[0].get('date_raw', '')).strftime('%Y-%m')
        else:
            selected_calendar_month = datetime.now().strftime('%Y-%m')
    last_login_at = format_timestamp(get_last_login_at(session.get('user_id')))
    return render_template(
        'school/school_term_programs.html',
        school=school,
        role='school_admin',
        managed_school_id=school_id,
        current_term=current_term,
        current_year=current_year,
        selected_program_term=selected_program_term,
        selected_program_year=selected_program_year,
        selected_calendar_month=selected_calendar_month,
        term_program=term_program,
        term_program_rows=term_program_rows,
        term_program_events=term_program_events,
        term_program_reminders=term_program_reminders,
        term_program_events_payload=event_payload,
        reminder_channels=meta.get('reminder_channels') if isinstance(meta.get('reminder_channels'), dict) else {'in_app': True, 'email': False, 'sms': False},
        reminder_contacts=meta.get('reminder_contacts') if isinstance(meta.get('reminder_contacts'), dict) else {'emails': [], 'phones': []},
        last_login_at=last_login_at,
    )

@app.route('/school-admin/term-programs', methods=['POST'])
def school_admin_save_term_programs():
    if session.get('role') != 'school_admin':
        return redirect(url_for('login'))
    role = 'school_admin'
    school_id = (session.get('school_id') or '').strip()
    school = get_school(school_id) or {}
    current_term = get_current_term(school)
    current_year = (school or {}).get('academic_year', '')
    target_term = (request.form.get('program_term', '') or '').strip() or current_term
    target_year = (request.form.get('program_year', '') or '').strip() or current_year
    if target_term not in {'First Term', 'Second Term', 'Third Term'}:
        flash('Program term must be First Term, Second Term, or Third Term.', 'error')
        return redirect(url_for('school_admin_term_programs'))
    if target_year and not re.fullmatch(r'^\d{4}-\d{4}$', target_year):
        flash('Program academic year must be in YYYY-YYYY format.', 'error')
        return redirect(url_for('school_admin_term_programs'))

    payload = {
        'midterm_break_start': (request.form.get('midterm_break_start', '') or '').strip(),
        'midterm_break_end': (request.form.get('midterm_break_end', '') or '').strip(),
        'exams_period_start': (request.form.get('exams_period_start', '') or '').strip(),
        'exams_period_end': (request.form.get('exams_period_end', '') or '').strip(),
        'pta_meeting_date': (request.form.get('pta_meeting_date', '') or '').strip(),
        'interhouse_sports_date': (request.form.get('interhouse_sports_date', '') or '').strip(),
        'graduation_ceremony_date': (request.form.get('graduation_ceremony_date', '') or '').strip(),
        'continuous_assessment_deadline': (request.form.get('continuous_assessment_deadline', '') or '').strip(),
        'school_events_date': (request.form.get('school_events_date', '') or '').strip(),
        'school_events': (request.form.get('school_events', '') or '').strip(),
        'next_term_begin_date': (request.form.get('next_term_begin_date', '') or '').strip(),
    }
    ext_names = request.form.getlist('external_program_name[]') or request.form.getlist('external_program_name')
    ext_dates = request.form.getlist('external_program_date[]') or request.form.getlist('external_program_date')
    ext_notes = request.form.getlist('external_program_note[]') or request.form.getlist('external_program_note')
    ext_statuses = request.form.getlist('external_program_status[]') or request.form.getlist('external_program_status')
    ext_attachments = request.form.getlist('external_program_attachment[]') or request.form.getlist('external_program_attachment')
    ext_recurrence = request.form.getlist('external_program_recurrence[]') or request.form.getlist('external_program_recurrence')
    ext_recurrence_until = request.form.getlist('external_program_recurrence_until[]') or request.form.getlist('external_program_recurrence_until')
    ext_visibility = request.form.getlist('external_program_visibility[]') or request.form.getlist('external_program_visibility')
    holiday_names = request.form.getlist('holiday_name[]') or request.form.getlist('holiday_name')
    holiday_starts = request.form.getlist('holiday_start[]') or request.form.getlist('holiday_start')
    holiday_ends = request.form.getlist('holiday_end[]') or request.form.getlist('holiday_end')
    holiday_types = request.form.getlist('holiday_type[]') or request.form.getlist('holiday_type')

    def _validate_date(name, value):
        if not value:
            return None
        parsed = _parse_iso_date(value)
        if not parsed:
            flash(f'{name} must be in YYYY-MM-DD format.', 'error')
            return False
        return parsed

    mid_start = _validate_date('Midterm break start', payload['midterm_break_start'])
    if mid_start is False:
        return redirect(url_for('school_admin_term_programs', program_term=target_term, program_year=target_year))
    mid_end = _validate_date('Midterm break end', payload['midterm_break_end'])
    if mid_end is False:
        return redirect(url_for('school_admin_term_programs', program_term=target_term, program_year=target_year))
    exam_start = _validate_date('Exams period start', payload['exams_period_start'])
    if exam_start is False:
        return redirect(url_for('school_admin_term_programs', program_term=target_term, program_year=target_year))
    exam_end = _validate_date('Exams period end', payload['exams_period_end'])
    if exam_end is False:
        return redirect(url_for('school_admin_term_programs', program_term=target_term, program_year=target_year))
    pta_date = _validate_date('PTA meeting date', payload['pta_meeting_date'])
    if pta_date is False:
        return redirect(url_for('school_admin_term_programs', program_term=target_term, program_year=target_year))
    interhouse_date = _validate_date('Inter-house sports date', payload['interhouse_sports_date'])
    if interhouse_date is False:
        return redirect(url_for('school_admin_term_programs', program_term=target_term, program_year=target_year))
    graduation_date = _validate_date('Graduation ceremony date', payload['graduation_ceremony_date'])
    if graduation_date is False:
        return redirect(url_for('school_admin_term_programs', program_term=target_term, program_year=target_year))
    ca_deadline = _validate_date('Continuous assessment deadline', payload['continuous_assessment_deadline'])
    if ca_deadline is False:
        return redirect(url_for('school_admin_term_programs', program_term=target_term, program_year=target_year))
    school_events_date = _validate_date('School event date', payload['school_events_date'])
    if school_events_date is False:
        return redirect(url_for('school_admin_term_programs', program_term=target_term, program_year=target_year))
    next_term_begin_date = _validate_date('Next term begin date', payload['next_term_begin_date'])
    if next_term_begin_date is False:
        return redirect(url_for('school_admin_term_programs', program_term=target_term, program_year=target_year))
    external_programs = []
    max_ext = max(len(ext_names), len(ext_dates), len(ext_notes), len(ext_statuses), len(ext_attachments), len(ext_recurrence), len(ext_recurrence_until), len(ext_visibility))
    valid_status = {'planned', 'confirmed', 'completed', 'cancelled'}
    if max_ext > 30:
        flash('Too many external programs (max 30 per term).', 'error')
        return redirect(url_for('school_admin_term_programs', program_term=target_term, program_year=target_year))
    for i in range(max_ext):
        name_value = (ext_names[i] if i < len(ext_names) else '').strip()
        date_value = (ext_dates[i] if i < len(ext_dates) else '').strip()
        note_value = (ext_notes[i] if i < len(ext_notes) else '').strip()
        status_value = (ext_statuses[i] if i < len(ext_statuses) else 'planned').strip().lower()
        attachment_value = (ext_attachments[i] if i < len(ext_attachments) else '').strip()
        recurrence_value = (ext_recurrence[i] if i < len(ext_recurrence) else 'none').strip().lower()
        recurrence_until_value = (ext_recurrence_until[i] if i < len(ext_recurrence_until) else '').strip()
        visibility_value = (ext_visibility[i] if i < len(ext_visibility) else 'all').strip().lower()
        if not any([name_value, date_value, note_value, attachment_value]):
            continue
        if not name_value:
            flash('Each external program must have a name.', 'error')
            return redirect(url_for('school_admin_term_programs', program_term=target_term, program_year=target_year))
        parsed_ext_date = _validate_date(f'External program date ({name_value})', date_value)
        if parsed_ext_date is False:
            return redirect(url_for('school_admin_term_programs', program_term=target_term, program_year=target_year))
        if not parsed_ext_date:
            flash(f'External program "{name_value}" requires a date.', 'error')
            return redirect(url_for('school_admin_term_programs', program_term=target_term, program_year=target_year))
        if recurrence_value not in {'none', 'weekly', 'monthly'}:
            recurrence_value = 'none'
        recurrence_until_date = _parse_iso_date(recurrence_until_value) if recurrence_until_value else None
        if recurrence_value != 'none':
            if not recurrence_until_date:
                flash(f'External program "{name_value}" recurrence needs a valid "Repeat Until" date.', 'error')
                return redirect(url_for('school_admin_term_programs', program_term=target_term, program_year=target_year))
            if recurrence_until_date < parsed_ext_date:
                flash(f'External program "{name_value}" repeat-until date cannot be before start date.', 'error')
                return redirect(url_for('school_admin_term_programs', program_term=target_term, program_year=target_year))
        vis_map = {'teachers': True, 'parents': True, 'students': True}
        if visibility_value == 'teachers':
            vis_map = {'teachers': True, 'parents': False, 'students': False}
        elif visibility_value == 'parents':
            vis_map = {'teachers': False, 'parents': True, 'students': False}
        elif visibility_value == 'students':
            vis_map = {'teachers': False, 'parents': False, 'students': True}
        elif visibility_value == 'staff':
            vis_map = {'teachers': True, 'parents': False, 'students': True}
        elif visibility_value == 'parents_students':
            vis_map = {'teachers': False, 'parents': True, 'students': True}
        external_programs.append({
            'name': name_value[:120],
            'date': parsed_ext_date.isoformat(),
            'note': note_value[:500],
            'status': status_value if status_value in valid_status else 'planned',
            'attachment': attachment_value[:400],
            'recurrence': recurrence_value,
            'recurrence_until': recurrence_until_date.isoformat() if recurrence_until_date else '',
            'visibility': vis_map,
        })
    holidays = []
    max_holidays = max(len(holiday_names), len(holiday_starts), len(holiday_ends), len(holiday_types))
    if max_holidays > 40:
        flash('Too many holiday rows (max 40 per term).', 'error')
        return redirect(url_for('school_admin_term_programs', program_term=target_term, program_year=target_year))
    for i in range(max_holidays):
        name_value = (holiday_names[i] if i < len(holiday_names) else '').strip()
        start_value = (holiday_starts[i] if i < len(holiday_starts) else '').strip()
        end_value = (holiday_ends[i] if i < len(holiday_ends) else '').strip()
        type_value = (holiday_types[i] if i < len(holiday_types) else 'holiday').strip().lower()
        if not any([name_value, start_value, end_value]):
            continue
        start_date = _validate_date(f'Holiday start ({name_value or "Unnamed"})', start_value)
        if start_date is False:
            return redirect(url_for('school_admin_term_programs', program_term=target_term, program_year=target_year))
        if not start_date:
            flash('Each holiday row requires a start date.', 'error')
            return redirect(url_for('school_admin_term_programs', program_term=target_term, program_year=target_year))
        end_date = _validate_date(f'Holiday end ({name_value or "Unnamed"})', end_value) if end_value else start_date
        if end_date is False:
            return redirect(url_for('school_admin_term_programs', program_term=target_term, program_year=target_year))
        if end_date < start_date:
            start_date, end_date = end_date, start_date
        holidays.append({
            'name': (name_value or 'Holiday')[:120],
            'start': start_date.isoformat(),
            'end': end_date.isoformat(),
            'type': (type_value or 'holiday')[:40],
        })

    if bool(payload['midterm_break_start']) != bool(payload['midterm_break_end']):
        flash('Midterm break start and end dates must both be set.', 'error')
        return redirect(url_for('school_admin_term_programs', program_term=target_term, program_year=target_year))
    if mid_start and mid_end and mid_end < mid_start:
        flash('Midterm break end date cannot be earlier than start date.', 'error')
        return redirect(url_for('school_admin_term_programs', program_term=target_term, program_year=target_year))
    if bool(payload['exams_period_start']) != bool(payload['exams_period_end']):
        flash('Exams period start and end dates must both be set.', 'error')
        return redirect(url_for('school_admin_term_programs', program_term=target_term, program_year=target_year))
    if exam_start and exam_end and exam_end < exam_start:
        flash('Exams period end date cannot be earlier than start date.', 'error')
        return redirect(url_for('school_admin_term_programs', program_term=target_term, program_year=target_year))
    if len(payload['school_events']) > 2000:
        flash('School events note is too long (max 2000 characters).', 'error')
        return redirect(url_for('school_admin_term_programs', program_term=target_term, program_year=target_year))

    is_locked = _is_past_term_locked(target_year, target_term, current_year, current_term)
    lock_override = False
    if is_locked:
        flash('Past terms are locked for editing.', 'error')
        return redirect(url_for('school_admin_term_programs', program_term=target_term, program_year=target_year, school_id=school_id))

    # Conflict checker with severity
    conflict_errors = []
    conflict_warnings = []
    if mid_start and mid_end and exam_start and exam_end:
        overlap = not (exam_end < mid_start or exam_start > mid_end)
        if overlap:
            conflict_errors.append('Mid-term break overlaps with exams period.')
    single_event_rows = [
        ('PTA meeting', pta_date),
        ('Inter-house sports', interhouse_date),
        ('Graduation ceremony', graduation_date),
        ('Continuous assessment deadline', ca_deadline),
        ('School event', school_events_date),
    ]
    for item in external_programs:
        start_occ = _parse_iso_date(item.get('date', ''))
        recurrence_mode = (item.get('recurrence') or 'none').strip().lower()
        recurrence_until = _parse_iso_date(item.get('recurrence_until', '')) if item.get('recurrence_until') else None
        for occ_date in _expand_recurring_dates(start_occ, recurrence_mode, recurrence_until):
            if occ_date:
                single_event_rows.append((f'External program "{item.get("name", "")}"', occ_date))
    date_index = {}
    for label, date_value in single_event_rows:
        if not date_value:
            continue
        iso = date_value.isoformat()
        if iso in date_index:
            conflict_warnings.append(f'{label} conflicts with {date_index[iso]} on {iso}.')
        else:
            date_index[iso] = label
        if mid_start and mid_end and mid_start <= date_value <= mid_end:
            conflict_warnings.append(f'{label} falls within mid-term break ({mid_start.isoformat()} to {mid_end.isoformat()}).')
        if exam_start and exam_end and exam_start <= date_value <= exam_end:
            conflict_warnings.append(f'{label} falls within exams period ({exam_start.isoformat()} to {exam_end.isoformat()}).')
    for holiday in holidays:
        h_start = _parse_iso_date(holiday.get('start', ''))
        h_end = _parse_iso_date(holiday.get('end', ''))
        if not h_start or not h_end:
            continue
        for label, date_value in single_event_rows:
            if date_value and h_start <= date_value <= h_end:
                conflict_warnings.append(f'{label} is scheduled during holiday "{holiday.get("name", "Holiday")}".')
    if conflict_errors:
        flash('Conflict checker: ' + ' '.join(conflict_errors[:4]), 'error')
        return redirect(url_for('school_admin_term_programs', program_term=target_term, program_year=target_year, school_id=school_id))
    if conflict_warnings:
        flash('Schedule warnings: ' + ' '.join(conflict_warnings[:4]), 'warning')

    source_meta = {}
    if request.form.get('copy_previous') == '1':
        source_year = _previous_academic_year(target_year)
        source = get_school_term_program(school_id, source_year, target_term) if source_year else {}
        if source and _term_program_has_content(source):
            for key in (
                'midterm_break_start',
                'midterm_break_end',
                'exams_period_start',
                'exams_period_end',
                'pta_meeting_date',
                'interhouse_sports_date',
                'graduation_ceremony_date',
                'continuous_assessment_deadline',
                'school_events_date',
                'school_events',
                'next_term_begin_date',
            ):
                if not (payload.get(key) or '').strip():
                    payload[key] = (source.get(key) or '').strip()
            source_meta = source.get('program_meta_json') if isinstance(source.get('program_meta_json'), dict) else {}
            flash(f'Program template copied from {source_year} {target_term}.', 'info')
        else:
            flash('No previous-year template found to copy.', 'error')
            return redirect(url_for('school_admin_term_programs', program_term=target_term, program_year=target_year, school_id=school_id))

    if not (payload.get('next_term_begin_date') or '').strip():
        inferred_next_begin = resolve_next_term_begin_date(
            school_id=school_id,
            academic_year=target_year,
            term=target_term,
            current_value='',
        )
        if inferred_next_begin:
            payload['next_term_begin_date'] = inferred_next_begin
            flash('Next term begin date was auto-filled from the next term calendar open date.', 'info')

    valid_status = {'planned', 'confirmed', 'completed', 'cancelled'}
    if not external_programs and isinstance(source_meta.get('external_programs'), list):
        for item in source_meta.get('external_programs') or []:
            if not isinstance(item, dict):
                continue
            n = (item.get('name') or '').strip()
            d = (item.get('date') or '').strip()
            if not n or not _parse_iso_date(d):
                continue
            external_programs.append({
                'name': n[:120],
                'date': d,
                'note': (item.get('note') or '').strip()[:500],
                'status': ((item.get('status') or 'planned').strip().lower() if (item.get('status') or '').strip().lower() in valid_status else 'planned'),
                'attachment': (item.get('attachment') or '').strip()[:400],
                'recurrence': ((item.get('recurrence') or 'none').strip().lower() if (item.get('recurrence') or '').strip().lower() in {'none', 'weekly', 'monthly'} else 'none'),
                'recurrence_until': (item.get('recurrence_until') or '').strip(),
                'visibility': item.get('visibility') if isinstance(item.get('visibility'), dict) else {'teachers': True, 'parents': True, 'students': True},
            })
    if not holidays and isinstance(source_meta.get('holidays'), list):
        for item in source_meta.get('holidays') or []:
            if not isinstance(item, dict):
                continue
            start = (item.get('start') or '').strip()
            end = (item.get('end') or start).strip()
            if not _parse_iso_date(start) or not _parse_iso_date(end):
                continue
            holidays.append({
                'name': ((item.get('name') or 'Holiday').strip() or 'Holiday')[:120],
                'start': start,
                'end': end,
                'type': ((item.get('type') or 'holiday').strip() or 'holiday')[:40],
            })
    event_status = dict(source_meta.get('event_status', {})) if isinstance(source_meta.get('event_status'), dict) else {}
    event_tags = dict(source_meta.get('event_tags', {})) if isinstance(source_meta.get('event_tags'), dict) else {}
    event_notes = dict(source_meta.get('event_notes', {})) if isinstance(source_meta.get('event_notes'), dict) else {}
    event_attachments = dict(source_meta.get('event_attachments', {})) if isinstance(source_meta.get('event_attachments'), dict) else {}
    event_visibility = dict(source_meta.get('event_visibility', {})) if isinstance(source_meta.get('event_visibility'), dict) else {}
    for event_key in _term_program_event_keys():
        status_value = (request.form.get(f'{event_key}_status', '') or '').strip().lower()
        if status_value:
            event_status[event_key] = status_value if status_value in valid_status else 'planned'
        tags_raw = (request.form.get(f'{event_key}_tags', '') or '').strip()
        if tags_raw:
            event_tags[event_key] = [x.strip() for x in tags_raw.split(',') if x.strip()][:8]
        note_value = (request.form.get(f'{event_key}_note', '') or '').strip()
        if note_value:
            event_notes[event_key] = note_value[:500]
        attachment_value = (request.form.get(f'{event_key}_attachment', '') or '').strip()
        if attachment_value:
            event_attachments[event_key] = attachment_value[:400]
        event_visibility[event_key] = {
            'teachers': bool(request.form.get(f'{event_key}_visible_teachers')),
            'parents': bool(request.form.get(f'{event_key}_visible_parents')),
            'students': bool(request.form.get(f'{event_key}_visible_students')),
        }
    for idx, item in enumerate(external_programs, start=1):
        event_visibility[f'external_program_{idx}'] = item.get('visibility') if isinstance(item.get('visibility'), dict) else {'teachers': True, 'parents': True, 'students': True}
    visibility = {
        'teachers': bool(request.form.get('visible_to_teachers')),
        'parents': bool(request.form.get('visible_to_parents')),
        'students': bool(request.form.get('visible_to_students')),
    }
    try:
        reminder_days_before = int((request.form.get('reminder_days_before', '') or '7').strip())
    except Exception:
        reminder_days_before = 7
    reminder_days_before = max(0, min(reminder_days_before, 90))
    reminder_channels = {
        'in_app': True,
        'email': bool(request.form.get('reminder_channel_email')),
        'sms': bool(request.form.get('reminder_channel_sms')),
    }
    reminder_emails = [x.strip().lower() for x in (request.form.get('reminder_emails', '') or '').split(',') if x.strip()]
    reminder_phones = [x.strip() for x in (request.form.get('reminder_phones', '') or '').split(',') if x.strip()]
    payload['program_meta_json'] = {
        'event_status': event_status,
        'event_tags': event_tags,
        'event_notes': event_notes,
        'event_attachments': event_attachments,
        'event_visibility': event_visibility,
        'external_programs': external_programs,
        'holidays': holidays,
        'visibility': visibility,
        'reminder_days_before': reminder_days_before,
        'reminder_channels': reminder_channels,
        'reminder_contacts': {'emails': reminder_emails, 'phones': reminder_phones},
        'locked_by_super_admin_override': bool(lock_override),
        'updated_by_role': role,
        'updated_at': datetime.now().isoformat(),
    }

    try:
        with db_connection(commit=True) as conn:
            c = conn.cursor()
            save_school_term_program_with_cursor(c, school_id, target_year, target_term, payload)
    except Exception as exc:
        flash(f'Failed to save school term programs: {str(exc)}', 'error')
        return redirect(url_for('school_admin_term_programs', program_term=target_term, program_year=target_year, school_id=school_id))

    flash(f'School programs saved for {target_term} ({target_year}).', 'success')
    return redirect(url_for('school_admin_term_programs', program_term=target_term, program_year=target_year, school_id=school_id))

@app.route('/school-admin/term-programs/print')
def school_admin_print_term_programs():
    if session.get('role') != 'school_admin':
        return redirect(url_for('login'))
    school_id = (session.get('school_id') or '').strip()
    school = get_school(school_id) or {}
    current_term = get_current_term(school)
    current_year = (school or {}).get('academic_year', '')
    selected_program_term = (request.args.get('program_term', '') or '').strip() or current_term
    selected_program_year = (request.args.get('program_year', '') or '').strip() or current_year
    term_program = get_school_term_program(school_id, selected_program_year, selected_program_term)
    events = build_term_program_events(term_program)
    return render_template(
        'school/school_term_programs_print.html',
        school=school,
        role='school_admin',
        managed_school_id=school_id,
        selected_program_term=selected_program_term,
        selected_program_year=selected_program_year,
        term_program=term_program,
        events=events,
        generated_at=datetime.now(),
    )

@app.route('/school-admin/term-programs/export-ics')
def school_admin_export_term_programs_ics():
    if session.get('role') != 'school_admin':
        return redirect(url_for('login'))
    school_id = (session.get('school_id') or '').strip()
    school = get_school(school_id) or {}
    current_term = get_current_term(school)
    current_year = (school or {}).get('academic_year', '')
    selected_program_term = (request.args.get('program_term', '') or '').strip() or current_term
    selected_program_year = (request.args.get('program_year', '') or '').strip() or current_year
    term_program = get_school_term_program(school_id, selected_program_year, selected_program_term)
    events = build_term_program_events(term_program)
    content = build_term_program_ics_content(
        school=school,
        events=events,
        term_label=selected_program_term,
        year_label=selected_program_year,
    )
    filename_school = re.sub(r'[^A-Za-z0-9_-]+', '_', (school.get('school_name', 'school') or 'school')).strip('_') or 'school'
    filename = f"{filename_school}_{selected_program_year}_{selected_program_term.replace(' ', '_')}.ics"
    return Response(
        content,
        mimetype='text/calendar',
        headers={'Content-Disposition': f'attachment; filename=\"{filename}\"'},
    )

@app.route('/school-admin/term-programs/send-reminders', methods=['POST'])
def school_admin_send_term_program_reminders():
    if session.get('role') != 'school_admin':
        return redirect(url_for('login'))
    school_id = (session.get('school_id') or '').strip()
    school = get_school(school_id) or {}
    current_term = get_current_term(school)
    current_year = (school or {}).get('academic_year', '')
    target_term = (request.form.get('program_term', '') or '').strip() or current_term
    target_year = (request.form.get('program_year', '') or '').strip() or current_year
    program = get_school_term_program(school_id, target_year, target_term)
    reminders = build_term_program_reminders(program)
    meta = program.get('program_meta_json') if isinstance(program.get('program_meta_json'), dict) else {}
    channels = meta.get('reminder_channels') if isinstance(meta.get('reminder_channels'), dict) else {'in_app': True, 'email': False, 'sms': False}
    contacts = meta.get('reminder_contacts') if isinstance(meta.get('reminder_contacts'), dict) else {}
    emails = [x.strip().lower() for x in (contacts.get('emails') or []) if str(x).strip()]
    phones = [x.strip() for x in (contacts.get('phones') or []) if str(x).strip()]
    result = send_term_program_notifications(
        school=school,
        reminders=reminders,
        channels=channels,
        email_recipients=emails,
        sms_recipients=phones,
    )
    if result.get('sent_email', 0) or result.get('sent_sms', 0):
        flash(f"Reminders sent. Email: {result.get('sent_email', 0)}, SMS: {result.get('sent_sms', 0)}.", 'success')
    else:
        flash('No reminders sent. Check channel settings, recipients, or upcoming events window.', 'warning')
    for err in result.get('errors', [])[:3]:
        flash(err, 'warning')
    return redirect(url_for('school_admin_term_programs', program_term=target_term, program_year=target_year))

@app.route('/school-admin/parents')
def school_admin_view_parents():
    if session.get('role') != 'school_admin':
        return redirect(url_for('login'))

    school_id = session.get('school_id')
    school = get_school(school_id) or {}
    parent_links = get_school_parent_links(school_id)
    parent_count = len({(row.get('parent_phone') or '').strip() for row in parent_links if (row.get('parent_phone') or '').strip()})
    linked_students = len(parent_links)
    last_login_at = format_timestamp(get_last_login_at(session.get('user_id')))

    return render_template(
        'school/school_admin_parents.html',
        school=school,
        parent_links=parent_links,
        parent_count=parent_count,
        linked_students=linked_students,
        last_login_at=last_login_at,
    )

@app.route('/school-admin/upload-principal-signature', methods=['POST'])
def school_admin_upload_principal_signature():
    if session.get('role') != 'school_admin':
        return redirect(url_for('login'))
    school_id = session.get('school_id')
    admin_password = request.form.get('admin_password', '')
    admin_user = get_user(session.get('user_id'))
    if not admin_user or not check_password(admin_user.get('password_hash', ''), admin_password):
        flash('Invalid school admin password. Principal signature not saved.', 'error')
        return redirect(url_for('school_admin_dashboard'))
    signature_data, err = parse_uploaded_signature(request.files.get('principal_signature'))
    if err:
        flash(err, 'error')
        return redirect(url_for('school_admin_dashboard'))
    set_principal_signature(school_id, signature_data)
    flash('Principal signature saved successfully.', 'success')
    return redirect(url_for('school_admin_dashboard'))

@app.route('/school-admin/class-subjects', methods=['GET', 'POST'])
def school_admin_class_subjects():
    if session.get('role') != 'school_admin':
        return redirect(url_for('login'))

    school_id = session.get('school_id')
    subject_catalog_map = get_school_subject_catalog_map(school_id)

    if request.method == 'POST':
        classname = canonicalize_classname(request.form.get('classname', '').strip())
        if not classname:
            flash('Class name is required.', 'error')
            return redirect(url_for('school_admin_class_subjects'))
        school = get_school(school_id) or {}

        core_subjects = _dedupe_keep_order([
            normalize_subject_name(s) for s in request.form.getlist('core_subjects') if (s or '').strip()
        ])
        science_subjects = _dedupe_keep_order([
            normalize_subject_name(s) for s in request.form.getlist('science_subjects') if (s or '').strip()
        ])
        art_subjects = _dedupe_keep_order([
            normalize_subject_name(s) for s in request.form.getlist('art_subjects') if (s or '').strip()
        ])
        commercial_subjects = _dedupe_keep_order([
            normalize_subject_name(s) for s in request.form.getlist('commercial_subjects') if (s or '').strip()
        ])
        optional_subjects = _dedupe_keep_order([
            normalize_subject_name(s) for s in request.form.getlist('optional_subjects') if (s or '').strip()
        ])
        # Allow adding brand-new subjects not currently present in the shared catalog.
        new_core = parse_subjects_text(request.form.get('new_core_subjects', ''))
        new_science = parse_subjects_text(request.form.get('new_science_subjects', ''))
        new_art = parse_subjects_text(request.form.get('new_art_subjects', ''))
        new_commercial = parse_subjects_text(request.form.get('new_commercial_subjects', ''))
        new_optional = parse_subjects_text(request.form.get('new_optional_subjects', ''))
        if new_core:
            core_subjects = _dedupe_keep_order(core_subjects + new_core)
        if new_science:
            science_subjects = _dedupe_keep_order(science_subjects + new_science)
        if new_art:
            art_subjects = _dedupe_keep_order(art_subjects + new_art)
        if new_commercial:
            commercial_subjects = _dedupe_keep_order(commercial_subjects + new_commercial)
        if new_optional:
            optional_subjects = _dedupe_keep_order(optional_subjects + new_optional)
        

        uses_stream = class_uses_stream_for_school(school, classname)
        if not uses_stream:
            if is_ss1_class(classname) and ((school or {}).get('ss1_stream_mode', 'separate') or '').strip().lower() == 'combined':
                # SS1 combined mode uses one unified subject list from all selected SS buckets.
                core_subjects = _dedupe_keep_order(core_subjects + science_subjects + art_subjects + commercial_subjects + optional_subjects)
            # Non-stream classes persist one unified subject list only.
            science_subjects = []
            art_subjects = []
            commercial_subjects = []
            optional_subjects = []

        if not core_subjects:
            flash('Subjects offered are required.', 'error')
            return redirect(url_for('school_admin_class_subjects'))

        if uses_stream and not (science_subjects or art_subjects or commercial_subjects):
            flash('For SS classes, add subjects for at least one stream (Science/Art/Commercial).', 'error')
            return redirect(url_for('school_admin_class_subjects'))

        try:
            save_class_subject_config(
                school_id=school_id,
                classname=classname,
                core_subjects=core_subjects,
                science_subjects=science_subjects,
                art_subjects=art_subjects,
                commercial_subjects=commercial_subjects,
                optional_subjects=optional_subjects,
            )
            flash(f'Subject configuration saved for {classname}.', 'success')
        except Exception as exc:
            flash(f'Error saving class subjects: {str(exc)}', 'error')

        return redirect(url_for('school_admin_class_subjects'))

    configs = get_all_class_subject_configs(school_id)
    school = get_school(school_id) or {}
    class_options = sorted(subject_catalog_map.keys())
    return render_template(
        'school/school_admin_class_subjects.html',
        configs=configs,
        school=school,
        subject_catalog_map=subject_catalog_map,
        class_options=class_options,
    )

@app.route('/school-admin/delete-class-subject-config', methods=['POST'])
def school_admin_delete_class_subject_config():
    if session.get('role') != 'school_admin':
        return redirect(url_for('login'))

    school_id = session.get('school_id')
    classname = (request.form.get('classname', '') or '').strip()
    if not classname:
        flash('Class name is required for delete.', 'error')
        return redirect(url_for('school_admin_class_subjects'))

    try:
        deleted = delete_class_subject_config(school_id, classname)
        if deleted:
            flash(f'Subject configuration deleted for {classname}. You can now reconfigure it.', 'success')
        else:
            flash(f'No subject configuration found for {classname}.', 'error')
    except Exception as exc:
        flash(f'Error deleting class subject configuration: {str(exc)}', 'error')
    return redirect(url_for('school_admin_class_subjects'))

@app.route('/school-admin/settings', methods=['GET', 'POST'])
def school_admin_settings():
    if session.get('role') != 'school_admin':
        return redirect(url_for('login'))
    
    school_id = session.get('school_id')
    current_school = get_school(school_id) or {}
    def _to_int(value, default):
        try:
            return int(value)
        except (TypeError, ValueError):
            return int(default)
    
    if request.method == 'POST':
        previous_term = get_current_term(current_school)
        previous_year = (current_school.get('academic_year', '') or '').strip()
        grade_a_min = _to_int(request.form.get('grade_a_min', 70), 70)
        grade_b_min = _to_int(request.form.get('grade_b_min', 60), 60)
        grade_c_min = _to_int(request.form.get('grade_c_min', 50), 50)
        grade_d_min = _to_int(request.form.get('grade_d_min', 40), 40)
        pass_mark = _to_int(request.form.get('pass_mark', 50), 50)
        max_tests = _to_int(request.form.get('max_tests', 3), 3)
        test_score_max = _to_int(request.form.get('test_score_max', 30), 30)
        ss_ranking_mode = request.form.get('ss_ranking_mode', 'together').strip().lower()
        class_arm_ranking_mode = request.form.get('class_arm_ranking_mode', 'separate').strip().lower()
        ss1_stream_mode = request.form.get('ss1_stream_mode', 'separate').strip().lower()
        show_positions = 1 if request.form.get('show_positions', '1').strip() == '1' else 0
        combine_third_raw = (request.form.get('combine_third_term_results', '0') or '0').strip()
        combine_third = 1 if combine_third_raw == '1' else 0
        if ss_ranking_mode not in {'together', 'separate'}:
            ss_ranking_mode = 'together'
        if class_arm_ranking_mode not in {'separate', 'together'}:
            class_arm_ranking_mode = 'separate'
        if ss1_stream_mode not in {'separate', 'combined'}:
            ss1_stream_mode = 'separate'
        if not (0 <= grade_d_min <= grade_c_min <= grade_b_min <= grade_a_min <= 100):
            flash('Invalid grade configuration. Use A >= B >= C >= D within 0-100.', 'error')
            return redirect(url_for('school_admin_settings'))
        if not (0 <= pass_mark <= 100):
            flash('Pass mark must be between 0 and 100.', 'error')
            return redirect(url_for('school_admin_settings'))
        if not (1 <= max_tests <= 10):
            flash('Maximum Number of Tests must be between 1 and 10.', 'error')
            return redirect(url_for('school_admin_settings'))
        if not (0 <= test_score_max <= 100):
            flash('Max Total Test Score must be between 0 and 100.', 'error')
            return redirect(url_for('school_admin_settings'))
        new_term = (request.form.get('current_term', '') or '').strip()
        if new_term not in {'First Term', 'Second Term', 'Third Term'}:
            flash('Current term must be First Term, Second Term, or Third Term.', 'error')
            return redirect(url_for('school_admin_settings'))
        new_year = (request.form.get('academic_year', '') or '').strip()
        if new_year and not re.fullmatch(r'^\d{4}-\d{4}$', new_year):
            flash('Academic year must be in YYYY-YYYY format (e.g., 2026-2027).', 'error')
            return redirect(url_for('school_admin_settings'))
        if new_year:
            start_year = int(new_year[:4])
            end_year = int(new_year[5:])
            if end_year != start_year + 1:
                flash('Academic year must be consecutive (e.g., 2026-2027).', 'error')
                return redirect(url_for('school_admin_settings'))

        calendar_target_term = (request.form.get('calendar_term', '') or '').strip() or new_term
        calendar_target_year = (request.form.get('calendar_academic_year', '') or '').strip() or new_year
        if calendar_target_term not in {'First Term', 'Second Term', 'Third Term'}:
            flash('Calendar term must be First Term, Second Term, or Third Term.', 'error')
            return redirect(url_for('school_admin_settings'))
        if calendar_target_year and not re.fullmatch(r'^\d{4}-\d{4}$', calendar_target_year):
            flash('Calendar academic year must be in YYYY-YYYY format.', 'error')
            return redirect(url_for('school_admin_settings'))

        open_date = (request.form.get('term_open_date', '') or '').strip()
        close_date = (request.form.get('term_close_date', '') or '').strip()
        next_term_begin_date = (request.form.get('next_term_begin_date', '') or '').strip()

        if bool(open_date) != bool(close_date):
            flash('Term open and close dates must both be set.', 'error')
            return redirect(url_for('school_admin_settings'))

        open_dt = _parse_iso_date(open_date)
        close_dt = _parse_iso_date(close_date)
        if open_date and not open_dt:
            flash('Term open date must be in YYYY-MM-DD format.', 'error')
            return redirect(url_for('school_admin_settings'))
        if close_date and not close_dt:
            flash('Term close date must be in YYYY-MM-DD format.', 'error')
            return redirect(url_for('school_admin_settings'))
        if open_dt and close_dt and close_dt < open_dt:
            flash('Term close date cannot be earlier than term open date.', 'error')
            return redirect(url_for('school_admin_settings'))
        next_term_begin_dt = _parse_iso_date(next_term_begin_date)
        if next_term_begin_date and not next_term_begin_dt:
            flash('Next term begin date must be in YYYY-MM-DD format.', 'error')
            return redirect(url_for('school_admin_settings'))

        # Mid-term break is now sourced from School Programs for the same year/term.
        program_for_calendar = get_school_term_program(school_id, calendar_target_year, calendar_target_term)
        break_start = (program_for_calendar.get('midterm_break_start') or '').strip()
        break_end = (program_for_calendar.get('midterm_break_end') or '').strip()
        if not next_term_begin_date:
            next_term_begin_date = resolve_next_term_begin_date(
                school_id=school_id,
                academic_year=calendar_target_year,
                term=calendar_target_term,
                current_value=(program_for_calendar.get('next_term_begin_date') or ''),
            )
        break_start_dt = _parse_iso_date(break_start)
        break_end_dt = _parse_iso_date(break_end)
        if bool(break_start) != bool(break_end):
            break_start = ''
            break_end = ''
            break_start_dt = None
            break_end_dt = None
            flash('School program mid-term break is incomplete for selected year/term, so it was not applied to Days Open.', 'info')
        elif break_start and break_end and (not break_start_dt or not break_end_dt):
            break_start = ''
            break_end = ''
            break_start_dt = None
            break_end_dt = None
            flash('School program mid-term break has invalid date format, so it was not applied to Days Open.', 'info')
        elif break_start_dt and break_end_dt:
            if break_end_dt < break_start_dt:
                break_start_dt, break_end_dt = break_end_dt, break_start_dt
                break_start, break_end = break_start_dt.isoformat(), break_end_dt.isoformat()
            if open_dt and close_dt and (break_start_dt < open_dt or break_end_dt > close_dt):
                break_start = ''
                break_end = ''
                break_start_dt = None
                break_end_dt = None
                flash('School program mid-term break is outside the term open/close date range, so it was not applied to Days Open.', 'info')

        raw_school_logo = (request.form.get('school_logo') or '').strip()
        normalized_school_logo = normalize_school_logo_url(raw_school_logo)
        uploaded_logo = request.files.get('school_logo_file')
        if uploaded_logo and (uploaded_logo.filename or '').strip():
            uploaded_logo_data, logo_err = parse_uploaded_profile_image(uploaded_logo)
            if logo_err:
                flash(logo_err.replace('Profile image', 'School logo'), 'error')
                return redirect(url_for('school_admin_settings'))
            normalized_school_logo = uploaded_logo_data
            flash('School logo image uploaded successfully.', 'success')
        elif not raw_school_logo:
            # Keep existing stored logo when URL field is blank and no new file is uploaded.
            normalized_school_logo = (current_school.get('school_logo', '') or '').strip()
        elif raw_school_logo and normalized_school_logo != raw_school_logo:
            flash('School logo URL was converted to a direct image link automatically.', 'info')

        settings = {
            'school_name': request.form.get('school_name'),
            # Preserve location when settings form does not include it.
            'location': request.form.get('location', current_school.get('location', '')),
            'school_logo': normalized_school_logo,
            'academic_year': new_year,
            'current_term': new_term,
            'test_enabled': 1 if request.form.get('test_enabled') else 0,
            'exam_enabled': 1 if request.form.get('exam_enabled') else 0,
            'max_tests': max_tests,
            'test_score_max': test_score_max,
            'exam_objective_max': _to_int(request.form.get('exam_objective_max', 30), 30),
            'exam_theory_max': _to_int(request.form.get('exam_theory_max', 40), 40),
            'grade_a_min': grade_a_min,
            'grade_b_min': grade_b_min,
            'grade_c_min': grade_c_min,
            'grade_d_min': grade_d_min,
            'pass_mark': pass_mark,
            'show_positions': show_positions,
            'ss_ranking_mode': ss_ranking_mode,
            'class_arm_ranking_mode': class_arm_ranking_mode,
            'combine_third_term_results': combine_third,
            'ss1_stream_mode': ss1_stream_mode,
            'theme_primary_color': normalize_hex_color(request.form.get('theme_primary_color', ''), '#1E3C72'),
            'theme_secondary_color': normalize_hex_color(request.form.get('theme_secondary_color', ''), '#2A5298'),
            'theme_accent_color': normalize_hex_color(request.form.get('theme_accent_color', ''), '#1F7A8C'),
        }
        assessment_updates = []
        for level in ('primary', 'jss', 'ss'):
            mode = request.form.get(f'exam_mode_{level}', 'separate').strip().lower()
            objective_max = _to_int(request.form.get(f'objective_max_{level}', 0), 0)
            theory_max = _to_int(request.form.get(f'theory_max_{level}', 0), 0)
            exam_score_max = _to_int(request.form.get(f'exam_score_max_{level}', 0), 0)
            if mode not in {'combined', 'separate'}:
                mode = 'separate'
            if objective_max < 0 or objective_max > 100 or theory_max < 0 or theory_max > 100:
                flash(f'{level.upper()} objective/theory maxima must be between 0 and 100.', 'error')
                return redirect(url_for('school_admin_settings'))
            if exam_score_max < 0 or exam_score_max > 100:
                flash(f'{level.upper()} exam score maximum must be between 0 and 100.', 'error')
                return redirect(url_for('school_admin_settings'))
            if mode == 'separate':
                exam_score_max = objective_max + theory_max
                if exam_score_max > 100:
                    flash(f'{level.upper()} objective + theory maxima must not exceed 100.', 'error')
                    return redirect(url_for('school_admin_settings'))
            if (test_score_max + exam_score_max) > 100:
                flash(
                    f'{level.upper()} total test + exam maxima must not exceed 100 '
                    f'(current: test={test_score_max}, exam={exam_score_max}).',
                    'error',
                )
                return redirect(url_for('school_admin_settings'))
            assessment_updates.append({
                'level': level,
                'exam_mode': mode,
                'objective_max': objective_max,
                'theory_max': theory_max,
                'exam_score_max': exam_score_max,
            })

        changed_term_or_year = previous_term.strip().lower() != new_term.strip().lower() or previous_year != new_year
        if changed_term_or_year:
            rollover_confirmed = (request.form.get('confirm_term_rollover', '') or '').strip() == '1'
            if not rollover_confirmed:
                flash(
                    'Confirm term/year rollover before saving. This moves students to new term and resets working scores.',
                    'error'
                )
                return redirect(url_for('school_admin_settings'))
        rollover_affected_rows = 0
        try:
            with db_connection(commit=True) as conn:
                c = conn.cursor()
                update_school_settings_with_cursor(c, school_id, settings)
                if changed_term_or_year:
                    rollover_affected_rows = rollover_school_term_data_with_cursor(
                        c,
                        school_id=school_id,
                        from_term=previous_term,
                        to_term=new_term,
                        from_year=previous_year,
                        to_year=new_year,
                    )
                for cfg in assessment_updates:
                    save_assessment_config_with_cursor(
                        c,
                        school_id=school_id,
                        level=cfg['level'],
                        exam_mode=cfg['exam_mode'],
                        objective_max=cfg['objective_max'],
                        theory_max=cfg['theory_max'],
                        exam_score_max=cfg['exam_score_max'],
                    )
                save_school_term_calendar_with_cursor(
                    c,
                    school_id=school_id,
                    academic_year=calendar_target_year,
                    term=calendar_target_term,
                    open_date=open_date,
                    close_date=close_date,
                    break_start=break_start,
                    break_end=break_end,
                    next_term_begin_date=next_term_begin_date,
                )
        except Exception as exc:
            flash(f'Failed to update school settings: {str(exc)}', 'error')
            return redirect(url_for('school_admin_settings'))

        if changed_term_or_year:
            log_promotion_audit_row(
                school_id=school_id,
                student_id='*',
                student_name='TERM_ROLLOVER',
                from_class='',
                to_class='',
                action='term_rollover',
                term=new_term,
                academic_year=new_year,
                changed_by=session.get('user_id', ''),
                note=(
                    f'Rollover: {previous_term} ({previous_year}) -> {new_term} ({new_year}); '
                    f'working scores reset for {int(rollover_affected_rows or 0)} student record(s).'
                ),
            )
            flash('Term/year changed: student working term moved forward, scores reset for new term, and teacher class assignments copied to the new term/year.', 'info')

        if open_date and close_date:
            days_open = calculate_open_days_excluding_weekend(open_date, close_date, break_start, break_end)
            flash(
                f'School settings updated successfully. {calendar_target_term} ({calendar_target_year}) open days: {days_open} (excluding Saturday and Sunday; mid-term break from School Programs).',
                'success'
            )
        else:
            flash('School settings updated successfully!', 'success')
        return redirect(url_for('school_admin_settings', calendar_term=calendar_target_term, calendar_year=calendar_target_year))
    
    school = get_school(school_id)
    assessment_configs = get_all_assessment_configs(school_id)
    selected_calendar_term = (request.args.get('calendar_term', '') or '').strip() or get_current_term(school)
    if selected_calendar_term not in {'First Term', 'Second Term', 'Third Term'}:
        selected_calendar_term = get_current_term(school)
    selected_calendar_year = (request.args.get('calendar_year', '') or '').strip() or ((school or {}).get('academic_year', '') or '')
    calendar = get_school_term_calendar(school_id, selected_calendar_year, selected_calendar_term)
    calendar_rows = list_school_term_calendars(school_id)
    logo_input_value = (school.get('school_logo') or '').strip() if school else ''
    if logo_input_value.lower().startswith('data:image/'):
        # Do not inject large base64 payloads into the URL input value.
        logo_input_value = ''
    return render_template(
        'school/school_settings.html',
        school=school,
        school_logo_input_value=logo_input_value,
        assessment_configs=assessment_configs,
        calendar=calendar,
        calendar_rows=calendar_rows,
        selected_calendar_term=selected_calendar_term,
        selected_calendar_year=selected_calendar_year,
    )

@app.route('/school-admin/score-audit')
def school_admin_score_audit():
    if session.get('role') != 'school_admin':
        return redirect(url_for('login'))

    school_id = session.get('school_id')
    school = get_school(school_id) or {}

    if not ensure_score_audit_schema():
        flash(
            'Score audit log table is not available yet. Run migration (python migrate.py) or use admin DB fix command.',
            'error',
        )
        return redirect(url_for('school_admin_dashboard'))

    classname = (request.args.get('classname', '') or '').strip()
    term = (request.args.get('term', '') or '').strip()
    academic_year = (request.args.get('academic_year', '') or '').strip()
    subject = normalize_subject_name((request.args.get('subject', '') or '').strip())
    teacher_id = (request.args.get('teacher_id', '') or '').strip()
    student_id = (request.args.get('student_id', '') or '').strip()
    date_from = (request.args.get('date_from', '') or '').strip()
    date_to = (request.args.get('date_to', '') or '').strip()
    try:
        limit = int(request.args.get('limit', 200))
    except (TypeError, ValueError):
        limit = 200
    limit = max(50, min(limit, 1000))
    try:
        page = int(request.args.get('page', 1))
    except (TypeError, ValueError):
        page = 1
    page = max(1, page)

    where_parts = ['school_id = ?']
    params = [school_id]

    if classname:
        where_parts.append('LOWER(classname) = LOWER(?)')
        params.append(classname)
    if term:
        where_parts.append('term = ?')
        params.append(term)
    if academic_year:
        where_parts.append("COALESCE(academic_year, '') = COALESCE(?, '')")
        params.append(academic_year)
    if subject:
        where_parts.append('LOWER(subject) = LOWER(?)')
        params.append(subject)
    if teacher_id:
        where_parts.append('LOWER(changed_by) = LOWER(?)')
        params.append(teacher_id)
    if student_id:
        where_parts.append('LOWER(student_id) = LOWER(?)')
        params.append(student_id)

    parsed_date_from = None
    parsed_date_to = None
    if date_from:
        try:
            parsed_date_from = datetime.strptime(date_from, '%Y-%m-%d')
        except Exception:
            flash('Invalid From date. Use YYYY-MM-DD.', 'error')
            return redirect(url_for('school_admin_score_audit'))
    if date_to:
        try:
            parsed_date_to = datetime.strptime(date_to, '%Y-%m-%d')
        except Exception:
            flash('Invalid To date. Use YYYY-MM-DD.', 'error')
            return redirect(url_for('school_admin_score_audit'))
    if parsed_date_from and parsed_date_to and parsed_date_to < parsed_date_from:
        flash('To date cannot be earlier than From date.', 'error')
        return redirect(url_for('school_admin_score_audit'))

    if parsed_date_from:
        where_parts.append('changed_at >= ?')
        params.append(parsed_date_from)
    if parsed_date_to:
        where_parts.append('changed_at < ?')
        params.append(parsed_date_to + timedelta(days=1))

    where_clause = ' AND '.join(where_parts)
    log_rows = []
    class_options = []
    subject_options = []
    year_options = []
    total_rows = 0
    with db_connection() as conn:
        c = conn.cursor()
        db_execute(
            c,
            f"""SELECT COUNT(*)
                FROM score_audit_logs
                WHERE {where_clause}""",
            tuple(params),
        )
        count_row = c.fetchone()
        total_rows = int((count_row[0] if count_row else 0) or 0)
        offset = (page - 1) * limit
        if offset >= total_rows and total_rows > 0:
            page = max(1, math.ceil(total_rows / limit))
            offset = (page - 1) * limit
        db_execute(
            c,
            f"""SELECT id, student_id, classname, term, COALESCE(academic_year, ''), subject,
                       old_score_json, new_score_json, changed_fields_json,
                       changed_by, changed_by_role, change_source, COALESCE(change_reason, ''), changed_at
                FROM score_audit_logs
                WHERE {where_clause}
                ORDER BY changed_at DESC
                LIMIT ? OFFSET ?""",
            tuple(params + [limit, offset]),
        )
        fetched = c.fetchall()
        for row in fetched:
            changes = _safe_json_object(row[8])
            change_items = []
            for field, values in changes.items():
                if not isinstance(values, dict):
                    continue
                change_items.append({
                    'field': field,
                    'old': values.get('old'),
                    'new': values.get('new'),
                })
            log_rows.append({
                'id': int(row[0]),
                'student_id': row[1] or '',
                'classname': row[2] or '',
                'term': row[3] or '',
                'academic_year': row[4] or '',
                'subject': row[5] or '',
                'old_score': _safe_json_object(row[6]),
                'new_score': _safe_json_object(row[7]),
                'changes': change_items,
                'changed_by': row[9] or '',
                'changed_by_role': row[10] or '',
                'change_source': row[11] or '',
                'change_reason': row[12] or '',
                'changed_at': row[13],
            })

        db_execute(
            c,
            """SELECT DISTINCT classname
               FROM score_audit_logs
               WHERE school_id = ?
               ORDER BY classname""",
            (school_id,),
        )
        class_options = [r[0] for r in c.fetchall() if r and r[0]]

        db_execute(
            c,
            """SELECT DISTINCT subject
               FROM score_audit_logs
               WHERE school_id = ?
               ORDER BY subject""",
            (school_id,),
        )
        subject_options = [r[0] for r in c.fetchall() if r and r[0]]

        db_execute(
            c,
            """SELECT DISTINCT COALESCE(academic_year, '')
               FROM score_audit_logs
               WHERE school_id = ?
               ORDER BY COALESCE(academic_year, '') DESC""",
            (school_id,),
        )
        year_options = [r[0] for r in c.fetchall() if r and r[0]]

    teacher_map = get_teachers(school_id)
    term_options = ['First Term', 'Second Term', 'Third Term']
    total_pages = max(1, math.ceil(total_rows / limit)) if total_rows else 1
    page = min(page, total_pages)
    filter_params = {
        'classname': classname,
        'term': term,
        'academic_year': academic_year,
        'subject': subject,
        'teacher_id': teacher_id,
        'student_id': student_id,
        'date_from': date_from,
        'date_to': date_to,
        'limit': limit,
    }
    prev_page_url = ''
    next_page_url = ''
    if page > 1:
        prev_page_url = url_for('school_admin_score_audit', page=page - 1, **filter_params)
    if page < total_pages:
        next_page_url = url_for('school_admin_score_audit', page=page + 1, **filter_params)

    return render_template(
        'school/score_audit_log.html',
        school=school,
        rows=log_rows,
        limit=limit,
        page=page,
        total_rows=total_rows,
        total_pages=total_pages,
        class_options=class_options,
        subject_options=subject_options,
        year_options=year_options,
        term_options=term_options,
        teachers=teacher_map,
        filter_params=filter_params,
        prev_page_url=prev_page_url,
        next_page_url=next_page_url,
        selected={
            'classname': classname,
            'term': term,
            'academic_year': academic_year,
            'subject': subject,
            'teacher_id': teacher_id,
            'student_id': student_id,
            'date_from': date_from,
            'date_to': date_to,
        },
    )

@app.route('/school-admin/score-audit/revert', methods=['POST'])
def school_admin_revert_score_audit():
    if session.get('role') != 'school_admin':
        return redirect(url_for('login'))
    school_id = session.get('school_id')
    admin_user = session.get('user_id')
    audit_id = (request.form.get('audit_id', '') or '').strip()
    if not audit_id:
        flash('Audit entry ID is required for revert.', 'error')
        return redirect(url_for('school_admin_score_audit'))
    row = get_audit_row_by_id(school_id, audit_id)
    if not row:
        flash('Audit entry not found.', 'error')
        return redirect(url_for('school_admin_score_audit'))

    student_id = row.get('student_id', '')
    student = load_student(school_id, student_id)
    if not student:
        flash('Student record for this audit entry no longer exists.', 'error')
        return redirect(url_for('school_admin_score_audit'))
    if (student.get('term') or '') != (row.get('term') or ''):
        flash('Cannot revert: student is now in a different working term.', 'error')
        return redirect(url_for('school_admin_score_audit'))

    classname = row.get('classname', '')
    term = row.get('term', '')
    academic_year = row.get('academic_year', '')
    lock_status = get_term_edit_lock_status(school_id, classname, term, academic_year)
    if lock_status.get('locked'):
        flash(f'Cannot revert: {classname} ({term}) is published and locked.', 'error')
        return redirect(url_for('school_admin_score_audit'))

    target_subject = normalize_subject_name(row.get('subject', ''))
    old_subject_score = row.get('old_score', {}) if isinstance(row.get('old_score', {}), dict) else {}
    current_scores = student.get('scores', {}) if isinstance(student.get('scores', {}), dict) else {}
    before_scores = {k: (dict(v) if isinstance(v, dict) else {}) for k, v in current_scores.items()}
    after_scores = {k: (dict(v) if isinstance(v, dict) else {}) for k, v in current_scores.items()}
    after_scores[target_subject] = old_subject_score
    student['scores'] = after_scores

    with db_connection(commit=True) as conn:
        c = conn.cursor()
        save_student_with_cursor(c, school_id, student_id, student)
        audit_student_score_changes_with_cursor(
            c=c,
            school_id=school_id,
            student_id=student_id,
            classname=classname,
            term=term,
            academic_year=academic_year,
            old_scores=before_scores,
            new_scores=after_scores,
            changed_by=admin_user,
            changed_by_role='school_admin',
            change_source='admin_revert',
            change_reason='Reverted from audit log by school admin.',
            subjects_scope=[target_subject],
        )

    set_result_published(school_id, classname, term, academic_year, row.get('changed_by', ''), False)
    flash('Score reverted successfully. Class publication status reset to not published.', 'success')
    return redirect(url_for('school_admin_score_audit'))

@app.route('/school-admin/change-password', methods=['GET', 'POST'])
def school_admin_change_password():
    if session.get('role') != 'school_admin':
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        current_password = request.form.get('current_password', '')
        new_password = request.form.get('new_password', '')
        confirm_password = request.form.get('confirm_password', '')
        
        if not current_password or not new_password or not confirm_password:
            flash('All fields are required.', 'error')
            return redirect(url_for('school_admin_change_password'))
        
        if new_password != confirm_password:
            flash('New passwords do not match.', 'error')
            return redirect(url_for('school_admin_change_password'))
        if len(new_password) < 12 and not ALLOW_INSECURE_DEFAULTS:
            flash('School admin password must be at least 12 characters.', 'error')
            return redirect(url_for('school_admin_change_password'))
        
        user = get_user(session.get('user_id'))
        if not user or not check_password(user['password_hash'], current_password):
            flash('Current password is incorrect.', 'error')
            return redirect(url_for('school_admin_change_password'))
        
        # Update password
        password_hash = hash_password(new_password)
        upsert_user(session.get('user_id'), password_hash, 'school_admin', session.get('school_id'))
        session.pop('force_password_change', None)
        
        flash('Password changed successfully!', 'success')
        return redirect(url_for('school_admin_dashboard'))
    
    return render_template('shared/change_password.html', form_action='school_admin_change_password', back_url='school_admin_dashboard')

@app.route('/super-admin/change-password', methods=['GET', 'POST'])
def super_admin_change_password():
    if session.get('role') != 'super_admin':
        return redirect(url_for('login'))
    if request.method == 'POST':
        current_password = request.form.get('current_password', '')
        new_password = request.form.get('new_password', '')
        confirm_password = request.form.get('confirm_password', '')
        if not current_password or not new_password or not confirm_password:
            flash('All fields are required.', 'error')
            return redirect(url_for('super_admin_change_password'))
        if new_password != confirm_password:
            flash('New passwords do not match.', 'error')
            return redirect(url_for('super_admin_change_password'))
        if len(new_password) < 12 and not ALLOW_INSECURE_DEFAULTS:
            flash('Super admin password must be at least 12 characters.', 'error')
            return redirect(url_for('super_admin_change_password'))
        user = get_user(session.get('user_id'))
        if not user or not check_password(user.get('password_hash', ''), current_password):
            flash('Current password is incorrect.', 'error')
            return redirect(url_for('super_admin_change_password'))
        upsert_user(session.get('user_id'), hash_password(new_password), 'super_admin', None)
        session.pop('force_password_change', None)
        flash('Password changed successfully!', 'success')
        return redirect(url_for('super_admin_dashboard'))
    return render_template('shared/change_password.html', form_action='super_admin_change_password', back_url='super_admin_dashboard')

@app.route('/school-admin/add-teacher', methods=['POST'])
def school_admin_add_teacher():
    if session.get('role') != 'school_admin':
        return redirect(url_for('login'))
    
    school_id = session.get('school_id')
    username = request.form.get('username', '').strip().lower()
    firstname = normalize_person_name(request.form.get('firstname', '').strip())
    lastname = normalize_person_name(request.form.get('lastname', '').strip())
    gender = normalize_teacher_gender(request.form.get('gender', '').strip())
    password = request.form.get('password', '').strip()
    
    if username and firstname:
        try:
            if not is_valid_email(username):
                flash('Teacher username must be a valid email address.', 'error')
                return redirect(url_for('school_admin_dashboard'))
            if not password:
                flash('Teacher password is required.', 'error')
                return redirect(url_for('school_admin_dashboard'))
            if gender not in {'male', 'female', 'other'}:
                flash('Teacher gender is required.', 'error')
                return redirect(url_for('school_admin_dashboard'))
            existing_user = get_user(username)
            if existing_user:
                existing_role = (existing_user.get('role') or '').strip().lower()
                existing_school = (existing_user.get('school_id') or '').strip()
                if not (existing_role == 'teacher' and existing_school == school_id):
                    flash('This username already belongs to another account/school. Choose a different email.', 'error')
                    return redirect(url_for('school_admin_dashboard'))
            password_hash = hash_password(password)
            upsert_user(username, password_hash, 'teacher', school_id)
            save_teacher(
                school_id,
                username,
                firstname,
                lastname,
                [],
                gender=gender,
            )
            flash(f'Teacher added successfully. Username: {username}', 'success')
        except Exception as e:
            flash(f'Error adding teacher: {str(e)}', 'error')
    
    return redirect(url_for('school_admin_dashboard'))

@app.route('/school-admin/promote-students', methods=['GET', 'POST'])
def school_admin_promote():
    if session.get('role') != 'school_admin':
        return redirect(url_for('login'))
    
    school_id = session.get('school_id')
    school = get_school(school_id) or {}
    current_term = get_current_term(school)
    
    if request.method == 'POST':
        from_class = canonicalize_classname(request.form.get('from_class', '').strip())
        to_class = canonicalize_classname(request.form.get('to_class', '').strip())
        from_level = get_class_level(from_class)
        from_no = _extract_class_number(from_class)
        auto_ss3 = from_level == 'ss' and from_no == 3
        action_by_student = {}
        for key, value in request.form.items():
            if key.startswith('action_'):
                student_id = key.replace('action_', '', 1)
                action_by_student[student_id] = value
        
        if from_class and to_class:
            if from_class == to_class and not auto_ss3:
                flash('Current class and promote-to class cannot be the same.', 'error')
                return redirect(url_for('school_admin_promote', from_class=from_class))
            if not auto_ss3 and not is_valid_promotion_target(from_class, to_class):
                expected = next_class_in_sequence(from_class)
                if expected:
                    flash(f'Invalid promotion path. {from_class} can only move to {expected}.', 'error')
                else:
                    flash(f'Invalid source class "{from_class}" for promotion.', 'error')
                return redirect(url_for('school_admin_promote', from_class=from_class))
            if auto_ss3:
                flash('SS3 promote actions are auto-mapped to Graduated.', 'info')
            promote_students(
                school_id,
                from_class,
                to_class,
                action_by_student,
                term=current_term,
                academic_year=(school.get('academic_year', '') or ''),
                changed_by=(session.get('user_id') or ''),
            )
            flash('Class transitions applied successfully.', 'success')
        
        return redirect(url_for('school_admin_dashboard'))
    
    students = load_students(school_id, term_filter=current_term)
    classes = list(set(s['classname'] for s in students.values()))
    selected_class = request.args.get('from_class', '').strip()
    selected_class_key = canonicalize_classname(selected_class) if selected_class else ''
    selected_class_display = next(
        (cls for cls in classes if canonicalize_classname(cls) == selected_class_key),
        selected_class
    )
    class_students = {
        sid: data for sid, data in students.items()
        if not selected_class or canonicalize_classname(data.get('classname', '')) == selected_class_key
    }
    base_to_classes = [
        'NURSERY2', 'NURSERY3',
        'PRIMARY1', 'PRIMARY2', 'PRIMARY3', 'PRIMARY4', 'PRIMARY5', 'PRIMARY6',
        'JSS1', 'JSS2', 'JSS3',
        'SS1', 'SS2', 'SS3',
        'GRADUATED',
    ]
    suggested_next_class = next_class_in_sequence(selected_class_display or selected_class) if selected_class else ''
    to_class_options = _dedupe_keep_order(
        [x for x in (base_to_classes + sorted(classes) + ([suggested_next_class] if suggested_next_class else [])) if x]
    )
    return render_template(
        'school/promote_students.html',
        classes=sorted(classes),
        to_class_options=to_class_options,
        suggested_next_class=suggested_next_class,
        students=class_students,
        selected_class=selected_class_display,
        current_term=current_term
    )

@app.route('/school-admin/promotion-audit')
def school_admin_promotion_audit():
    if session.get('role') != 'school_admin':
        return redirect(url_for('login'))
    school_id = session.get('school_id')
    ensure_extended_features_schema()
    classname = (request.args.get('classname', '') or '').strip()
    action = (request.args.get('action', '') or '').strip().lower()
    where = ['school_id = ?']
    params = [school_id]
    if classname:
        where.append('LOWER(from_class) = LOWER(?)')
        params.append(classname)
    if action in {'promote', 'repeat', 'remove'}:
        where.append('action = ?')
        params.append(action)
    with db_connection() as conn:
        c = conn.cursor()
        db_execute(
            c,
            f"""SELECT student_id, student_name, from_class, to_class, action, term, academic_year, changed_by, created_at
                FROM promotion_audit_logs
                WHERE {' AND '.join(where)}
                ORDER BY created_at DESC
                LIMIT 500""",
            tuple(params),
        )
        rows = c.fetchall() or []
    logs = [{
        'student_id': r[0] or '',
        'student_name': r[1] or '',
        'from_class': r[2] or '',
        'to_class': r[3] or '',
        'action': r[4] or '',
        'term': r[5] or '',
        'academic_year': r[6] or '',
        'changed_by': r[7] or '',
        'created_at': format_timestamp(r[8]),
    } for r in rows]
    classes = sorted(set((item.get('from_class') or '') for item in logs if item.get('from_class')))
    return render_template('school/school_admin_promotion_audit.html', logs=logs, classes=classes, selected_class=classname, selected_action=action)

@app.route('/school-admin/timetable', methods=['GET', 'POST'])
def school_admin_timetable():
    if session.get('role') != 'school_admin':
        return redirect(url_for('login'))
    school_id = session.get('school_id')
    ensure_extended_features_schema()
    school = get_school(school_id) or {}
    current_term = get_current_term(school)
    current_year = (school or {}).get('academic_year', '')
    assignments = get_class_assignments(school_id)
    classes = sorted(set(get_student_count_by_class(school_id).keys()) | {a.get('classname', '') for a in assignments if a.get('classname')})
    teachers = get_teachers(school_id)
    if request.method == 'POST':
        action = (request.form.get('action', '') or '').strip().lower()
        try:
            with db_connection(commit=True) as conn:
                c = conn.cursor()
                if action == 'delete':
                    row_id = int(request.form.get('row_id', 0) or 0)
                    db_execute(c, "DELETE FROM class_timetables WHERE school_id = ? AND id = ?", (school_id, row_id))
                    flash('Timetable row removed.', 'success')
                else:
                    classname = canonicalize_classname(request.form.get('classname', ''))
                    day_of_week = int(request.form.get('day_of_week', 1) or 1)
                    period_label = (request.form.get('period_label', '') or '').strip()
                    subject = normalize_subject_name(request.form.get('subject', ''))
                    teacher_id = (request.form.get('teacher_id', '') or '').strip()
                    start_time = (request.form.get('start_time', '') or '').strip()
                    end_time = (request.form.get('end_time', '') or '').strip()
                    room = (request.form.get('room', '') or '').strip()
                    if not classname or not period_label or not subject:
                        raise ValueError('Class, period label, and subject are required.')
                    if day_of_week < 1 or day_of_week > 7:
                        raise ValueError('Day must be between 1 and 7.')
                    db_execute(
                        c,
                        """INSERT INTO class_timetables
                           (school_id, classname, day_of_week, period_label, subject, teacher_id, start_time, end_time, room, updated_at)
                           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                           ON CONFLICT (school_id, classname, day_of_week, period_label) DO UPDATE SET
                             subject = EXCLUDED.subject,
                             teacher_id = EXCLUDED.teacher_id,
                             start_time = EXCLUDED.start_time,
                             end_time = EXCLUDED.end_time,
                             room = EXCLUDED.room,
                             updated_at = CURRENT_TIMESTAMP""",
                        (school_id, classname, day_of_week, period_label, subject, teacher_id, start_time, end_time, room),
                    )
                    flash('Timetable saved.', 'success')
        except Exception as exc:
            flash(f'Failed to save timetable: {exc}', 'error')
        return redirect(url_for('school_admin_timetable'))

    selected_class = (request.args.get('classname', '') or '').strip()
    rows = get_school_timetable_rows(school_id, classname=selected_class)
    return render_template(
        'school/school_admin_timetable.html',
        school=school,
        classes=classes,
        teachers=teachers,
        day_options=DAY_OF_WEEK_OPTIONS,
        rows=rows,
        selected_class=selected_class,
    )

@app.route('/teacher/timetable')
def teacher_timetable():
    if session.get('role') != 'teacher':
        return redirect(url_for('login'))
    school_id = session.get('school_id')
    teacher_id = session.get('user_id')
    school = get_school(school_id) or {}
    current_term = get_current_term(school)
    current_year = (school or {}).get('academic_year', '')
    classes = sorted(set(get_teacher_classes(school_id, teacher_id, term=current_term, academic_year=current_year)))
    rows = [r for r in get_school_timetable_rows(school_id) if (r.get('teacher_id') or '').strip().lower() == (teacher_id or '').strip().lower() or r.get('classname') in classes]
    return render_template('teacher/teacher_timetable.html', school=school, rows=rows, day_options=DAY_OF_WEEK_OPTIONS)

@app.route('/teacher/subject-ranks')
def teacher_subject_rank_history():
    if session.get('role') != 'teacher':
        return redirect(url_for('login'))
    school_id = session.get('school_id')
    teacher_id = session.get('user_id')
    school = get_school(school_id) or {}
    current_term = get_current_term(school)
    current_year = (school or {}).get('academic_year', '')

    assignment_rows, year_options, terms_by_year = get_teacher_subject_assignment_history(school_id, teacher_id)
    selected_year = (request.args.get('academic_year', '') or '').strip()
    if not selected_year:
        selected_year = current_year if current_year in year_options else (year_options[0] if year_options else '')
    term_options = terms_by_year.get(selected_year, [])
    selected_term = (request.args.get('term', '') or '').strip()
    if not selected_term:
        selected_term = current_term if current_term in term_options else (term_options[0] if term_options else '')

    scoped_assignments = [
        r for r in assignment_rows
        if (r.get('academic_year') or '').strip() == selected_year
        and (r.get('term') or '').strip() == selected_term
    ]
    class_options = sorted({(r.get('classname') or '').strip() for r in scoped_assignments if (r.get('classname') or '').strip()}, key=lambda x: x.lower())
    selected_class = (request.args.get('classname', '') or '').strip()
    if selected_class not in class_options:
        selected_class = class_options[0] if class_options else ''

    subject_options = sorted({
        normalize_subject_name(r.get('subject', ''))
        for r in scoped_assignments
        if (r.get('classname') or '').strip() == selected_class and normalize_subject_name(r.get('subject', ''))
    }, key=lambda x: x.lower())
    selected_subject = normalize_subject_name(request.args.get('subject', ''))
    if selected_subject not in subject_options:
        selected_subject = subject_options[0] if subject_options else ''

    rank_rows = []
    summary = {'ranked_students': 0, 'subject': selected_subject, 'classname': selected_class}
    if selected_class and selected_subject and selected_term and selected_year:
        with db_connection() as conn:
            c = conn.cursor()
            db_execute(
                c,
                """SELECT student_id, firstname, scores
                   FROM published_student_results
                   WHERE school_id = ?
                     AND LOWER(classname) = LOWER(?)
                     AND term = ?
                     AND COALESCE(academic_year, '') = COALESCE(?, '')""",
                (school_id, selected_class, selected_term, selected_year),
            )
            rows = c.fetchall() or []
        entries = []
        target_lower = selected_subject.lower()
        for sid, firstname, scores_raw in rows:
            try:
                scores = json.loads(scores_raw) if isinstance(scores_raw, str) else (scores_raw if isinstance(scores_raw, dict) else {})
            except Exception:
                scores = {}
            if not isinstance(scores, dict):
                continue
            block = None
            for subj_name, subj_block in scores.items():
                if normalize_subject_name(subj_name).lower() == target_lower and isinstance(subj_block, dict):
                    block = subj_block
                    break
            if not isinstance(block, dict):
                continue
            mark = float(subject_overall_mark(block))
            entries.append({
                'student_id': sid or '',
                'firstname': firstname or '',
                'mark': round(mark, 2),
            })
        entries.sort(key=lambda x: (-x['mark'], (x['firstname'] or '').lower(), (x['student_id'] or '').lower()))
        prev_mark = None
        current_rank = 0
        for idx, row in enumerate(entries, start=1):
            if prev_mark is None or not same_score(row['mark'], prev_mark):
                current_rank = idx
            prev_mark = row['mark']
            rank_rows.append({
                'position': current_rank,
                'student_id': row['student_id'],
                'firstname': row['firstname'],
                'mark': row['mark'],
            })
        summary['ranked_students'] = len(rank_rows)

    trend_student_id = (request.args.get('trend_student_id', '') or '').strip()
    trend_points = []
    if trend_student_id and selected_subject:
        with db_connection() as conn:
            c = conn.cursor()
            db_execute(
                c,
                """SELECT term, academic_year, scores
                   FROM published_student_results
                   WHERE school_id = ? AND student_id = ?
                   ORDER BY academic_year, term""",
                (school_id, trend_student_id),
            )
            raw_rows = c.fetchall() or []
        collected = []
        for term_name, year_name, scores_raw in raw_rows:
            try:
                scores = json.loads(scores_raw) if isinstance(scores_raw, str) else (scores_raw if isinstance(scores_raw, dict) else {})
            except Exception:
                scores = {}
            if not isinstance(scores, dict):
                continue
            block = None
            for subj_name, subj_block in scores.items():
                if normalize_subject_name(subj_name).lower() == selected_subject.lower() and isinstance(subj_block, dict):
                    block = subj_block
                    break
            if not block:
                continue
            mark = float(subject_overall_mark(block))
            collected.append({
                'term': term_name or '',
                'academic_year': year_name or '',
                'score': round(mark, 2),
            })
        collected.sort(key=lambda x: ((_academic_year_start(x.get('academic_year')) or 0), term_sort_value(x.get('term'))))
        for row in collected:
            trend_points.append({
                'label': f"{row.get('term', '')} ({row.get('academic_year', '')})",
                'score': row.get('score', 0.0),
            })

    return render_template(
        'teacher/teacher_subject_rank_history.html',
        school=school,
        year_options=year_options,
        term_options=term_options,
        class_options=class_options,
        subject_options=subject_options,
        selected_year=selected_year,
        selected_term=selected_term,
        selected_class=selected_class,
        selected_subject=selected_subject,
        rank_rows=rank_rows,
        summary=summary,
        trend_student_id=trend_student_id,
        trend_points=trend_points,
    )

@app.route('/teacher/subject-ranks/export')
def teacher_subject_rank_export():
    if session.get('role') != 'teacher':
        return redirect(url_for('login'))
    school_id = session.get('school_id')
    teacher_id = session.get('user_id')
    academic_year = (request.args.get('academic_year', '') or '').strip()
    term = (request.args.get('term', '') or '').strip()
    classname = (request.args.get('classname', '') or '').strip()
    subject = normalize_subject_name(request.args.get('subject', ''))
    if not academic_year or not term or not classname or not subject:
        flash('Missing filters for export.', 'error')
        return redirect(url_for('teacher_subject_rank_history'))
    assigned = get_teacher_subject_assignments(
        school_id,
        teacher_id=teacher_id,
        classname=classname,
        term=term,
        academic_year=academic_year,
    )
    if subject not in {normalize_subject_name(r.get('subject', '')) for r in assigned}:
        flash('You are not assigned to this subject/class for selected term/year.', 'error')
        return redirect(url_for('teacher_subject_rank_history'))

    rows = load_published_class_results(school_id, classname, term, academic_year, school=get_school(school_id) or {})
    rank_entries = []
    for row in rows:
        scores = row.get('scores', {}) if isinstance(row.get('scores', {}), dict) else {}
        block = None
        for subj_name, subj_block in scores.items():
            if normalize_subject_name(subj_name).lower() == subject.lower() and isinstance(subj_block, dict):
                block = subj_block
                break
        if not block:
            continue
        sid = row.get('student_id', '')
        student = load_student(school_id, sid) or {}
        mark = float(subject_overall_mark(block))
        rank_entries.append({
            'student_id': sid,
            'firstname': (student.get('firstname') or sid),
            'mark': round(mark, 2),
        })
    rank_entries.sort(key=lambda x: (-x['mark'], (x['firstname'] or '').lower(), (x['student_id'] or '').lower()))
    output = StringIO()
    writer = csv.writer(output)
    writer.writerow(['Position', 'Student Name', 'Student ID', 'Subject', 'Score', 'Class', 'Term', 'Academic Year'])
    prev_mark = None
    current_rank = 0
    for idx, item in enumerate(rank_entries, start=1):
        if prev_mark is None or not same_score(item['mark'], prev_mark):
            current_rank = idx
        prev_mark = item['mark']
        writer.writerow([current_rank, item['firstname'], item['student_id'], subject, item['mark'], classname, term, academic_year])
    filename = f'subject_ranks_{canonicalize_classname(classname)}_{subject}_{term.replace(" ", "_")}_{academic_year}.csv'
    return Response(
        output.getvalue(),
        mimetype='text/csv',
        headers={'Content-Disposition': f'attachment; filename={filename}'},
    )

@app.route('/teacher/period-attendance', methods=['GET', 'POST'])
def teacher_period_attendance():
    if session.get('role') != 'teacher':
        return redirect(url_for('login'))
    ensure_extended_features_schema()
    school_id = session.get('school_id')
    teacher_id = session.get('user_id')
    school = get_school(school_id) or {}
    current_term = get_current_term(school)
    current_year = (school or {}).get('academic_year', '')
    subject_rows = get_teacher_subject_assignments(
        school_id,
        teacher_id=teacher_id,
        term=current_term,
        academic_year=current_year,
    )
    class_subject_map = {}
    for row in subject_rows:
        classname = (row.get('classname') or '').strip()
        subject = normalize_subject_name(row.get('subject', ''))
        if not classname or not subject:
            continue
        class_subject_map.setdefault(classname, set()).add(subject)
    classes = sorted(class_subject_map.keys(), key=lambda x: str(x).lower())
    if not classes:
        flash('No subject assignment found for period attendance.', 'error')
        return redirect(url_for('teacher_dashboard'))
    requested_class = (request.values.get('classname', '') or '').strip()
    selected_class = requested_class if requested_class in classes else classes[0]
    subject_options = sorted(class_subject_map.get(selected_class, set()), key=lambda x: str(x).lower())
    selected_subject = normalize_subject_name((request.values.get('subject', '') or '').strip())
    if selected_subject not in set(subject_options):
        selected_subject = subject_options[0] if subject_options else ''
    timetable_rows = get_school_timetable_rows(school_id, classname=selected_class)
    periods = []
    for row in timetable_rows:
        row_subject = normalize_subject_name(row.get('subject', ''))
        if selected_subject and row_subject.lower() != selected_subject.lower():
            continue
        label = (row.get('period_label') or '').strip()
        if label and label not in periods:
            periods.append(label)
    if not periods:
        periods = get_timetable_period_labels_for_class(school_id, selected_class)
    selected_period = (request.values.get('period_label', '') or '').strip()
    if selected_period not in periods:
        selected_period = periods[0] if periods else ''
    selected_date = (request.values.get('attendance_date', '') or '').strip() or datetime.now().strftime('%Y-%m-%d')
    valid_info = get_term_instructional_dates(school_id, current_year, current_term)
    valid_dates = valid_info.get('valid_iso_set') or set()
    if selected_date not in valid_dates and valid_dates:
        selected_date = sorted(valid_dates)[-1]
    if request.method == 'POST':
        if requested_class and requested_class not in classes:
            flash('You are not assigned to this class/subject for the current term/year.', 'error')
            return redirect(url_for('teacher_dashboard'))
        if not selected_subject or selected_subject not in set(subject_options):
            flash('Select one of your assigned subjects for this class.', 'error')
            return redirect(url_for('teacher_period_attendance', classname=selected_class, attendance_date=selected_date))
        if not teacher_can_score_subject(
            school_id,
            teacher_id,
            selected_class,
            selected_subject,
            term=current_term,
            academic_year=current_year,
        ):
            flash('You are not assigned to mark attendance for this class/subject.', 'error')
            return redirect(url_for('teacher_dashboard'))
        if selected_date not in valid_dates:
            flash('Select a valid instructional date.', 'error')
            return redirect(url_for('teacher_period_attendance', classname=selected_class, subject=selected_subject, period_label=selected_period, attendance_date=selected_date))
        students_all = load_students(school_id, class_filter=selected_class, term_filter=current_term)
        students = {
            sid: st for sid, st in students_all.items()
            if selected_subject in normalize_subjects_list(st.get('subjects', []))
        }
        try:
            with db_connection(commit=True) as conn:
                c = conn.cursor()
                for sid, st in sorted(students.items(), key=lambda x: ((x[1].get('firstname', '') or '').lower(), (x[0] or '').lower())):
                    status = normalize_attendance_status(request.form.get(f'status_{sid}', ''))
                    note = (request.form.get(f'note_{sid}', '') or '').strip()[:250]
                    if not status:
                        continue
                    db_execute(
                        c,
                        """INSERT INTO period_attendance
                           (school_id, student_id, classname, term, academic_year, attendance_date, period_label, subject, status, note, marked_by, updated_at)
                           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                           ON CONFLICT(school_id, student_id, attendance_date, period_label) DO UPDATE SET
                             classname = EXCLUDED.classname,
                             term = EXCLUDED.term,
                             academic_year = EXCLUDED.academic_year,
                             subject = EXCLUDED.subject,
                             status = EXCLUDED.status,
                             note = EXCLUDED.note,
                             marked_by = EXCLUDED.marked_by,
                             updated_at = CURRENT_TIMESTAMP""",
                        (
                            school_id,
                            sid,
                            selected_class,
                            current_term,
                            current_year or '',
                            selected_date,
                            selected_period,
                            selected_subject,
                            status,
                            note,
                            teacher_id,
                        ),
                    )
            flash('Period attendance saved.', 'success')
        except Exception as exc:
            flash(f'Failed to save period attendance: {exc}', 'error')
        return redirect(url_for('teacher_period_attendance', classname=selected_class, subject=selected_subject, period_label=selected_period, attendance_date=selected_date))

    students_all = load_students(school_id, class_filter=selected_class, term_filter=current_term)
    students = {
        sid: st for sid, st in students_all.items()
        if selected_subject and selected_subject in normalize_subjects_list(st.get('subjects', []))
    }
    rows = sorted(students.items(), key=lambda x: ((x[1].get('firstname', '') or '').lower(), (x[0] or '').lower()))
    attendance_map = get_period_attendance_map_for_date(
        school_id,
        selected_class,
        selected_date,
        selected_period,
        current_term,
        current_year,
        subject=selected_subject,
    )
    return render_template(
        'teacher/teacher_period_attendance.html',
        school=school,
        classes=classes,
        subject_options=subject_options,
        selected_subject=selected_subject,
        periods=periods,
        selected_class=selected_class,
        selected_period=selected_period,
        selected_date=selected_date,
        current_term=current_term,
        current_year=current_year,
        student_rows=rows,
        attendance_map=attendance_map,
        status_options=ATTENDANCE_STATUS_OPTIONS,
        valid_attendance_dates=sorted(list(valid_dates)),
    )

@app.route('/parent/dispute', methods=['GET', 'POST'])
def parent_submit_dispute():
    if session.get('role') != 'parent':
        return redirect(url_for('parent_portal'))
    ensure_extended_features_schema()
    allowed = _parent_allowed_student_keys()
    student_key = (request.values.get('student_key', '') or '').strip()
    if student_key not in allowed or '::' not in student_key:
        flash('Student access is not allowed for this parent account.', 'error')
        return redirect(url_for('parent_dashboard'))
    school_id, student_id = student_key.split('::', 1)
    school = get_school(school_id) or {}
    published_terms = filter_visible_terms_for_student(school, get_published_terms_for_student(school_id, student_id))
    if request.method == 'POST':
        title = (request.form.get('title', '') or '').strip()
        details = (request.form.get('details', '') or '').strip()
        term_token = (request.form.get('term_token', '') or '').strip()
        if not title or not details:
            flash('Title and details are required.', 'error')
            return redirect(url_for('parent_submit_dispute', student_key=student_key))
        term_name = ''
        year_name = ''
        classname = ''
        for item in published_terms:
            if (item.get('token') or '') == term_token:
                term_name = item.get('term', '')
                year_name = item.get('academic_year', '')
                classname = item.get('classname', '')
                break
        if not term_name:
            flash('Select a valid published term for this dispute.', 'error')
            return redirect(url_for('parent_submit_dispute', student_key=student_key))
        try:
            with db_connection(commit=True) as conn:
                c = conn.cursor()
                db_execute(
                    c,
                    """INSERT INTO result_disputes
                       (school_id, student_id, classname, term, academic_year, parent_phone, title, details, status, created_by, created_at)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'open', ?, CURRENT_TIMESTAMP)""",
                    (school_id, student_id, classname, term_name, year_name, (session.get('parent_phone') or ''), title[:150], details[:2500], (session.get('parent_phone') or '')),
                )
            flash('Dispute submitted successfully. School admin will review it.', 'success')
            return redirect(url_for('parent_dashboard'))
        except Exception as exc:
            flash(f'Failed to submit dispute: {exc}', 'error')
            return redirect(url_for('parent_submit_dispute', student_key=student_key))
    return render_template('parent/parent_report_dispute.html', student_key=student_key, published_terms=published_terms)

@app.route('/school-admin/disputes')
def school_admin_disputes():
    if session.get('role') != 'school_admin':
        return redirect(url_for('login'))
    ensure_extended_features_schema()
    school_id = session.get('school_id')
    status_filter = (request.args.get('status', '') or '').strip().lower()
    where = ['school_id = ?']
    params = [school_id]
    if status_filter in {'open', 'resolved', 'rejected'}:
        where.append('status = ?')
        params.append(status_filter)
    with db_connection() as conn:
        c = conn.cursor()
        db_execute(
            c,
            f"""SELECT id, student_id, classname, term, academic_year, parent_phone, title, details, status, resolution_note, created_at, resolved_at
                FROM result_disputes
                WHERE {' AND '.join(where)}
                ORDER BY created_at DESC
                LIMIT 500""",
            tuple(params),
        )
        rows = c.fetchall() or []
    disputes = [{
        'id': int(r[0] or 0),
        'student_id': r[1] or '',
        'classname': r[2] or '',
        'term': r[3] or '',
        'academic_year': r[4] or '',
        'parent_phone': r[5] or '',
        'title': r[6] or '',
        'details': r[7] or '',
        'status': r[8] or '',
        'resolution_note': r[9] or '',
        'created_at': format_timestamp(r[10]),
        'resolved_at': format_timestamp(r[11]) if r[11] else '',
    } for r in rows]
    return render_template('school/school_admin_disputes.html', disputes=disputes, status_filter=status_filter)

@app.route('/school-admin/disputes/update', methods=['POST'])
def school_admin_update_dispute():
    if session.get('role') != 'school_admin':
        return redirect(url_for('login'))
    ensure_extended_features_schema()
    school_id = session.get('school_id')
    dispute_id = int(request.form.get('dispute_id', 0) or 0)
    status = (request.form.get('status', '') or '').strip().lower()
    resolution_note = (request.form.get('resolution_note', '') or '').strip()
    if status not in {'resolved', 'rejected', 'open'}:
        flash('Invalid dispute status.', 'error')
        return redirect(url_for('school_admin_disputes'))
    with db_connection(commit=True) as conn:
        c = conn.cursor()
        db_execute(
            c,
            """UPDATE result_disputes
               SET status = ?, resolution_note = ?, resolved_by = ?, resolved_at = CASE WHEN ? IN ('resolved', 'rejected') THEN CURRENT_TIMESTAMP ELSE NULL END
               WHERE school_id = ? AND id = ?""",
            (status, resolution_note[:1000], (session.get('user_id') or ''), status, school_id, dispute_id),
        )
    flash('Dispute updated.', 'success')
    return redirect(url_for('school_admin_disputes'))

@app.route('/school-admin/bulk-tools', methods=['GET'])
def school_admin_bulk_tools():
    if session.get('role') != 'school_admin':
        return redirect(url_for('login'))
    error_token = (request.args.get('error_token', '') or '').strip()
    return render_template('school/school_admin_bulk_tools.html', error_token=error_token)

@app.route('/school-admin/export/<target>')
def school_admin_export_target(target):
    if session.get('role') != 'school_admin':
        return redirect(url_for('login'))
    school_id = session.get('school_id')
    target_key = (target or '').strip().lower()
    mapping = {
        'students': ('students', ['student_id', 'firstname', 'date_of_birth', 'gender', 'classname', 'first_year_class', 'term', 'stream', 'number_of_subject', 'subjects', 'scores', 'promoted', 'parent_phone']),
        'teachers': ('teachers', ['user_id', 'firstname', 'lastname', 'phone', 'gender', 'assigned_classes', 'subjects_taught']),
        'class_assignments': ('class_assignments', ['teacher_id', 'classname', 'term', 'academic_year']),
    }
    if target_key not in mapping:
        flash('Invalid export target.', 'error')
        return redirect(url_for('school_admin_bulk_tools'))
    table_name, cols = mapping[target_key]
    with db_connection() as conn:
        c = conn.cursor()
        db_execute(c, f"SELECT {', '.join(cols)} FROM {table_name} WHERE school_id = ? ORDER BY 1", (school_id,))
        rows = c.fetchall() or []
    output = StringIO()
    writer = csv.writer(output)
    writer.writerow(cols)
    for row in rows:
        writer.writerow([row[idx] if row[idx] is not None else '' for idx in range(len(cols))])
    return Response(
        output.getvalue(),
        mimetype='text/csv',
        headers={'Content-Disposition': f'attachment; filename={target_key}_{school_id}.csv'},
    )

@app.route('/school-admin/import/<target>', methods=['POST'])
def school_admin_import_target(target):
    if session.get('role') != 'school_admin':
        return redirect(url_for('login'))
    school_id = session.get('school_id')
    target_key = (target or '').strip().lower()
    file = request.files.get('file')
    if not file or not (file.filename or '').lower().endswith('.csv'):
        flash('Upload a valid CSV file.', 'error')
        return redirect(url_for('school_admin_bulk_tools'))
    try:
        text = file.read().decode('utf-8-sig')
        reader = csv.DictReader(StringIO(text))
        if not reader.fieldnames:
            raise ValueError('CSV is empty or missing headers.')
        rows = list(reader)
    except Exception as exc:
        flash(f'Failed to parse CSV: {exc}', 'error')
        return redirect(url_for('school_admin_bulk_tools'))

    headers = {str(h or '').strip().lower(): h for h in (reader.fieldnames or []) if str(h or '').strip()}
    required_by_target = {
        'students': ['student_id', 'firstname', 'classname', 'term'],
        'teachers': ['user_id', 'firstname', 'lastname'],
        'class_assignments': ['teacher_id', 'classname', 'term', 'academic_year'],
    }
    if target_key not in required_by_target:
        flash('Invalid import target.', 'error')
        return redirect(url_for('school_admin_bulk_tools'))
    missing_headers = [h for h in required_by_target[target_key] if h not in headers]
    if missing_headers:
        flash(f'Missing required CSV columns: {", ".join(missing_headers)}', 'error')
        return redirect(url_for('school_admin_bulk_tools'))

    error_rows = []
    processed = 0
    imported = 0
    def add_error(row_num, row_obj, message):
        out = {k: (row_obj.get(k, '') if isinstance(row_obj, dict) else '') for k in (reader.fieldnames or [])}
        out['Error'] = message
        out['RowNumber'] = row_num
        error_rows.append(out)

    try:
        if target_key == 'students':
            for idx, row in enumerate(rows, start=2):
                sid = (row.get('student_id', '') or '').strip()
                if not sid:
                    add_error(idx, row, 'student_id is required.')
                    continue
                processed += 1
                existing_user = get_user(sid)
                if existing_user:
                    existing_role = (existing_user.get('role') or '').strip().lower()
                    existing_school = (existing_user.get('school_id') or '').strip()
                    if not (existing_role == 'student' and existing_school == school_id):
                        add_error(idx, row, f'student_id "{sid}" already belongs to another account/school.')
                        continue
                classname = canonicalize_classname(row.get('classname', ''))
                term = (row.get('term', '') or '').strip()
                firstname = normalize_person_name(row.get('firstname', ''))
                if not firstname:
                    add_error(idx, row, 'firstname is required.')
                    continue
                if term not in {'First Term', 'Second Term', 'Third Term'}:
                    add_error(idx, row, 'term must be First Term, Second Term, or Third Term.')
                    continue
                if not classname:
                    add_error(idx, row, 'classname is required.')
                    continue
                promoted_raw = (row.get('promoted', '') or '').strip().lower()
                if promoted_raw not in {'', '0', '1', 'true', 'false', 'yes', 'no'}:
                    add_error(idx, row, 'promoted must be 0/1/true/false/yes/no.')
                    continue
                student_data = {
                    'firstname': firstname,
                    'date_of_birth': row.get('date_of_birth', ''),
                    'gender': row.get('gender', ''),
                    'classname': classname,
                    'first_year_class': canonicalize_classname(row.get('first_year_class', row.get('classname', ''))),
                    'term': term,
                    'stream': row.get('stream', 'N/A'),
                    'number_of_subject': int(row.get('number_of_subject', 0) or 0),
                    'subjects': normalize_subjects_list(row.get('subjects', '')),
                    'scores': {},
                    'promoted': normalize_promoted_db_value(promoted_raw in {'1', 'true', 'yes'}),
                    'parent_phone': row.get('parent_phone', ''),
                    'parent_password_hash': '',
                }
                try:
                    save_student(school_id, sid, student_data)
                    if not get_user(sid):
                        upsert_user(sid, hash_password(DEFAULT_STUDENT_PASSWORD), 'student', school_id)
                    imported += 1
                except Exception as exc:
                    add_error(idx, row, str(exc))
        elif target_key == 'teachers':
            for idx, row in enumerate(rows, start=2):
                tid = (row.get('user_id', '') or '').strip().lower()
                if not tid:
                    add_error(idx, row, 'user_id is required.')
                    continue
                processed += 1
                existing_user = get_user(tid)
                if existing_user:
                    existing_role = (existing_user.get('role') or '').strip().lower()
                    existing_school = (existing_user.get('school_id') or '').strip()
                    if not (existing_role == 'teacher' and existing_school == school_id):
                        add_error(idx, row, f'user_id "{tid}" already belongs to another account/school.')
                        continue
                if not is_valid_email(tid):
                    add_error(idx, row, 'user_id must be a valid email address.')
                    continue
                firstname = normalize_person_name(row.get('firstname', ''))
                lastname = normalize_person_name(row.get('lastname', ''))
                if not firstname or not lastname:
                    add_error(idx, row, 'firstname and lastname are required.')
                    continue
                gender = normalize_teacher_gender(row.get('gender', ''))
                if not gender:
                    add_error(idx, row, 'gender must be male/female/other.')
                    continue
                save_teacher(
                    school_id,
                    tid,
                    firstname,
                    lastname,
                    _safe_json_rows(row.get('assigned_classes')),
                    subjects_taught=normalize_subjects_list(row.get('subjects_taught', '')),
                    phone=row.get('phone', ''),
                    gender=gender,
                )
                if not get_user(tid):
                    upsert_user(tid, hash_password(DEFAULT_TEACHER_PASSWORD), 'teacher', school_id)
                imported += 1
        elif target_key == 'class_assignments':
            teacher_ids = {k.lower() for k in get_teachers(school_id).keys()}
            for idx, row in enumerate(rows, start=2):
                teacher_id = (row.get('teacher_id', '') or '').strip().lower()
                classname = canonicalize_classname(row.get('classname', ''))
                term = (row.get('term', '') or '').strip()
                year = (row.get('academic_year', '') or '').strip()
                if not teacher_id or not classname or not term:
                    add_error(idx, row, 'teacher_id, classname, and term are required.')
                    continue
                processed += 1
                if teacher_id not in teacher_ids:
                    add_error(idx, row, f'teacher_id "{teacher_id}" not found in this school.')
                    continue
                if term not in {'First Term', 'Second Term', 'Third Term'}:
                    add_error(idx, row, 'term must be First Term, Second Term, or Third Term.')
                    continue
                if year and not re.fullmatch(r'^\d{4}-\d{4}$', year):
                    add_error(idx, row, 'academic_year must be in YYYY-YYYY format.')
                    continue
                try:
                    assign_teacher_to_class(school_id, teacher_id, classname, term, year)
                    imported += 1
                except Exception as exc:
                    add_error(idx, row, str(exc))
        else:
            raise ValueError('Invalid import target.')
        error_token = ''
        if error_rows:
            output = StringIO()
            fieldnames = list(reader.fieldnames or []) + ['Error', 'RowNumber']
            writer = csv.DictWriter(output, fieldnames=fieldnames)
            writer.writeheader()
            for item in error_rows:
                writer.writerow(item)
            error_token = _store_csv_error_export(
                output.getvalue(),
                f'{target_key}_import_errors.csv',
                owner_role='school_admin',
                owner_id=(session.get('user_id') or ''),
                school_id=(school_id or ''),
            )
            flash(
                f'{target_key.replace("_", " ").title()} import finished: {imported} imported, {len(error_rows)} failed rows.',
                'error',
            )
        else:
            flash(f'{target_key.replace("_", " ").title()} import completed. Imported {imported} row(s).', 'success')
        return redirect(url_for('school_admin_bulk_tools', error_token=error_token))
    except Exception as exc:
        flash(f'Import failed: {exc}', 'error')
    return redirect(url_for('school_admin_bulk_tools'))

@app.route('/school-admin/import-csv-errors/<token>')
def school_admin_import_csv_error_rows(token):
    if session.get('role') != 'school_admin':
        return redirect(url_for('login'))
    _cleanup_csv_error_exports()
    item = CSV_ERROR_EXPORTS.get((token or '').strip())
    if not item:
        flash('Error export link expired. Re-run import to generate it again.', 'error')
        return redirect(url_for('school_admin_bulk_tools'))
    owner_role = (item.get('owner_role') or '').strip().lower()
    owner_id = (item.get('owner_id') or '').strip().lower()
    owner_school_id = (item.get('school_id') or '').strip()
    current_user = (session.get('user_id') or '').strip().lower()
    current_school_id = (session.get('school_id') or '').strip()
    if owner_role and owner_role != 'school_admin':
        flash('You are not allowed to access this error export.', 'error')
        return redirect(url_for('school_admin_bulk_tools'))
    if owner_id and owner_id != current_user:
        flash('You are not allowed to access this error export.', 'error')
        return redirect(url_for('school_admin_bulk_tools'))
    if owner_school_id and owner_school_id != current_school_id:
        flash('You are not allowed to access this error export.', 'error')
        return redirect(url_for('school_admin_bulk_tools'))
    return Response(
        item.get('content', ''),
        mimetype='text/csv',
        headers={'Content-Disposition': f'attachment; filename={item.get("filename", "import_error_rows.csv")}'}
    )

@app.route('/school-admin/backup')
def school_admin_backup():
    if session.get('role') != 'school_admin':
        return redirect(url_for('login'))
    school_id = session.get('school_id')
    try:
        payload = build_school_backup_payload(school_id)
        body = json.dumps(payload, indent=2)
        return Response(
            body,
            mimetype='application/json',
            headers={'Content-Disposition': f'attachment; filename=school_backup_{school_id}.json'},
        )
    except Exception as exc:
        flash(f'Backup failed: {exc}', 'error')
        return redirect(url_for('school_admin_bulk_tools'))

@app.route('/school-admin/restore', methods=['POST'])
def school_admin_restore():
    if session.get('role') != 'school_admin':
        return redirect(url_for('login'))
    school_id = session.get('school_id')
    mode = (request.form.get('mode', 'merge') or 'merge').strip().lower()
    file = request.files.get('backup_file')
    if not file:
        flash('Choose a backup JSON file.', 'error')
        return redirect(url_for('school_admin_bulk_tools'))
    try:
        payload = json.loads(file.read().decode('utf-8'))
        restore_school_backup_payload(school_id, payload, mode=mode)
        flash(f'Backup restored successfully using {mode} mode.', 'success')
    except Exception as exc:
        flash(f'Restore failed: {exc}', 'error')
    return redirect(url_for('school_admin_bulk_tools'))

@app.route('/school-admin/security')
def school_admin_security():
    if session.get('role') != 'school_admin':
        return redirect(url_for('login'))
    ensure_extended_features_schema()
    school_id = session.get('school_id')
    username = (request.args.get('username', '') or '').strip().lower()
    with db_connection() as conn:
        c = conn.cursor()
        if username:
            db_execute(
                c,
                """SELECT username, role, endpoint, ip_address, success, reason, created_at
                   FROM login_audit_logs
                   WHERE school_id = ? AND LOWER(username) = LOWER(?)
                   ORDER BY created_at DESC
                   LIMIT 300""",
                (school_id, username),
            )
        else:
            db_execute(
                c,
                """SELECT username, role, endpoint, ip_address, success, reason, created_at
                   FROM login_audit_logs
                   WHERE school_id = ?
                   ORDER BY created_at DESC
                   LIMIT 300""",
                (school_id,),
            )
        rows = c.fetchall() or []
    logs = [{
        'username': r[0] or '',
        'role': r[1] or '',
        'endpoint': r[2] or '',
        'ip_address': r[3] or '',
        'success': bool(int(r[4] or 0)),
        'reason': r[5] or '',
        'created_at': format_timestamp(r[6]),
    } for r in rows]
    return render_template('school/school_admin_security.html', logs=logs, username=username, policy_days=ADMIN_PASSWORD_MAX_AGE_DAYS, timeout_minutes=SESSION_TIMEOUT_MINUTES)

@app.route('/school-admin/analytics')
def school_admin_analytics():
    if session.get('role') != 'school_admin':
        return redirect(url_for('login'))
    school_id = session.get('school_id')
    school = get_school(school_id) or {}
    current_term = get_current_term(school)
    current_year = (school or {}).get('academic_year', '')
    selected_term = (request.args.get('term', '') or '').strip() or current_term
    selected_year = (request.args.get('academic_year', '') or '').strip() or current_year
    class_pass_rows, subject_rows, attendance_impact_rows = build_school_analytics_data(school_id, selected_term, selected_year)
    return render_template(
        'school/school_admin_analytics.html',
        school=school,
        selected_term=selected_term,
        selected_year=selected_year,
        class_pass_rows=class_pass_rows,
        subject_rows=subject_rows,
        attendance_impact_rows=attendance_impact_rows,
    )

@app.route('/school-admin/add-students-by-class', methods=['GET', 'POST'])
def school_admin_add_students_by_class():
    """School admin can add multiple students to a class at once."""
    if session.get('role') != 'school_admin':
        return redirect(url_for('login'))
    
    school_id = session.get('school_id')
    school = get_school(school_id) or {}
    added_students = []
    selected_class = request.args.get('class', '').strip()
    
    if request.method == 'POST':
        classname = canonicalize_classname(request.form.get('classname', '').strip())
        first_year_class = classname  # First year class is the starting class
        term = request.form.get('term', '').strip()
        student_names = [normalize_person_name(name.strip()) for name in request.form.getlist('student_name[]')]
        reg_numbers = [reg.strip() for reg in request.form.getlist('reg_no[]')]
        birth_dates = [(dob or '').strip() for dob in request.form.getlist('date_of_birth[]')]
        genders = [normalize_student_gender(gender) for gender in request.form.getlist('gender[]')]
        config = get_class_subject_config(school_id, classname)
        stream = 'N/A'
        
        if not classname or not term:
            flash('Please fill in all required fields.', 'error')
            return redirect(url_for('school_admin_add_students_by_class'))
        if not config:
            flash('No class subject configuration found. Configure subjects for this class first.', 'error')
            return redirect(url_for('school_admin_add_students_by_class'))
        if class_uses_stream_for_school(school, classname):
            # School admin can create SS students first; stream/track is allocated later by teacher.
            subjects = _dedupe_keep_order(config.get('core_subjects', []) or [])
            stream = 'N/A'
        else:
            subjects, stream, subject_error = build_subjects_from_config(
                classname=classname,
                stream='N/A',
                config=config,
                selected_optional_subjects=[],
                school=school,
            )
            if subject_error:
                flash(subject_error, 'error')
                return redirect(url_for('school_admin_add_students_by_class'))
            subjects = _dedupe_keep_order(subjects or [])
        number_of_subject = len(subjects)
        if number_of_subject <= 0:
            flash('This class has no core subjects configured. Update Class Subjects first.', 'error')
            return redirect(url_for('school_admin_add_students_by_class'))
        
        # Keep only rows with name; reg no is optional.
        rows = []
        for idx, name in enumerate(student_names):
            if not name:
                continue
            reg_no = reg_numbers[idx] if idx < len(reg_numbers) else ''
            date_of_birth = birth_dates[idx] if idx < len(birth_dates) else ''
            gender = genders[idx] if idx < len(genders) else ''
            if not date_of_birth:
                flash(f'Date of birth is required for {name}.', 'error')
                continue
            if not gender:
                flash(f'Gender is required for {name}.', 'error')
                continue
            rows.append({
                'firstname': name,
                'reg_no': reg_no,
                'date_of_birth': date_of_birth,
                'gender': gender,
            })
        if not rows:
            flash('Add at least one student name.', 'error')
            return redirect(url_for('school_admin_add_students_by_class'))

        # First-time class setup: generate IDs based on alphabetical class list order.
        if not load_students(school_id, class_filter=classname):
            rows.sort(key=lambda r: (r.get('firstname', '').strip().lower(), r.get('reg_no', '').strip().lower()))
        
        # Starting index for generated IDs: append after the last student index in this class.
        next_index = get_next_student_index_for_class(school_id, classname)
        batch_ids = set()
        
        # Add each student. Use provided Reg No if present; otherwise auto-generate.
        for row in rows:
            firstname = normalize_person_name(row['firstname'])
            reg_no = row['reg_no']
            
            if reg_no:
                student_id = with_school_suffix_manual_id(reg_no, school_id)
                if not is_valid_manual_student_id(student_id):
                    flash(
                        f'Invalid Reg No. "{reg_no}" for {firstname}. Use only letters, numbers, /, -, _.',
                        'error'
                    )
                    continue
            else:
                current_index = next_index
                student_id = generate_student_id(school_id, current_index, first_year_class)
                # Ensure uniqueness even if a collision exists.
                while load_student(school_id, student_id):
                    current_index += 1
                    student_id = generate_student_id(school_id, current_index, first_year_class)
                next_index = current_index + 1

            if student_id.lower() in batch_ids:
                flash(f'Duplicate ID "{student_id}" in the submitted table. Skipped {firstname}.', 'error')
                continue
            batch_ids.add(student_id.lower())

            # Avoid ID collision in school.
            if load_student(school_id, student_id):
                flash(f'ID "{student_id}" already exists. Skipped {firstname}.', 'error')
                continue
            
            student_data = {
                'firstname': firstname,
                'date_of_birth': row.get('date_of_birth', ''),
                'gender': row.get('gender', ''),
                'classname': classname,
                'first_year_class': first_year_class,
                'term': term,
                'stream': stream,
                'number_of_subject': number_of_subject,
                'subjects': subjects,
                'scores': {},
                'promoted': 0
            }
            
            try:
                # Keep student row + login row atomic to avoid partial writes.
                with db_connection(commit=True) as conn:
                    c = conn.cursor()
                    existing_user = get_user(student_id)
                    if existing_user:
                        existing_role = (existing_user.get('role') or '').strip().lower()
                        existing_school = (existing_user.get('school_id') or '').strip()
                        if not (existing_role == 'student' and existing_school == school_id):
                            raise ValueError(
                                f'ID "{student_id}" is already used by another account '
                                f'({existing_role or "unknown"}).'
                            )
                    save_student_with_cursor(c, school_id, student_id, student_data)
                    if not existing_user:
                        upsert_user_with_cursor(c, student_id, hash_password(DEFAULT_STUDENT_PASSWORD), 'student', school_id)
                
                added_students.append({
                    'student_id': student_id,
                    'firstname': firstname,
                    'date_of_birth': row.get('date_of_birth', ''),
                    'gender': row.get('gender', ''),
                })
            except Exception as e:
                flash(f'Error adding student {firstname}: {str(e)}', 'error')
        
        if added_students:
            flash(f'Successfully added {len(added_students)} students to {classname}!', 'success')
            # Redirect to GET to prevent accidental form resubmission on refresh
            return redirect(f'{url_for("school_admin_add_students_by_class")}?class={urllib.parse.quote(classname)}')

    # Always build listing from fresh DB state so ordering and new additions are correct.
    all_students = load_students(school_id, include_archived=True)
    class_options = sorted(set(s.get('classname') for s in all_students.values() if s.get('classname')))
    class_students = [
        {
            'student_id': sid,
            'firstname': data.get('firstname', ''),
            'date_of_birth': data.get('date_of_birth', ''),
            'gender': data.get('gender', ''),
            'term': data.get('term', ''),
            'stream': data.get('stream', ''),
            'is_archived': int(data.get('is_archived', 0) or 0),
        }
        for sid, data in all_students.items()
        if selected_class and data.get('classname') == selected_class
    ]
    class_students.sort(key=lambda s: ((s.get('firstname') or '').strip().lower(), (s.get('student_id') or '').strip().lower()))

    return render_template(
        'school/add_students_by_class.html',
        added_students=added_students,
        class_options=class_options,
        selected_class=selected_class,
        class_students=class_students
    )

@app.route('/school-admin/assign-teacher', methods=['POST'])
def school_admin_assign_teacher():
    """Assign a teacher to a class."""
    if session.get('role') != 'school_admin':
        return redirect(url_for('login'))
    
    school_id = session.get('school_id')
    teacher_id = request.form.get('teacher_id', '').strip()
    classname = request.form.get('classname', '').strip()
    term = request.form.get('term', 'First Term').strip()
    valid_terms = {'First Term', 'Second Term', 'Third Term'}
    if term not in valid_terms:
        flash('Invalid term selected.', 'error')
        return redirect(url_for('school_admin_dashboard'))
    
    if teacher_id and classname:
        try:
            if teacher_id not in get_teachers(school_id):
                flash('Selected teacher does not belong to your school.', 'error')
                return redirect(url_for('school_admin_dashboard'))
            school = get_school(school_id)
            academic_year = (school.get('academic_year', '') or '').strip() if school else ''
            assign_teacher_to_class(school_id, teacher_id, classname, term, academic_year)
            flash(f'Teacher assigned to {classname} successfully!', 'success')
        except Exception as e:
            flash(f'Error assigning teacher: {str(e)}', 'error')
    else:
        flash('Please select a teacher and class.', 'error')
    
    return redirect(url_for('school_admin_dashboard'))

@app.route('/school-admin/assign-subject-teacher', methods=['POST'])
def school_admin_assign_subject_teacher():
    """Assign a teacher to one or more subjects in one/many compatible classes."""
    if session.get('role') != 'school_admin':
        return redirect(url_for('login'))

    school_id = session.get('school_id')
    teacher_id = request.form.get('teacher_id', '').strip()
    term = request.form.get('term', 'First Term').strip()
    assignment_scope = (request.form.get('assignment_scope', 'all_compatible') or 'all_compatible').strip().lower()
    legacy_classname = request.form.get('classname', '').strip()
    selected_classnames = [str(c).strip() for c in request.form.getlist('target_classnames') if str(c).strip()]
    subject_values = request.form.getlist('subjects')
    if not subject_values:
        subject_values = request.form.getlist('subjects[]')
    if subject_values:
        subjects = normalize_subjects_list(subject_values)
    else:
        subjects = normalize_subjects_list(request.form.get('subjects', ''))
    valid_terms = {'First Term', 'Second Term', 'Third Term'}
    if term not in valid_terms:
        flash('Invalid term selected.', 'error')
        return redirect(url_for('school_admin_dashboard'))

    if not teacher_id:
        flash('Please select teacher.', 'error')
        return redirect(url_for('school_admin_dashboard'))
    if teacher_id not in get_teachers(school_id):
        flash('Selected teacher does not belong to your school.', 'error')
        return redirect(url_for('school_admin_dashboard'))
    if not subjects:
        flash('Select at least one subject for assignment.', 'error')
        return redirect(url_for('school_admin_dashboard'))

    try:
        school = get_school(school_id)
        academic_year = (school.get('academic_year', '') or '').strip() if school else ''

        class_candidates = get_school_classnames(school_id)
        if not class_candidates:
            flash('No classes available for subject assignment yet.', 'error')
            return redirect(url_for('school_admin_dashboard'))

        class_subject_options = {}
        for cls in class_candidates:
            config = get_class_subject_config(school_id, cls) or {}
            cls_subjects = normalize_subjects_list(
                (config.get('core_subjects') or [])
                + (config.get('science_subjects') or [])
                + (config.get('art_subjects') or [])
                + (config.get('commercial_subjects') or [])
                + (config.get('optional_subjects') or [])
            )
            if not cls_subjects:
                defaults = _catalog_defaults_for_class(cls)
                cls_subjects = normalize_subjects_list(
                    (defaults.get('core') or [])
                    + (defaults.get('science') or [])
                    + (defaults.get('art') or [])
                    + (defaults.get('commercial') or [])
                    + (defaults.get('optional') or [])
                )
            class_subject_options[cls] = set(cls_subjects)

        compatible_classes = [
            cls for cls in class_candidates
            if all(subj in (class_subject_options.get(cls) or set()) for subj in subjects)
        ]
        if not compatible_classes:
            flash(
                'No compatible class found for selected subject(s): ' + ', '.join(subjects),
                'error',
            )
            return redirect(url_for('school_admin_dashboard'))

        if assignment_scope == 'selected':
            if not selected_classnames and legacy_classname:
                selected_classnames = [legacy_classname]
            if not selected_classnames:
                flash('Select at least one class or use "All compatible classes".', 'error')
                return redirect(url_for('school_admin_dashboard'))
            invalid_classes = [cls for cls in selected_classnames if cls not in compatible_classes]
            if invalid_classes:
                flash(
                    'Selected class(es) are not compatible with chosen subject(s): ' + ', '.join(invalid_classes),
                    'error',
                )
                return redirect(url_for('school_admin_dashboard'))
            target_classes = [cls for cls in class_candidates if cls in set(selected_classnames)]
        else:
            target_classes = compatible_classes

        # Enforce one-teacher-per-subject-per-class for the same term/year.
        existing_assignments = get_teacher_subject_assignments(
            school_id,
            term=term,
            academic_year=academic_year,
        )
        teachers_map = get_teachers(school_id)
        existing_owner_by_key = {}
        for row in existing_assignments:
            cls_key = (row.get('classname') or '').strip().lower()
            subj_key = normalize_subject_name(row.get('subject', '')).lower()
            owner_teacher_id = (row.get('teacher_id') or '').strip()
            if not cls_key or not subj_key or not owner_teacher_id:
                continue
            existing_owner_by_key[(cls_key, subj_key)] = owner_teacher_id

        conflicts = []
        for cls in target_classes:
            cls_key = (cls or '').strip().lower()
            for subject in subjects:
                subj_key = normalize_subject_name(subject).lower()
                owner_teacher_id = existing_owner_by_key.get((cls_key, subj_key), '')
                if owner_teacher_id and owner_teacher_id != teacher_id:
                    owner_profile = teachers_map.get(owner_teacher_id, {}) or {}
                    owner_name = f"{owner_profile.get('firstname', '')} {owner_profile.get('lastname', '')}".strip()
                    owner_label = owner_name or owner_teacher_id
                    conflicts.append(f'{subject} ({cls}) already assigned to {owner_label}')
        if conflicts:
            flash(
                'Cannot assign duplicate class-subject owner. '
                + '; '.join(conflicts[:6])
                + ('...' if len(conflicts) > 6 else ''),
                'error',
            )
            return redirect(url_for('school_admin_dashboard'))

        for cls in target_classes:
            assign_teacher_to_subjects(school_id, teacher_id, cls, subjects, term, academic_year)

        flash(
            f'Subject assignment saved for {len(target_classes)} class(es): ' + ', '.join(target_classes[:8])
            + ('...' if len(target_classes) > 8 else ''),
            'success',
        )
    except Exception as e:
        flash(f'Error assigning subject teacher: {str(e)}', 'error')

    return redirect(url_for('school_admin_dashboard'))

@app.route('/school-admin/send-student-message', methods=['POST'])
def school_admin_send_student_message():
    if session.get('role') != 'school_admin':
        return redirect(url_for('login'))

    school_id = session.get('school_id')
    admin_user_id = session.get('user_id')
    title = (request.form.get('title', '') or '').strip()
    message = (request.form.get('message', '') or '').strip()
    target_mode = (request.form.get('target_mode', 'all') or 'all').strip().lower()
    target_classname = (request.form.get('target_classname', '') or '').strip()
    target_stream = (request.form.get('target_stream', '') or '').strip()
    deadline_date = (request.form.get('deadline_date', '') or '').strip()

    if target_mode not in {'all', 'class', 'stream'}:
        target_mode = 'all'
    if target_mode == 'all':
        target_classname = ''
        target_stream = ''
    elif target_mode == 'class':
        if not target_classname:
            flash('Select class target for this message.', 'error')
            return redirect(url_for('school_admin_messages'))
        target_stream = ''
    else:  # stream
        if not target_classname:
            flash('Select class for stream-targeted message.', 'error')
            return redirect(url_for('school_admin_messages'))
        if target_stream not in {'Science', 'Art', 'Commercial'}:
            flash('Select a valid stream target (Science, Art, Commercial).', 'error')
            return redirect(url_for('school_admin_messages'))

    try:
        create_student_message(
            school_id=school_id,
            title=title,
            message=message,
            target_classname=target_classname,
            target_stream=target_stream,
            deadline_date=deadline_date,
            created_by=admin_user_id,
        )
        flash('Student message sent successfully.', 'success')
    except Exception as exc:
        flash(f'Failed to send student message: {exc}', 'error')
    return redirect(url_for('school_admin_messages'))

@app.route('/school-admin/send-teacher-message', methods=['POST'])
def school_admin_send_teacher_message():
    if session.get('role') != 'school_admin':
        return redirect(url_for('login'))
    school_id = session.get('school_id')
    admin_user_id = session.get('user_id')
    title = (request.form.get('title', '') or '').strip()
    message = (request.form.get('message', '') or '').strip()
    target_mode = (request.form.get('target_mode', 'all') or 'all').strip().lower()
    target_classname = (request.form.get('target_classname', '') or '').strip()
    target_subject = normalize_subject_name(request.form.get('target_subject', ''))
    deadline_date = (request.form.get('deadline_date', '') or '').strip()
    if target_mode not in {'all', 'class', 'subject', 'class_subject'}:
        target_mode = 'all'
    if target_mode == 'all':
        target_classname = ''
        target_subject = ''
    elif target_mode == 'class':
        if not target_classname:
            flash('Select class target for teacher message.', 'error')
            return redirect(url_for('school_admin_messages'))
        target_subject = ''
    elif target_mode == 'subject':
        if not target_subject:
            flash('Select subject target for teacher message.', 'error')
            return redirect(url_for('school_admin_messages'))
        target_classname = ''
    else:
        if not target_classname or not target_subject:
            flash('Select both class and subject for this teacher message target.', 'error')
            return redirect(url_for('school_admin_messages'))
    try:
        create_teacher_message(
            school_id=school_id,
            title=title,
            message=message,
            target_classname=target_classname,
            target_subject=target_subject,
            deadline_date=deadline_date,
            created_by=admin_user_id,
        )
        flash('Teacher message sent successfully.', 'success')
    except Exception as exc:
        flash(f'Failed to send teacher message: {exc}', 'error')
    return redirect(url_for('school_admin_messages'))

@app.route('/school-admin/toggle-operations', methods=['POST'])
def school_admin_toggle_operations():
    """School admin can toggle teacher editing operations only."""
    if session.get('role') != 'school_admin':
        return redirect(url_for('login'))
    school_id = session.get('school_id')
    enabled = request.form.get('teacher_operations_enabled', '1').strip() == '1'
    set_teacher_operations_enabled(school_id, enabled)
    state = 'ON' if enabled else 'OFF'
    flash(f'Teacher operations set to {state}.', 'success')
    return redirect(url_for('school_admin_dashboard'))

@app.route('/school-admin/remove-teacher-assignment', methods=['POST'])
def school_admin_remove_teacher_assignment():
    """Remove a teacher assignment from a class."""
    if session.get('role') != 'school_admin':
        return redirect(url_for('login'))

    school_id = session.get('school_id')
    teacher_id = request.form.get('teacher_id', '').strip()
    classname = request.form.get('classname', '').strip()
    term = request.form.get('term', '').strip()
    academic_year = request.form.get('academic_year', '').strip()

    if not teacher_id or not classname or not term or not academic_year:
        flash('Missing assignment details.', 'error')
        return redirect(url_for('school_admin_dashboard'))

    try:
        remove_teacher_from_class(school_id, teacher_id, classname, term, academic_year)
        flash(f'Removed assignment: {teacher_id} from {classname} ({term}).', 'success')
    except Exception as exc:
        flash(f'Error removing assignment: {str(exc)}', 'error')

    return redirect(url_for('school_admin_dashboard'))

@app.route('/school-admin/remove-subject-teacher-assignment', methods=['POST'])
def school_admin_remove_subject_teacher_assignment():
    """Remove a teacher subject assignment from class."""
    if session.get('role') != 'school_admin':
        return redirect(url_for('login'))

    school_id = session.get('school_id')
    teacher_id = request.form.get('teacher_id', '').strip()
    classname = request.form.get('classname', '').strip()
    subject = request.form.get('subject', '').strip()
    term = request.form.get('term', '').strip()
    academic_year = request.form.get('academic_year', '').strip()
    if not teacher_id or not classname or not subject or not term or not academic_year:
        flash('Missing subject assignment details.', 'error')
        return redirect(url_for('school_admin_dashboard'))
    try:
        remove_teacher_subject_assignment(school_id, teacher_id, classname, subject, term, academic_year)
        flash(f'Removed subject assignment: {subject} ({classname})', 'success')
    except Exception as exc:
        flash(f'Error removing subject assignment: {str(exc)}', 'error')
    return redirect(url_for('school_admin_dashboard'))

# ==================== TEACHER ROUTES ====================

@app.route('/teacher')
def teacher_dashboard():
    if session.get('role') != 'teacher':
        return redirect(url_for('login'))
    
    school_id = session.get('school_id')
    teacher_id = session.get('user_id')
    school = get_school(school_id)
    current_term = get_current_term(school)
    current_year = (school or {}).get('academic_year', '')
    term_calendar = get_school_term_calendar(school_id, current_year, current_term)
    term_program_for_progress = get_school_term_program(school_id, current_year, current_term)
    term_open_progress = build_term_open_progress(term_calendar, term_program_for_progress)
    teacher_profile = get_teachers(school_id).get(teacher_id, {})
    teacher_name = f"{teacher_profile.get('firstname', '')} {teacher_profile.get('lastname', '')}".strip() or teacher_id
    teacher_phone = (teacher_profile.get('phone') or '').strip()
    teacher_profile_image = (teacher_profile.get('profile_image') or '').strip()
    has_teacher_signature = bool(teacher_profile.get('signature_image'))
    teacher_subjects = normalize_subjects_list(teacher_profile.get('subjects_taught', []))
    teacher_subjects_set = {s.lower() for s in teacher_subjects}
    last_login_at = format_timestamp(get_last_login_at(session.get('user_id')))
    
    classes = get_teacher_classes(school_id, teacher_id, term=current_term, academic_year=current_year)
    class_students_data = load_students_for_classes(school_id, classes, term_filter=current_term)
    subject_assignment_rows = get_teacher_subject_assignments(
        school_id,
        teacher_id=teacher_id,
        term=current_term,
        academic_year=current_year,
    )
    subject_assignment_by_class = {}
    subject_assignment_set = set()
    for row in subject_assignment_rows:
        cls = (row.get('classname') or '').strip()
        subj = normalize_subject_name(row.get('subject', ''))
        if not cls or not subj:
            continue
        subject_assignment_by_class.setdefault(cls, set()).add(subj)
        subject_assignment_set.add(subj)
    subject_assignment_summary = [
        {
            'classname': cls,
            'subjects': sorted(values, key=lambda x: str(x).lower()),
        }
        for cls, values in sorted(subject_assignment_by_class.items(), key=lambda item: str(item[0]).lower())
    ]
    subject_classes = sorted({r.get('classname', '') for r in subject_assignment_rows if r.get('classname', '')})
    dashboard_classes = sorted(set(classes) | set(subject_classes))
    if set(dashboard_classes) == set(classes):
        students = class_students_data
    else:
        students = load_students_for_classes(school_id, dashboard_classes, term_filter=current_term)
    score_subject_nav_map = {}
    for row in subject_assignment_rows:
        cls = (row.get('classname') or '').strip()
        subj = normalize_subject_name(row.get('subject', ''))
        if not cls or not subj:
            continue
        score_subject_nav_map.setdefault(subj, set()).add(cls)
    score_nav_tree = [
        {
            'subject': subj,
            'classes': sorted(score_subject_nav_map.get(subj, set()), key=lambda x: str(x).lower()),
        }
        for subj in sorted(score_subject_nav_map.keys(), key=lambda x: str(x).lower())
    ]
    selected_score_subject = normalize_subject_name((request.args.get('score_subject', '') or '').strip())
    valid_subjects_for_nav = {row['subject'] for row in score_nav_tree}
    if selected_score_subject not in valid_subjects_for_nav:
        selected_score_subject = ''
    selected_score_class = (request.args.get('score_class', '') or '').strip()
    if selected_score_subject:
        valid_classes_for_subject = set(score_subject_nav_map.get(selected_score_subject, set()))
        if selected_score_class not in valid_classes_for_subject:
            selected_score_class = ''
    elif selected_score_class:
        valid_classes_global = {cls for values in score_subject_nav_map.values() for cls in values}
        if selected_score_class not in valid_classes_global:
            selected_score_class = ''

    subject_map_by_class = {}
    for row in subject_assignment_rows:
        cls = (row.get('classname') or '').strip()
        subj = normalize_subject_name(row.get('subject', ''))
        if not cls or not subj:
            continue
        subject_map_by_class.setdefault(cls, set()).add(subj)

    class_owner_set = {(c or '').strip().lower() for c in classes}
    recent_students = []
    for sid, s in sorted(
        students.items(),
        key=lambda item: (
            (item[1].get('classname', '') or '').strip().lower(),
            (item[1].get('firstname', '') or '').strip().lower(),
            (item[0] or '').strip().lower(),
        ),
    ):
        classname = (s.get('classname') or '').strip()
        is_class_owner = classname.lower() in class_owner_set if classname else False
        offered_subjects = normalize_subjects_list(s.get('subjects', []))
        matched_subjects = []
        if not is_class_owner:
            allowed_for_class = subject_map_by_class.get(classname, set())
            if not allowed_for_class:
                continue
            matched_subjects = [x for x in offered_subjects if x in allowed_for_class]
            if not matched_subjects:
                continue
        student_view = dict(s)
        student_view['is_class_owner'] = bool(is_class_owner)
        student_view['matched_subjects'] = matched_subjects
        if is_class_owner:
            scope_complete = is_student_score_complete(s, school, current_term)
        else:
            scores_map = s.get('scores', {}) if isinstance(s.get('scores', {}), dict) else {}
            scope_complete = bool(matched_subjects) and all(
                is_score_complete_for_subject(
                    get_subject_score_block(scores_map, subj),
                    school,
                )
                for subj in matched_subjects
            )
        student_view['scope_complete'] = bool(scope_complete)
        recent_students.append((sid, student_view))

    subject_students_data = load_students_for_classes(school_id, subject_map_by_class.keys(), term_filter=current_term)
    subject_student_rows = []
    for sid, s in sorted(
        subject_students_data.items(),
        key=lambda item: (
            (item[1].get('classname', '') or '').strip().lower(),
            (item[1].get('firstname', '') or '').strip().lower(),
            (item[0] or '').strip().lower(),
        )
    ):
        class_subjects = normalize_subjects_list(s.get('subjects', []))
        allowed_for_class = subject_map_by_class.get(s.get('classname', ''), set())
        if not allowed_for_class:
            continue
        matched_subjects = [x for x in class_subjects if x in allowed_for_class]
        if not matched_subjects:
            continue
        subject_student_rows.append({
            'student_id': sid,
            'firstname': s.get('firstname', ''),
            'classname': s.get('classname', ''),
            'term': s.get('term', ''),
            'stream': s.get('stream', ''),
            'subjects': matched_subjects,
        })
    filtered_subject_student_rows = []
    for row in subject_student_rows:
        row_class = (row.get('classname') or '').strip()
        if selected_score_class and row_class != selected_score_class:
            continue
        row_subjects = normalize_subjects_list(row.get('subjects', []))
        if selected_score_subject:
            if selected_score_subject not in row_subjects:
                continue
            row_subjects = [selected_score_subject]
        filtered_subject_student_rows.append({
            **row,
            'subjects': row_subjects,
        })
    rank_subjects_by_class = {}
    for item in subject_student_rows:
        cls = (item.get('classname') or '').strip()
        if not cls:
            continue
        rank_subjects_by_class.setdefault(cls, set()).update(normalize_subjects_list(item.get('subjects', [])))
    rank_class_options = sorted(rank_subjects_by_class.keys(), key=lambda x: str(x).lower())
    rank_default_arm_mode = ((school or {}).get('class_arm_ranking_mode') or 'separate').strip().lower()
    if rank_default_arm_mode not in {'separate', 'together'}:
        rank_default_arm_mode = 'separate'
    selected_rank_class = (request.args.get('rank_class') or '').strip()
    if selected_rank_class not in rank_subjects_by_class:
        selected_rank_class = rank_class_options[0] if rank_class_options else ''
    requested_rank_arm_mode = (request.args.get('rank_arm_mode') or '').strip().lower()
    if requested_rank_arm_mode:
        selected_rank_arm_mode = requested_rank_arm_mode
    else:
        _level, _num, selected_arm = _split_class_level_number_arm(selected_rank_class)
        selected_rank_arm_mode = 'together' if selected_arm else rank_default_arm_mode
    if selected_rank_arm_mode not in {'separate', 'together'}:
        selected_rank_arm_mode = rank_default_arm_mode
    rank_subject_options = sorted(rank_subjects_by_class.get(selected_rank_class, []), key=lambda x: str(x).lower())
    selected_rank_subject = normalize_subject_name(request.args.get('rank_subject', ''))
    if selected_rank_subject not in rank_subject_options:
        selected_rank_subject = rank_subject_options[0] if rank_subject_options else ''
    selected_rank_group_classes = []
    subject_rank_rows = []
    subject_rank_summary = {
        'available_students': 0,
        'ranked_students': 0,
        'missing_scores': 0,
    }
    if selected_rank_class and selected_rank_subject:
        if selected_rank_arm_mode == 'together':
            target_group = class_arm_ranking_group(selected_rank_class, mode='together')
            selected_rank_group_classes = sorted(
                [
                    c
                    for c, subject_set in rank_subjects_by_class.items()
                    if class_arm_ranking_group(c, mode='together') == target_group
                    and selected_rank_subject in subject_set
                ],
                key=lambda x: str(x).lower(),
            )
        else:
            selected_rank_group_classes = [selected_rank_class]
        rank_students_map = load_students_for_classes(
            school_id,
            selected_rank_group_classes,
            term_filter=current_term,
        )
        ranked_entries = []
        missing_scores = 0
        for sid, student in sorted(
            rank_students_map.items(),
            key=lambda item: (
                (item[1].get('classname', '') or '').strip().lower(),
                (item[1].get('firstname', '') or '').strip().lower(),
                (item[0] or '').strip().lower(),
            )
        ):
            classname = (student.get('classname') or '').strip()
            if not classname:
                continue
            if not teacher_can_score_subject(
                school_id,
                teacher_id,
                classname,
                selected_rank_subject,
                term=current_term,
                academic_year=current_year,
            ):
                continue
            offered_subjects = normalize_subjects_list(student.get('subjects', []))
            subj_map = {s.lower(): s for s in offered_subjects}
            subject_key = subj_map.get(selected_rank_subject.lower(), '')
            if not subject_key:
                continue
            subject_rank_summary['available_students'] += 1
            score_block = (student.get('scores') or {}).get(subject_key, {})
            if not is_score_complete_for_subject(score_block, school):
                missing_scores += 1
                continue
            mark = float(subject_overall_mark(score_block))
            ranked_entries.append({
                'student_id': sid,
                'firstname': student.get('firstname', ''),
                'classname': classname,
                'stream': student.get('stream', ''),
                'mark': mark,
            })
        ranked_entries.sort(
            key=lambda row: (
                -row.get('mark', 0),
                (row.get('firstname', '') or '').strip().lower(),
                (row.get('student_id', '') or '').strip().lower(),
            )
        )
        prev_mark = None
        current_rank = 0
        for idx, row in enumerate(ranked_entries, start=1):
            mark = row.get('mark', 0)
            if prev_mark is None or mark != prev_mark:
                current_rank = idx
                prev_mark = mark
            subject_rank_rows.append({
                **row,
                'position': current_rank,
            })
        subject_rank_summary['ranked_students'] = len(subject_rank_rows)
        subject_rank_summary['missing_scores'] = missing_scores
    current_term = get_current_term(school)
    pending_stream_students = {
        sid for sid, s in class_students_data.items()
        if class_uses_stream_for_school(school, s.get('classname', '')) and (s.get('stream') in ('', 'N/A', None))
    }
    stream_managed_students = {
        sid for sid, s in class_students_data.items()
        if class_uses_stream_for_school(school, s.get('classname', ''))
    }
    score_complete_students = {
        sid for sid, s in class_students_data.items() if is_student_score_complete(s, school, current_term)
    }
    class_publish_status = {}
    class_view_status = get_class_published_view_counts(school_id, current_term, current_year, classes)
    publication_rows = get_publication_rows_for_classes(school_id, current_term, current_year, classes)
    viewed_student_ids = get_viewed_student_ids_for_classes(school_id, classes, current_term, current_year)
    for classname in classes:
        class_students = [s for s in class_students_data.values() if s.get('classname') == classname and s.get('term') == current_term]
        total = len(class_students)
        class_student_ids = [sid for sid, s in class_students_data.items() if s.get('classname') == classname and s.get('term') == current_term]
        completed = sum(1 for s in class_students if is_student_score_complete(s, school, current_term))
        behaviour_progress = class_behaviour_completion(school_id, classname, current_term, current_year, class_student_ids)
        subject_progress = compute_class_subject_completion(
            school_id=school_id,
            classname=classname,
            term=current_term,
            academic_year=current_year,
            school=school,
            class_students_data={idx: s for idx, s in enumerate(class_students)},
        )
        class_views = class_view_status.get(classname, {})
        pub = publication_rows.get(classname, {})
        subject_pending_count = sum(1 for row in subject_progress.get('rows', []) if int(row.get('pending_students', 0)) > 0)
        class_publish_status[classname] = {
            'total': total,
            'completed': completed,
            'ready': total > 0 and completed == total and bool(subject_progress.get('ready', False)) and bool(behaviour_progress.get('ready', False)),
            'subject_ready': bool(subject_progress.get('ready', False)),
            'subject_progress': subject_progress.get('rows', []),
            'subject_pending_count': subject_pending_count,
            'behaviour_ready': bool(behaviour_progress.get('ready', False)),
            'behaviour_missing_count': int(behaviour_progress.get('missing_count', 0) or 0),
            'published': bool(pub.get('is_published', False)),
            'approval_status': pub.get('approval_status', 'not_submitted'),
            'submitted_at': pub.get('submitted_at', ''),
            'reviewed_at': pub.get('reviewed_at', ''),
            'review_note': pub.get('review_note', ''),
            'published_students': int(class_views.get('published_count', 0)),
            'viewed_students': int(class_views.get('viewed_count', 0)),
        }
    teacher_missing_score_alerts = []
    for classname in classes:
        s = class_publish_status.get(classname, {})
        if int(s.get('subject_pending_count', 0) or 0) <= 0:
            continue
        pending_subject_names = [
            row.get('subject', '')
            for row in (s.get('subject_progress') or [])
            if int(row.get('pending_students', 0) or 0) > 0
        ]
        teacher_missing_score_alerts.append({
            'scope': 'class_owner',
            'classname': classname,
            'subject': '',
            'pending_students': sum(
                int(row.get('pending_students', 0) or 0)
                for row in (s.get('subject_progress') or [])
                if int(row.get('pending_students', 0) or 0) > 0
            ),
            'message': f'{classname}: pending subjects - {", ".join(pending_subject_names[:6])}' + ('...' if len(pending_subject_names) > 6 else ''),
        })
    for classname in classes:
        s = class_publish_status.get(classname, {})
        if int(s.get('behaviour_missing_count', 0) or 0) > 0:
            teacher_missing_score_alerts.append({
                'scope': 'class_owner',
                'classname': classname,
                'subject': 'Behaviour Assessment',
                'pending_students': int(s.get('behaviour_missing_count', 0) or 0),
                'message': f'{classname}: behaviour assessment pending for {int(s.get("behaviour_missing_count", 0) or 0)} student(s).',
            })

    subject_students_lookup = subject_students_data
    seen_subject_alerts = set()
    for row in subject_assignment_rows:
        classname = (row.get('classname') or '').strip()
        subject = normalize_subject_name(row.get('subject', ''))
        key = (classname.lower(), subject.lower())
        if not classname or not subject or key in seen_subject_alerts:
            continue
        seen_subject_alerts.add(key)
        eligible = 0
        completed = 0
        for _sid, student in subject_students_lookup.items():
            if (student.get('classname') or '').strip().lower() != classname.lower():
                continue
            offered = {x.lower(): x for x in normalize_subjects_list(student.get('subjects', []))}
            subject_key = offered.get(subject.lower(), '')
            if not subject_key:
                continue
            eligible += 1
            score_block = get_subject_score_block((student.get('scores') or {}), subject_key)
            if is_score_complete_for_subject(score_block, school):
                completed += 1
        pending = max(0, eligible - completed)
        if pending <= 0:
            continue
        teacher_missing_score_alerts.append({
            'scope': 'subject_teacher',
            'classname': classname,
            'subject': subject,
            'pending_students': pending,
            'message': f'{classname} - {subject}: {pending} student(s) pending.',
        })
    teacher_missing_score_alerts.sort(
        key=lambda x: (
            (x.get('scope', '') or '').lower(),
            -(int(x.get('pending_students', 0) or 0)),
            (x.get('classname', '') or '').lower(),
            (x.get('subject', '') or '').lower(),
        )
    )
    teacher_term_events = get_visible_term_program_events(
        school_id=school_id,
        academic_year=current_year,
        term=current_term,
        audience='teachers',
    )
    subject_submit_rows = []
    submitted_map = get_subject_score_submission_map(school_id, teacher_id, current_term, current_year)
    subject_submit_students = load_students_for_classes(
        school_id,
        subject_map_by_class.keys(),
        term_filter=current_term,
    )
    students_by_class_for_submit = {}
    for sid, st in (subject_submit_students or {}).items():
        cls_name = (st.get('classname') or '').strip()
        if not cls_name:
            continue
        students_by_class_for_submit.setdefault(cls_name, {})[sid] = st
    for cls in sorted(subject_map_by_class.keys(), key=lambda x: str(x).lower()):
        if (cls or '').strip().lower() in class_owner_set:
            continue
        allowed_subjects = subject_map_by_class.get(cls, set())
        if not allowed_subjects:
            continue
        class_students = students_by_class_for_submit.get(cls, {})
        pending_entries = 0
        eligible_entries = 0
        for _sid, st in class_students.items():
            offered_subjects = normalize_subjects_list(st.get('subjects', []))
            offered_map = {s.lower(): s for s in offered_subjects}
            matched = [offered_map[s.lower()] for s in allowed_subjects if s.lower() in offered_map]
            for subj_key in matched:
                eligible_entries += 1
                score_block = get_subject_score_block((st.get('scores') or {}), subj_key)
                if not is_score_complete_for_subject(score_block, school):
                    pending_entries += 1
        submitted_at = submitted_map.get(cls, '')
        subject_submit_rows.append({
            'classname': cls,
            'subjects': sorted(list(allowed_subjects), key=lambda x: str(x).lower()),
            'eligible_entries': eligible_entries,
            'pending_entries': pending_entries,
            'ready': pending_entries == 0 and eligible_entries > 0,
            'submitted_at': format_timestamp(submitted_at) if submitted_at else '',
            'is_submitted': bool(submitted_at),
        })
    locked_subjects_by_class = {}
    for cls in classes:
        cls_rows = get_teacher_subject_assignments(
            school_id,
            classname=cls,
            term=current_term,
            academic_year=current_year,
        )
        if not cls_rows:
            continue
        submitted_teacher_ids = get_subject_submission_teacher_ids_for_class(
            school_id,
            cls,
            current_term,
            current_year,
        )
        locked = set()
        for row in cls_rows:
            assigned_teacher = (row.get('teacher_id') or '').strip()
            subject_name = normalize_subject_name(row.get('subject', ''))
            if not subject_name:
                continue
            if assigned_teacher and assigned_teacher != teacher_id and assigned_teacher not in submitted_teacher_ids:
                locked.add(subject_name)
        if locked:
            locked_subjects_by_class[cls] = sorted(locked, key=lambda x: str(x).lower())
    teacher_messages = get_teacher_messages_for_teacher(
        school_id=school_id,
        teacher_id=teacher_id,
        classes=dashboard_classes,
        subjects=list(subject_assignment_set),
        limit=20,
    )
    unread_teacher_messages = sum(1 for row in teacher_messages if not row.get('is_read'))

    return render_template('teacher/teacher_dashboard.html', 
                         classes=classes, 
                         subject_assignment_rows=subject_assignment_rows,
                         subject_assignment_summary=subject_assignment_summary,
                         subject_assignment_count=len(subject_assignment_rows),
                         subject_assignment_subject_count=len(subject_assignment_set),
                         students=students,
                         recent_students=recent_students,
                         school=school,
                         teacher_name=teacher_name,
                         teacher_id=teacher_id,
                         teacher_phone=teacher_phone,
                         teacher_profile_image=teacher_profile_image,
                         teacher_subjects=teacher_subjects,
                         pending_stream_students=pending_stream_students,
                         stream_managed_students=stream_managed_students,
                         subject_student_rows=subject_student_rows,
                         current_term=current_term,
                         current_year=current_year,
                         term_open_progress=term_open_progress,
                         last_login_at=last_login_at,
                         has_teacher_signature=has_teacher_signature,
                         score_complete_students=score_complete_students,
                         class_publish_status=class_publish_status,
                         teacher_missing_score_alerts=teacher_missing_score_alerts,
                         teacher_messages=teacher_messages,
                         unread_teacher_messages=unread_teacher_messages,
                         teacher_term_events=teacher_term_events,
                         subject_submit_rows=subject_submit_rows,
                         locked_subjects_by_class=locked_subjects_by_class,
                         score_nav_tree=score_nav_tree,
                         selected_score_subject=selected_score_subject,
                         selected_score_class=selected_score_class,
                         viewed_student_ids=viewed_student_ids,
                         filtered_subject_student_rows=filtered_subject_student_rows,
                         rank_class_options=rank_class_options,
                         rank_subject_options=rank_subject_options,
                         selected_rank_class=selected_rank_class,
                         selected_rank_subject=selected_rank_subject,
                         selected_rank_arm_mode=selected_rank_arm_mode,
                         selected_rank_group_classes=selected_rank_group_classes,
                         subject_rank_rows=subject_rank_rows,
                         subject_rank_summary=subject_rank_summary)

@app.route('/teacher/messages/mark-read', methods=['POST'])
def teacher_mark_message_read():
    if session.get('role') != 'teacher':
        return redirect(url_for('login'))
    school_id = session.get('school_id')
    teacher_id = session.get('user_id')
    message_id_raw = (request.form.get('message_id', '') or '').strip()
    try:
        message_id = int(message_id_raw)
    except Exception:
        flash('Invalid message selection.', 'error')
        return redirect(url_for('teacher_messages'))
    changed = mark_teacher_message_read(school_id, teacher_id, message_id)
    if changed:
        flash('Notification marked as read.', 'success')
    else:
        flash('Unable to update notification status.', 'warning')
    return redirect(url_for('teacher_messages'))

@app.route('/teacher/messages/mark-all-read', methods=['POST'])
def teacher_mark_all_messages_read():
    if session.get('role') != 'teacher':
        return redirect(url_for('login'))
    school_id = session.get('school_id')
    teacher_id = session.get('user_id')
    school = get_school(school_id) or {}
    current_term = get_current_term(school)
    current_year = (school.get('academic_year', '') or '').strip()
    classes = get_teacher_classes(school_id, teacher_id, term=current_term, academic_year=current_year)
    subject_rows = get_teacher_subject_assignments(
        school_id,
        teacher_id=teacher_id,
        term=current_term,
        academic_year=current_year,
    )
    subject_set = {normalize_subject_name(row.get('subject', '')) for row in subject_rows if normalize_subject_name(row.get('subject', ''))}
    class_set = sorted(set(classes) | {str(row.get('classname') or '').strip() for row in subject_rows if (row.get('classname') or '').strip()})
    changed = mark_all_teacher_messages_read(
        school_id=school_id,
        teacher_id=teacher_id,
        classes=class_set,
        subjects=sorted(subject_set),
    )
    if changed:
        flash('All notifications marked as read.', 'success')
    else:
        flash('No visible notifications to update.', 'warning')
    return redirect(url_for('teacher_messages'))


@app.route('/teacher/messages')
def teacher_messages():
    if session.get('role') != 'teacher':
        return redirect(url_for('login'))

    school_id = session.get('school_id')
    teacher_id = session.get('user_id')
    school = get_school(school_id) or {}
    current_term = get_current_term(school)
    current_year = (school.get('academic_year', '') or '').strip()
    classes = get_teacher_classes(school_id, teacher_id, term=current_term, academic_year=current_year)
    subject_rows = get_teacher_subject_assignments(
        school_id,
        teacher_id=teacher_id,
        term=current_term,
        academic_year=current_year,
    )
    subject_set = {normalize_subject_name(row.get('subject', '')) for row in subject_rows if normalize_subject_name(row.get('subject', ''))}
    class_set = sorted(set(classes) | {str(row.get('classname') or '').strip() for row in subject_rows if (row.get('classname') or '').strip()})
    teacher_messages = get_teacher_messages_for_teacher(
        school_id=school_id,
        teacher_id=teacher_id,
        classes=class_set,
        subjects=sorted(subject_set),
        limit=80,
    )
    unread_teacher_messages = sum(1 for row in teacher_messages if not row.get('is_read'))
    teacher_profile = get_teachers(school_id).get(teacher_id, {})
    teacher_name = f"{teacher_profile.get('firstname', '')} {teacher_profile.get('lastname', '')}".strip() or teacher_id
    teacher_profile_image = (teacher_profile.get('profile_image') or '').strip()

    return render_template(
        'teacher/teacher_messages.html',
        school=school,
        current_term=current_term,
        current_year=current_year,
        teacher_name=teacher_name,
        teacher_profile_image=teacher_profile_image,
        classes=classes,
        selected_class=(classes[0] if classes else ''),
        teacher_messages=teacher_messages,
        unread_teacher_messages=unread_teacher_messages,
    )

@app.route('/teacher/attendance', methods=['GET', 'POST'])
def teacher_attendance():
    if session.get('role') != 'teacher':
        return redirect(url_for('login'))

    school_id = session.get('school_id')
    teacher_id = session.get('user_id')
    school = get_school(school_id) or {}
    current_term = get_current_term(school)
    current_year = (school or {}).get('academic_year', '')
    classes = get_teacher_classes(school_id, teacher_id, term=current_term, academic_year=current_year)
    if not classes:
        flash('No class assignment found for attendance.', 'error')
        return redirect(url_for('teacher_dashboard'))
    classes = sorted(set(classes), key=lambda x: str(x).lower())

    selected_class = (request.values.get('classname', '') or '').strip()
    if selected_class not in classes:
        selected_class = classes[0]
    selected_date = (request.values.get('attendance_date', '') or '').strip()
    if not selected_date:
        selected_date = datetime.now().strftime('%Y-%m-%d')
    try:
        datetime.strptime(selected_date, '%Y-%m-%d')
    except Exception:
        selected_date = datetime.now().strftime('%Y-%m-%d')
    instructional_dates = get_term_instructional_dates(school_id, current_year, current_term)
    valid_date_list = instructional_dates.get('valid_dates') or []
    valid_iso_set = instructional_dates.get('valid_iso_set') or set()
    if selected_date not in valid_iso_set and valid_date_list:
        today = date.today()
        eligible = [d for d in valid_date_list if d <= today]
        selected_date = (eligible[-1] if eligible else valid_date_list[0]).isoformat()

    if request.method == 'POST':
        if selected_date not in valid_iso_set:
            flash(
                f'Invalid attendance date for {current_term} ({current_year}). '
                'Pick an instructional day from the current term calendar.',
                'error',
            )
            return redirect(url_for('teacher_attendance', classname=selected_class, attendance_date=selected_date))
        if not teacher_has_class_access(school_id, teacher_id, selected_class, term=current_term, academic_year=current_year):
            flash('You are not assigned to this class for the current term/year.', 'error')
            return redirect(url_for('teacher_dashboard'))
        students_map = load_students(school_id, class_filter=selected_class, term_filter=current_term)
        student_rows = sorted(
            students_map.items(),
            key=lambda item: ((item[1].get('firstname', '') or '').lower(), (item[0] or '').lower()),
        )
        if not student_rows:
            flash(f'No students found in {selected_class} for {current_term}.', 'error')
            return redirect(url_for('teacher_attendance', classname=selected_class, attendance_date=selected_date))

        missing = []
        prepared = []
        for sid, st in student_rows:
            status = normalize_attendance_status(request.form.get(f'status_{sid}', ''))
            note = (request.form.get(f'note_{sid}', '') or '').strip()[:250]
            if not status:
                missing.append(st.get('firstname', sid))
                continue
            prepared.append((sid, st, status, note))
        if missing:
            flash(
                f'Attendance status is required for all students. Missing: {", ".join(missing[:6])}'
                + ('...' if len(missing) > 6 else ''),
                'error',
            )
            return redirect(url_for('teacher_attendance', classname=selected_class, attendance_date=selected_date))

        try:
            with db_connection(commit=True) as conn:
                c = conn.cursor()
                for sid, _st, status, note in prepared:
                    save_attendance_record_with_cursor(
                        c=c,
                        school_id=school_id,
                        student_id=sid,
                        classname=selected_class,
                        term=current_term,
                        academic_year=current_year,
                        attendance_date=selected_date,
                        status=status,
                        note=note,
                        marked_by=teacher_id,
                    )
            flash(f'Attendance saved for {selected_class} on {selected_date}.', 'success')
        except Exception as exc:
            flash(f'Failed to save attendance: {exc}', 'error')
        return redirect(url_for('teacher_attendance', classname=selected_class, attendance_date=selected_date))

    class_students = load_students(school_id, class_filter=selected_class, term_filter=current_term)
    student_rows = sorted(
        class_students.items(),
        key=lambda item: ((item[1].get('firstname', '') or '').lower(), (item[0] or '').lower()),
    )
    attendance_map = get_class_attendance_for_date(
        school_id=school_id,
        classname=selected_class,
        attendance_date=selected_date,
        term=current_term,
        academic_year=current_year,
    )
    status_counts = {key: 0 for key, _label in ATTENDANCE_STATUS_OPTIONS}
    for sid, _st in student_rows:
        key = normalize_attendance_status((attendance_map.get(sid) or {}).get('status', ''))
        if key:
            status_counts[key] += 1
    summary = get_class_attendance_summary(
        school_id=school_id,
        classname=selected_class,
        term=current_term,
        academic_year=current_year,
    )
    total_students = len(student_rows)

    return render_template(
        'teacher/teacher_attendance.html',
        school=school,
        classes=classes,
        selected_class=selected_class,
        selected_date=selected_date,
        current_term=current_term,
        current_year=current_year,
        teacher_id=teacher_id,
        student_rows=student_rows,
        attendance_map=attendance_map,
        status_options=ATTENDANCE_STATUS_OPTIONS,
        status_counts=status_counts,
        summary=summary,
        total_students=total_students,
        attendance_min_date=(valid_date_list[0].isoformat() if valid_date_list else ''),
        attendance_max_date=(valid_date_list[-1].isoformat() if valid_date_list else ''),
        valid_attendance_dates=sorted(list(valid_iso_set)),
    )

@app.route('/teacher/behaviour-assessment', methods=['GET', 'POST'])
def teacher_behaviour_assessment():
    if session.get('role') != 'teacher':
        return redirect(url_for('login'))
    school_id = session.get('school_id')
    teacher_id = session.get('user_id')
    school = get_school(school_id) or {}
    current_term = get_current_term(school)
    current_year = (school or {}).get('academic_year', '')
    classname = (request.values.get('classname', '') or '').strip()
    if not classname:
        flash('Select a class for behaviour assessment.', 'error')
        return redirect(url_for('teacher_dashboard'))
    if not teacher_has_class_access(school_id, teacher_id, classname, term=current_term, academic_year=current_year):
        flash('You are not assigned to this class for the current term/year.', 'error')
        return redirect(url_for('teacher_dashboard'))

    class_students = load_students(school_id, class_filter=classname, term_filter=current_term)
    student_rows = sorted(
        [(sid, s) for sid, s in class_students.items()],
        key=lambda row: ((row[1].get('firstname', '') or '').lower(), (row[0] or '').lower()),
    )
    if not student_rows:
        flash(f'No students found in {classname} for {current_term}.', 'error')
        return redirect(url_for('teacher_dashboard'))
    existing = get_class_behaviour_assessments(school_id, classname, current_term, current_year)

    if request.method == 'POST':
        try:
            with db_connection(commit=True) as conn:
                c = conn.cursor()
                for sid, student in student_rows:
                    payload = {}
                    for trait in BEHAVIOUR_TRAITS:
                        key = f'{sid}__{trait}'
                        payload[trait] = (request.form.get(key, '') or '').strip().upper()
                    normalized = normalize_behaviour_assessment(payload)
                    if any((normalized.get(trait, '') or '').strip() not in BEHAVIOUR_GRADE_SCALE for trait in BEHAVIOUR_TRAITS):
                        flash(f'Behaviour grades are required for {student.get("firstname", sid)}.', 'error')
                        return redirect(url_for('teacher_behaviour_assessment', classname=classname))
                    save_behaviour_assessment_with_cursor(
                        c,
                        school_id=school_id,
                        student_id=sid,
                        classname=classname,
                        term=current_term,
                        academic_year=current_year,
                        behaviour_payload=normalized,
                        updated_by=teacher_id,
                    )
            flash(f'Behaviour assessment saved for {classname}.', 'success')
        except Exception as exc:
            flash(f'Failed to save behaviour assessment: {exc}', 'error')
        return redirect(url_for('teacher_behaviour_assessment', classname=classname))

    prepared_rows = []
    for sid, student in student_rows:
        prepared_rows.append({
            'student_id': sid,
            'firstname': student.get('firstname', ''),
            'stream': student.get('stream', ''),
            'assessment': existing.get(sid, _default_behaviour_assessment()),
        })
    return render_template(
        'teacher/teacher_behaviour_assessment.html',
        school=school,
        classname=classname,
        current_term=current_term,
        current_year=current_year,
        traits=BEHAVIOUR_TRAITS,
        grade_scale=BEHAVIOUR_GRADE_SCALE,
        student_rows=prepared_rows,
    )

@app.route('/teacher/update-profile', methods=['POST'])
def teacher_update_profile():
    if session.get('role') != 'teacher':
        return redirect(url_for('login'))
    school_id = session.get('school_id')
    teacher_id = session.get('user_id')
    phone = (request.form.get('phone', '') or '').strip()
    if phone and not re.fullmatch(r'^[0-9+\-\s()]{7,25}$', phone):
        flash('Invalid phone number format.', 'error')
        return redirect(url_for('teacher_dashboard'))
    with db_connection(commit=True) as conn:
        c = conn.cursor()
        db_execute(
            c,
            "UPDATE teachers SET phone = ? WHERE school_id = ? AND user_id = ?",
            (phone, school_id, teacher_id),
        )
    flash('Profile phone number updated successfully.', 'success')
    return redirect(url_for('teacher_dashboard'))

@app.route('/teacher/upload-signature', methods=['POST'])
def teacher_upload_signature():
    if session.get('role') != 'teacher':
        return redirect(url_for('login'))
    school_id = session.get('school_id')
    teacher_id = session.get('user_id')
    school = get_school(school_id) or {}
    current_term = get_current_term(school)
    current_year = (school or {}).get('academic_year', '')
    class_assignments = get_teacher_classes(
        school_id,
        teacher_id,
        term=current_term,
        academic_year=current_year,
    )
    if not class_assignments:
        flash('Teacher signature is only required for class teachers.', 'error')
        return redirect(url_for('teacher_dashboard'))
    signature_data, err = parse_uploaded_signature(request.files.get('teacher_signature'))
    if err:
        flash(err, 'error')
        return redirect(url_for('teacher_dashboard'))
    set_teacher_signature(school_id, teacher_id, signature_data)
    flash('Teacher signature saved successfully.', 'success')
    return redirect(url_for('teacher_dashboard'))

@app.route('/teacher/upload-profile-image', methods=['POST'])
def teacher_upload_profile_image():
    if session.get('role') != 'teacher':
        return redirect(url_for('login'))
    school_id = session.get('school_id')
    teacher_id = session.get('user_id')
    image_data, err = parse_uploaded_profile_image(request.files.get('profile_image'))
    if err:
        flash(err, 'error')
        return redirect(url_for('teacher_dashboard'))
    if not set_teacher_profile_image(school_id, teacher_id, image_data):
        flash('Profile picture column is not available in the database yet. Run DB fixes/startup DDL, then retry.', 'error')
        return redirect(url_for('teacher_dashboard'))
    flash('Profile picture saved successfully.', 'success')
    return redirect(url_for('teacher_dashboard'))

@app.route('/teacher/publish-results', methods=['POST'])
def teacher_publish_results():
    if session.get('role') != 'teacher':
        return redirect(url_for('login'))

    school_id = session.get('school_id')
    teacher_id = session.get('user_id')
    classname = request.form.get('classname', '').strip()
    if not classname:
        flash('Select a class to submit for approval.', 'error')
        return redirect(url_for('teacher_dashboard'))

    school = get_school(school_id)
    current_term = get_current_term(school)
    current_year = (school or {}).get('academic_year', '')
    if not teacher_has_class_access(school_id, teacher_id, classname, term=current_term, academic_year=current_year):
        flash('You are not assigned to this class for the current term/year.', 'error')
        return redirect(url_for('teacher_dashboard'))
    teacher_profile = get_teachers(school_id).get(teacher_id, {})
    if not (teacher_profile.get('signature_image') or '').strip():
        flash('Upload your class teacher signature before submitting this class result.', 'error')
        return redirect(url_for('teacher_dashboard'))
    if not ((school or {}).get('principal_signature_image') or '').strip():
        flash('Principal signature is required before approval. Ask school admin to upload it with admin password.', 'error')
        return redirect(url_for('teacher_dashboard'))
    if is_result_published(school_id, classname, current_term, current_year):
        flash(f'{classname} ({current_term}) is already published. Republish is not allowed.', 'error')
        return redirect(url_for('teacher_dashboard'))
    existing_pub = get_result_publication_row(school_id, classname, current_term, current_year)
    if (existing_pub.get('approval_status') or '') == 'pending':
        flash(f'{classname} ({current_term}) is already submitted and pending admin review.', 'error')
        return redirect(url_for('teacher_dashboard'))
    class_students = load_students(school_id, class_filter=classname, term_filter=current_term)
    student_list = list(class_students.values())
    if not student_list:
        flash(f'No students found in {classname}.', 'error')
        return redirect(url_for('teacher_dashboard'))

    subject_progress = compute_class_subject_completion(
        school_id=school_id,
        classname=classname,
        term=current_term,
        academic_year=current_year,
        school=school,
        class_students_data=class_students,
    )
    progress_rows = subject_progress.get('rows', []) if isinstance(subject_progress, dict) else []
    if progress_rows and not subject_progress.get('ready', False):
        pending_subjects = [
            row.get('subject', '')
            for row in progress_rows
            if int(row.get('pending_students', 0)) > 0
        ]
        if pending_subjects:
            flash(
                f'Cannot submit yet. Pending subject scores in {classname}: {", ".join(pending_subjects[:6])}'
                + ('...' if len(pending_subjects) > 6 else ''),
                'error',
            )
        else:
            flash(f'Cannot submit yet. Subject score entry is not complete for {classname}.', 'error')
        return redirect(url_for('teacher_dashboard'))

    incomplete = [s.get('firstname', '') for s in student_list if not is_student_score_complete(s, school, current_term)]
    if incomplete:
        flash(f'Cannot submit yet. Complete scores for all students in {classname} ({current_term}) first.', 'error')
        return redirect(url_for('teacher_dashboard'))

    behaviour_check = class_behaviour_completion(
        school_id=school_id,
        classname=classname,
        term=current_term,
        academic_year=current_year,
        student_ids=[sid for sid in class_students.keys()],
    )
    if not behaviour_check.get('ready', False):
        flash(
            f'Cannot submit yet. Complete Behaviour Assessment for all students in {classname}. '
            f'Pending: {int(behaviour_check.get("missing_count", 0) or 0)}.',
            'error',
        )
        return redirect(url_for('teacher_behaviour_assessment', classname=classname))

    attendance_gate = get_class_attendance_publish_readiness(
        school_id=school_id,
        classname=classname,
        term=current_term,
        academic_year=current_year,
        class_students_data=class_students,
    )
    if not attendance_gate.get('ready', False):
        gate_msg = (attendance_gate.get('message') or '').strip()
        if not gate_msg:
            rows = attendance_gate.get('missing_rows', []) or []
            sample = ', '.join(
                f"{r.get('student_name', r.get('student_id', ''))} ({int(r.get('marked_days', 0))}/{int(attendance_gate.get('days_open', 0))})"
                for r in rows[:6]
            )
            gate_msg = (
                f'Cannot submit yet. Attendance is incomplete for {classname}. '
                f'Each student needs {int(attendance_gate.get("days_open", 0))} marked days this term. '
                f'Missing: {sample}'
                + ('...' if len(rows) > 6 else '')
            )
        flash(gate_msg, 'error')
        return redirect(url_for('teacher_attendance', classname=classname))

    submit_result_approval_request(school_id, classname, current_term, current_year, teacher_id)
    flash(f'Results submitted for admin approval: {classname} ({current_term}).', 'success')
    return redirect(url_for('teacher_dashboard'))

@app.route('/teacher/submit-to-class-teacher', methods=['POST'])
def teacher_submit_to_class_teacher():
    if session.get('role') != 'teacher':
        return redirect(url_for('login'))
    school_id = session.get('school_id')
    teacher_id = session.get('user_id')
    classname = (request.form.get('classname', '') or '').strip()
    if not classname:
        flash('Class is required.', 'error')
        return redirect(url_for('teacher_dashboard'))
    school = get_school(school_id) or {}
    current_term = get_current_term(school)
    current_year = (school.get('academic_year', '') or '').strip()
    if teacher_has_class_access(school_id, teacher_id, classname, term=current_term, academic_year=current_year):
        flash('Class teachers submit directly to school admin. Subject handoff is not required for your own class.', 'error')
        return redirect(url_for('teacher_dashboard'))
    assigned_subjects = get_teacher_subjects_for_class_term(
        school_id,
        teacher_id,
        classname,
        term=current_term,
        academic_year=current_year,
    )
    if not assigned_subjects:
        flash('No subject assignment found for this class/term.', 'error')
        return redirect(url_for('teacher_dashboard'))
    class_students = load_students(school_id, class_filter=classname, term_filter=current_term)
    pending_entries = 0
    for _sid, st in class_students.items():
        offered_subjects = normalize_subjects_list(st.get('subjects', []))
        offered_map = {s.lower(): s for s in offered_subjects}
        for subject in assigned_subjects:
            subj_key = offered_map.get(subject.lower())
            if not subj_key:
                continue
            score_block = get_subject_score_block((st.get('scores') or {}), subj_key)
            if not is_score_complete_for_subject(score_block, school):
                pending_entries += 1
    if pending_entries > 0:
        flash(f'Cannot submit yet. {pending_entries} pending subject score entries remain in {classname}.', 'error')
        return redirect(url_for('teacher_dashboard'))
    existing_map = get_subject_score_submission_map(school_id, teacher_id, current_term, current_year)
    if existing_map.get(classname):
        flash(f'{classname} is already submitted to class teacher. Edit scores first to submit again.', 'info')
        return redirect(url_for('teacher_dashboard'))
    if not mark_subject_score_submitted(school_id, teacher_id, classname, current_term, current_year):
        flash('Failed to save submission status. Ensure database schema is up to date.', 'error')
        return redirect(url_for('teacher_dashboard'))
    flash(f'Subject scores submitted to class teacher for {classname} ({current_term}).', 'success')
    return redirect(url_for('teacher_dashboard'))

@app.route('/school-admin/approve-results', methods=['POST'])
def school_admin_approve_results():
    if session.get('role') != 'school_admin':
        return redirect(url_for('login'))
    school_id = session.get('school_id')
    admin_user_id = session.get('user_id')
    classname = request.form.get('classname', '').strip()
    term = (request.form.get('term', '') or '').strip()
    academic_year = (request.form.get('academic_year', '') or '').strip()
    if not classname:
        flash('Class is required.', 'error')
        return redirect(url_for('school_admin_publish_results'))
    school = get_school(school_id) or {}
    current_term = term or get_current_term(school)
    current_year = academic_year or school.get('academic_year', '')
    review_note = (request.form.get('review_note', '') or '').strip()
    ok = False
    message = 'Approval failed.'
    for attempt in range(2):
        try:
            ok, message = review_result_approval_request(
                school_id=school_id,
                classname=classname,
                term=current_term,
                academic_year=current_year,
                admin_user_id=admin_user_id,
                approve=True,
                review_note=review_note,
            )
            break
        except Exception as exc:
            transient = _is_transient_db_transport_error(exc)
            if transient and attempt == 0:
                logging.warning(
                    "Transient DB error during approve (retrying once). school_id=%s class=%s term=%s year=%s err=%s",
                    school_id,
                    classname,
                    current_term,
                    current_year,
                    exc,
                )
                time.sleep(0.2)
                continue
            logging.exception(
                "Unhandled error while approving results. school_id=%s class=%s term=%s year=%s admin=%s",
                school_id,
                classname,
                current_term,
                current_year,
                admin_user_id,
            )
            ok, message = False, f'Approval failed due to a server error: {exc}'
            break
    flash(message, 'success' if ok else 'error')
    return redirect(url_for('school_admin_publish_results'))

@app.route('/school-admin/reject-results', methods=['POST'])
def school_admin_reject_results():
    if session.get('role') != 'school_admin':
        return redirect(url_for('login'))
    school_id = session.get('school_id')
    admin_user_id = session.get('user_id')
    classname = request.form.get('classname', '').strip()
    term = (request.form.get('term', '') or '').strip()
    academic_year = (request.form.get('academic_year', '') or '').strip()
    if not classname:
        flash('Class is required.', 'error')
        return redirect(url_for('school_admin_publish_results'))
    school = get_school(school_id) or {}
    current_term = term or get_current_term(school)
    current_year = academic_year or school.get('academic_year', '')
    review_note = (request.form.get('review_note', '') or '').strip()
    if not review_note:
        flash('Rejection reason is required.', 'error')
        return redirect(url_for('school_admin_publish_results'))
    ok = False
    message = 'Rejection failed.'
    for attempt in range(2):
        try:
            ok, message = review_result_approval_request(
                school_id=school_id,
                classname=classname,
                term=current_term,
                academic_year=current_year,
                admin_user_id=admin_user_id,
                approve=False,
                review_note=review_note,
            )
            break
        except Exception as exc:
            transient = _is_transient_db_transport_error(exc)
            if transient and attempt == 0:
                logging.warning(
                    "Transient DB error during reject (retrying once). school_id=%s class=%s term=%s year=%s err=%s",
                    school_id,
                    classname,
                    current_term,
                    current_year,
                    exc,
                )
                time.sleep(0.2)
                continue
            logging.exception(
                "Unhandled error while rejecting results. school_id=%s class=%s term=%s year=%s admin=%s",
                school_id,
                classname,
                current_term,
                current_year,
                admin_user_id,
            )
            ok, message = False, f'Rejection failed due to a server error: {exc}'
            break
    flash(message, 'success' if ok else 'error')
    return redirect(url_for('school_admin_publish_results'))

@app.route('/school-admin/unlock-term-edit', methods=['POST'])
def school_admin_unlock_term_edit():
    if session.get('role') != 'school_admin':
        return redirect(url_for('login'))
    school_id = session.get('school_id')
    admin_user_id = session.get('user_id')
    classname = (request.form.get('classname', '') or '').strip()
    term = (request.form.get('term', '') or '').strip()
    academic_year = (request.form.get('academic_year', '') or '').strip()
    reason = (request.form.get('unlock_reason', '') or '').strip()
    try:
        minutes = max(5, min(240, int(request.form.get('unlock_minutes', 30) or 30)))
    except Exception:
        minutes = 30
    if not classname or not term:
        flash('Class and term are required.', 'error')
        return redirect(url_for('school_admin_publish_results'))
    if not reason:
        flash('Unlock reason is required.', 'error')
        return redirect(url_for('school_admin_publish_results'))
    if not is_result_published(school_id, classname, term, academic_year):
        flash('This class-term is not published, so lock override is not needed.', 'info')
        return redirect(url_for('school_admin_publish_results'))
    set_term_edit_lock(
        school_id=school_id,
        classname=classname,
        term=term,
        academic_year=academic_year,
        is_locked=False,
        unlocked_minutes=minutes,
        unlock_reason=reason,
        unlocked_by=admin_user_id,
    )
    flash(f'Edit lock unlocked for {classname} ({term}) for {minutes} minute(s).', 'success')
    return redirect(url_for('school_admin_publish_results'))

@app.route('/school-admin/relock-term-edit', methods=['POST'])
def school_admin_relock_term_edit():
    if session.get('role') != 'school_admin':
        return redirect(url_for('login'))
    school_id = session.get('school_id')
    admin_user_id = session.get('user_id')
    classname = (request.form.get('classname', '') or '').strip()
    term = (request.form.get('term', '') or '').strip()
    academic_year = (request.form.get('academic_year', '') or '').strip()
    if not classname or not term:
        flash('Class and term are required.', 'error')
        return redirect(url_for('school_admin_publish_results'))
    set_term_edit_lock(
        school_id=school_id,
        classname=classname,
        term=term,
        academic_year=academic_year,
        is_locked=True,
        unlocked_minutes=0,
        unlock_reason='',
        unlocked_by=admin_user_id,
    )
    flash(f'Edit lock restored for {classname} ({term}).', 'success')
    return redirect(url_for('school_admin_publish_results'))

@app.route('/school-admin/reset-class-student-passwords', methods=['POST'])
def school_admin_reset_class_student_passwords():
    if session.get('role') != 'school_admin':
        return redirect(url_for('login'))
    school_id = session.get('school_id')
    admin_user_id = session.get('user_id')
    classname = (request.form.get('classname', '') or '').strip()
    if not classname:
        flash('Class is required for password reset.', 'error')
        return redirect(request.referrer or url_for('school_admin_add_students_by_class'))
    result = reset_student_passwords_for_class(
        school_id=school_id,
        classname=classname,
        default_password=DEFAULT_STUDENT_PASSWORD,
        reset_by=admin_user_id,
    )
    flash(
        f'Class password reset completed for {classname}: reset={result.get("touched", 0)}, skipped={result.get("skipped", 0)}.',
        'success' if int(result.get('touched', 0)) > 0 else 'info',
    )
    return redirect(request.referrer or url_for('school_admin_add_students_by_class', **{'class': classname}))

@app.route('/school-admin/student/archive', methods=['POST'])
def school_admin_archive_student():
    if session.get('role') != 'school_admin':
        return redirect(url_for('login'))
    school_id = session.get('school_id')
    student_id = (request.form.get('student_id', '') or '').strip()
    if not student_id:
        flash('Student ID is required.', 'error')
        return redirect(request.referrer or url_for('school_admin_add_students_by_class'))
    archive_student_account(school_id, student_id, archived_by=session.get('user_id', '') or '')
    flash(f'Student {student_id} archived.', 'success')
    return redirect(request.referrer or url_for('school_admin_add_students_by_class'))

@app.route('/school-admin/student/restore', methods=['POST'])
def school_admin_restore_student():
    if session.get('role') != 'school_admin':
        return redirect(url_for('login'))
    school_id = session.get('school_id')
    student_id = (request.form.get('student_id', '') or '').strip()
    if not student_id:
        flash('Student ID is required.', 'error')
        return redirect(request.referrer or url_for('school_admin_add_students_by_class'))
    restore_student_account(school_id, student_id, restored_by=session.get('user_id', '') or '')
    flash(f'Student {student_id} restored.', 'success')
    return redirect(request.referrer or url_for('school_admin_add_students_by_class'))

@app.route('/school-admin/teacher/archive', methods=['POST'])
def school_admin_archive_teacher():
    if session.get('role') != 'school_admin':
        return redirect(url_for('login'))
    school_id = session.get('school_id')
    teacher_id = (request.form.get('teacher_id', '') or '').strip().lower()
    if not teacher_id:
        flash('Teacher ID is required.', 'error')
        return redirect(request.referrer or url_for('school_admin_dashboard'))
    archive_teacher_account(school_id, teacher_id, archived_by=session.get('user_id', '') or '')
    flash(f'Teacher {teacher_id} archived.', 'success')
    return redirect(request.referrer or url_for('school_admin_dashboard'))

@app.route('/school-admin/teacher/restore', methods=['POST'])
def school_admin_restore_teacher():
    if session.get('role') != 'school_admin':
        return redirect(url_for('login'))
    school_id = session.get('school_id')
    teacher_id = (request.form.get('teacher_id', '') or '').strip().lower()
    if not teacher_id:
        flash('Teacher ID is required.', 'error')
        return redirect(request.referrer or url_for('school_admin_dashboard'))
    restore_teacher_account(school_id, teacher_id, restored_by=session.get('user_id', '') or '')
    flash(f'Teacher {teacher_id} restored.', 'success')
    return redirect(request.referrer or url_for('school_admin_dashboard'))

@app.route('/teacher/allocate-stream', methods=['GET', 'POST'])
def teacher_allocate_stream():
    if session.get('role') != 'teacher':
        return redirect(url_for('login'))

    school_id = session.get('school_id')
    teacher_id = session.get('user_id')
    school = get_school(school_id) or {}
    current_term = get_current_term(school)
    current_year = school.get('academic_year', '')
    student_id = request.args.get('student_id', '').strip() if request.method == 'GET' else request.form.get('student_id', '').strip()
    if not student_id:
        flash('Student not selected.', 'error')
        return redirect(url_for('teacher_dashboard'))

    student = load_student(school_id, student_id)
    if not student:
        flash('Student not found.', 'error')
        return redirect(url_for('teacher_dashboard'))
    classname = student.get('classname', '')
    if not teacher_has_class_access(school_id, teacher_id, classname, term=current_term, academic_year=current_year):
        flash('You are not assigned to this class.', 'error')
        return redirect(url_for('teacher_dashboard'))
    if not class_uses_stream_for_school(school, classname):
        flash('This class does not use stream allocation.', 'error')
        return redirect(url_for('teacher_dashboard'))

    config = get_class_subject_config(school_id, classname)
    if not config:
        flash('No class subject configuration found for this class.', 'error')
        return redirect(url_for('teacher_dashboard'))

    if request.method == 'POST':
        previous_stream = (student.get('stream') or '').strip()
        stream = request.form.get('stream', '').strip()
        selected_optional_subjects = request.form.getlist('optional_subjects')
        subjects, final_stream, subject_error = build_subjects_from_config(
            classname=classname,
            stream=stream,
            config=config,
            selected_optional_subjects=selected_optional_subjects,
            school=school
        )
        if subject_error:
            flash(subject_error, 'error')
            return redirect(url_for('teacher_allocate_stream', student_id=student_id))

        # Keep only scores for currently selected subjects to maintain consistency.
        existing_scores = student.get('scores', {}) if isinstance(student.get('scores', {}), dict) else {}
        dropped = [subj for subj in existing_scores.keys() if subj not in subjects]
        if dropped:
            flash('Some previous subject scores were removed due to stream/optional changes.', 'info')
        student['scores'] = {subj: existing_scores[subj] for subj in existing_scores.keys() if subj in subjects}
        student['stream'] = final_stream
        student['subjects'] = subjects
        student['number_of_subject'] = len(subjects)
        save_student(school_id, student_id, student)
        if previous_stream in ('', 'N/A'):
            flash(f'Stream allocated for {student.get("firstname", "")}.', 'success')
        elif previous_stream != final_stream:
            flash(f'Stream changed from {previous_stream} to {final_stream} for {student.get("firstname", "")}.', 'success')
        else:
            flash(f'Stream details updated for {student.get("firstname", "")}.', 'success')
        return redirect(url_for('teacher_dashboard'))

    selected_optional_subjects = set(
        s for s in (student.get('subjects') or [])
        if s in (config.get('optional_subjects') or [])
    )
    return render_template(
        'teacher/teacher_allocate_stream.html',
        student=student,
        config=config,
        selected_optional_subjects=selected_optional_subjects,
    )

@app.route('/teacher/enter-scores', methods=['GET', 'POST'])
def teacher_enter_scores():
    if session.get('role') != 'teacher':
        return redirect(url_for('login'))
    
    school_id = session.get('school_id')
    teacher_id = session.get('user_id')
    school = get_school(school_id)
    current_term = get_current_term(school)
    current_year = (school or {}).get('academic_year', '')
    student_id = request.args.get('student_id')
    requested_subject = normalize_subject_name((request.args.get('subject', '') or '').strip())
    
    if not student_id:
        flash('No student selected.', 'error')
        return redirect(url_for('teacher_dashboard'))
    
    student = load_student(school_id, student_id)
    if not student:
        flash('Student not found.', 'error')
        return redirect(url_for('teacher_dashboard'))
    class_name = student.get('classname', '')
    class_access = teacher_has_class_access(school_id, teacher_id, class_name, term=current_term, academic_year=current_year)
    subject_access = bool(get_teacher_subjects_for_class_term(
        school_id, teacher_id, class_name, term=current_term, academic_year=current_year
    ))
    if not class_access and not subject_access:
        flash('You are not assigned to this student class/subjects.', 'error')
        return redirect(url_for('teacher_dashboard'))
    if class_uses_stream_for_school(school, student.get('classname', '')) and student.get('stream') in ('', 'N/A', None):
        flash('Allocate stream for this SS student before entering scores.', 'error')
        return redirect(url_for('teacher_allocate_stream', student_id=student_id))

    # Keep subject list aligned with current class config (important for SS1 combined mode).
    synced, sync_error = sync_student_subjects_to_class_config(student, school_id, school=school)
    if sync_error:
        flash(sync_error, 'error')
        return redirect(url_for('teacher_dashboard'))
    if synced:
        save_student(school_id, student_id, student)

    grade_cfg = get_grade_config(school_id)
    if student.get('term') != current_term:
        # New term starts with empty score entry for this student.
        student['scores'] = {}
    is_locked = is_result_published(school_id, student.get('classname', ''), current_term, current_year)
    exam_config = get_assessment_config_for_class(school_id, student.get('classname', ''))
    all_subjects = sorted(student.get('subjects', []), key=lambda x: str(x).lower())
    assigned_subjects = get_teacher_subjects_for_class_term(
        school_id,
        teacher_id,
        student.get('classname', ''),
        term=current_term,
        academic_year=current_year,
    )
    assigned_subjects_set = {s.lower() for s in assigned_subjects}
    can_edit_teacher_comment = bool(class_access)
    locked_subjects_for_class = []
    if class_access:
        class_subject_assignments = get_teacher_subject_assignments(
            school_id,
            classname=class_name,
            term=current_term,
            academic_year=current_year,
        )
        submitted_teacher_ids = get_subject_submission_teacher_ids_for_class(
            school_id,
            class_name,
            current_term,
            current_year,
        )
        protected_subjects = set()
        for row in class_subject_assignments:
            assigned_teacher = (row.get('teacher_id') or '').strip()
            subject_name = normalize_subject_name(row.get('subject', ''))
            if not subject_name:
                continue
            if assigned_teacher and assigned_teacher != teacher_id and assigned_teacher not in submitted_teacher_ids:
                protected_subjects.add(subject_name)
        locked_subjects_for_class = sorted(protected_subjects, key=lambda x: str(x).lower())
    locked_subjects_set = {s.lower() for s in locked_subjects_for_class}
    if class_access:
        editable_subjects = [s for s in all_subjects if s.lower() not in locked_subjects_set]
    else:
        editable_subjects = [s for s in all_subjects if s.lower() in assigned_subjects_set]
    if requested_subject:
        if requested_subject not in all_subjects:
            flash(f'Subject "{requested_subject}" is not offered by this student.', 'error')
            return redirect(url_for('teacher_dashboard'))
        if not class_access and requested_subject.lower() not in assigned_subjects_set:
            flash(f'You are not assigned to score {requested_subject}.', 'error')
            return redirect(url_for('teacher_dashboard'))
        if class_access and requested_subject.lower() in locked_subjects_set:
            editable_subjects = []
            flash(
                f'{requested_subject} is locked until the assigned subject teacher submits scores to class teacher.',
                'info',
            )
        subjects = [requested_subject]
        if editable_subjects:
            editable_subjects = [requested_subject]
    else:
        # Subject-only teachers should only see their assigned subject rows.
        subjects = list(all_subjects) if class_access else list(editable_subjects)
    if not editable_subjects and not class_access:
        flash('No class-term subject assignment found for this student. Contact school admin.', 'error')
        return redirect(url_for('teacher_dashboard'))
    subject_key_map = build_subject_key_map(subjects)
    subject_last_edits = get_latest_score_audit_map_for_student(
        school_id=school_id,
        student_id=student_id,
        term=current_term,
        academic_year=current_year or '',
    )
    teacher_name_map = {}
    for tid, trow in (get_teachers(school_id) or {}).items():
        full_name = f"{trow.get('firstname', '')} {trow.get('lastname', '')}".strip()
        teacher_name_map[tid] = full_name or tid
    
    if request.method == 'POST':
        if is_locked:
            flash(f'Scores for {student.get("classname", "")} ({current_term}) are already published and locked.', 'error')
            return redirect(url_for('teacher_dashboard'))
        if class_access and not editable_subjects:
            flash('Score editing is locked for this student until subject teachers submit their assigned subjects.', 'error')
            return redirect(url_for('teacher_dashboard'))
        redirect_kwargs = {'student_id': student_id}
        if requested_subject:
            redirect_kwargs['subject'] = requested_subject
        existing_scores = student.get('scores', {}) if isinstance(student.get('scores', {}), dict) else {}
        previous_scores_for_audit = {
            subj: (dict(vals) if isinstance(vals, dict) else {})
            for subj, vals in existing_scores.items()
        }
        scores = dict(existing_scores)
        score_override_reason = (request.form.get('score_override_reason', '') or '').strip()
        if can_edit_teacher_comment:
            teacher_comment = (request.form.get('teacher_comment', '') or '').strip()[:1500]
        else:
            teacher_comment = (student.get('teacher_comment', '') or '').strip()
        max_tests = max(1, min(safe_int(school.get('max_tests', 3), 3), 10))
        test_total_max = max(0.0, safe_float(school.get('test_score_max', 30), 30))
        for subject in editable_subjects:
            subj_key = subject_key_map.get(subject, '')
            subject_scores = {}
            subject_comment = (request.form.get(f'subject_comment_{subj_key}', '') or '').strip()[:300]
            
            # Test scores (based on school settings)
            if school.get('test_enabled', 1):
                for i in range(1, max_tests + 1):
                    raw_val = request.form.get(f'test_{i}_{subj_key}', 0)
                    try:
                        test_val = float(raw_val)
                    except (TypeError, ValueError):
                        flash(f'Invalid Test {i} score for {subject}.', 'error')
                        return redirect(url_for('teacher_enter_scores', **redirect_kwargs))
                    if not math.isfinite(test_val):
                        flash(f'Invalid Test {i} score for {subject}.', 'error')
                        return redirect(url_for('teacher_enter_scores', **redirect_kwargs))
                    if test_val < 0 or test_val > test_total_max:
                        flash(f'Test {i} score for {subject} must be between 0 and {test_total_max:g}.', 'error')
                        return redirect(url_for('teacher_enter_scores', **redirect_kwargs))
                    subject_scores[f'test_{i}'] = test_val
                subject_scores['total_test'] = sum(subject_scores.get(f'test_{i}', 0) for i in range(1, max_tests + 1))
                if subject_scores['total_test'] > test_total_max:
                    flash(f'Total test score for {subject} must not exceed {test_total_max:g}.', 'error')
                    return redirect(url_for('teacher_enter_scores', **redirect_kwargs))
            else:
                subject_scores['total_test'] = 0
            
            # Exam scores (based on school settings)
            if school.get('exam_enabled', 1):
                if exam_config.get('exam_mode') == 'combined':
                    exam_score_raw = request.form.get(f'exam_score_{subj_key}', 0)
                    try:
                        exam_score = float(exam_score_raw)
                    except (TypeError, ValueError):
                        flash(f'Invalid exam score for {subject}.', 'error')
                        return redirect(url_for('teacher_enter_scores', **redirect_kwargs))
                    if not math.isfinite(exam_score):
                        flash(f'Invalid exam score for {subject}.', 'error')
                        return redirect(url_for('teacher_enter_scores', **redirect_kwargs))
                    exam_max = max(0.0, safe_float(exam_config.get('exam_score_max', 70), 70))
                    if exam_score < 0 or exam_score > exam_max:
                        flash(f'Exam score for {subject} must be between 0 and {exam_max:g}.', 'error')
                        return redirect(url_for('teacher_enter_scores', **redirect_kwargs))
                    subject_scores['objective'] = 0
                    subject_scores['theory'] = 0
                    subject_scores['exam_score'] = exam_score
                    subject_scores['total_exam'] = exam_score
                    subject_scores['exam_mode'] = 'combined'
                else:
                    objective_raw = request.form.get(f'objective_{subj_key}', 0)
                    theory_raw = request.form.get(f'theory_{subj_key}', 0)
                    try:
                        objective = float(objective_raw)
                        theory = float(theory_raw)
                    except (TypeError, ValueError):
                        flash(f'Invalid objective/theory score for {subject}.', 'error')
                        return redirect(url_for('teacher_enter_scores', **redirect_kwargs))
                    if not math.isfinite(objective) or not math.isfinite(theory):
                        flash(f'Invalid objective/theory score for {subject}.', 'error')
                        return redirect(url_for('teacher_enter_scores', **redirect_kwargs))
                    objective_max = max(0.0, safe_float(exam_config.get('objective_max', 30), 30))
                    theory_max = max(0.0, safe_float(exam_config.get('theory_max', 40), 40))
                    exam_total_max = max(0.0, safe_float(exam_config.get('exam_score_max', objective_max + theory_max), objective_max + theory_max))
                    if objective < 0 or objective > objective_max:
                        flash(f'Objective score for {subject} must be between 0 and {objective_max:g}.', 'error')
                        return redirect(url_for('teacher_enter_scores', **redirect_kwargs))
                    if theory < 0 or theory > theory_max:
                        flash(f'Theory score for {subject} must be between 0 and {theory_max:g}.', 'error')
                        return redirect(url_for('teacher_enter_scores', **redirect_kwargs))
                    subject_scores['objective'] = objective
                    subject_scores['theory'] = theory
                    subject_scores['total_exam'] = subject_scores.get('objective', 0) + subject_scores.get('theory', 0)
                    if subject_scores['total_exam'] > exam_total_max:
                        flash(f'Total exam score for {subject} must not exceed {exam_total_max:g}.', 'error')
                        return redirect(url_for('teacher_enter_scores', **redirect_kwargs))
                    subject_scores['exam_mode'] = 'separate'
            else:
                subject_scores['total_exam'] = 0
            
            # Calculate overall
            subject_scores['overall_mark'] = subject_overall_mark(subject_scores)
            if subject_scores['overall_mark'] > 100:
                flash(
                    f'Total score for {subject} exceeds 100. '
                    'Reduce scores or adjust school test/exam maxima.',
                    'error',
                )
                return redirect(url_for('teacher_enter_scores', **redirect_kwargs))
            subject_scores['total_score'] = subject_scores['overall_mark']
            
            # Grade
            overall = subject_scores['overall_mark']
            subject_scores['grade'] = grade_from_score(overall, grade_cfg)
            subject_scores['subject_teacher_comment'] = subject_comment
            
            scores[subject] = subject_scores

        override_subjects = []
        if class_access:
            score_fields = [f'test_{i}' for i in range(1, max_tests + 1)] + ['objective', 'theory', 'exam_score']
            for subject in editable_subjects:
                old_block = previous_scores_for_audit.get(subject, {}) if isinstance(previous_scores_for_audit.get(subject, {}), dict) else {}
                new_block = scores.get(subject, {}) if isinstance(scores.get(subject, {}), dict) else {}
                score_changed = any(safe_float(old_block.get(f, 0), 0) != safe_float(new_block.get(f, 0), 0) for f in score_fields)
                if not score_changed:
                    continue
                last_edit = subject_last_edits.get(subject, {}) if isinstance(subject_last_edits.get(subject, {}), dict) else {}
                last_changed_by = (last_edit.get('changed_by', '') or '').strip()
                last_role = (last_edit.get('changed_by_role', '') or '').strip().lower()
                if last_role == 'teacher' and last_changed_by and last_changed_by != teacher_id:
                    override_subjects.append(subject)

        if override_subjects and not score_override_reason:
            listed = ', '.join(override_subjects[:3])
            suffix = '...' if len(override_subjects) > 3 else ''
            flash(
                f'Provide reason before changing score(s) entered by subject teacher: {listed}{suffix}.',
                'error',
            )
            return redirect(url_for('teacher_enter_scores', **redirect_kwargs))

        student['teacher_comment'] = teacher_comment
        student['term'] = current_term
        audit_change_source = 'manual_entry'
        audit_change_reason = ''
        if override_subjects:
            compact_reason = re.sub(r'\s+', ' ', score_override_reason).strip()
            compact_reason = compact_reason[:180]
            audit_change_source = f'class_teacher_override: {compact_reason}'
            audit_change_reason = compact_reason
        with db_connection(commit=True) as conn:
            c = conn.cursor()
            db_execute(
                c,
                "SELECT term, scores FROM students WHERE school_id = ? AND student_id = ? LIMIT 1",
                (school_id, student_id),
            )
            persisted_row = c.fetchone()
            persisted_term = ''
            persisted_scores = {}
            if persisted_row:
                persisted_term = (persisted_row[0] or '').strip() if len(persisted_row) > 1 else ''
                raw_scores = persisted_row[1] if len(persisted_row) > 1 else persisted_row[0]
                if isinstance(raw_scores, dict):
                    persisted_scores = raw_scores
                elif isinstance(raw_scores, str):
                    try:
                        loaded_scores = json.loads(raw_scores)
                        if isinstance(loaded_scores, dict):
                            persisted_scores = loaded_scores
                    except Exception:
                        persisted_scores = {}
            if not isinstance(persisted_scores, dict):
                persisted_scores = {}
            same_term_persisted = persisted_term == (current_term or '').strip()
            base_scores = persisted_scores if same_term_persisted else {}
            merged_scores = dict(base_scores)
            for subject in editable_subjects:
                merged_scores[subject] = scores.get(subject, {})
            student['scores'] = merged_scores
            save_student_with_cursor(c, school_id, student_id, student)
            audit_student_score_changes_with_cursor(
                c=c,
                school_id=school_id,
                student_id=student_id,
                classname=student.get('classname', ''),
                term=current_term,
                academic_year=current_year or '',
                old_scores=base_scores or previous_scores_for_audit,
                new_scores=merged_scores,
                changed_by=teacher_id,
                changed_by_role='teacher',
                change_source=audit_change_source,
                change_reason=audit_change_reason,
                subjects_scope=editable_subjects,
            )
        if not class_access:
            clear_subject_score_submission(
                school_id=school_id,
                teacher_id=teacher_id,
                classname=student.get('classname', ''),
                term=current_term,
                academic_year=current_year,
            )
        # Any edit requires re-publish for this class/term.
        class_name = (student.get('classname', '') or '').strip()
        set_result_published(school_id, class_name, current_term, current_year, teacher_id, False)
        flash('Scores saved successfully!', 'success')
        if not class_access:
            assigned_subjects_for_class = get_teacher_subjects_for_class_term(
                school_id,
                teacher_id,
                class_name,
                term=current_term,
                academic_year=current_year,
            )
            class_students_now = load_students(school_id, class_filter=class_name, term_filter=current_term)
            pending_by_subject = []
            for subj in assigned_subjects_for_class:
                eligible = 0
                completed = 0
                target = (subj or '').strip().lower()
                for _sid, st_now in class_students_now.items():
                    offered = normalize_subjects_list(st_now.get('subjects', []))
                    offered_map = {x.lower(): x for x in offered}
                    offered_key = offered_map.get(target, '')
                    if not offered_key:
                        continue
                    eligible += 1
                    score_block = get_subject_score_block((st_now.get('scores') or {}), offered_key)
                    if is_score_complete_for_subject(score_block, school):
                        completed += 1
                pending = max(0, eligible - completed)
                if pending > 0:
                    pending_by_subject.append(f'{subj}: {pending}')
            if pending_by_subject:
                flash(
                    'Still pending for your assigned subjects in '
                    f'{class_name}: ' + ', '.join(pending_by_subject[:5]) + ('...' if len(pending_by_subject) > 5 else ''),
                    'info',
                )
        return redirect(url_for('teacher_enter_scores', **redirect_kwargs))
    
    return render_template('teacher/teacher_enter_scores.html', 
                         student=student, 
                         subjects=subjects,
                         editable_subjects=editable_subjects,
                         subject_last_edits=subject_last_edits,
                         teacher_name_map=teacher_name_map,
                         school=school,
                         current_term=current_term,
                         is_locked=is_locked,
                         can_edit_teacher_comment=can_edit_teacher_comment,
                         locked_subjects_for_class=locked_subjects_for_class,
                         subject_key_map=subject_key_map,
                         exam_config=exam_config,
                         grade_cfg=grade_cfg)

@app.route('/teacher/enter-subject-scores', methods=['GET', 'POST'])
def teacher_enter_subject_scores():
    """Subject-specific score entry page for teachers."""
    return teacher_enter_scores()

@app.route('/teacher/upload-csv', methods=['GET', 'POST'])
def teacher_upload_csv():
    if session.get('role') != 'teacher':
        return redirect(url_for('login'))
    
    school_id = session.get('school_id')
    teacher_id = session.get('user_id')
    school = get_school(school_id) or {}
    current_term = get_current_term(school)
    current_year = school.get('academic_year', '')
    allowed_classes = set(get_teacher_classes(school_id, teacher_id, term=current_term, academic_year=current_year))
    subject_rows = get_teacher_subject_assignments(
        school_id,
        teacher_id=teacher_id,
        term=current_term,
        academic_year=current_year,
    )
    allowed_classes.update({r.get('classname', '') for r in subject_rows if r.get('classname', '')})
    allowed_classes_normalized = {(c or '').strip().lower() for c in allowed_classes if (c or '').strip()}

    exam_mode_view = 'none'
    if school.get('exam_enabled', 1):
        class_exam_modes = set()
        for cls in allowed_classes:
            class_exam_modes.add((get_assessment_config_for_class(school_id, cls).get('exam_mode') or 'separate').lower())
        if class_exam_modes == {'combined'}:
            exam_mode_view = 'combined'
        elif class_exam_modes and class_exam_modes <= {'separate'}:
            exam_mode_view = 'separate'
        elif class_exam_modes:
            exam_mode_view = 'mixed'
        else:
            exam_mode_view = 'separate'

    if request.method == 'POST':
        csv_result = {
            'success': False,
            'message': '',
            'total_rows': 0,
            'processed_rows': 0,
            'updated_students': 0,
            'updated_classes': 0,
            'error_token': '',
        }
        rows = []
        headers = {}
        fieldnames = []
        current_row_num = 0
        current_row_data = None
        processed_rows = 0

        def parse_csv_float(raw_value, row_num, field_label):
            try:
                value = float(raw_value)
            except (TypeError, ValueError):
                raise ValueError(f'Row {row_num}: {field_label} must be a number.')
            if not math.isfinite(value):
                raise ValueError(f'Row {row_num}: {field_label} is invalid.')
            return value
        try:
            file = request.files.get('file')
            if not file or not (file.filename or '').lower().endswith('.csv'):
                raise ValueError('Please upload a valid CSV file (.csv).')

            csv_content = file.read().decode('utf-8-sig')
            reader = csv.DictReader(StringIO(csv_content))
            if not reader.fieldnames:
                raise ValueError('CSV is empty or has no header row.')
            rows = list(reader)
            fieldnames = [h for h in (reader.fieldnames or []) if h]
            csv_result['total_rows'] = len(rows)
            headers = {h.strip().lower(): h for h in reader.fieldnames if h}
            has_exam_col = 'exam score' in headers
            has_obj_col = 'objective' in headers
            has_theory_col = 'theory' in headers

            score_mode = ('student id' in headers) and ('subject' in headers)
            grade_cfg = get_grade_config(school_id)
            if not score_mode:
                raise ValueError('CSV must include "Student ID" and "Subject" columns.')

            updated_students = set()
            staged_students = {}
            staged_original_scores = {}
            staged_changed_subjects = {}
            touched_classes = set()
            for idx, row in enumerate(rows, start=2):
                current_row_num = idx
                current_row_data = row
                student_id = (row.get(headers['student id'], '') or '').strip()
                raw_subject = (row.get(headers['subject'], '') or '').strip()
                subject = normalize_subject_name(raw_subject)
                if not student_id or not subject:
                    continue
                processed_rows += 1

                student = staged_students.get(student_id)
                if not student:
                    student = load_student(school_id, student_id)
                if not student:
                    raise ValueError(f'Row {idx}: student "{student_id}" not found.')
                if student_id not in staged_original_scores:
                    current_scores = student.get('scores', {}) if isinstance(student.get('scores', {}), dict) else {}
                    staged_original_scores[student_id] = {
                        subj: (dict(vals) if isinstance(vals, dict) else {})
                        for subj, vals in current_scores.items()
                    }
                classname = (student.get('classname') or '').strip()
                if classname.lower() not in allowed_classes_normalized:
                    raise ValueError(f'Row {idx}: class "{classname}" for {student_id} is not assigned to you.')
                if is_result_published(school_id, classname, current_term, current_year):
                    raise ValueError(f'Row {idx}: {classname} ({current_term}) is already published and locked.')

                subject_map = {str(s).strip().lower(): s for s in (student.get('subjects') or [])}
                if subject.lower() not in subject_map:
                    raise ValueError(f'Row {idx}: subject "{subject}" is not in {student_id} subject list.')
                subject_key = subject_map[subject.lower()]
                if not teacher_can_score_subject(
                    school_id,
                    teacher_id,
                    classname,
                    subject_key,
                    term=current_term,
                    academic_year=current_year,
                ):
                    raise ValueError(
                        f'Row {idx}: subject "{subject_key}" is not assigned to you for {classname} ({current_term}).'
                    )

                if student.get('term') != current_term:
                    student['scores'] = {}
                    student['term'] = current_term

                exam_config = get_assessment_config_for_class(school_id, classname)
                max_tests = max(1, min(safe_int(school.get('max_tests', 3), 3), 10))
                test_total_max = max(0.0, safe_float(school.get('test_score_max', 30), 30))
                existing_scores = student.get('scores', {}) if isinstance(student.get('scores', {}), dict) else {}
                subject_scores = existing_scores.get(subject_key, {}) if isinstance(existing_scores.get(subject_key, {}), dict) else {}
                subject_scores.pop('overall_mark', None)
                subject_scores.pop('total_score', None)
                subject_scores.pop('grade', None)

                if school.get('test_enabled', 1):
                    for i in range(1, max_tests + 1):
                        test_col = headers.get(f'test {i}')
                        raw_test = (row.get(test_col, '') if test_col else '')
                        test_val = float(subject_scores.get(f'test_{i}', 0) or 0) if str(raw_test).strip() == '' else parse_csv_float(raw_test, idx, f'Test {i} for {student_id} {subject_key}')
                        if test_val < 0 or test_val > test_total_max:
                            raise ValueError(f'Row {idx}: Test {i} for {student_id} {subject_key} must be 0..{test_total_max:g}.')
                        subject_scores[f'test_{i}'] = test_val
                    subject_scores['total_test'] = sum(subject_scores.get(f'test_{i}', 0) for i in range(1, max_tests + 1))
                    if subject_scores['total_test'] > test_total_max:
                        raise ValueError(f'Row {idx}: Total test score for {student_id} {subject_key} must be <= {test_total_max:g}.')
                else:
                    subject_scores['total_test'] = 0

                if school.get('exam_enabled', 1):
                    if exam_config.get('exam_mode') == 'combined':
                        if not has_exam_col:
                            raise ValueError('CSV must include "Exam Score" column for combined exam mode.')
                        if (has_obj_col and str(row.get(headers['objective'], '') or '').strip()) or (has_theory_col and str(row.get(headers['theory'], '') or '').strip()):
                            raise ValueError(f'Row {idx}: combined exam mode does not allow Objective/Theory values. Use Exam Score only.')
                        exam_col = headers.get('exam score')
                        raw_exam = row.get(exam_col, '') if exam_col else ''
                        exam_score = float(subject_scores.get('exam_score', subject_scores.get('total_exam', 0)) or 0) if str(raw_exam).strip() == '' else parse_csv_float(raw_exam, idx, f'Exam score for {student_id} {subject_key}')
                        exam_max = max(0.0, safe_float(exam_config.get('exam_score_max', 70), 70))
                        if exam_score < 0 or exam_score > exam_max:
                            raise ValueError(f'Row {idx}: Exam score for {student_id} {subject_key} must be 0..{exam_max:g}.')
                        subject_scores['objective'] = 0
                        subject_scores['theory'] = 0
                        subject_scores['exam_score'] = exam_score
                        subject_scores['total_exam'] = exam_score
                        subject_scores['exam_mode'] = 'combined'
                    else:
                        if not has_obj_col or not has_theory_col:
                            raise ValueError('CSV must include both "Objective" and "Theory" columns for separate exam mode.')
                        if has_exam_col and str(row.get(headers['exam score'], '') or '').strip():
                            raise ValueError(f'Row {idx}: separate exam mode does not allow Exam Score value. Use Objective and Theory only.')
                        obj_col = headers.get('objective')
                        thy_col = headers.get('theory')
                        raw_obj = row.get(obj_col, '') if obj_col else ''
                        raw_thy = row.get(thy_col, '') if thy_col else ''
                        objective = float(subject_scores.get('objective', 0) or 0) if str(raw_obj).strip() == '' else parse_csv_float(raw_obj, idx, f'Objective for {student_id} {subject_key}')
                        theory = float(subject_scores.get('theory', 0) or 0) if str(raw_thy).strip() == '' else parse_csv_float(raw_thy, idx, f'Theory for {student_id} {subject_key}')
                        objective_max = max(0.0, safe_float(exam_config.get('objective_max', 30), 30))
                        theory_max = max(0.0, safe_float(exam_config.get('theory_max', 40), 40))
                        exam_total_max = max(0.0, safe_float(exam_config.get('exam_score_max', objective_max + theory_max), objective_max + theory_max))
                        if objective < 0 or objective > objective_max:
                            raise ValueError(f'Row {idx}: Objective for {student_id} {subject_key} must be 0..{objective_max:g}.')
                        if theory < 0 or theory > theory_max:
                            raise ValueError(f'Row {idx}: Theory for {student_id} {subject_key} must be 0..{theory_max:g}.')
                        subject_scores['objective'] = objective
                        subject_scores['theory'] = theory
                        subject_scores['total_exam'] = objective + theory
                        if subject_scores['total_exam'] > exam_total_max:
                            raise ValueError(f'Row {idx}: Total exam score for {student_id} {subject_key} must be <= {exam_total_max:g}.')
                        subject_scores['exam_mode'] = 'separate'
                else:
                    subject_scores['total_exam'] = 0

                subject_scores['overall_mark'] = float(subject_scores.get('total_test', 0) or 0) + float(subject_scores.get('total_exam', 0) or 0)
                if subject_scores['overall_mark'] > 100:
                    raise ValueError(
                        f'Row {idx}: Total score for {student_id} {subject_key} exceeds 100. '
                        'Check test/exam limits or score values.'
                    )
                subject_scores['total_score'] = subject_scores['overall_mark']
                subject_scores['grade'] = grade_from_score(subject_scores['overall_mark'], grade_cfg)
                existing_scores[subject_key] = subject_scores
                student['scores'] = existing_scores
                student['term'] = current_term

                comment_col = headers.get('teacher comment')
                if comment_col:
                    comment = (row.get(comment_col, '') or '').strip()
                    if comment:
                        student['teacher_comment'] = comment

                staged_students[student_id] = student
                staged_changed_subjects.setdefault(student_id, set()).add(subject_key)
                updated_students.add(student_id)
                touched_classes.add(classname)

            if processed_rows == 0:
                raise ValueError('No valid data rows found. Fill at least Student ID and Subject in one row.')

            ensure_result_publication_approval_columns()
            has_approval_cols = result_publication_has_approval_columns()
            with db_connection(commit=True) as conn:
                c = conn.cursor()
                principal_name = (school.get('principal_name', '') or '').strip()
                teacher_name = f"{teacher_profile.get('firstname', '')} {teacher_profile.get('lastname', '')}".strip() or str(teacher_id)
                for sid, student_data in staged_students.items():
                    save_student_with_cursor(c, school_id, sid, student_data)
                    audit_student_score_changes_with_cursor(
                        c=c,
                        school_id=school_id,
                        student_id=sid,
                        classname=student_data.get('classname', ''),
                        term=current_term,
                        academic_year=current_year or '',
                        old_scores=staged_original_scores.get(sid, {}),
                        new_scores=student_data.get('scores', {}) if isinstance(student_data.get('scores', {}), dict) else {},
                        changed_by=teacher_id,
                        changed_by_role='teacher',
                        change_source='csv_upload',
                        change_reason='',
                        subjects_scope=sorted(staged_changed_subjects.get(sid, set())),
                    )
                for classname in touched_classes:
                    if has_approval_cols:
                        db_execute(
                            c,
                            (
                                "INSERT INTO result_publications "
                                "(school_id, classname, term, academic_year, teacher_id, teacher_name, principal_name, is_published, published_at, "
                                "approval_status, submitted_at, submitted_by, reviewed_at, reviewed_by, review_note, updated_at) "
                                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'not_submitted', NULL, NULL, NULL, NULL, NULL, CURRENT_TIMESTAMP) "
                                "ON CONFLICT(school_id, classname, term, academic_year) DO UPDATE SET "
                                "teacher_id = excluded.teacher_id, "
                                "teacher_name = excluded.teacher_name, "
                                "principal_name = excluded.principal_name, "
                                "is_published = excluded.is_published, "
                                "published_at = excluded.published_at, "
                                "approval_status = excluded.approval_status, "
                                "submitted_at = NULL, "
                                "submitted_by = NULL, "
                                "reviewed_at = NULL, "
                                "reviewed_by = NULL, "
                                "review_note = NULL, "
                                "updated_at = CURRENT_TIMESTAMP"
                            ),
                            (school_id, classname, current_term, current_year or '', teacher_id, teacher_name, principal_name, 0, None),
                        )
                    else:
                        db_execute(
                            c,
                            (
                                "INSERT INTO result_publications "
                                "(school_id, classname, term, academic_year, teacher_id, teacher_name, principal_name, is_published, published_at, updated_at) "
                                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP) "
                                "ON CONFLICT(school_id, classname, term, academic_year) DO UPDATE SET "
                                "teacher_id = excluded.teacher_id, "
                                "teacher_name = excluded.teacher_name, "
                                "principal_name = excluded.principal_name, "
                                "is_published = excluded.is_published, "
                                "published_at = excluded.published_at, "
                                "updated_at = CURRENT_TIMESTAMP"
                            ),
                            (school_id, classname, current_term, current_year or '', teacher_id, teacher_name, principal_name, 0, None),
                        )

            csv_result.update({
                'success': True,
                'message': f'CSV uploaded successfully. Updated {len(updated_students)} student(s).',
                'processed_rows': processed_rows,
                'updated_students': len(updated_students),
                'updated_classes': len(touched_classes),
            })
        except Exception as e:
            error_message = str(e)
            error_token = ''
            if current_row_num and current_row_data and fieldnames:
                output = StringIO()
                err_fields = list(fieldnames) + ['Error']
                writer = csv.DictWriter(output, fieldnames=err_fields)
                writer.writeheader()
                row_out = {h: (current_row_data.get(h, '') if isinstance(current_row_data, dict) else '') for h in fieldnames}
                row_out['Error'] = error_message
                writer.writerow(row_out)
                fname = f'csv_upload_error_row_{current_row_num}.csv'
                error_token = _store_csv_error_export(
                    output.getvalue(),
                    fname,
                    owner_role='teacher',
                    owner_id=(session.get('user_id') or ''),
                    school_id=(school_id or ''),
                )
            csv_result.update({
                'success': False,
                'message': error_message,
                'processed_rows': processed_rows,
                'error_token': error_token,
            })

        return render_template(
            'teacher/teacher_upload_csv.html',
            max_tests=max(1, min(safe_int(school.get('max_tests', 3), 3), 10)),
            exam_mode_view=exam_mode_view,
            csv_result=csv_result,
        )

    return render_template(
        'teacher/teacher_upload_csv.html',
        max_tests=max(1, min(safe_int(school.get('max_tests', 3), 3), 10)),
        exam_mode_view=exam_mode_view,
    )

@app.route('/teacher/upload-csv-errors/<token>')
def teacher_upload_csv_error_rows(token):
    if session.get('role') != 'teacher':
        return redirect(url_for('login'))
    _cleanup_csv_error_exports()
    item = CSV_ERROR_EXPORTS.get((token or '').strip())
    if not item:
        flash('Error export link expired. Re-run upload to generate it again.', 'error')
        return redirect(url_for('teacher_upload_csv'))
    owner_role = (item.get('owner_role') or '').strip().lower()
    owner_id = (item.get('owner_id') or '').strip().lower()
    owner_school_id = (item.get('school_id') or '').strip()
    current_user = (session.get('user_id') or '').strip().lower()
    current_school_id = (session.get('school_id') or '').strip()
    if owner_role and owner_role != 'teacher':
        flash('You are not allowed to access this error export.', 'error')
        return redirect(url_for('teacher_upload_csv'))
    if owner_id and owner_id != current_user:
        flash('You are not allowed to access this error export.', 'error')
        return redirect(url_for('teacher_upload_csv'))
    if owner_school_id and owner_school_id != current_school_id:
        flash('You are not allowed to access this error export.', 'error')
        return redirect(url_for('teacher_upload_csv'))
    return Response(
        item.get('content', ''),
        mimetype='text/csv',
        headers={'Content-Disposition': f'attachment; filename={item.get("filename", "csv_upload_error_rows.csv")}'}
    )

@app.route('/teacher/upload-csv-template')
def teacher_upload_csv_template():
    """Download CSV template for score upload."""
    if session.get('role') != 'teacher':
        return redirect(url_for('login'))

    school_id = session.get('school_id')
    school = get_school(school_id) or {}
    teacher_id = session.get('user_id')
    current_term = get_current_term(school)
    current_year = school.get('academic_year', '')
    allowed_classes = set(get_teacher_classes(school_id, teacher_id, term=current_term, academic_year=current_year))
    subject_rows = get_teacher_subject_assignments(
        school_id,
        teacher_id=teacher_id,
        term=current_term,
        academic_year=current_year,
    )
    allowed_classes.update({r.get('classname', '') for r in subject_rows if r.get('classname', '')})
    if not allowed_classes:
        flash('No assigned classes found for CSV template download.', 'error')
        return redirect(url_for('teacher_dashboard'))
    max_tests = max(1, min(safe_int(school.get('max_tests', 3), 3), 10))
    max_tests = max(1, min(max_tests, 10))
    exam_mode_view = 'none'
    if school.get('exam_enabled', 1):
        class_exam_modes = set()
        for cls in allowed_classes:
            class_exam_modes.add((get_assessment_config_for_class(school_id, cls).get('exam_mode') or 'separate').lower())
        if class_exam_modes == {'combined'}:
            exam_mode_view = 'combined'
        elif class_exam_modes and class_exam_modes <= {'separate'}:
            exam_mode_view = 'separate'
        elif class_exam_modes:
            exam_mode_view = 'mixed'
        else:
            exam_mode_view = 'separate'

    headers = ['Student ID', 'Subject']
    headers.extend([f'Test {i}' for i in range(1, max_tests + 1)])
    if exam_mode_view == 'combined':
        headers.append('Exam Score')
    elif exam_mode_view == 'separate':
        headers.extend(['Objective', 'Theory'])
    elif exam_mode_view == 'mixed':
        headers.extend(['Objective', 'Theory', 'Exam Score'])
    headers.append('Teacher Comment')

    output = StringIO()
    writer = csv.writer(output)
    writer.writerow(headers)
    sample = ['26/school/001/26', 'Mathematics']
    sample.extend(['' for _ in range(max_tests)])
    if exam_mode_view == 'combined':
        sample.append('')
    elif exam_mode_view == 'separate':
        sample.extend(['', ''])
    elif exam_mode_view == 'mixed':
        sample.extend(['', '', ''])
    sample.append('')
    writer.writerow(sample)

    filename = f'score_upload_template_{exam_mode_view}_{max_tests}_tests.csv'
    return Response(
        output.getvalue(),
        mimetype='text/csv',
        headers={'Content-Disposition': f'attachment; filename={filename}'}
    )

@app.route('/teacher/result-sheet-template')
def teacher_result_sheet_template():
    """Download blank class/subject score template without student identity fields."""
    if session.get('role') != 'teacher':
        return redirect(url_for('login'))

    school_id = session.get('school_id')
    teacher_id = session.get('user_id')
    school = get_school(school_id) or {}
    current_term = get_current_term(school)
    current_year = school.get('academic_year', '')
    allowed_classes = set(get_teacher_classes(school_id, teacher_id, term=current_term, academic_year=current_year))
    subject_rows = get_teacher_subject_assignments(
        school_id,
        teacher_id=teacher_id,
        term=current_term,
        academic_year=current_year,
    )
    allowed_classes.update({r.get('classname', '') for r in subject_rows if r.get('classname', '')})
    allowed_classes = sorted(allowed_classes)
    if not allowed_classes:
        flash('No assigned classes found for template download.', 'error')
        return redirect(url_for('teacher_dashboard'))

    requested_class = (request.args.get('classname', '') or '').strip()
    if requested_class:
        class_pool = {c.lower(): c for c in allowed_classes}
        if requested_class.lower() not in class_pool:
            flash('Selected class is not assigned to you.', 'error')
            return redirect(url_for('teacher_upload_csv'))
        target_classes = [class_pool[requested_class.lower()]]
    else:
        target_classes = allowed_classes

    max_tests = max(1, min(safe_int(school.get('max_tests', 3), 3), 10))
    max_tests = max(1, min(max_tests, 10))
    include_tests = bool(school.get('test_enabled', 1))
    include_exam = bool(school.get('exam_enabled', 1))

    headers = ['Class', 'Subject']
    if include_tests:
        headers.extend([f'Test {i}' for i in range(1, max_tests + 1)])
    if include_exam:
        # Keep all exam score columns so one template works across combined/separate classes.
        headers.extend(['Objective', 'Theory', 'Exam Score'])

    output = StringIO()
    writer = csv.writer(output)
    writer.writerow(headers)

    for classname in target_classes:
        config = get_class_subject_config(school_id, classname) or {}
        subjects = _dedupe_keep_order([
            normalize_subject_name(s)
            for s in (
                (config.get('core_subjects') or [])
                + (config.get('science_subjects') or [])
                + (config.get('art_subjects') or [])
                + (config.get('commercial_subjects') or [])
                + (config.get('optional_subjects') or [])
            )
            if str(s).strip()
        ])
        if not subjects:
            defaults = _catalog_defaults_for_class(classname)
            subjects = _dedupe_keep_order([
                normalize_subject_name(s)
                for bucket in ('core', 'science', 'art', 'commercial', 'optional')
                for s in (defaults.get(bucket) or [])
                if str(s).strip()
            ])
        if not subjects:
            subjects = ['Subject']

        class_exam_mode = (get_assessment_config_for_class(school_id, classname).get('exam_mode') or 'separate').lower()
        for subject in subjects:
            row = [classname, subject]
            if include_tests:
                row.extend([0 for _ in range(max_tests)])
            if include_exam:
                if class_exam_mode == 'combined':
                    row.extend(['', '', 0])
                else:
                    row.extend([0, 0, ''])
            writer.writerow(row)

    class_token = canonicalize_classname(target_classes[0]) if len(target_classes) == 1 else 'ALL_CLASSES'
    filename = f'result_sheet_template_{class_token}.csv'
    return Response(
        output.getvalue(),
        mimetype='text/csv',
        headers={'Content-Disposition': f'attachment; filename={filename}'}
    )

# ==================== STUDENT ROUTES ====================

@app.route('/student')
def student_dashboard():
    if session.get('role') != 'student':
        return redirect(url_for('login'))
    
    school_id = session.get('school_id')
    student_id = session.get('user_id')
    
    student = load_student(school_id, student_id)
    if not student:
        flash('Student data not found.', 'error')
        return redirect(url_for('login'))

    school = get_school(school_id) or {}
    current_term = get_current_term(school)
    current_year = (school or {}).get('academic_year', '')
    dashboard_notice = ''

    # Dashboard must show only published snapshot data (never raw working scores).
    my_data = {
        'firstname': student.get('firstname', ''),
        'student_id': student_id,
        'classname': student.get('classname', ''),
        'term': student.get('term', ''),
        'stream': student.get('stream', ''),
        'number_of_subject': 0,
        'scores': {},
        'average_marks': 0,
        'Grade': '',
        'Status': '',
    }

    visible_terms = filter_visible_terms_for_student(
        school,
        get_published_terms_for_student(school_id, student_id),
    )
    if visible_terms:
        target = pick_default_published_term(visible_terms, current_term, current_year)
        if target:
            snapshot = load_published_student_result(
                school_id,
                student_id,
                target.get('term', ''),
                target.get('academic_year', ''),
            )
            if snapshot:
                my_data.update({
                    'firstname': snapshot.get('firstname', my_data.get('firstname', '')),
                    'classname': snapshot.get('classname', my_data.get('classname', '')),
                    'term': snapshot.get('term', my_data.get('term', '')),
                    'stream': snapshot.get('stream', my_data.get('stream', '')),
                    'number_of_subject': snapshot.get('number_of_subject', 0),
                    'scores': snapshot.get('scores', {}),
                    'average_marks': snapshot.get('average_marks', 0),
                    'Grade': snapshot.get('Grade', ''),
                    'Status': snapshot.get('Status', ''),
                })
            else:
                dashboard_notice = 'No published result available yet.'
    else:
        if safe_int((school or {}).get('operations_enabled', 1), 1):
            dashboard_notice = 'No published result available yet.'
        else:
            dashboard_notice = 'Current term results are hidden while operations are OFF. Only previous published results are available.'
    parent_phone = (student.get('parent_phone', '') or '').strip()
    has_parent_access = bool(parent_phone and (student.get('parent_password_hash', '') or '').strip())
    student_messages = get_student_messages_for_student(
        school_id=school_id,
        classname=student.get('classname', ''),
        stream=student.get('stream', ''),
        student_id=student_id,
        limit=20,
    )
    unread_student_messages = sum(1 for row in student_messages if not row.get('is_read'))
    return render_template(
        'student/student_dashboard.html',
        school=school,
        student=my_data,
        dashboard_notice=dashboard_notice,
        parent_phone=parent_phone,
        has_parent_access=has_parent_access,
        student_messages=student_messages,
        unread_student_messages=unread_student_messages,
    )


@app.route('/student/messages')
def student_messages():
    if session.get('role') != 'student':
        return redirect(url_for('login'))

    school_id = session.get('school_id')
    student_id = session.get('user_id')
    student = load_student(school_id, student_id) or {}
    school = get_school(school_id) or {}
    current_term = get_current_term(school)
    current_year = (school or {}).get('academic_year', '')

    message_rows = get_student_messages_for_student(
        school_id=school_id,
        classname=student.get('classname', ''),
        stream=student.get('stream', ''),
        student_id=student_id,
        limit=80,
    )
    unread_student_messages = sum(1 for row in message_rows if not row.get('is_read'))

    student_view = {
        'firstname': student.get('firstname', ''),
        'student_id': student_id,
        'classname': student.get('classname', ''),
        'term': current_term,
        'stream': student.get('stream', ''),
    }

    return render_template(
        'student/student_messages.html',
        school=school,
        student=student_view,
        student_messages=message_rows,
        unread_student_messages=unread_student_messages,
        current_year=current_year,
    )


@app.route('/student/messages/mark-read', methods=['POST'])
def student_mark_message_read():
    if session.get('role') != 'student':
        return redirect(url_for('login'))
    school_id = session.get('school_id')
    student_id = session.get('user_id')
    student = load_student(school_id, student_id) or {}
    message_id_raw = (request.form.get('message_id', '') or '').strip()
    try:
        message_id = int(message_id_raw)
    except Exception:
        flash('Invalid message selection.', 'error')
        return redirect(url_for('student_messages'))
    changed = mark_student_message_read(
        school_id=school_id,
        student_id=student_id,
        message_id=message_id,
        classname=student.get('classname', ''),
        stream=student.get('stream', ''),
    )
    if changed:
        flash('Notification marked as read.', 'success')
    else:
        flash('Message not found or not visible to your account.', 'error')
    return redirect(url_for('student_messages'))

@app.route('/student/messages/mark-all-read', methods=['POST'])
def student_mark_all_messages_read():
    if session.get('role') != 'student':
        return redirect(url_for('login'))
    school_id = session.get('school_id')
    student_id = session.get('user_id')
    student = load_student(school_id, student_id) or {}
    changed = mark_all_student_messages_read(
        school_id=school_id,
        student_id=student_id,
        classname=student.get('classname', ''),
        stream=student.get('stream', ''),
    )
    if changed:
        flash('All notifications marked as read.', 'success')
    else:
        flash('No visible notifications to update.', 'warning')
    return redirect(url_for('student_messages'))

@app.route('/student/change-password', methods=['GET', 'POST'])
def student_change_password():
    if session.get('role') != 'student':
        return redirect(url_for('login'))

    username = session.get('user_id')
    school_id = session.get('school_id')
    user = get_user(username)
    if not user or (user.get('role') or '').strip().lower() != 'student':
        flash('Student account not found.', 'error')
        return redirect(url_for('login'))

    force_change = bool(session.get('must_change_password'))
    if request.method == 'POST':
        current_password = request.form.get('current_password', '')
        new_password = request.form.get('new_password', '')
        confirm_password = request.form.get('confirm_password', '')

        if not current_password or not new_password or not confirm_password:
            flash('Please fill in all password fields.', 'error')
            return redirect(url_for('student_change_password'))
        if not check_password(user.get('password_hash', ''), current_password):
            flash('Current password is incorrect.', 'error')
            return redirect(url_for('student_change_password'))
        if len(new_password) < 8:
            flash('New password must be at least 8 characters.', 'error')
            return redirect(url_for('student_change_password'))
        if new_password != confirm_password:
            flash('New passwords do not match.', 'error')
            return redirect(url_for('student_change_password'))
        if new_password == DEFAULT_STUDENT_PASSWORD:
            flash('Choose a new password different from the default password.', 'error')
            return redirect(url_for('student_change_password'))

        upsert_user(username, hash_password(new_password), 'student', school_id)
        session.pop('must_change_password', None)
        flash('Password changed successfully.', 'success')
        return redirect(url_for('student_dashboard'))

    return render_template(
        'shared/change_password.html',
        form_action='student_change_password',
        back_url=('' if force_change else 'student_dashboard'),
        force_change=force_change,
    )


@app.route('/student/parent-access', methods=['POST'])
def student_update_parent_access():
    if session.get('role') != 'student':
        return redirect(url_for('login'))
    school_id = session.get('school_id')
    student_id = session.get('user_id')
    student = load_student(school_id, student_id)
    if not student:
        flash('Student data not found.', 'error')
        return redirect(url_for('student_dashboard'))
    if not students_has_parent_access_columns():
        flash('Parent access is not available yet. Ask admin to run latest database migration.', 'error')
        return redirect(url_for('student_dashboard'))

    raw_phone = request.form.get('parent_phone', '')
    parent_phone = normalize_parent_phone(raw_phone)
    parent_password = (request.form.get('parent_password', '') or '').strip()
    confirm_password = (request.form.get('confirm_parent_password', '') or '').strip()
    has_existing_parent = bool((student.get('parent_phone', '') or '').strip() and (student.get('parent_password_hash', '') or '').strip())

    if not parent_phone and not parent_password and not confirm_password:
        if has_existing_parent:
            flash('Parent access cannot be removed once it has been added. You can only update phone/password.', 'error')
        else:
            flash('No parent access details were submitted.', 'error')
        return redirect(url_for('student_dashboard'))

    if not parent_phone or not parent_password:
        flash('Parent phone and password are both required to enable parent access.', 'error')
        return redirect(url_for('student_dashboard'))
    if not is_valid_parent_phone(parent_phone):
        flash('Enter a valid parent phone number.', 'error')
        return redirect(url_for('student_dashboard'))
    if len(parent_password) < 6:
        flash('Parent password must be at least 6 characters.', 'error')
        return redirect(url_for('student_dashboard'))
    if parent_password != confirm_password:
        flash('Parent passwords do not match.', 'error')
        return redirect(url_for('student_dashboard'))

    student['parent_phone'] = parent_phone
    student['parent_password_hash'] = hash_password(parent_password)
    save_student(school_id, student_id, student)
    flash('Parent access saved successfully.', 'success')
    return redirect(url_for('student_dashboard'))

@app.route('/student/view-result')
def student_view_result():
    if session.get('role') != 'student':
        return redirect(url_for('login'))
    
    school_id = session.get('school_id')
    school = get_school(school_id) or {}
    current_term = get_current_term(school)
    current_year = (school or {}).get('academic_year', '')
    student_id = session.get('user_id')
    live_student = load_student(school_id, student_id) or {}
    requested_term = (request.args.get('term', '') or '').strip()
    selected_class = (request.args.get('class_name', '') or '').strip()
    term_notice = ''

    all_published_terms = get_published_terms_for_student(school_id, student_id)
    available_result_classes = sorted({
        (t.get('classname') or '').strip()
        for t in all_published_terms
        if (t.get('classname') or '').strip()
    })
    if selected_class and selected_class not in available_result_classes:
        term_notice = f'No published results found for class "{selected_class}".'
        selected_class = ''

    published_terms = filter_visible_terms_for_student(
        school,
        get_published_terms_for_student(school_id, student_id, classname=selected_class),
    )
    if not published_terms:
        if safe_int((school or {}).get('operations_enabled', 1), 1):
            flash('No published result available yet.', 'error')
        else:
            flash('Current term results are hidden while operations are OFF. Only previous published results are available.', 'error')
        return redirect(url_for('student_dashboard'))

    if requested_term:
        target_entry = resolve_requested_published_term(
            published_terms,
            requested_term,
            current_term=current_term,
            current_year=current_year,
        )
        if not target_entry:
            term_notice = f'{requested_term} result is not published for you.'
            target_entry = pick_default_published_term(published_terms, current_term, current_year)
    else:
        target_entry = pick_default_published_term(published_terms, current_term, current_year)
    target_term = target_entry['term']
    target_year = target_entry.get('academic_year', '')
    current_term_token = target_entry['token']

    snapshot = load_published_student_result(
        school_id,
        student_id,
        target_term,
        target_year,
        classname=selected_class,
    )
    if not snapshot:
        flash('Published result snapshot not found.', 'error')
        return redirect(url_for('student_dashboard'))
    record_result_view(school_id, student_id, target_term, snapshot.get('academic_year', target_year))

    exam_config = get_assessment_config_for_class(school_id, snapshot.get('classname', ''))
    class_results = load_published_class_results(school_id, snapshot.get('classname', ''), target_term, target_year, school=school)
    position, subject_positions = build_positions_from_published_results(
        school=school,
        classname=snapshot.get('classname', ''),
        term=target_term,
        class_results=class_results,
        student_id=student_id,
        student_stream=snapshot.get('stream', ''),
        subjects=snapshot.get('subjects', []),
    )

    student_view = {
        'first_name': snapshot.get('firstname', ''),
        'student_id': student_id,
        'date_of_birth': (live_student.get('date_of_birth', '') or '').strip(),
        'gender': (live_student.get('gender', '') or '').strip(),
        'class_name': snapshot.get('classname', ''),
        'class_size': len(class_results or []),
        'term': target_term,
        'academic_year': target_year,
        'number_of_subject': snapshot.get('number_of_subject', 0),
        'subjects': snapshot.get('scores', {}),
        'behaviour_assessment': snapshot.get('behaviour_assessment', {}),
        'teacher_comment': snapshot.get('teacher_comment', ''),
        'principal_comment': snapshot.get('principal_comment', ''),
        'average_marks': snapshot.get('average_marks', 0),
        'Grade': snapshot.get('Grade', 'F'),
        'Status': snapshot.get('Status', 'Fail'),
    }
    student_view.update(
        build_result_term_attendance_data(
            school_id=school_id,
            student_id=student_id,
            classname=snapshot.get('classname', ''),
            term=target_term,
            academic_year=target_year,
        )
    )
    result_max_tests = detect_max_tests_from_scores(snapshot.get('scores', {}), school.get('max_tests', 3))
    signoff = get_result_signoff_details(
        school_id,
        snapshot.get('classname', ''),
        target_term,
        target_year,
    )
    show_positions = bool((school or {}).get('show_positions', 1))
    teacher_signature = signoff.get('teacher_signature', '')
    principal_signature = signoff.get('principal_signature', '')
    teacher_name = signoff.get('teacher_name', '')
    principal_name = signoff.get('principal_name', '')
    verify_ctx = build_result_verification_context(
        school_id=school_id,
        student_id=student_id,
        term=target_term,
        academic_year=target_year,
        classname=snapshot.get('classname', ''),
    )

    current_index = next((i for i, item in enumerate(published_terms) if item['token'] == current_term_token), 0)
    prev_term = published_terms[current_index - 1] if current_index > 0 else None
    next_term = published_terms[current_index + 1] if current_index < len(published_terms) - 1 else None

    return render_template('student/student_result.html', 
                         student=student_view,
                         school=school,
                         position=position,
                         subject_positions=subject_positions,
                         published_terms=published_terms,
                         current_term_token=current_term_token,
                         available_result_classes=available_result_classes,
                         selected_result_class=selected_class,
                         term_notice=term_notice,
                         term_view_endpoint='student_view_result',
                         prev_term=prev_term,
                         next_term=next_term,
                         teacher_signature=teacher_signature,
                         teacher_name=teacher_name,
                         principal_signature=principal_signature,
                          principal_name=principal_name,
                          result_max_tests=result_max_tests,
                          exam_config=exam_config,
                          verification_url=verify_ctx.get('verification_url', ''),
                          verification_qr_url=verify_ctx.get('verification_qr_url', ''),
                          now=datetime.now())


def _parent_allowed_student_keys():
    keys = session.get('parent_student_keys') or []
    return {str(k) for k in keys if isinstance(k, str) and '::' in k}


@app.route('/parent-portal', methods=['GET', 'POST'])
def parent_portal():
    if request.method == 'GET' and session.get('role') == 'parent':
        return redirect(url_for('parent_dashboard'))
    if request.method == 'POST':
        parent_phone = normalize_parent_phone(request.form.get('parent_phone', ''))
        parent_password = (request.form.get('password', '') or '').strip()
        requested_student_id = (request.form.get('student_id', '') or '').strip()
        client_ip = get_client_ip()
        if not parent_phone or not parent_password:
            flash('Enter parent phone and password.', 'error')
            return redirect(url_for('parent_portal'))
        blocked, wait_minutes = is_login_blocked('parent_portal', parent_phone, client_ip)
        if blocked:
            flash(f'Too many failed login attempts. Try again in about {wait_minutes} minute(s).', 'error')
            return redirect(url_for('parent_portal'))
        candidates = get_parent_students_by_phone(parent_phone)
        matched = []
        for row in candidates:
            sid = (row.get('student_id', '') or '').strip()
            if requested_student_id and sid.lower() != requested_student_id.lower():
                continue
            password_hash = (row.get('parent_password_hash') or '').strip()
            if not password_hash:
                continue
            if check_password(password_hash, parent_password):
                matched.append(row)
        if not matched:
            register_failed_login('parent_portal', parent_phone, client_ip)
            record_login_audit(parent_phone, 'parent', None, 'parent_portal', False, 'invalid_credentials')
            flash('Invalid parent phone or password.', 'error')
            return redirect(url_for('parent_portal'))
        if len(matched) > 1 and not requested_student_id:
            flash('Multiple student profiles are linked. Enter Student ID to continue.', 'error')
            return redirect(url_for('parent_portal'))
        clear_failed_login('parent_portal', parent_phone, client_ip)
        session.clear()
        session.permanent = True
        session['role'] = 'parent'
        session['parent_phone'] = parent_phone
        session['parent_student_keys'] = sorted(
            {f"{row.get('school_id', '')}::{row.get('student_id', '')}" for row in matched},
            key=lambda v: v.lower(),
        )
        if not has_parent_seen_first_login_tutorial(parent_phone):
            session['show_first_login_tutorial'] = True
            session['first_login_tutorial_role'] = 'parent'
        record_login_audit(parent_phone, 'parent', (matched[0].get('school_id', '') if matched else ''), 'parent_portal', True, '')
        flash('Security warning: change your parent password now to a private password only you know.', 'error')
        return redirect(url_for('parent_dashboard'))
    return render_template('parent/parent_portal.html')


@app.route('/parent/change-password', methods=['POST'])
def parent_change_password():
    if session.get('role') != 'parent':
        return redirect(url_for('parent_portal'))
    old_password = (request.form.get('current_password', '') or '').strip()
    new_password = (request.form.get('new_password', '') or '').strip()
    confirm_password = (request.form.get('confirm_password', '') or '').strip()
    if not old_password or not new_password or not confirm_password:
        flash('All parent password fields are required.', 'error')
        return redirect(url_for('parent_dashboard'))
    if new_password != confirm_password:
        flash('New parent passwords do not match.', 'error')
        return redirect(url_for('parent_dashboard'))
    if len(new_password) < 6:
        flash('New parent password must be at least 6 characters.', 'error')
        return redirect(url_for('parent_dashboard'))

    allowed_keys = _parent_allowed_student_keys()
    if not allowed_keys:
        flash('Parent session expired. Please login again.', 'error')
        return redirect(url_for('parent_portal'))

    matched_keys = []
    for key in sorted(allowed_keys):
        if '::' not in key:
            continue
        school_id, student_id = key.split('::', 1)
        student = load_student(school_id, student_id)
        if not student:
            continue
        current_hash = (student.get('parent_password_hash', '') or '').strip()
        if not current_hash or not check_password(current_hash, old_password):
            flash('Current parent password is incorrect for one or more linked students.', 'error')
            return redirect(url_for('parent_dashboard'))
        matched_keys.append((school_id, student_id))
    if not matched_keys:
        flash('Current parent password is incorrect.', 'error')
        return redirect(url_for('parent_dashboard'))
    new_hash = hash_password(new_password)
    with db_connection(commit=True) as conn:
        c = conn.cursor()
        for school_id, student_id in matched_keys:
            db_execute(
                c,
                """UPDATE students
                   SET parent_password_hash = ?
                   WHERE school_id = ? AND student_id = ?""",
                (new_hash, school_id, student_id),
            )
    flash('Parent password changed successfully.', 'success')
    return redirect(url_for('parent_dashboard'))


@app.route('/parent')
def parent_dashboard():
    if session.get('role') != 'parent':
        return redirect(url_for('parent_portal'))
    allowed_keys = _parent_allowed_student_keys()
    if not allowed_keys:
        flash('Parent session expired. Please login again.', 'error')
        return redirect(url_for('parent_portal'))
    key_pairs = []
    student_ids_by_school = {}
    for key in sorted(allowed_keys):
        if '::' not in key:
            continue
        school_id, student_id = key.split('::', 1)
        school_id = (school_id or '').strip()
        student_id = (student_id or '').strip()
        if not school_id or not student_id:
            continue
        key_pairs.append((key, school_id, student_id))
        student_ids_by_school.setdefault(school_id, []).append(student_id)

    schools_by_id = {sid: (get_school(sid) or {}) for sid in student_ids_by_school.keys()}
    students_by_key = {}
    parent_term_events_by_school = {}
    published_overview_by_school = {}
    for sid, student_ids in student_ids_by_school.items():
        current_school = schools_by_id.get(sid, {})
        current_term = get_current_term(current_school)
        current_year = (current_school or {}).get('academic_year', '')
        parent_term_events_by_school[sid] = get_visible_term_program_events(
            school_id=sid,
            academic_year=current_year,
            term=current_term,
            audience='parents',
        )
        rows = load_students_for_student_ids(sid, student_ids)
        for student_id, student in rows.items():
            students_by_key[f'{sid}::{student_id}'] = student
        published_overview_by_school[sid] = get_published_overview_for_students(sid, student_ids)

    children = []
    for key, school_id, student_id in key_pairs:
        student = students_by_key.get(key)
        if not student:
            continue
        school = schools_by_id.get(school_id, {})
        current_term = get_current_term(school)
        current_year = (school or {}).get('academic_year', '')
        overview = published_overview_by_school.get(school_id, {})
        all_terms = (overview.get('terms_by_student', {}) or {}).get(student_id, [])
        snapshot_map = (overview.get('snapshot_by_student_token', {}) or {}).get(student_id, {})
        published_terms = filter_visible_terms_for_student(school, all_terms)
        published_terms_sorted = sorted(
            list(published_terms or []),
            key=lambda x: ((_academic_year_start(x.get('academic_year')) or 0), term_sort_value(x.get('term'))),
        )
        latest = pick_default_published_term(published_terms, current_term, current_year) if published_terms else None
        latest_token = _term_token((latest or {}).get('academic_year', ''), (latest or {}).get('term', ''))
        snapshot = snapshot_map.get(latest_token)
        if latest and (latest.get('term', '') or '').strip().lower() == 'third term' and bool((school or {}).get('combine_third_term_results')):
            combined = load_published_student_result(
                school_id,
                student_id,
                latest.get('term', ''),
                latest.get('academic_year', ''),
            )
            if combined:
                snapshot = combined
        trend_points = []
        for term_item in published_terms_sorted:
            token = _term_token(term_item.get('academic_year', ''), term_item.get('term', ''))
            snap = snapshot_map.get(token)
            term_name = (term_item.get('term', '') or '').strip().lower()
            if term_name == 'third term' and bool((school or {}).get('combine_third_term_results')):
                combined = load_published_student_result(
                    school_id,
                    student_id,
                    term_item.get('term', ''),
                    term_item.get('academic_year', ''),
                )
                if combined:
                    snap = combined
            if not snap:
                continue
            trend_points.append({
                'label': f"{term_item.get('term', '')} ({term_item.get('academic_year', '')})",
                'average': round(float(snap.get('average_marks', 0) or 0), 2),
            })
        breakpoint_info = {'drop': 0.0, 'from': '', 'to': ''}
        for i in range(1, len(trend_points)):
            prev_row = trend_points[i - 1]
            curr_row = trend_points[i]
            drop = float(prev_row.get('average', 0) or 0) - float(curr_row.get('average', 0) or 0)
            if drop > float(breakpoint_info.get('drop', 0) or 0):
                breakpoint_info = {
                    'drop': round(drop, 2),
                    'from': prev_row.get('label', ''),
                    'to': curr_row.get('label', ''),
                }
        children.append({
            'key': key,
            'school_id': school_id,
            'school_name': (school or {}).get('school_name', school_id),
            'student_id': student_id,
            'firstname': student.get('firstname', ''),
            'classname': student.get('classname', ''),
            'stream': student.get('stream', ''),
            'has_result': bool(snapshot),
            'latest_term': (latest or {}).get('term', ''),
            'latest_year': (latest or {}).get('academic_year', ''),
            'grade': (snapshot or {}).get('Grade', ''),
            'status': (snapshot or {}).get('Status', ''),
            'average_marks': (snapshot or {}).get('average_marks', 0),
            'trend_points': trend_points,
            'breakpoint': breakpoint_info,
        })
    children.sort(key=lambda row: ((row.get('firstname') or '').lower(), (row.get('student_id') or '').lower()))
    parent_theme_accent = '#1F7A8C'
    if children:
        first_school_id = (children[0].get('school_id') or '').strip()
        first_school = schools_by_id.get(first_school_id, {}) if first_school_id else {}
        parent_theme_accent = normalize_hex_color(first_school.get('theme_accent_color', ''), '#1F7A8C')
    parent_term_events = []
    for child in children:
        sid = child.get('school_id', '')
        school_events = parent_term_events_by_school.get(sid, [])
        school_name = child.get('school_name', sid)
        for item in school_events:
            parent_term_events.append({
                'school_name': school_name,
                'label': item.get('label', ''),
                'date': item.get('date', ''),
                'status': item.get('status', ''),
                'note': item.get('note', ''),
            })
    parent_term_events.sort(key=lambda x: ((x.get('school_name') or '').lower(), (x.get('date') or ''), (x.get('label') or '').lower()))
    parent_messages = get_parent_messages_for_children(
        parent_phone=session.get('parent_phone', ''),
        children=children,
        limit_per_school=80,
    )
    unread_parent_messages = sum(1 for row in parent_messages if not row.get('is_read'))
    return render_template(
        'parent/parent_dashboard.html',
        parent_phone=session.get('parent_phone', ''),
        parent_theme_accent=parent_theme_accent,
        children=children,
        parent_term_events=parent_term_events,
        parent_messages=parent_messages,
        unread_parent_messages=unread_parent_messages,
    )

@app.route('/parent/messages/mark-read', methods=['POST'])
def parent_mark_message_read():
    if session.get('role') != 'parent':
        return redirect(url_for('parent_portal'))
    school_id = (request.form.get('school_id', '') or '').strip()
    message_id_raw = (request.form.get('message_id', '') or '').strip()
    parent_phone = session.get('parent_phone', '')
    if not school_id:
        flash('Invalid message selection.', 'error')
        return redirect(url_for('parent_messages'))
    try:
        message_id = int(message_id_raw)
    except Exception:
        flash('Invalid message selection.', 'error')
        return redirect(url_for('parent_messages'))
    allowed_keys = _parent_allowed_student_keys()
    children = []
    for key in sorted(allowed_keys):
        if '::' not in key:
            continue
        child_school_id, student_id = key.split('::', 1)
        student = load_student(child_school_id, student_id)
        if not student:
            continue
        children.append({
            'school_id': child_school_id,
            'classname': student.get('classname', ''),
            'stream': student.get('stream', ''),
        })
    allowed_messages = get_parent_messages_for_children(parent_phone=parent_phone, children=children, limit_per_school=160)
    allowed_pairs = {
        ((row.get('school_id') or '').strip(), int(row.get('id') or 0))
        for row in (allowed_messages or [])
        if int(row.get('id') or 0) > 0
    }
    if (school_id, message_id) not in allowed_pairs:
        flash('You are not allowed to update that notification.', 'error')
        return redirect(url_for('parent_messages'))
    changed = mark_parent_message_read(school_id, parent_phone, message_id)
    if changed:
        flash('Notification marked as read.', 'success')
    else:
        flash('Unable to update notification status.', 'warning')
    return redirect(url_for('parent_messages'))

@app.route('/parent/messages/mark-all-read', methods=['POST'])
def parent_mark_all_messages_read():
    if session.get('role') != 'parent':
        return redirect(url_for('parent_portal'))
    allowed_keys = _parent_allowed_student_keys()
    children = []
    for key in sorted(allowed_keys):
        if '::' not in key:
            continue
        school_id, student_id = key.split('::', 1)
        student = load_student(school_id, student_id)
        if not student:
            continue
        school = get_school(school_id) or {}
        children.append({
            'school_id': school_id,
            'school_name': (school or {}).get('school_name', school_id),
            'classname': student.get('classname', ''),
            'stream': student.get('stream', ''),
        })
    parent_phone = session.get('parent_phone', '')
    parent_messages = get_parent_messages_for_children(parent_phone=parent_phone, children=children, limit_per_school=120)
    changed = mark_all_parent_messages_read(parent_phone=parent_phone, parent_messages=parent_messages)
    if changed:
        flash('All notifications marked as read.', 'success')
    else:
        flash('No visible notifications to update.', 'warning')
    return redirect(url_for('parent_messages'))


@app.route('/parent/messages')
def parent_messages():
    if session.get('role') != 'parent':
        return redirect(url_for('parent_portal'))
    allowed_keys = _parent_allowed_student_keys()
    if not allowed_keys:
        flash('Parent session expired. Please login again.', 'error')
        return redirect(url_for('parent_portal'))

    key_pairs = []
    student_ids_by_school = {}
    for key in sorted(allowed_keys):
        if '::' not in key:
            continue
        school_id, student_id = key.split('::', 1)
        school_id = (school_id or '').strip()
        student_id = (student_id or '').strip()
        if not school_id or not student_id:
            continue
        key_pairs.append((key, school_id, student_id))
        student_ids_by_school.setdefault(school_id, []).append(student_id)

    schools_by_id = {sid: (get_school(sid) or {}) for sid in student_ids_by_school.keys()}
    students_by_key = {}
    for sid, student_ids in student_ids_by_school.items():
        rows = load_students_for_student_ids(sid, student_ids)
        for student_id, student in rows.items():
            students_by_key[f'{sid}::{student_id}'] = student

    children = []
    for key, school_id, student_id in key_pairs:
        student = students_by_key.get(key)
        if not student:
            continue
        school = schools_by_id.get(school_id, {})
        children.append({
            'key': key,
            'school_id': school_id,
            'school_name': (school or {}).get('school_name', school_id),
            'student_id': student_id,
            'firstname': student.get('firstname', ''),
            'classname': student.get('classname', ''),
            'stream': student.get('stream', ''),
        })
    children.sort(key=lambda row: ((row.get('firstname') or '').lower(), (row.get('student_id') or '').lower()))

    parent_theme_accent = '#1F7A8C'
    if children:
        first_school_id = (children[0].get('school_id') or '').strip()
        first_school = schools_by_id.get(first_school_id, {}) if first_school_id else {}
        parent_theme_accent = normalize_hex_color(first_school.get('theme_accent_color', ''), '#1F7A8C')

    parent_messages = get_parent_messages_for_children(
        parent_phone=session.get('parent_phone', ''),
        children=children,
        limit_per_school=120,
    )
    unread_parent_messages = sum(1 for row in parent_messages if not row.get('is_read'))

    return render_template(
        'parent/parent_messages.html',
        parent_phone=session.get('parent_phone', ''),
        parent_theme_accent=parent_theme_accent,
        children=children,
        parent_messages=parent_messages,
        unread_parent_messages=unread_parent_messages,
    )


@app.route('/parent/student-result')
def parent_view_result():
    if session.get('role') != 'parent':
        return redirect(url_for('parent_portal'))
    student_key = (request.args.get('student_key', '') or '').strip()
    allowed = _parent_allowed_student_keys()
    if not student_key or student_key not in allowed or '::' not in student_key:
        flash('Student access is not allowed for this parent account.', 'error')
        return redirect(url_for('parent_dashboard'))

    school_id, student_id = student_key.split('::', 1)
    school = get_school(school_id) or {}
    current_term = get_current_term(school)
    current_year = (school or {}).get('academic_year', '')
    requested_term = (request.args.get('term', '') or '').strip()
    student = load_student(school_id, student_id)
    if not student:
        flash('Student not found.', 'error')
        return redirect(url_for('parent_dashboard'))

    published_terms = filter_visible_terms_for_student(
        school,
        get_published_terms_for_student(school_id, student_id),
    )
    if not published_terms:
        flash('No published result available yet for this student.', 'error')
        return redirect(url_for('parent_dashboard'))

    if requested_term:
        target_entry = resolve_requested_published_term(
            published_terms,
            requested_term,
            current_term=current_term,
            current_year=current_year,
        )
        if not target_entry:
            flash(f'{requested_term} result is not published for this student.', 'error')
            return redirect(url_for('parent_dashboard'))
    else:
        target_entry = pick_default_published_term(published_terms, current_term, current_year)
    target_term = target_entry['term']
    target_year = target_entry.get('academic_year', '')
    current_term_token = target_entry['token']
    snapshot = load_published_student_result(school_id, student_id, target_term, target_year)
    if not snapshot:
        flash('Published result snapshot not found.', 'error')
        return redirect(url_for('parent_dashboard'))
    record_result_view(school_id, student_id, target_term, snapshot.get('academic_year', target_year))

    exam_config = get_assessment_config_for_class(school_id, snapshot.get('classname', ''))
    class_results = load_published_class_results(school_id, snapshot.get('classname', ''), target_term, target_year, school=school)
    position, subject_positions = build_positions_from_published_results(
        school=school,
        classname=snapshot.get('classname', ''),
        term=target_term,
        class_results=class_results,
        student_id=student_id,
        student_stream=snapshot.get('stream', ''),
        subjects=snapshot.get('subjects', []),
    )
    result_student = {
        'first_name': snapshot.get('firstname', student.get('firstname', '')),
        'student_id': student_id,
        'date_of_birth': (student.get('date_of_birth', '') or '').strip(),
        'gender': (student.get('gender', '') or '').strip(),
        'class_name': snapshot.get('classname', student.get('classname', '')),
        'class_size': len(class_results or []),
        'term': target_term,
        'academic_year': target_year,
        'number_of_subject': snapshot.get('number_of_subject', student.get('number_of_subject', 0)),
        'subjects': snapshot.get('scores', {}),
        'behaviour_assessment': snapshot.get('behaviour_assessment', {}),
        'teacher_comment': snapshot.get('teacher_comment', ''),
        'principal_comment': snapshot.get('principal_comment', ''),
        'average_marks': snapshot.get('average_marks', 0),
        'Grade': snapshot.get('Grade', 'F'),
        'Status': snapshot.get('Status', 'Fail'),
    }
    result_student.update(
        build_result_term_attendance_data(
            school_id=school_id,
            student_id=student_id,
            classname=snapshot.get('classname', student.get('classname', '')),
            term=target_term,
            academic_year=target_year,
        )
    )
    result_max_tests = detect_max_tests_from_scores(snapshot.get('scores', {}), school.get('max_tests', 3))
    signoff = get_result_signoff_details(
        school_id,
        snapshot.get('classname', ''),
        target_term,
        target_year,
    )
    teacher_signature = signoff.get('teacher_signature', '')
    principal_signature = signoff.get('principal_signature', '')
    teacher_name = signoff.get('teacher_name', '')
    principal_name = signoff.get('principal_name', '')
    verify_ctx = build_result_verification_context(
        school_id=school_id,
        student_id=student_id,
        term=target_term,
        academic_year=target_year,
        classname=snapshot.get('classname', ''),
    )
    current_index = next((i for i, item in enumerate(published_terms) if item['token'] == current_term_token), 0)
    prev_term = published_terms[current_index - 1] if current_index > 0 else None
    next_term = published_terms[current_index + 1] if current_index < len(published_terms) - 1 else None
    return render_template(
        'student/student_result.html',
        student=result_student,
        school=school,
        position=position,
        subject_positions=subject_positions,
        published_terms=published_terms,
        current_term_token=current_term_token,
        available_result_classes=[],
        selected_result_class='',
        term_notice='',
        term_view_endpoint='parent_view_result',
        student_key=student_key,
        prev_term=prev_term,
        next_term=next_term,
        teacher_signature=teacher_signature,
        teacher_name=teacher_name,
        principal_signature=principal_signature,
        principal_name=principal_name,
        result_max_tests=result_max_tests,
        exam_config=exam_config,
        verification_url=verify_ctx.get('verification_url', ''),
        verification_qr_url=verify_ctx.get('verification_qr_url', ''),
        now=datetime.now(),
    )

@app.route('/result/download-pdf')
def download_result_pdf():
    """Server-side PDF download for published result."""
    role = (session.get('role') or '').strip().lower()
    if role not in {'student', 'school_admin', 'parent'}:
        flash('Login required to download PDF.', 'error')
        return redirect(url_for('login'))

    requested_term = (request.args.get('term', '') or '').strip()
    selected_class = (request.args.get('class_name', '') or '').strip()
    sid = ''
    school_id = (session.get('school_id') or '').strip()
    if role == 'student':
        sid = (session.get('user_id') or '').strip()
        if not school_id:
            return redirect(url_for('login'))
    else:
        sid = (request.args.get('student_id', '') or '').strip()
        if role == 'school_admin':
            if not school_id:
                return redirect(url_for('login'))
            if not sid:
                flash('Student ID is required.', 'error')
                return redirect(url_for('school_admin_dashboard'))
            if not load_student(school_id, sid):
                flash('Student not found in your school.', 'error')
                return redirect(url_for('school_admin_dashboard'))
        else:
            student_key = (request.args.get('student_key', '') or '').strip()
            allowed = _parent_allowed_student_keys()
            if not student_key or student_key not in allowed or '::' not in student_key:
                flash('Student access is not allowed for this parent account.', 'error')
                return redirect(url_for('parent_dashboard'))
            school_id, sid = student_key.split('::', 1)
            if not load_student(school_id, sid):
                flash('Student not found.', 'error')
                return redirect(url_for('parent_dashboard'))

    school = get_school(school_id) or {}
    current_term = get_current_term(school)
    current_year = (school or {}).get('academic_year', '')
    if role == 'student':
        published_terms = filter_visible_terms_for_student(
            school,
            get_published_terms_for_student(school_id, sid, classname=selected_class),
        )
    else:
        published_terms = get_published_terms_for_student(school_id, sid)
    if not published_terms:
        flash('No published result available for PDF download.', 'error')
        return redirect(url_for('menu'))

    if requested_term:
        target_entry = resolve_requested_published_term(
            published_terms,
            requested_term,
            current_term=current_term,
            current_year=current_year,
        )
        if not target_entry:
            flash('Requested term is not available for this result.', 'error')
            return redirect(url_for('menu'))
    else:
        target_entry = pick_default_published_term(published_terms, current_term, current_year)
    if not target_entry:
        flash('No published result available for PDF download.', 'error')
        return redirect(url_for('menu'))

    target_term = target_entry.get('term', '') or ''
    target_year = target_entry.get('academic_year', '') or ''
    snapshot = load_published_student_result(
        school_id,
        sid,
        target_term,
        target_year,
        classname=selected_class if role == 'student' else '',
    )
    if not snapshot:
        flash('Published result snapshot not found.', 'error')
        return redirect(url_for('menu'))

    class_results = load_published_class_results(
        school_id,
        snapshot.get('classname', ''),
        target_term,
        target_year,
        school=school,
    )
    _position, subject_positions = build_positions_from_published_results(
        school=school,
        classname=snapshot.get('classname', ''),
        term=target_term,
        class_results=class_results,
        student_id=sid,
        student_stream=snapshot.get('stream', ''),
        subjects=snapshot.get('subjects', []),
    )

    exam_config = get_assessment_config_for_class(school_id, snapshot.get('classname', ''))
    combined_exam = (exam_config.get('exam_mode') or 'separate').strip().lower() == 'combined'
    scores = snapshot.get('scores', {}) if isinstance(snapshot.get('scores', {}), dict) else {}
    show_positions = bool((school or {}).get('show_positions', 1))
    signoff = get_result_signoff_details(
        school_id,
        snapshot.get('classname', ''),
        target_term,
        target_year,
    )

    lines = [
        f"School: {(school or {}).get('school_name', '')}",
        f"Student: {snapshot.get('firstname', '')} ({sid})",
        f"Class: {snapshot.get('classname', '')}",
        f"Term: {target_term}" + (f"  Year: {target_year}" if target_year else ''),
        f"Average: {_format_mark(snapshot.get('average_marks', 0))}  Grade: {snapshot.get('Grade', 'F')}  Status: {snapshot.get('Status', 'Fail')}",
        "",
        "Subject | Total Exam | Highest | Lowest | Total | Grade" + (" | Position" if show_positions else ""),
    ]
    subject_rows = []

    for subject, s in scores.items():
        if not isinstance(s, dict):
            continue
        if combined_exam:
            total_exam = _coerce_number(s.get('exam_score', s.get('total_exam', 0)), 0.0)
        else:
            total_exam = _coerce_number(s.get('objective', 0), 0.0) + _coerce_number(s.get('theory', 0), 0.0)
        total_score = _coerce_number(s.get('overall_mark', s.get('total', 0)), 0.0)
        grade = (s.get('grade') or '').strip() or grade_from_score(total_score, get_grade_config(school_id))
        sp = subject_positions.get(subject) if isinstance(subject_positions, dict) else None
        pos = f"{sp.get('pos', '-')}/{sp.get('size', '-')}" if isinstance(sp, dict) else '-'
        high = _format_mark(sp.get('highest')) if isinstance(sp, dict) else '-'
        low = _format_mark(sp.get('lowest')) if isinstance(sp, dict) else '-'
        subject_rows.append({
            'subject': subject,
            'total_exam': total_exam,
            'highest': sp.get('highest') if isinstance(sp, dict) else None,
            'lowest': sp.get('lowest') if isinstance(sp, dict) else None,
            'total': total_score,
            'grade': grade,
            'position': pos,
        })
        if show_positions:
            lines.append(
                f"{subject} | {_format_mark(total_exam)} | {high} | {low} | {_format_mark(total_score)} | {grade} | {pos}"
            )
        else:
            lines.append(
                f"{subject} | {_format_mark(total_exam)} | {high} | {low} | {_format_mark(total_score)} | {grade}"
            )

    rich_report = {
        'school_name': (school or {}).get('school_name', ''),
        'student_name': snapshot.get('firstname', ''),
        'student_id': sid,
        'class_name': snapshot.get('classname', ''),
        'term': target_term,
        'year': target_year,
        'average': snapshot.get('average_marks', 0),
        'grade': snapshot.get('Grade', 'F'),
        'status': snapshot.get('Status', 'Fail'),
        'teacher_name': signoff.get('teacher_name', ''),
        'principal_name': signoff.get('principal_name', ''),
        'teacher_signature': signoff.get('teacher_signature', ''),
        'principal_signature': signoff.get('principal_signature', ''),
        'generated_on': datetime.now().strftime('%Y-%m-%d %H:%M'),
        'subject_rows': subject_rows,
        'show_positions': show_positions,
    }
    pdf_bytes = _build_rich_result_pdf_reportlab(rich_report) or _build_simple_pdf(lines)
    token_term = re.sub(r'[^A-Za-z0-9_-]+', '_', (target_term or 'term').strip())
    token_year = re.sub(r'[^A-Za-z0-9_-]+', '_', (target_year or '').strip())
    token_sid = re.sub(r'[^A-Za-z0-9_-]+', '_', (sid or 'student').strip())
    filename = f"result_{token_sid}_{token_term}{('_' + token_year) if token_year else ''}.pdf"
    return Response(
        pdf_bytes,
        mimetype='application/pdf',
        headers={'Content-Disposition': f'attachment; filename=\"{filename}\"'},
    )

@app.route('/teacher/student-result')
def teacher_student_result():
    """Teacher can view published result only for students in classes assigned to that teacher."""
    if session.get('role') != 'teacher':
        return redirect(url_for('login'))

    school_id = (session.get('school_id') or '').strip()
    teacher_id = (session.get('user_id') or '').strip()
    sid = (request.args.get('student_id', '') or '').strip()
    requested_term = (request.args.get('term', '') or '').strip()
    if not school_id or not teacher_id or not sid:
        flash('Select a student first.', 'error')
        return redirect(url_for('teacher_dashboard'))

    student = load_student(school_id, sid)
    if not student:
        flash('Student not found in your school.', 'error')
        return redirect(url_for('teacher_dashboard'))

    school = get_school(school_id) or {}
    current_term = get_current_term(school)
    current_year = (school or {}).get('academic_year', '')
    published_terms = get_published_terms_for_student(school_id, sid)
    if not published_terms:
        flash('No published result available yet for this student.', 'error')
        return redirect(url_for('view_students'))

    if requested_term:
        target_entry = resolve_requested_published_term(
            published_terms,
            requested_term,
            current_term=current_term,
            current_year=current_year,
        )
        if not target_entry:
            flash(f'{requested_term} result is not published for this student.', 'error')
            return redirect(url_for('teacher_student_result', student_id=sid))
    else:
        target_entry = pick_default_published_term(published_terms, current_term, current_year)

    target_term = target_entry['term']
    target_year = target_entry.get('academic_year', '')
    current_term_token = target_entry['token']

    snapshot = load_published_student_result(school_id, sid, target_term, target_year)
    if not snapshot:
        flash('Published result snapshot not found.', 'error')
        return redirect(url_for('view_students'))

    snapshot_class = (snapshot.get('classname', '') or '').strip()
    if not teacher_has_class_access(
        school_id,
        teacher_id,
        snapshot_class,
        term=target_term,
        academic_year=target_year,
    ):
        flash('You can only view published results for classes assigned to you.', 'error')
        return redirect(url_for('view_students'))

    exam_config = get_assessment_config_for_class(school_id, snapshot_class)
    class_results = load_published_class_results(
        school_id,
        snapshot_class,
        target_term,
        target_year,
        school=school,
    )
    position, subject_positions = build_positions_from_published_results(
        school=school,
        classname=snapshot_class,
        term=target_term,
        class_results=class_results,
        student_id=sid,
        student_stream=snapshot.get('stream', ''),
        subjects=snapshot.get('subjects', []),
    )

    result_student = {
        'first_name': snapshot.get('firstname', student.get('firstname', '')),
        'student_id': sid,
        'date_of_birth': (student.get('date_of_birth', '') or '').strip(),
        'gender': (student.get('gender', '') or '').strip(),
        'class_name': snapshot_class,
        'class_size': len(class_results or []),
        'term': target_term,
        'academic_year': target_year,
        'number_of_subject': snapshot.get('number_of_subject', student.get('number_of_subject', 0)),
        'subjects': snapshot.get('scores', {}),
        'behaviour_assessment': snapshot.get('behaviour_assessment', {}),
        'teacher_comment': snapshot.get('teacher_comment', ''),
        'principal_comment': snapshot.get('principal_comment', ''),
        'average_marks': snapshot.get('average_marks', 0),
        'Grade': snapshot.get('Grade', 'F'),
        'Status': snapshot.get('Status', 'Fail'),
    }
    result_student.update(
        build_result_term_attendance_data(
            school_id=school_id,
            student_id=sid,
            classname=snapshot_class,
            term=target_term,
            academic_year=target_year,
        )
    )
    result_max_tests = detect_max_tests_from_scores(snapshot.get('scores', {}), school.get('max_tests', 3))
    signoff = get_result_signoff_details(
        school_id,
        snapshot_class,
        target_term,
        target_year,
    )
    teacher_signature = signoff.get('teacher_signature', '')
    principal_signature = signoff.get('principal_signature', '')
    teacher_name = signoff.get('teacher_name', '')
    principal_name = signoff.get('principal_name', '')
    verify_ctx = build_result_verification_context(
        school_id=school_id,
        student_id=sid,
        term=target_term,
        academic_year=target_year,
        classname=snapshot_class,
    )
    current_index = next((i for i, item in enumerate(published_terms) if item['token'] == current_term_token), 0)
    prev_term = published_terms[current_index - 1] if current_index > 0 else None
    next_term = published_terms[current_index + 1] if current_index < len(published_terms) - 1 else None
    return render_template(
        'student/student_result.html',
        student=result_student,
        school=school,
        position=position,
        subject_positions=subject_positions,
        published_terms=published_terms,
        current_term_token=current_term_token,
        available_result_classes=[],
        selected_result_class='',
        term_notice='',
        term_view_endpoint='teacher_student_result',
        prev_term=prev_term,
        next_term=next_term,
        teacher_signature=teacher_signature,
        teacher_name=teacher_name,
        principal_signature=principal_signature,
        principal_name=principal_name,
        result_max_tests=result_max_tests,
        exam_config=exam_config,
        verification_url=verify_ctx.get('verification_url', ''),
        verification_qr_url=verify_ctx.get('verification_qr_url', ''),
        now=datetime.now(),
    )

@app.route('/parent/compare-results')
def parent_compare_results():
    try:
        if session.get('role') != 'parent':
            return redirect(url_for('parent_portal'))
        student_key = (request.args.get('student_key', '') or '').strip()
        allowed = _parent_allowed_student_keys()
        if not student_key or student_key not in allowed or '::' not in student_key:
            flash('Student access is not allowed for this parent account.', 'error')
            return redirect(url_for('parent_dashboard'))

        school_id, student_id = student_key.split('::', 1)
        school = get_school(school_id) or {}
        student = load_student(school_id, student_id)
        if not student:
            flash('Student not found.', 'error')
            return redirect(url_for('parent_dashboard'))

        current_term = get_current_term(school)
        current_year = (school or {}).get('academic_year', '')
        published_terms = filter_visible_terms_for_student(
            school,
            get_published_terms_for_student(school_id, student_id),
        )
        published_terms_sorted = sorted(
            list(published_terms or []),
            key=lambda x: ((_academic_year_start(x.get('academic_year')) or 0), term_sort_value(x.get('term'))),
        )
        if len(published_terms_sorted) < 2:
            flash('At least two published terms are required for comparison.', 'error')
            return redirect(url_for('parent_view_result', student_key=student_key))

        term_a_raw = (request.args.get('term_a', '') or '').strip()
        term_b_raw = (request.args.get('term_b', '') or '').strip()
        selected_a = resolve_requested_published_term(
            published_terms_sorted,
            term_a_raw,
            current_term=current_term,
            current_year=current_year,
        ) if term_a_raw else published_terms_sorted[-2]
        selected_b = resolve_requested_published_term(
            published_terms_sorted,
            term_b_raw,
            current_term=current_term,
            current_year=current_year,
        ) if term_b_raw else published_terms_sorted[-1]
        if not selected_a or not selected_b:
            flash('Invalid terms selected for comparison.', 'error')
            return redirect(url_for('parent_compare_results', student_key=student_key))
        if selected_a.get('token') == selected_b.get('token'):
            flash('Select two different terms to compare.', 'error')
            return redirect(url_for('parent_compare_results', student_key=student_key))

        snap_a = load_published_student_result(
            school_id,
            student_id,
            selected_a.get('term', ''),
            selected_a.get('academic_year', ''),
        )
        snap_b = load_published_student_result(
            school_id,
            student_id,
            selected_b.get('term', ''),
            selected_b.get('academic_year', ''),
        )
        if not snap_a or not snap_b:
            flash('Could not load one or both selected term snapshots.', 'error')
            return redirect(url_for('parent_view_result', student_key=student_key))

        scores_a = snap_a.get('scores', {}) if isinstance(snap_a.get('scores', {}), dict) else {}
        scores_b = snap_b.get('scores', {}) if isinstance(snap_b.get('scores', {}), dict) else {}
        subjects = sorted(
            set(normalize_subjects_list(list(scores_a.keys()))) | set(normalize_subjects_list(list(scores_b.keys()))),
            key=lambda value: str(value).lower(),
        )
        grade_cfg = get_grade_config(school_id)
        rows = []
        for subject in subjects:
            block_a = get_subject_score_block(scores_a, subject)
            block_b = get_subject_score_block(scores_b, subject)
            score_a = round(subject_overall_mark(block_a), 2) if isinstance(block_a, dict) and block_a else None
            score_b = round(subject_overall_mark(block_b), 2) if isinstance(block_b, dict) and block_b else None
            delta = round((score_b - score_a), 2) if isinstance(score_a, (int, float)) and isinstance(score_b, (int, float)) else None
            grade_a = ''
            grade_b = ''
            if isinstance(block_a, dict) and block_a:
                grade_a = (block_a.get('grade') or '').strip()
            if isinstance(block_b, dict) and block_b:
                grade_b = (block_b.get('grade') or '').strip()
            if not grade_a and isinstance(score_a, (int, float)):
                grade_a = grade_from_score(score_a, grade_cfg)
            if not grade_b and isinstance(score_b, (int, float)):
                grade_b = grade_from_score(score_b, grade_cfg)
            rows.append({
                'subject': subject,
                'score_a': score_a,
                'score_b': score_b,
                'grade_a': grade_a,
                'grade_b': grade_b,
                'delta': delta,
            })

        avg_a = round(float(snap_a.get('average_marks', 0) or 0), 2)
        avg_b = round(float(snap_b.get('average_marks', 0) or 0), 2)
        avg_delta = round(avg_b - avg_a, 2)

        parent_phone = session.get('parent_phone', '')
        children = []
        for key in sorted(allowed):
            if '::' not in key:
                continue
            sid, stid = key.split('::', 1)
            st = load_student(sid, stid)
            school_row = get_school(sid) or {}
            if not st:
                continue
            children.append({
                'key': key,
                'school_id': sid,
                'school_name': school_row.get('school_name', sid),
                'classname': st.get('classname', ''),
                'stream': st.get('stream', ''),
                'firstname': st.get('firstname', stid),
            })
        unread_parent_messages = 0
        try:
            parent_messages = get_parent_messages_for_children(
                parent_phone=parent_phone,
                children=children,
                limit_per_school=80,
            )
            unread_parent_messages = sum(1 for row in parent_messages if not row.get('is_read'))
        except Exception as exc:
            logging.warning("Parent compare messages fetch failed: %s", exc)
            unread_parent_messages = 0
        parent_theme_accent = normalize_hex_color((school or {}).get('theme_accent_color', ''), '#1F7A8C')

        return render_template(
            'parent/parent_compare_results.html',
            school=school,
            student_key=student_key,
            student=student,
            selected_a=selected_a,
            selected_b=selected_b,
            published_terms=published_terms_sorted,
            rows=rows,
            avg_a=avg_a,
            avg_b=avg_b,
            avg_delta=avg_delta,
            children=children,
            unread_parent_messages=unread_parent_messages,
            parent_theme_accent=parent_theme_accent,
        )
    except Exception as exc:
        logging.exception("Parent compare results failed for student_key=%s", request.args.get('student_key', ''))
        flash(f'Could not open term comparison: {exc}', 'error')
        return redirect(url_for('parent_dashboard'))

@app.route('/school-admin/student-result')
def school_admin_student_result():
    """School admin can view any student's published result and switch terms."""
    if session.get('role') != 'school_admin':
        return redirect(url_for('login'))

    school_id = session.get('school_id')
    sid = (request.args.get('student_id', '') or '').strip()
    requested_term = (request.args.get('term', '') or '').strip()
    if not school_id or not sid:
        flash('Select a student first.', 'error')
        return redirect(url_for('school_admin_dashboard'))

    student = load_student(school_id, sid)
    if not student:
        flash('Student not found in your school.', 'error')
        return redirect(url_for('school_admin_dashboard'))

    school = get_school(school_id) or {}
    current_term = get_current_term(school)
    current_year = (school or {}).get('academic_year', '')
    published_terms = get_published_terms_for_student(school_id, sid)
    if not published_terms:
        flash('No published result available yet for this student.', 'error')
        return redirect(url_for('school_admin_dashboard'))

    if requested_term:
        target_entry = resolve_requested_published_term(
            published_terms,
            requested_term,
            current_term=current_term,
            current_year=current_year,
        )
        if not target_entry:
            flash(f'{requested_term} result is not published for this student.', 'error')
            return redirect(url_for('school_admin_student_result', student_id=sid))
    else:
        target_entry = pick_default_published_term(published_terms, current_term, current_year)

    target_term = target_entry['term']
    target_year = target_entry.get('academic_year', '')
    current_term_token = target_entry['token']

    snapshot = load_published_student_result(school_id, sid, target_term, target_year)
    if not snapshot:
        flash('Published result snapshot not found.', 'error')
        return redirect(url_for('school_admin_dashboard'))

    exam_config = get_assessment_config_for_class(school_id, snapshot.get('classname', ''))
    class_results = load_published_class_results(school_id, snapshot.get('classname', ''), target_term, target_year, school=school)
    position, subject_positions = build_positions_from_published_results(
        school=school,
        classname=snapshot.get('classname', ''),
        term=target_term,
        class_results=class_results,
        student_id=sid,
        student_stream=snapshot.get('stream', ''),
        subjects=snapshot.get('subjects', []),
    )

    result_student = {
        'first_name': snapshot.get('firstname', student.get('firstname', '')),
        'student_id': sid,
        'date_of_birth': (student.get('date_of_birth', '') or '').strip(),
        'gender': (student.get('gender', '') or '').strip(),
        'class_name': snapshot.get('classname', student.get('classname', '')),
        'class_size': len(class_results or []),
        'term': target_term,
        'academic_year': target_year,
        'number_of_subject': snapshot.get('number_of_subject', student.get('number_of_subject', 0)),
        'subjects': snapshot.get('scores', {}),
        'behaviour_assessment': snapshot.get('behaviour_assessment', {}),
        'teacher_comment': snapshot.get('teacher_comment', ''),
        'principal_comment': snapshot.get('principal_comment', ''),
        'average_marks': snapshot.get('average_marks', 0),
        'Grade': snapshot.get('Grade', 'F'),
        'Status': snapshot.get('Status', 'Fail'),
    }
    result_student.update(
        build_result_term_attendance_data(
            school_id=school_id,
            student_id=sid,
            classname=snapshot.get('classname', student.get('classname', '')),
            term=target_term,
            academic_year=target_year,
        )
    )
    result_max_tests = detect_max_tests_from_scores(snapshot.get('scores', {}), school.get('max_tests', 3))
    signoff = get_result_signoff_details(
        school_id,
        snapshot.get('classname', ''),
        target_term,
        target_year,
    )
    teacher_signature = signoff.get('teacher_signature', '')
    principal_signature = signoff.get('principal_signature', '')
    teacher_name = signoff.get('teacher_name', '')
    principal_name = signoff.get('principal_name', '')
    verify_ctx = build_result_verification_context(
        school_id=school_id,
        student_id=sid,
        term=target_term,
        academic_year=target_year,
        classname=snapshot.get('classname', ''),
    )
    current_index = next((i for i, item in enumerate(published_terms) if item['token'] == current_term_token), 0)
    prev_term = published_terms[current_index - 1] if current_index > 0 else None
    next_term = published_terms[current_index + 1] if current_index < len(published_terms) - 1 else None

    return render_template(
        'student/student_result.html',
        student=result_student,
        school=school,
        position=position,
        subject_positions=subject_positions,
        published_terms=published_terms,
        current_term_token=current_term_token,
        available_result_classes=[],
        selected_result_class='',
        term_notice='',
        term_view_endpoint='school_admin_student_result',
        prev_term=prev_term,
        next_term=next_term,
        teacher_signature=teacher_signature,
        teacher_name=teacher_name,
        principal_signature=principal_signature,
        principal_name=principal_name,
        result_max_tests=result_max_tests,
        exam_config=exam_config,
        verification_url=verify_ctx.get('verification_url', ''),
        verification_qr_url=verify_ctx.get('verification_qr_url', ''),
        now=datetime.now()
    )

@app.route('/school-admin/correct-result', methods=['GET', 'POST'])
def school_admin_correct_result():
    """Allow school admin to correct a published student result and republish."""
    if session.get('role') != 'school_admin':
        return redirect(url_for('login'))

    school_id = session.get('school_id')
    sid = (request.values.get('student_id', '') or '').strip()
    requested_term = (request.values.get('term', '') or '').strip()
    if not school_id or not sid:
        flash('Student ID is required.', 'error')
        return redirect(url_for('school_admin_dashboard'))

    student = load_student(school_id, sid)
    if not student:
        flash('Student not found in your school.', 'error')
        return redirect(url_for('school_admin_dashboard'))

    school = get_school(school_id) or {}
    current_term = get_current_term(school)
    current_year = (school or {}).get('academic_year', '')
    published_terms = get_published_terms_for_student(school_id, sid)
    if not published_terms:
        flash('No published result available for correction.', 'error')
        return redirect(url_for('school_admin_dashboard'))
    target_entry = resolve_requested_published_term(
        published_terms,
        requested_term,
        current_term=current_term,
        current_year=current_year,
    ) if requested_term else pick_default_published_term(published_terms, current_term, current_year)
    if not target_entry:
        flash('Selected published term was not found.', 'error')
        return redirect(url_for('school_admin_student_result', student_id=sid))

    target_term = target_entry.get('term', '')
    target_year = target_entry.get('academic_year', '')
    target_token = target_entry.get('token', _term_token(target_year, target_term))
    snapshot = load_published_student_result(school_id, sid, target_term, target_year)
    if not snapshot:
        flash('Published snapshot not found for correction.', 'error')
        return redirect(url_for('school_admin_student_result', student_id=sid, term=target_token))
    exam_config = get_assessment_config_for_class(school_id, snapshot.get('classname', ''))

    if request.method == 'POST':
        classname_for_lock = snapshot.get('classname', student.get('classname', ''))
        term_lock = get_term_edit_lock_status(school_id, classname_for_lock, target_term, target_year)
        if term_lock.get('locked'):
            flash('Published term is locked for edits. Unlock it temporarily from Publish Results page.', 'error')
            return redirect(url_for('school_admin_correct_result', student_id=sid, term=target_token))
        correction_reason = (request.form.get('correction_reason', '') or '').strip()
        if not correction_reason:
            flash('Reason is required before changing a published result.', 'error')
            return redirect(url_for('school_admin_correct_result', student_id=sid, term=target_token))
        correction_reason = re.sub(r'\s+', ' ', correction_reason).strip()[:500]
        previous_scores_for_audit = json.loads(
            json.dumps(snapshot.get('scores', {}) if isinstance(snapshot.get('scores', {}), dict) else {})
        )
        scores = json.loads(json.dumps(snapshot.get('scores', {}) if isinstance(snapshot.get('scores', {}), dict) else {}))
        allowed_subjects = normalize_subjects_list(snapshot.get('subjects', []) or [])
        posted_subjects = normalize_subjects_list(request.form.getlist('subject_name'))
        invalid_subjects = [s for s in posted_subjects if s not in allowed_subjects]
        if invalid_subjects:
            flash('Invalid subject payload detected. Reload and try again.', 'error')
            return redirect(url_for('school_admin_correct_result', student_id=sid, term=target_token))
        subjects = list(allowed_subjects)
        grade_cfg = get_grade_config(school_id)
        for idx, subject in enumerate(subjects):
            block = scores.get(subject, {}) if isinstance(scores.get(subject, {}), dict) else {}
            total_text = (request.form.get(f'subject_total_{idx}', '') or '').strip()
            if not total_text:
                continue
            try:
                total_value = float(total_text)
            except Exception:
                flash(f'Invalid total score for {subject}.', 'error')
                return redirect(url_for('school_admin_correct_result', student_id=sid, term=target_token))
            if not math.isfinite(total_value) or total_value < 0 or total_value > 100:
                flash(f'{subject} total score must be between 0 and 100.', 'error')
                return redirect(url_for('school_admin_correct_result', student_id=sid, term=target_token))
            total_value = round(total_value, 2)
            total_test = _coerce_number(block.get('total_test', 0), 0.0)
            if total_test > total_value:
                total_test = total_value
                block['total_test'] = total_test
            exam_mode = ((block.get('exam_mode') or exam_config.get('exam_mode') or 'separate')).strip().lower()
            exam_total_max = max(0.0, safe_float(exam_config.get('exam_score_max', 70), 70))
            computed_total_exam = round(max(0.0, total_value - total_test), 2)
            if computed_total_exam > exam_total_max:
                flash(
                    f'{subject} exam component cannot exceed {exam_total_max:g} for current exam configuration.',
                    'error',
                )
                return redirect(url_for('school_admin_correct_result', student_id=sid, term=target_token))
            block['total_exam'] = computed_total_exam
            if exam_mode == 'combined':
                block['objective'] = 0
                block['theory'] = 0
                block['exam_score'] = block['total_exam']
                block['exam_mode'] = 'combined'
            else:
                objective_max = max(0.0, safe_float(exam_config.get('objective_max', 30), 30))
                theory_max = max(0.0, safe_float(exam_config.get('theory_max', 40), 40))
                objective = min(block['total_exam'], objective_max)
                theory = round(block['total_exam'] - objective, 2)
                if theory > theory_max:
                    theory = theory_max
                    objective = round(block['total_exam'] - theory, 2)
                if objective < 0 or objective > objective_max or theory < 0 or theory > theory_max:
                    flash(
                        f'{subject} exam split does not fit configured objective/theory limits.',
                        'error',
                    )
                    return redirect(url_for('school_admin_correct_result', student_id=sid, term=target_token))
                block['objective'] = round(objective, 2)
                block['theory'] = round(theory, 2)
                block.pop('exam_score', None)
                block['exam_mode'] = 'separate'
            block['overall_mark'] = total_value
            block['total_score'] = total_value
            block['grade'] = grade_from_score(total_value, grade_cfg)
            scores[subject] = block

        teacher_comment = (request.form.get('teacher_comment', '') or '').strip()[:1500]
        principal_comment = (request.form.get('principal_comment', '') or '').strip()[:1500]
        average_marks = compute_average_marks_from_scores(scores, subjects=subjects)
        grade = grade_from_score(average_marks, grade_cfg)
        status = status_from_score(average_marks, grade_cfg)
        classname = snapshot.get('classname', student.get('classname', ''))

        try:
            with db_connection(commit=True) as conn:
                c = conn.cursor()
                db_execute(
                    c,
                    """UPDATE published_student_results
                       SET scores = ?, teacher_comment = ?, principal_comment = ?,
                           average_marks = ?, grade = ?, status = ?, published_at = CURRENT_TIMESTAMP
                       WHERE school_id = ? AND student_id = ? AND term = ?
                         AND COALESCE(academic_year, '') = COALESCE(?, '')
                         AND LOWER(classname) = LOWER(?)""",
                    (
                        json.dumps(scores),
                        teacher_comment,
                        principal_comment,
                        float(average_marks),
                        grade,
                        status,
                        school_id,
                        sid,
                        target_term,
                        target_year or '',
                        classname,
                    ),
                )
                audit_student_score_changes_with_cursor(
                    c=c,
                    school_id=school_id,
                    student_id=sid,
                    classname=classname,
                    term=target_term,
                    academic_year=target_year or '',
                    old_scores=previous_scores_for_audit,
                    new_scores=scores,
                    changed_by=(session.get('user_id') or ''),
                    changed_by_role='school_admin',
                    change_source=f'school_admin_correction: {correction_reason[:180]}',
                    change_reason=correction_reason,
                    subjects_scope=subjects,
                )
            pub_row = get_result_publication_row(school_id, classname, target_term, target_year or '') or {}
            set_result_published(
                school_id,
                classname,
                target_term,
                target_year or '',
                pub_row.get('teacher_id', '') or '',
                True,
                teacher_name=pub_row.get('teacher_name', '') or '',
                principal_name=(school.get('principal_name', '') or '').strip(),
            )
            flash('Result corrected and republished successfully.', 'success')
        except Exception as exc:
            flash(f'Failed to correct/republish result: {exc}', 'error')
            return redirect(url_for('school_admin_correct_result', student_id=sid, term=target_token))

        return redirect(url_for('school_admin_student_result', student_id=sid, term=target_token))

    subject_rows = []
    for subject in (snapshot.get('subjects', []) or []):
        block = (snapshot.get('scores', {}) or {}).get(subject, {})
        subject_rows.append({
            'subject': subject,
            'total': round(subject_overall_mark(block), 2) if isinstance(block, dict) else 0.0,
            'grade': (block.get('grade', '') if isinstance(block, dict) else ''),
        })
    return render_template(
        'school/school_admin_correct_result.html',
        school=school,
        student_id=sid,
        student_name=snapshot.get('firstname', student.get('firstname', '')),
        classname=snapshot.get('classname', student.get('classname', '')),
        term=target_term,
        academic_year=target_year,
        term_token=target_token,
        subject_rows=subject_rows,
        teacher_comment=snapshot.get('teacher_comment', ''),
        principal_comment=snapshot.get('principal_comment', ''),
    )

@app.route('/school-admin/unpublish-results', methods=['POST'])
def school_admin_unpublish_results():
    """Allow school admin to unpublish a class result after password confirmation."""
    if session.get('role') != 'school_admin':
        return redirect(url_for('login'))

    school_id = session.get('school_id')
    sid = (request.form.get('student_id', '') or '').strip()
    classname = (request.form.get('classname', '') or '').strip()
    term_token = (request.form.get('term_token', '') or '').strip()
    admin_password = (request.form.get('admin_password', '') or '').strip()
    client_ip = get_client_ip()
    lock_endpoint = 'school_admin_unpublish'

    fallback = url_for('view_students')
    if sid:
        fallback = url_for('school_admin_student_result', student_id=sid, term=term_token)

    if not school_id:
        flash('School context is missing. Login again.', 'error')
        return redirect(url_for('login'))
    if not classname or not term_token:
        flash('Class and term are required to unpublish.', 'error')
        return redirect(fallback)
    if not admin_password:
        flash('Enter your school admin password to unpublish result.', 'error')
        return redirect(fallback)
    blocked, wait_minutes = is_login_blocked(lock_endpoint, session.get('user_id', ''), client_ip)
    if blocked:
        flash(f'Too many failed password attempts. Try again in about {wait_minutes} minute(s).', 'error')
        return redirect(fallback)

    admin_user = get_user(session.get('user_id', ''))
    if not admin_user or (admin_user.get('role') or '').strip().lower() != 'school_admin':
        flash('School admin account could not be verified. Login again.', 'error')
        return redirect(url_for('login'))
    if not check_password(admin_user.get('password_hash', ''), admin_password):
        register_failed_login(lock_endpoint, session.get('user_id', ''), client_ip)
        flash('Invalid school admin password.', 'error')
        return redirect(fallback)
    clear_failed_login(lock_endpoint, session.get('user_id', ''), client_ip)

    target_year, target_term = _parse_term_token(term_token)
    target_term = (target_term or '').strip()
    target_year = (target_year or '').strip()
    if not target_term:
        flash('Invalid term selected for unpublish.', 'error')
        return redirect(fallback)

    if not is_result_published(school_id, classname, target_term, target_year):
        flash(f'{classname} ({target_term}) is already not published.', 'error')
        return redirect(fallback)

    pub_row = get_result_publication_row(school_id, classname, target_term, target_year) or {}
    try:
        with db_connection(commit=True) as conn:
            c = conn.cursor()
            _set_result_published_with_cursor(
                c=c,
                school_id=school_id,
                classname=classname,
                term=target_term,
                academic_year=target_year,
                teacher_id=pub_row.get('teacher_id', '') or '',
                is_published=False,
                teacher_name=pub_row.get('teacher_name', '') or '',
                principal_name=pub_row.get('principal_name', '') or '',
            )
            db_execute(
                c,
                """DELETE FROM published_student_results
                   WHERE school_id = ? AND LOWER(classname) = LOWER(?) AND term = ?
                     AND COALESCE(academic_year, '') = COALESCE(?, '')""",
                (school_id, classname, target_term, target_year or ''),
            )
            try:
                db_execute(
                    c,
                    """INSERT INTO term_edit_locks
                       (school_id, classname, term, academic_year, is_locked, unlocked_until, unlock_reason, unlocked_by, updated_at)
                       VALUES (?, ?, ?, ?, 0, NULL, 'Unpublished', ?, CURRENT_TIMESTAMP)
                       ON CONFLICT(school_id, classname, term, academic_year) DO UPDATE SET
                         is_locked = 0,
                         unlocked_until = NULL,
                         unlock_reason = 'Unpublished',
                         unlocked_by = excluded.unlocked_by,
                         updated_at = CURRENT_TIMESTAMP""",
                    (school_id, classname, target_term, target_year or '', session.get('user_id', '') or ''),
                )
            except Exception as lock_exc:
                logging.warning("Failed to update term_edit_locks during unpublish: %s", lock_exc)
    except Exception as exc:
        flash(f'Failed to unpublish result: {exc}', 'error')
        return redirect(fallback)

    flash(f'Unpublished {classname} ({target_term}). It is now hidden until republished.', 'success')
    return redirect(url_for('view_students', **{'class': classname, 'term': target_term}))

# ==================== PUBLIC STUDENT PORTAL ====================

@app.route('/verify-result')
def verify_result_qr():
    token = (request.args.get('token', '') or '').strip()
    payload = parse_result_verification_token(token)
    if not payload:
        return render_template('shared/result_verification.html', verified=False, reason='Invalid verification token.', details={})

    school_id = (payload.get('school_id') or '').strip()
    student_id = (payload.get('student_id') or '').strip()
    term = (payload.get('term') or '').strip()
    academic_year = (payload.get('academic_year') or '').strip()
    classname = (payload.get('classname') or '').strip()

    if not school_id or not student_id or not term:
        return render_template('shared/result_verification.html', verified=False, reason='Incomplete verification payload.', details={})

    snapshot = load_published_student_result(school_id, student_id, term, academic_year, classname=classname)
    if not snapshot:
        return render_template(
            'shared/result_verification.html',
            verified=False,
            reason='Result record not found or not published.',
            details={
                'school_id': school_id,
                'student_id': student_id,
                'term': term,
                'academic_year': academic_year,
            },
        )

    school = get_school(school_id) or {}
    details = {
        'school_name': (school.get('school_name') or school_id),
        'student_name': snapshot.get('firstname', ''),
        'student_id': student_id,
        'class_name': snapshot.get('classname', ''),
        'term': term,
        'academic_year': academic_year or snapshot.get('academic_year', ''),
        'average_marks': snapshot.get('average_marks', 0),
        'grade': snapshot.get('Grade', ''),
        'status': snapshot.get('Status', ''),
        'published_at': snapshot.get('published_at', ''),
    }
    return render_template('shared/result_verification.html', verified=True, reason='', details=details)

@app.route('/student-portal')
def student_portal():
    """Public portal for students to check results."""
    return render_template('student/student_portal.html')

@app.route('/check-result', methods=['POST'])
def check_result():
    """Check student result by student ID and password."""
    student_id = request.form.get('student_id', '').strip()
    password = request.form.get('password', '')
    client_ip = get_client_ip()
    
    if not student_id or not password:
        flash('Please enter your Student ID and password.', 'error')
        return redirect(url_for('student_portal'))
    blocked, wait_minutes = is_login_blocked('check_result', student_id, client_ip)
    if blocked:
        flash(f'Too many failed login attempts. Try again in about {wait_minutes} minute(s).', 'error')
        return redirect(url_for('student_portal'))
    requested_term = (request.form.get('term', '') or '').strip()
    
    # Authenticate user first, then resolve exact school row for that user.
    user = get_user(student_id)
    if not user or user.get('role') != 'student' or not check_password(user.get('password_hash', ''), password):
        register_failed_login('check_result', student_id, client_ip)
        record_login_audit(student_id, 'student', None, 'check_result', False, 'invalid_credentials')
        flash('Invalid Student ID or password.', 'error')
        return redirect(url_for('student_portal'))
    school_id = (user.get('school_id') or '').strip()
    if not school_id:
        school_id = find_student_school_id(student_id) or ''
    if not school_id:
        register_failed_login('check_result', student_id, client_ip)
        record_login_audit(student_id, 'student', None, 'check_result', False, 'missing_school')
        flash('Invalid Student ID or password.', 'error')
        return redirect(url_for('student_portal'))

    with db_connection() as conn:
        c = conn.cursor()
        db_execute(
            c,
            (
                "SELECT s.school_id, s.student_id, s.firstname, s.classname, s.term, s.stream, "
                "s.number_of_subject, s.subjects, s.scores, sc.current_term "
                "FROM students s "
                "JOIN schools sc ON sc.school_id = s.school_id "
                "WHERE s.school_id = ? AND s.student_id = ? "
                "LIMIT 1"
            ),
            (school_id, student_id),
        )
        row = c.fetchone()
    if not row:
        register_failed_login('check_result', student_id, client_ip)
        record_login_audit(student_id, 'student', school_id, 'check_result', False, 'student_row_not_found')
        flash('Invalid Student ID or password.', 'error')
        return redirect(url_for('student_portal'))

    school_id, sid, firstname, classname, term, stream, number_of_subject, subjects_str, scores_str, current_term = row
    if user.get('school_id') != school_id:
        update_user_school_id_only(user.get('username'), school_id)
    clear_failed_login('check_result', student_id, client_ip)
    record_login_audit(student_id, 'student', school_id, 'check_result', True, '')
    school = get_school(school_id) or {}
    published_terms = filter_visible_terms_for_student(school, get_published_terms_for_student(school_id, sid))
    if not published_terms:
        if safe_int((school or {}).get('operations_enabled', 1), 1):
            flash('No published result available yet.', 'error')
        else:
            flash('Current term results are hidden while operations are OFF. Only previous published results are available.', 'error')
        return redirect(url_for('student_portal'))
    if requested_term:
        current_year = (school or {}).get('academic_year', '')
        target_entry = resolve_requested_published_term(
            published_terms,
            requested_term,
            current_term=current_term,
            current_year=current_year,
        )
        if not target_entry:
            flash(f'{requested_term} result is not published for this student.', 'error')
            return redirect(url_for('student_portal'))
    else:
        current_year = (school or {}).get('academic_year', '')
        target_entry = pick_default_published_term(published_terms, current_term, current_year)
    target_term = target_entry['term']
    target_year = target_entry.get('academic_year', '')
    current_term_token = target_entry['token']

    snapshot = load_published_student_result(school_id, sid, target_term, target_year)
    if not snapshot:
        flash('Published result snapshot not found.', 'error')
        return redirect(url_for('student_portal'))
    record_result_view(school_id, sid, target_term, snapshot.get('academic_year', target_year))

    exam_config = get_assessment_config_for_class(school_id, snapshot.get('classname', ''))
    class_results = load_published_class_results(school_id, snapshot.get('classname', ''), target_term, target_year, school=school)
    position, subject_positions = build_positions_from_published_results(
        school=school,
        classname=snapshot.get('classname', ''),
        term=target_term,
        class_results=class_results,
        student_id=sid,
        student_stream=snapshot.get('stream', ''),
        subjects=snapshot.get('subjects', []),
    )

    student = {
        'first_name': snapshot.get('firstname', firstname),
        'student_id': sid,
        'class_name': snapshot.get('classname', classname),
        'class_size': len(class_results or []),
        'term': target_term,
        'academic_year': target_year,
        'stream': snapshot.get('stream', stream),
        'number_of_subject': snapshot.get('number_of_subject', number_of_subject),
        'subjects': snapshot.get('scores', {}),
        'behaviour_assessment': snapshot.get('behaviour_assessment', {}),
        'teacher_comment': snapshot.get('teacher_comment', ''),
        'principal_comment': snapshot.get('principal_comment', ''),
        'average_marks': snapshot.get('average_marks', 0),
        'Grade': snapshot.get('Grade', 'F'),
        'Status': snapshot.get('Status', 'Fail')
    }
    student.update(
        build_result_term_attendance_data(
            school_id=school_id,
            student_id=sid,
            classname=snapshot.get('classname', classname),
            term=target_term,
            academic_year=target_year,
        )
    )
    result_max_tests = detect_max_tests_from_scores(snapshot.get('scores', {}), school.get('max_tests', 3))
    signoff = get_result_signoff_details(
        school_id,
        snapshot.get('classname', ''),
        target_term,
        target_year,
    )
    teacher_signature = signoff.get('teacher_signature', '')
    principal_signature = signoff.get('principal_signature', '')
    teacher_name = signoff.get('teacher_name', '')
    principal_name = signoff.get('principal_name', '')
    verify_ctx = build_result_verification_context(
        school_id=school_id,
        student_id=sid,
        term=target_term,
        academic_year=target_year,
        classname=snapshot.get('classname', ''),
    )
    
    return render_template(
        'student/student_result.html',
        student=student,
        school=school,
        position=position,
        subject_positions=subject_positions,
        published_terms=published_terms,
        current_term_token=current_term_token,
        available_result_classes=[],
        selected_result_class='',
        term_notice='',
        teacher_signature=teacher_signature,
        teacher_name=teacher_name,
        principal_signature=principal_signature,
        principal_name=principal_name,
        result_max_tests=result_max_tests,
        exam_config=exam_config,
        verification_url=verify_ctx.get('verification_url', ''),
        verification_qr_url=verify_ctx.get('verification_qr_url', ''),
        now=datetime.now()
    )

@app.route('/menu')
def menu():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    role = session.get('role')
    if role == 'super_admin':
        return redirect(url_for('super_admin_dashboard'))
    elif role == 'school_admin':
        return redirect(url_for('school_admin_dashboard'))
    elif role == 'teacher':
        return redirect(url_for('teacher_dashboard'))
    elif role == 'student':
        return redirect(url_for('student_dashboard'))
    elif role == 'parent':
        return redirect(url_for('parent_dashboard'))
    
    return render_template('shared/menu.html')

@app.route('/change_password', methods=['GET', 'POST'])
@app.route('/change-password', methods=['GET', 'POST'])
def change_password():
    """Backward-compatible password endpoint for legacy templates."""
    role = (session.get('role') or '').strip().lower()
    if role == 'parent':
        if request.method == 'POST':
            return parent_change_password()
        flash('Use the parent dashboard password form to change password.', 'error')
        return redirect(url_for('parent_dashboard'))

    if 'user_id' not in session:
        return redirect(url_for('login'))

    if role == 'super_admin':
        return super_admin_change_password()
    if role == 'school_admin':
        # Reuse the dedicated school-admin handler for both GET and POST.
        return school_admin_change_password()
    if role == 'student':
        return student_change_password()

    flash('Password change is not available on this page.', 'error')
    return redirect(url_for('menu'))

@app.route('/view_students')
def view_students():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    role = (session.get('role') or '').strip().lower()
    if role not in {'teacher', 'school_admin'}:
        return redirect(url_for('menu'))
    
    school_id = session.get('school_id')
    if not school_id:
        return redirect(url_for('login'))
    school = get_school(school_id) or {}
    grade_cfg = get_grade_config(school_id)
    current_term = get_current_term(school)

    selected_class = request.args.get('class', '').strip()
    selected_term = request.args.get('term', '').strip()
    try:
        per_page = int((request.args.get('per_page', '') or '50').strip())
    except (TypeError, ValueError):
        per_page = 50
    per_page = max(10, min(per_page, 200))
    try:
        page = int((request.args.get('page', '') or '1').strip())
    except (TypeError, ValueError):
        page = 1
    page = max(1, page)
    if not selected_term:
        selected_term = current_term

    if session.get('role') == 'teacher':
        teacher_id = session.get('user_id')
        current_year = (school or {}).get('academic_year', '')
        class_owner_set = set(get_teacher_classes(school_id, teacher_id, term=selected_term, academic_year=current_year))
        class_set = set(class_owner_set)
        subject_rows = get_teacher_subject_assignments(
            school_id,
            teacher_id=teacher_id,
            term=selected_term,
            academic_year=current_year,
        )
        class_set.update({r.get('classname', '') for r in subject_rows if r.get('classname', '')})
        students_data = load_students_for_classes(school_id, class_set, term_filter=selected_term)
        available_classes, available_terms = get_student_filter_options(school_id, classnames=class_set)
        teacher_result_classes_lower = {(c or '').strip().lower() for c in class_owner_set}
        subject_map_by_class = {}
        for row in subject_rows:
            cls = (row.get('classname') or '').strip()
            subj = normalize_subject_name(row.get('subject', ''))
            if not cls or not subj:
                continue
            subject_map_by_class.setdefault(cls, set()).add(subj)
    else:
        # School admin path: query only currently requested class/term when provided.
        students_data = load_students(school_id, class_filter=selected_class, term_filter=selected_term)
        available_classes, available_terms = get_student_filter_options(school_id)
        teacher_result_classes_lower = set()
        class_owner_set = set()
        subject_map_by_class = {}

    if selected_class:
        students_data = {sid: s for sid, s in students_data.items() if (s.get('classname', '') or '').strip() == selected_class}
    if selected_term:
        students_data = {sid: s for sid, s in students_data.items() if (s.get('term', '') or '').strip() == selected_term}

    students = []
    for student_id, student_data in students_data.items():
        if session.get('role') == 'teacher':
            classname = (student_data.get('classname', '') or '').strip()
            is_class_owner = classname in class_owner_set
            subject_actions = []
            if not is_class_owner:
                allowed_subjects = subject_map_by_class.get(classname, set())
                if not allowed_subjects:
                    continue
                offered_subjects = normalize_subjects_list(student_data.get('subjects', []))
                subject_actions = [s for s in offered_subjects if s in allowed_subjects]
                if not subject_actions:
                    continue
        else:
            is_class_owner = False
            subject_actions = []
        scores = student_data.get('scores', {}) if isinstance(student_data.get('scores', {}), dict) else {}
        average_marks = compute_average_marks_from_scores(scores, subjects=student_data.get('subjects', []))
        grade = grade_from_score(average_marks, grade_cfg)
        status = status_from_score(average_marks, grade_cfg)

        students.append({
            'first_name': student_data.get('firstname', ''),
            'student_id': student_id,
            'class_name': student_data.get('classname', ''),
            'term': student_data.get('term', ''),
            'stream': student_data.get('stream', ''),
            'subjects': scores,
            'can_edit_full': bool(is_class_owner),
            'subject_actions': subject_actions,
            'average_marks': average_marks,
            'Grade': grade,
            'Status': status
        })

    students.sort(
        key=lambda s: (
            (s.get('class_name', '') or '').strip().lower(),
            (s.get('first_name', '') or '').strip().lower(),
            (s.get('student_id', '') or '').strip().lower(),
        )
    )

    positions = calculate_positions(students, school.get('ss_ranking_mode', 'together'), school=school)
    total_students = len(students)
    grade_a_count = sum(1 for s in students if s.get('Grade') == 'A')
    pass_count = sum(1 for s in students if s.get('Status') == 'Pass')
    overall_average = (sum(s.get('average_marks', 0) for s in students) / total_students) if total_students else 0
    total_pages = max(1, (total_students + per_page - 1) // per_page)
    if page > total_pages:
        page = total_pages
    start_idx = (page - 1) * per_page
    end_idx = start_idx + per_page
    page_students = students[start_idx:end_idx]

    return render_template(
        'shared/view_students.html',
        students=page_students,
        positions=positions,
        total_students=total_students,
        grade_a_count=grade_a_count,
        pass_count=pass_count,
        overall_average=overall_average,
        available_classes=available_classes,
        available_terms=available_terms,
        selected_class=selected_class,
        selected_term=selected_term,
        teacher_result_classes_lower=teacher_result_classes_lower,
        page=page,
        total_pages=total_pages,
        per_page=per_page
    )

@app.route('/help')
def help():
    ref = (request.referrer or '').strip()
    role = session.get('role')
    fallback = url_for('home')
    if role == 'super_admin':
        fallback = url_for('super_admin_dashboard')
    elif role == 'school_admin':
        fallback = url_for('school_admin_dashboard')
    elif role == 'teacher':
        fallback = url_for('teacher_dashboard')
    elif role == 'student':
        fallback = url_for('student_dashboard')
    back_url = ref or fallback
    return render_template('shared/help.html', back_url=back_url)

@app.route('/report_issue', methods=['GET', 'POST'])
def report_issue():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        description = (request.form.get('description', '') or request.form.get('issue_description', '')).strip()
        if not description:
            flash('Please describe the issue before submitting.', 'error')
            return redirect(url_for('report_issue'))
        if len(description) > 2000:
            flash('Report is too long. Keep it within 2000 characters.', 'error')
            return redirect(url_for('report_issue'))
        save_report(session['user_id'], description)
        flash('Thank you for your observation. We will fix it.', 'success')
        return redirect(url_for('report_issue'))
    
    return render_template('shared/report_issue.html')

@app.route('/view-reports')
def view_reports():
    """View reported issues inside the main Student Score app."""
    if 'user_id' not in session:
        return redirect(url_for('login'))
    if session.get('role') != 'super_admin':
        flash('Only super admin can view reported issues.', 'error')
        return redirect(url_for('menu'))
    status_filter = (request.args.get('status', '') or '').strip().lower()
    user_filter = (request.args.get('user', '') or '').strip()
    text_filter = (request.args.get('q', '') or '').strip()
    reports = load_reports(status_filter=status_filter, user_filter=user_filter, text_filter=text_filter)
    return render_template(
        'super/report_viewer_reports.html',
        reports=reports,
        status_filter=status_filter,
        user_filter=user_filter,
        text_filter=text_filter,
    )

@app.route('/view-reports/mark-all-read', methods=['POST'])
def view_reports_mark_all_read():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    if session.get('role') != 'super_admin':
        flash('Only super admin can update reports.', 'error')
        return redirect(url_for('menu'))
    mark_all_reports_read()
    flash('All reports marked as read.', 'success')
    return redirect(url_for('view_reports'))

@app.route('/view-reports/mark-read', methods=['POST'])
def view_reports_mark_read():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    if session.get('role') != 'super_admin':
        flash('Only super admin can update reports.', 'error')
        return redirect(url_for('menu'))
    rid = (request.form.get('report_id', '') or '').strip()
    try:
        updated = mark_report_status(int(rid), 'read')
    except Exception:
        updated = 0
    if updated:
        flash('Report marked as read.', 'success')
    else:
        flash('Report not found.', 'error')
    return redirect(url_for('view_reports'))

@app.route('/view-reports/mark-unread', methods=['POST'])
def view_reports_mark_unread():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    if session.get('role') != 'super_admin':
        flash('Only super admin can update reports.', 'error')
        return redirect(url_for('menu'))
    rid = (request.form.get('report_id', '') or '').strip()
    try:
        updated = mark_report_status(int(rid), 'unread')
    except Exception:
        updated = 0
    if updated:
        flash('Report marked as unread.', 'success')
    else:
        flash('Report not found.', 'error')
    return redirect(url_for('view_reports'))

@app.route('/view-reports/delete', methods=['POST'])
def view_reports_delete():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    if session.get('role') != 'super_admin':
        flash('Only super admin can delete reports.', 'error')
        return redirect(url_for('menu'))
    rid = (request.form.get('report_id', '') or '').strip()
    try:
        deleted = delete_report(int(rid))
    except Exception:
        deleted = 0
    if deleted:
        flash('Report deleted.', 'success')
    else:
        flash('Report not found.', 'error')
    return redirect(url_for('view_reports'))

# ==================== MAIN ====================

def run_db_health_check(apply_fixes=False, include_startup_ddl=False):
    """Run DB connectivity/schema checks and optionally apply best-effort fixes."""
    checks = []

    def add_check(name, ok, detail=''):
        checks.append({'name': name, 'ok': bool(ok), 'detail': (detail or '').strip()})

    try:
        with db_connection() as conn:
            c = conn.cursor()
            db_execute(c, 'SELECT 1')
            row = c.fetchone()
            add_check('db_connection', bool(row and int(row[0]) == 1), 'Connected to database.')
    except Exception as exc:
        add_check('db_connection', False, f'Connection failed: {exc}')
        apply_fixes = False

    if apply_fixes:
        try:
            with db_connection(commit=True) as conn:
                c = conn.cursor()
                db_execute(c, "ALTER TABLE users ADD COLUMN IF NOT EXISTS password_changed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP")
                db_execute(c, "UPDATE users SET password_changed_at = COALESCE(password_changed_at, CURRENT_TIMESTAMP)")
                db_execute(c, "ALTER TABLE students ADD COLUMN IF NOT EXISTS parent_phone TEXT")
                db_execute(c, "ALTER TABLE students ADD COLUMN IF NOT EXISTS parent_password_hash TEXT")
            add_check('fix_users_password_changed_at', True, 'Ensured users.password_changed_at exists.')
        except Exception as exc:
            add_check('fix_users_password_changed_at', False, str(exc))

        add_check('ensure_extended_features_schema', ensure_extended_features_schema(), 'Applied/verified extended schema.')
        add_check('ensure_student_attendance_schema', ensure_student_attendance_schema(), 'Applied/verified attendance schema.')
        add_check('ensure_behaviour_assessment_schema', ensure_behaviour_assessment_schema(), 'Applied/verified behaviour schema.')
        add_check('ensure_school_term_calendar_schema', ensure_school_term_calendar_schema(), 'Applied/verified term calendar schema.')

        prev_runtime_heal = os.environ.get('ALLOW_RUNTIME_SCHEMA_HEAL')
        os.environ['ALLOW_RUNTIME_SCHEMA_HEAL'] = '1'
        try:
            with schema_ddl_mode(True):
                add_check('ensure_result_publication_approval_columns', ensure_result_publication_approval_columns(), 'Applied/verified approval columns.')
                add_check('ensure_score_audit_schema', ensure_score_audit_schema(), 'Applied/verified score audit schema.')
        finally:
            if prev_runtime_heal is None:
                os.environ.pop('ALLOW_RUNTIME_SCHEMA_HEAL', None)
            else:
                os.environ['ALLOW_RUNTIME_SCHEMA_HEAL'] = prev_runtime_heal

        if include_startup_ddl:
            try:
                init_db()
                add_check('init_db_startup_ddl', True, 'Ran init_db startup DDL.')
            except Exception as exc:
                add_check('init_db_startup_ddl', False, str(exc))

    add_check('users_password_changed_at_column', users_has_password_changed_at_column(), 'users.password_changed_at present.')
    add_check('students_parent_access_columns', students_has_parent_access_columns(), 'students.parent_phone/password columns present.')
    add_check('result_publication_approval_columns', result_publication_has_approval_columns(), 'result_publications approval columns present.')
    add_check('score_audit_table_exists', score_audit_table_exists(), 'score_audit_logs table present.')
    try:
        verify_required_db_guards()
        add_check('verify_required_db_guards', True, 'Required indexes/FKs verified (or warning mode).')
    except Exception as exc:
        add_check('verify_required_db_guards', False, str(exc))

    ok_count = sum(1 for x in checks if x['ok'])
    fail_count = len(checks) - ok_count
    logging.info('DB Health Report')
    logging.info('Checks: %s | Passed: %s | Failed: %s', len(checks), ok_count, fail_count)
    for item in checks:
        status = 'PASS' if item['ok'] else 'FAIL'
        detail = f" - {item['detail']}" if item['detail'] else ''
        logging.info('[%s] %s%s', status, item["name"], detail)

    return 0 if fail_count == 0 else 1

def validate_production_env():
    """
    Enforce required runtime env vars for production server start.
    Enabled when:
      - FLASK_ENV/APP_ENV == 'production', or
      - ENFORCE_PRODUCTION_ENV=1/true/yes
    """
    app_env = (os.environ.get('APP_ENV', '') or os.environ.get('FLASK_ENV', '') or '').strip().lower()
    enforce_flag = (os.environ.get('ENFORCE_PRODUCTION_ENV', '') or '').strip().lower() in ('1', 'true', 'yes')
    if not (enforce_flag or app_env == 'production'):
        return
    required = [
        'DATABASE_URL',
        'SECRET_KEY',
        'DEFAULT_STUDENT_PASSWORD',
        'DEFAULT_TEACHER_PASSWORD',
        'BACKUP_SIGNING_KEY',
    ]
    missing = [name for name in required if not (os.environ.get(name, '') or '').strip()]
    if missing:
        raise RuntimeError(
            'Missing required production env vars: ' + ', '.join(missing)
        )
    backup_key = (os.environ.get('BACKUP_SIGNING_KEY', '') or '').strip()
    if len(backup_key) < 32:
        raise RuntimeError('BACKUP_SIGNING_KEY is too short. Use at least 32 characters in production.')

if __name__ == '__main__':
    # Enforce production env guards at process startup entrypoint.
    validate_production_env()
    parser = argparse.ArgumentParser(description='Student Score app runner and DB health tools')
    parser.add_argument('--db-health-check', action='store_true', help='Run DB connectivity/schema checks and exit.')
    parser.add_argument('--apply-fixes', action='store_true', help='With --db-health-check, apply best-effort schema fixes first.')
    parser.add_argument('--include-startup-ddl', action='store_true', help='With --db-health-check --apply-fixes, also run init_db().')
    args = parser.parse_args()

    if args.db_health_check:
        raise SystemExit(run_db_health_check(apply_fixes=args.apply_fixes, include_startup_ddl=args.include_startup_ddl))

    port = int(os.environ.get('PORT', 5000))
    debug_flag = (
        os.environ.get('FLASK_DEBUG', '')
        or os.environ.get('DEBUG', '')
        or '0'
    )
    debug = str(debug_flag).strip().lower() in ('1', 'true', 'yes')
    app.run(host='0.0.0.0', port=port, debug=debug)
