"""
Student Score Management System - Restructured Version

A comprehensive Flask web application for managing student academic records,
including multi-school support, role-based access, and advanced features.

Author: OSondu Stanley
Version: 2.0.0
"""

from flask import Flask, render_template, request, redirect, url_for, session, flash, send_file, Response
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, IntegerField, TextAreaField, SelectField, validators
from flask_wtf.csrf import CSRFProtect, CSRFError
import json
import csv
import re
import math
import base64
from io import StringIO, BytesIO
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash, check_password_hash

import os
import secrets
from contextlib import contextmanager
from tempfile import SpooledTemporaryFile

import logging
from dotenv import load_dotenv
try:
    from dotenv import load_dotenv
except Exception:
    load_dotenv = None

if load_dotenv:
    load_dotenv()

app = Flask(__name__, template_folder='frontend/templates', static_folder='static')
load_dotenv()
ALLOW_INSECURE_DEFAULTS = os.environ.get('ALLOW_INSECURE_DEFAULTS', '').strip().lower() in ('1', 'true', 'yes')
secret_key = os.environ.get('SECRET_KEY')
if not secret_key:
    if ALLOW_INSECURE_DEFAULTS:
        # Explicitly opt-in fallback for local/dev only.
        secret_key = 'dev-secret-key-change-me'
    else:
        raise RuntimeError("SECRET_KEY is required in production. Set SECRET_KEY or enable ALLOW_INSECURE_DEFAULTS for local development.")
if not ALLOW_INSECURE_DEFAULTS and len(secret_key) < 32:
    raise RuntimeError("SECRET_KEY is too short. Use at least 32 characters in production.")
app.secret_key = secret_key
app.config['WTF_CSRF_TIME_LIMIT'] = None

# Initialize CSRF Protection
csrf = CSRFProtect(app)

DATABASE_URL = os.environ.get('DATABASE_URL', '').strip()
if not DATABASE_URL.startswith(('postgres://', 'postgresql://')):
    raise RuntimeError("PostgreSQL is required. Set DATABASE_URL to a postgresql:// connection string.")
SUPER_ADMIN_USERNAME = os.environ.get('SUPER_ADMIN_USERNAME', 'osondu stanley').strip()
SUPER_ADMIN_PASSWORD = os.environ.get('SUPER_ADMIN_PASSWORD', '').strip()
if not SUPER_ADMIN_PASSWORD:
    raise RuntimeError("SUPER_ADMIN_PASSWORD is required. Set it in environment variables.")
if len(SUPER_ADMIN_PASSWORD) < 12:
    raise RuntimeError("SUPER_ADMIN_PASSWORD is too short. Use at least 12 characters.")
DEFAULT_STUDENT_PASSWORD = os.environ.get('DEFAULT_STUDENT_PASSWORD', '').strip()
if not DEFAULT_STUDENT_PASSWORD:
    raise RuntimeError("DEFAULT_STUDENT_PASSWORD is required. Set it in environment variables.")
if not ALLOW_INSECURE_DEFAULTS and len(DEFAULT_STUDENT_PASSWORD) < 8:
    raise RuntimeError("DEFAULT_STUDENT_PASSWORD is too short. Use at least 8 characters in production.")
PK_COLUMN_SQL = 'SERIAL PRIMARY KEY'
LOGIN_MAX_ATTEMPTS = 4
LOGIN_LOCK_MINUTES = 15

def _adapt_query(query):
    return query.replace('?', '%s')

def db_execute(cursor, query, params=None):
    if params is None:
        return cursor.execute(_adapt_query(query))
    return cursor.execute(_adapt_query(query), params)

def canonicalize_classname(value):
    """Canonical class key used for shared subject catalog (e.g. 'Primary 1' -> 'PRIMARY1')."""
    return re.sub(r'[^A-Za-z0-9]+', '', (value or '').strip()).upper()

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
        '''INSERT INTO global_class_subject_catalog (classname, bucket, subject_name)
           VALUES (?, ?, ?)
           ON CONFLICT(classname, bucket, subject_name) DO NOTHING''',
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
    return psycopg2.connect(DATABASE_URL, cursor_factory=DictCursor, connect_timeout=10)

@contextmanager
def db_connection(commit=False):
    """Context manager for SQLite connections with optional commit."""
    conn = get_db()
    try:
        yield conn
        if commit:
            conn.commit()
    finally:
        conn.close()

# Set up logging
logging.basicConfig(filename='app.log', level=logging.INFO, 
                    format='%(asctime)s - %(levelname)s - %(message)s')
if ALLOW_INSECURE_DEFAULTS:
    logging.warning("ALLOW_INSECURE_DEFAULTS is enabled. Development-only fallbacks may be active.")

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

def _store_csv_error_export(content, filename):
    _cleanup_csv_error_exports()
    token = secrets.token_urlsafe(18)
    CSV_ERROR_EXPORTS[token] = {
        'content': content,
        'filename': filename,
        'created_at': datetime.now(),
    }
    return token

def init_db():
    """Initialize the database with new schema for multi-school support."""
    conn = get_db()
    c = conn.cursor()
    
    def safe_exec_ignore(sql):
        """
        Execute DDL that may fail if column/index already exists, without
        poisoning the whole PostgreSQL transaction.
        """
        db_execute(c, 'SAVEPOINT ddl_ignore')
        try:
            db_execute(c, sql)
        except Exception:
            db_execute(c, 'ROLLBACK TO SAVEPOINT ddl_ignore')
        finally:
            db_execute(c, 'RELEASE SAVEPOINT ddl_ignore')

    def _quote_ident(name):
        return '"' + str(name).replace('"', '""') + '"'

    def drop_school_id_foreign_keys():
        """
        Drop any FK constraints on public tables that include a school_id column.
        Legacy deployments may have varying FK names/types.
        """
        try:
            db_execute(
                c,
                '''SELECT ns.nspname, cls.relname, con.conname
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
                     )'''
            )
            for schema_name, table_name, con_name in c.fetchall() or []:
                safe_exec_ignore(
                    f'ALTER TABLE {_quote_ident(schema_name)}.{_quote_ident(table_name)} '
                    f'DROP CONSTRAINT IF EXISTS {_quote_ident(con_name)}'
                )
        except Exception:
            pass

    # Users table with roles: super_admin, school_admin, teacher, student
    db_execute(c, f'''CREATE TABLE IF NOT EXISTS users (
                        id {PK_COLUMN_SQL},
                        username TEXT UNIQUE NOT NULL,
                        password_hash TEXT NOT NULL,
                        role TEXT DEFAULT 'student',
                        school_id TEXT,
                        terms_accepted INTEGER DEFAULT 0,
                        current_login_at TIMESTAMP,
                        last_login_at TIMESTAMP,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )''')
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
    safe_exec_ignore('ALTER TABLE students ALTER COLUMN school_id TYPE TEXT USING school_id::text')
    safe_exec_ignore('ALTER TABLE teachers ALTER COLUMN school_id TYPE TEXT USING school_id::text')
    safe_exec_ignore('ALTER TABLE class_assignments ALTER COLUMN school_id TYPE TEXT USING school_id::text')
    safe_exec_ignore('ALTER TABLE class_subject_configs ALTER COLUMN school_id TYPE TEXT USING school_id::text')
    safe_exec_ignore('ALTER TABLE assessment_configs ALTER COLUMN school_id TYPE TEXT USING school_id::text')
    safe_exec_ignore('ALTER TABLE result_publications ALTER COLUMN school_id TYPE TEXT USING school_id::text')
    safe_exec_ignore('ALTER TABLE published_student_results ALTER COLUMN school_id TYPE TEXT USING school_id::text')
    safe_exec_ignore('ALTER TABLE result_views ALTER COLUMN school_id TYPE TEXT USING school_id::text')
    safe_exec_ignore('ALTER TABLE users ADD COLUMN terms_accepted INTEGER DEFAULT 0')
    safe_exec_ignore('ALTER TABLE users ADD COLUMN current_login_at TIMESTAMP')
    safe_exec_ignore('ALTER TABLE users ADD COLUMN last_login_at TIMESTAMP')
    
    # Schools table
    db_execute(c, f'''CREATE TABLE IF NOT EXISTS schools (
                        id {PK_COLUMN_SQL},
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
                        ss_ranking_mode TEXT DEFAULT 'together',
                        ss1_stream_mode TEXT DEFAULT 'separate',
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )''')
    safe_exec_ignore('ALTER TABLE schools ADD COLUMN operations_enabled INTEGER DEFAULT 1')
    safe_exec_ignore('ALTER TABLE schools ADD COLUMN teacher_operations_enabled INTEGER DEFAULT 1')
    # Backfill grade config columns for existing databases.
    safe_exec_ignore('ALTER TABLE schools ADD COLUMN grade_a_min INTEGER DEFAULT 70')
    safe_exec_ignore('ALTER TABLE schools ADD COLUMN grade_b_min INTEGER DEFAULT 60')
    safe_exec_ignore('ALTER TABLE schools ADD COLUMN grade_c_min INTEGER DEFAULT 50')
    safe_exec_ignore('ALTER TABLE schools ADD COLUMN grade_d_min INTEGER DEFAULT 40')
    safe_exec_ignore('ALTER TABLE schools ADD COLUMN pass_mark INTEGER DEFAULT 50')
    safe_exec_ignore("ALTER TABLE schools ADD COLUMN ss_ranking_mode TEXT DEFAULT 'together'")
    safe_exec_ignore("ALTER TABLE schools ADD COLUMN ss1_stream_mode TEXT DEFAULT 'separate'")
    safe_exec_ignore("ALTER TABLE schools ADD COLUMN location TEXT")
    safe_exec_ignore("ALTER TABLE schools ADD COLUMN phone TEXT")
    safe_exec_ignore("ALTER TABLE schools ADD COLUMN email TEXT")
    safe_exec_ignore("ALTER TABLE schools ADD COLUMN principal_name TEXT")
    safe_exec_ignore("ALTER TABLE schools ADD COLUMN motto TEXT")
    safe_exec_ignore("ALTER TABLE schools ADD COLUMN updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP")
    safe_exec_ignore("ALTER TABLE schools ADD COLUMN principal_signature_image TEXT")
    
    # Migration: Add school_id column if it doesn't exist (for legacy databases)
    safe_exec_ignore("ALTER TABLE schools ADD COLUMN school_id TEXT")
    # Backfill school_id for existing schools (using id column value)
    try:
        db_execute(c, "UPDATE schools SET school_id = CAST(id AS TEXT) WHERE school_id IS NULL OR school_id = ''")
    except Exception:
        pass  # Skip if already up to date or column doesn't exist
    # Migrate all tables to use schools.id (as text) for school_id values.
    # This normalizes legacy text IDs to index-based IDs.
    safe_exec_ignore('ALTER TABLE class_assignments DROP CONSTRAINT IF EXISTS fk_class_assignments_teacher')
    safe_exec_ignore('ALTER TABLE class_assignments DROP CONSTRAINT IF EXISTS fk_class_assignments_school')
    safe_exec_ignore('ALTER TABLE teachers DROP CONSTRAINT IF EXISTS fk_teachers_school')
    safe_exec_ignore('ALTER TABLE students DROP CONSTRAINT IF EXISTS fk_students_school')
    try:
        db_execute(
            c,
            '''WITH mapping AS (
                   SELECT CAST(id AS TEXT) AS new_school_id, school_id AS old_school_id
                   FROM schools
               )
               UPDATE users u
               SET school_id = m.new_school_id
               FROM mapping m
               WHERE CAST(u.school_id AS TEXT) = m.old_school_id
                 AND CAST(u.school_id AS TEXT) <> m.new_school_id'''
        )
        db_execute(
            c,
            '''WITH mapping AS (
                   SELECT CAST(id AS TEXT) AS new_school_id, school_id AS old_school_id
                   FROM schools
               )
               UPDATE students s
               SET school_id = m.new_school_id
               FROM mapping m
               WHERE s.school_id = m.old_school_id
                 AND s.school_id <> m.new_school_id'''
        )
        db_execute(
            c,
            '''WITH mapping AS (
                   SELECT CAST(id AS TEXT) AS new_school_id, school_id AS old_school_id
                   FROM schools
               )
               UPDATE teachers t
               SET school_id = m.new_school_id
               FROM mapping m
               WHERE t.school_id = m.old_school_id
                 AND t.school_id <> m.new_school_id'''
        )
        db_execute(
            c,
            '''WITH mapping AS (
                   SELECT CAST(id AS TEXT) AS new_school_id, school_id AS old_school_id
                   FROM schools
               )
               UPDATE class_assignments ca
               SET school_id = m.new_school_id
               FROM mapping m
               WHERE ca.school_id = m.old_school_id
                 AND ca.school_id <> m.new_school_id'''
        )
        db_execute(
            c,
            '''WITH mapping AS (
                   SELECT CAST(id AS TEXT) AS new_school_id, school_id AS old_school_id
                   FROM schools
               )
               UPDATE class_subject_configs cfg
               SET school_id = m.new_school_id
               FROM mapping m
               WHERE cfg.school_id = m.old_school_id
                 AND cfg.school_id <> m.new_school_id'''
        )
        db_execute(
            c,
            '''WITH mapping AS (
                   SELECT CAST(id AS TEXT) AS new_school_id, school_id AS old_school_id
                   FROM schools
               )
               UPDATE assessment_configs ac
               SET school_id = m.new_school_id
               FROM mapping m
               WHERE ac.school_id = m.old_school_id
                 AND ac.school_id <> m.new_school_id'''
        )
        db_execute(
            c,
            '''WITH mapping AS (
                   SELECT CAST(id AS TEXT) AS new_school_id, school_id AS old_school_id
                   FROM schools
               )
               UPDATE result_publications rp
               SET school_id = m.new_school_id
               FROM mapping m
               WHERE rp.school_id = m.old_school_id
                 AND rp.school_id <> m.new_school_id'''
        )
        db_execute(
            c,
            '''WITH mapping AS (
                   SELECT CAST(id AS TEXT) AS new_school_id, school_id AS old_school_id
                   FROM schools
               )
               UPDATE published_student_results psr
               SET school_id = m.new_school_id
               FROM mapping m
               WHERE psr.school_id = m.old_school_id
                 AND psr.school_id <> m.new_school_id'''
        )
        db_execute(
            c,
            '''WITH mapping AS (
                   SELECT CAST(id AS TEXT) AS new_school_id, school_id AS old_school_id
                   FROM schools
               )
               UPDATE result_views rv
               SET school_id = m.new_school_id
               FROM mapping m
               WHERE rv.school_id = m.old_school_id
                 AND rv.school_id <> m.new_school_id'''
        )
        db_execute(c, 'UPDATE schools SET school_id = CAST(id AS TEXT) WHERE school_id <> CAST(id AS TEXT)')
    except Exception:
        pass
    
    # Students table with ID format: YY/school_id/index/start_year_yy
    db_execute(c, f'''CREATE TABLE IF NOT EXISTS students (
                        id {PK_COLUMN_SQL},
                        user_id TEXT NOT NULL,
                        school_id TEXT NOT NULL,
                        student_id TEXT NOT NULL,
                        firstname TEXT NOT NULL,
                        classname TEXT NOT NULL,
                        first_year_class TEXT NOT NULL,
                        term TEXT NOT NULL,
                        stream TEXT NOT NULL,
                        number_of_subject INTEGER NOT NULL,
                        subjects TEXT NOT NULL,
                        scores TEXT,
                        promoted INTEGER DEFAULT 0,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        UNIQUE(school_id, student_id)
                    )''')
    
    # Teachers table
    db_execute(c, f'''CREATE TABLE IF NOT EXISTS teachers (
                        id {PK_COLUMN_SQL},
                        user_id TEXT NOT NULL,
                        school_id TEXT NOT NULL,
                        firstname TEXT NOT NULL,
                        lastname TEXT NOT NULL,
                        signature_image TEXT,
                        assigned_classes TEXT,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )''')
    safe_exec_ignore("ALTER TABLE teachers ADD COLUMN signature_image TEXT")
    
    # Class assignments
    db_execute(c, f'''CREATE TABLE IF NOT EXISTS class_assignments (
                        id {PK_COLUMN_SQL},
                        school_id TEXT NOT NULL,
                        teacher_id TEXT NOT NULL,
                        classname TEXT NOT NULL,
                        term TEXT NOT NULL,
                        academic_year TEXT NOT NULL
                    )''')

    # Class subject configuration (set by school admin).
    db_execute(c, f'''CREATE TABLE IF NOT EXISTS class_subject_configs (
                        id {PK_COLUMN_SQL},
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
                    )''')
    # Global subject catalog by class (shared across all schools).
    db_execute(c, f'''CREATE TABLE IF NOT EXISTS global_class_subject_catalog (
                        id {PK_COLUMN_SQL},
                        classname TEXT NOT NULL,
                        bucket TEXT NOT NULL,
                        subject_name TEXT NOT NULL,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        UNIQUE(classname, bucket, subject_name)
                    )''')

    # Per-level assessment/exam configuration (primary, jss, ss).
    db_execute(c, f'''CREATE TABLE IF NOT EXISTS assessment_configs (
                        id {PK_COLUMN_SQL},
                        school_id TEXT NOT NULL,
                        level TEXT NOT NULL,
                        exam_mode TEXT NOT NULL DEFAULT 'separate',
                        objective_max INTEGER NOT NULL DEFAULT 30,
                        theory_max INTEGER NOT NULL DEFAULT 40,
                        exam_score_max INTEGER NOT NULL DEFAULT 70,
                        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        UNIQUE(school_id, level)
                    )''')
    # Result publication/ranking gate per class + term.
    db_execute(c, f'''CREATE TABLE IF NOT EXISTS result_publications (
                        id {PK_COLUMN_SQL},
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
                    )''')
    safe_exec_ignore("ALTER TABLE result_publications ADD COLUMN academic_year TEXT DEFAULT ''")
    safe_exec_ignore("ALTER TABLE result_publications ADD COLUMN teacher_name TEXT DEFAULT ''")
    safe_exec_ignore("ALTER TABLE result_publications ADD COLUMN principal_name TEXT DEFAULT ''")
    # Immutable snapshot of published student results per term.
    db_execute(c, f'''CREATE TABLE IF NOT EXISTS published_student_results (
                        id {PK_COLUMN_SQL},
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
                        teacher_comment TEXT,
                        average_marks REAL NOT NULL DEFAULT 0,
                        grade TEXT NOT NULL,
                        status TEXT NOT NULL,
                        published_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        UNIQUE(school_id, student_id, academic_year, term)
                    )''')
    # Track when students view published results.
    db_execute(c, f'''CREATE TABLE IF NOT EXISTS result_views (
                        id {PK_COLUMN_SQL},
                        school_id TEXT NOT NULL,
                        student_id TEXT NOT NULL,
                        term TEXT NOT NULL,
                        academic_year TEXT DEFAULT '',
                        first_viewed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        last_viewed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        view_count INTEGER NOT NULL DEFAULT 1,
                        UNIQUE(school_id, student_id, term, academic_year)
                    )''')
    safe_exec_ignore('ALTER TABLE published_student_results ADD COLUMN teacher_comment TEXT')
    safe_exec_ignore('ALTER TABLE published_student_results ADD COLUMN academic_year TEXT')
    
    # Reports table
    db_execute(c, f'''CREATE TABLE IF NOT EXISTS reports (
                        id {PK_COLUMN_SQL},
                        user_id TEXT NOT NULL,
                        description TEXT NOT NULL,
                        timestamp TEXT NOT NULL,
                        status TEXT DEFAULT 'unread',
                        read_at TEXT
                    )''')
    # Login attempt tracking for brute-force protection.
    db_execute(c, f'''CREATE TABLE IF NOT EXISTS login_attempts (
                        id {PK_COLUMN_SQL},
                        endpoint TEXT NOT NULL,
                        username TEXT NOT NULL,
                        ip_address TEXT NOT NULL,
                        failures INTEGER NOT NULL DEFAULT 0,
                        first_failed_at TIMESTAMP,
                        last_failed_at TIMESTAMP,
                        locked_until TIMESTAMP,
                        UNIQUE(endpoint, username, ip_address)
                    )''')

    # Create indexes
    db_execute(c, 'CREATE INDEX IF NOT EXISTS idx_users_username ON users(username)')
    db_execute(c, 'CREATE INDEX IF NOT EXISTS idx_users_role ON users(role)')
    db_execute(c, 'CREATE INDEX IF NOT EXISTS idx_students_school ON students(school_id)')
    db_execute(c, 'CREATE INDEX IF NOT EXISTS idx_students_class ON students(school_id, classname)')
    db_execute(c, 'CREATE INDEX IF NOT EXISTS idx_students_school_class_term ON students(school_id, classname, term)')
    db_execute(c, 'CREATE INDEX IF NOT EXISTS idx_students_school_term ON students(school_id, term)')
    db_execute(c, 'CREATE INDEX IF NOT EXISTS idx_teachers_school ON teachers(school_id)')
    db_execute(c, 'CREATE INDEX IF NOT EXISTS idx_teachers_school_user ON teachers(school_id, user_id)')
    db_execute(c, 'CREATE INDEX IF NOT EXISTS idx_class_subject_configs_school_class ON class_subject_configs(school_id, classname)')
    db_execute(c, 'CREATE INDEX IF NOT EXISTS idx_global_subject_catalog_class_bucket ON global_class_subject_catalog(classname, bucket)')
    db_execute(c, 'CREATE INDEX IF NOT EXISTS idx_assessment_configs_school_level ON assessment_configs(school_id, level)')
    db_execute(c, 'CREATE INDEX IF NOT EXISTS idx_result_views_lookup ON result_views(school_id, term, student_id)')
    db_execute(c, 'CREATE INDEX IF NOT EXISTS idx_login_attempts_lookup ON login_attempts(endpoint, username, ip_address)')
    db_execute(c, 'CREATE INDEX IF NOT EXISTS idx_login_attempts_locked_until ON login_attempts(locked_until)')
    db_execute(c, 'CREATE INDEX IF NOT EXISTS idx_result_publications_school_class_term_year ON result_publications(school_id, classname, term, academic_year)')
    db_execute(c, 'CREATE INDEX IF NOT EXISTS idx_published_school_class_term_year ON published_student_results(school_id, classname, term, academic_year)')
    db_execute(c, 'CREATE INDEX IF NOT EXISTS idx_published_school_student_term_year ON published_student_results(school_id, student_id, term, academic_year)')
    # Ensure upsert target exists for students ON CONFLICT(school_id, student_id).
    db_execute(
        c,
        '''DELETE FROM students
           WHERE id NOT IN (
             SELECT MIN(id)
             FROM students
             GROUP BY school_id, student_id
           )'''
    )
    db_execute(c, 'CREATE UNIQUE INDEX IF NOT EXISTS uq_students_school_student ON students(school_id, student_id)')
    # Normalize and deduplicate class subject config class names (e.g. "Primary 1" -> "PRIMARY1").
    db_execute(
        c,
        '''DELETE FROM class_subject_configs
           WHERE id NOT IN (
             SELECT MIN(id)
             FROM class_subject_configs
             GROUP BY school_id, REGEXP_REPLACE(UPPER(classname), '[^A-Z0-9]+', '', 'g')
           )'''
    )
    db_execute(
        c,
        '''UPDATE class_subject_configs
           SET classname = REGEXP_REPLACE(UPPER(classname), '[^A-Z0-9]+', '', 'g')
           WHERE classname <> REGEXP_REPLACE(UPPER(classname), '[^A-Z0-9]+', '', 'g')'''
    )
    # Deduplicate legacy assignment rows before enforcing uniqueness.
    db_execute(
        c,
        '''DELETE FROM class_assignments
           WHERE id NOT IN (
             SELECT MIN(id)
             FROM class_assignments
             GROUP BY school_id, teacher_id, classname, term, academic_year
           )'''
    )
    safe_exec_ignore('DROP INDEX IF EXISTS uq_class_assignments')
    safe_exec_ignore('DROP INDEX IF EXISTS uq_class_term_assignment')
    db_execute(c, 'CREATE UNIQUE INDEX IF NOT EXISTS uq_class_assignments ON class_assignments(school_id, teacher_id, classname, term, academic_year)')
    # Ensure one teacher per class per term and academic year.
    db_execute(
        c,
        '''DELETE FROM class_assignments
           WHERE id NOT IN (
             SELECT MIN(id)
             FROM class_assignments
             GROUP BY school_id, classname, term, academic_year
           )'''
    )
    db_execute(c, 'CREATE UNIQUE INDEX IF NOT EXISTS uq_class_term_assignment ON class_assignments(school_id, classname, term, academic_year)')
    # Deduplicate legacy teacher rows before enforcing one profile per school/user.
    db_execute(
        c,
        '''DELETE FROM teachers
           WHERE id NOT IN (
             SELECT MIN(id)
             FROM teachers
             GROUP BY school_id, user_id
           )'''
    )
    db_execute(c, 'CREATE UNIQUE INDEX IF NOT EXISTS uq_teachers_school_user ON teachers(school_id, user_id)')
    # Rebuild publication uniqueness to include academic year.
    db_execute(
        c,
        '''DELETE FROM result_publications
           WHERE id NOT IN (
             SELECT MIN(id)
             FROM result_publications
             GROUP BY school_id, classname, term, COALESCE(academic_year, '')
           )'''
    )
    safe_exec_ignore('ALTER TABLE result_publications DROP CONSTRAINT IF EXISTS result_publications_school_id_classname_term_key')
    safe_exec_ignore('DROP INDEX IF EXISTS result_publications_school_id_classname_term_key')
    safe_exec_ignore('DROP INDEX IF EXISTS uq_result_publications')
    db_execute(c, 'CREATE UNIQUE INDEX IF NOT EXISTS uq_result_publications ON result_publications(school_id, classname, term, academic_year)')
    # Best-effort tenancy integrity constraints for multi-school isolation.
    safe_exec_ignore('ALTER TABLE students ADD CONSTRAINT fk_students_school FOREIGN KEY (school_id) REFERENCES schools(school_id) ON DELETE CASCADE')
    safe_exec_ignore('ALTER TABLE teachers ADD CONSTRAINT fk_teachers_school FOREIGN KEY (school_id) REFERENCES schools(school_id) ON DELETE CASCADE')
    safe_exec_ignore('ALTER TABLE class_assignments ADD CONSTRAINT fk_class_assignments_school FOREIGN KEY (school_id) REFERENCES schools(school_id) ON DELETE CASCADE')
    safe_exec_ignore('ALTER TABLE class_assignments ADD CONSTRAINT fk_class_assignments_teacher FOREIGN KEY (school_id, teacher_id) REFERENCES teachers(school_id, user_id) ON DELETE CASCADE')

    # Seed global catalog defaults and backfill custom subjects from existing per-school configs.
    try:
        _seed_global_subject_catalog_defaults_with_cursor(c)
        db_execute(
            c,
            '''SELECT classname, core_subjects, science_subjects, art_subjects, commercial_subjects, optional_subjects
               FROM class_subject_configs'''
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
    except Exception:
        pass

    conn.commit()
    conn.close()

def verify_required_db_guards():
    """Verify critical multi-school constraints/indexes are present."""
    strict = os.environ.get('DB_GUARDS_STRICT', '0').strip().lower() in ('1', 'true', 'yes')
    required_indexes = {
        'uq_teachers_school_user',
        'uq_class_assignments',
        'uq_class_term_assignment',
        'uq_result_publications',
    }
    required_constraints = {
        'fk_students_school',
        'fk_teachers_school',
    }
    with db_connection() as conn:
        c = conn.cursor()
        db_execute(
            c,
            '''SELECT indexname
               FROM pg_indexes
               WHERE schemaname = 'public' '''
        )
        present_indexes = {str(row[0]) for row in c.fetchall() if row and row[0]}
        db_execute(
            c,
            '''SELECT conname
               FROM pg_constraint'''
        )
        present_constraints = {str(row[0]) for row in c.fetchall() if row and row[0]}

    missing_indexes = sorted(required_indexes - present_indexes)
    missing_constraints = sorted(required_constraints - present_constraints)
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
RUN_STARTUP_DDL = os.environ.get('RUN_STARTUP_DDL', '1').strip().lower() in ('1', 'true', 'yes')
if RUN_STARTUP_DDL:
    init_db()
else:
    logging.warning("RUN_STARTUP_DDL is disabled. Ensure schema is already migrated before startup.")
verify_required_db_guards()

# Create super admin user
def create_super_admin():
    """Ensure super admin account exists; do not reset password on every startup."""
    with db_connection() as conn:
        c = conn.cursor()
        db_execute(c, 'SELECT username, role FROM users WHERE LOWER(username) = LOWER(?)', (SUPER_ADMIN_USERNAME,))
        row = c.fetchone()
        if not row:
            if not SUPER_ADMIN_PASSWORD:
                raise RuntimeError(
                    "SUPER_ADMIN_PASSWORD is required to bootstrap the initial super admin account."
                )
            password_hash = generate_password_hash(SUPER_ADMIN_PASSWORD)
            db_execute(c, '''INSERT INTO users (username, password_hash, role, school_id) 
                           VALUES (?, ?, ?, ?)''', (SUPER_ADMIN_USERNAME, password_hash, 'super_admin', None))
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

create_super_admin()

def normalize_all_student_passwords():
    """Ensure all student accounts use the configured default password."""
    default_hash = generate_password_hash(DEFAULT_STUDENT_PASSWORD)
    with db_connection(commit=True) as conn:
        c = conn.cursor()
        db_execute(c, "UPDATE users SET password_hash = ? WHERE role = 'student'", (default_hash,))

if os.environ.get('RESET_STUDENT_PASSWORDS_ON_STARTUP', '').strip().lower() in ('1', 'true', 'yes'):
    if not ALLOW_INSECURE_DEFAULTS:
        raise RuntimeError(
            "RESET_STUDENT_PASSWORDS_ON_STARTUP is only allowed when ALLOW_INSECURE_DEFAULTS is enabled."
        )
    normalize_all_student_passwords()

def get_user(username):
    """Fetch one user by username."""
    with db_connection() as conn:
        c = conn.cursor()
        db_execute(c, 'SELECT username, password_hash, role, school_id, terms_accepted FROM users WHERE username = ?', (username,))
        row = c.fetchone()
        if not row:
            # Fallback to case-insensitive lookup so login is less brittle.
            db_execute(c, 'SELECT username, password_hash, role, school_id, terms_accepted FROM users WHERE LOWER(username) = LOWER(?) LIMIT 1', (username,))
            row = c.fetchone()
        if not row:
            return None
        return {
            'username': row[0],
            'password_hash': row[1],
            'role': row[2] or 'student',
            'school_id': row[3],
            'terms_accepted': int(row[4] or 0),
        }

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
    db_execute(
        c,
        '''SELECT username
           FROM users
           WHERE LOWER(username) = LOWER(?)
           LIMIT 1''',
        (uname,),
    )
    row = c.fetchone()
    if row:
        if overwrite_identity:
            db_execute(
                c,
                '''UPDATE users
                   SET password_hash = ?, role = ?, school_id = ?
                   WHERE LOWER(username) = LOWER(?)''',
                (password_hash, role, school_id, uname),
            )
        else:
            db_execute(
                c,
                '''UPDATE users
                   SET password_hash = ?
                   WHERE LOWER(username) = LOWER(?)''',
                (password_hash, uname),
            )
        return
    db_execute(
        c,
        '''INSERT INTO users (username, password_hash, role, school_id)
           VALUES (?, ?, ?, ?)''',
        (uname, password_hash, role, school_id),
    )

def update_user_school_id_only(username, school_id):
    """Update only school_id for an existing user without altering role/password."""
    with db_connection(commit=True) as conn:
        c = conn.cursor()
        db_execute(
            c,
            'UPDATE users SET school_id = ? WHERE LOWER(username) = LOWER(?)',
            ((school_id or '').strip(), (username or '').strip()),
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
            '''SELECT failures, locked_until
               FROM login_attempts
               WHERE endpoint = ? AND username = ? AND ip_address = ?
               LIMIT 1''',
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
            '''SELECT failures, last_failed_at, locked_until
               FROM login_attempts
               WHERE endpoint = ? AND username = ? AND ip_address = ?
               LIMIT 1''',
            (endpoint, username, ip_address),
        )
        row = c.fetchone()
        if not row:
            db_execute(
                c,
                '''INSERT INTO login_attempts
                   (endpoint, username, ip_address, failures, first_failed_at, last_failed_at, locked_until)
                   VALUES (?, ?, ?, ?, ?, ?, ?)''',
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
                '''UPDATE login_attempts
                   SET failures = ?, first_failed_at = ?, last_failed_at = ?, locked_until = ?
                   WHERE endpoint = ? AND username = ? AND ip_address = ?''',
                (failures, first_failed_at, now, new_locked_until, endpoint, username, ip_address),
            )
        else:
            db_execute(
                c,
                '''UPDATE login_attempts
                   SET failures = ?, last_failed_at = ?, locked_until = ?
                   WHERE endpoint = ? AND username = ? AND ip_address = ?''',
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
            '''DELETE FROM login_attempts
               WHERE endpoint = ? AND username = ? AND ip_address = ?''',
            (endpoint, username, ip_address),
        )

def purge_old_login_attempts():
    """Delete stale login-attempt rows to keep table size small."""
    cutoff = datetime.now() - timedelta(days=7)
    with db_connection(commit=True) as conn:
        c = conn.cursor()
        db_execute(
            c,
            '''DELETE FROM login_attempts
               WHERE (locked_until IS NOT NULL AND locked_until < ?)
                  OR (locked_until IS NULL AND last_failed_at IS NOT NULL AND last_failed_at < ?)''',
            (cutoff, cutoff),
        )

def update_login_timestamps(username):
    """Shift current_login_at -> last_login_at and set current_login_at=now."""
    with db_connection(commit=True) as conn:
        c = conn.cursor()
        db_execute(
            c,
            '''UPDATE users
               SET last_login_at = current_login_at,
                   current_login_at = CURRENT_TIMESTAMP
               WHERE LOWER(username) = LOWER(?)''',
            ((username or '').strip(),),
        )

def get_last_login_at(username):
    """Return last successful login timestamp for a user."""
    with db_connection() as conn:
        c = conn.cursor()
        db_execute(
            c,
            '''SELECT last_login_at
               FROM users
               WHERE LOWER(username) = LOWER(?)
               LIMIT 1''',
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
    firstname = normalize_person_name(student_data.get('firstname', ''))
    subjects = _dedupe_keep_order([normalize_subject_name(s) for s in (student_data.get('subjects', []) or []) if s])
    subjects_str = json.dumps(subjects)
    scores_str = json.dumps(student_data.get('scores', {}))
    term = student_data.get('term', 'First Term')
    stream = student_data.get('stream', 'Science')
    first_year_class = student_data.get('first_year_class', student_data.get('classname', ''))
    number_of_subject = len(subjects)
    user_id = student_id

    db_execute(
        c,
        '''INSERT INTO students
           (user_id, school_id, student_id, firstname, classname, first_year_class, term, stream, number_of_subject, subjects, scores, promoted)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
           ON CONFLICT(school_id, student_id) DO UPDATE SET
             firstname = excluded.firstname,
             classname = excluded.classname,
             first_year_class = excluded.first_year_class,
             term = excluded.term,
             stream = excluded.stream,
             number_of_subject = excluded.number_of_subject,
             subjects = excluded.subjects,
             scores = excluded.scores,
             promoted = excluded.promoted''',
        (
            user_id,
            school_id,
            student_id,
            firstname,
            student_data['classname'],
            first_year_class,
            term,
            stream,
            number_of_subject,
            subjects_str,
            scores_str,
            student_data.get('promoted', 0),
        ),
    )

def hash_password(password):
    """Hash a password."""
    return generate_password_hash(password)

def check_password(hashed, password):
    """Verify a password."""
    return check_password_hash(hashed, password)

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

def _extract_class_number(classname):
    normalized = re.sub(r'[^A-Za-z0-9]+', '', (classname or '')).upper()
    m = re.search(r'(\d+)$', normalized)
    if not m:
        return None
    try:
        return int(m.group(1))
    except (TypeError, ValueError):
        return None

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
    normalized = re.sub(r'[^A-Za-z0-9]+', '', (classname or '')).upper()
    return normalized in {'SS1', 'SS2', 'SS3', 'SSS1', 'SSS2', 'SSS3'}

def is_ss1_class(classname):
    normalized = re.sub(r'[^A-Za-z0-9]+', '', (classname or '')).upper()
    return normalized in {'SS1', 'SSS1'}

def class_uses_stream_for_school(school, classname):
    if not class_uses_stream(classname):
        return False
    mode = ((school or {}).get('ss1_stream_mode') or 'separate').strip().lower()
    if is_ss1_class(classname) and mode == 'combined':
        return False
    return True

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
    key = canonicalize_classname(classname)
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
    return progression.get(key)

def is_valid_promotion_target(from_class, to_class):
    """Allow only direct next-class progression."""
    expected = next_class_in_sequence(from_class)
    if not expected:
        return False
    return canonicalize_classname(to_class) == expected

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

def parse_subjects_text(value):
    """Parse comma-separated subjects into a clean list."""
    return [normalize_subject_name(s) for s in (value or '').split(',') if s.strip()]

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
    with db_connection() as conn:
        c = conn.cursor()
        db_execute(
            c,
            '''SELECT classname, core_subjects, science_subjects, art_subjects,
                      commercial_subjects, optional_subjects, optional_subject_limit
               FROM class_subject_configs
               WHERE school_id = ?
                 AND (
                   LOWER(classname) = LOWER(?)
                   OR REGEXP_REPLACE(UPPER(classname), '[^A-Z0-9]+', '', 'g') = ?
                 )
               ORDER BY
                 CASE WHEN LOWER(classname) = LOWER(?) THEN 0 ELSE 1 END,
                 id ASC
               LIMIT 1''',
            (school_id, classname, class_key, classname)
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
        'optional_subject_limit': int(row[6] or 0),
    }

def get_all_class_subject_configs(school_id):
    """Fetch all class subject configs for a school."""
    with db_connection() as conn:
        c = conn.cursor()
        db_execute(
            c,
            '''SELECT classname, core_subjects, science_subjects, art_subjects,
                      commercial_subjects, optional_subjects, optional_subject_limit
               FROM class_subject_configs
               WHERE school_id = ?
               ORDER BY classname''',
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
            'optional_subject_limit': int(row[6] or 0),
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
            '''SELECT classname, bucket, subject_name
               FROM global_class_subject_catalog
               ORDER BY classname, bucket, subject_name'''
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

def save_class_subject_config(
    school_id,
    classname,
    core_subjects,
    science_subjects=None,
    art_subjects=None,
    commercial_subjects=None,
    optional_subjects=None,
    optional_subject_limit=0,
):
    """Upsert class subject config."""
    classname = canonicalize_classname(classname)
    core = _dedupe_keep_order([normalize_subject_name(s) for s in (core_subjects or [])])
    science = _dedupe_keep_order([normalize_subject_name(s) for s in (science_subjects or [])])
    art = _dedupe_keep_order([normalize_subject_name(s) for s in (art_subjects or [])])
    commercial = _dedupe_keep_order([normalize_subject_name(s) for s in (commercial_subjects or [])])
    optional = _dedupe_keep_order([normalize_subject_name(s) for s in (optional_subjects or [])])
    optional_limit = max(0, int(optional_subject_limit or 0))

    with db_connection(commit=True) as conn:
        c = conn.cursor()
        db_execute(
            c,
            '''INSERT INTO class_subject_configs
               (school_id, classname, core_subjects, science_subjects, art_subjects,
                commercial_subjects, optional_subjects, optional_subject_limit, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
               ON CONFLICT(school_id, classname) DO UPDATE SET
                 core_subjects = excluded.core_subjects,
                 science_subjects = excluded.science_subjects,
                 art_subjects = excluded.art_subjects,
                 commercial_subjects = excluded.commercial_subjects,
                 optional_subjects = excluded.optional_subjects,
                 optional_subject_limit = excluded.optional_subject_limit,
                 updated_at = CURRENT_TIMESTAMP''',
            (
                school_id,
                classname,
                json.dumps(core),
                json.dumps(science),
                json.dumps(art),
                json.dumps(commercial),
                json.dumps(optional),
                optional_limit,
            ),
        )

def delete_class_subject_config(school_id, classname):
    """Delete one class subject configuration for a school/class."""
    class_key = canonicalize_classname(classname)
    with db_connection(commit=True) as conn:
        c = conn.cursor()
        db_execute(
            c,
            '''DELETE FROM class_subject_configs
               WHERE school_id = ?
                 AND (
                   LOWER(classname) = LOWER(?)
                   OR REGEXP_REPLACE(UPPER(classname), '[^A-Z0-9]+', '', 'g') = ?
                 )''',
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

    optional_limit = int(config.get('optional_subject_limit', 0) or 0) if uses_stream else 0
    if optional_limit > 0 and len(selected_optional) > optional_limit:
        return None, None, f'Select at most {optional_limit} optional subject(s).'

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
    student['scores'] = {subj: existing_scores[subj] for subj in existing_scores if subj in desired_subjects}
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
            '''SELECT exam_mode, objective_max, theory_max, exam_score_max
               FROM assessment_configs
               WHERE school_id = ? AND level = ?
               LIMIT 1''',
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
        '''INSERT INTO assessment_configs
           (school_id, level, exam_mode, objective_max, theory_max, exam_score_max, updated_at)
           VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
           ON CONFLICT(school_id, level) DO UPDATE SET
             exam_mode = excluded.exam_mode,
             objective_max = excluded.objective_max,
             theory_max = excluded.theory_max,
             exam_score_max = excluded.exam_score_max,
             updated_at = CURRENT_TIMESTAMP''',
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
    for student in students_list:
        class_name = student.get('class_name', '')
        term = student.get('term', '')
        stream = (student.get('stream') or '').strip()
        rank_key = f"{class_name}__{term}"
        if ss_ranking_mode == 'separate' and class_uses_stream_for_school(school or {}, class_name):
            rank_key = f"{class_name}__{term}__{stream or 'Unassigned'}"
        if rank_key not in class_groups:
            class_groups[rank_key] = []
        class_groups[rank_key].append(student)

    for rank_key, class_students in class_groups.items():
        sorted_students = sorted(class_students, key=lambda x: x.get('average_marks', 0), reverse=True)
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
            '''INSERT INTO schools (school_id, school_name, location, phone, email, principal_name, motto, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)''',
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

def create_school_with_index_id(school_name, location='', phone='', email='', principal_name='', motto=''):
    """Create a new school and use the table index (id) as school_id."""
    with db_connection(commit=True) as conn:
        c = conn.cursor()
        temp_school_id = f"tmp_{secrets.token_hex(8)}"
        db_execute(
            c,
            '''INSERT INTO schools (school_id, school_name, location, phone, email, principal_name, motto, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)
               RETURNING id''',
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

def get_school(school_id):
    """Get school details."""
    with db_connection() as conn:
        c = conn.cursor()
        db_execute(c, 'SELECT * FROM schools WHERE school_id = ?', (school_id,))
        row = c.fetchone()
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
            'school_logo': row['school_logo'],
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
            'ss_ranking_mode': row['ss_ranking_mode'] if 'ss_ranking_mode' in row.keys() else 'together',
            'ss1_stream_mode': row['ss1_stream_mode'] if 'ss1_stream_mode' in row.keys() else 'separate',
        }

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
                'school_logo': row['school_logo'],
                'academic_year': row['academic_year'],
                'current_term': row['current_term'],
                'operations_enabled': row['operations_enabled'] if 'operations_enabled' in row.keys() else 1,
                'teacher_operations_enabled': row['teacher_operations_enabled'] if 'teacher_operations_enabled' in row.keys() else 1,
                'ss1_stream_mode': row['ss1_stream_mode'] if 'ss1_stream_mode' in row.keys() else 'separate',
            })
        return schools

def get_school_admin_username(school_id):
    """Get the school admin username/email for a school."""
    with db_connection() as conn:
        c = conn.cursor()
        db_execute(
            c,
            '''SELECT username FROM users
               WHERE CAST(school_id AS TEXT) = ? AND role = 'school_admin'
               ORDER BY id ASC
               LIMIT 1''',
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
                    '''UPDATE users SET username = ?, school_id = ?, role = 'school_admin'
                       WHERE LOWER(username) = LOWER(?) AND role = 'school_admin' AND CAST(school_id AS TEXT) = ?''',
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
    db_execute(c, '''UPDATE schools SET
                    school_name = ?, location = ?, school_logo = ?, academic_year = ?,
                    current_term = ?, test_enabled = ?, exam_enabled = ?,
                    max_tests = ?, test_score_max = ?, exam_objective_max = ?, exam_theory_max = ?,
                    grade_a_min = ?, grade_b_min = ?, grade_c_min = ?, grade_d_min = ?, pass_mark = ?,
                    ss_ranking_mode = ?, ss1_stream_mode = ?
                    WHERE school_id = ?''',
               (settings.get('school_name'), settings.get('location', ''), settings.get('school_logo'),
                settings.get('academic_year'), settings.get('current_term'),
                settings.get('test_enabled', 1), settings.get('exam_enabled', 1),
                settings.get('max_tests', 3), settings.get('test_score_max', 30),
                settings.get('exam_objective_max', 30), settings.get('exam_theory_max', 40),
                settings.get('grade_a_min', 70), settings.get('grade_b_min', 60),
                settings.get('grade_c_min', 50), settings.get('grade_d_min', 40),
                settings.get('pass_mark', 50),
                settings.get('ss_ranking_mode', 'together'),
                settings.get('ss1_stream_mode', 'separate'),
                school_id))

def update_school_settings(school_id, settings):
    """Update school settings."""
    with db_connection(commit=True) as conn:
        c = conn.cursor()
        update_school_settings_with_cursor(c, school_id, settings)

def set_school_operations_enabled(school_id, enabled):
    """Enable/disable teacher/student operations for a school."""
    with db_connection(commit=True) as conn:
        c = conn.cursor()
        db_execute(
            c,
            'UPDATE schools SET operations_enabled = ? WHERE school_id = ?',
            (1 if enabled else 0, school_id)
        )

def set_teacher_operations_enabled(school_id, enabled):
    """Enable/disable teacher editing operations for a school (set by school admin)."""
    with db_connection(commit=True) as conn:
        c = conn.cursor()
        db_execute(
            c,
            'UPDATE schools SET teacher_operations_enabled = ? WHERE school_id = ?',
            (1 if enabled else 0, school_id)
        )

def get_grade_config(school_id):
    """Get grade thresholds for a school."""
    school = get_school(school_id) or {}
    return {
        'a': int(school.get('grade_a_min', 70) or 70),
        'b': int(school.get('grade_b_min', 60) or 60),
        'c': int(school.get('grade_c_min', 50) or 50),
        'd': int(school.get('grade_d_min', 40) or 40),
        'pass_mark': int(school.get('pass_mark', 50) or 50),
    }

def grade_from_score(score, cfg):
    """Get letter grade from score."""
    score = float(score or 0)
    if score >= cfg['a']:
        return 'A'
    if score >= cfg['b']:
        return 'B'
    if score >= cfg['c']:
        return 'C'
    if score >= cfg['d']:
        return 'D'
    return 'F'

def status_from_score(score, cfg):
    """Get pass/fail status from score."""
    return 'Pass' if float(score or 0) >= cfg['pass_mark'] else 'Fail'

def subject_overall_mark(subject_scores):
    """Safely compute one subject total score from stored score fields."""
    if not isinstance(subject_scores, dict):
        return 0.0
    explicit = subject_scores.get('overall_mark')

    total_test = subject_scores.get('total_test')
    if not isinstance(total_test, (int, float)):
        total_test = 0.0
        for k, v in subject_scores.items():
            if str(k).startswith('test_') and isinstance(v, (int, float)):
                total_test += float(v)

    total_exam = subject_scores.get('total_exam')
    if not isinstance(total_exam, (int, float)):
        if isinstance(subject_scores.get('exam_score'), (int, float)):
            total_exam = float(subject_scores.get('exam_score') or 0)
        else:
            objective = float(subject_scores.get('objective', 0) or 0)
            theory = float(subject_scores.get('theory', 0) or 0)
            total_exam = objective + theory

    # Backward-compat: if legacy rows only have overall_mark and no components, use it.
    has_components = (
        isinstance(subject_scores.get('total_test'), (int, float)) or
        isinstance(subject_scores.get('total_exam'), (int, float)) or
        isinstance(subject_scores.get('exam_score'), (int, float)) or
        isinstance(subject_scores.get('objective'), (int, float)) or
        isinstance(subject_scores.get('theory'), (int, float)) or
        any(str(k).startswith('test_') and isinstance(v, (int, float)) for k, v in subject_scores.items())
    )
    if not has_components and isinstance(explicit, (int, float)):
        return float(explicit)

    return float(total_test or 0) + float(total_exam or 0)

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
    if int((school or {}).get('operations_enabled', 1) or 1):
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

def is_score_complete_for_subject(subject_scores, school):
    if not isinstance(subject_scores, dict):
        return False
    if 'overall_mark' not in subject_scores:
        return False
    if school.get('test_enabled', 1) and 'total_test' not in subject_scores:
        return False
    if school.get('exam_enabled', 1) and 'total_exam' not in subject_scores:
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
        if not is_score_complete_for_subject(scores.get(subject), school):
            return False
    return True

def set_result_published(school_id, classname, term, academic_year, teacher_id, is_published, teacher_name='', principal_name=''):
    """Publish/unpublish a class result for a term."""
    school = get_school(school_id) or {}
    resolved_principal_name = (principal_name or school.get('principal_name', '') or '').strip()
    resolved_teacher_name = (teacher_name or '').strip()
    if not resolved_teacher_name and teacher_id:
        with db_connection() as conn:
            c = conn.cursor()
            db_execute(
                c,
                '''SELECT firstname, lastname
                   FROM teachers
                   WHERE school_id = ? AND user_id = ?
                   LIMIT 1''',
                (school_id, teacher_id),
            )
            row = c.fetchone()
            if row:
                resolved_teacher_name = f"{row[0] or ''} {row[1] or ''}".strip() or str(teacher_id)
            else:
                resolved_teacher_name = str(teacher_id)
    with db_connection(commit=True) as conn:
        c = conn.cursor()
        db_execute(
            c,
            '''INSERT INTO result_publications
               (school_id, classname, term, academic_year, teacher_id, teacher_name, principal_name, is_published, published_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
               ON CONFLICT(school_id, classname, term, academic_year) DO UPDATE SET
                 teacher_id = excluded.teacher_id,
                 teacher_name = excluded.teacher_name,
                 principal_name = excluded.principal_name,
                 is_published = excluded.is_published,
                 published_at = excluded.published_at,
                 updated_at = CURRENT_TIMESTAMP''',
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

def is_result_published(school_id, classname, term, academic_year=''):
    with db_connection() as conn:
        c = conn.cursor()
        db_execute(
            c,
            '''SELECT is_published FROM result_publications
               WHERE school_id = ? AND classname = ? AND term = ? AND COALESCE(academic_year, '') = COALESCE(?, '')
               LIMIT 1''',
            (school_id, classname, term, academic_year or ''),
        )
        row = c.fetchone()
        return bool(row and int(row[0]) == 1)

def snapshot_published_results_for_class(school_id, classname, term):
    """Save/refresh per-student published snapshots for one class+term."""
    school = get_school(school_id) or {}
    academic_year = school.get('academic_year', '')
    grade_cfg = get_grade_config(school_id)
    class_students = load_students(school_id, class_filter=classname, term_filter=term)
    with db_connection(commit=True) as conn:
        c = conn.cursor()
        for sid, student in class_students.items():
            scores = student.get('scores', {}) if isinstance(student.get('scores', {}), dict) else {}
            overall_marks = [subject_overall_mark(s) for s in scores.values() if isinstance(s, dict)]
            average_marks = (sum(overall_marks) / len(overall_marks)) if overall_marks else 0
            grade = grade_from_score(average_marks, grade_cfg)
            status = status_from_score(average_marks, grade_cfg)
            db_execute(
                c,
                '''INSERT INTO published_student_results
                   (school_id, student_id, firstname, classname, academic_year, term, stream, number_of_subject, subjects, scores, teacher_comment, average_marks, grade, status, published_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                   ON CONFLICT(school_id, student_id, academic_year, term) DO UPDATE SET
                     firstname = excluded.firstname,
                     classname = excluded.classname,
                     academic_year = excluded.academic_year,
                     stream = excluded.stream,
                     number_of_subject = excluded.number_of_subject,
                     subjects = excluded.subjects,
                     scores = excluded.scores,
                     teacher_comment = excluded.teacher_comment,
                     average_marks = excluded.average_marks,
                     grade = excluded.grade,
                     status = excluded.status,
                     published_at = excluded.published_at''',
                (
                    school_id,
                    sid,
                    student.get('firstname', ''),
                    classname,
                    academic_year,
                    term,
                    student.get('stream', 'N/A'),
                    int(student.get('number_of_subject', 0) or 0),
                    json.dumps(student.get('subjects', [])),
                    json.dumps(scores),
                    (student.get('teacher_comment') or '').strip(),
                    float(average_marks),
                    grade,
                    status,
                    datetime.now().isoformat(),
                ),
            )

def publish_results_for_class_atomic(school_id, classname, term, teacher_id):
    """Publish class results in a single transaction (snapshot + publish flag)."""
    school = get_school(school_id) or {}
    academic_year = school.get('academic_year', '')
    grade_cfg = get_grade_config(school_id)
    principal_name = (school.get('principal_name', '') or '').strip()
    teacher_profile = get_teachers(school_id).get(teacher_id, {})
    teacher_name = f"{teacher_profile.get('firstname', '')} {teacher_profile.get('lastname', '')}".strip() or str(teacher_id)
    class_students = load_students(school_id, class_filter=classname, term_filter=term)

    with db_connection(commit=True) as conn:
        c = conn.cursor()
        for sid, student in class_students.items():
            scores = student.get('scores', {}) if isinstance(student.get('scores', {}), dict) else {}
            overall_marks = [subject_overall_mark(s) for s in scores.values() if isinstance(s, dict)]
            average_marks = (sum(overall_marks) / len(overall_marks)) if overall_marks else 0
            grade = grade_from_score(average_marks, grade_cfg)
            status = status_from_score(average_marks, grade_cfg)
            db_execute(
                c,
                '''INSERT INTO published_student_results
                   (school_id, student_id, firstname, classname, academic_year, term, stream, number_of_subject, subjects, scores, teacher_comment, average_marks, grade, status, published_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                   ON CONFLICT(school_id, student_id, academic_year, term) DO UPDATE SET
                     firstname = excluded.firstname,
                     classname = excluded.classname,
                     academic_year = excluded.academic_year,
                     stream = excluded.stream,
                     number_of_subject = excluded.number_of_subject,
                     subjects = excluded.subjects,
                     scores = excluded.scores,
                     teacher_comment = excluded.teacher_comment,
                     average_marks = excluded.average_marks,
                     grade = excluded.grade,
                     status = excluded.status,
                     published_at = excluded.published_at''',
                (
                    school_id,
                    sid,
                    student.get('firstname', ''),
                    classname,
                    academic_year,
                    term,
                    student.get('stream', 'N/A'),
                    int(student.get('number_of_subject', 0) or 0),
                    json.dumps(student.get('subjects', [])),
                    json.dumps(scores),
                    (student.get('teacher_comment') or '').strip(),
                    float(average_marks),
                    grade,
                    status,
                    datetime.now().isoformat(),
                ),
            )

        db_execute(
            c,
            '''INSERT INTO result_publications
               (school_id, classname, term, academic_year, teacher_id, teacher_name, principal_name, is_published, published_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
               ON CONFLICT(school_id, classname, term, academic_year) DO UPDATE SET
                 teacher_id = excluded.teacher_id,
                 teacher_name = excluded.teacher_name,
                 principal_name = excluded.principal_name,
                 is_published = excluded.is_published,
                 published_at = excluded.published_at,
                 updated_at = CURRENT_TIMESTAMP''',
            (
                school_id,
                classname,
                term,
                academic_year,
                teacher_id,
                teacher_name,
                principal_name,
                1,
                datetime.now().isoformat(),
            ),
        )

def get_published_terms_for_student(school_id, student_id, classname=''):
    with db_connection() as conn:
        c = conn.cursor()
        if classname:
            db_execute(
                c,
                '''SELECT academic_year, term, classname, published_at FROM published_student_results
                   WHERE school_id = ? AND student_id = ? AND LOWER(classname) = LOWER(?)
                   ORDER BY published_at ASC''',
                (school_id, student_id, classname),
            )
        else:
            db_execute(
                c,
                '''SELECT academic_year, term, classname, published_at FROM published_student_results
                   WHERE school_id = ? AND student_id = ?
                   ORDER BY published_at ASC''',
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

def load_published_student_result(school_id, student_id, term, academic_year='', classname=''):
    with db_connection() as conn:
        c = conn.cursor()
        if academic_year and classname:
            db_execute(
                c,
                '''SELECT firstname, classname, academic_year, term, stream, number_of_subject, subjects, scores, teacher_comment, average_marks, grade, status
                   FROM published_student_results
                   WHERE school_id = ? AND student_id = ? AND term = ? AND COALESCE(academic_year, '') = ? AND LOWER(classname) = LOWER(?)
                   ORDER BY published_at DESC
                   LIMIT 1''',
                (school_id, student_id, term, academic_year, classname),
            )
        elif academic_year:
            db_execute(
                c,
                '''SELECT firstname, classname, academic_year, term, stream, number_of_subject, subjects, scores, teacher_comment, average_marks, grade, status
                   FROM published_student_results
                   WHERE school_id = ? AND student_id = ? AND term = ? AND COALESCE(academic_year, '') = ?
                   ORDER BY published_at DESC
                   LIMIT 1''',
                (school_id, student_id, term, academic_year),
            )
        elif classname:
            db_execute(
                c,
                '''SELECT firstname, classname, academic_year, term, stream, number_of_subject, subjects, scores, teacher_comment, average_marks, grade, status
                   FROM published_student_results
                   WHERE school_id = ? AND student_id = ? AND term = ? AND LOWER(classname) = LOWER(?)
                   ORDER BY published_at DESC
                   LIMIT 1''',
                (school_id, student_id, term, classname),
            )
        else:
            db_execute(
                c,
                '''SELECT firstname, classname, academic_year, term, stream, number_of_subject, subjects, scores, teacher_comment, average_marks, grade, status
                   FROM published_student_results
                   WHERE school_id = ? AND student_id = ? AND term = ?
                   ORDER BY published_at DESC
                   LIMIT 1''',
                (school_id, student_id, term),
            )
        row = c.fetchone()
    if not row:
        return None
    return {
        'firstname': row[0],
        'classname': row[1],
        'academic_year': row[2] or '',
        'term': row[3],
        'stream': row[4],
        'number_of_subject': row[5],
        'subjects': json.loads(row[6]) if row[6] else [],
        'scores': json.loads(row[7]) if row[7] else {},
        'teacher_comment': row[8] or '',
        'average_marks': float(row[9] or 0),
        'Grade': row[10],
        'Status': row[11],
    }

def load_published_class_results(school_id, classname, term, academic_year=''):
    with db_connection() as conn:
        c = conn.cursor()
        if academic_year:
            db_execute(
                c,
                '''SELECT student_id, stream, average_marks, subjects, scores
                   FROM published_student_results
                   WHERE school_id = ? AND classname = ? AND term = ? AND COALESCE(academic_year, '') = ?''',
                (school_id, classname, term, academic_year),
            )
        else:
            db_execute(
                c,
                '''SELECT student_id, stream, average_marks, subjects, scores
                   FROM published_student_results
                   WHERE school_id = ? AND classname = ? AND term = ?''',
                (school_id, classname, term),
            )
        rows = c.fetchall()
    out = []
    for row in rows:
        out.append({
            'student_id': row[0],
            'stream': row[1],
            'average_marks': float(row[2] or 0),
            'subjects': json.loads(row[3]) if row[3] else [],
            'scores': json.loads(row[4]) if row[4] else {},
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
            '''INSERT INTO result_views
               (school_id, student_id, term, academic_year, first_viewed_at, last_viewed_at, view_count)
               VALUES (?, ?, ?, ?, ?, ?, 1)
               ON CONFLICT(school_id, student_id, term, academic_year) DO UPDATE SET
                 last_viewed_at = excluded.last_viewed_at,
                 view_count = result_views.view_count + 1''',
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
            f'''SELECT psr.classname,
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
                GROUP BY psr.classname''',
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
            f'''SELECT DISTINCT psr.student_id
                FROM published_student_results psr
                JOIN result_views rv
                  ON rv.school_id = psr.school_id
                 AND rv.student_id = psr.student_id
                 AND rv.term = psr.term
                 AND COALESCE(rv.academic_year, '') = COALESCE(psr.academic_year, '')
                WHERE psr.school_id = ? AND psr.term = ?
                  AND COALESCE(psr.academic_year, '') = COALESCE(?, '')
                  AND psr.classname IN ({placeholders})''',
            tuple(params),
        )
        return {row[0] for row in c.fetchall() if row and row[0]}

def get_school_publication_statuses(school_id, term, academic_year=''):
    """Get class publication/view status for school admin dashboard."""
    assignments = [
        a for a in get_class_assignments(school_id)
        if (a.get('term') or '') == term and (a.get('academic_year') or '') == (academic_year or '')
    ]
    classes = [a.get('classname', '') for a in assignments if a.get('classname')]
    counts_by_class = get_class_published_view_counts(school_id, term, academic_year, classes)

    publication_rows = {}
    with db_connection() as conn:
        c = conn.cursor()
        db_execute(
            c,
            '''SELECT classname, teacher_id, is_published, published_at
               FROM result_publications
               WHERE school_id = ? AND term = ? AND COALESCE(academic_year, '') = COALESCE(?, '')''',
            (school_id, term, academic_year or ''),
        )
        for row in c.fetchall():
            publication_rows[row[0]] = {
                'teacher_id': row[1],
                'is_published': bool(int(row[2] or 0)),
                'published_at': row[3] or '',
            }

    out = []
    for a in assignments:
        classname = a.get('classname', '')
        pub = publication_rows.get(classname, {})
        cnt = counts_by_class.get(classname, {})
        out.append({
            'classname': classname,
            'teacher_name': a.get('teacher_name', ''),
            'teacher_id': a.get('teacher_id', ''),
            'term': term,
            'is_published': bool(pub.get('is_published', False)),
            'published_at': pub.get('published_at', ''),
            'published_count': int(cnt.get('published_count', 0)),
            'viewed_count': int(cnt.get('viewed_count', 0)),
        })
    out.sort(key=lambda x: (x.get('classname', ''), x.get('teacher_name', '')))
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
            sdata = x.get('scores', {}).get(subject, {}) if isinstance(x.get('scores', {}), dict) else {}
            mark = subject_overall_mark(sdata)
            ranked.append((x.get('student_id', ''), float(mark)))
        ranked.sort(key=lambda k: k[1], reverse=True)
        size = len(ranked)
        prev_score = None
        current_pos = 0
        for idx, (sid, score) in enumerate(ranked, 1):
            if prev_score is None or not same_score(score, prev_score):
                current_pos = idx
            if sid == student_id:
                subject_positions[subject] = {'pos': current_pos, 'size': size}
                break
            prev_score = score
    return position, subject_positions

# ==================== STUDENT FUNCTIONS ====================

def load_students(school_id, class_filter='', term_filter=''):
    """Load students for a school."""
    with db_connection() as conn:
        c = conn.cursor()
        query = 'SELECT student_id, firstname, classname, first_year_class, term, stream, number_of_subject, subjects, scores, promoted FROM students WHERE school_id = ?'
        params = [school_id]
        
        if class_filter:
            query += ' AND classname = ?'
            params.append(class_filter)
        if term_filter:
            query += ' AND term = ?'
            params.append(term_filter)
        
        query += ' ORDER BY student_id'
        
        db_execute(c, query, tuple(params))
        students_data = {}
        for row in c.fetchall():
            student_id, firstname, classname, first_year_class, term, stream, number_of_subject, subjects_str, scores_str, promoted = row
            subjects = json.loads(subjects_str) if subjects_str else []
            scores = json.loads(scores_str) if scores_str else {}
            students_data[student_id] = {
                'firstname': firstname,
                'classname': classname,
                'first_year_class': first_year_class,
                'term': term,
                'stream': stream,
                'number_of_subject': number_of_subject,
                'subjects': subjects,
                'scores': scores,
                'promoted': promoted
            }
        return students_data

def load_students_for_classes(school_id, classnames, term_filter=''):
    """Load students for a school limited to a class list."""
    class_list = [str(c).strip() for c in (classnames or []) if str(c).strip()]
    if not class_list:
        return {}
    with db_connection() as conn:
        c = conn.cursor()
        placeholders = ','.join(['?'] * len(class_list))
        query = (
            'SELECT student_id, firstname, classname, first_year_class, term, stream, '
            'number_of_subject, subjects, scores, promoted '
            f'FROM students WHERE school_id = ? AND classname IN ({placeholders})'
        )
        params = [school_id] + class_list
        if term_filter:
            query += ' AND term = ?'
            params.append(term_filter)
        query += ' ORDER BY student_id'
        db_execute(c, query, tuple(params))
        students_data = {}
        for row in c.fetchall():
            student_id, firstname, classname, first_year_class, term, stream, number_of_subject, subjects_str, scores_str, promoted = row
            students_data[student_id] = {
                'firstname': firstname,
                'classname': classname,
                'first_year_class': first_year_class,
                'term': term,
                'stream': stream,
                'number_of_subject': number_of_subject,
                'subjects': json.loads(subjects_str) if subjects_str else [],
                'scores': json.loads(scores_str) if scores_str else {},
                'promoted': promoted
            }
        return students_data

def load_student(school_id, student_id):
    """Load a single student."""
    with db_connection() as conn:
        c = conn.cursor()
        db_execute(c, '''SELECT student_id, firstname, classname, first_year_class, term, stream, 
                       number_of_subject, subjects, scores, promoted FROM students 
                       WHERE school_id = ? AND student_id = ?''',
                   (school_id, student_id))
        row = c.fetchone()
        if not row:
            return None
        return {
            'student_id': row[0],
            'firstname': row[1],
            'classname': row[2],
            'first_year_class': row[3],
            'term': row[4],
            'stream': row[5],
            'number_of_subject': row[6],
            'subjects': json.loads(row[7]) if row[7] else [],
            'scores': json.loads(row[8]) if row[8] else {},
            'promoted': row[9]
        }

def find_student_school_id(student_id):
    """Resolve school_id for a student ID from student records."""
    with db_connection() as conn:
        c = conn.cursor()
        db_execute(
            c,
            '''SELECT school_id FROM students
               WHERE LOWER(student_id) = LOWER(?)
               ORDER BY id DESC
               LIMIT 1''',
            (student_id,)
        )
        row = c.fetchone()
        return row[0] if row else None

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
        # user_id is used for student login - same as student_id
        user_id = student_id
        
        db_execute(c, '''INSERT INTO students
                         (user_id, school_id, student_id, firstname, classname, first_year_class, term, stream, number_of_subject, subjects, scores, promoted)
                         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                         ON CONFLICT(school_id, student_id) DO UPDATE SET
                            firstname = excluded.firstname,
                            classname = excluded.classname,
                            first_year_class = excluded.first_year_class,
                            term = excluded.term,
                            stream = excluded.stream,
                            number_of_subject = excluded.number_of_subject,
                           subjects = excluded.subjects,
                           scores = excluded.scores,
                           promoted = excluded.promoted''',
                   (user_id, school_id, student_id, firstname, student_data['classname'],
                    first_year_class, term, stream, number_of_subject,
                    subjects_str, scores_str, student_data.get('promoted', 0)))

def delete_student(school_id, student_id):
    """Delete a student."""
    with db_connection(commit=True) as conn:
        c = conn.cursor()
        db_execute(c, 'DELETE FROM students WHERE school_id = ? AND student_id = ?', (school_id, student_id))

def get_student_count_by_class(school_id):
    """Get student count by class."""
    with db_connection() as conn:
        c = conn.cursor()
        db_execute(c, '''SELECT classname, COUNT(*) as count FROM students 
                       WHERE school_id = ? GROUP BY classname''', (school_id,))
        return {row[0]: row[1] for row in c.fetchall()}

def get_total_student_count(school_id):
    """Get total student count for one school."""
    with db_connection() as conn:
        c = conn.cursor()
        db_execute(c, 'SELECT COUNT(*) FROM students WHERE school_id = ?', (school_id,))
        row = c.fetchone()
        return int(row[0] or 0) if row else 0

def get_next_student_index(school_id, first_year_class):
    """Get next numeric index for generated IDs in a first-year class."""
    with db_connection() as conn:
        c = conn.cursor()
        db_execute(c, '''SELECT student_id FROM students
                       WHERE school_id = ? AND first_year_class = ?''',
                   (school_id, first_year_class))
        max_index = 0
        for row in c.fetchall():
            idx = extract_generated_id_index(row[0] if row else '')
            if idx is None:
                continue
            if idx > max_index:
                max_index = idx
        return max_index + 1

def get_next_student_index_for_class(school_id, classname):
    """
    Get next numeric index for generated IDs in a class list.
    This appends after the last existing index in that class, without re-numbering.
    """
    with db_connection() as conn:
        c = conn.cursor()
        db_execute(c, '''SELECT student_id FROM students
                      WHERE school_id = ? AND LOWER(classname) = LOWER(?)''',
                   (school_id, classname))
        max_index = 0
        for row in c.fetchall():
            idx = extract_generated_id_index(row[0] if row else '')
            if idx is None:
                continue
            if idx > max_index:
                max_index = idx
        return max_index + 1

def promote_students(school_id, from_class, to_class, action_by_student, term=''):
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
            f'''SELECT student_id, firstname, first_year_class, classname, subjects FROM students
                       {where}''',
            tuple(params),
        )
        
        for row in c.fetchall():
            student_id = row[0]
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
                promoted_flag = 1
                db_execute(
                    c,
                    '''UPDATE students
                       SET classname = ?, first_year_class = ?, promoted = ?, stream = ?,
                           subjects = ?, number_of_subject = ?, scores = ?
                       WHERE school_id = ? AND student_id = ?''',
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
            elif action == 'remove':
                # Student left school: remove roster and login account for this school.
                db_execute(c, 'DELETE FROM students WHERE school_id = ? AND student_id = ?', (school_id, student_id))
                db_execute(c, 'DELETE FROM users WHERE school_id = ? AND username = ? AND role = ?', (school_id, student_id, 'student'))
            else:
                # Not passed / repeat class
                db_execute(
                    c,
                    '''UPDATE students
                       SET promoted = 0, scores = ?
                       WHERE school_id = ? AND student_id = ?''',
                    (json.dumps({}), school_id, student_id)
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
        return
    if src_term.lower() == dst_term.lower() and src_year == dst_year:
        return

    db_execute(
        c,
        '''INSERT INTO class_assignments (school_id, teacher_id, classname, term, academic_year)
           SELECT school_id, teacher_id, classname, ?, ?
           FROM class_assignments
           WHERE school_id = ? AND LOWER(term) = LOWER(?) AND COALESCE(academic_year, '') = COALESCE(?, '')
           ON CONFLICT(school_id, classname, term, academic_year) DO NOTHING''',
        (dst_term, dst_year, school_id, src_term, src_year),
    )
    db_execute(
        c,
        '''UPDATE students
           SET term = ?, scores = ?, promoted = 0
           WHERE school_id = ?
             AND LOWER(COALESCE(term, '')) = LOWER(COALESCE(?, ''))
             AND REGEXP_REPLACE(UPPER(COALESCE(classname, '')), '[^A-Z0-9]+', '', 'g') <> 'GRADUATED' ''',
        (dst_term, json.dumps({}), school_id, src_term),
    )

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
        return
    if src_term.lower() == dst_term.lower() and src_year == dst_year:
        return

    with db_connection(commit=True) as conn:
        c = conn.cursor()
        rollover_school_term_data_with_cursor(c, school_id, src_term, dst_term, src_year, dst_year)

# ==================== TEACHER FUNCTIONS ====================

def set_teacher_signature(school_id, teacher_id, signature_image):
    """Store teacher signature image for result authorization."""
    with db_connection(commit=True) as conn:
        c = conn.cursor()
        db_execute(
            c,
            '''UPDATE teachers
               SET signature_image = ?
               WHERE school_id = ? AND user_id = ?''',
            (signature_image, school_id, teacher_id),
        )

def set_principal_signature(school_id, signature_image):
    """Store principal signature image for result authorization."""
    with db_connection(commit=True) as conn:
        c = conn.cursor()
        db_execute(
            c,
            '''UPDATE schools
               SET principal_signature_image = ?, updated_at = ?
               WHERE school_id = ?''',
            (signature_image, datetime.now(), school_id),
        )

def get_signatures_for_result(school_id, classname, term, academic_year=''):
    """Resolve teacher+principal signatures tied to the publication record."""
    details = get_result_signoff_details(school_id, classname, term, academic_year)
    return details.get('teacher_signature', ''), details.get('principal_signature', '')

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
            '''SELECT teacher_id, teacher_name, principal_name
               FROM result_publications
               WHERE school_id = ? AND classname = ? AND term = ? AND COALESCE(academic_year, '') = COALESCE(?, '')
               LIMIT 1''',
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
                '''SELECT firstname, lastname, signature_image
                   FROM teachers
                   WHERE school_id = ? AND user_id = ?
                   LIMIT 1''',
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

def get_teachers(school_id):
    """Get all teachers for a school."""
    with db_connection() as conn:
        c = conn.cursor()
        db_execute(c, '''SELECT user_id, firstname, lastname, signature_image, assigned_classes FROM teachers 
                       WHERE school_id = ?''', (school_id,))
        teachers = {}
        for row in c.fetchall():
            teachers[row[0]] = {
                'firstname': row[1],
                'lastname': row[2],
                'signature_image': row[3] or '',
                'assigned_classes': json.loads(row[4]) if row[4] else []
            }
        return teachers

def save_teacher(school_id, user_id, firstname, lastname, assigned_classes):
    """Save a teacher."""
    with db_connection(commit=True) as conn:
        c = conn.cursor()
        firstname = normalize_person_name(firstname)
        lastname = normalize_person_name(lastname)
        classes_str = json.dumps(assigned_classes)
        # Check if teacher exists
        db_execute(c, 'SELECT user_id FROM teachers WHERE school_id = ? AND user_id = ?', (school_id, user_id))
        if c.fetchone():
            # Update existing teacher
            db_execute(c, 'UPDATE teachers SET firstname = ?, lastname = ?, assigned_classes = ? WHERE school_id = ? AND user_id = ?',
                       (firstname, lastname, classes_str, school_id, user_id))
        else:
            # Insert new teacher
            db_execute(c, 'INSERT INTO teachers (school_id, user_id, firstname, lastname, signature_image, assigned_classes) VALUES (?, ?, ?, ?, ?, ?)',
                       (school_id, user_id, firstname, lastname, '', classes_str))

def assign_teacher_to_class(school_id, teacher_id, classname, term, academic_year):
    """Assign teacher to a class."""
    with db_connection(commit=True) as conn:
        c = conn.cursor()
        # Provide default academic_year if None
        if not academic_year:
            academic_year = '2024-2025'
        classname = ' '.join((classname or '').strip().split())
        term = ' '.join((term or '').strip().split())
        db_execute(
            c,
            '''SELECT 1 FROM teachers
               WHERE school_id = ? AND user_id = ?
               LIMIT 1''',
            (school_id, teacher_id),
        )
        if not c.fetchone():
            raise ValueError('Selected teacher is not registered in this school.')
        db_execute(
            c,
            '''SELECT teacher_id FROM class_assignments
               WHERE school_id = ? AND LOWER(classname) = LOWER(?) AND LOWER(term) = LOWER(?) AND academic_year = ?
               LIMIT 1''',
            (school_id, classname, term, academic_year)
        )
        row = c.fetchone()
        if row and row[0] != teacher_id:
            raise ValueError(f'Class {classname} ({term}, {academic_year}) is already assigned to another teacher.')
        db_execute(c, '''INSERT INTO class_assignments
                       (school_id, teacher_id, classname, term, academic_year)
                       VALUES (?, ?, ?, ?, ?)
                       ON CONFLICT(school_id, teacher_id, classname, term, academic_year)
                       DO UPDATE SET academic_year = excluded.academic_year''',
                   (school_id, teacher_id, classname, term, academic_year))

def remove_teacher_from_class(school_id, teacher_id, classname, term, academic_year):
    """Remove teacher assignment from a class/term."""
    with db_connection(commit=True) as conn:
        c = conn.cursor()
        db_execute(
            c,
            '''DELETE FROM class_assignments
               WHERE school_id = ? AND teacher_id = ? AND LOWER(classname) = LOWER(?) AND LOWER(term) = LOWER(?) AND academic_year = ?''',
            (school_id, teacher_id, classname, term, academic_year)
        )

def get_class_assignments(school_id):
    """Get class assignments with teacher display names."""
    with db_connection() as conn:
        c = conn.cursor()
        db_execute(
            c,
            '''SELECT ca.teacher_id, ca.classname, ca.term, ca.academic_year, t.firstname, t.lastname
               FROM class_assignments ca
               LEFT JOIN teachers t ON t.user_id = ca.teacher_id AND t.school_id = ca.school_id
               WHERE ca.school_id = ?
               ORDER BY ca.classname, ca.term, ca.teacher_id''',
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
        db_execute(c, f'''SELECT DISTINCT classname FROM class_assignments 
                       WHERE {' AND '.join(where)}''',
                   tuple(params))
        return [row[0] for row in c.fetchall()]

def teacher_has_class_access(school_id, teacher_id, classname, term='', academic_year=''):
    """Check whether teacher is assigned to a class."""
    if not classname:
        return False
    target = (classname or '').strip().lower()
    classes = {(c or '').strip().lower() for c in get_teacher_classes(school_id, teacher_id, term=term, academic_year=academic_year)}
    return target in classes

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
            '''UPDATE reports
               SET status = 'read',
                   read_at = COALESCE(read_at, ?)
               WHERE status = 'unread' ''',
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
                '''UPDATE reports
                   SET status = 'read',
                       read_at = COALESCE(read_at, ?)
                   WHERE id = ?''',
                (now_ts, int(report_id)),
            )
        else:
            db_execute(
                c,
                '''UPDATE reports
                   SET status = 'unread',
                       read_at = NULL
                   WHERE id = ?''',
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
            '''SELECT table_name
               FROM information_schema.tables
               WHERE table_schema = 'public' AND table_type = 'BASE TABLE'
               ORDER BY table_name'''
        )
        return [row[0] for row in c.fetchall() if row and row[0]]

def save_report(user_id, description):
    """Save a report."""
    with db_connection(commit=True) as conn:
        c = conn.cursor()
        db_execute(c, 'INSERT INTO reports (user_id, description, timestamp, status) VALUES (?, ?, ?, ?)',
                   (user_id, description, datetime.now().isoformat(), 'unread'))

# ==================== ROUTES ====================

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
    school = get_school(school_id)
    if not school or int(school.get('operations_enabled', 1)):
        # School-level OFF is not active, but teacher-level OFF may still apply.
        if role != 'teacher' or int(school.get('teacher_operations_enabled', 1) or 1):
            return None

    teacher_blocked_endpoints = {
        'teacher_allocate_stream',
        'teacher_enter_scores',
        'teacher_upload_csv',
        'teacher_publish_results',
    }
    school_admin_blocked_endpoints = {
        'school_admin_class_subjects',
        'school_admin_settings',
        'school_admin_change_password',
        'school_admin_add_teacher',
        'school_admin_promote',
        'school_admin_add_students_by_class',
        'school_admin_assign_teacher',
        'school_admin_toggle_operations',
        'school_admin_remove_teacher_assignment',
    }

    if role == 'teacher' and endpoint in teacher_blocked_endpoints:
        if not int(school.get('operations_enabled', 1) or 1):
            flash('School operations are OFF by super admin. Teachers are read-only now.', 'error')
        elif not int(school.get('teacher_operations_enabled', 1) or 1):
            flash('Teacher operations are OFF by school admin. Teachers are read-only now.', 'error')
        else:
            return None
        return redirect(url_for('teacher_dashboard'))

    if role == 'school_admin' and (endpoint in school_admin_blocked_endpoints or request.method == 'POST'):
        flash('School operations are OFF by super admin. School admin is currently in read-only mode.', 'error')
        return redirect(url_for('school_admin_dashboard'))

    return None

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
        
        if user and check_password(user['password_hash'], password):
            role = user.get('role')
            if role not in {'super_admin', 'school_admin', 'teacher', 'student'}:
                register_failed_login('login', username, client_ip)
                flash('Invalid account role configuration. Contact system administrator.', 'error')
                return render_template('shared/login.html', terms_read=terms_read)
            terms_accepted = int(user.get('terms_accepted') or 0)
            if role != 'super_admin' and not terms_accepted and not agreed_terms:
                flash('You must agree to the Terms and Privacy Policy to continue.', 'error')
                return render_template('shared/login.html', terms_read=terms_read)
            if role != 'super_admin' and not terms_accepted and agreed_terms:
                mark_terms_accepted(user.get('username'))

            user_school_id = user.get('school_id')
            if user.get('role') == 'student' and not user_school_id:
                resolved_school_id = find_student_school_id(user.get('username'))
                if resolved_school_id:
                    update_user_school_id_only(user.get('username'), resolved_school_id)
                    user_school_id = resolved_school_id
            if role != 'super_admin' and not user_school_id:
                flash('Account is missing school assignment. Contact administrator.', 'error')
                return render_template('shared/login.html', terms_read=terms_read)
            if role != 'super_admin' and not get_school(user_school_id):
                flash('Account is linked to an invalid school. Contact administrator.', 'error')
                return render_template('shared/login.html', terms_read=terms_read)

            update_login_timestamps(user.get('username'))
            clear_failed_login('login', username, client_ip)
            session.clear()
            session['user_id'] = user['username']
            session['role'] = user['role']
            session['school_id'] = user_school_id
            
            # Redirect based on role
            if user['role'] == 'super_admin':
                return redirect(url_for('super_admin_dashboard'))
            elif user['role'] == 'school_admin':
                return redirect(url_for('school_admin_dashboard'))
            elif user['role'] == 'teacher':
                return redirect(url_for('teacher_dashboard'))
            elif user['role'] == 'student':
                return redirect(url_for('student_dashboard'))
            else:
                return redirect(url_for('menu'))
        else:
            register_failed_login('login', username, client_ip)
            flash('Invalid username or password.', 'error')
    
    return render_template('shared/login.html', terms_read=terms_read)

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

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('home'))

# ==================== SUPER ADMIN ROUTES ====================

@app.route('/super-admin')
def super_admin_dashboard():
    if session.get('role') != 'super_admin':
        return redirect(url_for('login'))
    
    schools = get_all_schools()
    last_login_at = format_timestamp(get_last_login_at(session.get('user_id')))
    for school in schools:
        school['admin_username'] = get_school_admin_username(school.get('school_id'))
    return render_template('super/super_admin_dashboard.html', schools=schools, last_login_at=last_login_at)

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
    admin_username = request.form.get('admin_username', '').strip().lower()
    admin_password = request.form.get('admin_password', '').strip()
    
    if school_name and admin_username and admin_password:
        try:
            if not is_valid_email(admin_username):
                flash('School admin username must be a valid email address.', 'error')
                return redirect(url_for('super_admin_dashboard'))
            if school_email and not is_valid_email(school_email):
                flash('School contact email must be a valid email address.', 'error')
                return redirect(url_for('super_admin_dashboard'))

            existing_admin = get_user(admin_username)
            if existing_admin:
                flash(f'Admin username "{admin_username}" already exists. Please choose another username.', 'error')
                return redirect(url_for('super_admin_dashboard'))

            school_id = create_school_with_index_id(
                school_name,
                location,
                phone=phone,
                email=school_email,
                principal_name=principal_name,
                motto=motto,
            )
            
            # Create school admin user with the provided username and password
            password_hash = hash_password(admin_password)
            upsert_user(admin_username, password_hash, 'school_admin', school_id)
            
            flash(f'School created successfully! School ID: {school_id} | Admin username: {admin_username}', 'success')
        except Exception as e:
            flash(f'Error creating school: {str(e)}', 'error')
    else:
        flash('Please fill in all fields.', 'error')
    
    return redirect(url_for('super_admin_dashboard'))

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
                # Delete class subject configs
                db_execute(c, 'DELETE FROM class_subject_configs WHERE school_id = ?', (school_id,))
                # Delete assessment configs
                db_execute(c, 'DELETE FROM assessment_configs WHERE school_id = ?', (school_id,))
                # Delete result publication and view history to avoid orphan records.
                db_execute(c, 'DELETE FROM result_views WHERE school_id = ?', (school_id,))
                db_execute(c, 'DELETE FROM published_student_results WHERE school_id = ?', (school_id,))
                db_execute(c, 'DELETE FROM result_publications WHERE school_id = ?', (school_id,))
                # Delete school by normalized index-based school_id (and support legacy text IDs).
                db_execute(c, 'DELETE FROM schools WHERE school_id = ? OR CAST(id AS TEXT) = ?', (school_id, school_id))
            
            flash(f'School "{school_id}" deleted successfully!', 'success')
        except Exception as e:
            flash(f'Error deleting school: {str(e)}', 'error')
    else:
        flash('School ID is required.', 'error')
    
    return redirect(url_for('super_admin_dashboard'))

@app.route('/super-admin/update-school-admin', methods=['POST'])
def super_admin_update_school_admin():
    if session.get('role') != 'super_admin':
        return redirect(url_for('login'))

    school_id = request.form.get('school_id', '').strip()
    admin_username = request.form.get('admin_username', '').strip().lower()
    admin_password = request.form.get('admin_password', '')
    if not school_id or not admin_username:
        flash('School ID and school admin email are required.', 'error')
        return redirect(url_for('super_admin_dashboard'))
    try:
        update_school_admin_account(school_id, admin_username, admin_password)
        flash(f'School admin updated for {school_id}: {admin_username}', 'success')
    except Exception as exc:
        flash(f'Error updating school admin: {str(exc)}', 'error')
    return redirect(url_for('super_admin_dashboard'))

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
    if not school_id or not school_name:
        flash('School ID and school name are required.', 'error')
        return redirect(url_for('super_admin_dashboard'))
    if school_email and not is_valid_email(school_email):
        flash('School contact email must be a valid email address.', 'error')
        return redirect(url_for('super_admin_dashboard'))
    try:
        with db_connection(commit=True) as conn:
            c = conn.cursor()
            db_execute(
                c,
                '''UPDATE schools
                   SET school_name = ?, location = ?, phone = ?, email = ?,
                       principal_name = ?, motto = ?, updated_at = ?
                   WHERE school_id = ?''',
                (school_name, location, phone, school_email, principal_name, motto, datetime.now(), school_id),
            )
        flash(f'School profile updated for {school_id}.', 'success')
    except Exception as exc:
        flash(f'Error updating school profile: {str(exc)}', 'error')
    return redirect(url_for('super_admin_dashboard'))

@app.route('/super-admin/toggle-school-operations', methods=['POST'])
def super_admin_toggle_school_operations():
    if session.get('role') != 'super_admin':
        return redirect(url_for('login'))
    school_id = request.form.get('school_id', '').strip()
    enabled = request.form.get('operations_enabled', '1').strip() == '1'
    if not school_id:
        flash('School ID is required.', 'error')
        return redirect(url_for('super_admin_dashboard'))
    set_school_operations_enabled(school_id, enabled)
    state = 'ON' if enabled else 'OFF'
    flash(f'Operations for {school_id} set to {state}.', 'success')
    return redirect(url_for('super_admin_dashboard'))

# ==================== SCHOOL ADMIN ROUTES ====================

@app.route('/school-admin')
def school_admin_dashboard():
    if session.get('role') != 'school_admin':
        return redirect(url_for('login'))
    
    school_id = session.get('school_id')
    school = get_school(school_id)
    current_term = get_current_term(school)
    current_year = (school or {}).get('academic_year', '')
    total_students = get_total_student_count(school_id)
    teachers = get_teachers(school_id)
    class_counts = get_student_count_by_class(school_id)
    assignments = get_class_assignments(school_id)
    publication_statuses = get_school_publication_statuses(school_id, current_term, current_year)
    last_login_at = format_timestamp(get_last_login_at(session.get('user_id')))
    has_principal_signature = bool((school or {}).get('principal_signature_image'))
    
    return render_template('school/school_admin_dashboard.html', 
                         school=school, 
                         total_students=total_students,
                         teachers=teachers,
                         class_counts=class_counts,
                         assignments=assignments,
                         current_term=current_term,
                         current_year=current_year,
                         last_login_at=last_login_at,
                         has_principal_signature=has_principal_signature,
                         publication_statuses=publication_statuses)

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
    subject_catalog_map = get_global_subject_catalog_map()

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
        try:
            optional_limit = int(request.form.get('optional_subject_limit', 0))
        except (TypeError, ValueError):
            optional_limit = 0

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
            optional_limit = 0

        if not core_subjects:
            flash('Subjects offered are required.', 'error')
            return redirect(url_for('school_admin_class_subjects'))

        if uses_stream and not (science_subjects or art_subjects or commercial_subjects):
            flash('For SS classes, add subjects for at least one stream (Science/Art/Commercial).', 'error')
            return redirect(url_for('school_admin_class_subjects'))

        try:
            with db_connection(commit=True) as conn:
                c = conn.cursor()
                for bucket, values in (
                    ('core', core_subjects),
                    ('science', science_subjects),
                    ('art', art_subjects),
                    ('commercial', commercial_subjects),
                    ('optional', optional_subjects),
                ):
                    for subject in values:
                        _upsert_global_catalog_subject_with_cursor(c, classname, bucket, subject)
            save_class_subject_config(
                school_id=school_id,
                classname=classname,
                core_subjects=core_subjects,
                science_subjects=science_subjects,
                art_subjects=art_subjects,
                commercial_subjects=commercial_subjects,
                optional_subjects=optional_subjects,
                optional_subject_limit=max(0, optional_limit),
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
        ss1_stream_mode = request.form.get('ss1_stream_mode', 'separate').strip().lower()
        if ss_ranking_mode not in {'together', 'separate'}:
            ss_ranking_mode = 'together'
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

        settings = {
            'school_name': request.form.get('school_name'),
            # Preserve location when settings form does not include it.
            'location': request.form.get('location', current_school.get('location', '')),
            'school_logo': request.form.get('school_logo'),
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
            'ss_ranking_mode': ss_ranking_mode,
            'ss1_stream_mode': ss1_stream_mode,
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
            assessment_updates.append({
                'level': level,
                'exam_mode': mode,
                'objective_max': objective_max,
                'theory_max': theory_max,
                'exam_score_max': exam_score_max,
            })

        changed_term_or_year = previous_term.strip().lower() != new_term.strip().lower() or previous_year != new_year
        try:
            with db_connection(commit=True) as conn:
                c = conn.cursor()
                update_school_settings_with_cursor(c, school_id, settings)
                if changed_term_or_year:
                    rollover_school_term_data_with_cursor(
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
        except Exception as exc:
            flash(f'Failed to update school settings: {str(exc)}', 'error')
            return redirect(url_for('school_admin_settings'))

        if changed_term_or_year:
            flash('Term/year changed: student working term moved forward, scores reset for new term, and teacher class assignments copied to the new term/year.', 'info')

        flash('School settings updated successfully!', 'success')
        return redirect(url_for('school_admin_dashboard'))
    
    school = get_school(school_id)
    assessment_configs = get_all_assessment_configs(school_id)
    return render_template('school/school_settings.html', school=school, assessment_configs=assessment_configs)

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
        
        user = get_user(session.get('user_id'))
        if not user or not check_password(user['password_hash'], current_password):
            flash('Current password is incorrect.', 'error')
            return redirect(url_for('school_admin_change_password'))
        
        # Update password
        password_hash = hash_password(new_password)
        upsert_user(session.get('user_id'), password_hash, 'school_admin', session.get('school_id'))
        
        flash('Password changed successfully!', 'success')
        return redirect(url_for('school_admin_dashboard'))
    
    return render_template('shared/change_password.html', form_action='school_admin_change_password', back_url='school_admin_dashboard')

@app.route('/school-admin/add-teacher', methods=['POST'])
def school_admin_add_teacher():
    if session.get('role') != 'school_admin':
        return redirect(url_for('login'))
    
    school_id = session.get('school_id')
    username = request.form.get('username', '').strip().lower()
    firstname = normalize_person_name(request.form.get('firstname', '').strip())
    lastname = normalize_person_name(request.form.get('lastname', '').strip())
    password = request.form.get('password', '').strip()
    
    if username and firstname:
        try:
            if not is_valid_email(username):
                flash('Teacher username must be a valid email address.', 'error')
                return redirect(url_for('school_admin_dashboard'))
            if not password:
                flash('Teacher password is required.', 'error')
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
            save_teacher(school_id, username, firstname, lastname, [])
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
            promote_students(school_id, from_class, to_class, action_by_student, term=current_term)
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
    return render_template(
        'school/promote_students.html',
        classes=sorted(classes),
        students=class_students,
        selected_class=selected_class_display,
        current_term=current_term
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
            rows.append({'firstname': name, 'reg_no': reg_no})
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
                    'firstname': firstname
                })
            except Exception as e:
                flash(f'Error adding student {firstname}: {str(e)}', 'error')
        
        if added_students:
            flash(f'Successfully added {len(added_students)} students to {classname}!', 'success')
            selected_class = classname

    # Always build listing from fresh DB state so ordering and new additions are correct.
    all_students = load_students(school_id)
    class_options = sorted(set(s.get('classname') for s in all_students.values() if s.get('classname')))
    class_students = [
        {'student_id': sid, 'firstname': data.get('firstname', ''), 'term': data.get('term', ''), 'stream': data.get('stream', '')}
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
            academic_year = school.get('academic_year', '2024-2025') if school else '2024-2025'
            assign_teacher_to_class(school_id, teacher_id, classname, term, academic_year)
            flash(f'Teacher assigned to {classname} successfully!', 'success')
        except Exception as e:
            flash(f'Error assigning teacher: {str(e)}', 'error')
    else:
        flash('Please select a teacher and class.', 'error')
    
    return redirect(url_for('school_admin_dashboard'))

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
    teacher_profile = get_teachers(school_id).get(teacher_id, {})
    teacher_name = f"{teacher_profile.get('firstname', '')} {teacher_profile.get('lastname', '')}".strip() or teacher_id
    has_teacher_signature = bool(teacher_profile.get('signature_image'))
    last_login_at = format_timestamp(get_last_login_at(session.get('user_id')))
    
    classes = get_teacher_classes(school_id, teacher_id, term=current_term, academic_year=current_year)
    students = load_students_for_classes(school_id, classes, term_filter=current_term)
    recent_students = sorted(
        students.items(),
        key=lambda item: (
            (item[1].get('classname', '') or '').strip().lower(),
            (item[1].get('firstname', '') or '').strip().lower(),
            (item[0] or '').strip().lower(),
        )
    )
    current_term = get_current_term(school)
    pending_stream_students = {
        sid for sid, s in students.items()
        if class_uses_stream_for_school(school, s.get('classname', '')) and (s.get('stream') in ('', 'N/A', None))
    }
    score_complete_students = {
        sid for sid, s in students.items() if is_student_score_complete(s, school, current_term)
    }
    class_publish_status = {}
    class_view_status = get_class_published_view_counts(school_id, current_term, current_year, classes)
    viewed_student_ids = get_viewed_student_ids_for_classes(school_id, classes, current_term, current_year)
    for classname in classes:
        class_students = [s for s in students.values() if s.get('classname') == classname and s.get('term') == current_term]
        total = len(class_students)
        completed = sum(1 for s in class_students if is_student_score_complete(s, school, current_term))
        class_views = class_view_status.get(classname, {})
        class_publish_status[classname] = {
            'total': total,
            'completed': completed,
            'ready': total > 0 and completed == total,
            'published': is_result_published(school_id, classname, current_term, current_year),
            'published_students': int(class_views.get('published_count', 0)),
            'viewed_students': int(class_views.get('viewed_count', 0)),
        }
    
    return render_template('teacher/teacher_dashboard.html', 
                         classes=classes, 
                         students=students,
                         recent_students=recent_students,
                         school=school,
                         teacher_name=teacher_name,
                         teacher_id=teacher_id,
                         pending_stream_students=pending_stream_students,
                         current_term=current_term,
                         current_year=current_year,
                         last_login_at=last_login_at,
                         has_teacher_signature=has_teacher_signature,
                         score_complete_students=score_complete_students,
                         class_publish_status=class_publish_status,
                         viewed_student_ids=viewed_student_ids)

@app.route('/teacher/upload-signature', methods=['POST'])
def teacher_upload_signature():
    if session.get('role') != 'teacher':
        return redirect(url_for('login'))
    school_id = session.get('school_id')
    teacher_id = session.get('user_id')
    signature_data, err = parse_uploaded_signature(request.files.get('teacher_signature'))
    if err:
        flash(err, 'error')
        return redirect(url_for('teacher_dashboard'))
    set_teacher_signature(school_id, teacher_id, signature_data)
    flash('Teacher signature saved successfully.', 'success')
    return redirect(url_for('teacher_dashboard'))

@app.route('/teacher/publish-results', methods=['POST'])
def teacher_publish_results():
    if session.get('role') != 'teacher':
        return redirect(url_for('login'))

    school_id = session.get('school_id')
    teacher_id = session.get('user_id')
    classname = request.form.get('classname', '').strip()
    if not classname:
        flash('Select a class to publish.', 'error')
        return redirect(url_for('teacher_dashboard'))

    school = get_school(school_id)
    teacher_profile = get_teachers(school_id).get(teacher_id, {})
    if not (teacher_profile.get('signature_image') or '').strip():
        flash('Upload your teacher signature before publishing results.', 'error')
        return redirect(url_for('teacher_dashboard'))
    if not ((school or {}).get('principal_signature_image') or '').strip():
        flash('Principal signature is required before publishing. Ask school admin to upload it with admin password.', 'error')
        return redirect(url_for('teacher_dashboard'))
    current_term = get_current_term(school)
    current_year = (school or {}).get('academic_year', '')
    if not teacher_has_class_access(school_id, teacher_id, classname, term=current_term, academic_year=current_year):
        flash('You are not assigned to this class for the current term/year.', 'error')
        return redirect(url_for('teacher_dashboard'))
    if is_result_published(school_id, classname, current_term, current_year):
        flash(f'{classname} ({current_term}) is already published. Republish is not allowed.', 'error')
        return redirect(url_for('teacher_dashboard'))
    class_students = load_students(school_id, class_filter=classname, term_filter=current_term)
    student_list = list(class_students.values())
    if not student_list:
        flash(f'No students found in {classname}.', 'error')
        return redirect(url_for('teacher_dashboard'))

    incomplete = [s.get('firstname', '') for s in student_list if not is_student_score_complete(s, school, current_term)]
    if incomplete:
        flash(f'Cannot publish yet. Complete scores for all students in {classname} ({current_term}) first.', 'error')
        return redirect(url_for('teacher_dashboard'))

    publish_results_for_class_atomic(school_id, classname, current_term, teacher_id)
    flash(f'Results ranked/published for {classname} ({current_term}). Students can now view results.', 'success')
    return redirect(url_for('teacher_dashboard'))

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
    if not teacher_has_class_access(school_id, teacher_id, student.get('classname', ''), term=current_term, academic_year=current_year):
        flash('You are not assigned to this student class.', 'error')
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
        flash(f'Stream allocated for {student.get("firstname", "")}.', 'success')
        return redirect(url_for('teacher_dashboard'))

    return render_template('teacher/teacher_allocate_stream.html', student=student, config=config)

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
    
    if not student_id:
        flash('No student selected.', 'error')
        return redirect(url_for('teacher_dashboard'))
    
    student = load_student(school_id, student_id)
    if not student:
        flash('Student not found.', 'error')
        return redirect(url_for('teacher_dashboard'))
    if not teacher_has_class_access(school_id, teacher_id, student.get('classname', ''), term=current_term, academic_year=current_year):
        flash('You are not assigned to this student class.', 'error')
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
    subjects = sorted(student.get('subjects', []), key=lambda x: str(x).lower())
    subject_key_map = build_subject_key_map(subjects)
    
    if request.method == 'POST':
        if is_locked:
            flash(f'Scores for {student.get("classname", "")} ({current_term}) are already published and locked.', 'error')
            return redirect(url_for('teacher_dashboard'))
        scores = {}
        teacher_comment = request.form.get('teacher_comment', '').strip()
        max_tests = max(1, min(safe_int(school.get('max_tests', 3), 3), 10))
        test_total_max = max(0.0, safe_float(school.get('test_score_max', 30), 30))
        for subject in subjects:
            subj_key = subject_key_map.get(subject, '')
            subject_scores = {}
            
            # Test scores (based on school settings)
            if school.get('test_enabled', 1):
                for i in range(1, max_tests + 1):
                    raw_val = request.form.get(f'test_{i}_{subj_key}', 0)
                    try:
                        test_val = float(raw_val)
                    except (TypeError, ValueError):
                        flash(f'Invalid Test {i} score for {subject}.', 'error')
                        return redirect(url_for('teacher_enter_scores', student_id=student_id))
                    if not math.isfinite(test_val):
                        flash(f'Invalid Test {i} score for {subject}.', 'error')
                        return redirect(url_for('teacher_enter_scores', student_id=student_id))
                    if test_val < 0 or test_val > test_total_max:
                        flash(f'Test {i} score for {subject} must be between 0 and {test_total_max:g}.', 'error')
                        return redirect(url_for('teacher_enter_scores', student_id=student_id))
                    subject_scores[f'test_{i}'] = test_val
                subject_scores['total_test'] = sum(subject_scores.get(f'test_{i}', 0) for i in range(1, max_tests + 1))
                if subject_scores['total_test'] > test_total_max:
                    flash(f'Total test score for {subject} must not exceed {test_total_max:g}.', 'error')
                    return redirect(url_for('teacher_enter_scores', student_id=student_id))
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
                        return redirect(url_for('teacher_enter_scores', student_id=student_id))
                    if not math.isfinite(exam_score):
                        flash(f'Invalid exam score for {subject}.', 'error')
                        return redirect(url_for('teacher_enter_scores', student_id=student_id))
                    exam_max = max(0.0, safe_float(exam_config.get('exam_score_max', 70), 70))
                    if exam_score < 0 or exam_score > exam_max:
                        flash(f'Exam score for {subject} must be between 0 and {exam_max:g}.', 'error')
                        return redirect(url_for('teacher_enter_scores', student_id=student_id))
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
                        return redirect(url_for('teacher_enter_scores', student_id=student_id))
                    if not math.isfinite(objective) or not math.isfinite(theory):
                        flash(f'Invalid objective/theory score for {subject}.', 'error')
                        return redirect(url_for('teacher_enter_scores', student_id=student_id))
                    objective_max = max(0.0, safe_float(exam_config.get('objective_max', 30), 30))
                    theory_max = max(0.0, safe_float(exam_config.get('theory_max', 40), 40))
                    exam_total_max = max(0.0, safe_float(exam_config.get('exam_score_max', objective_max + theory_max), objective_max + theory_max))
                    if objective < 0 or objective > objective_max:
                        flash(f'Objective score for {subject} must be between 0 and {objective_max:g}.', 'error')
                        return redirect(url_for('teacher_enter_scores', student_id=student_id))
                    if theory < 0 or theory > theory_max:
                        flash(f'Theory score for {subject} must be between 0 and {theory_max:g}.', 'error')
                        return redirect(url_for('teacher_enter_scores', student_id=student_id))
                    subject_scores['objective'] = objective
                    subject_scores['theory'] = theory
                    subject_scores['total_exam'] = subject_scores.get('objective', 0) + subject_scores.get('theory', 0)
                    if subject_scores['total_exam'] > exam_total_max:
                        flash(f'Total exam score for {subject} must not exceed {exam_total_max:g}.', 'error')
                        return redirect(url_for('teacher_enter_scores', student_id=student_id))
                    subject_scores['exam_mode'] = 'separate'
            else:
                subject_scores['total_exam'] = 0
            
            # Calculate overall
            subject_scores['overall_mark'] = subject_overall_mark(subject_scores)
            subject_scores['total_score'] = subject_scores['overall_mark']
            
            # Grade
            overall = subject_scores['overall_mark']
            subject_scores['grade'] = grade_from_score(overall, grade_cfg)
            
            scores[subject] = subject_scores
        
        student['scores'] = scores
        student['teacher_comment'] = teacher_comment
        student['term'] = current_term
        save_student(school_id, student_id, student)
        # Any edit requires re-publish for this class/term.
        set_result_published(school_id, student.get('classname', ''), current_term, current_year, teacher_id, False)
        flash('Scores saved successfully!', 'success')
        return redirect(url_for('teacher_dashboard'))
    
    return render_template('teacher/teacher_enter_scores.html', 
                         student=student, 
                         subjects=subjects,
                         school=school,
                         current_term=current_term,
                         is_locked=is_locked,
                         subject_key_map=subject_key_map,
                         exam_config=exam_config,
                         grade_cfg=grade_cfg)

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
        teacher_profile = get_teachers(school_id).get(teacher_id, {})
        if not (teacher_profile.get('signature_image') or '').strip():
            flash('Upload your teacher signature before uploading result CSV.', 'error')
            return redirect(url_for('teacher_dashboard'))
        if not (school.get('principal_signature_image') or '').strip():
            flash('Principal signature is required before uploading result CSV.', 'error')
            return redirect(url_for('teacher_dashboard'))
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
                classname = (student.get('classname') or '').strip()
                if classname.lower() not in allowed_classes_normalized:
                    raise ValueError(f'Row {idx}: class "{classname}" for {student_id} is not assigned to you.')
                if is_result_published(school_id, classname, current_term, current_year):
                    raise ValueError(f'Row {idx}: {classname} ({current_term}) is already published and locked.')

                subject_map = {str(s).strip().lower(): s for s in (student.get('subjects') or [])}
                if subject.lower() not in subject_map:
                    raise ValueError(f'Row {idx}: subject "{subject}" is not in {student_id} subject list.')
                subject_key = subject_map[subject.lower()]

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
                updated_students.add(student_id)
                touched_classes.add(classname)

            if processed_rows == 0:
                raise ValueError('No valid data rows found. Fill at least Student ID and Subject in one row.')

            with db_connection(commit=True) as conn:
                c = conn.cursor()
                principal_name = (school.get('principal_name', '') or '').strip()
                teacher_name = f"{teacher_profile.get('firstname', '')} {teacher_profile.get('lastname', '')}".strip() or str(teacher_id)
                for sid, student_data in staged_students.items():
                    save_student_with_cursor(c, school_id, sid, student_data)
                for classname in touched_classes:
                    db_execute(
                        c,
                        '''INSERT INTO result_publications
                           (school_id, classname, term, academic_year, teacher_id, teacher_name, principal_name, is_published, published_at, updated_at)
                           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                           ON CONFLICT(school_id, classname, term, academic_year) DO UPDATE SET
                             teacher_id = excluded.teacher_id,
                             teacher_name = excluded.teacher_name,
                             principal_name = excluded.principal_name,
                             is_published = excluded.is_published,
                             published_at = excluded.published_at,
                             updated_at = CURRENT_TIMESTAMP''',
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
                error_token = _store_csv_error_export(output.getvalue(), fname)
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
    allowed_classes = sorted(set(get_teacher_classes(school_id, teacher_id, term=current_term, academic_year=current_year)))
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
        if int((school or {}).get('operations_enabled', 1) or 1):
            dashboard_notice = 'No published result available yet.'
        else:
            dashboard_notice = 'Current term results are hidden while operations are OFF. Only previous published results are available.'

    return render_template('student/student_dashboard.html', student=my_data, dashboard_notice=dashboard_notice)

@app.route('/student/view-result')
def student_view_result():
    if session.get('role') != 'student':
        return redirect(url_for('login'))
    
    school_id = session.get('school_id')
    school = get_school(school_id) or {}
    current_term = get_current_term(school)
    current_year = (school or {}).get('academic_year', '')
    student_id = session.get('user_id')
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
        if int((school or {}).get('operations_enabled', 1) or 1):
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
    class_results = load_published_class_results(school_id, snapshot.get('classname', ''), target_term, target_year)
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
        'class_name': snapshot.get('classname', ''),
        'term': target_term,
        'academic_year': target_year,
        'number_of_subject': snapshot.get('number_of_subject', 0),
        'subjects': snapshot.get('scores', {}),
        'teacher_comment': snapshot.get('teacher_comment', ''),
        'average_marks': snapshot.get('average_marks', 0),
        'Grade': snapshot.get('Grade', 'F'),
        'Status': snapshot.get('Status', 'Fail'),
    }
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
                         now=datetime.now())

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
    class_results = load_published_class_results(school_id, snapshot.get('classname', ''), target_term, target_year)
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
        'class_name': snapshot.get('classname', student.get('classname', '')),
        'term': target_term,
        'academic_year': target_year,
        'number_of_subject': snapshot.get('number_of_subject', student.get('number_of_subject', 0)),
        'subjects': snapshot.get('scores', {}),
        'teacher_comment': snapshot.get('teacher_comment', ''),
        'average_marks': snapshot.get('average_marks', 0),
        'Grade': snapshot.get('Grade', 'F'),
        'Status': snapshot.get('Status', 'Fail'),
    }
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
        now=datetime.now()
    )

# ==================== PUBLIC STUDENT PORTAL ====================

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
        flash('Invalid Student ID or password.', 'error')
        return redirect(url_for('student_portal'))
    school_id = (user.get('school_id') or '').strip()
    if not school_id:
        school_id = find_student_school_id(student_id) or ''
    if not school_id:
        register_failed_login('check_result', student_id, client_ip)
        flash('Invalid Student ID or password.', 'error')
        return redirect(url_for('student_portal'))

    with db_connection() as conn:
        c = conn.cursor()
        db_execute(
            c,
            '''SELECT s.school_id, s.student_id, s.firstname, s.classname, s.term, s.stream,
                      s.number_of_subject, s.subjects, s.scores, sc.current_term
               FROM students s
               JOIN schools sc ON sc.school_id = s.school_id
               WHERE s.school_id = ? AND s.student_id = ?
               LIMIT 1''',
            (school_id, student_id),
        )
        row = c.fetchone()
    if not row:
        register_failed_login('check_result', student_id, client_ip)
        flash('Invalid Student ID or password.', 'error')
        return redirect(url_for('student_portal'))

    school_id, sid, firstname, classname, term, stream, number_of_subject, subjects_str, scores_str, current_term = row
    if user.get('school_id') != school_id:
        update_user_school_id_only(user.get('username'), school_id)
    clear_failed_login('check_result', student_id, client_ip)
    school = get_school(school_id) or {}
    published_terms = filter_visible_terms_for_student(school, get_published_terms_for_student(school_id, sid))
    if not published_terms:
        if int((school or {}).get('operations_enabled', 1) or 1):
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
    class_results = load_published_class_results(school_id, snapshot.get('classname', ''), target_term, target_year)
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
        'term': target_term,
        'academic_year': target_year,
        'stream': snapshot.get('stream', stream),
        'number_of_subject': snapshot.get('number_of_subject', number_of_subject),
        'subjects': snapshot.get('scores', {}),
        'teacher_comment': snapshot.get('teacher_comment', ''),
        'average_marks': snapshot.get('average_marks', 0),
        'Grade': snapshot.get('Grade', 'F'),
        'Status': snapshot.get('Status', 'Fail')
    }
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
    
    return render_template('shared/menu.html')

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

    students_data = load_students(school_id)
    if session.get('role') == 'teacher':
        teacher_id = session.get('user_id')
        current_year = (school or {}).get('academic_year', '')
        class_set = set(get_teacher_classes(school_id, teacher_id, term=selected_term, academic_year=current_year))
        students_data = load_students_for_classes(school_id, class_set, term_filter=selected_term)

    available_classes = sorted({(s.get('classname', '') or '').strip() for s in students_data.values() if (s.get('classname', '') or '').strip()})
    term_order = {'First Term': 1, 'Second Term': 2, 'Third Term': 3}
    available_terms = sorted(
        {(s.get('term', '') or '').strip() for s in students_data.values() if (s.get('term', '') or '').strip()},
        key=lambda t: (term_order.get(t, 99), t)
    )

    if selected_class:
        students_data = {sid: s for sid, s in students_data.items() if (s.get('classname', '') or '').strip() == selected_class}
    if selected_term:
        students_data = {sid: s for sid, s in students_data.items() if (s.get('term', '') or '').strip() == selected_term}

    students = []
    for student_id, student_data in students_data.items():
        scores = student_data.get('scores', {}) if isinstance(student_data.get('scores', {}), dict) else {}
        overall_marks = [subject_overall_mark(s) for s in scores.values() if isinstance(s, dict)]
        average_marks = (sum(overall_marks) / len(overall_marks)) if overall_marks else 0
        grade = grade_from_score(average_marks, grade_cfg)
        status = status_from_score(average_marks, grade_cfg)

        students.append({
            'first_name': student_data.get('firstname', ''),
            'student_id': student_id,
            'class_name': student_data.get('classname', ''),
            'term': student_data.get('term', ''),
            'stream': student_data.get('stream', ''),
            'subjects': scores,
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

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    debug = os.environ.get('FLASK_DEBUG', '0').strip().lower() in ('1', 'true', 'yes')
    app.run(host='0.0.0.0', port=port, debug=debug)

