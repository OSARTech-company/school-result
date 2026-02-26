"""
Run one-off database migrations/bootstrap without starting the web server.

Usage:
  python migrate.py

This script uses Flask-Migrate (Alembic) to apply schema migrations.
"""

import os
import sys


def main():
    # Keep app startup hooks disabled; run migration explicitly below.
    os.environ['RUN_STARTUP_DDL'] = '0'
    os.environ['RUN_STARTUP_BOOTSTRAP'] = '0'
    # Do not hard-fail migration on legacy FK guard mismatches.
    os.environ.setdefault('DB_GUARDS_STRICT', '0')
    # Runtime requests should not run DDL.
    os.environ.setdefault('ALLOW_RUNTIME_SCHEMA_HEAL', '0')
    # Safety: never run bulk student password reset from this command.
    os.environ.setdefault('RESET_STUDENT_PASSWORDS_ON_STARTUP', '0')

    import student_scor
    from flask_migrate import upgrade

    # Apply all pending migrations to the database
    try:
        print("Applying database migrations...")
        # Upgrade within app context so Flask-Migrate can find the migrate object
        with student_scor.app.app_context():
            upgrade(directory='migrations')
        print("✓ Migrations completed successfully.")
    except Exception as e:
        print(f"✗ Migration failed: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()
