"""
Run one-off database migrations/bootstrap without starting the web server.

Usage:
  python migrate.py
"""

import os


def main():
    # Keep app startup hooks disabled; run migration explicitly below.
    os.environ['RUN_STARTUP_DDL'] = '0'
    os.environ['RUN_STARTUP_BOOTSTRAP'] = '0'
    # Do not hard-fail migration on legacy FK guard mismatches.
    # We log warnings and keep migration moving; runtime remains fast/safe.
    os.environ.setdefault('DB_GUARDS_STRICT', '0')
    # Runtime requests should not run DDL.
    os.environ.setdefault('ALLOW_RUNTIME_SCHEMA_HEAL', '0')
    # Safety: never run bulk student password reset from this command.
    os.environ.setdefault('RESET_STUDENT_PASSWORDS_ON_STARTUP', '0')

    import student_scor
    student_scor.init_db()
    student_scor.verify_required_db_guards()

    print('Migration completed.')


if __name__ == '__main__':
    main()
