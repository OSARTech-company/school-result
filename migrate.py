"""
Run one-off database migrations/bootstrap without starting the web server.

Usage:
  python migrate.py

This script uses Alembic directly to apply schema migrations.
"""

import os
import sys


def main():
    # Keep app startup hooks disabled
    os.environ['RUN_STARTUP_DDL'] = '0'
    os.environ['RUN_STARTUP_BOOTSTRAP'] = '0'
    os.environ.setdefault('DB_GUARDS_STRICT', '0')
    os.environ.setdefault('ALLOW_RUNTIME_SCHEMA_HEAL', '0')
    os.environ.setdefault('RESET_STUDENT_PASSWORDS_ON_STARTUP', '0')

    # Use Alembic directly (doesn't require Flask app context)
    from alembic.config import Config
    from alembic import command

    try:
        print("Applying database migrations...")
        
        # Get the migrations directory
        migrations_dir = os.path.join(os.path.dirname(__file__), 'migrations')
        
        # Create Alembic config
        alembic_cfg = Config(os.path.join(migrations_dir, 'alembic.ini'))
        alembic_cfg.set_main_option('script_location', migrations_dir)
        alembic_cfg.set_main_option(
            'sqlalchemy.url',
            os.environ.get('DATABASE_URL', '')
        )
        
        # Apply all pending migrations
        command.upgrade(alembic_cfg, 'head')
        print("✓ Migrations completed successfully.")
        
    except Exception as e:
        print(f"✗ Migration failed: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()
