"""Alembic environment script for raw SQL migrations."""

from logging.config import fileConfig
from alembic import context
import os

config = context.config

# read the .ini file
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# add your model's MetaData object here for 'autogenerate' support
target_metadata = None

def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode (no engine needed, just SQL script output)."""
    url = os.environ.get('DATABASE_URL')
    if not url:
        raise RuntimeError('DATABASE_URL environment variable not set')
    
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run migrations in 'online' mode (with engine)."""
    import psycopg2
    
    url = os.environ.get('DATABASE_URL')
    if not url:
        raise RuntimeError('DATABASE_URL environment variable not set')
    
    # use psycopg2 directly for raw SQL migration execution
    conn = psycopg2.connect(url)
    
    try:
        context.configure(
            connection=conn,
            target_metadata=target_metadata,
        )

        with context.begin_transaction():
            context.run_migrations()
    finally:
        conn.close()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
