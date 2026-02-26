## Deployment Runtime vs Migration

Use two separate commands:

1. Migration step (run once per deploy when schema changes):
   `python migrate.py`

2. App runtime (fast startup):
   `RUN_STARTUP_DDL=0` and start app normally.

### Recommended env

- `RUN_STARTUP_DDL=0` for app instances
- `RUN_STARTUP_DDL=1` only inside `migrate.py` (already forced there)
- `DB_GUARDS_STRICT=1` during migration job

### Why

`student_scor.py` contains heavy schema/bootstrap SQL. Running that on every app boot slows startup and can create lock contention. Running migrations as a separate step keeps app startup predictable and fast.

