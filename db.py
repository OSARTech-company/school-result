from dotenv import load_dotenv
import os
import psycopg2

load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL")

if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL not found. Set it in .env")

conn = psycopg2.connect(DATABASE_URL)
cursor = conn.cursor()

def db_execute(query):
    """
    Executes a SQL query safely.
    Rolls back if there is an error.
    """
    try:
        cursor.execute(query)
        conn.commit()
    except Exception as e:
        conn.rollback()
        print("SQL ERROR:", e)
        raise
def init_db():
    """
    Creates all required tables in PostgreSQL if they don't exist.
    """

    db_execute('''
    CREATE TABLE IF NOT EXISTS students (
        id SERIAL PRIMARY KEY,
        school_id TEXT NOT NULL,
        student_id TEXT NOT NULL,
        firstname TEXT,
        classname TEXT,
        first_year_class TEXT,
        term TEXT,
        stream TEXT,
        number_of_subject INTEGER,
        subjects TEXT,
        scores TEXT,
        UNIQUE(school_id, student_id)
        )
        ''')
    db_execute('''
    CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        username TEXT UNIQUE NOT NULL,
        role TEXT NOT NULL,
        password TEXT NOT NULL
    )
    ''')

    print("✅ Database initialized successfully.")

if __name__ == "__main__":
    # Step 1: initialize tables
    init_db()

# Test query
cursor.execute("SELECT username, role FROM users;")
for row in cursor.fetchall():
    print(row)

cursor.close()
conn.close()
