from dotenv import load_dotenv
import os
import psycopg2

load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL")
if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL not found. Set it in .env")

def db_execute(cursor, query):
    """
    Executes a SQL query safely using the provided cursor.
    Rolls back if there is an error.
    """
    try:
        cursor.execute(query)
    except Exception as e:
        cursor.connection.rollback()
        print("SQL ERROR:", e)
        raise

def init_db():
    """
    Creates all required tables in PostgreSQL if they don't exist.
    """
    with psycopg2.connect(DATABASE_URL) as conn:
        with conn.cursor() as cursor:
            # Students table
            db_execute(cursor, '''
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
            # Users table
            db_execute(cursor, '''
                CREATE TABLE IF NOT EXISTS users (
                    id SERIAL PRIMARY KEY,
                    username TEXT UNIQUE NOT NULL,
                    role TEXT NOT NULL,
                    password TEXT NOT NULL
                )
            ''')
            # Commit changes
            conn.commit()
            print("✅ Database initialized successfully.")

def test_users():
    """Fetch users safely"""
    with psycopg2.connect(DATABASE_URL) as conn:
        with conn.cursor() as cursor:
            cursor.execute("SELECT username, role FROM users;")
            rows = cursor.fetchall()
            for row in rows:
                print(row)

if __name__ == "__main__":
    init_db()
    test_users()