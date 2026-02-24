from dotenv import load_dotenv
import os
import psycopg2

load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL")

if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL not found. Set it in .env")

conn = psycopg2.connect(DATABASE_URL)
cursor = conn.cursor()

# Test query
cursor.execute("SELECT username, role FROM users;")
for row in cursor.fetchall():
    print(row)

cursor.close()
conn.close()
