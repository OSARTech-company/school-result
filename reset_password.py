import sqlite3
from werkzeug.security import generate_password_hash

# Reset the super admin password
conn = sqlite3.connect('student_score.db')
c = conn.cursor()
password_hash = generate_password_hash('osartech2026')
c.execute("UPDATE users SET password_hash = ? WHERE username = 'osondu stanley'", (password_hash,))
conn.commit()
conn.close()
print('Password reset successfully!')
