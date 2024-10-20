import sqlite3
import hashlib

absolute_path = 'D:\\class\\year 3\\FYP\\Development\\vulnerability_scanner.db'

def login(username, password):
    try:
        conn = sqlite3.connect(absolute_path)
        cursor = conn.cursor()

        password_hash = hash_password(password)

        cursor.execute('''
            SELECT * FROM users WHERE username = ? AND password_hash = ?
        ''', (username, password_hash))

        user = cursor.fetchone()
        return user is not None
    except sqlite3.Error as e:
        print("Error logging in user:", e)
        return False
    finally:
        if conn:
            conn.close()

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()
