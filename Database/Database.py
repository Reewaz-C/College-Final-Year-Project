import sqlite3

absolute_path = 'D:\\class\\year 3\\FYP\\Development\\vulnerability_scanner.db'

def create_database():
    try:
        conn = sqlite3.connect(absolute_path)
        cursor = conn.cursor()

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_name TEXT NOT NULL,
                date_time TEXT NOT NULL,
                vulnerability_detected TEXT
            )
        ''')

        conn.commit()
    except sqlite3.Error as e:
        print("Error creating database:", e)
    finally:
        if conn:
            conn.close()
