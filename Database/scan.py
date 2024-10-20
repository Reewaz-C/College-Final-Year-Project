import sqlite3

absolute_path = 'D:\\class\\year 3\\FYP\\Development\\vulnerability_scanner.db'

def record_scan(scan_name, date_time, vulnerability_detected):
    try:
        conn = sqlite3.connect(absolute_path)
        cursor = conn.cursor()

        cursor.execute('''
            INSERT INTO scans (scan_name, date_time, vulnerability_detected) VALUES (?, ?, ?)
        ''', (scan_name, date_time, vulnerability_detected))

        conn.commit()
    except sqlite3.Error as e:
        print("Error recording scan:", e)
    finally:
        if conn:
            conn.close()

def clear_scan_records():
    try:
        conn = sqlite3.connect(absolute_path)
        cursor = conn.cursor()

        cursor.execute('''
            DELETE FROM scans
        ''')

        conn.commit()
        print("Scan records cleared successfully.")
    except sqlite3.Error as e:
        print("Error clearing scan records:", e)
    finally:
        if conn:
            conn.close()

def get_scans():
    try:
        conn = sqlite3.connect(absolute_path)
        cursor = conn.cursor()

        cursor.execute('''
            SELECT * FROM scans
        ''')

        return cursor.fetchall()
    except sqlite3.Error as e:
        print("Error retrieving scans:", e)
        return []
    finally:
        if conn:
            conn.close()
