import sqlite3
import hashlib

absolute_path = 'D:\\class\\year 3\\FYP\\Development\\vulnerability_scanner.db'

class User:
    def __init__(self, username, password_hash, role=None, permissions=None):
        self.username = username
        self.password_hash = password_hash
        self.role = role
        self.permissions = permissions if permissions else []  # Default to an empty list

    def has_permission(self, permission):
        return permission in self.permissions

    def check_password(self, password):
        provided_password_hash = self.hash_password(password)
        return provided_password_hash == self.password_hash

    @staticmethod
    def hash_password(password):
        return hashlib.sha256(password.encode()).hexdigest()

class UserManager:
    def __init__(self):
        self.users = []
        self.load_users()

    def load_users(self):
        try:
            conn = sqlite3.connect(absolute_path)
            cursor = conn.cursor()

            cursor.execute('''
                SELECT * FROM users
            ''')

            for user_info in cursor.fetchall():
                if len(user_info) >= 4:
                    user = User(user_info[1], user_info[2], user_info[3])
                    self.users.append(user)
                else:
                    print("Incomplete user information retrieved from the database.")

        except sqlite3.Error as e:
            print("Error loading users:", e)
        finally:
            if conn:
                conn.close()

    def add_user(self, username, password, role=None):
        password_hash = User.hash_password(password)
        if self.get_user(username):
            raise ValueError(f"Username '{username}' already exists.")

        new_user = User(username, password_hash, role)
        self.users.append(new_user)
        self.save_user(new_user)
        return new_user

    def get_user(self, username):
        for user in self.users:
            if user.username == username:
                return user
        return None

    def authenticate_user(self, username, password):
        user = self.get_user(username)
        if user and user.check_password(password):
            return user
        return None

    def save_user(self, user):
        try:
            conn = sqlite3.connect(absolute_path)
            cursor = conn.cursor()

            cursor.execute("""
                INSERT INTO users (username, password_hash, role)
                VALUES (?, ?, ?)
            """, (user.username, user.password_hash, user.role))

            conn.commit()
        except sqlite3.Error as e:
            print("Error saving user:", e)
        finally:
            if conn:
                conn.close()
