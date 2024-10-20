import hashlib
import secrets

class User:
    def __init__(self, username, password, role=None, permissions=None):
        self.username = username
        self.password_hash = self.hash_password(password)
        self.role = role
        self.permissions = permissions

    def hash_password(self, password):
        return hashlib.sha256(password.encode()).hexdigest()

    def check_password(self, password):
        return hashlib.sha256(password.encode()).hexdigest() == self.password_hash

class UserManager:
    def __init__(self):
        self.users = []

    def add_user(self, username, password, role=None):
        if self.get_user(username):
            raise ValueError(f"Username '{username}' already exists.")

        new_user = User(username, password, role)
        self.users.append(new_user)
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

class App:
    def __init__(self):
        self.user_manager = UserManager()

    def sign_up(self, username, password, role=None, permissions=None):
        try:
            new_user = self.user_manager.add_user(username, password, role, permissions)
            print(f"User '{new_user.username}' signed up successfully.")
        except ValueError as e:
            print(str(e))

    def log_in(self, username, password):
        user = self.user_manager.authenticate_user(username, password)
        if user:
            print("Login successful.")
        else:
            print("Invalid username or password.")

if __name__ == "__main__":
    app = App()
    

