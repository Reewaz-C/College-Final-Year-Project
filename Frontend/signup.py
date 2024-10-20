import tkinter as tk
from tkinter import messagebox
from PIL import Image, ImageTk
import logintk
import os
import sys
# Add the parent directory to the Python path
DB_path = os.path.abspath(r"D:\\class\\year 3\\FYP\\Development")
sys.path.insert(0, DB_path)
from Database.user_manager import UserManager

def clear_entry_on_click(entry, default_text):
    entry.delete(0, 'end')

def restore_default_text(entry, default_text):
    if entry.get() == "":
        entry.insert(0, default_text)

class SignupWindow(tk.Toplevel):
    def __init__(self, parent):
        super().__init__(parent)
        self.title('Sign Up')
        self.geometry('925x500+300+200')
        self.resizable(False, False)
        
        try:
            img = Image.open("D:\\class\\year 3\\FYP\\Development\\loginimg.png")
            photo = ImageTk.PhotoImage(img)
            label = tk.Label(self, image=photo, bg='white')
            label.image = photo
            label.place(x=50, y=50)
        except Exception as e:
            print(f"Error loading image: {e}")

        frame = tk.Frame(self, width=350, height=350, bg="white")
        frame.place(x=480, y=70)

        heading = tk.Label(frame, text='Sign Up', fg='#57a1f8', bg='white', font=('Microsoft YaHei UI Light', 23, 'bold'))
        heading.place(x=100, y=5)

        self.new_user = tk.Entry(frame, width=25, fg='black', border=0, bg="white", font=('Microsoft YaHei UI Light', 11))
        self.new_user.place(x=30, y=75)
        self.new_user.insert(0, 'New Username')
        self.new_user.bind('<FocusIn>', lambda e: clear_entry_on_click(self.new_user, 'New Username'))
        self.new_user.bind('<FocusOut>', lambda e: restore_default_text(self.new_user, 'New Username'))

        tk.Frame(frame, width=295, height=2, bg='black').place(x=25, y=100)

        self.new_code = tk.Entry(frame, width=25, fg='black', border=0, bg="white", font=('Microsoft YaHei UI Light', 11), show="")
        self.new_code.place(x=30, y=135)
        self.new_code.insert(0, 'New Password')
        self.new_code.bind('<FocusIn>', lambda e: clear_entry_on_click(self.new_code, 'New Password'))
        self.new_code.bind('<FocusOut>', lambda e: restore_default_text(self.new_code, 'New Password'))

        tk.Frame(frame, width=295, height=2, bg='black').place(x=25, y=160)

        self.confirm_code = tk.Entry(frame, width=25, fg='black', border=0, bg="white", font=('Microsoft YaHei UI Light', 11), show="")
        self.confirm_code.place(x=30, y=190)
        self.confirm_code.insert(0, 'Confirm Password')
        self.confirm_code.bind('<FocusIn>', lambda e: clear_entry_on_click(self.confirm_code, 'Confirm Password'))
        self.confirm_code.bind('<FocusOut>', lambda e: restore_default_text(self.confirm_code, 'Confirm Password'))

        tk.Frame(frame, width=295, height=2, bg='black').place(x=25, y=217)

        # Role Selection Dropdown
        self.role_var = tk.StringVar(self)
        self.role_var.set("Regular")  # Default role selection
        roles = ["Regular", "Admin"]  # List of roles
        role_dropdown = tk.OptionMenu(frame, self.role_var, *roles)
        role_dropdown.config(width=23, font=('Microsoft YaHei UI Light', 11), bg="white")
        role_dropdown.place(x=30, y=230)

        tk.Button(frame, width=39, pady=7, text='Sign Up', bg='#57a1f8', fg='white', border=0, command=self.on_sign_up).place(x=35, y=270)

        label = tk.Label(frame, text="Already have an account?", fg='black', bg='white', font=('Microsoft YaHei UI Light', 9))
        label.place(x=75, y=320)

        self.error_label = tk.Label(frame, text="", fg="red", bg='white', font=('Microsoft YaHei UI Light', 9))
        self.error_label.place(x=30, y=270)

        sign_in = tk.Button(frame, width=6, text="Sign In", border=0, bg="white", cursor='hand2', fg="#57a1f8", command=self.open_login_window)
        sign_in.place(x=215, y=320)

    def on_sign_up(self):
        username = self.new_user.get()
        password = self.new_code.get()
        confirm_password = self.confirm_code.get()
        role = self.role_var.get()  # Get selected role

        if username == "" or password == "" or confirm_password == "":
            self.show_error_message("All fields are required.")
            return

        if password != confirm_password:
            self.show_error_message("Passwords do not match.")
            return
        
        user_manager = UserManager()
        try:
            # Call the add_user method from UserManager to add a new user
            new_user = user_manager.add_user(username, password, role)
            messagebox.showinfo("Signup Successful", "Account created for {}".format(username))
            # Clear entry fields after successful signup
            self.new_user.delete(0, 'end')
            self.new_code.delete(0, 'end')
            self.confirm_code.delete(0, 'end')
        except ValueError as e:
            self.show_error_message(str(e))  # Display error message if username already exists

    def show_error_message(self, message, duration=3000):
        self.error_label.config(text=message, fg="red")
        self.after(duration, self.hide_error_message)

    def hide_error_message(self):
        self.error_label.config(text="")
        

    def open_login_window(self):
        self.destroy()  # Destroy current window
        logintk.open_login_window()  # Call the open_login_window function from logintk.py

def open_signup_window():
    root = tk.Tk()  # Use Tk() to create a new root window
    app = SignupWindow(root)
    root.mainloop()

if __name__ == "__main__":
    open_signup_window()
