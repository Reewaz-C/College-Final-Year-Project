import tkinter as tk
from tkinter import messagebox
from PIL import Image, ImageTk
import os
import sys
import signup
# Add the parent directory to the Python path
DB_path = os.path.abspath(r"D:\\class\\year 3\\FYP\\Development")
sys.path.insert(0, DB_path)
from Database.user_manager import UserManager

def clear_entry_on_click(entry, default_text):
    entry.delete(0, 'end')

def restore_default_text(entry, default_text):
    if entry.get() == "":
        entry.insert(0, default_text)

class LoginWindow(tk.Frame):
    def __init__(self, parent):
        super().__init__(parent, bg="#fff")
        self.user_manager = UserManager()
        self.parent = parent
        self.parent.title('Login')
        self.parent.geometry('925x500+300+200')
        self.parent.resizable(False, False)
        
        try:
            img = Image.open("D:\\class\\year 3\\FYP\\Development\\loginimg.png")
            photo = ImageTk.PhotoImage(img)
            label = tk.Label(self, image=photo, bg='white')
            label.image = photo 
            label.place(x=50, y=50)
        except Exception as e:
            messagebox.showerror("Image Error", "Failed to load image: {}".format(e))
            # You can choose to continue without the image or exit the application here

        frame = tk.Frame(self, width=350, height=350, bg="white")
        frame.place(x=480, y=70)

        heading = tk.Label(frame, text='Sign in', fg='#57a1f8', bg='white', font=('Microsoft YaHei UI Light', 23, 'bold'))
        heading.place(x=100, y=5)

        self.error_label = tk.Label(frame, text="", fg="red", bg='white', font=('Microsoft YaHei UI Light', 9))
        self.error_label.place(x=30, y=240)

        self.user = tk.Entry(frame, width=25, fg='black', border=0, bg="white", font=('Microsoft YaHei UI Light', 11))
        self.user.place(x=30, y=80)
        self.user.insert(0, 'Username')
        self.user.bind('<FocusIn>', lambda e: clear_entry_on_click(self.user, 'Username'))
        self.user.bind('<FocusOut>', lambda e: restore_default_text(self.user, 'Username'))

        tk.Frame(frame, width=295, height=2, bg='black').place(x=25, y=107)

        self.code = tk.Entry(frame, width=25, fg='black', border=0, bg="white", font=('Microsoft YaHei UI Light', 11), show="*")
        self.code.place(x=30, y=150)
        self.code.insert(0, 'Password')
        self.code.bind('<FocusIn>', lambda e: clear_entry_on_click(self.code, 'Password'))
        self.code.bind('<FocusOut>', lambda e: restore_default_text(self.code, 'Password'))

        tk.Frame(frame, width=295, height=2, bg='black').place(x=25, y=177)

        tk.Button(frame, width=39, pady=7, text='Sign in', bg='#57a1f8', fg='white', border=0, command=self.on_sign_in).place(x=35, y=204)

        label = tk.Label(frame, text="Don't have an account?", fg='black', bg='white', font=('Microsoft YaHei UI Light', 9))
        label.place(x=75, y=270)

        sign_up = tk.Button(frame, width=6, text="Sign up", border=0, bg="white", cursor='hand2', fg="#57a1f8", command=self.open_signup_window)
        sign_up.place(x=215, y=270)

        self.pack()

    def on_sign_in(self):
        username = self.user.get()
        password = self.code.get()

        if username == "" or password == "":
            self.show_error_message("Both username and password are required.")
            return

        user = self.user_manager.authenticate_user(username, password)
        if user:
            messagebox.showinfo("Login Successful", "Welcome, {}".format(username))
            self.open_main_window()
        else:
            self.show_error_message("Invalid username or password.")
            
    def show_error_message(self, message, duration=3000):
        self.error_label.config(text=message, fg="red")
        self.after(duration, self.hide_error_message)

    def hide_error_message(self):
        self.error_label.config(text="")

    def open_main_window(self):
        self.parent.destroy()

    def open_signup_window(self):
        self.parent.destroy()
        signup.open_signup_window()

def open_login_window():
    root = tk.Tk()
    app = LoginWindow(root)
    root.mainloop()

if __name__ == "__main__":
    open_login_window()

