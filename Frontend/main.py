import tkinter as tk
from tkinter import ttk
from PIL import Image, ImageTk
import time
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from logintk import LoginWindow
import subprocess
import os
import threading
import queue
from tkinter import simpledialog
from tkinter import filedialog, messagebox
import shutil
import urllib.request
import sys
import webbrowser
from urllib.parse import urlparse
# Add the parent directory to the Python path
DB_path = os.path.abspath(r"D:\\class\\year 3\\FYP\\Development")
sys.path.insert(0, DB_path)

from Database.scan import get_scans, clear_scan_records
from Backend.dependency_check import upload_project_directory,open_report, run_dependency_check

class DashboardPage(tk.Frame):  
    """Class representing the Dashboard page of the application."""

    def __init__(self, parent):
        super().__init__(parent, bg="#EFF0F1")
        self.parent = parent
        self.pack(fill="both", expand=True) 

        # Heading label for the entire window
        self.heading_label = tk.Label(self, text="ScanSentryX Dashboard", font=("Arial", 22, "bold"), bg="#EFF0F1", fg="#34495E")
        self.heading_label.pack(pady=20, padx=20, anchor="w")

        # Container for heading and menu
        left_frame = tk.Frame(self, width=200, bg="#34495E")  # Dark blue background
        left_frame.pack(side="left", fill="y")

        # Load the logo image
        logo_path =  "C:/Users/PC/Desktop/ScanSentryX/logopng.png"   # Replace with the actual path to your logo
        logo_image = Image.open(logo_path)
        resized_logo = logo_image.resize((150, 75), Image.LANCZOS)  # Resize logo
        logo_photo = ImageTk.PhotoImage(resized_logo)

        # Create a label to display the logo image
        logo_label = tk.Label(left_frame, image=logo_photo, bg="#34495E")  # Dark blue background
        logo_label.pack(pady=20, padx=20, anchor="w")

        # Menu buttons within the left frame
        menu_frame = tk.Frame(left_frame, bg="#34495E")  # Dark blue background
        menu_frame.pack(fill="both", expand=True)

        # Set a uniform width for all buttons
        button_width = 15  # Adjust as needed
        button_bg = "#2C3E50"  # Button background color

        def show_dashboard():
            dashboard_page.pack(fill="both", expand=True)
            scan_page.pack_forget()
            report_page.pack_forget()
            setting_page.pack_forget()

        def show_scan():
            dashboard_page.pack_forget()
            scan_page.pack(fill="both", expand=True)
            report_page.pack_forget()
            setting_page.pack_forget()

        def show_reports():
            dashboard_page.pack_forget()
            scan_page.pack_forget()
            report_page.pack(fill="both", expand=True)
            setting_page.pack_forget()

        def show_settings():
            dashboard_page.pack_forget()
            scan_page.pack_forget()
            report_page.pack_forget()
            setting_page.pack(fill="both", expand=True)

        # Menu buttons
        dashboard_button = tk.Button(menu_frame, text="Dashboard", width=button_width, bg=button_bg, fg="white", font=("Arial", 12, "bold"), command=show_dashboard)
        scan_button = tk.Button(menu_frame, text="Scan", width=button_width, bg=button_bg, fg="white", font=("Arial", 12, "bold"), command=show_scan)
        reports_button = tk.Button(menu_frame, text="Reports", width=button_width, bg=button_bg, fg="white", font=("Arial", 12, "bold"), command=show_reports)
        settings_button = tk.Button(menu_frame, text="Settings", width=button_width, bg=button_bg, fg="white", font=("Arial", 12, "bold"), command=show_settings)
        logout_button = tk.Button(menu_frame, text="Logout", width=button_width, bg=button_bg, fg="white", font=("Arial", 12, "bold"), command=self.logout)

        dashboard_button.pack(pady=10)
        scan_button.pack(pady=10)
        reports_button.pack(pady=10)
        settings_button.pack(pady=10)
        logout_button.pack(pady=10)

        # Create a frame for graphs
        graphs_frame = tk.Frame(self, bg="#EFF0F1")  # Light gray background
        graphs_frame.pack(fill="both", expand=True, padx=20, pady=(20, 10), anchor="w")

        # Create dummy data for vulnerabilities
        vulnerability_types = ["Critical", "High", "Medium", "Low"]
        vulnerability_counts = [5, 12, 23, 37]

        # Create the bar graph using Matplotlib
        fig, ax = plt.subplots()
        ax.bar(vulnerability_types, vulnerability_counts, color="#5DADE2")  # Adjust colors as needed
        ax.set_title("Vulnerabilities Detected", fontsize=14)
        ax.set_xlabel("Vulnerability Type", fontsize=12)
        ax.set_ylabel("Number of Vulnerabilities", fontsize=12)

        # Embed the graph in the Tkinter window
        canvas = FigureCanvasTkAgg(fig, master=graphs_frame)  # Use graphs frame as master
        canvas.draw()
        canvas.get_tk_widget().pack(side="left", padx=(20, 10), fill="both", expand=True)  # Pack the canvas within the graphs frame, fill both directions

        # Create dummy data for top vulnerabilities
        vulnerability_types = ["XSS", "SQLi", "CSRF", "OWASP Top 10"]
        vulnerability_counts = [15, 28, 12, 45]

        # Create the pie chart using Matplotlib
        fig2, ax2 = plt.subplots()
        ax2.pie(vulnerability_counts, labels=vulnerability_types, autopct="%1.1f%%", startangle=90)
        ax2.set_title("Top Vulnerabilities", fontsize=14)

        # Embed the pie chart in the Tkinter window
        canvas2 = FigureCanvasTkAgg(fig2, master=graphs_frame)  # Use graphs frame as master
        canvas2.draw()
        canvas2.get_tk_widget().pack(side="left", padx=(0, 20), fill="both", expand=True)  # Pack the canvas within the graphs frame, fill both directions

        # Create a frame for detected vulnerabilities
        detected_vulnerabilities_frame = tk.Frame(self, bg="#EFF0F1", bd=2, relief="groove")  # Light gray background
        detected_vulnerabilities_frame.pack(fill="x", padx=20, pady=(10, 20), anchor="w")  # Pack to the bottom and left

        # Heading for detected vulnerabilities
        detected_vulnerabilities_label = tk.Label(detected_vulnerabilities_frame, text="Detected Vulnerabilities", font=("Arial", 20, "bold"), bg="#EFF0F1", fg="#34495E")
        detected_vulnerabilities_label.pack(pady=2, anchor="w")

        # Detected vulnerabilities
        vulnerabilities_list = ["SQL Injections", "CSRF", "OWASP Top 10", "XSS","XYZ","ABC"]

        for vulnerability in vulnerabilities_list:
            label = tk.Label(detected_vulnerabilities_frame, text="•  " + vulnerability, font=("Arial", 11), bg="#EFF0F1", fg="#34495E")
            label.pack(pady=2, anchor="w")

        # Bind events for hover effect
        detected_vulnerabilities_frame.bind("<Enter>", self.on_hover)
        detected_vulnerabilities_frame.bind("<Leave>", self.on_leave)

    # Function to change frame background color on hover
    def on_hover(self, event):
        event.widget.config(bg="#F2F3F4")

    def on_leave(self, event):
        event.widget.config(bg="white")

    def logout(self):
        # Close the current window
        self.parent.destroy()

        # Create and open the login window
        login_window = tk.Tk()
        login_window.title("Login")
        login_window.geometry("925x500+300+200")
        login_window.configure(bg="#fff")
        login_window.resizable(False, False)

        # Create an instance of the LoginWindow class and add it to the Tkinter window
        login_page = LoginWindow(login_window)
        login_page.pack(fill="both", expand=True)

        # Run the Tkinter event loop for the login window
        login_window.mainloop()
def main():
    # Create a Tkinter window
    root = tk.Tk()
    root.title("ScanSentryX")
    root.geometry("925x500+300+200")
    root.configure(bg="#fff")
    root.resizable(False, False)

    # Function to switch to the dashboard after successful login
    def on_successful_login():
        # Remove the login page and display the dashboard
        login_page.pack_forget()
        dashboard_page = DashboardPage(root)
        dashboard_page.pack(fill="both", expand=True)

    # Create an instance of the LoginWindow class and add it to the Tkinter window
    login_page = LoginWindow(root)
    login_page.on_successful_login = on_successful_login

    # Run the Tkinter event loop for the login window
    login_page.pack(fill="both", expand=True)
    root.mainloop()

if __name__ == "__main__":
    main()
    
##########################SCAN PAGE###################################
class ScanPage(tk.Frame):
    """Class representing the Scan page of the application.""" 

    def __init__(self, parent):
        super().__init__(parent, bg="#EFF0F1")
        self.parent = parent
        self.pack(fill="both", expand=True) 

        # Load the logo image
        self.logo_photo = self.load_logo_image()

        # Initialize variables
        self.scanner_thread = None
        self.message_queue = queue.Queue()
        self.stop_scan_flag = False  # Flag to signal if the scan should be stopped

        # Create GUI elements
        self.create_gui()

    def load_logo_image(self):
        logo_path =  "C:/Users/PC/Desktop/ScanSentryX/logopng.png"   # Replace with the actual path to your logo
        logo_image = Image.open(logo_path)
        resized_logo = logo_image.resize((150, 75), Image.LANCZOS)  # Resize logo
        return ImageTk.PhotoImage(resized_logo)

    def create_gui(self):
        # Heading label for the entire window
        self.heading_label = tk.Label(self, text="ScanSentryX Scan", font=("Arial", 22, "bold"), bg="#EFF0F1", fg="#34495E")
        self.heading_label.pack(pady=20, padx=20, anchor="w")

        # Container for heading and menu
        left_frame = tk.Frame(self, width=200, bg="#34495E")  # Dark blue background with gradient
        left_frame.pack(side="left", fill="y")

        # Create a label to display the logo image
        logo_label = tk.Label(left_frame, image=self.logo_photo, bg="#34495E")  # Dark blue background
        logo_label.pack(pady=20, padx=20, anchor="w")

        # Menu buttons within the left frame
        menu_frame = tk.Frame(left_frame, bg="#34495E")  # Dark blue background
        menu_frame.pack(fill="both", expand=True)

        # Set a uniform width for all buttons
        button_width = 15  # Adjust as needed
        button_bg = "#2C3E50"  # Button background color

        def show_dashboard():
            dashboard_page.pack(fill="both", expand=True)
            scan_page.pack_forget()
            report_page.pack_forget()
            setting_page.pack_forget()

        def show_scan():
            dashboard_page.pack_forget()
            scan_page.pack(fill="both", expand=True)
            report_page.pack_forget()
            setting_page.pack_forget()

        def show_reports():
            dashboard_page.pack_forget()
            scan_page.pack_forget()
            report_page.pack(fill="both", expand=True)
            setting_page.pack_forget()

        def show_settings():
            dashboard_page.pack_forget()
            scan_page.pack_forget()
            report_page.pack_forget()
            setting_page.pack(fill="both", expand=True)

        # Menu buttons
        dashboard_button = tk.Button(menu_frame, text="Dashboard", width=button_width, bg=button_bg, fg="white", font=("Arial", 12, "bold"), command=show_dashboard)
        scan_button = tk.Button(menu_frame, text="Scan", width=button_width, bg=button_bg, fg="white", font=("Arial", 12, "bold"), command=show_scan)
        reports_button = tk.Button(menu_frame, text="Reports", width=button_width, bg=button_bg, fg="white", font=("Arial", 12, "bold"), command=show_reports)
        settings_button = tk.Button(menu_frame, text="Settings", width=button_width, bg=button_bg, fg="white", font=("Arial", 12, "bold"), command=show_settings)
        logout_button = tk.Button(menu_frame, text="Logout", width=button_width, bg=button_bg, fg="white", font=("Arial", 12, "bold"), command=self.logout)

        dashboard_button.pack(pady=10)
        scan_button.pack(pady=10)
        reports_button.pack(pady=10)
        settings_button.pack(pady=10)
        logout_button.pack(pady=10)
        dashboard_button.pack(pady=5)
        scan_button.pack(pady=5)

        # Heading 3 label and checkboxes for scan configurations
        scan_config_frame = tk.Frame(self, bg="#EFF0F1")  # Light gray background
        scan_config_frame.pack(pady=20, padx=20, anchor="w")

        # Heading 3 label for "Select Scan Configurations"
        heading3_label = tk.Label(scan_config_frame, text="Select Scan Configurations", font=("Arial", 14, "bold"), bg="#EFF0F1")
        heading3_label.pack(side="left", padx=5, pady=10)  

        # Checkboxes for scan configurations
        self.scan_config_vars = []
        scan_config_options = ["ZAP Scan", "OWASP API Security Check", "OWASP Dependency Checks"]
        for option in scan_config_options:
            var = tk.BooleanVar()
            checkbox = tk.Checkbutton(scan_config_frame, text=option, variable=var, onvalue=True, offvalue=False, bg="#EFF0F1")
            checkbox.pack(side="left", padx=5, pady=10)
            self.scan_config_vars.append(var)

        # Create a frame for URL input, Upload button, Scan button, and Dependency Check button
        url_scan_frame = tk.Frame(self, bg="#EFF0F1")
        url_scan_frame.pack(anchor="w")

        # Target URL label
        target_url_label = tk.Label(url_scan_frame, text="Target URL:", font=("Arial", 14, "bold"), bg="#EFF0F1")
        target_url_label.pack(side="left", pady=20, padx=20)

        # Entry widget for user to input URL
        self.url_entry = tk.Entry(url_scan_frame, font=("Arial", 12), width=20, fg='grey')
        self.url_entry.insert(0, "Enter URL...")  # Set a stylish placeholder text
        self.url_entry.pack(side="left", pady=20, padx=5)

        # Scan Start Button
        self.scan_start_button = tk.Button(url_scan_frame, text="Start Scan", width=15, bg="#3498DB", fg="white", font=("Arial", 12, "bold"), command=self.start_scan)
        self.scan_start_button.pack(side="left", pady=(20,10), padx=20)

        # Upload Button
        upload_button = tk.Button(url_scan_frame, text="Upload", width=15, bg="#2ECC71", fg="white", font=("Arial", 12, "bold"), command=self.upload_project_directory)
        upload_button.pack(side="left", pady=(20, 10), padx=5)

        # Dependency Check button
        self.dependency_check_button = tk.Button(url_scan_frame, text="Dependency Check Scan", width=20, bg="#3498DB", fg="white", font=("Arial", 12, "bold"), command=self.start_dependency_check)
        self.dependency_check_button.pack(side="left", pady=(20,10), padx=20)

        # Button to open HTML report
        open_report_button = tk.Button(self, text="Open HTML Report", width=20, bg="#3498DB", fg="white", font=("Arial", 12, "bold"), command=self.open_report)
        open_report_button.pack(pady=(10,0), padx=20, anchor="w")
        
        # Clear All Button
        self.clear_button = tk.Button(self, text="Clear All", width=15, bg="#E74C3C", fg="white", font=("Arial", 12, "bold"), command=self.clear_all)
        self.clear_button.pack(pady=(10,0), padx=20, anchor="w")

        # STOP Scan Button
        self.stop_scan_button = tk.Button(self, text="STOP Scan", width=15, bg="#E74C3C", fg="white", font=("Arial", 12, "bold"), command=self.stop_scan)
        self.stop_scan_button.pack(pady=(10,0), padx=20, anchor="w")

        # Scan Results Display (Placeholder)
        self.results_display = tk.Text(self, height=800, width=150)
        self.results_display.pack(pady=(0,10), padx=20, anchor="w")

    def start_dependency_check(self):
        project_directory = self.url_entry.get()
        results_display = self.results_display  # Assuming you have a results_display Text widget

        # Call the run_dependency_check function from dependency_check.py
        run_dependency_check(project_directory, results_display)

    def open_report(self):
        # Call the open_report function from dependency_check.py
        open_report(self.url_entry)

    def upload_project_directory(self):
        # Call the upload_project_directory function from dependency_check.py
        upload_project_directory(self.url_entry)
    
    def stop_scan(self):
        # Set the flag to signal the scan should be stopped
        self.stop_scan_flag = True
        
        # Display a message to indicate that the scan has been stopped
        self.results_display.insert(tk.END, "Scan has been stopped.\n")
        self.results_display.see(tk.END)

    def start_scan(self):
        url = self.url_entry.get()

        # Check if the provided URL is valid
        parsed_url = urlparse(url)
        if not (parsed_url.scheme and parsed_url.netloc):
            # Invalid URL, show error message and return
            messagebox.showerror("Invalid URL", "Please enter a valid URL (e.g., https://example.com).")
            return

        # Disable the Start Scan button to prevent multiple scans
        self.scan_start_button.config(state=tk.DISABLED)

        # Display a progress message
        self.results_display.insert(tk.END, "Scanning in progress...\n")
        self.results_display.see(tk.END)

        # Construct full path to scanner.py using os.path.join()
        scanner_path = os.path.join(r"D:/class/year 3/FYP/Development/Backend", "Scanner.py")

        # Execute the scanner.py script asynchronously in a separate thread
        self.scanner_thread = threading.Thread(target=self.execute_script, args=(scanner_path, url), daemon=True)
        self.scanner_thread.start()

    def execute_script(self, scanner_path, url):
        # Execute the scanner.py script and capture the output
        process = subprocess.Popen(["python", scanner_path, url], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, universal_newlines=True)

        # Read and insert the output into the Text widget
        for line in iter(process.stdout.readline, ""):
            # Check if the stop scan flag is set
            if self.stop_scan_flag:
                # Terminate the scan process
                process.terminate()
                break  # Exit the loop

            self.results_display.insert(tk.END, line)
            self.results_display.see(tk.END)  # Scroll to the end of the Text widget
            
            # Check for messages from scanner.py
            try:
                url = self.message_queue.get_nowait()
                self.process_url(url)
            except queue.Empty:
                pass

        process.stdout.close()

        # Re-enable the Start Scan button after scanning is completed
        self.scan_start_button.config(state=tk.NORMAL)

        # Reset the stop scan flag
        self.stop_scan_flag = False


    def process_url(self):
        # Display a dialog box for the user to enter the URL
        user_input = simpledialog.askstring("Enter URL", "Enter the URL for further processing:", parent=self)
        if user_input:
            # Check if the provided URL is valid
            parsed_url = urlparse(user_input)
            if parsed_url.scheme and parsed_url.netloc:
                # Valid URL, proceed with scanning
                self.results_display.insert(tk.END, f"Scanning URL: {user_input}\n")
                self.results_display.see(tk.END)
                # You can send the URL to scanner.py for scanning
                # Call start_scan with the valid URL
                self.start_scan(user_input)
            else:
                # Invalid URL, show error message
                messagebox.showerror("Invalid URL", "Please enter a valid URL (e.g., https://example.com).")

    def clear_all(self):
        # Clearing URL entry, progress bar, and results display
        self.url_entry.delete(0, tk.END)
        self.results_display.delete(1.0, tk.END)

    def logout(self):
        # Close the current window
        self.parent.destroy()

        # Create and open the login window
        login_window = tk.Tk()
        login_window.title("Login")
        login_window.geometry("925x500+300+200")
        login_window.configure(bg="#fff")
        login_window.resizable(False, False)

        # Create an instance of the LoginWindow class and add it to the Tkinter window
        login_page = LoginWindow(login_window)
        login_page.pack(fill="both", expand=True)

        # Run the Tkinter event loop for the login window
        login_window.mainloop()

#####################REPORT PAGE#######################################
class ReportPage(tk.Frame):
    def __init__(self, parent):
        super().__init__(parent, bg="#EFF0F1")
        self.parent = parent
        self.pack(fill="both", expand=True)
        self.load_ui()
        self.populate_scans_listbox()  # Call the method to populate the scans listbox

    def load_ui(self):
        # Heading label for the entire window
        self.heading_label = tk.Label(self, text="ScanSentryX Report", font=("Arial", 22, "bold"), bg="#EFF0F1", fg="#34495E")
        self.heading_label.pack(pady=20, padx=20, anchor="w")

        # Container for heading and menu
        left_frame = tk.Frame(self, width=200, bg="#34495E")  # Dark blue background with gradient
        left_frame.pack(side="left", fill="y")

        # Load the logo image
        logo_path =  "C:/Users/PC/Desktop/ScanSentryX/logopng.png"   # Replace with the actual path to your logo
        logo_image = Image.open(logo_path)
        resized_logo = logo_image.resize((150, 75), Image.LANCZOS)  # Resize logo
        logo_photo = ImageTk.PhotoImage(resized_logo)

        # Create a label to display the logo image
        logo_label = tk.Label(left_frame, image=logo_photo, bg="#34495E")  # Dark blue background
        logo_label.pack(pady=20, padx=20, anchor="w")

        # Menu buttons within the left frame
        menu_frame = tk.Frame(left_frame, bg="#34495E")  # Dark blue background
        menu_frame.pack(fill="both", expand=True)

        # Set a uniform width for all buttons
        button_width = 15  # Adjust as needed
        button_bg = "#2C3E50"  # Button background color

        # Define functions for menu buttons
        def show_dashboard():
            dashboard_page.pack(fill="both", expand=True)
            scan_page.pack_forget()
            report_page.pack_forget()
            setting_page.pack_forget()

        def show_scan():
            dashboard_page.pack_forget()
            scan_page.pack(fill="both", expand=True)
            report_page.pack_forget()
            setting_page.pack_forget()

        def show_reports():
            dashboard_page.pack_forget()
            scan_page.pack_forget()
            report_page.pack(fill="both", expand=True)
            setting_page.pack_forget()

        def show_settings():
            dashboard_page.pack_forget()
            scan_page.pack_forget()
            report_page.pack_forget()
            setting_page.pack(fill="both", expand=True)

        # Menu buttons
        dashboard_button = tk.Button(menu_frame, text="Dashboard", width=button_width, bg=button_bg, fg="white", font=("Arial", 12, "bold"), command=show_dashboard)
        scan_button = tk.Button(menu_frame, text="Scan", width=button_width, bg=button_bg, fg="white", font=("Arial", 12, "bold"), command=show_scan)
        reports_button = tk.Button(menu_frame, text="Reports", width=button_width, bg=button_bg, fg="white", font=("Arial", 12, "bold"), command=show_reports)
        settings_button = tk.Button(menu_frame, text="Settings", width=button_width, bg=button_bg, fg="white", font=("Arial", 12, "bold"), command=show_settings)
        logout_button = tk.Button(menu_frame, text="Logout", width=button_width, bg=button_bg, fg="white", font=("Arial", 12, "bold"), command=self.logout)

        dashboard_button.pack(pady=10)
        scan_button.pack(pady=10)
        reports_button.pack(pady=10)
        settings_button.pack(pady=10)
        logout_button.pack(pady=10)

        # Scan List Section
        self.scan_list_label = tk.Label(self, text="List of Scans Performed", font=("Arial", 14, "bold"), bg="#EFF0F1", fg="#34495E")
        self.scan_list_label.pack(pady=(20,10), padx=20, anchor="w")

        # Sample list of scans (Replace this with actual scan data)
        self.scan_listbox = tk.Listbox(self, font=("Arial", 12), bg="white", fg="black", selectbackground="#3498DB", selectforeground="white")
        self.scan_listbox.pack(pady=(0,10), padx=20, anchor="w", fill="both", expand=True)
        self.scan_listbox.bind("<<ListboxSelect>>", self.on_scan_select)  # Bind the selection event

        # Scan Details Display
        details_frame = tk.Frame(self, bg="#EFF0F1")  # Light gray background
        details_frame.pack(pady=(0, 20), padx=20, anchor="w", fill="both", expand=True)

        self.details_label = tk.Label(details_frame, text="Scan Details", font=("Arial", 14, "bold"), bg="#EFF0F1", fg="#34495E")
        self.details_label.pack(pady=(10, 5), padx=20, anchor="w")

        self.details_text = tk.Text(details_frame, wrap=tk.WORD, width=60, height=10, font=("Arial", 12), bg="white", fg="black")
        self.details_text.pack(pady=(0, 10), padx=20, anchor="w")

        # Buttons Section
        buttons_frame = tk.Frame(self, bg="#EFF0F1")  # Light gray background
        buttons_frame.pack(anchor="w")
        
        # Download Report Button
        self.download_report_button = tk.Button(buttons_frame, text="Download Report", width=15, bg="#3498DB", fg="white", font=("Arial", 12, "bold"), command=self.download_report)
        self.download_report_button.pack(side="left", padx=(20, 10), pady=(0, 10))

        # Mitigation Steps Button
        self.mitigation_steps_button = tk.Button(buttons_frame, text="Mitigation Steps", width=15, bg="#3498DB", fg="white", font=("Arial", 12, "bold"), command=self.on_mitigation_steps_click)
        self.mitigation_steps_button.pack(side="left", pady=(0, 10))
        
         # Clear Scans Button
        self.clear_scans_button = tk.Button(buttons_frame, text="Clear Scans", width=15, bg="#3498DB", fg="white", font=("Arial", 12, "bold"), command=self.clear_scan_records)
        self.clear_scans_button.pack(side="left", padx=(20, 10), pady=(0, 10))
        
         # Refresh Scans Button
        self.refresh_scans_button = tk.Button(buttons_frame, text="Refresh Scans", width=15, bg="#3498DB", fg="white", font=("Arial", 12, "bold"), command=self.populate_scans_listbox)
        self.refresh_scans_button.pack(side="left", pady=(0, 10))
        
    def clear_scan_records(self):
        # Call the function to clear scan records from the database
        clear_scan_records()
        # Repopulate the scans listbox after clearing the records
        self.populate_scans_listbox()
        
    def populate_scans_listbox(self):
        """Populate the scans listbox with unique URLs and their respective scan results."""
        # Clear existing items from the listbox
        self.scan_listbox.delete(0, tk.END)

        # Retrieve scans from the database
        scans = get_scans()

        # Keep track of unique URLs and their respective scan results
        self.unique_urls = {}

        # Iterate through the scans and store unique URLs with their results
        if scans:
            for scan in scans:
                url = scan[1]  # Assuming index 1 contains the URL
                result = scan[2]  # Assuming index 2 contains the scan result
                if url not in self.unique_urls:
                    self.unique_urls[url] = result

        # Populate the listbox with unique URLs and their respective scan results
        if self.unique_urls:
            for url, result in self.unique_urls.items():
                self.scan_listbox.insert(tk.END, f"{url}: {result}")
        else:
            self.scan_listbox.insert(tk.END, "No scans available")

    def on_scan_select(self, event):
        """Update the scan details text when a scan is selected in the listbox."""
        # Get the selected scan index
        selected_index = self.scan_listbox.curselection()

        # Clear previous details
        self.details_text.delete(1.0, tk.END)

        # If a scan is selected, display its details
        if selected_index:
            selected_scan = self.scan_listbox.get(selected_index)
            url = selected_scan.split(":")[0].strip()  # Extract URL from the selected scan
            result = self.unique_urls[url]  # Get the result for the selected URL from the stored data
            # Display the details
            self.details_text.insert(tk.END, f"URL: {url}\nResult: {result}")
        else:
            self.details_text.insert(tk.END, "No scan selected")

    def download_report(self):
        try:
            # Specify the source path of the report file generated by scanner.py
            source_path = "D:\\class\\year 3\\FYP\\Development\\security_scan_report.pdf"

            # Open a file dialog to choose the destination path to save the report
            destination_path = filedialog.asksaveasfilename(defaultextension=".pdf", filetypes=[("PDF files", "*.pdf")])

            if destination_path:
                # Copy the report file to the chosen destination path
                shutil.copyfile(source_path, destination_path)
                messagebox.showinfo("Download Complete", "Report downloaded successfully!")
            else:
                messagebox.showinfo("Download Cancelled", "Download operation cancelled.")
        except Exception as e:
            messagebox.showerror("Download Error", f"An error occurred while downloading the report: {str(e)}")
    
    def on_mitigation_steps_click(self):
        mitigation_window = tk.Toplevel(self)  # Create a new top-level window
        mitigation_window.title("Mitigation Steps")  # Set the window title
        mitigation_window.geometry("925x500+300+200")  # Set the window size
        mitigation_window.configure(bg="#EFF0F1")  # Set background color

        # Heading label for the mitigation window
        heading_label = tk.Label(mitigation_window, text="Mitigation Steps", font=("Arial", 18, "bold"), bg="#EFF0F1", fg="#34495E")
        heading_label.pack(pady=20)

        # Text widget to display mitigation steps
        mitigation_text = tk.Text(mitigation_window, wrap=tk.WORD, font=("Arial", 12), bg="white", fg="#34495E")
        mitigation_text.pack(pady=10, padx=20, fill="both", expand=True)
        
        # Insert styled mitigation steps into the text widget
        mitigation_text.insert(tk.END, """
        Mitigation Steps for Common Web Application Vulnerabilities:
        
        1. SQL Injection:
           - Use parameterized queries or prepared statements.
           - Implement input validation and sanitization.
           - Limit database user permissions.
           
        2. Broken Access Control:
           - Implement proper access control mechanisms based on roles and permissions.
           - Enforce authorization checks at both the server and client sides.
           - Regularly review and update access control policies to ensure they align with business requirements.
                               
        3. Insecure Design:
           - Follow secure coding practices and principles such as the principle of least privilege and defense in depth.
           - Conduct security design reviews during the development phase to identify and address potential security flaws.
           - Employ secure architecture patterns and frameworks that emphasize security controls and mechanisms.
        
        4. Authentication Failures:
           - Enforce strong password policies, including password complexity requirements and regular password expiration.
           - Implement multi-factor authentication (MFA) to add an extra layer of security.
           - Use secure authentication protocols such as OAuth or OpenID Connect for user authentication.
           
        5. Integrity Failures:
           - Implement data validation and integrity checks on both the client and server sides.
           - Utilize cryptographic techniques such as digital signatures and message authentication codes (MACs) to verify data integrity.
           - Implement version control and change management processes to track and monitor changes to critical data.
        
        6. Security Misconfiguration:
           - Regularly review and update configuration settings for web servers, application frameworks, and third-party libraries.
           -Disable unnecessary features and services to reduce the attack surface.
           -Implement secure defaults and harden the configuration of servers and applications.
        
        7. Sensitive Data Exposure and Cryptographic Failures:
           - Encrypt sensitive data both at rest and in transit using strong encryption algorithms.
           -Implement secure key management practices to protect cryptographic keys.
           -Use secure protocols such as HTTPS/TLS for data transmission over the network.
        
        8. Vulnerable Components:
           - Regularly update and patch all software components, including third-party libraries and dependencies.
           - Monitor vulnerability databases and security advisories for known vulnerabilities in software components.
           - Use dependency management tools to track and manage software dependencies effectively.
                            
        9. Server-Side Request Forgery (SSRF):
           - Validate and sanitize all user-supplied URLs and input to prevent SSRF attacks.
           - Implement network-level protections such as firewalls and network segmentation to restrict outbound connections.
           - Utilize allowlists to specify the domains and IP addresses that the application can access.
            
        10. Logging and Monitoring:
           - Implement comprehensive logging mechanisms to record all relevant security events and activities.
           - Regularly review and analyze logs to detect and investigate suspicious or malicious activities.
           - Use intrusion detection and prevention systems (IDS/IPS) to monitor network traffic and identify potential threats in real-time.
        ... Additional mitigation steps for other vulnerabilities ...
        """)
        
        # Make the window modal (prevents interaction with other windows)
        mitigation_window.grab_set()

    def logout(self):
        # Close the current window
        self.parent.destroy()

        # Create and open the login window
        login_window = tk.Tk()
        login_window.title("Login")
        login_window.geometry("925x500+300+200")
        login_window.configure(bg="#fff")
        login_window.resizable(False, False)

        # Create an instance of the LoginWindow class and add it to the Tkinter window
        login_page = LoginWindow(login_window)
        login_page.pack(fill="both", expand=True)

        # Run the Tkinter event loop for the login window
        login_window.mainloop()
                
#########################SETTING PAGE##################################

class SettingPage(tk.Frame):
    """Class representing the Setting page of the application."""

    def __init__(self, parent, current_user):
        super().__init__(parent, bg="#EFF0F1")
        self.parent = parent
        self.current_user = current_user
        self.pack(fill="both", expand=True)

        # Check user role
        if self.current_user['role'] != 'admin':
            self.display_permission_error()
            return

        # User information
        self.username = self.current_user.get('username', 'Unknown')

        # Default settings
        self.font_sizes = {"Small": 10, "Medium": 12, "Large": 16}
        self.current_font_size = tk.IntVar(value=self.font_sizes["Medium"])
        self.high_contrast_mode = tk.BooleanVar(value=False)

        # Heading label for the entire window
        self.heading_label = tk.Label(self, text="ScanSentryX Settings", font=("Arial", 22, "bold"), bg="#EFF0F1", fg="#34495E")
        self.heading_label.pack(pady=20, padx=20, anchor="w")

        # Container for heading and menu
        left_frame = tk.Frame(self, width=200, bg="#34495E")  # Dark blue background with gradient
        left_frame.pack(side="left", fill="y")

        # Load the logo image
        logo_path = "C:/Users/PC/Desktop/ScanSentryX/logopng.png"  # Replace with the actual path to your logo
        logo_image = Image.open(logo_path)
        resized_logo = logo_image.resize((150, 75), Image.LANCZOS)  # Resize logo
        logo_photo = ImageTk.PhotoImage(resized_logo)

        # Create a label to display the logo image
        logo_label = tk.Label(left_frame, image=logo_photo, bg="#34495E")  # Dark blue background
        logo_label.pack(pady=20, padx=20, anchor="w")

        # Menu buttons within the left frame
        menu_frame = tk.Frame(left_frame, bg="#34495E")  # Dark blue background
        menu_frame.pack(fill="both", expand=True)

        # Set a uniform width for all buttons
        button_width = 15  # Adjust as needed
        button_bg = "#2C3E50"  # Button background color

        # Define functions for menu buttons
        def show_dashboard():
            dashboard_page.pack(fill="both", expand=True)
            scan_page.pack_forget()
            report_page.pack_forget()
            setting_page.pack_forget()

        def show_scan():
            dashboard_page.pack_forget()
            scan_page.pack(fill="both", expand=True)
            report_page.pack_forget()
            setting_page.pack_forget()

        def show_reports():
            dashboard_page.pack_forget()
            scan_page.pack_forget()
            report_page.pack(fill="both", expand=True)
            setting_page.pack_forget()

        def show_settings():
            dashboard_page.pack_forget()
            scan_page.pack_forget()
            report_page.pack_forget()
            setting_page.pack(fill="both", expand=True)

        # Menu buttons
        dashboard_button = tk.Button(menu_frame, text="Dashboard", width=button_width, bg=button_bg, fg="white",
                                     font=("Arial", 12, "bold"), command=show_dashboard)
        scan_button = tk.Button(menu_frame, text="Scan", width=button_width, bg=button_bg, fg="white",
                                font=("Arial", 12, "bold"), command=show_scan)
        reports_button = tk.Button(menu_frame, text="Reports", width=button_width, bg=button_bg, fg="white",
                                   font=("Arial", 12, "bold"), command=show_reports)
        settings_button = tk.Button(menu_frame, text="Settings", width=button_width, bg=button_bg, fg="white",
                                    font=("Arial", 12, "bold"), command=show_settings)
        logout_button = tk.Button(menu_frame, text="Logout", width=button_width, bg=button_bg, fg="white",
                                  font=("Arial", 12, "bold"), command=self.logout)

        dashboard_button.pack(pady=10)
        scan_button.pack(pady=10)
        reports_button.pack(pady=10)
        settings_button.pack(pady=10)
        logout_button.pack(pady=10)

        # Personal Information Section
        self.personal_info_label = tk.Label(self, text="Personal Information", font=("Arial", 14, "bold"),
                                            bg="#EFF0F1", fg="#34495E")
        self.personal_info_label.pack(pady=(20, 10), padx=20, anchor="w")

        # Username
        username_label = tk.Label(self, text="Username:", font=("Arial", 12), bg="#EFF0F1")
        username_label.pack(pady=(0, 5), padx=20, anchor="w")
        self.username_entry = tk.Entry(self, font=("Arial", 12), width=20, fg='black', bg="#EFF0F1")
        self.username_entry.insert(0, self.username)  # Display username
        self.username_entry.pack(pady=(0, 10), padx=20, anchor="w")

        # Customization Section
        self.customization_label = tk.Label(self, text="Customization", font=("Arial", 14, "bold"), bg="#EFF0F1",
                                             fg="#34495E")
        self.customization_label.pack(pady=(20, 10), padx=20, anchor="w")

        # Theme Selection
        self.theme_label = tk.Label(self, text="Theme:", font=("Arial", 12), bg="#EFF0F1")
        self.theme_label.pack(pady=(0, 5), padx=20, anchor="w")

        self.theme_var = tk.StringVar(value="Light")  # Default value is Light theme
        self.theme_radiobutton_light = tk.Radiobutton(self, text="Light", variable=self.theme_var, value="Light",
                                                      font=("Arial", 12), bg="#EFF0F1")
        self.theme_radiobutton_light.pack(pady=(0, 5), padx=20, anchor="w")

        self.theme_radiobutton_dark = tk.Radiobutton(self, text="Dark", variable=self.theme_var, value="Dark",
                                                     font=("Arial", 12), bg="#EFF0F1")
        self.theme_radiobutton_dark.pack(pady=(0, 5), padx=20, anchor="w")

        # Language Selection
        self.language_label = tk.Label(self, text="Language:", font=("Arial", 12), bg="#EFF0F1")
        self.language_label.pack(pady=(0, 5), padx=20, anchor="w")

        self.language_var = tk.StringVar(value="English")  # Default value is English
        self.language_dropdown = ttk.Combobox(self, textvariable=self.language_var,
                                               values=["English", "French", "Spanish"],
                                               state="readonly", font=("Arial", 12), width=17)
        self.language_dropdown.pack(pady=(0, 10), padx=20, anchor="w")

        # Accessibility Options
        self.accessibility_label = tk.Label(self, text="Accessibility Options", font=("Arial", 14, "bold"),
                                            bg="#EFF0F1", fg="#34495E")
        self.accessibility_label.pack(pady=(20, 10), padx=20, anchor="w")

        # Font Size Selection
        self.font_size_label = tk.Label(self, text="Font Size:", font=("Arial", 12), bg="#EFF0F1")
        self.font_size_label.pack(pady=(0, 5), padx=20, anchor="w")

        self.font_size_dropdown = ttk.Combobox(self, textvariable=self.current_font_size,
                                                values=list(self.font_sizes.values()),
                                                state="readonly", font=("Arial", 12), width=17)
        self.font_size_dropdown.pack(pady=(0, 10), padx=20, anchor="w")

        # High Contrast Mode Checkbox
        self.high_contrast_checkbox = tk.Checkbutton(self, text="High Contrast Mode",
                                                      variable=self.high_contrast_mode,
                                                      font=("Arial", 12), bg="#EFF0F1", onvalue=True,
                                                      offvalue=False)
        self.high_contrast_checkbox.pack(pady=(0, 10), padx=20, anchor="w")

        # Apply Settings Button
        self.apply_settings_button = tk.Button(self, text="Apply Settings", width=15, bg="#2980B9", fg="white",
                                               font=("Arial", 12, "bold"), command=self.apply_settings)
        self.apply_settings_button.pack(pady=(0, 10), padx=20, anchor="w")

        # Help Button
        self.help_button = tk.Button(self, text="Help", width=10, bg="#3498DB", fg="white",
                                     font=("Arial", 12, "bold"))
        self.help_button.pack(pady=20, padx=20, anchor="s", side="bottom")

        # Session Management
        self.session_management_label = tk.Label(self, text="Session Management", font=("Arial", 14, "bold"),
                                                  bg="#EFF0F1", fg="#34495E")
        self.session_management_label.pack(pady=(20, 10), padx=20, anchor="w")

        # Active Sessions Listbox
        self.active_sessions_listbox = tk.Listbox(self, font=("Arial", 12), bg="#FFFFFF",
                                                   selectbackground="#DDDDDD",
                                                   width=30, height=4)
        # Populate listbox with mock session data
        mock_sessions = ["Session 1", "Session 2", "Session 3"]
        for session in mock_sessions:
            self.active_sessions_listbox.insert(tk.END, session)
        self.active_sessions_listbox.pack(pady=(0, 10), padx=20, anchor="w")

        # Logout Button
        self.logout_button = tk.Button(self, text="Logout", width=10, bg="#E74C3C", fg="white",
                                        font=("Arial", 12, "bold"), command=self.logout)
        self.logout_button.pack(pady=20, padx=20, anchor="w")

    def apply_settings(self):
        theme = self.theme_var.get()
        if theme == "Dark":
            self.apply_dark_theme()
        else:
            self.apply_light_theme()

        # Implement language change logic here

        # Implement font size change logic here
        font_size = self.current_font_size.get()
        self.apply_font_size(font_size)

        # Implement high contrast mode change logic here
        high_contrast = self.high_contrast_mode.get()
        self.apply_high_contrast(high_contrast)

    def apply_dark_theme(self):
        self.config(bg="#2C3E50")  # Background color
        # Apply dark theme to other elements

    def apply_light_theme(self):
        self.config(bg="#EFF0F1")  # Background color
        # Apply light theme to other elements

    def apply_font_size(self, font_size):
        self.heading_label.config(font=("Arial", font_size, "bold"))
        # Apply font size to other elements

    def apply_high_contrast(self, high_contrast):
        if high_contrast:
            # Apply high contrast mode
            pass
        else:
            # Revert to normal mode
            pass

    def display_permission_error(self):
        """Display permission error message."""
        error_label = tk.Label(self, text="You don't have permission to access this page.", font=("Arial", 16), bg="#EFF0F1")
        error_label.pack(pady=50)

    def logout(self):
        # Close the current window
        self.parent.destroy()

        # Create and open the login window
        login_window = tk.Tk()
        login_window.title("Login")
        login_window.geometry("925x500+300+200")
        login_window.configure(bg="#fff")
        login_window.resizable(False, False)

        # Create an instance of the LoginWindow class and add it to the Tkinter window
        login_page = LoginWindow(login_window)
        login_page.pack(fill="both", expand=True)

        # Run the Tkinter event loop for the login window
        login_window.mainloop()



# Create the Tkinter window
root = tk.Tk()
root.title("ScanSentryX Dashboard")
root.geometry("1920x1080")

current_user = {'username': 'admin', 'role': 'admin'}  # Example user information for an admin

# Create instances of each page and add them to the Tkinter window
dashboard_page = DashboardPage(root)
scan_page = ScanPage(root)
report_page = ReportPage(root)
setting_page = SettingPage(root, current_user)

# Pack each page into the window (you can change the layout as needed)
dashboard_page.pack(fill="both", expand=True)
scan_page.pack(fill="both", expand=True)
report_page.pack(fill="both", expand=True)
setting_page.pack(fill="both", expand=True)

# Run the Tkinter event loop
root.mainloop()