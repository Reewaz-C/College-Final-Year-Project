import subprocess
import os
import tkinter as tk
from tkinter import messagebox, filedialog
import webbrowser

def run_dependency_check(project_directory, results_display):
    try:
        # Construct the command to run Dependency-Check
        command = [
            r'C:\\Users\\PC\\Desktop\\dependency-check-9.0.10-release\\dependency-check\\bin\\dependency-check.bat',
            '--scan', project_directory
        ]

        # Run the command and capture the output
        result = subprocess.run(command, check=True, capture_output=True, text=True)

        # Check if Dependency-Check produced any output
        if result.stdout:
            results_display.insert(tk.END, "OWASP Dependency-Check output:\n")
            results_display.insert(tk.END, result.stdout)
        else:
            results_display.insert(tk.END, "No OWASP Dependency-Check result found.\n")

        results_display.insert(tk.END, "OWASP Dependency-Check completed successfully.\n")

        # Extract the path of the HTML report from the output
        report_path = extract_report_path(result.stdout)
        return report_path

    except subprocess.CalledProcessError as e:
        results_display.insert(tk.END, f"Error running OWASP Dependency-Check: {e}\n")
        if e.output:
            results_display.insert(tk.END, f"Dependency-Check output:\n{e.output}\n")
    except Exception as e:
        results_display.insert(tk.END, f"An unexpected error occurred: {e}\n")

def extract_report_path(output):
    # Parse the output to extract the path of the HTML report
    report_path = ""
    lines = output.split('\n')
    for line in lines:
        if "Writing HTML report to:" in line:
            report_path = line.split(":")[1].strip()
            break
    return report_path

def open_report(url_entry):
    # Get the path of the generated HTML report
    project_directory = url_entry.get()
    report_path = os.path.join("D:/class/year 3/FYP/Development/Frontend/dist/dependency-check-report.html")

    # Check if the report file exists
    if not os.path.isfile(report_path):
        messagebox.showerror("Report Not Found", "The HTML report file does not exist.")
        return

    # Open the HTML report in a web browser
    webbrowser.open_new_tab(report_path)

def start_dependency_check(project_directory, results_display):
    # Check if a directory is uploaded
    if not os.path.isdir(project_directory):
        messagebox.showerror("Invalid Directory", "Please select a valid directory.")
        return

    # Display a progress message
    results_display.insert(tk.END, "Dependency Check in progress...\n")
    results_display.see(tk.END)

    # Run the dependency check function
    run_dependency_check(project_directory, results_display)
    
def upload_project_directory(url_entry):
    selected_directory = filedialog.askdirectory()
    if selected_directory:
        url_entry.delete(0, tk.END)
        url_entry.insert(0, selected_directory)
