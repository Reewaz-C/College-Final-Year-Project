import PyInstaller.__main__

# Path to the main Python script you want to convert to .exe
main_script = "main.py"

# PyInstaller options
options = [
    '--onefile',    # Generate a single executable file
    '--noconsole',  # Don't display a console window (for GUI applications)
    '--clean',      # Clean PyInstaller cache and remove temporary files
]

# Add any additional options here
# options += ['--additional-option']

# Run PyInstaller
PyInstaller.__main__.run([main_script] + options)
