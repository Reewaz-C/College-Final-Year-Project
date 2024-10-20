# Use the official Python image as base
FROM python:3.12

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

# Set the working directory in the container
WORKDIR /app

# Copy the requirements file into the container
COPY requirements.txt .

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Install additional dependencies
RUN pip install --no-cache-dir Pillow

# Copy the Backend folder into the container
COPY Backend /app/Backend

# Copy the main.py file into the container
COPY main.py /app

# Set the working directory in the container
WORKDIR /app

# Expose port 5000 to the outside world
EXPOSE 5000

# Command to run the application
CMD ["python", "main.py"]
