# Use a Python 3 base image
FROM python:3.9-slim

# Set the working directory inside the container
WORKDIR /app

# Copy the project files into the container
COPY . .

# Install dependencies from the requirements.txt file
RUN pip install --no-cache-dir -r requirements.txt

# Expose port 8080 (if the script ever needs it)
EXPOSE 8080

# Default command to run the script
CMD ["python", "main.py"]