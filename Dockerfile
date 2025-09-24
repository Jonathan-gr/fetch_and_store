# Use a lightweight Python 3.12 image
FROM python:3.12-slim

# Set working directory inside container
WORKDIR /app

# Copy requirements first (helps Docker cache dependencies)
COPY requirements.txt .

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the project
COPY . .

# Expose the port your app runs on
EXPOSE 8080

# Run your app
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8080"]
