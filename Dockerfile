# Use an official lightweight Python runtime as a parent image.
FROM python:3.9-slim

# Set environment variables to prevent .pyc files and enable stdout/stderr logging
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

# Set working directory
WORKDIR /app

# Copy requirements file and install dependencies
COPY requirements.txt .
RUN pip install --upgrade pip && \
    pip install -r requirements.txt

# Copy the application code
COPY . .

# Expose port 8000 for the FastAPI application
EXPOSE 8000

# Command to run the application with Uvicorn
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000"] 
