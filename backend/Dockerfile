# Use official Python image
FROM python:3.12

# Set environment variables
# ENV PYTHONDONTWRITEBYTECODE=1 \
#     PYTHONUNBUFFERED=1

# Set work directory
WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --upgrade pip && pip install -r requirements.txt
# RUN pip install -r requirements.txt

# Copy project files
# COPY . .

# Expose the port FastAPI will run on
EXPOSE 8080

# Command to run the app with Uvicorn
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8080", "--reload"]
# CMD ["python3", "main.py"]