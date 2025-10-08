# Use official Python image
FROM python:3.12


# Set work directory
WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --upgrade pip && pip install -r requirements.txt

# Expose the port FastAPI will run on
EXPOSE 8080

# Command to run the app with Uvicorn
CMD ["uvicorn", "main:app", "--host", "localhost", "--port", "8080", "--reload"]
