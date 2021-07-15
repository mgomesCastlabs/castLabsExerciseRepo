FROM python:3.9-slim

WORKDIR /app

# Setup app.
COPY . /app

ADD main.py /app
ADD tester.py /app

# Install system dependencies.
RUN apt-get update && apt-get install -y 

# Uninstall base JWT library (we're replacing it with PyJWT)
RUN pip uninstall -r uninstall.txt

# Install Python dependencies.
RUN pip install -r requirements.txt

EXPOSE 8080

CMD ["python", "main.py"]
